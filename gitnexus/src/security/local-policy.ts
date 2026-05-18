import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);

const normalizeFeature = (feature: string): string =>
  feature.toUpperCase().replace(/[^A-Z0-9]+/g, '_');

export const isTruthyEnv = (value: string | undefined): boolean =>
  value !== undefined && TRUE_VALUES.has(value.trim().toLowerCase());

export const isCompanyMode = (): boolean => isTruthyEnv(process.env.GITNEXUS_COMPANY_MODE);

const splitList = (value: string | undefined): string[] =>
  (value ?? '')
    .split(/[\n,]/)
    .map((part) => part.trim())
    .filter(Boolean);

const featureEnvName = (prefix: string, feature: string, suffix = ''): string =>
  `${prefix}_${normalizeFeature(feature)}${suffix}`;

const audit = (event: Record<string, unknown>): void => {
  const logPath =
    process.env.GITNEXUS_SECURITY_AUDIT_LOG ||
    path.join(os.homedir(), '.gitnexus', 'security-audit.jsonl');
  try {
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    fs.appendFileSync(logPath, JSON.stringify({ ts: new Date().toISOString(), ...event }) + '\n');
  } catch {
    // Security decisions must not fail open because the audit sink is unavailable.
  }
};

export const writeSecurityAudit = audit;

const sanitizeTarget = (targetUrl: string | undefined): string | undefined => {
  if (!targetUrl) return undefined;
  try {
    const url = new URL(targetUrl);
    url.username = '';
    url.password = '';
    return `${url.origin}${url.pathname}`;
  } catch {
    return '[invalid-url]';
  }
};

const matchesAllowedUrl = (targetUrl: string, allowEntry: string): boolean => {
  let target: URL;
  try {
    target = new URL(targetUrl);
  } catch {
    return false;
  }

  const raw = allowEntry.trim();
  if (!raw) return false;

  if (raw === target.origin || raw === target.hostname) return true;

  const comparable = raw.includes('://') ? raw : `${target.protocol}//${raw}`;
  try {
    const allowed = new URL(comparable);
    if (allowed.protocol !== target.protocol || allowed.hostname !== target.hostname) return false;
    if (allowed.port !== target.port) return false;

    const allowedPath = allowed.pathname.replace(/\*$/, '').replace(/\/+$/, '');
    if (!allowedPath || allowedPath === '/') return true;
    return target.pathname === allowedPath || target.pathname.startsWith(allowedPath + '/');
  } catch {
    return false;
  }
};

export const getAllowedUrlsForFeature = (feature: string): string[] => {
  const generic = [
    ...splitList(process.env[featureEnvName('GITNEXUS_ALLOWED_OUTBOUND', feature, '_URLS')]),
    ...splitList(process.env.GITNEXUS_ALLOWED_OUTBOUND_URLS),
  ];
  if (normalizeFeature(feature) === 'WEB_ORIGIN') {
    generic.push(...splitList(process.env.GITNEXUS_ALLOWED_WEB_ORIGINS));
  }
  return generic;
};

export const isOutboundNetworkAllowed = (feature: string, targetUrl?: string): boolean => {
  const featureFlag = featureEnvName('GITNEXUS_ALLOW_OUTBOUND', feature);
  const allowedByFlag =
    isTruthyEnv(process.env.GITNEXUS_ALLOW_OUTBOUND) || isTruthyEnv(process.env[featureFlag]);
  const allowedByUrl =
    !!targetUrl && getAllowedUrlsForFeature(feature).some((entry) => matchesAllowedUrl(targetUrl, entry));
  const allowed = allowedByFlag || allowedByUrl;

  audit({
    type: 'network-policy',
    feature,
    target: sanitizeTarget(targetUrl),
    allowed,
    reason: allowedByFlag ? 'env-flag' : allowedByUrl ? 'url-allowlist' : 'default-deny',
  });

  return allowed;
};

export const assertOutboundNetworkAllowed = (feature: string, targetUrl: string): void => {
  if (!isOutboundNetworkAllowed(feature, targetUrl)) {
    throw new Error(
      outboundDisabledMessage(
        `${feature} network access`,
        `${featureEnvName('GITNEXUS_ALLOW_OUTBOUND', feature)}=1 or ${featureEnvName('GITNEXUS_ALLOWED_OUTBOUND', feature, '_URLS')}=<approved URL>`,
      ),
    );
  }
};

export const isLocalRepoPathAllowed = (repoPath: string): boolean => {
  const allowedRoots = splitList(process.env.GITNEXUS_ALLOWED_REPO_PATHS).map((root) =>
    path.resolve(root),
  );

  if (!isCompanyMode() && allowedRoots.length === 0) return true;
  if (allowedRoots.length === 0) return false;

  const resolved = path.resolve(repoPath);
  return allowedRoots.some((root) => {
    const rel = path.relative(root, resolved);
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  });
};

export const assertLocalRepoPathAllowed = (repoPath: string): void => {
  const allowed = isLocalRepoPathAllowed(repoPath);
  audit({
    type: 'repo-path-policy',
    path: path.resolve(repoPath),
    allowed,
    reason: allowed ? 'path-allowlist' : 'default-deny',
  });
  if (!allowed) {
    throw new Error(
      'Local repository path is not allowed in GitNexus company mode. Set GITNEXUS_ALLOWED_REPO_PATHS to an approved repo root.',
    );
  }
};

export const outboundDisabledMessage = (feature: string, envName: string): string =>
  `Outbound ${feature} is disabled by default in this security fork. Set ${envName} to allow it.`;

export const isLoopbackHost = (host: string | undefined): boolean => {
  const normalized = (host || '').trim().toLowerCase();
  return (
    normalized === '' ||
    normalized === 'localhost' ||
    normalized === '127.0.0.1' ||
    normalized === '::1' ||
    normalized === '[::1]'
  );
};

export const isHttpAuthRequired = (host: string | undefined): boolean =>
  isTruthyEnv(process.env.GITNEXUS_REQUIRE_AUTH) ||
  (isCompanyMode() && !isLoopbackHost(host));

export const getHttpApiToken = (): string | undefined =>
  process.env.GITNEXUS_API_TOKEN || process.env.GITNEXUS_SERVER_TOKEN;

export const isBearerTokenAuthorized = (
  authorizationHeader: string | undefined,
  headerToken: string | undefined,
  queryToken: string | undefined,
): boolean => {
  const expected = getHttpApiToken();
  if (!expected) return false;

  const bearer = authorizationHeader?.match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  const provided = bearer || headerToken || queryToken;
  return provided === expected;
};

const alwaysAllowedMcpTools = new Set(['list_repos']);

export const isMcpToolAllowed = (toolName: string, readOnly: boolean): boolean => {
  if (!isCompanyMode()) return true;

  const allowedTools = splitList(process.env.GITNEXUS_ALLOWED_MCP_TOOLS);
  if (allowedTools.includes(toolName)) return true;
  if (alwaysAllowedMcpTools.has(toolName)) return true;
  if (readOnly) return true;

  return isTruthyEnv(process.env.GITNEXUS_ALLOW_MCP_WRITE_TOOLS);
};

export const assertMcpToolAllowed = (toolName: string, readOnly: boolean): void => {
  const allowed = isMcpToolAllowed(toolName, readOnly);
  audit({
    type: 'mcp-tool-policy',
    tool: toolName,
    readOnly,
    allowed,
    reason: allowed
      ? readOnly
        ? 'read-only'
        : 'tool-allowlist'
      : 'company-mode-write-tool-deny',
  });
  if (!allowed) {
    throw new Error(
      `MCP tool "${toolName}" is disabled in GitNexus company mode. Set GITNEXUS_ALLOWED_MCP_TOOLS=${toolName} or GITNEXUS_ALLOW_MCP_WRITE_TOOLS=1 to allow it.`,
    );
  }
};

const SKIP_SCAN_DIRS = new Set([
  '.git',
  '.gitnexus',
  'node_modules',
  'vendor',
  'dist',
  'build',
  'out',
  'target',
  '.next',
  '.nuxt',
  '.cache',
  'coverage',
]);

const DEFAULT_INDEX_DENY_PATTERNS = [
  /^\.env(?:\..*)?$/i,
  /^\.npmrc$/i,
  /^\.pypirc$/i,
  /^\.netrc$/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)$/i,
  /(?:^|[._-])secret(?:s)?(?:[._-]|$)/i,
  /(?:^|[._-])credential(?:s)?(?:[._-]|$)/i,
  /(?:^|[._-])token(?:s)?(?:[._-]|$)/i,
  /(?:^|[._-])password(?:s)?(?:[._-]|$)/i,
  /\.(?:pem|key|p12|pfx|kdbx|gpg|asc)$/i,
  /\.(?:sqlite|sqlite3|db|dump)$/i,
  /(?:^|\/)(?:backup|backups|dumps?)(?:\/|$)/i,
];

export interface DeniedIndexFile {
  path: string;
  reason: string;
}

const matchDeniedIndexPath = (relativePath: string): string | null => {
  const normalized = relativePath.replace(/\\/g, '/');
  const basename = path.posix.basename(normalized);
  const custom = splitList(process.env.GITNEXUS_INDEX_DENY_PATTERNS);
  for (const pattern of custom) {
    if (normalized.includes(pattern) || basename.includes(pattern)) return `custom:${pattern}`;
  }
  for (const pattern of DEFAULT_INDEX_DENY_PATTERNS) {
    if (pattern.test(normalized) || pattern.test(basename)) return pattern.source;
  }
  return null;
};

export const findDeniedIndexFiles = async (
  repoPath: string,
  limit = 50,
): Promise<DeniedIndexFile[]> => {
  const root = path.resolve(repoPath);
  const matches: DeniedIndexFile[] = [];

  const walk = async (dir: string): Promise<void> => {
    if (matches.length >= limit) return;
    let entries: import('node:fs').Dirent[];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (matches.length >= limit) return;
      const fullPath = path.join(dir, entry.name);
      const relative = path.relative(root, fullPath).replace(/\\/g, '/');
      if (entry.isDirectory()) {
        if (SKIP_SCAN_DIRS.has(entry.name)) continue;
        const reason = matchDeniedIndexPath(relative + '/');
        if (reason) {
          matches.push({ path: relative + '/', reason });
          continue;
        }
        await walk(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const reason = matchDeniedIndexPath(relative);
      if (reason) matches.push({ path: relative, reason });
    }
  };

  await walk(root);
  return matches;
};

export const assertIndexAllowed = async (repoPath: string): Promise<void> => {
  const enforce =
    isCompanyMode() || isTruthyEnv(process.env.GITNEXUS_ENFORCE_INDEX_DENYLIST);
  if (!enforce || isTruthyEnv(process.env.GITNEXUS_ALLOW_INDEX_DENYLIST_BYPASS)) return;

  const denied = await findDeniedIndexFiles(repoPath);
  audit({
    type: 'index-denylist-policy',
    path: path.resolve(repoPath),
    allowed: denied.length === 0,
    deniedCount: denied.length,
    denied: denied.slice(0, 20),
  });
  if (denied.length > 0) {
    const sample = denied.slice(0, 10).map((item) => item.path).join(', ');
    throw new Error(
      `Index denied by GitNexus company mode because sensitive/private-looking files were found: ${sample}. Remove them, add ignore rules, or set GITNEXUS_ALLOW_INDEX_DENYLIST_BYPASS=1 after review.`,
    );
  }
};
