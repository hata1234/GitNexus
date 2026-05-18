import fs from 'node:fs';
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
