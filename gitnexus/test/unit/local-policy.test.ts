import { afterEach, describe, expect, it } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  assertIndexAllowed,
  assertLocalRepoPathAllowed,
  assertMcpToolAllowed,
  findDeniedIndexFiles,
  isBearerTokenAuthorized,
  isHttpAuthRequired,
  isLocalRepoPathAllowed,
  isMcpToolAllowed,
  isOutboundNetworkAllowed,
  isTruthyEnv,
} from '../../src/security/local-policy.js';
import { quoteCypherIdentifier, quoteCypherString } from '../../src/core/lbug/cypher-escape.js';

const KEYS = [
  'GITNEXUS_ALLOW_OUTBOUND',
  'GITNEXUS_ALLOW_OUTBOUND_PUBLISH',
  'GITNEXUS_ALLOW_OUTBOUND_HF_DOWNLOAD',
  'GITNEXUS_ALLOWED_OUTBOUND_CLONE_URLS',
  'GITNEXUS_ALLOWED_OUTBOUND_URLS',
  'GITNEXUS_ALLOWED_REPO_PATHS',
  'GITNEXUS_ALLOWED_MCP_TOOLS',
  'GITNEXUS_API_TOKEN',
  'GITNEXUS_ALLOW_MCP_WRITE_TOOLS',
  'GITNEXUS_ALLOW_INDEX_DENYLIST_BYPASS',
  'GITNEXUS_COMPANY_MODE',
  'GITNEXUS_ENFORCE_INDEX_DENYLIST',
  'GITNEXUS_REQUIRE_AUTH',
  'GITNEXUS_SECURITY_AUDIT_LOG',
];

describe('local security policy', () => {
  afterEach(() => {
    for (const key of KEYS) delete process.env[key];
  });

  it('treats outbound network features as disabled by default', () => {
    expect(isOutboundNetworkAllowed('publish')).toBe(false);
    expect(isOutboundNetworkAllowed('hf-download')).toBe(false);
  });

  it('supports global and feature-scoped opt-in flags', () => {
    process.env.GITNEXUS_ALLOW_OUTBOUND_PUBLISH = '1';
    expect(isOutboundNetworkAllowed('publish')).toBe(true);
    expect(isOutboundNetworkAllowed('hf-download')).toBe(false);

    delete process.env.GITNEXUS_ALLOW_OUTBOUND_PUBLISH;
    process.env.GITNEXUS_ALLOW_OUTBOUND = 'true';
    expect(isOutboundNetworkAllowed('hf-download')).toBe(true);
  });

  it('supports URL allowlists scoped by feature', () => {
    process.env.GITNEXUS_ALLOWED_OUTBOUND_CLONE_URLS = 'https://github.com/o-buster/';

    expect(isOutboundNetworkAllowed('clone', 'https://github.com/o-buster/private-repo')).toBe(
      true,
    );
    expect(isOutboundNetworkAllowed('clone', 'https://github.com/other/repo')).toBe(false);
    expect(isOutboundNetworkAllowed('wiki-llm', 'https://github.com/o-buster/private-repo')).toBe(
      false,
    );
  });

  it('allows any local repo path outside company mode when no path allowlist is configured', () => {
    expect(isLocalRepoPathAllowed('/tmp/example')).toBe(true);
  });

  it('requires local repo paths to be under an allowlisted root in company mode', () => {
    process.env.GITNEXUS_COMPANY_MODE = '1';
    process.env.GITNEXUS_ALLOWED_REPO_PATHS = '/work/company,/Users/me/src';

    expect(isLocalRepoPathAllowed('/work/company/app')).toBe(true);
    expect(isLocalRepoPathAllowed('/work/company')).toBe(true);
    expect(isLocalRepoPathAllowed('/work/company-evil/app')).toBe(false);
    expect(() => assertLocalRepoPathAllowed('/tmp/outside')).toThrow('not allowed');
  });

  it('parses only explicit truthy env values', () => {
    expect(isTruthyEnv('yes')).toBe(true);
    expect(isTruthyEnv('on')).toBe(true);
    expect(isTruthyEnv('0')).toBe(false);
    expect(isTruthyEnv(undefined)).toBe(false);
  });

  it('requires HTTP auth for non-loopback company-mode serving', () => {
    process.env.GITNEXUS_COMPANY_MODE = '1';
    expect(isHttpAuthRequired('127.0.0.1')).toBe(false);
    expect(isHttpAuthRequired('0.0.0.0')).toBe(true);

    process.env.GITNEXUS_API_TOKEN = 'secret';
    expect(isBearerTokenAuthorized('Bearer secret', undefined, undefined)).toBe(true);
    expect(isBearerTokenAuthorized(undefined, 'secret', undefined)).toBe(true);
    expect(isBearerTokenAuthorized('Bearer wrong', undefined, undefined)).toBe(false);
  });

  it('keeps company-mode MCP read-only by default', () => {
    process.env.GITNEXUS_COMPANY_MODE = '1';
    expect(isMcpToolAllowed('query', true)).toBe(true);
    expect(isMcpToolAllowed('rename', false)).toBe(false);
    expect(() => assertMcpToolAllowed('rename', false)).toThrow('disabled');

    process.env.GITNEXUS_ALLOWED_MCP_TOOLS = 'rename';
    expect(isMcpToolAllowed('rename', false)).toBe(true);
  });

  it('finds sensitive files before indexing when the denylist is enforced', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'gitnexus-policy-'));
    process.env.GITNEXUS_ENFORCE_INDEX_DENYLIST = '1';
    try {
      await fs.writeFile(path.join(tmp, '.env'), 'TOKEN=secret');
      await fs.mkdir(path.join(tmp, 'src'));
      await fs.writeFile(path.join(tmp, 'src', 'index.ts'), 'export const ok = true;');

      const denied = await findDeniedIndexFiles(tmp);
      expect(denied.map((item) => item.path)).toContain('.env');
      await expect(assertIndexAllowed(tmp)).rejects.toThrow('Index denied');

      process.env.GITNEXUS_ALLOW_INDEX_DENYLIST_BYPASS = '1';
      await expect(assertIndexAllowed(tmp)).resolves.toBeUndefined();
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });
});

describe('Cypher escaping helpers', () => {
  it('escapes quotes, backslashes, and newlines in string literals', () => {
    expect(quoteCypherString("a'b\\c\nnext\rline")).toBe("'a''b\\\\c\\nnext\\rline'");
  });

  it('quotes unsafe identifiers with backticks', () => {
    expect(quoteCypherIdentifier('Function')).toBe('Function');
    expect(quoteCypherIdentifier('Template')).toBe('Template');
    expect(quoteCypherIdentifier('Template', true)).toBe('`Template`');
    expect(quoteCypherIdentifier('weird-name`x')).toBe('`weird-name``x`');
  });
});
