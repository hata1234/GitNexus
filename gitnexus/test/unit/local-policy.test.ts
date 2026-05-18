import { afterEach, describe, expect, it } from 'vitest';
import {
  assertLocalRepoPathAllowed,
  isLocalRepoPathAllowed,
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
  'GITNEXUS_COMPANY_MODE',
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
