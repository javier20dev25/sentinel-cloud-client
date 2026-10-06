'use strict';
// Offline verification of the properties that matter for a package this
// deliberately extracted from a proprietary codebase.
//
// Nothing here touches the network. The point is to prove three things: the
// transport refuses to carry a bearer token in the clear, the credential path
// is outside any repository, and the runtime dependency graph reached the
// proprietary engine is empty.

const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const { builtinModules } = require('node:module');

const client = require('../dist/index.js');

const BUILTINS = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);
const PACKAGE_ROOT = path.resolve(__dirname, '..');

// The minimal payload the validator accepts. Read from the validator itself at
// src/index.ts:419 rather than assumed, because a test written from a guess is
// a test that certifies nothing.
const WELL_FORMED_SCAN = {
  status: 'complete',
  riskScore: 50,
  confidence: 0.5,
  verdict: 'SUSPICIOUS',
  risk: 'medium',
  findings: [],
};

// Session validation is deliberately exhaustive: every capability key must be a
// boolean and every limit a number. A partially populated session is treated as
// untrustworthy rather than merged with defaults. Keys mirror CAPABILITY_KEYS /
// LIMIT_KEYS in src/index.ts, and a test below fails if either list grows.
const CAPABILITY_KEYS = [
  'content_intel_lookup',
  'remote_scan',
  'oracle_integration',
  'offline_sync',
  'sbom',
  'ai_review',
];
const LIMIT_KEYS = ['apiRequestsPerMonth', 'maxRepos', 'retentionDays'];

function validSession(overrides = {}) {
  const capabilities = {};
  for (const key of CAPABILITY_KEYS) capabilities[key] = true;
  const limits = {};
  for (const key of LIMIT_KEYS) limits[key] = 1;
  return {
    token: 'sntl_testtoken',
    user: 'dev@example.com',
    subjectId: 'tenant-1',
    plan: 'PRO_QUANTUM',
    planLabel: 'Pro Quantum',
    planActive: true,
    landingUrl: null,
    expiresAt: new Date(Date.now() + 60000).toISOString(),
    issuedAt: new Date().toISOString(),
    capabilities,
    limits,
    fetchedAt: new Date().toISOString(),
    ...overrides,
  };
}

test('a cleartext remote endpoint is refused', () => {
  assert.throws(() => client.assertSecureBaseUrl('http://sentinel.example.com'), /insecure/i);
  assert.throws(() => client.assertSecureBaseUrl('http://10.0.0.5'), /insecure/i);
});

test('https and loopback are accepted so local development still works', () => {
  assert.equal(client.assertSecureBaseUrl('https://sentinel.example.com'), 'https://sentinel.example.com');
  assert.equal(client.assertSecureBaseUrl('http://localhost:3000'), 'http://localhost:3000');
  assert.equal(client.assertSecureBaseUrl('http://127.0.0.1:8080'), 'http://127.0.0.1:8080');
  assert.equal(client.isLoopbackHost('127.0.0.9'), true);
  assert.equal(client.isLoopbackHost('example.com'), false);
});

test('a lookalike host is not mistaken for loopback', () => {
  assert.equal(client.isLoopbackHost('localhost.example.com'), false);
  assert.equal(client.isLoopbackHost('127.0.0.1.example.com'), false);
  assert.equal(client.isLoopbackHost('notlocalhost'), false);
  assert.throws(() => client.assertSecureBaseUrl('http://localhost.example.com'), /insecure/i);
});

test('an unparseable endpoint fails instead of degrading to a default', () => {
  assert.throws(() => client.assertSecureBaseUrl('not a url'), /Invalid Sentinel Cloud base URL/);
  assert.throws(() => client.assertSecureBaseUrl(''), /Invalid Sentinel Cloud base URL/);
});

test('the session path is outside the package and outside any repository', () => {
  const home = os.homedir();
  assert.ok(
    client.SESSION_PATH.startsWith(home + path.sep),
    `session must live under the home directory, got ${client.SESSION_PATH}`
  );
  assert.ok(
    !client.SESSION_PATH.startsWith(PACKAGE_ROOT + path.sep),
    'session must never be written inside the package or its repository'
  );
  assert.equal(path.basename(client.SESSION_PATH), 'auth.json');
});

test('a session round-trips through a temporary directory and clears', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scc-test-'));
  try {
    client.saveSession(validSession(), { sessionDir: dir });
    const written = path.join(dir, 'auth.json');
    assert.ok(fs.existsSync(written), 'session must be persisted outside the repo');

    const writtenStat = fs.statSync(written);
    if (process.platform !== 'win32') {
      // On POSIX the 0o600 mode is honoured. On Windows Node ignores the mode
      // and file permissions come from the ACL instead, so asserting a bitmask
      // here would be asserting something untrue on this host.
      assert.equal(writtenStat.mode & 0o777, 0o600, 'the token file must not be group/world readable');
    } else {
      assert.ok(writtenStat.mode > 0, 'file must still be stat-able on Windows');
    }

    const loaded = client.loadSession({ sessionDir: dir });
    assert.ok(loaded, 'a well-formed session must survive the round-trip');
    assert.equal(loaded.subjectId, 'tenant-1');
    assert.equal(loaded.token, 'sntl_testtoken');
    assert.equal(loaded.capabilities.remote_scan, true);

    client.clearSession({ sessionDir: dir });
    assert.equal(client.loadSession({ sessionDir: dir }), null);
    assert.equal(fs.existsSync(written), false, 'clearSession must delete the token, not merely ignore it');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('clearing an absent session is a no-op rather than a throw', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scc-test-'));
  try {
    assert.doesNotThrow(() => client.clearSession({ sessionDir: dir }));
    assert.doesNotThrow(() => client.loadSession({ sessionDir: path.join(dir, 'nope') }));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('session validation refuses to trust a partially populated payload', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scc-test-'));
  const file = path.join(dir, 'auth.json');
  const load = (value) => {
    fs.writeFileSync(file, JSON.stringify(value));
    return client.loadSession({ sessionDir: dir });
  };
  try {
    assert.ok(load(validSession()), 'baseline must load');

    assert.equal(load({ ...validSession(), expiresAt: Date.now() + 60000, fetchedAt: Date.now() }), null,
      'numeric timestamps are not a valid session');
    assert.equal(load({ ...validSession(), expiresAt: null }), null, 'expiry is required');

    const { subjectId, ...noSubject } = validSession();
    assert.equal(load(noSubject), null, 'a session without a subject is unusable');
    assert.equal(load({ ...validSession(), token: '' }), null, 'an empty token is not a session');

    assert.equal(load({ ...validSession(), capabilities: {} }), null,
      'an empty capability map is rejected, not merged with defaults');
    const partial = validSession();
    delete partial.capabilities.sbom;
    assert.equal(load(partial), null, 'a missing capability key invalidates the session');
    assert.equal(load({ ...validSession(), capabilities: { ...validSession().capabilities, ai_review: 'yes' } }), null,
      'a non-boolean capability invalidates the session');
    assert.equal(load({ ...validSession(), limits: { apiRequestsPerMonth: 1, maxRepos: 1 } }), null,
      'a missing limit invalidates the session');
    assert.equal(load({ ...validSession(), limits: { ...validSession().limits, retentionDays: '90' } }), null,
      'a non-numeric limit invalidates the session');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the capability and limit key lists are not silently extended', () => {
  // If src/index.ts gains a capability or limit, this fails on purpose: a new key
  // changes what a valid session looks like, and the fixtures above would be
  // certifying a payload the server can no longer produce. Read the real arrays
  // out of the compiled output rather than trusting a copy in this file.
  const compiled = fs.readFileSync(path.join(PACKAGE_ROOT, 'dist', 'index.js'), 'utf8');
  const readArray = (name) => {
    const match = compiled.match(new RegExp(`const ${name} = \\[([\\s\\S]*?)\\]`));
    assert.ok(match, `${name} must still be a literal array in the compiled output`);
    return [...match[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
  };

  assert.deepEqual(readArray('CAPABILITY_KEYS'), CAPABILITY_KEYS,
    'CAPABILITY_KEYS changed; update validSession() and re-check session validation');
  assert.deepEqual(readArray('LIMIT_KEYS'), LIMIT_KEYS,
    'LIMIT_KEYS changed; update validSession() and re-check session validation');
});

test('a corrupt session file is treated as no session, never as a crash', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scc-test-'));
  try {
    fs.writeFileSync(path.join(dir, 'auth.json'), '{ this is not json');
    assert.equal(client.loadSession({ sessionDir: dir }), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('an incomplete remote-scan payload is rejected rather than half-trusted', () => {
  assert.equal(client.validateRemoteScanResult({ status: 'processing' }), null, 'an unfinished scan is not a result');
  assert.equal(client.validateRemoteScanResult({}), null);
  assert.equal(client.validateRemoteScanResult(null), null);
  const good = client.validateRemoteScanResult(WELL_FORMED_SCAN);
  assert.ok(good, 'a well-formed complete result must validate');
  assert.equal(good.verdict, 'SUSPICIOUS');
});

test('a result missing its findings array is rejected', () => {
  const { findings, ...withoutFindings } = WELL_FORMED_SCAN;
  assert.equal(withoutFindings.findings, undefined);
  assert.equal(client.validateRemoteScanResult(withoutFindings), null);
  assert.equal(client.validateRemoteScanResult({ ...WELL_FORMED_SCAN, findings: null }), null);
});

test('a finding missing severity or title is rejected', () => {
  assert.equal(
    client.validateRemoteScanResult({ ...WELL_FORMED_SCAN, findings: [{ title: 'x' }] }),
    null
  );
  assert.equal(
    client.validateRemoteScanResult({ ...WELL_FORMED_SCAN, findings: [{ severity: 'HIGH' }] }),
    null
  );
  assert.ok(client.validateRemoteScanResult({ ...WELL_FORMED_SCAN, findings: [] }), 'an empty finding list is valid');
});

test('an out-of-range risk score or confidence is rejected', () => {
  assert.equal(client.validateRemoteScanResult({ ...WELL_FORMED_SCAN, riskScore: 101 }), null);
  assert.equal(client.validateRemoteScanResult({ ...WELL_FORMED_SCAN, riskScore: -1 }), null);
  assert.equal(client.validateRemoteScanResult({ ...WELL_FORMED_SCAN, confidence: 2 }), null);
  assert.equal(client.validateRemoteScanResult({ ...WELL_FORMED_SCAN, confidence: -0.1 }), null);
});

test('an unknown verdict or risk band is rejected', () => {
  assert.equal(client.validateRemoteScanResult({ ...WELL_FORMED_SCAN, verdict: 'PROBABLY_FINE' }), null);
  assert.equal(client.validateRemoteScanResult({ ...WELL_FORMED_SCAN, risk: 'spicy' }), null);
});

test('the runtime dependency graph contains no proprietary module', () => {
  const foreign = [];
  for (const loaded of Object.keys(require.cache)) {
    if (BUILTINS.has(loaded)) continue;
    if (loaded.startsWith(PACKAGE_ROOT)) continue;
    foreign.push(loaded);
  }
  assert.deepEqual(foreign, [], `loading the client must not pull in ${foreign.join(', ')}`);
});

test('the compiled output carries no license text from the original work', () => {
  const compiled = fs.readFileSync(path.join(PACKAGE_ROOT, 'dist', 'index.js'), 'utf8');
  for (const marker of ['Business Source License', 'MariaDB', 'Additional Use Grant', 'Change License']) {
    assert.ok(!compiled.includes(marker), `dist must not carry "${marker}"`);
  }
});

test('no runtime dependency is declared', () => {
  const pkg = require('../package.json');
  assert.deepEqual(pkg.dependencies, {}, 'the transport must stay dependency-free');
  assert.equal(pkg.license, 'Apache-2.0');
});
