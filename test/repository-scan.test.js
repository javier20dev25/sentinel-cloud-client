'use strict';
// Hosted repository scans (P0-8): offline verification of the transport against
// the REAL backend contract.
//
// Every test drives a mocked fetch, so nothing here touches the network. The
// responses are copied from the deployed routes in sentinel-cloud:
//   src/app/api/scan/repository/route.ts
//   src/app/api/scan/repository/[scanId]/route.ts
//   src/app/api/scan/repository/[scanId]/result/route.ts
// and the envelope from packages/worker/repository-scan-envelope.js. A test
// written from a guess about the contract certifies nothing, so the shapes
// below are the server's, not invented ones.

const test = require('node:test');
const assert = require('node:assert');

const client = require('../dist/index.js');

const TOKEN = 'sntl_live_style_token_must_never_leak';
const BASE = 'https://sentinel.example.com';
const SCAN_ID = '11111111-2222-4333-8444-555555555555';

// What the worker writes: coverageKnown true implies coverageUnknown false,
// filesScanned is a number, and engine.hash is null when unreported.
function envelope(overrides = {}) {
  return {
    scanId: SCAN_ID,
    status: 'COMPLETED',
    engine: { revision: 'eng-2026.09', hash: null },
    executionComplete: true,
    coverageKnown: true,
    coverageUnknown: false,
    filesScanned: 12,
    filesFailed: 0,
    alertsSeen: 1,
    alertsEnrichFailed: 0,
    signals: [{ ruleId: 'install-script', severity: 'HIGH', file: 'package.json' }],
    ...overrides,
  };
}

function summary(overrides = {}) {
  return {
    scanId: SCAN_ID,
    status: 'PENDING',
    createdAt: '2026-09-30T10:00:00.000Z',
    updatedAt: '2026-09-30T10:00:01.000Z',
    ...overrides,
  };
}

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

/** Replaces global fetch for the duration of one call and records every request. */
function withFetch(handler, run) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return handler(String(url), init, calls.length);
  };
  return Promise.resolve()
    .then(() => run(calls))
    .finally(() => {
      globalThis.fetch = original;
    });
}

const archive = Uint8Array.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);

test('submit posts the gzip body itself, with the optional headers', async () => {
  await withFetch(
    () => json(202, { scanId: SCAN_ID, status: 'PENDING' }),
    async (calls) => {
      const result = await client.submitRepositoryScan(archive, TOKEN, BASE, {
        repoLabel: '  acme/web  ',
        commitSha: 'A1B2C3D4E5F6',
      });

      assert.equal(result.ok, true);
      assert.deepEqual(result.data, { scanId: SCAN_ID, status: 'PENDING' });

      assert.equal(calls.length, 1);
      const call = calls[0];
      assert.equal(call.url, `${BASE}/api/scan/repository`);
      assert.equal(call.init.method, 'POST');
      assert.equal(call.init.headers.Authorization, `Bearer ${TOKEN}`);
      assert.equal(call.init.headers['Content-Type'], 'application/gzip');
      assert.equal(call.init.headers['x-sentinel-repo-label'], 'acme/web', 'label must be trimmed');
      assert.equal(call.init.headers['x-sentinel-commit-sha'], 'a1b2c3d4e5f6', 'sha must be normalized');

      const sent = new Uint8Array(call.init.body);
      assert.deepEqual([...sent], [...archive], 'the archive travels as the raw body, not a JSON wrapper');
    }
  );
});

test('the status enum is the backend one, and QUEUED is only an input alias', () => {
  assert.deepEqual([...client.REPOSITORY_SCAN_STATUSES], [
    'PENDING',
    'PROCESSING',
    'COMPLETED',
    'FAILED',
    'CANCELLED',
  ]);
  assert.equal(client.REPOSITORY_SCAN_STATUSES.includes('QUEUED'), false, 'QUEUED is not a server value');
  assert.equal(client.normalizeRepositoryScanStatus('QUEUED'), 'PENDING', 'QUEUED folds into PENDING');
  assert.equal(client.normalizeRepositoryScanStatus('PENDING'), 'PENDING');
  assert.equal(client.normalizeRepositoryScanStatus('RUNNING'), null);
  assert.equal(client.normalizeRepositoryScanStatus(7), null);
});

test('a status response is validated rather than half-trusted', async () => {
  await withFetch(() => json(200, summary({ status: 'PROCESSING' })), async () => {
    const result = await client.getRepositoryScan(SCAN_ID, TOKEN, BASE);
    assert.equal(result.ok, true);
    assert.equal(result.data.status, 'PROCESSING');
    assert.equal(result.data.createdAt, '2026-09-30T10:00:00.000Z');
  });

  await withFetch(() => json(200, summary({ status: 'RUNNING' })), async () => {
    const result = await client.getRepositoryScan(SCAN_ID, TOKEN, BASE);
    assert.equal(result.ok, false, 'an undefined status must not be reported as a real state');
    assert.equal(result.code, 'SERVER_ERROR');
    assert.match(result.error, /Malformed status response/);
  });

  await withFetch(() => json(200, summary({ createdAt: null })), async () => {
    const result = await client.getRepositoryScan(SCAN_ID, TOKEN, BASE);
    assert.equal(result.ok, false);
    assert.match(result.error, /Malformed status response/);
  });
});

test('a completed scan yields the public envelope', async () => {
  await withFetch(
    () => json(200, { scanId: SCAN_ID, status: 'COMPLETED', result: envelope() }),
    async (calls) => {
      const result = await client.getRepositoryScanResult(SCAN_ID, TOKEN, BASE);
      assert.equal(result.ok, true);
      assert.equal(result.data.signals.length, 1);
      assert.equal(result.data.signals[0].severity, 'HIGH');
      assert.equal(result.data.coverageUnknown, false);
      assert.equal(result.data.engine.hash, null);
      assert.equal(calls[0].url, `${BASE}/api/scan/repository/${SCAN_ID}/result`);
      assert.equal(calls[0].init.method, undefined, 'the result route is a GET');
    }
  );
});

test('a result envelope that contradicts itself is refused', () => {
  assert.equal(
    client.validateRepositoryScanEnvelope(envelope({ coverageUnknown: true })),
    null,
    'coverageUnknown is the inverse of coverageKnown, not an independent claim'
  );
  assert.equal(client.validateRepositoryScanEnvelope(envelope({ coverageKnown: false })), null);
  assert.equal(client.validateRepositoryScanEnvelope(envelope({ filesScanned: '12' })), null);
  assert.equal(client.validateRepositoryScanEnvelope(envelope({ alertsSeen: -1 })), null);
  assert.equal(client.validateRepositoryScanEnvelope(envelope({ signals: {} })), null);
  assert.equal(client.validateRepositoryScanEnvelope(envelope({ engine: { revision: 7, hash: null } })), null);
  assert.equal(client.validateRepositoryScanEnvelope(envelope({ status: 'PROCESSING' })), null);
  assert.ok(client.validateRepositoryScanEnvelope(envelope()), 'the server-shaped envelope must validate');

  // The server itself emits these when the engine reports no counters.
  assert.ok(
    client.validateRepositoryScanEnvelope(
      envelope({ coverageKnown: false, coverageUnknown: true, filesScanned: null })
    ),
    'unknown coverage is a legitimate state and must survive validation'
  );
});

test('a result requested before COMPLETED is retryable, not a hard failure', async () => {
  await withFetch(() => json(409, { error: 'Scan is PROCESSING; result is not available.', status: 'PROCESSING' }), async () => {
    const result = await client.getRepositoryScanResult(SCAN_ID, TOKEN, BASE);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'UNAVAILABLE');
    assert.equal(result.retryable, true, 'a 409 resolves itself once the scan finishes');
    assert.equal(result.status, 409);
    assert.equal(result.scanStatus, 'PROCESSING');
  });
});

test('a FAILED scan carries its status rather than a bare server error', async () => {
  await withFetch(() => json(200, summary({ status: 'FAILED', error: 'engine crashed' })), async () => {
    const result = await client.getRepositoryScan(SCAN_ID, TOKEN, BASE);
    assert.equal(result.ok, true);
    assert.equal(result.data.status, 'FAILED');
    assert.equal(result.data.error, 'engine crashed');
  });
});

test('an invalid or expired token is UNAUTHORIZED and never retryable', async () => {
  await withFetch(() => json(401, { error: 'Invalid or expired API token.' }), async () => {
    for (const call of [
      () => client.submitRepositoryScan(archive, TOKEN, BASE),
      () => client.getRepositoryScan(SCAN_ID, TOKEN, BASE),
      () => client.getRepositoryScanResult(SCAN_ID, TOKEN, BASE),
    ]) {
      const result = await call();
      assert.equal(result.ok, false);
      assert.equal(result.code, 'UNAUTHORIZED');
      assert.equal(result.status, 401);
      assert.equal(result.retryable, false, 'retrying a bad token forever is how a CLI hangs');
    }
  });
});

test('a throttle is RATE_LIMITED and keeps the Retry-After hint', async () => {
  await withFetch(
    () => json(429, { error: 'Rate limit exceeded. Retry shortly.' }, { 'retry-after': '30' }),
    async () => {
      const result = await client.submitRepositoryScan(archive, TOKEN, BASE);
      assert.equal(result.ok, false);
      assert.equal(result.code, 'RATE_LIMITED');
      assert.equal(result.retryable, true);
      assert.equal(result.retryAfterSeconds, 30);
      assert.equal(result.serverCode, undefined, 'no PULSOS_EXHAUSTED means throttle, not quota');
    }
  );
});

test('an exhausted monthly quota is QUOTA_EXCEEDED, distinct from a throttle', async () => {
  await withFetch(
    () =>
      json(429, {
        error: 'Monthly API quota exhausted.',
        code: 'PULSOS_EXHAUSTED',
        used: 500,
        limit: 500,
      }),
    async () => {
      const result = await client.submitRepositoryScan(archive, TOKEN, BASE);
      assert.equal(result.ok, false);
      assert.equal(result.code, 'QUOTA_EXHAUSTED');
      assert.equal(result.serverCode, 'PULSOS_EXHAUSTED');
      assert.equal(result.used, 500);
      assert.equal(result.limit, 500);
    }
  );
});

test('a forbidden request keeps the server code and is not retryable', async () => {
  await withFetch(() => json(403, { error: 'remote_scan not enabled', code: 'CAPABILITY_MISSING' }), async () => {
    const result = await client.submitRepositoryScan(archive, TOKEN, BASE);
    assert.equal(result.code, 'FORBIDDEN');
    assert.equal(result.retryable, false);
    assert.equal(result.serverCode, 'CAPABILITY_MISSING');
  });
});

test('bad requests map to INVALID_REQUEST and dependency failures to UNAVAILABLE', async () => {
  const cases = [
    [400, 'INVALID_REQUEST', false],
    [413, 'INVALID_REQUEST', false],
    [415, 'INVALID_REQUEST', false],
    [404, 'INVALID_REQUEST', false],
    [502, 'UNAVAILABLE', true],
    [503, 'UNAVAILABLE', true],
    [500, 'SERVER_ERROR', true],
  ];
  for (const [status, code, retryable] of cases) {
    await withFetch(() => json(status, { error: `status ${status}` }), async () => {
      const result = await client.submitRepositoryScan(archive, TOKEN, BASE);
      assert.equal(result.ok, false);
      assert.equal(result.code, code, `HTTP ${status} must map to ${code}`);
      assert.equal(result.retryable, retryable, `HTTP ${status} retryability`);
    });
  }
});

test('a 502 with a non-JSON body still classifies instead of throwing', async () => {
  await withFetch(
    () => new Response('<html>bad gateway</html>', { status: 502, headers: { 'content-type': 'text/html' } }),
    async () => {
      const result = await client.getRepositoryScan(SCAN_ID, TOKEN, BASE);
      assert.equal(result.ok, false);
      assert.equal(result.code, 'UNAVAILABLE');
      assert.equal(result.status, 502);
    }
  );
});

test('a malformed success body is refused rather than half-trusted', async () => {
  await withFetch(() => json(202, {}), async () => {
    const result = await client.submitRepositoryScan(archive, TOKEN, BASE);
    assert.equal(result.ok, false);
    assert.match(result.error, /Malformed submit response/);
  });

  await withFetch(() => json(202, { scanId: SCAN_ID, status: 'MOSTLY_DONE' }), async () => {
    const result = await client.submitRepositoryScan(archive, TOKEN, BASE);
    assert.equal(result.ok, false);
    assert.match(result.error, /Malformed submit response/);
  });

  await withFetch(() => json(200, { scanId: SCAN_ID, status: 'COMPLETED', result: envelope({ filesFailed: null }) }), async () => {
    const result = await client.getRepositoryScanResult(SCAN_ID, TOKEN, BASE);
    assert.equal(result.ok, false);
    assert.match(result.error, /Malformed result response/);
  });

  // A body whose scanId disagrees with the requested one is not this scan's result.
  await withFetch(
    () => json(200, { scanId: '99999999-2222-4333-8444-555555555555', status: 'COMPLETED', result: envelope() }),
    async () => {
      const result = await client.getRepositoryScanResult(SCAN_ID, TOKEN, BASE);
      assert.equal(result.ok, false);
      assert.match(result.error, /Malformed result response/);
    }
  );

  await withFetch(() => new Response('not json at all', { status: 200 }), async () => {
    const result = await client.getRepositoryScan(SCAN_ID, TOKEN, BASE);
    assert.equal(result.ok, false);
    assert.match(result.error, /Malformed status response/);
  });
});

test('a malformed scanId never reaches the network', async () => {
  await withFetch(() => json(200, summary()), async (calls) => {
    for (const bad of ['../../etc/passwd', 'not-a-uuid', '', '11111111-2222-4333-8444-555555555555/../x']) {
      const result = await client.getRepositoryScan(bad, TOKEN, BASE);
      assert.equal(result.ok, false, `"${bad}" must be refused`);
      assert.equal(result.code, 'INVALID_REQUEST');
    }
    assert.equal(calls.length, 0, 'nothing may be sent before the id is validated');
  });
  assert.equal(client.isSafeScanId(SCAN_ID), true);
  assert.equal(client.isSafeScanId('not-a-uuid'), false);
  assert.equal(client.isSafeScanId(null), false);
});

test('a bad body is refused locally instead of spending an upload', async () => {
  await withFetch(() => json(202, { scanId: SCAN_ID, status: 'PENDING' }), async (calls) => {
    const empty = await client.submitRepositoryScan(new Uint8Array(0), TOKEN, BASE);
    assert.equal(empty.code, 'INVALID_REQUEST');
    assert.match(empty.error, /empty/);

    const oversized = await client.submitRepositoryScan(
      new Uint8Array(client.REPOSITORY_SCAN_MAX_ARCHIVE_BYTES + 1),
      TOKEN,
      BASE
    );
    assert.equal(oversized.code, 'INVALID_REQUEST');
    assert.match(oversized.error, /too large/);

    const wrongType = await client.submitRepositoryScan('not-bytes', TOKEN, BASE);
    assert.equal(wrongType.code, 'INVALID_REQUEST', 'a non-buffer must never be coerced into an upload');
    assert.match(wrongType.error, /Uint8Array/);

    const badSha = await client.submitRepositoryScan(archive, TOKEN, BASE, { commitSha: 'not-a-sha' });
    assert.equal(badSha.code, 'INVALID_REQUEST');

    const noToken = await client.submitRepositoryScan(archive, '', BASE);
    assert.equal(noToken.code, 'UNAUTHORIZED');

    assert.equal(calls.length, 0);
  });
});

test('a cleartext endpoint is refused before the token leaves the process', async () => {
  await withFetch(() => json(202, { scanId: SCAN_ID, status: 'PENDING' }), async (calls) => {
    const insecure = 'http://sentinel.example.com';
    await assert.rejects(() => client.submitRepositoryScan(archive, TOKEN, insecure), /insecure/i);
    await assert.rejects(() => client.getRepositoryScan(SCAN_ID, TOKEN, insecure), /insecure/i);
    await assert.rejects(() => client.getRepositoryScanResult(SCAN_ID, TOKEN, insecure), /insecure/i);
    await assert.rejects(
      () => client.getRepositoryScan(SCAN_ID, TOKEN, 'http://localhost.example.com'),
      /insecure/i
    );
    assert.equal(calls.length, 0, 'no authenticated request may be attempted over http');
  });

  // Loopback stays usable for local development.
  await withFetch(() => json(202, { scanId: SCAN_ID, status: 'PENDING' }), async (calls) => {
    const result = await client.submitRepositoryScan(archive, TOKEN, 'http://127.0.0.1:3000');
    assert.equal(result.ok, true);
    assert.equal(calls[0].url, 'http://127.0.0.1:3000/api/scan/repository');
  });
});

test('the bearer token never appears in an error, a body or a thrown message', async () => {
  const echo = `token=${TOKEN} rejected`;
  await withFetch(() => json(403, { error: echo, code: 'CAPABILITY_MISSING' }), async () => {
    const result = await client.submitRepositoryScan(archive, TOKEN, BASE);
    assert.equal(result.code, 'FORBIDDEN');
    assert.doesNotMatch(result.error, new RegExp(TOKEN), 'a server echo must be scrubbed');
    assert.match(result.error, /\[redacted\]/);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(TOKEN), 'nothing in the result may carry it');
  });

  await withFetch(() => json(401, { error: echo }), async () => {
    const result = await client.getRepositoryScan(SCAN_ID, TOKEN, BASE);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(TOKEN));
  });

  await withFetch(
    () => {
      throw new Error(`connect ECONNREFUSED for ${TOKEN}`);
    },
    async () => {
      const result = await client.getRepositoryScan(SCAN_ID, TOKEN, BASE);
      assert.equal(result.code, 'UNAVAILABLE', 'a transport failure is retryable');
      assert.doesNotMatch(result.error, new RegExp(TOKEN), 'a transport message must be scrubbed too');
    }
  );

  // The insecure-URL guard names the URL, never the credential.
  await assert.rejects(() => client.getRepositoryScan(SCAN_ID, TOKEN, 'http://evil.example.com'), (err) => {
    assert.doesNotMatch(err.message, new RegExp(TOKEN));
    return true;
  });
});

test('the polling helper stops at a terminal state instead of spinning', async () => {
  const seen = [];
  await withFetch(
    (url, _init, n) => {
      if (url.endsWith('/result')) return json(200, { scanId: SCAN_ID, status: 'COMPLETED', result: envelope() });
      if (n <= 2) return json(200, summary({ status: n === 1 ? 'PENDING' : 'PROCESSING' }));
      return json(200, summary({ status: 'COMPLETED' }));
    },
    async (calls) => {
      const statuses = [];
      const result = await client.waitForRepositoryScan(SCAN_ID, TOKEN, BASE, {
        pollIntervalMs: 1,
        waitTimeoutMs: 5000,
        onStatus: (s) => statuses.push(s.status),
      });
      assert.equal(result.ok, true);
      assert.equal(result.envelope.scanId, SCAN_ID);
      assert.deepEqual(statuses, ['PENDING', 'PROCESSING', 'COMPLETED'], 'only transitions are reported');
      assert.equal(calls.length, 4, 'three polls plus the result fetch');
    }
  );

  await withFetch(() => json(200, summary({ status: 'FAILED', error: 'engine crashed' })), async (calls) => {
    const result = await client.waitForRepositoryScan(SCAN_ID, TOKEN, BASE, { pollIntervalMs: 1 });
    assert.equal(result.ok, false);
    assert.equal(result.scanStatus, 'FAILED');
    assert.equal(result.error, 'engine crashed');
    assert.equal(calls.length, 1, 'a terminal failure must not be polled again');
  });

  await withFetch(() => json(200, summary({ status: 'PROCESSING' })), async (calls) => {
    const result = await client.waitForRepositoryScan(SCAN_ID, TOKEN, BASE, {
      pollIntervalMs: 1,
      waitTimeoutMs: 12,
    });
    assert.equal(result.ok, false);
    assert.equal(result.code, 'UNAVAILABLE');
    assert.match(result.error, /did not reach a terminal state/);
    assert.ok(calls.length >= 1);
  });
});

test('the polling helper honours a caller abort', async () => {
  const controller = new AbortController();
  controller.abort();
  await withFetch(() => json(200, summary()), async (calls) => {
    const result = await client.waitForRepositoryScan(SCAN_ID, TOKEN, BASE, {
      pollIntervalMs: 1,
      signal: controller.signal,
    });
    assert.equal(result.ok, false);
    assert.match(result.error, /aborted/);
    assert.equal(calls.length, 0, 'an already-aborted wait must not start polling');
  });
});

test('no cancel route is invented: the backend deploys none', () => {
  // repository_scans has a cancel RPC but no HTTP handler. Exposing
  // cancelRepositoryScan here would hand callers a function that cannot work.
  assert.equal(client.cancelRepositoryScan, undefined);
  for (const name of Object.keys(client)) {
    assert.doesNotMatch(name, /cancel/i, `unexpected cancel-shaped export: ${name}`);
  }
});