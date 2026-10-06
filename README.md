# @sentinel/cloud-client

Authenticated client for the Sentinel Cloud API.

This package is **transport and protocol only**. It contains no detection engine,
no rules, no scanners and no proprietary analysis logic. It is the piece that a
public client needs in order to talk to Sentinel Cloud without shipping any of
Sentinel's internals.

- Apache-2.0, relicensed by the sole copyright holder. See [NOTICE](NOTICE).
- Zero runtime dependencies. Node.js builtins only.
- Verified to pull nothing from the proprietary codebase at runtime.

## Install

```bash
npm install -g @sentinel/cloud-client
```

Requires Node.js 20 or newer.

## Usage

```js
const {
  loginWithToken,
  loadSession,
  fetchCapabilities,
  fetchUsage,
  fetchRemoteScan,
  validateRemoteScanResult,
} = require('@sentinel/cloud-client');

const baseUrl = process.env.SENTINEL_CLOUD_URL || 'https://sentinel.example.com';

// Validates the token against the server and persists a session.
const login = await loginWithToken(process.env.SENTINEL_CLOUD_API_TOKEN, baseUrl);
if (!login.ok) throw new Error(login.error);

// Later, in another process:
const session = loadSession();
if (session) {
  console.log(session.planLabel, session.capabilities.remote_scan);
}
```

### Environment

| Variable | Purpose |
| --- | --- |
| `SENTINEL_CLOUD_URL` | Base URL of the Sentinel Cloud deployment. |
| `SENTINEL_CLOUD_API_TOKEN` | Bearer token. Never send it anywhere else. |

The session is stored outside any repository, at `~/.sentinel/auth.json`, with
`0600` permissions on POSIX platforms. On Windows, permissions are governed by
the file's ACL.

## Safety properties

These are covered by tests in `test/index.test.js`, and they are the reason this
package can be published separately:

- **A bearer token never travels in the clear.** `assertSecureBaseUrl` rejects
  any `http://` endpoint that is not loopback. `http://localhost` and
  `http://127.0.0.1` remain allowed for local development.
- **Lookalike hosts are not mistaken for loopback.** `localhost.example.com`
  and `127.0.0.1.example.com` are treated as remote.
- **A malformed URL fails loudly** rather than falling back to a default host.
- **Credentials stay out of repositories.** The session path is derived from the
  home directory, never from the package or the current working directory.
- **A partial session is never trusted.** Every capability key must be a boolean
  and every limit a number; an incomplete payload is rejected outright instead of
  being merged with defaults.
- **Untrusted responses are validated before use.** Scan results are range
  checked (`riskScore` 0-100, `confidence` 0-1), the status must be terminal, and
  each finding must carry a severity and title.
- **Corrupt session files degrade to "no session"**, never to a crash.
- **The repository-scan routes refuse to carry a token in the clear.** The
  secure-base-URL guard runs inside every call, so an `http://` endpoint is
  rejected before a socket is opened rather than relying on the caller to have
  checked first.
- **A bearer token cannot reach an error message.** Every server string and
  every transport error is scrubbed, so an echoing server or a proxy that
  reflects the request cannot leak the credential into a log.
- **A contradictory envelope is refused.** `coverageKnown` and `coverageUnknown`
  are inverses on the server, so a payload where they disagree is corrupt and is
  rejected instead of being shown to a user as a coverage statement. Unknown
  coverage (`coverageKnown: false`, `filesScanned: null`) is a legitimate state
  and survives.
- **A terminal state is never re-polled**, and an already-aborted wait never
  starts polling.

## Hosted repository scans

Three routes, verified against the deployed Sentinel Cloud API:

| Call | Route | Answers |
| --- | --- | --- |
| `submitRepositoryScan(archive, token, baseUrl, opts)` | `POST /api/scan/repository` | `202 {scanId, status:'PENDING'}` |
| `getRepositoryScan(scanId, token, baseUrl, opts)` | `GET /api/scan/repository/:scanId` | `200 {scanId, status, createdAt, updatedAt, error?}` |
| `getRepositoryScanResult(scanId, token, baseUrl, opts)` | `GET /api/scan/repository/:scanId/result` | `200 {scanId, status, result}` |
| `waitForRepositoryScan(scanId, token, baseUrl, opts)` | *(the two GETs, polled)* | terminal summary plus envelope |

```js
const { submitRepositoryScan, waitForRepositoryScan } = require('@sentinel/cloud-client');

// The body is the gzip tar archive itself, not a JSON wrapper. Packing lives in
// the sibling `sentinel-audit` package; this one deliberately has no packer.
const { readFileSync } = require('node:fs');
const archive = new Uint8Array(readFileSync('/tmp/repo.tar.gz'));

const submitted = await submitRepositoryScan(archive, token, baseUrl, {
  repoLabel: 'acme/web',
  commitSha: 'a1b2c3d',
});
if (!submitted.ok) throw new Error(`${submitted.code}: ${submitted.error}`);

const done = await waitForRepositoryScan(submitted.data.scanId, token, baseUrl);
if (done.ok) {
  for (const signal of done.envelope.signals) {
    console.log(signal.severity, signal.ruleId, signal.file);
  }
}
```

### Status values

The backend enum is exactly `PENDING | PROCESSING | COMPLETED | FAILED | CANCELLED`,
exported as `REPOSITORY_SCAN_STATUSES`. There is no `QUEUED` state:
`normalizeRepositoryScanStatus('QUEUED')` returns `PENDING` so a caller using
the older spelling is not broken, and `QUEUED` is never sent to the server.

### Error taxonomy

Every failure resolves to `ok: false` with a stable `code`, so callers branch
on intent instead of on HTTP status codes:

| Code | HTTP | Retryable |
| --- | --- | --- |
| `UNAUTHORIZED` | 401 | no |
| `FORBIDDEN` | 403 | no |
| `RATE_LIMITED` | 429 without `PULSOS_EXHAUSTED` | yes |
| `QUOTA_EXCEUSTED` | 429 with `code: PULSOS_EXHAUSTED` | yes |
| `INVALID_REQUEST` | 400, 413, 415, 404 | no |
| `UNAVAILABLE` | 409, 502, 503, 504, transport failure | yes |
| `SERVER_ERROR` | other 5xx, malformed 2xx body | yes |

`retryable` is explicit on every error. `used`, `limit` and `retryAfterSeconds`
are carried through from the server so a caller can show real numbers instead
of inventing them. `scanStatus` is present when the server told us which state
the scan was in (409, or a terminal `FAILED`/`CANCELLED`).

404 is mapped to `INVALID_REQUEST` rather than to `UNAVAILABLE` on purpose. The
backend answers 404 for an absent scan, a non-UUID id, and someone else's scan
alike, and none of those can become a 200 — classifying them as retryable is how
a CLI burns its whole poll budget on a 404. The HTTP status is still on the
result for callers that need to tell the cases apart.

## What is not here

- **No cancel.** `repository_scans` has a cancel RPC behind the authenticated
  surface, but no cancel HTTP route is deployed, so this package exposes no
  `cancelRepositoryScan`. A test asserts its absence on purpose: a client that
  offers a cancel it cannot perform is worse than one that offers none.
- **No archive packer.** Packing a working tree into the gzip tar the endpoint
  expects lives in the sibling `sentinel-audit` package. This package never
  reads the caller's source tree.
- No interactive `login` command. `loginWithToken` expects an already-provisioned
  token; no OAuth or device-code flow has been verified end to end.
- Nothing derived from the proprietary engine. Files that import the engine at
  runtime were deliberately excluded and are not relicensed.

## Scripts

```bash
npm run build   # tsc -> dist/ (CommonJS + .d.ts)
npm test        # node --test, offline only
```

`npm test` performs no network access.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
