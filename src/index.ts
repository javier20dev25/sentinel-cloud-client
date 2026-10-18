import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import { randomUUID } from 'crypto';

/**
 * Closed enum of dependency signals accepted by the contribution endpoint.
 *
 * Inlined from the Sentinel CLI original, which reached the proprietary scanner
 * through a type-only import chain.  Keeping the type local removes that chain
 * entirely so this package has no dependency on proprietary code, not even at
 * the type level.
 */
export const CONTRIBUTE_SIGNALS = [
    'install_script',
    'network',
    'credential_access',
    'child_process',
    'runtime_execution',
    'obfuscation',
    'encoded_payload',
    'filesystem',
    'binary',
    'download',
    'config_tampering',
    'suspicious_url',
] as const;

export type ContributeSignal = (typeof CONTRIBUTE_SIGNALS)[number];

export const SESSION_PATH = path.join(os.homedir(), '.sentinel', 'auth.json');

export interface CapabilityMap {
    content_intel_lookup: boolean;
    remote_scan: boolean;
    oracle_integration: boolean;
    offline_sync: boolean;
    sbom: boolean;
    ai_review: boolean;
    contribute?: boolean;
}

export interface CapabilityLimits {
    apiRequestsPerMonth: number;
    // Commercial alias for the same allowance: one full-engine API call is
    // sold as a "pulso" (pulse). Optional so sessions minted before the field
    // existed keep validating; fall back to apiRequestsPerMonth when absent.
    pulsesPerMonth?: number;
    maxRepos: number;
    retentionDays: number;
}

/** Monthly "pulso" allowance, resolving the commercial alias when present. */
export function pulsesPerMonthOf(limits: Pick<CapabilityLimits, 'apiRequestsPerMonth' | 'pulsesPerMonth'>): number {
    return typeof limits.pulsesPerMonth === 'number' && limits.pulsesPerMonth >= 0
        ? limits.pulsesPerMonth
        : limits.apiRequestsPerMonth;
}

export interface CapabilitiesEnvelope {
    user: string | null;
    subjectId: string;
    plan: string;
    planLabel: string;
    /** True only when the subject holds an active paid entitlement. null when the server does not advertise it. */
    planActive: boolean | null;
    /** Public plan-landing URL advertised by the server (origin + /#pricing). */
    landingUrl: string | null;
    expiresAt: string;
    issuedAt: string;
    capabilities: CapabilityMap;
    limits: CapabilityLimits;
}

export interface Session {
    token: string;
    user: string | null;
    subjectId: string;
    plan: string;
    planLabel: string;
    /** True only when the subject holds an active paid entitlement. null for legacy sessions. */
    planActive: boolean | null;
    /** Public plan-landing URL advertised by the server (origin + /#pricing). */
    landingUrl: string | null;
    expiresAt: string;
    capabilities: CapabilityMap;
    limits: CapabilityLimits;
    fetchedAt: string;
}

export interface CloudClientOptions {
    sessionDir?: string;
    env?: NodeJS.ProcessEnv;
}

const CAPABILITY_KEYS: ReadonlyArray<keyof CapabilityMap> = [
    'content_intel_lookup',
    'remote_scan',
    'oracle_integration',
    'offline_sync',
    'sbom',
    'ai_review',
];

const LIMIT_KEYS: ReadonlyArray<keyof CapabilityLimits> = [
    'apiRequestsPerMonth',
    'maxRepos',
    'retentionDays',
];

const DEFAULT_TIMEOUT_MS = 10000;

const LOOKUP_TIMEOUT_MS = 5000;

const SIGNATURE_PATTERN = /^[0-9a-f]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null;
}

function isString(value: unknown): value is string {
    return typeof value === 'string';
}

/** Normalizes the optional subscription state: rejects wrong types, maps undefined -> null. */
function normalizePlanActive(value: unknown): boolean | null {
    if (value === true || value === false) return value;
    return null;
}

/** Normalizes the optional landing URL: rejects wrong types, maps undefined -> null. */
function normalizeLandingUrl(value: unknown): string | null {
    return isString(value) ? value : null;
}

function parseCapabilitiesAndLimits(
    value: Record<string, unknown>
): { capabilities: CapabilityMap; limits: CapabilityLimits } | null {
    const capabilities = value.capabilities;
    if (!isRecord(capabilities)) return null;
    for (const key of CAPABILITY_KEYS) {
        if (typeof capabilities[key] !== 'boolean') return null;
    }
    const limits = value.limits;
    if (!isRecord(limits)) return null;
    for (const key of LIMIT_KEYS) {
        if (typeof limits[key] !== 'number') return null;
    }
    return {
        capabilities: capabilities as unknown as CapabilityMap,
        limits: limits as unknown as CapabilityLimits,
    };
}

function validateEnvelope(body: unknown): CapabilitiesEnvelope | null {
    if (!isRecord(body)) return null;
    const parsed = parseCapabilitiesAndLimits(body);
    if (!parsed) return null;
    if (
        !isString(body.subjectId) ||
        !isString(body.plan) ||
        !isString(body.planLabel) ||
        !isString(body.expiresAt) ||
        !isString(body.issuedAt)
    ) {
        return null;
    }
    if (body.user !== null && !isString(body.user)) return null;
    return {
        user: body.user as string | null,
        subjectId: body.subjectId as string,
        plan: body.plan as string,
        planLabel: body.planLabel as string,
        planActive: normalizePlanActive(body.planActive),
        landingUrl: normalizeLandingUrl(body.landingUrl),
        expiresAt: body.expiresAt as string,
        issuedAt: body.issuedAt as string,
        ...parsed,
    };
}

function validateSession(value: unknown): Session | null {
    if (!isRecord(value)) return null;
    if (!isString(value.token) || value.token.length === 0) return null;
    if (!isString(value.fetchedAt)) return null;
    const parsed = parseCapabilitiesAndLimits(value);
    if (!parsed) return null;
    if (
        !isString(value.subjectId) ||
        !isString(value.plan) ||
        !isString(value.planLabel) ||
        !isString(value.expiresAt)
    ) {
        return null;
    }
    if (value.user !== null && !isString(value.user)) return null;
    return {
        token: value.token,
        user: value.user as string | null,
        subjectId: value.subjectId as string,
        plan: value.plan as string,
        planLabel: value.planLabel as string,
        planActive: normalizePlanActive(value.planActive),
        landingUrl: normalizeLandingUrl(value.landingUrl),
        expiresAt: value.expiresAt as string,
        fetchedAt: value.fetchedAt,
        ...parsed,
    };
}

function resolveSessionPath(opts?: { sessionDir?: string }): string {
    if (opts?.sessionDir) return path.join(opts.sessionDir, 'auth.json');
    return SESSION_PATH;
}

export async function fetchCapabilities(
    token: string,
    baseUrl: string,
    opts?: { timeoutMs?: number }
): Promise<{ ok: true; data: CapabilitiesEnvelope } | { ok: false; status?: number; error: string }> {
    const url = baseUrl.replace(/\/+$/, '') + '/api/auth/capabilities';
    const timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetch(url, {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${token}`,
                Accept: 'application/json',
            },
            signal: controller.signal,
        });
        if (res.status === 401) {
            return { ok: false, status: 401, error: 'Invalid or expired API token.' };
        }
        if (!res.ok) {
            return { ok: false, status: res.status, error: `Request failed with status ${res.status}.` };
        }
        const body: unknown = await res.json();
        const data = validateEnvelope(body);
        if (!data) {
            return { ok: false, status: res.status, error: 'Invalid capabilities response from server.' };
        }
        return { ok: true, data };
    } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
    } finally {
        clearTimeout(timer);
    }
}

export interface LookupResult {
    found: boolean;
    usable: boolean;
    reason?: 'invalid' | 'revoked' | 'not_decisive' | 'scanner_mismatch' | 'ttl_expired';
    contentId: string;
    state?: string;
    verdict?: 'KNOWN_SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
    confidence?: number;
    signature?: string;
    historyLength?: number;
    scannerVersion?: string;
    firstSeen?: number;
    lastSeen?: number;
    stateSince?: number;
    seenInRepoCount?: number;
    risk?: string;
    alertCount?: number;
    deltaCount?: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    takeover?: boolean;
    verified?: boolean;
}

export type LookupFetchResult =
    | { ok: true; data: LookupResult }
    | {
          ok: false;
          kind: 'auth' | 'forbidden' | 'bad_response' | 'network';
          status?: number;
          error?: string;
      };

function validateLookupResult(value: unknown): LookupResult | null {
    if (!isRecord(value)) return null;
    if (typeof value.found !== 'boolean') return null;
    if (typeof value.usable !== 'boolean') return null;
    if (!isString(value.contentId)) return null;
    if (value.signature !== undefined && value.signature !== null) {
        if (!isString(value.signature) || !SIGNATURE_PATTERN.test(value.signature)) {
            return null;
        }
    }
    return value as unknown as LookupResult;
}

export async function fetchLookup(
    contentId: string,
    token: string,
    baseUrl: string,
    opts?: {
        timeoutMs?: number;
        maxAgeMs?: number;
        scannerVersion?: string;
        env?: NodeJS.ProcessEnv;
    }
): Promise<LookupFetchResult> {
    const url = baseUrl.replace(/\/+$/, '') + '/api/intelligence/query';
    const timeoutMs = opts?.timeoutMs ?? LOOKUP_TIMEOUT_MS;
    const body: Record<string, unknown> = { contentId };
    if (opts?.maxAgeMs !== undefined) body.maxAgeMs = opts.maxAgeMs;
    if (opts?.scannerVersion !== undefined) body.scannerVersion = opts.scannerVersion;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
            body: JSON.stringify(body),
            signal: controller.signal,
        });
        if (res.status === 401) {
            return { ok: false, kind: 'auth', status: 401 };
        }
        if (res.status === 403) {
            const errBody: unknown = await res.json().catch(() => null);
            const error = isRecord(errBody) && isString(errBody.error) ? errBody.error : undefined;
            return { ok: false, kind: 'forbidden', status: 403, error };
        }
        if (!res.ok) {
            return { ok: false, kind: 'network', status: res.status };
        }
        const responseBody: unknown = await res.json();
        const data = validateLookupResult(responseBody);
        if (!data) {
            return { ok: false, kind: 'bad_response', status: res.status };
        }
        return { ok: true, data };
    } catch {
        return { ok: false, kind: 'network' };
    } finally {
        clearTimeout(timer);
    }
}

export type RemoteScanVerdict = 'KNOWN_SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
export type RemoteScanRisk = 'low' | 'medium' | 'high' | 'critical';

export interface RemoteScanFinding {
    severity: string;
    title: string;
    description?: string;
    message?: string;
    evidence?: string;
    type?: string;
    category?: string;
    remediation?: string;
    script?: string;
}

export interface RemoteScanResult {
    jobId?: string;
    status: string;
    engineVersion?: string;
    format?: string;
    scannedAt?: string;
    verdict: RemoteScanVerdict;
    risk: RemoteScanRisk;
    riskScore: number;
    confidence: number;
    findings: RemoteScanFinding[];
    summary?: string;
    explanation?: string[];
}

export type RemoteScanFetchResult =
    | { ok: true; data: RemoteScanResult }
    | {
          ok: false;
          kind: 'auth' | 'forbidden' | 'quota' | 'busy' | 'bad_request' | 'network';
          status?: number;
          error?: string;
          retryAfterSeconds?: number;
      };

const REMOTE_SCAN_TIMEOUT_MS = 20000;

const REMOTE_SCAN_VERDICTS: ReadonlyArray<string> = [
    'KNOWN_SAFE',
    'SUSPICIOUS',
    'MALICIOUS',
    'UNKNOWN',
];

const REMOTE_SCAN_RISKS: ReadonlyArray<string> = ['low', 'medium', 'high', 'critical'];

function isFiniteNumber(value: unknown): value is number {
    return typeof value === 'number' && Number.isFinite(value);
}

async function readErrorBody(res: Response): Promise<string | undefined> {
    try {
        const body: unknown = await res.json();
        if (isRecord(body) && isString(body.error)) return body.error;
    } catch {
        // never throw
    }
    return undefined;
}

export function validateRemoteScanResult(value: unknown): RemoteScanResult | null {
    if (!isRecord(value)) return null;
    if (value.status !== 'complete') return null;
    if (!isString(value.verdict) || !REMOTE_SCAN_VERDICTS.includes(value.verdict)) return null;
    if (!isString(value.risk) || !REMOTE_SCAN_RISKS.includes(value.risk)) return null;
    if (!isFiniteNumber(value.riskScore) || value.riskScore < 0 || value.riskScore > 100) {
        return null;
    }
    if (!isFiniteNumber(value.confidence) || value.confidence < 0 || value.confidence > 1) {
        return null;
    }
    if (!Array.isArray(value.findings)) return null;
    for (const finding of value.findings) {
        if (!isRecord(finding)) return null;
        if (!isString(finding.severity) || !isString(finding.title)) return null;
    }
    return value as unknown as RemoteScanResult;
}

export async function fetchRemoteScan(
    manifest: string,
    format: string,
    token: string,
    baseUrl: string,
    opts?: { timeoutMs?: number; idempotencyKey?: string; groupCredentials?: { groupKey: string; memberKey: string; repositoryId: string } }
): Promise<RemoteScanFetchResult> {
    const url = baseUrl.replace(/\/+$/, '') + '/api/scan/remote';
    const timeoutMs = opts?.timeoutMs ?? REMOTE_SCAN_TIMEOUT_MS;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            Accept: 'application/json',
            'Idempotency-Key': opts?.idempotencyKey ?? randomUUID(),
        };
        if (opts?.groupCredentials) {
            headers['x-sentinel-group-key'] = opts.groupCredentials.groupKey;
            headers['x-sentinel-member-key'] = opts.groupCredentials.memberKey;
            headers['x-sentinel-repository-id'] = opts.groupCredentials.repositoryId;
        } else {
            headers.Authorization = `Bearer ${token}`;
        }
        const res = await fetch(url, {
            method: 'POST',
            headers,
            body: JSON.stringify({ manifest, format }),
            signal: controller.signal,
        });
        if (res.status === 401) {
            return { ok: false, kind: 'auth', status: 401 };
        }
        if (res.status === 403) {
            return { ok: false, kind: 'forbidden', status: 403, error: await readErrorBody(res) };
        }
        if (res.status === 429) {
            const retryHeader = res.headers?.get?.('retry-after');
            const retryAfterSeconds = retryHeader ? parseInt(retryHeader, 10) : undefined;
            return {
                ok: false,
                kind: 'quota',
                status: 429,
                error: await readErrorBody(res),
                retryAfterSeconds: Number.isFinite(retryAfterSeconds)
                    ? retryAfterSeconds
                    : undefined,
            };
        }
        if (res.status === 503) {
            return { ok: false, kind: 'busy', status: 503, error: await readErrorBody(res) };
        }
        if (res.status === 400 || res.status === 413) {
            return {
                ok: false,
                kind: 'bad_request',
                status: res.status,
                error: await readErrorBody(res),
            };
        }
        if (!res.ok) {
            return { ok: false, kind: 'network', status: res.status };
        }
        const responseBody: unknown = await res.json();
        const data = validateRemoteScanResult(responseBody);
        if (!data) {
            return { ok: false, kind: 'network', status: res.status };
        }
        return { ok: true, data };
    } catch {
        return { ok: false, kind: 'network' };
    } finally {
        clearTimeout(timer);
    }
}

export interface CloudUsage {
    subjectId: string;
    plan: string | null;
    period: string;
    used: number;
    limit: number;
    remaining: number;
    ratio: number;
}

export type UsageFetchResult =
    | { ok: true; status: 200; data: CloudUsage }
    | { ok: false; status: number; error?: string };

/**
 * GET /api/auth/usage — the caller's monthly pulse consumption, pooled across
 * every repository/scan. Best effort for the CLI: a failure here must never
 * change a scan's exit code.
 */
export async function fetchUsage(
    token: string,
    baseUrl: string,
    opts?: { timeoutMs?: number }
): Promise<UsageFetchResult> {
    const url = baseUrl.replace(/\/+$/, '') + '/api/auth/usage';
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts?.timeoutMs ?? REMOTE_SCAN_TIMEOUT_MS);
    try {
        const res = await fetch(url, {
            headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
            signal: controller.signal,
        });
        if (!res.ok) {
            return { ok: false, status: res.status };
        }
        const body = (await res.json()) as CloudUsage;
        if (typeof body !== 'object' || body === null || typeof body.used !== 'number' || typeof body.limit !== 'number') {
            return { ok: false, status: res.status };
        }
        return { ok: true, status: 200, data: body };
    } catch {
        return { ok: false, status: 0 };
    } finally {
        clearTimeout(timer);
    }
}

export type ContributeState = 'KNOWN_SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
export type ContributeRisk = 'low' | 'medium' | 'high' | 'critical';
export type ContributeAlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'WARNING' | 'INFO';

export interface ContributeAlert {
    type: string;
    severity: ContributeAlertSeverity;
    riskLevel: number;
    message: string;
    evidence?: string;
    script?: string;
    category?: string;
}

export interface ContributeIdentity {
    ecosystem: string;
    package: string;
    version?: string;
    packageHash?: string;
}

export interface ContributeEvidence {
    risk: ContributeRisk;
    manifestHash: string;
    alerts: ContributeAlert[];
    deltas: never[];
    signals?: ContributeSignal[];
}

export interface ContributePayload {
    manifest: string;
    contentId: string;
    state: ContributeState;
    scannerVersion: string;
    evidence: ContributeEvidence;
    identity?: ContributeIdentity;
}

export interface ContributeResult {
    applied: boolean;
    contentId: string;
    state: ContributeState;
    previousState?: string | null;
    reason: string | null;
    scannerVersion: string;
    verified: false;
}

export type ContributeFetchResult =
    | { ok: true; data: ContributeResult }
    | {
          ok: false;
          kind: 'auth' | 'forbidden' | 'quota' | 'disabled' | 'bad_request' | 'network';
          status?: number;
          error?: string;
          retryAfterSeconds?: number;
      };

const CONTRIBUTE_TIMEOUT_MS = 20000;

const CONTRIBUTE_STATES: ReadonlyArray<string> = ['KNOWN_SAFE', 'SUSPICIOUS', 'MALICIOUS'];

const CONTRIBUTE_CONTENT_ID_PATTERN = /^sha512:[0-9a-f]{128}$/;

export function validateContributeResult(value: unknown): ContributeResult | null {
    if (!isRecord(value)) return null;
    if (typeof value.applied !== 'boolean') return null;
    if (!isString(value.contentId) || !CONTRIBUTE_CONTENT_ID_PATTERN.test(value.contentId)) {
        return null;
    }
    if (!isString(value.state) || !CONTRIBUTE_STATES.includes(value.state)) return null;
    if (value.previousState !== null && !isString(value.previousState)) return null;
    if (value.reason !== null && !isString(value.reason)) return null;
    if (!isString(value.scannerVersion) || value.scannerVersion.length === 0) return null;
    if (value.verified !== false) return null;
    return value as unknown as ContributeResult;
}

export async function fetchContribute(
    payload: ContributePayload,
    token: string,
    baseUrl: string,
    opts?: { timeoutMs?: number }
): Promise<ContributeFetchResult> {
    const url = baseUrl.replace(/\/+$/, '') + '/api/intelligence/contribute';
    const timeoutMs = opts?.timeoutMs ?? CONTRIBUTE_TIMEOUT_MS;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
            body: JSON.stringify(payload),
            signal: controller.signal,
        });
        if (res.status === 401) {
            return { ok: false, kind: 'auth', status: 401 };
        }
        if (res.status === 403) {
            return { ok: false, kind: 'forbidden', status: 403, error: await readErrorBody(res) };
        }
        if (res.status === 429) {
            const retryHeader = res.headers?.get?.('retry-after');
            const retryAfterSeconds = retryHeader ? parseInt(retryHeader, 10) : undefined;
            const validRetryAfter =
                retryAfterSeconds !== undefined &&
                Number.isFinite(retryAfterSeconds) &&
                retryAfterSeconds >= 0
                    ? retryAfterSeconds
                    : undefined;
            return {
                ok: false,
                kind: 'quota',
                status: 429,
                error: await readErrorBody(res),
                retryAfterSeconds: validRetryAfter,
            };
        }
        if (res.status === 503) {
            return { ok: false, kind: 'disabled', status: 503, error: await readErrorBody(res) };
        }
        if (res.status === 400 || res.status === 413) {
            return {
                ok: false,
                kind: 'bad_request',
                status: res.status,
                error: await readErrorBody(res),
            };
        }
        if (!res.ok) {
            return { ok: false, kind: 'network', status: res.status };
        }
        const responseBody: unknown = await res.json();
        const data = validateContributeResult(responseBody);
        if (!data) {
            return { ok: false, kind: 'network', status: res.status };
        }
        return { ok: true, data };
    } catch {
        return { ok: false, kind: 'network' };
    } finally {
        clearTimeout(timer);
    }
}

export type MatchState = 'NO_MATCH' | 'OBSERVED' | 'CORROBORATED' | 'MALICIOUS';
export type MatchVerdict = 'KNOWN_SAFE' | 'SUSPICIOUS' | 'MALICIOUS';
export type MatchMissReason = 'invalid' | 'revoked' | 'not_decisive' | 'scanner_mismatch' | 'ttl_expired';
export type MatchRiskBand = 'low' | 'medium' | 'high' | 'critical';

export interface MatchContentIdLevel {
    found: boolean;
    verified: boolean;
    usable: boolean;
    verdict: MatchVerdict | null;
    confidence: number | null;
    signature: string | null;
    reason: MatchMissReason | null;
    historyLength: number | null;
}

export interface MatchIdentityLevel {
    packageIdentity: string;
    identityKnown: boolean;
    observations: number;
    distinctContributors: number;
    artifacts: number;
    corroborated: boolean;
    corroboratedState: MatchVerdict | null;
    knownSignals: string[];
    maxRisk: MatchRiskBand | null;
    firstSeen: number | null;
    hasCurrentArtifact: boolean;
}

export interface MatchSharedEvidence {
    observations: number;
    distinctContributors: number;
    artifacts: number;
    riskBand: MatchRiskBand | null;
    corroborated: boolean;
    decisiveState: MatchVerdict | null;
    firstSeen: number | null;
}

export interface MatchResult {
    state: MatchState;
    decisiveState: MatchVerdict | null;
    contentId: string;
    revoked: boolean;
    contentIdLevel: MatchContentIdLevel;
    identityLevel: MatchIdentityLevel | null;
    match: {
        knownSignals: string[];
        newBehaviorSignals: string[];
        sharedEvidence: MatchSharedEvidence | null;
    };
}

export interface MatchPayload {
    contentId: string;
    identity?: ContributeIdentity;
    signals?: ContributeSignal[];
    scannerVersion?: string;
    maxAgeMs?: number;
}

export type MatchFetchResult =
    | { ok: true; data: MatchResult }
    | {
          ok: false;
          kind: 'auth' | 'forbidden' | 'quota' | 'disabled' | 'bad_request' | 'network';
          status?: number;
          error?: string;
          retryAfterSeconds?: number;
      };

/** Stable error taxonomy for Sentinel Cloud API errors. */
export type SentinelCloudErrorCode =
    | 'UNAUTHORIZED'
    | 'FORBIDDEN'
    | 'RATE_LIMITED'
    | 'QUOTA_EXHAUSTED'
    | 'UNAVAILABLE'
    | 'INVALID_REQUEST'
    | 'SERVER_ERROR';

const MATCH_TIMEOUT_MS = 20000;

const MATCH_STATES: ReadonlyArray<string> = ['NO_MATCH', 'OBSERVED', 'CORROBORATED', 'MALICIOUS'];
const MATCH_VERDICTS: ReadonlyArray<string> = ['KNOWN_SAFE', 'SUSPICIOUS', 'MALICIOUS'];
const MATCH_MISS_REASONS: ReadonlyArray<string> = [
    'invalid',
    'revoked',
    'not_decisive',
    'scanner_mismatch',
    'ttl_expired',
];
const MATCH_RISK_BANDS: ReadonlyArray<string> = ['low', 'medium', 'high', 'critical'];

function isNullableString(value: unknown): value is string | null {
    return value === null || value === undefined || isString(value);
}

function isNullableFiniteNumber(value: unknown): value is number | null {
    return value === null || value === undefined || isFiniteNumber(value);
}

function isStringArray(value: unknown): value is string[] {
    return Array.isArray(value) && value.every(isString);
}

function isRecordOrNull(value: unknown): boolean {
    return value === null || value === undefined || isRecord(value);
}

export function validateMatchResult(value: unknown): MatchResult | null {
    if (!isRecord(value)) return null;
    if (!isString(value.state) || !MATCH_STATES.includes(value.state)) return null;
    if (value.decisiveState !== null && value.decisiveState !== undefined) {
        if (!isString(value.decisiveState) || !MATCH_VERDICTS.includes(value.decisiveState)) return null;
    }
    if (!isString(value.contentId) || !CONTRIBUTE_CONTENT_ID_PATTERN.test(value.contentId)) return null;
    if (typeof value.revoked !== 'boolean') return null;

    const cl = value.contentIdLevel;
    if (!isRecord(cl)) return null;
    if (typeof cl.found !== 'boolean') return null;
    if (typeof cl.verified !== 'boolean') return null;
    if (typeof cl.usable !== 'boolean') return null;
    if (cl.verdict !== null && cl.verdict !== undefined) {
        if (!isString(cl.verdict) || !MATCH_VERDICTS.includes(cl.verdict)) return null;
    }
    if (!isNullableFiniteNumber(cl.confidence)) return null;
    if (cl.confidence !== null && cl.confidence !== undefined && (cl.confidence < 0 || cl.confidence > 1)) return null;
    if (!isNullableString(cl.signature)) return null;
    if (cl.signature !== null && cl.signature !== undefined && !SIGNATURE_PATTERN.test(cl.signature)) return null;
    if (cl.reason !== null && cl.reason !== undefined) {
        if (!isString(cl.reason) || !MATCH_MISS_REASONS.includes(cl.reason)) return null;
    }
    if (!isNullableFiniteNumber(cl.historyLength)) return null;

    if (!isRecordOrNull(value.identityLevel)) return null;
    if (value.identityLevel !== null && value.identityLevel !== undefined) {
        const il = value.identityLevel as Record<string, unknown>;
        if (!isString(il.packageIdentity) || il.packageIdentity.length === 0) return null;
        if (typeof il.identityKnown !== 'boolean') return null;
        if (!isFiniteNumber(il.observations) || il.observations < 0) return null;
        if (!isFiniteNumber(il.distinctContributors) || il.distinctContributors < 0) return null;
        if (!isFiniteNumber(il.artifacts) || il.artifacts < 0) return null;
        if (typeof il.corroborated !== 'boolean') return null;
        if (il.corroboratedState !== null && il.corroboratedState !== undefined) {
            if (!isString(il.corroboratedState) || !MATCH_VERDICTS.includes(il.corroboratedState)) return null;
        }
        if (!isStringArray(il.knownSignals)) return null;
        if (il.maxRisk !== null && il.maxRisk !== undefined) {
            if (!isString(il.maxRisk) || !MATCH_RISK_BANDS.includes(il.maxRisk)) return null;
        }
        if (!isNullableFiniteNumber(il.firstSeen)) return null;
        if (typeof il.hasCurrentArtifact !== 'boolean') return null;
    }

    const m = value.match;
    if (!isRecord(m)) return null;
    if (!isStringArray(m.knownSignals)) return null;
    if (!isStringArray(m.newBehaviorSignals)) return null;
    if (!isRecordOrNull(m.sharedEvidence)) return null;
    if (m.sharedEvidence !== null && m.sharedEvidence !== undefined) {
        const se = m.sharedEvidence as Record<string, unknown>;
        if (!isFiniteNumber(se.observations) || se.observations < 0) return null;
        if (!isFiniteNumber(se.distinctContributors) || se.distinctContributors < 0) return null;
        if (!isFiniteNumber(se.artifacts) || se.artifacts < 0) return null;
        if (se.riskBand !== null && se.riskBand !== undefined) {
            if (!isString(se.riskBand) || !MATCH_RISK_BANDS.includes(se.riskBand)) return null;
        }
        if (typeof se.corroborated !== 'boolean') return null;
        if (se.decisiveState !== null && se.decisiveState !== undefined) {
            if (!isString(se.decisiveState) || !MATCH_VERDICTS.includes(se.decisiveState)) return null;
        }
        if (!isNullableFiniteNumber(se.firstSeen)) return null;
    }

    return value as unknown as MatchResult;
}

export async function fetchMatch(
    payload: MatchPayload,
    token: string,
    baseUrl: string,
    opts?: { timeoutMs?: number }
): Promise<MatchFetchResult> {
    const url = baseUrl.replace(/\/+$/, '') + '/api/intelligence/match';
    const timeoutMs = opts?.timeoutMs ?? MATCH_TIMEOUT_MS;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
            body: JSON.stringify(payload),
            signal: controller.signal,
        });
        if (res.status === 401) {
            return { ok: false, kind: 'auth', status: 401 };
        }
        if (res.status === 403) {
            return { ok: false, kind: 'forbidden', status: 403, error: await readErrorBody(res) };
        }
        if (res.status === 429) {
            const retryHeader = res.headers?.get?.('retry-after');
            const retryAfterSeconds = retryHeader ? parseInt(retryHeader, 10) : undefined;
            const validRetryAfter =
                retryAfterSeconds !== undefined &&
                Number.isFinite(retryAfterSeconds) &&
                retryAfterSeconds >= 0
                    ? retryAfterSeconds
                    : undefined;
            return {
                ok: false,
                kind: 'quota',
                status: 429,
                error: await readErrorBody(res),
                retryAfterSeconds: validRetryAfter,
            };
        }
        if (res.status === 503) {
            return { ok: false, kind: 'disabled', status: 503, error: await readErrorBody(res) };
        }
        if (res.status === 400 || res.status === 413) {
            return {
                ok: false,
                kind: 'bad_request',
                status: res.status,
                error: await readErrorBody(res),
            };
        }
        if (!res.ok) {
            return { ok: false, kind: 'network', status: res.status };
        }
        const responseBody: unknown = await res.json();
        const data = validateMatchResult(responseBody);
        if (!data) {
            return { ok: false, kind: 'network', status: res.status };
        }
        return { ok: true, data };
    } catch {
        return { ok: false, kind: 'network' };
    } finally {
        clearTimeout(timer);
    }
}

/* -------------------------------------------------------------------------- *
 * Hosted repository scans (P0-8)
 *
 * Contract, verified against the deployed Sentinel Cloud routes:
 *   POST /api/scan/repository                  -> 202 {scanId, status:'PENDING'}
 *   GET  /api/scan/repository/:scanId          -> 200 summary
 *   GET  /api/scan/repository/:scanId/result   -> 200 {scanId, status, result}
 *
 * Known contract facts, deliberately modelled rather than invented:
 * - The status enum is exactly PENDING|PROCESSING|COMPLETED|FAILED|CANCELLED.
 *   'QUEUED' is not a server value; it is accepted on input and folded into
 *   PENDING, and it is never sent.
 * - There is NO cancel route. `repository_scans` has a cancel RPC behind the
 *   authenticated surface but no HTTP handler, so this package exposes no
 *   cancelRepositoryScan: a client that pretended to have one would be calling
 *   an endpoint that does not exist.
 * -------------------------------------------------------------------------- */

/**
 * Server status enum, verbatim from the backend. Read from this list rather
 * than from a hand-written union so the two cannot drift apart.
 */
export const REPOSITORY_SCAN_STATUSES = [
    'PENDING',
    'PROCESSING',
    'COMPLETED',
    'FAILED',
    'CANCELLED',
] as const;

export type RepositoryScanStatus = (typeof REPOSITORY_SCAN_STATUSES)[number];

/** Terminal statuses: polling must stop, not retry. */
const REPOSITORY_SCAN_TERMINAL: ReadonlyArray<RepositoryScanStatus> = ['COMPLETED', 'FAILED', 'CANCELLED'];

/** Mirrors the server's archive cap (26_214_400) so an oversized body fails locally. */
export const REPOSITORY_SCAN_MAX_ARCHIVE_BYTES = 26214400;

/** The server accepts a family of archive media types; this sends the canonical one. */
export const REPOSITORY_SCAN_CONTENT_TYPE = 'application/gzip';

/** Mirrors the server's label cap, applied before the request leaves the host. */
const REPOSITORY_SCAN_MAX_LABEL_LENGTH = 255;

/** Mirrors the server's commit-sha grammar: 7-64 hex characters. */
const REPOSITORY_SCAN_COMMIT_SHA_PATTERN = /^[0-9a-f]{7,64}$/i;

/** Mirrors the server's scanId guard: the generated value is a UUID. */
const REPOSITORY_SCAN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Mirrors the server's `isSafeScanId`. Checked client-side so an obviously
 * malformed id is rejected before it can travel in a request path at all; the
 * server enforces the same rule regardless.
 */
export function isSafeScanId(value: unknown): value is string {
    return isString(value) && REPOSITORY_SCAN_ID_PATTERN.test(value);
}

/** Marks a failure worth retrying later, as opposed to one that never will succeed. */
const REPOSITORY_SCAN_RETRYABLE: Readonly<Record<SentinelCloudErrorCode, boolean>> = {
    UNAUTHORIZED: false,
    FORBIDDEN: false,
    INVALID_REQUEST: false,
    RATE_LIMITED: true,
    QUOTA_EXHAUSTED: true,
    UNAVAILABLE: true,
    SERVER_ERROR: true,
};

/**
 * Normalizes a caller-supplied status. 'QUEUED' is accepted as a courtesy
 * spelling of 'PENDING' and folded into the server's own value; anything the
 * backend does not define is rejected rather than guessed at.
 */
export function normalizeRepositoryScanStatus(value: unknown): RepositoryScanStatus | null {
    if (value === 'QUEUED') return 'PENDING';
    return isString(value) && (REPOSITORY_SCAN_STATUSES as ReadonlyArray<string>).includes(value)
        ? (value as RepositoryScanStatus)
        : null;
}

export interface RepositoryScanSummary {
    scanId: string;
    status: RepositoryScanStatus;
    createdAt: string;
    updatedAt: string;
    error?: string;
}

/**
 * A single public signal. The server projects a fixed field allow-list onto
 * every alert, so no field here is guaranteed present: `toPublicSignal` copies
 * only the keys the raw alert happened to carry, and falls back to `{value}` for
 * a non-object alert. The optional block is therefore the honest model.
 */
export interface RepositoryScanSignal {
    id?: unknown;
    ruleId?: unknown;
    rule_id?: unknown;
    detector?: unknown;
    engine?: unknown;
    severity?: unknown;
    category?: unknown;
    file?: unknown;
    path?: unknown;
    line?: unknown;
    lineNumber?: unknown;
    message?: unknown;
    title?: unknown;
    evidence?: unknown;
    value?: unknown;
}

/**
 * Engine identity as the server reports it. `revision` and `hash` are null
 * whenever the engine did not report them; the client must not upgrade a null
 * into a claim of coverage.
 */
export interface RepositoryScanEngine {
    revision: string | null;
    hash: string | null;
}

/**
 * Public result envelope. Field-for-field what the server writes:
 * `filesScanned` is nullable because coverage is only asserted when the engine
 * actually reported parsed-file counters, and `coverageUnknown` is the inverse
 * of `coverageKnown` rather than an independent claim.
 */
export interface RepositoryScanEnvelope {
    scanId: string;
    status: 'COMPLETED';
    engine: RepositoryScanEngine;
    executionComplete: boolean;
    coverageKnown: boolean;
    coverageUnknown: boolean;
    filesScanned: number | null;
    filesFailed: number;
    alertsSeen: number;
    alertsEnrichFailed: number;
    signals: RepositoryScanSignal[];
}

export interface RepositoryScanSubmission {
    scanId: string;
    status: RepositoryScanStatus;
}

export interface RepositoryScanCallError {
    ok: false;
    /** Stable taxonomy, so callers branch on intent instead of on status codes. */
    code: SentinelCloudErrorCode;
    status?: number;
    /** Server-provided message, with the bearer token scrubbed out. */
    error?: string;
    /** Server error code, e.g. PULSOS_EXHAUSTED on an exhausted quota. */
    serverCode?: string;
    /** Present on 429 quota rejections so a caller can show real usage. */
    used?: number;
    limit?: number;
    retryAfterSeconds?: number;
    /** Scan status from the envelope, so a caller can tell FAILED from PENDING. */
    scanStatus?: RepositoryScanStatus;
    /** False only for UNAUTHORIZED, FORBIDDEN and INVALID_REQUEST. */
    retryable: boolean;
}

export type RepositoryScanCallResult<T> = { ok: true; data: T } | RepositoryScanCallError;

export interface RepositoryScanRequestOptions {
    timeoutMs?: number;
    /** Group scoped credentials; each credential identifies one side of a member operation. */
    groupCredentials?: { groupKey: string; memberKey: string; repositoryId: string };
}

function repositoryScanAuthHeaders(token: string, opts?: RepositoryScanRequestOptions): Record<string, string> {
    const group = opts?.groupCredentials;
    if (group) return {
        'x-sentinel-group-key': group.groupKey,
        'x-sentinel-member-key': group.memberKey,
        'x-sentinel-repository-id': group.repositoryId,
        Accept: 'application/json',
    };
    return { Authorization: `Bearer ${token}`, Accept: 'application/json' };
}

export interface SubmitRepositoryScanOptions extends RepositoryScanRequestOptions {
    /** Stable across retries of the same submission; generated when omitted. */
    idempotencyKey?: string;
    /** Sent as x-sentinel-repo-label; trimmed and capped at 255 characters. */
    repoLabel?: string;
    /** Sent as x-sentinel-commit-sha; must be 7-64 hex characters or it is dropped. */
    commitSha?: string;
    /** Override the media type. Defaults to application/gzip. */
    contentType?: string;
}

/** Submitting an archive over a bad body is a 400, not a transport failure. */
const REPOSITORY_SCAN_SUBMIT_TIMEOUT_MS = 60000;
const REPOSITORY_SCAN_STATUS_TIMEOUT_MS = 20000;
const REPOSITORY_SCAN_RESULT_TIMEOUT_MS = 60000;
const REPOSITORY_SCAN_POLL_INTERVAL_MS = 2000;
const REPOSITORY_SCAN_POLL_TIMEOUT_MS = 300000;

/**
 * Removes the bearer token from any text that will reach a caller, an error
 * message or a log. Server messages are attacker-influenceable in the general
 * case and this is the cheapest way to make token leakage structurally
 * impossible rather than merely unlikely.
 */
function scrubToken(text: string | undefined, token: string): string | undefined {
    if (!text) return undefined;
    return token.length > 0 ? text.split(token).join('[redacted]') : text;
}

function isNullableNumber(value: unknown): value is number | null {
    return value === null || isFiniteNumber(value);
}

function isNonNegativeNumber(value: unknown): boolean {
    return isFiniteNumber(value) && value >= 0;
}

/**
 * Rejects anything that is not a plausible envelope rather than half-trusting
 * it. coverageKnown is cross-checked against coverageUnknown: the server
 * derives the second from the first, so a payload where they disagree is
 * corrupt and must not be presented to a user as a coverage statement.
 */
export function validateRepositoryScanEnvelope(value: unknown): RepositoryScanEnvelope | null {
    if (!isRecord(value)) return null;
    if (!isString(value.scanId)) return null;
    if (normalizeRepositoryScanStatus(value.status) !== 'COMPLETED') return null;
    if (typeof value.executionComplete !== 'boolean') return null;
    if (typeof value.coverageKnown !== 'boolean') return null;
    if (typeof value.coverageUnknown !== 'boolean') return null;
    if (value.coverageUnknown === value.coverageKnown) return null;
    if (!isNullableNumber(value.filesScanned)) return null;
    if (value.filesScanned !== null && value.filesScanned < 0) return null;
    if (!isNonNegativeNumber(value.filesFailed)) return null;
    if (!isNonNegativeNumber(value.alertsSeen)) return null;
    if (!isNonNegativeNumber(value.alertsEnrichFailed)) return null;
    if (!Array.isArray(value.signals)) return null;

    const engine = value.engine;
    if (!isRecord(engine)) return null;
    if (engine.revision !== null && !isString(engine.revision)) return null;
    if (engine.hash !== null && !isString(engine.hash)) return null;

    return value as unknown as RepositoryScanEnvelope;
}

export function validateRepositoryScanSummary(value: unknown): RepositoryScanSummary | null {
    if (!isRecord(value)) return null;
    if (!isString(value.scanId)) return null;
    const status = normalizeRepositoryScanStatus(value.status);
    if (!status) return null;
    if (!isString(value.createdAt)) return null;
    if (!isString(value.updatedAt)) return null;
    if (value.error !== undefined && value.error !== null && !isString(value.error)) return null;
    const summary: RepositoryScanSummary = {
        scanId: value.scanId,
        status,
        createdAt: value.createdAt,
        updatedAt: value.updatedAt,
    };
    if (isString(value.error)) summary.error = value.error;
    return summary;
}

/**
 * Reads an error envelope without trusting its shape: every field is optional
 * and a non-JSON body (a proxy error page, an empty 502) degrades to undefined
 * rather than throwing.
 */
async function readRepositoryScanError(res: Response): Promise<{
    error?: string;
    code?: string;
    used?: number;
    limit?: number;
    retryAfterSeconds?: number;
    scanStatus?: RepositoryScanStatus;
}> {
    const out: {
        error?: string;
        code?: string;
        used?: number;
        limit?: number;
        retryAfterSeconds?: number;
        scanStatus?: RepositoryScanStatus;
    } = {};
    try {
        const body: unknown = await res.json();
        if (isRecord(body)) {
            if (isString(body.error)) out.error = body.error;
            if (isString(body.code)) out.code = body.code;
            if (isFiniteNumber(body.used)) out.used = body.used;
            if (isFiniteNumber(body.limit)) out.limit = body.limit;
            // The 409 body reuses `status` for the scan status, not the HTTP one.
            const scanStatus = normalizeRepositoryScanStatus(body.status);
            if (scanStatus) out.scanStatus = scanStatus;
        }
    } catch {
        // A body that is not JSON carries no envelope worth reading.
    }
    const retryHeader = res.headers?.get?.('retry-after');
    if (retryHeader) {
        const seconds = parseInt(retryHeader, 10);
        if (Number.isFinite(seconds) && seconds >= 0) out.retryAfterSeconds = seconds;
    }
    return out;
}

function fail(
    code: SentinelCloudErrorCode,
    token: string,
    extra: {
        status?: number;
        error?: string;
        serverCode?: string;
        used?: number;
        limit?: number;
        retryAfterSeconds?: number;
        scanStatus?: RepositoryScanStatus;
    } = {}
): RepositoryScanCallError {
    const result: {
        ok: false;
        code: SentinelCloudErrorCode;
        status?: number;
        error?: string;
        serverCode?: string;
        used?: number;
        limit?: number;
        retryAfterSeconds?: number;
        scanStatus?: RepositoryScanStatus;
        retryable: boolean;
    } = { ok: false, code, retryable: REPOSITORY_SCAN_RETRYABLE[code] };
    if (extra.status !== undefined) result.status = extra.status;
    const scrubbed = scrubToken(extra.error, token);
    if (scrubbed !== undefined) result.error = scrubbed;
    if (extra.serverCode !== undefined) result.serverCode = extra.serverCode;
    if (extra.used !== undefined) result.used = extra.used;
    if (extra.limit !== undefined) result.limit = extra.limit;
    if (extra.retryAfterSeconds !== undefined) result.retryAfterSeconds = extra.retryAfterSeconds;
    if (extra.scanStatus !== undefined) result.scanStatus = extra.scanStatus;
    return result as RepositoryScanCallError;
}

/**
 * Maps an HTTP response onto the stable taxonomy.
 *
 *   401            -> UNAUTHORIZED
 *   403            -> FORBIDDEN
 *   429            -> QUOTA_EXCEEDED when code is PULSOS_EXHAUSTED, else RATE_LIMITED
 *   400/413/415    -> INVALID_REQUEST
 *   409            -> UNAVAILABLE, carrying the scan status (not ready; retry)
 *   404            -> INVALID_REQUEST (see note)
 *   502/503/504    -> UNAVAILABLE (retryable transport/dependency failure)
 *   other 5xx      -> SERVER_ERROR
 *
 * 404 note: the backend answers 404 for an absent scan, or for a scanId that is
 * not a UUID, or for a scan owned by somebody else. None of those is retryable,
 * so 404 is mapped to INVALID_REQUEST rather than to UNAVAILABLE — folding a
 * terminal "no such scan" into a retryable bucket is how a CLI burns its poll
 * budget on a 404 that will never become 200. The HTTP status stays on the
 * result so a caller that needs to tell the cases apart still can.
 */
async function classifyResponse(res: Response, token: string): Promise<RepositoryScanCallError> {
    const status = res.status;
    if (status === 401) {
        const detail = await readRepositoryScanError(res);
        return fail('UNAUTHORIZED', token, { status, error: detail.error });
    }
    if (status === 403) {
        const detail = await readRepositoryScanError(res);
        return fail('FORBIDDEN', token, { status, error: detail.error, serverCode: detail.code });
    }
    if (status === 429) {
        const detail = await readRepositoryScanError(res);
        const quota = detail.code === 'PULSOS_EXHAUSTED';
        return fail(quota ? 'QUOTA_EXHAUSTED' : 'RATE_LIMITED', token, {
            status,
            error: detail.error,
            serverCode: detail.code,
            used: detail.used,
            limit: detail.limit,
            retryAfterSeconds: detail.retryAfterSeconds,
        });
    }
    if (status === 400 || status === 413 || status === 415) {
        const detail = await readRepositoryScanError(res);
        return fail('INVALID_REQUEST', token, { status, error: detail.error });
    }
    if (status === 404) {
        const detail = await readRepositoryScanError(res);
        return fail('INVALID_REQUEST', token, { status, error: detail.error });
    }
    if (status === 409) {
        const detail = await readRepositoryScanError(res);
        return fail('UNAVAILABLE', token, {
            status,
            error: detail.error,
            scanStatus: detail.scanStatus,
        });
    }
    if (status === 502 || status === 503 || status === 504) {
        const detail = await readRepositoryScanError(res);
        return fail('UNAVAILABLE', token, { status, error: detail.error, serverCode: detail.code });
    }
    if (status >= 500) {
        const detail = await readRepositoryScanError(res);
        return fail('SERVER_ERROR', token, { status, error: detail.error });
    }
    const detail = await readRepositoryScanError(res);
    return fail('SERVER_ERROR', token, {
        status,
        error: detail.error ?? `Unexpected repository-scan response status ${status}.`,
    });
}

function resolveRepositoryScanUrl(baseUrl: string, suffix: string): string {
    // Throws before any socket work when the endpoint would carry the bearer
    // token in the clear. Same guard the CLI entry points already use.
    const secureBase = assertSecureBaseUrl(baseUrl);
    return secureBase.replace(/\/+$/, '') + suffix;
}

function toBytes(archive: Uint8Array | ArrayBuffer): Uint8Array | null {
    if (archive instanceof Uint8Array) return archive;
    if (typeof ArrayBuffer !== 'undefined' && archive instanceof ArrayBuffer) return new Uint8Array(archive);
    // Never coerce an unexpected input into a buffer: a number would silently
    // allocate a zero-filled archive of that size and upload it.
    return null;
}

function archiveByteLength(archive: Uint8Array | ArrayBuffer): number {
    return archive.byteLength;
}

/**
 * Parses a 2xx JSON body, treating an unparseable one as a malformed response
 * rather than a transport failure. A server that answers 200 with a truncated
 * or non-JSON body is a contract violation; reporting it as UNAVAILABLE would
 * invite a caller to retry a request that will fail identically forever.
 */
async function readJsonBody(
    res: Response
): Promise<{ ok: true; body: Record<string, unknown> } | { ok: false }> {
    try {
        const body: unknown = await res.json();
        if (!isRecord(body)) return { ok: false };
        return { ok: true, body };
    } catch {
        return { ok: false };
    }
}

function malformed(token: string, what: string): RepositoryScanCallError {
    return fail('SERVER_ERROR', token, {
        error: `Malformed ${what} response from Sentinel Cloud.`,
    });
}

/**
 * POST /api/scan/repository — enqueue a hosted repository scan.
 *
 * The body is the gzip tar archive itself, not a JSON wrapper: the caller
 * builds the archive (see the sibling `sentinel-audit` package, which owns
 * packing). This package deliberately ships no packer, so it can never be the
 * place where a caller's source tree is turned into an upload.
 *
 * Answers 202 {scanId, status:'PENDING'}. The archive is handed to the worker
 * through private storage and destroyed when the scan terminates, so the caller
 * must not expect the bytes to be retained.
 */
export async function submitRepositoryScan(
    archive: Uint8Array | ArrayBuffer,
    token: string,
    baseUrl: string,
    opts?: SubmitRepositoryScanOptions
): Promise<RepositoryScanCallResult<RepositoryScanSubmission>> {
    const groupCredentials = opts?.groupCredentials;
    const hasGroupCredentials = !!groupCredentials;
    if ((!isString(token) || token.length === 0) && !hasGroupCredentials) {
        return fail('UNAUTHORIZED', '', { error: 'An API token is required.' });
    }
    if (hasGroupCredentials && (!/^scgrp_[A-Za-z0-9_-]{32,64}$/.test(groupCredentials.groupKey) || !/^scmem_[A-Za-z0-9_-]{32,64}$/.test(groupCredentials.memberKey) || !/^[0-9a-f-]{36}$/i.test(groupCredentials.repositoryId))) {
        return fail('INVALID_REQUEST', token, { error: 'Valid group and member credentials plus a repository UUID are required.' });
    }
    const bytes = toBytes(archive);
    if (!bytes) {
        return fail('INVALID_REQUEST', token, {
            error: 'Repository archive must be a Uint8Array or an ArrayBuffer.',
        });
    }
    const size = archiveByteLength(archive);
    if (size === 0) {
        return fail('INVALID_REQUEST', token, {
            error: 'Repository archive body is empty; the server requires a gzip tar body.',
        });
    }
    if (size > REPOSITORY_SCAN_MAX_ARCHIVE_BYTES) {
        return fail('INVALID_REQUEST', token, {
            error: `Repository archive too large: ${size} bytes exceeds the ${REPOSITORY_SCAN_MAX_ARCHIVE_BYTES} byte limit.`,
        });
    }

    const url = resolveRepositoryScanUrl(baseUrl, '/api/scan/repository');
    const headers: Record<string, string> = {
        ...repositoryScanAuthHeaders(token, opts),
        'Content-Type': opts?.contentType ?? REPOSITORY_SCAN_CONTENT_TYPE,
        'Idempotency-Key': opts?.idempotencyKey ?? randomUUID(),
    };
    if (opts?.repoLabel) {
        headers['x-sentinel-repo-label'] = opts.repoLabel.trim().slice(0, REPOSITORY_SCAN_MAX_LABEL_LENGTH);
    }
    if (opts?.commitSha) {
        const sha = opts.commitSha.trim();
        if (!REPOSITORY_SCAN_COMMIT_SHA_PATTERN.test(sha)) {
            return fail('INVALID_REQUEST', token, {
                error: 'commitSha must be 7 to 64 hexadecimal characters.',
            });
        }
        headers['x-sentinel-commit-sha'] = sha.toLowerCase();
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts?.timeoutMs ?? REPOSITORY_SCAN_SUBMIT_TIMEOUT_MS);
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers,
            body: bytes as unknown as BodyInit,
            signal: controller.signal,
        });
        if (!res.ok) return await classifyResponse(res, token);
        const parsed = await readJsonBody(res);
        if (!parsed.ok) return malformed(token, 'submit');
        const body = parsed.body;
        if (!isString(body.scanId)) return malformed(token, 'submit');
        const status = normalizeRepositoryScanStatus(body.status);
        if (!status) return malformed(token, 'submit');
        return { ok: true, data: { scanId: body.scanId, status } };
    } catch (err) {
        return fail('UNAVAILABLE', token, { error: describeTransportError(err, token) });
    } finally {
        clearTimeout(timer);
    }
}

/**
 * GET /api/scan/repository/:scanId — owner-scoped status. 404 means the scan
 * does not exist for this owner, which is indistinguishable by design from a
 * scan belonging to someone else.
 */
export async function getRepositoryScan(
    scanId: string,
    token: string,
    baseUrl: string,
    opts?: RepositoryScanRequestOptions
): Promise<RepositoryScanCallResult<RepositoryScanSummary>> {
    if ((!isString(token) || token.length === 0) && !opts?.groupCredentials) {
        return fail('UNAUTHORIZED', '', { error: 'An API token is required.' });
    }
    if (!isSafeScanId(scanId)) {
        return fail('INVALID_REQUEST', token, {
            error: 'scanId must be a UUID returned by submitRepositoryScan.',
        });
    }
    const url = resolveRepositoryScanUrl(baseUrl, `/api/scan/repository/${encodeURIComponent(scanId)}`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts?.timeoutMs ?? REPOSITORY_SCAN_STATUS_TIMEOUT_MS);
    try {
        const res = await fetch(url, {
            headers: repositoryScanAuthHeaders(token, opts),
            signal: controller.signal,
        });
        if (!res.ok) return await classifyResponse(res, token);
        const parsed = await readJsonBody(res);
        if (!parsed.ok) return malformed(token, 'status');
        const summary = validateRepositoryScanSummary(parsed.body);
        if (!summary) return malformed(token, 'status');
        return { ok: true, data: summary };
    } catch (err) {
        return fail('UNAVAILABLE', token, { error: describeTransportError(err, token) });
    } finally {
        clearTimeout(timer);
    }
}

/**
 * GET /api/scan/repository/:scanId/result — the public result envelope.
 *
 * The server answers 409 while the scan is not COMPLETED, so a caller that
 * wants the waiting behaviour should poll getRepositoryScan first, or treat
 * this 409 as retryable.
 */
export async function getRepositoryScanResult(
    scanId: string,
    token: string,
    baseUrl: string,
    opts?: RepositoryScanRequestOptions
): Promise<RepositoryScanCallResult<RepositoryScanEnvelope>> {
    if ((!isString(token) || token.length === 0) && !opts?.groupCredentials) {
        return fail('UNAUTHORIZED', '', { error: 'An API token is required.' });
    }
    if (!isSafeScanId(scanId)) {
        return fail('INVALID_REQUEST', token, {
            error: 'scanId must be a UUID returned by submitRepositoryScan.',
        });
    }
    const url = resolveRepositoryScanUrl(
        baseUrl,
        `/api/scan/repository/${encodeURIComponent(scanId)}/result`
    );
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts?.timeoutMs ?? REPOSITORY_SCAN_RESULT_TIMEOUT_MS);
    try {
        const res = await fetch(url, {
            headers: repositoryScanAuthHeaders(token, opts),
            signal: controller.signal,
        });
        if (!res.ok) return await classifyResponse(res, token);
        const parsed = await readJsonBody(res);
        if (!parsed.ok) return malformed(token, 'result');
        const body = parsed.body;
        if (body.scanId !== scanId) return malformed(token, 'result');
        if (normalizeRepositoryScanStatus(body.status) !== 'COMPLETED') return malformed(token, 'result');
        const envelope = validateRepositoryScanEnvelope(body.result);
        if (!envelope) return malformed(token, 'result');
        return { ok: true, data: envelope };
    } catch (err) {
        return fail('UNAVAILABLE', token, { error: describeTransportError(err, token) });
    } finally {
        clearTimeout(timer);
    }
}

function describeTransportError(err: unknown, token: string): string {
    const raw = err instanceof Error ? err.message : String(err);
    return scrubToken(raw, token) ?? 'Request failed.';
}

export interface WaitForRepositoryScanOptions extends RepositoryScanRequestOptions {
    /** Delay between status polls. */
    pollIntervalMs?: number;
    /** Overall wall-clock budget for the wait. */
    waitTimeoutMs?: number;
    /** Called on every observed status transition, for progress output. */
    onStatus?: (summary: RepositoryScanSummary) => void;
    /** Lets the host stop waiting without waiting out the budget. */
    signal?: AbortSignal;
}

export type WaitForRepositoryScanResult =
    | { ok: true; summary: RepositoryScanSummary; envelope: RepositoryScanEnvelope }
    | { ok: false; code: SentinelCloudErrorCode; status?: number; error?: string; retryable: boolean };

/**
 * Polls scan status until the scan reaches a terminal state, then fetches the
 * envelope.
 *
 * This is a convenience wrapper over the two GET routes, not a new endpoint.
 * FAILED and CANCELLED are terminal failures rather than transport errors, so
 * they come back as a SERVER_ERROR classification carrying `scanStatus`, which
 * a caller can branch on without string-matching a message.
 */
export async function waitForRepositoryScan(
    scanId: string,
    token: string,
    baseUrl: string,
    opts?: WaitForRepositoryScanOptions
): Promise<WaitForRepositoryScanResult> {
    const pollIntervalMs = opts?.pollIntervalMs ?? REPOSITORY_SCAN_POLL_INTERVAL_MS;
    const waitTimeoutMs = opts?.waitTimeoutMs ?? REPOSITORY_SCAN_POLL_TIMEOUT_MS;
    const deadline = Date.now() + waitTimeoutMs;
    let lastStatus: RepositoryScanStatus | null = null;

    while (Date.now() < deadline) {
        if (opts?.signal?.aborted) {
            return fail('UNAVAILABLE', token, { error: 'Waiting for the repository scan was aborted.' });
        }
        const statusResult = await getRepositoryScan(scanId, token, baseUrl, opts);
        if (!statusResult.ok) {
            // Do not spend the whole budget on a retryable error storm.
            if (statusResult.code === 'RATE_LIMITED') {
                const delay = statusResult.retryAfterSeconds ?? Math.ceil(pollIntervalMs / 1000);
                await sleep(Math.max(delay, 1) * 1000);
                continue;
            }
            return statusResult;
        }
        const summary = statusResult.data;
        if (summary.status !== lastStatus) {
            lastStatus = summary.status;
            opts?.onStatus?.(summary);
        }
        if (summary.status === 'COMPLETED') {
            const result = await getRepositoryScanResult(scanId, token, baseUrl, opts);
            if (!result.ok) return result;
            return { ok: true, summary, envelope: result.data };
        }
        if (summary.status === 'FAILED' || summary.status === 'CANCELLED') {
            return fail('SERVER_ERROR', token, {
                scanStatus: summary.status,
                error: summary.error ?? `Repository scan ${summary.status.toLowerCase()}.`,
            });
        }
        await sleep(pollIntervalMs);
    }
    return fail('UNAVAILABLE', token, {
        error: `Repository scan did not reach a terminal state within ${waitTimeoutMs}ms (last status ${lastStatus ?? 'unknown'}).`,
    });
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
        const timer = setTimeout(resolve, ms);
        // Never hold the event loop open just to finish a poll interval.
        if (typeof (timer as { unref?: () => void }).unref === 'function') {
            (timer as { unref: () => void }).unref();
        }
    });
}

export function saveSession(session: Session, opts?: { sessionDir?: string }): void {
    const sessionPath = resolveSessionPath(opts);
    const dir = path.dirname(sessionPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(sessionPath, JSON.stringify(session, null, 2) + '\n', { mode: 0o600 });
}

export async function loginWithToken(
    token: string,
    baseUrl: string,
    opts?: { sessionDir?: string }
): Promise<{ ok: true; session: Session } | { ok: false; error: string }> {
    const result = await fetchCapabilities(token, baseUrl);
    if (!result.ok) {
        if (result.status === 401) {
            clearSession(opts);
            return { ok: false, error: 'Invalid or expired token. Re-run "sentinel login" with a valid token.' };
        }
        return { ok: false, error: result.error };
    }
    const session: Session = {
        token,
        user: result.data.user,
        subjectId: result.data.subjectId,
        plan: result.data.plan,
        planLabel: result.data.planLabel,
        planActive: result.data.planActive,
        landingUrl: result.data.landingUrl,
        expiresAt: result.data.expiresAt,
        capabilities: result.data.capabilities,
        limits: result.data.limits,
        fetchedAt: new Date().toISOString(),
    };
    saveSession(session, opts);
    return { ok: true, session };
}

export function loadSession(opts?: { sessionDir?: string }): Session | null {
    const sessionPath = resolveSessionPath(opts);
    let raw: string;
    try {
        raw = fs.readFileSync(sessionPath, 'utf8');
    } catch {
        return null;
    }
    try {
        return validateSession(JSON.parse(raw));
    } catch {
        return null;
    }
}

export function clearSession(opts?: { sessionDir?: string }): void {
    try {
        const sessionPath = resolveSessionPath(opts);
        if (fs.existsSync(sessionPath)) fs.unlinkSync(sessionPath);
    } catch {
        // never throw
    }
}

export function isLoopbackHost(host: string | undefined): boolean {
    if (!host) return false;
    const h = host.toLowerCase().replace(/^\[|\]$/g, '');
    return h === 'localhost' || h === '::1' || /^127(\.\d{1,3}){3}$/.test(h);
}

/**
 * Refuses base URLs that would send the bearer token in the clear unless the
 * server is loopback (local development). Blocks http/ws to non-loopback hosts
 * and invalid URLs before any authenticated request is attempted.
 */
export function assertSecureBaseUrl(rawUrl: string): string {
    let parsed: URL;
    try {
        parsed = new URL(rawUrl);
    } catch {
        throw new Error(`Invalid Sentinel Cloud base URL: '${rawUrl}'.`);
    }
    if (parsed.protocol !== 'https:' && !isLoopbackHost(parsed.hostname)) {
        throw new Error(
            `Refusing insecure Sentinel Cloud base URL '${rawUrl}'. ` +
                'Only https:// (or loopback for local development) is allowed; ' +
                'bearer tokens must never travel in the clear.'
        );
    }
    return rawUrl;
}

export function getResolvedBaseUrl(
    flagValue: string | undefined,
    env: NodeJS.ProcessEnv = process.env
): string {
    if (flagValue) return assertSecureBaseUrl(flagValue);
    const fromEnv = env.SENTINEL_CLOUD_URL;
    if (fromEnv) return assertSecureBaseUrl(fromEnv);
    throw new Error(
        'No Sentinel Cloud base URL configured. Set SENTINEL_CLOUD_URL or pass --api <url>.'
    );
}

export function resolveToken(
    flagValue: string | undefined,
    env: NodeJS.ProcessEnv = process.env
): string | null {
    if (flagValue) return flagValue;
    const fromEnv = env.SENTINEL_CLOUD_API_TOKEN;
    if (fromEnv) return fromEnv;
    return null;
}
