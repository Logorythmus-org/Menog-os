import type { AppendOnlyLedger } from "@menog/event-ledger";
import type {
  ExecutionMemoryQuery,
  ExecutionMemoryReadResult,
  ExecutionMemoryRecord,
  ExecutionMemoryStatsResult,
  ExecutionMemoryWriteRequest,
  ExecutionOutcome,
  ExecutionMetadata,
  MemoryPreWriteCheckResult,
  MemoryRecord,
  MemoryRecordBody,
  MemoryScope,
  MemoryWriteResult,
} from "./types.js";
import { newMemoryId } from "./serialize.js";
import {
  BaseMemoryStore,
  type MemoryAccessContext,
  type MemoryStoreOptions,
} from "./memory.js";
import { secretKeyMatches, redactCredentialValues } from "./secrets.js";

/**
 * Phase 16B — Execution Memory.
 *
 * Structured, bounded, policy-gated record of what the runtime DID:
 * validated execution outcomes, failures, decisions, and ledger evidence
 * references. Replaces "remember what happened" via raw transcripts with
 * queryable records carrying taskId / verb / actor / time.
 *
 * Security contract (see ExecutionMetadata in types.ts):
 *  - NO SECRETS BY DEFAULT: any body key matching the shared secret-key
 *    hints is rejected with denyReason "secret_detected" BEFORE persistence —
 *    the write never happens, nothing partial is stored.
 *  - Credential-shaped string VALUES in surviving metadata are redacted to
 *    "[REDACTED]" at rest (defense in depth for values quoted in `summary`).
 *  - Raw blobs above EXECUTION_MEMORY_MAX_BLOB_BYTES are rejected with
 *    "oversized_blob"; evidence is stored by reference (evidenceRef), not by
 *    value.
 *  - evidenceRef, when supplied, must exist in the attached ledger (whose
 *    hash chain the ledger guarantees) AND be attributable to the same
 *    workspace as the record (16D anti-spoofing) — execution memory may not
 *    cite evidence the authoritative ledger does not contain.
 *  - Query filters (task/verb/agent/time/outcome) can only NARROW the
 *    caller's granted scope; they can never widen it (16A scope isolation is
 *    applied first, filters second).
 */

/** Upper bound for one execution-memory body, in serialized UTF-8 bytes. */
export const EXECUTION_MEMORY_MAX_BLOB_BYTES = 8 * 1024;
/** Record cap for the execution store (full Phase-16 history at v0 cadence). */
export const EXECUTION_MEMORY_MAX_RECORDS = 2048;
/** Reserved body key carrying ExecutionMetadata. */
export const EXECUTION_METADATA_KEY = "execution";
/** Only the execution metadata key may occupy the body of an execution record. */
export const EXECUTION_MEMORY_ALLOWED_BODY_KEYS: readonly string[] = Object.freeze([
  EXECUTION_METADATA_KEY,
]);

const KNOWN_POLICY_DECISION_VALUES: readonly string[] = Object.freeze([
  "allow",
  "deny",
  "not_applicable",
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function bodyByteLength(body: MemoryRecordBody): number {
  return Buffer.byteLength(JSON.stringify(body), "utf8");
}

function outOfRangeNumber(v: unknown): boolean {
  return typeof v !== "number" || !Number.isFinite(v) || v < 0;
}

/**
 * Collect every secret-like KEY at any depth of an object (values that are
 * plain objects are descended into; keys are checked, values are not read).
 */
function collectNestedSecretKeys(value: unknown, path: string): string[] {
  if (!isPlainObject(value)) return [];
  const hits: string[] = [];
  for (const [k, v] of Object.entries(value)) {
    const p = path.length === 0 ? k : path + "." + k;
    if (secretKeyMatches(k)) hits.push(p);
    if (isPlainObject(v)) hits.push(...collectNestedSecretKeys(v, p));
  }
  return hits;
}

/**
 * Validate the execution metadata half of an execution-memory body. Returns
 * a machine-readable error string or null.
 */
export function validateExecutionMetadata(raw: unknown): string | null {
  if (!isPlainObject(raw)) {
    return "invalid body.execution: must be a plain object";
  }
  const m = raw as {
    taskId?: unknown;
    verb?: unknown;
    outcome?: unknown;
    actorId?: unknown;
    actorType?: unknown;
    recordedAtEpochMs?: unknown;
    policyDecision?: unknown;
    evidenceRef?: unknown;
    summary?: unknown;
    attempt?: unknown;
    exitCode?: unknown;
  };
  if (typeof m.taskId !== "string" || m.taskId.length === 0) {
    return "invalid body.execution.taskId: must be non-empty string";
  }
  if (typeof m.verb !== "string" || m.verb.length === 0) {
    return "invalid body.execution.verb: must be non-empty string";
  }
  if (m.outcome !== "success" && m.outcome !== "failure" && m.outcome !== "denied") {
    return "invalid body.execution.outcome: must be 'success' | 'failure' | 'denied'";
  }
  if (typeof m.actorId !== "string" || m.actorId.length === 0) {
    return "invalid body.execution.actorId: must be non-empty string";
  }
  if (typeof m.actorType !== "string" || m.actorType.length === 0) {
    return "invalid body.execution.actorType: must be non-empty string";
  }
  if (outOfRangeNumber(m.recordedAtEpochMs)) {
    return "invalid body.execution.recordedAtEpochMs: must be finite non-negative epoch ms";
  }
  if (
    typeof m.policyDecision !== "string" ||
    !(KNOWN_POLICY_DECISION_VALUES as readonly string[]).includes(m.policyDecision)
  ) {
    return "invalid body.execution.policyDecision: must be allow | deny | not_applicable";
  }
  if (m.evidenceRef !== undefined && (typeof m.evidenceRef !== "string" || m.evidenceRef.length === 0)) {
    return "invalid body.execution.evidenceRef: if present must be non-empty string";
  }
  if (m.summary !== undefined && (typeof m.summary !== "string" || m.summary.length === 0)) {
    return "invalid body.execution.summary: if present must be non-empty string";
  }
  if (m.attempt !== undefined && (typeof m.attempt !== "number" || !Number.isInteger(m.attempt) || m.attempt < 1)) {
    return "invalid body.execution.attempt: if present must be positive integer";
  }
  if (m.exitCode !== undefined && (typeof m.exitCode !== "number" || !Number.isInteger(m.exitCode))) {
    return "invalid body.execution.exitCode: if present must be integer";
  }
  return null;
}

export type ExecutionMemoryStoreOptions = MemoryStoreOptions & {
  /**
   * Injected validator for evidence references. Default: when a ledger is
   * attached, the cited eventId must exist in it; when no ledger is
   * attached, evidenceRef is rejected — execution memory must not fabricate
   * evidence pointers it cannot verify.
   */
  readonly evidenceRefValidator?: (evidenceRef: string) => boolean;
  /** Inherited 16D opt-in (see MemoryStoreOptions.rejectSecretKeys). */
  readonly rejectSecretKeys?: boolean;
};

export class ExecutionMemoryStore extends BaseMemoryStore {
  public readonly kind = "execution" as const;
  readonly #ledger: AppendOnlyLedger | null;
  readonly #customEvidenceRefValidator: ((evidenceRef: string) => boolean) | null;

  /**
   * 16D containment: an execution record may cite a ledger event only if
   * the event exists AND is attributable to the SAME workspace as the
   * record's scope. Prevents cross-workspace evidence spoofing via crafted
   * eventIds. An injected `evidenceRefValidator` bypasses the workspace
   * check (test injection only) but never the existence check's semantics —
   * the injected validator owns the full verdict.
   */
  #verifyEvidenceRef(evidenceRef: string, scope: MemoryScope): boolean {
    if (this.#customEvidenceRefValidator !== null) {
      return this.#customEvidenceRefValidator(evidenceRef);
    }
    if (this.#ledger === null) return false;
    const evt = this.#ledger.events().find((e) => e.eventId === evidenceRef);
    if (evt === undefined) return false;
    return evt.workspaceId === scope.workspaceId;
  }

  public constructor(options: ExecutionMemoryStoreOptions = {}) {
    super(
      options.maxRecords === undefined
        ? { ...options, maxRecords: EXECUTION_MEMORY_MAX_RECORDS }
        : options
    );
    this.#ledger = options.ledger ?? null;
    this.#customEvidenceRefValidator = options.evidenceRefValidator ?? null;
  }

  /**
   * 16B input policy: execution bodies must be exactly
   * `{ execution: ExecutionMetadata }`, must contain no secret-like keys
   * (rejected, not redacted), must respect the raw-blob byte limit, and must
   * cite verifiable evidence. Credential-shaped values are redacted at rest
   * (the ONLY transform applied; everything else is rejected or stored
   * verbatim).
   */
  protected override preWriteCheck(
    input: Parameters<BaseMemoryStore["preWriteCheck"]>[0]
  ): MemoryPreWriteCheckResult {
    const body = input.body;

    // 1. NO SECRETS BY DEFAULT — reject, never store. Top-level body keys
    //    are checked before anything else: a secret channel is refused even
    //    when the rest of the body is malformed (nothing partial leaks).
    for (const key of Object.keys(body)) {
      if (secretKeyMatches(key)) {
        return {
          ok: false,
          denyReason: "secret_detected",
          reason: "body key '" + key + "' matches a secret-key pattern; execution memory stores no secrets",
        };
      }
    }

    // 2. Exact body shape: only the reserved `execution` key.
    const keys = Object.keys(body).sort();
    if (keys.length !== 1 || keys[0] !== EXECUTION_METADATA_KEY) {
      return {
        ok: false,
        denyReason: "invalid_input",
        reason:
          "execution memory body must be exactly { execution: ExecutionMetadata } with no other keys",
      };
    }
    const meta = body[EXECUTION_METADATA_KEY];
    const metaErr = validateExecutionMetadata(meta);
    if (metaErr !== null) {
      return { ok: false, denyReason: "invalid_input", reason: metaErr };
    }
    const executionObj = meta as Record<string, unknown>;

    // 3. NO SECRETS IN METADATA — every key at any depth of the metadata
    //    object is checked (always-on for execution stores); a metadata key
    //    named "apiKey" or nested "result.auth_token" is a secret channel
    //    regardless of its value.
    const nestedHits = collectNestedSecretKeys(executionObj, "");
    if (nestedHits.length > 0) {
      return {
        ok: false,
        denyReason: "secret_detected",
        reason: "execution metadata key '" + nestedHits[0]! + "' matches a secret-key pattern; execution memory stores no secrets",
      };
    }
    // 4. Raw-blob limit: evidence lives in the ledger, not in memory bodies.
    const bytes = bodyByteLength(body);
    if (bytes > EXECUTION_MEMORY_MAX_BLOB_BYTES) {
      return {
        ok: false,
        denyReason: "oversized_blob",
        reason:
          "execution memory body is " + String(bytes) +
          " bytes which exceeds EXECUTION_MEMORY_MAX_BLOB_BYTES (" +
          String(EXECUTION_MEMORY_MAX_BLOB_BYTES) +
          "); store raw output by reference (evidenceRef), not by value",
      };
    }

    // 5. Evidence integrity (16D): the cited ledger event must exist AND
    //    belong to the record's workspace (anti-spoofing containment).
    const evidenceRef = executionObj["evidenceRef"];
    if (typeof evidenceRef === "string") {
      const valid = this.#verifyEvidenceRef(evidenceRef, input.scope);
      if (!valid) {
        return {
          ok: false,
          denyReason: "invalid_input",
          reason:
            "execution.evidenceRef '" + evidenceRef +
            "' cannot be verified against the attached ledger; refusing to record unverifiable evidence",
        };
      }
    }

    // 6. Defense in depth: redact credential-shaped string VALUES (e.g. a
    //    summary quoting a bearer token). Key-level secrets were already
    //    rejected above.
    return { ok: true, body: redactCredentialValues(body) as MemoryRecordBody };
  }

  /**
   * Persist ONE validated execution outcome / failure / decision.
   * Denied unless policy allows the write, the scope is granted, the
   * metadata is complete, no secret-like keys are present, and the evidence
   * reference (when given) verifies against the ledger.
   */
  public recordExecution(
    ctx: MemoryAccessContext,
    request: ExecutionMemoryWriteRequest
  ): MemoryWriteResult {
    const recordedAtEpochMs = request.recordedAtEpochMs ?? this.nowMs;
    const metadata: Record<string, unknown> = {
      taskId: request.taskId,
      verb: request.verb,
      outcome: request.outcome,
      actorId: request.actor.id,
      actorType: request.actor.type,
      recordedAtEpochMs,
      policyDecision: request.policyDecision,
      evidenceRef: request.evidenceRef,
      summary: request.summary,
      attempt: request.attempt,
      exitCode: request.exitCode,
    };
    if (request.metadata !== undefined) {
      for (const [k, v] of Object.entries(request.metadata)) {
        if (metadata[k] === undefined) metadata[k] = v;
      }
    }
    return this.write(ctx, {
      scope: request.scope,
      provenance: request.provenance,
      retention: request.retention,
      body: { [EXECUTION_METADATA_KEY]: metadata },
    });
  }

  /**
   * Query execution memory within the caller's granted scope. Filters
   * (taskId / verb / actorId / outcome / fromMs..toMs) narrow only: a filter
   * can never surface a record outside the granted scope.
   */
  public query(
    ctx: MemoryAccessContext,
    filter: ExecutionMemoryQuery = {}
  ): ExecutionMemoryReadResult {
    const base = this.read(ctx, {});
    if (!base.ok) return base;
    const out: ExecutionMemoryRecord[] = [];
    for (const rec of base.records) {
      const meta = readExecutionMetadata(rec);
      if (meta === null) continue;
      if (filter.taskId !== undefined && meta.taskId !== filter.taskId) continue;
      if (filter.verb !== undefined && meta.verb !== filter.verb) continue;
      if (filter.actorId !== undefined && meta.actorId !== filter.actorId) continue;
      if (filter.outcome !== undefined && meta.outcome !== filter.outcome) continue;
      if (filter.fromMs !== undefined && meta.recordedAtEpochMs < filter.fromMs) continue;
      if (filter.toMs !== undefined && meta.recordedAtEpochMs > filter.toMs) continue;
      out.push(rec as ExecutionMemoryRecord);
    }
    return {
      ok: true,
      records: Object.freeze(out),
      policyEventId: base.policyEventId,
    };
  }

  /** Query + aggregate counters (bounded observability for dashboards). */
  public queryStats(
    ctx: MemoryAccessContext,
    filter: ExecutionMemoryQuery = {}
  ): ExecutionMemoryStatsResult {
    const base = this.query(ctx, filter);
    if (!base.ok) return base;
    const byOutcome: Record<ExecutionOutcome, number> = {
      success: 0,
      failure: 0,
      denied: 0,
    };
    let latest: number | undefined;
    for (const rec of base.records) {
      const meta = readExecutionMetadata(rec);
      if (meta === null) continue;
      byOutcome[meta.outcome] += 1;
      if (latest === undefined || meta.recordedAtEpochMs > latest) {
        latest = meta.recordedAtEpochMs;
      }
    }
    return {
      ok: true,
      total: base.records.length,
      byOutcome: Object.freeze(byOutcome),
      latestRecordedAtEpochMs: latest,
      policyEventId: base.policyEventId,
    };
  }
}

/** Typed accessor for the execution metadata of a stored record. */
export function readExecutionMetadata(
  record: MemoryRecord
): ExecutionMetadata | null {
  const v = record.body[EXECUTION_METADATA_KEY];
  if (validateExecutionMetadata(v) !== null) return null;
  return v as ExecutionMetadata;
}

export function newExecutionRecordId(): string {
  return newMemoryId("ex");
}
