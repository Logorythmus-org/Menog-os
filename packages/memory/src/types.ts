import type { Actor } from "@menog/core";

/**
 * Phase 16A — Memory Architecture: structured runtime memory contracts.
 *
 * Memory in Menog is STRUCTURED RUNTIME STATE with explicit scope, provenance,
 * and retention. It is NOT a raw chat transcript and never becomes execution
 * authority: reads and writes are policy-gated and policy-observable.
 */

export const MEMORY_SCHEMA_VERSION = "menog-memory/v0" as const;
export type MemorySchemaVersion = typeof MEMORY_SCHEMA_VERSION;

/**
 * Coarse kind of a memory entry. `working` = session/task-scoped runtime
 * learning; `project` = persistent workspace-scoped knowledge; `execution` =
 * structured record of what the runtime DID (16B: outcomes, failures,
 * decisions, evidence references).
 */
export type MemoryKind = "working" | "project" | "execution";

export const KNOWN_MEMORY_KINDS: readonly MemoryKind[] = Object.freeze([
  "working",
  "project",
  "execution",
]);

export function isMemoryKind(value: unknown): value is MemoryKind {
  return (
    value === "working" ||
    value === "project" ||
    value === "execution"
  );
}

/**
 * Scope boundary of a memory entry. A memory read/write may only touch a
 * scope that the caller has been granted (scope isolation is enforced by the
 * stores and verified by tests).
 */
export interface MemoryScope {
  /** Workspace identifier this memory is bound to (isolation key). */
  readonly workspaceId: string;
  /** Optional task identifier narrowing the scope below workspace level. */
  readonly taskId?: string;
  /** Optional session identifier narrowing working memory to one run. */
  readonly sessionId?: string;
}

/**
 * Where a memory entry originated. External content (tool output, repository
 * files, model output) is UNTRUSTED INPUT and is recorded as such so that no
 * consumer can mistake it for system-instruction-grade or runtime-authored
 * content (invariant: NO EXTERNAL CONTENT AS SYSTEM INSTRUCTION).
 */
export type MemoryProvenanceOrigin =
  | "runtime"
  | "human"
  | "agent"
  | "tool_output"
  | "model_output"
  | "repo_content"
  | "external";

export const KNOWN_MEMORY_PROVENANCE_ORIGINS: readonly MemoryProvenanceOrigin[] =
  Object.freeze([
    "runtime",
    "human",
    "agent",
    "tool_output",
    "model_output",
    "repo_content",
    "external",
  ]);

export function isMemoryProvenanceOrigin(
  value: unknown
): value is MemoryProvenanceOrigin {
  return (
    typeof value === "string" &&
    (KNOWN_MEMORY_PROVENANCE_ORIGINS as readonly string[]).includes(value)
  );
}

export interface MemoryProvenance {
  readonly origin: MemoryProvenanceOrigin;
  /** Actor that produced or relayed the memory content. */
  readonly actor: Actor;
  /** Ledger event id the content is anchored to, when one exists. */
  readonly sourceEventId?: string;
  /** Free-form, non-authoritative label (e.g. "menog inspect report"). */
  readonly label?: string;
  /** True when content entered via a path outside the runtime's own control. */
  readonly untrusted: boolean;
}

/**
 * Retention policy attached to every entry. Retention is metadata only in
 * 16A: entries are never silently destroyed or silently eternalized; expiry
 * is observable state, and expired entries are invisible to reads.
 */
export type MemoryRetentionClass = "ephemeral" | "session" | "persistent";

export const KNOWN_MEMORY_RETENTION_CLASSES: readonly MemoryRetentionClass[] =
  Object.freeze(["ephemeral", "session", "persistent"]);

export function isMemoryRetentionClass(
  value: unknown
): value is MemoryRetentionClass {
  return (
    value === "ephemeral" ||
    value === "session" ||
    value === "persistent"
  );
}

export interface MemoryRetention {
  readonly retentionClass: MemoryRetentionClass;
  /** Absolute epoch-ms expiry for ephemeral entries. */
  readonly expiresAtEpochMs?: number;
}

/** The structured payload. Keys are plain strings; values JSON-serializable. */
export type MemoryRecordBody = Readonly<Record<string, unknown>>;

/** Fully validated, immutable memory record as stored by a store. */
export interface MemoryRecord {
  readonly schemaVersion: MemorySchemaVersion;
  readonly memoryId: string;
  readonly kind: MemoryKind;
  readonly scope: MemoryScope;
  readonly provenance: MemoryProvenance;
  readonly retention: MemoryRetention;
  readonly body: MemoryRecordBody;
  readonly createdAtEpochMs: number;
  readonly createdByActorId: string;
}

/** Caller-supplied input for a memory write. */
export interface MemoryRecordInput {
  readonly kind: MemoryKind;
  readonly scope: MemoryScope;
  readonly provenance: MemoryProvenance;
  readonly retention: MemoryRetention;
  readonly body: MemoryRecordBody;
}

/** Machine-readable deny reasons emitted by memory stores. */
export type MemoryDenyReason =
  | "scope_mismatch"
  | "write_not_allowed"
  | "read_not_allowed"
  | "untrusted_provenance_write_denied"
  | "expired_entry"
  | "invalid_input"
  | "secret_detected"
  | "oversized_blob";

export interface MemoryDenial {
  readonly ok: false;
  readonly denyReason: MemoryDenyReason;
  readonly reason: string;
}

export interface MemoryWriteSuccess {
  readonly ok: true;
  readonly record: MemoryRecord;
  readonly policyEventId?: string;
}

export interface MemoryReadSuccess {
  readonly ok: true;
  readonly records: readonly MemoryRecord[];
  readonly policyEventId?: string;
}

export type MemoryWriteResult = MemoryWriteSuccess | MemoryDenial;
export type MemoryReadResult = MemoryReadSuccess | MemoryDenial;

export function isMemoryDenial(
  r: MemoryWriteResult | MemoryReadResult
): r is MemoryDenial {
  return r.ok === false;
}

/**
 * The policy gate every store delegates to. Deny-by-default: a gate that is
 * absent denies all memory access.
 */
export interface MemoryPolicyGate {
  /**
   * Must return true only when the policy engine allows this actor to
   * perform the named operation on memory bound to the given scope.
   */
  readonly canReadMemory: (input: {
    readonly actor: Actor;
    readonly scope: MemoryScope;
  }) => boolean;
  readonly canWriteMemory: (input: {
    readonly actor: Actor;
    readonly scope: MemoryScope;
  }) => boolean;
}

/**
 * Phase 16B — Execution Memory.
 *
 * Execution memory is the structured record of what the runtime DID:
 * validated execution outcomes, failures, decisions, and ledger evidence
 * references. It exists so that task/verb/agent/time queries can be answered
 * from bounded, policy-gated state instead of raw transcripts.
 *
 * Security contract (enforced by `ExecutionMemoryStore`):
 *  - Records live under the reserved body key `execution` with the typed
 *    `ExecutionMetadata` shape (taskId, verb, outcome, actorId, actorType,
 *    recordedAtEpochMs, policyDecision, evidenceRef, ...).
 *  - NO SECRETS BY DEFAULT: writes whose body keys look secret-like are
 *    rejected with `secret_detected` before anything is persisted.
 *  - Credential-shaped string VALUES are redacted at rest (defense in depth).
 *  - Raw blobs are rejected above EXECUTION_MEMORY_MAX_BLOB_BYTES with
 *    `oversized_blob` — evidence is stored by reference (evidenceRef), not
 *    by value.
 *  - Every allowed write/read is still policy-gated, scope-isolated and
 *    ledger-anchored exactly like 16A memory.
 */

/** Terminal disposition of one execution attempt. */
export type ExecutionOutcome = "success" | "failure" | "denied";

export const KNOWN_EXECUTION_OUTCOMES: readonly ExecutionOutcome[] =
  Object.freeze(["success", "failure", "denied"]);

export function isExecutionOutcome(value: unknown): value is ExecutionOutcome {
  return value === "success" || value === "failure" || value === "denied";
}

/** Typed metadata carried under the reserved body key `execution`. */
export interface ExecutionMetadata {
  readonly taskId: string;
  readonly verb: string;
  readonly outcome: ExecutionOutcome;
  readonly actorId: string;
  readonly actorType: string;
  /** When the execution happened (caller-known), not when it was recorded. */
  readonly recordedAtEpochMs: number;
  /** Policy verdict that governed the execution: allow | deny | not_applicable. */
  readonly policyDecision: string;
  /** Ledger event id anchoring the outcome to authoritative evidence. */
  readonly evidenceRef?: string;
  /** Short human-readable outcome summary (value-redacted at rest). */
  readonly summary?: string;
  readonly attempt?: number;
  readonly exitCode?: number;
}

/** A memory record whose body carries valid execution metadata. */
export type ExecutionMemoryRecord = MemoryRecord & {
  readonly body: { readonly execution: ExecutionMetadata };
};

/** Caller-supplied request for persisting one execution outcome. */
export interface ExecutionMemoryWriteRequest {
  readonly scope: MemoryScope;
  readonly provenance: MemoryProvenance;
  readonly retention: MemoryRetention;
  /** Actor that performed the execution (recorded in metadata). */
  readonly actor: Actor;
  readonly taskId: string;
  readonly verb: string;
  readonly outcome: ExecutionOutcome;
  readonly policyDecision: string;
  readonly evidenceRef?: string;
  readonly summary?: string;
  readonly attempt?: number;
  readonly exitCode?: number;
  /** Defaults to the store clock when omitted. */
  readonly recordedAtEpochMs?: number;
  /** Extra structured metadata; secret-like keys are rejected, credential-shaped values redacted. */
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/** Query filters for execution memory. All filters AND together. */
export interface ExecutionMemoryQuery {
  readonly taskId?: string;
  readonly verb?: string;
  readonly actorId?: string;
  readonly outcome?: ExecutionOutcome;
  /** Inclusive lower bound on metadata.recordedAtEpochMs. */
  readonly fromMs?: number;
  /** Inclusive upper bound on metadata.recordedAtEpochMs. */
  readonly toMs?: number;
}

export interface ExecutionMemoryReadSuccess {
  readonly ok: true;
  readonly records: readonly ExecutionMemoryRecord[];
  readonly policyEventId?: string;
}

export type ExecutionMemoryReadResult = ExecutionMemoryReadSuccess | MemoryDenial;

export interface ExecutionMemoryStatsSuccess {
  readonly ok: true;
  readonly total: number;
  readonly byOutcome: Readonly<Record<ExecutionOutcome, number>>;
  readonly latestRecordedAtEpochMs?: number;
  readonly policyEventId?: string;
}

export type ExecutionMemoryStatsResult = ExecutionMemoryStatsSuccess | MemoryDenial;

/** Result of the store-specific pre-write hook (16B). */
export type MemoryPreWriteCheckResult =
  | { readonly ok: true; readonly body: MemoryRecordBody }
  | { readonly ok: false; readonly denyReason: MemoryDenyReason; readonly reason: string };
