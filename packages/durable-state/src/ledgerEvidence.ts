/**
 * PHASE 22C — Durable Ledger & Tool-Evidence Persistence (APPEND-ONLY
 * INTEGRATION).
 *
 * Persists the EXISTING hash-chained Event Ledger (Phase 12) and the EXISTING
 * sealed Phase-21 tool-run evidence into the 22B durable store WITHOUT
 * changing any frozen identity or semantic:
 *
 * - Event order, `hash`, and `previousHash` are preserved byte-for-byte. The
 *   hash chain is RE-DERIVED ON VERIFY with the ledger's OWN frozen hash
 *   vocabulary, supplied through the `LedgerHashPort` by the caller (the
 *   `@menog/event-ledger` functions). Nothing here re-implements or
 *   substitutes that vocabulary — a wrong port fails verification closed.
 * - Existing `ToolRunRecord` canonical hashes (`recordHash`, sealed by 21E's
 *   canonical discipline) are preserved verbatim and re-verified on read and
 *   on recovery with the same sorted-key canonical JSON discipline.
 * - The relationship between a tool-run evidence record and its ledger
 *   observation event is ATOMIC when written through
 *   `persistToolRunEvidenceWithObservation` (one store transaction, ONE
 *   commit sequence for both envelopes) — or EXPLICITLY PENDING via
 *   `persistPendingToolRunEvidence` (the recoverable pending state; the
 *   linkage is re-derived on every verification pass and can be retired
 *   through `resolvePendingEvidence`). There is no implicit pending state
 *   and no mutation path: evidence is append-only, so a pending record is
 *   never "promoted" — the observation link is DERIVED, rebuildable data.
 * - Verification detects: missing event, broken chain, event-hash mismatch,
 *   duplicate sequence, sequence gap, duplicate event id, identity-binding
 *   mismatch, manifest/evidence mismatch (drift), unreadable (quarantined)
 *   records, and stale checkpoints. Corruption is REPORTED and quarantined —
 *   never repaired, never healed, never silently re-hashed.
 * - Redaction is preserved: the mirror persists the event EXACTLY as the
 *   ledger holds it (the ledger redacted at append; re-redaction here would
 *   break the frozen hash). Raw tool output can never enter storage through
 *   this boundary: raw-output-shaped payload keys are denied
 *   (`raw_output_denied`) and the sealed evidence record carries hashes and
 *   metadata only.
 * - Recovery reuses the FROZEN 22A decision function `decideRecovery`: every
 *   admitted record is `recovered_data` with `executionAuthorized: false`
 *   and `policyAuthorized: false`. Durable state ≠ executable replay ≠
 *   authorization. Recovered records grant NO authority.
 */

import {
  DURABLE_RECORD_SCHEMA_VERSION,
  type DurableRecordEnvelope,
  type DurableRecordEnvelopeBody,
  type PersistFailureCode,
} from "./records.js";
import { canonicalHash, durableContentHash } from "./canonical.js";
import type { DurableStore } from "./store.js";
import {
  decideRecovery,
  type RecoveredRecordFinding,
  type RecoveryDecision,
  type RecoveryRequest,
  type RecoverySnapshot,
} from "./recovery.js";

// ── bounded reasons ──────────────────────────────────────────────────────────

const MAX_REASON_CHARS = 240;

function truncateReason(s: string): string {
  return s.length > MAX_REASON_CHARS ? s.slice(0, MAX_REASON_CHARS) : s;
}

// ── the ledger hash port (the ONE frozen vocabulary, caller-injected) ───────

/**
 * The Event Ledger's OWN frozen hash vocabulary, injected by the caller.
 * The canonical implementation is `@menog/event-ledger`'s
 * `serializeEventForHash` / `computeEventHash` / `GENESIS_PREVIOUS_HASH`.
 * This module never re-implements that vocabulary; a port that disagrees
 * with the sealed hashes fails verification closed (test-pinned).
 *
 * Members are declared as METHODS (bivariant) so the ledger's own typed
 * functions satisfy the port structurally.
 */
export interface LedgerHashPort {
  /** The ledger's genesis previousHash (the chain's root sentinel). */
  readonly genesisPreviousHash: string;
  /** The ledger's canonical event serialization (hash input). */
  serializeEventForHash(event: object): string;
  /** The ledger's event hash function (sha256 over the serialization). */
  computeEventHash(event: object): string;
}

/**
 * Build the sanctioned LedgerHashPort from caller-supplied functions of the
 * REAL @menog/event-ledger vocabulary. This exists so callers pass the
 * frozen functions ONCE, in one audited place, instead of hand-assembling
 * port objects at every call site (a wrong function still fails
 * verification closed — the port constructor adds convenience, not trust).
 */
export function makeLedgerHashPort(input: {
  readonly genesisPreviousHash: string;
  readonly serializeEventForHash: (event: object) => string;
  readonly computeEventHash: (event: object) => string;
}): LedgerHashPort {
  return {
    genesisPreviousHash: input.genesisPreviousHash,
    serializeEventForHash: (event) => input.serializeEventForHash(event),
    computeEventHash: (event) => input.computeEventHash(event),
  };
}

// ── structural mirrors of the frozen shapes (no dependency, no re-hash) ─────

/** Structural mirror of the ledger's Actor. */
export interface LedgerActorMirror {
  readonly type: string;
  readonly id: string;
}

/**
 * Structural mirror of a frozen ledger event (the hash-chained identity).
 * A real `MenogEvent` satisfies this mirror; the mirror carries `hash`
 * because that IS the frozen identity being preserved.
 */
export interface LedgerEventMirror {
  readonly eventId: string;
  readonly timestamp: string;
  readonly eventType: string;
  readonly actor: LedgerActorMirror;
  readonly workspaceId?: string;
  readonly taskId?: string;
  readonly verb?: string;
  readonly capability?: string;
  readonly policyDecision?: "allow" | "deny" | "not_applicable";
  readonly inputSummary?: Readonly<Record<string, unknown>>;
  readonly resultSummary?: Readonly<Record<string, unknown>>;
  readonly parentEventId?: string;
  readonly previousHash: string;
  readonly hash: string;
}

/** Structural mirror of a sealed Phase-21 tool-run record (hashes only). */
export interface SealedToolRunRecordMirror {
  readonly schemaVersion: string;
  readonly parents: {
    readonly skillId: string | null;
    readonly skillStepId: string | null;
    readonly taskId: string | null;
    readonly assignmentId: string | null;
    readonly agentId: string;
  };
  readonly requestHash: string;
  readonly toolId: string;
  readonly version: string;
  readonly manifestHash: string;
  readonly policy: { readonly outcome: string; readonly matchedRule: string | null };
  readonly isolation: { readonly profileId: string; readonly evidenceHash: string | null };
  readonly result: {
    readonly status: string;
    readonly exitCode: number | null;
    readonly timedOut: boolean;
    readonly outputHash: string | null;
    readonly outputBytes: number | null;
    readonly truncated: boolean;
  };
  readonly workspaceId: string;
  readonly recordedAt: string;
  readonly recordHash: string;
}

// ── raw-output denial (never persist raw output merely because storage exists)

/**
 * Payload key names (NORMALIZED FORM: camelCase/separators folded to
 * underscores) that mark RAW execution data. A payload carrying any of these
 * keys at any depth is denied at the storage boundary. The sealed evidence
 * record carries output HASHES and SIZES only — those are metadata, never
 * raw output, and are deliberately absent from this list. Both spellings are
 * listed where camelCase and all-lowercase normalize differently.
 */
export const RAW_OUTPUT_KEY_DENYLIST: readonly string[] = Object.freeze([
  "stdout",
  "stderr",
  "argv",
  "cwd",
  "environ",
  "environment",
  "env",
  "command_line",
  "commandline",
  "raw_output",
  "rawoutput",
  "output_text",
  "outputtext",
  "target_argv",
  "targetargv",
  "launcher_flags",
  "launcherflags",
  "launcher_path",
  "launcherpath",
  "executable_path",
  "executablepath",
]);

function normalizedKey(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/[-\s.]+/g, "_").toLowerCase();
}

function keyIsRawOutputShaped(key: string): boolean {
  const n = normalizedKey(key);
  return RAW_OUTPUT_KEY_DENYLIST.includes(n);
}

/** Depth-bounded scan for raw-output-shaped keys at any depth. */
export function findRawOutputKeyPaths(
  value: unknown,
  prefix: string = "",
  maxDepth: number = 8
): string[] {
  if (maxDepth <= 0 || value === null || typeof value !== "object" || Array.isArray(value)) {
    return [];
  }
  const hits: string[] = [];
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    const p = prefix.length === 0 ? k : prefix + "." + k;
    if (keyIsRawOutputShaped(k)) hits.push(p);
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      hits.push(...findRawOutputKeyPaths(v, p, maxDepth - 1));
    }
  }
  return hits;
}

// ── durable record ids (deterministic, bounded, test-pinned derivations) ────

const EVENT_ID_PATTERN = /^[A-Za-z0-9-]{8,64}$/;
const HASH64_PATTERN = /^[0-9a-f]{64}$/;

/**
 * The durable record id of a mirrored ledger event: `evt-` + the event's own
 * frozen `eventId` (validated; never truncated — truncation could collide).
 */
export function ledgerEntryRecordId(eventId: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  if (typeof eventId !== "string" || !EVENT_ID_PATTERN.test(eventId)) {
    return { ok: false, reason: "eventId must match " + String(EVENT_ID_PATTERN) + " to be mirrored (no truncation, no rewriting)" };
  }
  return { ok: true, recordId: "evt-" + eventId };
}

/**
 * The durable record id of sealed tool evidence: `run-` + the first 32 hex
 * chars of the record's frozen `recordHash` (content-addressed; re-persisting
 * the same evidence is therefore an idempotent duplicate denial).
 */
export function toolEvidenceRecordId(recordHash: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  if (typeof recordHash !== "string" || !HASH64_PATTERN.test(recordHash)) {
    return { ok: false, reason: "recordHash must be 64 lowercase hex chars" };
  }
  return { ok: true, recordId: "run-" + recordHash.slice(0, 32) };
}

// ── adapter failure vocabulary (closed; store denials carried verbatim) ─────

export const LEDGER_EVIDENCE_FAILURE_CODES = Object.freeze([
  "store_closed",
  "store_denied",             // store-level denial; storeFailureCode carried
  "invalid_event_id",
  "invalid_sequence",
  "invalid_record_hash",
  "record_hash_mismatch",
  "observation_not_linked",   // event does not reference the record hash
  "ledger_event_missing",     // no event in the store carries the record hash
  "raw_output_denied",
  "invalid_pending_reason",
  "chain_not_verifiable",     // checkpoint write refused over a broken chain
  "scan_truncated",
] as const);
export type LedgerEvidenceFailureCode = (typeof LEDGER_EVIDENCE_FAILURE_CODES)[number];

export type LedgerEvidencePersistResult =
  | {
      readonly ok: true;
      readonly committed: true;
      readonly recordId: string;
      readonly commitSequence: number;
    }
  | {
      readonly ok: false;
      readonly committed: false;
      readonly code: LedgerEvidenceFailureCode;
      readonly reason: string;
      readonly storeFailureCode: PersistFailureCode | null;
    };

export type LedgerEvidenceAtomicResult =
  | {
      readonly ok: true;
      readonly committed: true;
      readonly eventId: string;
      readonly eventRecordId: string;
      readonly evidenceRecordId: string;
      readonly commitSequence: number;
    }
  | {
      readonly ok: false;
      readonly committed: false;
      readonly code: LedgerEvidenceFailureCode;
      readonly reason: string;
      readonly storeFailureCode: PersistFailureCode | null;
    };

function deny(
  code: LedgerEvidenceFailureCode,
  reason: string,
  storeFailureCode: PersistFailureCode | null = null
): { ok: false; committed: false; code: LedgerEvidenceFailureCode; reason: string; storeFailureCode: PersistFailureCode | null } {
  return { ok: false, committed: false, code, reason: truncateReason(reason), storeFailureCode };
}

function storeDenial(failureCode: PersistFailureCode, reason: string) {
  return deny("store_denied", failureCode + ": " + reason, failureCode);
}

// ── observation state (closed union) ────────────────────────────────────────

export type EvidenceObservation =
  | { readonly state: "observed"; readonly eventId: string }
  | { readonly state: "pending"; readonly reason: string };

/** Derived-index id for evidence→observation links (rebuildable, never authoritative). */
export const EVIDENCE_OBSERVATION_INDEX_ID = "evidence-observation";

// ── envelope sealing (22A vocabulary only; no new fields, no re-hash) ───────

function sealEnvelope(input: {
  recordId: string;
  recordKind: "event_ledger_entry" | "tool_run_evidence";
  transactionId: string;
  createdAtEpochMs: number;
  payload: Record<string, unknown>;
}): DurableRecordEnvelope {
  const body: DurableRecordEnvelopeBody = {
    schemaVersion: DURABLE_RECORD_SCHEMA_VERSION,
    recordId: input.recordId,
    recordKind: input.recordKind,
    durabilityClass: "append_only",
    secretPolicy: "secret_free",
    authority: "durable_evidence",
    revision: 1,
    supersedesRevision: null,
    createdAtEpochMs: input.createdAtEpochMs,
    transactionId: input.transactionId,
    payload: input.payload,
  };
  return Object.freeze({ ...body, contentHash: durableContentHash(body) });
}

// ── small typed readers for stored payloads (fail closed on malformed) ──────

function asString(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

function asInt(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) ? v : null;
}

// ── 21E recordHash re-verification (same canonical discipline) ──────────────

/**
 * Re-verify a sealed tool-run record's own `recordHash`: sha256 over the
 * sorted-key canonical JSON of the record body (the exact discipline 21E's
 * `isolationEvidenceHash` uses; equivalence with real 21E records is
 * test-pinned). This NEVER repairs: a mismatch is a corruption finding.
 */
export function verifyToolRunRecordIntegrity(
  record: SealedToolRunRecordMirror
): { ok: true } | { ok: false; reason: string } {
  if (typeof record?.recordHash !== "string" || !HASH64_PATTERN.test(record.recordHash)) {
    return { ok: false, reason: "recordHash missing or malformed" };
  }
  const { recordHash: _omit, ...body } = record;
  const recomputed = canonicalHash(body);
  if (recomputed !== record.recordHash) {
    return { ok: false, reason: "recordHash does not re-derive from the sealed body — the record was modified after sealing" };
  }
  return { ok: true };
}

// ── persist: one mirrored ledger event ──────────────────────────────────────

export function persistLedgerEvent(
  store: DurableStore,
  input: {
    readonly event: LedgerEventMirror;
    /** The event's position in the ledger (its frozen order). */
    readonly sequence: number;
    readonly transactionId: string;
    readonly createdAtEpochMs?: number;
  }
): LedgerEvidencePersistResult {
  if (!store.isOpen) return deny("store_closed", "store is closed");
  const id = ledgerEntryRecordId(input.event.eventId);
  if (!id.ok) return deny("invalid_event_id", id.reason);
  if (!Number.isInteger(input.sequence) || input.sequence < 0) {
    return deny("invalid_sequence", "sequence must be an integer ≥ 0");
  }
  const eventPayload: Record<string, unknown> = { ...input.event };
  const rawPaths = findRawOutputKeyPaths(eventPayload);
  if (rawPaths.length > 0) {
    return deny("raw_output_denied", "raw-output-shaped payload keys denied at the storage boundary: " + rawPaths.slice(0, 4).join(", "));
  }
  const envelope = sealEnvelope({
    recordId: id.recordId,
    recordKind: "event_ledger_entry",
    transactionId: input.transactionId,
    createdAtEpochMs: input.createdAtEpochMs ?? Date.now(),
    payload: {
      eventId: input.event.eventId,
      sequence: input.sequence,
      previousHash: input.event.previousHash,
      hash: input.event.hash,
      event: eventPayload,
    },
  });
  const decision = store.persist(envelope);
  if (!decision.ok) return storeDenial(decision.failureCode, decision.reason);
  return { ok: true, committed: true, recordId: id.recordId, commitSequence: decision.commitSequence };
}

// ── persist: evidence + its ledger observation, ATOMICALLY ──────────────────

/**
 * Persist a sealed tool-run record AND its observation event in ONE store
 * transaction (one commit sequence for both envelopes). The event's
 * summaries must reference the record's `recordHash` (the 21E observation
 * linkage); otherwise the whole transaction is refused — an evidence record
 * is never stored claiming an observation that does not exist.
 */
export function persistToolRunEvidenceWithObservation(
  store: DurableStore,
  input: {
    readonly event: LedgerEventMirror;
    readonly sequence: number;
    readonly record: SealedToolRunRecordMirror;
    readonly transactionId: string;
    readonly createdAtEpochMs?: number;
  }
): LedgerEvidenceAtomicResult {
  if (!store.isOpen) return deny("store_closed", "store is closed");
  const eventId = ledgerEntryRecordId(input.event.eventId);
  if (!eventId.ok) return deny("invalid_event_id", eventId.reason);
  const runId = toolEvidenceRecordId(input.record.recordHash);
  if (!runId.ok) return deny("invalid_record_hash", runId.reason);
  if (!Number.isInteger(input.sequence) || input.sequence < 0) {
    return deny("invalid_sequence", "sequence must be an integer ≥ 0");
  }
  const integrity = verifyToolRunRecordIntegrity(input.record);
  if (!integrity.ok) return deny("record_hash_mismatch", integrity.reason);

  const eventPayload: Record<string, unknown> = { ...input.event };
  const rawEvent = findRawOutputKeyPaths(eventPayload);
  if (rawEvent.length > 0) {
    return deny("raw_output_denied", "raw-output-shaped keys in the observation event: " + rawEvent.slice(0, 4).join(", "));
  }
  const evidencePayload: Record<string, unknown> = {
    recordHash: input.record.recordHash,
    toolId: input.record.toolId,
    version: input.record.version,
    manifestHash: input.record.manifestHash,
    observation: { state: "observed", eventId: input.event.eventId },
    sealedRecord: { ...input.record },
  };
  const rawEvidence = findRawOutputKeyPaths(evidencePayload);
  if (rawEvidence.length > 0) {
    return deny("raw_output_denied", "raw-output-shaped keys in the sealed evidence: " + rawEvidence.slice(0, 4).join(", "));
  }

  // The 21E observation linkage: the event must reference the record hash.
  const summariesJson = JSON.stringify({
    inputSummary: input.event.inputSummary ?? null,
    resultSummary: input.event.resultSummary ?? null,
  });
  if (!summariesJson.includes(input.record.recordHash)) {
    return deny("observation_not_linked", "the observation event's summaries do not reference the record's recordHash — refusing to store an unobserved evidence claim");
  }

  const eventEnvelope = sealEnvelope({
    recordId: eventId.recordId,
    recordKind: "event_ledger_entry",
    transactionId: input.transactionId,
    createdAtEpochMs: input.createdAtEpochMs ?? Date.now(),
    payload: {
      eventId: input.event.eventId,
      sequence: input.sequence,
      previousHash: input.event.previousHash,
      hash: input.event.hash,
      event: eventPayload,
    },
  });
  const evidenceEnvelope = sealEnvelope({
    recordId: runId.recordId,
    recordKind: "tool_run_evidence",
    transactionId: input.transactionId,
    createdAtEpochMs: input.createdAtEpochMs ?? Date.now(),
    payload: evidencePayload,
  });

  const began = store.beginTransaction(input.transactionId);
  if (!began.ok) return storeDenial(began.failureCode as PersistFailureCode, began.reason);
  const stagedEvent = store.stageRecord(eventEnvelope);
  if (!stagedEvent.ok) {
    store.abortTransaction();
    return storeDenial(stagedEvent.failureCode as PersistFailureCode, stagedEvent.reason);
  }
  const stagedEvidence = store.stageRecord(evidenceEnvelope);
  if (!stagedEvidence.ok) {
    store.abortTransaction();
    return storeDenial(stagedEvidence.failureCode as PersistFailureCode, stagedEvidence.reason);
  }
  const committed = store.commitTransaction();
  if (!committed.ok) {
    return storeDenial(committed.failureCode, committed.reason);
  }
  // Derived, rebuildable convenience link; verification always re-derives
  // links from the authoritative event payloads, never from this index.
  store.setDerivedEntry(EVIDENCE_OBSERVATION_INDEX_ID, input.record.recordHash, input.event.eventId);
  return {
    ok: true,
    committed: true,
    eventId: input.event.eventId,
    eventRecordId: eventId.recordId,
    evidenceRecordId: runId.recordId,
    commitSequence: committed.commitSequence,
  };
}

// ── persist: EXPLICIT recoverable pending state (no observation claimed) ────

/**
 * Persist sealed tool evidence in the EXPLICIT pending state: the record
 * claims NO ledger observation. The reason is bounded and required — pending
 * is a named, auditable state, never a silent gap. Pending records are
 * recoverable: when the observation event later appears, verification
 * reports the link as derivable and `resolvePendingEvidence` retires the
 * pending state in the derived index. The evidence envelope itself is
 * append-only and is never mutated.
 */
export function persistPendingToolRunEvidence(
  store: DurableStore,
  input: {
    readonly record: SealedToolRunRecordMirror;
    readonly transactionId: string;
    readonly reason: string;
    readonly createdAtEpochMs?: number;
  }
): LedgerEvidencePersistResult {
  if (!store.isOpen) return deny("store_closed", "store is closed");
  const runId = toolEvidenceRecordId(input.record.recordHash);
  if (!runId.ok) return deny("invalid_record_hash", runId.reason);
  if (typeof input.reason !== "string" || input.reason.trim().length === 0 || input.reason.length > MAX_REASON_CHARS) {
    return deny("invalid_pending_reason", "a bounded non-empty reason (≤ " + String(MAX_REASON_CHARS) + " chars) is required for the explicit pending state");
  }
  const integrity = verifyToolRunRecordIntegrity(input.record);
  if (!integrity.ok) return deny("record_hash_mismatch", integrity.reason);
  const evidencePayload: Record<string, unknown> = {
    recordHash: input.record.recordHash,
    toolId: input.record.toolId,
    version: input.record.version,
    manifestHash: input.record.manifestHash,
    observation: { state: "pending", reason: input.reason },
    sealedRecord: { ...input.record },
  };
  const raw = findRawOutputKeyPaths(evidencePayload);
  if (raw.length > 0) {
    return deny("raw_output_denied", "raw-output-shaped keys in the sealed evidence: " + raw.slice(0, 4).join(", "));
  }
  const envelope = sealEnvelope({
    recordId: runId.recordId,
    recordKind: "tool_run_evidence",
    transactionId: input.transactionId,
    createdAtEpochMs: input.createdAtEpochMs ?? Date.now(),
    payload: evidencePayload,
  });
  const decision = store.persist(envelope);
  if (!decision.ok) return storeDenial(decision.failureCode, decision.reason);
  return { ok: true, committed: true, recordId: runId.recordId, commitSequence: decision.commitSequence };
}

// ── verify-on-read ───────────────────────────────────────────────────────────

export type MirroredEventRead =
  | {
      readonly ok: true;
      readonly event: LedgerEventMirror;
      readonly sequence: number;
      readonly commitSequence: number;
    }
  | { readonly ok: false; readonly code: LedgerEvidenceFailureCode; readonly reason: string; readonly quarantined: boolean };

/**
 * Read one mirrored ledger event and VERIFY it on read: the stored event's
 * hash must re-derive with the injected ledger vocabulary. Never repairs.
 */
export function readMirroredLedgerEvent(
  store: DurableStore,
  eventId: string,
  port: LedgerHashPort
): MirroredEventRead {
  if (!store.isOpen) return { ok: false, code: "store_closed", reason: "store is closed", quarantined: false };
  const id = ledgerEntryRecordId(eventId);
  if (!id.ok) return { ok: false, code: "invalid_event_id", reason: id.reason, quarantined: false };
  const read = store.readRecord(id.recordId);
  if (!read.ok) {
    return {
      ok: false,
      code: read.code === "quarantined" ? "store_denied" : "ledger_event_missing",
      reason: read.reason,
      quarantined: read.quarantined,
    };
  }
  const parsed = parseMirroredEvent(read.record.payload);
  if (!parsed.ok) {
    return { ok: false, code: "store_denied", reason: parsed.reason, quarantined: false };
  }
  const recomputed = port.computeEventHash(parsed.event);
  if (recomputed !== parsed.hash) {
    return { ok: false, code: "record_hash_mismatch", reason: "event hash does not re-derive from the stored bytes (ledger vocabulary)", quarantined: false };
  }
  return { ok: true, event: parsed.event, sequence: parsed.sequence, commitSequence: read.commitSequence };
}

export type ToolEvidenceRead =
  | {
      readonly ok: true;
      readonly record: SealedToolRunRecordMirror;
      readonly observation: EvidenceObservation;
      readonly commitSequence: number;
    }
  | { readonly ok: false; readonly code: LedgerEvidenceFailureCode; readonly reason: string; readonly quarantined: boolean };

/** Read sealed tool evidence and VERIFY its recordHash on read. Never repairs. */
export function readToolRunEvidence(
  store: DurableStore,
  recordHash: string,
  _port: LedgerHashPort | null = null
): ToolEvidenceRead {
  if (!store.isOpen) return { ok: false, code: "store_closed", reason: "store is closed", quarantined: false };
  const runId = toolEvidenceRecordId(recordHash);
  if (!runId.ok) return { ok: false, code: "invalid_record_hash", reason: runId.reason, quarantined: false };
  const read = store.readRecord(runId.recordId);
  if (!read.ok) {
    return {
      ok: false,
      code: read.code === "quarantined" ? "store_denied" : "ledger_event_missing",
      reason: read.reason,
      quarantined: read.quarantined,
    };
  }
  const payload = read.record.payload as Record<string, unknown>;
  const sealed = payload.sealedRecord;
  if (sealed === null || typeof sealed !== "object" || Array.isArray(sealed)) {
    return { ok: false, code: "store_denied", reason: "stored evidence payload is missing its sealed record", quarantined: false };
  }
  const record = sealed as SealedToolRunRecordMirror;
  const integrity = verifyToolRunRecordIntegrity(record);
  if (!integrity.ok) {
    return { ok: false, code: "record_hash_mismatch", reason: integrity.reason, quarantined: false };
  }
  const observation = parseObservation(payload.observation);
  if (!observation.ok) {
    return { ok: false, code: "store_denied", reason: observation.reason, quarantined: false };
  }
  return { ok: true, record, observation: observation.value, commitSequence: read.commitSequence };
}

function parseObservation(v: unknown): { ok: true; value: EvidenceObservation } | { ok: false; reason: string } {
  if (v === null || typeof v !== "object" || Array.isArray(v)) {
    return { ok: false, reason: "observation state missing or malformed" };
  }
  const o = v as Record<string, unknown>;
  if (o.state === "observed") {
    const eventId = asString(o.eventId);
    if (eventId === null) return { ok: false, reason: "observed state without an eventId" };
    return { ok: true, value: { state: "observed", eventId } };
  }
  if (o.state === "pending") {
    const reason = asString(o.reason);
    if (reason === null) return { ok: false, reason: "pending state without a bounded reason" };
    return { ok: true, value: { state: "pending", reason } };
  }
  return { ok: false, reason: "unknown observation state" };
}

function parseMirroredEvent(payload: Readonly<Record<string, unknown>>):
  | { ok: true; event: LedgerEventMirror; sequence: number; hash: string; previousHash: string; eventId: string }
  | { ok: false; reason: string } {
  const event = payload.event;
  if (event === null || typeof event !== "object" || Array.isArray(event)) {
    return { ok: false, reason: "mirrored event payload is missing its event object" };
  }
  const eventId = asString(payload.eventId);
  const hash = asString(payload.hash);
  const previousHash = asString(payload.previousHash);
  const sequence = asInt(payload.sequence);
  if (eventId === null || hash === null || previousHash === null || sequence === null) {
    return { ok: false, reason: "mirrored event payload is missing identity fields" };
  }
  const innerEventId = asString((event as unknown as Record<string, unknown>).eventId);
  if (innerEventId !== eventId) {
    return { ok: false, reason: "inner event identity disagrees with the envelope payload" };
  }
  return { ok: true, event: event as LedgerEventMirror, sequence, hash, previousHash, eventId };
}

// ── verification (read-only, fail closed, never repairs) ────────────────────

export const LEDGER_EVIDENCE_FINDING_CODES = Object.freeze([
  "store_closed",
  "event_hash_mismatch",
  "previous_hash_mismatch",
  "duplicate_sequence",
  "sequence_gap",
  "duplicate_event_id",
  "identity_binding_mismatch",
  "unreadable_record",
  "record_hash_mismatch",
  "observation_missing",
  "manifest_drift",
  "scan_truncated",
] as const);
export type LedgerEvidenceFindingCode = (typeof LEDGER_EVIDENCE_FINDING_CODES)[number];

export interface LedgerEvidenceFinding {
  readonly code: LedgerEvidenceFindingCode;
  /** Bounded detail; hostile content is never echoed. */
  readonly detail: string;
  readonly recordIds: readonly string[];
  readonly sequence: number | null;
}

export interface LedgerEvidenceVerificationReport {
  readonly storeSchemaVersion: string | null;
  readonly eventsScanned: number;
  readonly evidenceScanned: number;
  readonly eventsVerified: number;
  readonly evidenceVerified: number;
  /** sha256 tail of the longest verified chain prefix (genesis when empty). */
  readonly verifiedTailHash: string;
  /** HARD findings — any of them fails verification closed. */
  readonly findings: readonly LedgerEvidenceFinding[];
  readonly ok: boolean;
  /** Stale checkpoint (frozen 22B verdict): derived data must be rebuilt. */
  readonly derivedRebuildRequired: boolean;
  /** Explicit pending evidence whose observation event is still absent. */
  readonly pendingUnresolved: readonly string[];
  /** Explicit pending evidence whose observation event now exists (link derivable). */
  readonly pendingResolvable: readonly string[];
  readonly scanTruncated: boolean;
}

interface StoredEventRow {
  readonly recordId: string;
  readonly eventId: string;
  readonly sequence: number;
  readonly hash: string;
  readonly previousHash: string;
  readonly event: LedgerEventMirror;
}

const DEFAULT_MAX_RECORDS = 10_000;

/**
 * Full read-only verification of the persisted ledger mirror and sealed
 * evidence. Detects missing events, broken chains, event-hash mismatches,
 * duplicate sequences, sequence gaps, duplicate event ids, identity-binding
 * mismatches, unreadable (quarantined) records, record-hash mismatches,
 * observation-missing evidence, manifest drift, stale checkpoints, and scan
 * bound exhaustion. Corruption is REPORTED — never repaired, never healed.
 */
export function verifyPersistedLedgerAndEvidence(
  store: DurableStore,
  port: LedgerHashPort,
  options: { readonly maxRecords?: number } = {}
): LedgerEvidenceVerificationReport {
  const findings: LedgerEvidenceFinding[] = [];
  const pendingUnresolved: string[] = [];
  const pendingResolvable: string[] = [];
  if (!store.isOpen) {
    findings.push({ code: "store_closed", detail: "store is closed — nothing can be verified", recordIds: [], sequence: null });
    return report(0, 0, 0, 0, port.genesisPreviousHash, findings, false, [], [], false, store.storeSchemaVersion);
  }
  const maxRecords = options.maxRecords ?? DEFAULT_MAX_RECORDS;

  const eventIds = store.listRecordIds("event_ledger_entry");
  const evidenceIds = store.listRecordIds("tool_run_evidence");
  const scanTruncated = eventIds.length + evidenceIds.length > maxRecords;
  if (scanTruncated) {
    findings.push({
      code: "scan_truncated",
      detail: "store holds more records than the verification bound — refusing partial verification",
      recordIds: [],
      sequence: null,
    });
  }
  const eventBound = Math.min(eventIds.length, maxRecords);
  const evidenceBound = Math.min(evidenceIds.length, Math.max(0, maxRecords - eventBound));

  // ── events: read + identity binding ──────────────────────────────────────
  const events: StoredEventRow[] = [];
  const unreadableOrFailed = new Set<string>();
  const verifiedEventIds: string[] = [];
  let duplicateEventIds = 0;
  for (let i = 0; i < eventBound; i++) {
    const recordId = eventIds[i] as string;
    const read = store.readRecord(recordId);
    if (!read.ok) {
      unreadableOrFailed.add(recordId);
      findings.push({
        code: "unreadable_record",
        detail: "mirrored event record could not be read" + (read.quarantined ? " (quarantined — stored bytes no longer verify)" : " (" + read.code + ")"),
        recordIds: [recordId],
        sequence: null,
      });
      continue;
    }
    const parsed = parseMirroredEvent(read.record.payload);
    if (!parsed.ok) {
      unreadableOrFailed.add(recordId);
      findings.push({ code: "identity_binding_mismatch", detail: parsed.reason, recordIds: [recordId], sequence: null });
      continue;
    }
    const expectedId = ledgerEntryRecordId(parsed.eventId);
    if (!expectedId.ok || expectedId.recordId !== recordId) {
      unreadableOrFailed.add(recordId);
      findings.push({ code: "identity_binding_mismatch", detail: "stored record id does not match the derived id of its eventId", recordIds: [recordId], sequence: null });
      continue;
    }
    // Inner/outer identity binding: hash and previousHash must agree.
    const innerEvent = parsed.event as unknown as Record<string, unknown>;
    const innerHash = asString(innerEvent.hash);
    const innerPrevious = asString(innerEvent.previousHash);
    if (innerHash !== parsed.hash || innerPrevious !== parsed.previousHash) {
      unreadableOrFailed.add(recordId);
      findings.push({ code: "identity_binding_mismatch", detail: "event hash/previousHash disagree between the payload header and the sealed event body", recordIds: [recordId], sequence: null });
      continue;
    }
    events.push({ recordId, eventId: parsed.eventId, sequence: parsed.sequence, hash: parsed.hash, previousHash: parsed.previousHash, event: parsed.event });
    verifiedEventIds.push(recordId);
  }
  // Duplicate event ids (different record ids claiming one eventId).
  const byEventId = new Map<string, string[]>();
  for (const e of events) {
    const list = byEventId.get(e.eventId) ?? [];
    list.push(e.recordId);
    byEventId.set(e.eventId, list);
  }
  for (const [eventId, ids] of byEventId) {
    if (ids.length > 1) {
      duplicateEventIds += ids.length - 1;
      findings.push({ code: "duplicate_event_id", detail: "eventId '" + eventId + "' is claimed by multiple stored records", recordIds: ids.slice(), sequence: null });
    }
  }

  // ── chain: order, duplicates, gaps, continuity, hash re-derivation ───────
  const sorted = events.slice().sort((a, b) => a.sequence - b.sequence);
  const seenSequences = new Map<number, string[]>();
  for (const e of sorted) {
    const list = seenSequences.get(e.sequence) ?? [];
    list.push(e.recordId);
    seenSequences.set(e.sequence, list);
  }
  for (const [seq, ids] of seenSequences) {
    if (ids.length > 1) {
      findings.push({ code: "duplicate_sequence", detail: "sequence " + String(seq) + " is claimed by multiple events", recordIds: ids.slice(), sequence: seq });
    }
  }
  let verifiedTailHash = port.genesisPreviousHash;
  let expectedSequence = 0;
  let chainIntact = true;
  let eventsVerified = 0;
  for (const e of sorted) {
    if (e.sequence !== expectedSequence) {
      findings.push({ code: "sequence_gap", detail: "expected sequence " + String(expectedSequence) + " but found " + String(e.sequence), recordIds: [e.recordId], sequence: e.sequence });
      expectedSequence = e.sequence;
    }
    if (chainIntact && e.previousHash !== verifiedTailHash) {
      chainIntact = false;
      findings.push({ code: "previous_hash_mismatch", detail: "event at sequence " + String(e.sequence) + " does not chain to the verified tail (missing event or forged entry)", recordIds: [e.recordId], sequence: e.sequence });
    }
    const recomputed = port.computeEventHash(e.event);
    if (recomputed !== e.hash) {
      findings.push({ code: "event_hash_mismatch", detail: "event hash does not re-derive from the stored event bytes with the ledger's own vocabulary", recordIds: [e.recordId], sequence: e.sequence });
    } else {
      eventsVerified++;
    }
    if (chainIntact && recomputed === e.hash) {
      verifiedTailHash = e.hash;
    }
    expectedSequence = e.sequence + 1;
  }

  // ── evidence: read + recordHash + observation linkage + manifest drift ──
  const evidenceVerifiedIds: string[] = [];
  let evidenceVerified = 0;
  const manifestByTool = new Map<string, Map<string, string[]>>();
  const observedEventSummaries = sorted
    .map((e) => JSON.stringify({ inputSummary: e.event.inputSummary ?? null, resultSummary: e.event.resultSummary ?? null }))
    .join("\n");
  for (let i = 0; i < evidenceBound; i++) {
    const recordId = evidenceIds[i] as string;
    const read = store.readRecord(recordId);
    if (!read.ok) {
      unreadableOrFailed.add(recordId);
      findings.push({
        code: "unreadable_record",
        detail: "evidence record could not be read" + (read.quarantined ? " (quarantined — stored bytes no longer verify)" : " (" + read.code + ")"),
        recordIds: [recordId],
        sequence: null,
      });
      continue;
    }
    const payload = read.record.payload as Record<string, unknown>;
    const recordHash = asString(payload.recordHash);
    const sealed = payload.sealedRecord;
    if (recordHash === null || sealed === null || typeof sealed !== "object" || Array.isArray(sealed)) {
      unreadableOrFailed.add(recordId);
      findings.push({ code: "identity_binding_mismatch", detail: "evidence payload is missing its recordHash or sealed record", recordIds: [recordId], sequence: null });
      continue;
    }
    const expectedId = toolEvidenceRecordId(recordHash);
    if (!expectedId.ok || expectedId.recordId !== recordId) {
      unreadableOrFailed.add(recordId);
      findings.push({ code: "identity_binding_mismatch", detail: "stored evidence record id does not match the content-addressed id of its recordHash", recordIds: [recordId], sequence: null });
      continue;
    }
    const record = sealed as SealedToolRunRecordMirror;
    if (asString(record.recordHash) !== recordHash) {
      unreadableOrFailed.add(recordId);
      findings.push({ code: "identity_binding_mismatch", detail: "sealed record's recordHash disagrees with the payload header", recordIds: [recordId], sequence: null });
      continue;
    }
    const integrity = verifyToolRunRecordIntegrity(record);
    if (!integrity.ok) {
      unreadableOrFailed.add(recordId);
      findings.push({ code: "record_hash_mismatch", detail: integrity.reason, recordIds: [recordId], sequence: null });
      continue;
    }
    evidenceVerified++;
    evidenceVerifiedIds.push(recordId);

    // Manifest drift across the persisted evidence set (same tool@version,
    // different manifestHash) — detectable without the registry.
    const toolKey = asString(record.toolId) + "@" + asString(record.version);
    const manifestHash = asString(record.manifestHash);
    if (manifestHash !== null) {
      const perTool = manifestByTool.get(toolKey) ?? new Map<string, string[]>();
      const holders = perTool.get(manifestHash) ?? [];
      holders.push(recordId);
      perTool.set(manifestHash, holders);
      manifestByTool.set(toolKey, perTool);
    }

    // Observation linkage, derived from authoritative event payloads ONLY.
    const observation = parseObservation(payload.observation);
    if (!observation.ok) {
      findings.push({ code: "identity_binding_mismatch", detail: observation.reason, recordIds: [recordId], sequence: null });
      continue;
    }
    if (observation.value.state === "observed") {
      const observedHere = observedEventSummaries.includes(recordHash);
      if (!observedHere) {
        findings.push({
          code: "observation_missing",
          detail: "evidence claims an observed run but no persisted ledger event carries its recordHash (atomic relationship broken or forged)",
          recordIds: [recordId],
          sequence: null,
        });
      }
    } else {
      if (observedEventSummaries.includes(recordHash)) {
        pendingResolvable.push(recordId);
      } else {
        pendingUnresolved.push(recordId);
      }
    }
  }
  for (const [toolKey, perTool] of manifestByTool) {
    if (perTool.size > 1) {
      const ids = [...perTool.values()].flat();
      findings.push({ code: "manifest_drift", detail: "tool '" + toolKey + "' is sealed under " + String(perTool.size) + " different manifestHashes in the persisted evidence set", recordIds: ids, sequence: null });
    }
  }

  // ── checkpoint staleness (frozen 22B verdict; never healed) ─────────────
  let derivedRebuildRequired = false;
  const checkpoint = store.verifyCheckpoint({ ledgerTailHash: verifiedTailHash });
  if (checkpoint.verdict === "rebuild_required") {
    derivedRebuildRequired = true;
  }

  return report(
    events.length + evidenceBound,
    events.length,
    eventsVerified,
    evidenceVerified,
    verifiedTailHash,
    findings,
    derivedRebuildRequired,
    pendingUnresolved,
    pendingResolvable,
    scanTruncated,
    store.storeSchemaVersion
  );

  function report(
    scanned: number,
    eventsScanned: number,
    eventsVerifiedCount: number,
    evidenceVerifiedCount: number,
    tail: string,
    hardFindings: LedgerEvidenceFinding[],
    rebuildRequired: boolean,
    unresolved: string[],
    resolvable: string[],
    truncated: boolean,
    schemaVersion: string | null
  ): LedgerEvidenceVerificationReport {
    return {
      storeSchemaVersion: schemaVersion,
      eventsScanned,
      evidenceScanned: Math.max(0, scanned - eventsScanned),
      eventsVerified: eventsVerifiedCount,
      evidenceVerified: evidenceVerifiedCount,
      verifiedTailHash: tail,
      findings: Object.freeze(hardFindings),
      ok: hardFindings.length === 0 && !truncated && duplicateEventIds === 0,
      derivedRebuildRequired: rebuildRequired,
      pendingUnresolved: Object.freeze(unresolved),
      pendingResolvable: Object.freeze(resolvable),
      scanTruncated: truncated,
    };
  }
}

// ── checkpoint reconciliation (fail closed over corruption) ─────────────────

export type LedgerCheckpointResult =
  | { readonly ok: true; readonly checkpointId: string; readonly ledgerTailHash: string; readonly verification: LedgerEvidenceVerificationReport }
  | { readonly ok: false; readonly code: LedgerEvidenceFailureCode; readonly reason: string; readonly verification: LedgerEvidenceVerificationReport | null };

/**
 * Write a store checkpoint bound to the VERIFIED ledger tail. Refuses (fail
 * closed) when verification finds corruption — no checkpoint is ever written
 * over a broken or unverified chain. Staleness of an EXISTING checkpoint is
 * detected by the frozen `store.verifyCheckpoint` verdict inside every
 * verification pass (`derivedRebuildRequired`).
 */
export function writeLedgerCheckpoint(
  store: DurableStore,
  port: LedgerHashPort,
  input: { readonly checkpointId: string; readonly maxRecords?: number }
): LedgerCheckpointResult {
  const verification = verifyPersistedLedgerAndEvidence(store, port, { maxRecords: input.maxRecords });
  if (!verification.ok) {
    return {
      ok: false,
      code: "chain_not_verifiable",
      reason: "refusing to checkpoint: " + String(verification.findings.length) + " hard finding(s) — corruption is never papered over",
      verification,
    };
  }
  const written = store.writeCheckpoint({ checkpointId: input.checkpointId, ledgerTailHash: verification.verifiedTailHash });
  if (!written.ok) {
    return { ok: false, code: "store_denied", reason: written.reason, verification };
  }
  return { ok: true, checkpointId: written.checkpoint.checkpointId, ledgerTailHash: written.checkpoint.ledgerTailHash, verification };
}

// ── pending-state retirement (derived link only; the evidence never mutates) ─

/**
 * Retire an explicit pending state whose observation event now exists: writes
 * the DERIVED observation link (rebuildable, never authoritative). The
 * evidence envelope itself is append-only and is never touched. Fails closed
 * when no persisted event carries the record hash.
 */
export function resolvePendingEvidence(
  store: DurableStore,
  recordHash: string
): { ok: true; eventId: string } | { ok: false; code: LedgerEvidenceFailureCode; reason: string } {
  if (!store.isOpen) return { ok: false, code: "store_closed", reason: "store is closed" };
  if (typeof recordHash !== "string" || !HASH64_PATTERN.test(recordHash)) {
    return { ok: false, code: "invalid_record_hash", reason: "recordHash must be 64 lowercase hex chars" };
  }
  const events = store.listRecordIds("event_ledger_entry");
  for (const recordId of events) {
    const read = store.readRecord(recordId);
    if (!read.ok) continue; // unreadable records carry no links; verification reports them
    const parsed = parseMirroredEvent(read.record.payload);
    if (!parsed.ok) continue;
    const summariesJson = JSON.stringify({
      inputSummary: parsed.event.inputSummary ?? null,
      resultSummary: parsed.event.resultSummary ?? null,
    });
    if (summariesJson.includes(recordHash)) {
      const set = store.setDerivedEntry(EVIDENCE_OBSERVATION_INDEX_ID, recordHash, parsed.eventId);
      if (!set.ok) {
        return { ok: false, code: "store_denied", reason: set.reason };
      }
      return { ok: true, eventId: parsed.eventId };
    }
  }
  return { ok: false, code: "ledger_event_missing", reason: "no persisted ledger event carries this recordHash — pending state remains explicit" };
}

/** The derived observation link for a record hash (never authoritative). */
export function getEvidenceObservationLink(store: DurableStore, recordHash: string): string | null {
  return store.getDerivedEntry(EVIDENCE_OBSERVATION_INDEX_ID, recordHash);
}

// ── recovery (frozen 22A decision vocabulary; recovered data grants nothing) ─

export interface LedgerEvidenceRecoveryResult {
  readonly verification: LedgerEvidenceVerificationReport;
  /** Built EXCLUSIVELY by the frozen 22A `decideRecovery`. */
  readonly decision: RecoveryDecision;
  /** Stale checkpoint verdict: derived data must be rebuilt before use. */
  readonly derivedRebuildRequired: boolean;
}

/**
 * Verify the persisted ledger/evidence and map the outcome onto the FROZEN
 * 22A recovery decision. Every admitted record is `recovered_data` with
 * `executionAuthorized: false` and `policyAuthorized: false`; corruption is
 * quarantined, never repaired; a truncated scan rejects recovery entirely;
 * a stale checkpoint demands a derived rebuild.
 */
export function recoverLedgerAndEvidence(
  store: DurableStore,
  port: LedgerHashPort,
  request: RecoveryRequest,
  options: { readonly maxRecords?: number } = {}
): LedgerEvidenceRecoveryResult {
  const verification = verifyPersistedLedgerAndEvidence(store, port, options);
  const findings: RecoveredRecordFinding[] = [];
  const hardIds = new Set<string>(verification.findings.flatMap((f) => f.recordIds));
  const unreadable = new Set<string>(
    verification.findings.filter((f) => f.code === "unreadable_record").flatMap((f) => f.recordIds)
  );
  // Verified mirrored events.
  const eventIds = store.listRecordIds("event_ledger_entry");
  for (const recordId of eventIds) {
    if (hardIds.has(recordId)) continue;
    findings.push({ recordId, recordKind: "event_ledger_entry", integrityStatus: "integrity_verified", cause: null, alreadyQuarantined: false });
  }
  const evidenceIds = store.listRecordIds("tool_run_evidence");
  for (const recordId of evidenceIds) {
    if (hardIds.has(recordId)) continue;
    findings.push({ recordId, recordKind: "tool_run_evidence", integrityStatus: "integrity_verified", cause: null, alreadyQuarantined: false });
  }
  // Hard-failed records (including store-quarantined ones) fail closed.
  // Store-quarantined records are `integrity_unknown` (alreadyQuarantined —
  // their bytes could not even be verified); semantically-tampered records
  // that still read back re-sealed are `integrity_failed`. The frozen 22A
  // decision function demands this split: only non-quarantined failures are
  // routed to ITS quarantine list; already-quarantined ones are excluded
  // from admission (and stay in the store's quarantine table).
  for (const finding of verification.findings) {
    for (const recordId of finding.recordIds) {
      if (findings.some((f) => f.recordId === recordId)) continue;
      const wasQuarantined = unreadable.has(recordId);
      findings.push({
        recordId,
        recordKind: recordId.startsWith("run-") ? "tool_run_evidence" : "event_ledger_entry",
        integrityStatus: wasQuarantined ? "integrity_unknown" : "integrity_failed",
        cause: finding.code,
        alreadyQuarantined: wasQuarantined,
      });
    }
  }
  const snapshot: RecoverySnapshot = {
    expectedStoreSchemaVersion: request.expectedStoreSchemaVersion,
    actualStoreSchemaVersion: verification.storeSchemaVersion,
    committedThrough: store.committedThrough,
    // 22B has no torn-write window at this layer (engine-level atomic
    // transactions); the faithful observation equals the committed position.
    observedThrough: store.committedThrough,
    totalRecordsScanned: verification.eventsScanned + verification.evidenceScanned,
    findings,
    scanTruncated: verification.scanTruncated,
  };
  const decision = decideRecovery(snapshot, request);
  return { verification, decision, derivedRebuildRequired: verification.derivedRebuildRequired };
}
