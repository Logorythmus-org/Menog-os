/**
 * PHASE 22D — Durable Memory, Agent & Task Lifecycle State
 * (STATE PERSISTENCE / NO AUTHORITY RESTORATION).
 *
 * Persists the authoritative MUTABLE state kinds of the 22A classification:
 *
 * - `memory_record`        (16A/16B working/project/execution memory)
 * - `agent_metadata`       (19A identity/profile bookkeeping)
 * - `goal_lifecycle`       (core Goal/Plan facts + allocation/recovery facts)
 * - `skill_tool_registry`  (21A tool/skill registry lifecycle state)
 *
 * LAWS (each test-locked):
 * - Durable state ≠ executable replay ≠ authorization. Restored records are
 *   data under recovery authority; the Planner→Allocation→Policy→Isolation→
 *   Governed Tool Runtime→Evidence/Ledger chain is untouched.
 * - Mutable records are versioned: an update is a NEW envelope with
 *   `supersedesRevision === revision - 1`; stale/duplicate/skipped revisions
 *   are store-level denials (`revision_conflict` / `duplicate_revision`).
 * - IDs and lineage are preserved verbatim: the durable record id is derived
 *   from the source id (never a new namespace), and parent references
 *   (goalId, planId, taskId, assignmentId, toolId, memoryId) are carried
 *   through unchanged and validated on read/recovery.
 * - Explicit durability differences for memory: working entries are bound to
 *   their retention (an expired entry is NOT restored — expiry survives
 *   restarts); project entries restore; execution entries restore as facts.
 *   Every memory payload is re-run through the same secret-key denial as the
 *   live stores (secret-shaped keys deny the whole record).
 * - Agent recovery restores METADATA only (identity/role/profile facts).
 *   It never reconstructs ephemeral execution authority: the restored
 *   snapshot pins `authority: "recovered_data"`, `executionAuthorized:
 *   false`, and suspension views stay derived.
 * - Task recovery restores FACTS (lifecycle status history). Terminal tasks
 *   (`done`/`failed`/`rejected`) are append-only facts once written; an
 *   interrupted task restores as `interrupted` — NEVER auto-resumed, never
 *   re-queued, never re-executed.
 * - Registry lifecycle restores EXACTLY: disabled stays disabled,
 *   quarantined stays quarantined, retired stays retired (terminal states
 *   can never be resurrected by recovery — the 22A
 *   TERMINAL_QUARANTINE_KINDS surface).
 * - Derived indexes are rebuildable: they persist through the derived-index
 *   table (never as authoritative records), and recovery REBUILDS them from
 *   authoritative records only (rebuild equivalence is test-locked).
 * - Fail closed: unknown schema, unknown kind, identity/lineage mismatch,
 *   hash mismatch, corruption, and unverifiable recovery all deny or
 *   quarantine. Nothing is ever silently repaired.
 * - Nothing secret-bearing is serialized: memory secret-hints, raw-output
 *   keys, process-handle/FD-shaped keys, raw policy-token keys, and
 *   executable replay material (argv/cwd/env/launcher) are all denied at
 *   the adapter boundary BEFORE any envelope is sealed.
 */

import {
  DURABLE_RECORD_SCHEMA_VERSION,
  type DurableRecordEnvelope,
  type DurableRecordEnvelopeBody,
  type PersistFailureCode,
  type RecordKind,
} from "./records.js";
import { TERMINAL_QUARANTINE_KINDS } from "./classification.js";
import { durableContentHash } from "./canonical.js";
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

// ── generic payload denylists (secret / handle / token / replay material) ───

/** Secret-shaped key hints — mirrored from the memory/ledger vocabulary. */
const STATE_SECRET_KEY_HINTS: readonly RegExp[] = Object.freeze([
  /(^|[-_ ])(pass(word|phrase)?)([-_ ]|$)/i,
  /(^|[-_ ])secret([-_ ]|$)/i,
  /(^|[-_ ])((api[-_]?)?key|apikey)([-_ ]|$)/i,
  /(^|[-_ ])(token)([-_ ]|$)/i,
  /(^|[-_ ])(credential|credentials|cred)([-_ ]|$)/i,
  /(^|[-_ ])(private[-_ ]?key|privkey)([-_ ]|$)/i,
  /(^|[-_ ])(auth|authentication)([-_ ]|$)/i,
  /(^|[-_ ])(cookie)([-_ ]|$)/i,
  /(^|[-_ ])(bearer)([-_ ]|$)/i,
  /(^|[-_ ])(access[-_ ]?token|refresh[-_ ]?token)([-_ ]|$)/i,
  /(^|[-_ ])(jwt|jwks)([-_ ]|$)/i,
]);

/** Process-handle / file-descriptor / raw-policy-token shaped keys. */
const HANDLE_TOKEN_KEY_HINTS: readonly RegExp[] = Object.freeze([
  /(^|[-_ ])(filedescriptor|filedesc|fd)([-_ ]|$)/i,
  /(^|[-_ ])(handle|proc_?handle|process_?handle|socket)([-_ ]|$)/i,
  /(^|[-_ ])(rawpolicy|policytoken|rawrule|raw_?policy_?token)([-_ ]|$)/i,
  /(^|[-_ ])(policydecisionraw|rawdecision)([-_ ]|$)/i,
]);

/** Executable replay material (mirrors the 22C raw-output denylist). */
const REPLAY_MATERIAL_KEYS: readonly string[] = Object.freeze([
  "stdout",
  "stderr",
  "argv",
  "target_argv",
  "targetargv",
  "cwd",
  "environ",
  "environment",
  "env",
  "command_line",
  "commandline",
  "launcher_flags",
  "launcherflags",
  "launcher_path",
  "launcherpath",
  "executable_path",
  "executablepath",
  "transport_override",
  "transportoverride",
]);

function normalizedKey(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/[-\s.]+/g, "_").toLowerCase();
}

function keyMatches(key: string, hints: readonly RegExp[]): boolean {
  const lower = key.toLowerCase();
  const normalized = normalizedKey(key);
  return hints.some((re) => re.test(lower)) || hints.some((re) => re.test(normalized));
}

function keyIsReplayMaterial(key: string): boolean {
  return REPLAY_MATERIAL_KEYS.includes(normalizedKey(key));
}

/** Structural keys the adapters themselves seal into payloads (never denied). */
const ADAPTER_STRUCTURAL_KEYS: ReadonlySet<string> = new Set([
  "stateKind",
  "stateId",
  "state",
  "lineage",
  "memory",
  "agentMetadata",
  "taskLifecycle",
  "registryLifecycle",
  "observation",
  "sealedRecord",
  "recordHash",
  "toolId",
  "version",
  "manifestHash",
]);

/**
 * Depth-bounded scan for DENIED payload keys at any depth. Structural keys
 * the adapter itself seals (and the well-known identity subkeys of the
 * mirrors) are exempt; everything user-supplied is scanned.
 */
export function findDeniedStateKeyPaths(
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
    const denied =
      !ADAPTER_STRUCTURAL_KEYS.has(k) &&
      (keyMatches(k, STATE_SECRET_KEY_HINTS) ||
        keyMatches(k, HANDLE_TOKEN_KEY_HINTS) ||
        keyIsReplayMaterial(k));
    if (denied) hits.push(p);
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      hits.push(...findDeniedStateKeyPaths(v, p, maxDepth - 1));
    }
  }
  return hits;
}

// ── adapter failure vocabulary (closed; store denials carried verbatim) ─────

export const STATE_PERSIST_FAILURE_CODES = Object.freeze([
  "store_closed",
  "store_denied",
  "invalid_state_id",
  "invalid_lineage",
  "invalid_retention",
  "unknown_state_kind",
  "denied_key_present",
  "state_hash_mismatch",
  "terminal_state_rewrite",
  "memory_expired_not_restorable",
  "invalid_task_transition",
] as const);
export type StatePersistFailureCode = (typeof STATE_PERSIST_FAILURE_CODES)[number];

export interface StatePersistFailure {
  readonly ok: false;
  readonly committed: false;
  readonly code: StatePersistFailureCode;
  readonly reason: string;
  readonly storeFailureCode: PersistFailureCode | null;
}

export interface StatePersistSuccess {
  readonly ok: true;
  readonly committed: true;
  readonly recordId: string;
  readonly revision: number;
  readonly commitSequence: number;
}

export type StatePersistResult = StatePersistSuccess | StatePersistFailure;

function denyState(
  code: StatePersistFailureCode,
  reason: string,
  storeFailureCode: PersistFailureCode | null = null
): StatePersistFailure {
  return { ok: false, committed: false, code, reason: truncateReason(reason), storeFailureCode };
}

function storeDenial(failureCode: PersistFailureCode, reason: string): StatePersistFailure {
  return denyState("store_denied", failureCode + ": " + reason, failureCode);
}

// ── id validation + deterministic durable ids (source ids preserved) ─────────

const STATE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{3,127}$/;

function validateStateId(id: string, label: string): string | null {
  if (typeof id !== "string" || !STATE_ID_PATTERN.test(id)) {
    return label + " must match " + String(STATE_ID_PATTERN) + " (no truncation, no rewriting)";
  }
  return null;
}

/** Durable id for a memory record: `mem-` + the memoryId. */
export function memoryDurableId(memoryId: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  const err = validateStateId(memoryId, "memoryId");
  if (err !== null) return { ok: false, reason: err };
  return { ok: true, recordId: "mem-" + memoryId };
}

/** Durable id for agent metadata: `agt-` + the agentId. */
export function agentDurableId(agentId: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  const err = validateStateId(agentId, "agentId");
  if (err !== null) return { ok: false, reason: err };
  return { ok: true, recordId: "agt-" + agentId };
}

/**
 * Durable id for 24C federation peer trust: `peer-` + the 64-hex NodeId
 * tail (injective: the canonical `node-<64hex>` NodeId maps to exactly one
 * record id inside the 22A id width; re-derive the full NodeId with
 * `peerNodeIdOfRecordId`).
 */
export const PEER_DURABLE_ID_PREFIX = "peer-" as const;
export function peerDurableId(nodeId: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  const m = /^node-([0-9a-f]{64})$/.exec(nodeId);
  const tail = m === null ? undefined : m[1];
  if (tail === undefined) {
    return { ok: false, reason: "nodeId must be the canonical node-<64 hex> form" };
  }
  return { ok: true, recordId: PEER_DURABLE_ID_PREFIX + tail };
}
/** Re-derive the full canonical NodeId from a peer trust record id. */
export function peerNodeIdOfRecordId(recordId: string): string {
  return "node-" + recordId.slice(PEER_DURABLE_ID_PREFIX.length);
}

/**
 * Durable id for 24D federation receipts: `frc-` + the federation message
 * id (`fm-<16hex>-<16alnum>` = 36 chars → 40-char record id, inside the
 * 22A id width). Injective: one receipt record per message id, which makes
 * the record id itself the durable message-id commitment (replay guard).
 */
export const FEDERATION_RECEIPT_ID_PREFIX = "frc-" as const;
export function federationReceiptDurableId(messageId: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  if (!/^fm-[0-9a-f]{16}-[a-zA-Z0-9]{16}$/.test(messageId)) {
    return { ok: false, reason: "messageId must be the canonical fm-<ts16>-<rnd16> form" };
  }
  return { ok: true, recordId: FEDERATION_RECEIPT_ID_PREFIX + messageId };
}

/**
 * Durable id for 24E cross-node task PROPOSAL records: `fpr-` + the
 * proposal id (`fp-<16hex>-<16alnum>` = 36 chars → 40-char record id,
 * inside the 22A id width). Injective: one proposal record per proposal
 * id, which makes the record id itself the durable duplicate-proposal
 * commitment (same discipline as the 24D receipt commitment).
 */
export const FEDERATION_PROPOSAL_ID_PREFIX = "fpr-" as const;
export function federationProposalDurableId(proposalId: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  if (!/^fp-[0-9a-f]{16}-[a-zA-Z0-9]{16}$/.test(proposalId)) {
    return { ok: false, reason: "proposalId must be the canonical fp-<ts16>-<rnd16> form" };
  }
  return { ok: true, recordId: FEDERATION_PROPOSAL_ID_PREFIX + proposalId };
}

/**
 * Durable id for 24F cross-node provenance ANCHOR records: `fpv-` + the
 * anchor id (`fv-<16hex>-<16alnum>` = 36 chars → 40-char record id, inside
 * the 22A id width). Injective: one anchor record per anchor id.
 */
export const FEDERATION_PROVENANCE_ID_PREFIX = "fpv-" as const;
export function federationProvenanceDurableId(anchorId: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  if (!/^fv-[0-9a-f]{16}-[a-zA-Z0-9]{16}$/.test(anchorId)) {
    return { ok: false, reason: "anchorId must be the canonical fv-<ts16>-<rnd16> form" };
  }
  return { ok: true, recordId: FEDERATION_PROVENANCE_ID_PREFIX + anchorId };
}

/** Durable id for goal/task lifecycle: `gol-` + the goalId (or taskId). */
export function goalDurableId(goalId: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  const err = validateStateId(goalId, "goalId");
  if (err !== null) return { ok: false, reason: err };
  return { ok: true, recordId: "gol-" + goalId };
}

/**
 * Durable id for registry lifecycle: `reg-` + a bounded, collision-free
 * encoding of the (toolId, version) pair. The pair IS the registry identity;
 * both segments are preserved (dot → `-d-`, @ → `-a-`, tilde → `-t-`) so the
 * id stays inside the 22A id vocabulary and can never collide or be
 * truncated.
 */
export function registryDurableId(toolId: string, version: string): { ok: true; recordId: string } | { ok: false; reason: string } {
  if (typeof toolId !== "string" || toolId.length === 0 || toolId.length > 64) {
    return { ok: false, reason: "toolId must be a non-empty string of at most 64 chars" };
  }
  if (typeof version !== "string" || version.length === 0 || version.length > 32) {
    return { ok: false, reason: "version must be a non-empty string of at most 32 chars" };
  }
  if (!/^[a-z][a-z0-9._-]*$/.test(toolId) || !/^[A-Za-z0-9][A-Za-z0-9.+_-]*$/.test(version)) {
    return { ok: false, reason: "toolId/version must be registry-vocabulary strings" };
  }
  // Encode to the 22A id vocabulary's second segment ([a-zA-Z0-9-]):
  // dot → -d- , @ → -a- , tilde → -t- (bounded, injective, reversible).
  const encode = (s: string): string => s.replace(/~/g, "-t-").replace(/\./g, "-d-").replace(/@/g, "-a-");
  const encoded = encode(toolId) + "-a-" + encode(version);
  if (encoded.length > 64) {
    return { ok: false, reason: "encoded toolId@version exceeds the 22A id width (64 chars); no truncation is permitted" };
  }
  return { ok: true, recordId: "reg-" + encoded };
}

// ── sealing (22A vocabulary; versioned_mutable kinds only) ───────────────────

function sealStateEnvelope(input: {
  recordId: string;
  recordKind: "memory_record" | "agent_metadata" | "goal_lifecycle" | "skill_tool_registry";
  revision: number;
  supersedesRevision: number | null;
  transactionId: string;
  createdAtEpochMs: number;
  payload: Record<string, unknown>;
}): DurableRecordEnvelope {
  const body: DurableRecordEnvelopeBody = {
    schemaVersion: DURABLE_RECORD_SCHEMA_VERSION,
    recordId: input.recordId,
    recordKind: input.recordKind,
    durabilityClass: "versioned_mutable",
    secretPolicy: "secret_free",
    authority: "durable_state",
    revision: input.revision,
    supersedesRevision: input.supersedesRevision,
    createdAtEpochMs: input.createdAtEpochMs,
    transactionId: input.transactionId,
    payload: input.payload,
  };
  return Object.freeze({ ...body, contentHash: durableContentHash(body) });
}

function scanPayload(payload: Record<string, unknown>): StatePersistFailure | null {
  const denied = findDeniedStateKeyPaths(payload);
  if (denied.length > 0) {
    return denyState("denied_key_present", "denied payload keys (secret/handle/token/replay-material shaped): " + denied.slice(0, 4).join(", "));
  }
  return null;
}

// ── memory records (explicit durability differences per kind) ────────────────

/** Structural mirror of a 16A/16B MemoryRecord (no dependency, no drift). */
export interface MemoryStateRecord {
  readonly schemaVersion: string;
  readonly memoryId: string;
  readonly kind: "working" | "project" | "execution";
  readonly scope: {
    readonly workspaceId: string;
    readonly taskId?: string;
    readonly sessionId?: string;
  };
  readonly provenance: {
    readonly origin: string;
    readonly actor: { readonly type: string; readonly id: string };
    readonly sourceEventId?: string;
    readonly label?: string;
    readonly untrusted: boolean;
  };
  readonly retention: {
    readonly retentionClass: "ephemeral" | "session" | "persistent";
    readonly expiresAtEpochMs?: number;
  };
  readonly body: Readonly<Record<string, unknown>>;
  readonly createdAtEpochMs: number;
  readonly createdByActorId: string;
}

/**
 * True when a memory entry is restorable after restart under its OWN
 * retention class: ephemeral entries expire (expiry survives restarts);
 * session and persistent entries restore; expired ephemeral entries never do.
 */
export function isMemoryRestorable(
  record: MemoryStateRecord,
  nowEpochMs: number
): boolean {
  if (record.retention.retentionClass === "ephemeral") {
    return (
      record.retention.expiresAtEpochMs !== undefined &&
      nowEpochMs < record.retention.expiresAtEpochMs
    );
  }
  return true;
}

/**
 * Persist one memory record as the newest revision of its durable record.
 * Enforces: secret-key denial, replay-material denial, retention
 * restorability for ephemeral entries, and id preservation. A re-write of
 * the same memoryId with NEW content is a NEW revision (supersedes
 * revision-1); a duplicate of the CURRENT content is a store-level
 * revision conflict — never last-writer-wins.
 */
export function persistMemoryRecord(
  store: DurableStore,
  input: {
    readonly record: MemoryStateRecord;
    readonly revision: number;
    readonly supersedesRevision: number | null;
    readonly transactionId: string;
    readonly createdAtEpochMs?: number;
  }
): StatePersistResult {
  if (!store.isOpen) return denyState("store_closed", "store is closed");
  const id = memoryDurableId(input.record.memoryId);
  if (!id.ok) return denyState("invalid_state_id", id.reason);
  if (input.record.kind !== "working" && input.record.kind !== "project" && input.record.kind !== "execution") {
    return denyState("unknown_state_kind", "memory kind must be working|project|execution");
  }
  if (input.record.retention.retentionClass === "ephemeral" && input.record.retention.expiresAtEpochMs === undefined) {
    return denyState("invalid_retention", "ephemeral memory requires an absolute expiry");
  }
  const payload: Record<string, unknown> = {
    stateKind: "memory_record",
    memory: { ...input.record },
  };
  const denied = scanPayload(payload);
  if (denied !== null) return denied;
  const envelope = sealStateEnvelope({
    recordId: id.recordId,
    recordKind: "memory_record",
    revision: input.revision,
    supersedesRevision: input.supersedesRevision,
    transactionId: input.transactionId,
    createdAtEpochMs: input.createdAtEpochMs ?? Date.now(),
    payload,
  });
  const decision = store.persist(envelope);
  if (!decision.ok) return storeDenial(decision.failureCode, decision.reason);
  return {
    ok: true,
    committed: true,
    recordId: id.recordId,
    revision: decision.revision,
    commitSequence: decision.commitSequence,
  };
}

export type MemoryReadResult =
  | { readonly ok: true; readonly record: MemoryStateRecord; readonly revision: number; readonly commitSequence: number }
  | { readonly ok: false; readonly code: StatePersistFailureCode | "not_found" | "quarantined"; readonly reason: string };

/**
 * Read the newest revision of one memory record and VERIFY on read:
 * payload identity must match the durable id, and the stored secret-key
 * posture is re-checked (a record that was valid at write time but whose
 * bytes now carry denied keys — i.e. a tamper — fails closed).
 */
export function readMemoryRecord(store: DurableStore, memoryId: string): MemoryReadResult {
  if (!store.isOpen) return { ok: false, code: "store_closed", reason: "store is closed" };
  const id = memoryDurableId(memoryId);
  if (!id.ok) return { ok: false, code: "invalid_state_id", reason: id.reason };
  const read = store.readRecord(id.recordId);
  if (!read.ok) {
    return {
      ok: false,
      code: read.code === "quarantined" ? "quarantined" : "not_found",
      reason: read.reason,
    };
  }
  const parsed = (read.record.payload as Record<string, unknown>)["memory"];
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, code: "state_hash_mismatch", reason: "stored memory payload is missing its record" };
  }
  const record = parsed as MemoryStateRecord;
  if (record.memoryId !== memoryId) {
    return { ok: false, code: "invalid_lineage", reason: "stored memoryId disagrees with the requested id" };
  }
  const denied = scanPayload(read.record.payload as Record<string, unknown>);
  if (denied !== null) {
    return { ok: false, code: denied.code, reason: denied.reason };
  }
  return { ok: true, record, revision: read.record.revision, commitSequence: read.commitSequence };
}

// ── agent metadata (restore metadata, NEVER execution authority) ─────────────

/** Structural mirror of the persistable part of a 19A AgentIdentity. */
export interface AgentMetadataState {
  readonly schemaVersion: string;
  readonly agentId: string;
  readonly role: "planner" | "builder" | "reviewer";
  readonly registeredAtEpochMs: number;
  readonly profile: {
    readonly allowedVerbs: readonly string[];
    readonly allowedCapabilities: readonly string[];
    readonly maxSideEffectClass: "none" | "read" | "write" | "network" | "system";
    readonly description: string;
  };
  /** ALWAYS "mediation" — mirrors the frozen 19A authority marker. */
  readonly authority: "mediation";
  /** ALWAYS false — an identity snapshot never carries execution authority. */
  readonly executionAuthorized: false;
}

/**
 * Persist one agent-metadata snapshot (registration or a reviewed profile
 * replacement) as a new revision. The payload keeps the frozen 19A markers
 * (`authority: "mediation"`, `executionAuthorized: false`) so a restored
 * snapshot can never be mistaken for a grant.
 */
export function persistAgentMetadata(
  store: DurableStore,
  input: {
    readonly state: AgentMetadataState;
    readonly revision: number;
    readonly supersedesRevision: number | null;
    readonly transactionId: string;
    readonly createdAtEpochMs?: number;
  }
): StatePersistResult {
  if (!store.isOpen) return denyState("store_closed", "store is closed");
  const id = agentDurableId(input.state.agentId);
  if (!id.ok) return denyState("invalid_state_id", id.reason);
  if (input.state.role !== "planner" && input.state.role !== "builder" && input.state.role !== "reviewer") {
    return denyState("unknown_state_kind", "agent role must be planner|builder|reviewer");
  }
  if (input.state.authority !== "mediation" || input.state.executionAuthorized !== false) {
    return denyState("state_hash_mismatch", "agent metadata must carry authority:'mediation' and executionAuthorized:false (no authority restoration)");
  }
  const payload: Record<string, unknown> = {
    stateKind: "agent_metadata",
    agentMetadata: { ...input.state },
  };
  const denied = scanPayload(payload);
  if (denied !== null) return denied;
  const envelope = sealStateEnvelope({
    recordId: id.recordId,
    recordKind: "agent_metadata",
    revision: input.revision,
    supersedesRevision: input.supersedesRevision,
    transactionId: input.transactionId,
    createdAtEpochMs: input.createdAtEpochMs ?? Date.now(),
    payload,
  });
  const decision = store.persist(envelope);
  if (!decision.ok) return storeDenial(decision.failureCode, decision.reason);
  return {
    ok: true,
    committed: true,
    recordId: id.recordId,
    revision: decision.revision,
    commitSequence: decision.commitSequence,
  };
}

export type AgentMetadataReadResult =
  | { readonly ok: true; readonly state: AgentMetadataState; readonly revision: number; readonly commitSequence: number }
  | { readonly ok: false; readonly code: StatePersistFailureCode | "not_found" | "quarantined"; readonly reason: string };

/**
 * Read the newest agent-metadata revision and verify the frozen authority
 * markers on read: a tampered snapshot claiming executionAuthorized:true
 * fails closed (no authority restoration, even through corruption).
 */
export function readAgentMetadata(store: DurableStore, agentId: string): AgentMetadataReadResult {
  if (!store.isOpen) return { ok: false, code: "store_closed", reason: "store is closed" };
  const id = agentDurableId(agentId);
  if (!id.ok) return { ok: false, code: "invalid_state_id", reason: id.reason };
  const read = store.readRecord(id.recordId);
  if (!read.ok) {
    return {
      ok: false,
      code: read.code === "quarantined" ? "quarantined" : "not_found",
      reason: read.reason,
    };
  }
  const parsed = (read.record.payload as Record<string, unknown>)["agentMetadata"];
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, code: "state_hash_mismatch", reason: "stored agent payload is missing its state" };
  }
  const state = parsed as AgentMetadataState;
  if (state.agentId !== agentId) {
    return { ok: false, code: "invalid_lineage", reason: "stored agentId disagrees with the requested id" };
  }
  if (state.authority !== "mediation" || state.executionAuthorized !== false) {
    return { ok: false, code: "state_hash_mismatch", reason: "stored agent metadata violates the frozen authority markers — refusing to restore" };
  }
  return { ok: true, state, revision: read.record.revision, commitSequence: read.commitSequence };
}

// ── goal/task lifecycle (facts restore; terminal facts append-only) ──────────

/** Goal/plan/task lifecycle statuses (closed union over the frozen vocabularies). */
export type TaskLifecycleStatus =
  | "pending"
  | "planning"
  | "proposed"
  | "executing"
  | "done"
  | "failed"
  | "rejected"
  | "interrupted";

export const TERMINAL_TASK_STATUSES: readonly TaskLifecycleStatus[] = Object.freeze([
  "done",
  "failed",
  "rejected",
]);

export function isTerminalTaskStatus(status: TaskLifecycleStatus): boolean {
  return TERMINAL_TASK_STATUSES.includes(status);
}

/** Structural mirror of one durable Goal/Plan/Task lifecycle snapshot. */
export interface TaskLifecycleState {
  readonly schemaVersion: string;
  readonly goalId: string;
  /** Plan id when one was proposed for this goal (lineage). */
  readonly planId: string | null;
  /** Task/assignment ids descended from the goal (lineage, order preserved). */
  readonly taskIds: readonly string[];
  readonly status: TaskLifecycleStatus;
  /** Bounded, conclusion-only status rationale. */
  readonly rationale: string;
  /**
   * Optional ledger event id that produced THIS status (a runtime ref for
   * reconciliation): when present, startup recovery (22E) resolves it
   * against the mirrored ledger — an unresolvable ref is an orphan-parent
   * finding and the record is excluded from admission.
   */
  readonly sourceEventId?: string;
  readonly updatedAtEpochMs: number;
}

const TASK_TRANSITIONS: Readonly<Record<TaskLifecycleStatus, readonly TaskLifecycleStatus[]>> = Object.freeze({
  pending: ["planning", "proposed", "executing", "interrupted"],
  planning: ["proposed", "interrupted"],
  proposed: ["executing", "rejected", "interrupted"],
  executing: ["done", "failed", "interrupted"],
  interrupted: ["executing", "proposed"],
  done: [],
  failed: [],
  rejected: [],
});

/** True when `from → to` is a legal lifecycle transition. */
export function isLegalTaskTransition(from: TaskLifecycleStatus, to: TaskLifecycleStatus): boolean {
  return TASK_TRANSITIONS[from].includes(to);
}

/**
 * Persist one goal/task lifecycle snapshot. Terminal statuses are
 * append-only facts: a snapshot arriving at a revision AFTER a terminal
 * status was recorded is a `terminal_state_rewrite` denial — the fact
 * cannot be rewritten by any later writer.
 */
export function persistTaskLifecycle(
  store: DurableStore,
  input: {
    readonly state: TaskLifecycleState;
    readonly previousStatus: TaskLifecycleStatus | null;
    readonly revision: number;
    readonly supersedesRevision: number | null;
    readonly transactionId: string;
    readonly createdAtEpochMs?: number;
  }
): StatePersistResult {
  if (!store.isOpen) return denyState("store_closed", "store is closed");
  const id = goalDurableId(input.state.goalId);
  if (!id.ok) return denyState("invalid_state_id", id.reason);
  if (input.previousStatus !== null) {
    if (!isLegalTaskTransition(input.previousStatus, input.state.status)) {
      return denyState("invalid_task_transition", "illegal task lifecycle transition " + input.previousStatus + " → " + input.state.status);
    }
    if (isTerminalTaskStatus(input.previousStatus)) {
      return denyState("terminal_state_rewrite", "task already reached terminal status '" + input.previousStatus + "'; terminal facts are append-only and cannot be rewritten");
    }
  }
  for (const taskId of input.state.taskIds) {
    const err = validateStateId(taskId, "taskId");
    if (err !== null) return denyState("invalid_lineage", err);
  }
  if (input.state.sourceEventId !== undefined && (typeof input.state.sourceEventId !== "string" || input.state.sourceEventId.length === 0 || input.state.sourceEventId.length > 128)) {
    return denyState("invalid_lineage", "sourceEventId must be a bounded non-empty string when present");
  }
  const payload: Record<string, unknown> = {
    stateKind: "task_lifecycle",
    taskLifecycle: { ...input.state, taskIds: [...input.state.taskIds] },
  };
  const denied = scanPayload(payload);
  if (denied !== null) return denied;
  const envelope = sealStateEnvelope({
    recordId: id.recordId,
    recordKind: "goal_lifecycle",
    revision: input.revision,
    supersedesRevision: input.supersedesRevision,
    transactionId: input.transactionId,
    createdAtEpochMs: input.createdAtEpochMs ?? Date.now(),
    payload,
  });
  const decision = store.persist(envelope);
  if (!decision.ok) return storeDenial(decision.failureCode, decision.reason);
  return {
    ok: true,
    committed: true,
    recordId: id.recordId,
    revision: decision.revision,
    commitSequence: decision.commitSequence,
  };
}

export type TaskLifecycleReadResult =
  | {
      readonly ok: true;
      readonly state: TaskLifecycleState;
      readonly revision: number;
      readonly commitSequence: number;
      /** True when the restored status is a terminal fact. */
      readonly terminal: boolean;
    }
  | { readonly ok: false; readonly code: StatePersistFailureCode | "not_found" | "quarantined"; readonly reason: string };

/**
 * Read the newest goal/task lifecycle revision. The restored status is
 * returned as a FACT: terminal stays terminal; an interrupted task stays
 * `interrupted` — the caller must explicitly drive any continuation, and
 * nothing here resumes, re-queues, or re-executes anything.
 */
export function readTaskLifecycle(store: DurableStore, goalId: string): TaskLifecycleReadResult {
  if (!store.isOpen) return { ok: false, code: "store_closed", reason: "store is closed" };
  const id = goalDurableId(goalId);
  if (!id.ok) return { ok: false, code: "invalid_state_id", reason: id.reason };
  const read = store.readRecord(id.recordId);
  if (!read.ok) {
    return {
      ok: false,
      code: read.code === "quarantined" ? "quarantined" : "not_found",
      reason: read.reason,
    };
  }
  const parsed = (read.record.payload as Record<string, unknown>)["taskLifecycle"];
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, code: "state_hash_mismatch", reason: "stored task payload is missing its state" };
  }
  const state = parsed as TaskLifecycleState;
  if (state.goalId !== goalId) {
    return { ok: false, code: "invalid_lineage", reason: "stored goalId disagrees with the requested id" };
  }
  for (const taskId of state.taskIds) {
    if (validateStateId(taskId, "taskId") !== null) {
      return { ok: false, code: "invalid_lineage", reason: "stored task lineage carries an invalid task id" };
    }
  }
  const known = Object.keys(TASK_TRANSITIONS) as TaskLifecycleStatus[];
  if (!known.includes(state.status)) {
    return { ok: false, code: "unknown_state_kind", reason: "stored task status is outside the closed vocabulary" };
  }
  return {
    ok: true,
    state,
    revision: read.record.revision,
    commitSequence: read.commitSequence,
    terminal: isTerminalTaskStatus(state.status),
  };
}

// ── registry lifecycle (exact restore; terminal states never resurrect) ──────

/** Registry lifecycle snapshot (the 21A closed vocabulary, mirrored). */
export interface RegistryLifecycleState {
  readonly schemaVersion: string;
  readonly toolId: string;
  readonly version: string;
  readonly manifestHash: string;
  readonly lifecycle: "registered" | "enabled" | "disabled" | "quarantined" | "retired";
  readonly registeredBy: string;
  readonly updatedAtEpochMs: number;
}

/**
 * 24C — federation peer trust state (durable shape). The lifecycle union
 * mirrors the 24A closed peer vocabulary as literals (no import: the 22D
 * layer stays vocabulary-independent). `quarantined` and `retired` are
 * TERMINAL (`TERMINAL_QUARANTINE_KINDS` covers this kind) — recovery can
 * never resurrect them. The record carries NO authority fields of any
 * kind: peer trust facts are data, never execution/policy authorization.
 */
export interface PeerTrustState {
  readonly schemaVersion: string;
  readonly nodeId: string;
  readonly fingerprint: string;
  readonly instanceId: string;
  readonly trustState: "unknown" | "candidate" | "admitted" | "quarantined" | "retired";
  readonly protocolVersion: string;
  /** When fingerprint+protocol+state were pinned (24C: at admission). */
  readonly pinnedAtEpochMs: number;
  readonly updatedAtEpochMs: number;
  /** The evidence string that backed the last trust transition (L6). */
  readonly lastTransitionEvidence: string;
}

const REGISTRY_TRANSITIONS: Readonly<Record<RegistryLifecycleState["lifecycle"], readonly RegistryLifecycleState["lifecycle"][]>> = Object.freeze({
  registered: ["enabled", "disabled", "quarantined", "retired"],
  enabled: ["disabled", "quarantined", "retired"],
  disabled: ["enabled", "quarantined", "retired"],
  quarantined: [],
  retired: [],
});

/** True when a registry lifecycle transition is legal (21A machine mirror). */
export function isLegalRegistryTransition(
  from: RegistryLifecycleState["lifecycle"],
  to: RegistryLifecycleState["lifecycle"]
): boolean {
  return REGISTRY_TRANSITIONS[from].includes(to);
}

/**
 * Persist one registry lifecycle snapshot. `quarantined` and `retired` are
 * terminal: a snapshot that would move a record OUT of a terminal state (or
 * rewrite it after the fact) is a `terminal_state_rewrite` denial —
 * recovery can never resurrect a quarantined/retired tool.
 */
export function persistRegistryLifecycle(
  store: DurableStore,
  input: {
    readonly state: RegistryLifecycleState;
    readonly previousLifecycle: RegistryLifecycleState["lifecycle"] | null;
    readonly revision: number;
    readonly supersedesRevision: number | null;
    readonly transactionId: string;
    readonly createdAtEpochMs?: number;
  }
): StatePersistResult {
  if (!store.isOpen) return denyState("store_closed", "store is closed");
  const id = registryDurableId(input.state.toolId, input.state.version);
  if (!id.ok) return denyState("invalid_state_id", id.reason);
  if (typeof input.state.manifestHash !== "string" || !/^[0-9a-f]{64}$/.test(input.state.manifestHash)) {
    return denyState("state_hash_mismatch", "registry snapshot must carry the 64-hex manifestHash that pinned the entry at persist time");
  }
  const knownLifecycles = Object.keys(REGISTRY_TRANSITIONS) as RegistryLifecycleState["lifecycle"][];
  if (!knownLifecycles.includes(input.state.lifecycle)) {
    return denyState("unknown_state_kind", "registry lifecycle must be one of the 21A closed vocabulary values");
  }
  if (input.previousLifecycle !== null) {
    // Terminal registry states are pinned by the 22A classification
    // (skill_tool_registry ∈ TERMINAL_QUARANTINE_KINDS): recovery can never
    // rewrite or resurrect a quarantined/retired entry.
    if (!TERMINAL_QUARANTINE_KINDS.includes("skill_tool_registry")) {
      return denyState("unknown_state_kind", "classification drift: skill_tool_registry must be a terminal-quarantine kind");
    }
    if (input.previousLifecycle === "quarantined" || input.previousLifecycle === "retired") {
      return denyState("terminal_state_rewrite", "registry entry is terminal ('" + input.previousLifecycle + "'); quarantined/retired can never be rewritten or resurrected");
    }
    if (!isLegalRegistryTransition(input.previousLifecycle, input.state.lifecycle)) {
      return denyState("invalid_task_transition", "illegal registry lifecycle transition " + input.previousLifecycle + " → " + input.state.lifecycle);
    }
  }
  const payload: Record<string, unknown> = {
    stateKind: "registry_lifecycle",
    registryLifecycle: { ...input.state },
  };
  const denied = scanPayload(payload);
  if (denied !== null) return denied;
  const envelope = sealStateEnvelope({
    recordId: id.recordId,
    recordKind: "skill_tool_registry",
    revision: input.revision,
    supersedesRevision: input.supersedesRevision,
    transactionId: input.transactionId,
    createdAtEpochMs: input.createdAtEpochMs ?? Date.now(),
    payload,
  });
  const decision = store.persist(envelope);
  if (!decision.ok) return storeDenial(decision.failureCode, decision.reason);
  return {
    ok: true,
    committed: true,
    recordId: id.recordId,
    revision: decision.revision,
    commitSequence: decision.commitSequence,
  };
}

export type RegistryLifecycleReadResult =
  | {
      readonly ok: true;
      readonly state: RegistryLifecycleState;
      readonly revision: number;
      readonly commitSequence: number;
      readonly terminal: boolean;
    }
  | { readonly ok: false; readonly code: StatePersistFailureCode | "not_found" | "quarantined"; readonly reason: string };

/**
 * Read the newest registry lifecycle revision. The lifecycle is restored
 * EXACTLY as stored: disabled stays disabled; quarantined/retired stay
 * terminal (and `terminal: true` is reported so no caller can mistake them
 * for executable states).
 */
export function readRegistryLifecycle(store: DurableStore, toolId: string, version: string): RegistryLifecycleReadResult {
  if (!store.isOpen) return { ok: false, code: "store_closed", reason: "store is closed" };
  const id = registryDurableId(toolId, version);
  if (!id.ok) return { ok: false, code: "invalid_state_id", reason: id.reason };
  const read = store.readRecord(id.recordId);
  if (!read.ok) {
    return {
      ok: false,
      code: read.code === "quarantined" ? "quarantined" : "not_found",
      reason: read.reason,
    };
  }
  const parsed = (read.record.payload as Record<string, unknown>)["registryLifecycle"];
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, code: "state_hash_mismatch", reason: "stored registry payload is missing its state" };
  }
  const state = parsed as RegistryLifecycleState;
  if (state.toolId !== toolId || state.version !== version) {
    return { ok: false, code: "invalid_lineage", reason: "stored toolId@version disagrees with the requested identity" };
  }
  const lifecycle = state.lifecycle;
  const knownLifecycles = Object.keys(REGISTRY_TRANSITIONS) as RegistryLifecycleState["lifecycle"][];
  if (!knownLifecycles.includes(lifecycle)) {
    return { ok: false, code: "unknown_state_kind", reason: "stored registry lifecycle is outside the closed vocabulary" };
  }
  return {
    ok: true,
    state,
    revision: read.record.revision,
    commitSequence: read.commitSequence,
    terminal: lifecycle === "quarantined" || lifecycle === "retired",
  };
}

// ── derived-index rebuild (rebuildable; equivalence is a contract) ───────────

/** Derived-index id: memory scope → memory ids (rebuildable). */
export const MEMORY_SCOPE_INDEX_ID = "memory-scope-index";
/** Derived-index id: task lineage goal → task ids (rebuildable). */
export const TASK_LINEAGE_INDEX_ID = "task-lineage-index";

/**
 * Rebuild the derived indexes from AUTHORITATIVE records only. The indexes
 * are written through the store's derived-index table (never as records).
 * Rebuild is deterministic: two rebuilds over the same authoritative set
 * produce identical indexes (equivalence is test-locked). Returns the
 * per-index entry counts.
 */
export function rebuildDerivedIndexes(store: DurableStore): {
  readonly ok: true;
  readonly memoryScopeEntries: number;
  readonly taskLineageEntries: number;
} | { readonly ok: false; readonly code: StatePersistFailureCode; readonly reason: string } {
  if (!store.isOpen) return { ok: false, code: "store_closed", reason: "store is closed" };

  // Discard the derived data first (rebuild_from_authoritative semantics).
  store.dropDerivedIndex(MEMORY_SCOPE_INDEX_ID);
  store.dropDerivedIndex(TASK_LINEAGE_INDEX_ID);

  let memoryScopeEntries = 0;
  for (const recordId of store.listRecordIds("memory_record")) {
    const read = store.readRecord(recordId);
    if (!read.ok) continue; // unreadable records contribute nothing; recovery reports them
    const parsed = (read.record.payload as Record<string, unknown>)["memory"];
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) continue;
    const record = parsed as MemoryStateRecord;
    const scopeKey =
      record.scope.workspaceId +
      "|" + (record.scope.taskId ?? "") +
      "|" + (record.scope.sessionId ?? "");
    const prior = store.getDerivedEntry(MEMORY_SCOPE_INDEX_ID, scopeKey);
    const joined = prior === null ? record.memoryId : prior + "," + record.memoryId;
    if (!store.setDerivedEntry(MEMORY_SCOPE_INDEX_ID, scopeKey, joined).ok) {
      return { ok: false, code: "store_denied", reason: "derived index write refused" };
    }
    memoryScopeEntries++;
  }

  let taskLineageEntries = 0;
  for (const recordId of store.listRecordIds("goal_lifecycle")) {
    const read = store.readRecord(recordId);
    if (!read.ok) continue;
    const parsed = (read.record.payload as Record<string, unknown>)["taskLifecycle"];
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) continue;
    const state = parsed as TaskLifecycleState;
    for (const taskId of state.taskIds) {
      if (!store.setDerivedEntry(TASK_LINEAGE_INDEX_ID, taskId, state.goalId).ok) {
        return { ok: false, code: "store_denied", reason: "derived index write refused" };
      }
      taskLineageEntries++;
    }
  }
  return { ok: true, memoryScopeEntries, taskLineageEntries };
}

// ── recovery (frozen 22A decision; recovered state grants nothing) ──────────

export interface StateRecoveryResult {
  readonly decision: RecoveryDecision;
  /** Per-kind counts of admitted records (data restored, never authority). */
  readonly admittedByKind: Readonly<Record<RecordKind, number>>;
  /** Memory entries that were NOT restored because their retention expired. */
  readonly expiredMemoryIds: readonly string[];
  /** Registry entries restored into a terminal (quarantined/retired) state. */
  readonly terminalRegistryIds: readonly string[];
  /** 24C peer trust records restored into a terminal (quarantined/retired) state. */
  readonly terminalPeerIds: readonly string[];
  /** True when derived indexes must be rebuilt before use. */
  readonly derivedRebuildRequired: boolean;
}

/**
 * Read-only lineage/reconciliation facts for ONE kind, consumed by the 22E
 * startup-recovery pipeline. Restores nothing: the caller decides.
 */
export interface StateKindFacts {
  readonly kind: RecordKind;
  /** recordId → latest revision (mutable kinds). */
  readonly revisions: ReadonlyMap<string, number>;
  /** Record ids that failed identity/integrity validation (excluded). */
  readonly failedRecordIds: readonly string[];
  /** Registry lifecycle per recordId (skill_tool_registry only). */
  readonly registryLifecycles: ReadonlyMap<string, RegistryLifecycleState["lifecycle"]>;
  /** Task lineage: recordId → taskIds (goal_lifecycle only). */
  readonly taskLineage: ReadonlyMap<string, readonly string[]>;
  /** Memory ids per recordId (memory_record only; ALL stored, incl. expired). */
  readonly memoryIds: readonly string[];
}

/**
 * Collect read-only facts about one authoritative mutable kind (the 22E
 * reconciliation input). Corrupt/unreadable records are reported in
 * `failedRecordIds` — never repaired, never admitted.
 */
export function collectStateKindFacts(store: DurableStore, kind: RecordKind): StateKindFacts {
  const revisions = new Map<string, number>();
  const failedRecordIds: string[] = [];
  const registryLifecycles = new Map<string, RegistryLifecycleState["lifecycle"]>();
  const taskLineage = new Map<string, readonly string[]>();
  const memoryIds: string[] = [];
  if (!store.isOpen) {
    return { kind, revisions, failedRecordIds, registryLifecycles, taskLineage, memoryIds };
  }
  const known: readonly RecordKind[] = ["memory_record", "agent_metadata", "goal_lifecycle", "skill_tool_registry", "peer_trust_registry"];
  if (!known.includes(kind)) {
    return { kind, revisions, failedRecordIds, registryLifecycles, taskLineage, memoryIds };
  }
  for (const recordId of store.listRecordIds(kind)) {
    const read = store.readRecord(recordId);
    if (!read.ok) {
      failedRecordIds.push(recordId);
      continue;
    }
    revisions.set(recordId, read.record.revision);
    if (kind === "memory_record") {
      const parsed = (read.record.payload as Record<string, unknown>)["memory"];
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        failedRecordIds.push(recordId);
        continue;
      }
      const record = parsed as MemoryStateRecord;
      if (record.memoryId !== recordId.slice("mem-".length)) {
        failedRecordIds.push(recordId);
        continue;
      }
      memoryIds.push(record.memoryId);
    }
    if (kind === "goal_lifecycle") {
      const parsed = (read.record.payload as Record<string, unknown>)["taskLifecycle"];
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        failedRecordIds.push(recordId);
        continue;
      }
      const state = parsed as TaskLifecycleState;
      if (state.goalId !== recordId.slice("gol-".length)) {
        failedRecordIds.push(recordId);
        continue;
      }
      taskLineage.set(recordId, state.taskIds);
    }
    if (kind === "skill_tool_registry") {
      const parsed = (read.record.payload as Record<string, unknown>)["registryLifecycle"];
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        failedRecordIds.push(recordId);
        continue;
      }
      const state = parsed as RegistryLifecycleState;
      const idCheck = registryDurableId(state.toolId, state.version);
      if (!idCheck.ok || idCheck.recordId !== recordId) {
        failedRecordIds.push(recordId);
        continue;
      }
      registryLifecycles.set(recordId, state.lifecycle);
    }
    if (kind === "peer_trust_registry") {
      const parsed = (read.record.payload as Record<string, unknown>)["peerTrust"];
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        failedRecordIds.push(recordId);
        continue;
      }
      const state = parsed as PeerTrustState;
      if (state.nodeId !== peerNodeIdOfRecordId(recordId)) {
        failedRecordIds.push(recordId);
        continue;
      }
    }
    if (kind === "agent_metadata") {
      const parsed = (read.record.payload as Record<string, unknown>)["agentMetadata"];
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        failedRecordIds.push(recordId);
        continue;
      }
      const state = parsed as AgentMetadataState;
      if (state.agentId !== recordId.slice("agt-".length)) {
        failedRecordIds.push(recordId);
        continue;
      }
    }
  }
  return { kind, revisions, failedRecordIds, registryLifecycles, taskLineage, memoryIds };
}

/**
 * Verify the persisted mutable state and map the outcome onto the FROZEN
 * 22A recovery decision. Restores state as data: agent metadata WITHOUT
 * execution authority, task facts WITHOUT auto-resume, registry lifecycle
 * WITHOUT resurrection. Expired ephemeral memory is excluded from admission
 * (retention survives restarts); corrupted records are quarantined, never
 * repaired; an exhausted scan bound rejects recovery entirely.
 */
export function recoverState(
  store: DurableStore,
  request: RecoveryRequest,
  options: { readonly maxRecords?: number; readonly nowEpochMs?: number } = {}
): StateRecoveryResult {
  const nowEpochMs = options.nowEpochMs ?? Date.now();
  const maxRecords = options.maxRecords ?? 10_000;
  const findings: RecoveredRecordFinding[] = [];
  const expiredMemoryIds: string[] = [];
  const terminalRegistryIds: string[] = [];
  const terminalPeerIds: string[] = [];
  const admittedByKind: Record<RecordKind, number> = {
    event_ledger_entry: 0,
    tool_run_evidence: 0,
    memory_record: 0,
    agent_metadata: 0,
    goal_lifecycle: 0,
    skill_tool_registry: 0,
    peer_trust_registry: 0,
    federation_receipt: 0,
    federation_proposal: 0,
    federation_provenance: 0,
    derived_index: 0,
    store_checkpoint: 0,
  };

  const kinds: RecordKind[] = ["memory_record", "agent_metadata", "goal_lifecycle", "skill_tool_registry", "peer_trust_registry"];
  let scanned = 0;
  let scanTruncated = false;
  outer: for (const kind of kinds) {
    const ids = store.listRecordIds(kind);
    for (const recordId of ids) {
      if (scanned >= maxRecords) {
        scanTruncated = true;
        break outer;
      }
      scanned++;
      const read = store.readRecord(recordId);
      if (!read.ok) {
        // Store-quarantined bytes: integrity could not be established.
        findings.push({
          recordId,
          recordKind: kind,
          integrityStatus: "integrity_unknown",
          cause: "unreadable_record",
          alreadyQuarantined: true,
        });
        continue;
      }
      if (kind === "memory_record") {
        const parsed = (read.record.payload as Record<string, unknown>)["memory"];
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
          findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_failed", cause: "identity_binding_mismatch", alreadyQuarantined: false });
          continue;
        }
        const record = parsed as MemoryStateRecord;
        if (record.memoryId !== recordId.slice("mem-".length)) {
          findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_failed", cause: "identity_binding_mismatch", alreadyQuarantined: false });
          continue;
        }
        const denied = scanPayload(read.record.payload as Record<string, unknown>);
        if (denied !== null) {
          findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_failed", cause: "denied_key_present", alreadyQuarantined: false });
          continue;
        }
        if (!isMemoryRestorable(record, nowEpochMs)) {
          expiredMemoryIds.push(record.memoryId);
          continue; // retention expiry is NOT corruption: excluded, not quarantined
        }
      }
      {
        // Secret-policy re-scan for EVERY mutable kind at recovery: the
        // write-time scan only ever saw the 22D adapter writers; a re-sealed
        // payload (content-hash-consistent corruption) must fail closed
        // here too — a denied key present at recovery is corruption, not a
        // legit persistence path.
        const denied = findDeniedStateKeyPaths(read.record.payload as Record<string, unknown>);
        if (denied.length > 0) {
          findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_failed", cause: "denied_key_present", alreadyQuarantined: false });
          continue;
        }
      }
      if (kind === "agent_metadata") {
        const parsed = (read.record.payload as Record<string, unknown>)["agentMetadata"];
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
          findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_failed", cause: "identity_binding_mismatch", alreadyQuarantined: false });
          continue;
        }
        const state = parsed as AgentMetadataState;
        if (state.agentId !== recordId.slice("agt-".length) || state.authority !== "mediation" || state.executionAuthorized !== false) {
          findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_failed", cause: "authority_marker_violation", alreadyQuarantined: false });
          continue;
        }
      }
      if (kind === "goal_lifecycle") {
        const parsed = (read.record.payload as Record<string, unknown>)["taskLifecycle"];
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
          findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_failed", cause: "identity_binding_mismatch", alreadyQuarantined: false });
          continue;
        }
        const state = parsed as TaskLifecycleState;
        if (state.goalId !== recordId.slice("gol-".length)) {
          findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_failed", cause: "identity_binding_mismatch", alreadyQuarantined: false });
          continue;
        }
      }
      if (kind === "skill_tool_registry") {
        const parsed = (read.record.payload as Record<string, unknown>)["registryLifecycle"];
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
          findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_failed", cause: "identity_binding_mismatch", alreadyQuarantined: false });
          continue;
        }
        const state = parsed as RegistryLifecycleState;
        const idCheck = registryDurableId(state.toolId, state.version);
        if (!idCheck.ok || idCheck.recordId !== recordId) {
          findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_failed", cause: "identity_binding_mismatch", alreadyQuarantined: false });
          continue;
        }
        if (state.lifecycle === "quarantined" || state.lifecycle === "retired") {
          terminalRegistryIds.push(recordId);
        }
      }
      if (kind === "peer_trust_registry") {
        const parsed = (read.record.payload as Record<string, unknown>)["peerTrust"];
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
          findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_failed", cause: "identity_binding_mismatch", alreadyQuarantined: false });
          continue;
        }
        const state = parsed as PeerTrustState;
        if (state.nodeId !== peerNodeIdOfRecordId(recordId)) {
          findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_failed", cause: "identity_binding_mismatch", alreadyQuarantined: false });
          continue;
        }
        if (state.trustState === "quarantined" || state.trustState === "retired") {
          terminalPeerIds.push(recordId);
        }
      }
      findings.push({ recordId, recordKind: kind, integrityStatus: "integrity_verified", cause: null, alreadyQuarantined: false });
      admittedByKind[kind] += 1;
    }
  }

  // A truncated scan rejects recovery entirely (partial recovery is not
  // recovery) — surfaced through the frozen 22A decision.
  const snapshot: RecoverySnapshot = {
    expectedStoreSchemaVersion: request.expectedStoreSchemaVersion,
    actualStoreSchemaVersion: store.storeSchemaVersion,
    committedThrough: store.committedThrough,
    observedThrough: store.committedThrough,
    totalRecordsScanned: scanned,
    findings,
    scanTruncated,
  };
  const decision = decideRecovery(snapshot, request);
  return {
    decision,
    admittedByKind,
    expiredMemoryIds: Object.freeze(expiredMemoryIds),
    terminalRegistryIds: Object.freeze(terminalRegistryIds),
    terminalPeerIds: Object.freeze(terminalPeerIds),
    derivedRebuildRequired: decision.code === "rebuild_derived_required",
  };
}
