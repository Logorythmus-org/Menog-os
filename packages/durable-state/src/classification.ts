/**
 * PHASE 22A — Durable-state classification: authoritative vs derived,
 * append-only vs mutable, secret policy, integrity binding, recovery
 * semantics, retention. PURE DATA + PURE PREDICATES. No I/O, no backend,
 * no authority.
 *
 * This is the table of record for HOW each RecordKind must be treated by
 * any Phase-22 store. The classification is frozen policy, not a suggestion:
 * a store that treats a `rebuildable` index as authoritative — or an
 * `append_only` ledger entry as mutable — is WRONG by contract, and the
 * contract tests pin each row.
 */

import type {
  DurabilityClass,
  RecordKind,
} from "./records.js";

// ── authority posture ────────────────────────────────────────────────────────

/** Is the kind an authoritative record of the past or of state? */
export type AuthorityPosture = "authoritative" | "derived";

/**
 * Is the kind append-only (no mutation/deletion representable),
 * versioned-mutable (new revision supersedes old), or rebuildable
 * (may be discarded and recomputed)?
 * (`durabilityClass` re-exported conceptually; the rows pin it per kind.)
 */
export type MutationPosture = DurabilityClass;

/**
 * Recovery semantics after restart (closed union):
 * - `replay_free`: the record IS the history; recovery must accept it as
 *   data and must NOT re-execute anything it describes.
 * - `restore_state`: the record restores semantic state; recovered state is
 *   still non-authoritative data until every integrity check passes.
 * - `rebuild_from_authoritative`: discard on load; recompute from
 *   authoritative records only.
 * - `verify_then_accept`: accept only after integrity + parent-chain
 *   verification; otherwise quarantine.
 */
export type RecoverySemantics =
  | "replay_free"
  | "restore_state"
  | "rebuild_from_authoritative"
  | "verify_then_accept";

/** Retention policy (closed union) — metadata now; enforcement is 22D scope. */
export type RetentionClass = "permanent" | "session_scoped" | "until_superseded" | "checkpoint_bound";

/** One classification row (frozen). */
export interface RecordKindClassification {
  readonly recordKind: RecordKind;
  readonly authorityPosture: AuthorityPosture;
  readonly mutationPosture: MutationPosture;
  /** ALWAYS "secret_free" today — see records.ts SECRET_POLICIES. */
  readonly secretPolicy: "secret_free";
  /**
   * Whether the record's bytes are bound by a content hash that recovery
   * MUST re-verify (tamper-evident) before use.
   */
  readonly integrityBinding: "content_hash_required" | "content_hash_derived";
  readonly recoverySemantics: RecoverySemantics;
  readonly retentionClass: RetentionClass;
  /** Bounded rationale (documentation-grade; test-pinned per kind). */
  readonly rationale: string;
}

/**
 * THE classification table. Every row is a frozen decision:
 *
 * - event_ledger_entry: authoritative append-only evidence (the ledger IS
 *   the tamper-evident record of what happened). Recovery replays NOTHING —
 *   it reads and verifies. Permanent retention.
 * - tool_run_evidence: authoritative append-only evidence (sealed 21E run
 *   records). verify_then_accept: hashes re-verified, parent ids preserved.
 * - memory_record: authoritative mutable state (structured memory is
 *   state, not evidence); versioned_mutable; restore_state. Session-scoped
 *   entries expire; persistent entries are retained.
 * - agent_metadata: authoritative mutable state (identity/profile
 *   bookkeeping); versioned_mutable; restore_state; verify_then_accept on
 *   load (profile changes are frozen records — drift is corruption).
 * - goal_lifecycle: authoritative mutable state (Goal/Task/Plan lifecycle);
 *   versioned_mutable; restore_state. Terminal states (done/failed/
 *   rejected) are append-only facts once written.
 * - skill_tool_registry: authoritative mutable lifecycle state; quarantined
 *   and retired are terminal — recovery can NEVER resurrect them
 *   (anti-resurrection is pinned by tests).
 * - derived_index: derived, rebuildable, never authoritative. Loss is not
 *   data loss. A poisoned index is discarded and rebuilt, never trusted.
 * - store_checkpoint: derived, rebuildable; aids recovery boundedness only;
 *   never overrides the ledger.
 */
export const RECORD_KIND_CLASSIFICATION: Readonly<
  Record<RecordKind, RecordKindClassification>
> = Object.freeze({
  event_ledger_entry: Object.freeze({
    recordKind: "event_ledger_entry",
    authorityPosture: "authoritative",
    mutationPosture: "append_only",
    secretPolicy: "secret_free",
    integrityBinding: "content_hash_required",
    recoverySemantics: "replay_free",
    retentionClass: "permanent",
    rationale: "the hash-chained ledger is the authoritative record of what happened; recovery reads and verifies, never re-executes",
  }),
  tool_run_evidence: Object.freeze({
    recordKind: "tool_run_evidence",
    authorityPosture: "authoritative",
    mutationPosture: "append_only",
    secretPolicy: "secret_free",
    integrityBinding: "content_hash_required",
    recoverySemantics: "verify_then_accept",
    retentionClass: "permanent",
    rationale: "sealed run records are tamper-evident evidence; verified on load, quarantined on mismatch, never repaired",
  }),
  memory_record: Object.freeze({
    recordKind: "memory_record",
    authorityPosture: "authoritative",
    mutationPosture: "versioned_mutable",
    secretPolicy: "secret_free",
    integrityBinding: "content_hash_required",
    recoverySemantics: "restore_state",
    retentionClass: "session_scoped",
    rationale: "structured memory is authoritative semantic state, restored as data; still policy-gated after recovery",
  }),
  agent_metadata: Object.freeze({
    recordKind: "agent_metadata",
    authorityPosture: "authoritative",
    mutationPosture: "versioned_mutable",
    secretPolicy: "secret_free",
    integrityBinding: "content_hash_required",
    recoverySemantics: "verify_then_accept",
    retentionClass: "until_superseded",
    rationale: "identity/profile records are frozen at write; restored only after verification, never re-derived from agent data",
  }),
  goal_lifecycle: Object.freeze({
    recordKind: "goal_lifecycle",
    authorityPosture: "authoritative",
    mutationPosture: "versioned_mutable",
    secretPolicy: "secret_free",
    integrityBinding: "content_hash_required",
    recoverySemantics: "restore_state",
    retentionClass: "until_superseded",
    rationale: "Goal/Task/Plan lifecycle state is authoritative semantic state; terminal outcomes are append-only facts",
  }),
  skill_tool_registry: Object.freeze({
    recordKind: "skill_tool_registry",
    authorityPosture: "authoritative",
    mutationPosture: "versioned_mutable",
    secretPolicy: "secret_free",
    integrityBinding: "content_hash_required",
    recoverySemantics: "verify_then_accept",
    retentionClass: "until_superseded",
    rationale: "registry lifecycle state restores as data; quarantined/retired are terminal and can never be resurrected by recovery",
  }),
  peer_trust_registry: Object.freeze({
    recordKind: "peer_trust_registry",
    authorityPosture: "authoritative",
    mutationPosture: "versioned_mutable",
    secretPolicy: "secret_free",
    integrityBinding: "content_hash_required",
    recoverySemantics: "verify_then_accept",
    retentionClass: "until_superseded",
    rationale: "24C federation peer trust facts are authoritative state restored as data; peer trust NEVER grants execution authority; quarantined/retired peers are terminal and can never be resurrected by recovery",
  }),
  federation_receipt: Object.freeze({
    recordKind: "federation_receipt",
    authorityPosture: "authoritative",
    mutationPosture: "append_only",
    secretPolicy: "secret_free",
    integrityBinding: "content_hash_required",
    recoverySemantics: "verify_then_accept",
    retentionClass: "permanent",
    rationale: "24D federation receipts are the tamper-evident local record of cross-node message decisions; identity/authentication/admission evidence NEVER grants execution authority; recovery reads and verifies, never re-executes",
  }),
  federation_proposal: Object.freeze({
    recordKind: "federation_proposal",
    authorityPosture: "authoritative",
    mutationPosture: "append_only",
    secretPolicy: "secret_free",
    integrityBinding: "content_hash_required",
    recoverySemantics: "verify_then_accept",
    retentionClass: "permanent",
    rationale: "24E cross-node task PROPOSALS are durable, inert evidence of what was PROPOSED and how the LOCAL receiver judged it; a proposal never grants capabilities, never chooses Policy, never invokes anything; allocation/Policy re-run fresh and locally after recovery, and recovery never replays a proposal into execution",
  }),
  federation_provenance: Object.freeze({
    recordKind: "federation_provenance",
    authorityPosture: "authoritative",
    mutationPosture: "append_only",
    secretPolicy: "secret_free",
    integrityBinding: "content_hash_required",
    recoverySemantics: "verify_then_accept",
    retentionClass: "permanent",
    rationale: "24F cross-node provenance anchors are durable, tamper-evident BINDINGS of what happened across nodes (proposal/receipt/candidate/allocation/policy/execution); a binding is evidence of linkage, never a grant of authority; foreign evidence stays DATA, recovery verifies and never replays",
  }),
  derived_index: Object.freeze({
    recordKind: "derived_index",
    authorityPosture: "derived",
    mutationPosture: "rebuildable",
    secretPolicy: "secret_free",
    integrityBinding: "content_hash_derived",
    recoverySemantics: "rebuild_from_authoritative",
    retentionClass: "checkpoint_bound",
    rationale: "indexes are caches over authoritative records; discarded on load, recomputed, never trusted over the source",
  }),
  store_checkpoint: Object.freeze({
    recordKind: "store_checkpoint",
    authorityPosture: "derived",
    mutationPosture: "rebuildable",
    secretPolicy: "secret_free",
    integrityBinding: "content_hash_derived",
    recoverySemantics: "rebuild_from_authoritative",
    retentionClass: "checkpoint_bound",
    rationale: "checkpoints bound recovery work; they never override the ledger and are rebuilt when inconsistent",
  }),
});

/** Authoritative kinds (derived kinds are excluded by construction). */
export const AUTHORITATIVE_RECORD_KINDS: readonly RecordKind[] = Object.freeze(
  (Object.keys(RECORD_KIND_CLASSIFICATION) as RecordKind[]).filter(
    (k) => RECORD_KIND_CLASSIFICATION[k].authorityPosture === "authoritative"
  )
);

/** Derived kinds (indexes/checkpoints): rebuildable, never authoritative. */
export const DERIVED_RECORD_KINDS: readonly RecordKind[] = Object.freeze(
  (Object.keys(RECORD_KIND_CLASSIFICATION) as RecordKind[]).filter(
    (k) => RECORD_KIND_CLASSIFICATION[k].authorityPosture === "derived"
  )
);

/** Append-only kinds: mutation/deletion must be unrepresentable in the store. */
export const APPEND_ONLY_RECORD_KINDS: readonly RecordKind[] = Object.freeze(
  (Object.keys(RECORD_KIND_CLASSIFICATION) as RecordKind[]).filter(
    (k) => RECORD_KIND_CLASSIFICATION[k].mutationPosture === "append_only"
  )
);

export function isAuthoritativeKind(kind: RecordKind): boolean {
  return RECORD_KIND_CLASSIFICATION[kind].authorityPosture === "authoritative";
}

export function isDerivedKind(kind: RecordKind): boolean {
  return RECORD_KIND_CLASSIFICATION[kind].authorityPosture === "derived";
}

export function isAppendOnlyKind(kind: RecordKind): boolean {
  return RECORD_KIND_CLASSIFICATION[kind].mutationPosture === "append_only";
}

export function isVersionedMutableKind(kind: RecordKind): boolean {
  return RECORD_KIND_CLASSIFICATION[kind].mutationPosture === "versioned_mutable";
}

export function isRebuildableKind(kind: RecordKind): boolean {
  return RECORD_KIND_CLASSIFICATION[kind].mutationPosture === "rebuildable";
}

/**
 * Kinds whose lifecycle states include terminal quarantine that recovery
 * must respect (anti-resurrection surface).
 */
export const TERMINAL_QUARANTINE_KINDS: readonly RecordKind[] = Object.freeze([
  "skill_tool_registry",
  "tool_run_evidence",
  "peer_trust_registry",
] as const);
