/**
 * PHASE 22A — Durable-State Trust Model: core record contracts (CONTRACT /
 * TEST-FIRST, NO BACKEND).
 *
 * This module defines WHAT a durable record IS inside Menog's authority
 * chain. It implements NO storage: no file I/O, no database, no network,
 * no serialization-to-disk. Nothing in this file can read, write, repair,
 * or authorize anything. Phase 22B (local transactional store) is the
 * backend gate that will later satisfy these contracts; until then these
 * types and pure functions are the authoritative vocabulary.
 *
 * Central invariant (frozen for the whole of Phase 22):
 *
 *     durable state ≠ executable replay ≠ authorization
 *
 * A DurableRecordEnvelope is EVIDENCE OF WHAT HAPPENED — never a request to
 * do it again, never a grant. Recovered records enter the runtime as data
 * under recovery authority; they can never flip a policy decision, restart
 * execution, or resurrect a quarantined/retired lifecycle state.
 *
 * Fail-closed law (each enforced by tests):
 * - Unknown schemaVersion → rejected (schema confusion fails closed).
 * - Unknown recordKind → rejected.
 * - Unknown durabilityClass → rejected.
 * - Immutable-record mutation is unrepresentable: updates produce a NEW
 *   envelope with a new revision, preserving id + parent chain.
 * - Secret-shaped payload keys are denied by default (no secret persistence
 *   unless a future gate explicitly models and proves it).
 * - Integrity failures are typed, never healed: corrupted records are
 *   quarantined, never silently repaired.
 */

// ── schema versions ──────────────────────────────────────────────────────────

/** Store layout version: bumped when the on-disk STORE layout changes. */
export const DURABLE_STORE_SCHEMA_VERSION = "menog-durable-store/v0" as const;
export type DurableStoreSchemaVersion = typeof DURABLE_STORE_SCHEMA_VERSION;

/** Record envelope version: bumped when the envelope shape itself changes. */
export const DURABLE_RECORD_SCHEMA_VERSION = "menog-durable-record/v0" as const;
export type DurableRecordSchemaVersion = typeof DURABLE_RECORD_SCHEMA_VERSION;

/** Checkpoint version. */
export const STORE_CHECKPOINT_SCHEMA_VERSION = "menog-store-checkpoint/v0" as const;
export type StoreCheckpointSchemaVersion = typeof STORE_CHECKPOINT_SCHEMA_VERSION;

/** Quarantine record version. */
export const QUARANTINE_SCHEMA_VERSION = "menog-storage-quarantine/v0" as const;
export type QuarantineSchemaVersion = typeof QUARANTINE_SCHEMA_VERSION;

// ── identity ─────────────────────────────────────────────────────────────────

/**
 * DurableRecordId: stable across restarts, immutable once written. Format:
 * kind-prefixed opaque token (validated; never parsed for meaning).
 */
export type DurableRecordId = string;

/** Content-addressed revision id: sha256 over the canonical envelope body. */
export type DurableRevisionId = string;

/** Pattern for a durable record id: '<kind-prefix>-<base32ish token>'. */
export const DURABLE_RECORD_ID_PATTERN = /^[a-z][a-z0-9]{1,15}-[a-zA-Z0-9-]{8,64}$/;

// ── record kinds (closed union) ──────────────────────────────────────────────

/**
 * WHAT is being made durable. Closed union: introducing a new kind is an
 * unfreeze-protocol event requiring an explicit contract change.
 */
export const RECORD_KINDS = Object.freeze([
  "event_ledger_entry",   // append-only ledger events (authoritative evidence)
  "tool_run_evidence",    // sealed tool run records (21E records)
  "memory_record",        // structured memory (16A/16B)
  "agent_metadata",       // agent identity/profile/mediation bookkeeping (19A)
  "goal_lifecycle",       // Goal/Task/Plan lifecycle state
  "skill_tool_registry",  // skill/tool registry lifecycle state (21B)
  "peer_trust_registry",  // federation peer trust state (24C; terminal-quarantine)
  "federation_receipt",   // append-only federation receipt evidence (24D)
  "federation_proposal",  // append-only cross-node task PROPOSAL evidence (24E; inert)
  "federation_provenance", // append-only cross-node provenance ANCHOR evidence (24F)
  "derived_index",        // rebuilt indexes (never authoritative)
  "store_checkpoint",     // store checkpoints (derived; aids recovery only)
] as const);
export type RecordKind = (typeof RECORD_KINDS)[number];

export function isRecordKind(value: unknown): value is RecordKind {
  return (
    typeof value === "string" &&
    (RECORD_KINDS as readonly string[]).includes(value)
  );
}

/** Id prefix per record kind (validated, never parsed for meaning). */
export const RECORD_KIND_ID_PREFIXES: Readonly<Record<RecordKind, string>> =
  Object.freeze({
    event_ledger_entry: "evt",
    tool_run_evidence: "run",
    memory_record: "mem",
    agent_metadata: "agt",
    goal_lifecycle: "gol",
    skill_tool_registry: "reg",
    peer_trust_registry: "peer",
    federation_receipt: "frc",
    federation_proposal: "fpr",
    federation_provenance: "fpv",
    derived_index: "idx",
    store_checkpoint: "chk",
  });

// ── durability classes (closed union) ────────────────────────────────────────

/**
 * HOW a record must survive. The class bounds what the future store may do:
 * - `append_only`: the store MUST refuse any mutation or deletion of the
 *   payload; new revisions are impossible (ledger entries, run evidence).
 * - `versioned_mutable`: mutation is modeled as a NEW revision of the same
 *   record id; the prior revision remains verifiable.
 * - `rebuildable`: the record MAY be discarded and recomputed from
 *   authoritative inputs; loss of it is never a data-loss event.
 */
export const DURABILITY_CLASSES = Object.freeze([
  "append_only",
  "versioned_mutable",
  "rebuildable",
] as const);
export type DurabilityClass = (typeof DURABILITY_CLASSES)[number];

export function isDurabilityClass(value: unknown): value is DurabilityClass {
  return (
    typeof value === "string" &&
    (DURABILITY_CLASSES as readonly string[]).includes(value)
  );
}

// ── secret policy (closed union) ─────────────────────────────────────────────

/**
 * Secret posture of a record. `secret_free` is the ONLY class a record may
 * carry today; anything else is rejected at the envelope boundary (no
 * secret persistence until a future gate explicitly models it, proves it,
 * and unfreezes this union).
 */
export const SECRET_POLICIES = Object.freeze(["secret_free"] as const);
export type SecretPolicy = (typeof SECRET_POLICIES)[number];

// ── authority classes (closed union) ─────────────────────────────────────────

/**
 * Which authority class a durable artifact is. Mirrors the established
 * authority markers of Phases 16/19/21 and ADDS the recovery class:
 * `recovered_data` marks anything read back from storage. The marker is
 * structural: nothing in the type system can turn recovered data into
 * execution authority or into a policy decision.
 */
export type DurableAuthorityClass =
  | "durable_evidence"    // authoritative, tamper-evident record of the past
  | "durable_state"       // authoritative mutable state snapshot
  | "derived_data"        // rebuildable; never authoritative
  | "recovered_data";     // read back from storage after a restart

// ── envelope ─────────────────────────────────────────────────────────────────

/**
 * The envelope EVERY durable record is wrapped in. The payload is opaque to
 * this contract layer; per-kind schemas are validated by their owning
 * subsystems (core, memory, agents, toolruntime) — never inferred here.
 */
export interface DurableRecordEnvelope {
  readonly schemaVersion: DurableRecordSchemaVersion;
  readonly recordId: DurableRecordId;
  readonly recordKind: RecordKind;
  readonly durabilityClass: DurabilityClass;
  /** Always "secret_free" today; the field exists so denial is explicit. */
  readonly secretPolicy: SecretPolicy;
  /**
   * Structural authority marker of the WRITER's intent at persist time.
   * Persisted records of kind event_ledger_entry / tool_run_evidence always
   * carry "durable_evidence"; derived kinds always "derived_data"; the
   * mutable state kinds carry "durable_state". "recovered_data" is stamped
   * ONLY by the recovery boundary (22E) when a record is read back.
   */
  readonly authority: DurableAuthorityClass;
  /** Monotone per-record revision; 1 for the first write of a record id. */
  readonly revision: number;
  /** For versioned_mutable records: the revision this one supersedes. */
  readonly supersedesRevision: number | null;
  /** Immutable creation stamp (epoch-ms; writer-provided, never inferred). */
  readonly createdAtEpochMs: number;
  /** Stamp of the writing transaction. */
  readonly transactionId: TransactionId;
  /** Opaque JSON-serializable payload; secret-shaped keys denied by default. */
  readonly payload: Readonly<Record<string, unknown>>;
  /** sha256 over the canonical envelope body EXCLUDING this hash field. */
  readonly contentHash: string;
}

/** Envelope with the hash removed — the hash input. */
export type DurableRecordEnvelopeBody = Omit<DurableRecordEnvelope, "contentHash">;

// ── transaction identity ─────────────────────────────────────────────────────

/**
 * TransactionId: identifies ONE atomic persist intent. Opaque, bounded,
 * never reused. The store (22B) is responsible for assigning commit
 * sequences; the contract layer only validates shape.
 */
export type TransactionId = string;

export const TRANSACTION_ID_PATTERN = /^[a-z][a-z0-9-]{2,63}$/;

/**
 * CommitSequence: total order of committed transactions in one store.
 * Monotone, gap-free per store, assigned by the store at commit.
 */
export type CommitSequence = number;

// ── integrity (closed union) ─────────────────────────────────────────────────

/**
 * IntegrityStatus of an envelope as verified against its own contentHash.
 * `integrity_failed` is terminal: the record is quarantined, never repaired,
 * never accepted. `integrity_unknown` means verification could not be
 * performed (missing hasher, truncated input) — also fail-closed for any
 * authority-bearing use.
 */
export const INTEGRITY_STATUSES = Object.freeze([
  "integrity_verified",
  "integrity_failed",
  "integrity_unknown",
] as const);
export type IntegrityStatus = (typeof INTEGRITY_STATUSES)[number];

// ── persistence decisions ────────────────────────────────────────────────────

/** Why a persist was refused (closed union; fail-closed reasons). */
export const PERSIST_FAILURE_CODES = Object.freeze([
  "unknown_schema_version",
  "unknown_record_kind",
  "unknown_durability_class",
  "unknown_secret_policy",
  "unknown_authority_class",
  "invalid_record_id",
  "id_kind_mismatch",
  "invalid_revision",
  "append_only_mutation",
  "append_only_delete",
  "invalid_transaction_id",
  "invalid_timestamp",
  "payload_not_serializable",
  "secret_key_denied",
  "payload_oversized",
  "content_hash_mismatch",
  "duplicate_revision",
  "revision_conflict",
  "store_closed",
  "store_readonly",
  "capacity_exhausted",
  // 22B (local transactional store): backend-level denials.
  "duplicate_transaction",
  "derived_kind_forbidden",
  "transaction_aborted",
  "transaction_open",
] as const);
export type PersistFailureCode = (typeof PERSIST_FAILURE_CODES)[number];

export function isPersistFailureCode(value: unknown): value is PersistFailureCode {
  return (
    typeof value === "string" &&
    (PERSIST_FAILURE_CODES as readonly string[]).includes(value)
  );
}

/** The decision a store must reach for one persist intent. */
export type PersistDecision =
  | {
      readonly ok: true;
      readonly committed: true;
      readonly recordId: DurableRecordId;
      readonly revision: number;
      readonly transactionId: TransactionId;
      readonly commitSequence: CommitSequence;
    }
  | {
      readonly ok: false;
      readonly committed: false;
      readonly failureCode: PersistFailureCode;
      /** Bounded reason; hostile payload text is never echoed. */
      readonly reason: string;
      readonly transactionId: TransactionId | null;
    };

/**
 * The result contract every Phase-22 store persist operation satisfies.
 * (`PersistResult` is the envelope-level outcome; `PersistDecision` is the
 * pure, storage-free decision function's output.)
 */
export type PersistResult = PersistDecision;

/**
 * A failed persist. `committed: false` is structural: a failure can never
 * be a partial commit (torn writes are a 22B concern handled by rollback to
 * the last checkpoint; the decision layer is all-or-nothing by type).
 */
export interface PersistFailure {
  readonly ok: false;
  readonly committed: false;
  readonly failureCode: PersistFailureCode;
  readonly reason: string;
  readonly transactionId: TransactionId | null;
}

// ── validation result ────────────────────────────────────────────────────────

export type EnvelopeValidationResult =
  | { readonly ok: true; readonly envelope: DurableRecordEnvelope }
  | { readonly ok: false; readonly failureCode: PersistFailureCode; readonly reason: string };
