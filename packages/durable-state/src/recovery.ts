/**
 * PHASE 22A — Recovery, migration, quarantine, and checkpoint contracts
 * (CONTRACT-ONLY; no backend, no recovery executor).
 *
 * Recovery is a READ-AND-DECIDE boundary. It produces Decisions about what
 * the store may load; it NEVER executes anything, authorizes anything, or
 * repairs anything. The central Phase-22 invariant is carried on the types:
 *
 *     durable state ≠ executable replay ≠ authorization
 *
 * Every recovery decision that admits a record stamps it `recovered_data` —
 * the structural marker that the record entered the runtime through the
 * recovery boundary. Nothing downstream may treat `recovered_data` as a
 * policy allow or an execution grant; the authority chain
 * (Planner → Allocation → Policy → Isolation → Governed Tool Runtime →
 * Evidence/Ledger) is untouched by recovery.
 */

import type {
  CommitSequence,
  DurableRecordId,
  IntegrityStatus,
  QuarantineSchemaVersion,
  RecordKind,
  StoreCheckpointSchemaVersion,
} from "./records.js";

// ── recovery request ─────────────────────────────────────────────────────────

/** What recovery is being asked to do (closed union). */
export const RECOVERY_MODES = Object.freeze([
  "load_committed_state",  // normal restart: load last committed state
  "verify_full_ledger",    // full integrity verification pass (read-only)
  "rebuild_derived_only",  // discard + recompute indexes/checkpoints only
] as const);
export type RecoveryMode = (typeof RECOVERY_MODES)[number];

export interface RecoveryRequest {
  readonly mode: RecoveryMode;
  /** Store schema the recovery was prepared against. */
  readonly expectedStoreSchemaVersion: string;
  /** Upper bound on records to scan (bounded recovery; no unbounded loops). */
  readonly maxRecords: number;
  /**
   * Always "no_execution": recovery never re-executes. The field is
   * structural — a recovery request that could request execution cannot be
   * expressed in this vocabulary.
   */
  readonly semantics: "no_execution";
}

// ── recovery snapshot ────────────────────────────────────────────────────────

/** Per-record integrity finding during recovery (typed, never healed). */
export interface RecoveredRecordFinding {
  readonly recordId: DurableRecordId;
  readonly recordKind: RecordKind;
  readonly integrityStatus: IntegrityStatus;
  /** For integrity_failed/unknown: the bounded, typed cause. */
  readonly cause: string | null;
  /** True when the record was found in a quarantined segment already. */
  readonly alreadyQuarantined: boolean;
}

/** The read-only snapshot recovery inspected (data, not authority). */
export interface RecoverySnapshot {
  readonly expectedStoreSchemaVersion: string;
  readonly actualStoreSchemaVersion: string | null;
  /** Commit sequence the store durably committed through (if discoverable). */
  readonly committedThrough: CommitSequence | null;
  /** Commit sequence observed on disk (may exceed committedThrough after a crash). */
  readonly observedThrough: CommitSequence | null;
  readonly totalRecordsScanned: number;
  readonly findings: readonly RecoveredRecordFinding[];
  /** Records whose scan hit the recovery bound (they were NOT evaluated). */
  readonly scanTruncated: boolean;
}

// ── recovery decision (closed union; fail closed) ────────────────────────────

export const RECOVERY_DECISION_CODES = Object.freeze([
  "accept_full_state",        // every record verified; state loaded as data
  "accept_without_quarantined", // verified records loaded; corrupt ones quarantined
  "rebuild_derived_required", // derived data is stale/poisoned; rebuild before use
  "rejected_schema_mismatch", // store schema unknown/mismatched — fail closed
  "rejected_unverifiable",    // integrity could not be established — fail closed
  "rejected_scan_bound",      // recovery could not complete within bounds — fail closed
] as const);
export type RecoveryDecisionCode = (typeof RECOVERY_DECISION_CODES)[number];

export const RECOVERY_DENY_REASONS = Object.freeze([
  "unknown_schema_version",
  "schema_version_mismatch",
  "integrity_failed",
  "integrity_unknown",
  "scan_bound_exceeded",
  "checkpoint_ledger_divergence",
] as const);
export type RecoveryDenyReason = (typeof RECOVERY_DENY_REASONS)[number];

export interface RecoveryDecision {
  readonly code: RecoveryDecisionCode;
  /** On accept codes: ids of records admitted, each implicitly `recovered_data`. */
  readonly admittedRecordIds: readonly DurableRecordId[];
  /** On accept_without_quarantined: ids routed to quarantine (never healed). */
  readonly quarantinedRecordIds: readonly DurableRecordId[];
  /** ALWAYS "recovered_data" — admitted records carry no execution authority. */
  readonly authority: "recovered_data";
  /** ALWAYS false — recovery can never authorize execution. */
  readonly executionAuthorized: false;
  /** ALWAYS false — recovery can never flip a policy decision. */
  readonly policyAuthorized: false;
  /** For rejections: the typed deny reason. */
  readonly denyReason: RecoveryDenyReason | null;
  /** Bounded human-readable explanation (never hostile record content). */
  readonly explanation: string;
}

/**
 * The ONLY sanctioned way to build a RecoveryDecision (pure function). The
 * constructor makes the invariants unrepresentable to violate: any decision
 * it returns carries authority "recovered_data", executionAuthorized false,
 * policyAuthorized false.
 */
export function decideRecovery(
  snapshot: RecoverySnapshot,
  request: RecoveryRequest
): RecoveryDecision {
  // Schema mismatch fails closed.
  if (
    snapshot.actualStoreSchemaVersion === null ||
    snapshot.actualStoreSchemaVersion !== request.expectedStoreSchemaVersion
  ) {
    return {
      code: "rejected_schema_mismatch",
      admittedRecordIds: Object.freeze([]),
      quarantinedRecordIds: Object.freeze([]),
      authority: "recovered_data",
      executionAuthorized: false,
      policyAuthorized: false,
      denyReason:
        snapshot.actualStoreSchemaVersion === null
          ? "unknown_schema_version"
          : "schema_version_mismatch",
      explanation:
        "store schema '" + String(snapshot.actualStoreSchemaVersion) +
        "' does not match expected '" + request.expectedStoreSchemaVersion + "' — failing closed",
    };
  }
  // Scan bound exceeded fails closed (partial recovery is not recovery).
  if (snapshot.scanTruncated) {
    return {
      code: "rejected_scan_bound",
      admittedRecordIds: Object.freeze([]),
      quarantinedRecordIds: Object.freeze([]),
      authority: "recovered_data",
      executionAuthorized: false,
      policyAuthorized: false,
      denyReason: "scan_bound_exceeded",
      explanation:
        "recovery scanned " + String(snapshot.totalRecordsScanned) +
        " records and hit the bound before completion — failing closed",
    };
  }
  // Unverifiable integrity fails closed when it touches authoritative data.
  const failed = snapshot.findings.filter(
    (f) => f.integrityStatus !== "integrity_verified" && !f.alreadyQuarantined
  );
  const quarantinedIds = failed.map((f) => f.recordId);
  const admitted = snapshot.findings
    .filter((f) => f.integrityStatus === "integrity_verified" && !f.alreadyQuarantined)
    .map((f) => f.recordId);
  if (failed.length > 0) {
    return {
      code: "accept_without_quarantined",
      admittedRecordIds: Object.freeze(admitted),
      quarantinedRecordIds: Object.freeze(quarantinedIds),
      authority: "recovered_data",
      executionAuthorized: false,
      policyAuthorized: false,
      denyReason: null,
      explanation:
        String(failed.length) + " record(s) failed integrity verification and were QUARANTINED (never repaired, never healed); " +
        String(admitted.length) + " verified record(s) admitted as recovered_data",
    };
  }
  // Derived data must be rebuilt after load unless it verified AND its
  // checkpoint agrees with the ledger position.
  const derivedStale =
    snapshot.observedThrough !== null &&
    snapshot.committedThrough !== null &&
    snapshot.observedThrough !== snapshot.committedThrough;
  if (derivedStale) {
    return {
      code: "rebuild_derived_required",
      admittedRecordIds: Object.freeze(admitted),
      quarantinedRecordIds: Object.freeze([]),
      authority: "recovered_data",
      executionAuthorized: false,
      policyAuthorized: false,
      denyReason: "checkpoint_ledger_divergence",
      explanation:
        "ledger observedThrough (" + String(snapshot.observedThrough) +
        ") diverges from committedThrough (" + String(snapshot.committedThrough) +
        ") — derived data must be rebuilt; authoritative data admitted as recovered_data",
    };
  }
  return {
    code: "accept_full_state",
    admittedRecordIds: Object.freeze(admitted),
    quarantinedRecordIds: Object.freeze([]),
    authority: "recovered_data",
    executionAuthorized: false,
    policyAuthorized: false,
    denyReason: null,
    explanation:
      "all " + String(admitted.length) + " scanned record(s) verified; state admitted as recovered_data (no execution, no authorization)",
  };
}

// ── migration (explicit, versioned, evidenced; never implicit) ───────────────

export const MIGRATION_DECISION_CODES = Object.freeze([
  "migration_unnecessary",
  "migration_planned",          // explicit plan produced; NOT executed
  "migration_rejected_unsupported", // unsupported source/target — fail closed
  "migration_rejected_evidence",    // prior migration evidence missing/mismatched
] as const);
export type MigrationDecisionCode = (typeof MIGRATION_DECISION_CODES)[number];

/**
 * A migration plan is a DESCRIPTION of a transformation, carrying evidence
 * requirements. Nothing here executes a migration — that is 22E scope, and
 * only after explicit evidence checks. Migrations are versioned: source →
 * target, one step at a time; skipping versions is unrepresentable.
 */
export interface MigrationPlan {
  readonly sourceStoreSchemaVersion: string;
  readonly targetStoreSchemaVersion: string;
  /** MUST be exactly one step ahead of source (no version skipping). */
  readonly stepCount: 1;
  /** Evidence that MUST exist before execution (checked by 22E, not here). */
  readonly requiredEvidence: readonly string[];
  /** Records that CANNOT be migrated (they must be quarantined instead). */
  readonly unmovableRecordKinds: readonly RecordKind[];
  /** Non-executing marker, mirroring the 21E replay discipline. */
  readonly semantics: "non_executing";
}

export type MigrationDecision =
  | {
      readonly ok: true;
      readonly code: "migration_unnecessary" | "migration_planned";
      readonly plan: MigrationPlan | null;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code: "migration_rejected_unsupported" | "migration_rejected_evidence";
      readonly plan: null;
      readonly explanation: string;
    };

/**
 * Decide whether a migration is needed. The store's CURRENT schema and the
 * code's KNOWN schemas are the only inputs. If the current schema is not
 * known to this code, the decision fails closed — no in-place "upgrades" of
 * unknown layouts, no guessing.
 */
export function decideMigration(input: {
  readonly currentStoreSchemaVersion: string | null;
  readonly knownStoreSchemaVersions: readonly string[];
  readonly codeStoreSchemaVersion: string;
}): MigrationDecision {
  const current = input.currentStoreSchemaVersion;
  if (current === null) {
    return {
      ok: true,
      code: "migration_unnecessary",
      plan: null,
      explanation: "no existing store (fresh layout) — no migration needed",
    };
  }
  if (!input.knownStoreSchemaVersions.includes(current)) {
    return {
      ok: false,
      code: "migration_rejected_unsupported",
      plan: null,
      explanation:
        "store schema '" + current + "' is not known to this code — migration is refused (unknown schemas fail closed)",
    };
  }
  if (current === input.codeStoreSchemaVersion) {
    return {
      ok: true,
      code: "migration_unnecessary",
      plan: null,
      explanation: "store already at the code's schema version",
    };
  }
  // Only one-step migrations are representable.
  const known = input.knownStoreSchemaVersions;
  const idx = known.indexOf(current);
  const next = known[idx + 1];
  if (next === undefined || next !== input.codeStoreSchemaVersion) {
    return {
      ok: false,
      code: "migration_rejected_unsupported",
      plan: null,
      explanation:
        "no single-step migration path from '" + current + "' to '" +
        input.codeStoreSchemaVersion + "' — refusing to skip versions",
    };
  }
  return {
    ok: true,
    code: "migration_planned",
    plan: Object.freeze({
      sourceStoreSchemaVersion: current,
      targetStoreSchemaVersion: next,
      stepCount: 1,
      requiredEvidence: Object.freeze([
        "pre-migration ledger verify pass (ok=true)",
        "pre-migration quarantine review (empty or human-acknowledged)",
        "post-migration full integrity re-verification",
      ]),
      unmovableRecordKinds: Object.freeze([]),
      semantics: "non_executing",
    }),
    explanation:
      "single-step migration plan produced (non-executing); execution requires the 22E evidence gate",
  };
}

// ── quarantine (corruption is isolated, never healed) ────────────────────────

export const QUARANTINE_CAUSES = Object.freeze([
  "content_hash_mismatch",
  "unknown_schema_version",
  "unknown_record_kind",
  "chain_broken",
  "parent_missing",
  "truncated_record",
  "oversized_record",
  "malformed_envelope",
] as const);
export type QuarantineCause = (typeof QUARANTINE_CAUSES)[number];

/**
 * A quarantine record: the storage-side sibling of the 19C agent-envelope
 * quarantine. The offending record is preserved AS FOUND (bytes hashed,
 * not repaired), moved out of all readable state, and retained for human
 * audit. There is no un-quarantine operation in this contract — recovery
 * of a quarantined record requires explicit human disposition (22E).
 */
export interface QuarantineRecord {
  readonly schemaVersion: QuarantineSchemaVersion;
  readonly quarantineId: string;
  readonly atEpochMs: number;
  readonly recordId: DurableRecordId;
  readonly recordKind: RecordKind | "unknown";
  readonly cause: QuarantineCause;
  /** sha256 of the record AS FOUND — evidence, never a repair source. */
  readonly asFoundHash: string;
  /** Bounded cause detail; hostile content is never echoed. */
  readonly detail: string;
  /** ALWAYS "recovered_data" — quarantine bookkeeping is recovery-layer data. */
  readonly authority: "recovered_data";
  /** ALWAYS false. */
  readonly executionAuthorized: false;
}

// ── store checkpoint (derived; bounds recovery work) ──────────────────────────

/**
 * A checkpoint summarizes committed state so recovery can bound its scan.
 * It is DERIVED: the ledger is always the source of truth. A checkpoint
 * that disagrees with the ledger is discarded and rebuilt (never trusted,
 * never "healed" to match).
 */
export interface StoreCheckpoint {
  readonly schemaVersion: StoreCheckpointSchemaVersion;
  readonly checkpointId: string;
  readonly atEpochMs: number;
  /** Highest commit sequence included in the checkpoint. */
  readonly committedThrough: CommitSequence;
  /** Number of authoritative records covered. */
  readonly authoritativeRecordCount: number;
  /** Hash over the checkpoint's own contents (self-integrity). */
  readonly checkpointHash: string;
  /** The ledger tail hash the checkpoint was built against. */
  readonly ledgerTailHash: string;
  /** ALWAYS "derived_data" — checkpoints never override the ledger. */
  readonly authority: "derived_data";
}
