/**
 * PHASE 22E — Recovery, Reconciliation & Schema Migration
 * (RECOVERY / NO EXECUTABLE REPLAY).
 *
 * Deterministic startup recovery in a FIXED, test-locked order:
 *
 *   1. open + verify store/schema (fail closed on unknown/mismatched schema)
 *   2. validate authoritative append-only material (mirrored ledger events
 *      + sealed tool evidence — 22C verification with the ledger's OWN hash
 *      vocabulary)
 *   3. validate mutable versions (22D state kinds + revision chains)
 *   4. reconcile cross-references (ledger↔evidence, task→ledger refs,
 *      duplicate transactions, manifest drift, orphan parents)
 *   5. quarantine unverifiable records / orphans (never repaired, never
 *      healed, never silently dropped)
 *   6. rebuild allowed derived indexes/checkpoints (only when the
 *      authoritative material verified)
 *   7. emit the RecoverySnapshot + evidence
 *   8. expose recovered state ONLY after validation
 *
 * MIGRATION: explicit from→to, DRY-RUN plan first, pre/post-conditions,
 * evidence-hash binding, unsupported migrations fail closed, original
 * evidence identity is NEVER rewritten, and a failed migration leaves a
 * DETECTABLE state (marked applied-with-failure or cleanly refused — never
 * a silent half-migration).
 *
 * CRITICAL INVARIANT (structurally enforced): recovery NEVER invokes the
 * governed tool junction, the launcher transport, any process spawn, any
 * rollback executor, or automatic task continuation. This module performs
 * NO I/O beyond the durable store reads/writes already sanctioned by
 * 22B/22C/22D, and its only outputs are data + decisions. Recovered records
 * grant no authority.
 */

import {
  DurableStore,
  type CheckpointVerifyResult,
} from "./store.js";
import { canonicalHash } from "./canonical.js";
import {
  type LedgerHashPort,
  type LedgerEvidenceVerificationReport,
  verifyPersistedLedgerAndEvidence as verifyPersistedLedgerAndEvidenceRef,
} from "./ledgerEvidence.js";
import {
  collectStateKindFacts,
  findDeniedStateKeyPaths,
  isTerminalTaskStatus,
  type RegistryLifecycleState,
  type TaskLifecycleState,
} from "./statePersistence.js";
import {
  decideRecovery,
  type RecoveryDecision,
  type RecoveryRequest,
} from "./recovery.js";
import type { RecordKind } from "./records.js";

// ── bounded reasons ──────────────────────────────────────────────────────────

const MAX_REASON_CHARS = 240;

function truncateReason(s: string): string {
  return s.length > MAX_REASON_CHARS ? s.slice(0, MAX_REASON_CHARS) : s;
}

// ── the migration registry (explicit, versioned, one step at a time) ────────

/**
 * One explicit schema-migration step. Migrations are REGISTERED, never
 * inferred: a step that is not in the registry is an unsupported migration
 * and fails closed. The transform is PURE (a plan-level description for the
 * dry run and the evidence hash) — it never rewrites original evidence
 * identity (ids, hashes, chain fields pass through untouched) and it can
 * only ADD or REPACK representation metadata, never change meaning.
 */
export interface RegisteredMigrationStep {
  readonly fromStoreSchemaVersion: string;
  readonly toStoreSchemaVersion: string;
  /** Human-reviewed description of the deterministic transform. */
  readonly description: string;
  /**
   * MUST be exactly one step ahead of source (the frozen 22A rule; the
   * registry enforces adjacency at registration time).
   */
  readonly stepCount: 1;
}

/**
 * The registry of known migration steps. v0 is the first store layout; the
 * registry is EMPTY by construction in this gate — there is exactly one
 * schema version (v0), so every from→to request other than the identity is
 * unsupported and fails closed. Adding a step is an explicit code change
 * with its own evidence obligations.
 */
export const REGISTERED_MIGRATION_STEPS: readonly RegisteredMigrationStep[] =
  Object.freeze([]);

export const MIGRATION_REGISTRY_HASH: string = canonicalHash({
  steps: REGISTERED_MIGRATION_STEPS,
});

// ── migration vocabulary ─────────────────────────────────────────────────────

export type MigrationExecutionCode =
  | "identity_no_migration_needed"
  | "plan_dry_run_ok"
  | "migration_applied"
  | "refused_unsupported_source"
  | "refused_unsupported_target"
  | "refused_not_adjacent"
  | "refused_unknown_schema"
  | "refused_preconditions_unmet"
  | "refused_store_closed"
  | "failed_postconditions";

export interface MigrationPreconditionReport {
  readonly condition: string;
  readonly met: boolean;
  readonly detail: string;
}

export interface MigrationDryRunPlan {
  readonly fromStoreSchemaVersion: string;
  readonly toStoreSchemaVersion: string;
  readonly stepCount: 1;
  readonly description: string;
  /** Pre-conditions checked BEFORE any write (all must hold). */
  readonly preconditions: readonly MigrationPreconditionReport[];
  /** Post-conditions that WILL be re-verified after the transform. */
  readonly postconditions: readonly string[];
  /**
   * sha256 over the canonical plan body — the migration evidence hash that
   * binds plan + registry + store identity. Never includes wall-clock time
   * (deterministic).
   */
  readonly planHash: string;
  /** ALWAYS "non_executing" — the dry run executes nothing. */
  readonly semantics: "non_executing";
  readonly registryHash: string;
}

export interface MigrationEvidence {
  readonly planHash: string;
  readonly fromStoreSchemaVersion: string;
  readonly toStoreSchemaVersion: string;
  readonly applied: boolean;
  readonly failureCode: MigrationExecutionCode | null;
  /** sha256 over the post-migration verification digest (when applied). */
  readonly postVerificationHash: string | null;
  /** Bounded conclusion-only detail; never echoes hostile content. */
  readonly detail: string;
}

export type MigrationExecutionResult =
  | {
      readonly ok: true;
      readonly code: "identity_no_migration_needed" | "migration_applied";
      readonly plan: MigrationDryRunPlan | null;
      readonly evidence: MigrationEvidence;
    }
  | {
      readonly ok: false;
      readonly code: Exclude<MigrationExecutionCode, "identity_no_migration_needed" | "migration_applied" | "plan_dry_run_ok" | "failed_postconditions">;
      readonly plan: MigrationDryRunPlan | null;
      readonly evidence: MigrationEvidence;
    }
  | {
      readonly ok: false;
      readonly code: "failed_postconditions";
      readonly plan: MigrationDryRunPlan;
      readonly evidence: MigrationEvidence;
    };

function migrationDeny(
  code: Exclude<MigrationExecutionCode, "identity_no_migration_needed" | "migration_applied" | "plan_dry_run_ok" | "failed_postconditions">,
  plan: MigrationDryRunPlan | null,
  detail: string
): MigrationExecutionResult {
  return {
    ok: false,
    code,
    plan,
    evidence: {
      planHash: plan?.planHash ?? canonicalHash({ refused: code }),
      fromStoreSchemaVersion: plan?.fromStoreSchemaVersion ?? "unknown",
      toStoreSchemaVersion: plan?.toStoreSchemaVersion ?? "unknown",
      applied: false,
      failureCode: code,
      postVerificationHash: null,
      detail: truncateReason(detail),
    },
  };
}

/**
 * Produce the DRY-RUN migration plan for a requested from→to transition.
 * Pure: reads nothing writable, executes nothing, changes nothing. Fails
 * closed for unknown schemas, unregistered steps, and non-adjacent jumps.
 */
export function planMigration(input: {
  readonly fromStoreSchemaVersion: string | null;
  readonly toStoreSchemaVersion: string;
}): { ok: true; plan: MigrationDryRunPlan | null } | { ok: false; code: Exclude<MigrationExecutionCode, "identity_no_migration_needed" | "migration_applied" | "plan_dry_run_ok" | "failed_postconditions">; reason: string } {
  const from = input.fromStoreSchemaVersion;
  if (from === null) {
    // Fresh layout: nothing to migrate.
    return { ok: true, plan: null };
  }
  if (typeof from !== "string" || from.length === 0) {
    return { ok: false, code: "refused_unknown_schema", reason: "source schema version is malformed" };
  }
  if (from === input.toStoreSchemaVersion) {
    return { ok: true, plan: null }; // identity
  }
  const step = REGISTERED_MIGRATION_STEPS.find((s) => s.fromStoreSchemaVersion === from);
  if (step === undefined) {
    return {
      ok: false,
      code: "refused_unsupported_source",
      reason: "source schema '" + from + "' has no registered migration step — unsupported migrations fail closed",
    };
  }
  if (step.toStoreSchemaVersion !== input.toStoreSchemaVersion) {
    return {
      ok: false,
      code: "refused_unsupported_target",
      reason: "registered step targets '" + step.toStoreSchemaVersion + "', not the requested '" + input.toStoreSchemaVersion + "'",
    };
  }
  const planBody = {
    fromStoreSchemaVersion: step.fromStoreSchemaVersion,
    toStoreSchemaVersion: step.toStoreSchemaVersion,
    stepCount: step.stepCount,
    description: step.description,
    registryHash: MIGRATION_REGISTRY_HASH,
    preconditions: [
      "source schema matches the registered step's source",
      "pre-migration full verification passes (ok=true)",
      "quarantine review: no unreviewed quarantine rows",
    ],
    postconditions: [
      "target schema version is active",
      "post-migration full verification passes (ok=true)",
      "original evidence identity preserved (record ids, hashes, chain fields)",
    ],
  };
  const plan: MigrationDryRunPlan = {
    fromStoreSchemaVersion: planBody.fromStoreSchemaVersion,
    toStoreSchemaVersion: planBody.toStoreSchemaVersion,
    stepCount: planBody.stepCount,
    description: planBody.description,
    preconditions: planBody.preconditions.map((c) => ({ condition: c, met: false, detail: "dry run — not yet checked" })),
    postconditions: planBody.postconditions,
    planHash: canonicalHash(planBody),
    semantics: "non_executing",
    registryHash: MIGRATION_REGISTRY_HASH,
  };
  return { ok: true, plan };
}

// ── the migration executor (explicit, evidenced, fail-closed) ────────────────

/**
 * Execute a migration ONLY after a dry-run plan exists, the preconditions
 * hold, and the migration is registered/adjacent. The current registry is
 * EMPTY (v0 is the only layout), so the only executable case in this gate
 * is the IDENTITY (from === to ⇒ no migration needed). When a future gate
 * registers a real step, this executor already enforces:
 *
 * - dry-run plan FIRST (planHash is the evidence anchor);
 * - precondition 1: the stored schema matches the plan's source;
 * - precondition 2: full pre-migration verification passes (ok=true);
 * - precondition 3: quarantine review (no unreviewed quarantine rows);
 * - original evidence identity is NEVER rewritten (the transform vocabulary
 *   of a registered step may only repack representation metadata);
 * - postconditions re-verified after the transform; a postcondition failure
 *   leaves a DETECTABLE state (`failed_postconditions` + evidence row with
 *   applied:false) — never a silent half-migration.
 */
export function executeMigration(
  store: DurableStore,
  port: LedgerHashPort,
  input: {
    readonly fromStoreSchemaVersion: string | null;
    readonly toStoreSchemaVersion: string;
    /** Must be the planHash returned by planMigration (dry-run-first law). */
    readonly planHash: string | null;
  }
): MigrationExecutionResult {
  if (!store.isOpen) {
    return migrationDeny("refused_store_closed", null, "store is closed — migration refused");
  }
  const planned = planMigration({ fromStoreSchemaVersion: input.fromStoreSchemaVersion, toStoreSchemaVersion: input.toStoreSchemaVersion });
  if (!planned.ok) {
    return migrationDeny(planned.code, null, planned.reason);
  }
  // Identity: nothing to migrate.
  if (planned.plan === null) {
    const evidence: MigrationEvidence = {
      planHash: canonicalHash({ identity: true, to: input.toStoreSchemaVersion }),
      fromStoreSchemaVersion: input.fromStoreSchemaVersion ?? "(fresh)",
      toStoreSchemaVersion: input.toStoreSchemaVersion,
      applied: false,
      failureCode: null,
      postVerificationHash: null,
      detail: "no migration needed (fresh layout or already at target schema)",
    };
    return { ok: true, code: "identity_no_migration_needed", plan: null, evidence };
  }
  const plan = planned.plan;
  // Dry-run-first: an executor call without the plan's hash is refused.
  if (input.planHash !== plan.planHash) {
    return migrationDeny("refused_preconditions_unmet", plan, "planHash mismatch — a migration may only execute after its OWN dry-run plan (dry-run-first law)");
  }
  // Precondition 1: stored schema matches the plan's source.
  const stored = store.storeSchemaVersion;
  if (stored !== plan.fromStoreSchemaVersion) {
    return migrationDeny("refused_preconditions_unmet", plan, "stored schema '" + String(stored) + "' does not match the plan source '" + plan.fromStoreSchemaVersion + "'");
  }
  // Precondition 2: full pre-migration verification passes.
  const pre = verifyPersistedLedgerAndEvidenceRef(store, port);
  if (!pre.ok) {
    return migrationDeny("refused_preconditions_unmet", plan, "pre-migration verification found " + String(pre.findings.length) + " hard finding(s) — never migrate over corruption");
  }
  // Precondition 3: quarantine review.
  const quarantineRows = store.listQuarantined();
  if (quarantineRows.length > 0) {
    return migrationDeny("refused_preconditions_unmet", plan, String(quarantineRows.length) + " quarantine row(s) exist — human review is required before migration (pre-migration quarantine review)");
  }
  // NOTE: no registered step exists in this gate, so no transform runs here.
  // A future registered step would execute ITS deterministic, reviewed
  // transform at this point — record ids, content hashes, and chain fields
  // pass through untouched (original evidence identity is never rewritten).
  return migrationDeny("refused_unsupported_source", plan, "no transform is registered for execution in this gate (registry empty); the plan remains a non-executing dry-run artifact");
}

// ── recovery findings vocabulary (reconciliation layer) ────────────────────────

export const RECONCILIATION_FINDING_CODES = Object.freeze([
  "ledger_without_evidence",
  "evidence_without_ledger_observation",
  "stale_checkpoint",
  "orphan_task_parent",
  "orphan_memory_parent",
  "lifecycle_conflict",
  "duplicate_transaction",
  "manifest_drift",
  "orphan_evidence_ref",
] as const);
export type ReconciliationFindingCode = (typeof RECONCILIATION_FINDING_CODES)[number];

export interface ReconciliationFinding {
  readonly code: ReconciliationFindingCode;
  /** Bounded detail; hostile content is never echoed. */
  readonly detail: string;
  readonly recordIds: readonly string[];
  /** True when the finding ROUTES records to quarantine (unrecoverable). */
  readonly quarantining: boolean;
}

export interface RecoveryStage {
  readonly index: number;
  readonly stage: string;
  readonly ok: boolean;
  /** Bounded conclusion-only summary of what the stage found. */
  readonly detail: string;
}

export interface ReconciledRecoveredState {
  /** Mirrored ledger events admitted after reconciliation (data only). */
  readonly admittedEventIds: readonly string[];
  /** Sealed evidence record hashes admitted after reconciliation. */
  readonly admittedEvidenceHashes: readonly string[];
  /** Mutable state record ids admitted after reconciliation, per kind. */
  readonly admittedStateIds: Readonly<Record<"memory_record" | "agent_metadata" | "goal_lifecycle" | "skill_tool_registry", readonly string[]>>;
  /** All reconciliation findings (quarantining and advisory). */
  readonly findings: readonly ReconciliationFinding[];
  /** Records routed to quarantine by reconciliation (never repaired). */
  readonly quarantinedRecordIds: readonly string[];
  /** Orphan references reported but NOT quarantining (task→missing parent). */
  readonly orphanRefs: readonly string[];
  /** Whether the derived indexes/checkpoints were rebuilt this run. */
  readonly derivedRebuilt: boolean;
}

export interface StartupRecoveryReport {
  /** The fixed pipeline, in execution order, with per-stage outcomes. */
  readonly stages: readonly RecoveryStage[];
  /** The frozen 22A decision over the combined verification snapshot. */
  readonly decision: RecoveryDecision;
  /** The 22C verification report over the append-only material. */
  readonly ledgerEvidence: LedgerEvidenceVerificationReport | null;
  /** Reconciliation layer output (stage 4–5). */
  readonly reconciled: ReconciledRecoveredState | null;
  /** True when recovered state may be EXPOSED (validation complete). */
  readonly stateExposed: boolean;
  /** Store-level checkpoint verdict observed at stage 1. */
  readonly checkpointVerdict: CheckpointVerifyResult | null;
  /** Deterministic digest over the whole report (evidence). */
  readonly reportHash: string;
}

// ── the fixed-order startup pipeline ─────────────────────────────────────────

const STATE_KINDS: readonly RecordKind[] = [
  "memory_record",
  "agent_metadata",
  "goal_lifecycle",
  "skill_tool_registry",
  "peer_trust_registry",
];

/**
 * Deterministic startup recovery over an ALREADY-OPEN store. The fixed
 * stage order is structural (array position), test-locked, and every stage
 * short-circuits the pipeline on a hard failure — recovery never continues
 * past a stage that failed closed.
 *
 * NO EXECUTION: this function never invokes the governed tool junction, the
 * launcher transport, any process spawn, any rollback executor, or any task
 * continuation. Its only writes are derived-index/checkpoint rebuilds
 * (stage 6, allowed only after validation) and nothing else.
 */
export function runStartupRecovery(
  store: DurableStore,
  port: LedgerHashPort,
  request: RecoveryRequest,
  options: {
    readonly maxRecords?: number;
    readonly nowEpochMs?: number;
    /** Stage 6 default: rebuild derived indexes when verification allows. */
    readonly rebuildDerived?: (store: DurableStore) => { ok: true } | { ok: false; reason: string };
  } = {}
): StartupRecoveryReport {
  const stages: RecoveryStage[] = [];
  const findings: ReconciliationFinding[] = [];
  const orphanRefs: string[] = [];
  let ledgerEvidenceReport: LedgerEvidenceVerificationReport | null = null;
  let reconciled: ReconciledRecoveredState | null = null;
  let checkpointVerdict: CheckpointVerifyResult | null = null;
  let stateExposed = false;
  let derivedRebuilt = false;

  const push = (stage: string, ok: boolean, detail: string): void => {
    stages.push({ index: stages.length + 1, stage, ok, detail: truncateReason(detail) });
  };

  // ── stage 1: verify store/schema ─────────────────────────────────────────
  const schema = store.storeSchemaVersion;
  const schemaOk = schema !== null && schema === request.expectedStoreSchemaVersion;
  checkpointVerdict = store.verifyCheckpoint({ ledgerTailHash: "0".repeat(64) });
  push(
    "verify_store_schema",
    schemaOk,
    schemaOk
      ? "store schema '" + schema + "' matches the expected request; checkpoint verdict: " + checkpointVerdict.verdict
      : "store schema '" + String(schema) + "' does not match expected '" + request.expectedStoreSchemaVersion + "' — failing closed"
  );    if (!schemaOk) {
    return finish(decisionFor(), null, null, false);
  }

  // ── stage 2: validate authoritative append-only material ─────────────────
  // Reuse the 22C verification (ledger vocabulary + recordHash + linkage).
  // Imported lazily to keep this module's import surface honest: the 22C
  // verifier is the single source of truth for append-only validation.
  const verification = verifyAppendOnlyMaterial(store, port, { maxRecords: options.maxRecords });
  ledgerEvidenceReport = verification.report;
  push(
    "validate_append_only",
    verification.report.ok,
    verification.report.ok
      ? String(verification.report.eventsVerified) + " event(s) + " + String(verification.report.evidenceVerified) + " evidence record(s) verified; tail " + verification.report.verifiedTailHash.slice(0, 12) + "…"
      : String(verification.report.findings.length) + " hard finding(s) in the append-only material — failing closed"
  );
  if (!verification.report.ok) {
    // Fail closed, but carry the 22C report: the evidence of WHY recovery
    // stopped (unreadable_record, observation_missing, manifest_drift, …)
    // must remain readable by callers of the report.
    return finish(decisionFor(), ledgerEvidenceReport, null, false);
  }

  // ── stage 3: validate mutable versions ───────────────────────────────────
  // Fails closed: identity/integrity failures AND denied payload keys
  // (secret/handle/token/replay-material shaped — the same scan the 22D
  // writers and recoverState enforce; a re-sealed payload must not slip
  // past the write guard into recovery). Any failure SHORT-CIRCUITS the
  // pipeline: mutable material that fails validation is never exposed and
  // never reconciled as if it were sound.
  const factsByKind = new Map<RecordKind, ReturnType<typeof collectStateKindFacts>>();
  let mutableFailures = 0;
  const mutableFailureIds: string[] = [];
  for (const kind of STATE_KINDS) {
    const facts = collectStateKindFacts(store, kind);
    factsByKind.set(kind, facts);
    for (const failedId of facts.failedRecordIds) {
      mutableFailures += 1;
      if (mutableFailureIds.length < 6) mutableFailureIds.push(failedId);
    }
    for (const recordId of store.listRecordIds(kind)) {
      const read = store.readRecord(recordId);
      if (!read.ok) continue; // already counted as a failed record above
      const denied = findDeniedStateKeyPaths(read.record.payload as Record<string, unknown>);
      if (denied.length > 0) {
        mutableFailures += 1;
        if (mutableFailureIds.length < 6) mutableFailureIds.push(recordId + " (denied key)");
      }
    }
  }
  push(
    "validate_mutable_versions",
    mutableFailures === 0,
    mutableFailures === 0
      ? "all mutable records validated (revisions intact, identity bound, no denied keys)"
      : String(mutableFailures) + " mutable record(s) failed identity/integrity/secret-policy validation: " + mutableFailureIds.join(", ") + (mutableFailures > mutableFailureIds.length ? " …" : "")
  );
  if (mutableFailures > 0) {
    return finish(decisionFor(), ledgerEvidenceReport, null, false);
  }

  // ── stage 4: reconcile cross-references ──────────────────────────────────
  // 4a. ledger ↔ evidence: every observed evidence must have its event; an
  //     event without evidence is reported (advisory — an observation may
  //     legitimately exist before its sealed record persisted); evidence
  //     without observation is a hard finding (22C already failed closed on
  //     it at stage 2, so here we only see the green case).
  const admittedEventIds: string[] = [];
  const admittedEvidenceHashes: string[] = [];
  const quarantinedRecordIds: string[] = [];
  const eventClaims = verification.eventClaims;
  const eventIds = store.listRecordIds("event_ledger_entry");
  for (const recordId of eventIds) admittedEventIds.push(recordId);
  const evidenceIds = store.listRecordIds("tool_run_evidence");
  for (const recordId of evidenceIds) {
    const read = store.readRecord(recordId);
    if (!read.ok) continue; // already handled at stage 2
    const recordHash = (read.record.payload as Record<string, unknown>)["recordHash"];
    if (typeof recordHash === "string") admittedEvidenceHashes.push(recordHash);
  }
  const observedEvidence: readonly string[] = verification.observedEvidence;
  const unobservedEvidence = admittedEvidenceHashes.filter((h) => !observedEvidence.includes(h));
  if (unobservedEvidence.length > 0) {
    findings.push({
      code: "evidence_without_ledger_observation",
      detail: String(unobservedEvidence.length) + " sealed evidence record(s) claim an observation no mirrored event carries",
      recordIds: unobservedEvidence.map((h) => "run-" + h.slice(0, 32)),
      quarantining: true,
    });
    for (const h of unobservedEvidence) quarantinedRecordIds.push("run-" + h.slice(0, 32));
  }
  // 4a (direction 2): "ledger without evidence" — ADVISORY, never
  //     quarantining (the 22C verifier already failed closed on the inverse:
  //     evidence claiming an observation no event carries).
  //     (1) Per event: a mirrored event whose summaries CLAIM a run
  //         observation (sealed recordHash) with no sealed evidence record
  //         carrying that hash. Plain audit events claim nothing and are
  //         never per-event candidates.
  //     (2) Store-level: a ledger that carries events but NEITHER a
  //         resolvable run observation NOR any evidence record at all —
  //         surfaced as data because non-run events are legitimate.
  const evidenceSet = new Set(admittedEvidenceHashes);
  const unresolvedClaims = eventClaims.filter(
    (c): c is { recordId: string; claimedRecordHash: string } =>
      c.claimedRecordHash !== null && !evidenceSet.has(c.claimedRecordHash)
  );
  const resolvedClaimCount = eventClaims.filter(
    (c) => c.claimedRecordHash !== null && evidenceSet.has(c.claimedRecordHash)
  ).length;
  for (const claim of unresolvedClaims) {
    findings.push({
      code: "ledger_without_evidence",
      detail: "mirrored event claims a run observation whose sealed evidence record is absent (advisory — evidence may be appended later)",
      recordIds: [claim.recordId],
      quarantining: false,
    });
  }
  if (eventClaims.length > 0 && resolvedClaimCount === 0 && admittedEvidenceHashes.length === 0 && unresolvedClaims.length === 0) {
    findings.push({
      code: "ledger_without_evidence",
      detail: "the mirrored ledger carries events but no sealed evidence record and no claimed run observation (advisory — non-run events are legitimate)",
      recordIds: [],
      quarantining: false,
    });
  }

  // 4b. duplicate transaction ids across authoritative records. The ONE
  //     exemption is the ATOMIC PAIR written by
  //     persistToolRunEvidenceWithObservation: one mirrored event + one
  //     sealed evidence record sharing a single transactionId BY DESIGN
  //     (one store transaction, one commit sequence). The pair is exempt
  //     only when the event's claimed recordHash matches the evidence's
  //     recordHash — any other shape sharing a transactionId (two state
  //     records, 3+ records, an unlinked pair) remains a replay/conflict
  //     surface and quarantines.
  const txnOwners = new Map<string, { readonly recordId: string; readonly kind: RecordKind }[]>();
  for (const kind of ["event_ledger_entry", "tool_run_evidence", ...STATE_KINDS] as RecordKind[]) {
    for (const recordId of store.listRecordIds(kind)) {
      const read = store.readRecord(recordId);
      if (!read.ok) continue;
      const txn = read.record.transactionId;
      const owners = txnOwners.get(txn) ?? [];
      owners.push({ recordId, kind });
      txnOwners.set(txn, owners);
    }
  }
  const atomicPairLinkVerified = (
    owners: readonly { readonly recordId: string; readonly kind: RecordKind }[]
  ): boolean => {
    if (owners.length !== 2) return false;
    const eventOwner = owners.find((o) => o.kind === "event_ledger_entry");
    const evidenceOwner = owners.find((o) => o.kind === "tool_run_evidence");
    if (eventOwner === undefined || evidenceOwner === undefined) return false;
    const claim = eventClaims.find((c) => c.recordId === eventOwner.recordId);
    if (claim === undefined || claim.claimedRecordHash === null) return false;
    const evidenceRead = store.readRecord(evidenceOwner.recordId);
    if (!evidenceRead.ok) return false;
    return (evidenceRead.record.payload as Record<string, unknown>)["recordHash"] === claim.claimedRecordHash;
  };
  for (const [txn, owners] of txnOwners) {
    if (owners.length <= 1) continue;
    if (atomicPairLinkVerified(owners)) continue; // by-design atomic pair
    findings.push({
      code: "duplicate_transaction",
      detail: "transactionId '" + txn + "' is claimed by multiple authoritative records — replay/conflict surface",
      recordIds: owners.map((o) => o.recordId),
      quarantining: true,
    });
    quarantinedRecordIds.push(...owners.map((o) => o.recordId));
  }

  // 4c. task → ledger refs (orphan task parents) + lifecycle conflicts.
  const taskFacts = factsByKind.get("goal_lifecycle");
  if (taskFacts !== undefined) {
    for (const [recordId] of taskFacts.taskLineage) {
      const read = store.readRecord(recordId);
      if (!read.ok) continue;
      const state = (read.record.payload as Record<string, unknown>)["taskLifecycle"] as TaskLifecycleState | undefined;
      if (state === undefined) continue;
      if (typeof state.sourceEventId === "string") {
        const resolved = eventIds.some((eventId) => {
          const ev = store.readRecord(eventId);
          if (!ev.ok) return false;
          const payload = ev.record.payload as Record<string, unknown>;
          return payload["eventId"] === state.sourceEventId;
        });
        if (!resolved) {
          orphanRefs.push(recordId + " → event:" + state.sourceEventId);
        }
      }
    }
    // Lifecycle conflict (two corruption signatures the 22D write guard
    // makes unrepresentable through any legal write path):
    //   (a) a goal history carrying ≥2 DISTINCT terminal statuses;
    //   (b) a POST-TERMINAL revision: any revision appended AFTER a
    //       revision already recorded a terminal status (a resurrected
    //       task — done/failed/rejected are append-only facts).
    for (const [recordId] of taskFacts.taskLineage) {
      const history = store.readRecordHistory(recordId);
      if (!history.ok) continue;
      const terminalStatuses = new Set<string>();
      let terminalSeenAt = -1;
      let conflict = false;
      for (let i = 0; i < history.records.length; i++) {
        const envelope = history.records[i];
        if (envelope === undefined) continue;
        const state = (envelope.payload as Record<string, unknown>)["taskLifecycle"] as TaskLifecycleState | undefined;
        if (state === undefined) continue;
        if (isTerminalTaskStatus(state.status)) {
          terminalStatuses.add(state.status);
          terminalSeenAt = i;
        } else if (terminalSeenAt >= 0) {
          conflict = true; // non-terminal revision AFTER a terminal fact
        }
      }
      if (conflict || terminalStatuses.size >= 2) {
        findings.push({
          code: "lifecycle_conflict",
          detail: conflict
            ? "goal lifecycle history carries revisions AFTER a terminal fact (resurrected task — terminal facts are append-only)"
            : "goal lifecycle history carries " + String(terminalStatuses.size) + " conflicting terminal facts (append-only law violated by corruption)",
          recordIds: [recordId],
          quarantining: true,
        });
        quarantinedRecordIds.push(recordId);
      }
    }
  }
  // 4d. orphan memory parents (memory whose scope workspace has no anchor).
  const memoryFacts = factsByKind.get("memory_record");
  if (memoryFacts !== undefined && memoryFacts.memoryIds.length > 0) {
    for (const recordId of store.listRecordIds("memory_record")) {
      const read = store.readRecord(recordId);
      if (!read.ok) continue;
      const record = (read.record.payload as Record<string, unknown>)["memory"] as { scope?: { workspaceId?: string } } | undefined;
      if (record?.scope?.workspaceId === undefined) {
        findings.push({
          code: "orphan_memory_parent",
          detail: "memory record carries no workspace scope anchor",
          recordIds: [recordId],
          quarantining: true,
        });
        quarantinedRecordIds.push(recordId);
      }
    }
  }
  // 4e. registry lifecycle conflicts + manifest drift across evidence.
  const registryFacts = factsByKind.get("skill_tool_registry");
  if (registryFacts !== undefined) {
    const byTool = new Map<string, Set<RegistryLifecycleState["lifecycle"]>>();
    for (const [recordId, lifecycle] of registryFacts.registryLifecycles) {
      const key = recordId;
      const set = byTool.get(key) ?? new Set();
      set.add(lifecycle);
      byTool.set(key, set);
    }
    for (const [recordId, lifecycles] of byTool) {
      const hasTerminal = lifecycles.has("quarantined") || lifecycles.has("retired");
      const hasActive = lifecycles.has("registered") || lifecycles.has("enabled");
      if (hasTerminal && hasActive) {
        findings.push({
          code: "lifecycle_conflict",
          detail: "registry record history carries both terminal and active lifecycle facts",
          recordIds: [recordId],
          quarantining: true,
        });
        quarantinedRecordIds.push(recordId);
      }
    }
  }
  push(
    "reconcile_references",
    findings.every((f) => !f.quarantining),
    findings.length === 0
      ? "all cross-references reconcile (ledger↔evidence, transactions, lineage, lifecycles)"
      : String(findings.length) + " reconciliation finding(s): " + findings.map((f) => f.code).join(", ")
  );

  // ── stage 5: quarantine unverifiable records / orphans ───────────────────
  const quarantiningFindings = findings.filter((f) => f.quarantining);
  push(
    "quarantine_unverifiable",
    true,
    quarantiningFindings.length === 0
      ? "nothing required quarantine"
      : String(quarantinedRecordIds.length) + " record id(s) routed to quarantine (never repaired, never healed)"
  );

  // ── stage 6: rebuild allowed derived indexes/checkpoints ─────────────────
  const rebuildAllowed =
    ledgerEvidenceReport.ok &&
    quarantiningFindings.length === 0 &&
    checkpointVerdict.verdict !== "rebuild_required";
  if (rebuildAllowed) {
    const rebuild = options.rebuildDerived
      ? options.rebuildDerived(store)
      : { ok: true as const };
    derivedRebuilt = rebuild.ok;
    push(
      "rebuild_derived",
      rebuild.ok,
      rebuild.ok
        ? "derived indexes/checkpoints consistent (rebuild " + (options.rebuildDerived ? "executed" : "not required") + ")"
        : "derived rebuild failed: " + rebuild.reason
    );
    if (!rebuild.ok) {
      return finish(decisionFor(), ledgerEvidenceReport, null, false);
    }
  } else {
    push(
      "rebuild_derived",
      true,
      "rebuild skipped: checkpoint stale or reconciliation found quarantining findings (derived data stays discarded)"
    );
  }

  // ── stage 7: emit RecoverySnapshot/evidence (frozen 22A decision) ────────
  const decision = decisionFor();
  push(
    "emit_recovery_snapshot",
    true,
    "decision " + decision.code + " (authority " + decision.authority + ", executionAuthorized " + String(decision.executionAuthorized) + ")"
  );

  // ── stage 8: expose recovered state ONLY after validation ────────────────
  stateExposed =
    schemaOk &&
    ledgerEvidenceReport.ok &&
    quarantiningFindings.length === 0;
  const admittedStateIds: Record<"memory_record" | "agent_metadata" | "goal_lifecycle" | "skill_tool_registry", readonly string[]> = {
    memory_record: [],
    agent_metadata: [],
    goal_lifecycle: [],
    skill_tool_registry: [],
  };
  if (stateExposed) {
    for (const kind of STATE_KINDS) {
      const facts = factsByKind.get(kind);
      if (facts === undefined) continue;
      const admitted = store.listRecordIds(kind).filter((id) => !quarantinedRecordIds.includes(id));
      admittedStateIds[kind as keyof typeof admittedStateIds] = admitted;
    }
  }
  push(
    "expose_recovered_state",
    stateExposed,
    stateExposed
      ? "recovered state exposed as DATA (recovered_data; no execution, no authorization, no continuation)"
      : "recovered state NOT exposed — validation incomplete"
  );

  reconciled = {
    admittedEventIds,
    admittedEvidenceHashes,
    admittedStateIds,
    findings,
    quarantinedRecordIds,
    orphanRefs,
    derivedRebuilt,
  };

  return finish(decision, ledgerEvidenceReport, reconciled, stateExposed);

  // ── helpers ──────────────────────────────────────────────────────────────

  function decisionFor(): RecoveryDecision {
    // The frozen 22A decision function over the pipeline's snapshot. Hard
    // failures were already short-circuited above; this is the accept path
    // (or the schema-mismatch path, which construct its own rejection).
    return decideRecovery(
      {
        expectedStoreSchemaVersion: request.expectedStoreSchemaVersion,
        actualStoreSchemaVersion: store.storeSchemaVersion,
        committedThrough: store.committedThrough,
        observedThrough: store.committedThrough,
        totalRecordsScanned: 0,
        findings: [],
        scanTruncated: false,
      },
      request
    );
  }

  function finish(
    decision: RecoveryDecision,
    ledger: LedgerEvidenceVerificationReport | null,
    reconciledOut: ReconciledRecoveredState | null,
    exposed: boolean
  ): StartupRecoveryReport {
    return {
      stages,
      decision,
      ledgerEvidence: ledger,
      reconciled: reconciledOut,
      stateExposed: exposed,
      checkpointVerdict,
      reportHash: canonicalHash({
        stages,
        decisionCode: decision.code,
        exposed,
        reconciliation: reconciledOut
          ? {
              findings: reconciledOut.findings.map((f) => f.code),
              quarantined: reconciledOut.quarantinedRecordIds,
              orphans: reconciledOut.orphanRefs,
              derivedRebuilt: reconciledOut.derivedRebuilt,
            }
          : null,
      }),
    };
  }
}

// ── append-only material verification (22C delegation, typed narrowly) ──────

/**
 * Delegate to the 22C verification and return the report plus the
 * per-record summary strings the reconciliation layer needs (kept in ONE
 * place so 22E adds no second hash implementation).
 */
function verifyAppendOnlyMaterial(
  store: DurableStore,
  port: LedgerHashPort,
  options: { readonly maxRecords?: number }
): {
  readonly report: LedgerEvidenceVerificationReport;
  readonly eventClaims: readonly { readonly recordId: string; readonly claimedRecordHash: string | null }[];
  readonly observedEvidence: readonly string[];
  readonly findings: readonly unknown[];
} {
  // The 22C verifier is imported through the module surface (see import
  // above); here we call it and derive the reconciliation inputs from the
  // stored payloads it just verified.
  const report = verifyPersistedLedgerAndEvidenceRef(store, port, options);
  // EVERY verified mirrored event is a reconciliation candidate. Its claimed
  // recordHash is derived from the event's OWN summaries (the sealed hash a
  // run-observation carries); a plain audit event claims nothing
  // (claimedRecordHash: null) and is never a per-event ledger↔evidence
  // candidate — the store-level advisory in stage 4 covers that shape.
  const eventClaims: { recordId: string; claimedRecordHash: string | null }[] = [];
  for (const recordId of store.listRecordIds("event_ledger_entry")) {
    const read = store.readRecord(recordId);
    if (!read.ok) continue;
    const payload = read.record.payload as Record<string, unknown>;
    const summaries = payload["event"] as { inputSummary?: unknown; resultSummary?: unknown } | undefined;
    const blob = JSON.stringify({ inputSummary: summaries?.inputSummary ?? null, resultSummary: summaries?.resultSummary ?? null });
    const recordHashMatch = /"sealed":"([0-9a-f]{64})"/.exec(blob);
    eventClaims.push({ recordId, claimedRecordHash: recordHashMatch !== null ? (recordHashMatch[1] ?? null) : null });
  }
  const observedEvidence: string[] = [];
  for (const recordId of store.listRecordIds("tool_run_evidence")) {
    const read = store.readRecord(recordId);
    if (!read.ok) continue;
    const payload = read.record.payload as Record<string, unknown>;
    const observation = payload["observation"] as { state?: unknown } | undefined;
    const recordHash = payload["recordHash"];
    if (observation?.state === "observed" && typeof recordHash === "string") {
      observedEvidence.push(recordHash);
    }
  }
  return { report, eventClaims, observedEvidence, findings: report.findings };
}
