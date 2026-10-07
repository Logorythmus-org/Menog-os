/**
 * PHASE 23D — Recovery Bootstrap → Live Runtime Handoff
 * (STARTUP INTEGRATION / AUTHORITY SEPARATION).
 *
 * The explicit, evidenced startup pipeline over the 23A machine:
 *
 *   BOOTING → RECOVERING → RECONCILED → READY → LIVE   (or → RECOVERED)
 *
 * Order is total and fail-closed:
 *   1. RECOVERING: the frozen Phase-22 recovery runs FIRST (`recoverState`
 *      over the 22D adapters). Nothing live exists yet.
 *   2. RECONCILED: findings are classified. HARD findings (rejected_*
 *      decision codes) and QUARANTINE findings (records this recovery
 *      quarantined, and records already quarantined in the store) BLOCK
 *      LIVE — the pipeline terminates in RECOVERED. Interrupted tasks are
 *      reported as FACTS and never resumed: a fresh caller action must
 *      traverse the normal authority chain (Planner → Allocation → Policy
 *      → Isolation → Governed Tool Runtime). This module offers no resume
 *      path at all.
 *   3. A NEW runtime epoch is admitted (never the BOOTING epoch id). The
 *      durable live-owner claim is superseded BY EVIDENCE
 *      (`transferOwnershipEvidenced`) — the claim must belong to the
 *      explicitly named prior epoch, and the justification carries the
 *      recovery report hash. This is the ONLY sanctioned path by which a
 *      new epoch acquires a claim held by another id; split-brain refusal
 *      remains the law everywhere else.
 *   4. READY: safe views are reconstructed ONLY from admitted data (the
 *      23C wiring is opened on the new epoch's coordinator).
 *   5. LIVE is granted ONLY on verified deterministic handoff evidence
 *      binding recoveryReportHash → new epoch → admitted-state summary.
 *
 * Never reactivated: recovered Policy decisions, allocations, capabilities,
 * approvals, process state. The pipeline grants NOTHING — it moves the
 * lifecycle machine and records evidence; every authority gate stays
 * downstream in the frozen Phase-20/21/22 chain.
 */

import type {
  RecordKind,
} from "./records.js";
import {
  DurableStore,
} from "./store.js";
import type {
  RuntimeEpoch,
  RuntimeEpochId,
} from "./continuity.js";
import {
  RUNTIME_EPOCH_ID_PATTERN,
  advanceLifecycle,
  decideRecoveryBootstrap,
} from "./continuity.js";
import type {
  RecoveryRequest,
} from "./recovery.js";
import {
  readRuntimeOwnership,
  RuntimeStateCoordinator,
} from "./coordinator.js";
import {
  canonicalHash,
} from "./canonical.js";
import type {
  StateRecoveryResult,
} from "./statePersistence.js";
import {
  recoverState,
} from "./statePersistence.js";
import {
  LiveSurfaceWiring,
} from "./surfaceWiring.js";

// ── schema version ───────────────────────────────────────────────────────────

/** Handoff contract version: bumped when THIS vocabulary changes. */
export const HANDOFF_SCHEMA_VERSION = "menog-runtime-handoff/v0" as const;
export type HandoffSchemaVersion = typeof HANDOFF_SCHEMA_VERSION;

// ── recovery report (deterministic; content-addressed) ───────────────────────

/** One per-record finding line (bounded; no record content is echoed). */
export interface RecoveryFindingLine {
  readonly recordId: string;
  readonly recordKind: string;
  readonly integrityStatus: string;
  readonly cause: string | null;
  readonly alreadyQuarantined: boolean;
}

/**
 * The ONE canonical recovery report for a handoff: the frozen 22D/22E
 * `recoverState` output plus the read-only surface scan (already-quarantined
 * records, interrupted tasks as FACTS). Every field is an input, never a
 * wall-clock read — the report hash is deterministic.
 */
export interface RecoveryReport {
  readonly schemaVersion: HandoffSchemaVersion;
  readonly request: RecoveryRequest;
  readonly decision: StateRecoveryResult["decision"];
  readonly admittedByKind: Readonly<Record<RecordKind, number>>;
  /** Records THIS recovery routed to quarantine (integrity failures). */
  readonly newQuarantineIds: readonly string[];
  /** Records already isolated in the store's quarantine (prior facts). */
  readonly alreadyQuarantinedIds: readonly string[];
  readonly expiredMemoryIds: readonly string[];
  readonly terminalRegistryIds: readonly string[];
  /** Interrupted tasks: reported, NEVER resumed. */
  readonly interruptedTaskIds: readonly string[];
  readonly derivedRebuildRequired: boolean;
  readonly scannedAtEpochMs: number;
}

/**
 * Read-only surface scan: which records are already quarantined (unreadable
 * through the 22B verification path) and which goal/task lifecycles are
 * interrupted FACTS. Nothing is repaired, resumed, or resurrected here.
 */
function scanStateSurface(store: DurableStore): {
  readonly alreadyQuarantinedIds: readonly string[];
  readonly interruptedTaskIds: readonly string[];
} {
  const alreadyQuarantinedIds: string[] = [];
  const interruptedTaskIds: string[] = [];
  if (!store.isOpen) {
    return { alreadyQuarantinedIds: Object.freeze(alreadyQuarantinedIds), interruptedTaskIds: Object.freeze(interruptedTaskIds) };
  }
  const kinds: readonly RecordKind[] = ["memory_record", "agent_metadata", "goal_lifecycle", "skill_tool_registry"];
  for (const kind of kinds) {
    for (const recordId of store.listRecordIds(kind)) {
      const read = store.readRecord(recordId);
      if (!read.ok) {
        alreadyQuarantinedIds.push(recordId);
        continue;
      }
      if (kind === "goal_lifecycle") {
        const parsed = (read.record.payload as Record<string, unknown>)["taskLifecycle"];
        if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
          const state = parsed as { status: string; goalId: string };
          if (state.status === "interrupted") interruptedTaskIds.push(state.goalId);
        }
      }
    }
  }
  return {
    alreadyQuarantinedIds: Object.freeze(alreadyQuarantinedIds),
    interruptedTaskIds: Object.freeze(interruptedTaskIds),
  };
}

/**
 * The ONE canonical recovery report: frozen 22D/22E recovery FIRST, then
 * the read-only surface scan. No wall-clock input beyond `nowEpochMs`.
 */
export function buildRecoveryReport(
  store: DurableStore,
  request: RecoveryRequest,
  nowEpochMs: number
): RecoveryReport {
  const recovered = recoverState(store, request, { nowEpochMs });
  const surface = scanStateSurface(store);
  return {
    schemaVersion: HANDOFF_SCHEMA_VERSION,
    request,
    decision: recovered.decision,
    admittedByKind: recovered.admittedByKind,
    newQuarantineIds: recovered.decision.quarantinedRecordIds,
    alreadyQuarantinedIds: surface.alreadyQuarantinedIds,
    expiredMemoryIds: recovered.expiredMemoryIds,
    terminalRegistryIds: recovered.terminalRegistryIds,
    interruptedTaskIds: surface.interruptedTaskIds,
    derivedRebuildRequired: recovered.derivedRebuildRequired,
    scannedAtEpochMs: nowEpochMs,
  };
}

/** Deterministic hash over the report's full content (no wall-clock). */
export function recoveryReportHash(report: RecoveryReport): string {
  return canonicalHash({
    schemaVersion: report.schemaVersion,
    request: report.request,
    decision: report.decision,
    admittedByKind: report.admittedByKind,
    newQuarantineIds: report.newQuarantineIds,
    alreadyQuarantinedIds: report.alreadyQuarantinedIds,
    expiredMemoryIds: report.expiredMemoryIds,
    terminalRegistryIds: report.terminalRegistryIds,
    interruptedTaskIds: report.interruptedTaskIds,
    derivedRebuildRequired: report.derivedRebuildRequired,
    scannedAtEpochMs: report.scannedAtEpochMs,
  });
}

// ── classification (hard / quarantine block LIVE; expiry does not) ───────────

export type HandoffBlockingClass = "hard" | "quarantine" | "none";

export interface FindingClassification {
  readonly blockingClass: HandoffBlockingClass;
  readonly newQuarantineCount: number;
  readonly alreadyQuarantinedCount: number;
  readonly expiredMemoryCount: number;
  readonly explanation: string;
}

const HARD_DECISION_CODES: readonly string[] = Object.freeze([
  "rejected_schema_mismatch",
  "rejected_unverifiable",
  "rejected_scan_bound",
]);

/**
 * Classify the report (closed mapping): any rejected_* decision → `hard`;
 * ANY quarantine finding (new OR already-isolated) → `quarantine` (LIVE is
 * blocked — quarantine is never silently absorbed); only expired memory →
 * does NOT block (retention exclusion, the frozen 22D law).
 */
export function classifyRecoveryReport(report: RecoveryReport): FindingClassification {
  if (HARD_DECISION_CODES.includes(report.decision.code)) {
    return {
      blockingClass: "hard",
      newQuarantineCount: 0,
      alreadyQuarantinedCount: 0,
      expiredMemoryCount: 0,
      explanation: "recovery rejected ('" + report.decision.code + "') — LIVE is blocked",
    };
  }
  if (report.newQuarantineIds.length > 0 || report.alreadyQuarantinedIds.length > 0) {
    return {
      blockingClass: "quarantine",
      newQuarantineCount: report.newQuarantineIds.length,
      alreadyQuarantinedCount: report.alreadyQuarantinedIds.length,
      expiredMemoryCount: 0,
      explanation:
        String(report.newQuarantineIds.length) + " new quarantine finding(s) and " +
        String(report.alreadyQuarantinedIds.length) + " already-quarantined record(s) block LIVE" +
        " (quarantine is never silently absorbed)",
    };
  }
  return {
    blockingClass: "none",
    newQuarantineCount: 0,
    alreadyQuarantinedCount: 0,
    expiredMemoryCount: report.expiredMemoryIds.length,
    explanation:
      report.expiredMemoryIds.length > 0
        ? String(report.expiredMemoryIds.length) + " expired ephemeral memory id(s) excluded from admission (retention, not corruption — does not block)"
        : "no blocking findings — the recovery report is clean",
  };
}

// ── handoff evidence (deterministic; NO wall-clock in the hashed body) ───────

export interface HandoffEvidenceBody {
  readonly schemaVersion: HandoffSchemaVersion;
  readonly recoveryReportHash: string;
  readonly newEpochId: RuntimeEpochId;
  readonly priorEpochId: RuntimeEpochId | null;
  /** Deterministic summary: sorted "kind=count" pairs (or "empty"). */
  readonly admittedStateSummary: string;
  readonly admittedByKind: Readonly<Record<string, number>>;
  readonly interruptedTaskIds: readonly string[];
  readonly terminalRegistryIds: readonly string[];
  readonly expiredMemoryIds: readonly string[];
  /** ALWAYS false — evidence moves the machine; it grants nothing. */
  readonly grantsAuthority: false;
  /** ALWAYS "no_auto_resume" — interrupted tasks stay interrupted. */
  readonly resumeSemantics: "no_auto_resume";
  /** ALWAYS the frozen chain — fresh execution must traverse it. */
  readonly executionPathRequirement: "planner_allocation_policy_isolation_governed_tool_runtime";
}

export interface HandoffEvidence extends HandoffEvidenceBody {
  readonly evidenceHash: string;
}

/**
 * Deterministically build the handoff evidence binding
 * recoveryReportHash → new epoch → admitted-state summary. The hash is the
 * canonical sha256 over the body; the body contains NO wall-clock field, so
 * identical inputs rebuild the identical hash byte-for-byte.
 */
export function buildHandoffEvidence(input: {
  readonly recoveryReport: RecoveryReport;
  readonly newEpochId: RuntimeEpochId;
  readonly priorEpochId: RuntimeEpochId | null;
}): HandoffEvidence {
  const summaryParts = Object.keys(input.recoveryReport.admittedByKind)
    .sort()
    .map((k) => k + "=" + String(input.recoveryReport.admittedByKind[k as RecordKind]));
  const body: HandoffEvidenceBody = {
    schemaVersion: HANDOFF_SCHEMA_VERSION,
    recoveryReportHash: recoveryReportHash(input.recoveryReport),
    newEpochId: input.newEpochId,
    priorEpochId: input.priorEpochId,
    admittedStateSummary: summaryParts.length > 0 ? summaryParts.join(",") : "empty",
    admittedByKind: { ...input.recoveryReport.admittedByKind },
    interruptedTaskIds: input.recoveryReport.interruptedTaskIds,
    terminalRegistryIds: input.recoveryReport.terminalRegistryIds,
    expiredMemoryIds: input.recoveryReport.expiredMemoryIds,
    grantsAuthority: false,
    resumeSemantics: "no_auto_resume",
    executionPathRequirement: "planner_allocation_policy_isolation_governed_tool_runtime",
  };
  return { ...body, evidenceHash: canonicalHash(body) };
}

/**
 * Verify claimed handoff evidence against the ACTUAL recovery report and
 * the new epoch. Deterministic: identical inputs → identical hash; ANY
 * drift (report, epoch, admitted summary, or semantics tampering) refuses.
 */
export function verifyHandoffEvidence(input: {
  readonly claimed: HandoffEvidence;
  readonly recoveryReport: RecoveryReport;
  readonly newEpochId: RuntimeEpochId;
}): { readonly ok: true; readonly evidenceHash: string } | { readonly ok: false; readonly reason: string } {
  const rebuilt = buildHandoffEvidence({
    recoveryReport: input.recoveryReport,
    newEpochId: input.newEpochId,
    priorEpochId: input.claimed.priorEpochId,
  });
  if (rebuilt.evidenceHash !== input.claimed.evidenceHash) {
    return { ok: false, reason: "handoff evidence hash mismatch — the claimed evidence does not match the actual recovery report and new epoch (deterministic rebuild diverged)" };
  }
  if (input.claimed.grantsAuthority !== false) {
    return { ok: false, reason: "handoff evidence claims authority — evidence can never grant authority (refusing)" };
  }
  if (input.claimed.resumeSemantics !== "no_auto_resume") {
    return { ok: false, reason: "handoff evidence claims auto-resume — no_auto_resume is the only representable semantics (refusing)" };
  }
  if (input.claimed.executionPathRequirement !== "planner_allocation_policy_isolation_governed_tool_runtime") {
    return { ok: false, reason: "handoff evidence claims an alternate execution path — the frozen chain is the only representable requirement (refusing)" };
  }
  if (input.claimed.newEpochId !== input.newEpochId || !RUNTIME_EPOCH_ID_PATTERN.test(input.newEpochId)) {
    return { ok: false, reason: "the new epoch id does not match the claimed evidence" };
  }
  return { ok: true, evidenceHash: input.claimed.evidenceHash };
}

// ── the NEW epoch after recovery ─────────────────────────────────────────────

/**
 * The NEW epoch admitted after recovery: derived from the BOOTING epoch's
 * identity by a bounded BIJECTIVE bump of the last four base-36 characters
 * of its random part (addition mod 36^4 — injective, so two different boot
 * identities can never derive the same new id; the result stays inside the
 * 23A epoch-id pattern). Never the same id, never reused. The epoch object
 * keeps the 23A construction law: lifecycle BOOTING, no authority.
 */
export function makeNewEpochAfterRecovery(bootedEpoch: RuntimeEpoch, nowEpochMs: number): RuntimeEpoch {
  const m = /^re-([0-9a-f]{12})-([a-zA-Z0-9]{16})$/.exec(bootedEpoch.epochId);
  const ts: string = m !== null && m[1] !== undefined ? m[1] : "000000000000";
  const rnd: string = m !== null && m[2] !== undefined ? m[2] : "0000000000000000";
  const last4 = rnd.slice(12);
  const base36Space = 36 ** 4; // 1,679,616
  const bump = 97669; // "23d1" in base36 — the 23D generation marker
  const a = parseInt(last4, 36) % base36Space;
  const bumped = ((a + bump) % base36Space).toString(36).padStart(4, "0");
  const newId = "re-" + ts + "-" + rnd.slice(0, 12) + bumped;
  return Object.freeze({
    schemaVersion: bootedEpoch.schemaVersion,
    epochId: newId,
    startedAtEpochMs: nowEpochMs,
    hostRef: bootedEpoch.hostRef,
    pidRef: bootedEpoch.pidRef,
    lifecycle: "BOOTING" as const,
    priorOwner: { code: "stale_claim_present" as const, epochId: bootedEpoch.epochId },
    startReason: "prior_owner_expired" as const,
    executionAuthorized: false as const,
    policyAuthorized: false as const,
  });
}

// ── evidenced ownership transfer (the ONLY sanctioned supersession) ──────────

export type EvidencedTransferResult =
  | { readonly ok: true; readonly ownerEpochId: string; readonly explanation: string }
  | {
      readonly ok: false;
      readonly code: "claim_not_current" | "epoch_not_new" | "epoch_invalid" | "justification_required" | "store_failure";
      readonly reason: string;
    };

/**
 * 23D — supersede a prior epoch's durable live-owner claim BY EVIDENCE.
 * Fail-closed: the claim must EXIST and belong to the explicitly named
 * `fromEpochId` (a stale/foreign prior epoch is refused); the target must
 * be a shape-valid, DIFFERENT (NEW) epoch id; the justification must be a
 * bounded non-empty string (the runner binds the recovery report hash into
 * it, so the supersession evidence is on record). This is the only path by
 * which a new epoch may acquire a claim held by another id.
 */
export function transferOwnershipEvidenced(
  store: DurableStore,
  fromEpochId: RuntimeEpochId,
  toEpoch: RuntimeEpoch,
  justification: string
): EvidencedTransferResult {
  if (!RUNTIME_EPOCH_ID_PATTERN.test(toEpoch.epochId)) {
    return { ok: false, code: "epoch_invalid", reason: "the target epoch id is missing or malformed" };
  }
  if (toEpoch.epochId === fromEpochId) {
    return { ok: false, code: "epoch_not_new", reason: "ownership transfer requires a NEW epoch id (self-transfer is refused)" };
  }
  if (typeof justification !== "string" || justification.length === 0 || justification.length > 512) {
    return { ok: false, code: "justification_required", reason: "a bounded non-empty justification is required for the evidenced supersession" };
  }
  const ownership = readRuntimeOwnership(store, fromEpochId);
  if (ownership.code !== "owner_current") {
    return {
      ok: false,
      code: "claim_not_current",
      reason:
        "the durable live-owner claim does not belong to the named prior epoch '" + fromEpochId +
        "' — refusing to transfer an unheld, stale, or foreign claim (stale/foreign epoch fails closed)",
    };
  }
  const wrote = store.setMeta("runtime_live_owner_epoch", toEpoch.epochId + "|" + (ownership.boundSourceIdentity ?? "unknown-prior-source"));
  if (!wrote.ok) {
    return { ok: false, code: "store_failure", reason: wrote.reason ?? "could not write the transferred claim" };
  }
  return {
    ok: true,
    ownerEpochId: toEpoch.epochId,
    explanation:
      "live-owner claim transferred from prior epoch " + fromEpochId + " to NEW epoch " + toEpoch.epochId +
      " (evidenced supersession after successful recovery: " + justification + ")",
  };
}

// ── the runner (BOOTING → RECOVERING → RECONCILED → READY → LIVE) ────────────

export type HandoffStep =
  | { readonly stage: "RECOVERING"; readonly ok: true; readonly reportHash: string }
  | { readonly stage: "RECONCILED"; readonly ok: false; readonly reason: string; readonly blockingClass: HandoffBlockingClass }
  | { readonly stage: "RECONCILED"; readonly ok: true; readonly newEpochId: RuntimeEpochId; readonly classification: FindingClassification }
  | { readonly stage: "READY"; readonly ok: true; readonly viewsReconstructedFrom: "admitted_data_only" }
  | { readonly stage: "READY"; readonly ok: false; readonly reason: string }
  | { readonly stage: "LIVE"; readonly ok: true; readonly evidenceHash: string }
  | { readonly stage: "LIVE"; readonly ok: false; readonly reason: string }
  | { readonly stage: "RECOVERED"; readonly reason: string };

export interface HandoffRunResult {
  readonly ok: boolean;
  readonly terminalState: "LIVE" | "RECOVERED";
  readonly newEpochId: RuntimeEpochId | null;
  readonly reportHash: string | null;
  readonly evidenceHash: string | null;
  readonly evidence: HandoffEvidence | null;
  readonly classification: FindingClassification | null;
  /** Interrupted tasks: reported as FACTS — never resumed by anyone here. */
  readonly interruptedTaskIds: readonly string[];
  readonly derivedRebuildRequired: boolean;
  /** The safe-view wiring on the NEW epoch (null unless LIVE). */
  readonly wiring: LiveSurfaceWiring | null;
  readonly steps: readonly HandoffStep[];
  readonly explanation: string;
}

/**
 * The explicit, evidenced startup handoff. FAIL-CLOSED: any blocking
 * finding, stale/foreign epoch, duplicate-owner conflict, or evidence
 * mismatch terminates in RECOVERED. Nothing resumes; nothing reactivates;
 * nothing grants authority.
 */
export function runStartupHandoff(input: {
  readonly store: DurableStore;
  readonly bootedEpoch: RuntimeEpoch;
  readonly recoveryRequest: RecoveryRequest;
  readonly sourceIdentity: string;
  /** The prior epoch being superseded; null ONLY for a fresh store. */
  readonly priorEpochId: RuntimeEpochId | null;
  readonly nowEpochMs: number;
}): HandoffRunResult {
  const steps: HandoffStep[] = [];

  // ── 1. RECOVERING: the frozen Phase-22 recovery runs FIRST. ────────────
  const report = buildRecoveryReport(input.store, input.recoveryRequest, input.nowEpochMs);
  const reportHash = recoveryReportHash(report);
  steps.push({ stage: "RECOVERING", ok: true, reportHash });

  // ── 2. RECONCILED: classify findings. Hard/quarantine BLOCK LIVE. ──────
  const classification = classifyRecoveryReport(report);
  if (classification.blockingClass !== "none") {
    steps.push({ stage: "RECONCILED", ok: false, reason: classification.explanation, blockingClass: classification.blockingClass });
    steps.push({ stage: "RECOVERED", reason: "blocking findings (" + classification.blockingClass + ") — no live exposure before successful validation" });
    return {
      ok: false,
      terminalState: "RECOVERED",
      newEpochId: null,
      reportHash,
      evidenceHash: null,
      evidence: null,
      classification,
      interruptedTaskIds: report.interruptedTaskIds,
      derivedRebuildRequired: report.derivedRebuildRequired,
      wiring: null,
      steps,
      explanation: classification.explanation,
    };
  }

  // The 23A bootstrap law maps the frozen decision onto READY admission.
  const bootstrap = decideRecoveryBootstrap({
    epochId: input.bootedEpoch.epochId,
    lifecycle: "RECONCILED",
    recoveryDecision: report.decision,
  });
  if (!bootstrap.ok) {
    steps.push({ stage: "RECONCILED", ok: false, reason: bootstrap.explanation, blockingClass: "hard" });
    steps.push({ stage: "RECOVERED", reason: "the 23A bootstrap law refused the recovered state — no live exposure" });
    return {
      ok: false,
      terminalState: "RECOVERED",
      newEpochId: null,
      reportHash,
      evidenceHash: null,
      evidence: null,
      classification,
      interruptedTaskIds: report.interruptedTaskIds,
      derivedRebuildRequired: report.derivedRebuildRequired,
      wiring: null,
      steps,
      explanation: bootstrap.explanation,
    };
  }

  // A NEW runtime epoch after recovery — never the BOOTING epoch id.
  const newEpoch = makeNewEpochAfterRecovery(input.bootedEpoch, input.nowEpochMs);
  steps.push({ stage: "RECONCILED", ok: true, newEpochId: newEpoch.epochId, classification });

  // ── 3. Ownership: evidenced supersession of the NAMED prior epoch. ─────
  const ownership = readRuntimeOwnership(input.store, null);
  if (ownership.code === "no_prior_owner") {
    if (input.priorEpochId !== null) {
      steps.push({ stage: "RECOVERED", reason: "a prior epoch was named but the store records NO live-owner claim — stale/foreign epoch fails closed" });
      return {
        ok: false,
        terminalState: "RECOVERED",
        newEpochId: null,
        reportHash,
        evidenceHash: null,
        evidence: null,
        classification,
        interruptedTaskIds: report.interruptedTaskIds,
        derivedRebuildRequired: report.derivedRebuildRequired,
        wiring: null,
        steps,
        explanation: "the named prior epoch does not match the durable ownership state (no claim exists) — refusing",
      };
    }
    const bound = RuntimeStateCoordinator.open(input.store, newEpoch, input.sourceIdentity);
    if (!bound.ok) {
      steps.push({ stage: "RECOVERED", reason: "the NEW epoch could not bind the coordinator: " + bound.reason });
      return {
        ok: false,
        terminalState: "RECOVERED",
        newEpochId: newEpoch.epochId,
        reportHash,
        evidenceHash: null,
        evidence: null,
        classification,
        interruptedTaskIds: report.interruptedTaskIds,
        derivedRebuildRequired: report.derivedRebuildRequired,
        wiring: null,
        steps,
        explanation: bound.reason,
      };
    }
  } else {
    // A claim exists: it must belong to the NAMED prior epoch, and the
    // supersession must be evidenced (the report hash rides in the
    // justification). A duplicate owner (claim now held by someone else)
    // or a foreign/stale name refuses here.
    const transferred = transferOwnershipEvidenced(
      input.store,
      ownership.ownerEpochId as string,
      newEpoch,
      "23D handoff after successful recovery; reportHash=" + reportHash,
    );
    if (!transferred.ok || ownership.ownerEpochId !== input.priorEpochId) {
      const reason = transferred.ok
        ? "the durable claim owner '" + String(ownership.ownerEpochId) + "' does not match the named prior epoch '" +
          String(input.priorEpochId) + "' — stale/foreign epoch fails closed"
        : transferred.reason;
      steps.push({ stage: "RECOVERED", reason });
      return {
        ok: false,
        terminalState: "RECOVERED",
        newEpochId: newEpoch.epochId,
        reportHash,
        evidenceHash: null,
        evidence: null,
        classification,
        interruptedTaskIds: report.interruptedTaskIds,
        derivedRebuildRequired: report.derivedRebuildRequired,
        wiring: null,
        steps,
        explanation: reason,
      };
    }
  }

  // ── 4. READY: safe views from ADMITTED data only (the 23C wiring). ─────
  const wired = LiveSurfaceWiring.open(input.store, coordinatorForNewEpoch(input.store, newEpoch, input.sourceIdentity), newEpoch);
  if (!wired.ok) {
    steps.push({ stage: "READY", ok: false, reason: wired.reason });
    steps.push({ stage: "RECOVERED", reason: "safe views could not be reconstructed — no live exposure" });
    return {
      ok: false,
      terminalState: "RECOVERED",
      newEpochId: newEpoch.epochId,
      reportHash,
      evidenceHash: null,
      evidence: null,
      classification,
      interruptedTaskIds: report.interruptedTaskIds,
      derivedRebuildRequired: report.derivedRebuildRequired,
      wiring: null,
      steps,
      explanation: wired.reason,
    };
  }
  steps.push({ stage: "READY", ok: true, viewsReconstructedFrom: "admitted_data_only" });

  // ── 5. LIVE: granted ONLY on verified deterministic evidence. ──────────
  const evidence = buildHandoffEvidence({
    recoveryReport: report,
    newEpochId: newEpoch.epochId,
    priorEpochId: input.priorEpochId,
  });
  const verified = verifyHandoffEvidence({
    claimed: evidence,
    recoveryReport: report,
    newEpochId: newEpoch.epochId,
  });
  if (!verified.ok) {
    steps.push({ stage: "LIVE", ok: false, reason: verified.reason });
    steps.push({ stage: "RECOVERED", reason: "handoff evidence mismatch — LIVE refused (fail closed)" });
    return {
      ok: false,
      terminalState: "RECOVERED",
      newEpochId: newEpoch.epochId,
      reportHash,
      evidenceHash: evidence.evidenceHash,
      evidence,
      classification,
      interruptedTaskIds: report.interruptedTaskIds,
      derivedRebuildRequired: report.derivedRebuildRequired,
      wiring: wired.wiring,
      steps,
      explanation: verified.reason,
    };
  }
  const liveOk = advanceLifecycle(newEpoch, "READY", "LIVE", "lifecycle_transition", input.nowEpochMs, {
    kind: "handoff_evidence",
    evidenceHash: evidence.evidenceHash,
  });
  if (!liveOk.ok) {
    steps.push({ stage: "LIVE", ok: false, reason: liveOk.explanation });
    steps.push({ stage: "RECOVERED", reason: "the machine refused the evidenced LIVE transition — fail closed" });
    return {
      ok: false,
      terminalState: "RECOVERED",
      newEpochId: newEpoch.epochId,
      reportHash,
      evidenceHash: evidence.evidenceHash,
      evidence,
      classification,
      interruptedTaskIds: report.interruptedTaskIds,
      derivedRebuildRequired: report.derivedRebuildRequired,
      wiring: wired.wiring,
      steps,
      explanation: liveOk.explanation,
    };
  }
  steps.push({ stage: "LIVE", ok: true, evidenceHash: evidence.evidenceHash });
  return {
    ok: true,
    terminalState: "LIVE",
    newEpochId: newEpoch.epochId,
    reportHash,
    evidenceHash: evidence.evidenceHash,
    evidence,
    classification,
    interruptedTaskIds: report.interruptedTaskIds,
    derivedRebuildRequired: report.derivedRebuildRequired,
    wiring: wired.wiring,
    steps,
    explanation:
      "explicit handoff complete: recovery ran first, findings classified (none blocking), NEW epoch " + newEpoch.epochId +
      " admitted by evidenced supersession, safe views reconstructed from admitted data only, LIVE granted on verified evidence; " +
      "no recovered Policy decision, allocation, capability, approval, or process state was reactivated; " +
      String(report.interruptedTaskIds.length) + " interrupted task(s) remain interrupted until a fresh caller action traverses the normal authority chain",
  };
}

/**
 * Bind the NEW epoch's coordinator for the wiring (the claim was already
 * transferred/bound by the runner; the open law re-checks and accepts the
 * current claim as `owner_current`).
 */
function coordinatorForNewEpoch(store: DurableStore, newEpoch: RuntimeEpoch, sourceIdentity: string): RuntimeStateCoordinator {
  const bound = RuntimeStateCoordinator.open(store, newEpoch, sourceIdentity);
  if (!bound.ok) {
    throw new Error(bound.reason);
  }
  return bound.coordinator;
}
