import type { AgentRuntime } from "./runtime.js";
import type {
  AgentFailureReport,
  AgentRecoveryRecord,
  AgentSuspensionView,
  ReassignmentResult,
  RecoveryDenyReason,
  RecoveryResult,
  ReassignInput,
  StaleOwnershipPolicy,
  StaleOwnershipView,
} from "./recoveryTypes.js";
import {
  KNOWN_AGENT_FAILURE_KINDS,
  RECOVERY_SCHEMA_VERSION,
} from "./recoveryTypes.js";
import {
  AGENTS_MAX_FAILURE_NOTE_CHARS,
  AGENTS_MAX_RECOVERY_CHAIN,
  AGENTS_MAX_RECOVERIES,
  AGENTS_SUSPENSION_FAILURE_THRESHOLD,
} from "./types.js";
import { taskDescriptorDigest } from "./allocation.js";
import { validateTaskDescriptor } from "./allocation.js";

/**
 * Phase 19E — the bounded recovery coordinator.
 *
 * Runs over the 19B allocator + runtime bookkeeping. It has NO authority of
 * its own: it reports failures (after verifying the reporter actually owns
 * the assignment), cancels via the allocator's own status surface, and
 * reassigns through TaskAllocator.allocate with the ORIGINAL task
 * descriptor (digest-equality enforced — scope drift cannot pass) and the
 * failed agent excluded from the availability map.
 *
 * Collusion resistance: agents have no reference to this coordinator and no
 * facade method reaches it; reassignment targets are chosen by the
 * deterministic allocator ranking, never by agent request.
 */

const AUTHORITY = "recovery_data" as const;

function deny(denyReason: RecoveryDenyReason, reason: string): ReassignmentResult {
  return { ok: false, denyReason, reason };
}

/** Validate a failure report (bounded, fail-closed). */
export function validateFailureReport(
  report: AgentFailureReport
): { ok: true } | { ok: false; denyReason: RecoveryDenyReason; reason: string } {
  if (!report || typeof report !== "object") {
    return { ok: false, denyReason: "invalid_report", reason: "report must be an object" };
  }
  if (typeof report.assignmentId !== "string" || report.assignmentId.length === 0 || report.assignmentId.length > 64) {
    return { ok: false, denyReason: "invalid_report", reason: "assignmentId must be a 1..64 char string" };
  }
  if (typeof report.agentId !== "string" || report.agentId.length === 0 || report.agentId.length > 64) {
    return { ok: false, denyReason: "invalid_report", reason: "agentId must be a 1..64 char string" };
  }
  if (!KNOWN_AGENT_FAILURE_KINDS.includes(report.failureKind)) {
    return { ok: false, denyReason: "invalid_report", reason: "failureKind must be timeout|error|stale|explicit_release" };
  }
  if (typeof report.atEpochMs !== "number" || !Number.isFinite(report.atEpochMs) || report.atEpochMs < 0) {
    return { ok: false, denyReason: "invalid_report", reason: "atEpochMs must be a non-negative number" };
  }
  if (report.note !== undefined && (typeof report.note !== "string" || report.note.length > AGENTS_MAX_FAILURE_NOTE_CHARS)) {
    return {
      ok: false,
      denyReason: "invalid_report",
      reason: "note must be a string ≤ " + String(AGENTS_MAX_FAILURE_NOTE_CHARS) + " chars",
    };
  }
  return { ok: true };
}

/** Validate a staleness policy (bounded). */
export function validateStaleOwnershipPolicy(
  policy: StaleOwnershipPolicy
): { ok: true } | { ok: false; denyReason: RecoveryDenyReason; reason: string } {
  if (!policy || typeof policy !== "object") {
    return { ok: false, denyReason: "stale_policy_invalid", reason: "policy must be an object" };
  }
  const m = policy.maxAgeMs;
  if (typeof m !== "number" || !Number.isFinite(m) || m < 1 || m > 3_600_000) {
    return { ok: false, denyReason: "stale_policy_invalid", reason: "maxAgeMs must be in [1,3600000]" };
  }
  return { ok: true };
}

export class RecoveryCoordinator {
  readonly #runtime: AgentRuntime;
  readonly #failures: AgentRecoveryRecord[] = [];
  readonly #chainRoots = new Map<string, string>();
  readonly #chainDepths = new Map<string, number>();

  constructor(runtime: AgentRuntime) {
    this.#runtime = runtime;
  }

  get runtime(): AgentRuntime {
    return this.#runtime;
  }

  /** Observable append-only recovery log (failure + reassignment records). */
  history(): readonly AgentRecoveryRecord[] {
    return Object.freeze([...this.#failures]);
  }

  /** Observable failure counts per agent (bounded log; suspension input). */
  failureCounts(): ReadonlyMap<string, number> {
    const map = new Map<string, number>();
    for (const rec of this.#failures) {
      if (rec.kind === "failure_recorded") {
        map.set(rec.agentId, (map.get(rec.agentId) ?? 0) + 1);
      }
    }
    return map;
  }

  /**
   * Derived suspension views for the caller's availability map. Agents at
   * or above the failure threshold are suspended. The registry and all
   * profiles are NEVER mutated by this — suspension is a caller-applied
   * availability view (NO AGENT SELF-MODIFICATION WITHOUT REVIEW).
   */
  suspensions(): readonly AgentSuspensionView[] {
    const out: AgentSuspensionView[] = [];
    for (const [agentId, count] of this.failureCounts()) {
      if (count >= AGENTS_SUSPENSION_FAILURE_THRESHOLD) {
        out.push({ agentId, failureCount: count, available: false, reason: "suspended" });
      }
    }
    return Object.freeze(out);
  }

  /**
   * Report a failure on an ACTIVE assignment. Ownership-checked: the
   * reporting agentId must be the assignment's assignee. The assignment is
   * cancelled through the allocator's status surface (terminal; capacity
   * freed) and an append-only failure record is created.
   */
  reportFailure(report: AgentFailureReport): RecoveryResult {
    if (this.#failures.length >= AGENTS_MAX_RECOVERIES) {
      return { ok: false, denyReason: "recovery_cap_reached", reason: "recovery log cap reached (" + String(AGENTS_MAX_RECOVERIES) + ")" };
    }
    const shape = validateFailureReport(report);
    if (!shape.ok) return shape;
    const active = this.#runtime.activeAllocations().find(
      (v) => v.assignment.assignmentId === report.assignmentId
    );
    if (!active) {
      // Distinguish "never existed" from "already terminal" (double-failure
      // and completed assignments are refused, not unknown).
      const known = this.#runtime.allocationHistory().some(
        (r) => r.assignment.assignmentId === report.assignmentId
      );
      return {
        ok: false,
        denyReason: known ? "not_failed" : "unknown_assignment",
        reason: known
          ? "assignment '" + report.assignmentId + "' is no longer active (already terminal)"
          : "no active assignment '" + report.assignmentId + "'",
      };
    }
    if (active.assignment.assignedAgentId !== report.agentId) {
      return {
        ok: false,
        denyReason: "ownership_mismatch",
        reason:
          "agent '" +
          report.agentId +
          "' does not own assignment '" +
          report.assignmentId +
          "' (owned by '" +
          active.assignment.assignedAgentId +
          "')",
      };
    }
    const cancelled = this.#runtime.recordAllocationStatus(
      report.assignmentId,
      "cancelled",
      report.note,
      report.atEpochMs
    );
    if (!cancelled.ok) {
      return { ok: false, denyReason: "not_failed", reason: cancelled.reason };
    }
    const record: AgentRecoveryRecord = Object.freeze({
      recordId: "rec-" + String(this.#failures.length + 1).padStart(6, "0"),
      schemaVersion: RECOVERY_SCHEMA_VERSION,
      kind: "failure_recorded",
      atEpochMs: report.atEpochMs,
      assignmentId: report.assignmentId,
      agentId: report.agentId,
      failureKind: report.failureKind,
      reassignedFromAssignmentId: null,
      reassignedToAssignmentId: null,
      chainRootId: null,
      taskDigest: null,
      rationale:
        "failure '" +
        report.failureKind +
        "' recorded on assignment '" +
        report.assignmentId +
        "' (agent '" +
        report.agentId +
        "'); assignment cancelled, capacity freed",
      authority: AUTHORITY,
      executionAuthorized: false,
    });
    this.#failures.push(record);
    this.#emit("agent_failure_recorded", report.agentId, record.rationale);
    return { ok: true, record };
  }

  /**
   * Reassign a FAILED assignment's task. Constraints (all enforced):
   *   - the failed assignment must exist in the allocator history and be
   *     cancelled (not active, not completed);
   *   - the task descriptor must digest-match the original (anti-drift);
   *   - the failed agent AND all explicitly excluded agents are removed
   *     from the candidate pool via the availability map;
   *   - the recovery chain for this task is bounded (≤ AGENTS_MAX_RECOVERY_CHAIN);
   *   - the replacement is chosen by the deterministic allocator ranking —
   *     never by agent request.
   */
  reassign(input: ReassignInput, allocator: import("./allocation.js").TaskAllocator): ReassignmentResult {
    if (this.#failures.length >= AGENTS_MAX_RECOVERIES) {
      return deny("recovery_cap_reached", "recovery log cap reached (" + String(AGENTS_MAX_RECOVERIES) + ")");
    }
    if (!input || typeof input !== "object") {
      return deny("invalid_report", "input must be an object");
    }
    if (typeof input.failedAssignmentId !== "string" || input.failedAssignmentId.length === 0) {
      return deny("invalid_report", "failedAssignmentId must be a non-empty string");
    }
    const taskShape = validateTaskDescriptor(input.task);
    if (!taskShape.ok) {
      return deny("invalid_report", "task descriptor invalid: " + taskShape.reason);
    }
    const alsoExcluded = input.alsoExcludeAgentIds ?? [];
    if (alsoExcluded.length > 8) {
      return deny("invalid_report", "alsoExcludeAgentIds cap is 8");
    }

    const history = this.#runtime.allocationHistory();
    const failedRecord = history.find((r) => r.assignment.assignmentId === input.failedAssignmentId);
    if (!failedRecord) {
      return deny("unknown_assignment", "unknown assignment '" + input.failedAssignmentId + "'");
    }
    const active = this.#runtime.activeAllocations().some(
      (v) => v.assignment.assignmentId === input.failedAssignmentId
    );
    if (active) {
      return deny("not_failed", "assignment '" + input.failedAssignmentId + "' is still active; report failure first");
    }
    // A failure must have been RECORDED for this assignment before
    // reassignment: completing or releasing is not failure (release is
    // deliberate; completion is success). This keeps recovery scoped to
    // actual failures.
    const failureRecorded = this.#failures.some(
      (r) => r.kind === "failure_recorded" && r.assignmentId === input.failedAssignmentId
    );
    if (!failureRecorded) {
      return deny(
        "not_failed",
        "no failure was recorded on assignment '" + input.failedAssignmentId + "'; reassignment requires a recorded failure"
      );
    }

    // Anti-drift: the digest of the given descriptor must equal the digest
    // recorded at original allocation (canonical serialization ignores key
    // order but pins label/caps/budget/risk).
    if (failedRecord.taskDigest !== taskDescriptorDigest(input.task)) {
      return deny(
        "task_descriptor_drift",
        "task descriptor digest mismatch: recovery may only reassign the ORIGINAL task (scope drift is structurally refused)"
      );
    }

    // Chain bound: walk reassignedTo links back to the chain root. The
    // depth counts REASSIGNMENT HOPS (the original allocation is hop 0;
    // the first reassignment is hop 1). A hop beyond the cap is refused.
    const chainRoot = this.#chainRootOf(input.failedAssignmentId);
    const depth = (this.#chainDepths.get(chainRoot) ?? 0) + 1;
    if (depth > AGENTS_MAX_RECOVERY_CHAIN) {
      return deny(
        "reassignment_exhausted",
        "recovery chain for task '" + failedRecord.assignment.taskLabel + "' reached cap " + String(AGENTS_MAX_RECOVERY_CHAIN)
      );
    }

    // Build the exclusion-aware availability map from the ORIGINAL
    // allocation's candidates plus the failed agent and explicit exclusions.
    const originalCandidates = history
      .flatMap((r) => (r.recordId === failedRecord.recordId ? [] : []))
      .concat([]); // candidates are not persisted per-record; use registry + status
    void originalCandidates;
    const availability: Record<string, { available: boolean; reason?: "busy" | "suspended" | "offline" }> = {};
    const failedAgentId = failedRecord.assignment.assignedAgentId;
    availability[failedAgentId] = { available: false, reason: "offline" };
    for (const ex of alsoExcluded) {
      if (typeof ex !== "string" || ex.length === 0) {
        return deny("invalid_report", "alsoExcludeAgentIds entries must be non-empty strings");
      }
      availability[ex] = { available: false, reason: "offline" };
    }
    // Suspended agents (derived from the failure log) are excluded too.
    for (const s of this.suspensions()) {
      availability[s.agentId] = { available: false, reason: "suspended" };
    }

    const result = allocator.allocate({
      allocatedBy: "recovery-coordinator",
      task: input.task,
      availability,
      atEpochMs: input.atEpochMs,
    });
    if (!result.ok) {
      // Map allocator denials onto recovery deny reasons (fail-closed).
      if (result.denyReason === "no_candidates" || result.denyReason === "no_qualified_agent") {
        return deny("no_reassignment_candidate", "no qualified, available, under-capacity replacement: " + result.reason);
      }
      if (result.denyReason === "oversized_request") {
        return deny("reassignment_exhausted", "no capacity for reassignment: " + result.reason);
      }
      return deny("invalid_report", "allocator refused: " + result.reason);
    }

    const record: AgentRecoveryRecord = Object.freeze({
      recordId: "rec-" + String(this.#failures.length + 1).padStart(6, "0"),
      schemaVersion: RECOVERY_SCHEMA_VERSION,
      kind: "reassigned",
      atEpochMs: input.atEpochMs,
      assignmentId: result.assignment.assignmentId,
      agentId: result.assignment.assignedAgentId,
      failureKind: null,
      reassignedFromAssignmentId: input.failedAssignmentId,
      reassignedToAssignmentId: result.assignment.assignmentId,
      chainRootId: chainRoot,
      taskDigest: failedRecord.taskDigest,
      rationale:
        "reassigned task '" +
        failedRecord.assignment.taskLabel +
        "' from '" +
        failedAgentId +
        "' to '" +
        result.assignment.assignedAgentId +
        "' (chain depth " +
        String(depth) +
        "/" +
        String(AGENTS_MAX_RECOVERY_CHAIN) +
        "); descriptor digest unchanged",
      authority: AUTHORITY,
      executionAuthorized: false,
    });
    this.#failures.push(record);
    this.#chainRoots.set(result.assignment.assignmentId, chainRoot);
    this.#chainDepths.set(chainRoot, depth);
    this.#emit("agent_task_reassigned", result.assignment.assignedAgentId, record.rationale);
    return { ok: true, record, assignment: result.assignment, candidates: result.candidates };
  }

  /**
   * Caller-driven stale-ownership sweep: returns every ACTIVE assignment
   * whose age (now − allocatedAtEpochMs) exceeds the policy. NEVER mutates
   * anything and never runs in the background — the caller decides what to
   * do with the view (typically reportFailure with kind "stale").
   */
  detectStaleOwnership(policy: StaleOwnershipPolicy, nowEpochMs: number): readonly StaleOwnershipView[] {
    const shape = validateStaleOwnershipPolicy(policy);
    if (!shape.ok) {
      throw new Error("invalid stale ownership policy: " + shape.reason);
    }
    const out: StaleOwnershipView[] = [];
    for (const view of this.#runtime.activeAllocations()) {
      const ageMs = nowEpochMs - view.assignment.allocatedAtEpochMs;
      if (ageMs > policy.maxAgeMs) {
        out.push({
          assignmentId: view.assignment.assignmentId,
          agentId: view.assignment.assignedAgentId,
          taskLabel: view.assignment.taskLabel,
          allocatedAtEpochMs: view.assignment.allocatedAtEpochMs,
          ageMs,
        });
      }
    }
    return Object.freeze(out);
  }

  /** Release an assignment WITHOUT failure (explicit human/caller release). */
  release(assignmentId: string, atEpochMs: number, note?: string): RecoveryResult {
    if (this.#failures.length >= AGENTS_MAX_RECOVERIES) {
      return { ok: false, denyReason: "recovery_cap_reached", reason: "recovery log cap reached" };
    }
    if (note !== undefined && (typeof note !== "string" || note.length > AGENTS_MAX_FAILURE_NOTE_CHARS)) {
      return { ok: false, denyReason: "invalid_report", reason: "note too long" };
    }
    const active = this.#runtime.activeAllocations().find((v) => v.assignment.assignmentId === assignmentId);
    if (!active) {
      return { ok: false, denyReason: "unknown_assignment", reason: "no active assignment '" + assignmentId + "'" };
    }
    const cancelled = this.#runtime.recordAllocationStatus(assignmentId, "cancelled", note, atEpochMs);
    if (!cancelled.ok) {
      return { ok: false, denyReason: "not_failed", reason: cancelled.reason };
    }
    const record: AgentRecoveryRecord = Object.freeze({
      recordId: "rec-" + String(this.#failures.length + 1).padStart(6, "0"),
      schemaVersion: RECOVERY_SCHEMA_VERSION,
      kind: "released",
      atEpochMs,
      assignmentId,
      agentId: active.assignment.assignedAgentId,
      failureKind: "explicit_release",
      reassignedFromAssignmentId: null,
      reassignedToAssignmentId: null,
      chainRootId: null,
      taskDigest: null,
      rationale: "assignment '" + assignmentId + "' released explicitly (no failure imputed)",
      authority: AUTHORITY,
      executionAuthorized: false,
    });
    this.#failures.push(record);
    this.#emit("agent_assignment_released", active.assignment.assignedAgentId, record.rationale);
    return { ok: true, record };
  }

  #chainRootOf(assignmentId: string): string {
    let current = assignmentId;
    for (let i = 0; i < AGENTS_MAX_RECOVERY_CHAIN + 2; i++) {
      const root = this.#chainRoots.get(current);
      if (!root) return current;
      current = root;
    }
    return current;
  }

  #emit(eventType: "agent_failure_recorded" | "agent_task_reassigned" | "agent_assignment_released", subjectId: string, rationale: string): void {
    // Ledger observability goes through the runtime's emitter (the
    // coordinator holds no emitter reference of its own).
    this.#runtime.emitRecoveryEvent(eventType, subjectId, rationale);
  }
}
