/**
 * Phase 19E — Bounded Recovery & Reassignment (Agent Runtime V0).
 *
 * Closes the operational loop over 19A–19C with explicit, bounded failure
 * handling:
 *
 *   failure reported (caller-supplied, ownership-checked)
 *   → assignment cancelled (explicit terminal status, capacity freed)
 *   → reassignment of the SAME task (digest-equality enforced: a widened
 *     descriptor denies `task_descriptor_drift` — scope drift is structurally
 *     impossible through recovery)
 *   → to a qualified, available, under-capacity agent that is NOT the
 *     failed one (exclusion enforced), bounded per task chain
 *
 * Authority separation (unchanged):
 *   - Recovery is bookkeeping. The reassigned task still requires a full
 *     deny-by-default policy evaluation before anything executes.
 *   - Agents have NO recovery surface: they cannot report failures, cancel
 *     assignments, trigger reassignment, or steer the replacement choice
 *     (collusion-resistant by construction: no agent-callable path exists).
 *   - Suspension is a DERIVED availability view computed from the bounded
 *     failure log — the registry and profiles are never mutated (NO AGENT
 *     SELF-MODIFICATION WITHOUT REVIEW).
 *   - Stale-ownership detection is caller-driven (a now-epoch comparison),
 *     never a background timer (no hidden background execution).
 */

/** Canonical schema version pinned for the 19E recovery surface. */
export const RECOVERY_SCHEMA_VERSION = "menog-agent-recovery/v0" as const;
export type RecoverySchemaVersion = typeof RECOVERY_SCHEMA_VERSION;

/** Which authority class a recovery artifact is. */
export type RecoveryAuthority = "recovery_data";

/** Observable failure classes a caller may report (closed union). */
export type AgentFailureKind = "timeout" | "error" | "stale" | "explicit_release";

export const KNOWN_AGENT_FAILURE_KINDS: readonly AgentFailureKind[] =
  Object.freeze(["timeout", "error", "stale", "explicit_release"]);

/** Machine-readable deny reasons for recovery operations (fail-closed). */
export type RecoveryDenyReason =
  | "invalid_report"
  | "unknown_assignment"
  | "ownership_mismatch"
  | "not_failed"
  | "task_descriptor_drift"
  | "reassignment_exhausted"
  | "no_reassignment_candidate"
  | "recovery_cap_reached"
  | "stale_policy_invalid";

export const KNOWN_RECOVERY_DENY_REASONS: readonly RecoveryDenyReason[] =
  Object.freeze([
    "invalid_report",
    "unknown_assignment",
    "ownership_mismatch",
    "not_failed",
    "task_descriptor_drift",
    "reassignment_exhausted",
    "no_reassignment_candidate",
    "recovery_cap_reached",
    "stale_policy_invalid",
  ]);

export function isRecoveryDenyReason(value: unknown): value is RecoveryDenyReason {
  return (
    typeof value === "string" &&
    (KNOWN_RECOVERY_DENY_REASONS as readonly string[]).includes(value)
  );
}

/** A caller-supplied, ownership-checked failure report (bounded). */
export interface AgentFailureReport {
  readonly assignmentId: string;
  readonly agentId: string;
  readonly failureKind: AgentFailureKind;
  readonly atEpochMs: number;
  /** Bounded conclusion-only note (observability; never executed). */
  readonly note?: string;
}

/** One immutable recovery record (append-only audit trail). */
export interface AgentRecoveryRecord {
  readonly recordId: string;
  readonly schemaVersion: RecoverySchemaVersion;
  readonly kind: "failure_recorded" | "reassigned" | "released";
  readonly atEpochMs: number;
  readonly assignmentId: string;
  readonly agentId: string;
  readonly failureKind: AgentFailureKind | null;
  /** For reassignments: the assignment the failure was reported on. */
  readonly reassignedFromAssignmentId: string | null;
  /** For reassignments: the NEW assignment id. */
  readonly reassignedToAssignmentId: string | null;
  /** Chain root: the first assignment id of this recovery chain. */
  readonly chainRootId: string | null;
  /** For reassignments: digest of the (unchanged) task descriptor. */
  readonly taskDigest: string | null;
  /** Bounded conclusion-only rationale. */
  readonly rationale: string;
  /** ALWAYS "recovery_data" — recovery is bookkeeping, never authority. */
  readonly authority: RecoveryAuthority;
  /** ALWAYS false — recovery can never authorize execution. */
  readonly executionAuthorized: false;
}

/** A read-only view of one stale active assignment (caller-driven). */
export interface StaleOwnershipView {
  readonly assignmentId: string;
  readonly agentId: string;
  readonly taskLabel: string;
  readonly allocatedAtEpochMs: number;
  readonly ageMs: number;
}

/**
 * A derived suspension view (read-only data for the caller's availability
 * map). This NEVER mutates the registry or any profile.
 */
export interface AgentSuspensionView {
  readonly agentId: string;
  readonly failureCount: number;
  readonly available: false;
  readonly reason: "suspended";
}

/** Bounded staleness policy (caller-supplied, validated). */
export interface StaleOwnershipPolicy {
  /** Active assignments older than this (epoch-ms delta) are stale (1..3_600_000). */
  readonly maxAgeMs: number;
}

export interface ReassignInput {
  /** The assignment the failure was reported on (must be cancelled/terminal). */
  readonly failedAssignmentId: string;
  /** The ORIGINAL task descriptor — digest-equality is enforced (anti-drift). */
  readonly task: import("./allocationTypes.js").TaskDescriptor;
  /** Additional agent ids to exclude (bounded; the failed agent is always excluded). */
  readonly alsoExcludeAgentIds?: readonly string[];
  readonly atEpochMs: number;
}

export type ReassignmentResult =
  | {
      readonly ok: true;
      readonly record: AgentRecoveryRecord;
      readonly assignment: import("./allocationTypes.js").TaskAssignment;
      readonly candidates: readonly import("./allocationTypes.js").AllocationCandidate[];
    }
  | {
      readonly ok: false;
      readonly denyReason: RecoveryDenyReason;
      readonly reason: string;
    };

export type RecoveryResult =
  | { readonly ok: true; readonly record: AgentRecoveryRecord }
  | { readonly ok: false; readonly denyReason: RecoveryDenyReason; readonly reason: string };
