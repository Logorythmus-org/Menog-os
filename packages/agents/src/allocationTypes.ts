/**
 * Phase 19B — Baseline Task Allocation (Agent Runtime V0).
 *
 * Implements the FIRST concrete slice of the WHO layer's task-assignment
 * duty on top of the 19A identity/runtime foundation:
 *
 *   task descriptor (WHAT is needed)
 *   → candidate enumeration over REGISTERED agents (WHO exists)
 *   → qualification: capability match + role fit + availability
 *   → ranking: risk score, then budget headroom, then availability, then
 *     registration order (deterministic tie-breaking)
 *   → allocation: an ASSIGNMENT RECORD (advisory data), never authority
 *
 * Authority separation (unchanged from 19A):
 *   - The allocator ASSIGNS work proposals; it can never execute anything.
 *     Executing an assigned task still requires a full policy evaluation by
 *     the deny-by-default policy engine (`PolicyEngine.evaluate`), which
 *     remains the sole execution authority.
 *   - Allocation outputs carry `authority: "allocation_data"` and
 *     `executionAuthorized: false`.
 *   - Agents cannot allocate to themselves, cannot allocate from an
 *     unregistered sender, and cannot influence allocation by message
 *     content (allocation inputs are caller-supplied descriptors, not
 *     agent-authored payloads).
 *
 * Relationship to Phase-17 family 4 (multiagent_task_allocation): that
 * family remains contract-only in @menog/algorithms (frozen by 17E); this
 * module is the concrete baseline allocator in the WHO layer and does not
 * modify the algorithms package.
 */

/** Canonical schema version pinned for the 19B allocation surface. */
export const ALLOCATION_SCHEMA_VERSION = "menog-agent-allocation/v0" as const;
export type AllocationSchemaVersion = typeof ALLOCATION_SCHEMA_VERSION;

/** Which authority class an allocation artifact is. */
export type AllocationAuthority = "allocation_data";

/** Machine-readable deny reasons for allocation (fail-closed). */
export type AllocationDenyReason =
  | "invalid_task"
  | "oversized_task"
  | "required_capability_unknown"
  | "no_candidates"
  | "no_qualified_agent"
  | "allocator_unknown"
  | "oversized_request";

export const KNOWN_ALLOCATION_DENY_REASONS: readonly AllocationDenyReason[] =
  Object.freeze([
    "invalid_task",
    "oversized_task",
    "required_capability_unknown",
    "no_candidates",
    "no_qualified_agent",
    "allocator_unknown",
    "oversized_request",
  ]);

export function isAllocationDenyReason(
  value: unknown
): value is AllocationDenyReason {
  return (
    typeof value === "string" &&
    (KNOWN_ALLOCATION_DENY_REASONS as readonly string[]).includes(value)
  );
}

export interface AllocationDenial {
  readonly ok: false;
  readonly schemaVersion: AllocationSchemaVersion;
  readonly denyReason: AllocationDenyReason;
  readonly reason: string;
}

/** Why an agent is unavailable (closed union; callers supply this). */
export type AgentUnavailableReason =
  | "busy"
  | "suspended"
  | "offline";

export const KNOWN_UNAVAILABLE_REASONS: readonly AgentUnavailableReason[] =
  Object.freeze(["busy", "suspended", "offline"]);

/**
 * Caller-declared budget for one allocated task (bounded). Budget is
 * bookkeeping data for ranking/observation — never a resource grant; the
 * runtime still requires policy allow for any actual execution.
 */
export interface TaskBudget {
  /** Maximum steps the assignee may propose for this task (1..1000). */
  readonly maxSteps: number;
  /** Maximum wall-clock the assignee may consume, in epoch-ms delta (0..3_600_000). */
  readonly maxRuntimeMs?: number;
  /** Optional monotone deadline in epoch-ms (ranking tie-breaker, observability). */
  readonly deadlineEpochMs?: number;
}

/**
 * A task descriptor: WHAT the allocated work needs. Inputs are
 * caller-supplied and bounded; no agent-authored content is accepted here
 * (allocation cannot be steered by message payloads).
 */
export interface TaskDescriptor {
  /** Non-empty human-meaningful task label (bounded). */
  readonly label: string;
  /** Capability ids the assignee MUST hold in its profile (bounded, may be empty). */
  readonly requiredCapabilities: readonly string[];
  /** Roles that may receive this task (bounded 1..3; defaults to all three). */
  readonly allowedRoles?: readonly ("planner" | "builder" | "reviewer")[];
  /** Caller-declared budget for ranking and headroom comparison. */
  readonly budget: TaskBudget;
  /** Caller-declared risk score in [0,1] on the 0.1 grid (higher = riskier). */
  readonly riskScore?: number;
  /** Bounded free-text note (observability only; never executed). */
  readonly note?: string;
}

/** Caller-supplied availability view of one registered agent. */
export interface AgentAvailability {
  readonly available: boolean;
  readonly reason?: AgentUnavailableReason;
  /**
   * Caller-declared current load 0..1 (0.1 grid); used as a ranking
   * tie-breaker AFTER risk. Unavailable agents are excluded before ranking.
   */
  readonly load?: number;
}

/** Ranked qualification detail for one candidate (observable, read-only). */
export interface AllocationCandidate {
  readonly agentId: string;
  readonly role: "planner" | "builder" | "reviewer";
  /** True when the agent's profile covers every required capability. */
  readonly qualified: boolean;
  /** Required capabilities the profile did NOT cover (empty when qualified). */
  readonly missingCapabilities: readonly string[];
  readonly available: boolean;
  readonly unavailableReason: AgentUnavailableReason | null;
  /** Caller-declared load (0 when absent), 0.1-grid clamped. */
  readonly load: number;
  /**
   * Deterministic headroom in [0,1]: 1 - min(1, declaredSteps/maxSteps),
   * where declaredSteps is the sum of maxSteps of this agent's currently
   * ACTIVE allocations (runtime-tracked; not agent-claimed).
   */
  readonly budgetHeadroom: number;
  /** True when the agent already holds the per-agent cap of active assignments. */
  readonly atCapacity: boolean;
  /** Registration order index (lower = earlier; final deterministic tie-breaker). */
  readonly registrationOrder: number;
  /** True when this candidate received the allocation. */
  readonly selected: boolean;
}

/**
 * One assigned task (the allocation OUTPUT). Deliberately
 * NON-authoritative: it orders a proposal to be evaluated by policy later —
 * it can never authorize, execute, or grant anything.
 */
export interface TaskAssignment {
  readonly assignmentId: string;
  readonly schemaVersion: AllocationSchemaVersion;
  readonly taskLabel: string;
  readonly assignedAgentId: string;
  readonly assignedRole: "planner" | "builder" | "reviewer";
  readonly allocatedAtEpochMs: number;
  readonly budget: TaskBudget;
  readonly riskScore: number;
  /** ALWAYS "allocation_data" — assignments are coordination data. */
  readonly authority: AllocationAuthority;
  /** ALWAYS false — an assignment can never authorize execution. */
  readonly executionAuthorized: false;
}

/**
 * A frozen, immutable record of one completed allocation. The active view
 * is derived by the runtime from these records; records themselves are
 * never mutated or retracted (append-only bookkeeping).
 */
export interface AllocationRecord {
  readonly recordId: string;
  readonly assignment: TaskAssignment;
  readonly allocatedBy: string;
  readonly allocatedAtEpochMs: number;
  readonly candidateCount: number;
  /** Agent ids considered, in deterministic evaluation order. */
  readonly consideredAgentIds: readonly string[];
  /** SHA-256 digest of the canonical descriptor serialization. */
  readonly taskDigest: string;
  /** Bounded conclusion-only explanation of WHY this candidate won. */
  readonly rationale: string;
  /** ALWAYS "allocation_data". */
  readonly authority: AllocationAuthority;
  /** ALWAYS false. */
  readonly executionAuthorized: false;
}

/** One observable lifecycle event on an active assignment (bounded). */
export interface AllocationStatusEvent {
  readonly assignmentId: string;
  readonly agentId: string;
  readonly status: "assigned" | "completed" | "cancelled";
  readonly atEpochMs: number;
  /** Bounded conclusion-only note (never a derivation trace). */
  readonly note?: string;
}

/** A read-only view of one active allocation. */
export interface ActiveAllocationView {
  readonly assignment: TaskAssignment;
  readonly allocatedBy: string;
  readonly statusEventCount: number;
}

export type AllocationResult =
  | {
      readonly ok: true;
      readonly assignment: TaskAssignment;
      readonly record: AllocationRecord;
      readonly candidates: readonly AllocationCandidate[];
    }
  | AllocationDenial;
