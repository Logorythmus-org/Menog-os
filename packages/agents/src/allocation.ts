import { createHash } from "node:crypto";
import type { AgentRuntime } from "./runtime.js";
import type {
  ActiveAllocationView,
  AgentAvailability,
  AllocationCandidate,
  AllocationRecord,
  AllocationResult,
  AllocationStatusEvent,
  TaskAssignment,
  TaskDescriptor,
} from "./allocationTypes.js";
import {
  ALLOCATION_SCHEMA_VERSION,
  KNOWN_UNAVAILABLE_REASONS,
  type AllocationAuthority,
  type AllocationDenial,
  type AllocationDenyReason,
} from "./allocationTypes.js";
import {
  AGENTS_MAX_ALLOCATIONS,
  AGENTS_MAX_ASSIGNMENTS_PER_AGENT,
  AGENTS_MAX_TASK_LABEL_CHARS,
  AGENTS_MAX_TASK_NOTE_CHARS,
  AGENTS_MAX_TASKS,
  AGENTS_RISK_SCORE_STEP,
  AGENTS_REQUIRED_CAPABILITY_CAP,
} from "./types.js";

/**
 * Phase 19B — the baseline task allocator.
 *
 * Deterministic, synchronous, allocation-only (never executes). Ranking:
 *
 *   1. riskScore ascending (least risky first)
 *   2. budgetHeadroom descending (most headroom first)
 *   3. load ascending (least loaded first)
 *   4. registrationOrder ascending (stable final tie-breaker)
 *
 * An agent that is NOT qualified (its registered profile does not cover
 * every required capability) or NOT available (caller-supplied availability
 * view) can never be selected — `no_qualified_agent` denies the whole
 * allocation rather than falling back to an unqualified candidate.
 */

const AUTHORITY: AllocationAuthority = "allocation_data";

const ALL_ROLES = ["planner", "builder", "reviewer"] as const;

/** Validate the task descriptor (bounded, fail-closed). */
export function validateTaskDescriptor(
  task: TaskDescriptor
): { ok: true } | { ok: false; denyReason: AllocationDenyReason; reason: string } {
  if (!task || typeof task !== "object") {
    return { ok: false, denyReason: "invalid_task", reason: "task must be an object" };
  }
  if (typeof task.label !== "string" || task.label.length === 0) {
    return { ok: false, denyReason: "invalid_task", reason: "task.label must be a non-empty string" };
  }
  if (task.label.length > AGENTS_MAX_TASK_LABEL_CHARS) {
    return {
      ok: false,
      denyReason: "oversized_task",
      reason:
        "task.label length " +
        String(task.label.length) +
        " exceeds cap " +
        String(AGENTS_MAX_TASK_LABEL_CHARS),
    };
  }
  if (!Array.isArray(task.requiredCapabilities)) {
    return { ok: false, denyReason: "invalid_task", reason: "task.requiredCapabilities must be an array" };
  }
  if (task.requiredCapabilities.length > AGENTS_REQUIRED_CAPABILITY_CAP) {
    return {
      ok: false,
      denyReason: "oversized_task",
      reason:
        "task.requiredCapabilities length " +
        String(task.requiredCapabilities.length) +
        " exceeds cap " +
        String(AGENTS_REQUIRED_CAPABILITY_CAP),
    };
  }
  for (const c of task.requiredCapabilities) {
    if (typeof c !== "string" || c.length === 0) {
      return { ok: false, denyReason: "invalid_task", reason: "requiredCapabilities entries must be non-empty strings" };
    }
  }
  const roles = task.allowedRoles;
  if (roles !== undefined) {
    if (!Array.isArray(roles) || roles.length === 0 || roles.length > 3) {
      return { ok: false, denyReason: "invalid_task", reason: "allowedRoles must be a 1..3 length array" };
    }
    for (const r of roles) {
      if (!ALL_ROLES.includes(r)) {
        return { ok: false, denyReason: "invalid_task", reason: "allowedRoles entries must be planner|builder|reviewer" };
      }
    }
  }
  if (!task.budget || typeof task.budget !== "object") {
    return { ok: false, denyReason: "invalid_task", reason: "task.budget must be an object with maxSteps" };
  }
  const ms = task.budget.maxSteps;
  if (
    typeof ms !== "number" ||
    !Number.isFinite(ms) ||
    ms < 1 ||
    ms > 1000 ||
    Math.floor(ms) !== ms
  ) {
    return { ok: false, denyReason: "invalid_task", reason: "budget.maxSteps must be an integer in [1,1000]" };
  }
  if (task.budget.maxRuntimeMs !== undefined) {
    const rt = task.budget.maxRuntimeMs;
    if (typeof rt !== "number" || !Number.isFinite(rt) || rt < 0 || rt > 3_600_000) {
      return { ok: false, denyReason: "invalid_task", reason: "budget.maxRuntimeMs must be in [0,3600000] if present" };
    }
  }
  if (task.budget.deadlineEpochMs !== undefined) {
    const dl = task.budget.deadlineEpochMs;
    if (typeof dl !== "number" || !Number.isFinite(dl) || dl < 0) {
      return { ok: false, denyReason: "invalid_task", reason: "budget.deadlineEpochMs must be non-negative if present" };
    }
  }
  if (task.riskScore !== undefined) {
    const rs = task.riskScore;
    if (
      typeof rs !== "number" ||
      !Number.isFinite(rs) ||
      rs < 0 ||
      rs > 1 ||
      Math.abs(rs / AGENTS_RISK_SCORE_STEP - Math.round(rs / AGENTS_RISK_SCORE_STEP)) > 1e-9
    ) {
      return {
        ok: false,
        denyReason: "invalid_task",
        reason: "riskScore must be a finite number in [0,1] on the 0.1 grid",
      };
    }
  }
  if (task.note !== undefined && (typeof task.note !== "string" || task.note.length > AGENTS_MAX_TASK_NOTE_CHARS)) {
    return {
      ok: false,
      denyReason: "oversized_task",
      reason: "task.note must be a string ≤ " + String(AGENTS_MAX_TASK_NOTE_CHARS) + " chars if present",
    };
  }
  return { ok: true };
}

/** Validate one availability entry (bounded, fail-closed). */
export function validateAvailability(
  availability: AgentAvailability
): { ok: true } | { ok: false; denyReason: AllocationDenyReason; reason: string } {
  if (!availability || typeof availability !== "object") {
    return { ok: false, denyReason: "invalid_task", reason: "availability entry must be an object" };
  }
  if (typeof availability.available !== "boolean") {
    return { ok: false, denyReason: "invalid_task", reason: "availability.available must be boolean" };
  }
  if (availability.available && availability.reason !== undefined) {
    return { ok: false, denyReason: "invalid_task", reason: "available agents must not carry an unavailability reason" };
  }
  if (!availability.available) {
    if (availability.reason === undefined) {
      return { ok: false, denyReason: "invalid_task", reason: "unavailable agents must carry a reason" };
    }
    if (!KNOWN_UNAVAILABLE_REASONS.includes(availability.reason)) {
      return { ok: false, denyReason: "invalid_task", reason: "unavailability reason must be busy|suspended|offline" };
    }
  }
  if (availability.load !== undefined) {
    const l = availability.load;
    if (typeof l !== "number" || !Number.isFinite(l) || l < 0 || l > 1) {
      return { ok: false, denyReason: "invalid_task", reason: "load must be a finite number in [0,1]" };
    }
  }
  return { ok: true };
}

/** SHA-256 digest of the canonical descriptor serialization (observability). */
export function taskDescriptorDigest(task: TaskDescriptor): string {
  const canonical = JSON.stringify({
    label: task.label,
    requiredCapabilities: [...task.requiredCapabilities].sort(),
    allowedRoles: task.allowedRoles
      ? [...task.allowedRoles].sort()
      : [...ALL_ROLES],
    budget: {
      maxSteps: task.budget.maxSteps,
      maxRuntimeMs: task.budget.maxRuntimeMs ?? null,
      deadlineEpochMs: task.budget.deadlineEpochMs ?? null,
    },
    riskScore: task.riskScore ?? 0,
    note: task.note ?? "",
  });
  return createHash("sha256").update(canonical).digest("hex");
}

export interface AllocateInput {
  /** Registered identity initiating the allocation (non-agent actors allowed). */
  readonly allocatedBy: string;
  readonly task: TaskDescriptor;
  /** Availability view keyed by registered agentId; agents absent = available. */
  readonly availability?: Readonly<Record<string, AgentAvailability>>;
  /** Explicit allocator clock (defaults to the runtime clock). */
  readonly atEpochMs?: number;
}

/**
 * The 19B baseline allocator. Constructed over an AgentRuntime; it reads
 * identities and active-allocation state from the runtime and records
 * assignments back into it. It has no other authority: it cannot execute,
 * cannot authorize, cannot send messages, and cannot mutate identities.
 */
export class TaskAllocator {
  readonly #runtime: AgentRuntime;

  constructor(runtime: AgentRuntime) {
    this.#runtime = runtime;
  }

  get runtime(): AgentRuntime {
    return this.#runtime;
  }

  /**
   * Allocate one task to the best-ranked qualified+available agent.
   * Deterministic for identical inputs (same registry state, availability
   * map, and clock).
   */
  allocate(input: AllocateInput): AllocationResult {
    const at = input.atEpochMs ?? this.#runtime.now();
    const callerCheck = this.#checkCaller(input.allocatedBy);
    if (callerCheck) return this.#deny(callerCheck, at);
    const shape = validateTaskDescriptor(input.task);
    if (!shape.ok) return this.#deny(shape, at);
    const task = input.task;

    const availability = input.availability ?? {};
    const entries = Object.entries(availability);
    if (entries.length > AGENTS_MAX_TASKS) {
      return this.#deny(
        {
          ok: false as const,
          denyReason: "oversized_request" as const,
          reason: "availability map exceeds " + String(AGENTS_MAX_TASKS) + " entries",
        },
        at
      );
    }
    for (const [, av] of entries) {
      const check = validateAvailability(av);
      if (!check.ok) return this.#deny(check, at);
    }

    // Required capabilities must be capability-shaped (registration-time
    // validation lives in identity.ts; the same structural rule here keeps
    // unknown capability strings from silently matching nothing).
    for (const cap of task.requiredCapabilities) {
      if (cap.length === 0 || cap.length > 64) {
        return this.#deny(
          {
            ok: false as const,
            denyReason: "required_capability_unknown" as const,
            reason: "required capability '" + cap + "' is not capability-shaped",
          },
          at
        );
      }
    }

    const identities = this.#runtime.identities();
    if (identities.length === 0) {
      return this.#deny(
        { ok: false as const, denyReason: "no_candidates" as const, reason: "no agents are registered" },
        at
      );
    }

    // Deterministic candidate order: registration order.
    const ordered = [...identities].sort(
      (a, b) => a.registeredAtEpochMs - b.registeredAtEpochMs || a.agentId.localeCompare(b.agentId)
    );

    const activeByAgent = this.#runtime.activeAllocationsByAgent();
    const candidates: AllocationCandidate[] = [];
    for (let i = 0; i < ordered.length; i++) {
      const identity = ordered[i]!;
      const av = availability[identity.agentId];
      const available = av ? av.available : true;
      const missing: string[] = [];
      for (const cap of task.requiredCapabilities) {
        if (!identity.profile.allowedCapabilities.includes(cap)) missing.push(cap);
      }
      const roleOk = task.allowedRoles
        ? (task.allowedRoles as readonly string[]).includes(identity.role)
        : true;
      const declaredSteps = (activeByAgent.get(identity.agentId) ?? []).reduce(
        (sum, view) => sum + view.assignment.budget.maxSteps,
        0
      );
      const headroom = Math.max(0, 1 - Math.min(1, declaredSteps / Math.max(1, task.budget.maxSteps)));
      const activeCount = (activeByAgent.get(identity.agentId) ?? []).length;
      candidates.push({
        agentId: identity.agentId,
        role: identity.role,
        qualified: missing.length === 0 && roleOk,
        missingCapabilities: Object.freeze(missing),
        available,
        unavailableReason: av && !av.available ? av.reason ?? "busy" : null,
        load: av?.load !== undefined ? clampGrid(av.load) : 0,
        budgetHeadroom: headroom,
        atCapacity: activeCount >= AGENTS_MAX_ASSIGNMENTS_PER_AGENT,
        registrationOrder: i,
        selected: false,
      });
    }

    const eligible = candidates.filter((c) => c.qualified && c.available && !c.atCapacity);
    if (eligible.length === 0) {
      const anyQualifiedAvailable = candidates.some((c) => c.qualified && c.available);
      const anyCandidate = candidates.length > 0;
      return this.#deny(
        {
          ok: false as const,
          denyReason: (
            anyQualifiedAvailable
              ? "oversized_request" // everyone eligible is at capacity
              : anyCandidate
                ? "no_qualified_agent"
                : "no_candidates"
          ) as AllocationDenyReason,
          reason: anyQualifiedAvailable
            ? "all qualified+available agents hold the per-agent cap of active assignments ("
              + String(AGENTS_MAX_ASSIGNMENTS_PER_AGENT)
              + "); capacity is exhausted"
            : anyCandidate
              ? "no qualified+available agent covers the required capabilities/roles; unqualified agents are never selected"
              : "no registered agents matched the task scope",
        },
        at
      );
    }

    eligible.sort((a, b) => {
      const ar = taskRiskOf(task, a);
      const br = taskRiskOf(task, b);
      if (ar !== br) return ar - br; // risk ascending
      if (b.budgetHeadroom !== a.budgetHeadroom) return b.budgetHeadroom - a.budgetHeadroom; // headroom desc
      if (a.load !== b.load) return a.load - b.load; // load asc
      return a.registrationOrder - b.registrationOrder; // stable final tie-break
    });

    const winner = eligible[0]!;
    const winnerIndex = candidates.indexOf(winner);
    candidates[winnerIndex] = { ...winner, selected: true };

    const activeCount = this.#runtime.activeAllocationCount();
    if (activeCount >= AGENTS_MAX_ALLOCATIONS) {
      return this.#deny(
        {
          ok: false as const,
          denyReason: "oversized_request" as const,
          reason: "active allocation cap reached (" + String(AGENTS_MAX_ALLOCATIONS) + ")",
        },
        at
      );
    }

    // 19E fix: the sequence must be the runtime's monotone allocation
    // counter (incremented per recorded allocation), NOT the active count —
    // deriving ids from the active count reuses ids after cancellation and
    // collides with history records.
    const sequence = this.#runtime.allocationSequence() + 1;
    const assignment: TaskAssignment = Object.freeze({
      assignmentId:
        "asg-" +
        String(sequence).padStart(6, "0") +
        "-" +
        taskDescriptorDigest(task).slice(0, 12),
      schemaVersion: ALLOCATION_SCHEMA_VERSION,
      taskLabel: task.label,
      assignedAgentId: winner.agentId,
      assignedRole: winner.role,
      allocatedAtEpochMs: at,
      budget: Object.freeze({ ...task.budget }),
      riskScore: task.riskScore ?? 0,
      authority: AUTHORITY,
      executionAuthorized: false,
    });

    const record: AllocationRecord = Object.freeze({
      recordId: "alc-" + String(sequence).padStart(6, "0"),
      assignment,
      allocatedBy: input.allocatedBy,
      allocatedAtEpochMs: at,
      candidateCount: candidates.length,
      consideredAgentIds: Object.freeze(candidates.map((c) => c.agentId)),
      taskDigest: taskDescriptorDigest(task),
      rationale:
        "ranked first of " +
        String(eligible.length) +
        " qualified+available candidate(s): risk " +
        taskRiskOf(task, winner).toFixed(1) +
        ", headroom " +
        winner.budgetHeadroom.toFixed(2) +
        ", load " +
        winner.load.toFixed(1) +
        ", order " +
        String(winner.registrationOrder),
      authority: AUTHORITY,
      executionAuthorized: false,
    });

    this.#runtime.recordAllocation(record, candidates);

    return { ok: true, assignment, record, candidates: Object.freeze(candidates) };
  }

  /** Record a bounded lifecycle status on an active assignment. */
  recordStatus(
    assignmentId: string,
    status: AllocationStatusEvent["status"],
    note?: string,
    atEpochMs?: number
  ): { ok: true; event: AllocationStatusEvent } | { ok: false; reason: string } {
    if (status === "assigned") {
      return { ok: false, reason: "status 'assigned' is set only by allocate()" };
    }
    if (note !== undefined && (typeof note !== "string" || note.length > AGENTS_MAX_TASK_NOTE_CHARS)) {
      return { ok: false, reason: "note must be a string ≤ " + String(AGENTS_MAX_TASK_NOTE_CHARS) + " chars" };
    }
    return this.#runtime.recordAllocationStatus(assignmentId, status, note, atEpochMs ?? this.#runtime.now());
  }

  /** Observable active-allocation view (read-only). */
  activeAllocations(): readonly ActiveAllocationView[] {
    return this.#runtime.activeAllocations();
  }

  /** Observable append-only allocation history (read-only). */
  history(): readonly AllocationRecord[] {
    return this.#runtime.allocationHistory();
  }

  #checkCaller(allocatedBy: string): { ok: false; denyReason: AllocationDenyReason; reason: string } | null {
    if (typeof allocatedBy !== "string" || allocatedBy.length === 0 || allocatedBy.length > 64) {
      return { ok: false as const, denyReason: "allocator_unknown", reason: "allocatedBy must be a non-empty string ≤64 chars" };
    }
    const identity = this.#runtime.identity(allocatedBy);
    if (identity && identity.agentId !== allocatedBy) {
      return { ok: false as const, denyReason: "allocator_unknown", reason: "identity lookup mismatch" };
    }
    return null;
  }

  #deny(
    d: { ok: false; denyReason: AllocationDenyReason; reason: string },
    _at: number
  ): AllocationDenial {
    void _at;
    return {
      ok: false,
      schemaVersion: ALLOCATION_SCHEMA_VERSION,
      denyReason: d.denyReason,
      reason: d.reason,
    };
  }
}

function taskRiskOf(task: TaskDescriptor, _c: AllocationCandidate): number {
  void _c;
  return task.riskScore ?? 0;
}

function clampGrid(value: number): number {
  const snapped = Math.round(value / AGENTS_RISK_SCORE_STEP) * AGENTS_RISK_SCORE_STEP;
  return Math.min(1, Math.max(0, Number(snapped.toFixed(1))));
}
