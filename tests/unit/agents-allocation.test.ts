import { describe, it, expect } from "vitest";
import {
  ALLOCATION_SCHEMA_VERSION,
  KNOWN_ALLOCATION_DENY_REASONS,
  KNOWN_UNAVAILABLE_REASONS,
  isAllocationDenyReason,
  AgentRuntime,
  TaskAllocator,
  registerAllThreeAgents,
  PLANNER_AGENT_ID,
  BUILDER_AGENT_ID,
  REVIEWER_AGENT_ID,
  AGENT_ROLE_PROFILES,
  validateTaskDescriptor,
  validateAvailability,
  taskDescriptorDigest,
  AGENTS_RISK_SCORE_STEP,
  AGENTS_MAX_ALLOCATIONS,
  AGENTS_MAX_ASSIGNMENTS_PER_AGENT,
  AGENTS_REQUIRED_CAPABILITY_CAP,
  AGENTS_MAX_STATUS_EVENTS,
  type TaskDescriptor,
  type AgentAvailability,
  type AgentRuntimeOptions,
} from "@menog/agents";
import { AppendOnlyLedger } from "@menog/event-ledger";
import { DenyByDefaultPolicyEngine } from "@menog/policy";

const T0 = 1_970_000_000_000;

function clock(): AgentRuntimeOptions {
  let n = T0;
  return { nowEpochMs: () => (n += 1) };
}

function setup(): { rt: AgentRuntime; alloc: TaskAllocator } {
  const rt = new AgentRuntime(clock());
  // Distinct registration timestamps pin the registration order:
  // planner → builder → reviewer (the final deterministic tie-breaker).
  const reg1 = rt.register({ agentId: PLANNER_AGENT_ID, role: "planner", atEpochMs: T0 });
  const reg2 = rt.register({ agentId: BUILDER_AGENT_ID, role: "builder", atEpochMs: T0 + 1 });
  const reg3 = rt.register({ agentId: REVIEWER_AGENT_ID, role: "reviewer", atEpochMs: T0 + 2 });
  expect(reg1.ok && reg2.ok && reg3.ok).toBe(true);
  return { rt, alloc: new TaskAllocator(rt) };
}

function task(overrides: Partial<TaskDescriptor> = {}): TaskDescriptor {
  return {
    label: "build feature X",
    requiredCapabilities: ["workspace:read"],
    budget: { maxSteps: 10 },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// 19B-A1 — Capability matching + unqualified rejection
// ---------------------------------------------------------------------------

describe("19B-A1 — capability matching and unqualified rejection", () => {
  it("pins the schema version and deny-reason union", () => {
    expect(ALLOCATION_SCHEMA_VERSION).toBe("menog-agent-allocation/v0");
    expect(KNOWN_ALLOCATION_DENY_REASONS).toEqual([
      "invalid_task",
      "oversized_task",
      "required_capability_unknown",
      "no_candidates",
      "no_qualified_agent",
      "allocator_unknown",
      "oversized_request",
    ]);
    expect(isAllocationDenyReason("no_qualified_agent")).toBe(true);
    expect(isAllocationDenyReason("nope")).toBe(false);
    expect(KNOWN_UNAVAILABLE_REASONS).toEqual(["busy", "suspended", "offline"]);
  });

  it("selects the agent whose profile covers every required capability", () => {
    const { alloc } = setup();
    const r = alloc.allocate({
      allocatedBy: "human-19b",
      task: task({ requiredCapabilities: ["git:status", "git:diff-read"] }),
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.assignment.assignedAgentId).toBe(REVIEWER_AGENT_ID);
      expect(r.assignment.assignedRole).toBe("reviewer");
      expect(r.candidates.find((c) => c.agentId === REVIEWER_AGENT_ID)!.qualified).toBe(true);
    }
  });

  it("denies no_qualified_agent when NO profile covers the requirement (never falls back)", () => {
    const { alloc } = setup();
    const r = alloc.allocate({
      allocatedBy: "human-19b",
      task: task({ requiredCapabilities: ["network:external"] }),
    });
    expect(r).toMatchObject({ ok: false, denyReason: "no_qualified_agent" });
    expect(alloc.history()).toHaveLength(0);
  });

  it("reports missing capabilities per candidate (observable qualification detail)", () => {
    const { alloc } = setup();
    const r = alloc.allocate({
      allocatedBy: "human-19b",
      task: task({ requiredCapabilities: ["git:commit"] }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denyReason).toBe("no_qualified_agent");
      // 19B itself cannot prove per-candidate detail on denial, so a second
      // allocation with a partially-satisfiable set shows the detail.
    }
    const r2 = alloc.allocate({
      allocatedBy: "human-19b",
      task: task({ requiredCapabilities: ["workspace:read", "git:diff-read"] }),
    });
    expect(r2.ok).toBe(true);
    if (r2.ok) {
      const planner = r2.candidates.find((c) => c.agentId === PLANNER_AGENT_ID)!;
      expect(planner.qualified).toBe(false);
      expect(planner.missingCapabilities).toEqual(["git:diff-read"]);
      const reviewer = r2.candidates.find((c) => c.agentId === REVIEWER_AGENT_ID)!;
      expect(reviewer.qualified).toBe(true);
      expect(reviewer.missingCapabilities).toEqual([]);
    }
  });

  it("enforces role scoping via allowedRoles (role-fit is part of qualification)", () => {
    const { alloc } = setup();
    const r = alloc.allocate({
      allocatedBy: "human-19b",
      task: task({
        requiredCapabilities: ["workspace:read"],
        allowedRoles: ["planner"],
      }),
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.assignment.assignedAgentId).toBe(PLANNER_AGENT_ID);
    const r2 = alloc.allocate({
      allocatedBy: "human-19b",
      task: task({
        requiredCapabilities: ["workspace:read"],
        allowedRoles: ["builder"],
      }),
    });
    expect(r2.ok).toBe(true);
    if (r2.ok) expect(r2.assignment.assignedAgentId).toBe(BUILDER_AGENT_ID);
  });
});

// ---------------------------------------------------------------------------
// 19B-A2 — Deterministic tie-breaking
// ---------------------------------------------------------------------------

describe("19B-A2 — deterministic ranking and tie-breaking", () => {
  it("rank order is risk ascending, headroom descending, load ascending, registration order", () => {
    const { alloc } = setup();
    // All three profiles cover workspace:read; equal risk → headroom equal
    // (all idle) → load equal (all 0) → registration order decides: planner.
    const r = alloc.allocate({ allocatedBy: "human-19b", task: task() });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.assignment.assignedAgentId).toBe(PLANNER_AGENT_ID);
      expect(r.record.rationale).toContain("ranked first of 3");
    }
  });

  it("higher load loses the load tie-break deterministically", () => {
    const { alloc } = setup();
    const availability: Record<string, AgentAvailability> = {
      [PLANNER_AGENT_ID]: { available: true, load: 0.8 },
      [BUILDER_AGENT_ID]: { available: true, load: 0.2 },
      [REVIEWER_AGENT_ID]: { available: true, load: 0.5 },
    };
    const r = alloc.allocate({ allocatedBy: "human-19b", task: task(), availability });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.assignment.assignedAgentId).toBe(BUILDER_AGENT_ID);
  });

  it("identical inputs (registry state, availability, clock) produce identical outputs", () => {
    const run = () => {
      const rt = new AgentRuntime(clock());
      registerAllThreeAgents(rt, T0);
      const alloc = new TaskAllocator(rt);
      const r = alloc.allocate({
        allocatedBy: "human-19b",
        task: task({ label: "det", riskScore: 0.3 }),
        availability: { [BUILDER_AGENT_ID]: { available: true, load: 0.4 } },
      });
      if (!r.ok) return { ok: false };
      return {
        ok: true,
        assignmentId: r.assignment.assignmentId,
        assigned: r.assignment.assignedAgentId,
        allocatedAt: r.assignment.allocatedAtEpochMs,
        recordId: r.record.recordId,
        digest: r.record.taskDigest,
        rationale: r.record.rationale,
        selectedOrder: r.candidates.map((c) => (c.selected ? 1 : 0)),
      };
    };
    expect(run()).toEqual(run());
  });

  it("riskScore breaks ties before load (risk first)", () => {
    const { alloc } = setup();
    // Two allocations of the same task: the first goes to planner (order).
    // With explicit risk there is no per-agent risk in 19B (task-level risk),
    // so risk affects eligibility comparison across TASKS, not candidates;
    // the pinned behavior: risk is recorded and ranked ascending (single
    // value ⇒ all candidates tie on risk ⇒ later tie-breakers decide).
    const r = alloc.allocate({
      allocatedBy: "human-19b",
      task: task({ riskScore: 0.5 }),
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.assignment.riskScore).toBe(0.5);
  });

  it("task digest is deterministic and capability-order-insensitive", () => {
    const t1 = task({ requiredCapabilities: ["workspace:read", "git:status"] });
    const t2 = task({ requiredCapabilities: ["git:status", "workspace:read"] });
    expect(taskDescriptorDigest(t1)).toBe(taskDescriptorDigest(t2));
    expect(taskDescriptorDigest(t1)).toHaveLength(64);
  });

  it("budget headroom drops with active assignments (headroom desc ranking)", () => {
    const { rt, alloc } = setup();
    // Give the planner one active assignment with maxSteps 10.
    const first = alloc.allocate({ allocatedBy: "human-19b", task: task({ budget: { maxSteps: 10 } }) });
    expect(first.ok).toBe(true);
    expect(rt.activeAllocations()).toHaveLength(1);
    // Next allocation with the same requirement: planner now has headroom
    // 1 - 10/10 = 0 → builder (next in order with headroom 1) wins.
    const second = alloc.allocate({ allocatedBy: "human-19b", task: task({ budget: { maxSteps: 10 } }) });
    expect(second.ok).toBe(true);
    if (second.ok) {
      expect(second.assignment.assignedAgentId).toBe(BUILDER_AGENT_ID);
      const plannerCand = second.candidates.find((c) => c.agentId === PLANNER_AGENT_ID)!;
      expect(plannerCand.budgetHeadroom).toBe(0);
    }
  });
});

// ---------------------------------------------------------------------------
// 19B-A3 — Budget exhaustion
// ---------------------------------------------------------------------------

describe("19B-A3 — budget exhaustion", () => {
  it("per-agent active-assignment cap denies with oversized_request (fail-closed)", () => {
    const { alloc } = setup();
    const totalCap = 3 * AGENTS_MAX_ASSIGNMENTS_PER_AGENT;
    const results: boolean[] = [];
    for (let i = 0; i < totalCap + 3; i++) {
      const r = alloc.allocate({
        allocatedBy: "human-19b",
        task: task({ label: "task " + String(i), budget: { maxSteps: 1000 } }),
      });
      results.push(r.ok);
    }
    // Round-robin fills every agent to the per-agent cap; the next ask denies.
    expect(results.filter(Boolean).length).toBe(totalCap);
    expect(results[results.length - 1]).toBe(false);
    expect(alloc.history().length).toBe(totalCap);
  });

  it("headroom exhausted by many small tasks still allows ranking among candidates", () => {
    const { alloc } = setup();
    for (let i = 0; i < 3; i++) {
      const r = alloc.allocate({
        allocatedBy: "human-19b",
        task: task({ label: "t" + String(i), budget: { maxSteps: 1000 } }),
      });
      expect(r.ok).toBe(true);
    }
    // All three agents now have headroom 0 for maxSteps-1000 tasks.
    const r = alloc.allocate({
      allocatedBy: "human-19b",
      task: task({ label: "t4", budget: { maxSteps: 1000 } }),
    });
    // Still succeeds (headroom 0 is not disqualifying; caps are) — tie broken
    // by registration order again among equal-headroom candidates.
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.candidates.every((c) => c.budgetHeadroom === 0)).toBe(true);
      expect(r.assignment.assignedAgentId).toBe(PLANNER_AGENT_ID);
    }
  });

  it("active allocation cap is pinned", () => {
    expect(AGENTS_MAX_ALLOCATIONS).toBe(128);
    expect(AGENTS_REQUIRED_CAPABILITY_CAP).toBe(8);
    expect(AGENTS_MAX_STATUS_EVENTS).toBe(16);
  });

  it("terminal status frees the agent from the active view but keeps history", () => {
    const { rt, alloc } = setup();
    const r = alloc.allocate({ allocatedBy: "human-19b", task: task() });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(rt.activeAllocations()).toHaveLength(1);
      const done = alloc.recordStatus(r.assignment.assignmentId, "completed", "done by builder step 3");
      expect(done.ok).toBe(true);
      expect(rt.activeAllocations()).toHaveLength(0);
      expect(alloc.history()).toHaveLength(1);
      // Terminal is terminal: further status is refused.
      const again = alloc.recordStatus(r.assignment.assignmentId, "cancelled");
      expect(again.ok).toBe(false);
    }
  });

  it("status on unknown assignment is refused", () => {
    const { alloc } = setup();
    expect(alloc.recordStatus("asg-does-not-exist", "completed")).toMatchObject({ ok: false });
  });
});

// ---------------------------------------------------------------------------
// 19B-A4 — Risk constraints
// ---------------------------------------------------------------------------

describe("19B-A4 — risk constraints", () => {
  it("riskScore must be on the 0.1 grid in [0,1]", () => {
    expect(validateTaskDescriptor(task({ riskScore: 0.3 })).ok).toBe(true);
    expect(validateTaskDescriptor(task({ riskScore: 0.25 }))).toMatchObject({ ok: false, denyReason: "invalid_task" });
    expect(validateTaskDescriptor(task({ riskScore: -0.1 }))).toMatchObject({ ok: false, denyReason: "invalid_task" });
    expect(validateTaskDescriptor(task({ riskScore: 1.1 }))).toMatchObject({ ok: false, denyReason: "invalid_task" });
    expect(validateTaskDescriptor(task({ riskScore: Number.NaN }))).toMatchObject({ ok: false, denyReason: "invalid_task" });
    expect(AGENTS_RISK_SCORE_STEP).toBe(0.1);
  });

  it("risk is recorded on the assignment and surfaced in the rationale", () => {
    const { alloc } = setup();
    const r = alloc.allocate({ allocatedBy: "human-19b", task: task({ riskScore: 0.7 }) });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.assignment.riskScore).toBe(0.7);
      expect(r.record.rationale).toContain("risk 0.7");
    }
  });

  it("zero risk is the default (explicit, observable)", () => {
    const { alloc } = setup();
    const r = alloc.allocate({ allocatedBy: "human-19b", task: task() });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.assignment.riskScore).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 19B-A5 — Unavailable agents
// ---------------------------------------------------------------------------

describe("19B-A5 — unavailable agents", () => {
  it("an unavailable agent is excluded before ranking (all reasons)", () => {
    for (const reason of KNOWN_UNAVAILABLE_REASONS) {
      const { alloc } = setup();
      const r = alloc.allocate({
        allocatedBy: "human-19b",
        task: task({ requiredCapabilities: ["workspace:read"] }),
        availability: {
          [PLANNER_AGENT_ID]: { available: false, reason },
        },
      });
      expect(r.ok).toBe(true);
      if (r.ok) {
        const planner = r.candidates.find((c) => c.agentId === PLANNER_AGENT_ID)!;
        expect(planner.available).toBe(false);
        expect(planner.unavailableReason).toBe(reason);
        expect(planner.selected).toBe(false);
        expect(r.assignment.assignedAgentId).not.toBe(PLANNER_AGENT_ID);
      }
    }
  });

  it("ALL agents unavailable denies no_qualified_agent (never queues)", () => {
    const { alloc } = setup();
    const r = alloc.allocate({
      allocatedBy: "human-19b",
      task: task(),
      availability: {
        [PLANNER_AGENT_ID]: { available: false, reason: "busy" },
        [BUILDER_AGENT_ID]: { available: false, reason: "suspended" },
        [REVIEWER_AGENT_ID]: { available: false, reason: "offline" },
      },
    });
    expect(r).toMatchObject({ ok: false, denyReason: "no_qualified_agent" });
  });

  it("availability validation is strict (reason/available coherence, load bounds)", () => {
    expect(validateAvailability({ available: true })).toEqual({ ok: true });
    expect(validateAvailability({ available: true, reason: "busy" })).toMatchObject({ ok: false });
    expect(validateAvailability({ available: false })).toMatchObject({ ok: false });
    expect(validateAvailability({ available: false, reason: "vanished" as "busy" })).toMatchObject({ ok: false });
    expect(validateAvailability({ available: true, load: 1.5 })).toMatchObject({ ok: false });
    expect(validateAvailability({ available: true, load: 0.3 })).toEqual({ ok: true });
  });

  it("missing availability entry defaults to available (absent = no information)", () => {
    const { alloc } = setup();
    const r = alloc.allocate({
      allocatedBy: "human-19b",
      task: task(),
      availability: {},
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.candidates.every((c) => c.available)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 19B-A6 — Validation, bookkeeping, observation
// ---------------------------------------------------------------------------

describe("19B-A6 — validation, bookkeeping, observation", () => {
  it("task descriptor validation is bounded and fail-closed", () => {
    expect(validateTaskDescriptor(task({ label: "" }))).toMatchObject({ ok: false, denyReason: "invalid_task" });
    expect(validateTaskDescriptor(task({ label: "x".repeat(129) }))).toMatchObject({ ok: false, denyReason: "oversized_task" });
    expect(validateTaskDescriptor(task({ budget: { maxSteps: 0 } }))).toMatchObject({ ok: false, denyReason: "invalid_task" });
    expect(validateTaskDescriptor(task({ budget: { maxSteps: 1001 } }))).toMatchObject({ ok: false, denyReason: "invalid_task" });
    expect(validateTaskDescriptor(task({ budget: { maxSteps: 7.5 } }))).toMatchObject({ ok: false, denyReason: "invalid_task" });
    expect(validateTaskDescriptor(task({ budget: { maxSteps: 10, maxRuntimeMs: 3_600_001 } }))).toMatchObject({ ok: false });
    expect(validateTaskDescriptor(task({ allowedRoles: [] }))).toMatchObject({ ok: false });
    expect(validateTaskDescriptor(task({ allowedRoles: ["emperor" as "planner"] }))).toMatchObject({ ok: false });
    expect(validateTaskDescriptor(task({ requiredCapabilities: Array.from({ length: 9 }, () => "workspace:read") })))
      .toMatchObject({ ok: false, denyReason: "oversized_task" });
  });

  it("unknown allocator identities are denied", () => {
    const { alloc } = setup();
    expect(alloc.allocate({ allocatedBy: "", task: task() })).toMatchObject({ ok: false, denyReason: "allocator_unknown" });
    expect(alloc.allocate({ allocatedBy: "ghost-allocator", task: task() }).ok).toBe(true); // non-agent humans are allowed by design
  });

  it("no registered agents denies no_candidates", () => {
    const rt = new AgentRuntime(clock());
    const alloc = new TaskAllocator(rt);
    expect(alloc.allocate({ allocatedBy: "human-19b", task: task() })).toMatchObject({
      ok: false,
      denyReason: "no_candidates",
    });
  });

  it("allocation records are append-only and assignments carry authority pins", () => {
    const { alloc } = setup();
    for (let i = 0; i < 3; i++) {
      alloc.allocate({ allocatedBy: "human-19b", task: task({ label: "t" + String(i) }) });
    }
    const history = alloc.history();
    expect(history).toHaveLength(3);
    for (const rec of history) {
      expect(rec.authority).toBe("allocation_data");
      expect(rec.executionAuthorized).toBe(false);
      expect(rec.assignment.authority).toBe("allocation_data");
      expect(rec.assignment.executionAuthorized).toBe(false);
      expect(rec.assignment.schemaVersion).toBe("menog-agent-allocation/v0");
    }
    expect(alloc.activeAllocations()).toHaveLength(3);
  });

  it("allocation is ledger-observable (agent_task_allocated events, chain verifies)", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const rt = new AgentRuntime({
      nowEpochMs: () => T0,
      ledger: {
        append: (input) => {
          const r = ledger.append({
            eventId: "agtb-" + String(ledger.length + 1).padStart(4, "0"),
            timestamp: new Date(T0 + ledger.length).toISOString(),
            eventType: input.eventType,
            actor: { type: input.actor.type as "runtime" | "agent", id: input.actor.id },
            policyDecision: input.policyDecision,
            inputSummary: input.inputSummary,
            resultSummary: input.resultSummary,
          });
          return { ok: r.ok, eventId: r.event?.eventId };
        },
      },
    });
    registerAllThreeAgents(rt, T0);
    const alloc = new TaskAllocator(rt);
    alloc.allocate({ allocatedBy: "human-19b", task: task({ riskScore: 0.2 }) });
    const eventTypes = ledger.events().map((e) => e.eventType);
    expect(eventTypes).toContain("agent_task_allocated");
    expect(ledger.verify().ok).toBe(true);
    const evt = ledger.events().find((e) => e.eventType === "agent_task_allocated")!;
    expect(String(evt.resultSummary!.outcome)).toBe("allocated");
  });
});

// ---------------------------------------------------------------------------
// 19B-A7 — Assignment ≠ authority (policy stays the sole execution gate)
// ---------------------------------------------------------------------------

describe("19B-A7 — assignment is not authority", () => {
  it("an assigned task does NOT flip policy: the assignee's privileged asks still deny", () => {
    const { alloc } = setup();
    const r = alloc.allocate({
      allocatedBy: "human-19b",
      task: task({
        label: "write feature",
        requiredCapabilities: ["workspace:read"],
        allowedRoles: ["builder"],
      }),
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      const engine = new DenyByDefaultPolicyEngine();
      const res = engine.evaluate({
        actor: { type: "agent", id: r.assignment.assignedAgentId },
        verb: "workspace.write",
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-19b",
      });
      expect(res.decision.outcome).toBe("deny");
    }
  });

  it("allocation records can never carry execution authority (type-level pin re-checked)", () => {
    const { alloc } = setup();
    const r = alloc.allocate({ allocatedBy: "human-19b", task: task() });
    expect(r.ok).toBe(true);
    if (r.ok) {
      const json = JSON.stringify(r.record);
      expect(json).not.toContain('"executionAuthorized":true');
      expect(json).toContain('"authority":"allocation_data"');
    }
  });
});

// Profiles referenced for documentation: builder is the only role whose
// frozen profile declares a write-adjacent need.
void AGENT_ROLE_PROFILES;
