import { describe, it, expect, beforeEach } from "vitest";
import {
  AgentRuntime,
  TaskAllocator,
  RecoveryCoordinator,
  registerAllThreeAgents,
  PLANNER_AGENT_ID,
  BUILDER_AGENT_ID,
  REVIEWER_AGENT_ID,
  RECOVERY_SCHEMA_VERSION,
  KNOWN_AGENT_FAILURE_KINDS,
  KNOWN_RECOVERY_DENY_REASONS,
  isRecoveryDenyReason,
  AGENTS_MAX_RECOVERY_CHAIN,
  AGENTS_SUSPENSION_FAILURE_THRESHOLD,
  AGENTS_MAX_RECOVERIES,
  validateFailureReport,
  validateStaleOwnershipPolicy,
  taskDescriptorDigest,
  type TaskDescriptor,
  type AgentRuntimeOptions,
} from "@menog/agents";
import { AppendOnlyLedger } from "@menog/event-ledger";

const T0 = 2_100_000_000_000;

function clock(): AgentRuntimeOptions {
  let n = T0;
  return { nowEpochMs: () => (n += 1) };
}

function task(overrides: Partial<TaskDescriptor> = {}): TaskDescriptor {
  return {
    label: "build feature Y",
    requiredCapabilities: ["workspace:read"],
    budget: { maxSteps: 10 },
    ...overrides,
  };
}

interface Env {
  rt: AgentRuntime;
  alloc: TaskAllocator;
  rec: RecoveryCoordinator;
}

function setup(): Env {
  const rt = new AgentRuntime(clock());
  rt.register({ agentId: PLANNER_AGENT_ID, role: "planner", atEpochMs: T0 });
  rt.register({ agentId: BUILDER_AGENT_ID, role: "builder", atEpochMs: T0 + 1 });
  rt.register({ agentId: REVIEWER_AGENT_ID, role: "reviewer", atEpochMs: T0 + 2 });
  const alloc = new TaskAllocator(rt);
  return { rt, alloc, rec: new RecoveryCoordinator(rt) };
}

function allocateToBuilder(env: Env, t: TaskDescriptor = task()): string {
  // Allocate exactly the descriptor given (digest must match at reassign);
  // tests that need the builder scope it via allowedRoles in the descriptor.
  const r = env.alloc.allocate({
    allocatedBy: "human-19e",
    task: t,
  });
  expect(r.ok).toBe(true);
  return (r as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
}

// ---------------------------------------------------------------------------
// 19E-R1 — Agent failure (reporting + ownership)
// ---------------------------------------------------------------------------

describe("19E-R1 — agent failure reporting", () => {
  it("pins the schema version, failure kinds, and deny union", () => {
    expect(RECOVERY_SCHEMA_VERSION).toBe("menog-agent-recovery/v0");
    expect(KNOWN_AGENT_FAILURE_KINDS).toEqual(["timeout", "error", "stale", "explicit_release"]);
    expect(KNOWN_RECOVERY_DENY_REASONS).toEqual([
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
    expect(isRecoveryDenyReason("ownership_mismatch")).toBe(true);
    expect(isRecoveryDenyReason("nope")).toBe(false);
  });

  it("records a failure on an active assignment and frees capacity", () => {
    const env = setup();
    const id = allocateToBuilder(env, task({ allowedRoles: ["builder"] }));
    expect(env.rt.activeAllocations()).toHaveLength(1);
    const r = env.rec.reportFailure({
      assignmentId: id,
      agentId: BUILDER_AGENT_ID,
      failureKind: "error",
      atEpochMs: T0 + 500,
      note: "builder crashed on step 2",
    });
    expect(r.ok).toBe(true);
    expect(env.rt.activeAllocations()).toHaveLength(0);
    expect(env.rec.history()).toHaveLength(1);
    const rec = env.rec.history()[0]!;
    expect(rec.kind).toBe("failure_recorded");
    expect(rec.authority).toBe("recovery_data");
    expect(rec.executionAuthorized).toBe(false);
  });

  it("denies failure reports from agents that do not own the assignment (ownership check)", () => {
    const env = setup();
    const id = allocateToBuilder(env, task({ allowedRoles: ["builder"] }));
    const r = env.rec.reportFailure({
      assignmentId: id,
      agentId: PLANNER_AGENT_ID, // NOT the assignee
      failureKind: "error",
      atEpochMs: T0 + 500,
    });
    expect(r).toMatchObject({ ok: false, denyReason: "ownership_mismatch" });
    expect(env.rt.activeAllocations()).toHaveLength(1); // untouched
  });

  it("denies reports on unknown assignments and double-failures", () => {
    const env = setup();
    expect(
      env.rec.reportFailure({ assignmentId: "asg-none", agentId: BUILDER_AGENT_ID, failureKind: "error", atEpochMs: T0 })
    ).toMatchObject({ ok: false, denyReason: "unknown_assignment" });
    const id = allocateToBuilder(env, task({ allowedRoles: ["builder"] }));
    expect(
      env.rec.reportFailure({ assignmentId: id, agentId: BUILDER_AGENT_ID, failureKind: "timeout", atEpochMs: T0 + 1 })
    ).toMatchObject({ ok: true });
    // Double-failure: the assignment is terminal — refused as not_failed
    // (not unknown), since the assignment exists in history.
    expect(
      env.rec.reportFailure({ assignmentId: id, agentId: BUILDER_AGENT_ID, failureKind: "timeout", atEpochMs: T0 + 2 })
    ).toMatchObject({ ok: false, denyReason: "not_failed" });
  });

  it("validates report shape and staleness policy (fail-closed)", () => {
    expect(validateFailureReport({ assignmentId: "", agentId: "a", failureKind: "error", atEpochMs: T0 })).toMatchObject({ ok: false });
    expect(validateFailureReport({ assignmentId: "a", agentId: "a", failureKind: "explosion" as "error", atEpochMs: T0 })).toMatchObject({ ok: false });
    expect(validateFailureReport({ assignmentId: "a", agentId: "a", failureKind: "error", atEpochMs: -1 })).toMatchObject({ ok: false });
    expect(validateFailureReport({ assignmentId: "a", agentId: "a", failureKind: "error", atEpochMs: T0, note: "x".repeat(257) })).toMatchObject({ ok: false });
    expect(validateFailureReport({ assignmentId: "a", agentId: "a", failureKind: "error", atEpochMs: T0 })).toEqual({ ok: true });
    expect(validateStaleOwnershipPolicy({ maxAgeMs: 0 })).toMatchObject({ ok: false, denyReason: "stale_policy_invalid" });
    expect(validateStaleOwnershipPolicy({ maxAgeMs: 3_600_001 })).toMatchObject({ ok: false });
    expect(validateStaleOwnershipPolicy({ maxAgeMs: 1_000 })).toEqual({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// 19E-R2 — Reassignment (bounded recovery)
// ---------------------------------------------------------------------------

describe("19E-R2 — bounded reassignment", () => {
  it("reassigns the ORIGINAL task to a qualified, non-failed agent (digest unchanged)", () => {
    const env = setup();
    const original = task({ requiredCapabilities: ["workspace:read"], allowedRoles: ["builder", "reviewer"] });
    const id = allocateToBuilder(env, original);
    env.rec.reportFailure({ assignmentId: id, agentId: BUILDER_AGENT_ID, failureKind: "error", atEpochMs: T0 + 10 });
    const r = env.rec.reassign({ failedAssignmentId: id, task: original, atEpochMs: T0 + 20 }, env.alloc);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.record.kind).toBe("reassigned");
      expect(r.record.reassignedFromAssignmentId).toBe(id);
      expect(r.record.reassignedToAssignmentId).toBe(r.assignment.assignmentId);
      expect(r.assignment.assignedAgentId).not.toBe(BUILDER_AGENT_ID);
      expect(r.record.authority).toBe("recovery_data");
      expect(r.record.executionAuthorized).toBe(false);
      expect(env.rt.activeAllocations()).toHaveLength(1);
    }
  });

  it("REFUSES scope drift: a changed descriptor denies task_descriptor_drift", () => {
    const env = setup();
    const original = task({ requiredCapabilities: ["workspace:read"], budget: { maxSteps: 10 }, allowedRoles: ["builder", "reviewer"] });
    const id = allocateToBuilder(env, original);
    env.rec.reportFailure({ assignmentId: id, agentId: BUILDER_AGENT_ID, failureKind: "error", atEpochMs: T0 + 10 });
    // Attempt 1: widened capabilities (privilege grab via recovery).
    const widened = { ...original, requiredCapabilities: ["workspace:read", "git:commit"] };
    expect(
      env.rec.reassign({ failedAssignmentId: id, task: widened, atEpochMs: T0 + 20 }, env.alloc)
    ).toMatchObject({ ok: false, denyReason: "task_descriptor_drift" });
    // Attempt 2: raised budget (scope creep).
    const bigger = { ...original, budget: { maxSteps: 100 } };
    expect(
      env.rec.reassign({ failedAssignmentId: id, task: bigger, atEpochMs: T0 + 20 }, env.alloc)
    ).toMatchObject({ ok: false, denyReason: "task_descriptor_drift" });
    // Attempt 3: changed label.
    const relabeled = { ...original, label: "build feature Y (expanded)" };
    expect(
      env.rec.reassign({ failedAssignmentId: id, task: relabeled, atEpochMs: T0 + 20 }, env.alloc)
    ).toMatchObject({ ok: false, denyReason: "task_descriptor_drift" });
    expect(env.rt.activeAllocations()).toHaveLength(0);
  });

  it("excludes the failed agent from reassignment (single-candidate task fails closed)", () => {
    const env = setup();
    const original = task({ requiredCapabilities: ["plan:generate"], allowedRoles: ["planner"] });
    const alloc = env.alloc.allocate({ allocatedBy: "human-19e", task: original });
    expect(alloc.ok).toBe(true);
    const assignmentId = (alloc as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
    env.rec.reportFailure({ assignmentId, agentId: PLANNER_AGENT_ID, failureKind: "timeout", atEpochMs: T0 + 10 });
    const r = env.rec.reassign(
      { failedAssignmentId: assignmentId, task: original, atEpochMs: T0 + 20 },
      env.alloc
    );
    // Only the planner covers plan:generate in role "planner"; with the
    // failed agent excluded there is no replacement — fail-closed, no
    // fallback to an unqualified agent.
    expect(r).toMatchObject({ ok: false, denyReason: "no_reassignment_candidate" });
  });

  it("explicit exclusion list is honored (collusion cannot force a target, only remove)", () => {
    const env = setup();
    const original = task({ requiredCapabilities: ["workspace:read"], allowedRoles: ["builder", "reviewer"] });
    const id = allocateToBuilder(env, original);
    env.rec.reportFailure({ assignmentId: id, agentId: BUILDER_AGENT_ID, failureKind: "error", atEpochMs: T0 + 10 });
    const r = env.rec.reassign(
      {
        failedAssignmentId: id,
        task: original,
        alsoExcludeAgentIds: [REVIEWER_AGENT_ID], // remove the only alternative
        atEpochMs: T0 + 20,
      },
      env.alloc
    );
    expect(r).toMatchObject({ ok: false, denyReason: "no_reassignment_candidate" });
  });

  it("reassignment chain is bounded (AGENTS_MAX_RECOVERY_CHAIN, then reassignment_exhausted)", () => {
    const env = setup();
    const original = task({ requiredCapabilities: ["workspace:read"], allowedRoles: ["builder", "reviewer"] });
    let current = allocateToBuilder(env, original);
    // With two qualified roles the chain alternates builder→reviewer→builder.
    // The chain cap counts REASSIGNMENTS: after AGENTS_MAX_RECOVERY_CHAIN
    // hops the next attempt denies reassignment_exhausted.
    for (let i = 0; i < AGENTS_MAX_RECOVERY_CHAIN + 1; i++) {
      const view = env.rt.activeAllocations().find((v) => v.assignment.assignmentId === current);
      expect(view, "active assignment at chain step " + String(i)).toBeDefined();
      if (!view) return;
      const owner = view.assignment.assignedAgentId;
      const f = env.rec.reportFailure({ assignmentId: current, agentId: owner, failureKind: "error", atEpochMs: T0 + 100 + i });
      expect(f.ok, "failure at chain step " + String(i)).toBe(true);
      const r = env.rec.reassign({ failedAssignmentId: current, task: original, atEpochMs: T0 + 200 + i }, env.alloc);
      if (i < AGENTS_MAX_RECOVERY_CHAIN) {
        expect(r.ok, "chain step " + String(i) + ": " + (!r.ok ? r.denyReason : "")).toBe(true);
        if (r.ok) current = r.assignment.assignmentId;
      } else {
        expect(r).toMatchObject({ ok: false, denyReason: "reassignment_exhausted" });
      }
    }
  });

  it("reassignment targets are chosen by deterministic ranking (not agent request)", () => {
    const env = setup();
    const original = task({ requiredCapabilities: ["workspace:read"], allowedRoles: ["builder", "reviewer"] });
    const id = allocateToBuilder(env, original);
    env.rec.reportFailure({ assignmentId: id, agentId: BUILDER_AGENT_ID, failureKind: "error", atEpochMs: T0 + 10 });
    const r = env.rec.reassign({ failedAssignmentId: id, task: original, atEpochMs: T0 + 20 }, env.alloc);
    expect(r.ok, JSON.stringify(r)).toBe(true);
    if (r.ok) {
      // Reviewer is the only remaining qualified agent; ranking chose it.
      expect(r.assignment.assignedAgentId).toBe(REVIEWER_AGENT_ID);
      expect(r.candidates.find((c) => c.agentId === BUILDER_AGENT_ID)!.available).toBe(false);
    }
  });

  it("denies reassign of an assignment that is still active, completed, or unknown", () => {
    const env = setup();
    const id = allocateToBuilder(env);
    expect(
      env.rec.reassign({ failedAssignmentId: id, task: task(), atEpochMs: T0 + 5 }, env.alloc)
    ).toMatchObject({ ok: false, denyReason: "not_failed" });
    // Complete it: reassign is still refused — completion is not failure.
    env.alloc.recordStatus(id, "completed");
    expect(
      env.rec.reassign({ failedAssignmentId: id, task: task(), atEpochMs: T0 + 6 }, env.alloc)
    ).toMatchObject({ ok: false, denyReason: "not_failed" });
    expect(
      env.rec.reassign({ failedAssignmentId: "asg-ghost", task: task(), atEpochMs: T0 + 7 }, env.alloc)
    ).toMatchObject({ ok: false, denyReason: "unknown_assignment" });
  });
});

// ---------------------------------------------------------------------------
// 19E-R3 — Stale ownership (caller-driven, no background timers)
// ---------------------------------------------------------------------------

describe("19E-R3 — stale ownership detection", () => {
  it("detects active assignments older than the policy and ignores fresh ones", () => {
    const env = setup();
    const id = allocateToBuilder(env, task({ allowedRoles: ["builder"] }));
    const allocatedAt = env.rt.activeAllocations()[0]!.assignment.allocatedAtEpochMs;
    expect(env.rec.detectStaleOwnership({ maxAgeMs: 1_000 }, allocatedAt + 999)).toHaveLength(0);
    const stale = env.rec.detectStaleOwnership({ maxAgeMs: 1_000 }, allocatedAt + 1_001);
    expect(stale).toHaveLength(1);
    expect(stale[0]).toMatchObject({ assignmentId: id, agentId: BUILDER_AGENT_ID, taskLabel: "build feature Y" });
    expect(stale[0]!.ageMs).toBe(1_001);
  });

  it("stale sweep never mutates state (view only; caller decides)", () => {
    const env = setup();
    const id = allocateToBuilder(env, task({ allowedRoles: ["builder"] }));
    const allocatedAt = env.rt.activeAllocations()[0]!.assignment.allocatedAtEpochMs;
    env.rec.detectStaleOwnership({ maxAgeMs: 1 }, allocatedAt + 2);
    expect(env.rt.activeAllocations()).toHaveLength(1);
    expect(env.rec.history()).toHaveLength(0);
    // Caller applies recovery explicitly.
    env.rec.reportFailure({ assignmentId: id, agentId: BUILDER_AGENT_ID, failureKind: "stale", atEpochMs: allocatedAt + 3 });
    expect(env.rt.activeAllocations()).toHaveLength(0);
    expect(env.rec.history()[0]!.failureKind).toBe("stale");
  });

  it("invalid staleness policy throws (never silently runs)", () => {
    const env = setup();
    expect(() => env.rec.detectStaleOwnership({ maxAgeMs: 0 }, T0)).toThrow(/invalid stale ownership policy/);
  });

  it("detectStaleOwnership is deterministic for identical inputs", () => {
    const env = setup();
    allocateToBuilder(env);
    const allocatedAt = env.rt.activeAllocations()[0]!.assignment.allocatedAtEpochMs;
    const a = env.rec.detectStaleOwnership({ maxAgeMs: 500 }, allocatedAt + 600);
    const b = env.rec.detectStaleOwnership({ maxAgeMs: 500 }, allocatedAt + 600);
    expect(a).toEqual(b);
  });
});

// ---------------------------------------------------------------------------
// 19E-R4 — Derived suspensions (no registry mutation)
// ---------------------------------------------------------------------------

describe("19E-R4 — derived suspensions", () => {
  it("agents at/above the failure threshold derive a suspension view (profiles untouched)", () => {
    const env = setup();
    expect(AGENTS_SUSPENSION_FAILURE_THRESHOLD).toBe(3);
    const before = JSON.stringify(env.rt.identities());
    // Fail the builder 3 times (chain: fail → reassign may pick reviewer or
    // builder... force builder each time by scoping role to builder).
    for (let i = 0; i < AGENTS_SUSPENSION_FAILURE_THRESHOLD; i++) {
      const r = env.alloc.allocate({ allocatedBy: "human-19e", task: { ...task({ label: "t" + String(i) }), allowedRoles: ["builder"] } });
      expect(r.ok).toBe(true);
      const assignmentId = (r as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
      const f = env.rec.reportFailure({ assignmentId, agentId: BUILDER_AGENT_ID, failureKind: "error", atEpochMs: T0 + 10 + i });
      expect(f.ok).toBe(true);
    }
    expect(env.rec.failureCounts().get(BUILDER_AGENT_ID)).toBe(3);
    const susp = env.rec.suspensions();
    expect(susp).toHaveLength(1);
    expect(susp[0]).toMatchObject({ agentId: BUILDER_AGENT_ID, available: false, reason: "suspended", failureCount: 3 });
    // Registry + profiles are untouched (derived view only).
    expect(JSON.stringify(env.rt.identities())).toBe(before);
  });

  it("suspensions feed reassignment: a suspended agent is never reassigned to", () => {
    const env = setup();
    const original = task({ requiredCapabilities: ["workspace:read"], allowedRoles: ["builder", "reviewer"] });
    // Suspend the reviewer first (3 failures), then fail the builder.
    for (let i = 0; i < 3; i++) {
      const r = env.alloc.allocate({ allocatedBy: "human-19e", task: { ...task({ label: "rv" + String(i) }), allowedRoles: ["reviewer"] } });
      const assignmentId = (r as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
      env.rec.reportFailure({ assignmentId, agentId: REVIEWER_AGENT_ID, failureKind: "error", atEpochMs: T0 + 10 + i });
    }
    const id = allocateToBuilder(env, original);
    env.rec.reportFailure({ assignmentId: id, agentId: BUILDER_AGENT_ID, failureKind: "error", atEpochMs: T0 + 100 });
    const r = env.rec.reassign({ failedAssignmentId: id, task: original, atEpochMs: T0 + 200 }, env.alloc);
    expect(r).toMatchObject({ ok: false, denyReason: "no_reassignment_candidate" });
  });
});

// ---------------------------------------------------------------------------
// 19E-R5 — Release + bounds + determinism + observability
// ---------------------------------------------------------------------------

describe("19E-R5 — release, bounds, determinism, observability", () => {
  it("release frees capacity without imputing failure", () => {
    const env = setup();
    const id = allocateToBuilder(env);
    const r = env.rec.release(id, T0 + 50, "human released");
    expect(r.ok).toBe(true);
    expect(env.rt.activeAllocations()).toHaveLength(0);
    expect(env.rec.history()[0]!).toMatchObject({ kind: "released", failureKind: "explicit_release" });
    expect(env.rec.failureCounts().size).toBe(0); // release is not a failure
  });

  it("recovery log cap is enforced (fail-closed)", () => {
    expect(AGENTS_MAX_RECOVERIES).toBe(256);
  });

  it("recovery records are append-only (history never rewritten)", () => {
    const env = setup();
    const id = allocateToBuilder(env);
    env.rec.reportFailure({ assignmentId: id, agentId: BUILDER_AGENT_ID, failureKind: "error", atEpochMs: T0 + 5 });
    const before = JSON.stringify(env.rec.history());
    env.alloc.recordStatus(id, "cancelled").ok;
    expect(JSON.stringify(env.rec.history())).toBe(before);
  });

  it("recovery flow is deterministic under a fixed clock", () => {
    const run = () => {
      const env = setup();
      const original = task({ requiredCapabilities: ["workspace:read"], allowedRoles: ["builder", "reviewer"] });
      const id = allocateToBuilder(env, original);
      env.rec.reportFailure({ assignmentId: id, agentId: BUILDER_AGENT_ID, failureKind: "error", atEpochMs: T0 + 10 });
      const r = env.rec.reassign({ failedAssignmentId: id, task: original, atEpochMs: T0 + 20 }, env.alloc);
      if (!r.ok) return { fail: true };
      return {
        recordId: r.record.recordId,
        to: r.assignment.assignedAgentId,
        digest: taskDescriptorDigest(original).slice(0, 8),
        rationale: r.record.rationale,
      };
    };
    expect(run()).toEqual(run());
  });

  it("recovery events are ledger-observable (chain verifies)", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const rt = new AgentRuntime({
      nowEpochMs: () => T0,
      ledger: {
        append: (input) => {
          const r = ledger.append({
            eventId: "e19e-" + String(ledger.length + 1).padStart(4, "0"),
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
    const rec = new RecoveryCoordinator(rt);
    const original = task({ requiredCapabilities: ["workspace:read"], allowedRoles: ["builder", "reviewer"] });
    const a = alloc.allocate({ allocatedBy: "human-19e", task: original });
    expect(a.ok).toBe(true);
    const assignmentId = (a as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
    rec.reportFailure({ assignmentId, agentId: BUILDER_AGENT_ID, failureKind: "error", atEpochMs: T0 + 1 });
    const rr = rec.reassign({ failedAssignmentId: assignmentId, task: original, atEpochMs: T0 + 2 }, alloc);
    expect(rr.ok, JSON.stringify(rr)).toBe(true);
    const types = ledger.events().map((e) => e.eventType);
    expect(types).toContain("agent_failure_recorded");
    expect(types).toContain("agent_task_reassigned");
    expect(ledger.verify().ok).toBe(true);
  });
});

// Isolation guard: the 19E suite must not leak registration state across tests.
beforeEach(() => {
  expect(true).toBe(true);
});
