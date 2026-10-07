import { describe, it, expect } from "vitest";
import { DeterministicPlanner } from "@menog/planner";
import type { PlannerObservationEvent } from "@menog/planner";
import { VerbRegistry, type VerbContract } from "@menog/verbs";
import type { Goal } from "@menog/core";
import { AppendOnlyLedger, type MenogEventInput } from "@menog/event-ledger";
import type { Actor } from "@menog/core";

function inspectGoal(maxSteps = 4, overrides: Partial<Goal> = {}): Goal {
  return {
    goalId: "g-0",
    description: "inspect workspace then compare state",
    requestedVerbSequence: ["observe", "inspect", "compare", "plan"],
    budget: { maxSteps },
    ...overrides,
  };
}

describe("DeterministicPlanner — deterministic planning", () => {
  it("produces identical planId and step sequence for identical inputs", () => {
    const reg = new VerbRegistry();
    const p1 = new DeterministicPlanner(reg, { emitObservabilityEvents: false });
    const p2 = new DeterministicPlanner(reg, { emitObservabilityEvents: false });
    const fixedCreatedAt = "2026-09-06T10:00:00.000Z";
    const goal = inspectGoal();
    const patched: Goal = {
      ...goal,
      budget: { ...goal.budget },
    };
    const spyDate = Date;
    const origISO = spyDate.prototype.toISOString;
    spyDate.prototype.toISOString = function () {
      return fixedCreatedAt;
    };
    try {
      const a = p1.propose(patched);
      const b = p2.propose(patched);
      expect(a.disposition).toBe("proposed");
      expect(b.disposition).toBe("proposed");
      expect(a.plan).toBeDefined();
      expect(b.plan).toBeDefined();
      const ap = a.plan!;
      const bp = b.plan!;
      expect(ap.planId).toBe(bp.planId);
      expect(ap.steps.length).toBe(bp.steps.length);
      for (let i = 0; i < ap.steps.length; i++) {
        const as = ap.steps[i]!;
        const bs = bp.steps[i]!;
        expect(as.verbId).toBe(bs.verbId);
        expect(as.requiredCapabilities).toEqual(bs.requiredCapabilities);
      }
    } finally {
      spyDate.prototype.toISOString = origISO;
    }
  });

  it("planId changes when verb registry changes (deterministic sensitivity)", () => {
    const regA = new VerbRegistry();
    const p1 = new DeterministicPlanner(regA, { emitObservabilityEvents: false });
    const regB = new VerbRegistry();
    const extra: VerbContract = {
      id: "custom-read",
      description: "custom read verb",
      sideEffectClass: "read",
      requiredCapabilities: ["workspace:read-file"],
      replayable: true,
      reversible: true,
      inputSchemaVersion: "0.0.1",
      outputSchemaVersion: "0.0.1",
    };
    const ok = regB.register(extra);
    expect(ok.ok).toBe(true);
    const p2 = new DeterministicPlanner(regB, { emitObservabilityEvents: false });
    const fixedCreatedAt = "2026-09-06T10:00:00.000Z";
    const origISO = Date.prototype.toISOString;
    Date.prototype.toISOString = function () {
      return fixedCreatedAt;
    };
    try {
      const goalA: Goal = {
        goalId: "g-x",
        description: "observe only",
        requestedVerbSequence: ["observe"],
        budget: { maxSteps: 1 },
      };
      const goalB: Goal = {
        goalId: "g-y",
        description: "custom observe",
        requestedVerbSequence: ["observe", "custom-read"],
        budget: { maxSteps: 2 },
      };
      const a = p1.propose(goalA);
      const b = p2.propose(goalB);
      expect(a.disposition).toBe("proposed");
      expect(b.disposition).toBe("proposed");
      expect(a.plan!.planId).not.toBe(b.plan!.planId);
    } finally {
      Date.prototype.toISOString = origISO;
    }
  });
});

describe("DeterministicPlanner — unknown verb rejection", () => {
  it("rejects immediately with structured disposition on unknown verb", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-u",
      description: "unknown",
      requestedVerbSequence: ["observe", "nonexistent_verb", "inspect"],
      budget: { maxSteps: 4 },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("unknown_verb_rejected");
    expect(r.rejectedStepIndex).toBe(1);
    expect(r.rejectedVerbId).toBe("nonexistent_verb");
    expect(typeof r.reason).toBe("string");
    expect(r.reason.length).toBeGreaterThan(0);
    expect(r.trace).toContain("unknown_verb:nonexistent_verb");
    expect(r.plan).toBeUndefined();
  });

  it("rejects empty sequence with dedicated disposition", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-e",
      description: "empty",
      requestedVerbSequence: [],
      budget: { maxSteps: 10 },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("empty_sequence_rejected");
    expect(r.plan).toBeUndefined();
  });

  it("rejects non-string step entry safely", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal = {
      goalId: "g-bad",
      description: "bad step",
      requestedVerbSequence: ["observe", 42 as unknown as string],
      budget: { maxSteps: 4 },
    } as Goal;
    const r = p.propose(goal);
    expect(r.disposition).toBe("unknown_verb_rejected");
    expect(r.rejectedStepIndex).toBe(1);
  });
});

describe("DeterministicPlanner — capability declaration correctness", () => {
  it("each PlanStep carries verb.requiredCapabilities verbatim from registry", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-c",
      description: "inspect",
      requestedVerbSequence: ["inspect"],
      budget: { maxSteps: 1 },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("proposed");
    const planA = r.plan;
    expect(planA).toBeDefined();
    const step = planA!.steps[0];
    expect(step).toBeDefined();
    expect(step!.verbId).toBe("inspect");
    expect(step!.requiredCapabilities).toEqual([
      "workspace:list",
      "workspace:read-metadata",
      "git:status",
      "git:diff-read",
    ]);
  });

  it("totalRequiredCapabilities is deduped union of all step caps", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-union",
      description: "observe+inspect",
      requestedVerbSequence: ["observe", "inspect"],
      budget: { maxSteps: 3 },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("proposed");
    const caps = r.plan!.totalRequiredCapabilities;
    expect(caps).toEqual([
      "git:diff-read",
      "git:status",
      "workspace:list",
      "workspace:read-metadata",
    ]);
  });

  it("PlanStep.requiresHumanApproval mirrors CAPABILITY_EFFECT_TABLE per cap", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-app",
      description: "inspect + modify",
      requestedVerbSequence: ["inspect", "modify"],
      budget: { maxSteps: 2 },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("proposed");
    const plan = r.plan;
    expect(plan).toBeDefined();
    const st = plan!.steps;
    const sInspect = st[0];
    const sModify = st[1];
    expect(sInspect).toBeDefined();
    expect(sModify).toBeDefined();
    expect(sInspect!.humanApprovalCount).toBe(0);
    expect(sInspect!.requiresHumanApproval.every((x: boolean) => x === false)).toBe(true);
    expect(sModify!.humanApprovalCount).toBeGreaterThan(0);
    expect(sModify!.requiresHumanApproval.some((x: boolean) => x === true)).toBe(true);
    expect(plan!.humanApprovalRequiredOverall).toBe(true);
  });

  it("rejects verbs declaring unknown capabilities when deny flag is on (default)", () => {
    const reg = new VerbRegistry([]);
    const badVerb: VerbContract = {
      id: "evil",
      description: "bad verb with rogue cap",
      sideEffectClass: "write",
      requiredCapabilities: ["workspace:write", "rogue:undefined-cap"],
      replayable: false,
      reversible: false,
      inputSchemaVersion: "0.0.1",
      outputSchemaVersion: "0.0.1",
    };
    const ok = reg.register(badVerb);
    expect(ok.ok).toBe(true);
    const p = new DeterministicPlanner(reg);
    const goal: Goal = {
      goalId: "g-r",
      description: "rogue-cap test",
      requestedVerbSequence: ["evil"],
      budget: { maxSteps: 1 },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("capability_unsupported_rejected");
    expect(r.rejectedVerbId).toBe("evil");
  });
});

describe("DeterministicPlanner — budget propagation & enforcement", () => {
  it("rejects sequence longer than budget.maxSteps", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal = inspectGoal(2);
    const r = p.propose(goal);
    expect(r.disposition).toBe("budget_exceeded_rejected");
    expect(r.reason).toContain("exceeds budget.maxSteps=2");
  });

  it("honours maxSideEffectClass upper bound and rejects write-verb in read-only budget", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-b",
      description: "try commit inside read-only budget",
      requestedVerbSequence: ["observe", "commit"],
      budget: { maxSteps: 4, maxSideEffectClass: "read" },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("budget_exceeded_rejected");
    expect(r.rejectedStepIndex).toBe(1);
    expect(r.rejectedVerbId).toBe("commit");
    expect(r.reason).toContain("exceeds budget.maxSideEffectClass");
  });

  it("allows read-only verbs inside read maxSideEffectClass budget", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-ro",
      description: "all read verbs",
      requestedVerbSequence: ["observe", "inspect", "compare", "search"],
      budget: { maxSteps: 4, maxSideEffectClass: "read" },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("proposed");
    expect(r.plan!.maxSideEffectClassEncountered).toBe("read");
  });

  it("copies budget into Plan verbatim so downstream consumers can propagate", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const budget = { maxSteps: 8, maxRuntimeMs: 30_000, maxSideEffectClass: "write" as const };
    const goal: Goal = {
      goalId: "g-bcopy",
      description: "budget copy",
      requestedVerbSequence: ["observe", "inspect", "plan"],
      budget,
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("proposed");
    expect(r.plan!.budget).toEqual(budget);
    expect(r.plan!.budget).not.toBe(budget);
  });

  it("rejects non-integer maxSteps with typed error", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const badGoal = inspectGoal(4.5);
    const r = p.propose(badGoal);
    expect(r.disposition).toBe("budget_exceeded_rejected");
    expect(r.reason).toContain("non-negative finite integer");
  });
});

describe("DeterministicPlanner — ledger observability via event stream", () => {
  it("produces structured planner:goal_received + planner:plan_proposed observations for proposed plan", () => {
    const p = new DeterministicPlanner(new VerbRegistry(), {
      emitObservabilityEvents: true,
    });
    const goal: Goal = {
      goalId: "g-obs",
      description: "observe and plan",
      requestedVerbSequence: ["observe", "plan"],
      budget: { maxSteps: 4 },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("proposed");
    const obs = p.observations();
    const types = obs.map((o: PlannerObservationEvent) => o.observationType);
    expect(types).toContain("planner:goal_received");
    expect(types).toContain("planner:step_validated");
    expect(types).toContain("planner:plan_proposed");
    for (const o of obs) {
      expect(typeof o.at).toBe("string");
      expect(o.goalId).toBe("g-obs");
      expect(Array.isArray(o.trace)).toBe(true);
      expect(o.schemaVersion.startsWith("menog-planner/")).toBe(true);
    }
  });

  it("records planner:step_rejected with rejectedStepIndex on unknown verb", () => {
    const p = new DeterministicPlanner(new VerbRegistry(), {
      emitObservabilityEvents: true,
    });
    const goal: Goal = {
      goalId: "g-rej",
      description: "one good one bad",
      requestedVerbSequence: ["observe", "bogus"],
      budget: { maxSteps: 3 },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("unknown_verb_rejected");
    const obs = p.observations();
    const last = obs[obs.length - 1];
    expect(last).toBeDefined();
    expect(last!.observationType).toBe("planner:step_rejected");
    expect(last!.stepIndex).toBe(1);
    expect(last!.verbId).toBe("bogus");
  });

  it("observations can be appended to AppendOnlyLedger as typed events (ledger-observability contract)", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-ledger",
      description: "ledger observable",
      requestedVerbSequence: ["observe", "plan"],
      budget: { maxSteps: 3 },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("proposed");
    const actor: Actor = { type: "agent", id: "planner/0" };
    const ledger = AppendOnlyLedger.inMemory();
    const obs = p.observations();
    for (const o of obs) {
      const input: MenogEventInput = {
        eventId: "evt-" + o.observationType + "-" + String(Math.random()).slice(2, 10),
        timestamp: o.at,
        eventType: o.observationType,
        actor,
        goalId: o.goalId,
        planId: o.planId,
        taskId: goal.goalId,
        verb: o.verbId,
        capability: (o.requiredCapabilities ?? [])[0],
        inputSummary: {
          schemaVersion: o.schemaVersion,
          stepIndex: o.stepIndex ?? null,
          reason: o.reason ?? null,
          trace: o.trace,
        } as unknown as Readonly<Record<string, unknown>>,
        resultSummary: {
          disposition: r.disposition,
          planId: r.plan?.planId ?? null,
          steps: r.plan?.steps.length ?? 0,
        } as unknown as Readonly<Record<string, unknown>>,
      } as MenogEventInput;
      const appended = ledger.append(input);
      expect(appended.ok).toBe(true);
    }
    expect(ledger.length).toBe(obs.length);
    const v = ledger.verify();
    expect(v.ok).toBe(true);
    expect(v.verifiedCount).toBe(obs.length);
  });

  it("observations list is returned frozen copy and clearObservations resets", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    p.propose(inspectGoal(4));
    const before = p.observations();
    expect(before.length).toBeGreaterThan(0);
    p.clearObservations();
    const after = p.observations();
    expect(after.length).toBe(0);
  });
});
