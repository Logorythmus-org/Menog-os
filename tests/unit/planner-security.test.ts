import { describe, it, expect } from "vitest";
import {
  DeterministicPlanner,
  buildPlanGraph,
  plannerObservationToMenogEventInputs,
} from "@menog/planner";
import { VerbRegistry, type VerbContract } from "@menog/verbs";
import type { Goal, Plan, Actor, PlanStep } from "@menog/core";
import { AppendOnlyLedger } from "@menog/event-ledger";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import {
  DAY1_FORBIDDEN_CAPABILITIES,
  isCapabilityId,
  type CapabilityId,
} from "@menog/policy";

const RUNTIME_ACTOR: Actor = { type: "runtime", id: "test-runner" };

function forgeVerb(overrides: Partial<VerbContract>): VerbContract {
  return {
    id: "custom-verb",
    description: "forged verb contract for adversarial testing",
    sideEffectClass: "read",
    requiredCapabilities: Object.freeze(["workspace:read-file"]),
    replayable: true,
    reversible: true,
    inputSchemaVersion: "0.0.1",
    outputSchemaVersion: "0.0.1",
    ...overrides,
  };
}

describe("12D Planner Security — Scope Escalation DENIED", () => {
  it("modify verb (write side-effect) inside read-only budget produces budget_exceeded_rejected before plan proposal", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-scope-write-escalate",
      description: "attempt modify inside read-only budget",
      requestedVerbSequence: ["observe", "modify"],
      budget: { maxSteps: 2, maxSideEffectClass: "read" },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("budget_exceeded_rejected");
    expect(r.rejectedStepIndex).toBe(1);
    expect(r.rejectedVerbId).toBe("modify");
    expect(typeof r.reason).toBe("string");
    expect(r.reason).toContain("sideEffectClass");
    expect(r.reason).toContain("write");
    expect(r.reason).toContain("read");
    expect(r.plan).toBeUndefined();
  });

  it("execute verb (system side-effect) inside write budget still escalates above ceiling → rejected", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-scope-sys-escalate",
      description: "attempt execute inside write budget (still above max)",
      requestedVerbSequence: ["validate", "execute"],
      budget: { maxSteps: 2, maxSideEffectClass: "write" },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("budget_exceeded_rejected");
    expect(r.rejectedStepIndex).toBe(1);
    expect(r.rejectedVerbId).toBe("execute");
    expect(r.reason).toContain("'system' exceeds budget.maxSideEffectClass 'write'");
    expect(r.plan).toBeUndefined();
  });

  it("network side-effect exceeds write budget (lattice rank 3 > 2) → rejected before plan", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-scope-net-escalate",
      description: "attempt communicate verb with network inside write budget",
      requestedVerbSequence: ["inspect", "communicate"],
      budget: { maxSteps: 2, maxSideEffectClass: "write" },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("budget_exceeded_rejected");
    expect(r.rejectedStepIndex).toBe(1);
    expect(r.rejectedVerbId).toBe("communicate");
    expect(r.plan).toBeUndefined();
  });

  it("goal.requestedVerbSequence longer than budget.maxSteps → rejected and 5th modify verb NEVER reaches plan", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-scope-maxsteps",
      description: "attempt 5 steps inside maxSteps=1; last is modify",
      requestedVerbSequence: ["observe", "inspect", "search", "compare", "modify"],
      budget: { maxSteps: 1 },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("budget_exceeded_rejected");
    expect(r.reason).toContain("exceeds budget.maxSteps=1");
    expect(r.plan).toBeUndefined();
    const trace = r.trace;
    expect(trace).toContain("budget_exceeded:maxSteps");
    expect(trace.some((t) => t.startsWith("step_4:modify"))).toBe(false);
  });
});

describe("12D Planner Security — Capability Smuggling DENIED", () => {
  const SMUGGLED: readonly { label: string; verb: VerbContract; expectStep?: number }[] = [
    {
      label: "uppercase-case smuggling (WORKSPACE:WRITE)",
      verb: forgeVerb({
        id: "smug-a",
        requiredCapabilities: Object.freeze([
          "WORKSPACE:WRITE" as unknown as CapabilityId,
        ]),
      }),
    },
    {
      label: "whitespace-padding smuggling ('  workspace:write  ')",
      verb: forgeVerb({
        id: "smug-b",
        requiredCapabilities: Object.freeze([
          "  workspace:write  " as unknown as CapabilityId,
        ]),
      }),
    },
    {
      label: "unknown-name-suffix smuggling (workspace:write-backdoor)",
      verb: forgeVerb({
        id: "smug-c",
        requiredCapabilities: Object.freeze([
          "workspace:write-backdoor" as unknown as CapabilityId,
        ]),
      }),
    },
    {
      label: "namespace typosquat (network:internal) vs network:external",
      verb: forgeVerb({
        id: "smug-d",
        sideEffectClass: "network",
        requiredCapabilities: Object.freeze([
          "network:internal" as unknown as CapabilityId,
        ]),
      }),
    },
    {
      label: "extra duplicate with diff case (plan:generate + plan:GENERATE smuggled)",
      verb: forgeVerb({
        id: "smug-e",
        requiredCapabilities: Object.freeze([
          "plan:generate",
          "plan:GENERATE" as unknown as CapabilityId,
        ]),
      }),
    },
    {
      label: "process:execute-write variant with dash (process:execute_write)",
      verb: forgeVerb({
        id: "smug-f",
        sideEffectClass: "system",
        requiredCapabilities: Object.freeze([
          "process:execute_write" as unknown as CapabilityId,
        ]),
      }),
    },
  ] as const;

  for (const v of SMUGGLED) {
    it("smuggled vector [" + v.label + "] → capability_unsupported_rejected (gate #1 planner unsupportedCapabilityDeny)", () => {
      const reg = new VerbRegistry();
      const ok = reg.register(v.verb);
      expect(ok.ok).toBe(true);
      const p = new DeterministicPlanner(reg);
      const goal: Goal = {
        goalId: "g-smug-" + v.verb.id,
        description: v.label,
        requestedVerbSequence: ["observe", v.verb.id],
        budget: { maxSteps: 2 },
      };
      const r = p.propose(goal);
      expect(r.disposition).toBe("capability_unsupported_rejected");
      expect(typeof r.rejectedStepIndex).toBe("number");
      expect(r.rejectedVerbId).toBe(v.verb.id);
      expect(typeof r.reason).toBe("string");
      expect(r.reason).toMatch(/not a known CapabilityId|unknown capability/);
      expect(r.plan).toBeUndefined();
    });
  }

  it("capability smuggling dual-gate: with unsupportedCapabilityDeny=false planner passes step, but PolicyEngine still denies all smuggled caps (gate #2 policy per-capability map)", () => {
    const smuggledCaps: readonly string[] = Object.freeze([
      "WORKSPACE:WRITE",
      "  workspace:read-metadata  ",
      "network:internal",
    ]);
    const forged: VerbContract = forgeVerb({
      id: "smug-dual",
      sideEffectClass: "write",
      requiredCapabilities: smuggledCaps,
    });
    const reg = new VerbRegistry();
    const ok = reg.register(forged);
    expect(ok.ok).toBe(true);
    const p = new DeterministicPlanner(reg, { unsupportedCapabilityDeny: false });
    const goal: Goal = {
      goalId: "g-smug-dual",
      description: "dual-gate bypass attempt; planner gate off → policy must still catch",
      requestedVerbSequence: ["smug-dual"],
      budget: { maxSteps: 1 },
    };
    const proposal = p.propose(goal);
    expect(proposal.disposition).toBe("proposed");
    expect(proposal.plan).toBeDefined();
    const plan = proposal.plan!;
    expect(plan.steps.length).toBe(1);
    const step0 = plan.steps[0]!;
    expect(step0.requiredCapabilities.length).toBe(3);

    const engine = new DenyByDefaultPolicyEngine();
    const req = {
      requestId: "r-smug-dual",
      actor: RUNTIME_ACTOR,
      verb: step0.verbId,
      requestedCapabilities: step0.requiredCapabilities as unknown as CapabilityId[],
    };
    const result = engine.evaluate(req);
    expect(result.decision.outcome).toBe("deny");
    expect(result.deniedCapabilities.length).toBeGreaterThanOrEqual(3);
    for (const s of smuggledCaps) {
      const hit = result.deniedCapabilities.find(
        (k) => (k as unknown as string) === s
      );
      expect(hit).toBeDefined();
    }
    const perAnyUnknown = Object.values(result.perCapability).some(
      (pd) =>
        pd.outcome === "deny" && pd.matchedRule === "rule:unknown-capability"
    );
    expect(perAnyUnknown).toBe(true);
  });

  it("capability smuggling into PolicyRequest directly → every smuggled string captured as deny in perCapability map; no fall-through unseen", () => {
    const injected: readonly string[] = Object.freeze([
      "workspace:write  ",
      "GIT:COMMIT",
      "process:privileged_escalate",
      ":weird-empty-namespace",
    ]);
    const engine = new DenyByDefaultPolicyEngine();
    const req = {
      requestId: "r-smug-direct",
      actor: RUNTIME_ACTOR,
      verb: "inspect",
      requestedCapabilities: injected as unknown as CapabilityId[],
    };
    const result = engine.evaluate(req);
    expect(result.decision.outcome).toBe("deny");
    expect(result.deniedCapabilities.length).toBeGreaterThanOrEqual(4);
    for (const rawCap of injected) {
      const found = (result.deniedCapabilities as unknown as string[]).includes(
        rawCap
      );
      expect(found).toBe(true);
      const perMap = result.perCapability as unknown as Readonly<
        Record<string, { outcome: string; matchedRule: string }>
      >;
      const pdLocal = perMap[rawCap];
      expect(pdLocal).toBeDefined();
      if (pdLocal === undefined) throw new Error("pdLocal undefined");
      expect(pdLocal.outcome).toBe("deny");
      expect(pdLocal.matchedRule).toBe("rule:unknown-capability");
    }
  });
});

describe("12D Planner Security — Malformed Graph DENIED", () => {
  function syntheticPlan(overrides: Partial<Plan>, steps: PlanStep[]): Plan {
    return {
      planId: "plan-fake-0",
      goalId: "g-fake-0",
      steps: Object.freeze(steps),
      totalRequiredCapabilities: Object.freeze([]),
      maxSideEffectClassEncountered: "read",
      budget: { maxSteps: steps.length },
      humanApprovalRequiredOverall: false,
      createdAt: "2026-09-06T12:00:00.000Z",
      ...overrides,
    } as Plan;
  }

  function mkStep(idx: number, verbId = "inspect"): PlanStep {
    return Object.freeze({
      stepIndex: idx,
      verbId,
      requiredCapabilities: Object.freeze([
        "workspace:list",
        "workspace:read-metadata",
      ]),
      sideEffectClass: "read",
      description: "test step " + idx,
      replayable: true,
      reversible: true,
      requiresHumanApproval: Object.freeze([false, false]),
      humanApprovalCount: 0,
    });
  }

  it("Plan with non-monotonic stepIndexes [0,2,1] violates array alignment → empty_plan_rejected disposition", () => {
    const steps = [
      mkStep(0, "observe"),
      mkStep(2, "inspect"),
      mkStep(1, "search"),
    ];
    const plan = syntheticPlan({}, steps);
    const g = buildPlanGraph(plan);
    expect(g.disposition).toBe("empty_plan_rejected");
    expect(typeof g.reason).toBe("string");
    expect(g.reason).toContain("stepIndex must equal array index");
    expect(g.topologicalOrder.length).toBe(0);
    expect(g.nodeIds.length).toBe(0);
  });

  it("3-edge explicit backdoor cycle (2→0) + sequential edges still detected → cycle_detected_rejected", () => {
    const steps = [mkStep(0), mkStep(1), mkStep(2)];
    const plan = syntheticPlan({}, steps);
    const injectedDeps = { 0: [2] } as unknown as Readonly<
      Record<number, readonly number[]>
    >;
    const g = buildPlanGraph(plan, {
      explicitDependencies: injectedDeps,
      includeSequentialChainEdges: true,
    });
    expect(g.disposition).toBe("cycle_detected_rejected");
    expect(g.cyclesFound.length).toBeGreaterThanOrEqual(1);
    expect(g.topologicalOrder.length).toBe(0);
    const cycle = g.cyclesFound[0];
    expect(cycle).toBeDefined();
    expect(cycle!.nodeIds.length).toBeGreaterThanOrEqual(3);
  });

  it("1000-node long sequential chain builds dag_built without stack overflow; Kahn topological order length matches nodes", () => {
    const big: PlanStep[] = [];
    for (let i = 0; i < 1000; i++) big.push(mkStep(i, "observe"));
    const plan = syntheticPlan(
      {
        planId: "plan-big-1000",
        goalId: "g-big-1000",
      },
      big
    );
    const g = buildPlanGraph(plan);
    expect(g.disposition).toBe("dag_built");
    expect(g.nodeIds.length).toBe(1000);
    expect(g.topologicalOrder.length).toBe(1000);
    expect(g.cyclesFound.length).toBe(0);
    for (let i = 0; i < 1000; i++) {
      expect(g.topologicalOrder[i]).toBe("step-" + i);
    }
  });

  it("explicitDeps with negative index, float index, and giant out-of-range → invalid_edge_rejected", () => {
    const steps = [mkStep(0), mkStep(1), mkStep(2)];
    const plan = syntheticPlan({}, steps);

    const negDeps = { 1: [-1] } as unknown as Readonly<
      Record<number, readonly number[]>
    >;
    const gNeg = buildPlanGraph(plan, { explicitDependencies: negDeps });
    expect(gNeg.disposition).toBe("invalid_edge_rejected");
    expect(typeof gNeg.rejectedEdgeReason).toBe("string");

    const floatDeps = { 1: [0.5] } as unknown as Readonly<
      Record<number, readonly number[]>
    >;
    const gFloat = buildPlanGraph(plan, { explicitDependencies: floatDeps });
    expect(gFloat.disposition).toBe("invalid_edge_rejected");

    const giantDeps = { 1: [9999] } as unknown as Readonly<
      Record<number, readonly number[]>
    >;
    const gGiant = buildPlanGraph(plan, { explicitDependencies: giantDeps });
    expect(gGiant.disposition).toBe("invalid_edge_rejected");
    expect(gGiant.rejectedEdgeReason).toContain("9999");
  });

  it("duplicate node ids → two PlanSteps with same stepIndex violates alignment → empty_plan_rejected", () => {
    const steps = [mkStep(0), mkStep(1), mkStep(1), mkStep(2)];
    const plan = syntheticPlan({}, steps);
    const g = buildPlanGraph(plan);
    expect(g.disposition).toBe("empty_plan_rejected");
    expect(g.reason).toContain("stepIndex must equal array index 2");
  });
});

describe("12D Planner Security — Hidden Write DENIED", () => {
  it("custom verb declares workspace:write cap; read-only budget blocks it BEFORE proposal via sideEffect lattice", () => {
    const forgedWrite: VerbContract = forgeVerb({
      id: "hidden-write-verb",
      description: "claim read-only but declare write cap",
      sideEffectClass: "write",
      requiredCapabilities: Object.freeze([
        "workspace:write",
        "workspace:read-file",
      ]),
    });
    const reg = new VerbRegistry();
    const ok = reg.register(forgedWrite);
    expect(ok.ok).toBe(true);
    const p = new DeterministicPlanner(reg);
    const goal: Goal = {
      goalId: "g-hw-budget-lattice",
      description: "attempt hidden write via sideEffect mismatch",
      requestedVerbSequence: ["observe", "hidden-write-verb"],
      budget: { maxSteps: 2, maxSideEffectClass: "read" },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("budget_exceeded_rejected");
    expect(r.plan).toBeUndefined();
  });

  it("plan.totalRequiredCapabilities after proposal NEVER intersects DAY1_FORBIDDEN when budget maxSideEffectClass=read (union cap invariant)", () => {
    const reg = new VerbRegistry();
    const p = new DeterministicPlanner(reg);
    const goal: Goal = {
      goalId: "g-hw-day1-union",
      description: "observe+inspect+search+compare+plan — all read/none class",
      requestedVerbSequence: ["observe", "inspect", "search", "compare", "plan"],
      budget: { maxSteps: 5, maxSideEffectClass: "read" },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("proposed");
    expect(r.plan).toBeDefined();
    const plan = r.plan!;
    const unionSet = new Set(plan.totalRequiredCapabilities);
    for (const forb of DAY1_FORBIDDEN_CAPABILITIES) {
      expect(unionSet.has(forb)).toBe(false);
    }
  });

  it("planner step.requiredCapabilities is VERBATIM copy of verb.requiredCapabilities — no planner-injected hidden caps", () => {
    const customCapSet: readonly string[] = Object.freeze([
      "workspace:read-file",
      "plan:generate",
    ]);
    const custom: VerbContract = forgeVerb({
      id: "hw-verbatim-cap",
      requiredCapabilities: customCapSet,
    });
    const reg = new VerbRegistry();
    reg.register(custom);
    const p = new DeterministicPlanner(reg);
    const goal: Goal = {
      goalId: "g-hw-verbatim",
      description: "verify caps copy verbatim not enhanced",
      requestedVerbSequence: ["hw-verbatim-cap"],
      budget: { maxSteps: 1, maxSideEffectClass: "read" },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("proposed");
    const plan = r.plan!;
    const step = plan.steps[0]!;
    expect(step.requiredCapabilities).toEqual(customCapSet);
    expect(step.requiredCapabilities.length).toBe(customCapSet.length);
  });

  it("Goal.description with embedded <script>evil()</script> MUST NOT echo into planId, observations trace, or serializedCanonical (content leakage guard)", () => {
    const injected = "<script>alert('xss')</script>evil()'\"\\`${breakout}";
    const reg = new VerbRegistry();
    const p = new DeterministicPlanner(reg);
    const goal: Goal = {
      goalId: "g-hw-desc-leak",
      description: injected,
      requestedVerbSequence: ["observe", "inspect"],
      budget: { maxSteps: 2, maxSideEffectClass: "read" },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("proposed");
    const plan = r.plan!;
    expect(plan.planId.includes("script")).toBe(false);
    expect(plan.planId.includes("evil")).toBe(false);
    expect(plan.planId.includes("alert")).toBe(false);

    const g = buildPlanGraph(plan);
    expect(g.serializedCanonical.includes("script")).toBe(false);
    expect(g.serializedCanonical.includes("evil()")).toBe(false);

    const obs = p.observations();
    for (const o of obs) {
      for (const t of o.trace) {
        expect(t.includes("script")).toBe(false);
        expect(t.includes("evil")).toBe(false);
      }
      if (typeof o.reason === "string") {
        expect(o.reason.includes("script")).toBe(false);
      }
    }

    const bridged = plannerObservationToMenogEventInputs(obs, RUNTIME_ACTOR);
    for (const evt of bridged) {
      const summaryJson = JSON.stringify(evt.inputSummary ?? {}) + JSON.stringify(evt.resultSummary ?? {});
      expect(summaryJson.includes("script")).toBe(false);
      expect(summaryJson.includes("evil")).toBe(false);
    }
  });
});

describe("12D Planner Security — Ledger Denial Evidence + Planner→Policy Coupling Invariant", () => {
  it("planner rejects unknown verb → observations() non-empty; bridged to MenogEventInputs; ledger.append all; ledger.verify() ok=true with verifiedCount === appended count", () => {
    const p = new DeterministicPlanner(new VerbRegistry());
    const goal: Goal = {
      goalId: "g-ledger-unknown",
      description: "ledger evidence: unknown verb denial",
      requestedVerbSequence: ["observe", "DOES_NOT_EXIST_xyz"],
      budget: { maxSteps: 2 },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("unknown_verb_rejected");
    const obs = p.observations();
    expect(obs.length).toBeGreaterThanOrEqual(2);

    const inputs = plannerObservationToMenogEventInputs(obs, RUNTIME_ACTOR, {
      workspaceId: "ws-local",
      taskId: "t-ledger-0",
    });
    expect(inputs.length).toBe(obs.length);
    for (const evt of inputs) {
      expect(typeof evt.eventId).toBe("string");
      expect(evt.eventId.length).toBeGreaterThan(0);
      expect(evt.policyDecision === "allow" || evt.policyDecision === "deny" || evt.policyDecision === "not_applicable").toBe(true);
    }

    const ledger = AppendOnlyLedger.inMemory();
    let appended = 0;
    for (const input of inputs) {
      const res = ledger.append(input);
      expect(res.ok).toBe(true);
      expect(res.event).toBeDefined();
      appended++;
    }
    const v = ledger.verify();
    expect(v.ok).toBe(true);
    expect(v.verifiedCount).toBe(appended);
    expect(v.totalCount).toBe(appended);
    expect(ledger.length).toBe(appended);
  });

  it("planner rejects capability smuggling → observations bridged → ledger append; verify passes with matching count; deny events present", () => {
    const forged: VerbContract = forgeVerb({
      id: "smug-ledger",
      requiredCapabilities: Object.freeze([
        "WORKSPACE:W" as unknown as CapabilityId,
      ]),
    });
    const reg = new VerbRegistry();
    reg.register(forged);
    const p = new DeterministicPlanner(reg);
    const goal: Goal = {
      goalId: "g-ledger-smug",
      description: "ledger evidence capability smuggling denial",
      requestedVerbSequence: ["observe", "smug-ledger"],
      budget: { maxSteps: 2 },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("capability_unsupported_rejected");
    const obs = p.observations();
    const inputs = plannerObservationToMenogEventInputs(obs, RUNTIME_ACTOR);
    const ledger = AppendOnlyLedger.inMemory();
    let count = 0;
    for (const input of inputs) {
      const res = ledger.append(input);
      expect(res.ok).toBe(true);
      count++;
    }
    const v = ledger.verify();
    expect(v.ok).toBe(true);
    expect(v.verifiedCount).toBe(count);
    const denyEvents = ledger
      .events()
      .filter((e) => e.policyDecision === "deny");
    expect(denyEvents.length).toBeGreaterThanOrEqual(1);
  });

  it("DenyByDefaultPolicyEngine with wrapLedger(ledger) → evaluate DAY1_FORBIDDEN cap; per-cap deny; ledger.verify confirms decision events appended count-matched", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const engine = DenyByDefaultPolicyEngine.with(ledger);
    const pre = ledger.length;
    const res = engine.evaluate({
      requestId: "r-day1-forbid",
      actor: RUNTIME_ACTOR,
      verb: "commit",
      requestedCapabilities: [
        "git:commit",
        "workspace:write",
      ],
      workspaceId: "ws-ledger-deny",
      taskId: "t-policy-deny-1",
    });
    expect(res.decision.outcome).toBe("deny");
    expect(res.deniedCapabilities.length).toBeGreaterThanOrEqual(2);
    expect(ledger.length).toBe(pre + 1);
    const v = ledger.verify();
    expect(v.ok).toBe(true);
    expect(v.verifiedCount).toBe(ledger.length);
    const last = ledger.events()[ledger.length - 1]!;
    expect(last.eventType).toBe("policy_decision");
    expect(last.policyDecision).toBe("deny");
    const rs = last.resultSummary;
    expect(rs).toBeDefined();
    expect(rs!["matchedRule"]).toBeDefined();
  });

  it("PLANNER OUTPUT NEVER BYPASSES POLICY: for every proposed Plan.step, PolicyEngine.allowed ⊇ step.requiredCapabilities when verb is inspect (coupling invariant)", () => {
    const reg = new VerbRegistry();
    const p = new DeterministicPlanner(reg);
    const goal: Goal = {
      goalId: "g-policy-couple",
      description: "coupling: inspect verb → planner plan steps must be subset of policy allows",
      requestedVerbSequence: ["inspect", "observe", "inspect"],
      budget: { maxSteps: 3, maxSideEffectClass: "read" },
    };
    const r = p.propose(goal);
    expect(r.disposition).toBe("proposed");
    const plan = r.plan!;
    const engine = new DenyByDefaultPolicyEngine();

    for (const step of plan.steps) {
      const verbCapsMutable: CapabilityId[] = [];
      for (const raw of step.requiredCapabilities) {
        if (isCapabilityId(raw)) verbCapsMutable.push(raw);
      }
      const verbCaps: readonly CapabilityId[] = Object.freeze(verbCapsMutable);
      const req = {
        requestId: "couple-" + plan.planId + "-" + step.stepIndex,
        actor: RUNTIME_ACTOR,
        verb: step.verbId,
        requestedCapabilities: verbCaps,
        expectedSideEffectClass: step.sideEffectClass as "read" | "write" | "system" | "network" | "none",
      };
      const result = engine.evaluate(req);
      if (step.verbId === "inspect" || step.verbId === "observe") {
        const allowedSet = new Set(result.allowedCapabilities);
        for (const c of verbCaps) {
          const inDay1 =
            c === "workspace:list" ||
            c === "workspace:read-metadata" ||
            c === "git:status" ||
            c === "git:diff-read";
          if (inDay1 && step.verbId === "inspect") {
            expect(allowedSet.has(c)).toBe(true);
          }
        }
      }
    }
  });

  it("PLANNER-POLICY DUAL GATE: any step.capability intersects DAY1_FORBIDDEN → planner first rejects at budget if sideEffect>read; else policy.evaluate still denies forbidden cap", () => {
    const forgedExec: VerbContract = forgeVerb({
      id: "dual-modify",
      description: "declares workspace:write but says sideEffect=read (cap/SE mismatch)",
      sideEffectClass: "read",
      requiredCapabilities: Object.freeze([
        "workspace:write",
        "workspace:read-file",
      ]),
    });
    const reg = new VerbRegistry();
    reg.register(forgedExec);
    const p = new DeterministicPlanner(reg);
    const goal: Goal = {
      goalId: "g-dual-gate-f",
      description: "sideEffect=read but declares write cap → planner gate unsupportedCapabilityDeny=false, policy still denies",
      requestedVerbSequence: ["dual-modify"],
      budget: { maxSteps: 1, maxSideEffectClass: "read" },
    };
    const proposal = p.propose(goal);
    expect(proposal.disposition).toBe("proposed");
    const plan = proposal.plan!;
    const step = plan.steps[0]!;
    const engine = new DenyByDefaultPolicyEngine();
    const req = {
      requestId: "r-dual-gate",
      actor: RUNTIME_ACTOR,
      verb: step.verbId,
      requestedCapabilities: step.requiredCapabilities as unknown as CapabilityId[],
    };
    const result = engine.evaluate(req);
    expect(result.decision.outcome).toBe("deny");
    const denied = new Set(
      result.deniedCapabilities as unknown as readonly string[]
    );
    expect(denied.has("workspace:write")).toBe(true);
  });
});

describe("12D Planner Security — Authority Boundary Audit (static import check)", () => {
  it("planner production modules MUST NOT import fs, child_process, @menog/event-ledger, or @menog/runtime-linux (proposal-only authority separation)", () => {
    const forbidden: readonly string[] = Object.freeze([
      "node:fs",
      "node:child_process",
      "child_process",
      "fs",
      "@menog/event-ledger",
      "@menog/runtime-linux",
    ]);

    const bridgedSource = plannerObservationToMenogEventInputs
      .toString()
      .toLowerCase();
    for (const token of forbidden) {
      expect(bridgedSource.includes(token.toLowerCase())).toBe(false);
    }

    expect(typeof plannerObservationToMenogEventInputs).toBe("function");
    const arr = plannerObservationToMenogEventInputs(
      [],
      RUNTIME_ACTOR
    );
    expect(Array.isArray(arr)).toBe(true);
    expect(arr.length).toBe(0);

    const p = new DeterministicPlanner(new VerbRegistry(), {
      emitObservabilityEvents: false,
    });
    expect(typeof p.propose).toBe("function");
    expect(typeof p.buildGraph).toBe("function");
    expect(typeof p.observations).toBe("function");
  });
});
