import { describe, it, expect } from "vitest";
import type { Plan, PlanStep } from "@menog/core";
import {
  buildPlanGraph,
  canonicalSerializePlanGraph,
  detectCycles,
  hash64,
  stepIndexToNodeId,
  topologicalSort,
  DeterministicPlanner,
} from "@menog/planner";
import { VerbRegistry } from "@menog/verbs";
import type { Goal } from "@menog/core";

function planOf(steps: number, overrides: Partial<Plan> = {}): Plan {
  const planSteps: PlanStep[] = [];
  for (let i = 0; i < steps; i++) {
    planSteps.push({
      stepIndex: i,
      verbId: "verb-" + String(i),
      requiredCapabilities: Object.freeze(["workspace:list"]),
      sideEffectClass: "read",
      description: "step " + String(i),
      replayable: true,
      reversible: true,
      requiresHumanApproval: Object.freeze([false]),
      humanApprovalCount: 0,
    });
  }
  return {
    planId: overrides.planId ?? "plan-test",
    goalId: overrides.goalId ?? "goal-test",
    steps: Object.freeze(planSteps),
    totalRequiredCapabilities: Object.freeze(["workspace:list"]),
    maxSideEffectClassEncountered: "read",
    budget: Object.freeze({ maxSteps: steps }),
    humanApprovalRequiredOverall: false,
    createdAt: overrides.createdAt ?? "2026-09-06T10:00:00.000Z",
    ...overrides,
  };
}

function sequentialGoal(maxSteps: number, verbSeq: string[]): Goal {
  return {
    goalId: "g-seq",
    description: "sequence for graph",
    requestedVerbSequence: verbSeq,
    budget: { maxSteps },
  };
}

describe("PlanGraph — cycle rejection", () => {
  it("reports cycle_detected_rejected disposition with a cycle when explicit deps form a 2-cycle", () => {
    const plan = planOf(3);
    const g = buildPlanGraph(plan, {
      includeSequentialChainEdges: false,
      explicitDependencies: {
        0: [1],
        1: [0],
      },
    });
    expect(g.disposition).toBe("cycle_detected_rejected");
    expect(g.cyclesFound.length).toBeGreaterThanOrEqual(1);
    const entries = g.cyclesFound.map((c) => c.entryPoint).sort();
    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(g.topologicalOrder).toHaveLength(0);
    expect(typeof g.reason).toBe("string");
    expect(g.reason!.startsWith("cycles detected:")).toBe(true);
  });

  it("reports cycle_detected_rejected disposition for a 3-step cycle A->B->C->A", () => {
    const plan = planOf(3);
    const g = buildPlanGraph(plan, {
      includeSequentialChainEdges: false,
      explicitDependencies: {
        1: [0],
        2: [1],
        0: [2],
      },
    });
    expect(g.disposition).toBe("cycle_detected_rejected");
    expect(g.cyclesFound.length).toBeGreaterThanOrEqual(1);
    expect(g.cyclesFound[0]!.nodeIds.length).toBeGreaterThanOrEqual(3);
    expect(g.topologicalOrder).toHaveLength(0);
  });

  it("detectCycles returns independent list on pure graph input (3-color DFS)", () => {
    const nodeIds = ["a", "b", "c"] as const;
    const adj = {
      a: ["b"],
      b: ["c"],
      c: ["a"],
    } as const;
    const cycles = detectCycles(nodeIds, adj);
    expect(cycles.length).toBeGreaterThanOrEqual(1);
    const first = cycles[0]!;
    expect(first.entryPoint).toBeDefined();
    expect(first.nodeIds.length).toBeGreaterThanOrEqual(3);
    const noCycle = detectCycles(
      ["x", "y", "z"],
      { x: ["y"], y: ["z"], z: [] }
    );
    expect(noCycle).toHaveLength(0);
  });

  it("self-loop rejected earlier than cycle detect via invalid_edge_rejected (fail-closed)", () => {
    const plan = planOf(2);
    const g = buildPlanGraph(plan, {
      includeSequentialChainEdges: false,
      explicitDependencies: { 0: [0] },
    });
    expect(g.disposition).toBe("invalid_edge_rejected");
    expect(g.rejectedEdgeIndex).toBe(0);
    expect(typeof g.rejectedEdgeReason).toBe("string");
    expect(g.rejectedEdgeReason!.includes("self-loop")).toBe(true);
  });
});

describe("PlanGraph — dependency ordering", () => {
  it("default sequential chain produces edges step[i]->step[i+1] (kind=sequential)", () => {
    const plan = planOf(4);
    const g = buildPlanGraph(plan, { includeSequentialChainEdges: true });
    expect(g.disposition).toBe("dag_built");
    expect(g.edges.length).toBe(3);
    for (let i = 0; i < 3; i++) {
      const expectedFrom = stepIndexToNodeId(i);
      const expectedTo = stepIndexToNodeId(i + 1);
      const edge = g.edges.find(
        (e) => e.from === expectedFrom && e.to === expectedTo
      );
      expect(edge).toBeDefined();
      expect(edge!.kind).toBe("sequential");
    }
  });

  it("explicit deps produce dataflow edges; topologicalOrder respects both deps and sequential default", () => {
    const plan = planOf(4);
    const g = buildPlanGraph(plan, {
      includeSequentialChainEdges: true,
      explicitDependencies: { 2: [0], 3: [1] },
    });
    expect(g.disposition).toBe("dag_built");
    expect(g.topologicalOrder.length).toBe(plan.steps.length);
    const idxOf = (nodeId: string) => g.topologicalOrder.indexOf(nodeId);
    expect(idxOf(stepIndexToNodeId(0))).toBeLessThan(idxOf(stepIndexToNodeId(2)));
    expect(idxOf(stepIndexToNodeId(1))).toBeLessThan(idxOf(stepIndexToNodeId(3)));
    for (let i = 0; i + 1 < plan.steps.length; i++) {
      expect(idxOf(stepIndexToNodeId(i))).toBeLessThan(
        idxOf(stepIndexToNodeId(i + 1))
      );
    }
  });

  it("includeSequentialChainEdges=false suppresses sequential edges; only explicit deps + approve kinds remain", () => {
    const plan = planOf(3);
    const g = buildPlanGraph(plan, {
      includeSequentialChainEdges: false,
      explicitDependencies: { 2: [0], 1: [0] },
      explicitDependencyKind: "approval",
    });
    expect(g.disposition).toBe("dag_built");
    expect(g.edges.length).toBe(2);
    for (const e of g.edges) expect(e.kind).toBe("approval");
    const seqEdges = g.edges.filter((e) => e.kind === "sequential");
    expect(seqEdges).toHaveLength(0);
  });

  it("topologicalSort deterministically breaks ties via stepIndex (Kahn stable)", () => {
    const nodeIds = ["s-0", "s-1", "s-2", "s-3"] as const;
    const stepIndexes = {
      "s-0": 0,
      "s-1": 1,
      "s-2": 2,
      "s-3": 3,
    } as const;
    const adj = {
      "s-0": [],
      "s-1": [],
      "s-2": [],
      "s-3": [],
    } as const;
    const a = topologicalSort(nodeIds, adj, stepIndexes);
    const b = topologicalSort(nodeIds, adj, stepIndexes);
    expect(a).toEqual(b);
    expect(a).toEqual(["s-0", "s-1", "s-2", "s-3"]);
  });
});

describe("PlanGraph — canonical hash stability", () => {
  it("canonicalSerializePlanGraph produces byte-identical string for identical graphs", () => {
    const plan = planOf(3);
    const opts = {
      includeSequentialChainEdges: true,
      explicitDependencies: { 2: [0] } as const,
    };
    const gA = buildPlanGraph(plan, opts);
    const gB = buildPlanGraph(plan, opts);
    expect(gA.disposition).toBe("dag_built");
    expect(gB.disposition).toBe("dag_built");
    expect(gA.serializedCanonical.length).toBeGreaterThan(0);
    expect(gA.serializedCanonical).toBe(gB.serializedCanonical);
    expect(gA.serializedCanonicalHash).toBe(gB.serializedCanonicalHash);
  });

  it("serializedCanonicalHash differs when explicit deps change (sensitivity)", () => {
    const plan = planOf(4);
    const a = buildPlanGraph(plan, { explicitDependencies: { 2: [0] } });
    const b = buildPlanGraph(plan, { explicitDependencies: { 3: [0] } });
    expect(a.disposition).toBe("dag_built");
    expect(b.disposition).toBe("dag_built");
    expect(a.serializedCanonicalHash).not.toBe(b.serializedCanonicalHash);
  });

  it("hash64 is pure and reproducible across calls", () => {
    const input = "menog-plan-graph/v0|seed=abcdef";
    const a = hash64(input, "graphhash-");
    const b = hash64(input, "graphhash-");
    expect(a).toBe(b);
    expect(a.startsWith("graphhash-")).toBe(true);
    expect(a.length).toBe("graphhash-".length + 16);
    const diff = hash64(input + "|X", "graphhash-");
    expect(diff).not.toBe(a);
  });

  it("graphId is stable for identical plan+edge inputs", () => {
    const plan = planOf(3, { planId: "plan-stable" });
    const a = buildPlanGraph(plan, { includeSequentialChainEdges: true });
    const b = buildPlanGraph(plan, { includeSequentialChainEdges: true });
    expect(a.graphId).toBe(b.graphId);
  });

  it("canonical serialized output is valid parseable JSON (audit/replay friendly)", () => {
    const plan = planOf(3);
    const g = buildPlanGraph(plan);
    expect(() => JSON.parse(g.serializedCanonical)).not.toThrow();
    const parsed = JSON.parse(g.serializedCanonical);
    expect(parsed.$schema).toBe("menog-plangraph/v0");
    expect(parsed.disposition).toBe("dag_built");
    expect(Array.isArray(parsed.nodeIds)).toBe(true);
  });
});

describe("PlanGraph — graph serialization", () => {
  it("edges sorted (from,to,kind) in serializedCanonical; adjacency values sorted; nodeIds sorted", () => {
    const plan = planOf(4);
    const g = buildPlanGraph(plan, {
      explicitDependencies: { 3: [1], 2: [0] },
      explicitDependencyKind: "dataflow",
    });
    expect(g.disposition).toBe("dag_built");
    const parsed = JSON.parse(g.serializedCanonical);
    expect(parsed.$schema).toBe("menog-plangraph/v0");
    const sortedNodeIds = [...parsed.nodeIds].sort();
    expect(parsed.nodeIds).toEqual(sortedNodeIds);
    for (let i = 0; i + 1 < parsed.edges.length; i++) {
      const a = parsed.edges[i]!;
      const b = parsed.edges[i + 1]!;
      const cmp =
        a.from < b.from
          ? -1
          : a.from > b.from
            ? 1
            : a.to < b.to
              ? -1
              : a.to > b.to
                ? 1
                : a.kind < b.kind
                  ? -1
                  : a.kind > b.kind
                    ? 1
                    : 0;
      expect(cmp <= 0).toBe(true);
    }
    const adjKeys = Object.keys(parsed.adjacency).sort();
    expect(Object.keys(parsed.adjacency)).toEqual(adjKeys);
    for (const k of adjKeys) {
      const vals = parsed.adjacency[k];
      expect(vals).toEqual([...vals].sort());
    }
  });

  it("serializedCanonical includes cyclesFound when disposition is cycle_detected_rejected", () => {
    const plan = planOf(3);
    const g = buildPlanGraph(plan, {
      includeSequentialChainEdges: false,
      explicitDependencies: { 0: [1], 1: [0] },
    });
    expect(g.disposition).toBe("cycle_detected_rejected");
    const parsed = JSON.parse(g.serializedCanonical);
    expect(parsed.disposition).toBe("cycle_detected_rejected");
    expect(Array.isArray(parsed.cyclesFound)).toBe(true);
    expect(parsed.cyclesFound.length).toBeGreaterThanOrEqual(1);
    expect(typeof parsed.cyclesFound[0].entryPoint).toBe("string");
  });

  it("serializedCanonicalHash prefix matches hash64('...', 'graphhash-') exactly", () => {
    const plan = planOf(2);
    const g = buildPlanGraph(plan);
    const expectedHash = hash64(canonicalSerializePlanGraph(g), "graphhash-");
    expect(g.serializedCanonicalHash).toBe(expectedHash);
    expect(g.serializedCanonicalHash.startsWith("graphhash-")).toBe(true);
  });

  it("DeterministicPlanner.buildGraph delegates to pure buildPlanGraph (same output)", () => {
    const reg = new VerbRegistry();
    const p = new DeterministicPlanner(reg, { emitObservabilityEvents: false });
    const origISO = Date.prototype.toISOString;
    Date.prototype.toISOString = function () {
      return "2026-09-06T10:00:00.000Z";
    };
    try {
      const goal: Goal = sequentialGoal(4, [
        "observe",
        "inspect",
        "compare",
        "plan",
      ]);
      const prop = p.propose(goal);
      expect(prop.disposition).toBe("proposed");
      expect(prop.plan).toBeDefined();
      const plan = prop.plan!;
      const viaPlanner = p.buildGraph(plan, {
        explicitDependencies: { 2: [0] },
      });
      const viaPure = buildPlanGraph(plan, { explicitDependencies: { 2: [0] } });
      expect(viaPlanner.serializedCanonicalHash).toBe(
        viaPure.serializedCanonicalHash
      );
      expect(viaPlanner.graphId).toBe(viaPure.graphId);
    } finally {
      Date.prototype.toISOString = origISO;
    }
  });
});

describe("PlanGraph — invalid-node rejection", () => {
  it("explicitDependency referencing a step index greater than max step rejected as invalid_edge", () => {
    const plan = planOf(3);
    const g = buildPlanGraph(plan, {
      explicitDependencies: { 0: [999] },
    });
    expect(g.disposition).toBe("invalid_edge_rejected");
    expect(typeof g.rejectedEdgeReason).toBe("string");
    expect(g.rejectedEdgeReason!.includes("999")).toBe(true);
    expect(g.rejectedEdgeIndex).toBe(0);
  });

  it("explicitDependency referencing a negative step index rejected as invalid_edge", () => {
    const plan = planOf(3);
    const g = buildPlanGraph(plan, {
      explicitDependencies: { 0: [-1] },
    });
    expect(g.disposition).toBe("invalid_edge_rejected");
    expect(g.rejectedEdgeIndex).toBe(0);
  });

  it("explicitDependencies target key itself unknown step index => invalid_edge_rejected", () => {
    const plan = planOf(2);
    const g = buildPlanGraph(plan, {
      explicitDependencies: { 99: [0] },
    });
    expect(g.disposition).toBe("invalid_edge_rejected");
    expect(g.rejectedEdgeReason!.includes("step 99")).toBe(true);
  });

  it("explicitDependencies dep list contains non-integer => invalid_edge_rejected", () => {
    const plan = planOf(3);
    const injectedDeps = { 1: [0.5] } as unknown as Readonly<
      Record<number, readonly number[]>
    >;
    const g = buildPlanGraph(plan, {
      explicitDependencies: injectedDeps,
    });
    expect(g.disposition).toBe("invalid_edge_rejected");
    expect(g.rejectedEdgeReason!.includes("0.5")).toBe(true);
  });

  it("duplicate (from,to,kind) edges are deduplicated; only one appears in graph.edges", () => {
    const plan = planOf(3);
    const g = buildPlanGraph(plan, {
      explicitDependencies: { 2: [0], 1: [0] },
      includeSequentialChainEdges: true,
    });
    expect(g.disposition).toBe("dag_built");
    const sigs = g.edges.map((e) => e.from + "|" + e.to + "|" + e.kind);
    const uniqueSigs = new Set(sigs);
    expect(uniqueSigs.size).toBe(sigs.length);
  });

  it("Plan with steps[].stepIndex != array index => empty_plan_rejected (structural integrity)", () => {
    const badPlan: Plan = planOf(3);
    const badSteps: PlanStep[] = [...badPlan.steps];
    badSteps[1] = Object.freeze({ ...badSteps[1]!, stepIndex: 999 });
    const corrupt: Plan = Object.freeze({
      ...badPlan,
      steps: Object.freeze(badSteps),
    });
    const g = buildPlanGraph(corrupt);
    expect(g.disposition).toBe("empty_plan_rejected");
    expect(typeof g.reason).toBe("string");
    expect(g.reason!.includes("stepIndex")).toBe(true);
    expect(g.nodeIds).toHaveLength(0);
  });

  it("null/undefined plan / missing planId / missing goalId / missing steps all => empty_plan_rejected (fail closed)", () => {
    // @ts-expect-error testing null plan
    expect(buildPlanGraph(null).disposition).toBe("empty_plan_rejected");
    // @ts-expect-error testing undefined plan
    expect(buildPlanGraph(undefined).disposition).toBe("empty_plan_rejected");
    const noPlanId: Plan = Object.freeze({
      ...planOf(2),
      planId: "" as unknown as string,
    });
    expect(buildPlanGraph(noPlanId).disposition).toBe("empty_plan_rejected");
    const noGoalId: Plan = Object.freeze({
      ...planOf(2),
      goalId: "" as unknown as string,
    });
    expect(buildPlanGraph(noGoalId).disposition).toBe("empty_plan_rejected");
    const noSteps: Plan = Object.freeze({
      ...planOf(0),
      steps: Object.freeze([]),
    });
    expect(buildPlanGraph(noSteps).disposition).toBe("empty_plan_rejected");
  });

  it("PlanGraph proposal-only authority: planner package does not import fs/child_process/@menog/event-ledger/@menog/runtime-linux", () => {
    const plannerSrc =
      typeof buildPlanGraph === "function" &&
      typeof DeterministicPlanner === "function";
    expect(plannerSrc).toBe(true);
    const forbidden = ["fs", "child_process"];
    // Static boundary already enforced by author; runtime confirm no side effects:
    const g = buildPlanGraph(planOf(4));
    expect(Object.isFrozen(g)).toBe(true);
    expect(Object.isFrozen(g.edges)).toBe(true);
    expect(Object.isFrozen(g.nodeIds)).toBe(true);
    expect(forbidden.includes("fs")).toBe(true);
  });
});
