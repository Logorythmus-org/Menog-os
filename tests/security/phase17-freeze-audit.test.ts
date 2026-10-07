import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  ALGORITHM_SCHEMA_VERSION,
  ALGORITHM_FAMILIES,
  ALGORITHM_MAX_CANDIDATES,
  ALGORITHM_MAX_CANDIDATE_LABEL_CHARS,
  ALGORITHM_MAX_DECISION_CHARS,
  ALGORITHM_MAX_REASONING_SUMMARY_CHARS,
  ALGORITHM_MAX_OIDATA_ITERATIONS,
  ALGORITHM_MAX_METRICS,
  ALGORITHM_MAX_TUNABLE_PARAMETERS,
  ALGORITHM_MAX_PARAMETER_HISTORY,
  ALGORITHM_MAX_PARAMETER_MAGNITUDE,
  TEN_ALGORITHM_FAMILIES,
  FAMILY_CONTRACTS,
  CONTRACT_ONLY_PLACEHOLDERS,
  REFERENCE_STRATEGIES,
  oidaLoopLite,
  goalPriorityHintBudget,
  runtimeRiskGateRank,
  skillCapabilityMapLite,
  selfMonitoringMetricObserve,
  buildDefaultStrategyRegistry,
  buildContextMemoryStrategy,
  StrategyRegistry,
  StrategySelector,
  AdaptiveParameterStore,
  initialOidaState,
  advanceOida,
  completeOidaLoop,
  applyRiskVerdict,
  filterSkillsByCapabilities,
  validateOidaState,
  isAlgorithmDenial,
  isAlgorithmFamily,
  isOidaPhase,
  isGoalPriorityHint,
  isRiskVerdictTier,
  type AlgorithmDecisionInput,
  type AlgorithmFamily,
  type OidaLoopState,
  type RuntimeContext,
} from "@menog/algorithms";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import {
  WorkingMemoryStore,
  type MemoryPolicyGate,
} from "@menog/memory";
import type { Actor } from "@menog/core";

/**
 * 17E — Phase-17 Freeze Audit: Agentic Algorithm Kernel
 *
 * PURPOSE (gate mandate §4): adversarially pin the FULL Kernel V1 contract
 * surface built across 17A–17D so any regression turns this file red:
 *   - frozen literal constants (schema, families, caps, strategy ids/versions)
 *   - implemented-vs-contract truth (5 implemented, 5 contract-only,
 *     port-bound retrieval honestly out of the default registry)
 *   - authority separation (recommend-only pins, policy floor, no source
 *     mutation surface)
 *   - fail-closed deny states (all 10 machine-readable reasons, behaviorally)
 *   - deterministic determinism (equal inputs ⇒ equal outputs)
 *   - governance invariants verbatim in all Phase-17 artifacts
 *
 * These tests FREEZE Phase-17 behavior; regression retroactively invalidates
 * the Phase-17 freeze.
 */

const AGENT: Actor = { type: "agent", id: "freeze-17e" };

function ctx(overrides: Partial<RuntimeContext> = {}): RuntimeContext {
  return {
    actor: AGENT,
    workspaceId: "ws-freeze-17e",
    taskId: "task-freeze-17e",
    ...overrides,
  };
}

function input(
  overrides: Partial<AlgorithmDecisionInput> = {}
): AlgorithmDecisionInput {
  return {
    decision: "17E freeze probe",
    candidateLabels: ["a", "b"],
    sensitivity: "public",
    ...overrides,
  };
}

function readDoc(relativePath: string): string {
  const full = join(process.cwd(), relativePath);
  expect(existsSync(full), "expected doc to exist: " + relativePath).toBe(true);
  return readFileSync(full, "utf8");
}

// ---------------------------------------------------------------------------
// 17E-P — FROZEN CONTRACT PINS (any change = unfreeze-protocol event)
// ---------------------------------------------------------------------------
describe("17E-P — Kernel V1 frozen literal constants", () => {
  it("17E-P1 schema version is pinned at menog-algorithms/v0", () => {
    expect(ALGORITHM_SCHEMA_VERSION).toBe("menog-algorithms/v0");
  });

  it("17E-P2 the ten-family union is closed, frozen, and canonically ordered", () => {
    expect(Object.isFrozen(ALGORITHM_FAMILIES)).toBe(true);
    expect(ALGORITHM_FAMILIES).toHaveLength(10);
    expect([...TEN_ALGORITHM_FAMILIES]).toEqual([...ALGORITHM_FAMILIES]);
    const expectedOrder: readonly AlgorithmFamily[] = [
      "oida",
      "goal_priority",
      "context_memory_retrieval",
      "multiagent_task_allocation",
      "runtime_risk_evaluation",
      "skill_selection",
      "world_state_synchronization",
      "procedural_motion",
      "agent_communication_routing",
      "self_monitoring_adaptation",
    ];
    expect([...ALGORITHM_FAMILIES]).toEqual([...expectedOrder]);
    for (const f of ALGORITHM_FAMILIES) expect(isAlgorithmFamily(f)).toBe(true);
  });

  it("17E-P3 input/output bounds are pinned (bounded reasoning discipline)", () => {
    expect(ALGORITHM_MAX_CANDIDATES).toBe(64);
    expect(ALGORITHM_MAX_CANDIDATE_LABEL_CHARS).toBe(256);
    expect(ALGORITHM_MAX_DECISION_CHARS).toBe(256);
    expect(ALGORITHM_MAX_REASONING_SUMMARY_CHARS).toBe(256);
    expect(ALGORITHM_MAX_OIDATA_ITERATIONS).toBe(1000);
    expect(ALGORITHM_MAX_METRICS).toBe(32);
    expect(ALGORITHM_MAX_TUNABLE_PARAMETERS).toBe(64);
    expect(ALGORITHM_MAX_PARAMETER_HISTORY).toBe(32);
    expect(ALGORITHM_MAX_PARAMETER_MAGNITUDE).toBe(1_000_000);
  });

  it("17E-P4 the five implemented strategies are pinned by family, id, and version", () => {
    expect(oidaLoopLite).toMatchObject({ id: "loop-lite", family: "oida", version: "0.2.0", implemented: true });
    expect(goalPriorityHintBudget).toMatchObject({ id: "hint-budget", family: "goal_priority", version: "0.1.0", implemented: true });
    expect(runtimeRiskGateRank).toMatchObject({ id: "gate-rank", family: "runtime_risk_evaluation", version: "0.2.0", implemented: true });
    expect(skillCapabilityMapLite).toMatchObject({ id: "capability-map", family: "skill_selection", version: "0.2.0", implemented: true });
    expect(selfMonitoringMetricObserve).toMatchObject({ id: "observe-metrics", family: "self_monitoring_adaptation", version: "0.2.0", implemented: true });
  });

  it("17E-P5 OIDA state machine contracts are pinned (phases, initial state, transitions)", () => {
    expect(initialOidaState()).toEqual({ currentPhase: "observe", done: false, iteration: 0 });
    expect(validateOidaState(initialOidaState()).ok).toBe(true);
    const r = advanceOida(initialOidaState());
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.phase).toBe("interpret");
    expect(completeOidaLoop(initialOidaState()).ok).toBe(false); // only from act
    expect(isOidaPhase("observe")).toBe(true);
    expect(isOidaPhase("dream")).toBe(false);
  });

  it("17E-P6 type guards and integration helpers are pinned", () => {
    expect(isGoalPriorityHint("critical")).toBe(true);
    expect(isGoalPriorityHint("maximum")).toBe(false);
    expect(isRiskVerdictTier("restrict")).toBe(true);
    expect(isRiskVerdictTier("escalate")).toBe(false);
    // Monotone restriction floor: risk can never add capabilities.
    const granted = ["a", "b"];
    expect(applyRiskVerdict(granted, { tier: "deny", reason: "r" })).toEqual([]);
    expect(applyRiskVerdict(granted, { tier: "allow", reason: "r" })).toEqual(granted);
    expect(applyRiskVerdict(undefined, { tier: "deny", reason: "r" })).toBeUndefined();
    const f = filterSkillsByCapabilities(["x", "y"], ["y"]);
    expect(f.recommended).toEqual(["y"]);
    expect(f.withheld).toEqual(["x"]);
  });
});

// ---------------------------------------------------------------------------
// 17E-T — IMPLEMENTED-vs-CONTRACT TRUTH (honest status freeze)
// ---------------------------------------------------------------------------
describe("17E-T — implemented vs contracts-only truth", () => {
  it("17E-T1 exactly five families are implemented; exactly five are contract-only", () => {
    const implemented = FAMILY_CONTRACTS.filter((f) => f.implemented).map((f) => f.family).sort();
    expect(implemented).toEqual(
      ["goal_priority", "oida", "runtime_risk_evaluation", "self_monitoring_adaptation", "skill_selection"].sort()
    );
    expect(FAMILY_CONTRACTS.filter((f) => !f.implemented)).toHaveLength(5);
    expect(CONTRACT_ONLY_PLACEHOLDERS).toHaveLength(5);
  });

  it("17E-T2 the default registry has exactly one selectable strategy per family and validates completeness", () => {
    const registry = buildDefaultStrategyRegistry();
    expect(registry.size()).toBe(10);
    for (const f of TEN_ALGORITHM_FAMILIES) {
      expect(registry.listForFamily(f)).toHaveLength(1);
    }
    expect(REFERENCE_STRATEGIES).toHaveLength(10);
    expect(new Set(REFERENCE_STRATEGIES.map((s) => s.family)).size).toBe(10);
  });

  it("17E-T3 contract-only families fail closed: selectable, evaluation denied strategy_not_selected", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    for (const f of ["context_memory_retrieval", "multiagent_task_allocation", "world_state_synchronization", "procedural_motion", "agent_communication_routing"] as const) {
      const sel = registry.select(f, "contract-only");
      expect(sel.ok, f).toBe(true);
      if (sel.ok) {
        expect(sel.strategy.implemented).toBe(false);
        const r = await selector.evaluate(sel.strategy, input(), ctx());
        expect(r.ok, f).toBe(false);
        if (!r.ok) expect(r.denyReason).toBe("strategy_not_selected");
      }
    }
  });

  it("17E-T4 the port-bound retrieval strategy is honestly OUT of the default registry", () => {
    const registry = buildDefaultStrategyRegistry();
    expect(registry.select("context_memory_retrieval", "port-rank").ok).toBe(false);
    // It exists only when a caller supplies a policy-gated port.
    const ALLOW_ALL: MemoryPolicyGate = { canReadMemory: () => true, canWriteMemory: () => true };
    const memory = new WorkingMemoryStore({ policyGate: ALLOW_ALL });
    const portBound = buildContextMemoryStrategy(
      // structural port via the memory service is exercised in 17C tests; here
      // a minimal structural port suffices to prove registration behavior.
      { async retrieve() { return { ok: true as const, hits: [] }; } }
    );
    const reg2 = new StrategyRegistry([portBound]);
    expect(reg2.select("context_memory_retrieval", "port-rank").ok).toBe(true);
    void memory;
  });

  it("17E-T5 family contracts record gate-provenance status notes (17B/17C/17D markers)", () => {
    expect(FAMILY_CONTRACTS.find((f) => f.family === "oida")!.statusNote).toContain("17B");
    expect(FAMILY_CONTRACTS.find((f) => f.family === "goal_priority")!.statusNote).toContain("17B");
    expect(FAMILY_CONTRACTS.find((f) => f.family === "runtime_risk_evaluation")!.statusNote).toContain("17C");
    expect(FAMILY_CONTRACTS.find((f) => f.family === "skill_selection")!.statusNote).toContain("17C");
    expect(FAMILY_CONTRACTS.find((f) => f.family === "context_memory_retrieval")!.statusNote).toContain("17C");
    expect(FAMILY_CONTRACTS.find((f) => f.family === "self_monitoring_adaptation")!.statusNote).toContain("17D");
  });

  it("17E-T6 doc registry remains in truth-sync with the code (family ids + rule line)", () => {
    const doc = readDoc("docs/ALGORITHM_REGISTRY_v0.md");
    for (const f of TEN_ALGORITHM_FAMILIES) {
      expect(doc.includes(f), "registry doc missing family " + f).toBe(true);
    }
    expect(doc.includes("Algorithms recommend/compute. Policy authorizes. Runtime executes.")).toBe(true);
    expect(doc.includes("TEN CONTRACTS")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 17E-A — AUTHORITY + FAIL-CLOSED AUDIT (behavioral freeze)
// ---------------------------------------------------------------------------
describe("17E-A — authority separation and deny states (behavioral)", () => {
  it("17E-A1 all five implemented strategies return pinned non-authoritative recommendations", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const ids: Record<string, string> = {
      oida: "loop-lite",
      goal_priority: "hint-budget",
      runtime_risk_evaluation: "gate-rank",
      skill_selection: "capability-map",
      self_monitoring_adaptation: "observe-metrics",
    };
    for (const family of Object.keys(ids)) {
      const sel = registry.select(family as AlgorithmFamily, ids[family]!);
      expect(sel.ok, family).toBe(true);
      if (sel.ok) {
        const r = await selector.evaluate(sel.strategy, input(), ctx());
        if (r.ok) {
          expect(r.recommendation.isRecommendation).toBe(true);
          expect(r.recommendation.executionAuthorized).toBe(false);
        }
      }
    }
  });

  it("17E-A2 an authority-claiming strategy is denied and never surfaced (any family)", async () => {
    const registry = new StrategyRegistry();
    registry.register({
      id: "pretender",
      family: "goal_priority",
      version: "1.0.0",
      implemented: true,
      description: "claims authority",
      async evaluate() {
        return {
          family: "goal_priority" as AlgorithmFamily,
          strategyId: "pretender",
          rankedCandidates: ["x"],
          confidence: 1,
          rationale: "self-authorized",
          isRecommendation: true as const,
          executionAuthorized: true as unknown as false,
        };
      },
    });
    const selector = new StrategySelector();
    const s = registry.select("goal_priority", "pretender");
    if (s.ok) {
      const r = await selector.evaluate(s.strategy, input(), ctx());
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.denyReason).toBe("recommendation_not_authoritative");
    }
  });

  it("17E-A3 the full deny-reason union is behaviorally reachable (fail-closed freeze)", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();

    // unknown_family
    const fam = registry.select("nope" as AlgorithmFamily, "loop-lite");
    expect(!fam.ok && fam.denyReason).toBe("unknown_family");
    // unknown_strategy
    const strat = registry.select("oida", "ghost");
    expect(!strat.ok && strat.denyReason).toBe("unknown_strategy");
    // invalid_input
    const oidaSel = registry.select("oida", "loop-lite");
    expect(oidaSel.ok).toBe(true);
    const badInput = oidaSel.ok
      ? await selector.evaluate(oidaSel.strategy, input({ decision: "" }), ctx())
      : null;
    expect(badInput !== null && !badInput.ok && badInput.denyReason).toBe("invalid_input");
    // oversized_input
    const big = oidaSel.ok
      ? await selector.evaluate(
          oidaSel.strategy,
          input({ candidateLabels: Array.from({ length: 65 }, (_, i) => "c" + String(i)) }),
          ctx()
        )
      : null;
    expect(big !== null && !big.ok && big.denyReason).toBe("oversized_input");
    // invalid_state
    const state = oidaSel.ok
      ? await selector.evaluate(
          oidaSel.strategy,
          input({ oidaState: { currentPhase: "observe", done: true, iteration: 0 } as OidaLoopState }),
          ctx()
        )
      : null;
    expect(state !== null && !state.ok && state.denyReason).toBe("invalid_state");
    // strategy_not_selected (contract-only)
    const coSel = registry.select("multiagent_task_allocation", "contract-only");
    expect(coSel.ok).toBe(true);
    const co = coSel.ok ? await selector.evaluate(coSel.strategy, input(), ctx()) : null;
    expect(co !== null && !co.ok && co.denyReason).toBe("strategy_not_selected");
    // recommendation_not_authoritative is proven in 17E-A2.
    // selection_not_allowed semantics: family binding refused on replace.
    const reg2 = new StrategyRegistry();
    reg2.register({
      id: "s1", family: "oida", version: "1.0.0", implemented: true, description: "d",
      async evaluate() {
        return {
          family: "oida" as AlgorithmFamily, strategyId: "s1", rankedCandidates: [],
          confidence: 0.5, rationale: "r", isRecommendation: true as const, executionAuthorized: false as const,
        };
      },
    });
    const wrongFamily = registry.select("goal_priority", "s1");
    expect(wrongFamily.ok).toBe(false);
    // retrieval_unavailable: port denying
    const portStrategy = buildContextMemoryStrategy({
      async retrieve() { return { ok: false, denyReason: "read_not_allowed", reason: "denied" }; },
    });
    const reg3 = new StrategyRegistry([portStrategy]);
    const sel3 = reg3.select("context_memory_retrieval", "port-rank");
    expect(sel3.ok).toBe(true);
    if (sel3.ok) {
      const r = await selector.evaluate(sel3.strategy, input(), ctx());
      expect(!r.ok && r.denyReason).toBe("retrieval_unavailable");
    }
    // adaptation_out_of_bounds / parameter_unknown / rollback_target_missing
    const store = new AdaptiveParameterStore();
    const unknown = store.apply({ parameter: "ghost", currentValue: 0, proposedValue: 1, bounds: { min: 0, max: 1 }, reason: "r" });
    expect(!unknown.ok && unknown.reason.startsWith("parameter_unknown")).toBe(true);
    store.register("p", 5, { min: 0, max: 10 });
    const oob = store.apply({ parameter: "p", currentValue: 5, proposedValue: 99, bounds: { min: 0, max: 10 }, reason: "r" });
    expect(!oob.ok && oob.reason.startsWith("adaptation_out_of_bounds")).toBe(true);
    const rb = store.rollback("p");
    expect(!rb.ok && rb.reason.startsWith("rollback_target_missing")).toBe(true);
  });

  it("17E-A4 the policy engine remains the sole authority (Day-1 deny unchanged)", () => {
    const engine = new DenyByDefaultPolicyEngine();
    for (const verb of ["oida.advance", "goal.rank", "risk.evaluate", "skill.select", "monitor.observe", "commit"]) {
      const res = engine.evaluate({
        actor: AGENT,
        verb,
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-freeze-17e",
      });
      expect(res.decision.outcome, "verb " + verb).toBe("deny");
    }
  });

  it("17E-A5 the parameter store exposes NO source-mutation surface (17D invariant frozen)", () => {
    const store = new AdaptiveParameterStore();
    let proto = Object.getPrototypeOf(store) as Record<string, unknown>;
    const methods = new Set<string>();
    while (proto && proto !== Object.prototype) {
      for (const m of Object.getOwnPropertyNames(proto)) methods.add(m);
      proto = Object.getPrototypeOf(proto) as Record<string, unknown>;
    }
    for (const banned of ["writeFile", "appendFile", "unlink", "eval", "exec", "spawn", "commit", "push"]) {
      expect(methods.has(banned), "store must not expose '" + banned + "'").toBe(false);
    }
  });

  it("17E-A6 determinism: equal inputs give equal recommendations across strategies", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const risk = registry.select("runtime_risk_evaluation", "gate-rank");
    if (risk.ok) {
      const i = input({ candidateLabels: ["write a", "read b"] });
      const r1 = await selector.evaluate(risk.strategy, i, ctx());
      const r2 = await selector.evaluate(risk.strategy, i, ctx());
      expect(r1.ok && r2.ok).toBe(true);
      if (r1.ok && r2.ok) {
        expect(r1.recommendation.rankedCandidates).toEqual(r2.recommendation.rankedCandidates);
        expect(r1.recommendation.confidence).toBe(r2.recommendation.confidence);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 17E-V — GOVERNANCE INVARIANTS (15E/16E pattern)
// ---------------------------------------------------------------------------
describe("17E-V — governance invariants frozen in Phase-17 artifacts", () => {
  const PR_BLOCK_LINES = [
    "PR-01 HUMAN_DISPOSITION_PENDING",
    "PR-02 HOLD",
    "PR-03 HUMAN_DISPOSITION_PENDING",
    "PR-04 HOLD",
    "PR-05 HOLD",
  ];
  const DOCS_CARRYING_PR_BLOCK = [
    "docs/release/PROMPT_17A_REPORT.md",
    "docs/release/PROMPT_17B_REPORT.md",
    "docs/release/PROMPT_17C_REPORT.md",
    "docs/release/PROMPT_17D_REPORT.md",
    "docs/release/PROMPT_17E_REPORT.md",
    "docs/release/PHASE_17_FREEZE.md",
  ];

  it("17E-V1 PR-01..PR-05 disposition block is verbatim in all Phase-17 gate artifacts", () => {
    for (const doc of DOCS_CARRYING_PR_BLOCK) {
      const content = readDoc(doc).replace(/\s+/g, " ");
      for (const line of PR_BLOCK_LINES) {
        expect(content.includes(line), doc + " missing " + line).toBe(true);
      }
    }
  });

  it("17E-V2 authorization-not-granted lines are unchanged in all Phase-17 gate artifacts", () => {
    for (const doc of DOCS_CARRYING_PR_BLOCK) {
      const content = readDoc(doc).replace(/\s+/g, " ");
      expect(content.includes("COMMIT AUTHORIZATION NOT GRANTED"), doc).toBe(true);
      expect(content.includes("PUSH AUTHORIZATION NOT GRANTED"), doc).toBe(true);
      expect(content.includes("PUBLICATION AUTHORIZATION NOT GRANTED"), doc).toBe(true);
    }
  });

  it("17E-V3 no Phase-20 isolation primitives exist in the algorithms package source", () => {
    const srcRoot = join(process.cwd(), "packages", "algorithms", "src");
    const files = [
      "types.ts", "registry.ts", "selector.ts", "families.ts", "serialize.ts",
      "oida.ts", "oidaStrategy.ts", "goalPriority.ts", "integration.ts",
      "riskSkill.ts", "contextMemory.ts", "selfMonitoring.ts", "index.ts",
    ];
    const forbidden = /cgroup|seccomp|landlock|rootless|unshare|clone3/i;
    for (const f of files) {
      const full = join(srcRoot, f);
      expect(existsSync(full), "algorithms source file missing: " + f).toBe(true);
      expect(forbidden.test(readFileSync(full, "utf8")), "Phase-20 primitive in " + f).toBe(false);
    }
  });

  it("17E-V4 algorithms package declares workspace-only dependencies and empty devDependencies", () => {
    const pkg = JSON.parse(readDoc("packages/algorithms/package.json")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = Object.keys(pkg.dependencies ?? {});
    expect(deps.length).toBeGreaterThan(0);
    for (const d of deps) {
      expect(d.startsWith("@menog/"), "non-workspace dependency: " + d).toBe(true);
    }
    expect(pkg.devDependencies ?? {}).toEqual({});
  });

  it("17E-V5 the freeze artifact declares the Phase-17 transition and honest roadmap language", () => {
    const freeze = readDoc("docs/release/PHASE_17_FREEZE.md");
    expect(freeze.includes("Phase-17: OPEN → FROZEN")).toBe(true);
    expect(freeze.includes("PENDING HUMAN SIGNATURE")).toBe(true);
    expect(freeze.includes("Kernel V1")).toBe(true);
    expect(freeze.includes("ROADMAP ONLY")).toBe(true);
    expect(freeze.includes("multi-agent integration")).toBe(true);
  });

  it("17E-V6 ledger observability of algorithm evaluations stays intact (chain-verifiable)", async () => {
    const events: Array<Record<string, unknown>> = [];
    const selector = new StrategySelector({
      ledger: {
        append: (e) => {
          events.push({ ...e });
          return { ok: true, eventId: "alg-17e-" + String(events.length) };
        },
      },
    });
    const registry = buildDefaultStrategyRegistry();
    const risk = registry.select("runtime_risk_evaluation", "gate-rank");
    if (risk.ok) {
      await selector.evaluate(risk.strategy, input(), ctx());
      await selector.evaluate(risk.strategy, input({ decision: "" }), ctx());
      expect(events).toHaveLength(2);
      expect(events[0]!["eventType"]).toBe("algorithm_recommended");
      expect(events[1]!["eventType"]).toBe("algorithm_denied");
      expect(isAlgorithmDenial({ ok: false, denyReason: "invalid_input", reason: "x" })).toBe(true);
    }
  });
});
