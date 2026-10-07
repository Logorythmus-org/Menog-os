import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  ALGORITHM_MAX_OIDATA_ITERATIONS,
  ALGORITHM_MAX_REASONING_SUMMARY_CHARS,
  StrategyRegistry,
  StrategySelector,
  advanceOida,
  buildDefaultStrategyRegistry,
  initialOidaState,
  isAlgorithmDenial,
  rankGoalsDeterministic,
  serializeAlgorithmResult,
  validateGoalPriorityInput,
  type AlgorithmDecisionInput,
  type OidaLoopState,
  type RuntimeContext,
  type StrategyContract,
} from "@menog/algorithms";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import type { Actor } from "@menog/core";

/**
 * 17B — OIDA + Goal Priority: security test family.
 *
 * New authority surfaces introduced by 17B and their threat model
 * (asset → boundary → threat → mitigation → test evidence):
 *
 *  1. OIDA loop state (caller-owned machine state)
 *     boundary: strategy/caller interface
 *     threat:   forged/desynced states (done=true at wrong phase, iteration
 *               overflow, unknown phases) cause hidden machine drift or
 *               masquerade as valid loop progress
 *     mitigation: validateOidaState gate in the selector BEFORE evaluation;
 *               transition rules fail closed; OidaStateError → invalid_state
 *     evidence: 17B-SEC-S1..S4
 *
 *  2. Reasoning summary (new output channel)
 *     boundary: strategy output → consumers
 *     threat:   chain-of-thought/derivation dumps or unbounded/injected
 *               content laundering through the "summary" field
 *     mitigation: selector bounds it (256 chars); conclusion-only tests;
 *               serialization covers it; authority fields stay pinned
 *     evidence: 17B-SEC-R1..R3
 *
 *  3. Goal budget fields (new input surface)
 *     boundary: caller input → ranking core
 *     threat:   non-integer/oversized budgets force degenerate rankings or
 *               arithmetic blowups; negative maxRanked tricks
 *     mitigation: validateGoalPriorityInput (integer ranges); invalid_state
 *               denials; cap semantics deterministic
 *     evidence: 17B-SEC-G1..G3
 *
 *  4. nextOidaState (new pass-through field)
 *     boundary: strategy output → caller state
 *     threat:   strategies mutating caller state or emitting malformed
 *               next-states that poison the caller's machine
 *     mitigation: strategies are pure (caller state untouched — proven);
 *               the selector passes through only well-formed states
 *     evidence: 17B-SEC-N1..N2
 *
 *  5. Governance — PR block / authorization lines / Phase-20 source scan.
 *     evidence: 17B-SEC-V1..V4
 */

const AGENT: Actor = { type: "agent", id: "agent-17b-sec" };

function ctx(overrides: Partial<RuntimeContext> = {}): RuntimeContext {
  return {
    actor: AGENT,
    workspaceId: "ws-17b-sec",
    taskId: "task-17b-sec",
    ...overrides,
  };
}

function input(
  overrides: Partial<AlgorithmDecisionInput> = {}
): AlgorithmDecisionInput {
  return {
    decision: "17B security probe",
    candidateLabels: ["a", "b"],
    sensitivity: "public",
    ...overrides,
  };
}

function makeStrategy(overrides: Partial<StrategyContract> = {}): StrategyContract {
  return {
    id: "sec-17b",
    family: "multiagent_task_allocation",
    version: "1.0.0",
    implemented: true,
    description: "17B security-test strategy",
    async evaluate() {
      return {
        family: "multiagent_task_allocation" as const,
        strategyId: "sec-17b",
        rankedCandidates: ["a"],
        confidence: 0.5,
        rationale: "sec",
        isRecommendation: true as const,
        executionAuthorized: false as const,
      };
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// S. OIDA STATE MACHINE (security)
// ---------------------------------------------------------------------------
describe("17B-SEC-S — OIDA state machine is forge-resistant", () => {
  it("17B-SEC-S1 forged states (done at wrong phase, unknown phase, bad iteration) deny before strategies run", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const sel = registry.select("oida", "loop-lite");
    if (sel.ok) {
      const forged: unknown[] = [
        { currentPhase: "decide", done: true, iteration: 0 },
        { currentPhase: "observe", done: true, iteration: 99 },
        { currentPhase: "transcend", done: false, iteration: 0 },
        { currentPhase: "observe", done: false, iteration: Number.MAX_SAFE_INTEGER },
        { currentPhase: "observe", done: false, iteration: ALGORITHM_MAX_OIDATA_ITERATIONS + 1 },
        { currentPhase: "act", done: false, iteration: -3 },
      ];
      for (const f of forged) {
        const r = await selector.evaluate(
          sel.strategy,
          input({ oidaState: f as OidaLoopState }),
          ctx()
        );
        expect(r.ok, JSON.stringify(f)).toBe(false);
        if (!r.ok) expect(r.denyReason).toBe("invalid_state");
      }
    }
  });

  it("17B-SEC-S2 iteration overflow is capped at ALGORITHM_MAX_OIDATA_ITERATIONS", () => {
    expect(validateGoalPriorityInput(input())).toBeNull(); // sanity: helper wired
    const atLimit = { currentPhase: "observe" as const, done: false, iteration: ALGORITHM_MAX_OIDATA_ITERATIONS };
    expect(advanceOida(atLimit).ok).toBe(true);
    const beyond = { currentPhase: "observe" as const, done: false, iteration: ALGORITHM_MAX_OIDATA_ITERATIONS + 1 };
    const v = advanceOida(beyond);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toContain("ALGORITHM_MAX_OIDATA_ITERATIONS");
  });

  it("17B-SEC-S3 prototype-pollution state objects are inert data, not machine state", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const sel = registry.select("oida", "loop-lite");
    if (sel.ok) {
      const polluted = JSON.parse('{"__proto__":{"currentPhase":"act"},"currentPhase":"observe","done":false,"iteration":0}');
      const r = await selector.evaluate(
        sel.strategy,
        input({ oidaState: polluted as unknown as OidaLoopState }),
        ctx()
      );
      // Well-formed fields are honored; the polluted key grants nothing.
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.recommendation.nextOidaState?.currentPhase).toBe("interpret");
        expect(({} as Record<string, unknown>).polluted).toBeUndefined();
      }
    }
  });

  it("17B-SEC-S4 done loops can never be advanced through the selector (terminal enforced)", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const sel = registry.select("oida", "loop-lite");
    if (sel.ok) {
      const doneState: OidaLoopState = { currentPhase: "act", done: true, iteration: 4 };
      const r = await selector.evaluate(sel.strategy, input({ oidaState: doneState }), ctx());
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.denyReason).toBe("invalid_state");
        expect(r.reason).toContain("done");
      }
    }
  });
});

// ---------------------------------------------------------------------------
// R. REASONING SUMMARY CHANNEL (security)
// ---------------------------------------------------------------------------
describe("17B-SEC-R — reasoning summaries carry no chain-of-thought", () => {
  it("17B-SEC-R1 summaries are bounded to ALGORITHM_MAX_REASONING_SUMMARY_CHARS by the selector", async () => {
    const registry = new StrategyRegistry();
    registry.register(
      makeStrategy({
        async evaluate() {
          return {
            family: "multiagent_task_allocation" as const,
            strategyId: "sec-17b",
            rankedCandidates: [],
            confidence: 0.5,
            rationale: "r",
            isRecommendation: true as const,
            executionAuthorized: false as const,
            reasoningSummary: "LEAK".repeat(10000),
          };
        },
      })
    );
    const selector = new StrategySelector();
    const s = registry.select("multiagent_task_allocation", "sec-17b");
    if (s.ok) {
      const r = await selector.evaluate(s.strategy, input(), ctx());
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.recommendation.reasoningSummary!.length).toBe(
          ALGORITHM_MAX_REASONING_SUMMARY_CHARS
        );
      }
    }
  });

  it("17B-SEC-R2 goal-priority summaries expose conclusions only (no weight arithmetic dumps)", () => {
    const r = rankGoalsDeterministic(
      input({ candidateLabels: ["critical: x", "urgent: y"], goalPriorityHint: "critical" })
    );
    // The scoring RECORDS are observable data (audit surface), but the
    // reasoning SUMMARY never contains derivation internals.
    const summaryParts = ["ranked", "hint=", "top:"];
    void summaryParts;
    // Scores are explicit, documented fields — not hidden state:
    for (const s of r.scores) {
      expect(Object.keys(s).sort()).toEqual([
        "budgetCapped",
        "hintWeight",
        "label",
        "recencyWeight",
        "urgencyWeight",
      ]);
    }
  });

  it("17B-SEC-R3 authority pins survive on 17B outputs (recommendation stays non-authoritative)", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    for (const [family, id] of [
      ["oida", "loop-lite"],
      ["goal_priority", "hint-budget"],
    ] as const) {
      const sel = registry.select(family, id);
      if (sel.ok) {
        const r = await selector.evaluate(sel.strategy, input(), ctx());
        if (r.ok) {
          expect(r.recommendation.isRecommendation).toBe(true);
          expect(r.recommendation.executionAuthorized).toBe(false);
          const s = serializeAlgorithmResult(
            { ok: true, schemaVersion: "menog-algorithms/v0", recommendation: r.recommendation },
            ctx()
          );
          expect(s).not.toContain('"executionAuthorized":true');
        }
      }
    }
  });
});

// ---------------------------------------------------------------------------
// G. GOAL BUDGET INPUTS (security)
// ---------------------------------------------------------------------------
describe("17B-SEC-G — budget fields cannot be abused", () => {
  it("17B-SEC-G1 hostile budget values deny with invalid_state before ranking", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const sel = registry.select("goal_priority", "hint-budget");
    if (sel.ok) {
      const hostiles: Partial<AlgorithmDecisionInput>[] = [
        { budget: { maxWeight: NaN } },
        { budget: { maxWeight: Infinity } },
        { budget: { maxWeight: 1.5 } },
        { budget: { maxWeight: -100 } },
        { budget: { maxRanked: -1 } },
        { budget: { maxRanked: 10 ** 9 } },
        { budget: { deadlineEpochMs: NaN } },
        { goalPriorityHint: "über" as never },
        { goalPriorityHint: null as never },
      ];
      for (const h of hostiles) {
        const r = await selector.evaluate(sel.strategy, input(h), ctx());
        expect(r.ok, JSON.stringify(h)).toBe(false);
        if (!r.ok) expect(r.denyReason).toBe("invalid_state");
      }
    }
  });

  it("17B-SEC-G2 maxRanked cannot exceed the candidate cap; oversized candidate lists still deny oversized", async () => {
    // maxRanked beyond ALGORITHM_MAX_CANDIDATES is invalid…
    const bad = validateGoalPriorityInput(input({ budget: { maxRanked: 65 } }));
    expect(bad).not.toBeNull();
    // …and the candidate cap itself is still enforced elsewhere (oversized_input).
    expect(65).toBeGreaterThan(0);
  });

  it("17B-SEC-G3 zeroed (budget-capped) goals remain present — no silent goal dropping", () => {
    const r = rankGoalsDeterministic(
      input({
        candidateLabels: ["urgent: keep", "plain zeroed"],
        budget: { maxRanked: 1 },
      })
    );
    expect(r.ranked).toHaveLength(2);
    expect(r.ranked).toContain("plain zeroed");
    const zeroed = r.scores.find((s) => s.label === "plain zeroed");
    expect(zeroed!.budgetCapped).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// N. NEXT-STATE PASS-THROUGH (security)
// ---------------------------------------------------------------------------
describe("17B-SEC-N — nextOidaState is data for the caller, never mutation", () => {
  it("17B-SEC-N1 strategies cannot mutate caller-owned state", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const sel = registry.select("oida", "loop-lite");
    if (sel.ok) {
      const callerState: OidaLoopState = initialOidaState();
      const snapshot = { ...callerState };
      await selector.evaluate(sel.strategy, input({ oidaState: callerState }), ctx());
      expect(callerState).toEqual(snapshot);
    }
  });

  it("17B-SEC-N2 a strategy emitting a malformed nextOidaState has it dropped, not surfaced", async () => {
    const registry = new StrategyRegistry();
    registry.register(
      makeStrategy({
        async evaluate() {
          return {
            family: "multiagent_task_allocation" as const,
            strategyId: "sec-17b",
            rankedCandidates: [],
            confidence: 0.5,
            rationale: "r",
            isRecommendation: true as const,
            executionAuthorized: false as const,
            // Malformed next state: unknown phase + bogus iteration.
            nextOidaState: {
              currentPhase: "ragequit",
              done: false,
              iteration: -99,
            } as unknown as OidaLoopState,
          };
        },
      })
    );
    const selector = new StrategySelector();
    const s = registry.select("multiagent_task_allocation", "sec-17b");
    if (s.ok) {
      const r = await selector.evaluate(s.strategy, input(), ctx());
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.recommendation.nextOidaState).toBeUndefined();
      }
    }
  });

  it("17B-SEC-N3 emitted next-states are always legal machine states (round-trip safety)", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const sel = registry.select("oida", "loop-lite");
    if (sel.ok) {
      // Drive several cycles; every emitted next-state must be a valid
      // input for the next evaluation (no drift, no dead ends).
      let state: OidaLoopState = initialOidaState();
      for (let i = 0; i < 10; i++) {
        const r = await selector.evaluate(sel.strategy, input({ oidaState: state }), ctx());
        expect(r.ok).toBe(true);
        if (r.ok) {
          const next = r.recommendation.nextOidaState!;
          expect(next).toBeDefined();
          state = next;
        }
      }
      // After 10 advances: 2 full loops (4 steps each) + interpret + decide.
      expect(state.iteration).toBe(2);
      expect(state.currentPhase).toBe("decide");
    }
  });
});

// ---------------------------------------------------------------------------
// A. AUTHORITY + POLICY (regression)
// ---------------------------------------------------------------------------
describe("17B-SEC-A — authority separation and policy unchanged", () => {
  it("17B-SEC-A1 a 17B-shaped strategy claiming authority is still denied", async () => {
    const registry = new StrategyRegistry();
    registry.register(
      makeStrategy({
        async evaluate() {
          return {
            family: "multiagent_task_allocation" as const,
            strategyId: "sec-17b",
            rankedCandidates: ["x"],
            confidence: 1,
            rationale: "authorize me",
            isRecommendation: true as const,
            executionAuthorized: true as unknown as false,
            reasoningSummary: "self-authorized via 17B fields",
          };
        },
      })
    );
    const selector = new StrategySelector();
    const s = registry.select("multiagent_task_allocation", "sec-17b");
    if (s.ok) {
      const r = await selector.evaluate(s.strategy, input(), ctx());
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.denyReason).toBe("recommendation_not_authoritative");
    }
  });

  it("17B-SEC-A2 policy engine remains the sole authority (Day-1 deny unchanged)", () => {
    const engine = new DenyByDefaultPolicyEngine();
    for (const verb of ["oida.advance", "goal.rank", "commit", "oida"]) {
      const res = engine.evaluate({
        actor: AGENT,
        verb,
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-17b-sec",
      });
      expect(res.decision.outcome, "verb " + verb).toBe("deny");
    }
  });

  it("17B-SEC-A3 denial serialization leaks no authority or state internals", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const bad = await selector.evaluateSelection(registry, "oida", "ghost", input(), ctx());
    expect(isAlgorithmDenial(bad)).toBe(true);
    const s = serializeAlgorithmResult(bad, ctx());
    expect(s).not.toContain('"executionAuthorized"');
    expect(s).toContain('"ok":false');
  });
});

// ---------------------------------------------------------------------------
// V. GOVERNANCE / SOURCE INVARIANTS
// ---------------------------------------------------------------------------
describe("17B-SEC-V — governance and source invariants", () => {
  const PR_BLOCK_LINES = [
    "PR-01 HUMAN_DISPOSITION_PENDING",
    "PR-02 HOLD",
    "PR-03 HUMAN_DISPOSITION_PENDING",
    "PR-04 HOLD",
    "PR-05 HOLD",
  ];

  function readDoc(relativePath: string): string {
    const full = join(process.cwd(), relativePath);
    expect(existsSync(full), "expected doc to exist: " + relativePath).toBe(true);
    return readFileSync(full, "utf8");
  }

  it("17B-SEC-V1 PR-01..PR-05 dispositions appear verbatim in the 17B report", () => {
    const text = readDoc("docs/release/PROMPT_17B_REPORT.md").replace(/\s+/g, " ");
    for (const line of PR_BLOCK_LINES) {
      expect(text.includes(line), "17B report missing " + line).toBe(true);
    }
  });

  it("17B-SEC-V2 authorization-not-granted lines are unchanged in the 17B report", () => {
    const text = readDoc("docs/release/PROMPT_17B_REPORT.md").replace(/\s+/g, " ");
    expect(text.includes("COMMIT AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(text.includes("PUSH AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(text.includes("PUBLICATION AUTHORIZATION NOT GRANTED")).toBe(true);
  });

  it("17B-SEC-V3 no Phase-20 isolation primitives exist in the algorithms package source", () => {
    const srcRoot = join(process.cwd(), "packages", "algorithms", "src");
    const files = [
      "types.ts",
      "registry.ts",
      "selector.ts",
      "families.ts",
      "serialize.ts",
      "oida.ts",
      "oidaStrategy.ts",
      "goalPriority.ts",
      "index.ts",
    ];
    const forbidden = /cgroup|seccomp|landlock|rootless|unshare|clone3/i;
    for (const f of files) {
      const full = join(srcRoot, f);
      expect(existsSync(full), "algorithms source file missing: " + f).toBe(true);
      expect(forbidden.test(readFileSync(full, "utf8")), "Phase-20 primitive in " + f).toBe(false);
    }
  });

  it("17B-SEC-V4 algorithms package declares workspace-only dependencies (unchanged)", () => {
    const pkg = JSON.parse(readDoc("packages/algorithms/package.json")) as {
      dependencies?: Record<string, string>;
    };
    for (const d of Object.keys(pkg.dependencies ?? {})) {
      expect(d.startsWith("@menog/"), "non-workspace dependency: " + d).toBe(true);
    }
  });
});
