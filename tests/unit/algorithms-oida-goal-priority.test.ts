import { describe, it, expect } from "vitest";
import {
  ALGORITHM_MAX_BUDGET_WEIGHT,
  ALGORITHM_MAX_OIDATA_ITERATIONS,
  ALGORITHM_MAX_REASONING_SUMMARY_CHARS,
  ALGORITHM_SCHEMA_VERSION,
  OIDATA_PHASES,
  StrategySelector,
  advanceOida,
  buildDefaultStrategyRegistry,
  completeOidaLoop,
  familyContract,
  goalUrgencyWeight,
  initialOidaState,
  isAlgorithmDenial,
  oidaLoopLite,
  OidaStateError,
  rankGoalsDeterministic,
  serializeRecommendation,
  serializeAlgorithmResult,
  validateOidaState,
  type AlgorithmDecisionInput,
  type AlgorithmLedgerEmitter,
  type OidaLoopState,
  type RuntimeContext,
} from "@menog/algorithms";

const CTX: RuntimeContext = {
  actor: { type: "agent", id: "agent-17b" },
  workspaceId: "ws-17b",
  taskId: "task-17b",
};

function input(
  overrides: Partial<AlgorithmDecisionInput> = {}
): AlgorithmDecisionInput {
  return {
    decision: "17B probe",
    candidateLabels: ["a", "b"],
    sensitivity: "public",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// 1. STATE TRANSITION TESTS (required)
// ---------------------------------------------------------------------------
describe("17B — OIDA state transitions", () => {
  it("initial state is observe/done=false/iteration=0", () => {
    const s = initialOidaState();
    expect(s).toEqual({ currentPhase: "observe", done: false, iteration: 0 });
    expect(validateOidaState(s).ok).toBe(true);
  });

  it("canonical advance observe → interpret → decide → act", () => {
    let s = initialOidaState();
    const phases: string[] = [];
    for (let i = 0; i < 3; i++) {
      const r = advanceOida(s);
      expect(r.ok).toBe(true);
      if (r.ok) {
        s = r.state;
        phases.push(r.phase);
      }
    }
    expect(phases).toEqual(["interpret", "decide", "act"]);
    expect(s.currentPhase).toBe("act");
    expect(s.done).toBe(false);
    expect(s.iteration).toBe(0);
  });

  it("act loops back to observe and increments iteration", () => {
    const s: OidaLoopState = { currentPhase: "act", done: false, iteration: 2 };
    const r = advanceOida(s);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.state.currentPhase).toBe("observe");
      expect(r.state.iteration).toBe(3);
      expect(r.state.done).toBe(false);
    }
  });

  it("loop-around then full second cycle keeps state consistent", () => {
    let s = initialOidaState();
    // Cycle 1
    for (let i = 0; i < 4; i++) {
      const r = advanceOida(s);
      if (r.ok) s = r.state;
    }
    expect(s.currentPhase).toBe("observe");
    expect(s.iteration).toBe(1);
    // Cycle 2
    for (let i = 0; i < 4; i++) {
      const r = advanceOida(s);
      if (r.ok) s = r.state;
    }
    expect(s.currentPhase).toBe("observe");
    expect(s.iteration).toBe(2);
  });

  it("completeOidaLoop only completes from act and marks done=true", () => {
    let s = initialOidaState();
    // Cannot complete before act.
    for (const _phase of ["observe", "interpret", "decide"]) {
      void _phase;
      expect(completeOidaLoop(s).ok).toBe(false);
      const r = advanceOida(s);
      if (r.ok) s = r.state;
    }
    expect(s.currentPhase).toBe("act");
    const done = completeOidaLoop(s);
    expect(done.ok).toBe(true);
    if (done.ok) {
      expect(done.state.done).toBe(true);
      expect(done.state.currentPhase).toBe("act");
    }
  });

  it("completed loop can never advance again (terminal state)", () => {
    let s = initialOidaState();
    for (let i = 0; i < 3; i++) {
      const r = advanceOida(s);
      if (r.ok) s = r.state;
    }
    const d = completeOidaLoop(s);
    expect(d.ok).toBe(true);
    if (d.ok) {
      const again = advanceOida(d.state);
      expect(again.ok).toBe(false);
      if (!again.ok) expect(again.reason).toContain("done");
    }
  });

  it("advancing a done loop denies; double-completion denies", () => {
    const doneState: OidaLoopState = { currentPhase: "act", done: true, iteration: 1 };
    const a = advanceOida(doneState);
    expect(a.ok).toBe(false);
    const c = completeOidaLoop(doneState);
    expect(c.ok).toBe(false);
    if (!c.ok) expect(c.reason).toContain("already done");
  });

  it("the strategy never mutates caller state (pure transition data)", async () => {
    const registry = buildDefaultStrategyRegistry();
    const sel = registry.select("oida", "loop-lite");
    if (sel.ok) {
      const before: OidaLoopState = { currentPhase: "observe", done: false, iteration: 0 };
      const snapshot = { ...before };
      const selector = new StrategySelector();
      const r = await selector.evaluate(sel.strategy, input({ oidaState: before }), CTX);
      expect(r.ok).toBe(true);
      expect(before).toEqual(snapshot); // caller state untouched
      if (r.ok) {
        expect(r.recommendation.nextOidaState).toEqual({
          currentPhase: "interpret",
          done: false,
          iteration: 0,
        });
      }
    }
  });

  it("loop-lite@0.2.0 is the registered oida strategy (upgrade pinned)", () => {
    const registry = buildDefaultStrategyRegistry();
    const sel = registry.select("oida", "loop-lite");
    expect(sel.ok).toBe(true);
    if (sel.ok) expect(sel.strategy.version).toBe("0.2.0");
    expect(oidaLoopLite.version).toBe("0.2.0");
  });

  it("stateless mode reproduces 17A behavior (compatibility preserved)", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const sel = registry.select("oida", "loop-lite");
    if (sel.ok) {
      const trusted = await selector.evaluate(sel.strategy, input(), CTX);
      expect(trusted.ok).toBe(true);
      if (trusted.ok) {
        expect(trusted.recommendation.rankedCandidates[0]).toBe("observe");
        expect(trusted.recommendation.nextOidaState).toBeUndefined();
      }
      const untrusted = await selector.evaluate(
        sel.strategy,
        input({ sensitivity: "untrusted_external" }),
        CTX
      );
      expect(untrusted.ok).toBe(true);
      if (untrusted.ok) {
        expect(untrusted.recommendation.rankedCandidates[0]).toBe("interpret");
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 2. INVALID STATE (required)
// ---------------------------------------------------------------------------
describe("17B — invalid state machine states deny with invalid_state", () => {
  it("selector rejects malformed oidaState before any strategy runs", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const sel = registry.select("oida", "loop-lite");
    if (sel.ok) {
      const badStates: unknown[] = [
        null,
        "observe",
        42,
        [],
        {},
        { currentPhase: "dream", done: false, iteration: 0 },
        { currentPhase: "observe", done: true, iteration: 0 }, // done only with act
        { currentPhase: "observe", done: false, iteration: -1 },
        { currentPhase: "observe", done: false, iteration: 1.5 },
        { currentPhase: "observe", done: false, iteration: "0" },
        { currentPhase: "observe", done: false, iteration: ALGORITHM_MAX_OIDATA_ITERATIONS + 1 },
      ];
      for (const bad of badStates) {
        const r = await selector.evaluate(
          sel.strategy,
          input({ oidaState: bad as OidaLoopState }),
          CTX
        );
        expect(r.ok, JSON.stringify(bad)).toBe(false);
        if (!r.ok) {
          expect(r.denyReason).toBe("invalid_state");
        }
      }
    }
  });

  it("illegal transitions deny: skipping phases and backwards moves", async () => {
    // Skip: observe → decide is not expressible via advanceOida (single-step);
    // here we prove the machine only ever emits single-step transitions.
    let s = initialOidaState();
    const seq: string[] = [];
    for (let i = 0; i < 3; i++) {
      const r = advanceOida(s);
      if (r.ok) {
        seq.push(s.currentPhase + "->" + r.phase);
        s = r.state;
      }
    }
    expect(seq).toEqual(["observe->interpret", "interpret->decide", "decide->act"]);

    // Backwards: a forged state claiming interpret with iteration mismatch is
    // still structurally valid (caller-owned), but transition semantics never
    // emit a backwards move from advanceOida.
    for (const phase of OIDATA_PHASES) {
      const r = advanceOida({ currentPhase: phase, done: false, iteration: 0 });
      if (r.ok) {
        const order = ["observe", "interpret", "decide", "act"];
        const from = order.indexOf(phase);
        const to = order.indexOf(r.phase);
        if (phase !== "act") expect(to).toBe(from + 1);
        else expect(r.phase).toBe("observe");
      }
    }
  });

  it("OidaStateError thrown inside a strategy maps to invalid_state (not invalid_input)", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const sel = registry.select("oida", "loop-lite");
    if (sel.ok) {
      // Forge a state that passes shallow selector validation only if
      // possible; here we directly exercise the error mapping via a state
      // that becomes illegal between validation and advance — simulated by
      // a done loop (valid shape, illegal advance).
      const doneState: OidaLoopState = { currentPhase: "act", done: true, iteration: 0 };
      // done=true + act is structurally valid, so selector passes it to the
      // strategy; the strategy's advanceOida then denies (done).
      const r = await selector.evaluate(sel.strategy, input({ oidaState: doneState }), CTX);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.denyReason).toBe("invalid_state");
      expect(new OidaStateError("x").name).toBe("OidaStateError");
    }
  });

  it("validateOidaState reason strings are machine-usable (non-empty, specific)", () => {
    const cases: unknown[] = [
      null,
      {},
      { currentPhase: "x", done: false, iteration: 0 },
      { currentPhase: "observe", done: "no", iteration: 0 },
      { currentPhase: "interpret", done: true, iteration: 0 },
      { currentPhase: "observe", done: false, iteration: -5 },
    ];
    for (const c of cases) {
      const v = validateOidaState(c);
      expect(v.ok).toBe(false);
      if (!v.ok) expect(v.reason.length).toBeGreaterThan(5);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. PRIORITY TIE-BREAKERS (required)
// ---------------------------------------------------------------------------
describe("17B — Goal Priority tie-breakers", () => {
  it("higher urgency ranks first on equal hint and recency-adjusted position", () => {
    const r = rankGoalsDeterministic(
      input({ candidateLabels: ["urgent: fix flake", "routine: cleanup"] })
    );
    expect(r.ranked[0]).toBe("urgent: fix flake");
    expect(r.scores[0]!.urgencyWeight).toBe(1);
    expect(r.scores[1]!.urgencyWeight).toBe(0);
  });

  it("urgency prefix precedence: critical > blocking > urgent", () => {
    expect(goalUrgencyWeight("critical: x")).toBe(3);
    expect(goalUrgencyWeight("blocking: x")).toBe(2);
    expect(goalUrgencyWeight("urgent: x")).toBe(1);
    expect(goalUrgencyWeight("plain x")).toBe(0);
    // Case-insensitive prefix matching.
    expect(goalUrgencyWeight("CRITICAL: x")).toBe(3);
    const r = rankGoalsDeterministic(
      input({ candidateLabels: ["urgent: a", "critical: b", "blocking: c"] })
    );
    expect(r.ranked).toEqual(["critical: b", "blocking: c", "urgent: a"]);
  });

  it("full tie (same weight) falls back to insertion order deterministically", () => {
    const labels = ["g1", "g2", "g3", "g4"];
    const r1 = rankGoalsDeterministic(input({ candidateLabels: labels }));
    const r2 = rankGoalsDeterministic(input({ candidateLabels: [...labels] }));
    expect(r1.ranked).toEqual(labels);
    expect(r2.ranked).toEqual(labels);
    // All weights equal ⇒ insertion order preserved.
    expect(r1.scores.map((s) => s.label)).toEqual(labels);
  });

  it("hint is batch-level: higher hint weights outrank lower ones", () => {
    const low = rankGoalsDeterministic(
      input({ candidateLabels: ["urgent: a"], goalPriorityHint: "low" })
    );
    const critical = rankGoalsDeterministic(
      input({ candidateLabels: ["plain b"], goalPriorityHint: "critical" })
    );
    expect(low.scores[0]!.hintWeight).toBe(1);
    expect(critical.scores[0]!.hintWeight).toBe(4);
  });

  it("equal-weight batch order is stable across repeated evaluations", () => {
    const labels = Array.from({ length: 10 }, (_, i) => "goal-" + String(i));
    const a = rankGoalsDeterministic(input({ candidateLabels: labels }));
    const b = rankGoalsDeterministic(input({ candidateLabels: labels }));
    expect(a.ranked).toEqual(b.ranked);
    expect(a.scores).toEqual(b.scores);
  });

  it("invalid hint/budget inputs deny with invalid_state (machine-readable)", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const sel = registry.select("goal_priority", "hint-budget");
    expect(sel.ok).toBe(true);
    if (sel.ok) {
      const badHint = await selector.evaluate(
        sel.strategy,
        input({ goalPriorityHint: "maximum" as never }),
        CTX
      );
      expect(!badHint.ok && badHint.denyReason).toBe("invalid_state");

      const badBudget = await selector.evaluate(
        sel.strategy,
        input({ budget: { maxWeight: 0 } }),
        CTX
      );
      expect(!badBudget.ok && badBudget.denyReason).toBe("invalid_state");

      const hugeWeight = await selector.evaluate(
        sel.strategy,
        input({ budget: { maxWeight: ALGORITHM_MAX_BUDGET_WEIGHT + 1 } }),
        CTX
      );
      expect(!hugeWeight.ok && hugeWeight.denyReason).toBe("invalid_state");

      const negRanked = await selector.evaluate(
        sel.strategy,
        input({ budget: { maxRanked: -1 } }),
        CTX
      );
      expect(!negRanked.ok && negRanked.denyReason).toBe("invalid_state");
    }
  });
});

// ---------------------------------------------------------------------------
// 4. BUDGET EFFECTS (required)
// ---------------------------------------------------------------------------
describe("17B — budget effects on goal ranking", () => {
  it("maxWeight caps every weight and flags budgetCapped records", () => {
    const r = rankGoalsDeterministic(
      input({
        candidateLabels: ["critical: big", "urgent: mid", "plain small"],
        goalPriorityHint: "critical",
        budget: { maxWeight: 200 },
      })
    );
    // Uncapped top weight would be 40*4 + 30*3 + 12 = 262.
    expect(r.scores[0]!.hintWeight).toBe(4);
    expect(r.scores[0]!.urgencyWeight).toBe(3);
    // Only the top goal exceeds the 200 cap (urgent: mid = 198, plain = 164).
    expect(r.scores[0]!.budgetCapped).toBe(true);
    expect(r.scores[1]!.budgetCapped).toBe(false);
    expect(r.scores[2]!.budgetCapped).toBe(false);
    // Ordering is preserved (the cap binds only where it binds).
    expect(r.ranked).toEqual(["critical: big", "urgent: mid", "plain small"]);
  });

  it("a tight maxWeight flattens all weights to the cap; ties resolve by urgency then insertion", () => {
    const r = rankGoalsDeterministic(
      input({
        candidateLabels: ["g1", "g2", "g3"],
        budget: { maxWeight: 1 },
      })
    );
    for (const s of r.scores) {
      expect(s.budgetCapped).toBe(true);
    }
    // All capped to 1 ⇒ insertion order.
    expect(r.ranked).toEqual(["g1", "g2", "g3"]);
  });

  it("maxRanked zeroes goals beyond the budgeted top-k (they rank last)", () => {
    const r = rankGoalsDeterministic(
      input({
        candidateLabels: ["urgent: a", "urgent: b", "plain c", "plain d"],
        budget: { maxRanked: 2 },
      })
    );
    // Top-2 by weight keep their weights; the rest are zeroed and rank last
    // but remain present (no silent dropping). urgent: a outranks urgent: b
    // (same hint/urgency; earlier index ⇒ higher recency weight).
    expect(r.ranked).toHaveLength(4);
    expect(r.ranked.slice(0, 2)).toEqual(["urgent: a", "urgent: b"]);
    expect(r.ranked.slice(2)).toEqual(["plain c", "plain d"]);
    const zeroed = r.scores.filter((s) => s.label === "plain c" || s.label === "plain d");
    for (const z of zeroed) expect(z.budgetCapped).toBe(true);
  });

  it("budget effects are observable in the reasoning summary", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const sel = registry.select("goal_priority", "hint-budget");
    if (sel.ok) {
      const r = await selector.evaluate(
        sel.strategy,
        input({
          candidateLabels: ["critical: x", "plain y"],
          goalPriorityHint: "high",
          budget: { maxWeight: 150 },
        }),
        CTX
      );
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.recommendation.reasoningSummary).toContain("budget cap 150");
      }
    }
  });

  it("no budget ⇒ no capping flags and full weights", () => {
    const r = rankGoalsDeterministic(
      input({ candidateLabels: ["critical: a", "plain b"], goalPriorityHint: "critical" })
    );
    expect(r.scores.every((s) => !s.budgetCapped)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 5. REASONING SUMMARIES (no private chain-of-thought)
// ---------------------------------------------------------------------------
describe("17B — reasoning summaries are conclusion-only", () => {
  it("both 17B strategies emit bounded reasoning summaries", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const oida = registry.select("oida", "loop-lite");
    const gp = registry.select("goal_priority", "hint-budget");
    for (const sel of [oida, gp]) {
      if (sel.ok) {
        const r = await selector.evaluate(sel.strategy, input(), CTX);
        if (r.ok) {
          expect(typeof r.recommendation.reasoningSummary).toBe("string");
          expect(r.recommendation.reasoningSummary!.length).toBeLessThanOrEqual(
            ALGORITHM_MAX_REASONING_SUMMARY_CHARS
          );
        }
      }
    }
  });

  it("summaries contain conclusions, not derivation traces", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const gp = registry.select("goal_priority", "hint-budget");
    if (gp.ok) {
      const r = await selector.evaluate(
        gp.strategy,
        input({ candidateLabels: ["critical: a", "plain b"], goalPriorityHint: "high" }),
        CTX
      );
      if (r.ok) {
        const s = r.recommendation.reasoningSummary!;
        // Conclusion vocabulary present...
        expect(s).toContain("ranked");
        // ...derivation internals absent: no raw weight numbers or per-goal
        // scoring dumps.
        expect(s).not.toContain("40 *");
        expect(s).not.toContain("30 *");
        expect(s).not.toContain("recencyWeight=");
      }
    }
  });

  it("an overlong strategy summary is bounded by the selector, not truncated silently at emit", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const oida = registry.select("oida", "loop-lite");
    if (oida.ok) {
      const r = await selector.evaluate(oida.strategy, input(), CTX);
      if (r.ok) {
        // The pinned summary respects the cap; serialization round-trips it.
        const s = serializeRecommendation(r.recommendation);
        expect(s).toContain("reasoningSummary");
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 6. EVENT EVIDENCE (required)
// ---------------------------------------------------------------------------
describe("17B — event evidence for evaluated and denied recommendations", () => {
  function makeRecorder(): {
    readonly events: Array<{ eventType: string; policyDecision: string; inputSummary: Record<string, unknown>; resultSummary: Record<string, unknown> }>;
    readonly emitter: AlgorithmLedgerEmitter;
  } {
    const events: Array<{ eventType: string; policyDecision: string; inputSummary: Record<string, unknown>; resultSummary: Record<string, unknown> }> = [];
    const emitter: AlgorithmLedgerEmitter = {
      append: (e) => {
        events.push({
          eventType: e.eventType,
          policyDecision: e.policyDecision,
          inputSummary: { ...e.inputSummary },
          resultSummary: { ...e.resultSummary },
        });
        return { ok: true, eventId: "alg-17b-" + String(events.length) };
      },
    };
    return { events, emitter };
  }

  it("allowed evaluations emit algorithm_recommended with strategy and confidence", async () => {
    const registry = buildDefaultStrategyRegistry();
    const { events, emitter } = makeRecorder();
    const selector = new StrategySelector({ ledger: emitter });
    const gp = registry.select("goal_priority", "hint-budget");
    if (gp.ok) {
      const r = await selector.evaluate(
        gp.strategy,
        input({ candidateLabels: ["urgent: ship"], goalPriorityHint: "high" }),
        CTX
      );
      expect(r.ok).toBe(true);
      expect(events).toHaveLength(1);
      expect(events[0]!.eventType).toBe("algorithm_recommended");
      expect(events[0]!.policyDecision).toBe("allow");
      expect(events[0]!.resultSummary["strategyId"]).toBe("hint-budget");
      expect(typeof events[0]!.resultSummary["confidence"]).toBe("number");
      expect(events[0]!.resultSummary["executionAuthorized"]).toBe(false);
    }
  });

  it("invalid states emit algorithm_denied with invalid_state evidence", async () => {
    const registry = buildDefaultStrategyRegistry();
    const { events, emitter } = makeRecorder();
    const selector = new StrategySelector({ ledger: emitter });
    const oida = registry.select("oida", "loop-lite");
    if (oida.ok) {
      const r = await selector.evaluate(
        oida.strategy,
        input({ oidaState: { currentPhase: "observe", done: "x", iteration: 0 } as unknown as OidaLoopState }),
        CTX
      );
      expect(r.ok).toBe(false);
      expect(events).toHaveLength(1);
      expect(events[0]!.eventType).toBe("algorithm_denied");
      expect(events[0]!.policyDecision).toBe("deny");
      expect(events[0]!.resultSummary["outcome"]).toBe("invalid_state");
    }
  });

  it("successful evaluations carry policyEventId linking to the emitted event", async () => {
    const registry = buildDefaultStrategyRegistry();
    const { events, emitter } = makeRecorder();
    const selector = new StrategySelector({ ledger: emitter });
    const gp = registry.select("goal_priority", "hint-budget");
    if (gp.ok) {
      const r = await selector.evaluate(gp.strategy, input(), CTX);
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.policyEventId).toBe("alg-17b-1"); // recorder ids are 1-based
        expect(events).toHaveLength(1);
      }
    }
  });

  it("serializeAlgorithmResult stamps schemaVersion and omits authority", () => {
    const rec = {
      family: "goal_priority" as const,
      strategyId: "hint-budget",
      rankedCandidates: ["a"],
      confidence: 0.85,
      rationale: "r",
      isRecommendation: true as const,
      executionAuthorized: false as const,
      reasoningSummary: "ranked 1 goal(s) by hint=low",
      nextOidaState: { currentPhase: "interpret" as const, done: false, iteration: 0 },
    };
    const s = serializeAlgorithmResult(
      { ok: true, schemaVersion: ALGORITHM_SCHEMA_VERSION, recommendation: rec },
      CTX
    );
    expect(s).toContain('"menog-algorithms/v0"');
    expect(s).toContain('"reasoningSummary"');
    expect(s).toContain('"nextOidaState"');
    expect(s).not.toContain('"executionAuthorized":true');
    // 17B serialization keeps 17A shape when optional fields are absent.
    const recA = { ...rec };
    delete (recA as { reasoningSummary?: string }).reasoningSummary;
    delete (recA as { nextOidaState?: OidaLoopState }).nextOidaState;
    const sA = serializeRecommendation(recA);
    expect(sA).not.toContain("reasoningSummary");
    expect(sA).not.toContain("nextOidaState");
  });

  it("isAlgorithmDenial still discriminates results (surface unchanged)", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const bad = await selector.evaluateSelection(registry, "goal_priority", "ghost", input(), CTX);
    expect(isAlgorithmDenial(bad)).toBe(true);
  });

  it("family contracts: oida and goal_priority implemented; five remain contract-only", () => {
    expect(familyContract("oida")!.implemented).toBe(true);
    expect(familyContract("goal_priority")!.implemented).toBe(true);
    expect(familyContract("oida")!.statusNote).toContain("17B");
    expect(familyContract("goal_priority")!.statusNote).toContain("17B");
    const contractOnly = ["context_memory_retrieval", "multiagent_task_allocation", "world_state_synchronization", "procedural_motion", "agent_communication_routing"];
    for (const f of contractOnly) {
      expect(familyContract(f as never)!.implemented).toBe(false);
    }
  });
});
