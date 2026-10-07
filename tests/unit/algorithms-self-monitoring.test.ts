import { describe, it, expect } from "vitest";
import {
  ALGORITHM_MAX_METRICS,
  ALGORITHM_MAX_PARAMETER_HISTORY,
  AdaptiveParameterStore,
  buildDefaultStrategyRegistry,
  buildSelfMonitoringStrategy,
  deriveAdaptationProposal,
  executionStatsFeedbackPort,
  familyContract,
  globalDefaultStore,
  METRIC_DENY_RATIO,
  METRIC_FAILURE_RATIO,
  METRIC_SUCCESS_RATIO,
  StrategySelector,
  selfMonitoringMetricObserve,
  validateMetricsInput,
  type AdaptationProposal,
  type AlgorithmDecisionInput,
  type MetricFeedbackPort,
  type ParameterChangeRecord,
  type RuntimeContext,
} from "@menog/algorithms";

const CTX: RuntimeContext = {
  actor: { type: "agent", id: "agent-17d" },
  workspaceId: "ws-17d",
  taskId: "task-17d",
};

function input(
  overrides: Partial<AlgorithmDecisionInput> = {}
): AlgorithmDecisionInput {
  return {
    decision: "17D probe",
    candidateLabels: [],
    sensitivity: "public",
    ...overrides,
  };
}

function makeStore(): AdaptiveParameterStore {
  return new AdaptiveParameterStore();
}

// ---------------------------------------------------------------------------
// 1. METRIC FEEDBACK (required)
// ---------------------------------------------------------------------------
describe("17D — metric feedback", () => {
  it("metrics are observable inputs: the strategy ranks them by salience deterministically", async () => {
    const selector = new StrategySelector();
    const r = await selector.evaluate(
      selfMonitoringMetricObserve,
      input({
        metrics: [
          { name: "deny_ratio", value: 0.2 },
          { name: "failure_ratio", value: 0.8 },
          { name: "success_ratio", value: 0.4 },
        ],
      }),
      CTX
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      // Most salient (highest |value|) first.
      expect(r.recommendation.rankedCandidates[0]).toBe("failure_ratio=0.8");
      expect(r.recommendation.rankedCandidates).toHaveLength(3);
      expect(r.recommendation.reasoningSummary).toContain("observed 3");
    }
  });

  it("executionStatsFeedbackPort derives ratio metrics from 16B-style stats", async () => {
    const port = executionStatsFeedbackPort(() => ({
      ok: true,
      total: 10,
      byOutcome: { success: 7, failure: 2, denied: 1 },
    }));
    const c = await port.collect();
    expect(c.ok).toBe(true);
    if (c.ok) {
      expect(c.metrics).toContainEqual({ name: METRIC_SUCCESS_RATIO, value: 0.7 });
      expect(c.metrics).toContainEqual({ name: METRIC_FAILURE_RATIO, value: 0.2 });
      expect(c.metrics).toContainEqual({ name: METRIC_DENY_RATIO, value: 0.1 });
    }
  });

  it("a failing feedback port fails closed to zero metrics (honest starvation, not fabrication)", async () => {
    const port: MetricFeedbackPort = {
      async collect() {
        return { ok: false, denyReason: "invalid_input", reason: "stats unavailable" };
      },
    };
    const strategy = buildSelfMonitoringStrategy(makeStore(), port);
    const selector = new StrategySelector();
    const r = await selector.evaluate(strategy, input(), CTX);
    expect(r.ok).toBe(true); // observation succeeds with zero data
    if (r.ok) {
      expect(r.recommendation.rankedCandidates).toEqual([]);
      expect(r.recommendation.reasoningSummary).toContain("no metrics");
    }
  });

  it("a zero-total stats source yields zero metrics (no divide-by-zero fabrication)", async () => {
    const port = executionStatsFeedbackPort(() => ({ ok: true, total: 0 }));
    const c = await port.collect();
    expect(c.ok).toBe(true);
    if (c.ok) expect(c.metrics).toHaveLength(0);
  });

  it("malformed metrics deny with invalid_state before strategies run", async () => {
    expect(validateMetricsInput(input({ metrics: [{ name: "x", value: NaN }] }))).not.toBeNull();
    expect(validateMetricsInput(input({ metrics: [{ name: "x", value: Infinity }] }))).not.toBeNull();
    expect(validateMetricsInput(input({ metrics: [{ name: "", value: 1 }] }))).not.toBeNull();
    expect(
      validateMetricsInput(input({ metrics: [{ name: "x".repeat(65), value: 1 }] }))
    ).not.toBeNull();
    expect(
      validateMetricsInput(
        input({ metrics: Array.from({ length: ALGORITHM_MAX_METRICS + 1 }, (_, i) => ({ name: "m" + String(i), value: 1 })) })
      )
    ).not.toBeNull();
    expect(validateMetricsInput(input({ metrics: [{ name: "ok", value: 0.5 }] }))).toBeNull();

    const selector = new StrategySelector();
    const r = await selector.evaluate(
      selfMonitoringMetricObserve,
      input({ metrics: [{ name: "x", value: NaN }] }),
      CTX
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denyReason).toBe("invalid_state");
  });
});

// ---------------------------------------------------------------------------
// 2. BOUNDED ADAPTATION (required)
// ---------------------------------------------------------------------------
describe("17D — bounded adaptation within policy bounds", () => {
  it("default parameters are registered with policy bounds", () => {
    const s = globalDefaultStore.get("retrieval.limit");
    expect(s).not.toBeNull();
    expect(s!.bounds).toEqual({ min: 1, max: 100 });
    expect(s!.value).toBe(10);
  });

  it("apply() accepts in-bounds proposals and updates revision monotonically", () => {
    const store = makeStore();
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    const r = store.apply({
      parameter: "retrieval.limit",
      currentValue: 10,
      proposedValue: 9,
      bounds: { min: 1, max: 100 },
      reason: "test",
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.state.value).toBe(9);
      expect(r.state.revision).toBe(1);
      expect(r.record.kind).toBe("adapt");
    }
  });

  it("apply() DENIES out-of-bounds proposals with adaptation_out_of_bounds", () => {
    const store = makeStore();
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    const tooBig = store.apply({
      parameter: "retrieval.limit",
      currentValue: 10,
      proposedValue: 101,
      bounds: { min: 1, max: 100 },
      reason: "test",
    });
    expect(!tooBig.ok && tooBig.reason.startsWith("adaptation_out_of_bounds")).toBe(true);
    const tooSmall = store.apply({
      parameter: "retrieval.limit",
      currentValue: 10,
      proposedValue: 0,
      bounds: { min: 1, max: 100 },
      reason: "test",
    });
    expect(!tooSmall.ok && tooSmall.reason.startsWith("adaptation_out_of_bounds")).toBe(true);
    // The value is untouched after denial.
    expect(store.get("retrieval.limit")!.value).toBe(10);
  });

  it("a lying proposal cannot move the goalposts: REGISTERED bounds govern, not proposal bounds", () => {
    const store = makeStore();
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    const r = store.apply({
      parameter: "retrieval.limit",
      currentValue: 10,
      proposedValue: 500,
      bounds: { min: 0, max: 1000 }, // proposal claims looser bounds
      reason: "self-loosening attempt",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("adaptation_out_of_bounds");
  });

  it("unknown parameters deny with parameter_unknown", () => {
    const store = makeStore();
    const r = store.apply({
      parameter: "ghost.param",
      currentValue: 0,
      proposedValue: 1,
      bounds: { min: 0, max: 1 },
      reason: "r",
    });
    expect(!r.ok && r.reason.startsWith("parameter_unknown")).toBe(true);
  });

  it("deriveAdaptationProposal proposes only registered, in-bounds adjustments", () => {
    const store = makeStore();
    for (const p of [
      { name: "retrieval.limit", initialValue: 10, bounds: { min: 1, max: 100 }, sensitivity: "performance" as const },
      { name: "risk.confidenceFloor", initialValue: 0.5, bounds: { min: 0, max: 1 }, sensitivity: "threshold" as const },
    ]) {
      store.register(p.name, p.initialValue, p.bounds, p.sensitivity);
    }
    // High deny ratio ⇒ lower the confidence floor, in bounds.
    const p1 = deriveAdaptationProposal([{ name: METRIC_DENY_RATIO, value: 0.8 }], store);
    expect(p1).not.toBeNull();
    if (p1) {
      expect(p1.parameter).toBe("risk.confidenceFloor");
      expect(p1.proposedValue).toBeGreaterThanOrEqual(p1.bounds.min);
      expect(p1.proposedValue).toBeLessThanOrEqual(p1.bounds.max);
      expect(p1.proposedValue).toBeLessThan(p1.currentValue);
    }
    // High success ⇒ grow retrieval limit, in bounds.
    const p2 = deriveAdaptationProposal([{ name: METRIC_SUCCESS_RATIO, value: 0.95 }], store);
    expect(p2).not.toBeNull();
    if (p2) {
      expect(p2.parameter).toBe("retrieval.limit");
      expect(p2.proposedValue).toBeLessThanOrEqual(p2.bounds.max);
      expect(p2.proposedValue).toBeGreaterThan(p2.currentValue);
    }
    // Healthy metrics ⇒ no adaptation.
    const p3 = deriveAdaptationProposal(
      [
        { name: METRIC_DENY_RATIO, value: 0.1 },
        { name: METRIC_SUCCESS_RATIO, value: 0.8 },
        { name: METRIC_FAILURE_RATIO, value: 0.1 },
      ],
      store
    );
    expect(p3).toBeNull();
  });

  it("adaptation at the boundary never crosses it (floor/ceiling clamped)", () => {
    const store = makeStore();
    store.register("risk.confidenceFloor", 0.03, { min: 0, max: 1 });
    // Repeated declines walk to the floor and stop (each proposal in-bounds).
    let applied = 0;
    for (let i = 0; i < 5; i++) {
      const proposal = deriveAdaptationProposal([{ name: METRIC_DENY_RATIO, value: 0.9 }], store);
      if (proposal === null) break;
      const r = store.apply(proposal);
      if (!r.ok) break;
      applied++;
    }
    const s = store.get("risk.confidenceFloor")!;
    expect(s.value).toBeGreaterThanOrEqual(s.bounds.min);
    expect(applied).toBeGreaterThan(0);
    expect(s.value).toBe(s.bounds.min); // clamped at the floor
  });

  it("the strategy attaches at most ONE proposal, never self-applies it", async () => {
    const store = makeStore();
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    store.register("risk.confidenceFloor", 0.5, { min: 0, max: 1 });
    const strategy = buildSelfMonitoringStrategy(store);
    const selector = new StrategySelector();
    const r = await selector.evaluate(
      strategy,
      input({ metrics: [{ name: METRIC_DENY_RATIO, value: 0.9 }] }),
      CTX
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      const proposals = [r.recommendation.adaptationProposal].filter(Boolean);
      expect(proposals.length).toBeLessThanOrEqual(1);
      // The proposal was NOT applied — store state unchanged.
      expect(store.get("risk.confidenceFloor")!.revision).toBe(0);
      expect(store.get("retrieval.limit")!.revision).toBe(0);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. ROLLBACK OF PARAMETER CHANGES (required)
// ---------------------------------------------------------------------------
describe("17D — rollback of parameter changes", () => {
  it("rollback restores the previous value and records a rollback record", () => {
    const store = makeStore();
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    const a = store.apply({
      parameter: "retrieval.limit",
      currentValue: 10,
      proposedValue: 8,
      bounds: { min: 1, max: 100 },
      reason: "shrink",
    });
    expect(a.ok).toBe(true);
    const rb = store.rollback("retrieval.limit");
    expect(rb.ok).toBe(true);
    if (rb.ok) {
      expect(rb.state.value).toBe(10); // restored
      expect(rb.record.kind).toBe("rollback");
      expect(rb.record.toValue).toBe(10);
      expect(rb.record.revision).toBe(2);
    }
  });

  it("multiple rollbacks walk the history backwards step by step", () => {
    const store = makeStore();
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    store.apply({ parameter: "retrieval.limit", currentValue: 10, proposedValue: 9, bounds: { min: 1, max: 100 }, reason: "a" });
    store.apply({ parameter: "retrieval.limit", currentValue: 9, proposedValue: 7, bounds: { min: 1, max: 100 }, reason: "b" });
    expect(store.get("retrieval.limit")!.value).toBe(7);
    store.rollback("retrieval.limit");
    expect(store.get("retrieval.limit")!.value).toBe(9);
    store.rollback("retrieval.limit");
    expect(store.get("retrieval.limit")!.value).toBe(10);
    // Rolling back past the initial registration is refused.
    const r = store.rollback("retrieval.limit");
    expect(!r.ok && r.reason.startsWith("rollback_target_missing")).toBe(true);
  });

  it("rollback denies for unknown parameters and history-less parameters", () => {
    const store = makeStore();
    expect(!store.rollback("ghost").ok).toBe(true);
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    const r = store.rollback("retrieval.limit");
    expect(!r.ok && r.reason.startsWith("rollback_target_missing")).toBe(true);
  });

  it("change history is bounded (ALGORITHM_MAX_PARAMETER_HISTORY) with oldest dropped", () => {
    const store = makeStore();
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    // Oscillate to generate many records.
    let flip = false;
    for (let i = 0; i < ALGORITHM_MAX_PARAMETER_HISTORY + 10; i++) {
      store.apply({
        parameter: "retrieval.limit",
        currentValue: store.get("retrieval.limit")!.value,
        proposedValue: flip ? 10 : 9,
        bounds: { min: 1, max: 100 },
        reason: "osc " + String(i),
      });
      flip = !flip;
    }
    const h = store.historyOf("retrieval.limit");
    expect(h.length).toBe(ALGORITHM_MAX_PARAMETER_HISTORY);
    // Value remains within bounds after the storm.
    const s = store.get("retrieval.limit")!;
    expect(s.value).toBeGreaterThanOrEqual(s.bounds.min);
    expect(s.value).toBeLessThanOrEqual(s.bounds.max);
  });
});

// ---------------------------------------------------------------------------
// 4. NO SOURCE MUTATION (required)
// ---------------------------------------------------------------------------
describe("17D — no source mutation surface", () => {
  it("the parameter store exposes no file/code/config mutation methods", () => {
    const store = makeStore();
    const proto = Object.getPrototypeOf(store) as Record<string, unknown>;
    const methods = Object.getOwnPropertyNames(proto);
    const forbidden = [
      "writeFile", "appendFile", "unlink", "eval", "require", "import",
      "spawn", "exec", "commit", "push", "readFile", "rm", "rmdir",
    ];
    for (const f of forbidden) {
      expect(methods, "store must not expose '" + f + "'").not.toContain(f);
    }
    // Public surface is strictly the bounded parameter API.
    for (const required of ["register", "apply", "rollback", "get", "list", "historyOf"]) {
      expect(methods).toContain(required);
    }
  });

  it("proposals are inert data: they carry no executable fields", async () => {
    const selector = new StrategySelector();
    const r = await selector.evaluate(
      selfMonitoringMetricObserve,
      input({ metrics: [{ name: METRIC_DENY_RATIO, value: 0.9 }] }),
      CTX
    );
    expect(r.ok).toBe(true);
    if (r.ok && r.recommendation.adaptationProposal) {
      const keys = Object.keys(r.recommendation.adaptationProposal).sort();
      expect(keys).toEqual(["bounds", "currentValue", "parameter", "proposedValue", "reason"]);
      for (const v of Object.values(r.recommendation.adaptationProposal)) {
        expect(typeof v === "function").toBe(false);
      }
    }
  });

  it("adaptation cannot alter strategy REGISTRY state (families/ids immutable)", async () => {
    const registry = buildDefaultStrategyRegistry();
    const before = registry.deterministicFingerprint();
    const strategy = buildSelfMonitoringStrategy(makeStore());
    const selector = new StrategySelector();
    await selector.evaluate(
      strategy,
      input({ metrics: [{ name: METRIC_DENY_RATIO, value: 0.95 }] }),
      CTX
    );
    // Register a parameter, adapt it, roll it back — the registry is untouched.
    const store = makeStore();
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    store.apply({ parameter: "retrieval.limit", currentValue: 10, proposedValue: 99, bounds: { min: 1, max: 100 }, reason: "r" });
    expect(registry.deterministicFingerprint()).toBe(before);
  });
});

// ---------------------------------------------------------------------------
// 5. AUDIT EVENTS (required)
// ---------------------------------------------------------------------------
describe("17D — audit events for every adaptation", () => {
  it("the audit sink receives every applied change with full before/after evidence", () => {
    const records: ParameterChangeRecord[] = [];
    const store = new AdaptiveParameterStore({
      audit: (r) => records.push(r),
    });
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    const a = store.apply({
      parameter: "retrieval.limit",
      currentValue: 10,
      proposedValue: 9,
      bounds: { min: 1, max: 100 },
      reason: "audit probe",
    });
    expect(a.ok).toBe(true);
    store.rollback("retrieval.limit");
    expect(records).toHaveLength(2);
    expect(records[0]).toMatchObject({
      parameter: "retrieval.limit",
      fromValue: 10,
      toValue: 9,
      kind: "adapt",
      revision: 1,
    });
    expect(records[1]).toMatchObject({
      parameter: "retrieval.limit",
      fromValue: 9,
      toValue: 10,
      kind: "rollback",
      revision: 2,
    });
  });

  it("denied adaptations emit NO audit records (nothing happened)", () => {
    const records: ParameterChangeRecord[] = [];
    const store = new AdaptiveParameterStore({ audit: (r) => records.push(r) });
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    store.apply({
      parameter: "retrieval.limit",
      currentValue: 10,
      proposedValue: 9999,
      bounds: { min: 1, max: 100 },
      reason: "should fail",
    });
    expect(records).toHaveLength(0);
  });

  it("the strategy's proposal is observable via the selector's ledger emitter", async () => {
    const events: Array<{ eventType: string; resultSummary: Record<string, unknown> }> = [];
    const selector = new StrategySelector({
      ledger: {
        append: (e) => {
          events.push({ eventType: e.eventType, resultSummary: { ...e.resultSummary } });
          return { ok: true, eventId: "alg-17d-" + String(events.length) };
        },
      },
    });
    await selector.evaluate(
      selfMonitoringMetricObserve,
      input({ metrics: [{ name: METRIC_DENY_RATIO, value: 0.9 }] }),
      CTX
    );
    expect(events).toHaveLength(1);
    expect(events[0]!.eventType).toBe("algorithm_recommended");
    expect(events[0]!.resultSummary["executionAuthorized"]).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 6. DETERMINISM + CONTRACT SURFACE
// ---------------------------------------------------------------------------
describe("17D — determinism and contract surface", () => {
  it("equal metrics give byte-identical recommendations", async () => {
    const selector = new StrategySelector();
    const m = [{ name: METRIC_DENY_RATIO, value: 0.9 }, { name: METRIC_FAILURE_RATIO, value: 0.3 }];
    const r1 = await selector.evaluate(selfMonitoringMetricObserve, input({ metrics: m }), CTX);
    const r2 = await selector.evaluate(selfMonitoringMetricObserve, input({ metrics: m }), CTX);
    expect(r1.ok && r2.ok).toBe(true);
    if (r1.ok && r2.ok) {
      expect(r1.recommendation.rankedCandidates).toEqual(r2.recommendation.rankedCandidates);
      expect(r1.recommendation.reasoningSummary).toBe(r2.recommendation.reasoningSummary);
      expect(r1.recommendation.adaptationProposal?.proposedValue).toBe(
        r2.recommendation.adaptationProposal?.proposedValue
      );
    }
  });

  it("no metrics ⇒ honest empty observation (17A fallback semantics preserved)", async () => {
    const selector = new StrategySelector();
    const r = await selector.evaluate(selfMonitoringMetricObserve, input(), CTX);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.recommendation.rankedCandidates).toEqual([]);
      expect(r.recommendation.adaptationProposal).toBeUndefined();
    }
  });

  it("family 10 records the 17D status; strategy id/version pinned", () => {
    expect(familyContract("self_monitoring_adaptation")!.statusNote).toContain("17D");
    expect(selfMonitoringMetricObserve.id).toBe("observe-metrics");
    expect(selfMonitoringMetricObserve.version).toBe("0.2.0");
  });

  it("registration validation rejects malformed names/values/bounds", () => {
    const store = makeStore();
    expect(!store.register("", 1, { min: 0, max: 2 }).ok).toBe(true);
    expect(!store.register("bad name!", 1, { min: 0, max: 2 }).ok).toBe(true);
    expect(!store.register("x", NaN, { min: 0, max: 2 }).ok).toBe(true);
    expect(!store.register("x", 1, { min: 2, max: 0 }).ok).toBe(true);
    expect(!store.register("x", 1, { min: NaN, max: 2 }).ok).toBe(true);
    expect(!store.register("x", 1, { min: 0, max: 2 }, "bogus" as never).ok).toBe(true);
    // Initial values are clamped into bounds, not rejected for being outside.
    const r = store.register("y", 50, { min: 0, max: 10 });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.state.value).toBe(10);
  });

  it("proposal type is importable and constructible as plain data", () => {
    const p: AdaptationProposal = {
      parameter: "retrieval.limit",
      currentValue: 10,
      proposedValue: 9,
      bounds: { min: 1, max: 100 },
      reason: "type check",
    };
    expect(p.proposedValue).toBe(9);
  });
});
