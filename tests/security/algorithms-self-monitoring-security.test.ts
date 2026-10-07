import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  ALGORITHM_MAX_METRICS,
  ALGORITHM_MAX_PARAMETER_HISTORY,
  ALGORITHM_MAX_TUNABLE_PARAMETERS,
  AdaptiveParameterStore,
  buildDefaultStrategyRegistry,
  buildSelfMonitoringStrategy,
  deriveAdaptationProposal,
  globalDefaultStore,
  isAlgorithmDenial,
  METRIC_DENY_RATIO,
  StrategyRegistry,
  StrategySelector,
  validateMetricsInput,
  type AlgorithmDecisionInput,
  type ParameterChangeRecord,
  type RuntimeContext,
  type StrategyContract,
} from "@menog/algorithms";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import type { Actor } from "@menog/core";

/**
 * 17D — Self-Monitoring & Adaptation: security test family.
 *
 * New authority surfaces introduced by 17D and their threat model
 * (asset → boundary → threat → mitigation → test evidence):
 *
 *  1. Parameter adaptation path (NEW WRITE-ADJACENT AUTHORITY)
 *     boundary: AdaptiveParameterStore.apply
 *     threat:   out-of-bounds self-tuning; lying proposal bounds; runtime
 *               loosening its own registered bounds; source/config mutation
 *     mitigation: REGISTERED bounds govern (proposal bounds ignored); store
 *               has no file/code/config mutation methods (frozen surface
 *               audit); bounds changes require explicit re-registration
 *               (a caller/policy step); proposals never self-apply
 *     evidence:  17D-SEC-B1..B4, S1..S3
 *
 *  2. Metric feedback input
 *     boundary: caller metrics / MetricFeedbackPort
 *     threat:   NaN/Infinity poisoning; oversized metric floods; hostile
 *               metric names steering adaptation; fabricated metrics
 *               driving unauthorized adaptation
 *     mitigation: validateMetricsInput (finite, bounded, name-capped) with
 *               invalid_state denial pre-evaluation; derivation proposes
 *               ONLY registered-parameter, in-bounds adjustments; applying
 *               remains a separate explicit audited step
 *     evidence:  17D-SEC-M1..M3
 *
 *  3. Audit trail
 *     boundary: ParameterChangeRecord sink
 *     threat:   unaudited parameter changes; audit flooding
 *     mitigation: every applied/rolled-back change is recorded (denied
 *               changes record nothing); history bounded; audit sink fed
 *               synchronously inside apply/rollback
 *     evidence:  17D-SEC-A1..A3
 *
 *  4. Governance — PR block / authorization lines / Phase-20 scan.
 *     evidence:  17D-SEC-V1..V4
 */

const AGENT: Actor = { type: "agent", id: "agent-17d-sec" };

function ctx(overrides: Partial<RuntimeContext> = {}): RuntimeContext {
  return {
    actor: AGENT,
    workspaceId: "ws-17d-sec",
    taskId: "task-17d-sec",
    ...overrides,
  };
}

function input(
  overrides: Partial<AlgorithmDecisionInput> = {}
): AlgorithmDecisionInput {
  return {
    decision: "17D security probe",
    candidateLabels: [],
    sensitivity: "public",
    ...overrides,
  };
}

function makeStrategy(overrides: Partial<StrategyContract> = {}): StrategyContract {
  return {
    id: "sec-17d",
    family: "multiagent_task_allocation",
    version: "1.0.0",
    implemented: true,
    description: "17D security-test strategy",
    async evaluate() {
      return {
        family: "multiagent_task_allocation" as const,
        strategyId: "sec-17d",
        rankedCandidates: [],
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
// B. BOUNDS ENFORCEMENT (security)
// ---------------------------------------------------------------------------
describe("17D-SEC-B — adaptation is bounded by registered policy bounds", () => {
  it("17D-SEC-B1 out-of-bounds proposals are denied and change nothing", () => {
    const store = new AdaptiveParameterStore();
    store.register("p", 5, { min: 0, max: 10 });
    for (const bad of [11, -1, 100, 1_000_001, -1_000_001]) {
      const r = store.apply({
        parameter: "p",
        currentValue: 5,
        proposedValue: bad,
        bounds: { min: 0, max: 10 },
        reason: "probe",
      });
      expect(r.ok, String(bad)).toBe(false);
      if (!r.ok) expect(r.reason.startsWith("adaptation_out_of_bounds")).toBe(true);
    }
    expect(store.get("p")!.value).toBe(5);
  });

  it("17D-SEC-B2 lying proposal bounds cannot move the goalposts (registered bounds govern)", () => {
    const store = new AdaptiveParameterStore();
    store.register("p", 5, { min: 0, max: 10 });
    for (const lie of [{ min: -1000, max: 1000 }, { min: 5, max: 5 }, { min: 0, max: 1e9 }]) {
      const r = store.apply({
        parameter: "p",
        currentValue: 5,
        proposedValue: 500,
        bounds: lie,
        reason: "lying bounds",
      });
      expect(r.ok, JSON.stringify(lie)).toBe(false);
    }
  });

  it("17D-SEC-B3 the store cannot be re-bounded through apply — bounds changes need explicit re-registration", () => {
    const store = new AdaptiveParameterStore();
    store.register("p", 5, { min: 0, max: 10 });
    // Every adaptation attempt with looser claimed bounds fails.
    const r1 = store.apply({
      parameter: "p", currentValue: 5, proposedValue: 50, bounds: { min: 0, max: 100 }, reason: "r",
    });
    expect(r1.ok).toBe(false);
    // Re-registration IS the policy step (audited caller action), and even it
    // clamps the value into the NEW bounds rather than escaping them.
    const re = store.register("p", 5, { min: 0, max: 20 });
    expect(re.ok).toBe(true);
    const r2 = store.apply({
      parameter: "p", currentValue: 5, proposedValue: 15, bounds: { min: 0, max: 20 }, reason: "r",
    });
    expect(r2.ok).toBe(true);
    if (r2.ok) expect(r2.state.value).toBe(15); // still inside registered bounds
  });

  it("17D-SEC-B4 non-finite and pathological values cannot pass the store", () => {
    const store = new AdaptiveParameterStore();
    store.register("p", 5, { min: 0, max: 10 });
    for (const bad of [NaN, Infinity, -Infinity]) {
      const r = store.apply({
        parameter: "p", currentValue: 5, proposedValue: bad, bounds: { min: 0, max: 10 }, reason: "r",
      });
      expect(r.ok, String(bad)).toBe(false);
    }
    expect(store.get("p")!.value).toBe(5);
  });

  it("17D-SEC-B5 derivation only proposes registered parameters, always in bounds", () => {
    const store = new AdaptiveParameterStore();
    store.register("risk.confidenceFloor", 0.5, { min: 0, max: 1 });
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    const hostileMetrics = [
      { name: METRIC_DENY_RATIO, value: 1 },
      { name: "unregistered.param", value: 999 },
      { name: "__proto__", value: 1 },
      { name: "constructor", value: 1 },
    ];
    const p = deriveAdaptationProposal(hostileMetrics, store);
    if (p !== null) {
      expect(store.get(p.parameter)).not.toBeNull(); // registered only
      expect(p.proposedValue).toBeGreaterThanOrEqual(p.bounds.min);
      expect(p.proposedValue).toBeLessThanOrEqual(p.bounds.max);
    }
  });
});

// ---------------------------------------------------------------------------
// S. NO SOURCE MUTATION (security)
// ---------------------------------------------------------------------------
describe("17D-SEC-S — no self-modifying source code", () => {
  it("17D-SEC-S1 the parameter store has NO file/code/config/exec surface", () => {
    const store = new AdaptiveParameterStore();
    let proto = Object.getPrototypeOf(store) as Record<string, unknown>;
    const methods = new Set<string>();
    while (proto && proto !== Object.prototype) {
      for (const m of Object.getOwnPropertyNames(proto)) methods.add(m);
      proto = Object.getPrototypeOf(proto) as Record<string, unknown>;
    }
    for (const banned of [
      "writeFile", "appendFile", "unlink", "mkdir", "rmdir", "rm",
      "eval", "exec", "spawn", "fork", "require", "import", "compile",
      "readFile", "commit", "push", "register", // register is on the class but listed here only as a dup check below
    ]) {
      if (banned === "register") continue; // parameter registration is expected
      expect(methods.has(banned), "store must not expose '" + banned + "'").toBe(false);
    }
  });

  it("17D-SEC-S2 adaptation never changes strategy registry content", () => {
    const registry = buildDefaultStrategyRegistry();
    const before = registry.deterministicFingerprint();
    const store = new AdaptiveParameterStore();
    store.register("retrieval.limit", 10, { min: 1, max: 100 });
    store.apply({ parameter: "retrieval.limit", currentValue: 10, proposedValue: 99, bounds: { min: 1, max: 100 }, reason: "r" });
    store.apply({ parameter: "retrieval.limit", currentValue: 99, proposedValue: 1, bounds: { min: 1, max: 100 }, reason: "r" });
    store.rollback("retrieval.limit");
    store.rollback("retrieval.limit");
    expect(registry.deterministicFingerprint()).toBe(before);
  });

  it("17D-SEC-S3 proposals are pure data and never self-apply (selector leaves state untouched)", async () => {
    const store = new AdaptiveParameterStore();
    store.register("risk.confidenceFloor", 0.5, { min: 0, max: 1 });
    const strategy = buildSelfMonitoringStrategy(store);
    const selector = new StrategySelector();
    const r = await selector.evaluate(
      strategy,
      input({ metrics: [{ name: METRIC_DENY_RATIO, value: 0.99 }] }),
      ctx()
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.recommendation.adaptationProposal).toBeDefined();
      expect(store.get("risk.confidenceFloor")!.revision).toBe(0); // nothing applied
    }
  });

  it("17D-SEC-S4 a hostile strategy emitting executable-looking proposal fields has them dropped", async () => {
    const registry = new StrategyRegistry();
    registry.register(
      makeStrategy({
        async evaluate() {
          return {
            family: "multiagent_task_allocation" as const,
            strategyId: "sec-17d",
            rankedCandidates: [],
            confidence: 0.5,
            rationale: "r",
            isRecommendation: true as const,
            executionAuthorized: false as const,
            adaptationProposal: {
              parameter: "p",
              currentValue: 0,
              proposedValue: NaN, // pathological
              bounds: { min: -1e9, max: 1e9 },
              reason: "r",
              // hostile extras:
              exec: "rm -rf /",
              apply: "self",
            } as never,
          };
        },
      })
    );
    const selector = new StrategySelector();
    const s = registry.select("multiagent_task_allocation", "sec-17d");
    if (s.ok) {
      const r = await selector.evaluate(s.strategy, input(), ctx());
      expect(r.ok).toBe(true);
      if (r.ok) {
        // Non-finite proposal dropped by the selector's pinning.
        expect(r.recommendation.adaptationProposal).toBeUndefined();
        const s2 = JSON.stringify(r.recommendation);
        expect(s2).not.toContain("rm -rf");
        expect(s2).not.toContain('"apply"');
      }
    }
  });
});

// ---------------------------------------------------------------------------
// M. METRIC INPUT (security)
// ---------------------------------------------------------------------------
describe("17D-SEC-M — metric feedback cannot poison or flood adaptation", () => {
  it("17D-SEC-M1 NaN/Infinity/flooded metrics deny with invalid_state pre-evaluation", async () => {
    expect(validateMetricsInput(input({ metrics: [{ name: "x", value: NaN }] }))).not.toBeNull();
    expect(validateMetricsInput(input({ metrics: [{ name: "x", value: Infinity }] }))).not.toBeNull();
    expect(
      validateMetricsInput(
        input({ metrics: Array.from({ length: ALGORITHM_MAX_METRICS + 1 }, (_, i) => ({ name: "m" + String(i), value: 0.5 })) })
      )
    ).not.toBeNull();

    const selector = new StrategySelector();
    const r = await selector.evaluate(
      buildSelfMonitoringStrategy(new AdaptiveParameterStore()),
      input({ metrics: [{ name: "x", value: Infinity }] }),
      ctx()
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denyReason).toBe("invalid_state");
  });

  it("17D-SEC-M2 prototype-pollution metric names are inert data", async () => {
    const store = new AdaptiveParameterStore();
    store.register("risk.confidenceFloor", 0.5, { min: 0, max: 1 });
    const strategy = buildSelfMonitoringStrategy(store);
    const selector = new StrategySelector();
    const polluted = JSON.parse('{"__proto__":{"polluted":true}}');
    const r = await selector.evaluate(
      strategy,
      input({
        metrics: [
          polluted as never,
          { name: METRIC_DENY_RATIO, value: 0.9 },
        ],
      }),
      ctx()
    );
    // Malformed entry denies closed (strict validation) rather than being
    // silently coerced — pollution can never ride through.
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denyReason).toBe("invalid_state");
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("17D-SEC-M3 fabricated metrics cannot create an out-of-bounds or unregistered adaptation", () => {
    const store = new AdaptiveParameterStore();
    store.register("retrieval.limit", 100, { min: 1, max: 100 }); // at ceiling
    // Extreme success pressure at the ceiling: proposal stays in bounds or absent.
    const p = deriveAdaptationProposal(
      [{ name: "success_ratio", value: 1 }],
      store
    );
    if (p !== null) {
      expect(p.proposedValue).toBeLessThanOrEqual(100);
      const r = store.apply(p);
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.state.value).toBeLessThanOrEqual(100);
    }
    void globalDefaultStore;
  });
});

// ---------------------------------------------------------------------------
// A. AUDIT TRAIL (security)
// ---------------------------------------------------------------------------
describe("17D-SEC-A — every adaptation is audited", () => {
  it("17D-SEC-A1 apply and rollback both emit audit records with before/after values", () => {
    const records: ParameterChangeRecord[] = [];
    const store = new AdaptiveParameterStore({ audit: (r) => records.push(r) });
    store.register("p", 5, { min: 0, max: 10 });
    store.apply({ parameter: "p", currentValue: 5, proposedValue: 7, bounds: { min: 0, max: 10 }, reason: "up" });
    store.rollback("p");
    expect(records).toHaveLength(2);
    expect(records.map((r) => r.kind)).toEqual(["adapt", "rollback"]);
    expect(records[0]!.fromValue).toBe(5);
    expect(records[0]!.toValue).toBe(7);
    expect(records[1]!.toValue).toBe(5);
  });

  it("17D-SEC-A2 denied adaptations emit no audit records", () => {
    const records: ParameterChangeRecord[] = [];
    const store = new AdaptiveParameterStore({ audit: (r) => records.push(r) });
    store.register("p", 5, { min: 0, max: 10 });
    store.apply({ parameter: "p", currentValue: 5, proposedValue: 99, bounds: { min: 0, max: 10 }, reason: "deny me" });
    store.apply({ parameter: "ghost", currentValue: 0, proposedValue: 1, bounds: { min: 0, max: 1 }, reason: "unknown" });
    store.rollback("p"); // nothing to undo
    expect(records).toHaveLength(0);
  });

  it("17D-SEC-A3 audit history is bounded against flooding", () => {
    const store = new AdaptiveParameterStore();
    store.register("p", 5, { min: 0, max: 10 });
    let flip = false;
    for (let i = 0; i < ALGORITHM_MAX_PARAMETER_HISTORY + 50; i++) {
      store.apply({
        parameter: "p",
        currentValue: store.get("p")!.value,
        proposedValue: flip ? 6 : 5,
        bounds: { min: 0, max: 10 },
        reason: "flood " + String(i),
      });
      flip = !flip;
    }
    expect(store.historyOf("p").length).toBe(ALGORITHM_MAX_PARAMETER_HISTORY);
  });
});

// ---------------------------------------------------------------------------
// A2. AUTHORITY REGRESSION
// ---------------------------------------------------------------------------
describe("17D-SEC-A2 — authority separation holds on 17D outputs", () => {
  it("17D-SEC-A2-1 a 17D strategy claiming authority is still denied", async () => {
    const registry = new StrategyRegistry();
    registry.register(
      makeStrategy({
        async evaluate() {
          return {
            family: "multiagent_task_allocation" as const,
            strategyId: "sec-17d",
            rankedCandidates: [],
            confidence: 1,
            rationale: "metrics say I may self-modify",
            isRecommendation: true as const,
            executionAuthorized: true as unknown as false,
            adaptationProposal: {
              parameter: "p", currentValue: 0, proposedValue: 1,
              bounds: { min: 0, max: 1 }, reason: "self-apply",
            },
          };
        },
      })
    );
    const selector = new StrategySelector();
    const s = registry.select("multiagent_task_allocation", "sec-17d");
    if (s.ok) {
      const r = await selector.evaluate(s.strategy, input(), ctx());
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.denyReason).toBe("recommendation_not_authoritative");
    }
  });

  it("17D-SEC-A2-2 policy engine remains the sole authority (Day-1 deny unchanged)", () => {
    const engine = new DenyByDefaultPolicyEngine();
    for (const verb of ["monitor.observe", "params.adapt", "commit"]) {
      const res = engine.evaluate({
        actor: AGENT,
        verb,
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-17d-sec",
      });
      expect(res.decision.outcome, "verb " + verb).toBe("deny");
    }
  });

  it("17D-SEC-A2-3 denial serialization leaks no adaptation or authority internals", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const bad = await selector.evaluateSelection(registry, "oida", "ghost", input(), ctx());
    expect(isAlgorithmDenial(bad)).toBe(true);
    const s = JSON.stringify(bad);
    expect(s).not.toContain('"adaptationProposal"');
    expect(s).not.toContain('"executionAuthorized"');
  });
});

// ---------------------------------------------------------------------------
// V. GOVERNANCE / SOURCE INVARIANTS
// ---------------------------------------------------------------------------
describe("17D-SEC-V — governance and source invariants", () => {
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

  it("17D-SEC-V1 PR-01..PR-05 dispositions appear verbatim in the 17D report", () => {
    const text = readDoc("docs/release/PROMPT_17D_REPORT.md").replace(/\s+/g, " ");
    for (const line of PR_BLOCK_LINES) {
      expect(text.includes(line), "17D report missing " + line).toBe(true);
    }
  });

  it("17D-SEC-V2 authorization-not-granted lines are unchanged in the 17D report", () => {
    const text = readDoc("docs/release/PROMPT_17D_REPORT.md").replace(/\s+/g, " ");
    expect(text.includes("COMMIT AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(text.includes("PUSH AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(text.includes("PUBLICATION AUTHORIZATION NOT GRANTED")).toBe(true);
  });

  it("17D-SEC-V3 no Phase-20 isolation primitives exist in the algorithms package source", () => {
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
      "integration.ts",
      "riskSkill.ts",
      "contextMemory.ts",
      "selfMonitoring.ts",
      "index.ts",
    ];
    const forbidden = /cgroup|seccomp|landlock|rootless|unshare|clone3/i;
    for (const f of files) {
      const full = join(srcRoot, f);
      expect(existsSync(full), "algorithms source file missing: " + f).toBe(true);
      expect(forbidden.test(readFileSync(full, "utf8")), "Phase-20 primitive in " + f).toBe(false);
    }
  });

  it("17D-SEC-V4 algorithms package declares workspace-only dependencies (unchanged)", () => {
    const pkg = JSON.parse(readDoc("packages/algorithms/package.json")) as {
      dependencies?: Record<string, string>;
    };
    for (const d of Object.keys(pkg.dependencies ?? {})) {
      expect(d.startsWith("@menog/"), "non-workspace dependency: " + d).toBe(true);
    }
  });

  it("17D-SEC-V5 the parameter store cap is bounded (ALGORITHM_MAX_TUNABLE_PARAMETERS)", () => {
    const store = new AdaptiveParameterStore();
    let registered = 0;
    for (let i = 0; i < ALGORITHM_MAX_TUNABLE_PARAMETERS + 5; i++) {
      const r = store.register("param." + String(i), 1, { min: 0, max: 2 });
      if (r.ok) registered++;
    }
    expect(registered).toBe(ALGORITHM_MAX_TUNABLE_PARAMETERS);
  });
});
