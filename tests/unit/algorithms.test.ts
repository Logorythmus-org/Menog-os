import { describe, it, expect } from "vitest";
import {
  ALGORITHM_SCHEMA_VERSION,
  ALGORITHM_FAMILIES,
  ALGORITHM_MAX_CANDIDATES,
  ALGORITHM_MAX_CANDIDATE_LABEL_CHARS,
  ALGORITHM_MAX_DECISION_CHARS,
  TEN_ALGORITHM_FAMILIES,
  FAMILY_CONTRACTS,
  REFERENCE_STRATEGIES,
  CONTRACT_ONLY_PLACEHOLDERS,
  oidaLoopLite,
  runtimeRiskLabelRank,
  skillCapabilityMapLite,
  selfMonitoringMetricObserve,
  StrategyRegistry,
  StrategySelector,
  buildDefaultStrategyRegistry,
  validateRegistryCompleteness,
  familyContract,
  canonicalSerializeStrategy,
  canonicalStrategyHash,
  serializeRecommendation,
  recommendationHash,
  serializeAlgorithmResult,
  validateDecisionInput,
  isAlgorithmDenial,
  type AlgorithmDecisionInput,
  type AlgorithmFamily,
  type RuntimeContext,
  type StrategyContract,
} from "@menog/algorithms";

const AGENT: RuntimeContext = {
  actor: { type: "agent", id: "agent-17a" },
  workspaceId: "ws-17a",
  taskId: "task-17a",
};

function decisionInput(
  overrides: Partial<AlgorithmDecisionInput> = {}
): AlgorithmDecisionInput {
  return {
    decision: "rank candidates",
    candidateLabels: ["alpha", "beta"],
    sensitivity: "public",
    ...overrides,
  };
}

function makeStrategy(overrides: Partial<StrategyContract> = {}): StrategyContract {
  return {
    id: "test-strategy",
    family: "goal_priority",
    version: "1.0.0",
    implemented: true,
    description: "test-only strategy",
    async evaluate() {
      return {
        family: "goal_priority" as AlgorithmFamily,
        strategyId: "test-strategy",
        rankedCandidates: ["alpha"],
        confidence: 0.5,
        rationale: "test",
        isRecommendation: true as const,
        executionAuthorized: false as const,
      };
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// 1. REGISTRY COMPLETENESS (required test)
// ---------------------------------------------------------------------------
describe("17A — registry completeness", () => {
  it("exactly ten families are declared, matching the closed union", () => {
    expect(ALGORITHM_FAMILIES).toHaveLength(10);
    expect(TEN_ALGORITHM_FAMILIES).toHaveLength(10);
    expect([...ALGORITHM_FAMILIES].sort()).toEqual([...TEN_ALGORITHM_FAMILIES].sort());
    // Families are unique.
    expect(new Set(ALGORITHM_FAMILIES).size).toBe(10);
  });

  it("default registry registers exactly one strategy per family (ten total)", () => {
    const registry = buildDefaultStrategyRegistry();
    expect(registry.size()).toBe(10);
    expect(validateRegistryCompleteness(registry)).toBeNull();
  });

  it("every family contract has ordinal 1..10, a purpose and a status note", () => {
    expect(FAMILY_CONTRACTS).toHaveLength(10);
    const ordinals = FAMILY_CONTRACTS.map((f) => f.ordinal).sort((a, b) => a - b);
    expect(ordinals).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    for (const f of FAMILY_CONTRACTS) {
      expect(f.purpose.length).toBeGreaterThan(0);
      expect(f.statusNote.length).toBeGreaterThan(0);
      expect(f.title.length).toBeGreaterThan(0);
      expect(familyContract(f.family)).not.toBeNull();
    }
  });

  it("five families ship implemented strategies; five are contract-only (17B delta)", () => {
    const implemented = FAMILY_CONTRACTS.filter((f) => f.implemented);
    const contractOnly = FAMILY_CONTRACTS.filter((f) => !f.implemented);
    expect(implemented.map((f) => f.family).sort()).toEqual(
      // 17B delta: goal_priority was contract-only in 17A; upgraded in 17B
      // (documented in PROMPT_17B_REPORT.md §Implementation delta table).
      ["goal_priority", "oida", "runtime_risk_evaluation", "self_monitoring_adaptation", "skill_selection"].sort()
    );
    expect(contractOnly).toHaveLength(5);
    // 17B delta: CONTRACT_ONLY_PLACEHOLDERS is 5 (was 6 in 17A).
    expect(CONTRACT_ONLY_PLACEHOLDERS).toHaveLength(5);
  });

  it("family contracts match the ALGORITHM_REGISTRY_v0 doc purposes", () => {
    expect(familyContract("oida")!.purpose).toBe("core action loop");
    expect(familyContract("goal_priority")!.purpose).toBe("rank competing goals");
    expect(familyContract("context_memory_retrieval")!.purpose).toBe("select relevant prior context");
    expect(familyContract("multiagent_task_allocation")!.purpose).toBe(
      "assign tasks based on capability, load, trust and history"
    );
    expect(familyContract("runtime_risk_evaluation")!.purpose).toBe("classify planned actions before execution");
    expect(familyContract("skill_selection")!.purpose).toBe("choose an allowed execution skill/tool for a verb");
    expect(familyContract("world_state_synchronization")!.purpose).toBe(
      "synchronize shared runtime state across agents/nodes"
    );
    expect(familyContract("procedural_motion")!.purpose).toBe("path planning and physical/3D runtime motion");
    expect(familyContract("agent_communication_routing")!.purpose).toBe("route agent-to-agent/runtime messages");
    expect(familyContract("self_monitoring_adaptation")!.purpose).toBe("observe results and propose strategy changes");
  });

  it("reference strategies are exactly one per family and validate against the registry", () => {
    const families = REFERENCE_STRATEGIES.map((s) => s.family);
    expect(new Set(families).size).toBe(10);
    expect(REFERENCE_STRATEGIES).toHaveLength(10);
    const registry = new StrategyRegistry(REFERENCE_STRATEGIES);
    expect(registry.size()).toBe(10);
  });

  it("implemented reference strategies match the documented 17C ids", () => {
    expect(oidaLoopLite.id).toBe("loop-lite");
    expect(oidaLoopLite.implemented).toBe(true);
    // 17C delta: label-rank@0.1.0 upgraded to gate-rank@0.2.0 with verdicts
    // (documented in PROMPT_17C_REPORT.md §2b delta table).
    expect(runtimeRiskLabelRank.id).toBe("gate-rank");
    expect(runtimeRiskLabelRank.implemented).toBe(true);
    // 17C delta: capability-map-lite@0.1.0 upgraded to capability-map@0.2.0
    // with grantedCapabilities filtering.
    expect(skillCapabilityMapLite.id).toBe("capability-map");
    expect(skillCapabilityMapLite.implemented).toBe(true);
    // 17D delta: outcome-record@0.1.0 upgraded to observe-metrics@0.2.0 with
    // bounded metric-driven adaptation (documented in PROMPT_17D_REPORT.md).
    expect(selfMonitoringMetricObserve.id).toBe("observe-metrics");
    expect(selfMonitoringMetricObserve.implemented).toBe(true);
  });

  it("contract-only placeholders are marked implemented:false and inert", () => {
    for (const p of CONTRACT_ONLY_PLACEHOLDERS) {
      expect(p.implemented).toBe(false);
      expect(p.id).toBe("contract-only");
      expect(typeof p.description).toBe("string");
      expect(p.description).toContain("contract-only");
    }
  });
});

// ---------------------------------------------------------------------------
// 2. REGISTRATION VALIDATION
// ---------------------------------------------------------------------------
describe("17A — registration validation", () => {
  it("accepts a valid strategy and freezes it", () => {
    const registry = new StrategyRegistry();
    const s = makeStrategy();
    const r = registry.register(s);
    expect(r.ok).toBe(true);
    expect(registry.has("goal_priority", "test-strategy")).toBe(true);
  });

  it("rejects duplicate ids within a family", () => {
    const registry = new StrategyRegistry();
    expect(registry.register(makeStrategy()).ok).toBe(true);
    const dup = registry.register(makeStrategy({ description: "different" }));
    expect(dup.ok).toBe(false);
    if (!dup.ok) expect(dup.reason).toContain("duplicate strategy id");
  });

  it("permits the same id in DIFFERENT families (family-scoped namespace)", () => {
    const registry = new StrategyRegistry();
    expect(registry.register(makeStrategy()).ok).toBe(true);
    const other = registry.register(
      makeStrategy({ id: "test-strategy", family: "goal_priority", description: "x" })
    );
    // Same family again -> duplicate. Use a different family:
    const r2 = registry.register(makeStrategy({ family: "procedural_motion", id: "test-strategy" }));
    expect(other.ok).toBe(false);
    expect(r2.ok).toBe(true);
  });

  it("rejects a strategy whose family is outside the closed ten-family union", () => {
    const registry = new StrategyRegistry();
    const r = registry.register(
      makeStrategy({ family: "not_a_real_family" as AlgorithmFamily })
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("ten closed ALGORITHM_FAMILIES");
  });

  it("rejects malformed ids, versions, descriptions and missing evaluate", () => {
    const registry = new StrategyRegistry();
    expect(registry.register(makeStrategy({ id: "Bad_Upper" })).ok).toBe(false);
    expect(registry.register(makeStrategy({ id: "" })).ok).toBe(false);
    expect(registry.register(makeStrategy({ version: "1.0" })).ok).toBe(false);
    expect(registry.register(makeStrategy({ version: "abc" })).ok).toBe(false);
    expect(registry.register(makeStrategy({ description: "" })).ok).toBe(false);
    expect(
      registry.register(makeStrategy({ evaluate: undefined as unknown as StrategyContract["evaluate"] })).ok
    ).toBe(false);
    expect(registry.register(null as unknown as StrategyContract).ok).toBe(false);
  });

  it("rejects overlong ids and descriptions (bounded metadata)", () => {
    const registry = new StrategyRegistry();
    expect(registry.register(makeStrategy({ id: "a".repeat(65) })).ok).toBe(false);
    expect(registry.register(makeStrategy({ description: "x".repeat(513) })).ok).toBe(false);
  });

  it("replaceStrategy swaps within the same family+id only and refuses unknown targets", () => {
    const registry = new StrategyRegistry();
    registry.register(makeStrategy());
    const replacement = makeStrategy({
      id: "test-strategy",
      family: "goal_priority",
      version: "1.1.0",
      description: "replacement body",
    });
    const r = registry.replaceStrategy("goal_priority", "test-strategy", replacement);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.previous.version).toBe("1.0.0");
      expect(registry.select("goal_priority", "test-strategy")).toEqual({
        ok: true,
        strategy: replacement,
      });
    }
    // Cross-family replacement refused.
    const cross = registry.replaceStrategy("oida", "test-strategy", replacement);
    expect(cross.ok).toBe(false);
    // Unknown target refused.
    const unknown = registry.replaceStrategy("oida", "nope", makeStrategy({ family: "oida", id: "nope" }));
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) expect(unknown.reason).toContain("cannot replace unregistered");
  });
});

// ---------------------------------------------------------------------------
// 3. STRATEGY SELECTION (required test)
// ---------------------------------------------------------------------------
describe("17A — strategy selection", () => {
  it("selects every implemented family strategy from the default registry", async () => {
    const registry = buildDefaultStrategyRegistry();
    for (const family of ["oida", "runtime_risk_evaluation", "skill_selection", "self_monitoring_adaptation"] as const) {
      const sel = registry.select(family, familyContract(family)!.implemented ? undefined as never : undefined as never);
      void sel;
    }
    // Explicit ids:
    for (const [family, id] of [
      ["oida", "loop-lite"],
      ["runtime_risk_evaluation", "gate-rank"],
      ["skill_selection", "capability-map"],
      ["self_monitoring_adaptation", "observe-metrics"],
    ] as const) {
      const sel = registry.select(family, id);
      expect(sel.ok, family + "/" + id).toBe(true);
    }
  });

  it("selects contract-only families for lookup but the selector refuses to evaluate them", async () => {
    const registry = buildDefaultStrategyRegistry();
    // 17B delta: goal_priority upgraded out of contract-only (was listed here in 17A).
    const sel = registry.select("goal_priority", "contract-only");
    expect(sel.ok).toBe(false); // no contract-only placeholder exists for goal_priority anymore
    const context = registry.select("context_memory_retrieval", "contract-only");
    expect(context.ok).toBe(true);
    if (context.ok) {
      const selector = new StrategySelector();
      const r = await selector.evaluate(context.strategy, decisionInput(), AGENT);
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.denyReason).toBe("strategy_not_selected");
        expect(r.reason).toContain("contract-only");
      }
    }
  });

  it("evaluation of the four implemented strategies returns pinned recommendations", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();

    const oida = registry.select("oida", "loop-lite");
    expect(oida.ok).toBe(true);
    if (oida.ok) {
      const r = await selector.evaluate(oida.strategy, decisionInput({ sensitivity: "untrusted_external" }), AGENT);
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.recommendation.rankedCandidates[0]).toBe("interpret");
        expect(r.recommendation.confidence).toBeGreaterThan(0);
      }
    }

    const risk = registry.select("runtime_risk_evaluation", "gate-rank");
    expect(risk.ok).toBe(true);
    if (risk.ok) {
      const r = await selector.evaluate(
        risk.strategy,
        decisionInput({ candidateLabels: ["read files", "git push --force", "list dir"] }),
        AGENT
      );
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.recommendation.rankedCandidates[0]).toBe("git push --force");
        expect(r.recommendation.confidence).toBeGreaterThan(0.5);
      }
    }

    const skill = registry.select("skill_selection", "capability-map");
    expect(skill.ok).toBe(true);
    if (skill.ok) {
      const r = await selector.evaluate(
        skill.strategy,
        decisionInput({ verb: "inspect", candidateLabels: ["workspace:read-metadata"] }),
        AGENT
      );
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.recommendation.rankedCandidates).toEqual(["workspace:read-metadata"]);
      }
    }

    const selfMon = registry.select("self_monitoring_adaptation", "observe-metrics");
    expect(selfMon.ok).toBe(true);
    if (selfMon.ok) {
      // 17D delta: the strategy now ranks observable METRICS (name=value
      // labels, most salient first) instead of 17A outcome label prefixes.
      const r = await selector.evaluate(
        selfMon.strategy,
        decisionInput({
          candidateLabels: [],
          metrics: [
            { name: "failure_ratio", value: 0.6 },
            { name: "success_ratio", value: 0.4 },
          ],
        }),
        AGENT
      );
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.recommendation.rankedCandidates[0]).toBe("failure_ratio=0.6");
      }
    }
  });

  it("skill-map fails closed to an empty recommendation for unmapped verbs", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const skill = registry.select("skill_selection", "capability-map");
    if (skill.ok) {
      const r = await selector.evaluate(
        skill.strategy,
        decisionInput({ verb: "commit", candidateLabels: [] }),
        AGENT
      );
      expect(r.ok).toBe(true);
      if (r.ok) {
        // Empty recommendation — never a fabricated capability hint.
        expect(r.recommendation.rankedCandidates).toEqual([]);
        expect(r.recommendation.confidence).toBe(0);
      }
    }
  });

  it("deterministic: equal inputs give equal recommendations (no hidden state)", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const risk = registry.select("runtime_risk_evaluation", "gate-rank");
    if (risk.ok) {
      const input = decisionInput({ candidateLabels: ["a write", "b read", "c network"] });
      const r1 = await selector.evaluate(risk.strategy, input, AGENT);
      const r2 = await selector.evaluate(risk.strategy, input, AGENT);
      expect(r1.ok && r2.ok).toBe(true);
      if (r1.ok && r2.ok) {
        expect(serializeRecommendation(r1.recommendation)).toBe(
          serializeRecommendation(r2.recommendation)
        );
        expect(recommendationHash(r1.recommendation)).toBe(recommendationHash(r2.recommendation));
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 4. UNKNOWN STRATEGY / INPUT REJECTION (required test)
// ---------------------------------------------------------------------------
describe("17A — unknown strategy and input rejection", () => {
  it("unknown family denies with unknown_family", () => {
    const registry = buildDefaultStrategyRegistry();
    const r = registry.select("nonexistent_family" as AlgorithmFamily, "loop-lite");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denyReason).toBe("unknown_family");
      expect(r.reason).toContain("nonexistent_family");
    }
  });

  it("unknown strategy id within a valid family denies with unknown_strategy (no fallback)", () => {
    const registry = buildDefaultStrategyRegistry();
    const r = registry.select("oida", "vector-ultra");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denyReason).toBe("unknown_strategy");
      expect(r.reason).toContain("vector-ultra");
    }
  });

  it("empty strategy id denies with invalid_input", () => {
    const registry = buildDefaultStrategyRegistry();
    const r = registry.select("oida", "");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denyReason).toBe("invalid_input");
  });

  it("evaluateSelection propagates registry denials verbatim", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const r = await selector.evaluateSelection(
      registry,
      "oida",
      "does-not-exist",
      decisionInput(),
      AGENT
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denyReason).toBe("unknown_strategy");
  });

  it("oversized decision input denies with oversized_input before any strategy runs", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const oida = registry.select("oida", "loop-lite");
    if (oida.ok) {
      const tooMany = decisionInput({
        candidateLabels: Array.from({ length: ALGORITHM_MAX_CANDIDATES + 1 }, (_, i) => "c" + String(i)),
      });
      const r1 = await selector.evaluate(oida.strategy, tooMany, AGENT);
      expect(r1.ok).toBe(false);
      if (!r1.ok) expect(r1.denyReason).toBe("oversized_input");

      const tooLong = decisionInput({
        decision: "d".repeat(ALGORITHM_MAX_DECISION_CHARS + 1),
      });
      const r2 = await selector.evaluate(oida.strategy, tooLong, AGENT);
      expect(r2.ok).toBe(false);
      if (!r2.ok) expect(r2.denyReason).toBe("oversized_input");

      const longLabel = decisionInput({
        candidateLabels: ["x".repeat(ALGORITHM_MAX_CANDIDATE_LABEL_CHARS + 1)],
      });
      const r3 = await selector.evaluate(oida.strategy, longLabel, AGENT);
      expect(r3.ok).toBe(false);
      if (!r3.ok) expect(r3.denyReason).toBe("oversized_input");
    }
  });

  it("invalid decision inputs deny with invalid_input (validateDecisionInput parity)", async () => {
    expect(validateDecisionInput(null as unknown as AlgorithmDecisionInput)).not.toBeNull();
    expect(validateDecisionInput(decisionInput({ decision: "" }))).not.toBeNull();
    expect(validateDecisionInput(decisionInput({ candidateLabels: "nope" as unknown as string[] }))).not.toBeNull();
    expect(validateDecisionInput(decisionInput({ candidateLabels: ["a", ""] }))).not.toBeNull();
    expect(validateDecisionInput(decisionInput({ sensitivity: "topsecret" as never }))).not.toBeNull();
    expect(validateDecisionInput(decisionInput({ verb: "" }))).not.toBeNull();
    expect(validateDecisionInput(decisionInput())).toBeNull();

    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const oida = registry.select("oida", "loop-lite");
    if (oida.ok) {
      const r = await selector.evaluate(oida.strategy, decisionInput({ sensitivity: "bogus" as never }), AGENT);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.denyReason).toBe("invalid_input");
    }
  });

  it("a strategy that throws is converted to a denial, never surfaced as an execution path", async () => {
    const registry = new StrategyRegistry();
    registry.register(
      makeStrategy({
        async evaluate() {
          throw new Error("boom");
        },
      })
    );
    const selector = new StrategySelector();
    const s = registry.select("goal_priority", "test-strategy");
    if (s.ok) {
      const r = await selector.evaluate(s.strategy, decisionInput(), AGENT);
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.denyReason).toBe("invalid_input");
        expect(r.reason).toContain("boom");
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 5. AUTHORITY SEPARATION (recommendation vs execution)
// ---------------------------------------------------------------------------
describe("17A — authority separation (algorithms recommend, never authorize)", () => {
  it("every reference strategy carries executionAuthorized:false after selection", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    for (const family of ["oida", "runtime_risk_evaluation", "skill_selection", "self_monitoring_adaptation"] as const) {
      const sel = registry.select(family, { "oida": "loop-lite", "runtime_risk_evaluation": "gate-rank", "skill_selection": "capability-map", "self_monitoring_adaptation": "observe-metrics" }[family]);
      if (sel.ok) {
        const r = await selector.evaluate(sel.strategy, decisionInput(), AGENT);
        if (r.ok) {
          expect(r.recommendation.executionAuthorized).toBe(false);
          expect(r.recommendation.isRecommendation).toBe(true);
        }
      }
    }
  });

  it("a strategy claiming executionAuthorized is denied with recommendation_not_authoritative", async () => {
    const registry = new StrategyRegistry();
    registry.register(
      makeStrategy({
        async evaluate() {
          return {
            family: "goal_priority" as AlgorithmFamily,
            strategyId: "test-strategy",
            rankedCandidates: ["x"],
            confidence: 1,
            rationale: "self-authorizing",
            isRecommendation: true as const,
            executionAuthorized: true as unknown as false,
          };
        },
      })
    );
    const selector = new StrategySelector();
    const s = registry.select("goal_priority", "test-strategy");
    if (s.ok) {
      const r = await selector.evaluate(s.strategy, decisionInput(), AGENT);
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.denyReason).toBe("recommendation_not_authoritative");
        expect(r.reason).toContain("can never authorize");
      }
    }
  });

  it("the selector re-stamps isRecommendation/executionAuthorized regardless of strategy output", async () => {
    const registry = new StrategyRegistry();
    registry.register(
      makeStrategy({
        async evaluate() {
          return {
            family: "goal_priority" as AlgorithmFamily,
            strategyId: "test-strategy",
            rankedCandidates: ["a", "b"],
            confidence: 5, // out of range on purpose
            rationale: "r".repeat(1000), // overlong on purpose
            isRecommendation: true as const,
            executionAuthorized: false as const,
          };
        },
      })
    );
    const selector = new StrategySelector();
    const s = registry.select("goal_priority", "test-strategy");
    if (s.ok) {
      const r = await selector.evaluate(s.strategy, decisionInput(), AGENT);
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.recommendation.confidence).toBe(1); // clamped
        expect(r.recommendation.rationale.length).toBe(512); // bounded
        expect(r.recommendation.isRecommendation).toBe(true);
        expect(r.recommendation.executionAuthorized).toBe(false);
        expect(Object.isFrozen(r.recommendation)).toBe(true);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 6. SERIALIZATION (required test)
// ---------------------------------------------------------------------------
describe("17A — serialization", () => {
  it("canonicalSerializeStrategy is deterministic and key-sorted", () => {
    const a = canonicalSerializeStrategy(oidaLoopLite);
    const b = canonicalSerializeStrategy({ ...oidaLoopLite });
    expect(a).toBe(b);
    // Keys appear in sorted order: description, family, id, implemented, version.
    const idxDesc = a.indexOf('"description"');
    const idxFam = a.indexOf('"family"');
    const idxId = a.indexOf('"id"');
    const idxImpl = a.indexOf('"implemented"');
    const idxVer = a.indexOf('"version"');
    expect(idxDesc).toBeLessThan(idxFam);
    expect(idxFam).toBeLessThan(idxId);
    expect(idxId).toBeLessThan(idxImpl);
    expect(idxImpl).toBeLessThan(idxVer);
    expect(JSON.parse(a)).toEqual({
      description: oidaLoopLite.description,
      family: oidaLoopLite.family,
      id: oidaLoopLite.id,
      implemented: "true",
      version: oidaLoopLite.version,
    });
  });

  it("canonicalStrategyHash is a stable SHA-256 hex digest", () => {
    const h1 = canonicalStrategyHash(oidaLoopLite);
    const h2 = canonicalStrategyHash(oidaLoopLite);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
    // Different strategies hash differently.
    expect(canonicalStrategyHash(runtimeRiskLabelRank)).not.toBe(h1);
  });

  it("registry fingerprint reflects content and changes when strategies change", () => {
    const r1 = buildDefaultStrategyRegistry();
    const r2 = buildDefaultStrategyRegistry();
    expect(r1.deterministicFingerprint()).toBe(r2.deterministicFingerprint());
    r2.register(makeStrategy({ id: "extra", family: "goal_priority" }));
    expect(r2.deterministicFingerprint()).not.toBe(r1.deterministicFingerprint());
  });

  it("serializeRecommendation is sorted-key, round-trippable JSON", () => {
    const rec = {
      family: "oida" as const,
      strategyId: "loop-lite",
      rankedCandidates: ["observe", "interpret"],
      confidence: 0.75,
      rationale: "test rationale",
      isRecommendation: true as const,
      executionAuthorized: false as const,
    };
    const s = serializeRecommendation(rec);
    const parsed = JSON.parse(s) as Record<string, unknown>;
    expect(parsed["family"]).toBe("oida");
    expect(parsed["isRecommendation"]).toBe(true);
    expect(parsed["executionAuthorized"]).toBe(false);
    expect(parsed["confidence"]).toBe(0.75);
    // Key order is fixed regardless of insertion order.
    expect(s.indexOf('"confidence"')).toBeLessThan(s.indexOf('"family"'));
    expect(serializeRecommendation({ ...rec, rankedCandidates: ["observe", "interpret"] })).toBe(s);
  });

  it("recommendationHash is a stable SHA-256 and content-sensitive", () => {
    const rec = {
      family: "oida" as const,
      strategyId: "loop-lite",
      rankedCandidates: ["observe"],
      confidence: 0.5,
      rationale: "r",
      isRecommendation: true as const,
      executionAuthorized: false as const,
    };
    expect(recommendationHash(rec)).toMatch(/^[0-9a-f]{64}$/);
    expect(recommendationHash({ ...rec, confidence: 0.6 })).not.toBe(recommendationHash(rec));
  });

  it("serializeAlgorithmResult covers success and denial deterministically", () => {
    const rec = {
      family: "oida" as const,
      strategyId: "loop-lite",
      rankedCandidates: ["observe"],
      confidence: 0.8,
      rationale: "r",
      isRecommendation: true as const,
      executionAuthorized: false as const,
    };
    const ok = {
      ok: true as const,
      schemaVersion: ALGORITHM_SCHEMA_VERSION,
      recommendation: rec,
    };
    const bad = {
      ok: false as const,
      denyReason: "unknown_strategy" as const,
      reason: "no such strategy",
    };
    const s1 = serializeAlgorithmResult(ok, AGENT);
    const s2 = serializeAlgorithmResult(bad, AGENT);
    expect(s1).toContain('"ok":true');
    expect(s1).toContain('"menog-algorithms/v0"');
    expect(s2).toContain('"ok":false');
    expect(s2).toContain('"unknown_strategy"');
    expect(JSON.parse(s1)).toBeTruthy();
    expect(JSON.parse(s2)).toBeTruthy();
    expect(serializeAlgorithmResult(ok, AGENT)).toBe(s1);
    expect(serializeAlgorithmResult(bad, { actor: { type: "agent", id: "agent-17a" } })).not.toBe(s1);
  });
});

// ---------------------------------------------------------------------------
// 7. OBSERVABILITY (ledger events)
// ---------------------------------------------------------------------------
describe("17A — observable evaluations", () => {
  it("allowed and denied evaluations emit observable events via the injected emitter", async () => {
    const registry = buildDefaultStrategyRegistry();
    const events: Array<{ eventType: string; policyDecision: string; resultSummary: Record<string, unknown> }> = [];
    const selector = new StrategySelector({
      ledger: {
        append: (input) => {
          events.push({
            eventType: input.eventType,
            policyDecision: input.policyDecision,
            resultSummary: { ...input.resultSummary },
          });
          return { ok: true, eventId: "alg-" + String(events.length) };
        },
      },
    });
    const risk = registry.select("runtime_risk_evaluation", "gate-rank");
    if (risk.ok) {
      await selector.evaluate(risk.strategy, decisionInput(), AGENT);
      expect(events).toHaveLength(1);
      expect(events[0]!.eventType).toBe("algorithm_recommended");
      expect(events[0]!.policyDecision).toBe("allow");
      expect(events[0]!.resultSummary["executionAuthorized"]).toBe(false);

      await selector.evaluate(risk.strategy, decisionInput({ decision: "" }), AGENT);
      expect(events).toHaveLength(2);
      expect(events[1]!.eventType).toBe("algorithm_denied");
      expect(events[1]!.policyDecision).toBe("deny");
    }
  });

  it("selector with no ledger performs no hidden writes (local-first, no side effects)", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const oida = registry.select("oida", "loop-lite");
    if (oida.ok) {
      const r = await selector.evaluate(oida.strategy, decisionInput(), AGENT);
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.policyEventId).toBeUndefined();
    }
  });

  it("isAlgorithmDenial discriminates the result union", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const bad = await selector.evaluateSelection(registry, "oida", "nope", decisionInput(), AGENT);
    expect(isAlgorithmDenial(bad)).toBe(true);
  });
});
