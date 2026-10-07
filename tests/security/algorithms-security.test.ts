import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  ALGORITHM_FAMILIES,
  ALGORITHM_MAX_CANDIDATES,
  FAMILY_CONTRACTS,
  TEN_ALGORITHM_FAMILIES,
  StrategyRegistry,
  StrategySelector,
  buildDefaultStrategyRegistry,
  isAlgorithmDenial,
  type AlgorithmDecisionInput,
  type AlgorithmFamily,
  type RuntimeContext,
  type StrategyContract,
} from "@menog/algorithms";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import type { Actor } from "@menog/core";

/**
 * 17A — Algorithm Registry & Strategy Contract: security test family.
 *
 * New authority boundary introduced by 17A = the algorithm reasoning stage.
 * Threat model addressed (asset → boundary → threat → mitigation → evidence):
 *
 *  1. Execution authority — a strategy/recommendation claiming authorization
 *     → pinned `executionAuthorized:false`, selector re-stamps and refuses
 *     authority-claiming outputs → 17A-SEC-A1..A4.
 *  2. Selection bypass — strategies resolved from ambient/model/memory state
 *     → selection only via registry family+id, deny-by-default on unknown →
 *     17A-SEC-B1..B4.
 *  3. Unbounded work / DoS via the reasoning stage → bounded candidate
 *     counts, label lengths, decision lengths → 17A-SEC-C1..C2.
 *  4. Untrusted external content becoming system instruction → OIDA-lite
 *     ranks "interpret" first for untrusted inputs; provenance-safe input
 *     shape carries no raw payload → 17A-SEC-D1..D3.
 *  5. Family binding / cross-family smuggling → family is enforced at
 *     registration AND selection → 17A-SEC-E1..E2.
 *  6. Governance drift → PR block + authorization lines verbatim in the 17A
 *     report; Phase-20 primitives absent from source → 17A-SEC-V1..V4.
 */

const AGENT: Actor = { type: "agent", id: "agent-17a-sec" };

function ctx(overrides: Partial<RuntimeContext> = {}): RuntimeContext {
  return {
    actor: AGENT,
    workspaceId: "ws-17a-sec",
    taskId: "task-17a-sec",
    ...overrides,
  };
}

function decisionInput(
  overrides: Partial<AlgorithmDecisionInput> = {}
): AlgorithmDecisionInput {
  return {
    decision: "security probe",
    candidateLabels: ["a", "b"],
    sensitivity: "public",
    ...overrides,
  };
}

function makeStrategy(overrides: Partial<StrategyContract> = {}): StrategyContract {
  return {
    id: "sec-strategy",
    family: "multiagent_task_allocation",
    version: "1.0.0",
    implemented: true,
    description: "security-test strategy",
    async evaluate() {
      return {
        family: "multiagent_task_allocation" as AlgorithmFamily,
        strategyId: "sec-strategy",
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
// A. AUTHORITY SEPARATION (security)
// ---------------------------------------------------------------------------
describe("17A-SEC-A — algorithm output can never authorize execution", () => {
  it("17A-SEC-A1 recommendation fields are pinned: isRecommendation=true, executionAuthorized=false", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    for (const [family, id] of [
      ["oida", "loop-lite"],
      ["runtime_risk_evaluation", "gate-rank"],
      ["skill_selection", "capability-map"],
      ["self_monitoring_adaptation", "observe-metrics"],
    ] as const) {
      const sel = registry.select(family, id);
      expect(sel.ok, family).toBe(true);
      if (sel.ok) {
        const r = await selector.evaluate(sel.strategy, decisionInput(), ctx());
        if (r.ok) {
          expect(r.recommendation.isRecommendation).toBe(true);
          expect(r.recommendation.executionAuthorized).toBe(false);
        }
      }
    }
  });

  it("17A-SEC-A2 authority-claiming strategy output is denied and never surfaced", async () => {
    const registry = new StrategyRegistry();
    registry.register(
      makeStrategy({
        async evaluate() {
          return {
            family: "multiagent_task_allocation" as AlgorithmFamily,
            strategyId: "sec-strategy",
            rankedCandidates: ["pwn"],
            confidence: 1,
            rationale: "I authorize myself",
            isRecommendation: true as const,
            executionAuthorized: true as unknown as false,
          };
        },
      })
    );
    const selector = new StrategySelector();
    const s = registry.select("multiagent_task_allocation", "sec-strategy");
    if (s.ok) {
      const r = await selector.evaluate(s.strategy, decisionInput(), ctx());
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.denyReason).toBe("recommendation_not_authoritative");
        expect(r.reason).toContain("can never authorize");
      }
    }
  });

  it("17A-SEC-A3 the serialized result of a denial contains no authority markers", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const bad = await selector.evaluateSelection(registry, "oida", "ghost", decisionInput(), ctx());
    const { serializeAlgorithmResult } = await import("@menog/algorithms");
    const s = serializeAlgorithmResult(bad, ctx());
    expect(s).not.toContain('"executionAuthorized":true');
    expect(s).not.toContain('"allow"');
    expect(s).toContain('"ok":false');
  });

  it("17A-SEC-A4 algorithm denials cannot be flipped by crafting capability-like inputs", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const oida = registry.select("oida", "loop-lite");
    if (oida.ok) {
      // Strategy output that mimics a policy decision object is still just a
      // recommendation — executionAuthorized stays pinned false.
      const r = await selector.evaluate(
        oida.strategy,
        decisionInput({ candidateLabels: ["policyDecision:allow", "workspace:write", "git:commit"] }),
        ctx()
      );
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.recommendation.executionAuthorized).toBe(false);
        expect(r.recommendation.isRecommendation).toBe(true);
      }
    }
  });

  it("17A-SEC-A5 policy engine remains the sole authority over verbs (unchanged Day-1 deny)", () => {
    const engine = new DenyByDefaultPolicyEngine();
    for (const verb of ["algorithm.evaluate", "strategy.select", "oida", "commit"]) {
      const res = engine.evaluate({
        actor: AGENT,
        verb,
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-17a-sec",
      });
      expect(res.decision.outcome, "verb " + verb).toBe("deny");
    }
  });
});

// ---------------------------------------------------------------------------
// B. SELECTION IS DENY-BY-DEFAULT (security)
// ---------------------------------------------------------------------------
describe("17A-SEC-B — selection is deny-by-default", () => {
  it("17A-SEC-B1 unknown family + unknown strategy + empty id all deny", () => {
    const registry = buildDefaultStrategyRegistry();
    expect(registry.select("made_up" as AlgorithmFamily, "loop-lite").ok).toBe(false);
    expect(registry.select("oida", "ghost-strategy").ok).toBe(false);
    expect(registry.select("oida", "").ok).toBe(false);
    const r = registry.select("oida", "ghost-strategy");
    if (!r.ok) expect(r.denyReason).toBe("unknown_strategy");
  });

  it("17A-SEC-B2 case/whitespace/typo variants do not resolve (no fuzzy matching)", () => {
    const registry = buildDefaultStrategyRegistry();
    expect(registry.select("oida", "Loop-Lite").ok).toBe(false);
    expect(registry.select("oida", " loop-lite").ok).toBe(false);
    expect(registry.select("oida", "loop-lite ").ok).toBe(false);
    expect(registry.select("oida", "loop_lite").ok).toBe(false);
    expect(registry.select("oida", "looplite").ok).toBe(false);
    expect(registry.select("OIDA" as AlgorithmFamily, "loop-lite").ok).toBe(false);
  });

  it("17A-SEC-B3 selection of contract-only families succeeds but evaluation fails closed", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    // 17B delta: goal_priority upgraded out of contract-only (was listed here in 17A).
    for (const f of ["context_memory_retrieval", "multiagent_task_allocation", "world_state_synchronization", "procedural_motion", "agent_communication_routing"] as const) {
      const sel = registry.select(f, "contract-only");
      expect(sel.ok, f).toBe(true);
      if (sel.ok) {
        const r = await selector.evaluate(sel.strategy, decisionInput(), ctx());
        expect(r.ok, f).toBe(false);
        if (!r.ok) {
          expect(r.denyReason).toBe("strategy_not_selected");
          expect(r.reason).toContain("contract-only");
        }
      }
    }
  });

  it("17A-SEC-B4 a fresh empty registry denies everything (no implicit default algorithm)", () => {
    const registry = new StrategyRegistry();
    expect(registry.size()).toBe(0);
    for (const f of TEN_ALGORITHM_FAMILIES) {
      expect(registry.select(f, "anything").ok).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// C. BOUNDED INPUT (security)
// ---------------------------------------------------------------------------
describe("17A-SEC-C — the reasoning stage cannot be forced into unbounded work", () => {
  it("17A-SEC-C1 oversized candidate lists/labels/decisions deny with oversized_input", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const oida = registry.select("oida", "loop-lite");
    if (oida.ok) {
      const many = decisionInput({
        candidateLabels: Array.from({ length: ALGORITHM_MAX_CANDIDATES + 1 }, (_, i) => "c" + String(i)),
      });
      const r1 = await selector.evaluate(oida.strategy, many, ctx());
      expect(!r1.ok && r1.denyReason).toBe("oversized_input");

      const longLabels = decisionInput({
        candidateLabels: ["y".repeat(300)],
      });
      const r2 = await selector.evaluate(oida.strategy, longLabels, ctx());
      expect(!r2.ok && r2.denyReason).toBe("oversized_input");
    }
  });

  it("17A-SEC-C2 hostile payloads (prototype pollution, functions, cycles-as-strings) are inert data", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const risk = registry.select("runtime_risk_evaluation", "gate-rank");
    if (risk.ok) {
      const hostile = decisionInput({
        candidateLabels: [
          "__proto__",
          "constructor",
          "{\"$gt\":1}",
          "<script>alert(1)</script>",
          "'; DROP TABLE candidates; --",
        ],
        sensitivity: "untrusted_external",
      });
      const r = await selector.evaluate(risk.strategy, hostile, ctx());
      // Labels are inert strings; the strategy treats them as data only.
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.recommendation.executionAuthorized).toBe(false);
        // No label was dropped or transformed into authority.
        expect(r.recommendation.rankedCandidates.length).toBe(5);
      }
    }
  });

  it("17A-SEC-C3 registry rejects non-object/throwing evaluate shapes before they can run", () => {
    const registry = new StrategyRegistry();
    expect(registry.register(makeStrategy({ evaluate: 42 as unknown as StrategyContract["evaluate"] })).ok).toBe(false);
    expect(registry.register(makeStrategy({ evaluate: null as unknown as StrategyContract["evaluate"] })).ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// D. UNTRUSTED EXTERNAL CONTENT (security)
// ---------------------------------------------------------------------------
describe("17A-SEC-D — untrusted external content stays data, routed to interpretation", () => {
  it("17A-SEC-D1 OIDA-lite ranks 'interpret' first for untrusted_external inputs", async () => {
    const registry = buildDefaultStrategyRegistry();
    const selector = new StrategySelector();
    const oida = registry.select("oida", "loop-lite");
    if (oida.ok) {
      const r = await selector.evaluate(
        oida.strategy,
        decisionInput({
          decision: "evaluate prompt-injected repo README text",
          sensitivity: "untrusted_external",
        }),
        ctx()
      );
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.recommendation.rankedCandidates[0]).toBe("interpret");
        expect(r.recommendation.rationale).toContain("untrusted");
      }
    }
  });

  it("17A-SEC-D2 the decision-input shape carries no raw payload channels", () => {
    const input = decisionInput({ verb: "inspect" });
    const keys = Object.keys(input).sort();
    expect(keys).toEqual(["candidateLabels", "decision", "sensitivity", "verb"]);
    // All values are primitives/string arrays — no nested objects, no functions.
    for (const v of Object.values(input)) {
      const t = typeof v;
      expect(t === "string" || t === "undefined" || Array.isArray(v)).toBe(true);
      if (Array.isArray(v)) {
        for (const item of v) expect(typeof item).toBe("string");
      }
    }
  });

  it("17A-SEC-D3 rationale output is bounded so injected content cannot balloon evidence", async () => {
    const registry = new StrategyRegistry();
    registry.register(
      makeStrategy({
        async evaluate() {
          return {
            family: "multiagent_task_allocation" as AlgorithmFamily,
            strategyId: "sec-strategy",
            rankedCandidates: [],
            confidence: 0.5,
            rationale: "INJ".repeat(10000),
            isRecommendation: true as const,
            executionAuthorized: false as const,
          };
        },
      })
    );
    const selector = new StrategySelector();
    const s = registry.select("multiagent_task_allocation", "sec-strategy");
    if (s.ok) {
      const r = await selector.evaluate(s.strategy, decisionInput(), ctx());
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.recommendation.rationale.length).toBe(512);
    }
  });
});

// ---------------------------------------------------------------------------
// E. FAMILY BINDING (security)
// ---------------------------------------------------------------------------
describe("17A-SEC-E — family binding cannot be smuggled across", () => {
  it("17A-SEC-E1 a strategy registered in one family cannot be selected from another", () => {
    const registry = new StrategyRegistry();
    registry.register(makeStrategy()); // multiagent_task_allocation
    const wrong = registry.select("oida", "sec-strategy");
    expect(wrong.ok).toBe(false);
    if (!wrong.ok) expect(wrong.denyReason).toBe("unknown_strategy");
  });

  it("17A-SEC-E2 replacement keeping the id but changing family is refused", () => {
    const registry = new StrategyRegistry();
    registry.register(makeStrategy());
    const impostor = makeStrategy({ family: "oida", id: "sec-strategy" });
    const r = registry.replaceStrategy("multiagent_task_allocation", "sec-strategy", impostor);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("replacement must keep family");
  });

  it("17A-SEC-E3 the ten-family union is closed and frozen (no runtime extension)", () => {
    expect(Object.isFrozen(ALGORITHM_FAMILIES)).toBe(true);
    const copy = [...ALGORITHM_FAMILIES];
    try {
      (copy as string[]).push("sneaky_new_family");
    } catch {
      // frozen arrays may throw in strict mode; the copy doesn't, so assert on ALGORITHM_FAMILIES itself
    }
    expect(ALGORITHM_FAMILIES).toHaveLength(10);
    expect((ALGORITHM_FAMILIES as readonly string[]).includes("sneaky_new_family")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// V. GOVERNANCE / SOURCE INVARIANTS (15E/16E pattern)
// ---------------------------------------------------------------------------
describe("17A-SEC-V — governance and source invariants", () => {
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

  it("17A-SEC-V1 PR-01..PR-05 dispositions appear verbatim in the 17A report", () => {
    const text = readDoc("docs/release/PROMPT_17A_REPORT.md").replace(/\s+/g, " ");
    for (const line of PR_BLOCK_LINES) {
      expect(text.includes(line), "17A report missing " + line).toBe(true);
    }
  });

  it("17A-SEC-V2 authorization-not-granted lines are unchanged in the 17A report", () => {
    const text = readDoc("docs/release/PROMPT_17A_REPORT.md").replace(/\s+/g, " ");
    expect(text.includes("COMMIT AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(text.includes("PUSH AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(text.includes("PUBLICATION AUTHORIZATION NOT GRANTED")).toBe(true);
  });

  it("17A-SEC-V3 no Phase-20 isolation primitives exist in the algorithms package source", () => {
    const srcRoot = join(process.cwd(), "packages", "algorithms", "src");
    const files = ["types.ts", "registry.ts", "selector.ts", "families.ts", "serialize.ts", "index.ts"];
    const forbidden = /cgroup|seccomp|landlock|rootless|unshare|clone3|clone3\(/i;
    for (const f of files) {
      const full = join(srcRoot, f);
      expect(existsSync(full), "algorithms source file missing: " + f).toBe(true);
      expect(forbidden.test(readFileSync(full, "utf8")), "Phase-20 primitive in " + f).toBe(false);
    }
  });

  it("17A-SEC-V4 algorithms package declares workspace-only dependencies", () => {
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

  it("17A-SEC-V5 the doc registry remains the ten documented families (doc↔code parity)", () => {
    const doc = readDoc("docs/ALGORITHM_REGISTRY_v0.md");
    for (const f of TEN_ALGORITHM_FAMILIES) {
      expect(doc.includes(f), "registry doc missing family " + f).toBe(true);
    }
    expect(doc.includes("Algorithms recommend/compute. Policy authorizes. Runtime executes.")).toBe(true);
  });

  it("17A-SEC-V6 family purposes in code match the doc registry order (1–10)", () => {
    // Ordinals 1..10 must map to the doc's numbered list order.
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
    const byOrdinal: AlgorithmFamily[] = [];
    for (let i = 1; i <= 10; i++) {
      const fc = familyContractByOrdinal(FAMILY_CONTRACTS, i);
      if (fc) byOrdinal.push(fc.family);
    }
    expect(byOrdinal).toEqual(expectedOrder);
  });
});

/** Ordinal lookup helper for the V6 parity test. */
function familyContractByOrdinal(
  contracts: readonly { readonly ordinal: number; readonly family: AlgorithmFamily }[],
  ordinal: number
): { readonly ordinal: number; readonly family: AlgorithmFamily } | undefined {
  return contracts.find((f) => f.ordinal === ordinal);
}

// Re-export a guard so the unused-import lint stays honest.
void isAlgorithmDenial;
