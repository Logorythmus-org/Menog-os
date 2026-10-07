import type {
  AlgorithmDecisionInput,
  AlgorithmFamily,
  AlgorithmRecommendation,
  RuntimeContext,
  StrategyContract,
} from "./types.js";
import { ALGORITHM_FAMILIES } from "./types.js";
import { StrategyRegistry } from "./registry.js";
import { oidaLoopLite } from "./oidaStrategy.js";
import { goalPriorityHintBudget } from "./goalPriority.js";
import {
  runtimeRiskGateRank,
  skillCapabilityMapLite as skillCapabilityMapLiteImpl,
} from "./riskSkill.js";
import { selfMonitoringMetricObserve } from "./selfMonitoring.js";

/**
 * Phase 17A — Ten Behavioral Algorithm Families (formalized contracts).
 *
 * Formalizes docs/ALGORITHM_REGISTRY_v0: the ten historical agentic
 * algorithm families become machine-readable, replaceable strategy contracts.
 * This is the HOW layer of the Menog taxonomy:
 *
 *   Verb Taxonomy = WHAT      (packages/verbs)
 *   Algorithm     = HOW       (THIS package)
 *   Agent         = WHO       (packages/core Actor — NOT created here)
 *   Skill / Tool  = WITH WHAT (later phase)
 *
 * Ten families are formalized. TEN CONTRACTS — NOT TEN AGENTS. No agent is
 * instantiated by this package; `Agent` instantiation is out of 17A scope.
 *
 * Implementation status mirror (17A → 17B → 17C):
 *  - oida (upgraded 17B, stateful loop-lite@0.2.0),
 *    goal_priority (implemented 17B, hint-budget),
 *    runtime_risk_evaluation (upgraded 17C, gate-rank@0.2.0 with risk
 *    verdicts), skill_selection (upgraded 17C, capability-map@0.2.0 with
 *    capability filtering),
 *    self_monitoring_adaptation (17A outcome-record):
 *    deterministic reference strategies shipped (implemented: true).
 *  - context_memory_retrieval (17C): implemented as a PORT-BOUND strategy
 *    (`buildContextMemoryStrategy`); it is NOT part of the default registry
 *    because it requires a caller-supplied retrieval port — the family stays
 *    `implemented: false` in FAMILY_CONTRACTS (no strategy in the default
 *    registry) and selection denies `unknown_strategy` fail-closed unless a
 *    caller explicitly registers a port-bound instance.
 *  - The remaining four families: contract-only (implemented: false).
 */

/** The ten canonical family ids in registry order (1–10 of the doc registry). */
export const TEN_ALGORITHM_FAMILIES: readonly AlgorithmFamily[] = ALGORITHM_FAMILIES;

export interface FamilyContract {
  readonly family: AlgorithmFamily;
  /** Ordinal position in the canonical registry (1–10). */
  readonly ordinal: number;
  readonly title: string;
  readonly purpose: string;
  /** Whether a concrete strategy ships in this phase. */
  readonly implemented: boolean;
  /** Implementation note for implemented families; contract-only note otherwise. */
  readonly statusNote: string;
}

export const FAMILY_CONTRACTS: readonly FamilyContract[] = Object.freeze([
  {
    family: "oida",
    ordinal: 1,
    title: "Observe–Interpret–Decide–Act",
    purpose: "core action loop",
    implemented: true,
    statusNote: "17B: explicit caller-owned state machine + stateful loop-lite@0.2.0 (no execution)",
  },
  {
    family: "goal_priority",
    ordinal: 2,
    title: "Goal Priority",
    purpose: "rank competing goals",
    implemented: true,
    statusNote: "17B: deterministic hint+urgency+recency ranking with budget caps (recommend-only)",
  },
  {
    family: "context_memory_retrieval",
    ordinal: 3,
    title: "Context-Aware Memory Retrieval",
    purpose: "select relevant prior context",
    implemented: false,
    statusNote: "17C: port-bound strategy available (buildContextMemoryStrategy over a policy-gated retrieval port); NOT in the default registry — family stays contract-only there",
  },
  {
    family: "multiagent_task_allocation",
    ordinal: 4,
    title: "Multiagent Task Allocation",
    purpose: "assign tasks based on capability, load, trust and history",
    implemented: false,
    statusNote: "contract only",
  },
  {
    family: "runtime_risk_evaluation",
    ordinal: 5,
    title: "Runtime Risk Evaluation",
    purpose: "classify planned actions before execution",
    implemented: true,
    statusNote: "17C: risk verdicts (allow/restrict/deny) + monotone restriction via applyRiskVerdict (policy is the floor)",
  },
  {
    family: "skill_selection",
    ordinal: 6,
    title: "Skill Selection",
    purpose: "choose an allowed execution skill/tool for a verb",
    implemented: true,
    statusNote: "17C: capability-aware — recommendations intersected with caller-asserted grantedCapabilities (NO TOOL WITHOUT CAPABILITY)",
  },
  {
    family: "world_state_synchronization",
    ordinal: 7,
    title: "World-State Synchronization",
    purpose: "synchronize shared runtime state across agents/nodes",
    implemented: false,
    statusNote: "contract only; federation is a non-goal for this phase",
  },
  {
    family: "procedural_motion",
    ordinal: 8,
    title: "Procedural Motion",
    purpose: "path planning and physical/3D runtime motion",
    implemented: false,
    statusNote: "contract only; 3D runtime is ROADMAP ONLY",
  },
  {
    family: "agent_communication_routing",
    ordinal: 9,
    title: "Agent Communication Routing",
    purpose: "route agent-to-agent/runtime messages",
    implemented: false,
    statusNote: "contract only",
  },
  {
    family: "self_monitoring_adaptation",
    ordinal: 10,
    title: "Self-Monitoring & Adaptation",
    purpose: "observe results and propose strategy changes",
    implemented: true,
    statusNote: "17D: bounded metric-driven monitoring + audited in-bounds parameter adaptation (proposals never self-apply; NO source mutation)",
  },
]);

function recommendation(
  family: AlgorithmFamily,
  strategyId: string,
  rankedCandidates: readonly string[],
  confidence: number,
  rationale: string
): AlgorithmRecommendation {
  return {
    family,
    strategyId,
    rankedCandidates,
    confidence,
    rationale,
    isRecommendation: true,
    executionAuthorized: false,
  };
}

// ---------------------------------------------------------------------------
// Family 1 — OIDA (observe–interpret–decide–act loop strategy)
// ---------------------------------------------------------------------------

// 17B: the OIDA strategy implementation moved to ./oidaStrategy.ts (stateful
// loop-lite@0.2.0 + pure state machine in ./oida.ts). Re-exported here so the
// families module remains the one-stop reference-strategy surface.
export { oidaLoopLite, OidaStateError } from "./oidaStrategy.js";
export {
  initialOidaState,
  validateOidaState,
  advanceOida,
  completeOidaLoop,
} from "./oida.js";

// ---------------------------------------------------------------------------
// Family 5 — Runtime Risk Evaluation (upgraded 17C)
// ---------------------------------------------------------------------------

// 17C: the risk strategy moved to ./riskSkill.ts (gate-rank@0.2.0 with
// machine-readable verdicts + monotone restriction via applyRiskVerdict).
// The 17A label-rank@0.1.0 export is retired; gate-rank supersedes it.
export {
  runtimeRiskGateRank as runtimeRiskLabelRank,
} from "./riskSkill.js";
export { applyRiskVerdict } from "./integration.js";
export type { SkillFilterResult } from "./integration.js";

// ---------------------------------------------------------------------------
// Family 2 — Goal Priority (implemented 17B)
// ---------------------------------------------------------------------------

// 17B: the Goal Priority implementation lives in ./goalPriority.ts. The
// contract-only placeholder for goal_priority is no longer generated; the
// concrete hint-budget strategy takes its place in REFERENCE_STRATEGIES.
export { goalPriorityHintBudget } from "./goalPriority.js";
export {
  GOAL_PRIORITY_HINT_WEIGHTS,
  GOAL_URGENCY_PREFIX_WEIGHTS,
  rankGoalsDeterministic,
  validateGoalPriorityInput,
  goalUrgencyWeight,
} from "./goalPriority.js";

// ---------------------------------------------------------------------------
// Family 6 — Skill Selection (upgraded 17C)
// ---------------------------------------------------------------------------

// 17C: the skill strategy moved to ./riskSkill.ts (capability-map@0.2.0 with
// grantedCapabilities filtering). The 17A capability-map-lite@0.1.0 export is
// retired; capability-map supersedes it.
export {
  skillCapabilityMapLiteImpl as skillCapabilityMapLite,
} from "./riskSkill.js";
export { filterSkillsByCapabilities } from "./integration.js";

// ---------------------------------------------------------------------------
// Family 10 — Self-Monitoring & Adaptation
// ---------------------------------------------------------------------------

/**
 * `self-monitoring.outcome-record` — deterministic outcome observation.
 * Ranks candidate labels by observed outcome markers (`ok:` / `fail:` /
 * `deny:` prefixes), failures first — the only "adaptation" it performs is
 * surfacing what already happened. It NEVER modifies strategies or policies:
 * any change proposal is DATA for human review.
 */
export const selfMonitoringOutcomeRecord: StrategyContract = Object.freeze({
  id: "outcome-record",
  family: "self_monitoring_adaptation",
  version: "0.1.0",
  implemented: true,
  description:
    "deterministic outcome ranking: failed/denied outcomes rank first for human review; proposes nothing, modifies nothing",
  async evaluate(
    input: AlgorithmDecisionInput,
    _context: RuntimeContext
  ): Promise<AlgorithmRecommendation> {
    void _context;
    const failed: string[] = [];
    const ok: string[] = [];
    for (const label of input.candidateLabels) {
      const l = label.toLowerCase();
      (l.startsWith("fail:") || l.startsWith("deny:") ? failed : ok).push(label);
    }
    const ranked = [...failed, ...ok];
    return recommendation(
      "self_monitoring_adaptation",
      "outcome-record",
      ranked,
      failed.length > 0 ? 0.9 : 0.6,
      failed.length > 0
        ? String(failed.length) + " failed/denied outcome(s) rank first for human review; adaptation is proposal-only and requires human approval"
        : "no failures observed; ordering is insertion order"
    );
  },
});

// ---------------------------------------------------------------------------
// Contract-only families (2,3,4,7,8,9) — registered, not implemented
// ---------------------------------------------------------------------------

/**
 * 17B: the contract-only placeholder generator. Families 3,4,7,8,9 remain
 * contract-only; their registered placeholder is INERT: the selector refuses
 * to evaluate any strategy with `implemented: false` (deny
 * `strategy_not_selected`), so this body is a deterministic fail-closed
 * guard, never a guessing path.
 */
function contractOnlyStrategy(family: AlgorithmFamily): StrategyContract {
  return Object.freeze({
    id: "contract-only",
    family,
    version: "0.1.0",
    implemented: false,
    description:
      "contract-only placeholder for family '" +
      family +
      "': the family contract is formalized; no concrete strategy ships in this phase",
    async evaluate(
      _input: AlgorithmDecisionInput,
      _context: RuntimeContext
    ): Promise<AlgorithmRecommendation> {
      void _input;
      void _context;
      // Unreachable through the selector (it denies implemented:false first).
      // Deterministic empty recommendation keeps the contract total.
      return recommendation(
        family,
        "contract-only",
        [],
        0,
        "contract-only family: no concrete strategy is implemented"
      );
    },
  });
}

/**
 * The contract-only families (5 in 17B: context_memory_retrieval,
 * multiagent_task_allocation, world_state_synchronization,
 * procedural_motion, agent_communication_routing) get a registered
 * placeholder whose evaluation is always refused by the selector with
 * `strategy_not_selected` — a missing implementation is a machine-readable
 * denial, never a silent pass-through.
 */
export const CONTRACT_ONLY_PLACEHOLDERS: readonly StrategyContract[] =
  Object.freeze(
    FAMILY_CONTRACTS.filter((f) => !f.implemented).map((f) =>
      contractOnlyStrategy(f.family)
    )
  );

/**
 * All ten reference strategies: five implemented (oida@0.2.0,
 * goal_priority, runtime_risk_evaluation@0.2.0, skill_selection@0.2.0,
 * self_monitoring_adaptation@0.2.0) + five contract-only placeholders,
 * exactly one per family. Ordered by the canonical family ordinals 1–10.
 */
export const REFERENCE_STRATEGIES: readonly StrategyContract[] = Object.freeze(
  FAMILY_CONTRACTS.map((fc) => {
    if (fc.family === "oida") return oidaLoopLite;
    if (fc.family === "goal_priority") return goalPriorityHintBudget;
    if (fc.family === "runtime_risk_evaluation") return runtimeRiskGateRank;
    if (fc.family === "skill_selection") return skillCapabilityMapLiteImpl;
    if (fc.family === "self_monitoring_adaptation") return selfMonitoringMetricObserve;
    // 17C: context_memory_retrieval intentionally has NO default-registry
    // strategy (it requires a caller-supplied retrieval port); it falls
    // through to the contract-only placeholder here, keeping the default
    // registry complete with exactly one selectable strategy per family.
    return contractOnlyStrategy(fc.family);
  })
);

/**
 * Build a fully-populated registry containing exactly one strategy per
 * family (ten total). Selection of any family+id pair works; evaluation of
 * contract-only placeholders denies with `strategy_not_selected`.
 */
export function buildDefaultStrategyRegistry(): StrategyRegistry {
  return new StrategyRegistry(REFERENCE_STRATEGIES);
}

/**
 * Registry completeness probe: verifies all ten families are represented
 * exactly once. Returns an error string or null.
 */
export function validateRegistryCompleteness(
  registry: StrategyRegistry
): string | null {
  for (const f of TEN_ALGORITHM_FAMILIES) {
    const strategies = registry.listForFamily(f);
    if (strategies.length === 0) {
      return "family '" + f + "' has no registered strategy";
    }
    if (strategies.length > 1) {
      return (
        "family '" + f + "' has " + String(strategies.length) +
        " strategies; default registry requires exactly one"
      );
    }
  }
  const extra = registry.familiesWithStrategies().filter(
    (f) => !TEN_ALGORITHM_FAMILIES.includes(f)
  );
  if (extra.length > 0) {
    return "registry contains strategies outside the ten closed families: " + extra.join(",");
  }
  return null;
}

/**
 * Family contract lookup by family id; null for unknown families.
 */
export function familyContract(
  family: AlgorithmFamily
): FamilyContract | null {
  return FAMILY_CONTRACTS.find((f) => f.family === family) ?? null;
}

// Re-export the denial type guard for one-stop consumers.
export { isAlgorithmDenial } from "./types.js";
