import type { Actor } from "@menog/core";

/**
 * Phase 17A — Algorithm Registry & Strategy Contract.
 *
 * Algorithms are HOW. Agents are WHO. Verbs are WHAT.
 * A strategy family describes *how reasoning is performed* for a class of
 * runtime decision. Strategies recommend and compute; they NEVER execute,
 * authorize, or modify state: policy remains the sole authority for what the
 * runtime MAY do, and the runtime remains the sole executor of what policy
 * allowed. Every evaluation result carries `isRecommendation: true` so no
 * consumer can mistake algorithm output for an execution permission.
 */

/** Canonical schema version pinned for the 17A algorithm contract surface. */
export const ALGORITHM_SCHEMA_VERSION = "menog-algorithms/v0" as const;
export type AlgorithmSchemaVersion = typeof ALGORITHM_SCHEMA_VERSION;

/**
 * The ten behavioral algorithm families (docs/ALGORITHM_REGISTRY_v0).
 * The union is CLOSED: introducing an eleventh family is an unfreeze-protocol
 * event requiring explicit human approval.
 */
export type AlgorithmFamily =
  | "oida"
  | "goal_priority"
  | "context_memory_retrieval"
  | "multiagent_task_allocation"
  | "runtime_risk_evaluation"
  | "skill_selection"
  | "world_state_synchronization"
  | "procedural_motion"
  | "agent_communication_routing"
  | "self_monitoring_adaptation";

export const ALGORITHM_FAMILIES: readonly AlgorithmFamily[] = Object.freeze([
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
]);

export function isAlgorithmFamily(value: unknown): value is AlgorithmFamily {
  return (
    typeof value === "string" &&
    (ALGORITHM_FAMILIES as readonly string[]).includes(value)
  );
}

/**
 * Deterministic, provenance-safe classification of one strategic decision
 * input. No raw payload is carried — inputs are summarized by the caller and
 * summarized again here so strategies cannot become a covert data channel.
 */
export type AlgorithmInputSensitivity =
  | "public"
  | "workspace_internal"
  | "untrusted_external";

export const KNOWN_ALGORITHM_INPUT_SENSITIVITIES: readonly AlgorithmInputSensitivity[] =
  Object.freeze(["public", "workspace_internal", "untrusted_external"]);

export function isAlgorithmInputSensitivity(
  value: unknown
): value is AlgorithmInputSensitivity {
  return (
    typeof value === "string" &&
    (KNOWN_ALGORITHM_INPUT_SENSITIVITIES as readonly string[]).includes(value)
  );
}

// ---------------------------------------------------------------------------
// Phase 17B — OIDA state machine + Goal Priority contracts.
// ---------------------------------------------------------------------------

/** The four canonical OIDA loop phases (closed union). */
export type OidaPhase = "observe" | "interpret" | "decide" | "act";

export const OIDATA_PHASES: readonly OidaPhase[] = Object.freeze([
  "observe",
  "interpret",
  "decide",
  "act",
]);

export function isOidaPhase(value: unknown): value is OidaPhase {
  return (
    value === "observe" ||
    value === "interpret" ||
    value === "decide" ||
    value === "act"
  );
}

/**
 * Explicit, observable state of one OIDA loop instance (17B).
 *
 * The state machine is caller-owned: strategies compute the NEXT state and
 * phase, but never mutate state themselves (no hidden state, no self-modi-
 * fication). The canonical phase order is observe → interpret → decide →
 * act → (loop or done). Transitions that skip a phase, go backwards, or
 * continue past `done` are invalid and denied.
 */
export interface OidaLoopState {
  readonly currentPhase: OidaPhase;
  /** True once the loop has legally reached `act` completion. */
  readonly done: boolean;
  /** Number of completed phase advances (monotone, caller-owned counter). */
  readonly iteration: number;
}

/**
 * Optional Goal Priority hints attached to a decision input (17B).
 * Callers supply OBSERVABLE data — a declarative priority hint, an urgency
 * class, and/or a bounded budget. Goal labels come from `candidateLabels`;
 * no hidden scoring state exists.
 */
export type GoalPriorityHint = "low" | "medium" | "high" | "critical";

export const KNOWN_GOAL_PRIORITY_HINTS: readonly GoalPriorityHint[] =
  Object.freeze(["low", "medium", "high", "critical"]);

export function isGoalPriorityHint(
  value: unknown
): value is GoalPriorityHint {
  return (
    typeof value === "string" &&
    (KNOWN_GOAL_PRIORITY_HINTS as readonly string[]).includes(value)
  );
}

/** Budget surface for budget-aware goal ranking (all fields optional). */
export interface AlgorithmBudget {
  /** Maximum ranking weight assigned to a single goal (bounded 1..1000). */
  readonly maxWeight?: number;
  /** Maximum number of goals that may be ranked above weight 0. */
  readonly maxRanked?: number;
  /** Soft deadline in epoch-ms; later-started goals rank below earlier ones on ties. */
  readonly deadlineEpochMs?: number;
}

/**
 * Structured, bounded description of the decision context handed to a
 * strategy. Only primitive scalar fields are permitted (validated by the
 * registry) so a strategy evaluation can never smuggle opaque blobs,
 * functions, or unbounded payloads through the reasoning stage.
 */
export interface AlgorithmDecisionInput {
  /** Human-meaningful label of what is being decided (e.g. "rank goals"). */
  readonly decision: string;
  /** Which verb the surrounding task is attempting (informational only). */
  readonly verb?: string;
  /** Bounded candidate labels the strategy may rank/select among. */
  readonly candidateLabels: readonly string[];
  /** Provenance-safe sensitivity class of the decision input. */
  readonly sensitivity: AlgorithmInputSensitivity;  /**
   * 17C: optional set of capabilities the CALLER claims are currently granted
   * (e.g. from a policy decision). Skill selection filters its recommendations
   * to this set when present. This is CALLER-ASSERTED data — the policy engine
   * remains the sole authority on what is actually allowed (17C threat model).
   */
  readonly grantedCapabilities?: readonly string[];
  /**
   * 17D: observable outcome/metric feedback for self-monitoring strategies.
   * Metrics are OBSERVABLE DATA (counts, ratios, timings) supplied by the
   * caller — no hidden background collection exists anywhere.
   */
  readonly metrics?: readonly MonitorMetric[];
  /**
   * 17C: current OIDA loop state, when the caller owns a loop instance. */
  readonly oidaState?: OidaLoopState;
  /** 17B: caller-owned observable priority hint for goal ranking. */
  readonly goalPriorityHint?: GoalPriorityHint;
  /** 17B: bounded budget surface for budget-aware ranking. */
  readonly budget?: AlgorithmBudget;
}

/**
 * Candidate labels are bounded both in count and per-label length so that no
 * caller can force unbounded work inside a strategy evaluation.
 */
export const ALGORITHM_MAX_CANDIDATES = 64;
export const ALGORITHM_MAX_CANDIDATE_LABEL_CHARS = 256;
export const ALGORITHM_MAX_DECISION_CHARS = 256;
/** 17B: reasoning summaries are conclusion-only and bounded. */
export const ALGORITHM_MAX_REASONING_SUMMARY_CHARS = 256;
/** 17B: OIDA loop iteration counter is bounded (loop budget). */
export const ALGORITHM_MAX_OIDATA_ITERATIONS = 1000;
/** 17B: budget weight bounds. */
export const ALGORITHM_MIN_BUDGET_WEIGHT = 1;
export const ALGORITHM_MAX_BUDGET_WEIGHT = 1000;
/** 17D: metric feedback bounds (bounded self-monitoring). */
export const ALGORITHM_MAX_METRICS = 32;
export const ALGORITHM_MAX_METRIC_NAME_CHARS = 64;
/** 17D: parameter values are clamped to this magnitude (bounded adaptation). */
export const ALGORITHM_MAX_PARAMETER_MAGNITUDE = 1_000_000;
/** 17D: maximum number of tunable parameters per store. */
export const ALGORITHM_MAX_TUNABLE_PARAMETERS = 64;
/** 17D: maximum retained change records per parameter (bounded history). */
export const ALGORITHM_MAX_PARAMETER_HISTORY = 32;
/** 17C: risk verdict tiers, ordered non-strictly below. */
export type RiskVerdictTier = "allow" | "restrict" | "deny";

export const KNOWN_RISK_VERDICT_TIERS: readonly RiskVerdictTier[] =
  Object.freeze(["allow", "restrict", "deny"]);

export function isRiskVerdictTier(value: unknown): value is RiskVerdictTier {
  return (
    typeof value === "string" &&
    (KNOWN_RISK_VERDICT_TIERS as readonly string[]).includes(value)
  );
}

/**
 * Machine-readable risk verdict attached to a runtime-risk recommendation
 * (17C). RISK MAY RESTRICT/DENY EXECUTION — but only ADVISORY-ly: a verdict
 * is a recommendation to the policy/decision layer, never an authorization
 * and never a bypass. `executionAuthorized` stays pinned false on every
 * result regardless of tier. Monotone restriction invariant: `applyRiskVerdict`
 * can only LOWER what the caller claims policy granted (policy = floor).
 */
export interface RiskVerdict {
  readonly tier: RiskVerdictTier;
  /** Short bounded reason the tier was chosen (e.g. risk-indicator hits). */
  readonly reason: string;
  /** Capability labels the verdict recommends withholding (restrict/deny). */
  readonly withholdCapabilities?: readonly string[];
}

/**
 * The recommendation a strategy returns. Deliberately NON-authoritative:
 * `isRecommendation` is pinned `true` on every valid result and the registry
 * refuses results that try to carry policy/execution fields.
 */
export interface AlgorithmRecommendation {
  /** The family whose strategy produced this recommendation. */
  readonly family: AlgorithmFamily;
  /** Identifier of the concrete strategy that produced this recommendation. */
  readonly strategyId: string;
  /** Ranked candidate labels (best first); empty when nothing is recommended. */
  readonly rankedCandidates: readonly string[];
  /** Deterministic confidence in [0,1]. */
  readonly confidence: number;
  /** Short, bounded human-readable rationale (audit/observability only). */
  readonly rationale: string;
  /** ALWAYS true — pinned by the registry, immutable by construction. */
  readonly isRecommendation: true;
  /** ALWAYS false — algorithm output can never carry execution authority. */
  readonly executionAuthorized: false;
  /**
   * 17B: observable REASONING SUMMARY — what the strategy concluded, not
   * how it was derived. Strategies MAY emit it; the selector pins/omits it
   * consistently. It is explicitly NOT private chain-of-thought: it must
   * never contain derivation traces, intermediate scoring, or hidden state.
   */
  readonly reasoningSummary?: string;
  /**
   * 17B (OIDA strategies only): the recommended NEXT observable loop state.
   * Computed data for the caller — the caller owns all state mutation.
   */
  readonly nextOidaState?: OidaLoopState;
  /**
   * 17C (runtime-risk strategies only): the machine-readable risk verdict.
   * Pinned/passed-through by the selector; advisory only — policy remains
   * the sole authority on what MAY run.
   */
  readonly riskVerdict?: RiskVerdict;
  /**
   * 17D (self-monitoring strategies only): a bounded, audited parameter
   * adaptation proposal. DATA for the caller/human review — applying it is
   * a separate, explicit, caller-owned step; proposals never self-apply.
   */
  readonly adaptationProposal?: AdaptationProposal;
}

/** Machine-readable deny reasons for the algorithm stage (fail-closed). */
export type AlgorithmDenyReason =
  | "unknown_family"
  | "unknown_strategy"
  | "strategy_not_selected"
  | "invalid_input"
  | "invalid_state"
  | "oversized_input"
  | "recommendation_not_authoritative"
  | "selection_not_allowed"
  | "retrieval_unavailable"
  | "adaptation_out_of_bounds"
  | "parameter_unknown"
  | "rollback_target_missing";

export interface AlgorithmDenial {
  readonly ok: false;
  readonly denyReason: AlgorithmDenyReason;
  readonly reason: string;
}

export interface AlgorithmEvaluationSuccess {
  readonly ok: true;
  readonly schemaVersion: AlgorithmSchemaVersion;
  readonly recommendation: AlgorithmRecommendation;
  /** Ledger event id of the underlying observable selection, when available. */
  readonly policyEventId?: string;
}

export type AlgorithmEvaluationResult =
  | AlgorithmEvaluationSuccess
  | AlgorithmDenial;

export type AlgorithmSelectionResult =
  | { readonly ok: true; readonly strategy: StrategyContract }
  | AlgorithmDenial;

export function isAlgorithmDenial(
  r: AlgorithmEvaluationResult | AlgorithmSelectionResult
): r is AlgorithmDenial {
  return r.ok === false;
}

/**
 * Runtime context handed to every strategy invocation. Carries the requesting
 * actor and workspace identity for observability; strategies receive it as
 * read-only data and must not treat it as authority.
 */
export interface RuntimeContext {
  readonly actor: Actor;
  readonly workspaceId?: string;
  readonly taskId?: string;
}

/**
 * The 17A strategy contract (formalizes ALGORITHM_REGISTRY_v0 §Algorithm
 * contract). A strategy is a PURE, DETERMINISTIC recommender: given the same
 * input and context it must return the same recommendation. It performs no
 * I/O, holds no mutable authority, and can never authorize anything.
 */
export interface AlgorithmStrategy<I = unknown, O = unknown> {
  /** Stable strategy id, unique within its family (e.g. "oida.loop-lite"). */
  readonly id: string;
  /** The closed family this strategy belongs to. */
  readonly family: AlgorithmFamily;
  /** Strategy version (semver string, registry-validated). */
  readonly version: string;
  /** Whether this family currently ships a concrete implementation. */
  readonly implemented: boolean;
  /** Human-readable description of the reasoning approach. */
  readonly description: string;
  /**
   * Compute a recommendation. MUST be deterministic for deterministic inputs;
   * MUST NOT perform I/O, mutate state, or authorize execution.
   */
  evaluate(input: I, context: RuntimeContext): Promise<O>;
}

/**
 * Type-erased strategy shape stored in the registry. Generic type parameters
 * are erased at the registry boundary; input validation is delegated to the
 * shared `AlgorithmDecisionInput` shape so storage stays uniform.
 */
export type StrategyContract = AlgorithmStrategy<
  AlgorithmDecisionInput,
  AlgorithmRecommendation
>;

/** Descriptor of one registered strategy (observability surface). */
export interface StrategyDescriptor {
  readonly id: string;
  readonly family: AlgorithmFamily;
  readonly version: string;
  readonly implemented: boolean;
  readonly description: string;
}

// ---------------------------------------------------------------------------
// Phase 17B — OIDA state machine transition contracts (pure functions).
// ---------------------------------------------------------------------------

/** Result of validating an OIDA loop state (17B). */
export type OidaStateValidation =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: string };

/** Result of computing the next OIDA state (17B). */
export type OidaAdvanceResult =
  | { readonly ok: true; readonly state: OidaLoopState; readonly phase: OidaPhase }
  | { readonly ok: false; readonly reason: string };

/**
 * Internal scoring record for goal ranking (17B). Exported read-only for
 * observability: it carries the DETERMINISTIC inputs of the ranking (hint,
 * urgency, recency, budget), never any hidden chain-of-thought.
 */
export interface GoalScoreRecord {
  readonly label: string;
  readonly hintWeight: number;
  readonly urgencyWeight: number;
  readonly recencyWeight: number;
  readonly budgetCapped: boolean;
}

// ---------------------------------------------------------------------------
// Phase 17C — integration contracts (memory retrieval port, risk verdicts,
// capability-aware skill selection).
// ---------------------------------------------------------------------------

/**
 * The MINIMAL read-only retrieval surface the context-memory strategy
 * consumes (17C). Structural (not nominal) so the EXISTING, policy-gated
 * `MemoryRetrievalService` from `@menog/memory` satisfies it unchanged —
 * integration WITHOUT bypass: memory reads stay policy-gated, scope-isolated
 * and ledger-observable inside the memory package.
 */
export interface MemoryRetrievalPort {
  /**
   * Must return ranked hits through the underlying policy-gated store reads.
   * Implementations are expected to fail closed (return { ok:false }) when
   * policy denies, scope mismatches, or no store is attached.
   */
  retrieve(
    ctx: {
      readonly actor: { readonly type: string; readonly id: string };
      readonly grantedScope: { readonly workspaceId: string; readonly taskId?: string; readonly sessionId?: string };
    },
    query: { readonly text?: string; readonly limit?: number },
    strategyId?: string
  ): Promise<
    | {
        readonly ok: true;
        readonly hits: readonly {
          readonly score: number;
          readonly snippet: string;
          readonly origin: string;
          readonly untrusted: boolean;
        }[];
      }
    | { readonly ok: false; readonly denyReason: string; readonly reason: string }
  >;
}

/** Explicit failure for a missing/unusable retrieval port (17C). */
export class RetrievalPortError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RetrievalPortError";
  }
}

/** Result of projecting a retrieval port response into labels (17C). */
export interface MemoryProjectionResult {
  readonly labels: readonly string[];
  readonly sourceCount: number;
  readonly untrustedCount: number;
}

// ---------------------------------------------------------------------------
// Phase 17D — bounded self-monitoring & adaptation contracts.
// ---------------------------------------------------------------------------

/** One observable outcome/metric sample supplied by the caller (17D). */
export interface MonitorMetric {
  /** Stable metric name (e.g. "deny_ratio", "p95_latency_ms"). */
  readonly name: string;
  /** Finite numeric value. */
  readonly value: number;
}

/**
 * The minimal read-only metric-feedback surface a self-monitoring strategy
 * consumes (17D). Structural so callers can adapt any observable source —
 * execution memory (16B), ledger event counts, CLI-supplied metrics —
 * WITHOUT the algorithm package reaching into those packages directly.
 */
export interface MetricFeedbackPort {
  /** Must return bounded observable metrics; implementations fail closed. */
  collect(): Promise<{ readonly ok: true; readonly metrics: readonly MonitorMetric[] } | { readonly ok: false; readonly denyReason: string; readonly reason: string }>;
}

/**
 * Human-registered bounds for one tunable parameter (17D). Bounds are set
 * by POLICY/humans at registration; adaptation can only move values WITHIN
 * them. This is the "adapt parameters only within policy bounds" contract.
 */
export interface ParameterBounds {
  readonly min: number;
  readonly max: number;
}

/** Declared mutation class of one tunable parameter (17D). */
export type ParameterSensitivity = "performance" | "threshold" | "scheduling";

/** Observable state of one tunable parameter (17D). */
export interface TunableParameterState {
  readonly name: string;
  readonly value: number;
  readonly bounds: ParameterBounds;
  readonly sensitivity: ParameterSensitivity;
  /** Number of applied adaptations since registration (monotone). */
  readonly revision: number;
}

/**
 * A bounded parameter-adaptation proposal (17D). Proposals are DATA: they
 * never self-apply; application is an explicit caller step through the
 * audited store, and every applied change is recorded + reversible.
 */
export interface AdaptationProposal {
  readonly parameter: string;
  readonly currentValue: number;
  readonly proposedValue: number;
  readonly bounds: ParameterBounds;
  /** Bounded conclusion-only reason (no derivation internals). */
  readonly reason: string;
}
