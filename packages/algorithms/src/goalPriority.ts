import type {
  AlgorithmBudget,
  AlgorithmDecisionInput,
  AlgorithmRecommendation,
  GoalScoreRecord,
  GoalPriorityHint,
  RuntimeContext,
  StrategyContract,
} from "./types.js";
import {
  ALGORITHM_MAX_BUDGET_WEIGHT,
  ALGORITHM_MAX_CANDIDATES,
  ALGORITHM_MIN_BUDGET_WEIGHT,
  isGoalPriorityHint,
} from "./types.js";

/**
 * Phase 17B — Goal Priority (family 2): deterministic goal ranking.
 *
 * Upgrades the 17A contract-only `goal_priority/contract-only` family to a
 * concrete strategy `goal-priority.hint-budget@0.1.0` (implemented: true).
 *
 * Scoring model (all inputs OBSERVABLE — no hidden state, no chain-of-thought):
 *
 *   weight(goal) = 40 × hint + 30 × urgency + 12 × recency − budgetCap
 *
 *  - hint:    caller-supplied `goalPriorityHint` ∈ {low=1, medium=2, high=3,
 *             critical=4} applied to the whole batch (batch-level declarative
 *             priority), default "low";
 *  - urgency: declarative label prefixes per goal — `urgent:` = 1,
 *             `blocking:` = 2, `critical:` = 3, else 0;
 *  - recency: "newer runs hotter" tie-break guidance — the position index in
 *             the candidate list stands in for recency; index i scores
 *             12 × (1 − i/len). The `deadlineEpochMs` budget field carries
 *             the caller's absolute deadline for deadline-aware tie-breaks.
 *  - budget:  when `budget.maxWeight` is set, every weight is capped at it
 *             (budgetCapped=true on affected records) and `maxRanked` caps
 *             how many goals may rank above weight 0.
 *
 * Tie-breakers, applied in order (all deterministic):
 *  1. higher weight;
 *  2. higher urgency;
 *  3. higher hint;
 *  4. earlier candidate index (insertion order).
 */

/** Hint weight table (declarative, documented). */
export const GOAL_PRIORITY_HINT_WEIGHTS: Readonly<
  Record<GoalPriorityHint, number>
> = Object.freeze({ low: 1, medium: 2, high: 3, critical: 4 });

/** Urgency prefix table (declarative, documented). */
export const GOAL_URGENCY_PREFIX_WEIGHTS: Readonly<Record<string, number>> =
  Object.freeze({ "critical:": 3, "blocking:": 2, "urgent:": 1 });

const RECENCY_WEIGHT_SPAN = 12;
const HINT_SCALE = 40;
const URGENCY_SCALE = 30;

/** Validate the 17B input extensions; returns an error string or null. */
export function validateGoalPriorityInput(
  input: AlgorithmDecisionInput
): string | null {
  if (input.goalPriorityHint !== undefined && !isGoalPriorityHint(input.goalPriorityHint)) {
    return (
      "goalPriorityHint must be one of low | medium | high | critical; got '" +
      String(input.goalPriorityHint) +
      "'"
    );
  }
  if (input.budget !== undefined) {
    const b = input.budget as Partial<AlgorithmBudget>;
    if (b === null || typeof b !== "object") {
      return "budget must be an object when present";
    }
    if (
      b.maxWeight !== undefined &&
      (typeof b.maxWeight !== "number" ||
        !Number.isInteger(b.maxWeight) ||
        b.maxWeight < ALGORITHM_MIN_BUDGET_WEIGHT ||
        b.maxWeight > ALGORITHM_MAX_BUDGET_WEIGHT)
    ) {
      return (
        "budget.maxWeight must be an integer in [" +
        String(ALGORITHM_MIN_BUDGET_WEIGHT) +
        ", " +
        String(ALGORITHM_MAX_BUDGET_WEIGHT) +
        "]"
      );
    }
    if (
      b.maxRanked !== undefined &&
      (typeof b.maxRanked !== "number" ||
        !Number.isInteger(b.maxRanked) ||
        b.maxRanked < 0 ||
        b.maxRanked > ALGORITHM_MAX_CANDIDATES)
    ) {
      return "budget.maxRanked must be an integer in [0, ALGORITHM_MAX_CANDIDATES]";
    }
    if (
      b.deadlineEpochMs !== undefined &&
      (typeof b.deadlineEpochMs !== "number" || !Number.isFinite(b.deadlineEpochMs))
    ) {
      return "budget.deadlineEpochMs must be a finite number when present";
    }
  }
  return null;
}

/** Compute the urgency component for one goal label. */
export function goalUrgencyWeight(label: string): number {
  const l = label.toLowerCase();
  if (l.startsWith("critical:")) return GOAL_URGENCY_PREFIX_WEIGHTS["critical:"]!;
  if (l.startsWith("blocking:")) return GOAL_URGENCY_PREFIX_WEIGHTS["blocking:"]!;
  if (l.startsWith("urgent:")) return GOAL_URGENCY_PREFIX_WEIGHTS["urgent:"]!;
  return 0;
}

interface ScoredGoal {
  readonly label: string;
  readonly weight: number;
  readonly hintWeight: number;
  readonly urgencyWeight: number;
  readonly recencyWeight: number;
  readonly budgetCapped: boolean;
  readonly index: number;
}

function scoreGoals(
  input: AlgorithmDecisionInput
): readonly ScoredGoal[] {
  const hint = input.goalPriorityHint ?? "low";
  const hintWeight = GOAL_PRIORITY_HINT_WEIGHTS[hint];
  const maxWeight = input.budget?.maxWeight;
  const maxRanked = input.budget?.maxRanked;
  const out: ScoredGoal[] = [];

  const n = input.candidateLabels.length;
  for (let i = 0; i < n; i++) {
    const label = input.candidateLabels[i]!;
    const urgency = goalUrgencyWeight(label);
    const recency = RECENCY_WEIGHT_SPAN * (1 - i / Math.max(1, n));
    let weight = HINT_SCALE * hintWeight + URGENCY_SCALE * urgency + recency;
    let budgetCapped = false;
    if (maxWeight !== undefined && weight > maxWeight) {
      weight = maxWeight;
      budgetCapped = true;
    }
    out.push({
      label,
      weight,
      hintWeight,
      urgencyWeight: urgency,
      recencyWeight: recency,
      budgetCapped,
      index: i,
    });
  }

  // maxRanked: only the first `maxRanked` goals by current ordering may rank
  // above weight 0; the rest are zeroed (they remain in the list, ranked last).
  if (maxRanked !== undefined) {
    const ordered = [...out].sort(
      (a, b) => b.weight - a.weight || a.index - b.index
    );
    const keep = new Set<string>();
    for (let i = 0; i < ordered.length && i < maxRanked; i++) {
      keep.add(ordered[i]!.label);
    }
    for (const g of out) {
      if (!keep.has(g.label)) {
        (g as { weight: number }).weight = 0;
        (g as { budgetCapped: boolean }).budgetCapped = true;
        // Weight zeroed; keep original component weights for observability.
      }
    }
  }

  return out;
}

/** Deterministic sort: weight desc, urgency desc, hint desc, index asc. */
function tieBreakSort(goals: readonly ScoredGoal[]): readonly ScoredGoal[] {
  return [...goals].sort((a, b) => {
    if (b.weight !== a.weight) return b.weight - a.weight;
    if (b.urgencyWeight !== a.urgencyWeight) return b.urgencyWeight - a.urgencyWeight;
    if (b.hintWeight !== a.hintWeight) return b.hintWeight - a.hintWeight;
    return a.index - b.index;
  });
}

/**
 * Pure ranking core: returns the ranked labels + per-goal observable score
 * records. Exported read-only for tests/observability.
 */
export function rankGoalsDeterministic(
  input: AlgorithmDecisionInput
): { readonly ranked: readonly string[]; readonly scores: readonly GoalScoreRecord[] } {
  const scored = tieBreakSort(scoreGoals(input));
  return {
    ranked: scored.map((g) => g.label),
    scores: scored.map((g) =>
      Object.freeze({
        label: g.label,
        hintWeight: g.hintWeight,
        urgencyWeight: g.urgencyWeight,
        recencyWeight: g.recencyWeight,
        budgetCapped: g.budgetCapped,
      })
    ),
  };
}

/** Build the 17B reasoning summary (conclusion-only, bounded). */
function buildReasoningSummary(
  input: AlgorithmDecisionInput,
  ranked: readonly string[],
  scores: readonly GoalScoreRecord[]
): string {
  const hint = input.goalPriorityHint ?? "low";
  const capped = scores.filter((s) => s.budgetCapped).length;
  const top = ranked[0];
  const topUrgency = scores.find((s) => s.label === top)?.urgencyWeight ?? 0;
  const budgetPart =
    input.budget?.maxWeight !== undefined
      ? "; budget cap " + String(input.budget.maxWeight) + " applied to " + String(capped) + " goal(s)"
      : "";
  const summary =
    "ranked " +
    String(ranked.length) +
    " goal(s) by hint=" +
    hint +
    (topUrgency > 0 ? "; top goal carries urgency prefix" : "") +
    budgetPart +
    (top !== undefined ? "; top: " + top : "");
  return summary.length > 256 ? summary.slice(0, 256) : summary;
}

/**
 * `goal-priority.hint-budget` — the 17B Goal Priority strategy.
 * Deterministic; recommend-only; no execution authority.
 */
export const goalPriorityHintBudget: StrategyContract = Object.freeze({
  id: "hint-budget",
  family: "goal_priority",
  version: "0.1.0",
  implemented: true,
  description:
    "deterministic goal ranking: weight = 40*hint + 30*urgency + 12*recency, capped by budget.maxWeight/maxRanked; ties by urgency, hint, insertion order",
  async evaluate(
    input: AlgorithmDecisionInput,
    _context: RuntimeContext
  ): Promise<AlgorithmRecommendation> {
    void _context;
    const { ranked, scores } = rankGoalsDeterministic(input);
    return {
      family: "goal_priority",
      strategyId: "hint-budget",
      rankedCandidates: ranked,
      confidence: ranked.length > 0 ? 0.85 : 0.5,
      rationale:
        "deterministic goal ranking by declarative hint, urgency prefix, recency tie-break and budget caps",
      isRecommendation: true,
      executionAuthorized: false,
      reasoningSummary: buildReasoningSummary(input, ranked, scores),
    };
  },
});


