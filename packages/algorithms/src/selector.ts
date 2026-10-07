import type {
  AlgorithmDecisionInput,
  AlgorithmDenial,
  AlgorithmDenyReason,
  AlgorithmEvaluationResult,
  AlgorithmRecommendation,
  RuntimeContext,
  StrategyContract,
} from "./types.js";
import {
  ALGORITHM_MAX_CANDIDATES,
  ALGORITHM_MAX_CANDIDATE_LABEL_CHARS,
  ALGORITHM_MAX_DECISION_CHARS,
  ALGORITHM_MAX_REASONING_SUMMARY_CHARS,
} from "./types.js";
import { validateGoalPriorityInput } from "./goalPriority.js";
import { validateOidaState } from "./oida.js";
import { OidaStateError } from "./oidaStrategy.js";
import { validateGrantedCapabilities } from "./integration.js";
import { validateMetricsInput } from "./selfMonitoring.js";
import { RetrievalPortError } from "./types.js";

/**
 * Phase 17A — Strategy Selector.
 *
 * The selector is the SINGLE observable entry point for running a strategy
 * evaluation. It exists so that:
 *  1. Selection is deny-by-default: no strategy is ever resolved from
 *     ambient state, model output, or memory content — only from the
 *     registry via explicit family+id.
 *  2. Inputs are bounded and validated BEFORE any strategy runs (no
 *     unbounded work can be forced through the reasoning stage).
 *  3. Results are pinned non-authoritative: `isRecommendation: true` and
 *     `executionAuthorized: false` are re-stamped by the selector itself, so
 *     even a misbehaving strategy cannot emit an authoritative-looking
 *     result object. `recommendation_not_authoritative` denies any strategy
 *     output that attempts to set `executionAuthorized` to a truthy value.
 *  4. Every allowed evaluation is observable (optional ledger event via the
 *     injected emitter — the selector never appends by itself, preserving
 *     NO WRITE WITHOUT SCOPE: callers retain append authority).
 */

/** Minimal ledger-emitter surface (mirrors policy `LedgerEmitter`). */
export interface AlgorithmLedgerEmitter {
  readonly append: (input: {
    readonly eventType: string;
    readonly policyDecision: "allow" | "deny" | "not_applicable";
    readonly actor: { readonly type: string; readonly id: string };
    readonly workspaceId?: string;
    readonly taskId?: string;
    readonly inputSummary: Readonly<Record<string, unknown>>;
    readonly resultSummary: Readonly<Record<string, unknown>>;
  }) => { readonly ok: boolean; readonly eventId?: string };
}

export interface StrategySelectorOptions {
  /** Optional ledger emitter; when absent, evaluations are simply not logged. */
  readonly ledger?: AlgorithmLedgerEmitter | null;
}

function deny(
  denyReason: AlgorithmDenyReason,
  reason: string
): AlgorithmDenial {
  return { ok: false, denyReason, reason };
}

/** Validate the bounded decision input; returns an error string or null. */
export function validateDecisionInput(
  input: AlgorithmDecisionInput
): string | null {
  if (input === null || typeof input !== "object") {
    return "decision input must be an object";
  }
  if (typeof input.decision !== "string" || input.decision.length === 0) {
    return "decision must be a non-empty string";
  }
  if (input.decision.length > ALGORITHM_MAX_DECISION_CHARS) {
    return (
      "decision is " +
      String(input.decision.length) +
      " chars which exceeds ALGORITHM_MAX_DECISION_CHARS (" +
      String(ALGORITHM_MAX_DECISION_CHARS) +
      ")"
    );
  }
  if (input.verb !== undefined && (typeof input.verb !== "string" || input.verb.length === 0)) {
    return "verb, when present, must be a non-empty string";
  }
  if (!Array.isArray(input.candidateLabels)) {
    return "candidateLabels must be an array";
  }
  if (input.candidateLabels.length > ALGORITHM_MAX_CANDIDATES) {
    return (
      "candidateLabels has " +
      String(input.candidateLabels.length) +
      " entries which exceeds ALGORITHM_MAX_CANDIDATES (" +
      String(ALGORITHM_MAX_CANDIDATES) +
      ")"
    );
  }
  for (let i = 0; i < input.candidateLabels.length; i++) {
    const label = input.candidateLabels[i];
    if (typeof label !== "string" || label.length === 0) {
      return "candidateLabels[" + String(i) + "] must be a non-empty string";
    }
    if (label.length > ALGORITHM_MAX_CANDIDATE_LABEL_CHARS) {
      return (
        "candidateLabels[" +
        String(i) +
        "] is " +
        String(label.length) +
        " chars which exceeds ALGORITHM_MAX_CANDIDATE_LABEL_CHARS (" +
        String(ALGORITHM_MAX_CANDIDATE_LABEL_CHARS) +
        ")"
      );
    }
  }
  if (
    input.sensitivity !== "public" &&
    input.sensitivity !== "workspace_internal" &&
    input.sensitivity !== "untrusted_external"
  ) {
    return "sensitivity must be one of public | workspace_internal | untrusted_external";
  }
  // 17B: OIDA loop state, when present, must be a well-formed state-machine
  // state (machine-readable invalid_state denials come from here).
  if (input.oidaState !== undefined) {
    const st = validateOidaState(input.oidaState);
    if (!st.ok) return st.reason;
  }
  // 17B: Goal Priority hints/budget, when present, must be well-formed.
  const gpErr = validateGoalPriorityInput(input);
  if (gpErr !== null) return gpErr;
  // 17C: caller-asserted granted capabilities, when present, must be a
  // bounded array of non-empty strings.
  const gcErr = validateGrantedCapabilities(input);
  if (gcErr !== null) return gcErr;
  // 17D: observable metric feedback, when present, must be bounded and
  // finite (no NaN/Infinity can poison adaptation derivation).
  const mErr = validateMetricsInput(input);
  if (mErr !== null) return mErr;
  return null;
}

/**
 * Clamp and freeze a strategy's raw output into the pinned recommendation
 * shape. `isRecommendation: true` / `executionAuthorized: false` are ALWAYS
 * re-stamped here — the strategy's own values for those fields are ignored.
 */
function pinRecommendation(
  raw: AlgorithmRecommendation,
  strategy: StrategyContract
): AlgorithmRecommendation | string {
  if (raw === null || typeof raw !== "object") {
    return "strategy output must be an object";
  }
  if (!Array.isArray(raw.rankedCandidates)) {
    return "strategy output rankedCandidates must be an array";
  }
  for (const c of raw.rankedCandidates) {
    if (typeof c !== "string") {
      return "strategy output rankedCandidates entries must be strings";
    }
  }
  if (typeof raw.confidence !== "number" || !Number.isFinite(raw.confidence)) {
    return "strategy output confidence must be a finite number";
  }
  if (typeof raw.rationale !== "string") {
    return "strategy output rationale must be a string";
  }
  // Authority guard: a strategy that claims authorization is denied outright
  // (its output is never surfaced, even redacted).
  if (raw.executionAuthorized !== false) {
    return "__AUTHORITY_VIOLATION__";
  }
  const clampedConfidence = Math.max(0, Math.min(1, raw.confidence));
  const boundedRationale =
    raw.rationale.length > 512 ? raw.rationale.slice(0, 512) : raw.rationale;
  // 17B: reasoning summaries are conclusion-only and bounded. A strategy
  // output may carry one; the selector bounds it and never invents one.
  const reasoningSummary =
    typeof raw.reasoningSummary === "string"
      ? raw.reasoningSummary.length > ALGORITHM_MAX_REASONING_SUMMARY_CHARS
        ? raw.reasoningSummary.slice(0, ALGORITHM_MAX_REASONING_SUMMARY_CHARS)
        : raw.reasoningSummary
      : undefined;
  // 17B: nextOidaState passes through only when well-formed (state data for
  // the caller, never state mutation by the algorithm stage).
  const nextOidaState =
    raw.nextOidaState !== undefined && validateOidaState(raw.nextOidaState).ok
      ? raw.nextOidaState
      : undefined;
  // 17D: adaptationProposal passes through only when well-formed (finite
  // values). It is DATA for the caller — never self-applied by the selector.
  let adaptationProposal: import("./types.js").AdaptationProposal | undefined;
  if (raw.adaptationProposal !== undefined) {
    const ap = raw.adaptationProposal as import("./types.js").AdaptationProposal;
    if (
      ap !== null &&
      typeof ap === "object" &&
      typeof ap.parameter === "string" && ap.parameter.length > 0 &&
      typeof ap.currentValue === "number" && Number.isFinite(ap.currentValue) &&
      typeof ap.proposedValue === "number" && Number.isFinite(ap.proposedValue) &&
      typeof ap.reason === "string"
    ) {
      adaptationProposal = Object.freeze({
        parameter: ap.parameter.slice(0, 64),
        currentValue: ap.currentValue,
        proposedValue: ap.proposedValue,
        bounds: Object.freeze({
          min: typeof ap.bounds?.min === "number" && Number.isFinite(ap.bounds.min) ? ap.bounds.min : -Number.MAX_VALUE,
          max: typeof ap.bounds?.max === "number" && Number.isFinite(ap.bounds.max) ? ap.bounds.max : Number.MAX_VALUE,
        }),
        reason: ap.reason.slice(0, 256),
      });
    }
  }
  // 17C: riskVerdict passes through only when well-formed (tier in the
  // closed union, bounded reason). It stays ADVISORY data; authority pins
  // are unaffected.
  let riskVerdict: import("./types.js").RiskVerdict | undefined;
  if (raw.riskVerdict !== undefined) {
    const rv = raw.riskVerdict as import("./types.js").RiskVerdict;
    if (
      rv !== null &&
      typeof rv === "object" &&
      (rv.tier === "allow" || rv.tier === "restrict" || rv.tier === "deny") &&
      typeof rv.reason === "string"
    ) {
      riskVerdict = Object.freeze({
        tier: rv.tier,
        reason: rv.reason.length > 256 ? rv.reason.slice(0, 256) : rv.reason,
        ...(Array.isArray(rv.withholdCapabilities)
          ? {
              withholdCapabilities: Object.freeze(
                rv.withholdCapabilities.filter(
                  (c): c is string => typeof c === "string" && c.length > 0
                )
              ),
            }
          : {}),
      });
    }
  }
  return Object.freeze({
    family: strategy.family,
    strategyId: strategy.id,
    rankedCandidates: Object.freeze([...raw.rankedCandidates]),
    confidence: clampedConfidence,
    rationale: boundedRationale,
    isRecommendation: true,
    executionAuthorized: false,
    ...(reasoningSummary !== undefined ? { reasoningSummary } : {}),
    ...(nextOidaState !== undefined ? { nextOidaState } : {}),
    ...(riskVerdict !== undefined ? { riskVerdict } : {}),
    ...(adaptationProposal !== undefined ? { adaptationProposal } : {}),
  });
}

export class StrategySelector {
  readonly #ledger: AlgorithmLedgerEmitter | null;

  constructor(options: StrategySelectorOptions = {}) {
    this.#ledger = options.ledger ?? null;
  }

  /**
   * Select and evaluate a strategy.
   *
   * Fail-closed on: unknown family, unknown strategy, invalid/oversized
   * input, strategy output attempting to claim authority, or strategy
   * throwing (exception becomes `invalid_input` denial — never surfaced as
   * an execution error path).
   */
  async evaluate(
    strategy: StrategyContract,
    input: AlgorithmDecisionInput,
    context: RuntimeContext
  ): Promise<AlgorithmEvaluationResult> {
    const inputErr = validateDecisionInput(input);
    if (inputErr !== null) {
      const isOversized = inputErr.includes("exceeds ALGORITHM_MAX");
      // 17B/17C: malformed caller-owned state (OIDA loop state, goal priority
      // hint, budget, granted capabilities) denies with invalid_state —
      // precedence over size checks, because a malformed state is never
      // merely "too big".
      const isInvalidState =
        inputErr.includes("oidaState") ||
        inputErr.includes("budget") ||
        inputErr.includes("goalPriorityHint") ||
        inputErr.includes("grantedCapabilities") ||
        inputErr.includes("metrics");
      const denyReason: AlgorithmDenyReason = isInvalidState
        ? "invalid_state"
        : isOversized
          ? "oversized_input"
          : "invalid_input";
      this.#log(context, "deny", denyReason, inputErr, strategy, null);
      return deny(denyReason, inputErr);
    }

    // Fail-closed for contract-only families: a strategy marked
    // `implemented: false` is never evaluated — a missing implementation is
    // a machine-readable denial, never a guessed or empty "success".
    if (strategy.implemented !== true) {
      const reason =
        "strategy '" +
        strategy.id +
        "' in family '" +
        strategy.family +
        "' is contract-only (implemented=false); evaluation denied rather than guessed";
      this.#log(context, "deny", "strategy_not_selected", reason, strategy, null);
      return deny("strategy_not_selected", reason);
    }

    let raw: unknown;
    try {
      raw = await strategy.evaluate(input, context);
    } catch (e) {
      // 17C: retrieval-port failures surface as retrieval_unavailable — a
      // missing or denying memory source is a distinct machine-readable
      // state from generic invalid input.
      if (e instanceof RetrievalPortError) {
        const reason = "memory retrieval unavailable: " + String(e.message);
        this.#log(context, "deny", "retrieval_unavailable", reason, strategy, null);
        return deny("retrieval_unavailable", reason);
      }
      // 17B: OIDA state-machine violations surface as invalid_state (a
      // distinct machine-readable denial from generic invalid_input).
      if (e instanceof OidaStateError) {
        const reason = "oida state machine denial: " + String(e.message);
        this.#log(context, "deny", "invalid_state", reason, strategy, null);
        return deny("invalid_state", reason);
      }
      const reason = "strategy evaluation threw: " + String((e as Error).message);
      this.#log(context, "deny", "invalid_input", reason, strategy, null);
      return deny("invalid_input", reason);
    }

    const pinned = pinRecommendation(raw as AlgorithmRecommendation, strategy);
    if (typeof pinned === "string") {
      if (pinned === "__AUTHORITY_VIOLATION__") {
        const reason =
          "strategy '" +
          strategy.id +
          "' attempted to set executionAuthorized on its output; algorithm output can never authorize execution";
        this.#log(context, "deny", "recommendation_not_authoritative", reason, strategy, null);
        return deny("recommendation_not_authoritative", reason);
      }
      const reason = "strategy '" + strategy.id + "' produced invalid output: " + pinned;
      this.#log(context, "deny", "invalid_input", reason, strategy, null);
      return deny("invalid_input", reason);
    }

    const policyEventId = this.#log(context, "allow", "evaluated", "recommendation produced", strategy, pinned);
    return {
      ok: true,
      schemaVersion: "menog-algorithms/v0",
      recommendation: pinned,
      ...(policyEventId !== undefined ? { policyEventId } : {}),
    };
  }

  /**
   * Observable-selection helper: resolves from the registry (deny-by-default
   * via `registry.select`) and evaluates. Selection denials emit a `deny`
   * ledger event when an emitter is attached. This keeps "who ran what"
   * observable without ever making selection output an authority.
   */
  async evaluateSelection(
    registry: { select(family: string, id: string): { ok: true; strategy: StrategyContract } | { ok: false; denyReason: AlgorithmDenyReason; reason: string } },
    family: string,
    id: string,
    input: AlgorithmDecisionInput,
    context: RuntimeContext
  ): Promise<AlgorithmEvaluationResult> {
    const selected = registry.select(family as never, id);
    if (!selected.ok) {
      this.#log(
        context,
        "deny",
        selected.denyReason,
        selected.reason,
        null,
        null
      );
      return { ok: false, denyReason: selected.denyReason, reason: selected.reason };
    }
    return this.evaluate(selected.strategy, input, context);
  }

  #log(
    context: RuntimeContext,
    decision: "allow" | "deny",
    denyReasonOrOutcome: string,
    reason: string,
    strategy: StrategyContract | null,
    recommendation: AlgorithmRecommendation | null
  ): string | undefined {
    if (this.#ledger === null) return undefined;
    const res = this.#ledger.append({
      eventType: decision === "allow" ? "algorithm_recommended" : "algorithm_denied",
      policyDecision: decision,
      actor: { type: context.actor.type, id: context.actor.id },
      workspaceId: context.workspaceId,
      taskId: context.taskId,
      inputSummary: {
        family: strategy?.family ?? "unknown",
        strategyId: strategy?.id ?? "unselected",
        decision: decision === "allow" ? "evaluated" : denyReasonOrOutcome,
        sensitivity: strategy ? "validated" : "not_reached",
      },
      resultSummary: {
        outcome: denyReasonOrOutcome,
        reason,
        strategyId: recommendation?.strategyId ?? null,
        confidence: recommendation?.confidence ?? null,
        rankedCount: recommendation?.rankedCandidates.length ?? 0,
        isRecommendation: true,
        executionAuthorized: false,
      },
    });
    return res.ok && res.eventId !== undefined ? res.eventId : undefined;
  }
}
