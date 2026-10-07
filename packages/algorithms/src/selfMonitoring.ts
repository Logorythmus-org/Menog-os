import type {
  AdaptationProposal,
  AlgorithmDecisionInput,
  AlgorithmRecommendation,
  MetricFeedbackPort,
  MonitorMetric,
  ParameterBounds,
  ParameterSensitivity,
  RuntimeContext,
  StrategyContract,
  TunableParameterState,
} from "./types.js";
import {
  ALGORITHM_MAX_METRICS,
  ALGORITHM_MAX_METRIC_NAME_CHARS,
  ALGORITHM_MAX_PARAMETER_HISTORY,
  ALGORITHM_MAX_PARAMETER_MAGNITUDE,
  ALGORITHM_MAX_TUNABLE_PARAMETERS,
} from "./types.js";

/**
 * Phase 17D — bounded self-monitoring & adaptation (family 10 upgrade).
 *
 * Hard boundaries (all test-pinned):
 *  - MONITOR:   metrics are OBSERVABLE data supplied by the caller or read
 *               through a structural `MetricFeedbackPort` (e.g. over 16B
 *               execution memory). No hidden background collection, no
 *               timers, no I/O of its own.
 *  - ADAPT:     parameter values move ONLY within human-registered bounds
 *               (`ParameterBounds`); out-of-bounds adaptation is denied with
 *               `adaptation_out_of_bounds`. Values are finite and magnitude-
 *               clamped. Bounds themselves are NEVER adaptable by the
 *               runtime — tightening/loosening bounds is a human step.
 *  - NO SOURCE  MUTATION: adaptation targets ONLY registered tunable
 *               parameters (runtime values). The store exposes no method
 *               that can write files, evaluate code, or alter source/config;
 *               proposals never self-apply — application is an explicit,
 *               audited, caller-owned step.
 *  - AUDIT:     every applied adaptation is a frozen, observable change
 *               record; `rollback` restores the previous value and is itself
 *               recorded. Change history is bounded.
 */

/** One audited parameter change record (17D). */
export interface ParameterChangeRecord {
  readonly parameter: string;
  readonly fromValue: number;
  readonly toValue: number;
  readonly reason: string;
  readonly revision: number;
  /** "adapt" = forward adaptation; "rollback" = revert of a previous change. */
  readonly kind: "adapt" | "rollback";
}

export interface AdaptiveParameterStoreOptions {
  /** Optional audit sink; when absent, changes are still recorded in-memory. */
  readonly audit?: (record: ParameterChangeRecord) => void;
}

interface MutableParameter {
  name: string;
  value: number;
  bounds: ParameterBounds;
  sensitivity: ParameterSensitivity;
  revision: number;
  history: ParameterChangeRecord[];
  /** Undo stack of pre-change values; rollback pops one entry per step. */
  undo: number[];
}

function clampMagnitude(v: number): number {
  if (!Number.isFinite(v)) return 0;
  return Math.max(-ALGORITHM_MAX_PARAMETER_MAGNITUDE, Math.min(ALGORITHM_MAX_PARAMETER_MAGNITUDE, v));
}

/**
 * The audited, bounded store of tunable runtime parameters (17D).
 * Registration (with bounds) is the POLICY step; adaptation is bounded by
 * those registered bounds forever. No source/config mutation surface exists.
 */
export class AdaptiveParameterStore {
  readonly #params = new Map<string, MutableParameter>();
  readonly #order: string[] = [];
  readonly #audit: ((record: ParameterChangeRecord) => void) | null;

  constructor(options: AdaptiveParameterStoreOptions = {}) {
    this.#audit = options.audit ?? null;
  }

  /**
   * Register (or re-register bounds for) a tunable parameter. Registration
   * is the POLICY step: bounds come from humans/config, never from
   * adaptation. Re-registration keeps the current value but replaces the
   * bounds — intentionally a caller-owned policy action, audited as such.
   */
  register(
    name: string,
    initialValue: number,
    bounds: ParameterBounds,
    sensitivity: ParameterSensitivity = "performance"
  ): { ok: true; state: TunableParameterState } | { ok: false; reason: string } {
    if (typeof name !== "string" || name.length === 0 || name.length > ALGORITHM_MAX_METRIC_NAME_CHARS) {
      return { ok: false, reason: "parameter name must be a non-empty string of at most " + String(ALGORITHM_MAX_METRIC_NAME_CHARS) + " chars" };
    }
    if (!/^[a-zA-Z][a-zA-Z0-9_.-]*$/.test(name)) {
      return { ok: false, reason: "parameter name must match [a-zA-Z][a-zA-Z0-9_.-]*" };
    }
    if (typeof initialValue !== "number" || !Number.isFinite(initialValue)) {
      return { ok: false, reason: "initialValue must be a finite number" };
    }
    if (
      bounds === null || typeof bounds !== "object" ||
      typeof bounds.min !== "number" || !Number.isFinite(bounds.min) ||
      typeof bounds.max !== "number" || !Number.isFinite(bounds.max) ||
      bounds.min > bounds.max
    ) {
      return { ok: false, reason: "bounds must be finite numbers with min <= max" };
    }
    if (
      sensitivity !== "performance" && sensitivity !== "threshold" && sensitivity !== "scheduling"
    ) {
      return { ok: false, reason: "sensitivity must be performance | threshold | scheduling" };
    }
    if (!this.#params.has(name) && this.#params.size >= ALGORITHM_MAX_TUNABLE_PARAMETERS) {
      return { ok: false, reason: "parameter store is full (max " + String(ALGORITHM_MAX_TUNABLE_PARAMETERS) + ")" };
    }

    const existing = this.#params.get(name);
    const param: MutableParameter = existing ?? {
      name,
      value: 0,
      bounds,
      sensitivity,
      revision: 0,
      history: [],
      undo: [],
    };
    param.bounds = { min: clampMagnitude(bounds.min), max: clampMagnitude(bounds.max) };
    param.sensitivity = sensitivity;
    if (existing === undefined) {
      param.value = clampMagnitude(initialValue);
      // Initial value must respect the registered bounds (clamped in).
      param.value = Math.max(param.bounds.min, Math.min(param.bounds.max, param.value));
      this.#params.set(name, param);
      this.#order.push(name);
    }
    return { ok: true, state: this.snapshot(param) };
  }

  /** Observable snapshot of one parameter; null when unknown. */
  get(name: string): TunableParameterState | null {
    const p = this.#params.get(name);
    return p ? this.snapshot(p) : null;
  }

  /** All parameter snapshots, in registration order (frozen). */
  list(): readonly TunableParameterState[] {
    const out: TunableParameterState[] = [];
    for (const name of this.#order) {
      const p = this.#params.get(name);
      if (p) out.push(this.snapshot(p));
    }
    return Object.freeze(out);
  }

  /**
   * Apply an adaptation proposal: bounded, audited, reversible. Denies with
   * `parameter_unknown` / `adaptation_out_of_bounds` (machine-readable).
   */
  apply(
    proposal: AdaptationProposal
  ): { ok: true; state: TunableParameterState; record: ParameterChangeRecord } | { ok: false; reason: string } {
    const p = this.#params.get(proposal.parameter);
    if (!p) {
      return { ok: false, reason: "parameter_unknown: '" + proposal.parameter + "' is not registered" };
    }
    if (typeof proposal.proposedValue !== "number" || !Number.isFinite(proposal.proposedValue)) {
      return { ok: false, reason: "proposedValue must be a finite number" };
    }
    // Bounds are checked against the REGISTERED bounds, not the proposal's
    // claimed bounds — a lying proposal cannot move the goalposts.
    if (
      proposal.proposedValue < p.bounds.min ||
      proposal.proposedValue > p.bounds.max
    ) {
      return {
        ok: false,
        reason:
          "adaptation_out_of_bounds: proposed " +
          String(proposal.proposedValue) +
          " outside registered bounds [" +
          String(p.bounds.min) + ", " + String(p.bounds.max) +
          "] for '" + proposal.parameter + "'",
      };
    }
    const value = clampMagnitude(proposal.proposedValue);
    const record: ParameterChangeRecord = Object.freeze({
      parameter: p.name,
      fromValue: p.value,
      toValue: value,
      reason: typeof proposal.reason === "string" ? proposal.reason.slice(0, 256) : "",
      revision: p.revision + 1,
      kind: "adapt",
    });
    p.undo.push(p.value);
    p.value = value;
    p.revision += 1;
    p.history.push(record);
    if (p.history.length > ALGORITHM_MAX_PARAMETER_HISTORY) {
      p.history.splice(0, p.history.length - ALGORITHM_MAX_PARAMETER_HISTORY);
    }
    this.#audit?.(record);
    return { ok: true, state: this.snapshot(p), record };
  }

  /**
   * Roll back ONE change to a parameter by walking the undo stack backwards
   * step by step (rollback-of-rollback never re-applies — it keeps walking
   * to the pre-change value). The rollback itself is recorded (kind:
   * "rollback"). Denies when the parameter is unknown or has no remaining
   * undo entries (`rollback_target_missing`).
   */
  rollback(
    name: string
  ): { ok: true; state: TunableParameterState; record: ParameterChangeRecord } | { ok: false; reason: string } {
    const p = this.#params.get(name);
    if (!p) {
      return { ok: false, reason: "parameter_unknown: '" + name + "' is not registered" };
    }
    const previous = p.undo.pop();
    if (previous === undefined) {
      return { ok: false, reason: "rollback_target_missing: '" + name + "' has no recorded changes to undo" };
    }
    const record: ParameterChangeRecord = Object.freeze({
      parameter: p.name,
      fromValue: p.value,
      toValue: previous,
      reason: "rollback to pre-change value (revision " + String(p.revision) + ")",
      revision: p.revision + 1,
      kind: "rollback",
    });
    p.value = previous;
    p.revision += 1;
    p.history.push(record);
    if (p.history.length > ALGORITHM_MAX_PARAMETER_HISTORY) {
      p.history.splice(0, p.history.length - ALGORITHM_MAX_PARAMETER_HISTORY);
    }
    this.#audit?.(record);
    return { ok: true, state: this.snapshot(p), record };
  }

  /** Change history for one parameter (frozen copy, bounded). */
  historyOf(name: string): readonly ParameterChangeRecord[] {
    const p = this.#params.get(name);
    return p ? Object.freeze([...p.history]) : Object.freeze([]);
  }

  private snapshot(p: MutableParameter): TunableParameterState {
    return Object.freeze({
      name: p.name,
      value: p.value,
      bounds: Object.freeze({ ...p.bounds }),
      sensitivity: p.sensitivity,
      revision: p.revision,
    });
  }
}

/**
 * Bounded-validation helper for the metric-feedback input (17D). Returns an
 * error string or null. Metrics must be finite (no NaN/Infinity poisoning
 * the adaptation derivation) and bounded in count/name length.
 */
export function validateMetricsInput(
  input: AlgorithmDecisionInput
): string | null {
  const metrics = input.metrics;
  if (metrics === undefined) return null;
  if (!Array.isArray(metrics)) return "metrics must be an array when present";
  if (metrics.length > ALGORITHM_MAX_METRICS) {
    return (
      "metrics has " +
      String(metrics.length) +
      " entries which exceeds ALGORITHM_MAX_METRICS (" +
      String(ALGORITHM_MAX_METRICS) +
      ")"
    );
  }
  for (let i = 0; i < metrics.length; i++) {
    const m = metrics[i] as MonitorMetric | undefined;
    if (m === null || typeof m !== "object") {
      return "metrics[" + String(i) + "] must be an object";
    }
    if (typeof m.name !== "string" || m.name.length === 0) {
      return "metrics[" + String(i) + "].name must be a non-empty string";
    }
    if (m.name.length > ALGORITHM_MAX_METRIC_NAME_CHARS) {
      return (
        "metrics[" +
        String(i) +
        "].name exceeds ALGORITHM_MAX_METRIC_NAME_CHARS (" +
        String(ALGORITHM_MAX_METRIC_NAME_CHARS) +
        ")"
      );
    }
    if (typeof m.value !== "number" || !Number.isFinite(m.value)) {
      return "metrics[" + String(i) + "].value must be a finite number";
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Adaptation derivation: metrics → bounded proposal (pure, deterministic)
// ---------------------------------------------------------------------------

/** Default registered parameters and their POLICY bounds (17D). */
export const DEFAULT_TUNABLE_PARAMETERS: readonly {
  readonly name: string;
  readonly initialValue: number;
  readonly bounds: ParameterBounds;
  readonly sensitivity: ParameterSensitivity;
}[] = Object.freeze([
  { name: "retrieval.limit", initialValue: 10, bounds: { min: 1, max: 100 }, sensitivity: "performance" },
  { name: "risk.confidenceFloor", initialValue: 0.5, bounds: { min: 0, max: 1 }, sensitivity: "threshold" },
  { name: "monitor.sampleRatio", initialValue: 1, bounds: { min: 0, max: 1 }, sensitivity: "scheduling" },
]);

/** Metric names consumed by the default derivation. */
export const METRIC_DENY_RATIO = "deny_ratio";
export const METRIC_FAILURE_RATIO = "failure_ratio";
export const METRIC_SUCCESS_RATIO = "success_ratio";

/**
 * Derive a bounded adaptation proposal from observable metrics.
 * Deterministic policy (conclusion in the proposal, arithmetic here):
 *  - high deny_ratio  (> 0.5) ⇒ lower risk.confidenceFloor slightly (fewer
 *    borderline risk escalations for human review);
 *  - high failure_ratio (> 0.5) ⇒ shrink retrieval.limit (reduce noise);
 *  - high success_ratio (> 0.9) ⇒ grow retrieval.limit slightly (more context);
 *  - otherwise: no adaptation proposed (null).
 * All proposals are clamped INTO the registered bounds by the store on apply.
 */
export function deriveAdaptationProposal(
  metrics: readonly MonitorMetric[],
  store: AdaptiveParameterStore
): AdaptationProposal | null {
  const byName = new Map<string, number>();
  for (const m of metrics) {
    if (typeof m?.name === "string" && typeof m?.value === "number" && Number.isFinite(m.value)) {
      byName.set(m.name, m.value);
    }
  }

  const deny = byName.get(METRIC_DENY_RATIO);
  const failure = byName.get(METRIC_FAILURE_RATIO);
  const success = byName.get(METRIC_SUCCESS_RATIO);

  if (deny !== undefined && deny > 0.5) {
    const cur = store.get("risk.confidenceFloor");
    if (cur && cur.value > cur.bounds.min) {
      const proposed = Math.max(cur.bounds.min, Math.round((cur.value - 0.05) * 100) / 100);
      return {
        parameter: "risk.confidenceFloor",
        currentValue: cur.value,
        proposedValue: proposed,
        bounds: cur.bounds,
        reason: "deny_ratio " + String(Math.round(deny * 100) / 100) + " above 0.5; lower confidence floor within bounds",
      };
    }
  }
  if (failure !== undefined && failure > 0.5) {
    const cur = store.get("retrieval.limit");
    if (cur && cur.value > cur.bounds.min) {
      const proposed = Math.max(cur.bounds.min, cur.value - 1);
      return {
        parameter: "retrieval.limit",
        currentValue: cur.value,
        proposedValue: proposed,
        bounds: cur.bounds,
        reason: "failure_ratio " + String(Math.round(failure * 100) / 100) + " above 0.5; shrink retrieval limit within bounds",
      };
    }
  }
  if (success !== undefined && success > 0.9) {
    const cur = store.get("retrieval.limit");
    if (cur && cur.value < cur.bounds.max) {
      const proposed = Math.min(cur.bounds.max, cur.value + 1);
      return {
        parameter: "retrieval.limit",
        currentValue: cur.value,
        proposedValue: proposed,
        bounds: cur.bounds,
        reason: "success_ratio " + String(Math.round(success * 100) / 100) + " above 0.9; grow retrieval limit within bounds",
      };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// MetricFeedbackPort adapters (structural integration, no package coupling)
// ---------------------------------------------------------------------------

/**
 * Adapt 16B execution-memory-style query stats into a `MetricFeedbackPort`.
 * The stats surface is structural: `{ ok, byOutcome: {success, failure, denied}, total }`.
 */
export function executionStatsFeedbackPort(
  queryStats: () => {
    ok: boolean;
    byOutcome?: { success?: number; failure?: number; denied?: number };
    total?: number;
  }
): MetricFeedbackPort {
  return {
    async collect() {
      const raw: unknown = queryStats();
      const s = raw as {
        ok: boolean;
        byOutcome?: { success?: number; failure?: number; denied?: number };
        total?: number;
      };
      if (typeof s !== "object" || s === null || s.ok !== true) {
        return { ok: false, denyReason: "invalid_input", reason: "execution stats unavailable" };
      }
      const total = typeof s.total === "number" && s.total > 0 ? s.total : 0;
      if (total === 0) {
        return { ok: true, metrics: Object.freeze<MonitorMetric[]>([]) };
      }
      const success = s.byOutcome?.success ?? 0;
      const failure = s.byOutcome?.failure ?? 0;
      const denied = s.byOutcome?.denied ?? 0;
      return {
        ok: true,
        metrics: Object.freeze([
          { name: METRIC_SUCCESS_RATIO, value: success / total },
          { name: METRIC_FAILURE_RATIO, value: failure / total },
          { name: METRIC_DENY_RATIO, value: denied / total },
        ]),
      };
    },
  };
}

// ---------------------------------------------------------------------------
// Family 10 strategy upgrade: monitor.observe-metrics@0.2.0
// ---------------------------------------------------------------------------

function boundedSummary(s: string): string {
  return s.length > 256 ? s.slice(0, 256) : s;
}

/**
 * Core evaluation: metric observation + at-most-one bounded proposal,
 * parameterized by the store proposals are derived against.
 */
async function evaluateObserveMetrics(
  input: AlgorithmDecisionInput,
  store: AdaptiveParameterStore,
  _context: RuntimeContext
): Promise<AlgorithmRecommendation> {
  void _context;
  const metrics = input.metrics ?? [];

  // Rank metrics by salience (deviation-style deterministic ordering):
  // higher |value| first, then name asc — stable and reproducible.
  const salient = [...metrics].sort((a, b) => {
    const da = Math.abs(a.value);
    const db = Math.abs(b.value);
    if (da !== db) return db - da;
    return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  });
  const ranked = salient.map((m) => m.name + "=" + String(Math.round(m.value * 1000) / 1000));

  // One bounded proposal, derived deterministically. The proposal is DATA;
  // the caller decides whether to apply it through the audited store.
  const proposal = deriveAdaptationProposal(metrics, store);

  return {
    family: "self_monitoring_adaptation",
    strategyId: "observe-metrics",
    rankedCandidates: ranked,
    confidence: metrics.length > 0 ? 0.85 : 0.5,
    rationale:
      metrics.length > 0
        ? "bounded metric observation; any adaptation proposal is data for human review and moves within registered bounds only"
        : "no metrics supplied; honest empty observation (17A fallback semantics)",
    isRecommendation: true,
    executionAuthorized: false,
    reasoningSummary: boundedSummary(
      metrics.length > 0
        ? "observed " + String(metrics.length) + " metric(s)" + (proposal ? "; proposal ready for human review: " + proposal.parameter : "; no adaptation warranted")
        : "no metrics observed"
    ),
    ...(proposal ? { adaptationProposal: proposal } : {}),
  };
}

/**
 * `self-monitoring.observe-metrics@0.2.0` — bounded metric-driven
 * self-monitoring. Observes caller-supplied observable metrics, ranks
 * findings for human review, and attaches at most ONE bounded adaptation
 * proposal (derived against the global default store). It NEVER self-applies
 * proposals, NEVER mutates source/config, and NEVER escalates its own
 * authority. Fallback: no metrics ⇒ honest empty observation.
 */
export const selfMonitoringMetricObserve: StrategyContract = Object.freeze({
  id: "observe-metrics",
  family: "self_monitoring_adaptation",
  version: "0.2.0",
  implemented: true,
  description:
    "bounded metric-driven self-monitoring: ranks metric findings for human review and proposes at most one in-bounds parameter adaptation; proposals never self-apply; no source mutation",
  async evaluate(
    input: AlgorithmDecisionInput,
    context: RuntimeContext
  ): Promise<AlgorithmRecommendation> {
    return evaluateObserveMetrics(input, globalDefaultStore, context);
  },
});

/**
 * Process-wide default store used by the strategy when the caller does not
 * supply one via `buildSelfMonitoringStrategy`. Registered with the DEFAULT
 * POLICY BOUNDS; callers can build isolated stores instead.
 */
export const globalDefaultStore: AdaptiveParameterStore = new AdaptiveParameterStore();
for (const p of DEFAULT_TUNABLE_PARAMETERS) {
  globalDefaultStore.register(p.name, p.initialValue, p.bounds, p.sensitivity);
}

/**
 * Build the metric-observe strategy bound to a SPECIFIC store + optional
 * feedback port (isolated testing / per-workspace tuning).
 */
export function buildSelfMonitoringStrategy(
  store: AdaptiveParameterStore,
  port?: MetricFeedbackPort
): StrategyContract {
  return Object.freeze({
    id: "observe-metrics",
    family: "self_monitoring_adaptation",
    version: "0.2.0",
    implemented: true,
    description: selfMonitoringMetricObserve.description,
    async evaluate(
      input: AlgorithmDecisionInput,
      context: RuntimeContext
    ): Promise<AlgorithmRecommendation> {
      let metrics = input.metrics;
      if (metrics === undefined && port !== undefined) {
        const collected = await port.collect();
        if (!collected.ok) {
          // Fail-closed: port denial is data starvation, not fabrication.
          metrics = [];
        } else {
          metrics = collected.metrics;
        }
      }
      return evaluateObserveMetrics({ ...input, metrics }, store, context);
    },
  });
}

// 17A strategy retained for fallback semantics inside this module.
export const selfMonitoringOutcomeRecordCompat = {
  id: "outcome-record",
  version: "0.1.0",
} as const;
