import type { Actor } from "@menog/core";

/**
 * Phase 18A — SemantIQ Adapter Contract (SemantIQ V1).
 *
 * SemantIQ is the HOW WELL layer of the Menog verb taxonomy. It is an
 * OPTIONAL, POST-HOC evaluator over the local event ledger (ADR-0007):
 *
 *   - Menog works FULLY with the adapter absent, disabled, or failing;
 *   - the adapter reads events; it never sits inside the execution pipeline;
 *   - evaluation output is non-authoritative DATA for humans — it can never
 *     flip a policy decision, authorize execution, or mutate authoritative
 *     state;
 *   - there is no network, no secrets, no background work anywhere in this
 *     package (verify-local network-invariant stays green).
 *
 * Authority separation (ADR-0007 §Decision 3):
 *
 *   Ledger --read-only--> Adapter --evaluations--> Human review
 *
 *   SemantIQ has NO direct arrow into Policy, Runtime, or Commit.
 */

/** Canonical schema version pinned for the 18A SemantIQ adapter surface. */
export const SEMANTIQ_SCHEMA_VERSION = "menog-semantiq/v0" as const;
export type SemantiqSchemaVersion = typeof SEMANTIQ_SCHEMA_VERSION;

/** Event types this adapter is designed to read (observability surface). */
export type SemantiqEventType =
  | "algorithm_recommended"
  | "algorithm_denied"
  | "verb_executed"
  | "evaluation_requested"
  // 18B: evaluation RESULT events (typed payloads, distinct from runtime
  // authority) joined the observable event-type union.
  | "evaluation_result";

export const KNOWN_SEMANTIQ_EVENT_TYPES: readonly SemantiqEventType[] =
  Object.freeze([
    "algorithm_recommended",
    "algorithm_denied",
    "verb_executed",
    "evaluation_requested",
    "evaluation_result",
  ]);

/** The three explicit lifecycle stages of an evaluation (closed union). */
export type SemantiqStage = "requested" | "computed" | "delivered";

export const SEMANTIQ_STAGES: readonly SemantiqStage[] = Object.freeze([
  "requested",
  "computed",
  "delivered",
]);

/** How an evaluation reached its current stage (observability only). */
export type SemantiqTrigger =
  | "manual"
  | "scheduled"
  | "cli"
  | "event_hook"
  | "unknown";

export const KNOWN_SEMANTIQ_TRIGGERS: readonly SemantiqTrigger[] =
  Object.freeze([
    "manual",
    "scheduled",
    "cli",
    "event_hook",
    "unknown",
  ]);

/**
 * Machine-readable claims an adapter may attach to an evaluation. Closed
 * union: a misbehaving/unknown kind is dropped by the normalizer (fail
 * closed on unknown shapes), never surfaced as a claim.
 */
export type SemantiqClaimKind =
  | "goal_achievement"
  | "metric_delta"
  | "narrative_summary"
  | "regression_indicator"
  | "recommendation_proposal";

export const KNOWN_SEMANTIQ_CLAIM_KINDS: readonly SemantiqClaimKind[] =
  Object.freeze([
    "goal_achievement",
    "metric_delta",
    "narrative_summary",
    "regression_indicator",
    "recommendation_proposal",
  ]);

/**
 * Machine-readable denial reasons for the evaluation stage (fail-closed).
 * Disabled/unconfigured are DISTINCT machine-readable states, not errors.
 */
export type SemantiqDenyReason =
  | "adapter_disabled"
  | "adapter_unconfigured"
  | "adapter_degraded"
  | "invalid_request"
  | "ledger_unavailable"
  | "oversized_request"
  // 18B: two engines delivered conflicting scores for the same dimension and
  // no human resolution exists — the conflict is surfaced, never averaged
  // away silently or resolved by authority.
  | "conflict_unresolved";

export const KNOWN_SEMANTIQ_DENY_REASONS: readonly SemantiqDenyReason[] =
  Object.freeze([
    "adapter_disabled",
    "adapter_unconfigured",
    "adapter_degraded",
    "invalid_request",
    "ledger_unavailable",
    "oversized_request",
    "conflict_unresolved",
  ]);

/** Which authority surface an evaluation is (explicitly, and only, data). */
export type SemantiqAuthority = "advisory_data";

/**
 * Explicit lifecycle states of the adapter (closed union). The adapter is
 * constructed in exactly one of these; state transitions happen only via
 * the returned `lifecycle` record — there is no ambient reconfiguration.
 */
export type SemantiqAdapterState =
  | "disabled"
  | "unconfigured"
  | "degraded"
  | "ready";

/** The normalized, bounded view of one ledger event the adapter consumes. */
export interface SemantiqEventView {
  readonly eventId: string;
  readonly eventType: string;
  readonly actor: { readonly type: string; readonly id: string };
  readonly timestamp: string;
  readonly verb?: string;
  readonly policyDecision?: string;
}

/**
 * The one and only consumer port: a read-only view over the local
 * append-only ledger. Structural (not nominal) so the real
 * `AppendOnlyLedger` satisfies it unchanged — integration WITHOUT bypass.
 * Implementations must fail closed ({ ok:false, ledger_unavailable }).
 */
export interface SemantiqLedgerPort {
  readonly readEvents: (query: {
    readonly limit: number;
  }) =>
    | { readonly ok: true; readonly events: readonly SemantiqEventView[] }
    | { readonly ok: false; readonly denyReason: "ledger_unavailable"; readonly reason: string };
}

/** Minimal ledger-emitter surface (mirrors policy/algorithm emitters). */
export interface SemantiqLedgerEmitter {
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

/** The bounded, structured evaluation request — the SemantIQ analogue of AlgorithmDecisionInput. */
export interface SemantiqEvaluationRequest {
  /** Human-meaningful label of what is being evaluated (bounded). */
  readonly subject: string;
  /** Explicit trigger provenance for observability. */
  readonly trigger: SemantiqTrigger;
  /** Event types the evaluation should read (optional; defaults to all known). */
  readonly eventTypes?: readonly SemantiqEventType[];
  /** Bounded free-text note supplied by the caller (observability only). */
  readonly note?: string;
}

/** One bounded, machine-readable claim inside an evaluation. */
export interface SemantiqClaim {
  readonly kind: SemantiqClaimKind;
  /** Bounded conclusion-only value (e.g. a metric delta or short narrative). */
  readonly value: string;
  /** Deterministic confidence in [0,1]; adapter-pinned for computed claims. */
  readonly confidence: number;
}

/**
 * A delivered evaluation. Deliberately NON-authoritative: `authority` is
 * pinned `advisory_data` on every result and the contract layer refuses any
 * payload that tries to carry an authority claim. An evaluation is DATA for
 * human review; it can never flip a policy decision or authorize execution.
 */
export interface SemantiqEvaluation {
  readonly ok: true;
  readonly schemaVersion: SemantiqSchemaVersion;
  readonly stage: "computed";
  readonly trigger: SemantiqTrigger;
  readonly adapterId: string;
  readonly adapterVersion: string;
  /** Bounded event ids the evaluation was derived from (traceability). */
  readonly derivedFrom: readonly string[];
  readonly claims: readonly SemantiqClaim[];
  /** Bounded human-readable conclusion (never a derivation trace). */
  readonly summary: string;
  /** ALWAYS advisory_data — pinned by the adapter, ignored from the engine. */
  readonly authority: SemantiqAuthority;
  /** ALWAYS false — evaluation output can never carry execution authority. */
  readonly executionAuthorized: false;
  /** Ledger event id of the `evaluation_delivered` record, when emitted. */
  readonly evaluationEventId?: string;
}

/** Machine-readable denial (includes disabled/unconfigured/degraded). */
export interface SemantiqDenial {
  readonly ok: false;
  readonly schemaVersion: SemantiqSchemaVersion;
  readonly stage: SemantiqStage;
  readonly denyReason: SemantiqDenyReason;
  readonly reason: string;
}

/** The full result union returned by `SemantiqAdapterContract.evaluate`. */
export type SemantiqResult = SemantiqEvaluation | SemantiqDenial;

/**
 * The 18A adapter contract. An adapter wraps ONE external evaluation engine
 * (or none). The contract layer (see adapter.ts) wraps ANY engine — trusted
 * or hostile — and guarantees the authority/isolation discipline above.
 */
export interface SemantiqAdapterContract {
  /** Stable adapter id (e.g. "semantiq.manual-briefing"). */
  readonly id: string;
  /** Adapter version (semver string). */
  readonly version: string;
  /** Human-readable description of what the adapter evaluates and how. */
  readonly description: string;
  /** Explicit lifecycle state (closed union, observable). */
  readonly state: SemantiqAdapterState;
  /**
   * Evaluate post-hoc. MUST NOT perform I/O beyond the injected ledger port,
   * MUST NOT mutate policy/runtime/commit state, and MUST be deterministic
   * for identical ledger views.
   */
  evaluate(
    request: SemantiqEvaluationRequest,
    context: SemantiqRuntimeContext
  ): Promise<SemantiqResult>;
}

/** Read-only runtime context handed to adapter invocations. */
export interface SemantiqRuntimeContext {
  readonly actor: Actor;
  readonly workspaceId?: string;
  readonly taskId?: string;
}

/** Type-erased engine surface the contract layer wraps (never trusted). */
export type SemantiqEngine = (
  view: {
    readonly events: readonly SemantiqEventView[];
    readonly request: SemantiqEvaluationRequest;
  }
) =>
  | {
      readonly ok: true;
      readonly claims: readonly SemantiqClaim[];
      readonly summary: string;
    }
  | { readonly ok: false; readonly denyReason: SemantiqDenyReason; readonly reason: string };

/** Observable record of one evaluation lifecycle transition. */
export interface SemantiqLifecycleRecord {
  readonly evaluationId: string;
  readonly stage: SemantiqStage;
  readonly trigger: SemantiqTrigger;
  readonly atEpochMs: number;
  readonly outcome: "delivered" | "denied";
  readonly denyReason?: SemantiqDenyReason;
}

// ---------------------------------------------------------------------------
// Phase 18B — Evaluation Event Model (typed event schemas + provenance).
//
// Evaluation REQUEST / RESULT / DENIED events are typed, bounded, provance-
// carrying records ABOUT the HOW WELL layer. They are a SEPARATE event
// family from ledger execution facts (ADR-0007 §Decision 5: evaluations are
// NOT events — they may be recorded NEXT TO the ledger and must never
// rewrite or shadow it). Every event payload re-states, and is pinned to,
// the non-authoritative discipline: `authority: "advisory_data"` and
// `executionAuthorized: false` on every valid event, re-stamped by the
// builder regardless of caller input.
// ---------------------------------------------------------------------------

/**
 * The four evaluation dimensions of the 18B event model (closed union):
 * plan quality, task completion, policy compliance, reproducibility.
 */
export type SemantiqEvaluationDimension =
  | "plan_quality"
  | "task_completion"
  | "policy_compliance"
  | "reproducibility";

export const SEMANTIQ_EVALUATION_DIMENSIONS: readonly SemantiqEvaluationDimension[] =
  Object.freeze([
    "plan_quality",
    "task_completion",
    "policy_compliance",
    "reproducibility",
  ]);

export function isSemantiqEvaluationDimension(
  value: unknown
): value is SemantiqEvaluationDimension {
  return (
    typeof value === "string" &&
    (SEMANTIQ_EVALUATION_DIMENSIONS as readonly string[]).includes(value)
  );
}

/** Who/what produced an evaluation event's content (closed union). */
export type SemantiqProvenanceSource =
  | "human"
  | "engine"
  | "derived_from_ledger"
  | "mixed";

export const SEMANTIQ_PROVENANCE_SOURCES: readonly SemantiqProvenanceSource[] =
  Object.freeze(["human", "engine", "derived_from_ledger", "mixed"]);

/**
 * One bounded per-dimension score. Scores are deterministic discrete steps
 * in [0,1] (see events.ts SEMANTIQ_SCORES) so equal inputs always produce
 * byte-identical events, and conflict detection has exact arithmetic.
 */
export interface SemantiqDimensionScore {
  readonly dimension: SemantiqEvaluationDimension;
  /** Score in [0,1] on the pinned discrete step grid. */
  readonly score: number;
  /** Deterministic confidence in [0,1]. */
  readonly confidence: number;
  /** Bounded conclusion-only rationale (never a derivation trace). */
  readonly rationale?: string;
}

/** Persisted provenance for an evaluation event (bounded, frozen). */
export interface SemantiqEvaluationProvenance {
  /** Which authority class produced the content (closed union). */
  readonly source: SemantiqProvenanceSource;
  /** Bounded engine/adapter identifier, when machine-produced. */
  readonly engineId?: string;
  /** Bounded engine version, when machine-produced. */
  readonly engineVersion?: string;
  /** Bounded human reviewer identifier, when human-produced. */
  readonly reviewerId?: string;
  /** Bounded actor identifier the event is attributed to. */
  readonly actorId: string;
  /** Bounded actor type the event is attributed to. */
  readonly actorType: string;
  /** Ledger event ids the content was derived from (bounded, may be empty). */
  readonly derivedFrom: readonly string[];
  /** Bounded free-text provenance note. */
  readonly note?: string;
}

/** The three kinds of typed evaluation event (closed union). */
export type SemantiqEvaluationEventKind = "request" | "result" | "denied";

/** Verdict carried by a result event (closed union; distinct from policy). */
export type SemantiqEvaluationVerdict =
  | "pass"
  | "borderline"
  | "fail"
  | "indeterminate";

export const SEMANTIQ_EVALUATION_VERDICTS: readonly SemantiqEvaluationVerdict[] =
  Object.freeze(["pass", "borderline", "fail", "indeterminate"]);

/** A typed evaluation REQUEST event (no scores, no verdict). */
export interface SemantiqEvaluationRequestEvent {
  readonly kind: "request";
  readonly schemaVersion: SemantiqSchemaVersion;
  readonly subject: string;
  readonly trigger: SemantiqTrigger;
  readonly requestedAtEpochMs: number;
  /** Requests carry no scores — enforced by type (never[]) and validator. */
  readonly dimensions: readonly never[];
  readonly verdict: "indeterminate";
  readonly provenance: SemantiqEvaluationProvenance;
  /** ALWAYS advisory_data — evaluation events are never authority. */
  readonly authority: SemantiqAuthority;
  /** ALWAYS false — pinned by the builder. */
  readonly executionAuthorized: false;
}

/** A typed evaluation RESULT event (scores + verdict + provenance). */
export interface SemantiqEvaluationResultEvent {
  readonly kind: "result";
  readonly schemaVersion: SemantiqSchemaVersion;
  readonly subject: string;
  readonly trigger: SemantiqTrigger;
  readonly evaluatedAtEpochMs: number;
  /** One score per evaluated dimension (1..4; at least one required). */
  readonly dimensions: readonly SemantiqDimensionScore[];
  /** Verdict for human review — NEVER a policy decision or permission. */
  readonly verdict: SemantiqEvaluationVerdict;
  readonly provenance: SemantiqEvaluationProvenance;
  readonly authority: SemantiqAuthority;
  readonly executionAuthorized: false;
}

/** A typed evaluation DENIED event (machine-readable, no scores). */
export interface SemantiqEvaluationDeniedEvent {
  readonly kind: "denied";
  readonly schemaVersion: SemantiqSchemaVersion;
  readonly subject: string;
  readonly trigger: SemantiqTrigger;
  readonly deniedAtEpochMs: number;
  /** Denials carry no scores — enforced by type (never[]) and validator. */
  readonly dimensions: readonly never[];
  readonly verdict: "indeterminate";
  readonly denyReason: SemantiqDenyReason;
  readonly reason: string;
  readonly provenance: SemantiqEvaluationProvenance;
  readonly authority: SemantiqAuthority;
  readonly executionAuthorized: false;
}

export type SemantiqEvaluationEvent =
  | SemantiqEvaluationRequestEvent
  | SemantiqEvaluationResultEvent
  | SemantiqEvaluationDeniedEvent;

/** A persisted, hash-anchored evaluation event record. */
export interface SemantiqEvaluationRecord {
  readonly recordId: string;
  readonly eventId: string;
  readonly createdAtEpochMs: number;
  readonly event: SemantiqEvaluationEvent;
  /** SHA-256 of the canonical event serialization (integrity anchor). */
  readonly contentHash: string;
}
