/**
 * PHASE 23A — Runtime Continuity Model & Live/Durable Authority Contract
 * (CONTRACT-FIRST / NO LIVE WIRING).
 *
 * This module defines WHAT it means for one local runtime to be the single
 * live owner of a durable store, how live-visible work becomes durable
 * work, and how a restarted runtime may be explicitly handed the recovered
 * state. It implements NO wiring: no store access, no coordinator, no
 * lifecycle runner, no process supervision. 23B wires a coordinator ON TOP
 * of these contracts and inherits every law below; nothing here calls the
 * store, the launcher, the policy engine, or the planner.
 *
 * Central Phase-23 statement (extends, never relaxes, the Phase-22 one):
 *
 *     durable state ≠ execution authority ≠ Policy authorization
 *                    ≠ executable replay
 *     acknowledged-to-the-user ≠ durably committed
 *
 * The 23A laws, each structurally enforced below and pinned by contract
 * tests:
 *
 *  L1  persistence grants no execution authority; only a LIVE runtime may
 *      request execution, and only through the frozen authority vocabulary
 *      (Planner → Allocation → Policy → Isolation → Governed Tool Runtime).
 *  L2  recovered state reuses no Policy authority; recovery admission
 *      always ends at RECOVERED, and LIVE requires an explicit, evidenced
 *      epoch transition.
 *  L3  terminal and quarantined facts cannot resurrect; this contract adds
 *      no resurrection surface and forbids the coordinator from building
 *      one (the recovery decision admits records as recovered_data only).
 *  L4  no durability acknowledgement before durable confirmation: a
 *      mutation may only reach `acknowledged` through a DurabilityBarrier
 *      whose commitSequence is present and monotone (the barrier is a
 *      future store/callback result; nothing fabricates it here).
 *  L5  ambiguous ownership and stale epochs fail closed: an epoch id is
 *      mandatory, checked against the durable claim, and every decision
 *      carries the epoch it was made in so stale decisions are detectable.
 *  L6  recovery → live is explicit and evidenced: the machine path is
 *      BOOTING → RECOVERING → READY → LIVE; READY is never skipped; RECOVERED
 *      → LIVE requires the 22E recovery decision reference.
 *  L7  no auto-resume: interruption never re-enters a live execution path;
 *      interrupted work re-enters only as non-authoritative recovered work
 *      re-planned through the normal junction.
 *  L8  derived state is non-authoritative: derived kinds cannot appear in
 *      a live/durable mutation or a continuity admission at all.
 *  L9  executable replay stays out of scope: no vocabulary here requests
 *      re-execution; evidence replay planning remains the 21E/22G
 *      non-executing discipline.
 */

import type {
  CommitSequence,
  DurableRecordId,
  RecordKind,
} from "./records.js";
import type { RecoveryDecision } from "./recovery.js";

// ── schema versions ──────────────────────────────────────────────────────────

/** Continuity contract version: bumped when THIS vocabulary changes.
 *  v1 (23D): the pack-mandated explicit RECONCILED state between RECOVERING
 *  and READY, the recovery_reconciled reason, and the handoff_evidence
 *  evidence kind for the evidenced LIVE transition.
 */
export const CONTINUITY_SCHEMA_VERSION = "menog-runtime-continuity/v1" as const;
export type ContinuitySchemaVersion = typeof CONTINUITY_SCHEMA_VERSION;

/** Runtime epoch (ownership lease) record version. */
export const RUNTIME_EPOCH_SCHEMA_VERSION = "menog-runtime-epoch/v0" as const;
export type RuntimeEpochSchemaVersion = typeof RUNTIME_EPOCH_SCHEMA_VERSION;

// ── runtime lifecycle (closed machine; no hidden states) ─────────────────────

/**
 * The complete lifecycle of one runtime process with respect to the
 * durable store:
 *
 *   BOOTING     process started; nothing durable has been read yet
 *   RECOVERING  22E startup recovery is running (or a fresh store was
 *               detected); no state is exposed to live surfaces yet
 *   RECONCILED  the frozen recovery produced its decision; findings are
 *               classified (hard/quarantine findings block LIVE) and the
 *               NEW runtime epoch is admitted — still NO live exposure
 *   READY       recovery decision accepted; recovered state exposed as
 *               recovered_data; NO live execution surface is open
 *   LIVE        the single live owner; execution requests may be made
 *               through the normal authority chain
 *   RECOVERED   a LIVE runtime lost the durable store (or was restarted);
 *               everything visible is now recovered data; the process is
 *               NOT authoritative and MUST re-traverse RECOVERING
 *
 * BOOTING, RECOVERING, RECONCILED and RECOVERED are non-living states: they
 * may not issue continuity decisions or durability barriers. Only LIVE may.
 */
export const RUNTIME_LIFECYCLE_STATES = Object.freeze([
  "BOOTING",
  "RECOVERING",
  "RECONCILED",
  "READY",
  "LIVE",
  "RECOVERED",
] as const);
export type RuntimeLifecycleState = (typeof RUNTIME_LIFECYCLE_STATES)[number];

export function isRuntimeLifecycleState(value: unknown): value is RuntimeLifecycleState {
  return (
    typeof value === "string" &&
    (RUNTIME_LIFECYCLE_STATES as readonly string[]).includes(value)
  );
}

/** Why a lifecycle transition is happening (closed union). */
export const RUNTIME_LIFECYCLE_REASONS = Object.freeze([
  "process_start",              // → BOOTING
  "fresh_store_detected",       // → RECOVERING (no store existed)
  "recovery_started",           // → RECOVERING
  "recovery_reconciled",        // → RECONCILED (23D: decision in hand, findings classified)
  "recovery_decision_ready",    // → READY (decision carried in evidence)
  "recovery_bootstrap_rejected",// → RECOVERED (22E did not admit state)
  "lifecycle_transition",       // → LIVE (explicit; evidence carried)
  "barrier_lost",               // → RECOVERED (store/persistence failed)
  "store_unavailable",          // → RECOVERED
  "explicit_shutdown",          // → RECOVERED
  "operator_pause",             // → RECOVERED
] as const);
export type RuntimeLifecycleReason = (typeof RUNTIME_LIFECYCLE_REASONS)[number];

/**
 * The ONLY transitions the machine permits. The transition table is total:
 * every other (from, to) pair is unrepresentable in decision functions
 * below. READY is never skipped on the path to LIVE, and a runtime in
 * RECOVERED re-enters through RECOVERING — never directly to LIVE.
 */
export const RUNTIME_TRANSITIONS: Readonly<
  Record<RuntimeLifecycleState, readonly RuntimeLifecycleState[]>
> = Object.freeze({
  BOOTING: Object.freeze(["RECOVERING"] as const),
  RECOVERING: Object.freeze(["RECONCILED", "RECOVERED"] as const),
  RECONCILED: Object.freeze(["READY", "RECOVERED"] as const),
  READY: Object.freeze(["LIVE"] as const),
  LIVE: Object.freeze(["RECOVERED"] as const),
  RECOVERED: Object.freeze(["RECOVERING"] as const),
});

export function isRuntimeTransition(
  from: RuntimeLifecycleState,
  to: RuntimeLifecycleState
): boolean {
  return (RUNTIME_TRANSITIONS[from] as readonly string[]).includes(to);
}

// ── runtime epoch identity ───────────────────────────────────────────────────

/**
 * RuntimeEpochId: identity of ONE live-owner incarnation of the runtime
 * over one store. Generated fresh at every process start; never reused
 * across restarts. Opaque, bounded, monotone-mixing (timestamp + random)
 * — it is an identity token, not a parseable structure.
 */
export type RuntimeEpochId = string;

export const RUNTIME_EPOCH_ID_PATTERN = /^re-[0-9a-f]{12}-[a-zA-Z0-9]{16}$/;

/**
 * Pure epoch-id factory (injectable clock/randomness; deterministic in
 * tests). NOT called by any runtime wiring in this gate.
 */
export function makeRuntimeEpochId(nowEpochMs: number, randomness: string): RuntimeEpochId {
  const t = Number.isFinite(nowEpochMs) && nowEpochMs > 0 ? Math.floor(nowEpochMs) : 0;
  const ts = t.toString(16).padStart(12, "0").slice(-12);
  const rnd = randomness.replace(/[^a-zA-Z0-9]/g, "").padEnd(16, "0").slice(0, 16);
  return `re-${ts}-${rnd}`;
}

/** Why an epoch STARTED relative to a prior owner (closed union). */
export const RUNTIME_EPOCH_END_REASONS = Object.freeze([
  "fresh_store_no_prior_owner",
  "prior_owner_released",
  "prior_owner_expired",
] as const);
export type RuntimeEpochEndReason = (typeof RUNTIME_EPOCH_END_REASONS)[number];

/** What the durable layer said about a previous owner (closed union). */
export const RUNTIME_EPOCH_PRIOR_OWNER_CODES = Object.freeze([
  "none",
  "same_epoch_id",
  "live_claim_present",
  "stale_claim_present",
  "unverifiable",
] as const);
export type RuntimeEpochPriorOwnerCode =
  (typeof RUNTIME_EPOCH_PRIOR_OWNER_CODES)[number];

/**
 * The decision that opens an epoch (BOOTING admission). Fail-closed by
 * construction: an epoch id MUST be present and MUST be fresh; a fresh
 * store refuses a declared (carried-over) epoch id; a store with a LIVE
 * claim from another id is refused (split-brain refusal).
 */
export const RUNTIME_BOOTSTRAP_DECISION_CODES = Object.freeze([
  "epoch_opened",
  "epoch_refused_stale",
  "epoch_refused_mismatch",
  "epoch_refused_live_owner",
  "epoch_refused_unverifiable",
] as const);
export type RuntimeBootstrapDecisionCode =
  (typeof RUNTIME_BOOTSTRAP_DECISION_CODES)[number];

export interface RuntimeEpochInput {
  readonly schemaVersion: RuntimeEpochSchemaVersion;
  readonly epochId: RuntimeEpochId;
  readonly startedAtEpochMs: number;
  readonly hostRef: string;
  readonly pidRef: number;
  /**
   * What the durable layer reports about any previous owner. Supplied by
   * the caller (23B wiring); this contract only decides on it. A claim
   * whose owner cannot be established (`unverifiable`, or a live claim
   * with no id) is AMBIGUOUS OWNERSHIP and refuses the epoch (L5).
   */
  readonly priorOwner: {
    readonly code: RuntimeEpochPriorOwnerCode;
    readonly epochId: string | null;
  };
  /**
   * The epoch id the runtime believes it is carrying (e.g. inherited from
   * an exec environment). MUST be absent/null for a fresh start; MUST
   * equal epochId when present.
   */
  readonly declaredEpochId: RuntimeEpochId | null;
}

export interface RuntimeEpoch {
  readonly schemaVersion: RuntimeEpochSchemaVersion;
  readonly epochId: RuntimeEpochId;
  readonly startedAtEpochMs: number;
  readonly hostRef: string;
  readonly pidRef: number;
  /** Lifecycle always starts at BOOTING (L6); LIVE is never skipped. */
  readonly lifecycle: Extract<RuntimeLifecycleState, "BOOTING">;
  readonly priorOwner: RuntimeEpochInput["priorOwner"];
  readonly startReason: RuntimeEpochEndReason;
  /** ALWAYS false — an epoch is identity, never authority. */
  readonly executionAuthorized: false;
  /** ALWAYS false. */
  readonly policyAuthorized: false;
}

export type RuntimeBootstrapDecision =
  | { readonly ok: true; readonly code: "epoch_opened"; readonly epoch: RuntimeEpoch; readonly explanation: string }
  | {
      readonly ok: false;
      readonly code:
        | "epoch_refused_stale"
        | "epoch_refused_mismatch"
        | "epoch_refused_live_owner"
        | "epoch_refused_unverifiable";
      readonly epoch: null;
      readonly explanation: string;
    };

/**
 * The ONLY sanctioned constructor for a RuntimeEpoch (pure function).
 * Fails closed on: missing/malformed epoch id, epoch-id mismatch with the
 * declared id, a carried-over id over a fresh store, and a LIVE claim
 * held by another epoch id (split-brain refusal — L5).
 */
export function makeRuntimeEpoch(input: RuntimeEpochInput): RuntimeBootstrapDecision {
  if (!RUNTIME_EPOCH_ID_PATTERN.test(input.epochId)) {
    return {
      ok: false,
      code: "epoch_refused_stale",
      epoch: null,
      explanation: "epoch id missing or malformed — refusing to open an epoch (fail closed)",
    };
  }
  if (input.declaredEpochId !== null && input.declaredEpochId !== input.epochId) {
    return {
      ok: false,
      code: "epoch_refused_mismatch",
      epoch: null,
      explanation:
        "declared epoch id does not match the generated epoch id — refusing (ambiguous identity fails closed)",
    };
  }
  if (input.priorOwner.code === "none" && input.declaredEpochId !== null) {
    return {
      ok: false,
      code: "epoch_refused_stale",
      epoch: null,
      explanation:
        "fresh store reports no prior owner while an epoch id was carried in — refusing (a carried id over a fresh store is stale by definition)",
    };
  }
  if (
    input.priorOwner.code === "live_claim_present" &&
    input.priorOwner.epochId !== null &&
    input.priorOwner.epochId !== input.epochId
  ) {
    return {
      ok: false,
      code: "epoch_refused_live_owner",
      epoch: null,
      explanation:
        "another epoch id still holds the live-ownership claim — refusing (two live owners is unrepresentable; ambiguous ownership fails closed)",
    };
  }
  if (
    input.priorOwner.code === "unverifiable" ||
    (input.priorOwner.code === "live_claim_present" && input.priorOwner.epochId === null)
  ) {
    return {
      ok: false,
      code: "epoch_refused_unverifiable",
      epoch: null,
      explanation:
        "the prior-ownership claim cannot be attributed to an epoch id — ambiguous ownership fails closed (L5)",
    };
  }
  const startReason: RuntimeEpochEndReason =
    input.priorOwner.code === "none"
      ? "fresh_store_no_prior_owner"
      : input.priorOwner.code === "same_epoch_id"
        ? "prior_owner_released"
        : "prior_owner_expired";
  return {
    ok: true,
    code: "epoch_opened",
    epoch: Object.freeze({
      schemaVersion: RUNTIME_EPOCH_SCHEMA_VERSION,
      epochId: input.epochId,
      startedAtEpochMs: input.startedAtEpochMs,
      hostRef: input.hostRef,
      pidRef: input.pidRef,
      lifecycle: "BOOTING",
      priorOwner: input.priorOwner,
      startReason,
      executionAuthorized: false,
      policyAuthorized: false,
    }),
    explanation:
      "epoch opened at BOOTING; identity only — no execution or policy authority is granted by epoch admission",
  };
}

/** L5: an epoch id different from the current one is stale, full stop. */
export function checkStaleEpoch(
  currentEpochId: RuntimeEpochId,
  candidateEpochId: RuntimeEpochId
): boolean {
  return currentEpochId !== candidateEpochId;
}

// ── live/durable mutations ───────────────────────────────────────────────────

/** Kinds that may appear in a live/durable mutation (L8 excludes derived). */
export type ContinuityRecordKind = Exclude<RecordKind, "derived_index" | "store_checkpoint">;

/**
 * Runtime mirror of the type-level L8 exclusion: derived kinds are checked
 * again at the decision boundary so the exclusion survives a hostile cast.
 */
export const DERIVED_CONTINUITY_KINDS: ReadonlySet<string> = Object.freeze(
  new Set<string>(["derived_index", "store_checkpoint"])
);

/**
 * Mutation phases (closed):
 *   requested  — the live surface asked; nothing is durable or visible-yet
 *   durable    — a DurabilityBarrier with a commitSequence confirmed it
 *   visible    — the live runtime may now present it to its own surfaces
 *
 * The machine is linear: requested → durable → visible. Skipping durable
 * is unrepresentable (L4). A mutation that fails never becomes visible.
 */
export const LIVE_DURABLE_MUTATION_PHASES = Object.freeze([
  "requested",
  "durable",
  "visible",
] as const);
export type LiveDurableMutationPhase = (typeof LIVE_DURABLE_MUTATION_PHASES)[number];

/**
 * Outcomes (closed). `unknown` is explicit: persistence failures can be
 * ambiguous, and an ambiguous outcome is NEVER visible (L4: the store's
 * own transaction may or may not have committed — 22F/23E territory).
 */
export const LIVE_DURABLE_MUTATION_OUTCOMES = Object.freeze([
  "durable",
  "refused_pre_commit",
  "unknown_after_error",
] as const);
export type LiveDurableMutationOutcome = (typeof LIVE_DURABLE_MUTATION_OUTCOMES)[number];

export interface LiveDurableMutation {
  readonly schemaVersion: ContinuitySchemaVersion;
  readonly mutationId: string;
  readonly epochId: RuntimeEpochId;
  readonly kind: ContinuityRecordKind;
  readonly recordId: DurableRecordId;
  readonly phase: LiveDurableMutationPhase;
  readonly outcome: LiveDurableMutationOutcome | null;
  /** null until a barrier confirms; a fabricated barrier is unrepresentable. */
  readonly barrier: DurabilityBarrier | null;
  readonly atEpochMs: number;
}

export function makeLiveDurableMutation(input: {
  readonly mutationId: string;
  readonly epochId: RuntimeEpochId;
  readonly kind: ContinuityRecordKind;
  readonly recordId: DurableRecordId;
  readonly atEpochMs: number;
}): LiveDurableMutation {
  return Object.freeze({
    schemaVersion: CONTINUITY_SCHEMA_VERSION,
    mutationId: input.mutationId,
    epochId: input.epochId,
    kind: input.kind,
    recordId: input.recordId,
    phase: "requested",
    outcome: null,
    barrier: null,
    atEpochMs: input.atEpochMs,
  });
}

/**
 * Advance a mutation after the store layer answered. The barrier is the
 * ONLY path to `durable`/`visible`; a refused mutation stops at
 * `requested`; an errored one becomes outcome `unknown_after_error` and
 * can never be advanced again (ambiguity is terminal for visibility).
 */
export function advanceLiveDurableMutation(
  mutation: LiveDurableMutation,
  result:
    | { readonly kind: "barrier_confirmed"; readonly barrier: DurabilityBarrier }
    | { readonly kind: "refused"; readonly reason: string }
    | { readonly kind: "store_error"; readonly reason: string }
): LiveDurableMutation {
  if (mutation.outcome !== null) {
    // Terminal outcomes never advance (ambiguity cannot be healed).
    return mutation;
  }
  if (result.kind === "barrier_confirmed" && mutation.phase === "requested") {
    return Object.freeze({
      ...mutation,
      phase: "durable",
      outcome: "durable",
      barrier: result.barrier,
    });
  }
  if (result.kind === "refused") {
    return Object.freeze({ ...mutation, outcome: "refused_pre_commit" });
  }
  return Object.freeze({ ...mutation, outcome: "unknown_after_error" });
}

// ── durability barrier (the ack boundary; L4) ────────────────────────────────

/**
 * Barrier outcomes (closed). `rolled_back` and `ambiguous` are real
 * engine outcomes (22F fault injection territory) and both deny the ack.
 */
export const DURABILITY_BARRIER_OUTCOMES = Object.freeze([
  "committed",
  "rolled_back",
  "ambiguous",
] as const);
export type DurabilityBarrierOutcome = (typeof DURABILITY_BARRIER_OUTCOMES)[number];

/**
 * A DurabilityBarrier is the durable layer's confirmation of ONE atomic
 * persist. It is produced by the store/callback (22B/23B), never invented
 * here. `committed` with a commitSequence present is the ONLY shape that
 * authorises acknowledgement (L4).
 */
export interface DurabilityBarrier {
  readonly barrierId: string;
  readonly epochId: RuntimeEpochId;
  readonly outcome: DurabilityBarrierOutcome;
  readonly commitSequence: CommitSequence | null;
  readonly transactionId: string;
  readonly atEpochMs: number;
}

export function makeDurabilityBarrier(input: {
  readonly barrierId: string;
  readonly epochId: RuntimeEpochId;
  readonly outcome: DurabilityBarrierOutcome;
  readonly commitSequence: CommitSequence | null;
  readonly transactionId: string;
  readonly atEpochMs: number;
}): DurabilityBarrier {
  return Object.freeze({ ...input });
}

/** L4 as a predicate: ONLY a confirmed commit sequence acknowledges. */
export function acknowledgedBarrier(barrier: DurabilityBarrier): boolean {
  return barrier.outcome === "committed" && typeof barrier.commitSequence === "number";
}

// ── execution authority vocabulary (the ONLY allowed request shape) ─────────

/**
 * The exact authority vocabulary a LIVE runtime may use to seek execution.
 * It is a REQUEST shape: the junction still enforces Planner → Allocation
 * → Policy → Isolation → Governed Tool Runtime. Nothing in this contract
 * evaluates, grants, or bypasses any of those stages.
 */
export interface ExecutionAuthorityVocabulary {
  readonly stage: "planner_to_allocation_to_policy_to_isolation_to_governed_tool_runtime";
  readonly epochId: RuntimeEpochId;
  readonly taskRef: string;
  readonly planRef: string;
  readonly policyRequestId: string;
  /** ALWAYS false here: the runtime never self-declares authority. */
  readonly selfAuthorized: false;
}

// ── continuity decision (LIVE-side; closed union) ────────────────────────────

export const CONTINUITY_DECISION_CODES = Object.freeze([
  "admitted",
  "rejected_stale_epoch",
  "rejected_not_live",
  "rejected_no_epoch",
  "rejected_barrier_not_confirmed",
  "rejected_barrier_not_recognized",
  "rejected_epoch_mismatch",
  "rejected_derived_kind",
  "rejected_invalid_lifecycle_state",
] as const);
export type ContinuityDecisionCode = (typeof CONTINUITY_DECISION_CODES)[number];

/** Deny reasons for LIVE-side continuity refusals (closed union). */
export const LIVE_DURABLE_DENY_CODES = Object.freeze([
  "stale_epoch",
  "not_live",
  "no_epoch",
  "durability_barrier_not_confirmed",
  "durability_barrier_not_recognized",
  "epoch_mismatch",
  "derived_kind_denied",
  "invalid_lifecycle_state",
] as const);
export type LiveDurableDenyCode = (typeof LIVE_DURABLE_DENY_CODES)[number];

export type ContinuityDecision =
  | {
      readonly ok: true;
      readonly code: "admitted";
      readonly epochId: RuntimeEpochId;
      readonly mutationId: string;
      readonly commitSequence: CommitSequence | null;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code:
        | "rejected_stale_epoch"
        | "rejected_not_live"
        | "rejected_no_epoch"
        | "rejected_barrier_not_confirmed"
        | "rejected_barrier_not_recognized"
        | "rejected_epoch_mismatch"
        | "rejected_derived_kind"
        | "rejected_invalid_lifecycle_state";
      readonly epochId: RuntimeEpochId | null;
      readonly mutationId: string;
      readonly denyReason: LiveDurableDenyCode;
      readonly explanation: string;
    };

/**
 * The ONLY sanctioned LIVE-side continuity decision (pure function).
 * Preconditions enforced: epoch present; lifecycle LIVE; mutation's epoch
 * equals the deciding epoch; barrier present, recognized for this
 * mutation/epoch, and acknowledged (committed + commitSequence present).
 * A non-acknowledged barrier NEVER becomes visible (L4).
 */
export function decideContinuity(input: {
  readonly epochId: RuntimeEpochId | null;
  readonly lifecycle: RuntimeLifecycleState;
  readonly mutation: LiveDurableMutation;
}): ContinuityDecision {
  const mut = input.mutation;
  if (input.epochId === null) {
    return {
      ok: false,
      code: "rejected_no_epoch",
      epochId: null,
      mutationId: mut.mutationId,
      denyReason: "no_epoch",
      explanation: "no epoch is open — nothing may be admitted (fail closed)",
    };
  }
  if (input.lifecycle !== "LIVE") {
    return {
      ok: false,
      code: "rejected_not_live",
      epochId: input.epochId,
      mutationId: mut.mutationId,
      denyReason: "not_live",
      explanation:
        "lifecycle '" + input.lifecycle + "' is not LIVE — only the single live owner admits mutations (fail closed)",
    };
  }
  if (mut.epochId !== input.epochId) {
    return {
      ok: false,
      code: "rejected_epoch_mismatch",
      epochId: input.epochId,
      mutationId: mut.mutationId,
      denyReason: "epoch_mismatch",
      explanation: "mutation belongs to a different epoch — stale epochs fail closed",
    };
  }
  // L8 as a runtime check: derived kinds never enter the live/durable
  // admission boundary, even from a hostile caller that cast the type away.
  if (DERIVED_CONTINUITY_KINDS.has(mut.kind)) {
    return {
      ok: false,
      code: "rejected_derived_kind",
      epochId: input.epochId,
      mutationId: mut.mutationId,
      denyReason: "derived_kind_denied",
      explanation:
        "derived kinds ('" + mut.kind + "') are non-authoritative and can never be live/durable mutations (L8)",
    };
  }
  if (mut.barrier === null) {
    return {
      ok: false,
      code: "rejected_barrier_not_confirmed",
      epochId: input.epochId,
      mutationId: mut.mutationId,
      denyReason: "durability_barrier_not_confirmed",
      explanation:
        "no durability barrier exists for this mutation — nothing is acknowledged before durable confirmation (L4)",
    };
  }
  if (!acknowledgedBarrier(mut.barrier)) {
    return {
      ok: false,
      code: "rejected_barrier_not_confirmed",
      epochId: input.epochId,
      mutationId: mut.mutationId,
      denyReason: "durability_barrier_not_confirmed",
      explanation:
        "barrier outcome '" + mut.barrier.outcome + "' is not a confirmed commit — acknowledgement refused (fail closed)",
    };
  }
  if (mut.barrier.epochId !== input.epochId) {
    return {
      ok: false,
      code: "rejected_barrier_not_recognized",
      epochId: input.epochId,
      mutationId: mut.mutationId,
      denyReason: "durability_barrier_not_recognized",
      explanation: "barrier was not issued for the deciding epoch — refusing (L5)",
    };
  }
  return {
    ok: true,
    code: "admitted",
    epochId: input.epochId,
    mutationId: mut.mutationId,
    commitSequence: mut.barrier.commitSequence,
    explanation: "mutation admitted with durable confirmation (commit sequence present)",
  };
}

/** Is a previously issued decision still fresh for THIS epoch (L5)? */
export function decisionStillFresh(
  decision: ContinuityDecision,
  currentEpochId: RuntimeEpochId
): boolean {
  return decision.epochId === currentEpochId;
}

// ── recovery bootstrap decision (READY-side; closed union) ───────────────────

export const RECOVERY_BOOTSTRAP_DECISION_CODES = Object.freeze([
  "bootstrap_to_ready",
  "bootstrap_refused_recovery_failed",
  "bootstrap_refused_epoch_mismatch",
  "bootstrap_refused_epoch_not_open",
] as const);
export type RecoveryBootstrapDecisionCode =
  (typeof RECOVERY_BOOTSTRAP_DECISION_CODES)[number];

/** Deny reasons for recovery→READY bootstrap (closed union). */
export const RECOVERY_BOOTSTRAP_DENY_CODES = Object.freeze([
  "recovery_not_accepted",
  "epoch_mismatch",
  "epoch_not_open",
] as const);
export type RecoveryBootstrapDenyCode = (typeof RECOVERY_BOOTSTRAP_DENY_CODES)[number];

export type RecoveryBootstrapDecision =
  | {
      readonly ok: true;
      readonly code: "bootstrap_to_ready";
      readonly admittedRecordIds: readonly DurableRecordId[];
      readonly authority: "recovered_data";
      readonly executionAuthorized: false;
      readonly policyAuthorized: false;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code:
        | "bootstrap_refused_recovery_failed"
        | "bootstrap_refused_epoch_mismatch"
        | "bootstrap_refused_epoch_not_open";
      readonly authority: "recovered_data";
      readonly executionAuthorized: false;
      readonly policyAuthorized: false;
      readonly denyReason: RecoveryBootstrapDenyCode;
      readonly explanation: string;
    };

/**
 * The ONLY sanctioned recovery→READY admission (pure function; L2/L6).
 * The input recovery decision is the frozen 22A/22E object: admission
 * inherits its admitted ids and its recovered_data authority; a rejected
 * recovery can never be converted into READY. There is NO path here to
 * LIVE: reaching LIVE is a separate, explicit, evidenced epoch transition.
 */
export function decideRecoveryBootstrap(input: {
  readonly epochId: RuntimeEpochId | null;
  readonly lifecycle: RuntimeLifecycleState;
  readonly recoveryDecision: RecoveryDecision;
}): RecoveryBootstrapDecision {
  if (input.epochId === null) {
    return {
      ok: false,
      code: "bootstrap_refused_epoch_not_open",
      authority: "recovered_data",
      executionAuthorized: false,
      policyAuthorized: false,
      denyReason: "epoch_not_open",
      explanation: "no epoch is open — recovered state cannot be exposed (fail closed)",
    };
  }
  if (input.lifecycle !== "RECONCILED") {
    return {
      ok: false,
      code: "bootstrap_refused_epoch_mismatch",
      authority: "recovered_data",
      executionAuthorized: false,
      policyAuthorized: false,
      denyReason: "epoch_mismatch",
      explanation:
        "lifecycle '" + input.lifecycle + "' is not RECONCILED — READY is reachable only through reconciliation (fail closed)",
    };
  }
  if (
    input.recoveryDecision.code === "rejected_schema_mismatch" ||
    input.recoveryDecision.code === "rejected_unverifiable" ||
    input.recoveryDecision.code === "rejected_scan_bound"
  ) {
    return {
      ok: false,
      code: "bootstrap_refused_recovery_failed",
      authority: "recovered_data",
      executionAuthorized: false,
      policyAuthorized: false,
      denyReason: "recovery_not_accepted",
      explanation:
        "startup recovery refused ('" + input.recoveryDecision.code +
        "') — the runtime may not expose state (fail closed); re-enter RECOVERING only after an explicit, evidenced retry",
    };
  }
  return {
    ok: true,
    code: "bootstrap_to_ready",
    admittedRecordIds: input.recoveryDecision.admittedRecordIds,
    authority: "recovered_data",
    executionAuthorized: false,
    policyAuthorized: false,
    explanation:
      String(input.recoveryDecision.admittedRecordIds.length) +
      " record(s) exposed as recovered_data; no authority; LIVE requires a separate explicit transition",
  };
}

// ── lifecycle transitions (explicit, evidenced; never implicit) ──────────────

export interface LifecycleTransition {
  readonly schemaVersion: ContinuitySchemaVersion;
  readonly epochId: RuntimeEpochId;
  readonly from: RuntimeLifecycleState;
  readonly to: RuntimeLifecycleState;
  readonly reason: RuntimeLifecycleReason;
  readonly atEpochMs: number;
  /** Evidence for RECOVERING→RECONCILED, RECONCILED→READY and READY→LIVE
   *  (see laws L6/L2 and the 23D handoff). */
  readonly evidence:
    | { readonly kind: "recovery_decision"; readonly code: RecoveryDecision["code"] }
    | { readonly kind: "handoff_evidence"; readonly evidenceHash: string }
    | { readonly kind: "none" };
}

/**
 * Transition legality per REASON (closed): the reason must make sense for
 * the target state, and the machine table must permit the edge. RECOVERED
 * → LIVE is unrepresentable in ANY reason (L6: re-entry goes through
 * RECOVERING).
 */
const REASON_TARGETS: Readonly<
  Record<RuntimeLifecycleReason, readonly RuntimeLifecycleState[]>
> = Object.freeze({
  process_start: Object.freeze(["BOOTING"] as const),
  fresh_store_detected: Object.freeze(["RECOVERING"] as const),
  recovery_started: Object.freeze(["RECOVERING"] as const),
  recovery_reconciled: Object.freeze(["RECONCILED"] as const),
  recovery_decision_ready: Object.freeze(["READY"] as const),
  recovery_bootstrap_rejected: Object.freeze(["RECOVERED"] as const),
  lifecycle_transition: Object.freeze(["LIVE"] as const),
  barrier_lost: Object.freeze(["RECOVERED"] as const),
  store_unavailable: Object.freeze(["RECOVERED"] as const),
  explicit_shutdown: Object.freeze(["RECOVERED"] as const),
  operator_pause: Object.freeze(["RECOVERED"] as const),
});

export function isLifecycleTransitionAllowed(
  from: RuntimeLifecycleState,
  to: RuntimeLifecycleState,
  reason: RuntimeLifecycleReason
): boolean {
  if (!isRuntimeTransition(from, to)) return false;
  if (!(REASON_TARGETS[reason] as readonly string[]).includes(to)) return false;
  // RECOVERED → LIVE is unrepresentable for any reason (L6).
  if (from === "RECOVERED" && to === "LIVE") return false;
  return true;
}

export type LifecycleTransitionDecision =
  | { readonly ok: true; readonly code: "transition_applied"; readonly to: RuntimeLifecycleState; readonly explanation: string }
  | { readonly ok: false; readonly code: "transition_refused"; readonly to: RuntimeLifecycleState; readonly explanation: string };

/**
 * Apply a lifecycle transition on an epoch (pure). RECOVERING→READY MUST
 * carry recovery-decision evidence (L6: recovery→live is explicit AND
 * evidenced); the REAL authority gates remain downstream (the junction) —
 * this function only moves the machine and records evidence. The caller
 * re-checks epoch freshness via checkStaleEpoch before calling (stale
 * epochs fail closed before any transition is even considered).
 */
export function advanceLifecycle(
  epoch: RuntimeEpoch,
  current: RuntimeLifecycleState,
  to: RuntimeLifecycleState,
  reason: RuntimeLifecycleReason,
  atEpochMs: number,
  evidence: LifecycleTransition["evidence"] = { kind: "none" }
): LifecycleTransitionDecision {
  void atEpochMs;
  void epoch;
  if (!isLifecycleTransitionAllowed(current, to, reason)) {
    return {
      ok: false,
      code: "transition_refused",
      to,
      explanation:
        "transition " + current + "→" + to + " with reason '" + reason +
        "' is not permitted by the closed machine (fail closed)",
    };
  }
  if (to === "RECONCILED" && evidence.kind !== "recovery_decision") {
    return {
      ok: false,
      code: "transition_refused",
      to,
      explanation:
        "RECOVERING→RECONCILED requires recovery-decision evidence (L6) — refusing an unevidenced reconciliation",
    };
  }
  if (to === "READY" && evidence.kind !== "recovery_decision") {
    return {
      ok: false,
      code: "transition_refused",
      to,
      explanation:
        "RECONCILED→READY requires recovery-decision evidence (L6) — refusing an unevidenced handoff",
    };
  }
  if (to === "LIVE" && evidence.kind !== "handoff_evidence") {
    return {
      ok: false,
      code: "transition_refused",
      to,
      explanation:
        "READY→LIVE requires handoff evidence binding recovery→new epoch→admitted state (23D) — refusing an unevidenced go-live",
    };
  }
  return {
    ok: true,
    code: "transition_applied",
    to,
    explanation: "lifecycle advanced " + current + "→" + to + " (" + reason + ")",
  };
}

// ── runtime continuity snapshot (the answer to "are we continuous?") ─────────

export interface RuntimeContinuitySnapshot {
  readonly schemaVersion: ContinuitySchemaVersion;
  readonly epochId: RuntimeEpochId;
  readonly lifecycle: RuntimeLifecycleState;
  readonly lastKnownCommitSequence: CommitSequence | null;
  readonly mutations: readonly LiveDurableMutation[];
  readonly admittedRecoveredRecordCount: number;
  readonly atEpochMs: number;
  /** ALWAYS "recovered_data" — the snapshot is data, never authority. */
  readonly authority: "recovered_data";
  /** ALWAYS false. */
  readonly executionAuthorized: false;
  /** ALWAYS false. */
  readonly policyAuthorized: false;
}

export function buildRuntimeContinuitySnapshot(input: {
  readonly epochId: RuntimeEpochId;
  readonly lifecycle: RuntimeLifecycleState;
  readonly lastKnownCommitSequence: CommitSequence | null;
  readonly mutations: readonly LiveDurableMutation[];
  readonly admittedRecoveredRecordCount: number;
  readonly atEpochMs: number;
}): RuntimeContinuitySnapshot {
  return Object.freeze({
    schemaVersion: CONTINUITY_SCHEMA_VERSION,
    epochId: input.epochId,
    lifecycle: input.lifecycle,
    lastKnownCommitSequence: input.lastKnownCommitSequence,
    mutations: Object.freeze([...input.mutations]),
    admittedRecoveredRecordCount: input.admittedRecoveredRecordCount,
    atEpochMs: input.atEpochMs,
    authority: "recovered_data",
    executionAuthorized: false,
    policyAuthorized: false,
  });
}
