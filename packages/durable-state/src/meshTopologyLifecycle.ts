/**
 * PHASE 27C — Node & Edge Lifecycle (TOPOLOGY-OBSERVATION LIFECYCLE —
 * SEPARATE FROM PeerTrustState / NO DISCOVERY / NO POLICY / NO TOOL /
 * ZERO AUTHORITY).
 *
 * This module implements the lifecycle of a TOPOLOGY OBSERVATION: the
 * knowledge record produced when a local node observes a node or edge in
 * the mesh graph (27B records the content; 27C decides how that knowledge
 * may move between lifecycle states). It is a pure decision layer over
 * caller-supplied facts — no store, no socket, no clock (caller-supplied
 * `evidenceAtEpochMs` only), no I/O.
 *
 * THE LAWS IT ENFORCES
 *   · LIFECYCLE SEPARATION — the topology-observation vocabulary
 *     (observed / stale / quarantined_observation / retired_observation /
 *     unknown_observation) is DISJOINT from the frozen 24C PeerTrustState
 *     vocabulary (unknown / candidate / admitted / quarantined / retired).
 *     Every PeerTrustState value presented here refuses with
 *     `refused_cross_lifecycle_state`: a trust state is never a topology
 *     state, and a topology state is never a trust state (cross-lifecycle
 *     confusion fails closed). This module only READS NODE_TRUST_STATES in
 *     order to refuse it; it never mutates, exports, or re-exports peer
 *     trust state, and it has no path into the 24C registry.
 *   · PINNED LEGAL TRANSITIONS — a closed 5x5 table plus a closed
 *     reason->target map; both must agree or the transition refuses.
 *     Unknown states, unknown reasons, and reasons that don't match the
 *     target refuse (fail closed).
 *   · TERMINAL ANTI-RESURRECTION — `retired_observation` has NO out-edge:
 *     any transition out of it refuses `refused_terminal_state`,
 *     regardless of reason, evidence, or epoch. `quarantined_observation`
 *     exits ONLY to retirement; quarantine never returns to observed
 *     (mirrors the 24C L6 law for peer trust).
 *   · FRESHNESS ORDERING — evidence older than the record's recorded
 *     freshness refuses `refused_stale_fact`; returning to `observed`
 *     (re-observation) requires STRICTLY NEWER evidence. Non-finite or
 *     negative evidence refuses `refused_invalid_fact`. Stale facts never
 *     drive any transition.
 *   · EPOCH BOUNDARY — a record from another epoch refuses
 *     `refused_stale_epoch` and must pass through recovery first; empty
 *     epoch ids refuse `refused_invalid_epoch`.
 *   · RECOVERY GRANTS NOTHING — `recoverTopologyObservation` restores a
 *     saved record with `authority: "none"`, `trustInherited: false`, and
 *     `autoResumed: false` as STRUCTURAL LITERALS. A request to inherit
 *     trust refuses `refused_no_trust_inheritance` before anything else is
 *     evaluated. Terminal restores EXACTLY terminal; quarantine restores
 *     EXACTLY quarantine (never auto-clears); an `observed` record
 *     recovered into a DIFFERENT epoch restores as `stale` — freshness
 *     does not inherit across epochs and re-observation is required.
 *
 * SCOPE LAW: LOCAL-ONLY. No discovery/scanning/mDNS/broadcast/gossip
 * membership/WAN/Internet/cloud relay/NAT traversal/UPnP/tunnel/consensus/
 * global authority; no alternate listener/spawn/persist/control path;
 * observability is read-only, never control; recovery never auto-resumes.
 *
 * Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
 * Separation law: PEER != PATH != TOPOLOGY != TRUST != AUTHORITY != EXECUTION.
 */

import { canonicalHash } from "./canonical.js";
import { NODE_TRUST_STATES } from "./federationIdentity.js";

/** Topology-observation lifecycle schema version (27C). */
export const TOPOLOGY_LIFECYCLE_SCHEMA_VERSION =
  "menog-mesh-topology-lifecycle/v0" as const;
export type TopologyLifecycleSchemaVersion =
  typeof TOPOLOGY_LIFECYCLE_SCHEMA_VERSION;

// ── lifecycle state vocabulary (closed; DISJOINT from PeerTrustState) ────────

/**
 * The closed topology-observation lifecycle states. Deliberately disjoint
 * from NODE_TRUST_STATES (24C): no value here is a trust state and no
 * trust value is accepted here (cross-lifecycle confusion fails closed).
 */
export const TOPOLOGY_OBSERVATION_STATES = Object.freeze([
  "observed",
  "stale",
  "quarantined_observation",
  "retired_observation",
  "unknown_observation",
] as const);
export type TopologyObservationState =
  (typeof TOPOLOGY_OBSERVATION_STATES)[number];

/** Terminal states: NO out-edges exist (anti-resurrection). */
export const TOPOLOGY_TERMINAL_OBSERVATION_STATES = Object.freeze([
  "retired_observation",
] as const);

/** Quarantine states: exit ONLY to retirement; never back to observed. */
export const TOPOLOGY_QUARANTINE_OBSERVATION_STATES = Object.freeze([
  "quarantined_observation",
] as const);

/**
 * The ONLY legal topology-observation transitions (closed, frozen).
 * unknown_observation has no out-edges (an unnamed state cannot move).
 */
export const TOPOLOGY_OBSERVATION_TRANSITIONS: Readonly<
  Record<TopologyObservationState, readonly TopologyObservationState[]>
> = Object.freeze({
  observed: Object.freeze(["stale", "quarantined_observation", "retired_observation"] as const),
  stale: Object.freeze(["observed", "quarantined_observation", "retired_observation"] as const),
  quarantined_observation: Object.freeze(["retired_observation"] as const),
  retired_observation: Object.freeze([] as const),
  unknown_observation: Object.freeze([] as const),
});

// ── transition-reason vocabulary (closed; reason -> allowed targets) ─────────

/** The closed reasons a topology-observation transition may cite. */
export const TOPOLOGY_OBSERVATION_REASONS = Object.freeze([
  "freshness_expired",
  "re_observed",
  "evidence_conflict",
  "operator_retirement",
  "unknown_reason",
] as const);
export type TopologyObservationReason =
  (typeof TOPOLOGY_OBSERVATION_REASONS)[number];

/** Each reason maps to a CLOSED set of targets; unknown_reason maps to none. */
export const TOPOLOGY_OBSERVATION_REASON_TARGETS: Readonly<
  Record<TopologyObservationReason, readonly TopologyObservationState[]>
> = Object.freeze({
  freshness_expired: Object.freeze(["stale"] as const),
  re_observed: Object.freeze(["observed"] as const),
  evidence_conflict: Object.freeze(["quarantined_observation"] as const),
  operator_retirement: Object.freeze(["retired_observation"] as const),
  unknown_reason: Object.freeze([] as const),
});

// ── refusal vocabulary (closed) ──────────────────────────────────────────────

/** Closed lifecycle refusal codes (fail-closed; no silent handling). */
export const TOPOLOGY_OBSERVATION_REFUSAL_CODES = Object.freeze([
  "refused_cross_lifecycle_state",
  "refused_unknown_state",
  "refused_unknown_reason",
  "refused_reason_mismatch",
  "refused_illegal_transition",
  "refused_terminal_state",
  "refused_stale_fact",
  "refused_invalid_fact",
  "refused_stale_epoch",
  "refused_invalid_epoch",
  "refused_invalid_record",
  "refused_no_trust_inheritance",
  "refused_unknown",
] as const);
export type TopologyObservationRefusalCode =
  (typeof TOPOLOGY_OBSERVATION_REFUSAL_CODES)[number];

// ── record shape ─────────────────────────────────────────────────────────────

/**
 * A topology-observation lifecycle record: WHICH knowledge record, its
 * lifecycle state, the freshness of the evidence behind it, and the epoch
 * it belongs to. No trust, no admission, no authority field exists here.
 */
export interface TopologyObservationRecord {
  readonly recordId: string;
  readonly state: TopologyObservationState;
  readonly observedAtEpochMs: number;
  readonly epochId: string;
}

// ── transition decisions ─────────────────────────────────────────────────────

export type TopologyObservationTransitionDecision =
  | {
      readonly ok: true;
      readonly code: "transition_allowed";
      readonly from: TopologyObservationState;
      readonly to: TopologyObservationState;
      readonly reason: TopologyObservationReason;
      /** The NEXT record (pure — the caller applies it; no store here). */
      readonly record: TopologyObservationRecord;
      /** Structural literal: a lifecycle transition grants zero authority. */
      readonly authority: "none";
      readonly explanation: string;
      readonly provenanceHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "transition_refused";
      readonly refusal: TopologyObservationRefusalCode;
      readonly explanation: string;
      readonly provenanceHash: string;
    };

/**
 * Decide one topology-observation lifecycle transition (pure).
 *
 * Pinned validation order (first match wins):
 *   1. record state vocabulary — PeerTrustState values refuse
 *      `refused_cross_lifecycle_state`; other unknowns refuse
 *      `refused_unknown_state` (the unknown_observation sentinel included)
 *   2. target state vocabulary — same classification for `to`
 *   3. reason vocabulary — unknown_reason refuses `refused_unknown_reason`
 *   4. epoch validity/boundary — empty id `refused_invalid_epoch`; record
 *      from another epoch `refused_stale_epoch` (recover first)
 *   5. terminal — from retired_observation refuses `refused_terminal_state`
 *   6. fact validity — non-finite/negative evidence `refused_invalid_fact`
 *   7. freshness ordering — evidence older than the record refuses
 *      `refused_stale_fact`; reaching observed requires STRICTLY newer
 *      evidence (equal refuses `refused_stale_fact`)
 *   8. edge legality — target must be in the closed transition table
 *      (else `refused_illegal_transition`)
 *   9. reason-target agreement — target must be in the reason's closed set
 *      (else `refused_reason_mismatch`)
 *  10. allowed: authority structurally "none"; the next record carries the
 *      evidence freshness forward under the CURRENT epoch.
 */
export function decideTopologyObservationTransition(input: {
  readonly record: TopologyObservationRecord;
  readonly to: string;
  readonly reason: string;
  readonly currentEpochId: string;
  readonly evidenceAtEpochMs: number;
}): TopologyObservationTransitionDecision {
  const provenanceHash = canonicalHash({
    schemaVersion: TOPOLOGY_LIFECYCLE_SCHEMA_VERSION,
    record: input.record,
    to: input.to,
    reason: input.reason,
    currentEpochId: input.currentEpochId,
    evidenceAtEpochMs: input.evidenceAtEpochMs,
  });
  // 1. record state
  const fromCheck = classifyState(input.record.state);
  if (fromCheck !== null) {
    return refuseTransition(fromCheck, provenanceHash);
  }
  // 2. target state
  const toCheck = classifyState(input.to);
  if (toCheck !== null) {
    return refuseTransition(toCheck, provenanceHash);
  }
  const to = input.to as TopologyObservationState;
  // 3. reason vocabulary
  if (
    input.reason === "unknown_reason" ||
    !(TOPOLOGY_OBSERVATION_REASONS as readonly string[]).includes(input.reason)
  ) {
    return refuseTransition("refused_unknown_reason", provenanceHash);
  }
  const reason = input.reason as TopologyObservationReason;
  // 4. epoch validity / boundary
  if (
    typeof input.currentEpochId !== "string" ||
    input.currentEpochId.length === 0 ||
    typeof input.record.epochId !== "string" ||
    input.record.epochId.length === 0
  ) {
    return refuseTransition("refused_invalid_epoch", provenanceHash);
  }
  if (input.record.epochId !== input.currentEpochId) {
    return refuseTransition(
      "refused_stale_epoch",
      provenanceHash,
      "the record belongs to epoch '" +
        input.record.epochId +
        "' but the current epoch is '" +
        input.currentEpochId +
        "' — a cross-epoch record refuses and must pass through recovery first (recovery grants nothing and never auto-resumes)",
    );
  }
  // 5. terminal anti-resurrection (absolute within the epoch)
  if (input.record.state === "retired_observation") {
    return refuseTransition(
      "refused_terminal_state",
      provenanceHash,
      "record '" +
        input.record.recordId +
        "' is retired_observation — TERMINAL, no out-edge exists; any resurrection attempt refuses regardless of reason, evidence, or epoch (terminal anti-resurrection)",
    );
  }
  // 6. fact validity
  if (
    typeof input.evidenceAtEpochMs !== "number" ||
    !Number.isFinite(input.evidenceAtEpochMs) ||
    input.evidenceAtEpochMs < 0
  ) {
    return refuseTransition(
      "refused_invalid_fact",
      provenanceHash,
      "evidence time '" +
        String(input.evidenceAtEpochMs) +
        "' is not a finite, non-negative epoch millisecond — refusing (fail closed); an unorderable fact cannot drive any transition",
    );
  }
  // 7. freshness ordering
  if (input.evidenceAtEpochMs < input.record.observedAtEpochMs) {
    return refuseTransition(
      "refused_stale_fact",
      provenanceHash,
      "evidence (" +
        input.evidenceAtEpochMs +
        ") is OLDER than the record's recorded freshness (" +
        input.record.observedAtEpochMs +
        ") — stale facts fail closed and never drive any transition (freshness ordering)",
    );
  }
  if (to === "observed" && input.evidenceAtEpochMs <= input.record.observedAtEpochMs) {
    return refuseTransition(
      "refused_stale_fact",
      provenanceHash,
      "returning a record to 'observed' requires STRICTLY NEWER evidence than " +
        input.record.observedAtEpochMs +
        " — equal or older evidence refuses (freshness ordering); re-observation is never free",
    );
  }
  // 8. edge legality (closed table)
  if (
    !(
      TOPOLOGY_OBSERVATION_TRANSITIONS[input.record.state] as readonly string[]
    ).includes(to)
  ) {
    return refuseTransition(
      "refused_illegal_transition",
      provenanceHash,
      "transition '" +
        input.record.state +
        "' -> '" +
        to +
        "' is not in the closed topology-observation transition table — refusing (fail closed); quarantine exits only to retirement and no state reaches an unnamed one",
    );
  }
  // 9. reason-target agreement (closed map)
  if (
    !(TOPOLOGY_OBSERVATION_REASON_TARGETS[reason] as readonly string[]).includes(
      to,
    )
  ) {
    return refuseTransition(
      "refused_reason_mismatch",
      provenanceHash,
      "reason '" +
        reason +
        "' does not produce target '" +
        to +
        "' — refusing (fail closed); each reason maps to exactly one closed target set",
    );
  }
  const next: TopologyObservationRecord = Object.freeze({
    recordId: input.record.recordId,
    state: to,
    observedAtEpochMs: input.evidenceAtEpochMs,
    epochId: input.currentEpochId,
  });
  return {
    ok: true,
    code: "transition_allowed",
    from: input.record.state as TopologyObservationState,
    to,
    reason,
    record: next,
    authority: "none",
    explanation:
      "lifecycle transition '" +
      input.record.state +
      "' -> '" +
      to +
      "' allowed under reason '" +
      reason +
      "' with fresh evidence — this is TOPOLOGY KNOWLEDGE moving state; authority stays 'none' by construction (TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY; PEER != TOPOLOGY != TRUST != AUTHORITY != EXECUTION)",
    provenanceHash,
  };
}

// ── recovery decisions (zero authority; no trust inheritance) ────────────────

export type TopologyObservationRecoveryDecision =
  | {
      readonly ok: true;
      readonly code: "observation_recovered";
      /** Restored record under the CURRENT epoch. */
      readonly record: TopologyObservationRecord;
      /** Structural literals — recovery grants nothing, ever. */
      readonly authority: "none";
      readonly trustInherited: false;
      readonly autoResumed: false;
      readonly terminal: boolean;
      readonly explanation: string;
      readonly provenanceHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "recovery_refused";
      readonly refusal: TopologyObservationRefusalCode;
      readonly explanation: string;
      readonly provenanceHash: string;
    };

/**
 * Recover a saved topology-observation record into an epoch (pure).
 *
 * Pinned validation order (first match wins):
 *   1. `trustClaim` — any request to inherit trust refuses
 *      `refused_no_trust_inheritance` BEFORE anything else (recovery
 *      grants nothing; no trust inheritance across epochs, ever)
 *   2. saved state vocabulary — PeerTrustState values refuse
 *      `refused_cross_lifecycle_state`; unknowns refuse
 *      `refused_unknown_state`
 *   3. record shape — empty recordId refuses `refused_invalid_record`
 *   4. epoch ids — empty id refuses `refused_invalid_epoch`
 *   5. fact validity — non-finite/negative saved freshness
 *      `refused_invalid_fact`
 *   6. restore rules:
 *      - retired_observation  -> EXACTLY terminal (terminal: true)
 *      - quarantined_observation -> EXACTLY quarantine (never auto-clears)
 *      - stale                -> stale
 *      - observed             -> observed ONLY within the same epoch;
 *                                into a DIFFERENT epoch restores as STALE
 *                                (freshness never inherits across epochs;
 *                                re-observation with strictly newer evidence
 *                                is required to become observed again)
 *   Every success carries authority "none", trustInherited false, and
 *   autoResumed false as structural literals.
 */
export function recoverTopologyObservation(input: {
  readonly saved: TopologyObservationRecord;
  readonly recoveredEpochId: string;
  readonly trustClaim: "none" | "inherit";
}): TopologyObservationRecoveryDecision {
  const provenanceHash = canonicalHash({
    schemaVersion: TOPOLOGY_LIFECYCLE_SCHEMA_VERSION,
    saved: input.saved,
    recoveredEpochId: input.recoveredEpochId,
    trustClaim: input.trustClaim,
  });
  // 1. trust inheritance is refused before ANYTHING else is evaluated
  if (input.trustClaim !== "none") {
    return {
      ok: false,
      code: "recovery_refused",
      refusal: "refused_no_trust_inheritance",
      explanation:
        "recovery was asked to inherit trust ('" +
        String(input.trustClaim) +
        "') — refused before evaluation (recovery grants nothing; no trust inheritance across epochs; PEER != TOPOLOGY != TRUST != AUTHORITY != EXECUTION)",
      provenanceHash,
    };
  }
  // 2. saved state vocabulary
  const stateCheck = classifyState(input.saved.state);
  if (stateCheck !== null) {
    return {
      ok: false,
      code: "recovery_refused",
      refusal: stateCheck,
      explanation: STATE_EXPLANATIONS[stateCheck],
      provenanceHash,
    };
  }
  // 3. record shape
  if (
    typeof input.saved.recordId !== "string" ||
    input.saved.recordId.length === 0
  ) {
    return {
      ok: false,
      code: "recovery_refused",
      refusal: "refused_invalid_record",
      explanation:
        "saved record carries an empty recordId — refusing (fail closed); an unkeyed record cannot be recovered, deduplicated, or audited",
      provenanceHash,
    };
  }
  // 4. epoch ids
  if (
    typeof input.recoveredEpochId !== "string" ||
    input.recoveredEpochId.length === 0 ||
    typeof input.saved.epochId !== "string" ||
    input.saved.epochId.length === 0
  ) {
    return {
      ok: false,
      code: "recovery_refused",
      refusal: "refused_invalid_epoch",
      explanation:
        "recovery requires non-empty saved and recovered epoch ids — refusing (fail closed); without epochs, staleness and inheritance are unrepresentable",
      provenanceHash,
    };
  }
  // 5. fact validity
  if (
    typeof input.saved.observedAtEpochMs !== "number" ||
    !Number.isFinite(input.saved.observedAtEpochMs) ||
    input.saved.observedAtEpochMs < 0
  ) {
    return {
      ok: false,
      code: "recovery_refused",
      refusal: "refused_invalid_fact",
      explanation:
        "saved freshness '" +
        String(input.saved.observedAtEpochMs) +
        "' is not a finite, non-negative epoch millisecond — refusing (fail closed); an unorderable fact cannot be recovered",
      provenanceHash,
    };
  }
  // 6. restore rules
  const crossEpoch = input.saved.epochId !== input.recoveredEpochId;
  const saved = input.saved;
  let state: TopologyObservationState;
  let terminal = false;
  if (saved.state === "retired_observation") {
    state = "retired_observation";
    terminal = true;
  } else if (saved.state === "quarantined_observation") {
    state = "quarantined_observation";
  } else if (saved.state === "observed" && crossEpoch) {
    state = "stale";
  } else {
    state = saved.state;
  }
  const record: TopologyObservationRecord = Object.freeze({
    recordId: saved.recordId,
    state,
    observedAtEpochMs: saved.observedAtEpochMs,
    epochId: input.recoveredEpochId,
  });
  return {
    ok: true,
    code: "observation_recovered",
    record,
    authority: "none",
    trustInherited: false,
    autoResumed: false,
    terminal,
    explanation:
      "recovered record '" +
      saved.recordId +
      "' into epoch '" +
      input.recoveredEpochId +
      "' as '" +
      state +
      "'" +
      (crossEpoch && saved.state === "observed"
        ? " — an observed record recovered across an epoch boundary restores STALE (freshness never inherits across epochs; re-observation with strictly newer evidence is required)"
        : saved.state === "retired_observation"
          ? " — EXACTLY terminal (terminal anti-resurrection; recovery restores terminal as terminal)"
          : saved.state === "quarantined_observation"
            ? " — EXACTLY quarantine (quarantine never auto-clears on recovery)"
            : "") +
      "; recovery grants nothing: authority 'none', no trust inherited, no auto-resume (recovery/reconnect/reconciliation never auto-resume)",
    provenanceHash,
  };
}

// ── shared classification (cross-lifecycle guard) ────────────────────────────

const STATE_EXPLANATIONS: Readonly<
  Record<TopologyObservationRefusalCode, string>
> = Object.freeze({
  refused_cross_lifecycle_state:
    "the value presented is a frozen 24C PeerTrustState, not a topology-observation state — cross-lifecycle confusion refuses (fail closed); PEER != TOPOLOGY != TRUST: a trust state is never a topology state and this module never mutates, exports, or re-exports peer trust state",
  refused_unknown_state:
    "unknown topology-observation state — refusing (fail closed); an unnamed state cannot ride through the lifecycle",
  refused_unknown_reason:
    "unknown transition reason — refusing (fail closed); an unnamed reason cannot drive a transition",
  refused_reason_mismatch:
    "reason does not produce this target — refusing (fail closed)",
  refused_illegal_transition:
    "transition is not in the closed table — refusing (fail closed)",
  refused_terminal_state:
    "terminal state — refusing (terminal anti-resurrection; no out-edge exists)",
  refused_stale_fact:
    "stale evidence — refusing (freshness ordering; stale facts never drive a transition)",
  refused_invalid_fact:
    "invalid evidence time — refusing (fail closed)",
  refused_stale_epoch:
    "cross-epoch record — refusing (recover first; recovery grants nothing)",
  refused_invalid_epoch:
    "invalid epoch id — refusing (fail closed)",
  refused_invalid_record:
    "invalid record — refusing (fail closed)",
  refused_no_trust_inheritance:
    "trust inheritance refused (recovery grants nothing; no trust inheritance across epochs)",
  refused_unknown:
    "unmapped lifecycle condition — refusing (fail closed)",
});

/**
 * Classify a state string against the topology-observation vocabulary.
 * Returns null when valid; otherwise the refusal code — PeerTrustState
 * values are specifically named `refused_cross_lifecycle_state`.
 */
function classifyState(
  state: string,
): TopologyObservationRefusalCode | null {
  if ((NODE_TRUST_STATES as readonly string[]).includes(state)) {
    return "refused_cross_lifecycle_state";
  }
  if (state === "unknown_observation") {
    return "refused_unknown_state";
  }
  if (!((TOPOLOGY_OBSERVATION_STATES as readonly string[]).includes(state))) {
    return "refused_unknown_state";
  }
  return null;
}

function refuseTransition(
  refusal: TopologyObservationRefusalCode,
  provenanceHash: string,
  explanation?: string,
): TopologyObservationTransitionDecision {
  return {
    ok: false,
    code: "transition_refused",
    refusal,
    explanation: explanation ?? STATE_EXPLANATIONS[refusal],
    provenanceHash,
  };
}
