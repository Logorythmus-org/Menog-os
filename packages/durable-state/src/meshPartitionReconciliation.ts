/**
 * PHASE 27G — Partition & Reconciliation (LOCAL WORLD-VIEWS ONLY /
 * NO CONSENSUS / NO GLOBAL TRUTH / NO AUTHORITY INHERITANCE /
 * NO AUTO-RESUME).
 *
 * This module models partition, rejoin, and KNOWLEDGE reconciliation
 * between two LOCAL world-views (e.g. what each side saw before a
 * split, re-presented when contact resumes). Reconciliation is a PURE
 * function over two caller-supplied views: it mutates neither view,
 * reaches no network, reads no clock, and creates no store. There is
 * no consensus protocol of any kind (no Raft/Paxos, no gossip, no
 * quorum, no leader, no global ordering, no discovery): reconciliation
 * does not decide WHICH SIDE IS RIGHT — it classifies agreement,
 * records CONFLICTS ATTRIBUTABLY (both claims, both owners, both
 * times), and keeps each side's exclusive knowledge attributed to the
 * side that holds it. Each node RETAINS its own world-view.
 *
 * THE LAWS IT ENFORCES
 *   · AUTHORITY INHERITANCE IS IMPOSSIBLE — every success carries
 *     authority: "none", consensusReached: false, globalOrdering:
 *     false, trustTransferred: false as STRUCTURAL LITERALS: merged
 *     knowledge grants no trust, no admission, no authority, and the
 *     other side's claims never become local truth by being merged.
 *   · NO AUTO-RESUME — autoResumed: false is structural, and merging
 *     NEVER transitions any observation: the 27C lifecycle is read,
 *     never advanced. Rejoin does not un-retire, un-quarantine, or
 *     refresh anything (the merged state is a CLAIM CLASSIFICATION,
 *     not a transition).
 *   · STALE DATA CANNOT RESURRECT TERMINAL FACTS — if EITHER view
 *     records a terminal state (27C TOPOLOGY_TERMINAL_OBSERVATION_STATES
 *     — retired_observation), the merged state stays terminal and the
 *     opposing claim is recorded as an attributed conflict
 *     (resolution "terminal_retained"). Time NEVER decides: even a
 *     strictly fresher "observed" claim cannot move a terminal fact
 *     (no global ordering — recorded times are attribution only).
 *   · QUARANTINE NEVER AUTO-CLEARS — if either view records a
 *     quarantine state (27C TOPOLOGY_QUARANTINE_OBSERVATION_STATES),
 *     the merged state stays quarantine with the conflict attributed
 *     (resolution "quarantine_retained"): rejoin is not a legal
 *     transition.
 *   · NO CONSENSUS => NO INVENTED AGREEMENT — two DIFFERENT non-
 *     terminal claims merge to `unknown_observation` (resolution
 *     "no_consensus_unknown"): without consensus the merged view does
 *     not assert a winner, while both claims remain fully attributed
 *     in the conflict record. Unknown stays unknown.
 *   · CONFLICTS REMAIN ATTRUTABLE — every conflict carries both
 *     owners, both states, both recorded times, and the resolution
 *     class; nothing is silently dropped, silently last-write-wins, or
 *     silently averaged.
 *   · FAIL-CLOSED INPUT — views are bounded (64 facts), epoch-bound
 *     (cross-epoch views refuse; a fact from another epoch refuses),
 *     closed-vocabulary (27C states, 27B provenance), duplicate-free
 *     within a view (a view contradicting itself refuses).
 *
 * SCOPE LAW: LOCAL-ONLY. No discovery/scanning/mDNS/broadcast/gossip
 * membership/WAN/Internet/cloud relay/NAT traversal/UPnP/tunnel/
 * consensus/global authority; no socket, no listener, no spawn, no
 * clock (caller-supplied epochs only), no store access; no alternate
 * listener/spawn/persist/control path; no tool or Policy surface.
 * Observability is read-only, never control.
 *
 * Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
 * Separation law: PEER != PATH != TOPOLOGY != TRUST != AUTHORITY != EXECUTION.
 */

import { canonicalHash } from "./canonical.js";
import {
  TOPOLOGY_PROVENANCE_SOURCES,
  type TopologyProvenance,
} from "./meshTopologyGraph.js";
import {
  TOPOLOGY_OBSERVATION_STATES,
  TOPOLOGY_QUARANTINE_OBSERVATION_STATES,
  TOPOLOGY_TERMINAL_OBSERVATION_STATES,
  type TopologyObservationState,
} from "./meshTopologyLifecycle.js";

/** Reconciliation schema version (27G). */
export const RECONCILIATION_SCHEMA_VERSION =
  "menog-mesh-reconciliation/v0" as const;
export type ReconciliationSchemaVersion =
  typeof RECONCILIATION_SCHEMA_VERSION;

// ── frozen bounds (callers may exceed, never redefine) ───────────────────────

/** Hard caps on one view. Refusal, never truncation, past a bound. */
export const RECONCILIATION_BOUNDS = Object.freeze({
  maxFactsPerView: 64,
  maxViewIdChars: 128,
  maxNodeChars: 128,
  maxEvidenceIdChars: 128,
});
export type ReconciliationBoundName = keyof typeof RECONCILIATION_BOUNDS;

// ── refusal vocabulary (closed) ──────────────────────────────────────────────

/** Closed reconciliation refusal codes (fail-closed; no silent handling). */
export const RECONCILIATION_REFUSAL_CODES = Object.freeze([
  "refused_invalid_view",
  "refused_field_bound",
  "refused_epoch_mismatch",
  "refused_duplicate_fact",
  "refused_unknown_state",
  "refused_unknown_provenance_source",
  "refused_invalid_provenance",
  "refused_unknown",
] as const);
export type ReconciliationRefusalCode =
  (typeof RECONCILIATION_REFUSAL_CODES)[number];

// ── views and facts ──────────────────────────────────────────────────────────

/**
 * ONE observation inside a node's world-view: what THIS view claims
 * about one subject, with 27B provenance and the view's epoch.
 */
export interface PartitionFact {
  readonly subjectNodeId: string;
  readonly state: TopologyObservationState;
  readonly provenance: TopologyProvenance;
  readonly epochId: string;
}

/** ONE node's local world-view (bounded, epoch-scoped, duplicate-free). */
export interface PartitionView {
  readonly viewId: string;
  readonly ownerNodeId: string;
  readonly epochId: string;
  readonly facts: readonly PartitionFact[];
}

/** Caller-supplied reconciliation input: two views, one epoch, pure. */
export interface ReconciliationInput {
  readonly reconciliationId: string;
  readonly localView: PartitionView;
  readonly remoteView: PartitionView;
}

// ── merged knowledge + conflicts ─────────────────────────────────────────────

/** One view's attributed claim about a merged subject. */
export interface FactAttribution {
  readonly ownerNodeId: string;
  readonly state: TopologyObservationState;
  readonly source: TopologyProvenance["source"];
  readonly evidenceId: string | null;
  readonly recordedAtEpochMs: number;
}

/** One merged fact: classified state + full attribution (local first). */
export interface MergedFact {
  readonly subjectNodeId: string;
  readonly state: TopologyObservationState;
  readonly conflicted: boolean;
  readonly attributions: readonly FactAttribution[];
}

/** The merged knowledge view (sorted, frozen; authority of NONE). */
export interface MergedKnowledgeView {
  readonly viewId: string;
  readonly epochId: string;
  readonly facts: readonly MergedFact[];
}

/** How a conflict's merged state was classified (never a winner). */
export type ConflictResolution =
  | "terminal_retained"
  | "quarantine_retained"
  | "no_consensus_unknown";

/** An ATTRIBUTABLE conflict: both claims preserved, neither declared true. */
export interface ReconciliationConflict {
  readonly subjectNodeId: string;
  readonly localState: TopologyObservationState;
  readonly remoteState: TopologyObservationState;
  readonly localOwnerNodeId: string;
  readonly remoteOwnerNodeId: string;
  readonly localRecordedAtEpochMs: number;
  readonly remoteRecordedAtEpochMs: number;
  readonly resolution: ConflictResolution;
}

// ── decisions ────────────────────────────────────────────────────────────────

/**
 * Outcome of one reconciliation. Every SUCCESS carries the no-consensus
 * structural literals: `authority: "none"`, `consensusReached: false`,
 * `globalOrdering: false`, `autoResumed: false`, `trustTransferred:
 * false` — merging knowledge is not agreeing, ordering, resuming, or
 * inheriting anything.
 */
export type ReconciliationDecision =
  | {
      readonly ok: true;
      readonly code: "views_reconciled";
      readonly reconciliationId: string;
      readonly merged: MergedKnowledgeView;
      readonly conflicts: readonly ReconciliationConflict[];
      readonly agreementCount: number;
      readonly localExclusiveCount: number;
      readonly remoteExclusiveCount: number;
      readonly authority: "none";
      readonly consensusReached: false;
      readonly globalOrdering: false;
      readonly autoResumed: false;
      readonly trustTransferred: false;
      readonly explanation: string;
      readonly reconciliationHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "reconciliation_refused";
      readonly reconciliationId: string;
      readonly refusal: ReconciliationRefusalCode;
      readonly explanation: string;
      readonly reconciliationHash: string;
    };

// ── refusal explanations (every refusal is explained; no silent handling) ────

const REFUSAL_EXPLANATIONS: Readonly<
  Record<ReconciliationRefusalCode, string>
> = Object.freeze({
  refused_invalid_view:
    "malformed view — refusing (fail closed); each view needs non-empty view/owner/epoch ids, an array of well-formed facts (non-empty subject, closed state, provenance object, view epoch) and both views must be objects",
  refused_field_bound:
    "field over frozen bound — refusing (fail closed); a caller may exceed a bound, never redefine one; view ids, node ids, evidence ids, and the per-view fact count are hard-capped — never truncate, never evict",
  refused_epoch_mismatch:
    "epoch mismatch — refusing (fail closed); views from DIFFERENT epochs (or a fact from another epoch) never reconcile — cross-epoch merging would fabricate a world the evidence never described (epoch substitution refused)",
  refused_duplicate_fact:
    "duplicate fact in one view — refusing (fail closed); a view that contradicts itself (same subject twice) cannot be reconciled — first the view must be coherent",
  refused_unknown_state:
    "unknown observation state — refusing (fail closed) under the frozen 27C vocabulary; an unnamed state cannot ride through as knowledge",
  refused_unknown_provenance_source:
    "unknown provenance source — refusing (fail closed); knowledge enters ONLY from explicit local configuration or governed evidence, so an unnamed source (or the refused unknown_source) is never reconciled",
  refused_invalid_provenance:
    "invalid provenance — refusing (fail closed); governed evidence must cite its evidence id, local configuration must not pretend to, and the recorded time must be finite and non-negative",
  refused_unknown:
    "unmapped reconciliation condition — refusing (fail closed)",
});

// ── shared guards ────────────────────────────────────────────────────────────

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/**
 * Validate ONE view's facts in array order (pinned inner order:
 * shape → field bounds → fact epoch → state vocabulary → provenance →
 * duplicate subject). Returns the first failing refusal code, or null
 * when the view is coherent. Records every subject in `seen` so a
 * self-contradicting view refuses.
 */
function validateViewFacts(
  view: PartitionView,
  seen: Set<string>,
): ReconciliationRefusalCode | null {
  for (const fact of view.facts) {
    if (fact === null || typeof fact !== "object") {
      return "refused_invalid_view";
    }
    if (
      !isNonEmptyString(fact.subjectNodeId) ||
      typeof fact.state !== "string" ||
      typeof fact.epochId !== "string" ||
      fact.epochId.length === 0 ||
      fact.provenance === null ||
      typeof fact.provenance !== "object"
    ) {
      return "refused_invalid_view";
    }
    if (fact.subjectNodeId.length > RECONCILIATION_BOUNDS.maxNodeChars) {
      return "refused_field_bound";
    }
    const evidenceId = fact.provenance.evidenceId;
    if (
      typeof evidenceId === "string" &&
      evidenceId.length > RECONCILIATION_BOUNDS.maxEvidenceIdChars
    ) {
      return "refused_field_bound";
    }
    if (fact.epochId !== view.epochId) {
      return "refused_epoch_mismatch";
    }
    if (!((TOPOLOGY_OBSERVATION_STATES as readonly string[]).includes(fact.state))) {
      return "refused_unknown_state";
    }
    const source = fact.provenance.source;
    if (
      typeof source !== "string" ||
      !((TOPOLOGY_PROVENANCE_SOURCES as readonly string[]).includes(source)) ||
      source === "unknown_source"
    ) {
      return "refused_unknown_provenance_source";
    }
    if (source === "governed_evidence") {
      if (
        typeof fact.provenance.evidenceId !== "string" ||
        fact.provenance.evidenceId.length === 0
      ) {
        return "refused_invalid_provenance";
      }
    } else if (fact.provenance.evidenceId !== null) {
      return "refused_invalid_provenance";
    }
    const recordedAt = fact.provenance.recordedAtEpochMs;
    if (
      typeof recordedAt !== "number" ||
      !Number.isFinite(recordedAt) ||
      recordedAt < 0
    ) {
      return "refused_invalid_provenance";
    }
    if (seen.has(fact.subjectNodeId)) {
      return "refused_duplicate_fact";
    }
    seen.add(fact.subjectNodeId);
  }
  return null;
}

// ── reconcile two local world-views ───────────────────────────────────────

/**
 * Reconcile TWO local world-views over ONE epoch. Pinned validation
 * order (first match wins):
 *   1. both views are objects with non-empty view/owner/epoch ids and
 *      an array of facts (`refused_invalid_view`)
 *   2. view-level field bounds (ids, fact count)
 *      (`refused_field_bound`)
 *   3. the two views claim the SAME epoch (`refused_epoch_mismatch`)
 *   4. per-fact, local view first then remote, array order: inner
 *      shape → subject/evidence bounds → fact epoch → state vocab →
 *      provenance rules → duplicate subject
 *   5. merge (pure, sorted by subject):
 *      · same state both sides => agreement, both attributions
 *      · EITHER side terminal (27C) => terminal retained + attributed
 *        conflict — time NEVER decides (no global ordering)
 *      · EITHER side quarantined (27C) => quarantine retained +
 *        attributed conflict (rejoin is not a transition)
 *      · other disagreements => `unknown_observation` + attributed
 *        conflict (no consensus => no invented winner; unknown stays
 *        unknown)
 *      · one side only => that side's claim, attributed to that side
 *   6. success with the no-consensus structural literals
 * Reconciliation mutates NOTHING (both inputs are read and left
 * exactly as they were) and grants nothing.
 */
export function reconcilePartitionViews(
  input: ReconciliationInput,
): ReconciliationDecision {
  const reconciliationHash = canonicalHash({
    schemaVersion: RECONCILIATION_SCHEMA_VERSION,
    reconciliationId: input.reconciliationId,
    localView: input.localView,
    remoteView: input.remoteView,
  });
  const refuse = (
    refusal: ReconciliationRefusalCode,
    explanation?: string,
  ): ReconciliationDecision => ({
    ok: false,
    code: "reconciliation_refused",
    reconciliationId:
      typeof input.reconciliationId === "string" ? input.reconciliationId : "",
    refusal,
    explanation: explanation ?? REFUSAL_EXPLANATIONS[refusal],
    reconciliationHash,
  });

  const local = input.localView;
  const remote = input.remoteView;
  // 1. view-level shape
  for (const view of [local, remote]) {
    if (view === null || typeof view !== "object") {
      return refuse("refused_invalid_view");
    }
    if (
      !isNonEmptyString(view.viewId) ||
      !isNonEmptyString(view.ownerNodeId) ||
      !isNonEmptyString(view.epochId) ||
      !Array.isArray(view.facts)
    ) {
      return refuse("refused_invalid_view");
    }
  }
  // 2. view-level bounds
  for (const view of [local, remote]) {
    if (
      view.viewId.length > RECONCILIATION_BOUNDS.maxViewIdChars ||
      view.ownerNodeId.length > RECONCILIATION_BOUNDS.maxNodeChars ||
      view.facts.length > RECONCILIATION_BOUNDS.maxFactsPerView
    ) {
      return refuse("refused_field_bound");
    }
  }
  // 3. one epoch (no cross-epoch reconciliation)
  if (local.epochId !== remote.epochId) {
    return refuse("refused_epoch_mismatch");
  }
  // 4. per-fact validation (local first, then remote)
  const localSeen = new Set<string>();
  const localFailure = validateViewFacts(local, localSeen);
  if (localFailure !== null) {
    return refuse(localFailure);
  }
  const remoteSeen = new Set<string>();
  const remoteFailure = validateViewFacts(remote, remoteSeen);
  if (remoteFailure !== null) {
    return refuse(remoteFailure);
  }

  // 5. merge (pure; sorted by subject; local attribution first)
  const localBySubject = new Map<string, PartitionFact>();
  for (const fact of local.facts) {
    localBySubject.set(fact.subjectNodeId, fact);
  }
  const remoteBySubject = new Map<string, PartitionFact>();
  for (const fact of remote.facts) {
    remoteBySubject.set(fact.subjectNodeId, fact);
  }
  const subjects = [...new Set([...localBySubject.keys(), ...remoteBySubject.keys()])].sort();

  const attribute = (ownerNodeId: string, fact: PartitionFact): FactAttribution =>
    Object.freeze({
      ownerNodeId,
      state: fact.state,
      source: fact.provenance.source,
      evidenceId: fact.provenance.evidenceId,
      recordedAtEpochMs: fact.provenance.recordedAtEpochMs,
    });

  const mergedFacts: MergedFact[] = [];
  const conflicts: ReconciliationConflict[] = [];
  let agreementCount = 0;
  let localExclusiveCount = 0;
  let remoteExclusiveCount = 0;

  for (const subject of subjects) {
    const localFact = localBySubject.get(subject);
    const remoteFact = remoteBySubject.get(subject);
    if (localFact !== undefined && remoteFact !== undefined) {
      if (localFact.state === remoteFact.state) {
        agreementCount += 1;
        mergedFacts.push(
          Object.freeze({
            subjectNodeId: subject,
            state: localFact.state,
            conflicted: false,
            attributions: Object.freeze([
              attribute(local.ownerNodeId, localFact),
              attribute(remote.ownerNodeId, remoteFact),
            ]),
          }),
        );
        continue;
      }
      let state: TopologyObservationState;
      let resolution: ConflictResolution;
      if (
        (TOPOLOGY_TERMINAL_OBSERVATION_STATES as readonly string[]).includes(
          localFact.state,
        ) ||
        (TOPOLOGY_TERMINAL_OBSERVATION_STATES as readonly string[]).includes(
          remoteFact.state,
        )
      ) {
        // Terminal protection: stale (or even fresher) data never resurrects.
        state = TOPOLOGY_TERMINAL_OBSERVATION_STATES[0] as TopologyObservationState;
        resolution = "terminal_retained";
      } else if (
        (TOPOLOGY_QUARANTINE_OBSERVATION_STATES as readonly string[]).includes(
          localFact.state,
        ) ||
        (TOPOLOGY_QUARANTINE_OBSERVATION_STATES as readonly string[]).includes(
          remoteFact.state,
        )
      ) {
        // Quarantine never auto-clears on rejoin.
        state = TOPOLOGY_QUARANTINE_OBSERVATION_STATES[0] as TopologyObservationState;
        resolution = "quarantine_retained";
      } else {
        // No consensus => no invented winner; unknown stays unknown.
        state = "unknown_observation";
        resolution = "no_consensus_unknown";
      }
      conflicts.push(
        Object.freeze({
          subjectNodeId: subject,
          localState: localFact.state,
          remoteState: remoteFact.state,
          localOwnerNodeId: local.ownerNodeId,
          remoteOwnerNodeId: remote.ownerNodeId,
          localRecordedAtEpochMs: localFact.provenance.recordedAtEpochMs,
          remoteRecordedAtEpochMs: remoteFact.provenance.recordedAtEpochMs,
          resolution,
        }),
      );
      mergedFacts.push(
        Object.freeze({
          subjectNodeId: subject,
          state,
          conflicted: true,
          attributions: Object.freeze([
            attribute(local.ownerNodeId, localFact),
            attribute(remote.ownerNodeId, remoteFact),
          ]),
        }),
      );
      continue;
    }
    if (localFact !== undefined) {
      localExclusiveCount += 1;
      mergedFacts.push(
        Object.freeze({
          subjectNodeId: subject,
          state: localFact.state,
          conflicted: false,
          attributions: Object.freeze([attribute(local.ownerNodeId, localFact)]),
        }),
      );
    } else if (remoteFact !== undefined) {
      remoteExclusiveCount += 1;
      mergedFacts.push(
        Object.freeze({
          subjectNodeId: subject,
          state: remoteFact.state,
          conflicted: false,
          attributions: Object.freeze([attribute(remote.ownerNodeId, remoteFact)]),
        }),
      );
    }
  }

  // 6. success — merging knowledge agrees nothing, orders nothing,
  // resumes nothing, transfers nothing (structural literals)
  const merged: MergedKnowledgeView = Object.freeze({
    viewId: input.reconciliationId,
    epochId: local.epochId,
    facts: Object.freeze(mergedFacts),
  });
  return {
    ok: true,
    code: "views_reconciled",
    reconciliationId: input.reconciliationId,
    merged,
    conflicts: Object.freeze(conflicts),
    agreementCount,
    localExclusiveCount,
    remoteExclusiveCount,
    authority: "none",
    consensusReached: false,
    globalOrdering: false,
    autoResumed: false,
    trustTransferred: false,
    explanation:
      "views '" +
      local.viewId +
      "' and '" +
      remote.viewId +
      "' reconciled over epoch '" +
      local.epochId +
      "' — " +
      mergedFacts.length +
      " merged fact(s): " +
      agreementCount +
      " agreement, " +
      conflicts.length +
      " conflict(s) ATTRIBUTED (both claims kept; terminal/quarantine retained, no-consensus unknown), " +
      localExclusiveCount +
      " local-exclusive, " +
      remoteExclusiveCount +
      " remote-exclusive — NO consensus, NO global ordering, NO auto-resume, NO trust transfer: each node keeps its own world-view and the merged view is knowledge with authority 'none'. Every execution still requires fresh LOCAL allocation + fresh LOCAL Policy for the assigned actor + frozen Phase-20/21.",
    reconciliationHash,
  };
}
