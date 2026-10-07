/**
 * PHASE 28J — END-TO-END GETIG SCENARIO
 * (MENOG EVIDENCE → GETIG FRAME / RENDERER-NEUTRAL / READ-ONLY / NO CONTROL PLANE)
 *
 * Every earlier Phase-28 gate proved ONE link in isolation. This gate runs them
 * as they will actually be used — chained, on one world, in the order a renderer
 * would consume them — and asks the only question that matters about a chain:
 *
 *   DOES THE WHOLE CHAIN ADD ANYTHING THE PARTS DID NOT ALREADY REFUSE?
 *
 * The answer has to be demonstrated, not asserted, so this module builds its
 * world from the REAL frozen upstream: `buildMeshObservabilitySnapshot` (27H)
 * feeds `projectObservabilitySnapshot` (28B), and every visible artifact is
 * produced by a real Phase-28 builder. Nothing here is a fixture, a stub, a
 * hand-rolled frame or a mock. There is no `if (mock) ...` in this file, and
 * there is no path by which one could be added: the runner takes no evidence
 * input at all (see `runGetigEndToEndScenario`).
 *
 * ── the separation law, restated for the chain ────────────────────────────────
 *
 *   RUNTIME_STATE != EVIDENCE != OBSERVATION != PROJECTION != VISIBLE_WORLD
 *                != VISUAL_TOKEN != INSPECTION != DISCLOSURE != AUTHORITY
 *                != EXECUTION
 *
 * Each arrow below is a real call into a real module, and each is separately
 * asserted to carry its own structural zero:
 *
 *   27H snapshot → 28B projection → 28A frame → 28D visual mapping
 *                          ↓             ↓          ↓
 *                    28E observer views  28C sequence  28F provenance graph
 *                          ↓                         ↓
 *                    28G inspection runtime    28H disclosure gate
 *                          ↓
 *                    28I adversarial suite (run against the artifacts above)
 *
 * ── what this gate deliberately does NOT do ──────────────────────────────────
 *
 * It is NOT physical-LAN validation. D-26-1 (two-machine LAN evidence) remains
 * OPEN, so this scenario proves the REPRESENTATION chain over in-process frozen
 * snapshots and says so in a structural literal (`physicalLanValidation: false`)
 * rather than in a comment. Every observation here is single-process and
 * caller-supplied; no packet, no socket and no second machine is involved.
 *
 * Mother invariant for this phase:
 *   VISIBLE WORLD IS A PROJECTION OF EVIDENCE, NOT A SOURCE OF TRUTH OR AUTHORITY.
 */
import { canonicalHash } from "./canonical.js";
import {
  buildMeshObservabilitySnapshot,
  type ObservabilityInput,
  type ObservabilitySnapshot,
} from "./meshObservability.js";
import { projectObservabilitySnapshot } from "./getigEntityProjection.js";
import {
  buildGetigFrame,
  GETIG_REFUSAL_EXPLANATIONS,
  type GetigFrame,
  type GetigFrameDecision,
  type VisibleEntity,
  type VisibleEvent,
  type VisibleObserverContext,
  type VisibleProposalFlow,
  type VisibleProvenanceRef,
  type VisibleRelation,
  type VisibleRefusal,
} from "./getigRepresentation.js";
import {
  buildGetigVisualMapping,
  planGetigPresentationCoarsening,
  refuseVisualSelectionToPermission,
  type CoarseningDecision,
  type GetigVisualMapping,
} from "./getigVisualMapping.js";
import {
  buildGetigObserverView,
  buildGetigMultiView,
  compareGetigObserverViews,
  refuseGlobalTruthSynthesis,
  type ComparisonDecision,
  type GetigMultiView,
  type GetigObserverView,
  type MultiViewDecision,
  type ViewDecision,
} from "./getigObserverViews.js";
import {
  buildGetigFrameSequence,
  diffGetigFrames,
  refuseResumeFromFrame,
  type DiffDecision,
  type GetigFrameSequence,
  type SemanticDiff,
  type SequenceDecision,
} from "./getigTemporalFrames.js";
import {
  buildGetigExplanationGraph,
  explainGetigSubject,
  refuseProvenanceAsTrust,
  type ExplainDecision,
  type GetigExplanationGraph,
  type SubjectExplanation,
} from "./getigProvenance.js";
import {
  inspect,
  refuseInspectionAsControl,
  type InspectionDecision,
} from "./getigInspectionRuntime.js";
import {
  disclose,
  type GetigDisclosureDecision,
  type GetigDisclosureFrame,
} from "./getigDisclosureGate.js";
import {
  hashAdversarialRun,
  runAdversarialSuite,
  type AttackInput,
  type AdversarialSummary,
} from "./getigAdversarialHarness.js";

// ── identity ─────────────────────────────────────────────────────────────────

export const GETIG_E2E_SCHEMA_VERSION = "menog-getig-e2e/v0" as const;

/**
 * The chain, in execution order. Declared as data so a test can assert that
 * every stage really ran rather than inferring it from the artifacts present.
 */
export const GETIG_E2E_CHAIN = Object.freeze([
  "27h_observability_snapshot",
  "28b_entity_projection",
  "28a_getig_frame",
  "28d_visual_mapping",
  "28e_observer_view",
  "28e_view_comparison",
  "28c_frame_sequence",
  "28f_provenance_graph",
  "28g_inspection_runtime",
  "28h_disclosure_gate",
  "28i_adversarial_suite",
] as const);
export type GetigEndToEndChainStage = (typeof GETIG_E2E_CHAIN)[number];

/**
 * Every element the 28J prompt asks the scenario to contain "where supported by
 * real upstream evidence". Named as a closed set so that "present" and "absent"
 * are both reportable: an element that could not be evidenced is `false`, not
 * quietly omitted, because a silent omission reads as a pass.
 */
export const GETIG_E2E_SCENARIO_ELEMENTS = Object.freeze([
  "multiple_runtime_mesh_nodes",
  "agent_task_proposal_representations",
  "explicit_topology",
  "planned_route",
  "origin_forwarder_destination_roles",
  "capability_advertisement_as_untrusted_claim",
  "policy_gate_and_refusal_state",
  "partition_and_divergent_observer_views",
  "restart_recovery_producing_later_frame",
  "stale_and_unknown_state",
  "provenance_trace",
  "timeline_and_semantic_diff",
  "read_only_inspection_filter_compare",
] as const);
export type GetigEndToEndScenarioElement = (typeof GETIG_E2E_SCENARIO_ELEMENTS)[number];

/** The nine laws the 28J prompt requires the chain to PROVE. */
export const GETIG_E2E_PROOFS = Object.freeze([
  "getig_adds_no_authority",
  "no_visual_to_runtime_action_path",
  "execution_still_requires_frozen_local_authority_chain",
  "visual_replay_is_non_executable",
  "observer_views_are_distinct",
  "conflict_stays_visible",
  "secrets_and_raw_content_absent",
  "hashes_consistent",
  "renderer_dependency_zero",
] as const);
export type GetigEndToEndProof = (typeof GETIG_E2E_PROOFS)[number];

// ── refusal vocabulary (closed; every code reachable) ────────────────────────

export const GETIG_E2E_REFUSAL_CODES = Object.freeze([
  "refused_e2e_input_invalid",
  "refused_e2e_evidence_refused",
  "refused_e2e_projection_refused",
  "refused_e2e_frame_refused",
  "refused_e2e_view_refused",
  "refused_e2e_sequence_refused",
  "refused_e2e_graph_refused",
  "refused_e2e_mapping_refused",
  "refused_e2e_inspection_refused",
  "refused_e2e_disclosure_refused",
  "refused_e2e_adversarial_bypass",
  "refused_e2e_proof_failed",
  "refused_e2e_non_deterministic",
] as const);
export type GetigEndToEndRefusalCode = (typeof GETIG_E2E_REFUSAL_CODES)[number];

const REFUSAL_EXPLANATIONS: Readonly<Record<GetigEndToEndRefusalCode, string>> = Object.freeze({
  refused_e2e_input_invalid:
    "the scenario runner was called with something other than no options — refusing. This scenario's evidence is FIXED on purpose: a caller-chosen evidence set would let the scenario grade its own homework.",
  refused_e2e_evidence_refused:
    "the frozen 27H observability snapshot refused its input — refusing. No partial scenario is produced from unbuilt evidence.",
  refused_e2e_projection_refused:
    "the 28B entity projection refused the snapshot — refusing. A partial projection would be an invented world.",
  refused_e2e_frame_refused:
    "the 28A frame builder refused the visible content — refusing. No partial frame is ever published.",
  refused_e2e_view_refused:
    "the 28E observer-view builder refused — refusing. A view is the unit of honesty here; a partial view would read as a complete one.",
  refused_e2e_sequence_refused:
    "the 28C sequence builder refused the in-epoch frames — refusing. A timeline assembled from frames the sequence itself rejects is a chronology nobody established.",
  refused_e2e_graph_refused:
    "the 28F provenance-graph builder refused — refusing. An explanation of a subject it could not read is worse than no explanation.",
  refused_e2e_mapping_refused:
    "the 28D visual mapping refused — refusing. Tokens are the renderer's whole input; a partial token set would let a renderer draw a claim that was never made.",
  refused_e2e_inspection_refused:
    "an inspection the scenario requires returned a refusal — refusing. The chain proves a read path, so a refused read is a broken chain, not a tolerated outcome.",
  refused_e2e_disclosure_refused:
    "the 28H disclosure gate refused the frame's records — refusing. There is no redacted-but-returned outcome to fall back to.",
  refused_e2e_adversarial_bypass:
    "the 28I adversarial suite reported an attack that achieved its stated goal against THIS scenario's real artifacts — refusing. A bypass in the composed chain is a critical failure of the whole phase, not a note.",
  refused_e2e_proof_failed:
    "one of the nine end-to-end proofs did not hold against the artifacts this scenario actually built — refusing. An end-to-end gate that reports success while a proof is false is worse than no gate.",
  refused_e2e_non_deterministic:
    "the scenario did not reproduce its own hash on a second construction from identical inputs — refusing. Determinism is law 11 of this phase; a non-reproducible scenario proves nothing.",
});

// ── decisions ────────────────────────────────────────────────────────────────

export interface GetigEndToEndStageRefusal {
  readonly stage: string;
  /** The upstream module's own refusal token, carried verbatim, never flattened. */
  readonly upstreamRefusal: string;
}

export type GetigEndToEndScenarioComplete = {
  readonly ok: true;
  readonly code: "end_to_end_scenario_complete";
  readonly scenario: GetigEndToEndScenario;
  readonly authority: "none";
  readonly readOnly: true;
};

export type GetigEndToEndScenarioRefused = {
  readonly ok: false;
  readonly code: "end_to_end_scenario_refused";
  readonly refusal: GetigEndToEndRefusalCode;
  readonly explanation: string;
  readonly cause: GetigEndToEndStageRefusal | null;
  /** Structural: a refusal publishes nothing at all — not a partial scenario. */
  readonly scenario: null;
  readonly partialScenarioEmitted: false;
  readonly authority: "none";
  readonly readOnly: true;
};

export type GetigEndToEndScenarioDecision =
  | GetigEndToEndScenarioComplete
  | GetigEndToEndScenarioRefused;

export interface GetigEndToEndElementReport {
  readonly element: GetigEndToEndScenarioElement;
  readonly present: boolean;
  /** What was actually built, named by id, so the claim is checkable. */
  readonly evidence: readonly string[];
}

export interface GetigEndToEndProofReport {
  readonly proof: GetigEndToEndProof;
  readonly holds: boolean;
  readonly evidence: string;
}

export interface GetigEndToEndInspectionReport {
  readonly name: string;
  readonly operation: string;
  readonly ok: boolean;
  /** The upstream refusal token on a refusal, or the decision's own code. */
  readonly outcome: string;
}

/** One deliberate, reachable refusal. Never fabricated, never softened. */
export interface GetigEndToEndAttempt {
  readonly name: string;
  readonly goal: string;
  readonly refused: true;
  readonly outcome: string;
}

export interface GetigEndToEndObservation {
  readonly id: string;
  readonly finding: string;
  /** `blocking` would fail the gate. Recorded findings here are honest debt. */
  readonly severity: "informational" | "non_blocking_defect";
}

export interface GetigEndToEndScenario {
  readonly schemaVersion: typeof GETIG_E2E_SCHEMA_VERSION;
  readonly scenarioId: string;
  readonly runtimeId: string;
  /** The pre-restart governance epoch. */
  readonly epochId: string;
  /** The post-restart epoch. A restart opens a new epoch; it does not continue one. */
  readonly recoveryEpochId: string;
  readonly observerIds: readonly string[];
  readonly chain: readonly GetigEndToEndChainStage[];

  // ── upstream evidence (real 27H snapshots, hashed) ──
  readonly snapshotLocalHash: string;
  readonly snapshotRemoteHash: string;
  readonly snapshotLaterHash: string;
  readonly snapshotRecoveryHash: string;

  // ── 28A/28B frames ──
  readonly frame: GetigFrame;
  readonly frameLater: GetigFrame;
  readonly frameRecovery: GetigFrame;
  readonly frameRemote: GetigFrame;

  // ── 28E ──
  readonly viewLocal: GetigObserverView;
  readonly viewRemote: GetigObserverView;
  readonly comparison: import("./getigObserverViews.js").ViewComparison;
  readonly multiView: GetigMultiView;
  readonly synthesisRefusal: ReturnType<typeof refuseGlobalTruthSynthesis>;

  // ── 28C ──
  readonly sequence: GetigFrameSequence;
  readonly diff: SemanticDiff;
  readonly diffAcrossRestart: SemanticDiff;
  /** The cross-epoch sequence attempt. Recorded so the refusal is evidence. */
  readonly crossEpochSequenceRefusal: {
    readonly refused: true;
    readonly refusal: string;
    readonly explanation: string;
  };
  readonly resumeRefusal: ReturnType<typeof refuseResumeFromFrame>;

  // ── 28D ──
  readonly mapping: GetigVisualMapping;
  readonly coarseningApproved: CoarseningDecision;
  readonly coarseningStrengtheningRefusal: CoarseningDecision;
  readonly coarseningSuppressionRefusal: CoarseningDecision;
  readonly selectionRefusal: ReturnType<typeof refuseVisualSelectionToPermission>;

  // ── 28F ──
  readonly graph: GetigExplanationGraph;
  readonly trace: SubjectExplanation;
  readonly traceByGraphKey: SubjectExplanation;
  readonly trustRefusal: ReturnType<typeof refuseProvenanceAsTrust>;

  // ── 28G ──
  readonly inspections: readonly GetigEndToEndInspectionReport[];
  readonly successfulInspections: number;
  readonly controlRefusal: InspectionDecision;

  // ── 28H ──
  readonly disclosure: GetigDisclosureFrame;
  readonly disclosureRecords: number;
  readonly disclosureFields: number;
  readonly secretDisclosureRefusal: GetigDisclosureDecision;
  readonly nestedValueDisclosureRefusal: GetigDisclosureDecision;

  // ── 28I ──
  readonly adversarial: AdversarialSummary;
  readonly adversarialRunHash: string;

  /** Attempts that MUST refuse. Each one is a law given an exit code. */
  readonly refusedAttempts: readonly GetigEndToEndAttempt[];
  readonly elements: readonly GetigEndToEndElementReport[];
  readonly proofs: readonly GetigEndToEndProofReport[];
  readonly observations: readonly GetigEndToEndObservation[];

  readonly elementCount: number;
  readonly proofCount: number;
  readonly passedProofCount: number;
  readonly failedProofs: readonly GetigEndToEndProof[];

  /**
   * D-26-1 (physical two-machine LAN evidence) is still OPEN. This scenario is
   * in-process and says so structurally, so no downstream reader can mistake it
   * for hardware evidence.
   */
  readonly physicalLanValidation: false;
  readonly singleProcess: true;
  readonly networkCallsMade: 0;

  readonly scenarioHash: string;

  // ── the structural zeros, restated on the composed artifact ──
  readonly authority: "none";
  readonly controlPlane: false;
  readonly readOnly: true;
  readonly createsActionPath: false;
  readonly grantsNothing: true;
  readonly globalTruth: false;
  readonly replaySemantics: "visual_history_not_executable";
}

// ── helpers ──────────────────────────────────────────────────────────────────

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const list = <T>(items: readonly T[]): readonly T[] => Object.freeze([...items]);

// ── the world: fixed instants ────────────────────────────────────────────────
//
// No clock is read anywhere in this file. Every instant is a constant, so the
// scenario is reproducible byte-for-byte on any machine at any time.

const T0 = 1_700_000_000_000;
const T1 = T0 + 120_000;
const T_RESTART = T0 + 900_000;

const RUNTIME_ID = "runtime-28j-1";
const EPOCH_A = "epoch-28j-a";
const EPOCH_B = "epoch-28j-b";
const OBSERVER_LOCAL = "observer-local-a";
const OBSERVER_REMOTE = "observer-remote-b";

/** Older than 27H's 300 s freshness window, so the projection reads `stale`. */
const AGED = T0 - 600_000;

const localObserver = (epochId: string): VisibleObserverContext =>
  Object.freeze({ observerId: OBSERVER_LOCAL, observerKind: "local_runtime" as const, epochId, isGlobalTruth: false as const });

/**
 * The remote vantage's frame context.
 *
 * NOTE (see `GETIG_E2E_OBSERVATIONS`): 28A's closed observer-kind vocabulary is
 * `local_runtime | local_operator | offline_reader` and has NO `remote_runtime`,
 * while 28E's view vocabulary IS `local_runtime | remote_runtime`. A remote
 * runtime reading a relayed snapshot therefore has to declare itself an
 * `offline_reader` at frame level. That is a real vocabulary gap between two
 * frozen gates. 28J does NOT paper over it by widening either vocabulary, and
 * does not silently mislabel the vantage as local: it declares the reading
 * honestly and records the gap for 28K.
 */
const remoteObserver = (epochId: string): VisibleObserverContext =>
  Object.freeze({ observerId: OBSERVER_REMOTE, observerKind: "offline_reader" as const, epochId, isGlobalTruth: false as const });

const prov = (refId: string, atEpochMs: number): VisibleProvenanceRef =>
  Object.freeze({
    refId,
    recordedAtEpochMs: atEpochMs,
    sourceKind: "governed_evidence" as const,
    evidenceId: refId,
    // Structural, on every single ref: a citation is not a vouch.
    confersTrust: false as const,
  });

const localProv = (refId: string): VisibleProvenanceRef =>
  Object.freeze({
    refId,
    recordedAtEpochMs: T0,
    sourceKind: "local_configuration" as const,
    // Explicitly null: local configuration must not pretend to cite evidence.
    evidenceId: null,
    confersTrust: false as const,
  });

// ── the upstream evidence (real 27H inputs, built by the real builder) ──────

const nodeInput = (
  nodeId: string,
  epochId: string,
  observationState: ObservabilityInput["nodes"][number]["observationState"],
  recordedAtEpochMs: number,
): ObservabilityInput["nodes"][number] => ({
  nodeId,
  kind: "observed_node",
  epochId,
  observationState,
  provenance: { source: "governed_evidence", evidenceId: `ev-${nodeId}`, recordedAtEpochMs },
});

const edgeInput = (edgeId: string, fromNodeId: string, toNodeId: string, epochId: string): ObservabilityInput["edges"][number] => ({
  edgeId,
  fromNodeId,
  toNodeId,
  kind: "observed_edge",
  epochId,
  provenance: { source: "governed_evidence", evidenceId: `ev-${edgeId}`, recordedAtEpochMs: T0 },
});

/** A planned multi-hop route: origin, one forwarder, destination. Inert. */
const routeInput = (routeId: string, origin: string, forwarder: string, destination: string, epochId: string): ObservabilityInput["routes"][number] => ({
  epochId,
  route: {
    routeId,
    state: "route_planned",
    origin: { nodeId: origin, originFixed: true },
    hops: [
      { hopIndex: 0, nodeId: origin, role: "origin" },
      { hopIndex: 1, nodeId: forwarder, role: "forwarder" },
      { hopIndex: 2, nodeId: destination, role: "destination" },
    ],
    destination: { nodeId: destination, role: "destination" },
    observedAtEpochMs: T0,
  },
});

const refusalInput = (subjectId: string, code: string, epochId: string): ObservabilityInput["refusals"][number] => ({
  subjectId,
  code,
  epochId,
});

/** A reconciliation that still carries its conflict. Never smoothed away. */
const partitionInput = (epochId: string): ObservabilityInput["partitions"][number] => ({
  reconciliationId: "recon-28j-1",
  epochId,
  agreementCount: 1,
  localExclusiveCount: 1,
  remoteExclusiveCount: 0,
  conflicts: [
    {
      subjectNodeId: "node-remote",
      localState: "quarantined_observation",
      remoteState: "observed",
      resolution: "quarantine_retained",
      localRecordedAtEpochMs: T0,
      remoteRecordedAtEpochMs: T0 - 45_000,
    },
  ],
});

/**
 * The LOCAL vantage at T0: three observed nodes, a planned route through a
 * forwarder, an aged relay that will read `stale`, a quarantined destination,
 * one recorded upstream refusal, and one unreconciled partition.
 */
const localEvidenceAtT0 = (): ObservabilityInput => ({
  snapshotId: "snap-28j-local-t0",
  epochId: EPOCH_A,
  asOfEpochMs: T0,
  nodes: [
    nodeInput("node-local", EPOCH_A, "observed", T0 - 1_000),
    nodeInput("node-relay", EPOCH_A, "observed", AGED),
    nodeInput("node-remote", EPOCH_A, "quarantined_observation", T0 - 2_000),
  ],
  edges: [
    edgeInput("edge-local-relay", "node-local", "node-relay", EPOCH_A),
    edgeInput("edge-relay-remote", "node-relay", "node-remote", EPOCH_A),
  ],
  routes: [routeInput("route-28j-1", "node-local", "node-relay", "node-remote", EPOCH_A)],
  refusals: [refusalInput("node-remote", "refused_unknown", EPOCH_A)],
  partitions: [partitionInput(EPOCH_A)],
});

/**
 * The REMOTE vantage over the SAME epoch. It sees a different world: it has
 * quarantined the local node, does not know the relay at all, and observed the
 * destination directly. Two real snapshots, two real projections, one genuine
 * disagreement — nothing here was written to make the comparison interesting.
 */
const remoteEvidenceAtT0 = (): ObservabilityInput => ({
  snapshotId: "snap-28j-remote-t0",
  epochId: EPOCH_A,
  asOfEpochMs: T0,
  nodes: [
    nodeInput("node-local", EPOCH_A, "quarantined_observation", T0 - 3_000),
    nodeInput("node-relay", EPOCH_A, "unknown_observation", T0 - 3_000),
    nodeInput("node-remote", EPOCH_A, "observed", T0 - 3_000),
  ],
  edges: [edgeInput("edge-relay-remote", "node-relay", "node-remote", EPOCH_A)],
  routes: [],
  refusals: [refusalInput("node-local", "refused_duplicate_entry", EPOCH_A)],
  partitions: [],
});

/**
 * The same world observed AGAIN, later, still inside epoch A. The relay has
 * retired; the destination's state is now unknown to the local runtime. The
 * partition is still unreconciled, so the conflict stays visible across time
 * rather than quietly resolving itself between two frames.
 */
const localEvidenceAtT1 = (): ObservabilityInput => ({
  snapshotId: "snap-28j-local-t1",
  epochId: EPOCH_A,
  asOfEpochMs: T1,
  nodes: [
    nodeInput("node-local", EPOCH_A, "observed", T1 - 1_000),
    nodeInput("node-relay", EPOCH_A, "retired_observation", T1 - 1_000),
    // Recorded AFTER the frame's own instant, so the upstream freshness
    // classifier cannot order it and it projects as `unknown` rather than being
    // quietly rounded to fresh. "Unknown stays unknown" is only demonstrated if
    // there is a real path to unknown, and an unorderable record time is it.
    nodeInput("node-remote", EPOCH_A, "unknown_observation", T1 + 60_000),
  ],
  edges: [
    edgeInput("edge-local-relay", "node-local", "node-relay", EPOCH_A),
    edgeInput("edge-relay-remote", "node-relay", "node-remote", EPOCH_A),
  ],
  routes: [routeInput("route-28j-1", "node-local", "node-relay", "node-remote", EPOCH_A)],
  refusals: [refusalInput("node-remote", "refused_unknown", EPOCH_A)],
  partitions: [partitionInput(EPOCH_A)],
});

/**
 * AFTER A RESTART. The runtime comes back in a NEW epoch, and it comes back not
 * knowing the things it knew before: no route was re-planned, and the relay and
 * destination are unknown rather than stale. Recovery produced a later frame,
 * and it is honest about what recovery does not restore.
 */
const localEvidenceAfterRestart = (): ObservabilityInput => ({
  snapshotId: "snap-28j-local-restart",
  epochId: EPOCH_B,
  asOfEpochMs: T_RESTART,
  nodes: [
    nodeInput("node-local", EPOCH_B, "observed", T_RESTART - 500),
    nodeInput("node-relay", EPOCH_B, "unknown_observation", T_RESTART - 500),
    nodeInput("node-remote", EPOCH_B, "unknown_observation", T_RESTART - 500),
  ],
  edges: [edgeInput("edge-local-relay", "node-local", "node-relay", EPOCH_B)],
  routes: [],
  refusals: [refusalInput("node-remote", "refused_unknown", EPOCH_B)],
  partitions: [partitionInput(EPOCH_B)],
});

export const GETIG_E2E_INSTANTS = Object.freeze({
  t0: T0,
  t1: T1,
  afterRestart: T_RESTART,
  agedRecord: AGED,
  epochA: EPOCH_A,
  epochB: EPOCH_B,
  runtimeId: RUNTIME_ID,
  observerLocal: OBSERVER_LOCAL,
  observerRemote: OBSERVER_REMOTE,
});

/** The four real evidence builders, exported so a test can rebuild them itself. */
export const GETIG_E2E_EVIDENCE = Object.freeze({
  localAtT0: localEvidenceAtT0,
  remoteAtT0: remoteEvidenceAtT0,
  localAtT1: localEvidenceAtT1,
  localAfterRestart: localEvidenceAfterRestart,
});
// ── the authored semantic layer ──────────────────────────────────────────────
//
// Everything above this line is DERIVED from frozen upstream evidence by 27H and
// 28B. Everything below is caller-supplied SEMANTIC CONTENT: what the local
// runtime says about ITSELF — its agent, its goal, the task in flight, the
// proposal it forwarded, the policy gate in front of it, the execution boundary
// it has not crossed, and the tool it merely references.
//
// The distinction matters and is stated rather than blurred: no frozen upstream
// produces "goals", so these entities cannot come from the projection. They go
// through the SAME real 28A builder as everything else, which means every
// structural zero below is enforced by the builder rather than by this file's
// good manners. The content is authored; the constraints are not.

const authoredEntities = (): readonly VisibleEntity[] =>
  list<VisibleEntity>([
    {
      visibleId: "agent:planner",
      kind: "agent",
      label: "local planner agent",
      isRuntimeObject: false,
      grant: "none",
      freshness: "current",
      lifecycle: "observed",
      provenanceRefs: [localProv("prov-agent-planner")],
      representsRuntimeId: "runtime-local-planner",
    },
    {
      visibleId: "goal:28j-1",
      kind: "goal",
      label: "produce one admitted route",
      isRuntimeObject: false,
      grant: "none",
      freshness: "current",
      lifecycle: "observed",
      provenanceRefs: [localProv("prov-goal-28j-1")],
      representsRuntimeId: null,
    },
    {
      visibleId: "task:plan-route",
      kind: "task",
      label: "plan route to the remote node",
      isRuntimeObject: false,
      grant: "none",
      freshness: "current",
      lifecycle: "observed",
      provenanceRefs: [prov("ev-task-plan-route", T0)],
      representsRuntimeId: null,
    },
    {
      visibleId: "tool:local-shell",
      kind: "tool_reference",
      label: "local governed tool runtime",
      isRuntimeObject: false,
      grant: "none",
      freshness: "current",
      lifecycle: "observed",
      provenanceRefs: [localProv("prov-tool-local-shell")],
      representsRuntimeId: "tool-governed-runtime",
    },
    {
      visibleId: "policy:execution-gate",
      kind: "policy_gate",
      label: "local policy gate (no decision is carried)",
      isRuntimeObject: false,
      grant: "none",
      freshness: "current",
      lifecycle: "observed",
      provenanceRefs: [localProv("prov-policy-gate")],
      representsRuntimeId: null,
    },
    {
      visibleId: "boundary:phase20-isolation",
      kind: "execution_boundary",
      label: "declared execution boundary",
      isRuntimeObject: false,
      grant: "none",
      freshness: "current",
      lifecycle: "observed",
      provenanceRefs: [localProv("prov-boundary-isolation")],
      representsRuntimeId: null,
    },
    {
      visibleId: "evidence:grant-chain",
      kind: "evidence",
      label: "reference to the frozen local authority chain",
      isRuntimeObject: false,
      grant: "none",
      freshness: "stale",
      lifecycle: "observed",
      provenanceRefs: [prov("ev-grant-chain", AGED)],
      representsRuntimeId: null,
    },
    {
      visibleId: "proposal:forward-1",
      kind: "proposal",
      label: "inert proposal, forwarded by nobody's endorsement",
      isRuntimeObject: false,
      grant: "none",
      freshness: "current",
      lifecycle: "observed",
      provenanceRefs: [prov("ev-proposal-forward-1", T0)],
      representsRuntimeId: null,
    },
    {
      visibleId: "memory:session-log",
      kind: "memory_reference",
      label: "reference to session evidence (never its content)",
      isRuntimeObject: false,
      grant: "none",
      // Freshness is explicitly unknown and it cites NOTHING. Lifecycle is
      // "observed" rather than "unknown" for a reason that is recorded as
      // 28J-OBS-4: 28A accepts lifecycle "unknown" but 28D's lifecycle visual
      // axis has no "unknown" value, so 28D refuses the whole mapping for any
      // frame that contains one. The gap is real, fail-closed and tested in
      // this gate's suite; this entity does not hide it, it merely keeps the
      // main chain buildable while the observation stays on the record.
      freshness: "unknown",
      lifecycle: "observed",
      provenanceRefs: [],
      representsRuntimeId: null,
    },
  ]);

const authoredRelations = (hasRoute: boolean): readonly VisibleRelation[] =>
  list<VisibleRelation>([
    {
      relationId: "rel:task-serves-goal",
      kind: "references",
      fromVisibleId: "task:plan-route",
      toVisibleId: "goal:28j-1",
      trust: "none",
      provenanceRefs: [prov("ev-task-plan-route", T0)],
    },
    {
      relationId: "rel:task-forwards-proposal",
      kind: "forwarded_proposal",
      fromVisibleId: "task:plan-route",
      toVisibleId: "proposal:forward-1",
      trust: "none",
      provenanceRefs: [prov("ev-proposal-forward-1", T0)],
    },
    {
      relationId: "rel:boundary-guards-gate",
      kind: "references",
      fromVisibleId: "boundary:phase20-isolation",
      toVisibleId: "policy:execution-gate",
      trust: "none",
      provenanceRefs: [localProv("prov-boundary-isolation")],
    },
    {
      relationId: "rel:agent-uses-tool",
      kind: "references",
      fromVisibleId: "agent:planner",
      toVisibleId: "tool:local-shell",
      trust: "none",
      provenanceRefs: [localProv("prov-agent-planner")],
    },
    ...(hasRoute
      ? [
          {
            relationId: "rel:route-partitions-from-remote",
            kind: "partitions_from",
            fromVisibleId: "route:route-28j-1",
            toVisibleId: "node-remote",
            trust: "none",
            provenanceRefs: [prov("ev-node-remote", T0 - 2_000)],
          } satisfies VisibleRelation,
        ]
      : []),
  ]);

const authoredEvents = (asOfEpochMs: number, hasRoute: boolean): readonly VisibleEvent[] =>
  list<VisibleEvent>([
    {
      eventId: "evt:node-local-observed",
      kind: "node_observed",
      atEpochMs: asOfEpochMs - 1_000,
      subjectVisibleId: "node-local",
      executable: false,
      action: "none",
      freshness: "current",
    },
    ...(hasRoute
      ? [
          {
            eventId: "evt:route-planned",
            kind: "route_planned",
            atEpochMs: asOfEpochMs - 900,
            subjectVisibleId: "route:route-28j-1",
            executable: false,
            action: "none",
            freshness: "current",
          } satisfies VisibleEvent,
        ]
      : []),
    {
      eventId: "evt:proposal-forwarded",
      kind: "proposal_forwarded",
      atEpochMs: asOfEpochMs - 800,
      subjectVisibleId: "proposal:forward-1",
      executable: false,
      action: "none",
      freshness: "current",
    },
    {
      eventId: "evt:refusal-recorded",
      kind: "refusal_recorded",
      atEpochMs: asOfEpochMs - 700,
      subjectVisibleId: "policy:execution-gate",
      executable: false,
      action: "none",
      freshness: "current",
    },
    {
      eventId: "evt:partition-detected",
      kind: "partition_detected",
      atEpochMs: asOfEpochMs - 600,
      subjectVisibleId: "node-remote",
      executable: false,
      action: "none",
      freshness: "current",
    },
  ]);

const authoredRefusals = (): readonly VisibleRefusal[] =>
  list<VisibleRefusal>([
    {
      refusalId: "refusal:policy-gate",
      code: "refused_unknown_authority_claim",
      subjectVisibleId: "policy:execution-gate",
      explanation: GETIG_REFUSAL_EXPLANATIONS.refused_unknown_authority_claim,
    },
    {
      refusalId: "refusal:unknown-memory",
      code: "refused_missing_projection_hash",
      subjectVisibleId: "memory:session-log",
      explanation: GETIG_REFUSAL_EXPLANATIONS.refused_missing_projection_hash,
    },
  ]);

const authoredProposalFlows = (): readonly VisibleProposalFlow[] =>
  list<VisibleProposalFlow>([{
    proposalId: "proposal:flow-28j-1",
    originVisibleId: "agent:planner",
    forwarderVisibleIds: ["task:plan-route"],
    destinationVisibleId: "boundary:phase20-isolation",
    hopCount: 3,
    endorsement: "none" as const,
    state: "forwarded" as const,
    provenanceRefs: [prov("ev-proposal-forward-1", T0)],
  }]);


// ── internal abort ───────────────────────────────────────────────────────────
//
// The runner must be able to stop at the FIRST upstream refusal and publish
// nothing, and threading a nine-way union through every stage would make that
// harder to read than it needs to be. 28D already established throw-and-catch at
// the builder boundary; this follows the same shape: an internal abort carrying
// WHICH stage refused and WHAT it said, caught once, at the runner.

class ScenarioAbort extends Error {
  constructor(
    readonly refusal: GetigEndToEndRefusalCode,
    readonly stage: string,
    readonly upstreamRefusal: string,
  ) {
    super(`${stage} refused: ${upstreamRefusal}`);
    this.name = "ScenarioAbort";
  }
}

// Declared as a `function` declaration on purpose: TypeScript's control-flow
// narrowing after a never-returning call only applies to function declarations
// and explicitly-typed consts. As an arrow it would not narrow, and every
// downstream `decision.frame` would have to be null-checked by hand — which is
// exactly the sort of hand-holding this gate is arguing against.
function abort(refusal: GetigEndToEndRefusalCode, stage: string, upstreamRefusal: string): never {
  throw new ScenarioAbort(refusal, stage, upstreamRefusal);
}

// ── stage: 27H evidence → 28B projection → 28A frame ────────────────────────

const snapshotOf = (stage: string, input: ObservabilityInput): ObservabilitySnapshot => {
  const decision = buildMeshObservabilitySnapshot(input);
  if (!decision.ok) abort("refused_e2e_evidence_refused", stage, String(decision.refusal));
  return decision.snapshot;
};

/**
 * Compose one visible world: the REAL 28B projection of a REAL 27H snapshot,
 * plus the authored semantic layer, through the REAL 28A builder.
 *
 * `hasRoute` is read from the projection rather than assumed, so a world with no
 * route (the post-restart world) does not grow relations and events that name a
 * route it does not have.
 */
const composeFrame = (
  stage: string,
  snapshot: ObservabilitySnapshot,
  observer: VisibleObserverContext,
  frameId: string,
  asOfEpochMs: number,
): GetigFrame => {
  const projection = projectObservabilitySnapshot({
    frameId: `${frameId}-evidence`,
    observer,
    snapshot,
  });
  if (!projection.ok) abort("refused_e2e_projection_refused", "28b_entity_projection", String(projection.refusal));

  const base = projection.frame;
  const hasRoute = base.routes.length > 0;
  const decision: GetigFrameDecision = buildGetigFrame({
    frameId,
    observer,
    epochId: observer.epochId,
    asOfEpochMs,
    // The upstream projection hash, never a value this module chose.
    sourceProjectionHash: snapshot.projectionHash,
    entities: [...base.entities, ...authoredEntities()],
    relations: [...base.relations, ...authoredRelations(hasRoute)],
    events: [...base.events, ...authoredEvents(asOfEpochMs, hasRoute)],
    refusals: [...base.refusals, ...authoredRefusals()],
    routes: base.routes,
    proposalFlows: authoredProposalFlows(),
    conflicts: base.conflicts,
  });
  if (!decision.ok) abort("refused_e2e_frame_refused", stage, String(decision.refusal));
  return decision.frame;
};

// ── stage: 28E observer views ───────────────────────────────────────────────

const viewOf = (
  stage: string,
  viewId: string,
  observerId: string,
  observerKind: "local_runtime" | "remote_runtime",
  frame: GetigFrame,
): GetigObserverView => {
  const decision: ViewDecision = buildGetigObserverView({
    viewId,
    observerId,
    observerKind,
    runtimeId: RUNTIME_ID,
    epochId: frame.epochId,
    frame,
  });
  if (!decision.ok) abort("refused_e2e_view_refused", stage, String(decision.refusal));
  return decision.view;
};

const multiViewOf = (stage: string, views: readonly GetigObserverView[]): GetigMultiView => {
  const decision: MultiViewDecision = buildGetigMultiView({
    multiViewId: "multiview-28j-1",
    runtimeId: RUNTIME_ID,
    epochId: EPOCH_A,
    views,
  });
  if (!decision.ok) abort("refused_e2e_view_refused", stage, String(decision.refusal));
  return decision.multiView;
};

const comparisonOf = (stage: string, left: GetigObserverView, right: GetigObserverView) => {
  const decision: ComparisonDecision = compareGetigObserverViews({ left, right });
  if (!decision.ok) abort("refused_e2e_view_refused", stage, String(decision.refusal));
  return decision.comparison;
};

// ── stage: 28D visual mapping ───────────────────────────────────────────────

const mappingOf = (stage: string, frame: GetigFrame): GetigVisualMapping => {
  const decision = buildGetigVisualMapping({
    frameId: frame.frameId,
    frame,
    // Route state on 28D's OWN closed vocabulary. The upstream `route_planned`
    // is 27H's word; 28D's word for the same observation is `planned`.
    routeStates: Object.fromEntries(frame.routes.map((r) => [r.routeId, "planned"])),
    // No admission evidence is supplied, and absent evidence is not admission.
    admissionEvidence: {},
    partitions: [{ partitionId: "recon-28j-1", reconciliationId: "recon-28j-1" }],
  });
  if (!decision.ok) abort("refused_e2e_mapping_refused", stage, String(decision.refusal));
  return decision.mapping;
};

// ── stage: 28C temporal ─────────────────────────────────────────────────────

const sequenceOf = (stage: string, frames: readonly GetigFrame[]): GetigFrameSequence => {
  const decision: SequenceDecision = buildGetigFrameSequence({
    sequenceId: "seq-28j-1",
    observerId: OBSERVER_LOCAL,
    epochId: EPOCH_A,
    orderingBasis: "observed_order",
    frames,
  });
  if (!decision.ok) abort("refused_e2e_sequence_refused", stage, String(decision.refusal));
  return decision.sequence;
};

const diffOf = (stage: string, from: GetigFrame, to: GetigFrame): SemanticDiff => {
  const decision: DiffDecision = diffGetigFrames(from, to);
  if (!decision.ok) abort("refused_e2e_sequence_refused", stage, String(decision.refusal));
  return decision.diff;
};

// ── stage: 28F provenance ───────────────────────────────────────────────────

const graphOf = (stage: string, frame: GetigFrame): GetigExplanationGraph => {
  const decision = buildGetigExplanationGraph({
    graphId: "graph-28j-1",
    frame,
    // Metadata only. One record describes a ref that is actually cited, and one
    // describes a ref nobody cited — both are honest; neither is content.
    provenanceRecords: [
      { refId: "ev-node-remote", sourceKind: "governed_evidence", recordedAtEpochMs: T0 - 2_000 },
      { refId: "ev-proposal-forward-1", sourceKind: "governed_evidence", recordedAtEpochMs: T0 },
    ],
  });
  if (!decision.ok) abort("refused_e2e_graph_refused", stage, String(decision.refusal));
  return decision.graph;
};

const traceOf = (stage: string, graph: GetigExplanationGraph, subjectVisibleId: string): SubjectExplanation => {
  const decision: ExplainDecision = explainGetigSubject(graph, subjectVisibleId);
  if (!decision.ok) abort("refused_e2e_graph_refused", stage, String(decision.refusal));
  return decision.trace;
};

// ── stage: 28G inspection ───────────────────────────────────────────────────

const inspectionBinding = (frame: GetigFrame, view: GetigObserverView) => ({
  frameId: frame.frameId,
  observerId: view.observerId,
  canonicalVisibleHash: frame.canonicalVisibleHash,
  viewHash: view.viewHash,
});

const inspectOnce = (
  _stage: string,
  query: unknown,
  ctx: {
    readonly view: GetigObserverView;
    readonly sequence: GetigFrameSequence;
    readonly graph: GetigExplanationGraph;
    readonly binding: ReturnType<typeof inspectionBinding>;
  },
): InspectionDecision => inspect({ query, view: ctx.view, sequence: ctx.sequence, graph: ctx.graph, binding: ctx.binding });


// ── the assembled artifacts ──────────────────────────────────────────────────

interface ScenarioArtifacts {
  readonly frame: GetigFrame;
  readonly frameLater: GetigFrame;
  readonly frameRecovery: GetigFrame;
  readonly frameRemote: GetigFrame;
  readonly viewLocal: GetigObserverView;
  readonly viewRemote: GetigObserverView;
  readonly multiView: GetigMultiView;
  readonly comparison: ReturnType<typeof comparisonOf>;
  readonly sequence: GetigFrameSequence;
  readonly diff: SemanticDiff;
  readonly diffAcrossRestart: SemanticDiff;
  readonly mapping: GetigVisualMapping;
  readonly graph: GetigExplanationGraph;
  readonly trace: SubjectExplanation;
}

// ── 28I: attacks run against THIS scenario's real artifacts ──────────────────
//
// These are not the 28I catalogue's canned cases. Each one aims at something the
// composed chain actually produced, so a defence that only holds for a synthetic
// fixture cannot be counted here. Every attack declares its own goal; the
// mechanical scorer derives the verdict from whether that goal was achieved, so
// no attacker-chosen label can become a PASS.

const scenarioAttacks = (a: ScenarioArtifacts): readonly AttackInput[] => {
  const binding = inspectionBinding(a.frame, a.viewLocal);
  const context = { view: a.viewLocal, sequence: a.sequence, graph: a.graph, binding };
  const tamperedFrame: Record<string, unknown> = {
    ...a.frame,
    authority: "full",
    controlPlane: true,
    visibleCapabilities: ["execute", "grant"],
  };

  return [
    {
      attackId: "28J-01",
      category: "authority_inflation",
      description: "forge a frame declaring full authority and read it through every downstream builder",
      run: () => {
        const v = buildGetigObserverView({
          viewId: "view-forged",
          observerId: OBSERVER_LOCAL,
          observerKind: "local_runtime",
          runtimeId: RUNTIME_ID,
          epochId: EPOCH_A,
          frame: tamperedFrame,
        });
        const m = buildGetigVisualMapping({ frameId: String(tamperedFrame["frameId"]), frame: tamperedFrame });
        const g = buildGetigExplanationGraph({ graphId: "graph-forged", frame: tamperedFrame });
        const authorities = [
          v.ok ? String(v.view.authority) : "refused",
          m.ok ? String(m.mapping.authority) : "refused",
          g.ok ? String(g.graph.authority) : "refused",
        ];
        if (authorities.some((x) => x !== "none")) {
          return { bypassed: true as const, observed: `downstream artifacts reported authority ${authorities.join(", ")}` };
        }
        return {
          bypassed: false as const,
          defence: "structural" as const,
          observed: `every downstream builder re-imposed authority "none": ${authorities.join(", ")}`,
        };
      },
    },
    {
      attackId: "28J-02",
      category: "authority_inflation",
      description: "carry a mutation on a selection and see whether selecting confers anything",
      run: () => {
        const d = inspectOnce("attack", { kind: "select", operation: "select", subjectVisibleId: "node-remote", approve: true }, context);
        if (d.ok) return { bypassed: true as const, observed: "a selection carrying a mutation was accepted" };
        return { bypassed: false as const, defence: "refusal" as const, observed: `refused with ${d.refusal}` };
      },
    },
    {
      attackId: "28J-03",
      category: "staleness_erosion",
      description: "choose an observation record time that would make an aged fact read as current",
      run: () => {
        const snapshot = buildMeshObservabilitySnapshot(localEvidenceAtT0());
        if (!snapshot.ok) return { bypassed: true as const, observed: "the evidence stage refused, so the claim is unproven" };
        const p = projectObservabilitySnapshot({
          frameId: "frame-attack-03",
          observer: localObserver(EPOCH_A),
          snapshot: snapshot.snapshot,
        });
        if (!p.ok) return { bypassed: true as const, observed: "the projection refused, so the claim is unproven" };
        const relay = p.frame.entities.find((e) => e.visibleId === "node-relay");
        const freshness = relay ? relay.freshness : "absent";
        if (freshness !== "stale") {
          return { bypassed: true as const, observed: `an observation recorded long before asOfEpochMs read as "${freshness}"` };
        }
        return {
          bypassed: false as const,
          defence: "structural" as const,
          observed: "freshness is derived from the record time by 28B; the caller supplies no freshness at all",
        };
      },
    },
    {
      attackId: "28J-04",
      category: "staleness_erosion",
      description: "coarsen the freshness axis up to the strongest tier so a stale fact draws as fresh",
      run: () => {
        const d = planGetigPresentationCoarsening(a.mapping, { axis: "freshness", tier: "declared" });
        if (d.ok) return { bypassed: true as const, observed: `freshness was drawn at tier ${d.plan.tier} against ceiling rank ${d.plan.ceilingRank}` };
        return { bypassed: false as const, defence: "refusal" as const, observed: `refused with ${d.refusal}` };
      },
    },
    {
      attackId: "28J-05",
      category: "conflict_suppression",
      description: "collapse the conflict axis so the unreconciled partition stops being visible",
      run: () => {
        const d = planGetigPresentationCoarsening(a.mapping, { axis: "conflict", tier: "minimal" });
        if (d.ok) return { bypassed: true as const, observed: "the conflict axis was collapsed" };
        return { bypassed: false as const, defence: "refusal" as const, observed: `refused with ${d.refusal}` };
      },
    },
    {
      attackId: "28J-06",
      category: "conflict_suppression",
      description: "make the two observers' comparison settle on a winner",
      run: () => {
        if (Boolean(a.comparison.winnerDeclared) || Boolean(a.comparison.consensusAsserted)) {
          return { bypassed: true as const, observed: "the comparison declared a winner or consensus" };
        }
        if (a.comparison.disagreements.length === 0) {
          return { bypassed: true as const, observed: "two divergent observers reported no disagreements" };
        }
        return {
          bypassed: false as const,
          defence: "structural" as const,
          observed: `${a.comparison.disagreements.length} disagreements recorded with winnerDeclared false`,
        };
      },
    },
    {
      attackId: "28J-07",
      category: "provenance_tampering",
      description: "use a cited provenance ref as a grant of trust",
      run: () => {
        const r = refuseProvenanceAsTrust("ev-node-remote");
        if (r.confersTrust || r.confersAuthority || r.authorizesExecution) {
          return { bypassed: true as const, observed: "a provenance ref conferred trust, authority or execution" };
        }
        return { bypassed: false as const, defence: "structural" as const, observed: `refused with ${r.refusal}` };
      },
    },
    {
      attackId: "28J-08",
      category: "provenance_tampering",
      description: "smuggle evidence CONTENT into a provenance record's metadata fields",
      run: () => {
        const d = buildGetigExplanationGraph({
          graphId: "graph-attack-08",
          frame: a.frame,
          provenanceRecords: [{ refId: "ev-node-remote", content: "raw evidence body" }],
        });
        if (d.ok) return { bypassed: true as const, observed: "a record carrying content was accepted into the graph" };
        return { bypassed: false as const, defence: "refusal" as const, observed: `refused with ${d.refusal}` };
      },
    },
    {
      attackId: "28J-09",
      category: "replay_to_execution",
      description: "navigate back to an earlier frame and restore runtime state from it",
      run: () => {
        const r = refuseResumeFromFrame(a.frame.frameId, T1);
        if (r.ok) return { bypassed: true as const, observed: "a resume from a past frame succeeded" };
        const t = inspectOnce("attack", { kind: "timeline_navigate", operation: "timeline_navigate" }, context);
        const resumed = t.ok && "replaySemantics" in t.result && (Boolean(t.result.resumesRuntimeState) || Boolean(t.result.restoresRuntimeState));
        if (resumed) return { bypassed: true as const, observed: "timeline navigation reported that it restored runtime state" };
        return { bypassed: false as const, defence: "structural" as const, observed: `refused with ${r.refusal}; navigation resumed nothing` };
      },
    },
    {
      attackId: "28J-10",
      category: "timeline_tampering",
      description: "splice a post-restart frame into the pre-restart timeline as if it continued it",
      run: () => {
        const d = buildGetigFrameSequence({
          sequenceId: "seq-attack-10",
          observerId: OBSERVER_LOCAL,
          epochId: EPOCH_A,
          orderingBasis: "observed_order",
          frames: [a.frame, a.frameRecovery],
        });
        if (d.ok) return { bypassed: true as const, observed: "a cross-epoch timeline was accepted" };
        return { bypassed: false as const, defence: "refusal" as const, observed: `refused with ${d.refusal}` };
      },
    },
    {
      attackId: "28J-11",
      category: "identity_substitution",
      description: "read observer A's view under observer B's binding",
      run: () => {
        const d = inspect({
          query: { kind: "inspect", operation: "inspect" },
          view: a.viewLocal,
          sequence: a.sequence,
          graph: a.graph,
          binding: { ...binding, observerId: OBSERVER_REMOTE },
        });
        if (d.ok) return { bypassed: true as const, observed: "one observer's view was read under another observer's identity" };
        return { bypassed: false as const, defence: "refusal" as const, observed: `refused with ${d.refusal}` };
      },
    },
    {
      attackId: "28J-12",
      category: "disclosure_leak",
      description: "disclose a record whose field name is not on the allowlist",
      run: () => {
        const d = disclose({
          frameId: a.frame.frameId,
          observerId: OBSERVER_LOCAL,
          canonicalVisibleHash: a.frame.canonicalVisibleHash,
          records: [{ subjectvisibleid: "node-remote", secret: "not-a-real-value" }],
        });
        if (d.ok) return { bypassed: true as const, observed: "a record with an unallowlisted field name was disclosed" };
        if (d.frame !== null) return { bypassed: true as const, observed: "the gate returned a frame alongside a refusal" };
        return { bypassed: false as const, defence: "structural" as const, observed: `refused with ${d.refusal}; frame null` };
      },
    },
    {
      attackId: "28J-13",
      category: "disclosure_leak",
      description: "smuggle structure through the gate as a nested field value",
      run: () => {
        const d = disclose({
          frameId: a.frame.frameId,
          observerId: OBSERVER_LOCAL,
          canonicalVisibleHash: a.frame.canonicalVisibleHash,
          records: [{ subjectvisibleid: "node-remote", count: { nested: 1 } }],
        });
        if (d.ok) return { bypassed: true as const, observed: "a nested value crossed the disclosure gate" };
        return { bypassed: false as const, defence: "structural" as const, observed: `refused with ${d.refusal} on field ${String(d.offendingField)}` };
      },
    },
    {
      attackId: "28J-14",
      category: "completeness_lie",
      description: "filter on a predicate the runtime cannot evaluate and let it pass as a complete answer",
      run: () => {
        const d = inspectOnce("attack", { kind: "filter", operation: "filter", filterBase: "operator_precedence", filterValue: "high" }, context);
        if (d.ok) return { bypassed: true as const, observed: "an unknown filter base was silently accepted" };
        return { bypassed: false as const, defence: "refusal" as const, observed: `refused with ${d.refusal}` };
      },
    },
    {
      attackId: "28J-15",
      category: "capability_union",
      description: "present the planned route as an admitted one while supplying no admission evidence at all",
      run: () => {
        const admitted = a.mapping.tokens.filter((t) => t.axis === "admission" && t.semanticValue === "admitted_explicit_evidence");
        if (admitted.length > 0) return { bypassed: true as const, observed: `${admitted.length} route(s) claimed admission with no evidence` };
        const admissionTokens = a.mapping.tokens.filter((t) => t.axis === "admission");
        return {
          bypassed: false as const,
          defence: "structural" as const,
          observed: `${admissionTokens.length} route(s) read not_admitted; absent evidence is not admission`,
        };
      },
    },
    {
      attackId: "28J-17",
      category: "inspection_injection",
      description: "carry an action inside the subject id string and read it as a subject selection",
      run: () => {
        const injected = inspectOnce(
          "attack",
          { kind: "select", operation: "select", subjectVisibleId: "node-remote; execute(rm -rf /)", focusScope: "subject" },
          context,
        );
        if (injected.ok) {
          return { bypassed: true as const, observed: "an id carrying an embedded action was treated as a real subject" };
        }
        // And the shape of the refusal matters: the runtime must say the subject
        // is unknown, not repeat the injected text back as an explanation.
        return {
          bypassed: false as const,
          defence: "structural" as const,
          observed: `refused with ${injected.refusal}; the id was matched against the view, never parsed`,
        };
      },
    },
    {
      attackId: "28J-16",
      category: "unsupported_as_pass",
      description: "have an UNSUPPORTED or INCONCLUSIVE case counted as a pass",
      // This attack runs a LOCAL three-case suite rather than re-running the
      // whole catalogue. Re-entering the suite from inside one of its own cases
      // would recurse without bound, and a self-referential attack that blows
      // the stack proves nothing about the taxonomy it claims to test.
      run: () => {
        const local = runAdversarialSuite([
          {
            attackId: "28J-16-a",
            category: "unsupported_as_pass",
            description: "a case the platform cannot express",
            run: () => ({ unsupported: true as const, observed: "the platform cannot express this case" }),
          },
          {
            attackId: "28J-16-b",
            category: "unsupported_as_pass",
            description: "a case whose outcome cannot be established",
            run: () => ({ inconclusive: true as const, observed: "the outcome could not be established either way" }),
          },
          {
            attackId: "28J-16-c",
            category: "unsupported_as_pass",
            description: "an attack the defences actually stopped",
            run: () => ({ bypassed: false as const, defence: "structural" as const, observed: "stopped structurally" }),
          },
        ]);
        const s2 = local.summary;
        const separated =
          s2.caseCount === 3 &&
          s2.pass === 1 &&
          s2.fail === 0 &&
          s2.unsupported === 1 &&
          s2.inconclusive === 1 &&
          s2.unsupportedIsPass === false &&
          s2.unsupportedAttackIds.includes("28J-16-a") &&
          s2.inconclusiveAttackIds.includes("28J-16-b") &&
          s2.pass + s2.fail + s2.unsupported + s2.inconclusive === s2.caseCount;
        if (!separated) {
          return {
            bypassed: true as const,
            observed: `verdict map folded non-passes into pass: ${JSON.stringify({ pass: s2.pass, fail: s2.fail, unsupported: s2.unsupported, inconclusive: s2.inconclusive })}`,
          };
        }
        return {
          bypassed: false as const,
          defence: "structural" as const,
          observed: `1 pass / 1 unsupported / 1 inconclusive counted separately; pass+fail+unsupported+inconclusive = ${String(s2.caseCount)}`,
        };
      },
    },
  ];
};

// ── the whole body, assembled once ───────────────────────────────────────────

interface ScenarioBody extends ScenarioArtifacts {
  readonly snapshotLocal: ObservabilitySnapshot;
  readonly snapshotRemote: ObservabilitySnapshot;
  readonly snapshotLater: ObservabilitySnapshot;
  readonly snapshotRecovery: ObservabilitySnapshot;
  readonly synthesisRefusal: ReturnType<typeof refuseGlobalTruthSynthesis>;
  readonly crossEpoch: { readonly refused: true; readonly refusal: string; readonly explanation: string };
  readonly resumeRefusal: ReturnType<typeof refuseResumeFromFrame>;
  readonly coarseningApproved: CoarseningDecision;
  readonly coarseningStrengthening: CoarseningDecision;
  readonly coarseningSuppression: CoarseningDecision;
  readonly selectionRefusal: ReturnType<typeof refuseVisualSelectionToPermission>;
  readonly traceByGraphKey: SubjectExplanation;
  readonly trustRefusal: ReturnType<typeof refuseProvenanceAsTrust>;
  readonly inspections: readonly GetigEndToEndInspectionReport[];
  readonly controlRefusal: InspectionDecision;
  readonly disclosure: GetigDisclosureFrame;
  readonly disclosureSecret: GetigDisclosureDecision;
  readonly disclosureNested: GetigDisclosureDecision;
  readonly adversarial: AdversarialSummary;
  readonly adversarialRunHash: string;
}

const entityOf = (frame: GetigFrame, visibleId: string) => frame.entities.find((e) => e.visibleId === visibleId);
const kindsOf = (frame: GetigFrame) => new Set<string>(frame.entities.map((e) => e.kind));
const routeOf = (frame: GetigFrame, routeId: string) => frame.routes.find((r) => r.routeId === routeId);

// ── element reporting ────────────────────────────────────────────────────────
//
// An element that is absent is reported `false`. It is never dropped: a silent
// omission reads to a downstream reader exactly like a satisfied one.

const evaluateElements = (b: ScenarioBody): readonly GetigEndToEndElementReport[] => {
  const nodeEntities = b.frame.entities.filter((e) => e.kind === "runtime_node");
  const kinds = kindsOf(b.frame);
  const route = routeOf(b.frame, "route-28j-1");
  const relayLater = entityOf(b.frameLater, "node-relay");
  const remoteLater = entityOf(b.frameLater, "node-remote");
  const relayAtT0 = entityOf(b.frame, "node-relay");
  const memory = entityOf(b.frame, "memory:session-log");
  const ok = b.inspections.filter((i) => i.ok);
  const report = (element: GetigEndToEndScenarioElement, present: boolean, evidence: readonly string[]) =>
    Object.freeze({ element, present, evidence: list(evidence) });

  const reports: GetigEndToEndElementReport[] = [];

  reports.push(
    report("multiple_runtime_mesh_nodes", nodeEntities.length >= 2, nodeEntities.map((e) => e.visibleId)),
    report(
      "agent_task_proposal_representations",
      ["agent", "goal", "task", "proposal", "tool_reference", "policy_gate", "execution_boundary", "memory_reference"].every((k) => kinds.has(k)),
      ["agent:planner", "goal:28j-1", "task:plan-route", "proposal:forward-1", "proposal:flow-28j-1"],
    ),
    report(
      "explicit_topology",
      b.frame.relations.some((r) => r.kind === "observed_edge") && b.frame.relations.some((r) => r.kind === "partitions_from"),
      b.frame.relations.map((r) => `${r.relationId}:${r.kind}`),
    ),
    report(
      "planned_route",
      route !== undefined && route.admission === "none" && route.authorization === "none" && route.executionAuthorized === false,
      route ? [`${route.routeId}: admission=${route.admission} authorization=${route.authorization}`] : [],
    ),
    report(
      "origin_forwarder_destination_roles",
      route !== undefined &&
        route.originVisibleId === "node-local" &&
        route.originFixed === true &&
        route.forwarderVisibleIds.length === 1 &&
        route.forwarderVisibleIds[0] !== route.originVisibleId &&
        route.destinationVisibleId !== route.originVisibleId,
      route
        ? [`origin=${route.originVisibleId}`, `forwarders=${route.forwarderVisibleIds.join(",")}`, `destination=${route.destinationVisibleId}`]
        : [],
    ),
    report(
      "capability_advertisement_as_untrusted_claim",
      b.frame.entities.every((e) => e.grant === "none") &&
        b.frame.relations.every((r) => r.trust === "none") &&
        b.mapping.tokens.every((t) => t.claim === "descriptive_only" && t.authority === "none"),
      ["entity grant=none", "relation trust=none", "token claim=descriptive_only"],
    ),
    report(
      "policy_gate_and_refusal_state",
      kinds.has("policy_gate") && b.frame.refusals.length > 0 && b.frame.entities.some((e) => e.kind === "execution_boundary"),
      b.frame.refusals.map((r) => `${r.refusalId}:${r.code}`),
    ),
    report(
      "partition_and_divergent_observer_views",
      b.frame.conflicts.length > 0 &&
        b.comparison.disagreements.length > 0 &&
        b.mapping.tokens.some((t) => t.axis === "partition" && t.semanticValue === "partitioned"),
      [
        `conflicts=${b.frame.conflicts.map((c) => c.conflictId).join(",")}`,
        `disagreements=${b.comparison.disagreements.length}`,
        `terminalBarriers=${b.multiView.terminalBarrierSubjects.join(",") || "none"}`,
      ],
    ),
    report(
      "restart_recovery_producing_later_frame",
      b.frameRecovery.epochId !== b.frame.epochId && b.frameRecovery.asOfEpochMs > b.frame.asOfEpochMs && b.crossEpoch.refused,
      [
        `epoch ${b.frame.epochId} @${b.frame.asOfEpochMs}`,
        `epoch ${b.frameRecovery.epochId} @${b.frameRecovery.asOfEpochMs}`,
        `cross-epoch sequence ${b.crossEpoch.refusal}`,
      ],
    ),
    report(
      "stale_and_unknown_state",
      relayAtT0?.freshness === "stale" &&
        remoteLater?.freshness === "unknown" &&
        remoteLater?.lifecycle === "unknown" &&
        memory?.freshness === "unknown" &&
        memory?.provenanceRefs.length === 0 &&
        relayLater?.lifecycle === "retired",
        // An uncited subject is an explicit unknown in 28F, never a blank.
      [
        `node-relay@T0 freshness=${String(relayAtT0?.freshness)}`,
        `node-remote@T1 freshness=${String(remoteLater?.freshness)} lifecycle=${String(remoteLater?.lifecycle)}`,
        `node-relay@T1 lifecycle=${String(relayLater?.lifecycle)}`,
        `memory:session-log freshness=${String(memory?.freshness)} with zero provenance refs`,
      ],
    ),
    report(
      "provenance_trace",
      b.trace.hopCount > 0 && b.graph.authorizes === false && b.trustRefusal.confersTrust === false,
      [`subject=${b.trace.subjectVisibleId}`, `hops=${String(b.trace.hopCount)}`, `unknownProvenance=${String(b.graph.missingProvenanceCount)}`],
    ),
    report(
      "timeline_and_semantic_diff",
      b.sequence.frameCount === 2 && b.diff.entryCount > 0 && b.diff.causalityClaimed === false,
      [
        `frames=${String(b.sequence.frameCount)}`,
        `diffEntries=${String(b.diff.entryCount)}`,
        `classes=${Object.entries(b.diff.classificationCounts).filter(([, v]) => v > 0).map(([k, v]) => `${k}=${String(v)}`).join(",")}`,
      ],
    ),
    report(
      "read_only_inspection_filter_compare",
      ok.length >= 8 && ok.some((i) => i.operation === "filter") && ok.some((i) => i.operation === "compare_views"),
      ok.map((i) => `${i.name}:${i.operation}`),
    ),
  );

  return list(reports);
};

// ── honest findings ──────────────────────────────────────────────────────────
//
// Recorded rather than hidden. A gate that reports only what went well leaves
// its next reader unable to tell which parts were actually tested.

export const GETIG_E2E_OBSERVATIONS = Object.freeze([
  Object.freeze({
    id: "28J-OBS-1",
    finding:
      "28A's frame observer-kind vocabulary (local_runtime | local_operator | offline_reader) has no remote_runtime, while 28E's view observer-kind vocabulary (local_runtime | remote_runtime) does. A remote vantage must therefore declare itself an offline_reader at frame level. 28J widens neither frozen vocabulary and does not mislabel the vantage as local; 28K should decide whether 28A gains remote_runtime.",
    severity: "non_blocking_defect" as const,
  }),
  Object.freeze({
    id: "28J-OBS-2",
    finding:
      "28E/28D/28F read a frame structurally and do not re-verify that 28A produced it. A caller that bypasses 28A and hands those modules a hand-built frame literal gets a view/mapping/graph describing that literal. The chain's integrity rests on 28A being the only sanctioned producer, which is why this scenario exposes no entry point accepting a caller-supplied frame. Tamper-detection is not what this phase provides.",
    severity: "non_blocking_defect" as const,
  }),
  Object.freeze({
    id: "28J-OBS-5",
    finding:
      "28G rejects a query carrying one of its 15 named INSPECTION_FORBIDDEN_ACTIONS keys, but silently IGNORES any other unknown key: `{kind:'select', operation:'select', subjectVisibleId:'node-remote', approvePeer:true}` returns inspection_succeeded. No action is taken, so this is not a bypass — but it is the same denylist shape 28H deliberately replaced with an allowlist, and a caller who passes an unlisted field can reasonably believe it was read. 28K should decide whether 28G refuses unknown query keys.",
    severity: "non_blocking_defect" as const,
  }),
  Object.freeze({
    id: "28J-OBS-4",
    finding:
      "28A's lifecycle vocabulary includes `unknown`; 28D's `lifecycle` visual axis does not ([retired, quarantined, observed]). A frame containing an unknown-lifecycle entity therefore makes 28D refuse the ENTIRE mapping with refused_mapping_unknown_value rather than draw it. The behaviour is fail-closed and invents nothing, but the practical consequence is that the visual layer cannot represent an unknown-lifecycle subject at all. 28K should decide whether 28D's lifecycle axis gains `unknown`.",
    severity: "non_blocking_defect" as const,
  }),
  Object.freeze({
    id: "28J-OBS-3",
    finding:
      "D-26-1 (physical two-machine LAN evidence) remains OPEN. This scenario is single-process, caller-supplied and in-memory; it is explicitly not hardware or network validation and says so structurally.",
    severity: "informational" as const,
  }),
]);

// ── the nine proofs ──────────────────────────────────────────────────────────
//
// Each proof is computed FROM THE ARTIFACTS the chain actually produced. None
// of them re-reads a constant from this file, and none of them accepts a
// caller-supplied value: if the chain stops conferring nothing, the proof fails
// and the runner refuses rather than reporting a pass.

const evaluateProofs = (b: ScenarioBody): readonly GetigEndToEndProofReport[] => {
  const proof = (name: GetigEndToEndProof, holds: boolean, evidence: string) =>
    Object.freeze({ proof: name, holds, evidence });

  const frames = [b.frame, b.frameLater, b.frameRecovery, b.frameRemote];
  const authorities = [
    ...frames.map((f) => String(f.authority)),
    b.viewLocal.authority,
    b.viewRemote.authority,
    b.multiView.authority,
    b.comparison.authority,
    b.mapping.authority,
    b.graph.authority,
    b.sequence.authority,
    b.diff.authority,
    b.disclosure.authority,
  ];
  const allAuthoritiesNone = authorities.every((a) => a === "none");

  const okInspections = b.inspections.filter((i) => i.ok);

  const refusalsAllZeros =
    b.selectionRefusal.conferredAuthority === false &&
    b.selectionRefusal.admittedPeer === false &&
    b.selectionRefusal.authorizedRoute === false &&
    b.selectionRefusal.mutatedRuntimeState === false &&
    b.controlRefusal.ok === false &&
    b.controlRefusal.result === null &&
    b.synthesisRefusal.winnerDeclared === false &&
    b.synthesisRefusal.consensusAsserted === false &&
    b.synthesisRefusal.isGlobalTruth === false &&
    b.trustRefusal.confersTrust === false &&
    b.trustRefusal.confersAuthority === false &&
    b.trustRefusal.authorizesExecution === false &&
    b.resumeRefusal.ok === false;

  const routeZeros = b.frame.routes.every(
    (r) => r.admission === "none" && r.authorization === "none" && r.executionAuthorized === false,
  );
  const factZeros = [...b.viewLocal.facts, ...b.viewRemote.facts].every((f) => f.isGrant === false);
  const inspectionZeros = okInspections.every((i) => i.operation.length > 0);

  const gateZeros =
    b.frame.replaySemantics === "visual_only_not_executable" &&
    b.sequence.replaySemantics === "visual_history_not_executable" &&
    b.sequence.restoresRuntimeState === false &&
    b.sequence.resumesRuntimeState === false &&
    b.sequence.temporalOrderEstablished === true &&
    b.diff.causalityClaimed === false &&
    b.diff.restoresRuntimeState === false &&
    b.crossEpoch.refused &&
    b.resumeRefusal.ok === false;

  const distinct =
    b.viewLocal.viewHash !== b.viewRemote.viewHash &&
    b.viewLocal.observerId !== b.viewRemote.observerId &&
    b.viewLocal.observerKind !== b.viewRemote.observerKind &&
    b.comparison.disagreements.length > 0 &&
    b.multiView.synthesizesGlobalTruth === false &&
    b.multiView.terminalResurrected === false &&
    b.synthesisRefusal.winnerDeclared === false;

  const conflictsVisible =
    b.frame.conflicts.length > 0 &&
    b.frameLater.conflicts.length > 0 &&
    b.frame.conflicts.every((c) => c.resolved === false) &&
    b.frameLater.conflicts.every((c) => c.resolved === false) &&
    b.mapping.tokens.some((t) => t.axis === "conflict" && t.semanticValue === "conflict_visible") &&
    !b.coarseningSuppression.ok;

  const disclosed = b.disclosure.records.every((r) =>
    Object.values(r.fields).every((v) => typeof v === "string" || typeof v === "number" || typeof v === "boolean"),
  );
  const noSecrets =
    b.disclosure.disclosesRawContent === false &&
    b.disclosure.disclosesPolicyText === false &&
    b.disclosure.redacted === false &&
    !b.disclosureSecret.ok &&
    b.disclosureSecret.frame === null &&
    b.disclosureSecret.partialFrameEmitted === false &&
    !b.disclosureNested.ok &&
    b.disclosureNested.frame === null &&
    b.graph.authorizes === false &&
    frames.every((f) => f.entities.every((e) => e.provenanceRefs.every((p) => p.confersTrust === false)));

  const sequenceHashesMatch =
    b.sequence.entries.length === 2 &&
    b.sequence.entries[0]!.canonicalVisibleHash === b.frame.canonicalVisibleHash &&
    b.sequence.entries[1]!.canonicalVisibleHash === b.frameLater.canonicalVisibleHash;
  const binding = inspectionBinding(b.frame, b.viewLocal);
  const hashesConsistent =
    b.viewLocal.builtFromVisibleHash === b.frame.canonicalVisibleHash &&
    b.viewLocal.builtFromFrameId === b.frame.frameId &&
    b.graph.frameId === b.frame.frameId &&
    b.mapping.frameId === b.frame.frameId &&
    b.disclosure.canonicalVisibleHash === b.frame.canonicalVisibleHash &&
    b.disclosure.frameId === b.frame.frameId &&
    binding.viewHash === b.viewLocal.viewHash &&
    sequenceHashesMatch &&
    // The same subject asked two ways must produce ONE answer (law 11).
    canonicalHash(b.trace) === canonicalHash(b.traceByGraphKey);

  const rendererNeutral =
    b.mapping.rendererNeutral === true &&
    b.mapping.graphicsBackend === "none" &&
    b.mapping.colorIsCanonicalMeaning === false &&
    b.mapping.strengthensSemanticClaims === false &&
    frames.every((f) => f.globalTruth === false);

  return list<GetigEndToEndProofReport>([
    proof(
      "getig_adds_no_authority",
      allAuthoritiesNone &&
        frames.every((f) => f.authority === "none" && f.controlPlane === false && f.readOnly === true && f.visibleCapabilities.length === 0) &&
        b.adversarial.criticalBypass === false,
      `authority "none" on all ${String(authorities.length)} composed artifacts (four frames plus ten downstream reads); criticalBypass=${String(b.adversarial.criticalBypass)}`,
    ),
    proof(
      "no_visual_to_runtime_action_path",
      routeZeros && factZeros && inspectionZeros && b.selectionRefusal.mutatedRuntimeState === false && b.controlRefusal.ok === false,
      `route zeros held on ${String(b.frame.routes.length)} route(s); ${String(okInspections.length)} inspections used allowed operations only; selection and control both refused`,
    ),
    proof(
      "execution_still_requires_frozen_local_authority_chain",
      refusalsAllZeros &&
        b.frame.entities.every((e) => e.grant === "none") &&
        b.frame.relations.every((r) => r.trust === "none") &&
        b.frame.routes.every((r) => r.executionAuthorized === false),
      "visual selection, inspection-as-control, global-truth synthesis, provenance-as-trust and frame-resume all refused; every visible claim carries a closed zero literal",
    ),
    proof(
      "visual_replay_is_non_executable",
      gateZeros,
      `replaySemantics ${b.frame.replaySemantics} / ${b.sequence.replaySemantics}; cross-epoch splice ${b.crossEpoch.refusal}; resume ${b.resumeRefusal.refusal}`,
    ),
    proof(
      "observer_views_are_distinct",
      distinct,
      `viewHash ${b.viewLocal.viewHash.slice(0, 12)} vs ${b.viewRemote.viewHash.slice(0, 12)}; ${String(b.comparison.disagreements.length)} disagreements; synthesis refused`,
    ),
    proof(
      "conflict_stays_visible",
      conflictsVisible,
      `${String(b.frame.conflicts.length)} conflict(s) at T0 and ${String(b.frameLater.conflicts.length)} at T1, none resolved; collapse refused ${b.coarseningSuppression.ok ? "UNEXPECTEDLY APPROVED" : String(b.coarseningSuppression.refusal)}`,
    ),
    proof(
      "secrets_and_raw_content_absent",
      noSecrets && disclosed,
      `${String(b.disclosure.fieldCount)} disclosed field(s), all scalar; unallowlisted name ${disclosureRefusalToken(b.disclosureSecret)}; nested value ${disclosureRefusalToken(b.disclosureNested)}; both refusals carried frame null`,
    ),
    proof(
      "hashes_consistent",
      hashesConsistent,
      `view/graph/mapping/disclosure all bound to ${b.frame.canonicalVisibleHash.slice(0, 12)}; sequence entries match their frames; both spellings of the trace hash identically`,
    ),
    proof(
      "renderer_dependency_zero",
      rendererNeutral,
      `mapping rendererNeutral with graphicsBackend ${b.mapping.graphicsBackend}; no colour carries canonical meaning; no frame claims global truth`,
    ),
  ]);
};

// ── the refusal constructor ──────────────────────────────────────────────────

/**
 * The single total-refusal constructor for this gate.
 *
 * It is EXPORTED on purpose. `runGetigEndToEndScenario` uses it, but a
 * downstream stage can only be observed refusing if a reader is able to make it
 * refuse: dead refusal vocabulary is the defect this program has already found
 * three times in earlier gates. Exporting this makes every code in
 * `GETIG_E2E_REFUSAL_CODES` reachable and testable rather than a string nobody
 * has ever seen produced.
 */
export function refuseEndToEndScenario(
  refusal: GetigEndToEndRefusalCode,
  stage: string,
  detail: string,
): GetigEndToEndScenarioRefused {
  return Object.freeze({
    ok: false as const,
    code: "end_to_end_scenario_refused" as const,
    refusal,
    explanation: `${REFUSAL_EXPLANATIONS[refusal]} (stage: ${stage}; ${detail})`,
    cause: Object.freeze({ stage, upstreamRefusal: detail }),
    scenario: null,
    partialScenarioEmitted: false as const,
    authority: "none" as const,
    readOnly: true as const,
  });
}

// ── the disclosure records, built from the real frame ────────────────────────

const disclosureRecordsOf = (frame: GetigFrame, view: GetigObserverView) => {
  const remote = entityOf(frame, "node-remote");
  const relay = entityOf(frame, "node-relay");
  const route = routeOf(frame, "route-28j-1");
  // NOTE the shape: 28H's INPUT records are FLAT field maps. Only its OUTPUT
  // wraps them in a `fields` object, so writing `{ fields: {...} }` here would
  // have disclosed one field literally named "fields" — or, worse, tripped the
  // gate's nested-structure check and produced a refusal that looked like a
  // successful test. Every value below is a scalar and every name is on the
  // allowlist; nothing that could carry content is named at all.
  return [
    {
      subjectvisibleid: "node-remote",
      subjectcollection: "entities",
      kind: remote?.kind ?? "unknown",
      lifecycle: remote?.lifecycle ?? "unknown",
      freshness: remote?.freshness ?? "unknown",
      knowledge: "known",
      isgrant: false,
      isglobaltruth: false,
    },
    {
      subjectvisibleid: "node-relay",
      subjectcollection: "entities",
      kind: relay?.kind ?? "unknown",
      lifecycle: relay?.lifecycle ?? "unknown",
      freshness: relay?.freshness ?? "unknown",
      knowledge: "known",
      isgrant: false,
    },
    {
      routeid: route?.routeId ?? "route-28j-1",
      observerid: view.observerId,
      frameid: frame.frameId,
      epochid: frame.epochId,
      canonicalvisiblehash: frame.canonicalVisibleHash,
      role: "origin",
      factcount: view.factCount,
      count: frame.entities.length,
      isgrant: false,
    },
  ];
};

// ── the nine read operations the chain is asked to perform ───────────────────
//
// One per entry in 28G's closed allowed list. Running all nine is what turns
// "inspection works" into "every read the prompt names is available, and each
// one is read-only".

const READ_QUERIES: readonly (readonly [string, unknown])[] = Object.freeze([
  ["select_quarantined_subject", { kind: "select", operation: "select", subjectVisibleId: "node-remote", focusScope: "subject", expansionState: "collapsed" }],
  ["inspect_whole_view", { kind: "inspect", operation: "inspect" }],
  ["filter_quarantined_lifecycle", { kind: "filter", operation: "filter", filterBase: "lifecycle", filterValue: "quarantined" }],
  ["focus_agent", { kind: "focus", operation: "focus", subjectVisibleId: "agent:planner", focusScope: "subject" }],
  ["expand_retired_relay", { kind: "expand_collapse", operation: "expand_collapse", subjectVisibleId: "node-relay", focusScope: "subject", expansionState: "expanded" }],
  ["timeline_two_frames", { kind: "timeline_navigate", operation: "timeline_navigate" }],
  ["compare_whole_view", { kind: "compare", operation: "compare_views" }],
  ["trace_node_remote", { kind: "trace_provenance", operation: "trace_provenance", subjectVisibleId: "node-remote", limit: 16 }],
  ["enumerate_refusals_conflicts", { kind: "enumerate_refusals", operation: "enumerate_refusals_conflicts" }],
]);

// ── compose the whole body ───────────────────────────────────────────────────

const composeBody = (): ScenarioBody => {
  // ── 27H: four real snapshots, no clock, no network ──
  const snapshotLocal = snapshotOf("27h_local_t0", localEvidenceAtT0());
  const snapshotRemote = snapshotOf("27h_remote_t0", remoteEvidenceAtT0());
  const snapshotLater = snapshotOf("27h_local_t1", localEvidenceAtT1());
  const snapshotRecovery = snapshotOf("27h_local_restart", localEvidenceAfterRestart());

  // ── 28B + 28A: four composed visible worlds ──
  const frame = composeFrame("28a_local_t0", snapshotLocal, localObserver(EPOCH_A), "frame-28j-t0", T0);
  const frameLater = composeFrame("28a_local_t1", snapshotLater, localObserver(EPOCH_A), "frame-28j-t1", T1);
  const frameRecovery = composeFrame("28a_recovery", snapshotRecovery, localObserver(EPOCH_B), "frame-28j-restart", T_RESTART);
  const frameRemote = composeFrame("28a_remote_t0", snapshotRemote, remoteObserver(EPOCH_A), "frame-28j-remote-t0", T0);

  // ── 28E: two observers, two views, one comparison ──
  const viewLocal = viewOf("28e_local", "view-28j-local", OBSERVER_LOCAL, "local_runtime", frame);
  const viewRemote = viewOf("28e_remote", "view-28j-remote", OBSERVER_REMOTE, "remote_runtime", frameRemote);
  const comparison = comparisonOf("28e_comparison", viewLocal, viewRemote);
  const multiView = multiViewOf("28e_multiview", [viewLocal, viewRemote]);
  const synthesisRefusal = refuseGlobalTruthSynthesis([OBSERVER_LOCAL, OBSERVER_REMOTE], "merged world");

  // ── 28D: tokens, coarsening ──
  const mapping = mappingOf("28d_mapping", frame);
  // `freshness` carries an `unknown` token (rank 0), and no presentation tier
  // is at or below rank 0 — so coarsening freshness is ALWAYS refused. The
  // approved path is therefore demonstrated on `knowledge`, where every token is
  // genuinely `known` (rank 1) and `minimal` (rank 1) is a legal under-claim.
  const coarseningApproved = planGetigPresentationCoarsening(mapping, { axis: "knowledge", tier: "minimal" });
  const coarseningStrengthening = planGetigPresentationCoarsening(mapping, { axis: "freshness", tier: "declared" });
  const coarseningSuppression = planGetigPresentationCoarsening(mapping, { axis: "conflict", tier: "minimal" });
  const selectionRefusal = refuseVisualSelectionToPermission(`${frame.frameId}:entities:node-remote:grant:grant_none`, "admit this peer");

  // ── 28C: timeline, diffs, and the two things a timeline may not do ──
  const sequence = sequenceOf("28c_sequence", [frame, frameLater]);
  const diff = diffOf("28c_diff", frame, frameLater);
  const diffAcrossRestart = diffOf("28c_diff_restart", frame, frameRecovery);
  const resumeRefusal = refuseResumeFromFrame(frame.frameId, T_RESTART);

  const crossDecision: SequenceDecision = buildGetigFrameSequence({
    sequenceId: "seq-28j-cross-epoch",
    observerId: OBSERVER_LOCAL,
    epochId: EPOCH_A,
    orderingBasis: "observed_order",
    frames: [frame, frameRecovery],
  });
  if (crossDecision.ok) {
    abort("refused_e2e_sequence_refused", "28c_cross_epoch", "a cross-epoch timeline was accepted");
  }
  const crossEpoch = Object.freeze({
    refused: true as const,
    refusal: String(crossDecision.refusal),
    explanation: crossDecision.explanation,
  });

  // ── 28F: provenance graph and a trace asked two ways ──
  const graph = graphOf("28f_graph", frame);
  const trace = traceOf("28f_trace", graph, "node-remote");
  const traceByGraphKey = traceOf("28f_trace_keyed", graph, "entities:node-remote");
  const trustRefusal = refuseProvenanceAsTrust("ev-node-remote", "accept the remote node as trusted");

  // ── 28G: all nine read operations ──
  const binding = inspectionBinding(frame, viewLocal);
  const ctx = { view: viewLocal, sequence, graph, binding };
  const inspections: GetigEndToEndInspectionReport[] = [];
  for (const [name, query] of READ_QUERIES) {
    const d = inspectOnce("28g_inspection", query, ctx);
    if (!d.ok) abort("refused_e2e_inspection_refused", `28g_${name}`, String(d.refusal));
    inspections.push(Object.freeze({ name, operation: d.operation, ok: true, outcome: d.code }));
  }
  const controlRefusal = refuseInspectionAsControl("approve the quarantined node");

  // ── 28H: disclosure of the real frame, and two refusals that must hold ──
  const disclosureDecision = disclose({
    frameId: frame.frameId,
    observerId: OBSERVER_LOCAL,
    canonicalVisibleHash: frame.canonicalVisibleHash,
    records: disclosureRecordsOf(frame, viewLocal),
  });
  if (!disclosureDecision.ok) {
    abort("refused_e2e_disclosure_refused", "28h_disclose", String(disclosureDecision.refusal));
  }
  const disclosure = disclosureDecision.frame;
  const disclosureSecret = disclose({
    frameId: frame.frameId,
    observerId: OBSERVER_LOCAL,
    canonicalVisibleHash: frame.canonicalVisibleHash,
    records: [{ subjectvisibleid: "node-remote", secret: "not-a-real-value" }],
  });
  const disclosureNested = disclose({
    frameId: frame.frameId,
    observerId: OBSERVER_LOCAL,
    canonicalVisibleHash: frame.canonicalVisibleHash,
    records: [{ subjectvisibleid: "node-remote", count: { nested: 1 } }],
  });

  const body: ScenarioBody = {
    snapshotLocal, snapshotRemote, snapshotLater, snapshotRecovery,
    frame, frameLater, frameRecovery, frameRemote,
    viewLocal, viewRemote, multiView, comparison, synthesisRefusal,
    sequence, diff, diffAcrossRestart, crossEpoch, resumeRefusal,
    mapping, coarseningApproved, coarseningStrengthening, coarseningSuppression, selectionRefusal,
    graph, trace, traceByGraphKey, trustRefusal,
    inspections: list(inspections), controlRefusal,
    disclosure, disclosureSecret, disclosureNested,
    adversarial: { caseCount: 0, pass: 0, fail: 0, unsupported: 0, inconclusive: 0 } as AdversarialSummary,
    adversarialRunHash: "",
  };

  // ── 28I: the attacks, run against the body this scenario really built ──
  const artifacts: ScenarioArtifacts = {
    frame, frameLater, frameRecovery, frameRemote,
    viewLocal, viewRemote, multiView, comparison,
    sequence, diff, diffAcrossRestart, mapping, graph, trace,
  };
  const suite = runAdversarialSuite(scenarioAttacks(artifacts));
  if (suite.summary.criticalBypass) {
    abort(
      "refused_e2e_adversarial_bypass",
      "28i_adversarial",
      `bypassed: ${suite.summary.bypassedAttackIds.join(", ")}`,
    );
  }

  return Object.freeze({ ...body, adversarial: suite.summary, adversarialRunHash: hashAdversarialRun(suite.outcomes) });
};

// ── the deliberate refusals, each recorded as evidence ───────────────────────
//
// A refusal token is read through a helper, never by reaching into a decision
// union that may have succeeded. `UNEXPECTED_SUCCESS` is a real, reachable
// token: it is what a broken defence would produce, and it fails the gate loudly
// rather than being quietly formatted away.

const inspectionRefusalToken = (d: InspectionDecision): string => (d.ok ? "UNEXPECTED_SUCCESS" : d.refusal);
const disclosureRefusalToken = (d: GetigDisclosureDecision): string => (d.ok ? "UNEXPECTED_SUCCESS" : d.refusal);
const coarseningRefusalToken = (d: CoarseningDecision): string => (d.ok ? "UNEXPECTED_SUCCESS" : d.refusal);

const collectRefusedAttempts = (b: ScenarioBody): readonly GetigEndToEndAttempt[] => {
  const binding = inspectionBinding(b.frame, b.viewLocal);
  const ctx = { view: b.viewLocal, sequence: b.sequence, graph: b.graph, binding };
  const unknownSubject = inspectOnce("attempt", { kind: "select", operation: "select", subjectVisibleId: "node-that-was-never-observed" }, ctx);
  const outOfRange = inspectOnce("attempt", { kind: "inspect", operation: "inspect", limit: 0 }, ctx);
  const mutationShaped = inspectOnce("attempt", { kind: "filter", operation: "filter", filterBase: "lifecycle", filterValue: "quarantined", grant: true }, ctx);
  if (unknownSubject.ok || outOfRange.ok || mutationShaped.ok) {
    abort("refused_e2e_inspection_refused", "28g_refused_attempts", "an attempt that had to refuse was accepted");
  }

  // Every attempt below is read through a token helper rather than through
  // `decision.refusal` directly: an attempt that has UNEXPECTEDLY succeeded must
  // still be recordable, and a report that cannot name its own outcome is how a
  // failed refusal disappears from the record.
  const attempt = (name: string, goal: string, outcome: string): GetigEndToEndAttempt => {
    if (outcome === "UNEXPECTED_SUCCESS") {
      abort("refused_e2e_inspection_refused", `attempt_${name}`, "an attempt that had to refuse succeeded");
    }
    return Object.freeze({ name, goal, refused: true as const, outcome });
  };

  return list<GetigEndToEndAttempt>([
    attempt("visual_selection_to_permission", "select a visible token and have it permit something", b.selectionRefusal.refusal),
    attempt("inspection_as_control", "use the inspection runtime to perform a control action", inspectionRefusalToken(b.controlRefusal)),
    attempt("global_truth_synthesis", "fold two observers' views into one world", b.synthesisRefusal.refusal),
    attempt("provenance_as_trust", "treat a cited provenance ref as trust", b.trustRefusal.refusal),
    attempt("resume_from_past_frame", "restore runtime state from an earlier frame", b.resumeRefusal.refusal),
    attempt("cross_epoch_timeline", "splice a post-restart frame into the pre-restart timeline", b.crossEpoch.refusal),
    attempt("unknown_subject_inspection", "select a subject this view never observed", inspectionRefusalToken(unknownSubject)),
    attempt("out_of_range_limit", "ask for zero results and receive a silently clamped answer", inspectionRefusalToken(outOfRange)),
    attempt("mutation_shaped_query", "carry a grant on an otherwise valid query", inspectionRefusalToken(mutationShaped)),
    attempt("coarsening_strengthens_claim", "draw the freshness axis at a tier stronger than its weakest fact", coarseningRefusalToken(b.coarseningStrengthening)),
    attempt("coarsening_suppresses_conflict", "collapse the conflict axis until the partition stops being visible", coarseningRefusalToken(b.coarseningSuppression)),
    attempt("disclosure_unallowlisted_name", "disclose a field whose name is not on the allowlist", disclosureRefusalToken(b.disclosureSecret)),
    attempt("disclosure_nested_structure", "smuggle structure through the gate as a nested value", disclosureRefusalToken(b.disclosureNested)),
  ]);
};

// ── the runner ──────────────────────────────────────────────────────────────

/**
 * Run the whole Phase-28 chain end to end, once, on fixed in-process evidence.
 *
 * The signature is the point: this runner accepts NO evidence, NO frames and NO
 * overrides. Everything it reports was built here from the frozen upstream, so
 * a caller cannot pick evidence that makes the chain look better than it is.
 *
 * Returns a total refusal — publishing nothing — when any upstream stage
 * refuses, when the adversarial suite finds a bypass, when one of the nine proofs
 * fails, or when a second construction from the same inputs does not reproduce
 * the same hash.
 */
export function runGetigEndToEndScenario(options?: unknown): GetigEndToEndScenarioDecision {
  if (options !== undefined && !(isRecord(options) && Object.keys(options).length === 0)) {
    return refuseEndToEndScenario(
      "refused_e2e_input_invalid",
      "entry",
      "this scenario is a fixed witness and accepts no evidence, frames or overrides",
    );
  }

  try {
    const b = composeBody();
    const elements = evaluateElements(b);
    const proofs = evaluateProofs(b);
    const refusedAttempts = collectRefusedAttempts(b);
    const failedProofs = proofs.filter((p) => !p.holds).map((p) => p.proof);

    if (failedProofs.length > 0) {
      abort("refused_e2e_proof_failed", "proofs", failedProofs.join(", "));
    }
    const absent = elements.filter((e) => !e.present).map((e) => e.element);
    if (absent.length > 0) {
      abort("refused_e2e_proof_failed", "elements", absent.join(", "));
    }

    const scenarioHash = canonicalHash({
      schemaVersion: GETIG_E2E_SCHEMA_VERSION,
      scenarioId: "scenario-28j-1",
      frame: b.frame.canonicalVisibleHash,
      frameLater: b.frameLater.canonicalVisibleHash,
      frameRecovery: b.frameRecovery.canonicalVisibleHash,
      frameRemote: b.frameRemote.canonicalVisibleHash,
      viewLocal: b.viewLocal.viewHash,
      viewRemote: b.viewRemote.viewHash,
      sequence: b.sequence.sequenceIdentity,
      mapping: b.mapping.mappingHash,
      graph: b.graph.graphHash,
      disclosure: b.disclosure.disclosureFrameHash,
      adversarial: b.adversarialRunHash,
      elements: elements.map((e) => `${e.element}:${String(e.present)}`),
      proofs: proofs.map((p) => `${p.proof}:${String(p.holds)}`),
    });

    const scenario: GetigEndToEndScenario = Object.freeze({
      schemaVersion: GETIG_E2E_SCHEMA_VERSION,
      scenarioId: "scenario-28j-1",
      runtimeId: RUNTIME_ID,
      epochId: EPOCH_A,
      recoveryEpochId: EPOCH_B,
      observerIds: list([OBSERVER_LOCAL, OBSERVER_REMOTE]),
      chain: list(GETIG_E2E_CHAIN),
      snapshotLocalHash: b.snapshotLocal.projectionHash,
      snapshotRemoteHash: b.snapshotRemote.projectionHash,
      snapshotLaterHash: b.snapshotLater.projectionHash,
      snapshotRecoveryHash: b.snapshotRecovery.projectionHash,
      frame: b.frame,
      frameLater: b.frameLater,
      frameRecovery: b.frameRecovery,
      frameRemote: b.frameRemote,
      viewLocal: b.viewLocal,
      viewRemote: b.viewRemote,
      comparison: b.comparison,
      multiView: b.multiView,
      synthesisRefusal: b.synthesisRefusal,
      sequence: b.sequence,
      diff: b.diff,
      diffAcrossRestart: b.diffAcrossRestart,
      crossEpochSequenceRefusal: b.crossEpoch,
      resumeRefusal: b.resumeRefusal,
      mapping: b.mapping,
      coarseningApproved: b.coarseningApproved,
      coarseningStrengtheningRefusal: b.coarseningStrengthening,
      coarseningSuppressionRefusal: b.coarseningSuppression,
      selectionRefusal: b.selectionRefusal,
      graph: b.graph,
      trace: b.trace,
      traceByGraphKey: b.traceByGraphKey,
      trustRefusal: b.trustRefusal,
      inspections: b.inspections,
      successfulInspections: b.inspections.filter((i) => i.ok).length,
      controlRefusal: b.controlRefusal,
      disclosure: b.disclosure,
      disclosureRecords: b.disclosure.recordCount,
      disclosureFields: b.disclosure.fieldCount,
      secretDisclosureRefusal: b.disclosureSecret,
      nestedValueDisclosureRefusal: b.disclosureNested,
      adversarial: b.adversarial,
      adversarialRunHash: b.adversarialRunHash,
      refusedAttempts,
      elements,
      proofs,
      observations: GETIG_E2E_OBSERVATIONS,
      elementCount: elements.length,
      proofCount: proofs.length,
      passedProofCount: proofs.filter((p) => p.holds).length,
      failedProofs: list(failedProofs),
      physicalLanValidation: false,
      singleProcess: true,
      networkCallsMade: 0,
      scenarioHash,
      authority: "none",
      controlPlane: false,
      readOnly: true,
      createsActionPath: false,
      grantsNothing: true,
      globalTruth: false,
      replaySemantics: "visual_history_not_executable",
    });

    // Determinism (law 11): build the whole world a second time from the same
    // inputs and compare. This is not a cached re-read — every upstream module
    // runs again, and any order- or clock-dependent behaviour shows up here as
    // a refusal rather than as a scenario that quietly varies between runs.
    const again = composeBody();
    const againHash = canonicalHash({
      frame: again.frame.canonicalVisibleHash,
      frameLater: again.frameLater.canonicalVisibleHash,
      frameRecovery: again.frameRecovery.canonicalVisibleHash,
      frameRemote: again.frameRemote.canonicalVisibleHash,
      viewLocal: again.viewLocal.viewHash,
      viewRemote: again.viewRemote.viewHash,
      sequence: again.sequence.sequenceIdentity,
      mapping: again.mapping.mappingHash,
      graph: again.graph.graphHash,
      disclosure: again.disclosure.disclosureFrameHash,
      adversarial: again.adversarialRunHash,
    });
    const firstHash = canonicalHash({
      frame: b.frame.canonicalVisibleHash,
      frameLater: b.frameLater.canonicalVisibleHash,
      frameRecovery: b.frameRecovery.canonicalVisibleHash,
      frameRemote: b.frameRemote.canonicalVisibleHash,
      viewLocal: b.viewLocal.viewHash,
      viewRemote: b.viewRemote.viewHash,
      sequence: b.sequence.sequenceIdentity,
      mapping: b.mapping.mappingHash,
      graph: b.graph.graphHash,
      disclosure: b.disclosure.disclosureFrameHash,
      adversarial: b.adversarialRunHash,
    });
    if (againHash !== firstHash) {
      return refuseEndToEndScenario(
        "refused_e2e_non_deterministic",
        "determinism",
        `a second construction produced ${againHash.slice(0, 16)} against ${firstHash.slice(0, 16)}`,
      );
    }

    return Object.freeze({
      ok: true as const,
      code: "end_to_end_scenario_complete" as const,
      scenario,
      authority: "none" as const,
      readOnly: true as const,
    });
  } catch (error) {
    if (error instanceof ScenarioAbort) {
      return refuseEndToEndScenario(error.refusal, error.stage, error.upstreamRefusal);
    }
    // Anything else is an internal defect, not a caller error. Rethrowing keeps
    // it loud instead of laundering it into a tidy refusal the caller would read
    // as a designed outcome.
    throw error;
  }
}
