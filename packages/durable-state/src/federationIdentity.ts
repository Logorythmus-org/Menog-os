/**
 * PHASE 24A — Federation Trust Model & Node Identity Contract
 * (CONTRACT-FIRST / NO NETWORK / NO EXECUTION API).
 *
 * This module defines WHAT a federation peer IS, WHAT a peer may claim,
 * and WHICH local decisions a peer's claims can trigger. It implements no
 * transport, no sockets, no discovery, no crypto primitives, and no
 * execution surface: the signature verifier is a caller-injected port
 * (24B supplies the real one), peer persistence is 24C scope, the message
 * bus pipeline is 24D scope. Nothing here calls the store, the launcher,
 * the policy engine, the planner, or any network API.
 *
 * Central Phase-24 statement (extends, never relaxes, Phase-22/23):
 *
 *     identity ≠ authority      authentication ≠ authorization
 *     peer admission ≠ execution permission
 *     federation ≠ capability union
 *     a remote peer can only ever hand us DATA to evaluate locally
 *
 * The 24A laws, each structurally enforced below and pinned by contract
 * tests:
 *
 *  L1  identity ≠ authority: a NodeId, a RuntimeInstanceId, or an epoch
 *      never grants execution; no type in this module carries an
 *      execution or policy authorization field at all.
 *  L2  authentication ≠ authorization: a verified signature proves
 *      provenance of DATA, nothing more; verification outcomes carry
 *      `authority: "none"` permanently.
 *  L3  peer admission ≠ execution permission: an admission decision only
 *      moves a peer's TRUST STATE for communication; every execution
 *      remains behind fresh LOCAL Allocation → Policy → Phase-20
 *      isolation → Phase-21 governed tool runtime.
 *  L4  federation ≠ capability union: no type aggregates capabilities
 *      across peers; identity documents and messages have a CLOSED field
 *      set with strict validation — unknown fields are refused, so a
 *      remote claim cannot smuggle capability vocabulary in.
 *  L5  stale epochs fail: an epoch observed for an instance is only
 *      acceptable while it is that instance's NEWEST observed epoch;
 *      anything older (or a same-tick rival) is refused; epoch freshness
 *      reuses the frozen 23A epoch vocabulary.
 *  L6  quarantined/retired peers do not resurrect: the peer trust machine
 *      mirrors the repository's terminal-lifecycle law (quarantined →
 *      retired only; retired is terminal); an admission request from a
 *      terminal peer is refused, never silently re-admitted.
 *  L7  remote claims never broaden local Policy: this module imports no
 *      policy vocabulary and no decision here can widen any local
 *      authority; remote-intent fields are inert, closed-union DATA.
 *  L8  replay, protocol, and schema mismatch fail closed: message ids are
 *      observed exactly once (a second sighting of the same id is a
 *      replay and is refused), the protocol version must match exactly
 *      (downgrades are refused), and documents/messages with malformed or
 *      unknown fields are refused before anything is admitted.
 *  L9  admitted facts are provenance-bound: EVERY decision (admit,
 *      quarantine, refuse, accept) embeds a deterministic provenance
 *      binding — canonical hash of the evaluated subject, sender
 *      identity/epoch, protocol version, and the local epoch that decided.
 *
 * Instance/epoch relation: a RuntimeInstanceId names ONE installation of
 * the runtime (stable across restarts); a RuntimeEpochId (23A) names ONE
 * live-owner incarnation of that installation. One instance has many
 * epochs over its life; an epoch belongs to exactly one instance. An
 * instance that presents two different node identities, or two rival
 * epochs that are not a monotone restart, is refused (split-brain
 * identity fails closed).
 */

import type { RuntimeEpochId } from "./continuity.js";
import { RUNTIME_EPOCH_ID_PATTERN } from "./continuity.js";
import { canonicalHash } from "./canonical.js";

// ── schema & protocol versions ───────────────────────────────────────────────

/** The ONLY federation protocol version this contract supports (v0). */
export const FEDERATION_PROTOCOL_VERSION = "menog-federation/v1" as const;
export type FederationProtocolVersion = typeof FEDERATION_PROTOCOL_VERSION;

/** Node identity document schema version. */
export const FEDERATION_IDENTITY_SCHEMA_VERSION = "menog-federation-identity/v0" as const;
export type FederationIdentitySchemaVersion = typeof FEDERATION_IDENTITY_SCHEMA_VERSION;

/** Federation signed-message schema version. */
export const FEDERATION_MESSAGE_SCHEMA_VERSION = "menog-federation-message/v0" as const;
export type FederationMessageSchemaVersion = typeof FEDERATION_MESSAGE_SCHEMA_VERSION;

/**
 * Clock-skew tolerance for `issuedAt`-style timestamps: timestamps are
 * ADVISORY evidence, never authority, but a document dated implausibly far
 * from local time is refused (fail closed). Beyond this window the local
 * runtime does not try to guess whose clock is wrong.
 */
export const FEDERATION_CLOCK_SKEW_TOLERANCE_MS = 120_000 as const;
export const FEDERATION_MAX_CLOCK_SKEW_TOLERANCE_MS = 600_000 as const;

/** Lineage depth bound: a causation chain deeper than this is refused. */
export const FEDERATION_MAX_LINEAGE_DEPTH = 16 as const;

// ── identity primitives (shapes only; the crypto lives in 24B) ───────────────

/**
 * Public key fingerprint, as produced by the 24B identity layer. Shape is
 * pinned here so the trust decisions do not depend on the primitive.
 */
export type NodeFingerprint = string;
/**
 * The pinned fingerprint form: algorithm-tagged SHA-256 hex (24B defines
 * the hash over the raw Ed25519 public key). The tag makes the fingerprint
 * self-describing and the pattern exact.
 */
export const NODE_FINGERPRINT_PREFIX = "fp-sha256-" as const;
export const NODE_FINGERPRINT_PATTERN = /^fp-sha256-[0-9a-f]{64}$/;

/**
 * NodeId: the stable identity of a federation peer. By contract it is the
 * CANONICAL, INJECTIVE function of the public fingerprint
 * (`node-` + fingerprint hex), so "same NodeId, different key" is
 * structurally detectable and key substitution fails closed (L1).
 */
export type NodeId = string;
export const NODE_ID_PATTERN = /^node-[0-9a-f]{32,128}$/;

/** Pure, injective NodeId derivation (no crypto, no I/O). */
export function deriveNodeId(fingerprint: NodeFingerprint):
  | { readonly ok: true; readonly nodeId: NodeId }
  | { readonly ok: false; readonly reason: string } {
  if (!NODE_FINGERPRINT_PATTERN.test(fingerprint)) {
    return { ok: false, reason: "fingerprint missing or malformed — no NodeId is derived (fail closed)" };
  }
  return { ok: true, nodeId: "node-" + fingerprint.slice(NODE_FINGERPRINT_PREFIX.length) };
}

/** L1 key-substitution check: a claimed NodeId must BE its fingerprint. */
export function nodeIdMatchesFingerprint(nodeId: NodeId, fingerprint: NodeFingerprint): boolean {
  const derived = deriveNodeId(fingerprint);
  return derived.ok && derived.nodeId === nodeId;
}

/**
 * RuntimeInstanceId: stable identity of ONE runtime installation,
 * persistent across restarts (unlike the 23A epoch, which is fresh per
 * process). Opaque, bounded, monotone-mixing — identity, never authority.
 */
export type RuntimeInstanceId = string;
export const RUNTIME_INSTANCE_ID_PATTERN = /^ri-[0-9a-f]{12}-[a-zA-Z0-9]{12}$/;

/** Pure instance-id factory (injectable clock/randomness; deterministic in tests). */
export function makeRuntimeInstanceId(nowEpochMs: number, randomness: string): RuntimeInstanceId {
  const t = Number.isFinite(nowEpochMs) && nowEpochMs > 0 ? Math.floor(nowEpochMs) : 0;
  const ts = t.toString(16).padStart(12, "0").slice(-12);
  const rnd = randomness.replace(/[^a-zA-Z0-9]/g, "").padEnd(12, "0").slice(0, 12);
  return `ri-${ts}-${rnd}`;
}

/** Federation message id (content-uniqueness is enforced by observation). */
export type FederationMessageId = string;
export const FEDERATION_MESSAGE_ID_PATTERN = /^fm-[0-9a-f]{16}-[a-zA-Z0-9]{16}$/;

/** Pure message-id factory (injectable clock/randomness; deterministic in tests). */
export function makeFederationMessageId(nowEpochMs: number, randomness: string): FederationMessageId {
  const t = Number.isFinite(nowEpochMs) && nowEpochMs > 0 ? Math.floor(nowEpochMs) : 0;
  const ts = t.toString(16).padStart(16, "0").slice(-16);
  const rnd = randomness.replace(/[^a-zA-Z0-9]/g, "").padEnd(16, "0").slice(0, 16);
  return `fm-${ts}-${rnd}`;
}

// ── instance→epoch observation (L5 + split-brain identity) ───────────────────

interface InstanceObservation {
  readonly nodeId: NodeId;
  newestEpochStartedMs: number;
  readonly epochIds: Set<string>;
}

/** Pure, caller-owned observation state (24C persists it later; not here). */
export interface InstanceEpochTracker {
  readonly instances: Map<RuntimeInstanceId, InstanceObservation>;
}

export function newInstanceEpochTracker(): InstanceEpochTracker {
  return { instances: new Map() };
}

export type InstanceEpochObservation =
  | { readonly ok: true; readonly code: "observed_new"; readonly explanation: string }
  | { readonly ok: true; readonly code: "observed_same"; readonly explanation: string }
  | { readonly ok: false; readonly code: "refused_stale"; readonly explanation: string }
  | { readonly ok: false; readonly code: "refused_split_brain"; readonly explanation: string }
  | { readonly ok: false; readonly code: "refused_identity_collision"; readonly explanation: string }
  | { readonly ok: false; readonly code: "refused_malformed_epoch"; readonly explanation: string };

function epochStartedMsOf(epochId: RuntimeEpochId): number | null {
  if (!RUNTIME_EPOCH_ID_PATTERN.test(epochId)) return null;
  const m = /^re-([0-9a-f]{12})-/.exec(epochId);
  const hex = m === null ? undefined : m[1];
  if (hex === undefined) return null;
  const ms = Number.parseInt(hex, 16);
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Observe one (instance, epoch, node) triple. Fail-closed rules:
 *  - the epoch id must match the frozen 23A epoch shape (else malformed);
 *  - an instance already bound to a DIFFERENT NodeId is an identity
 *    collision (Sybil / key-substitution signal) and refuses;
 *  - an epoch NEWER than the newest observed epoch for the instance is a
 *    legitimate restart/supersession and is admitted;
 *  - an epoch OLDER than the newest observed is stale and refuses (L5);
 *  - a DIFFERENT epoch with the SAME start tick as the newest observed is
 *    a same-tick rival (split-brain identity) and refuses.
 */
export function observeInstanceEpoch(
  tracker: InstanceEpochTracker,
  input: {
    readonly nodeId: NodeId;
    readonly instanceId: RuntimeInstanceId;
    readonly epochId: RuntimeEpochId;
  }
): InstanceEpochObservation {
  const startedMs = epochStartedMsOf(input.epochId);
  if (startedMs === null) {
    return {
      ok: false,
      code: "refused_malformed_epoch",
      explanation: "epoch id does not match the frozen 23A epoch shape — refusing (fail closed)",
    };
  }
  if (!NODE_ID_PATTERN.test(input.nodeId)) {
    return {
      ok: false,
      code: "refused_identity_collision",
      explanation: "node id is malformed — refusing (fail closed)",
    };
  }
  const existing = tracker.instances.get(input.instanceId);
  if (existing === undefined) {
    tracker.instances.set(input.instanceId, {
      nodeId: input.nodeId,
      newestEpochStartedMs: startedMs,
      epochIds: new Set([input.epochId]),
    });
    return {
      ok: true,
      code: "observed_new",
      explanation: "first observation of this instance — identity bound, epoch admitted as newest",
    };
  }
  if (existing.nodeId !== input.nodeId) {
    return {
      ok: false,
      code: "refused_identity_collision",
      explanation:
        "instance '" + input.instanceId + "' is already bound to a different node identity — refusing (split-brain identity / key substitution fails closed)",
    };
  }
  if (existing.epochIds.has(input.epochId)) {
    return {
      ok: true,
      code: "observed_same",
      explanation: "epoch already observed for this instance (idempotent re-observation)",
    };
  }
  if (startedMs === existing.newestEpochStartedMs) {
    return {
      ok: false,
      code: "refused_split_brain",
      explanation:
        "a rival epoch with the same start tick as the newest observed epoch for this instance — split-brain identity fails closed",
    };
  }
  if (startedMs < existing.newestEpochStartedMs) {
    return {
      ok: false,
      code: "refused_stale",
      explanation: "epoch is older than the newest observed epoch for this instance — stale epochs fail (L5)",
    };
  }
  existing.epochIds.add(input.epochId);
  existing.newestEpochStartedMs = startedMs;
  return {
    ok: true,
    code: "observed_new",
    explanation: "newer epoch for a known instance — monotone restart/supersession admitted",
  };
}

// ── peer trust state machine (L6; mirrors repository terminal law) ───────────

/**
 * The closed peer-trust vocabulary (pack-defined; quarantine/retirement
 * semantics mirror the repository's registry lifecycle law: quarantined →
 * retired only, retired is terminal, neither resurrects).
 */
export const NODE_TRUST_STATES = Object.freeze([
  "unknown",
  "candidate",
  "admitted",
  "quarantined",
  "retired",
] as const);
export type NodeTrustState = (typeof NODE_TRUST_STATES)[number];

/**
 * The ONLY legal trust transitions. quarantined → admitted and retired →
 * anything are UNREPRESENTABLE (L6). `admitted → candidate` is likewise
 * refused: demotion is not a path around quarantine.
 */
export const PEER_TRUST_TRANSITIONS: Readonly<
  Record<NodeTrustState, readonly NodeTrustState[]>
> = Object.freeze({
  unknown: Object.freeze(["candidate"] as const),
  candidate: Object.freeze(["admitted", "quarantined", "retired"] as const),
  // 24C amendment (unfreeze event): admitted → retired added — direct
  // evidenced operator retirement mirrors the 21A registry law
  // (enabled → retired). Quarantined → admitted and retired → anything
  // remain UNREPRESENTABLE (L6).
  admitted: Object.freeze(["quarantined", "retired"] as const),
  quarantined: Object.freeze(["retired"] as const),
  retired: Object.freeze([] as const),
});

export function isPeerTrustTransition(from: NodeTrustState, to: NodeTrustState): boolean {
  return (PEER_TRUST_TRANSITIONS[from] as readonly string[]).includes(to);
}

export type PeerTrustTransitionDecision =
  | { readonly ok: true; readonly code: "transition_allowed"; readonly to: NodeTrustState; readonly explanation: string }
  | { readonly ok: false; readonly code: "transition_refused"; readonly to: NodeTrustState; readonly explanation: string };

/**
 * Pure decision for a proposed trust transition. Evidence-bearing
 * transitions (unknown→candidate, candidate→admitted, any→quarantined/
 * retired) are the caller's responsibility to persist (24C); this
 * function only decides legality and records WHY (L6: no resurrection).
 */
export function decideTrustTransition(input: {
  readonly from: NodeTrustState;
  readonly to: NodeTrustState;
  readonly evidence: string;
}): PeerTrustTransitionDecision {
  if (!isPeerTrustTransition(input.from, input.to)) {
    return {
      ok: false,
      code: "transition_refused",
      to: input.to,
      explanation:
        "trust transition " + input.from + "→" + input.to + " is not in the closed machine — quarantined/retired peers never resurrect (L6, fail closed)",
    };
  }
  if (input.evidence.trim() === "") {
    return {
      ok: false,
      code: "transition_refused",
      to: input.to,
      explanation: "trust transitions require evidence — refusing an unevidenced trust change (fail closed)",
    };
  }
  return {
    ok: true,
    code: "transition_allowed",
    to: input.to,
    explanation: "trust transition " + input.from + "→" + input.to + " allowed with evidence",
  };
}

// ── node identity document (signed by 24B; verified through a port) ──────────

/** The unsigned body of a node identity document (closed field set, L4). */
export interface NodeIdentityDocumentBody {
  readonly schemaVersion: FederationIdentitySchemaVersion;
  readonly nodeId: NodeId;
  readonly fingerprint: NodeFingerprint;
  readonly instanceId: RuntimeInstanceId;
  /** The sender's CURRENT 23A epoch (fresh per process; L5 applies). */
  readonly epochId: RuntimeEpochId;
  readonly protocolVersion: FederationProtocolVersion;
  readonly issuedAtEpochMs: number;
}

/** A signed identity document: body + opaque signature (verified via port). */
export interface SignedIdentityDocument {
  readonly document: NodeIdentityDocumentBody;
  /** Opaque signature material — produced/verified by the 24B layer. */
  readonly signature: string;
}

/**
 * The ONLY signature-verification seam in this contract. 24B implements
 * it; 24A never imports crypto. A verification outcome is AUTHENTICATION
 * evidence and never authorization (L2). The port is subject-agnostic:
 * it verifies identity documents AND federation message bodies.
 */
export type IdentitySignatureVerifier = (input: {
  readonly document: NodeIdentityDocumentBody | FederationMessageBody;
  readonly signature: string;
}) => { readonly ok: boolean; readonly reason?: string };

const IDENTITY_DOCUMENT_KEYS: readonly string[] = Object.freeze([
  "schemaVersion",
  "nodeId",
  "fingerprint",
  "instanceId",
  "epochId",
  "protocolVersion",
  "issuedAtEpochMs",
]);

function hasExactlyKeys(value: object, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((k, i) => k === expected[i]);
}

/**
 * Structural + relational validation of a signed identity document
 * (pure). Order of refusal (fail closed, most specific first):
 * shape/unknown-fields → schema → key-substitution (NodeId↔fingerprint) →
 * protocol (downgrade) → signature (port) → skew → epoch freshness via
 * the instance tracker (stale/split-brain/identity-collision).
 */
export function validateNodeIdentityDocument(input: {
  readonly document: SignedIdentityDocument["document"];
  readonly signature: SignedIdentityDocument["signature"];
  readonly verifier: IdentitySignatureVerifier;
  readonly epochTracker: InstanceEpochTracker;
  readonly nowEpochMs: number;
  readonly localEpochId: RuntimeEpochId | null;
  readonly skewToleranceMs?: number;
}):
  | { readonly ok: true; readonly code: "identity_document_accepted"; readonly provenance: FederationProvenanceBinding; readonly explanation: string }
  | {
      readonly ok: false;
      readonly code:
        | "refused_malformed"
        | "refused_nodeid_fingerprint_mismatch"
        | "refused_protocol_mismatch"
        | "refused_signature_invalid"
        | "refused_skew_out_of_tolerance"
        | "refused_stale_epoch"
        | "refused_split_brain"
        | "refused_identity_collision";
      readonly provenance: FederationProvenanceBinding | null;
      readonly explanation: string;
    } {
  const doc = input.document;
  if (
    typeof doc !== "object" ||
    doc === null ||
    !hasExactlyKeys(doc, IDENTITY_DOCUMENT_KEYS) ||
    typeof doc.schemaVersion !== "string" ||
    typeof doc.nodeId !== "string" ||
    typeof doc.fingerprint !== "string" ||
    typeof doc.instanceId !== "string" ||
    typeof doc.epochId !== "string" ||
    typeof doc.protocolVersion !== "string" ||
    typeof doc.issuedAtEpochMs !== "number" ||
    typeof input.signature !== "string" ||
    input.signature.length === 0
  ) {
    return {
      ok: false,
      code: "refused_malformed",
      provenance: null,
      explanation: "identity document is missing fields, has unknown fields, or carries malformed values — refusing (L4/L8, fail closed)",
    };
  }
  const provenanceBase = {
    subjectId: doc.nodeId,
    subjectHash: canonicalHash(doc),
    senderNodeId: doc.nodeId,
    senderInstanceId: doc.instanceId,
    senderEpochId: doc.epochId,
    protocolVersion: doc.protocolVersion as FederationProtocolVersion,
    localEpochId: input.localEpochId,
    decidedAtEpochMs: input.nowEpochMs,
    authority: "none" as const,
  };
  if (doc.schemaVersion !== FEDERATION_IDENTITY_SCHEMA_VERSION) {
    return {
      ok: false,
      code: "refused_malformed",
      provenance: { ...provenanceBase, subjectId: "unidentified" },
      explanation: "identity document schema version '" + doc.schemaVersion + "' is not supported — refusing (L8, fail closed)",
    };
  }
  if (!nodeIdMatchesFingerprint(doc.nodeId, doc.fingerprint)) {
    return {
      ok: false,
      code: "refused_nodeid_fingerprint_mismatch",
      provenance: { ...provenanceBase, subjectId: "unidentified" },
      explanation: "claimed NodeId is not the canonical derivation of the presented fingerprint — key substitution fails closed (L1)",
    };
  }
  if (doc.protocolVersion !== FEDERATION_PROTOCOL_VERSION) {
    return {
      ok: false,
      code: "refused_protocol_mismatch",
      provenance: { ...provenanceBase, subjectId: "unidentified" },
      explanation: "peer speaks protocol '" + doc.protocolVersion + "', not '" + FEDERATION_PROTOCOL_VERSION + "' — downgrade refused (L8)",
    };
  }
  const verification = input.verifier({ document: doc, signature: input.signature });
  if (!verification.ok) {
    return {
      ok: false,
      code: "refused_signature_invalid",
      provenance: { ...provenanceBase, subjectId: "unidentified" },
      explanation: "signature verification failed" + (verification.reason ? " (" + verification.reason + ")" : "") + " — spoofing fails closed; note: a VALID signature would still grant no authority (L2)",
    };
  }
  const tolerance = input.skewToleranceMs ?? FEDERATION_CLOCK_SKEW_TOLERANCE_MS;
  if (
    !Number.isFinite(tolerance) ||
    tolerance < 0 ||
    tolerance > FEDERATION_MAX_CLOCK_SKEW_TOLERANCE_MS
  ) {
    return {
      ok: false,
      code: "refused_malformed",
      provenance: { ...provenanceBase, subjectId: "unidentified" },
      explanation: "skew tolerance is out of the contracted range — refusing rather than widening the window (fail closed)",
    };
  }
  if (
    Math.abs(input.nowEpochMs - doc.issuedAtEpochMs) > tolerance ||
    !Number.isFinite(doc.issuedAtEpochMs)
  ) {
    return {
      ok: false,
      code: "refused_skew_out_of_tolerance",
      provenance: { ...provenanceBase, subjectId: "unidentified" },
      explanation: "document issuance time is outside the local skew tolerance — clock-skewed claims are refused, never silently accepted",
    };
  }
  const observation = observeInstanceEpoch(input.epochTracker, {
    nodeId: doc.nodeId,
    instanceId: doc.instanceId,
    epochId: doc.epochId,
  });
  if (!observation.ok) {
    return {
      ok: false,
      code:
        observation.code === "refused_malformed_epoch"
          ? "refused_malformed"
          : observation.code === "refused_stale"
            ? "refused_stale_epoch"
            : observation.code,
      provenance: { ...provenanceBase, subjectId: "unidentified" },
      explanation: observation.explanation,
    };
  }
  return {
    ok: true,
    code: "identity_document_accepted",
    provenance: provenanceBase,
    explanation: "identity document accepted (" + observation.code + "): authenticated data about a peer — this grants NO authority (L1/L2)",
  };
}

// ── provenance binding (L9: every decision binds its subject) ────────────────

export interface FederationProvenanceBinding {
  readonly subjectId: string;
  /** Deterministic canonical hash of the evaluated subject body. */
  readonly subjectHash: string;
  readonly senderNodeId: NodeId;
  readonly senderInstanceId: RuntimeInstanceId;
  readonly senderEpochId: RuntimeEpochId;
  readonly protocolVersion: FederationProtocolVersion;
  /** The LOCAL epoch that made this decision (null only if none is open). */
  readonly localEpochId: RuntimeEpochId | null;
  readonly decidedAtEpochMs: number;
  /** ALWAYS "none" — provenance is data, never authority (L1/L2). */
  readonly authority: "none";
}

// ── peer admission request/decision ─────────────────────────────────────────

export interface PeerAdmissionRequest {
  readonly requestId: string;
  readonly document: SignedIdentityDocument["document"];
  readonly signature: SignedIdentityDocument["signature"];
  readonly requestedAtEpochMs: number;
}

export const PEER_ADMISSION_OUTCOMES = Object.freeze([
  "admit",
  "quarantine",
  "refuse",
] as const);
export type PeerAdmissionOutcome = (typeof PEER_ADMISSION_OUTCOMES)[number];

export const PEER_ADMISSION_DENY_CODES = Object.freeze([
  "malformed_request",
  "identity_document_rejected",
  "peer_terminal_state",
  "trust_transition_refused",
  "request_skew_out_of_tolerance",
] as const);
export type PeerAdmissionDenyCode = (typeof PEER_ADMISSION_DENY_CODES)[number];

/**
 * The admission decision. Outcomes (closed):
 *  - admit      → the peer's trust state may move to `admitted`
 *  - quarantine → the peer's trust state may move to `quarantined`
 *  - refuse     → NO trust change; the request is dead
 * NONE of these outcomes grants, narrows, or references execution
 * permission (L3): there is no execution field in this type at all.
 */
export type PeerAdmissionDecision =
  | {
      readonly ok: true;
      readonly outcome: "admit";
      readonly code: "admission_admitted";
      readonly targetState: "admitted";
      readonly provenance: FederationProvenanceBinding;
      readonly explanation: string;
    }
  | {
      readonly ok: true;
      readonly outcome: "quarantine";
      readonly code: "admission_quarantined";
      readonly targetState: "quarantined";
      readonly provenance: FederationProvenanceBinding;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly outcome: "refuse";
      readonly code: "admission_refused";
      readonly denyReason: PeerAdmissionDenyCode;
      readonly provenance: FederationProvenanceBinding | null;
      readonly explanation: string;
    };

/**
 * The ONLY sanctioned admission decision (pure). Fail-closed chain:
 * request shape → skew → identity document (full validator) → terminal
 * peers refuse (L6) → target transition must be legal in the closed trust
 * machine. A well-formed, authenticated, fresh request from a non-terminal
 * peer is ADMITTED as communication trust only — every later execution
 * still needs fresh LOCAL authority (L3/L7).
 */
export function decidePeerAdmission(input: {
  readonly request: PeerAdmissionRequest;
  readonly senderTrustState: NodeTrustState;
  readonly verifier: IdentitySignatureVerifier;
  readonly epochTracker: InstanceEpochTracker;
  readonly nowEpochMs: number;
  readonly localEpochId: RuntimeEpochId | null;
  readonly skewToleranceMs?: number;
}): PeerAdmissionDecision {
  const req = input.request;
  if (
    typeof req !== "object" ||
    req === null ||
    typeof req.requestId !== "string" ||
    req.requestId.length === 0 ||
    typeof req.requestedAtEpochMs !== "number" ||
    !Number.isFinite(req.requestedAtEpochMs)
  ) {
    return {
      ok: false,
      outcome: "refuse",
      code: "admission_refused",
      denyReason: "malformed_request",
      provenance: null,
      explanation: "admission request is malformed — refusing (fail closed)",
    };
  }
  const tolerance = input.skewToleranceMs ?? FEDERATION_CLOCK_SKEW_TOLERANCE_MS;
  if (Math.abs(input.nowEpochMs - req.requestedAtEpochMs) > tolerance) {
    return {
      ok: false,
      outcome: "refuse",
      code: "admission_refused",
      denyReason: "request_skew_out_of_tolerance",
      provenance: null,
      explanation: "admission request timestamp is outside the local skew tolerance — refusing (fail closed)",
    };
  }
  const docDecision = validateNodeIdentityDocument({
    document: req.document,
    signature: req.signature,
    verifier: input.verifier,
    epochTracker: input.epochTracker,
    nowEpochMs: input.nowEpochMs,
    localEpochId: input.localEpochId,
    skewToleranceMs: input.skewToleranceMs,
  });
  if (!docDecision.ok) {
    return {
      ok: false,
      outcome: "refuse",
      code: "admission_refused",
      denyReason: "identity_document_rejected",
      provenance: docDecision.provenance,
      explanation: "identity document rejected ('" + docDecision.code + "'): " + docDecision.explanation,
    };
  }
  const provenance = docDecision.provenance;
  if (input.senderTrustState === "quarantined" || input.senderTrustState === "retired") {
    return {
      ok: false,
      outcome: "refuse",
      code: "admission_refused",
      denyReason: "peer_terminal_state",
      provenance,
      explanation:
        "sender is '" + input.senderTrustState + "' — quarantined/retired peers do not resurrect (L6, fail closed); re-entry requires a genuinely new identity evaluated as a new peer",
    };
  }
  const target: NodeTrustState = "admitted";
  const transition = decideTrustTransition({
    from: input.senderTrustState,
    to: target,
    evidence: "admission: " + provenance.subjectHash,
  });
  if (!transition.ok) {
    return {
      ok: false,
      outcome: "refuse",
      code: "admission_refused",
      denyReason: "trust_transition_refused",
      provenance,
      explanation: transition.explanation,
    };
  }
  return {
    ok: true,
    outcome: "admit",
    code: "admission_admitted",
    targetState: "admitted",
    provenance,
    explanation:
      "peer admitted for COMMUNICATION trust only — this decision grants no execution permission; every execution remains behind fresh LOCAL Allocation → Policy → Phase-20 isolation → Phase-21 governed tool runtime (L3/L7)",
  };
}

// ── federation signed-message contract (shape + admission laws) ──────────────

/** Closed union of remote intents. INERT DATA: none of these execute. */
export const FEDERATION_DECLARED_INTENTS = Object.freeze([
  "task_proposal",
  "evidence",
  "response",
] as const);
export type FederationDeclaredIntent = (typeof FEDERATION_DECLARED_INTENTS)[number];

/** The unsigned body of a federation signed message (closed field set, L4). */
export interface FederationMessageBody {
  readonly schemaVersion: FederationMessageSchemaVersion;
  readonly messageId: FederationMessageId;
  readonly senderNodeId: NodeId;
  readonly senderFingerprint: NodeFingerprint;
  readonly senderInstanceId: RuntimeInstanceId;
  readonly senderEpochId: RuntimeEpochId;
  readonly protocolVersion: FederationProtocolVersion;
  /** Hash of the payload — the payload itself never travels in the envelope. */
  readonly payloadHash: string;
  readonly declaredIntent: FederationDeclaredIntent;
  /** Conversation group id (a message id), or null. */
  readonly correlationId: FederationMessageId | null;
  /** The direct parent message id, or null (root). */
  readonly causationId: FederationMessageId | null;
  /** Ancestor chain (bounded, acyclic, no self-reference). */
  readonly lineage: readonly FederationMessageId[];
  readonly issuedAtEpochMs: number;
}

/** A signed federation message: body + opaque signature (verified via port). */
export interface FederationSignedMessage {
  readonly message: FederationMessageBody;
  readonly signature: string;
}



const MESSAGE_BODY_KEYS: readonly string[] = Object.freeze([
  "schemaVersion",
  "messageId",
  "senderNodeId",
  "senderFingerprint",
  "senderInstanceId",
  "senderEpochId",
  "protocolVersion",
  "payloadHash",
  "declaredIntent",
  "correlationId",
  "causationId",
  "lineage",
  "issuedAtEpochMs",
]);

/**
 * The exact body field set of a federation signed message (24D reuses this
 * for envelope staging so a real envelope cannot drift from the contract).
 */
export const FEDERATION_MESSAGE_BODY_KEYS: readonly string[] = MESSAGE_BODY_KEYS;

export const FEDERATION_MESSAGE_DENY_CODES = Object.freeze([
  "malformed_message",
  "unknown_field",
  "nodeid_fingerprint_mismatch",
  "protocol_mismatch",
  "signature_invalid",
  "replay_detected",
  "stale_epoch",
  "split_brain",
  "identity_collision",
  "skew_out_of_tolerance",
  "lineage_malformed",
] as const);
export type FederationMessageDenyCode = (typeof FEDERATION_MESSAGE_DENY_CODES)[number];

/** Pure, caller-owned replay state (24D wires it into its pipeline). */
export interface MessageReplayTracker {
  readonly seen: Set<FederationMessageId>;
}

export function newMessageReplayTracker(): MessageReplayTracker {
  return { seen: new Set() };
}

export type MessageIdObservation =
  | { readonly ok: true; readonly code: "first_observed"; readonly explanation: string }
  | { readonly ok: false; readonly code: "replay_detected"; readonly explanation: string };

/** L8 replay control: a message id is admitted exactly ONCE, ever. */
export function observeMessageId(
  tracker: MessageReplayTracker,
  messageId: FederationMessageId
): MessageIdObservation {
  if (tracker.seen.has(messageId)) {
    return {
      ok: false,
      code: "replay_detected",
      explanation: "message id was already observed — this is a REPLAY and is refused (L8, fail closed)",
    };
  }
  tracker.seen.add(messageId);
  return {
    ok: true,
    code: "first_observed",
    explanation: "message id first observed — replay window consumed",
  };
}

export type LineageCheck =
  | { readonly ok: true; readonly explanation: string }
  | { readonly ok: false; readonly reason: string };

/**
 * Structural lineage well-formedness: bounded depth, valid ids, no
 * duplicates, no self-reference, causation (when present) must appear in
 * the lineage, correlation (when present) must not be self. Lineage
 * CONTENT is remote data — it is provenance-bound, never trusted (L7/L9).
 */
export function checkLineage(message: FederationMessageBody): LineageCheck {
  if (!Array.isArray(message.lineage)) {
    return { ok: false, reason: "lineage is not an array" };
  }
  if (message.lineage.length > FEDERATION_MAX_LINEAGE_DEPTH) {
    return { ok: false, reason: "lineage exceeds the contracted depth bound" };
  }
  const seen = new Set<string>();
  for (const entry of message.lineage) {
    if (typeof entry !== "string" || !FEDERATION_MESSAGE_ID_PATTERN.test(entry)) {
      return { ok: false, reason: "lineage contains a malformed message id" };
    }
    if (entry === message.messageId) {
      return { ok: false, reason: "lineage contains the message itself (self-reference)" };
    }
    if (seen.has(entry)) {
      return { ok: false, reason: "lineage contains a duplicate entry" };
    }
    seen.add(entry);
  }
  if (message.causationId !== null) {
    if (!FEDERATION_MESSAGE_ID_PATTERN.test(message.causationId)) {
      return { ok: false, reason: "causation id is malformed" };
    }
    if (message.causationId === message.messageId) {
      return { ok: false, reason: "message causes itself" };
    }
    if (!seen.has(message.causationId)) {
      return { ok: false, reason: "causation id is not present in the lineage" };
    }
  }
  if (message.correlationId !== null) {
    if (!FEDERATION_MESSAGE_ID_PATTERN.test(message.correlationId)) {
      return { ok: false, reason: "correlation id is malformed" };
    }
    if (message.correlationId === message.messageId) {
      return { ok: false, reason: "message correlates with itself" };
    }
  }
  return { ok: true, explanation: "lineage is structurally well-formed (content remains untrusted remote data)" };
}

/**
 * The ONLY sanctioned signed-message contract validation (pure). Checks,
 * in fail-closed order: exact shape/unknown fields → schema →
 * NodeId↔fingerprint (key substitution) → protocol (downgrade) →
 * signature (port) → skew → lineage well-formedness → replay (once-ever
 * message ids) → epoch freshness via the instance tracker. Acceptance
 * means "well-formed, authenticated DATA about a proposal/evidence/
 * response" — it NEVER authorizes execution (L1/L2/L7).
 */
export function validateSignedMessageContract(input: {
  readonly message: FederationSignedMessage["message"];
  readonly signature: FederationSignedMessage["signature"];
  readonly verifier: IdentitySignatureVerifier;
  readonly replayTracker: MessageReplayTracker;
  readonly epochTracker: InstanceEpochTracker;
  readonly nowEpochMs: number;
  readonly localEpochId: RuntimeEpochId | null;
  readonly skewToleranceMs?: number;
}):
  | { readonly ok: true; readonly code: "message_contract_accepted"; readonly provenance: FederationProvenanceBinding; readonly explanation: string }
  | {
      readonly ok: false;
      readonly code: "message_contract_refused";
      readonly denyReason: FederationMessageDenyCode;
      readonly provenance: FederationProvenanceBinding | null;
      readonly explanation: string;
    } {
  const msg = input.message;
  const bodyWellFormed =
    typeof msg === "object" &&
    msg !== null &&
    hasExactlyKeys(msg, MESSAGE_BODY_KEYS) &&
    typeof msg.schemaVersion === "string" &&
    typeof msg.messageId === "string" &&
    typeof msg.senderNodeId === "string" &&
    typeof msg.senderFingerprint === "string" &&
    typeof msg.senderInstanceId === "string" &&
    typeof msg.senderEpochId === "string" &&
    typeof msg.protocolVersion === "string" &&
    typeof msg.payloadHash === "string" &&
    msg.payloadHash.length > 0 &&
    typeof msg.declaredIntent === "string" &&
    (FEDERATION_DECLARED_INTENTS as readonly string[]).includes(msg.declaredIntent) &&
    (msg.correlationId === null || typeof msg.correlationId === "string") &&
    (msg.causationId === null || typeof msg.causationId === "string") &&
    typeof msg.issuedAtEpochMs === "number";
  if (!bodyWellFormed || typeof input.signature !== "string" || input.signature.length === 0) {
    return {
      ok: false,
      code: "message_contract_refused",
      denyReason: "malformed_message",
      provenance: null,
      explanation: "signed message is missing fields, carries unknown fields, or has malformed values — refusing (L4/L8, fail closed)",
    };
  }
  const provenanceBase: FederationProvenanceBinding = {
    subjectId: msg.messageId,
    subjectHash: canonicalHash(msg),
    senderNodeId: msg.senderNodeId,
    senderInstanceId: msg.senderInstanceId,
    senderEpochId: msg.senderEpochId,
    protocolVersion: msg.protocolVersion as FederationProtocolVersion,
    localEpochId: input.localEpochId,
    decidedAtEpochMs: input.nowEpochMs,
    authority: "none",
  };
  const refused = (
    denyReason: FederationMessageDenyCode,
    explanation: string
  ): {
    readonly ok: false;
    readonly code: "message_contract_refused";
    readonly denyReason: FederationMessageDenyCode;
    readonly provenance: FederationProvenanceBinding | null;
    readonly explanation: string;
  } => ({ ok: false, code: "message_contract_refused", denyReason, provenance: provenanceBase, explanation });

  if (msg.schemaVersion !== FEDERATION_MESSAGE_SCHEMA_VERSION) {
    return refused("malformed_message", "message schema version '" + msg.schemaVersion + "' is not supported — refusing (L8)");
  }
  if (!FEDERATION_MESSAGE_ID_PATTERN.test(msg.messageId)) {
    return refused("malformed_message", "message id is malformed — refusing (fail closed)");
  }
  if (!nodeIdMatchesFingerprint(msg.senderNodeId, msg.senderFingerprint)) {
    return refused("nodeid_fingerprint_mismatch", "claimed NodeId is not the canonical derivation of the presented fingerprint — key substitution fails closed (L1)");
  }
  if (msg.protocolVersion !== FEDERATION_PROTOCOL_VERSION) {
    return refused("protocol_mismatch", "peer speaks protocol '" + msg.protocolVersion + "', not '" + FEDERATION_PROTOCOL_VERSION + "' — downgrade refused (L8)");
  }
  const verification = input.verifier({ document: msg, signature: input.signature });
  if (!verification.ok) {
    return refused("signature_invalid", "signature verification failed" + (verification.reason ? " (" + verification.reason + ")" : "") + " — spoofing fails closed; a VALID signature would still grant no authority (L2)");
  }
  const tolerance = input.skewToleranceMs ?? FEDERATION_CLOCK_SKEW_TOLERANCE_MS;
  if (!Number.isFinite(tolerance) || tolerance < 0 || tolerance > FEDERATION_MAX_CLOCK_SKEW_TOLERANCE_MS) {
    return refused("malformed_message", "skew tolerance is out of the contracted range — refusing rather than widening the window");
  }
  if (Math.abs(input.nowEpochMs - msg.issuedAtEpochMs) > tolerance || !Number.isFinite(msg.issuedAtEpochMs)) {
    return refused("skew_out_of_tolerance", "message issuance time is outside the local skew tolerance — clock-skewed claims are refused, never silently accepted");
  }
  const lineage = checkLineage(msg);
  if (!lineage.ok) {
    return refused("lineage_malformed", "lineage rejected: " + lineage.reason + " — lineage forgery fails closed (L8)");
  }
  const replay = observeMessageId(input.replayTracker, msg.messageId);
  if (!replay.ok) {
    return refused("replay_detected", replay.explanation);
  }
  const observation = observeInstanceEpoch(input.epochTracker, {
    nodeId: msg.senderNodeId,
    instanceId: msg.senderInstanceId,
    epochId: msg.senderEpochId,
  });
  if (!observation.ok) {
    return refused(
      observation.code === "refused_malformed_epoch"
        ? "malformed_message"
        : observation.code === "refused_stale"
          ? "stale_epoch"
          : observation.code === "refused_split_brain"
            ? "split_brain"
            : "identity_collision",
      observation.explanation
    );
  }
  return {
    ok: true,
    code: "message_contract_accepted",
    provenance: provenanceBase,
    explanation:
      "message accepted under the contract (" + observation.code + "): well-formed, authenticated, replay-free DATA — remote intent '" +
      msg.declaredIntent + "' is inert and can never execute locally (L7); any resulting local action needs fresh LOCAL authority",
  };
}
