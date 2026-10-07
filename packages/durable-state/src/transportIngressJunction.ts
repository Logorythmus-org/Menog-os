/**
 * PHASE 26E — Transport → Federation Ingress Junction (THE ONE JUNCTION).
 *
 * This module is the SINGLE place where live local-transport bytes become a
 * federation message. It composes the frozen Phase-24/25 gates and the Phase-26
 * transport stack; it re-implements none of them and holds NO store, NO
 * listener, NO dialer, NO shell, NO tool surface, and NO clock.
 *
 * THE MANDATORY ORDER (fail closed, first refusal wins, suite-pinned):
 *   1 frame_validity          26A decideFrame — bounded/intact/in-order DATA
 *   2 session_binding         26D session established + transcript/epoch bound
 *   3 current_key_use         25B decideKeyUse, live records, both sides
 *   4 local_admission         24C current LOCAL admission of THIS peer
 *   5 disclosure_verification 25D verifyEgressManifest where required
 *   6 schema_version          frozen 22A/24A shape, version and claim scope
 *   7 authentication          24B Ed25519 over the closed body
 *   8 replay_receipt          24D durable replay guard + receipt (the port)
 *   9 untrusted_inbox         untrusted DATA only — never execution
 *
 * REACHABILITY != IDENTITY != ADMISSION != AUTHORITY != EXECUTION. A refusal
 * at any stage means the message never reaches the next stage; there is no
 * fallback, widening, partial admission, or alternate path.
 *
 * EXECUTION IS NOT REACHABLE FROM HERE. Ingress grants nothing: the result
 * carries authority "none" and executionAuthorized false, and the closed
 * authority-claim field set refuses any inbound field that would smuggle a
 * LOCAL allocation, a LOCAL Policy decision, an actor binding, a capability
 * grant, or a tool invocation. Only later fresh LOCAL allocation + fresh
 * LOCAL Policy FOR THE ASSIGNED ACTOR + Phase-20/21 may execute, and that
 * gate is not on the wire, not reachable from this module, and never
 * satisfiable by remote data.
 */

import { canonicalHash } from "./canonical.js";
import {
  decideFrame,
  decideTransportScope,
  type TransportTrustPin,
} from "./federationTransportTrust.js";
import { makeIdentitySignatureVerifier, verifyRestartIdentity } from "./federationCrypto.js";
import { decideKeyUse, deriveKeyId, type KeyLifecycleRecord } from "./federationKeyLifecycle.js";
import {
  FEDERATION_DECLARED_INTENTS,
  FEDERATION_MESSAGE_BODY_KEYS,
  NODE_ID_PATTERN,
  NODE_TRUST_STATES,
  type FederationSignedMessage,
  type NodeTrustState,
} from "./federationIdentity.js";
import { RUNTIME_EPOCH_ID_PATTERN } from "./continuity.js";
import { verifyEgressManifest, type DisclosureManifest } from "./federationEgress.js";
import type { AuthenticatedSession } from "./authenticatedSession.js";

/** Closed schema version of this junction's own decision record. */
export const INGRESS_JUNCTION_SCHEMA_VERSION = "menog-transport-ingress-junction/v0" as const;

/** The TRANSPORT protocol a frame must present to reach the junction (26D's pinned one). */
export const INGRESS_EXPECTED_PROTOCOL_VERSION = "menog-auth-session/v1" as const;

/**
 * The FEDERATION protocol a message body must declare (frozen 24A). This is
 * deliberately a DIFFERENT pin from the transport protocol above: the frame
 * speaks the session protocol, the signed body speaks the federation
 * protocol, and each refuses the other's version as a downgrade.
 */
export const INGRESS_EXPECTED_FEDERATION_PROTOCOL_VERSION = "menog-federation/v1" as const;

/** The frozen 24A message schema version this junction accepts. */
export const INGRESS_EXPECTED_MESSAGE_SCHEMA_VERSION = "menog-federation-message/v0" as const;

/**
 * The MANDATORY ORDER as a closed vocabulary. Index IS the position: the
 * decision function walks this array and never reorders, skips, or repeats a
 * stage. A caller may not add, remove, or reorder a stage.
 */
export const INGRESS_STAGES = Object.freeze([
  "frame_validity",
  "session_binding",
  "current_key_use",
  "local_admission",
  "disclosure_verification",
  "schema_version",
  "authentication",
  "replay_receipt",
  "untrusted_inbox",
] as const);
export type IngressStage = (typeof INGRESS_STAGES)[number];

/**
 * Which refusal codes each stage may emit. Closed and suite-pinned: a stage
 * cannot refuse with another stage's code, so the failing stage is
 * unambiguous from the result alone.
 */
export const INGRESS_STAGE_CODES: Readonly<Record<IngressStage, readonly IngressRefusalCode[]>> =
  Object.freeze({
    frame_validity: Object.freeze(["config_invalid", "frame_refused"] as const),
    session_binding: Object.freeze(["config_invalid", "session_not_bound", "epoch_stale"] as const),
    current_key_use: Object.freeze(["config_invalid", "key_use_refused"] as const),
    local_admission: Object.freeze(["config_invalid", "peer_not_admitted"] as const),
    disclosure_verification: Object.freeze(["config_invalid", "disclosure_refused", "disclosure_required"] as const),
    schema_version: Object.freeze(["config_invalid", "schema_refused", "scope_violation", "authority_claim_refused"] as const),
    authentication: Object.freeze(["config_invalid", "authentication_refused"] as const),
    replay_receipt: Object.freeze(["config_invalid", "replay_refused", "port_refused"] as const),
    untrusted_inbox: Object.freeze(["config_invalid"] as const),
  });

/** Closed refusal vocabulary — one code per distinct law at this junction. */
export const INGRESS_REFUSAL_CODES = Object.freeze([
  "config_invalid",
  "frame_refused",
  "session_not_bound",
  "epoch_stale",
  "key_use_refused",
  "peer_not_admitted",
  "disclosure_refused",
  "disclosure_required",
  "schema_refused",
  "scope_violation",
  "authority_claim_refused",
  "authentication_refused",
  "replay_refused",
  "port_refused",
] as const);
export type IngressRefusalCode = (typeof INGRESS_REFUSAL_CODES)[number];

/** Deterministic explanation for every refusal code (closed, suite-pinned). */
export const INGRESS_REFUSAL_EXPLANATIONS: Readonly<Record<IngressRefusalCode, string>> =
  Object.freeze({
    config_invalid:
      "ingress input failed validation at this stage; refused before any later stage could observe it (fail closed)",
    frame_refused:
      "the frozen 26A frame decision refused this frame — acceptance there means bounded transport DATA only, never application acceptance",
    session_not_bound:
      "the message is not bound to an ESTABLISHED 26D session whose transcript hash and peer facts match; cross-session splicing refuses",
    epoch_stale:
      "the sender's runtime epoch is not the epoch this session bound — a stale or substituted epoch refuses (fail closed)",
    key_use_refused:
      "the frozen 25B key-use gate refused a key on CURRENT facts — an old, rotated, revoked, retired, mismatched, or unknown key refuses even though its crypto still verifies",
    peer_not_admitted:
      "the peer's CURRENT local admission is not admitted (unknown, candidate, quarantined, or retired) — identity is not admission",
    disclosure_refused:
      "the frozen 25D egress gate refused the disclosure manifest bound to this payload; a stale or unbound disclosure refuses",
    disclosure_required:
      "this payload requires a disclosure manifest and none was supplied — verification is mandatory where required, never optional",
    schema_refused:
      "the message body is outside the frozen closed shape or schema version (unknown field, unknown intent, malformed id, or downgrade)",
    scope_violation:
      "the message claims a capability outside the frozen transport MAY set — naming the violated pin; capability inflation refuses",
    authority_claim_refused:
      "the message claims authority, execution, a LOCAL allocation, a LOCAL Policy decision, an actor binding, or a tool invocation — remote input is untrusted DATA and can never carry any of these",
    authentication_refused:
      "24B Ed25519 verification over the frozen message body failed — the sender did not prove control of the admitted key",
    replay_refused:
      "the frozen 24D durable replay guard refused this message id — replay is refused with no fallback and no partial admission",
    port_refused:
      "the federation ingress port refused the receipt; its refusal code is carried verbatim and the message is not admitted",
  });

/**
 * Closed set of inbound field names that would smuggle LOCAL authority, a
 * LOCAL allocation, a LOCAL Policy decision, an actor binding, a capability
 * grant, or a tool invocation. There is deliberately NO input slot anywhere in
 * this module through which a Policy decision, an allocation, or an actor
 * binding could arrive: LOCAL authorization is unreachable from the wire.
 */
export const INGRESS_AUTHORITY_CLAIM_FIELDS = Object.freeze([
  "authority",
  "executionAuthorized",
  "policyAuthorized",
  "grantAuthority",
  "policy",
  "policyDecision",
  "policyActorId",
  "localPolicy",
  "assignment",
  "assignmentId",
  "assignedAgentId",
  "localAllocation",
  "allocation",
  "capabilities",
  "requiredCapabilities",
  "capabilityUnion",
  "toolInvocation",
  "executeTool",
  "toolCall",
  "adminCommand",
  "remoteAdmin",
] as const);
export type IngressAuthorityClaimField = (typeof INGRESS_AUTHORITY_CLAIM_FIELDS)[number];

/**
 * Closed containers a peer may use to ASK for capabilities. They are not
 * authority: each string inside is judged by the frozen 26A scope decision,
 * so a capability outside the transport MAY set refuses naming its violated
 * pin (capability inflation), and an unknown capability refuses with a null
 * pin rather than riding through.
 */
export const INGRESS_CAPABILITY_CLAIM_CONTAINERS = Object.freeze([
  "requestedCapabilities",
  "claimedCapabilities",
  "requestedScopes",
  "claimedScopes",
  "requestedScope",
  "claimedScope",
] as const);
export type IngressCapabilityClaimContainer =
  (typeof INGRESS_CAPABILITY_CLAIM_CONTAINERS)[number];

const AUTHORITY_FIELD_SET: ReadonlySet<string> = new Set(INGRESS_AUTHORITY_CLAIM_FIELDS);
const CAPABILITY_CONTAINER_SET: ReadonlySet<string> =
  new Set(INGRESS_CAPABILITY_CLAIM_CONTAINERS);
const TRUST_STATE_SET: ReadonlySet<string> = new Set(NODE_TRUST_STATES);
const DECLARED_INTENT_SET: ReadonlySet<string> = new Set(FEDERATION_DECLARED_INTENTS);

/** The pins each stage carries when it refuses (closed, suite-pinned). */
export const INGRESS_STAGE_PINS: Readonly<Record<IngressStage, readonly TransportTrustPin[]>> =
  Object.freeze({
    frame_validity: Object.freeze([
      "TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE",
      "CONNECTION_STATE_NOT_TRUST_STATE",
    ] as const),
    session_binding: Object.freeze([
      "CONNECTION_STATE_NOT_TRUST_STATE",
      "AUTHENTICATED_SESSION_NOT_EXECUTION",
    ] as const),
    current_key_use: Object.freeze(["IDENTITY_NOT_ADMISSION", "ADMISSION_NOT_AUTHORITY"] as const),
    local_admission: Object.freeze(["IDENTITY_NOT_ADMISSION", "ADMISSION_NOT_AUTHORITY"] as const),
    disclosure_verification: Object.freeze(["NETWORK_EVIDENCE_NOT_AUTHORITY"] as const),
    schema_version: Object.freeze(["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"] as const),
    authentication: Object.freeze([
      "IDENTITY_NOT_ADMISSION",
      "AUTHENTICATED_SESSION_NOT_EXECUTION",
    ] as const),
    replay_receipt: Object.freeze([
      "TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE",
      "NETWORK_EVIDENCE_NOT_AUTHORITY",
    ] as const),
    untrusted_inbox: Object.freeze([
      "AUTHENTICATED_SESSION_NOT_EXECUTION",
      "ADMISSION_NOT_AUTHORITY",
    ] as const),
  });

const PAYLOAD_HASH_PATTERN = /^sha256-[0-9a-f]{64}$/;
const HEX64_PATTERN = /^[0-9a-f]{64}$/;

/** Current LOCAL admission fact for the peer (24C view). */
export interface IngressAdmissionFact {
  readonly state: NodeTrustState;
  /** The fingerprint this node CURRENTLY admits for that peer. */
  readonly fingerprint: string;
}

/**
 * LIVE fact ports. Every call re-reads the current state — nothing is
 * snapshotted at handshake time, so quarantine, retirement, or revocation
 * during an active session closes ingress at the very next message.
 */
export interface IngressProbes {
  readonly localKey: () => KeyLifecycleRecord | null;
  readonly peerKey: () => KeyLifecycleRecord | null;
  readonly peerAdmission: () => IngressAdmissionFact;
}

/**
 * The federation ingress port. This is the ONLY egress this module has, and
 * it is deliberately narrow: durable replay guard, receipt commit, untrusted
 * inbox. It is wired by the caller to the frozen 24D bus (which reaches the
 * store only through the sanctioned 23B junction); this module never touches
 * a store, never writes a record, and never bypasses the coordinator.
 */
export interface IngressFederationPort {
  readonly admit: (input: {
    readonly envelope: FederationSignedMessage;
    readonly payload: Readonly<Record<string, unknown>>;
    readonly nowEpochMs: number;
  }) => IngressPortResult;
}

/** The port's closed result vocabulary. */
export type IngressPortResult =
  | {
      readonly ok: true;
      readonly messageId: string;
      readonly senderNodeId: string;
      readonly receiptRecordId: string;
      readonly commitSequence: number;
    }
  | {
      readonly ok: false;
      /** "replay_detected" maps to replay_refused; anything else to port_refused. */
      readonly code: string;
      readonly explanation: string;
    };

/** Frame facts exactly as the frozen 26A decision consumes them. */
export interface IngressFrameFacts {
  readonly declaredBytes: number;
  readonly actualBytes: number;
  readonly sequence: number;
  readonly expectedSequence: number;
  readonly previouslyDelivered: boolean;
  readonly integrityOk: boolean;
  readonly protocolVersion: string;
  /** The caller's transport-level disclosure freshness observation (26A). */
  readonly disclosureFresh: boolean;
  readonly halfClosedDirection: "none" | "local" | "remote";
}

/** The peer facts the 26D session bound during its handshake. */
export interface IngressSessionBinding {
  readonly session: AuthenticatedSession;
  readonly transcriptHash: string;
  readonly peerNodeId: string;
  readonly peerFingerprint: string;
  readonly peerRuntimeEpochId: string;
  readonly peerPublicKeyHex: string;
}

/** Everything the junction needs for one inbound message. */
export interface TransportIngressInput {
  readonly frame: IngressFrameFacts;
  readonly binding: IngressSessionBinding;
  readonly envelope: FederationSignedMessage;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly probes: IngressProbes;
  readonly federation: IngressFederationPort;
  /** The caller's own classification: does THIS payload require a manifest? */
  readonly requiresDisclosure: boolean;
  readonly disclosure?: DisclosureManifest;
  readonly nowEpochMs: number;
}

/** The untrusted inbox entry ingress produces. DATA only. */
export interface IngressInboxEntry {
  readonly schemaVersion: typeof INGRESS_JUNCTION_SCHEMA_VERSION;
  readonly messageId: string;
  readonly senderNodeId: string;
  readonly senderFingerprint: string;
  readonly declaredIntent: string;
  readonly payloadHash: string;
  readonly transcriptHash: string;
  readonly senderEpochId: string;
  readonly receiptRecordId: string;
  readonly commitSequence: number;
  /** Untrusted DATA for LOCAL evaluation only. */
  readonly payload: Readonly<Record<string, unknown>>;
  /** Structural statements of the pack law — not booleans a caller can flip. */
  readonly authority: "none";
  readonly executionAuthorized: false;
}

/** The only legal continuation after ingress, stated by the junction itself. */
export const INGRESS_NEXT_GATE =
  "fresh_local_allocation_then_fresh_local_policy_for_the_assigned_actor_then_phase_20_21" as const;

/** The deterministic ingress decision. */
export type TransportIngressDecision =
  | {
      readonly ok: true;
      readonly stage: "untrusted_inbox";
      readonly stagesRun: readonly IngressStage[];
      readonly inbox: IngressInboxEntry;
      readonly transcriptHash: string;
      readonly nextGate: typeof INGRESS_NEXT_GATE;
      readonly authority: "none";
      readonly executionAuthorized: false;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly stage: IngressStage;
      readonly stagesRun: readonly IngressStage[];
      readonly code: IngressRefusalCode;
      /** The frozen upstream code (26A/25B/25D/24B/24D) carried verbatim. */
      readonly upstreamCode: string | null;
      readonly pins: readonly TransportTrustPin[];
      readonly explanation: string;
    };

// ── the ONE decision ─────────────────────────────────────────────────────────

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function refuse(
  stage: IngressStage,
  stagesRun: readonly IngressStage[],
  code: IngressRefusalCode,
  upstreamCode: string | null,
  pins: readonly TransportTrustPin[],
  detail: string,
): TransportIngressDecision {
  return {
    ok: false,
    stage,
    stagesRun: Object.freeze([...stagesRun] as const),
    code,
    upstreamCode,
    pins: Object.freeze([...pins] as const),
    explanation:
      INGRESS_REFUSAL_EXPLANATIONS[code] +
      " [stage " +
      String(INGRESS_STAGES.indexOf(stage) + 1) +
      "/" +
      String(INGRESS_STAGES.length) +
      " " +
      stage +
      (upstreamCode === null ? "" : "; upstream " + upstreamCode) +
      "] " +
      detail,
  };
}

/**
 * The transport → federation ingress decision. Walks the MANDATORY ORDER
 * exactly once, in the pinned sequence, refusing at the FIRST stage that
 * fails. There is no fallback, no widening, no partial admission, and no way
 * to skip or reorder a stage: `stagesRun` is the literal prefix of
 * INGRESS_STAGES that actually executed.
 */
export function decideTransportIngress(input: TransportIngressInput): TransportIngressDecision {
  const stagesRun: IngressStage[] = [];
  const done = (stage: IngressStage): void => {
    stagesRun.push(stage);
  };

  // ── stage 1: frame_validity (26A) ─────────────────────────────────────────
  done("frame_validity");
  const f = input.frame;
  if (
    !isFiniteNumber(input.nowEpochMs) ||
    !isPlainObject(f) ||
    !Number.isInteger(f.declaredBytes) ||
    !Number.isInteger(f.actualBytes) ||
    !Number.isInteger(f.sequence) ||
    !Number.isInteger(f.expectedSequence) ||
    typeof f.previouslyDelivered !== "boolean" ||
    typeof f.integrityOk !== "boolean" ||
    typeof f.protocolVersion !== "string" ||
    typeof f.disclosureFresh !== "boolean" ||
    (f.halfClosedDirection !== "none" &&
      f.halfClosedDirection !== "local" &&
      f.halfClosedDirection !== "remote")
  ) {
    return refuse(
      "frame_validity",
      stagesRun,
      "config_invalid",
      null,
      INGRESS_STAGE_PINS.frame_validity,
      "frame facts or the gate clock are malformed — refusing before the frame decision runs"
    );
  }
  const frame = decideFrame({
    declaredBytes: f.declaredBytes,
    actualBytes: f.actualBytes,
    sequence: f.sequence,
    expectedSequence: f.expectedSequence,
    previouslyDelivered: f.previouslyDelivered,
    integrityOk: f.integrityOk,
    protocolVersion: f.protocolVersion,
    expectedProtocolVersion: INGRESS_EXPECTED_PROTOCOL_VERSION,
    disclosureFresh: f.disclosureFresh,
    halfClosedDirection: f.halfClosedDirection,
    frameDirection: "inbound",
  });
  if (frame.disposition !== "frame_accepted") {
    return refuse(
      "frame_validity",
      stagesRun,
      "frame_refused",
      frame.refusal ?? "refused_unknown",
      frame.pins,
      frame.explanation
    );
  }

  // ── stage 2: session_binding (26D) ────────────────────────────────────────
  done("session_binding");
  const b = input.binding;
  const env = input.envelope;
  if (
    !isPlainObject(env) ||
    !isPlainObject(env.message) ||
    typeof env.signature !== "string" ||
    env.signature.length === 0 ||
    !isPlainObject(b) ||
    b.session === null ||
    typeof b.session !== "object" ||
    typeof b.transcriptHash !== "string" ||
    !HEX64_PATTERN.test(b.transcriptHash) ||
    typeof b.peerNodeId !== "string" ||
    typeof b.peerFingerprint !== "string" ||
    typeof b.peerPublicKeyHex !== "string" ||
    typeof b.peerRuntimeEpochId !== "string" ||
    !isFiniteNumber(input.nowEpochMs)
  ) {
    return refuse(
      "session_binding",
      stagesRun,
      "config_invalid",
      null,
      INGRESS_STAGE_PINS.session_binding,
      "the session binding or envelope is structurally malformed — refusing before any identity claim is examined"
    );
  }
  if (b.session.state() !== "established" || b.session.transcriptHash() === null) {
    return refuse(
      "session_binding",
      stagesRun,
      "session_not_bound",
      null,
      INGRESS_STAGE_PINS.session_binding,
      "the transport session is '" +
        b.session.state() +
        "', not established — an unestablished session never carries federation traffic"
    );
  }
  if (b.transcriptHash !== b.session.transcriptHash()) {
    return refuse(
      "session_binding",
      stagesRun,
      "session_not_bound",
      null,
      INGRESS_STAGE_PINS.session_binding,
      "the message declares transcript hash '" +
        b.transcriptHash.slice(0, 16) +
        "' but the live session bound '" +
        String(b.session.transcriptHash()).slice(0, 16) +
        "' — cross-session splicing refuses (fail closed)"
    );
  }
  const msg = env.message as unknown as Record<string, unknown>;
  if (msg["senderNodeId"] !== b.peerNodeId || msg["senderFingerprint"] !== b.peerFingerprint) {
    return refuse(
      "session_binding",
      stagesRun,
      "session_not_bound",
      null,
      INGRESS_STAGE_PINS.session_binding,
      "the message sender does not match the peer this session authenticated — a message from anyone but the bound peer refuses"
    );
  }
  if (
    !RUNTIME_EPOCH_ID_PATTERN.test(b.peerRuntimeEpochId) ||
    msg["senderEpochId"] !== b.peerRuntimeEpochId
  ) {
    return refuse(
      "session_binding",
      stagesRun,
      "epoch_stale",
      null,
      INGRESS_STAGE_PINS.session_binding,
      "the message carries sender epoch '" +
        String(msg["senderEpochId"]) +
        "' but this session bound '" +
        b.peerRuntimeEpochId +
        "' — a stale or substituted runtime epoch refuses (fail closed)"
    );
  }

  // ── stage 3: current_key_use (25B, live records, both sides) ─────────────
  done("current_key_use");
  if (!isPlainObject(input.probes) || typeof input.probes.localKey !== "function" || typeof input.probes.peerKey !== "function") {
    return refuse(
      "current_key_use",
      stagesRun,
      "config_invalid",
      null,
      INGRESS_STAGE_PINS.current_key_use,
      "the live key probes are malformed — refusing without consulting key state"
    );
  }
  let presentedKeyId: string;
  try {
    presentedKeyId = deriveKeyId(b.peerPublicKeyHex);
  } catch {
    return refuse(
      "current_key_use",
      stagesRun,
      "config_invalid",
      null,
      INGRESS_STAGE_PINS.current_key_use,
      "the session-bound peer public key does not derive a canonical key id — refusing before key use"
    );
  }
  const peerUse = decideKeyUse({
    record: input.probes.peerKey(),
    keyIdClaim: presentedKeyId,
    fingerprintClaim: b.peerFingerprint,
  });
  if (!peerUse.ok) {
    return refuse(
      "current_key_use",
      stagesRun,
      "key_use_refused",
      peerUse.code,
      INGRESS_STAGE_PINS.current_key_use,
      "peer key: " + peerUse.explanation
    );
  }
  const localUse = decideKeyUse({ record: input.probes.localKey() });
  if (!localUse.ok) {
    return refuse(
      "current_key_use",
      stagesRun,
      "key_use_refused",
      localUse.code,
      INGRESS_STAGE_PINS.current_key_use,
      "local key: " + localUse.explanation
    );
  }

  // ── stage 4: local_admission (24C current admission) ──────────────────────
  done("local_admission");
  if (typeof input.probes.peerAdmission !== "function") {
    return refuse(
      "local_admission",
      stagesRun,
      "config_invalid",
      null,
      INGRESS_STAGE_PINS.local_admission,
      "the live admission probe is malformed — refusing without consulting admission state"
    );
  }
  const admission = input.probes.peerAdmission();
  if (!isPlainObject(admission) || typeof admission.state !== "string" || !TRUST_STATE_SET.has(admission.state)) {
    return refuse(
      "local_admission",
      stagesRun,
      "peer_not_admitted",
      "unknown_trust_state",
      INGRESS_STAGE_PINS.local_admission,
      "the current admission fact is malformed or names no known trust state — refusing (fail closed)"
    );
  }
  if (admission.state !== "admitted") {
    return refuse(
      "local_admission",
      stagesRun,
      "peer_not_admitted",
      admission.state,
      INGRESS_STAGE_PINS.local_admission,
      "the peer's CURRENT local trust state is '" +
        admission.state +
        "' — reachability and identity are not admission"
    );
  }
  if (admission.fingerprint !== b.peerFingerprint) {
    return refuse(
      "local_admission",
      stagesRun,
      "peer_not_admitted",
      "fingerprint_not_admitted",
      INGRESS_STAGE_PINS.local_admission,
      "the currently admitted fingerprint is not the one this session bound — a rotated identity inherits NO trust and needs a new evidenced re-admission"
    );
  }

  // ── stage 5: disclosure_verification (25D where required) ────────────────
  done("disclosure_verification");
  if (typeof input.requiresDisclosure !== "boolean") {
    return refuse(
      "disclosure_verification",
      stagesRun,
      "config_invalid",
      null,
      INGRESS_STAGE_PINS.disclosure_verification,
      "the caller's disclosure classification is malformed — refusing rather than guessing whether verification applies"
    );
  }
  if (input.requiresDisclosure && (input.disclosure === undefined || input.disclosure === null)) {
    return refuse(
      "disclosure_verification",
      stagesRun,
      "disclosure_required",
      null,
      INGRESS_STAGE_PINS.disclosure_verification,
      "this payload requires a disclosure manifest and none was supplied — verification is mandatory where required, never optional"
    );
  }
  if (input.disclosure !== undefined && input.disclosure !== null) {
    const manifest = input.disclosure;
    if (typeof manifest.payloadHash !== "string" || !PAYLOAD_HASH_PATTERN.test(manifest.payloadHash)) {
      return refuse(
        "disclosure_verification",
        stagesRun,
        "disclosure_refused",
        "malformed_candidate",
        INGRESS_STAGE_PINS.disclosure_verification,
        "the disclosure manifest is malformed — refusing"
      );
    }
    // The manifest is verified against the payload hash the SIGNED BODY
    // claims — never against the manifest's own hash, which would make
    // every manifest self-consistent and therefore worthless as evidence.
    const claimed =
      typeof msg["payloadHash"] === "string" && PAYLOAD_HASH_PATTERN.test(msg["payloadHash"])
        ? (msg["payloadHash"] as string)
        : null;
    if (claimed === null) {
      return refuse(
        "disclosure_verification",
        stagesRun,
        "disclosure_refused",
        "malformed_candidate",
        INGRESS_STAGE_PINS.disclosure_verification,
        "the signed body carries no well-formed payload hash for the disclosure to bind to — refusing"
      );
    }
    const verified = verifyEgressManifest({ manifest, outgoingPayloadHash: claimed });
    if (!verified.ok) {
      return refuse(
        "disclosure_verification",
        stagesRun,
        "disclosure_refused",
        verified.denyCode,
        INGRESS_STAGE_PINS.disclosure_verification,
        verified.explanation
      );
    }
  }

  // ── stage 6: schema_version (frozen shape, version, claims, scope) ───────
  done("schema_version");
  const schema = checkFrozenSchema(msg);
  if (schema !== null) {
    return refuse(
      "schema_version",
      stagesRun,
      "schema_refused",
      schema.code,
      INGRESS_STAGE_PINS.schema_version,
      schema.detail
    );
  }
  const claim = checkClaims(input.payload);
  if (claim !== null) {
    return refuse(
      "schema_version",
      stagesRun,
      claim.code,
      claim.upstreamCode,
      claim.pins,
      claim.detail
    );
  }
  const deliveredHash = canonicalHash(input.payload);
  const claimedHash = msg["payloadHash"] as string;
  if ("sha256-" + deliveredHash !== claimedHash) {
    return refuse(
      "schema_version",
      stagesRun,
      "schema_refused",
      "payload_hash_mismatch",
      INGRESS_STAGE_PINS.schema_version,
      "the delivered payload hashes to '" +
        deliveredHash.slice(0, 16) +
        "' but the signed body claims '" +
        claimedHash.slice(7, 23) +
        "' — tampered payload bytes refuse before authentication"
    );
  }

  // ── stage 7: authentication (24B Ed25519 over the frozen body) ───────────
  done("authentication");
  const identity = verifyRestartIdentity({
    publicKeyHex: b.peerPublicKeyHex,
    fingerprint: b.peerFingerprint,
    nodeId: b.peerNodeId,
  });
  if (!identity.ok) {
    return refuse(
      "authentication",
      stagesRun,
      "authentication_refused",
      "verify_restart_identity",
      INGRESS_STAGE_PINS.authentication,
      identity.reason
    );
  }
  let verifiedSignature: { readonly ok: boolean; readonly reason?: string };
  try {
    const verifier = makeIdentitySignatureVerifier(b.peerPublicKeyHex);
    verifiedSignature = verifier({ document: msg, signature: env.signature });
  } catch {
    return refuse(
      "authentication",
      stagesRun,
      "authentication_refused",
      "verifier_construction_failed",
      INGRESS_STAGE_PINS.authentication,
      "the session-bound public key is not a usable Ed25519 verification key — refusing"
    );
  }
  if (!verifiedSignature.ok) {
    return refuse(
      "authentication",
      stagesRun,
      "authentication_refused",
      verifiedSignature.reason ?? "signature_invalid",
      INGRESS_STAGE_PINS.authentication,
      "Ed25519 verification over the frozen message body failed — the sender did not prove control of the admitted key"
    );
  }

  // ── stage 8: replay_receipt (24D durable replay guard + receipt) ─────────
  done("replay_receipt");
  if (
    !isPlainObject(input.federation) ||
    typeof input.federation.admit !== "function" ||
    !isPlainObject(input.payload)
  ) {
    return refuse(
      "replay_receipt",
      stagesRun,
      "config_invalid",
      null,
      INGRESS_STAGE_PINS.replay_receipt,
      "the federation ingress port or payload is malformed — refusing before any receipt is written"
    );
  }
  const admitted = input.federation.admit({
    envelope: input.envelope,
    payload: input.payload,
    nowEpochMs: input.nowEpochMs,
  });
  if (!admitted || typeof admitted !== "object" || typeof admitted.ok !== "boolean") {
    return refuse(
      "replay_receipt",
      stagesRun,
      "port_refused",
      "port_result_malformed",
      INGRESS_STAGE_PINS.replay_receipt,
      "the ingress port returned no decision — a missing receipt decision is a refusal (fail closed)"
    );
  }
  if (!admitted.ok) {
    return refuse(
      "replay_receipt",
      stagesRun,
      admitted.code === "replay_detected" ? "replay_refused" : "port_refused",
      admitted.code,
      INGRESS_STAGE_PINS.replay_receipt,
      admitted.explanation
    );
  }
  if (
    admitted.messageId !== msg["messageId"] ||
    admitted.senderNodeId !== b.peerNodeId ||
    typeof admitted.receiptRecordId !== "string" ||
    admitted.receiptRecordId.length === 0 ||
    !Number.isInteger(admitted.commitSequence)
  ) {
    return refuse(
      "replay_receipt",
      stagesRun,
      "port_refused",
      "port_result_mismatch",
      INGRESS_STAGE_PINS.replay_receipt,
      "the receipt the port returned does not bind THIS message, sender, receipt id and commit sequence — refusing"
    );
  }

  // ── stage 9: untrusted_inbox (DATA only; grants nothing) ─────────────────
  done("untrusted_inbox");
  const inbox: IngressInboxEntry = Object.freeze({
    schemaVersion: INGRESS_JUNCTION_SCHEMA_VERSION,
    messageId: admitted.messageId,
    senderNodeId: admitted.senderNodeId,
    senderFingerprint: b.peerFingerprint,
    declaredIntent: msg["declaredIntent"] as string,
    payloadHash: claimedHash,
    transcriptHash: b.transcriptHash,
    senderEpochId: b.peerRuntimeEpochId,
    receiptRecordId: admitted.receiptRecordId,
    commitSequence: admitted.commitSequence,
    payload: Object.freeze({ ...input.payload }),
    authority: "none",
    executionAuthorized: false,
  });
  return {
    ok: true,
    stage: "untrusted_inbox",
    stagesRun: Object.freeze([...stagesRun] as const),
    inbox,
    transcriptHash: b.transcriptHash,
    nextGate: INGRESS_NEXT_GATE,
    authority: "none",
    executionAuthorized: false,
    explanation:
      "admitted as UNTRUSTED DATA through all nine mandatory stages: frame, session binding, current key use, current local admission, disclosure verification, frozen schema, authentication, durable replay/receipt, inbox. " +
      "Ingress grants NO authority and NO execution: the only legal continuation is " +
      INGRESS_NEXT_GATE +
      ", which remote data can never satisfy (network reachability is not identity, not admission, not authority, not execution).",
  };
}

// ── stage 6 helpers ──────────────────────────────────────────────────────────

interface SchemaFault {
  readonly code: string;
  readonly detail: string;
}

/** The frozen 24A closed body shape + pinned versions (stage 6, part 1). */
function checkFrozenSchema(msg: Record<string, unknown>): SchemaFault | null {
  const present = Object.keys(msg).sort();
  const expected = [...FEDERATION_MESSAGE_BODY_KEYS].sort();
  if (present.length !== expected.length || present.some((key, index) => key !== expected[index])) {
    return {
      code: "body_shape_mismatch",
      detail:
        "the message body is not the frozen closed field set — it has " +
        String(present.length) +
        " field(s) where the frozen shape has " +
        String(expected.length) +
        " (unknown and missing fields both refuse)",
    };
  }
  if (msg["schemaVersion"] !== INGRESS_EXPECTED_MESSAGE_SCHEMA_VERSION) {
    return {
      code: "schema_version_mismatch",
      detail:
        "message schema '" +
        String(msg["schemaVersion"]) +
        "' is not the frozen '" +
        INGRESS_EXPECTED_MESSAGE_SCHEMA_VERSION +
        "' — a downgrade or an unknown version refuses with no negotiation path",
    };
  }
  if (msg["protocolVersion"] !== INGRESS_EXPECTED_FEDERATION_PROTOCOL_VERSION) {
    return {
      code: "protocol_version_mismatch",
      detail:
        "message body protocol '" +
        String(msg["protocolVersion"]) +
        "' is not the frozen federation protocol '" +
        INGRESS_EXPECTED_FEDERATION_PROTOCOL_VERSION +
        "' — the transport protocol is not the federation protocol, and a downgrade refuses with no negotiation path",
    };
  }
  if (typeof msg["declaredIntent"] !== "string" || !DECLARED_INTENT_SET.has(msg["declaredIntent"])) {
    return {
      code: "unknown_declared_intent",
      detail: "the declared intent is not in the frozen closed union — refusing",
    };
  }
  if (typeof msg["senderNodeId"] !== "string" || !NODE_ID_PATTERN.test(msg["senderNodeId"])) {
    return { code: "sender_node_malformed", detail: "senderNodeId is not in the frozen node shape" };
  }
  if (typeof msg["messageId"] !== "string" || msg["messageId"].length === 0) {
    return { code: "message_id_malformed", detail: "messageId is missing or empty" };
  }
  if (typeof msg["payloadHash"] !== "string" || !PAYLOAD_HASH_PATTERN.test(msg["payloadHash"])) {
    return { code: "payload_hash_malformed", detail: "payloadHash is not the pinned sha256-64hex shape" };
  }
  return null;
}

interface ClaimFault {
  readonly code: "authority_claim_refused" | "scope_violation" | "schema_refused";
  readonly upstreamCode: string;
  readonly pins: readonly TransportTrustPin[];
  readonly detail: string;
}

/**
 * Authority-claim and capability-claim refusal (stage 6, part 2). Runs
 * BEFORE the payload is treated as data: a payload that claims authority is
 * refused, never hashed, never receipted, never admitted.
 */
function checkClaims(
  payload: Readonly<Record<string, unknown>>,
): ClaimFault | null {
  for (const key of Object.keys(payload)) {
    if (AUTHORITY_FIELD_SET.has(key)) {
      return {
        code: "authority_claim_refused",
        upstreamCode: "claim_field:" + key,
        pins: Object.freeze(["REMOTE_MESSAGE_NOT_LOCAL_POLICY", "ADMISSION_NOT_AUTHORITY"] as const),
        detail:
          "the payload carries the closed authority-claim field '" +
          key +
          "' — remote input is untrusted DATA; a LOCAL allocation, a LOCAL Policy decision, an actor binding, a capability grant, and a tool invocation are all unreachable from the wire",
      };
    }
  }
  for (const key of Object.keys(payload)) {
    if (!CAPABILITY_CONTAINER_SET.has(key)) continue;
    const raw = payload[key];
    const claims =
      key === "requestedScope" || key === "claimedScope"
        ? typeof raw === "string"
          ? [raw]
          : []
        : Array.isArray(raw)
          ? raw
          : [];
    if (claims.length === 0 || !claims.every((entry) => typeof entry === "string")) {
      return {
        code: "schema_refused",
        upstreamCode: "capability_container_malformed:" + key,
        pins: Object.freeze(["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"] as const),
        detail:
          "the capability-claim container '" +
          key +
          "' must hold capability-shaped strings — a malformed claim refuses (fail closed)",
      };
    }
    for (const claim of claims as readonly string[]) {
      const scope = decideTransportScope({ capability: claim });
      if (!scope.ok) {
        return {
          code: "scope_violation",
          upstreamCode: "capability:" + claim,
          pins: scope.violatedPin === null ? Object.freeze(["ADMISSION_NOT_AUTHORITY"] as const) : Object.freeze([scope.violatedPin] as const),
          detail:
            "the message asks for the capability '" +
            claim +
            "' — " +
            (scope.violatedPin === null
              ? "an unnamed capability cannot ride through (fail closed)"
              : "naming the violated pin " + scope.violatedPin) +
            "; capability inflation refuses here",
        };
      }
    }
  }
  return null;
}
