/**
 * PHASE 26D — Governed Local Network Transport: Authenticated Session
 * (LIVE TRANSPORT × FROZEN IDENTITY / FAIL CLOSED / NO NEW AUTHORITY).
 *
 * This module binds the 26C framed transport to the FROZEN Phase-24/25
 * identity and key-lifecycle stack. It adds exactly one thing on top of
 * 26C's bounded bytes: cryptographic proof that the peer at the other end
 * of this LOCAL connection controls the private half of the admitted
 * public identity — nothing more.
 *
 *   - HANDSHAKE BINDS: protocol (`menog-auth-session/v1`), NodeId, runtime
 *     epoch, active fingerprint + key-id, fresh per-session challenges
 *     (both directions), and a canonical transcript hash. Three messages:
 *     hello (initiator claims + challenge) → reply (responder claims +
 *     challenge + responder signature over the transcript) → finish
 *     (initiator signature over the same transcript). Both signatures are
 *     Ed25519 over SHA-256(canonical JSON) through the frozen 24B helpers.
 *   - REFUSES: unknown protocol or message kind (downgrade — there is no
 *     version negotiation), malformed handshake data, claims that do not
 *     re-derive (publicKey → fingerprint → NodeId → key-id), a NodeId that
 *     is not the expected peer, a fingerprint that is not the currently
 *     ADMITTED fingerprint (a rotated identity inherits NO trust — trust
 *     transfers only through a new evidenced re-admission), a peer key the
 *     25B key-use gate refuses (old/rotated/revoked/retired/unknown),
 *     a stale runtime epoch, a reused challenge, a replayed transcript,
 *     a transcript-hash mismatch, and a bad signature.
 *   - ENDPOINT FACTS ARE EVIDENCE, NOT AUTHORITY: the remote address/port
 *     are recorded verbatim and never enter a single decision — the trust
 *     path is key material only. IP is never identity, never trust.
 *   - RECHECK DURING THE SESSION: before every delivered ingress byte and
 *     on every explicit recheck, the CURRENT local key, peer key, and peer
 *     trust state are re-read through the caller's probes — quarantine or
 *     retirement (or any key-state death) closes future ingress the moment
 *     it happens, mid-session.
 *   - PRIVATE KEYS NEVER APPEAR: this module receives only the frozen 24B
 *     `LocalSigningIdentity` (public facts + the module-closure signing
 *     capability) and public `KeyLifecycleRecord`s. No handshake message,
 *     transcript, or evidence value carries key material (the 24B secret
 *     denylist is applied to what this module emits).
 *   - NO AUTHORITY: a completed handshake authenticates a peer for THIS
 *     transport session only. It grants no admission (24C owns that), no
 *     Policy choice, no execution, no capability. NETWORK REACHABILITY !=
 *     IDENTITY != ADMISSION != AUTHORITY != EXECUTION.
 *
 * Freshness: challenges come from a per-session factory (default: crypto
 * randomness), and a per-node `SessionReplayGuard` records every challenge
 * and transcript this node has seen — a second observation refuses.
 * Determinism: the module never reads a wall clock; every entry point takes
 * a caller-supplied nowMs.
 */
import { randomBytes } from "node:crypto";
import { canonicalHash } from "./canonical.js";
import {
  signFederationMessage,
  makeIdentitySignatureVerifier,
  verifyRestartIdentity,
  payloadContainsSecretKeyMaterial,
  type LocalSigningIdentity,
} from "./federationCrypto.js";
import {
  deriveKeyId,
  decideKeyUse,
  type KeyLifecycleRecord,
} from "./federationKeyLifecycle.js";
import { NODE_ID_PATTERN, type NodeTrustState } from "./federationIdentity.js";
import { RUNTIME_EPOCH_ID_PATTERN } from "./continuity.js";
import {
  FramedTransport,
  type FramedSession,
  type FramedSink,
} from "./framedSocketTransport.js";

/** Closed schema versions for the authenticated-session contract. */
export const AUTH_SESSION_SCHEMA_VERSION = "menog-auth-session/v0" as const;
/** The ONE pinned handshake protocol — anything else is a downgrade. */
export const AUTH_SESSION_PROTOCOL = "menog-auth-session/v1" as const;
/** Transcript schema (bound into the transcript hash itself). */
export const AUTH_SESSION_TRANSCRIPT_SCHEMA = "menog-auth-transcript/v0" as const;

/** Closed handshake message-kind vocabulary (no negotiation, no extensions). */
export const AUTH_SESSION_MESSAGE_KINDS = Object.freeze(["hello", "reply", "finish"] as const);
export type AuthSessionMessageKind = (typeof AUTH_SESSION_MESSAGE_KINDS)[number];

/** Fresh per-session challenge shape: `nnc-` + 32 lowercase hex characters. */
export const AUTH_SESSION_NONCE_PATTERN = /^nnc-[0-9a-f]{32}$/;

/** Session lifecycle states (closed). */
export const AUTH_SESSION_STATES = Object.freeze(["handshaking", "established", "closed"] as const);
export type AuthSessionState = (typeof AUTH_SESSION_STATES)[number];

/** Handshake roles (closed). */
export const AUTH_SESSION_ROLES = Object.freeze(["initiator", "responder"] as const);
export type AuthSessionRole = (typeof AUTH_SESSION_ROLES)[number];

/**
 * Closed refusal vocabulary. One code per distinct law; every refusal ends
 * the session (fail closed) and is deterministic.
 */
export const AUTH_SESSION_REFUSAL_CODES = Object.freeze([
  "config_invalid",
  "clock_invalid",
  "transport_refused",
  "session_closed",
  "session_not_established",
  "unexpected_message",
  "protocol_downgrade",
  "malformed_handshake",
  "node_mismatch",
  "fingerprint_not_admitted",
  "peer_not_admitted",
  "peer_key_refused",
  "local_key_refused",
  "epoch_stale",
  "challenge_reused",
  "transcript_mismatch",
  "transcript_replayed",
  "signature_invalid",
] as const);
export type AuthSessionRefusalCode = (typeof AUTH_SESSION_REFUSAL_CODES)[number];

/** Non-refusal terminal codes (explicit local close, clean remote close). */
export const AUTH_SESSION_LOCAL_END_CODES = Object.freeze(["local_close", "peer_stream_closed"] as const);
export type AuthSessionLocalEndCode = (typeof AUTH_SESSION_LOCAL_END_CODES)[number];

/** A session ends in exactly one code: a refusal, or a local/peer close. */
export type AuthSessionEndCode = AuthSessionRefusalCode | AuthSessionLocalEndCode;

/** Deterministic explanation for every refusal code (closed, suite-pinned). */
export const AUTH_SESSION_REFUSAL_EXPLANATIONS: Readonly<Record<AuthSessionRefusalCode, string>> = Object.freeze({
  config_invalid: "authenticated-session config failed validation; refused before any transport session exists",
  clock_invalid: "caller-supplied clock input must be a finite number; operation refused, session unchanged",
  transport_refused: "the underlying framed transport refused or ended; the authenticated session fails closed with it",
  session_closed: "the session is closed; a closed session accepts no further operations",
  session_not_established: "application data may only be sent after the handshake establishes; refused (caller error, session unchanged)",
  unexpected_message: "handshake message arrived for the wrong state, role, or sequence; refused (no renegotiation, no reordering)",
  protocol_downgrade: "protocol or message kind is not the pinned one; unknown versions refuse with no negotiation path",
  malformed_handshake: "handshake data failed structural validation (JSON, object shape, required fields, challenge shape)",
  node_mismatch: "presented claims do not re-derive from their public key, or the NodeId is not the expected peer",
  fingerprint_not_admitted: "presented fingerprint is not the currently admitted fingerprint — a rotated identity inherits no trust and requires a new evidenced re-admission",
  peer_not_admitted: "current peer trust state is not admitted (quarantine, retirement, or unknown closes the door)",
  peer_key_refused: "the 25B key-use gate refuses the peer's key (old, rotated, revoked, retired, unknown, or mismatched)",
  local_key_refused: "the 25B key-use gate refuses the local key; the session cannot authenticate or sign",
  epoch_stale: "presented runtime epoch does not match the expected current epoch; stale epochs refuse",
  challenge_reused: "a challenge value was already seen by this node (replay guard) or collides with the local fresh challenge",
  transcript_mismatch: "presented transcript hash does not match the locally computed transcript — the bound facts differ",
  transcript_replayed: "this transcript hash was already observed by this node — a replayed handshake refuses",
  signature_invalid: "Ed25519 verification over the transcript failed — the peer did not prove control of the admitted key",
});

/**
 * Per-node replay guard (in-memory, process lifetime). Each node owns ONE
 * guard and shares it across that node's sessions: every challenge the node
 * generates or receives, and every transcript it produces or verifies, is
 * recorded exactly once — a second observation refuses. Durable replay
 * protection across restarts stays the 24D receipt layer's duty (out of
 * scope here; no store access, no new record kind).
 */
export class SessionReplayGuard {
  readonly #challenges = new Set<string>();
  readonly #transcripts = new Set<string>();

  observeChallenge(value: string): "fresh" | "reused" {
    if (this.#challenges.has(value)) return "reused";
    this.#challenges.add(value);
    return "fresh";
  }

  observeTranscript(value: string): "fresh" | "reused" {
    if (this.#transcripts.has(value)) return "reused";
    this.#transcripts.add(value);
    return "fresh";
  }

  seenChallenges(): number {
    return this.#challenges.size;
  }

  seenTranscripts(): number {
    return this.#transcripts.size;
  }
}

/** Current peer-trust facts (what the caller's 24C registry view returns). */
export interface PeerTrustFact {
  readonly state: NodeTrustState;
  readonly fingerprint: string;
}

/**
 * Endpoint facts — DATA recorded as evidence only. These values never enter
 * any decision, transcript, or signature: IP is never identity, never trust.
 */
export interface SessionEndpointEvidence {
  readonly remoteAddress?: string;
  readonly remotePort?: number;
}

/** Caller ports: CURRENT facts, re-read at handshake and during the session. */
export interface AuthenticatedSessionProbes {
  /** Current local key lifecycle record (25B), or null when none exists. */
  readonly localKey: () => KeyLifecycleRecord | null;
  /** Current local record of the PEER's key lifecycle (25B), or null. */
  readonly peerKey: () => KeyLifecycleRecord | null;
  /** Current peer trust facts (24C view): state + admitted fingerprint. */
  readonly peerTrust: () => PeerTrustFact;
}

/** Everything an authenticated session needs. Validated as a closed shape. */
export interface AuthenticatedSessionConfig {
  readonly transport: FramedTransport;
  readonly sink: FramedSink;
  readonly role: AuthSessionRole;
  readonly local: {
    readonly identity: LocalSigningIdentity;
    readonly runtimeEpochId: string;
  };
  readonly expectedPeer: {
    readonly nodeId: string;
    /** When supplied, the peer's presented epoch must equal it (stale refuses). */
    readonly runtimeEpochId?: string;
  };
  readonly probes: AuthenticatedSessionProbes;
  readonly replayGuard: SessionReplayGuard;
  readonly endpointEvidence?: SessionEndpointEvidence;
  /** Freshness source for challenges (default: crypto randomness). */
  readonly challengeFactory?: () => string;
}

/** The claims one side presents in the handshake (all public facts). */
export interface AuthSessionClaims {
  readonly nodeId: string;
  readonly fingerprint: string;
  readonly publicKeyHex: string;
  readonly keyId: string;
  readonly runtimeEpochId: string;
  readonly challenge: string;
}

// ── deterministic handshake construction ───────────────────────────────────────

function makeFreshChallenge(): string {
  return "nnc-" + randomBytes(16).toString("hex");
}

function makeCorrelation(): string {
  return randomBytes(16).toString("hex");
}

/** The canonical transcript both sides hash and sign (order-independent). */
function transcriptOf(initiator: AuthSessionClaims, responder: AuthSessionClaims): unknown {
  return {
    schema: AUTH_SESSION_TRANSCRIPT_SCHEMA,
    protocol: AUTH_SESSION_PROTOCOL,
    initiator: {
      nodeId: initiator.nodeId,
      fingerprint: initiator.fingerprint,
      publicKeyHex: initiator.publicKeyHex,
      keyId: initiator.keyId,
      runtimeEpochId: initiator.runtimeEpochId,
      challenge: initiator.challenge,
    },
    responder: {
      nodeId: responder.nodeId,
      fingerprint: responder.fingerprint,
      publicKeyHex: responder.publicKeyHex,
      keyId: responder.keyId,
      runtimeEpochId: responder.runtimeEpochId,
      challenge: responder.challenge,
    },
  };
}

function transcriptHashOf(initiator: AuthSessionClaims, responder: AuthSessionClaims): string {
  return canonicalHash(transcriptOf(initiator, responder));
}

/** The exact subject each signature covers: fingerprint claim + role + transcript. */
function signatureSubject(fingerprint: string, role: AuthSessionRole, transcriptHash: string): unknown {
  return { fingerprint, role, transcriptHash };
}

function claimsFromMessage(message: Record<string, unknown>): AuthSessionClaims | null {
  const fields = ["nodeId", "fingerprint", "publicKeyHex", "keyId", "runtimeEpochId", "challenge"];
  const values: Record<string, unknown> = {};
  for (const field of fields) {
    const value = message[field];
    if (typeof value !== "string" || value.length === 0 || value.length > 256) return null;
    values[field] = value;
  }
  return {
    nodeId: values["nodeId"] as string,
    fingerprint: values["fingerprint"] as string,
    publicKeyHex: values["publicKeyHex"] as string,
    keyId: values["keyId"] as string,
    runtimeEpochId: values["runtimeEpochId"] as string,
    challenge: values["challenge"] as string,
  };
}

function ownClaimsOf(identity: LocalSigningIdentity, runtimeEpochId: string, challenge: string): AuthSessionClaims {
  return {
    nodeId: identity.nodeId,
    fingerprint: identity.fingerprint,
    publicKeyHex: identity.publicKeyHex,
    keyId: deriveKeyId(identity.publicKeyHex),
    runtimeEpochId,
    challenge,
  };
}

const KNOWN_EVIDENCE_KEYS = Object.freeze(["remoteAddress", "remotePort"] as const);

/** Closed-shape config validation (first failure wins; deterministic). */
function validateConfig(config: AuthenticatedSessionConfig | null | undefined): string | null {
  if (config === null || config === undefined || typeof config !== "object") {
    return "config must be an object (fail closed)";
  }
  if (!(config.transport instanceof FramedTransport)) {
    return "transport must be a FramedTransport (26C) — the authenticated session never builds its own transport";
  }
  if (config.role !== "initiator" && config.role !== "responder") {
    return "role must be exactly initiator or responder";
  }
  const local = config.local;
  if (local === null || typeof local !== "object") {
    return "local facts must be an object with identity and runtimeEpochId";
  }
  const identity = local.identity;
  if (identity === null || typeof identity !== "object") {
    return "local identity must be a 24B LocalSigningIdentity (public facts only)";
  }
  const rederived = verifyRestartIdentity({
    publicKeyHex: identity.publicKeyHex,
    fingerprint: identity.fingerprint,
    nodeId: identity.nodeId,
  });
  if (!rederived.ok) {
    return "local identity failed 24B public-fact re-derivation: " + rederived.reason;
  }
  if (typeof local.runtimeEpochId !== "string" || !RUNTIME_EPOCH_ID_PATTERN.test(local.runtimeEpochId)) {
    return "local runtimeEpochId must match the pinned re- epoch shape";
  }
  const expected = config.expectedPeer;
  if (expected === null || typeof expected !== "object") {
    return "expectedPeer must be an object with nodeId";
  }
  if (typeof expected.nodeId !== "string" || !NODE_ID_PATTERN.test(expected.nodeId)) {
    return "expectedPeer.nodeId must match the pinned node- shape";
  }
  if (expected.nodeId === identity.nodeId) {
    return "expectedPeer.nodeId equals the local identity — a node never authenticates itself (fail closed)";
  }
  if (expected.runtimeEpochId !== undefined && (typeof expected.runtimeEpochId !== "string" || !RUNTIME_EPOCH_ID_PATTERN.test(expected.runtimeEpochId))) {
    return "expectedPeer.runtimeEpochId must match the pinned re- epoch shape when supplied";
  }
  const probes = config.probes;
  if (
    probes === null ||
    typeof probes !== "object" ||
    typeof probes.localKey !== "function" ||
    typeof probes.peerKey !== "function" ||
    typeof probes.peerTrust !== "function"
  ) {
    return "probes must expose localKey(), peerKey() and peerTrust() — current facts are re-read, never cached (fail closed)";
  }
  if (!(config.replayGuard instanceof SessionReplayGuard)) {
    return "replayGuard must be a SessionReplayGuard shared across this node's sessions";
  }
  if (config.challengeFactory !== undefined && typeof config.challengeFactory !== "function") {
    return "challengeFactory must be a function when supplied";
  }
  const evidence = config.endpointEvidence;
  if (evidence !== undefined) {
    if (evidence === null || typeof evidence !== "object" || Array.isArray(evidence)) {
      return "endpointEvidence must be a plain object of known keys (evidence is validated, never trusted)";
    }
    for (const key of Object.keys(evidence)) {
      if (!(KNOWN_EVIDENCE_KEYS as readonly string[]).includes(key)) {
        return "endpointEvidence carries unknown key `" + key + "` — closed shape (fail closed)";
      }
    }
    const address = evidence.remoteAddress;
    if (address !== undefined && (typeof address !== "string" || address.length === 0 || address.length > 64)) {
      return "endpointEvidence.remoteAddress must be a non-empty string of at most 64 characters";
    }
    const port = evidence.remotePort;
    if (port !== undefined && (typeof port !== "number" || !Number.isInteger(port) || port < 0 || port > 65535)) {
      return "endpointEvidence.remotePort must be an integer in [0, 65535]";
    }
    if (payloadContainsSecretKeyMaterial(evidence)) {
      return "endpointEvidence carries secret-key-shaped material — private key material never enters evidence (fail closed)";
    }
  }
  return null;
}

function validateSinkShape(sink: FramedSink | null | undefined): string | null {
  if (sink === null || sink === undefined || typeof sink !== "object" || typeof sink.write !== "function" || typeof sink.destroy !== "function") {
    return "sink must expose write(chunk) -> boolean and destroy(); refused before any session exists";
  }
  return null;
}

// ── results ────────────────────────────────────────────────────────────────────

/** A plain operation result (begin/send/close/recheck). */
export type AuthSessionOpResult =
  | { readonly ok: true; readonly state: AuthSessionState; readonly code?: "session_closed" | "session_already_closed" }
  | { readonly ok: false; readonly code: AuthSessionRefusalCode; readonly explanation: string; readonly state: AuthSessionState };

/** ingest(): decoded application payloads arrive ONLY when ok. */
export type AuthSessionIngestResult =
  | { readonly ok: true; readonly state: AuthSessionState; readonly delivered: readonly Uint8Array[] }
  | { readonly ok: false; readonly code: AuthSessionRefusalCode; readonly explanation: string; readonly state: AuthSessionState };

/** Result of openAuthenticatedSession. */
export type OpenAuthenticatedSessionResult =
  | { readonly ok: true; readonly session: AuthenticatedSession }
  | {
      readonly ok: false;
      readonly code: "config_invalid" | "sink_invalid" | "clock_invalid" | "connections_exceeded";
      readonly explanation: string;
    };

/** The public session shape (construction stays module-private). */
export interface AuthenticatedSession {
  state(): AuthSessionState;
  role(): AuthSessionRole;
  /** The bound transcript hash once computed; null until then. */
  transcriptHash(): string | null;
  /** Recorded endpoint EVIDENCE (never used in any decision). */
  endpointEvidence(): SessionEndpointEvidence;
  /** Terminal code once closed (refusal or local/peer close); null while live. */
  endCode(): AuthSessionEndCode | null;
  endExplanation(): string | null;
  /** Initiator only: send the hello and start the handshake. */
  beginHandshake(nowMs: number): AuthSessionOpResult;
  /** Feed inbound socket bytes; decoded application payloads are returned. */
  ingest(chunk: Uint8Array, nowMs: number): AuthSessionIngestResult;
  /** Send one application payload (established sessions only). */
  send(payload: Uint8Array, nowMs: number): AuthSessionOpResult;
  /** Explicit re-read of current local key / peer key / peer trust facts. */
  recheck(nowMs: number): AuthSessionOpResult;
  /** Explicit, idempotent local close. */
  close(): AuthSessionOpResult;
  /** The local stream ended (clean or truncated); mirrors the 26C session. */
  notifyStreamClosed(nowMs: number): AuthSessionOpResult;
}

interface HandshakeDispatchFailure {
  readonly code: AuthSessionRefusalCode;
  readonly explanation: string;
}

class AuthenticatedSessionImpl implements AuthenticatedSession {
  readonly #role: AuthSessionRole;
  readonly #localIdentity: LocalSigningIdentity;
  readonly #localEpoch: string;
  readonly #expectedPeer: { readonly nodeId: string; readonly runtimeEpochId?: string };
  readonly #probes: AuthenticatedSessionProbes;
  readonly #guard: SessionReplayGuard;
  readonly #evidence: SessionEndpointEvidence;
  readonly #challengeFactory: () => string;
  readonly #framed: FramedSession;
  readonly #correlation: string;
  #state: AuthSessionState = "handshaking";
  #end: { readonly code: AuthSessionEndCode; readonly explanation: string } | null = null;
  #ownChallenge: string | null = null;
  #peerClaims: AuthSessionClaims | null = null;
  #transcriptHash: string | null = null;
  #begun = false;

  constructor(
    config: AuthenticatedSessionConfig,
    framed: FramedSession,
    correlation: string
  ) {
    this.#role = config.role;
    this.#localIdentity = config.local.identity;
    this.#localEpoch = config.local.runtimeEpochId;
    this.#expectedPeer = Object.freeze({ ...config.expectedPeer });
    this.#probes = config.probes;
    this.#guard = config.replayGuard;
    this.#evidence = Object.freeze({ ...(config.endpointEvidence ?? {}) });
    this.#challengeFactory = config.challengeFactory ?? makeFreshChallenge;
    this.#framed = framed;
    this.#correlation = correlation;
  }

  state(): AuthSessionState {
    return this.#state;
  }
  role(): AuthSessionRole {
    return this.#role;
  }
  transcriptHash(): string | null {
    return this.#transcriptHash;
  }
  endpointEvidence(): SessionEndpointEvidence {
    return this.#evidence;
  }
  endCode(): AuthSessionEndCode | null {
    return this.#end === null ? null : this.#end.code;
  }
  endExplanation(): string | null {
    return this.#end === null ? null : this.#end.explanation;
  }

  #fail(code: AuthSessionRefusalCode, explanation: string): AuthSessionRefusalCode {
    if (this.#state !== "closed") {
      this.#state = "closed";
      this.#end = Object.freeze({ code, explanation });
      this.#framed.close("local_close");
    }
    return code;
  }

  #refuse(code: AuthSessionRefusalCode, explanation: string): { readonly ok: false; readonly code: AuthSessionRefusalCode; readonly explanation: string; readonly state: AuthSessionState } {
    this.#fail(code, explanation);
    return Object.freeze({ ok: false as const, code, explanation, state: this.#state });
  }

  #endLocal(code: AuthSessionLocalEndCode, explanation: string): void {
    if (this.#state !== "closed") {
      this.#state = "closed";
      this.#end = Object.freeze({ code, explanation });
    }
  }

  /**
   * Re-read CURRENT facts through the caller's probes: local key use, peer
   * trust state + admitted fingerprint, peer key use. No challenge or
   * transcript observation happens here (that is one-shot per handshake).
   */
  #recheckCurrent(storedClaims: AuthSessionClaims | null): HandshakeDispatchFailure | null {
    const localRecord = this.#probes.localKey();
    const localUse = decideKeyUse({ record: localRecord });
    if (!localUse.ok) {
      return { code: "local_key_refused", explanation: "local key-use gate refused the session's local key (" + localUse.code + "): " + localUse.explanation };
    }
    let trust: PeerTrustFact;
    try {
      trust = this.#probes.peerTrust();
    } catch {
      return { code: "peer_not_admitted", explanation: "peer trust probe failed — current facts unreadable, admitting nothing (fail closed)" };
    }
    if (trust === null || typeof trust !== "object" || typeof trust.state !== "string" || typeof trust.fingerprint !== "string") {
      return { code: "peer_not_admitted", explanation: "peer trust probe returned malformed facts — admitting nothing (fail closed)" };
    }
    if (trust.state !== "admitted") {
      return { code: "peer_not_admitted", explanation: "current peer trust state is `" + trust.state + "` (not admitted) — quarantine, retirement, or unknown closes the door at recheck" };
    }
    if (storedClaims !== null && trust.fingerprint !== storedClaims.fingerprint) {
      return { code: "fingerprint_not_admitted", explanation: "peer now presents fingerprint " + storedClaims.fingerprint + " but the admitted fingerprint is " + trust.fingerprint + " — a rotated identity inherits no trust (new evidenced re-admission required)" };
    }
    const peerRecord = this.#probes.peerKey();
    const peerUse = decideKeyUse(
      storedClaims === null
        ? { record: peerRecord }
        : { record: peerRecord, keyIdClaim: storedClaims.keyId, fingerprintClaim: storedClaims.fingerprint }
    );
    if (!peerUse.ok) {
      return { code: "peer_key_refused", explanation: "peer key-use gate refused (" + peerUse.code + "): " + peerUse.explanation };
    }
    return null;
  }

  /** One-shot verification of freshly received peer claims (handshake only). */
  #verifyPeerClaims(claims: AuthSessionClaims): HandshakeDispatchFailure | null {
    const rederived = verifyRestartIdentity({
      publicKeyHex: claims.publicKeyHex,
      fingerprint: claims.fingerprint,
      nodeId: claims.nodeId,
    });
    if (!rederived.ok) {
      return { code: "node_mismatch", explanation: "presented claims do not re-derive from the presented public key: " + rederived.reason };
    }
    if (deriveKeyId(claims.publicKeyHex) !== claims.keyId) {
      return { code: "node_mismatch", explanation: "presented key-id does not re-derive from the presented public key — fingerprint/key-id mismatch refuses" };
    }
    if (claims.nodeId !== this.#expectedPeer.nodeId) {
      return { code: "node_mismatch", explanation: "presented NodeId `" + claims.nodeId + "` is not the expected peer `" + this.#expectedPeer.nodeId + "`" };
    }
    const recheckFailure = this.#recheckCurrent(claims);
    if (recheckFailure !== null) return recheckFailure;
    if (this.#expectedPeer.runtimeEpochId !== undefined && claims.runtimeEpochId !== this.#expectedPeer.runtimeEpochId) {
      return { code: "epoch_stale", explanation: "presented runtime epoch `" + claims.runtimeEpochId + "` != expected current epoch `" + this.#expectedPeer.runtimeEpochId + "` — stale epochs refuse" };
    }
    if (!AUTH_SESSION_NONCE_PATTERN.test(claims.challenge)) {
      return { code: "malformed_handshake", explanation: "presented challenge is not nnc- + 32 lowercase hex characters — freshness cannot be assumed (fail closed)" };
    }
    if (this.#guard.observeChallenge(claims.challenge) === "reused") {
      return { code: "challenge_reused", explanation: "this node has already seen challenge `" + claims.challenge + "` — challenge reuse refuses (replay guard)" };
    }
    return null;
  }

  #signOrRefuse(fingerprint: string, role: AuthSessionRole, transcriptHash: string): { readonly signature: string } | HandshakeDispatchFailure {
    const signed = signFederationMessage(this.#localIdentity, signatureSubject(fingerprint, role, transcriptHash));
    if (!signed.ok) {
      return { code: "local_key_refused", explanation: "local signing refused: " + signed.explanation };
    }
    return { signature: signed.signature };
  }

  #sendJson(message: unknown, nowMs: number): HandshakeDispatchFailure | null {
    const payload = Buffer.from(JSON.stringify(message), "utf8");
    const sent = this.#framed.send(
      { type: "data", correlationId: this.#correlation, payload },
      nowMs
    );
    if (!sent.ok) {
      return { code: "transport_refused", explanation: "framed transport refused the outbound handshake message (" + sent.refusal + "): " + sent.explanation };
    }
    return null;
  }

  beginHandshake(nowMs: number): AuthSessionOpResult {
    if (this.#state === "closed") {
      return Object.freeze({ ok: false as const, code: "session_closed" as const, explanation: "session is closed", state: this.#state });
    }
    if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
      return Object.freeze({ ok: false as const, code: "clock_invalid" as const, explanation: "clock input must be a finite number; operation refused, session unchanged", state: this.#state });
    }
    if (this.#role !== "initiator") {
      return this.#refuse("unexpected_message", "a responder never begins — it waits for the initiator's hello (single initiator, fixed sequence)");
    }
    if (this.#begun) {
      return this.#refuse("unexpected_message", "handshake already begun on this session — duplicate hello refuses (no renegotiation)");
    }
    const early = this.#recheckCurrent(null);
    if (early !== null) {
      return this.#refuse(early.code, early.explanation);
    }
    const challenge = this.#challengeFactory();
    if (typeof challenge !== "string" || !AUTH_SESSION_NONCE_PATTERN.test(challenge)) {
      return this.#refuse("config_invalid", "challengeFactory produced a malformed nonce — freshness source unusable (fail closed)");
    }
    if (this.#guard.observeChallenge(challenge) === "reused") {
      return this.#refuse("challenge_reused", "freshly generated challenge `" + challenge + "` was already seen by this node — freshness source broken (fail closed)");
    }
    this.#ownChallenge = challenge;
    const own = ownClaimsOf(this.#localIdentity, this.#localEpoch, challenge);
    const failure = this.#sendJson(
      { protocol: AUTH_SESSION_PROTOCOL, kind: "hello", ...own },
      nowMs
    );
    if (failure !== null) {
      return this.#refuse(failure.code, failure.explanation);
    }
    this.#begun = true;
    return Object.freeze({ ok: true as const, state: this.#state });
  }

  #dispatchHandshake(payload: Uint8Array, nowMs: number): HandshakeDispatchFailure | null {
    let parsed: unknown;
    try {
      parsed = JSON.parse(Buffer.from(payload).toString("utf8"));
    } catch {
      return { code: "malformed_handshake", explanation: "handshake frame is not valid JSON — unparseable handshake data refuses (fail closed)" };
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { code: "malformed_handshake", explanation: "handshake frame is not a JSON object — structural refusal (fail closed)" };
    }
    const message = parsed as Record<string, unknown>;
    if (message["protocol"] !== AUTH_SESSION_PROTOCOL) {
      return { code: "protocol_downgrade", explanation: "handshake protocol `" + String(message["protocol"]) + "` != pinned `" + AUTH_SESSION_PROTOCOL + "` — unknown protocols refuse, there is no negotiation" };
    }
    const kind = message["kind"];
    if (typeof kind !== "string" || !(AUTH_SESSION_MESSAGE_KINDS as readonly string[]).includes(kind)) {
      return { code: "protocol_downgrade", explanation: "unknown handshake message kind `" + String(kind) + "` — the kind vocabulary is closed (no version negotiation)" };
    }
    if (kind === "hello") {
      if (this.#role !== "responder") {
        return { code: "unexpected_message", explanation: "an initiator never receives hello — no renegotiation, no role swap" };
      }
      return this.#handleHello(message, nowMs);
    }
    if (kind === "reply") {
      if (this.#role !== "initiator") {
        return { code: "unexpected_message", explanation: "a responder never receives reply — fixed message sequence" };
      }
      if (!this.#begun) {
        return { code: "unexpected_message", explanation: "reply arrived before this session began a handshake — unexpected message (fail closed)" };
      }
      return this.#handleReply(message, nowMs);
    }
    // kind === "finish"
    if (this.#role !== "responder") {
      return { code: "unexpected_message", explanation: "an initiator never receives finish — fixed message sequence" };
    }
    if (this.#peerClaims === null || this.#transcriptHash === null) {
      return { code: "unexpected_message", explanation: "finish arrived before hello — the sequence is hello → reply → finish, fixed" };
    }
    return this.#handleFinish(message, nowMs);
  }

  #handleHello(message: Record<string, unknown>, nowMs: number): HandshakeDispatchFailure | null {
    if (this.#peerClaims !== null) {
      return { code: "unexpected_message", explanation: "a hello was already processed on this session — duplicate hello refuses (fixed sequence, no renegotiation)" };
    }
    const claims = claimsFromMessage(message);
    if (claims === null) {
      return { code: "malformed_handshake", explanation: "hello is missing required claim fields (or they exceed bounds) — structural refusal" };
    }
    const claimFailure = this.#verifyPeerClaims(claims);
    if (claimFailure !== null) return claimFailure;
    const challenge = this.#challengeFactory();
    if (typeof challenge !== "string" || !AUTH_SESSION_NONCE_PATTERN.test(challenge)) {
      return { code: "config_invalid", explanation: "challengeFactory produced a malformed nonce — freshness source unusable (fail closed)" };
    }
    if (challenge === claims.challenge) {
      return { code: "challenge_reused", explanation: "the local fresh challenge collides with the received challenge — freshness source broken (fail closed)" };
    }
    if (this.#guard.observeChallenge(challenge) === "reused") {
      return { code: "challenge_reused", explanation: "locally generated challenge was already seen by this node — freshness source broken (fail closed)" };
    }
    const own = ownClaimsOf(this.#localIdentity, this.#localEpoch, challenge);
    const transcriptHash = transcriptHashOf(claims, own);
    if (this.#guard.observeTranscript(transcriptHash) === "reused") {
      return { code: "transcript_replayed", explanation: "this node already produced this transcript hash — a replayed handshake refuses (replay guard)" };
    }
    const signed = this.#signOrRefuse(own.fingerprint, "responder", transcriptHash);
    if ("code" in signed) return signed;
    const failure = this.#sendJson(
      {
        protocol: AUTH_SESSION_PROTOCOL,
        kind: "reply",
        ...own,
        transcriptHash,
        signature: signed.signature,
      },
      nowMs
    );
    if (failure !== null) return failure;
    this.#ownChallenge = challenge;
    this.#peerClaims = claims;
    this.#transcriptHash = transcriptHash;
    return null;
  }

  #handleReply(message: Record<string, unknown>, nowMs: number): HandshakeDispatchFailure | null {
    const claims = claimsFromMessage(message);
    if (claims === null) {
      return { code: "malformed_handshake", explanation: "reply is missing required claim fields (or they exceed bounds) — structural refusal" };
    }
    const presentedHash = message["transcriptHash"];
    const signature = message["signature"];
    if (typeof presentedHash !== "string" || typeof signature !== "string" || signature.length === 0 || signature.length > 256) {
      return { code: "malformed_handshake", explanation: "reply must carry transcriptHash and signature fields (bounded strings) — structural refusal" };
    }
    if (this.#ownChallenge === null) {
      return { code: "unexpected_message", explanation: "reply arrived without a local half of the transcript — session state inconsistent (fail closed)" };
    }
    const claimFailure = this.#verifyPeerClaims(claims);
    if (claimFailure !== null) return claimFailure;
    const own = ownClaimsOf(this.#localIdentity, this.#localEpoch, this.#ownChallenge);
    const transcriptHash = transcriptHashOf(own, claims);
    if (presentedHash !== transcriptHash) {
      return { code: "transcript_mismatch", explanation: "presented transcript hash `" + presentedHash + "` != locally computed `" + transcriptHash + "` — the bound facts differ" };
    }
    if (this.#guard.observeTranscript(transcriptHash) === "reused") {
      return { code: "transcript_replayed", explanation: "this node already observed this transcript hash — a replayed handshake refuses (replay guard)" };
    }
    const verifier = makeIdentitySignatureVerifier(claims.publicKeyHex);
    const verified = verifier({
      document: signatureSubject(claims.fingerprint, "responder", transcriptHash),
      signature,
    });
    if (!verified.ok) {
      return { code: "signature_invalid", explanation: "responder signature over the transcript failed verification (" + String(verified.reason) + ") — control of the admitted key was not proven" };
    }
    const signed = this.#signOrRefuse(own.fingerprint, "initiator", transcriptHash);
    if ("code" in signed) return signed;
    const failure = this.#sendJson(
      {
        protocol: AUTH_SESSION_PROTOCOL,
        kind: "finish",
        transcriptHash,
        signature: signed.signature,
      },
      nowMs
    );
    if (failure !== null) return failure;
    this.#peerClaims = claims;
    this.#transcriptHash = transcriptHash;
    this.#state = "established";
    return null;
  }

  #handleFinish(message: Record<string, unknown>, _nowMs: number): HandshakeDispatchFailure | null {
    const presentedHash = message["transcriptHash"];
    const signature = message["signature"];
    if (typeof presentedHash !== "string" || typeof signature !== "string" || signature.length === 0 || signature.length > 256) {
      return { code: "malformed_handshake", explanation: "finish must carry transcriptHash and signature fields (bounded strings) — structural refusal" };
    }
    if (this.#peerClaims === null || this.#transcriptHash === null) {
      return { code: "unexpected_message", explanation: "finish arrived before hello — fixed message sequence" };
    }
    if (presentedHash !== this.#transcriptHash) {
      return { code: "transcript_mismatch", explanation: "finish transcript hash `" + presentedHash + "` != bound `" + this.#transcriptHash + "` — refusal" };
    }
    const recheckFailure = this.#recheckCurrent(this.#peerClaims);
    if (recheckFailure !== null) return recheckFailure;
    const verifier = makeIdentitySignatureVerifier(this.#peerClaims.publicKeyHex);
    const verified = verifier({
      document: signatureSubject(this.#peerClaims.fingerprint, "initiator", this.#transcriptHash),
      signature,
    });
    if (!verified.ok) {
      return { code: "signature_invalid", explanation: "initiator signature over the transcript failed verification (" + String(verified.reason) + ") — control of the admitted key was not proven" };
    }
    this.#state = "established";
    return null;
  }

  ingest(chunk: Uint8Array, nowMs: number): AuthSessionIngestResult {
    if (this.#state === "closed") {
      return Object.freeze({ ok: false as const, code: "session_closed" as const, explanation: "session is closed; a closed session never accepts bytes", state: this.#state });
    }
    if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
      return Object.freeze({ ok: false as const, code: "clock_invalid" as const, explanation: "clock input must be a finite number; operation refused, session unchanged", state: this.#state });
    }
    const received = this.#framed.receive(chunk, nowMs);
    if (!received.ok) {
      return this.#refuse("transport_refused", "framed transport refused inbound bytes (" + received.refusal + "): " + received.explanation);
    }
    const frames = this.#framed.read();
    const delivered: Uint8Array[] = [];
    for (const frame of frames) {
      if (frame.type !== "data") {
        return this.#refuse("transport_refused", "non-data frame (`" + frame.type + "`) arrives at the authenticated session — only opaque data frames belong here");
      }
      if (this.#state === "handshaking") {
        const failure = this.#dispatchHandshake(frame.payload, nowMs);
        if (failure !== null) {
          return this.#refuse(failure.code, failure.explanation);
        }
      } else {
        const recheckFailure = this.#recheckCurrent(this.#peerClaims);
        if (recheckFailure !== null) {
          return this.#refuse(recheckFailure.code, "recheck before delivering ingress bytes refused: " + recheckFailure.explanation);
        }
        delivered.push(frame.payload);
      }
    }
    return Object.freeze({
      ok: true as const,
      state: this.#state,
      delivered: Object.freeze(delivered),
    });
  }

  send(payload: Uint8Array, nowMs: number): AuthSessionOpResult {
    if (this.#state === "closed") {
      return Object.freeze({ ok: false as const, code: "session_closed" as const, explanation: "session is closed", state: this.#state });
    }
    if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
      return Object.freeze({ ok: false as const, code: "clock_invalid" as const, explanation: "clock input must be a finite number; operation refused, session unchanged", state: this.#state });
    }
    if (this.#state !== "established") {
      return Object.freeze({ ok: false as const, code: "session_not_established" as const, explanation: "application data requires an established session — handshake first (caller error, session unchanged)", state: this.#state });
    }
    const recheckFailure = this.#recheckCurrent(this.#peerClaims);
    if (recheckFailure !== null) {
      return this.#refuse(recheckFailure.code, "recheck before egress refused: " + recheckFailure.explanation);
    }
    const sent = this.#framed.send({ type: "data", correlationId: this.#correlation, payload }, nowMs);
    if (!sent.ok) {
      return this.#refuse("transport_refused", "framed transport refused outbound bytes (" + sent.refusal + "): " + sent.explanation);
    }
    return Object.freeze({ ok: true as const, state: this.#state });
  }

  recheck(nowMs: number): AuthSessionOpResult {
    if (this.#state === "closed") {
      return Object.freeze({ ok: false as const, code: "session_closed" as const, explanation: "session is closed", state: this.#state });
    }
    if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
      return Object.freeze({ ok: false as const, code: "clock_invalid" as const, explanation: "clock input must be a finite number; operation refused, session unchanged", state: this.#state });
    }
    const failure = this.#recheckCurrent(this.#peerClaims);
    if (failure !== null) {
      return this.#refuse(failure.code, failure.explanation);
    }
    return Object.freeze({ ok: true as const, state: this.#state });
  }

  close(): AuthSessionOpResult {
    if (this.#state === "closed") {
      return Object.freeze({ ok: true as const, state: this.#state, code: "session_already_closed" as const });
    }
    this.#framed.close("local_close");
    this.#endLocal("local_close", "authenticated session closed explicitly by the local caller — idempotent, deterministic");
    return Object.freeze({ ok: true as const, state: this.#state, code: "session_closed" as const });
  }

  notifyStreamClosed(nowMs: number): AuthSessionOpResult {
    if (this.#state === "closed") {
      return Object.freeze({ ok: true as const, state: this.#state, code: "session_already_closed" as const });
    }
    if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
      return Object.freeze({ ok: false as const, code: "clock_invalid" as const, explanation: "clock input must be a finite number; operation refused, session unchanged", state: this.#state });
    }
    const result = this.#framed.notifyStreamClosed(nowMs);
    if (!result.ok) {
      return this.#refuse("transport_refused", "the stream ended mid-frame (" + result.refusal + "): " + result.explanation);
    }
    if (result.code === "remote_close") {
      this.#endLocal("peer_stream_closed", "peer closed the local stream cleanly before this session closed it — deterministic teardown, nothing partial delivered");
      return Object.freeze({ ok: true as const, state: this.#state, code: "session_closed" as const });
    }
    // The framed session was already closed from outside (e.g. transport shutdown).
    return this.#refuse("transport_refused", "underlying framed session was already closed externally — the authenticated session fails closed with it");
  }
}

/**
 * Open an authenticated session over a caller-supplied local sink.
 * Check order (pinned): config_invalid → sink_invalid → clock_invalid →
 * transport-level open refusals (pass-through). A refusal never creates a
 * session and never consumes a connection slot.
 */
export function openAuthenticatedSession(
  config: AuthenticatedSessionConfig,
  nowMs: number
): OpenAuthenticatedSessionResult {
  const configProblem = validateConfig(config);
  if (configProblem !== null) {
    return Object.freeze({ ok: false as const, code: "config_invalid" as const, explanation: configProblem });
  }
  const sinkProblem = validateSinkShape(config.sink);
  if (sinkProblem !== null) {
    return Object.freeze({ ok: false as const, code: "sink_invalid" as const, explanation: sinkProblem });
  }
  if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
    return Object.freeze({ ok: false as const, code: "clock_invalid" as const, explanation: "openedAt clock must be a finite number; refused (caller error, no session created)" });
  }
  const opened = config.transport.openSession(config.sink, nowMs);
  if (!opened.ok) {
    return Object.freeze({ ok: false as const, code: opened.refusal, explanation: opened.explanation });
  }
  const session = new AuthenticatedSessionImpl(config, opened.session, makeCorrelation());
  return Object.freeze({ ok: true as const, session });
}

