/**
 * PHASE 26D — Authenticated Session Tests
 * (LIVE TRANSPORT × FROZEN IDENTITY / FAIL CLOSED / IP IS NEVER IDENTITY /
 *  RECHECK CLOSES FUTURE INGRESS / PRIVATE KEYS NEVER ON THE WIRE).
 *
 * Pack-mandated coverage:
 *   handshake binds     — protocol, NodeId, runtime epoch, active
 *                          fingerprint/key-id, fresh per-session
 *                          challenges both ways, transcript hash
 *   refusals            — old/rotated/revoked/retired key, stale epoch,
 *                          replayed transcript, challenge reuse, downgrade
 *   rotation            — a new rotated identity inherits NO trust; only a
 *                          new evidenced re-admission opens the door
 *   recheck             — quarantine/retirement (and key-state death)
 *                          closes future INGRESS mid-session
 *   endpoint            — evidence only; never identity, never trust
 *   private keys        — never on the wire, never in evidence
 *   real loopback       — full handshake over 127.0.0.1 sockets
 *
 * Two simulation styles: an in-memory duplex (fake sinks cross-fed) for
 * deterministic unit paths, and real loopback sockets for the pack's
 * live-transport mandate. Every scenario uses FROZEN 24B/25B primitives:
 * real Ed25519 identities, real lifecycle records, real signatures.
 */
import { describe, it, expect } from "vitest";
import {
  AUTH_SESSION_SCHEMA_VERSION,
  AUTH_SESSION_PROTOCOL,
  AUTH_SESSION_TRANSCRIPT_SCHEMA,
  AUTH_SESSION_MESSAGE_KINDS,
  AUTH_SESSION_NONCE_PATTERN,
  AUTH_SESSION_STATES,
  AUTH_SESSION_ROLES,
  AUTH_SESSION_REFUSAL_CODES,
  AUTH_SESSION_LOCAL_END_CODES,
  AUTH_SESSION_REFUSAL_EXPLANATIONS,
  SessionReplayGuard,
  openAuthenticatedSession,
  generateLocalSigningIdentity,
  rotateLocalIdentity,
  payloadContainsSecretKeyMaterial,
  signFederationMessage,
  decideLifecycleTransition,
  deriveKeyId,
  encodeFrame,
  canonicalHash,
  FramedTransport,
  type AuthenticatedSession,
  type AuthSessionEndCode,
  type AuthSessionIngestResult,
  type SessionEndpointEvidence,
  type FramedSink,
  type KeyLifecycleRecord,
  type KeyLifecycleState,
  type LocalSigningIdentity,
  type NodeTrustState,
} from "@menog/durable-state";
import { createServer, connect, type Server, type Socket } from "node:net";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// ── module source (structural scan) ─────────────────────────────────────────

function moduleSource(): string {
  const raw = readFileSync(
    join(process.cwd(), "packages", "durable-state", "src", "authenticatedSession.ts"),
    "utf8"
  );
  return raw
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

// ── node simulation (frozen primitives only) ────────────────────────────────

interface NodeSim {
  name: string;
  identity: LocalSigningIdentity;
  localRecord: KeyLifecycleRecord | null;
  guard: SessionReplayGuard;
  epoch: string;
  seq: number;
  seqBase: number;
  challengeFactory: () => string;
  peerKeyRecord: KeyLifecycleRecord | null;
  trustState: NodeTrustState;
  trustFingerprint: string;
}

const EPOCH_A = "re-000000000000-aaaaaaaaaaaaaaaa";
const EPOCH_B = "re-111111111111-bbbbbbbbbbbbbbbb";
const EPOCH_ALT = "re-333333333333-dddddddddddddddd";

function makeRecord(identity: LocalSigningIdentity, evidence = "gate-26d-fixture"): KeyLifecycleRecord {
  const result = decideLifecycleTransition({
    record: null,
    to: "active",
    evidence,
    nowEpochMs: 1000,
    freshPublicFacts: {
      publicKeyHex: identity.publicKeyHex,
      fingerprint: identity.fingerprint,
      nodeId: identity.nodeId,
    },
  });
  if (!result.ok) throw new Error(`initialize refused: ${result.explanation}`);
  return result.record;
}

function makeNode(name: string, epoch: string, seqBase: number): NodeSim {
  const identity = generateLocalSigningIdentity();
  const node: NodeSim = {
    name,
    identity,
    localRecord: makeRecord(identity),
    guard: new SessionReplayGuard(),
    epoch,
    seq: 0,
    seqBase,
    challengeFactory: () => "",
    peerKeyRecord: null,
    trustState: "admitted",
    trustFingerprint: "",
  };
  node.challengeFactory = () => {
    node.seq += 1;
    return "nnc-" + (node.seqBase + node.seq).toString(16).padStart(32, "0");
  };
  return node;
}

/** Link one node's view of the other: admitted trust + peer key record. */
function link(from: NodeSim, to: NodeSim): void {
  from.peerKeyRecord = to.localRecord;
  from.trustFingerprint = to.identity.fingerprint;
  from.trustState = "admitted";
}

function makePair(): [NodeSim, NodeSim] {
  const a = makeNode("a", EPOCH_A, 0x1000);
  const b = makeNode("b", EPOCH_B, 0x2000);
  link(a, b);
  link(b, a);
  return [a, b];
}

function resetNode(node: NodeSim): void {
  node.guard = new SessionReplayGuard();
  node.seq = 0;
}

function transitionRecord(record: KeyLifecycleRecord, to: KeyLifecycleState, fresh?: LocalSigningIdentity): KeyLifecycleRecord {
  const result = decideLifecycleTransition({
    record,
    to,
    evidence: `gate-26d-${to}`,
    nowEpochMs: 2000,
    freshPublicFacts:
      fresh === undefined
        ? undefined
        : { publicKeyHex: fresh.publicKeyHex, fingerprint: fresh.fingerprint, nodeId: fresh.nodeId },
  });
  if (!result.ok) throw new Error(`transition to ${to} refused: ${result.explanation}`);
  return result.record;
}

/** Rotate a node's identity exactly as 24B prescribes: re-identity, not mutation. */
function rotateNode(node: NodeSim): void {
  const rotated = rotateLocalIdentity(node.identity);
  node.identity = rotated.fresh;
  node.localRecord = makeRecord(rotated.fresh, "gate-26d-rotation");
}

// ── in-memory duplex sides ─────────────────────────────────────────────────

interface Pipe {
  outbox: Buffer[];
  destroyed: number;
  sink: FramedSink;
}

function makePipe(): Pipe {
  const pipe: Pipe = { outbox: [], destroyed: 0, sink: { write: () => false, destroy: () => undefined } };
  pipe.sink = {
    write: (chunk: Uint8Array) => {
      pipe.outbox.push(Buffer.from(chunk));
      return true;
    },
    destroy: () => {
      pipe.destroyed += 1;
    },
  };
  return pipe;
}

interface Side {
  node: NodeSim;
  pipe: Pipe;
  session: AuthenticatedSession;
}

function openSide(opts: {
  node: NodeSim;
  role: "initiator" | "responder";
  peer: NodeSim;
  expectEpoch?: string;
  evidence?: SessionEndpointEvidence;
}): Side {
  const pipe = makePipe();
  const result = openAuthenticatedSession(
    {
      transport: new FramedTransport(),
      sink: pipe.sink,
      role: opts.role,
      local: { identity: opts.node.identity, runtimeEpochId: opts.node.epoch },
      expectedPeer: { nodeId: opts.peer.identity.nodeId, runtimeEpochId: opts.expectEpoch ?? opts.peer.epoch },
      probes: {
        localKey: () => opts.node.localRecord,
        peerKey: () => opts.node.peerKeyRecord,
        peerTrust: () => ({ state: opts.node.trustState, fingerprint: opts.node.trustFingerprint }),
      },
      replayGuard: opts.node.guard,
      endpointEvidence: opts.evidence,
      challengeFactory: opts.node.challengeFactory,
    },
    1000
  );
  if (!result.ok) throw new Error(`open refused: ${result.code} — ${result.explanation}`);
  return { node: opts.node, pipe, session: result.session };
}

function drain(pipe: Pipe, session: AuthenticatedSession, nowMs: number): AuthSessionIngestResult[] {
  const results: AuthSessionIngestResult[] = [];
  for (const bytes of pipe.outbox.splice(0)) {
    results.push(session.ingest(bytes, nowMs));
  }
  return results;
}

/** hello → reply → finish (the three one-way deliveries of the handshake). */
function exchange(a: Side, b: Side): void {
  drain(a.pipe, b.session, 1001);
  drain(b.pipe, a.session, 1002);
  drain(a.pipe, b.session, 1003);
}

function flow(from: Side, to: Side, nowMs = 1005): AuthSessionIngestResult[] {
  return drain(from.pipe, to.session, nowMs);
}

function handshake(): { a: Side; b: Side } {
  const [na, nb] = makePair();
  const a = openSide({ node: na, role: "initiator", peer: nb });
  const b = openSide({ node: nb, role: "responder", peer: na });
  const began = a.session.beginHandshake(1000);
  if (!began.ok) throw new Error(`begin refused: ${began.code} — ${began.explanation}`);
  exchange(a, b);
  return { a, b };
}

// ── wire crafting helpers (test-side, over the frozen 26C frame layout) ─────

function craftFrame(message: unknown): Buffer {
  const body = typeof message === "string" ? message : JSON.stringify(message);
  const encoded = encodeFrame({ type: "data", correlationId: "0".repeat(32), payload: Buffer.from(body, "utf8") });
  if (!encoded.ok) throw new Error(`encode refused: ${encoded.explanation}`);
  return encoded.bytes;
}

function claimsOf(node: NodeSim, challenge: string): Record<string, unknown> {
  return {
    nodeId: node.identity.nodeId,
    fingerprint: node.identity.fingerprint,
    publicKeyHex: node.identity.publicKeyHex,
    keyId: deriveKeyId(node.identity.publicKeyHex),
    runtimeEpochId: node.epoch,
    challenge,
  };
}

/** The test-side twin of the module transcript (pins the bound layout). */
function computeTranscript(initiator: Record<string, unknown>, responder: Record<string, unknown>): string {
  const strip = (claims: Record<string, unknown>): Record<string, unknown> => ({
    nodeId: claims["nodeId"],
    fingerprint: claims["fingerprint"],
    publicKeyHex: claims["publicKeyHex"],
    keyId: claims["keyId"],
    runtimeEpochId: claims["runtimeEpochId"],
    challenge: claims["challenge"],
  });
  return canonicalHash({
    schema: AUTH_SESSION_TRANSCRIPT_SCHEMA,
    protocol: AUTH_SESSION_PROTOCOL,
    initiator: strip(initiator),
    responder: strip(responder),
  });
}

function expectEnd(session: AuthenticatedSession, code: AuthSessionEndCode): void {
  expect(session.state()).toBe("closed");
  expect(session.endCode()).toBe(code);
  expect((session.endExplanation() ?? "").length).toBeGreaterThan(10);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(condition: () => boolean, ms = 4000): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (condition()) return true;
    await sleep(10);
  }
  return condition();
}

// Deterministic ports for the real-loopback tests (fixed, explicit).
const PORT_ROUNDTRIP = 41885;
const PORT_REPLAY = 41886;
const PORT_QUARANTINE = 41887;

// ── vocabulary pins ─────────────────────────────────────────────────────────

describe("vocabularies and constants are pinned", () => {
  it("protocol, schema, kinds, roles, states and nonce shape are exact", () => {
    expect(AUTH_SESSION_SCHEMA_VERSION).toBe("menog-auth-session/v0");
    expect(AUTH_SESSION_PROTOCOL).toBe("menog-auth-session/v1");
    expect(AUTH_SESSION_TRANSCRIPT_SCHEMA).toBe("menog-auth-transcript/v0");
    expect([...AUTH_SESSION_MESSAGE_KINDS]).toEqual(["hello", "reply", "finish"]);
    expect([...AUTH_SESSION_ROLES]).toEqual(["initiator", "responder"]);
    expect([...AUTH_SESSION_STATES]).toEqual(["handshaking", "established", "closed"]);
    expect(AUTH_SESSION_NONCE_PATTERN.test("nnc-" + "a".repeat(32))).toBe(true);
    expect(AUTH_SESSION_NONCE_PATTERN.test("nnc-" + "A".repeat(32))).toBe(false);
    expect(AUTH_SESSION_NONCE_PATTERN.test("nnc-" + "a".repeat(31))).toBe(false);
    expect(AUTH_SESSION_NONCE_PATTERN.test("nc-" + "a".repeat(32))).toBe(false);
  });

  it("the refusal vocabulary is the exact closed list with a full explanation table", () => {
    expect([...AUTH_SESSION_REFUSAL_CODES]).toEqual([
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
    ]);
    expect([...AUTH_SESSION_LOCAL_END_CODES]).toEqual(["local_close", "peer_stream_closed"]);
    expect(Object.keys(AUTH_SESSION_REFUSAL_EXPLANATIONS).sort()).toEqual([...AUTH_SESSION_REFUSAL_CODES].sort());
    for (const code of AUTH_SESSION_REFUSAL_CODES) {
      expect(AUTH_SESSION_REFUSAL_EXPLANATIONS[code].length).toBeGreaterThan(10);
    }
    expect(Object.isFrozen(AUTH_SESSION_REFUSAL_CODES)).toBe(true);
    expect(Object.isFrozen(AUTH_SESSION_REFUSAL_EXPLANATIONS)).toBe(true);
  });
});

// ── open validation ─────────────────────────────────────────────────────────

describe("open validation: closed shape, fail closed, order pinned", () => {
  it("a valid config opens a handshaking session with clean facts", () => {
    const [na, nb] = makePair();
    const side = openSide({ node: na, role: "initiator", peer: nb });
    expect(side.session.state()).toBe("handshaking");
    expect(side.session.role()).toBe("initiator");
    expect(side.session.endCode()).toBeNull();
    expect(side.session.transcriptHash()).toBeNull();
    expect(side.session.endpointEvidence()).toEqual({});
  });

  it("config violations refuse with config_invalid before any session exists", () => {
    const [na, nb] = makePair();
    const base = (overrides: Record<string, unknown>): never => overrides as never;
    const good = {
      transport: new FramedTransport(),
      sink: makePipe().sink,
      role: "initiator",
      local: { identity: na.identity, runtimeEpochId: na.epoch },
      expectedPeer: { nodeId: nb.identity.nodeId, runtimeEpochId: nb.epoch },
      probes: {
        localKey: () => na.localRecord,
        peerKey: () => na.peerKeyRecord,
        peerTrust: () => ({ state: na.trustState, fingerprint: na.trustFingerprint }),
      },
      replayGuard: na.guard,
      challengeFactory: na.challengeFactory,
    };
    const badConfigs: ReadonlyArray<[string, never, string]> = [
      ["bad role", base({ ...good, role: "both" }), ""],
      ["tampered identity", base({ ...good, local: { identity: { ...na.identity, fingerprint: "fp-sha256-" + "0".repeat(64) }, runtimeEpochId: na.epoch } }), "re-derivation"],
      ["bad local epoch", base({ ...good, local: { identity: na.identity, runtimeEpochId: "re-nope" } }), "epoch"],
      ["bad peer nodeId", base({ ...good, expectedPeer: { nodeId: "guest-1" } }), "nodeId"],
      ["self node", base({ ...good, expectedPeer: { nodeId: na.identity.nodeId } }), "authenticates itself"],
      ["bad peer epoch", base({ ...good, expectedPeer: { nodeId: nb.identity.nodeId, runtimeEpochId: "re-nope" } }), "epoch"],
      ["missing probes", base({ ...good, probes: { localKey: () => na.localRecord } }), "probes"],
      ["bad guard", base({ ...good, replayGuard: {} }), "SessionReplayGuard"],
      ["bad factory", base({ ...good, challengeFactory: "nope" }), "challengeFactory"],
      ["evidence unknown key", base({ ...good, endpointEvidence: { ip: "10.0.0.1" } }), "unknown key"],
      ["evidence port range", base({ ...good, endpointEvidence: { remotePort: 70000 } }), "[0, 65535]"],
      ["evidence address shape", base({ ...good, endpointEvidence: { remoteAddress: "" } }), "remoteAddress"],
      ["plain-object evidence", base({ ...good, endpointEvidence: ["127.0.0.1"] }), "plain object"],
    ];
    for (const [label, config, needle] of badConfigs) {
      const result = openAuthenticatedSession(config, 1000);
      expect(result.ok, label).toBe(false);
      if (result.ok) throw new Error("unreachable");
      expect(result.code, label).toBe("config_invalid");
      expect(result.explanation, label).toContain(needle === "" ? "role" : needle);
    }
  });

  it("sink shape and clock are validated after config (order pinned)", () => {
    const [na, nb] = makePair();
    const config = {
      transport: new FramedTransport(),
      sink: makePipe().sink,
      role: "initiator" as const,
      local: { identity: na.identity, runtimeEpochId: na.epoch },
      expectedPeer: { nodeId: nb.identity.nodeId, runtimeEpochId: nb.epoch },
      probes: {
        localKey: () => na.localRecord,
        peerKey: () => na.peerKeyRecord,
        peerTrust: () => ({ state: na.trustState, fingerprint: na.trustFingerprint }),
      },
      replayGuard: na.guard,
      challengeFactory: na.challengeFactory,
    };
    // Bad config AND bad sink → config wins (config first).
    const both = openAuthenticatedSession({ ...config, role: "both" as never, sink: null as never }, 1000);
    expect(both.ok).toBe(false);
    if (both.ok) throw new Error("unreachable");
    expect(both.code).toBe("config_invalid");
    // Valid config, bad sink → sink_invalid.
    const badSink = openAuthenticatedSession({ ...config, sink: {} as never }, 1000);
    expect(badSink.ok).toBe(false);
    if (badSink.ok) throw new Error("unreachable");
    expect(badSink.code).toBe("sink_invalid");
    // Valid config+sink, bad clock → clock_invalid.
    const badClock = openAuthenticatedSession(config, Number.NaN);
    expect(badClock.ok).toBe(false);
    if (badClock.ok) throw new Error("unreachable");
    expect(badClock.code).toBe("clock_invalid");
  });
});

// ── happy path ──────────────────────────────────────────────────────────────

describe("mutual handshake over the frozen identity stack", () => {
  it("three messages establish both sides with one identical transcript hash", () => {
    const { a, b } = handshake();
    expect(a.session.state()).toBe("established");
    expect(b.session.state()).toBe("established");
    expect(a.session.endCode()).toBeNull();
    expect(b.session.endCode()).toBeNull();
    const hash = a.session.transcriptHash();
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(b.session.transcriptHash()).toBe(hash);
    // Both nodes recorded exactly two challenges and one transcript.
    expect(a.node.guard.seenChallenges()).toBe(2);
    expect(b.node.guard.seenChallenges()).toBe(2);
    expect(a.node.guard.seenTranscripts()).toBe(1);
    expect(b.node.guard.seenTranscripts()).toBe(1);
  });

  it("the transcript binds protocol, NodeId, key-id, epoch and both challenges", () => {
    const [na, nb] = makePair();
    const a1 = openSide({ node: na, role: "initiator", peer: nb });
    const b1 = openSide({ node: nb, role: "responder", peer: na });
    a1.session.beginHandshake(1000);
    exchange(a1, b1);
    const hashNormal = a1.session.transcriptHash();
    expect(hashNormal).toMatch(/^[0-9a-f]{64}$/);

    // Same identities, same challenges, ONE bound field changed (B's epoch):
    // the transcript hash must change. Then restore → identical hash again
    // (determinism: identical facts, identical binding).
    resetNode(na);
    resetNode(nb);
    nb.epoch = EPOCH_ALT;
    const a2 = openSide({ node: na, role: "initiator", peer: nb, expectEpoch: EPOCH_ALT });
    const b2 = openSide({ node: nb, role: "responder", peer: na });
    a2.session.beginHandshake(1000);
    exchange(a2, b2);
    const hashAltEpoch = a2.session.transcriptHash();
    expect(hashAltEpoch).toMatch(/^[0-9a-f]{64}$/);
    expect(hashAltEpoch).not.toBe(hashNormal);

    resetNode(na);
    resetNode(nb);
    nb.epoch = EPOCH_B;
    const a3 = openSide({ node: na, role: "initiator", peer: nb });
    const b3 = openSide({ node: nb, role: "responder", peer: na });
    a3.session.beginHandshake(1000);
    exchange(a3, b3);
    expect(a3.session.transcriptHash()).toBe(hashNormal);
    expect(b3.session.transcriptHash()).toBe(hashNormal);
  });

  it("application data flows byte-identically in both directions after establishment", () => {
    const { a, b } = handshake();
    const payload = Buffer.from([0x00, 0xff, 0x80, 0x0a, 0x41, 0x00]);
    const sent = a.session.send(payload, 1010);
    expect(sent.ok).toBe(true);
    const toB = flow(a, b);
    expect(toB).toHaveLength(1);
    expect(toB[0]?.ok).toBe(true);
    if (!toB[0] || !toB[0].ok) throw new Error("unreachable");
    expect(toB[0].delivered).toHaveLength(1);
    expect(Buffer.from(toB[0].delivered[0] ?? new Uint8Array()).equals(payload)).toBe(true);

    const reply = Buffer.from("reverse-path");
    expect(b.session.send(reply, 1011).ok).toBe(true);
    const toA = flow(b, a);
    if (!toA[0] || !toA[0].ok) throw new Error("unreachable");
    expect(Buffer.from(toA[0].delivered[0] ?? new Uint8Array()).toString("utf8")).toBe("reverse-path");
    expect(a.session.state()).toBe("established");
  });

  it("sending before establishment refuses without closing the session", () => {
    const [na, nb] = makePair();
    const a = openSide({ node: na, role: "initiator", peer: nb });
    const refused = a.session.send(Buffer.from("early"), 1000);
    expect(refused.ok).toBe(false);
    if (refused.ok) throw new Error("unreachable");
    expect(refused.code).toBe("session_not_established");
    expect(a.session.state()).toBe("handshaking"); // caller error, session unchanged
    // The handshake still completes normally afterwards.
    const b = openSide({ node: nb, role: "responder", peer: na });
    a.session.beginHandshake(1001);
    exchange(a, b);
    expect(a.session.state()).toBe("established");
    expect(b.session.state()).toBe("established");
  });

  it("endpoint evidence is recorded as evidence and never enters the transcript", () => {
    const [na, nb] = makePair();
    // Run 1: both sides carry endpoint evidence.
    const a1 = openSide({ node: na, role: "initiator", peer: nb, evidence: { remoteAddress: "127.0.0.1", remotePort: 51234 } });
    const b1 = openSide({ node: nb, role: "responder", peer: na, evidence: { remoteAddress: "127.0.0.1", remotePort: 41885 } });
    expect(a1.session.endpointEvidence()).toEqual({ remoteAddress: "127.0.0.1", remotePort: 51234 });
    expect(b1.session.endpointEvidence()).toEqual({ remoteAddress: "127.0.0.1", remotePort: 41885 });
    a1.session.beginHandshake(1000);
    exchange(a1, b1);
    expect(a1.session.state()).toBe("established");
    const withEvidence = a1.session.transcriptHash();

    // Run 2: identical facts, NO endpoint evidence → identical binding.
    resetNode(na);
    resetNode(nb);
    const a2 = openSide({ node: na, role: "initiator", peer: nb });
    const b2 = openSide({ node: nb, role: "responder", peer: na });
    expect(a2.session.endpointEvidence()).toEqual({});
    a2.session.beginHandshake(1000);
    exchange(a2, b2);
    expect(a2.session.state()).toBe("established");
    const withoutEvidence = a2.session.transcriptHash();

    expect(withEvidence).toMatch(/^[0-9a-f]{64}$/);
    expect(withoutEvidence).toBe(withEvidence);
  });
});

// ── handshake refusals (every one fails the session closed) ───────────────

function firstFrame(outbox: readonly Buffer[]): Buffer {
  const frame = outbox[0];
  if (frame === undefined) throw new Error("outbox is empty");
  return Buffer.from(frame);
}

function firstMessage(outbox: readonly Buffer[]): Record<string, unknown> {
  const frame = outbox[0];
  if (frame === undefined) throw new Error("outbox is empty");
  return JSON.parse(frame.subarray(42).toString("utf8")) as Record<string, unknown>;
}

function responderOnly(): { na: NodeSim; nb: NodeSim; b: Side } {
  const [na, nb] = makePair();
  const b = openSide({ node: nb, role: "responder", peer: na });
  return { na, nb, b };
}

function initiatorBegun(): { na: NodeSim; nb: NodeSim; a: Side; hello: Record<string, unknown> } {
  const [na, nb] = makePair();
  const a = openSide({ node: na, role: "initiator", peer: nb });
  const began = a.session.beginHandshake(1000);
  if (!began.ok) throw new Error(`begin refused: ${began.code}`);
  const hello = firstMessage(a.pipe.outbox);
  return { na, nb, a, hello };
}

describe("handshake refusals (fail closed, one code per law)", () => {
  it("unknown protocol and unknown message kind refuse as downgrade", () => {
    const cases: ReadonlyArray<Record<string, unknown>> = [
      { protocol: "menog-auth-session/v2", kind: "hello" },
      { protocol: AUTH_SESSION_PROTOCOL, kind: "hello2" },
      { protocol: AUTH_SESSION_PROTOCOL, kind: { evil: true } },
    ];
    for (const patch of cases) {
      const { na, b } = responderOnly();
      const hello = { ...claimsOf(na, na.challengeFactory()), protocol: AUTH_SESSION_PROTOCOL, kind: "hello", ...patch };
      b.session.ingest(craftFrame(hello), 1001);
      expectEnd(b.session, "protocol_downgrade");
    }
  });

  it("malformed handshake data refuses: bad JSON, non-object, missing fields, bad challenge", () => {
    const payloads: ReadonlyArray<(na: NodeSim) => unknown> = [
      () => "not-json{",
      () => [1, 2, 3],
      (na) => {
        const claims = claimsOf(na, na.challengeFactory());
        delete (claims as Record<string, unknown>)["challenge"];
        return { protocol: AUTH_SESSION_PROTOCOL, kind: "hello", ...claims };
      },
      (na) => ({ protocol: AUTH_SESSION_PROTOCOL, kind: "hello", ...claimsOf(na, "nnc-TOOSHORT") }),
    ];
    for (const build of payloads) {
      const { na, b } = responderOnly();
      b.session.ingest(craftFrame(build(na)), 1001);
      expectEnd(b.session, "malformed_handshake");
    }
  });

  it("claims that do not re-derive, or a foreign NodeId, refuse as node_mismatch", () => {
    // (a) tampered fingerprint: does not re-derive from the public key.
    {
      const { na, b } = responderOnly();
      const hello = {
        protocol: AUTH_SESSION_PROTOCOL,
        kind: "hello",
        ...claimsOf(na, na.challengeFactory()),
        fingerprint: "fp-sha256-" + "0".repeat(64),
      };
      b.session.ingest(craftFrame(hello), 1001);
      expectEnd(b.session, "node_mismatch");
      expect(b.session.endExplanation()).toContain("re-derive");
    }
    // (b) a well-formed but different node: not the expected peer.
    {
      const { b } = responderOnly();
      const stranger = makeNode("stranger", EPOCH_ALT, 0x4000);
      const hello = { protocol: AUTH_SESSION_PROTOCOL, kind: "hello", ...claimsOf(stranger, stranger.challengeFactory()) };
      b.session.ingest(craftFrame(hello), 1001);
      expectEnd(b.session, "node_mismatch");
      expect(b.session.endExplanation()).toContain(stranger.identity.nodeId);
    }
    // (c) wrong key-id for a correct public key.
    {
      const { na, b } = responderOnly();
      const hello = {
        protocol: AUTH_SESSION_PROTOCOL,
        kind: "hello",
        ...claimsOf(na, na.challengeFactory()),
        keyId: "kid-" + "f".repeat(16),
      };
      b.session.ingest(craftFrame(hello), 1001);
      expectEnd(b.session, "node_mismatch");
      expect(b.session.endExplanation()).toContain("key-id");
    }
  });

  it("a rotated identity inherits no trust — only evidenced re-admission opens the door", () => {
    // Part 1: expectation NOT updated → the fresh NodeId is simply not the
    // expected peer (rotation is re-identity; nothing carries over).
    const [na, nb] = makePair();
    const a = openSide({ node: na, role: "initiator", peer: nb }); // captures the OLD nodeId
    rotateNode(nb);
    const bFresh = openSide({ node: nb, role: "responder", peer: na });
    a.session.beginHandshake(1000);
    exchange(a, bFresh);
    expectEnd(a.session, "node_mismatch");
    expect(a.session.endExplanation()).toContain(nb.identity.nodeId);
    expect(bFresh.session.state()).toBe("handshaking"); // no false establishment on either side

    // Part 2: expectation UPDATED to the fresh NodeId but the registry was
    // never re-admitted (still trusts the old fingerprint) → refused.
    const [na2, nb2] = makePair();
    rotateNode(nb2); // link() ran inside makePair → nb2's view is the fresh node, trustFingerprint is the OLD one
    const a2 = openSide({ node: na2, role: "initiator", peer: nb2 }); // captures the NEW nodeId
    expect(nb2.trustFingerprint).not.toBe(nb2.identity.fingerprint);
    const b2 = openSide({ node: nb2, role: "responder", peer: na2 });
    a2.session.beginHandshake(1000);
    exchange(a2, b2);
    expectEnd(a2.session, "fingerprint_not_admitted");
    expect(a2.session.endExplanation()).toContain("inherits no trust");

    // Part 3: the evidenced re-admission (registry + key record refreshed)
    // is the ONLY path that opens — then the handshake succeeds.
    link(na2, nb2);
    const [na3, nb3] = makePair();
    rotateNode(nb3);
    link(na3, nb3); // fresh registry view of the rotated identity
    const a3 = openSide({ node: na3, role: "initiator", peer: nb3 });
    const b3 = openSide({ node: nb3, role: "responder", peer: na3 });
    a3.session.beginHandshake(1000);
    exchange(a3, b3);
    expect(a3.session.state()).toBe("established");
    expect(b3.session.state()).toBe("established");
  });

  it("a peer that is not admitted never passes — quarantine/retirement/candidate/unknown", () => {
    const states: ReadonlyArray<NodeTrustState> = ["quarantined", "retired", "candidate", "unknown"];
    for (const state of states) {
      const { na, b } = responderOnly();
      b.node.trustState = state;
      // Endpoint evidence present on BOTH sides: IP never overrides trust.
      const guarded = openSide({
        node: b.node,
        role: "responder",
        peer: na,
        evidence: { remoteAddress: "127.0.0.1", remotePort: 12345 },
      });
      const hello = { protocol: AUTH_SESSION_PROTOCOL, kind: "hello", ...claimsOf(na, na.challengeFactory()) };
      guarded.session.ingest(craftFrame(hello), 1001);
      expectEnd(guarded.session, "peer_not_admitted");
      expect(guarded.session.endExplanation()).toContain(state);
      expect(guarded.session.endpointEvidence()).toEqual({ remoteAddress: "127.0.0.1", remotePort: 12345 });
    }
  });

  it("the 25B key-use gate refuses the peer key with its embedded code", () => {
    const mutations: ReadonlyArray<[string, (na: NodeSim) => KeyLifecycleRecord | null, string]> = [
      ["unknown record", () => null, "unknown_record"],
      [
        "revoked",
        (na) => transitionRecord(na.localRecord as KeyLifecycleRecord, "revoked"),
        "state_revoked",
      ],
      [
        "retired",
        (na) => transitionRecord(na.localRecord as KeyLifecycleRecord, "retired"),
        "state_retired",
      ],
      [
        "rotated (stale)",
        (na) => {
          const requested = transitionRecord(na.localRecord as KeyLifecycleRecord, "rotation_requested");
          return transitionRecord(requested, "rotated", rotateLocalIdentity(na.identity).fresh);
        },
        "stale_rotated_key",
      ],
    ];
    for (const [label, mutate, embedded] of mutations) {
      const { na, nb, a, hello } = initiatorBegun();
      nb.peerKeyRecord = mutate(na);
      const b = openSide({ node: nb, role: "responder", peer: na });
      b.session.ingest(craftFrame(hello), 1001);
      expectEnd(b.session, "peer_key_refused");
      expect(b.session.endExplanation(), label).toContain(embedded);
      expect(a.session.state()).toBe("handshaking"); // the initiator never got a reply
    }
  });

  it("a stale runtime epoch refuses", () => {
    const [na, nb] = makePair();
    const staleExpectation = "re-444444444444-eeeeeeeeeeeeeeee";
    const b = openSide({ node: nb, role: "responder", peer: na, expectEpoch: staleExpectation });
    const hello = { protocol: AUTH_SESSION_PROTOCOL, kind: "hello", ...claimsOf(na, na.challengeFactory()) };
    b.session.ingest(craftFrame(hello), 1001);
    expectEnd(b.session, "epoch_stale");
    expect(b.session.endExplanation()).toContain(EPOCH_A);
    expect(b.session.endExplanation()).toContain(staleExpectation);
  });

  it("a replayed hello refuses on the shared replay guard (challenge reuse)", () => {
    // Handshake 1 completes: the responder's node records the challenge.
    const [na, nb] = makePair();
    const a1 = openSide({ node: na, role: "initiator", peer: nb });
    const b1 = openSide({ node: nb, role: "responder", peer: na });
    a1.session.beginHandshake(1000);
    const replayedHello = Buffer.from(firstFrame(a1.pipe.outbox));
    exchange(a1, b1);
    expect(a1.session.state()).toBe("established");
    expect(nb.guard.seenChallenges()).toBe(2);

    // A NEW responder session on the same node sees the byte-identical hello.
    const b2 = openSide({ node: nb, role: "responder", peer: na });
    const result = b2.session.ingest(replayedHello, 1001);
    expect(result.ok).toBe(false);
    expectEnd(b2.session, "challenge_reused");
    expect(nb.guard.seenChallenges()).toBe(2); // nothing new was accepted
  });

  it("a tampered transcript hash refuses as transcript_mismatch", () => {
    const { nb, a } = initiatorBegun();
    const reply = {
      protocol: AUTH_SESSION_PROTOCOL,
      kind: "reply",
      ...claimsOf(nb, nb.challengeFactory()),
      transcriptHash: "0".repeat(64),
      signature: Buffer.alloc(64).toString("base64"),
    };
    a.session.ingest(craftFrame(reply), 1001);
    expectEnd(a.session, "transcript_mismatch");
    expect(a.session.endExplanation()).toContain("locally computed");
  });

  it("a transcript already in the replay record refuses as transcript_replayed", () => {
    const { na, nb, a, hello } = initiatorBegun();
    const responderClaims = claimsOf(nb, nb.challengeFactory());
    const realHash = computeTranscript(hello, responderClaims);
    // The node's replay record already contains this transcript (as a durable
    // replay import would seed it) — the second observation must refuse.
    expect(na.guard.observeTranscript(realHash)).toBe("fresh");
    const reply = {
      protocol: AUTH_SESSION_PROTOCOL,
      kind: "reply",
      ...responderClaims,
      transcriptHash: realHash,
      signature: Buffer.alloc(64).toString("base64"),
    };
    a.session.ingest(craftFrame(reply), 1001);
    expectEnd(a.session, "transcript_replayed");
  });

  it("a signature not produced by the admitted key refuses as signature_invalid", () => {
    // (a) garbage bytes in the signature field.
    {
      const { nb, a, hello } = initiatorBegun();
      const responderClaims = claimsOf(nb, nb.challengeFactory());
      const reply = {
        protocol: AUTH_SESSION_PROTOCOL,
        kind: "reply",
        ...responderClaims,
        transcriptHash: computeTranscript(hello, responderClaims),
        signature: Buffer.alloc(64).toString("base64"),
      };
      a.session.ingest(craftFrame(reply), 1001);
      expectEnd(a.session, "signature_invalid");
    }
    // (b) a WELL-FORMED signature by a DIFFERENT identity over the same subject.
    {
      const { nb, a, hello } = initiatorBegun();
      const responderClaims = claimsOf(nb, nb.challengeFactory());
      const transcriptHash = computeTranscript(hello, responderClaims);
      const stranger = generateLocalSigningIdentity();
      const forged = signFederationMessage(stranger, {
        fingerprint: nb.identity.fingerprint,
        role: "responder",
        transcriptHash,
      });
      if (!forged.ok) throw new Error("sign refused");
      const reply = {
        protocol: AUTH_SESSION_PROTOCOL,
        kind: "reply",
        ...responderClaims,
        transcriptHash,
        signature: forged.signature,
      };
      a.session.ingest(craftFrame(reply), 1001);
      expectEnd(a.session, "signature_invalid");
    }
  });

  it("wrong-direction and out-of-order messages refuse as unexpected_message", () => {
    // A responder never begins.
    const { b } = responderOnly();
    const began = b.session.beginHandshake(1000);
    expect(began.ok).toBe(false);
    if (began.ok) throw new Error("unreachable");
    expect(began.code).toBe("unexpected_message");
    expect(b.session.state()).toBe("closed");

    // An initiator never receives hello.
    const init = initiatorBegun();
    init.a.session.ingest(
      craftFrame({ protocol: AUTH_SESSION_PROTOCOL, kind: "hello", ...claimsOf(init.nb, init.nb.challengeFactory()) }),
      1001
    );
    expectEnd(init.a.session, "unexpected_message");

    // A responder never receives reply.
    const { na: naR, b: bR } = responderOnly();
    bR.session.ingest(
      craftFrame({
        protocol: AUTH_SESSION_PROTOCOL,
        kind: "reply",
        ...claimsOf(naR, naR.challengeFactory()),
        transcriptHash: "0".repeat(64),
        signature: "AA==",
      }),
      1001
    );
    expectEnd(bR.session, "unexpected_message");

    // Finish before hello refuses.
    const { b: bF } = responderOnly();
    bF.session.ingest(
      craftFrame({ protocol: AUTH_SESSION_PROTOCOL, kind: "finish", transcriptHash: "0".repeat(64), signature: "AA==" }),
      1001
    );
    expectEnd(bF.session, "unexpected_message");

    // Duplicate hello (second hello in the same handshake) refuses.
    const { na: naD, b: bD } = responderOnly();
    const helloD = { protocol: AUTH_SESSION_PROTOCOL, kind: "hello", ...claimsOf(naD, naD.challengeFactory()) };
    bD.session.ingest(craftFrame(helloD), 1001);
    expect(bD.session.state()).toBe("handshaking");
    bD.session.ingest(craftFrame(helloD), 1002);
    expectEnd(bD.session, "unexpected_message");
  });
});

// ── during-session recheck (current facts, every ingress) ───────────────────

describe("recheck during the session closes future ingress", () => {
  it("quarantine mid-session refuses the next ingress and closes the session", () => {
    const { a, b } = handshake();
    a.node.trustState = "quarantined"; // A's CURRENT view of B flips
    expect(b.session.send(Buffer.from("after-quarantine"), 1020).ok).toBe(true);
    const results = flow(b, a, 1021);
    expect(results).toHaveLength(1);
    expect(results[0]?.ok).toBe(false);
    if (results[0] !== undefined && !results[0].ok) {
      expect(results[0].code).toBe("peer_not_admitted");
      expect(results[0].explanation).toContain("quarantine");
    }
    expectEnd(a.session, "peer_not_admitted");
    expect(a.pipe.destroyed).toBe(1); // the sink was torn down exactly once
    // Future ingress AND egress both refuse; B's own state is untouched.
    const again = a.session.ingest(Buffer.from("more"), 1022);
    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.code).toBe("session_closed");
    const sendAfter = a.session.send(Buffer.from("out"), 1023);
    expect(sendAfter.ok).toBe(false);
    if (!sendAfter.ok) expect(sendAfter.code).toBe("session_closed");
    expect(b.session.state()).toBe("established");
  });

  it("retirement mid-session refuses the next ingress too", () => {
    const { a, b } = handshake();
    a.node.trustState = "retired";
    expect(b.session.send(Buffer.from("post-retirement"), 1020).ok).toBe(true);
    flow(b, a, 1021);
    expectEnd(a.session, "peer_not_admitted");
    expect(a.session.endExplanation()).toContain("retired");
  });

  it("peer key revocation mid-session refuses ingress with the embedded 25B code", () => {
    const { a, b } = handshake();
    a.node.peerKeyRecord = transitionRecord(a.node.peerKeyRecord as KeyLifecycleRecord, "revoked");
    expect(b.session.send(Buffer.from("signed-by-now-dead-key"), 1020).ok).toBe(true);
    const results = flow(b, a, 1021);
    expect(results[0]?.ok).toBe(false);
    expectEnd(a.session, "peer_key_refused");
    expect(a.session.endExplanation()).toContain("state_revoked");
  });

  it("local key revocation mid-session refuses egress", () => {
    const { a } = handshake();
    a.node.localRecord = transitionRecord(a.node.localRecord as KeyLifecycleRecord, "revoked");
    const send = a.session.send(Buffer.from("signed-by-now-dead-local-key"), 1020);
    expect(send.ok).toBe(false);
    if (send.ok) throw new Error("unreachable");
    expect(send.code).toBe("local_key_refused");
    expectEnd(a.session, "local_key_refused");
    expect(a.session.endExplanation()).toContain("state_revoked");
  });

  it("explicit recheck() reads current facts on demand", () => {
    const { a } = handshake();
    expect(a.session.recheck(1020).ok).toBe(true);
    a.node.trustState = "quarantined";
    const refused = a.session.recheck(1021);
    expect(refused.ok).toBe(false);
    if (refused.ok) throw new Error("unreachable");
    expect(refused.code).toBe("peer_not_admitted");
    expectEnd(a.session, "peer_not_admitted");
  });
});

// ── lifecycle, transport mapping, determinism, secrets ─────────────────────

describe("explicit lifecycle, transport mapping and evidence discipline", () => {
  it("close is idempotent and terminal", () => {
    const { a } = handshake();
    const first = a.session.close();
    expect(first.ok).toBe(true);
    if (!first.ok) throw new Error("unreachable");
    expect(first.code).toBe("session_closed");
    expect(a.session.endCode()).toBe("local_close");
    expect((a.session.endExplanation() ?? "").length).toBeGreaterThan(10);
    const second = a.session.close();
    expect(second.ok).toBe(true);
    if (!second.ok) throw new Error("unreachable");
    expect(second.code).toBe("session_already_closed");
    expect(a.pipe.destroyed).toBe(1); // exactly one destroy, ever
    const ingest = a.session.ingest(Buffer.from("x"), 1030);
    expect(ingest.ok).toBe(false);
    if (!ingest.ok) expect(ingest.code).toBe("session_closed");
    const send = a.session.send(Buffer.from("x"), 1031);
    expect(send.ok).toBe(false);
    if (!send.ok) expect(send.code).toBe("session_closed");
  });

  it("clean remote stream close and truncated stream close map deterministically", () => {
    // Clean: peer ends the stream with nothing partial pending.
    const { a } = handshake();
    const closed = a.session.notifyStreamClosed(1020);
    expect(closed.ok).toBe(true);
    if (!closed.ok) throw new Error("unreachable");
    expect(closed.code).toBe("session_closed");
    expect(a.session.endCode()).toBe("peer_stream_closed");
    const again = a.session.notifyStreamClosed(1021);
    expect(again.ok).toBe(true);
    if (!again.ok) throw new Error("unreachable");
    expect(again.code).toBe("session_already_closed");

    // Truncated: half a frame, then the stream ends.
    const [na, nb] = makePair();
    const a2 = openSide({ node: na, role: "initiator", peer: nb });
    const half = craftFrame({ protocol: AUTH_SESSION_PROTOCOL, kind: "hello", ...claimsOf(nb, nb.challengeFactory()) }).subarray(0, 30);
    const partial = a2.session.ingest(half, 1000);
    expect(partial.ok).toBe(true); // held safely, nothing delivered
    if (partial.ok) expect(partial.delivered).toHaveLength(0);
    const trunc = a2.session.notifyStreamClosed(1001);
    expect(trunc.ok).toBe(false);
    if (trunc.ok) throw new Error("unreachable");
    expect(trunc.code).toBe("transport_refused");
    expectEnd(a2.session, "transport_refused");
  });

  it("non-finite clock inputs refuse without closing the session", () => {
    const { a } = handshake();
    const refused = a.session.ingest(Buffer.from("x"), Number.NaN);
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.code).toBe("clock_invalid");
    const send = a.session.send(Buffer.from("x"), Number.POSITIVE_INFINITY);
    expect(send.ok).toBe(false);
    if (!send.ok) expect(send.code).toBe("clock_invalid");
    const recheck = a.session.recheck(Number.NaN);
    expect(recheck.ok).toBe(false);
    if (recheck.ok) throw new Error("unreachable");
    expect(recheck.code).toBe("clock_invalid");
    expect(a.session.state()).toBe("established"); // caller error, session unchanged
  });

  it("identical inputs produce identical refusal explanations (determinism)", () => {
    const run = (): string => {
      const { na, b } = responderOnly();
      const hello = { protocol: AUTH_SESSION_PROTOCOL, kind: "hello", ...claimsOf(na, "nnc-TOOSHORT") };
      b.session.ingest(craftFrame(hello), 1001);
      return `${String(b.session.endCode())}::${String(b.session.endExplanation())}`;
    };
    expect(run()).toBe(run());
  });

  it("private key material never appears in handshake messages, transcript or evidence", () => {
    const [na, nb] = makePair();
    const a = openSide({ node: na, role: "initiator", peer: nb, evidence: { remoteAddress: "127.0.0.1", remotePort: 41885 } });
    const b = openSide({ node: nb, role: "responder", peer: na });
    const began = a.session.beginHandshake(1000);
    if (!began.ok) throw new Error("begin refused");
    const helloFrames = [...a.pipe.outbox];
    drain(a.pipe, b.session, 1001);
    const replyFrames = [...b.pipe.outbox];
    drain(b.pipe, a.session, 1002);
    const finishFrames = [...a.pipe.outbox];
    drain(a.pipe, b.session, 1003);
    expect(a.session.state()).toBe("established");

    const messages = [...helloFrames, ...replyFrames, ...finishFrames].map(
      (frame) => JSON.parse(frame.subarray(42).toString("utf8")) as Record<string, unknown>
    );
    expect(messages.map((message) => message["kind"])).toEqual(["hello", "reply", "finish"]);
    for (const message of messages) {
      expect(payloadContainsSecretKeyMaterial(message)).toBe(false);
      const json = JSON.stringify(message);
      for (const needle of ["privateKey", "private_key", "pkcs8", "BEGIN", "seed", "keystore"]) {
        expect(json).not.toContain(needle);
      }
    }
    // Closed wire shape: only the bound public fields travel.
    expect(Object.keys(messages[0] ?? {}).sort()).toEqual([
      "challenge",
      "fingerprint",
      "keyId",
      "kind",
      "nodeId",
      "protocol",
      "publicKeyHex",
      "runtimeEpochId",
    ]);
    expect(Object.keys(messages[1] ?? {}).sort()).toEqual([
      "challenge",
      "fingerprint",
      "keyId",
      "kind",
      "nodeId",
      "protocol",
      "publicKeyHex",
      "runtimeEpochId",
      "signature",
      "transcriptHash",
    ]);
    expect(Object.keys(messages[2] ?? {}).sort()).toEqual(["kind", "protocol", "signature", "transcriptHash"]);
    // Evidence and hash values carry nothing secret-shaped either.
    expect(payloadContainsSecretKeyMaterial(a.session.endpointEvidence())).toBe(false);
    expect(payloadContainsSecretKeyMaterial(a.session.transcriptHash())).toBe(false);
  });
});

// ── structural scan ─────────────────────────────────────────────────────────

describe("structural scan: the module keeps to its sanctioned surface", () => {
  it("imports exactly the sanctioned modules", () => {
    const raw = readFileSync(
      join(process.cwd(), "packages", "durable-state", "src", "authenticatedSession.ts"),
      "utf8"
    );
    const importMatches = [...raw.matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1]);
    expect(importMatches).toEqual([
      "node:crypto",
      "./canonical.js",
      "./federationCrypto.js",
      "./federationKeyLifecycle.js",
      "./federationIdentity.js",
      "./continuity.js",
      "./framedSocketTransport.js",
    ]);
  });

  it("forbids shell/child/env/dial/listener/clock/timer/key-export/persistence surfaces", () => {
    const source = moduleSource();
    const forbidden = [
      "child_process",
      "spawn",
      "process.env",
      "node:dns",
      "node:http",
      "node:net",
      "node:tls",
      "createServer",
      ".listen(",
      "fetch(",
      "axios",
      "XMLHttpRequest",
      "WebSocket",
      "createConnection",
      "connect(",
      "request(",
      ".pipe(",
      "setTimeout",
      "setInterval",
      "Date.now",
      "Math.random",
      "eval(",
      "require(",
      ".persist(",
      "root =",
      "createPrivateKey",
      "generateKeyPair",
      "edSign",
      "edVerify",
      "privateKey",
      "private_key",
      "discovery",
      "policy",
      "execution",
    ];
    for (const token of forbidden) {
      expect(source, token).not.toContain(token);
    }
  });
});

// ── real loopback sockets (pack mandate: live transport) ───────────────────

function listenOn(server: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ port, host: "127.0.0.1" }, () => resolve());
  });
}

function connectTo(port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect({ port, host: "127.0.0.1" }, () => resolve(socket));
    socket.once("error", reject);
  });
}

async function closeServer(server: Server, sockets: readonly Socket[]): Promise<void> {
  for (const socket of sockets) socket.destroy();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

function wireSocket(
  transport: FramedTransport,
  socket: Socket,
  opts: {
    node: NodeSim;
    role: "initiator" | "responder";
    peer: NodeSim;
    received: Uint8Array[];
    raw?: Buffer[];
  }
): AuthenticatedSession {
  const opened = openAuthenticatedSession(
    {
      transport,
      sink: { write: (chunk) => socket.write(chunk), destroy: () => socket.destroy() },
      role: opts.role,
      local: { identity: opts.node.identity, runtimeEpochId: opts.node.epoch },
      expectedPeer: { nodeId: opts.peer.identity.nodeId, runtimeEpochId: opts.peer.epoch },
      probes: {
        localKey: () => opts.node.localRecord,
        peerKey: () => opts.node.peerKeyRecord,
        peerTrust: () => ({ state: opts.node.trustState, fingerprint: opts.node.trustFingerprint }),
      },
      replayGuard: opts.node.guard,
      endpointEvidence: { remoteAddress: socket.remoteAddress, remotePort: socket.remotePort },
      challengeFactory: opts.node.challengeFactory,
    },
    Date.now()
  );
  if (!opened.ok) throw new Error(`open refused: ${opened.code} — ${opened.explanation}`);
  socket.on("data", (chunk) => {
    if (opts.raw !== undefined) opts.raw.push(Buffer.from(chunk));
    const result = opened.session.ingest(chunk, Date.now());
    if (result.ok) {
      for (const payload of result.delivered) opts.received.push(payload);
    }
  });
  socket.on("close", () => {
    opened.session.notifyStreamClosed(Date.now());
  });
  socket.on("error", () => {
    // teardown races are expected; the session close path is authoritative
  });
  return opened.session;
}

describe("real loopback sockets: authenticated session over live local transport", () => {
  it("full mutual handshake and byte-identical data over 127.0.0.1", async () => {
    const [na, nb] = makePair();
    const serverSockets: Socket[] = [];
    const serverSessions: AuthenticatedSession[] = [];
    const serverReceived: Uint8Array[] = [];
    const serverTransport = new FramedTransport();
    const server = createServer((socket) => {
      serverSockets.push(socket);
      const session = wireSocket(serverTransport, socket, {
        node: nb,
        role: "responder",
        peer: na,
        received: serverReceived,
      });
      serverSessions.push(session);
    });
    await listenOn(server, PORT_ROUNDTRIP);
    let clientSocket: Socket | null = null;
    try {
      clientSocket = await connectTo(PORT_ROUNDTRIP);
      const clientReceived: Uint8Array[] = [];
      const client = wireSocket(new FramedTransport(), clientSocket, {
        node: na,
        role: "initiator",
        peer: nb,
        received: clientReceived,
      });
      const serverAttached = await waitFor(() => serverSessions.length === 1);
      expect(serverAttached).toBe(true);
      expect(client.beginHandshake(Date.now()).ok).toBe(true);
      const established = await waitFor(
        () => client.state() === "established" && (serverSessions[0]?.state() ?? "") === "established"
      );
      expect(established).toBe(true);
      expect(client.transcriptHash()).toMatch(/^[0-9a-f]{64}$/);
      expect(serverSessions[0]?.transcriptHash()).toBe(client.transcriptHash());

      // Endpoint facts are recorded as evidence on both ends — never more.
      expect(serverSessions[0]?.endpointEvidence().remoteAddress).toBe("127.0.0.1");
      expect(client.endpointEvidence().remoteAddress).toBe("127.0.0.1");

      // Data: initiator → responder, byte-identical.
      const payload = Buffer.from([0x00, 0xff, 0x80, 0x41, 0x0a, 0x00]);
      expect(client.send(payload, Date.now()).ok).toBe(true);
      const gotAtServer = await waitFor(() => serverReceived.length === 1);
      expect(gotAtServer).toBe(true);
      expect(Buffer.from(serverReceived[0] ?? new Uint8Array()).equals(payload)).toBe(true);

      // Data: responder → initiator, byte-identical.
      const reply = Buffer.from("loopback-reply");
      expect(serverSessions[0]?.send(reply, Date.now()).ok).toBe(true);
      const gotAtClient = await waitFor(() => clientReceived.length === 1);
      expect(gotAtClient).toBe(true);
      expect(Buffer.from(clientReceived[0] ?? new Uint8Array()).toString("utf8")).toBe("loopback-reply");
      expect(client.state()).toBe("established");
    } finally {
      clientSocket?.destroy();
      await closeServer(server, serverSockets);
    }
  });

  it("a replayed hello on a NEW real connection refuses (challenge reuse)", async () => {
    const [na, nb] = makePair();
    const serverSockets: Socket[] = [];
    const serverSessions: AuthenticatedSession[] = [];
    const serverReceived: Uint8Array[] = [];
    const serverRaw: Buffer[][] = [];
    const serverTransport = new FramedTransport();
    const server = createServer((socket) => {
      serverSockets.push(socket);
      const raw: Buffer[] = [];
      serverRaw.push(raw);
      const session = wireSocket(serverTransport, socket, {
        node: nb,
        role: "responder",
        peer: na,
        received: serverReceived,
        raw,
      });
      serverSessions.push(session);
    });
    await listenOn(server, PORT_REPLAY);
    let clientSocket: Socket | null = null;
    try {
      // Connection 1: a full, legitimate handshake.
      clientSocket = await connectTo(PORT_REPLAY);
      const client1 = wireSocket(new FramedTransport(), clientSocket, {
        node: na,
        role: "initiator",
        peer: nb,
        received: [],
      });
      await waitFor(() => serverSessions.length === 1);
      expect(client1.beginHandshake(Date.now()).ok).toBe(true);
      const established = await waitFor(() => client1.state() === "established");
      expect(established).toBe(true);
      const capturedHello = serverRaw[0]?.[0];
      expect(capturedHello).toBeDefined(); // the raw hello bytes, as on the wire
      clientSocket.destroy();
      await waitFor(() => (serverSessions[0]?.state() ?? "") === "closed");

      // Connection 2: the byte-identical hello is replayed at a NEW session
      // on the same node — the shared replay guard refuses the challenge.
      const client2Socket = await connectTo(PORT_REPLAY);
      clientSocket = client2Socket;
      await waitFor(() => serverSessions.length === 2);
      client2Socket.write(capturedHello as Buffer);
      const refused = await waitFor(() => (serverSessions[1]?.state() ?? "") === "closed");
      expect(refused).toBe(true);
      expect(serverSessions[1]?.endCode()).toBe("challenge_reused");
      expect(nb.guard.seenChallenges()).toBe(2); // nothing new accepted
    } finally {
      clientSocket?.destroy();
      await closeServer(server, serverSockets);
    }
  });

  it("quarantine during a real session closes future ingress over the wire", async () => {
    const [na, nb] = makePair();
    const serverSockets: Socket[] = [];
    const serverSessions: AuthenticatedSession[] = [];
    const serverReceived: Uint8Array[] = [];
    const serverTransport = new FramedTransport();
    const server = createServer((socket) => {
      serverSockets.push(socket);
      const session = wireSocket(serverTransport, socket, {
        node: nb,
        role: "responder",
        peer: na,
        received: serverReceived,
      });
      serverSessions.push(session);
    });
    await listenOn(server, PORT_QUARANTINE);
    let clientSocket: Socket | null = null;
    try {
      clientSocket = await connectTo(PORT_QUARANTINE);
      const client = wireSocket(new FramedTransport(), clientSocket, {
        node: na,
        role: "initiator",
        peer: nb,
        received: [],
      });
      await waitFor(() => serverSessions.length === 1);
      expect(client.beginHandshake(Date.now()).ok).toBe(true);
      const established = await waitFor(
        () => client.state() === "established" && (serverSessions[0]?.state() ?? "") === "established"
      );
      expect(established).toBe(true);

      // The operator quarantines A on B: the CURRENT state read closes ingress.
      nb.trustState = "quarantined";
      expect(client.send(Buffer.from("one-more-message"), Date.now()).ok).toBe(true);
      const closedAtServer = await waitFor(() => (serverSessions[0]?.state() ?? "") === "closed");
      expect(closedAtServer).toBe(true);
      expect(serverSessions[0]?.endCode()).toBe("peer_not_admitted");
      expect(serverSessions[0]?.endExplanation()).toContain("quarantine");
      expect(serverReceived).toHaveLength(0); // the quarantined byte was never delivered
      // The refusal tore the socket down: the client observes the close.
      const clientSawClose = await waitFor(() => clientSocket !== null && clientSocket.destroyed);
      expect(clientSawClose).toBe(true);
      expect(client.state()).toBe("closed"); // stream end closes the peer side too
    } finally {
      clientSocket?.destroy();
      await closeServer(server, serverSockets);
    }
  });
});

