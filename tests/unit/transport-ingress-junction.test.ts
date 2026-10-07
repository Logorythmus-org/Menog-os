/**
 * PHASE 26E — Transport → Federation Ingress Junction Tests
 * (THE ONE JUNCTION / MANDATORY ORDER / FAIL CLOSED / NO EXECUTION).
 *
 * Pack-mandated attacks, each refusing at its own stage:
 *   terminal/unknown peer · rotated key · stale epoch · replay · tamper ·
 *   stale disclosure · actor mismatch · stale Policy · capability inflation ·
 *   direct exec · admission revoked mid-session.
 *
 * The junction is exercised over the REAL stack: real Ed25519 identities,
 * real 25B lifecycle records, a real 26D handshake (in-memory pipes and a
 * real loopback socket), and the REAL frozen 24D bus on a real durable store
 * — so the replay/receipt stage is genuine frozen machinery, not a mock.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  INGRESS_JUNCTION_SCHEMA_VERSION,
  INGRESS_STAGES,
  INGRESS_STAGE_CODES,
  INGRESS_STAGE_PINS,
  INGRESS_REFUSAL_CODES,
  INGRESS_REFUSAL_EXPLANATIONS,
  INGRESS_AUTHORITY_CLAIM_FIELDS,
  INGRESS_CAPABILITY_CLAIM_CONTAINERS,
  INGRESS_EXPECTED_PROTOCOL_VERSION,
  INGRESS_EXPECTED_FEDERATION_PROTOCOL_VERSION,
  INGRESS_EXPECTED_MESSAGE_SCHEMA_VERSION,
  INGRESS_NEXT_GATE,
  decideTransportIngress,
  // frozen surfaces the junction composes (reused to build honest fixtures)
  DurableStore,
  RuntimeStateCoordinator,
  PeerRegistry,
  FederationBus,
  openAuthenticatedSession,
  generateLocalSigningIdentity,
  rotateLocalIdentity,
  signFederationMessage,
  makeIdentitySignatureVerifier,
  decideLifecycleTransition,
  deriveKeyId,
  canonicalHash,
  makeRuntimeEpochId,
  FramedTransport,
  decideTransportScope,
  decideEgress,
  SessionReplayGuard,
  type AuthenticatedSession,
  type DisclosureManifest,
  type FederationMessageBody,
  type FederationSignedMessage,
  type FramedSink,
  type IngressAdmissionFact,
  type IngressFederationPort,
  type IngressProbes,
  type IngressPortResult,
  type KeyLifecycleRecord,
  type KeyLifecycleState,
  type LocalSigningIdentity,
  type NodeTrustState,
  type RuntimeEpoch,
  type TransportIngressDecision,
  type TransportIngressInput,
} from "@menog/durable-state";
import { createServer, connect, type Server, type Socket } from "node:net";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

// ── cleanup bookkeeping ─────────────────────────────────────────────────────

const roots: string[] = [];
const openStores: DurableStore[] = [];
const openCoords: RuntimeStateCoordinator[] = [];
function newRoot(): string {
  const r = mkdtempSync(join(tmpdir(), "menog-26e-"));
  roots.push(r);
  return r;
}
afterEach(() => {
  for (const c of openCoords) {
    try { c.close(); } catch { /* windows handle */ }
  }
  openCoords.length = 0;
  for (const s of openStores) {
    try { if (s.isOpen) s.close(); } catch { /* windows handle */ }
  }
  openStores.length = 0;
  for (const r of roots) {
    try { rmSync(r, { recursive: true, force: true }); } catch { /* windows */ }
  }
  roots.length = 0;
});

const NOW = 1_700_000_000_000;
const INGRESS_FEDERATION_PROTOCOL = INGRESS_EXPECTED_FEDERATION_PROTOCOL_VERSION;

function epochOf(epochId: string): RuntimeEpoch {
  return Object.freeze({
    schemaVersion: "menog-runtime-epoch/v0",
    epochId,
    startedAtEpochMs: NOW,
    hostRef: "wsl2-target-of-record",
    pidRef: 4242,
    lifecycle: "BOOTING",
    priorOwner: { code: "none" as const, epochId: null },
    startReason: "fresh_store_no_prior_owner",
    executionAuthorized: false as const,
    policyAuthorized: false as const,
  });
}

// ── node simulation (real 24B identities + real 25B records) ───────────────

interface NodeSim {
  identity: LocalSigningIdentity;
  record: KeyLifecycleRecord;
  epoch: string;
  instanceId: string;
  seq: number;
  challengeFactory: () => string;
  peerRecord: KeyLifecycleRecord | null;
  trustState: NodeTrustState;
  trustFingerprint: string;
}

function makeRecord(identity: LocalSigningIdentity, evidence: string): KeyLifecycleRecord {
  const result = decideLifecycleTransition({
    record: null,
    to: "active",
    evidence,
    nowEpochMs: NOW,
    freshPublicFacts: {
      publicKeyHex: identity.publicKeyHex,
      fingerprint: identity.fingerprint,
      nodeId: identity.nodeId,
    },
  });
  if (!result.ok) throw new Error(`initialize refused: ${result.explanation}`);
  return result.record;
}

function makeNode(tag: string, epoch: string, seqBase: number): NodeSim {
  const identity = generateLocalSigningIdentity();
  const node: NodeSim = {
    identity,
    record: makeRecord(identity, "gate-26e-fixture"),
    epoch,
    instanceId: "ri-000000e8fa00-instance" + tag.padEnd(4, "0"),
    seq: 0,
    challengeFactory: () => "",
    peerRecord: null,
    trustState: "admitted",
    trustFingerprint: "",
  };
  node.challengeFactory = () => {
    node.seq += 1;
    return "nnc-" + (seqBase + node.seq).toString(16).padStart(32, "0");
  };
  return node;
}

function transition(record: KeyLifecycleRecord, to: KeyLifecycleState, fresh?: LocalSigningIdentity): KeyLifecycleRecord {
  const result = decideLifecycleTransition({
    record,
    to,
    evidence: `gate-26e-${to}`,
    nowEpochMs: NOW + 2,
    freshPublicFacts:
      fresh === undefined
        ? undefined
        : { publicKeyHex: fresh.publicKeyHex, fingerprint: fresh.fingerprint, nodeId: fresh.nodeId },
  });
  if (!result.ok) throw new Error(`transition to ${to} refused: ${result.explanation}`);
  return result.record;
}

function link(local: NodeSim, peer: NodeSim): void {
  local.peerRecord = peer.record;
  local.trustFingerprint = peer.identity.fingerprint;
  local.trustState = "admitted";
}

// ── in-memory duplex sides (real 26D handshake, no socket) ─────────────────

interface Pipe {
  outbox: Buffer[];
  sink: FramedSink;
}

function makePipe(): Pipe {
  const pipe: Pipe = { outbox: [], sink: { write: () => false, destroy: () => undefined } };
  pipe.sink = {
    write: (chunk: Uint8Array) => {
      pipe.outbox.push(Buffer.from(chunk));
      return true;
    },
    destroy: () => undefined,
  };
  return pipe;
}

interface Side {
  node: NodeSim;
  pipe: Pipe;
  session: AuthenticatedSession;
}

function openSide(local: NodeSim, role: "initiator" | "responder", peer: NodeSim): Side {
  const pipe = makePipe();
  const result = openAuthenticatedSession(
    {
      transport: new FramedTransport(),
      sink: pipe.sink,
      role,
      local: { identity: local.identity, runtimeEpochId: local.epoch },
      expectedPeer: { nodeId: peer.identity.nodeId, runtimeEpochId: peer.epoch },
      probes: {
        localKey: () => local.record,
        peerKey: () => local.peerRecord,
        peerTrust: () => ({ state: local.trustState, fingerprint: local.trustFingerprint }),
      },
      replayGuard: replayGuardFor(local),
      challengeFactory: local.challengeFactory,
    },
    NOW
  );
  if (!result.ok) throw new Error(`open refused: ${result.code} — ${result.explanation}`);
  return { node: local, pipe, session: result.session };
}

const GUARDS = new WeakMap<object, SessionReplayGuard>();
function replayGuardFor(node: NodeSim): SessionReplayGuard {
  let guard = GUARDS.get(node);
  if (guard === undefined) {
    guard = new SessionReplayGuard();
    GUARDS.set(node, guard);
  }
  return guard;
}

function drain(from: Pipe, session: AuthenticatedSession, nowMs: number): void {
  for (const bytes of from.outbox.splice(0)) session.ingest(bytes, nowMs);
}

function handshake(a: Side, b: Side): void {
  const began = a.session.beginHandshake(NOW);
  if (!began.ok) throw new Error(`begin refused: ${began.code}`);
  drain(a.pipe, b.session, NOW + 1);
  drain(b.pipe, a.session, NOW + 2);
  drain(a.pipe, b.session, NOW + 3);
}

// ── the REAL 24D stack (durable store, coordinator, registry, bus) ──────────

let txnCounter = 0;
function txn(tag: string): string {
  txnCounter += 1;
  return tag + "-" + String(txnCounter).padStart(6, "0");
}

interface Federation {
  readonly bus: FederationBus;
  readonly registry: PeerRegistry;
  readonly port: IngressFederationPort;
  /** Close the durable stack so the port refuses (proves port_refused). */
  readonly breakStack: () => void;
}

function openFederation(peer: NodeSim): Federation {
  const open = DurableStore.open(newRoot());
  if (!open.ok) throw new Error(open.reason);
  const store = open.store;
  openStores.push(store);
  const epochId = makeRuntimeEpochId(NOW, "junction000001");
  const bound = RuntimeStateCoordinator.open(store, epochOf(epochId), "unit-test:26e");
  if (!bound.ok) throw new Error(bound.reason);
  const coordinator = bound.coordinator;
  openCoords.push(coordinator);
  const reg = PeerRegistry.open(store, coordinator);
  if (!reg.ok) throw new Error(reg.reason);
  const registry = reg.registry;

  const enroll = registry.applyTrustTransition({
    nodeId: peer.identity.nodeId,
    fingerprint: peer.identity.fingerprint,
    instanceId: peer.instanceId,
    protocolVersion: "menog-federation/v1",
    reason: "first_contact_enrolled",
    evidence: "26E ingress junction fixture",
    transactionId: txn("enroll"),
    lineageRoot: "26e-junction",
    lineageParent: null,
    nowEpochMs: NOW,
  });
  if (!enroll.ok) throw new Error(enroll.explanation);
  const admit = registry.applyTrustTransition({
    nodeId: peer.identity.nodeId,
    fingerprint: peer.identity.fingerprint,
    instanceId: peer.instanceId,
    protocolVersion: "menog-federation/v1",
    reason: "admission_request_accepted",
    evidence: "26E ingress junction fixture",
    transactionId: txn("admit"),
    lineageRoot: "26e-junction",
    lineageParent: null,
    nowEpochMs: NOW + 1,
  });
  if (!admit.ok) throw new Error(admit.explanation);

  const verifiers = new Map<string, ReturnType<typeof makeIdentitySignatureVerifier>>();
  verifiers.set(peer.identity.nodeId.slice(5), makeIdentitySignatureVerifier(peer.identity.publicKeyHex));
  const busOpen = FederationBus.open({ store, coordinator, peers: registry, verifiers });
  if (!busOpen.ok) throw new Error(busOpen.reason);

  const port: IngressFederationPort = {
    admit: ({ envelope, payload, nowEpochMs }): IngressPortResult => {
      const result = busOpen.bus.ingest({ envelope, payload, nowEpochMs });
      if (result.ok) {
        return {
          ok: true,
          messageId: result.messageId,
          senderNodeId: result.senderNodeId,
          receiptRecordId: result.receiptRecordId,
          commitSequence: result.commitSequence,
        };
      }
      return { ok: false, code: result.failureCode, explanation: result.explanation };
    },
  };
  return {
    bus: busOpen.bus,
    registry,
    port,
    breakStack: () => coordinator.close(),
  };
}

// ── the fixture: local node + remote peer + established session + real bus ──

interface Fixture {
  readonly local: NodeSim;
  readonly peer: NodeSim;
  readonly initiator: Side;
  readonly responder: Side;
  readonly federation: Federation;
  readonly transcriptHash: string;
  readonly payload: Record<string, unknown>;
  readonly envelope: FederationSignedMessage;
}

let messageCounter = 0;
function nextMessageId(): string {
  messageCounter += 1;
  return (
    "fm-" +
    (NOW % 0xffffffffffffffff).toString(16).padStart(16, "0") +
    "-" +
    ("j" + String(messageCounter).padStart(15, "0"))
  );
}

function bodyOf(peer: NodeSim, payload: Record<string, unknown>, overrides: Partial<FederationMessageBody> = {}): FederationMessageBody {
  return {
    schemaVersion: INGRESS_EXPECTED_MESSAGE_SCHEMA_VERSION,
    messageId: nextMessageId(),
    senderNodeId: peer.identity.nodeId,
    senderFingerprint: peer.identity.fingerprint,
    senderInstanceId: peer.instanceId,
    senderEpochId: peer.epoch,
    protocolVersion: INGRESS_FEDERATION_PROTOCOL,
    payloadHash: "sha256-" + canonicalHash(payload),
    declaredIntent: "evidence",
    correlationId: null,
    causationId: null,
    lineage: [],
    issuedAtEpochMs: NOW,
    ...overrides,
  };
}

function signedEnvelope(peer: NodeSim, message: FederationMessageBody): FederationSignedMessage {
  const signature = signFederationMessage(peer.identity, message);
  if (!signature.ok) throw new Error(`sign refused: ${signature.explanation}`);
  return { message, signature: signature.signature };
}

function buildFixture(): Fixture {
  const epochA = "re-000000000000-localnodeaaaaaaa";
  const epochB = "re-111111111111-remotenodebbbbbb";
  const local = makeNode("locl", epochA, 0x1000);
  const peer = makeNode("prmr", epochB, 0x2000);
  link(local, peer);
  link(peer, local);
  const initiator = openSide(local, "initiator", peer);
  const responder = openSide(peer, "responder", local);
  handshake(initiator, responder);
  const transcriptHash = initiator.session.transcriptHash();
  if (transcriptHash === null) throw new Error("handshake produced no transcript");
  const federation = openFederation(peer);
  const payload = { note: "ingress-note", sequence: 1 };
  return {
    local,
    peer,
    initiator,
    responder,
    federation,
    transcriptHash,
    payload,
    envelope: signedEnvelope(peer, bodyOf(peer, payload)),
  };
}

/** The default ingress input for a fixture (every stage honest). */
function ingressInput(
  f: Fixture,
  overrides: Partial<TransportIngressInput> = {},
): TransportIngressInput {
  const admission = (): IngressAdmissionFact => ({ state: f.local.trustState, fingerprint: f.local.trustFingerprint });
  const probes: IngressProbes = {
    localKey: () => f.local.record,
    peerKey: () => f.local.peerRecord,
    peerAdmission: admission,
  };
  return {
    frame: {
      declaredBytes: 1024,
      actualBytes: 1024,
      sequence: 1,
      expectedSequence: 1,
      previouslyDelivered: false,
      integrityOk: true,
      protocolVersion: INGRESS_EXPECTED_PROTOCOL_VERSION,
      disclosureFresh: true,
      halfClosedDirection: "none",
    },
    binding: {
      session: f.initiator.session,
      transcriptHash: f.transcriptHash,
      peerNodeId: f.peer.identity.nodeId,
      peerFingerprint: f.peer.identity.fingerprint,
      peerRuntimeEpochId: f.peer.epoch,
      peerPublicKeyHex: f.peer.identity.publicKeyHex,
    },
    envelope: f.envelope,
    payload: f.payload,
    probes,
    federation: f.federation.port,
    requiresDisclosure: false,
    nowEpochMs: NOW + 10,
    ...overrides,
  };
}

/** Assert a refusal and return it for further pinning. */
function expectRefusal(decision: TransportIngressDecision) {
  expect(decision.ok).toBe(false);
  if (decision.ok) throw new Error("unreachable");
  expect(decision.code.length).toBeGreaterThan(0);
  expect(decision.explanation.length).toBeGreaterThan(40);
  return decision;
}

// ── 1. vocabularies ──────────────────────────────────────────────────────────

describe("26E vocabularies: the mandatory order is closed and pinned", () => {
  it("the nine stages are exactly the pack order and nothing else", () => {
    expect(INGRESS_JUNCTION_SCHEMA_VERSION).toBe("menog-transport-ingress-junction/v0");
    expect([...INGRESS_STAGES]).toEqual([
      "frame_validity",
      "session_binding",
      "current_key_use",
      "local_admission",
      "disclosure_verification",
      "schema_version",
      "authentication",
      "replay_receipt",
      "untrusted_inbox",
    ]);
    expect(INGRESS_STAGES.length).toBe(9);
  });

  it("every stage declares which refusal codes it may emit", () => {
    expect(Object.keys(INGRESS_STAGE_CODES).sort()).toEqual([...INGRESS_STAGES].sort());
    for (const stage of INGRESS_STAGES) {
      expect(INGRESS_STAGE_CODES[stage].length).toBeGreaterThan(0);
      for (const code of INGRESS_STAGE_CODES[stage]) {
        expect([...INGRESS_REFUSAL_CODES]).toContain(code);
      }
    }
    // Every refusal code EXCEPT the universal caller-error code is reachable
    // from exactly one stage's vocabulary, so the failing stage is
    // unambiguous from the result alone.
    const flat = INGRESS_STAGES.flatMap((stage) => INGRESS_STAGE_CODES[stage]);
    for (const code of INGRESS_REFUSAL_CODES) {
      const owners = INGRESS_STAGES.filter((stage) => INGRESS_STAGE_CODES[stage].includes(code));
      if (code === "config_invalid") {
        expect(owners.length).toBe(INGRESS_STAGES.length);
      } else {
        expect(owners.length).toBe(1);
      }
      expect(flat.filter((entry) => entry === code).length).toBe(owners.length);
    }
  });

  it("the refusal vocabulary is closed with a full explanation table", () => {
    expect([...INGRESS_REFUSAL_CODES]).toEqual([
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
    ]);
    for (const code of INGRESS_REFUSAL_CODES) {
      expect(INGRESS_REFUSAL_EXPLANATIONS[code].length).toBeGreaterThan(30);
    }
  });

  it("each stage carries closed transport-trust pins", () => {
    expect(Object.keys(INGRESS_STAGE_PINS).sort()).toEqual([...INGRESS_STAGES].sort());
    for (const stage of INGRESS_STAGES) {
      expect(INGRESS_STAGE_PINS[stage].length).toBeGreaterThan(0);
    }
  });

  it("the authority-claim field set and capability containers are closed", () => {
    expect([...INGRESS_AUTHORITY_CLAIM_FIELDS]).toContain("policyDecision");
    expect([...INGRESS_AUTHORITY_CLAIM_FIELDS]).toContain("policyActorId");
    expect([...INGRESS_AUTHORITY_CLAIM_FIELDS]).toContain("assignment");
    expect([...INGRESS_AUTHORITY_CLAIM_FIELDS]).toContain("executionAuthorized");
    expect([...INGRESS_AUTHORITY_CLAIM_FIELDS]).toContain("executeTool");
    expect([...INGRESS_AUTHORITY_CLAIM_FIELDS]).toContain("toolInvocation");
    expect([...INGRESS_CAPABILITY_CLAIM_CONTAINERS]).toEqual([
      "requestedCapabilities",
      "claimedCapabilities",
      "requestedScopes",
      "claimedScopes",
      "requestedScope",
      "claimedScope",
    ]);
    expect(INGRESS_EXPECTED_PROTOCOL_VERSION).toBe("menog-auth-session/v1");
    expect(INGRESS_EXPECTED_MESSAGE_SCHEMA_VERSION).toBe("menog-federation-message/v0");
    expect(INGRESS_NEXT_GATE).toBe(
      "fresh_local_allocation_then_fresh_local_policy_for_the_assigned_actor_then_phase_20_21",
    );
  });
});

// ── 2. the happy path runs all nine stages ───────────────────────────────────

describe("26E the ONE junction admits a bound message as untrusted DATA", () => {
  it("runs every stage in order and returns an inbox entry that grants nothing", () => {
    const f = buildFixture();
    const decision = decideTransportIngress(ingressInput(f));
    expect(decision.ok).toBe(true);
    if (!decision.ok) throw new Error(decision.explanation);
    expect([...decision.stagesRun]).toEqual([...INGRESS_STAGES]);
    expect(decision.stage).toBe("untrusted_inbox");
    expect(decision.authority).toBe("none");
    expect(decision.executionAuthorized).toBe(false);
    expect(decision.nextGate).toBe(INGRESS_NEXT_GATE);
    expect(decision.transcriptHash).toBe(f.transcriptHash);
    expect(decision.inbox.authority).toBe("none");
    expect(decision.inbox.executionAuthorized).toBe(false);
    expect(decision.inbox.senderNodeId).toBe(f.peer.identity.nodeId);
    expect(decision.inbox.senderFingerprint).toBe(f.peer.identity.fingerprint);
    expect(decision.inbox.transcriptHash).toBe(f.transcriptHash);
    expect(decision.inbox.payloadHash).toBe("sha256-" + canonicalHash(f.payload));
    expect(decision.inbox.commitSequence).toBeGreaterThan(0);
    expect(decision.inbox.receiptRecordId.length).toBeGreaterThan(0);
    expect({ ...decision.inbox.payload }).toEqual(f.payload);
    expect(decision.explanation).toContain("UNTRUSTED DATA");
    expect(decision.explanation).toContain("grants NO authority");
  });

  it("the REAL 24D bus committed a receipt and exposed the payload in its inbox", () => {
    const f = buildFixture();
    decideTransportIngress(ingressInput(f));
    const inbox = f.federation.bus.inbox();
    expect(inbox.length).toBe(1);
    const entry = inbox[0];
    if (entry === undefined) throw new Error("no inbox entry");
    expect(entry.senderNodeId).toBe(f.peer.identity.nodeId);
    expect(entry.receiptRecordId.startsWith("frc-")).toBe(true);
  });

  it("the inbox entry is frozen so a caller cannot mutate it into authority", () => {
    const f = buildFixture();
    const decision = decideTransportIngress(ingressInput(f));
    if (!decision.ok) throw new Error(decision.explanation);
    expect(Object.isFrozen(decision.inbox)).toBe(true);
    expect(Object.isFrozen(decision.inbox.payload)).toBe(true);
    expect(decision.inbox.executionAuthorized).toBe(false as const);
  });

  it("two identical ingresses produce identical decisions (determinism)", () => {
    const f = buildFixture();
    const first = decideTransportIngress(ingressInput(f));
    expect(first.ok).toBe(true);
    if (!first.ok) throw new Error(first.explanation);
    // Second call with the same message id must refuse at replay, with an
    // identical explanation shape — determinism is on the refusal path too.
    const second = expectRefusal(decideTransportIngress(ingressInput(f)));
    expect(second.stage).toBe("replay_receipt");
    expect(second.code).toBe("replay_refused");
    expect(second.explanation).toContain("replay");
  });
});

// ── 3. the order is mandatory, not decorative ───────────────────────────────

describe("26E the mandatory order cannot be skipped, reordered, or bypassed", () => {
  it("stagesRun is always a literal prefix of the pinned order", () => {
    const f = buildFixture();
    const cases: TransportIngressInput[] = [
      ingressInput(f, { frame: { ...ingressInput(f).frame, integrityOk: false } }),
      ingressInput(f, { binding: { ...ingressInput(f).binding, transcriptHash: "0".repeat(64) } }),
      ingressInput(f, { probes: { ...ingressInput(f).probes, peerKey: () => null } }),
      ingressInput(f, { probes: { ...ingressInput(f).probes, peerAdmission: () => ({ state: "unknown", fingerprint: "" }) } }),
      ingressInput(f, { requiresDisclosure: true }),
      ingressInput(f, { nowEpochMs: Number.NaN }),
    ];
    for (const input of cases) {
      const decision = decideTransportIngress(input);
      expect(decision.ok).toBe(false);
      const run = [...decision.stagesRun];
      expect(run).toEqual([...INGRESS_STAGES].slice(0, run.length));
    }
  });

  it("a multi-violation message refuses at the EARLIEST stage and runs no later stage", () => {
    const f = buildFixture();
    let portCalled = false;
    const input = ingressInput(f, {
      // Frame is broken AND the key is revoked AND the peer is quarantined:
      // the frame must win, and the port must never be reached.
      frame: { ...ingressInput(f).frame, actualBytes: 1 },
      probes: {
        localKey: () => transition(f.local.record, "revoked"),
        peerKey: () => transition(f.local.peerRecord ?? f.peer.record, "revoked"),
        peerAdmission: () => ({ state: "quarantined", fingerprint: f.local.trustFingerprint }),
      },
      federation: {
        admit: () => {
          portCalled = true;
          return { ok: false, code: "should_never_happen", explanation: "unreachable" };
        },
      },
    });
    const decision = expectRefusal(decideTransportIngress(input));
    expect(decision.stage).toBe("frame_validity");
    expect(decision.code).toBe("frame_refused");
    expect(decision.stagesRun).toEqual(["frame_validity"]);
    expect(portCalled).toBe(false);
  });

  it("frame beats session beats key-use beats admission: precedence is pinned", () => {
    const f = buildFixture();
    // Session not bound + revoked key + quarantined peer.
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, {
          binding: { ...ingressInput(f).binding, transcriptHash: "0".repeat(64) },
          probes: {
            localKey: () => transition(f.local.record, "revoked"),
            peerKey: () => transition(f.local.peerRecord ?? f.peer.record, "revoked"),
            peerAdmission: () => ({ state: "quarantined", fingerprint: f.local.trustFingerprint }),
          },
        }),
      ),
    );
    expect(decision.stage).toBe("session_binding");
    expect(decision.code).toBe("session_not_bound");

    // Revoked key + quarantined peer: key-use wins (stage 3 before stage 4).
    const next = expectRefusal(
      decideTransportIngress(
        ingressInput(f, {
          probes: {
            localKey: () => transition(f.local.record, "revoked"),
            peerKey: () => f.local.peerRecord,
            peerAdmission: () => ({ state: "quarantined", fingerprint: f.local.trustFingerprint }),
          },
        }),
      ),
    );
    expect(next.stage).toBe("current_key_use");
    expect(next.code).toBe("key_use_refused");

    // Only the peer is quarantined: admission is reached.
    const last = expectRefusal(
      decideTransportIngress(
        ingressInput(f, {
          probes: {
            ...ingressInput(f).probes,
            peerAdmission: () => ({ state: "quarantined", fingerprint: f.local.trustFingerprint }),
          },
        }),
      ),
    );
    expect(last.stage).toBe("local_admission");
    expect(last.code).toBe("peer_not_admitted");
  });

  it("every refusal names its stage position and a transport-trust pin", () => {
    const f = buildFixture();
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, {
          probes: { ...ingressInput(f).probes, peerKey: () => null },
        }),
      ),
    );
    expect(decision.explanation).toContain("stage 3/9 current_key_use");
    expect(decision.pins).toEqual([...INGRESS_STAGE_PINS.current_key_use]);
    expect(decision.upstreamCode).toBe("unknown_record");
  });
});

// ── 4. pack-named attacks ───────────────────────────────────────────────────

describe("26E peer admission attacks (stage 4: CURRENT local admission)", () => {
  for (const state of ["unknown", "candidate", "quarantined", "retired"] as const) {
    it("a " + state + " peer never reaches the federation", () => {
      const f = buildFixture();
      const decision = expectRefusal(
        decideTransportIngress(
          ingressInput(f, {
            probes: {
              ...ingressInput(f).probes,
              peerAdmission: () => ({ state, fingerprint: f.local.trustFingerprint }),
            },
          }),
        ),
      );
      expect(decision.stage).toBe("local_admission");
      expect(decision.code).toBe("peer_not_admitted");
      expect(decision.upstreamCode).toBe(state);
      expect(decision.explanation).toContain("reachability and identity are not admission");
    });
  }

  it("an unknown trust state string refuses rather than riding through", () => {
    const f = buildFixture();
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, {
          probes: {
            ...ingressInput(f).probes,
            peerAdmission: () => ({ state: "trusted" as NodeTrustState, fingerprint: f.local.trustFingerprint }),
          },
        }),
      ),
    );
    expect(decision.code).toBe("peer_not_admitted");
    expect(decision.upstreamCode).toBe("unknown_trust_state");
  });

  it("admission revoked MID-SESSION closes ingress on the very next message", () => {
    const f = buildFixture();
    expect(decideTransportIngress(ingressInput(f)).ok).toBe(true);
    // The operator quarantines the peer while the session is still open.
    f.local.trustState = "quarantined";
    const second = signedEnvelope(f.peer, bodyOf(f.peer, f.payload));
    const decision = expectRefusal(
      decideTransportIngress(ingressInput(f, { envelope: second })),
    );
    expect(decision.stage).toBe("local_admission");
    expect(decision.code).toBe("peer_not_admitted");
    expect(decision.stagesRun).toEqual([...INGRESS_STAGES].slice(0, 4));
  });

  it("a re-identified peer inherits NO trust until re-admitted (fingerprint check)", () => {
    const f = buildFixture();
    expect(decideTransportIngress(ingressInput(f)).ok).toBe(true);
    const oldFingerprint = f.local.trustFingerprint;

    // The peer re-identifies (24B rotation) and opens a NEW authenticated
    // session carrying the FRESH identity. Everything about that session is
    // honest — the only thing missing is LOCAL re-admission.
    const fresh = rotateLocalIdentity(f.peer.identity).fresh;
    const newPeer: NodeSim = {
      ...f.peer,
      identity: fresh,
      record: makeRecord(fresh, "gate-26e-reidentity"),
      peerRecord: f.local.record,
      trustFingerprint: f.local.identity.fingerprint,
    };
    const newLocal: NodeSim = {
      ...f.local,
      peerRecord: newPeer.record,
      trustFingerprint: fresh.fingerprint,
    };
    const initiator = openSide(newLocal, "initiator", newPeer);
    const responder = openSide(newPeer, "responder", newLocal);
    handshake(initiator, responder);
    // LOCAL admission still names the PRE-rotation fingerprint.
    newLocal.trustFingerprint = oldFingerprint;
    expect(fresh.fingerprint).not.toBe(oldFingerprint);

    const payload = { note: "re-identified", sequence: 7 };
    const decision = expectRefusal(
      decideTransportIngress({
        frame: ingressInput(f).frame,
        binding: {
          session: initiator.session,
          transcriptHash: initiator.session.transcriptHash() ?? "",
          peerNodeId: fresh.nodeId,
          peerFingerprint: fresh.fingerprint,
          peerRuntimeEpochId: newPeer.epoch,
          peerPublicKeyHex: fresh.publicKeyHex,
        },
        envelope: signedEnvelope(newPeer, bodyOf(newPeer, payload)),
        payload,
        probes: {
          localKey: () => newLocal.record,
          peerKey: () => newLocal.peerRecord,
          peerAdmission: () => ({ state: newLocal.trustState, fingerprint: newLocal.trustFingerprint }),
        },
        federation: f.federation.port,
        requiresDisclosure: false,
        nowEpochMs: NOW + 20,
      }),
    );
    expect(decision.stage).toBe("local_admission");
    expect(decision.code).toBe("peer_not_admitted");
    expect(decision.upstreamCode).toBe("fingerprint_not_admitted");
    expect(decision.explanation).toContain("inherits NO trust");
  });
});

describe("26E key-state attacks (stage 3: CURRENT key use)", () => {
  it("a ROTATED peer key refuses with the frozen 25B code", () => {
    const f = buildFixture();
    // 25B rotation is request-then-execute with the FRESH identity's facts;
    // the resulting record is ROTATED and keeps the OLD public facts, so the
    // session-bound (old) claims match the record and the state check fires.
    const requested = transition(f.peer.record, "rotation_requested");
    const rotated = transition(requested, "rotated", rotateLocalIdentity(f.peer.identity).fresh);
    expect(rotated.state).toBe("rotated");
    expect(rotated.fingerprint).toBe(f.peer.identity.fingerprint);
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, { probes: { ...ingressInput(f).probes, peerKey: () => rotated } }),
      ),
    );
    expect(decision.stage).toBe("current_key_use");
    expect(decision.code).toBe("key_use_refused");
    expect(decision.upstreamCode).toBe("stale_rotated_key");
    expect(decision.explanation).toContain("even though its crypto still verifies");
  });

  for (const [state, code] of [
    ["revoked", "state_revoked"],
    ["retired", "state_retired"],
  ] as const) {
    it("a " + state + " peer key refuses with the frozen 25B code", () => {
      const f = buildFixture();
      const decision = expectRefusal(
        decideTransportIngress(
          ingressInput(f, {
            probes: {
              ...ingressInput(f).probes,
              peerKey: () => transition(f.peer.record, state),
            },
          }),
        ),
      );
      expect(decision.upstreamCode).toBe(code);
    });
  }

  it("the LOCAL key being revoked refuses ingress too", () => {
    const f = buildFixture();
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, {
          probes: { ...ingressInput(f).probes, localKey: () => transition(f.local.record, "revoked") },
        }),
      ),
    );
    expect(decision.stage).toBe("current_key_use");
    expect(decision.upstreamCode).toBe("state_revoked");
    expect(decision.explanation).toContain("local key");
  });

  it("a key-id that does not re-derive refuses (key substitution)", () => {
    const f = buildFixture();
    const foreign = makeNode("forg", f.peer.epoch, 0x3000);
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, {
          binding: { ...ingressInput(f).binding, peerPublicKeyHex: foreign.identity.publicKeyHex },
        }),
      ),
    );
    expect(decision.code).toBe("key_use_refused");
    expect(decision.upstreamCode).toBe("key_id_mismatch");
    expect(deriveKeyId(foreign.identity.publicKeyHex)).not.toBe(deriveKeyId(f.peer.identity.publicKeyHex));
  });
});

describe("26E epoch attacks (stage 2: session binding)", () => {
  it("a stale sender epoch refuses", () => {
    const f = buildFixture();
    const stale = "re-222222222222-staleepochcccc";
    const envelope = signedEnvelope(f.peer, bodyOf(f.peer, f.payload, { senderEpochId: stale }));
    const decision = expectRefusal(decideTransportIngress(ingressInput(f, { envelope })));
    expect(decision.stage).toBe("session_binding");
    expect(decision.code).toBe("epoch_stale");
    expect(decision.explanation).toContain("stale or substituted runtime epoch");
  });

  it("a message from a different node than the bound peer refuses", () => {
    const f = buildFixture();
    const stranger = makeNode("strn", f.peer.epoch, 0x4000);
    const envelope = signedEnvelope(stranger, bodyOf(stranger, f.payload));
    const decision = expectRefusal(decideTransportIngress(ingressInput(f, { envelope })));
    expect(decision.code).toBe("session_not_bound");
    expect(decision.explanation).toContain("does not match the peer this session authenticated");
  });

  it("cross-session transcript splicing refuses", () => {
    const f = buildFixture();
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, { binding: { ...ingressInput(f).binding, transcriptHash: "a".repeat(64) } }),
      ),
    );
    expect(decision.code).toBe("session_not_bound");
    expect(decision.explanation).toContain("cross-session splicing refuses");
  });

  it("a session that is not established carries no federation traffic", () => {
    const f = buildFixture();
    f.initiator.session.close();
    const decision = expectRefusal(decideTransportIngress(ingressInput(f)));
    expect(decision.stage).toBe("session_binding");
    expect(decision.code).toBe("session_not_bound");
    expect(decision.explanation).toContain("closed");
  });
});

describe("26E disclosure attacks (stage 5: 25D verification where required)", () => {
  function manifestFor(payload: Record<string, unknown>): DisclosureManifest {
    const payloadHash = "sha256-" + canonicalHash(payload);
    const decision = decideEgress({
      candidate: {
        schemaVersion: "menog-egress-disclosure/v0",
        payloadHash,
        fields: [
          { key: "messageId", egressClass: "protocol_metadata", value: "j-unit-test" },
          { key: "payloadHash", egressClass: "content_hashes", value: payloadHash },
        ],
      },
      outgoingPayloadHash: payloadHash,
      nowEpochMs: NOW,
    });
    if (!decision.ok) throw new Error(`egress refused: ${decision.denyCode}`);
    return decision.manifest;
  }

  it("a valid manifest bound to the signed payload hash verifies", () => {
    const f = buildFixture();
    const manifest = manifestFor(f.payload);
    expect(manifest.payloadHash).toBe("sha256-" + canonicalHash(f.payload));
    const decision = decideTransportIngress(
      ingressInput(f, { disclosure: manifest, requiresDisclosure: true }),
    );
    expect(decision.ok).toBe(true);
  });

  it("a STALE disclosure (bound to a different payload) refuses", () => {
    const f = buildFixture();
    const staleManifest = manifestFor({ note: "different-payload", sequence: 2 });
    expect(staleManifest.payloadHash).not.toBe("sha256-" + canonicalHash(f.payload));
    const decision = expectRefusal(
      decideTransportIngress(ingressInput(f, { disclosure: staleManifest, requiresDisclosure: true })),
    );
    expect(decision.stage).toBe("disclosure_verification");
    expect(decision.code).toBe("disclosure_refused");
    expect(decision.upstreamCode).toBe("stale_disclosure");
  });

  it("a payload that REQUIRES disclosure but has no manifest refuses", () => {
    const f = buildFixture();
    const decision = expectRefusal(
      decideTransportIngress(ingressInput(f, { requiresDisclosure: true })),
    );
    expect(decision.stage).toBe("disclosure_verification");
    expect(decision.code).toBe("disclosure_required");
  });

  it("a presented manifest is verified even when the caller did not require one", () => {
    const f = buildFixture();
    const staleManifest = manifestFor({ note: "sneaked-in" });
    const decision = expectRefusal(
      decideTransportIngress(ingressInput(f, { disclosure: staleManifest })),
    );
    expect(decision.code).toBe("disclosure_refused");
  });

  it("a malformed manifest refuses", () => {
    const f = buildFixture();
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, {
          disclosure: { payloadHash: "not-a-hash" } as unknown as DisclosureManifest,
        }),
      ),
    );
    expect(decision.code).toBe("disclosure_refused");
    expect(decision.upstreamCode).toBe("malformed_candidate");
  });
});

describe("26E authority-claim attacks (stage 6: no fabricated LOCAL authority)", () => {
  for (const field of INGRESS_AUTHORITY_CLAIM_FIELDS) {
    it("a payload claiming '" + field + "' refuses before authentication", () => {
      const f = buildFixture();
      const payload = { note: "authority-claim", [field]: "smuggled" };
      const envelope = signedEnvelope(f.peer, bodyOf(f.peer, payload));
      const decision = expectRefusal(decideTransportIngress(ingressInput(f, { envelope, payload })));
      expect(decision.stage).toBe("schema_version");
      expect(decision.code).toBe("authority_claim_refused");
      expect(decision.upstreamCode).toBe("claim_field:" + field);
      expect(decision.pins).toContain("REMOTE_MESSAGE_NOT_LOCAL_POLICY");
      expect(decision.stagesRun).toEqual([...INGRESS_STAGES].slice(0, 6));
    });
  }

  it("an actor-mismatch ride (a Policy minted for another actor) cannot arrive at all", () => {
    const f = buildFixture();
    const payload = {
      note: "ride",
      policyActorId: "agent-attacker",
      policy: { outcome: "allow", decidedAtEpochMs: NOW },
      assignment: { assignmentId: "as-1", assignedAgentId: "agent-victim", allocatedAtEpochMs: NOW },
    };
    const envelope = signedEnvelope(f.peer, bodyOf(f.peer, payload));
    const decision = expectRefusal(decideTransportIngress(ingressInput(f, { envelope, payload })));
    // The first authority-claim field encountered decides — whichever it is,
    // the message is refused and never reaches authentication or the receipt.
    expect(decision.code).toBe("authority_claim_refused");
    expect(decision.upstreamCode?.startsWith("claim_field:")).toBe(true);
    expect(decision.explanation).toContain("unreachable from the wire");
  });

  it("a stale LOCAL Policy decision offered by a peer refuses", () => {
    const f = buildFixture();
    const payload = { note: "stale-policy", policyDecision: { outcome: "allow", decidedAtEpochMs: NOW - 9_999_999 } };
    const envelope = signedEnvelope(f.peer, bodyOf(f.peer, payload));
    const decision = expectRefusal(decideTransportIngress(ingressInput(f, { envelope, payload })));
    expect(decision.code).toBe("authority_claim_refused");
    expect(decision.upstreamCode).toBe("claim_field:policyDecision");
  });

  it("capability inflation refuses naming the violated 26A pin", () => {
    const f = buildFixture();
    const payload = { note: "inflate", requestedCapabilities: ["grant_authority", "execute_tool"] };
    const envelope = signedEnvelope(f.peer, bodyOf(f.peer, payload));
    const decision = expectRefusal(decideTransportIngress(ingressInput(f, { envelope, payload })));
    expect(decision.stage).toBe("schema_version");
    expect(decision.code).toBe("scope_violation");
    expect(decision.upstreamCode).toBe("capability:grant_authority");
    expect(decision.pins).toEqual(["ADMISSION_NOT_AUTHORITY"]);
    expect(decision.explanation).toContain("capability inflation refuses");
  });

  it("an unnamed capability refuses with a null pin rather than riding through", () => {
    const f = buildFixture();
    const payload = { note: "unnamed", requestedScope: "do_something_useful" };
    const envelope = signedEnvelope(f.peer, bodyOf(f.peer, payload));
    const decision = expectRefusal(decideTransportIngress(ingressInput(f, { envelope, payload })));
    expect(decision.code).toBe("scope_violation");
    expect(decision.pins).toEqual(["ADMISSION_NOT_AUTHORITY"]);
    expect(decision.explanation).toContain("cannot ride through");
    // The 26A scope gate agrees, with a null pin.
    expect(decideTransportScope({ capability: "do_something_useful" }).ok).toBe(false);
  });

  it("an in-scope capability request is NOT a refusal by itself", () => {
    const f = buildFixture();
    const payload = { note: "legit", requestedCapabilities: ["record_network_evidence"] };
    const envelope = signedEnvelope(f.peer, bodyOf(f.peer, payload));
    const decision = decideTransportIngress(ingressInput(f, { envelope, payload }));
    expect(decision.ok).toBe(true);
  });

  it("a direct-exec request names no escape: executeTool is an authority-claim field", () => {
    const f = buildFixture();
    const payload = { note: "exec", executeTool: { name: "shell", args: ["rm"] } };
    const envelope = signedEnvelope(f.peer, bodyOf(f.peer, payload));
    const decision = expectRefusal(decideTransportIngress(ingressInput(f, { envelope, payload })));
    expect(decision.code).toBe("authority_claim_refused");
    expect(decision.explanation).toContain("a tool invocation");
  });

  it("a malformed capability container refuses rather than defaulting", () => {
    const f = buildFixture();
    const payload = { note: "malformed", requestedCapabilities: [{ nested: true }] };
    const envelope = signedEnvelope(f.peer, bodyOf(f.peer, payload));
    const decision = expectRefusal(decideTransportIngress(ingressInput(f, { envelope, payload })));
    expect(decision.code).toBe("schema_refused");
    expect(decision.upstreamCode).toBe("capability_container_malformed:requestedCapabilities");
  });
});

// ── 5. schema, tamper, authentication, replay, port ────────────────────────

describe("26E schema and tamper attacks (stage 6)", () => {
  it("an unknown body field refuses (the frozen shape is closed)", () => {
    const f = buildFixture();
    const body = { ...bodyOf(f.peer, f.payload), extraField: "surprise" } as FederationMessageBody;
    const decision = expectRefusal(
      decideTransportIngress(ingressInput(f, { envelope: signedEnvelope(f.peer, body) })),
    );
    expect(decision.code).toBe("schema_refused");
    expect(decision.upstreamCode).toBe("body_shape_mismatch");
  });

  it("a dropped body field refuses too", () => {
    const f = buildFixture();
    const body = { ...bodyOf(f.peer, f.payload) } as Record<string, unknown>;
    delete body["lineage"];
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, { envelope: signedEnvelope(f.peer, body as unknown as FederationMessageBody) }),
      ),
    );
    expect(decision.upstreamCode).toBe("body_shape_mismatch");
  });

  it("a schema-version downgrade refuses", () => {
    const f = buildFixture();
    const body = { ...bodyOf(f.peer, f.payload), schemaVersion: "menog-federation-message/v1" };
    const decision = expectRefusal(
      decideTransportIngress(ingressInput(f, { envelope: signedEnvelope(f.peer, body as FederationMessageBody) })),
    );
    expect(decision.code).toBe("schema_refused");
    expect(decision.upstreamCode).toBe("schema_version_mismatch");
    expect(decision.explanation).toContain("no negotiation path");
  });

  it("the TRANSPORT protocol on the body is a downgrade (it is not the federation protocol)", () => {
    const f = buildFixture();
    const body = { ...bodyOf(f.peer, f.payload), protocolVersion: INGRESS_EXPECTED_PROTOCOL_VERSION };
    const decision = expectRefusal(
      decideTransportIngress(ingressInput(f, { envelope: signedEnvelope(f.peer, body as unknown as FederationMessageBody) })),
    );
    expect(decision.upstreamCode).toBe("protocol_version_mismatch");
  });

  it("an unknown declared intent refuses", () => {
    const f = buildFixture();
    const body = { ...bodyOf(f.peer, f.payload), declaredIntent: "run_shell" };
    const decision = expectRefusal(
      decideTransportIngress(ingressInput(f, { envelope: signedEnvelope(f.peer, body as FederationMessageBody) })),
    );
    expect(decision.upstreamCode).toBe("unknown_declared_intent");
  });

  it("TAMPERED payload bytes refuse before authentication is attempted", () => {
    const f = buildFixture();
    const envelope = f.envelope; // signed over payload {note: ingress-note, sequence: 1}
    const tampered = { ...f.payload, sequence: 999 };
    const decision = expectRefusal(decideTransportIngress(ingressInput(f, { envelope, payload: tampered })));
    expect(decision.stage).toBe("schema_version");
    expect(decision.code).toBe("schema_refused");
    expect(decision.upstreamCode).toBe("payload_hash_mismatch");
    expect(decision.stagesRun).toEqual([...INGRESS_STAGES].slice(0, 6));
  });
});

describe("26E authentication attacks (stage 7: 24B over the frozen body)", () => {
  it("a signature from a different key refuses", () => {
    const f = buildFixture();
    const imposter = makeNode("impo", f.peer.epoch, 0x5000);
    const body = bodyOf(f.peer, f.payload);
    const signature = signFederationMessage(imposter.identity, body);
    if (!signature.ok) throw new Error(signature.explanation);
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, { envelope: { message: body, signature: signature.signature } }),
      ),
    );
    expect(decision.stage).toBe("authentication");
    expect(decision.code).toBe("authentication_refused");
  });

  it("fingerprint substitution (claiming a different fingerprint) refuses", () => {
    const f = buildFixture();
    const foreign = makeNode("swpt", f.peer.epoch, 0x6000);
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, {
          binding: { ...ingressInput(f).binding, peerFingerprint: foreign.identity.fingerprint },
        }),
      ),
    );
    // The bound fingerprint IS the session's peer fact, so a substituted
    // claim cannot even reach the key-use gate: stage 2 refuses first.
    expect(decision.stage).toBe("session_binding");
    expect(decision.code).toBe("session_not_bound");
  });

  it("a public-key swap under an unchanged fingerprint refuses at the key-use gate", () => {
    const f = buildFixture();
    const foreign = makeNode("swap", f.peer.epoch, 0x6500);
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, {
          binding: { ...ingressInput(f).binding, peerPublicKeyHex: foreign.identity.publicKeyHex },
        }),
      ),
    );
    expect(decision.stage).toBe("current_key_use");
    expect(decision.code).toBe("key_use_refused");
    expect(decision.upstreamCode).toBe("key_id_mismatch");
  });

  it("a garbage signature refuses", () => {
    const f = buildFixture();
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, { envelope: { message: f.envelope.message, signature: "AAAA" } }),
      ),
    );
    expect(decision.stage).toBe("authentication");
    expect(decision.code).toBe("authentication_refused");
  });
});

describe("26E replay and port attacks (stages 8–9)", () => {
  it("a replayed message id refuses at the durable 24D receipt", () => {
    const f = buildFixture();
    const first = decideTransportIngress(ingressInput(f));
    expect(first.ok).toBe(true);
    const replay = expectRefusal(decideTransportIngress(ingressInput(f)));
    expect(replay.stage).toBe("replay_receipt");
    expect(replay.code).toBe("replay_refused");
    expect(replay.upstreamCode).toBe("replay_detected");
    expect(replay.stagesRun).toEqual([...INGRESS_STAGES].slice(0, 8));
    // The durable bus holds exactly ONE receipt for the message.
    expect(f.federation.bus.inbox().length).toBe(1);
  });

  it("a port refusal is carried verbatim as port_refused", () => {
    const f = buildFixture();
    f.federation.breakStack();
    const decision = expectRefusal(decideTransportIngress(ingressInput(f)));
    expect(decision.stage).toBe("replay_receipt");
    expect(decision.code).toBe("port_refused");
    expect(decision.upstreamCode).toBe("bus_closed");
  });

  it("a port that admits a DIFFERENT message refuses", () => {
    const f = buildFixture();
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, {
          federation: {
            admit: () => ({
              ok: true,
              messageId: "fm-0000000000000000-zzzzzzzzzzzzzzz",
              senderNodeId: f.peer.identity.nodeId,
              receiptRecordId: "frc-something",
              commitSequence: 1,
            }),
          },
        }),
      ),
    );
    expect(decision.code).toBe("port_refused");
    expect(decision.upstreamCode).toBe("port_result_mismatch");
  });

  it("a port that returns no decision refuses (a missing receipt is a refusal)", () => {
    const f = buildFixture();
    const decision = expectRefusal(
      decideTransportIngress(
        ingressInput(f, { federation: { admit: () => undefined as unknown as IngressPortResult } }),
      ),
    );
    expect(decision.code).toBe("port_refused");
    expect(decision.upstreamCode).toBe("port_result_malformed");
  });

  it("a malformed frame clock refuses at stage 1 before anything else", () => {
    const f = buildFixture();
    const decision = expectRefusal(decideTransportIngress(ingressInput(f, { nowEpochMs: Number.NaN })));
    expect(decision.stage).toBe("frame_validity");
    expect(decision.code).toBe("config_invalid");
  });

  for (const [label, frame] of [
    ["oversize", { actualBytes: 99_999 }],
    ["truncated", { actualBytes: 1023 }],
    ["tampered", { integrityOk: false }],
    ["reordered", { sequence: 7 }],
    ["duplicate", { previouslyDelivered: true }],
    ["downgrade", { protocolVersion: "menog-auth-session/v0" }],
    ["stale disclosure", { disclosureFresh: false }],
  ] as const) {
    it("a " + label + " frame refuses at stage 1", () => {
      const f = buildFixture();
      const decision = expectRefusal(
        decideTransportIngress(ingressInput(f, { frame: { ...ingressInput(f).frame, ...frame } })),
      );
      expect(decision.stage).toBe("frame_validity");
      expect(decision.code).toBe("frame_refused");
      expect(decision.upstreamCode).not.toBeNull();
    });
  }
});

// ── 6. structural pins ───────────────────────────────────────────────────────

describe("26E structural scan: the junction keeps to its sanctioned surface", () => {
  it("imports exactly the sanctioned frozen modules", () => {
    const raw = SRC("transportIngressJunction.ts");
    const imports = [...raw.matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1]);
    expect(imports).toEqual([
      "./canonical.js",
      "./federationTransportTrust.js",
      "./federationCrypto.js",
      "./federationKeyLifecycle.js",
      "./federationIdentity.js",
      "./continuity.js",
      "./federationEgress.js",
      "./authenticatedSession.js",
    ]);
  });

  it("exports exactly ONE decision entry point", () => {
    const raw = SRC("transportIngressJunction.ts");
    const functions = [...raw.matchAll(/export function\s+(\w+)/g)].map((match) => match[1]);
    expect(functions).toEqual(["decideTransportIngress"]);
  });

  it("holds no store, no listener, no dialer, no shell, no clock and no tool surface", () => {
    const code = codeOnly(SRC("transportIngressJunction.ts"));
    const forbidden = [
      "child_process", "spawn", "process.env", "node:dns", "node:http", "node:net", "node:tls",
      "node:http2", "createServer", ".listen(", "fetch(", "axios", "XMLHttpRequest", "WebSocket",
      "createConnection", "connect(", "request(", ".pipe(", "setTimeout", "setInterval",
      "Date.now", "Math.random", "eval(", "require(", ".persist(", "root =", "acceptMutation",
      "./store.js", "./coordinator.js", "./federationBus.js", "./records.js", "./persist.js",
      "./federationProposals.js", "./statePersistence.js",
      "openAuthenticatedSession(", "FramedTransport", "requireFreshLocalAuthorization",
      "deriveLocalTaskCandidate", "ProposalLedger", "PeerRegistry", "DurableStore",
      "RuntimeStateCoordinator", "phase20", "phase21",
    ];
    for (const token of forbidden) {
      expect(code, token).not.toContain(token);
    }
  });

  it("names no execution or allocation surface of its own", () => {
    const raw = SRC("transportIngressJunction.ts");
    // The ONLY occurrences of execution vocabulary are the closed refusal
    // field names and the structural statements — never a call.
    expect(raw).not.toMatch(/execute[A-Za-z]*\(/);
    expect(codeOnly(raw)).not.toContain("spawn");
  });
});

// ── 7. real loopback: the junction over live local transport ────────────────

const PORT_INGRESS = 41890;

function listenOn(server: Server, port: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ port, host: "127.0.0.1" }, () => resolve());
  });
}

function connectTo(port: number): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    const socket = connect({ port, host: "127.0.0.1" }, () => resolve(socket));
    socket.once("error", reject);
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe("26E real loopback sockets: ingress over live local transport", () => {
  it("a signed envelope carried over a real 127.0.0.1 socket is admitted through all nine stages", async () => {
    // `receiver` is the LOCAL node in this direction: it runs the responder
    // and performs ingress. `sender` is the remote node on the wire.
    const sender = makeNode("sndr", "re-000000000000-looplocalaaaaaaa", 0x7000);
    const receiver = makeNode("rcvr", "re-111111111111-looppeerbbbbbbbb", 0x8000);
    link(receiver, sender);
    link(sender, receiver);
    // The registry admits the SENDER: that is the node whose messages ingress accepts.
    const federation = openFederation(sender);
    const payload = { note: "live-wire", sequence: 42 };
    const envelope = signedEnvelope(sender, bodyOf(sender, payload));
    const wire = Buffer.from(JSON.stringify(envelope), "utf8");

    const sockets: Socket[] = [];
    const server = createServer((sock) => {
      sockets.push(sock);
      sock.on("error", () => undefined);
    });
    await listenOn(server, PORT_INGRESS);
    const clientSock = await connectTo(PORT_INGRESS);
    clientSock.on("error", () => undefined);
    for (let attempt = 0; sockets.length === 0 && attempt < 400; attempt += 1) await sleep(5);
    const serverSock = sockets[0];
    if (serverSock === undefined) throw new Error("server socket never arrived");

    // REAL 26C frame bytes over a REAL socket. The 26D session owns its own
    // framing, so raw wire bytes go straight into ingest().
    const toServer: Buffer[] = [];
    const toClient: Buffer[] = [];
    serverSock.on("data", (chunk: Buffer) => { toServer.push(Buffer.from(chunk)); });
    clientSock.on("data", (chunk: Buffer) => { toClient.push(Buffer.from(chunk)); });

    const serverSink: FramedSink = {
      write: (chunk: Uint8Array) => { serverSock.write(Buffer.from(chunk)); return true; },
      destroy: () => serverSock.destroy(),
    };
    const clientSink: FramedSink = {
      write: (chunk: Uint8Array) => { clientSock.write(Buffer.from(chunk)); return true; },
      destroy: () => clientSock.destroy(),
    };

    const responder = openAuthenticatedSession(
      {
        transport: new FramedTransport(),
        sink: serverSink,
        role: "responder",
        local: { identity: receiver.identity, runtimeEpochId: receiver.epoch },
        expectedPeer: { nodeId: sender.identity.nodeId, runtimeEpochId: sender.epoch },
        probes: {
          localKey: () => receiver.record,
          peerKey: () => receiver.peerRecord,
          peerTrust: () => ({ state: receiver.trustState, fingerprint: receiver.trustFingerprint }),
        },
        replayGuard: new SessionReplayGuard(),
      },
      NOW,
    );
    const initiator = openAuthenticatedSession(
      {
        transport: new FramedTransport(),
        sink: clientSink,
        role: "initiator",
        local: { identity: sender.identity, runtimeEpochId: sender.epoch },
        expectedPeer: { nodeId: receiver.identity.nodeId, runtimeEpochId: receiver.epoch },
        probes: {
          localKey: () => sender.record,
          peerKey: () => sender.peerRecord,
          peerTrust: () => ({ state: sender.trustState, fingerprint: sender.trustFingerprint }),
        },
        replayGuard: new SessionReplayGuard(),
      },
      NOW,
    );
    if (!responder.ok || !initiator.ok) throw new Error("session open refused on the live wire");
    const responderSession = responder.session;
    const initiatorSession = initiator.session;

    /** Pump real socket bytes into the real 26D sessions. */
    const delivered: Uint8Array[] = [];
    const pump = async (): Promise<void> => {
      for (const chunk of toServer.splice(0)) {
        const result = responderSession.ingest(new Uint8Array(chunk), NOW);
        if (result.ok) delivered.push(...result.delivered);
      }
      for (const chunk of toClient.splice(0)) initiatorSession.ingest(new Uint8Array(chunk), NOW);
      await sleep(2);
    };

    initiatorSession.beginHandshake(NOW);
    for (let attempt = 0; responderSession.state() !== "established" && attempt < 400; attempt += 1) await pump();
    expect(responderSession.state()).toBe("established");
    expect(initiatorSession.state()).toBe("established");
    const transcriptHash = responderSession.transcriptHash();
    expect(transcriptHash).not.toBeNull();

    // The signed envelope travels as one 26C data frame over the real socket.
    const sent = initiatorSession.send(new Uint8Array(wire), NOW);
    expect(sent.ok).toBe(true);
    for (let attempt = 0; delivered.length === 0 && attempt < 400; attempt += 1) await pump();
    expect(delivered.length).toBeGreaterThan(0);
    const firstPayload = delivered[0];
    if (firstPayload === undefined) throw new Error("no payload delivered");

    const received = JSON.parse(Buffer.from(firstPayload).toString("utf8")) as FederationSignedMessage;
    expect(received.message.messageId).toBe(envelope.message.messageId);

    const decision = decideTransportIngress({
      frame: {
        declaredBytes: wire.length,
        actualBytes: wire.length,
        sequence: 1,
        expectedSequence: 1,
        previouslyDelivered: false,
        integrityOk: true,
        protocolVersion: INGRESS_EXPECTED_PROTOCOL_VERSION,
        disclosureFresh: true,
        halfClosedDirection: "none",
      },
      binding: {
        session: responderSession,
        transcriptHash: transcriptHash ?? "",
        peerNodeId: sender.identity.nodeId,
        peerFingerprint: sender.identity.fingerprint,
        peerRuntimeEpochId: sender.epoch,
        peerPublicKeyHex: sender.identity.publicKeyHex,
      },
      envelope: received,
      payload,
      probes: {
        localKey: () => receiver.record,
        peerKey: () => receiver.peerRecord,
        peerAdmission: () => ({
          state: receiver.trustState,
          fingerprint: receiver.trustFingerprint,
        }),
      },
      federation: federation.port,
      requiresDisclosure: false,
      nowEpochMs: NOW + 30,
    });
    expect(decision.ok).toBe(true);
    if (!decision.ok) throw new Error(decision.explanation);
    expect([...decision.stagesRun]).toEqual([...INGRESS_STAGES]);
    expect(decision.inbox.authority).toBe("none");
    expect(decision.inbox.executionAuthorized).toBe(false);
    expect(decision.inbox.transcriptHash).toBe(transcriptHash);
    // The REAL 24D bus committed a receipt for the wire message.
    expect(federation.bus.inbox().length).toBe(1);

    clientSock.destroy();
    for (const sock of sockets) sock.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }, 20_000);
});
