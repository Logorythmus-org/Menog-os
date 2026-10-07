/**
 * PHASE 24D — Authenticated Bounded Federation Message Bus Tests
 * (IN-PROCESS FIXTURE ONLY / NO LAN·INTERNET·DISCOVERY / FAIL CLOSED).
 *
 * Pack-mandated negative tests (each one refuses at its pipeline stage):
 *   tamper · unknown/quarantined peer · replay · stale epoch · oversize ·
 *   schema/downgrade · lineage/evidence tamper · restart
 * Plus structural pins: receipts carry the pack binding fields and NEVER
 * invoke a tool/process; payload stays untrusted DATA; the bus holds zero
 * network/execution surface; persistence only through the 23B junction.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DurableStore,
  RuntimeStateCoordinator,
  PeerRegistry,
  FederationBus,
  generateLocalSigningIdentity,
  signFederationMessage,
  makeIdentitySignatureVerifier,
  FEDERATION_MAX_ENVELOPE_BYTES,
  FEDERATION_MAX_BATCH,
  FEDERATION_BUS_FAILURE_CODES,
  makeFederationMessageId,
  makeRuntimeEpochId,
  type RuntimeEpoch,
  type FederationMessageBody,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

// ── fixtures ─────────────────────────────────────────────────────────────────

const NOW = 1_700_000_000_000;

const roots: string[] = [];
const openStores: DurableStore[] = [];
const openCoords: RuntimeStateCoordinator[] = [];
function newRoot(): string {
  const r = mkdtempSync(join(tmpdir(), "menog-24d-"));
  roots.push(r);
  return r;
}
afterEach(() => {
  for (const c of openCoords) {
    try { c.close(); } catch { /* already closed */ }
  }
  for (const s of openStores) {
    try { if (s.isOpen) s.close(); } catch { /* windows handles */ }
  }
  openCoords.length = 0;
  openStores.length = 0;
  for (const r of roots) {
    try { rmSync(r, { recursive: true, force: true }); } catch { /* windows handles */ }
  }
  roots.length = 0;
});

const EPOCH_1 = makeRuntimeEpochId(NOW, "epoch0000000001");
const EPOCH_2 = makeRuntimeEpochId(NOW + 1_000, "epoch0000000002");

function epochOf(id: string): RuntimeEpoch {
  return Object.freeze({
    schemaVersion: "menog-runtime-epoch/v0",
    epochId: id,
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

/** Hex-tail NodeId factory (canonical node-<64hex> form). */
function nodeIdOf(tag: string): string {
  const hex = Buffer.from(tag.padEnd(16, "0"), "utf8").toString("hex").padEnd(64, "0").slice(0, 64);
  return "node-" + hex;
}
const NODE_A = nodeIdOf("peer-alpha");

interface Harness {
  readonly store: DurableStore;
  readonly coordinator: RuntimeStateCoordinator;
  readonly registry: PeerRegistry;
  readonly bus: FederationBus;
}

let txnCounter = 0;
function txn(tag: string): string {
  txnCounter += 1;
  return tag + "-" + String(txnCounter).padStart(6, "0");
}

const ROOT = "bus-root-24d";

/** Open a full stack and admit ONE peer (A) with real 24B keys. */
function openWithAdmittedPeer(epochId: string = EPOCH_1): Harness & { readonly sign: (m: FederationMessageBody) => string; readonly msg: (overrides?: Partial<FederationMessageBody>) => FederationMessageBody } {
  const open = DurableStore.open(newRoot());
  if (!open.ok) throw new Error(open.reason);
  const store = open.store;
  openStores.push(store);
  const bound = RuntimeStateCoordinator.open(store, epochOf(epochId), "unit-test:24d");
  if (!bound.ok) throw new Error(bound.reason);
  const coordinator = bound.coordinator;
  openCoords.push(coordinator);
  const reg = PeerRegistry.open(store, coordinator);
  if (!reg.ok) throw new Error(reg.reason);
  const registry = reg.registry;

  const identity = generateLocalSigningIdentity();
  const keyTail = identity.nodeId.slice(5);
  const enroll = registry.applyTrustTransition({
    nodeId: identity.nodeId, fingerprint: identity.fingerprint, instanceId: "ri-000000e8fa00-instanceaaaa",
    protocolVersion: "menog-federation/v1", reason: "first_contact_enrolled",
    evidence: "identity doc hash", transactionId: txn("enroll"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: NOW,
  });
  if (!enroll.ok) throw new Error(enroll.explanation);
  const admit = registry.applyTrustTransition({
    nodeId: identity.nodeId, fingerprint: identity.fingerprint, instanceId: "ri-000000e8fa00-instanceaaaa",
    protocolVersion: "menog-federation/v1", reason: "admission_request_accepted",
    evidence: "admission provenance", transactionId: txn("admit"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: NOW + 1,
  });
  if (!admit.ok) throw new Error(admit.explanation);

  const verifiers = new Map<string, ReturnType<typeof makeIdentitySignatureVerifier>>();
  verifiers.set(keyTail, makeIdentitySignatureVerifier(identity.publicKeyHex));
  const busOpen = FederationBus.open({ store, coordinator, peers: registry, verifiers });
  if (!busOpen.ok) throw new Error(busOpen.reason);
  const bus = busOpen.bus;

  let n = 0;
  const msg = (overrides: Partial<FederationMessageBody> = {}): FederationMessageBody => {
    n += 1;
    return {
      schemaVersion: "menog-federation-message/v0",
      messageId: makeFederationMessageId(NOW + n, "bus" + String(n).padStart(13, "0")),
      senderNodeId: identity.nodeId,
      senderFingerprint: identity.fingerprint,
      senderInstanceId: "ri-000000e8fa00-instanceaaaa",
      senderEpochId: makeRuntimeEpochId(NOW, "senderepoch00001"),
      protocolVersion: "menog-federation/v1",
      payloadHash: "sha256-" + "5".repeat(64),
      declaredIntent: "evidence",
      correlationId: null,
      causationId: null,
      lineage: [],
      issuedAtEpochMs: NOW,
      ...overrides,
    };
  };
  const sign = (m: FederationMessageBody): string => {
    const s = signFederationMessage(identity, m);
    if (!s.ok) throw new Error(s.explanation);
    return s.signature;
  };
  void NODE_A;
  return { store, coordinator, registry, bus, sign, msg };
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("24D structure — bounds, single path, no execution surface", () => {
  it("bounds and failure vocabulary are pinned exactly", () => {
    expect(FEDERATION_MAX_ENVELOPE_BYTES).toBe(8192);
    expect(FEDERATION_MAX_BATCH).toBe(32);
    expect([...FEDERATION_BUS_FAILURE_CODES]).toContain("peer_not_admitted");
    expect([...FEDERATION_BUS_FAILURE_CODES]).toContain("replay_detected");
    expect([...FEDERATION_BUS_FAILURE_CODES]).toContain("receipt_persistence_denied");
  });

  it("the bus performs no direct store.persist, no network I/O, and no tool invocation", () => {
    const code = codeOnly(SRC("federationBus.ts"));
    expect(code).not.toContain(".persist(");
    expect(code).toContain("acceptMutation");
    expect(code).toContain('kind: "federation_receipt"');
    for (const forbidden of ["fetch(", "node:net", "node:http", "node:https", "child_process", "spawn(", "listen(", "executeToolRun", "runIsolated"]) {
      expect(code).not.toContain(forbidden);
    }
  });

  it("a receipt body binds the pack fields and no receipt ever authorizes execution", () => {
    const src = SRC("federationBus.ts");
    for (const field of ["senderFingerprint", "senderEpochId", "messageId", "payloadHash", "protocolVersion", "receiverDecision", "receiverEpochId"]) {
      expect(src).toContain("readonly " + field);
    }
    const code = codeOnly(src);
    expect(code).not.toMatch(/receiverDecision:\s*"(?!message_admitted)/);
  });
});

// ── positive path ────────────────────────────────────────────────────────────

describe("24D pipeline — the happy path receipts and delivers", () => {
  it("an admitted peer's signed message traverses every stage: receipt + typed inbox", () => {
    const h = openWithAdmittedPeer();
    const m = h.msg();
    const result = h.bus.ingest({ envelope: { message: m, signature: h.sign(m) }, payload: { note: "untrusted" }, nowEpochMs: NOW + 5 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.receiptRecordId).toContain("frc-");
    expect(result.explanation).toContain("UNTRUSTED DATA");
    const inbox = h.bus.inbox();
    expect(inbox).toHaveLength(1);
    expect(inbox[0]?.messageId).toBe(m.messageId);
    expect(inbox[0]?.payload).toEqual({ note: "untrusted" });
    // the receipt is durable and binds the decision
    const receipt = h.store.readRecord(result.receiptRecordId);
    expect(receipt.ok).toBe(true);
    if (receipt.ok) {
      const body = receipt.record.payload as Record<string, unknown>;
      expect(body["receiverDecision"]).toBe("message_admitted");
      expect(body["receiverEpochId"]).toBe(EPOCH_1);
      expect(body["senderFingerprint"]).toBe(m.senderFingerprint);
      expect(body["payloadHash"]).toBe(m.payloadHash);
    }
  });

  it("an oversized INBOX payload still leaves the receipt durable but exposes nothing", () => {
    const h = openWithAdmittedPeer();
    const m = h.msg();
    const bigPayload = { blob: "x".repeat(70_000) };
    const result = h.bus.ingest({ envelope: { message: m, signature: h.sign(m) }, payload: bigPayload, nowEpochMs: NOW + 5 });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.stage).toBe("receipt");
    expect(result.failureCode).toBe("oversize_envelope");
    expect(h.bus.inbox()).toHaveLength(0);
    const receipt = h.store.readRecord("frc-" + m.messageId);
    expect(receipt.ok).toBe(true); // the decision was bound; exposure was refused
  });
});

// ── pack negative tests ──────────────────────────────────────────────────────

describe("24D negative tests — every stage refuses", () => {
  it("TAMPER: a modified body refuses at the signature stage", () => {
    const h = openWithAdmittedPeer();
    const m = h.msg();
    const sig = h.sign(m);
    const tampered = { ...m, payloadHash: "sha256-" + "f".repeat(64) };
    const result = h.bus.ingest({ envelope: { message: tampered, signature: sig }, nowEpochMs: NOW + 5 });
    expect(result).toMatchObject({ ok: false, stage: "signature", failureCode: "signature_stage_refused" });
    expect(h.bus.inbox()).toHaveLength(0);
  });

  it("UNKNOWN PEER: a sender absent from the durable registry refuses before any signature evaluation", () => {
    const h = openWithAdmittedPeer();
    const stranger = generateLocalSigningIdentity();
    const m: FederationMessageBody = {
      ...h.msg(),
      senderNodeId: stranger.nodeId,
      senderFingerprint: stranger.fingerprint,
    };
    const s = signFederationMessage(stranger, m);
    if (!s.ok) throw new Error(s.explanation);
    const verifiers = new Map<string, ReturnType<typeof makeIdentitySignatureVerifier>>();
    verifiers.set(stranger.nodeId.slice(5), makeIdentitySignatureVerifier(stranger.publicKeyHex));
    // register the key so the refusal is provably the ADMISSION stage
    const busOpen2 = FederationBus.open({ store: h.store, coordinator: h.coordinator, peers: h.registry, verifiers });
    if (!busOpen2.ok) throw new Error(busOpen2.reason);
    const result = busOpen2.bus.ingest({ envelope: { message: m, signature: s.signature }, nowEpochMs: NOW + 5 });
    expect(result).toMatchObject({ ok: false, stage: "peer_admission", failureCode: "peer_not_admitted" });
  });

  it("QUARANTINED PEER: an admitted-then-quarantined sender refuses with no signature oracle", () => {
    const h = openWithAdmittedPeer();
    const q = h.registry.applyTrustTransition({
      nodeId: h.msg().senderNodeId, fingerprint: (h.msg() as FederationMessageBody).senderFingerprint,
      instanceId: "ri-000000e8fa00-instanceaaaa", protocolVersion: "menog-federation/v1",
      reason: "peer_misbehavior_evidenced", evidence: "adversarial finding",
      transactionId: txn("quarantine"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: NOW + 2,
    });
    expect(q.ok).toBe(true);
    const m = h.msg();
    const result = h.bus.ingest({ envelope: { message: m, signature: h.sign(m) }, nowEpochMs: NOW + 5 });
    expect(result).toMatchObject({ ok: false, stage: "peer_admission", failureCode: "peer_not_admitted" });
    expect(result.ok === false && result.explanation).toContain("quarantined");
  });

  it("REPLAY: the same message id refuses on second delivery — in-process AND after restart", () => {
    const h = openWithAdmittedPeer();
    const m = h.msg();
    const first = h.bus.ingest({ envelope: { message: m, signature: h.sign(m) }, nowEpochMs: NOW + 5 });
    expect(first.ok).toBe(true);
    const replay = h.bus.ingest({ envelope: { message: m, signature: h.sign(m) }, nowEpochMs: NOW + 6 });
    expect(replay).toMatchObject({ ok: false, stage: "replay_freshness", failureCode: "replay_detected" });
    // RESTART: close the epoch, reopen under a NEW epoch/registry/bus.
    h.coordinator.close();
    const bound = RuntimeStateCoordinator.open(h.store, epochOf(EPOCH_2), "unit-test:24d-e2");
    if (!bound.ok) throw new Error(bound.reason);
    openCoords.push(bound.coordinator);
    const reg = PeerRegistry.open(h.store, bound.coordinator);
    if (!reg.ok) throw new Error(reg.reason);
    const busOpen = FederationBus.open({ store: h.store, coordinator: bound.coordinator, peers: reg.registry, verifiers: new Map() });
    if (!busOpen.ok) throw new Error(busOpen.reason);
    const after = busOpen.bus.ingest({ envelope: { message: m, signature: h.sign(m) }, nowEpochMs: NOW + 7 });
    expect(after).toMatchObject({ ok: false, stage: "replay_freshness", failureCode: "replay_detected" });
    if (!after.ok) expect(after.explanation).toContain("durable receipt already exists");
  });

  it("OVERSIZE: an envelope beyond the pinned byte bound refuses at shape", () => {
    const h = openWithAdmittedPeer();
    const m = h.msg({ payloadHash: "sha256-" + "5".repeat(64), lineage: Array.from({ length: 16 }, (_, i) => makeFederationMessageId(NOW + 100 + i, "pad" + String(i).padStart(13, "0"))) });
    // pad the body through extra lineage depth is bounded; use a huge payloadHash instead
    const huge = { ...m, payloadHash: "sha256-" + "5".repeat(64) + "x".repeat(FEDERATION_MAX_ENVELOPE_BYTES) } as unknown as FederationMessageBody;
    const result = h.bus.ingest({ envelope: { message: huge, signature: h.sign(m) }, nowEpochMs: NOW + 5 });
    expect(result).toMatchObject({ ok: false, stage: "envelope_shape", failureCode: "oversize_envelope" });
  });

  it("SCHEMA/DOWNGRADE: wrong message schema version and older protocol both refuse", () => {
    const h = openWithAdmittedPeer();
    const badSchema = h.msg({ schemaVersion: "menog-federation-message/v9" as FederationMessageBody["schemaVersion"] });
    expect(h.bus.ingest({ envelope: { message: badSchema, signature: h.sign(badSchema) }, nowEpochMs: NOW + 5 })).toMatchObject({
      ok: false,
    });
    const downgrade = h.msg({ protocolVersion: "menog-federation/v0" as FederationMessageBody["protocolVersion"] });
    const result = h.bus.ingest({ envelope: { message: downgrade, signature: h.sign(downgrade) }, nowEpochMs: NOW + 5 });
    expect(result).toMatchObject({ ok: false, stage: "protocol_schema", failureCode: "protocol_mismatch" });
  });

  it("LINEAGE TAMPER: dangling causation refuses; a well-formed lineage still delivers", () => {
    const h = openWithAdmittedPeer();
    const forged = h.msg({ lineage: [], causationId: makeFederationMessageId(NOW + 999, "forged000000001") });
    expect(h.bus.ingest({ envelope: { message: forged, signature: h.sign(forged) }, nowEpochMs: NOW + 5 })).toMatchObject({
      ok: false,
      failureCode: "lineage_malformed",
    });
    const parent = makeFederationMessageId(NOW + 50, "parent000000001");
    const ok = h.msg({ lineage: [parent], causationId: parent });
    const result = h.bus.ingest({ envelope: { message: ok, signature: h.sign(ok) }, nowEpochMs: NOW + 5 });
    expect(result.ok).toBe(true);
  });

  it("STALE EPOCH: the sender's older epoch refuses after its newer one was observed", () => {
    const h = openWithAdmittedPeer();
    const newer = h.msg({ senderEpochId: makeRuntimeEpochId(NOW + 10, "senderepoch00002") });
    expect(h.bus.ingest({ envelope: { message: newer, signature: h.sign(newer) }, nowEpochMs: NOW + 5 })).toMatchObject({ ok: true });
    const older = h.msg({ senderEpochId: makeRuntimeEpochId(NOW, "senderepoch00001") });
    const result = h.bus.ingest({ envelope: { message: older, signature: h.sign(older) }, nowEpochMs: NOW + 6 });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(["stale_epoch", "replay_freshness", "malformed_envelope"]).toContain(result.failureCode);
    }
  });

  it("EVIDENCE TAMPER: a receipt row cannot be rewritten through the junction (append-only + hash binding)", () => {
    const h = openWithAdmittedPeer();
    const m = h.msg();
    const first = h.bus.ingest({ envelope: { message: m, signature: h.sign(m) }, nowEpochMs: NOW + 5 });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const receipt = h.store.readRecord(first.receiptRecordId);
    if (!receipt.ok) throw new Error("fixture");
    const forgedPayload = { ...(receipt.record.payload as Record<string, unknown>), receiverDecision: "execution_granted" };
    const resealed = Object.freeze({ ...receipt.record, payload: Object.freeze(forgedPayload) });
    const attempt = h.store.persist(resealed);
    // append-only kind → the store refuses any revision of it; even if a
    // hostile caller resealed the hash, recovery re-verifies (22E).
    expect(attempt.ok).toBe(false);
  });

  it("bounded batch: oversized batches refuse whole; each message inside a batch is judged independently", () => {
    const h = openWithAdmittedPeer();
    const many = Array.from({ length: FEDERATION_MAX_BATCH + 1 }, () => ({ message: h.msg(), signature: "AAAA" }));
    const refused = h.bus.ingestBatch({ envelopes: many.map((e) => e), nowEpochMs: NOW + 5 });
    expect(refused).toHaveLength(1);
    expect(refused[0]).toMatchObject({ ok: false, failureCode: "oversize_envelope" });
    const m1 = h.msg();
    const m2 = h.msg();
    const mixed = h.bus.ingestBatch({
      envelopes: [
        { message: m1, signature: h.sign(m1) },
        { message: m2, signature: h.sign(m1) }, // wrong signature (tamper-like)
      ],
      nowEpochMs: NOW + 5,
    });
    expect(mixed[0]?.ok).toBe(true);
    expect(mixed[1]).toMatchObject({ ok: false, stage: "signature" });
  });
});
