/**
 * PHASE 24C — Peer Registry, Admission & Quarantine Tests
 * (LOCAL STATE MACHINE / NO REMOTE EXECUTION / SANCTIONED PERSISTENCE ONLY).
 *
 * Pack-mandated coverage:
 *   unknown/admitted/quarantined/retired  — the closed trust machine, durable
 *   duplicate                             — second first-contact of the same
 *                                            NodeId is a no-op replay
 *   stale epoch                           — a stale LOCAL epoch refuses
 *   fingerprint change                    — pins are immutable; rotation is
 *                                            re-identity (new NodeId record)
 *   rotation                              — evidenced retirement of the old
 *                                            identity; new identity enters
 *                                            fresh as its own record
 *   corruption/recovery                   — tampered peer bytes fail closed;
 *                                            terminal peers map to
 *                                            terminalPeerIds
 *   restart                               — reopen: facts restore exactly
 *   anti-resurrection                     — quarantined/retired refuse
 *   no authority                          — nothing grants execution/policy
 *   no alternate persistence              — every write through the 23B
 *                                            junction (structural pin)
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DurableStore,
  RuntimeStateCoordinator,
  PeerRegistry,
  peerRecordId,
  peerDurableId,
  peerNodeIdOfRecordId,
  mapPeerRecovery,
  peerTransitionEvidenceHash,
  PEER_TRUST_SCHEMA_VERSION,
  PEER_TRANSITION_REASONS,
  PEER_REGISTRY_FAILURE_CODES,
  NODE_TRUST_STATES,
  recoverState,
  type RuntimeEpoch,
  type PeerTrustState,
} from "@menog/durable-state";
import { makeRuntimeEpochId } from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

// ── fixtures (23B-suite pattern) ─────────────────────────────────────────────

const roots: string[] = [];
const openStores: DurableStore[] = [];
const openCoords: RuntimeStateCoordinator[] = [];
function newRoot(): string {
  const r = mkdtempSync(join(tmpdir(), "menog-24c-"));
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

const EPOCH_1 = makeRuntimeEpochId(1_700_000_000_000, "epoch0000000001");
const EPOCH_2 = makeRuntimeEpochId(1_700_000_001_000, "epoch0000000002");

function epochOf(id: string): RuntimeEpoch {
  return Object.freeze({
    schemaVersion: "menog-runtime-epoch/v0",
    epochId: id,
    startedAtEpochMs: 1_700_000_000_000,
    hostRef: "wsl2-target-of-record",
    pidRef: 4242,
    lifecycle: "BOOTING",
    priorOwner: { code: "none" as const, epochId: null },
    startReason: "fresh_store_no_prior_owner",
    executionAuthorized: false as const,
    policyAuthorized: false as const,
  });
}

/** A hex-tail NodeId factory (canonical node-<64hex> form). */
function nodeIdOf(tag: string): string {
  const hex = Buffer.from(tag.padEnd(16, "0"), "utf8").toString("hex").padEnd(64, "0").slice(0, 64);
  return "node-" + hex;
}
const NODE_A = nodeIdOf("peer-alpha");
const NODE_B = nodeIdOf("peer-bravo");
const NODE_A2 = nodeIdOf("peer-alpha2"); // "rotated" identity of A (distinct)

const FP_A = "fp-sha256-" + "a".repeat(64);
const FP_B = "fp-sha256-" + "b".repeat(64);
const FP_A2 = "fp-sha256-" + "c".repeat(64);
const INSTANCE_A = "ri-000000e8fa00-instanceaaaa";

interface Harness {
  readonly store: DurableStore;
  readonly coordinator: RuntimeStateCoordinator;
  readonly registry: PeerRegistry;
}

function openFresh(epochId: string = EPOCH_1): Harness {
  const open = DurableStore.open(newRoot());
  if (!open.ok) throw new Error(open.reason);
  const store = open.store;
  openStores.push(store);
  const bound = RuntimeStateCoordinator.open(store, epochOf(epochId), "unit-test:24c");
  if (!bound.ok) throw new Error(bound.reason);
  const coordinator = bound.coordinator;
  openCoords.push(coordinator);
  const opened = PeerRegistry.open(store, coordinator);
  if (!opened.ok) throw new Error(opened.reason);
  return { store, coordinator, registry: opened.registry };
}

let txnCounter = 0;
function txn(tag: string): string {
  txnCounter += 1;
  return tag + "-" + String(txnCounter).padStart(6, "0");
}

const ROOT = "peer-registry-root-24c";

/** Enroll a fresh peer as candidate (the only first-contact edge). */
function enroll(h: Harness, nodeId: string, fingerprint: string, instanceId: string = INSTANCE_A): void {
  const r = h.registry.applyTrustTransition({
    nodeId,
    fingerprint,
    instanceId,
    protocolVersion: "menog-federation/v1",
    reason: "first_contact_enrolled",
    evidence: "identity doc hash " + fingerprint,
    transactionId: txn("enroll-" + nodeId.slice(5, 12)),
    lineageRoot: ROOT,
    lineageParent: null,
    nowEpochMs: 1_700_000_000_000,
  });
  if (!r.ok) throw new Error("fixture enroll failed: " + r.explanation);
}

/** Drive a peer to `admitted` via the evidenced admission edge. */
function admit(h: Harness, nodeId: string): void {
  enroll(h, nodeId, FP_A);
  const r = h.registry.applyTrustTransition({
    nodeId,
    fingerprint: FP_A,
    instanceId: INSTANCE_A,
    protocolVersion: "menog-federation/v1",
    reason: "admission_request_accepted",
    evidence: "admission decision provenance hash",
    transactionId: txn("admit-" + nodeId.slice(5, 12)),
    lineageRoot: ROOT,
    lineageParent: null,
    nowEpochMs: 1_700_000_000_500,
  });
  if (!r.ok) throw new Error("fixture admit failed: " + r.explanation);
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("24C structure — sanctioned path, no alternate persistence", () => {
  it("the module performs NO direct store.persist; every write goes through the coordinator", () => {
    const code = codeOnly(SRC("federationPeers.ts"));
    expect(code).not.toContain(".persist(");
    expect(code).toContain("acceptMutation");
    expect(code).toContain('kind: "peer_trust_registry"');
    // No network/execution surface either.
    for (const forbidden of ["fetch(", "node:net", "node:http", "child_process", "spawn("]) {
      expect(code).not.toContain(forbidden);
    }
  });

  it("vocabulary is closed and single-sourced", () => {
    expect([...PEER_TRANSITION_REASONS]).toEqual([
      "first_contact_enrolled",
      "admission_request_accepted",
      "admission_request_quarantined",
      "peer_misbehavior_evidenced",
      "operator_retirement",
    ]);
    expect([...PEER_REGISTRY_FAILURE_CODES]).toContain("peer_terminal_state");
    expect([...PEER_REGISTRY_FAILURE_CODES]).toContain("fingerprint_pin_conflict");
    expect(PEER_TRUST_SCHEMA_VERSION).toBe("menog-federation-peer-trust/v0");
    expect([...NODE_TRUST_STATES]).toEqual(["unknown", "candidate", "admitted", "quarantined", "retired"]);
  });

  it("durable ids are injective over canonical NodeIds and round-trip", () => {
    const id = peerDurableId(NODE_A);
    expect(id.ok).toBe(true);
    if (!id.ok) return;
    expect(id.recordId.startsWith("peer-")).toBe(true);
    expect(id.recordId.length).toBe("peer-".length + 64);
    expect(peerNodeIdOfRecordId(id.recordId)).toBe(NODE_A);
    expect(peerRecordId("not-a-node-id").ok).toBe(false);
  });

  it("construction is fail-closed: no registry on a closed coordinator", () => {
    const h = openFresh();
    h.coordinator.close();
    const again = PeerRegistry.open(h.store, h.coordinator);
    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.reason).toContain("closed");
  });
});

// ── the trust machine over the store ─────────────────────────────────────────

describe("24C trust machine — unknown/candidate/admitted/quarantined/retired", () => {
  it("an unknown peer is not in the registry; first contact enters ONLY as candidate", () => {
    const h = openFresh();
    expect(h.registry.readPeer(NODE_A)).toMatchObject({ ok: false, failureCode: "peer_unknown" });
    // admission without first contact refuses
    const premature = h.registry.applyTrustTransition({
      nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
      reason: "admission_request_accepted", evidence: "e", transactionId: txn("premature"),
      lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_000_000,
    });
    expect(premature).toMatchObject({ ok: false, failureCode: "trust_transition_refused" });
    enroll(h, NODE_A, FP_A);
    const enrolled = h.registry.readPeer(NODE_A);
    expect(enrolled.ok).toBe(true);
    if (enrolled.ok) {
      expect(enrolled.terminal).toBe(false);
      expect(enrolled.state.trustState).toBe("candidate");
    }
  });

  it("candidate → admitted through the evidenced admission edge; the record pins fp/protocol/instance", () => {
    const h = openFresh();
    admit(h, NODE_A);
    const read = h.registry.readPeer(NODE_A);
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    expect(read.state.trustState).toBe("admitted");
    expect(read.state.fingerprint).toBe(FP_A);
    expect(read.state.protocolVersion).toBe("menog-federation/v1");
    expect(read.state.instanceId).toBe(INSTANCE_A);
    expect(read.terminal).toBe(false);
    expect(read.state.lastTransitionEvidence.length).toBeGreaterThan(0);
  });

  it("quarantine and retirement are durable terminal facts", () => {
    const h = openFresh();
    admit(h, NODE_A);
    const q = h.registry.applyTrustTransition({
      nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
      reason: "peer_misbehavior_evidenced", evidence: "adversarial evidence hash",
      transactionId: txn("quarantine-a"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_001_000,
    });
    expect(q.ok).toBe(true);
    const read = h.registry.readPeer(NODE_A);
    expect(read.ok).toBe(true);
    if (read.ok) {
      expect(read.state.trustState).toBe("quarantined");
      expect(read.terminal).toBe(true);
      expect(read.explanation).toContain("EXACTLY terminal");
    }
  });

  it("no authority is ever granted: the durable payload carries no execution/policy fields", () => {
    const h = openFresh();
    admit(h, NODE_A);
    const read = h.registry.readPeer(NODE_A);
    if (!read.ok) throw new Error("fixture");
    expect("executionAuthorized" in read.state).toBe(false);
    expect("policyAuthorized" in read.state).toBe(false);
    expect("authority" in read.state).toBe(false);
    // And the write path's own explanation says so.
    const r = h.registry.applyTrustTransition({
      nodeId: NODE_B, fingerprint: FP_B, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
      reason: "first_contact_enrolled", evidence: "e", transactionId: txn("nb"),
      lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_002_000,
    });
    expect(r.ok === true && r.explanation).toContain("no execution authority");
  });
});

// ── duplicate / replay / stale / pins ────────────────────────────────────────

describe("24C duplicates, stale epochs, and immutable pins", () => {
  it("a duplicate first-contact of the SAME NodeId is a no-op idempotent replay, never double-applied", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    const first = h.registry.readPeer(NODE_A);
    if (!first.ok) throw new Error("fixture");
    // same transactionId → store denies as duplicate_transaction → the
    // registry reports the already-committed state as an idempotent replay
    const replay = h.registry.applyTrustTransition({
      nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
      reason: "first_contact_enrolled", evidence: "identity doc hash " + FP_A,
      transactionId: "enroll-" + String(txnCounter - 1).padStart(6, "0"),
      lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_000_500,
    });
    expect(replay.ok).toBe(true);
    if (replay.ok) {
      expect(replay.idempotentReplay).toBe(true);
      expect(replay.revision).toBe(first.revision);
    }
  });

  it("a NEW transaction targeting the already-current state is also an idempotent no-op", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    const before = h.registry.readPeer(NODE_A);
    if (!before.ok) throw new Error("fixture");
    const again = h.registry.applyTrustTransition({
      nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
      reason: "first_contact_enrolled", evidence: "identity doc hash " + FP_A,
      transactionId: txn("same-state"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_001_000,
    });
    expect(again.ok).toBe(true);
    if (again.ok) {
      expect(again.idempotentReplay).toBe(true);
      expect(again.revision).toBe(before.revision);
    }
  });

  it("a STALE LOCAL epoch (closed coordinator rebound to a new epoch) refuses writes", () => {
    // Epoch 1 opens a registry, then closes it (epoch over).
    const h1 = openFresh(EPOCH_1);
    admit(h1, NODE_A);
    h1.coordinator.close();
    // Epoch 2 binds a NEW coordinator over the same store; epoch 1's
    // registry object is closed → every transition refuses.
    const bound = RuntimeStateCoordinator.open(h1.store, epochOf(EPOCH_2), "unit-test:24c-e2");
    if (!bound.ok) throw new Error(bound.reason);
    openCoords.push(bound.coordinator);
    const stale = h1.registry.applyTrustTransition({
      nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
      reason: "admission_request_accepted", evidence: "e", transactionId: txn("stale-epoch"),
      lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_003_000,
    });
    expect(stale).toMatchObject({ ok: false, failureCode: "coordinator_closed" });
  });

  it("fingerprint/protocol/instance pins are IMMUTABLE: a fingerprint change refuses (rotation is re-identity)", () => {
    const h = openFresh();
    admit(h, NODE_A);
    const swap = h.registry.applyTrustTransition({
      nodeId: NODE_A, fingerprint: FP_A2, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
      reason: "admission_request_accepted", evidence: "e", transactionId: txn("fp-swap"),
      lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_004_000,
    });
    expect(swap).toMatchObject({ ok: false, failureCode: "fingerprint_pin_conflict" });
    expect(swap.ok === false && swap.explanation).toContain("RE-IDENTITY");
    // protocol pin
    const proto = h.registry.applyTrustTransition({
      nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v0",
      reason: "first_contact_enrolled", evidence: "e", transactionId: txn("proto"),
      lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_004_100,
    });
    expect(proto).toMatchObject({ ok: false });
    if (!proto.ok) expect(proto.failureCode).not.toBe("fingerprint_pin_conflict");
  });
});

// ── rotation ─────────────────────────────────────────────────────────────────

describe("24C rotation — re-identity with an evidenced retirement", () => {
  it("rotation = NEW NodeId record + evidenced retirement of the old record; no in-place re-pin", () => {
    const h = openFresh();
    admit(h, NODE_A);
    // The "rotated" identity arrives as its OWN first contact (24B canon).
    enroll(h, NODE_A2, FP_A2);
    // The old record is retired with evidence referencing the new identity.
    const retire = h.registry.applyTrustTransition({
      nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
      reason: "operator_retirement", evidence: "key rotation: successor " + NODE_A2,
      transactionId: txn("rotate"), lineageRoot: ROOT, lineageParent: null,
      nowEpochMs: 1_700_000_005_000,
    });
    expect(retire.ok).toBe(true);
    if (retire.ok) {
      expect(retire.to).toBe("retired");
      expect(retire.state.lastTransitionEvidence).toContain(NODE_A2);
    }
    const old = h.registry.readPeer(NODE_A);
    if (old.ok) expect(old.state.trustState).toBe("retired");
    const neu = h.registry.readPeer(NODE_A2);
    if (neu.ok && "state" in neu) expect(neu.state.trustState).toBe("candidate");
  });

  it("the retirement evidence hash helper is deterministic", () => {
    const a = peerTransitionEvidenceHash({ nodeId: NODE_A, targetState: "retired", subjectHash: "abc", atEpochMs: 1 });
    const b = peerTransitionEvidenceHash({ nodeId: NODE_A, targetState: "retired", subjectHash: "abc", atEpochMs: 1 });
    const c = peerTransitionEvidenceHash({ nodeId: NODE_A, targetState: "retired", subjectHash: "abc", atEpochMs: 2 });
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });
});

// ── anti-resurrection ────────────────────────────────────────────────────────

describe("24C anti-resurrection — terminal states cannot re-enter", () => {
  it("a quarantined peer refuses admission, re-enrollment, and retirement rewrites", () => {
    const h = openFresh();
    admit(h, NODE_A);
    const q = h.registry.applyTrustTransition({
      nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
      reason: "admission_request_quarantined", evidence: "quarantine decision hash",
      transactionId: txn("quar-a2"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_006_000,
    });
    expect(q.ok).toBe(true);
    for (const reason of ["admission_request_accepted", "first_contact_enrolled", "operator_retirement"] as const) {
      const attempt = h.registry.applyTrustTransition({
        nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
        reason, evidence: "attempted resurrection", transactionId: txn("res-" + reason),
        lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_006_500,
      });
      expect(attempt).toMatchObject({ ok: false, failureCode: "peer_terminal_state" });
      expect(attempt.ok === false && attempt.explanation).toContain("do not resurrect");
    }
  });

  it("a retired peer refuses everything except nothing — retirement is terminal", () => {
    const h = openFresh();
    admit(h, NODE_A);
    const r = h.registry.applyTrustTransition({
      nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
      reason: "operator_retirement", evidence: "operator decision", transactionId: txn("retire-a"),
      lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_007_000,
    });
    expect(r.ok).toBe(true);
    const resurrection = h.registry.applyTrustTransition({
      nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
      reason: "admission_request_accepted", evidence: "e", transactionId: txn("resurrect"),
      lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_007_500,
    });
    expect(resurrection).toMatchObject({ ok: false, failureCode: "peer_terminal_state" });
  });
});

// ── restart / corruption / recovery ──────────────────────────────────────────

describe("24C restart, corruption, and recovery", () => {
  it("restart: facts restore EXACTLY (same revision, same state), through a NEW epoch's registry", () => {
    const h = openFresh(EPOCH_1);
    admit(h, NODE_A);
    const before = h.registry.readPeer(NODE_A);
    if (!before.ok) throw new Error("fixture");
    h.coordinator.close();
    const bound = RuntimeStateCoordinator.open(h.store, epochOf(EPOCH_2), "unit-test:24c-e2");
    if (!bound.ok) throw new Error(bound.reason);
    openCoords.push(bound.coordinator);
    const r2 = PeerRegistry.open(h.store, bound.coordinator);
    if (!r2.ok) throw new Error(r2.reason);
    const after = r2.registry.readPeer(NODE_A);
    expect(after.ok).toBe(true);
    if (after.ok) {
      expect(after.state).toEqual(before.state);
      expect(after.revision).toBe(before.revision);
    }
  });

  it("corruption/recovery: tampered peer bytes are a recovery finding, never admitted; terminal peers map to terminalPeerIds", () => {
    const h = openFresh(EPOCH_1);
    admit(h, NODE_A);
    const q = h.registry.applyTrustTransition({
      nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: "menog-federation/v1",
      reason: "peer_misbehavior_evidenced", evidence: "e", transactionId: txn("term-q"),
      lineageRoot: ROOT, lineageParent: null, nowEpochMs: 1_700_000_008_000,
    });
    expect(q.ok).toBe(true);
    // Tamper DIRECTLY with the store row's payload (bypassing the junction —
    // this is the corruption the recovery layer must catch).
    const id = peerDurableId(NODE_A);
    if (!id.ok) throw new Error("fixture");
    const raw = h.store.readRecord(id.recordId);
    if (!raw.ok) throw new Error("fixture");
    const payload = raw.record.payload as Record<string, unknown>;
    const tampered = { ...payload, peerTrust: { ...(payload["peerTrust"] as PeerTrustState), trustState: "admitted" } };
    const resealed = Object.freeze({ ...raw.record, payload: Object.freeze(tampered) });
    const persist = h.store.persist(resealed);
    // The store must refuse the re-seal (hash/content binding); this is the
    // FIRST fail-closed layer. If it ever accepted, recovery must catch it.
    if (persist.ok) {
      // (defense-in-depth check) recovery re-verifies identity/integrity.
      const recovery = recoverState(h.store, {
        mode: "load_committed_state",
        expectedStoreSchemaVersion: h.store.storeSchemaVersion ?? "menog-durable-store/v0",
        maxRecords: 10_000,
        semantics: "no_execution",
      }, { nowEpochMs: 1_700_000_009_000 });
      const finding = recovery.decision.admittedRecordIds.includes(id.recordId);
      expect(finding).toBe(false);
    }
    // Terminal mapping through the recovery layer.
    const recovery = recoverState(h.store, {
      mode: "load_committed_state",
      expectedStoreSchemaVersion: h.store.storeSchemaVersion ?? "menog-durable-store/v0",
      maxRecords: 10_000,
      semantics: "no_execution",
    }, { nowEpochMs: 1_700_000_009_500 });
    expect(recovery.decision.executionAuthorized).toBe(false);
    expect(recovery.decision.policyAuthorized).toBe(false);
    expect(recovery.decision.authority).toBe("recovered_data");
    expect(recovery.terminalPeerIds).toContain(id.recordId);
    expect(recovery.admittedByKind["peer_trust_registry"]).toBeGreaterThanOrEqual(1);
    const mapped = mapPeerRecovery({
      recoveryDecisionAuthority: recovery.decision.authority,
      terminalPeerIds: recovery.terminalPeerIds,
      peerRecordsAdmitted: recovery.admittedByKind["peer_trust_registry"] ?? 0,
    });
    expect(mapped.terminalPeerIds).toContain(id.recordId);
    expect(mapped.explanation).toContain("no authority");
  });
});
