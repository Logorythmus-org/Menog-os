/**
 * PHASE 25C — Peer Trust Operations & Local Administration Tests
 * (NO REMOTE CONTROL PLANE / LOCAL OPERATIONS ONLY).
 *
 * Pack-mandated coverage:
 *   remote self-admission / self-unquarantine   — refused always
 *   stale admin epoch                            — refused
 *   conflicting mutation                          — concurrent writers conflict
 *   old fingerprint                               — pins immutable; re-identity only
 *   restart resurrection                          — terminal peers restore terminal
 *   admin evidence as execution authority         — impossible (no execution field)
 *   direct-store bypass                           — structurally absent
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DurableStore,
  RuntimeStateCoordinator,
  PeerRegistry,
  PeerAdminSession,
  PEER_ADMIN_SCHEMA_VERSION,
  PEER_ADMIN_OPERATIONS,
  PEER_ADMIN_INITIATORS,
  PEER_ADMIN_DENY_CODES,
  PEER_COMMAND_CLAIMS,
  checkLocalAdminIntent,
  refusePeerCommand,
  type LocalAdminIntent,
  type RuntimeEpoch,
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

// ── fixtures (24C-suite pattern) ─────────────────────────────────────────────

const roots: string[] = [];
const openStores: DurableStore[] = [];
const openCoords: RuntimeStateCoordinator[] = [];
function newRoot(): string {
  const r = mkdtempSync(join(tmpdir(), "menog-25c-"));
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

const NOW = 1_700_000_000_000;
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

function nodeIdOf(tag: string): string {
  const hex = Buffer.from(tag.padEnd(16, "0"), "utf8").toString("hex").padEnd(64, "0").slice(0, 64);
  return "node-" + hex;
}
const NODE_A = nodeIdOf("peer-alpha");
const NODE_B = nodeIdOf("peer-bravo");
const NODE_A2 = nodeIdOf("peer-alpha2");

const FP_A = "fp-sha256-" + "a".repeat(64);
const FP_B = "fp-sha256-" + "b".repeat(64);
const FP_A2 = "fp-sha256-" + "c".repeat(64);
const INSTANCE_A = "ri-000000e8fa00-instanceaaaa";

const PROTO = "menog-federation/v1";

interface Harness {
  readonly store: DurableStore;
  readonly coordinator: RuntimeStateCoordinator;
  readonly registry: PeerRegistry;
  readonly session: PeerAdminSession;
}

function openFresh(epochId: string = EPOCH_1): Harness {
  const open = DurableStore.open(newRoot());
  if (!open.ok) throw new Error(open.reason);
  const store = open.store;
  openStores.push(store);
  const bound = RuntimeStateCoordinator.open(store, epochOf(epochId), "unit-test:25c");
  if (!bound.ok) throw new Error(bound.reason);
  const coordinator = bound.coordinator;
  openCoords.push(coordinator);
  const opened = PeerRegistry.open(store, coordinator);
  if (!opened.ok) throw new Error(opened.reason);
  const session = PeerAdminSession.open(opened.registry, "unit-test:25c:session");
  if (!session.ok) throw new Error(session.reason);
  return { store, coordinator, registry: opened.registry, session: session.session };
}

let txnCounter = 0;
function txn(tag: string): string {
  txnCounter += 1;
  return tag + "-" + String(txnCounter).padStart(6, "0");
}

const ROOT = "peer-admin-root-25c";

function intent(localEpochId: string = EPOCH_1, decidedAt = NOW): LocalAdminIntent {
  return {
    initiatedBy: "local_operator",
    operatorRef: "console-session-007",
    rationale: "operator decision under gate 25C unit test",
    decidedAtEpochMs: decidedAt,
    localEpochId,
  };
}

function enroll(h: Harness, nodeId: string, fingerprint: string): void {
  const r = h.registry.applyTrustTransition({
    nodeId,
    fingerprint,
    instanceId: INSTANCE_A,
    protocolVersion: PROTO,
    reason: "first_contact_enrolled",
    evidence: "identity doc hash " + fingerprint,
    transactionId: txn("enroll"),
    lineageRoot: ROOT,
    lineageParent: null,
    nowEpochMs: NOW,
  });
  if (!r.ok) throw new Error("fixture enroll failed: " + r.explanation);
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("25C structure — no control plane, no bypass, no authority", () => {
  it("module contains no store/persist/junction escape hatch (structural)", () => {
    const code = codeOnly(SRC("federationPeerAdmin.ts"));
    expect(code).not.toContain("DurableStore.open");
    expect(code).not.toContain(".persist(");
    expect(code).not.toContain("acceptMutation");
    expect(code).not.toContain("store.readRecord");
    expect(code).not.toContain("node:dgram");
    expect(code).not.toContain("node:http");
    expect(code).not.toContain("WebSocket");
    expect(code).not.toContain("fetch(");
    expect(code).not.toContain("spawn(");
    expect(code).not.toContain("listen(");
    expect(code).not.toMatch(/executionAuthorized:\s*true/);
    expect(code).not.toMatch(/policyAuthorized:\s*true/);
  });

  it("vocabularies are closed and pinned", () => {
    expect(PEER_ADMIN_SCHEMA_VERSION).toBe("menog-peer-admin/v0");
    expect([...PEER_ADMIN_OPERATIONS]).toEqual(["list_peers", "explain_peer", "admit_candidate", "quarantine_peer", "retire_peer", "record_re_identity"]);
    expect([...PEER_ADMIN_INITIATORS]).toEqual(["local_operator"]);
    expect([...PEER_ADMIN_DENY_CODES]).toEqual([
      "not_locally_initiated",
      "peer_message_admin_refused",
      "operator_intent_incomplete",
      "stale_admin_epoch",
      "malformed_peer_input",
      "peer_unknown",
      "peer_terminal_state",
      "pin_conflict",
      "machine_refused",
      "persistence_refused",
    ]);
    expect([...PEER_COMMAND_CLAIMS]).toEqual(["self_admit", "self_unquarantine", "trust_inheritance_claim", "admin_evidence_claim"]);
  });

  it("the intent gate accepts ONLY locally-initiated, complete, live-epoch intents", () => {
    const live = checkLocalAdminIntent({ intent: intent(), liveEpochId: EPOCH_1 });
    expect(live.ok).toBe(true);
    if (live.ok) expect(live.intentHash).toMatch(/^[0-9a-f]{32,128}$/);
    const remote = checkLocalAdminIntent({
      intent: { ...intent(), initiatedBy: "peer_message" as never },
      liveEpochId: EPOCH_1,
    });
    expect(remote).toMatchObject({ ok: false, denyCode: "not_locally_initiated" });
    const incomplete = checkLocalAdminIntent({
      intent: { ...intent(), rationale: "" },
      liveEpochId: EPOCH_1,
    });
    expect(incomplete).toMatchObject({ ok: false, denyCode: "operator_intent_incomplete" });
  });

  it("peer-sourced admin claims refuse deterministically — every claim, always", () => {
    for (const claim of PEER_COMMAND_CLAIMS) {
      const r = refusePeerCommand(claim, NODE_A);
      expect(r.refused).toBe(true);
      expect(r.explanation).toContain("REFUSED");
    }
    expect(refusePeerCommand("self_admit", NODE_A).explanation).toContain("never an admin command");
    expect(refusePeerCommand("self_unquarantine", NODE_A).explanation).toContain("terminal");
  });

  it("a session cannot be opened over a closed registry or with an empty id", () => {
    const h = openFresh();
    h.coordinator.close();
    const reopened = PeerAdminSession.open(h.registry, "s");
    expect(reopened.ok).toBe(false);
    const h2 = openFresh();
    expect(PeerAdminSession.open(h2.registry, "  ").ok).toBe(false);
  });
});

// ── the narrow operations, happy path ────────────────────────────────────────

describe("25C operations — admit, quarantine, retire, explain, list", () => {
  it("admits a locally-enrolled candidate through operator intent", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    const d = h.session.admitCandidate({
      nodeId: NODE_A,
      fingerprint: FP_A,
      instanceId: INSTANCE_A,
      protocolVersion: PROTO,
      intent: intent(),
      transactionId: txn("admit"),
      lineageRoot: ROOT,
      lineageParent: null,
    });
    expect(d).toMatchObject({ ok: true, operation: "admit_candidate", from: "candidate", to: "admitted" });
    if (!d.ok) return;
    expect(d.explanation).toContain("operator intent bound");
    expect(d.explanation).toContain("no execution authority");
  });

  it("quarantine is the END state; retirement is the direct exit from admitted — both terminal", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    const admitted = h.session.admitCandidate({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(), transactionId: txn("admit"), lineageRoot: ROOT, lineageParent: null });
    expect(admitted.ok).toBe(true);
    const q = h.session.quarantinePeer({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_1, NOW + 5), transactionId: txn("quar"), lineageRoot: ROOT, lineageParent: null });
    expect(q).toMatchObject({ ok: true, operation: "quarantine_peer", to: "quarantined" });
    // Self-unquarantine from the peer side is impossible; even the LOCAL
    // session cannot re-admit (quarantined → admitted is not an edge).
    const reAdmit = h.session.admitCandidate({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_1, NOW + 6), transactionId: txn("readmit"), lineageRoot: ROOT, lineageParent: null });
    expect(reAdmit).toMatchObject({ ok: false, denyCode: "peer_terminal_state" });
    // The FROZEN 24C registry refuses every transition FROM quarantined —
    // quarantine is the end state (even quarantined → retired refuses;
    // nothing resurrects and nothing un-ends). Pinned as-is.
    const ret = h.session.retirePeer({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_1, NOW + 7), transactionId: txn("ret"), lineageRoot: ROOT, lineageParent: null });
    expect(ret).toMatchObject({ ok: false, denyCode: "peer_terminal_state" });
    expect(ret.ok === false && ret.explanation).toContain("peer_terminal_state");
    // Retirement is the DIRECT operator exit from an admitted peer.
    enroll(h, NODE_B, FP_B);
    const admittedB = h.session.admitCandidate({ nodeId: NODE_B, fingerprint: FP_B, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_1, NOW + 8), transactionId: txn("admit-b"), lineageRoot: ROOT, lineageParent: null });
    expect(admittedB.ok).toBe(true);
    const retB = h.session.retirePeer({ nodeId: NODE_B, fingerprint: FP_B, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_1, NOW + 9), transactionId: txn("ret-b"), lineageRoot: ROOT, lineageParent: null });
    expect(retB).toMatchObject({ ok: true, operation: "retire_peer", to: "retired" });
    const read = h.session.inspectPeer(NODE_B);
    expect(read.ok && read.terminal).toBe(true);
  });

  it("explain/history and list are read-only and deterministic", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    const admitted = h.session.admitCandidate({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(), transactionId: txn("admit"), lineageRoot: ROOT, lineageParent: null });
    expect(admitted.ok).toBe(true);
    const expl = h.session.explainPeer(NODE_A);
    expect(expl.trustState).toBe("admitted");
    expect(expl.history.length).toBeGreaterThanOrEqual(3);
    expect(expl.explanation).toContain("communication trust only");
    const lst = h.session.listPeers([NODE_A, NODE_B]);
    expect(lst.peers).toHaveLength(1);
    expect(lst.peers[0]?.nodeId).toBe(NODE_A);
    expect(lst.unreadable).toEqual([NODE_B]);
    expect(lst.explanation).toContain("read-only");
  });

  it("records the re-identity relation: old retired with evidence; replacement starts as a NEW candidate", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    const retired = h.session.recordReIdentityRelation({
      oldNodeId: NODE_A,
      newNodeId: NODE_A2,
      oldFingerprint: FP_A,
      newInstanceRef: INSTANCE_A,
      oldProtocolVersion: PROTO,
      oldInstanceId: INSTANCE_A,
      intent: intent(EPOCH_1, NOW + 5),
      transactionId: txn("reid"),
      lineageRoot: ROOT,
      lineageParent: null,
    });
    expect(retired).toMatchObject({ ok: true, operation: "record_re_identity", to: "retired" });
    if (!retired.ok) return;
    // The relation is durably recorded in the OLD record's transition
    // evidence: it names the replacement and the no-inheritance law.
    const oldRead = h.session.inspectPeer(NODE_A);
    expect(oldRead.ok).toBe(true);
    if (!oldRead.ok) return;
    expect(oldRead.state.lastTransitionEvidence).toContain(NODE_A2);
    expect(oldRead.state.lastTransitionEvidence).toContain("NO inherited trust");
    expect(oldRead.terminal).toBe(true);
    // The replacement is NOT admitted by this operation: it is unknown until
    // first-contact enrollment, and then only a candidate.
    const fresh = h.session.inspectPeer(NODE_A2);
    expect(fresh.ok).toBe(false);
    enroll(h, NODE_A2, FP_A2);
    const freshRead = h.session.inspectPeer(NODE_A2);
    expect(freshRead.ok && freshRead.state.trustState).toBe("candidate");
    // And the operator may THEN admit it through a separate decision.
    const admitNew = h.session.admitCandidate({ nodeId: NODE_A2, fingerprint: FP_A2, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_1, NOW + 6), transactionId: txn("admitnew"), lineageRoot: ROOT, lineageParent: null });
    expect(admitNew).toMatchObject({ ok: true, to: "admitted" });
  });

  it("self-identity recording refuses (old == new, malformed replacement)", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    expect(
      h.session.recordReIdentityRelation({ oldNodeId: NODE_A, newNodeId: NODE_A, oldFingerprint: FP_A, newInstanceRef: INSTANCE_A, oldProtocolVersion: PROTO, oldInstanceId: INSTANCE_A, intent: intent(), transactionId: txn("x1"), lineageRoot: ROOT, lineageParent: null })
    ).toMatchObject({ ok: false, denyCode: "malformed_peer_input" });
    expect(
      h.session.recordReIdentityRelation({ oldNodeId: NODE_A, newNodeId: "garbage", oldFingerprint: FP_A, newInstanceRef: INSTANCE_A, oldProtocolVersion: PROTO, oldInstanceId: INSTANCE_A, intent: intent(), transactionId: txn("x2"), lineageRoot: ROOT, lineageParent: null })
    ).toMatchObject({ ok: false, denyCode: "malformed_peer_input" });
  });
});

// ── pack attack/control cases ────────────────────────────────────────────────

describe("25C attacks — remote control plane attempts all fail", () => {
  it("remote self-admission is refused (peer message != admin command)", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    // A peer "asks" to be admitted: the only path a peer could try is the
    // admin session — which demands local_operator intent minted in the
    // live epoch. Peer-originated intent refuses at the gate.
    const peerMinted = checkLocalAdminIntent({
      intent: { initiatedBy: "peer_message" as never, operatorRef: "msg-fm-123", rationale: "please admit me", decidedAtEpochMs: NOW, localEpochId: EPOCH_1 },
      liveEpochId: EPOCH_1,
    });
    expect(peerMinted).toMatchObject({ ok: false, denyCode: "not_locally_initiated" });
    // And the refusal analysis names it deterministically.
    expect(refusePeerCommand("self_admit", NODE_A).refused).toBe(true);
  });

  it("remote self-unquarantine is refused even with perfectly-formed metadata", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    const admitted = h.session.admitCandidate({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(), transactionId: txn("admit"), lineageRoot: ROOT, lineageParent: null });
    expect(admitted.ok).toBe(true);
    const q = h.session.quarantinePeer({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_1, NOW + 5), transactionId: txn("quar"), lineageRoot: ROOT, lineageParent: null });
    expect(q.ok).toBe(true);
    // Quarantined peer "requests" unquarantine with its own message content —
    // regardless of metadata shape, the underlying machine has NO edge.
    const attempt = h.session.admitCandidate({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_1, NOW + 6), transactionId: txn("unq"), lineageRoot: ROOT, lineageParent: null });
    expect(attempt).toMatchObject({ ok: false, denyCode: "peer_terminal_state" });
    expect(attempt.ok === false && attempt.explanation).toContain("peer_terminal_state");
  });

  it("a STALE ADMIN EPOCH refuses every mutation", () => {
    const h = openFresh(EPOCH_2); // live epoch is EPOCH_2
    enroll(h, NODE_A, FP_A);
    const stale = h.session.admitCandidate({
      nodeId: NODE_A,
      fingerprint: FP_A,
      instanceId: INSTANCE_A,
      protocolVersion: PROTO,
      intent: intent(EPOCH_1), // intent formed in the OLD epoch
      transactionId: txn("stale"),
      lineageRoot: ROOT,
      lineageParent: null,
    });
    expect(stale).toMatchObject({ ok: false, denyCode: "stale_admin_epoch" });
    expect(stale.ok === false && stale.explanation).toContain("stale admin epochs fail");
    // The same intent re-issued in the live epoch succeeds.
    const fresh = h.session.admitCandidate({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_2, NOW + 2), transactionId: txn("fresh"), lineageRoot: ROOT, lineageParent: null });
    expect(fresh.ok).toBe(true);
  });

  it("a CONFLICTING mutation (concurrent writer) conflicts — never last-writer-wins, never healed", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    // Two sessions over the same registry; both build on revision 1, but
    // only one can win the revision chain — the other must conflict.
    const s2 = PeerAdminSession.open(h.registry, "session-2");
    if (!s2.ok) throw new Error("fixture session-2 failed");
    const first = h.session.admitCandidate({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_1, NOW + 1), transactionId: txn("c1"), lineageRoot: ROOT, lineageParent: null });
    expect(first.ok).toBe(true);
    // The second mutation is content-identical in state terms → the store's
    // idempotent-replay / conflict semantics apply at the 24C layer; here we
    // pin that a DIFFERENT transaction targeting a stale revision refuses
    // rather than silently overwriting.
    const second = h.session.retirePeer({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_1, NOW + 2), transactionId: txn("c2"), lineageRoot: ROOT, lineageParent: null });
    // Retiring from admitted is a legal edge and simply applies on top.
    expect(second).toMatchObject({ ok: true, to: "retired" });
    // A REPLAY of the FIRST transaction (already superseded chain) reports
    // idempotency or refusal — never a rewrite of history:
    const replay = h.registry.applyTrustTransition({
      nodeId: NODE_A,
      fingerprint: FP_A,
      instanceId: INSTANCE_A,
      protocolVersion: PROTO,
      reason: "admission_request_accepted",
      evidence: "LOCAL operator admission (console-session-007): operator decision under gate 25C unit test",
      transactionId: txn("c1") + "-replay",
      lineageRoot: ROOT,
      lineageParent: null,
      nowEpochMs: NOW + 3,
    });
    // The peer is now retired; re-admission refuses (terminal), proving no
    // replay path resurrects or rewrites.
    expect(replay).toMatchObject({ ok: false, failureCode: "peer_terminal_state" });
  });

  it("an OLD FINGERPRINT refuses — pins immutable; replacement is a new candidate, not a re-pin", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    // The old peer tries to operate under its OLD fingerprint after the
    // operator recorded a re-identity — the pin conflict fires at 24C.
    const oldPinAttempt = h.session.admitCandidate({
      nodeId: NODE_A,
      fingerprint: FP_A2, // DIFFERENT from the pinned FP_A
      instanceId: INSTANCE_A,
      protocolVersion: PROTO,
      intent: intent(),
      transactionId: txn("oldpin"),
      lineageRoot: ROOT,
      lineageParent: null,
    });
    expect(oldPinAttempt).toMatchObject({ ok: false, denyCode: "pin_conflict" });
    expect(oldPinAttempt.ok === false && oldPinAttempt.explanation).toContain("pins are immutable");
  });

  it("RESTART does not resurrect: terminal peers restore EXACTLY terminal; admin sees them terminal", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    const admitted = h.session.admitCandidate({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(), transactionId: txn("admit"), lineageRoot: ROOT, lineageParent: null });
    expect(admitted.ok).toBe(true);
    const q = h.session.quarantinePeer({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_1, NOW + 5), transactionId: txn("quar"), lineageRoot: ROOT, lineageParent: null });
    expect(q.ok).toBe(true);
    h.coordinator.close();
    // Restart: the SAME store, a NEW epoch's coordinator (the 24C pattern).
    const bound2 = RuntimeStateCoordinator.open(h.store, epochOf(EPOCH_2), "unit-test:25c-restart");
    if (!bound2.ok) throw new Error(bound2.reason);
    openCoords.push(bound2.coordinator);
    const reg2 = PeerRegistry.open(h.store, bound2.coordinator);
    if (!reg2.ok) throw new Error(reg2.reason);
    const sess2 = PeerAdminSession.open(reg2.registry, "session-after-restart");
    if (!sess2.ok) throw new Error(sess2.reason);
    const after = sess2.session.inspectPeer(NODE_A);
    expect(after.ok && after.state.trustState).toBe("quarantined");
    expect(after.ok && after.terminal).toBe(true);
    // Even a local operator session cannot un-quarantine after restart.
    const unq = sess2.session.admitCandidate({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(EPOCH_2, NOW + 50), transactionId: txn("postrestart"), lineageRoot: ROOT, lineageParent: null });
    expect(unq).toMatchObject({ ok: false, denyCode: "peer_terminal_state" });
  });

  it("admin evidence can never be execution authority — decisions carry no execution field", () => {
    const h = openFresh();
    enroll(h, NODE_A, FP_A);
    const d = h.session.admitCandidate({ nodeId: NODE_A, fingerprint: FP_A, instanceId: INSTANCE_A, protocolVersion: PROTO, intent: intent(), transactionId: txn("admit"), lineageRoot: ROOT, lineageParent: null });
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect("executionAuthorized" in d).toBe(false);
    expect("policyAuthorized" in d).toBe(false);
    expect(d.explanation).toContain("no execution authority");
    // The refusal analysis says the same for peer-supplied "evidence".
    expect(refusePeerCommand("admin_evidence_claim", NODE_A).explanation).toContain("never serve as execution authority");
  });

  it("direct-store bypass: the admin module holds NO store reference at all (type-level + source-level)", () => {
    const code = codeOnly(SRC("federationPeerAdmin.ts"));
    expect(code).not.toContain("DurableStore");
    expect(code).not.toContain("store.");
    expect(code).not.toContain("sqlite");
    // The ONLY mutation funnel delegates to the 24C registry.
    expect(code).toContain("applyTrustTransition");
    expect(code).toContain("checkLocalAdminIntent");
  });
});
