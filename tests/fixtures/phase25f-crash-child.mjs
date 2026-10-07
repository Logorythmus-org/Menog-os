/**
 * PHASE 25F — Crash-window child fixture for the PHASE-25 SURFACES
 * (NOT a test file). Extends the frozen 23E harness pattern to the new
 * federation operational layers; adds ZERO new durability semantics.
 *
 * Usage: node phase25f-crash-child.mjs <window> <root>
 *
 * Windows (each parks after printing `ready:<window>`, then SIGKILLed):
 *   F1  identity lifecycle: rotation COMMITTED to the durable record, before
 *       the operator could record the retirement of the old identity.
 *   F2  peer quarantine COMMITTED through the 23B junction, before the
 *       ack file (committed-before-ack).
 *   F3  federation receipt append-only record COMMITTED (24D junction path).
 *   F4  federation proposal append-only record COMMITTED (24E junction path).
 *   F5  federation provenance anchor COMMITTED (24F junction path).
 *   F6  handoff COMPLETE (NEW epoch LIVE), ready for idempotent replay of a
 *       pre-crash transaction (the parent replays it after reopen).
 *   F7  egress disclosure (25D): a durable receipt is committed (the durable
 *       truth the disclosure binds to), then the stateless egress gate
 *       computes the deterministic manifest (its hash printed). The gate
 *       persists NOTHING — the parent re-derives the manifest byte-identically
 *       from durable truth and proves stale re-binding refuses.
 */
import { mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const ds = await import(new URL("../../packages/durable-state/dist/index.js", import.meta.url).href);

const [crashWindow, root] = process.argv.slice(2);
if (!crashWindow || !root) process.exit(2);
mkdirSync(root, { recursive: true });

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function bootEpoch(id) {
  return Object.freeze({
    schemaVersion: "menog-runtime-epoch/v0",
    epochId: id,
    startedAtEpochMs: 1759100000000,
    hostRef: "25f-child",
    pidRef: process.pid,
    lifecycle: "BOOTING",
    priorOwner: { code: "none", epochId: null },
    startReason: "fresh_store_no_prior_owner",
    executionAuthorized: false,
    policyAuthorized: false,
  });
}

const open = ds.DurableStore.open(root);
if (!open.ok) {
  console.log("ready:" + crashWindow + "-open-failed");
  process.exit(3);
}
const store = open.store;

// The node id/fingerprint shapes used across windows (public facts only).
// Peer durable-id discipline (24C): `peer-` + the 64-hex NodeId TAIL.
const NODE_X = "node-" + "f".repeat(64);
const PEER_RECORD_X = "peer-" + "f".repeat(64);
const FP_X = "fp-sha256-" + "f".repeat(64);
const NODE_Y = "node-" + "e".repeat(64);
const FP_Y = "fp-sha256-" + "e".repeat(64);
// sender epoch ids use the 23A `re-<ts12>-<rnd16>` shape (24-char tail)
const INSTANCE = "ri-000000e8fa00-25fchildaaaa";
const PROTO = "menog-federation/v1";
const ROOT = "gol-25f-crash";

switch (crashWindow) {
  // F1: identity lifecycle rotation committed; the OLD key's retirement is
  // NOT yet recorded (the crash gap 25B must reconcile without resurrecting
  // anything: the fresh record exists; the old record never had one).
  case "f1": {
    const bound = ds.RuntimeStateCoordinator.open(store, bootEpoch("re-000000ef000f-f1epochepoch0000"), "25f-child");
    if (!bound.ok) { console.log("ready:f1-bind-failed"); process.exit(3); }
    // Durable peer fact for the OLD identity (admitted), then the operator
    // retires it as part of the rotation — the crash lands between the
    // retirement commit and the ack.
    const r1 = bound.coordinator.acceptMutation({
      kind: "peer_trust_registry",
      recordId: PEER_RECORD_X,
      revision: 1,
      supersedesRevision: null,
      payload: {
        stateKind: "peer_trust",
        peerTrust: {
          schemaVersion: "menog-federation-peer-trust/v0",
          nodeId: NODE_X,
          fingerprint: FP_X,
          instanceId: INSTANCE,
          trustState: "retired",
          protocolVersion: PROTO,
          pinnedAtEpochMs: 1759100000100,
          updatedAtEpochMs: 1759100000150,
          lastTransitionEvidence: "25F F1: operator re-identity retirement (evidenced)",
        },
      },
      transactionId: "tx-25f-f1-retire",
      lineageRoot: ROOT,
      lineageParent: null,
      createdAtEpochMs: 1759100000150,
    });
    if (!r1.ok) { console.log("ready:f1-retire-failed"); process.exit(3); }
    console.log("ready:f1");
    await delay(60000);
    break;
  }
  // F2: peer quarantine COMMITTED, before the ack file (committed-before-ack).
  case "f2": {
    const bound = ds.RuntimeStateCoordinator.open(store, bootEpoch("re-000000ef000f-f2epochepoch0000"), "25f-child");
    if (!bound.ok) { console.log("ready:f2-bind-failed"); process.exit(3); }
    const r = bound.coordinator.acceptMutation({
      kind: "peer_trust_registry",
      recordId: PEER_RECORD_X,
      revision: 1,
      supersedesRevision: null,
      payload: {
        stateKind: "peer_trust",
        peerTrust: {
          schemaVersion: "menog-federation-peer-trust/v0",
          nodeId: NODE_X,
          fingerprint: FP_X,
          instanceId: INSTANCE,
          trustState: "quarantined",
          protocolVersion: PROTO,
          pinnedAtEpochMs: 1759100000200,
          updatedAtEpochMs: 1759100000250,
          lastTransitionEvidence: "25F F2: evidenced misbehavior quarantine",
        },
      },
      transactionId: "tx-25f-f2-quarantine",
      lineageRoot: ROOT,
      lineageParent: null,
      createdAtEpochMs: 1759100000250,
    });
    if (!r.ok) { console.log("ready:f2-mut-failed"); process.exit(3); }
    console.log("ready:f2");
    await delay(60000);
    break;
  }
  // F3: federation RECEIPT (append-only kind) committed — EXACT 24D payload
  // shape and EXACT durable-id discipline (`frc-` + canonical message id).
  case "f3": {
    const bound = ds.RuntimeStateCoordinator.open(store, bootEpoch("re-000000ef000f-f3epochepoch0000"), "25f-child");
    if (!bound.ok) { console.log("ready:f3-bind-failed"); process.exit(3); }
    const msgId = "fm-000000000025f-aaaa000000000001";
    const receiptPayload = {
      receiptKind: "message_accepted",
      messageId: msgId,
      senderNodeId: NODE_Y,
      senderFingerprint: FP_Y,
      senderEpochId: "re-000000ef000f-senderepochepo00",
      payloadHash: "sha256-" + "5".repeat(64),
      protocolVersion: PROTO,
      schemaVersion: "menog-federation-message/v0",
      declaredIntent: "task_proposal",
      receiverDecision: "message_admitted",
      receiverEpochId: "re-000000ef000f-f3epochepoch0000",
      subjectHash: "sha256-" + "6".repeat(64),
      decidedAtEpochMs: 1759100000300,
    };
    const r = bound.coordinator.acceptMutation({
      kind: "federation_receipt",
      recordId: "frc-" + msgId,
      revision: 1,
      supersedesRevision: null,
      payload: receiptPayload,
      transactionId: "frc-" + msgId,
      lineageRoot: msgId,
      lineageParent: null,
      createdAtEpochMs: 1759100000300,
    });
    if (!r.ok) { console.log("ready:f3-mut-failed:" + (r.storeFailureCode ?? r.explanation ?? "")); process.exit(3); }
    console.log("ready:f3");
    await delay(60000);
    break;
  }
  // F4: federation PROPOSAL (append-only kind) committed — EXACT 24E record
  // body shape and EXACT durable-id discipline (`fpr-` + `fp-<16hex>-<16alnum>`).
  case "f4": {
    const bound = ds.RuntimeStateCoordinator.open(store, bootEpoch("re-000000ef000f-f4epochepoch0000"), "25f-child");
    if (!bound.ok) { console.log("ready:f4-bind-failed"); process.exit(3); }
    const proposalId = "fp-000000000025f-aaaa000000000001";
    const msgId = "fm-000000000025f-bbbb000000000001";
    const body = {
      schemaVersion: "menog-federation-proposal/v0",
      proposalId,
      messageId: msgId,
      senderNodeId: NODE_Y,
      senderFingerprint: FP_Y,
      proposalHash: "sha256-" + "7".repeat(64),
      intentClass: "code_generation",
      contentHashes: { primary: "sha256-" + "a".repeat(64) },
      provenance: { originNodeId: NODE_Y, originEpochId: "re-000000ef000f-senderepochepo00" },
      constraints: { maxDurationMs: 30000 },
      expectedEvidence: [],
      receiverDecision: "proposal_admitted",
      receiverEpochId: "re-000000ef000f-f4epochepoch0000",
      receiptRecordId: "frc-" + msgId,
      decidedAtEpochMs: 1759100000400,
    };
    const r = bound.coordinator.acceptMutation({
      kind: "federation_proposal",
      recordId: "fpr-" + proposalId,
      revision: 1,
      supersedesRevision: null,
      payload: body,
      transactionId: "fpr-commit-" + proposalId,
      lineageRoot: proposalId,
      lineageParent: msgId,
      createdAtEpochMs: 1759100000400,
    });
    if (!r.ok) { console.log("ready:f4-mut-failed:" + (r.storeFailureCode ?? r.explanation ?? "")); process.exit(3); }
    console.log("ready:f4");
    await delay(60000);
    break;
  }
  // F5: federation PROVENANCE anchor (append-only kind) committed.
  case "f5": {
    const bound = ds.RuntimeStateCoordinator.open(store, bootEpoch("re-000000ef000f-f5epochepoch0000"), "25f-child");
    if (!bound.ok) { console.log("ready:f5-bind-failed"); process.exit(3); }
    const anchorId = "fv-000000000025f-aaaa000000000001";
    const anchor = {
      schemaVersion: "menog-federation-provenance/v0",
      anchorId,
      anchorKind: "message",
      senderNodeId: NODE_Y,
      senderFingerprint: FP_Y,
      senderEpochId: "re-000000ef000f-senderepochepo00",
      messageId: "fm-000000000025f-cccc000000000001",
      proposalId: null,
      protocolVersion: PROTO,
      payloadHash: "sha256-" + "8".repeat(64),
      subjectHash: "sha256-" + "9".repeat(64),
      authority: "none",
      decidedAtEpochMs: 1759100000500,
    };
    const r = bound.coordinator.acceptMutation({
      kind: "federation_provenance",
      recordId: "fpv-" + anchorId,
      revision: 1,
      supersedesRevision: null,
      payload: anchor,
      transactionId: "fpv-commit-" + anchorId,
      lineageRoot: anchorId,
      lineageParent: null,
      createdAtEpochMs: 1759100000500,
    });
    if (!r.ok) { console.log("ready:f5-mut-failed"); process.exit(3); }
    console.log("ready:f5");
    await delay(60000);
    break;
  }
  // F6: handoff COMPLETE (NEW epoch holds the claim); the parent will replay
  // the PRE-CRASH transaction after reopening — the store's duplicate-
  // transaction idempotency is the thing under test.
  case "f6": {
    const run = ds.runStartupHandoff({
      store,
      bootedEpoch: bootEpoch("re-000000ef000f-f6bootbootboot00"),
      recoveryRequest: { mode: "load_committed_state", expectedStoreSchemaVersion: "menog-durable-store/v0", maxRecords: 10000, semantics: "no_execution" },
      sourceIdentity: "25f-child",
      priorEpochId: null,
      nowEpochMs: 1759100000600,
    });
    if (!run.ok) { console.log("ready:f6-handoff-failed:" + run.explanation); process.exit(3); }
    console.log("ready:f6");
    await delay(60000);
    break;
  }
  // F7: EGRESS DISCLOSURE across crash — a durable receipt (append-only) is
  // COMMITTED as the durable truth the disclosure binds to; then the stateless
  // 25D egress gate computes the deterministic disclosure manifest pre-crash
  // (hash printed for the parent's cross-process comparison). Nothing about
  // the disclosure is persisted — nothing half-authoritative can exist.
  case "f7": {
    const bound = ds.RuntimeStateCoordinator.open(store, bootEpoch("re-000000ef000f-f7epochepoch0000"), "25f-child");
    if (!bound.ok) { console.log("ready:f7-bind-failed"); process.exit(3); }
    const msgId = "fm-000000000025f-dddd000000000001";
    const payloadHash = "sha256-" + "4".repeat(64);
    const receiptPayload = {
      receiptKind: "message_accepted",
      messageId: msgId,
      senderNodeId: NODE_Y,
      senderFingerprint: FP_Y,
      senderEpochId: "re-000000ef000f-senderepochepo00",
      payloadHash,
      protocolVersion: PROTO,
      schemaVersion: "menog-federation-message/v0",
      declaredIntent: "task_proposal",
      receiverDecision: "message_admitted",
      receiverEpochId: "re-000000ef000f-f7epochepoch0000",
      subjectHash: "sha256-" + "6".repeat(64),
      decidedAtEpochMs: 1759100000700,
    };
    const r = bound.coordinator.acceptMutation({
      kind: "federation_receipt",
      recordId: "frc-" + msgId,
      revision: 1,
      supersedesRevision: null,
      payload: receiptPayload,
      transactionId: "frc-" + msgId,
      lineageRoot: msgId,
      lineageParent: null,
      createdAtEpochMs: 1759100000700,
    });
    if (!r.ok) { console.log("ready:f7-mut-failed:" + (r.storeFailureCode ?? r.explanation ?? "")); process.exit(3); }
    const candidate = {
      schemaVersion: "menog-egress-disclosure/v0",
      payloadHash,
      fields: [
        { key: "nodeId", egressClass: "public_identity", value: NODE_Y },
        { key: "messageId", egressClass: "protocol_metadata", value: msgId },
        { key: "payloadHash", egressClass: "content_hashes", value: payloadHash },
        { key: "receiptRecordId", egressClass: "provenance_refs", value: "frc-" + msgId },
      ],
    };
    const decision = ds.decideEgress({ candidate, outgoingPayloadHash: payloadHash, nowEpochMs: 1759100000800 });
    if (!decision.ok) { console.log("ready:f7-egress-failed:" + decision.denyCode); process.exit(3); }
    console.log("manifest:" + decision.manifest.manifestHash);
    console.log("ready:f7");
    await delay(60000);
    break;
  }
  default:
    process.exit(2);
}
process.exit(0);
