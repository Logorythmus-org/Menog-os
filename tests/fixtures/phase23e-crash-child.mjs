/**
 * PHASE 23E — Crash-window child fixture (NOT a test file).
 *
 * Usage: node phase23e-crash-child.mjs <window> <root>
 *
 * Drives the REAL built durable-state machinery to a precise kill window,
 * prints `ready:<window>` on stdout, then parks (the parent SIGKILLs it at
 * that exact point). Exit code 3 + a `ready:<window>-failed` marker means
 * the window could not be reached (the parent treats that as a harness
 * failure, never as a crash-window PASS).
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const ds = await import(new URL("../../packages/durable-state/dist/index.js", import.meta.url).href);

const [crashWindow, root] = process.argv.slice(2);
if (!crashWindow || !root) process.exit(2);
mkdirSync(root, { recursive: true });

const RECOVERY_REQUEST = {
  mode: "load_committed_state",
  expectedStoreSchemaVersion: "menog-durable-store/v0",
  maxRecords: 10000,
  semantics: "no_execution",
};

function bootEpoch(id) {
  return Object.freeze({
    schemaVersion: "menog-runtime-epoch/v0",
    epochId: id,
    startedAtEpochMs: 1759100000000,
    hostRef: "23e-child",
    pidRef: process.pid,
    lifecycle: "BOOTING",
    priorOwner: { code: "none", epochId: null },
    startReason: "fresh_store_no_prior_owner",
    executionAuthorized: false,
    policyAuthorized: false,
  });
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

const open = ds.DurableStore.open(root);
if (!open.ok) {
  console.log("ready:" + crashWindow + "-open-failed");
  process.exit(3);
}
const store = open.store;

switch (crashWindow) {
  // Window 1: store open, NOTHING written, killed before any transaction.
  case "w1": {
    console.log("ready:w1");
    await delay(60000);
    break;
  }
  // Window 2: INSIDE a store transaction (BEGIN + staged record), before COMMIT.
  case "w2": {
    const envelope = ds.sealMutationEnvelope({
      kind: "memory_record",
      recordId: "mem-23e-w2-crash",
      revision: 1,
      supersedesRevision: null,
      transactionId: "tx-23e-w2",
      createdAtEpochMs: 1759100000100,
      epochId: "re-000000ef0001-w2epochepoch0000",
      sourceIdentity: "23e-child",
      lineageRoot: "gol-23e-w2",
      lineageParent: null,
      payload: { note: "w2 mid-transaction" },
    });
    const began = store.beginTransaction("tx-23e-w2");
    if (!began.ok) { console.log("ready:w2-begin-failed"); process.exit(3); }
    const staged = store.stageRecord(envelope);
    if (!staged.ok) { console.log("ready:w2-stage-failed:" + staged.failureCode); process.exit(3); }
    console.log("ready:w2");
    await delay(60000);
    break;
  }
  // Window 3: mutation COMMITTED, before any live acknowledgement.
  case "w3": {
    const bound = ds.RuntimeStateCoordinator.open(store, bootEpoch("re-000000ef0003-w3epochepoch0000"), "23e-child");
    if (!bound.ok) { console.log("ready:w3-bind-failed"); process.exit(3); }
    const r = bound.coordinator.acceptMutation({
      kind: "memory_record",
      recordId: "mem-23e-w3-crash",
      revision: 1,
      supersedesRevision: null,
      // EXACT 22D payload shape (recovery verifies the identity binding):
      payload: {
        stateKind: "memory_record",
        memory: {
          schemaVersion: "test/mem/v1",
          memoryId: "23e-w3-crash",
          kind: "project",
          scope: { workspaceId: "ws-23e" },
          provenance: { origin: "23e-child", actor: { type: "agent", id: "agent-23e" }, untrusted: false },
          retention: { retentionClass: "persistent" },
          body: { note: "w3 after-commit" },
          createdAtEpochMs: 1759100000300,
          createdByActorId: "agent-23e",
        },
      },
      transactionId: "tx-23e-w3",
      lineageRoot: "gol-23e-w3",
      lineageParent: null,
      createdAtEpochMs: 1759100000300,
    });
    if (!r.ok) { console.log("ready:w3-mut-failed"); process.exit(3); }
    console.log("ready:w3");
    await delay(60000);
    break;
  }
  // Window 4: mutation COMMITTED and acknowledged (ack file written).
  case "w4": {
    const bound = ds.RuntimeStateCoordinator.open(store, bootEpoch("re-000000ef0004-w4epochepoch0000"), "23e-child");
    if (!bound.ok) { console.log("ready:w4-bind-failed"); process.exit(3); }
    const r = bound.coordinator.acceptMutation({
      kind: "memory_record",
      recordId: "mem-23e-w4-crash",
      revision: 1,
      supersedesRevision: null,
      // EXACT 22D payload shape (recovery verifies the identity binding):
      payload: {
        stateKind: "memory_record",
        memory: {
          schemaVersion: "test/mem/v1",
          memoryId: "23e-w4-crash",
          kind: "project",
          scope: { workspaceId: "ws-23e" },
          provenance: { origin: "23e-child", actor: { type: "agent", id: "agent-23e" }, untrusted: false },
          retention: { retentionClass: "persistent" },
          body: { note: "w4 after-ack" },
          createdAtEpochMs: 1759100000400,
          createdByActorId: "agent-23e",
        },
      },
      transactionId: "tx-23e-w4",
      lineageRoot: "gol-23e-w4",
      lineageParent: null,
      createdAtEpochMs: 1759100000400,
    });
    if (!r.ok) { console.log("ready:w4-mut-failed"); process.exit(3); }
    writeFileSync(join(root, "ack-w4.json"), JSON.stringify({ commitSequence: r.commitSequence, barrier: r.barrier.outcome }));
    console.log("ready:w4");
    await delay(60000);
    break;
  }
  // Window 5: frozen recovery COMPLETED, before the LIVE handoff machinery.
  case "w5": {
    const rec = ds.recoverState(store, RECOVERY_REQUEST, { nowEpochMs: 1759100000500 });
    if (!String(rec.decision.code).startsWith("accept")) {
      console.log("ready:w5-recovery-rejected:" + rec.decision.code);
      process.exit(3);
    }
    console.log("ready:w5");
    await delay(60000);
    break;
  }
  // Window 6: full handoff COMPLETE (NEW epoch holds the claim), no mutation yet.
  case "w6": {
    const run = ds.runStartupHandoff({
      store,
      bootedEpoch: bootEpoch("re-000000ef0006-w6bootbootboot00"),
      recoveryRequest: RECOVERY_REQUEST,
      sourceIdentity: "23e-child",
      priorEpochId: null,
      nowEpochMs: 1759100000600,
    });
    if (!run.ok) { console.log("ready:w6-handoff-failed:" + run.explanation); process.exit(3); }
    console.log("ready:w6");
    await delay(60000);
    break;
  }
  default:
    process.exit(2);
}
process.exit(0);
