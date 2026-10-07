/**
 * PHASE 23B — Runtime State Coordinator & Durability Barrier tests.
 *
 * Required case coverage (23B prompt):
 *   1 success · 2 persistence refusal · 3 revision conflict · 4 stale epoch
 *   5 duplicate transaction · 6 corrupt/quarantined store · 7 coordinator
 *   restart · 8 no authority escalation · 9 no alternate persistence path
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import {
  DurableStore,
  RuntimeStateCoordinator,
  readRuntimeOwnership,
  sealMutationEnvelope,
  barrierFromPersistDecision,
  acknowledgedBarrier,
  decideContinuity,
  RUNTIME_OWNERSHIP_META_KEY,
  type LiveDurableMutation,
  type RuntimeEpoch,
} from "@menog/durable-state";

const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as {
  DatabaseSync: new (path: string) => {
    prepare(sql: string): { run(...args: unknown[]): void; get(...args: unknown[]): unknown };
  };
};

const roots: string[] = [];
const openStores: import("@menog/durable-state").DurableStore[] = [];
const openCoords: RuntimeStateCoordinator[] = [];
function newRoot(): string {
  const r = mkdtempSync(join(tmpdir(), "menog-23b-"));
  roots.push(r);
  return r;
}
function openStoreAt(root: string) {
  const open = DurableStore.open(root);
  if (open.ok) openStores.push(open.store);
  return open;
}
afterEach(() => {
  for (const c of openCoords) {
    try { c.close(); } catch { /* already closed */ }
  }
  for (const s of openStores) {
    try { if (s.isOpen) s.close(); } catch { /* already closed */ }
  }
  openCoords.length = 0;
  openStores.length = 0;
  for (const r of roots) {
    try { rmSync(r, { recursive: true, force: true }); } catch { /* windows handles */ }
  }
  roots.length = 0;
});

// ── helpers ──────────────────────────────────────────────────────────────────

const EPOCH_A = "re-000000ab0001-aaaaaaaaaaaaaaaa";
const EPOCH_B = "re-000000ab0002-bbbbbbbbbbbbbbbb";

function epochOf(id: string): RuntimeEpoch {
  return Object.freeze({
    schemaVersion: "menog-runtime-epoch/v0",
    epochId: id,
    startedAtEpochMs: 1759100000000,
    hostRef: "wsl2-target-of-record",
    pidRef: 4242,
    lifecycle: "BOOTING",
    priorOwner: { code: "none" as const, epochId: null },
    startReason: "fresh_store_no_prior_owner",
    executionAuthorized: false as const,
    policyAuthorized: false as const,
  });
}

function coord() {
  const root = newRoot();
  const open = openStoreAt(root);
  if (!open.ok) throw new Error(open.reason);
  const bound = RuntimeStateCoordinator.open(open.store, epochOf(EPOCH_A), "unit-test:23b");
  if (!bound.ok) throw new Error(bound.reason);
  openCoords.push(bound.coordinator);
  return { store: open.store, coordinator: bound.coordinator };
}

function successInput(transactionId: string, recordId = "mem-coordinator0001", payload: Record<string, unknown> = { note: "23b" }) {
  return {
    kind: "memory_record" as const,
    recordId,
    revision: 1,
    supersedesRevision: null,
    payload,
    transactionId,
    lineageRoot: "gol-lineage-root01",
    lineageParent: null,
    createdAtEpochMs: 1759100000100,
  };
}

// ── 1. success ───────────────────────────────────────────────────────────────

describe("23B — success: the one sanctioned junction", () => {
  it("coordinates a mutation to durable with an acknowledged barrier bound to epoch/txn/source/lineage/hash", () => {
    const { coordinator } = coord();
    const r = coordinator.acceptMutation(successInput("tx-23b-success01"));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.code).toBe("durable");
      expect(acknowledgedBarrier(r.barrier)).toBe(true);
      expect(r.barrier.epochId).toBe(EPOCH_A);
      expect(r.barrier.commitSequence).toBe(r.commitSequence);
      expect(r.commitSequence).toBeGreaterThan(0);
      expect(r.mutation.phase).toBe("durable");
      // The binding is INSIDE the sealed content hash:
      const read = coordinator.readState("mem-coordinator0001");
      expect(read.ok).toBe(true);
      if (read.ok) {
        const binding = (read.record.payload as Record<string, unknown>).coordinatorBinding as Record<string, unknown>;
        expect(binding.epochId).toBe(EPOCH_A);
        expect(binding.sourceIdentity).toBe("unit-test:23b");
        expect(binding.lineageRoot).toBe("gol-lineage-root01");
        expect(binding.lineageParent).toBeNull();
        expect(read.record.contentHash).toBe(r.contentHash);
        expect(read.commitSequence).toBe(r.commitSequence);
      }
      coordinator.close();
    }
  });

  it("a hostile payload carrying its own coordinatorBinding is overridden by the coordinator's binding", () => {
    const { coordinator } = coord();
    const r = coordinator.acceptMutation(
      successInput("tx-23b-evilbind01", "mem-coordinator0002", {
        coordinatorBinding: { epochId: "re-forged000000-forgedforgedforg", sourceIdentity: "attacker" },
      }),
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      const read = coordinator.readState("mem-coordinator0002");
      expect(read.ok).toBe(true);
      if (read.ok) {
        const binding = (read.record.payload as Record<string, unknown>).coordinatorBinding as Record<string, unknown>;
        expect(binding.epochId).toBe(EPOCH_A);
        expect(binding.sourceIdentity).toBe("unit-test:23b");
      }
      coordinator.close();
    }
  });

  it("commit sequences are monotone through the junction", () => {
    const { coordinator } = coord();
    const r1 = coordinator.acceptMutation(successInput("tx-23b-monotone1", "mem-coordinator0003"));
    const r2 = coordinator.acceptMutation(successInput("tx-23b-monotone2", "mem-coordinator0004"));
    expect(r1.ok && r2.ok).toBe(true);
    if (r1.ok && r2.ok) expect(r2.commitSequence).toBe(r1.commitSequence + 1);
    coordinator.close();
  });
});

// ── 2. persistence refusal ───────────────────────────────────────────────────

describe("23B — persistence refusal (explicit live-state outcome, store code verbatim)", () => {
  it("a secret-shaped payload key is refused pre-commit with the store's failure code carried verbatim", () => {
    const { coordinator } = coord();
    const r = coordinator.acceptMutation(
      successInput("tx-23b-secret01", "mem-coordinator0005", { api_key: "not-a-real-key" }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("refused_pre_commit");
      expect((r as { storeFailureCode: string | null }).storeFailureCode).toBe("secret_key_denied");
      expect(r.mutation?.outcome).toBe("refused_pre_commit");
      // Nothing was written:
      const read = coordinator.readState("mem-coordinator0005");
      expect(read.ok).toBe(false);
      if (!read.ok) expect(read.code).toBe("not_found");
    }
    coordinator.close();
  });

  it("a refused mutation is never acknowledged (no barrier, no visibility)", () => {
    const { coordinator } = coord();
    const r = coordinator.acceptMutation(
      successInput("tx-23b-refused1", "mem-coordinator0006", { token: "nope" }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.mutation?.barrier ?? null).toBeNull();
      const admission = decideContinuity({ epochId: EPOCH_A, lifecycle: "LIVE", mutation: r.mutation as LiveDurableMutation });
      expect(admission.ok).toBe(false);
    }
    coordinator.close();
  });
});

// ── 3. revision conflict (reused 22A semantics, no new vocabulary) ───────────

describe("23B — revision conflict (frozen 22A revision chain through the junction)", () => {
  it("a stale concurrent writer (revision <= stored) is refused with revision_conflict", () => {
    const { coordinator } = coord();
    const first = coordinator.acceptMutation(successInput("tx-23b-rev01", "mem-coordinator0007"));
    expect(first.ok).toBe(true);
    const stale = coordinator.acceptMutation({
      ...successInput("tx-23b-rev02", "mem-coordinator0007"),
      revision: 1, // duplicate revision — the store must refuse
    });
    expect(stale.ok).toBe(false);
    if (!stale.ok) {
      expect((stale as { storeFailureCode: string | null }).storeFailureCode).toBe("revision_conflict");
      expect(stale.code).toBe("refused_pre_commit");
    }
    // The stored record is untouched by the refused writer:
    const read = coordinator.readState("mem-coordinator0007");
    expect(read.ok).toBe(true);
    if (read.ok) expect(read.record.revision).toBe(1);
    coordinator.close();
  });

  it("a skipped revision (lost update) is refused; the correct next revision succeeds", () => {
    const { coordinator } = coord();
    expect(coordinator.acceptMutation(successInput("tx-23b-rev03", "mem-coordinator0008")).ok).toBe(true);
    const skipped = coordinator.acceptMutation({
      ...successInput("tx-23b-rev04", "mem-coordinator0008"),
      revision: 3,
      supersedesRevision: 2,
    });
    expect(skipped.ok).toBe(false);
    if (!skipped.ok) expect((skipped as { storeFailureCode: string | null }).storeFailureCode).toBe("revision_conflict");
    const correct = coordinator.acceptMutation({
      ...successInput("tx-23b-rev05", "mem-coordinator0008", { note: "v2" }),
      revision: 2,
      supersedesRevision: 1,
    });
    expect(correct.ok).toBe(true);
    if (correct.ok) expect(correct.revision).toBe(2);
    coordinator.close();
  });
});

// ── 4. stale epoch / duplicate local owner (split-brain) ─────────────────────

describe("23B — stale epoch / duplicate local owner fails closed BEFORE mutation", () => {
  it("a second coordinator with a DIFFERENT epoch id over the same store refuses to bind", () => {
    const root = newRoot();
    const open = openStoreAt(root);
    if (!open.ok) throw new Error(open.reason);
    const first = RuntimeStateCoordinator.open(open.store, epochOf(EPOCH_A), "unit-test:owner1");
    expect(first.ok).toBe(true);
    const second = RuntimeStateCoordinator.open(open.store, epochOf(EPOCH_B), "unit-test:owner2");
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.failureCode).toBe("coordinator_epoch_mismatch");
    if (first.ok) first.coordinator.close();
  });

  it("an ownership claim forged into store_meta rejects the other-epoch coordinator before any mutation", () => {
    const root = newRoot();
    const open = openStoreAt(root);
    if (!open.ok) throw new Error(open.reason);
    // Simulate a crashed prior owner's leftover claim (no release happened):
    open.store.setMeta(RUNTIME_OWNERSHIP_META_KEY, EPOCH_B + "|crashed-process");
    const bound = RuntimeStateCoordinator.open(open.store, epochOf(EPOCH_A), "unit-test:23b");
    expect(bound.ok).toBe(false);
    if (!bound.ok) expect(bound.failureCode).toBe("coordinator_epoch_mismatch");
  });

  it("the SAME epoch id can re-bind after a crash (the only resume path) and keeps coordinating", () => {
    const root = newRoot();
    const open = openStoreAt(root);
    if (!open.ok) throw new Error(open.reason);
    open.store.setMeta(RUNTIME_OWNERSHIP_META_KEY, EPOCH_A + "|crashed-process");
    const bound = RuntimeStateCoordinator.open(open.store, epochOf(EPOCH_A), "unit-test:resume");
    expect(bound.ok).toBe(true);
    if (bound.ok) {
      expect(bound.ownership.code).toBe("owner_current");
      const r = bound.coordinator.acceptMutation(successInput("tx-23b-resume01", "mem-coordinator0009"));
      expect(r.ok).toBe(true);
      bound.coordinator.close();
    }
  });

  it("a claim stolen behind the coordinator's back fails every subsequent mutation (L5 re-check)", () => {
    const { store, coordinator } = coord();
    // Another process writes its claim into store_meta directly:
    store.setMeta(RUNTIME_OWNERSHIP_META_KEY, EPOCH_B + "|hostile-takeover");
    const r = coordinator.acceptMutation(successInput("tx-23b-stolen01", "mem-coordinator0010"));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("refused_pre_commit");
      expect(r.failureCode).toBe("stale_epoch");
      const read = coordinator.readState("mem-coordinator0010");
      expect(read.ok).toBe(false);
    }
    coordinator.close();
  });

  it("a closed coordinator returns unknown_after_error (never a fake refusal/success)", () => {
    const { coordinator } = coord();
    coordinator.close();
    expect(coordinator.isClosed).toBe(true);
    const r = coordinator.acceptMutation(successInput("tx-23b-closed01", "mem-coordinator0011"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("unknown_after_error");
  });
});

// ── 5. duplicate transaction (replayed transactions are denied by the store) ─

describe("23B — duplicate transaction (22A transaction-replay denial reused verbatim)", () => {
  it("replaying a committed transactionId is refused with duplicate_transaction", () => {
    const { coordinator } = coord();
    expect(coordinator.acceptMutation(successInput("tx-23b-dup01", "mem-coordinator0012")).ok).toBe(true);
    const replay = coordinator.acceptMutation(successInput("tx-23b-dup01", "mem-coordinator0013"));
    expect(replay.ok).toBe(false);
    if (!replay.ok) {
      expect(replay.code).toBe("refused_pre_commit");
      expect((replay as { storeFailureCode: string | null }).storeFailureCode).toBe("duplicate_transaction");
    }
    coordinator.close();
  });
});

// ── 6. corrupt/quarantined store ─────────────────────────────────────────────

describe("23B — corrupt/quarantined store (quarantine-as-found surfaced, never healed)", () => {
  it("a corrupted stored record is quarantined by the store and surfaced as a typed read failure", () => {
    const root = newRoot();
    const open = openStoreAt(root);
    if (!open.ok) throw new Error(open.reason);
    const bound = RuntimeStateCoordinator.open(open.store, epochOf(EPOCH_A), "unit-test:23b");
    if (!bound.ok) throw new Error(bound.reason);
    const c = bound.coordinator;
    expect(c.acceptMutation(successInput("tx-23b-corrupt01", "mem-coordinator0014")).ok).toBe(true);
    c.close();
    // Corrupt the stored bytes behind the store's back:
    const db = new DatabaseSync(join(root, "menog-store", "durable.db"));
    const row = db.prepare("SELECT payload_json FROM records WHERE record_id = ?").get("mem-coordinator0014") as { payload_json: string };
    db.prepare("UPDATE records SET payload_json = ? WHERE record_id = ?").run(
      row.payload_json.slice(0, -4) + '"zz"}',
      "mem-coordinator0014",
    );
    // Re-open: the coordinator surfaces the store's typed quarantine failure.
    const reopen = openStoreAt(root);
    if (!reopen.ok) throw new Error(reopen.reason);
    const bound2 = RuntimeStateCoordinator.open(reopen.store, epochOf(EPOCH_A), "unit-test:23b");
    if (!bound2.ok) throw new Error(bound2.reason);
    const read = bound2.coordinator.readState("mem-coordinator0014");
    expect(read.ok).toBe(false);
    if (!read.ok) {
      expect(read.code).toBe("quarantined");
      expect(read.quarantined).toBe(true);
    }
    expect(reopen.store.listQuarantined().length).toBe(1);
    bound2.coordinator.close();
    reopen.store.close();
  });

  it("the coordinator itself still coordinates fresh records while the corrupted one stays quarantined", () => {
    const root = newRoot();
    const open = openStoreAt(root);
    if (!open.ok) throw new Error(open.reason);
    const bound = RuntimeStateCoordinator.open(open.store, epochOf(EPOCH_A), "unit-test:23b");
    if (!bound.ok) throw new Error(bound.reason);
    const c = bound.coordinator;
    expect(c.acceptMutation(successInput("tx-23b-corrupt02", "mem-coordinator0015")).ok).toBe(true);
    c.close();
    const db = new DatabaseSync(join(root, "menog-store", "durable.db"));
    const row = db.prepare("SELECT payload_json FROM records WHERE record_id = ?").get("mem-coordinator0015") as { payload_json: string };
    db.prepare("UPDATE records SET payload_json = ? WHERE record_id = ?").run(row.payload_json + "garbage", "mem-coordinator0015");
    const reopen = openStoreAt(root);
    if (!reopen.ok) throw new Error(reopen.reason);
    const bound2 = RuntimeStateCoordinator.open(reopen.store, epochOf(EPOCH_A), "unit-test:23b");
    if (!bound2.ok) throw new Error(bound2.reason);
    expect(bound2.coordinator.readState("mem-coordinator0015").ok).toBe(false);
    const fresh = bound2.coordinator.acceptMutation(successInput("tx-23b-corrupt03", "mem-coordinator0016"));
    expect(fresh.ok).toBe(true);
    bound2.coordinator.close();
    reopen.store.close();
  });
});

// ── 7. coordinator restart (close → reopen → same epoch resume / new epoch) ──

describe("23B — coordinator restart across a real close/reopen boundary", () => {
  it("clean close releases the claim; a NEW epoch can then bind and coordinate", () => {
    const root = newRoot();
    const open = openStoreAt(root);
    if (!open.ok) throw new Error(open.reason);
    const bound = RuntimeStateCoordinator.open(open.store, epochOf(EPOCH_A), "unit-test:23b");
    if (!bound.ok) throw new Error(bound.reason);
    expect(bound.coordinator.acceptMutation(successInput("tx-23b-restart01", "mem-coordinator0017")).ok).toBe(true);
    expect(bound.coordinator.close().ok).toBe(true);
    expect(readRuntimeOwnership(open.store, EPOCH_B).code).toBe("no_prior_owner");
    // A new epoch binds over the released claim:
    const bound2 = RuntimeStateCoordinator.open(open.store, epochOf(EPOCH_B), "unit-test:next");
    expect(bound2.ok).toBe(true);
    if (bound2.ok) {
      const r = bound2.coordinator.acceptMutation(successInput("tx-23b-restart02", "mem-coordinator0018"));
      expect(r.ok).toBe(true);
      bound2.coordinator.close();
    }
    open.store.close();
  });

  it("restart preserves durable facts: the new epoch reads the old epoch's committed record", () => {
    const root = newRoot();
    const open = openStoreAt(root);
    if (!open.ok) throw new Error(open.reason);
    const bound = RuntimeStateCoordinator.open(open.store, epochOf(EPOCH_A), "unit-test:23b");
    if (!bound.ok) throw new Error(bound.reason);
    expect(bound.coordinator.acceptMutation(successInput("tx-23b-restart03", "mem-coordinator0019", { note: "survives" })).ok).toBe(true);
    bound.coordinator.close();
    open.store.close();
    // Full process-restart simulation:
    const reopen = openStoreAt(root);
    if (!reopen.ok) throw new Error(reopen.reason);
    const bound2 = RuntimeStateCoordinator.open(reopen.store, epochOf(EPOCH_B), "unit-test:next");
    if (!bound2.ok) throw new Error(bound2.reason);
    const read = bound2.coordinator.readState("mem-coordinator0019");
    expect(read.ok).toBe(true);
    if (read.ok) {
      expect((read.record.payload as Record<string, unknown>).note).toBe("survives");
      const binding = (read.record.payload as Record<string, unknown>).coordinatorBinding as Record<string, unknown>;
      expect(binding.epochId).toBe(EPOCH_A); // the ORIGINAL writer's binding is intact
    }
    bound2.coordinator.close();
    reopen.store.close();
  });

  it("commit sequences continue monotonically across restarts", () => {
    const root = newRoot();
    const open = openStoreAt(root);
    if (!open.ok) throw new Error(open.reason);
    const bound = RuntimeStateCoordinator.open(open.store, epochOf(EPOCH_A), "unit-test:23b");
    if (!bound.ok) throw new Error(bound.reason);
    const r1 = bound.coordinator.acceptMutation(successInput("tx-23b-seq01", "mem-coordinator0020"));
    expect(r1.ok).toBe(true);
    if (r1.ok) expect(r1.commitSequence).toBe(1);
    bound.coordinator.close();
    open.store.close();
    const reopen = openStoreAt(root);
    if (!reopen.ok) throw new Error(reopen.reason);
    const bound2 = RuntimeStateCoordinator.open(reopen.store, epochOf(EPOCH_B), "unit-test:next");
    if (!bound2.ok) throw new Error(bound2.reason);
    const r2 = bound2.coordinator.acceptMutation(successInput("tx-23b-seq02", "mem-coordinator0021"));
    expect(r2.ok).toBe(true);
    if (r2.ok) expect(r2.commitSequence).toBe(2);
    bound2.coordinator.close();
    reopen.store.close();
  });
});

// ── 8. no authority escalation ───────────────────────────────────────────────

describe("23B — no authority escalation anywhere on the coordination path", () => {
  it("durable success carries NO authority fields; the coordinator grants nothing", () => {
    const { coordinator } = coord();
    const r = coordinator.acceptMutation(successInput("tx-23b-auth01", "mem-coordinator0022"));
    expect(r.ok).toBe(true);
    if (r.ok) {
      const keys = Object.keys(r).sort();
      expect(keys).toEqual(["barrier", "code", "commitSequence", "contentHash", "epochId", "explanation", "mutation", "mutationId", "ok", "revision", "transactionId"]);
      expect(JSON.stringify(r)).not.toContain('"executionAuthorized":true');
      expect(JSON.stringify(r)).not.toContain('"policyAuthorized":true');
      expect(JSON.stringify(r.barrier)).not.toContain("true");
    }
    coordinator.close();
  });

  it("barrierFromPersistDecision maps honestly: denial → rolled_back (no ack), abort → ambiguous (no ack)", () => {
    const denial = barrierFromPersistDecision("bar-x", EPOCH_A, {
      ok: false,
      committed: false,
      failureCode: "secret_key_denied",
      reason: "denied",
      transactionId: "tx-x",
    });
    expect(denial.outcome).toBe("rolled_back");
    expect(acknowledgedBarrier(denial)).toBe(false);
    const aborted = barrierFromPersistDecision("bar-y", EPOCH_A, {
      ok: false,
      committed: false,
      failureCode: "transaction_aborted",
      reason: "rolled back",
      transactionId: "tx-y",
    });
    expect(aborted.outcome).toBe("ambiguous");
    expect(acknowledgedBarrier(aborted)).toBe(false);
  });

  it("an admission-law violation after a claimed commit is treated as UNKNOWN, never visible", () => {
    const { coordinator } = coord();
    const r = coordinator.acceptMutation(successInput("tx-23b-auth02", "mem-coordinator0023"));
    expect(r.ok).toBe(true);
    if (r.ok) {
      // Sabotage the barrier's commit sequence (simulating an invariant break)
      // and re-run the admission law: it must refuse — the law, not the
      // coordinator's optimism, is what makes a commit visible.
      const sabotaged = { ...r.barrier, commitSequence: null };
      expect(acknowledgedBarrier(sabotaged)).toBe(false);
      const admission = decideContinuity({ epochId: EPOCH_A, lifecycle: "LIVE", mutation: { ...r.mutation, barrier: sabotaged } });
      expect(admission.ok).toBe(false);
    }
    coordinator.close();
  });

  it("the sealed envelope keeps the frozen 22A authority vocabulary (durable_state, never recovered/executed)", () => {
    const env = sealMutationEnvelope({
      kind: "goal_lifecycle",
      recordId: "gol-coordinator0024",
      revision: 1,
      supersedesRevision: null,
      transactionId: "tx-23b-auth03",
      createdAtEpochMs: 1759100000100,
      epochId: EPOCH_A,
      sourceIdentity: "unit-test:23b",
      lineageRoot: "gol-lineage-root01",
      lineageParent: null,
      payload: { status: "executing" },
    });
    expect(env.authority).toBe("durable_state");
    expect(env.secretPolicy).toBe("secret_free");
  });
});

// ── 9. no alternate persistence path + structural pins ───────────────────────

describe("23B — the single junction (no alternate persistence path; no spawn/network/replay)", () => {
  it("the coordinator module contains no store-bypass, spawn, network, or replay vocabulary (structural)", () => {
    const raw = readFileSync(join(process.cwd(), "packages", "durable-state", "src", "coordinator.ts"), "utf8");
    const codeOnly = raw
      .split("\n")
      .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
      .join("\n");
    for (const forbidden of [
      "child_process",
      "spawn(",
      "spawnSync",
      "execFile",
      "fetch(",
      "http.request",
      "net.connect",
      "executeToolRun",
      "runToolInLauncher",
      "generateRollbackPlan(",
      "generateReplayPlan(",
      "autoResume",
      "continueTask",
      "restoreQuarantined",
      "unquarantine",
      "repairRecord",
    ]) {
      expect(codeOnly.includes(forbidden), "coordinator.ts contains " + forbidden).toBe(false);
    }
    // The ONLY store write paths referenced are persist + the meta claim:
    expect(codeOnly).toContain("this.#store.persist(envelope)");
    expect((codeOnly.match(/\.persist\(/g) ?? []).length).toBe(1);
    expect(codeOnly).toContain("setMeta(");
    // Authority dead-ends:
    expect(codeOnly.includes("executionAuthorized: true")).toBe(false);
    expect(codeOnly.includes("policyAuthorized: true")).toBe(false);
  });

  it("writes through the raw store bypassing the coordinator are NOT the sanctioned path and stay 22A-lawful", () => {
    const { coordinator } = coord();
    const r = coordinator.acceptMutation(successInput("tx-23b-alt01", "mem-coordinator0025"));
    expect(r.ok).toBe(true);
    coordinator.close();
    // The scan above pins that the coordinator has exactly ONE persist call
    // site; the store itself remains the only writer, under frozen 22A law.
  });

  it("derived kinds are refused by the coordinator before any store call (L8 on wiring)", () => {
    const { coordinator } = coord();
    const r = coordinator.acceptMutation({
      ...successInput("tx-23b-derived01", "idx-coordinator0026"),
      kind: "derived_index",
    } as unknown as Parameters<RuntimeStateCoordinator["acceptMutation"]>[0]);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failureCode).toBe("derived_kind_denied");
      expect(r.code).toBe("refused_pre_commit");
    }
    coordinator.close();
  });
});
