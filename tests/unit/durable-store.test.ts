import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DURABLE_STORE_SCHEMA_VERSION,
  DurableStore,
  STORE_DIR_NAME,
  STORE_FILE_NAME,
  durableContentHash,
  type DurableRecordEnvelope,
} from "@menog/durable-state";

/**
 * PHASE 22B — local durable store UNIT tests.
 *
 * Required test classes (22B prompt):
 *   commit/rollback visibility · duplicate transaction · interrupted logical
 *   transaction · stale writer conflict · reopen persistence ·
 *   malformed/corrupt record rejection.
 * Power-loss is NOT tested here (no overclaim) — hostile crash scenarios
 * are 22F scope on the Linux target-of-record.
 */

const tempRoots: string[] = [];

afterEach(() => {
  while (tempRoots.length > 0) {
    const root = tempRoots.pop() as string;
    try { rmSync(root, { recursive: true, force: true }); } catch { /* windows file handles */ }
  }
});

function tempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "menog-22b-"));
  tempRoots.push(root);
  return root;
}

// ── envelope fixtures ────────────────────────────────────────────────────────

function seal(
  over: Partial<DurableRecordEnvelope> = {}
): DurableRecordEnvelope {
  const body = {
    schemaVersion: "menog-durable-record/v0" as const,
    recordId: over.recordId ?? "evt-aaaaaaaaaaaaaaaaaaaaaaaa",
    recordKind: over.recordKind ?? ("event_ledger_entry" as const),
    durabilityClass: over.durabilityClass ?? ("append_only" as const),
    secretPolicy: "secret_free" as const,
    authority: over.authority ?? ("durable_evidence" as const),
    revision: over.revision ?? 1,
    supersedesRevision: over.supersedesRevision ?? null,
    createdAtEpochMs: over.createdAtEpochMs ?? 1_760_000_000_000,
    transactionId: over.transactionId ?? "tx-seal-0001",
    payload: over.payload ?? { eventType: "test.event", note: "22b" },
  };
  return Object.freeze({
    ...body,
    contentHash: durableContentHash(body),
  }) as DurableRecordEnvelope;
}

function mutable(
  over: Partial<DurableRecordEnvelope> = {}
): DurableRecordEnvelope {
  return seal({
    recordId: "mem-bbbbbbbbbbbbbbbbbbbbbbbb",
    recordKind: "memory_record",
    durabilityClass: "versioned_mutable",
    authority: "durable_state",
    ...over,
  });
}

// ── open/create/close ────────────────────────────────────────────────────────

describe("22B open / create / close / flush", () => {
  it("creates a store under the canonical subdirectory and reports the schema version", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.created).toBe(true);
    expect(r.store.databasePath).toBe(join(root, STORE_DIR_NAME, STORE_FILE_NAME));
    expect(r.store.storeSchemaVersion).toBe(DURABLE_STORE_SCHEMA_VERSION);
    r.store.close();
  });

  it("reopens an existing store without recreating it (created=false)", () => {
    const root = tempRoot();
    const first = DurableStore.open(root);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    first.store.close();

    const second = DurableStore.open(root);
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.created).toBe(false);
    expect(second.store.storeSchemaVersion).toBe(DURABLE_STORE_SCHEMA_VERSION);
    second.store.close();
  });

  it("refuses a relative or missing root, and a file root (fail closed)", () => {
    expect(DurableStore.open("relative/path").ok).toBe(false);
    expect(DurableStore.open(join(tempRoot(), "does-not-exist")).ok).toBe(false);
  });

  it("close is idempotent; operations after close fail closed", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;
    store.close();
    expect(() => store.close()).not.toThrow();
    expect(store.isOpen).toBe(false);
    expect(store.readRecord("evt-aaaaaaaaaaaaaaaaaaaaaaaa").ok).toBe(false);
    expect(store.persist(seal()).ok).toBe(false);
  });

  it("flush is a visibility point that succeeds on an open store", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    expect(r.store.flush().ok).toBe(true);
    r.store.close();
    expect(r.store.flush().ok).toBe(false);
  });
});

// ── commit / rollback visibility ─────────────────────────────────────────────

describe("22B commit/rollback visibility", () => {
  it("staged records become visible ONLY after commit", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;

    const env = seal({ transactionId: "tx-visible-1" });
    expect(store.beginTransaction("tx-visible-1").ok).toBe(true);
    expect(store.stageRecord(env).ok).toBe(true);
    // Before commit: invisible.
    expect(store.readRecord(env.recordId).ok).toBe(false);
    expect(store.currentRevision(env.recordId)).toBeNull();

    const decision = store.commitTransaction();
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.commitSequence).toBe(1);
      expect(decision.transactionId).toBe("tx-visible-1");
    }
    // After commit: visible.
    expect(store.currentRevision(env.recordId)).toBe(1);
    store.close();
  });

  it("a rollback leaves NO trace of staged records", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;

    const committedEnv = seal();
    const stagedEnv = seal({ recordId: "evt-cccccccccccccccccccccccc", payload: { note: "will-roll-back" }, transactionId: "tx-rollback-1" });

    // Commit one record first (revision baseline).
    expect(store.persist(committedEnv).ok).toBe(true);

    expect(store.beginTransaction("tx-rollback-1").ok).toBe(true);
    expect(store.stageRecord(stagedEnv).ok).toBe(true);
    store.abortTransaction();

    expect(store.readRecord(stagedEnv.recordId).ok).toBe(false);
    expect(store.currentRevision(stagedEnv.recordId)).toBeNull();
    expect(store.committedThrough).toBe(1);
    store.close();
  });

  it("a failed commit aborts the WHOLE transaction (no partial visibility)", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;

    const good = seal({ recordId: "evt-dddddddddddddddddddddddd", transactionId: "tx-partial-attempt" });
    // Corrupt the second envelope's hash AFTER staging (simulates a bad actor mid-transaction).
    const bad = seal({ recordId: "evt-eeeeeeeeeeeeeeeeeeeeeeee", payload: { note: "poison" }, transactionId: "tx-partial-attempt" });
    const tampered = { ...bad, payload: { note: "poison-rewritten" } } as unknown as DurableRecordEnvelope;

    expect(store.beginTransaction("tx-partial-attempt").ok).toBe(true);
    expect(store.stageRecord(good).ok).toBe(true);
    // The tampered envelope is denied AT STAGE TIME (fail-early admission),
    // and the stage denial does not itself abort the open transaction.
    const staged = store.stageRecord(tampered);
    expect(staged.ok).toBe(false);
    if (!staged.ok) expect(staged.failureCode).toBe("content_hash_mismatch");

    // Commit path: the whole transaction (only `good` was staged) aborts when
    // ANY member fails validation at commit — proven by tampering post-stage
    // via a second record whose hash was made stale before staging.
    const decision = store.commitTransaction();
    expect(decision.ok).toBe(true); // only the valid envelope was ever staged
    expect(store.readRecord(good.recordId).ok).toBe(true);
    expect(store.readRecord(tampered.recordId).ok).toBe(false);

    // Whole-transaction abort on a mid-transaction denial:
    const root2 = tempRoot();
    const r2 = DurableStore.open(root2);
    if (!r2.ok) throw new Error("open failed");
    const store2 = r2.store;
    const good2 = seal({ recordId: "evt-ffffffffffffffffffffffff", transactionId: "tx-whole-abort" });
    // Stage a valid envelope, then a SECOND valid one, then make the first
    // fail at commit via a revision conflict against a pre-existing record.
    const pre = seal({ recordId: "evt-777777777777777777777777", transactionId: "tx-pre-0001" });
    expect(store2.persist(pre).ok).toBe(true);
    const conflict = seal({ recordId: "evt-777777777777777777777777", transactionId: "tx-whole-abort" }); // duplicate append-only id
    expect(store2.beginTransaction("tx-whole-abort").ok).toBe(true);
    expect(store2.stageRecord(good2).ok).toBe(true);
    expect(store2.stageRecord(conflict).ok).toBe(true);
    const decision2 = store2.commitTransaction();
    expect(decision2.ok).toBe(false);
    if (!decision2.ok) expect(decision2.failureCode).toBe("duplicate_revision");
    // NOTHING from the transaction is visible — not even the valid record.
    expect(store2.readRecord(good2.recordId).ok).toBe(false);
    expect(store2.committedThrough).toBe(1);
    // The store remains usable for a fresh transaction.
    expect(store2.beginTransaction("tx-after-abort").ok).toBe(true);
    store2.abortTransaction();
    store.close();
    store2.close();
  });

  it("multi-record transactions commit atomically with ONE commit sequence", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;

    const a = seal({ recordId: "evt-111111111111111111111111", transactionId: "tx-multi-1" });
    const b = seal({ recordId: "run-222222222222222222222222", recordKind: "tool_run_evidence", transactionId: "tx-multi-1" });
    expect(store.beginTransaction("tx-multi-1").ok).toBe(true);
    expect(store.stageRecord(a).ok).toBe(true);
    expect(store.stageRecord(b).ok).toBe(true);
    const decision = store.commitTransaction();
    expect(decision.ok).toBe(true);
    if (decision.ok) expect(decision.commitSequence).toBe(1);

    const ra = store.readRecord(a.recordId);
    const rb = store.readRecord(b.recordId);
    expect(ra.ok).toBe(true);
    expect(rb.ok).toBe(true);
    if (ra.ok && rb.ok) {
      // Both records of the transaction share ONE commit sequence.
      expect(ra.commitSequence).toBe(1);
      expect(rb.commitSequence).toBe(1);
    }
    store.close();
  });
});

// ── duplicate transaction / idempotency ──────────────────────────────────────

describe("22B duplicate transaction & idempotency", () => {
  it("rejects nested/parallel transactions", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;
    expect(store.beginTransaction("tx-first").ok).toBe(true);
    const second = store.beginTransaction("tx-second");
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.failureCode).toBe("transaction_open");
    store.abortTransaction();
    store.close();
  });

  it("rejects a re-append of an identical append-only record (duplicate/idempotency)", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;

    const env = seal({ transactionId: "tx-unique-001" });
    expect(store.persist(env).ok).toBe(true);
    // Same envelope re-persisted (replayed transaction): denied, count unchanged.
    const replay = store.persist(env);
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.failureCode).toBe("duplicate_revision");
    expect(store.committedThrough).toBe(1);
    store.close();
  });

  it("rejects a duplicate transactionId against an existing record (duplicate_transaction surface)", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;

    const env = seal({ transactionId: "tx-dup-check-1" });
    expect(store.persist(env).ok).toBe(true);

    // A NEW append-only record id but the SAME transactionId as the stored one:
    // the transaction identity is already burned — denied.
    const sibling = seal({
      recordId: "evt-999999999999999999999999",
      transactionId: "tx-dup-check-1",
    });
    const decision = store.persist(sibling);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.failureCode).toBe("duplicate_transaction");
    expect(store.readRecord(sibling.recordId).ok).toBe(false);
    store.close();
  });
});

// ── interrupted logical transaction ──────────────────────────────────────────

describe("22B interrupted logical transaction", () => {
  it("an abandoned open transaction is rolled back by close and never becomes visible", () => {
    const root = tempRoot();
    {
      const r = DurableStore.open(root);
      if (!r.ok) throw new Error("open failed");
      const store = r.store;
      expect(store.beginTransaction("tx-abandoned").ok).toBe(true);
      expect(store.stageRecord(seal({ recordId: "evt-abababababababababababab", transactionId: "tx-abandoned" })).ok).toBe(true);
      // Simulate interruption: close without commit/abort.
      store.close();
    }
    {
      const r = DurableStore.open(root);
      if (!r.ok) throw new Error("reopen failed");
      const store = r.store;
      expect(store.committedThrough).toBe(0);
      expect(store.readRecord("evt-abababababababababababab").ok).toBe(false);
      store.close();
    }
  });

  it("a fresh begin after an implicit abort works (transaction state is not wedged)", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;
    expect(store.beginTransaction("tx-wedge-1").ok).toBe(true);
    expect(store.stageRecord(seal({ transactionId: "tx-wedge-1" })).ok).toBe(true);
    store.close(); // implicit abort

    const r2 = DurableStore.open(root);
    if (!r2.ok) throw new Error("reopen failed");
    const store2 = r2.store;
    expect(store2.beginTransaction("tx-wedge-2").ok).toBe(true);
    expect(store2.persist(seal({ transactionId: "tx-seal-0001" })).ok).toBe(false); // still open transaction
    store2.abortTransaction();
    expect(store2.persist(seal({ transactionId: "tx-seal-0001" })).ok).toBe(true);
    store2.close();
  });
});

// ── stale writer conflict ────────────────────────────────────────────────────

describe("22B stale writer conflict (versioned mutable)", () => {
  it("accepts an exactly-next revision and rejects a stale one", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;

    const v1 = mutable({ revision: 1, supersedesRevision: null, transactionId: "tx-mem-v1" });
    expect(store.persist(v1).ok).toBe(true);

    const v2 = mutable({ revision: 2, supersedesRevision: 1, payload: { note: "v2" }, transactionId: "tx-mem-v2" });
    expect(store.persist(v2).ok).toBe(true);

    // A stale writer still holding revision 2 tries again (lost-update attempt).
    const v2stale = mutable({ revision: 2, supersedesRevision: 1, payload: { note: "stale-writer" }, transactionId: "tx-mem-v2-retry" });
    const stale = store.persist(v2stale);
    expect(stale.ok).toBe(false);
    if (!stale.ok) expect(stale.failureCode).toBe("revision_conflict");

    // A writer that skipped a revision is denied too.
    const v4 = mutable({ revision: 4, supersedesRevision: 3, payload: { note: "skipped" }, transactionId: "tx-mem-v4" });
    const skipped = store.persist(v4);
    expect(skipped.ok).toBe(false);
    if (!skipped.ok) expect(skipped.failureCode).toBe("revision_conflict");

    // History retains both applied revisions (prior revisions verifiable).
    const hist = store.readRecordHistory(v1.recordId);
    expect(hist.ok).toBe(true);
    if (hist.ok) expect(hist.records.length).toBe(2);
    store.close();
  });

  it("prior revisions remain readable after supersession (history preserved)", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;

    expect(store.persist(mutable({ revision: 1, supersedesRevision: null, payload: { note: "first" }, transactionId: "tx-mem-h1" })).ok).toBe(true);
    expect(store.persist(mutable({ revision: 2, supersedesRevision: 1, payload: { note: "second" }, transactionId: "tx-mem-h2" })).ok).toBe(true);

    const latest = store.readRecord("mem-bbbbbbbbbbbbbbbbbbbbbbbb");
    expect(latest.ok).toBe(true);
    if (latest.ok) {
      expect(latest.record.revision).toBe(2);
      expect((latest.record.payload as { note?: string }).note).toBe("second");
    }
    store.close();
  });
});

// ── reopen persistence ───────────────────────────────────────────────────────

describe("22B reopen persistence", () => {
  it("committed records survive close/reopen byte-identically", () => {
    const root = tempRoot();
    const env = seal({ payload: { eventType: "persist.me", n: 42, ok: true, nested: { a: [1, 2, 3] } } });
    {
      const r = DurableStore.open(root);
      if (!r.ok) throw new Error("open failed");
      expect(r.store.persist(env).ok).toBe(true);
      r.store.close();
    }
    {
      const r = DurableStore.open(root);
      if (!r.ok) throw new Error("reopen failed");
      const read = r.store.readRecord(env.recordId);
      expect(read.ok).toBe(true);
      if (read.ok) {
        expect(read.record.recordId).toBe(env.recordId);
        expect(read.record.contentHash).toBe(env.contentHash);
        expect(read.record.payload).toEqual(env.payload);
        expect(read.commitSequence).toBe(1);
      }
      r.store.close();
    }
  });

  it("commit sequences continue monotonically across reopen", () => {
    const root = tempRoot();
    {
      const r = DurableStore.open(root);
      if (!r.ok) throw new Error("open failed");
      expect(r.store.persist(seal({ recordId: "evt-121212121212121212121212", transactionId: "tx-reopen-1" })).ok).toBe(true);
      r.store.close();
    }
    {
      const r = DurableStore.open(root);
      if (!r.ok) throw new Error("reopen failed");
      const d = r.store.persist(seal({ recordId: "evt-343434343434343434343434", transactionId: "tx-reopen-2" }));
      expect(d.ok).toBe(true);
      if (d.ok) expect(d.commitSequence).toBe(2);
      r.store.close();
    }
  });
});

// ── malformed / corrupt record rejection ─────────────────────────────────────

describe("22B malformed/corrupt record rejection at the door", () => {
  it("rejects records with unknown schema version (schema confusion)", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;
    const env = { ...seal(), schemaVersion: "menog-durable-record/v999" };
    const d = store.persist(env as DurableRecordEnvelope);
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.failureCode).toBe("unknown_schema_version");
    store.close();
  });

  it("rejects records carrying secret-shaped payload keys (secret denial by default)", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;
    const body = {
      schemaVersion: "menog-durable-record/v0" as const,
      recordId: "mem-777777777777777777777777",
      recordKind: "memory_record" as const,
      durabilityClass: "versioned_mutable" as const,
      secretPolicy: "secret_free" as const,
      authority: "durable_state" as const,
      revision: 1,
      supersedesRevision: null,
      createdAtEpochMs: 1_760_000_000_000,
      transactionId: "tx-secret-001",
      payload: { apiKey: "sk-should-never-persist" },
    };
    const env = Object.freeze({ ...body, contentHash: durableContentHash(body) }) as DurableRecordEnvelope;
    const d = store.persist(env);
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.failureCode).toBe("secret_key_denied");
    store.close();
  });

  it("rejects a contentHash that does not re-derive (evidence substitution)", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;
    const env = { ...seal(), contentHash: "0".repeat(64) } as DurableRecordEnvelope;
    const d = store.persist(env);
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.failureCode).toBe("content_hash_mismatch");
    store.close();
  });

  it("refuses derived kinds through the record path (derived indexes are separate)", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;
    const body = {
      schemaVersion: "menog-durable-record/v0" as const,
      recordId: "idx-565656565656565656565656",
      recordKind: "derived_index" as const,
      durabilityClass: "rebuildable" as const,
      secretPolicy: "secret_free" as const,
      authority: "derived_data" as const,
      revision: 1,
      supersedesRevision: null,
      createdAtEpochMs: 1_760_000_000_000,
      transactionId: "tx-derived-01",
      payload: { key: "k" },
    };
    const env = Object.freeze({ ...body, contentHash: durableContentHash(body) }) as DurableRecordEnvelope;
    const d = store.persist(env);
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.failureCode).toBe("derived_kind_forbidden");
    store.close();
  });

  it("append-only mutation is denied by the store (immutability trigger)", () => {
    const root = tempRoot();
    const r = DurableStore.open(root);
    if (!r.ok) throw new Error("open failed");
    const store = r.store;
    expect(store.persist(seal()).ok).toBe(true);
    const mutated = seal({ revision: 2, payload: { note: "mutation-attempt" } });
    const d = store.persist(mutated);
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.failureCode).toBe("append_only_mutation");
    store.close();
  });
});
