import { describe, it, expect } from "vitest";
import {
  WorkingMemoryStore,
  ProjectMemoryStore,
  scopeCovers,
  memoryRecordHash,
  serializeMemoryRecord,
  serializeMemoryBody,
  memoryRecordRoundTrip,
  materializeMemoryRecord,
  validateMemoryRecordInput,
  MEMORY_SCHEMA_VERSION,
  type MemoryPolicyGate,
  type MemoryScope,
} from "@menog/memory";
import { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";

const HUMAN: Actor = { type: "human", id: "human-16a" };
const AGENT: Actor = { type: "agent", id: "agent-16a" };

/** Allow-all policy gate for positive-path unit tests. */
const ALLOW_ALL: MemoryPolicyGate = {
  canReadMemory: () => true,
  canWriteMemory: () => true,
};

function fixedClock(startEpochMs: number): () => number {
  let t = startEpochMs;
  return () => {
    t += 1;
    return t;
  };
}

const T0 = 1_750_000_000_000;

function wmScope(overrides: Partial<MemoryScope> = {}): MemoryScope {
  return { workspaceId: "ws-16a", taskId: "task-16a", sessionId: "sess-16a", ...overrides };
}

function trustedInput(overrides: Record<string, unknown> = {}) {
  return {
    kind: "working",
    scope: wmScope(),
    provenance: { origin: "runtime", actor: AGENT, untrusted: false },
    retention: { retentionClass: "session" },
    body: { fact: "menog uses deny-by-default policy" },
    ...overrides,
  } as Parameters<WorkingMemoryStore["write"]>[1];
}

function makeWorking(options: { policyGate?: MemoryPolicyGate | null; ledger?: AppendOnlyLedger | null; now?: () => number; maxRecords?: number } = {}) {
  return new WorkingMemoryStore({
    policyGate: options.policyGate === undefined ? ALLOW_ALL : options.policyGate,
    ledger: options.ledger ?? null,
    now: options.now ?? fixedClock(T0),
    maxRecords: options.maxRecords,
  });
}

function ctx(actor: Actor = AGENT, scope: MemoryScope = wmScope()) {
  return { actor, grantedScope: scope };
}

describe("16A — scope isolation", () => {
  it("scopeCovers: identical scopes covered", () => {
    expect(scopeCovers(wmScope(), wmScope())).toBe(true);
  });

  it("scopeCovers: different workspaceId never covered", () => {
    expect(scopeCovers(wmScope(), wmScope({ workspaceId: "other-ws" }))).toBe(false);
  });

  it("scopeCovers: narrowing from workspace-level grant is allowed", () => {
    expect(scopeCovers({ workspaceId: "ws" }, { workspaceId: "ws", taskId: "t1" })).toBe(true);
    expect(scopeCovers({ workspaceId: "ws" }, { workspaceId: "ws", sessionId: "s1" })).toBe(true);
  });

  it("scopeCovers: widening from task-level grant denied", () => {
    expect(scopeCovers({ workspaceId: "ws", taskId: "t1" }, { workspaceId: "ws" })).toBe(false);
    expect(scopeCovers({ workspaceId: "ws", taskId: "t1" }, { workspaceId: "ws", taskId: "t2" })).toBe(false);
  });

  it("scopeCovers: widening from session-level grant denied", () => {
    expect(scopeCovers({ workspaceId: "ws", sessionId: "s1" }, { workspaceId: "ws", sessionId: "s2" })).toBe(false);
    expect(scopeCovers({ workspaceId: "ws", sessionId: "s1" }, { workspaceId: "ws" })).toBe(false);
  });

  it("working-memory writes are invisible to a different workspace scope", () => {
    const store = makeWorking();
    const w = store.write(ctx(), trustedInput());
    expect(w.ok).toBe(true);
    const other = store.read(ctx(AGENT, wmScope({ workspaceId: "ws-other" })));
    expect(other.ok).toBe(true);
    if (other.ok) expect(other.records).toHaveLength(0);
  });

  it("a task-scoped caller cannot widen its read to the whole workspace", () => {
    const store = makeWorking();
    // runtime wrote with a task-scoped grant
    store.write(ctx(AGENT, { workspaceId: "ws" }), {
      scope: { workspaceId: "ws", taskId: "t-secret" },
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { secret: "task-only" },
    });
    // caller granted only t-public reads: t-secret entries must be invisible
    const res = store.read(ctx(AGENT, { workspaceId: "ws", taskId: "t-public" }));
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.records).toHaveLength(0);
  });

  it("working and project memory are isolated namespaces", () => {
    const w = makeWorking();
    const p = new ProjectMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    w.write(ctx(), trustedInput());
    const pRead = p.read(ctx(AGENT, { workspaceId: "ws-16a" }));
    expect(pRead.ok).toBe(true);
    if (pRead.ok) expect(pRead.records).toHaveLength(0);
  });

  it("working memory FIFO cap keeps bounded state", () => {
    const store = makeWorking({ maxRecords: 3 });
    for (let i = 0; i < 5; i++) {
      store.write(ctx(), trustedInput({ body: { i } }));
    }
    expect(store.size).toBe(3);
  });
});

describe("16A — serialization", () => {
  it("canonical record serialization is deterministic (equal records ⇒ equal string)", () => {
    const a = materializeMemoryRecord(
      { kind: "working", scope: wmScope(), provenance: { origin: "runtime", actor: AGENT, untrusted: false }, retention: { retentionClass: "session" }, body: { b: 2, a: 1 } },
      { memoryId: "wm-fixed", createdAtEpochMs: T0 }
    );
    const b = materializeMemoryRecord(
      { kind: "working", scope: wmScope(), provenance: { origin: "runtime", actor: AGENT, untrusted: false }, retention: { retentionClass: "session" }, body: { a: 1, b: 2 } },
      { memoryId: "wm-fixed", createdAtEpochMs: T0 }
    );
    expect(serializeMemoryRecord(a)).toBe(serializeMemoryRecord(b));
    expect(memoryRecordHash(a)).toBe(memoryRecordHash(b));
  });

  it("serialization order-independent across differing key insertion order", () => {
    const r1 = serializeMemoryBody({ alpha: 1, beta: { y: 2, x: 1 } });
    const r2 = serializeMemoryBody({ beta: { x: 1, y: 2 }, alpha: 1 });
    expect(r1).toBe(r2);
  });

  it("record hash changes when any protected field changes", () => {
    const base = materializeMemoryRecord(
      { kind: "project", scope: { workspaceId: "w" }, provenance: { origin: "human", actor: HUMAN, untrusted: false }, retention: { retentionClass: "persistent" }, body: { k: "v" } },
      { memoryId: "pm-1", createdAtEpochMs: T0 }
    );
    const tampered = materializeMemoryRecord(
      { kind: "project", scope: { workspaceId: "w" }, provenance: { origin: "human", actor: HUMAN, untrusted: false }, retention: { retentionClass: "persistent" }, body: { k: "v2" } },
      { memoryId: "pm-1", createdAtEpochMs: T0 }
    );
    expect(memoryRecordHash(base)).not.toBe(memoryRecordHash(tampered));
  });

  it("round-trip preserves schemaVersion and memoryId and yields valid JSON", () => {
    const rec = materializeMemoryRecord(
      { kind: "working", scope: wmScope(), provenance: { origin: "runtime", actor: AGENT, untrusted: false }, retention: { retentionClass: "session" }, body: { ok: true } },
      { memoryId: "wm-rt", createdAtEpochMs: T0 }
    );
    const rt = memoryRecordRoundTrip(rec);
    expect(rt.ok).toBe(true);
    if (rt.ok) {
      const parsed = JSON.parse(rt.canonical) as Record<string, unknown>;
      expect(parsed["schemaVersion"]).toBe(MEMORY_SCHEMA_VERSION);
      expect(parsed["memoryId"]).toBe("wm-rt");
    }
  });

  it("validateMemoryRecordInput rejects malformed inputs (machine-readable failure)", () => {
    expect(validateMemoryRecordInput(null as unknown as Parameters<typeof validateMemoryRecordInput>[0])).toContain("must be object");
    expect(validateMemoryRecordInput({ ...trustedInput(), kind: "chat" } as unknown as Parameters<typeof validateMemoryRecordInput>[0])).toContain("invalid kind");
    expect(validateMemoryRecordInput({ ...trustedInput(), scope: { workspaceId: "" } } as unknown as Parameters<typeof validateMemoryRecordInput>[0])).toContain("scope.workspaceId");
    expect(validateMemoryRecordInput({ ...trustedInput(), body: "not-an-object" } as unknown as Parameters<typeof validateMemoryRecordInput>[0])).toContain("invalid body");
    expect(validateMemoryRecordInput({ ...trustedInput(), retention: { retentionClass: "ephemeral" } } as unknown as Parameters<typeof validateMemoryRecordInput>[0])).toContain("ephemeral");
    expect(validateMemoryRecordInput({ ...trustedInput(), retention: { retentionClass: "persistent", expiresAtEpochMs: T0 + 5 } } as unknown as Parameters<typeof validateMemoryRecordInput>[0])).toContain("expiresAtEpochMs");
  });

  it("stored records are deeply frozen (structured runtime state, not mutable blobs)", () => {
    const store = makeWorking();
    const w = store.write(ctx(), trustedInput());
    expect(w.ok).toBe(true);
    if (w.ok) {
      expect(Object.isFrozen(w.record)).toBe(true);
      expect(Object.isFrozen(w.record.scope)).toBe(true);
      expect(Object.isFrozen(w.record.provenance)).toBe(true);
      expect(Object.isFrozen(w.record.body)).toBe(true);
    }
  });
});

describe("16A — provenance", () => {
  it("provenance origin + actor + untrusted flag survive a write/read cycle", () => {
    const store = makeWorking();
    store.write(ctx(), trustedInput({
      provenance: { origin: "human", actor: HUMAN, untrusted: false, label: "operator note" },
    }));
    const r = store.read(ctx());
    expect(r.ok).toBe(true);
    if (r.ok && r.records[0]) {
      expect(r.records[0].provenance.origin).toBe("human");
      expect(r.records[0].provenance.actor).toEqual(HUMAN);
      expect(r.records[0].provenance.untrusted).toBe(false);
      expect(r.records[0].provenance.label).toBe("operator note");
    }
  });

  it("external-origin entries keep untrusted: true in storage", () => {
    const store = makeWorking();
    const w = store.write(ctx(), trustedInput({
      provenance: { origin: "tool_output", actor: { type: "tool", id: "git-status" }, untrusted: true },
    }));
    expect(w.ok).toBe(true);
    if (w.ok) {
      expect(w.record.provenance.origin).toBe("tool_output");
      expect(w.record.provenance.untrusted).toBe(true);
    }
  });

  it("externally-originated content cannot be stored as trusted runtime memory", () => {
    const store = makeWorking();
    const w = store.write(ctx(), trustedInput({
      provenance: { origin: "model_output", actor: AGENT, untrusted: false },
    }));
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("untrusted_provenance_write_denied");
  });

  it("createdByActorId is derived from provenance actor, not caller-supplied text", () => {
    const rec = materializeMemoryRecord(
      { kind: "working", scope: wmScope(), provenance: { origin: "agent", actor: AGENT, untrusted: false }, retention: { retentionClass: "session" }, body: {} },
      { createdAtEpochMs: T0 }
    );
    expect(rec.createdByActorId).toBe("agent-16a");
    expect(rec.schemaVersion).toBe(MEMORY_SCHEMA_VERSION);
  });
});

describe("16A — retention metadata", () => {
  it("session entries without expiry remain visible", () => {
    const store = makeWorking();
    store.write(ctx(), trustedInput({ retention: { retentionClass: "session" } }));
    const r = store.read(ctx());
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.records).toHaveLength(1);
  });

  it("ephemeral entries expire exactly at their retention deadline", () => {
    let now = T0;
    const store = makeWorking({ now: () => now });
    const w = store.write(ctx(), trustedInput({ retention: { retentionClass: "ephemeral", expiresAtEpochMs: T0 + 100 } }));
    expect(w.ok).toBe(true);
    now = T0 + 99;
    let r = store.read(ctx());
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.records).toHaveLength(1);
    now = T0 + 100;
    r = store.read(ctx());
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.records).toHaveLength(0);
    expect(store.size).toBe(0);
  });

  it("persistent project entries survive many clock advances", () => {
    let now = T0;
    const store = new ProjectMemoryStore({ policyGate: ALLOW_ALL, now: () => now });
    const w = store.write(
      ctx(AGENT, { workspaceId: "ws-16a" }),
      {
        scope: { workspaceId: "ws-16a" },
        provenance: { origin: "runtime", actor: AGENT, untrusted: false },
        retention: { retentionClass: "persistent" },
        body: { lesson: "scope isolation enforced" },
      }
    );
    expect(w.ok).toBe(true);
    now += 1000 * 60 * 60 * 24 * 365;
    const r = store.read(ctx(AGENT, { workspaceId: "ws-16a" }));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.records).toHaveLength(1);
  });

  it("retention metadata is exposed on every stored record", () => {
    const store = makeWorking();
    const w = store.write(ctx(), trustedInput({ retention: { retentionClass: "ephemeral", expiresAtEpochMs: T0 + 50 } }));
    expect(w.ok).toBe(true);
    if (w.ok) {
      expect(w.record.retention.retentionClass).toBe("ephemeral");
      expect(w.record.retention.expiresAtEpochMs).toBe(T0 + 50);
    }
  });
});

describe("16A — ledger linkage", () => {
  it("every allowed write appends a memory_write event with intact chain", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeWorking({ ledger });
    const w = store.write(ctx(), trustedInput());
    expect(w.ok).toBe(true);
    expect(ledger.length).toBe(1);
    const evt = ledger.events()[0]!;
    expect(evt.eventType).toBe("memory_write");
    expect(evt.policyDecision).toBe("allow");
    expect(evt.workspaceId).toBe("ws-16a");
    expect(ledger.verify().ok).toBe(true);
  });

  it("every allowed read appends a memory_read event", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeWorking({ ledger });
    store.write(ctx(), trustedInput());
    const before = ledger.length;
    const r = store.read(ctx());
    expect(r.ok).toBe(true);
    expect(ledger.length).toBe(before + 1);
    expect(ledger.events()[ledger.length - 1]!.eventType).toBe("memory_read");
  });

  it("write result carries the ledger eventId (ledger linkage)", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeWorking({ ledger });
    const w = store.write(ctx(), trustedInput());
    expect(w.ok).toBe(true);
    if (w.ok) {
      expect(w.policyEventId).toBeDefined();
      expect(ledger.events().some((e) => e.eventId === w.policyEventId)).toBe(true);
    }
  });

  it("write events carry the canonical record hash for tamper evidence", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeWorking({ ledger });
    const w = store.write(ctx(), trustedInput({ body: { n: 1 } }));
    expect(w.ok).toBe(true);
    if (w.ok) {
      const evt = ledger.events().find((e) => e.eventId === w.policyEventId)!;
      const stored = evt.resultSummary?.["recordHash"];
      expect(typeof stored).toBe("string");
      expect(stored).toBe(memoryRecordHash(w.record));
    }
  });

  it("ledger events are redaction-safe: secret-looking keys do not leak", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeWorking({ ledger });
    store.write(ctx(), trustedInput({ body: { apiKey: "SHOULD-NOT-APPEAR", fact: "safe" } }));
    const raw = ledger.events()[0]!;
    expect(JSON.stringify(raw)).not.toContain("SHOULD-NOT-APPEAR");
  });

  it("ledger hash chain stays intact across many memory ops", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeWorking({ ledger });
    for (let i = 0; i < 5; i++) store.write(ctx(), trustedInput({ body: { i } }));
    store.read(ctx());
    store.read(ctx());
    const v = ledger.verify();
    expect(v.ok).toBe(true);
    expect(v.verifiedCount).toBe(ledger.length);
  });
});
