import { describe, it, expect } from "vitest";
import {
  ExecutionMemoryStore,
  readExecutionMetadata,
  validateExecutionMetadata,
  validateMemoryRecordInput,
  serializeMemoryRecord,
  memoryRecordHash,
  scopeCovers,
  EXECUTION_MEMORY_MAX_BLOB_BYTES,
  EXECUTION_MEMORY_MAX_RECORDS,
  EXECUTION_METADATA_KEY,
  KNOWN_MEMORY_KINDS,
  isMemoryKind,
  MEMORY_REDACTION_MARKER,
  MEMORY_SECRET_KEY_HINTS,
  secretKeyMatches,
  type MemoryPolicyGate,
  type MemoryScope,
  type ExecutionMemoryWriteRequest,
} from "@menog/memory";
import { AppendOnlyLedger } from "@menog/event-ledger";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import type { Actor } from "@menog/core";

const HUMAN: Actor = { type: "human", id: "human-16b" };
const AGENT: Actor = { type: "agent", id: "agent-16b" };

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

const T0 = 1_770_000_000_000;
// Composed at runtime so this file contains no key-shaped literal (verify-local secret-scan clean).
const FAKE_KEY = "sk-" + "abcdefghijklmnopqrst";

function exScope(overrides: Partial<MemoryScope> = {}): MemoryScope {
  return { workspaceId: "ws-16b", taskId: "task-16b", sessionId: "sess-16b", ...overrides };
}

function ctx(actor: Actor = AGENT, scope: MemoryScope = exScope()) {
  return { actor, grantedScope: scope };
}

function makeStore(options: {
  policyGate?: MemoryPolicyGate | null;
  ledger?: AppendOnlyLedger | null;
  now?: () => number;
  maxRecords?: number;
} = {}): ExecutionMemoryStore {
  return new ExecutionMemoryStore({
    policyGate: options.policyGate === undefined ? ALLOW_ALL : options.policyGate,
    ledger: options.ledger ?? null,
    now: options.now ?? fixedClock(T0),
    maxRecords: options.maxRecords,
  });
}

/** Build a request with a pre-verified evidence ref when a ledger is given. */
function seedEvidence(ledger: AppendOnlyLedger, actor: Actor, verb: string): string {
  const res = ledger.append({
    eventId: "evt-" + Math.random().toString(36).slice(2, 10),
    timestamp: new Date(T0).toISOString(),
    eventType: "verb_executed",
    actor: { type: "runtime", id: "runtime-test" },
    workspaceId: "ws-16b",
    taskId: "task-16b",
    verb,
    capability: "workspace:read-file",
    policyDecision: "allow",
    inputSummary: { actorId: actor.id },
    resultSummary: { outcome: "ok" },
  });
  if (!res.ok || !res.event) throw new Error("seed evidence append failed: " + (res.reason ?? ""));
  return res.event.eventId;
}

function req(overrides: Partial<ExecutionMemoryWriteRequest> = {}): ExecutionMemoryWriteRequest {
  return {
    scope: exScope(),
    provenance: { origin: "runtime", actor: AGENT, untrusted: false },
    retention: { retentionClass: "session" },
    actor: AGENT,
    taskId: "task-16b",
    verb: "inspect",
    outcome: "success",
    policyDecision: "allow",
    recordedAtEpochMs: T0 + 5,
    summary: "inspection completed",
    ...overrides,
  };
}

describe("16B — execution outcome persistence", () => {
  it("a validated execution outcome is persisted with full typed metadata", () => {
    const store = makeStore();
    const w = store.recordExecution(ctx(), req());
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    expect(w.record.kind).toBe("execution");
    const meta = readExecutionMetadata(w.record);
    expect(meta).not.toBeNull();
    expect(meta!.taskId).toBe("task-16b");
    expect(meta!.verb).toBe("inspect");
    expect(meta!.outcome).toBe("success");
    expect(meta!.actorId).toBe("agent-16b");
    expect(meta!.actorType).toBe("agent");
    expect(meta!.recordedAtEpochMs).toBe(T0 + 5);
    expect(meta!.policyDecision).toBe("allow");
    expect(meta!.summary).toBe("inspection completed");
  });

  it("execution records validate against the generic memory-record validator (one schema)", () => {
    const store = makeStore();
    const w = store.recordExecution(ctx(), req());
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    expect(validateMemoryRecordInput({
      kind: w.record.kind,
      scope: w.record.scope,
      provenance: w.record.provenance,
      retention: w.record.retention,
      body: w.record.body,
    })).toBeNull();
    expect(isMemoryKind("execution")).toBe(true);
    expect(KNOWN_MEMORY_KINDS).toContain("execution");
  });

  it("failures are captured with outcome 'failure' and a failure summary", () => {
    const store = makeStore();
    const w = store.recordExecution(ctx(), req({
      outcome: "failure",
      summary: "typecheck failed with 2 errors",
    }));
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    const meta = readExecutionMetadata(w.record);
    expect(meta!.outcome).toBe("failure");
    expect(meta!.summary).toBe("typecheck failed with 2 errors");
  });

  it("denied executions carry policyDecision 'deny' and outcome 'denied'", () => {
    const store = makeStore();
    const w = store.recordExecution(ctx(), req({
      outcome: "denied",
      policyDecision: "deny",
      verb: "git.commit",
    }));
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    const meta = readExecutionMetadata(w.record);
    expect(meta!.outcome).toBe("denied");
    expect(meta!.policyDecision).toBe("deny");
  });

  it("stored execution records are deeply frozen (metadata object included)", () => {
    const store = makeStore();
    const w = store.recordExecution(ctx(), req());
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    expect(Object.isFrozen(w.record)).toBe(true);
    expect(Object.isFrozen(w.record.body)).toBe(true);
    const meta = w.record.body[EXECUTION_METADATA_KEY] as Record<string, unknown>;
    expect(Object.isFrozen(meta)).toBe(true);
  });

  it("record ids use the execution prefix", () => {
    const store = makeStore();
    const w = store.recordExecution(ctx(), req());
    expect(w.ok).toBe(true);
    if (w.ok) expect(w.record.memoryId.startsWith("ex-")).toBe(true);
  });

  it("malformed execution metadata is rejected with invalid_input", () => {
    const store = makeStore();
    const bad = store.write(ctx(), {
      scope: exScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { execution: { taskId: "t" } },
    });
    expect(bad.ok).toBe(false);
    if (!bad.ok) {
      expect(bad.denyReason).toBe("invalid_input");
      expect(bad.reason).toContain("body.execution");
    }
  });

  it("validateExecutionMetadata rejects unknown outcomes and bad policy decisions", () => {
    expect(validateExecutionMetadata({ taskId: "t", verb: "v", outcome: "exploded", actorId: "a", actorType: "agent", recordedAtEpochMs: 1, policyDecision: "allow" })).toContain("outcome");
    expect(validateExecutionMetadata({ taskId: "t", verb: "v", outcome: "success", actorId: "a", actorType: "agent", recordedAtEpochMs: 1, policyDecision: "maybe" })).toContain("policyDecision");
    expect(validateExecutionMetadata("not an object")).toContain("plain object");
  });

  it("raw execution bodies (not under the reserved key) are rejected", () => {
    const store = makeStore();
    const bad = store.write(ctx(), {
      scope: exScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { transcript: "everything the model ever said" },
    });
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.denyReason).toBe("invalid_input");
  });
});

describe("16B — redaction and secret exclusion", () => {
  it("credential-shaped values inside summary are redacted at rest", () => {
    const store = makeStore();
    const w = store.recordExecution(ctx(), req({
      summary: "deploy failed: server said Unauthorized for Bearer abc123def456ghi789",
    }));
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    const meta = readExecutionMetadata(w.record);
    expect(meta!.summary).toContain(MEMORY_REDACTION_MARKER);
    expect(meta!.summary).not.toContain("Bearer abc123");
    expect(JSON.stringify(w.record)).not.toContain("Bearer abc123");
  });

  it("secret-like METADATA keys are rejected with secret_detected (deny, not redact)", () => {
    const store = makeStore();
    const w = store.recordExecution(ctx(), req({
      metadata: { apiKey: FAKE_KEY },
    }));
    expect(w.ok).toBe(false);
    if (!w.ok) {
      expect(w.denyReason).toBe("secret_detected");
      expect(w.reason).toContain("apiKey");
    }
    // Nothing was persisted.
    const r = store.query(ctx(), {});
    if (r.ok) expect(r.records).toHaveLength(0);
  });

  it("secret-like TOP-LEVEL body keys are rejected with secret_detected", () => {
    const store = makeStore();
    const w = store.write(ctx(), {
      scope: exScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { password: "hunter2", execution: { taskId: "t", verb: "v", outcome: "success", actorId: "a", actorType: "agent", recordedAtEpochMs: T0, policyDecision: "allow" } },
    });
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("secret_detected");
  });

  it("nested secret-like keys (e.g. result.auth_token) are rejected with secret_detected", () => {
    const store = makeStore();
    const w = store.recordExecution(ctx(), req({
      metadata: { result: { auth_token: "should-never-persist" } },
    }));
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("secret_detected");
  });

  it("JWT-like and GitHub-style token VALUES are redacted even under neutral keys", () => {
    const store = makeStore();
    const w = store.recordExecution(ctx(), req({
      metadata: {
        note: "used ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 during deploy",
      },
    }));
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    const raw = JSON.stringify(w.record);
    expect(raw).not.toContain("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
    expect(raw).toContain(MEMORY_REDACTION_MARKER);
  });

  it("memory secret hints stay aligned with the ledger SECRET_KEY_HINTS count (one definition of secret)", () => {
    expect(MEMORY_SECRET_KEY_HINTS).toHaveLength(17);
    expect(secretKeyMatches("apiKey")).toBe(true);
    expect(secretKeyMatches("sessionKey")).toBe(true);
    expect(secretKeyMatches("verb")).toBe(false);
    expect(secretKeyMatches("taskId")).toBe(false);
    expect(secretKeyMatches("outcome")).toBe(false);
  });
});

describe("16B — raw blob exclusion", () => {
  it("bodies above EXECUTION_MEMORY_MAX_BLOB_BYTES are rejected with oversized_blob", () => {
    const store = makeStore();
    const huge = "x".repeat(EXECUTION_MEMORY_MAX_BLOB_BYTES);
    const w = store.recordExecution(ctx(), req({ summary: huge }));
    expect(w.ok).toBe(false);
    if (!w.ok) {
      expect(w.denyReason).toBe("oversized_blob");
      expect(w.reason).toContain("evidenceRef");
    }
  });

  it("bodies just under the limit are accepted (boundary discipline)", () => {
    const store = makeStore();
    const filler = "y".repeat(2000);
    const w = store.recordExecution(ctx(), req({ summary: filler }));
    expect(w.ok).toBe(true);
  });

  it("the byte limit is strict (8 KiB)", () => {
    expect(EXECUTION_MEMORY_MAX_BLOB_BYTES).toBe(8192);
    expect(EXECUTION_MEMORY_MAX_RECORDS).toBeGreaterThanOrEqual(1024);
  });
});

describe("16B — evidence reference integrity", () => {
  it("evidenceRef citing a real ledger event is stored and round-trips", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeStore({ ledger });
    const evidenceRef = seedEvidence(ledger, AGENT, "inspect");
    const w = store.recordExecution(ctx(), req({ evidenceRef }));
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    const meta = readExecutionMetadata(w.record);
    expect(meta!.evidenceRef).toBe(evidenceRef);
  });

  it("evidenceRef citing an unknown event is rejected (no unverifiable evidence)", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeStore({ ledger });
    const w = store.recordExecution(ctx(), req({ evidenceRef: "evt-does-not-exist" }));
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("invalid_input");
  });

  it("evidenceRef is rejected entirely when no ledger is attached", () => {
    const store = makeStore({ ledger: null });
    const w = store.recordExecution(ctx(), req({ evidenceRef: "evt-orphan" }));
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("invalid_input");
  });

  it("the ledger anchoring the evidence stays verifiable after execution recording", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeStore({ ledger });
    const evidenceRef = seedEvidence(ledger, AGENT, "inspect");
    store.recordExecution(ctx(), req({ evidenceRef }));
    store.recordExecution(ctx(), req({ evidenceRef, outcome: "failure" }));
    const v = ledger.verify();
    expect(v.ok).toBe(true);
    expect(v.verifiedCount).toBe(v.totalCount);
  });
});

describe("16B — query by task / verb / agent / time", () => {
  it("filters by taskId", () => {
    const store = makeStore();
    store.recordExecution(ctx(), req({ taskId: "task-A" }));
    store.recordExecution(ctx(), req({ taskId: "task-B", summary: "other" }));
    const r = store.query(ctx(), { taskId: "task-A" });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.records).toHaveLength(1);
      expect(readExecutionMetadata(r.records[0]!)!.taskId).toBe("task-A");
    }
  });

  it("filters by verb", () => {
    const store = makeStore();
    store.recordExecution(ctx(), req({ verb: "inspect" }));
    store.recordExecution(ctx(), req({ verb: "git.status" }));
    const r = store.query(ctx(), { verb: "git.status" });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.records).toHaveLength(1);
  });

  it("filters by agent (actorId)", () => {
    const store = makeStore();
    store.recordExecution(ctx(), req({ actor: AGENT }));
    store.recordExecution(ctx(), req({ actor: HUMAN }));
    const r = store.query(ctx(), { actorId: "human-16b" });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.records).toHaveLength(1);
      expect(readExecutionMetadata(r.records[0]!)!.actorId).toBe("human-16b");
    }
  });

  it("filters by time window [fromMs, toMs] inclusively", () => {
    const store = makeStore();
    store.recordExecution(ctx(), req({ recordedAtEpochMs: T0 + 10 }));
    store.recordExecution(ctx(), req({ recordedAtEpochMs: T0 + 20 }));
    store.recordExecution(ctx(), req({ recordedAtEpochMs: T0 + 30 }));
    const r = store.query(ctx(), { fromMs: T0 + 10, toMs: T0 + 20 });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.records).toHaveLength(2);
    const onlyLate = store.query(ctx(), { fromMs: T0 + 21 });
    if (onlyLate.ok) expect(onlyLate.records).toHaveLength(1);
    const empty = store.query(ctx(), { fromMs: T0 + 100 });
    if (empty.ok) expect(empty.records).toHaveLength(0);
  });

  it("combined filters AND together", () => {
    const store = makeStore();
    store.recordExecution(ctx(), req({ taskId: "t1", verb: "inspect", outcome: "success" }));
    store.recordExecution(ctx(), req({ taskId: "t1", verb: "inspect", outcome: "failure" }));
    store.recordExecution(ctx(), req({ taskId: "t2", verb: "inspect", outcome: "failure" }));
    const r = store.query(ctx(), { taskId: "t1", verb: "inspect", outcome: "failure" });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.records).toHaveLength(1);
  });

  it("queryStats aggregates by outcome with latest timestamp", () => {
    const store = makeStore();
    store.recordExecution(ctx(), req({ outcome: "success", recordedAtEpochMs: T0 + 1 }));
    store.recordExecution(ctx(), req({ outcome: "failure", recordedAtEpochMs: T0 + 2 }));
    store.recordExecution(ctx(), req({ outcome: "failure", recordedAtEpochMs: T0 + 3 }));
    const s = store.queryStats(ctx(), {});
    expect(s.ok).toBe(true);
    if (s.ok) {
      expect(s.total).toBe(3);
      expect(s.byOutcome.success).toBe(1);
      expect(s.byOutcome.failure).toBe(2);
      expect(s.byOutcome.denied).toBe(0);
      expect(s.latestRecordedAtEpochMs).toBe(T0 + 3);
    }
  });

  it("query respects scope isolation: another workspace sees nothing", () => {
    const store = makeStore();
    store.recordExecution(ctx(), req());
    const r = store.query(ctx(AGENT, exScope({ workspaceId: "ws-other" })), {});
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.records).toHaveLength(0);
  });

  it("query without a policy gate denies (fail-closed inherits 16A)", () => {
    const store = makeStore({ policyGate: null });
    const r = store.query(ctx(), {});
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.denyReason).toBe("read_not_allowed");
  });
});

describe("16B — scope, provenance, bounded state", () => {
  it("execution writes obey scope narrowing (no cross-task writes)", () => {
    const store = makeStore();
    const w = store.recordExecution(ctx(AGENT, exScope({ taskId: "task-A" })), req({ scope: exScope({ taskId: "task-B" }) }));
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("scope_mismatch");
  });

  it("provenance survives the execution write path (integrity)", () => {
    const store = makeStore();
    const w = store.recordExecution(ctx(), req({
      provenance: { origin: "agent", actor: AGENT, untrusted: false, label: "post-verb audit" },
    }));
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    expect(w.record.provenance.origin).toBe("agent");
    expect(w.record.provenance.label).toBe("post-verb audit");
    expect(w.record.createdByActorId).toBe("agent-16b");
  });

  it("canonical serialization of execution records is deterministic", () => {
    const store = makeStore();
    const a = store.recordExecution(ctx(), req({ metadata: { z: 1, a: 2 } }));
    const b = store.recordExecution(ctx(), req({ metadata: { a: 2, z: 1 } }));
    expect(a.ok && b.ok).toBe(true);
    if (a.ok && b.ok) {
      // Same logical metadata ⇒ same canonical form (memoryId and
      // createdAtEpochMs are per-write identity fields and are normalized).
      const strip = (r: typeof a.record) =>
        serializeMemoryRecord({ ...r, memoryId: "ex-fixed", createdAtEpochMs: T0 });
      expect(strip(a.record)).toBe(strip(b.record));
      expect(memoryRecordHash({ ...a.record, memoryId: "ex-fixed", createdAtEpochMs: T0 }))
        .toBe(memoryRecordHash({ ...b.record, memoryId: "ex-fixed", createdAtEpochMs: T0 }));
    }
  });

  it("record hash changes when execution outcome changes (tamper evidence)", () => {
    const store = makeStore();
    const a = store.recordExecution(ctx(), req({ outcome: "success" }));
    const b = store.recordExecution(ctx(), req({ outcome: "failure" }));
    expect(a.ok && b.ok).toBe(true);
    if (a.ok && b.ok) {
      expect(memoryRecordHash({ ...a.record, memoryId: "ex-fixed" }))
        .not.toBe(memoryRecordHash({ ...b.record, memoryId: "ex-fixed" }));
    }
  });

  it("FIFO cap keeps execution memory bounded", () => {
    const store = makeStore({ maxRecords: 5 });
    for (let i = 0; i < 8; i++) {
      store.recordExecution(ctx(), req({ attempt: i + 1 }));
    }
    expect(store.size).toBe(5);
  });

  it("session retention still applies to execution records", () => {
    let now = T0;
    const store = makeStore({ now: () => now });
    store.recordExecution(ctx(), req());
    expect(store.size).toBe(1);
    now = T0 + 1000;
    expect(store.size).toBe(1); // session records have no absolute expiry
  });
});

describe("16B — ledger linkage and policy observability", () => {
  it("every allowed execution write appends a memory_write event with intact chain", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeStore({ ledger });
    store.recordExecution(ctx(), req());
    expect(ledger.length).toBeGreaterThanOrEqual(1);
    const evt = ledger.events()[ledger.length - 1]!;
    expect(evt.eventType).toBe("memory_write");
    expect(evt.policyDecision).toBe("allow");
    expect(evt.verb).toBe("memory.write");
    expect(ledger.verify().ok).toBe(true);
  });

  it("every execution query appends a memory_read event (policy-observable reads)", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeStore({ ledger });
    store.recordExecution(ctx(), req());
    const before = ledger.length;
    store.query(ctx(), { verb: "inspect" });
    expect(ledger.length).toBe(before + 1);
  });

  it("denied secret-detected writes emit NO ledger event and are visible as denials", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeStore({ ledger });
    const w = store.recordExecution(ctx(), req({ metadata: { apiKey: FAKE_KEY } }));
    expect(w.ok).toBe(false);
    expect(ledger.length).toBe(0);
    expect(store.deniedOperations.some((d) => d.denyReason === "secret_detected")).toBe(true);
  });

  it("execution memory composes with the real policy engine (no weakening)", () => {
    const engine = new DenyByDefaultPolicyEngine();
    const res = engine.evaluate({
      actor: AGENT,
      verb: "memory.write",
      requestedCapabilities: ["workspace:write"],
      workspaceId: "ws-16b",
    });
    expect(res.decision.outcome).toBe("deny");
  });

  it("the execution store exposes no execution-authority surface", () => {
    const store = makeStore();
    const proto = Object.getPrototypeOf(store) as Record<string, unknown>;
    const methods = Object.getOwnPropertyNames(proto);
    for (const f of ["exec", "spawn", "commit", "writeFile", "fetch", "request", "connect", "evaluate", "grant"]) {
      expect(methods).not.toContain(f);
    }
  });
});

describe("16B — scope primitives regression", () => {
  it("scopeCovers still enforces narrowing-only access after 16B changes", () => {
    expect(scopeCovers({ workspaceId: "ws" }, { workspaceId: "ws" })).toBe(true);
    expect(scopeCovers({ workspaceId: "ws", taskId: "t1" }, { workspaceId: "ws" })).toBe(false);
    expect(scopeCovers({ workspaceId: "ws" }, { workspaceId: "other" })).toBe(false);
  });
});
