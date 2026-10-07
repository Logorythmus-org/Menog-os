import { describe, it, expect } from "vitest";
import {
  WorkingMemoryStore,
  ProjectMemoryStore,
  WORKING_MEMORY_MAX_RECORDS,
  PROJECT_MEMORY_MAX_RECORDS,
  MEMORY_SCHEMA_VERSION,
  type MemoryPolicyGate,
  type MemoryScope,
} from "@menog/memory";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";

const AGENT: Actor = { type: "agent", id: "agent-sec-16a" };

function fixedClock(startEpochMs: number): () => number {
  let t = startEpochMs;
  return () => {
    t += 1;
    return t;
  };
}

const T0 = 1_760_000_000_000;

function ws(overrides: Partial<MemoryScope> = {}): MemoryScope {
  return { workspaceId: "ws-sec", taskId: "task-sec", sessionId: "sess-sec", ...overrides };
}

function allowCtx(scope: MemoryScope = ws()) {
  return { actor: AGENT, grantedScope: scope };
}

const ALLOW_ALL: MemoryPolicyGate = {
  canReadMemory: () => true,
  canWriteMemory: () => true,
};

const DENY_ALL: MemoryPolicyGate = {
  canReadMemory: () => false,
  canWriteMemory: () => false,
};

function trustedInput(overrides: Record<string, unknown> = {}) {
  return {
    scope: ws(),
    provenance: { origin: "runtime", actor: AGENT, untrusted: false },
    retention: { retentionClass: "session" },
    body: { fact: "structured memory" },
    ...overrides,
  } as Parameters<WorkingMemoryStore["write"]>[1];
}

describe("16A-SEC — deny-by-default memory access", () => {
  it("a store without a policy gate denies ALL reads (fail-closed)", () => {
    const store = new WorkingMemoryStore({ policyGate: null, now: fixedClock(T0) });
    const r = store.read(allowCtx());
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denyReason).toBe("read_not_allowed");
      expect(r.reason).toContain("deny-by-default");
    }
  });

  it("a store without a policy gate denies ALL writes (fail-closed)", () => {
    const store = new WorkingMemoryStore({ policyGate: null, now: fixedClock(T0) });
    const w = store.write(allowCtx(), trustedInput());
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("write_not_allowed");
  });

  it("a deny-all policy gate blocks reads and writes and records the denial observably", () => {
    const store = new WorkingMemoryStore({ policyGate: DENY_ALL, now: fixedClock(T0) });
    const r = store.read(allowCtx());
    const w = store.write(allowCtx(), trustedInput());
    expect(r.ok).toBe(false);
    expect(w.ok).toBe(false);
    expect(store.deniedOperations).toHaveLength(2);
    expect(store.deniedOperations[0]!.denyReason).toBe("read_not_allowed");
    expect(store.deniedOperations[1]!.denyReason).toBe("write_not_allowed");
  });

  it("denied operations emit NO ledger event (no false evidence of success)", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = new WorkingMemoryStore({ policyGate: DENY_ALL, ledger, now: fixedClock(T0) });
    store.read(allowCtx());
    store.write(allowCtx(), trustedInput());
    expect(ledger.length).toBe(0);
    expect(ledger.verify().ok).toBe(true);
  });

  it("policy-gate denials are scoped per-operation: read-only gate still denies writes", () => {
    const readOnlyGate: MemoryPolicyGate = {
      canReadMemory: () => true,
      canWriteMemory: () => false,
    };
    const store = new WorkingMemoryStore({ policyGate: readOnlyGate, now: fixedClock(T0) });
    expect(store.read(allowCtx()).ok).toBe(true);
    const w = store.write(allowCtx(), trustedInput());
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("write_not_allowed");
  });
});

describe("16A-SEC — scope escape containment", () => {
  it("a task-granted caller cannot write into another task's memory", () => {
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const w = store.write(allowCtx(ws({ taskId: "task-A" })), trustedInput({ scope: ws({ taskId: "task-B" }) }));
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("scope_mismatch");
    expect(store.deniedOperations.some((d) => d.denyReason === "scope_mismatch")).toBe(true);
  });

  it("a session-granted caller cannot write across sessions", () => {
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const w = store.write(allowCtx(ws({ sessionId: "sess-1" })), trustedInput({ scope: ws({ sessionId: "sess-2" }) }));
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("scope_mismatch");
  });

  it("cross-workspace write escape is denied even when workspaceId differs only slightly", () => {
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const w = store.write(allowCtx(ws({ workspaceId: "ws-sec" })), trustedInput({ scope: ws({ workspaceId: "ws-secret" }) }));
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("scope_mismatch");
  });

  it("cross-workspace READ escape returns empty, never foreign data", () => {
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    store.write(allowCtx(), trustedInput({ body: { crown: "jewels" } }));
    const r = store.read(allowCtx(ws({ workspaceId: "ws-other" })));
    expect(r.ok).toBe(true); // policy allowed, but isolation holds
    if (r.ok) expect(r.records).toHaveLength(0);
  });

  it("memoryId filter cannot be used to read across scopes", () => {
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const w = store.write(allowCtx(), trustedInput({ body: { secret: "x" } }));
    expect(w.ok).toBe(true);
    const r = store.read(allowCtx(ws({ workspaceId: "ws-other" })), { memoryId: w.ok ? w.record.memoryId : "wm-nope" });
    if (r.ok) expect(r.records).toHaveLength(0);
  });

  it("working vs project stores are isolated: project store never returns working records", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const w = new WorkingMemoryStore({ policyGate: ALLOW_ALL, ledger, now: fixedClock(T0) });
    const p = new ProjectMemoryStore({ policyGate: ALLOW_ALL, ledger, now: fixedClock(T0) });
    w.write(allowCtx(), trustedInput({ body: { only: "working" } }));
    const r = p.read(allowCtx(ws()));
    if (r.ok) expect(r.records).toHaveLength(0);
  });
});

describe("16A-SEC — untrusted external content", () => {
  it("tool_output claimed as trusted is denied (NO EXTERNAL CONTENT AS SYSTEM INSTRUCTION)", () => {
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    for (const origin of ["tool_output", "model_output", "repo_content", "external"] as const) {
      const w = store.write(allowCtx(), trustedInput({ provenance: { origin, actor: AGENT, untrusted: false } }));
      expect(w.ok).toBe(false);
      if (!w.ok) expect(w.denyReason).toBe("untrusted_provenance_write_denied");
    }
  });

  it("externally-originated content stored with untrusted:true keeps the flag through reads", () => {
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    store.write(allowCtx(), trustedInput({ provenance: { origin: "repo_content", actor: { type: "tool", id: "reader" }, untrusted: true } }));
    const r = store.read(allowCtx());
    expect(r.ok).toBe(true);
    if (r.ok && r.records[0]) {
      expect(r.records[0].provenance.untrusted).toBe(true);
      expect(r.records[0].provenance.origin).toBe("repo_content");
    }
  });

  it("stored external content never gains runtime authority markers", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, ledger, now: fixedClock(T0) });
    store.write(allowCtx(), trustedInput({ provenance: { origin: "external", actor: { type: "tool", id: "web" }, untrusted: true } }));
    const evt = ledger.events()[0]!;
    // The audit event is runtime-authored and memory-scoped; it grants nothing.
    expect(evt.actor.type).toBe("runtime");
    expect(evt.capability).toBe("memory");
    expect(evt.verb).toMatch(/^memory\./);
    expect(JSON.stringify(evt)).not.toContain("workspace:write");
    expect(JSON.stringify(evt)).not.toContain("git:commit");
  });
});

describe("16A-SEC — retention & bounded state", () => {
  it("expired ephemeral entries are never readable even by id", () => {
    let now = T0;
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: () => now });
    const w = store.write(allowCtx(), trustedInput({ retention: { retentionClass: "ephemeral", expiresAtEpochMs: T0 + 10 } }));
    expect(w.ok).toBe(true);
    const id = w.ok ? w.record.memoryId : "wm-x";
    now = T0 + 11;
    const r = store.read(allowCtx(), { memoryId: id });
    if (r.ok) expect(r.records).toHaveLength(0);
    expect(store.rawSize).toBe(0);
  });

  it("store capacity caps are sane and enforced (bounded memory state)", () => {
    expect(WORKING_MEMORY_MAX_RECORDS).toBeLessThanOrEqual(512);
    expect(PROJECT_MEMORY_MAX_RECORDS).toBeLessThanOrEqual(4096);
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0), maxRecords: 2 });
    store.write(allowCtx(), trustedInput({ body: { i: 1 } }));
    store.write(allowCtx(), trustedInput({ body: { i: 2 } }));
    store.write(allowCtx(), trustedInput({ body: { i: 3 } }));
    expect(store.size).toBe(2);
  });

  it("invalid retention (ephemeral without expiry) is rejected with invalid_input", () => {
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const w = store.write(allowCtx(), trustedInput({ retention: { retentionClass: "ephemeral" } }));
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("invalid_input");
  });

  it("empty workspaceId scope is rejected (no unscoped writes)", () => {
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const w = store.write(allowCtx(), trustedInput({ scope: { workspaceId: "" } }));
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("invalid_input");
  });
});

describe("16A-SEC — structural invariants", () => {
  it("schema version is pinned", () => {
    expect(MEMORY_SCHEMA_VERSION).toBe("menog-memory/v0");
  });

  it("read results are frozen snapshots (callers cannot mutate store state)", () => {
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    store.write(allowCtx(), trustedInput());
    const r = store.read(allowCtx());
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(Object.isFrozen(r.records)).toBe(true);
      if (r.records[0]) expect(Object.isFrozen(r.records[0])).toBe(true);
    }
  });

  it("memory store exposes NO execution authority surface", () => {
    const store = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const proto = Object.getPrototypeOf(store) as Record<string, unknown>;
    const methods = Object.getOwnPropertyNames(proto);
    const forbidden = ["exec", "spawn", "commit", "gitCommit", "writeFile", "appendFile", "fetch", "request", "connect", "evaluate", "grant"];
    for (const f of forbidden) {
      expect(methods).not.toContain(f);
    }
  });

  it("day-1 policy engine still denies non-inspect verbs even with memory present (no policy weakening)", () => {
    const engine = new DenyByDefaultPolicyEngine();
    const res = engine.evaluate({
      actor: AGENT,
      verb: "memory.write",
      requestedCapabilities: ["workspace:write"],
      workspaceId: "ws-sec",
    });
    expect(res.decision.outcome).toBe("deny");
  });
});
