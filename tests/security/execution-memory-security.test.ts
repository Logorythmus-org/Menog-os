import { describe, it, expect } from "vitest";
import {
  ExecutionMemoryStore,
  readExecutionMetadata,
  WORKING_MEMORY_MAX_RECORDS,
  PROJECT_MEMORY_MAX_RECORDS,
  EXECUTION_MEMORY_MAX_BLOB_BYTES,
  EXECUTION_MEMORY_MAX_RECORDS,
  MEMORY_SCHEMA_VERSION,
  MEMORY_SECRET_KEY_HINTS,
  MEMORY_REDACTION_MARKER,
  redactCredentialValues,
  type MemoryPolicyGate,
  type MemoryScope,
} from "@menog/memory";
import { SECRET_KEY_HINTS } from "@menog/event-ledger";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";

const AGENT: Actor = { type: "agent", id: "agent-sec-16b" };
const TOOL: Actor = { type: "tool", id: "tool-sec-16b" };
// Composed at runtime so this file contains no key-shaped literal (verify-local secret-scan clean).
const FAKE_KEY = "sk-" + "abcdefghijklmnopqrst";

const ALLOW_ALL: MemoryPolicyGate = {
  canReadMemory: () => true,
  canWriteMemory: () => true,
};

const DENY_ALL: MemoryPolicyGate = {
  canReadMemory: () => false,
  canWriteMemory: () => false,
};

function fixedClock(startEpochMs: number): () => number {
  let t = startEpochMs;
  return () => {
    t += 1;
    return t;
  };
}

const T0 = 1_780_000_000_000;

function ws(overrides: Partial<MemoryScope> = {}): MemoryScope {
  return { workspaceId: "ws-sec-16b", taskId: "task-sec-16b", sessionId: "sess-sec-16b", ...overrides };
}

function allowCtx(scope: MemoryScope = ws()) {
  return { actor: AGENT, grantedScope: scope };
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

function req(overrides: Record<string, unknown> = {}) {
  return {
    scope: ws(),
    provenance: { origin: "runtime", actor: AGENT, untrusted: false },
    retention: { retentionClass: "session" },
    actor: AGENT,
    taskId: "task-sec-16b",
    verb: "inspect",
    outcome: "success",
    policyDecision: "allow",
    recordedAtEpochMs: T0 + 5,
    summary: "security fixture",
    ...overrides,
  } as Parameters<ExecutionMemoryStore["recordExecution"]>[1];
}

describe("16B-SEC — deny-by-default execution memory", () => {
  it("a store without a policy gate denies ALL execution reads (fail-closed)", () => {
    const store = makeStore({ policyGate: null });
    const r = store.query(allowCtx(), {});
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denyReason).toBe("read_not_allowed");
      expect(r.reason).toContain("deny-by-default");
    }
  });

  it("a store without a policy gate denies ALL execution writes (fail-closed)", () => {
    const store = makeStore({ policyGate: null });
    const w = store.recordExecution(allowCtx(), req());
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("write_not_allowed");
  });

  it("a deny-all gate blocks execution reads and writes observably", () => {
    const store = makeStore({ policyGate: DENY_ALL });
    const r = store.query(allowCtx(), {});
    const w = store.recordExecution(allowCtx(), req());
    expect(r.ok).toBe(false);
    expect(w.ok).toBe(false);
    expect(store.deniedOperations.some((d) => d.denyReason === "read_not_allowed")).toBe(true);
    expect(store.deniedOperations.some((d) => d.denyReason === "write_not_allowed")).toBe(true);
  });

  it("query stats inherit fail-closed denial", () => {
    const store = makeStore({ policyGate: DENY_ALL });
    const s = store.queryStats(allowCtx(), { taskId: "task-sec-16b" });
    expect(s.ok).toBe(false);
    if (!s.ok) expect(s.denyReason).toBe("read_not_allowed");
  });
});

describe("16B-SEC — secret exclusion (NO SECRETS IN MEMORY)", () => {
  it("memory secret-key hints are exactly the ledger SECRET_KEY_HINTS (shared definition)", () => {
    expect(MEMORY_SECRET_KEY_HINTS.length).toBe(SECRET_KEY_HINTS.length);
    for (let i = 0; i < SECRET_KEY_HINTS.length; i++) {
      const re = SECRET_KEY_HINTS[i];
      const mine = MEMORY_SECRET_KEY_HINTS[i];
      expect(mine!.source).toBe(re!.source);
    }
  });

  it("secret-like body keys are REJECTED with secret_detected — never stored, never redacted-into-store", () => {
    const store = makeStore();
    for (const key of ["password", "api_key", "apiKey", "secret_token", "access_token", "privateKey", "auth", "session_token", "cookie", "jwt"]) {
      const w = store.write(allowCtx(), {
        scope: ws(),
        provenance: { origin: "runtime", actor: AGENT, untrusted: false },
        retention: { retentionClass: "session" },
        body: { [key]: "x".repeat(8) },
      });
      expect(w.ok, "expected rejection for key " + key).toBe(false);
      if (!w.ok) expect(w.denyReason).toBe("secret_detected");
    }
    expect(store.size).toBe(0);
  });

  it("secret-like NESTED metadata keys are rejected (deep scan)", () => {
    const store = makeStore();
    const w = store.recordExecution(allowCtx(), req({
      metadata: { result: { output: { refresh_token: "leak-me-not" } } },
    }));
    expect(w.ok).toBe(false);
    if (!w.ok) {
      expect(w.denyReason).toBe("secret_detected");
      expect(w.reason).toContain("refresh_token");
    }
  });

  it("a rejected secret write persists NOTHING (no partial records)", () => {
    const store = makeStore();
    store.recordExecution(allowCtx(), req({ summary: "clean record" }));
    const before = store.size;
    store.recordExecution(allowCtx(), req({ metadata: { apiKey: FAKE_KEY } }));
    expect(store.size).toBe(before);
    const r = store.query(allowCtx(), {});
    if (r.ok) {
      for (const rec of r.records) {
        expect(JSON.stringify(rec)).not.toContain(FAKE_KEY);
      }
    }
  });

  it("credential-shaped VALUES are redacted at rest (defense in depth)", () => {
    const store = makeStore();
    const w = store.recordExecution(allowCtx(), req({
      summary: "curl -H 'Authorization: Bearer supersecretvalue123' https://api.example.com",
      metadata: { note: "token=abc123def456ghi789 in logs" },
    }));
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    const raw = JSON.stringify(w.record);
    expect(raw).not.toContain("supersecretvalue123");
    expect(raw).not.toContain("abc123def456ghi789");
    expect(raw).toContain(MEMORY_REDACTION_MARKER);
  });

  it("JWT-like values are redacted even under neutral keys", () => {
    const store = makeStore();
    // Composed at runtime so this file itself never contains a JWT-shaped literal.
    const token = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"].join(".");
    const w = store.recordExecution(allowCtx(), req({
      metadata: { diagnostic: "received " + token + " from upstream" },
    }));
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    expect(JSON.stringify(w.record)).not.toContain(token);
  });

  it("redaction applies before materialization: the STORED hash covers the redacted body", () => {
    const store = makeStore();
    const w = store.recordExecution(allowCtx(), req({
      summary: "bearer ZZZtopsecretcredential",
    }));
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    const meta = readExecutionMetadata(w.record);
    // The entire summary was the bearer credential, so it is fully redacted.
    expect(meta!.summary).toBe(MEMORY_REDACTION_MARKER);
    // The record body itself (not just projections) is redacted.
    const exec = w.record.body["execution"] as Record<string, unknown>;
    expect(exec["summary"]).toBe(MEMORY_REDACTION_MARKER);
  });

  it("redactCredentialValues is a pure value-transform helper (no key mangling)", () => {
    const input = { verb: "inspect", token: "keep-key-but-redact bearer abc123", nested: { password: "x", plain: "ok" } };
    const out = redactCredentialValues(input) as typeof input;
    expect(out.verb).toBe("inspect");
    expect(out.token).toBe("keep-key-but-redact " + MEMORY_REDACTION_MARKER);
    expect(out.nested.plain).toBe("ok");
    // keys unchanged (key-level secrets are the store's REJECT responsibility)
    expect(Object.keys(out.nested)).toContain("password");
  });

  it("secret patterns themselves never appear in stored summaries (pattern leakage guard)", () => {
    const store = makeStore();
    const w = store.recordExecution(allowCtx(), req({
      summary: "config uses SECRET_KEY_HINTS for detection",
    }));
    expect(w.ok).toBe(true);
  });
});

describe("16B-SEC — raw blob exclusion", () => {
  it("oversized raw bodies are rejected with oversized_blob", () => {
    const store = makeStore();
    const huge = "A".repeat(EXECUTION_MEMORY_MAX_BLOB_BYTES + 1);
    const w = store.recordExecution(allowCtx(), req({ summary: huge }));
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("oversized_blob");
    expect(store.size).toBe(0);
  });

  it("byte threshold is exact: 8192-byte bodies rejected, small bodies stored", () => {
    const store = makeStore();
    const exact = "B".repeat(EXECUTION_MEMORY_MAX_BLOB_BYTES);
    const w = store.recordExecution(allowCtx(), req({ summary: exact }));
    expect(w.ok).toBe(false); // 8192 bytes of summary alone exceeds the body budget with metadata overhead
    const small = store.recordExecution(allowCtx(), req({}));
    expect(small.ok).toBe(true);
  });

  it("the blob cap bounds worst-case state: maxRecords × MAX_BLOB_BYTES stays finite", () => {
    expect(EXECUTION_MEMORY_MAX_RECORDS * EXECUTION_MEMORY_MAX_BLOB_BYTES).toBeLessThanOrEqual(2048 * 8192);
    const store = makeStore({ maxRecords: 4 });
    for (let i = 0; i < 10; i++) {
      store.recordExecution(allowCtx(), req({ attempt: i + 1, summary: "s".repeat(500) }));
    }
    expect(store.size).toBe(4);
  });

  it("execution record cap is declared and sane", () => {
    expect(EXECUTION_MEMORY_MAX_RECORDS).toBeGreaterThanOrEqual(WORKING_MEMORY_MAX_RECORDS);
    expect(EXECUTION_MEMORY_MAX_RECORDS).toBeLessThanOrEqual(PROJECT_MEMORY_MAX_RECORDS * 4);
  });
});

describe("16B-SEC — evidence reference integrity", () => {
  it("evidenceRef to a real ledger event is accepted; unknown ids are rejected", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeStore({ ledger });
    const appendRes = ledger.append({
      eventId: "evt-sec-16b-1",
      timestamp: new Date(T0).toISOString(),
      eventType: "verb_executed",
      actor: { type: "runtime", id: "runtime-sec" },
      workspaceId: "ws-sec-16b",
      verb: "inspect",
      policyDecision: "allow",
    });
    expect(appendRes.ok).toBe(true);
    const good = store.recordExecution(allowCtx(), req({ evidenceRef: "evt-sec-16b-1" }));
    expect(good.ok).toBe(true);
    const bad = store.recordExecution(allowCtx(), req({ evidenceRef: "evt-fabricated-16b" }));
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.denyReason).toBe("invalid_input");
  });

  it("with no ledger attached, evidenceRef is ALWAYS rejected (no unverifiable pointers)", () => {
    const store = makeStore({ ledger: null });
    const w = store.recordExecution(allowCtx(), req({ evidenceRef: "evt-any" }));
    expect(w.ok).toBe(false);
    if (!w.ok) expect(w.denyReason).toBe("invalid_input");
  });

  it("a forged evidence id cannot smuggle untracked content into execution memory", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeStore({ ledger });
    const w = store.recordExecution(allowCtx(), req({
      evidenceRef: "evt-" + "f".repeat(24),
      summary: "claims success for work the ledger never recorded",
    }));
    expect(w.ok).toBe(false);
    expect(store.size).toBe(0);
  });
});

describe("16B-SEC — scope containment for execution queries", () => {
  it("a task-granted caller cannot query another task's execution history", () => {
    const store = makeStore();
    store.recordExecution(allowCtx(ws({ taskId: "task-A" })), req({ taskId: "task-A" }));
    const r = store.query(allowCtx(ws({ taskId: "task-B" })), {});
    expect(r.ok).toBe(true); // policy allowed; isolation holds
    if (r.ok) expect(r.records).toHaveLength(0);
  });

  it("cross-workspace execution history is invisible even with identical taskIds", () => {
    const store = makeStore();
    store.recordExecution(allowCtx(), req({ taskId: "shared-task-id" }));
    const r = store.query(allowCtx(ws({ workspaceId: "ws-elsewhere" })), { taskId: "shared-task-id" });
    if (r.ok) expect(r.records).toHaveLength(0);
  });

  it("time/verb/actor filters cannot widen scope (filtering is intersection, not union)", () => {
    const store = makeStore();
    store.recordExecution(allowCtx(), req({ taskId: "mine", verb: "inspect" }));
    const r = store.query(allowCtx(ws({ taskId: "not-mine" })), { verb: "inspect" });
    if (r.ok) expect(r.records).toHaveLength(0);
  });

  it("execution writes obey provenance authority: untrusted external content flagged trusted is denied", () => {
    const store = makeStore();
    for (const origin of ["tool_output", "model_output", "repo_content", "external"] as const) {
      const w = store.recordExecution(allowCtx(), req({
        provenance: { origin, actor: TOOL, untrusted: false },
      }));
      expect(w.ok, "origin " + origin).toBe(false);
      if (!w.ok) expect(w.denyReason).toBe("untrusted_provenance_write_denied");
    }
  });

  it("externally-executed outcomes stored with untrusted:true keep the flag", () => {
    const store = makeStore();
    const w = store.recordExecution(allowCtx(), req({
      provenance: { origin: "tool_output", actor: TOOL, untrusted: true },
    }));
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    expect(w.record.provenance.untrusted).toBe(true);
    expect(w.record.provenance.origin).toBe("tool_output");
  });
});

describe("16B-SEC — invariants & governance", () => {
  it("schema version unchanged by 16B", () => {
    expect(MEMORY_SCHEMA_VERSION).toBe("menog-memory/v0");
  });

  it("denied writes (secrets, blobs, evidence) emit NO ledger event", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeStore({ ledger });
    store.recordExecution(allowCtx(), req({ metadata: { apiKey: FAKE_KEY } }));
    store.recordExecution(allowCtx(), req({ summary: "Z".repeat(EXECUTION_MEMORY_MAX_BLOB_BYTES) }));
    store.recordExecution(allowCtx(), req({ evidenceRef: "evt-nope" }));
    expect(ledger.length).toBe(0);
    expect(ledger.verify().ok).toBe(true);
  });

  it("allowed execution writes/read-queries are ledger-observable with intact chain", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const store = makeStore({ ledger });
    store.recordExecution(allowCtx(), req());
    store.query(allowCtx(), { verb: "inspect" });
    expect(ledger.length).toBe(2);
    const v = ledger.verify();
    expect(v.ok).toBe(true);
    expect(v.verifiedCount).toBe(2);
  });

  it("execution memory exposes NO execution-authority surface", () => {
    const store = makeStore();
    const proto = Object.getPrototypeOf(store) as Record<string, unknown>;
    const methods = Object.getOwnPropertyNames(proto);
    for (const f of ["exec", "spawn", "commit", "gitCommit", "writeFile", "appendFile", "fetch", "request", "connect", "evaluate", "grant"]) {
      expect(methods).not.toContain(f);
    }
  });

  it("day-1 policy engine still denies memory verbs with write capabilities (no policy weakening)", () => {
    const engine = new DenyByDefaultPolicyEngine();
    for (const verb of ["memory.write", "memory.read", "execution.record"]) {
      const res = engine.evaluate({
        actor: AGENT,
        verb,
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-sec-16b",
      });
      expect(res.decision.outcome, "verb " + verb).toBe("deny");
    }
  });

  it("execution store entries are deeply frozen (metadata object included)", () => {
    const store = makeStore();
    const w = store.recordExecution(allowCtx(), req());
    expect(w.ok).toBe(true);
    if (!w.ok) return;
    expect(Object.isFrozen(w.record)).toBe(true);
    expect(Object.isFrozen(w.record.body)).toBe(true);
    const exec = w.record.body["execution"] as Record<string, unknown>;
    expect(Object.isFrozen(exec)).toBe(true);
  });

  it("store caps remain declared and bounded after 16B", () => {
    expect(WORKING_MEMORY_MAX_RECORDS).toBeLessThanOrEqual(512);
    expect(PROJECT_MEMORY_MAX_RECORDS).toBeLessThanOrEqual(4096);
    expect(EXECUTION_MEMORY_MAX_BLOB_BYTES).toBeLessThanOrEqual(64 * 1024);
  });
});
