import { describe, it, expect } from "vitest";
import {
  WorkingMemoryStore,
  ProjectMemoryStore,
  ExecutionMemoryStore,
  MemoryRetrievalService,
  lexicalRetrievalStrategy,
  recencyRetrievalStrategy,
  hybridRetrievalStrategy,
  MEMORY_SCHEMA_VERSION,
  MEMORY_SECRET_KEY_HINTS,
  findSecretKeyPaths,
  scopeCovers,
  memoryRecordHash,
  readExecutionMetadata,
  EXECUTION_MEMORY_MAX_BLOB_BYTES,
  EXECUTION_MEMORY_MAX_RECORDS,
  EXECUTION_METADATA_KEY,
  WORKING_MEMORY_MAX_RECORDS,
  PROJECT_MEMORY_MAX_RECORDS,
  RETRIEVAL_MAX_QUERY_CHARS,
  RETRIEVAL_MAX_LIMIT,
  RETRIEVAL_LEXICAL_WEIGHT,
  RETRIEVAL_RECENCY_WEIGHT,
  RETRIEVAL_RECENCY_HALF_LIFE_MS,
  isMemoryDenial,
  type MemoryPolicyGate,
  type MemoryScope,
  type RetrievalStrategy,
} from "@menog/memory";
import { SECRET_KEY_HINTS } from "@menog/event-ledger";
import { AppendOnlyLedger } from "@menog/event-ledger";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import type { Actor } from "@menog/core";

const AGENT: Actor = { type: "agent", id: "agent-freeze-16e" };
const TOOL: Actor = { type: "tool", id: "tool-freeze-16e" };

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

const T0 = 1_820_000_000_000;

function ws(overrides: Partial<MemoryScope> = {}): MemoryScope {
  return { workspaceId: "ws-freeze-16e", taskId: "task-freeze-16e", sessionId: "sess-freeze-16e", ...overrides };
}

function ctx(actor: Actor = AGENT, scope: MemoryScope = ws()) {
  return { actor, grantedScope: scope };
}

function note(memory: WorkingMemoryStore | ProjectMemoryStore, body: Record<string, unknown>, scope: MemoryScope = ws()): void {
  const w = memory.write(ctx(AGENT, scope), {
    scope,
    provenance: { origin: "runtime", actor: AGENT, untrusted: false },
    retention: { retentionClass: "session" },
    body,
  });
  if (!w.ok) throw new Error("fixture write failed: " + (w.ok ? "" : w.reason));
}

/**
 * 16E-E1 — Frozen literal constants. Any change to these values is a
 * contract break and must go through the unfreeze protocol
 * (PHASE_16_FREEZE.md §5) with explicit human approval.
 */
describe("16E — Memory V1 contract pins (schema, kinds, deny states)", () => {
  it("16E-P1 schema version is pinned at menog-memory/v0 (Memory V1)", () => {
    expect(MEMORY_SCHEMA_VERSION).toBe("menog-memory/v0");
  });

  it("16E-P2 memory kinds are exactly working | project | execution", () => {
    const w = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const p = new ProjectMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const e = new ExecutionMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    expect(w.kind).toBe("working");
    expect(p.kind).toBe("project");
    expect(e.kind).toBe("execution");
  });

  it("16E-P3 store capacity caps are pinned (bounded state)", () => {
    expect(WORKING_MEMORY_MAX_RECORDS).toBe(256);
    expect(PROJECT_MEMORY_MAX_RECORDS).toBe(1024);
    expect(EXECUTION_MEMORY_MAX_RECORDS).toBe(2048);
    expect(EXECUTION_MEMORY_MAX_BLOB_BYTES).toBe(8192);
  });

  it("16E-P4 retrieval constants are pinned (deterministic scoring contract)", () => {
    expect(RETRIEVAL_MAX_QUERY_CHARS).toBe(4096);
    expect(RETRIEVAL_MAX_LIMIT).toBe(100);
    expect(RETRIEVAL_LEXICAL_WEIGHT).toBe(0.6);
    expect(RETRIEVAL_RECENCY_WEIGHT).toBe(0.4);
    expect(RETRIEVAL_RECENCY_HALF_LIFE_MS).toBe(24 * 60 * 60 * 1000);
  });

  it("16E-P5 machine-readable deny reasons are exactly the frozen union (via observable behavior)", () => {
    const w = new WorkingMemoryStore({ policyGate: null, now: fixedClock(T0) });
    const r = w.read(ctx());
    const wr = w.write(ctx(), {
      scope: ws(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { note: "x" },
    });
    expect(isMemoryDenial(r) && r.denyReason).toBe("read_not_allowed");
    expect(isMemoryDenial(wr) && wr.denyReason).toBe("write_not_allowed");

    const wScope = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const cross = wScope.write(ctx(AGENT, ws({ taskId: "t-other" })), {
      scope: ws({ taskId: "t-here" }),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: {},
    });
    expect(isMemoryDenial(cross) && cross.denyReason).toBe("scope_mismatch");

    const bad = wScope.write(ctx(), {
      scope: ws(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "nope" } as unknown as { retentionClass: "session" },
      body: {},
    });
    expect(isMemoryDenial(bad) && bad.denyReason).toBe("invalid_input");

    const ex = new ExecutionMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const secret = ex.recordExecution(ctx(), {
      scope: ws(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      actor: AGENT,
      taskId: "t",
      verb: "v",
      outcome: "success",
      policyDecision: "allow",
      metadata: { apiKey: "x".repeat(8) },
    });
    expect(isMemoryDenial(secret) && secret.denyReason).toBe("secret_detected");

    const blob = ex.recordExecution(ctx(), {
      scope: ws(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      actor: AGENT,
      taskId: "t",
      verb: "v",
      outcome: "success",
      policyDecision: "allow",
      summary: "Z".repeat(EXECUTION_MEMORY_MAX_BLOB_BYTES),
    });
    expect(isMemoryDenial(blob) && blob.denyReason).toBe("oversized_blob");

    const untrusted = wScope.write(ctx(), {
      scope: ws(),
      provenance: { origin: "model_output", actor: TOOL, untrusted: false },
      retention: { retentionClass: "session" },
      body: {},
    });
    expect(isMemoryDenial(untrusted) && untrusted.denyReason).toBe("untrusted_provenance_write_denied");
  });

  it("16E-P6 retrieval strategy ids are pinned and the strategy surface is pure data", () => {
    expect(lexicalRetrievalStrategy.id).toBe("lexical");
    expect(recencyRetrievalStrategy.id).toBe("recency");
    expect(hybridRetrievalStrategy.id).toBe("hybrid");
    const strategies: readonly RetrievalStrategy[] = [lexicalRetrievalStrategy, recencyRetrievalStrategy, hybridRetrievalStrategy];
    for (const s of strategies) {
      expect(typeof s.description).toBe("string");
      expect(typeof s.rank).toBe("function");
    }
  });
});

/**
 * 16E-E2 — Memory semantics audit: records are typed structured state with
 * provenance, retention and hash anchoring — never raw transcripts.
 */
describe("16E — memory semantics audit", () => {
  it("16E-S1 records carry schema/provenance/retention/hash and are deeply frozen", () => {
    const w = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    note(w, { note: "semantic probe", nested: { deep: "value" } });
    const r = w.read(ctx());
    expect(r.ok).toBe(true);
    if (r.ok && r.records[0]) {
      const rec = r.records[0];
      expect(rec.schemaVersion).toBe(MEMORY_SCHEMA_VERSION);
      expect(rec.provenance.origin).toBe("runtime");
      expect(rec.provenance.untrusted).toBe(false);
      expect(rec.retention.retentionClass).toBe("session");
      expect(Object.isFrozen(rec)).toBe(true);
      expect(Object.isFrozen(rec.body)).toBe(true);
      expect(Object.isFrozen((rec.body as Record<string, unknown>)["nested"])).toBe(true);
      expect(memoryRecordHash(rec)).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("16E-S2 execution records are exactly { execution: ExecutionMetadata } with ledger-verifiable evidence", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const ex = new ExecutionMemoryStore({ policyGate: ALLOW_ALL, ledger, now: fixedClock(T0) });
    const app = ledger.append({
      eventId: "evt-16e-1",
      timestamp: new Date(T0).toISOString(),
      eventType: "verb_executed",
      actor: { type: "runtime", id: "runtime-16e" },
      workspaceId: "ws-freeze-16e",
      verb: "inspect",
      policyDecision: "allow",
    });
    expect(app.ok).toBe(true);
    const w = ex.recordExecution(ctx(), {
      scope: ws(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      actor: AGENT,
      taskId: "task-freeze-16e",
      verb: "inspect",
      outcome: "success",
      policyDecision: "allow",
      evidenceRef: "evt-16e-1",
      summary: "audit probe",
      recordedAtEpochMs: T0 + 5,
    });
    expect(w.ok).toBe(true);
    if (w.ok) {
      const body = w.record.body as Record<string, unknown>;
      expect(Object.keys(body).sort()).toEqual([EXECUTION_METADATA_KEY]);
      const meta = readExecutionMetadata(w.record);
      expect(meta).not.toBeNull();
      expect(meta!.evidenceRef).toBe("evt-16e-1");
    }
  });

  it("16E-S3 scope isolation semantics: narrowing allowed, widening denied (frozen rule)", () => {
    expect(scopeCovers({ workspaceId: "ws" }, { workspaceId: "ws" })).toBe(true);
    expect(scopeCovers({ workspaceId: "ws" }, { workspaceId: "ws", taskId: "t" })).toBe(true);
    expect(scopeCovers({ workspaceId: "ws", taskId: "t" }, { workspaceId: "ws" })).toBe(false);
    expect(scopeCovers({ workspaceId: "ws", sessionId: "s" }, { workspaceId: "ws", sessionId: "s2" })).toBe(false);
    expect(scopeCovers({ workspaceId: "a" }, { workspaceId: "b" })).toBe(false);
  });
});

/**
 * 16E-E3 — Redaction & secret-channel audit: ONE definition of a secret,
 * enforced across memory bodies, execution metadata, and ledger summaries.
 */
describe("16E — redaction and secret-channel audit", () => {
  it("16E-R1 memory secret hints are exactly the ledger SECRET_KEY_HINTS (shared definition)", () => {
    expect(MEMORY_SECRET_KEY_HINTS.length).toBe(SECRET_KEY_HINTS.length);
    for (let i = 0; i < SECRET_KEY_HINTS.length; i++) {
      expect(MEMORY_SECRET_KEY_HINTS[i]!.source).toBe(SECRET_KEY_HINTS[i]!.source);
    }
  });

  it("16E-R2 execution metadata secret channels are always rejected; values are redacted at rest", () => {
    const ex = new ExecutionMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const rejected = ex.recordExecution(ctx(), {
      scope: ws(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      actor: AGENT,
      taskId: "t",
      verb: "v",
      outcome: "success",
      policyDecision: "allow",
      metadata: { nested: { auth_token: "leak" } },
    });
    expect(rejected.ok).toBe(false);
    expect(findSecretKeyPaths({ a: { api_key: "v" } })).toEqual(["a.api_key"]);
  });

  it("16E-R3 ledger events across full memory traffic stay free of secret content and chain-verifiable", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const w = new WorkingMemoryStore({ policyGate: ALLOW_ALL, ledger, now: fixedClock(T0), rejectSecretKeys: true });
    const ex = new ExecutionMemoryStore({ policyGate: ALLOW_ALL, ledger, now: fixedClock(T0) });
    note(w, { note: "clean content for chain probe" });
    const wBad = w.write(ctx(), {
      scope: ws(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { apiKey: "x".repeat(8) },
    });
    expect(wBad.ok).toBe(false);
    const app = ledger.append({
      eventId: "evt-16e-2",
      timestamp: new Date(T0).toISOString(),
      eventType: "verb_executed",
      actor: { type: "runtime", id: "runtime-16e" },
      workspaceId: "ws-freeze-16e",
      verb: "inspect",
      policyDecision: "allow",
    });
    expect(app.ok).toBe(true);
    const wEx = ex.recordExecution(ctx(), {
      scope: ws(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      actor: AGENT,
      taskId: "task-freeze-16e",
      verb: "inspect",
      outcome: "success",
      policyDecision: "allow",
      evidenceRef: "evt-16e-2",
      summary: "curl -H 'Authorization: Bearer topsecretvalue999' failed",
      recordedAtEpochMs: T0 + 5,
    });
    expect(wEx.ok).toBe(true);
    const raw = JSON.stringify(ledger.events());
    expect(raw).not.toContain("x".repeat(8));
    expect(raw).not.toContain("topsecretvalue999");
    const v = ledger.verify();
    expect(v.ok).toBe(true);
    expect(v.verifiedCount).toBe(v.totalCount);
  });
});

/**
 * 16E-E4 — Isolation & authority audit: retrieval is projection, policy is
 * authoritative, memory confers no execution power.
 */
describe("16E — isolation and authority audit", () => {
  it("16E-A1 no memory surface exposes execution authority methods", () => {
    const stores = [
      new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) }),
      new ProjectMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) }),
      new ExecutionMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) }),
      new MemoryRetrievalService({}),
    ];
    const forbidden = ["exec", "spawn", "commit", "gitCommit", "writeFile", "appendFile", "fetch", "request", "connect", "evaluate", "grant"];
    for (const s of stores) {
      const proto = Object.getPrototypeOf(s) as Record<string, unknown>;
      for (const f of forbidden) {
        expect(Object.getOwnPropertyNames(proto)).not.toContain(f);
      }
    }
  });

  it("16E-A2 fail-closed is frozen: null gate denies reads AND writes on every store kind", () => {
    for (const store of [
      new WorkingMemoryStore({ policyGate: null, now: fixedClock(T0) }),
      new ProjectMemoryStore({ policyGate: null, now: fixedClock(T0) }),
      new ExecutionMemoryStore({ policyGate: null, now: fixedClock(T0) }),
    ]) {
      const r = store.read(ctx());
      expect(r.ok).toBe(false);
      const w = store.write(ctx(), {
        scope: ws(),
        provenance: { origin: "runtime", actor: AGENT, untrusted: false },
        retention: { retentionClass: "session" },
        body: { note: "x" },
      });
      expect(w.ok).toBe(false);
    }
  });

  it("16E-A3 policy engine remains authoritative over memory verbs (Day-1 deny unchanged)", () => {
    const engine = new DenyByDefaultPolicyEngine();
    for (const verb of ["memory.read", "memory.write", "retrieval.query", "execution.record"]) {
      const res = engine.evaluate({
        actor: AGENT,
        verb,
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-freeze-16e",
      });
      expect(res.decision.outcome, "verb " + verb).toBe("deny");
    }
  });

  it("16E-A4 retrieval composition cannot cross workspace boundaries (projection, not bypass)", () => {
    const w = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    const ex = new ExecutionMemoryStore({ policyGate: ALLOW_ALL, now: fixedClock(T0) });
    note(w, { note: "victim workspace treasure map" });
    const svc = new MemoryRetrievalService({ memory: w, execution: ex });
    const r = svc.retrieve(ctx(AGENT, ws({ workspaceId: "ws-attacker-16e" })), { text: "treasure map" });
    expect(r.ok).toBe(true); // policy allowed; isolation holds
    if (r.ok) expect(r.hits).toHaveLength(0);
  });
});

import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

function readDoc(relativePath: string): string {
  const full = path.resolve(process.cwd(), relativePath);
  expect(existsSync(full), "expected doc to exist: " + relativePath).toBe(true);
  return readFileSync(full, "utf8");
}

/**
 * 16E-V — Governance invariants frozen in Phase-16 artifacts (15E pattern).
 */
describe("16E — governance invariants frozen in Phase-16 artifacts", () => {
  const PR_BLOCK_LINES = [
    "PR-01 HUMAN_DISPOSITION_PENDING",
    "PR-02 HOLD",
    "PR-03 HUMAN_DISPOSITION_PENDING",
    "PR-04 HOLD",
    "PR-05 HOLD",
  ];
  const DOCS_CARRYING_PR_BLOCK = [
    "docs/release/PHASE_15_FREEZE.md",
    "docs/release/PROMPT_16B_REPORT.md",
    "docs/release/PROMPT_16C_REPORT.md",
    "docs/release/PROMPT_16D_REPORT.md",
    "docs/release/PHASE_16_FREEZE.md",
    "docs/release/PROMPT_16E_REPORT.md",
  ];

  it("16E-V1 PR-01..PR-05 disposition block is verbatim in all Phase-16 gate artifacts", () => {
    for (const doc of DOCS_CARRYING_PR_BLOCK) {
      // Whitespace-normalized: artifacts may align the block with extra spaces.
      const content = readDoc(doc).replace(/\s+/g, " ");
      for (const line of PR_BLOCK_LINES) {
        expect(content.includes(line), doc + " missing " + line).toBe(true);
      }
    }
  });

  it("16E-V2 authorization-not-granted lines are unchanged in all Phase-16 gate artifacts", () => {
    for (const doc of DOCS_CARRYING_PR_BLOCK) {
      const content = readDoc(doc).replace(/\s+/g, " ");
      expect(content.includes("AUTHORIZATION NOT GRANTED"), doc).toBe(true);
    }
  });

  it("16E-V3 no Phase-20 isolation primitives exist in the memory package source", () => {
    const srcRoot = path.resolve(process.cwd(), "packages/memory/src");
    const files = ["memory.ts", "execution-memory.ts", "retrieval.ts", "secrets.ts", "serialize.ts", "types.ts", "index.ts"];
    const forbidden = /cgroup|seccomp|landlock|rootless|unshare|clone3/i;
    for (const f of files) {
      const full = path.join(srcRoot, f);
      expect(existsSync(full), "memory source file missing: " + f).toBe(true);
      expect(forbidden.test(readFileSync(full, "utf8")), "Phase-20 primitive in " + f).toBe(false);
    }
  });

  it("16E-V4 memory package declares no external dependencies (workspace links only)", () => {
    const pkg = JSON.parse(readDoc("packages/memory/package.json")) as { dependencies?: Record<string, string> };
    const deps = Object.keys(pkg.dependencies ?? {});
    expect(deps.length).toBeGreaterThan(0);
    for (const d of deps) {
      expect(d.startsWith("@menog/"), "non-workspace dependency: " + d).toBe(true);
    }
  });

  it("16E-V5 semantic/vector memory is documented as ROADMAP ONLY in the freeze artifact", () => {
    const freeze = readDoc("docs/release/PHASE_16_FREEZE.md");
    expect(freeze.includes("ROADMAP ONLY")).toBe(true);
    // No implementation claim may appear for vector retrieval.
    expect(freeze.includes("vector retrieval is IMPLEMENTED")).toBe(false);
    expect(freeze.includes("Memory V1")).toBe(true);
  });

  it("16E-V6 phase freeze transition is declared (OPEN → FROZEN)", () => {
    const freeze = readDoc("docs/release/PHASE_16_FREEZE.md");
    expect(freeze.includes("Phase-16: OPEN → FROZEN")).toBe(true);
    expect(freeze.includes("PENDING HUMAN SIGNATURE")).toBe(true);
  });
});
