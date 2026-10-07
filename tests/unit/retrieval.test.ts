import { describe, it, expect } from "vitest";
import {
  WorkingMemoryStore,
  ExecutionMemoryStore,
  MemoryRetrievalService,
  lexicalRetrievalStrategy,
  recencyRetrievalStrategy,
  hybridRetrievalStrategy,
  lexicalScore,
  recencyScore,
  hybridScore,
  retrievalTokens,
  RETRIEVAL_MAX_LIMIT,
  RETRIEVAL_DEFAULT_LIMIT,
  RETRIEVAL_LEXICAL_WEIGHT,
  RETRIEVAL_RECENCY_WEIGHT,
  RETRIEVAL_RECENCY_HALF_LIFE_MS,
  MEMORY_SCHEMA_VERSION,
  type MemoryPolicyGate,
  type MemoryScope,
  type RetrievalStrategy,
} from "@menog/memory";
import { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";

const AGENT: Actor = { type: "agent", id: "agent-16c" };

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

const T0 = 1_790_000_000_000;

function wsScope(overrides: Partial<MemoryScope> = {}): MemoryScope {
  return { workspaceId: "ws-16c", taskId: "task-16c", sessionId: "sess-16c", ...overrides };
}

function ctx(actor: Actor = AGENT, scope: MemoryScope = wsScope()) {
  return { actor, grantedScope: scope };
}

function makeMemory(options: { now?: () => number; ledger?: AppendOnlyLedger | null } = {}): WorkingMemoryStore {
  return new WorkingMemoryStore({
    policyGate: ALLOW_ALL,
    ledger: options.ledger ?? null,
    now: options.now ?? fixedClock(T0),
  });
}

function makeExecution(options: { now?: () => number; ledger?: AppendOnlyLedger | null } = {}): ExecutionMemoryStore {
  return new ExecutionMemoryStore({
    policyGate: ALLOW_ALL,
    ledger: options.ledger ?? null,
    now: options.now ?? fixedClock(T0),
  });
}

/** Seed the execution store with one verifiable ledger event and one execution record. */
function seedExecution(
  ledger: AppendOnlyLedger,
  execution: ExecutionMemoryStore,
  overrides: { verb?: string; outcome?: "success" | "failure" | "denied"; summary?: string; taskId?: string } = {}
): void {
  const appendRes = ledger.append({
    eventId: "evt-16c-" + Math.random().toString(36).slice(2, 10),
    timestamp: new Date(T0).toISOString(),
    eventType: "verb_executed",
    actor: { type: "runtime", id: "runtime-16c" },
    workspaceId: "ws-16c",
    verb: overrides.verb ?? "inspect",
    policyDecision: "allow",
  });
  if (!appendRes.ok || !appendRes.event) throw new Error("ledger append failed");
  const w = execution.recordExecution(ctx(), {
    scope: wsScope(),
    provenance: { origin: "runtime", actor: AGENT, untrusted: false },
    retention: { retentionClass: "session" },
    actor: AGENT,
    taskId: overrides.taskId ?? "task-16c",
    verb: overrides.verb ?? "inspect",
    outcome: overrides.outcome ?? "success",
    policyDecision: "allow",
    evidenceRef: appendRes.event.eventId,
    summary: overrides.summary ?? "executed inspect verb",
    recordedAtEpochMs: T0 + 5,
  });
  if (!w.ok) throw new Error("execution record failed: " + (w.ok ? "" : w.reason));
}

describe("16C — ranking determinism", () => {
  it("equal inputs give byte-identical ranked output (same service instance)", () => {
    const memory = makeMemory();
    for (let i = 0; i < 5; i++) {
      memory.write(ctx(), {
        scope: wsScope(),
        provenance: { origin: "runtime", actor: AGENT, untrusted: false },
        retention: { retentionClass: "session" },
        body: { note: "policy gates memory writes", idx: i },
      });
    }
    const svc = new MemoryRetrievalService({ memory, now: () => T0 });
    const a = { svc, c: ctx() };
    const b = { svc, c: ctx() };
    const ra = a.svc.retrieve(a.c, { text: "policy gates", limit: 10 });
    const rb = b.svc.retrieve(b.c, { text: "policy gates", limit: 10 });
    expect(ra.ok && rb.ok).toBe(true);
    if (ra.ok && rb.ok) {
      expect(ra.hits.map((h) => [h.evidence.recordHash, h.score]))
        .toEqual(rb.hits.map((h) => [h.evidence.recordHash, h.score]));
      // Scores themselves are deterministic for equal inputs.
      for (const h of ra.hits) expect(Number.isFinite(h.score)).toBe(true);
    }
  });

  it("ties are broken by insertion order (stable sort), not arbitrarily", () => {
    const memory = makeMemory();
    const writtenIds: string[] = [];
    for (let i = 0; i < 4; i++) {
      const w = memory.write(ctx(), {
        scope: wsScope(),
        provenance: { origin: "runtime", actor: AGENT, untrusted: false },
        retention: { retentionClass: "session" },
        body: { tag: "identical-body-content", n: i },
      });
      if (w.ok) writtenIds.push(w.record.memoryId);
    }
    const svc = new MemoryRetrievalService({ memory, now: () => T0 });
    const r = svc.retrieve(ctx(), { text: "identical-body-content", limit: 10 });
    expect(r.ok).toBe(true);
    if (r.ok) {
      // All lexical scores equal ⇒ insertion order preserved within the
      // store's newest-first read order.
      const ids = r.hits.map((h) => h.evidence.recordId);
      expect(ids).toEqual(writtenIds.slice().reverse());
    }
  });

  it("higher lexical relevance ranks first", () => {
    const memory = makeMemory();
    const entries: Array<Record<string, unknown>> = [
      { note: "the quokka is a small marsupial" },
      { note: "policy gates memory writes in menog" },
      { note: "completely unrelated content about weather" },
    ];
    for (const body of entries) {
      memory.write(ctx(), {
        scope: wsScope(),
        provenance: { origin: "runtime", actor: AGENT, untrusted: false },
        retention: { retentionClass: "session" },
        body,
      });
    }
    const svc = new MemoryRetrievalService({ memory });
    const r = svc.retrieve(ctx(), { text: "policy gates memory", limit: 3 });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.hits.length).toBeGreaterThan(0);
      const top = String(r.hits[0]!.record.body["note"]);
      expect(top).toContain("policy gates memory");
      // Scores are non-increasing.
      for (let i = 1; i < r.hits.length; i++) {
        expect(r.hits[i - 1]!.score).toBeGreaterThanOrEqual(r.hits[i]!.score);
      }
    }
  });

  it("hybrid score equals the documented weighted blend of components", () => {
    const memory = makeMemory();
    memory.write(ctx(), {
      scope: wsScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { note: "budget approval workflow" },
    });
    const svc = new MemoryRetrievalService({ memory, recencyHalfLifeMs: 1000 });
    const r = svc.retrieve(ctx(), { text: "budget approval", limit: 5 });
    expect(r.ok).toBe(true);
    if (r.ok && r.hits[0]) {
      const h = r.hits[0];
      const expected = hybridScore(h.components.lexical, h.components.recency);
      expect(h.score).toBeCloseTo(expected, 12);
      expect(expected).toBeCloseTo(
        h.components.lexical * RETRIEVAL_LEXICAL_WEIGHT +
        h.components.recency * RETRIEVAL_RECENCY_WEIGHT,
        12
      );
    }
  });

  it("limit clamps to [0, RETRIEVAL_MAX_LIMIT] and defaults to RETRIEVAL_DEFAULT_LIMIT", () => {
    expect(RETRIEVAL_MAX_LIMIT).toBe(100);
    expect(RETRIEVAL_DEFAULT_LIMIT).toBe(10);
    const memory = makeMemory();
    for (let i = 0; i < 15; i++) {
      memory.write(ctx(), {
        scope: wsScope(),
        provenance: { origin: "runtime", actor: AGENT, untrusted: false },
        retention: { retentionClass: "session" },
        body: { topic: "clamp me", i },
      });
    }
    const svc = new MemoryRetrievalService({ memory });
    const r1 = svc.retrieve(ctx(), { text: "clamp", limit: 3 });
    if (r1.ok) expect(r1.hits).toHaveLength(3);
    const r2 = svc.retrieve(ctx(), { text: "clamp", limit: 100000 });
    if (r2.ok) expect(r2.hits.length).toBeLessThanOrEqual(RETRIEVAL_MAX_LIMIT);
    const r3 = svc.retrieve(ctx(), { text: "clamp" });
    if (r3.ok) expect(r3.hits).toHaveLength(RETRIEVAL_DEFAULT_LIMIT);
  });
});

describe("16C — empty memory", () => {
  it("retrieving from an empty store yields ok with zero hits (not an error)", () => {
    const svc = new MemoryRetrievalService({ memory: makeMemory() });
    const r = svc.retrieve(ctx(), { text: "anything" });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.hits).toHaveLength(0);
      expect(r.candidatesConsidered).toBe(0);
    }
  });

  it("empty query text with lexical strategy returns zero-score hits only when minScore=0", () => {
    const memory = makeMemory();
    memory.write(ctx(), {
      scope: wsScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { note: "some content" },
    });
    const svc = new MemoryRetrievalService({ memory });
    const rLex = svc.retrieve(ctx(), { text: "", limit: 5 }, "lexical");
    expect(rLex.ok).toBe(true);
    if (rLex.ok) {
      for (const h of rLex.hits) expect(h.score).toBe(0);
    }
    const rFiltered = svc.retrieve(ctx(), { text: "", minScore: 0.01 }, "lexical");
    if (rFiltered.ok) expect(rFiltered.hits).toHaveLength(0);
  });

  it("retrieval service with no stores denies with read_not_allowed (no silent empty)", () => {
    const svc = new MemoryRetrievalService({});
    const r = svc.retrieve(ctx(), { text: "anything" });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denyReason).toBe("read_not_allowed");
      expect(r.reason).toContain("deny-by-default");
    }
  });
});

describe("16C — scope filters", () => {
  it("retrieval never crosses workspace boundaries", () => {
    const memory = makeMemory();
    memory.write(ctx(), {
      scope: wsScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { note: "workspace one budget plan" },
    });
    const svc = new MemoryRetrievalService({ memory });
    const r = svc.retrieve(ctx(AGENT, wsScope({ workspaceId: "ws-elsewhere" })), { text: "budget plan" });
    expect(r.ok).toBe(true); // policy allowed; isolation holds
    if (r.ok) expect(r.hits).toHaveLength(0);
  });

  it("task-granted callers cannot retrieve other tasks' records via taskId filters", () => {
    const memory = makeMemory();
    memory.write(ctx(AGENT, { workspaceId: "ws-16c", taskId: "task-A" }), {
      scope: { workspaceId: "ws-16c", taskId: "task-A" },
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { note: "task A private budget" },
    });
    const svc = new MemoryRetrievalService({ memory });
    const r = svc.retrieve(
      ctx(AGENT, { workspaceId: "ws-16c", taskId: "task-B" }),
      { text: "task A private budget", taskId: "task-A" }
    );
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.hits).toHaveLength(0);
  });

  it("execution metadata filters (verb/actorId/outcome) narrow without widening", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const execution = makeExecution({ ledger });
    seedExecution(ledger, execution, { verb: "inspect", outcome: "success", summary: "inspect ran" });
    seedExecution(ledger, execution, { verb: "git.status", outcome: "failure", summary: "git status failed" });
    const svc = new MemoryRetrievalService({ execution });
    const r = svc.retrieve(ctx(), { text: "git", verb: "git.status" });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.hits).toHaveLength(1);
      expect(r.hits[0]!.sourceKind).toBe("execution");
    }
    const rEmpty = svc.retrieve(ctx(AGENT, wsScope({ workspaceId: "ws-other" })), { text: "git" });
    if (rEmpty.ok) expect(rEmpty.hits).toHaveLength(0);
  });
});

describe("16C — stale data behavior", () => {
  it("expired ephemeral records disappear from retrieval (16A retention respected)", () => {
    let now = T0;
    const memory = new WorkingMemoryStore({
      policyGate: ALLOW_ALL,
      now: () => now,
    });
    memory.write(ctx(), {
      scope: wsScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "ephemeral", expiresAtEpochMs: T0 + 100 },
      body: { note: "short-lived scratch note" },
    });
    const svc = new MemoryRetrievalService({ memory });
    const before = svc.retrieve(ctx(), { text: "scratch" });
    expect(before.ok).toBe(true);
    if (before.ok) expect(before.hits).toHaveLength(1);

    now = T0 + 101;
    const after = svc.retrieve(ctx(), { text: "scratch" });
    expect(after.ok).toBe(true);
    if (after.ok) expect(after.hits).toHaveLength(0);
  });

  it("recency decays with age: newer records outrank older identical records", () => {
    let now = T0;
    const memory = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: () => now });
    memory.write(ctx(), {
      scope: wsScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { note: "deploy runbook", v: 1 },
    });
    now = T0 + RETRIEVAL_RECENCY_HALF_LIFE_MS; // one half-life later
    memory.write(ctx(), {
      scope: wsScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { note: "deploy runbook", v: 2 },
    });
    now = T0 + RETRIEVAL_RECENCY_HALF_LIFE_MS + 50; // read time
    const svc = new MemoryRetrievalService({ memory, recencyHalfLifeMs: RETRIEVAL_RECENCY_HALF_LIFE_MS });
    const r = svc.retrieve(ctx(), { text: "deploy runbook", limit: 2 }, "hybrid");
    expect(r.ok).toBe(true);
    if (r.ok && r.hits.length === 2) {
      // Equal lexical, different recency ⇒ v2 (newer) first with ~2x recency component.
      expect(r.hits[0]!.record.body["v"]).toBe(2);
      expect(r.hits[0]!.components.recency).toBeGreaterThan(r.hits[1]!.components.recency);
      const ratio = r.hits[0]!.components.recency / r.hits[1]!.components.recency;
      expect(ratio).toBeCloseTo(2, 1); // exactly one half-life apart
    }
  });

  it("stale records (old recency) are still retrievable via lexical when relevant", () => {
    let now = T0;
    const memory = new WorkingMemoryStore({ policyGate: ALLOW_ALL, now: () => now });
    memory.write(ctx(), {
      scope: wsScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { note: "the canonical build command is pnpm build" },
    });
    now = T0 + 100 * RETRIEVAL_RECENCY_HALF_LIFE_MS; // very stale
    const svc = new MemoryRetrievalService({ memory, recencyHalfLifeMs: RETRIEVAL_RECENCY_HALF_LIFE_MS });
    const r = svc.retrieve(ctx(), { text: "canonical build command" }, "lexical");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.hits).toHaveLength(1); // lexical does not age
  });
});

describe("16C — evidence references", () => {
  it("execution hits carry the ledger evidenceRef verbatim", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const execution = makeExecution({ ledger });
    seedExecution(ledger, execution, { summary: "deploy completed successfully" });
    const svc = new MemoryRetrievalService({ execution });
    const r = svc.retrieve(ctx(), { text: "deploy completed" });
    expect(r.ok).toBe(true);
    if (r.ok && r.hits[0]) {
      expect(r.hits[0].evidence.evidenceRef).toMatch(/^evt-16c-/);
      expect(r.hits[0].evidence.recordHash).toMatch(/^[0-9a-f]{64}$/);
      expect(r.hits[0].evidence.recordId).toMatch(/^ex-/);
    }
  });

  it("plain memory hits carry evidenceRef null but a real record hash", () => {
    const memory = makeMemory();
    memory.write(ctx(), {
      scope: wsScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { note: "plain memory note" },
    });
    const svc = new MemoryRetrievalService({ memory });
    const r = svc.retrieve(ctx(), { text: "plain memory" });
    expect(r.ok).toBe(true);
    if (r.ok && r.hits[0]) {
      expect(r.hits[0].evidence.evidenceRef).toBeNull();
      expect(r.hits[0].evidence.recordHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("retrieved records keep provenance (origin + untrusted) intact for downstream consumers", () => {
    const memory = makeMemory();
    memory.write(ctx(), {
      scope: wsScope(),
      provenance: { origin: "repo_content", actor: { type: "tool", id: "reader" }, untrusted: true },
      retention: { retentionClass: "session" },
      body: { note: "content read from a repository file" },
    });
    const svc = new MemoryRetrievalService({ memory });
    const r = svc.retrieve(ctx(), { text: "repository file" });
    expect(r.ok).toBe(true);
    if (r.ok && r.hits[0]) {
      expect(r.hits[0].record.provenance.untrusted).toBe(true);
      expect(r.hits[0].record.provenance.origin).toBe("repo_content");
    }
  });

  it("every allowed retrieval is policy-observable via the underlying store ledger event", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const memory = makeMemory({ ledger });
    memory.write(ctx(), {
      scope: wsScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { note: "observable retrieval" },
    });
    const writes = ledger.length;
    const svc = new MemoryRetrievalService({ memory });
    const r = svc.retrieve(ctx(), { text: "observable" });
    expect(r.ok).toBe(true);
    expect(ledger.length).toBe(writes + 1); // one memory_read event
    expect(ledger.verify().ok).toBe(true);
    if (r.ok) {
      const evt = ledger.events().find((e) => e.eventId === r.policyEventId);
      expect(evt).toBeDefined();
      expect(evt!.eventType).toBe("memory_read");
    }
  });
});

describe("16C — scoring functions and strategy interface", () => {
  it("retrievalTokens is deterministic and lowercased", () => {
    expect(retrievalTokens("Hello World-foo_bar 42")).toEqual(["hello", "world", "foo", "bar", "42"]);
    expect(retrievalTokens("")).toEqual([]);
    expect(retrievalTokens("...")).toEqual([]);
  });

  it("lexicalScore: exact match beats partial beats miss; always in [0,1]", () => {
    const mk = (note: string) => ({
      schemaVersion: MEMORY_SCHEMA_VERSION,
      memoryId: "wm-x",
      kind: "working" as const,
      scope: { workspaceId: "w" },
      provenance: { origin: "runtime" as const, actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" as const },
      body: { note },
      createdAtEpochMs: T0,
      createdByActorId: "agent-16c",
    });
    const exact = lexicalScore("budget approval", mk("budget approval workflow"));
    const partial = lexicalScore("budget approval", mk("budget discussion"));
    const miss = lexicalScore("budget approval", mk("weather report"));
    expect(exact).toBeGreaterThan(partial);
    expect(partial).toBeGreaterThan(miss);
    expect(miss).toBeGreaterThanOrEqual(0);
    expect(exact).toBeLessThanOrEqual(1);
    expect(lexicalScore("", mk("anything"))).toBe(0);
    // Subtoken matching: "auth" matches "authtoken" partially.
    const sub = lexicalScore("auth", mk("stored authtoken here"));
    expect(sub).toBeGreaterThan(0);
  });

  it("recencyScore: 1 at age 0, halves each half-life, clamped to [0,1] and finite", () => {
    expect(recencyScore(T0, T0, 1000)).toBe(1);
    expect(recencyScore(T0 - 1000, T0, 1000)).toBeCloseTo(0.5, 10);
    expect(recencyScore(T0 - 2000, T0, 1000)).toBeCloseTo(0.25, 10);
    // Deep decay underflows to exactly 0 in f64 (deterministic, finite, in range);
    // reachable only with pathological half-life parameters (default 24h never does).
    const ancient = recencyScore(T0 - 10_000_000, T0, 1000);
    expect(ancient).toBeGreaterThanOrEqual(0);
    expect(Number.isFinite(ancient)).toBe(true);
    // Monotonic: older never scores higher.
    expect(recencyScore(T0 - 3000, T0, 1000)).toBeLessThanOrEqual(recencyScore(T0 - 2000, T0, 1000));
    expect(recencyScore(T0 + 1000, T0, 1000)).toBe(1); // future timestamp clamps to 1
  });

  it("hybridScore blends with documented weights and clamps to [0,1]", () => {
    expect(hybridScore(1, 0)).toBeCloseTo(RETRIEVAL_LEXICAL_WEIGHT, 12);
    expect(hybridScore(0, 1)).toBeCloseTo(RETRIEVAL_RECENCY_WEIGHT, 12);
    expect(hybridScore(1, 1)).toBe(1);
    expect(hybridScore(0, 0)).toBe(0);
    expect(hybridScore(2, -5)).toBeLessThanOrEqual(1);
    expect(hybridScore(0.6, 0.4)).toBeCloseTo(0.6 * 0.6 + 0.4 * 0.4, 12);
  });

  it("built-in strategies are registered with stable ids and descriptions", () => {
    const svc = new MemoryRetrievalService({});
    expect(svc.strategyIds).toEqual(["hybrid", "lexical", "recency"]);
    expect(lexicalRetrievalStrategy.id).toBe("lexical");
    expect(recencyRetrievalStrategy.id).toBe("recency");
    expect(hybridRetrievalStrategy.id).toBe("hybrid");
    expect(typeof lexicalRetrievalStrategy.description).toBe("string");
  });

  it("unknown strategy id denies with strategy_not_found (no silent fallback)", () => {
    const svc = new MemoryRetrievalService({ memory: makeMemory() });
    const r = svc.retrieve(ctx(), { text: "anything" }, "vector-v1");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.denyReason).toBe("strategy_not_found");
      expect(r.reason).toContain("vector-v1");
    }
  });

  it("a custom RetrievalStrategy participates in ranking (extension point for vector/graph)", () => {
    const keywordBoost: RetrievalStrategy = {
      id: "keyword-boost",
      description: "test-only strategy: exact keyword presence",
      rank: (candidates, query) => {
        const text = (query.text ?? "").toLowerCase();
        const hits = candidates
          .filter((c) => JSON.stringify(c.record.body).toLowerCase().includes(text))
          .slice(0, query.limit ?? 10)
          .map((c) => ({
            record: c.record,
            sourceKind: c.sourceKind,
            score: 1,
            components: { lexical: 1, recency: 0 },
            evidence: {
              evidenceRef: null,
              recordHash: "custom-hash-not-used",
              recordId: c.record.memoryId,
            },
          }));
        return {
          ok: true,
          strategy: "keyword-boost",
          hits: Object.freeze(hits),
          candidatesConsidered: candidates.length,
        };
      },
    };
    const memory = makeMemory();
    memory.write(ctx(), {
      scope: wsScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { note: "menog custom strategy target" },
    });
    const svc = new MemoryRetrievalService({ memory, strategies: [keywordBoost] });
    expect(svc.strategyIds).toContain("keyword-boost");
    const r = svc.retrieve(ctx(), { text: "custom strategy" }, "keyword-boost");
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.strategy).toBe("keyword-boost");
      expect(r.hits).toHaveLength(1);
      expect(r.hits[0]!.score).toBe(1);
    }
  });

  it("hybrid combines both stores (memory + execution) in one ranked result", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const memory = makeMemory({ ledger });
    const execution = makeExecution({ ledger });
    memory.write(ctx(), {
      scope: wsScope(),
      provenance: { origin: "runtime", actor: AGENT, untrusted: false },
      retention: { retentionClass: "session" },
      body: { note: "inspect flow learned behavior" },
    });
    seedExecution(ledger, execution, { verb: "inspect", summary: "inspect executed ok" });
    const svc = new MemoryRetrievalService({ memory, execution });
    const r = svc.retrieve(ctx(), { text: "inspect", limit: 10 });
    expect(r.ok).toBe(true);
    if (r.ok) {
      const kinds = r.hits.map((h) => h.sourceKind).sort();
      expect(kinds).toEqual(["execution", "memory"]);
    }
  });
});
