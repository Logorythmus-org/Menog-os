/**
 * PHASE 23C — Live Surface Continuity Wiring tests
 * (INTEGRATION / NO AUTO-RESUME).
 *
 * Required proofs (per surface: memory / task / agent / registry):
 *   P1 live mutation → durable confirmation (formal barrier)
 *   P2 reopen/bootstrap → safe equivalent view
 *   P3 persistence failure cannot create an unrecorded authoritative transition
 *   P4 stale revision/epoch denial
 *   P5 no restored execution authority
 *   P6 anti-resurrection (terminal facts stay terminal)
 * Cross-cutting: expiry survives restart · denylists on write AND view ·
 * no subsystem bypasses the coordinator (structural pin).
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import {
  DurableStore,
  RuntimeStateCoordinator,
  LiveSurfaceWiring,
  SURFACE_WIRING_PERSIST_CALLS,
  durableContentHash,
  type AgentMetadataState,
  type MemoryStateRecord,
  type RegistryLifecycleState,
  type TaskLifecycleState,
  type RecoveryRequest,
  type RuntimeEpoch,
} from "@menog/durable-state";

const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as {
  DatabaseSync: new (path: string) => {
    prepare(sql: string): { run(...args: unknown[]): void; get(...args: unknown[]): unknown };
  };
};

const roots: string[] = [];
const openStores: DurableStore[] = [];
const openCoords: RuntimeStateCoordinator[] = [];
function newRoot(): string {
  const r = mkdtempSync(join(tmpdir(), "menog-23c-"));
  roots.push(r);
  return r;
}
function openStoreAt(root: string) {
  const open = DurableStore.open(root);
  if (open.ok) openStores.push(open.store);
  return open;
}
afterEach(() => {
  for (const c of openCoords) { try { c.close(); } catch { /* already closed */ } }
  for (const s of openStores) { try { if (s.isOpen) s.close(); } catch { /* already closed */ } }
  openCoords.length = 0;
  openStores.length = 0;
  for (const r of roots) {
    try { rmSync(r, { recursive: true, force: true }); } catch { /* windows handles */ }
  }
  roots.length = 0;
});

// ── fixtures ─────────────────────────────────────────────────────────────────

const EPOCH_A = "re-000000ca0001-aaaaaaaaaaaaaaaa";
const EPOCH_B = "re-000000ca0002-bbbbbbbbbbbbbbbb";

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

function memRecord(memoryId: string, overrides: Partial<MemoryStateRecord> = {}): MemoryStateRecord {
  return {
    schemaVersion: "test/mem/v1",
    memoryId,
    kind: "project",
    scope: { workspaceId: "ws-23c" },
    provenance: { origin: "unit-test:23c", actor: { type: "agent", id: "agent-wire-01" }, untrusted: false },
    retention: { retentionClass: "persistent" },
    body: { note: "23c memory" },
    createdAtEpochMs: 1759100000100,
    createdByActorId: "agent-wire-01",
    ...overrides,
  };
}

function agentState(agentId = "agent-wire-01"): AgentMetadataState {
  return {
    schemaVersion: "test/agent/v1",
    agentId,
    role: "builder",
    registeredAtEpochMs: 1759100000000,
    profile: {
      allowedVerbs: ["workspace:read"],
      allowedCapabilities: ["workspace:read"],
      maxSideEffectClass: "read",
      description: "wired agent",
    },
    authority: "mediation",
    executionAuthorized: false as const,
  };
}

function taskState(goalId: string, status: TaskLifecycleState["status"]): TaskLifecycleState {
  return {
    schemaVersion: "test/task/v1",
    goalId,
    planId: null,
    taskIds: ["task-" + goalId],
    status,
    rationale: "unit-test:23c",
    updatedAtEpochMs: 1759100000200,
  };
}

function regState(lifecycle: RegistryLifecycleState["lifecycle"], toolId = "fs.read", version = "1.0.0"): RegistryLifecycleState {
  return {
    schemaVersion: "test/reg/v1",
    toolId,
    version,
    manifestHash: "a".repeat(64),
    lifecycle,
    registeredBy: "unit-test:23c",
    updatedAtEpochMs: 1759100000300,
  };
}

const RECOVERY_REQUEST: RecoveryRequest = {
  mode: "load_committed_state",
  expectedStoreSchemaVersion: "menog-durable-store/v0",
  maxRecords: 10000,
  semantics: "no_execution",
};

function openWiring(root: string, epochId = EPOCH_A) {
  const open = openStoreAt(root);
  if (!open.ok) throw new Error(open.reason);
  const bound = RuntimeStateCoordinator.open(open.store, epochOf(epochId), "unit-test:23c");
  if (!bound.ok) throw new Error(bound.reason);
  openCoords.push(bound.coordinator);
  const wired = LiveSurfaceWiring.open(open.store, bound.coordinator, epochOf(epochId));
  if (!wired.ok) throw new Error(wired.reason);
  return { store: open.store, coordinator: bound.coordinator, wiring: wired.wiring };
}

// ── memory surface ───────────────────────────────────────────────────────────

describe("23C memory — live mutation → durable confirmation → safe view", () => {
  it("P1: writeMemory is barrier-confirmed and the view resolves the identical record", () => {
    const { wiring } = openWiring(newRoot());
    const r = wiring.writeMemory({ record: memRecord("mem-wire-01"), transactionId: "tx-23c-mem-01" });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.code).toBe("durable");
      expect(r.barrier.outcome).toBe("committed");
      expect(r.commitSequence).toBeGreaterThan(0);
    }
    const view = wiring.readMemory("mem-wire-01", 1759200000000);
    expect(view.ok).toBe(true);
    if (view.ok) {
      expect(view.record.body).toEqual({ note: "23c memory" });
      expect(view.revision).toBe(1);
      expect(view.restorable).toBe(true);
    }
  });

  it("P3: a denied-key refusal records NOTHING (no revision consumed, no fact created)", () => {
    const { wiring } = openWiring(newRoot());
    const refused = wiring.writeMemory({
      record: memRecord("mem-wire-02", { body: { api_key: "not-a-real-key" } as unknown as Record<string, unknown> }),
      transactionId: "tx-23c-mem-02",
    });
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.code).toBe("store_denied");
    const view = wiring.readMemory("mem-wire-02", 1759200000000);
    expect(view.ok).toBe(false);
    // The next legitimate write must still be revision 1 — the refusal
    // consumed no revision and created no authoritative transition:
    const good = wiring.writeMemory({ record: memRecord("mem-wire-02"), transactionId: "tx-23c-mem-03" });
    expect(good.ok).toBe(true);
    if (good.ok) expect(good.revision).toBe(1);
  });

  it("P4: a hostile ownership takeover denies every subsequent write (stale epoch)", () => {
    const { store, wiring } = openWiring(newRoot());
    expect(wiring.writeMemory({ record: memRecord("mem-wire-03"), transactionId: "tx-23c-mem-04" }).ok).toBe(true);
    store.setMeta("runtime_live_owner_epoch", EPOCH_B + "|hostile-takeover");
    const r = wiring.writeMemory({ record: memRecord("mem-wire-04"), transactionId: "tx-23c-mem-05" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("stale_epoch");
    const view = wiring.readMemory("mem-wire-04", 1759200000000);
    expect(view.ok).toBe(false);
  });

  it("the wiring's records are byte-compatible with the 22D readers (same record, same chain)", async () => {
    const { store, wiring } = openWiring(newRoot());
    expect(wiring.writeMemory({ record: memRecord("mem-wire-05"), transactionId: "tx-23c-mem-06" }).ok).toBe(true);
    const { readMemoryRecord, persistMemoryRecord } = await import("@menog/durable-state");
    const via22D = readMemoryRecord(store, "mem-wire-05");
    expect(via22D.ok).toBe(true);
    if (via22D.ok) expect(via22D.record.memoryId).toBe("mem-wire-05");
    // A 22D writer at the consumed revision is a store-level conflict —
    // the wiring did not fork a parallel namespace:
    const conflict = persistMemoryRecord(store, {
      record: memRecord("mem-wire-05"),
      revision: 1,
      supersedesRevision: null,
      transactionId: "tx-23c-mem-07",
    });
    expect(conflict.ok).toBe(false);
  });

  it("expiry survives restart: expired ephemeral memory is excluded (not corrupt), future expiry is restorable", () => {
    const root = newRoot();
    const { wiring } = openWiring(root);
    expect(wiring.writeMemory({
      record: memRecord("mem-wire-06", {
        kind: "working",
        retention: { retentionClass: "ephemeral", expiresAtEpochMs: 1759100000500 },
      }),
      transactionId: "tx-23c-mem-08",
    }).ok).toBe(true);
    expect(wiring.writeMemory({
      record: memRecord("mem-wire-07", {
        kind: "working",
        retention: { retentionClass: "ephemeral", expiresAtEpochMs: 1759300000500 },
      }),
      transactionId: "tx-23c-mem-09",
    }).ok).toBe(true);
    const viewPast = wiring.readMemory("mem-wire-06", 1759200000000);
    expect(viewPast.ok).toBe(true);
    if (viewPast.ok) expect(viewPast.restorable).toBe(false);
    // Restart + bootstrap: the expired entry is excluded from admission.
    wiring.close();
    const reopened = openWiring(root, EPOCH_B);
    const boot = reopened.wiring.bootstrapFromRecovery({ request: RECOVERY_REQUEST, nowEpochMs: 1759200000000 });
    expect(boot.ok).toBe(true);
    expect(boot.expiredMemoryIds).toContain("mem-wire-06");
    expect(boot.expiredMemoryIds).not.toContain("mem-wire-07");
  });
});

// ── task/goal surface ────────────────────────────────────────────────────────

describe("23C task lifecycle — facts only, NO auto-resume, terminal stays terminal", () => {
  it("P1: executing → durable; the view reports the fact and the next legal transitions", () => {
    const { wiring } = openWiring(newRoot());
    const r = wiring.writeTaskLifecycle({ state: taskState("goal-wire-01", "executing"), previousStatus: null, transactionId: "tx-23c-task-01" });
    expect(r.ok).toBe(true);
    const view = wiring.readTaskLifecycle("goal-wire-01");
    expect(view.ok).toBe(true);
    if (view.ok) {
      expect(view.state.status).toBe("executing");
      expect(view.terminal).toBe(false);
      expect(view.nextLegalTransitions).toContain("interrupted");
    }
  });

  it("P3: an illegal transition is refused and records NOTHING (the fact stays as it was)", () => {
    const { wiring } = openWiring(newRoot());
    expect(wiring.writeTaskLifecycle({ state: taskState("goal-wire-02", "executing"), previousStatus: null, transactionId: "tx-23c-task-02" }).ok).toBe(true);
    const illegal = wiring.writeTaskLifecycle({
      state: taskState("goal-wire-02", "rejected"),
      previousStatus: "executing",
      transactionId: "tx-23c-task-03",
    });
    expect(illegal.ok).toBe(false);
    if (!illegal.ok) expect(illegal.code).toBe("invalid_task_transition");
    const view = wiring.readTaskLifecycle("goal-wire-02");
    expect(view.ok).toBe(true);
    if (view.ok) expect(view.state.status).toBe("executing"); // unchanged fact
  });

  it("P6: terminal facts cannot be rewritten (done stays done); interrupted restores as interrupted — no resume API exists", () => {
    const root = newRoot();
    const { wiring } = openWiring(root);
    expect(wiring.writeTaskLifecycle({ state: taskState("goal-wire-03", "executing"), previousStatus: null, transactionId: "tx-23c-task-04" }).ok).toBe(true);
    expect(wiring.writeTaskLifecycle({ state: taskState("goal-wire-03", "done"), previousStatus: "executing", transactionId: "tx-23c-task-05" }).ok).toBe(true);
    const rewrite = wiring.writeTaskLifecycle({
      state: taskState("goal-wire-03", "executing"),
      previousStatus: "done",
      transactionId: "tx-23c-task-06",
    });
    expect(rewrite.ok).toBe(false);
    if (!rewrite.ok) expect(rewrite.code).toBe("terminal_state_rewrite");
    const view = wiring.readTaskLifecycle("goal-wire-03");
    expect(view.ok).toBe(true);
    if (view.ok) {
      expect(view.state.status).toBe("done");
      expect(view.terminal).toBe(true);
      expect(view.nextLegalTransitions).toEqual([]); // terminal: no next transitions
    }
    // In-flight interruption: restores as a FACT, never auto-resumed.
    expect(wiring.writeTaskLifecycle({ state: taskState("goal-wire-04", "executing"), previousStatus: null, transactionId: "tx-23c-task-07" }).ok).toBe(true);
    expect(wiring.writeTaskLifecycle({ state: taskState("goal-wire-04", "interrupted"), previousStatus: "executing", transactionId: "tx-23c-task-08" }).ok).toBe(true);
    wiring.close();
    const reopened = openWiring(root, EPOCH_B);
    const boot = reopened.wiring.bootstrapFromRecovery({ request: RECOVERY_REQUEST, nowEpochMs: 1759200000000 });
    expect(boot.ok).toBe(true);
    const iview = reopened.wiring.readTaskLifecycle("goal-wire-04");
    expect(iview.ok).toBe(true);
    if (iview.ok) {
      expect(iview.state.status).toBe("interrupted"); // NOT executing: nothing resumed
      expect(iview.nextLegalTransitions).toEqual(["executing", "proposed"]); // a CALLER must drive it explicitly
    }
  });
});

// ── agent surface ────────────────────────────────────────────────────────────

describe("23C agent metadata — metadata only, NO restored execution authority", () => {
  it("P1+P5: write is barrier-confirmed; the view re-verifies the frozen 19A markers", () => {
    const { wiring } = openWiring(newRoot());
    const r = wiring.writeAgentMetadata({ state: agentState(), transactionId: "tx-23c-agent-01" });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.barrier.outcome).toBe("committed");
    const view = wiring.readAgentMetadata("agent-wire-01");
    expect(view.ok).toBe(true);
    if (view.ok) {
      expect(view.state.authority).toBe("mediation");
      expect(view.state.executionAuthorized).toBe(false);
    }
  });

  it("P5: a re-sealed tamper claiming execution authority fails closed at the view AND is excluded from recovery", () => {
    const root = newRoot();
    const { wiring } = openWiring(root);
    expect(wiring.writeAgentMetadata({ state: agentState(), transactionId: "tx-23c-agent-02" }).ok).toBe(true);
    // Tamper + re-seal (content-hash-consistent corruption, 22F A12 class):
    const db = new DatabaseSync(join(root, "menog-store", "durable.db"));
    const row = db.prepare("SELECT record_id, revision, record_kind, durability_class, transaction_id, created_at_epoch_ms, payload_json FROM records WHERE record_id = ?")
      .get("agt-agent-wire-01") as Record<string, string | number>;
    const payload = JSON.parse(row.payload_json as string) as Record<string, unknown>;
    const tampered = {
      ...payload,
      agentMetadata: { ...(payload.agentMetadata as Record<string, unknown>), executionAuthorized: true },
    };
    const body = {
      schemaVersion: "menog-durable-record/v0",
      recordId: row.record_id,
      recordKind: row.record_kind,
      durabilityClass: row.durability_class,
      secretPolicy: "secret_free",
      authority: "durable_state",
      revision: row.revision,
      supersedesRevision: Number(row.revision) > 1 ? Number(row.revision) - 1 : null,
      createdAtEpochMs: row.created_at_epoch_ms,
      transactionId: row.transaction_id,
      payload: tampered,
    };
    db.prepare("UPDATE records SET payload_json = ?, content_hash = ? WHERE record_id = ?")
      .run(JSON.stringify(tampered), durableContentHash(body as Parameters<typeof durableContentHash>[0]), "agt-agent-wire-01");
    // The view refuses (metadata only — a tampered grant is not a grant):
    const view = wiring.readAgentMetadata("agent-wire-01");
    expect(view.ok).toBe(false);
    if (!view.ok) expect(view.code).toBe("invalid_lineage");
    // Recovery excludes the tampered record (authority_marker_violation):
    const boot = wiring.bootstrapFromRecovery({ request: RECOVERY_REQUEST, nowEpochMs: 1759200000000 });
    expect(boot.decision.code).toBe("accept_without_quarantined");
    expect(boot.admittedByKind.agent_metadata).toBe(0);
  });

  it("P2: reopen + bootstrap restores metadata exactly (equivalent view), still authority-free", () => {
    const root = newRoot();
    const { wiring } = openWiring(root);
    expect(wiring.writeAgentMetadata({ state: agentState(), transactionId: "tx-23c-agent-03" }).ok).toBe(true);
    wiring.close();
    const reopened = openWiring(root, EPOCH_B);
    const boot = reopened.wiring.bootstrapFromRecovery({ request: RECOVERY_REQUEST, nowEpochMs: 1759200000000 });
    expect(boot.ok).toBe(true);
    expect(boot.admittedByKind.agent_metadata).toBe(1);
    const view = reopened.wiring.readAgentMetadata("agent-wire-01");
    expect(view.ok).toBe(true);
    if (view.ok) {
      expect(view.state.profile.allowedVerbs).toEqual(["workspace:read"]);
      expect(view.state.executionAuthorized).toBe(false);
    }
  });
});

// ── registry surface ─────────────────────────────────────────────────────────

describe("23C registry lifecycle — exact restore, terminal states never resurrect", () => {
  it("P2: disabled stays disabled across reopen + bootstrap (exact restore)", () => {
    const root = newRoot();
    const { wiring } = openWiring(root);
    expect(wiring.writeRegistryLifecycle({ state: regState("registered"), previousLifecycle: null, transactionId: "tx-23c-reg-01" }).ok).toBe(true);
    expect(wiring.writeRegistryLifecycle({ state: regState("disabled"), previousLifecycle: "registered", transactionId: "tx-23c-reg-02" }).ok).toBe(true);
    wiring.close();
    const reopened = openWiring(root, EPOCH_B);
    const boot = reopened.wiring.bootstrapFromRecovery({ request: RECOVERY_REQUEST, nowEpochMs: 1759200000000 });
    expect(boot.ok).toBe(true);
    const view = reopened.wiring.readRegistryLifecycle("fs.read", "1.0.0");
    expect(view.ok).toBe(true);
    if (view.ok) {
      expect(view.state.lifecycle).toBe("disabled"); // exactly as stored
      expect(view.terminal).toBe(false);
    }
  });

  it("P6: quarantined/retired are terminal — rewrite refused, bootstrap reports them, no resurrection", () => {
    const root = newRoot();
    const { wiring } = openWiring(root);
    expect(wiring.writeRegistryLifecycle({ state: regState("registered"), previousLifecycle: null, transactionId: "tx-23c-reg-03" }).ok).toBe(true);
    expect(wiring.writeRegistryLifecycle({ state: regState("quarantined"), previousLifecycle: "registered", transactionId: "tx-23c-reg-04" }).ok).toBe(true);
    const resurrect = wiring.writeRegistryLifecycle({
      state: regState("enabled"),
      previousLifecycle: "quarantined",
      transactionId: "tx-23c-reg-05",
    });
    expect(resurrect.ok).toBe(false);
    if (!resurrect.ok) expect(resurrect.code).toBe("terminal_state_rewrite");
    const view = wiring.readRegistryLifecycle("fs.read", "1.0.0");
    expect(view.ok).toBe(true);
    if (view.ok) {
      expect(view.state.lifecycle).toBe("quarantined");
      expect(view.terminal).toBe(true);
    }
    const boot = wiring.bootstrapFromRecovery({ request: RECOVERY_REQUEST, nowEpochMs: 1759200000000 });
    expect(boot.terminalRegistryIds.length).toBe(1);
  });
});

// ── cross-cutting: corruption, denylist-on-view, no-bypass ───────────────────

describe("23C cross-cutting laws", () => {
  it("a corrupted stored record is surfaced quarantined; bootstrap excludes it; fresh writes still coordinate", () => {
    const root = newRoot();
    const { store, wiring } = openWiring(root);
    expect(wiring.writeMemory({ record: memRecord("mem-wire-08"), transactionId: "tx-23c-x-01" }).ok).toBe(true);
    const db = new DatabaseSync(join(root, "menog-store", "durable.db"));
    const row = db.prepare("SELECT payload_json FROM records WHERE record_id = ?").get("mem-mem-wire-08") as { payload_json: string };
    db.prepare("UPDATE records SET payload_json = ? WHERE record_id = ?").run(row.payload_json + "garbage", "mem-mem-wire-08");
    const view = wiring.readMemory("mem-wire-08", 1759200000000);
    expect(view.ok).toBe(false);
    if (!view.ok) expect(view.code).toBe("store_denied"); // surfaced, never healed
    const boot = wiring.bootstrapFromRecovery({ request: RECOVERY_REQUEST, nowEpochMs: 1759200000000 });
    // The corrupted record is already isolated by the store (quarantined
    // as-found), so recovery neither admits it nor heals it — the decision
    // stays an accept code with the corrupted record contributing NOTHING:
    expect(["accept_full_state", "accept_without_quarantined"]).toContain(boot.decision.code);
    expect(boot.admittedByKind.memory_record).toBe(0);
    expect(store.listQuarantined().length).toBeGreaterThanOrEqual(1);
    expect(wiring.writeMemory({ record: memRecord("mem-wire-09"), transactionId: "tx-23c-x-02" }).ok).toBe(true);
  });

  it("a re-sealed denylist injection into a stored record fails the VIEW scan (denylist applies on view, not just write)", () => {
    const root = newRoot();
    const { wiring } = openWiring(root);
    expect(wiring.writeMemory({ record: memRecord("mem-wire-10"), transactionId: "tx-23c-x-03" }).ok).toBe(true);
    const db = new DatabaseSync(join(root, "menog-store", "durable.db"));
    const row = db.prepare("SELECT record_id, revision, record_kind, durability_class, transaction_id, created_at_epoch_ms, payload_json FROM records WHERE record_id = ?")
      .get("mem-mem-wire-10") as Record<string, string | number>;
    const payload = JSON.parse(row.payload_json as string) as Record<string, unknown>;
    const record = { ...(payload.memory as Record<string, unknown>) };
    (record.body as Record<string, unknown>) = { ...(record.body as Record<string, unknown>), launcher_path: "/injected" };
    const tampered = { ...payload, memory: record };
    const body = {
      schemaVersion: "menog-durable-record/v0",
      recordId: row.record_id,
      recordKind: row.record_kind,
      durabilityClass: row.durability_class,
      secretPolicy: "secret_free",
      authority: "durable_state",
      revision: row.revision,
      supersedesRevision: Number(row.revision) > 1 ? Number(row.revision) - 1 : null,
      createdAtEpochMs: row.created_at_epoch_ms,
      transactionId: row.transaction_id,
      payload: tampered,
    };
    db.prepare("UPDATE records SET payload_json = ?, content_hash = ? WHERE record_id = ?")
      .run(JSON.stringify(tampered), durableContentHash(body as Parameters<typeof durableContentHash>[0]), "mem-mem-wire-10");
    const view = wiring.readMemory("mem-wire-10", 1759200000000);
    expect(view.ok).toBe(false);
    if (!view.ok) expect(view.code).toBe("denied_key_present");
  });

  it("NO subsystem may bypass the coordinator: structural scan of the wiring module", () => {
    const raw = readFileSync(join(process.cwd(), "packages", "durable-state", "src", "surfaceWiring.ts"), "utf8");
    const codeOnly = raw
      .split("\n")
      .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
      .join("\n");
    // None of the 22D persist functions may be called with a store — the
    // ONLY write path is coordinator.acceptMutation:
    for (const forbidden of [
      "persistMemoryRecord(",
      "persistAgentMetadata(",
      "persistTaskLifecycle(",
      "persistRegistryLifecycle(",
      ".persist(",
      "store.persist",
    ]) {
      expect(codeOnly.includes(forbidden), "surfaceWiring.ts contains " + forbidden).toBe(false);
    }
    expect((codeOnly.match(/acceptMutation\(/g) ?? []).length).toBe(1);
    // No spawn / network / replay / resume vocabulary:
    for (const forbidden of ["child_process", "spawn(", "fetch(", "http.request", "autoResume", "continueTask", "executeToolRun", "generateReplayPlan("]) {
      expect(codeOnly.includes(forbidden), "surfaceWiring.ts contains " + forbidden).toBe(false);
    }
    // The structural persist-call pin is exported and empty:
    expect(SURFACE_WIRING_PERSIST_CALLS).toEqual([]);
  });

  it("every acknowledged write carries the formal barrier; refusals never do (P1 across all four surfaces)", () => {
    const { wiring } = openWiring(newRoot());
    const m = wiring.writeMemory({ record: memRecord("mem-wire-11"), transactionId: "tx-23c-y-01" });
    const t = wiring.writeTaskLifecycle({ state: taskState("goal-wire-05", "pending"), previousStatus: null, transactionId: "tx-23c-y-02" });
    const a = wiring.writeAgentMetadata({ state: agentState("agent-wire-02"), transactionId: "tx-23c-y-03" });
    const g = wiring.writeRegistryLifecycle({ state: regState("registered", "fs.write", "2.0.0"), previousLifecycle: null, transactionId: "tx-23c-y-04" });
    for (const r of [m, t, a, g]) {
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.barrier.outcome).toBe("committed");
        expect(r.commitSequence).toBeGreaterThan(0);
      }
    }
  });
});
