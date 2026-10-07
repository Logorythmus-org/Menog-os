/**
 * PHASE 23D — Recovery Bootstrap → Live Runtime Handoff (integration).
 *
 * Positives:
 *   P1 fresh store → recovery first → NEW epoch → READY views → LIVE
 *   P2 restart over a RELEASED claim → LIVE; durable facts survive
 *   P3 a held claim superseded BY EVIDENCE when the named prior matches
 *   P4 evidence determinism (no wall clock in the hashed body)
 *   P5 NEW-epoch derivation is injective
 * Negatives (fail closed → RECOVERED):
 *   N1 corruption/quarantine findings BLOCK LIVE
 *   N2 hard recovery rejection (scan bound) BLOCKS LIVE
 *   N3 a named prior epoch that does not match the claim refuses
 *   N4 a duplicate owner (claim moved on) refuses
 *   N5 handoff evidence tamper refuses
 *   N6 interrupted tasks stay interrupted (reported, never resumed)
 *   N7 no authority reactivation (structural + behavioral)
 * Unit pins: evidenced ownership transfer refusals.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import {
  DurableStore,
  LiveSurfaceWiring,
  buildHandoffEvidence,
  buildRecoveryReport,
  classifyRecoveryReport,
  makeNewEpochAfterRecovery,
  readRuntimeOwnership,
  recoveryReportHash,
  runStartupHandoff,
  transferOwnershipEvidenced,
  verifyHandoffEvidence,
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
function newRoot(): string {
  const r = mkdtempSync(join(tmpdir(), "menog-23d-"));
  roots.push(r);
  return r;
}
function openStoreAt(root: string) {
  const open = DurableStore.open(root);
  if (open.ok) openStores.push(open.store);
  return open;
}
afterEach(() => {
  for (const s of openStores) { try { if (s.isOpen) s.close(); } catch { /* already closed */ } }
  openStores.length = 0;
  for (const r of roots) { try { rmSync(r, { recursive: true, force: true }); } catch { /* windows handles */ } }
  roots.length = 0;
});

const RECOVERY_REQUEST: RecoveryRequest = {
  mode: "load_committed_state",
  expectedStoreSchemaVersion: "menog-durable-store/v0",
  maxRecords: 10000,
  semantics: "no_execution",
};

/** Valid 23A epoch id: re-<12 hex>-<16 alnum>. */
function eid(tag: string): string {
  const cleaned = tag.replace(/[^a-zA-Z0-9]/g, "");
  return "re-000000dd0000-" + cleaned.padEnd(16, "0").slice(0, 16);
}

const BOOT_EPOCH: RuntimeEpoch = Object.freeze({
  schemaVersion: "menog-runtime-epoch/v0",
  epochId: eid("boot01"),
  startedAtEpochMs: 1759100000000,
  hostRef: "wsl2-target-of-record",
  pidRef: 4242,
  lifecycle: "BOOTING" as const,
  priorOwner: { code: "none" as const, epochId: null },
  startReason: "fresh_store_no_prior_owner" as const,
  executionAuthorized: false as const,
  policyAuthorized: false as const,
});

function bootEpochAt(tag: string): RuntimeEpoch {
  return { ...BOOT_EPOCH, epochId: eid(tag) };
}

function writeFixtureMemory(wiring: LiveSurfaceWiring, memoryId: string, transactionId: string) {
  return wiring.writeMemory({
    record: {
      schemaVersion: "test/mem/v1",
      memoryId,
      kind: "project",
      scope: { workspaceId: "ws-23d" },
      provenance: { origin: "unit-test:23d", actor: { type: "agent", id: "agent-23d" }, untrusted: false },
      retention: { retentionClass: "persistent" },
      body: { note: "23d fixture" },
      createdAtEpochMs: 1759100000600,
      createdByActorId: "agent-23d",
    },
    transactionId,
  });
}

function runHandoff(store: DurableStore, boot: RuntimeEpoch, priorEpochId: string | null, now = 1759100000500) {
  return runStartupHandoff({
    store,
    bootedEpoch: boot,
    recoveryRequest: RECOVERY_REQUEST,
    sourceIdentity: "unit-test:23d",
    priorEpochId,
    nowEpochMs: now,
  });
}

// ── positives ────────────────────────────────────────────────────────────────

describe("23D — the explicit, evidenced handoff (positive paths)", () => {
  it("P1: fresh store → recovery first → NEW epoch → READY views → LIVE on verified evidence", () => {
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    const run = runHandoff(open.store, BOOT_EPOCH, null);
    expect(run.ok).toBe(true);
    expect(run.terminalState).toBe("LIVE");
    expect(run.steps.map((s) => s.stage)).toEqual(["RECOVERING", "RECONCILED", "READY", "LIVE"]);
    expect(run.newEpochId).not.toBe(BOOT_EPOCH.epochId);
    expect(run.newEpochId).toMatch(/^re-[0-9a-f]{12}-[a-zA-Z0-9]{16}$/);
    expect(run.reportHash).toHaveLength(64);
    expect(run.evidenceHash).toHaveLength(64);
    if (run.evidence !== null) {
      expect(run.evidence.grantsAuthority).toBe(false);
      expect(run.evidence.resumeSemantics).toBe("no_auto_resume");
      expect(run.evidence.executionPathRequirement).toBe("planner_allocation_policy_isolation_governed_tool_runtime");
    }
    expect(run.wiring).not.toBeNull();
    if (run.wiring !== null) {
      const w = writeFixtureMemory(run.wiring, "mem-23d-live-01", "tx-23d-live-01");
      expect(w.ok).toBe(true);
      if (w.ok) expect(w.barrier.outcome).toBe("committed");
    }
  });

  it("P2: restart over a RELEASED claim → LIVE; durable facts survive the handoff", () => {
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    const first = runHandoff(open.store, bootEpochAt("first02"), null);
    expect(first.ok).toBe(true);
    expect(first.wiring).not.toBeNull();
    if (first.wiring !== null) {
      expect(writeFixtureMemory(first.wiring, "mem-23d-live-02", "tx-23d-live-02").ok).toBe(true);
      first.wiring.close();
    }
    const restarted = runHandoff(open.store, bootEpochAt("second02"), null, 1759100000700);
    expect(restarted.ok).toBe(true);
    expect(restarted.terminalState).toBe("LIVE");
    expect(restarted.newEpochId).not.toBe(eid("first02"));
    expect(restarted.wiring).not.toBeNull();
    if (restarted.wiring !== null) {
      const view = restarted.wiring.readMemory("mem-23d-live-02", 1759200000000);
      expect(view.ok).toBe(true);
      restarted.wiring.close();
    }
  });

  it("P3: a held claim is superseded BY EVIDENCE when the named prior epoch matches", () => {
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    open.store.setMeta("runtime_live_owner_epoch", eid("prior03") + "|crashed-owner");
    const run = runHandoff(open.store, bootEpochAt("boot03"), eid("prior03"), 1759100000800);
    expect(run.ok).toBe(true);
    expect(run.terminalState).toBe("LIVE");
    if (run.evidence !== null) expect(run.evidence.priorEpochId).toBe(eid("prior03"));
  });

  it("P4: evidence is deterministic — identical inputs rebuild the identical hash", () => {
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    const report = buildRecoveryReport(open.store, RECOVERY_REQUEST, 1759100000500);
    const e1 = buildHandoffEvidence({ recoveryReport: report, newEpochId: BOOT_EPOCH.epochId, priorEpochId: null });
    const e2 = buildHandoffEvidence({ recoveryReport: report, newEpochId: BOOT_EPOCH.epochId, priorEpochId: null });
    expect(e1.evidenceHash).toBe(e2.evidenceHash);
    expect(recoveryReportHash(report)).toBe(recoveryReportHash(report));
  });

  it("P5: the NEW epoch derivation is injective and shape-valid", () => {
    const a = makeNewEpochAfterRecovery({ ...BOOT_EPOCH, epochId: eid("aaaa0001") }, 0);
    const b = makeNewEpochAfterRecovery({ ...BOOT_EPOCH, epochId: eid("aaaa0002") }, 0);
    expect(a.epochId).not.toBe(b.epochId);
    expect(a.epochId).toMatch(/^re-[0-9a-f]{12}-[a-zA-Z0-9]{16}$/);
    expect(a.epochId).not.toBe(eid("aaaa0001"));
  });
});

// ── negatives (fail closed) ──────────────────────────────────────────────────

describe("23D — negatives: blocking findings, ownership, evidence (all → RECOVERED)", () => {
  it("N1: corruption and quarantine findings BLOCK LIVE (never silently absorbed)", () => {
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    const first = runHandoff(open.store, bootEpochAt("first11"), null);
    expect(first.ok).toBe(true);
    expect(first.wiring).not.toBeNull();
    if (first.wiring !== null) {
      expect(writeFixtureMemory(first.wiring, "mem-23d-live-11", "tx-23d-live-11").ok).toBe(true);
      first.wiring.close();
    }
    // Corrupt the stored record behind the store's back:
    const corruptRoot = roots[roots.length - 1];
    if (corruptRoot === undefined) throw new Error("fixture root missing");
    const db = new DatabaseSync(join(corruptRoot, "menog-store", "durable.db"));
    const row = db.prepare("SELECT payload_json FROM records WHERE record_id = ?").get("mem-mem-23d-live-11") as { payload_json: string };
    expect(row).toBeDefined();
    db.prepare("UPDATE records SET payload_json = ? WHERE record_id = ?").run(row.payload_json + "garbage", "mem-mem-23d-live-11");
    const run = runHandoff(open.store, bootEpochAt("blocked11"), null, 1759100000900);
    expect(run.ok).toBe(false);
    expect(run.terminalState).toBe("RECOVERED");
    expect(run.classification?.blockingClass).toBe("quarantine");
    expect(run.wiring).toBeNull();
  });

  it("N2: a hard recovery rejection (schema mismatch) BLOCKS LIVE", () => {
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    const first = runHandoff(open.store, bootEpochAt("first22"), null);
    expect(first.ok).toBe(true);
    expect(first.wiring).not.toBeNull();
    if (first.wiring !== null) {
      expect(writeFixtureMemory(first.wiring, "mem-23d-live-22", "tx-23d-live-22").ok).toBe(true);
      first.wiring.close();
    }
    // Typed hard rejection through the honored vocabulary path: the store's
    // recorded schema is sabotaged behind the open handle's back, so the
    // frozen 22D recovery reports rejected_schema_mismatch (the recorded
    // note also covers the DEBT-23-01 finding that recoverState takes its
    // scan bound from its options argument, not request.maxRecords).
    const root = roots[roots.length - 1];
    if (root === undefined) throw new Error("fixture root missing");
    const db = new DatabaseSync(join(root, "menog-store", "durable.db"));
    db.prepare("UPDATE store_meta SET value = 'menog-durable-store/v9' WHERE key = 'store_schema_version'").run();
    const run = runStartupHandoff({
      store: open.store,
      bootedEpoch: bootEpochAt("blocked22"),
      recoveryRequest: RECOVERY_REQUEST,
      sourceIdentity: "unit-test:23d",
      priorEpochId: null,
      nowEpochMs: 1759100001000,
    });
    expect(run.ok).toBe(false);
    expect(run.terminalState).toBe("RECOVERED");
    expect(run.classification?.blockingClass).toBe("hard");
  });

  it("N3: a named prior epoch that does NOT match the durable claim refuses (stale/foreign epoch)", () => {
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    open.store.setMeta("runtime_live_owner_epoch", eid("real33") + "|someone");
    const run = runHandoff(open.store, bootEpochAt("boot33"), eid("stale33"), 1759100001100);
    expect(run.ok).toBe(false);
    expect(run.terminalState).toBe("RECOVERED");
    expect(run.explanation).toContain("stale/foreign epoch");
  });

  it("N4: a duplicate owner (claim moved on since it was named) refuses", () => {
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    open.store.setMeta("runtime_live_owner_epoch", eid("prior44") + "|prior");
    const ok = runHandoff(open.store, bootEpochAt("boot44"), eid("prior44"), 1759100001200);
    expect(ok.ok).toBe(true);
    if (ok.wiring !== null) ok.wiring.close();
    // The claim now belongs to boot44's NEW epoch; naming the OLD prior refuses:
    const stolen = runHandoff(open.store, bootEpochAt("boot45"), eid("prior44"), 1759100001300);
    expect(stolen.ok).toBe(false);
    expect(stolen.terminalState).toBe("RECOVERED");
  });

  it("N5: handoff evidence tamper refuses (deterministic rebuild diverges; semantics tampering refuses)", () => {
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    const report = buildRecoveryReport(open.store, RECOVERY_REQUEST, 1759100000500);
    const real = buildHandoffEvidence({ recoveryReport: report, newEpochId: BOOT_EPOCH.epochId, priorEpochId: null });
    const otherReport = { ...report, interruptedTaskIds: ["goal-phantom"] };
    const t1 = verifyHandoffEvidence({ claimed: real, recoveryReport: otherReport, newEpochId: BOOT_EPOCH.epochId });
    expect(t1.ok).toBe(false);
    if (!t1.ok) expect(t1.reason).toContain("hash mismatch");
    const t2 = verifyHandoffEvidence({ claimed: real, recoveryReport: report, newEpochId: eid("other55") });
    expect(t2.ok).toBe(false);
    const forged = { ...real, grantsAuthority: true } as unknown as typeof real;
    const t3 = verifyHandoffEvidence({ claimed: forged, recoveryReport: report, newEpochId: BOOT_EPOCH.epochId });
    expect(t3.ok).toBe(false);
  });

  it("N6: interrupted tasks survive the handoff as FACTS — reported, never resumed", () => {
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    const first = runHandoff(open.store, bootEpochAt("first66"), null);
    expect(first.ok).toBe(true);
    expect(first.wiring).not.toBeNull();
    if (first.wiring !== null) {
      const written = first.wiring.writeTaskLifecycle({
        state: {
          schemaVersion: "test/task/v1",
          goalId: "goal-23d-interrupt",
          planId: null,
          taskIds: ["task-23d-interrupt"],
          status: "interrupted",
          rationale: "crashed mid-run (fixture)",
          updatedAtEpochMs: 1759100000500,
        },
        previousStatus: null,
        transactionId: "tx-23d-interrupt-01",
      });
      expect(written.ok).toBe(true);
      first.wiring.close();
    }
    const run = runHandoff(open.store, bootEpochAt("boot66"), null, 1759100001400);
    expect(run.ok).toBe(true);
    expect(run.interruptedTaskIds).toContain("goal-23d-interrupt");
    expect(run.wiring).not.toBeNull();
    if (run.wiring !== null) {
      const view = run.wiring.readTaskLifecycle("goal-23d-interrupt");
      expect(view.ok).toBe(true);
      if (view.ok) {
        expect(view.state.status).toBe("interrupted");
        expect(view.nextLegalTransitions).toEqual(["executing", "proposed"]);
      }
      run.wiring.close();
    }
  });

  it("N7: no authority reactivation — recovered data stays recovered_data (structural + behavioral)", () => {
    const raw = readFileSync(join(process.cwd(), "packages", "durable-state", "src", "handoff.ts"), "utf8");
    const codeOnly = raw
      .split("\n")
      .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
      .join("\n");
    for (const forbidden of [
      "child_process",
      "spawn(",
      "fetch(",
      "executeToolRun",
      "runToolInLauncher",
      "autoResume",
      "continueTask",
      "generateReplayPlan(",
      "generateRollbackPlan(",
      "executionAuthorized: true",
      "policyAuthorized: true",
    ]) {
      expect(codeOnly.includes(forbidden), "handoff.ts contains " + forbidden).toBe(false);
    }
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    const report = buildRecoveryReport(open.store, RECOVERY_REQUEST, 1759100000500);
    expect(classifyRecoveryReport(report).blockingClass).toBe("none");
    expect(report.decision.executionAuthorized).toBe(false);
    expect(report.decision.policyAuthorized).toBe(false);
    expect(report.decision.authority).toBe("recovered_data");
  });
});

// ── evidenced ownership transfer (unit pins) ─────────────────────────────────

describe("23D — evidenced ownership transfer (unit pins)", () => {
  it("refuses unheld claims (valid target), then self/foreign/malformed/empty-justification cases", () => {
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    const target = bootEpochAt("target88");
    const noClaim = transferOwnershipEvidenced(open.store, BOOT_EPOCH.epochId, target, "justification");
    expect(noClaim.ok).toBe(false);
    if (!noClaim.ok) expect(noClaim.code).toBe("claim_not_current");
    open.store.setMeta("runtime_live_owner_epoch", BOOT_EPOCH.epochId + "|prior");
    const ok = transferOwnershipEvidenced(open.store, BOOT_EPOCH.epochId, target, "reportHash=abc");
    expect(ok.ok).toBe(true);
    const view = readRuntimeOwnership(open.store, target.epochId);
    expect(view.code).toBe("owner_current");
    expect(view.boundSourceIdentity).toBe("prior");
  });

  it("refuses self-transfer, malformed targets, and empty justifications (each on a prepared claim)", () => {
    const open = openStoreAt(newRoot());
    if (!open.ok) throw new Error(open.reason);
    open.store.setMeta("runtime_live_owner_epoch", BOOT_EPOCH.epochId + "|prior");
    const self = transferOwnershipEvidenced(open.store, BOOT_EPOCH.epochId, BOOT_EPOCH, "justification");
    expect(self.ok).toBe(false);
    if (!self.ok) expect(self.code).toBe("epoch_not_new");
    const malformed = transferOwnershipEvidenced(open.store, BOOT_EPOCH.epochId, { ...BOOT_EPOCH, epochId: "not-an-epoch" }, "justification");
    expect(malformed.ok).toBe(false);
    if (!malformed.ok) expect(malformed.code).toBe("epoch_invalid");
    const emptyJust = transferOwnershipEvidenced(open.store, BOOT_EPOCH.epochId, bootEpochAt("target99"), "");
    expect(emptyJust.ok).toBe(false);
    if (!emptyJust.ok) expect(emptyJust.code).toBe("justification_required");
  });
});
