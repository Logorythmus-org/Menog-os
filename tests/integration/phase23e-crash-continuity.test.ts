/**
 * PHASE 23E — Process-Kill Crash Windows & Local Continuity Validation.
 *
 * Six bounded child-process kill windows over the REAL machinery:
 *   W1 before any transaction · W2 after BEGIN/stage, before COMMIT ·
 *   W3 after COMMIT, before live acknowledgement · W4 after acknowledgement ·
 *   W5 recovery completed, before LIVE handoff · W6 after handoff (NEW epoch)
 *
 * Every case records: crash point, expected vs observed durable state after
 * reopen, reconciliation/quarantine, LIVE eligibility, duplicate/lost/
 * half-visible mutations, and authority/execution resurrection.
 *
 * Scope honesty (the gate's own rule): this validates PROCESS-KILL only.
 * No power-cut, controller-cache, kernel-panic, filesystem, or hardware
 * durability claim is made or testable here.
 */
import { describe, it, expect, afterEach } from "vitest";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DurableStore,
  RuntimeStateCoordinator,
  buildRecoveryReport,
  classifyRecoveryReport,
  runStartupHandoff,
  type RecoveryRequest,
  type RuntimeEpoch,
} from "@menog/durable-state";

const CHILD = join(process.cwd(), "tests", "fixtures", "phase23e-crash-child.mjs");
const RECOVERY_REQUEST: RecoveryRequest = {
  mode: "load_committed_state",
  expectedStoreSchemaVersion: "menog-durable-store/v0",
  maxRecords: 10000,
  semantics: "no_execution",
};

const roots: string[] = [];
const openStores: DurableStore[] = [];
function newRoot(): string {
  const r = mkdtempSync(join(tmpdir(), "menog-23e-"));
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

function bootEpoch(id: string): RuntimeEpoch {
  return Object.freeze({
    schemaVersion: "menog-runtime-epoch/v0",
    epochId: id,
    startedAtEpochMs: 1759100000000,
    hostRef: "23e-parent",
    pidRef: process.pid,
    lifecycle: "BOOTING" as const,
    priorOwner: { code: "none" as const, epochId: null },
    startReason: "fresh_store_no_prior_owner" as const,
    executionAuthorized: false as const,
    policyAuthorized: false as const,
  });
}

function eid(tag: string): string {
  return "re-000000ef0000-" + tag.replace(/[^a-zA-Z0-9]/g, "").padEnd(16, "0").slice(0, 16);
}

interface ChildOutcome {
  readonly reached: boolean;
  readonly stdout: string;
  readonly stderr: string;
  readonly signal: NodeJS.Signals | null;
  readonly code: number | null;
}

function killChildAt(windowId: string, root: string, timeoutMs = 45000): Promise<ChildOutcome> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CHILD, windowId, root], {
      stdio: ["ignore", "pipe", "pipe"],
      cwd: process.cwd(),
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try { child.kill("SIGKILL"); } catch { /* already dead */ }
        resolve({ reached: false, stdout, stderr: stderr + "\n[harness timeout]", signal: "SIGKILL", code: null });
      }
    }, timeoutMs);
    child.stdout.on("data", (d: Buffer) => {
      stdout += d.toString();
      // Exact readiness match (console.log appends \n) — a failure marker
      // like "ready:w2-stage-failed" must NOT satisfy the "ready:w2" check.
      if (stdout.includes("ready:" + windowId + "\n") && !settled) {
        settled = true;
        clearTimeout(timer);
        // Kill AT the window: the child parked right after signaling.
        setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* already dead */ } }, 120);
        child.once("exit", (code, signal) => resolve({ reached: true, stdout, stderr, signal, code }));
      }
    });
    child.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
    child.on("error", (err) => {
      if (!settled) { settled = true; clearTimeout(timer); resolve({ reached: false, stdout, stderr: String(err), signal: null, code: null }); }
    });
    child.on("exit", (code, signal) => {
      if (!settled) { settled = true; clearTimeout(timer); resolve({ reached: false, stdout, stderr, signal, code }); }
    });
  });
}

function reopenAndAssess(root: string, tag: string) {
  const reopened = openStoreAt(root);
  if (!reopened.ok) {
    return { openable: false as const, reason: reopened.reason };
  }
  const report = buildRecoveryReport(reopened.store, RECOVERY_REQUEST, 1759200000000);
  const classification = classifyRecoveryReport(report);
  // The prior epoch is whatever the durable claim says (the crashed child's
  // claim, when one exists). Handing the ACTUAL owner id makes the evidenced
  // supersession the tested path; a null prior is only correct for a fresh
  // store.
  const ownership = reopened.store.getMeta("runtime_live_owner_epoch");
  const priorEpochId = ownership === null ? null : (ownership.split("|")[0] ?? null);
  const handoff = runStartupHandoff({
    store: reopened.store,
    bootedEpoch: bootEpoch(eid("reopen" + tag)),
    recoveryRequest: RECOVERY_REQUEST,
    sourceIdentity: "23e-parent",
    priorEpochId,
    nowEpochMs: 1759200000100,
  });
  return {
    openable: true as const,
    store: reopened.store,
    committedThrough: reopened.store.committedThrough,
    decisionCode: report.decision.code,
    authority: report.decision.authority,
    executionAuthorized: report.decision.executionAuthorized,
    policyAuthorized: report.decision.policyAuthorized,
    blockingClass: classification.blockingClass,
    explanation: classification.explanation,
    quarantinedCount: reopened.store.listQuarantined().length,
    handoff,
  };
}

describe("23E — crash windows (process-kill only; no power-loss claim)", () => {
  it("W1: kill before any transaction → clean reopen, clean handoff, zero writes", async () => {
    const root = newRoot();
    const outcome = await killChildAt("w1", root);
    expect(outcome.reached, "harness must reach the window: " + outcome.stderr).toBe(true);
    const a = reopenAndAssess(root, "w1");
    expect(a.openable).toBe(true);
    if (a.openable) {
      expect(a.committedThrough).toBe(0);            // nothing was written
      expect(a.decisionCode).toBe("accept_full_state");
      expect(a.blockingClass).toBe("none");
      expect(a.quarantinedCount).toBe(0);
      expect(a.handoff.ok).toBe(true);               // LIVE eligible
      expect(a.executionAuthorized).toBe(false);     // no authority resurrection
      expect(a.policyAuthorized).toBe(false);
    }
  }, 60000);

  it("W2: kill after BEGIN/stage, before COMMIT → the transaction never existed (no half-visible mutation)", async () => {
    const root = newRoot();
    const outcome = await killChildAt("w2", root);
    expect(outcome.reached, "harness must reach the window: " + outcome.stderr).toBe(true);
    const a = reopenAndAssess(root, "w2");
    expect(a.openable).toBe(true);
    if (a.openable) {
      expect(a.committedThrough).toBe(0);            // uncommitted work is gone
      expect(a.decisionCode).toBe("accept_full_state");
      expect(a.blockingClass).toBe("none");
      expect(a.quarantinedCount).toBe(0);            // no corruption, no quarantine
      expect(a.handoff.ok).toBe(true);
      // The post-handoff wiring must NOT see the never-committed record:
      expect(a.handoff.wiring).not.toBeNull();
      if (a.handoff.wiring !== null) {
        const view = a.handoff.wiring.readMemory("23e-w2-crash", 1759200000000);
        expect(view.ok).toBe(false);                 // lost, not half-visible
      }
    }
  }, 60000);

  it("W3: kill after COMMIT, before live acknowledgement → the record IS durable after reopen (no duplicate on re-write)", async () => {
    const root = newRoot();
    const outcome = await killChildAt("w3", root);
    expect(outcome.reached, "harness must reach the window: " + outcome.stderr).toBe(true);
    const a = reopenAndAssess(root, "w3");
    expect(a.openable).toBe(true);
    if (a.openable) {
      expect(a.committedThrough).toBe(1);            // the commit survived
      expect(a.decisionCode).toBe("accept_full_state");
      expect(a.blockingClass).toBe("none");
      expect(a.handoff.ok).toBe(true);
      expect(a.handoff.wiring).not.toBeNull();
      if (a.handoff.wiring !== null) {
        const view = a.handoff.wiring.readMemory("23e-w3-crash", 1759200000000);
        expect(view.ok).toBe(true);                  // found, not lost
        if (view.ok) expect(view.revision).toBe(1);
        // Re-writing the SAME transaction id is a duplicate-transaction denial
        // (idempotency across the crash boundary):
        const dup = a.handoff.wiring.writeMemory({
          record: {
            schemaVersion: "test/mem/v1",
            memoryId: "23e-w3-crash",
            kind: "project",
            scope: { workspaceId: "ws-23e" },
            provenance: { origin: "23e-parent", actor: { type: "agent", id: "agent-23e" }, untrusted: false },
            retention: { retentionClass: "persistent" },
            body: { note: "retry" },
            createdAtEpochMs: 1759200000200,
            createdByActorId: "agent-23e",
          },
          transactionId: "tx-23e-w3",
        });
        expect(dup.ok).toBe(false);
        if (!dup.ok) expect(dup.reason).toContain("duplicate_transaction");
        // A legitimately NEW transaction on the same record is the normal path:
        const next = a.handoff.wiring.writeMemory({
          record: {
            schemaVersion: "test/mem/v1",
            memoryId: "23e-w3-crash",
            kind: "project",
            scope: { workspaceId: "ws-23e" },
            provenance: { origin: "23e-parent", actor: { type: "agent", id: "agent-23e" }, untrusted: false },
            retention: { retentionClass: "persistent" },
            body: { note: "v2" },
            createdAtEpochMs: 1759200000300,
            createdByActorId: "agent-23e",
          },
          transactionId: "tx-23e-w3-v2",
        });
        expect(next.ok).toBe(true);
        if (next.ok) expect(next.revision).toBe(2);
      }
    }
  }, 60000);

  it("W4: kill after acknowledgement → durable state and the ack AGREE (no half-visible divergence)", async () => {
    const root = newRoot();
    const outcome = await killChildAt("w4", root);
    expect(outcome.reached, "harness must reach the window: " + outcome.stderr).toBe(true);
    const ack = JSON.parse(readFileSync(join(root, "ack-w4.json"), "utf8")) as { commitSequence: number; barrier: string };
    expect(ack.barrier).toBe("committed");
    const a = reopenAndAssess(root, "w4");
    expect(a.openable).toBe(true);
    if (a.openable) {
      expect(a.committedThrough).toBe(ack.commitSequence); // live/durable agree at the barrier
      expect(a.decisionCode).toBe("accept_full_state");
      expect(a.handoff.ok).toBe(true);
      expect(a.handoff.wiring).not.toBeNull();
      if (a.handoff.wiring !== null) {
        const view = a.handoff.wiring.readMemory("23e-w4-crash", 1759200000000);
        expect(view.ok).toBe(true);
      }
    }
  }, 60000);

  it("W5: kill after recovery completed, before LIVE handoff → recovery is idempotent; LIVE reached on reopen; nothing executed", async () => {
    const root = newRoot();
    const outcome = await killChildAt("w5", root);
    expect(outcome.reached, "harness must reach the window: " + outcome.stderr).toBe(true);
    const a = reopenAndAssess(root, "w5");
    expect(a.openable).toBe(true);
    if (a.openable) {
      expect(a.decisionCode).toBe("accept_full_state");  // recovery re-runs cleanly
      expect(a.authority).toBe("recovered_data");        // still no authority
      expect(a.executionAuthorized).toBe(false);
      expect(a.policyAuthorized).toBe(false);
      expect(a.handoff.ok).toBe(true);                   // LIVE eligible after re-recovery
      expect(a.handoff.terminalState).toBe("LIVE");
      expect(a.handoff.newEpochId).not.toBe(eid("reopenw5"));
    }
  }, 60000);

  it("W6: kill after handoff (NEW epoch holds the claim) → reopen honors the claim; stale writes fail; no resurrection", async () => {
    const root = newRoot();
    const outcome = await killChildAt("w6", root);
    expect(outcome.reached, "harness must reach the window: " + outcome.stderr).toBe(true);
    const a = reopenAndAssess(root, "w6");
    expect(a.openable).toBe(true);
    if (a.openable) {
      expect(a.committedThrough).toBe(0);            // the handoff wrote nothing
      expect(a.decisionCode).toBe("accept_full_state");
      expect(a.handoff.ok).toBe(true);
      expect(a.handoff.wiring).not.toBeNull();
      if (a.handoff.wiring !== null) {
        // Fresh writes under the NEW handoff epoch work:
        const fresh = a.handoff.wiring.writeMemory({
          record: {
            schemaVersion: "test/mem/v1",
            memoryId: "mem-23e-w6-fresh",
            kind: "project",
            scope: { workspaceId: "ws-23e" },
            provenance: { origin: "23e-parent", actor: { type: "agent", id: "agent-23e" }, untrusted: false },
            retention: { retentionClass: "persistent" },
            body: { note: "post-w6" },
            createdAtEpochMs: 1759200000400,
            createdByActorId: "agent-23e",
          },
          transactionId: "tx-23e-w6-fresh",
        });
        expect(fresh.ok).toBe(true);
      }
      // The dead child epoch's id is stale forever: a coordinator bound to it
      // cannot re-acquire (the claim belongs to the handoff's NEW epoch now):
      const staleBind = RuntimeStateCoordinator.open(a.store, bootEpoch(eid("w6bootbootb00")), "23e-parent");
      expect(staleBind.ok).toBe(false);
      if (!staleBind.ok) expect(staleBind.failureCode).toBe("coordinator_epoch_mismatch");
    }
  }, 60000);
});

describe("23E — scope honesty and evidence invariants", () => {
  it("the scope claim is stated in-source: process-kill only, no power-loss extension", () => {
    const raw = readFileSync(join(process.cwd(), "tests", "integration", "phase23e-crash-continuity.test.ts"), "utf8");
    expect(raw).toContain("process-kill only");
    expect(raw).toContain("No power-cut, controller-cache, kernel-panic");
    // Needles are split across the literal so they cannot match their own
    // assertion arguments:
    expect(raw).not.toContain("certifies power" + "-loss");
    expect(raw).not.toContain("hardware durability" + " guaranteed");
  });
});
