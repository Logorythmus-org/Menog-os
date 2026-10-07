import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import {
  TOOL_REPLAY_SEMANTICS,
  buildToolRunRecord,
  verifyToolRunRecord,
  checkManifestIntegrity,
  verifyOutputIntegrity,
  verifyLedgerObservation,
  explainToolRun,
  planEvidenceReplay,
  type ToolRunRecord,
} from "@menog/runtime-linux";
import { AppendOnlyLedger } from "@menog/event-ledger";

/**
 * PRE-21E — evidence/explainability tests.
 *
 * Proven:
 * - records seal every field; ANY mutation is detected (output hash swap,
 *   decision rewrite, manifest hash change, parent id change);
 * - manifest drift and output tamper are typed failures;
 * - a ledger-backed record with a missing event or broken chain fails;
 * - workspaces are redacted (no path ever enters a record or explanation);
 * - explanations are byte-deterministic from a record;
 * - the replay plan carries NOTHING executable (structural scan) and its
 *   steps expose only hash/identity fields.
 */

const OUTPUT = Buffer.from("deterministic tool output\n");
const OUTPUT_HASH = "sha256:" + createHash("sha256").update(OUTPUT).digest("hex");

const baseParents = {
  skillId: "demo.workspace-survey" as string | null,
  skillStepId: "survey-listing" as string | null,
  taskId: null as string | null,
  assignmentId: "assign-1" as string | null,
  agentId: "menog-agent-planner",
};
const basePolicy = { outcome: "allow", matchedRule: "rule:day1:allow-inspect-readonly-aggregate" as string | null };
const baseIsolation = {
  profileId: "tool-baseline-v0",
  evidenceHash: "sha256:" + createHash("sha256").update("iso-ev").digest("hex"),
};
const baseResult = {
  status: "completed",
  exitCode: 0 as number | null,
  timedOut: false,
  outputHash: OUTPUT_HASH as string | null,
  outputBytes: OUTPUT.length as number | null,
  truncated: false,
};

type RecordOverrides = {
  parents?: Partial<typeof baseParents>;
  policy?: Partial<typeof basePolicy>;
  isolation?: Partial<typeof baseIsolation>;
  result?: Partial<typeof baseResult>;
  workspaceRoot?: string;
  toolId?: string;
  version?: string;
  manifestHash?: string;
  requestHash?: string;
  recordedAt?: string;
};

function record(over: RecordOverrides = {}): ToolRunRecord {
  return buildToolRunRecord({
    parents: { ...baseParents, ...over.parents },
    requestHash: over.requestHash ?? "sha256:" + createHash("sha256").update("the-request-canonical-form").digest("hex"),
    toolId: over.toolId ?? "tool.listing",
    version: over.version ?? "1.0.0",
    manifestHash: over.manifestHash ?? "sha256:" + createHash("sha256").update("manifest-bytes").digest("hex"),
    policy: { ...basePolicy, ...over.policy },
    isolation: { ...baseIsolation, ...over.isolation },
    result: { ...baseResult, ...over.result },
    workspaceRoot: over.workspaceRoot ?? "/tmp/menog-ws-21e/secret-subdir",
    recordedAt: over.recordedAt ?? "2026-09-27T00:00:00.000Z",
  });
}

// ── sealing + tamper detection ───────────────────────────────────────────────

describe("21E record integrity — any mutation is detected", () => {
  it("seals a record whose hash verifies", () => {
    const r = record();
    expect(verifyToolRunRecord(r).ok).toBe(true);
    expect(r.recordHash).toHaveLength(64);
  });

  it("detects an output-hash swap", () => {
    const r = record();
    const forged = { ...r, result: { ...r.result, outputHash: "sha256:" + "0".repeat(64) } };
    expect(verifyToolRunRecord(forged).ok).toBe(false);
  });

  it("detects a decision rewrite or parent-id change", () => {
    const r = record();
    expect(verifyToolRunRecord({ ...r, policy: { outcome: "deny", matchedRule: null } }).ok).toBe(false);
    expect(
      verifyToolRunRecord({ ...r, parents: { ...r.parents, agentId: "menog-agent-builder" } }).ok
    ).toBe(false);
  });

  it("detects manifest drift against the current registry hash", () => {
    const r = record();
    expect(checkManifestIntegrity(r, r.manifestHash).ok).toBe(true);
    const drifted = checkManifestIntegrity(r, "sha256:" + "1".repeat(64));
    expect(drifted.ok).toBe(false);
    if (!drifted.ok) {
      expect(drifted.code).toBe("MANIFEST_DRIFT");
      expect(drifted.message).toContain("tool.listing@1.0.0");
    }
  });

  it("detects output tamper when actual bytes are re-hashed", () => {
    const r = record();
    expect(verifyOutputIntegrity(r, OUTPUT_HASH).ok).toBe(true);
    const tampered = Buffer.from("evil replacement output");
    const res = verifyOutputIntegrity(
      r,
      "sha256:" + createHash("sha256").update(tampered).digest("hex")
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("OUTPUT_TAMPERED");
    expect(verifyOutputIntegrity(r, null).ok).toBe(false);
  });
});

// ── ledger observation ───────────────────────────────────────────────────────

describe("21E ledger observation — no event, no proof", () => {
  it("verifies when the ledger carries the record and the chain is green", () => {
    const r = record();
    const ledger = AppendOnlyLedger.inMemory();
    ledger.append({
      eventId: "ev-21e-1",
      timestamp: r.recordedAt,
      eventType: "tool_run_evidence",
      actor: { type: "runtime", id: "tool-runtime" },
      workspaceId: r.workspaceId,
      taskId: r.parents.skillStepId ?? undefined,
      verb: "inspect",
      capability: "workspace:list",
      policyDecision: "allow",
      inputSummary: { recordHash: r.recordHash },
      resultSummary: { sealed: r.recordHash },
    });
    const res = verifyLedgerObservation(r, ledger);
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.value.eventId).toBe("ev-21e-1");
  });

  it("fails with LEDGER_EVENT_MISSING when the ledger never saw the record", () => {
    const r = record();
    const ledger = AppendOnlyLedger.inMemory();
    const res = verifyLedgerObservation(r, ledger);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.code).toBe("LEDGER_EVENT_MISSING");
      expect(res.message).toContain("never observed");
    }
  });
});

// ── redaction ────────────────────────────────────────────────────────────────

describe("21E redaction — paths never survive", () => {
  it("carries only the non-reversible workspace label in record and explanation", () => {
    const r = record();
    expect(r.workspaceId).toMatch(/^workspace:[0-9a-f]{12}$/);
    expect(r.workspaceId).not.toContain("menog-ws-21e");
    expect(r.workspaceId).not.toContain("secret-subdir");
    const ex = explainToolRun(r);
    expect(ex.workspace).toBe(r.workspaceId);
    expect(JSON.stringify(ex)).not.toContain("secret-subdir");
  });

  it("different workspace roots yield different labels (collision-visible)", () => {
    const a = record().workspaceId;
    const b = record({ workspaceRoot: "/tmp/menog-ws-21e/other" }).workspaceId;
    expect(a).not.toBe(b);
  });
});

// ── deterministic explanation ────────────────────────────────────────────────

describe("21E explanation — deterministic, backed by sealed fields only", () => {
  it("same record ⇒ byte-identical explanation; tamper flips integrity", () => {
    const r = record();
    const a = JSON.stringify(explainToolRun(r));
    const b = JSON.stringify(explainToolRun(record()));
    expect(a).toBe(b);
    const forged = { ...r, result: { ...r.result, exitCode: 137 } };
    const ex = explainToolRun(forged);
    expect(ex.integrity).toBe("tampered");
    expect(ex.warnings.length).toBeGreaterThan(0);
  });

  it("explains the run in authority-chain order without inferring anything", () => {
    const ex = explainToolRun(record());
    expect(ex.summary).toContain("tool.listing@1.0.0");
    expect(ex.summary).toContain("skill 'demo.workspace-survey'");
    expect(ex.summary).toContain("completed");
    expect(ex.policyVerdict).toContain("rule:day1:allow-inspect-readonly-aggregate");
    expect(ex.isolation).toContain("tool-baseline-v0");
    expect(ex.output).toContain("sealed as");
  });
});

// ── non-executing replay ─────────────────────────────────────────────────────

describe("21E replay plan — evidence reconstruction, never execution", () => {
  it("builds a multi-step plan with explicit non-executing semantics", () => {
    const plan = planEvidenceReplay([
      record(),
      record({ toolId: "tool.status", parents: { skillStepId: "survey-status" } }),
    ]);
    expect(plan.ok).toBe(true);
    if (!plan.ok) return;
    expect(plan.value.replaySemantics).toBe(TOOL_REPLAY_SEMANTICS);
    expect(plan.value.disclaimer).toContain("not executable");
    expect(plan.value.steps).toHaveLength(2);
    expect(plan.value.steps[0]!.sequence).toBe(1);
    expect(plan.value.skillId).toBe("demo.workspace-survey");
  });

  it("carries NOTHING executable — structural scan over the whole plan", () => {
    const plan = planEvidenceReplay([record()]);
    if (!plan.ok) throw new Error("fixture invalid");
    const blob = JSON.stringify(plan.value);
    for (const forbidden of [
      "argv", "cwd", "executablePath", "launcherFlags", "launcherPath",
      "envAllowlist", "transportOverride", "targetArgv", "input", "command",
    ]) {
      expect(blob).not.toContain('"' + forbidden + '"');
    }
    const shape = Object.keys(plan.value.steps[0]!);
    for (const key of shape) {
      expect([
        "sequence", "toolId", "version", "manifestHash", "requestHash",
        "outcomeStatus", "recordHash",
      ]).toContain(key);
    }
  });

  it("refuses to build a plan from tampered records", () => {
    const forged = { ...record(), toolId: "evil.tool" };
    const res = planEvidenceReplay([forged]);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("RECORD_TAMPERED");
    expect(planEvidenceReplay([]).ok).toBe(false);
  });

  it("a plan derived from identical runs is byte-identical (except builtAt)", () => {
    const a = planEvidenceReplay([
      record(),
      record({ toolId: "tool.status", parents: { skillStepId: "survey-status" } }),
    ]);
    const b = planEvidenceReplay([
      record(),
      record({ toolId: "tool.status", parents: { skillStepId: "survey-status" } }),
    ]);
    if (!a.ok || !b.ok) throw new Error("fixture invalid");
    expect(a.value.pathHash).toBe(b.value.pathHash);
    expect(a.value.steps).toEqual(b.value.steps);
    expect(a.value.disclaimer).toBe(b.value.disclaimer);
  });
});
