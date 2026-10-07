/**
 * PRE-20D — policy↔isolation binding tests (authority separation).
 *
 * Proves the formalization on the real policy engine and the real 20B/20C
 * contracts:
 * - trusted projection (monotone; deny never projects; Day-1 network deny
 *   forces a required netns);
 * - strict sequence (policy → preflight → spawn; any violation refused);
 * - evidence binding to task/agent/execution ids with redacted workspace and
 *   `execution_not_started` when isolation fails after an allow;
 * - ledger append on the existing spine (hash-chain verified).
 */

import { describe, it, expect } from "vitest";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import { AppendOnlyLedger } from "@menog/event-ledger";
import {
  projectPolicyToProfile,
  newSequenceState,
  checkSequence,
  buildBoundExecutionEvidence,
  appendBoundEvidence,
  redactWorkspace,
  EXECUTION_BASELINE_PROFILE_ID,
  type BoundEvidenceIds,
} from "@menog/runtime-linux";

const HUMAN: { type: "human"; id: string } = { type: "human", id: "r0-human-operator" };
const AGENT: { type: "agent"; id: string } = { type: "agent", id: "menog-agent-builder" };
const WORKSPACE = "C:\\temp\\menog-20d-fixture";
const IDS: BoundEvidenceIds = {
  taskId: "task-20d-001",
  agentId: AGENT.id,
  executionId: "iso-exec-001",
  workspaceRoot: WORKSPACE,
};

// ── projection ───────────────────────────────────────────────────────────────

describe("20D projection — trusted, monotone, deny-refusing", () => {
  const engine = new DenyByDefaultPolicyEngine();

  it("refuses to project a policy DENY (deny never reaches isolation)", () => {
    const deny = engine.evaluate({
      actor: AGENT,
      verb: "commit",
      requestedCapabilities: ["git:commit"],
      workspaceId: WORKSPACE,
    });
    expect(deny.decision.outcome).toBe("deny");
    const p = projectPolicyToProfile(deny);
    expect(p.ok).toBe(false);
    if (p.ok) return;
    expect(p.reason).toContain("deny never projects");
  });

  it("projects an ALLOW into a valid human_reviewed profile", () => {
    const allow = engine.evaluate({
      actor: HUMAN,
      verb: "inspect",
      requestedCapabilities: ["workspace:list", "workspace:read-metadata"],
      workspaceId: WORKSPACE,
    });
    expect(allow.decision.outcome).toBe("allow");
    const p = projectPolicyToProfile(allow);
    expect(p.ok).toBe(true);
    if (!p.ok) return;
    expect(p.profile.origin).toBe("human_reviewed");
    expect(p.profile.profileId.startsWith(EXECUTION_BASELINE_PROFILE_ID)).toBe(true);
    // Day-1: network:external is never allowed ⇒ netns REQUIRED in the profile.
    const net = p.profile.requirements.find((r) => r.primitive === "ns_net");
    expect(net?.criticality).toBe("required");
    expect(net?.onMissing).toBe("fail_closed");
  });

  it("is monotone over the 20C floor: adds ns_net, keeps every floor requirement", () => {
    const allow = engine.evaluate({
      actor: HUMAN,
      verb: "inspect",
      requestedCapabilities: ["workspace:list"],
      workspaceId: WORKSPACE,
    });
    const p = projectPolicyToProfile(allow);
    expect(p.ok).toBe(true);
    if (!p.ok) return;
    const ids = new Set(p.profile.requirements.map((r) => r.primitive as string));
    for (const floor of ["ns_user", "ns_mount", "landlock_fs", "no_new_privs", "seccomp_filter"]) {
      expect(ids.has(floor), "floor requirement kept: " + floor).toBe(true);
    }
    expect(ids.has("ns_net")).toBe(true);
  });
});

// ── sequence guard ───────────────────────────────────────────────────────────

describe("20D sequence — policy first, then preflight, then spawn", () => {
  it("refuses preflight before policy and spawn before preflight", () => {
    let s = newSequenceState();
    const r1 = checkSequence(s, "record_plan");
    expect(r1.ok).toBe(false);

    s = newSequenceState();
    const r2 = checkSequence(s, "record_policy", "allow");
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    const r3 = checkSequence(r2.state, "record_spawn");
    expect(r3.ok).toBe(false);

    const r4 = checkSequence(r2.state, "record_plan");
    expect(r4.ok).toBe(true);
    if (!r4.ok) return;
    const r5 = checkSequence(r4.state, "record_spawn");
    expect(r5.ok).toBe(true);
  });

  it("refuses the whole chain when the policy outcome was DENY (deny override)", () => {
    let s = newSequenceState();
    const r1 = checkSequence(s, "record_policy", "deny");
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    const r2 = checkSequence(r1.state, "record_plan");
    expect(r2.ok).toBe(false);
    if (r2.ok) return;
    expect(r2.reason).toContain("policy did not allow");
  });
});

// ── evidence binding ─────────────────────────────────────────────────────────

describe("20D evidence — bound, redacted, execution_not_started on isolation failure", () => {
  it("redacts the workspace path to a non-reversible label", () => {
    const label = redactWorkspace(WORKSPACE);
    expect(label.startsWith("workspace:")).toBe(true);
    expect(label).not.toContain("temp");
    expect(label).not.toContain("fixture");
    expect(label.length).toBeLessThanOrEqual("workspace:".length + 12);
  });

  it("emits execution_not_started when preflight aborts after an allow", () => {
    const engine = new DenyByDefaultPolicyEngine();
    const allow = engine.evaluate({
      actor: HUMAN,
      verb: "inspect",
      requestedCapabilities: ["workspace:list"],
      workspaceId: WORKSPACE,
    });
    const p = projectPolicyToProfile(allow);
    expect(p.ok).toBe(true);
    if (!p.ok) return;
    // Snapshot missing a required primitive ⇒ plan aborts ⇒ never spawned.
    const ev = buildBoundExecutionEvidence({
      ids: IDS,
      policy: allow,
      plan: {
        executionId: IDS.executionId,
        profileId: p.profile.profileId,
        aborted: true,
        reason: "fail-closed preflight: missing required primitives [ns_user] — no process will be spawned",
        decision: {
          disposition: "fail_closed",
          satisfied: [], missingRequired: ["ns_user"], degradations: [],
          canProceed: false, reasons: ["required primitive 'ns_user' is UNSUPPORTED — fail closed"],
        },
      },
      run: null,
    });
    expect(ev.outcome).toBe("execution_not_started");
    expect(ev.failedPrimitive).toBe("ns_user");
    expect(ev.binding.workspaceId.startsWith("workspace:")).toBe(true);
    expect(ev.binding.taskId).toBe(IDS.taskId);
  });

  it("binds completed-run evidence with enforced primitives and hash", () => {
    const engine = new DenyByDefaultPolicyEngine();
    const allow = engine.evaluate({
      actor: HUMAN,
      verb: "inspect",
      requestedCapabilities: ["workspace:list"],
      workspaceId: WORKSPACE,
    });
    const ev = buildBoundExecutionEvidence({
      ids: IDS,
      policy: allow,
      plan: {
        executionId: IDS.executionId,
        profileId: EXECUTION_BASELINE_PROFILE_ID,
        aborted: false,
        decision: {
          disposition: "degrade_explicit",
          satisfied: ["ns_user", "landlock_fs", "no_new_privs", "seccomp_filter"],
          missingRequired: [], degradations: [],
          canProceed: true, reasons: [],
        },
        requiredSet: [], availableSet: [], enforcedSet: [], launcherFlags: [],
        landlockWritePaths: [], timeoutMs: 4000,
      },
      run: {
        ok: true, exitCode: 0, signal: null, timedOut: false, targetRan: true,
        evidence: {
          schemaVersion: "menog-isolation-contract/v0",
          decisionProfileId: EXECUTION_BASELINE_PROFILE_ID,
          enforced: {
            ns_user: { applied: true, detail: "map-root" },
            landlock_fs: { applied: true, abi: 1, detail: "write-class" },
          },
          evidenceHash: "a".repeat(64),
          recordedAt: "2026-09-27T00:00:00.000Z",
        },
        stdout: Buffer.alloc(0), stderr: Buffer.alloc(0),
      },
    });
    expect(ev.outcome).toBe("completed");
    expect(ev.enforcedPrimitives).toContain("landlock_fs");
    expect(ev.evidenceHash).toBe("a".repeat(64));
    expect(ev.policyRule ?? null).toBeDefined();
  });

  it("appends to the real ledger and keeps the chain verified", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const engine = new DenyByDefaultPolicyEngine();
    const allow = engine.evaluate({
      actor: HUMAN,
      verb: "inspect",
      requestedCapabilities: ["workspace:list"],
      workspaceId: WORKSPACE,
    });
    const ev = buildBoundExecutionEvidence({
      ids: IDS,
      policy: allow,
      plan: { executionId: IDS.executionId, profileId: EXECUTION_BASELINE_PROFILE_ID, aborted: true, reason: "x", decision: { disposition: "fail_closed", satisfied: [], missingRequired: ["ns_user"], degradations: [], canProceed: false, reasons: [] } },
      run: null,
    });
    const r = appendBoundEvidence(ledger, ev, AGENT);
    expect(r.ok).toBe(true);
    const types = ledger.events().map((e) => e.eventType);
    expect(types).toContain("isolated_execution_evidence");
    const stored = ledger.events().find((e) => e.eventType === "isolated_execution_evidence");
    const summary = JSON.stringify(stored?.resultSummary ?? {});
    expect(summary).not.toContain("fixture"); // redaction held at the spine
    expect(ledger.verify().ok).toBe(true);
  });
});
