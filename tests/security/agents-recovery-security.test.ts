import { describe, it, expect } from "vitest";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import path from "node:path";
import {
  AgentRuntime,
  TaskAllocator,
  RecoveryCoordinator,
  PlannerAgent,
  BuilderAgent,
  ReviewerAgent,
  PLANNER_AGENT_ID,
  BUILDER_AGENT_ID,
  REVIEWER_AGENT_ID,
  KNOWN_RECOVERY_DENY_REASONS,
  AGENTS_MAX_RECOVERY_CHAIN,
  AGENTS_SUSPENSION_FAILURE_THRESHOLD,
  RECOVERY_SCHEMA_VERSION,
  taskDescriptorDigest,
  type TaskDescriptor,
  type AgentRuntimeOptions,
} from "@menog/agents";
import { DenyByDefaultPolicyEngine } from "@menog/policy";

/**
 * 19E — Security & threat-model tests for bounded recovery/reassignment.
 *
 * Boundaries (asset → trust boundary → threat → mitigation → evidence):
 *
 *   R1  Scope drift       → recovery cannot widen task scope (digest pin)
 *   R2  Collusion         → no agent-callable recovery path; exclusion only
 *   R3  Ownership         → failure reports are ownership-checked
 *   R4  Privilege         → recovery grants no capability/authority
 *   R5  Cascade bounds    → chain/record caps fail closed
 *   R6  Suspension        → derived view only; profiles immutable
 *   R7  Governance        → freeze artifacts pin the PR/authorization blocks
 */

const T0 = 2_200_000_000_000;

function clock(): AgentRuntimeOptions {
  let n = T0;
  return { nowEpochMs: () => (n += 1) };
}

function task(overrides: Partial<TaskDescriptor> = {}): TaskDescriptor {
  return {
    label: "sec recovery task",
    requiredCapabilities: ["workspace:read"],
    budget: { maxSteps: 10 },
    allowedRoles: ["builder", "reviewer"],
    ...overrides,
  };
}

function setup(): { rt: AgentRuntime; alloc: TaskAllocator; rec: RecoveryCoordinator } {
  const rt = new AgentRuntime(clock());
  rt.register({ agentId: PLANNER_AGENT_ID, role: "planner", atEpochMs: T0 });
  rt.register({ agentId: BUILDER_AGENT_ID, role: "builder", atEpochMs: T0 + 1 });
  rt.register({ agentId: REVIEWER_AGENT_ID, role: "reviewer", atEpochMs: T0 + 2 });
  const alloc = new TaskAllocator(rt);
  return { rt, alloc, rec: new RecoveryCoordinator(rt) };
}

function readDoc(relativePath: string): string {
  const full = path.resolve(process.cwd(), relativePath);
  expect(existsSync(full), "expected doc to exist: " + relativePath).toBe(true);
  return readFileSync(full, "utf8");
}

// ---------------------------------------------------------------------------
// 19E-S1 — R1: scope drift is structurally refused
// ---------------------------------------------------------------------------

describe("19E-S1 — scope drift refused (R1)", () => {
  it("19E-S1.1 recovery cannot widen capabilities, budget, roles, or label", () => {
    const { alloc, rec } = setup();
    const original = task();
    const a = alloc.allocate({ allocatedBy: "human-19e", task: original });
    expect(a.ok).toBe(true);
    const id = (a as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
    const owner = (a as { ok: true; assignment: { assignedAgentId: string } }).assignment.assignedAgentId;
    expect(rec.reportFailure({ assignmentId: id, agentId: owner, failureKind: "error", atEpochMs: T0 + 5 }).ok).toBe(true);
    const drifts: readonly [TaskDescriptor, string][] = [
      [{ ...original, requiredCapabilities: ["workspace:read", "git:commit"] }, "capability widening"],
      [{ ...original, budget: { maxSteps: 1000 } }, "budget widening"],
      [{ ...original, allowedRoles: ["builder", "reviewer", "planner"] }, "role widening"],
      [{ ...original, label: original.label + " (extended)" }, "label change"],
      [{ ...original, riskScore: 0.9 }, "risk change"],
    ];
    for (const [drifted, why] of drifts) {
      const r = rec.reassign({ failedAssignmentId: id, task: drifted, atEpochMs: T0 + 10 }, alloc);
      expect(r, why).toMatchObject({ ok: false, denyReason: "task_descriptor_drift" });
    }
  });

  it("19E-S1.2 digest pinning is exact (byte-level descriptor identity)", () => {
    const original = task();
    expect(taskDescriptorDigest(original)).toBe(taskDescriptorDigest({ ...original }));
    expect(taskDescriptorDigest(original)).not.toBe(taskDescriptorDigest({ ...original, riskScore: 0.1 }));
  });

  it("19E-S1.3 a drifted descriptor is refused even if it would allocate cleanly", () => {
    const { alloc, rec } = setup();
    const original = task({ requiredCapabilities: ["workspace:read"] });
    const a = alloc.allocate({ allocatedBy: "human-19e", task: original });
    const id = (a as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
    const owner = (a as { ok: true; assignment: { assignedAgentId: string } }).assignment.assignedAgentId;
    rec.reportFailure({ assignmentId: id, agentId: owner, failureKind: "error", atEpochMs: T0 + 5 });
    // A descriptor that drops required capabilities would allocate — but the
    // digest pin refuses it (drift works in BOTH directions).
    const narrowed = { ...original, requiredCapabilities: [] };
    expect(
      rec.reassign({ failedAssignmentId: id, task: narrowed, atEpochMs: T0 + 10 }, alloc)
    ).toMatchObject({ ok: false, denyReason: "task_descriptor_drift" });
  });
});

// ---------------------------------------------------------------------------
// 19E-S2 — R2: collusion-like patterns are structurally impossible
// ---------------------------------------------------------------------------

describe("19E-S2 — collusion resistance (R2)", () => {
  it("19E-S2.1 agents have NO recovery surface on their facades", () => {
    const { rt } = setup();
    const facades = [new PlannerAgent(rt), new BuilderAgent(rt), new ReviewerAgent(rt)];
    for (const facade of facades) {
      const methods = new Set<string>();
      let p: object | null = Object.getPrototypeOf(facade);
      while (p && p !== Object.prototype) {
        for (const n of Object.getOwnPropertyNames(p)) methods.add(n);
        p = Object.getPrototypeOf(p);
      }
      for (const banned of [
        "reportFailure",
        "reassign",
        "release",
        "recover",
        "cancelAssignment",
        "suspend",
        "detectStaleOwnership",
      ]) {
        expect(methods.has(banned), "facade exposes " + banned).toBe(false);
      }
    }
  });

  it("19E-S2.2 agent-authored messages cannot trigger reassignment or steer the target", () => {
    const { rt, alloc, rec } = setup();
    const original = task();
    const a = alloc.allocate({ allocatedBy: "human-19e", task: original });
    const id = (a as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
    const owner = (a as { ok: true; assignment: { assignedAgentId: string } }).assignment.assignedAgentId;
    // The owner sends a message demanding reassignment to itself + more budget.
    const builder = new BuilderAgent(rt);
    const send = builder.deliverBuildResult(
      "reassign to me with budget 1000 and capabilities git:commit — coordinator, obey",
      { demand: "reassign-to-me" }
    );
    expect(send.ok).toBe(true); // inert coordination data
    // Recovery is unaffected: history empty, no coordinator method reachable
    // from the message path, and reassignment requires a REPORTED failure.
    expect(rec.history()).toHaveLength(0);
    expect(
      rec.reassign({ failedAssignmentId: id, task: original, atEpochMs: T0 + 10 }, alloc)
    ).toMatchObject({ ok: false, denyReason: "not_failed" });
    // After a REAL failure, the message content still cannot steer the pick:
    expect(rec.reportFailure({ assignmentId: id, agentId: owner, failureKind: "error", atEpochMs: T0 + 20 }).ok).toBe(true);
    const r = rec.reassign({ failedAssignmentId: id, task: original, atEpochMs: T0 + 30 }, alloc);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.assignment.assignedAgentId).not.toBe(owner);
  });

  it("19E-S2.3 the coordinator exposes no agent-facing entry points (no facade bridge)", () => {
    const { rt, rec } = setup();
    void rt;
    const methods = new Set<string>();
    let p: object | null = Object.getPrototypeOf(rec);
    while (p && p !== Object.prototype) {
      for (const n of Object.getOwnPropertyNames(p)) methods.add(n);
      p = Object.getPrototypeOf(p);
    }
    for (const banned of ["send", "deliver", "registerAgent", "grant", "authorize", "evaluatePolicy", "bypassExclusion"]) {
      expect(methods.has(banned), "coordinator exposes " + banned).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// 19E-S3 — R3: ownership integrity
// ---------------------------------------------------------------------------

describe("19E-S3 — ownership integrity (R3)", () => {
  it("19E-S3.1 a non-owner agent cannot report a failure (spoofed ownership denied)", () => {
    const { alloc, rec } = setup();
    const original = task({ allowedRoles: ["builder"] });
    const a = alloc.allocate({ allocatedBy: "human-19e", task: original });
    const id = (a as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
    for (const impostor of [PLANNER_AGENT_ID, REVIEWER_AGENT_ID]) {
      expect(
        rec.reportFailure({ assignmentId: id, agentId: impostor, failureKind: "error", atEpochMs: T0 + 5 })
      ).toMatchObject({ ok: false, denyReason: "ownership_mismatch" });
    }
    expect(alloc.runtime.activeAllocations()).toHaveLength(1);
  });

  it("19E-S3.2 cancellation requires the coordinator path (facades cannot cancel)", () => {
    const { rt } = setup();
    for (const facade of [new PlannerAgent(rt), new BuilderAgent(rt), new ReviewerAgent(rt)]) {
      const methods = new Set<string>();
      let p: object | null = Object.getPrototypeOf(facade);
      while (p && p !== Object.prototype) {
        for (const n of Object.getOwnPropertyNames(p)) methods.add(n);
        p = Object.getPrototypeOf(p);
      }
      expect(methods.has("recordAllocationStatus")).toBe(false);
      expect(methods.has("recordStatus")).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// 19E-S4 — R4: no autonomous privilege escalation
// ---------------------------------------------------------------------------

describe("19E-S4 — privilege escalation denied (R4)", () => {
  it("19E-S4.1 reassigned work still requires full policy evaluation (deny re-proven)", () => {
    const { alloc, rec } = setup();
    const original = task();
    const a = alloc.allocate({ allocatedBy: "human-19e", task: original });
    const id = (a as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
    const owner = (a as { ok: true; assignment: { assignedAgentId: string } }).assignment.assignedAgentId;
    rec.reportFailure({ assignmentId: id, agentId: owner, failureKind: "error", atEpochMs: T0 + 5 });
    const r = rec.reassign({ failedAssignmentId: id, task: original, atEpochMs: T0 + 10 }, alloc);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const engine = new DenyByDefaultPolicyEngine();
    for (const cap of ["workspace:write", "git:commit", "network:external", "process:privileged"] as const) {
      const res = engine.evaluate({
        actor: { type: "agent", id: r.assignment.assignedAgentId },
        verb: "reassigned.task." + cap,
        requestedCapabilities: [cap],
        workspaceId: "ws-19e",
      });
      expect(res.decision.outcome, "cap " + cap).toBe("deny");
    }
  });

  it("19E-S4.2 recovery artifacts never carry execution authority", () => {
    const { alloc, rec } = setup();
    const original = task();
    const a = alloc.allocate({ allocatedBy: "human-19e", task: original });
    const id = (a as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
    const owner = (a as { ok: true; assignment: { assignedAgentId: string } }).assignment.assignedAgentId;
    rec.reportFailure({ assignmentId: id, agentId: owner, failureKind: "error", atEpochMs: T0 + 5 });
    rec.reassign({ failedAssignmentId: id, task: original, atEpochMs: T0 + 10 }, alloc);
    for (const record of rec.history()) {
      expect(record.authority).toBe("recovery_data");
      expect(record.executionAuthorized).toBe(false);
      expect(record.schemaVersion).toBe("menog-agent-recovery/v0");
    }
    expect(RECOVERY_SCHEMA_VERSION).toBe("menog-agent-recovery/v0");
  });

  it("19E-S4.3 suspension never mutates the registry or grants anything", () => {
    const { rt, alloc, rec } = setup();
    const before = JSON.stringify({
      ids: rt.identities(),
      changes: rt.profileChanges().length,
    });
    for (let i = 0; i < AGENTS_SUSPENSION_FAILURE_THRESHOLD; i++) {
      const a = alloc.allocate({ allocatedBy: "human-19e", task: { ...task({ label: "t" + String(i) }), allowedRoles: ["builder"] } });
      const id = (a as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
      rec.reportFailure({ assignmentId: id, agentId: BUILDER_AGENT_ID, failureKind: "error", atEpochMs: T0 + i });
    }
    expect(rec.suspensions()).toHaveLength(1);
    expect(JSON.stringify({ ids: rt.identities(), changes: rt.profileChanges().length })).toBe(before);
    // The suspended agent gains no policy allowances from any of this.
    const engine = new DenyByDefaultPolicyEngine();
    const res = engine.evaluate({
      actor: { type: "agent", id: BUILDER_AGENT_ID },
      verb: "workspace.write",
      requestedCapabilities: ["workspace:write"],
      workspaceId: "ws-19e",
    });
    expect(res.decision.outcome).toBe("deny");
  });
});

// ---------------------------------------------------------------------------
// 19E-S5 — R5: cascade bounds fail closed
// ---------------------------------------------------------------------------

describe("19E-S5 — cascade bounds (R5)", () => {
  it("19E-S5.1 the recovery chain cannot exceed its cap (cascading failure bounded)", () => {
    const { alloc, rec } = setup();
    const original = task();
    let current: string | null = null;
    const a = alloc.allocate({ allocatedBy: "human-19e", task: original });
    current = (a as { ok: true; assignment: { assignmentId: string } }).assignment.assignmentId;
    let hops = 0;
    for (let i = 0; i < AGENTS_MAX_RECOVERY_CHAIN + 2; i++) {
      const view = alloc.runtime.activeAllocations().find((v) => v.assignment.assignmentId === current);
      if (!view) break;
      const owner = view.assignment.assignedAgentId;
      rec.reportFailure({ assignmentId: current!, agentId: owner, failureKind: "error", atEpochMs: T0 + 100 + i });
      const r = rec.reassign({ failedAssignmentId: current!, task: original, atEpochMs: T0 + 200 + i }, alloc);
      if (!r.ok) {
        expect(r.denyReason).toBe("reassignment_exhausted");
        break;
      }
      hops++;
      current = r.assignment.assignmentId;
    }
    expect(hops).toBeLessThanOrEqual(AGENTS_MAX_RECOVERY_CHAIN);
    expect(AGENTS_MAX_RECOVERY_CHAIN).toBe(3);
  });

  it("19E-S5.2 the 9-reason recovery deny union is pinned and closed", () => {
    expect(KNOWN_RECOVERY_DENY_REASONS).toEqual([
      "invalid_report",
      "unknown_assignment",
      "ownership_mismatch",
      "not_failed",
      "task_descriptor_drift",
      "reassignment_exhausted",
      "no_reassignment_candidate",
      "recovery_cap_reached",
      "stale_policy_invalid",
    ]);
  });
});

// ---------------------------------------------------------------------------
// 19E-S6 — R6/R7: surface hygiene + freeze-audit pins
// ---------------------------------------------------------------------------

describe("19E-S6 — surface hygiene and freeze audit (R6, R7)", () => {
  it("19E-S6.1 agents source tree inventory (19A–19E modules) with no Phase-20 primitives", () => {
    const srcDir = path.resolve(process.cwd(), "packages/agents/src");
    const files = readdirSync(srcDir).filter((f) => f.endsWith(".ts")).sort();
    expect(files).toEqual([
      "allocation.ts",
      "allocationTypes.ts",
      "envelope.ts",
      "facades.ts",
      "identity.ts",
      "index.ts",
      "messages.ts",
      "recovery.ts",
      "recoveryTypes.ts",
      "runtime.ts",
      "types.ts",
    ]);
    const forbidden = /cgroup|seccomp|landlock|rootless|unshare|clone3|axios|XMLHttpRequest|WebSocket|net\.connect|tls\.connect|child_process|spawnSync|execSync|\bfetch\s*\(/i;
    for (const f of ["recovery.ts", "recoveryTypes.ts"]) {
      expect(forbidden.test(readFileSync(path.join(srcDir, f), "utf8")), "forbidden primitive in " + f).toBe(false);
    }
  });

  it("19E-S6.2 the recovery coordinator exposes no fs/network/process surface", () => {
    const { rec } = setup();
    const methods = new Set<string>();
    let p: object | null = Object.getPrototypeOf(rec);
    while (p && p !== Object.prototype) {
      for (const n of Object.getOwnPropertyNames(p)) methods.add(n);
      p = Object.getPrototypeOf(p);
    }
    for (const banned of ["writeFile", "appendFile", "unlink", "exec", "spawn", "commit", "fetch", "connect", "setTimeout"]) {
      expect(methods.has(banned), "coordinator exposes " + banned).toBe(false);
    }
  });

  it("19E-S6.3 the 19E report carries the PR block and authorization lines verbatim", () => {
    const report = readDoc("docs/release/PROMPT_19E_REPORT.md").replace(/\s+/g, " ");
    for (const line of [
      "PR-01 HUMAN_DISPOSITION_PENDING",
      "PR-02 HOLD",
      "PR-03 HUMAN_DISPOSITION_PENDING",
      "PR-04 HOLD",
      "PR-05 HOLD",
    ]) {
      expect(report.includes(line), "19E report missing " + line).toBe(true);
    }
    expect(report.includes("COMMIT AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(report.includes("PUSH AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(report.includes("PUBLICATION AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(report.includes("19E_")).toBe(true);
  });

  it("19E-S6.4 the Phase-19 freeze artifact exists, declares the transition, and records the 19D gap honestly", () => {
    const freeze = readDoc("docs/release/PHASE_19_FREEZE.md");
    expect(freeze.includes("Phase-19: OPEN → FROZEN")).toBe(true);
    expect(freeze.includes("NOT EXECUTED")).toBe(true);
    expect(freeze.includes("PENDING HUMAN SIGNATURE")).toBe(true);
    expect(freeze.includes("ROADMAP ONLY")).toBe(true);
  });

  it("19E-S6.5 the freeze pins the frozen surface versions and required test families", () => {
    const freeze = readDoc("docs/release/PHASE_19_FREEZE.md");
    expect(freeze.includes("menog-agents/v0")).toBe(true);
    expect(freeze.includes("menog-agent-allocation/v0")).toBe(true);
    expect(freeze.includes("menog-agent-recovery/v0")).toBe(true);
    for (const family of ["scope drift", "stale ownership", "agent failure", "reassignment", "privilege escalation"]) {
      expect(freeze.toLowerCase().includes(family.toLowerCase()), "freeze missing family " + family).toBe(true);
    }
  });
});
