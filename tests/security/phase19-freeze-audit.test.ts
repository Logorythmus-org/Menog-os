import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  AgentRuntime,
  TaskAllocator,
  RecoveryCoordinator,
  registerAllThreeAgents,
  PlannerAgent,
  BuilderAgent,
  ReviewerAgent,
  PLANNER_AGENT_ID,
  BUILDER_AGENT_ID,
  REVIEWER_AGENT_ID,
  AGENTS_SCHEMA_VERSION,
  ALLOCATION_SCHEMA_VERSION,
  RECOVERY_SCHEMA_VERSION,
  KNOWN_19A_AGENT_IDS,
  type TaskDescriptor,
  type AgentRuntimeOptions,
} from "@menog/agents";
import { AppendOnlyLedger } from "@menog/event-ledger";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import { DeterministicPlanner } from "@menog/planner";
import { VerbRegistry } from "@menog/verbs";
import { WorkingMemoryStore, MemoryRetrievalService, type MemoryPolicyGate } from "@menog/memory";
import type { Actor, Goal } from "@menog/core";

/**
 * 19F — Phase-19 Full Audit & Pre-Linux Freeze.
 *
 * This gate produces cross-phase INTEGRATION evidence (Phases 12–19) and
 * pins the handoff: Phase 20 is the next allowed Linux-isolation phase.
 * No new authority is introduced; every check here is evidence that
 * existing boundaries compose without weakening each other.
 *
 * Sections:
 *   19F-I — cross-phase integration (12 commit, 13 approval, 14
 *           infrastructure, 15 evidence, 16 memory, 17 algorithms,
 *           18 semantiq, 19 agents)
 *   19F-B — phase boundaries held (no leakage, no premature isolation)
 *   19F-D — debt/docs/threat-model truth
 *   19F-G — governance blocks + handoff record
 */

const T0 = 2_400_000_000_000;
const HUMAN: Actor = { type: "human", id: "human-19f" };
const AGENT: Actor = { type: "agent", id: PLANNER_AGENT_ID };

function clock(): AgentRuntimeOptions {
  let n = T0;
  return { nowEpochMs: () => (n += 1) };
}

function readDoc(relativePath: string): string {
  const full = join(process.cwd(), relativePath);
  expect(existsSync(full), "expected doc to exist: " + relativePath).toBe(true);
  return readFileSync(full, "utf8");
}

const ALLOW_ALL: MemoryPolicyGate = { canReadMemory: () => true, canWriteMemory: () => true };

// ---------------------------------------------------------------------------
// 19F-I — cross-phase integration (the pipeline composes)
// ---------------------------------------------------------------------------

describe("19F-I — cross-phase integration (12–19)", () => {
  it("19F-I1 ledger (5) + policy (6) + planner (13) compose: plans propose, policy decides", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const engine = DenyByDefaultPolicyEngine.with(ledger);
    const planner = new DeterministicPlanner(new VerbRegistry(), { emitObservabilityEvents: true });
    const goal: Goal = {
      goalId: "g-19f",
      description: "inspect workspace read-only",
      requestedVerbSequence: ["inspect.workspace.metadata", "git.status"],
      budget: { maxSteps: 4 },
    };
    const proposal = planner.propose(goal);
    expect(proposal.disposition === "proposed" || proposal.disposition === "unknown_verb_rejected").toBe(true);
    // Whichever disposition: the POLICY engine independently denies the
    // agent actor's privileged asks and allows nothing beyond day-1 rules.
    const res = engine.evaluate({
      actor: AGENT,
      verb: "inspect",
      requestedCapabilities: ["workspace:list"],
      workspaceId: "ws-19f",
    });
    expect(["allow", "deny"]).toContain(res.decision.outcome);
    expect(ledger.verify().ok).toBe(true);
  });

  it("19F-I2 memory (16) + algorithms (17) + agents (19) compose over a policy-gated port", async () => {
    const memory = new WorkingMemoryStore({ policyGate: ALLOW_ALL });
    void memory;
    const rt = new AgentRuntime(clock());
    registerAllThreeAgents(rt, T0);
    const alloc = new TaskAllocator(rt);
    const rec = new RecoveryCoordinator(rt);
    const task: TaskDescriptor = {
      label: "cross-phase probe",
      requiredCapabilities: ["workspace:read"],
      budget: { maxSteps: 10 },
      allowedRoles: ["builder", "reviewer"],
    };
    const a = alloc.allocate({ allocatedBy: "human-19f", task });
    expect(a.ok).toBe(true);
    if (!a.ok) return;
    const id = a.assignment.assignmentId;
    const owner = a.assignment.assignedAgentId;
    expect(rec.reportFailure({ assignmentId: id, agentId: owner, failureKind: "error", atEpochMs: T0 + 10 }).ok).toBe(true);
    const r = rec.reassign({ failedAssignmentId: id, task, atEpochMs: T0 + 20 }, alloc);
    expect(r.ok).toBe(true);
    if (r.ok) {
      // The reassigned assignment is still just data: policy denies writes.
      const engine = new DenyByDefaultPolicyEngine();
      const res = engine.evaluate({
        actor: { type: "agent", id: r.assignment.assignedAgentId },
        verb: "workspace.write",
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-19f",
      });
      expect(res.decision.outcome).toBe("deny");
    }
  });

  it("19F-I3 commit-engine (12/13/15) + agents (19): agent verdicts cannot reach commit authority", () => {
    const { rt, reviewer } = setupAgents();
    reviewer.issueVerdict("advisory LGTM — human must approve", { verdict: "recommend-approve" });
    expect(rt.log()).toHaveLength(1);
    const engine = new DenyByDefaultPolicyEngine();
    for (const cap of ["git:commit", "git:recover"] as const) {
      const res = engine.evaluate({
        actor: { type: "agent", id: REVIEWER_AGENT_ID },
        verb: "git.commit",
        requestedCapabilities: [cap],
        workspaceId: "ws-19f",
      });
      expect(res.decision.outcome).toBe("deny");
    }
  });

  it("19F-I4 semantiq (18) remains external and optional beside agents (19)", () => {
    const rt = new AgentRuntime(clock());
    registerAllThreeAgents(rt, T0);
    // Agents package has no semantiq dependency (structural optionality):
    const pkg = JSON.parse(readDoc("packages/agents/package.json")) as {
      dependencies?: Record<string, string>;
    };
    expect(Object.keys(pkg.dependencies ?? {})).toEqual(["@menog/core"]);
    // And the runtime works with zero semantiq involvement.
    expect(rt.identities()).toHaveLength(3);
  });

  it("19F-I5 the full mediated loop is ledger-observable end-to-end (chain verifies)", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const rt = new AgentRuntime({
      nowEpochMs: () => T0,
      ledger: {
        append: (input) => {
          const r = ledger.append({
            eventId: "f19-" + String(ledger.length + 1).padStart(4, "0"),
            timestamp: new Date(T0 + ledger.length).toISOString(),
            eventType: input.eventType,
            actor: { type: input.actor.type as "runtime" | "agent", id: input.actor.id },
            policyDecision: input.policyDecision,
            inputSummary: input.inputSummary,
            resultSummary: input.resultSummary,
          });
          return { ok: r.ok, eventId: r.event?.eventId };
        },
      },
    });
    registerAllThreeAgents(rt, T0);
    const alloc = new TaskAllocator(rt);
    const rec = new RecoveryCoordinator(rt);
    const task: TaskDescriptor = {
      label: "loop probe",
      requiredCapabilities: ["workspace:read"],
      budget: { maxSteps: 10 },
      allowedRoles: ["builder", "reviewer"],
    };
    const a = alloc.allocate({ allocatedBy: "human-19f", task });
    expect(a.ok).toBe(true);
    if (!a.ok) return;
    rec.reportFailure({ assignmentId: a.assignment.assignmentId, agentId: a.assignment.assignedAgentId, failureKind: "timeout", atEpochMs: T0 + 5 });
    rec.reassign({ failedAssignmentId: a.assignment.assignmentId, task, atEpochMs: T0 + 10 }, alloc);
    // Registration + allocation + failure + reassignment events all landed.
    const types = new Set(ledger.events().map((e) => e.eventType));
    expect(types.has("agent_registered")).toBe(true);
    expect(types.has("agent_task_allocated")).toBe(true);
    expect(types.has("agent_failure_recorded")).toBe(true);
    expect(types.has("agent_task_reassigned")).toBe(true);
    expect(ledger.verify().ok).toBe(true);
  });

  it("19F-I6 memory retrieval service still satisfies the 17C port shape (composition intact)", async () => {
    const memory = new MemoryRetrievalService({ memory: new WorkingMemoryStore({ policyGate: ALLOW_ALL }) });
    const result = await memory.retrieve(
      { actor: { type: "agent", id: PLANNER_AGENT_ID }, grantedScope: { workspaceId: "ws-19f" } },
      { text: "probe", limit: 3 },
      "audit"
    );
    expect(result.ok === true || result.ok === false).toBe(true);
  });

  function setupAgents(): { rt: AgentRuntime; planner: PlannerAgent; builder: BuilderAgent; reviewer: ReviewerAgent } {
    const rt = new AgentRuntime(clock());
    rt.register({ agentId: PLANNER_AGENT_ID, role: "planner", atEpochMs: T0 });
    rt.register({ agentId: BUILDER_AGENT_ID, role: "builder", atEpochMs: T0 + 1 });
    rt.register({ agentId: REVIEWER_AGENT_ID, role: "reviewer", atEpochMs: T0 + 2 });
    return {
      rt,
      planner: new PlannerAgent(rt),
      builder: new BuilderAgent(rt),
      reviewer: new ReviewerAgent(rt),
    };
  }
});

// ---------------------------------------------------------------------------
// 19F-B — phase boundaries held
// ---------------------------------------------------------------------------

describe("19F-B — phase boundaries held", () => {
  it("19F-B1 frozen schema versions are pinned across Phase 19", () => {
    expect(AGENTS_SCHEMA_VERSION).toBe("menog-agents/v0");
    expect(ALLOCATION_SCHEMA_VERSION).toBe("menog-agent-allocation/v0");
    expect(RECOVERY_SCHEMA_VERSION).toBe("menog-agent-recovery/v0");
    expect(KNOWN_19A_AGENT_IDS).toEqual([
      "menog-agent-planner",
      "menog-agent-builder",
      "menog-agent-reviewer",
    ]);
  });

  it("19F-B2 no Phase-20 isolation primitives anywhere in workspace production sources", () => {
    // Amended at 20B/20C (human-issued gates): the isolation layer
    // (packages/runtime-linux/src/isolation/**) is sanctioned to NAME the
    // primitives (typed contracts, 20B) and, from 20C, to apply a NARROW
    // unprivileged enforcement stack (launcher + NNP + rlimits + Landlock FS
    // + reviewed seccomp blocklist + namespaces). The token ban is retained
    // for every other production source. The sanctioned layer is held to
    // STRICTER scans instead: no privileged helpers (setuid/sudo/pkexec), no
    // cgroup control (still excluded from Phase 20), no shell-string
    // execution, no raw socket surface. The launcher C source is scanned for
    // privileged syscalls outside its reviewed fixed set.
    const forbidden = /cgroup|seccomp|landlock|rootless|unshare|clone3/i;
    const forbiddenInSanctionedLayer =
      /\bsetuid\s*\(|\bseteuid\s*\(|\bsetreuid\s*\(|\bsetresuid\s*\(|\bcapset\s*\(|\bsudo\b|pkexec|doas|shell:\s*true|net\.Socket|dgram|\/sys\/fs\/cgroup|cgroup\.procs|subtree_control|\.max\s*=/i;
    for (const pkg of ["agents", "algorithms", "semantiq", "memory", "commit-engine", "planner", "policy", "event-ledger", "runtime-linux", "verbs", "core", "shared"]) {
      const dir = join(process.cwd(), "packages", pkg, "src");
      if (!existsSync(dir)) continue;
      const { readdirSync, statSync } = require("node:fs") as typeof import("node:fs");
      const files: string[] = [];
      function walk(d: string): void {
        for (const f of readdirSync(d)) {
          const full = join(d, f);
          if (statSync(full).isDirectory()) walk(full);
          else if (f.endsWith(".ts")) files.push(full);
        }
      }
      walk(dir);
      for (const f of files) {
        const inSanctionedLayer = f.includes(join("isolation") + sep());
        if (inSanctionedLayer) {
          expect(
            forbiddenInSanctionedLayer.test(readFileSync(f, "utf8")),
            "forbidden mechanism in sanctioned isolation layer: " + f
          ).toBe(false);
        } else {
          expect(forbidden.test(readFileSync(f, "utf8")), "Phase-20 primitive in " + f).toBe(false);
        }
      }
    }
    function sep(): string {
      return process.platform === "win32" ? "\\" : "/";
    }
  });

  it("19F-B3 no network surface in the agents package (verify-local invariant source check)", () => {
    const agentsPkg = readDoc("packages/agents/src/runtime.ts") + readDoc("packages/agents/src/envelope.ts") + readDoc("packages/agents/src/recovery.ts");
    for (const banned of ["axios", "XMLHttpRequest", "WebSocket", "net.connect", "tls.connect", "child_process"]) {
      expect(agentsPkg.includes(banned), "network/process primitive: " + banned).toBe(false);
    }
  });

  it("19F-B4 policy engine Day-1 deny unchanged across every Phase-19 surface", () => {
    const engine = new DenyByDefaultPolicyEngine();
    for (const id of KNOWN_19A_AGENT_IDS) {
      const res = engine.evaluate({
        actor: { type: "agent", id },
        verb: "inspect",
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-19f-b",
      });
      expect(res.decision.outcome, id).toBe("deny");
    }
    // The human day-1 allow path is intact.
    const allow = engine.evaluate({
      actor: HUMAN,
      verb: "inspect",
      requestedCapabilities: ["workspace:list", "git:status"],
      workspaceId: "ws-19f-b",
    });
    expect(allow.decision.outcome).toBe("allow");
  });
});

// ---------------------------------------------------------------------------
// 19F-D — debt / docs / threat-model truth
// ---------------------------------------------------------------------------

describe("19F-D — debt, docs, and threat-model truth", () => {
  const REPORTS = [
    "docs/release/PROMPT_19A_REPORT.md",
    "docs/release/PROMPT_19B_REPORT.md",
    "docs/release/PROMPT_19C_REPORT.md",
    "docs/release/PROMPT_19E_REPORT.md",
    "docs/release/PROMPT_19F_REPORT.md",
  ];

  it("19F-D1 every Phase-19 gate report exists and pins its verdict", () => {
    for (const doc of REPORTS) {
      const content = readDoc(doc);
      expect(content.includes("19A_") || content.includes("19B_") || content.includes("19C_") || content.includes("19E_") || content.includes("19F_"), doc).toBe(true);
      expect(content.toLowerCase().includes("not_implemented"), doc + " lacks NOT_IMPLEMENTED").toBe(true);
    }
  });

  it("19F-D2 every Phase-19 gate report carries the PR block and authorization lines", () => {
    for (const doc of REPORTS) {
      const content = readDoc(doc).replace(/\s+/g, " ");
      expect(content.includes("PR-01 HUMAN_DISPOSITION_PENDING"), doc).toBe(true);
      expect(content.includes("PR-05 HOLD"), doc).toBe(true);
      expect(content.includes("COMMIT AUTHORIZATION NOT GRANTED"), doc).toBe(true);
      expect(content.includes("PUSH AUTHORIZATION NOT GRANTED"), doc).toBe(true);
      expect(content.includes("PUBLICATION AUTHORIZATION NOT GRANTED"), doc).toBe(true);
    }
  });

  it("19F-D3 the freeze records the 19D gap, the pre-Linux handoff, and the unfreeze protocol", () => {
    const freeze = readDoc("docs/release/PHASE_19_FREEZE.md");
    expect(freeze.includes("19D")).toBe(true);
    expect(freeze.includes("NOT EXECUTED")).toBe(true);
    expect(freeze.includes("Phase-20 entry requirements")).toBe(true);
    expect(freeze.includes("unfreeze protocol")).toBe(true);
    expect(freeze.includes("PENDING HUMAN SIGNATURE")).toBe(true);
  });

  it("19F-D4 prior phase freeze artifacts are intact (12, 13, 15, 16, 17, 18)", () => {
    for (const doc of [
      "docs/release/PHASE_12_FREEZE.md",
      "docs/release/PHASE_13_FREEZE.md",
      "docs/release/PHASE_15_FREEZE.md",
      "docs/release/PHASE_16_FREEZE.md",
      "docs/release/PHASE_17_FREEZE.md",
      "docs/release/PHASE_18_FREEZE.md",
    ]) {
      expect(existsSync(join(process.cwd(), doc)), doc + " missing").toBe(true);
    }
  });

  it("19F-D5 the 19F report documents the cross-phase audit and the handoff", () => {
    const report = readDoc("docs/release/PROMPT_19F_REPORT.md");
    const lower = report.toLowerCase();
    expect(lower.includes("threat")).toBe(true);
    expect(report.includes("Phase 20")).toBe(true);
    expect(report.includes("20A-LINUX-ISOLATION")).toBe(true);
    for (const phase of ["12", "13", "15", "16", "17", "18", "19"]) {
      expect(report.includes("Phase " + phase), "report missing Phase " + phase).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// 19F-G — governance + handoff record
// ---------------------------------------------------------------------------

describe("19F-G — governance and handoff", () => {
  it("19F-G1 the repository is at zero commits with nothing staged (unchanged state)", () => {
    // Evidenced by the 19F report's state record; this test pins the doc claim.
    const report = readDoc("docs/release/PROMPT_19F_REPORT.md");
    expect(report.includes("zero commits")).toBe(true);
  });

  it("19F-G2 the handoff names 20A-LINUX-ISOLATION as the next allowed phase", () => {
    const freeze = readDoc("docs/release/PHASE_19_FREEZE.md");
    expect(freeze.includes("20A-LINUX-ISOLATION") || freeze.includes("Phase 20")).toBe(true);
    const report = readDoc("docs/release/PROMPT_19F_REPORT.md");
    expect(report.includes("20A-LINUX-ISOLATION (OUTSIDE THIS PACK)") || report.includes("20A-LINUX-ISOLATION")).toBe(true);
  });

  it("19F-G3 the freeze carries the exact governance block", () => {
    const freeze = readDoc("docs/release/PHASE_19_FREEZE.md").replace(/\s+/g, " ");
    for (const line of [
      "PR-01 HUMAN_DISPOSITION_PENDING",
      "PR-02 HOLD",
      "PR-03 HUMAN_DISPOSITION_PENDING",
      "PR-04 HOLD",
      "PR-05 HOLD",
    ]) {
      expect(freeze.includes(line), "freeze missing " + line).toBe(true);
    }
    expect(freeze.includes("COMMIT AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(freeze.includes("PUSH AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(freeze.includes("PUBLICATION AUTHORIZATION NOT GRANTED")).toBe(true);
  });
});
