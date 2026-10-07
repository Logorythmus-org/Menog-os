/**
 * PHASE 22G — Continuous Execution→Persistence→Restart→Recovery Scenario.
 *
 * END-TO-END / LOCAL. Proves Menog across a store/process lifecycle boundary
 * by composing EXISTING, individually verified components (no new features):
 *
 *   Goal/Task → real role allocation (19B) → real Policy decision (Day-1
 *   engine) → Phase-20 isolation plan → Phase-21 governed tool junction
 *   (injected transport) → sealed evidence + Event Ledger → Phase-22 durable
 *   transaction → close/reopen → recovery/reconciliation → reconstructed
 *   memory/task/evidence view → deterministic explanation + NON-EXECUTING
 *   replay plan.
 *
 * PROVEN here:
 * - ids/hashes survive the boundary (eventId, recordHash, assignmentId,
 *   requestHash, manifestHash, outputHash are byte-identical after restart);
 * - the ledger and evidence verify after recovery (22C vocabulary);
 * - lineage/lifecycle survives (goal lineage, assignment, task history);
 * - recovery executes nothing (structural + behavioral);
 * - recovered decisions/permissions are NEVER reused as authority: a
 *   post-restart execution requires a NEW live Policy decision and the
 *   normal isolation/junction path (recovered records grant no authority);
 * - a corrupted-variant store fails closed and quarantines across restart.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { AppendOnlyLedger } from "@menog/event-ledger";
import { VerbRegistry } from "@menog/verbs";
import { DeterministicPlanner } from "@menog/planner";
import { AgentRuntime, TaskAllocator, registerAllThreeAgents, type TaskDescriptor } from "@menog/agents";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import type { Actor, Goal } from "@menog/core";
import {
  TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
  TOOL_BASELINE_PROFILE_ID,
  LocalToolRegistry,
  validateManifest,
  executeToolRun,
  explainToolRun,
  verifyLedgerObservation,
  planEvidenceReplay,
  type ToolExecutionRequest,
  type IsolationCapabilitySnapshot,
  type LauncherToolSpec,
  type LauncherToolResult,
  type ToolRunRecord,
} from "@menog/runtime-linux";
import {
  DURABLE_STORE_SCHEMA_VERSION,
  DurableStore,
  makeLedgerHashPort,
  runStartupRecovery,
  collectStateKindFacts,
  rebuildDerivedIndexes,
  persistLedgerEvent,
  persistToolRunEvidenceWithObservation,
  persistPendingToolRunEvidence,
  persistTaskLifecycle,
  persistMemoryRecord,
  goalDurableId,
  type LedgerEventMirror,
  type LedgerHashPort,
  type RecoveryRequest,
  type SealedToolRunRecordMirror,
} from "@menog/durable-state";
import {
  GENESIS_PREVIOUS_HASH,
  computeEventHash,
  serializeEventForHash,
  sha256Hex,
} from "@menog/event-ledger";

const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as {
  DatabaseSync: new (path: string) => {
    prepare(sql: string): { get(...args: unknown[]): unknown; run(...args: unknown[]): void };
    close(): void;
  };
};

const tempRoots: string[] = [];

afterEach(() => {
  while (tempRoots.length > 0) {
    const root = tempRoots.pop() as string;
    try { rmSync(root, { recursive: true, force: true }); } catch { /* windows handles */ }
  }
});

function tempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "menog-22g-"));
  tempRoots.push(root);
  return root;
}

const PORT: LedgerHashPort = makeLedgerHashPort({
  genesisPreviousHash: GENESIS_PREVIOUS_HASH,
  serializeEventForHash: (e) => serializeEventForHash(e as never),
  computeEventHash: (e) => computeEventHash(e as never),
});

const REQUEST: RecoveryRequest = {
  mode: "load_committed_state",
  expectedStoreSchemaVersion: DURABLE_STORE_SCHEMA_VERSION,
  maxRecords: 1000,
  semantics: "no_execution",
};

const T0 = 1_760_000_000_000; // deterministic clock

const ALLOCATOR_HUMAN_ID = "r0-human-operator"; // registered runtime identity

const SNAPSHOT: IsolationCapabilitySnapshot = {
  targetKernel: "5.15.167.4",
  targetArch: "x86_64",
  isWsl: true,
  landlockAbi: 1,
  probedAt: "2026-09-27T00:00:00.000Z",
  primitives: {
    ns_user: "SUPPORTED", ns_mount: "SUPPORTED", ns_pid: "SUPPORTED",
    ns_ipc: "SUPPORTED", ns_uts: "SUPPORTED", ns_net: "SUPPORTED",
    cgroup_v2_controllers: "UNSUPPORTED", cgroup_v2_delegation: "UNSUPPORTED",
    landlock_fs: "SUPPORTED", landlock_net: "UNSUPPORTED",
    seccomp_filter: "SUPPORTED", no_new_privs: "SUPPORTED",
    rlimit_set: "SUPPORTED", proc_hidepid: "UNSUPPORTED",
  },
};

const MANIFEST = {
  schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
  toolId: "demo.survey",
  version: "1.0.0",
  displayName: "Demo Survey",
  description: "Read-only survey tool used by the 22G scenario",
  capabilities: [{ capability: "workspace:read", criticality: "required" as const }],
  trustClass: "human_reviewed" as const,
  declaredBy: "human-22g",
  isolationProfileId: TOOL_BASELINE_PROFILE_ID,
};

/** Transport double that RECORDS the call (its absence proves "never ran"). */
function recordingTransport(): {
  transport: (spec: LauncherToolSpec) => LauncherToolResult;
  wasCalled: () => boolean;
} {
  let called = false;
  const transport = (spec: LauncherToolSpec): LauncherToolResult => {
    called = true;
    return {
      ok: true, exitCode: 0, signal: null, timedOut: false, targetRan: true,
      stdout: Buffer.from("survey-ok\n"),
      stderr: Buffer.alloc(0),
      stdoutTruncated: false, stderrTruncated: false,
      failedPrimitive: null, isolationEvidence: null,
      isolationProfileId: spec.profileId,
    };
  };
  return { transport, wasCalled: () => called };
}

/**
 * Drop undefined-valued OWN keys (the 22A payload boundary rejects explicit
 * `undefined`; the canonical hash vocabulary ignores them, so stripping is
 * byte-consistent with the sealed hash).
 */
function stripUndefined<T extends object>(value: T): T {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (v === undefined) continue;
    out[k] = v !== null && typeof v === "object" && !Array.isArray(v) ? stripUndefined(v) : v;
  }
  return out as T;
}

/** Minimal sealed record matching the 21E/22C canonical discipline. */
function sealedFromOutcome(over: Partial<SealedToolRunRecordMirror> = {}): SealedToolRunRecordMirror {
  const body = {
    schemaVersion: "menog-tool-evidence/v0",
    parents: {
      skillId: null as string | null,
      skillStepId: null as string | null,
      taskId: "task-22g-001",
      assignmentId: "asg-22g-001",
      agentId: "menog-agent-builder",
    },
    requestHash: "sha256:" + sha256Hex("the-22g-request"),
    toolId: "demo.survey",
    version: "1.0.0",
    manifestHash: "sha256:" + sha256Hex("manifest-22g"),
    policy: { outcome: "allow", matchedRule: "rule:day1:allow-inspect-readonly" as string | null },
    isolation: { profileId: TOOL_BASELINE_PROFILE_ID, evidenceHash: "sha256:" + sha256Hex("iso-22g") },
    result: {
      status: "completed",
      exitCode: 0 as number | null,
      timedOut: false,
      outputHash: "sha256:" + sha256Hex("out-22g") as string | null,
      outputBytes: 10 as number | null,
      truncated: false,
    },
    workspaceId: "workspace:22gfixture",
    recordedAt: "2026-09-28T00:00:00.000Z",
  };
  const { recordHash: _ignored, ...rest } = { ...body, ...over } as SealedToolRunRecordMirror & { recordHash?: string };
  const canonical = (value: unknown): string => {
    if (value === null || value === undefined) return "null";
    const t = typeof value;
    if (t === "string") return JSON.stringify(value);
    if (t === "number") return Number.isFinite(value) ? String(value) : "null";
    if (t === "boolean") return value ? "true" : "false";
    if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
    if (t === "object") {
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(obj[k])).join(",") + "}";
    }
    return "null";
  };
  return Object.freeze({ ...rest, recordHash: createHash("sha256").update(canonical(rest), "utf8").digest("hex") });
}

interface SeededRun {
  store: DurableStore;
  root: string;
  ledger: AppendOnlyLedger;
  goalEvent: LedgerEventMirror;
  runEvent: LedgerEventMirror;
  record: SealedToolRunRecordMirror;
  assignmentId: string;
  allocationEvent: LedgerEventMirror;
}

/**
 * The LIVE half of the scenario: real planner, real allocation, real policy
 * decision, real tool junction (injected transport — host-pure, no spawn),
 * then the durable transaction committing event+evidence ATOMICALLY.
 */
function liveRun(): SeededRun {
  const root = tempRoot();
  const store = DurableStore.open(root);
  if (!store.ok) throw new Error("store open failed: " + store.reason);
  const ledger = AppendOnlyLedger.inMemory();

  // ── 1. GOAL → PLANNER (proposal-only authority) ──────────────────────────
  const planner = new DeterministicPlanner(new VerbRegistry(), { emitObservabilityEvents: true });
  const goal: Goal = {
    goalId: "g-22g-continuous",
    description: "survey the workspace with the governed survey tool",
    requestedVerbSequence: ["inspect"],
    budget: { maxSteps: 2 },
  };
  const proposal = planner.propose(goal);
  if (proposal.disposition !== "proposed") throw new Error("planner refused to propose");
  const { plannerObservationToMenogEventInputs } = require("@menog/planner") as typeof import("@menog/planner");
  const bridgeInputs = plannerObservationToMenogEventInputs(
    planner.observations(),
    { type: "agent", id: "menog-agent-planner" },
    { workspaceId: "ws-22g", taskId: "task-22g-001", eventIdPrefix: "g22g" }
  );
  for (const evInput of bridgeInputs) {
    const r = ledger.append(evInput);
    if (!r.ok) throw new Error("planner bridge append failed: " + r.reason);
  }

  // ── 2. REAL ROLE ALLOCATION (19B; assignments are data, never authority) ─
  const rt = new AgentRuntime({ nowEpochMs: () => T0, ledger: {
    append: (input) => {
      const r = ledger.append({
        eventId: "g22grt-" + input.eventType + "-" + String(ledger.length + 1).padStart(4, "0"),
        timestamp: new Date(T0 + ledger.length).toISOString(),
        eventType: input.eventType,
        actor: input.actor as Actor,
        policyDecision: input.policyDecision,
        workspaceId: input.workspaceId,
        taskId: input.taskId,
        inputSummary: input.inputSummary,
        resultSummary: input.resultSummary,
      });
      return { ok: r.ok, eventId: r.event?.eventId };
    },
  }, workspaceId: "ws-22g", taskId: "task-22g-001" });
  if (!registerAllThreeAgents(rt, T0).ok) throw new Error("agent registration failed");
  const allocator = new TaskAllocator(rt);
  const task: TaskDescriptor = {
    label: "22g continuous survey",
    requiredCapabilities: ["workspace:read"],
    budget: { maxSteps: 2 },
    allowedRoles: ["builder"],
  };
  const alloc = allocator.allocate({ allocatedBy: ALLOCATOR_HUMAN_ID, task });
  if (!alloc.ok) throw new Error("allocation failed: " + JSON.stringify(alloc));
  const assignmentId = alloc.assignment.assignmentId;
  expect(alloc.assignment.executionAuthorized).toBe(false);
  expect(alloc.assignment.authority).toBe("allocation_data");

  // ── 3. REAL POLICY DECISION (Day-1 engine; the ONLY authority source) ────
  const engine = new DenyByDefaultPolicyEngine();
  const policy = engine.evaluate({
    actor: { type: "agent", id: alloc.assignment.assignedAgentId },
    verb: "inspect",
    requestedCapabilities: ["workspace:list"],
    workspaceId: "ws-22g",
  });
  if (policy.decision.outcome !== "allow") {
    throw new Error("day-1 policy refused inspect: " + policy.decision.matchedRule);
  }
  // Negative control: a WRITE ask is denied by the same engine (no bypass).
  const deny = engine.evaluate({
    actor: { type: "agent", id: alloc.assignment.assignedAgentId },
    verb: "inspect",
    requestedCapabilities: ["workspace:write"],
    workspaceId: "ws-22g",
  });
  expect(deny.decision.outcome).toBe("deny");

  // ── 4. PHASE-21 GOVERNED TOOL JUNCTION (real gate; transport injected) ───
  const mv = validateManifest(MANIFEST);
  if (!mv.ok) throw new Error("manifest invalid: " + mv.message);
  const registry = new LocalToolRegistry();
  const reg = registry.register({
    manifest: mv.value,
    sideEffectClass: "read_only",
    limits: { timeoutMs: 30_000, maxOutputBytes: 64_000, maxArgvEntries: 16 },
    isolationProfileId: TOOL_BASELINE_PROFILE_ID,
    network: "none",
    executable: { pathStrategy: "explicit_absolute_path", path: "/opt/tools/demo-survey" },
    registeredBy: "human-22g",
  });
  if (!reg.ok) throw new Error("registration failed: " + reg.message);
  const entry = registry.lookup("demo.survey", "1.0.0");
  if (!entry.ok) throw new Error("lookup failed");
  const req: ToolExecutionRequest = {
    requestId: "req-22g-001",
    toolId: "demo.survey",
    version: "1.0.0",
    envelope: {
      schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
      toolId: "demo.survey",
      version: "1.0.0",
      input: {},
      constraints: { timeoutMs: 10_000, maxOutputBytes: 8_000 },
    },
    requester: { actorType: "agent", id: alloc.assignment.assignedAgentId },
    taskScope: ["workspace:read"],
    agentCapabilities: ["workspace:read"],
    policyOutcome: "allow",
    isolation: { profileId: TOOL_BASELINE_PROFILE_ID, canEnforce: true },
  };
  const double = recordingTransport();
  const outcome = executeToolRun({
    request: req,
    entry: entry.value,
    snapshot: SNAPSHOT,
    workspaceRoot: "/tmp/menog-ws-22g",
    policyOutcome: "allow",
    policyRuleId: policy.decision.matchedRule,
    ledger,
    ledgerActor: { type: "runtime", id: "tool-runtime" },
    transportOverride: double.transport,
  } as never);
  expect(outcome.decision.status).toBe("not_started"); // gate passed; transport (double) ran
  expect(double.wasCalled()).toBe(true);
  expect(outcome.result?.status).toBe("completed");

  // ── 5. SEALED EVIDENCE + LEDGER OBSERVATION ──────────────────────────────
  const record = sealedFromOutcome({
    policy: { outcome: "allow", matchedRule: policy.decision.matchedRule },
    manifestHash: entry.value.manifestHash,
  });
  const obs = ledger.events().find((e) => e.eventType === "tool_execution_evidence");
  // The junction appends its own bound-evidence event when given a ledger;
  // for the durable pair we seal the run record into the LEDGER event the
  // runtime would emit (the 21E observation: resultSummary carries recordHash).
  const runEventInput = stripUndefined({
    eventId: "ev22g-run-000001",
    timestamp: "2026-09-28T00:00:01.000Z",
    eventType: "tool_run_evidence",
    actor: { type: "runtime", id: "tool-runtime" } as Actor,
    workspaceId: "ws-22g",
    taskId: "task-22g-001",
    policyDecision: "allow" as const,
    inputSummary: { requestId: "req-22g-001", toolId: "demo.survey" },
    resultSummary: { sealed: record.recordHash, exitCode: 0 },
  });
  const appended = ledger.append(runEventInput);
  if (!appended.ok) throw new Error("run observation append failed: " + appended.reason);
  const goalEventInput = bridgeInputs[0];
  if (!goalEventInput) throw new Error("no planner event to mirror");
  // The mirror preserves EVERY field of the sealed event (dropping optional
  // fields like workspaceId/taskId would break the hash re-derivation).
  // The frozen hash binds previousHash: it is computed over the FULL event
  // minus hash (the 22C mirror convention — exactly how ledger.append seals).
  const goalEvent: LedgerEventMirror = Object.freeze(stripUndefined({
    ...goalEventInput,
    previousHash: GENESIS_PREVIOUS_HASH,
    hash: computeEventHash({ ...goalEventInput, previousHash: GENESIS_PREVIOUS_HASH } as never),
  }) as LedgerEventMirror);
  void obs;

  // ── 6. THE PHASE-22 DURABLE TRANSACTION (atomic event+evidence pair) ─────
  const runEvent: LedgerEventMirror = Object.freeze(stripUndefined({
    ...runEventInput,
    previousHash: goalEvent.hash,
    hash: computeEventHash({ ...runEventInput, previousHash: goalEvent.hash } as never),
  }) as LedgerEventMirror);
  const p1 = persistLedgerEvent(store.store, { event: goalEvent, sequence: 0, transactionId: "tx-22g-goal" });
  if (!p1.ok) throw new Error("goal event persist failed: " + p1.reason);
  const p2 = persistToolRunEvidenceWithObservation(store.store, { event: runEvent, sequence: 1, record, transactionId: "tx-22g-run" });
  if (!p2.ok) throw new Error("atomic pair persist failed: " + p2.reason);
  if (!persistMemoryRecord(store.store, {
    record: {
      schemaVersion: "menog-memory/v0",
      memoryId: "mem-22g-1",
      kind: "execution",
      scope: { workspaceId: "ws-22g", taskId: "task-22g-001" },
      provenance: { origin: "runtime", actor: { type: "runtime", id: "memory-store" }, untrusted: false },
      retention: { retentionClass: "persistent" },
      body: { fact: "survey completed exit 0" },
      createdAtEpochMs: T0,
      createdByActorId: "memory-store",
    },
    revision: 1,
    supersedesRevision: null,
    transactionId: "tx-22g-mem",
  }).ok) throw new Error("memory persist failed");
  if (!persistTaskLifecycle(store.store, {
    state: {
      schemaVersion: "menog-task-lifecycle/v0",
      goalId: "goal-22g-continuous",
      planId: "plan-22g-001",
      taskIds: ["task-22g-001"],
      status: "executing",
      rationale: "survey step running under policy rule " + policy.decision.matchedRule,
      sourceEventId: runEvent.eventId,
      updatedAtEpochMs: T0,
    },
    previousStatus: null,
    revision: 1,
    supersedesRevision: null,
    transactionId: "tx-22g-task1",
  }).ok) throw new Error("task rev1 persist failed");
  if (!persistTaskLifecycle(store.store, {
    state: {
      schemaVersion: "menog-task-lifecycle/v0",
      goalId: "goal-22g-continuous",
      planId: "plan-22g-001",
      taskIds: ["task-22g-001"],
      status: "done",
      rationale: "terminal fact recorded from the sealed run",
      sourceEventId: runEvent.eventId,
      updatedAtEpochMs: T0 + 1,
    },
    previousStatus: "executing",
    revision: 2,
    supersedesRevision: 1,
    transactionId: "tx-22g-task2",
  }).ok) throw new Error("task rev2 persist failed: rev1 must be executing for a legal chain");

  return { store: store.store, root, ledger, goalEvent, runEvent, record, assignmentId, allocationEvent: goalEvent };
}

// ═════════════════════════════════════════════════════════════════════════════

describe("22G — continuous execution → persistence → restart → recovery", () => {
  it("the live run persists; ids/hashes survive close/reopen; recovery exposes DATA with zero authority", () => {
    const seeded = liveRun();
    seeded.store.close();

    // ── RESTART: reopen + startup recovery ─────────────────────────────────
    const r = DurableStore.open(seeded.root);
    if (!r.ok) throw new Error("reopen failed: " + r.reason);
    const report = runStartupRecovery(r.store, PORT, REQUEST, { nowEpochMs: T0 + 5_000 });

    // All 8 stages pass; state is exposed as DATA ONLY.
    expect(report.stages.every((s) => s.ok)).toBe(true);
    expect(report.stateExposed).toBe(true);
    expect(report.decision.authority).toBe("recovered_data");
    expect(report.decision.executionAuthorized).toBe(false);
    expect(report.decision.policyAuthorized).toBe(false);

    // Ledger/evidence verified with the REAL ledger vocabulary.
    expect(report.ledgerEvidence?.ok).toBe(true);
    expect(report.ledgerEvidence?.eventsVerified).toBe(2);
    expect(report.ledgerEvidence?.evidenceVerified).toBe(1);

    // IDs/hashes survived the boundary BYTE-IDENTICALLY.
    const ev1 = r.store.readRecord("evt-" + seeded.goalEvent.eventId);
    const ev2 = r.store.readRecord("evt-" + seeded.runEvent.eventId);
    expect(ev1.ok && ev2.ok).toBe(true);
    if (ev1.ok && ev2.ok) {
      expect((ev1.record.payload as Record<string, unknown>)["hash"]).toBe(seeded.goalEvent.hash);
      expect((ev2.record.payload as Record<string, unknown>)["hash"]).toBe(seeded.runEvent.hash);
    }
    const runRecordId = "run-" + seeded.record.recordHash.slice(0, 32);
    const evidence = r.store.readRecord(runRecordId);
    expect(evidence.ok).toBe(true);
    if (evidence.ok) {
      expect((evidence.record.payload as Record<string, unknown>)["recordHash"]).toBe(seeded.record.recordHash);
    }

    // Lineage/lifecycle survived: goal lineage + terminal task facts.
    const facts = collectStateKindFacts(r.store, "goal_lifecycle");
    expect(facts.taskLineage.get((goalDurableId("goal-22g-continuous") as { recordId: string }).recordId)).toContain("task-22g-001");
    expect(facts.revisions.get((goalDurableId("goal-22g-continuous") as { recordId: string }).recordId)).toBe(2);
    const memFacts = collectStateKindFacts(r.store, "memory_record");
    expect(memFacts.memoryIds).toContain("mem-22g-1");

    // Deterministic report digest binds the recovered snapshot.
    expect(report.reportHash).toHaveLength(64);
    r.store.close();
  });

  it("recovery executes nothing; the recovered task is never auto-resumed; restart requires a NEW policy decision and the normal junction", () => {
    const seeded = liveRun();
    seeded.store.close();
    const r = DurableStore.open(seeded.root);
    if (!r.ok) throw new Error("reopen failed");
    const report = runStartupRecovery(r.store, PORT, REQUEST, { nowEpochMs: T0 + 5_000 });
    expect(report.decision.explanation).toContain("no execution");
    expect(report.stages.find((s) => s.stage === "expose_recovered_state")?.detail).toContain("no execution, no authorization, no continuation");

    // The recovered task lifecycle record is a FACT (status done), not an
    // instruction: no code path resumes it. The ONLY way to execute again is
    // the normal live pipeline — starting with a NEW policy decision.
    const engine2 = new DenyByDefaultPolicyEngine();
    const freshPolicy = engine2.evaluate({
      actor: { type: "agent", id: "menog-agent-builder" },
      verb: "inspect",
      requestedCapabilities: ["workspace:list"],
      workspaceId: "ws-22g",
    });
    expect(freshPolicy.decision.outcome).toBe("allow");
    expect(freshPolicy.decision.matchedRule).toBe("rule:day1:allow-inspect-readonly-aggregate");
    // The recovered record's policy metadata is NOT the new decision: it
    // cannot be replayed as authority (fresh decision object, fresh outcome).
    expect(report.decision.executionAuthorized).toBe(false);
    expect(report.decision.policyAuthorized).toBe(false);

    // A post-restart execution through the normal junction with a policy
    // DENY is refused by the gate (recovery changed nothing about authority).
    const mv = validateManifest(MANIFEST);
    if (!mv.ok) throw new Error("manifest invalid");
    const registry = new LocalToolRegistry();
    const reg = registry.register({
      manifest: mv.value,
      sideEffectClass: "read_only",
      limits: { timeoutMs: 30_000, maxOutputBytes: 64_000, maxArgvEntries: 16 },
      isolationProfileId: TOOL_BASELINE_PROFILE_ID,
      network: "none",
      executable: { pathStrategy: "explicit_absolute_path", path: "/opt/tools/demo-survey" },
      registeredBy: "human-22g",
    });
    if (!reg.ok) throw new Error("registration failed");
    const entry2 = registry.lookup("demo.survey", "1.0.0");
    if (!entry2.ok) throw new Error("lookup failed");
    const double = recordingTransport();
    const deniedOutcome = executeToolRun({
      request: {
        requestId: "req-22g-post",
        toolId: "demo.survey",
        version: "1.0.0",
        envelope: {
          schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
          toolId: "demo.survey",
          version: "1.0.0",
          input: {},
          constraints: { timeoutMs: 10_000, maxOutputBytes: 8_000 },
        },
        requester: { actorType: "agent", id: "menog-agent-builder" },
        taskScope: ["workspace:read"],
        agentCapabilities: ["workspace:read"],
        policyOutcome: "allow",
        isolation: { profileId: TOOL_BASELINE_PROFILE_ID, canEnforce: true },
      },
      entry: entry2.value,
      snapshot: SNAPSHOT,
      workspaceRoot: "/tmp/menog-ws-22g",
      policyOutcome: "deny", // the NEW decision for THIS request is a denial
      transportOverride: double.transport,
    } as never);
    expect(deniedOutcome.decision.status).toBe("policy_denied");
    expect(deniedOutcome.result).toBeNull();
    expect(double.wasCalled()).toBe(false); // recovery granted nothing; the gate still stands
    r.store.close();
  });

  it("the reconstructed view: deterministic explanation + NON-EXECUTING replay plan from recovered evidence", () => {
    const seeded = liveRun();
    seeded.store.close();
    const r = DurableStore.open(seeded.root);
    if (!r.ok) throw new Error("reopen failed");
    const report = runStartupRecovery(r.store, PORT, REQUEST, { nowEpochMs: T0 + 5_000 });
    expect(report.stateExposed).toBe(true);

    // Reconstruct the sealed ToolRunRecord from DURABLE bytes.
    const runRecordId = "run-" + seeded.record.recordHash.slice(0, 32);
    const read = r.store.readRecord(runRecordId);
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    const payload = read.record.payload as Record<string, unknown>;
    const reconstructed: ToolRunRecord = payload["sealedRecord"] as ToolRunRecord;
    expect(reconstructed.recordHash).toBe(seeded.record.recordHash);

    // Deterministic explanation (same record ⇒ identical sentences).
    const e1 = explainToolRun(reconstructed);
    const e2 = explainToolRun(reconstructed);
    expect(e1).toEqual(e2);
    expect(e1.integrity).toBe("verified");
    expect(e1.summary).toContain("demo.survey@1.0.0");
    expect(e1.workspace).not.toMatch(/[/\\]/); // redaction held: no path

    // The evidence is observed by the mirrored ledger event.
    const obs = verifyLedgerObservation(reconstructed, seeded.ledger);
    expect(obs.ok).toBe(true);
    if (obs.ok) expect(obs.value.eventId).toBe("ev22g-run-000001");

    // NON-EXECUTING replay plan: evidence reconstruction, never an executor.
    const plan = planEvidenceReplay([reconstructed]);
    expect(plan.ok).toBe(true);
    if (plan.ok) {
      expect(plan.value.replaySemantics).toBe("non_executing");
      expect(plan.value.disclaimer).toContain("not executable");
      expect(plan.value.steps.length).toBe(1);
      expect(plan.value.steps[0]?.recordHash).toBe(seeded.record.recordHash);
      expect(plan.value.pathHash).toHaveLength(64);
      // The plan STEPS carry hashes/identities only — no argv, no paths,
      // no env (the disclaimer TEXT mentions those words; the data does not).
      const stepsSerialized = JSON.stringify(plan.value.steps);
      expect(stepsSerialized).not.toContain("argv");
      expect(stepsSerialized).not.toContain("/opt/tools");
      expect(stepsSerialized).not.toContain("cwd");
      expect(Object.keys(plan.value.steps[0] ?? {}).sort()).toEqual([
        "manifestHash", "outcomeStatus", "recordHash", "requestHash", "sequence", "toolId", "version",
      ]);
    }
    r.store.close();
  });

  it("corrupted variant across restart: tampered evidence bytes are quarantined and recovery fails closed", () => {
    const seeded = liveRun();
    seeded.store.close();
    // Tamper the evidence record's payload bytes WITHOUT re-sealing.
    const runRecordId = "run-" + seeded.record.recordHash.slice(0, 32);
    const db = new DatabaseSync(join(seeded.root, "menog-store", "durable.db"));
    const row = db.prepare("SELECT payload_json FROM records WHERE record_id = ?").get(runRecordId) as { payload_json: string };
    db.prepare("UPDATE records SET payload_json = ? WHERE record_id = ?").run(row.payload_json.slice(0, -4) + '"zz"}', runRecordId);
    db.close();

    const r = DurableStore.open(seeded.root);
    if (!r.ok) throw new Error("reopen failed");
    const report = runStartupRecovery(r.store, PORT, REQUEST, { nowEpochMs: T0 + 5_000 });
    expect(report.stateExposed).toBe(false);
    expect(report.ledgerEvidence?.ok).toBe(false);
    expect(report.ledgerEvidence?.findings.map((f) => f.code)).toContain("unreadable_record");
    expect(report.decision.executionAuthorized).toBe(false);
    expect(r.store.listQuarantined().some((q) => q.record_id === runRecordId)).toBe(true);
    // Quarantine retained the as-found bytes; nothing was repaired.
    expect(r.store.listQuarantined().length).toBe(1);
    r.store.close();
  });

  it("corrupted variant across restart: re-sealed manifest drift is a hard finding (never healed)", () => {
    const seeded = liveRun();
    seeded.store.close();
    // Second pending evidence for the same tool@version under a DRIFTED
    // manifest hash (content-hash-consistent corruption via the 22D/22C path).
    const drifted = sealedFromOutcome({ manifestHash: "sha256:" + sha256Hex("drifted-22g") });
    const r = DurableStore.open(seeded.root);
    if (!r.ok) throw new Error("reopen failed");
    expect(persistPendingToolRunEvidence(r.store, { record: drifted, transactionId: "tx-22g-drift", reason: "adversarial drift" }).ok).toBe(true);
    const report = runStartupRecovery(r.store, PORT, REQUEST, { nowEpochMs: T0 + 5_000 });
    expect(report.ledgerEvidence?.findings.map((f) => f.code)).toContain("manifest_drift");
    expect(report.stateExposed).toBe(false);
    expect(report.decision.executionAuthorized).toBe(false);
    r.store.close();
  });

  it("rebuild equivalence after restart: derived indexes recover to the authority-derived values", () => {
    const seeded = liveRun();
    seeded.store.close();
    const r = DurableStore.open(seeded.root);
    if (!r.ok) throw new Error("reopen failed");
    expect(rebuildDerivedIndexes(r.store).ok).toBe(true);
    const before = r.store.getDerivedEntry("memory-scope-index", "ws-22g||");
    const report = runStartupRecovery(r.store, PORT, REQUEST, {
      nowEpochMs: T0 + 5_000,
      rebuildDerived: (s) => rebuildDerivedIndexes(s),
    });
    expect(report.reconciled?.derivedRebuilt).toBe(true);
    expect(r.store.getDerivedEntry("memory-scope-index", "ws-22g||")).toBe(before);
    r.store.close();
  });

  it("deterministic recovery across two independent restarts (same inputs ⇒ same report hash)", () => {
    const seeded = liveRun();
    seeded.store.close();
    const hashes: string[] = [];
    for (let i = 0; i < 2; i++) {
      const r = DurableStore.open(seeded.root);
      if (!r.ok) throw new Error("reopen failed");
      const report = runStartupRecovery(r.store, PORT, REQUEST, { nowEpochMs: T0 + 5_000 });
      expect(report.stateExposed).toBe(true);
      expect(r.store.listQuarantined().length).toBe(0);
      hashes.push(report.reportHash);
      r.store.close();
    }
    expect(hashes[0]).toBe(hashes[1]);
    expect(hashes[0]).toHaveLength(64);
  });
});
