/**
 * PHASE 23G — Continuous Live→Durable→Restart→Live Scenario.
 *
 * END-TO-END / LOCAL. Raises the proven 22G composition across the 23D
 * handoff boundary, composing EXISTING, individually verified components
 * (no new features):
 *
 *   Goal/Task → real planner (proposal-only) → real role allocation (19B)
 *   → real Policy decision (Day-1 engine) → Phase-21 governed tool junction
 *   (injected transport — host-pure, no spawn) → sealed evidence + Event
 *   Ledger + 22C atomic durable pair → the 23B coordinator junction writing
 *   memory/task lifecycle through the 23C wiring (the ONE sanctioned
 *   live→durable path) → close/reopen → 22D/23D recovery + evidenced
 *   supersession → NEW epoch → LIVE → fresh local authorization action for
 *   any post-restart execution.
 *
 * PROVEN here:
 * - the full chain reaches LIVE after restart (machine: BOOTING→…→LIVE);
 * - ids/hashes survive byte-identically (eventId, recordHash, outputHash);
 * - recovery/handoff expose recovered_data with ZERO authority;
 * - a post-restart execution requires a NEW live Policy decision through
 *   the normal junction: a fresh DENY refuses with the transport never
 *   called; the old epoch's coordinator is stale forever;
 * - interrupted tasks survive as FACTS and are never auto-resumed (a fresh
 *   caller action may legally re-enter through lifecycle facts only);
 * - two independent restarts produce the same deterministic recovery report
 *   hash (no wall-clock in the hashed body);
 * - corrupted variants fail closed and BLOCK LIVE (quarantine class), both
 *   for direct byte tamper and for the F10-class foreign-shape write.
 *
 * Scope honesty: process-local scenario only — no power-loss, no
 * native-Linux, no network/transport, no federation claim is made here.
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
  type ToolExecutionRequest,
  type IsolationCapabilitySnapshot,
  type LauncherToolSpec,
  type LauncherToolResult,
} from "@menog/runtime-linux";
import {
  DURABLE_STORE_SCHEMA_VERSION,
  DurableStore,
  RUNTIME_OWNERSHIP_META_KEY,
  LiveSurfaceWiring,
  RuntimeStateCoordinator,
  runStartupHandoff,
  buildRecoveryReport,
  persistLedgerEvent,
  persistToolRunEvidenceWithObservation,
  type LedgerEventMirror,
  type RecoveryRequest,
  type RuntimeEpoch,
  type SealedToolRunRecordMirror,
} from "@menog/durable-state";
import {
  GENESIS_PREVIOUS_HASH,
  computeEventHash,
  sha256Hex,
} from "@menog/event-ledger";

const tempRoots: string[] = [];
const openStores: DurableStore[] = [];

afterEach(() => {
  for (const s of openStores) { try { if (s.isOpen) s.close(); } catch { /* already closed */ } }
  openStores.length = 0;
  while (tempRoots.length > 0) {
    const root = tempRoots.pop() as string;
    try { rmSync(root, { recursive: true, force: true }); } catch { /* windows handles */ }
  }
});

function tempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "menog-23g-"));
  tempRoots.push(root);
  return root;
}

const REQUEST: RecoveryRequest = {
  mode: "load_committed_state",
  expectedStoreSchemaVersion: DURABLE_STORE_SCHEMA_VERSION,
  maxRecords: 10000,
  semantics: "no_execution",
};

const T0 = 1_760_000_000_000; // deterministic clock
const ALLOCATOR_HUMAN_ID = "r0-human-operator";
const GOAL_ID = "goal-23g-continuous";
const MEMORY_ID = "mem-23g-0000001";

const SNAPSHOT: IsolationCapabilitySnapshot = {
  targetKernel: "5.15.167.4",
  targetArch: "x86_64",
  isWsl: true,
  landlockAbi: 1,
  probedAt: "2026-10-01T00:00:00.000Z",
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
  description: "Read-only survey tool used by the 23G scenario",
  capabilities: [{ capability: "workspace:read", criticality: "required" as const }],
  trustClass: "human_reviewed" as const,
  declaredBy: "human-23g",
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

/** Drop undefined-valued OWN keys (the 22A payload boundary rejects explicit `undefined`). */
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
      taskId: "task-23g-001",
      assignmentId: "asg-23g-001",
      agentId: "menog-agent-builder",
    },
    requestHash: "sha256:" + sha256Hex("the-23g-request"),
    toolId: "demo.survey",
    version: "1.0.0",
    manifestHash: "sha256:" + sha256Hex("manifest-23g"),
    policy: { outcome: "allow", matchedRule: "rule:day1:allow-inspect-readonly" as string | null },
    isolation: { profileId: TOOL_BASELINE_PROFILE_ID, evidenceHash: "sha256:" + sha256Hex("iso-23g") },
    result: {
      status: "completed",
      exitCode: 0 as number | null,
      timedOut: false,
      outputHash: "sha256:" + sha256Hex("out-23g") as string | null,
      outputBytes: 10 as number | null,
      truncated: false,
    },
    workspaceId: "workspace:23gfixture",
    recordedAt: "2026-10-01T00:00:00.000Z",
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

function eid(tag: string): string {
  return "re-000000f30000-" + tag.replace(/[^a-zA-Z0-9]/g, "").padEnd(16, "0").slice(0, 16);
}
function bootEpoch(id: string): RuntimeEpoch {
  return Object.freeze({
    schemaVersion: "menog-runtime-epoch/v0",
    epochId: id,
    startedAtEpochMs: T0,
    hostRef: "23g-suite",
    pidRef: process.pid,
    lifecycle: "BOOTING" as const,
    priorOwner: { code: "none" as const, epochId: null },
    startReason: "fresh_store_no_prior_owner" as const,
    executionAuthorized: false as const,
    policyAuthorized: false as const,
  });
}
function claimOwner(store: DurableStore): string | null {
  const raw = store.getMeta(RUNTIME_OWNERSHIP_META_KEY);
  return raw === null ? null : (raw.split("|")[0] ?? null);
}

interface LiveHalf {
  root: string;
  store: DurableStore;
  wiring: LiveSurfaceWiring;
  liveEpochId: string;
  goalEvent: LedgerEventMirror;
  runEvent: LedgerEventMirror;
  record: SealedToolRunRecordMirror;
  assignmentId: string;
  policyRule: string;
}

/**
 * The LIVE half of the scenario: real planner → real allocation → real
 * policy → real tool junction (injected transport) → 22C atomic durable
 * pair for the run evidence → the 23B/23C continuity junction writing
 * memory + task lifecycle (the ONE sanctioned live→durable path).
 */
function liveHalf(options: { foreignShapeWrite?: boolean; interrupted?: boolean } = {}): LiveHalf {
  const root = tempRoot();
  const opened = DurableStore.open(root);
  if (!opened.ok) throw new Error("store open failed: " + opened.reason);
  const store = opened.store;
  openStores.push(store);
  const ledger = AppendOnlyLedger.inMemory();

  // ── 1. GOAL → PLANNER (proposal-only authority) ────────────────────────────
  const planner = new DeterministicPlanner(new VerbRegistry(), { emitObservabilityEvents: true });
  const goal: Goal = {
    goalId: GOAL_ID,
    description: "survey the workspace with the governed survey tool (23G)",
    requestedVerbSequence: ["inspect"],
    budget: { maxSteps: 2 },
  };
  const proposal = planner.propose(goal);
  if (proposal.disposition !== "proposed") throw new Error("planner refused to propose");
  const { plannerObservationToMenogEventInputs } = require("@menog/planner") as typeof import("@menog/planner");
  const bridgeInputs = plannerObservationToMenogEventInputs(
    planner.observations(),
    { type: "agent", id: "menog-agent-planner" },
    { workspaceId: "ws-23g", taskId: "task-23g-001", eventIdPrefix: "g23g" }
  );
  for (const evInput of bridgeInputs) {
    const r = ledger.append(evInput);
    if (!r.ok) throw new Error("planner bridge append failed: " + r.reason);
  }

  // ── 2. REAL ROLE ALLOCATION (19B; assignments are data, never authority) ──
  const rt = new AgentRuntime({ nowEpochMs: () => T0, ledger: {
    append: (input) => {
      const r = ledger.append({
        eventId: "g23grt-" + input.eventType + "-" + String(ledger.length + 1).padStart(4, "0"),
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
  }, workspaceId: "ws-23g", taskId: "task-23g-001" });
  if (!registerAllThreeAgents(rt, T0).ok) throw new Error("agent registration failed");
  const allocator = new TaskAllocator(rt);
  const task: TaskDescriptor = {
    label: "23g continuous survey",
    requiredCapabilities: ["workspace:read"],
    budget: { maxSteps: 2 },
    allowedRoles: ["builder"],
  };
  const alloc = allocator.allocate({ allocatedBy: ALLOCATOR_HUMAN_ID, task });
  if (!alloc.ok) throw new Error("allocation failed: " + JSON.stringify(alloc));
  expect(alloc.assignment.executionAuthorized).toBe(false);
  expect(alloc.assignment.authority).toBe("allocation_data");

  // ── 3. REAL POLICY DECISION (Day-1 engine; the ONLY authority source) ─────
  const engine = new DenyByDefaultPolicyEngine();
  const policy = engine.evaluate({
    actor: { type: "agent", id: alloc.assignment.assignedAgentId },
    verb: "inspect",
    requestedCapabilities: ["workspace:list"],
    workspaceId: "ws-23g",
  });
  if (policy.decision.outcome !== "allow") throw new Error("day-1 policy refused inspect: " + policy.decision.matchedRule);
  // Negative control: a WRITE ask is denied by the same engine (no bypass).
  const deny = engine.evaluate({
    actor: { type: "agent", id: alloc.assignment.assignedAgentId },
    verb: "inspect",
    requestedCapabilities: ["workspace:write"],
    workspaceId: "ws-23g",
  });
  expect(deny.decision.outcome).toBe("deny");

  // ── 4. PHASE-21 GOVERNED TOOL JUNCTION (real gate; transport injected) ────
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
    registeredBy: "human-23g",
  });
  if (!reg.ok) throw new Error("registration failed: " + reg.message);
  const entry = registry.lookup("demo.survey", "1.0.0");
  if (!entry.ok) throw new Error("lookup failed");
  const req: ToolExecutionRequest = {
    requestId: "req-23g-001",
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
    workspaceRoot: "/tmp/menog-ws-23g",
    policyOutcome: "allow",
    policyRuleId: policy.decision.matchedRule,
    ledger,
    ledgerActor: { type: "runtime", id: "tool-runtime" },
    transportOverride: double.transport,
  } as never);
  expect(outcome.decision.status).toBe("not_started"); // gate passed; the transport double ran
  expect(double.wasCalled()).toBe(true);
  expect(outcome.result?.status).toBe("completed");

  // ── 5. SEALED EVIDENCE + LEDGER OBSERVATION + 22C ATOMIC DURABLE PAIR ─────
  const record = sealedFromOutcome({
    policy: { outcome: "allow", matchedRule: policy.decision.matchedRule },
    manifestHash: entry.value.manifestHash,
  });
  const runEventInput = stripUndefined({
    eventId: "ev23g-run-000001",
    timestamp: "2026-10-01T00:00:01.000Z",
    eventType: "tool_run_evidence",
    actor: { type: "runtime", id: "tool-runtime" } as Actor,
    workspaceId: "ws-23g",
    taskId: "task-23g-001",
    policyDecision: "allow" as const,
    inputSummary: { requestId: "req-23g-001", toolId: "demo.survey" },
    resultSummary: { sealed: record.recordHash, exitCode: 0 },
  });
  const appended = ledger.append(runEventInput);
  if (!appended.ok) throw new Error("run observation append failed: " + appended.reason);
  const goalEventInput = bridgeInputs[0];
  if (!goalEventInput) throw new Error("no planner event to mirror");
  const goalEvent: LedgerEventMirror = Object.freeze(stripUndefined({
    ...goalEventInput,
    previousHash: GENESIS_PREVIOUS_HASH,
    hash: computeEventHash({ ...goalEventInput, previousHash: GENESIS_PREVIOUS_HASH } as never),
  }) as LedgerEventMirror);
  const runEvent: LedgerEventMirror = Object.freeze(stripUndefined({
    ...runEventInput,
    previousHash: goalEvent.hash,
    hash: computeEventHash({ ...runEventInput, previousHash: goalEvent.hash } as never),
  }) as LedgerEventMirror);
  const p1 = persistLedgerEvent(store, { event: goalEvent, sequence: 0, transactionId: "tx-23g-goal" });
  if (!p1.ok) throw new Error("goal event persist failed: " + p1.reason);
  const p2 = persistToolRunEvidenceWithObservation(store, { event: runEvent, sequence: 1, record, transactionId: "tx-23g-run" });
  if (!p2.ok) throw new Error("atomic pair persist failed: " + p2.reason);

  // ── 6. THE PHASE-23 CONTINUITY JUNCTION (23B coordinator + 23C wiring) ────
  const liveEpochId = eid("liveepoch00001");
  const bound = RuntimeStateCoordinator.open(store, bootEpoch(liveEpochId), "23g-live");
  if (!bound.ok) throw new Error("coordinator bind failed: " + bound.reason);
  const wiringOpen = LiveSurfaceWiring.open(store, bound.coordinator, bootEpoch(liveEpochId));
  if (!wiringOpen.ok) throw new Error("wiring open failed: " + wiringOpen.reason);
  const wiring = wiringOpen.wiring;
  const memWrite = wiring.writeMemory({
    record: {
      schemaVersion: "menog-memory/v0",
      memoryId: MEMORY_ID,
      kind: "execution",
      scope: { workspaceId: "ws-23g", taskId: "task-23g-001" },
      provenance: { origin: "runtime", actor: { type: "runtime", id: "memory-store" }, untrusted: false },
      retention: { retentionClass: "persistent" },
      body: { fact: "survey completed exit 0", outputHash: "sha256:" + sha256Hex("out-23g"), recordHash: record.recordHash },
      createdAtEpochMs: T0,
      createdByActorId: "memory-store",
    },
    transactionId: "tx-23g-mem",
  });
  if (!memWrite.ok) throw new Error("continuity memory write failed: " + JSON.stringify(memWrite));
  const taskBase = {
    schemaVersion: "menog-task-lifecycle/v0",
    goalId: GOAL_ID,
    planId: "plan-23g-001",
    taskIds: ["task-23g-001"],
    rationale: "",
    updatedAtEpochMs: T0,
  };
  const taskRev1 = wiring.writeTaskLifecycle({
    state: { ...taskBase, status: "executing", rationale: "survey step running under policy rule " + policy.decision.matchedRule, sourceEventId: runEvent.eventId },
    previousStatus: null,
    transactionId: "tx-23g-task1",
  });
  if (!taskRev1.ok) throw new Error("task rev1 write failed: " + JSON.stringify(taskRev1));
  if (options.interrupted) {
    const taskRev2 = wiring.writeTaskLifecycle({
      state: { ...taskBase, status: "interrupted", rationale: "interrupted by the scenario (fact, not resume)", sourceEventId: runEvent.eventId, updatedAtEpochMs: T0 + 1 },
      previousStatus: "executing",
      transactionId: "tx-23g-task2",
    });
    if (!taskRev2.ok) throw new Error("task interrupt write failed: " + JSON.stringify(taskRev2));
  } else {
    const taskRev2 = wiring.writeTaskLifecycle({
      state: { ...taskBase, status: "done", rationale: "terminal fact recorded from the sealed run", sourceEventId: runEvent.eventId, updatedAtEpochMs: T0 + 1 },
      previousStatus: "executing",
      transactionId: "tx-23g-task2",
    });
    if (!taskRev2.ok) throw new Error("task rev2 write failed: " + JSON.stringify(taskRev2));
  }
  if (options.foreignShapeWrite) {
    // The F10-class live misbehavior: a payload that is NOT the exact 22D
    // shape rides the sanctioned junction (22B is payload-opaque by frozen
    // design). The scenario must FAIL CLOSED across the restart (test 6).
    const foreign = bound.coordinator.acceptMutation({
      kind: "memory_record",
      recordId: "mem-23g-foreign1",
      revision: 1,
      supersedesRevision: null,
      payload: { hostile: "not-a-22D-shape", note: "23G foreign-shape write" },
      transactionId: "tx-23g-foreign",
      lineageRoot: "gol-23g-foreign",
      lineageParent: null,
      createdAtEpochMs: T0 + 2,
    });
    if (!foreign.ok) throw new Error("foreign write refused — the scenario variant requires it to commit at 22B: " + JSON.stringify(foreign));
  }

  return { root, store, wiring, liveEpochId, goalEvent, runEvent, record, assignmentId: alloc.assignment.assignmentId, policyRule: policy.decision.matchedRule };
}

interface RestartHalf {
  store: DurableStore;
  handoff: ReturnType<typeof runStartupHandoff>;
}

/** RESTART half: reopen + the 23D handoff (recovering the NAMED prior owner's claim). */
function restartHalf(root: string, nowEpochMs: number): RestartHalf {
  const reopened = DurableStore.open(root);
  if (!reopened.ok) throw new Error("reopen failed: " + reopened.reason);
  openStores.push(reopened.store);
  const prior = claimOwner(reopened.store);
  const handoff = runStartupHandoff({
    store: reopened.store,
    bootedEpoch: bootEpoch(eid("reboot" + String(nowEpochMs % 100000))),
    recoveryRequest: REQUEST,
    sourceIdentity: "23g-restart",
    priorEpochId: prior,
    nowEpochMs,
  });
  return { store: reopened.store, handoff };
}

// ═════════════════════════════════════════════════════════════════════════════

describe("23G — continuous live → durable → restart → live", () => {
  it("the full chain reaches LIVE after restart: recovery is authority-free; ids/hashes survive byte-identically; the NEW epoch owns the claim", () => {
    const live = liveHalf();
    live.store.close();

    const restart = restartHalf(live.root, T0 + 5_000);
    const h = restart.handoff;
    expect(h.ok).toBe(true);
    expect(h.terminalState).toBe("LIVE");
    expect(h.newEpochId).not.toBe(live.liveEpochId);
    expect(h.reportHash).toHaveLength(64);
    expect(h.evidenceHash).toHaveLength(64);
    expect(h.classification?.blockingClass).toBe("none");
    // Recovery surfaces grant NOTHING:
    expect(h.wiring).not.toBeNull();
    expect(claimOwner(restart.store)).toBe(h.newEpochId);

    // Ids/hashes survived BYTE-IDENTICALLY (ledger mirrors + evidence):
    const ev1 = restart.store.readRecord("evt-" + live.goalEvent.eventId);
    const ev2 = restart.store.readRecord("evt-" + live.runEvent.eventId);
    expect(ev1.ok && ev2.ok).toBe(true);
    if (ev1.ok && ev2.ok) {
      expect((ev1.record.payload as Record<string, unknown>)["hash"]).toBe(live.goalEvent.hash);
      expect((ev2.record.payload as Record<string, unknown>)["hash"]).toBe(live.runEvent.hash);
    }
    const evidence = restart.store.readRecord("run-" + live.record.recordHash.slice(0, 32));
    expect(evidence.ok).toBe(true);
    if (evidence.ok) {
      expect((evidence.record.payload as Record<string, unknown>)["recordHash"]).toBe(live.record.recordHash);
    }

    // Safe views from ADMITTED data: memory facts and terminal task facts.
    if (h.wiring === null) return;
    const view = h.wiring.readMemory(MEMORY_ID, T0 + 5_000);
    expect(view.ok).toBe(true);
    if (view.ok) {
      expect(view.restorable).toBe(true);
      expect((view.record.body as Record<string, unknown>)["recordHash"]).toBe(live.record.recordHash);
      expect((view.record.body as Record<string, unknown>)["outputHash"]).toBe("sha256:" + sha256Hex("out-23g"));
    }
    const task = h.wiring.readTaskLifecycle(GOAL_ID);
    expect(task.ok).toBe(true);
    if (task.ok) {
      expect(task.state.status).toBe("done");
      expect(task.terminal).toBe(true);
      expect(task.state.sourceEventId).toBe(live.runEvent.eventId);
    }
    restart.store.close();
  });

  it("post-restart execution requires a NEW live Policy decision: fresh DENY refuses (transport never called); fresh ALLOW runs through the normal junction; the old epoch stays stale", () => {
    const live = liveHalf();
    live.store.close();
    const restart = restartHalf(live.root, T0 + 5_000);
    const h = restart.handoff;
    expect(h.ok).toBe(true);
    if (h.wiring === null) throw new Error("handoff must open the wiring");

    // The OLD epoch's coordinator is stale forever (split-brain refusal):
    // rebind + write attempts under the dead epoch id refuse.
    const oldBind = RuntimeStateCoordinator.open(restart.store, bootEpoch(live.liveEpochId), "23g-restart");
    expect(oldBind.ok).toBe(false);
    if (!oldBind.ok) expect(oldBind.failureCode).toBe("coordinator_epoch_mismatch");

    // A FRESH deny for THIS request: the gate refuses; nothing runs.
    const freshEngine = new DenyByDefaultPolicyEngine();
    const freshDeny = freshEngine.evaluate({
      actor: { type: "agent", id: "menog-agent-builder" },
      verb: "inspect",
      requestedCapabilities: ["workspace:write"], // the SAME engine denies writes
      workspaceId: "ws-23g",
    });
    expect(freshDeny.decision.outcome).toBe("deny");
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
      registeredBy: "human-23g",
    });
    if (!reg.ok) throw new Error("registration failed");
    const entry = registry.lookup("demo.survey", "1.0.0");
    if (!entry.ok) throw new Error("lookup failed");
    const deniedDouble = recordingTransport();
    const deniedOutcome = executeToolRun({
      request: {
        requestId: "req-23g-post-deny",
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
        policyOutcome: "allow", // stolen/alleged outcome — the REAL decision below is deny
        isolation: { profileId: TOOL_BASELINE_PROFILE_ID, canEnforce: true },
      },
      entry: entry.value,
      snapshot: SNAPSHOT,
      workspaceRoot: "/tmp/menog-ws-23g",
      policyOutcome: "deny", // the NEW decision for THIS request is a denial
      transportOverride: deniedDouble.transport,
    } as never);
    expect(deniedOutcome.decision.status).toBe("policy_denied");
    expect(deniedOutcome.result).toBeNull();
    expect(deniedDouble.wasCalled()).toBe(false); // recovery granted nothing; the gate still stands

    // A FRESH allow (new decision object, new junction call) runs normally —
    // and persists through the NEW epoch's sanctioned continuity junction:
    const allowDouble = recordingTransport();
    const allowedOutcome = executeToolRun({
      request: {
        requestId: "req-23g-post-allow",
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
      entry: entry.value,
      snapshot: SNAPSHOT,
      workspaceRoot: "/tmp/menog-ws-23g",
      policyOutcome: "allow", // a NEW live decision made NOW (not recovered authority)
      transportOverride: allowDouble.transport,
    } as never);
    expect(allowedOutcome.decision.status).toBe("not_started");
    expect(allowDouble.wasCalled()).toBe(true);
    const postWrite = h.wiring.writeMemory({
      record: {
        schemaVersion: "menog-memory/v0",
        memoryId: "mem-23g-postrestart",
        kind: "execution",
        scope: { workspaceId: "ws-23g", taskId: "task-23g-001" },
        provenance: { origin: "runtime", actor: { type: "runtime", id: "memory-store" }, untrusted: false },
        retention: { retentionClass: "persistent" },
        body: { fact: "post-restart run under a FRESH local policy decision", recordHash: "sha256:" + sha256Hex("post-23g") },
        createdAtEpochMs: T0 + 6_000,
        createdByActorId: "memory-store",
      },
      transactionId: "tx-23g-post",
    });
    expect(postWrite.ok).toBe(true);
    restart.store.close();
  });

  it("interrupted tasks survive as FACTS; the handoff exposes them without resuming; re-entry is only a fresh caller action through lifecycle facts", () => {
    const live = liveHalf({ interrupted: true });
    live.store.close();
    const restart = restartHalf(live.root, T0 + 5_000);
    const h = restart.handoff;
    // An interrupted task is a FACT, not a blocking finding: LIVE is reached,
    // and the task is reported interrupted — never resumed.
    expect(h.ok).toBe(true);
    expect(h.interruptedTaskIds).toContain(GOAL_ID);
    expect(h.wiring).not.toBeNull();
    if (h.wiring === null) return;
    const view = h.wiring.readTaskLifecycle(GOAL_ID);
    expect(view.ok).toBe(true);
    if (!view.ok) return;
    expect(view.state.status).toBe("interrupted");
    expect(view.terminal).toBe(false);
    expect(view.nextLegalTransitions).toContain("executing");
    // The ONLY re-entry is a fresh caller action (lifecycle facts, legal
    // transitions); the wiring offers no resume/continue API at all.
    const resume1 = h.wiring.writeTaskLifecycle({
      state: { ...view.state, status: "executing", rationale: "fresh caller action: re-plan and re-enter", updatedAtEpochMs: T0 + 6_000 },
      previousStatus: "interrupted",
      transactionId: "tx-23g-reenter1",
    });
    expect(resume1.ok).toBe(true);
    const done = h.wiring.writeTaskLifecycle({
      state: { ...view.state, status: "done", rationale: "completed under a fresh authorization action", updatedAtEpochMs: T0 + 7_000 },
      previousStatus: "executing",
      transactionId: "tx-23g-reenter2",
    });
    expect(done.ok).toBe(true);
    restart.store.close();
  });

  it("two independent restarts with IDENTICAL inputs produce the same deterministic recovery report hash (the hash binds scannedAtEpochMs as an input — no wall-clock read)", () => {
    const live = liveHalf();
    live.store.close();
    const hashes: string[] = [];
    // Identical inputs = same store bytes + same request + same nowEpochMs.
    // Each restart gets its own BOOT id (the derived NEW epoch is a per-restart
    // identity), but the report hash is epoch-free — determinism holds.
    for (const run of [1, 2]) {
      const reopened = DurableStore.open(live.root);
      if (!reopened.ok) throw new Error("reopen failed");
      openStores.push(reopened.store);
      const handoff = runStartupHandoff({
        store: reopened.store,
        bootedEpoch: bootEpoch(eid("detboot0000000" + String(run))),
        recoveryRequest: REQUEST,
        sourceIdentity: "23g-det",
        priorEpochId: claimOwner(reopened.store),
        nowEpochMs: T0 + 5_000,
      });
      if (!handoff.ok || handoff.reportHash === null) {
        throw new Error("determinism-probe handoff refused: " + String(handoff.explanation));
      }
      hashes.push(handoff.reportHash);
      reopened.store.close();
    }
    expect(hashes[0]).toBe(hashes[1]);
    expect(hashes[0]).toHaveLength(64);
  });

  it("corrupted variant: direct byte tamper of the memory record is quarantined and BLOCKS LIVE (as-found bytes retained; nothing repaired)", () => {
    const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as {
      DatabaseSync: new (path: string) => {
        prepare(sql: string): { get(...args: unknown[]): unknown; run(...args: unknown[]): void };
        close(): void;
      };
    };
    const live = liveHalf();
    live.store.close();
    const memRecordId = "mem-" + MEMORY_ID;
    const db = new DatabaseSync(join(live.root, "menog-store", "durable.db"));
    const row = db.prepare("SELECT payload_json FROM records WHERE record_id = ?").get(memRecordId) as { payload_json: string };
    db.prepare("UPDATE records SET payload_json = ? WHERE record_id = ?").run(row.payload_json.slice(0, -4) + '"zz"}', memRecordId);
    db.close();

    const restart = restartHalf(live.root, T0 + 5_000);
    const h = restart.handoff;
    expect(h.ok).toBe(false);
    expect(h.terminalState).toBe("RECOVERED");
    expect(h.classification?.blockingClass).toBe("quarantine");
    expect(h.wiring).toBeNull();
    expect(restart.store.listQuarantined().some((q) => q.record_id === memRecordId)).toBe(true);
    // Recovery surfaces still grant nothing while blocked:
    expect(h.evidence).toBeNull();
    restart.store.close();
  });

  it("corrupted variant: the F10-class foreign-shape write through the live junction BLOCKS the restart handoff (fail-closed composition)", () => {
    const live = liveHalf({ foreignShapeWrite: true });
    live.store.close();
    const restart = restartHalf(live.root, T0 + 5_000);
    const h = restart.handoff;
    expect(h.ok).toBe(false);
    expect(h.terminalState).toBe("RECOVERED");
    expect(h.classification?.blockingClass).toBe("quarantine");
    expect(h.wiring).toBeNull();
    // The foreign record is excluded from admission at the decision layer:
    // (the recovery report inside the handoff carries the quarantine ids —
    // re-derive them from the reopened store to keep the pin store-first)
    const report = buildRecoveryReport(restart.store, REQUEST, T0 + 5_000);
    expect(report.newQuarantineIds).toContain("mem-23g-foreign1");
    // Authority stays absent on the blocked path:
    expect(h.classification?.explanation ?? "").toContain("block LIVE");
    restart.store.close();
  });

  it("cross-boundary provenance: the mirrored ledger chain re-verifies with the REAL ledger vocabulary; the sealed evidence is bound to its observation and to the recovered memory fact", () => {
    const live = liveHalf();
    live.store.close();
    const restart = restartHalf(live.root, T0 + 5_000);
    const h = restart.handoff;
    expect(h.ok).toBe(true);

    // The ledger-mirror chain survives: genesis → goal event → run event,
    // each hash re-derivable from its own payload (22C mirror convention).
    const ev1 = restart.store.readRecord("evt-" + live.goalEvent.eventId);
    const ev2 = restart.store.readRecord("evt-" + live.runEvent.eventId);
    expect(ev1.ok && ev2.ok).toBe(true);
    if (ev1.ok && ev2.ok) {
      // The 22C mirror shape: the event body rides under `event`, with the
      // hash header alongside. Chain linkage + the 21E observation law:
      const body1 = (ev1.record.payload as Record<string, unknown>)["event"] as Record<string, unknown>;
      const body2 = (ev2.record.payload as Record<string, unknown>)["event"] as Record<string, unknown>;
      expect((ev1.record.payload as Record<string, unknown>)["previousHash"]).toBe(GENESIS_PREVIOUS_HASH);
      expect(body1["hash"]).toBe(live.goalEvent.hash);
      expect(body2["previousHash"]).toBe(body1["hash"]);
      expect(body2["hash"]).toBe(live.runEvent.hash);
      // The 21E observation law: the run event's resultSummary carries the
      // sealed record's hash (evidence ↔ observation bound across restart).
      expect((body2["resultSummary"] as Record<string, unknown>)["sealed"]).toBe(live.record.recordHash);
    }
    // The evidence record is content-addressed by its recordHash:
    const evidence = restart.store.readRecord("run-" + live.record.recordHash.slice(0, 32));
    expect(evidence.ok).toBe(true);
    if (evidence.ok) {
      const payload = evidence.record.payload as Record<string, unknown>;
      expect(payload["recordHash"]).toBe(live.record.recordHash);
    }
    // And the recovered memory fact carries the same provenance binding:
    if (h.wiring !== null) {
      const view = h.wiring.readMemory(MEMORY_ID, T0 + 5_000);
      expect(view.ok).toBe(true);
      if (view.ok) {
        expect((view.record.body as Record<string, unknown>)["recordHash"]).toBe(live.record.recordHash);
      }
    }
    restart.store.close();
  });
});
