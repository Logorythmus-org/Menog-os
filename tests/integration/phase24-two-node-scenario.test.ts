/**
 * PHASE 24H — Two-Node Local Federation Continuous Scenario
 * (IN-PROCESS FIXTURES ONLY / NO LAN·INTERNET·DISCOVERY / FAIL CLOSED).
 *
 * Two isolated local runtime fixtures A/B with distinct crypto identities
 * and epochs. A signs a proposal → a BOUNDED in-flight transport (no
 * sockets) → B verifies identity/admission/replay/schema (the 24D
 * pipeline) → untrusted local candidate → fresh LOCAL 19B allocation →
 * fresh LOCAL Day-1 Policy → if allowed: Phase-20 isolation → Phase-21
 * governed tool runtime (injected transport double) → evidence/ledger →
 * 22C atomic durable pair → 23B/23C continuity on B → cross-node
 * provenance anchored on B (24F; no consensus, no global order) →
 * RESTART B → NEW B epoch → facts recovered WITHOUT authority → the OLD
 * message replay is DENIED (durable receipt guard) → a NEW A proposal
 * requires fresh local authority again.
 *
 * Negative controls: B Policy denial · unknown A · quarantined A · stale A
 * epoch · tamper · no auto-resume · no old Policy reuse · no capability
 * union · no direct remote execution.
 *
 * Provenance claim honesty: every "provenance" here is B-side LOCAL
 * evidence binding what B observed and judged, ordered only by B's own
 * durable commit sequence — no total order, no consensus, no clock
 * agreement is claimed or implemented.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { AppendOnlyLedger, GENESIS_PREVIOUS_HASH, computeEventHash, sha256Hex } from "@menog/event-ledger";
import { VerbRegistry } from "@menog/verbs";
import type { Actor, Goal } from "@menog/core";
import { DeterministicPlanner } from "@menog/planner";
import { AgentRuntime, TaskAllocator, registerAllThreeAgents, type TaskDescriptor } from "@menog/agents";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
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
  DurableStore,
  DURABLE_STORE_SCHEMA_VERSION,
  RUNTIME_OWNERSHIP_META_KEY,
  RuntimeStateCoordinator,
  PeerRegistry,
  FederationBus,
  ProposalLedger,
  ProvenanceLedger,
  LiveSurfaceWiring,
  runStartupHandoff,
  persistLedgerEvent,
  persistToolRunEvidenceWithObservation,
  generateLocalSigningIdentity,
  signFederationMessage,
  makeIdentitySignatureVerifier,
  makeFederationMessageId,
  makeRuntimeEpochId,
  canonicalHash,
  requireFreshLocalAuthorization,
  deriveLocalTaskCandidate,
  FEDERATION_MAX_BATCH,
  type RuntimeEpoch,
  type FederationMessageBody,
  type FederationTaskProposalPayload,
  type FederationProvenanceAnchor,
  type LedgerEventMirror,
  type RecoveryRequest,
  type SealedToolRunRecordMirror,
} from "@menog/durable-state";

// ── fixtures ─────────────────────────────────────────────────────────────────

const NOW = 1_700_000_000_000;
/** The post-restart clock: > the 300 s fresh-action window after NOW. */
const T1 = NOW + 400_000;

const roots: string[] = [];
const openStores: DurableStore[] = [];
const openCoords: RuntimeStateCoordinator[] = [];
afterEach(() => {
  for (const c of openCoords) {
    try { c.close(); } catch { /* already closed */ }
  }
  for (const s of openStores) {
    try { if (s.isOpen) s.close(); } catch { /* windows handles */ }
  }
  openCoords.length = 0;
  openStores.length = 0;
  for (const r of roots) {
    try { rmSync(r, { recursive: true, force: true }); } catch { /* windows handles */ }
  }
  roots.length = 0;
});

const EPOCH_A = makeRuntimeEpochId(NOW, "epochA000000001");
const EPOCH_B1 = makeRuntimeEpochId(NOW, "epochB000000001");
const EPOCH_B2 = makeRuntimeEpochId(T1, "epochB000000002");

function epochOf(id: string, startedAt: number = NOW): RuntimeEpoch {
  return Object.freeze({
    schemaVersion: "menog-runtime-epoch/v0",
    epochId: id,
    startedAtEpochMs: startedAt,
    hostRef: "wsl2-target-of-record",
    pidRef: 4242,
    lifecycle: "BOOTING",
    priorOwner: { code: "none" as const, epochId: null },
    startReason: "fresh_store_no_prior_owner",
    executionAuthorized: false as const,
    policyAuthorized: false as const,
  });
}

const REQUEST: RecoveryRequest = {
  mode: "load_committed_state",
  expectedStoreSchemaVersion: DURABLE_STORE_SCHEMA_VERSION,
  maxRecords: 10000,
  semantics: "no_execution",
};

function claimOwner(store: DurableStore): string | null {
  const raw = store.getMeta(RUNTIME_OWNERSHIP_META_KEY);
  return raw === null ? null : (raw.split("|")[0] ?? null);
}

let txnCounter = 0;
function txn(tag: string): string {
  txnCounter += 1;
  return "t24h-" + tag + "-" + String(txnCounter).padStart(6, "0");
}

const ROOT_LINEAGE = "two-node-root-24h";
const GOAL_ID = "goal-24h-twonode";
const MEMORY_ID = "mem-24h-0000001";

// ── Phase-20/21 fixtures (the 23G pattern; transport double, no spawn) ──────

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
  description: "Read-only survey tool used by the 24H two-node scenario",
  capabilities: [{ capability: "workspace:read", criticality: "required" as const }],
  trustClass: "human_reviewed" as const,
  declaredBy: "human-24h",
  isolationProfileId: TOOL_BASELINE_PROFILE_ID,
};

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

function sealedFromOutcome(over: Partial<SealedToolRunRecordMirror> = {}): SealedToolRunRecordMirror {
  const body = {
    schemaVersion: "menog-tool-evidence/v0",
    parents: {
      skillId: null as string | null,
      skillStepId: null as string | null,
      taskId: "task-24h-001",
      assignmentId: "asg-24h-001",
      agentId: "menog-agent-builder",
    },
    requestHash: "sha256:" + sha256Hex("the-24h-request"),
    toolId: "demo.survey",
    version: "1.0.0",
    manifestHash: "sha256:" + sha256Hex("manifest-24h"),
    policy: { outcome: "allow", matchedRule: "rule:day1:allow-inspect-readonly" as string | null },
    isolation: { profileId: TOOL_BASELINE_PROFILE_ID, evidenceHash: "sha256:" + sha256Hex("iso-24h") },
    result: {
      status: "completed",
      exitCode: 0 as number | null,
      timedOut: false,
      outputHash: "sha256:" + sha256Hex("out-24h") as string | null,
      outputBytes: 10 as number | null,
      truncated: false,
    },
    workspaceId: "workspace:24h",
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

function stripUndefined<T extends object>(value: T): T {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (v === undefined) continue;
    out[k] = v !== null && typeof v === "object" && !Array.isArray(v) ? stripUndefined(v) : v;
  }
  return out as T;
}

// ── node worlds + the bounded transport ──────────────────────────────────────

interface NodeWorld {
  readonly tag: "A" | "B";
  readonly root: string;
  readonly store: DurableStore;
  readonly coordinator: RuntimeStateCoordinator;
  readonly registry: PeerRegistry;
  readonly identity: ReturnType<typeof generateLocalSigningIdentity>;
  readonly epochId: string;
}

function openNode(tag: "A" | "B", epochId: string, startedAt: number = NOW): NodeWorld {
  const root = mkdtempSync(join(tmpdir(), "menog-24h-" + tag.toLowerCase() + "-"));
  roots.push(root);
  const open = DurableStore.open(root);
  if (!open.ok) throw new Error(open.reason);
  const store = open.store;
  openStores.push(store);
  const bound = RuntimeStateCoordinator.open(store, epochOf(epochId, startedAt), "24h-node-" + tag);
  if (!bound.ok) throw new Error(bound.reason);
  const coordinator = bound.coordinator;
  openCoords.push(coordinator);
  const reg = PeerRegistry.open(store, coordinator);
  if (!reg.ok) throw new Error(reg.reason);
  const identity = generateLocalSigningIdentity();
  return { tag, root, store, coordinator, registry: reg.registry, identity, epochId };
}

/**
 * The bounded in-flight transport between A and B: a frozen, size-capped
 * FIFO of signed envelopes + their payloads. NO sockets, NO discovery —
 * this is the ONLY thing "network" means in this scenario.
 */
function boundedTransport() {
  const wire: { envelope: FederationMessageBody extends never ? never : { message: FederationMessageBody; signature: string }; payload: Record<string, unknown> }[] = [];
  return {
    push(envelope: { message: FederationMessageBody; signature: string }, payload: Record<string, unknown>): { readonly ok: boolean; readonly reason?: string } {
      if (wire.length >= FEDERATION_MAX_BATCH) {
        return { ok: false, reason: "the in-flight wire is full (bound " + String(FEDERATION_MAX_BATCH) + ") — refusing (fail closed)" };
      }
      wire.push(Object.freeze({ envelope: Object.freeze({ ...envelope }), payload: Object.freeze({ ...payload }) }));
      return { ok: true };
    },
    drain(): readonly { envelope: { message: FederationMessageBody; signature: string }; payload: Record<string, unknown> }[] {
      return Object.freeze(wire.splice(0, wire.length));
    },
    get depth(): number {
      return wire.length;
    },
  };
}

/** B's bus + proposal + provenance ledgers over ONE coordinator binding. */
function openBReceivers(
  world: { readonly store: DurableStore; readonly coordinator: RuntimeStateCoordinator; readonly registry: PeerRegistry },
  aIdentities: readonly { readonly nodeId: string; readonly publicKeyHex: string }[]
) {
  // the 24D key directory is keyed by the NodeId's 64-hex tail
  const verifiers = new Map<string, ReturnType<typeof makeIdentitySignatureVerifier>>();
  for (const id of aIdentities) {
    verifiers.set(id.nodeId.slice(5), makeIdentitySignatureVerifier(id.publicKeyHex));
  }
  const busOpen = FederationBus.open({ store: world.store, coordinator: world.coordinator, peers: world.registry, verifiers });
  if (!busOpen.ok) throw new Error(busOpen.reason);
  const proposalsOpen = ProposalLedger.open({ store: world.store, coordinator: world.coordinator });
  if (!proposalsOpen.ok) throw new Error(proposalsOpen.reason);
  const provenanceOpen = ProvenanceLedger.open({ store: world.store, coordinator: world.coordinator });
  if (!provenanceOpen.ok) throw new Error(provenanceOpen.reason);
  return { bus: busOpen.bus, proposals: proposalsOpen.ledger, provenance: provenanceOpen.ledger };
}

/** B's LOCAL fresh authority: real 19B allocation + real Day-1 decision. */
function bLocalAuthority(atEpochMs: number, requestedCapabilities: readonly string[], verb: "inspect" = "inspect") {
  const ledger = AppendOnlyLedger.inMemory();
  const rt = new AgentRuntime({
    nowEpochMs: () => atEpochMs,
    ledger: {
      append: (input) => {
        const r = ledger.append({
          eventId: "e24h-" + input.eventType + "-" + String(ledger.length + 1).padStart(4, "0"),
          timestamp: new Date(atEpochMs).toISOString(),
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
    },
    workspaceId: "ws-24h",
    taskId: "task-24h-001",
  });
  if (!registerAllThreeAgents(rt, atEpochMs).ok) throw new Error("agent registration failed");
  const allocator = new TaskAllocator(rt);
  const task: TaskDescriptor = {
    label: "24h two-node proposed survey (locally scoped)",
    requiredCapabilities: ["workspace:read"],
    budget: { maxSteps: 2 },
    allowedRoles: ["builder"],
  };
  const alloc = allocator.allocate({ allocatedBy: "r0-human-operator", task, atEpochMs });
  if (!alloc.ok) throw new Error("B allocation refused: " + JSON.stringify(alloc));
  const engine = new DenyByDefaultPolicyEngine();
  const policy = engine.evaluate({
    actor: { type: "agent", id: alloc.assignment.assignedAgentId },
    verb,
    requestedCapabilities: [...requestedCapabilities] as Parameters<typeof engine.evaluate>[0]["requestedCapabilities"],
    workspaceId: "ws-24h",
  });
  return { alloc, policy, engine };
}

/** The Phase-20/21 governed run on B (injected transport; never a spawn). */
function bGovernedRun(assignedAgentId: string, policyOutcome: "allow" | "deny", requestId: string) {
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
    registeredBy: "human-24h",
  });
  if (!reg.ok) throw new Error("registration failed: " + reg.message);
  const entry = registry.lookup("demo.survey", "1.0.0");
  if (!entry.ok) throw new Error("lookup failed");
  const double = recordingTransport();
  const req: ToolExecutionRequest = {
    requestId,
    toolId: "demo.survey",
    version: "1.0.0",
    envelope: {
      schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
      toolId: "demo.survey",
      version: "1.0.0",
      input: {},
      constraints: { timeoutMs: 10_000, maxOutputBytes: 8_000 },
    },
    requester: { actorType: "agent", id: assignedAgentId },
    taskScope: ["workspace:read"],
    agentCapabilities: ["workspace:read"],
    policyOutcome: "allow",
    isolation: { profileId: TOOL_BASELINE_PROFILE_ID, canEnforce: true },
  };
  const outcome = executeToolRun({
    request: req,
    entry: entry.value,
    snapshot: SNAPSHOT,
    workspaceRoot: "/tmp/menog-ws-24h",
    policyOutcome,
    policyRuleId: "rule:day1:allow-inspect-readonly",
    ledger: AppendOnlyLedger.inMemory(),
    ledgerActor: { type: "runtime", id: "tool-runtime" },
    transportOverride: double.transport,
  } as never);
  return { outcome, double, entry };
}

/** A signs one task_proposal for B (or any overrides). */
function aProposalMessage(
  a: NodeWorld,
  payload: FederationTaskProposalPayload,
  seq: number,
  overrides: Partial<FederationMessageBody> = {}
): { message: FederationMessageBody; signature: string } {
  const m: FederationMessageBody = {
    schemaVersion: "menog-federation-message/v0",
    messageId: makeFederationMessageId(NOW + seq, "a2b" + String(seq).padStart(13, "0")),
    senderNodeId: a.identity.nodeId,
    senderFingerprint: a.identity.fingerprint,
    senderInstanceId: "ri-000000e8fa00-instanceaaaa",
    senderEpochId: EPOCH_A,
    protocolVersion: "menog-federation/v1",
    payloadHash: canonicalHash(payload),
    declaredIntent: "task_proposal",
    correlationId: null,
    causationId: null,
    lineage: [],
    issuedAtEpochMs: NOW,
    ...overrides,
  };
  const s = signFederationMessage(a.identity as unknown as Parameters<typeof signFederationMessage>[0], m);
  if (!s.ok) throw new Error(s.explanation);
  return { message: m, signature: s.signature };
}

function freshProposal(proposalSeq: number): FederationTaskProposalPayload {
  return {
    schemaVersion: "menog-task-proposal/v0",
    proposalId: makeFederationMessageId(NOW + 500 + proposalSeq, "proposal000000001").replace(/^fm-/, "fp-"),
    intentClass: "workspace_survey",
    contentHashes: ["sha256-" + "a".repeat(64)],
    provenance: { originNodeId: "PENDING", originFingerprint: "PENDING", note: "proposed by node A" },
    constraints: { maxBudgetSteps: 2, readonlyWorkspaceOnly: true },
    expectedEvidence: ["sha256-" + "b".repeat(64)],
  };
}

/** B's continuity writes (23C wiring; the ONE sanctioned live→durable path). */
function bContinuityWrite(
  wiring: LiveSurfaceWiring,
  record: SealedToolRunRecordMirror,
  status: "executing" | "done",
  atEpochMs: number
): void {
  const memWrite = wiring.writeMemory({
    record: {
      schemaVersion: "menog-memory/v0",
      memoryId: MEMORY_ID,
      kind: "execution",
      scope: { workspaceId: "ws-24h", taskId: "task-24h-001" },
      provenance: { origin: "runtime", actor: { type: "runtime", id: "memory-store" }, untrusted: false },
      retention: { retentionClass: "persistent" },
      body: { fact: "two-node survey completed under fresh LOCAL authority", outputHash: "sha256:" + sha256Hex("out-24h"), recordHash: record.recordHash },
      createdAtEpochMs: atEpochMs,
      createdByActorId: "memory-store",
    },
    transactionId: txn("mem"),
  });
  if (!memWrite.ok) throw new Error("continuity memory write failed: " + JSON.stringify(memWrite));
  const taskBase = {
    schemaVersion: "menog-task-lifecycle/v0",
    goalId: GOAL_ID,
    planId: "plan-24h-001",
    taskIds: ["task-24h-001"],
    rationale: "",
    updatedAtEpochMs: atEpochMs,
  };
  const w1 = wiring.writeTaskLifecycle({
    state: { ...taskBase, status: "executing", rationale: "two-node survey step running", sourceEventId: "ev24h-run" },
    previousStatus: null,
    transactionId: txn("task1"),
  });
  if (!w1.ok) throw new Error("task executing write failed: " + JSON.stringify(w1));
  const w2 = wiring.writeTaskLifecycle({
    state: { ...taskBase, status, rationale: status === "done" ? "terminal fact from the sealed run" : "running", sourceEventId: "ev24h-run", updatedAtEpochMs: atEpochMs + 1 },
    previousStatus: "executing",
    transactionId: txn("task2"),
  });
  if (!w2.ok) throw new Error("task " + status + " write failed: " + JSON.stringify(w2));
}

/** B seals the run evidence + 22C atomic pair (the 23G pattern). */
function bEvidencePersist(store: DurableStore, record: SealedToolRunRecordMirror, matchedRule: string): { goalEvent: LedgerEventMirror; runEvent: LedgerEventMirror } {
  const ledger = AppendOnlyLedger.inMemory();
  const planner = new DeterministicPlanner(new VerbRegistry(), { emitObservabilityEvents: true });
  const goal: Goal = {
    goalId: GOAL_ID,
    description: "two-node survey proposed by A, judged and run by B (24H)",
    requestedVerbSequence: ["inspect"],
    budget: { maxSteps: 2 },
  };
  const proposal = planner.propose(goal);
  if (proposal.disposition !== "proposed") throw new Error("planner refused to propose");
  const { plannerObservationToMenogEventInputs } = createRequire(import.meta.url)("@menog/planner") as typeof import("@menog/planner");
  const bridgeInputs = plannerObservationToMenogEventInputs(
    planner.observations(),
    { type: "agent", id: "menog-agent-planner" },
    { workspaceId: "ws-24h", taskId: "task-24h-001", eventIdPrefix: "h24g" }
  );
  for (const evInput of bridgeInputs) {
    const r = ledger.append(evInput);
    if (!r.ok) throw new Error("planner bridge append failed: " + r.reason);
  }
  const runEventInput = stripUndefined({
    eventId: "ev24h-run-000001",
    timestamp: "2026-10-01T00:00:01.000Z",
    eventType: "tool_run_evidence",
    actor: { type: "runtime", id: "tool-runtime" } as Actor,
    workspaceId: "ws-24h",
    taskId: "task-24h-001",
    policyDecision: "allow" as const,
    inputSummary: { requestId: "req-24h-001", toolId: "demo.survey" },
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
  const p1 = persistLedgerEvent(store, { event: goalEvent, sequence: 0, transactionId: txn("goal") });
  if (!p1.ok) throw new Error("goal event persist failed: " + p1.reason);
  const p2 = persistToolRunEvidenceWithObservation(store, { event: runEvent, sequence: 1, record, transactionId: txn("run") });
  if (!p2.ok) throw new Error("atomic pair persist failed: " + p2.reason);
  void matchedRule;
  return { goalEvent, runEvent };
}

// ═════════════════════════════════════════════════════════════════════════════

describe("24H — two-node local federation continuous scenario", () => {

  it("A→bounded transport→B: verify/candidate/LOCAL allocation+Policy/Phase20-21 run/evidence/durable/continuity/provenance; restart B → NEW epoch → facts without authority → old replay denied → NEW proposal needs fresh authority", () => {
    // ── two isolated worlds, distinct identities + epochs ──
    const a = openNode("A", EPOCH_A);
    const b = openNode("B", EPOCH_B1);
    expect(a.identity.nodeId).not.toBe(b.identity.nodeId);
    expect(a.epochId).not.toBe(b.epochId);

    // B enrolls A: first contact → candidate → admitted (evidenced, durable)
    const enroll = b.registry.applyTrustTransition({
      nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId: "ri-000000e8fa00-instanceaaaa",
      protocolVersion: "menog-federation/v1", reason: "first_contact_enrolled",
      evidence: "identity doc hash", transactionId: txn("enroll-a"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: NOW,
    });
    expect(enroll.ok).toBe(true);
    const admit = b.registry.applyTrustTransition({
      nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId: "ri-000000e8fa00-instanceaaaa",
      protocolVersion: "menog-federation/v1", reason: "admission_request_accepted",
      evidence: "admission provenance", transactionId: txn("admit-a"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: NOW + 1,
    });
    expect(admit.ok).toBe(true);

    const receivers = openBReceivers(b, [a.identity]);

    // ── A signs the proposal; bounded transport carries it ──
    const payload = { ...freshProposal(1), provenance: { originNodeId: a.identity.nodeId, originFingerprint: a.identity.fingerprint, note: "proposed by node A" } } as FederationTaskProposalPayload;
    const signed = aProposalMessage(a, payload, 1);
    const wire = boundedTransport();
    expect(wire.push(signed, payload as unknown as Record<string, unknown>).ok).toBe(true);
    expect(wire.depth).toBe(1);

    // ── B verifies identity/admission/replay/schema (the 24D pipeline) ──
    const delivered = wire.drain();
    expect(delivered).toHaveLength(1);
    const busResult = receivers.bus.ingest({ envelope: delivered[0]!.envelope, payload: delivered[0]!.payload, nowEpochMs: NOW + 5 });
    expect(busResult.ok).toBe(true);
    const entry = receivers.bus.inbox()[receivers.bus.inbox().length - 1];
    if (!entry) throw new Error("fixture: no inbox entry");
    // the proposal becomes durable inert evidence on B (24E receiver step)
    const admitted1 = receivers.proposals.receiveTaskProposal({
      inboxEntry: { messageId: entry.messageId, senderNodeId: entry.senderNodeId, declaredIntent: entry.declaredIntent, payload: entry.payload },
      senderFingerprint: a.identity.fingerprint,
      receiptRecordId: entry.receiptRecordId,
      nowEpochMs: NOW + 6,
    });
    expect(admitted1.ok).toBe(true);

    // ── untrusted local candidate (inert; intent only) ──
    const cand = deriveLocalTaskCandidate({
      proposal: { proposalId: payload.proposalId, senderNodeId: a.identity.nodeId, intentClass: payload.intentClass, constraints: payload.constraints, expectedEvidence: payload.expectedEvidence },
      localTaskLabel: "24h two-node proposed survey (locally scoped)",
      requiredCapabilities: ["workspace:read"],
    });
    expect(cand.ok).toBe(true);

    // ── fresh LOCAL allocation + fresh LOCAL Policy on B ──
    const { alloc, policy } = bLocalAuthority(NOW + 6, ["workspace:list"]);
    expect(alloc.assignment.executionAuthorized).toBe(false);
    expect(policy.decision.outcome).toBe("allow");

    // ── the fresh-authorization gate (LOCAL facts only) ──
    const gate = requireFreshLocalAuthorization({
      assignment: {
        assignmentId: alloc.assignment.assignmentId,
        assignedAgentId: alloc.assignment.assignedAgentId,
        allocatedAtEpochMs: alloc.assignment.allocatedAtEpochMs,
        executionAuthorized: alloc.assignment.executionAuthorized,
      },
      policy: { outcome: policy.decision.outcome, decidedAtEpochMs: NOW + 6 },
      policyActorId: alloc.assignment.assignedAgentId,
      atEpochMs: NOW + 7,
    });
    expect(gate.ok).toBe(true);

    // ── Phase-20 isolation + Phase-21 governed tool runtime on B ──
    const run = bGovernedRun(alloc.assignment.assignedAgentId, "allow", "req-24h-001");
    expect(run.outcome.decision.status).toBe("not_started");
    expect(run.double.wasCalled()).toBe(true);
    expect(run.outcome.result?.status).toBe("completed");

    // ── evidence/ledger + 22C atomic pair on B ──
    const record = sealedFromOutcome({
      policy: { outcome: "allow", matchedRule: policy.decision.matchedRule },
      manifestHash: run.entry.value.manifestHash,
    });
    const { runEvent } = bEvidencePersist(b.store, record, policy.decision.matchedRule);

    // ── cross-node provenance anchored on B (24F; LOCAL evidence only) ──
    const anchor: FederationProvenanceAnchor = {
      schemaVersion: "menog-federation-provenance/v0",
      anchorId: "fv-" + (NOW + 60).toString(16).padStart(16, "0") + "-twonode24hab0001",
      kind: "task_proposal",
      messageId: null,
      proposalId: payload.proposalId,
      senderNodeId: a.identity.nodeId,
      senderFingerprint: a.identity.fingerprint,
      senderEpochId: EPOCH_A,
      receiverNodeId: b.identity.nodeId,
      receiverEpochId: EPOCH_B1,
      protocolVersion: "menog-federation/v1",
      schemaVersionOfMessage: "menog-task-proposal/v0",
      payloadHash: canonicalHash(payload),
      correlationId: null,
      causationId: null,
      lineage: [],
      signatureResult: { result: "verified", reason: null },
      peerAdmission: "admitted",
      localPolicyDecision: "allow",
      policyEvidenceRefs: [policy.decision.matchedRule ?? "rule"],
      toolEvidenceRefs: ["run-" + record.recordHash.slice(0, 32)],
      commitRefs: [entry.receiptRecordId, "fpr-" + payload.proposalId],
      responseHash: "sha256-" + record.recordHash.slice(0, 64),
      decision: "local_action",
      decidedAtEpochMs: NOW + 7,
    };
    const anchored = receivers.provenance.anchor({ anchor, nowEpochMs: NOW + 8 });
    if (!anchored.ok) throw new Error("anchor refused: " + anchored.failureCode + ": " + anchored.explanation);
    expect(anchored.ok).toBe(true);

    // ── Phase-22 durable state + Phase-23 continuity on B ──
    const wiringOpen = LiveSurfaceWiring.open(b.store, b.coordinator, epochOf(EPOCH_B1));
    if (!wiringOpen.ok) throw new Error(wiringOpen.reason);
    bContinuityWrite(wiringOpen.wiring, record, "done", NOW + 9);
    b.coordinator.close();

    // ── RESTART B: NEW epoch, facts recovered WITHOUT authority ──
    const reopened = DurableStore.open(b.root);
    if (!reopened.ok) throw new Error("reopen failed: " + reopened.reason);
    openStores.push(reopened.store);
    const handoff = runStartupHandoff({
      store: reopened.store,
      bootedEpoch: epochOf(EPOCH_B2, T1),
      recoveryRequest: REQUEST,
      sourceIdentity: "24h-restart",
      priorEpochId: claimOwner(reopened.store),
      nowEpochMs: T1,
    });
    expect(handoff.ok).toBe(true);
    expect(handoff.terminalState).toBe("LIVE");
    expect(handoff.newEpochId).not.toBe(EPOCH_B1);
    expect(handoff.classification?.blockingClass).toBe("none");
    // recovered facts, zero authority:
    expect(handoff.wiring).not.toBeNull();
    expect(claimOwner(reopened.store)).toBe(handoff.newEpochId);

    // the OLD epoch's coordinator identity is stale forever:
    const oldBind = RuntimeStateCoordinator.open(reopened.store, epochOf(EPOCH_B1), "24h-stale");
    expect(oldBind.ok).toBe(false);

    // facts survived: receipt, proposal, anchor, peer admission (as DATA)
    const newReceivers = (() => {
      const newBound = RuntimeStateCoordinator.open(reopened.store, epochOf(handoff.newEpochId as string, T1), "24h-node-B2");
      if (!newBound.ok) throw new Error(newBound.reason);
      openCoords.push(newBound.coordinator);
      const reg = PeerRegistry.open(reopened.store, newBound.coordinator);
      if (!reg.ok) throw new Error(reg.reason);
      const r = openBReceivers({ store: reopened.store, coordinator: newBound.coordinator, registry: reg.registry }, [a.identity]);
      return { ...r, registry: reg.registry, coordinator: newBound.coordinator };
    })();
    const peer = newReceivers.registry.readPeer(a.identity.nodeId);
    expect(peer.ok).toBe(true);
    if (!peer.ok) throw new Error(peer.reason);
    expect(peer.state.trustState).toBe("admitted"); // recovered data, not authority
    expect(newReceivers.proposals.hasProposal(payload.proposalId)).toBe(true);
    const anchorBack = newReceivers.provenance.readAnchor(anchor.anchorId);
    expect(anchorBack.ok).toBe(true);
    if (anchorBack.ok) expect(anchorBack.anchor.decision).toBe("local_action");

    // ── OLD message replay DENIED (durable receipt guard; no signature evaluation) ──
    const replay = newReceivers.bus.ingest({ envelope: delivered[0]!.envelope, nowEpochMs: T1 + 5 });
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.failureCode).toBe("replay_detected");

    // ── NEW A proposal requires fresh local authority again ──
    const payload2 = { ...freshProposal(2), provenance: { originNodeId: a.identity.nodeId, originFingerprint: a.identity.fingerprint, note: "second proposal" } } as FederationTaskProposalPayload;
    const signed2 = aProposalMessage(a, payload2, 900, {
      messageId: makeFederationMessageId(T1 + 1, "a2b" + String(900).padStart(13, "0")),
      payloadHash: canonicalHash(payload2),
      issuedAtEpochMs: T1,
      senderEpochId: makeRuntimeEpochId(T1, "epochA000000002"),
    });
    const bus2 = newReceivers.bus.ingest({ envelope: signed2, payload: payload2 as unknown as Record<string, unknown>, nowEpochMs: T1 + 5 });
    expect(bus2.ok).toBe(true);
    const entry2 = newReceivers.bus.inbox()[newReceivers.bus.inbox().length - 1];
    if (!entry2) throw new Error("fixture: no second inbox entry");
    const admitted2 = newReceivers.proposals.receiveTaskProposal({
      inboxEntry: { messageId: entry2.messageId, senderNodeId: entry2.senderNodeId, declaredIntent: entry2.declaredIntent, payload: entry2.payload },
      senderFingerprint: a.identity.fingerprint,
      receiptRecordId: entry2.receiptRecordId,
      nowEpochMs: T1 + 6,
    });
    expect(admitted2.ok).toBe(true);

    // fresh LOCAL allocation + fresh LOCAL Policy at T1 — the PRE-restart
    // facts are both stale now (> the fresh window); the allocation-age check
    // fires first and neither old fact can be reused:
    const staleGate = requireFreshLocalAuthorization({
      assignment: {
        assignmentId: alloc.assignment.assignmentId,
        assignedAgentId: alloc.assignment.assignedAgentId,
        allocatedAtEpochMs: alloc.assignment.allocatedAtEpochMs,
        executionAuthorized: alloc.assignment.executionAuthorized,
      },
      policy: { outcome: policy.decision.outcome, decidedAtEpochMs: NOW + 6 },
      policyActorId: alloc.assignment.assignedAgentId,
      atEpochMs: T1 + 7,
    });
    expect(staleGate.ok).toBe(false);
    if (!staleGate.ok) expect(staleGate.failureCode).toBe("stale_local_allocation");

    const fresh2 = bLocalAuthority(T1 + 6, ["workspace:list"]);
    expect(fresh2.policy.decision.outcome).toBe("allow");
    const gate2 = requireFreshLocalAuthorization({
      assignment: {
        assignmentId: fresh2.alloc.assignment.assignmentId,
        assignedAgentId: fresh2.alloc.assignment.assignedAgentId,
        allocatedAtEpochMs: fresh2.alloc.assignment.allocatedAtEpochMs,
        executionAuthorized: fresh2.alloc.assignment.executionAuthorized,
      },
      policy: { outcome: fresh2.policy.decision.outcome, decidedAtEpochMs: T1 + 6 },
      policyActorId: fresh2.alloc.assignment.assignedAgentId,
      atEpochMs: T1 + 7,
    });
    expect(gate2.ok).toBe(true);
    const run2 = bGovernedRun(fresh2.alloc.assignment.assignedAgentId, "allow", "req-24h-002");
    expect(run2.outcome.decision.status).toBe("not_started");
    expect(run2.double.wasCalled()).toBe(true);
    void runEvent;
  });

  // ── negative controls ──────────────────────────────────────────────────────

  it("NEGATIVE B Policy denial: the chain stops before execution; the transport double is never called", () => {
    // B's Day-1 engine denies a WRITE ask — denial is valid and final
    const engine = new DenyByDefaultPolicyEngine();
    const deny = engine.evaluate({
      actor: { type: "agent", id: "menog-agent-builder" },
      verb: "inspect",
      requestedCapabilities: ["workspace:write"],
      workspaceId: "ws-24h",
    });
    expect(deny.decision.outcome).toBe("deny");
    const run = bGovernedRun("menog-agent-builder", "deny", "req-24h-deny");
    expect(run.outcome.decision.status).toBe("policy_denied");
    expect(run.outcome.result).toBeNull();
    expect(run.double.wasCalled()).toBe(false);
  });

  it("NEGATIVE unknown A and quarantined A: both refuse at B's bus before any signature evaluation", () => {
    // unknown A: a fresh B world where A was never enrolled
    const aStranger = generateLocalSigningIdentity();
    const b = openNode("B", EPOCH_B1);
    const receiversUnknown = openBReceivers(b, [aStranger]);
    const m: FederationMessageBody = {
      schemaVersion: "menog-federation-message/v0",
      messageId: makeFederationMessageId(NOW + 1, "stranger00000001"),
      senderNodeId: aStranger.nodeId,
      senderFingerprint: aStranger.fingerprint,
      senderInstanceId: "ri-000000e8fa00-instancezzzz",
      senderEpochId: EPOCH_A,
      protocolVersion: "menog-federation/v1",
      payloadHash: "sha256-" + "5".repeat(64),
      declaredIntent: "task_proposal",
      correlationId: null, causationId: null, lineage: [],
      issuedAtEpochMs: NOW,
    };
    const s = signFederationMessage(aStranger, m);
    if (!s.ok) throw new Error(s.explanation);
    const unknown = receiversUnknown.bus.ingest({ envelope: { message: m, signature: s.signature }, nowEpochMs: NOW + 5 });
    expect(unknown).toMatchObject({ ok: false, stage: "peer_admission", failureCode: "peer_not_admitted" });

    // quarantined A: enrolled+admitted, then evidenced-quarantined (terminal)
    const a = openNode("A", EPOCH_A);
    const enrollQ = b.registry.applyTrustTransition({
      nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId: "ri-000000e8fa00-instanceaaaa",
      protocolVersion: "menog-federation/v1", reason: "first_contact_enrolled",
      evidence: "identity doc hash", transactionId: txn("enroll-q"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: NOW,
    });
    expect(enrollQ.ok).toBe(true);
    const admitQ = b.registry.applyTrustTransition({
      nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId: "ri-000000e8fa00-instanceaaaa",
      protocolVersion: "menog-federation/v1", reason: "admission_request_accepted",
      evidence: "admission provenance", transactionId: txn("admit-q"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: NOW + 1,
    });
    expect(admitQ.ok).toBe(true);
    const q = b.registry.applyTrustTransition({
      nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId: "ri-000000e8fa00-instanceaaaa",
      protocolVersion: "menog-federation/v1", reason: "peer_misbehavior_evidenced", evidence: "24H adversarial finding",
      transactionId: txn("quarantine"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: NOW + 2,
    });
    expect(q.ok).toBe(true);
    const receiversQ = openBReceivers(b, [a.identity]);
    const mq = {
      ...m,
      messageId: makeFederationMessageId(NOW + 2, "quarantined000001"),
      senderNodeId: a.identity.nodeId,
      senderFingerprint: a.identity.fingerprint,
    };
    const sq = signFederationMessage(a.identity, mq);
    if (!sq.ok) throw new Error(sq.explanation);
    const quarantined = receiversQ.bus.ingest({ envelope: { message: mq, signature: sq.signature }, nowEpochMs: NOW + 5 });
    expect(quarantined).toMatchObject({ ok: false, stage: "peer_admission", failureCode: "peer_not_admitted" });
    if (!quarantined.ok) expect(quarantined.explanation).toContain("quarantined");
    expect(receiversQ.bus.inbox()).toHaveLength(0);
  });

  it("NEGATIVE stale A epoch and tamper: both refuse at B's bus", () => {
    const a = openNode("A", EPOCH_A);
    const b = openNode("B", EPOCH_B1);
    const enroll = b.registry.applyTrustTransition({
      nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId: "ri-000000e8fa00-instanceaaaa",
      protocolVersion: "menog-federation/v1", reason: "first_contact_enrolled",
      evidence: "identity doc hash", transactionId: txn("enroll"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: NOW,
    });
    expect(enroll.ok).toBe(true);
    const admit = b.registry.applyTrustTransition({
      nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId: "ri-000000e8fa00-instanceaaaa",
      protocolVersion: "menog-federation/v1", reason: "admission_request_accepted",
      evidence: "admission provenance", transactionId: txn("admit"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: NOW + 1,
    });
    expect(admit.ok).toBe(true);
    const receivers = openBReceivers(b, [a.identity]);
    const payload = { ...freshProposal(3), provenance: { originNodeId: a.identity.nodeId, originFingerprint: a.identity.fingerprint, note: "stale probe" } } as FederationTaskProposalPayload;

    // newer sender epoch first…
    const newer = aProposalMessage(a, payload, 4, { senderEpochId: makeRuntimeEpochId(NOW + 10, "epochA000000009") });
    const r1 = receivers.bus.ingest({ envelope: newer, payload: payload as unknown as Record<string, unknown>, nowEpochMs: NOW + 5 });
    // …then the OLDER epoch refuses (stale)
    const older = aProposalMessage(a, payload, 5, { senderEpochId: EPOCH_A });
    const r2 = receivers.bus.ingest({ envelope: older, payload: payload as unknown as Record<string, unknown>, nowEpochMs: NOW + 6 });
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(false);

    // tamper: a post-signature body mutation refuses at the signature stage
    const tamperTarget = aProposalMessage(a, payload, 6);
    const tampered = { ...tamperTarget.message, payloadHash: "sha256-" + "f".repeat(64) };
    const r3 = receivers.bus.ingest({ envelope: { message: tampered, signature: tamperTarget.signature }, nowEpochMs: NOW + 7 });
    expect(r3).toMatchObject({ ok: false, stage: "signature", failureCode: "signature_stage_refused" });
  });

  it("NEGATIVE no auto-resume / no old Policy reuse / no direct remote execution: recovery grants nothing; only fresh LOCAL facts open the gate", () => {
    // no auto-resume: a proposal-only input satisfies NOTHING after recovery
    const proposalOnly = requireFreshLocalAuthorization({
      assignment: null as unknown as { assignmentId: string; assignedAgentId: string; allocatedAtEpochMs: number; executionAuthorized: boolean },
      policy: null as unknown as { outcome: "allow" | "deny"; decidedAtEpochMs: number },
      policyActorId: "menog-agent-builder",
      atEpochMs: T1,
    });
    expect(proposalOnly).toMatchObject({ ok: false, failureCode: "no_local_allocation" });
    // no old Policy reuse: a PRE-restart Policy allow fails the freshness
    // window even against a FRESH assignment (assignment age 7ms, policy age > window)
    const oldPolicy = requireFreshLocalAuthorization({
      assignment: { assignmentId: "asg-24h-old", assignedAgentId: "menog-agent-builder", allocatedAtEpochMs: T1, executionAuthorized: false },
      policy: { outcome: "allow", decidedAtEpochMs: NOW + 6 },
      policyActorId: "menog-agent-builder",
      atEpochMs: T1 + 7,
    });
    expect(oldPolicy).toMatchObject({ ok: false, failureCode: "stale_local_policy" });
    // no direct remote execution: even a forged "everything" claim needs the
    // assignment's actor binding — a mismatched actor refuses
    const engine = new DenyByDefaultPolicyEngine();
    const allowPlanner = engine.evaluate({
      actor: { type: "agent", id: "menog-agent-planner" },
      verb: "inspect",
      requestedCapabilities: ["workspace:list"],
      workspaceId: "ws-24h",
    });
    const deputy = requireFreshLocalAuthorization({
      assignment: { assignmentId: "asg-24h-dep", assignedAgentId: "menog-agent-builder", allocatedAtEpochMs: T1, executionAuthorized: false },
      policy: { outcome: allowPlanner.decision.outcome, decidedAtEpochMs: T1 + 1 },
      policyActorId: "menog-agent-planner",
      atEpochMs: T1 + 2,
    });
    expect(deputy).toMatchObject({ ok: false, failureCode: "actor_mismatch" });
  });

  it("NEGATIVE no capability union: B's local descriptor keeps B-local capabilities; the remote proposal adds none", () => {
    const a = openNode("A", EPOCH_A);
    const b = openNode("B", EPOCH_B1);
    void b;
    const payload = { ...freshProposal(7), provenance: { originNodeId: a.identity.nodeId, originFingerprint: a.identity.fingerprint, note: "cap probe" } } as FederationTaskProposalPayload;
    // the candidate carries ONLY the local descriptor's capabilities — the
    // proposal structurally cannot contribute any:
    const cand = deriveLocalTaskCandidate({
      proposal: { proposalId: payload.proposalId, senderNodeId: a.identity.nodeId, intentClass: payload.intentClass, constraints: payload.constraints, expectedEvidence: payload.expectedEvidence },
      localTaskLabel: "cap probe",
      requiredCapabilities: ["workspace:read"],
    });
    expect(cand.ok).toBe(true);
    if (cand.ok) expect(cand.candidate.requiredCapabilities).toEqual(["workspace:read"]);
    // and B's Day-1 engine denies the inflated write ask regardless:
    const engine = new DenyByDefaultPolicyEngine();
    const writeAsk = engine.evaluate({
      actor: { type: "agent", id: "menog-agent-builder" },
      verb: "inspect",
      requestedCapabilities: ["workspace:write", "network:external"],
      workspaceId: "ws-24h",
    });
    expect(writeAsk.decision.outcome).toBe("deny");
  });

  it("cross-node provenance WITHOUT consensus/global-order: B-side anchors order only by B's own commit sequence; no total-order claim exists", () => {
    const a = openNode("A", EPOCH_A);
    const b = openNode("B", EPOCH_B1);
    const enroll = b.registry.applyTrustTransition({
      nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId: "ri-000000e8fa00-instanceaaaa",
      protocolVersion: "menog-federation/v1", reason: "first_contact_enrolled",
      evidence: "identity doc hash", transactionId: txn("enroll"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: NOW,
    });
    expect(enroll.ok).toBe(true);
    const admit = b.registry.applyTrustTransition({
      nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId: "ri-000000e8fa00-instanceaaaa",
      protocolVersion: "menog-federation/v1", reason: "admission_request_accepted",
      evidence: "admission provenance", transactionId: txn("admit"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: NOW + 1,
    });
    expect(admit.ok).toBe(true);
    const receivers = openBReceivers(b, [a.identity]);
    // two proposals in quick succession → two receipts + two proposals + two anchors
    const ids: string[] = [];
    for (let i = 0; i < 2; i++) {
      const payload = { ...freshProposal(10 + i), provenance: { originNodeId: a.identity.nodeId, originFingerprint: a.identity.fingerprint, note: "order probe " + String(i) } } as FederationTaskProposalPayload;
      const signed = aProposalMessage(a, payload, 10 + i, { messageId: makeFederationMessageId(NOW + 10 + i, "a2b" + String(10 + i).padStart(13, "0")), payloadHash: canonicalHash(payload) });
      const r = receivers.bus.ingest({ envelope: signed, payload: payload as unknown as Record<string, unknown>, nowEpochMs: NOW + 5 + i });
      expect(r.ok).toBe(true);
      const entry = receivers.bus.inbox()[receivers.bus.inbox().length - 1];
      if (!entry) throw new Error("fixture");
      const admitted = receivers.proposals.receiveTaskProposal({
        inboxEntry: { messageId: entry.messageId, senderNodeId: entry.senderNodeId, declaredIntent: entry.declaredIntent, payload: entry.payload },
        senderFingerprint: a.identity.fingerprint,
        receiptRecordId: entry.receiptRecordId,
        nowEpochMs: NOW + 6 + i,
      });
      expect(admitted.ok).toBe(true);
      if (!admitted.ok) continue;
      const anchor: FederationProvenanceAnchor = {
        schemaVersion: "menog-federation-provenance/v0",
        anchorId: "fv-" + (NOW + 100 + i).toString(16).padStart(16, "0") + "-orderprobe24hab" + String(i),
        kind: "task_proposal",
        messageId: null,
        proposalId: payload.proposalId,
        senderNodeId: a.identity.nodeId,
        senderFingerprint: a.identity.fingerprint,
        senderEpochId: EPOCH_A,
        receiverNodeId: b.identity.nodeId,
        receiverEpochId: EPOCH_B1,
        protocolVersion: "menog-federation/v1",
        schemaVersionOfMessage: "menog-task-proposal/v0",
        payloadHash: canonicalHash(payload),
        correlationId: null,
        causationId: null,
        lineage: [],
        signatureResult: { result: "verified", reason: null },
        peerAdmission: "admitted",
        localPolicyDecision: "none",
        policyEvidenceRefs: [],
        toolEvidenceRefs: [],
        commitRefs: [entry.receiptRecordId, "fpr-" + payload.proposalId],
        responseHash: null,
        decision: "admitted",
        decidedAtEpochMs: NOW + 6 + i,
      };
      const anchored = receivers.provenance.anchor({ anchor, nowEpochMs: NOW + 7 + i });
      expect(anchored.ok).toBe(true);
      if (anchored.ok) ids.push(anchored.commitSequence + ":" + anchored.anchorId);
    }
    // the ONLY ordering is B's own durable commit sequence — monotone, local,
    // and claimed as nothing more than that:
    const seqs = ids.map((s) => Number(s.split(":")[0]));
    expect(seqs.length).toBe(2);
    expect(seqs[1]! > seqs[0]!).toBe(true);
    // no global-order/consensus vocabulary exists in any federation module:
    const files = ["federationIdentity.ts", "federationCrypto.ts", "federationPeers.ts", "federationBus.ts", "federationProposals.ts", "federationProvenance.ts"];
    let hits = 0;
    for (const f of files) {
      const src = readSrc("federationProvenance.ts" === f ? f : f);
      const code = src
        .split("\n")
        .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
        .join("\n");
      if (/global\s?order|total\s?order|consensus|lamport|vector\s?clock/i.test(code)) hits += 1;
    }
    expect(hits).toBe(0);
  });
});

function readSrc(p: string): string {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { readFileSync } = require("node:fs") as typeof import("node:fs");
  const { join } = require("node:path") as typeof import("node:path");
  return readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");
}
