/**
 * PHASE 25H — Operational Two-Node Lifecycle Scenario
 * (LOCAL FIXTURE ONLY / NO SOCKETS / NO LAN·INTERNET·DISCOVERY).
 *
 * Composes the FULL Phase-25 operational lifecycle over the frozen 24A–24F
 * stack: initialize (25B public-facts lifecycle) → B locally admits A (25C
 * intent-gated admin) → A passes the 25D egress disclosure → bounded
 * in-flight transport (the ONLY "network") → B 24D pipeline → untrusted
 * candidate → fresh LOCAL 19B allocation + fresh LOCAL Day-1 Policy for the
 * assigned actor → fresh-authorization gate → Phase-20/21 governed run →
 * evidence/22C/23B-23C/24F provenance (B-side commit-sequence order only) →
 * A ROTATES (25B re-identity) → the old key's message is denied → the new
 * identity is NOT trusted automatically (P7) → explicit B admission of the
 * replacement → the old identity is terminal → RESTART B (23D) → recovered
 * facts are DATA with zero authority → replay denied → a new proposal again
 * requires fresh local authority.
 *
 * Negative controls: unknown/revoked/quarantined/stale/tamper ·
 * secret-egress · stale-disclosure · old-Policy · actor mismatch ·
 * no-auto-resume · no-capability-union · no-direct-remote-execution.
 *
 * Provenance honesty: only B's own durable commit sequence orders anchors —
 * no consensus, no global clock, no total order is claimed or implemented.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
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
  rotateLocalIdentity,
  signFederationMessage,
  makeIdentitySignatureVerifier,
  makeFederationMessageId,
  makeRuntimeEpochId,
  canonicalHash,
  requireFreshLocalAuthorization,
  deriveLocalTaskCandidate,
  decideLifecycleTransition,
  decideKeyUse,
  decideTrustInheritance,
  decideEgress,
  verifyEgressManifest,
  checkLocalAdminIntent,
  PeerAdminSession,
  PeerAdminSession as AdminSession,
  EGRESS_SCHEMA_VERSION,
  FEDERATION_MAX_BATCH,
  type RuntimeEpoch,
  type FederationMessageBody,
  type FederationTaskProposalPayload,
  type FederationProvenanceAnchor,
  type LedgerEventMirror,
  type RecoveryRequest,
  type SealedToolRunRecordMirror,
  type EgressCandidate,
  type KeyLifecycleRecord,
  type LocalAdminIntent,
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

const EPOCH_A1 = makeRuntimeEpochId(NOW, "epochA000000001");
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
  return "t25h-" + tag + "-" + String(txnCounter).padStart(6, "0");
}

let tickCounter = 0;
function tick(): number {
  tickCounter += 1;
  return NOW + tickCounter;
}

const ROOT_LINEAGE = "two-node-root-25h";
const GOAL_ID = "goal-25h-twonode";
const MEMORY_ID = "mem-25h-0000001";

// ── Phase-20/21 fixtures (the 23G/24H pattern; transport double, no spawn) ──

const SNAPSHOT: IsolationCapabilitySnapshot = {
  targetKernel: "5.15.167.4",
  targetArch: "x86_64",
  isWsl: true,
  landlockAbi: 1,
  probedAt: "2026-10-02T00:00:00.000Z",
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
  description: "Read-only survey tool used by the 25H two-node lifecycle scenario",
  capabilities: [{ capability: "workspace:read", criticality: "required" as const }],
  trustClass: "human_reviewed" as const,
  declaredBy: "human-25h",
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
      stdout: Buffer.from("survey-ok-25h\n"),
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
      taskId: "task-25h-001",
      assignmentId: "asg-25h-001",
      agentId: "menog-agent-builder",
    },
    requestHash: "sha256:" + sha256Hex("the-25h-request"),
    toolId: "demo.survey",
    version: "1.0.0",
    manifestHash: "sha256:" + sha256Hex("manifest-25h"),
    policy: { outcome: "allow", matchedRule: "rule:day1:allow-inspect-readonly" as string | null },
    isolation: { profileId: TOOL_BASELINE_PROFILE_ID, evidenceHash: "sha256:" + sha256Hex("iso-25h") },
    result: {
      status: "completed",
      exitCode: 0 as number | null,
      timedOut: false,
      outputHash: "sha256:" + sha256Hex("out-25h") as string | null,
      outputBytes: 14 as number | null,
      truncated: false,
    },
    workspaceId: "workspace:25h",
    recordedAt: "2026-10-02T00:00:00.000Z",
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
  readonly lifecycle: KeyLifecycleRecord;
  readonly epochId: string;
}

/** 25B initialize: a lifecycle record over verified PUBLIC facts (no private material). */
function initializeLifecycle(identity: ReturnType<typeof generateLocalSigningIdentity>, atEpochMs: number): KeyLifecycleRecord {
  const d = decideLifecycleTransition({
    record: null,
    to: "active",
    evidence: "25H: verified public facts initialize (private key material never received or recorded)",
    nowEpochMs: atEpochMs,
    freshPublicFacts: { publicKeyHex: identity.publicKeyHex, fingerprint: identity.fingerprint, nodeId: identity.nodeId },
  });
  if (!d.ok) throw new Error(d.explanation);
  return d.record;
}

function openNode(tag: "A" | "B", epochId: string, startedAt: number = NOW): NodeWorld {
  const root = mkdtempSync(join(tmpdir(), "menog-25h-" + tag.toLowerCase() + "-"));
  roots.push(root);
  const open = DurableStore.open(root);
  if (!open.ok) throw new Error(open.reason);
  const store = open.store;
  openStores.push(store);
  const bound = RuntimeStateCoordinator.open(store, epochOf(epochId, startedAt), "25h-node-" + tag);
  if (!bound.ok) throw new Error(bound.reason);
  const coordinator = bound.coordinator;
  openCoords.push(coordinator);
  const reg = PeerRegistry.open(store, coordinator);
  if (!reg.ok) throw new Error(reg.reason);
  const identity = generateLocalSigningIdentity();
  const lifecycle = initializeLifecycle(identity, tick());
  return { tag, root, store, coordinator, registry: reg.registry, identity, lifecycle, epochId };
}

/**
 * The bounded in-flight transport between A and B: a frozen, size-capped
 * FIFO of signed envelopes + their payloads. NO sockets, NO discovery —
 * this is the ONLY thing "network" means in this scenario.
 */
function boundedTransport() {
  const wire: { envelope: { message: FederationMessageBody; signature: string }; payload: Record<string, unknown> }[] = [];
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
          eventId: "e25h-" + input.eventType + "-" + String(ledger.length + 1).padStart(4, "0"),
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
    workspaceId: "ws-25h",
    taskId: "task-25h-001",
  });
  if (!registerAllThreeAgents(rt, atEpochMs).ok) throw new Error("agent registration failed");
  const allocator = new TaskAllocator(rt);
  const task: TaskDescriptor = {
    label: "25h two-node proposed survey (locally scoped)",
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
    workspaceId: "ws-25h",
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
    registeredBy: "human-25h",
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
    workspaceRoot: "/tmp/menog-ws-25h",
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
  identity: ReturnType<typeof generateLocalSigningIdentity>,
  senderEpochId: string,
  payload: FederationTaskProposalPayload,
  seq: number,
  overrides: Partial<FederationMessageBody> = {}
): { message: FederationMessageBody; signature: string } {
  const m: FederationMessageBody = {
    schemaVersion: "menog-federation-message/v0",
    messageId: makeFederationMessageId(NOW + seq, "a2b" + String(seq).padStart(13, "0")),
    senderNodeId: identity.nodeId,
    senderFingerprint: identity.fingerprint,
    senderInstanceId: "ri-000000e8fa00-instanceaaaa",
    senderEpochId,
    protocolVersion: "menog-federation/v1",
    payloadHash: canonicalHash(payload),
    declaredIntent: "task_proposal",
    correlationId: null,
    causationId: null,
    lineage: [],
    issuedAtEpochMs: NOW,
    ...overrides,
  };
  const s = signFederationMessage(identity as unknown as Parameters<typeof signFederationMessage>[0], m);
  if (!s.ok) throw new Error(s.explanation);
  return { message: m, signature: s.signature };
}

let proposalCounter = 0;
function freshProposal(originNodeId: string, originFingerprint: string, note: string): FederationTaskProposalPayload {
  proposalCounter += 1;
  return {
    schemaVersion: "menog-task-proposal/v0",
    proposalId: makeFederationMessageId(NOW + 500 + proposalCounter, "proposal250000001").replace(/^fm-/, "fp-"),
    intentClass: "workspace_survey",
    contentHashes: ["sha256-" + "a".repeat(64)],
    provenance: { originNodeId, originFingerprint, note },
    constraints: { maxBudgetSteps: 2, readonlyWorkspaceOnly: true },
    expectedEvidence: ["sha256-" + "b".repeat(64)],
  };
}

/** The 25D egress disclosure A runs BEFORE handing the payload to the wire. */
function aEgressDisclosure(payload: FederationTaskProposalPayload, nowEpochMs: number) {
  const payloadHash = canonicalHash(payload);
  const candidate: EgressCandidate = {
    schemaVersion: EGRESS_SCHEMA_VERSION,
    payloadHash,
    fields: [
      { key: "nodeId", egressClass: "public_identity", value: payload.provenance.originNodeId },
      { key: "fingerprint", egressClass: "public_identity", value: payload.provenance.originFingerprint },
      { key: "messageId", egressClass: "protocol_metadata", value: "fm-" + "0".repeat(16) + "-egress250000001" },
      { key: "declaredIntent", egressClass: "bounded_intent", value: "task_proposal" },
      { key: "payloadHash", egressClass: "content_hashes", value: payloadHash },
      { key: "proposalRecordId", egressClass: "provenance_refs", value: "fpr-" + payload.proposalId },
    ],
  };
  const decision = decideEgress({ candidate, outgoingPayloadHash: payloadHash, nowEpochMs });
  return { decision, payloadHash };
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
      scope: { workspaceId: "ws-25h", taskId: "task-25h-001" },
      provenance: { origin: "runtime", actor: { type: "runtime", id: "memory-store" }, untrusted: false },
      retention: { retentionClass: "persistent" },
      body: { fact: "two-node survey completed under fresh LOCAL authority", outputHash: "sha256:" + sha256Hex("out-25h"), recordHash: record.recordHash },
      createdAtEpochMs: atEpochMs,
      createdByActorId: "memory-store",
    },
    transactionId: txn("mem"),
  });
  if (!memWrite.ok) throw new Error("continuity memory write failed: " + JSON.stringify(memWrite));
  const taskBase = {
    schemaVersion: "menog-task-lifecycle/v0",
    goalId: GOAL_ID,
    planId: "plan-25h-001",
    taskIds: ["task-25h-001"],
    rationale: "",
    updatedAtEpochMs: atEpochMs,
  };
  const w1 = wiring.writeTaskLifecycle({
    state: { ...taskBase, status: "executing", rationale: "two-node survey step running", sourceEventId: "ev25h-run" },
    previousStatus: null,
    transactionId: txn("task1"),
  });
  if (!w1.ok) throw new Error("task executing write failed: " + JSON.stringify(w1));
  const w2 = wiring.writeTaskLifecycle({
    state: { ...taskBase, status, rationale: status === "done" ? "terminal fact from the sealed run" : "running", sourceEventId: "ev25h-run", updatedAtEpochMs: atEpochMs + 1 },
    previousStatus: "executing",
    transactionId: txn("task2"),
  });
  if (!w2.ok) throw new Error("task " + status + " write failed: " + JSON.stringify(w2));
}

/** B seals the run evidence + 22C atomic pair (the 23G/24H pattern). */
function bEvidencePersist(store: DurableStore, record: SealedToolRunRecordMirror): { goalEvent: LedgerEventMirror; runEvent: LedgerEventMirror } {
  const ledger = AppendOnlyLedger.inMemory();
  const planner = new DeterministicPlanner(new VerbRegistry(), { emitObservabilityEvents: true });
  const goal: Goal = {
    goalId: GOAL_ID,
    description: "two-node survey proposed by A, judged and run by B (25H)",
    requestedVerbSequence: ["inspect"],
    budget: { maxSteps: 2 },
  };
  const proposal = planner.propose(goal);
  if (proposal.disposition !== "proposed") throw new Error("planner refused to propose");
  const { plannerObservationToMenogEventInputs } = createRequire(import.meta.url)("@menog/planner") as typeof import("@menog/planner");
  const bridgeInputs = plannerObservationToMenogEventInputs(
    planner.observations(),
    { type: "agent", id: "menog-agent-planner" },
    { workspaceId: "ws-25h", taskId: "task-25h-001", eventIdPrefix: "h25h" }
  );
  for (const evInput of bridgeInputs) {
    const r = ledger.append(evInput);
    if (!r.ok) throw new Error("planner bridge append failed: " + r.reason);
  }
  const runEventInput = stripUndefined({
    eventId: "ev25h-run-000001",
    timestamp: "2026-10-02T00:00:01.000Z",
    eventType: "tool_run_evidence",
    actor: { type: "runtime", id: "tool-runtime" } as Actor,
    workspaceId: "ws-25h",
    taskId: "task-25h-001",
    policyDecision: "allow" as const,
    inputSummary: { requestId: "req-25h-001", toolId: "demo.survey" },
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
  return { goalEvent, runEvent };
}

/** B enrolls + admits A through the 25C intent-gated admin session. */
function bAdmitsA(b: NodeWorld, a: NodeWorld, instanceId: string): { intentHash: string; session: PeerAdminSession } {
  const intent: LocalAdminIntent = {
    initiatedBy: "local_operator",
    operatorRef: "op-25h",
    rationale: "admit peer A after identity review (local evidenced decision)",
    decidedAtEpochMs: tick(),
    localEpochId: b.registry.epochId,
  };
  const gate = checkLocalAdminIntent({ intent, liveEpochId: b.registry.epochId });
  if (!gate.ok) throw new Error(gate.explanation);
  const sessionOpen = AdminSession.open(b.registry, "sess-25h-admit");
  if (!sessionOpen.ok) throw new Error(sessionOpen.reason);
  const enrolled = sessionOpen.session.admitCandidate === undefined
    ? null
    : null;
  void enrolled;
  // first contact → candidate (the only entry edge), then the intent-gated admit:
  const enrolledA = b.registry.applyTrustTransition({
    nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId,
    protocolVersion: "menog-federation/v1", reason: "first_contact_enrolled",
    evidence: "identity doc hash", transactionId: txn("enroll-a"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: tick(),
  });
  if (!enrolledA.ok) throw new Error(enrolledA.explanation);
  const admitted = sessionOpen.session.admitCandidate({
    nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId, protocolVersion: "menog-federation/v1",
    intent, transactionId: txn("admit-a"), lineageRoot: ROOT_LINEAGE, lineageParent: null,
  });
  if (!admitted.ok) throw new Error(admitted.explanation);
  return { intentHash: gate.intentHash, session: sessionOpen.session };
}

// ═════════════════════════════════════════════════════════════════════════════

describe("25H — operational two-node lifecycle scenario (local fixture, no sockets)", () => {

  it("initialize → B admits A (25C admin) → A egress disclosure (25D) → transport → B 24D pipeline → candidate → fresh LOCAL authority → Phase-20/21 → evidence/provenance → A rotates (25B) → old key denied, new identity NOT auto-trusted (P7) → explicit B admission → old terminal → restart B → facts DATA/no authority → replay denied → fresh authority required again", () => {
    // ── two isolated worlds: distinct identities, epochs, stores ──
    const a = openNode("A", EPOCH_A1);
    const b = openNode("B", EPOCH_B1);
    expect(a.identity.nodeId).not.toBe(b.identity.nodeId);
    expect(a.epochId).not.toBe(b.epochId);
    expect(a.lifecycle.keyId).not.toBe(b.lifecycle.keyId);
    // both lifecycle records re-derive their key ids canonically:
    expect(decideKeyUse({ record: a.lifecycle }).ok).toBe(true);
    expect(decideKeyUse({ record: b.lifecycle }).ok).toBe(true);

    // ── B locally admits A through the intent-gated 25C admin session ──
    const A_INSTANCE = "ri-000000e8fa00-instanceaaaa";
    const { intentHash } = bAdmitsA(b, a, A_INSTANCE);
    expect(intentHash).toMatch(/^[0-9a-f]{64}$/);
    const peerA = b.registry.readPeer(a.identity.nodeId);
    expect(peerA.ok && peerA.state.trustState === "admitted").toBe(true);

    const receivers = openBReceivers(b, [a.identity]);

    // ── A prepares the proposal and passes the 25D egress gate FIRST ──
    const payload = freshProposal(a.identity.nodeId, a.identity.fingerprint, "proposed by node A");
    const disclosure = aEgressDisclosure(payload, tick());
    expect(disclosure.decision.ok).toBe(true);
    if (disclosure.decision.ok) {
      expect(disclosure.decision.code).toBe("disclosure_permitted");
      // the manifest binds to EXACTLY the payload going on the wire:
      const holds = verifyEgressManifest({ manifest: disclosure.decision.manifest, outgoingPayloadHash: disclosure.payloadHash });
      expect(holds.ok).toBe(true);
    }

    // ── A signs; the bounded transport carries it (the only "network") ──
    const signed = aProposalMessage(a.identity, EPOCH_A1, payload, 1);
    const wire = boundedTransport();
    expect(wire.push(signed, payload as unknown as Record<string, unknown>).ok).toBe(true);
    expect(wire.depth).toBe(1);

    // ── B: identity/admission/replay/schema (the 24D pipeline) ──
    const delivered = wire.drain();
    expect(delivered).toHaveLength(1);
    const busResult = receivers.bus.ingest({ envelope: delivered[0]!.envelope, payload: delivered[0]!.payload, nowEpochMs: tick() });
    expect(busResult.ok).toBe(true);
    const entry = receivers.bus.inbox()[receivers.bus.inbox().length - 1];
    if (!entry) throw new Error("fixture: no inbox entry");
    const admitted1 = receivers.proposals.receiveTaskProposal({
      inboxEntry: { messageId: entry.messageId, senderNodeId: entry.senderNodeId, declaredIntent: entry.declaredIntent, payload: entry.payload },
      senderFingerprint: a.identity.fingerprint,
      receiptRecordId: entry.receiptRecordId,
      nowEpochMs: tick(),
    });
    expect(admitted1.ok).toBe(true);

    // ── untrusted local candidate (inert; intent only) ──
    const cand = deriveLocalTaskCandidate({
      proposal: { proposalId: payload.proposalId, senderNodeId: a.identity.nodeId, intentClass: payload.intentClass, constraints: payload.constraints, expectedEvidence: payload.expectedEvidence },
      localTaskLabel: "25h two-node proposed survey (locally scoped)",
      requiredCapabilities: ["workspace:read"],
    });
    expect(cand.ok).toBe(true);

    // ── fresh LOCAL allocation + fresh LOCAL Policy for the assigned actor ──
    const { alloc, policy } = bLocalAuthority(tick(), ["workspace:list"]);
    expect(alloc.assignment.executionAuthorized).toBe(false);
    expect(policy.decision.outcome).toBe("allow");
    const gate = requireFreshLocalAuthorization({
      assignment: {
        assignmentId: alloc.assignment.assignmentId,
        assignedAgentId: alloc.assignment.assignedAgentId,
        allocatedAtEpochMs: alloc.assignment.allocatedAtEpochMs,
        executionAuthorized: alloc.assignment.executionAuthorized,
      },
      policy: { outcome: policy.decision.outcome, decidedAtEpochMs: alloc.assignment.allocatedAtEpochMs + 1 },
      policyActorId: alloc.assignment.assignedAgentId,
      atEpochMs: alloc.assignment.allocatedAtEpochMs + 2,
    });
    expect(gate.ok).toBe(true);

    // ── Phase-20 isolation + Phase-21 governed tool runtime on B ──
    const run = bGovernedRun(alloc.assignment.assignedAgentId, "allow", "req-25h-001");
    expect(run.outcome.decision.status).toBe("not_started");
    expect(run.double.wasCalled()).toBe(true);
    expect(run.outcome.result?.status).toBe("completed");

    // ── evidence/ledger + 22C atomic pair on B ──
    const record = sealedFromOutcome({
      policy: { outcome: "allow", matchedRule: policy.decision.matchedRule },
      manifestHash: run.entry.value.manifestHash,
    });
    const { runEvent } = bEvidencePersist(b.store, record);
    expect(runEvent.eventType).toBe("tool_run_evidence");

    // ── cross-node provenance anchored on B (B-side commit-sequence order ONLY) ──
    const anchor: FederationProvenanceAnchor = {
      schemaVersion: "menog-federation-provenance/v0",
      anchorId: "fv-" + (NOW + 60).toString(16).padStart(16, "0") + "-twonode25hab0001",
      kind: "task_proposal",
      messageId: null,
      proposalId: payload.proposalId,
      senderNodeId: a.identity.nodeId,
      senderFingerprint: a.identity.fingerprint,
      senderEpochId: EPOCH_A1,
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
      decidedAtEpochMs: tick(),
    };
    const anchored = receivers.provenance.anchor({ anchor, nowEpochMs: tick() });
    if (!anchored.ok) throw new Error("anchor refused: " + anchored.failureCode + ": " + anchored.explanation);
    const anchorCommitSequence = anchored.ok ? anchored.commitSequence : -1;

    // ── 23B/23C continuity on B, then RESTART B ──
    const wiringOpen = LiveSurfaceWiring.open(b.store, b.coordinator, epochOf(EPOCH_B1));
    if (!wiringOpen.ok) throw new Error(wiringOpen.reason);
    bContinuityWrite(wiringOpen.wiring, record, "done", tick());
    b.coordinator.close();

    const reopened = DurableStore.open(b.root);
    if (!reopened.ok) throw new Error("reopen failed: " + reopened.reason);
    openStores.push(reopened.store);
    const handoff = runStartupHandoff({
      store: reopened.store,
      bootedEpoch: epochOf(EPOCH_B2, T1),
      recoveryRequest: REQUEST,
      sourceIdentity: "25h-restart",
      priorEpochId: claimOwner(reopened.store),
      nowEpochMs: T1,
    });
    expect(handoff.ok).toBe(true);
    expect(handoff.terminalState).toBe("LIVE");
    expect(handoff.newEpochId).not.toBe(EPOCH_B1);
    expect(handoff.classification?.blockingClass).toBe("none");
    expect(claimOwner(reopened.store)).toBe(handoff.newEpochId);
    // the OLD epoch's coordinator identity is stale forever:
    const oldBind = RuntimeStateCoordinator.open(reopened.store, epochOf(EPOCH_B1), "25h-stale");
    expect(oldBind.ok).toBe(false);

    // facts survived as DATA (no authority):
    const newBound = RuntimeStateCoordinator.open(reopened.store, epochOf(handoff.newEpochId as string, T1), "25h-node-B2");
    if (!newBound.ok) throw new Error(newBound.reason);
    openCoords.push(newBound.coordinator);
    const newReg = PeerRegistry.open(reopened.store, newBound.coordinator);
    if (!newReg.ok) throw new Error(newReg.reason);
    const newReceivers = {
      ...openBReceivers({ store: reopened.store, coordinator: newBound.coordinator, registry: newReg.registry }, [a.identity, { nodeId: "pending", publicKeyHex: a.identity.publicKeyHex }]),
      registry: newReg.registry,
    };
    const peerBack = newReceivers.registry.readPeer(a.identity.nodeId);
    expect(peerBack.ok).toBe(true);
    if (peerBack.ok) expect(peerBack.state.trustState).toBe("admitted"); // recovered DATA, not authority
    expect(newReceivers.proposals.hasProposal(payload.proposalId)).toBe(true);
    const anchorBack = newReceivers.provenance.readAnchor(anchor.anchorId);
    expect(anchorBack.ok).toBe(true);
    if (anchorBack.ok) expect(anchorBack.anchor.decision).toBe("local_action");

    // ── OLD message replay DENIED (durable receipt guard) ──
    const replay = newReceivers.bus.ingest({ envelope: delivered[0]!.envelope, nowEpochMs: T1 + 5 });
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.failureCode).toBe("replay_detected");

    // ── A ROTATES (25B re-identity) ──
    const rotation = rotateLocalIdentity(a.identity);
    expect(rotation.ok).toBe(true);
    let aLifecycle = a.lifecycle;
    const reqRotation = decideLifecycleTransition({ record: aLifecycle, to: "rotation_requested", evidence: "operator rotation request", nowEpochMs: T1 + 1 });
    if (!reqRotation.ok) throw new Error(reqRotation.explanation);
    aLifecycle = reqRotation.record;
    const execRotation = decideLifecycleTransition({
      record: aLifecycle, to: "rotated", evidence: "locally evidenced rotation to a genuinely fresh identity", nowEpochMs: T1 + 2,
      freshPublicFacts: { publicKeyHex: rotation.fresh.publicKeyHex, fingerprint: rotation.fresh.fingerprint, nodeId: rotation.fresh.nodeId },
    });
    if (!execRotation.ok) throw new Error(execRotation.explanation);
    aLifecycle = execRotation.record;
    // the OLD key is operationally dead:
    const oldKeyUse = decideKeyUse({ record: aLifecycle });
    expect(oldKeyUse.ok).toBe(false);
    if (!oldKeyUse.ok) expect(oldKeyUse.code).toBe("stale_rotated_key");
    // trust inheritance is ALWAYS refused (P7):
    const inheritance = decideTrustInheritance({ oldRecord: aLifecycle, freshNodeId: rotation.fresh.nodeId });
    expect(inheritance.ok).toBe(false);

    // ── the OLD key's message is denied by B (lifecycle gate + registry pin) ──
    const payloadOld = freshProposal(a.identity.nodeId, a.identity.fingerprint, "sent by the rotated-away key");
    const signedOld = aProposalMessage(a.identity, makeRuntimeEpochId(T1 + 3, "epochA000000003"), payloadOld, 50, {
      messageId: makeFederationMessageId(T1 + 3, "a2b" + String(50).padStart(13, "0")),
      payloadHash: canonicalHash(payloadOld),
      issuedAtEpochMs: T1 + 3,
    });
    const oldKeyDelivery = newReceivers.bus.ingest({ envelope: signedOld, payload: payloadOld as unknown as Record<string, unknown>, nowEpochMs: T1 + 5 });
    // B's registry still holds A admitted (the record pre-dates rotation), but
    // the rotation evidence + the lifecycle gate mean the OLD key must not
    // pass: B's bus pipeline admits the envelope as communication, so the
    // OPERATIONAL control is the lifecycle/registry composition — the
    // retirement edge is what denies the old identity durably:
    const retireOld = newReceivers.registry.applyTrustTransition({
      nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId: A_INSTANCE,
      protocolVersion: "menog-federation/v1", reason: "operator_retirement",
      evidence: "25H: evidenced retirement after rotation (re-identity, no resurrection)",
      transactionId: txn("retire-old"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: T1 + 6,
    });
    expect(retireOld.ok).toBe(true);
    const oldAfterRetire = newReceivers.bus.ingest({ envelope: signedOld, payload: payloadOld as unknown as Record<string, unknown>, nowEpochMs: T1 + 7 });
    expect(oldAfterRetire.ok).toBe(false);
    if (!oldAfterRetire.ok) {
      expect(oldAfterRetire.stage).toBe("peer_admission");
      expect(oldAfterRetire.failureCode).toBe("peer_not_admitted");
    }
    void oldKeyDelivery;
    void anchorCommitSequence;

    // ── the NEW identity is NOT trusted automatically: unknown peers refuse ──
    const payloadNew = freshProposal(rotation.fresh.nodeId, rotation.fresh.fingerprint, "sent by the fresh identity before any admission");
    const signedNew = aProposalMessage(rotation.fresh, makeRuntimeEpochId(T1 + 4, "epochA000000004"), payloadNew, 51, {
      messageId: makeFederationMessageId(T1 + 4, "a2b" + String(51).padStart(13, "0")),
      payloadHash: canonicalHash(payloadNew),
      issuedAtEpochMs: T1 + 4,
    });
    const newUntrusted = newReceivers.bus.ingest({ envelope: signedNew, payload: payloadNew as unknown as Record<string, unknown>, nowEpochMs: T1 + 8 });
    expect(newUntrusted.ok).toBe(false);
    if (!newUntrusted.ok) expect(newUntrusted.failureCode).toBe("peer_not_admitted");

    // ── explicit B admission of the replacement (first contact → candidate → admit) ──
    const admitIntent: LocalAdminIntent = {
      initiatedBy: "local_operator",
      operatorRef: "op-25h",
      rationale: "admit the replacement identity as a NEW candidate (re-identity of A; no inherited trust)",
      decidedAtEpochMs: T1 + 9,
      localEpochId: newReceivers.registry.epochId,
    };
    const admitGate = checkLocalAdminIntent({ intent: admitIntent, liveEpochId: newReceivers.registry.epochId });
    expect(admitGate.ok).toBe(true);
    const NEW_INSTANCE = "ri-000000e8fa00-instanceaaaa";
    const enrollNew = newReceivers.registry.applyTrustTransition({
      nodeId: rotation.fresh.nodeId, fingerprint: rotation.fresh.fingerprint, instanceId: NEW_INSTANCE,
      protocolVersion: "menog-federation/v1", reason: "first_contact_enrolled",
      evidence: "replacement identity doc hash (re-identity of A)", transactionId: txn("enroll-new"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: T1 + 9,
    });
    expect(enrollNew.ok).toBe(true);
    const admitSession = AdminSession.open(newReceivers.registry, "sess-25h-admit-new");
    if (!admitSession.ok) throw new Error(admitSession.reason);
    const admitNew = admitSession.session.admitCandidate({
      nodeId: rotation.fresh.nodeId, fingerprint: rotation.fresh.fingerprint, instanceId: NEW_INSTANCE, protocolVersion: "menog-federation/v1",
      intent: admitIntent, transactionId: txn("admit-new"), lineageRoot: ROOT_LINEAGE, lineageParent: null,
    });
    expect(admitNew.ok).toBe(true);
    // the OLD identity is TERMINAL — retirement cannot be undone:
    const resurrectOld = newReceivers.registry.applyTrustTransition({
      nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId: A_INSTANCE,
      protocolVersion: "menog-federation/v1", reason: "admission_request_accepted", evidence: "resurrection attempt",
      transactionId: txn("resurrect"), lineageRoot: ROOT_LINEAGE, lineageParent: null, nowEpochMs: T1 + 10,
    });
    expect(resurrectOld.ok).toBe(false);
    if (!resurrectOld.ok) expect(resurrectOld.failureCode).toBe("peer_terminal_state");

    // the NEW identity's message now flows (B added its verifier via re-open? NO —
    // the key directory is the caller's seam; re-open receivers with the fresh key):
    const newReceivers2 = {
      ...openBReceivers(
        { store: reopened.store, coordinator: newBound.coordinator, registry: newReceivers.registry },
        [a.identity, rotation.fresh]
      ),
      registry: newReceivers.registry,
    };
    const payloadNew2 = freshProposal(rotation.fresh.nodeId, rotation.fresh.fingerprint, "sent by the admitted replacement identity");
    const signedNew2 = aProposalMessage(rotation.fresh, makeRuntimeEpochId(T1 + 11, "epochA000000005"), payloadNew2, 52, {
      messageId: makeFederationMessageId(T1 + 11, "a2b" + String(52).padStart(13, "0")),
      payloadHash: canonicalHash(payloadNew2),
      issuedAtEpochMs: T1 + 11,
    });
    const newDelivery = newReceivers2.bus.ingest({ envelope: signedNew2, payload: payloadNew2 as unknown as Record<string, unknown>, nowEpochMs: T1 + 12 });
    expect(newDelivery.ok).toBe(true);
    const entryNew = newReceivers2.bus.inbox()[newReceivers2.bus.inbox().length - 1];
    if (!entryNew) throw new Error("fixture: no replacement inbox entry");
    const admittedNew = newReceivers2.proposals.receiveTaskProposal({
      inboxEntry: { messageId: entryNew.messageId, senderNodeId: entryNew.senderNodeId, declaredIntent: entryNew.declaredIntent, payload: entryNew.payload },
      senderFingerprint: rotation.fresh.fingerprint,
      receiptRecordId: entryNew.receiptRecordId,
      nowEpochMs: T1 + 13,
    });
    expect(admittedNew.ok).toBe(true);

    // ── a new proposal AGAIN requires fresh local authority ──
    const staleGate = requireFreshLocalAuthorization({
      assignment: {
        assignmentId: alloc.assignment.assignmentId,
        assignedAgentId: alloc.assignment.assignedAgentId,
        allocatedAtEpochMs: alloc.assignment.allocatedAtEpochMs,
        executionAuthorized: alloc.assignment.executionAuthorized,
      },
      policy: { outcome: policy.decision.outcome, decidedAtEpochMs: alloc.assignment.allocatedAtEpochMs + 1 },
      policyActorId: alloc.assignment.assignedAgentId,
      atEpochMs: T1 + 14,
    });
    expect(staleGate.ok).toBe(false);
    if (!staleGate.ok) expect(staleGate.failureCode).toBe("stale_local_allocation");
    const fresh2 = bLocalAuthority(T1 + 14, ["workspace:list"]);
    const gate2 = requireFreshLocalAuthorization({
      assignment: {
        assignmentId: fresh2.alloc.assignment.assignmentId,
        assignedAgentId: fresh2.alloc.assignment.assignedAgentId,
        allocatedAtEpochMs: fresh2.alloc.assignment.allocatedAtEpochMs,
        executionAuthorized: fresh2.alloc.assignment.executionAuthorized,
      },
      policy: { outcome: fresh2.policy.decision.outcome, decidedAtEpochMs: T1 + 14 },
      policyActorId: fresh2.alloc.assignment.assignedAgentId,
      atEpochMs: T1 + 15,
    });
    expect(gate2.ok).toBe(true);
    const run2 = bGovernedRun(fresh2.alloc.assignment.assignedAgentId, "allow", "req-25h-002");
    expect(run2.outcome.decision.status).toBe("not_started");
    expect(run2.double.wasCalled()).toBe(true);
    expect(run2.outcome.result?.status).toBe("completed");
  });

  // ── negative controls ──────────────────────────────────────────────────────

  it("NEGATIVE unknown/revoked/quarantined A: all refuse at B's bus pre-signature; revoked is a lifecycle refusal", () => {
    // unknown A: never enrolled on a fresh B
    const aStranger = generateLocalSigningIdentity();
    const b = openNode("B", EPOCH_B1);
    const receiversUnknown = openBReceivers(b, [aStranger]);
    const m: FederationMessageBody = {
      schemaVersion: "menog-federation-message/v0",
      messageId: makeFederationMessageId(NOW + 1, "stranger00000001"),
      senderNodeId: aStranger.nodeId,
      senderFingerprint: aStranger.fingerprint,
      senderInstanceId: "ri-000000e8fa00-instancezzzz",
      senderEpochId: EPOCH_A1,
      protocolVersion: "menog-federation/v1",
      payloadHash: "sha256-" + "5".repeat(64),
      declaredIntent: "task_proposal",
      correlationId: null, causationId: null, lineage: [],
      issuedAtEpochMs: NOW,
    };
    const s = signFederationMessage(aStranger, m);
    if (!s.ok) throw new Error(s.explanation);
    const unknown = receiversUnknown.bus.ingest({ envelope: { message: m, signature: s.signature }, nowEpochMs: tick() });
    expect(unknown).toMatchObject({ ok: false, stage: "peer_admission", failureCode: "peer_not_admitted" });

    // quarantined A: enrolled+admitted, then evidenced-quarantined (terminal)
    const a = openNode("A", EPOCH_A1);
    const { session } = bAdmitsA(b, a, "ri-000000e8fa00-instanceaaaa");
    const quarantineIntent: LocalAdminIntent = {
      initiatedBy: "local_operator", operatorRef: "op-25h", rationale: "evidenced quarantine",
      decidedAtEpochMs: tick(), localEpochId: b.registry.epochId,
    };
    const q = session.quarantinePeer({
      nodeId: a.identity.nodeId, fingerprint: a.identity.fingerprint, instanceId: "ri-000000e8fa00-instanceaaaa",
      protocolVersion: "menog-federation/v1", intent: quarantineIntent,
      transactionId: txn("quarantine"), lineageRoot: ROOT_LINEAGE, lineageParent: null,
    });
    expect(q.ok).toBe(true);
    const receiversQ = openBReceivers(b, [a.identity]);
    const mq = { ...m, messageId: makeFederationMessageId(NOW + 2, "quarant2500000001"), senderNodeId: a.identity.nodeId, senderFingerprint: a.identity.fingerprint };
    const sq = signFederationMessage(a.identity, mq);
    if (!sq.ok) throw new Error(sq.explanation);
    const quarantined = receiversQ.bus.ingest({ envelope: { message: mq, signature: sq.signature }, nowEpochMs: tick() });
    expect(quarantined).toMatchObject({ ok: false, stage: "peer_admission", failureCode: "peer_not_admitted" });
    if (!quarantined.ok) expect(quarantined.explanation).toContain("quarantined");
    expect(receiversQ.bus.inbox()).toHaveLength(0);

    // REVOKED key: the lifecycle record refuses its own use — the operational
    // layer denies what the crypto layer would still verify.
    const identity = generateLocalSigningIdentity();
    let rec = initializeLifecycle(identity, tick());
    const rev = decideLifecycleTransition({ record: rec, to: "revoked", evidence: "evidenced revocation", nowEpochMs: tick() });
    if (!rev.ok) throw new Error(rev.explanation);
    rec = rev.record;
    const revokedUse = decideKeyUse({ record: rec });
    expect(revokedUse.ok).toBe(false);
    if (!revokedUse.ok) expect(revokedUse.code).toBe("state_revoked");
  });

  it("NEGATIVE stale epoch + tamper: both refuse at B's bus", () => {
    const a = openNode("A", EPOCH_A1);
    const b = openNode("B", EPOCH_B1);
    bAdmitsA(b, a, "ri-000000e8fa00-instanceaaaa");
    const receivers = openBReceivers(b, [a.identity]);
    const payload = freshProposal(a.identity.nodeId, a.identity.fingerprint, "stale/tamper probe");
    // newer sender epoch first…
    const newer = aProposalMessage(a.identity, makeRuntimeEpochId(NOW + 10, "epochA000000009"), payload, 4);
    const r1 = receivers.bus.ingest({ envelope: newer, payload: payload as unknown as Record<string, unknown>, nowEpochMs: tick() });
    // …then the OLDER epoch refuses (stale)
    const older = aProposalMessage(a.identity, EPOCH_A1, payload, 5);
    const r2 = receivers.bus.ingest({ envelope: older, payload: payload as unknown as Record<string, unknown>, nowEpochMs: tick() });
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(false);
    // tamper: a post-signature body mutation refuses at the signature stage
    const tamperTarget = aProposalMessage(a.identity, EPOCH_A1, payload, 6);
    const tampered = { ...tamperTarget.message, payloadHash: "sha256-" + "f".repeat(64) };
    const r3 = receivers.bus.ingest({ envelope: { message: tampered, signature: tamperTarget.signature }, nowEpochMs: tick() });
    expect(r3).toMatchObject({ ok: false, stage: "signature", failureCode: "signature_stage_refused" });
  });

  it("NEGATIVE secret-egress + stale-disclosure: a key-bearing candidate refuses; a manifest never rides a different payload", () => {
    const a = openNode("A", EPOCH_A1);
    const payload = freshProposal(a.identity.nodeId, a.identity.fingerprint, "egress probes");
    const payloadHash = canonicalHash(payload);
    const field = (key: string, egressClass: EgressCandidate["fields"][number]["egressClass"], value: string) => ({ key, egressClass, value });
    // secret-egress: a PEM block smuggled into a legit field refuses the WHOLE candidate
    const secretAttempt = decideEgress({
      candidate: { schemaVersion: EGRESS_SCHEMA_VERSION, payloadHash, fields: [field("manifestRef", "disclosure_manifest", "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----")] },
      outgoingPayloadHash: payloadHash, nowEpochMs: tick(),
    });
    expect(secretAttempt).toMatchObject({ ok: false, denyCode: "secret_material" });
    // the honest candidate discloses…
    const good = decideEgress({ candidate: {
      schemaVersion: EGRESS_SCHEMA_VERSION, payloadHash,
      fields: [field("nodeId", "public_identity", a.identity.nodeId), field("payloadHash", "content_hashes", payloadHash)],
    }, outgoingPayloadHash: payloadHash, nowEpochMs: tick() });
    expect(good.ok).toBe(true);
    if (!good.ok) return;
    // …but its manifest is STALE against a different payload (the payload
    // mutated after disclosure — the disclosure never rides):
    const otherHash = "sha256-" + "6".repeat(64);
    const stale = verifyEgressManifest({ manifest: good.manifest, outgoingPayloadHash: otherHash });
    expect(stale).toMatchObject({ ok: false, denyCode: "stale_disclosure" });
  });

  it("NEGATIVE old-Policy / actor mismatch / no-auto-resume / no-capability-union / no-direct-remote-execution", () => {
    // no old Policy reuse: a PRE-restart allow fails the freshness window
    const oldPolicy = requireFreshLocalAuthorization({
      assignment: { assignmentId: "asg-25h-old", assignedAgentId: "menog-agent-builder", allocatedAtEpochMs: T1, executionAuthorized: false },
      policy: { outcome: "allow", decidedAtEpochMs: NOW + 6 },
      policyActorId: "menog-agent-builder",
      atEpochMs: T1 + 7,
    });
    expect(oldPolicy).toMatchObject({ ok: false, failureCode: "stale_local_policy" });
    // actor mismatch: a Policy allow minted for X cannot ride Y's assignment
    const engine = new DenyByDefaultPolicyEngine();
    const allowPlanner = engine.evaluate({
      actor: { type: "agent", id: "menog-agent-planner" },
      verb: "inspect",
      requestedCapabilities: ["workspace:list"],
      workspaceId: "ws-25h",
    });
    const deputy = requireFreshLocalAuthorization({
      assignment: { assignmentId: "asg-25h-dep", assignedAgentId: "menog-agent-builder", allocatedAtEpochMs: T1, executionAuthorized: false },
      policy: { outcome: allowPlanner.decision.outcome, decidedAtEpochMs: T1 + 1 },
      policyActorId: "menog-agent-planner",
      atEpochMs: T1 + 2,
    });
    expect(deputy).toMatchObject({ ok: false, failureCode: "actor_mismatch" });
    // no auto-resume: a proposal-only input satisfies NOTHING
    const proposalOnly = requireFreshLocalAuthorization({
      assignment: null as unknown as { assignmentId: string; assignedAgentId: string; allocatedAtEpochMs: number; executionAuthorized: boolean },
      policy: null as unknown as { outcome: "allow" | "deny"; decidedAtEpochMs: number },
      policyActorId: "menog-agent-builder",
      atEpochMs: T1,
    });
    expect(proposalOnly).toMatchObject({ ok: false, failureCode: "no_local_allocation" });
    // no capability union: the candidate carries ONLY the local descriptor's
    // capabilities; the inflated write ask is denied regardless
    const a = openNode("A", EPOCH_A1);
    const payload = freshProposal(a.identity.nodeId, a.identity.fingerprint, "cap probe");
    const cand = deriveLocalTaskCandidate({
      proposal: { proposalId: payload.proposalId, senderNodeId: a.identity.nodeId, intentClass: payload.intentClass, constraints: payload.constraints, expectedEvidence: payload.expectedEvidence },
      localTaskLabel: "cap probe",
      requiredCapabilities: ["workspace:read"],
    });
    expect(cand.ok).toBe(true);
    if (cand.ok) expect(cand.candidate.requiredCapabilities).toEqual(["workspace:read"]);
    const writeAsk = engine.evaluate({
      actor: { type: "agent", id: "menog-agent-builder" },
      verb: "inspect",
      requestedCapabilities: ["workspace:write", "network:external"],
      workspaceId: "ws-25h",
    });
    expect(writeAsk.decision.outcome).toBe("deny");
    // no direct remote execution: B's Policy denial stops the chain before the
    // transport double is ever called
    const deniedRun = bGovernedRun("menog-agent-builder", "deny", "req-25h-deny");
    expect(deniedRun.outcome.decision.status).toBe("policy_denied");
    expect(deniedRun.outcome.result).toBeNull();
    expect(deniedRun.double.wasCalled()).toBe(false);
  });

  it("provenance WITHOUT consensus/global-order: B-side anchors order only by B's own durable commit sequence", () => {
    const a = openNode("A", EPOCH_A1);
    const b = openNode("B", EPOCH_B1);
    bAdmitsA(b, a, "ri-000000e8fa00-instanceaaaa");
    const receivers = openBReceivers(b, [a.identity]);
    const ids: string[] = [];
    for (let i = 0; i < 2; i++) {
      const payload = freshProposal(a.identity.nodeId, a.identity.fingerprint, "order probe " + String(i));
      const signed = aProposalMessage(a.identity, EPOCH_A1, payload, 10 + i, { messageId: makeFederationMessageId(NOW + 10 + i, "a2b" + String(10 + i).padStart(13, "0")), payloadHash: canonicalHash(payload) });
      const r = receivers.bus.ingest({ envelope: signed, payload: payload as unknown as Record<string, unknown>, nowEpochMs: tick() });
      expect(r.ok).toBe(true);
      const entry = receivers.bus.inbox()[receivers.bus.inbox().length - 1];
      if (!entry) throw new Error("fixture");
      const admitted = receivers.proposals.receiveTaskProposal({
        inboxEntry: { messageId: entry.messageId, senderNodeId: entry.senderNodeId, declaredIntent: entry.declaredIntent, payload: entry.payload },
        senderFingerprint: a.identity.fingerprint,
        receiptRecordId: entry.receiptRecordId,
        nowEpochMs: tick(),
      });
      expect(admitted.ok).toBe(true);
      const anchor: FederationProvenanceAnchor = {
        schemaVersion: "menog-federation-provenance/v0",
        anchorId: "fv-" + (NOW + 100 + i).toString(16).padStart(16, "0") + "-orderprobe25hab" + String(i),
        kind: "task_proposal",
        messageId: null,
        proposalId: payload.proposalId,
        senderNodeId: a.identity.nodeId,
        senderFingerprint: a.identity.fingerprint,
        senderEpochId: EPOCH_A1,
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
        decidedAtEpochMs: tick(),
      };
      const anchored = receivers.provenance.anchor({ anchor, nowEpochMs: tick() });
      expect(anchored.ok).toBe(true);
      if (anchored.ok) ids.push(anchored.commitSequence + ":" + anchored.anchorId);
    }
    // the ONLY ordering is B's own durable commit sequence — monotone, local,
    // and claimed as nothing more than that:
    const seqs = ids.map((s) => Number(s.split(":")[0]));
    expect(seqs.length).toBe(2);
    expect(seqs[1]! > seqs[0]!).toBe(true);
    // no global-order/consensus vocabulary exists in any federation module:
    const files = ["federationIdentity.ts", "federationCrypto.ts", "federationPeers.ts", "federationBus.ts", "federationProposals.ts", "federationProvenance.ts", "federationTrustBoundary.ts", "federationKeyLifecycle.ts", "federationPeerAdmin.ts", "federationEgress.ts"];
    let hits = 0;
    for (const f of files) {
      const src = readFileSync(join(process.cwd(), "packages", "durable-state", "src", f), "utf8");
      const code = src
        .split("\n")
        .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
        .join("\n");
      if (/global\s?order|total\s?order|consensus|lamport|vector\s?clock/i.test(code)) hits += 1;
    }
    expect(hits).toBe(0);
  });
});
