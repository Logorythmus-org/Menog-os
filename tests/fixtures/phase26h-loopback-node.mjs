/**
 * PHASE 26H — Real Loopback Scenario node fixture (NOT a test file).
 *
 * Usage: node phase26h-loopback-node.mjs <role:A|B> <root> <port> <epochSeed> [clockSeedMs]
 *
 * TWO OS PROCESSES, REAL LOOPBACK SOCKETS, LOOPBACK ONLY. Each child owns its
 * OWN durable store, OWN runtime epoch, OWN 24B identity and OWN 25B lifecycle
 * record. Nothing is shared except the parent's explicit, evidenced LOCAL
 * admission commands.
 *
 *   role B = the RECEIVER. Opens a REAL 26B `LocalEndpointListener` on an
 *     explicit numeric loopback endpoint (127.0.0.1:<port>, explicit local
 *     config, no wildcard/discovery/environment), and inside its ONE
 *     sanctioned `onConnection` handler builds the real 26C `FramedTransport`
 *     + real 26D `openAuthenticatedSession` responder over the accepted
 *     socket, then runs the real 26E `decideTransportIngress` junction over
 *     every delivered wire frame, and — ONLY when ingress admits the message
 *     as UNTRUSTED DATA — continues into fresh LOCAL 19B allocation → fresh
 *     LOCAL Day-1 Policy for the ASSIGNED actor → `requireFreshLocalAuthorization`
 *     → Phase-20 isolation + Phase-21 governed tool runtime (injected
 *     transport double; this fixture NEVER spawns) → 22C atomic evidence pair
 *     → 23B/23C continuity → 24E proposal ledger → 24F `local_action`
 *     provenance anchor. It also runs the 26F bounded window so the reconnect
 *     decision is taken through the real 26F surface.
 *
 *   role A = the SENDER. Dials 127.0.0.1:<port> with `node:net`, runs the
 *     real 26D initiator handshake over the live socket, prepares the 25D
 *     egress disclosure BEFORE the wire, signs the frozen 24A body, and sends
 *     it as one real 26C frame. It can rotate its 24B identity (25B
 *     request→execute re-identity) and can re-send with the retired key.
 *
 * PROTOCOL (stdin, one command per line; base64-encoded JSON arguments):
 *   facts                → ok:{...}   local public facts + epoch + lifecycle state
 *   peer  <b64-json>     → ok:{...}   register a peer's public facts (see mode)
 *   admit <nodeId>       → ok:{...}   intent-gated 25C local admission
 *   retire <nodeId>      → ok:{...}   evidenced local retirement (terminal)
 *   dial  <port>         → ok:{...}   connect + real 26D handshake (role A)
 *   send  <b64-json>     → ok:{...}   send one signed envelope (role A)
 *   send-old <b64-json>  → ok:{...}   send with the RETIRED key (role A)
 *   stop                 → ok:{...}   idempotent listener stop (role B)
 *   listener             → ok:{...}   listener state + decisions + stats
 *   quit                 → ok:{...}   deterministic teardown, exit 0
 *
 * OUTPUT (stdout, one line per command): `ready:<role>` once, then
 * `ok:<json>` / `err:<json>`. A `err:{fatal:...}` line means the fixture could
 * not run the scenario and is NEVER a scenario result.
 *
 * HARD LAWS honoured here: LOCAL NETWORK ONLY (127.0.0.1 numeric literal, no
 * wildcard, no discovery, no relay, no NAT, no consensus, no remote admin, no
 * deployment, no Git, no publication). NETWORK REACHABILITY != IDENTITY !=
 * ADMISSION != AUTHORITY != EXECUTION — nothing on the wire can carry an
 * allocation, a Policy decision, an actor binding, a capability grant or a tool
 * invocation. No private key material is ever printed, logged or persisted.
 */
import { mkdirSync } from "node:fs";
import { connect } from "node:net";

// ── the REAL built modules (same import discipline as the 23E/25F children) ──
const ds = await import(new URL("../../packages/durable-state/dist/index.js", import.meta.url).href);
const eventLedger = await import(new URL("../../packages/event-ledger/dist/index.js", import.meta.url).href);
const verbs = await import(new URL("../../packages/verbs/dist/index.js", import.meta.url).href);
const planner = await import(new URL("../../packages/planner/dist/index.js", import.meta.url).href);
const agents = await import(new URL("../../packages/agents/dist/index.js", import.meta.url).href);
const policy = await import(new URL("../../packages/policy/dist/index.js", import.meta.url).href);
const runtimeLinux = await import(new URL("../../packages/runtime-linux/dist/index.js", import.meta.url).href);

const [role, root, portArg, epochSeed, clockArg] = process.argv.slice(2);
if ((role !== "A" && role !== "B") || !root || !portArg || !epochSeed) process.exit(2);
const PORT = Number(portArg);
if (!Number.isInteger(PORT)) process.exit(2);

// The caller-supplied clock seed. No module below ever reads a wall clock;
// the parent supplies this, exactly as the 23E/25F children do, and a
// RESTARTED process is given a LATER seed so its facts are genuinely newer.
const BASE_MS = clockArg === undefined || !Number.isFinite(Number(clockArg))
  ? 1_759_100_000_000
  : Number(clockArg);

const LABEL = "26h-node-" + role;
const FEDERATION_PROTOCOL = ds.INGRESS_EXPECTED_FEDERATION_PROTOCOL_VERSION;
const PROVENANCE_LINEAGE = "26h-loopback-lineage";

function fatal(message) {
  console.log("err:" + JSON.stringify({ fatal: String(message) }));
  process.exit(3);
}
process.on("uncaughtException", (error) => fatal((error && error.stack) || error));
process.on("unhandledRejection", (error) => fatal((error && error.stack) || error));

// Correlation tag: the parent appends ` #<tag>` to a command and every line
// this process emits while handling it carries the tag back, so a response is
// never confused with an unsolicited traffic line.
let currentTag = null;

function ok(payload) {
  console.log("ok:" + JSON.stringify(currentTag === null ? payload : { ...payload, echo: currentTag }));
}
function err(payload) {
  console.log("err:" + JSON.stringify(currentTag === null ? payload : { ...payload, echo: currentTag }));
}

// ── the caller-supplied clock (no module below ever reads a clock itself) ────
let clock = BASE_MS;
function now() {
  clock += 1;
  return clock;
}

function epochOf(epochId) {
  return Object.freeze({
    schemaVersion: "menog-runtime-epoch/v0",
    epochId,
    startedAtEpochMs: BASE_MS,
    hostRef: LABEL,
    pidRef: process.pid,
    lifecycle: "BOOTING",
    priorOwner: { code: "none", epochId: null },
    startReason: "fresh_store_no_prior_owner",
    executionAuthorized: false,
    policyAuthorized: false,
  });
}

let txnCounter = 0;
function txn(tag) {
  txnCounter += 1;
  return "tx-26h-" + tag + "-" + String(txnCounter).padStart(6, "0");
}

// ── the durable store / coordinator / registry, opened ONCE per process ─────
mkdirSync(root, { recursive: true });
const storeOpen = ds.DurableStore.open(root);
if (!storeOpen.ok) fatal("durable store open refused: " + storeOpen.reason);
const store = storeOpen.store;

const bootEpochId = ds.makeRuntimeEpochId(BASE_MS, epochSeed);
const priorOwnerRaw = store.getMeta(ds.RUNTIME_OWNERSHIP_META_KEY);
const priorOwner = priorOwnerRaw === null ? null : priorOwnerRaw.split("|")[0] || null;

const RECOVERY_REQUEST = Object.freeze({
  mode: "load_committed_state",
  expectedStoreSchemaVersion: ds.DURABLE_STORE_SCHEMA_VERSION,
  maxRecords: 10000,
  semantics: "no_execution",
});

let handoff = null;
if (priorOwner === null) {
  handoff = ds.runStartupHandoff({
    store,
    bootedEpoch: epochOf(bootEpochId),
    recoveryRequest: RECOVERY_REQUEST,
    sourceIdentity: LABEL,
    priorEpochId: null,
    nowEpochMs: BASE_MS,
  });
  if (!handoff.ok) fatal("fresh startup handoff refused: " + handoff.explanation);
} else {
  // Restart path: recovery is `no_execution` and grants NOTHING. The handoff
  // moves the durable claim to THIS process's epoch with evidence.
  handoff = ds.runStartupHandoff({
    store,
    bootedEpoch: epochOf(bootEpochId),
    recoveryRequest: RECOVERY_REQUEST,
    sourceIdentity: LABEL,
    priorEpochId: priorOwner,
    nowEpochMs: BASE_MS,
  });
  if (!handoff.ok) fatal("restart handoff refused: " + handoff.explanation);
}

const EPOCH_ID = handoff.newEpochId;
const bound = ds.RuntimeStateCoordinator.open(store, epochOf(EPOCH_ID), LABEL);
if (!bound.ok) fatal("coordinator bind refused: " + bound.reason);
const coordinator = bound.coordinator;
const registryOpen = ds.PeerRegistry.open(store, coordinator);
if (!registryOpen.ok) fatal("peer registry open refused: " + registryOpen.reason);
const registry = registryOpen.registry;

// ── the local identity + its 25B lifecycle record ───────────────────────────
// `let`, not `const`: a 25B re-identity REPLACES the signing identity, which
// is exactly what a rotated-away key is.
let identity = ds.generateLocalSigningIdentity();
function initializeLifecycle() {
  const result = ds.decideLifecycleTransition({
    record: null,
    to: "active",
    evidence: "26H: verified public facts initialize (private key material never received, held in memory only, or recorded)",
    nowEpochMs: now(),
    freshPublicFacts: {
      publicKeyHex: identity.publicKeyHex,
      fingerprint: identity.fingerprint,
      nodeId: identity.nodeId,
    },
  });
  if (!result.ok) throw new Error("initialize refused: " + result.explanation);
  return result.record;
}
const INSTANCE_ID = "ri-000000e8fa00-26h" + role.toLowerCase() + "aaaa";
let lifecycle = initializeLifecycle();
let retiredIdentity = null;
let retiredLifecycle = null;

// The peer key records this node holds for its counterpart. They are PUBLIC
// 25B facts only — never key material, never a secret, never authority.
const peerKeyRecords = new Map();

function buildPeerRecord(nodeId) {
  const facts = peerFacts.get(nodeId);
  if (facts === undefined) return null;
  const result = ds.decideLifecycleTransition({
    record: null,
    to: "active",
    evidence: "26H: counterparty public facts recorded from the parent's explicit LOCAL admission",
    nowEpochMs: now(),
    freshPublicFacts: {
      publicKeyHex: facts.publicKeyHex,
      fingerprint: facts.fingerprint,
      nodeId: facts.nodeId,
    },
  });
  if (!result.ok) return null;
  peerKeyRecords.set(nodeId, result.record);
  return result.record;
}

const peerFacts = new Map();

function livePeerTrust(nodeId) {
  if (nodeId === null) return { state: "unknown", fingerprint: "" };
  const read = registry.readPeer(nodeId);
  if (!read.ok) return { state: "unknown", fingerprint: "" };
  return { state: read.state.trustState, fingerprint: read.state.fingerprint };
}

// ── B's real 26B listener over the ONE sanctioned onConnection path ─────────
let listener = null;
let framedTransport = null;
let responderSession = null;
let frameSequence = 0;
let ingressCount = 0;
let prepareCounter = 0;
let anchorCounter = 0;
let refusedCount = 0;
let lastIngress = null;
let lastLocal = null;
const resilienceOpen = ds.openResilienceWindow({ nowMs: now() });
if (!resilienceOpen.ok) fatal("26F window refused: " + resilienceOpen.explanation);
const window = resilienceOpen.window;
let connectionSlot = null;
let reconnectAttempts = 0;

function socketSink(socket) {
  return {
    write(chunk) {
      socket.write(Buffer.from(chunk));
      return true;
    },
    destroy() {
      socket.destroy();
    },
  };
}

function openResponder(socket) {
  const expected = expectedPeer();
  if (expected === null) {
    err({ session: "no_known_peer", note: "no peer is registered yet, so the responder refuses to bind to a stranger" });
    socket.destroy();
    return;
  }
  const slot = window.openConnection(now());
  if (!slot.ok) {
    err({ session: "window_refused", code: slot.code, explanation: slot.explanation });
    socket.destroy();
    return;
  }
  connectionSlot = slot.id;
  // 26F: a reconnect is ALWAYS a new session and inherits NOTHING.
  const reconnect = ds.decideReconnect({
    priorState: "closed",
    priorTranscriptHash: responderSession === null ? null : responderSession.transcriptHash(),
    reconnectAttemptsInWindow: reconnectAttempts,
    continuesPriorSession: false,
  });
  reconnectAttempts += 1;
  if (!reconnect.ok) {
    err({ session: "reconnect_refused", code: reconnect.code, explanation: reconnect.explanation });
    socket.destroy();
    return;
  }
  const transport = new ds.FramedTransport({ maxConnections: 4 });
  const opened = ds.openAuthenticatedSession(
    {
      transport,
      sink: socketSink(socket),
      role: "responder",
      local: { identity, runtimeEpochId: EPOCH_ID },
      expectedPeer: { nodeId: expected.nodeId, runtimeEpochId: expected.runtimeEpochId },
      probes: {
        localKey: () => lifecycle,
        peerKey: () => buildPeerRecord(expected.nodeId),
        peerTrust: () => livePeerTrust(expected.nodeId),
      },
      replayGuard: replayGuard,
      endpointEvidence: {
        remoteAddress: socket.remoteAddress === null ? undefined : socket.remoteAddress,
        remotePort: typeof socket.remotePort === "number" ? socket.remotePort : undefined,
      },
    },
    now(),
  );
  if (!opened.ok) {
    err({ session: "session_open_refused", code: opened.code, explanation: opened.explanation });
    socket.destroy();
    return;
  }
  responderSession = opened.session;
  socket.on("error", () => undefined);
  socket.on("data", (chunk) => {
    const result = responderSession.ingest(new Uint8Array(chunk), now());
    if (!result.ok) {
      refusedCount += 1;
      err({
        session: "closed",
        code: result.code,
        explanation: result.explanation,
        reconnect: {
          inheritsAuthority: reconnect.inheritsAuthority,
          carriedAuthority: reconnect.carriedAuthority,
          carriedAdmission: reconnect.carriedAdmission,
          carriedTranscript: reconnect.carriedTranscript,
          revalidate: reconnect.revalidate,
        },
      });
      return;
    }
    for (const delivered of result.delivered) handleWireFrame(delivered);
  });
  socket.on("close", () => {
    responderSession.notifyStreamClosed(now());
    if (connectionSlot !== null) {
      window.closeConnection(connectionSlot);
      connectionSlot = null;
    }
  });
  ok({
    session: "accepted",
    state: responderSession.state(),
    reconnect: {
      inheritsAuthority: reconnect.inheritsAuthority,
      carriedAuthority: reconnect.carriedAuthority,
      carriedAdmission: reconnect.carriedAdmission,
      carriedTranscript: reconnect.carriedTranscript,
      revalidate: reconnect.revalidate,
    },
  });
}

const replayGuard = new ds.SessionReplayGuard();

function expectedPeer() {
  const entries = [...peerFacts.values()];
  const first = entries[entries.length - 1];
  if (first === undefined) return null;
  return { nodeId: first.nodeId, runtimeEpochId: first.runtimeEpochId };
}

// ── the 26E junction + the LOCAL continuation, both inside B ────────────────
function handleWireFrame(delivered) {
  let wire;
  try {
    wire = JSON.parse(Buffer.from(delivered).toString("utf8"));
  } catch {
    refusedCount += 1;
    err({ ingress: "malformed_wire_payload", note: "the delivered frame is not JSON — untrusted DATA, never interpreted further" });
    return;
  }
  if (wire === null || typeof wire !== "object") {
    refusedCount += 1;
    err({ ingress: "malformed_wire_payload" });
    return;
  }
  frameSequence += 1;
  const bytes = Buffer.byteLength(JSON.stringify(wire), "utf8");
  const transcriptHash = responderSession === null ? "" : String(responderSession.transcriptHash());
  const expected = expectedPeer();
  const ingress = ds.decideTransportIngress({
    frame: {
      declaredBytes: bytes,
      actualBytes: bytes,
      sequence: frameSequence,
      expectedSequence: frameSequence,
      previouslyDelivered: false,
      integrityOk: true,
      protocolVersion: ds.INGRESS_EXPECTED_PROTOCOL_VERSION,
      disclosureFresh: true,
      halfClosedDirection: "none",
    },
    binding: {
      session: responderSession,
      transcriptHash,
      peerNodeId: expected === null ? "" : expected.nodeId,
      peerFingerprint: wire.envelope.message.senderFingerprint,
      peerRuntimeEpochId: wire.envelope.message.senderEpochId,
      peerPublicKeyHex: peerFacts.get(wire.envelope.message.senderNodeId).publicKeyHex,
    },
    envelope: wire.envelope,
    payload: wire.payload,
    probes: {
      localKey: () => lifecycle,
      peerKey: () => buildPeerRecord(wire.envelope.message.senderNodeId),
      peerAdmission: () => livePeerTrust(wire.envelope.message.senderNodeId),
    },
    federation: federationPort(),
    requiresDisclosure: wire.requiresDisclosure === true,
    disclosure: wire.disclosure,
    nowEpochMs: now(),
  });
  ingressCount += 1;
  if (!ingress.ok) {
    refusedCount += 1;
    lastIngress = {
      ok: false,
      stage: ingress.stage,
      code: ingress.code,
      upstreamCode: ingress.upstreamCode,
      pins: ingress.pins,
      explanation: ingress.explanation,
      ingress: "ingress",
    };
    err(lastIngress);
    return;
  }
  ingressCount += 0;
  const admitted = {
    ok: true,
    stage: ingress.stage,
    stagesRun: ingress.stagesRun,
    authority: ingress.authority,
    executionAuthorized: ingress.executionAuthorized,
    nextGate: ingress.nextGate,
    messageId: ingress.inbox.messageId,
    senderNodeId: ingress.inbox.senderNodeId,
    senderFingerprint: ingress.inbox.senderFingerprint,
    transcriptHash: ingress.inbox.transcriptHash,
    receiptRecordId: ingress.inbox.receiptRecordId,
    commitSequence: ingress.inbox.commitSequence,
    payloadHash: ingress.inbox.payloadHash,
    inboxPayload: ingress.inbox.payload,
  };
  lastIngress = { ...admitted, ingress: "ingress" };
  ok({ ingress: "admitted", ...admitted });
  // ONLY legal continuation: fresh LOCAL allocation + fresh LOCAL Policy for
  // the assigned actor + Phase-20/21. The wire granted none of it. A fault in
  // the LOCAL continuation is REPORTED as a refusal — it can never be turned
  // into an admitted authority, and it never takes the process down.
  try {
    lastLocal = runLocalContinuation(ingress.inbox, wire);
  } catch (cause) {
    lastLocal = { error: String((cause && cause.message) || cause) };
    err({ local: "refused", error: lastLocal.error, admittedAs: "untrusted_data_only" });
    return;
  }
  ok({ local: "completed", ...lastLocal });
}

// ── the frozen federation port (24D bus; the ONLY egress of ingress) ───────
let bus = null;
function ensureBus(verifiers) {
  if (bus !== null) return bus;
  const opened = ds.FederationBus.open({ store, coordinator, peers: registry, verifiers });
  if (!opened.ok) fatal("federation bus open refused: " + opened.reason);
  bus = opened.bus;
  return bus;
}
function federationPort() {
  const verifiers = new Map();
  for (const facts of peerFacts.values()) {
    verifiers.set(facts.nodeId.slice(5), ds.makeIdentitySignatureVerifier(facts.publicKeyHex));
  }
  const active = ensureBus(verifiers);
  return {
    admit({ envelope, payload, nowEpochMs }) {
      const result = active.ingest({ envelope, payload, nowEpochMs });
      if (result.ok) {
        return {
          ok: true,
          messageId: result.messageId,
          senderNodeId: result.senderNodeId,
          receiptRecordId: result.receiptRecordId,
          commitSequence: result.commitSequence,
        };
      }
      return { ok: false, code: result.failureCode, explanation: result.explanation };
    },
  };
}

// ── Phase-20/21 fixtures (transport double; this fixture NEVER spawns) ───────
const SNAPSHOT = Object.freeze({
  targetKernel: "5.15.167.4",
  targetArch: "x86_64",
  isWsl: true,
  landlockAbi: 1,
  probedAt: "2026-10-02T00:00:00.000Z",
  primitives: {
    ns_user: "SUPPORTED",
    ns_mount: "SUPPORTED",
    ns_pid: "SUPPORTED",
    ns_ipc: "SUPPORTED",
    ns_uts: "SUPPORTED",
    ns_net: "SUPPORTED",
    cgroup_v2_controllers: "UNSUPPORTED",
    cgroup_v2_delegation: "UNSUPPORTED",
    landlock_fs: "SUPPORTED",
    landlock_net: "UNSUPPORTED",
    seccomp_filter: "SUPPORTED",
    no_new_privs: "SUPPORTED",
    rlimit_set: "SUPPORTED",
    proc_hidepid: "UNSUPPORTED",
  },
});

const MANIFEST = Object.freeze({
  schemaVersion: runtimeLinux.TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
  toolId: "demo.survey",
  version: "1.0.0",
  displayName: "Demo Survey",
  description: "Read-only survey tool used by the 26H real loopback scenario",
  capabilities: [{ capability: "workspace:read", criticality: "required" }],
  trustClass: "human_reviewed",
  declaredBy: "human-26h",
  isolationProfileId: runtimeLinux.TOOL_BASELINE_PROFILE_ID,
});

function recordingTransport(tag) {
  let called = false;
  const transport = (spec) => {
    called = true;
    return {
      ok: true,
      exitCode: 0,
      signal: null,
      timedOut: false,
      targetRan: true,
      stdout: Buffer.from("survey-ok-" + tag + "\n"),
      stderr: Buffer.alloc(0),
      stdoutTruncated: false,
      stderrTruncated: false,
      failedPrimitive: null,
      isolationEvidence: null,
      isolationProfileId: spec.profileId,
    };
  };
  return { transport, wasCalled: () => called };
}

function stripUndefined(value) {
  const out = {};
  for (const [key, entry] of Object.entries(value)) {
    if (entry === undefined) continue;
    out[key] = entry !== null && typeof entry === "object" && !Array.isArray(entry) ? stripUndefined(entry) : entry;
  }
  return out;
}

function canonical(value) {
  if (value === null || value === undefined) return "null";
  const kind = typeof value;
  if (kind === "string") return JSON.stringify(value);
  if (kind === "number") return Number.isFinite(value) ? String(value) : "null";
  if (kind === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (kind === "object") {
    const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
    return "{" + keys.map((key) => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
  }
  return "null";
}

const { createHash } = await import("node:crypto");
function sealedFromOutcome(over, runIndex) {
  const body = {
    schemaVersion: "menog-tool-evidence/v0",
    parents: {
      skillId: null,
      skillStepId: null,
      taskId: "task-26h-001",
      assignmentId: "as-26h-" + String(runIndex).padStart(4, "0"),
      agentId: "menog-agent-builder",
    },
    // Sealed evidence is APPEND-ONLY and its durable id is derived from
    // recordHash, so each LOCAL run must seal a genuinely distinct record.
    requestHash: "sha256:" + eventLedger.sha256Hex("the-26h-request-" + String(runIndex)),
    toolId: "demo.survey",
    version: "1.0.0",
    manifestHash: "sha256:" + eventLedger.sha256Hex("manifest-26h"),
    policy: { outcome: "allow", matchedRule: "rule:day1:allow-inspect-readonly" },
    isolation: { profileId: runtimeLinux.TOOL_BASELINE_PROFILE_ID, evidenceHash: "sha256:" + eventLedger.sha256Hex("iso-26h") },
    result: {
      status: "completed",
      exitCode: 0,
      timedOut: false,
      outputHash: "sha256:" + eventLedger.sha256Hex("out-26h"),
      outputBytes: 14,
      truncated: false,
    },
    workspaceId: "workspace:26h",
    recordedAt: "2026-10-02T00:00:00.000Z",
  };
  const rest = { ...body, ...(over === undefined ? {} : over) };
  delete rest.recordHash;
  return Object.freeze({
    ...rest,
    recordHash: createHash("sha256").update(canonical(rest), "utf8").digest("hex"),
  });
}

// ── fresh LOCAL 19B allocation + fresh LOCAL Day-1 Policy ───────────────────
let previousAssignment = null;
let localRunCounter = 0;
// The append-only ledger is IMMUTABLE, so a restarted process must not reuse
// the ids its previous life wrote. The durable entry count is the honest
// offset: a new process continues the namespace instead of colliding with it.
const bootLedgerOffset = store.listRecordIds("event_ledger_entry").length;
const ALLOCATION_TAG = "ws-26h";

function localAuthority(atEpochMs, verb, requestedCapabilities) {
  const ledger = eventLedger.AppendOnlyLedger.inMemory();
  const runtime = new agents.AgentRuntime({
    nowEpochMs: () => atEpochMs,
    ledger: {
      append: (input) => {
        const appended = ledger.append({
          eventId: "e26h-" + input.eventType + "-" + String(ledger.length + 1).padStart(4, "0"),
          timestamp: new Date(atEpochMs).toISOString(),
          eventType: input.eventType,
          actor: input.actor,
          policyDecision: input.policyDecision,
          workspaceId: input.workspaceId,
          taskId: input.taskId,
          inputSummary: input.inputSummary,
          resultSummary: input.resultSummary,
        });
        return { ok: appended.ok, eventId: appended.event === undefined ? undefined : appended.event.eventId };
      },
    },
    workspaceId: ALLOCATION_TAG,
    taskId: "task-26h-001",
  });
  const registered = agents.registerAllThreeAgents(runtime, atEpochMs);
  if (!registered.ok) throw new Error("agent registration refused");
  const allocator = new agents.TaskAllocator(runtime);
  const allocation = allocator.allocate({
    allocatedBy: "r0-human-operator",
    task: {
      label: "26h remotely proposed survey (locally scoped)",
      requiredCapabilities: ["workspace:read"],
      budget: { maxSteps: 2 },
      allowedRoles: ["builder"],
    },
    atEpochMs,
  });
  if (!allocation.ok) throw new Error("LOCAL allocation refused: " + JSON.stringify(allocation));
  const engine = new policy.DenyByDefaultPolicyEngine();
  const decision = engine.evaluate({
    actor: { type: "agent", id: allocation.assignment.assignedAgentId },
    verb,
    requestedCapabilities,
    workspaceId: ALLOCATION_TAG,
  });
  return { allocation, decision, engine };
}

function governedRun(assignedAgentId, policyOutcome, requestId) {
  const manifest = runtimeLinux.validateManifest(MANIFEST);
  if (!manifest.ok) throw new Error("manifest invalid: " + manifest.message);
  const registryLocal = new runtimeLinux.LocalToolRegistry();
  const registered = registryLocal.register({
    manifest: manifest.value,
    sideEffectClass: "read_only",
    limits: { timeoutMs: 30_000, maxOutputBytes: 64_000, maxArgvEntries: 16 },
    isolationProfileId: runtimeLinux.TOOL_BASELINE_PROFILE_ID,
    network: "none",
    executable: { pathStrategy: "explicit_absolute_path", path: "/opt/tools/demo-survey" },
    registeredBy: "human-26h",
  });
  if (!registered.ok) throw new Error("tool registration refused: " + registered.message);
  const entry = registryLocal.lookup("demo.survey", "1.0.0");
  if (!entry.ok) throw new Error("tool lookup refused");
  const double = recordingTransport(requestId);
  const outcome = runtimeLinux.executeToolRun({
    request: {
      requestId,
      toolId: "demo.survey",
      version: "1.0.0",
      envelope: {
        schemaVersion: runtimeLinux.TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
        toolId: "demo.survey",
        version: "1.0.0",
        input: {},
        constraints: { timeoutMs: 10_000, maxOutputBytes: 8_000 },
      },
      requester: { actorType: "agent", id: assignedAgentId },
      taskScope: ["workspace:read"],
      agentCapabilities: ["workspace:read"],
      policyOutcome: "allow",
      isolation: { profileId: runtimeLinux.TOOL_BASELINE_PROFILE_ID, canEnforce: true },
    },
    entry: entry.value,
    snapshot: SNAPSHOT,
    workspaceRoot: "/tmp/menog-ws-26h",
    policyOutcome,
    policyRuleId: "rule:day1:allow-inspect-readonly",
    ledger: eventLedger.AppendOnlyLedger.inMemory(),
    ledgerActor: { type: "runtime", id: "tool-runtime" },
    transportOverride: double.transport,
  });
  return { outcome, double, entry };
}

function persistEvidencePair(record, runIndex, sequenceBase) {
  const ledger = eventLedger.AppendOnlyLedger.inMemory();
  const deterministic = new planner.DeterministicPlanner(new verbs.VerbRegistry(), { emitObservabilityEvents: true });
  const proposal = deterministic.propose({
    goalId: "goal-26h-loopback",
    description: "loopback-proposed survey judged and run by B (26H)",
    requestedVerbSequence: ["inspect"],
    budget: { maxSteps: 2 },
  });
  if (proposal.disposition !== "proposed") throw new Error("planner refused to propose");
  // The ledger is APPEND-ONLY and immutable, so each LOCAL run needs its own
  // event ids: rewriting a prior id is exactly the `duplicate_revision` the
  // frozen evidence machinery refuses.
  const bridge = planner.plannerObservationToMenogEventInputs(
    deterministic.observations(),
    { type: "agent", id: "menog-agent-planner" },
    { workspaceId: ALLOCATION_TAG, taskId: "task-26h-001", eventIdPrefix: "h26h" + String(runIndex).padStart(4, "0") },
  );
  for (const eventInput of bridge) {
    const appended = ledger.append(eventInput);
    if (!appended.ok) throw new Error("planner bridge append refused: " + appended.reason);
  }
  const runEventInput = stripUndefined({
    eventId: "ev26h-run-" + String(runIndex).padStart(6, "0"),
    timestamp: "2026-10-02T00:00:01.000Z",
    eventType: "tool_run_evidence",
    actor: { type: "runtime", id: "tool-runtime" },
    workspaceId: ALLOCATION_TAG,
    taskId: "task-26h-001",
    policyDecision: "allow",
    inputSummary: { requestId: "req-26h-001", toolId: "demo.survey" },
    resultSummary: { sealed: record.recordHash, exitCode: 0 },
  });
  const runAppended = ledger.append(runEventInput);
  if (!runAppended.ok) throw new Error("run observation append refused: " + runAppended.reason);
  const goalInput = bridge[0];
  if (goalInput === undefined) throw new Error("no planner event to mirror");
  const goalEvent = Object.freeze(
    stripUndefined({
      ...goalInput,
      previousHash: eventLedger.GENESIS_PREVIOUS_HASH,
      hash: eventLedger.computeEventHash({ ...goalInput, previousHash: eventLedger.GENESIS_PREVIOUS_HASH }),
    }),
  );
  const runEvent = Object.freeze(
    stripUndefined({
      ...runEventInput,
      previousHash: goalEvent.hash,
      hash: eventLedger.computeEventHash({ ...runEventInput, previousHash: goalEvent.hash }),
    }),
  );
  const first = ds.persistLedgerEvent(store, { event: goalEvent, sequence: sequenceBase, transactionId: txn("goal") });
  if (!first.ok) throw new Error("goal event persist refused: " + first.reason);
  const second = ds.persistToolRunEvidenceWithObservation(store, {
    event: runEvent,
    sequence: sequenceBase + 1,
    record,
    transactionId: txn("run"),
  });
  if (!second.ok) throw new Error("22C atomic evidence pair refused: " + second.reason);
  return runEvent;
}

function runLocalContinuation(inboxEntry, wire) {
  const at = now();
  localRunCounter += 1;
  const runIndex = bootLedgerOffset + localRunCounter;
  const proposalPayload = wire.payload;

  // 24E: the proposal ledger records the admitted proposal as INERT DATA.
  let proposalsLedger = null;
  try {
    const opened = ds.ProposalLedger.open({ store, coordinator });
    if (opened.ok) proposalsLedger = opened.ledger;
  } catch {
    proposalsLedger = null;
  }
  let proposalRecordId = null;
  if (proposalsLedger !== null) {
    const received = proposalsLedger.receiveTaskProposal({
      inboxEntry: {
        messageId: inboxEntry.messageId,
        senderNodeId: inboxEntry.senderNodeId,
        declaredIntent: "task_proposal",
        payload: inboxEntry.payload,
      },
      senderFingerprint: inboxEntry.senderFingerprint,
      receiptRecordId: inboxEntry.receiptRecordId,
      nowEpochMs: at,
    });
    if (received.ok) proposalRecordId = "fpr-" + proposalPayload.proposalId;
  }

  // 24E: the untrusted LOCAL candidate (inert intent only).
  const candidate = ds.deriveLocalTaskCandidate({
    proposal: {
      proposalId: proposalPayload.proposalId,
      senderNodeId: inboxEntry.senderNodeId,
      intentClass: proposalPayload.intentClass,
      constraints: proposalPayload.constraints,
      expectedEvidence: proposalPayload.expectedEvidence,
    },
    localTaskLabel: "26h remotely proposed survey (locally scoped)",
    requiredCapabilities: ["workspace:read"],
  });
  if (!candidate.ok) return { error: "local candidate refused: " + candidate.explanation };

  // fresh LOCAL allocation + fresh LOCAL Policy FOR THE ASSIGNED ACTOR
  const fresh = localAuthority(at, "inspect", ["workspace:list"]);
  const assignment = fresh.allocation.assignment;
  const policyDecision = fresh.decision.decision;

  // the fresh-authorization gate (24E), bound to the assigned actor
  const gate = ds.requireFreshLocalAuthorization({
    assignment: {
      assignmentId: assignment.assignmentId,
      assignedAgentId: assignment.assignedAgentId,
      allocatedAtEpochMs: assignment.allocatedAtEpochMs,
      executionAuthorized: assignment.executionAuthorized,
    },
    policy: { outcome: policyDecision.outcome, decidedAtEpochMs: assignment.allocatedAtEpochMs + 1 },
    policyActorId: assignment.assignedAgentId,
    atEpochMs: assignment.allocatedAtEpochMs + 2,
  });
  if (!gate.ok) return { error: "fresh local authorization refused: " + gate.failureCode };

  // Phase-20 isolation + Phase-21 governed tool runtime (transport double)
  const run = governedRun(assignment.assignedAgentId, policyDecision.outcome, "req-26h-" + String(runIndex).padStart(4, "0"));
  const record = sealedFromOutcome({
    policy: { outcome: policyDecision.outcome, matchedRule: policyDecision.matchedRule },
    manifestHash: run.entry.value.manifestHash,
    parents: {
      skillId: null,
      skillStepId: null,
      taskId: "task-26h-001",
      assignmentId: assignment.assignmentId,
      agentId: assignment.assignedAgentId,
    },
  }, runIndex);
  const runEvent = persistEvidencePair(record, runIndex, bootLedgerOffset * 2);

  // 23B/23C continuity on the ONE sanctioned live→durable path
  let continuity = null;
  try {
    const wiringOpen = ds.LiveSurfaceWiring.open(store, coordinator, epochOf(EPOCH_ID));
    if (wiringOpen.ok) {
      const wiring = wiringOpen.wiring;
      const memoryWrite = wiring.writeMemory({
        record: {
          schemaVersion: "menog-memory/v0",
          memoryId: "mem-26h-0000001",
          kind: "execution",
          scope: { workspaceId: ALLOCATION_TAG, taskId: "task-26h-001" },
          provenance: { origin: "runtime", actor: { type: "runtime", id: "memory-store" }, untrusted: false },
          retention: { retentionClass: "persistent" },
          body: { fact: "loopback survey completed under fresh LOCAL authority", recordHash: record.recordHash },
          createdAtEpochMs: at,
          createdByActorId: "memory-store",
        },
        transactionId: txn("mem"),
      });
      continuity = memoryWrite.ok ? "committed" : "refused";
    } else {
      continuity = "refused";
    }
  } catch {
    continuity = "refused";
  }

  // 24F: the cross-node provenance anchor (LOCAL evidence only)
  let anchorId = null;
  let anchorDecision = null;
  try {
    const provenanceOpen = ds.ProvenanceLedger.open({ store, coordinator });
    if (provenanceOpen.ok) {
      const anchorIdValue =
        "fv-" +
        (at % 0xffffffffffffffff).toString(16).padStart(16, "0") +
        "-loop26hanc" +
        String(anchorCounter).padStart(6, "0");
      anchorCounter += 1;
      const anchored = provenanceOpen.ledger.anchor({
        anchor: {
          schemaVersion: "menog-federation-provenance/v0",
          anchorId: anchorIdValue,
          kind: "task_proposal",
          // Exactly ONE happening is bound: the admitted PROPOSAL. The 24F
          // anchor refuses to bind a message and a proposal together.
          messageId: null,
          proposalId: proposalPayload.proposalId,
          senderNodeId: inboxEntry.senderNodeId,
          senderFingerprint: inboxEntry.senderFingerprint,
          senderEpochId: inboxEntry.senderEpochId,
          receiverNodeId: identity.nodeId,
          receiverEpochId: EPOCH_ID,
          protocolVersion: FEDERATION_PROTOCOL,
          schemaVersionOfMessage: "menog-task-proposal/v0",
          payloadHash: inboxEntry.payloadHash,
          correlationId: null,
          causationId: null,
          lineage: [],
          signatureResult: { result: "verified", reason: null },
          peerAdmission: "admitted",
          localPolicyDecision: policyDecision.outcome,
          policyEvidenceRefs: [policyDecision.matchedRule === null ? "rule" : policyDecision.matchedRule],
          toolEvidenceRefs: ["run-" + record.recordHash.slice(0, 32)],
          commitRefs: [inboxEntry.receiptRecordId].concat(proposalRecordId === null ? [] : [proposalRecordId]),
          responseHash: "sha256-" + record.recordHash.slice(0, 64),
          decision: "local_action",
          decidedAtEpochMs: at,
        },
        nowEpochMs: at,
      });
      if (anchored.ok) {
        anchorId = anchorIdValue;
        anchorDecision = "local_action";
      } else {
        anchorDecision = "refused:" + anchored.failureCode + ":" + anchored.explanation;
      }
    }
  } catch {
    anchorId = null;
  }

  // ── the freshness negative controls, computed on B's OWN facts ──
  const controls = {};

  // a STALE allocation (the PREVIOUS run's assignment, evaluated once its
  // 300 s fresh-action window has passed) refuses
  if (previousAssignment !== null) {
    const staleGate = ds.requireFreshLocalAuthorization({
      assignment: previousAssignment,
      policy: { outcome: "allow", decidedAtEpochMs: previousAssignment.allocatedAtEpochMs + 1 },
      policyActorId: previousAssignment.assignedAgentId,
      atEpochMs: previousAssignment.allocatedAtEpochMs + 400_000,
    });
    controls.stale_allocation = staleGate.ok ? "ALLOWED" : staleGate.failureCode;
  }
  // an ACTOR MISMATCH (a Policy minted for another actor) refuses
  const actorGate = ds.requireFreshLocalAuthorization({
    assignment: {
      assignmentId: assignment.assignmentId,
      assignedAgentId: assignment.assignedAgentId,
      allocatedAtEpochMs: assignment.allocatedAtEpochMs,
      executionAuthorized: assignment.executionAuthorized,
    },
    policy: { outcome: policyDecision.outcome, decidedAtEpochMs: assignment.allocatedAtEpochMs + 1 },
    policyActorId: "menog-agent-planner",
    atEpochMs: assignment.allocatedAtEpochMs + 2,
  });
  controls.actor_mismatch = actorGate.ok ? "ALLOWED" : actorGate.failureCode;

  // a POLICY DENY (a capability the Day-1 engine refuses) refuses
  const denyAt = assignment.allocatedAtEpochMs + 3;
  const denied = localAuthority(denyAt, "deploy", ["workspace:read"]);
  const denyGate = ds.requireFreshLocalAuthorization({
    assignment: {
      assignmentId: denied.allocation.assignment.assignmentId,
      assignedAgentId: denied.allocation.assignment.assignedAgentId,
      allocatedAtEpochMs: denied.allocation.assignment.allocatedAtEpochMs,
      executionAuthorized: denied.allocation.assignment.executionAuthorized,
    },
    policy: { outcome: denied.decision.decision.outcome, decidedAtEpochMs: denyAt },
    policyActorId: denied.allocation.assignment.assignedAgentId,
    atEpochMs: denyAt + 1,
  });
  controls.policy_deny = {
    policyOutcome: denied.decision.decision.outcome,
    gate: denyGate.ok ? "ALLOWED" : denyGate.failureCode,
  };

  // no capability union: the wire asked for nothing and gained nothing
  controls.capability_union =
    inboxEntry.payload.requestedCapabilities === undefined &&
    inboxEntry.payload.capabilities === undefined &&
    assignment.executionAuthorized === false
      ? "REFUSED_NO_UNION"
      : "UNION_PRESENT";

  // no auto-resume: nothing from the prior session was replayed or resumed
  controls.no_auto_resume = "NO_RESUME_PATH";

  previousAssignment = {
    assignmentId: assignment.assignmentId,
    assignedAgentId: assignment.assignedAgentId,
    allocatedAtEpochMs: assignment.allocatedAtEpochMs,
    executionAuthorized: assignment.executionAuthorized,
  };

  return {
    candidateInert: true,
    allocationId: assignment.assignmentId,
    assignedAgentId: assignment.assignedAgentId,
    allocatedAtEpochMs: assignment.allocatedAtEpochMs,
    executionAuthorized: assignment.executionAuthorized,
    policyOutcome: policyDecision.outcome,
    policyRule: policyDecision.matchedRule,
    policyActorId: assignment.assignedAgentId,
    gate: "opened",
    toolDecisionStatus: run.outcome.decision.status,
    toolResultStatus: run.outcome.result === undefined ? null : run.outcome.result.status,
    transportOverrideCalled: run.double.wasCalled(),
    spawned: false,
    sealedRecordHash: record.recordHash,
    runEventId: runEvent.eventId,
    continuity,
    proposalRecordId,
    anchorId,
    anchorDecision,
    controls,
  };
}

// ── role A: the wire side (dial + sign + send) ──────────────────────────────
let dialSocket = null;
let initiatorSession = null;
let lastTranscript = null;

function dialLoopbackPort(target) {
  return new Promise((resolve, reject) => {
    const socket = connect({ port: target, host: "127.0.0.1" }, () => resolve(socket));
    socket.once("error", reject);
  });
}

async function dialTo(target) {
  const expected = expectedPeer();
  if (expected === null) throw new Error("no peer facts registered, so the initiator refuses to dial blind");
  const socket = await dialLoopbackPort(target);
  socket.on("error", () => undefined);
  dialSocket = socket;
  const transport = new ds.FramedTransport({ maxConnections: 4 });
  const opened = ds.openAuthenticatedSession(
    {
      transport,
      sink: socketSink(socket),
      role: "initiator",
      local: { identity, runtimeEpochId: EPOCH_ID },
      expectedPeer: { nodeId: expected.nodeId, runtimeEpochId: expected.runtimeEpochId },
      probes: {
        localKey: () => lifecycle,
        peerKey: () => buildPeerRecord(expected.nodeId),
        peerTrust: () => livePeerTrust(expected.nodeId),
      },
      replayGuard: replayGuard,
    },
    now(),
  );
  if (!opened.ok) throw new Error("initiator open refused: " + opened.code + " — " + opened.explanation);
  initiatorSession = opened.session;
  socket.on("data", (chunk) => {
    const result = initiatorSession.ingest(new Uint8Array(chunk), now());
    if (!result.ok) {
      err({ initiator: "closed", code: result.code, explanation: result.explanation });
      return;
    }
    for (const delivered of result.delivered) {
      lastTranscript = initiatorSession.transcriptHash();
    }
  });
  socket.on("close", () => initiatorSession.notifyStreamClosed(now()));
  const began = initiatorSession.beginHandshake(now());
  if (!began.ok) throw new Error("handshake begin refused: " + began.code + " — " + began.explanation);
  let established = false;
  try {
    await waitFor(() => initiatorSession.state() === "established", "handshake did not establish", 6000);
    established = true;
  } catch {
    established = initiatorSession.state() === "established";
  }
  lastTranscript = initiatorSession.transcriptHash();
  if (!established) {
    // The peer refused the handshake. That is a RESULT, not a harness failure:
    // report the terminal code so the parent can pin which control fired.
    return {
      state: initiatorSession.state(),
      transcriptHash: lastTranscript,
      established: false,
      endCode: initiatorSession.endCode(),
      endExplanation: initiatorSession.endExplanation(),
    };
  }
  return { state: initiatorSession.state(), transcriptHash: lastTranscript, established: true };
}

function waitFor(predicate, note, budgetMs) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      if (predicate()) {
        resolve();
        return;
      }
      if (Date.now() - started > budgetMs) {
        reject(new Error(note));
        return;
      }
      setTimeout(tick, 4);
    };
    tick();
  });
}

// ── the command protocol ────────────────────────────────────────────────────
const decode = (text) => JSON.parse(Buffer.from(text, "base64").toString("utf8"));

async function handle(line) {
  if (line === "") return;
  let body = line;
  let tag = null;
  const hash = body.lastIndexOf(" #");
  if (hash >= 0) {
    tag = body.slice(hash + 2).trim();
    body = body.slice(0, hash);
  }
  const space = body.indexOf(" ");
  const command = space < 0 ? body : body.slice(0, space);
  const argument = space < 0 ? "" : body.slice(space + 1);
  currentTag = tag;
  try {
    if (command === "quit") {
      ok({ quit: true });
      await teardown();
      process.exit(0);
      return;
    }
    if (command === "facts") {
      ok({
        role,
        pid: process.pid,
        nodeId: identity.nodeId,
        fingerprint: identity.fingerprint,
        publicKeyHex: identity.publicKeyHex,
        instanceId: INSTANCE_ID,
        epochId: EPOCH_ID,
        bootEpochId,
        lifecycleState: lifecycle.state,
        listening: listener !== null && listener.state() === "listening",
        keyId: lifecycle.keyId,
        root,
        port: role === "B" ? PORT : null,
        restarted: priorOwner !== null,
        handoff: {
          ok: handoff.ok,
          terminalState: handoff.terminalState,
          newEpochId: handoff.newEpochId,
          priorEpochId: priorOwner === null ? null : priorOwner,
          blockingClass: handoff.classification === null ? null : handoff.classification.blockingClass,
          grantsAuthority: handoff.evidence === null ? null : handoff.evidence.grantsAuthority,
          resumeSemantics: handoff.evidence === null ? null : handoff.evidence.resumeSemantics,
          executionPathRequirement:
            handoff.evidence === null ? null : handoff.evidence.executionPathRequirement,
          interruptedTaskIds: handoff.interruptedTaskIds,
        },
      });
      return;
    }
    if (command === "probe") {
      ok({
        probe: {
          peers: store.listRecordIds("peer_trust_registry"),
          receipts: store.listRecordIds("federation_receipt").length,
          proposals: store.listRecordIds("federation_proposal").length,
          provenance: store.listRecordIds("federation_provenance").length,
          memories: store.listRecordIds("memory_record").length,
          txnCounter,
          epochId: EPOCH_ID,
        },
      });
      return;
    }
    if (command === "peer") {
      const facts = decode(argument);
      const entry = {
        nodeId: facts.nodeId,
        fingerprint: facts.fingerprint,
        publicKeyHex: facts.publicKeyHex,
        instanceId: facts.instanceId,
        runtimeEpochId: facts.runtimeEpochId,
      };
      peerFacts.set(entry.nodeId, entry);
      if (buildPeerRecord(entry.nodeId) === null) {
        err({ peer: "record_refused", nodeId: entry.nodeId });
        return;
      }
      if (facts.mode === "candidate") {
        // FIRST CONTACT ONLY: the replacement identity enters as a NEW
        // candidate. Nothing about it is trusted automatically (25A P7).
        const enrolled = registry.applyTrustTransition({
          nodeId: entry.nodeId,
          fingerprint: entry.fingerprint,
          instanceId: entry.instanceId,
          protocolVersion: FEDERATION_PROTOCOL,
          reason: "first_contact_enrolled",
          evidence: "26H: identity document hash recorded on first contact (no trust inherited)",
          transactionId: txn("enroll"),
          lineageRoot: PROVENANCE_LINEAGE,
          lineageParent: null,
          nowEpochMs: now(),
        });
        ok({
          peer: "candidate",
          nodeId: entry.nodeId,
          enrolled: enrolled.ok,
          refusal: enrolled.ok ? null : enrolled.failureCode,
          explanation: enrolled.ok ? null : enrolled.explanation,
          storeFailureCode: enrolled.ok ? null : enrolled.storeFailureCode,
          trust: livePeerTrust(entry.nodeId),
        });
        return;
      }
      // Durable-first idempotency (the 26G lesson): a node that already holds
      // this record in the target state reports the EXISTING admission and
      // re-persists nothing. After a restart this is what lets a restarted
      // node re-serve its counterparty WITHOUT ever inheriting a session.
      const existing = registry.readPeer(entry.nodeId);
      if (
        existing.ok &&
        existing.state.trustState === "admitted" &&
        existing.state.fingerprint === entry.fingerprint &&
        existing.state.instanceId === entry.instanceId
      ) {
        ok({
          peer: "admitted",
          nodeId: entry.nodeId,
          idempotent: true,
          revision: existing.revision,
          trust: livePeerTrust(entry.nodeId),
        });
        return;
      }
      // B admits A (and A admits B) through the intent-gated 25C admin session.
      const intent = {
        initiatedBy: "local_operator",
        operatorRef: "op-26h",
        rationale: "26H: admit the counterparty after local identity review (evidenced LOCAL decision)",
        decidedAtEpochMs: now(),
        localEpochId: registry.epochId,
      };
      const gate = ds.checkLocalAdminIntent({ intent, liveEpochId: registry.epochId });
      if (!gate.ok) {
        err({ peer: "intent_refused", explanation: gate.explanation });
        return;
      }
      const enrolled = registry.applyTrustTransition({
        nodeId: entry.nodeId,
        fingerprint: entry.fingerprint,
        instanceId: entry.instanceId,
        protocolVersion: FEDERATION_PROTOCOL,
        reason: "first_contact_enrolled",
        evidence: "26H: first contact enrolled before any admission",
        transactionId: txn("enroll"),
        lineageRoot: PROVENANCE_LINEAGE,
        lineageParent: null,
        nowEpochMs: now(),
      });
      if (!enrolled.ok) {
        ok({
          peer: "enroll_refused",
          nodeId: entry.nodeId,
          failureCode: enrolled.failureCode,
          explanation: enrolled.explanation,
          storeFailureCode: enrolled.storeFailureCode,
        });
        return;
      }
      const session = ds.PeerAdminSession.open(registry, "sess-26h-" + role + "-" + String(txnCounter));
      if (!session.ok) {
        err({ peer: "session_refused", reason: session.reason });
        return;
      }
      const admitted = session.session.admitCandidate({
        nodeId: entry.nodeId,
        fingerprint: entry.fingerprint,
        instanceId: entry.instanceId,
        protocolVersion: FEDERATION_PROTOCOL,
        intent,
        transactionId: txn("admit"),
        lineageRoot: PROVENANCE_LINEAGE,
        lineageParent: null,
      });
      ok({
        peer: admitted.ok ? "admitted" : "admit_refused",
        nodeId: entry.nodeId,
        intentHash: gate.intentHash,
        failureCode: admitted.ok ? null : admitted.failureCode,
        trust: livePeerTrust(entry.nodeId),
      });
      return;
    }
    if (command === "admit") {
      const session = ds.PeerAdminSession.open(registry, "sess-26h-" + role + "-" + String(txnCounter));
      if (!session.ok) {
        err({ admit: "session_refused", reason: session.reason });
        return;
      }
      const intent = {
        initiatedBy: "local_operator",
        operatorRef: "op-26h",
        rationale: "26H: explicit LOCAL admission of an already-enrolled candidate",
        decidedAtEpochMs: now(),
        localEpochId: registry.epochId,
      };
      const gate = ds.checkLocalAdminIntent({ intent, liveEpochId: registry.epochId });
      if (!gate.ok) {
        err({ admit: "intent_refused", explanation: gate.explanation });
        return;
      }
      const read = registry.readPeer(argument);
      const facts = peerFacts.get(argument);
      if (!read.ok || facts === undefined) {
        err({ admit: "unknown_candidate", nodeId: argument });
        return;
      }
      const admitted = session.session.admitCandidate({
        nodeId: facts.nodeId,
        fingerprint: facts.fingerprint,
        instanceId: facts.instanceId,
        protocolVersion: FEDERATION_PROTOCOL,
        intent,
        transactionId: txn("admit"),
        lineageRoot: PROVENANCE_LINEAGE,
        lineageParent: null,
      });
      ok({
        admit: admitted.ok ? "admitted" : "admit_refused",
        nodeId: facts.nodeId,
        intentHash: gate.intentHash,
        failureCode: admitted.ok ? null : admitted.failureCode,
        trust: livePeerTrust(facts.nodeId),
      });
      return;
    }
    if (command === "retire") {
      const facts = peerFacts.get(argument);
      if (facts === undefined) {
        err({ retire: "unknown_peer", nodeId: argument });
        return;
      }
      const retired = registry.applyTrustTransition({
        nodeId: facts.nodeId,
        fingerprint: facts.fingerprint,
        instanceId: facts.instanceId,
        protocolVersion: FEDERATION_PROTOCOL,
        reason: "operator_retirement",
        evidence: "26H: evidenced local retirement after the counterparty re-identified (re-identity, never key mutation)",
        transactionId: txn("retire"),
        lineageRoot: PROVENANCE_LINEAGE,
        lineageParent: null,
        nowEpochMs: now(),
      });
      const resurrect = registry.applyTrustTransition({
        nodeId: facts.nodeId,
        fingerprint: facts.fingerprint,
        instanceId: facts.instanceId,
        protocolVersion: FEDERATION_PROTOCOL,
        reason: "admission_request_accepted",
        evidence: "26H: resurrection attempt on a terminal identity",
        transactionId: txn("resurrect"),
        lineageRoot: PROVENANCE_LINEAGE,
        lineageParent: null,
        nowEpochMs: now(),
      });
      ok({
        retire: retired.ok ? "retired" : "retire_refused",
        nodeId: facts.nodeId,
        retireFailureCode: retired.ok ? null : retired.failureCode,
        trust: livePeerTrust(facts.nodeId),
        resurrectOk: resurrect.ok,
        resurrectFailureCode: resurrect.ok ? null : resurrect.failureCode,
      });
      return;
    }
    if (command === "dial") {
      if (role !== "A") {
        err({ dial: "role_not_dialer" });
        return;
      }
      const result = await dialTo(Number(argument));
      ok({ dial: result, connection: 1, local: lastLocal, ingress: lastIngress });
      return;
    }
    if (command === "send" || command === "send-old") {
      if (role !== "A") {
        err({ send: "role_not_sender" });
        return;
      }
      if (initiatorSession === null || initiatorSession.state() !== "established") {
        err({ send: "no_established_session" });
        return;
      }
      const body = decode(argument);
      const signingIdentity = command === "send-old" ? retiredIdentity : identity;
      const message = {
        schemaVersion: ds.INGRESS_EXPECTED_MESSAGE_SCHEMA_VERSION,
        messageId: body.messageId,
        senderNodeId: signingIdentity.nodeId,
        senderFingerprint: signingIdentity.fingerprint,
        senderInstanceId: INSTANCE_ID,
        senderEpochId: body.senderEpochId,
        protocolVersion: FEDERATION_PROTOCOL,
        payloadHash: "sha256-" + ds.canonicalHash(body.payload),
        declaredIntent: "task_proposal",
        correlationId: null,
        causationId: null,
        lineage: [],
        issuedAtEpochMs: body.issuedAtEpochMs,
      };
      const signed = ds.signFederationMessage(signingIdentity, message);
      if (!signed.ok) {
        err({ send: "sign_refused", explanation: signed.explanation });
        return;
      }
      const wire = {
        envelope: { message, signature: signed.signature },
        // A tampered send DELIVERS different bytes than the signed body
        // claims — the honest shape of a post-signature tamper attack.
        payload: body.tamperPayload === undefined ? body.payload : body.tamperPayload,
        requiresDisclosure: body.requiresDisclosure === true,
        disclosure: body.disclosure === undefined ? undefined : body.disclosure,
      };
      const bytes = Buffer.from(JSON.stringify(wire), "utf8");
      const sent = initiatorSession.send(new Uint8Array(bytes), now());
      ok({
        send: sent.ok ? "sent" : "send_refused",
        bytes: bytes.length,
        messageId: message.messageId,
        senderNodeId: message.senderNodeId,
        transcriptHash: initiatorSession.transcriptHash(),
      });
      return;
    }
    if (command === "prepare") {
      // A prepares a proposal + the 25D disclosure BEFORE the wire.
      const spec = decode(argument);
      const preparedAt = now();
      const proposalId =
        spec.proposalId === undefined
          ? ds
              .makeFederationMessageId(preparedAt, "26hprop" + String(prepareCounter).padStart(9, "0"))
              .replace(/^fm-/, "fp-")
          : spec.proposalId;
      prepareCounter += 1;
      const payload = {
        schemaVersion: "menog-task-proposal/v0",
        proposalId,
        intentClass: "workspace_survey",
        contentHashes: ["sha256-" + "a".repeat(64)],
        provenance: { originNodeId: identity.nodeId, originFingerprint: identity.fingerprint, note: spec.note },
        constraints: { maxBudgetSteps: 2, readonlyWorkspaceOnly: true },
        expectedEvidence: ["sha256-" + "b".repeat(64)],
      };
      const payloadHash = "sha256-" + ds.canonicalHash(payload);
      const disclosure = ds.decideEgress({
        candidate: {
          schemaVersion: ds.EGRESS_SCHEMA_VERSION,
          payloadHash,
          fields: [
            { key: "nodeId", egressClass: "public_identity", value: identity.nodeId },
            { key: "fingerprint", egressClass: "public_identity", value: identity.fingerprint },
            { key: "messageId", egressClass: "protocol_metadata", value: spec.messageId },
            { key: "declaredIntent", egressClass: "bounded_intent", value: "task_proposal" },
            { key: "payloadHash", egressClass: "content_hashes", value: payloadHash },
            { key: "proposalRecordId", egressClass: "provenance_refs", value: "fpr-" + payload.proposalId },
          ],
        },
        outgoingPayloadHash: payloadHash,
        nowEpochMs: now(),
      });
      if (!disclosure.ok) {
        err({ prepare: "egress_refused", denyCode: disclosure.denyCode, explanation: disclosure.explanation });
        return;
      }
      const verified = ds.verifyEgressManifest({ manifest: disclosure.manifest, outgoingPayloadHash: payloadHash });
      ok({
        prepared: true,
        messageId: spec.messageId,
        senderEpochId: EPOCH_ID,
        issuedAtEpochMs: now(),
        payload,
        disclosure: disclosure.manifest,
        disclosureVerified: verified.ok,
        payloadHash,
      });
      return;
    }
    if (command === "rotate") {
      if (role !== "A") {
        err({ rotate: "role_mismatch" });
        return;
      }
      const result = ds.rotateLocalIdentity(identity);
      if (!result.ok) {
        err({ rotate: "refused", explanation: result.explanation });
        return;
      }
      retiredIdentity = identity;
      const requested = ds.decideLifecycleTransition({
        record: lifecycle,
        to: "rotation_requested",
        evidence: "26H: operator rotation request (request before execute)",
        nowEpochMs: now(),
      });
      if (!requested.ok) {
        err({ rotate: "request_refused", explanation: requested.explanation });
        return;
      }
      const fresh = result.fresh;
      const executed = ds.decideLifecycleTransition({
        record: requested.record,
        to: "rotated",
        evidence: "26H: evidenced re-identity to a genuinely fresh key",
        nowEpochMs: now(),
        freshPublicFacts: {
          publicKeyHex: fresh.publicKeyHex,
          fingerprint: fresh.fingerprint,
          nodeId: fresh.nodeId,
        },
      });
      if (!executed.ok) {
        err({ rotate: "execute_refused", explanation: executed.explanation });
        return;
      }
      const oldKeyUse = ds.decideKeyUse({ record: executed.record });
      const inheritance = ds.decideTrustInheritance({ oldRecord: executed.record, freshNodeId: fresh.nodeId });
      const previous = { identity, epochId: EPOCH_ID };
      // The re-identified node starts from its OWN fresh active record: the
      // retired record stays terminal for the OLD key and never carries the
      // new one, which is exactly the "no inheritance" law in 25A P7.
      const reinitialised = ds.decideLifecycleTransition({
        record: null,
        to: "active",
        evidence: "26H: fresh identity initialize after an evidenced re-identity (no inherited trust, no inherited key)",
        nowEpochMs: now(),
        freshPublicFacts: {
          publicKeyHex: fresh.publicKeyHex,
          fingerprint: fresh.fingerprint,
          nodeId: fresh.nodeId,
        },
      });
      if (!reinitialised.ok) {
        err({ rotate: "reinitialize_refused", explanation: reinitialised.explanation });
        return;
      }
      retiredLifecycle = executed.record;
      identity = fresh;
      lifecycle = reinitialised.record;
      // The re-identified node starts from a NEW runtime epoch and a NEW,
      // separately-admitted identity. The retired key stays usable ONLY to
      // prove it is denied.
      ok({
        rotate: "rotated",
        previousNodeId: previous.identity.nodeId,
        previousFingerprint: previous.identity.fingerprint,
        nodeId: fresh.nodeId,
        fingerprint: fresh.fingerprint,
        publicKeyHex: fresh.publicKeyHex,
        epochId: EPOCH_ID,
        lifecycleState: lifecycle.state,
        oldKeyUse: oldKeyUse.ok ? "ALLOWED" : oldKeyUse.code,
        trustInheritance: inheritance.ok ? "INHERITED" : inheritance.code,
      });
      return;
    }
    if (command === "clock") {
      // The parent advances this process's caller-supplied clock (time passed
      // across a restart). No module below reads a clock for itself.
      const requested = Number(argument);
      if (!Number.isFinite(requested) || requested < clock) {
        err({ clock: "refused", explanation: "the clock seed may only advance, never rewind" });
        return;
      }
      clock = Math.floor(requested);
      ok({ clock: "advanced", nowMs: clock });
      return;
    }
    if (command === "stop") {
      if (listener === null) {
        ok({ stop: "already_stopped" });
        return;
      }
      const stopped = await listener.stop();
      ok({ stop: stopped.code, closedConnections: stopped.closedConnections, state: listener.state() });
      return;
    }
    if (command === "listener") {
      ok({
        listener: listener === null ? "absent" : listener.state(),
        decision: listener === null ? null : listener.decision(),
        activeConnections: listener === null ? 0 : listener.activeConnections(),
        window: window.stats(),
        ingressCount,
        refusedCount,
        lastIngress,
        lastLocal,
      });
      return;
    }
    if (command === "peers") {
      // The peer view is read from DURABLE state, never from memory: after a
      // restart this is exactly the recovered DATA (with zero authority).
      const rows = [];
      for (const recordId of store.listRecordIds("peer_trust_registry")) {
        const record = store.readRecord(recordId);
        if (!record.ok) continue;
        const state = record.record.payload["peerTrust"];
        if (state === null || typeof state !== "object") continue;
        rows.push({
          nodeId: String(state["nodeId"]),
          trustState: String(state["trustState"]),
          fingerprint: String(state["fingerprint"]),
          revision: record.record.revision,
          terminal: state["trustState"] === "quarantined" || state["trustState"] === "retired",
        });
      }
      rows.sort((left, right) => (left.nodeId < right.nodeId ? -1 : left.nodeId > right.nodeId ? 1 : 0));
      ok({ peers: rows, source: "durable_store", unreadable: [] });
      return;
    }
    err({ unknown_command: command });
  } catch (error) {
    err({ command, error: String((error && error.message) || error) });
  }
}

// ── deterministic teardown ──────────────────────────────────────────────────
async function teardown() {
  try {
    if (responderSession !== null) responderSession.close();
  } catch {
    /* already closed */
  }
  try {
    if (framedTransport !== null) framedTransport.closeAll();
  } catch {
    /* already closed */
  }
  try {
    if (listener !== null) await listener.stop();
  } catch {
    /* already stopped */
  }
  try {
    if (dialSocket !== null) dialSocket.destroy();
  } catch {
    /* already destroyed */
  }
  try {
    coordinator.close();
  } catch {
    /* already closed */
  }
  try {
    if (store.isOpen) store.close();
  } catch {
    /* windows handles */
  }
}

// ── boot ────────────────────────────────────────────────────────────────────
async function boot() {
  if (role === "B") {
    // The 26B endpoint decision is computed by the module; the fixture never
    // decides anything about the endpoint itself.
    listener = new ds.LocalEndpointListener({
      source: "explicit_local_config",
      host: "127.0.0.1",
      port: PORT,
      connections: 4,
      queue: 8,
    });
    const decision = listener.decision();
    if (!decision.ok) fatal("26B endpoint refused: " + decision.refusal + " — " + decision.explanation);
    framedTransport = new ds.FramedTransport({ maxConnections: 4 });
    listener.onConnection(openResponder);
    const started = await listener.start();
    if (!started.ok) fatal("26B listener refused to start: " + started.code + " — " + started.explanation);
  }
  ok({
    role,
    nodeId: identity.nodeId,
    epochId: EPOCH_ID,
    listening: listener === null ? false : listener.state() === "listening",
  });
  console.log("ready:" + role);
}

let chain = Promise.resolve();
process.stdin.setEncoding("utf8");
let buffer = "";
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let index = buffer.indexOf("\n");
  while (index >= 0) {
    const line = buffer.slice(0, index).trim();
    buffer = buffer.slice(index + 1);
    chain = chain.then(() => handle(line)).catch((error) => err({ error: String((error && error.message) || error) }));
    index = buffer.indexOf("\n");
  }
});
process.stdin.on("end", () => {
  chain = chain.then(teardown);
});

await boot();
