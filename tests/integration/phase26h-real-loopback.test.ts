/**
 * PHASE 26H — Real Loopback Scenario (TWO OS PROCESSES / REAL SOCKETS /
 * LOOPBACK ONLY / NO INTERNET·PUBLIC·DISCOVERY·RELAY·CONSENSUS).
 *
 * This is the scenario gate: it does NOT re-test the 26A–26F units (those
 * suites own them). It proves they COMPOSE across a real OS process boundary
 * over a real 127.0.0.1 socket, and that the whole chain still ends where the
 * hard law says it must end:
 *
 *   NETWORK REACHABILITY != IDENTITY != ADMISSION != AUTHORITY != EXECUTION.
 *
 * Scenario, as the pack specifies it:
 *   1. two processes, distinct identities, distinct runtime epochs, distinct
 *      durable stores; explicit numeric loopback endpoint only;
 *   2. B LOCALLY admits A through the intent-gated 25C admin session (and A
 *      admits B for its own side — a mutual handshake needs mutual LOCAL
 *      admission, and neither is inferred from reachability);
 *   3. A prepares a proposal and passes the 25D egress disclosure BEFORE the
 *      wire, so the manifest binds the exact bytes that travel;
 *   4. a REAL socket: A dials 127.0.0.1, the REAL 26B listener accepts inside
 *      its ONE sanctioned connection handler, REAL 26C framing and the REAL
 *      26D three-message handshake establish a bound transcript;
 *   5. the signed envelope is judged by the REAL 26E junction — all nine
 *      mandatory stages — and lands as UNTRUSTED DATA with `authority: "none"`
 *      and `executionAuthorized: false`;
 *   6. ONLY then does B continue locally: fresh LOCAL 19B allocation → fresh
 *      LOCAL Day-1 Policy FOR THE ASSIGNED ACTOR → fresh-authorization gate →
 *      Phase-20 isolation + Phase-21 governed tool runtime (injected transport
 *      double, never a spawn) → 22C atomic evidence pair → 23B/23C continuity
 *      → 24E proposal ledger → 24F `local_action` provenance anchor;
 *   7. rotate/re-identify A: the old key is denied, the replacement is NOT
 *      trusted automatically, and only an explicit LOCAL admission opens the
 *      door;
 *   8. restart B (SIGKILL, new process, new epoch, same store): recovered
 *      facts are DATA with zero authority, the old envelope is refused at the
 *      durable receipt, A reconnects, and a new proposal again needs FRESH
 *      local authority.
 *
 * Negative controls (all over the real wire or the real durable store):
 *   unknown · wrong-key · stale-epoch · tamper · replay · stale disclosure ·
 *   revoked admission · Policy deny · actor mismatch · no auto-resume ·
 *   no capability union · no auto-trust of a re-identified peer.
 *
 * SCOPE HONESTY: loopback only. No Internet/public endpoint, no discovery, no
 * relay, no NAT traversal, no consensus, no remote authority, no deployment,
 * no Git, no publication. This is a PROCESS-KILL restart, not a power-cut —
 * no power-loss, controller-cache, hardware-failure, DDoS, WAN or
 * production-capacity claim is made or testable here.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DurableStore,
  makeFederationMessageId,
  type DurableRecordEnvelope,
} from "@menog/durable-state";

const CHILD = join(process.cwd(), "tests", "fixtures", "phase26h-loopback-node.mjs");
const CHILD_SOURCE = readFileSync(CHILD, "utf8");

/** Ports are explicit and unique per scenario; nothing is discovered. */
const PORT_MAIN = 41910;
const PORT_ROTATE = 41911;
const PORT_RESTART = 41912;
const PORT_CONTROL = 41913;

const NOW = 1_759_100_000_000;
/** Time that has passed by the time B is restarted after the process kill. */
const RESTART_NOW = NOW + 900_000;

const b64 = (value: unknown): string =>
  Buffer.from(JSON.stringify(value), "utf8").toString("base64");

// ── the child-process harness ────────────────────────────────────────────────

interface ChildLine {
  readonly raw: string;
  readonly value: Record<string, unknown> | null;
  readonly ok: boolean;
}

interface NodeHandle {
  readonly role: "A" | "B";
  readonly root: string;
  readonly port: number;
  readonly child: ChildProcess;
  readonly lines: ChildLine[];
  readonly stderr: () => string;
  /** Forget every line seen so far (used right after the readiness marker). */
  drain(): void;
  send(command: string): void;
  /** Ask + correlate: resolves on the line echoing this command's tag. */
  ask<T>(command: string, note: string): Promise<T>;
  /** Resolve on the first not-yet-consumed line whose value satisfies `match`. */
  waitFor(match: (line: ChildLine) => boolean, note: string, timeoutMs?: number): Promise<ChildLine>;
  kill(signal?: NodeJS.Signals): void;
}

const spawned: NodeHandle[] = [];

function parseLine(raw: string): ChildLine {
  const trimmed = raw.trim();
  const isOk = trimmed.startsWith("ok:");
  const isErr = trimmed.startsWith("err:");
  const body = isOk ? trimmed.slice(3) : isErr ? trimmed.slice(4) : "";
  let value: Record<string, unknown> | null = null;
  try {
    value = body === "" ? null : (JSON.parse(body) as Record<string, unknown>);
  } catch {
    value = null;
  }
  return { raw: trimmed, value, ok: isOk };
}

function spawnNode(role: "A" | "B", root: string, port: number, seed: string, clockSeedMs: number = NOW): NodeHandle {
  const child = spawn(process.execPath, [CHILD, role, root, String(port), seed, String(clockSeedMs)], {
    stdio: ["pipe", "pipe", "pipe"],
    cwd: process.cwd(),
  });
  const lines: ChildLine[] = [];
  let stderrText = "";
  const waiters: Array<{ match: (line: ChildLine) => boolean; resolve: (line: ChildLine) => void }> = [];
  const consume = (line: ChildLine): void => {
    for (let index = 0; index < waiters.length; index += 1) {
      const waiter = waiters[index];
      if (waiter === undefined) continue;
      if (!waiter.match(line)) continue;
      waiters.splice(index, 1);
      waiter.resolve(line);
      return;
    }
    lines.push(line);
  };
  let buffer = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    buffer += chunk;
    let index = buffer.indexOf("\n");
    while (index >= 0) {
      const raw = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      consume(parseLine(raw));
      index = buffer.indexOf("\n");
    }
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderrText += chunk;
  });
  let tagCounter = 0;
  const handle: NodeHandle = {
    role,
    root,
    port,
    child,
    lines,
    stderr: () => stderrText,
    drain() {
      lines.length = 0;
    },
    send(command) {
      child.stdin.write(command + "\n");
    },
    async ask<T>(command: string, note: string): Promise<T> {
      tagCounter += 1;
      const tag = role + "-" + String(tagCounter);
      child.stdin.write(command + " #" + tag + "\n");
      const line = await handle.waitFor(
        (candidate) => candidate.value !== null && candidate.value["echo"] === tag,
        note + " (response to `" + command.split(" ")[0] + "`) on " + role,
        20_000,
      );
      if (line.value === null) throw new Error(note + ": unparseable line " + line.raw.slice(0, 200));
      return line.value as unknown as T;
    },
    async waitFor(match, note, timeoutMs = 20_000) {
      const existing = lines.findIndex(match);
      if (existing >= 0) {
        const found = lines[existing];
        lines.splice(existing, 1);
        if (found === undefined) throw new Error("unreachable");
        return found;
      }
      return new Promise<ChildLine>((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(
            new Error(
              "timed out waiting for " + note + " on " + role +
              " (exitCode=" + String(child.exitCode) + " signal=" + String(child.signalCode) + ")\nstdout: " +
              lines.map((line) => line.raw.slice(0, 200)).join("\n") +
              "\nstderr: " + stderrText.slice(0, 800),
            ),
          );
        }, timeoutMs);
        waiters.push({
          match,
          resolve: (line) => {
            clearTimeout(timer);
            resolve(line);
          },
        });
      });
    },
    kill(signal = "SIGKILL") {
      try {
        child.kill(signal);
      } catch {
        /* already dead */
      }
    },
  };
  spawned.push(handle);
  return handle;
}

async function awaitReady(node: NodeHandle): Promise<void> {
  await node.waitFor((line) => line.raw === "ready:" + node.role, "ready:" + node.role, 30_000);
  // Everything printed before the marker is the boot banner, not a command
  // response; forgetting it keeps `ask` from answering with it.
  node.drain();
}

async function ask<T>(node: NodeHandle, command: string, note: string): Promise<T> {
  return node.ask<T>(command, note);
}

interface Facts {
  readonly role: string;
  readonly pid: number;
  readonly nodeId: string;
  readonly fingerprint: string;
  readonly publicKeyHex: string;
  readonly instanceId: string;
  readonly epochId: string;
  readonly lifecycleState: string;
  readonly restarted: boolean;
  readonly listening: boolean;
  readonly port: number | null;
  readonly handoff: {
    readonly ok: boolean;
    readonly terminalState: string;
    readonly newEpochId: string | null;
    readonly priorEpochId: string | null;
    readonly blockingClass: string | null;
    readonly grantsAuthority: boolean | null;
    readonly resumeSemantics: string | null;
    readonly executionPathRequirement: string | null;
  };
}

interface PeerResult {
  readonly peer: string;
  readonly nodeId: string;
  readonly intentHash?: string;
  readonly failureCode?: string | null;
  readonly trust: { readonly state: string; readonly fingerprint: string };
}

interface AdmitResult {
  readonly admit: string;
  readonly nodeId: string;
  readonly intentHash: string;
  readonly failureCode: string | null;
  readonly trust: { readonly state: string; readonly fingerprint: string };
}

interface PreparedWire {
  readonly messageId: string;
  readonly senderEpochId: string;
  readonly issuedAtEpochMs: number;
  readonly payload: Record<string, unknown>;
  readonly disclosure: Record<string, unknown>;
  readonly disclosureVerified: boolean;
  readonly payloadHash: string;
}

interface IngressLine {
  readonly ingress?: string;
  readonly ok?: boolean;
  readonly stage?: string;
  readonly stagesRun?: readonly string[];
  readonly authority?: string;
  readonly executionAuthorized?: boolean;
  readonly nextGate?: string;
  readonly code?: string;
  readonly upstreamCode?: string | null;
  readonly pins?: readonly string[];
  readonly explanation?: string;
  readonly messageId?: string;
  readonly senderNodeId?: string;
  readonly transcriptHash?: string;
  readonly receiptRecordId?: string;
  readonly commitSequence?: number;
}

interface LocalResult {
  readonly local?: string;
  readonly candidateInert: boolean;
  readonly allocationId: string;
  readonly assignedAgentId: string;
  readonly policyOutcome: string;
  readonly policyRule: string;
  readonly policyActorId: string;
  readonly gate: string;
  readonly toolDecisionStatus: string;
  readonly toolResultStatus: string | null;
  readonly transportOverrideCalled: boolean;
  readonly spawned: boolean;
  readonly sealedRecordHash: string;
  readonly continuity: string;
  readonly proposalRecordId: string | null;
  readonly anchorId: string | null;
  readonly anchorDecision: string | null;
  readonly controls: {
    readonly stale_allocation?: string;
    readonly actor_mismatch: string;
    readonly policy_deny: { readonly policyOutcome: string; readonly gate: string };
    readonly capability_union: string;
    readonly no_auto_resume: string;
  };
}

interface DialResult {
  readonly dial: {
    readonly state: string;
    readonly transcriptHash: string | null;
    readonly established?: boolean;
    readonly endCode?: string | null;
    readonly endExplanation?: string | null;
  };
}

interface SendBody {
  readonly messageId: string;
  readonly senderEpochId: string;
  readonly issuedAtEpochMs: number;
  readonly payload: Record<string, unknown>;
  readonly requiresDisclosure?: boolean;
  readonly disclosure?: Record<string, unknown>;
  readonly tamperPayload?: Record<string, unknown>;
}

const isIngress = (line: ChildLine): boolean =>
  line.value !== null && (line.value["ingress"] === "ingress" || line.value["ingress"] === "admitted");
const isLocal = (line: ChildLine): boolean =>
  line.value !== null && (line.value["local"] === "completed" || line.value["local"] === "refused");
const isSessionClosed = (line: ChildLine): boolean =>
  line.value !== null && (line.value["session"] === "closed" || line.value["initiator"] === "closed");

/** Peer facts in the shape the fixture's `peer` command consumes. */
function peerFactsOf(other: Facts, mode: "admit" | "candidate") {
  return b64({
    nodeId: other.nodeId,
    fingerprint: other.fingerprint,
    publicKeyHex: other.publicKeyHex,
    instanceId: other.instanceId,
    runtimeEpochId: other.epochId,
    mode,
  });
}

// ── durable read-back (proves the evidence really landed on disk) ─────────────

const openedRoots: string[] = [];
function readDurable(root: string, recordId: string): DurableRecordEnvelope | null {
  const opened = DurableStore.open(root);
  if (!opened.ok) throw new Error("reopen refused for " + root + ": " + opened.reason);
  openedRoots.push(root);
  const read = opened.store.readRecord(recordId);
  opened.store.close();
  return read.ok ? read.record : null;
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. the main scenario, end to end, in two OS processes
// ═════════════════════════════════════════════════════════════════════════════

describe("26H real loopback scenario (two OS processes, real 127.0.0.1 sockets)", () => {
  let base = "";
  let b: NodeHandle;
  let a: NodeHandle;
  let bFacts: Facts;
  let aFacts: Facts;
  let wire: PreparedWire;
  let ingress: IngressLine;
  let local: LocalResult;

  beforeAll(async () => {
    base = mkdtempSync(join(tmpdir(), "menog-26h-"));
    b = spawnNode("B", join(base, "b"), PORT_MAIN, "bootbbbbbbbbbb");
    await awaitReady(b);
    a = spawnNode("A", join(base, "a"), 0, "bootaaaaaaaaaaa");
    await awaitReady(a);

    bFacts = await ask<Facts>(b, "facts", "B facts");
    aFacts = await ask<Facts>(a, "facts", "A facts");

    // mutual, evidenced LOCAL admission — neither side infers trust from a
    // reachable port; each records its own operator intent in its own store
    const aAdmitsB = await ask<PeerResult>(a, "peer " + peerFactsOf(bFacts, "admit"), "A admits B");
    expect(aAdmitsB.peer).toBe("admitted");
    const bAdmitsA = await ask<PeerResult>(b, "peer " + peerFactsOf(aFacts, "admit"), "B admits A");
    expect(bAdmitsA.peer).toBe("admitted");

    const messageId = makeFederationMessageId(NOW, "26hmainproposal01");
    wire = await ask<PreparedWire>(
      a,
      "prepare " + b64({ messageId, note: "26H: proposed by node A over loopback" }),
      "A prepares the proposal and its 25D disclosure",
    );

    const dial = await ask<DialResult>(
      a,
      "dial " + String(PORT_MAIN),
      "A completes the real 26D handshake",
    );
    expect(dial.dial.state).toBe("established");
    expect(dial.dial.transcriptHash).toMatch(/^[0-9a-f]{64}$/);

    a.send(
      "send " +
        b64({
          messageId: wire.messageId,
          senderEpochId: wire.senderEpochId,
          issuedAtEpochMs: wire.issuedAtEpochMs,
          payload: wire.payload,
          requiresDisclosure: true,
          disclosure: wire.disclosure,
        } satisfies SendBody),
    );

    const ingressLine = await b.waitFor(isIngress, "B's 26E ingress decision");
    ingress = ingressLine.value as IngressLine;
    const localLine = await b.waitFor(isLocal, "B's local continuation");
    local = localLine.value as unknown as LocalResult;
  }, 90_000);

  afterAll(() => {
    for (const node of spawned) node.kill();
    for (const root of openedRoots) {
      try { rmSync(root, { recursive: true, force: true }); } catch { /* windows handles */ }
    }
    try { rmSync(base, { recursive: true, force: true }); } catch { /* windows handles */ }
  });

  it("runs in two OS processes with distinct identities, epochs and stores", () => {
    expect(a.child.pid).not.toBe(b.child.pid);
    expect(aFacts.nodeId).not.toBe(bFacts.nodeId);
    expect(aFacts.fingerprint).not.toBe(bFacts.fingerprint);
    expect(aFacts.publicKeyHex).not.toBe(bFacts.publicKeyHex);
    expect(aFacts.epochId).not.toBe(bFacts.epochId);
    expect(a.root).not.toBe(b.root);
    expect(bFacts.handoff.ok).toBe(true);
    expect(bFacts.handoff.terminalState).toBe("LIVE");
    // recovery/handoff never grants authority and never auto-resumes
    expect(bFacts.handoff.grantsAuthority).toBe(false);
    expect(bFacts.handoff.resumeSemantics).toBe("no_auto_resume");
    expect(bFacts.handoff.executionPathRequirement).toBe(
      "planner_allocation_policy_isolation_governed_tool_runtime",
    );
    expect(aFacts.listening).toBe(false);
    expect(bFacts.listening).toBe(true);
  });

  it("B binds ONE explicit numeric loopback endpoint and nothing else", async () => {
    const listener = await ask<{
      listener: string;
      decision: { ok: boolean; addressClass: string; host: string; port: number };
      activeConnections: number;
    }>(b, "listener", "B's listener state");
    expect(listener.listener).toBe("listening");
    expect(listener.decision.ok).toBe(true);
    expect(listener.decision.addressClass).toBe("ipv4_loopback");
    expect(listener.decision.host).toBe("127.0.0.1");
    expect(listener.decision.port).toBe(PORT_MAIN);
    expect(listener.activeConnections).toBeGreaterThanOrEqual(1);
  });

  it("the fixture binds loopback explicitly and never a wildcard, a name, or the environment", () => {
    // Static scan of the ONE sanctioned bind site: the explicit numeric
    // loopback literal, the explicit config source, and nothing that could
    // reach a public endpoint, discover one, or read one from the environment.
    expect(CHILD_SOURCE).toContain('source: "explicit_local_config"');
    expect(CHILD_SOURCE).toContain('host: "127.0.0.1"');
    for (const forbidden of ["0.0.0.0", '"::"', '"*"', "process.env", "dns.lookup", "os.hostname", "external"]) {
      expect(CHILD_SOURCE).not.toContain(forbidden);
    }
    // The dialer is a plain numeric loopback connect, never a name lookup.
    expect(CHILD_SOURCE).toContain('connect({ port: target, host: "127.0.0.1" }');
    // No shell, no child process, no remote admin anywhere in the fixture.
    for (const forbidden of ["exec(", "execSync", "spawnSync", "child_process", "eval("]) {
      expect(CHILD_SOURCE).not.toContain(forbidden);
    }
  });

  it("A's 25D disclosure binds the exact bytes that go on the wire", () => {
    expect(wire.disclosureVerified).toBe(true);
    expect(wire.payloadHash).toMatch(/^sha256-[0-9a-f]{64}$/);
    const disclosed = wire.disclosure["disclosed"] as ReadonlyArray<{ key: string; value: string }>;
    expect(disclosed.some((field) => field.key === "payloadHash" && field.value === wire.payloadHash)).toBe(true);
    expect(wire.disclosure["refused"]).toEqual([]);
    expect(wire.disclosure["redacted"]).toEqual([]);
  });

  it("the real handshake over the real socket admitted the message through ALL NINE ingress stages", () => {
    expect(ingress.ok).toBe(true);
    expect(ingress.stage).toBe("untrusted_inbox");
    expect([...(ingress.stagesRun ?? [])]).toEqual([
      "frame_validity",
      "session_binding",
      "current_key_use",
      "local_admission",
      "disclosure_verification",
      "schema_version",
      "authentication",
      "replay_receipt",
      "untrusted_inbox",
    ]);
    expect(ingress.senderNodeId).toBe(aFacts.nodeId);
    expect(ingress.transcriptHash).toMatch(/^[0-9a-f]{64}$/);
    expect(ingress.receiptRecordId?.startsWith("frc-")).toBe(true);
    expect(ingress.commitSequence).toBeGreaterThan(0);
  });

  it("the admitted message is UNTRUSTED DATA that grants NOTHING", () => {
    expect(ingress.authority).toBe("none");
    expect(ingress.executionAuthorized).toBe(false);
    expect(ingress.nextGate).toBe(
      "fresh_local_allocation_then_fresh_local_policy_for_the_assigned_actor_then_phase_20_21",
    );
  });

  it("only then did B run fresh LOCAL allocation + fresh LOCAL Policy for the assigned actor", () => {
    expect(local.candidateInert).toBe(true);
    expect(local.allocationId).toMatch(/^asg-/);
    // The Policy was judged FOR the assigned actor, and that actor is the one
    // the allocation produced — the confused-deputy binding holds over a real
    // socket exactly as it holds in-process.
    expect(local.policyActorId).toBe(local.assignedAgentId);
    expect(local.policyOutcome).toBe("allow");
    expect(local.policyRule.length).toBeGreaterThan(0);
    expect(local.gate).toBe("opened");
  });

  it("Phase-20 isolation + the Phase-21 governed tool runtime ran inside B, with no spawn", () => {
    expect(local.toolDecisionStatus).toBe("not_started");
    expect(local.toolResultStatus).toBe("completed");
    expect(local.transportOverrideCalled).toBe(true);
    expect(local.spawned).toBe(false);
  });

  it("the evidence and provenance are DURABLE in B's own store, readable after the fact", async () => {
    await ask(b, "stop", "B's idempotent listener stop");
    const received = await ask<{ stop: string }>(b, "stop", "B's second (idempotent) stop");
    expect(received.stop).toBe("listener_already_stopped");

    const receipt = readDurable(b.root, ingress.receiptRecordId ?? "");
    expect(receipt).not.toBeNull();
    const proposal = readDurable(b.root, local.proposalRecordId ?? "");
    expect(proposal).not.toBeNull();
    const anchor = readDurable(b.root, "fpv-" + (local.anchorId ?? ""));
    expect(anchor).not.toBeNull();
    if (anchor !== null) {
      const body = anchor.payload as Record<string, unknown>;
      expect(body["decision"]).toBe("local_action");
      expect(body["localPolicyDecision"]).toBe("allow");
      expect(body["receiverEpochId"]).toBe(bFacts.epochId);
      expect(body["senderNodeId"]).toBe(aFacts.nodeId);
    }
    expect(local.continuity).toBe("committed");
  });

  it("every LOCAL freshness control refuses on B's own facts", () => {
    expect(local.controls.actor_mismatch).toBe("actor_mismatch");
    expect(local.controls.policy_deny.policyOutcome).toBe("deny");
    expect(local.controls.policy_deny.gate).toBe("local_policy_denial");
    expect(local.controls.capability_union).toBe("REFUSED_NO_UNION");
    expect(local.controls.no_auto_resume).toBe("NO_RESUME_PATH");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 2. negative controls over the same real socket + the same real store
// ═════════════════════════════════════════════════════════════════════════════

describe("26H negative controls over the real loopback wire", () => {
  let base = "";
  let b: NodeHandle;
  let a: NodeHandle;
  let bFacts: Facts;
  let aFacts: Facts;
  let counter = 0;
  let established = false;

  /** A fresh, honest, disclosure-approved wire message. */
  async function prepare(): Promise<PreparedWire> {
    counter += 1;
    const messageId = makeFederationMessageId(NOW + counter, "26hcontrol" + String(counter).padStart(6, "0"));
    return ask<PreparedWire>(
      a,
      "prepare " + b64({ messageId, note: "26H control " + counter }),
      "A prepares control " + counter,
    );
  }

  async function connect(): Promise<void> {
    if (established) return;
    const dial = await ask<DialResult>(a, "dial " + String(PORT_CONTROL), "A dials B");
    expect(dial.dial.state).toBe("established");
    established = true;
  }

  beforeAll(async () => {
    base = mkdtempSync(join(tmpdir(), "menog-26h-ctl-"));
    b = spawnNode("B", join(base, "b"), PORT_CONTROL, "bootbbbbbbbbbb");
    await awaitReady(b);
    a = spawnNode("A", join(base, "a"), 0, "bootaaaaaaaaaaa");
    await awaitReady(a);
    bFacts = await ask<Facts>(b, "facts", "B facts");
    aFacts = await ask<Facts>(a, "facts", "A facts");
    await ask<PeerResult>(a, "peer " + peerFactsOf(bFacts, "admit"), "A admits B");
    await ask<PeerResult>(b, "peer " + peerFactsOf(aFacts, "admit"), "B admits A");
    await connect();
  }, 90_000);

  afterAll(() => {
    for (const node of [a, b]) node.kill();
    try { rmSync(base, { recursive: true, force: true }); } catch { /* windows handles */ }
  });

  it("an ADMITTED honest message flows, so every refusal below is real", async () => {
    const prepared = await prepare();
    a.send(
      "send " +
        b64({
          messageId: prepared.messageId,
          senderEpochId: prepared.senderEpochId,
          issuedAtEpochMs: prepared.issuedAtEpochMs,
          payload: prepared.payload,
          requiresDisclosure: true,
          disclosure: prepared.disclosure,
        } satisfies SendBody),
    );
    const line = await b.waitFor(isIngress, "the control's admitted ingress");
    expect(line.value?.["ok"]).toBe(true);
    await b.waitFor(isLocal, "the control's local continuation");
  });

  it("REPLAY of the identical envelope is refused at the DURABLE receipt", async () => {
    const prepared = await prepare();
    const body: SendBody = {
      messageId: prepared.messageId,
      senderEpochId: prepared.senderEpochId,
      issuedAtEpochMs: prepared.issuedAtEpochMs,
      payload: prepared.payload,
      requiresDisclosure: true,
      disclosure: prepared.disclosure,
    };
    a.send("send " + b64(body));
    const first = await b.waitFor((candidate) => isIngress(candidate) && candidate.value?.["ok"] === true, "the replay probe's first delivery");
    expect(first.value?.["ok"]).toBe(true);
    await b.waitFor(isLocal, "the replay probe's local continuation");
    // the SAME envelope again — the durable receipt is the commitment
    a.send("send " + b64(body));
    const second = await b.waitFor((line) => isIngress(line) && line.value?.["ok"] === false, "the replay refusal");
    expect(second.value?.["stage"]).toBe("replay_receipt");
    expect(second.value?.["code"]).toBe("replay_refused");
    expect(second.value?.["upstreamCode"]).toBe("replay_detected");
  }, 40_000);

  it("TAMPERED payload bytes refuse before authentication, naming the hash mismatch", async () => {
    const prepared = await prepare();
    a.send(
      "send " +
        b64({
          messageId: prepared.messageId,
          senderEpochId: prepared.senderEpochId,
          issuedAtEpochMs: prepared.issuedAtEpochMs,
          payload: prepared.payload,
          tamperPayload: { ...prepared.payload, note: "tampered after signing" },
          requiresDisclosure: true,
          disclosure: prepared.disclosure,
        } satisfies SendBody),
    );
    const line = await b.waitFor((candidate) => isIngress(candidate) && candidate.value?.["ok"] === false, "the tamper refusal");
    expect(line.value?.["stage"]).toBe("schema_version");
    expect(line.value?.["upstreamCode"]).toBe("payload_hash_mismatch");
  }, 40_000);

  it("a STALE sender epoch refuses at session binding", async () => {
    const prepared = await prepare();
    a.send(
      "send " +
        b64({
          messageId: prepared.messageId,
          senderEpochId: "re-222222222222-staleepochcccc",
          issuedAtEpochMs: prepared.issuedAtEpochMs,
          payload: prepared.payload,
          requiresDisclosure: true,
          disclosure: prepared.disclosure,
        } satisfies SendBody),
    );
    const line = await b.waitFor((candidate) => isIngress(candidate) && candidate.value?.["ok"] === false, "the stale-epoch refusal");
    expect(line.value?.["stage"]).toBe("session_binding");
    expect(line.value?.["code"]).toBe("epoch_stale");
  }, 40_000);

  it("a STALE disclosure (bound to a different payload) refuses", async () => {
    const prepared = await prepare();
    const other = await prepare();
    a.send(
      "send " +
        b64({
          messageId: prepared.messageId,
          senderEpochId: prepared.senderEpochId,
          issuedAtEpochMs: prepared.issuedAtEpochMs,
          payload: prepared.payload,
          requiresDisclosure: true,
          // a manifest that is perfectly valid — for a DIFFERENT payload
          disclosure: other.disclosure,
        } satisfies SendBody),
    );
    const line = await b.waitFor((candidate) => isIngress(candidate) && candidate.value?.["ok"] === false, "the stale-disclosure refusal");
    expect(line.value?.["stage"]).toBe("disclosure_verification");
    expect(line.value?.["code"]).toBe("disclosure_refused");
    expect(line.value?.["upstreamCode"]).toBe("stale_disclosure");
  }, 40_000);

  it("an UNKNOWN peer that was never locally admitted cannot get past B's session binding", async () => {
    const stranger = spawnNode("A", join(base, "stranger"), 0, "bootcccccccccccc");
    await awaitReady(stranger);
    const strangerFacts = await ask<Facts>(stranger, "facts", "stranger facts");
    expect(strangerFacts.nodeId).not.toBe(aFacts.nodeId);
    // The stranger honestly decides to trust B on ITS OWN side (its own local
    // admission, its own store). B has never enrolled or admitted the stranger.
    const admittedB = await ask<PeerResult>(
      stranger,
      "peer " + peerFactsOf(bFacts, "admit"),
      "the stranger admits B locally",
    );
    expect(admittedB.peer).toBe("admitted");
    stranger.send("dial " + String(PORT_CONTROL));
    // B's responder is bound to the admitted peer; a stranger presenting a
    // different NodeId is refused at the handshake, before any byte of
    // federation traffic is interpreted.
    const refusal = await b.waitFor(isSessionClosed, "B's refusal of the stranger");
    expect(refusal.value?.["code"]).toBe("node_mismatch");
    expect(String(refusal.value?.["explanation"])).toContain("is not the expected peer");
    stranger.kill();
  }, 40_000);

  it("REVOKED admission closes the very next session (evidenced retirement is terminal)", async () => {
    const retired = await ask<{
      retire: string;
      trust: { state: string };
      resurrectOk: boolean;
      resurrectFailureCode: string | null;
    }>(b, "retire " + aFacts.nodeId, "B retires A (evidenced)");
    expect(retired.retire).toBe("retired");
    expect(retired.trust.state).toBe("retired");
    // the retired identity is TERMINAL — resurrection is refused, not replayed
    expect(retired.resurrectOk).toBe(false);
    expect(retired.resurrectFailureCode).toBe("peer_terminal_state");

    established = false;
    const refusal = await ask<DialResult>(a, "dial " + String(PORT_CONTROL), "A's post-retirement dial");
    // A's side: the session never establishes and no transcript is ever bound.
    expect(refusal.dial.established).toBe(false);
    expect(refusal.dial.state).toBe("closed");
    expect(refusal.dial.transcriptHash).toBeNull();
    // B's side names the exact control that closed the door, on the live socket.
    const closed = await b.waitFor(isSessionClosed, "B's responder closure after retirement");
    expect(closed.value?.["code"]).toBe("peer_not_admitted");
    expect(String(closed.value?.["explanation"])).toContain("not admitted");
  }, 40_000);
});

// ═════════════════════════════════════════════════════════════════════════════
// 3. rotate / re-identify A
// ═════════════════════════════════════════════════════════════════════════════

describe("26H re-identification: rotate A, old denied, replacement not auto-trusted", () => {
  let base = "";
  let b: NodeHandle;
  let a: NodeHandle;
  let bFacts: Facts;
  let aFacts: Facts;

  beforeAll(async () => {
    base = mkdtempSync(join(tmpdir(), "menog-26h-rot-"));
    b = spawnNode("B", join(base, "b"), PORT_ROTATE, "bootbbbbbbbbbb");
    await awaitReady(b);
    a = spawnNode("A", join(base, "a"), 0, "bootaaaaaaaaaaa");
    await awaitReady(a);
    bFacts = await ask<Facts>(b, "facts", "B facts");
    aFacts = await ask<Facts>(a, "facts", "A facts");
    await ask<PeerResult>(a, "peer " + peerFactsOf(bFacts, "admit"), "A admits B");
    await ask<PeerResult>(b, "peer " + peerFactsOf(aFacts, "admit"), "B admits A");
  }, 90_000);

  afterAll(() => {
    for (const node of [a, b]) node.kill();
    try { rmSync(base, { recursive: true, force: true }); } catch { /* windows handles */ }
  });

  it("A ROTATES: request-before-execute, the old key is dead, trust inheritance is refused", async () => {
    const rotated = await ask<{
      rotate: string;
      previousNodeId: string;
      nodeId: string;
      fingerprint: string;
      oldKeyUse: string;
      trustInheritance: string;
    }>(a, "rotate", "A rotates its identity");
    expect(rotated.rotate).toBe("rotated");
    expect(rotated.previousNodeId).toBe(aFacts.nodeId);
    expect(rotated.nodeId).not.toBe(aFacts.nodeId);
    expect(rotated.fingerprint).not.toBe(aFacts.fingerprint);
    // 25B: the rotated-away key refuses use, and inheritance is ALWAYS refused
    expect(rotated.oldKeyUse).toBe("stale_rotated_key");
    expect(rotated.trustInheritance).toBe("trust_inheritance_refused");
  });

  it("the RETIRED key cannot get back in: B retires it and the record is terminal", async () => {
    const retired = await ask<{
      retire: string;
      trust: { state: string };
      resurrectOk: boolean;
      resurrectFailureCode: string | null;
    }>(b, "retire " + aFacts.nodeId, "B retires the OLD identity");
    expect(retired.retire).toBe("retired");
    expect(retired.trust.state).toBe("retired");
    expect(retired.resurrectOk).toBe(false);
    expect(retired.resurrectFailureCode).toBe("peer_terminal_state");
  });

  it("the REPLACEMENT identity enters only as a NEW candidate — never auto-trusted", async () => {
    const fresh = await ask<Facts>(a, "facts", "A's post-rotation facts");
    expect(fresh.nodeId).not.toBe(aFacts.nodeId);
    expect(fresh.lifecycleState).toBe("active");
    // B learns the replacement's PUBLIC facts and enrolls it on first contact.
    // Nothing about it is trusted: it is a CANDIDATE, not admitted.
    const enrolled = await ask<PeerResult>(
      b,
      "peer " + peerFactsOf(fresh, "candidate"),
      "B enrolls the replacement as a candidate",
    );
    expect(enrolled.peer).toBe("candidate");
    expect(enrolled.trust.state).toBe("candidate");
    // A also has to learn about B under the new epoch binding to dial it.
    await ask<PeerResult>(a, "peer " + peerFactsOf(bFacts, "admit"), "A re-binds B");

    const refusal = await ask<DialResult>(a, "dial " + String(PORT_ROTATE), "the not-auto-trusted dial");
    // The replacement's session never establishes: a CANDIDATE is not admitted,
    // so the frozen 26D recheck closes the door before any handshake completes.
    expect(refusal.dial.established).toBe(false);
    expect(refusal.dial.state).toBe("closed");
    expect(refusal.dial.transcriptHash).toBeNull();
    const closed = await b.waitFor(isSessionClosed, "B's responder closure for the untrusted replacement");
    expect(closed.value?.["code"]).toBe("peer_not_admitted");
    expect(String(closed.value?.["explanation"])).toContain("not admitted");
  }, 40_000);

  it("an EXPLICIT local admission opens the door, and the replacement then flows end to end", async () => {
    const fresh = await ask<Facts>(a, "facts", "A's post-rotation facts");
    const admitted = await ask<AdmitResult>(b, "admit " + fresh.nodeId, "B explicitly admits the replacement");
    expect(admitted.admit).toBe("admitted");
    expect(admitted.trust.state).toBe("admitted");

    const dial = await ask<DialResult>(
      a,
      "dial " + String(PORT_ROTATE),
      "the replacement completes a NEW handshake",
    );
    expect(dial.dial.state).toBe("established");

    const prepared = await ask<PreparedWire>(
      a,
      "prepare " + b64({ messageId: makeFederationMessageId(NOW, "26hrotatepropo1"), note: "26H: replacement proposal" }),
      "the replacement prepares a proposal",
    );
    a.send(
      "send " +
        b64({
          messageId: prepared.messageId,
          senderEpochId: prepared.senderEpochId,
          issuedAtEpochMs: prepared.issuedAtEpochMs,
          payload: prepared.payload,
          requiresDisclosure: true,
          disclosure: prepared.disclosure,
        } satisfies SendBody),
    );
    const admittedLine = await b.waitFor(isIngress, "the replacement's ingress");
    expect(admittedLine.value?.["ok"]).toBe(true);
    const freshLocal = await b.waitFor(isLocal, "the replacement's local continuation");
    const localResult = (freshLocal.value as unknown as LocalResult);
    expect(localResult.policyActorId).toBe(localResult.assignedAgentId);
    expect(localResult.spawned).toBe(false);
  }, 60_000);
});

// ═════════════════════════════════════════════════════════════════════════════
// 4. restart B (PROCESS-KILL — never a power-cut claim)
// ═════════════════════════════════════════════════════════════════════════════

describe("26H restart B: recovered DATA/no authority, replay denied, reconnect, fresh authority", () => {
  let base = "";
  let bRoot = "";
  let b: NodeHandle;
  let a: NodeHandle;
  let bFacts: Facts;
  let aFacts: Facts;
  let firstWire: PreparedWire;
  let firstLocal: LocalResult;

  beforeAll(async () => {
    base = mkdtempSync(join(tmpdir(), "menog-26h-rst-"));
    bRoot = join(base, "b");
    b = spawnNode("B", bRoot, PORT_RESTART, "bootbbbbbbbbbb");
    await awaitReady(b);
    a = spawnNode("A", join(base, "a"), 0, "bootaaaaaaaaaaa");
    await awaitReady(a);
    bFacts = await ask<Facts>(b, "facts", "B facts");
    aFacts = await ask<Facts>(a, "facts", "A facts");
    await ask<PeerResult>(a, "peer " + peerFactsOf(bFacts, "admit"), "A admits B");
    await ask<PeerResult>(b, "peer " + peerFactsOf(aFacts, "admit"), "B admits A");
    await ask<DialResult>(a, "dial " + String(PORT_RESTART), "A dials B");

    // two honest runs so B itself proves that a PREVIOUS allocation goes stale
    for (let index = 0; index < 2; index += 1) {
      firstWire = await ask<PreparedWire>(
        a,
        "prepare " + b64({ messageId: makeFederationMessageId(NOW + 700 + index, "26hrestartprop" + String(index)), note: "26H pre-restart " + index }),
        "A prepares pre-restart proposal " + index,
      );
      a.send(
        "send " +
          b64({
            messageId: firstWire.messageId,
            senderEpochId: firstWire.senderEpochId,
            issuedAtEpochMs: firstWire.issuedAtEpochMs,
            payload: firstWire.payload,
            requiresDisclosure: true,
            disclosure: firstWire.disclosure,
          } satisfies SendBody),
      );
      await b.waitFor(isIngress, "pre-restart ingress " + index);
      const line = await b.waitFor(isLocal, "pre-restart local continuation " + index);
      firstLocal = (line.value as unknown as LocalResult);
    }
  }, 120_000);

  afterAll(() => {
    for (const node of spawned) node.kill();
    try { rmSync(base, { recursive: true, force: true }); } catch { /* windows handles */ }
  });

  it("the pre-restart allocation went STALE — recovery never re-authorizes it", () => {
    expect(firstLocal.controls.stale_allocation).toBe("stale_local_allocation");
  });

  it("B is SIGKILLed and restarted in a NEW process on the SAME store and endpoint", async () => {
    b.kill("SIGKILL");
    await new Promise<void>((resolve) => b.child.once("exit", () => resolve()));
    b = spawnNode("B", bRoot, PORT_RESTART, "bootbbbbbbbbb2", RESTART_NOW);
    await awaitReady(b);
    // Time passed across the restart, on BOTH sides: A's caller-supplied
    // clock advances too, so neither node is outside the other's frozen skew
    // bound — the only difference is the crash.
    await ask(a, "clock " + String(RESTART_NOW), "A advances its clock past the restart");
    const restarted = await ask<Facts>(b, "facts", "the restarted B facts");
    expect(restarted.restarted).toBe(true);
    expect(restarted.pid).not.toBe(bFacts.pid);
    expect(restarted.handoff.priorEpochId).toBe(bFacts.epochId);
    expect(restarted.handoff.newEpochId).not.toBe(bFacts.epochId);
    expect(restarted.handoff.ok).toBe(true);
    expect(restarted.handoff.terminalState).toBe("LIVE");
    expect(restarted.handoff.grantsAuthority).toBe(false);
    expect(restarted.handoff.resumeSemantics).toBe("no_auto_resume");
    bFacts = restarted;
  }, 60_000);

  it("recovered facts are DATA: A is still a durable peer record, with zero authority", async () => {
    const peers = await ask<{ peers: ReadonlyArray<{ nodeId: string; trustState: string }>; unreadable: readonly string[] }>(
      b,
      "peers",
      "the restarted B's peer view",
    );
    const recovered = peers.peers.find((entry) => entry.nodeId === aFacts.nodeId);
    expect(recovered).toBeDefined();
    expect(recovered?.trustState).toBe("admitted");
    // the durable receipt for the pre-restart message survived the kill
    const receipt = readDurable(b.root, "frc-" + firstWire.messageId);
    expect(receipt).not.toBeNull();
  });

  it("the OLD envelope is refused at the durable receipt in the NEW epoch, with no auto-resume", async () => {
    const fresh = await ask<Facts>(b, "facts", "B facts for the replay probe");
    // A restarted node holds NO session and NO in-memory peer binding — it
    // recovers DATA, not authority. The operator re-declares the
    // counterparty's PUBLIC facts; the durable admission is then read first
    // and reported idempotently (nothing is re-persisted, nothing inherited).
    const rebind = await ask<PeerResult & { idempotent?: boolean }>(
      b,
      "peer " + peerFactsOf(aFacts, "admit"),
      "B re-declares A's public facts after the restart",
    );
    expect(rebind.peer).toBe("admitted");
    expect(rebind.idempotent).toBe(true);
    await ask<PeerResult>(a, "peer " + peerFactsOf(fresh, "admit"), "A re-binds the restarted B");
    const dial = await ask<DialResult>(a, "dial " + String(PORT_RESTART), "A reconnects to the restarted B");
    expect(dial.dial.established).toBe(true);
    expect(dial.dial.state).toBe("established");
    a.send(
      "send " +
        b64({
          messageId: firstWire.messageId,
          senderEpochId: firstWire.senderEpochId,
          issuedAtEpochMs: firstWire.issuedAtEpochMs,
          payload: firstWire.payload,
          requiresDisclosure: true,
          disclosure: firstWire.disclosure,
        } satisfies SendBody),
    );
    const line = await b.waitFor((candidate) => isIngress(candidate) && candidate.value?.["ok"] === false, "the post-restart replay refusal");
    expect(line.value?.["stage"]).toBe("replay_receipt");
    expect(line.value?.["code"]).toBe("replay_refused");
    expect(line.value?.["upstreamCode"]).toBe("replay_detected");
  }, 60_000);

  it("a NEW proposal after the restart again requires FRESH local authority", async () => {
    const prepared = await ask<PreparedWire>(
      a,
      "prepare " + b64({ messageId: makeFederationMessageId(NOW + 800, "26hrestartprop9"), note: "26H post-restart" }),
      "A prepares the post-restart proposal",
    );
    a.send(
      "send " +
        b64({
          messageId: prepared.messageId,
          senderEpochId: prepared.senderEpochId,
          issuedAtEpochMs: prepared.issuedAtEpochMs,
          payload: prepared.payload,
          requiresDisclosure: true,
          disclosure: prepared.disclosure,
        } satisfies SendBody),
    );
    await b.waitFor(isIngress, "the post-restart ingress");
    const line = await b.waitFor(isLocal, "the post-restart local continuation");
    const after = (line.value as unknown as LocalResult);
    expect(after).toMatchObject({ local: "completed" });
    // a genuinely FRESH local authorization decision was taken AGAIN after the
    // crash: a new allocation, a new Policy for the assigned actor, and NEW
    // durable evidence. Nothing was resumed, inherited, or replayed — and the
    // pre-restart facts are provably stale now that time has passed.
    expect(after.allocationId).toMatch(/^asg-/);
    expect(after.sealedRecordHash).not.toBe(firstLocal.sealedRecordHash);
    expect(after.anchorId).not.toBe(firstLocal.anchorId);
    expect(firstLocal.controls.stale_allocation).toBe("stale_local_allocation");
    expect(after.policyOutcome).toBe("allow");
    expect(after.policyActorId).toBe(after.assignedAgentId);
    expect(after.gate).toBe("opened");
    expect(after.spawned).toBe(false);
    expect(after.controls.capability_union).toBe("REFUSED_NO_UNION");
    expect(after.controls.actor_mismatch).toBe("actor_mismatch");
  }, 60_000);
});
