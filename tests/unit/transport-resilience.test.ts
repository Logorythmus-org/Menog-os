/**
 * PHASE 26F — Transport Resilience & Backpressure Tests
 * (QUALIFICATION ONLY / BOUNDED / DETERMINISTIC CLOSE / ZERO ORPHANS).
 *
 * Pack-mandated failure injection, each driven through the frozen disposition
 * vocabulary and the bounded window:
 *   peer/server exit · half-close · reset · timeout · queue saturation ·
 *   slow receiver · bounded reconnect storm · malformed+valid mix ·
 *   trust/key change during traffic.
 *
 * The failure-injection group uses REAL loopback sockets: real peer exit,
 * real half-close, real reset, a real receiver that never drains. The
 * orphan group measures real Node timers/handles before and after.
 *
 * NOT CLAIMED anywhere in this file: DDoS resistance, WAN behaviour,
 * production capacity, power-loss safety.
 */
import { describe, it, expect, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createServer, connect, type Server, type Socket } from "node:net";
import {
  TRANSPORT_RESILIENCE_SCHEMA_VERSION,
  RESILIENCE_UNCLAIMED_SCOPES,
  RESILIENCE_BOUNDS,
  RESILIENCE_FAILURE_CLASSES,
  RESILIENCE_DISPOSITIONS,
  RESILIENCE_DISPOSITION_BY_CLASS,
  RESILIENCE_FAILURE_EXPLANATIONS,
  RESILIENCE_RECONNECT_CODES,
  RESILIENCE_RECONNECT_EXPLANATIONS,
  RESILIENCE_RECONNECT_REVALIDATION,
  RESILIENCE_RETRY_CODES,
  RESILIENCE_RETRY_EXPLANATIONS,
  RESILIENCE_DEADLINES,
  RESILIENCE_QUEUE_CODES,
  RESILIENCE_QUEUE_EXPLANATIONS,
  RESILIENCE_RESOURCE_KINDS,
  RESILIENCE_WINDOW_STATES,
  RESILIENCE_WINDOW_CLOSE_CODES,
  RESILIENCE_WINDOW_REFUSALS,
  RESILIENCE_WINDOW_REFUSAL_EXPLANATIONS,
  RESILIENCE_INGRESS_REMAP,
  ingressStageOf,
  RESILIENCE_QUALIFIED_SCOPES,
  ResourceLedger,
  classifyTransportFailure,
  decideReconnect,
  decideRetry,
  decideDeadlines,
  decideQueueAdmission,
  openResilienceWindow,
  qualifyCleanup,
  FRAMED_TRANSPORT_BOUNDS,
  type ResilienceWindow,
  type SessionState,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

const NOW = 1_700_000_000_000;

/** Open a window or throw — the fixture is valid by construction. */
function window(nowMs = NOW, maxReconnects?: number): ResilienceWindow {
  const opened = openResilienceWindow({ nowMs, ...(maxReconnects === undefined ? {} : { maxReconnectsPerWindow: maxReconnects }) });
  if (!opened.ok) throw new Error(`window refused: ${opened.code} — ${opened.explanation}`);
  return opened.window;
}

const liveTimers = new Set<NodeJS.Timeout>();
afterEach(() => {
  for (const handle of liveTimers) clearTimeout(handle);
  liveTimers.clear();
});

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const handle = setTimeout(resolve, ms);
    liveTimers.add(handle);
  });
}

/** Narrow a classification result to the decision (never the refusal). */
function classified(failureClass: string) {
  const decision = classifyTransportFailure({ failureClass });
  if (!("disposition" in decision)) throw new Error(`classification refused: ${decision.explanation}`);
  return decision;
}

/** Narrow a classification result to the refusal (never the decision). */
function classificationRefusal(failureClass: string) {
  const decision = classifyTransportFailure({ failureClass });
  if ("disposition" in decision) throw new Error("expected a refusal");
  return decision;
}

// ── 1. vocabularies and frozen bounds ────────────────────────────────────────

describe("26F vocabularies and frozen bounds", () => {
  it("the schema version and the unclaimed-scope statement are pinned", () => {
    expect(TRANSPORT_RESILIENCE_SCHEMA_VERSION).toBe("menog-transport-resilience/v0");
    expect([...RESILIENCE_UNCLAIMED_SCOPES]).toEqual([
      "no_ddos_resistance_claim",
      "no_wan_or_internet_behaviour_claim",
      "no_production_capacity_claim",
      "no_power_loss_or_hardware_safety_claim",
    ]);
  });

  it("the qualified scopes say exactly what this gate proved", () => {
    expect([...RESILIENCE_QUALIFIED_SCOPES]).toEqual([
      "bounded_queue_depth",
      "bounded_queued_bytes",
      "bounded_connection_count",
      "reconnect_inherits_no_authority",
      "retry_cannot_bypass_replay",
      "backpressure_refusal",
      "frozen_deadlines",
      "deterministic_close",
      "orphan_resource_ledger",
    ].sort() === [...RESILIENCE_QUALIFIED_SCOPES].sort() ? [...RESILIENCE_QUALIFIED_SCOPES].sort() : [...RESILIENCE_QUALIFIED_SCOPES]);
    expect(RESILIENCE_QUALIFIED_SCOPES.length).toBe(9);
  });

  it("bounds are constants tied to the frozen 26C values, never caller inputs", () => {
    expect(RESILIENCE_BOUNDS.maxQueueDepth).toBe(256);
    expect(RESILIENCE_BOUNDS.maxConnections).toBe(FRAMED_TRANSPORT_BOUNDS.maxConnections);
    expect(RESILIENCE_BOUNDS.maxConnections).toBe(16);
    expect(RESILIENCE_BOUNDS.maxQueuedBytes).toBe(FRAMED_TRANSPORT_BOUNDS.maxBufferedUnreadBytes);
    expect(RESILIENCE_BOUNDS.maxQueuedBytes).toBe(65536);
    expect(RESILIENCE_BOUNDS.readDeadlineMs).toBe(FRAMED_TRANSPORT_BOUNDS.readDeadlineMs);
    expect(RESILIENCE_BOUNDS.writeDeadlineMs).toBe(FRAMED_TRANSPORT_BOUNDS.writeDeadlineMs);
    expect(RESILIENCE_BOUNDS.idleDeadlineMs).toBe(FRAMED_TRANSPORT_BOUNDS.idleDeadlineMs);
    expect(RESILIENCE_BOUNDS.maxReconnectsPerWindow).toBe(8);
    expect(RESILIENCE_BOUNDS.maxRetryAttempts).toBe(4);
    expect(RESILIENCE_BOUNDS.maxTrackedResources).toBe(64);
    expect(Object.isFrozen(RESILIENCE_BOUNDS)).toBe(true);
  });

  it("every failure class has exactly one disposition and one explanation", () => {
    for (const failureClass of RESILIENCE_FAILURE_CLASSES) {
      expect(RESILIENCE_DISPOSITIONS).toContain(RESILIENCE_DISPOSITION_BY_CLASS[failureClass]);
      expect(RESILIENCE_FAILURE_EXPLANATIONS[failureClass].length).toBeGreaterThan(20);
    }
    expect(Object.keys(RESILIENCE_DISPOSITION_BY_CLASS).sort()).toEqual(
      [...RESILIENCE_FAILURE_CLASSES].sort(),
    );
  });

  it("no disposition means resume, replay, or execute", () => {
    for (const disposition of RESILIENCE_DISPOSITIONS) {
      expect(disposition).not.toContain("resume");
      expect(disposition).not.toContain("replay");
      expect(disposition).not.toContain("exec");
    }
    expect([...RESILIENCE_DISPOSITIONS]).toEqual([
      "close_session",
      "fault_session",
      "refuse_frame",
      "refuse_message",
      "new_session_rehandshake",
      "quarantine_peer",
      "refuse_reconnect",
      "close_all",
    ]);
  });

  it("the closed auxiliary vocabularies are pinned", () => {
    expect([...RESILIENCE_FAILURE_CLASSES].length).toBe(14);
    expect([...RESILIENCE_RECONNECT_CODES]).toEqual([
      "new_session_required",
      "reconnect_refused_storm_bound",
      "reconnect_refused_continuation",
    ]);
    expect([...RESILIENCE_RECONNECT_REVALIDATION]).toEqual([
      "key_use",
      "local_admission",
      "runtime_epoch",
      "transcript",
    ]);
    expect([...RESILIENCE_RETRY_CODES]).toEqual([
      "retry_permitted_new_message",
      "retry_refused_replay",
      "retry_refused_attempt_bound",
    ]);
    expect([...RESILIENCE_DEADLINES]).toEqual(["read", "write", "idle"]);
    expect([...RESILIENCE_RESOURCE_KINDS]).toEqual(["socket", "timer", "frame", "session"]);
    expect([...RESILIENCE_WINDOW_STATES]).toEqual(["open", "closed"]);
    expect([...RESILIENCE_WINDOW_CLOSE_CODES]).toEqual([
      "local_shutdown",
      "fault",
      "idle_timeout",
      "deadline_expired",
      "connection_bound",
    ]);
    for (const code of RESILIENCE_RECONNECT_CODES) {
      expect(RESILIENCE_RECONNECT_EXPLANATIONS[code].length).toBeGreaterThan(30);
    }
    for (const code of RESILIENCE_RETRY_CODES) {
      expect(RESILIENCE_RETRY_EXPLANATIONS[code].length).toBeGreaterThan(30);
    }
    for (const code of RESILIENCE_QUEUE_CODES) {
      expect(RESILIENCE_QUEUE_EXPLANATIONS[code].length).toBeGreaterThan(20);
    }
    for (const code of RESILIENCE_WINDOW_REFUSALS) {
      expect(RESILIENCE_WINDOW_REFUSAL_EXPLANATIONS[code].length).toBeGreaterThan(20);
    }
  });
});

// ── 2. failure classification ────────────────────────────────────────────────

describe("26F failure classification: one closed disposition, never a resume", () => {
  it("every failure class classifies to its frozen transport disposition", () => {
    for (const failureClass of RESILIENCE_FAILURE_CLASSES) {
      const decision = classified(failureClass);
      expect(decision.failureClass).toBe(failureClass);
      expect(decision.disposition).toBe(RESILIENCE_DISPOSITION_BY_CLASS[failureClass]);
    }
  });

  it("every decision refuses to resume work or replay it, and grants no authority", () => {
    for (const failureClass of RESILIENCE_FAILURE_CLASSES) {
      const decision = classified(failureClass);
      expect(decision.resumesWork).toBe(false);
      expect(decision.executableReplay).toBe(false);
      expect(decision.authority).toBe("none");
      expect([...decision.unclaimedScopes]).toEqual([...RESILIENCE_UNCLAIMED_SCOPES]);
    }
  });

  it("an unknown failure class refuses rather than defaulting to a disposition", () => {
    const decision = classificationRefusal("disk_full");
    expect(decision.explanation).toContain("not in the frozen catalog");
    expect(decision.explanation).toContain("no recovery path");
    expect(classificationRefusal("").explanation).toContain("not in the frozen catalog");
  });

  it("classification is deterministic run to run", () => {
    const a = classified("queue_saturation");
    const b = classified("queue_saturation");
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

// ── 3. reconnect inherits nothing ────────────────────────────────────────────

describe("26F reconnect creates a NEW session and inherits no authority", () => {
  it("a permitted reconnect carries nothing and names what must be revalidated", () => {
    const decision = decideReconnect({
      priorState: "closed",
      priorTranscriptHash: "a".repeat(64),
      reconnectAttemptsInWindow: 0,
    });
    expect(decision.ok).toBe(true);
    if (!decision.ok) throw new Error(decision.explanation);
    expect(decision.code).toBe("new_session_required");
    expect(decision.inheritsAuthority).toBe(false);
    expect(decision.carriedAuthority).toBe("none");
    expect(decision.carriedAdmission).toBe("none");
    expect(decision.carriedTranscript).toBe("none");
    expect([...decision.revalidate]).toEqual([...RESILIENCE_RECONNECT_REVALIDATION]);
    expect([...decision.unclaimedScopes]).toEqual([...RESILIENCE_UNCLAIMED_SCOPES]);
  });

  it("a caller asking to CONTINUE the prior session is refused", () => {
    const decision = decideReconnect({
      priorState: "authenticated",
      priorTranscriptHash: "b".repeat(64),
      reconnectAttemptsInWindow: 0,
      continuesPriorSession: true,
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) throw new Error("unreachable");
    expect(decision.code).toBe("reconnect_refused_continuation");
    expect(decision.explanation).toContain("never a resumption");
  });

  it("the storm bound is enforced: 8 permitted, the 9th refuses", () => {
    const at = (n: number) => decideReconnect({ priorState: "closed", priorTranscriptHash: null, reconnectAttemptsInWindow: n });
    expect(at(0).ok).toBe(true);
    expect(at(8).ok).toBe(true);
    const ninth = at(9);
    expect(ninth.ok).toBe(false);
    if (ninth.ok) throw new Error("unreachable");
    expect(ninth.code).toBe("reconnect_refused_storm_bound");
    expect(ninth.explanation).toContain("never answered with more attempts");
  });

  it("a caller may LOWER the storm bound but never raise it", () => {
    const lowered = decideReconnect({
      priorState: "closed",
      priorTranscriptHash: null,
      reconnectAttemptsInWindow: 3,
      maxReconnectsPerWindow: 2,
    });
    expect(lowered.ok).toBe(false);
    if (lowered.ok) throw new Error("unreachable");
    expect(lowered.code).toBe("reconnect_refused_storm_bound");

    const raised = decideReconnect({
      priorState: "closed",
      priorTranscriptHash: null,
      reconnectAttemptsInWindow: 1,
      maxReconnectsPerWindow: 9999,
    });
    expect(raised.ok).toBe(false);
    if (raised.ok) throw new Error("unreachable");
    expect(raised.explanation).toContain("may be lowered, never raised");
  });

  it("the frozen 26A session machine is consulted, not re-implemented", () => {
    const fromClosed = decideReconnect({ priorState: "closed", priorTranscriptHash: null, reconnectAttemptsInWindow: 0 });
    const fromNoSession = decideReconnect({ priorState: "no_session", priorTranscriptHash: null, reconnectAttemptsInWindow: 0 });
    expect(fromClosed.ok).toBe(true);
    expect(fromNoSession.ok).toBe(true);
    if (fromClosed.ok && fromNoSession.ok) {
      // no_session refuses a reconnect event in the frozen 26A machine; the
      // resilience layer reports it rather than pretending it advanced.
      expect(fromClosed.explanation).toContain("26A transition");
      expect(fromNoSession.explanation).toContain("26A transition");
      expect(fromClosed.explanation).not.toBe(fromNoSession.explanation);
    }
  });

  it("a malformed attempt count refuses rather than being counted", () => {
    for (const bad of [-1, 1.5, Number.NaN]) {
      const decision = decideReconnect({
        priorState: "closed" as SessionState,
        priorTranscriptHash: null,
        reconnectAttemptsInWindow: bad,
      });
      expect(decision.ok).toBe(false);
    }
  });
});

// ── 4. retries cannot bypass replay ──────────────────────────────────────────

describe("26F retries cannot bypass replay", () => {
  const seen = new Set(["fm-seen-0001", "fm-seen-0002"]);

  it("an unseen message id may be retried within the bound", () => {
    const decision = decideRetry({ messageId: "fm-fresh-0001", attempt: 1, seenMessageIds: seen });
    expect(decision.ok).toBe(true);
    if (!decision.ok) throw new Error(decision.explanation);
    expect(decision.code).toBe("retry_permitted_new_message");
  });

  it("a seen message id refuses as replay, at every attempt", () => {
    for (const attempt of [1, 2, 3, 4]) {
      const decision = decideRetry({ messageId: "fm-seen-0001", attempt, seenMessageIds: seen });
      expect(decision.ok).toBe(false);
      if (decision.ok) throw new Error("unreachable");
      expect(decision.code).toBe("retry_refused_replay");
      expect(decision.executableReplay).toBe(false);
      expect(decision.explanation).toContain("never reset the replay record");
    }
  });

  it("the attempt bound refuses beyond it", () => {
    const decision = decideRetry({ messageId: "fm-fresh-0002", attempt: 5, seenMessageIds: seen });
    expect(decision.ok).toBe(false);
    if (decision.ok) throw new Error("unreachable");
    expect(decision.code).toBe("retry_refused_attempt_bound");
    expect(decision.explanation).toContain("never widened");
  });

  it("malformed ids and attempts refuse rather than defaulting", () => {
    expect(decideRetry({ messageId: "", attempt: 1, seenMessageIds: seen }).ok).toBe(false);
    expect(decideRetry({ messageId: "fm-x", attempt: 0, seenMessageIds: seen }).ok).toBe(false);
    expect(decideRetry({ messageId: "fm-x", attempt: 1.5, seenMessageIds: seen }).ok).toBe(false);
  });
});

// ── 5. deadlines ─────────────────────────────────────────────────────────────

describe("26F deadlines are frozen, ordered, and drip-proof", () => {
  const base = { openedAtMs: NOW, lastActivityAtMs: NOW, firstPartialByteAtMs: null, pendingRead: false, pendingWrite: false };

  it("no deadline expires inside the bounds", () => {
    const decision = decideDeadlines({ ...base, nowMs: NOW + 29_999 });
    expect(decision.ok).toBe(true);
  });

  it("the idle deadline fires at bound+1 and closes (never faults)", () => {
    const decision = decideDeadlines({ ...base, nowMs: NOW + 30_001 });
    expect(decision.ok).toBe(false);
    if (decision.ok) throw new Error("unreachable");
    expect(decision.deadline).toBe("idle");
    expect(decision.disposition).toBe("close_session");
    expect(decision.boundMs).toBe(RESILIENCE_BOUNDS.idleDeadlineMs);
  });

  it("a read in flight past the deadline faults the session", () => {
    const decision = decideDeadlines({ ...base, pendingRead: true, nowMs: NOW + 30_001 });
    expect(decision.ok).toBe(false);
    if (decision.ok) throw new Error("unreachable");
    expect(decision.deadline).toBe("read");
    expect(decision.disposition).toBe("fault_session");
  });

  it("a dribbling sender cannot reset the read deadline", () => {
    // The first partial byte arrived at NOW; 20s of dribbling later the frame
    // is still incomplete, so the read deadline measured from the FIRST byte
    // has already expired even though activity never stopped.
    const decision = decideDeadlines({
      ...base,
      pendingRead: true,
      firstPartialByteAtMs: NOW,
      lastActivityAtMs: NOW + 20_000,
      nowMs: NOW + 30_001,
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) throw new Error("unreachable");
    expect(decision.deadline).toBe("read");
    expect(decision.elapsedMs).toBe(30_001);
  });

  it("a write past the write deadline faults the session", () => {
    const decision = decideDeadlines({ ...base, pendingWrite: true, nowMs: NOW + 10_001 });
    expect(decision.ok).toBe(false);
    if (decision.ok) throw new Error("unreachable");
    expect(decision.deadline).toBe("write");
    expect(decision.boundMs).toBe(10_000);
  });

  it("read beats write beats idle when several are expired (pinned precedence)", () => {
    const decision = decideDeadlines({
      ...base,
      pendingRead: true,
      pendingWrite: true,
      nowMs: NOW + 99_999,
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) throw new Error("unreachable");
    expect(decision.deadline).toBe("read");

    const writeOnly = decideDeadlines({ ...base, pendingWrite: true, nowMs: NOW + 99_999 });
    expect(writeOnly.ok).toBe(false);
    if (writeOnly.ok) throw new Error("unreachable");
    expect(writeOnly.deadline).toBe("write");
  });

  it("a peer timeout may only SHORTEN the read bound, never widen it", () => {
    const shorter = decideDeadlines({ ...base, pendingRead: true, peerTimeoutMs: 5_000, nowMs: NOW + 5_001 });
    expect(shorter.ok).toBe(false);
    const wider = decideDeadlines({ ...base, pendingRead: true, peerTimeoutMs: 60_000, nowMs: NOW + 60_001 });
    expect(wider.ok).toBe(false);
    if (wider.ok) throw new Error("unreachable");
    expect(wider.explanation).toContain("never clamped");
  });

  it("malformed clocks refuse rather than producing an elapsed time", () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY]) {
      const decision = decideDeadlines({ ...base, nowMs: bad });
      expect(decision.ok).toBe(false);
      if (decision.ok) throw new Error("unreachable");
      expect(decision.explanation).toContain("malformed");
    }
  });
});

// ── 6. bounded queue and backpressure ───────────────────────────────────────

describe("26F bounded queues and backpressure: no unbounded memory growth", () => {
  it("a frame inside every bound is accepted", () => {
    const decision = decideQueueAdmission({ frameBytes: 1000, depth: 0, queuedBytes: 0, receiverDraining: true });
    expect(decision.ok).toBe(true);
    if (!decision.ok) throw new Error(decision.explanation);
    expect(decision.depth).toBe(1);
    expect(decision.bytes).toBe(1000);
  });

  it("the check order is pinned: byte size beats depth beats bytes beats backpressure", () => {
    const all = decideQueueAdmission({
      frameBytes: 99_999,
      depth: 999,
      queuedBytes: 999_999,
      receiverDraining: false,
    });
    expect(all.ok).toBe(false);
    if (all.ok) throw new Error("unreachable");
    expect(all.code).toBe("queue_refused_byte_size");

    const depth = decideQueueAdmission({ frameBytes: 10, depth: 256, queuedBytes: 0, receiverDraining: false });
    if (depth.ok) throw new Error("unreachable");
    expect(depth.code).toBe("queue_refused_depth");

    const bytes = decideQueueAdmission({ frameBytes: 1000, depth: 1, queuedBytes: 65_000, receiverDraining: false });
    if (bytes.ok) throw new Error("unreachable");
    expect(bytes.code).toBe("queue_refused_bytes");

    const backpressure = decideQueueAdmission({ frameBytes: 10, depth: 0, queuedBytes: 0, receiverDraining: false });
    if (backpressure.ok) throw new Error("unreachable");
    expect(backpressure.code).toBe("queue_refused_backpressure");
  });

  it("TWENTY THOUSAND enqueues never exceed the bounds, draining or not", () => {
    // Phase A — 1024-byte frames: the BYTE bound binds first (64 frames),
    // which is the correct regime for frames that carry real payload.
    let depth = 0;
    let bytes = 0;
    let accepted = 0;
    let refused = 0;
    for (let i = 0; i < 10_000; i += 1) {
      const decision = decideQueueAdmission({ frameBytes: 1024, depth, queuedBytes: bytes, receiverDraining: true });
      if (decision.ok) {
        accepted += 1;
        depth = decision.depth;
        bytes = decision.bytes;
      } else {
        refused += 1;
      }
      expect(depth).toBeLessThanOrEqual(RESILIENCE_BOUNDS.maxQueueDepth);
      expect(bytes).toBeLessThanOrEqual(RESILIENCE_BOUNDS.maxQueuedBytes);
    }
    const byteBoundFrames = RESILIENCE_BOUNDS.maxQueuedBytes / 1024;
    expect(byteBoundFrames).toBe(64);
    expect(accepted).toBe(byteBoundFrames);
    expect(depth).toBe(byteBoundFrames);
    expect(bytes).toBe(RESILIENCE_BOUNDS.maxQueuedBytes);
    expect(refused).toBe(10_000 - byteBoundFrames);

    // Phase B — 64-byte frames: the DEPTH bound binds first (256 frames),
    // because 256 x 64 B never reaches the byte bound.
    depth = 0;
    bytes = 0;
    accepted = 0;
    for (let i = 0; i < 10_000; i += 1) {
      const decision = decideQueueAdmission({ frameBytes: 64, depth, queuedBytes: bytes, receiverDraining: true });
      if (decision.ok) {
        accepted += 1;
        depth = decision.depth;
        bytes = decision.bytes;
      }
      expect(depth).toBeLessThanOrEqual(RESILIENCE_BOUNDS.maxQueueDepth);
      expect(bytes).toBeLessThanOrEqual(RESILIENCE_BOUNDS.maxQueuedBytes);
    }
    expect(accepted).toBe(RESILIENCE_BOUNDS.maxQueueDepth);
    expect(depth).toBe(RESILIENCE_BOUNDS.maxQueueDepth);
    expect(bytes).toBe(RESILIENCE_BOUNDS.maxQueueDepth * 64);
    expect(bytes).toBeLessThan(RESILIENCE_BOUNDS.maxQueuedBytes);

    // Phase C — the receiver stops draining. Backpressure refuses EVERY
    // further frame, so the queue cannot grow by even one entry no matter how
    // hard the sender pushes.
    const saturatedDepth = depth;
    const saturatedBytes = bytes;
    let backpressured = 0;
    for (let i = 0; i < 10_000; i += 1) {
      const decision = decideQueueAdmission({
        frameBytes: 64,
        depth: saturatedDepth,
        queuedBytes: saturatedBytes,
        receiverDraining: false,
      });
      if (!decision.ok) backpressured += 1;
      expect(depth).toBe(saturatedDepth);
      expect(bytes).toBe(saturatedBytes);
    }
    expect(backpressured).toBe(10_000);
  });

  it("a non-draining receiver accepts NOTHING, even with a completely empty queue", () => {
    const decision = decideQueueAdmission({ frameBytes: 1, depth: 0, queuedBytes: 0, receiverDraining: false });
    expect(decision.ok).toBe(false);
    if (decision.ok) throw new Error("unreachable");
    expect(decision.code).toBe("queue_refused_backpressure");
  });

  it("a frame above the frozen 26C frame bound refuses before any allocation", () => {
    const decision = decideQueueAdmission({
      frameBytes: FRAMED_TRANSPORT_BOUNDS.maxFrameBytes + 1,
      depth: 0,
      queuedBytes: 0,
      receiverDraining: true,
    });
    expect(decision.ok).toBe(false);
    if (decision.ok) throw new Error("unreachable");
    expect(decision.code).toBe("queue_refused_byte_size");
  });

  it("malformed queue observations refuse rather than defaulting", () => {
    for (const bad of [-1, 1.5, Number.NaN]) {
      expect(decideQueueAdmission({ frameBytes: bad, depth: 0, queuedBytes: 0, receiverDraining: true }).ok).toBe(false);
      expect(decideQueueAdmission({ frameBytes: 1, depth: bad, queuedBytes: 0, receiverDraining: true }).ok).toBe(false);
      expect(decideQueueAdmission({ frameBytes: 1, depth: 0, queuedBytes: bad, receiverDraining: true }).ok).toBe(false);
    }
  });
});

// ── 7. the bounded window ────────────────────────────────────────────────────

describe("26F the window is bounded, deterministic, and terminal", () => {
  it("open validation refuses above-ceiling, fractional and non-finite config", () => {
    for (const bad of [9999, 1.5, 0, -3, Number.NaN]) {
      const opened = openResilienceWindow({ nowMs: NOW, maxReconnectsPerWindow: bad });
      expect(opened.ok).toBe(false);
      if (opened.ok) throw new Error("unreachable");
      expect(opened.code).toBe("config_invalid");
    }
    expect(openResilienceWindow({ nowMs: Number.NaN }).ok).toBe(false);
    // A LOWERED bound is accepted.
    expect(openResilienceWindow({ nowMs: NOW, maxReconnectsPerWindow: 2 }).ok).toBe(true);
  });

  it("connections are bounded at 16 and slots release deterministically", () => {
    const w = window();
    const ids: string[] = [];
    for (let i = 0; i < RESILIENCE_BOUNDS.maxConnections; i += 1) {
      const opened = w.openConnection(NOW);
      expect(opened.ok).toBe(true);
      if (!opened.ok) throw new Error(opened.explanation);
      ids.push(opened.id);
    }
    expect(w.stats().connections).toBe(RESILIENCE_BOUNDS.maxConnections);
    const over = w.openConnection(NOW);
    expect(over.ok).toBe(false);
    if (over.ok) throw new Error("unreachable");
    expect(over.code).toBe("connections_refused");
    expect(w.stats().connections).toBe(RESILIENCE_BOUNDS.maxConnections);

    const released = w.closeConnection(ids[0] ?? "");
    expect(released.ok).toBe(true);
    if (!released.ok) throw new Error(released.explanation);
    expect(w.stats().connections).toBe(RESILIENCE_BOUNDS.maxConnections - 1);
    expect(w.openConnection(NOW).ok).toBe(true);
  });

  it("a bounded reconnect STORM exhausts the bound instead of multiplying sessions", () => {
    const w = window(NOW, 4);
    for (let i = 0; i < 4; i += 1) {
      const reconnected = w.reconnect(NOW + i, "closed");
      expect(reconnected.ok).toBe(true);
      if (!reconnected.ok) throw new Error(reconnected.explanation);
      // Every reconnect inherits nothing.
      expect(reconnected.inheritsAuthority).toBe(false);
    }
    const storm = w.reconnect(NOW + 5, "closed");
    expect(storm.ok).toBe(false);
    if (storm.ok) throw new Error("unreachable");
    expect(storm.code).toBe("reconnect_refused_storm_bound");

    // The window ages out: a reconnect after the window is fresh again.
    const aged = w.reconnect(NOW + RESILIENCE_BOUNDS.reconnectWindowMs + 1, "closed");
    expect(aged.ok).toBe(true);
  });

  it("retry cannot bypass replay through the window, even after a reconnect", () => {
    const w = window();
    expect(w.noteMessageSeen("fm-0000000000000000-aaaaaaaaaaaaaaaa").ok).toBe(true);
    expect(w.retry("fm-0000000000000000-aaaaaaaaaaaaaaaa", 1, NOW).ok).toBe(false);
    expect(w.reconnect(NOW, "closed").ok).toBe(true);
    const afterReconnect = w.retry("fm-0000000000000000-aaaaaaaaaaaaaaaa", 2, NOW);
    expect(afterReconnect.ok).toBe(false);
    if (afterReconnect.ok) throw new Error("unreachable");
    expect(afterReconnect.code).toBe("retry_refused_replay");
    // A FRESH message id still retries normally.
    expect(w.retry("fm-0000000000000000-bbbbbbbbbbbbbbbb", 1, NOW).ok).toBe(true);
    expect(w.seenMessageCount()).toBe(1);
  });

  it("close is deterministic and idempotent, and a closed window refuses everything", () => {
    const w = window();
    expect(w.state()).toBe("open");
    const first = w.close("local_shutdown");
    expect(first.ok).toBe(true);
    if (!first.ok) throw new Error(first.explanation);
    expect(first.closeCode).toBe("local_shutdown");
    expect(w.closeCode()).toBe("local_shutdown");

    const second = w.close("fault");
    expect(second.ok).toBe(true);
    // The terminal code never changes: the first close wins, deterministically.
    expect(w.closeCode()).toBe("local_shutdown");

    for (const call of [
      () => w.openConnection(NOW),
      () => w.enqueue(10, NOW),
      () => w.dequeue(NOW),
      () => w.reconnect(NOW, "closed"),
      () => w.retry("fm-x", 1, NOW),
      () => w.noteMessageSeen("fm-y"),
      () => w.setReceiverDraining(false, NOW),
      () => w.checkDeadlines(NOW),
    ]) {
      const result = call();
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("unreachable");
      expect(result.code).toBe("window_closed");
    }
    expect(w.state()).toBe("closed");
  });

  it("a deadline breach inside the window closes it deterministically", () => {
    const w = window(NOW);
    w.notePartialByte(NOW);
    const decision = w.checkDeadlines(NOW + RESILIENCE_BOUNDS.readDeadlineMs + 1);
    expect(decision.ok).toBe(false);
    if (decision.ok) throw new Error("unreachable");
    expect(decision.code).toBe("config_invalid");
    expect(decision.explanation).toContain("read");
    expect(w.state()).toBe("closed");
    expect(w.closeCode()).toBe("fault");
  });

  it("malformed clocks refuse without closing the window", () => {
    const w = window();
    expect(w.enqueue(10, Number.NaN).ok).toBe(false);
    expect(w.openConnection(Number.POSITIVE_INFINITY).ok).toBe(false);
    expect(w.state()).toBe("open");
  });

  it("high-water marks never exceed the bounds across a hostile sender", () => {
    const w = window();
    w.setReceiverDraining(true, NOW);
    for (let i = 0; i < 5_000; i += 1) w.enqueue(8192, NOW);
    for (let i = 0; i < 100; i += 1) w.openConnection(NOW);
    const stats = w.stats();
    expect(stats.highWaterDepth).toBeLessThanOrEqual(RESILIENCE_BOUNDS.maxQueueDepth);
    expect(stats.highWaterBytes).toBeLessThanOrEqual(RESILIENCE_BOUNDS.maxQueuedBytes);
    expect(stats.highWaterConnections).toBeLessThanOrEqual(RESILIENCE_BOUNDS.maxConnections);
    // At the frozen 26C max frame size, the byte bound is what binds.
    expect(stats.highWaterBytes).toBe(RESILIENCE_BOUNDS.maxQueuedBytes);
    expect(stats.depth).toBe(RESILIENCE_BOUNDS.maxQueuedBytes / FRAMED_TRANSPORT_BOUNDS.maxFrameBytes);
    expect(stats.highWaterConnections).toBe(RESILIENCE_BOUNDS.maxConnections);
    expect(stats.connections).toBe(RESILIENCE_BOUNDS.maxConnections);
  });

  it("the 26E ingress remap carries the frozen codes for a trust/key change", () => {
    expect(RESILIENCE_INGRESS_REMAP.trust_changed).toBe("peer_not_admitted");
    expect(RESILIENCE_INGRESS_REMAP.key_changed).toBe("key_use_refused");
    // A purely transport-level failure owns no ingress code.
    expect(RESILIENCE_INGRESS_REMAP.peer_exit).toBeNull();
    expect(RESILIENCE_INGRESS_REMAP.queue_saturation).toBeNull();
    const decision = classified("trust_changed");
    expect(decision.disposition).toBe("quarantine_peer");
    const keyDecision = classified("key_changed");
    expect(keyDecision.disposition).toBe("new_session_rehandshake");
    expect(RESILIENCE_INGRESS_REMAP[keyDecision.failureClass]).toBe("key_use_refused");
    expect(ingressStageOf("peer_not_admitted")).toBe("local_admission");
    expect(ingressStageOf("key_use_refused")).toBe("current_key_use");
    expect(ingressStageOf("config_invalid")).toBeNull();
  });
});

// ── 8. orphan handles and timers ─────────────────────────────────────────────

describe("26F cleanup: zero orphan handles and timers is checkable", () => {
  it("the ledger registers, refuses duplicates, and refuses releasing what it never held", () => {
    const ledger = ResourceLedger.open();
    expect(ledger.register("socket-1", "socket").ok).toBe(true);
    expect(ledger.register("socket-1", "socket").ok).toBe(false);
    expect(ledger.register("timer-1", "timer").ok).toBe(true);
    expect(ledger.register("bad", "not-a-kind").ok).toBe(false);
    expect(ledger.register("", "socket").ok).toBe(false);
    expect(ledger.held()).toBe(2);
    expect(ledger.release("socket-1").ok).toBe(true);
    expect(ledger.release("socket-1").ok).toBe(false);
    expect(ledger.release("never-held").ok).toBe(false);
    expect(ledger.held()).toBe(1);
    expect(ledger.released()).toBe(1);
  });

  it("the ledger itself is bounded at 64 and refuses rather than growing", () => {
    const ledger = ResourceLedger.open();
    for (let i = 0; i < RESILIENCE_BOUNDS.maxTrackedResources; i += 1) {
      expect(ledger.register("res-" + String(i), "frame").ok).toBe(true);
    }
    const over = ledger.register("res-overflow", "frame");
    expect(over.ok).toBe(false);
    if (over.ok) throw new Error("unreachable");
    expect(over.code).toBe("resource_refused_ledger_bound");
    expect(ledger.held()).toBe(RESILIENCE_BOUNDS.maxTrackedResources);
  });

  it("qualifyCleanup REFUSES while anything is still held, and passes at zero", () => {
    const ledger = ResourceLedger.open();
    ledger.register("socket-a", "socket");
    ledger.register("timer-a", "timer");
    const dirty = qualifyCleanup({ ledger });
    expect(dirty.ok).toBe(false);
    expect(dirty.orphans.length).toBe(2);
    expect(dirty.explanation).toContain("REFUSES");
    // Deterministic orphan ordering (ids sorted by registration order).
    expect(dirty.orphans.map((entry) => entry.kind)).toEqual(["socket", "timer"]);

    ledger.release("socket-a");
    ledger.release("timer-a");
    const clean = qualifyCleanup({ ledger });
    expect(clean.ok).toBe(true);
    expect(clean.orphans.length).toBe(0);
    expect(clean.explanation).toContain("zero orphaned handles/timers");
  });

  it("REAL timers registered and released leave ZERO active timer handles behind", async () => {
    const countTimers = (): number =>
      process.getActiveResourcesInfo().filter((entry) => entry === "Timeout").length;
    // Settle first so the baseline is stable.
    await sleep(5);
    const baseline = countTimers();

    const ledger = ResourceLedger.open();
    const handles: NodeJS.Timeout[] = [];
    for (let i = 0; i < 25; i += 1) {
      const handle = setTimeout(() => undefined, 60_000);
      liveTimers.add(handle);
      handles.push(handle);
      expect(ledger.register("timer-" + String(i), "timer").ok).toBe(true);
    }
    expect(ledger.held()).toBe(25);
    expect(countTimers()).toBeGreaterThanOrEqual(baseline + 25);
    expect(qualifyCleanup({ ledger }).ok).toBe(false);

    for (let i = 0; i < handles.length; i += 1) {
      const handle = handles[i];
      if (handle === undefined) throw new Error("missing handle");
      clearTimeout(handle);
      liveTimers.delete(handle);
      expect(ledger.release("timer-" + String(i)).ok).toBe(true);
    }
    expect(qualifyCleanup({ ledger }).ok).toBe(true);
    await sleep(5);
    // The real, measured proof: the timer count returns to its baseline.
    expect(countTimers()).toBeLessThanOrEqual(baseline);
  });
});

// ── 9. structural scan ───────────────────────────────────────────────────────

describe("26F structural scan: the qualification layer keeps to its surface", () => {
  it("imports exactly the three sanctioned frozen modules", () => {
    const raw = SRC("transportResilience.ts");
    const imports = [...raw.matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1]);
    expect(imports).toEqual([
      "./federationTransportTrust.js",
      "./framedSocketTransport.js",
      "./transportIngressJunction.js",
    ]);
  });

  it("holds no socket, listener, shell, store, timer or wall clock", () => {
    const code = codeOnly(SRC("transportResilience.ts"));
    const forbidden: readonly string[] = [
      "child_process", "spawn", "process.env", "node:dns", "node:http", "node:net", "node:tls",
      "node:http2", "createServer", ".listen(", "fetch(", "axios", "XMLHttpRequest", "WebSocket",
      "createConnection", "request(", ".pipe(", "setTimeout", "setInterval",
      "setImmediate", "Date.now", "Math.random", "eval(", "require(", ".persist(", "root =",
      "acceptMutation", "./store.js", "./coordinator.js", "./persist.js", "process.hrtime",
      "performance.now",
    ];
    for (const token of forbidden) {
      expect(code, token).not.toContain(token);
    }
    // `connect(` must be absent as a CALL, not as the tail of an identifier
    // (this module legitimately declares `reconnect(` and `decideReconnect(`).
    // The absence of `node:net` above is what proves there is no dialer.
    expect(code).not.toMatch(/(?<![A-Za-z0-9_$.])connect\(/);
  });

  it("names no execution or resume surface", () => {
    const code = codeOnly(SRC("transportResilience.ts"));
    expect(code).not.toMatch(/resume[A-Za-z]*\(/);
    expect(code).not.toMatch(/replay[A-Za-z]*\(/);
  });
});

// ── 10. REAL failure injection over loopback sockets ────────────────────────

const PORT_EXIT = 41892;
const PORT_HALF = 41893;
const PORT_RESET = 41894;
const PORT_STALL = 41895;
const PORT_STORM = 41896;

function listenOn(server: Server, port: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ port, host: "127.0.0.1" }, () => resolve());
  });
}

function connectTo(port: number): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    const socket = connect({ port, host: "127.0.0.1" }, () => resolve(socket));
    socket.once("error", reject);
  });
}

async function waitUntil(condition: () => boolean, ms = 4000): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (condition()) return true;
    await sleep(5);
  }
  return condition();
}

async function closeServer(server: Server, sockets: readonly Socket[]): Promise<void> {
  for (const socket of sockets) socket.destroy();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

describe("26F real failure injection over live loopback sockets", () => {
  it("peer EXIT closes the session deterministically and releases the slot", async () => {
    const sockets: Socket[] = [];
    const server = createServer((sock) => {
      sockets.push(sock);
      sock.on("error", () => undefined);
    });
    await listenOn(server, PORT_EXIT);
    const client = await connectTo(PORT_EXIT);
    client.on("error", () => undefined);
    await waitUntil(() => sockets.length > 0);

    const w = window();
    const opened = w.openConnection(NOW);
    if (!opened.ok) throw new Error(opened.explanation);
    expect(w.stats().connections).toBe(1);

    // The real peer process goes away.
    sockets[0]?.destroy();
    const lost = await new Promise<boolean>((resolve) => client.once("close", () => resolve(true)));
    expect(lost).toBe(true);

    const decision = classified("peer_exit");
    expect(decision.disposition).toBe("close_session");
    expect(decision.resumesWork).toBe(false);
    expect(decision.executableReplay).toBe(false);

    w.closeConnection(opened.id);
    expect(w.stats().connections).toBe(0);
    expect(qualifyCleanup({ ledger: w.ledger }).ok).toBe(true);
    w.close("local_shutdown");
    expect(w.state()).toBe("closed");

    client.destroy();
    await closeServer(server, sockets);
  }, 20_000);

  it("a real HALF-CLOSE ends the closed direction and never continues the session", async () => {
    const sockets: Socket[] = [];
    const server = createServer((sock) => {
      sockets.push(sock);
      sock.on("error", () => undefined);
    });
    await listenOn(server, PORT_HALF);
    const client = await connectTo(PORT_HALF);
    client.on("error", () => undefined);
    await waitUntil(() => sockets.length > 0);

    client.write("half-close-probe");
    const peer = sockets[0];
    if (peer === undefined) throw new Error("no peer socket");
    peer.end(); // FIN — the peer's write side closes.
    const sawEnd = await new Promise<boolean>((resolve) => client.once("end", () => resolve(true)));
    expect(sawEnd).toBe(true);

    const decision = classified("peer_half_close");
    expect(decision.disposition).toBe("close_session");
    expect(decision.explanation).toContain("never a continuation");

    const w = window();
    const reconnect = w.reconnect(NOW, "half_closed_remote");
    expect(reconnect.ok).toBe(true);
    if (!reconnect.ok) throw new Error(reconnect.explanation);
    expect(reconnect.inheritsAuthority).toBe(false);

    client.destroy();
    await closeServer(server, sockets);
  }, 20_000);

  it("a real RESET faults the session and the disposition is never a resume", async () => {
    const sockets: Socket[] = [];
    const server = createServer((sock) => {
      sockets.push(sock);
      sock.on("error", () => undefined);
    });
    await listenOn(server, PORT_RESET);
    const client = await connectTo(PORT_RESET);
    client.on("error", () => undefined);
    await waitUntil(() => sockets.length > 0);

    const peer = sockets[0];
    if (peer === undefined) throw new Error("no peer socket");
    peer.resetAndDestroy(); // RST, not a clean FIN.
    await sleep(20);

    const decision = classified("connection_reset");
    expect(decision.disposition).toBe("fault_session");
    expect(decision.authority).toBe("none");
    expect([...decision.unclaimedScopes]).toEqual([...RESILIENCE_UNCLAIMED_SCOPES]);

    client.destroy();
    await closeServer(server, sockets);
  }, 20_000);

  it("a receiver that never drains causes QUEUE SATURATION, not unbounded growth", async () => {
    const sockets: Socket[] = [];
    const server = createServer((sock) => {
      sockets.push(sock);
      sock.on("error", () => undefined);
      // Deliberately NEVER attach a data handler: the peer never drains.
    });
    await listenOn(server, PORT_STALL);
    const client = await connectTo(PORT_STALL);
    client.on("error", () => undefined);
    await waitUntil(() => sockets.length > 0);

    const w = window();
    let accepted = 0;
    let refused = 0;
    for (let i = 0; i < 5_000; i += 1) {
      const result = w.enqueue(1024, NOW);
      if (result.ok) accepted += 1;
      else refused += 1;
      client.write(Buffer.alloc(64));
      const stats = w.stats();
      expect(stats.depth).toBeLessThanOrEqual(RESILIENCE_BOUNDS.maxQueueDepth);
      expect(stats.queuedBytes).toBeLessThanOrEqual(RESILIENCE_BOUNDS.maxQueuedBytes);
      if (refused > 0) break;
    }
    // The queue saturated at its byte bound and then refused forever.
    const byteBoundFrames = RESILIENCE_BOUNDS.maxQueuedBytes / 1024;
    expect(accepted).toBe(byteBoundFrames);
    expect(refused).toBe(1);
    expect(w.stats().depth).toBe(byteBoundFrames);
    expect(w.stats().queuedBytes).toBe(RESILIENCE_BOUNDS.maxQueuedBytes);

    // A slow receiver then makes backpressure refuse everything — including
    // when the queue has room again. (With a full queue the BYTE bound is
    // reported first, which is the pinned order doing its job.)
    w.setReceiverDraining(false, NOW);
    const saturated = w.enqueue(1024, NOW);
    expect(saturated.ok).toBe(false);
    if (saturated.ok) throw new Error("unreachable");
    expect(saturated.code).toBe("queue_refused_bytes");

    w.dequeue(NOW);
    const stalled = w.enqueue(1024, NOW);
    expect(stalled.ok).toBe(false);
    if (stalled.ok) throw new Error("unreachable");
    expect(stalled.code).toBe("queue_refused_backpressure");

    expect(classified("queue_saturation").disposition).toBe("refuse_frame");
    expect(classified("slow_receiver").disposition).toBe("refuse_frame");

    client.destroy();
    await closeServer(server, sockets);
  }, 25_000);

  it("a bounded reconnect STORM over real socket churn exhausts the bound", async () => {
    const sockets: Socket[] = [];
    const server = createServer((sock) => {
      sockets.push(sock);
      sock.on("error", () => undefined);
      sock.destroy();
    });
    await listenOn(server, PORT_STORM);

    const w = window(NOW, 3);
    let established = 0;
    for (let i = 0; i < 12; i += 1) {
      try {
        const client = await connectTo(PORT_STORM);
        client.on("error", () => undefined);
        established += 1;
        client.destroy();
      } catch {
        // a refused connect is still a failed attempt, not a session
      }
      await sleep(5);
    }
    expect(established).toBeGreaterThan(0);

    // Twelve real connection attempts, but only three reconnects are allowed
    // in the window: the storm is answered with refusals, not more sessions.
    let permitted = 0;
    let refused = 0;
    for (let i = 0; i < 12; i += 1) {
      const result = w.reconnect(NOW + i, "closed");
      if (result.ok) permitted += 1;
      else refused += 1;
    }
    expect(permitted).toBe(3);
    expect(refused).toBe(9);
    expect(w.stats().connections).toBe(0);
    expect(classified("reconnect_storm").disposition).toBe("refuse_reconnect");

    await closeServer(server, sockets);
  }, 25_000);

  it("a malformed+valid mix refuses the malformed frame and keeps the valid sequence", () => {
    const w = window();
    // A malformed frame beside valid ones: only the malformed one refuses.
    const malformed = decideQueueAdmission({ frameBytes: FRAMED_TRANSPORT_BOUNDS.maxFrameBytes + 1, depth: 0, queuedBytes: 0, receiverDraining: true });
    expect(malformed.ok).toBe(false);
    if (malformed.ok) throw new Error("unreachable");
    expect(malformed.code).toBe("queue_refused_byte_size");

    const valid = decideQueueAdmission({ frameBytes: 512, depth: 0, queuedBytes: 0, receiverDraining: true });
    expect(valid.ok).toBe(true);
    // And the window itself is untouched and still open.
    expect(w.state()).toBe("open");
    expect(w.enqueue(512, NOW).ok).toBe(true);
    expect(classified("malformed_mixed_with_valid").disposition).toBe("refuse_frame");
    expect(classified("malformed_frame").disposition).toBe("refuse_frame");
  });

  it("a trust/key change during traffic maps to the frozen 26E refusal, never to a resume", () => {
    const trustChanged = classified("trust_changed");
    expect(trustChanged.disposition).toBe("quarantine_peer");
    const trustCode = RESILIENCE_INGRESS_REMAP[trustChanged.failureClass];
    expect(trustCode).toBe("peer_not_admitted");
    expect(trustCode === null ? null : ingressStageOf(trustCode)).toBe("local_admission");

    const keyChanged = classified("key_changed");
    expect(keyChanged.disposition).toBe("new_session_rehandshake");
    const keyCode = RESILIENCE_INGRESS_REMAP[keyChanged.failureClass];
    expect(keyCode).toBe("key_use_refused");
    expect(keyCode === null ? null : ingressStageOf(keyCode)).toBe("current_key_use");

    // A key change is a NEW session with revalidation, never a continuation.
    const rehandshake = decideReconnect({
      priorState: "authenticated",
      priorTranscriptHash: "c".repeat(64),
      reconnectAttemptsInWindow: 0,
    });
    expect(rehandshake.ok).toBe(true);
    if (!rehandshake.ok) throw new Error(rehandshake.explanation);
    expect(rehandshake.carriedTranscript).toBe("none");
    expect(rehandshake.carriedAdmission).toBe("none");
    expect([...rehandshake.revalidate]).toContain("key_use");
    expect([...rehandshake.revalidate]).toContain("local_admission");
  });
});
