/**
 * PHASE 26C — Bounded Framed LOCAL Socket Transport Tests
 * (BINARY-SAFE / HARD BOUNDS NEVER WIDEN / FAIL CLOSED / NO AUTH HERE).
 *
 * Pack-mandated coverage:
 *   overflow            — declared length over the bound refuses from the
 *                          length word alone: no allocation, no wait for body
 *   short/extra bytes   — partial frames hold exactly; stray tail bytes fault
 *   fragmentation       — byte-at-a-time delivery completes exactly once
 *   coalesced frames    — several frames in one chunk decode in order
 *   unknown type/version— non-pinned wire type/version refuse
 *   buffer exhaustion   — inbound chunk and unread-queue bounds refuse
 *   slow partial sender  — the read deadline faults a stalling peer
 *   abrupt close        — stream end mid-frame refuses, never delivered
 *   write-after-close    — a closed session never reaches the sink
 *
 * Plus: frozen bounds/config decisions, encoder layout + determinism,
 * frames/window flood bound, write/idle deadlines, idempotent close,
 * the connections bound, a structural source scan, and real loopback
 * socket round trips (loopback only, exact numeric address, torn down
 * inside each test).
 */
import { describe, it, expect } from "vitest";
import {
  FRAMED_TRANSPORT_SCHEMA_VERSION,
  FRAME_MAGIC,
  FRAME_PROTOCOL_VERSION,
  FRAME_HEADER_BYTES,
  FRAME_CORRELATION_CHARS,
  FRAME_TYPES,
  FRAME_TYPE_CODES,
  FRAMED_TRANSPORT_BOUNDS,
  FRAMED_TRANSPORT_REFUSAL_CODES,
  FRAMED_SESSION_STATES,
  FRAMED_LOCAL_CLOSE_CODES,
  REFUSAL_EXPLANATIONS,
  decideFramedTransportConfig,
  encodeFrame,
  FramedTransport,
  type FramedSession,
  type FramedSink,
  type FramedPayload,
  type FramedTransportRefusalCode,
  type FramedSessionState,
} from "@menog/durable-state";
import { createServer, connect, type Server, type Socket } from "node:net";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// ── helpers ─────────────────────────────────────────────────────────────────

/** Comment-stripped module source (same discipline as the 24A+ frozen suites). */
function moduleSource(): string {
  const raw = readFileSync(
    join(process.cwd(), "packages", "durable-state", "src", "framedSocketTransport.ts"),
    "utf8"
  );
  return raw
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

function rawModuleSource(): string {
  return readFileSync(
    join(process.cwd(), "packages", "durable-state", "src", "framedSocketTransport.ts"),
    "utf8"
  );
}

const CORR_A = "0123456789abcdef0123456789abcdef";
const CORR_B = "fedcba9876543210fedcba9876543210";

/** Structural shape shared by every refusal result (ok:false + code + state). */
interface RefusalLike {
  readonly ok: boolean;
  readonly refusal?: FramedTransportRefusalCode | null;
  readonly state?: FramedSessionState;
}

function expectRefusal(result: RefusalLike, code: FramedTransportRefusalCode, state?: FramedSessionState): void {
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("unreachable: expected a refusal");
  expect(result.refusal).toBe(code);
  if (state !== undefined) expect(result.state).toBe(state);
  const explanation = (result as { explanation?: unknown }).explanation;
  if (explanation !== undefined) expect(String(explanation).length).toBeGreaterThan(10);
}

/** Fake sink: records writes, counts destroys, simulates backpressure. */
function fakeSink(backpressure = false): {
  sink: FramedSink;
  writes: Buffer[];
  destroyCount: () => number;
  setBackpressure: (value: boolean) => void;
} {
  const writes: Buffer[] = [];
  let destroys = 0;
  let pressured = backpressure;
  const sink: FramedSink = {
    write: (chunk: Uint8Array) => {
      writes.push(Buffer.from(chunk));
      return !pressured;
    },
    destroy: () => {
      destroys += 1;
    },
  };
  return { sink, writes, destroyCount: () => destroys, setBackpressure: (value: boolean) => { pressured = value; } };
}

/** Open one session at a fixed clock (default t0 = 0 ms). */
function openAt(
  t0 = 0,
  config?: ConstructorParameters<typeof FramedTransport>[0]
): { transport: FramedTransport; fake: ReturnType<typeof fakeSink>; session: FramedSession } {
  const transport = new FramedTransport(config);
  const fake = fakeSink();
  const opened = transport.openSession(fake.sink, t0);
  if (!opened.ok) throw new Error(`openSession refused: ${opened.refusal} — ${opened.explanation}`);
  return { transport, fake, session: opened.session };
}

/** Encode a frame as bytes (test-side convenience over the exported encoder). */
function bytes(
  type: "data" | "close",
  correlationId: string,
  payload: Uint8Array | string
): Buffer {
  const body = typeof payload === "string" ? Buffer.from(payload, "utf8") : Buffer.from(payload);
  const encoded = encodeFrame({ type, correlationId, payload: body });
  if (!encoded.ok) throw new Error(`encode refused: ${encoded.explanation}`);
  return encoded.bytes;
}

/** Return a mutated copy of `source` (never mutates the original). */
function corrupted(source: Buffer, index: number, value: number): Buffer {
  const copy = Buffer.from(source);
  copy[index] = value;
  return copy;
}

/** A valid 10-byte header prefix carrying an arbitrary declared length. */
function headerPrefixWithLength(length: number): Buffer {
  const prefix = Buffer.alloc(10);
  prefix[0] = 0x4d;
  prefix[1] = 0x4e;
  prefix[2] = 0x4f;
  prefix[3] = 0x47;
  prefix.writeUInt8(FRAME_PROTOCOL_VERSION, 4);
  prefix.writeUInt8(FRAME_TYPE_CODES.data, 5);
  prefix.writeUInt32BE(length, 6);
  return prefix;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(condition: () => boolean, ms = 3000): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (condition()) return true;
    await sleep(10);
  }
  return condition();
}

/** One attached session over a real local socket: glue lives test-side. */
interface Attached {
  session: FramedSession;
  received: FramedPayload[];
  failures: RefusalLike[];
}
function attachSession(transport: FramedTransport, socket: Socket): Attached {
  const opened = transport.openSession(
    { write: (chunk) => socket.write(chunk), destroy: () => socket.destroy() },
    Date.now()
  );
  if (!opened.ok) throw new Error(`openSession refused: ${opened.refusal} — ${opened.explanation}`);
  const received: FramedPayload[] = [];
  const failures: RefusalLike[] = [];
  socket.on("data", (chunk) => {
    const bytes = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
    const result = opened.session.receive(bytes, Date.now());
    if (!result.ok) {
      failures.push(result);
      return;
    }
    if (result.framesAccepted > 0) received.push(...opened.session.read());
  });
  socket.on("close", () => {
    opened.session.notifyStreamClosed(Date.now());
  });
  socket.on("error", () => {
    // Local socket errors surface as close events; the session close path is authoritative.
  });
  return { session: opened.session, received, failures };
}

function listenOn(port: number, onSocket: (socket: Socket) => void): Promise<{ server: Server; sockets: Socket[] }> {
  return new Promise((resolve, reject) => {
    const sockets: Socket[] = [];
    const server = createServer((socket) => {
      sockets.push(socket);
      onSocket(socket);
    });
    server.once("error", reject);
    server.listen({ port, host: "127.0.0.1" }, () => resolve({ server, sockets }));
  });
}

function connectTo(port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect({ port, host: "127.0.0.1" }, () => resolve(socket));
    socket.once("error", reject);
  });
}

async function closeServer(server: Server, sockets: Socket[]): Promise<void> {
  for (const socket of sockets) socket.destroy();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

// Deterministic ports for the real-socket tests (fixed, explicit, loopback only).
const PORT_ROUNDTRIP = 41880;
const PORT_FRAGMENT = 41881;
const PORT_COALESCED = 41882;
const PORT_ABRUPT = 41883;
const PORT_WRITE_AFTER_CLOSE = 41884;

// ── vocabulary + bound pins ────────────────────────────────────────────────

describe("vocabularies and bounds are pinned", () => {
  it("schema, magic, version, header width and type vocabulary are exact", () => {
    expect(FRAMED_TRANSPORT_SCHEMA_VERSION).toBe("menog-framed-transport/v0");
    expect([...FRAME_MAGIC]).toEqual([0x4d, 0x4e, 0x4f, 0x47]);
    expect(FRAME_PROTOCOL_VERSION).toBe(1);
    expect(FRAME_HEADER_BYTES).toBe(42);
    expect(FRAME_CORRELATION_CHARS).toBe(32);
    expect([...FRAME_TYPES]).toEqual(["data", "close"]);
    expect({ ...FRAME_TYPE_CODES }).toEqual({ data: 1, close: 2 });
  });

  it("the refusal vocabulary is the exact closed list and every code explains itself", () => {
    expect([...FRAMED_TRANSPORT_REFUSAL_CODES]).toEqual([
      "config_invalid",
      "sink_invalid",
      "clock_invalid",
      "connections_exceeded",
      "session_closed",
      "write_after_close",
      "chunk_invalid",
      "magic_refused",
      "version_refused",
      "type_refused",
      "declared_oversize_refused",
      "correlation_refused",
      "buffer_exhausted",
      "flood_refused",
      "read_deadline_exceeded",
      "write_deadline_exceeded",
      "idle_deadline_exceeded",
      "truncated_frame_refused",
      "send_invalid_refused",
      "send_oversize_refused",
    ]);
    expect(Object.keys(REFUSAL_EXPLANATIONS).sort()).toEqual([...FRAMED_TRANSPORT_REFUSAL_CODES].sort());
    for (const code of FRAMED_TRANSPORT_REFUSAL_CODES) {
      expect(REFUSAL_EXPLANATIONS[code].length).toBeGreaterThan(10);
    }
    expect(Object.isFrozen(FRAMED_TRANSPORT_REFUSAL_CODES)).toBe(true);
    expect(Object.isFrozen(REFUSAL_EXPLANATIONS)).toBe(true);
  });

  it("every hard bound is the pinned constant and the object is frozen", () => {
    expect({ ...FRAMED_TRANSPORT_BOUNDS }).toEqual({
      headerBytes: 42,
      correlationChars: 32,
      maxFrameBytes: 8192,
      maxPayloadBytes: 8150,
      maxBufferedUnreadBytes: 65536,
      maxFramesPerWindow: 256,
      frameWindowMs: 1000,
      maxConnections: 16,
      readDeadlineMs: 30000,
      writeDeadlineMs: 10000,
      idleDeadlineMs: 30000,
    });
    expect(Object.isFrozen(FRAMED_TRANSPORT_BOUNDS)).toBe(true);
    expect([...FRAMED_SESSION_STATES]).toEqual(["open", "closed"]);
    expect([...FRAMED_LOCAL_CLOSE_CODES]).toEqual(["local_close", "remote_close", "transport_shutdown"]);
  });
});

// ── config decision ────────────────────────────────────────────────────────

describe("config decision: defaults admit, out-of-range refuses, never clamps", () => {
  it("unset config admits the pinned bounds with a deterministic hash", () => {
    for (const config of [undefined, null, {}]) {
      const decision = decideFramedTransportConfig(config);
      expect(decision.ok).toBe(true);
      expect(decision.refusal).toBeNull();
      expect({ ...decision.admitted }).toEqual({
        maxConnections: 16,
        readDeadlineMs: 30000,
        writeDeadlineMs: 10000,
        idleDeadlineMs: 30000,
      });
      expect(decision.provenanceHash).toMatch(/^[0-9a-f]{64}$/);
      expect(decision.explanation.length).toBeGreaterThan(10);
    }
    const a = decideFramedTransportConfig({ maxConnections: 4 });
    const b = decideFramedTransportConfig({ maxConnections: 4 });
    const c = decideFramedTransportConfig({ maxConnections: 5 });
    expect(a.provenanceHash).toBe(b.provenanceHash);
    expect(a.provenanceHash).not.toBe(c.provenanceHash);
  });

  it("above-ceiling, zero, negative, fractional, NaN and non-number values all refuse", () => {
    const bad: ReadonlyArray<unknown> = [
      { maxConnections: 17 },
      { readDeadlineMs: 30001 },
      { writeDeadlineMs: 10001 },
      { idleDeadlineMs: 30001 },
      { maxConnections: 0 },
      { maxConnections: -1 },
      { readDeadlineMs: 1.5 },
      { writeDeadlineMs: Number.NaN },
      { idleDeadlineMs: "9" },
    ];
    for (const config of bad) {
      const decision = decideFramedTransportConfig(config as never);
      expect(decision.ok).toBe(false);
      expect(decision.refusal).toBe("config_invalid");
      expect(decision.explanation).toContain("refused");
      expect(decision.provenanceHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("unknown config keys refuse (closed shape — no surprise widening)", () => {
    const decision = decideFramedTransportConfig({ maxConnections: 4, fromEnvironment: 1 } as never);
    expectRefusal(decision, "config_invalid");
    expect(decision.ok).toBe(false);
    expect(decision.explanation).toContain("fromEnvironment");
  });
});

// ── encoder ────────────────────────────────────────────────────────────────

describe("encodeFrame: pinned layout, determinism, opaque payload", () => {
  it("writes the exact 42-byte header layout", () => {
    const encoded = bytes("data", CORR_A, "hi");
    expect(encoded.length).toBe(44);
    expect([encoded[0], encoded[1], encoded[2], encoded[3]]).toEqual([0x4d, 0x4e, 0x4f, 0x47]);
    expect(encoded.readUInt8(4)).toBe(1);
    expect(encoded.readUInt8(5)).toBe(1);
    expect(encoded.readUInt32BE(6)).toBe(2);
    expect(encoded.subarray(10, 42).toString("ascii")).toBe(CORR_A);
    expect(encoded.subarray(42).toString("utf8")).toBe("hi");
  });

  it("encoding is byte-identical across runs (no randomness, no clock)", () => {
    const first = bytes("close", CORR_B, Buffer.from([0x00, 0xff, 0x80]));
    const second = bytes("close", CORR_B, Buffer.from([0x00, 0xff, 0x80]));
    expect(first.equals(second)).toBe(true);
  });

  it("payload bytes survive the round trip opaque and byte-identical", () => {
    const { session } = openAt(0);
    const payload = Buffer.from([0x00, 0xff, 0x80, 0xfe, 0x01, 0x00, 0x0a]);
    const received = session.receive(bytes("close", CORR_B, payload), 10);
    expect(received.ok).toBe(true);
    const frames = session.read();
    expect(frames).toHaveLength(1);
    expect(frames[0]?.type).toBe("close");
    expect(frames[0]?.correlationId).toBe(CORR_B);
    expect(Buffer.from(frames[0]?.payload ?? new Uint8Array()).equals(payload)).toBe(true);
    expect(session.state()).toBe("open");
  });

  it("8150-byte payload admits; 8151 refuses (bound never widens, never truncates)", () => {
    const atBound = encodeFrame({ type: "data", correlationId: CORR_A, payload: Buffer.alloc(8150, 0xab) });
    expect(atBound.ok).toBe(true);
    if (!atBound.ok) throw new Error("unreachable");
    expect(atBound.frameBytes).toBe(8192);

    const overBound = encodeFrame({ type: "data", correlationId: CORR_A, payload: Buffer.alloc(8151, 0xab) });
    expect(overBound.ok).toBe(false);
    if (overBound.ok) throw new Error("unreachable");
    expect(overBound.refusal).toBe("send_oversize_refused");
    expect(overBound.explanation).toContain("8151");
    expect(overBound.explanation).toContain("8150");
  });

  it("outbound shape violations refuse with send_invalid_refused", () => {
    const badFrames: ReadonlyArray<unknown> = [
      null,
      undefined,
      { type: "ping", correlationId: CORR_A, payload: Buffer.alloc(1) },
      { type: "data", correlationId: CORR_A.toUpperCase(), payload: Buffer.alloc(1) },
      { type: "data", correlationId: CORR_A.slice(0, 31), payload: Buffer.alloc(1) },
      { type: "data", correlationId: "z".repeat(32), payload: Buffer.alloc(1) },
      { type: "data", correlationId: CORR_A, payload: null },
    ];
    for (const frame of badFrames) {
      const encoded = encodeFrame(frame as never);
      expect(encoded.ok).toBe(false);
      if (encoded.ok) throw new Error("unreachable");
      expect(encoded.refusal).toBe("send_invalid_refused");
      expect(encoded.explanation.length).toBeGreaterThan(10);
    }
  });
});

// ── receive: one-shot, fragmentation, coalescing ───────────────────────────

describe("receive: one-shot, fragmentation, coalescing", () => {
  it("one chunk delivers one frame with pinned fields, drained exactly once", () => {
    const { session } = openAt(0);
    const result = session.receive(bytes("data", CORR_A, "payload-one"), 5);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(result.framesAccepted).toBe(1);
    expect(result.queuedFrames).toBe(1);
    expect(result.bufferedUnreadBytes).toBe(0);
    const frames = session.read();
    expect(frames).toHaveLength(1);
    expect(frames[0]?.type).toBe("data");
    expect(frames[0]?.correlationId).toBe(CORR_A);
    expect(Buffer.from(frames[0]?.payload ?? new Uint8Array()).toString("utf8")).toBe("payload-one");
    expect(session.read()).toHaveLength(0);
    expect(session.state()).toBe("open");
  });

  it("byte-at-a-time fragmentation completes exactly once", () => {
    const { session } = openAt(0);
    const whole = bytes("data", CORR_A, "fragmented-payload");
    for (let index = 0; index < whole.length - 1; index += 1) {
      const step = session.receive(whole.subarray(index, index + 1), index);
      expect(step.ok).toBe(true);
      if (!step.ok) throw new Error("unreachable");
      expect(step.framesAccepted).toBe(0);
      expect(step.bufferedUnreadBytes).toBe(index + 1);
    }
    const last = session.receive(whole.subarray(whole.length - 1), whole.length - 1);
    expect(last.ok).toBe(true);
    if (!last.ok) throw new Error("unreachable");
    expect(last.framesAccepted).toBe(1);
    expect(last.bufferedUnreadBytes).toBe(0);
    expect(session.read()).toHaveLength(1);
    expect(session.bufferedUnreadBytes()).toBe(0);
  });

  it("splits at every header boundary hold safely and complete once", () => {
    const whole = bytes("data", CORR_A, "boundary");
    for (const split of [1, 3, 4, 5, 6, 10, 41, 42]) {
      const { session } = openAt(0);
      const head = session.receive(whole.subarray(0, split), 1);
      expect(head.ok).toBe(true);
      if (!head.ok) throw new Error("unreachable");
      expect(head.framesAccepted).toBe(0);
      expect(head.bufferedUnreadBytes).toBe(split);
      const tail = session.receive(whole.subarray(split), 2);
      expect(tail.ok).toBe(true);
      if (!tail.ok) throw new Error("unreachable");
      expect(tail.framesAccepted).toBe(1);
      expect(session.read()).toHaveLength(1);
    }
  });

  it("coalesced frames decode in one chunk, in order, with distinct fields", () => {
    const { session } = openAt(0);
    const batch = Buffer.concat([
      bytes("data", CORR_A, "one"),
      bytes("close", CORR_B, "two"),
      bytes("data", CORR_A, "three"),
    ]);
    const result = session.receive(batch, 7);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(result.framesAccepted).toBe(3);
    expect(result.queuedFrames).toBe(3);
    expect(result.bufferedUnreadBytes).toBe(0);
    const frames = session.read();
    expect(frames.map((frame) => frame.type)).toEqual(["data", "close", "data"]);
    expect(frames.map((frame) => frame.correlationId)).toEqual([CORR_A, CORR_B, CORR_A]);
    expect(frames.map((frame) => Buffer.from(frame.payload).toString("utf8"))).toEqual(["one", "two", "three"]);
  });
});

// ── peer refusals (fail closed) ──────────────────────────────────────────

describe("peer violations fault the session and never deliver partial data", () => {
  it("wrong magic faults: closed, sink destroyed once, nothing delivered", () => {
    const { session, fake } = openAt(0);
    const result = session.receive(corrupted(bytes("data", CORR_A, "x"), 0, 0x00), 10);
    expectRefusal(result, "magic_refused", "closed");
    expect(session.state()).toBe("closed");
    expect(session.closeCode()).toBe("magic_refused");
    expect(fake.destroyCount()).toBe(1);
    expect(session.read()).toHaveLength(0);
  });

  it("unknown frame versions (0 and 2) refuse — no upgrade or downgrade path", () => {
    for (const version of [0, 2]) {
      const { session } = openAt(0);
      const result = session.receive(corrupted(bytes("data", CORR_A, "v"), 4, version), 10);
      expectRefusal(result, "version_refused", "closed");
      expect(session.closeCode()).toBe("version_refused");
    }
  });

  it("unknown frame types (0, 3, 255) refuse the closed vocabulary", () => {
    for (const typeCode of [0, 3, 255]) {
      const { session } = openAt(0);
      const result = session.receive(corrupted(bytes("data", CORR_A, "t"), 5, typeCode), 10);
      expectRefusal(result, "type_refused", "closed");
      expect(session.closeCode()).toBe("type_refused");
    }
  });

  it("declared oversize refuses from the length word alone (no body, no allocation)", () => {
    // 0xffffffff arrives in a 10-byte prefix: no correlation, no payload bytes
    // are ever supplied, yet the refusal is immediate — the bound is checked
    // against the declared length BEFORE any body is requested or reserved.
    const { session, fake } = openAt(0);
    const result = session.receive(headerPrefixWithLength(0xffffffff), 10);
    expectRefusal(result, "declared_oversize_refused", "closed");
    expect(result.ok).toBe(false);
    expect(String((result as { explanation?: string }).explanation)).toContain("4294967295");
    expect(session.bufferedUnreadBytes()).toBe(0);
    expect(fake.destroyCount()).toBe(1);

    // One past the bound still refuses with only the 10-byte prefix present.
    const over = openAt(0);
    const overResult = over.session.receive(headerPrefixWithLength(8151), 10);
    expectRefusal(overResult, "declared_oversize_refused", "closed");

    // Exactly at the bound admits once every byte arrives.
    const atBound = openAt(0);
    const complete = atBound.session.receive(bytes("data", CORR_A, Buffer.alloc(8150, 0xcd)), 10);
    expect(complete.ok).toBe(true);
    if (!complete.ok) throw new Error("unreachable");
    expect(complete.framesAccepted).toBe(1);
    expect(atBound.session.read()).toHaveLength(1);
  });

  it("invalid required correlation refuses (non-hex and uppercase)", () => {
    const valid = bytes("data", CORR_A, "c");
    const nonHex = corrupted(valid, 10, 0x7a); // 'z'
    const upper = corrupted(valid, 10, 0x41); // 'A'
    for (const variant of [nonHex, upper]) {
      const { session } = openAt(0);
      const result = session.receive(variant, 10);
      expectRefusal(result, "correlation_refused", "closed");
      expect(session.closeCode()).toBe("correlation_refused");
      expect(session.read()).toHaveLength(0);
    }
  });

  it("stray tail bytes fault the session and drop the already-decoded queue", () => {
    const { session, fake } = openAt(0);
    const frameAndTail = Buffer.concat([bytes("data", CORR_A, "valid"), Buffer.from([0x00, 0x01, 0x02, 0x03])]);
    const result = session.receive(frameAndTail, 10);
    expectRefusal(result, "magic_refused", "closed");
    // Uniform drop rule: NOTHING queued is readable after a fault.
    expect(session.read()).toHaveLength(0);
    expect(session.droppedFrames()).toBe(1);
    expect(fake.destroyCount()).toBe(1);
  });

  it("abrupt stream end mid-frame refuses the partial frame (truncated)", () => {
    const { session, fake } = openAt(0);
    const whole = bytes("data", CORR_A, "cut-off-mid-frame");
    const partial = session.receive(whole.subarray(0, 20), 10);
    expect(partial.ok).toBe(true);
    if (!partial.ok) throw new Error("unreachable");
    expect(partial.framesAccepted).toBe(0);
    expect(session.bufferedUnreadBytes()).toBe(20);
    const closed = session.notifyStreamClosed(20);
    expectRefusal(closed, "truncated_frame_refused", "closed");
    expect(session.closeCode()).toBe("truncated_frame_refused");
    expect(session.bufferedUnreadBytes()).toBe(0);
    expect(fake.destroyCount()).toBe(1);
  });
});

// ── hard bounds ─────────────────────────────────────────────────────────────

describe("hard bounds refuse instead of widening", () => {
  it("frames/window: 256 admit, the 257th refuses, a fresh window opens", () => {
    const tiny = bytes("data", CORR_A, "f");

    const flood = openAt(0);
    const batch = Buffer.concat(Array.from({ length: 256 }, () => tiny));
    const first = flood.session.receive(batch, 0);
    expect(first.ok).toBe(true);
    if (!first.ok) throw new Error("unreachable");
    expect(first.framesAccepted).toBe(256);
    const overflow = flood.session.receive(tiny, 0);
    expectRefusal(overflow, "flood_refused", "closed");
    expect(flood.session.closeCode()).toBe("flood_refused");

    // Window rollover: a frame exactly one window later is admitted again.
    const rollover = openAt(0);
    const beforeWindow = rollover.session.receive(tiny, 999);
    expect(beforeWindow.ok).toBe(true);
    const afterWindow = rollover.session.receive(tiny, 1000);
    expect(afterWindow.ok).toBe(true);
    if (!afterWindow.ok) throw new Error("unreachable");
    expect(afterWindow.framesAccepted).toBe(1);
    expect(rollover.session.read()).toHaveLength(2);
  });

  it("unread-queue bound: draining stops at the bound; one more frame refuses", () => {
    const big = bytes("data", CORR_A, Buffer.alloc(8150, 0xab)); // 8192 B frames
    expect(big.length).toBe(8192);
    const { session } = openAt(0);
    const eight = Buffer.concat(Array.from({ length: 8 }, () => big)); // exactly 65536 B
    expect(eight.length).toBe(65536);
    const fill = session.receive(eight, 10);
    expect(fill.ok).toBe(true);
    if (!fill.ok) throw new Error("unreachable");
    expect(fill.framesAccepted).toBe(8);
    expect(session.queuedFrames()).toBe(8);

    const ninth = session.receive(big, 11);
    expectRefusal(ninth, "buffer_exhausted", "closed");
    expect(session.read()).toHaveLength(0); // fault drops the whole queue
    expect(session.droppedFrames()).toBe(8);
    expect(session.closeCode()).toBe("buffer_exhausted");
  });

  it("inbound chunk bound refuses before a single byte is buffered", () => {
    const { session } = openAt(0);
    const prefix = headerPrefixWithLength(500); // valid partial start (10 B)
    const partial = session.receive(prefix, 0);
    expect(partial.ok).toBe(true);
    const oversizedChunk = Buffer.alloc(65527, 0x41); // 10 + 65527 = 65537 > 65536
    const refused = session.receive(oversizedChunk, 100);
    expectRefusal(refused, "buffer_exhausted", "closed");
    expect(String((refused as { explanation?: string }).explanation)).toContain("65537");
    expect(session.bufferedUnreadBytes()).toBe(0);
  });
});

// ── deadlines ───────────────────────────────────────────────────────────────

describe("read/write/idle deadlines are hard bounds with caller-supplied time", () => {
  it("read deadline: completion exactly at the bound admits; one ms later faults", () => {
    const whole = bytes("data", CORR_A, "slow-but-in-time");

    const inTime = openAt(0);
    const headInTime = inTime.session.receive(whole.subarray(0, 10), 0);
    expect(headInTime.ok).toBe(true);
    const finishInTime = inTime.session.receive(whole.subarray(10), 30000);
    expect(finishInTime.ok).toBe(true);
    if (!finishInTime.ok) throw new Error("unreachable");
    expect(finishInTime.framesAccepted).toBe(1);

    const tooLate = openAt(0);
    const headTooLate = tooLate.session.receive(whole.subarray(0, 10), 0);
    expect(headTooLate.ok).toBe(true);
    const finishTooLate = tooLate.session.receive(whole.subarray(10), 30001);
    expectRefusal(finishTooLate, "read_deadline_exceeded", "closed");
    expect(tooLate.session.closeCode()).toBe("read_deadline_exceeded");
    expect(tooLate.session.read()).toHaveLength(0);
  });

  it("a dripping partial sender cannot reset the read deadline", () => {
    const whole = bytes("data", CORR_A, "drip-drip-drip");
    const { session } = openAt(0);
    expect(session.receive(whole.subarray(0, 4), 0).ok).toBe(true); // partial starts at t=0
    expect(session.receive(whole.subarray(4, 5), 10000).ok).toBe(true);
    expect(session.receive(whole.subarray(5, 6), 20000).ok).toBe(true);
    const finish = session.receive(whole.subarray(6), 30001);
    expectRefusal(finish, "read_deadline_exceeded", "closed"); // measured from the FIRST byte
  });

  it("write deadline faults sustained backpressure; a drain notice clears it", () => {
    const { session, fake } = openAt(0);
    fake.setBackpressure(true);
    const sent = session.send({ type: "data", correlationId: CORR_A, payload: Buffer.from("w") }, 0);
    expect(sent.ok).toBe(true);
    if (!sent.ok) throw new Error("unreachable");
    expect(sent.backpressured).toBe(true);

    expect(session.checkDeadlines(10000).ok).toBe(true); // exactly at the bound: still open
    const faulted = session.checkDeadlines(10001);
    expectRefusal(faulted, "write_deadline_exceeded", "closed");

    // A drain notice clears a real block: the same check would fault without it.
    const drained = openAt(0);
    drained.fake.setBackpressure(true);
    const sentAgain = drained.session.send({ type: "data", correlationId: CORR_A, payload: Buffer.from("w") }, 0);
    expect(sentAgain.ok).toBe(true);
    if (!sentAgain.ok) throw new Error("unreachable");
    expect(sentAgain.backpressured).toBe(true);
    drained.fake.setBackpressure(false);
    expect(drained.session.notifyWriteDrained().ok).toBe(true);
    expect(drained.session.checkDeadlines(20000).ok).toBe(true); // 20000 > 10000 but drained
    const idleAfterDrain = drained.session.checkDeadlines(30001);
    expectRefusal(idleAfterDrain, "idle_deadline_exceeded", "closed"); // the idle law still holds
  });

  it("idle deadline faults a silent session (boundary inclusive)", () => {
    const atBoundary = openAt(0);
    const okAtBoundary = atBoundary.session.receive(bytes("data", CORR_A, "i"), 30000);
    expect(okAtBoundary.ok).toBe(true);

    const silent = openAt(0);
    const faulted = silent.session.receive(bytes("data", CORR_A, "i"), 30001);
    expectRefusal(faulted, "idle_deadline_exceeded", "closed");
    expect(silent.session.closeCode()).toBe("idle_deadline_exceeded");
  });

  it("multi-violation precedence is pinned: read beats idle", () => {
    const { session } = openAt(0);
    const partial = session.receive(headerPrefixWithLength(100), 0);
    expect(partial.ok).toBe(true);
    // At t=30001 both the read and the idle deadline are exceeded; read wins.
    const faulted = session.checkDeadlines(30001);
    expectRefusal(faulted, "read_deadline_exceeded", "closed");
  });

  it("non-finite clock inputs refuse without faulting (caller error, session unchanged)", () => {
    const { session } = openAt(0);
    expectRefusal(session.receive(bytes("data", CORR_A, "n"), Number.NaN), "clock_invalid", "open");
    expectRefusal(session.checkDeadlines(Number.POSITIVE_INFINITY), "clock_invalid", "open");
    expectRefusal(session.notifyStreamClosed(Number.NaN), "clock_invalid", "open");
    expectRefusal(session.send({ type: "data", correlationId: CORR_A, payload: Buffer.from("n") }, Number.NaN), "clock_invalid", "open");
    // The session is still usable afterwards.
    const recovered = session.receive(bytes("data", CORR_A, "still-open"), 10);
    expect(recovered.ok).toBe(true);
    expect(session.state()).toBe("open");
  });
});

// ── session lifecycle ───────────────────────────────────────────────────────

describe("explicit lifecycle: write-after-close, idempotent close, uniform drop", () => {
  it("write-after-close never reaches the sink", () => {
    const { session, fake } = openAt(0);
    const closed = session.close();
    expect(closed.ok).toBe(true);
    expect(closed.code).toBe("session_closed");
    expect(closed.state).toBe("closed");
    expect(fake.destroyCount()).toBe(1);
    const writesBefore = fake.writes.length;
    expectRefusal(
      session.send({ type: "data", correlationId: CORR_A, payload: Buffer.from("late") }, 10),
      "write_after_close",
      "closed"
    );
    expect(fake.writes.length).toBe(writesBefore); // sink untouched
    expect(fake.destroyCount()).toBe(1); // destroy exactly once, ever
    expect(session.closeCode()).toBe("local_close");
    expectRefusal(session.receive(bytes("data", CORR_A, "x"), 10), "session_closed", "closed");
    expectRefusal(session.checkDeadlines(10), "session_closed", "closed");
    expectRefusal(session.notifyWriteDrained(), "session_closed", "closed");
    expect(session.read()).toHaveLength(0);
  });

  it("close is idempotent and drops every unread frame exactly once", () => {
    const { session, fake } = openAt(0);
    expect(session.receive(bytes("data", CORR_A, "unread"), 5).ok).toBe(true);
    expect(session.queuedFrames()).toBe(1);
    const first = session.close();
    expect(first.ok).toBe(true);
    expect(first.code).toBe("session_closed");
    expect(first.droppedFrames).toBe(1);
    const second = session.close();
    expect(second.code).toBe("session_already_closed");
    expect(second.droppedFrames).toBe(0);
    const third = session.close("transport_shutdown");
    expect(third.code).toBe("session_already_closed");
    expect(fake.destroyCount()).toBe(1);
    expect(session.read()).toHaveLength(0);
    expect(session.droppedFrames()).toBe(1);
  });

  it("a clean remote close is idempotent and records the drop", () => {
    const { session, fake } = openAt(0);
    expect(session.receive(bytes("data", CORR_A, "pending"), 5).ok).toBe(true);
    const first = session.notifyStreamClosed(10);
    expect(first.ok).toBe(true);
    if (!first.ok) throw new Error("unreachable");
    expect(first.code).toBe("remote_close");
    expect(first.droppedFrames).toBe(1);
    expect(session.closeCode()).toBe("remote_close");
    expect(fake.destroyCount()).toBe(1);
    expect(session.read()).toHaveLength(0);
    const second = session.notifyStreamClosed(20);
    expect(second.ok).toBe(true);
    if (!second.ok) throw new Error("unreachable");
    expect(second.code).toBe("session_already_closed");
    expect(fake.destroyCount()).toBe(1); // still exactly one destroy
  });

  it("caller-error refusals leave the session open and usable", () => {
    const { session, fake } = openAt(0);
    expectRefusal(
      session.send({ type: "ping", correlationId: CORR_A, payload: Buffer.alloc(1) } as never, 5),
      "send_invalid_refused",
      "open"
    );
    expectRefusal(
      session.send({ type: "data", correlationId: CORR_A, payload: Buffer.alloc(8151) }, 5),
      "send_oversize_refused",
      "open"
    );
    expectRefusal(session.receive("not-bytes" as never, 5), "chunk_invalid", "open");
    expect(session.state()).toBe("open");
    expect(fake.destroyCount()).toBe(0);
    // Still fully functional afterwards.
    expect(session.receive(bytes("data", CORR_A, "works"), 6).ok).toBe(true);
    const sent = session.send({ type: "data", correlationId: CORR_B, payload: Buffer.from("out") }, 7);
    expect(sent.ok).toBe(true);
    expect(fake.writes.length).toBe(1);
  });

  it("identical input sequences produce byte-identical results (determinism)", () => {
    const runs: string[] = [];
    for (let run = 0; run < 2; run += 1) {
      const { session } = openAt(0);
      const good = session.receive(bytes("data", CORR_A, "first"), 10);
      const bad = session.receive(Buffer.from([0x00, 0x01, 0x02, 0x03]), 11);
      const closed = session.receive(bytes("data", CORR_A, "never"), 12);
      runs.push(
        JSON.stringify([good, bad, closed, session.state(), session.closeCode(), session.droppedFrames()])
      );
    }
    expect(runs[0]).toBe(runs[1]);
  });
});

// ── transport host ──────────────────────────────────────────────────────────

describe("transport host: connections bound, validation, deterministic cleanup", () => {
  it("openSession enforces the pinned connection bound and releases slots on close", () => {
    const transport = new FramedTransport();
    const sessions: FramedSession[] = [];
    for (let index = 0; index < 16; index += 1) {
      const opened = transport.openSession(fakeSink().sink, 0);
      expect(opened.ok).toBe(true);
      if (!opened.ok) throw new Error("unreachable");
      sessions.push(opened.session);
    }
    expect(transport.activeConnections()).toBe(16);
    const refused = transport.openSession(fakeSink().sink, 0);
    expect(refused.ok).toBe(false);
    if (refused.ok) throw new Error("unreachable");
    expect(refused.refusal).toBe("connections_exceeded");
    expect(refused.explanation).toContain("16");
    expect(transport.activeConnections()).toBe(16);
    // Closing one session frees exactly one slot.
    sessions[0]?.close();
    expect(transport.activeConnections()).toBe(15);
    const reopened = transport.openSession(fakeSink().sink, 0);
    expect(reopened.ok).toBe(true);
    expect(transport.activeConnections()).toBe(16);
  });

  it("a refused config gates openSession before any session exists", () => {
    const transport = new FramedTransport({ maxConnections: 99 });
    expect(transport.decision().ok).toBe(false);
    expect(transport.decision().refusal).toBe("config_invalid");
    const opened = transport.openSession(fakeSink().sink, 0);
    expect(opened.ok).toBe(false);
    if (opened.ok) throw new Error("unreachable");
    expect(opened.refusal).toBe("config_invalid");
    expect(transport.activeConnections()).toBe(0);
  });

  it("sink shape and openedAt clock are validated at open", () => {
    const transport = new FramedTransport();
    const badSinks: ReadonlyArray<unknown> = [null, undefined, {}, { write: 1, destroy() {} }, { write() {} }];
    for (const badSink of badSinks) {
      const opened = transport.openSession(badSink as never, 0);
      expect(opened.ok).toBe(false);
      if (opened.ok) throw new Error("unreachable");
      expect(opened.refusal).toBe("sink_invalid");
    }
    const badClock = transport.openSession(fakeSink().sink, Number.NaN);
    expect(badClock.ok).toBe(false);
    if (badClock.ok) throw new Error("unreachable");
    expect(badClock.refusal).toBe("clock_invalid");
    expect(transport.activeConnections()).toBe(0);
  });

  it("closeAll closes every session deterministically and is idempotent", () => {
    const transport = new FramedTransport();
    const fakes = [fakeSink(), fakeSink(), fakeSink()];
    const sessions: FramedSession[] = [];
    for (const fake of fakes) {
      const opened = transport.openSession(fake.sink, 0);
      if (!opened.ok) throw new Error(`open refused: ${opened.refusal}`);
      sessions.push(opened.session);
    }
    expect(transport.activeConnections()).toBe(3);
    const first = transport.closeAll();
    expect(first.code).toBe("transport_closed");
    expect(first.closedSessions).toBe(3);
    expect(transport.activeConnections()).toBe(0);
    for (const session of sessions) expect(session.closeCode()).toBe("transport_shutdown");
    for (const fake of fakes) expect(fake.destroyCount()).toBe(1);
    const second = transport.closeAll();
    expect(second.code).toBe("transport_already_closed");
    expect(second.closedSessions).toBe(0);
  });

  it("decision provenance is deterministic across transports", () => {
    const a = new FramedTransport({ readDeadlineMs: 5000 }).decision();
    const b = new FramedTransport({ readDeadlineMs: 5000 }).decision();
    const c = new FramedTransport({ readDeadlineMs: 5001 }).decision();
    expect(a.provenanceHash).toBe(b.provenanceHash);
    expect(a.provenanceHash).not.toBe(c.provenanceHash);
    expect(a.admitted.readDeadlineMs).toBe(5000);
    expect(a.admitted.maxConnections).toBe(16);
    expect(a.admitted.writeDeadlineMs).toBe(10000);
    expect(a.admitted.idleDeadlineMs).toBe(30000);
  });
});

// ── structural scan ─────────────────────────────────────────────────────────

describe("structural scan: the module keeps to its sanctioned surface", () => {
  it("imports exactly ./canonical.js and nothing else", () => {
    const importMatches = [...rawModuleSource().matchAll(/from\s+"([^"]+)"/g)].map((match) => match[1]);
    expect(importMatches).toEqual(["./canonical.js"]);
  });

  it("forbids shell/child/env/dial/listener/clock/timer/crypto/persist/auth surfaces", () => {
    const source = moduleSource();
    const forbidden = [
      "child_process",
      "spawn",
      "process.env",
      "node:dns",
      "node:http",
      "node:net",
      "node:tls",
      "createServer",
      ".listen(",
      "fetch(",
      "axios",
      "XMLHttpRequest",
      "WebSocket",
      "createConnection",
      "connect(",
      "request(",
      ".pipe(",
      "setTimeout",
      "setInterval",
      "Date.now",
      "Math.random",
      "eval(",
      "require(",
      ".persist(",
      "createHash",
      "root =",
      "federation",
      "admission",
      "authenticate",
      "authority",
      "identity",
      "policy",
      "execution",
      "discovery",
    ];
    for (const token of forbidden) {
      expect(source).not.toContain(token);
    }
  });
});

// ── real local sockets (loopback only) ──────────────────────────────────────

describe("real local sockets: framed bytes over exact loopback endpoints", () => {
  it("binary-safe round trip over 127.0.0.1", async () => {
    const transport = new FramedTransport();
    const serverSessions: Attached[] = [];
    const { server, sockets } = await listenOn(PORT_ROUNDTRIP, (socket) => {
      serverSessions.push(attachSession(transport, socket));
    });
    let clientSocket: Socket | null = null;
    try {
      clientSocket = await connectTo(PORT_ROUNDTRIP);
      const client = attachSession(transport, clientSocket);
      await waitFor(() => serverSessions.length === 1);
      const payload = Buffer.from([0x00, 0xff, 0x80, 0x0a, 0x41, 0x00]);
      const sent = client.session.send({ type: "close", correlationId: CORR_B, payload }, Date.now());
      expect(sent.ok).toBe(true);
      const got = await waitFor(() => (serverSessions[0]?.received.length ?? 0) === 1);
      expect(got).toBe(true);
      const frame = serverSessions[0]?.received[0];
      expect(frame?.type).toBe("close");
      expect(frame?.correlationId).toBe(CORR_B);
      expect(Buffer.from(frame?.payload ?? new Uint8Array()).equals(payload)).toBe(true);
      expect(serverSessions[0]?.failures).toHaveLength(0);
    } finally {
      clientSocket?.destroy();
      await closeServer(server, sockets);
      transport.closeAll();
    }
  });

  it("a frame fragmented by the network completes exactly once", async () => {
    const transport = new FramedTransport();
    const serverSessions: Attached[] = [];
    const { server, sockets } = await listenOn(PORT_FRAGMENT, (socket) => {
      serverSessions.push(attachSession(transport, socket));
    });
    let clientSocket: Socket | null = null;
    try {
      clientSocket = await connectTo(PORT_FRAGMENT);
      clientSocket.on("error", () => {
        // teardown races are expected; the session close path is authoritative
      });
      await waitFor(() => serverSessions.length === 1);
      await sleep(20);
      const whole = bytes("data", CORR_A, "wire-fragmented");
      clientSocket.write(whole.subarray(0, 9));
      await sleep(15);
      clientSocket.write(whole.subarray(9, 41));
      await sleep(15);
      clientSocket.write(whole.subarray(41, 42));
      await sleep(15);
      clientSocket.write(whole.subarray(42));
      const got = await waitFor(() => (serverSessions[0]?.received.length ?? 0) === 1);
      expect(got).toBe(true);
      expect(serverSessions[0]?.failures).toHaveLength(0);
      const frame = serverSessions[0]?.received[0];
      expect(Buffer.from(frame?.payload ?? new Uint8Array()).toString("utf8")).toBe("wire-fragmented");
      expect(serverSessions[0]?.session.bufferedUnreadBytes()).toBe(0);
    } finally {
      clientSocket?.destroy();
      await closeServer(server, sockets);
      transport.closeAll();
    }
  });

  it("coalesced frames on the wire decode in order", async () => {
    const transport = new FramedTransport();
    const serverSessions: Attached[] = [];
    const { server, sockets } = await listenOn(PORT_COALESCED, (socket) => {
      serverSessions.push(attachSession(transport, socket));
    });
    let clientSocket: Socket | null = null;
    try {
      clientSocket = await connectTo(PORT_COALESCED);
      clientSocket.on("error", () => {
        // teardown races are expected
      });
      await waitFor(() => serverSessions.length === 1);
      await sleep(20);
      const batch = Buffer.concat([
        bytes("data", CORR_A, "first"),
        bytes("close", CORR_B, "second"),
        bytes("data", CORR_A, "third"),
      ]);
      clientSocket.write(batch);
      const got = await waitFor(() => (serverSessions[0]?.received.length ?? 0) === 3);
      expect(got).toBe(true);
      const frames = serverSessions[0]?.received ?? [];
      expect(frames.map((frame) => frame.type)).toEqual(["data", "close", "data"]);
      expect(frames.map((frame) => Buffer.from(frame.payload).toString("utf8"))).toEqual([
        "first",
        "second",
        "third",
      ]);
      expect(serverSessions[0]?.failures).toHaveLength(0);
    } finally {
      clientSocket?.destroy();
      await closeServer(server, sockets);
      transport.closeAll();
    }
  });

  it("abrupt close mid-frame faults the server session as truncated", async () => {
    const transport = new FramedTransport();
    const serverSessions: Attached[] = [];
    const { server, sockets } = await listenOn(PORT_ABRUPT, (socket) => {
      serverSessions.push(attachSession(transport, socket));
    });
    let clientSocket: Socket | null = null;
    try {
      clientSocket = await connectTo(PORT_ABRUPT);
      clientSocket.on("error", () => {
        // deliberate destruction produces an error event locally
      });
      await waitFor(() => serverSessions.length === 1);
      await sleep(20);
      const whole = bytes("data", CORR_A, "cut-off-before-the-end");
      clientSocket.write(whole.subarray(0, 20));
      await sleep(40); // let the partial frame arrive, then die abruptly
      clientSocket.destroy();
      const closed = await waitFor(() => serverSessions[0]?.session.state() === "closed");
      expect(closed).toBe(true);
      expect(serverSessions[0]?.session.closeCode()).toBe("truncated_frame_refused");
      expect(serverSessions[0]?.received).toHaveLength(0); // partial never delivered
    } finally {
      clientSocket?.destroy();
      await closeServer(server, sockets);
      transport.closeAll();
    }
  });

  it("write-after-close over a real socket refuses and tears down once", async () => {
    const transport = new FramedTransport();
    const serverSessions: Attached[] = [];
    const { server, sockets } = await listenOn(PORT_WRITE_AFTER_CLOSE, (socket) => {
      serverSessions.push(attachSession(transport, socket));
    });
    let clientSocket: Socket | null = null;
    try {
      clientSocket = await connectTo(PORT_WRITE_AFTER_CLOSE);
      const attached = await waitFor(() => serverSessions.length === 1);
      expect(attached).toBe(true);
      const session = serverSessions[0]?.session;
      expect(session?.state()).toBe("open");
      const closed = session?.close();
      expect(closed?.code).toBe("session_closed");
      if (!session) throw new Error("no server session");
      expectRefusal(
        session.send({ type: "data", correlationId: CORR_A, payload: Buffer.from("too-late") }, Date.now()),
        "write_after_close",
        "closed"
      );
      // The sink destruction reached the peer: the client observes the close.
      const peerClosed = await waitFor(() => clientSocket !== null && clientSocket.destroyed, 4000);
      expect(peerClosed).toBe(true);
    } finally {
      clientSocket?.destroy();
      await closeServer(server, sockets);
      transport.closeAll();
    }
  });
});


