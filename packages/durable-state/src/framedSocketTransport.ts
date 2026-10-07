/**
 * PHASE 26C — Governed Local Network Transport: Bounded Framed LOCAL Socket
 * Transport (MINIMAL / BINARY-SAFE / HARD BOUNDS / FAIL CLOSED).
 *
 * This module is the byte-level framing layer that sits directly above the
 * 26B endpoint/listener boundary and below any later interpretation. It is
 * deliberately the SMALLEST thing that can turn an untrusted local byte
 * stream into bounded, structured frames — and nothing else:
 *
 *   - FRAME BINDS magic + version + type + length + REQUIRED correlation,
 *     and only those fields. The header is a fixed 42-byte layout; there is
 *     no sequence number, no flag byte, no extension slot (replay, duplicate
 *     and reorder judgments belong to the 26A decideFrame contract above,
 *     never here).
 *   - HARD BOUNDS, all frozen constants a caller can exceed but never
 *     redefine: frame bytes (8192 total / 8150 payload), buffered unread
 *     bytes (65536), frames per window (256 per 1000 ms), connections (16),
 *     and read (30000 ms) / write (10000 ms) / idle (30000 ms) deadlines.
 *     Exceeding a bound REFUSES — never clamps, never widens, never retries.
 *   - NEVER ALLOCATE FROM AN UNCHECKED LENGTH: a declared payload length is
 *     validated against the pinned bound from the length word alone, before
 *     a single body byte is requested or reserved; the inbound chunk is
 *     bounded before it is buffered; every payload handed out is an isolated
 *     copy made only after its length has passed the bound.
 *   - REJECTS malformed / truncated / oversized / unknown-version /
 *     unknown-type / bad-correlation streams, and any flood, buffer
 *     exhaustion, deadline breach or mid-frame end — every peer-side
 *     violation FAULTS the session: state -> closed, unread queue dropped,
 *     sink destroyed exactly once, nothing partial ever delivered.
 *   - PAYLOAD IS OPAQUE DATA: this layer never decodes, parses, interprets
 *     or executes payload bytes; type and correlation are labels only.
 *   - NO AUTHENTICATION / FEDERATION LOGIC HERE: no identity, admission,
 *     authority, Policy, or execution surface exists in this module. Frame
 *     acceptance means ONLY "bounded, well-formed, in-order, timely" bytes.
 *     NETWORK REACHABILITY != IDENTITY != ADMISSION != AUTHORITY != EXECUTION.
 *   - NO I/O OF ITS OWN: the module never dials, never listens, never reads
 *     the environment, never spawns a process, never touches the wall clock
 *     or a timer (every entry point takes a caller-supplied nowMs), never
 *     persists anything, never uses crypto. Bytes leave through the caller's
 *     FramedSink only; bytes arrive through the caller's receive() call.
 *
 * Caller-error refusals (bad config, bad sink, bad clock input, bad outbound
 * frame, write-after-close) leave the session OPEN — only peer-side stream
 * violations fault it. Both paths are deterministic and suite-pinned.
 */
import { canonicalHash } from "./canonical.js";

/** Closed schema version for the framed-transport contract. */
export const FRAMED_TRANSPORT_SCHEMA_VERSION = "menog-framed-transport/v0" as const;

/** Frame magic: the four fixed header bytes "MNOG". */
export const FRAME_MAGIC = Object.freeze([0x4d, 0x4e, 0x4f, 0x47] as const);

/** The single supported frame protocol version (anything else refuses). */
export const FRAME_PROTOCOL_VERSION = 1 as const;

/** Fixed header size: magic 4 + version 1 + type 1 + length 4 + correlation 32. */
export const FRAME_HEADER_BYTES = 42 as const;

/** Required correlation field width in ASCII lowercase hex characters. */
export const FRAME_CORRELATION_CHARS = 32 as const;

/** Closed frame-type vocabulary (payload semantics stay opaque DATA). */
export const FRAME_TYPES = Object.freeze(["data", "close"] as const);
export type FrameType = (typeof FRAME_TYPES)[number];

/** Wire codes for the closed type vocabulary. */
export const FRAME_TYPE_CODES: Readonly<Record<FrameType, number>> = Object.freeze({
  data: 1,
  close: 2,
});

/** Reverse map: wire code -> closed type; unknown codes are absent (refused). */
const FRAME_TYPE_FROM_CODE: Readonly<Record<number, FrameType>> = Object.freeze({
  1: "data",
  2: "close",
});

/** ASCII-hex correlation shape (strict: 32 lowercase hex characters). */
const CORRELATION_RE = /^[0-9a-f]{32}$/;

/**
 * Pinned hard bounds. Frozen constants — a caller can exceed a bound (and be
 * refused) but can never redefine it. Aligned with the 26A TRANSPORT_BOUNDS
 * where the same quantity exists there (8192 B frames, 256/1000 ms window,
 * 30000 ms slow-sender gap) and with the 26B connection ceiling (16).
 */
export const FRAMED_TRANSPORT_BOUNDS = Object.freeze({
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

/**
 * Closed refusal vocabulary. One code per distinct law:
 * caller/config refusals (config/sink/clock/connections/encode), stream
 * refusals (magic/version/type/length/correlation), resource refusals
 * (buffer/flood), deadline refusals (read/write/idle), terminal-stream
 * refusals (truncated), and the pack-mandated write-after-close.
 */
export const FRAMED_TRANSPORT_REFUSAL_CODES = Object.freeze([
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
] as const);
export type FramedTransportRefusalCode = (typeof FRAMED_TRANSPORT_REFUSAL_CODES)[number];

/** Session lifecycle states (closed two-state vocabulary). */
export const FRAMED_SESSION_STATES = Object.freeze(["open", "closed"] as const);
export type FramedSessionState = (typeof FRAMED_SESSION_STATES)[number];

/** Local (caller-initiated) close reasons. */
export const FRAMED_LOCAL_CLOSE_CODES = Object.freeze([
  "local_close",
  "remote_close",
  "transport_shutdown",
] as const);
export type FramedLocalCloseCode = (typeof FRAMED_LOCAL_CLOSE_CODES)[number];

/** A session ends in exactly one code: a refusal, or a local close reason. */
export type FramedCloseCode = FramedTransportRefusalCode | FramedLocalCloseCode;

/** Deterministic explanation for every refusal code (closed, suite-pinned). */
export const REFUSAL_EXPLANATIONS: Readonly<Record<FramedTransportRefusalCode, string>> = Object.freeze({
  config_invalid: "framed-transport config is outside its pinned bounds or has unknown keys; refused, never clamped (no silent widening)",
  sink_invalid: "sink must expose write(chunk) -> boolean and destroy(); refused before any session exists",
  clock_invalid: "caller-supplied clock input must be a finite number; operation refused, session unchanged",
  connections_exceeded: "the pinned connection bound is reached; the new session is refused, never queued, never widened",
  session_closed: "the session is closed; a closed session never accepts further operations",
  write_after_close: "send refused after close; a closed session never reaches the sink again",
  chunk_invalid: "receive expects a Uint8Array/Buffer chunk; refused as a caller error, session unchanged",
  magic_refused: "frame magic mismatch at the buffer head; the stream is malformed and the session fails closed",
  version_refused: "frame version is not the pinned protocol version; unknown versions refuse with no upgrade or downgrade path here",
  type_refused: "frame type is outside the closed type vocabulary; unknown types refuse",
  declared_oversize_refused: "declared payload length exceeds the pinned frame bound; refused from the length word alone with no allocation and no wait for the body",
  correlation_refused: "the required correlation field is missing or not 32 lowercase hex characters; every frame must carry a valid correlation",
  buffer_exhausted: "buffered unread bytes would exceed the pinned bound; refusing instead of buffering (the consumer is not draining)",
  flood_refused: "the frames-per-window bound is already reached; flood refuses (frames/window is a hard bound, never widened)",
  read_deadline_exceeded: "a partial frame did not complete within the read deadline; the slow partial sender fails closed",
  write_deadline_exceeded: "the sink stayed backpressured beyond the write deadline; the stalled write path fails closed",
  idle_deadline_exceeded: "no byte activity within the idle deadline; the idle session fails closed",
  truncated_frame_refused: "the stream ended with an incomplete frame; the partial frame is rejected and never delivered",
  send_invalid_refused: "outbound frame failed validation (type, correlation, or payload shape); caller error, session unchanged",
  send_oversize_refused: "outbound payload exceeds the pinned payload bound; refused, never truncated or split",
});

/**
 * Closed shape for transport config. Every field is optional (defaults are
 * the pinned bounds) and every supplied value must be an integer in
 * [1, bound] — above-ceiling or malformed values refuse (`config_invalid`),
 * never clamp.
 */
export interface FramedTransportConfig {
  readonly maxConnections?: number;
  readonly readDeadlineMs?: number;
  readonly writeDeadlineMs?: number;
  readonly idleDeadlineMs?: number;
}

/** The admitted (effective) values a session is created with. */
export interface FramedAdmittedConfig {
  readonly maxConnections: number;
  readonly readDeadlineMs: number;
  readonly writeDeadlineMs: number;
  readonly idleDeadlineMs: number;
}

/** Deterministic config decision (26B discipline: ok + refusal + explanation + hash). */
export interface FramedTransportConfigDecision {
  readonly ok: boolean;
  readonly refusal: FramedTransportRefusalCode | null;
  readonly admitted: FramedAdmittedConfig;
  readonly explanation: string;
  readonly provenanceHash: string;
}

/** Known config keys (closed shape — unknown keys refuse). */
const KNOWN_CONFIG_KEYS: readonly string[] = [
  "maxConnections",
  "readDeadlineMs",
  "writeDeadlineMs",
  "idleDeadlineMs",
];

function isInvalidBoundValue(value: unknown, bound: number): boolean {
  return typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > bound;
}

/**
 * The deterministic config decision. Check order (first match wins, pinned):
 * closed-shape key scan -> maxConnections -> readDeadlineMs ->
 * writeDeadlineMs -> idleDeadlineMs. Unset fields take the pinned bound as
 * the default; a supplied-but-out-of-range field refuses.
 */
export function decideFramedTransportConfig(
  config?: FramedTransportConfig | null
): FramedTransportConfigDecision {
  const admitted: {
    maxConnections: number;
    readDeadlineMs: number;
    writeDeadlineMs: number;
    idleDeadlineMs: number;
  } = {
    maxConnections: FRAMED_TRANSPORT_BOUNDS.maxConnections,
    readDeadlineMs: FRAMED_TRANSPORT_BOUNDS.readDeadlineMs,
    writeDeadlineMs: FRAMED_TRANSPORT_BOUNDS.writeDeadlineMs,
    idleDeadlineMs: FRAMED_TRANSPORT_BOUNDS.idleDeadlineMs,
  };
  let refusal: FramedTransportRefusalCode | null = null;
  let explanation =
    "framed-transport config admitted: every value within its pinned ceiling (defaults are the bounds themselves)";
  if (config !== null && config !== undefined) {
    if (typeof config !== "object" || Array.isArray(config)) {
      refusal = "config_invalid";
      explanation = "framed-transport config must be an object literal of known keys; refused (fail closed)";
    } else {
      for (const key of Object.keys(config)) {
        if (!KNOWN_CONFIG_KEYS.includes(key)) {
          refusal = "config_invalid";
          explanation = `unknown config key \`${key}\` refused: the framed-transport config is a closed shape (no surprise widening)`;
          break;
        }
      }
      if (refusal === null) {
        const checks: ReadonlyArray<readonly [keyof FramedTransportConfig & string, number]> = [
          ["maxConnections", FRAMED_TRANSPORT_BOUNDS.maxConnections],
          ["readDeadlineMs", FRAMED_TRANSPORT_BOUNDS.readDeadlineMs],
          ["writeDeadlineMs", FRAMED_TRANSPORT_BOUNDS.writeDeadlineMs],
          ["idleDeadlineMs", FRAMED_TRANSPORT_BOUNDS.idleDeadlineMs],
        ];
        for (const [field, bound] of checks) {
          const supplied = (config as FramedTransportConfig)[field];
          if (supplied === undefined) continue;
          if (isInvalidBoundValue(supplied, bound)) {
            refusal = "config_invalid";
            explanation = `${field}=${String(supplied)} is outside [1, ${bound}]; refused, never clamped (no silent widening)`;
            break;
          }
          if (field === "maxConnections") admitted.maxConnections = supplied;
          else if (field === "readDeadlineMs") admitted.readDeadlineMs = supplied;
          else if (field === "writeDeadlineMs") admitted.writeDeadlineMs = supplied;
          else admitted.idleDeadlineMs = supplied;
        }
      }
    }
  }
  const frozenAdmitted = Object.freeze({ ...admitted });
  return Object.freeze({
    ok: refusal === null,
    refusal,
    admitted: frozenAdmitted,
    explanation,
    provenanceHash: canonicalHash({
      schema: FRAMED_TRANSPORT_SCHEMA_VERSION,
      ok: refusal === null,
      refusal,
      admitted: frozenAdmitted,
    }),
  });
}

// ── wire shapes and encoder ──────────────────────────────────────────────────

/**
 * The ONLY byte exit of a session. write() returns false for backpressure
 * (a normal condition tracked against the write deadline, not an error);
 * destroy() performs deterministic local teardown. Implemented by the
 * caller over a local socket — this module never builds a sink itself.
 */
export interface FramedSink {
  write(chunk: Uint8Array): boolean;
  destroy(): void;
}

/** A decoded inbound frame. Payload is opaque DATA — byte-identical, never interpreted. */
export interface FramedPayload {
  readonly type: FrameType;
  readonly correlationId: string;
  readonly payload: Uint8Array;
}

/** An outbound frame: type + required correlation + opaque payload. */
export interface FramedSendFrame {
  readonly type: FrameType;
  readonly correlationId: string;
  readonly payload: Uint8Array;
}

/** Result of encodeFrame. */
export type EncodeFrameResult =
  | { readonly ok: true; readonly bytes: Buffer; readonly frameBytes: number }
  | {
      readonly ok: false;
      readonly refusal: "send_invalid_refused" | "send_oversize_refused";
      readonly explanation: string;
    };

/**
 * Deterministic frame encoder (pure; no I/O, no randomness — identical
 * inputs always yield byte-identical output). Validation order (pinned):
 * shape -> type -> correlation -> payload shape -> payload size. The single
 * allocation happens only AFTER the payload length has passed the bound —
 * never allocate from an unchecked length.
 */
export function encodeFrame(frame: FramedSendFrame | null | undefined): EncodeFrameResult {
  if (frame === null || frame === undefined || typeof frame !== "object") {
    return {
      ok: false,
      refusal: "send_invalid_refused",
      explanation: "frame must be an object with type, correlationId, and payload",
    };
  }
  if (!FRAME_TYPES.includes(frame.type)) {
    return {
      ok: false,
      refusal: "send_invalid_refused",
      explanation: `outbound frame type ${String(frame.type)} is outside the closed type vocabulary {1=data,2=close}`,
    };
  }
  if (typeof frame.correlationId !== "string" || !CORRELATION_RE.test(frame.correlationId)) {
    return {
      ok: false,
      refusal: "send_invalid_refused",
      explanation: `outbound correlation must be exactly ${FRAME_CORRELATION_CHARS} lowercase hex characters (got ${
        typeof frame.correlationId === "string" ? String(frame.correlationId.length) + " chars" : typeof frame.correlationId
      })`,
    };
  }
  if (!(frame.payload instanceof Uint8Array)) {
    return {
      ok: false,
      refusal: "send_invalid_refused",
      explanation: "outbound payload must be a Uint8Array/Buffer of opaque bytes",
    };
  }
  if (frame.payload.length > FRAMED_TRANSPORT_BOUNDS.maxPayloadBytes) {
    return {
      ok: false,
      refusal: "send_oversize_refused",
      explanation: `outbound payload ${frame.payload.length} B > bound ${FRAMED_TRANSPORT_BOUNDS.maxPayloadBytes} B; refused, never truncated or split`,
    };
  }
  const bytes = Buffer.allocUnsafe(FRAME_HEADER_BYTES + frame.payload.length);
  bytes[0] = 0x4d;
  bytes[1] = 0x4e;
  bytes[2] = 0x4f;
  bytes[3] = 0x47;
  bytes.writeUInt8(FRAME_PROTOCOL_VERSION, 4);
  bytes.writeUInt8(FRAME_TYPE_CODES[frame.type], 5);
  bytes.writeUInt32BE(frame.payload.length, 6);
  bytes.write(frame.correlationId, 10, "ascii");
  bytes.set(frame.payload, FRAME_HEADER_BYTES);
  return Object.freeze({ ok: true as const, bytes, frameBytes: bytes.length });
}

// ── session results ──────────────────────────────────────────────────────────

/** A refusal result. `state` shows the session state AFTER the refusal. */
export interface FramedOperationRefusal {
  readonly ok: false;
  readonly refusal: FramedTransportRefusalCode;
  readonly explanation: string;
  readonly state: FramedSessionState;
}

/** receive() accepted a chunk (frames may still be waiting for more bytes). */
export interface FramedReceiveOk {
  readonly ok: true;
  readonly framesAccepted: number;
  readonly queuedFrames: number;
  readonly bufferedUnreadBytes: number;
}
export type ReceiveResult = FramedReceiveOk | FramedOperationRefusal;

/** send() handed bytes to the sink. */
export interface FramedSendOk {
  readonly ok: true;
  readonly bytesQueued: number;
  readonly backpressured: boolean;
}
export type SendResult = FramedSendOk | FramedOperationRefusal;

/** checkDeadlines() found every deadline within bound. */
export interface FramedDeadlinesOk {
  readonly ok: true;
  readonly code: "deadlines_ok";
}
export type DeadlinesResult = FramedDeadlinesOk | FramedOperationRefusal;

/** Backpressure cleared (idempotent; a closed session refuses). */
export interface FramedDrainOk {
  readonly ok: true;
  readonly code: "write_drained";
}
export type DrainResult = FramedDrainOk | FramedOperationRefusal;

/** Stream end processed: clean remote close, or an already-closed session. */
export interface FramedStreamCloseOk {
  readonly ok: true;
  readonly code: "remote_close" | "session_already_closed";
  readonly droppedFrames: number;
}
export type StreamCloseResult = FramedStreamCloseOk | FramedOperationRefusal;

/** Explicit close result — closing twice is a success, never an error. */
export interface FramedCloseOk {
  readonly ok: true;
  readonly code: "session_closed" | "session_already_closed";
  readonly state: "closed";
  readonly droppedFrames: number;
}
export type FramedLocalCloseArgument = "local_close" | "transport_shutdown";

// ── session ──────────────────────────────────────────────────────────────────

/**
 * One connection's framing state. Instances exist ONLY through
 * FramedTransport.openSession (the constructor is module-private), so the
 * connection bound cannot be bypassed. All clock inputs are caller-supplied;
 * the session itself never reads a clock or timer.
 */
export interface FramedSession {
  state(): FramedSessionState;
  /** The code that closed the session; null while open. */
  closeCode(): FramedCloseCode | null;
  /** Unparsed bytes held at the wire head (bounded). */
  bufferedUnreadBytes(): number;
  /** Frames decoded but not yet drained by read() (bounded). */
  queuedFrames(): number;
  /** Frames dropped across every close/fault (never delivered after close). */
  droppedFrames(): number;
  /**
   * Feed inbound bytes. Pinned check order: session_closed -> chunk_invalid
   * -> clock_invalid -> read deadline -> write deadline -> idle deadline ->
   * buffered-unread bound -> parse loop (magic -> version -> type -> length
   * bound -> correlation -> frame complete -> flood -> queue bound -> push).
   * Peer violations fault the session (closed, queue dropped, sink destroyed).
   */
  receive(chunk: Uint8Array, nowMs: number): ReceiveResult;
  /** Drain decoded frames (byte-opaque). Empty after any close or fault. */
  read(): readonly FramedPayload[];
  /**
   * Send one frame. write-after-close refuses before the sink; caller-side
   * encode refusals leave the session open; backpressure is tracked against
   * the write deadline.
   */
  send(frame: FramedSendFrame, nowMs: number): SendResult;
  /** Clear write backpressure (call on the local sink's drain signal). */
  notifyWriteDrained(): DrainResult;
  /** Explicit deadline probe: read -> write -> idle, first match wins. */
  checkDeadlines(nowMs: number): DeadlinesResult;
  /**
   * The local stream ended. An incomplete buffered frame faults the session
   * (truncated_frame_refused, never delivered); a clean end closes it as
   * remote_close. Idempotent.
   */
  notifyStreamClosed(nowMs: number): StreamCloseResult;
  /** Explicit, idempotent local close; every unread frame is dropped. */
  close(code?: FramedLocalCloseArgument): FramedCloseOk;
}

/** Empty shared buffer (never mutated). */
const EMPTY_BUFFER: Buffer = Buffer.alloc(0);

/**
 * Internal session implementation. NOT exported: every instance is created
 * by FramedTransport.openSession, which is what makes the connection bound
 * structural rather than advisory.
 */
class FramedSessionImpl implements FramedSession {
  readonly #sink: FramedSink;
  readonly #admitted: FramedAdmittedConfig;
  readonly #onClosed: (session: FramedSession) => void;
  #state: FramedSessionState = "open";
  #closeCode: FramedCloseCode | null = null;
  #wire: Buffer = EMPTY_BUFFER;
  #queue: FramedPayload[] = [];
  #queueBytes = 0;
  #droppedFrames = 0;
  #sinkAlive = true;
  #lastActivityMs: number;
  #partialSinceMs: number | null = null;
  #blockedSinceMs: number | null = null;
  #windowStartMs: number;
  #framesInWindow = 0;

  constructor(sink: FramedSink, admitted: FramedAdmittedConfig, onClosed: (session: FramedSession) => void, openedAtMs: number) {
    this.#sink = sink;
    this.#admitted = admitted;
    this.#onClosed = onClosed;
    this.#lastActivityMs = openedAtMs;
    this.#windowStartMs = openedAtMs;
  }

  state(): FramedSessionState {
    return this.#state;
  }
  closeCode(): FramedCloseCode | null {
    return this.#closeCode;
  }
  bufferedUnreadBytes(): number {
    return this.#wire.length;
  }
  queuedFrames(): number {
    return this.#queue.length;
  }
  droppedFrames(): number {
    return this.#droppedFrames;
  }
  read(): readonly FramedPayload[] {
    const out = this.#queue;
    this.#queue = [];
    this.#queueBytes = 0;
    return Object.freeze(out);
  }

  #refusal(code: FramedTransportRefusalCode, explanation: string): FramedOperationRefusal {
    return Object.freeze({ ok: false as const, refusal: code, explanation, state: this.#state });
  }

  /** Terminal transition: drop every unread frame, kill the sink exactly once, release the slot. */
  #shutdown(code: FramedCloseCode): number {
    const dropped = this.#queue.length;
    this.#droppedFrames += dropped;
    this.#queue = [];
    this.#queueBytes = 0;
    this.#wire = EMPTY_BUFFER;
    this.#partialSinceMs = null;
    this.#blockedSinceMs = null;
    this.#state = "closed";
    this.#closeCode = code;
    if (this.#sinkAlive) {
      this.#sinkAlive = false;
      try {
        this.#sink.destroy();
      } catch {
        // OS-handle teardown is best effort; the session state change is authoritative.
      }
    }
    this.#onClosed(this);
    return dropped;
  }

  #fault(code: FramedTransportRefusalCode, explanation: string): FramedOperationRefusal {
    this.#shutdown(code);
    return this.#refusal(code, explanation);
  }

  /** Shared entry checks (clock -> read -> write -> idle), first match wins and faults. */
  #preCheck(nowMs: number): FramedOperationRefusal | null {
    if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
      return this.#refusal("clock_invalid", "clock input must be a finite number; operation refused, session unchanged");
    }
    if (this.#partialSinceMs !== null && nowMs - this.#partialSinceMs > this.#admitted.readDeadlineMs) {
      return this.#fault(
        "read_deadline_exceeded",
        `partial frame incomplete for ${nowMs - this.#partialSinceMs} ms > read deadline ${this.#admitted.readDeadlineMs} ms — slow partial sender refused (fail closed)`
      );
    }
    if (this.#blockedSinceMs !== null && nowMs - this.#blockedSinceMs > this.#admitted.writeDeadlineMs) {
      return this.#fault(
        "write_deadline_exceeded",
        `sink backpressured for ${nowMs - this.#blockedSinceMs} ms > write deadline ${this.#admitted.writeDeadlineMs} ms — stalled write path refused (fail closed)`
      );
    }
    if (nowMs - this.#lastActivityMs > this.#admitted.idleDeadlineMs) {
      return this.#fault(
        "idle_deadline_exceeded",
        `no byte activity for ${nowMs - this.#lastActivityMs} ms > idle deadline ${this.#admitted.idleDeadlineMs} ms — idle session refused (fail closed)`
      );
    }
    return null;
  }

  receive(chunk: Uint8Array, nowMs: number): ReceiveResult {
    if (this.#state === "closed") {
      return this.#refusal("session_closed", "receive refused: the session is closed; a closed session never accepts bytes");
    }
    if (!(chunk instanceof Uint8Array)) {
      return this.#refusal("chunk_invalid", "receive expects a Uint8Array/Buffer chunk; refused as a caller error, session unchanged");
    }
    const early = this.#preCheck(nowMs);
    if (early !== null) return early;
    const wouldBuffer = this.#wire.length + chunk.length;
    if (wouldBuffer > FRAMED_TRANSPORT_BOUNDS.maxBufferedUnreadBytes) {
      return this.#fault(
        "buffer_exhausted",
        `buffered unread would reach ${wouldBuffer} B > bound ${FRAMED_TRANSPORT_BOUNDS.maxBufferedUnreadBytes} B — refusing before buffering a single byte (no unbounded accumulation)`
      );
    }
    // One copy of ACTUAL received bytes (bounded above) — never of a declared length.
    const incoming = Buffer.from(chunk);
    this.#wire = this.#wire.length === 0 ? incoming : Buffer.concat([this.#wire, incoming]);
    let rest = this.#wire;
    let accepted = 0;
    let completed = false;
    for (;;) {
      if (rest.length < 4) break;
      if (rest[0] !== 0x4d || rest[1] !== 0x4e || rest[2] !== 0x4f || rest[3] !== 0x47) {
        return this.#fault("magic_refused", "frame magic mismatch at the buffer head; the stream is malformed and the session fails closed");
      }
      if (rest.length < 5) break;
      const version = rest.readUInt8(4);
      if (version !== FRAME_PROTOCOL_VERSION) {
        return this.#fault(
          "version_refused",
          `frame version ${version} != pinned version ${FRAME_PROTOCOL_VERSION}; unknown versions refuse (no upgrade or downgrade path at this layer)`
        );
      }
      if (rest.length < 6) break;
      const frameType = FRAME_TYPE_FROM_CODE[rest.readUInt8(5)];
      if (frameType === undefined) {
        return this.#fault(
          "type_refused",
          `unknown frame type ${rest.readUInt8(5)}; the closed type vocabulary is {1=data,2=close} and unknown types refuse`
        );
      }
      if (rest.length < 10) break;
      const declared = rest.readUInt32BE(6);
      if (declared > FRAMED_TRANSPORT_BOUNDS.maxPayloadBytes) {
        return this.#fault(
          "declared_oversize_refused",
          `declared payload length ${declared} B > bound ${FRAMED_TRANSPORT_BOUNDS.maxPayloadBytes} B — refused from the length word alone; no allocation, no wait for the body`
        );
      }
      if (rest.length < FRAME_HEADER_BYTES) break;
      const correlationId = rest.subarray(10, FRAME_HEADER_BYTES).toString("utf8");
      if (!CORRELATION_RE.test(correlationId)) {
        return this.#fault(
          "correlation_refused",
          `required correlation is not exactly ${FRAME_CORRELATION_CHARS} lowercase hex characters; every frame must carry a valid correlation`
        );
      }
      const totalBytes = FRAME_HEADER_BYTES + declared;
      if (rest.length < totalBytes) break;
      if (nowMs - this.#windowStartMs >= FRAMED_TRANSPORT_BOUNDS.frameWindowMs) {
        this.#windowStartMs = nowMs;
        this.#framesInWindow = 0;
      }
      if (this.#framesInWindow >= FRAMED_TRANSPORT_BOUNDS.maxFramesPerWindow) {
        return this.#fault(
          "flood_refused",
          `frame window already holds ${FRAMED_TRANSPORT_BOUNDS.maxFramesPerWindow} frames within ${FRAMED_TRANSPORT_BOUNDS.frameWindowMs} ms — flood refuses; frames/window is a hard bound`
        );
      }
      if (this.#queueBytes + totalBytes > FRAMED_TRANSPORT_BOUNDS.maxBufferedUnreadBytes) {
        return this.#fault(
          "buffer_exhausted",
          `unread queue would hold ${this.#queueBytes + totalBytes} B > bound ${FRAMED_TRANSPORT_BOUNDS.maxBufferedUnreadBytes} B — the consumer is not draining; refusing instead of buffering`
        );
      }
      const payload = Buffer.from(rest.subarray(FRAME_HEADER_BYTES, totalBytes));
      this.#framesInWindow += 1;
      this.#queue.push({ type: frameType, correlationId, payload });
      this.#queueBytes += totalBytes;
      accepted += 1;
      completed = true;
      rest = rest.subarray(totalBytes);
    }
    this.#wire = rest.length > 0 ? Buffer.from(rest) : EMPTY_BUFFER;
    if (this.#wire.length > 0) {
      if (completed || this.#partialSinceMs === null) this.#partialSinceMs = nowMs;
    } else {
      this.#partialSinceMs = null;
    }
    if (chunk.length > 0) this.#lastActivityMs = nowMs;
    return Object.freeze({
      ok: true as const,
      framesAccepted: accepted,
      queuedFrames: this.#queue.length,
      bufferedUnreadBytes: this.#wire.length,
    });
  }

  send(frame: FramedSendFrame, nowMs: number): SendResult {
    if (this.#state === "closed") {
      return this.#refusal("write_after_close", "send refused after close; a closed session never reaches the sink");
    }
    const early = this.#preCheck(nowMs);
    if (early !== null) return early;
    const encoded = encodeFrame(frame);
    if (!encoded.ok) {
      return this.#refusal(encoded.refusal, encoded.explanation);
    }
    const accepted = this.#sink.write(encoded.bytes);
    if (accepted) {
      this.#blockedSinceMs = null;
    } else if (this.#blockedSinceMs === null) {
      this.#blockedSinceMs = nowMs;
    }
    this.#lastActivityMs = nowMs;
    return Object.freeze({ ok: true as const, bytesQueued: encoded.frameBytes, backpressured: !accepted });
  }

  notifyWriteDrained(): DrainResult {
    if (this.#state === "closed") {
      return this.#refusal("session_closed", "drain notice refused: the session is closed");
    }
    this.#blockedSinceMs = null;
    return Object.freeze({ ok: true as const, code: "write_drained" as const });
  }

  checkDeadlines(nowMs: number): DeadlinesResult {
    if (this.#state === "closed") {
      return this.#refusal("session_closed", "deadline check refused: the session is closed");
    }
    const early = this.#preCheck(nowMs);
    if (early !== null) return early;
    return Object.freeze({ ok: true as const, code: "deadlines_ok" as const });
  }

  notifyStreamClosed(nowMs: number): StreamCloseResult {
    if (this.#state === "closed") {
      return Object.freeze({ ok: true as const, code: "session_already_closed" as const, droppedFrames: 0 });
    }
    if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
      return this.#refusal("clock_invalid", "clock input must be a finite number; operation refused, session unchanged");
    }
    if (this.#wire.length > 0) {
      return this.#fault(
        "truncated_frame_refused",
        `stream ended with ${this.#wire.length} B of an incomplete frame buffered; the partial frame is rejected and never delivered`
      );
    }
    const dropped = this.#shutdown("remote_close");
    return Object.freeze({ ok: true as const, code: "remote_close" as const, droppedFrames: dropped });
  }

  close(code: FramedLocalCloseArgument = "local_close"): FramedCloseOk {
    if (this.#state === "closed") {
      return Object.freeze({ ok: true as const, code: "session_already_closed" as const, state: "closed" as const, droppedFrames: 0 });
    }
    const dropped = this.#shutdown(code);
    return Object.freeze({ ok: true as const, code: "session_closed" as const, state: "closed" as const, droppedFrames: dropped });
  }
}

// ── transport host ───────────────────────────────────────────────────────────

/** Result of openSession. */
export type OpenSessionResult =
  | { readonly ok: true; readonly session: FramedSession }
  | {
      readonly ok: false;
      readonly refusal: "config_invalid" | "sink_invalid" | "clock_invalid" | "connections_exceeded";
      readonly explanation: string;
    };

/** Result of closeAll — idempotent like every close in this stack. */
export interface CloseAllResult {
  readonly ok: true;
  readonly code: "transport_closed" | "transport_already_closed";
  readonly closedSessions: number;
}

/**
 * The framed-transport host: frozen config decision + the connections bound.
 * Sessions are opened ONLY here, so `maxConnections` is structurally
 * enforced (the session class is module-private). closeAll() is the
 * deterministic cleanup: every session closed as transport_shutdown, sink
 * destroyed once each, idempotent on a second call.
 */
export class FramedTransport {
  readonly #decision: FramedTransportConfigDecision;
  readonly #sessions = new Set<FramedSession>();

  constructor(config?: FramedTransportConfig | null) {
    this.#decision = decideFramedTransportConfig(config ?? undefined);
  }

  /** The frozen decision for this transport's config (pure, computed once). */
  decision(): FramedTransportConfigDecision {
    return this.#decision;
  }

  /** Number of currently open sessions (each counts one connection). */
  activeConnections(): number {
    return this.#sessions.size;
  }

  /**
   * Open a framed session over a caller-supplied local sink. Check order
   * (pinned): config_invalid -> sink_invalid -> clock_invalid ->
   * connections_exceeded. A refusal NEVER creates a session.
   */
  openSession(sink: FramedSink, nowMs: number): OpenSessionResult {
    if (!this.#decision.ok) {
      return Object.freeze({
        ok: false as const,
        refusal: "config_invalid" as const,
        explanation: `transport config refused at construction: ${this.#decision.explanation}`,
      });
    }
    if (
      sink === null ||
      sink === undefined ||
      typeof sink !== "object" ||
      typeof sink.write !== "function" ||
      typeof sink.destroy !== "function"
    ) {
      return Object.freeze({
        ok: false as const,
        refusal: "sink_invalid" as const,
        explanation: "sink must expose write(chunk) -> boolean and destroy(); refused before any session exists",
      });
    }
    if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
      return Object.freeze({
        ok: false as const,
        refusal: "clock_invalid" as const,
        explanation: "openedAt clock must be a finite number; refused (caller error, no session created)",
      });
    }
    if (this.#sessions.size >= this.#decision.admitted.maxConnections) {
      return Object.freeze({
        ok: false as const,
        refusal: "connections_exceeded" as const,
        explanation: `connection bound ${this.#decision.admitted.maxConnections} already reached; the new session is refused, never queued, never widened`,
      });
    }
    const session = new FramedSessionImpl(sink, this.#decision.admitted, (s) => {
      this.#sessions.delete(s);
    }, nowMs);
    this.#sessions.add(session);
    return Object.freeze({ ok: true as const, session });
  }

  /** Deterministic, idempotent cleanup: closes every open session at once. */
  closeAll(): CloseAllResult {
    const sessions = [...this.#sessions];
    if (sessions.length === 0) {
      return Object.freeze({ ok: true as const, code: "transport_already_closed" as const, closedSessions: 0 });
    }
    for (const session of sessions) {
      session.close("transport_shutdown");
    }
    return Object.freeze({ ok: true as const, code: "transport_closed" as const, closedSessions: sessions.length });
  }
}


