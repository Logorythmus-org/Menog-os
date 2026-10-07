/**
 * PHASE 26B — Governed Local Network Transport: Endpoint/Listener Boundary
 * (SMALLEST EXPLICIT LOCAL LISTENER / DEFAULT NO LISTENER / FAIL CLOSED).
 *
 * This module is the first REAL socket surface in Phase-26: the smallest
 * explicit LOCAL endpoint/listener boundary. Everything above it stays pure;
 * everything below these decisions is OS binding only. The module enforces,
 * each point enforced structurally below and by the suite:
 *
 *   - DEFAULT NO LISTENER: absent config refuses (`endpoint_unset`);
 *     construction binds nothing; only start() may open a port.
 *   - ALLOW ONLY: numeric loopback (127.0.0.0/8, ::1) and explicitly
 *     configured private numeric addresses (RFC1918, fc00::/7 ULA).
 *   - REFUSE: wildcard 0.0.0.0/:: (any spelling, plus `*`/`[::]`),
 *     public/global, unspecified/empty, ambiguous hostname, non-numeric or
 *     malformed numeric literals, zone/scope ids (interface selection),
 *     discovery-derived endpoints, environment-sourced endpoints, automatic
 *     interface selection — each with its own closed refusal code.
 *   - BOUNDS: port [1024, 65535] (integer), connections <= 16, queue/backlog
 *     <= 64 — exceeding a bound refuses, never clamps (no silent widening).
 *   - EXPLICIT LIFECYCLE: start() refuses double-start; stop() is
 *     IDEMPOTENT (`not_listening` is a success, never an error); cleanup
 *     destroys every tracked connection and releases the port deterministically.
 *   - NO SHELL/CHILD/ENV/PROXY: the module imports ONLY `node:net`
 *     (server side) + the frozen canonical hash; it never reads the
 *     environment, never spawns, never forwards a byte to a second hop,
 *     never reconfigures remotely (config frozen at construction; there are
 *     no setters).
 *
 * HARD LAW: NETWORK REACHABILITY != IDENTITY != ADMISSION != AUTHORITY !=
 * EXECUTION. A bound local port proves NOTHING else: no identity, no
 * admission, no authority, no execution. Remote input never enters this
 * module; every connection handled here is untrusted raw bytes that only a
 * later governed gate (26C+ framing) may interpret.
 *
 * Provenance discipline (as 26A): every decision is a pure function of
 * caller-supplied facts, carries a deterministic explanation, and embeds a
 * canonical provenance hash. No wall-clock, no randomness, no I/O in
 * decideLocalEndpoint().
 */
import { createServer, type Server, type Socket } from "node:net";
import { canonicalHash } from "./canonical.js";

/** Closed schema version for the endpoint/listener boundary contract. */
export const ENDPOINT_BOUNDARY_SCHEMA_VERSION = "menog-endpoint-boundary/v0" as const;

/**
 * Closed address-class vocabulary. Only the four allow-listed classes may
 * ever be admitted; the remaining classes exist so every refusal names the
 * exact shape of what was rejected.
 */
export const ENDPOINT_ADDRESS_CLASSES = Object.freeze([
  "ipv4_loopback",
  "ipv6_loopback",
  "ipv4_private",
  "ipv6_ula",
  "ipv4_public",
  "ipv6_public",
  "ipv4_nonlocal",
  "ipv6_nonlocal",
  "wildcard",
  "unspecified",
  "hostname",
  "malformed",
] as const);

/** Type of the closed address-class vocabulary. */
export type EndpointAddressClass = (typeof ENDPOINT_ADDRESS_CLASSES)[number];

/**
 * Closed refusal vocabulary. One code per distinct boundary law — provenance
 * refusals (discovery/environment/auto-interface), content refusals
 * (wildcard/unspecified/public/nonlocal/hostname/malformed), and bound
 * refusals (port/connections/queue). Refusals never widen, never fall back,
 * never retry on a different endpoint.
 */
export const ENDPOINT_REFUSAL_CODES = Object.freeze([
  "endpoint_unset",
  "discovery_refused",
  "environment_refused",
  "auto_interface_refused",
  "wildcard_refused",
  "unspecified_refused",
  "public_refused",
  "nonlocal_refused",
  "hostname_refused",
  "malformed_refused",
  "port_invalid",
  "connections_invalid",
  "queue_invalid",
] as const);

/** Type of the closed refusal vocabulary. */
export type EndpointRefusalCode = (typeof ENDPOINT_REFUSAL_CODES)[number];

/**
 * Closed config-provenance vocabulary. ONLY `explicit_local_config` admits.
 * `environment` = env surprise widening; `discovery` = discovery-derived
 * endpoint; `auto_interface` = automatic interface selection. The module
 * reads no environment itself — these refusals exist so a CALLER that
 * assembled config from any non-explicit source is refused at this boundary.
 */
export const ENDPOINT_CONFIG_SOURCES = Object.freeze([
  "explicit_local_config",
  "environment",
  "discovery",
  "auto_interface",
] as const);

/** Type of the closed config-provenance vocabulary. */
export type EndpointConfigSource = (typeof ENDPOINT_CONFIG_SOURCES)[number];

/**
 * Pinned bounds. Port floor 1024 = no privileged-port binds (least
 * privilege); connections/queue ceilings are small and explicit. A config
 * above any ceiling is REFUSED (`*_invalid`) — bounds are never clamped,
 * because clamping would be a silent fallback.
 */
export const ENDPOINT_BOUNDS = Object.freeze({
  portMin: 1024,
  portMax: 65535,
  connectionsMax: 16,
  queueMax: 64,
  defaultConnections: 4,
  defaultQueue: 16,
});

/** Closed listener lifecycle states (two states; no hidden third state). */
export const LISTENER_STATES = Object.freeze(["stopped", "listening"] as const);

/** Type of the closed listener lifecycle. */
export type ListenerState = (typeof LISTENER_STATES)[number];

/**
 * The ONE sanctioned connection handler for a local listener. It receives a
 * socket the listener itself accepted on the decided endpoint; it grants no
 * trust, names no peer, and is untrusted raw input to whatever it wires up.
 */
export type EndpointConnectionHandler = (socket: Socket) => void;

/**
 * Caller-supplied endpoint configuration. MUST carry
 * `source: "explicit_local_config"` — any other provenance refuses.
 * Absent config (or absent source) is the DEFAULT: no listener.
 */
export interface EndpointConfig {
  readonly source?: EndpointConfigSource;
  readonly host?: string;
  readonly port?: number;
  readonly connections?: number;
  readonly queue?: number;
}

/**
 * The endpoint decision. Mirrors the 26A shape: every branch carries a
 * deterministic explanation and a canonical provenance hash; admitted
 * decisions carry the pinned bounds actually in force.
 */
export type EndpointDecision =
  | {
      readonly ok: true;
      readonly code: "endpoint_admitted";
      readonly addressClass: EndpointAddressClass;
      readonly host: string;
      readonly port: number;
      readonly connections: number;
      readonly queue: number;
      readonly explanation: string;
      readonly provenanceHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "endpoint_refused";
      readonly refusal: EndpointRefusalCode;
      readonly addressClass: EndpointAddressClass;
      readonly explanation: string;
      readonly provenanceHash: string;
    };

// ── strict numeric parsing (no normalization, no guessing) ──────────────────

/** Strict IPv4: exactly 4 dot-separated parts, no leading zeros, <= 255. */
function parseIPv4(host: string): number[] | null {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    out.push(value);
  }
  return out;
}

/** Strict IPv6: hex groups, at most one `::`, no embedded IPv4, no zone. */
function parseIPv6(host: string): number[][] | null {
  const halves = host.split("::");
  if (halves.length > 2) return null;
  const side = (text: string): number[][] | null => {
    if (text === "") return [];
    const groups: number[][] = [];
    for (const group of text.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
      groups.push([parseInt(group, 16)]);
    }
    return groups;
  };
  if (halves.length === 1) {
    const groups = side(halves[0] ?? "");
    if (groups === null || groups.length !== 8) return null;
    return groups;
  }
  const left = side(halves[0] ?? "");
  const right = side(halves[1] ?? "");
  if (left === null || right === null) return null;
  // `::` must elide at least one group, never more than seven.
  if (left.length + right.length > 7) return null;
  const zeros: number[][] = [];
  for (let i = 0; i < 8 - left.length - right.length; i += 1) zeros.push([0]);
  return [...left, ...zeros, ...right];
}

/** True when every IPv6 group is zero — the FULL-form wildcard `::`. */
function isAllZero(groups: number[][]): boolean {
  return groups.every((groups2) => groups2.every((value) => value === 0));
}

/** RFC1918 check (IPv4 private). */
function isRFC1918(octets: number[]): boolean {
  const a = octets[0] ?? -1;
  const b = octets[1] ?? -1;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

/**
 * Deterministic classification of a raw host string into the closed address
 * class vocabulary. Pure; never resolves, never normalizes: an input that is
 * not an exact numeric literal lands in `hostname` or `malformed`.
 */
export function classifyEndpointHost(host: string): EndpointAddressClass {
  if (host === "") return "unspecified";
  // Exact wildcard spellings first — 0.0.0.0, ::, [::], * (and full-form 0:0:…:0).
  if (host === "0.0.0.0" || host === "::" || host === "[::]" || host === "*") return "wildcard";
  if (host.includes("%")) return "malformed"; // zone/scope id = interface selection
  if (/^[0-9.]+$/.test(host)) {
    const octets = parseIPv4(host);
    if (octets === null) return "malformed";
    if (octets[0] === 127) return "ipv4_loopback";
    if (isRFC1918(octets)) return "ipv4_private";
    if (octets[0] === 0) return "wildcard"; // 0.x.x.x = "this network"/unspecified space
    if (octets[0] === 169 && octets[1] === 254) return "ipv4_nonlocal"; // link-local
    if (octets[0] === 224 || octets[0] === 255) return "ipv4_nonlocal"; // multicast/broadcast
    return "ipv4_public";
  }
  if (/^[0-9a-fA-F:.]+$/.test(host) && host.includes(":")) {
    const groups = parseIPv6(host);
    if (groups === null) return "malformed";
    if (isAllZero(groups)) return "wildcard";
    const g0 = groups[0]?.[0] ?? 0;
    const g1 = groups[1]?.[0] ?? 0;
    const last = groups[7]?.[0] ?? 0;
    if (g0 === 0 && g1 === 0 && last === 1 && groups.slice(0, 7).every((gr) => gr[0] === 0)) return "ipv6_loopback";
    if ((g0 & 0xfe00) === 0xfc00) return "ipv6_ula"; // fc00::/7 unique-local
    if ((g0 & 0xffc0) === 0xfe80) return "ipv6_nonlocal"; // fe80::/10 link-local
    if ((g0 & 0xff00) === 0xff00) return "ipv6_nonlocal"; // ff00::/8 multicast
    return "ipv6_public";
  }
  // Anything else: letters, dashes, spaces, brackets, empty-ish → hostname
  // (ambiguous name; discovery-derived names belong here and never resolve).
  return "hostname";
}

/** Explanation table — one deterministic sentence per refusal code. */
const REFUSAL_EXPLANATIONS: Readonly<Record<EndpointRefusalCode, string>> = Object.freeze({
  endpoint_unset: "no endpoint configuration supplied; default is NO LISTENER (fail closed)",
  discovery_refused: "endpoint is discovery-derived; only explicit local configuration may bind",
  environment_refused: "endpoint is environment-sourced; env surprise widening is refused",
  auto_interface_refused: "automatic interface selection is refused; the address must be explicit and numeric",
  wildcard_refused: "wildcard/unspecified bind address (0.0.0.0 / :: / * / [::]) refused; LOCAL NETWORK ONLY binds an explicit numeric address",
  unspecified_refused: "empty or unspecified address refused; no interface may be chosen implicitly",
  public_refused: "public/global address refused; LOCAL NETWORK ONLY — loopback and explicitly configured private addresses only",
  nonlocal_refused: "non-local address class (link-local, multicast, broadcast, zone-scoped) refused",
  hostname_refused: "non-numeric or ambiguous hostname refused; names are never resolved at this boundary",
  malformed_refused: "malformed numeric literal refused (strict IPv4/IPv6 grammar; no normalization is attempted)",
  port_invalid: `port must be an integer in [${ENDPOINT_BOUNDS.portMin}, ${ENDPOINT_BOUNDS.portMax}]`,
  connections_invalid: `connections bound must be an integer in [1, ${ENDPOINT_BOUNDS.connectionsMax}]`,
  queue_invalid: `queue bound must be an integer in [1, ${ENDPOINT_BOUNDS.queueMax}]`,
});

/**
 * Runtime-safe wrapper: a non-string host (possible from non-TS callers)
 * classifies as `malformed` instead of throwing — fail closed, never crash.
 */
function classifyHostValue(host: unknown): EndpointAddressClass {
  return typeof host === "string" ? classifyEndpointHost(host) : "malformed";
}

/** The allow-listed classes — the ONLY classes that may ever bind. */
const ADMITTABLE: ReadonlySet<EndpointAddressClass> = new Set<EndpointAddressClass>([
  "ipv4_loopback",
  "ipv6_loopback",
  "ipv4_private",
  "ipv6_ula",
]);

/** Helper: build a deterministic refusal branch (explanation + hash included). */
function refuse(
  refusal: EndpointRefusalCode,
  addressClass: EndpointAddressClass,
  facts: Readonly<Record<string, unknown>>
): EndpointDecision {
  const explanation = REFUSAL_EXPLANATIONS[refusal];
  return Object.freeze({
    ok: false as const,
    code: "endpoint_refused" as const,
    refusal,
    addressClass,
    explanation,
    provenanceHash: canonicalHash({ code: "endpoint_refused", refusal, addressClass, explanation, ...facts }),
  });
}

/**
 * The single deterministic endpoint decision. Order is pinned:
 *   1. config present at all?          → endpoint_unset
 *   2. provenance must be explicit     → discovery/environment/auto_interface
 *   3. address class (strict grammar)  → wildcard/unspecified/public/nonlocal/hostname/malformed
 *   4. class must be admissible        → public_refused (via REFUSAL table)
 *   5. port bound                      → port_invalid
 *   6. connections bound               → connections_invalid
 *   7. queue bound                     → queue_invalid
 *   8. otherwise ADMIT with bounds in force.
 * No branch retries, widens, clamps, or falls back.
 */
export function decideEndpoint(config: EndpointConfig | null | undefined): EndpointDecision {
  if (config === null || config === undefined) return refuse("endpoint_unset", "unspecified", { stage: "absent" });
  if (config.source === undefined || config.host === undefined) {
    return refuse("endpoint_unset", "unspecified", { stage: "incomplete", source: config.source ?? null, host: config.host ?? null });
  }
  if (config.source === "discovery") return refuse("discovery_refused", classifyHostValue(config.host), { stage: "provenance" });
  if (config.source === "environment") return refuse("environment_refused", classifyHostValue(config.host), { stage: "provenance" });
  if (config.source === "auto_interface") return refuse("auto_interface_refused", classifyHostValue(config.host), { stage: "provenance" });
  if (config.source !== "explicit_local_config") {
    // Fail closed on ANY unrecognized provenance (possible from non-TS callers):
    // unknown provenance is not explicit config, so the default (no listener) holds.
    return refuse("endpoint_unset", "unspecified", { stage: "provenance_unknown", source: String(config.source) });
  }
  if (typeof config.host !== "string") return refuse("malformed_refused", "malformed", { stage: "address", host: typeof config.host });
  const addressClass = classifyEndpointHost(config.host);
  if (addressClass === "wildcard") return refuse("wildcard_refused", addressClass, { stage: "address" });
  if (addressClass === "unspecified") return refuse("unspecified_refused", addressClass, { stage: "address" });
  if (addressClass === "hostname") return refuse("hostname_refused", addressClass, { stage: "address" });
  if (addressClass === "malformed") return refuse("malformed_refused", addressClass, { stage: "address" });
  if (addressClass === "ipv4_public" || addressClass === "ipv6_public") return refuse("public_refused", addressClass, { stage: "address" });
  if (addressClass === "ipv4_nonlocal" || addressClass === "ipv6_nonlocal") return refuse("nonlocal_refused", addressClass, { stage: "address" });
  if (!ADMITTABLE.has(addressClass)) return refuse("public_refused", addressClass, { stage: "address" }); // unreachable; belt
  const port = config.port;
  if (typeof port !== "number" || !Number.isInteger(port) || port < ENDPOINT_BOUNDS.portMin || port > ENDPOINT_BOUNDS.portMax) {
    return refuse("port_invalid", addressClass, { stage: "port", port: typeof port === "number" ? port : null });
  }
  const connections = config.connections ?? ENDPOINT_BOUNDS.defaultConnections;
  if (!Number.isInteger(connections) || connections < 1 || connections > ENDPOINT_BOUNDS.connectionsMax) {
    return refuse("connections_invalid", addressClass, { stage: "connections", connections });
  }
  const queue = config.queue ?? ENDPOINT_BOUNDS.defaultQueue;
  if (!Number.isInteger(queue) || queue < 1 || queue > ENDPOINT_BOUNDS.queueMax) {
    return refuse("queue_invalid", addressClass, { stage: "queue", queue });
  }
  const explanation = `endpoint admitted: ${addressClass} numeric local address, explicit port ${port}, connections<=${connections}, queue<=${queue}`;
  return Object.freeze({
    ok: true as const,
    code: "endpoint_admitted" as const,
    addressClass,
    host: config.host,
    port,
    connections,
    queue,
    explanation,
    provenanceHash: canonicalHash({ code: "endpoint_admitted", addressClass, host: config.host, port, connections, queue, explanation }),
  });
}

// ── the smallest explicit LOCAL listener ────────────────────────────────────

/** Closed start() outcome codes. */
export const LISTENER_START_CODES = Object.freeze([
  "listener_started",
  "listener_already_listening",
  "listener_bind_failed",
  "listener_start_aborted",
] as const);

/** Type of the closed start() outcomes. */
export type ListenerStartCode = (typeof LISTENER_START_CODES)[number];

/** Closed stop() outcome codes — BOTH are successes (idempotent close). */
export const LISTENER_STOP_CODES = Object.freeze([
  "listener_stopped",
  "listener_already_stopped",
] as const);

/** Type of the closed stop() outcomes. */
export type ListenerStopCode = (typeof LISTENER_STOP_CODES)[number];

/** Result of start(): either an admitted listener, or a deterministic refusal. */
export type ListenerStartResult =
  | { readonly ok: true; readonly code: "listener_started"; readonly state: "listening"; readonly decision: EndpointDecision; readonly explanation: string }
  | { readonly ok: false; readonly code: ListenerStartCode | "endpoint_refused"; readonly state: ListenerState; readonly decision: EndpointDecision | null; readonly refusal: EndpointRefusalCode | null; readonly explanation: string };

/** Result of stop(): always ok — closing an already-stopped listener is success. */
export type ListenerStopResult =
  | { readonly ok: true; readonly code: ListenerStopCode; readonly state: "stopped"; readonly closedConnections: number; readonly explanation: string };

/**
 * The smallest explicit LOCAL endpoint/listener boundary.
 *
 * - Default NO LISTENER: construction binds nothing; only start() can.
 * - start() re-decides the frozen config through decideEndpoint() every call;
 *   a refusal returns WITHOUT touching `node:net` at all.
 * - The config is frozen at construction — there is no setter, no remote
 *   reconfiguration, no environment read, no forwarding path: the server
 *   accepts connections, counts them against the pinned bound, and holds
 *   them as untrusted raw sockets for a later governed gate to interpret.
 * - stop() is idempotent and deterministic: it destroys every tracked
 *   socket, closes the server, and releases the port. A second stop() on a
 *   stopped listener is a SUCCESS (`listener_already_stopped`).
 */
export class LocalEndpointListener {
  readonly #config: Readonly<EndpointConfig>;
  readonly #decision: EndpointDecision;
  readonly #sockets = new Set<Socket>();
  #server: Server | null = null;
  #state: ListenerState = "stopped";
  #pending = false;
  /** Monotone operation epoch: stop() bumps it so a pending start() detects the abort. */
  #epoch = 0;
  #onConnection: EndpointConnectionHandler | null = null;

  constructor(config: EndpointConfig | null | undefined) {
    this.#config = Object.freeze({ ...(config ?? {}) });
    this.#decision = decideEndpoint(this.#config);
  }

  /** The frozen decision for this listener's config (pure, recomputed at construction only). */
  decision(): EndpointDecision {
    return this.#decision;
  }

  /** Current lifecycle state — closed two-state vocabulary. */
  state(): ListenerState {
    return this.#state;
  }

  /**
   * Register the ONE sanctioned connection handler (Phase 26H). It is a
   * separate method rather than a config field so the frozen closed
   * `EndpointConfig` shape is unchanged, and it fires only for connections
   * this listener accepted on its decided endpoint. Passing null clears it.
   */
  public onConnection(handler: EndpointConnectionHandler | null): void {
    this.#onConnection = handler;
  }

  /** Number of tracked (accepted, not yet closed) connections. */
  activeConnections(): number {
    return this.#sockets.size;
  }

  /**
   * Explicit start. A non-admitted decision refuses with NO socket created;
   * a second start refuses (`listener_already_listening`); an OS bind error
   * refuses (`listener_bind_failed`) — never retries, never widens the port
   * or address to "whatever is free".
   */
  async start(): Promise<ListenerStartResult> {
    if (this.#state === "listening" || this.#pending) {
      return Object.freeze({
        ok: false as const,
        code: "listener_already_listening" as const,
        state: this.#state,
        decision: this.#decision,
        refusal: null,
        explanation: "listener is already listening or starting; explicit stop() is required before another start()",
      });
    }
    if (!this.#decision.ok) {
      return Object.freeze({
        ok: false as const,
        code: "endpoint_refused" as const,
        state: this.#state,
        decision: this.#decision,
        refusal: this.#decision.refusal,
        explanation: `start refused at the endpoint boundary: ${this.#decision.explanation}`,
      });
    }
    this.#pending = true;
    const epoch = ++this.#epoch;
    const decision = this.#decision;
    const server = createServer((socket: Socket) => {
      if (this.#sockets.size >= decision.connections) {
        // Bound enforced at accept time: over-limit connections are dropped,
        // never queued, never allowed to widen the pinned ceiling.
        socket.destroy();
        return;
      }
      this.#sockets.add(socket);
      const release = (): void => {
        this.#sockets.delete(socket);
      };
      socket.on("close", release);
      // A socket-level error must never crash the process: the socket is
      // untrusted raw input; its failure only releases the tracked slot.
      socket.on("error", release);
      // The ONE sanctioned connection handler. It is invoked only for a
      // connection the listener itself accepted on the decided endpoint, so
      // there is exactly one bind path and no alternate listener. A handler
      // throw is contained here: the socket is untrusted input and a handler
      // fault releases the slot rather than crashing the process.
      const handler = this.#onConnection;
      if (handler !== null) {
        try {
          handler(socket);
        } catch {
          this.#sockets.delete(socket);
          socket.destroy();
        }
      }
    });
    server.maxConnections = decision.connections;
    const bindResult = await new Promise<ListenerStartResult>((resolve) => {
      const onError = (error: Error): void => {
        server.removeListener("listening", onListening);
        if (server.listening) server.close();
        resolve(
          Object.freeze({
            ok: false as const,
            code: "listener_bind_failed" as const,
            state: "stopped" as const,
            decision,
            refusal: null,
            explanation: `OS refused the explicit local bind (no fallback, no alternate port, no retry): ${error.message}`,
          })
        );
      };
      const onListening = (): void => {
        server.removeListener("error", onError);
        resolve(
          Object.freeze({
            ok: true as const,
            code: "listener_started" as const,
            state: "listening" as const,
            decision,
            explanation: `listener started on explicit local endpoint ${decision.host}:${decision.port}`,
          })
        );
      };
      server.once("error", onError);
      server.once("listening", onListening);
      server.listen({ port: decision.port, host: decision.host, backlog: decision.queue });
    });
    if (bindResult.ok && epoch !== this.#epoch) {
      // A stop() intervened while the bind was in flight: honor the stop and
      // tear the fresh server down — the aborted start never becomes visible.
      server.removeAllListeners();
      this.#sockets.clear();
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
      this.#pending = false;
      return Object.freeze({
        ok: false as const,
        code: "listener_start_aborted" as const,
        state: "stopped" as const,
        decision,
        refusal: null,
        explanation: "start aborted: stop() intervened while the bind was in flight; the listener ends stopped (fail closed)",
      });
    }
    if (bindResult.ok) {
      this.#server = server;
      this.#state = "listening";
      // Fail-closed runtime guard: an unexpected post-bind server error
      // tears the listener down instead of lingering in a broken state.
      server.on("error", () => {
        void this.stop();
      });
    } else {
      server.removeAllListeners();
      this.#sockets.clear();
    }
    this.#pending = false;
    return bindResult;
  }

  /**
   * Explicit, IDEMPOTENT stop: destroys every tracked connection, closes the
   * server, releases the port, and returns `listener_already_stopped` (a
   * success) when there was nothing to close.
   */
  async stop(): Promise<ListenerStopResult> {
    this.#epoch += 1;
    const closedConnections = this.#sockets.size;
    for (const socket of [...this.#sockets]) socket.destroy();
    this.#sockets.clear();
    const server = this.#server;
    this.#server = null;
    this.#state = "stopped";
    this.#pending = false;
    if (server !== null) {
      server.removeAllListeners();
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
      return Object.freeze({
        ok: true as const,
        code: "listener_stopped" as const,
        state: "stopped" as const,
        closedConnections,
        explanation: `listener stopped; ${closedConnections} tracked connection(s) destroyed deterministically`,
      });
    }
    return Object.freeze({
      ok: true as const,
      code: "listener_already_stopped" as const,
      state: "stopped" as const,
      closedConnections: 0,
      explanation: "listener was already stopped; idempotent close is a success, not an error",
    });
  }
}
