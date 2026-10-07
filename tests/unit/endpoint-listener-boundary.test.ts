/**
 * PHASE 26B — Endpoint/Listener Boundary Tests
 * (DEFAULT NO LISTENER / LOCAL ONLY / BOUNDS NEVER WIDEN / IDEMPOTENT CLOSE).
 *
 * Pack-mandated coverage:
 *   IPv4/IPv6        — loopback + private numeric binds for both families;
 *                      full-form and compressed literals classify identically
 *   malformed        — strict grammar refuses (no normalization, no guessing)
 *   public/wildcard  — wildcard (0.0.0.0, ::, star) and public/global refuse
 *   explicit config  — provenance must be explicit_local_config; environment/
 *                      discovery/auto-interface refuse even with a valid host
 *   idempotent close — stop() twice = two successes; cleanup is deterministic
 *
 * Real sockets are bound here (loopback only, exact numeric addresses,
 * bounded ports) — this is the FIRST sanctioned listener in the repository.
 * Every bind is torn down in the same test; no test leaves a listener open.
 */
import { describe, it, expect } from "vitest";
import {
  ENDPOINT_BOUNDARY_SCHEMA_VERSION,
  ENDPOINT_ADDRESS_CLASSES,
  ENDPOINT_REFUSAL_CODES,
  ENDPOINT_CONFIG_SOURCES,
  ENDPOINT_BOUNDS,
  LISTENER_STATES,
  LISTENER_START_CODES,
  LISTENER_STOP_CODES,
  classifyEndpointHost,
  decideEndpoint,
  LocalEndpointListener,
  type EndpointConfig,
  type EndpointDecision,
  type EndpointRefusalCode,
} from "@menog/durable-state";
import { connect, type Socket } from "node:net";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// ── helpers ─────────────────────────────────────────────────────────────────

/** Comment-stripped module source (same discipline as the frozen suites). */
function moduleSource(): string {
  const raw = readFileSync(
    join(process.cwd(), "packages", "durable-state", "src", "endpointListenerBoundary.ts"),
    "utf8"
  );
  return raw
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

function explicit(host: string, port: number, extra: Partial<EndpointConfig> = {}): EndpointConfig {
  return { source: "explicit_local_config", host, port, ...extra };
}

/** A deterministic refusal assertion: code, non-empty explanation, stable hash. */
function expectRefusal(decision: EndpointDecision, refusal: EndpointRefusalCode): void {
  expect(decision.ok).toBe(false);
  if (decision.ok) throw new Error("unreachable");
  expect(decision.refusal).toBe(refusal);
  expect(decision.explanation.length).toBeGreaterThan(10);
  expect(decision.provenanceHash).toMatch(/^[0-9a-f]{64}$/);
}

/** Connect a client, resolve once connected, always destroyed at teardown. */
function connectTo(port: number, host: string): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect({ port, host }, () => resolve(socket));
    socket.once("error", reject);
  });
}

/** Wait (bounded) until a tracked-connection count reaches `n`. */
async function waitForConnections(listener: LocalEndpointListener, n: number, ms = 2000): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (listener.activeConnections() === n) return true;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return listener.activeConnections() === n;
}

// Deterministic ports for the real-bind tests (fixed, explicit, bounded).
const PORT_V4 = 41871;
const PORT_V6 = 41872;
const PORT_IDEMPOTENT = 41873;
const PORT_COLLIDE = 41874;
const PORT_REBIND = 41875;
const PORT_BOUND = 41876;
const PORT_ABORT = 41877;

// ── structure: closed vocabularies, pinned bounds, minimal surface ──────────

describe("26B structure — closed vocabularies and minimal socket surface", () => {
  it("schema version and all vocabularies are pinned exactly", () => {
    expect(ENDPOINT_BOUNDARY_SCHEMA_VERSION).toBe("menog-endpoint-boundary/v0");
    expect([...ENDPOINT_ADDRESS_CLASSES]).toEqual([
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
    ]);
    expect([...ENDPOINT_REFUSAL_CODES]).toEqual([
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
    ]);
    expect([...ENDPOINT_CONFIG_SOURCES]).toEqual([
      "explicit_local_config",
      "environment",
      "discovery",
      "auto_interface",
    ]);
    expect([...LISTENER_STATES]).toEqual(["stopped", "listening"]);
    expect([...LISTENER_START_CODES]).toEqual([
      "listener_started",
      "listener_already_listening",
      "listener_bind_failed",
      "listener_start_aborted",
    ]);
    expect([...LISTENER_STOP_CODES]).toEqual(["listener_stopped", "listener_already_stopped"]);
  });

  it("bounds are pinned: port floor/ceiling, connections, queue, defaults", () => {
    expect(ENDPOINT_BOUNDS).toEqual({
      portMin: 1024,
      portMax: 65535,
      connectionsMax: 16,
      queueMax: 64,
      defaultConnections: 4,
      defaultQueue: 16,
    });
    expect(Object.isFrozen(ENDPOINT_BOUNDS)).toBe(true);
  });

  it("the module imports ONLY node:net + canonical (no child, no env, no proxy, no dns)", () => {
    const code = moduleSource();
    const imports = [...code.matchAll(/from\s+"([^"]+)"/g)].map((m) => m[1]).sort();
    expect(imports).toEqual(["./canonical.js", "node:net"]);
    for (const forbidden of [
      "child_process",
      "spawn(",
      "execSync",
      "process.env",
      "node:dns",
      "lookup(",
      "readline",
      "WebSocket",
      "fetch(",
      "request(",
      ".pipe(",
      "createConnection",
      "shell:",
      "acceptMutation",
      ".persist(",
      "executeToolRun",
      "runIsolated",
      "policy",
      "authority",
      "identity",
    ]) {
      expect(code.includes(forbidden), "module contains " + forbidden).toBe(false);
    }
    // The FIRST sanctioned socket surface: server-side only, no client dialing.
    expect(code.includes("createServer")).toBe(true);
    expect(code.includes("listen(")).toBe(true);
    // The wildcard literal appears only as a REFUSAL target (classification),
    // never as a bind argument: no `host: "0.0.0.0"` ever reaches listen().
    expect(code.includes("host === \"0.0.0.0\"")).toBe(true);
    expect(code.includes("host: \"0.0.0.0\"")).toBe(false);
    // Config is frozen at construction; there is no setter by design.
    expect(code.includes("Object.freeze")).toBe(true);
  });
});

// ── classification: IPv4/IPv6, malformed, wildcard, public ─────────────────

describe("26B classification — strict numeric grammar, closed classes", () => {
  it("IPv4/IPv6 loopback and private classes classify into the allow-list", () => {
    expect(classifyEndpointHost("127.0.0.1")).toBe("ipv4_loopback");
    expect(classifyEndpointHost("127.50.1.2")).toBe("ipv4_loopback");
    expect(classifyEndpointHost("::1")).toBe("ipv6_loopback");
    expect(classifyEndpointHost("0:0:0:0:0:0:0:1")).toBe("ipv6_loopback");
    expect(classifyEndpointHost("10.1.2.3")).toBe("ipv4_private");
    expect(classifyEndpointHost("172.16.0.1")).toBe("ipv4_private");
    expect(classifyEndpointHost("172.31.255.254")).toBe("ipv4_private");
    expect(classifyEndpointHost("192.168.1.10")).toBe("ipv4_private");
    expect(classifyEndpointHost("fc00::1")).toBe("ipv6_ula");
    expect(classifyEndpointHost("fd12:3456::1")).toBe("ipv6_ula");
  });

  it("wildcard and unspecified forms classify as wildcard/unspecified", () => {
    expect(classifyEndpointHost("0.0.0.0")).toBe("wildcard");
    expect(classifyEndpointHost("::")).toBe("wildcard");
    expect(classifyEndpointHost("0:0:0:0:0:0:0:0")).toBe("wildcard");
    expect(classifyEndpointHost("[::]")).toBe("wildcard");
    expect(classifyEndpointHost("*")).toBe("wildcard");
    expect(classifyEndpointHost("0.1.2.3")).toBe("wildcard"); // 0.x.x.x = this-network space
    expect(classifyEndpointHost("")).toBe("unspecified");
  });

  it("public and non-local classes classify (never admit)", () => {
    expect(classifyEndpointHost("8.8.8.8")).toBe("ipv4_public");
    expect(classifyEndpointHost("1.1.1.1")).toBe("ipv4_public");
    expect(classifyEndpointHost("2001:4860:4860::8888")).toBe("ipv6_public");
    expect(classifyEndpointHost("169.254.1.1")).toBe("ipv4_nonlocal"); // link-local
    expect(classifyEndpointHost("224.0.0.1")).toBe("ipv4_nonlocal"); // multicast
    expect(classifyEndpointHost("255.255.255.255")).toBe("ipv4_nonlocal"); // broadcast
    expect(classifyEndpointHost("fe80::1")).toBe("ipv6_nonlocal"); // link-local
    expect(classifyEndpointHost("ff02::1")).toBe("ipv6_nonlocal"); // multicast
  });

  it("malformed literals refuse strictly (no normalization, no guessing)", () => {
    expect(classifyEndpointHost("999.1.1.1")).toBe("malformed"); // octet > 255
    expect(classifyEndpointHost("10.0.0")).toBe("malformed"); // 3 octets
    expect(classifyEndpointHost("10.0.0.1.1")).toBe("malformed"); // 5 octets
    expect(classifyEndpointHost("010.0.0.1")).toBe("malformed"); // leading zero
    expect(classifyEndpointHost("10.0.0.01")).toBe("malformed"); // trailing zero pad
    expect(classifyEndpointHost("1.2.3.04")).toBe("malformed");
    expect(classifyEndpointHost(":::1")).toBe("malformed"); // doubled ::
    expect(classifyEndpointHost("1:2:3:4:5:6:7:8:9")).toBe("malformed"); // 9 groups
    expect(classifyEndpointHost("gg::1")).toBe("hostname"); // non-hex letters
    expect(classifyEndpointHost("127.0.0.1%eth0")).toBe("malformed"); // zone id
    expect(classifyEndpointHost("127.0.0.1 ")).toBe("hostname"); // trailing space
    expect(classifyEndpointHost("0x7f000001")).toBe("hostname"); // hex form
    expect(classifyEndpointHost("fe80::1%1")).toBe("malformed"); // zone id (interface selection)
  });

  it("hostnames and discovery-shaped names classify as hostname (never resolved)", () => {
    expect(classifyEndpointHost("localhost")).toBe("hostname");
    expect(classifyEndpointHost("my-host.local")).toBe("hostname");
    expect(classifyEndpointHost("192.168.1.1.router")).toBe("hostname");
    expect(classifyEndpointHost("printer")).toBe("hostname");
    expect(classifyEndpointHost("::ffff:127.0.0.1")).toBe("malformed"); // v4-mapped refused
  });
});

// ── decideEndpoint: default deny, provenance first, bounds ─────────────────

describe("26B decideEndpoint — default no listener, provenance first, bounds never widen", () => {
  it("default: absent/incomplete config refuses endpoint_unset", () => {
    expectRefusal(decideEndpoint(undefined), "endpoint_unset");
    expectRefusal(decideEndpoint(null), "endpoint_unset");
    expectRefusal(decideEndpoint({}), "endpoint_unset");
    expectRefusal(decideEndpoint({ source: "explicit_local_config" }), "endpoint_unset"); // no host
    expectRefusal(decideEndpoint({ host: "127.0.0.1", port: 41871 }), "endpoint_unset"); // no source
  });

  it("provenance refuses discovery/environment/auto-interface BEFORE the address", () => {
    expectRefusal(decideEndpoint({ source: "discovery", host: "127.0.0.1", port: 41871 }), "discovery_refused");
    expectRefusal(decideEndpoint({ source: "environment", host: "10.0.0.1", port: 41871 }), "environment_refused");
    expectRefusal(decideEndpoint({ source: "auto_interface", host: "192.168.1.10", port: 41871 }), "auto_interface_refused");
    // Unknown provenance from a non-TS caller still fails closed.
    expectRefusal(
      decideEndpoint({ source: "remote_admin" as never, host: "127.0.0.1", port: 41871 }),
      "endpoint_unset"
    );
    // Provenance beats content: discovery + wildcard = discovery_refused.
    expectRefusal(decideEndpoint({ source: "discovery", host: "0.0.0.0", port: 41871 }), "discovery_refused");
  });

  it("wildcard/public/hostname/malformed addresses refuse with their own codes", () => {
    expectRefusal(decideEndpoint(explicit("0.0.0.0", 41871)), "wildcard_refused");
    expectRefusal(decideEndpoint(explicit("::", 41871)), "wildcard_refused");
    expectRefusal(decideEndpoint(explicit("*", 41871)), "wildcard_refused");
    expectRefusal(decideEndpoint(explicit("", 41871)), "unspecified_refused");
    expectRefusal(decideEndpoint(explicit("8.8.8.8", 41871)), "public_refused");
    expectRefusal(decideEndpoint(explicit("2001:4860:4860::8888", 41871)), "public_refused");
    expectRefusal(decideEndpoint(explicit("169.254.1.1", 41871)), "nonlocal_refused");
    expectRefusal(decideEndpoint(explicit("localhost", 41871)), "hostname_refused");
    expectRefusal(decideEndpoint(explicit("my-host.local", 41871)), "hostname_refused");
    expectRefusal(decideEndpoint(explicit("999.1.1.1", 41871)), "malformed_refused");
    expectRefusal(decideEndpoint(explicit(":::1", 41871)), "malformed_refused");
    // Non-string host from a non-TS caller refuses instead of throwing.
    expectRefusal(decideEndpoint({ source: "explicit_local_config", host: 123 as never, port: 41871 }), "malformed_refused");
  });

  it("port bound: non-integers, out-of-range, and below floor refuse", () => {
    expectRefusal(decideEndpoint(explicit("127.0.0.1", 80)), "port_invalid"); // below floor
    expectRefusal(decideEndpoint(explicit("127.0.0.1", 1023)), "port_invalid");
    expectRefusal(decideEndpoint(explicit("127.0.0.1", 0)), "port_invalid");
    expectRefusal(decideEndpoint(explicit("127.0.0.1", 65536)), "port_invalid");
    expectRefusal(decideEndpoint(explicit("127.0.0.1", 41871.5)), "port_invalid");
    expectRefusal(decideEndpoint(explicit("127.0.0.1", NaN)), "port_invalid");
    expectRefusal(decideEndpoint(explicit("127.0.0.1", "41871" as never)), "port_invalid");
    expectRefusal(decideEndpoint({ source: "explicit_local_config", host: "127.0.0.1" }), "port_invalid");
    // Boundaries are inclusive and exact.
    expect(decideEndpoint(explicit("127.0.0.1", 1024)).ok).toBe(true);
    expect(decideEndpoint(explicit("127.0.0.1", 65535)).ok).toBe(true);
  });

  it("connections/queue bounds refuse over-ceiling (never clamp)", () => {
    expectRefusal(decideEndpoint(explicit("127.0.0.1", 41871, { connections: 17 })), "connections_invalid");
    expectRefusal(decideEndpoint(explicit("127.0.0.1", 41871, { connections: 0 })), "connections_invalid");
    expectRefusal(decideEndpoint(explicit("127.0.0.1", 41871, { connections: -1 })), "connections_invalid");
    expectRefusal(decideEndpoint(explicit("127.0.0.1", 41871, { connections: 2.5 })), "connections_invalid");
    expectRefusal(decideEndpoint(explicit("127.0.0.1", 41871, { queue: 65 })), "queue_invalid");
    expectRefusal(decideEndpoint(explicit("127.0.0.1", 41871, { queue: 0 })), "queue_invalid");
    expectRefusal(decideEndpoint(explicit("127.0.0.1", 41871, { queue: 99 })), "queue_invalid");
    // Exact ceilings admit.
    expect(decideEndpoint(explicit("127.0.0.1", 41871, { connections: 16 })).ok).toBe(true);
    expect(decideEndpoint(explicit("127.0.0.1", 41871, { queue: 64 })).ok).toBe(true);
  });

  it("admitted decisions carry class, bounds in force, explanation, stable hash", () => {
    const d = decideEndpoint(explicit("127.0.0.1", 41871));
    expect(d.ok).toBe(true);
    if (!d.ok) throw new Error("expected admission");
    expect(d.code).toBe("endpoint_admitted");
    expect(d.addressClass).toBe("ipv4_loopback");
    expect(d.host).toBe("127.0.0.1");
    expect(d.port).toBe(41871);
    expect(d.connections).toBe(4); // default
    expect(d.queue).toBe(16); // default
    expect(d.explanation).toContain("ipv4_loopback");
    expect(d.provenanceHash).toMatch(/^[0-9a-f]{64}$/);
    // Determinism: identical input → byte-identical decision.
    expect(decideEndpoint(explicit("127.0.0.1", 41871))).toEqual(d);
    // Different port → different provenance hash.
    const other = decideEndpoint(explicit("127.0.0.1", 41879));
    if (!other.ok) throw new Error("expected admission");
    expect(other.provenanceHash).not.toBe(d.provenanceHash);
    // IPv6 loopback admits with its class.
    const v6 = decideEndpoint(explicit("::1", 41872));
    if (!v6.ok) throw new Error("expected admission");
    expect(v6.addressClass).toBe("ipv6_loopback");
    // Private IPv4 and ULA admit.
    expect(decideEndpoint(explicit("10.1.2.3", 41871)).ok).toBe(true);
    expect(decideEndpoint(explicit("fd12:3456::1", 41871)).ok).toBe(true);
  });
});

// ── the real listener: default no listener, explicit start/stop ────────────

describe("26B listener — default no listener, explicit lifecycle, idempotent close", () => {
  it("construction binds nothing; start() with unset config refuses with NO socket", async () => {
    const listener = new LocalEndpointListener(undefined);
    expect(listener.state()).toBe("stopped");
    expect(listener.activeConnections()).toBe(0);
    expectRefusal(listener.decision(), "endpoint_unset");
    const start = await listener.start();
    expect(start.ok).toBe(false);
    if (start.ok) throw new Error("expected refusal");
    expect(start.code).toBe("endpoint_refused");
    expect(start.refusal).toBe("endpoint_unset");
    expect(listener.state()).toBe("stopped");
    // Close before start is still a success (idempotent by design).
    const stop = await listener.stop();
    expect(stop.ok).toBe(true);
    expect(stop.code).toBe("listener_already_stopped");
  });

  it("refused endpoints (wildcard/public/hostname) never create a socket", async () => {
    for (const bad of ["0.0.0.0", "::", "8.8.8.8", "localhost"]) {
      const listener = new LocalEndpointListener(explicit(bad, PORT_V4));
      const start = await listener.start();
      expect(start.ok).toBe(false);
      if (start.ok) throw new Error("expected refusal for " + bad);
      expect(start.code).toBe("endpoint_refused");
      expect(listener.state()).toBe("stopped");
      expect(listener.activeConnections()).toBe(0);
      await listener.stop();
    }
  });

  it("explicit IPv4 loopback: start, accept one connection, stop destroys it", async () => {
    const listener = new LocalEndpointListener(explicit("127.0.0.1", PORT_V4, { connections: 4 }));
    const start = await listener.start();
    expect(start.ok).toBe(true);
    if (!start.ok) throw new Error("start failed: " + start.explanation);
    expect(start.code).toBe("listener_started");
    expect(listener.state()).toBe("listening");
    expect(start.decision.ok).toBe(true);

    const client = await connectTo(PORT_V4, "127.0.0.1");
    expect(await waitForConnections(listener, 1)).toBe(true);
    expect(listener.activeConnections()).toBe(1);

    // Double start refuses — no hidden rebind, no silent port switch.
    const again = await listener.start();
    expect(again.ok).toBe(false);
    if (again.ok) throw new Error("expected double-start refusal");
    expect(again.code).toBe("listener_already_listening");
    expect(listener.state()).toBe("listening");

    const closed = new Promise<void>((resolve) => client.once("close", () => resolve()));
    const stop = await listener.stop();
    expect(stop.ok).toBe(true);
    expect(stop.code).toBe("listener_stopped");
    expect(stop.closedConnections).toBe(1);
    expect(listener.state()).toBe("stopped");
    expect(listener.activeConnections()).toBe(0);
    await closed; // deterministic cleanup: the client observes the close
    client.destroy();
  });

  it("explicit IPv6 loopback ::1 binds and closes identically", async () => {
    const listener = new LocalEndpointListener(explicit("::1", PORT_V6));
    const start = await listener.start();
    expect(start.ok).toBe(true);
    if (!start.ok) throw new Error("IPv6 start failed: " + start.explanation);
    expect(listener.state()).toBe("listening");

    const client = await connectTo(PORT_V6, "::1");
    expect(await waitForConnections(listener, 1)).toBe(true);

    const stop = await listener.stop();
    expect(stop.ok).toBe(true);
    expect(stop.code).toBe("listener_stopped");
    expect(listener.state()).toBe("stopped");
    client.destroy();
  });

  it("stop() is idempotent: three stops, three successes", async () => {
    const listener = new LocalEndpointListener(explicit("127.0.0.1", PORT_IDEMPOTENT));
    const start = await listener.start();
    expect(start.ok).toBe(true);
    const first = await listener.stop();
    expect(first.ok).toBe(true);
    expect(first.code).toBe("listener_stopped");
    const second = await listener.stop();
    expect(second.ok).toBe(true);
    expect(second.code).toBe("listener_already_stopped");
    const third = await listener.stop();
    expect(third.ok).toBe(true);
    expect(third.code).toBe("listener_already_stopped");
    expect(listener.state()).toBe("stopped");
  });

  it("deterministic cleanup: after stop the port is released and rebindable", async () => {
    const first = new LocalEndpointListener(explicit("127.0.0.1", PORT_REBIND));
    expect((await first.start()).ok).toBe(true);
    const client = await connectTo(PORT_REBIND, "127.0.0.1");
    expect(await waitForConnections(first, 1)).toBe(true);
    expect((await first.stop()).ok).toBe(true);

    // The port is free immediately: a second listener binds the same port.
    const second = new LocalEndpointListener(explicit("127.0.0.1", PORT_REBIND));
    const restart = await second.start();
    expect(restart.ok).toBe(true);
    if (!restart.ok) throw new Error("rebind failed: " + restart.explanation);
    expect(second.state()).toBe("listening");
    expect((await second.stop()).ok).toBe(true);
    client.destroy();
  });

  it("bind collision refuses (listener_bind_failed) with no fallback port", async () => {
    const holder = new LocalEndpointListener(explicit("127.0.0.1", PORT_COLLIDE));
    expect((await holder.start()).ok).toBe(true);

    const rival = new LocalEndpointListener(explicit("127.0.0.1", PORT_COLLIDE));
    const clash = await rival.start();
    expect(clash.ok).toBe(false);
    if (clash.ok) throw new Error("expected bind failure");
    expect(clash.code).toBe("listener_bind_failed");
    expect(clash.explanation).toContain("no fallback");
    expect(rival.state()).toBe("stopped"); // fail closed, not half-listening

    expect((await holder.stop()).ok).toBe(true);
    expect((await rival.stop()).ok).toBe(true); // already stopped = success
  });

  it("connections bound: the (connections+1)th client is dropped, never queued", async () => {
    const listener = new LocalEndpointListener(explicit("127.0.0.1", PORT_BOUND, { connections: 1 }));
    expect((await listener.start()).ok).toBe(true);

    const first = await connectTo(PORT_BOUND, "127.0.0.1");
    expect(await waitForConnections(listener, 1)).toBe(true);

    // Second dial: accepted by the OS, dropped by the boundary (bound = 1).
    const second = await connectTo(PORT_BOUND, "127.0.0.1");
    const secondClosed = new Promise<void>((resolve) => second.once("close", () => resolve()));
    await secondClosed;
    expect(listener.activeConnections()).toBe(1); // never exceeds the bound

    expect((await listener.stop()).ok).toBe(true);
    expect(listener.activeConnections()).toBe(0);
    first.destroy();
    second.destroy();
  });

  it("stop() during a pending start() aborts the start (fail closed)", async () => {
    const listener = new LocalEndpointListener(explicit("127.0.0.1", PORT_ABORT));
    const startPromise = listener.start();
    const stopPromise = listener.stop();
    const [start, stop] = await Promise.all([startPromise, stopPromise]);
    // Whichever won the race, the listener must END STOPPED.
    expect(listener.state()).toBe("stopped");
    if (start.ok) {
      // Start won the race: the intervening stop must still have closed it.
      expect(start.code).toBe("listener_started");
      expect(stop.code).toBe("listener_stopped");
    } else {
      expect(["listener_start_aborted", "listener_already_listening"]).toContain(start.code);
    }
    expect((await listener.stop()).ok).toBe(true); // settle to already_stopped
    expect(listener.state()).toBe("stopped");
  });
});
