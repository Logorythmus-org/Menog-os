# PHASE 26B — Endpoint/Listener Boundary

**Date:** 2026-10-02 · **Mode:** SMALLEST EXPLICIT LOCAL LISTENER / DEFAULT NO LISTENER / FAIL CLOSED
**Module:** `packages/durable-state/src/endpointListenerBoundary.ts` (exported from `@menog/durable-state`)
**Suite:** `tests/unit/endpoint-listener-boundary.test.ts` (23 tests, real loopback binds)
**Entry:** `PRE26_R0_READY` · **Prior gate:** `26A_PASS` (transport trust contract, contract-first)

---

## 1. Purpose

26A defined the trust laws with **no socket implementation**. 26B adds the *smallest*
explicit LOCAL endpoint/listener boundary: the FIRST real socket surface in the
repository. Everything it does is bounded, explicit, and fail-closed; everything it
refuses is refused by name.

HARD LAW this boundary enforces structurally:

```
NETWORK REACHABILITY != IDENTITY != ADMISSION != AUTHORITY != EXECUTION
```

A bound local port proves *nothing else*. No identity, no admission, no authority,
no execution comes from reaching this listener. Bytes arriving on an accepted
connection are untrusted raw DATA that only a later governed gate (26C+ framing)
may interpret — this module never parses them.

## 2. Default: no listener

- Constructing `new LocalEndpointListener(config)` binds **nothing**.
- An absent/incomplete config decides `endpoint_unset` and `start()` returns
  `endpoint_refused` **without creating a socket** (structurally: the refusal
  branch precedes `createServer()`).
- Only an explicit `start()` can open a port; only an explicit `stop()` closes it.

## 3. Allow-list (address classes)

Only four classes may ever bind:

| Class | Range |
|:--|:--|
| `ipv4_loopback` | `127.0.0.0/8` |
| `ipv6_loopback` | `::1` (and full-form `0:0:0:0:0:0:0:1`) |
| `ipv4_private` | RFC1918: `10/8`, `172.16/12`, `192.168/16` |
| `ipv6_ula` | `fc00::/7` unique-local |

The host must be an **exact numeric literal**. The grammar is strict:
IPv4 = exactly 4 dot-separated octets, no leading zeros, ≤ 255; IPv6 = hex
groups with at most one `::`, no embedded IPv4, no zone/scope id. There is
**no normalization, no trimming, no guessing** — inputs are classified as
written or refused.

## 4. Refusals (closed vocabulary — one code per law)

| Refusal | Trigger |
|:--|:--|
| `endpoint_unset` | absent/incomplete config, unknown provenance (default = NO LISTENER) |
| `discovery_refused` | provenance is discovery-derived |
| `environment_refused` | provenance is environment (env surprise widening) |
| `auto_interface_refused` | automatic interface selection |
| `wildcard_refused` | `0.0.0.0`, `::`, `0:0:…:0`, `[::]`, `*`, `0.x.x.x` |
| `unspecified_refused` | empty address |
| `public_refused` | public/global unicast (v4 and v6) |
| `nonlocal_refused` | link-local, multicast, broadcast (v4/v6) |
| `hostname_refused` | non-numeric/ambiguous name (`localhost`, `*.local`, hex-ish tokens) — **never resolved** |
| `malformed_refused` | strict-grammar violation, zone ids (`%eth0`), v4-mapped v6 |
| `port_invalid` | not an integer in `[1024, 65535]` |
| `connections_invalid` | not an integer in `[1, 16]` |
| `queue_invalid` | not an integer in `[1, 64]` |

**Provenance is checked before content**: `discovery + 0.0.0.0` refuses as
`discovery_refused` — a bad source never gets to argue about its address.
Unknown provenance from a non-TS caller fails closed to `endpoint_unset`.

## 5. Bounds (pinned; never widened, never clamped)

```ts
ENDPOINT_BOUNDS = {
  portMin: 1024,        // no privileged ports (least privilege)
  portMax: 65535,
  connectionsMax: 16,   // accept-time drop above the bound, never queued
  queueMax: 64,         // listen backlog ceiling
  defaultConnections: 4,
  defaultQueue: 16,
}
```

A config above a ceiling is **refused**, not clamped — clamping would be a
silent fallback. Inclusive boundary values (1024 / 65535 / 16 / 64) admit.

## 6. Lifecycle (explicit start/stop, idempotent close)

States: `stopped` ↔ `listening` (closed two-state vocabulary).

| Situation | Result |
|:--|:--|
| `start()` on unset/refused config | `endpoint_refused` · no socket created |
| `start()` while listening | `listener_already_listening` (no hidden rebind) |
| OS refuses the bind (port collision) | `listener_bind_failed` — **no fallback, no alternate port, no retry** |
| `stop()` while a start is in flight | `listener_start_aborted` — the listener **ends stopped** |
| `stop()` on a listening listener | `listener_stopped` + tracked connections destroyed |
| `stop()` again (and again) | `listener_already_stopped` — **idempotent success, never an error** |

Deterministic cleanup: `stop()` destroys every tracked socket, closes the
server, and releases the port — proven by an immediate rebind test on the same
port. A post-bind server error tears the listener down instead of lingering
broken. Socket-level errors only release their tracked slot (a peer crash can
never crash this process).

## 7. Structural surface (what the module cannot do)

Imports exactly two modules: `node:net` (server side) + `./canonical.js`.

- **No shell/child** — no `child_process`, `spawn`, `execSync`.
- **No environment** — no `process.env`; provenance must be passed explicitly,
  so env surprise widening is refused at the decision layer.
- **No DNS/lookup** — hostnames are refused, never resolved.
- **No forwarding/proxy** — no `.pipe(`, no client dialing
  (`createConnection` absent): bytes in are never relayed anywhere.
- **No remote reconfiguration** — config is `Object.freeze`-d at construction;
  there are no setters.
- **No authority** — no policy/identity/execution tokens; zero store access;
  zero new 22A kinds; zero unfreeze events; zero dependencies.

## 8. Threats covered by this gate (tested)

| Threat | Control |
|:--|:--|
| wildcard/public bind (`0.0.0.0`, `::`, `*`, `8.8.8.8`) | address class refusal before any socket |
| discovery-derived endpoint | provenance refusal (first) |
| env surprise widening | provenance refusal + no `process.env` |
| automatic interface selection | `auto_interface` provenance + zone-id refusal |
| ambiguous hostname / DNS rebinding | hostname refusal — names never resolved |
| malformed/normalized-input smuggling | strict grammar, no normalization |
| privileged/automatic port | port floor 1024, integer range pin |
| bound widening via config | over-ceiling config refuses (never clamps) |
| double start / double stop | `listener_already_listening` / idempotent stop |
| port collision | `listener_bind_failed`, no fallback port |
| connection flood past the bound | accept-time drop (bound = 1 in test), never queued |
| leaked listener after stop | deterministic cleanup + immediate rebind proof |
| start/stop race | `listener_start_aborted` — ends stopped |

**Out of scope here (later gates):** framing, session state, peer identity,
admission, message authentication — all still pure 26A contracts above this
boundary; nothing here feeds execution.

## 9. Verification (2026-10-02, actual)

| Check | Result |
|:--|:--|
| typecheck / build | **PASS** / **PASS** |
| 26B suite | **23/23** (real IPv4 + IPv6 binds, all torn down in-test) |
| federation + 26A + 25G + 26B combined | **189/189** (8 files) |
| Full suite | **2055/2055** (100 files, 0 fail, 0 skip — 2032 + 23 exactly additive) |
| verify-local | **PASS**, network-invariant PASS, 0 errors, 1 warning (the recorded 5 fixture entries) |
| setup-local `--no-install` | exit 0 |
| lockfile / package.json | `bd289ce7ad6d0d8c` / `77500e08443e424a` byte-identical |
