# PHASE 26F — Transport Resilience & Backpressure

**Date:** 2026-10-02 · **Status:** QUALIFIED (local loopback only)
**Module:** `packages/durable-state/src/transportResilience.ts`
**Entry:** `PHASE25_FROZEN_READY_FOR_PHASE26_LOCAL_NETWORK_DESIGN` · **Prior gates:** `26A_PASS` … `26E_PASS`

---

## 1. Scope, and what this document deliberately does not claim

This document records the resilience qualification of the Phase-26 governed
local network transport: what the transport does when a queue fills, when a
peer disappears, when a receiver stalls, when a deadline passes, and when a
connection is re-established.

**NOT CLAIMED, anywhere, in this gate:**

| Non-claim | Why |
|:--|:--|
| DDoS resistance | No flooding, amplification, or volumetric behaviour was tested or is claimed. The bounds here make a *single node's* behaviour deterministic; they say nothing about an adversary's ability to reach it. |
| WAN / Internet behaviour | All failure injection ran on `127.0.0.1` loopback. Path MTU, NAT, proxying, reordering, and real Internet loss are out of scope and untested. |
| Production capacity | No throughput, concurrency, or latency number is claimed. The bounds are correctness bounds, not sizing guidance. |
| Power-loss / hardware safety | Phase-25 crash evidence remains **process-crash evidence**. Nothing here survives, certifies, or implies power-loss safety. |

These four statements are also carried as a machine-readable closed
vocabulary, `RESILIENCE_UNCLAIMED_SCOPES`, attached verbatim to **every**
failure classification this module emits — so a downstream reader cannot
strip them.

Conversely, `RESILIENCE_QUALIFIED_SCOPES` states exactly what *was*
qualified: bounded queue depth, bounded queued bytes, bounded connection
count, backpressure refusal, frozen deadlines, deterministic close, the
orphan resource ledger, reconnect-inherits-no-authority, and
retry-cannot-bypass-replay.

## 2. The laws

1. **No unbounded memory growth.** Queue depth (256), queued bytes (65 536),
   connections (16), reconnects per window (8), retry attempts (4), and
   tracked resources (64) are **constants**. A caller may exceed a bound and
   be refused; a caller may never redefine one. Refuse, never clamp, never
   grow, never drop-and-silently-continue.
2. **Deterministic close.** A window closes in one pinned order with one
   terminal code. The first close wins and no later close changes it. Every
   operation on a closed window refuses with `window_closed`.
3. **Zero orphan handles/timers.** Every resource a caller registers must be
   released. `qualifyCleanup` **refuses** while anything is held, which makes
   this a checkable property rather than a promise.
4. **Reconnect inherits no authority.** A reconnect is a NEW session. It
   carries no trust, no admission, no transcript, and no authority, and it
   must revalidate key use, local admission, runtime epoch, and transcript
   before it can carry anything.
5. **Retries cannot bypass replay.** Re-sending a message id this node has
   already seen refuses as replay. No reconnect, no backpressure state, and
   no failure disposition can clear that record.
6. **Network failure never triggers executable replay.** The disposition
   vocabulary is closed and contains **no** resume, replay, or execute entry.
   Every decision carries `resumesWork: false` and `executableReplay: false`
   as literal types.

The deadlines and connection bound are read from the frozen 26C
`FRAMED_TRANSPORT_BOUNDS` object rather than restated, so the two layers
cannot drift apart.

## 3. The failure catalog

Fourteen failure classes, each with **exactly one** frozen disposition. The
catalog is closed: an unrecognised failure refuses to classify, and therefore
receives no disposition and no recovery path.

| Failure class | Disposition | What it means |
|:--|:--|:--|
| `peer_exit` | `close_session` | the peer process or connection ended; nothing is resumed |
| `peer_half_close` | `close_session` | a half-close finishes one direction; it is never a continuation |
| `connection_reset` | `fault_session` | reset, not a clean FIN; every held resource is released |
| `read_timeout` | `fault_session` | a slow peer never extends a deadline |
| `write_timeout` | `fault_session` | backpressure never becomes a longer buffer |
| `idle_timeout` | `close_session` | an idle connection holds no work |
| `queue_saturation` | `refuse_frame` | memory stays bounded; nothing is silently dropped and retried |
| `slow_receiver` | `refuse_frame` | the receiver is not draining; the queue never grows |
| `reconnect_storm` | `refuse_reconnect` | a storm is never answered with more attempts |
| `trust_changed` | `quarantine_peer` | trust is re-evaluated by LOCAL judgment, never assumed |
| `key_changed` | `new_session_rehandshake` | a changed key inherits nothing |
| `malformed_frame` | `refuse_frame` | one bad frame never tears down healthy state |
| `malformed_mixed_with_valid` | `refuse_frame` | refuse the bad frame; keep the valid sequence in order |
| `local_shutdown` | `close_all` | close everything deterministically, release everything |

A **trust change** and a **key change** during live traffic map onto the
frozen 26E ingress codes, carried verbatim: `trust_changed` →
`peer_not_admitted` (the 26E `local_admission` stage), `key_changed` →
`key_use_refused` (the 26E `current_key_use` stage). Purely transport-level
failures own no ingress code (`null`).

## 4. Bounds and backpressure

The queue decision checks in a **pinned order** — byte size → depth → bytes →
backpressure — and the first match refuses. Nothing allocates: the frame's
byte size is compared against the frozen 26C frame bound before any buffer
could grow.

Two regimes matter, and both are pinned by tests:

- **Byte-bound regime** (frames carrying real payload): with 1 024-byte
  frames the 65 536-byte bound binds first, at 64 queued frames.
- **Depth-bound regime** (small frames): with 64-byte frames the 256-frame
  depth bound binds first, at 16 384 queued bytes — the byte bound is never
  reached.

The outbound queue is a genuine bounded FIFO: each entry holds its frame's
byte count, so a dequeue releases exactly what was enqueued, and the array can
never exceed 256 entries because `enqueue` refuses before pushing.

**A non-draining receiver accepts nothing at all**, even with an empty queue.
That is the fail-closed reading of backpressure: if the receiver is not
draining, buffering more is wrong, so the frame is refused rather than held.

## 5. Deadlines

Checked in the frozen order **read → write → idle**, first expired wins, with
read-beats-write-beats-idle precedence pinned by multi-violation tests.

- **The read deadline is measured from the first byte of an incomplete
  frame.** A sender that dribbles bytes cannot reset it, which is the classic
  slow-loris shape and is closed here.
- A caller may **shorten** `peerTimeoutMs` but never widen it; above the
  ceiling or fractional refuses rather than clamping.
- Idle expiry **closes**; read/write expiry **faults**.

## 6. Reconnect, retry, and the replay record

A reconnect decision carries `inheritsAuthority: false`, `carriedAuthority:
"none"`, `carriedAdmission: "none"`, and `carriedTranscript: "none"` as
**literal types** — a caller cannot widen them. A caller that explicitly asks
to continue the prior session is refused with
`reconnect_refused_continuation`. The frozen 26A session machine is consulted
for whether a reconnect event is legal from the current state; the resilience
layer reports that outcome rather than re-implementing it.

The storm bound is checked against the **prospective** attempt number, so a
bound of N permits exactly N reconnects per window and refuses the N+1th.

Retries are gated twice: the message id must be unseen, and the attempt must
be within the frozen bound. A retry of a seen id refuses at **every** attempt
number — including after a reconnect, which is precisely the "retry as a way
past replay" path the law closes.

## 7. Failure injection actually performed

All of the following ran against **real** loopback sockets (`node:net`) and
the real bounded window:

| Injection | How it was produced | Result |
|:--|:--|:--|
| Peer / server exit | server socket `destroy()` | `peer_exit` → `close_session`; slot released; ledger qualifies clean |
| Half-close | `socket.end()` (FIN) | `peer_half_close` → `close_session`; reconnect still inherits nothing |
| Reset | `socket.resetAndDestroy()` (RST) | `connection_reset` → `fault_session`; no resume, no authority |
| Timeout | deadline arithmetic incl. a dribbling sender | read/write → `fault_session`, idle → `close_session` |
| Queue saturation | a receiver that never attaches a data handler | queue saturates at the byte bound, then refuses forever |
| Slow receiver | same socket, drain state false | `queue_refused_backpressure`, even with room in the queue |
| Bounded reconnect storm | 12 real connect/close cycles against a server that destroys each | exactly 3 reconnects permitted, 9 refused, 0 sessions created |
| Malformed + valid mix | oversize frame beside valid ones | only the malformed refuses; the valid frame is accepted; the window stays open |
| Trust / key change during traffic | the frozen remap over live-facts codes | `quarantine_peer` / `new_session_rehandshake`, carrying the frozen 26E codes |

**Orphan measurement.** 25 real `setTimeout` handles were registered in the
ledger; `qualifyCleanup` refused while they were held; after `clearTimeout`
plus release, `process.getActiveResourcesInfo()` returned to its measured
baseline. That is a measurement, not an assertion about intent.

## 8. Structural pins

The module imports exactly three frozen modules and nothing else:
`./federationTransportTrust.js`, `./framedSocketTransport.js`,
`./transportIngressJunction.js`. A 44-token scan pins the absence of: child
process, `process.env`, DNS/HTTP/Net/TLS/HTTP2, `createServer`, `.listen(`,
`fetch(`, axios, `XMLHttpRequest`, `WebSocket`, `createConnection`, a bare
`connect(` call, `request(`, `.pipe(`, `setTimeout`, `setInterval`,
`setImmediate`, `Date.now`, `Math.random`, `performance.now`, `process.hrtime`,
`eval(`, `require(`, `.persist(`, `root =`, `acceptMutation`, and the
store/coordinator/persist modules.

The module holds no socket, opens no listener, sets no timer, reads no wall
clock, and reaches no store. It is a decision layer plus one bounded state
object; callers supply `nowMs` on every operation, exactly as in the frozen
gates above.

## 9. Standing debt and limits

- Bounds are **correctness** bounds, not capacity guidance (§1).
- The reconnect window is a fixed 60 s; it is a constant, and it is not a
  rate limiter against a determined adversary (§1: no DDoS claim).
- The orphan ledger tracks resources a caller *registers*. A caller that
  allocates a handle and never registers it is outside this module's view —
  the ledger is a discipline with a measurement, not a garbage collector.
- Phase-25 crash evidence is process-crash evidence; nothing here changes that.
