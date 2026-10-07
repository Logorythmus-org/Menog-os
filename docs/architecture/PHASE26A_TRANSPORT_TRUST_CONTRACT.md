# PHASE 26A — Transport Trust Model & Contract

**Date:** 2026-10-02 · **Mode:** CONTRACT-FIRST / NO SOCKET IMPLEMENTATION / NO NEW AUTHORITY
**Module:** `packages/durable-state/src/federationTransportTrust.ts` (exported from `@menog/durable-state`)
**Suite:** `tests/unit/federation-transport-trust.test.ts` (30 tests)
**Entry:** `PRE26_R0_READY` (2026-10-02 — Phase-25 frozen, baselines re-verified)

---

## 1. Purpose

This contract defines the closed vocabularies and deterministic, fail-closed
decisions for Phase-26 governed local-network transport BEFORE any socket,
listener, or frame-carrying code exists (26B+ builds on top of these laws).
It is a pure decision layer: no transport, no sockets, no discovery, no
crypto, no store access, no execution surface — every output is a function of
caller-supplied facts and embeds a deterministic explanation.

Hard law restated: **NETWORK REACHABILITY ≠ IDENTITY ≠ ADMISSION ≠ AUTHORITY
≠ EXECUTION.** Remote input is untrusted DATA. LOCAL NETWORK ONLY.

## 2. The nine pins (closed, ordered T1..T9)

| Pin | Law | Enforced by |
|:--|:--|:--|
| T1 | REACHABILITY ≠ IDENTITY | endpoint decisions; TT-01/TT-16; claim matrix |
| T2 | IDENTITY ≠ ADMISSION | freshAdmissionRequired on every usable session; TT-02/TT-15; claim matrix |
| T3 | ADMISSION ≠ AUTHORITY | scope MAY-NOT set (`grant_authority`, `administer_peer`); TT-17 |
| T4 | AUTHENTICATED SESSION ≠ EXECUTION | scope MAY-NOT `execute_tool`; claim matrix; TT-18 |
| T5 | REMOTE MESSAGE ≠ LOCAL POLICY | scope MAY-NOT `choose_policy`; claim matrix |
| T6 | TRANSPORT SUCCESS ≠ APPLICATION ACCEPTANCE | every frame decision carries the pin; accepted frames explain "NOT application acceptance" |
| T7 | CONNECTION STATE ≠ TRUST STATE | session machine: `trustCarried` is the literal `false` on every transition; half-close/flood/pace pins |
| T8 | RECONNECT ≠ RE-ADMISSION | reconnect from closed/faulted starts a NEW session with zero carried trust + `freshAdmissionRequired: true` |
| T9 | NETWORK EVIDENCE ≠ AUTHORITY | scope MAY-NOT `persist_record`; stale-disclosure refusal; evidence-authority claim refusal |

Each pin has a closed, deterministic explanation string
(`TRANSPORT_TRUST_PIN_EXPLANATIONS`) that is embedded verbatim in decisions
and test-pinned (no free-form authority prose).

## 3. Closed vocabularies

| Vocabulary | Values | Decision surface |
|:--|:--|:--|
| Endpoint classes | `loopback · local_lan · public · discovery · unknown` | `decideEndpointDeclaration` — loopback/local_lan in scope; public/discovery refuse; wildcard binds (`0.0.0.0`, `::`, `*`, `[::]`) refuse REGARDLESS of declared class; unknown refuses |
| Transport outcomes | `transport_connected · transport_refused · transport_timeout · transport_reset` | facts only — none is an acceptance |
| Refusal codes | 20 closed codes (`refused_public_bind` … `refused_unknown`) | emitted only by this vocabulary |
| Close reasons | 9 closed reasons (`local_close` … `refused_by_gate`) | session machine outputs only these |
| Frame dispositions | `frame_accepted` + 9 refusal dispositions | `decideFrame` (pinned check order, §4) |
| Session states | `no_session · connected · authenticated · half_closed_local · half_closed_remote · closed · faulted` | `decideSessionTransition` (§5) — none is a trust state |
| Scopes | 6 MAY (`declare_local_endpoint`…`record_network_evidence`) vs 11 MAY-NOT (`execute_tool`, `choose_policy`, `admit_peer`, `grant_authority`, `persist_record`, `administer_peer`, `discover_peers`, `bind_public`, `traverse_nat`, `relay_cloud`, `reach_internet`) | `decideTransportScope` — MAY-NOT refuses naming its pin; unknown refuses with null pin |
| Threats | `TT-01`…`TT-18` | `classifyTransportThreat` (§6) |

**Bounds (pinned constants — refuse to widen):**
`maxFrameBytes: 8192` · `maxFramesPerWindow: 256` · `frameWindowMs: 1000` ·
`slowSenderMaxGapMs: 30000`. The caller supplies observations only; it can
exceed a bound (→ refusal) but can never redefine it.

## 4. Frame decision (deterministic, pinned precedence)

`decideFrame` checks in this exact order — first match wins (suite-pinned
with multi-violation inputs):

1. oversize/malformed (declared or actual > 8192, negative, non-integer) → `refused_oversize`
2. truncation (actual ≠ declared) → `refused_truncated`
3. integrity failure → `refused_tampered`
4. protocol version ≠ pinned expected → `refused_downgrade`
5. previously delivered (durable replay guard) → `refused_replay`
6. sequence < expected → `refused_duplicate`
7. sequence > expected → `refused_reordered`
8. frame direction blocked by half-close → `refused_half_closed_direction`
9. stale 25D disclosure binding → `refused_stale_disclosure`
10. otherwise → `frame_accepted` **as bounded, intact, in-order transport DATA only** — never acceptance/admission/authority/Policy/execution (T6/T7)

`decideSenderPace` covers the pacing threats: frames-in-window ≥ bound →
`refused_flood`; idle gap > bound → `refused_slow_sender`; otherwise OK
(which itself says nothing about identity or acceptance).

## 5. Session state machine (transport facts only)

`decideSessionTransition({state, event})` — 7 states × 8 events, every cell
deterministic (suite iterates all 56 combinations):

- **no_session + connect** → `connected` (names no peer, carries no trust).
- **connected + authenticate_ok** → `authenticated`; **authenticate_fail** → `closed(authentication_failed)`.
- **authenticated/half-close paths** → the second half-close completes → `closed(half_close_completed)`.
- **closed/faulted + connect/reconnect** → NEW `connected` session with
  `trustCarried: false` (structural literal) and
  `freshAdmissionRequired: true` — reconnect is never re-admission (T8).
- **Everything else refuses** with `refused_invalid_session_transition`, and
  the state NEVER changes on a refusal (fail closed).
- Invariant on all 56 results: `trustCarried === false`; every non-terminal
  state has `freshAdmissionRequired === true`; no state name contains any
  trust/admission/authority concept (T7).

## 6. Threat catalog TT-01..TT-18

Every pack-named threat appears exactly once with a closed disposition
(`refuse` / `close_session` / `monitor`), a refusal code from the closed
vocabulary, and ≥1 pin:

TT-01 unknown source (refuse) · TT-02 wrong key (close) · TT-03 stale session
(refuse) · TT-04 replay (refuse) · TT-05 duplicate (refuse) · TT-06 truncation
(refuse) · TT-07 oversize (refuse) · TT-08 slow sender (close) · TT-09 flood
(close) · TT-10 half-close misuse (refuse) · TT-11 reorder (refuse) · TT-12
tamper (close) · TT-13 downgrade (refuse) · TT-14 stale disclosure (refuse) ·
TT-15 peer terminal mid-session (close — the 24C registry's terminal state
wins over any transport session) · TT-16 public bind (refuse — LOCAL NETWORK
ONLY) · TT-17 remote admin (refuse — no remote control plane exists) · TT-18
direct tool (refuse — no network→tool path exists; execution stays behind
fresh LOCAL Allocation → Policy → Phase-20 → Phase-21).

## 7. Claim matrix (facts receivable, conflations refused)

- **Receivable as DATA** (they grant nothing): `reachability_fact`,
  `identity_fact`, `admission_fact`, `frame_data_fact`.
- **Refused, naming the violated pin:** session→execution (T4),
  message→policy (T5), transport-success→acceptance (T6), connection→trust
  (T7), reconnect→re-admission (T8), evidence→authority (T9).
- An empty/anonymous subject refuses before evaluation (fail closed).
- All decisions bind a deterministic `provenanceHash` (canonical 22A hash of
  schema + kind + subject + decidedAt — caller-supplied time; the module
  never reads the wall clock).

## 8. Out of scope (by pack law)

No socket or listener implementation (26B+ owns any real transport boundary
and must obey this contract) · no discovery, relay, NAT traversal, consensus,
remote authority, deployment, or Git publication · no new 22A kind, no
unfreeze event, no dependency, no store access, no Policy vocabulary, no
execution vocabulary · native Linux remains `UNSUPPORTED_ON_CURRENT_TARGET`.
