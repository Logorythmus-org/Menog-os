# PHASE 26A — Local Network Transport Threat Model

**Date:** 2026-10-02 · **Mode:** CONTRACT-FIRST / NO NETWORK / SAFE LOCAL FIXTURES
**Scope:** the transport trust model only — every control lives in
`packages/durable-state/src/federationTransportTrust.ts`; no real socket exists
at this gate, so all tests exercise the contract's deterministic decisions.

---

## 1. Adversary and assets

- **Adversary:** a remote peer (admitted, formerly-admitted, or unknown) that
  can send arbitrary bytes, reorder/duplicate/replay them, flood or trickle
  them, claim identities/sessions/acceptance, or attempt to bind public
  interfaces; also a local process attempting to widen transport scope.
- **Assets:** local trust state (the frozen 24C registry), local Policy
  decisions (25A/Day-1), execution authority (19B allocation → Phase-20/21),
  disclosure freshness (25D), evidence integrity (22C/24F), and the LOCAL
  NETWORK ONLY boundary itself.
- **Trusted computing base:** the local operator, the frozen 24A–24F
  federation stack, the 25A–25D operational layers, the 23B persistence
  junction, and this contract. Host-below-runtime compromise stays out of
  scope (carried from 25A).

## 2. What this gate does NOT protect against (honest boundaries)

- It ships **no socket**, so wire-level attacks (MITM on the medium, OS-level
  eavesdropping) are not yet in scope — they arrive with 26B/26C and every
  frame/session decision here is their pre-condition.
- It performs **no cryptographic verification** (24B owns that); integrity and
  authentication arrive as caller-supplied facts.
- It **grants nothing** — even a fully accepted frame is transport DATA only.

## 3. Threats → controls (TT-01..TT-18)

| ID | Threat | Control (deterministic) | Pin(s) |
|:--|:--|:--|:--|
| TT-01 | unknown source | refuse before evaluation; unnamed sources are DATA at best | T1/T2 |
| TT-02 | wrong key | close_session — 24B verification result closes, never "fails forward" | T2 |
| TT-03 | stale session | refuse — session state never was trust state | T7 |
| TT-04 | replay | refuse at the durable replay guard, zero downstream evaluation | T6 |
| TT-05 | duplicate | refuse (sequence < expected) | T6 |
| TT-06 | truncation | refuse (actual ≠ declared bytes) — never pad or guess | T6 |
| TT-07 | oversize | refuse against the PINNED 8192 B bound — bound cannot widen | T6 |
| TT-08 | slow sender | close_session past the pinned 30 000 ms idle gap | T7 |
| TT-09 | flood | close_session past the pinned 256 frames/1000 ms window | T7 |
| TT-10 | half-close misuse | refuse frames in a half-closed direction | T7 |
| TT-11 | reorder | refuse (sequence > expected) — strict in-order, no gap-fill | T6 |
| TT-12 | tamper | close_session on integrity failure | T6 |
| TT-13 | downgrade | refuse on exact-equality protocol version mismatch — never negotiated down | T6 |
| TT-14 | stale disclosure | refuse a stale 25D disclosure binding — a prior disclosure never authorizes a later send | T9 |
| TT-15 | peer terminal mid-session | close_session when the 24C registry says quarantined/retired — transport never overrides terminal trust | T2/T7 |
| TT-16 | public bind | refuse at the contract layer — LOCAL NETWORK ONLY; wildcard binds refuse regardless of declared class | T1 |
| TT-17 | remote admin | refuse — no remote control plane exists; a peer message can never be an admin command (25C law) | T3 |
| TT-18 | direct tool | refuse — no network→tool path exists; execution stays behind fresh LOCAL Allocation → Policy → Phase-20 → Phase-21 | T4 |

## 4. Cross-cutting laws under attack

| Attacker goal | Why it fails |
|:--|:--|
| Make reachability imply identity (T1) | endpoint/claim decisions refuse; reachability facts are DATA only |
| Turn identity into admission (T2) | admission stays in 24C; every usable session sets `freshAdmissionRequired` |
| Turn admission into authority (T3) | `grant_authority`/`administer_peer` are in the closed MAY-NOT set and refuse naming their pin |
| Execute via an authenticated session (T4) | `execute_tool` refuses; zero execution vocabulary in the module (structural scan) |
| Smuggle a Policy decision via a message (T5) | `choose_policy` refuses; frame bytes are untrusted DATA |
| Claim bytes-sent = accepted (T6) | every frame decision carries T6; acceptance explanations state "NOT application acceptance" |
| Treat connection events as trust events (T7) | `trustCarried` is structurally `false` on all 56 transitions |
| Reconnect = re-admission (T8) | reconnect starts a zero-trust session requiring fresh admission |
| Replay transport evidence as authority (T9) | `persist_record`/evidence-authority claim refuse |
| Widen a bound or add a capability | bounds are frozen constants; scope vocabulary is closed; unknown values refuse |

## 5. Pinning suites and assumptions

- `tests/unit/federation-transport-trust.test.ts` (30 tests): structural
  no-socket scan (14 forbidden surfaces + crypto/store/execution tokens),
  vocabulary exact-equality pins, endpoint/frame/pace/session/scope/claim/
  threat decisions incl. the full 56-cell session matrix, determinism
  (same input → identical output incl. provenance hash), and fingerprint
  determinism.
- Assumptions: caller-supplied facts (integrity, admission, disclosure
  freshness) are produced by the frozen 24B/24C/25D layers; the caller is
  local code, not the network; clocks are caller-supplied (`decidedAtEpochMs`)
  — this module never reads the wall clock.
- Residual risk: real-socket behaviors (accept/backlog/EPIPE/half-close at
  the OS level) are untested until 26B/26C; that debt is explicit and owned
  by those gates.
