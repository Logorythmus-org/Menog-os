# Phase 24A — Federation Trust Threat Model (CONTRACT-FIRST, NO NETWORK)

**Gate:** 24A · **Date:** 2026-10-01 · **Scope:** the identity/trust/admission/message
CONTRACT layer of `packages/durable-state/src/federationIdentity.ts` and its suite
`tests/unit/federation-identity-contract.test.ts`. Transport (24D), signatures (24B),
persistence (24C), proposals (24E), and cross-node evidence (24F) are downstream and each
carries its own threat surface; 24G adversarially attacks the composition.

Central stance: **a remote peer can only ever hand us DATA to evaluate locally.**
Identity/authentication/admission/persistence/recovery/evidence never grant execution
authority. Local Policy can always deny. Fail closed.

## Trust boundary and assets

- Inside: the local runtime's durable store (22B/22D), live-owner epoch (23A/23D), Policy
  authority, Phase-20 isolation, Phase-21 junction.
- Across the boundary: signed identity documents, signed messages, admission requests.
- Assets to protect: local execution authority (must never follow from peer data), peer
  registry integrity (24C), evidence chain integrity (22C/24F), the single live-owner
  claim (23A).

## Attack catalog → control (pinned where noted)

| # | Attack | Control | Pinned by |
|:--|:--|:--|:--|
| T1 | **Spoofing** — impersonate an admitted peer | signature port must verify; invalid → `refused_signature_invalid`; shape/identity checks precede it | suite "INVALID signature spoofs nothing" |
| T2 | **Malicious authenticated peer** — valid key, hostile intent | closed field sets (unknown fields refuse), inert intent union, no execution field in any decision type; downstream gates (24C–24F) inherit | suite "unknown fields refuse"; structural scan `executionAuthorized: true` absent |
| T3 | **Replay** — re-deliver an old message | `observeMessageId`: a message id is first-observed exactly ONCE, ever; second sighting → `replay_detected` | suite "second sighting of the id is a replay" |
| T4 | **Downgrade** — force an older protocol/schema | exact equality with `menog-federation/v1` and the pinned schema versions; anything else → `refused_protocol_mismatch` / `refused_malformed` | suite "protocol downgrade and key substitution refuse" |
| T5 | **Sybil** — one operator, many cheap identities | identity documents are cheap to mint; the control is ECONOMIC+STRUCTURAL, not cryptographic: each identity is a separate peer evaluated on its own merits, admission never unions capabilities (L4), and 24C persistence makes peer facts auditable. Local Policy remains the real wall (L7). Recorded as an ASSUMPTION: admission is not scarcity | law L4 + L7; §Assumptions below |
| T6 | **Key substitution** — same NodeId, different key | NodeId = canonical injective derivation of the fingerprint; mismatch → `refused_nodeid_fingerprint_mismatch` before signature checks | suite "key substitution fails closed" |
| T7 | **Capability inflation** — peer claims broad local authority | remote vocabulary cannot express it: unknown fields refuse (L4); intent union is closed and inert (L7); decisions carry no authority fields (L1/L3) | structural scan; suite L1/L4 cases |
| T8 | **Confused deputy** — trick the local runtime into executing for the peer | structurally out of 24A's reach: no execution API exists here; any local action goes through fresh LOCAL Allocation → Policy → Phase-20 → Phase-21 (global rule); 24E pins the proposal→candidate path | module imports no execution vocabulary (scan) |
| T9 | **Lineage forgery** — fabricated causation/correlation chains | structural checks: depth bound (16), valid ids, no duplicates, no self-reference, no dangling causation, correlation ≠ self; content stays untrusted remote DATA (L9) | suite "lineage forgery variants refuse" + positive control |
| T10 | **Clock skew** — stale-dated or future-dated claims | issuance time outside ±120 s (configurable only DOWNWARD, cap 600 s) → `refused_skew_out_of_tolerance`; tolerance out of range → refuse rather than widen | suite "clock-skewed documents refuse" |
| T11 | **Split-brain identity** — one instance, two live epochs / two identities | `observeInstanceEpoch`: same-tick rival epoch → `refused_split_brain`; re-bound NodeId → `refused_identity_collision`; older epoch → `refused_stale` | suite "same-tick rival epoch and a re-bound NodeId both refuse" |
| T12 | **Quarantine resurrection** — eject then re-admit a bad peer | closed trust machine: `quarantined→[retired]`, `retired→[]`, no demotion; admission from a terminal peer → `peer_terminal_state`; re-entry only as a genuinely NEW identity evaluated as a new peer | suite "quarantined or retired sender never resurrects" |
| T13 | **Evidence forgery about the peer** — assert trust that was never granted | trust transitions REQUIRE evidence strings (unevidenced → refuse); 24C will bind them to durable records through the sanctioned coordinator; 24F binds cross-node evidence deterministically | suite "transitions require evidence" |

## Assumptions (stated, not hidden)

1. **Sybil (T5):** local-first federation has no scarce resource to gate identity minting;
   admission is therefore NOT an anti-Sybil mechanism. The real walls are: closed
   vocabularies (no capability injection), inert remote intent, and LOCAL Policy denial.
   No claim is made that admission rate-limits Sybil attacks.
2. **Key lifecycle (T6):** 24A pins the NodeId↔fingerprint relation but declares NO
   rotation/revocation semantics — that is 24B's explicitly-proven-only scope. Until 24B
   proves rotation, key replacement means a NEW NodeId (a new peer), never an in-place
   identity mutation.
3. **Time source (T10):** skew checks assume the LOCAL clock is sane. A wrong local clock
   degrades availability, not safety: too-far-off timestamps refuse (fail closed) in both
   directions.
4. **Verifier correctness (T1/T2):** 24A assumes the injected verifier is honest. A
   broken verifier is out of 24A's threat scope but NOT out of the program's: 24B must
   prove the real verifier, and 24G attacks the composition.

## Residual risks carried to later gates

- Transport-level attacks (DoS, flooding, oversized payloads) — 24D bounds payloads/counts.
- Foreign-evidence-as-authority — 24F binds evidence as DATA; 24G attacks it.
- Persistence-level attacks on peer records — 24C via the sanctioned coordinator; the 23F
  F10 class (foreign-shape writes at 22B opacity) is already fail-closed there.
- Cryptographic weaknesses of the actual primitive — 24B scope; nothing in 24A claims any.
