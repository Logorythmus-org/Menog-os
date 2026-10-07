# Phase 25A — Operational Federation Threat Model (CONTRACT-FIRST, NO NETWORK)

**Gate:** 25A · **Date:** 2026-10-01 · **Scope:** the OPERATIONAL trust boundary of
`packages/durable-state/src/federationTrustBoundary.ts` and its suite
`tests/unit/federation-trust-boundary.test.ts`, composed over the frozen Phase-24 stack
(24A–24F) and the frozen durable/continuity machinery (22A–22E, 23A–23D).

Central stance (unchanged from 24A, now operationalized): **a remote peer, a possession of
keys, a verified signature, an admission decision, a durable record, and a recovery are all
DATA or FACTS — none of them is authority.** Authority is produced only by fresh LOCAL
Allocation → LOCAL Policy (for the assigned actor) → Phase-20 isolation → Phase-21 governed
tool runtime. Fail closed, everywhere, deterministically.

## Trust boundary and assets

- Inside the boundary: the local operator's decisions (through sanctioned surfaces), the
  single live-owner epoch (23A), the durable store (22B/22D), the evidence chain
  (22C/24F), Policy authority, Phase-20 isolation, Phase-21 junction.
- Across the boundary (inbound DATA): signed identity documents, signed messages,
  admission requests, proposals, provenance anchors, receipts — and CLAIMS about all of
  the above.
- Assets to protect: local execution authority (must never follow from peer data or key
  possession), the private signing key (memory-only, 24B), peer registry integrity (24C),
  evidence integrity (22C/24F), the single live-owner claim (23A).

## The seven pins as the control frame

Every threat below is answered by one or more of P1–P7 (see
`docs/architecture/PHASE25A_TRUST_BOUNDARY_CONTRACT.md` §2). The pins are machine-readable
vocabulary in the module; the suite pins their exact statements and their embedding in
decisions.

## Threat catalog → control (pinned where noted)

| # | Threat (pack-named) | Control | Pinned by |
|:--|:--|:--|:--|
| T1 | **Unknown peer** — first contact | enters only as `candidate`; treated as untrusted DATA source (24A/24C); classified OT-01 `monitor` | suite classification table |
| T2 | **Revoked peer** — quarantined/retired returns | terminal states never resurrect (24A L6); traffic refused pre-signature, no oracle; OT-02 `refuse` | suite "revoked/stale/replay refuse" |
| T3 | **Compromised peer** — key change / key copy | key change or a copied key ⇒ COMPROMISED: quarantine pending local evidenced investigation; old trust does NOT extend to the new key (P7); OT-03/OT-05 `quarantine` | suite "compromised/copy demand quarantine" |
| T4 | **Stale peer** — rolled-back or replayed sender epoch | older-than-newest epochs refuse (24A L5); OT-04 `refuse` | suite classification table |
| T5 | **Copied key material** — same key, two trust contexts | a copy is a compromised identity, not a second node (P6: possession never authorized anything); only quarantine + re-identity exit; OT-05 `quarantine` | suite key-copy case |
| T6 | **Malicious payload** — hostile DATA after authentication | closed-shape validation refuses unknown fields (24A L4/24E); payload contained in the typed inbox; never reaches tools/Policy inputs/authority records; OT-06 `contain` | suite classification table |
| T7 | **Replay** — re-delivered message ids | durable receipt-index guard refuses with zero signature evaluation (24D); OT-07 `refuse` | suite classification table |
| T8 | **Local attacker** — malicious process on the host | fresh LOCAL Policy deny is final and cannot be overridden by identity/admission/evidence (P1/P3/P6); durability + isolation contain blast radius; OT-08 `contain` | suite local-policy-denied case |
| T9 | **Operator error** — out-of-band intent | operator intent is captured ONLY through sanctioned evidenced decision surfaces (quarantine/retire/admit with evidence, Policy through the engine); out-of-band intent is investigated, never silently applied; OT-09 `investigate` | suite classification table |
| T10 | **Clock anomaly** — skewed/rollback clocks | issuance timestamps outside the 24A tolerance refuse (`refused_skew_out_of_tolerance`); tolerance cannot be widened beyond the pin; OT-10 `refuse` | suite classification table |
| T11 | **Crash during trust mutation** | 22B transactional semantics: committed-or-absent, no third state visible; the recovered view is `recovered_data`; completion requires a NEW evidenced local decision — never auto-completed (P5/P7); OT-11 `investigate` | suite interrupted-mutation case |
| T12 | **Untrusted evidence consumer** — evidence replayed as authority | evidence stays inert on read (P4/P5); consumers must re-derive authority through fresh LOCAL decisions; OT-12 `contain` | suite evidence-as-authority case |
| T13 | **Execution claim at the boundary** — any claim that execution/authority follows from peer-side state | `decideBoundaryClaim` refuses with `ADMISSION_NOT_EXECUTION` (P3) | suite boundary-claim refusals |
| T14 | **Key-possession authority claim** — "I hold keys, therefore allow" | refused with `KEY_POSSESSION_NOT_POLICY_ALLOW` (P6) | suite boundary-claim refusals |
| T15 | **Rotation trust claim** — "the rotated identity inherits" | refused with `ROTATION_NO_TRUST_INHERITANCE` (P7); inheritance only via LOCAL evidenced re-admission | suite boundary-claim refusals |
| T16 | **Private-key escape** — key at rest / in evidence / in egress | `authorizeKeyMaterialPlacement` denies with distinct FINDING codes; never normalized; remediation = rotation; OT-class containment | suite key-storage cases |

## Assumptions (stated, not hidden)

1. **The host is not compromised below the runtime.** A kernel/root attacker can read
   process memory (including memory-only keys) and is OUT of scope for the boundary — the
   boundary contains FEDERATION and OPERATIONAL risk, not full host compromise. (Consistent
   with the 24A threat model's Sybil/economic assumptions.)
2. **The operator is the top authority but not an execution path.** Operator intent acts
   only through sanctioned evidenced surfaces; even a human decision executes nothing by
   itself (P3 — the human is inside the boundary, not a bypass of it).
3. **Clocks are advisory.** Timestamp evidence informs decisions but the skew guard is the
   only clock-based REFUSAL; no decision treats time as authority.
4. **Evidence consumers are code the local runtime runs** — the boundary pins that even
   local consumers re-derive authority; no record grants anything on read (P4/P5).

## Dispositions and what they may trigger

`contain | refuse | quarantine | investigate | monitor` — all five affect TRUST STATE or
LOCAL JUDGMENT only. None executes anything. Quarantine/refuse map onto the frozen 24A/24C
trust machine; investigate/monitor produce evidence for the operator. This is the
operational bridge: later Phase-25 gates (25C peer trust operations, 25F crash
qualification, 25G adversarial hardening) build procedures on these dispositions WITHOUT
widening them.
