# Phase 25A — Operational Federation Trust Boundary Architecture (CONTRACT-FIRST, NO NETWORK)

**Gate:** 25A · **Date:** 2026-10-01 · **Status:** CONTRACT ONLY — no transport, no
discovery, no listener, no execution API exists. This gate models the OPERATIONAL trust
boundary around the frozen Phase-24 foundation and adds zero new authority.

Composes the frozen vocabulary — **never forks it**:

- **24A** identity/trust/admission/message contract (nine laws L1–L9; `NodeId`,
  `RuntimeInstanceId`, 23A epochs, the closed peer trust machine).
- **24B** memory-only private-key law and rotation = re-identity.
- **24C** durable peer trust facts through the sanctioned 23B coordinator junction.
- **24D** in-process bounded message pipeline (the only "transport": bounded FIFO fixtures).
- **24E/24F** proposal/provenance DATA surfaces.
- **22A/22B/22E/23A/23D** durable semantics, transactional committed-or-absent mutations,
  recovery-as-`recovered_data`, and the epoch/LIVE machine.

## 1. Module and suite

Module: `packages/durable-state/src/federationTrustBoundary.ts` (exported from
`@menog/durable-state`). Suite: `tests/unit/federation-trust-boundary.test.ts`.

## 2. The seven operational pins (P1–P7)

Pinned as a closed, ordered vocabulary (`OPERATIONAL_TRUST_PINS`) with deterministic,
closed explanation strings (`OPERATIONAL_TRUST_PIN_EXPLANATIONS`) that decisions embed
verbatim — explanations are stable and greppable, never free-form authority prose:

| Pin | Statement |
|:--|:--|
| P1 | `IDENTITY != AUTHORITY` — a NodeId, instance, or epoch is a NAME, never a permission |
| P2 | `AUTHENTICATION != ADMISSION` — a verified signature proves provenance of DATA; it never moves trust state by itself |
| P3 | `ADMISSION != EXECUTION` — admitted peers gain communication trust only; execution stays behind fresh LOCAL Allocation → Policy → Phase-20 → Phase-21 |
| P4 | `EVIDENCE != AUTHORITY` — durable evidence records what HAPPENED; consuming it grants nothing |
| P5 | `RECOVERY != AUTHORITY` — recovered facts are `recovered_data` with zero authority, across every restart |
| P6 | `KEY_POSSESSION != POLICY_ALLOW` — holding or copying key material never yields a Policy decision |
| P7 | `ROTATION DOES NOT INHERIT TRUST` — a rotated identity is a NEW peer; trust transfers only through a LOCAL, EVIDENCED decision |

## 3. The boundary planes and what each may decide

`TRUST_BOUNDARY_PLANES` is closed and covers exactly the pack's model set — local operator,
runtime epoch, identity key material, peer identity/trust, key storage, ingress, egress,
durable evidence, policy, execution, restart/recovery. `TRUST_BOUNDARY_PLANE_DECISIONS`
gives each plane a MAY / MAY NOT statement; no plane statement claims execution or
authority-widening power (suite-pinned):

| Plane | MAY (summary) | MAY NOT (summary) |
|:--|:--|:--|
| local_operator | create/rotate identity, quarantine/retire peers, judge evidence, choose Policy inputs | mint authority bypassing fresh LOCAL Policy |
| runtime_epoch | own the single live-owner claim (23A), refuse stale/rival epochs | grant execution; LIVE is process scope |
| identity_key_material | sign local outbound facts (24B) | authorize admission, execution, or Policy (P6) |
| peer_identity_trust | hold peer trust STATE per the closed machine (24A/24C) | convert trust state into execution permission (P3) |
| key_storage | hold PUBLIC material durably; PRIVATE material memory-only | persist private keys/secrets into durable state or evidence (pack law) |
| ingress | deliver untrusted DATA into typed inboxes after the 24D checks | execute, persist raw payloads as authority, bypass the pipeline |
| egress | emit locally signed facts the operator chose to share | disclose private keys or evidence beyond the operator's explicit release |
| durable_evidence | record happenings tamper-evidently (22C/24F) | authorize anything on read (P4) |
| policy | deny by default; allow only fresh LOCAL decisions for assigned actors | accept remote claims as policy inputs (P6/L7) |
| execution | run only behind fresh LOCAL Allocation + Policy + Phase-20 + Phase-21 | exist on any federation→tool path; no capability union |
| restart_recovery | re-derive public facts, expose `recovered_data`, require NEW fresh local authority | auto-resume, auto-re-admit, restore pre-restart authority (P5) |

## 4. The key-storage boundary (P6 in code)

`authorizeKeyMaterialPlacement` is the pure, fail-closed decision over the closed
`KEY_MATERIAL_CLASSES × KEY_STORAGE_LOCATIONS` vocabulary:

- `private_signing_key` is permitted ONLY in `memory_only` (the 24B law).
- `private_signing_key` in `durable_store` / `durable_evidence` / `outbound_message` is a
  **FINDING** with distinct deny codes (`private_key_at_rest_denied`,
  `private_key_in_evidence_denied`, `private_key_in_egress_denied`) — never normalized,
  never repaired; remediation is rotation to a fresh identity.
- `public_identity_facts` / `derived_public_facts` may be stored or shared — they
  authenticate, never authorize.
- `unknown` material or location refuses rather than guessing.

## 5. Operational risk vocabulary (closed; every pack threat modeled)

`OPERATIONAL_RISK_IDS` (OT-01..OT-12) covers every threat the pack names exactly once;
`classifyOperationalRisk` maps one closed `OperationalSignal` to a risk id, a closed
disposition (`contain | refuse | quarantine | investigate | monitor`), invoked pins, and a
DETERMINISTIC explanation (same signal → same classification, suite-pinned):

| Risk | Signal | Disposition |
|:--|:--|:--|
| OT-01 unknown peer | `peer_unknown` | monitor (first contact only as candidate) |
| OT-02 revoked peer | `peer_revoked` | refuse (terminal states never resurrect) |
| OT-03 compromised peer | `peer_key_changed` | quarantine (old trust does not extend to the new key, P7) |
| OT-04 stale peer | `peer_epoch_stale` | refuse (24A L5) |
| OT-05 copied key material | `key_material_copy_detected` | quarantine (a copy is a compromised identity, not a second node) |
| OT-06 malicious payload | `payload_rejected` | contain (untrusted DATA stays in the typed inbox) |
| OT-07 replayed message | `message_replayed` | refuse (durable replay guard, zero signature evaluation) |
| OT-08 local attacker | `local_policy_denied` | contain (a fresh LOCAL deny is final and proven valid) |
| OT-09 operator error | `operator_action_out_of_band` | investigate (intent only via sanctioned decision surfaces) |
| OT-10 clock anomaly | `clock_skew_exceeded` | refuse (skewed claims refused, never silently accepted) |
| OT-11 crash during trust mutation | `trust_mutation_interrupted` | investigate (committed-or-absent per 22B; completion needs a NEW evidenced decision) |
| OT-12 untrusted evidence consumer | `evidence_replayed_as_authority` | contain (consumers re-derive authority locally) |

## 6. Boundary claims: receivable DATA vs boundary-crossing authority

`decideBoundaryClaim` decides, deterministically and with a canonical provenance hash over
(claim kind, peer, local epoch, decision time), whether a claim stays inside the boundary:

- `identity_claim`, `authentication_claim`, `admission_claim`,
  `evidence_authority_claim`, `recovery_authority_claim` are **receivable** — precisely
  because each grants nothing (the embedded pin explanation says which).
- `execution_claim`, `key_possession_authority_claim`, `rotation_trust_claim`
  **cross the boundary** and are refused, naming the violated pin (P3 / P6 / P7).
- An anonymous claim (empty peer id) cannot even be evaluated as DATA — refused under P1.

## 7. The restart/recovery boundary (P5/P7 in code)

`decideRestartRecovery` classifies closed `RestartSurvivorKind` facts: peer trust registry
facts, durable evidence records, `federation_receipt`/`federation_proposal`/
`federation_provenance_anchor` records all re-enter as
`recovered_as_data_zero_authority`; an `interrupted_trust_mutation` re-enters as
`recovered_as_data_requires_fresh_evidence` — committed-or-absent per the frozen 22B
transactional semantics, never auto-completed. Unknown survivors refuse.

## 8. Deterministic explanations and provenance

Every decision embeds (a) the closed pin explanation(s) it invokes and (b) where
applicable a canonical hash (`trustBoundaryFingerprint`, `provenanceHash`) binding the
local epoch, the subject, and the decision time. Identical inputs yield byte-identical
explanations (suite-pinned).

## 9. Out of scope (unchanged pack law)

No real LAN/WAN listener, discovery, cloud relay, NAT traversal, public endpoint, or
consensus. No key-lifecycle automation beyond what 24B froze (rotation = re-identity). No
new unfreeze events, no new durable record kinds, no store schema changes. Downstream
gates (25B–25I) build operational procedures ON this boundary; none may widen it.
