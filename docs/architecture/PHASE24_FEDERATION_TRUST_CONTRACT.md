# Phase 24A — Federation Runtime Identity & Trust Architecture (CONTRACT-FIRST, NO NETWORK)

**Gate:** 24A · **Date:** 2026-10-01 · **Status:** CONTRACT ONLY — no transport, no
discovery, no execution API exists. 24B supplies real signatures behind the verifier port;
24C persists peer facts through the sanctioned durable path; 24D wires the message pipeline.

Composes the frozen vocabulary — **never forks it**:

- **23A runtime epochs** (`menog-runtime-continuity/v1`): `RuntimeEpochId`
  (`re-<ts12>-<rnd16>`), the BOOTING→RECOVERING→RECONCILED→READY→LIVE machine, and the L5
  stale-epoch law. A peer's epoch is a **23A epoch**; freshness is observed, never claimed.
- **22A closed record/authority vocabulary** and `canonicalHash` (deterministic canonical
  hashing over `menog-durable-record/v0`-style bodies) for all provenance bindings (L9).
- **Repository terminal-lifecycle law** (21A/22D registry: quarantined → retired only,
  retired terminal, no resurrection) mirrored into the peer trust machine (L6).

## 1. The identity stack

| Concept | Type | Scope | Derivation |
|:--|:--|:--|:--|
| Public fingerprint | `NodeFingerprint` (`fp-<hex32..128>`) | a KEY | produced by 24B |
| Node identity | `NodeId` (`node-<same hex as fingerprint>`) | a PEER | canonical, injective: `deriveNodeId(fingerprint)` — a NodeId IS its fingerprint |
| Installation | `RuntimeInstanceId` (`ri-<ts12>-<rnd12>`, pattern-pinned) | an install of the runtime on one host | fresh at install, stable across restarts |
| Incarnation | `RuntimeEpochId` (23A pattern `re-<ts12>-<rnd16>`) | one live-owner process | fresh per process start |

**Instance/epoch relation (fail-closed):** one instance has many epochs over its life; an
epoch belongs to exactly one instance. An instance that presents a second identity, or a
rival same-tick epoch, is refused (`observeInstanceEpoch`: `refused_identity_collision`,
`refused_split_brain`). An epoch older than the instance's newest observed epoch is stale
(`refused_stale`). The tracker is pure caller-owned state; 24C persists the facts.

**Key substitution (L1):** because the NodeId is the canonical function of the
fingerprint, "same NodeId, different key" is structurally detectable:
`nodeIdMatchesFingerprint` refuses, before signature checks.

## 2. The nine laws and where they live in code

Module: `packages/durable-state/src/federationIdentity.ts` (exported from
`@menog/durable-state`). Suite: `tests/unit/federation-identity-contract.test.ts`.

| Law | Statement | Code surface |
|:--|:--|:--|
| L1 | identity ≠ authority | no type carries `executionAuthorized`/`policyAuthorized`; `deriveNodeId`/`nodeIdMatchesFingerprint` make key substitution fail closed |
| L2 | authentication ≠ authorization | `validateNodeIdentityDocument` / `validateSignedMessageContract` accept a VALID signature with `authority: "none"` provenance, permanently |
| L3 | peer admission ≠ execution permission | `decidePeerAdmission` outcomes (`admit`/`quarantine`/`refuse`) move TRUST STATE only; the decision type has no execution field |
| L4 | federation ≠ capability union | exact-key-shape validation on documents and messages — unknown fields (e.g. a smuggled `grantedCapabilities` / `localPolicyOverride`) refuse; `FEDERATION_DECLARED_INTENTS` is a closed inert union |
| L5 | stale epochs fail | `observeInstanceEpoch` refuses older-than-newest and same-tick rivals; reuses the frozen 23A `RUNTIME_EPOCH_ID_PATTERN` |
| L6 | quarantined/retired never resurrect | `PEER_TRUST_TRANSITIONS` closed machine (`quarantined→[retired]`, `retired→[]`, no demotion path); `decidePeerAdmission` refuses terminal senders (`peer_terminal_state`) |
| L7 | remote claims never broaden local Policy | the module imports no policy vocabulary; remote intent fields are inert DATA; message bodies with unknown fields never enter |
| L8 | replay/protocol/schema mismatch fail closed | `observeMessageId` (once-ever ids), exact `protocolVersion`/`schemaVersion` equality (downgrades refuse), structural lineage checks (depth bound, acyclicity, no self-reference, no dangling causation) |
| L9 | admitted facts are provenance-bound | every decision embeds `FederationProvenanceBinding` = deterministic `canonicalHash(subject)` + sender identity/epoch + protocol + local epoch + `authority: "none"` |

**Clock skew:** timestamps are advisory evidence, never authority; a document/message
whose issuance time is more than `FEDERATION_CLOCK_SKEW_TOLERANCE_MS` (120 s; cap
600 s) from local time refuses (`refused_skew_out_of_tolerance`) rather than being
silently accepted.

## 3. What 24A does NOT do

- **No network:** no sockets, no HTTP, no listeners; the module imports no
  `node:net`/`node:http`/`node:crypto` and no process primitive (pinned by scan).
- **No crypto:** signatures are opaque strings checked through the caller-injected
  `IdentitySignatureVerifier` port. 24B owns algorithms, canonical encoding, rotation.
- **No persistence:** peer facts are not written anywhere by 24A; 24C persists through
  the sanctioned durable coordinator and inherits the recovered-data/no-authority law.
- **No execution:** nothing here can reach the planner, allocation, Policy, Phase-20
  isolation, or the Phase-21 junction. A remote `task_proposal` is DATA for a future
  local decision (24E), never a task.

## 4. Decision pipelines (fail-closed order)

**Identity document:** exact shape/unknown fields → schema version → NodeId↔fingerprint
(L1) → protocol version (downgrade) → signature (port) → skew window → instance/epoch
observation (L5, split-brain, identity collision) → accept with provenance.

**Signed message:** exact shape/unknown fields → schema → message-id shape →
NodeId↔fingerprint → protocol → signature → skew → lineage well-formedness → replay
(once-ever) → instance/epoch observation → accept with provenance.

**Peer admission:** request shape → request skew → full identity-document pipeline →
terminal-state refusal (L6) → trust-transition legality → admit/quarantine/refuse with
provenance.

Every refusal explains itself and binds provenance where the subject was well-formed
enough to hash; nothing is silently dropped.
