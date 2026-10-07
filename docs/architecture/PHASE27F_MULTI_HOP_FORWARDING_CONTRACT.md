# PHASE 27F — Multi-Hop Proposal Forwarding (Governed Logical Forwarding)

**Phase:** 27 — Governed Local Mesh & Runtime Topology
**Gate:** 27F (governed logical multi-hop forwarding over the existing sanctioned transport; FORWARD ≠ ENDORSE; immutable origin; append-only provenance; bounded hop budget; replay refused)
**Entry:** `27E_PASS` (2026-10-03 — route & path planning, 42/42). **Honest status note:** `PRE27-R1` (D-26-2 evidence-writer race repair) is **still NOT executed** — the operator sequence has run `PRE27-R0 → 27A → 27B → 27C → 27D → 27E → 27F`; D-26-2 remains carried, unrepaired (present at `scripts/phase25e-environment-probe.mjs:351`). No `PRE27_R1_PASS` is claimed anywhere.
**Status:** implemented, tested, in-memory bounded registry — no store, no socket, no clock

> **Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.**
> Separation law: `PEER ≠ PATH ≠ TOPOLOGY ≠ TRUST ≠ AUTHORITY ≠ EXECUTION`.

---

## 1. What this gate implements

`packages/durable-state/src/meshForwarding.ts` (exported from
`@menog/durable-state`) — the LOCAL logical decision layer for
governed multi-hop proposal forwarding: `ProposalForwardingRegistry`
with one method, `forward(input)`, deciding whether ONE hop of ONE
proposal through ONE forwarder may proceed. The bytes ride the
caller's existing sanctioned transport (24D/26 fixture discipline);
this module opens no socket, spawns nothing, and adds no network
surface. Pure in-memory decisions over caller-supplied facts: no
store, no clock (caller-supplied epochs only), no I/O.

## 2. FORWARD ≠ ENDORSE (the law this registry enforces)

- Every successful forward carries `endorsement: "none"` and
  `authority: "none"` as **structural literals** — relaying inert DATA
  endorses nothing, grants no trust, no admission, no authority.
- `originFixed: true` (27A M4), `capabilityWidened: false`,
  `admissionBypassed: false`, `executionAuthorized: false` are also
  structural on every success; the 27A M4 law text
  ("forwarding a proposal never makes the forwarder its origin …")
  rides into every success explanation.
- The registry has no endorse/approve/grant/authorize method: the
  prototype method set is suite-pinned to exactly `{constructor,
  fingerprint, forward, get, has, proposalCount, snapshot}`; the export
  surface is the single class; source scans pin every
  `authority:`/`endorsement:` literal to `"none"` and no trust/Policy
  token in the module.
- **Origin substitution composes the frozen 27A contract:** whenever
  `refused_origin_substitution` fires (a forwarder presenting itself as
  origin, or a later hop changing the recorded origin), the decision
  also carries the composed `decideMeshClaim({claimKind:
  "forwarder_origin_claim"})` refusal text naming the
  `FORWARDER_NOT_ORIGIN` pin and the boundary-crossing law (suite
  pins both strings).
- **Destination execution is not here:** forwarding never executes;
  `executionAuthorized: false` plus the explanation that destination
  execution still requires fresh LOCAL allocation + fresh LOCAL Policy
  for the assigned actor + frozen Phase-20/21.

## 3. Pinned semantics

**Frozen bounds (`FORWARDING_BOUNDS`; a caller may exceed a bound,
never redefine one):** `maxHops: 8` · `maxTrackedProposals: 64` ·
`maxProvenanceRefs: 16` · `maxNodeIdChars: 128` ·
`maxProvenanceRefChars: 128`.

**Identity binding (24E composition):** `proposalId` must match the
frozen 24E pattern `fp-<16hex>-<16alnum>` and `proposalHash` the
`sha256-<64hex>` ref pattern (both imported from
`federationProposals`). At first forward the id↔hash pair binds:
the same id with a different hash, or a bound hash under a different
id, refuses `refused_identity_mutation` (first binding stands).
A changed destination refuses `refused_destination_mutation`.

**Append-only provenance:** every forward presents `provenanceRefs`;
presented refs must CONTAIN every ref recorded on earlier hops
(stripping refuses `refused_provenance_stripped`); new refs append in
order, duplicates never pad. The record's `originNodeId`,
`destinationNodeId`, `proposalHash`, and first-seen
`observedAtEpochMs` are copied from the ORIGINAL record on every
continuation — later hops cannot rewrite them (the rewrite checks
refuse before any state changes).

**Bounded hop budget:** a new proposal's `hopBudgetRemaining` must be
in `[1, maxHops]`; each forward stores `presented − 1`, and a
continuation must present exactly the remaining value the last hop
left (so the budget sequence descends by exactly one: no re-inflation,
no skip, no exhaustion bypass); exhausted (0) or over-bound budgets
refuse `refused_hop_limit`; `forwardCount ≥ maxHops` refuses.

**Sequence + replay context:** a new proposal must start at hop 0 and
a continuation's `hopIndex` must equal the recorded `forwardCount`
(ahead refuses `refused_hop_out_of_sequence`); a completed hop
re-presented (behind) or a forwarder already IN the recorded chain
refuses `refused_replay`. Refusals leave the registry byte-identical
(count + fingerprint + record deep-equality suite-pinned).

**Transport-boundary hygiene (25D composition):** every string surface
is scanned by the frozen egress classifier BEFORE anything is recorded
— secret material (incl. JSON-nested payloads parsed at depth),
executable material, and forbidden material (paths/handles/env/raw
output/policy text) refuse with their own codes. Material outranks the
semantic laws (data safety first, pinned).

**Pinned validation order (first match wins):** shape (24E identity
patterns, distinct origin/destination/forwarder, safe types, finite
time) → field bounds → material scan → forwarder == origin →
hash-under-other-id → registry capacity (new only) → recorded rules
(origin → hash → destination → provenance subset → chain replay →
hop-behind replay → hop sequence → budget continuity/bound) → new
rules (hop 0, budget within [1, maxHops]) → record updated frozen →
success literals.

**Refusal vocabulary:** closed, 14 codes, `Object.freeze`d; every code
carries an explanation (suite-pinned from source).

**Snapshot/fingerprint:** `snapshot()` canonically sorted by
proposalId and frozen (records, chains, refs);
`fingerprint()` = canonicalHash over sorted per-record hashes — pure,
order-insensitive, deterministic.

**Docs:** `docs/architecture/PHASE27F_MULTI_HOP_FORWARDING_CONTRACT.md`
(this file).

## 4. Scope law (LOCAL-ONLY)

No discovery/scanning/mDNS/broadcast/gossip membership/WAN/Internet/
cloud relay/NAT traversal/UPnP/tunnel/consensus/global authority; no
socket, no listener, no spawn, no clock, no store access (in-memory
bounded registry only); no alternate listener/spawn/persist/control
path; no tool or Policy surface. Observability is read-only
(`snapshot`/`fingerprint`), never control. Suite-pinned: 29 forbidden
surfaces absent from module source, imports pinned to
`{./canonical.js, ./federationEgress.js, ./federationProposals.js,
./meshTopologyTrust.js}`, zero network-call tokens (independently
grep-verified against verify-local's pattern list).

## 5. Test suite

`tests/unit/mesh-forwarding.test.ts` — **36/36**: structural pins
(vocabularies, bounds, 29 forbidden surfaces, import pin, zero-
authority/zero-endorsement literal scan, forbidden law tokens, single-
class export + pinned prototype method set, no instance fields) ·
governed chain (first forward budget 8→7, three-hop accumulation with
origin/identity fixed, byte-identical fresh registries, independent
proposals) · hop limits (birth bound `[1,8]` ×3, non-integer malformed,
full 8-hop consumption + ninth refusal with fingerprint invariance,
budget continuity ×5 with invariance) · origin immutability (forwarder
== origin with composed 27A pin + boundary text, recorded-origin
change refused with record kept, substitution outranks sequence) ·
identity/destination (id with new hash, bound hash under new id,
changed destination — all with record + fingerprint invariance) ·
provenance (stripping refused + history unchanged, append with
dedupe) · replay/sequence (identical re-forward, chain member again,
behind = replay vs ahead = out-of-sequence vs new-not-at-0) ·
registry bound (65th new refuses, recorded still advances at capacity)
· material (JSON-nested secret, shell, local path, material outranks
origin substitution) · malformed ×16 + field bounds ×3 · observability
(sorted frozen snapshots across insertion orders, every refusal class
leaves the registry byte-identical, empty fingerprints, all 14
explanations in source).
