# PHASE 27D — Capability Advertisement (Bounded Versioned Provenance-Rich Untrusted Claims)

**Phase:** 27 — Governed Local Mesh & Runtime Topology
**Gate:** 27D (capability advertisements recorded as UNTRUSTED REMOTE CLAIMS; ADVERTISEMENT ≠ GRANT; bounded, versioned, provenance-rich; material rejection; rotation replaces — never unions)
**Entry:** `27C_PASS` (2026-10-03 — node & edge lifecycle, 33/33). **Honest status note:** `PRE27-R1` (D-26-2 evidence-writer race repair) is **still NOT executed** — the operator sequence has run `PRE27-R0 → 27A → 27B → 27C → 27D`; D-26-2 remains carried, unrepaired (present at `scripts/phase25e-environment-probe.mjs:351`). No `PRE27_R1_PASS` is claimed anywhere.
**Status:** implemented, tested, in-memory bounded registry — no store, no socket, no clock

> **Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.**
> Separation law: `PEER ≠ PATH ≠ TOPOLOGY ≠ TRUST ≠ AUTHORITY ≠ EXECUTION`.

---

## 1. What this gate implements

`packages/durable-state/src/meshCapabilityAdvertisement.ts` (exported from
`@menog/durable-state`) — the LOCAL registry of capability advertisements:
bounded, versioned, provenance-rich records of what some node CLAIMS it
can do. Every record is an UNTRUSTED REMOTE CLAIM recorded as DATA — the
registry stores claims, it never honors them. Pure in-memory decisions
over caller-supplied facts: no store, no socket, no clock (caller-supplied
epochs only), no I/O.

## 2. ADVERTISEMENT ≠ GRANT (the law this registry enforces)

- Every successful decision carries `grant: "none"` and
  `capabilitiesWidened: false` as **structural literals** (27A pin M5).
- No record has a capability, authority, Policy, trust, or execution
  field; the stored shape is knowledge only (`StoredCapabilityAdvertisement`
  = input fields + `contentHash`).
- No method widens agent/tool/Policy/isolation capability, and **no
  union/merge surface over claims exists**: the prototype method set is
  pinned by suite to exactly `{advertisementCount, constructor,
  fingerprint, get, has, record, snapshot}` — a name matching
  union/merge/grant/widen/execut/allow/authority/trust fails the pin.
  Extra input fields are DROPPED, never stored.
- Recording, rotating, or replaying claims changes only stored knowledge;
  rotation **REPLACES** the previous claim set outright — old claims are
  dropped, never accumulated (suite asserts the pre-rotation claims are
  absent from the stored record).

## 3. Pinned semantics

**Frozen bounds (`ADVERTISEMENT_REGISTRY_BOUNDS`; a caller may exceed a
bound, never redefine one — refusal, never truncation, never eviction):**
`maxAdvertisements: 64` · `maxAdvertisementsPerClaimant: 8` ·
`maxClaimsPerAdvertisement: 4` · `maxAdvertisementIdChars: 128` ·
`maxClaimantIdChars: 128` · `maxDetailChars: 512`.

**Provenance (closed — records enter ONLY from sanctioned sources):**
`local_configuration` · `governed_evidence` · `unknown_source`
(exists to be **refused**, never recorded). Governed evidence MUST cite
its `evidenceId` (null/empty refuses `refused_invalid_provenance`);
local configuration MUST NOT pretend to (non-null refuses);
`recordedAtEpochMs` must be finite and ≥ 0. Every decision carries a
64-hex `provenanceHash`.

**Material rejection (before anything is recorded):** every string
surface (ids, claims, detail, provenance) is scanned by the frozen 25D
egress classifier (`findEgressFindings`) for secret material
(`refused_secret_material`), executable material
(`refused_executable_material`), and other forbidden content — local
paths, handles, env, raw output, policy text
(`refused_forbidden_material`). **JSON-nested payloads are parsed at
depth**, so a `private_key` field cannot hide inside a JSON string
(detail or claim). Any finding refuses the whole advertisement.

**Frozen 27A composition:** anonymity, the closed claim vocabulary, and
the known-kind gate are decided by `decideMeshAdvertisement` (27A) and
its refusals propagate through `mapMeshRefusal` unchanged
(`refused_anonymous_claim`, `refused_unknown_capability_claim`,
`refused_unknown_advertisement_kind`, else `refused_unknown`). On top of
27A, this registry stores **capability advertisements only** — a valid
but non-capability kind (e.g. `topology_advertisement`) refuses
`refused_wrong_advertisement_kind`.

**Versioning (integer version ≥ 1; first match wins):**
1. existing id from ANOTHER claimant → `refused_claimant_mismatch`
   (no hijack, no overwrite)
2. same version: identical content → `advertisement_replayed`
   (idempotent no-op, counts unchanged); different content →
   `refused_version_conflict` (first evidenced claim stands)
3. lower version → `refused_stale_version` (a rotated-out claim never
   comes back)
4. jump beyond +1 → `refused_version_gap` (no unseen claim skips in)
5. rotation (+1): requires **strictly fresher**
   `provenance.recordedAtEpochMs` AND never-older `observedAtEpochMs`,
   else `refused_stale_fact`; the old claim set is REPLACED
6. new id: must be version 1 (`refused_version_gap`), then
   per-claimant bound (`refused_claimant_bound`), then registry bound
   (`refused_registry_bound`) — refuse, never evict
7. record added, frozen.

**Pinned validation order (first match wins):** provenance source →
provenance shape → record shape (`refused_invalid_advertisement`) →
field bounds (`refused_oversize_field`) → claim inflation (count or
duplicate → `refused_claim_inflation`) → material scan → 27A decision →
kind gate → registry state. Any refusal leaves the registry EXACTLY as
it was (suite-pinned via count + fingerprint invariance).

**Refusal vocabulary:** closed, 20 codes, `Object.freeze`d; every code
carries an explanation (suite-pinned from source).

**Snapshot/fingerprint:** `snapshot()` is canonically sorted by
`advertisementId` and frozen (records, claims, provenance);
`fingerprint()` = canonicalHash over sorted content hashes — pure,
order-insensitive, deterministic (two registries with the same records
in different insertion orders fingerprint identically).

**Docs:** `docs/architecture/PHASE27D_CAPABILITY_ADVERTISEMENT_CONTRACT.md`
(this file).

## 4. Scope law (LOCAL-ONLY)

No discovery/scanning/mDNS/broadcast/gossip membership/WAN/Internet/
cloud relay/NAT traversal/UPnP/tunnel/consensus/global authority; no
socket, no listener, no spawn, no clock, no store access (in-memory
bounded registry only); no alternate listener/spawn/persist/control
path. Observability is read-only (`snapshot`/`fingerprint`), never
control. Suite-pinned: 29 forbidden surfaces absent from module source,
imports pinned to `{./canonical.js, ./federationEgress.js,
./meshTopologyTrust.js}`.

## 5. Test suite

`tests/unit/mesh-capability-advertisement.test.ts` — **49/49**: structural
pins (vocabularies, bounds, forbidden surfaces, import pin, refusal
explanations, prototype surface, no-grant literals) · provenance rules ·
malformed-shape fail-closed · bounds + inflation · material rejection
(nested JSON secret, PEM, shell, path) · 27A composition (anonymous,
closed claims, unknown/unnamed kind, non-capability kind) · versioning
(new-id=1, rotation +1 freshness, replay idempotence, conflict, stale,
gap, claimant mismatch, rotation-replaces-no-union, refusal
invariance) · per-claimant and registry bounds · snapshot/fingerprint
determinism.
