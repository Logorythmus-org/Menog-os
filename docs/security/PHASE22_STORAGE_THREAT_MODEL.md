# Phase 22 — Storage Trust Model & Durable-State Threat Model

**Scope:** the authoritative durable-state contract for Menog — what may be persisted, how it
must be classified, how restart recovery decides, and why durable state can never become
executable replay or authorization. 22A defines the trust model and contracts ONLY; no backend
exists yet (22B introduces the local transactional store).
**Mode:** CONTRACT / TEST-FIRST — no storage I/O anywhere in the 22A surface.
**Schema:** `menog-durable-store/v0` · `menog-durable-record/v0` · `menog-store-checkpoint/v0` ·
`menog-storage-quarantine/v0` (`packages/durable-state/src/`).
**Date:** 2026-09-28 · **LOCAL-ONLY** · Phases 20/21 remain frozen.

Central invariant (frozen for all of Phase 22):

    durable state ≠ executable replay ≠ authorization

Authority chain (unchanged, preserved): Planner proposes → Allocation scopes → Policy
authorizes → Phase-20 Isolation constrains → Governed Tool Runtime executes → Ledger observes.
Durable state sits BESIDE this chain as evidence and state; recovery re-enters records as
`recovered_data` and touches nothing in the chain.

---

## 1. Durable-state decomposition (as contracted in 22A)

| Element | Contract type | Trust posture |
|:--|:--|:--|
| `DurableRecordEnvelope` | uniform record wrapper | self-hashed (contentHash); any field mutation detectable; never self-authorizing |
| `RecordKind` (8 kinds, closed) | classification key | closed union; new kind = unfreeze event |
| `DurabilityClass` | mutation law | append_only / versioned_mutable / rebuildable, pinned per kind by the classification table |
| `PersistDecision` | admission output | all-or-nothing; failure can never be a partial commit; `commitSequence` assigned by store at commit |
| `RecoveryDecision` | restart boundary output | admits records ONLY as `recovered_data`; `executionAuthorized: false`, `policyAuthorized: false` are structural |
| `MigrationPlan` | versioned transform description | `non_executing`; execution requires the 22E evidence gate |
| `QuarantineRecord` | corruption isolation | preserves bytes AS FOUND (hash, not content); no un-quarantine in contract; human disposition required |
| `StoreCheckpoint` | derived recovery bound | never overrides the ledger; divergence ⇒ rebuild, never heal |

## 2. Classification table (frozen; test-pinned per row)

| RecordKind | Authoritative? | Mutation | Integrity binding | Recovery semantics | Retention | Secret policy |
|:--|:--|:--|:--|:--|:--|:--|
| `event_ledger_entry` | authoritative | append_only | content_hash_required | replay_free (read+verify, never re-execute) | permanent | secret_free |
| `tool_run_evidence` | authoritative | append_only | content_hash_required | verify_then_accept | permanent | secret_free |
| `memory_record` | authoritative | versioned_mutable | content_hash_required | restore_state (still policy-gated) | session_scoped | secret_free |
| `agent_metadata` | authoritative | versioned_mutable | content_hash_required | verify_then_accept | until_superseded | secret_free |
| `goal_lifecycle` | authoritative | versioned_mutable | content_hash_required | restore_state | until_superseded | secret_free |
| `skill_tool_registry` | authoritative | versioned_mutable | content_hash_required | verify_then_accept (terminal states never resurrected) | until_superseded | secret_free |
| `derived_index` | **derived** | rebuildable | content_hash_derived | rebuild_from_authoritative | checkpoint_bound | secret_free |
| `store_checkpoint` | **derived** | rebuildable | content_hash_derived | rebuild_from_authoritative | checkpoint_bound | secret_free |

Secret policy is a closed union with exactly one member (`secret_free`). Any future secret
persistence requires an explicit contract change that models it, proves it, and unfreezes the
union — the deny-by-default posture is structural, not a check that could be skipped.

## 3. Threat → control → primitive → residual → negative test → evidence

| ID | Threat | Menog control (22A contract) | Enforcement primitive (present/future) | Residual risk | Negative test | Evidence |
|:--|:--|:--|:--|:--|:--|:--|
| TS22-01 | Torn/partial write | decisions are all-or-nothing by type (`committed: false` is structural on failure); 22B store rolls back to last checkpoint; recovery treats crash-window records as uncommitted | `PersistDecision` type + 22B transactional layout | 22B not yet implemented — contract layer cannot prove atomic file semantics | contract tests "failures are never partial commits" | `durable-state-contract.test.ts` |
| TS22-02 | Corruption (bit rot, hostile edit) | `contentHash` re-derivation on every read path; `integrity_failed` is terminal ⇒ QUARANTINE, never heal, never accept | `verifyEnvelopeIntegrity` + `QuarantineRecord` + recovery quarantine path | corruption inside a hash-consistent rewrite by the original writer is out of scope (local single-writer trust) | "quarantines corrupt records instead of healing them" | `durable-state-recovery.test.ts` |
| TS22-03 | Stale DB rollback (store state older than ledger) | schema-version + request/store schema match required; divergence between `observedThrough` and `committedThrough` ⇒ `rebuild_derived_required`, authoritative data still admitted as recovered_data only | `decideRecovery` checkpoint/ledger divergence branch | a rolled-back store with a fully consistent ledger tail is indistinguishable from a legitimate older state — bounded by the ledger being append-only and authoritative | "detects checkpoint/ledger divergence… never a silent heal" | `durable-state-recovery.test.ts` |
| TS22-04 | Concurrent writers | mutation modeled as strict revision chain (`supersedesRevision === revision - 1`); stale or skipped revisions deny (`revision_conflict`); single-writer store assumed at 22B | `decidePersist` revision checks | multi-process contention is a 22B lock/ownership concern; contract layer makes lost updates detectable, not possible | "denies stale and lost updates on mutable records" | `durable-state-contract.test.ts` |
| TS22-05 | Lost/duplicate update | same revision chain: duplicate append of an append-only id denies (`duplicate_revision`); revision ≤ stored denies; revision > stored+1 denies | `decidePersist` | none at contract layer | same tests as TS22-04 | `durable-state-contract.test.ts` |
| TS22-06 | Replayed transaction | transaction ids are unique, bounded, never reused; envelope transactionId must equal the persist intent's; re-append of an existing append-only id denies | `decidePersist` + `TRANSACTION_ID_PATTERN` | replay detection across store generations requires checkpoint binding (22E) | "denies a re-append of an existing append-only id" | `durable-state-contract.test.ts` |
| TS22-07 | Schema confusion (unknown/future/mutated schema) | unknown `schemaVersion`, `recordKind`, `durabilityClass`, `secretPolicy`, or authority class ⇒ typed denial; kind/class and authority/class consistency enforced | `validateEnvelope` fail-closed branches | none at contract layer | "rejects an unknown schemaVersion…", full suite around closed vocabularies | `durable-state-contract.test.ts` |
| TS22-08 | Migration failure / hostile migration | migrations are explicit, single-step, version-locked, and `non_executing`; unknown source schema refuses; version skipping refuses; plans carry required-evidence lists (checked by 22E, never by the planner itself) | `decideMigration` | migration EXECUTION is 22E; until then plans are inert data | "refuses to migrate an unknown store schema", "refuses version-skipping" | `durable-state-recovery.test.ts` |
| TS22-09 | Ledger/store divergence | the ledger is authoritative; store records and checkpoints are projections; divergence demands a derived rebuild; checkpoints never override the ledger | classification table + `decideRecovery` divergence branch | divergence detection is positional (commit sequences); byte-level divergence inside authoritative store records is caught by content hashes (TS22-02) | "detects checkpoint/ledger divergence…" | `durable-state-recovery.test.ts` |
| TS22-10 | Index poisoning | `derived_index` is rebuildable and NEVER authoritative; poisoned/stale indexes are discarded and recomputed from authoritative records only | classification row `rebuild_from_authoritative` | none — indexes are structurally untrusted | "indexes and checkpoints are derived, rebuildable, never authoritative" | `durable-state-contract.test.ts` |
| TS22-11 | Evidence substitution (swap sealed bytes for lookalikes) | contentHash binds every envelope field; substitution breaks re-derivation and denies (`content_hash_mismatch`) | `validateEnvelope` hash branch + `verifyEnvelopeIntegrity` | a substituted record WITH a valid recomputed hash is indistinguishable from an original written by the trusted runtime — out of scope for local single-writer trust | "rejects envelopes whose contentHash does not re-derive" | `durable-state-contract.test.ts` |
| TS22-12 | Storage path/symlink escape | OUT OF SCOPE at 22A: the contract layer has no paths at all (no file name, no directory, no I/O). 22B must enforce path containment inside its store root; recovery never opens caller-supplied paths | structural absence of path vocabulary in 22A | deferred to 22B/F with negative tests at that layer | n/a — no path exists to escape | contract layer performs zero I/O |
| TS22-13 | Malicious DB content (crafted records) | every field is validated against closed vocabularies; unknown values deny; ids are shape+prefix validated; payloads are JSON-bounded and depth-bounded; scan bounds cap recovery work and partial scans fail closed | `validateEnvelope` + recovery scan bound | adversarial payload CONTENT inside valid JSON remains untrusted data for consumers (same posture as tool output) | "rejects a scan that hit its bound", vocabulary tests | both test files |
| TS22-14 | Secret leakage into storage | secret-shaped payload keys deny the WHOLE record (`secret_key_denied`); `secretPolicy` closed to `secret_free`; stronger than redaction — nothing secret-shaped persists at all | `findSecretPayloadKeyPaths` + validation order | credential-shaped VALUES with innocent key names are not key-detectable; 22B must mirror the ledger's value redaction as defense in depth | "denies records carrying secret-shaped keys" | `durable-state-contract.test.ts` |
| TS22-15 | Unauthorized recovery (recovery as authority) | recovery decisions structurally stamp `recovered_data` + `executionAuthorized: false` + `policyAuthorized: false`; recovery cannot express execution (`semantics: "no_execution"` literal type); schema mismatch / scan bound fail closed | `RecoveryDecision` type + `decideRecovery` | none — the invariant is type-structural | "every accept decision stamps recovered_data…" | `durable-state-recovery.test.ts` |
| TS22-16 | Authority resurrection (terminal states revived by restart) | quarantined/retired registry + evidence kinds are in `TERMINAL_QUARANTINE_KINDS`; quarantine has no un-quarantine operation; recovery admits verified records as data only — the 21A closed lifecycle machine remains the sole lifecycle authority | classification table + `QuarantineRecord` (no un-quarantine in vocabulary) | resurrection via a FRESH store that never knew the quarantine is a ledger-provenance question (22E reconciliation) | "names the anti-resurrection surface", recovery-never-authorizes suite | both test files |

## 4. Explicit non-goals (never represented in this layer)

No backend/storage engine · no network/cloud DB, federation, or distributed consensus · no
executable replay/rollback (the Phase-14 question remains unresolved) · no secret persistence
(closed union admits only `secret_free`) · no un-quarantine without human disposition · no
migration execution (plans are non-executing) · no healing/repair of corrupt records · no
auto-signature of any human gate.

## 5. Residual-risk register (honest, carried forward)

1. **No backend yet** — 22A proves the contract layer only; atomicity, fsync discipline,
   path containment, and crash visibility are 22B/F concerns and must be adversarially
   validated there (22F).
2. **Hash-consistent malicious writes** by a compromised runtime process are not detectable
   by self-hashing alone; the ledger's append-only chain is the cross-check (TS22-02/11).
3. **Multi-process contention** is detectable (revision chain) but not arbitrated; 22B owns
   the single-writer guarantee.
4. **Credential-shaped values under innocent keys** are not key-detectable; value-level
   redaction (mirroring the ledger/memory lists) is required defense-in-depth at 22B.
5. **Migration execution** is deliberately absent; until 22E's evidence gate exists, a
   migration plan is inert data and any executed migration is a contract violation.

## 6. What 22A deliberately does NOT decide

The storage backend, file layout, sync strategy, and IPC model are all 22B choices that must
satisfy — and can narrow but never widen — these contracts. Any 22B mechanism that would make
an append-only record mutable, a derived index authoritative, a quarantined record readable,
or a recovered record authorizing is WRONG by this document and by the tests that pin it.
