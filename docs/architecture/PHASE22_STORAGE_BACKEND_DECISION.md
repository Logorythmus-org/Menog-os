# Phase 22B — Storage Backend Decision

**Gate:** 22B · **Date:** 2026-09-28 · **Status:** DECIDED (for 22B scope)
**Decision:** SQLite via Node's built-in `node:sqlite` (`DatabaseSync`) — zero new dependencies.
**Mode:** LOCAL PERSISTENCE / SINGLE-MACHINE / NO NETWORK.

---

## 1. Constraints (from the repository and the phase prompt)

| Constraint | Source | Consequence for the backend |
|:--|:--|:--|
| LOCAL-ONLY; no cloud/network DB, federation, consensus, external service | Phase-22 global rules | embedded, file-based, single-process engine only |
| "Prefer a boring proven transactional backend over a custom engine" | 22B OBJECTIVE | no hand-rolled B-tree/WAL/journal engine |
| Atomic transaction boundary; rollback visibility | 22B REQUIRE/TEST | engine-level BEGIN/COMMIT/ROLLBACK |
| Append-only tamper-evident semantics preserved; corruption quarantined, never healed | 22A contracts + global rules | engine integrity + Menog content-hash layer on top |
| Fail closed on unknown schema | 22A | explicit schema-version table checked at open |
| Default secret-free records | 22A | content is envelope-validated BEFORE it reaches SQL |
| Existing stack: TypeScript strict ESM, Node ≥ 22 (running 24.20.0), pnpm, zero runtime deps in packages so far, MPL-2.0, supply-chain-averse (DIRECT_DEPENDENCY_REVIEW.md) | repository | adding a native dep (better-sqlite3) would be the repo's first compiled dependency |
| Windows dev host + WSL2 Linux target-of-record | Phase-20/21 record | backend must work on both without per-platform builds |

## 2. Candidates evaluated

### Candidate A — SQLite via `node:sqlite` (built-in `DatabaseSync`) ✅ CHOSEN
- **Proven engine:** SQLite is the most widely deployed transactional database in existence;
  full ACID with WAL or rollback journal; crash-safe by decades of production history.
- **Zero new dependencies:** shipped inside Node ≥ 22.5. No npm package, no lockfile churn,
  no supply-chain review surface, no license questions (Node's binding is part of the runtime
  the repo already requires; `engines >= 22` is already declared).
- **Synchronous API** matches every existing Menog store (all current stores are synchronous,
  in-process, deterministic; no async plumbing to introduce).
- **Cross-platform:** same engine on the Windows dev host and the WSL2 Linux target.
- **Cons:** API marked experimental-ish (stability index 1.1 — "under active development");
  typing comes from `@types/node` 22.10.2 (`DatabaseSync`/`StatementSync`, since 22.5.0) and is
  sufficient for the small surface used here; not available on Node 22.0–22.4 (repo declares
  `>=22`; running 24.20.0; risk recorded, not hidden).
- **No network capability at all.** No secrets stored (Menog layer denies them before SQL).

### Candidate B — `better-sqlite3` (npm native module)
- Same engine underneath; mature typings.
- **Cons:** first compiled native dependency in the repo (node-gyp toolchain, per-Node-version
  binaries, Windows+WSL2 dual builds), new supply-chain review obligation against the repo's
  dependency-review discipline, new MPL/APACHE-adjacent license paperwork for
  THIRD_PARTY_NOTICES. All of that buys exactly what Candidate A already provides. Rejected.

### Candidate C — custom append-only journal + compaction (hand-rolled engine)
- Maximum transparency, zero deps, trivially auditable.
- **Cons:** explicitly what the 22B prompt says to avoid — a custom transactional engine
  (crash atomicity, torn-write windows, compaction correctness) is exactly the surface where
  subtle durability bugs live. The 22A contract layer already proved the fail-closed
  vocabulary; 22B should not re-implement durability from scratch. Rejected for 22B; the
  hash-chained JSONL ledger (Phase 12) remains the append-only evidence store it always was —
  22B is the STATE store beside it, not a replacement.

### Candidate D — `sql.js` / pure-JS SQLite (WASM)
- No native build, but persistence is manual (export/import of the whole DB), transactions
  are in-memory only until a full-file write, and it is a large vendored WASM blob.
  Worst of both worlds for durability. Rejected.

## 3. Decision record

**SQLite via `node:sqlite`.** Rationale in one line: the smallest proven transactional
backend that satisfies 22A with zero new dependencies and zero network surface.

## 4. How the 22A contracts map onto SQLite

| 22A contract | SQLite realization |
|:--|:--|
| Explicit schema version | `store_meta(key, value)` row `store_schema_version = menog-durable-store/v0`; mismatch ⇒ open refuses (fail closed) |
| Atomic transaction boundary | one `BEGIN IMMEDIATE … COMMIT/ROLLBACK` per `commitTransaction`; every persist inside validates first — any denial aborts the WHOLE transaction (`transaction_aborted`), nothing partial exists |
| Canonical serialization/hash | envelope `contentHash` verified on write (22A `validateEnvelope`) and re-verified on read (`integrity_failed` ⇒ quarantine row, never returned as data) |
| Unique IDs/idempotency | `records(record_id, revision)` PRIMARY KEY; duplicate transactionId ⇒ `duplicate_transaction` denial (recorded, not applied) |
| Append-only immutable records | append-only kinds: PK conflict ⇒ denial; no UPDATE/DELETE statements exist for them in the store's vocabulary |
| Versioned mutable + conflict detection | UNIQUE(record_id, revision) + `prev_revision` self-check; stale/skipped revision ⇒ `revision_conflict` |
| Derived indexes separate | `derived_index` table, rebuildable, never read as authority; checkpoint consistency recomputes it |
| Checkpoint metadata | `checkpoints` table + `store_meta` counters; checkpoint hash recomputed and compared — divergence ⇒ derived rebuild demanded, never healed |
| Authorized canonical state-root path | `openDurableStore(rootDir)` accepts ONLY a directory the caller already owns; the store resolves ONE canonical level (`menog-store`) beneath it; traversal components (`..`, absolute escapes, symlinked store file) are rejected before any I/O |
| Safe open/create/close/flush | `open` (create-or-open + schema check), `close` (checkpoint + SQLite `PRAGMA wal_checkpoint(TRUNCATE)` + close); SQLite fsync discipline NOT overclaimed beyond the engine's guarantees (see §6) |
| No network | no socket-capable construct exists in the module (verify-local network-invariant scan stays green) |
| No secrets by default | 22A `validateEnvelope` denies secret-shaped keys before any SQL runs |
| Corruption quarantined, never healed | `quarantine` table keyed by as-found hash; quarantined bytes are never returned as records and never modified |

## 5. Alternatives considered for specific sub-problems

- **WAL vs DELETE journal:** WAL chosen (`journal_mode=WAL`, `synchronous=NORMAL`) for
  crash-consistent commits with good throughput. The engine's own fsync guarantees are
  inherited; Menog adds NOTHING on top and claims nothing beyond them (§6).
- **One DB file vs per-kind files:** one file; per-kind separation is by `record_kind`
  column + classification predicates, keeping cross-record transaction atomicity trivial.
- **SQLCipher / at-rest encryption:** rejected — encryption implies secret handling
  (key storage), which Phase 22 does not model. Records are secret-FREE, so there is nothing
  to encrypt until a future gate models keys explicitly.

## 6. Honest guarantee boundary (no overclaiming)

What 22B claims: engine-level transaction atomicity and rollback; content-hash tamper
DETECTION on every record read; fail-closed schema/open/validation; quarantine of corrupt
bytes; persistence across clean close/reopen; idempotent duplicate-transaction handling.

What 22B does NOT claim:
- **No power-loss/crash guarantee beyond SQLite's own** — 22B inherits the engine's durability
  (WAL + `synchronous=NORMAL`); Menog performs no additional fsync layer and makes no
  independent power-fail claim. Hostile crash testing is 22F scope on the Linux
  target-of-record; this gate's tests cover logical interruption only, on the dev host.
- **No multi-process locking protocol** — SQLite's file locking prevents interleaved writes,
  but the 22A revision-chain remains the correctness mechanism; concurrent-writer adversarial
  scenarios are 22F scope.
- **No tamper-proofing against the store owner** — content hashes DETECT mutation; a local
  attacker who can rewrite SQLite bytes can recompute... nothing (they'd need to also rewrite
  the ledger chain — that cross-check is 22C/22E reconciliation, not 22B).
