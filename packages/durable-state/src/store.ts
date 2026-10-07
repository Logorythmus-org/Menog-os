/**
 * PHASE 22B — Local Durable Store & Transaction Boundary.
 *
 * The smallest transactional local backend satisfying the 22A contracts.
 * Backend: SQLite via Node's built-in `node:sqlite` (DatabaseSync) — see
 * docs/architecture/PHASE22_STORAGE_BACKEND_DECISION.md. Zero new
 * dependencies; no network capability; no secrets.
 *
 * Trust structure:
 * - Every record passes the 22A fail-closed envelope validation BEFORE any
 *   SQL runs (unknown schema/kind/class, secret-shaped keys, hash mismatch,
 *   append-only mutation attempts, revision conflicts all deny).
 * - All writes happen inside ONE `BEGIN IMMEDIATE … COMMIT/ROLLBACK` per
 *   transaction; any denial aborts the WHOLE transaction (no partial
 *   transaction is representable).
 * - Reads re-verify contentHash; a record whose stored bytes no longer
 *   verify is QUARANTINED (moved to the quarantine table, never returned as
 *   data, never repaired) — corruption isolation, never healing.
 * - append_only kinds have no UPDATE/DELETE in the vocabulary: their
 *   immutability is enforced by denial, not by convention.
 * - derived_index rows live in a separate table, are rebuildable, and are
 *   never returned as authoritative records.
 * - Schema version is checked at open: unknown/mismatched store files fail
 *   closed. Migrations remain 22E scope.
 *
 * Honest guarantee boundary (no overclaiming): durability inherits SQLite's
 * WAL + synchronous=NORMAL; this module adds no independent fsync layer and
 * makes no power-loss claim beyond the engine's. Multi-process behavior is
 * SQLite's file locking + the 22A revision chain; adversarial crash testing
 * is 22F scope.
 */

import { mkdirSync, existsSync, lstatSync, realpathSync } from "node:fs";
import { join, resolve, basename, dirname, isAbsolute } from "node:path";
import { DatabaseSync } from "./sqliteNative.js";
import {
  DURABLE_STORE_SCHEMA_VERSION,
  type CommitSequence,
  type DurableRecordEnvelope,
  type PersistDecision,
  type RecordKind,
} from "./records.js";
import {
  isRebuildableKind,
} from "./classification.js";
import {
  canonicalHash,
  verifyEnvelopeIntegrity,
} from "./canonical.js";
import {
  decidePersist,
  validateEnvelope,
  type PersistIntent,
} from "./persist.js";

// ── store-level bounds & paths ───────────────────────────────────────────────

/** Bounded reason strings — hostile content is never echoed. */
const MAX_REASON_CHARS = 240;
function truncateReason(s: string): string {
  return s.length > MAX_REASON_CHARS ? s.slice(0, MAX_REASON_CHARS) : s;
}

/**
 * The canonical single-level store directory beneath the caller-provided
 * root. The store NEVER writes outside this one directory.
 */
export const STORE_DIR_NAME = "menog-store";
export const STORE_FILE_NAME = "durable.db";

// ── open result ──────────────────────────────────────────────────────────────

export type StoreOpenFailureCode =
  | "root_invalid"
  | "root_unwritable"
  | "path_escape_denied"
  | "store_file_unexpected"
  | "unknown_schema_version"
  | "schema_version_mismatch"
  | "open_failed";

export type StoreOpenResult =
  | { ok: true; store: DurableStore; created: boolean }
  | { ok: false; failureCode: StoreOpenFailureCode; reason: string };

/** Instance type of the runtime-loaded SQLite DatabaseSync class. */
type DatabaseSyncInstanceType = InstanceType<typeof DatabaseSync>;

// ── the store ────────────────────────────────────────────────────────────────

/**
 * The local transactional durable store. All operations are synchronous.
 * The store performs no authorization: it persists what passes the 22A
 * validation boundary, and nothing else. Recovered records read from this
 * store are still just data — nothing here executes or grants.
 */
export class DurableStore {
  readonly  #db: DatabaseSyncInstanceType;
  readonly #dbPath: string;
  readonly #stateRoot: string;
  #closed: boolean = false;
  #openTransactionId: string | null = null;
  #openTransactionEnvelopes: DurableRecordEnvelope[] = [];

  private constructor(db: DatabaseSyncInstanceType, dbPath: string, stateRoot: string) {
    this.#db = db;
    this.#dbPath = dbPath;
    this.#stateRoot = stateRoot;
  }

  // ── open / create / close / flush ────────────────────────────────────────

  /**
   * Open (or create) the store under `rootDir/<STORE_DIR_NAME>/`. The root
   * directory must already exist and be writable; the store resolves the
   * canonical path itself and rejects traversal (no `..`, no absolute
   * components, no symlinked store directory). Unknown or mismatched
   * schema versions fail closed.
   */
  public static open(rootDir: string): StoreOpenResult {
    if (typeof rootDir !== "string" || rootDir.length === 0) {
      return { ok: false, failureCode: "root_invalid", reason: "rootDir must be a non-empty string" };
    }
    if (!isAbsolute(rootDir)) {
      return { ok: false, failureCode: "root_invalid", reason: "rootDir must be an absolute path (the caller owns canonicalization of its own workspace root)" };
    }
    if (!existsSync(rootDir)) {
      return { ok: false, failureCode: "root_invalid", reason: "rootDir does not exist — the caller must create its own workspace root first" };
    }
    let rootStat;
    try {
      rootStat = lstatSync(rootDir);
    } catch (e) {
      return { ok: false, failureCode: "root_invalid", reason: "rootDir is not statable: " + truncateReason(String((e as Error).message)) };
    }
    if (!rootStat.isDirectory()) {
      return { ok: false, failureCode: "root_invalid", reason: "rootDir is not a directory" };
    }

    const storeDir = join(rootDir, STORE_DIR_NAME);
    const dbPath = join(storeDir, STORE_FILE_NAME);

    // Path-escape guard: the store file must sit exactly one canonical
    // level beneath the caller's root (no symlinked directory component,
    // no traversal, no substitution).
    try {
      const canonicalDir = realpathSync(dirname(dbPath) === storeDir ? storeDir : storeDir);
      const canonicalRoot = realpathSync(rootDir);
      if (!canonicalDir.startsWith(canonicalRoot)) {
        return { ok: false, failureCode: "path_escape_denied", reason: "store directory resolves outside the caller's root" };
      }
      if (basename(canonicalDir) !== STORE_DIR_NAME) {
        return { ok: false, failureCode: "path_escape_denied", reason: "store directory component was substituted (symlink escape denied)" };
      }
    } catch {
      // realpath on a not-yet-created directory: verify the parent instead.
      try {
        const canonicalRoot = realpathSync(rootDir);
        if (!resolve(storeDir).startsWith(canonicalRoot)) {
          return { ok: false, failureCode: "path_escape_denied", reason: "store directory resolves outside the caller's root" };
        }
      } catch (e2) {
        return { ok: false, failureCode: "root_invalid", reason: "rootDir is not resolvable: " + truncateReason(String((e2 as Error).message)) };
      }
    }

    let created = false;
    try {
      if (!existsSync(storeDir)) {
        mkdirSync(storeDir, { recursive: false });
        created = true;
      } else {
        const st = lstatSync(storeDir);
        if (!st.isDirectory() || st.isSymbolicLink()) {
          return { ok: false, failureCode: "path_escape_denied", reason: "store directory exists but is not a plain directory (symlink escape denied)" };
        }
      }
      if (existsSync(dbPath)) {
        const st = lstatSync(dbPath);
        if (!st.isFile() || st.isSymbolicLink()) {
          return { ok: false, failureCode: "store_file_unexpected", reason: "store file exists but is not a plain file (symlink/substitution denied)" };
        }
      }
    } catch (e) {
      return { ok: false, failureCode: "root_unwritable", reason: "cannot prepare store directory: " + truncateReason(String((e as Error).message)) };
    }

    let db: DatabaseSyncInstanceType;
    try {
      db = new DatabaseSync(dbPath);
    } catch (e) {
      return { ok: false, failureCode: "open_failed", reason: "sqlite open failed: " + truncateReason(String((e as Error).message)) };
    }

    const store = new DurableStore(db, dbPath, rootDir);
    const initErr = store.#initializeOrVerifySchema();
    if (initErr !== null) {
      try { db.close(); } catch { /* already closed */ }
      return initErr;
    }

    // Engine pragmas: WAL for crash-consistent commits; NORMAL sync (the
    // engine's own durability guarantees — nothing extra claimed on top).
    try {
      db.exec("PRAGMA journal_mode = WAL;");
      db.exec("PRAGMA synchronous = NORMAL;");
      db.exec("PRAGMA foreign_keys = ON;");
    } catch (e) {
      try { db.close(); } catch { /* already closed */ }
      return { ok: false, failureCode: "open_failed", reason: "pragma setup failed: " + truncateReason(String((e as Error).message)) };
    }

    return { ok: true, store, created };
  }

  /** Canonical path of the store file (diagnostics only; never handed to callers for writing). */
  public get databasePath(): string {
    return this.#dbPath;
  }

  /** The caller-provided state root this store was authorized under. */
  public get stateRoot(): string {
    return this.#stateRoot;
  }

  public get isOpen(): boolean {
    return !this.#closed;
  }

  /**
   * Close the store: flush WAL (checkpoint TRUNCATE) then close. Idempotent
   * — closing twice is a no-op, never an error.
   */
  public close(): void {
    if (this.#closed) return;
    this.#abortOpenTransactionIfAny("store_closed");
    try {
      this.#db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
    } catch {
      // A failed checkpoint must not prevent close; SQLite remains
      // crash-consistent without it.
    }
    try {
      this.#db.close();
    } finally {
      this.#closed = true;
    }
  }

  /**
   * Flush pending WAL frames into the main database file (visibility point,
   * not a durability claim beyond the engine's).
   */
  public flush(): { ok: boolean; reason?: string } {
    if (this.#closed) return { ok: false, reason: "store is closed" };
    try {
      this.#db.exec("PRAGMA wal_checkpoint(PASSIVE);");
      return { ok: true };
    } catch (e) {
      return { ok: false, reason: truncateReason(String((e as Error).message)) };
    }
  }

  // ── schema ───────────────────────────────────────────────────────────────

  #initializeOrVerifySchema(): { ok: false; failureCode: StoreOpenFailureCode; reason: string } | null {
    try {
      this.#db.exec(`
        CREATE TABLE IF NOT EXISTS store_meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS records (
          record_id TEXT NOT NULL,
          revision INTEGER NOT NULL,
          record_kind TEXT NOT NULL,
          durability_class TEXT NOT NULL,
          transaction_id TEXT NOT NULL,
          commit_sequence INTEGER NOT NULL,
          created_at_epoch_ms INTEGER NOT NULL,
          payload_json TEXT NOT NULL,
          content_hash TEXT NOT NULL,
          PRIMARY KEY (record_id, revision)
        );
        CREATE INDEX IF NOT EXISTS idx_records_txn ON records(transaction_id);
        CREATE INDEX IF NOT EXISTS idx_records_kind ON records(record_kind);
        CREATE TABLE IF NOT EXISTS quarantine (
          record_id TEXT NOT NULL,
          as_found_hash TEXT NOT NULL,
          cause TEXT NOT NULL,
          detail TEXT NOT NULL,
          quarantined_at_epoch_ms INTEGER NOT NULL,
          payload_json TEXT NOT NULL,
          PRIMARY KEY (record_id, as_found_hash)
        );
        CREATE TABLE IF NOT EXISTS derived_index (
          index_id TEXT NOT NULL,
          entry_key TEXT NOT NULL,
          entry_value TEXT NOT NULL,
          built_at_commit INTEGER NOT NULL,
          PRIMARY KEY (index_id, entry_key)
        );
        CREATE TABLE IF NOT EXISTS checkpoints (
          checkpoint_id TEXT NOT NULL,
          committed_through INTEGER NOT NULL,
          authoritative_count INTEGER NOT NULL,
          ledger_tail_hash TEXT NOT NULL,
          checkpoint_hash TEXT NOT NULL,
          created_at_epoch_ms INTEGER NOT NULL,
          PRIMARY KEY (checkpoint_id)
        );
      `);
      const row = this.#db
        .prepare("SELECT value FROM store_meta WHERE key = 'store_schema_version'")
        .get() as { value: string } | undefined;
      if (row === undefined) {
        this.#db
          .prepare("INSERT INTO store_meta (key, value) VALUES ('store_schema_version', ?)")
          .run(DURABLE_STORE_SCHEMA_VERSION);
        return null;
      }
      if (row.value !== DURABLE_STORE_SCHEMA_VERSION) {
        return {
          ok: false,
          failureCode: "schema_version_mismatch",
          reason:
            "store schema '" + row.value + "' does not match this code's '" +
            DURABLE_STORE_SCHEMA_VERSION + "' — failing closed (migrations are 22E scope)",
        };
      }
      return null;
    } catch (e) {
      return { ok: false, failureCode: "open_failed", reason: "schema init failed: " + truncateReason(String((e as Error).message)) };
    }
  }

  /** The store's schema version (typed read; unknown ⇒ the store never opened). */
  public get storeSchemaVersion(): string | null {
    if (this.#closed) return null;
    const row = this.#db
      .prepare("SELECT value FROM store_meta WHERE key = ?")
      .get("store_schema_version") as { value: string } | undefined;
    return row?.value ?? null;
  }

  // ── store meta (23B live-owner claim surface; the ONLY mutable meta) ─────

  /** Read one store_meta value (null when absent or store closed). */
  public getMeta(key: string): string | null {
    if (this.#closed) return null;
    if (typeof key !== "string" || key.length === 0 || key.length > 64) return null;
    const row = this.#db
      .prepare("SELECT value FROM store_meta WHERE key = ?")
      .get(key) as { value: string } | undefined;
    return row?.value ?? null;
  }

  /** Set one store_meta value (23B live-owner claim binding). */
  public setMeta(key: string, value: string): { ok: true } | { ok: false; reason: string } {
    if (this.#closed) return { ok: false, reason: "store is closed" };
    if (typeof key !== "string" || !/^[a-z][a-z0-9_]{2,63}$/.test(key)) {
      return { ok: false, reason: "meta key must match ^[a-z][a-z0-9_]{2,63}$" };
    }
    if (typeof value !== "string" || value.length === 0 || value.length > 256) {
      return { ok: false, reason: "meta value must be a non-empty string of at most 256 chars" };
    }
    try {
      this.#db
        .prepare("INSERT INTO store_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .run(key, value);
      return { ok: true };
    } catch (e) {
      return { ok: false, reason: truncateReason(String((e as Error).message)) };
    }
  }

  /** Delete one store_meta value (23B live-owner claim release). Idempotent. */
  public deleteMeta(key: string): { ok: true } | { ok: false; reason: string } {
    if (this.#closed) return { ok: false, reason: "store is closed" };
    if (typeof key !== "string" || key.length === 0 || key.length > 64) {
      return { ok: false, reason: "meta key must be a non-empty string of at most 64 chars" };
    }
    try {
      this.#db.prepare("DELETE FROM store_meta WHERE key = ?").run(key);
      return { ok: true };
    } catch (e) {
      return { ok: false, reason: truncateReason(String((e as Error).message)) };
    }
  }

  // ── transaction boundary ─────────────────────────────────────────────────

  /**
   * Begin a logical transaction. Exactly one transaction may be open at a
   * time (single-writer store); nested begins are denied, not queued.
   */
  public beginTransaction(transactionId: string): { ok: true } | { ok: false; failureCode: "store_closed" | "transaction_open" | "invalid_transaction_id"; reason: string } {
    if (this.#closed) return { ok: false, failureCode: "store_closed", reason: "store is closed" };
    if (this.#openTransactionId !== null) {
      return { ok: false, failureCode: "transaction_open", reason: "transaction '" + this.#openTransactionId + "' is already open — nested/parallel transactions are denied" };
    }
    if (typeof transactionId !== "string" || !/^[a-z][a-z0-9-]{2,63}$/.test(transactionId)) {
      return { ok: false, failureCode: "invalid_transaction_id", reason: "transactionId must match ^[a-z][a-z0-9-]{2,63}$" };
    }
    try {
      this.#db.exec("BEGIN IMMEDIATE;");
    } catch (e) {
      return { ok: false, failureCode: "transaction_open", reason: "BEGIN failed: " + truncateReason(String((e as Error).message)) };
    }
    this.#openTransactionId = transactionId;
    this.#openTransactionEnvelopes = [];
    return { ok: true };
  }

  /**
   * Commit the open transaction atomically: every staged envelope is
   * validated, then all are written, then COMMIT. Any validation failure,
   * conflict, or SQL error rolls back EVERYTHING (no partial transaction).
   */
  public commitTransaction(): PersistDecision {
    if (this.#closed) {
      return this.#deny("store_closed", "store is closed", this.#openTransactionId);
    }
    if (this.#openTransactionId === null) {
      return this.#deny("transaction_aborted", "no transaction is open", null);
    }
    const txnId = this.#openTransactionId;

    // 1. Validate every staged envelope FIRST (no SQL has run for them yet).
    for (const env of this.#openTransactionEnvelopes) {
      const existing = this.#lookupStoredRevision(env.recordId);
      const intent: PersistIntent = {
        envelope: env,
        transactionId: txnId,
        idExists: existing !== null,
        existingRevision: existing,
        storeWritable: true,
      };
      const decision = decidePersist(intent);
      if (!decision.ok) {
        this.#rollbackOpen();
        return decision;
      }
    }
    // 2. Transaction-id replay check: the open transaction id must never
    //    have committed before (rows with it can only come from a PRIOR
    //    transaction — nothing from this one has been inserted yet).
    if (this.#transactionIdAlreadyUsed(txnId)) {
      this.#rollbackOpen();
      return this.#deny("duplicate_transaction", "transactionId was already committed — replayed transactions are denied", txnId);
    }

    // 3. Assign one commit sequence for the whole transaction.
    const seqRow = this.#db
      .prepare("SELECT COALESCE(MAX(commit_sequence), 0) AS s FROM records")
      .get() as { s: number | bigint };
    const commitSequence = Number(seqRow.s) + 1;

    // 4. Write everything; any SQL failure aborts the whole transaction.
    try {
      const insert = this.#db.prepare(`
        INSERT INTO records
          (record_id, revision, record_kind, durability_class, transaction_id, commit_sequence, created_at_epoch_ms, payload_json, content_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const env of this.#openTransactionEnvelopes) {
        insert.run(
          env.recordId,
          env.revision,
          env.recordKind,
          env.durabilityClass,
          env.transactionId,
          commitSequence,
          env.createdAtEpochMs,
          JSON.stringify({ ...env.payload }),
          env.contentHash,
        );
      }
      this.#db.exec("COMMIT;");
    } catch (e) {
      this.#rollbackOpen();
      return this.#deny("transaction_aborted", "commit failed and rolled back: " + truncateReason(String((e as Error).message)), txnId);
    }

    const first = this.#openTransactionEnvelopes[0] as DurableRecordEnvelope;
    const committed: PersistDecision = {
      ok: true,
      committed: true,
      recordId: first.recordId,
      revision: first.revision,
      transactionId: txnId,
      commitSequence,
    };
    this.#openTransactionId = null;
    this.#openTransactionEnvelopes = [];
    return committed;
  }

  /**
   * Abort the open transaction explicitly. Idempotent: aborting when no
   * transaction is open is a no-op.
   */
  public abortTransaction(): void {
    this.#rollbackOpen();
  }

  #rollbackOpen(): void {
    if (this.#openTransactionId === null) return;
    try {
      this.#db.exec("ROLLBACK;");
    } catch {
      // ROLLBACK of an already-broken transaction is best-effort; SQLite
      // guarantees the transaction never becomes visible either way.
    }
    this.#openTransactionId = null;
    this.#openTransactionEnvelopes = [];
  }

  #abortOpenTransactionIfAny(reason: string): void {
    if (this.#openTransactionId !== null) {
      this.#rollbackOpen();
      void reason; // reason is diagnostics-only; the abort itself is silent by design
    }
  }

  // ── persist (staging + direct) ───────────────────────────────────────────

  /**
   * Stage one envelope into the open transaction. Validation happens at
   * commit (so a later stage cannot bypass it) — but obviously-invalid
   * envelopes are rejected here too, as a courtesy denial that does NOT
   * abort the transaction.
   */
  public stageRecord(envelope: DurableRecordEnvelope): StageRecordResult {
    if (this.#closed) {
      return { ok: false, failureCode: "store_closed", reason: "store is closed" };
    }
    if (this.#openTransactionId === null) {
      return { ok: false, failureCode: "transaction_aborted", reason: "no transaction is open — stageRecord requires beginTransaction first" };
    }
    // The envelope's sealed transactionId must be THIS transaction's id.
    if (envelope.transactionId !== this.#openTransactionId) {
      return { ok: false, failureCode: "invalid_transaction_id", reason: "envelope transactionId does not match the open transaction" };
    }
    // Derived kinds never persist through the record path.
    if (isRebuildableKind(envelope.recordKind)) {
      return { ok: false, failureCode: "derived_kind_forbidden", reason: "derived records persist through setDerivedEntry, never as authoritative records" };
    }
    const quick = validateEnvelope(envelope);
    if (!quick.ok) {
      return { ok: false, failureCode: quick.failureCode, reason: truncateReason(quick.reason) };
    }
    this.#openTransactionEnvelopes.push(envelope);
    return { ok: true };
  }

  /**
   * One-shot persist: opens an anonymous transaction, stages, commits.
   * `transactionId` must match the envelope's.
   */
  public persist(envelope: DurableRecordEnvelope): PersistDecision {
    if (this.#closed) {
      return this.#deny("store_closed", "store is closed", envelope?.transactionId ?? null);
    }
    if (isRebuildableKind(envelope?.recordKind)) {
      return this.#deny("derived_kind_forbidden", "derived records persist through setDerivedEntry, never as authoritative records", envelope?.transactionId ?? null);
    }
    const validation = validateEnvelope(envelope);
    if (!validation.ok) {
      return this.#deny(validation.failureCode, truncateReason(validation.reason), envelope?.transactionId ?? null);
    }
    // The envelope's own transactionId IS the persist's transaction
    // identity (validated for shape); the one-shot persist uses it directly
    // so the decision layer's transaction-consistency check always agrees.
    const txnId = envelope.transactionId;
    const began = this.beginTransaction(txnId);
    if (!began.ok) {
      return this.#deny(began.failureCode, began.reason, envelope.transactionId);
    }
    const existing = this.#lookupStoredRevision(envelope.recordId);
    const decision = decidePersist({
      envelope,
      transactionId: txnId,
      idExists: existing !== null,
      existingRevision: existing,
      storeWritable: true,
    });
    if (!decision.ok) {
      this.#rollbackOpen();
      return decision;
    }
    if (this.#transactionIdAlreadyUsed(txnId)) {
      this.#rollbackOpen();
      return this.#deny("duplicate_transaction", "transactionId was already committed — replayed transactions are denied", txnId);
    }
    const seqRow = this.#db
      .prepare("SELECT COALESCE(MAX(commit_sequence), 0) AS s FROM records")
      .get() as { s: number | bigint };
    const commitSequence = Number(seqRow.s) + 1;
    try {
      this.#db.prepare(`
        INSERT INTO records
          (record_id, revision, record_kind, durability_class, transaction_id, commit_sequence, created_at_epoch_ms, payload_json, content_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        envelope.recordId,
        envelope.revision,
        envelope.recordKind,
        envelope.durabilityClass,
        envelope.transactionId,
        commitSequence,
        envelope.createdAtEpochMs,
        JSON.stringify({ ...envelope.payload }),
        envelope.contentHash,
      );
      this.#db.exec("COMMIT;");
    } catch (e) {
      this.#rollbackOpen();
      return this.#deny("transaction_aborted", "commit failed and rolled back: " + truncateReason(String((e as Error).message)), envelope.transactionId);
    }
    this.#openTransactionId = null;
    this.#openTransactionEnvelopes = [];
    return { ok: true, committed: true, recordId: envelope.recordId, revision: envelope.revision, transactionId: envelope.transactionId, commitSequence };
  }

  // ── reads ────────────────────────────────────────────────────────────────

  #lookupStoredRevision(recordId: string): number | null {
    const row = this.#db
      .prepare("SELECT MAX(revision) AS r FROM records WHERE record_id = ?")
      .get(recordId) as { r: number | bigint | null };
    return row.r === null || row.r === undefined ? null : Number(row.r);
  }

  /** True when any committed record already carries this transactionId. */
  #transactionIdAlreadyUsed(transactionId: string): boolean {
    const row = this.#db
      .prepare("SELECT 1 AS hit FROM records WHERE transaction_id = ? LIMIT 1")
      .get(transactionId) as { hit: number } | undefined;
    return row !== undefined;
  }

  /** Highest stored revision for a record id (null when unknown). */
  public currentRevision(recordId: string): number | null {
    if (this.#closed) return null;
    return this.#lookupStoredRevision(recordId);
  }

  /** Highest commit sequence durably committed (0 for an empty store). */
  public get committedThrough(): CommitSequence {
    if (this.#closed) return 0;
    const row = this.#db
      .prepare("SELECT COALESCE(MAX(commit_sequence), 0) AS s FROM records")
      .get() as { s: number | bigint };
    return Number(row.s);
  }

  /**
   * Read the latest revision of a record. The stored bytes are re-verified
   * against contentHash; an unverified record is QUARANTINED and reported
   * as a typed read failure — never returned as data, never repaired.
   */
  public readRecord(recordId: string): ReadResult {
    if (this.#closed) {
      return { ok: false, code: "store_closed", reason: "store is closed", quarantined: false };
    }
    const row = this.#db
      .prepare(`
        SELECT record_id, revision, record_kind, durability_class, transaction_id,
               commit_sequence, created_at_epoch_ms, payload_json, content_hash
        FROM records
        WHERE record_id = ?
        ORDER BY revision DESC
        LIMIT 1
      `)
      .get(recordId) as StoredRow | undefined;
    if (row === undefined) {
      return { ok: false, code: "not_found", reason: "no record with id '" + recordId + "'", quarantined: false };
    }
    return this.#verifyAndMaterialize(row);
  }

  /** Read ALL revisions of a record (ascending), each re-verified. */
  public readRecordHistory(recordId: string): { ok: true; records: readonly DurableRecordEnvelope[] } | ReadFailure {
    if (this.#closed) {
      return { ok: false, code: "store_closed", reason: "store is closed", quarantined: false };
    }
    const rows = this.#db
      .prepare(`
        SELECT record_id, revision, record_kind, durability_class, transaction_id,
               commit_sequence, created_at_epoch_ms, payload_json, content_hash
        FROM records
        WHERE record_id = ?
        ORDER BY revision ASC
      `)
      .all(recordId) as unknown as StoredRow[];
    const out: DurableRecordEnvelope[] = [];
    for (const row of rows) {
      const r = this.#verifyAndMaterialize(row);
      if (!r.ok) return r;
      out.push(r.record);
    }
    return { ok: true, records: out };
  }

  /** List record ids by kind (latest revision per id). */
  public listRecordIds(recordKind: RecordKind): readonly string[] {
    if (this.#closed) return [];
    const rows = this.#db
      .prepare("SELECT DISTINCT record_id FROM records WHERE record_kind = ? ORDER BY record_id ASC")
      .all(recordKind) as unknown as { record_id: string }[];
    return rows.map((r) => r.record_id);
  }

  #verifyAndMaterialize(row: StoredRow): ReadResult {
    let payload: unknown;
    try {
      payload = JSON.parse(row.payload_json);
    } catch {
      this.#quarantineRow(row, "malformed_envelope", "stored payload is not valid JSON");
      return { ok: false, code: "quarantined", reason: "record payload is not valid JSON — quarantined, never repaired", quarantined: true };
    }
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
      this.#quarantineRow(row, "malformed_envelope", "stored payload is not an object");
      return { ok: false, code: "quarantined", reason: "record payload is not an object — quarantined, never repaired", quarantined: true };
    }
    const revision = Number(row.revision);
    const envelope: DurableRecordEnvelope = Object.freeze({
      schemaVersion: DURABLE_RECORD_SCHEMA_VERSION_MARKER,
      recordId: row.record_id,
      recordKind: row.record_kind as RecordKind,
      durabilityClass: row.durability_class as DurableRecordEnvelope["durabilityClass"],
      secretPolicy: "secret_free",
      authority:
        row.durability_class === "append_only"
          ? "durable_evidence"
          : row.durability_class === "rebuildable"
            ? "derived_data"
            : "durable_state",
      revision,
      supersedesRevision: revision > 1 ? revision - 1 : null,
      createdAtEpochMs: row.created_at_epoch_ms,
      transactionId: row.transaction_id,
      payload: payload as Readonly<Record<string, unknown>>,
      contentHash: row.content_hash,
    } satisfies DurableRecordEnvelope);
    const status = verifyEnvelopeIntegrity(envelope);
    if (status === "integrity_failed") {
      this.#quarantineRow(row, "content_hash_mismatch", "stored bytes no longer match the sealed content hash");
      return { ok: false, code: "quarantined", reason: "content hash mismatch — record quarantined, never repaired", quarantined: true };
    }
    if (status === "integrity_unknown") {
      this.#quarantineRow(row, "malformed_envelope", "content hash missing or malformed");
      return { ok: false, code: "quarantined", reason: "content hash missing or malformed — record quarantined, never repaired", quarantined: true };
    }
    return { ok: true, record: envelope, commitSequence: row.commit_sequence };
  }

  #quarantineRow(row: StoredRow, cause: string, detail: string): void {
    try {
      this.#db.prepare(`
        INSERT OR IGNORE INTO quarantine
          (record_id, as_found_hash, cause, detail, quarantined_at_epoch_ms, payload_json)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(row.record_id, row.content_hash, cause, truncateReason(detail), Date.now(), row.payload_json);
    } catch {
      // Quarantine itself must never crash a read; the record simply stays
      // unreadable, which is the fail-closed outcome.
    }
  }

  /** List quarantine records (audit surface; quarantined bytes are data-of-record, never restored). */
  public listQuarantined(): readonly QuarantineRowView[] {
    if (this.#closed) return [];
    const rows = this.#db
      .prepare("SELECT record_id, as_found_hash, cause, detail, quarantined_at_epoch_ms FROM quarantine ORDER BY quarantined_at_epoch_ms ASC, record_id ASC")
      .all() as unknown as QuarantineRowView[];
    return rows;
  }

  // ── derived index (separate, rebuildable, never authoritative) ───────────

  /** Write one derived-index entry. Replaces any prior value for the key. */
  public setDerivedEntry(indexId: string, entryKey: string, entryValue: string): { ok: true } | { ok: false; reason: string } {
    if (this.#closed) return { ok: false, reason: "store is closed" };
    if (typeof indexId !== "string" || !/^[a-z][a-z0-9_-]{0,63}$/.test(indexId)) {
      return { ok: false, reason: "indexId must match ^[a-z][a-z0-9_-]{0,63}$" };
    }
    if (typeof entryKey !== "string" || entryKey.length === 0 || entryKey.length > 256) {
      return { ok: false, reason: "entryKey must be a non-empty string of at most 256 chars" };
    }
    if (typeof entryValue !== "string" || entryValue.length > 4096) {
      return { ok: false, reason: "entryValue must be a string of at most 4096 chars" };
    }
    try {
      this.#db.prepare(`
        INSERT INTO derived_index (index_id, entry_key, entry_value, built_at_commit)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(index_id, entry_key) DO UPDATE SET entry_value = excluded.entry_value, built_at_commit = excluded.built_at_commit
      `).run(indexId, entryKey, entryValue, this.committedThrough);
      return { ok: true };
    } catch (e) {
      return { ok: false, reason: truncateReason(String((e as Error).message)) };
    }
  }

  /** Read one derived-index entry (derived data; never authority). */
  public getDerivedEntry(indexId: string, entryKey: string): string | null {
    if (this.#closed) return null;
    const row = this.#db
      .prepare("SELECT entry_value FROM derived_index WHERE index_id = ? AND entry_key = ?")
      .get(indexId, entryKey) as { entry_value: string } | undefined;
    return row?.entry_value ?? null;
  }

  /** Discard one entire derived index (rebuildable by design). */
  public dropDerivedIndex(indexId: string): void {
    if (this.#closed) return;
    this.#db.prepare("DELETE FROM derived_index WHERE index_id = ?").run(indexId);
  }

  // ── checkpoint metadata ──────────────────────────────────────────────────

  /**
   * Write a checkpoint summarizing committed state. The checkpoint hash is
   * recomputed from its own contents; a later reader can detect checkpoint
   * drift without trusting the row.
   */
  public writeCheckpoint(input: { checkpointId: string; ledgerTailHash: string }): { ok: true; checkpoint: StoreCheckpointView } | { ok: false; reason: string } {
    if (this.#closed) return { ok: false, reason: "store is closed" };
    if (typeof input.checkpointId !== "string" || !/^[a-z][a-z0-9-]{2,63}$/.test(input.checkpointId)) {
      return { ok: false, reason: "checkpointId must match ^[a-z][a-z0-9-]{2,63}$" };
    }
    const committedThrough = this.committedThrough;
    const countRow = this.#db
      .prepare(`
        SELECT COUNT(DISTINCT record_id) AS c FROM records
        WHERE record_kind IN ('event_ledger_entry','tool_run_evidence','memory_record','agent_metadata','goal_lifecycle','skill_tool_registry')
      `)
      .get() as { c: number | bigint };
    const authoritativeCount = Number(countRow.c);
    const checkpointHash = canonicalHash({
      checkpointId: input.checkpointId,
      committedThrough,
      authoritativeCount,
      ledgerTailHash: input.ledgerTailHash,
    });
    try {
      this.#db.prepare(`
        INSERT OR REPLACE INTO checkpoints
          (checkpoint_id, committed_through, authoritative_count, ledger_tail_hash, checkpoint_hash, created_at_epoch_ms)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(input.checkpointId, committedThrough, authoritativeCount, input.ledgerTailHash, checkpointHash, Date.now());
      return {
        ok: true,
        checkpoint: {
          checkpointId: input.checkpointId,
          committedThrough,
          authoritativeCount,
          ledgerTailHash: input.ledgerTailHash,
          checkpointHash,
        },
      };
    } catch (e) {
      return { ok: false, reason: truncateReason(String((e as Error).message)) };
    }
  }

  /**
   * Verify the latest checkpoint's self-consistency against CURRENT store
   * state. Returns `rebuild_required` when the checkpoint is stale or
   * drifted — the caller rebuilds derived data; the checkpoint is never
   * "healed" to match.
   */
  public verifyCheckpoint(input: { ledgerTailHash: string }): CheckpointVerifyResult {
    if (this.#closed) {
      return { verdict: "store_closed", committedThrough: null, checkpointCommittedThrough: null };
    }
    const row = this.#db
      .prepare(`
        SELECT checkpoint_id, committed_through, authoritative_count, ledger_tail_hash, checkpoint_hash
        FROM checkpoints
        ORDER BY created_at_epoch_ms DESC
        LIMIT 1
      `)
      .get() as CheckpointStoredRow | undefined;
    if (row === undefined) {
      return { verdict: "no_checkpoint", committedThrough: this.committedThrough, checkpointCommittedThrough: null };
    }
    const expectedHash = canonicalHash({
      checkpointId: row.checkpoint_id,
      committedThrough: row.committed_through,
      authoritativeCount: row.authoritative_count,
      ledgerTailHash: row.ledger_tail_hash,
    });
    if (expectedHash !== row.checkpoint_hash) {
      return { verdict: "rebuild_required", committedThrough: this.committedThrough, checkpointCommittedThrough: row.committed_through, reason: "checkpoint hash drift (row contents no longer match the sealed hash)" };
    }
    const countRow = this.#db
      .prepare(`
        SELECT COUNT(DISTINCT record_id) AS c FROM records
        WHERE record_kind IN ('event_ledger_entry','tool_run_evidence','memory_record','agent_metadata','goal_lifecycle','skill_tool_registry')
      `)
      .get() as { c: number | bigint };
    if (Number(countRow.c) !== row.authoritative_count) {
      return { verdict: "rebuild_required", committedThrough: this.committedThrough, checkpointCommittedThrough: row.committed_through, reason: "authoritative record count diverged from the checkpoint (store advanced or was rolled back)" };
    }
    if (row.ledger_tail_hash !== input.ledgerTailHash) {
      return { verdict: "rebuild_required", committedThrough: this.committedThrough, checkpointCommittedThrough: row.committed_through, reason: "ledger tail hash diverged from the checkpoint" };
    }
    return { verdict: "consistent", committedThrough: this.committedThrough, checkpointCommittedThrough: row.committed_through };
  }

  // ── small helpers ────────────────────────────────────────────────────────

  #deny(failureCode: DenyFailureCode, reason: string, transactionId: string | null): PersistDecision {
    return { ok: false, committed: false, failureCode, reason: truncateReason(reason), transactionId };
  }
}

// ── supporting types ─────────────────────────────────────────────────────────

interface StoredRow {
  readonly record_id: string;
  readonly revision: number;
  readonly record_kind: string;
  readonly durability_class: string;
  readonly transaction_id: string;
  readonly commit_sequence: number;
  readonly created_at_epoch_ms: number;
  readonly payload_json: string;
  readonly content_hash: string;
}

export interface QuarantineRowView {
  readonly record_id: string;
  readonly as_found_hash: string;
  readonly cause: string;
  readonly detail: string;
  readonly quarantined_at_epoch_ms: number | bigint;
}

export interface StoreCheckpointView {
  readonly checkpointId: string;
  readonly committedThrough: CommitSequence;
  readonly authoritativeCount: number;
  readonly ledgerTailHash: string;
  readonly checkpointHash: string;
}

interface CheckpointStoredRow {
  readonly checkpoint_id: string;
  readonly committed_through: number;
  readonly authoritative_count: number;
  readonly ledger_tail_hash: string;
  readonly checkpoint_hash: string;
}

export type CheckpointVerifyResult =
  | { readonly verdict: "consistent"; readonly committedThrough: CommitSequence; readonly checkpointCommittedThrough: CommitSequence }
  | { readonly verdict: "no_checkpoint"; readonly committedThrough: CommitSequence; readonly checkpointCommittedThrough: null }
  | { readonly verdict: "rebuild_required"; readonly committedThrough: CommitSequence; readonly checkpointCommittedThrough: CommitSequence; readonly reason: string }
  | { readonly verdict: "store_closed"; readonly committedThrough: null; readonly checkpointCommittedThrough: null };

export type ReadFailureCode = "not_found" | "store_closed" | "quarantined";

export type ReadFailure = {
  readonly ok: false;
  readonly code: ReadFailureCode;
  readonly reason: string;
  readonly quarantined: boolean;
};

export type ReadResult =
  | { readonly ok: true; readonly record: DurableRecordEnvelope; readonly commitSequence: CommitSequence }
  | ReadFailure;

type PersistDecisionFailureCode = Extract<PersistDecision, { ok: false }>["failureCode"];

/**
 * Failure codes the store itself can emit beyond the validation codes
 * decided by decidePersist.
 */
type DenyFailureCode =
  | PersistDecisionFailureCode
  | "transaction_open"
  | "invalid_transaction_id";

/** stageRecord's typed denial (subset of the persist vocabulary). */
export type StageRecordResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly failureCode: DenyFailureCode;
      readonly reason: string;
    };

/**
 * Read-back envelopes are re-materialized under the pinned record schema
 * version (the store only persists records that validated against it).
 */
const DURABLE_RECORD_SCHEMA_VERSION_MARKER = "menog-durable-record/v0" as const;
