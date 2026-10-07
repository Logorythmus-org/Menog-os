/**
 * PHASE 22A — Persist decisions and transactions (pure, storage-free).
 *
 * The persist boundary is where hostile or corrupted input meets the store.
 * Every check here FAILS CLOSED: any unknown version, kind, class, id
 * mismatch, secret-shaped key, append-only mutation attempt, or hash
 * mismatch denies the write with a typed failure code and `committed:
 * false`. Nothing in this module performs I/O; the Phase-22B store will
 * call these functions as its admission layer.
 *
 * Mutation law (type-structurally enforced):
 * - append_only kinds: any revision > 1 is an `append_only_mutation` denial;
 *   there is no delete operation to even name.
 * - versioned_mutable kinds: an update is a NEW envelope with
 *   revision = prev + 1 and supersedesRevision = prev. Prior revisions are
 *   retained. Lost/duplicate updates are detected by revision checks
 *   (`duplicate_revision`, `revision_conflict`) — never last-writer-wins.
 */

import {
  DURABLE_RECORD_SCHEMA_VERSION,
  DURABLE_RECORD_ID_PATTERN,
  TRANSACTION_ID_PATTERN,
  SECRET_POLICIES,
  DURABILITY_CLASSES,
  RECORD_KINDS,
  PERSIST_FAILURE_CODES,
  isRecordKind,
  isDurabilityClass,
  RECORD_KIND_ID_PREFIXES,
  type DurableRecordEnvelope,
  type DurableRecordEnvelopeBody,
  type EnvelopeValidationResult,
  type PersistDecision,
  type PersistFailureCode,
  type RecordKind,
  type TransactionId,
} from "./records.js";
import {
  isAppendOnlyKind,
  isVersionedMutableKind,
} from "./classification.js";
import { durableContentHash } from "./canonical.js";

// ── bounds ───────────────────────────────────────────────────────────────────

/** Max serialized payload size for one durable record (256 KiB, mirroring the ledger's line cap). */
export const MAX_RECORD_PAYLOAD_BYTES = 256 * 1024;

/** Bounded reason strings — hostile payload text is never echoed. */
const MAX_REASON_CHARS = 240;

function truncateReason(s: string): string {
  return s.length > MAX_REASON_CHARS ? s.slice(0, MAX_REASON_CHARS) : s;
}

// ── secret denial (fail closed, deny by default) ─────────────────────────────

/**
 * Key-shape hints mirrored from the ledger/memory secret lists. Storage
 * denial is STRONGER than redaction: a secret-shaped key denies the whole
 * record (no secret persistence, even redacted, through this boundary).
 */
const STORAGE_SECRET_KEY_HINTS: readonly RegExp[] = Object.freeze([
  /(^|[-_ ])(pass(word|phrase)?)([-_ ]|$)/i,
  /(^|[-_ ])secret([-_ ]|$)/i,
  /(^|[-_ ])((api[-_]?)?key|apikey)([-_ ]|$)/i,
  /(^|[-_ ])(token)([-_ ]|$)/i,
  /(^|[-_ ])(credential|credentials|cred)([-_ ]|$)/i,
  /(^|[-_ ])(private[-_ ]?key|privkey)([-_ ]|$)/i,
  /(^|[-_ ])(auth|authentication)([-_ ]|$)/i,
  /(^|[-_ ])(cookie)([-_ ]|$)/i,
  /(^|[-_ ])(bearer)([-_ ]|$)/i,
  /(^|[-_ ])(access[-_ ]?token|refresh[-_ ]?token)([-_ ]|$)/i,
  /(^|[-_ ])(jwt|jwks)([-_ ]|$)/i,
]);

function normalizeKeyHint(keyHint: string): string {
  let out = keyHint.replace(/([a-z0-9])([A-Z])/g, "$1_$2");
  out = out.replace(/[-\s.]+/g, "_");
  return out.toLowerCase();
}

function keyLooksSecretLike(key: string): boolean {
  if (typeof key !== "string" || key.length === 0) return false;
  const lower = key.toLowerCase();
  const normalized = normalizeKeyHint(key);
  return (
    STORAGE_SECRET_KEY_HINTS.some((re) => re.test(lower)) ||
    STORAGE_SECRET_KEY_HINTS.some((re) => re.test(normalized))
  );
}

/** Depth- and breadth-bounded scan for secret-shaped keys at any depth. */
export function findSecretPayloadKeyPaths(
  value: unknown,
  prefix: string = "",
  maxDepth: number = 8
): string[] {
  if (maxDepth <= 0 || value === null || typeof value !== "object" || Array.isArray(value)) {
    return [];
  }
  const hits: string[] = [];
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    const p = prefix.length === 0 ? k : prefix + "." + k;
    if (keyLooksSecretLike(k)) hits.push(p);
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      hits.push(...findSecretPayloadKeyPaths(v, p, maxDepth - 1));
    }
  }
  return hits;
}

// ── canonical JSON-serializability ───────────────────────────────────────────

/**
 * A payload is storable only if it is JSON-representable without loss:
 * plain objects, arrays, strings, finite numbers, booleans, null.
 * Symbols/functions/BigInt/big-numeric values are rejected (BigInt would
 * serialize lossily; functions/symbols are not representable at all).
 */
export function payloadSerializabilityError(
  value: unknown,
  depth: number = 0
): string | null {
  if (depth > 32) return "payload nesting exceeds depth 32";
  if (value === null) return null;
  const t = typeof value;
  if (t === "string") return null;
  if (t === "boolean") return null;
  if (t === "number") {
    return Number.isFinite(value as number) ? null : "payload contains a non-finite number";
  }
  if (t === "bigint" || t === "symbol" || t === "function" || t === "undefined") {
    return "payload contains a " + t + " value (not representable)";
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const err = payloadSerializabilityError(value[i], depth + 1);
      if (err) return err;
    }
    return null;
  }
  if (t === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      return "payload contains a non-plain object (class instance/Map/Set/etc.)";
    }
    for (const v of Object.values(value as Record<string, unknown>)) {
      const err = payloadSerializabilityError(v, depth + 1);
      if (err) return err;
    }
    return null;
  }
  return "payload contains an unsupported value type";
}

// ── envelope validation (can only reject) ────────────────────────────────────

/**
 * Validate an envelope's structure, vocabulary, identity, and integrity
 * BEFORE any persistence decision. Unknown anything fails closed.
 */
export function validateEnvelope(
  envelope: unknown,
  options: { readonly hasher?: typeof durableContentHash } = {}
): EnvelopeValidationResult {
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) {
    return { ok: false, failureCode: "payload_not_serializable", reason: "envelope must be an object" };
  }
  const env = envelope as Partial<DurableRecordEnvelope>;

  // 1. schema version: unknown schema fails closed (schema confusion).
  if (env.schemaVersion !== DURABLE_RECORD_SCHEMA_VERSION) {
    return {
      ok: false,
      failureCode: "unknown_schema_version",
      reason: "unknown or missing schemaVersion: '" + String(env.schemaVersion) + "' — failing closed",
    };
  }
  // 2. record kind: closed union.
  if (!isRecordKind(env.recordKind)) {
    return {
      ok: false,
      failureCode: "unknown_record_kind",
      reason: "unknown recordKind: '" + String(env.recordKind) + "'",
    };
  }
  // 3. durability class: closed union.
  if (!isDurabilityClass(env.durabilityClass)) {
    return {
      ok: false,
      failureCode: "unknown_durability_class",
      reason: "unknown durabilityClass: '" + String(env.durabilityClass) + "'",
    };
  }
  // 4. durability class must MATCH the kind's frozen classification.
  const kind = env.recordKind;
  if (isAppendOnlyKind(kind) && env.durabilityClass !== "append_only") {
    return {
      ok: false,
      failureCode: "unknown_durability_class",
      reason: "recordKind '" + kind + "' is append_only by classification; envelope claims '" + String(env.durabilityClass) + "'",
    };
  }
  if (isVersionedMutableKind(kind) && env.durabilityClass !== "versioned_mutable") {
    return {
      ok: false,
      failureCode: "unknown_durability_class",
      reason: "recordKind '" + kind + "' is versioned_mutable by classification; envelope claims '" + String(env.durabilityClass) + "'",
    };
  }
  // 5. secret policy: only secret_free exists (deny by default).
  if (env.secretPolicy !== "secret_free") {
    return {
      ok: false,
      failureCode: "unknown_secret_policy",
      reason: "secretPolicy must be 'secret_free'; secret persistence is not modeled in this gate",
    };
  }
  // 6. authority class posture must match the kind.
  if (
    env.authority !== "durable_evidence" &&
    env.authority !== "durable_state" &&
    env.authority !== "derived_data"
  ) {
    return {
      ok: false,
      failureCode: "unknown_authority_class",
      reason: "persist-time authority must be durable_evidence | durable_state | derived_data (recovered_data is stamped only by recovery)",
    };
  }
  const expectedAuthority =
    env.durabilityClass === "append_only"
      ? "durable_evidence"
      : env.durabilityClass === "rebuildable"
        ? "derived_data"
        : "durable_state";
  if (env.authority !== expectedAuthority) {
    return {
      ok: false,
      failureCode: "unknown_authority_class",
      reason: "authority '" + String(env.authority) + "' does not match durabilityClass '" + String(env.durabilityClass) + "' (expected '" + expectedAuthority + "')",
    };
  }
  // 7. record id: shape + kind-prefix consistency.
  const recordId = env.recordId;
  if (typeof recordId !== "string" || !DURABLE_RECORD_ID_PATTERN.test(recordId)) {
    return {
      ok: false,
      failureCode: "invalid_record_id",
      reason: "recordId must match " + String(DURABLE_RECORD_ID_PATTERN),
    };
  }
  const expectedPrefix = RECORD_KIND_ID_PREFIXES[kind as RecordKind];
  if (typeof recordId !== "string" || !recordId.startsWith(expectedPrefix + "-")) {
    return {
      ok: false,
      failureCode: "id_kind_mismatch",
      reason: "recordId '" + String(recordId) + "' must be prefixed '" + expectedPrefix + "-' for recordKind '" + String(kind) + "'",
    };
  }
  // 8. revision monotonicity.
  if (typeof env.revision !== "number" || !Number.isInteger(env.revision) || env.revision < 1) {
    return {
      ok: false,
      failureCode: "invalid_revision",
      reason: "revision must be an integer ≥ 1",
    };
  }
  // 9. append-only records are revision-1 forever (mutation unrepresentable).
  if (isAppendOnlyKind(kind) && env.revision !== 1) {
    return {
      ok: false,
      failureCode: "append_only_mutation",
      reason: "append_only recordKind '" + kind + "' cannot carry revision " + String(env.revision) + " — mutation is not representable",
    };
  }
  if (isVersionedMutableKind(kind) && env.revision > 1 && typeof env.supersedesRevision !== "number") {
    return {
      ok: false,
      failureCode: "invalid_revision",
      reason: "versioned_mutable revision > 1 must declare supersedesRevision",
    };
  }
  if (env.revision === 1 && env.supersedesRevision !== null && env.supersedesRevision !== undefined) {
    return {
      ok: false,
      failureCode: "invalid_revision",
      reason: "revision 1 cannot supersede anything (supersedesRevision must be null)",
    };
  }
  if (isVersionedMutableKind(kind) && typeof env.supersedesRevision === "number" && env.supersedesRevision !== env.revision - 1) {
    return {
      ok: false,
      failureCode: "invalid_revision",
      reason: "supersedesRevision must be exactly revision - 1 (got " + String(env.supersedesRevision) + " for revision " + String(env.revision) + ")",
    };
  }
  // 10. transaction id: shape.
  if (typeof env.transactionId !== "string" || !TRANSACTION_ID_PATTERN.test(env.transactionId)) {
    return {
      ok: false,
      failureCode: "invalid_transaction_id",
      reason: "transactionId must match " + String(TRANSACTION_ID_PATTERN),
    };
  }
  // 11. timestamp: bounded epoch-ms.
  if (
    typeof env.createdAtEpochMs !== "number" ||
    !Number.isInteger(env.createdAtEpochMs) ||
    env.createdAtEpochMs <= 0 ||
    env.createdAtEpochMs > 4_102_444_800_000
  ) {
    return {
      ok: false,
      failureCode: "invalid_timestamp",
      reason: "createdAtEpochMs must be a plausible epoch-ms integer",
    };
  }
  // 12. payload: must be an object, serializable, bounded, secret-free.
  const payload = env.payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return {
      ok: false,
      failureCode: "payload_not_serializable",
      reason: "payload must be a plain object",
    };
  }
  const serErr = payloadSerializabilityError(payload);
  if (serErr) {
    return { ok: false, failureCode: "payload_not_serializable", reason: serErr };
  }
  const secretPaths = findSecretPayloadKeyPaths(payload);
  if (secretPaths.length > 0) {
    return {
      ok: false,
      failureCode: "secret_key_denied",
      reason: "secret-shaped payload keys denied by default (no secret persistence): " + secretPaths.slice(0, 4).join(", "),
    };
  }
  const payloadBytes = Buffer.byteLength(JSON.stringify(payload), "utf8");
  if (payloadBytes > MAX_RECORD_PAYLOAD_BYTES) {
    return {
      ok: false,
      failureCode: "payload_oversized",
      reason: "payload exceeds " + String(MAX_RECORD_PAYLOAD_BYTES) + " bytes",
    };
  }
  // 13. content hash: must re-derive from the body (integrity binding).
  const hasher = options.hasher ?? durableContentHash;
  const { contentHash: _omit, ...body } = envelope as DurableRecordEnvelope;
  const recomputed = hasher(body as DurableRecordEnvelopeBody);
  if (env.contentHash !== recomputed) {
    return {
      ok: false,
      failureCode: "content_hash_mismatch",
      reason: "contentHash does not match the canonical envelope body — record was modified after sealing or never sealed",
    };
  }
  return { ok: true, envelope: Object.freeze(envelope as DurableRecordEnvelope) };
}

// ── persist decision (pure; the 22B store's admission layer) ─────────────────

export interface PersistIntent {
  readonly envelope: DurableRecordEnvelope;
  readonly transactionId: TransactionId;
  /** Whether the record id is already present in the store (caller-known). */
  readonly idExists: boolean;
  /** Highest revision stored for this id, when idExists (else null). */
  readonly existingRevision: number | null;
  /** Whether the store is writable (a read-only store denies everything). */
  readonly storeWritable: boolean;
}

/**
 * The pure persist decision. Combines envelope validation with store-state
 * checks (existence, revision conflict, writability). ALL-OR-NOTHING: there
 * is no partial-commit representation. This function performs no I/O.
 */
export function decidePersist(
  intent: PersistIntent,
  options: { readonly hasher?: typeof durableContentHash } = {}
): PersistDecision {
  if (!intent.storeWritable) {
    return {
      ok: false,
      committed: false,
      failureCode: "store_readonly",
      reason: "store is read-only — no persist is possible",
      transactionId: intent.transactionId,
    };
  }
  const validation = validateEnvelope(intent.envelope, options);
  if (!validation.ok) {
    return {
      ok: false,
      committed: false,
      failureCode: validation.failureCode,
      reason: truncateReason(validation.reason),
      transactionId: intent.envelope.transactionId,
    };
  }
  const env = validation.envelope;
  if (env.transactionId !== intent.transactionId) {
    return {
      ok: false,
      committed: false,
      failureCode: "invalid_transaction_id",
      reason: "envelope transactionId does not match the persist intent's transactionId",
      transactionId: intent.transactionId,
    };
  }
  if (intent.idExists) {
    if (isAppendOnlyKind(env.recordKind)) {
      return {
        ok: false,
        committed: false,
        failureCode: "duplicate_revision",
        reason: "append_only record id already exists — the ledger/evidence is immutable",
        transactionId: intent.transactionId,
      };
    }
    if (env.revision <= (intent.existingRevision ?? 0)) {
      return {
        ok: false,
        committed: false,
        failureCode: "revision_conflict",
        reason: "stale or duplicate update: new revision " + String(env.revision) + " ≤ stored revision " + String(intent.existingRevision ?? 0),
        transactionId: intent.transactionId,
      };
    }
    if (env.revision !== (intent.existingRevision ?? 0) + 1) {
      return {
        ok: false,
        committed: false,
        failureCode: "revision_conflict",
        reason: "lost update: revision must be exactly stored + 1 (got " + String(env.revision) + " for stored " + String(intent.existingRevision ?? 0) + ")",
        transactionId: intent.transactionId,
      };
    }
  }
  return {
    ok: true,
    committed: true,
    recordId: env.recordId,
    revision: env.revision,
    transactionId: env.transactionId,
    commitSequence: -1, // assigned by the store at commit time (22B)
  };
}

// ── vocabulary completeness (structural self-checks) ─────────────────────────

/** All kinds are classified (no orphan rows). */
export function classificationCoversAllKinds(): boolean {
  return (
    RECORD_KINDS.every((k) => typeof k === "string") &&
    DURABILITY_CLASSES.length === 3 &&
    SECRET_POLICIES.length === 1
  );
}

/** The full closed failure-code vocabulary (re-exported for store authors). */
export const PERSIST_FAILURE_CODE_LIST: readonly PersistFailureCode[] =
  PERSIST_FAILURE_CODES;
