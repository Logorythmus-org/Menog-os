import { SEMANTIQ_SCHEMA_VERSION } from "./types.js";
import type {
  SemantiqEvaluationEvent,
  SemantiqEvaluationRecord,
} from "./types.js";
import {
  SEMANTIQ_MAX_RECORDS,
  evaluationEventHash,
  evaluationRecordId,
  validateEvaluationEvent,
} from "./events.js";

/**
 * Phase 18B — bounded persistor for typed evaluation events.
 *
 * ADR-0007 §Decision 5: evaluations are NOT ledger events. Evaluation
 * records live NEXT TO the ledger (a separate store), never rewrite or
 * shadow it. The store:
 *  - accepts ONLY schema-valid events (validateEvaluationEvent gate);
 *  - is INSERT-ONCE per record id: a record id already present is REJECTED
 *    — persisted provenance cannot be rewritten through this surface;
 *  - is bounded (SEMANTIQ_MAX_RECORDS); beyond the bound it fails CLOSED
 *    (store_full) rather than silently evicting provenance history;
 *  - validates on READ as well: a corrupted/tampered persisted payload
 *    surfaces as a machine-readable validation failure, never as data.
 */

export type SemantiqStoreResult =
  | { readonly ok: true; readonly record: SemantiqEvaluationRecord }
  | {
      readonly ok: false;
      readonly denyReason: "invalid_event" | "duplicate_record" | "store_full";
      readonly reason: string;
    };

export class SemantiqEvaluationRecordStore {
  readonly #records: Map<string, SemantiqEvaluationRecord> = new Map();
  readonly #order: string[] = [];

  /**
   * Validate + persist one evaluation event. Insert-once: re-persisting a
   * byte-identical event is a duplicate_record denial, never a rewrite.
   */
  persist(
    event: SemantiqEvaluationEvent
  ): SemantiqStoreResult {
    const err = validateEvaluationEvent(event);
    if (err !== null) {
      return { ok: false, denyReason: "invalid_event", reason: err };
    }
    const contentHash = evaluationEventHash(event);
    const recordId = evaluationRecordId(event, contentHash);
    if (this.#records.has(recordId)) {
      return {
        ok: false,
        denyReason: "duplicate_record",
        reason: "an identical evaluation event is already persisted (insert-once)",
      };
    }
    if (this.#records.size >= SEMANTIQ_MAX_RECORDS) {
      return {
        ok: false,
        denyReason: "store_full",
        reason:
          "record store is full (" +
          String(SEMANTIQ_MAX_RECORDS) +
          "); failing closed rather than evicting provenance",
      };
    }
    const record: SemantiqEvaluationRecord = Object.freeze({
      recordId,
      eventId: recordId,
      createdAtEpochMs: event.kind === "result"
        ? event.evaluatedAtEpochMs
        : event.kind === "denied"
          ? event.deniedAtEpochMs
          : event.requestedAtEpochMs,
      event,
      contentHash,
    });
    this.#records.set(recordId, record);
    this.#order.push(recordId);
    return { ok: true, record };
  }

  /**
   * Return records oldest-first, oldest-N if `limit` is given. Every record
   * is re-validated on read; a corrupted payload is DROPPED and surfaced via
   * `corruptedDropped` (read path never returns unvalidated data).
   */
  read(limit?: number): {
    readonly records: readonly SemantiqEvaluationRecord[];
    readonly corruptedDropped: number;
  } {
    const out: SemantiqEvaluationRecord[] = [];
    let corrupted = 0;
    for (const id of this.#order) {
      const rec = this.#records.get(id);
      if (rec === undefined) continue;
      if (validateEvaluationEvent(rec.event) !== null) {
        corrupted++;
        continue;
      }
      out.push(rec);
    }
    const sliced =
      typeof limit === "number" && Number.isFinite(limit) && limit >= 0
        ? out.slice(0, limit)
        : out;
    return { records: Object.freeze(sliced), corruptedDropped: corrupted };
  }

  /** Number of persisted records (observable). */
  get length(): number {
    return this.#records.size;
  }

  /** Look up one record by id; null when absent. */
  getById(recordId: string): SemantiqEvaluationRecord | null {
    return this.#records.get(recordId) ?? null;
  }

  /**
   * Deterministic persistence summary for the most recent event of each
   * kind (observability only — machine-readable counts, no content).
   */
  summary(): Readonly<Record<"request" | "result" | "denied", number>> {
    const counts = { request: 0, result: 0, denied: 0 };
    for (const id of this.#order) {
      const rec = this.#records.get(id);
      if (rec !== undefined) counts[rec.event.kind]++;
    }
    return Object.freeze(counts);
  }
}

/** Schema-version guard re-exported for consumers of persisted records. */
export function isCurrentSchemaVersion(v: unknown): v is typeof SEMANTIQ_SCHEMA_VERSION {
  return v === SEMANTIQ_SCHEMA_VERSION;
}
