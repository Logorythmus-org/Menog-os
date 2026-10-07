/**
 * PHASE 22A — Canonical serialization + hashing for durable records.
 *
 * Deterministic JSON (recursively sorted keys, no insignificant whitespace),
 * mirroring the isolation/commit-engine/memory canonical discipline so
 * content hashes are stable across processes and platforms. Pure functions
 * only: no I/O, no storage, no authority.
 */

import { createHash } from "node:crypto";
import type {
  DurableRecordEnvelope,
  DurableRecordEnvelopeBody,
} from "./records.js";
import { DURABLE_RECORD_SCHEMA_VERSION } from "./records.js";

export function canonicalDurableJson(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "number") {
    if (!Number.isFinite(value)) return "null";
    return String(value);
  }
  if (t === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) {
    const items = value.map((v) => canonicalDurableJson(v));
    return "[" + items.join(",") + "]";
  }
  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    const parts = keys.map((k) => JSON.stringify(k) + ":" + canonicalDurableJson(obj[k]));
    return "{" + parts.join(",") + "}";
  }
  // Functions/symbols/etc. are not representable in durable payloads.
  return "null";
}

/**
 * SHA-256 hex over the canonical body of an envelope. The `contentHash`
 * field itself is excluded from the hash input (a record's hash never
 * includes itself).
 */
export function durableContentHash(body: DurableRecordEnvelopeBody): string {
  return createHash("sha256")
    .update(canonicalDurableJson(body), "utf8")
    .digest("hex");
}

/**
 * Generic canonical hash over ANY JSON-representable value (used for
 * checkpoint self-integrity and other store-internal bindings). Same
 * discipline as durableContentHash; not envelope-specific.
 */
export function canonicalHash(value: unknown): string {
  return createHash("sha256")
    .update(canonicalDurableJson(value), "utf8")
    .digest("hex");
}

/**
 * Verify an envelope's self-integrity against its own contentHash. Returns
 * the typed IntegrityStatus; this function NEVER repairs, NEVER re-stamps.
 * A mismatch is a corruption finding for the caller to quarantine.
 */
export function verifyEnvelopeIntegrity(
  envelope: DurableRecordEnvelope,
  options: { readonly hasher?: typeof durableContentHash } = {}
): "integrity_verified" | "integrity_failed" | "integrity_unknown" {
  if (typeof envelope.contentHash !== "string" || envelope.contentHash.length !== 64) {
    return "integrity_unknown";
  }
  const hash = (options.hasher ?? durableContentHash)(envelopeBodyOf(envelope));
  if (hash !== envelope.contentHash) {
    return "integrity_failed";
  }
  return "integrity_verified";
}

/** Strip the hash field, producing the canonical hash input. */
export function envelopeBodyOf(
  envelope: DurableRecordEnvelope
): DurableRecordEnvelopeBody {
  const { contentHash: _contentHash, ...body } = envelope;
  return body;
}

/** True when the envelope claims the pinned record schema version. */
export function hasKnownRecordSchema(
  envelope: Pick<DurableRecordEnvelope, "schemaVersion">
): boolean {
  return envelope.schemaVersion === DURABLE_RECORD_SCHEMA_VERSION;
}
