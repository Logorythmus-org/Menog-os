/**
 * PRE-20B — Canonical serialization + hashing for isolation contracts.
 *
 * Deterministic JSON (recursively sorted object keys, no insignificant
 * whitespace) so evidence hashes are stable across processes and platforms.
 * Same discipline as @menog/commit-engine's canonicalHash, kept local because
 * runtime-linux must not depend on commit-engine.
 */

import { createHash } from "node:crypto";

export function canonicalIsolationJson(value: unknown): string {
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
    const items = value.map((v) => canonicalIsolationJson(v));
    return "[" + items.join(",") + "]";
  }
  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    const parts = keys.map((k) => JSON.stringify(k) + ":" + canonicalIsolationJson(obj[k]));
    return "{" + parts.join(",") + "}";
  }
  // Functions/symbols/etc. are not representable.
  return "null";
}

export function isolationEvidenceHash(value: unknown): string {
  return createHash("sha256").update(canonicalIsolationJson(value), "utf8").digest("hex");
}
