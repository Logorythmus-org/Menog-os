import { createHash, randomUUID } from "node:crypto";
import type {
  MemoryRecord,
  MemoryRecordInput,
  MemorySchemaVersion,
} from "./types.js";
import { MEMORY_SCHEMA_VERSION } from "./types.js";

/**
 * Canonical serialization + hashing for memory records (16A).
 *
 * Deterministic sorted-key JSON, mirroring the commit-engine canonical
 * serialization discipline: identical logical records serialize identically,
 * so a record's identity hash is stable across processes and runs.
 */

/** Validate a memory record input; returns an error string or null. */
export function validateMemoryRecordInput(
  input: MemoryRecordInput
): string | null {
  if (input === null || typeof input !== "object") {
    return "invalid input: must be object";
  }
  if (input.kind !== "working" && input.kind !== "project" && input.kind !== "execution") {
    return "invalid kind: must be 'working', 'project', or 'execution'";
  }
  const scope = input.scope as MemoryRecordInput["scope"] | undefined;
  if (!scope || typeof scope !== "object") {
    return "invalid scope: must be object";
  }
  if (typeof scope.workspaceId !== "string" || scope.workspaceId.length === 0) {
    return "invalid scope.workspaceId: must be non-empty string";
  }
  if (scope.taskId !== undefined && (typeof scope.taskId !== "string" || scope.taskId.length === 0)) {
    return "invalid scope.taskId: if present must be non-empty string";
  }
  if (scope.sessionId !== undefined && (typeof scope.sessionId !== "string" || scope.sessionId.length === 0)) {
    return "invalid scope.sessionId: if present must be non-empty string";
  }
  const prov = input.provenance as MemoryRecordInput["provenance"] | undefined;
  if (!prov || typeof prov !== "object") {
    return "invalid provenance: must be object";
  }
  if (!isProvenanceOrigin(prov.origin)) {
    return "invalid provenance.origin: unknown origin";
  }
  if (!prov.actor || typeof prov.actor !== "object") {
    return "invalid provenance.actor: must be object";
  }
  if (typeof prov.actor.type !== "string" || prov.actor.type.length === 0) {
    return "invalid provenance.actor.type: must be non-empty string";
  }
  if (typeof prov.actor.id !== "string" || prov.actor.id.length === 0) {
    return "invalid provenance.actor.id: must be non-empty string";
  }
  if (typeof prov.untrusted !== "boolean") {
    return "invalid provenance.untrusted: must be boolean";
  }
  if (prov.sourceEventId !== undefined && (typeof prov.sourceEventId !== "string" || prov.sourceEventId.length === 0)) {
    return "invalid provenance.sourceEventId: if present must be non-empty string";
  }
  if (prov.label !== undefined && (typeof prov.label !== "string" || prov.label.length === 0)) {
    return "invalid provenance.label: if present must be non-empty string";
  }
  const ret = input.retention as MemoryRecordInput["retention"] | undefined;
  if (!ret || typeof ret !== "object") {
    return "invalid retention: must be object";
  }
  if (
    ret.retentionClass !== "ephemeral" &&
    ret.retentionClass !== "session" &&
    ret.retentionClass !== "persistent"
  ) {
    return "invalid retention.retentionClass";
  }
  if (ret.retentionClass !== "ephemeral" && ret.expiresAtEpochMs !== undefined) {
    return "invalid retention.expiresAtEpochMs: only ephemeral entries may carry an absolute expiry";
  }
  if (
    ret.retentionClass === "ephemeral" &&
    (ret.expiresAtEpochMs === undefined || typeof ret.expiresAtEpochMs !== "number" || !Number.isFinite(ret.expiresAtEpochMs))
  ) {
    return "invalid retention.expiresAtEpochMs: ephemeral entries require a finite expiry";
  }
  if (input.body === null || typeof input.body !== "object" || Array.isArray(input.body)) {
    return "invalid body: must be a plain object";
  }
  return null;
}

function isProvenanceOrigin(value: unknown): boolean {
  return (
    value === "runtime" ||
    value === "human" ||
    value === "agent" ||
    value === "tool_output" ||
    value === "model_output" ||
    value === "repo_content" ||
    value === "external"
  );
}

function stableValue(value: unknown): unknown {
  if (value === null) return null;
  const t = typeof value;
  if (t === "string" || t === "boolean") return value;
  if (t === "number") return Number.isFinite(value as number) ? value : String(value);
  if (t === "bigint") return (value as bigint).toString();
  if (t === "undefined") return null;
  if (t === "function" || t === "symbol") return undefined;
  if (Array.isArray(value)) {
    return value.map((v) => {
      const s = stableValue(v);
      return s === undefined ? null : s;
    });
  }
  if (t === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      const v = stableValue((value as Record<string, unknown>)[k]);
      if (v !== undefined) out[k] = v;
    }
    return out;
  }
  return String(value);
}

/**
 * Deterministic sorted-key JSON serialization of the record body.
 * Returns null when the body contains values with no stable serialization
 * (functions/symbols are dropped by stableValue, so this is defensive).
 */
export function serializeMemoryBody(body: Readonly<Record<string, unknown>>): string {
  return JSON.stringify(stableValue(body));
}

/** Input to canonical record serialization (a fully built record). */
export type MemoryRecordForSerialize = Omit<MemoryRecord, "recordHash">;

const RECORD_KEY_ORDER: readonly string[] = Object.freeze([
  "schemaVersion",
  "memoryId",
  "kind",
  "scope",
  "provenance",
  "retention",
  "body",
  "createdAtEpochMs",
  "createdByActorId",
]);

function readonlyToPlain(value: object): Record<string, unknown> {
  return value as unknown as Record<string, unknown>;
}

/**
 * Canonical serialization of a full memory record: fixed key order, sorted
 * keys inside bodies/scopes/provenance. Equal records ⇒ equal strings.
 */
export function serializeMemoryRecord(record: MemoryRecordForSerialize): string {
  const scopeKeys = Object.keys(record.scope).sort();
  const scopeParts: string[] = [];
  for (const k of scopeKeys) {
    const v = readonlyToPlain(record.scope)[k];
    if (v === undefined) continue;
    scopeParts.push(JSON.stringify(k) + ":" + JSON.stringify(v));
  }

  const provKeys = Object.keys(record.provenance).sort();
  const provParts: string[] = [];
  for (const k of provKeys) {
    const v = readonlyToPlain(record.provenance)[k];
    if (v === undefined) continue;
    provParts.push(
      JSON.stringify(k) + ":" + (k === "actor" ? JSON.stringify({ type: record.provenance.actor.type, id: record.provenance.actor.id }) : JSON.stringify(v))
    );
  }

  const retKeys = Object.keys(record.retention).sort();
  const retParts: string[] = [];
  for (const k of retKeys) {
    const v = readonlyToPlain(record.retention)[k];
    if (v === undefined) continue;
    retParts.push(JSON.stringify(k) + ":" + JSON.stringify(v));
  }

  const map: Record<string, string> = {
    schemaVersion: JSON.stringify(record.schemaVersion),
    memoryId: JSON.stringify(record.memoryId),
    kind: JSON.stringify(record.kind),
    scope: "{" + scopeParts.join(",") + "}",
    provenance: "{" + provParts.join(",") + "}",
    retention: "{" + retParts.join(",") + "}",
    body: serializeMemoryBody(record.body),
    createdAtEpochMs: JSON.stringify(record.createdAtEpochMs),
    createdByActorId: JSON.stringify(record.createdByActorId),
  };

  const parts: string[] = [];
  for (const k of RECORD_KEY_ORDER) {
    parts.push(JSON.stringify(k) + ":" + map[k]!);
  }
  return "{" + parts.join(",") + "}";
}

/** SHA-256 hex of the canonical record serialization. */
export function memoryRecordHash(record: MemoryRecordForSerialize): string {
  return createHash("sha256").update(serializeMemoryRecord(record), "utf8").digest("hex");
}

export function newMemoryId(prefix: string = "mem"): string {
  const safePrefix = /^[a-z][a-z0-9-]{0,15}$/i.test(prefix) ? prefix : "mem";
  return safePrefix + "-" + randomUUID().replace(/-/g, "").slice(0, 24);
}

/** Recursively freeze a value (structured runtime state must be immutable). */
function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  Object.freeze(value);
  for (const k of Object.keys(value as Record<string, unknown>)) {
    deepFreeze((value as Record<string, unknown>)[k]);
  }
  return value;
}

/** Freeze a validated input into an immutable MemoryRecord. */
export function materializeMemoryRecord(
  input: MemoryRecordInput,
  options: {
    readonly memoryId?: string;
    readonly createdAtEpochMs?: number;
  } = {}
): MemoryRecord {
  const err = validateMemoryRecordInput(input);
  if (err !== null) {
    throw new Error("memory: cannot materialize invalid record: " + err);
  }
  const createdAtEpochMs = options.createdAtEpochMs ?? Date.now();
  const record: MemoryRecord = Object.freeze({
    schemaVersion: MEMORY_SCHEMA_VERSION,
    memoryId:
      options.memoryId ??
      newMemoryId(input.kind === "working" ? "wm" : input.kind === "execution" ? "ex" : "pm"),
    kind: input.kind,
    scope: deepFreeze({ ...input.scope }),
    provenance: deepFreeze({
      origin: input.provenance.origin,
      actor: Object.freeze({
        type: input.provenance.actor.type,
        id: input.provenance.actor.id,
      }),
      sourceEventId: input.provenance.sourceEventId,
      label: input.provenance.label,
      untrusted: input.provenance.untrusted,
    }),
    retention: deepFreeze({
      retentionClass: input.retention.retentionClass,
      expiresAtEpochMs: input.retention.expiresAtEpochMs,
    }),
    body: deepFreeze({ ...input.body }),
    createdAtEpochMs,
    createdByActorId: input.provenance.actor.id,
  });
  return record;
}

/** Round-trip: a record serialized canonically and re-parsed is deep-equal in content. */
export function memoryRecordRoundTrip(
  record: MemoryRecord
): { ok: true; canonical: string } | { ok: false; reason: string } {
  const canonical = serializeMemoryRecord(record);
  try {
    const parsed: unknown = JSON.parse(canonical);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, reason: "canonical serialization is not a JSON object" };
    }
    const obj = parsed as Record<string, unknown>;
    if (obj["schemaVersion"] !== record.schemaVersion) {
      return { ok: false, reason: "schemaVersion lost in round-trip" };
    }
    if (obj["memoryId"] !== record.memoryId) {
      return { ok: false, reason: "memoryId lost in round-trip" };
    }
    return { ok: true, canonical };
  } catch (e) {
    return { ok: false, reason: "canonical serialization is not valid JSON: " + String((e as Error).message) };
  }
}

export type { MemorySchemaVersion };
