import { createHash } from "node:crypto";
import { SEMANTIQ_SCHEMA_VERSION } from "./types.js";
import type { SemantiqEvaluationRecord } from "./types.js";
import {
  SEMANTIQ_MAX_ID_CHARS,
  evaluationEventHash,
  evaluationRecordId,
  stableStringify,
  validateEvaluationEvent,
} from "./events.js";
import { SEMANTIQ_MAX_EVENT_ID_CHARS } from "./rules.js";

/**
 * Phase 18C — Evidence Export / Import (bounded, secret-free, validated).
 *
 * EXPORT: bounded, deterministic, SECRET-FREE-BY-DEFAULT evidence packages
 * built from evaluation records (+ optional bounded ledger event summaries).
 * Every string field passes a layered redaction scanner; oversized content
 * is TRUNCATED rather than dropped (record counts are stable); redactions
 * are counted and reported in package metadata. No file/network I/O exists
 * here — export/import operate on in-memory structures and callers own any
 * persistence (NO WRITE WITHOUT SCOPE, NO NETWORK WITHOUT POLICY).
 *
 * IMPORT: deny-by-default validation of untrusted packages:
 *  - schema gate (exact version, bounded sizes, known kinds);
 *  - record integrity: stored hash must equal recomputed canonical hash
 *    (tampered packages deny `tampered_record`);
 *  - id integrity: recordId must equal the deterministic record id;
 *  - evaluator identity: engineId/engineVersion, WHEN PROVIDED, are
 *    validated against the caller's allow-list; unknown evaluators deny
 *    `unknown_evaluator` — import of evaluation results is opt-in per
 *    source, never ambient trust;
 *  - imported events must re-pass the full 18B schema validator.
 *
 * Imported records are watermarked with their package hash and are never
 * authority: they carry the same advisory pins the 18B builders re-stamp.
 */

// ---------------------------------------------------------------------------
// Caps (18C) — bounded transfer surface.
// ---------------------------------------------------------------------------

export const SEMANTIQ_MAX_EXPORT_RECORDS = 256;
export const SEMANTIQ_MAX_EXPORT_EVENTS = 256;
export const SEMANTIQ_MAX_STRING_CHARS = 512;
export const SEMANTIQ_MAX_VALUE_CHARS = 1024;
export const SEMANTIQ_MAX_TOTAL_BYTES = 262_144;
export const SEMANTIQ_MAX_PACKAGES = 1;

// ---------------------------------------------------------------------------
// Secret scanning (defense in depth — deny by default, then redact).
// ---------------------------------------------------------------------------

/**
 * Secret patterns for the transfer layer. Order matters (first hit wins).
 * The local-first invariant means NO network endpoints belong in evidence;
 * connection strings are treated like secrets and redacted by default.
 */
export const SEMANTIQ_SECRET_PATTERNS: readonly { readonly name: string; readonly re: RegExp }[] =
  Object.freeze([
    { name: "aws_access_key_id", re: /\bAKIA[0-9A-Z]{16}\b/ },
    { name: "aws_secret_key", re: /\b(?:aws)?_?secret_?access_?key\b\s*[:=]\s*\S+/i },
    { name: "github_token", re: /\bgh[pousr]_[A-Za-z0-9]{16,}\b/ },
    { name: "openai_style_key", re: /\bsk-[A-Za-z0-9_-]{16,}\b/ },
    { name: "slack_token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
    { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/ },
    { name: "bearer_token", re: /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/i },
    { name: "basic_auth", re: /\bBasic\s+[A-Za-z0-9+/=]{16,}\b/i },
    { name: "private_key_block", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
    { name: "password_assignment", re: /\b(?:password|passwd|pwd)\b\s*[:=]\s*\S+/i },
    { name: "api_key_assignment", re: /\bapi_?key\b\s*[:=]\s*\S+/i },
    { name: "authorization_header", re: /\bauthorization\b\s*[:=]\s*\S+/i },
    { name: "connection_string", re: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?|ftp|sftp):\/\/[^\s"']+:[^\s"']+@[^\s"']+/i },
    { name: "generic_secret_assignment", re: /\b(?:secret|token|client_?secret|access_?token|refresh_?token|session_?token|private_?key)\b\s*[:=]\s*\S+/i },
  ]);

/**
 * Keys whose VALUES are treated as secrets wholesale (JSON objects split
 * key and value across fields, so assignment patterns cannot see them).
 * Word-boundary careful: "author" does not match, "authorization" does.
 */
const SECRET_KEY_RE = /(?:password|passwd|pwd|secret|token|api_?key|authorization|credential|private_?key|session_?id)/i;

export interface RedactionResult {
  readonly value: string;
  readonly redactions: number;
}

function redactString(value: string, maxChars: number): RedactionResult {
  let out = value;
  let count = 0;
  for (const p of SEMANTIQ_SECRET_PATTERNS) {
    // Non-overlapping global replace per pattern; each replacement counts.
    out = out.replace(new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g"), () => {
      count++;
      return "[REDACTED:" + p.name + "]";
    });
  }
  const truncated =
    out.length > maxChars
      ? out.slice(0, maxChars) + "…[TRUNCATED]"
      : out;
  return { value: truncated, redactions: count + (out.length > maxChars ? 1 : 0) };
}

/**
 * Deep-walk a JSON-like value and redact secrets in every string, bounding
 * every string to maxChars. Returns the sanitized value (new structure;
 * the input is never mutated) and the number of redactions performed.
 * Bounded: walk depth is capped and non-JSON values are replaced with
 * sentinels, so hostile payloads cannot force unbounded work.
 */
export function redactValue(
  value: unknown,
  maxChars: number = SEMANTIQ_MAX_STRING_CHARS,
  depth: number = 0
): { readonly value: unknown; readonly redactions: number } {
  if (depth > 6) return { value: "[DEPTH_LIMIT]", redactions: 0 };
  if (typeof value === "string") {
    const r = redactString(value, maxChars);
    return { value: r.value, redactions: r.redactions };
  }
  if (typeof value === "number" || typeof value === "boolean" || value === null) {
    return { value, redactions: 0 };
  }
  if (Array.isArray(value)) {
    let count = 0;
    const out: unknown[] = [];
    for (const item of value.slice(0, 128)) {
      const r = redactValue(item, maxChars, depth + 1);
      count += r.redactions;
      out.push(r.value);
    }
    if (value.length > 128) out.push("[ARRAY_TRUNCATED]");
    return { value: out, redactions: count };
  }
  if (typeof value === "object") {
    let count = 0;
    const src = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(src).sort().slice(0, 64)) {
      const keyRes = redactString(k, 64);
      count += keyRes.redactions;
      if (SECRET_KEY_RE.test(k)) {
        // Structured secret: the KEY names it, so the VALUE is redacted
        // wholesale regardless of its content.
        count++;
        out[keyRes.value] = "[REDACTED:key_" + keyRes.value + "]";
        continue;
      }
      const valRes = redactValue(src[k], maxChars, depth + 1);
      count += valRes.redactions;
      out[keyRes.value] = valRes.value;
    }
    return { value: out, redactions: count };
  }
  return { value: "[UNSERIALIZABLE]", redactions: 0 };
}

// ---------------------------------------------------------------------------
// Bounded export.
// ---------------------------------------------------------------------------

export type SemantiqTransferDenyReason =
  | "invalid_input"
  | "oversized_export"
  | "invalid_package"
  | "schema_mismatch"
  | "tampered_record"
  | "unknown_evaluator"
  | "oversized_package"
  | "duplicate_record"
  | "store_full";

export const KNOWN_SEMANTIQ_TRANSFER_DENY_REASONS: readonly SemantiqTransferDenyReason[] =
  Object.freeze([
    "invalid_input",
    "oversized_export",
    "invalid_package",
    "schema_mismatch",
    "tampered_record",
    "unknown_evaluator",
    "oversized_package",
    "duplicate_record",
    "store_full",
  ]);

export function isSemantiqTransferDenyReason(value: unknown): value is SemantiqTransferDenyReason {
  return (
    typeof value === "string" &&
    (KNOWN_SEMANTIQ_TRANSFER_DENY_REASONS as readonly string[]).includes(value)
  );
}

/** Bounded summary of one ledger event carried inside an evidence package. */
export interface SemantiqEvidenceEventSummary {
  readonly eventId: string;
  readonly eventType: string;
  readonly actorType: string;
  readonly actorId: string;
  readonly timestamp: string;
  readonly policyDecision?: string;
  readonly verb?: string;
}

export interface SemantiqEvidencePackageMetadata {
  readonly schemaVersion: typeof SEMANTIQ_SCHEMA_VERSION;
  readonly packageKind: "menog-evidence";
  readonly exportedAtEpochMs: number;
  readonly exporterId: string;
  readonly exporterVersion: string;
  readonly recordCount: number;
  readonly eventCount: number;
  readonly redactionCount: number;
  readonly truncated: boolean;
}

export interface SemantiqEvidencePackage {
  readonly metadata: SemantiqEvidencePackageMetadata;
  readonly records: readonly SemantiqEvaluationRecord[];
  readonly events: readonly SemantiqEvidenceEventSummary[];
  /** SHA-256 over the canonical serialization of metadata+records+events. */
  readonly packageHash: string;
}

export interface EvidenceExportInput {
  readonly records: readonly SemantiqEvaluationRecord[];
  readonly events?: readonly SemantiqEvidenceEventSummary[];
  readonly exporterId: string;
  readonly exporterVersion: string;
  readonly exportedAtEpochMs: number;
}

export type EvidenceExportResult =
  | { readonly ok: true; readonly package: SemantiqEvidencePackage; readonly redactions: number }
  | { readonly ok: false; readonly denyReason: SemantiqTransferDenyReason; readonly reason: string };

function hashEvidencePayload(
  metadata: SemantiqEvidencePackageMetadata,
  records: readonly SemantiqEvaluationRecord[],
  events: readonly SemantiqEvidenceEventSummary[]
): string {
  return createHash("sha256")
    .update(
      stableStringify({ kind: "menog-evidence-v1", metadata, records, events }),
      "utf8"
    )
    .digest("hex");
}

/**
 * Build a bounded, secret-free evidence package. Deterministic: identical
 * inputs (records, events, exporter identity, exportedAt) produce identical
 * packages (stableStringify ordering + redaction). Oversized content is
 * truncated and counted; the export itself never denies for size unless the
 * record/event COUNT exceeds the caps.
 */
export function exportEvidence(input: EvidenceExportInput): EvidenceExportResult {
  if (input === null || typeof input !== "object") {
    return { ok: false, denyReason: "invalid_input", reason: "export input must be an object" };
  }
  if (typeof input.exporterId !== "string" || input.exporterId.length === 0 || input.exporterId.length > SEMANTIQ_MAX_ID_CHARS) {
    return { ok: false, denyReason: "invalid_input", reason: "exporterId must be a bounded non-empty string" };
  }
  if (typeof input.exporterVersion !== "string" || input.exporterVersion.length === 0 || input.exporterVersion.length > SEMANTIQ_MAX_ID_CHARS) {
    return { ok: false, denyReason: "invalid_input", reason: "exporterVersion must be a bounded non-empty string" };
  }
  if (typeof input.exportedAtEpochMs !== "number" || !Number.isFinite(input.exportedAtEpochMs)) {
    return { ok: false, denyReason: "invalid_input", reason: "exportedAtEpochMs must be a finite number" };
  }
  if (!Array.isArray(input.records)) {
    return { ok: false, denyReason: "invalid_input", reason: "records must be an array" };
  }
  if (input.records.length > SEMANTIQ_MAX_EXPORT_RECORDS) {
    return {
      ok: false,
      denyReason: "oversized_export",
      reason:
        "records exceed the export bound (" +
        String(SEMANTIQ_MAX_EXPORT_RECORDS) +
        ")",
    };
  }
  const rawEvents = input.events ?? [];
  if (!Array.isArray(rawEvents)) {
    return { ok: false, denyReason: "invalid_input", reason: "events must be an array" };
  }
  if (rawEvents.length > SEMANTIQ_MAX_EXPORT_EVENTS) {
    return {
      ok: false,
      denyReason: "oversized_export",
      reason:
        "events exceed the export bound (" +
        String(SEMANTIQ_MAX_EXPORT_EVENTS) +
        ")",
    };
  }

  // Redact every record through deep JSON round-trip (defense in depth over
  // the 18B builders' own validation; import re-validates regardless).
  let redactions = 0;
  let truncated = false;
  const records: SemantiqEvaluationRecord[] = [];
  for (const rec of input.records) {
    if (rec === null || typeof rec !== "object") {
      return { ok: false, denyReason: "invalid_input", reason: "records must be record objects" };
    }
    const res = redactValue(rec, SEMANTIQ_MAX_STRING_CHARS);
    redactions += res.redactions;
    const round = res.value as unknown as SemantiqEvaluationRecord;
    if (JSON.stringify(res.value).length > JSON.stringify(rec).length) truncated = true;
    records.push(Object.freeze(round));
  }

  const events: SemantiqEvidenceEventSummary[] = [];
  for (const ev of rawEvents) {
    if (ev === null || typeof ev !== "object") {
      return { ok: false, denyReason: "invalid_input", reason: "events must be event-summary objects" };
    }
    const res = redactValue(ev, SEMANTIQ_MAX_STRING_CHARS);
    redactions += res.redactions;
    events.push(Object.freeze(res.value as unknown as SemantiqEvidenceEventSummary));
  }

  const metadata: SemantiqEvidencePackageMetadata = Object.freeze({
    schemaVersion: SEMANTIQ_SCHEMA_VERSION,
    packageKind: "menog-evidence",
    exportedAtEpochMs: input.exportedAtEpochMs,
    exporterId: input.exporterId,
    exporterVersion: input.exporterVersion,
    recordCount: records.length,
    eventCount: events.length,
    redactionCount: redactions,
    truncated,
  });

  const pkg: SemantiqEvidencePackage = Object.freeze({
    metadata,
    records: Object.freeze(records),
    events: Object.freeze(events),
    packageHash: hashEvidencePayload(metadata, records, events),
  });

  const size = Buffer.byteLength(JSON.stringify(pkg), "utf8");
  if (size > SEMANTIQ_MAX_TOTAL_BYTES) {
    return {
      ok: false,
      denyReason: "oversized_export",
      reason:
        "serialized package is " +
        String(size) +
        " bytes which exceeds SEMANTIQ_MAX_TOTAL_BYTES (" +
        String(SEMANTIQ_MAX_TOTAL_BYTES) +
        ")",
    };
  }
  return { ok: true, package: pkg, redactions };
}

// ---------------------------------------------------------------------------
// Validated import.
// ---------------------------------------------------------------------------

export interface EvidenceImportOptions {
  /**
   * Allow-list of evaluator identities. WHEN a record's provenance provides
   * engineId/engineVersion, the pair must be listed here or the import
   * denies `unknown_evaluator`. Absent allow-list ⇒ engine-sourced records
   * cannot be imported at all (deny-by-default on machine opinions).
   */
  readonly allowedEvaluators?: readonly { readonly engineId: string; readonly engineVersion: string }[];
}

export type EvidenceImportResult =
  | { readonly ok: true; readonly records: readonly SemantiqEvaluationRecord[]; readonly imported: number }
  | { readonly ok: false; readonly denyReason: SemantiqTransferDenyReason; readonly reason: string };

function boundedString(v: unknown, max: number): v is string {
  return typeof v === "string" && v.length > 0 && v.length <= max;
}

/** Validate one bounded event summary; returns an error string or null. */
function validateEventSummary(ev: unknown): string | null {
  if (ev === null || typeof ev !== "object") return "event summary must be an object";
  const r = ev as Record<string, unknown>;
  if (!boundedString(r.eventId, SEMANTIQ_MAX_EVENT_ID_CHARS)) return "eventId must be a bounded non-empty string";
  if (!boundedString(r.eventType, 64)) return "eventType must be a bounded non-empty string";
  if (!boundedString(r.actorType, SEMANTIQ_MAX_ID_CHARS)) return "actorType must be a bounded non-empty string";
  if (!boundedString(r.actorId, SEMANTIQ_MAX_ID_CHARS)) return "actorId must be a bounded non-empty string";
  if (typeof r.timestamp !== "string" || r.timestamp.length === 0 || r.timestamp.length > 64) {
    return "timestamp must be a bounded non-empty string";
  }
  if (r.policyDecision !== undefined && (typeof r.policyDecision !== "string" || r.policyDecision.length > 32)) {
    return "policyDecision, when present, must be a bounded string";
  }
  if (r.verb !== undefined && (typeof r.verb !== "string" || r.verb.length > 64)) {
    return "verb, when present, must be a bounded string";
  }
  return null;
}

/**
 * Import (validate + materialize) an untrusted evidence package.
 * Deny-by-default at every layer; imported records are returned in a NEW
 * array — the caller decides where they go (no hidden writes anywhere).
 */
export function importEvidence(
  pkg: unknown,
  options: EvidenceImportOptions = {}
): EvidenceImportResult {
  if (pkg === null || typeof pkg !== "object") {
    return { ok: false, denyReason: "invalid_package", reason: "package must be an object" };
  }
  const p = pkg as Record<string, unknown>;
  const meta = p.metadata as Record<string, unknown> | undefined;
  if (meta === undefined || meta === null || typeof meta !== "object") {
    return { ok: false, denyReason: "invalid_package", reason: "package metadata missing" };
  }
  if (meta.schemaVersion !== SEMANTIQ_SCHEMA_VERSION) {
    return { ok: false, denyReason: "schema_mismatch", reason: "package schemaVersion must be " + SEMANTIQ_SCHEMA_VERSION };
  }
  if (meta.packageKind !== "menog-evidence") {
    return { ok: false, denyReason: "invalid_package", reason: "packageKind must be menog-evidence" };
  }
  if (typeof meta.exporterId !== "string" || meta.exporterId.length === 0 || meta.exporterId.length > SEMANTIQ_MAX_ID_CHARS) {
    return { ok: false, denyReason: "invalid_package", reason: "metadata.exporterId must be a bounded non-empty string" };
  }
  if (typeof meta.exportedAtEpochMs !== "number" || !Number.isFinite(meta.exportedAtEpochMs)) {
    return { ok: false, denyReason: "invalid_package", reason: "metadata.exportedAtEpochMs must be a finite number" };
  }
  if (!Array.isArray(p.records) || !Array.isArray(p.events)) {
    return { ok: false, denyReason: "invalid_package", reason: "package records/events must be arrays" };
  }
  if (p.records.length > SEMANTIQ_MAX_EXPORT_RECORDS || p.events.length > SEMANTIQ_MAX_EXPORT_EVENTS) {
    return { ok: false, denyReason: "oversized_package", reason: "package exceeds record/event caps" };
  }
  if (p.records.length !== meta.recordCount || p.events.length !== meta.eventCount) {
    return { ok: false, denyReason: "invalid_package", reason: "metadata counts do not match payload" };
  }
  for (const ev of p.events) {
    const err = validateEventSummary(ev);
    if (err !== null) return { ok: false, denyReason: "invalid_package", reason: err };
  }

  // Evaluator allow-list (identity check applies only when provided).
  const allowed = (options.allowedEvaluators ?? []).map((e) => e.engineId + "@" + e.engineVersion);

  const imported: SemantiqEvaluationRecord[] = [];
  for (const rec of p.records) {
    if (rec === null || typeof rec !== "object") {
      return { ok: false, denyReason: "invalid_package", reason: "records must be record objects" };
    }
    const r = rec as Record<string, unknown>;
    // 1) Full 18B schema gate on the event (authority pins included).
    const eventErr = validateEvaluationEvent(r.event);
    if (eventErr !== null) {
      return { ok: false, denyReason: "invalid_package", reason: "record event invalid: " + eventErr };
    }
    const event = r.event as SemantiqEvaluationRecord["event"];
    // 2) Evaluator identity check (when the provenance provides one).
    const prov = event.provenance;
    if (prov.engineId !== undefined || prov.engineVersion !== undefined) {
      if (prov.engineId === undefined || prov.engineVersion === undefined) {
        return { ok: false, denyReason: "invalid_package", reason: "engine identity requires both engineId and engineVersion" };
      }
      if (!allowed.includes(prov.engineId + "@" + prov.engineVersion)) {
        return {
          ok: false,
          denyReason: "unknown_evaluator",
          reason:
            "evaluator '" +
            prov.engineId +
            "@" +
            prov.engineVersion +
            "' is not on the import allow-list; machine-sourced evaluations are opt-in",
        };
      }
    }
    // 3) Hash integrity: stored contentHash must equal recomputed hash.
    const contentHash = r.contentHash;
    if (typeof contentHash !== "string" || contentHash.length !== 64) {
      return { ok: false, denyReason: "tampered_record", reason: "record contentHash missing or malformed" };
    }
    // Recompute with the CANONICAL 18B hash (serializeEvaluationEvent key
    // order) — not a local re-implementation — so export and import can
    // never drift apart on what "identical content" means.
    const recomputed = evaluationEventHash(event);
    if (contentHash !== recomputed) {
      return {
        ok: false,
        denyReason: "tampered_record",
        reason: "record content does not match its contentHash (tampered package); import refused",
      };
    }
    // 4) Id integrity: recordId must be the deterministic record id.
    const recordId = r.recordId;
    if (typeof recordId !== "string" || recordId.length !== 64) {
      return { ok: false, denyReason: "tampered_record", reason: "recordId missing or malformed" };
    }
    if (recordId !== evaluationRecordId(event, contentHash)) {
      return { ok: false, denyReason: "tampered_record", reason: "recordId does not match event content; import refused" };
    }
    imported.push(
      Object.freeze({
        recordId,
        eventId: typeof r.eventId === "string" && r.eventId.length > 0 ? r.eventId.slice(0, SEMANTIQ_MAX_ID_CHARS) : recordId,
        createdAtEpochMs:
          typeof r.createdAtEpochMs === "number" && Number.isFinite(r.createdAtEpochMs)
            ? r.createdAtEpochMs
            : 0,
        event,
        contentHash,
      })
    );
  }

  // 5) Package hash integrity over the FULL received payload.
  const recomputedPackageHash = hashEvidencePayload(
    p.metadata as unknown as SemantiqEvidencePackageMetadata,
    p.records as unknown as readonly SemantiqEvaluationRecord[],
    p.events as unknown as readonly SemantiqEvidenceEventSummary[]
  );
  if (p.packageHash !== recomputedPackageHash) {
    return {
      ok: false,
      denyReason: "tampered_record",
      reason: "packageHash does not match package content (tampered package); import refused",
    };
  }

  return { ok: true, records: Object.freeze(imported), imported: imported.length };
}
