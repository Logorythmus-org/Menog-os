import { createHash } from "node:crypto";
import type { MenogEvent } from "@menog/core";

export const MAX_LINE_BYTES = 256 * 1024;
export const DEFAULT_REDACTION_MARKER = "[REDACTED]";
// NOTE (16B): this list is mirrored textually in
// packages/memory/src/secrets.ts (MEMORY_SECRET_KEY_HINTS) so memory bodies
// and ledger summaries share ONE definition of "looks like a secret".
// Keep the two lists identical when updating either.
export const SECRET_KEY_HINTS: readonly RegExp[] = Object.freeze([
  /(^|[-_ ])(pass(word|phrase)?)([-_ ]|$)/i,
  /(^|[-_ ])secret([-_ ]|$)/i,
  /(^|[-_ ])((api[-_]?)?key|apikey)([-_ ]|$)/i,
  /(^|[-_ ])(token)([-_ ]|$)/i,
  /(^|[-_ ])(credential|credentials|cred)([-_ ]|$)/i,
  /(^|[-_ ])(private[-_ ]?key|privkey)([-_ ]|$)/i,
  /(^|[-_ ])(auth|authentication)([-_ ]|$)/i,
  /(^|[-_ ])(cookie)([-_ ]|$)/i,
  /(^|[-_ ])(session)([-_ ]|$)/i,
  /(^|[-_ ])(bearer)([-_ ]|$)/i,
  /(^|[-_ ])(signing[-_ ]?secret)([-_ ]|$)/i,
  /(^|[-_ ])(access[-_ ]?token)([-_ ]|$)/i,
  /(^|[-_ ])(refresh[-_ ]?token)([-_ ]|$)/i,
  /(^|[-_ ])((aws|gcp|azure)[-_ ]?(secret|key))([-_ ]|$)/i,
  /(^|[-_ ])(signing|signature|sign)[-_ ]?key([-_ ]|$)/i,
  /(^|[-_ ])(jwt|jwks)([-_ ]|$)/i,
  /(^|[-_ ])(secret[-_ ]?key|key[-_ ]?secret)([-_ ]|$)/i,
]);

export const SAFE_SUMMARY_KEYS: readonly RegExp[] = Object.freeze([
  /(^|[-_ ])(event|task|workspace|actor|policy|rule|verb|capability|ledger|hash|parent|request|result|summary|decision|requested|allowed|denied|matched|authoritative|side|effect|schema|version|registry|type|timestamp)[-_ ]?(id|ids|rule|rules|class|classes|count|set|capabilities|outcome|approval|marker|engine|time|level|process|mode|token|hint|code|status|key|keys)?([-_ ]|$)/i,
  /^(id|ids|status|code|reason|outcome|count|size|name|path|paths|count|index|ruleId|ruleIds|authoritativeRuleId|matchedRule|riskClass|requiresHumanApproval|allowedCapabilities|deniedCapabilities|policyDecision|eventType|verb|capability|commandHint|requestId|taskId|workspaceId|eventId|parentEventId|previousHash|hash|actorType|actorId|requestedCapabilities|inputSummary|resultSummary|sideEffectClass|schemaVersion|order|sort|null|true|false|undefined|type|timestamp|process|line|bytes)$/i,
]);

const EVENT_KEY_ORDER: readonly (keyof MenogEvent)[] = Object.freeze([
  "eventId",
  "timestamp",
  "eventType",
  "actor",
  "workspaceId",
  "taskId",
  "verb",
  "capability",
  "policyDecision",
  "inputSummary",
  "resultSummary",
  "parentEventId",
  "previousHash",
  "hash",
]);

const ACTOR_KEY_ORDER: readonly ["type", "id"] = Object.freeze(["type", "id"]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function normalizeKeyHint(keyHint: string): string {
  if (typeof keyHint !== "string") return "";
  let out = keyHint.replace(/([a-z0-9])([A-Z])/g, "$1_$2");
  out = out.replace(/[-\s.]+/g, "_");
  return out.toLowerCase();
}

function redactString(value: string, keyHint: string): string {
  if (typeof keyHint !== "string" || keyHint.length === 0) return value;
  const safe =
    SAFE_SUMMARY_KEYS.some((re) => re.test(keyHint.toLowerCase())) ||
    SAFE_SUMMARY_KEYS.some((re) => re.test(normalizeKeyHint(keyHint)));
  if (safe) return value;
  const hit =
    SECRET_KEY_HINTS.some((re) => re.test(keyHint.toLowerCase())) ||
    SECRET_KEY_HINTS.some((re) => re.test(normalizeKeyHint(keyHint)));
  if (hit) return DEFAULT_REDACTION_MARKER;
  return value;
}

function sanitizeUnknown(value: unknown, keyHint: string): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return redactString(value, keyHint);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "symbol" || typeof value === "function") return undefined;
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (let i = 0; i < value.length; i++) {
      out.push(sanitizeUnknown(value[i], keyHint + "[" + String(i) + "]"));
    }
    return out;
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    const out: Record<string, unknown> = {};
    for (const k of keys) {
      const v = (value as Record<string, unknown>)[k];
      out[k] = sanitizeUnknown(v, k);
    }
    return out;
  }
  return String(value);
}

function serializeActor(actor: MenogEvent["actor"]): string {
  const parts: string[] = [];
  for (const k of ACTOR_KEY_ORDER) {
    parts.push(JSON.stringify(k) + ":" + JSON.stringify(actor[k]));
  }
  return "{" + parts.join(",") + "}";
}

function serializeSummary(
  summary: Readonly<Record<string, unknown>> | undefined,
  fieldName: "inputSummary" | "resultSummary"
): string {
  if (summary === undefined) return "undefined";
  const sanitized = sanitizeUnknown(summary, fieldName) as Record<string, unknown>;
  const keys = Object.keys(sanitized).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const v = sanitized[k];
    parts.push(JSON.stringify(k) + ":" + JSON.stringify(v));
  }
  return "{" + parts.join(",") + "}";
}

function serializeOptional(value: string | undefined): string {
  return value === undefined ? "undefined" : JSON.stringify(value);
}

export function serializeEventForHash(event: Omit<MenogEvent, "hash">): string {
  const parts: string[] = [];
  for (const k of EVENT_KEY_ORDER) {
    if (k === "hash") continue;
    let v: string;
    switch (k) {
      case "actor":
        v = serializeActor(event.actor);
        break;
      case "inputSummary":
        v = serializeSummary(event.inputSummary, "inputSummary");
        break;
      case "resultSummary":
        v = serializeSummary(event.resultSummary, "resultSummary");
        break;
      case "workspaceId":
      case "taskId":
      case "verb":
      case "capability":
      case "policyDecision":
      case "parentEventId":
        v = serializeOptional(event[k]);
        break;
      default: {
        const value = event[k];
        v = typeof value === "string" ? JSON.stringify(value) : JSON.stringify(value);
      }
    }
    parts.push(JSON.stringify(k) + ":" + v);
  }
  return "{" + parts.join(",") + "}";
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

export const GENESIS_PREVIOUS_HASH =
  "0000000000000000000000000000000000000000000000000000000000000000";

export function computeEventHash(
  eventWithoutHash: Omit<MenogEvent, "hash">
): string {
  return sha256Hex(serializeEventForHash(eventWithoutHash));
}

export function redactSummary(
  summary: Readonly<Record<string, unknown>> | undefined
): Readonly<Record<string, unknown>> | undefined {
  if (summary === undefined) return undefined;
  return Object.freeze(sanitizeUnknown(summary, "summary") as Record<string, unknown>);
}
