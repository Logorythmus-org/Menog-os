import { createHash } from "node:crypto";
import type {
  AgentMessageDenyReason,
  AgentSendRequest,
  AgentMessageKind,
  RoutingRule,
} from "./types.js";
import {
  AGENT_ROUTING_RULES,
  AGENTS_MAX_PAYLOAD_CHARS,
  AGENTS_MAX_SUMMARY_FIELDS,
  AGENTS_MAX_SUMMARY_VALUE_CHARS,
  KNOWN_AGENT_MESSAGE_KINDS,
} from "./types.js";

/**
 * Phase 19A — runtime-mediated message validation.
 *
 * Messages are coordination DATA between agent identities, mediated by the
 * runtime. Validation is fail-closed and layered:
 *   layer 1 — shape/bounds (malformed_message / oversized_message)
 *   layer 2 — routing rules (message_kind_not_allowed)
 *   layer 3 — authority confusion (a message may never carry authority
 *             claims or demand execution/policy changes)
 *   layer 4 — instruction smuggling (hostile directive patterns in text)
 *
 * Denial reasons never echo hostile payload text back (digest-only
 * rejection records); the same discipline as the 18D boundary.
 */

/** Closed union of hostile text patterns (authority demands in payload text). */
export type AgentHostilePattern =
  | "system_instruction_override"
  | "role_redirection"
  | "policy_override_directive"
  | "tool_authorization_demand"
  | "capability_grant_demand"
  | "write_demand"
  | "commit_demand"
  | "authority_claim"
  | "execution_claim"
  | "instruction_boundary_probe";

export const KNOWN_AGENT_HOSTILE_PATTERNS: readonly AgentHostilePattern[] =
  Object.freeze([
    "system_instruction_override",
    "role_redirection",
    "policy_override_directive",
    "tool_authorization_demand",
    "capability_grant_demand",
    "authority_claim",
    "execution_claim",
    "write_demand",
    "commit_demand",
    "instruction_boundary_probe",
  ]);

export const AGENT_HOSTILE_TEXT_PATTERNS: readonly {
  readonly pattern: AgentHostilePattern;
  readonly re: RegExp;
}[] = Object.freeze([
  { pattern: "system_instruction_override", re: /ignore\s+(all\s+)?(previous|prior)\s+instructions/i },
  { pattern: "role_redirection", re: /you\s+are\s+now\s+a\b|act\s+as\s+(an?|the)\b/i },
  { pattern: "policy_override_directive", re: /policy\s+(says|allows|permits)|override\s+the\s+policy/i },
  { pattern: "tool_authorization_demand", re: /use\s+the\s+\w+\s+tool/i },
  { pattern: "capability_grant_demand", re: /grant\s+(me\s+)?(the\s+)?(workspace:write|git:commit|network:external)/i },
  { pattern: "authority_claim", re: /i\s+am\s+(the\s+)?(human|policy|authority)/i },
  { pattern: "execution_claim", re: /execution\s+authorized|you\s+may\s+execute/i },
  { pattern: "write_demand", re: /write\s+to\s+disk|modify\s+the\s+files?\s+now/i },
  { pattern: "commit_demand", re: /commit\s+(the\s+)?(changes|now)|git\s+commit/i },
  { pattern: "instruction_boundary_probe", re: /what\s+are\s+your\s+(instructions|rules|policy)/i },
]);

/**
 * Scan free text for hostile directive patterns. Deterministic: returns the
 * FIRST matching pattern in the canonical order above.
 */
export function scanAgentText(text: string): AgentHostilePattern | null {
  if (typeof text !== "string") return null;
  for (const entry of AGENT_HOSTILE_TEXT_PATTERNS) {
    if (typeof entry === "string") continue;
    if (entry.re.test(text)) return entry.pattern;
  }
  return null;
}

/** Scan a summary value for hostile directives. */
export function scanSummaryValue(value: string): AgentHostilePattern | null {
  return scanAgentText(value);
}

/** One screening finding (pattern + bounded location hint). */
export interface AgentScreeningFinding {
  readonly pattern: AgentHostilePattern;
  readonly location: "payload" | "summary";
  readonly key: string | null;
}

/** Full screening of a send attempt (payload + summary values). */
export function screenAgentSendRequest(
  request: AgentSendRequest
): { ok: true } | { ok: false; finding: AgentScreeningFinding } {
  const payloadHit = scanAgentText(request.payloadText);
  if (payloadHit) {
    return { ok: false, finding: { pattern: payloadHit, location: "payload", key: null } };
  }
  if (request.summary !== undefined) {
    for (const [key, value] of Object.entries(request.summary)) {
      if (typeof value === "string" && scanSummaryValue(value)) {
        return {
          ok: false,
          finding: {
            pattern: scanSummaryValue(value)!,
            location: "summary",
            key,
          },
        };
      }
    }
  }
  return { ok: true };
}

/** Validate the message kind against the closed union. */
export function isKnownMessageKind(value: unknown): value is AgentMessageKind {
  return (
    typeof value === "string" &&
    (KNOWN_AGENT_MESSAGE_KINDS as readonly string[]).includes(value)
  );
}

/**
 * Routing rule lookup: does role(from) → role(to) allow `kind`? The rule
 * map is closed: planner → builder → reviewer → planner is the authority
 * chain for substantive messages; log kinds may also flow across.
 */
export function routingAllows(
  fromRole: RoutingRule["fromRole"],
  toRole: RoutingRule["toRole"],
  kind: AgentMessageKind
): boolean {
  for (const rule of AGENT_ROUTING_RULES) {
    if (rule.fromRole === fromRole && rule.toRole === toRole && rule.kinds.includes(kind)) {
      return true;
    }
  }
  return false;
}

/** Machine-readable validation of a send request's shape and bounds. */
export function validateSendRequestShape(
  request: AgentSendRequest
): { ok: true } | { ok: false; denyReason: AgentMessageDenyReason; reason: string } {
  if (!request || typeof request !== "object") {
    return { ok: false, denyReason: "malformed_message", reason: "request must be an object" };
  }
  if (!isKnownMessageKind(request.kind)) {
    return { ok: false, denyReason: "malformed_message", reason: "kind must be a known AgentMessageKind" };
  }
  if (typeof request.fromAgentId !== "string" || request.fromAgentId.length === 0) {
    return { ok: false, denyReason: "malformed_message", reason: "fromAgentId must be a non-empty string" };
  }
  if (typeof request.toAgentId !== "string" || request.toAgentId.length === 0) {
    return { ok: false, denyReason: "malformed_message", reason: "toAgentId must be a peers id or the runtime log" };
  }
  if (typeof request.payloadText !== "string") {
    return { ok: false, denyReason: "malformed_message", reason: "payloadText must be a string" };
  }
  if (request.payloadText.length > AGENTS_MAX_PAYLOAD_CHARS) {
    return {
      ok: false,
      denyReason: "oversized_message",
      reason:
        "payloadText length " +
        String(request.payloadText.length) +
        " exceeds cap " +
        String(AGENTS_MAX_PAYLOAD_CHARS),
    };
  }
  if (request.summary !== undefined) {
    if (typeof request.summary !== "object" || Array.isArray(request.summary)) {
      return { ok: false, denyReason: "malformed_message", reason: "summary must be an object" };
    }
    const entries = Object.entries(request.summary);
    if (entries.length > AGENTS_MAX_SUMMARY_FIELDS) {
      return {
        ok: false,
        denyReason: "oversized_message",
        reason:
          "summary has " +
          String(entries.length) +
          " fields; cap is " +
          String(AGENTS_MAX_SUMMARY_FIELDS),
      };
    }
    for (const [k, v] of entries) {
      if (typeof k !== "string" || k.length === 0 || k.length > 64) {
        return { ok: false, denyReason: "malformed_message", reason: "summary keys must be non-empty strings ≤64 chars" };
      }
      if (
        typeof v !== "string" &&
        typeof v !== "number" &&
        typeof v !== "boolean"
      ) {
        return { ok: false, denyReason: "malformed_message", reason: "summary values must be string|number|boolean" };
      }
      if (typeof v === "string" && v.length > AGENTS_MAX_SUMMARY_VALUE_CHARS) {
        return {
          ok: false,
          denyReason: "oversized_message",
          reason:
            "summary value at '" +
            k +
            "' length " +
            String(v.length) +
            " exceeds cap " +
            String(AGENTS_MAX_SUMMARY_VALUE_CHARS),
        };
      }
    }
  }
  return { ok: true };
}

/** SHA-256 digest of payload text (rejection records carry digests, not text). */
export function agentPayloadDigest(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}
