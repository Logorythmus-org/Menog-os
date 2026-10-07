import { createHash } from "node:crypto";
import { SEMANTIQ_SCHEMA_VERSION } from "./types.js";
import type {
  SemantiqEvaluationRequest,
  SemantiqRuntimeContext,
} from "./types.js";
import { validateEvaluationRequest } from "./rules.js";

/**
 * Phase 18D — Evaluation Boundary Security.
 *
 * Threat-tests and hardens the SemantIQ evaluation boundary against the
 * three named attack classes (18D objectives):
 *
 *  1. EVALUATOR INJECTION / INSTRUCTION SMUGGLING — evaluator payloads that
 *     try to speak AS the runtime (system-instruction style text, policy
 *     overrides, tool/capability/commit demands) are CLASSIFIED, REFUSED,
 *     and RECORDED in an insert-once rejection log; they never reach an
 *     engine as instructions and never surface as runtime truth.
 *  2. SCORE MANIPULATION — non-finite, off-grid, out-of-range, duplicated
 *     or authority-carrying score payloads are refused before any verdict
 *     derivation can be poisoned.
 *  3. AUTHORITY CONFUSION — any evaluator payload (request, claims, events)
 *     claiming execution/policy authority is refused and recorded; the
 *     policy engine remains the sole MAY-IT authority (18A/18B pins).
 *
 * Everything here is LOCAL, DETERMINISTIC, I/O-free, and observable: every
 * refusal is a machine-readable record the caller may persist or emit via
 * the provided deny-by-default emitter surface. Rejected instructions are
 * recorded — never executed, never forwarded, never forgotten silently.
 */

// ---------------------------------------------------------------------------
// Hostile-pattern taxonomy (18D).
// ---------------------------------------------------------------------------

export type SemantiqHostilePattern =
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

export const KNOWN_SEMANTIQ_HOSTILE_PATTERNS: readonly SemantiqHostilePattern[] =
  Object.freeze([
    "system_instruction_override",
    "role_redirection",
    "policy_override_directive",
    "tool_authorization_demand",
    "capability_grant_demand",
    "write_demand",
    "commit_demand",
    "authority_claim",
    "execution_claim",
    "instruction_boundary_probe",
  ]);

/**
 * Text patterns for the named attack classes. These scan evaluator-supplied
 * free text (request subject/note, claim values, engine summaries). They are
 * deliberately CONSERVATIVE (exact-phrase-ish) to avoid false positives on
 * honest evaluations that merely DISCUSS security topics with different
 * phrasing; authority claims carried as FIELDS are caught structurally
 * regardless of text.
 */
export const SEMANTIQ_HOSTILE_TEXT_PATTERNS: readonly {
  readonly pattern: SemantiqHostilePattern;
  readonly re: RegExp;
}[] = Object.freeze([
  { pattern: "system_instruction_override", re: /\b(?:system\s*prompt|system\s*instruction|system\s*message)\b\s*(?:override|update|replace|ignore|:)/i },
  { pattern: "role_redirection", re: /\b(?:you\s+are\s+now|act\s+as\s+(?:an?\s+)?(?:admin|root|policy|authority)|ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions)\b/i },
  { pattern: "policy_override_directive", re: /\bpolicy\s*(?:override|bypass|suspend|disable)\b/i },
  { pattern: "tool_authorization_demand", re: /\b(?:authorize|grant|allow|enable)\s+(?:the\s+)?(?:tool|shell|network|filesystem)\b/i },
  { pattern: "capability_grant_demand", re: /\bgrant\s+(?:capability|capabilities|workspace:(?:write|network|system))\b/i },
  { pattern: "write_demand", re: /\b(?:write|modify|delete|overwrite)\s+(?:the\s+)?(?:policy|policies|ledger|registry)\b/i },
  { pattern: "commit_demand", re: /\b(?:git\s+)?(?:commit|push|force-push)\s+(?:this|the|now|immediately)\b/i },
  { pattern: "authority_claim", re: /\b(?:by\s+)?(?:order|directive|authority)\s+of\s+the\s+(?:operator|administrator|system)\b/i },
  { pattern: "execution_claim", re: /\b(?:execution|run|command)\s+(?:is\s+)?(?:now\s+)?authorized\b/i },
  { pattern: "instruction_boundary_probe", re: /\b(?:end\s+of|begin)\s+(?:system|instruction)s?\b/i },
]);

/** Structured authority fields an evaluator payload must never carry. */
const AUTHORITY_FIELD_NAMES: readonly string[] = Object.freeze([
  "executionAuthorized",
  "policyDecision",
  "grants",
  "capabilities",
  "authority",
  "grantedCapabilities",
]);

export type SemantiqBoundaryDenyReason =
  | "authority_confusion"
  | "instruction_smuggling"
  | "score_manipulation"
  | "schema_abuse"
  | "invalid_input";

export const KNOWN_SEMANTIQ_BOUNDARY_DENY_REASONS: readonly SemantiqBoundaryDenyReason[] =
  Object.freeze([
    "authority_confusion",
    "instruction_smuggling",
    "score_manipulation",
    "schema_abuse",
    "invalid_input",
  ]);

export function isSemantiqBoundaryDenyReason(value: unknown): value is SemantiqBoundaryDenyReason {
  return (
    typeof value === "string" &&
    (KNOWN_SEMANTIQ_BOUNDARY_DENY_REASONS as readonly string[]).includes(value)
  );
}

export interface SemantiqFinding {
  readonly pattern: SemantiqHostilePattern;
  /** Where the payload was found (bounded path string). */
  readonly location: string;
  /** Bounded excerpt AROUND the match — never the full hostile text. */
  readonly excerpt: string;
}

function excerptAround(text: string, index: number): string {
  const start = Math.max(0, index - 24);
  const end = Math.min(text.length, index + 40);
  const prefix = start > 0 ? "…" : "";
  const suffix = end < text.length ? "…" : "";
  // The excerpt carries the MATCHED REGION only (bounded forensic context),
  // with newlines collapsed so log/event surfaces stay single-line.
  return (prefix + text.slice(start, end) + suffix).replace(/\s+/g, " ");
}

/** Scan one string for hostile instruction patterns. */
export function scanHostileText(
  text: string,
  location: string
): readonly SemantiqFinding[] {
  const findings: SemantiqFinding[] = [];
  if (typeof text !== "string" || text.length === 0) return findings;
  for (const p of SEMANTIQ_HOSTILE_TEXT_PATTERNS) {
    const m = p.re.exec(text);
    if (m !== null) {
      findings.push(
        Object.freeze({
          pattern: p.pattern,
          location,
          excerpt: excerptAround(text, m.index),
        })
      );
    }
  }
  return Object.freeze(findings);
}

/**
 * Structurally inspect an unknown payload for authority fields or smuggled
 * instruction text anywhere in a bounded JSON-like tree (depth/width
 * capped; hostile structures cannot force unbounded work).
 */
export function inspectPayload(
  value: unknown,
  location: string = "payload",
  depth: number = 0
): readonly SemantiqFinding[] {
  if (depth > 6) return Object.freeze([]);
  if (typeof value === "string") {
    return scanHostileText(value, location);
  }
  if (Array.isArray(value)) {
    const out: SemantiqFinding[] = [];
    for (let i = 0; i < Math.min(value.length, 64); i++) {
      out.push(...inspectPayload(value[i], location + "[" + String(i) + "]", depth + 1));
    }
    return Object.freeze(out);
  }
  if (value !== null && typeof value === "object") {
    const out: SemantiqFinding[] = [];
    const rec = value as Record<string, unknown>;
    for (const k of Object.keys(rec).slice(0, 64)) {
      if (AUTHORITY_FIELD_NAMES.includes(k)) {
        out.push(
          Object.freeze({
            pattern: "authority_claim",
            location: location + "." + k,
            excerpt: "[authority field present: " + k + "]",
          })
        );
      }
      out.push(...inspectPayload(rec[k], location + "." + k, depth + 1));
    }
    return Object.freeze(out);
  }
  return Object.freeze([]);
}

// ---------------------------------------------------------------------------
// Score-manipulation defense (18B grid re-check at the boundary).
// ---------------------------------------------------------------------------

export interface SemantiqScoreCheckInput {
  readonly dimension: unknown;
  readonly score: unknown;
  readonly confidence: unknown;
}

/** Inspect one claimed score for manipulation; returns a finding or null. */
export function inspectScore(s: SemantiqScoreCheckInput, location: string): SemantiqFinding | null {
  const reasons: string[] = [];
  if (typeof s.score !== "number" || !Number.isFinite(s.score)) {
    reasons.push("non-finite score");
  } else if (s.score < 0 || s.score > 1) {
    reasons.push("score out of range");
  } else {
    const snapped = Math.round(s.score * 10) / 10;
    if (Math.abs(s.score - snapped) > 1e-9) reasons.push("off-grid score");
  }
  if (typeof s.confidence !== "number" || !Number.isFinite(s.confidence) || s.confidence < 0 || s.confidence > 1) {
    reasons.push("invalid confidence");
  }
  if (
    s.dimension !== "plan_quality" &&
    s.dimension !== "task_completion" &&
    s.dimension !== "policy_compliance" &&
    s.dimension !== "reproducibility"
  ) {
    reasons.push("unknown dimension");
  }
  if (reasons.length === 0) return null;
  return Object.freeze({
    pattern: "authority_claim", // structural manipulation, not text smuggling
    location,
    excerpt: reasons.join("; "),
  });
}

// ---------------------------------------------------------------------------
// Rejection record (observable, insert-once, hash-anchored).
// ---------------------------------------------------------------------------

export type SemantiqRejectedBy = "adapter" | "contract_layer" | "import_gate" | "policy_engine";

export interface SemantiqRejectedInstruction {
  readonly schemaVersion: typeof SEMANTIQ_SCHEMA_VERSION;
  readonly rejectedAtEpochMs: number;
  readonly rejectedBy: SemantiqRejectedBy;
  readonly denyReason: SemantiqBoundaryDenyReason;
  readonly patterns: readonly SemantiqHostilePattern[];
  readonly subject: string;
  readonly trigger: string;
  readonly findings: readonly SemantiqFinding[];
  /** Bounded, redacted-free digest of what was refused (never full payload). */
  readonly payloadDigest: string;
  /** ALWAYS advisory_data — even rejections are records, not authority. */
  readonly authority: "advisory_data";
  /** ALWAYS false. */
  readonly executionAuthorized: false;
}

export interface RejectedInstructionInput {
  readonly rejectedAtEpochMs: number;
  readonly rejectedBy: SemantiqRejectedBy;
  readonly denyReason: SemantiqBoundaryDenyReason;
  readonly patterns: readonly SemantiqHostilePattern[];
  readonly request?: SemantiqEvaluationRequest;
  readonly findings: readonly SemantiqFinding[];
  readonly payload?: unknown;
  readonly context?: SemantiqRuntimeContext;
}

/** Build a frozen rejection record (authority-pinned like every 18A event). */
export function buildRejectedInstruction(
  input: RejectedInstructionInput
): { readonly ok: true; readonly record: SemantiqRejectedInstruction } | { readonly ok: false; readonly reason: string } {
  if (!isSemantiqBoundaryDenyReason(input.denyReason)) {
    return { ok: false, reason: "denyReason must be a known boundary deny reason" };
  }
  if (typeof input.rejectedAtEpochMs !== "number" || !Number.isFinite(input.rejectedAtEpochMs)) {
    return { ok: false, reason: "rejectedAtEpochMs must be a finite number" };
  }
  const patterns = (input.patterns ?? []).filter(
    (p): p is SemantiqHostilePattern =>
      (KNOWN_SEMANTIQ_HOSTILE_PATTERNS as readonly string[]).includes(p)
  );
  const subject = input.request?.subject ?? "(no request)";
  const payloadDigest = createHash("sha256")
    .update(
      typeof input.payload === "string"
        ? input.payload
        : safeJson(input.payload),
      "utf8"
    )
    .digest("hex");
  const record: SemantiqRejectedInstruction = Object.freeze({
    schemaVersion: SEMANTIQ_SCHEMA_VERSION,
    rejectedAtEpochMs: input.rejectedAtEpochMs,
    rejectedBy: input.rejectedBy,
    denyReason: input.denyReason,
    patterns: Object.freeze(patterns),
    subject: subject.slice(0, 256),
    trigger: typeof input.request?.trigger === "string" ? input.request.trigger : "unknown",
    findings: Object.freeze(
      input.findings.slice(0, 16).map((f) =>
        Object.freeze({
          pattern: f.pattern,
          location: f.location.slice(0, 128),
          excerpt: f.excerpt.slice(0, 96),
        })
      )
    ),
    payloadDigest,
    authority: "advisory_data",
    executionAuthorized: false,
  });
  return { ok: true, record };
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "undefined";
  } catch {
    return "<unserializable>";
  }
}

/**
 * Bounded, INSERT-ONCE log of rejected evaluator instructions. Same
 * discipline as the 18B record store: duplicates deny, overflow fails
 * closed, reads revalidate. Rejected instructions are RECORDS — they must
 * be retrievable for audit ("record rejected evaluator instructions") but
 * can never be replayed as instructions.
 */
export class SemantiqRejectionLog {
  readonly #records: Map<string, SemantiqRejectedInstruction> = new Map();
  readonly #order: string[] = [];

  /** Insert-once persistence keyed by a stable rejection id. */
  record(input: RejectedInstructionInput):
    | { readonly ok: true; readonly record: SemantiqRejectedInstruction; readonly rejectionId: string }
    | { readonly ok: false; readonly denyReason: "invalid_input" | "duplicate_rejection" | "log_full"; readonly reason: string } {
    const built = buildRejectedInstruction(input);
    if (!built.ok) {
      return { ok: false, denyReason: "invalid_input", reason: built.reason };
    }
    const rejectionId = createHash("sha256")
      .update(built.record.payloadDigest + "|" + built.record.denyReason + "|" + String(built.record.rejectedAtEpochMs), "utf8")
      .digest("hex");
    if (this.#records.has(rejectionId)) {
      return { ok: false, denyReason: "duplicate_rejection", reason: "identical rejection already logged (insert-once)" };
    }
    if (this.#records.size >= SEMANTIQ_MAX_REJECTIONS) {
      return { ok: false, denyReason: "log_full", reason: "rejection log is full (" + String(SEMANTIQ_MAX_REJECTIONS) + "); failing closed" };
    }
    this.#records.set(rejectionId, built.record);
    this.#order.push(rejectionId);
    return { ok: true, record: built.record, rejectionId };
  }

  /** All rejections oldest-first (frozen). */
  read(): readonly SemantiqRejectedInstruction[] {
    const out: SemantiqRejectedInstruction[] = [];
    for (const id of this.#order) {
      const rec = this.#records.get(id);
      if (rec !== undefined) out.push(rec);
    }
    return Object.freeze(out);
  }

  get length(): number {
    return this.#records.size;
  }
}

/** Rejection-log cap (bounded surface, fails closed). */
export const SEMANTIQ_MAX_REJECTIONS = 512;

// ---------------------------------------------------------------------------
// One-shot request screening (used by the adapter; deterministic).
// ---------------------------------------------------------------------------

export interface ScreenResult {
  readonly ok: boolean;
  readonly denyReason?: SemantiqBoundaryDenyReason;
  readonly reason?: string;
  readonly findings: readonly SemantiqFinding[];
}

/**
 * Screen an evaluation request BEFORE the engine sees it: hostile text in
 * subject/note and authority fields anywhere in the request are refused.
 * Deterministic: same input ⇒ same findings.
 */
export function screenEvaluationRequest(request: SemantiqEvaluationRequest): ScreenResult {
  const base = validateEvaluationRequest(request);
  if (base !== null) {
    return { ok: false, denyReason: "invalid_input", reason: base, findings: [] };
  }
  const findings: SemantiqFinding[] = [];
  findings.push(...scanHostileText(request.subject, "request.subject"));
  if (request.note !== undefined) findings.push(...scanHostileText(request.note, "request.note"));
  findings.push(...inspectPayload(request, "request", 0).filter((f) => f.pattern === "authority_claim" && f.location.startsWith("request.")));
  if (findings.length > 0) {
    const smuggling = findings.some((f) => f.pattern !== "authority_claim");
    return {
      ok: false,
      denyReason: smuggling ? "instruction_smuggling" : "authority_confusion",
      reason:
        "evaluation request refused at the boundary: " +
        findings.map((f) => f.pattern + "@" + f.location).join(", "),
      findings,
    };
  }
  return { ok: true, findings: [] };
}

// ---------------------------------------------------------------------------
// Deny-by-default rejection emitter (ledger evidence, caller-owned store).
// ---------------------------------------------------------------------------

/**
 * Wrap a caller append function so ONLY `evaluation_rejected` (and the
 * pre-existing 18A/18B observability types) may pass. Rejected-instruction
 * evidence can thus reach the ledger WITHOUT widening the write surface.
 */
export function rejectionLedgerEmitter(
  append: (input: {
    readonly eventType: string;
    readonly policyDecision: "allow" | "deny" | "not_applicable";
    readonly actor: { readonly type: string; readonly id: string };
    readonly workspaceId?: string;
    readonly taskId?: string;
    readonly inputSummary: Readonly<Record<string, unknown>>;
    readonly resultSummary: Readonly<Record<string, unknown>>;
  }) => { readonly ok: boolean; readonly eventId?: string }
): { readonly appendRejection: (input: {
  readonly record: SemantiqRejectedInstruction;
  readonly actor: { readonly type: string; readonly id: string };
  readonly workspaceId?: string;
  readonly taskId?: string;
}) => { readonly ok: boolean; readonly eventId?: string } } {
  return Object.freeze({
    appendRejection: (input) => {
      if (input.record.schemaVersion !== SEMANTIQ_SCHEMA_VERSION) {
        return { ok: false };
      }
      if (input.record.authority !== "advisory_data" || input.record.executionAuthorized !== false) {
        return { ok: false };
      }
      return append({
        eventType: "evaluation_rejected",
        policyDecision: "deny",
        actor: input.actor,
        workspaceId: input.workspaceId,
        taskId: input.taskId,
        inputSummary: {
          subject: input.record.subject,
          trigger: input.record.trigger,
          rejectedBy: input.record.rejectedBy,
        },
        resultSummary: {
          outcome: "rejected",
          denyReason: input.record.denyReason,
          patterns: [...input.record.patterns],
          findingCount: input.record.findings.length,
          payloadDigest: input.record.payloadDigest,
          authority: "advisory_data",
          executionAuthorized: false,
        },
      });
    },
  });
}


