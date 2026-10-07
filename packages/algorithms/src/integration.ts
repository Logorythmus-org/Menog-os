import type {
  AlgorithmDecisionInput,
  MemoryProjectionResult,
  MemoryRetrievalPort,
  RiskVerdict,
} from "./types.js";
import {
  ALGORITHM_MAX_CANDIDATES,
  ALGORITHM_MAX_CANDIDATE_LABEL_CHARS,
  RetrievalPortError,
} from "./types.js";

/**
 * Phase 17C — integration contracts between the algorithm kernel and the
 * three capability-adjacent subsystems:
 *
 *  1. MEMORY (context_memory_retrieval) — a strategy consumes a
 *     `MemoryRetrievalPort`. The port is STRUCTURAL so the existing,
 *     policy-gated `MemoryRetrievalService` from `@menog/memory` satisfies
 *     it via an adapter WITHOUT modification: integration, never bypass.
 *     Memory reads stay policy-gated, scope-isolated, and ledger-observable
 *     inside the memory package. NO EXTERNAL CONTENT AS SYSTEM INSTRUCTION:
 *     projected snippets are inert candidate labels.
 *
 *  2. RISK (runtime_risk_evaluation) — `applyRiskVerdict` turns a strategy's
 *     verdict into a RESTRICTED capability/label view. Monotone restriction
 *     invariant: the result can only LOWER what the caller claims policy
 *     granted (policy is the floor) and can never raise it. Risk may
 *     restrict/deny execution only ADVISORY-ly; the deny-by-default policy
 *     engine remains the sole authority on what MAY run.
 *
 *  3. SKILL (skill_selection) — `filterSkillsByCapabilities` intersects
 *     recommended capability labels with the caller-asserted granted set.
 *     NO TOOL WITHOUT CAPABILITY: anything not granted is withheld from the
 *     recommendation (and flagged as withheld for observability).
 */

/** Maximum snippets projected from one retrieval response (bounded work). */
export const ALGORITHM_MAX_MEMORY_HITS = 32;
/** Maximum snippet length projected into a candidate label. */
export const ALGORITHM_MAX_SNIPPET_CHARS = 96;

/** Map a memory `MemoryRetrievalService` onto the algorithm retrieval port. */
export function memoryRetrievalPortAdapter(
  svc: {
    retrieve(
      ctx: {
        readonly actor: { readonly type: string; readonly id: string };
        readonly grantedScope: {
          readonly workspaceId: string;
          readonly taskId?: string;
          readonly sessionId?: string;
        };
      },
      query: { readonly text?: string; readonly limit?: number; readonly minScore?: number },
      strategyId?: string
    ): unknown;
  },
  options: { readonly strategyId?: string } = {}
): MemoryRetrievalPort {
  return {
    async retrieve(ctx, query) {
      const raw: unknown = svc.retrieve(ctx, query, options.strategyId);
      const r = raw as {
        ok: boolean;
        hits?: readonly { score: number; record: { body: unknown; provenance: { origin: string; untrusted: boolean } } }[];
        denyReason?: string;
        reason?: string;
      };
      if (typeof r !== "object" || r === null || typeof r.ok !== "boolean") {
        return { ok: false, denyReason: "retrieval_unavailable", reason: "retrieval port returned a malformed response" };
      }
      if (!r.ok) {
        return {
          ok: false,
          denyReason: typeof r.denyReason === "string" ? r.denyReason : "retrieval_unavailable",
          reason: typeof r.reason === "string" ? r.reason : "memory retrieval denied",
        };
      }
      const hits = Array.isArray(r.hits) ? r.hits : [];
      const out: Array<{ score: number; snippet: string; origin: string; untrusted: boolean }> = [];
      for (const h of hits) {
        if (typeof h !== "object" || h === null) continue;
        const body = (h.record as { body?: unknown } | undefined)?.body;
        out.push({
          score: typeof h.score === "number" && Number.isFinite(h.score) ? h.score : 0,
          snippet: bodySnippet(body),
          origin: String((h.record as { provenance?: { origin?: unknown } } | undefined)?.provenance?.origin ?? "external"),
          untrusted: Boolean((h.record as { provenance?: { untrusted?: unknown } } | undefined)?.provenance?.untrusted),
        });
      }
      return { ok: true, hits: out };
    },
  };
}

/** Extract a bounded one-line snippet from an arbitrary record body. */
function bodySnippet(body: unknown): string {
  let text = "";
  const visit = (v: unknown, depth: number): void => {
    if (text.length >= ALGORITHM_MAX_SNIPPET_CHARS || depth > 4) return;
    if (typeof v === "string") {
      text += (text.length > 0 ? " " : "") + v;
    } else if (Array.isArray(v)) {
      for (const item of v) visit(item, depth + 1);
    } else if (v !== null && typeof v === "object") {
      for (const k of Object.keys(v as Record<string, unknown>).sort()) {
        if (text.length >= ALGORITHM_MAX_SNIPPET_CHARS) return;
        text += (text.length > 0 ? " " : "") + k;
        visit((v as Record<string, unknown>)[k], depth + 1);
      }
    }
  };
  visit(body, 0);
  const oneLine = text.replace(/\s+/g, " ").trim();
  return oneLine.length > ALGORITHM_MAX_SNIPPET_CHARS
    ? oneLine.slice(0, ALGORITHM_MAX_SNIPPET_CHARS)
    : oneLine;
}

/**
 * Project a port response into bounded, provenance-safe candidate labels.
 * Untrusted hits get the `untrusted:` prefix so downstream consumers can
 * never mistake external content for runtime-authored truth. Fails closed
 * with `RetrievalPortError` when the port denies (the strategy converts
 * this to the machine-readable `retrieval_unavailable` denial).
 */
export function projectHitsToLabels(
  response:
    | { readonly ok: true; readonly hits: readonly { readonly score: number; readonly snippet: string; readonly origin: string; readonly untrusted: boolean }[] }
    | { readonly ok: false; readonly denyReason: string; readonly reason: string }
): MemoryProjectionResult {
  if (!response.ok) {
    throw new RetrievalPortError(
      "memory retrieval denied (" + response.denyReason + "): " + response.reason
    );
  }
  const labels: string[] = [];
  let untrustedCount = 0;
  const hits = response.hits.slice(0, ALGORITHM_MAX_MEMORY_HITS);
  for (const h of hits) {
    if (typeof h.snippet !== "string" || h.snippet.length === 0) continue;
    let label = h.snippet;
    if (label.length > ALGORITHM_MAX_CANDIDATE_LABEL_CHARS) {
      label = label.slice(0, ALGORITHM_MAX_CANDIDATE_LABEL_CHARS);
    }
    if (h.untrusted) {
      untrustedCount++;
      label = "untrusted: " + label;
    }
    labels.push(label);
  }
  return {
    labels,
    sourceCount: hits.length,
    untrustedCount,
  };
}

/**
 * Monotone risk restriction. Given the capability labels the caller claims
 * policy granted and a risk verdict, returns the labels that survive.
 *
 * Invariants (all test-pinned):
 *  - POLICY FLOOR: the result is always a SUBSET of the granted set; risk
 *    can only withhold, never add;
 *  - deny:     withholds everything (result empty);
 *  - restrict: withholds `verdict.withholdCapabilities` ∩ granted;
 *  - allow:    returns granted unchanged;
 *  - granted === undefined: returns `undefined` (nothing claimed, nothing
 *    restricted — restriction applies only to what exists).
 */
export function applyRiskVerdict(
  granted: readonly string[] | undefined,
  verdict: RiskVerdict
): readonly string[] | undefined {
  if (granted === undefined) return undefined;
  if (verdict.tier === "deny") return Object.freeze([]);
  if (verdict.tier === "allow") return Object.freeze([...granted]);
  // restrict: withhold only capabilities actually claimed as granted.
  const withhold = new Set(verdict.withholdCapabilities ?? []);
  const out = granted.filter((c) => !withhold.has(c));
  return Object.freeze(out);
}

/** Outcome record of a skill/capability intersection (observability). */
export interface SkillFilterResult {
  /** Capability labels that survive the granted-capability intersection. */
  readonly recommended: readonly string[];
  /** Capability labels withheld because the caller did not claim them. */
  readonly withheld: readonly string[];
}

/**
 * Capability-aware skill selection filter. NO TOOL WITHOUT CAPABILITY:
 * recommended capability labels are intersected with the caller-asserted
 * granted set; everything else is withheld (and reported). With an absent
 * granted set, no filtering occurs (caller chose not to constrain).
 */
export function filterSkillsByCapabilities(
  recommendedCapabilities: readonly string[],
  granted: readonly string[] | undefined
): SkillFilterResult {
  if (granted === undefined) {
    return {
      recommended: Object.freeze([...recommendedCapabilities]),
      withheld: Object.freeze([]),
    };
  }
  const grantedSet = new Set(granted);
  const rec: string[] = [];
  const withheld: string[] = [];
  for (const c of recommendedCapabilities) {
    (grantedSet.has(c) ? rec : withheld).push(c);
  }
  return {
    recommended: Object.freeze(rec),
    withheld: Object.freeze(withheld),
  };
}

/**
 * Bounded-validation helper for the caller-asserted granted-capabilities
 * input (17C). Returns an error string or null.
 */
export function validateGrantedCapabilities(
  input: AlgorithmDecisionInput
): string | null {
  const caps = input.grantedCapabilities;
  if (caps === undefined) return null;
  if (!Array.isArray(caps)) return "grantedCapabilities must be an array when present";
  if (caps.length > ALGORITHM_MAX_CANDIDATES) {
    return (
      "grantedCapabilities has " +
      String(caps.length) +
      " entries which exceeds ALGORITHM_MAX_CANDIDATES (" +
      String(ALGORITHM_MAX_CANDIDATES) +
      ")"
    );
  }
  for (let i = 0; i < caps.length; i++) {
    const c = caps[i];
    if (typeof c !== "string" || c.length === 0) {
      return "grantedCapabilities[" + String(i) + "] must be a non-empty string";
    }
    if (c.length > ALGORITHM_MAX_CANDIDATE_LABEL_CHARS) {
      return (
        "grantedCapabilities[" +
        String(i) +
        "] exceeds ALGORITHM_MAX_CANDIDATE_LABEL_CHARS (" +
        String(ALGORITHM_MAX_CANDIDATE_LABEL_CHARS) +
        ")"
      );
    }
  }
  return null;
}
