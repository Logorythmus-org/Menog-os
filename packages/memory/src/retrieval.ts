import type { Actor } from "@menog/core";
import type { AppendOnlyLedger } from "@menog/event-ledger";
import type {
  MemoryDenial,
  MemoryRecord,
  MemoryScope,
} from "./types.js";
import { type MemoryAccessContext, type BaseMemoryStore } from "./memory.js";
import { ExecutionMemoryStore } from "./execution-memory.js";
import { memoryRecordHash } from "./serialize.js";
import { secretKeyMatches } from "./secrets.js";

/**
 * Phase 16C — Context-Aware Retrieval.
 *
 * Read-side discipline over the policy-gated 16A/16B stores. Retrieval is
 * NOT a new authority: every candidate passes through the same policy gate,
 * scope isolation and ledger observability as the underlying store reads —
 * "retrieved" is not a bypass for "read".
 *
 *  - NO EXTERNAL CONTENT AS SYSTEM INSTRUCTION: retrieved records are
 *    advisory data; provenance (origin + untrusted flag) travels with every
 *    record so no consumer can mistake external content for runtime truth.
 *  - NO SECRETS IN QUERIES: query text is length-capped and pattern-scanned
 *    (shared MEMORY_SECRET_KEY_HINTS); a query carrying secret-like keys is
 *    refused with query_not_allowed — queries never become an exfiltration
 *    channel.
 *  - Deterministic: equal stores + equal queries ⇒ equal ranked output
 *    (stable sort; lexical ties fall back to insertion order = record id).
 *  - Evidence-first: every hit carries evidence = ledger anchor (16B
 *    execution evidenceRef when present) + record content hash + record id.
 */

/** Maximum accepted query-text length in characters. */
export const RETRIEVAL_MAX_QUERY_CHARS = 4096;
/** Maximum number of results one retrieval may return. */
export const RETRIEVAL_MAX_LIMIT = 100;
/** Default result cap. */
export const RETRIEVAL_DEFAULT_LIMIT = 10;
/** lexical scoring weights (deterministic, documented). */
export const RETRIEVAL_LEXICAL_WEIGHT = 0.6;
export const RETRIEVAL_RECENCY_WEIGHT = 0.4;
/** Half-life for recency scoring (default 24h). */
export const RETRIEVAL_RECENCY_HALF_LIFE_MS = 24 * 60 * 60 * 1000;

/** Source kind of a retrieval candidate. */
export type RetrievalSourceKind = "memory" | "execution";

/** Strategy identifier ("lexical" | "recency" | "hybrid" implemented in 16C). */
export type RetrievalStrategyId = string;

/** Common strategy input. */
export interface RetrievalQuery {
  /** Free-text lexical query (empty string = pure recency ordering). */
  readonly text?: string;
  /** Result cap (clamped to [0, RETRIEVAL_MAX_LIMIT], default 10). */
  readonly limit?: number;
  /** Minimum relevance score in [0,1] (default 0). */
  readonly minScore?: number;
}

/** Strategy-specific context handed to retrieve(). */
export interface RetrievalContext {
  /** Monotonic clock for recency computations. */
  readonly nowMs: number;
  /** Half-life for exponential recency decay. */
  readonly recencyHalfLifeMs: number;
  /** Deterministic ranking: equal scores keep insertion order (stable sort). */
  readonly deterministic: boolean;
}

/** A candidate record surfaced for ranking (16A memory record). */
export interface RetrievalCandidate {
  readonly record: MemoryRecord;
  readonly sourceKind: RetrievalSourceKind;
}

/**
 * Strategy interface — the extension point for future vector / graph
 * retrieval (Phase 17+). A strategy is a PURE function from candidates +
 * query to ranked output: no I/O, no store access, no authority.
 */
export interface RetrievalStrategy {
  /** Stable strategy id (e.g. "lexical", "recency", "hybrid"). */
  readonly id: RetrievalStrategyId;
  /** Human-readable description of the ranking function. */
  readonly description: string;
  /** Rank candidates; MUST be deterministic for deterministic inputs. */
  readonly rank: (
    candidates: readonly RetrievalCandidate[],
    query: RetrievalQuery,
    ctx: RetrievalContext
  ) => RetrievalResult;
}

/** Evidence attached to every retrieved record (16C core requirement). */
export interface RetrievalEvidence {
  /** 16B ledger evidenceRef when the record carries execution metadata. */
  readonly evidenceRef: string | null;
  /** Canonical SHA-256 content hash of the stored record. */
  readonly recordHash: string;
  /** Record id (ledger events reference memoryId in inputSummary). */
  readonly recordId: string;
}

/** One ranked retrieval hit. */
export interface RetrievalHit {
  readonly record: MemoryRecord;
  /** Source store kind ("memory" | "execution"). */
  readonly sourceKind: RetrievalSourceKind;
  /** Overall relevance in [0,1]. */
  readonly score: number;
  /** Component scores — inspection, tuning, and strategy comparability. */
  readonly components: {
    /** Lexical term-overlap score in [0,1] (0 when no text query). */
    readonly lexical: number;
    /** Recency score in (0,1]: 2^(-age/halfLife); 1 = recorded now. */
    readonly recency: number;
  };
  /** Evidence pointers for the hit. */
  readonly evidence: RetrievalEvidence;
}

/** Successful retrieval result (frozen snapshot). */
export interface RetrievalSuccess {
  readonly ok: true;
  readonly strategy: RetrievalStrategyId;
  readonly hits: readonly RetrievalHit[];
  /** Number of candidates the strategy ranked before limit/minScore cut. */
  readonly candidatesConsidered: number;
  /** Ledger event id of the underlying observable read, when available. */
  readonly policyEventId?: string;
}

/** Machine-readable retrieval failure. */
export type RetrievalDenyReason =
  | MemoryDenial["denyReason"]
  | "query_not_allowed"
  | "query_too_long"
  | "strategy_not_found";

export interface RetrievalFailure {
  readonly ok: false;
  readonly denyReason: RetrievalDenyReason;
  readonly reason: string;
}

export type RetrievalResult = RetrievalSuccess | RetrievalFailure;

export function isRetrievalFailure(r: RetrievalResult): r is RetrievalFailure {
  return r.ok === false;
}

// ---------------------------------------------------------------------------
// Lexical model: token → subtoken index over ALL string values of a body.
// Deterministic term-frequency scoring; no hidden state.
// ---------------------------------------------------------------------------

/** Extract deterministic tokens from a string (alphanumeric runs, lowercased). */
export function retrievalTokens(text: string): string[] {
  if (typeof text !== "string") return [];
  return text.toLowerCase().match(/[a-z0-9]+/g) ?? [];
}

function bodyText(record: MemoryRecord): string {
  const parts: string[] = [];
  const visit = (v: unknown): void => {
    if (typeof v === "string") {
      parts.push(v);
    } else if (Array.isArray(v)) {
      for (const item of v) visit(item);
    } else if (v !== null && typeof v === "object") {
      for (const k of Object.keys(v as Record<string, unknown>).sort()) {
        parts.push(k);
        visit((v as Record<string, unknown>)[k]);
      }
    }
  };
  visit(record.body);
  return parts.join(" ");
}

/** Exact string appears somewhere in the body (field-name OR value match). */
function bodyContains(record: MemoryRecord, needle: string): boolean {
  return bodyText(record).includes(needle);
}

/**
 * Deterministic lexical relevance in [0,1] between query and record:
 *  - exact-substring multiplier for full-query and token matches;
 *  - subtoken (camelCase / separator-insensitive) partial matches;
 *  - term-frequency dampened, coverage-normalized.
 */
export function lexicalScore(queryText: string, record: MemoryRecord): number {
  const q = queryText.toLowerCase().trim();
  if (q.length === 0) return 0;
  const qTokens = retrievalTokens(q);
  if (qTokens.length === 0) return 0;

  const hay = bodyText(record);
  const hayTokens = retrievalTokens(hay);
  if (hayTokens.length === 0) return 0;

  const hayTokenSet = new Set(hayTokens);
  const hayJoined = hayTokens.join(" ");

  let score = 0;

  // 1. Full exact substring of the whole query.
  if (hayJoined.includes(q) || bodyContains(record, q)) score += 0.5;

  // 2. Token coverage: fraction of query tokens present as whole tokens.
  let matched = 0;
  for (const t of qTokens) {
    if (hayTokenSet.has(t)) matched++;
  }
  const coverage = matched / qTokens.length;
  score += 0.3 * coverage;

  // 3. Subtoken partial match (e.g. "auth" ⊂ "authtoken" via camel/sep splits).
  let partial = 0;
  for (const t of qTokens) {
    if (hayTokenSet.has(t)) {
      partial += 1;
      continue;
    }
    let best = 0;
    for (const h of hayTokenSet) {
      if (h.includes(t) && t.length >= 3) {
        const ratio = t.length / h.length;
        if (ratio > best) best = ratio;
      }
    }
    partial += best * 0.5;
  }
  score += 0.2 * (partial / qTokens.length);

  // 4. Term-frequency dampening (first occurrence dominates).
  const firstToken = qTokens[0]!;
  let tf = 0;
  for (const h of hayTokens) {
    if (h === firstToken) tf++;
  }
  score += Math.min(0.1, tf * 0.01);

  return Math.max(0, Math.min(1, score));
}

/** Exponential recency decay: 2^(-age/halfLife) ∈ (0,1]. */
export function recencyScore(recordedAtMs: number, nowMs: number, halfLifeMs: number): number {
  if (!(halfLifeMs > 0)) return 1;
  const age = Math.max(0, nowMs - recordedAtMs);
  return Math.pow(2, -age / halfLifeMs);
}

function clamp01(v: number): number {
  if (!Number.isFinite(v)) return 0;
  return Math.max(0, Math.min(1, v));
}

/** Weighted blend of lexical + recency (documented default 0.6 / 0.4). */
export function hybridScore(
  lexical: number,
  recency: number,
  lexicalWeight: number = RETRIEVAL_LEXICAL_WEIGHT
): number {
  const recencyWeight = 1 - lexicalWeight;
  return clamp01(lexical * lexicalWeight + recency * recencyWeight);
}

// ---------------------------------------------------------------------------
// Built-in strategies
// ---------------------------------------------------------------------------

function rankAndAssemble(
  candidates: readonly RetrievalCandidate[],
  query: RetrievalQuery,
  ctx: RetrievalContext,
  strategyId: RetrievalStrategyId,
  compute: (c: RetrievalCandidate, q: RetrievalQuery, cx: RetrievalContext) => { score: number; lexical: number; recency: number } | null
): RetrievalResult {
  const limit = Math.max(0, Math.min(RETRIEVAL_MAX_LIMIT, query.limit ?? RETRIEVAL_DEFAULT_LIMIT));
  const minScore = clamp01(query.minScore ?? 0);

  const scored: Array<{ hit: RetrievalHit; order: number }> = [];
  for (let i = 0; i < candidates.length; i++) {
    const c = candidates[i]!;
    const s = compute(c, query, ctx);
    if (s === null) continue;
    if (s.score < minScore) continue;
    scored.push({
      hit: {
        record: c.record,
        sourceKind: c.sourceKind,
        score: s.score,
        components: { lexical: s.lexical, recency: s.recency },
        evidence: Object.freeze({
          // 16D containment: evidenceRef comes ONLY from execution-sourced
          // candidates. A memory-body field named "evidenceRef" is untrusted
          // DATA and can never impersonate a ledger anchor in retrieval output.
          evidenceRef:
            c.sourceKind === "execution" ? readExecutionEvidenceRef(c.record) : null,
          recordHash: memoryRecordHash(c.record),
          recordId: c.record.memoryId,
        }),
      },
      order: i,
    });
  }

  // Deterministic ordering: score desc, then insertion order asc (stable).
  scored.sort((a, b) => {
    if (b.hit.score !== a.hit.score) return b.hit.score - a.hit.score;
    return ctx.deterministic ? a.order - b.order : 0;
  });

  const hits = scored.slice(0, limit).map((s) => Object.freeze(s.hit));
  return {
    ok: true,
    strategy: strategyId,
    hits: Object.freeze(hits),
    candidatesConsidered: candidates.length,
  };
}

/** 16B ledger evidenceRef when the record carries execution metadata, else null. */
function readExecutionEvidenceRef(record: MemoryRecord): string | null {
  const v = record.body["execution"];
  if (v !== null && typeof v === "object" && !Array.isArray(v)) {
    const ref = (v as Record<string, unknown>)["evidenceRef"];
    if (typeof ref === "string" && ref.length > 0) return ref;
  }
  return null;
}

/** lexical strategy — pure term relevance; ties fall back to insertion order. */
export const lexicalRetrievalStrategy: RetrievalStrategy = {
  id: "lexical",
  description:
    "term-overlap relevance over record bodies (exact > coverage > subtoken), score = lexical",
  rank: (candidates, query, ctx) =>
    rankAndAssemble(candidates, query, ctx, "lexical", (c) => {
      const text = query.text ?? "";
      const lexical = clamp01(lexicalScore(text, c.record));
      return { score: lexical, lexical, recency: 0 };
    }),
};

/** recency strategy — pure time decay; ties fall back to insertion order. */
export const recencyRetrievalStrategy: RetrievalStrategy = {
  id: "recency",
  description: "exponential recency decay 2^(-age/halfLife), score = recency",
  rank: (candidates, query, ctx) =>
    rankAndAssemble(candidates, query, ctx, "recency", (c) => {
      const recency = clamp01(
        recencyScore(c.record.createdAtEpochMs, ctx.nowMs, ctx.recencyHalfLifeMs)
      );
      return { score: recency, lexical: 0, recency };
    }),
};

/** hybrid strategy — weighted lexical + recency (default 0.6 / 0.4). */
export const hybridRetrievalStrategy: RetrievalStrategy = {
  id: "hybrid",
  description:
    "weighted blend: score = " +
    String(RETRIEVAL_LEXICAL_WEIGHT) +
    " * lexical + " +
    String(RETRIEVAL_RECENCY_WEIGHT) +
    " * recency",
  rank: (candidates, query, ctx) =>
    rankAndAssemble(candidates, query, ctx, "hybrid", (c) => {
      const lexical = clamp01(lexicalScore(query.text ?? "", c.record));
      const recency = clamp01(
        recencyScore(c.record.createdAtEpochMs, ctx.nowMs, ctx.recencyHalfLifeMs)
      );
      return { score: hybridScore(lexical, recency), lexical, recency };
    }),
};

const BUILTIN_STRATEGIES: readonly RetrievalStrategy[] = Object.freeze([
  lexicalRetrievalStrategy,
  recencyRetrievalStrategy,
  hybridRetrievalStrategy,
]);

/** Register-free strategy lookup (built-ins + any supplied overrides). */
export function defaultRetrievalStrategies(): readonly RetrievalStrategy[] {
  return BUILTIN_STRATEGIES;
}

// ---------------------------------------------------------------------------
// Service: the only retrieval entry point; policy-gated + scope-isolated.
// ---------------------------------------------------------------------------

export interface MemoryRetrievalServiceOptions {
  /** Any policy-gated memory store (Working, Project, or a 16A-compatible subclass). */
  readonly memory?: BaseMemoryStore | null;
  readonly execution?: ExecutionMemoryStore | null;
  readonly strategies?: readonly RetrievalStrategy[];
  /** Half-life for recency decay (default 24h). */
  readonly recencyHalfLifeMs?: number;
  /** Clock for recency scoring (injectable for deterministic tests). */
  readonly now?: () => number;
}

export class MemoryRetrievalService {
  readonly #memory: BaseMemoryStore | null;
  readonly #execution: ExecutionMemoryStore | null;
  readonly #strategies: ReadonlyMap<string, RetrievalStrategy>;
  readonly #halfLifeMs: number;
  readonly #now: () => number;

  public constructor(options: MemoryRetrievalServiceOptions = {}) {
    this.#memory = options.memory ?? null;
    this.#execution = options.execution ?? null;
    const map = new Map<string, RetrievalStrategy>();
    for (const s of defaultRetrievalStrategies()) map.set(s.id, s);
    for (const s of options.strategies ?? []) map.set(s.id, s);
    this.#strategies = map;
    this.#halfLifeMs = options.recencyHalfLifeMs ?? RETRIEVAL_RECENCY_HALF_LIFE_MS;
    this.#now = options.now ?? (() => Date.now());
  }

  /** Registered strategy ids (built-ins included). */
  public get strategyIds(): readonly string[] {
    return Array.from(this.#strategies.keys()).sort();
  }

  /**
   * Retrieve context from memory + execution stores within the caller's
   * granted scope. The query is validated BEFORE any read: queries carrying
   * secret-like content are refused without touching the stores (queries
   * must never become an exfiltration channel).
   *
   * Denies (fail-closed) when: no store is attached, no policy gate allows
   * the read, or the query is malformed/disallowed.
   */
  public retrieve(
    ctx: MemoryAccessContext,
    query: RetrievalQuery & {
      /** Optional metadata narrowing (ANDed with scope isolation). */
      readonly taskId?: string;
      readonly verb?: string;
      readonly actorId?: string;
      readonly outcome?: "success" | "failure" | "denied";
    } = {},
    strategyId: RetrievalStrategyId = "hybrid"
  ): RetrievalResult {
    const strategy = this.#strategies.get(strategyId);
    if (strategy === undefined) {
      return {
        ok: false,
        denyReason: "strategy_not_found",
        reason:
          "retrieval strategy '" + strategyId + "' is not registered; available: " +
          this.strategyIds.join(", "),
      };
    }

    const text = query.text ?? "";
    if (typeof text !== "string") {
      return {
        ok: false,
        denyReason: "query_not_allowed",
        reason: "query.text must be a string when present",
      };
    }
    if (text.length > RETRIEVAL_MAX_QUERY_CHARS) {
      return {
        ok: false,
        denyReason: "query_too_long",
        reason:
          "query.text is " + String(text.length) +
          " chars which exceeds RETRIEVAL_MAX_QUERY_CHARS (" +
          String(RETRIEVAL_MAX_QUERY_CHARS) + ")",
      };
    }
    if (secretKeyMatches(text)) {
      return {
        ok: false,
        denyReason: "query_not_allowed",
        reason:
          "query text matches a secret-key pattern; retrieval queries must not carry secret channels",
      };
    }

    if (this.#memory === null && this.#execution === null) {
      return {
        ok: false,
        denyReason: "read_not_allowed",
        reason: "no memory store attached to the retrieval service; retrieval is deny-by-default",
      };
    }

    const nowMs = this.#now();
    const candidates: RetrievalCandidate[] = [];
    let policyEventId: string | undefined;

    if (this.#memory !== null) {
      // 16D containment: metadata narrowing (taskId/verb/actorId/outcome) is
      // applied ONLY to the execution store, whose record schema owns those
      // field names. Field names inside plain memory bodies are untrusted
      // DATA and must never become filter channels.
      const read = this.#memory.read(ctx, {});
      if (!read.ok) {
        return { ok: false, denyReason: read.denyReason, reason: read.reason };
      }
      policyEventId = read.policyEventId ?? policyEventId;
      for (const rec of read.records) {
        candidates.push({ record: rec, sourceKind: "memory" });
      }
    }
    if (this.#execution !== null) {
      const read = this.#execution.query(ctx, {
        taskId: query.taskId,
        verb: query.verb,
        actorId: query.actorId,
        outcome: query.outcome,
      });
      if (!read.ok) {
        return { ok: false, denyReason: read.denyReason, reason: read.reason };
      }
      policyEventId = read.policyEventId ?? policyEventId;
      for (const rec of read.records) {
        candidates.push({ record: rec, sourceKind: "execution" });
      }
    }

    const ranked = strategy.rank(
      candidates,
      { text, limit: query.limit, minScore: query.minScore },
      {
        nowMs,
        recencyHalfLifeMs: this.#halfLifeMs,
        deterministic: true,
      }
    );
    if (!ranked.ok) return ranked;

    return {
      ok: true,
      strategy: ranked.strategy,
      hits: ranked.hits,
      candidatesConsidered: ranked.candidatesConsidered,
      policyEventId: ranked.policyEventId ?? policyEventId,
    };
  }
}

// Re-exports so consumers import the retrieval surface from one module.
export {
  BaseMemoryStore,
  WorkingMemoryStore,
  ProjectMemoryStore,
} from "./memory.js";
export { ExecutionMemoryStore } from "./execution-memory.js";
export type { MemoryAccessContext, MemoryStoreOptions } from "./memory.js";
export type { ExecutionMemoryStoreOptions } from "./execution-memory.js";
export type { Actor, AppendOnlyLedger, MemoryDenial, MemoryRecord, MemoryScope };
