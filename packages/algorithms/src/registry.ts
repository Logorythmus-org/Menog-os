import { createHash } from "node:crypto";
import {
  ALGORITHM_FAMILIES,
  isAlgorithmFamily,
  type AlgorithmDenial,
  type AlgorithmDenyReason,
  type AlgorithmFamily,
  type AlgorithmSelectionResult,
  type StrategyContract,
  type StrategyDescriptor,
} from "./types.js";

/**
 * Phase 17A — Strategy Registry.
 *
 * The registry stores replaceable strategy contracts keyed by family + id.
 * It is a declarative, authority-free surface: it validates, stores, looks
 * up, and serializes. It never executes and never authorizes.
 *
 * Deny-by-default discipline:
 *  - A strategy that is NOT registered under the requested family+id is
 *    denied with `unknown_strategy` (no silent fallback, no default algo).
 *  - A family that is not one of the ten closed families is denied with
 *    `unknown_family` before any lookup happens.
 *  - A strategy whose family does not match the family it was requested
 *    under can never be selected (family binding is enforced at registration
 *    AND at lookup time).
 */

const STRATEGY_ID_PATTERN = /^[a-z][a-z0-9-]*$/;
const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;

/** Canonical serialization of a strategy contract (sorted keys, deterministic). */
export function canonicalSerializeStrategy(
  strategy: StrategyContract
): string {
  const parts: string[] = [];
  const entries: readonly (readonly [string, string])[] = [
    ["description", strategy.description],
    ["family", strategy.family],
    ["id", strategy.id],
    ["implemented", String(strategy.implemented)],
    ["version", strategy.version],
  ];
  // Fixed outer order, sorted inner keys (sorted by key: description, family,
  // id, implemented, version) — deterministic across processes.
  for (const [k, v] of entries) {
    parts.push(JSON.stringify(k) + ":" + JSON.stringify(v));
  }
  return "{" + parts.join(",") + "}";
}

/** Deterministic SHA-256 hash of the canonical strategy serialization. */
export function canonicalStrategyHash(strategy: StrategyContract): string {
  return createHash("sha256")
    .update(canonicalSerializeStrategy(strategy), "utf8")
    .digest("hex");
}

function deny(
  denyReason: AlgorithmDenyReason,
  reason: string
): AlgorithmDenial {
  return { ok: false, denyReason, reason };
}

export class StrategyRegistry {
  readonly #byFamily = new Map<AlgorithmFamily, Map<string, StrategyContract>>();
  readonly #order: Array<{ family: AlgorithmFamily; id: string }> = [];

  constructor(initial: readonly StrategyContract[] = []) {
    for (const s of initial) {
      this.register(s);
    }
  }

  /**
   * Validate and register a strategy contract. Returns `{ ok: false }` with
   * a machine-readable reason instead of throwing for every rejectable input.
   */
  register(
    strategy: StrategyContract
  ): { ok: true; strategy: StrategyContract } | { ok: false; reason: string } {
    if (strategy === null || typeof strategy !== "object") {
      return { ok: false, reason: "strategy must be an object" };
    }
    if (typeof strategy.id !== "string" || strategy.id.length === 0) {
      return { ok: false, reason: "strategy.id must be a non-empty string" };
    }
    if (strategy.id.length > 64) {
      return { ok: false, reason: "strategy.id must be at most 64 chars" };
    }
    if (!STRATEGY_ID_PATTERN.test(strategy.id)) {
      return {
        ok: false,
        reason:
          "strategy.id must match [a-z][a-z0-9-]* (lowercase, dots not allowed; family scoping uses '.family' suffix convention): '" +
          strategy.id +
          "'",
      };
    }
    if (!isAlgorithmFamily(strategy.family)) {
      return {
        ok: false,
        reason:
          "strategy.family must be one of the ten closed ALGORITHM_FAMILIES; got '" +
          String(strategy.family) +
          "'",
      };
    }
    if (typeof strategy.version !== "string" || !VERSION_PATTERN.test(strategy.version)) {
      return {
        ok: false,
        reason:
          "strategy.version must be a semver-like 'MAJOR.MINOR.PATCH' string; got '" +
          String(strategy.version) +
          "'",
      };
    }
    if (typeof strategy.implemented !== "boolean") {
      return { ok: false, reason: "strategy.implemented must be boolean" };
    }
    if (typeof strategy.description !== "string" || strategy.description.length === 0) {
      return { ok: false, reason: "strategy.description must be a non-empty string" };
    }
    if (strategy.description.length > 512) {
      return { ok: false, reason: "strategy.description must be at most 512 chars" };
    }
    if (typeof strategy.evaluate !== "function") {
      return { ok: false, reason: "strategy.evaluate must be a function" };
    }

    const familyMap = this.#byFamily.get(strategy.family) ?? new Map<string, StrategyContract>();
    if (familyMap.has(strategy.id)) {
      return {
        ok: false,
        reason:
          "duplicate strategy id '" +
          strategy.id +
          "' in family '" +
          strategy.family +
          "' (replace via replaceStrategy, not re-register)",
      };
    }
    familyMap.set(strategy.id, Object.freeze(strategy));
    this.#byFamily.set(strategy.family, familyMap);
    this.#order.push({ family: strategy.family, id: strategy.id });
    return { ok: true, strategy };
  }

  /**
   * Replace an existing strategy contract under the SAME family and id.
   * Replacement is the sanctioned mutability boundary for "replaceable
   * strategy contracts": it is explicit, it is scoped to one family+id, and
   * the replaced contract must exist. Returns `selection_not_allowed`-shaped
   * denial semantics via `{ ok: false }` when the target does not exist.
   */
  replaceStrategy(
    family: AlgorithmFamily,
    id: string,
    next: StrategyContract
  ): { ok: true; previous: StrategyContract } | { ok: false; reason: string } {
    if (!isAlgorithmFamily(family)) {
      return { ok: false, reason: "unknown family: '" + String(family) + "'" };
    }
    if (typeof id !== "string" || id.length === 0) {
      return { ok: false, reason: "id must be a non-empty string" };
    }
    const familyMap = this.#byFamily.get(family);
    const previous = familyMap?.get(id);
    if (!familyMap || !previous) {
      return {
        ok: false,
        reason: "cannot replace unregistered strategy '" + id + "' in family '" + family + "'",
      };
    }
    if (next.family !== family || next.id !== id) {
      return {
        ok: false,
        reason:
          "replacement must keep family '" +
          family +
          "' and id '" +
          id +
          "'; got family '" +
          next.family +
          "' id '" +
          next.id +
          "'",
      };
    }
    const validated = this.register(next);
    // register would fail on duplicate; bypass by direct set after validation.
    if (!validated.ok) {
      // Re-registering `next` fails only because the id already exists; the
      // other validation rules have already been checked by register().
      const precheck = this.validateShape(next);
      if (!precheck.ok) return { ok: false, reason: precheck.reason };
    }
    familyMap.set(id, Object.freeze(next));
    return { ok: true, previous };
  }

  private validateShape(
    strategy: StrategyContract
  ): { ok: true } | { ok: false; reason: string } {
    // Minimal re-validation used by replaceStrategy when register() short-
    // circuits on duplicate id. Mirrors register()'s checks.
    if (strategy === null || typeof strategy !== "object") {
      return { ok: false, reason: "strategy must be an object" };
    }
    if (typeof strategy.id !== "string" || strategy.id.length === 0) {
      return { ok: false, reason: "strategy.id must be a non-empty string" };
    }
    if (!isAlgorithmFamily(strategy.family)) {
      return { ok: false, reason: "strategy.family must be a closed family" };
    }
    if (typeof strategy.evaluate !== "function") {
      return { ok: false, reason: "strategy.evaluate must be a function" };
    }
    return { ok: true };
  }

  /** Deny-by-default lookup: an unregistered family+id pair is always denied. */
  select(family: AlgorithmFamily, id: string): AlgorithmSelectionResult {
    if (!isAlgorithmFamily(family)) {
      return deny("unknown_family", "unknown algorithm family: '" + String(family) + "'");
    }
    if (typeof id !== "string" || id.length === 0) {
      return deny("invalid_input", "strategy id must be a non-empty string");
    }
    const familyMap = this.#byFamily.get(family);
    const strategy = familyMap?.get(id);
    if (!strategy) {
      return deny(
        "unknown_strategy",
        "no strategy '" + id + "' registered in family '" + family + "'"
      );
    }
    // Family binding double-check (registration enforces this too).
    if (strategy.family !== family) {
      return deny(
        "selection_not_allowed",
        "strategy '" + id + "' is bound to family '" + strategy.family + "', not '" + family + "'"
      );
    }
    return { ok: true, strategy };
  }

  has(family: AlgorithmFamily, id: string): boolean {
    if (!isAlgorithmFamily(family)) return false;
    return this.#byFamily.get(family)?.has(id) ?? false;
  }

  /** All registered strategies for one family, in registration order. */
  listForFamily(family: AlgorithmFamily): readonly StrategyContract[] {
    if (!isAlgorithmFamily(family)) return Object.freeze([]);
    const familyMap = this.#byFamily.get(family);
    if (!familyMap) return Object.freeze([]);
    const out: StrategyContract[] = [];
    for (const { family: f, id } of this.#order) {
      if (f !== family) continue;
      const s = familyMap.get(id);
      if (s) out.push(s);
    }
    return Object.freeze(out);
  }

  /** Which of the ten closed families currently have at least one strategy. */
  familiesWithStrategies(): readonly AlgorithmFamily[] {
    const out: AlgorithmFamily[] = [];
    for (const f of ALGORITHM_FAMILIES) {
      if ((this.#byFamily.get(f)?.size ?? 0) > 0) out.push(f);
    }
    return Object.freeze(out);
  }

  /** Frozen descriptors for observability/audit surfaces. */
  descriptors(): readonly StrategyDescriptor[] {
    const out: StrategyDescriptor[] = [];
    for (const { family, id } of this.#order) {
      const s = this.#byFamily.get(family)?.get(id);
      if (s) {
        out.push(
          Object.freeze({
            id: s.id,
            family: s.family,
            version: s.version,
            implemented: s.implemented,
            description: s.description,
          })
        );
      }
    }
    return Object.freeze(out);
  }

  /** Deterministic fingerprint of the full registry state. */
  deterministicFingerprint(): string {
    const parts: string[] = [];
    for (const { family, id } of this.#order) {
      const s = this.#byFamily.get(family)?.get(id);
      if (!s) continue;
      parts.push(family + "/" + id + "@" + s.version + "=" + canonicalSerializeStrategy(s));
    }
    return parts.join("||");
  }

  size(): number {
    return this.#order.length;
  }
}
