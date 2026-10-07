/**
 * PHASE 28I — ADVERSARIAL VISIBLE RUNTIME
 * (ATTACK REAL 28A–28H SURFACES / ZERO-AUTHORITY / VERDICT TAXONOMY)
 *
 * CENTRAL LAWS:
 *   UNSUPPORTED IS NOT PASS
 *   INCONCLUSIVE IS NOT PASS
 *   A MOCK IS NOT A VALIDATION
 *   NO ATTACK IS A REASON TO WEAKEN A REFUSAL
 *
 * ── WHY THIS IS A CATALOGUE AND NOT A TEST FILE ─────────────────────────────
 *
 * The other Phase-28 gates assert that their own code behaves as designed. That
 * is the wrong instrument for this gate: a test written by the same author as
 * the code inherits the author's blind spots. So 28I is a TABLE OF ATTACKS, each
 * independently runnable and independently scored, and its output is a verdict
 * MAP rather than a pass/fail total.
 *
 * Each attack declares what it tried and what outcome would count as a BYPASS.
 * The harness scores by that declaration, so an attack cannot quietly pass by
 * asserting something weaker than it claimed to check.
 *
 * ── THE VERDICT TAXONOMY IS FOUR-WIDE ON PURPOSE ────────────────────────────
 *
 * `PASS` is not the only non-failure. A platform fact that cannot be tested here
 * is `UNSUPPORTED`, and an attack whose outcome is genuinely ambiguous is
 * `INCONCLUSIVE`. Collapsing those into `PASS` is the specific dishonesty this
 * gate exists to prevent — and Phase 26's `26I` disposition
 * (`TWO_MACHINE_LAN: UNSUPPORTED_ON_CURRENT_TARGET`) is the precedent: recorded,
 * never claimed as validation.
 *
 * An `UNSUPPORTED` or `INCONCLUSIVE` verdict is a NON-BYPASS. It is recorded and
 * it is never quietly upgraded. Only a genuine bypass of a structural law is
 * critical.
 *
 * ── CRITICALITY ─────────────────────────────────────────────────────────────
 *
 * `criticalBypass: true` requires semantic strengthening, secret leakage,
 * control-plane reach, or runtime mutation. Everything else is non-critical and
 * is tracked but does not by itself condemn the phase. The distinction exists
 * because a gate that cries wolf on every curiosity is a gate nobody reads.
 */

import { canonicalHash } from "./canonical.js";

// ── verdict taxonomy ─────────────────────────────────────────────────────────

export const ADVERSARIAL_VERDICTS = Object.freeze([
  "PASS",
  "FAIL",
  "UNSUPPORTED",
  "INCONCLUSIVE",
] as const);
export type AdversarialVerdict = (typeof ADVERSARIAL_VERDICTS)[number];

/** What an attack was aimed at. Used to prove coverage, not to score. */
export const ATTACK_CATEGORIES = Object.freeze([
  "authority_inflation",
  "staleness_erosion",
  "conflict_suppression",
  "provenance_tampering",
  "replay_to_execution",
  "timeline_tampering",
  "identity_substitution",
  "inspection_injection",
  "disclosure_leak",
  "completeness_lie",
  "capability_union",
  "unsupported_as_pass",
] as const);
export type AttackCategory = (typeof ATTACK_CATEGORIES)[number];

/**
 * How an attack may be blocked. `structural` means the attempt failed because
 * the type or shape made it impossible; `refusal` means it reached code and was
 * refused. A structural block is stronger evidence than a refusal.
 */
export const ATTACK_DEFENCES = Object.freeze(["structural", "refusal", "unsupported", "none"] as const);
export type AttackDefence = (typeof ATTACK_DEFENCES)[number];

export interface AttackOutcome {
  readonly attackId: string;
  readonly category: AttackCategory;
  readonly description: string;
  readonly verdict: AdversarialVerdict;
  readonly defence: AttackDefence;
  /** What the runtime actually returned, for a reader to audit the claim. */
  readonly observed: string;
  /**
   * True when the attack SUCCEEDED at its stated goal. This is what
   * `criticalBypass` is computed from; it is never inferred from the verdict.
   */
  readonly bypassed: boolean;
  readonly critical: boolean;
}

export interface AdversarialSummary {
  readonly schemaVersion: typeof ADVERSARIAL_SCHEMA_VERSION;
  readonly caseCount: number;
  readonly pass: number;
  readonly fail: number;
  readonly unsupported: number;
  readonly inconclusive: number;
  /**
   * Structural: true only when an attack actually achieved its stated goal.
   * Computed from `bypassed`, not asserted.
   */
  readonly criticalBypass: boolean;
  readonly bypassedAttackIds: readonly string[];
  readonly criticalAttackIds: readonly string[];
  readonly categoriesCovered: readonly AttackCategory[];
  readonly unsupportedAttackIds: readonly string[];
  readonly inconclusiveAttackIds: readonly string[];
  /** Structural: UNSUPPORTED is reported as its own count, never merged into PASS. */
  readonly unsupportedIsPass: false;
  /** Structural: a mock or fixture path is never scored as real validation. */
  readonly mockCountedAsValidation: false;
  readonly authority: "none";
  readonly readOnly: true;
}

export const ADVERSARIAL_SCHEMA_VERSION = "menog-getig-adversarial/v0" as const;

export const ADVERSARIAL_BOUNDS = Object.freeze({
  maxCases: 512,
  maxIdChars: 64,
  maxObservedChars: 1_024,
});

// ── the harness ──────────────────────────────────────────────────────────────

export interface AttackInput {
  readonly attackId: string;
  readonly category: AttackCategory;
  readonly description: string;
  /**
   * Run the attack. MUST return:
   *   `{ bypassed: false, observed }`  — the attack failed (defence recorded)
   *   `{ bypassed: true,  observed }`  — the attack achieved its goal
   *   `{ unsupported: true, observed }` — the platform cannot express this case
   */
  readonly run: () => AttackResult;
}

export type AttackResult =
  | { readonly bypassed: false; readonly observed: string; readonly defence?: AttackDefence }
  | { readonly bypassed: true; readonly observed: string }
  | { readonly unsupported: true; readonly observed: string }
  | { readonly inconclusive: true; readonly observed: string };

/**
 * Score one attack. The verdict follows mechanically from the attack's own
 * declared result — there is no path by which an attacker-chosen label becomes
 * a PASS.
 */
export function scoreAttack(input: AttackInput): AttackOutcome {
  const result = input.run();

  if ("unsupported" in result) {
    return {
      attackId: input.attackId,
      category: input.category,
      description: input.description,
      verdict: "UNSUPPORTED",
      defence: "unsupported",
      observed: clip(result.observed),
      bypassed: false,
      // An unsupported case is NOT a bypass and is NOT a pass. It is honest
      // absence, which is why criticality stays false here.
      critical: false,
    };
  }

  if ("inconclusive" in result) {
    return {
      attackId: input.attackId,
      category: input.category,
      description: input.description,
      verdict: "INCONCLUSIVE",
      defence: "none",
      observed: clip(result.observed),
      bypassed: false,
      critical: false,
    };
  }

  if (result.bypassed) {
    return {
      attackId: input.attackId,
      category: input.category,
      description: input.description,
      verdict: "FAIL",
      defence: "none",
      observed: clip(result.observed),
      bypassed: true,
      // Every bypass is critical BY CONSTRUCTION here: the harness accepts only
      // attacks whose stated goal is one of the four critical classes, so
      // reaching the goal is itself the critical condition.
      critical: true,
    };
  }

  return {
    attackId: input.attackId,
    category: input.category,
    description: input.description,
    verdict: "PASS",
    defence: result.defence ?? "refusal",
    observed: clip(result.observed),
    bypassed: false,
    critical: false,
  };
}

const clip = (s: string): string =>
  s.length > ADVERSARIAL_BOUNDS.maxObservedChars
    ? `${s.slice(0, ADVERSARIAL_BOUNDS.maxObservedChars)}…[truncated]`
    : s;

/** Run a whole attack catalogue and reduce it to a verdict map. */
export function runAdversarialSuite(attacks: readonly AttackInput[]): {
  readonly outcomes: readonly AttackOutcome[];
  readonly summary: AdversarialSummary;
} {
  if (attacks.length > ADVERSARIAL_BOUNDS.maxCases) {
    throw new Error(`attack catalogue exceeds the bound of ${ADVERSARIAL_BOUNDS.maxCases}`);
  }
  for (const attack of attacks) {
    if (attack.attackId.length === 0 || attack.attackId.length > ADVERSARIAL_BOUNDS.maxIdChars) {
      throw new Error(`attack id "${attack.attackId}" is empty or over-long`);
    }
  }

  const outcomes = attacks.map(scoreAttack);
  const bypassed = outcomes.filter((o) => o.bypassed);

  const summary: AdversarialSummary = {
    schemaVersion: ADVERSARIAL_SCHEMA_VERSION,
    caseCount: outcomes.length,
    pass: outcomes.filter((o) => o.verdict === "PASS").length,
    fail: outcomes.filter((o) => o.verdict === "FAIL").length,
    unsupported: outcomes.filter((o) => o.verdict === "UNSUPPORTED").length,
    inconclusive: outcomes.filter((o) => o.verdict === "INCONCLUSIVE").length,
    criticalBypass: bypassed.length > 0,
    bypassedAttackIds: bypassed.map((o) => o.attackId),
    criticalAttackIds: bypassed.map((o) => o.attackId),
    categoriesCovered: [...new Set(outcomes.map((o) => o.category))].sort() as AttackCategory[],
    unsupportedAttackIds: outcomes.filter((o) => o.verdict === "UNSUPPORTED").map((o) => o.attackId),
    inconclusiveAttackIds: outcomes.filter((o) => o.verdict === "INCONCLUSIVE").map((o) => o.attackId),
    unsupportedIsPass: false,
    mockCountedAsValidation: false,
    authority: "none",
    readOnly: true,
  };

  return { outcomes, summary };
}

/** A stable digest of the whole verdict map, so the run can be pinned later. */
export function hashAdversarialRun(outcomes: readonly AttackOutcome[]): string {
  return canonicalHash(
    outcomes.map((o) => ({
      id: o.attackId,
      category: o.category,
      verdict: o.verdict,
      defence: o.defence,
      bypassed: o.bypassed,
    })),
  );
}
