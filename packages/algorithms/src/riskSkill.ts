import type {
  AlgorithmDecisionInput,
  AlgorithmRecommendation,
  RuntimeContext,
  StrategyContract,
} from "./types.js";
import { filterSkillsByCapabilities } from "./integration.js";

/**
 * Phase 17C — upgraded Runtime Risk + Skill Selection strategies.
 *
 * RISK (`runtime-risk.gate-rank@0.2.0`): extends 17A's label-rank with a
 * machine-readable verdict (allow / restrict / deny). Risk MAY restrict or
 * deny execution ADVISORY-ly — the verdict is data for the decision layer;
 * `applyRiskVerdict` (integration.ts) enforces the monotone-restriction
 * invariant with the policy engine as the floor. `executionAuthorized`
 * stays pinned false on every output.
 *
 * SKILL (`skill-selection.capability-map@0.2.0`): extends 17A's
 * capability-map-lite with caller-asserted `grantedCapabilities` filtering
 * (NO TOOL WITHOUT CAPABILITY): anything recommended but not granted is
 * withheld from the recommendation and reported as `withheld`. The verb→
 * capability hint table is unchanged.
 */

/** Risk-indicator substrings (17A table, unchanged). */
const RISK_INDICATORS: readonly string[] = Object.freeze([
  "commit",
  "push",
  "rm ",
  "delete",
  "write",
  "modify",
  "network",
  "external",
  "privileged",
  "force",
]);

/** Danger-tier indicators → deny verdict; medium-tier → restrict. */
const DENY_INDICATORS: readonly string[] = Object.freeze([
  "commit",
  "push",
  "rm ",
  "privileged",
  "force",
]);
const RESTRICT_INDICATORS: readonly string[] = Object.freeze([
  "write",
  "modify",
  "network",
  "external",
  "delete",
]);

function boundedSummary(s: string): string {
  return s.length > 256 ? s.slice(0, 256) : s;
}

export const runtimeRiskGateRank: StrategyContract = Object.freeze({
  id: "gate-rank",
  family: "runtime_risk_evaluation",
  version: "0.2.0",
  implemented: true,
  description:
    "deterministic risk ranking + machine-readable verdict (allow/restrict/deny): danger-tier indicators deny, medium-tier restrict, none allow; advisory only — policy remains authoritative",
  async evaluate(
    input: AlgorithmDecisionInput,
    _context: RuntimeContext
  ): Promise<AlgorithmRecommendation> {
    void _context;
    const flagged: string[] = [];
    const clean: string[] = [];
    let denyHit: string | null = null;
    let restrictHit: string | null = null;

    for (const label of input.candidateLabels) {
      const lower = label.toLowerCase();
      const isFlagged = RISK_INDICATORS.some((ind) => lower.includes(ind));
      (isFlagged ? flagged : clean).push(label);
      if (denyHit === null) {
        const d = DENY_INDICATORS.find((ind) => lower.includes(ind));
        if (d !== undefined) denyHit = d;
      }
      if (restrictHit === null) {
        const r = RESTRICT_INDICATORS.find((ind) => lower.includes(ind));
        if (r !== undefined) restrictHit = r;
      }
    }

    const ranked = [...flagged, ...clean];

    // Verdict: the most severe tier any candidate earned.
    let verdict: "allow" | "restrict" | "deny" = "allow";
    let verdictReason = "no risk-indicative substrings found; uniform low-confidence ordering";
    if (denyHit !== null) {
      verdict = "deny";
      verdictReason = "danger-tier risk indicator '" + denyHit + "' present among candidates";
    } else if (restrictHit !== null) {
      verdict = "restrict";
      verdictReason = "medium-tier risk indicator '" + restrictHit + "' present among candidates";
    }

    // Withholding recommendations: the flagged labels themselves (advisory).
    const withhold =
      verdict === "allow" ? undefined : flagged.length > 0 ? flagged : undefined;

    const confidence = verdict === "deny" ? 0.95 : flagged.length > 0 ? 0.85 : 0.5;
    const summary = boundedSummary(
      "verdict " +
        verdict +
        "; " +
        String(flagged.length) +
        " flagged candidate(s)" +
        (verdict === "allow" ? "" : "; recommended withholding " + String(flagged.length) + " flagged label(s)")
    );

    return {
      family: "runtime_risk_evaluation",
      strategyId: "gate-rank",
      rankedCandidates: ranked,
      confidence,
      rationale:
        "deterministic risk ranking with " +
        verdict +
        " verdict; advisory only — the deny-by-default policy engine remains the sole execution authority",
      isRecommendation: true,
      executionAuthorized: false,
      reasoningSummary: summary,
      riskVerdict: Object.freeze({
        tier: verdict,
        reason: verdictReason,
        ...(withhold !== undefined ? { withholdCapabilities: Object.freeze([...withhold]) } : {}),
      }),
    };
  },
});

const VERB_CAPABILITY_HINT: Readonly<Record<string, string>> = Object.freeze({
  inspect: "workspace:read-metadata",
  observe: "workspace:list",
  search: "workspace:search",
  retrieve: "workspace:read-file",
  compare: "workspace:read-file",
  plan: "plan:generate",
  validate: "workspace:read-file",
});

export const skillCapabilityMapLite: StrategyContract = Object.freeze({
  id: "capability-map",
  family: "skill_selection",
  version: "0.2.0",
  implemented: true,
  description:
    "deterministic verb→capability hint mapping with grantedCapabilities filtering (NO TOOL WITHOUT CAPABILITY): ungranted hints are withheld and reported; never grants capabilities",
  async evaluate(
    input: AlgorithmDecisionInput,
    _context: RuntimeContext
  ): Promise<AlgorithmRecommendation> {
    void _context;
    const verb = typeof input.verb === "string" ? input.verb.toLowerCase() : "";
    const hint = verb !== "" ? VERB_CAPABILITY_HINT[verb] : undefined;

    if (hint === undefined) {
      // Fail-closed to an empty recommendation — never a fabricated hint.
      return {
        family: "skill_selection",
        strategyId: "capability-map",
        rankedCandidates: [],
        confidence: 0,
        rationale:
          "no deterministic capability hint for verb '" +
          (verb || "(none)") +
          "'; empty recommendation (fail-closed to no-hint)",
        isRecommendation: true,
        executionAuthorized: false,
        reasoningSummary: "no capability hint for verb; recommended 0, withheld 0",
      };
    }

    const filtered = filterSkillsByCapabilities([hint], input.grantedCapabilities);
    const withheldNote =
      filtered.withheld.length > 0
        ? "; " + String(filtered.withheld.length) + " hint(s) withheld (capability not granted)"
        : "";

    return {
      family: "skill_selection",
      strategyId: "capability-map",
      rankedCandidates: filtered.recommended,
      confidence: filtered.recommended.length > 0 ? 0.8 : 0.5,
      rationale:
        "deterministic capability hint for verb '" + verb + "'" + withheldNote,
      isRecommendation: true,
      executionAuthorized: false,
      reasoningSummary: boundedSummary(
        "recommended " +
          String(filtered.recommended.length) +
          ", withheld " +
          String(filtered.withheld.length) +
          " capability hint(s) for verb " +
          verb
      ),
    };
  },
});

// 17A strategy id retained for import compatibility in families.ts.
export { skillCapabilityMapLite as skillCapabilityMapLiteImpl };
