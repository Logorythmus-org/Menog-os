/**
 * PRE-20B — Isolation evaluation logic (pure, deterministic, no I/O, no
 * enforcement). These functions are the ONLY sanctioned way to turn a
 * (profile, snapshot) pair into a decision; they make fail-open states
 * unrepresentable: any non-SUPPORTED (or ABI-insufficient) required primitive
 * ⇒ canProceed = false, before any target execution.
 *
 * Agent-supplied profiles are untrusted: composeProfileBaseline() accepts an
 * agent-proposed profile ONLY as a restriction delta over a human-reviewed
 * baseline — any relaxation of a baseline requirement, or any introduce of a
 * required primitive absent from the baseline, is REJECTED with a typed
 * failure. Agent proposals never execute directly.
 *
 * evaluateIsolation() returns BOTH a typed failure AND a fail-closed decision
 * for invalid inputs: consumers that only inspect canProceed are safe.
 */

import {
  ISOLATION_PRIMITIVE_IDS,
  isUsableState,
  ISOLATION_CONTRACT_SCHEMA_VERSION,
  type IsolationCapabilitySnapshot,
  type IsolationDecision,
  type IsolationDegradation,
  type IsolationEvidence,
  type IsolationFailure,
  type IsolationProfile,
  type IsolationRequirement,
  type IsolationPrimitiveId,
  type PrimitiveState,
} from "./types.js";
import { isolationEvidenceHash } from "./canonical.js";

export { ISOLATION_PRIMITIVE_IDS, isUsableState };

// ── internal helpers ─────────────────────────────────────────────────────────

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const PRIMITIVE_ID_SET: ReadonlySet<string> = new Set(ISOLATION_PRIMITIVE_IDS);

function isPrimitiveId(v: unknown): v is IsolationPrimitiveId {
  return typeof v === "string" && PRIMITIVE_ID_SET.has(v);
}

function isNonEmptyBounded(v: unknown, max: number): v is string {
  return typeof v === "string" && v.trim().length > 0 && v.length <= max;
}

const VALID_CRITICALITY = new Set(["required", "optional"]);
const VALID_ON_MISSING = new Set(["fail_closed", "degrade_explicit", "proceed"]);
const VALID_ORIGIN = new Set(["human_reviewed", "agent_proposed"]);

// ── profile validation (typed failures, no exceptions) ──────────────────────

export function validateIsolationProfile(
  input: unknown
): { ok: true; profile: IsolationProfile } | { ok: false; failure: IsolationFailure } {
  if (!isObject(input)) {
    return { ok: false, failure: { code: "PROFILE_INVALID", message: "profile must be an object" } };
  }

  const profileId = input.profileId;
  if (!isNonEmptyBounded(profileId, 64)) {
    return {
      ok: false,
      failure: { code: "PROFILE_INVALID", message: "profileId must be a non-empty string of at most 64 characters" },
    };
  }

  const origin = input.origin;
  if (typeof origin !== "string" || !VALID_ORIGIN.has(origin)) {
    return {
      ok: false,
      failure: { code: "PROFILE_INVALID", message: "origin must be 'human_reviewed' or 'agent_proposed'" },
    };
  }

  if (!Array.isArray(input.requirements)) {
    return { ok: false, failure: { code: "PROFILE_INVALID", message: "requirements must be an array" } };
  }
  if (input.requirements.length === 0) {
    return { ok: false, failure: { code: "PROFILE_INVALID", message: "requirements must not be empty" } };
  }
  if (input.requirements.length > 32) {
    return { ok: false, failure: { code: "PROFILE_INVALID", message: "requirements must not exceed 32 entries" } };
  }

  const seen = new Set<string>();
  for (const r of input.requirements) {
    if (!isObject(r)) {
      return { ok: false, failure: { code: "PROFILE_INVALID", message: "each requirement must be an object" } };
    }
    if (!isPrimitiveId(r.primitive)) {
      return {
        ok: false,
        failure: { code: "PROFILE_INVALID", message: "requirement.primitive must be a known IsolationPrimitiveId" },
      };
    }
    if (seen.has(r.primitive)) {
      return {
        ok: false,
        failure: { code: "PROFILE_INVALID", message: "duplicate requirement for primitive '" + r.primitive + "'" },
      };
    }
    seen.add(r.primitive);

    if (typeof r.criticality !== "string" || !VALID_CRITICALITY.has(r.criticality)) {
      return { ok: false, failure: { code: "PROFILE_INVALID", message: "criticality must be 'required' or 'optional'" } };
    }
    if (typeof r.onMissing !== "string" || !VALID_ON_MISSING.has(r.onMissing)) {
      return {
        ok: false,
        failure: {
          code: "PROFILE_INVALID",
          message: "onMissing must be one of 'fail_closed' | 'degrade_explicit' | 'proceed'",
        },
      };
    }
    // Optional primitives may not demand hard failure; required primitives
    // may not silently proceed.
    if (r.criticality === "required" && r.onMissing === "proceed") {
      return {
        ok: false,
        failure: {
          code: "PROFILE_INVALID",
          message: "required primitives may not use onMissing='proceed' (fail-closed contract)",
        },
      };
    }
    if (r.criticality === "optional" && r.onMissing === "fail_closed") {
      return {
        ok: false,
        failure: {
          code: "PROFILE_INVALID",
          message: "optional primitives may not use onMissing='fail_closed' (use required instead)",
        },
      };
    }
    if (r.onMissing === "degrade_explicit" && !isNonEmptyBounded(r.degradationNote, 200)) {
      return {
        ok: false,
        failure: {
          code: "PROFILE_INVALID",
          message: "onMissing='degrade_explicit' requires a degradationNote (bounded to 200 chars)",
        },
      };
    }
    if (r.minLandlockAbi !== undefined) {
      if (
        (r.primitive !== "landlock_fs" && r.primitive !== "landlock_net") ||
        typeof r.minLandlockAbi !== "number" ||
        !Number.isInteger(r.minLandlockAbi) ||
        r.minLandlockAbi < 1 ||
        r.minLandlockAbi > 4
      ) {
        return {
          ok: false,
          failure: {
            code: "PROFILE_INVALID",
            message: "minLandlockAbi is only valid for Landlock primitives as an integer 1..4",
          },
        };
      }
    }
  }

  const note = input.note;
  if (note !== undefined && !isNonEmptyBounded(note, 300)) {
    return { ok: false, failure: { code: "PROFILE_INVALID", message: "note must be a non-empty string of at most 300 characters" } };
  }

  return {
    ok: true,
    profile: {
      schemaVersion: ISOLATION_CONTRACT_SCHEMA_VERSION,
      profileId,
      origin: origin as "human_reviewed" | "agent_proposed",
      requirements: input.requirements.map((r) => {
        const req: {
          primitive: IsolationPrimitiveId;
          criticality: "required" | "optional";
          onMissing: "fail_closed" | "degrade_explicit" | "proceed";
          degradationNote?: string;
          minLandlockAbi?: number;
        } = {
          primitive: r.primitive,
          criticality: r.criticality as "required" | "optional",
          onMissing: r.onMissing as "fail_closed" | "degrade_explicit" | "proceed",
        };
        if (r.degradationNote !== undefined) req.degradationNote = r.degradationNote as string;
        if (r.minLandlockAbi !== undefined) req.minLandlockAbi = r.minLandlockAbi as number;
        return Object.freeze(req);
      }),
      ...(note !== undefined ? { note } : {}),
    },
  };
}

// ── agent-proposal composition (restrict-only) ──────────────────────────────

/**
 * Compose a human-reviewed baseline with an AGENT-PROPOSED profile. The
 * proposal is untrusted: it may only ADD restrictions. Any attempt to
 * relax a baseline requirement (criticality/downgrade/onMissing/minAbi) is
 * rejected with PROFILE_RELAXES_BASELINE. The result is always a
 * human_reviewed profile (authority chain preserved) whose profileId records
 * the composition.
 */
export function composeProfileBaseline(
  baseline: IsolationProfile,
  proposal: unknown
): { ok: true; profile: IsolationProfile } | { ok: false; failure: IsolationFailure } {
  if (baseline.origin !== "human_reviewed") {
    return {
      ok: false,
      failure: { code: "PROFILE_INVALID", message: "baseline must have origin='human_reviewed'" },
    };
  }

  const parsed = validateIsolationProfile(proposal);
  if (!parsed.ok) return parsed;
  const proposalProfile = parsed.profile;
  if (proposalProfile.origin !== "agent_proposed") {
    return {
      ok: false,
      failure: { code: "PROFILE_INVALID", message: "proposal must have origin='agent_proposed'" },
    };
  }

  const baselineReqs = new Map(baseline.requirements.map((r) => [r.primitive, r]));
  const composed: IsolationRequirement[] = [];

  for (const base of baseline.requirements) {
    const prop = proposalProfile.requirements.find((r) => r.primitive === base.primitive);

    if (!prop) {
      composed.push(base); // untouched baseline requirement
      continue;
    }
    // Restrict-only: the proposal may require strictly MORE than the baseline.
    if (base.criticality === "required") {
      if (prop.criticality !== "required") {
        return {
          ok: false,
          failure: {
            code: "PROFILE_RELAXES_BASELINE",
            message: "proposal downgrades required primitive '" + base.primitive + "'",
            primitives: [base.primitive],
          },
        };
      }
      const baseAbi = base.minLandlockAbi ?? 1;
      const propAbi = prop.minLandlockAbi ?? 1;
      if (propAbi < baseAbi) {
        return {
          ok: false,
          failure: {
            code: "PROFILE_RELAXES_BASELINE",
            message: "proposal lowers the required Landlock ABI for '" + base.primitive + "'",
            primitives: [base.primitive],
          },
        };
      }
      composed.push(prop); // may raise minAbi; onMissing already equals fail_closed
    } else {
      // baseline optional: proposal may make it required, or keep optional.
      composed.push(prop);
    }
  }

  // New primitives introduced by the proposal: allowed ONLY as restrictions
  // (they may be required — adding a requirement is restricting; onMissing
  // for new optional primitives must not be 'proceed' with no note, which
  // validateIsolationProfile already enforces).
  for (const prop of proposalProfile.requirements) {
    if (!baselineReqs.has(prop.primitive)) {
      composed.push(prop);
    }
  }

  return {
    ok: true,
    profile: {
      schemaVersion: ISOLATION_CONTRACT_SCHEMA_VERSION,
      profileId: baseline.profileId + "+agent:" + proposalProfile.profileId,
      origin: "human_reviewed",
      requirements: composed,
      ...(baseline.note !== undefined || proposalProfile.note !== undefined
        ? { note: ("baseline: " + (baseline.note ?? "—") + " | agent: " + (proposalProfile.note ?? "—")).slice(0, 300) }
        : {}),
    },
  };
}

// ── capability snapshot validation + decision ───────────────────────────────

export function validateCapabilitySnapshot(
  input: unknown
): { ok: true; snapshot: IsolationCapabilitySnapshot } | { ok: false; failure: IsolationFailure } {
  if (!isObject(input)) {
    return { ok: false, failure: { code: "PROFILE_INVALID", message: "snapshot must be an object" } };
  }
  const kernel = input.targetKernel;
  if (!isNonEmptyBounded(kernel, 120)) {
    return { ok: false, failure: { code: "PROFILE_INVALID", message: "snapshot.targetKernel must be a non-empty string" } };
  }
  if (!isNonEmptyBounded(input.targetArch, 40)) {
    return { ok: false, failure: { code: "PROFILE_INVALID", message: "snapshot.targetArch must be a non-empty string" } };
  }
  if (typeof input.isWsl !== "boolean") {
    return { ok: false, failure: { code: "PROFILE_INVALID", message: "snapshot.isWsl must be a boolean" } };
  }
  const abi = input.landlockAbi;
  if (abi !== null && (typeof abi !== "number" || !Number.isInteger(abi) || abi < 0)) {
    return { ok: false, failure: { code: "PROFILE_INVALID", message: "snapshot.landlockAbi must be a non-negative integer or null" } };
  }
  if (!isObject(input.primitives)) {
    return { ok: false, failure: { code: "PROFILE_INVALID", message: "snapshot.primitives must be an object" } };
  }
  for (const p of ISOLATION_PRIMITIVE_IDS) {
    const st = (input.primitives as Record<string, unknown>)[p];
    if (typeof st !== "string" || !["SUPPORTED", "UNSUPPORTED", "PERMISSION_DENIED", "UNVERIFIED", "NOT_APPLICABLE"].includes(st)) {
      return {
        ok: false,
        failure: { code: "PROFILE_INVALID", message: "snapshot.primitives['" + p + "'] must be a valid PrimitiveState" },
      };
    }
  }
  if (!isNonEmptyBounded(input.probedAt, 40) || Number.isNaN(Date.parse(input.probedAt))) {
    return { ok: false, failure: { code: "PROFILE_INVALID", message: "snapshot.probedAt must be an ISO timestamp" } };
  }
  return {
    ok: true,
    snapshot: input as unknown as IsolationCapabilitySnapshot,
  };
}

/**
 * The fail-closed decision function. Pure: (profile, snapshot) → decision.
 *
 * - required primitive with state ≠ SUPPORTED ⇒ missingRequired ⇒ canProceed=false
 * - required Landlock primitive with snapshot ABI < minLandlockAbi ⇒ canProceed=false
 * - optional primitive not usable + onMissing='degrade_explicit' ⇒ recorded degradation
 * - optional primitive not usable + onMissing='proceed' ⇒ no entry (the profile
 *   author asserted no consequence during validation)
 */
export function evaluateIsolation(
  profile: IsolationProfile,
  snapshot: IsolationCapabilitySnapshot
): IsolationDecision {
  const satisfied: IsolationPrimitiveId[] = [];
  const missingRequired: IsolationPrimitiveId[] = [];
  const degradations: IsolationDegradation[] = [];
  const reasons: string[] = [];

  for (const req of profile.requirements) {
    const state: PrimitiveState = snapshot.primitives[req.primitive] ?? "UNVERIFIED";
    const usable = isUsableState(state);
    const abiOk =
      (req.primitive !== "landlock_fs" && req.primitive !== "landlock_net") ||
      req.minLandlockAbi === undefined ||
      (snapshot.landlockAbi !== null && snapshot.landlockAbi >= req.minLandlockAbi);

    if (req.criticality === "required") {
      if (usable && abiOk) {
        satisfied.push(req.primitive);
      } else {
        missingRequired.push(req.primitive);
        if (!usable) {
          reasons.push("required primitive '" + req.primitive + "' is " + state + " — fail closed");
        } else {
          reasons.push(
            "required primitive '" + req.primitive + "' ABI " + String(snapshot.landlockAbi) +
              " < required " + String(req.minLandlockAbi) + " — fail closed"
          );
        }
      }
      continue;
    }

    // optional
    if (usable && abiOk) {
      satisfied.push(req.primitive);
    } else if (req.onMissing === "degrade_explicit") {
      degradations.push({
        primitive: req.primitive,
        consequence: req.degradationNote ?? "primitive unavailable",
      });
    }
    // optional + 'proceed': no entry either way (profile author asserted no consequence)
  }

  const canProceed = missingRequired.length === 0;
  const disposition: IsolationDecision["disposition"] = !canProceed
    ? "fail_closed"
    : degradations.length > 0
      ? "degrade_explicit"
      : "enforce_full";

  return Object.freeze({
    disposition,
    satisfied,
    missingRequired,
    degradations,
    canProceed,
    reasons,
  });
}

// ── policy necessity combinator ─────────────────────────────────────────

export interface IsolationGateVerdict {
  readonly permitted: boolean;
  readonly reason?: string;
  readonly degradations: readonly IsolationDegradation[];
}

/**
 * Policy ALLOW is NECESSARY but NOT SUFFICIENT. This combinator is the only
 * sanctioned junction of the two authorities; it can only deny. It accepts
 * the policy engine's outcome structurally (PolicyResult.decision.outcome or
 * any { outcome } record) so 20C/20D can wire it without new coupling.
 */
export function assertIsolationPermits(
  policy: { readonly outcome: string },
  decision: IsolationDecision
): IsolationGateVerdict {
  if (policy.outcome !== "allow") {
    return {
      permitted: false,
      reason: "policy denied: isolation never expands authority",
      degradations: decision.degradations,
    };
  }
  if (!decision.canProceed) {
    return {
      permitted: false,
      reason:
        "isolation decision failed closed (missing required primitives: " +
        decision.missingRequired.join(", ") +
        ") — policy allow alone is not sufficient",
      degradations: decision.degradations,
    };
  }
  return { permitted: true, degradations: decision.degradations };
}

// ── evidence assembly (per-primitive; never "sandboxed: true") ───────────────

export type EvidenceInputRecord = Record<
  string,
  { applied: boolean; abi?: number | null; detail: string }
>;

/**
 * Build per-primitive evidence from the decision and the ACTUAL enforcement
 * results. Enforces the anti-overclaim contract: an entry may claim
 * applied=true only when the decision satisfied that primitive; applied=false
 * requires a detail. Evidence hash binds decision profile + records.
 */
export function buildIsolationEvidence(
  decision: IsolationDecision,
  records: EvidenceInputRecord,
  profileId: string,
  recordedAt: string
): { ok: true; evidence: IsolationEvidence } | { ok: false; failure: IsolationFailure } {
  if (!isObject(records)) {
    return { ok: false, failure: { code: "EVIDENCE_OVERCLAIM", message: "records must be an object" } };
  }
  const satisfiedSet = new Set<string>(decision.satisfied);
  const enforced: Record<string, { applied: boolean; abi?: number | null; detail: string }> = {};

  for (const [primitive, rec] of Object.entries(records)) {
    if (!isPrimitiveId(primitive)) {
      return { ok: false, failure: { code: "EVIDENCE_OVERCLAIM", message: "unknown primitive id in records: '" + primitive + "'" } };
    }
    if (!isObject(rec) || typeof rec.detail !== "string") {
      return { ok: false, failure: { code: "EVIDENCE_OVERCLAIM", message: "each record needs a string detail" } };
    }
    if (rec.applied === true && !satisfiedSet.has(primitive)) {
      return {
        ok: false,
        failure: {
          code: "EVIDENCE_OVERCLAIM",
          message: "applied=true for primitive '" + primitive + "' which the decision did not satisfy",
        },
      }
    }
    if (rec.applied === false && rec.detail.trim().length === 0) {
      return {
        ok: false,
        failure: { code: "EVIDENCE_OVERCLAIM", message: "applied=false requires a non-empty detail for '" + primitive + "'" },
      };
    }
    const entry: { applied: boolean; abi?: number | null; detail: string } = {
      applied: rec.applied,
      detail: rec.detail.slice(0, 200),
    };
    if (rec.abi !== undefined) entry.abi = rec.abi;
    enforced[primitive] = entry;
  }

  const hashBody = {
    schemaVersion: ISOLATION_CONTRACT_SCHEMA_VERSION,
    decisionProfileId: profileId,
    enforced,
    recordedAt,
  };
  // Hash binds everything except the hash field itself.
  const evidenceHash = isolationEvidenceHash(hashBody);
  const evidence: IsolationEvidence = Object.freeze({
    ...hashBody,
    evidenceHash,
  });
  return { ok: true, evidence };
}
