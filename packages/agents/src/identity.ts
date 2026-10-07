import { createHash } from "node:crypto";
import type {
  AgentCapabilityProfile,
  AgentIdentity,
  AgentProfileChangeRecord,
  AgentRegistrationDenial,
  AgentRegistrationResult,
  AgentRole,
  MediationAuthority,
} from "./types.js";
import {
  AGENTS_MAX_AGENTS,
  AGENTS_MAX_PROFILE_CAPABILITIES,
  AGENTS_MAX_PROFILE_DESCRIPTION_CHARS,
  AGENTS_MAX_PROFILE_VERBS,
  KNOWN_19A_AGENT_IDS,
} from "./types.js";

/**
 * Phase 19A — Agent identity & capability-profile contracts.
 *
 * AGENT = IDENTITY + ROLE + CAPABILITY PROFILE.
 * - IDENTITY: a frozen AgentIdentity created only via registration.
 * - ROLE: planner | builder | reviewer (closed union).
 * - PROFILE: the verbs/capabilities the agent may ASK about — never a grant.
 *
 * The deny-by-default policy engine remains the sole execution authority;
 * a profile is advisory scoping data used (a) by the runtime to scope what
 * an agent may propose, and (b) by humans to audit an agent's request
 * surface. A profile can never add policy allowances.
 */

const AUTHORITY: MediationAuthority = "mediation";

/**
 * The three human-reviewed Phase-19A capability profiles. Frozen literals:
 * any change is an unfreeze-protocol event requiring explicit approval.
 *
 * Scoping rationale (documents the least-privilege intent):
 * - planner: proposes plans (read-only world knowledge + plan generation).
 * - builder: would execute builds (read + workspace write ASK — policy
 *   still denies day-1 writes; the profile records the role's declared
 *   need, the authority stays with policy).
 * - reviewer: reviews diffs/commits (read + git read verbs; the reviewer
 *   ADVISES on commits — it can never authorize one).
 */
export const AGENT_ROLE_PROFILES: Readonly<
  Record<AgentRole, AgentCapabilityProfile>
> = Object.freeze({
  planner: Object.freeze({
    allowedVerbs: Object.freeze([
      "plan.generate",
      "workspace.read",
      "workspace.search",
    ]),
    allowedCapabilities: Object.freeze([
      "plan:generate",
      "workspace:read",
      "workspace:search",
    ]),
    maxSideEffectClass: "read",
    description:
      "proposes deterministic plans from goals; read-only world knowledge; can never execute or authorize",
  }),
  builder: Object.freeze({
    allowedVerbs: Object.freeze([
      "workspace.read",
      "workspace.search",
      "workspace.write",
    ]),
    allowedCapabilities: Object.freeze([
      "workspace:read",
      "workspace:search",
      "workspace:write",
    ]),
    maxSideEffectClass: "write",
    description:
      "proposes build/execution steps; declares write needs that policy must independently allow; can never self-authorize",
  }),
  reviewer: Object.freeze({
    allowedVerbs: Object.freeze([
      "workspace.read",
      "git.status",
      "git.diffRead",
    ]),
    allowedCapabilities: Object.freeze([
      "workspace:read",
      "git:status",
      "git:diff-read",
    ]),
    maxSideEffectClass: "read",
    description:
      "reviews proposed changes and issues advisory verdicts; advises humans on approvals it can never grant",
  }),
});

const KNOWN_CAPABILITY_ID_PREFIXES = [
  "workspace:",
  "git:",
  "plan:",
  "process:",
  "network:",
] as const;

function isKnownCapabilityShape(value: string): boolean {
  // 19A keeps this structural (prefix + suffix shape) so the agents package
  // does not need a dependency on @menog/policy. Registration of an unknown
  // capability id (e.g. "nonsense") is denied here; the authoritative
  // unknown-capability denial for actual policy requests stays in policy.
  if (value.length === 0 || value.length > 64) return false;
  return KNOWN_CAPABILITY_ID_PREFIXES.some(
    (p) => value.startsWith(p) && value.length > p.length
  );
}

export interface RegisterAgentInput {
  readonly agentId: string;
  readonly role: AgentRole;
  readonly profile?: AgentCapabilityProfile;
  readonly atEpochMs: number;
}

/** Validate one capability profile shape (bounded, fail-closed). */
export function validateAgentProfile(
  profile: AgentCapabilityProfile
): AgentRegistrationDenial | null {
  if (!profile || typeof profile !== "object") {
    return {
      ok: false,
      denyReason: "profile_invalid",
      reason: "profile must be an object",
    };
  }
  const verbs = profile.allowedVerbs;
  if (!Array.isArray(verbs)) {
    return {
      ok: false,
      denyReason: "profile_invalid",
      reason: "profile.allowedVerbs must be an array",
    };
  }
  if (verbs.length > AGENTS_MAX_PROFILE_VERBS) {
    return {
      ok: false,
      denyReason: "oversized_profile",
      reason:
        "profile.allowedVerbs length " +
        String(verbs.length) +
        " exceeds cap " +
        String(AGENTS_MAX_PROFILE_VERBS),
    };
  }
  for (const v of verbs) {
    if (typeof v !== "string" || v.length === 0 || v.length > 64) {
      return {
        ok: false,
        denyReason: "profile_invalid",
        reason: "profile.allowedVerbs entries must be non-empty strings ≤64 chars",
      };
    }
  }
  const caps = profile.allowedCapabilities;
  if (!Array.isArray(caps)) {
    return {
      ok: false,
      denyReason: "profile_invalid",
      reason: "profile.allowedCapabilities must be an array",
    };
  }
  if (caps.length > AGENTS_MAX_PROFILE_CAPABILITIES) {
    return {
      ok: false,
      denyReason: "oversized_profile",
      reason:
        "profile.allowedCapabilities length " +
        String(caps.length) +
        " exceeds cap " +
        String(AGENTS_MAX_PROFILE_CAPABILITIES),
    };
  }
  for (const c of caps) {
    if (typeof c !== "string" || !isKnownCapabilityShape(c)) {
      return {
        ok: false,
        denyReason: "profile_invalid",
        reason: "profile.allowedCapabilities entry '" + String(c) + "' is not a capability-shaped id",
      };
    }
  }
  const sec = profile.maxSideEffectClass;
  if (
    sec !== "none" &&
    sec !== "read" &&
    sec !== "write" &&
    sec !== "network" &&
    sec !== "system"
  ) {
    return {
      ok: false,
      denyReason: "profile_invalid",
      reason: "profile.maxSideEffectClass must be a valid upper bound",
    };
  }
  const desc = profile.description;
  if (typeof desc !== "string" || desc.length === 0) {
    return {
      ok: false,
      denyReason: "profile_invalid",
      reason: "profile.description must be a non-empty string",
    };
  }
  if (desc.length > AGENTS_MAX_PROFILE_DESCRIPTION_CHARS) {
    return {
      ok: false,
      denyReason: "oversized_profile",
      reason:
        "profile.description length " +
        String(desc.length) +
        " exceeds cap " +
        String(AGENTS_MAX_PROFILE_DESCRIPTION_CHARS),
    };
  }
  return null;
}

/**
 * Identity registry: the ONLY way an AgentIdentity can come into existence.
 * The runtime owns one instance; there is no public constructor for
 * identities and no mutation surface on registered ones (all fields frozen;
 * profile objects deep-frozen).
 */
export class AgentIdentityRegistry {
  readonly #identities = new Map<string, AgentIdentity>();
  readonly #changes: AgentProfileChangeRecord[] = [];

  /** Observable change log (registration + profile replacement). */
  changes(): readonly AgentProfileChangeRecord[] {
    return Object.freeze([...this.#changes]);
  }

  get(agentId: string): AgentIdentity | null {
    const id = this.#identities.get(agentId);
    return id ?? null;
  }

  has(agentId: string): boolean {
    return this.#identities.has(agentId);
  }

  roleOf(agentId: string): AgentRole | null {
    return this.#identities.get(agentId)?.role ?? null;
  }

  ids(): readonly string[] {
    return Object.freeze([...this.#identities.keys()]);
  }

  size(): number {
    return this.#identities.size;
  }

  /**
   * Register an agent identity. Role/id binding is PINNED for the three
   * 19A identities: 'menog-agent-planner' must register as planner, etc.
   * The default profile is the frozen role profile; a caller-supplied
   * profile REPLACES it only after full validation (and is recorded).
   */
  register(input: RegisterAgentInput): AgentRegistrationResult {
    const { agentId, role } = input;
    if (typeof agentId !== "string" || agentId.length === 0 || agentId.length > 64) {
      return {
        ok: false,
        denyReason: "identity_invalid",
        reason: "agentId must be a non-empty string ≤64 chars",
      };
    }
    if (!KNOWN_19A_AGENT_IDS.includes(agentId)) {
      return {
        ok: false,
        denyReason: "identity_mismatch",
        reason:
          "agentId '" +
          agentId +
          "' is not one of the three pinned 19A identity ids; introducing a new identity is an unfreeze-protocol event",
      };
    }
    if (role !== "planner" && role !== "builder" && role !== "reviewer") {
      return {
        ok: false,
        denyReason: "unknown_role",
        reason: "role must be planner|builder|reviewer",
      };
    }
    const expectedRole: AgentRole =
      agentId === "menog-agent-planner"
        ? "planner"
        : agentId === "menog-agent-builder"
          ? "builder"
          : "reviewer";
    if (role !== expectedRole) {
      return {
        ok: false,
        denyReason: "identity_mismatch",
        reason:
          "agentId '" +
          agentId +
          "' is pinned to role '" +
          expectedRole +
          "'; got '" +
          role +
          "'",
      };
    }
    if (this.#identities.has(agentId)) {
      return {
        ok: false,
        denyReason: "duplicate_identity",
        reason: "identity '" + agentId + "' is already registered",
      };
    }
    if (this.#identities.size >= AGENTS_MAX_AGENTS) {
      return {
        ok: false,
        denyReason: "oversized_profile",
        reason:
          "registry full (cap " + String(AGENTS_MAX_AGENTS) + "); registration denied",
      };
    }
    const profile = input.profile ?? AGENT_ROLE_PROFILES[role]!;
    const profileErr = validateAgentProfile(profile);
    if (profileErr) return profileErr;

    const identity: AgentIdentity = Object.freeze({
      agentId,
      role,
      schemaVersion: "menog-agents/v0" as const,
      registeredAtEpochMs: input.atEpochMs,
      profile: deepFreezeProfile(profile),
      authority: AUTHORITY,
      executionAuthorized: false,
    });
    this.#identities.set(agentId, identity);
    this.#changes.push(
      Object.freeze({
        agentId,
        role,
        changeKind: "registered",
        atEpochMs: input.atEpochMs,
        profile: identity.profile,
        authority: AUTHORITY,
        executionAuthorized: false,
      })
    );
    return { ok: true, identity };
  }

  /**
   * Replace an agent's profile. Runtime-only surface (deliberately not on
   * the agent side): every replacement is validated and recorded. This is
   * the reviewed channel for profile changes — there is no agent-side or
   * message-driven path to alter a profile.
   */
  replaceProfile(
    agentId: string,
    profile: AgentCapabilityProfile,
    atEpochMs: number
  ): AgentRegistrationResult {
    const identity = this.#identities.get(agentId);
    if (!identity) {
      return {
        ok: false,
        denyReason: "identity_invalid",
        reason: "unknown agentId '" + agentId + "'",
      };
    }
    const profileErr = validateAgentProfile(profile);
    if (profileErr) return profileErr;
    const next: AgentIdentity = Object.freeze({
      ...identity,
      profile: deepFreezeProfile(profile),
    });
    this.#identities.set(agentId, next);
    this.#changes.push(
      Object.freeze({
        agentId,
        role: identity.role,
        changeKind: "profile_replaced",
        atEpochMs,
        profile: next.profile,
        authority: AUTHORITY,
        executionAuthorized: false,
      })
    );
    return { ok: true, identity: next };
  }

  /** SHA-256 digest helper exposed for observability/test pinning. */
  static profileDigest(profile: AgentCapabilityProfile): string {
    const canonical = JSON.stringify(
      profile,
      Object.keys(profile).sort()
    );
    return createHash("sha256").update(canonical).digest("hex");
  }
}

function deepFreezeProfile(profile: AgentCapabilityProfile): AgentCapabilityProfile {
  return Object.freeze({
    ...profile,
    allowedVerbs: Object.freeze([...profile.allowedVerbs]),
    allowedCapabilities: Object.freeze([...profile.allowedCapabilities]),
  });
}
