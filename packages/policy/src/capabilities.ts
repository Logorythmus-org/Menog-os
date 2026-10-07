import type { SideEffectClass } from "@menog/shared";

export type CapabilityId =
  | "workspace:list"
  | "workspace:read-metadata"
  | "workspace:read"
  | "workspace:write"
  | "workspace:read-file"
  | "workspace:search"
  | "git:status"
  | "git:diff-read"
  | "git:commit"
  | "git:recover"
  | "plan:generate"
  | "process:spawn"
  | "process:execute-readonly"
  | "process:execute-write"
  | "network:external"
  | "process:privileged";

export const CAPABILITY_IDS: readonly CapabilityId[] = Object.freeze([
  "workspace:list",
  "workspace:read-metadata",
  "workspace:read",
  "workspace:write",
  "workspace:read-file",
  "workspace:search",
  "git:status",
  "git:diff-read",
  "git:commit",
  "git:recover",
  "plan:generate",
  "process:spawn",
  "process:execute-readonly",
  "process:execute-write",
  "network:external",
  "process:privileged",
]);

export type RiskClass =
  | "none"
  | "low"
  | "medium"
  | "high"
  | "critical";

export const RISK_CLASSES: readonly RiskClass[] = Object.freeze([
  "none",
  "low",
  "medium",
  "high",
  "critical",
]);

export function isCapabilityId(value: unknown): value is CapabilityId {
  return typeof value === "string" && (CAPABILITY_IDS as readonly string[]).includes(value);
}

export function isRiskClass(value: unknown): value is RiskClass {
  return typeof value === "string" && (RISK_CLASSES as readonly string[]).includes(value);
}

export type CapabilityEffect = {
  readonly sideEffectClass: SideEffectClass;
  readonly riskClass: RiskClass;
  readonly requiresHumanApproval: boolean;
};

export const CAPABILITY_EFFECT_TABLE: Readonly<Record<CapabilityId, CapabilityEffect>> = Object.freeze({
  "workspace:list":           { sideEffectClass: "read",     riskClass: "none",     requiresHumanApproval: false },
  "workspace:read-metadata":  { sideEffectClass: "read",     riskClass: "low",      requiresHumanApproval: false },
  "workspace:read":           { sideEffectClass: "read",     riskClass: "low",      requiresHumanApproval: false },
  "workspace:write":          { sideEffectClass: "write",    riskClass: "high",     requiresHumanApproval: true  },
  "workspace:read-file":      { sideEffectClass: "read",     riskClass: "low",      requiresHumanApproval: false },
  "workspace:search":         { sideEffectClass: "read",     riskClass: "low",      requiresHumanApproval: false },
  "git:status":               { sideEffectClass: "read",     riskClass: "none",     requiresHumanApproval: false },
  "git:diff-read":            { sideEffectClass: "read",     riskClass: "low",      requiresHumanApproval: false },
  "git:commit":               { sideEffectClass: "write",    riskClass: "critical", requiresHumanApproval: true  },
  "git:recover":              { sideEffectClass: "write",    riskClass: "high",     requiresHumanApproval: true  },
  "plan:generate":            { sideEffectClass: "none",     riskClass: "none",     requiresHumanApproval: false },
  "process:spawn":            { sideEffectClass: "system",   riskClass: "medium",   requiresHumanApproval: false },
  "process:execute-readonly": { sideEffectClass: "system",   riskClass: "medium",   requiresHumanApproval: false },
  "process:execute-write":    { sideEffectClass: "system",   riskClass: "high",     requiresHumanApproval: true  },
  "network:external":         { sideEffectClass: "network",  riskClass: "critical", requiresHumanApproval: true  },
  "process:privileged":       { sideEffectClass: "system",   riskClass: "critical", requiresHumanApproval: true  },
});

export function sideEffectClassFor(cap: CapabilityId): SideEffectClass {
  return CAPABILITY_EFFECT_TABLE[cap].sideEffectClass;
}

export function riskClassFor(cap: CapabilityId): RiskClass {
  return CAPABILITY_EFFECT_TABLE[cap].riskClass;
}

export function requiresHumanApprovalFor(cap: CapabilityId): boolean {
  return CAPABILITY_EFFECT_TABLE[cap].requiresHumanApproval;
}

export type Day1InspectCapabilities =
  | "workspace:list"
  | "workspace:read-metadata"
  | "git:status"
  | "git:diff-read";

export const DAY1_INSPECT_CAPABILITIES: readonly Day1InspectCapabilities[] = Object.freeze([
  "workspace:list",
  "workspace:read-metadata",
  "git:status",
  "git:diff-read",
]);

export const DAY1_FORBIDDEN_CAPABILITIES: readonly CapabilityId[] = Object.freeze([
  "workspace:write",
  "git:commit",
  "process:execute-write",
  "network:external",
  "process:privileged",
]);
