import type { SideEffectClass } from "@menog/shared";
import type { CapabilityId, RiskClass } from "./capabilities.js";
import type { Actor } from "@menog/core";

export type PolicyOutcome = "allow" | "deny";

export interface PolicyDecisionRecord {
  readonly outcome: PolicyOutcome;
  readonly reason: string;
  readonly matchedRule: string;
  readonly riskClass: RiskClass;
  readonly requiresHumanApproval: boolean;
}

export interface PolicyRequest {
  readonly requestId?: string;
  readonly actor: Actor;
  readonly verb: string;
  readonly requestedCapabilities: readonly CapabilityId[];
  readonly expectedSideEffectClass?: SideEffectClass;
  readonly workspaceId?: string;
  readonly taskId?: string;
  readonly commandHint?: string;
}

export interface PolicyResult {
  readonly decision: PolicyDecisionRecord;
  readonly perCapability: Readonly<Record<CapabilityId, PolicyDecisionRecord>>;
  readonly allowedCapabilities: readonly CapabilityId[];
  readonly deniedCapabilities: readonly CapabilityId[];
  readonly at: string;
}

export interface PolicyEngine {
  evaluate(request: PolicyRequest): PolicyResult;
}
