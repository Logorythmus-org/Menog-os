export type ActorType = "human" | "agent" | "runtime" | "tool";

export interface Actor {
  readonly type: ActorType;
  readonly id: string;
}

export type PolicyDecision = "allow" | "deny" | "not_applicable";

export const KNOWN_ACTOR_TYPES: readonly ActorType[] = Object.freeze([
  "human",
  "agent",
  "runtime",
  "tool",
]);

export const KNOWN_POLICY_DECISIONS: readonly PolicyDecision[] = Object.freeze([
  "allow",
  "deny",
  "not_applicable",
]);

export interface MenogEvent {
  readonly eventId: string;
  readonly timestamp: string;
  readonly eventType: string;
  readonly actor: Actor;
  readonly workspaceId?: string;
  readonly taskId?: string;
  readonly verb?: string;
  readonly capability?: string;
  readonly policyDecision?: PolicyDecision;
  readonly inputSummary?: Readonly<Record<string, unknown>>;
  readonly resultSummary?: Readonly<Record<string, unknown>>;
  readonly parentEventId?: string;
  readonly previousHash: string;
  readonly hash: string;
}

export type MenogEventInput = Omit<MenogEvent, "previousHash" | "hash"> & {
  readonly previousHash?: string;
  readonly hash?: never;
};

export type GoalStatus = "pending" | "planning" | "proposed" | "executing" | "done" | "failed" | "rejected";

export const KNOWN_GOAL_STATUSES: readonly GoalStatus[] = Object.freeze([
  "pending",
  "planning",
  "proposed",
  "executing",
  "done",
  "failed",
  "rejected",
]);

export interface GoalBudget {
  readonly maxSteps: number;
  readonly maxRuntimeMs?: number;
  readonly maxSideEffectClass?: SideEffectClassUpperBound;
}

export type SideEffectClassUpperBound = "none" | "read" | "write" | "network" | "system";

export interface Goal {
  readonly goalId: string;
  readonly description: string;
  readonly requestedVerbSequence: readonly string[];
  readonly budget: GoalBudget;
  readonly workspaceId?: string;
  readonly context?: Readonly<Record<string, unknown>>;
  readonly status?: GoalStatus;
}

export interface PlanStep {
  readonly stepIndex: number;
  readonly verbId: string;
  readonly requiredCapabilities: readonly string[];
  readonly sideEffectClass: string;
  readonly description: string;
  readonly replayable: boolean;
  readonly reversible: boolean;
  readonly requiresHumanApproval: readonly boolean[];
  readonly humanApprovalCount: number;
}

export interface Plan {
  readonly planId: string;
  readonly goalId: string;
  readonly steps: readonly PlanStep[];
  readonly totalRequiredCapabilities: readonly string[];
  readonly maxSideEffectClassEncountered: SideEffectClassUpperBound;
  readonly budget: GoalBudget;
  readonly humanApprovalRequiredOverall: boolean;
  readonly createdAt: string;
}

export type PlannerDisposition =
  | "proposed"
  | "unknown_verb_rejected"
  | "budget_exceeded_rejected"
  | "capability_unsupported_rejected"
  | "empty_sequence_rejected";

export interface PlannerProposal {
  readonly disposition: PlannerDisposition;
  readonly plan?: Plan;
  readonly rejectedStepIndex?: number;
  readonly rejectedVerbId?: string;
  readonly reason: string;
  readonly trace: readonly string[];
}

export function isGoalStatus(value: unknown): value is GoalStatus {
  return typeof value === "string" && (KNOWN_GOAL_STATUSES as readonly string[]).includes(value);
}

export function isSideEffectClassUpperBound(value: unknown): value is SideEffectClassUpperBound {
  return (
    value === "none" ||
    value === "read" ||
    value === "write" ||
    value === "network" ||
    value === "system"
  );
}

const SIDE_EFFECT_RANK: Readonly<Record<SideEffectClassUpperBound, number>> = Object.freeze({
  none: 0,
  read: 1,
  write: 2,
  network: 3,
  system: 4,
});

export function sideEffectClassRank(
  value: SideEffectClassUpperBound
): number {
  return SIDE_EFFECT_RANK[value];
}

export function maxSideEffectClass(
  a: SideEffectClassUpperBound,
  b: SideEffectClassUpperBound
): SideEffectClassUpperBound {
  return SIDE_EFFECT_RANK[a] >= SIDE_EFFECT_RANK[b] ? a : b;
}

export type PlanGraphNodeId = string;

export type PlanDependencyKind = "sequential" | "capability" | "dataflow" | "approval";

export interface PlanGraphEdge {
  readonly from: PlanGraphNodeId;
  readonly to: PlanGraphNodeId;
  readonly kind: PlanDependencyKind;
  readonly label?: string;
}

export interface PlanGraphCycle {
  readonly nodeIds: readonly PlanGraphNodeId[];
  readonly entryPoint: PlanGraphNodeId;
}

export type PlanGraphDisposition =
  | "dag_built"
  | "cycle_detected_rejected"
  | "invalid_edge_rejected"
  | "empty_plan_rejected";

export interface PlanGraph {
  readonly graphId: string;
  readonly planId: string;
  readonly goalId: string;
  readonly disposition: PlanGraphDisposition;
  readonly schemaVersion: "menog-plangraph/v0";
  readonly nodeIds: readonly PlanGraphNodeId[];
  readonly nodeStepIndexes: Readonly<Record<PlanGraphNodeId, number>>;
  readonly edges: readonly PlanGraphEdge[];
  readonly adjacency: Readonly<Record<PlanGraphNodeId, readonly PlanGraphNodeId[]>>;
  readonly inDegree: Readonly<Record<PlanGraphNodeId, number>>;
  readonly topologicalOrder: readonly PlanGraphNodeId[];
  readonly cyclesFound: readonly PlanGraphCycle[];
  readonly rejectedEdgeIndex?: number;
  readonly rejectedEdgeReason?: string;
  readonly reason?: string;
  readonly serializedCanonical: string;
  readonly serializedCanonicalHash: string;
}

export type ModelProvider = "local_llama" | "local_onnx" | "test_dummy" | "unspecified" | "ollama" | "llamacpp";

export interface ModelMetadata {
  readonly id: string;
  readonly provider: ModelProvider;
  readonly requireNetwork: boolean;
  readonly contextWindow: number;
}

export type ModelInputRole = "system" | "user" | "model" | "evaluator";

export interface ModelMessage {
  readonly role: ModelInputRole;
  readonly content: string;
}

export interface ModelInput {
  readonly messages: readonly ModelMessage[];
  readonly maxTokens?: number;
  readonly stopSequences?: readonly string[];
  readonly temperature?: number;
}

export type ModelResponseDisposition =
  | "success"
  | "rejected_invalid_input"
  | "rejected_network_required"
  | "rejected_timeout"
  | "rejected_content_filter"
  | "rejected_endpoint_error";

export interface ModelProposal {
  readonly disposition: ModelResponseDisposition;
  readonly text?: string;
  readonly metadata: ModelMetadata;
  readonly serializedMetadata: string;
  readonly reason?: string;
}

export interface ModelAdapter {
  readonly metadata: ModelMetadata;
  propose(input: ModelInput): Promise<ModelProposal>;
}
