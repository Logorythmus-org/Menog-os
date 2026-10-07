export {
  AGENTS_SCHEMA_VERSION,
  KNOWN_AGENT_ROLES,
  KNOWN_19A_AGENT_IDS,
  PLANNER_AGENT_ID,
  BUILDER_AGENT_ID,
  REVIEWER_AGENT_ID,
  AGENT_ROUTING_RULES,
  KNOWN_AGENT_MESSAGE_KINDS,
  KNOWN_AGENT_MESSAGE_DENY_REASONS,
  isAgentRole,
  isAgentMessageDenyReason,
  AGENTS_MAX_PAYLOAD_CHARS,
  AGENTS_MAX_SUMMARY_FIELDS,
  AGENTS_MAX_SUMMARY_VALUE_CHARS,
  AGENTS_MAX_INBOX,
  AGENTS_MAX_MESSAGES,
  AGENTS_MAX_REJECTIONS,
  AGENTS_MAX_PROFILE_VERBS,
  AGENTS_MAX_PROFILE_CAPABILITIES,
  AGENTS_MAX_PROFILE_DESCRIPTION_CHARS,
  AGENTS_MAX_AGENTS,
  AGENTS_MAX_LOG,
  type AgentsSchemaVersion,
  type AgentRole,
  type MediationAuthority,
  type AgentCapabilityProfile,
  type AgentIdentity,
  type AgentProfileChangeRecord,
  type AgentRegistrationDenyReason,
  type AgentRegistrationDenial,
  type AgentRegistrationSuccess,
  type AgentRegistrationResult,
  type AgentMessageKind,
  type AgentMessageDenyReason,
  type AgentMessage,
  type AgentDeliveryRecord,
  type AgentDeliveryDenial,
  type AgentRejectedBy,
  type AgentRejectedMessageRecord,
  type AgentSendRequest,
  type AgentSendOutcome,
  type RoutingRule,
} from "./types.js";

export {
  AGENT_ROLE_PROFILES,
  AgentIdentityRegistry,
  validateAgentProfile,
  type RegisterAgentInput,
} from "./identity.js";

export {
  AGENT_HOSTILE_TEXT_PATTERNS,
  KNOWN_AGENT_HOSTILE_PATTERNS,
  scanAgentText,
  scanSummaryValue,
  screenAgentSendRequest,
  isKnownMessageKind,
  routingAllows,
  validateSendRequestShape,
  agentPayloadDigest,
  type AgentHostilePattern,
  type AgentScreeningFinding,
} from "./messages.js";

export {
  AgentRuntime,
  type AgentLedgerEmitter,
  type AgentRuntimeOptions,
} from "./runtime.js";

export {
  PlannerAgent,
  BuilderAgent,
  ReviewerAgent,
  AGENT_FACADE_CONSTRUCTORS,
  registerAllThreeAgents,
} from "./facades.js";

// ---------------------------------------------------------------------------
// Phase 19B — Baseline Task Allocation.
// ---------------------------------------------------------------------------
export {
  ALLOCATION_SCHEMA_VERSION,
  KNOWN_ALLOCATION_DENY_REASONS,
  KNOWN_UNAVAILABLE_REASONS,
  isAllocationDenyReason,
  type AllocationSchemaVersion,
  type AllocationAuthority,
  type AllocationDenyReason,
  type AllocationDenial,
  type AgentUnavailableReason,
  type TaskBudget,
  type TaskDescriptor,
  type AgentAvailability,
  type AllocationCandidate,
  type TaskAssignment,
  type AllocationRecord,
  type AllocationStatusEvent,
  type ActiveAllocationView,
  type AllocationResult,
} from "./allocationTypes.js";
export {
  AGENTS_MAX_ALLOCATIONS,
  AGENTS_MAX_TASKS,
  AGENTS_MAX_ASSIGNMENTS_PER_AGENT,
  AGENTS_MAX_TASK_LABEL_CHARS,
  AGENTS_MAX_TASK_NOTE_CHARS,
  AGENTS_REQUIRED_CAPABILITY_CAP,
  AGENTS_RISK_SCORE_STEP,
  AGENTS_MAX_STATUS_EVENTS,
} from "./types.js";

export {
  TaskAllocator,
  validateTaskDescriptor,
  validateAvailability,
  taskDescriptorDigest,
  type AllocateInput,
} from "./allocation.js";

// ---------------------------------------------------------------------------
// Phase 19C — Message Envelopes, Channels, Receiver Boundary.
// ---------------------------------------------------------------------------
export {
  KNOWN_AGENT_CHANNEL_KINDS,
  KNOWN_AGENT_CHANNEL_STATES,
  KNOWN_AGENT_CHANNEL_DENY_REASONS,
  KNOWN_AGENT_BOUNDARY_DENY_REASONS,
  KNOWN_AGENT_BOUNDARY_DISPOSITIONS,
  AGENTS_MAX_CHANNELS,
  AGENTS_MAX_CHANNEL_PARTICIPANTS,
  AGENTS_MAX_CHANNEL_HISTORY,
  AGENTS_MAX_QUARANTINE,
  AGENTS_MAX_PROVENANCE_FIELDS,
  AGENTS_MAX_PROVENANCE_VALUE_CHARS,
  AGENTS_MAX_RECEIPTS,
  type AgentChannelKind,
  type AgentChannelState,
  type AgentChannelPolicy,
  type AgentChannel,
  type AgentChannelDenyReason,
  type AgentEnvelope,
  type AgentProvenanceEntry,
  type AgentBoundaryDenyReason,
  type AgentBoundaryDisposition,
  type AgentQuarantineRecord,
  type AgentBoundaryReceipt,
  type AgentBoundaryResult,
} from "./types.js";

export {
  validateChannelPolicy,
  channelPolicyAllows,
  validateProvenanceChain,
  validateEnvelopeIntegrity,
  decideBoundary,
  envelopePayloadDigest,
  buildQuarantineRecord,
  type BoundaryCheckInput,
} from "./envelope.js";

// ---------------------------------------------------------------------------
// Phase 19E — Bounded Recovery & Reassignment.
// ---------------------------------------------------------------------------
export {
  RECOVERY_SCHEMA_VERSION,
  KNOWN_AGENT_FAILURE_KINDS,
  KNOWN_RECOVERY_DENY_REASONS,
  isRecoveryDenyReason,
  type RecoverySchemaVersion,
  type RecoveryAuthority,
  type AgentFailureKind,
  type AgentFailureReport,
  type AgentRecoveryRecord,
  type AgentSuspensionView,
  type StaleOwnershipPolicy,
  type StaleOwnershipView,
  type ReassignInput,
  type ReassignmentResult,
  type RecoveryResult,
  type RecoveryDenyReason,
} from "./recoveryTypes.js";
export {
  AGENTS_MAX_RECOVERIES,
  AGENTS_MAX_RECOVERY_CHAIN,
  AGENTS_SUSPENSION_FAILURE_THRESHOLD,
  AGENTS_MAX_FAILURE_NOTE_CHARS,
} from "./types.js";

export {
  RecoveryCoordinator,
  validateFailureReport,
  validateStaleOwnershipPolicy,
} from "./recovery.js";
