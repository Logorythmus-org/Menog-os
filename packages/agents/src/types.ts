/**
 * Phase 19A — Multi-Agent Runtime Foundation (Agent Runtime V0).
 *
 * This package introduces the WHO layer of the Menog taxonomy:
 *
 *   Verb Taxonomy = WHAT      (packages/verbs)
 *   Algorithm     = HOW       (packages/algorithms)
 *   Agent         = WHO       (THIS package)
 *   Skill / Tool  = WITH WHAT (later phase)
 *   Policy        = MAY IT    (packages/policy — still the sole authority)
 *
 * Core invariants of this surface (pinned by tests/security/agents-security.test.ts):
 *
 *   1. AGENT = IDENTITY + ROLE + CAPABILITY PROFILE. An agent can only ask
 *      for what its profile declares. The POLICY ENGINE remains the sole
 *      execution authority — a profile is a proposal, never a grant.
 *   2. NO DIRECT TRUST: agents NEVER hold references to each other. All
 *      communication is routed through the AgentRuntime (runtime-mediated
 *      messages). Sending, receiving, and delivery are runtime decisions.
 *   3. NO AGENT SELF-MODIFICATION WITHOUT REVIEW: agents cannot alter their
 *      own identity, role, or profile; only the runtime can register or
 *      replace profiles, and every such change is a frozen, auditable
 *      profile-change record.
 *   4. MODEL/AGENT OUTPUT IS NEVER EXECUTION AUTHORITY: every message,
 *      delivery decision, and profile record pins authority: "mediation"
 *      and executionAuthorized: false.
 *   5. NO NETWORK, NO SECRETS, NO HIDDEN BACKGROUND EXECUTION: the runtime
 *      is synchronous, in-process, deterministic (modulo injected clocks),
 *      and performs no I/O beyond an optional injected ledger emitter.
 *
 * Relationship to Phase-17 algorithm families: families 4
 * (multiagent_task_allocation) and 9 (agent_communication_routing) remain
 * contract-only recommendation strategies in @menog/algorithms. This
 * package does NOT implement those algorithms — it provides the identity,
 * message, and mediation contracts an allocator/router strategy would
 * later consume. No allocator or router logic ships here.
 */

/** Canonical schema version pinned for the 19A agent runtime surface. */
export const AGENTS_SCHEMA_VERSION = "menog-agents/v0" as const;
export type AgentsSchemaVersion = typeof AGENTS_SCHEMA_VERSION;

/**
 * The three Phase-19A agent roles (closed union). Introducing a fourth role
 * is an unfreeze-protocol event requiring explicit human approval.
 */
export type AgentRole = "planner" | "builder" | "reviewer";

export const KNOWN_AGENT_ROLES: readonly AgentRole[] = Object.freeze([
  "planner",
  "builder",
  "reviewer",
]);

export function isAgentRole(value: unknown): value is AgentRole {
  return (
    typeof value === "string" &&
    (KNOWN_AGENT_ROLES as readonly string[]).includes(value)
  );
}

/**
 * Stable ids of the three Phase-19A agent identities. Ids are opaque
 * strings on the Actor level, but the runtime rejects registration of any
 * OTHER id under these roles (identity binding is pinned).
 */
export const PLANNER_AGENT_ID = "menog-agent-planner" as const;
export const BUILDER_AGENT_ID = "menog-agent-builder" as const;
export const REVIEWER_AGENT_ID = "menog-agent-reviewer" as const;

export const KNOWN_19A_AGENT_IDS: readonly string[] = Object.freeze([
  PLANNER_AGENT_ID,
  BUILDER_AGENT_ID,
  REVIEWER_AGENT_ID,
]);

/** Which authority class a runtime-mediated artifact is. */
export type MediationAuthority = "mediation";

/**
 * A declared, human-reviewed capability profile: the ONLY set of verbs and
 * capabilities an agent identity may ASK the policy engine about. Profiles
 * are declarative, frozen at registration, and never secrets or grants:
 * the deny-by-default policy engine still decides every actual request.
 */
export interface AgentCapabilityProfile {
  /** Verbs the agent may ask about (bounded count and length). */
  readonly allowedVerbs: readonly string[];
  /**
   * Capability ids the agent may place in a policy ask (bounded count).
   * Each entry must be a KNOWN CapabilityId at registration time; unknown
   * entries deny registration with `profile_invalid`.
   */
  readonly allowedCapabilities: readonly string[];
  /**
   * Upper bound the agent may request for a task's side-effect class.
   * Bound in spirit only: policy still denies any request above the day-1
   * allowlist regardless of this ceiling.
   */
  readonly maxSideEffectClass: "none" | "read" | "write" | "network" | "system";
  /** Human-readable description of the role's mandate (bounded). */
  readonly description: string;
}

/**
 * One registered agent identity. Frozen at registration; only the runtime
 * can create records of this type, and only through registration, which
 * validates and freezes every field. Agents cannot mutate their identity.
 */
export interface AgentIdentity {
  readonly agentId: string;
  readonly role: AgentRole;
  readonly schemaVersion: AgentsSchemaVersion;
  readonly registeredAtEpochMs: number;
  readonly profile: AgentCapabilityProfile;
  /** ALWAYS "mediation" — identity records are runtime bookkeeping. */
  readonly authority: MediationAuthority;
  /** ALWAYS false — an identity is not and cannot carry execution authority. */
  readonly executionAuthorized: false;
}

/** A frozen, auditable record of one registration or profile replacement. */
export interface AgentProfileChangeRecord {
  readonly agentId: string;
  readonly role: AgentRole;
  readonly changeKind: "registered" | "profile_replaced";
  readonly atEpochMs: number;
  readonly profile: AgentCapabilityProfile;
  /** ALWAYS "mediation". */
  readonly authority: MediationAuthority;
  /** ALWAYS false. */
  readonly executionAuthorized: false;
}

/** Machine-readable deny reasons for agent registration (fail-closed). */
export type AgentRegistrationDenyReason =
  | "identity_invalid"
  | "identity_mismatch"
  | "unknown_role"
  | "duplicate_identity"
  | "profile_invalid"
  | "oversized_profile";

export interface AgentRegistrationDenial {
  readonly ok: false;
  readonly denyReason: AgentRegistrationDenyReason;
  readonly reason: string;
}

export interface AgentRegistrationSuccess {
  readonly ok: true;
  readonly identity: AgentIdentity;
}

export type AgentRegistrationResult =
  | AgentRegistrationSuccess
  | AgentRegistrationDenial;

// ---------------------------------------------------------------------------
// Runtime-mediated messages.
// ---------------------------------------------------------------------------

/**
 * The message kinds agents may exchange (closed union). Every message is a
 * PROPOSAL or an OBSERVATION — never an instruction to execute. The
 * human/policy/runtime authority chain is unchanged by any message content.
 */
export type AgentMessageKind =
  | "plan_proposal"      // planner → builder: a proposed plan (data)
  | "build_result"       // builder → reviewer: a build outcome summary (data)
  | "review_verdict"     // reviewer → planner: an advisory verdict (data)
  | "status_observation" // any → runtime log: bounded status text (data)
  | "error_report";      // any → runtime log: bounded error text (data)

export const KNOWN_AGENT_MESSAGE_KINDS: readonly AgentMessageKind[] =
  Object.freeze([
    "plan_proposal",
    "build_result",
    "review_verdict",
    "status_observation",
    "error_report",
  ]);

/**
 * Machine-readable deny reasons for message send/deliver (fail-closed).
 * These are MEDIATION denials: they govern communication, not execution;
 * policy denials for actual verbs are a separate, stronger boundary.
 */
export type AgentMessageDenyReason =
  | "sender_unknown"
  | "recipient_unknown"
  | "sender_recipient_same"
  | "message_kind_not_allowed"
  | "oversized_message"
  | "malformed_message"
  | "authority_confusion"
  | "instruction_smuggling";

export const KNOWN_AGENT_MESSAGE_DENY_REASONS: readonly AgentMessageDenyReason[] =
  Object.freeze([
    "sender_unknown",
    "recipient_unknown",
    "sender_recipient_same",
    "message_kind_not_allowed",
    "oversized_message",
    "malformed_message",
    "authority_confusion",
    "instruction_smuggling",
  ]);

export function isAgentMessageDenyReason(
  value: unknown
): value is AgentMessageDenyReason {
  return (
    typeof value === "string" &&
    (KNOWN_AGENT_MESSAGE_DENY_REASONS as readonly string[]).includes(value)
  );
}

/**
 * A runtime-mediated message. Built ONLY by the runtime; callers hand the
 * runtime a send request, the runtime validates, wraps, sequences, and
 * delivers it. Messages carry bounded text payloads — no functions, no
 * capabilities, no policy decisions, no executable content.
 */
export interface AgentMessage {
  readonly messageId: string;
  readonly schemaVersion: AgentsSchemaVersion;
  readonly kind: AgentMessageKind;
  readonly fromAgentId: string;
  readonly toAgentId: string;
  /** Runtime-assigned monotone sequence number (per-runtime, 1-based). */
  readonly sequence: number;
  readonly sentAtEpochMs: number;
  /** Bounded text payload (no derivations, no executable content). */
  readonly payloadText: string;
  /** Bounded structured summary of what the payload proposes/observes. */
  readonly summary: Readonly<Record<string, string | number | boolean>>;
  /** ALWAYS "mediation" — messages are coordination data, never authority. */
  readonly authority: MediationAuthority;
  /** ALWAYS false — a message can never authorize execution. */
  readonly executionAuthorized: false;
}

/** A delivered message as recorded in the recipient's inbox. */
export interface AgentDeliveryRecord {
  readonly messageId: string;
  readonly toAgentId: string;
  readonly deliveredAtEpochMs: number;
  readonly message: AgentMessage;
}

/** Machine-readable record of one refused send (observable, no payload). */
export interface AgentDeliveryDenial {
  readonly ok: false;
  readonly denyReason: AgentMessageDenyReason;
  readonly reason: string;
  /** Bounded kind/summary only — hostile payload text is NEVER echoed. */
  readonly kind: AgentMessageKind | null;
}

/** Who refused a message and why (for the rejection log). */
export type AgentRejectedBy = "runtime";

/** A frozen, bounded record of one refused message. Insert-once. */
export interface AgentRejectedMessageRecord {
  readonly recordId: string;
  readonly rejectedAtEpochMs: number;
  readonly rejectedBy: AgentRejectedBy;
  readonly denyReason: AgentMessageDenyReason;
  readonly fromAgentId: string;
  readonly toAgentId: string;
  readonly kind: AgentMessageKind | null;
  /** SHA-256 digest of the payload text — NEVER the payload itself. */
  readonly payloadDigest: string;
  /** Digest-length bounded summary fields (pre-redaction). */
  readonly summaryDigest: string;
  /** ALWAYS "mediation". */
  readonly authority: MediationAuthority;
  /** ALWAYS false. */
  readonly executionAuthorized: false;
}

/** A send request handed to the runtime by an agent (or its harness). */
export interface AgentSendRequest {
  readonly kind: AgentMessageKind;
  readonly fromAgentId: string;
  readonly toAgentId: string;
  readonly payloadText: string;
  readonly summary?: Readonly<Record<string, string | number | boolean>>;
}

export type AgentSendOutcome =
  | { readonly ok: true; readonly message: AgentMessage }
  | AgentDeliveryDenial;

// ---------------------------------------------------------------------------
// Message routing contract — who may send which kind to whom (closed map).
// PlannerAgent → BuilderAgent → ReviewerAgent → PlannerAgent. Runtime log
// kinds (status_observation / error_report) may flow from any agent to the
// runtime log, expressed here as any-role → any-role (validated further by
// the runtime's log delivery rules).
// ---------------------------------------------------------------------------

export interface RoutingRule {
  readonly fromRole: AgentRole;
  readonly toRole: AgentRole;
  readonly kinds: readonly AgentMessageKind[];
}

export const AGENT_ROUTING_RULES: readonly RoutingRule[] = Object.freeze([
  Object.freeze({
    fromRole: "planner",
    toRole: "builder",
    kinds: Object.freeze<AgentMessageKind[]>(["plan_proposal", "status_observation", "error_report"]),
  }),
  Object.freeze({
    fromRole: "builder",
    toRole: "reviewer",
    kinds: Object.freeze<AgentMessageKind[]>(["build_result", "status_observation", "error_report"]),
  }),
  Object.freeze({
    fromRole: "reviewer",
    toRole: "planner",
    kinds: Object.freeze<AgentMessageKind[]>(["review_verdict", "status_observation", "error_report"]),
  }),
  // Log-style observations/errors are also deliverable to the runtime log
  // (represented as routing to ANY other agent's log surface; the runtime
  // treats these as log records, not inbox messages).
  Object.freeze({
    fromRole: "planner",
    toRole: "reviewer",
    kinds: Object.freeze<AgentMessageKind[]>(["status_observation", "error_report"]),
  }),
  Object.freeze({
    fromRole: "builder",
    toRole: "planner",
    kinds: Object.freeze<AgentMessageKind[]>(["status_observation", "error_report"]),
  }),
  Object.freeze({
    fromRole: "reviewer",
    toRole: "builder",
    kinds: Object.freeze<AgentMessageKind[]>(["status_observation", "error_report"]),
  }),
]);

// ---------------------------------------------------------------------------
// Bounded-surface caps (mirror the 17A/18A bounding discipline).
// ---------------------------------------------------------------------------

export const AGENTS_MAX_PAYLOAD_CHARS = 1024;
export const AGENTS_MAX_SUMMARY_FIELDS = 16;
export const AGENTS_MAX_SUMMARY_VALUE_CHARS = 128;
export const AGENTS_MAX_INBOX = 256;
export const AGENTS_MAX_MESSAGES = 1024;
export const AGENTS_MAX_REJECTIONS = 512;
export const AGENTS_MAX_PROFILE_VERBS = 16;
export const AGENTS_MAX_PROFILE_CAPABILITIES = 16;
export const AGENTS_MAX_PROFILE_DESCRIPTION_CHARS = 256;
export const AGENTS_MAX_AGENTS = 8;
export const AGENTS_MAX_LOG = 256;

// ---------------------------------------------------------------------------
// Phase 19B — bounded-surface caps for baseline task allocation.
// ---------------------------------------------------------------------------

export const AGENTS_MAX_ALLOCATIONS = 128;
export const AGENTS_MAX_TASKS = 128;
export const AGENTS_MAX_ASSIGNMENTS_PER_AGENT = 8;
export const AGENTS_MAX_TASK_LABEL_CHARS = 128;
export const AGENTS_MAX_TASK_NOTE_CHARS = 256;
export const AGENTS_REQUIRED_CAPABILITY_CAP = 8;
export const AGENTS_RISK_SCORE_STEP = 0.1;
export const AGENTS_MAX_STATUS_EVENTS = 16;

// ---------------------------------------------------------------------------
// Phase 19C — bounded-surface caps for envelopes, channels, and provenance.
// ---------------------------------------------------------------------------

/** Maximum number of concurrently open channels per runtime. */
export const AGENTS_MAX_CHANNELS = 16;
/** Maximum participants per channel. */
export const AGENTS_MAX_CHANNEL_PARTICIPANTS = 3;
/** Maximum delivered messages retained per channel. */
export const AGENTS_MAX_CHANNEL_HISTORY = 128;
/** Maximum quarantine records retained per runtime. */
export const AGENTS_MAX_QUARANTINE = 256;
/** Maximum provenance fields retained per envelope. */
export const AGENTS_MAX_PROVENANCE_FIELDS = 16;
/** Maximum chars per provenance field value. */
export const AGENTS_MAX_PROVENANCE_VALUE_CHARS = 128;
/** Maximum receiver processing records retained per runtime. */
export const AGENTS_MAX_RECEIPTS = 512;

// ---------------------------------------------------------------------------
// Phase 19E — bounded-surface caps for recovery/reassignment.
// ---------------------------------------------------------------------------

/** Maximum recovery records retained per coordinator (append-only log). */
export const AGENTS_MAX_RECOVERIES = 256;
/** Maximum recovery chain depth per task (reassignment bound). */
export const AGENTS_MAX_RECOVERY_CHAIN = 3;
/** Failures at/above this count derive a suspension view for the agent. */
export const AGENTS_SUSPENSION_FAILURE_THRESHOLD = 3;
/** Maximum failure-report note chars. */
export const AGENTS_MAX_FAILURE_NOTE_CHARS = 256;

/**
 * The three message channel kinds (closed union). A channel is a named,
 * policy-scoped communication route between explicitly listed participants;
 * it is bookkeeping, not authority.
 */
export type AgentChannelKind = "planner_builder" | "builder_reviewer" | "reviewer_planner";

export const KNOWN_AGENT_CHANNEL_KINDS: readonly AgentChannelKind[] =
  Object.freeze(["planner_builder", "builder_reviewer", "reviewer_planner"]);

/** Channel state (closed union): open channels are the only routable ones. */
export type AgentChannelState = "open" | "closed";

export const KNOWN_AGENT_CHANNEL_STATES: readonly AgentChannelState[] =
  Object.freeze(["open", "closed"]);

/**
 * Routing policy for one channel (frozen at open time). Every rule is
 * validated against the closed AGENT_ROUTING_RULES map — a channel cannot
 * open a route the mediation layer forbids.
 */
export interface AgentChannelPolicy {
  readonly kind: AgentChannelKind;
  readonly fromRole: "planner" | "builder" | "reviewer";
  readonly toRole: "planner" | "builder" | "reviewer";
  /** Message kinds this channel carries (subset of the closed kind union). */
  readonly allowedKinds: readonly AgentMessageKind[];
  /** Per-message payload cap for this channel (≤ AGENTS_MAX_PAYLOAD_CHARS). */
  readonly maxPayloadChars: number;
  /** Whether out-of-policy messages on this channel quarantine or drop. */
  readonly onViolation: "quarantine" | "drop";
}

/** An opened channel (frozen identity + policy; participants pinned). */
export interface AgentChannel {
  readonly channelId: string;
  readonly state: AgentChannelState;
  readonly policy: AgentChannelPolicy;
  readonly participants: readonly string[];
  readonly openedAtEpochMs: number;
  readonly openedBy: string;
  /** ALWAYS "mediation" — channels are bookkeeping, never authority. */
  readonly authority: MediationAuthority;
  /** ALWAYS false. */
  readonly executionAuthorized: false;
}

/** Machine-readable deny reasons for channel open/route (fail-closed). */
export type AgentChannelDenyReason =
  | "channel_unknown"
  | "channel_closed"
  | "policy_invalid"
  | "participants_invalid"
  | "route_not_allowed"
  | "channel_cap_reached";

export const KNOWN_AGENT_CHANNEL_DENY_REASONS: readonly AgentChannelDenyReason[] =
  Object.freeze([
    "channel_unknown",
    "channel_closed",
    "policy_invalid",
    "participants_invalid",
    "route_not_allowed",
    "channel_cap_reached",
  ]);

/**
 * A delivered message ENVELOPE: the runtime-stamped wrapper around a
 * mediated message. The envelope carries the routing identity, the
 * untrusted-input marker, and the immutable provenance chain. Receivers
 * consume envelopes; raw payloads are untrusted input at their boundary.
 */
export interface AgentEnvelope {
  readonly envelopeId: string;
  readonly schemaVersion: AgentsSchemaVersion;
  readonly channelId: string;
  readonly channelKind: AgentChannelKind;
  readonly message: AgentMessage;
  /** Sender identity id (re-stamped by the runtime; never caller-claimed). */
  readonly senderId: string;
  /** Receiver identity id. */
  readonly receiverId: string;
  /** Runtime-stamped delivery sequence on this channel (1-based). */
  readonly channelSequence: number;
  /** Provenance chain (origin + mediation + delivery stamps). */
  readonly provenance: readonly AgentProvenanceEntry[];
  /** ALWAYS true — receiver must treat envelope payload as untrusted. */
  readonly untrusted: true;
  /** ALWAYS "mediation". */
  readonly authority: MediationAuthority;
  /** ALWAYS false. */
  readonly executionAuthorized: false;
}

/** One immutable provenance stamp (who/what/when/where in the chain). */
export interface AgentProvenanceEntry {
  readonly stage: "origin" | "mediation" | "delivery";
  readonly actorId: string;
  readonly actorType: string;
  readonly atEpochMs: number;
  /** Bounded structured detail (e.g. messageId, channelId, sequence). */
  readonly detail: Readonly<Record<string, string | number | boolean>>;
}

/** Machine-readable deny reasons at the RECEIVER boundary (fail-closed). */
export type AgentBoundaryDenyReason =
  | "receiver_unknown"
  | "not_addressed_to_receiver"
  | "duplicate_envelope"
  | "envelope_malformed"
  | "provenance_broken"
  | "content_refused";

export const KNOWN_AGENT_BOUNDARY_DENY_REASONS: readonly AgentBoundaryDenyReason[] =
  Object.freeze([
    "receiver_unknown",
    "not_addressed_to_receiver",
    "duplicate_envelope",
    "envelope_malformed",
    "provenance_broken",
    "content_refused",
  ]);

/** How the receiver boundary disposed of one envelope (closed union). */
export type AgentBoundaryDisposition =
  | "accepted"
  | "refused"
  | "quarantined";

export const KNOWN_AGENT_BOUNDARY_DISPOSITIONS: readonly AgentBoundaryDisposition[] =
  Object.freeze(["accepted", "refused", "quarantined"]);

/** A quarantine record: a refused envelope retained for human audit. */
export interface AgentQuarantineRecord {
  readonly quarantineId: string;
  readonly atEpochMs: number;
  readonly envelopeId: string;
  readonly channelId: string;
  readonly senderId: string;
  readonly receiverId: string;
  readonly denyReason: AgentBoundaryDenyReason;
  /** SHA-256 of the payload — NEVER the payload text itself. */
  readonly payloadDigest: string;
  /** Provenance chain snapshot (bounded). */
  readonly provenance: readonly AgentProvenanceEntry[];
  /** ALWAYS "mediation". */
  readonly authority: MediationAuthority;
  /** ALWAYS false. */
  readonly executionAuthorized: false;
}

/** The receiver-boundary outcome for one envelope (observable receipt). */
export interface AgentBoundaryReceipt {
  readonly receiptId: string;
  readonly envelopeId: string;
  readonly receiverId: string;
  readonly disposition: AgentBoundaryDisposition;
  readonly denyReason: AgentBoundaryDenyReason | null;
  readonly atEpochMs: number;
  /** ALWAYS "mediation". */
  readonly authority: MediationAuthority;
  /** ALWAYS false. */
  readonly executionAuthorized: false;
}

export type AgentBoundaryResult =
  | { readonly ok: true; readonly receipt: AgentBoundaryReceipt }
  | { readonly ok: false; readonly denyReason: AgentBoundaryDenyReason; readonly reason: string };
