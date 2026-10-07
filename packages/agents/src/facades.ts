import type {
  AgentBoundaryResult,
  AgentCapabilityProfile,
  AgentDeliveryRecord,
  AgentEnvelope,
  AgentIdentity,
  AgentMessage,
  AgentMessageKind,
  AgentRegistrationResult,
  AgentRole,
  AgentSendOutcome,
  AgentSendRequest,
} from "./types.js";
import type { AgentRuntime } from "./runtime.js";
import { PLANNER_AGENT_ID, BUILDER_AGENT_ID, REVIEWER_AGENT_ID } from "./types.js";

/**
 * Phase 19A — the three agent facades.
 *
 * IMPORTANT (no-direct-trust invariant): an agent facade holds exactly ONE
 * capability — a reference to the runtime — plus its own frozen identity.
 * It holds NO reference to any other agent, NO inbox of any other agent,
 * and NO authority object of any kind. Every send goes through
 * `runtime.send(...)`, and every read goes through `runtime.inbox(ownId)`.
 * A facade exposes nothing else: no policy engine, no ledger, no executor,
 * no registry mutation surface.
 *
 * Facades are thin, deterministic convenience wrappers over the runtime —
 * they are not trusted just because they exist. Anything an agent "wants"
 * becomes a proposal (message or policy request); the runtime mediates
 * communication and the policy engine decides execution.
 */

/** Base facade shared by all three roles (not exported publicly). */
abstract class BaseAgentFacade {
  readonly #runtime: AgentRuntime;
  readonly #agentId: string;

  protected constructor(runtime: AgentRuntime, agentId: string) {
    if (!runtime.identity(agentId)) {
      throw new Error(
        "AgentFacade requires a registered identity; call runtime.register() for '" +
          agentId +
          "' first"
      );
    }
    this.#runtime = runtime;
    this.#agentId = agentId;
  }

  /** This agent's frozen identity (read-only view). */
  get identity(): AgentIdentity {
    // Non-null: the constructor refuses unregistered ids.
    return this.#runtime.identity(this.#agentId)!;
  }

  get agentId(): string {
    return this.#agentId;
  }

  get role(): AgentRole {
    return this.identity.role;
  }

  /**
   * The verbs this agent may ASK about (advisory scoping data from its
   * capability profile — never a grant; policy remains the authority).
   */
  get allowedVerbs(): readonly string[] {
    return this.identity.profile.allowedVerbs;
  }

  /** The frozen role profile (same data the runtime registered). */
  get profile(): AgentCapabilityProfile {
    return this.identity.profile;
  }

  /**
   * Send a message through the runtime. The runtime may refuse for any
   * mediation reason (routing, bounds, hostile content, caps); the facade
   * adds nothing and bypasses nothing.
   */
  protected sendViaRuntime(request: Omit<AgentSendRequest, "fromAgentId">): AgentSendOutcome {
    return this.#runtime.send({
      ...request,
      fromAgentId: this.#agentId,
    });
  }

  /** Read ONLY this agent's own inbox. No cross-inbox access exists. */
  inbox(): readonly AgentDeliveryRecord[] {
    return this.#runtime.inbox(this.#agentId);
  }

  /**
   * 19C — process this agent's own channel envelope through the receiver
   * boundary. The envelope is UNTRUSTED INPUT: the runtime re-validates
   * addressing, duplication, integrity, provenance, and content before the
   * disposition is returned. Only an envelope addressed to THIS agent can
   * be accepted; an agent cannot run the boundary on someone else's mail.
   */
  receive(envelope: AgentEnvelope): AgentBoundaryResult {
    return this.#runtime.receive(envelope, this.#agentId);
  }

  /**
   * 19C — send on a named channel (runtime still re-validates identity,
   * membership, policy, and content; the facade adds nothing).
   */
  protected sendOnChannelViaRuntime(
    channelId: string,
    request: Omit<AgentSendRequest, "fromAgentId">
  ): { ok: true; envelope: AgentEnvelope } | { ok: false; denyReason: string; reason: string } {
    return this.#runtime.sendOnChannel(channelId, {
      ...request,
      fromAgentId: this.#agentId,
    });
  }
}

/**
 * PlannerAgent — proposes plans. Its outputs are PROPOSALS: a plan proposal
 * message is coordination data for the builder; it can never execute,
 * authorize, or grant. (The DeterministicPlanner in @menog/planner remains
 * the deterministic plan-generation HOW; this facade is the WHO that would
 * carry such proposals in Phase 19B+.)
 */
export class PlannerAgent extends BaseAgentFacade {
  static readonly AGENT_ID = PLANNER_AGENT_ID;

  constructor(runtime: AgentRuntime) {
    super(runtime, PLANNER_AGENT_ID);
  }

  /** Propose a plan to the builder (runtime-mediated, refusable). */
  proposePlan(payloadText: string, summary?: Readonly<Record<string, string | number | boolean>>): AgentSendOutcome {
    return this.sendViaRuntime({ kind: "plan_proposal", toAgentId: BUILDER_AGENT_ID, payloadText, summary });
  }

  /** 19C — send a plan proposal on a planner→builder channel. */
  proposePlanOn(
    channelId: string,
    payloadText: string,
    summary?: Readonly<Record<string, string | number | boolean>>
  ): { ok: true; envelope: import("./types.js").AgentEnvelope } | { ok: false; denyReason: string; reason: string } {
    return this.sendOnChannelViaRuntime(channelId, { kind: "plan_proposal", toAgentId: BUILDER_AGENT_ID, payloadText, summary });
  }

  /** 19C — send a status observation on a channel whose policy allows it. */
  observeStatusOn(
    channelId: string,
    toAgentId: string,
    payloadText: string,
    summary?: Readonly<Record<string, string | number | boolean>>
  ): { ok: true; envelope: import("./types.js").AgentEnvelope } | { ok: false; denyReason: string; reason: string } {
    return this.sendOnChannelViaRuntime(channelId, { kind: "status_observation", toAgentId, payloadText, summary });
  }

  /** Observe status to the reviewer's log surface (runtime-mediated). */
  observeStatus(payloadText: string, summary?: Readonly<Record<string, string | number | boolean>>): AgentSendOutcome {
    return this.sendViaRuntime({ kind: "status_observation", toAgentId: REVIEWER_AGENT_ID, payloadText, summary });
  }

  /** Report an error to the reviewer's log surface (runtime-mediated). */
  reportError(payloadText: string, summary?: Readonly<Record<string, string | number | boolean>>): AgentSendOutcome {
    return this.sendViaRuntime({ kind: "error_report", toAgentId: REVIEWER_AGENT_ID, payloadText, summary });
  }
}

/**
 * BuilderAgent — carries build/execution proposals. Its write needs are
 * DECLARATIONS that the policy engine must independently allow; the facade
 * can never self-authorize and never touches an executor.
 */
export class BuilderAgent extends BaseAgentFacade {
  static readonly AGENT_ID = BUILDER_AGENT_ID;

  constructor(runtime: AgentRuntime) {
    super(runtime, BUILDER_AGENT_ID);
  }

  /** Deliver a build-result summary to the reviewer (runtime-mediated). */
  deliverBuildResult(payloadText: string, summary?: Readonly<Record<string, string | number | boolean>>): AgentSendOutcome {
    return this.sendViaRuntime({ kind: "build_result", toAgentId: REVIEWER_AGENT_ID, payloadText, summary });
  }

  /** 19C — send a build result on a builder→reviewer channel. */
  deliverBuildResultOn(
    channelId: string,
    payloadText: string,
    summary?: Readonly<Record<string, string | number | boolean>>
  ): { ok: true; envelope: AgentEnvelope } | { ok: false; denyReason: string; reason: string } {
    return this.sendOnChannelViaRuntime(channelId, { kind: "build_result", toAgentId: REVIEWER_AGENT_ID, payloadText, summary });
  }

  /** 19C — send a status observation on a channel whose policy allows it. */
  observeStatusOn(
    channelId: string,
    toAgentId: string,
    payloadText: string,
    summary?: Readonly<Record<string, string | number | boolean>>
  ): { ok: true; envelope: AgentEnvelope } | { ok: false; denyReason: string; reason: string } {
    return this.sendOnChannelViaRuntime(channelId, { kind: "status_observation", toAgentId, payloadText, summary });
  }

  /** Observe status to the planner's log surface (runtime-mediated). */
  observeStatus(payloadText: string, summary?: Readonly<Record<string, string | number | boolean>>): AgentSendOutcome {
    return this.sendViaRuntime({ kind: "status_observation", toAgentId: PLANNER_AGENT_ID, payloadText, summary });
  }

  /** Report an error to the planner's log surface (runtime-mediated). */
  reportError(payloadText: string, summary?: Readonly<Record<string, string | number | boolean>>): AgentSendOutcome {
    return this.sendViaRuntime({ kind: "error_report", toAgentId: PLANNER_AGENT_ID, payloadText, summary });
  }
}

/**
 * ReviewerAgent — reviews and issues ADVISORY verdicts. A verdict is data
 * for the planner and for humans; it can never approve a commit, grant a
 * capability, or authorize execution (NO CRITICAL COMMIT WITHOUT APPROVAL
 * stays with the human).
 */
export class ReviewerAgent extends BaseAgentFacade {
  static readonly AGENT_ID = REVIEWER_AGENT_ID;

  constructor(runtime: AgentRuntime) {
    super(runtime, REVIEWER_AGENT_ID);
  }

  /** Issue an advisory verdict to the planner (runtime-mediated). */
  issueVerdict(payloadText: string, summary?: Readonly<Record<string, string | number | boolean>>): AgentSendOutcome {
    return this.sendViaRuntime({ kind: "review_verdict", toAgentId: PLANNER_AGENT_ID, payloadText, summary });
  }

  /** 19C — issue a verdict on a reviewer→planner channel. */
  issueVerdictOn(
    channelId: string,
    payloadText: string,
    summary?: Readonly<Record<string, string | number | boolean>>
  ): { ok: true; envelope: AgentEnvelope } | { ok: false; denyReason: string; reason: string } {
    return this.sendOnChannelViaRuntime(channelId, { kind: "review_verdict", toAgentId: PLANNER_AGENT_ID, payloadText, summary });
  }

  /** 19C — send a status observation on a channel whose policy allows it. */
  observeStatusOn(
    channelId: string,
    toAgentId: string,
    payloadText: string,
    summary?: Readonly<Record<string, string | number | boolean>>
  ): { ok: true; envelope: AgentEnvelope } | { ok: false; denyReason: string; reason: string } {
    return this.sendOnChannelViaRuntime(channelId, { kind: "status_observation", toAgentId, payloadText, summary });
  }

  /** Observe status to the builder's log surface (runtime-mediated). */
  observeStatus(payloadText: string, summary?: Readonly<Record<string, string | number | boolean>>): AgentSendOutcome {
    return this.sendViaRuntime({ kind: "status_observation", toAgentId: BUILDER_AGENT_ID, payloadText, summary });
  }

  /** Report an error to the builder's log surface (runtime-mediated). */
  reportError(payloadText: string, summary?: Readonly<Record<string, string | number | boolean>>): AgentSendOutcome {
    return this.sendViaRuntime({ kind: "error_report", toAgentId: BUILDER_AGENT_ID, payloadText, summary });
  }
}

/** The three facade constructors keyed by pinned agent id (observability). */
export const AGENT_FACADE_CONSTRUCTORS: Readonly<
  Record<string, new (runtime: AgentRuntime) => PlannerAgent | BuilderAgent | ReviewerAgent>
> = Object.freeze({
  [PLANNER_AGENT_ID]: PlannerAgent,
  [BUILDER_AGENT_ID]: BuilderAgent,
  [REVIEWER_AGENT_ID]: ReviewerAgent,
} as Record<string, new (runtime: AgentRuntime) => PlannerAgent | BuilderAgent | ReviewerAgent>);

/** Convenience: register all three identities on a runtime (pinned profiles). */
export function registerAllThreeAgents(
  runtime: AgentRuntime,
  atEpochMs = 0
): { ok: boolean; failures: readonly string[] } {
  const failures: string[] = [];
  for (const [id, role] of [
    [PLANNER_AGENT_ID, "planner"],
    [BUILDER_AGENT_ID, "builder"],
    [REVIEWER_AGENT_ID, "reviewer"],
  ] as const) {
    const r: AgentRegistrationResult = runtime.register({ agentId: id, role, atEpochMs });
    if (!r.ok) failures.push(id + ": " + r.reason);
  }
  return { ok: failures.length === 0, failures };
}

/** Exposed for type-level tests only (kind union re-export). */
export type { AgentMessageKind, AgentMessage, AgentSendRequest, AgentSendOutcome };
