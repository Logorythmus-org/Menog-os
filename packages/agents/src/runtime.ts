import type {
  AgentBoundaryDisposition,
  AgentBoundaryReceipt,
  AgentBoundaryResult,
  AgentChannel,
  AgentChannelPolicy,
  AgentDeliveryDenial,
  AgentDeliveryRecord,
  AgentEnvelope,
  AgentIdentity,
  AgentMessage,
  AgentMessageDenyReason,
  AgentProfileChangeRecord,
  AgentProvenanceEntry,
  AgentQuarantineRecord,
  AgentRegistrationResult,
  AgentRejectedMessageRecord,
  AgentRole,
  AgentSendOutcome,
  AgentSendRequest,
  MediationAuthority,
} from "./types.js";
import {
  AGENTS_MAX_CHANNELS,
  AGENTS_MAX_CHANNEL_PARTICIPANTS,
  AGENTS_MAX_QUARANTINE,
  AGENTS_MAX_RECEIPTS,
  AGENTS_MAX_STATUS_EVENTS,
} from "./types.js";
import {
  buildQuarantineRecord,
  channelPolicyAllows,
  decideBoundary,
  validateChannelPolicy,
  type BoundaryCheckInput,
} from "./envelope.js";
import type {
  ActiveAllocationView,
  AllocationCandidate,
  AllocationRecord,
  AllocationStatusEvent,
} from "./allocationTypes.js";
import {
  AGENTS_MAX_INBOX,
  AGENTS_MAX_LOG,
  AGENTS_MAX_MESSAGES,
  AGENTS_MAX_REJECTIONS,
  isAgentMessageDenyReason,
} from "./types.js";
import {
  agentPayloadDigest,
  isKnownMessageKind,
  routingAllows,
  screenAgentSendRequest,
  validateSendRequestShape,
} from "./messages.js";
import {
  AgentIdentityRegistry,
  type RegisterAgentInput,
} from "./identity.js";

/**
 * Phase 19A — the runtime-mediated multi-agent foundation.
 *
 * The AgentRuntime is the ONLY communication surface between agents:
 *
 *   PlannerAgent ──plan_proposal──▶ Runtime ──▶ BuilderAgent
 *   BuilderAgent ──build_result───▶ Runtime ──▶ ReviewerAgent
 *   ReviewerAgent ─review_verdict─▶ Runtime ──▶ PlannerAgent
 *
 * Agents hold NO references to other agents; they cannot read each other's
 * inboxes; they cannot discover recipients they did not explicitly name;
 * and they can never emit a message that the routing map refuses. Every
 * delivered message carries `authority: "mediation"` and
 * `executionAuthorized: false` — a message is coordination data for the
 * receiving agent's next PROPOSAL, never an instruction the runtime or
 * policy must obey.
 *
 * The runtime performs no network I/O, spawns no processes, and keeps no
 * background work: every effect is synchronous and driven by an explicit
 * call from the owning harness.
 */

const AUTHORITY: MediationAuthority = "mediation";

/** Optional, structural ledger emitter (mirrors policy/algorithm emitters). */
export interface AgentLedgerEmitter {
  readonly append: (input: {
    readonly eventType: string;
    readonly policyDecision: "allow" | "deny" | "not_applicable";
    readonly actor: { readonly type: string; readonly id: string };
    readonly workspaceId?: string;
    readonly taskId?: string;
    readonly inputSummary: Readonly<Record<string, unknown>>;
    readonly resultSummary: Readonly<Record<string, unknown>>;
  }) => { readonly ok: boolean; readonly eventId?: string };
}

export interface AgentRuntimeOptions {
  /** Explicit, caller-owned epoch-ms clock (deterministic tests). */
  readonly nowEpochMs?: () => number;
  /** Optional ledger emitter for observable mediation decisions. */
  readonly ledger?: AgentLedgerEmitter;
  /** Optional workspace/task correlation for emitted events. */
  readonly workspaceId?: string;
  readonly taskId?: string;
}

export class AgentRuntime {
  readonly #registry = new AgentIdentityRegistry();
  readonly #inboxes = new Map<string, AgentDeliveryRecord[]>();
  readonly #messages: AgentMessage[] = [];
  readonly #rejections: AgentRejectedMessageRecord[] = [];
  readonly #allocationHistory: AllocationRecord[] = [];
  readonly #allocationStatus = new Map<string, AllocationStatusEvent[]>();
  #allocationSequence = 0;
  // 19C: channels, envelopes, receipts, quarantine.
  readonly #channels = new Map<string, AgentChannel>();
  readonly #channelEnvelopes = new Map<string, AgentEnvelope[]>();
  readonly #channelSequences = new Map<string, number>();
  readonly #deliveredEnvelopeIds = new Set<string>();
  readonly #receipts: AgentBoundaryReceipt[] = [];
  readonly #quarantine: AgentQuarantineRecord[] = [];
  #envelopeSequence = 0;
  readonly #now: () => number;
  readonly #ledger: AgentLedgerEmitter | null;
  readonly #workspaceId?: string;
  readonly #taskId?: string;
  #sequence = 0;

  constructor(options: AgentRuntimeOptions = {}) {
    this.#now = options.nowEpochMs ?? (() => Date.now());
    this.#ledger = options.ledger ?? null;
    this.#workspaceId = options.workspaceId;
    this.#taskId = options.taskId;
  }

  // -- Identity / profiles -------------------------------------------------

  /** Register the three 19A identities (idempotence denied explicitly). */
  register(input: RegisterAgentInput): AgentRegistrationResult {
    const r = this.#registry.register(input);
    if (r.ok) {
      this.#emit(
        "agent_registered",
        { type: "runtime", id: "agent-runtime" },
        {
          agentId: r.identity.agentId,
          role: r.identity.role,
          registeredAtEpochMs: r.identity.registeredAtEpochMs,
        },
        { outcome: "registered", agentId: r.identity.agentId, role: r.identity.role }
      );
    }
    return r;
  }

  /**
   * Replace an agent's capability profile (runtime-owned reviewed channel).
   * Denials are machine-readable; every success is recorded as a
   * profile_replaced change record.
   */
  replaceProfile(
    agentId: string,
    profile: import("./types.js").AgentCapabilityProfile,
    atEpochMs?: number
  ): AgentRegistrationResult {
    const r = this.#registry.replaceProfile(agentId, profile, atEpochMs ?? this.#now());
    if (r.ok) {
      this.#emit(
        "agent_profile_replaced",
        { type: "runtime", id: "agent-runtime" },
        {
          agentId,
          role: r.identity.role,
          atEpochMs: atEpochMs ?? this.#now(),
        },
        { outcome: "profile_replaced", agentId }
      );
    }
    return r;
  }

  identity(agentId: string): AgentIdentity | null {
    return this.#registry.get(agentId);
  }

  identities(): readonly AgentIdentity[] {
    return Object.freeze(
      this.#registry
        .ids()
        .map((id) => this.#registry.get(id))
        .filter((x): x is AgentIdentity => x !== null)
    );
  }

  profileChanges(): readonly AgentProfileChangeRecord[] {
    return this.#registry.changes();
  }

  roleOf(agentId: string): AgentRole | null {
    return this.#registry.roleOf(agentId);
  }

  /** The verbs an agent may ASK about (advisory scoping data only). */
  allowedVerbsOf(agentId: string): readonly string[] | null {
    return this.#registry.get(agentId)?.profile.allowedVerbs ?? null;
  }

  // -- Mediated messaging --------------------------------------------------

  /**
   * Send a message THROUGH the runtime. Validation order (fail-closed):
   * shape/bounds → identity existence → routing rules → hostile screening
   * → caps. On success the runtime wraps, sequences, freezes, delivers, and
   * records; on refusal the payload is digested, never echoed.
   */
  send(request: AgentSendRequest): AgentSendOutcome {
    const now = this.#now();

    const shape = validateSendRequestShape(request);
    if (!shape.ok) {
      return this.#refuse(request, shape.denyReason, shape.reason, now);
    }

    const sender = this.#registry.get(request.fromAgentId);
    if (!sender) {
      return this.#refuse(
        request,
        "sender_unknown",
        "fromAgentId '" + request.fromAgentId + "' is not a registered identity",
        now
      );
    }
    const recipient = this.#registry.get(request.toAgentId);
    if (!recipient) {
      return this.#refuse(
        request,
        "recipient_unknown",
        "toAgentId '" + request.toAgentId + "' is not a registered identity",
        now
      );
    }
    if (request.fromAgentId === request.toAgentId) {
      return this.#refuse(
        request,
        "sender_recipient_same",
        "self-addressed messages are refused (no self-channels)",
        now
      );
    }

    const routingOk = routingAllows(sender.role, recipient.role, request.kind);
    if (!routingOk) {
      return this.#refuse(
        request,
        "message_kind_not_allowed",
        "routing map refuses kind '" +
          request.kind +
          "' from role '" +
          sender.role +
          "' to role '" +
          recipient.role +
          "'",
        now
      );
    }

    const screen = screenAgentSendRequest(request);
    if (!screen.ok) {
      // Authority-claim patterns deny as authority_confusion (the message
      // tries to carry decision authority); all other hostile patterns deny
      // as instruction_smuggling (the message carries hostile directives).
      const authorityPattern =
        screen.finding.pattern === "authority_claim" ||
        screen.finding.pattern === "execution_claim" ||
        screen.finding.pattern === "policy_override_directive";
      return this.#refuse(
        request,
        authorityPattern ? "authority_confusion" : "instruction_smuggling",
        "hostile pattern '" +
          screen.finding.pattern +
          "' detected in message " +
          screen.finding.location +
          (screen.finding.key ? " field '" + screen.finding.key + "'" : ""),
        now
      );
    }

    if (this.#messages.length >= AGENTS_MAX_MESSAGES) {
      return this.#refuse(
        request,
        "oversized_message",
        "message cap reached (" + String(AGENTS_MAX_MESSAGES) + " in flight); send refused",
        now
      );
    }
    if ((this.#inboxes.get(request.toAgentId)?.length ?? 0) >= AGENTS_MAX_INBOX) {
      return this.#refuse(
        request,
        "oversized_message",
        "recipient inbox full (cap " + String(AGENTS_MAX_INBOX) + "); send refused",
        now
      );
    }

    this.#sequence += 1;
    const message: AgentMessage = Object.freeze({
      messageId: "msg-" + String(this.#sequence).padStart(8, "0") + "-" + agentPayloadDigest(request.payloadText).slice(0, 12),
      schemaVersion: "menog-agents/v0" as const,
      kind: request.kind,
      fromAgentId: request.fromAgentId,
      toAgentId: request.toAgentId,
      sequence: this.#sequence,
      sentAtEpochMs: now,
      payloadText: request.payloadText,
      summary: Object.freeze({ ...(request.summary ?? {}) }),
      authority: AUTHORITY,
      executionAuthorized: false,
    });

    const record: AgentDeliveryRecord = Object.freeze({
      messageId: message.messageId,
      toAgentId: message.toAgentId,
      deliveredAtEpochMs: now,
      message,
    });

    const box = this.#inboxes.get(request.toAgentId) ?? [];
    box.push(record);
    this.#inboxes.set(request.toAgentId, box);

    this.#messages.push(message);

    this.#emit(
      "agent_message_delivered",
      { type: "agent", id: request.fromAgentId },
      {
        messageId: message.messageId,
        kind: message.kind,
        fromAgentId: message.fromAgentId,
        toAgentId: message.toAgentId,
        sequence: message.sequence,
      },
      { outcome: "delivered", messageId: message.messageId }
    );

    return { ok: true, message };
  }

  /**
   * The ONLY way an agent learns about incoming traffic: its own inbox,
   * addressed to its own id. Reading another agent's inbox is impossible by
   * construction (the runtime refuses unknown/mismatched reads).
   */
  inbox(agentId: string): readonly AgentDeliveryRecord[] {
    const identity = this.#registry.get(agentId);
    if (!identity) return Object.freeze([]);
    return Object.freeze([...(this.#inboxes.get(agentId) ?? [])]);
  }

  /** Observable, bounded runtime log of ALL delivered messages. */
  log(): readonly AgentDeliveryRecord[] {
    return Object.freeze([
      ...this.#messages.map((m) => ({
        messageId: m.messageId,
        toAgentId: m.toAgentId,
        deliveredAtEpochMs: m.sentAtEpochMs,
        message: m,
      })),
    ]);
  }

  /** Bounded runtime log cap probe (for tests/observability). */
  logCap(): number {
    return AGENTS_MAX_LOG;
  }

  /** Bounded record of every refused send (digest-only, insert-once). */
  rejections(): readonly AgentRejectedMessageRecord[] {
    return Object.freeze([...this.#rejections]);
  }

  /**
   * Record a completed allocation (called ONLY by TaskAllocator). The
   * runtime owns allocation bookkeeping; the allocator itself has no
   * storage. Emits an observable `agent_task_allocated` ledger event.
   */
  recordAllocation(record: AllocationRecord, candidates: readonly AllocationCandidate[]): void {
    this.#allocationHistory.push(record);
    this.#allocationSequence += 1;
    this.#allocationStatus.set(record.assignment.assignmentId, [
      Object.freeze({
        assignmentId: record.assignment.assignmentId,
        agentId: record.assignment.assignedAgentId,
        status: "assigned",
        atEpochMs: record.allocatedAtEpochMs,
      }),
    ]);
    this.#emit(
      "agent_task_allocated",
      { type: "runtime", id: "agent-runtime" },
      {
        assignmentId: record.assignment.assignmentId,
        taskLabel: record.assignment.taskLabel,
        assignedAgentId: record.assignment.assignedAgentId,
        assignedRole: record.assignment.assignedRole,
        riskScore: record.assignment.riskScore,
        candidateCount: record.candidateCount,
        qualifiedCount: candidates.filter((c) => c.qualified).length,
        availableCount: candidates.filter((c) => c.available).length,
        taskDigest: record.taskDigest,
      },
      { outcome: "allocated", assignmentId: record.assignment.assignmentId, rationale: record.rationale }
    );
  }

  /**
   * Record a lifecycle status on an active allocation. Terminal statuses
   * (completed/cancelled) remove the assignment from the ACTIVE view but
   * keep its record in the append-only history.
   */
  recordAllocationStatus(
    assignmentId: string,
    status: AllocationStatusEvent["status"],
    note: string | undefined,
    atEpochMs: number
  ): { ok: true; event: AllocationStatusEvent } | { ok: false; reason: string } {
    const events = this.#allocationStatus.get(assignmentId);
    if (!events || events.length === 0) {
      return { ok: false, reason: "unknown assignmentId: '" + assignmentId + "'" };
    }
    const latest = events[events.length - 1]!;
    if (latest.status !== "assigned") {
      return {
        ok: false,
        reason: "assignment '" + assignmentId + "' is already '" + latest.status + "' (terminal)",
      };
    }
    if (events.length >= AGENTS_MAX_STATUS_EVENTS) {
      return { ok: false, reason: "status event cap reached (" + String(AGENTS_MAX_STATUS_EVENTS) + ")" };
    }
    const event: AllocationStatusEvent = Object.freeze({
      assignmentId,
      agentId: latest.agentId,
      status,
      atEpochMs,
      ...(note !== undefined ? { note } : {}),
    });
    events.push(event);
    this.#emit(
      "agent_task_status",
      { type: "runtime", id: "agent-runtime" },
      { assignmentId, agentId: event.agentId, status },
      { outcome: status }
    );
    return { ok: true, event };
  }

  /** Active (assigned, not yet completed/cancelled) allocations. */
  activeAllocations(): readonly ActiveAllocationView[] {
    const out: ActiveAllocationView[] = [];
    for (const record of this.#allocationHistory) {
      const events = this.#allocationStatus.get(record.assignment.assignmentId);
      const latest = events && events.length > 0 ? events[events.length - 1]! : null;
      if (latest && latest.status === "assigned") {
        out.push({
          assignment: record.assignment,
          allocatedBy: record.allocatedBy,
          statusEventCount: events ? events.length : 0,
        });
      }
    }
    return Object.freeze(out);
  }

  /** Active assignments grouped per agent (budget-headroom bookkeeping). */
  activeAllocationsByAgent(): ReadonlyMap<string, ActiveAllocationView[]> {
    const map = new Map<string, ActiveAllocationView[]>();
    for (const view of this.activeAllocations()) {
      const list = map.get(view.assignment.assignedAgentId) ?? [];
      list.push(view);
      map.set(view.assignment.assignedAgentId, list);
    }
    return map;
  }

  /** Append-only allocation history (records are never mutated/retracted). */
  allocationHistory(): readonly AllocationRecord[] {
    return Object.freeze([...this.#allocationHistory]);
  }

  /** Number of active allocations (cap probe). */
  activeAllocationCount(): number {
    return this.activeAllocations().length;
  }

  /** Runtime allocation sequence (observability). */
  allocationSequence(): number {
    return this.#allocationSequence;
  }

  /** Explicit allocator clock access (deterministic allocation timestamps). */
  now(): number {
    return this.#now();
  }

  /** Clear allocation bookkeeping too (test/teardown convenience). */
  clearTraffic(): void {
    this.#messages.length = 0;
    this.#rejections.length = 0;
    this.#inboxes.clear();
    this.#sequence = 0;
    this.#allocationHistory.length = 0;
    this.#allocationStatus.clear();
    this.#allocationSequence = 0;
    this.#channels.clear();
    this.#channelEnvelopes.clear();
    this.#channelSequences.clear();
    this.#deliveredEnvelopeIds.clear();
    this.#receipts.length = 0;
    this.#quarantine.length = 0;
    this.#envelopeSequence = 0;
  }

  // -- 19C: channels, envelopes, receiver boundary --------------------------

  /**
   * Open a channel with a frozen routing policy. The policy is validated
   * against the closed mediation routing map (a channel cannot legalize a
   * route/kind the mediation layer forbids); participants must be
   * registered identities; the channel cannot exceed the runtime cap.
   */
  openChannel(
    policy: AgentChannelPolicy,
    participants: readonly string[],
    openedBy: string,
    atEpochMs?: number
  ): { ok: true; channel: AgentChannel } | { ok: false; denyReason: string; reason: string } {
    const at = atEpochMs ?? this.#now();
    const shape = validateChannelPolicy(policy);
    if (!shape.ok) return shape;
    if (!Array.isArray(participants) || participants.length < 2 || participants.length > AGENTS_MAX_CHANNEL_PARTICIPANTS) {
      return {
        ok: false,
        denyReason: "participants_invalid",
        reason: "participants must list 2.." + String(AGENTS_MAX_CHANNEL_PARTICIPANTS) + " registered agents",
      };
    }
    for (const p of participants) {
      if (!this.#registry.get(p)) {
        return { ok: false, denyReason: "participants_invalid", reason: "participant '" + p + "' is not a registered identity" };
      }
    }
    if (this.#channels.size >= AGENTS_MAX_CHANNELS) {
      return { ok: false, denyReason: "channel_cap_reached", reason: "channel cap reached (" + String(AGENTS_MAX_CHANNELS) + ")" };
    }
    // Enforce that every allowed kind is routable for the role pair.
    const fromRole = this.#registry.get(participants[0]!)!.role;
    const toRole = this.#registry.get(participants[1]!)!.role;
    if (fromRole !== policy.fromRole || toRole !== policy.toRole) {
      return {
        ok: false,
        denyReason: "route_not_allowed",
        reason: "participant roles do not match the declared policy role pair",
      };
    }
    for (const kind of policy.allowedKinds) {
      if (!routingAllows(fromRole, toRole, kind)) {
        return {
          ok: false,
          denyReason: "route_not_allowed",
          reason: "channel policy allows kind '" + kind + "' which the mediation routing map refuses",
        };
      }
    }
    this.#envelopeSequence += 1;
    const channel: AgentChannel = Object.freeze({
      channelId: "chn-" + String(this.#envelopeSequence).padStart(4, "0") + "-" + policy.kind,
      state: "open",
      policy: Object.freeze({ ...policy, allowedKinds: Object.freeze([...policy.allowedKinds]) }),
      participants: Object.freeze([...participants]),
      openedAtEpochMs: at,
      openedBy,
      authority: "mediation",
      executionAuthorized: false,
    });
    this.#channels.set(channel.channelId, channel);
    this.#channelEnvelopes.set(channel.channelId, []);
    this.#channelSequences.set(channel.channelId, 0);
    this.#emit(
      "agent_channel_opened",
      { type: "runtime", id: "agent-runtime" },
      { channelId: channel.channelId, kind: policy.kind, fromRole: policy.fromRole, toRole: policy.toRole, openedBy },
      { outcome: "opened", channelId: channel.channelId }
    );
    return { ok: true, channel };
  }

  channel(channelId: string): AgentChannel | null {
    return this.#channels.get(channelId) ?? null;
  }

  channels(): readonly AgentChannel[] {
    return Object.freeze([...this.#channels.values()]);
  }

  /** Close a channel (explicit lifecycle; closed channels refuse traffic). */
  closeChannel(channelId: string, atEpochMs?: number): { ok: boolean; reason?: string } {
    const ch = this.#channels.get(channelId);
    if (!ch) return { ok: false, reason: "unknown channel: '" + channelId + "'" };
    if (ch.state === "closed") return { ok: false, reason: "channel already closed" };
    this.#channels.set(
      channelId,
      Object.freeze({ ...ch, state: "closed" })
    );
    this.#emit(
      "agent_channel_closed",
      { type: "runtime", id: "agent-runtime" },
      { channelId },
      { outcome: "closed" }
    );
    void atEpochMs;
    return { ok: true };
  }

  /**
   * Send a message on a channel: the runtime validates channel state,
   * participant membership, routing policy, and hostile content, stamps
   * the ENVELOPE (sender identity re-stamped from the registry, never
   * caller input), delivers it to the receiver's inbox, and records the
   * provenance chain. The receiver boundary processes it on `receive()`.
   */
  sendOnChannel(
    channelId: string,
    request: AgentSendRequest,
    atEpochMs?: number
  ): { ok: true; envelope: AgentEnvelope } | { ok: false; denyReason: string; reason: string } {
    const at = atEpochMs ?? this.#now();
    const ch = this.#channels.get(channelId);
    if (!ch) {
      return { ok: false, denyReason: "channel_unknown", reason: "unknown channel: '" + channelId + "'" };
    }
    if (ch.state !== "open") {
      return { ok: false, denyReason: "channel_closed", reason: "channel '" + channelId + "' is closed" };
    }
    // Channel policy membership/kind gate BEFORE per-identity resolution so
    // non-participants learn nothing about recipient registration.
    const policyCheck = channelPolicyAllows(ch.policy, request.kind, request.fromAgentId, request.toAgentId, ch.participants);
    if (!policyCheck.ok) {
      return { ok: false, denyReason: "route_not_allowed", reason: policyCheck.reason };
    }
    // Sender identity is resolved by the RUNTIME, not claimed by the caller
    // (anti-spoofing); envelope stamps registry-resolved identities.
    const sender = this.#registry.get(request.fromAgentId);
    if (!sender) {
      return { ok: false, denyReason: "sender_unknown", reason: "fromAgentId '" + request.fromAgentId + "' is not registered" };
    }
    const receiver = this.#registry.get(request.toAgentId);
    if (!receiver) {
      return { ok: false, denyReason: "recipient_unknown", reason: "toAgentId '" + request.toAgentId + "' is not registered" };
    }
    if (request.payloadText.length > ch.policy.maxPayloadChars) {
      return {
        ok: false,
        denyReason: "policy_invalid",
        reason:
          "payload length " +
          String(request.payloadText.length) +
          " exceeds the channel cap " +
          String(ch.policy.maxPayloadChars),
      };
    }
    // Full mediation validation still applies on channels (hostile content,
    // bounds, role-pair discipline) — a channel adds constraints, never removes them.
    const base = this.send(request);
    if (!base.ok) {
      return { ok: false, denyReason: base.denyReason, reason: base.reason };
    }
    const seq = (this.#channelSequences.get(channelId) ?? 0) + 1;
    this.#channelSequences.set(channelId, seq);
    const provenance: readonly AgentProvenanceEntry[] = Object.freeze([
      Object.freeze({
        stage: "origin",
        actorId: sender.agentId,
        actorType: "agent",
        atEpochMs: at,
        detail: Object.freeze({ messageId: base.message.messageId, kind: request.kind }),
      }),
      Object.freeze({
        stage: "mediation",
        actorId: "agent-runtime",
        actorType: "runtime",
        atEpochMs: at,
        detail: Object.freeze({ channelId, channelKind: ch.policy.kind, sequence: seq }),
      }),
      Object.freeze({
        stage: "delivery",
        actorId: receiver.agentId,
        actorType: "agent",
        atEpochMs: at,
        detail: Object.freeze({ channelSequence: seq, toInbox: receiver.agentId }),
      }),
    ]);
    const envelope: AgentEnvelope = Object.freeze({
      envelopeId: "env-" + String(seq).padStart(6, "0") + "-" + base.message.messageId.slice(4, 16),
      schemaVersion: "menog-agents/v0",
      channelId,
      channelKind: ch.policy.kind,
      message: base.message,
      senderId: sender.agentId,
      receiverId: receiver.agentId,
      channelSequence: seq,
      provenance,
      untrusted: true,
      authority: "mediation",
      executionAuthorized: false,
    });
    this.#channelEnvelopes.get(channelId)!.push(envelope);
    this.#emit(
      "agent_envelope_sent",
      { type: "agent", id: sender.agentId },
      { envelopeId: envelope.envelopeId, channelId, senderId: envelope.senderId, receiverId: envelope.receiverId, channelSequence: seq },
      { outcome: "sent", envelopeId: envelope.envelopeId }
    );
    return { ok: true, envelope };
  }

  /**
   * The RECEIVER boundary: the only way an envelope becomes an accepted
   * input. Deterministic checks in fixed order (receiver known → addressed
   * → non-duplicate → integrity → provenance → capacity → content); every
   * outcome is recorded as a receipt; quarantined envelopes are retained
   * digest-only for human audit. Accepting an envelope grants NO authority.
   */
  receive(
    envelope: AgentEnvelope,
    receiverId: string,
    atEpochMs?: number
  ): AgentBoundaryResult {
    const at = atEpochMs ?? this.#now();
    const receiverKnown = this.#registry.get(receiverId) !== null;
    const ch = this.#channels.get(envelope.channelId);
    const historyCount = ch ? (this.#channelEnvelopes.get(envelope.channelId)?.length ?? 0) : 0;
    const input: BoundaryCheckInput = {
      envelope,
      callerReceiverId: receiverId,
      receiverKnown,
      alreadyDelivered: this.#deliveredEnvelopeIds.has(envelope.envelopeId),
      channelHistoryCount: historyCount,
      contentScreen: (() => {
        const s = screenAgentSendRequest({
          kind: envelope.message.kind,
          fromAgentId: envelope.message.fromAgentId,
          toAgentId: envelope.message.toAgentId,
          payloadText: envelope.message.payloadText,
          summary: envelope.message.summary,
        });
        return s.ok ? { ok: true as const } : { ok: false as const, reason: s.finding.pattern };
      })(),
    };
    const decision = decideBoundary(input);
    return this.#recordBoundaryOutcome(envelope, receiverId, decision.disposition, decision.result, at);
  }

  #recordBoundaryOutcome(
    envelope: AgentEnvelope,
    receiverId: string,
    disposition: AgentBoundaryDisposition,
    result: AgentBoundaryResult,
    at: number
  ): AgentBoundaryResult {
    const denyReason = result.ok ? null : result.denyReason;
    const receiptCount = this.#receipts.length;
    const receipt: AgentBoundaryReceipt = Object.freeze({
      receiptId: "rcp-" + String(receiptCount + 1).padStart(6, "0"),
      envelopeId: envelope.envelopeId,
      receiverId,
      disposition,
      denyReason,
      atEpochMs: at,
      authority: "mediation",
      executionAuthorized: false,
    });
    if (this.#receipts.length < AGENTS_MAX_RECEIPTS) this.#receipts.push(receipt);
    if (!result.ok && (disposition === "quarantined" || disposition === "refused")) {
      if (disposition === "quarantined" && this.#quarantine.length < AGENTS_MAX_QUARANTINE) {
        this.#quarantine.push(
          Object.freeze(
            buildQuarantineRecord(envelope, result.denyReason, at, this.#quarantine.length + 1)
          )
        );
      }
      this.#emit(
        "agent_envelope_refused",
        { type: "runtime", id: "agent-runtime" },
        { envelopeId: envelope.envelopeId, receiverId, denyReason: result.denyReason },
        { outcome: disposition }
      );
    } else if (result.ok) {
      this.#deliveredEnvelopeIds.add(envelope.envelopeId);
      this.#emit(
        "agent_envelope_accepted",
        { type: "agent", id: envelope.senderId },
        { envelopeId: envelope.envelopeId, receiverId, channelId: envelope.channelId },
        { outcome: "accepted" }
      );
    }
    return result;
  }

  /** Observable receipts (one per receiver-boundary decision). */
  boundaryReceipts(): readonly AgentBoundaryReceipt[] {
    return Object.freeze([...this.#receipts]);
  }

  /** Observable quarantine (digest-only; for human audit). */
  quarantine(): readonly AgentQuarantineRecord[] {
    return Object.freeze([...this.#quarantine]);
  }

  /** Delivered envelopes on one channel (bounded history). */
  channelEnvelopeHistory(channelId: string): readonly AgentEnvelope[] {
    return Object.freeze([...(this.#channelEnvelopes.get(channelId) ?? [])]);
  }

  /** Raw envelope lookup by id (runtime/audit use; NOT a receiver surface). */
  envelopeById(envelopeId: string): AgentEnvelope | null {
    for (const list of this.#channelEnvelopes.values()) {
      const hit = list.find((e) => e.envelopeId === envelopeId);
      if (hit) return hit;
    }
    return null;
  }

  // -- internals -----------------------------------------------------------

  #refuse(
    request: AgentSendRequest,
    denyReason: AgentMessageDenyReason,
    reason: string,
    now: number
  ): AgentDeliveryDenial {
    if (!isAgentMessageDenyReason(denyReason)) {
      denyReason = "malformed_message";
    }
    const record: AgentRejectedMessageRecord = Object.freeze({
      recordId:
        "rej-" +
        String(this.#rejections.length + 1).padStart(6, "0") +
        "-" +
        agentPayloadDigest(
          (request && typeof request.payloadText === "string" ? request.payloadText : "")
        ).slice(0, 12),
      rejectedAtEpochMs: now,
      rejectedBy: "runtime",
      denyReason,
      fromAgentId:
        request && typeof request.fromAgentId === "string" ? request.fromAgentId : "unknown",
      toAgentId:
        request && typeof request.toAgentId === "string" ? request.toAgentId : "unknown",
      kind: request && isKnownMessageKind(request.kind) ? request.kind : null,
      payloadDigest: agentPayloadDigest(
        request && typeof request.payloadText === "string" ? request.payloadText : ""
      ),
      summaryDigest: agentPayloadDigest(JSON.stringify(request?.summary ?? {})),
      authority: AUTHORITY,
      executionAuthorized: false,
    });
    if (this.#rejections.length < AGENTS_MAX_REJECTIONS) {
      this.#rejections.push(record);
    }
    this.#emit(
      "agent_message_denied",
      { type: "runtime", id: "agent-runtime" },
      {
        denyReason,
        fromAgentId: record.fromAgentId,
        toAgentId: record.toAgentId,
        kind: record.kind,
      },
      { outcome: "denied", denyReason }
    );
    const denial: AgentDeliveryDenial = {
      ok: false,
      denyReason,
      reason,
      kind: record.kind,
    };
    return denial;
  }

  /**
   * 19E — ledger-observable recovery event (called ONLY by the
   * RecoveryCoordinator, which holds no emitter of its own). Only the
   * closed recovery event-type set may pass; anything else is ignored
   * (fail-closed observability).
   */
  emitRecoveryEvent(eventType: "agent_failure_recorded" | "agent_task_reassigned" | "agent_assignment_released", subjectId: string, rationale: string): void {
    const allowed = ["agent_failure_recorded", "agent_task_reassigned", "agent_assignment_released"] as const;
    if (!allowed.includes(eventType)) return;
    this.#emit(eventType, { type: "runtime", id: "agent-runtime" }, { subjectId }, { outcome: eventType, rationale });
  }

  #emit(
    eventType: string,
    actor: { type: "runtime" | "agent"; id: string },
    inputSummary: Record<string, unknown>,
    resultSummary: Record<string, unknown>
  ): void {
    if (this.#ledger === null) return;
    this.#ledger.append({
      eventType,
      policyDecision: "not_applicable",
      actor,
      workspaceId: this.#workspaceId,
      taskId: this.#taskId,
      inputSummary,
      resultSummary,
    });
  }
}
