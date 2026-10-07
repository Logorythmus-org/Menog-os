import { describe, it, expect } from "vitest";
import {
  AgentRuntime,
  PlannerAgent,
  BuilderAgent,
  ReviewerAgent,
  PLANNER_AGENT_ID,
  BUILDER_AGENT_ID,
  REVIEWER_AGENT_ID,
  KNOWN_AGENT_CHANNEL_KINDS,
  KNOWN_AGENT_CHANNEL_STATES,
  KNOWN_AGENT_CHANNEL_DENY_REASONS,
  KNOWN_AGENT_BOUNDARY_DENY_REASONS,
  KNOWN_AGENT_BOUNDARY_DISPOSITIONS,
  AGENTS_MAX_PAYLOAD_CHARS,
  AGENTS_MAX_CHANNELS,
  AGENTS_MAX_CHANNEL_PARTICIPANTS,
  AGENTS_MAX_CHANNEL_HISTORY,
  AGENTS_MAX_PROVENANCE_FIELDS,
  validateChannelPolicy,
  validateProvenanceChain,
  validateEnvelopeIntegrity,
  decideBoundary,
  envelopePayloadDigest,
  type AgentChannelPolicy,
  type AgentEnvelope,
  type AgentRuntimeOptions,
} from "@menog/agents";
import { AppendOnlyLedger } from "@menog/event-ledger";

const T0 = 1_990_000_000_000;
const T1 = T0 + 1000;

function clock(): AgentRuntimeOptions {
  let n = T0;
  return { nowEpochMs: () => (n += 1) };
}

function setup(): {
  rt: AgentRuntime;
  planner: PlannerAgent;
  builder: BuilderAgent;
  reviewer: ReviewerAgent;
} {
  const rt = new AgentRuntime(clock());
  rt.register({ agentId: PLANNER_AGENT_ID, role: "planner", atEpochMs: T0 });
  rt.register({ agentId: BUILDER_AGENT_ID, role: "builder", atEpochMs: T0 + 1 });
  rt.register({ agentId: REVIEWER_AGENT_ID, role: "reviewer", atEpochMs: T0 + 2 });
  return { rt, planner: new PlannerAgent(rt), builder: new BuilderAgent(rt), reviewer: new ReviewerAgent(rt) };
}

function pbPolicy(overrides: Partial<AgentChannelPolicy> = {}): AgentChannelPolicy {
  return {
    kind: "planner_builder",
    fromRole: "planner",
    toRole: "builder",
    allowedKinds: ["plan_proposal", "status_observation", "error_report"],
    maxPayloadChars: AGENTS_MAX_PAYLOAD_CHARS,
    onViolation: "quarantine",
    ...overrides,
  };
}

function openPb(rt: AgentRuntime, overrides: Partial<AgentChannelPolicy> = {}, at = T1): string {
  const r = rt.openChannel(pbPolicy(overrides), [PLANNER_AGENT_ID, BUILDER_AGENT_ID], "human-19c", at);
  expect(r.ok).toBe(true);
  return (r as { ok: true; channel: { channelId: string } }).channel.channelId;
}

// ---------------------------------------------------------------------------
// 19C-C1 — Routing policy (channels)
// ---------------------------------------------------------------------------

describe("19C-C1 — channels and routing policy", () => {
  it("pins the closed channel/boundary unions and caps", () => {
    expect(KNOWN_AGENT_CHANNEL_KINDS).toEqual(["planner_builder", "builder_reviewer", "reviewer_planner"]);
    expect(KNOWN_AGENT_CHANNEL_STATES).toEqual(["open", "closed"]);
    expect(KNOWN_AGENT_CHANNEL_DENY_REASONS).toEqual([
      "channel_unknown",
      "channel_closed",
      "policy_invalid",
      "participants_invalid",
      "route_not_allowed",
      "channel_cap_reached",
    ]);
    expect(KNOWN_AGENT_BOUNDARY_DENY_REASONS).toEqual([
      "receiver_unknown",
      "not_addressed_to_receiver",
      "duplicate_envelope",
      "envelope_malformed",
      "provenance_broken",
      "content_refused",
    ]);
    expect(KNOWN_AGENT_BOUNDARY_DISPOSITIONS).toEqual(["accepted", "refused", "quarantined"]);
    expect(AGENTS_MAX_CHANNELS).toBe(16);
    expect(AGENTS_MAX_CHANNEL_PARTICIPANTS).toBe(3);
    expect(AGENTS_MAX_CHANNEL_HISTORY).toBe(128);
    expect(AGENTS_MAX_PROVENANCE_FIELDS).toBe(16);
  });

  it("opens a channel with frozen policy, participants, and authority pins", () => {
    const { rt } = setup();
    const id = openPb(rt);
    const ch = rt.channel(id)!;
    expect(ch.state).toBe("open");
    expect(ch.participants).toEqual([PLANNER_AGENT_ID, BUILDER_AGENT_ID]);
    expect(ch.openedBy).toBe("human-19c");
    expect(ch.authority).toBe("mediation");
    expect(ch.executionAuthorized).toBe(false);
    expect(Object.isFrozen(ch.policy)).toBe(true);
    expect(Object.isFrozen(ch.policy.allowedKinds)).toBe(true);
  });

  it("a channel cannot legalize a route the mediation map refuses", () => {
    const { rt } = setup();
    const r = rt.openChannel(
      {
        kind: "planner_builder",
        fromRole: "planner",
        toRole: "reviewer",
        allowedKinds: ["plan_proposal"],
        maxPayloadChars: 100,
        onViolation: "drop",
      },
      [PLANNER_AGENT_ID, REVIEWER_AGENT_ID],
      "human-19c",
      T1
    );
    expect(r).toMatchObject({ ok: false, denyReason: "route_not_allowed" });
  });

  it("channel kind must match the role pair; participants must be registered", () => {
    const { rt } = setup();
    expect(
      rt.openChannel(pbPolicy({ kind: "builder_reviewer" }), [PLANNER_AGENT_ID, BUILDER_AGENT_ID], "h", T1)
    ).toMatchObject({ ok: false, denyReason: "route_not_allowed" });
    expect(
      rt.openChannel(pbPolicy(), ["ghost", BUILDER_AGENT_ID], "h", T1)
    ).toMatchObject({ ok: false, denyReason: "participants_invalid" });
    expect(
      rt.openChannel(pbPolicy(), [PLANNER_AGENT_ID], "h", T1)
    ).toMatchObject({ ok: false, denyReason: "participants_invalid" });
  });

  it("invalid policies deny with policy_invalid (bounds, kinds)", () => {
    const { rt } = setup();
    expect(
      rt.openChannel(pbPolicy({ maxPayloadChars: AGENTS_MAX_PAYLOAD_CHARS + 1 }), [PLANNER_AGENT_ID, BUILDER_AGENT_ID], "h", T1)
    ).toMatchObject({ ok: false, denyReason: "policy_invalid" });
    expect(validateChannelPolicy(pbPolicy({ allowedKinds: [] }))).toMatchObject({ ok: false, denyReason: "policy_invalid" });
    expect(
      validateChannelPolicy(pbPolicy({ allowedKinds: ["ghost_kind" as "plan_proposal"] }))
    ).toMatchObject({ ok: false, denyReason: "policy_invalid" });
  });

  it("explicit channel lifecycle: closed channels refuse traffic", () => {
    const { rt, planner } = setup();
    const id = openPb(rt);
    expect(rt.closeChannel(id).ok).toBe(true);
    expect(rt.channel(id)!.state).toBe("closed");
    expect(planner.proposePlanOn(id, "hello after close")).toMatchObject({ ok: false, denyReason: "channel_closed" });
    expect(rt.closeChannel(id).ok).toBe(false); // terminal
  });

  it("channel cap is enforced", () => {
    const { rt } = setup();
    for (let i = 0; i < AGENTS_MAX_CHANNELS; i++) {
      expect(rt.openChannel(pbPolicy(), [PLANNER_AGENT_ID, BUILDER_AGENT_ID], "h", T1 + i).ok).toBe(true);
    }
    expect(rt.openChannel(pbPolicy(), [PLANNER_AGENT_ID, BUILDER_AGENT_ID], "h", T1)).toMatchObject({
      ok: false,
      denyReason: "channel_cap_reached",
    });
  });

  it("sendOnChannel enforces per-channel payload caps and kind policy", () => {
    const { rt, planner } = setup();
    const narrow = openPb(rt, { maxPayloadChars: 32, allowedKinds: ["plan_proposal"] }, T1);
    // Payload over the CHANNEL cap (below the global cap) refuses.
    expect(planner.proposePlanOn(narrow, "x".repeat(33))).toMatchObject({ ok: false, denyReason: "policy_invalid" });
    // Kind not in allowedKinds refuses even though the role pair allows it.
    expect(planner.observeStatusOn(narrow, BUILDER_AGENT_ID, "status not allowed here")).toMatchObject({
      ok: false,
      denyReason: "route_not_allowed",
    });
    // Within policy succeeds.
    expect(planner.proposePlanOn(narrow, "ok")).toMatchObject({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// 19C-C2 — Envelopes, provenance, receiver boundary
// ---------------------------------------------------------------------------

describe("19C-C2 — envelopes, provenance, and the receiver boundary", () => {
  it("sendOnChannel produces a runtime-stamped envelope with a full provenance chain", () => {
    const { rt, planner } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "the plan", { steps: 2 });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const env = r.envelope;
    expect(env.channelId).toBe(id);
    expect(env.channelKind).toBe("planner_builder");
    expect(env.senderId).toBe(PLANNER_AGENT_ID); // re-stamped by runtime
    expect(env.receiverId).toBe(BUILDER_AGENT_ID);
    expect(env.channelSequence).toBe(1);
    expect(env.untrusted).toBe(true);
    expect(env.authority).toBe("mediation");
    expect(env.executionAuthorized).toBe(false);
    expect(env.provenance.map((p) => p.stage)).toEqual(["origin", "mediation", "delivery"]);
    expect(validateProvenanceChain(env.provenance)).toEqual({ ok: true });
    expect(validateEnvelopeIntegrity(env)).toEqual({ ok: true });
    expect(env.provenance[0]!.actorId).toBe(PLANNER_AGENT_ID);
    expect(env.provenance[1]!.actorId).toBe("agent-runtime");
    expect(env.provenance[2]!.actorId).toBe(BUILDER_AGENT_ID);
  });

  it("receive() accepts an honest envelope addressed to the receiver", () => {
    const { rt, planner, builder } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "plan body");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const out = builder.receive(r.envelope);
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.receipt.disposition).toBe("accepted");
      expect(out.receipt.receiverId).toBe(BUILDER_AGENT_ID);
      expect(out.receipt.authority).toBe("mediation");
      expect(out.receipt.executionAuthorized).toBe(false);
    }
    expect(rt.boundaryReceipts()).toHaveLength(1);
    expect(rt.quarantine()).toHaveLength(0);
  });

  it("duplicate delivery is refused (replay protection)", () => {
    const { rt, planner, builder } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "plan body");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(builder.receive(r.envelope).ok).toBe(true);
    expect(builder.receive(r.envelope)).toMatchObject({ ok: false, denyReason: "duplicate_envelope" });
    expect(rt.quarantine()).toHaveLength(1); // replay is quarantined for audit
  });

  it("an envelope not addressed to the receiver is refused", () => {
    const { rt, planner, reviewer } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "for the builder only");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(reviewer.receive(r.envelope)).toMatchObject({ ok: false, denyReason: "not_addressed_to_receiver" });
    // Correct receiver still accepts afterwards (refusal was receiver-scoped).
    expect(new BuilderAgent(rt).receive(r.envelope).ok).toBe(true);
  });

  it("tampered envelopes are refused at the boundary (integrity + provenance)", () => {
    const { rt, planner, builder } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "honest body");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const spoofed: AgentEnvelope = { ...r.envelope, senderId: REVIEWER_AGENT_ID };
    expect(builder.receive(spoofed)).toMatchObject({ ok: false, denyReason: "envelope_malformed" });
    const marked: AgentEnvelope = { ...r.envelope, untrusted: false as unknown as true };
    expect(builder.receive(marked)).toMatchObject({ ok: false, denyReason: "envelope_malformed" });
    const broken: AgentEnvelope = { ...r.envelope, provenance: [...r.envelope.provenance].reverse() };
    expect(builder.receive(broken)).toMatchObject({ ok: false, denyReason: "provenance_broken" });
    const forged: AgentEnvelope = {
      ...r.envelope,
      message: { ...r.envelope.message, executionAuthorized: true as unknown as false },
    };
    expect(builder.receive(forged)).toMatchObject({ ok: false, denyReason: "envelope_malformed" });
    // The honest envelope still processes fine after the tamper attempts.
    expect(builder.receive(r.envelope).ok).toBe(true);
  });

  it("hostile content is refused at the receiver boundary (content_refused, quarantined)", () => {
    const { rt, planner, builder } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "honest");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    // The send-side mediation already refuses hostile payloads; to pin the
    // receiver's own content gate we drive decideBoundary directly.
    const decision = decideBoundary({
      envelope: r.envelope,
      callerReceiverId: BUILDER_AGENT_ID,
      receiverKnown: true,
      alreadyDelivered: false,
      channelHistoryCount: 0,
      contentScreen: { ok: false, reason: "system_instruction_override" },
    });
    expect(decision.disposition).toBe("quarantined");
    expect(decision.result).toMatchObject({ ok: false, denyReason: "content_refused" });
    void builder;
  });

  it("boundary outcomes are receipted and quarantines are digest-only", () => {
    const { rt, planner, reviewer, builder } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "payload with secrets sk-abcdef0123456789abcdef");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(reviewer.receive(r.envelope)).toMatchObject({ ok: false, denyReason: "not_addressed_to_receiver" });
    expect(builder.receive(r.envelope).ok).toBe(true);
    expect(rt.boundaryReceipts().map((x) => x.disposition).sort()).toEqual(["accepted", "refused"]);
    const q = JSON.stringify(rt.quarantine());
    expect(q).not.toContain("sk-abcdef");
    for (const rec of rt.quarantine()) {
      expect(rec.authority).toBe("mediation");
      expect(rec.executionAuthorized).toBe(false);
      expect(rec.payloadDigest).toHaveLength(64);
    }
  });

  it("channel history is bounded and observable", () => {
    const { rt, planner } = setup();
    const id = openPb(rt);
    for (let i = 0; i < 5; i++) {
      expect(planner.proposePlanOn(id, "m" + String(i)).ok).toBe(true);
    }
    expect(rt.channelEnvelopeHistory(id)).toHaveLength(5);
    expect(rt.channelEnvelopeHistory(id)[0]!.channelSequence).toBe(1);
    expect(rt.channelEnvelopeHistory(id)[4]!.channelSequence).toBe(5);
    expect(rt.envelopeById(rt.channelEnvelopeHistory(id)[2]!.envelopeId)).not.toBeNull();
    expect(rt.envelopeById("env-none")).toBeNull();
  });

  it("channel traffic is deterministic under a fixed clock", () => {
    const run = () => {
      const rt = new AgentRuntime(clock());
      rt.register({ agentId: PLANNER_AGENT_ID, role: "planner", atEpochMs: T0 });
      rt.register({ agentId: BUILDER_AGENT_ID, role: "builder", atEpochMs: T0 + 1 });
    const ch = rt.openChannel(pbPolicy(), [PLANNER_AGENT_ID, BUILDER_AGENT_ID], "human-19c", T1);
    if (!ch.ok) return { fail: true };
    const id: string = ch.channel.channelId;
      const s = rt.sendOnChannel(id, {
        kind: "plan_proposal",
        fromAgentId: PLANNER_AGENT_ID,
        toAgentId: BUILDER_AGENT_ID,
        payloadText: "det body",
      });
      if (!s.ok) return { fail: true };
      return {
        envelopeId: s.envelope.envelopeId,
        sender: s.envelope.senderId,
        receiver: s.envelope.receiverId,
        seq: s.envelope.channelSequence,
        prov: s.envelope.provenance.map((p) => [p.stage, p.actorId, p.atEpochMs]),
        digest: envelopePayloadDigest(s.envelope.message.payloadText).slice(0, 8),
      };
    };
    expect(run()).toEqual(run());
  });

  it("channel + envelope + receipt events are ledger-observable (chain verifies)", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const rt = new AgentRuntime({
      nowEpochMs: () => T0,
      ledger: {
        append: (input) => {
          const r = ledger.append({
            eventId: "c19c-" + String(ledger.length + 1).padStart(4, "0"),
            timestamp: new Date(T0 + ledger.length).toISOString(),
            eventType: input.eventType,
            actor: { type: input.actor.type as "runtime" | "agent", id: input.actor.id },
            policyDecision: input.policyDecision,
            inputSummary: input.inputSummary,
            resultSummary: input.resultSummary,
          });
          return { ok: r.ok, eventId: r.event?.eventId };
        },
      },
    });
    rt.register({ agentId: PLANNER_AGENT_ID, role: "planner", atEpochMs: T0 });
    rt.register({ agentId: BUILDER_AGENT_ID, role: "builder", atEpochMs: T0 });
    const ch = rt.openChannel(pbPolicy(), [PLANNER_AGENT_ID, BUILDER_AGENT_ID], "human-19c", T1);
    expect(ch.ok).toBe(true);
    if (!ch.ok) return;
    const id = ch.channel.channelId;
    const s = rt.sendOnChannel(id, {
      kind: "plan_proposal",
      fromAgentId: PLANNER_AGENT_ID,
      toAgentId: BUILDER_AGENT_ID,
      payloadText: "observed",
    });
    expect(s.ok).toBe(true);
    if (s.ok) {
      expect(new BuilderAgent(rt).receive(s.envelope).ok).toBe(true);
    }
    const types = ledger.events().map((e) => e.eventType);
    expect(types).toContain("agent_channel_opened");
    expect(types).toContain("agent_envelope_sent");
    expect(types).toContain("agent_envelope_accepted");
    expect(ledger.verify().ok).toBe(true);
  });
});
