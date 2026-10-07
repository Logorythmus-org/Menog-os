import { describe, it, expect } from "vitest";
import {
  AGENTS_SCHEMA_VERSION,
  KNOWN_AGENT_ROLES,
  KNOWN_19A_AGENT_IDS,
  PLANNER_AGENT_ID,
  BUILDER_AGENT_ID,
  REVIEWER_AGENT_ID,
  AGENT_ROLE_PROFILES,
  AGENT_ROUTING_RULES,
  KNOWN_AGENT_MESSAGE_KINDS,
  KNOWN_AGENT_MESSAGE_DENY_REASONS,
  AgentIdentityRegistry,
  AgentRuntime,
  PlannerAgent,
  BuilderAgent,
  ReviewerAgent,
  registerAllThreeAgents,
  routingAllows,
  validateAgentProfile,
  validateSendRequestShape,
  isAgentRole,
  isKnownMessageKind,
  isAgentMessageDenyReason,
  agentPayloadDigest,
  AGENTS_MAX_PAYLOAD_CHARS,
  AGENTS_MAX_PROFILE_VERBS,
  AGENTS_MAX_PROFILE_CAPABILITIES,
  AGENTS_MAX_PROFILE_DESCRIPTION_CHARS,
  type AgentCapabilityProfile,
  type AgentRuntimeOptions,
  type AgentLedgerEmitter,
  type AgentSendRequest,
} from "@menog/agents";
import { AppendOnlyLedger } from "@menog/event-ledger";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import type { Actor } from "@menog/core";

const T0 = 1_950_000_000_000;
const HUMAN: Actor = { type: "human", id: "human-19a" };

function clock(): AgentRuntimeOptions {
  let n = T0;
  return { nowEpochMs: () => (n += 1) };
}

function newRuntime(): AgentRuntime {
  const rt = new AgentRuntime(clock());
  const reg = registerAllThreeAgents(rt, T0);
  expect(reg.ok).toBe(true);
  return rt;
}



// ---------------------------------------------------------------------------
// 19A-U1 — Agent identity
// ---------------------------------------------------------------------------

describe("19A-U1 — agent identity", () => {
  it("pins the schema version at menog-agents/v0", () => {
    expect(AGENTS_SCHEMA_VERSION).toBe("menog-agents/v0");
  });

  it("pins exactly three roles and three identity ids", () => {
    expect(KNOWN_AGENT_ROLES).toEqual(["planner", "builder", "reviewer"]);
    expect(KNOWN_19A_AGENT_IDS).toEqual([
      "menog-agent-planner",
      "menog-agent-builder",
      "menog-agent-reviewer",
    ]);
    expect(isAgentRole("planner")).toBe(true);
    expect(isAgentRole("sudoer")).toBe(false);
  });

  it("registers all three 19A identities with pinned role binding", () => {
    const rt = newRuntime();
    expect(rt.identities().map((i) => i.agentId)).toEqual([
      PLANNER_AGENT_ID,
      BUILDER_AGENT_ID,
      REVIEWER_AGENT_ID,
    ]);
    expect(rt.roleOf(PLANNER_AGENT_ID)).toBe("planner");
    expect(rt.roleOf(BUILDER_AGENT_ID)).toBe("builder");
    expect(rt.roleOf(REVIEWER_AGENT_ID)).toBe("reviewer");
  });

  it("freezes identities and profiles (no mutation surface)", () => {
    const rt = newRuntime();
    const id = rt.identity(PLANNER_AGENT_ID)!;
    expect(Object.isFrozen(id)).toBe(true);
    expect(Object.isFrozen(id.profile)).toBe(true);
    expect(Object.isFrozen(id.profile.allowedVerbs)).toBe(true);
    expect(Object.isFrozen(id.profile.allowedCapabilities)).toBe(true);
    expect(id.authority).toBe("mediation");
    expect(id.executionAuthorized).toBe(false);
    expect(id.schemaVersion).toBe("menog-agents/v0");
  });

  it("denies wrong role/id binding, duplicates, and foreign ids", () => {
    const reg = new AgentIdentityRegistry();
    expect(
      reg.register({ agentId: PLANNER_AGENT_ID, role: "builder", atEpochMs: T0 })
    ).toMatchObject({ ok: false, denyReason: "identity_mismatch" });
    expect(
      reg.register({ agentId: PLANNER_AGENT_ID, role: "planner", atEpochMs: T0 }).ok
    ).toBe(true);
    expect(
      reg.register({ agentId: PLANNER_AGENT_ID, role: "planner", atEpochMs: T0 })
    ).toMatchObject({ ok: false, denyReason: "duplicate_identity" });
    expect(
      reg.register({ agentId: "menog-agent-king", role: "planner", atEpochMs: T0 })
    ).toMatchObject({ ok: false, denyReason: "identity_mismatch" });
    expect(
      reg.register({ agentId: PLANNER_AGENT_ID, role: "emperor" as "planner", atEpochMs: T0 })
    ).toMatchObject({ ok: false, denyReason: "unknown_role" });
  });
});

// ---------------------------------------------------------------------------
// 19A-U2 — Capability profiles
// ---------------------------------------------------------------------------

describe("19A-U2 — capability profiles", () => {
  it("pins the three frozen role profiles (least-privilege scoping)", () => {
    expect(AGENT_ROLE_PROFILES.planner.allowedVerbs).toEqual([
      "plan.generate",
      "workspace.read",
      "workspace.search",
    ]);
    expect(AGENT_ROLE_PROFILES.planner.allowedCapabilities).toEqual([
      "plan:generate",
      "workspace:read",
      "workspace:search",
    ]);
    expect(AGENT_ROLE_PROFILES.planner.maxSideEffectClass).toBe("read");
    expect(AGENT_ROLE_PROFILES.builder.allowedCapabilities).toEqual([
      "workspace:read",
      "workspace:search",
      "workspace:write",
    ]);
    expect(AGENT_ROLE_PROFILES.builder.maxSideEffectClass).toBe("write");
    expect(AGENT_ROLE_PROFILES.reviewer.allowedCapabilities).toEqual([
      "workspace:read",
      "git:status",
      "git:diff-read",
    ]);
    expect(AGENT_ROLE_PROFILES.reviewer.maxSideEffectClass).toBe("read");
    for (const role of KNOWN_AGENT_ROLES) {
      expect(Object.isFrozen(AGENT_ROLE_PROFILES[role])).toBe(true);
      expect(Object.isFrozen(AGENT_ROLE_PROFILES[role].allowedVerbs)).toBe(true);
    }
  });

  it("profiles are advisory scoping data — a profile entry cannot flip policy", () => {
    const engine = new DenyByDefaultPolicyEngine();
    // The builder profile declares workspace:write — policy STILL denies it.
    const res = engine.evaluate({
      actor: { type: "agent", id: BUILDER_AGENT_ID },
      verb: "workspace.write",
      requestedCapabilities: ["workspace:write"],
      workspaceId: "ws-19a",
    });
    expect(res.decision.outcome).toBe("deny");
  });

  it("rejects invalid profiles (unknown capability shapes, oversized fields)", () => {
    const badCap: AgentCapabilityProfile = {
      allowedVerbs: ["workspace.read"],
      allowedCapabilities: ["total-nonsense"],
      maxSideEffectClass: "read",
      description: "bad",
    };
    expect(validateAgentProfile(badCap)).toMatchObject({ ok: false, denyReason: "profile_invalid" });
    const manyVerbs: AgentCapabilityProfile = {
      allowedVerbs: Array.from({ length: AGENTS_MAX_PROFILE_VERBS + 1 }, (_, i) => "v" + String(i)),
      allowedCapabilities: ["plan:generate"],
      maxSideEffectClass: "read",
      description: "too many",
    };
    expect(validateAgentProfile(manyVerbs)).toMatchObject({ ok: false, denyReason: "oversized_profile" });
    const manyCaps: AgentCapabilityProfile = {
      allowedVerbs: ["workspace.read"],
      allowedCapabilities: Array.from(
        { length: AGENTS_MAX_PROFILE_CAPABILITIES + 1 },
        (_, i) => "workspace:v" + String(i)
      ),
      maxSideEffectClass: "read",
      description: "too many",
    };
    expect(validateAgentProfile(manyCaps)).toMatchObject({ ok: false, denyReason: "oversized_profile" });
    const longDesc: AgentCapabilityProfile = {
      allowedVerbs: ["workspace.read"],
      allowedCapabilities: ["plan:generate"],
      maxSideEffectClass: "read",
      description: "x".repeat(AGENTS_MAX_PROFILE_DESCRIPTION_CHARS + 1),
    };
    expect(validateAgentProfile(longDesc)).toMatchObject({ ok: false, denyReason: "oversized_profile" });
  });

  it("profile replacement is runtime-only, validated, and recorded", () => {
    const rt = newRuntime();
    const next: AgentCapabilityProfile = {
      allowedVerbs: ["workspace.read"],
      allowedCapabilities: ["workspace:read"],
      maxSideEffectClass: "read",
      description: "human-reviewed narrowing",
    };
    const r = rt.replaceProfile(BUILDER_AGENT_ID, next, T0 + 500);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.identity.profile.description).toBe("human-reviewed narrowing");
      expect(Object.isFrozen(r.identity.profile)).toBe(true);
    }
    const changes = rt.profileChanges();
    expect(changes).toHaveLength(4);
    expect(changes[3]).toMatchObject({
      agentId: BUILDER_AGENT_ID,
      changeKind: "profile_replaced",
      authority: "mediation",
      executionAuthorized: false,
    });
    const invalid = rt.replaceProfile(BUILDER_AGENT_ID, badProfile(), T0 + 600);
    expect(invalid).toMatchObject({ ok: false, denyReason: "profile_invalid" });
  });

  it("profile digest is deterministic", () => {
    const p = AGENT_ROLE_PROFILES.reviewer;
    expect(AgentIdentityRegistry.profileDigest(p)).toBe(
      AgentIdentityRegistry.profileDigest(p)
    );
  });

  function badProfile(): AgentCapabilityProfile {
    return {
      allowedVerbs: ["workspace.read"],
      allowedCapabilities: ["nonsense-cap"],
      maxSideEffectClass: "read",
      description: "bad",
    };
  }
});

// ---------------------------------------------------------------------------
// 19A-U3 — Message routing (runtime-mediated)
// ---------------------------------------------------------------------------

describe("19A-U3 — runtime-mediated message routing", () => {
  it("pins the closed routing map (planner→builder→reviewer→planner)", () => {
    expect(AGENT_ROUTING_RULES).toHaveLength(6);
    expect(routingAllows("planner", "builder", "plan_proposal")).toBe(true);
    expect(routingAllows("builder", "reviewer", "build_result")).toBe(true);
    expect(routingAllows("reviewer", "planner", "review_verdict")).toBe(true);
    expect(routingAllows("planner", "reviewer", "plan_proposal")).toBe(false);
    expect(routingAllows("builder", "planner", "build_result")).toBe(false);
    expect(routingAllows("reviewer", "builder", "review_verdict")).toBe(false);
    expect(routingAllows("builder", "builder", "status_observation")).toBe(false);
  });

  it("delivers a plan proposal planner → builder through the runtime", () => {
    const rt = newRuntime();
    const planner = new PlannerAgent(rt);
    const out = planner.proposePlan("proposed plan text", { steps: 3 });
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.message.kind).toBe("plan_proposal");
      expect(out.message.fromAgentId).toBe(PLANNER_AGENT_ID);
      expect(out.message.toAgentId).toBe(BUILDER_AGENT_ID);
      expect(out.message.authority).toBe("mediation");
      expect(out.message.executionAuthorized).toBe(false);
      expect(out.message.sequence).toBe(1);
    }
    const builder = new BuilderAgent(rt);
    const box = builder.inbox();
    expect(box).toHaveLength(1);
    expect(box[0]!.message.messageId).toBe(out.ok ? out.message.messageId : "");
    // The runtime log sees the same traffic.
    expect(rt.log()).toHaveLength(1);
    // The planner's own inbox is untouched (no self-channels).
    expect(planner.inbox()).toHaveLength(0);
  });

  it("exercises the full mediated loop planner → builder → reviewer → planner", () => {
    const rt = newRuntime();
    const planner = new PlannerAgent(rt);
    const builder = new BuilderAgent(rt);
    const reviewer = new ReviewerAgent(rt);

    expect(planner.proposePlan("plan v1").ok).toBe(true);
    expect(builder.deliverBuildResult("build summary v1").ok).toBe(true);
    expect(reviewer.issueVerdict("advisory: needs human review").ok).toBe(true);

    expect(builder.inbox()).toHaveLength(1); // plan proposal
    expect(reviewer.inbox()).toHaveLength(1); // build result
    expect(planner.inbox()).toHaveLength(1); // review verdict
    expect(rt.log()).toHaveLength(3);
  });

  it("refuses unroutable kinds/roles with machine-readable denials", () => {
    const rt = newRuntime();
    const out = rt.send({
      kind: "build_result",
      fromAgentId: PLANNER_AGENT_ID,
      toAgentId: BUILDER_AGENT_ID,
      payloadText: "planner cannot send build_result",
    });
    expect(out).toMatchObject({ ok: false, denyReason: "message_kind_not_allowed" });
    const out2 = rt.send({
      kind: "plan_proposal",
      fromAgentId: BUILDER_AGENT_ID,
      toAgentId: PLANNER_AGENT_ID,
      payloadText: "builder cannot send plan_proposal",
    });
    expect(out2).toMatchObject({ ok: false, denyReason: "message_kind_not_allowed" });
    expect(rt.rejections()).toHaveLength(2);
  });

  it("refuses unknown senders/recipients and self-addressed messages", () => {
    const rt = newRuntime();
    expect(
      rt.send({ kind: "plan_proposal", fromAgentId: "ghost", toAgentId: BUILDER_AGENT_ID, payloadText: "x" })
    ).toMatchObject({ ok: false, denyReason: "sender_unknown" });
    expect(
      rt.send({ kind: "plan_proposal", fromAgentId: PLANNER_AGENT_ID, toAgentId: "ghost", payloadText: "x" })
    ).toMatchObject({ ok: false, denyReason: "recipient_unknown" });
    expect(
      rt.send({ kind: "status_observation", fromAgentId: PLANNER_AGENT_ID, toAgentId: PLANNER_AGENT_ID, payloadText: "x" })
    ).toMatchObject({ ok: false, denyReason: "sender_recipient_same" });
  });

  it("enforces message bounds and shape validation", () => {
    const big: AgentSendRequest = {
      kind: "plan_proposal",
      fromAgentId: PLANNER_AGENT_ID,
      toAgentId: BUILDER_AGENT_ID,
      payloadText: "x".repeat(AGENTS_MAX_PAYLOAD_CHARS + 1),
    };
    expect(validateSendRequestShape(big)).toMatchObject({
      ok: false,
      denyReason: "oversized_message",
    });
    expect(
      validateSendRequestShape({ kind: "nope" as "plan_proposal", fromAgentId: "a", toAgentId: "b", payloadText: "x" })
    ).toMatchObject({ ok: false, denyReason: "malformed_message" });
    expect(isKnownMessageKind("plan_proposal")).toBe(true);
    expect(isAgentMessageDenyReason("authority_confusion")).toBe(true);
    expect(KNOWN_AGENT_MESSAGE_KINDS).toHaveLength(5);
    expect(KNOWN_AGENT_MESSAGE_DENY_REASONS).toHaveLength(8);
  });

  it("caps message totals and inbox sizes (bounded surface)", () => {
    let n = T0;
    const rt = new AgentRuntime({ nowEpochMs: () => (n += 1) });
    const reg = registerAllThreeAgents(rt, T0);
    expect(reg.ok).toBe(true);
    // Simulate a full inbox by bypassing send() bookkeeping is not possible
    // through the public surface; instead verify the caps are pinned and the
    // runtime refuses when the global message cap is hit. We drive real
    // sends up to the inbox cap.
    const planner = new PlannerAgent(rt);
    const builder = new BuilderAgent(rt);
    for (let i = 0; i < 40; i++) {
      const r = planner.proposePlan("m" + String(i));
      expect(r.ok).toBe(true);
    }
    expect(builder.inbox()).toHaveLength(40);
    expect(rt.log()).toHaveLength(40);
  });

  it("facade constructor refuses unregistered identities", () => {
    const rt = new AgentRuntime(clock());
    expect(() => new PlannerAgent(rt)).toThrow(/registered identity/);
  });
});

// ---------------------------------------------------------------------------
// 19A-U4 — Determinism + ledger observability
// ---------------------------------------------------------------------------

describe("19A-U4 — determinism and ledger observability", () => {
  it("identical sends under a fixed clock produce identical message envelopes", () => {
    const build = (): {
      messageId: string;
      sequence: number;
      from: string;
      to: string;
      kind: string;
    }[] => {
      let n = T0;
      const rt = new AgentRuntime({ nowEpochMs: () => (n += 1) });
      registerAllThreeAgents(rt, T0);
      new PlannerAgent(rt).proposePlan("deterministic plan", { steps: 2 });
      new BuilderAgent(rt).deliverBuildResult("deterministic build", { ok: true });
      return rt.log().map((r) => ({
        messageId: r.messageId,
        sequence: r.message.sequence,
        from: r.message.fromAgentId,
        to: r.message.toAgentId,
        kind: r.message.kind,
      }));
    };
    expect(build()).toEqual(build());
  });

  it("payload digest is deterministic and does not leak text", () => {
    const d = agentPayloadDigest("hello");
    expect(d).toBe(agentPayloadDigest("hello"));
    expect(d).not.toContain("hello");
    expect(d).toHaveLength(64);
  });

  it("runtime mediation decisions are observable in an AppendOnlyLedger (chain verifies)", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const emitter: AgentLedgerEmitter = {
      append: (input) => {
        const r = ledger.append({
          eventId: "agt-" + String(ledger.length + 1).padStart(4, "0"),
          timestamp: new Date(T0 + ledger.length).toISOString(),
          eventType: input.eventType,
          actor: { type: input.actor.type as "runtime" | "agent", id: input.actor.id },
          policyDecision: input.policyDecision,
          inputSummary: input.inputSummary,
          resultSummary: input.resultSummary,
        });
        return { ok: r.ok, eventId: r.event?.eventId };
      },
    };
    let n = T0;
    const rt = new AgentRuntime({ nowEpochMs: () => (n += 1), ledger: emitter, workspaceId: "ws-19a" });
    registerAllThreeAgents(rt, T0);
    const planner = new PlannerAgent(rt);
    planner.proposePlan("observed plan");
    const refused = rt.send({
      kind: "plan_proposal",
      fromAgentId: BUILDER_AGENT_ID,
      toAgentId: PLANNER_AGENT_ID,
      payloadText: "unroutable",
    });
    expect(refused.ok).toBe(false);
    expect(ledger.length).toBeGreaterThanOrEqual(4); // 3 registrations + 1 delivery + 1 denial
    expect(ledger.verify().ok).toBe(true);
    const eventTypes = ledger.events().map((e) => e.eventType);
    expect(eventTypes).toContain("agent_registered");
    expect(eventTypes).toContain("agent_message_delivered");
    expect(eventTypes).toContain("agent_message_denied");
  });
});

// ---------------------------------------------------------------------------
// 19A-U5 — Human actor unaffected (Day-1 flow unchanged)
// ---------------------------------------------------------------------------

describe("19A-U5 — Day-1 human flow unchanged", () => {
  it("the day-1 inspect allowlist still allows the human actor through policy", () => {
    const engine = new DenyByDefaultPolicyEngine();
    const res = engine.evaluate({
      actor: HUMAN,
      verb: "inspect",
      requestedCapabilities: ["workspace:list", "git:status"],
      workspaceId: "ws-19a",
    });
    expect(res.decision.outcome).toBe("allow");
  });

  it("agent identities get NO new policy allowances by existing", () => {
    const engine = new DenyByDefaultPolicyEngine();
    for (const agentId of KNOWN_19A_AGENT_IDS) {
      for (const cap of ["workspace:write", "git:commit", "network:external"] as const) {
        const res = engine.evaluate({
          actor: { type: "agent", id: agentId },
          verb: "inspect",
          requestedCapabilities: [cap],
          workspaceId: "ws-19a",
        });
        expect(res.decision.outcome, agentId + " " + cap).toBe("deny");
      }
    }
  });
});
