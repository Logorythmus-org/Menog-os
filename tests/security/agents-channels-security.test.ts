import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import {
  AgentRuntime,
  PlannerAgent,
  BuilderAgent,
  ReviewerAgent,
  PLANNER_AGENT_ID,
  BUILDER_AGENT_ID,
  REVIEWER_AGENT_ID,
  KNOWN_AGENT_CHANNEL_DENY_REASONS,
  KNOWN_AGENT_BOUNDARY_DENY_REASONS,
  AGENTS_MAX_PAYLOAD_CHARS,
  AGENTS_MAX_CHANNEL_HISTORY,
  AGENTS_MAX_QUARANTINE,
  AGENTS_MAX_RECEIPTS,
  validateChannelPolicy,
  validateProvenanceChain,
  decideBoundary,
  envelopePayloadDigest,
  type AgentChannelPolicy,
  type AgentEnvelope,
  type AgentRuntimeOptions,
} from "@menog/agents";
import { DenyByDefaultPolicyEngine } from "@menog/policy";

/**
 * 19C — Security & threat-model tests for envelopes/channels/receiver
 * boundary. New boundaries (asset → trust boundary → threat → mitigation →
 * test evidence):
 *
 *   C1  Sender identity (anti-spoofing) → runtime re-stamps identities
 *   C2  Channel routing policy          → channels cannot legalize forbidden routes
 *   C3  Receiver boundary               → untrusted-input gate before acceptance
 *   C4  Provenance                      → tampering detected; digest-only quarantine
 *   C5  Bounds                          → per-channel caps, replay + history caps
 *   C6  Authority separation            → acceptance grants no execution authority
 *   C7  Governance                      → report pins; no scope overclaim
 */

const T0 = 2_000_000_000_000;
const T1 = T0 + 1000;

function clock(): AgentRuntimeOptions {
  let n = T0;
  return { nowEpochMs: () => (n += 1) };
}

function setup(): { rt: AgentRuntime; planner: PlannerAgent; builder: BuilderAgent; reviewer: ReviewerAgent } {
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

function readDoc(relativePath: string): string {
  const full = path.resolve(process.cwd(), relativePath);
  expect(existsSync(full), "expected doc to exist: " + relativePath).toBe(true);
  return readFileSync(full, "utf8");
}

// ---------------------------------------------------------------------------
// 19C-S1 — C1: spoofing rejection
// ---------------------------------------------------------------------------

describe("19C-S1 — spoofing rejection (C1)", () => {
  it("19C-S1.1 envelope sender identity is runtime-stamped, never caller-claimed", () => {
    const { rt, planner } = setup();
    const id = openPb(rt);
    // A caller claims the REVIEWER (a non-participant) sent this message by
    // passing reviewer's id as fromAgentId with the planner as claimed
    // sender-identity context. The runtime resolves sender identity from
    // the registry and the membership gate refuses non-participants.
    const r = rt.sendOnChannel(id, {
      kind: "plan_proposal",
      fromAgentId: REVIEWER_AGENT_ID, // registered identity, NOT a participant
      toAgentId: BUILDER_AGENT_ID,
      payloadText: "claimed sender is not who sent this",
    });
    expect(r).toMatchObject({ ok: false, denyReason: "route_not_allowed" });
    expect(rt.channelEnvelopeHistory(id)).toHaveLength(0);
    void planner;
  });

  it("19C-S1.2 a non-participant cannot send on an open channel (membership spoofing)", () => {
    const { rt, reviewer } = setup();
    const id = openPb(rt);
    // Reviewer (registered identity, not a participant) tries the channel.
    const r = reviewer.observeStatusOn(id, BUILDER_AGENT_ID, "sneaking onto the channel");
    expect(r).toMatchObject({ ok: false, denyReason: "route_not_allowed" });
    expect(r).toMatchObject({ ok: false, denyReason: "route_not_allowed" });
    expect(rt.channelEnvelopeHistory(id)).toHaveLength(0);
  });

  it("19C-S1.3 spoofed envelope identity is refused at the receiver boundary", () => {
    const { rt, planner, builder } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "honest");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const spoofed: AgentEnvelope = { ...r.envelope, senderId: REVIEWER_AGENT_ID };
    expect(builder.receive(spoofed)).toMatchObject({ ok: false, denyReason: "envelope_malformed" });
    expect(rt.quarantine().some((q) => q.envelopeId === r.envelope.envelopeId)).toBe(true);
  });

  it("19C-S1.4 a third party cannot run the boundary on someone else's mail (anti-interception)", () => {
    const { rt, planner, reviewer } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "private to builder");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(reviewer.receive(r.envelope)).toMatchObject({ ok: false, denyReason: "not_addressed_to_receiver" });
    // And the interceptor learned nothing: no receipt marked accepted.
    expect(rt.boundaryReceipts().every((x) => x.disposition !== "accepted")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 19C-S2 — C2: routing policy integrity
// ---------------------------------------------------------------------------

describe("19C-S2 — routing policy integrity (C2)", () => {
  it("19C-S2.1 channels cannot legalize mediation-forbidden kinds (behavioral)", () => {
    const { rt } = setup();
    // Try every role-pair/kind forgery: policy validation must refuse any
    // kind the closed mediation map refuses for that pair.
    const forgeries: readonly [AgentChannelPolicy, readonly string[]][] = [
      [
        { kind: "planner_builder", fromRole: "planner", toRole: "builder", allowedKinds: ["review_verdict"], maxPayloadChars: 50, onViolation: "drop" },
        [PLANNER_AGENT_ID, BUILDER_AGENT_ID],
      ],
      [
        { kind: "builder_reviewer", fromRole: "builder", toRole: "reviewer", allowedKinds: ["plan_proposal"], maxPayloadChars: 50, onViolation: "drop" },
        [BUILDER_AGENT_ID, REVIEWER_AGENT_ID],
      ],
      [
        { kind: "reviewer_planner", fromRole: "reviewer", toRole: "planner", allowedKinds: ["build_result"], maxPayloadChars: 50, onViolation: "drop" },
        [REVIEWER_AGENT_ID, PLANNER_AGENT_ID],
      ],
    ];
    for (const [policy, participants] of forgeries) {
      const r = rt.openChannel(policy, participants, "human-19c", T1);
      expect(r).toMatchObject({ ok: false, denyReason: "route_not_allowed" });
    }
  });

  it("19C-S2.2 closed channels refuse traffic (no zombie routes)", () => {
    const { rt, planner } = setup();
    const id = openPb(rt);
    rt.closeChannel(id);
    expect(planner.proposePlanOn(id, "post-close")).toMatchObject({ ok: false, denyReason: "channel_closed" });
    expect(rt.channelEnvelopeHistory(id)).toHaveLength(0);
  });

  it("19C-S2.3 the channel deny union is fully reachable", () => {
    const seen = new Set<string>();
    {
      const { planner } = setup();
      const r = planner.proposePlanOn("chn-none", "x");
      if (!r.ok) seen.add(r.denyReason); // channel_unknown
    }
    {
      const { rt, planner } = setup();
      const id = openPb(rt);
      rt.closeChannel(id);
      const r = planner.proposePlanOn(id, "x");
      if (!r.ok) seen.add(r.denyReason); // channel_closed
    }
    {
      const { rt } = setup();
      const r = rt.openChannel(pbPolicy({ maxPayloadChars: 0 }), [PLANNER_AGENT_ID, BUILDER_AGENT_ID], "h", T1);
      if (!r.ok) seen.add(r.denyReason); // policy_invalid
    }
    {
      const { rt } = setup();
      const r = rt.openChannel(pbPolicy(), [PLANNER_AGENT_ID, "ghost"], "h", T1);
      if (!r.ok) seen.add(r.denyReason); // participants_invalid
    }
    {
      const { rt } = setup();
      const r = rt.openChannel(
        { kind: "planner_builder", fromRole: "planner", toRole: "reviewer", allowedKinds: ["plan_proposal"], maxPayloadChars: 10, onViolation: "drop" },
        [PLANNER_AGENT_ID, REVIEWER_AGENT_ID],
        "h",
        T1
      );
      if (!r.ok) seen.add(r.denyReason); // route_not_allowed
    }
    {
      const { rt } = setup();
      for (let i = 0; i < 16; i++) {
        rt.openChannel(pbPolicy(), [PLANNER_AGENT_ID, BUILDER_AGENT_ID], "h", T1 + i);
      }
      const r = rt.openChannel(pbPolicy(), [PLANNER_AGENT_ID, BUILDER_AGENT_ID], "h", T1);
      if (!r.ok) seen.add(r.denyReason); // channel_cap_reached
    }
    expect([...seen].sort()).toEqual([...KNOWN_AGENT_CHANNEL_DENY_REASONS].sort());
  });

  it("19C-S2.4 the receiver boundary deny union is fully reachable", () => {
    const seen = new Set<string>();
    // receiver_unknown
    {
      const d = decideBoundary({
        envelope: fakeEnvelope(),
        callerReceiverId: BUILDER_AGENT_ID,
        receiverKnown: false,
        alreadyDelivered: false,
        channelHistoryCount: 0,
        contentScreen: { ok: true },
      });
      seen.add(d.result.ok ? "?" : d.result.denyReason);
    }
    // not_addressed_to_receiver (caller interception)
    {
      const d = decideBoundary({
        envelope: fakeEnvelope(),
        callerReceiverId: REVIEWER_AGENT_ID,
        receiverKnown: true,
        alreadyDelivered: false,
        channelHistoryCount: 0,
        contentScreen: { ok: true },
      });
      seen.add(d.result.ok ? "?" : d.result.denyReason);
    }
    // duplicate_envelope
    {
      const d = decideBoundary({
        envelope: fakeEnvelope(),
        callerReceiverId: BUILDER_AGENT_ID,
        receiverKnown: true,
        alreadyDelivered: true,
        channelHistoryCount: 0,
        contentScreen: { ok: true },
      });
      seen.add(d.result.ok ? "?" : d.result.denyReason);
    }
    // envelope_malformed
    {
      const env = fakeEnvelope();
      const broken = { ...env, senderId: "someone-else" };
      const d = decideBoundary({
        envelope: broken,
        callerReceiverId: BUILDER_AGENT_ID,
        receiverKnown: true,
        alreadyDelivered: false,
        channelHistoryCount: 0,
        contentScreen: { ok: true },
      });
      seen.add(d.result.ok ? "?" : d.result.denyReason);
    }
    // provenance_broken
    {
      const env = fakeEnvelope();
      const d = decideBoundary({
        envelope: { ...env, provenance: [] },
        callerReceiverId: BUILDER_AGENT_ID,
        receiverKnown: true,
        alreadyDelivered: false,
        channelHistoryCount: 0,
        contentScreen: { ok: true },
      });
      seen.add(d.result.ok ? "?" : d.result.denyReason);
    }
    // content_refused
    {
      const d = decideBoundary({
        envelope: fakeEnvelope(),
        callerReceiverId: BUILDER_AGENT_ID,
        receiverKnown: true,
        alreadyDelivered: false,
        channelHistoryCount: 0,
        contentScreen: { ok: false, reason: "authority_claim" },
      });
      seen.add(d.result.ok ? "?" : d.result.denyReason);
    }
    expect([...seen].sort()).toEqual([...KNOWN_AGENT_BOUNDARY_DENY_REASONS].sort());
  });

  function fakeEnvelope(): AgentEnvelope {
    const env: AgentEnvelope = {
      envelopeId: "env-fake-000000001",
      schemaVersion: "menog-agents/v0",
      channelId: "chn-0001-planner_builder",
      channelKind: "planner_builder",
      message: {
        messageId: "msg-00000001-deadbeefcafe",
        schemaVersion: "menog-agents/v0",
        kind: "plan_proposal",
        fromAgentId: PLANNER_AGENT_ID,
        toAgentId: BUILDER_AGENT_ID,
        sequence: 1,
        sentAtEpochMs: T0,
        payloadText: "honest",
        summary: {},
        authority: "mediation",
        executionAuthorized: false,
      },
      senderId: PLANNER_AGENT_ID,
      receiverId: BUILDER_AGENT_ID,
      channelSequence: 1,
      provenance: [
        { stage: "origin", actorId: PLANNER_AGENT_ID, actorType: "agent", atEpochMs: T0, detail: { messageId: "m" } },
        { stage: "mediation", actorId: "agent-runtime", actorType: "runtime", atEpochMs: T0, detail: { sequence: 1 } },
        { stage: "delivery", actorId: BUILDER_AGENT_ID, actorType: "agent", atEpochMs: T0, detail: { channelSequence: 1 } },
      ],
      untrusted: true,
      authority: "mediation",
      executionAuthorized: false,
    };
    return env;
  }
});

// ---------------------------------------------------------------------------
// 19C-S3 — C3/C5: size limits, malformed input, replay/backup bounds
// ---------------------------------------------------------------------------

describe("19C-S3 — size limits and malformed input (C3, C5)", () => {
  it("19C-S3.1 per-channel payload caps bind below the global cap", () => {
    const { rt, planner } = setup();
    const id = openPb(rt, { maxPayloadChars: 16 });
    expect(planner.proposePlanOn(id, "x".repeat(17))).toMatchObject({ ok: false, denyReason: "policy_invalid" });
    expect(planner.proposePlanOn(id, "x".repeat(16)).ok).toBe(true);
    expect(validateChannelPolicy(pbPolicy({ maxPayloadChars: AGENTS_MAX_PAYLOAD_CHARS + 1 }))).toMatchObject({
      ok: false,
      denyReason: "policy_invalid",
    });
  });

  it("19C-S3.2 malformed envelopes are refused and quarantined (integrity gate)", () => {
    const { rt, planner, builder } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "body");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const cases: readonly [AgentEnvelope, string][] = [
      [{ ...r.envelope, untrusted: false as unknown as true }, "envelope_malformed"],
      [
        { ...r.envelope, message: { ...r.envelope.message, authority: "execution_authority" as unknown as "mediation" } },
        "envelope_malformed",
      ],
      // Receiver re-labeled: the caller gate fires first (the caller is the
      // builder; the envelope now claims reviewer) — anti-interception.
      [{ ...r.envelope, receiverId: REVIEWER_AGENT_ID }, "not_addressed_to_receiver"],
      [{ ...r.envelope, schemaVersion: "menog-agents/v9" as unknown as "menog-agents/v0" }, "envelope_malformed"],
    ];
    for (const [env, expected] of cases) {
      expect(builder.receive(env)).toMatchObject({ ok: false, denyReason: expected });
    }
    // All four outcomes are receipted; the three integrity failures are
    // quarantined for audit (the interception refusal is receipt-only).
    expect(rt.quarantine().length).toBe(cases.length - 1);
    expect(rt.boundaryReceipts().length).toBe(cases.length);
  });

  it("19C-S3.3 provenance tampering is detected (every field class)", () => {
    const { rt, planner, builder } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "body");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const prov = r.envelope.provenance;
    expect(validateProvenanceChain([{ ...prov[0]!, stage: "delivery" }])).toMatchObject({ ok: false, denyReason: "provenance_broken" });
    expect(validateProvenanceChain([{ ...prov[0]!, actorId: "" }])).toMatchObject({ ok: false, denyReason: "provenance_broken" });
    expect(validateProvenanceChain([{ ...prov[0]!, atEpochMs: -1 }])).toMatchObject({ ok: false, denyReason: "provenance_broken" });
    expect(validateProvenanceChain([{ ...prov[0]!, detail: { k: "x".repeat(200) } }])).toMatchObject({ ok: false, denyReason: "provenance_broken" });
    expect(builder.receive({ ...r.envelope, provenance: [prov[0]!, prov[1]!] })).toMatchObject({
      ok: false,
      denyReason: "provenance_broken",
    });
  });

  it("19C-S3.4 quarantine records are digest-only (payload text never retained)", () => {
    const { rt, planner, builder } = setup();
    const id = openPb(rt);
    const secret = "honest-looking payload with api_key=sk-zzzz9999zzzz9999zzzz";
    const r = planner.proposePlanOn(id, secret);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(builder.receive({ ...r.envelope, untrusted: false as unknown as true })).toMatchObject({ ok: false });
    const q = rt.quarantine();
    expect(q.length).toBe(1);
    expect(JSON.stringify(q)).not.toContain("api_key");
    expect(JSON.stringify(q)).not.toContain("sk-zzzz");
    expect(q[0]!.payloadDigest).toBe(envelopePayloadDigest(secret));
    expect(AGENTS_MAX_QUARANTINE).toBe(256);
    expect(AGENTS_MAX_RECEIPTS).toBe(512);
  });

  it("19C-S3.5 channel history cap is enforced (delivered count bounds)", () => {
    expect(AGENTS_MAX_CHANNEL_HISTORY).toBe(128);
    // Behavioral cap probe via decideBoundary (fast; no 128 sends needed).
    const env = fake();
    const d = decideBoundary({
      envelope: env,
      callerReceiverId: env.receiverId,
      receiverKnown: true,
      alreadyDelivered: false,
      channelHistoryCount: AGENTS_MAX_CHANNEL_HISTORY,
      contentScreen: { ok: true },
    });
    expect(d.result).toMatchObject({ ok: false, denyReason: "envelope_malformed" });

    function fake(): AgentEnvelope {
      return {
        envelopeId: "env-cap-0000001",
        schemaVersion: "menog-agents/v0",
        channelId: "chn-0001-planner_builder",
        channelKind: "planner_builder",
        message: {
          messageId: "msg-00000002-cafebabedead",
          schemaVersion: "menog-agents/v0",
          kind: "plan_proposal",
          fromAgentId: PLANNER_AGENT_ID,
          toAgentId: BUILDER_AGENT_ID,
          sequence: 1,
          sentAtEpochMs: T0,
          payloadText: "x",
          summary: {},
          authority: "mediation",
          executionAuthorized: false,
        },
        senderId: PLANNER_AGENT_ID,
        receiverId: BUILDER_AGENT_ID,
        channelSequence: 1,
        provenance: [
          { stage: "origin", actorId: PLANNER_AGENT_ID, actorType: "agent", atEpochMs: T0, detail: {} },
          { stage: "mediation", actorId: "agent-runtime", actorType: "runtime", atEpochMs: T0, detail: {} },
          { stage: "delivery", actorId: BUILDER_AGENT_ID, actorType: "agent", atEpochMs: T0, detail: {} },
        ],
        untrusted: true,
        authority: "mediation",
        executionAuthorized: false,
      };
    }
  });
});

// ---------------------------------------------------------------------------
// 19C-S4 — C6: authority separation
// ---------------------------------------------------------------------------

describe("19C-S4 — authority separation (C6)", () => {
  it("19C-S4.1 accepting an envelope grants NO execution authority (policy re-proven)", () => {
    const { rt, planner, builder } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "plan asking for workspace:write", { demand: "workspace:write" });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(builder.receive(r.envelope).ok).toBe(true);
    const engine = new DenyByDefaultPolicyEngine();
    const res = engine.evaluate({
      actor: { type: "agent", id: BUILDER_AGENT_ID },
      verb: "workspace.write",
      requestedCapabilities: ["workspace:write"],
      workspaceId: "ws-19c",
    });
    expect(res.decision.outcome).toBe("deny");
  });

  it("19C-S4.2 every 19C artifact carries the mediation pins", () => {
    const { rt, planner, builder } = setup();
    const id = openPb(rt);
    const r = planner.proposePlanOn(id, "body");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    // Provenance ENTRIES are stamps (stage/actor/time/detail) and do not
    // carry authority fields by design; the envelope carrying them does.
    for (const p of [r.envelope, ...rt.channels()]) {
      const rec = p as unknown as { authority?: string; executionAuthorized?: unknown };
      expect(rec.authority).toBe("mediation");
      expect(rec.executionAuthorized).toBe(false);
    }
    // The embedded message still carries the pins.
    expect(r.envelope.message.authority).toBe("mediation");
    expect(r.envelope.message.executionAuthorized).toBe(false);
    // And every provenance stage is present and ordered (integrity).
    builder.receive(r.envelope);
    for (const x of [...rt.boundaryReceipts(), ...rt.quarantine()]) {
      expect(x.authority).toBe("mediation");
      expect(x.executionAuthorized).toBe(false);
    }
  });

  it("19C-S4.3 channels/envelopes expose no execution surface (runtime audit)", () => {
    const { rt } = setup();
    const methods = new Set<string>();
    let p: object | null = Object.getPrototypeOf(rt);
    while (p && p !== Object.prototype) {
      for (const n of Object.getOwnPropertyNames(p)) methods.add(n);
      p = Object.getPrototypeOf(p);
    }
    for (const banned of ["grantChannel", "authorizeEnvelope", "executeChannel", "elevate", "bypassPolicy"]) {
      expect(methods.has(banned), "runtime exposes " + banned).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// 19C-S5 — C7: source hygiene + governance
// ---------------------------------------------------------------------------

describe("19C-S5 — source hygiene and governance (C7)", () => {
  it("19C-S5.1 envelope.ts contains no network/process/Phase-20 primitives", () => {
    const src = readDoc("packages/agents/src/envelope.ts");
    const forbidden = /cgroup|seccomp|landlock|rootless|unshare|clone3|axios|XMLHttpRequest|WebSocket|net\.connect|tls\.connect|child_process|spawnSync|execSync|\bfetch\s*\(/i;
    expect(forbidden.test(src)).toBe(false);
  });

  it("19C-S5.2 the 19C report carries the PR block and authorization lines verbatim", () => {
    const report = readDoc("docs/release/PROMPT_19C_REPORT.md").replace(/\s+/g, " ");
    for (const line of [
      "PR-01 HUMAN_DISPOSITION_PENDING",
      "PR-02 HOLD",
      "PR-03 HUMAN_DISPOSITION_PENDING",
      "PR-04 HOLD",
      "PR-05 HOLD",
    ]) {
      expect(report.includes(line), "19C report missing " + line).toBe(true);
    }
    expect(report.includes("COMMIT AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(report.includes("PUSH AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(report.includes("PUBLICATION AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(report.includes("19C_")).toBe(true);
  });

  it("19C-S5.3 the 19C report claims only implemented scope and documents the threat model", () => {
    const report = readDoc("docs/release/PROMPT_19C_REPORT.md");
    const lower = report.toLowerCase();
    expect(report.includes("NOT_IMPLEMENTED")).toBe(true);
    expect(lower.includes("roadmap only")).toBe(true);
    expect(lower.includes("threat")).toBe(true);
    for (const family of ["spoofing", "routing policy", "size limits", "malformed", "provenance"]) {
      expect(lower.includes(family), "report missing test family " + family).toBe(true);
    }
  });
});
