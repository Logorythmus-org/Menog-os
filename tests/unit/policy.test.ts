import { describe, it, expect } from "vitest";
import {
  DenyByDefaultPolicyEngine,
  CAPABILITY_IDS,
  DAY1_INSPECT_CAPABILITIES,
  DAY1_FORBIDDEN_CAPABILITIES,
  type PolicyRequest,
} from "@menog/policy";
import { AppendOnlyLedger as Ledger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";

const AGENT: Actor = { type: "agent", id: "agent-day1" };
const HUMAN: Actor = { type: "human", id: "human-0" };

function inspectReq(
  capabilities: PolicyRequest["requestedCapabilities"],
  overrides: Partial<PolicyRequest> = {}
): PolicyRequest {
  return {
    requestId: "req-" + Math.random().toString(36).slice(2, 8),
    actor: AGENT,
    verb: "inspect",
    requestedCapabilities: capabilities,
    workspaceId: "ws-day1",
    taskId: "task-day1",
    commandHint: overrides.commandHint,
    ...overrides,
  };
}

describe("Prompt 05 — explicit deny tests (5 required classes)", () => {
  const engine = new DenyByDefaultPolicyEngine();

  it("denies write requests (workspace:write)", () => {
    const r = engine.evaluate(inspectReq(["workspace:write"]));
    expect(r.decision.outcome).toBe("deny");
    expect(r.decision.matchedRule).toContain("rule:day1:deny-workspace-write");
    expect(r.deniedCapabilities).toContain("workspace:write");
    expect(r.allowedCapabilities).toHaveLength(0);
    expect(r.decision.riskClass).toBe("high");
    expect(r.decision.requiresHumanApproval).toBe(true);
    expect(DAY1_FORBIDDEN_CAPABILITIES).toContain("workspace:write");
  });

  it("denies network requests (network:external)", () => {
    const r = engine.evaluate(inspectReq(["workspace:list", "network:external"]));
    expect(r.decision.outcome).toBe("deny");
    expect(r.decision.matchedRule).toContain("rule:day1:deny-network-external");
    expect(r.deniedCapabilities).toContain("network:external");
    expect(r.allowedCapabilities).toEqual(["workspace:list"]);
    expect(r.decision.riskClass).toBe("critical");
  });

  it("denies privileged requests (process:privileged)", () => {
    const r = engine.evaluate(inspectReq(["process:privileged"]));
    expect(r.decision.outcome).toBe("deny");
    expect(r.decision.matchedRule).toContain("rule:day1:deny-process-privileged");
    expect(r.deniedCapabilities).toContain("process:privileged");
    expect(r.decision.riskClass).toBe("critical");
    expect(r.decision.requiresHumanApproval).toBe(true);
  });

  it("denies git:commit", () => {
    const r = engine.evaluate(
      inspectReq(["git:commit"], { verb: "commit", actor: HUMAN })
    );
    expect(r.decision.outcome).toBe("deny");
    expect(r.decision.matchedRule).toContain("rule:day1:deny-git-commit");
    expect(r.deniedCapabilities).toContain("git:commit");
    expect(r.decision.riskClass).toBe("critical");
    expect(r.decision.requiresHumanApproval).toBe(true);
  });

  it("denies unknown capability IDs", () => {
    const r = engine.evaluate(
      inspectReq(
        ["workspace:list", "workspace:totally-made-up-cap"] as unknown as PolicyRequest["requestedCapabilities"]
      )
    );
    expect(r.decision.outcome).toBe("deny");
    const unknown = (r.deniedCapabilities as unknown as string[]).find((s) =>
      s.includes("made-up")
    );
    expect(unknown).toBeDefined();
    const perCap = r.perCapability as Record<string, { matchedRule: string }>;
    expect(perCap["workspace:totally-made-up-cap"]!.matchedRule).toBe(
      "rule:unknown-capability"
    );
  });

  it("default deny: empty capabilities → deny", () => {
    const r = engine.evaluate(inspectReq([]));
    expect(r.decision.outcome).toBe("deny");
    expect(r.decision.matchedRule).toBe("rule:default-deny-empty-request");
    expect(r.decision.reason).toContain("no capabilities requested");
  });

  it("default deny: any verb other than inspect → deny even for read caps", () => {
    const req = inspectReq(
      DAY1_INSPECT_CAPABILITIES as unknown as PolicyRequest["requestedCapabilities"],
      { verb: "execute" }
    );
    const r = engine.evaluate(req);
    expect(r.decision.outcome).toBe("deny");
    expect(r.decision.matchedRule).toContain("rule:day1:deny-non-inspect-verb");
  });
});

describe("Prompt 05 — inspect allowlist happy path", () => {
  const engine = new DenyByDefaultPolicyEngine();

  it("allows verb=inspect + the 4 inspect caps with allow + no human approval", () => {
    const r = engine.evaluate(
      inspectReq(
        DAY1_INSPECT_CAPABILITIES as unknown as PolicyRequest["requestedCapabilities"]
      )
    );
    expect(r.decision.outcome).toBe("allow");
    expect([...r.allowedCapabilities].sort()).toEqual(
      [...DAY1_INSPECT_CAPABILITIES].sort()
    );
    expect(r.deniedCapabilities).toHaveLength(0);
    expect(r.decision.matchedRule).toBe(
      "rule:day1:allow-inspect-readonly-aggregate"
    );
    expect(r.decision.requiresHumanApproval).toBe(false);
    const riskOrder = ["none", "low", "medium", "high", "critical"] as const;
    const allowRiskIdx = riskOrder.indexOf(
      r.decision.riskClass as (typeof riskOrder)[number]
    );
    expect(allowRiskIdx).toBeLessThanOrEqual(riskOrder.indexOf("low"));
  });

  it("denies commandHint containing forbidden tokens (git commit / pipe / redir)", () => {
    const r = engine.evaluate(
      inspectReq(["git:diff-read"], { commandHint: "git commit -m oops" })
    );
    expect(r.decision.outcome).toBe("deny");
    expect(r.decision.matchedRule).toContain(
      "rule:day1:deny-command-not-on-allowlist"
    );
    expect(r.decision.riskClass).toBe("critical");
  });

  it("DAY1_FORBIDDEN_CAPABILITIES contains all 5 prompt-specified deny classes", () => {
    const want = [
      "workspace:write",
      "git:commit",
      "network:external",
      "process:privileged",
      "process:execute-write",
    ] as const;
    for (const c of want) expect(DAY1_FORBIDDEN_CAPABILITIES).toContain(c);
  });
});

describe("Prompt 05 — every decision emits a ledger event (authoritative rule)", () => {
  it("allow decision → 1 policy_decision event in ledger with policyDecision=allow", () => {
    const ledger = Ledger.inMemory();
    const engine = DenyByDefaultPolicyEngine.with(ledger);
    expect(ledger.length).toBe(0);
    engine.evaluate(inspectReq(["workspace:list", "git:status"]));
    expect(ledger.length).toBe(1);
    const ev = ledger.events()[0]!;
    expect(ev.eventType).toBe("policy_decision");
    expect(ev.policyDecision).toBe("allow");
    expect(ev.actor.type).toBe("runtime");
    expect(ev.actor.id).toBe("policy-engine");
    const result = ev.resultSummary as Record<string, unknown>;
    expect(result.outcome).toBe("allow");
    expect(result.authoritativeRuleId).toBe("menog-policy-v0");
    expect(result.allowedCapabilities).toEqual(["workspace:list", "git:status"]);
    expect(ledger.verify().ok).toBe(true);
  });

  it("deny decision → 1 policy_decision event in ledger with policyDecision=deny + hash chain intact", () => {
    const ledger = Ledger.inMemory();
    const engine = DenyByDefaultPolicyEngine.with(ledger);
    engine.evaluate(inspectReq(["workspace:write", "network:external"]));
    expect(ledger.length).toBe(1);
    const ev = ledger.events()[0]!;
    expect(ev.policyDecision).toBe("deny");
    const rs = ev.resultSummary as Record<string, unknown>;
    expect(rs.outcome).toBe("deny");
    expect((rs.deniedCapabilities as string[]).sort()).toEqual(
      ["network:external", "workspace:write"].sort()
    );
    expect(ev.previousHash).toMatch(/^0{64}$/);
  });

  it("3 sequential decisions → 3 events, order preserved, verify() passes", () => {
    const ledger = Ledger.inMemory();
    const engine = DenyByDefaultPolicyEngine.with(ledger);
    engine.evaluate(inspectReq(["workspace:list"]));
    engine.evaluate(inspectReq(["network:external"]));
    engine.evaluate(
      inspectReq(
        DAY1_INSPECT_CAPABILITIES as unknown as PolicyRequest["requestedCapabilities"]
      )
    );
    expect(ledger.length).toBe(3);
    const ids = ledger.events().map((e: { eventId: string }) => e.eventId);
    expect(new Set(ids).size).toBe(3);
    const events = ledger.events();
    expect(events[0]!.previousHash).toMatch(/^0{64}$/);
    expect(events[1]!.previousHash).toBe(events[0]!.hash);
    expect(events[2]!.previousHash).toBe(events[1]!.hash);
    expect(ledger.verify().ok).toBe(true);
  });
});

describe("Prompt 05 — deny by default at data-structure level (16 caps explicit)", () => {
  it("CAPABILITY_IDS has exactly 16 entries", () => {
    expect(CAPABILITY_IDS).toHaveLength(16);
  });

  it("perCapability map entries for unrequested caps all show deny outcome", () => {
    const engine = new DenyByDefaultPolicyEngine();
    const r = engine.evaluate(inspectReq(["workspace:list"]));
    for (const cap of CAPABILITY_IDS) {
      const d = r.perCapability[cap];
      if (cap === "workspace:list") continue;
      expect(d.outcome).toBe("deny");
      expect(d.reason.length).toBeGreaterThan(0);
      expect(d.matchedRule.length).toBeGreaterThan(0);
    }
  });
});
