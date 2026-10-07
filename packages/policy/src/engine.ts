import { randomUUID } from "node:crypto";
import type { AppendOnlyLedger } from "@menog/event-ledger";
import type {
  PolicyEngine,
  PolicyRequest,
  PolicyResult,
  PolicyDecisionRecord,
} from "./types.js";
import {
  CAPABILITY_IDS,
  CAPABILITY_EFFECT_TABLE,
  DAY1_INSPECT_CAPABILITIES,
  DAY1_FORBIDDEN_CAPABILITIES,
  isCapabilityId,
  riskClassFor,
  requiresHumanApprovalFor,
  type CapabilityId,
  type RiskClass,
} from "./capabilities.js";
import type { MenogEventInput } from "@menog/core";

type PerCapabilityDecision = Record<CapabilityId, PolicyDecisionRecord>;
type MutablePerCapMap = Record<string, PolicyDecisionRecord>;

function maxRisk(a: RiskClass, b: RiskClass): RiskClass {
  const order: Record<RiskClass, number> = {
    none: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };
  return order[a] >= order[b] ? a : b;
}

function allowDecision(rule: string, cap: CapabilityId): PolicyDecisionRecord {
  return {
    outcome: "allow",
    reason: "capability '" + cap + "' on verb 'inspect' in day-1 allowlist",
    matchedRule: rule,
    riskClass: riskClassFor(cap),
    requiresHumanApproval: requiresHumanApprovalFor(cap),
  };
}

function denyDecision(
  rule: string,
  reason: string,
  riskClass: RiskClass,
  humanApproval: boolean = false
): PolicyDecisionRecord {
  return {
    outcome: "deny",
    reason,
    matchedRule: rule,
    riskClass,
    requiresHumanApproval: humanApproval,
  };
}

function baseUnknownEventInput(
  request: PolicyRequest,
  now: string,
  overrides: Partial<MenogEventInput> = {}
): MenogEventInput {
  const caps = request.requestedCapabilities.slice().sort().join("+");
  const evt: MenogEventInput = {
    eventId: "pol-" + randomUUID().replace(/-/g, "").slice(0, 24),
    timestamp: now,
    eventType: "policy_decision",
    actor: { type: "runtime", id: "policy-engine" },
    workspaceId: request.workspaceId,
    taskId: request.taskId,
    verb: request.verb,
    capability: caps || "none",
    policyDecision: "allow",
    inputSummary: {
      actorType: request.actor.type,
      actorId: request.actor.id,
      verb: request.verb,
      requestedCapabilities: request.requestedCapabilities,
      requestId: request.requestId ?? null,
      commandHint: request.commandHint ?? null,
    },
    resultSummary: {
      matchedRule: "unset",
      riskClass: "none",
      allowedCapabilities: [],
      deniedCapabilities: [],
      requiresHumanApproval: false,
    },
    ...overrides,
  };
  return evt;
}

export type LedgerEmitter = {
  readonly append: (input: MenogEventInput) => {
    readonly ok: boolean;
    readonly event?: { readonly eventId: string; readonly hash: string };
    readonly reason?: string;
  };
};

export function wrapLedger(ledger: AppendOnlyLedger): LedgerEmitter {
  return {
    append: (input) => {
      const r = ledger.append(input);
      if (!r.ok || !r.event) return { ok: false, reason: r.reason };
      return { ok: true, event: { eventId: r.event.eventId, hash: r.event.hash } };
    },
  };
}

export class DenyByDefaultPolicyEngine implements PolicyEngine {
  readonly #ledger: LedgerEmitter | null;
  readonly #eventDecisionId: string = "menog-policy-v0";

  public constructor(ledger?: LedgerEmitter | null) {
    this.#ledger = ledger ?? null;
  }

  public static with(ledger: AppendOnlyLedger): DenyByDefaultPolicyEngine {
    return new DenyByDefaultPolicyEngine(wrapLedger(ledger));
  }

  public get authoritativeRuleId(): string {
    return this.#eventDecisionId;
  }

  public evaluate(request: PolicyRequest): PolicyResult {
    const now = new Date().toISOString();
    const perCap: MutablePerCapMap = Object.create(null) as MutablePerCapMap;
    const seen = new Set<string>();
    const allowed: CapabilityId[] = [];
    const denied: string[] = [];

    for (const rawCap of CAPABILITY_IDS) {
      perCap[rawCap] = denyDecision(
        "rule:default-deny-unrequested",
        "capability '" + rawCap + "' not in request, default deny",
        "low"
      );
    }

    for (const rawCap of request.requestedCapabilities) {
      if (seen.has(rawCap as string)) continue;
      seen.add(rawCap as string);
      const capStr: string = rawCap as string;
      if (!isCapabilityId(rawCap)) {
        if (perCap[capStr] === undefined) {
          perCap[capStr] = denyDecision(
            "rule:unknown-capability",
            "unknown capability id: '" + capStr + "' is not in CAPABILITY_IDS",
            "high"
          );
        }
        denied.push(capStr);
        continue;
      }
      const cap: CapabilityId = rawCap;
      if (DAY1_FORBIDDEN_CAPABILITIES.includes(cap)) {
        let rule: string;
        let reason: string;
        switch (cap) {
          case "workspace:write":
            rule = "rule:day1:deny-workspace-write";
            reason = "day-1 phase-0 forbids any write to workspace contents";
            break;
          case "git:commit":
            rule = "rule:day1:deny-git-commit";
            reason = "day-1 commit is manual-human only; policy never allows git:commit";
            break;
          case "process:execute-write":
            rule = "rule:day1:deny-process-write";
            reason = "day-1 process execution restricted to readonly argv allowlist only";
            break;
          case "network:external":
            rule = "rule:day1:deny-network-external";
            reason = "day-1 phase-0 no external network; no egress permitted";
            break;
          case "process:privileged":
            rule = "rule:day1:deny-process-privileged";
            reason = "day-1 phase-0 never allows elevated/privileged process";
            break;
          default:
            rule = "rule:day1:deny-forbidden";
            reason = "capability '" + cap + "' is in DAY1_FORBIDDEN_CAPABILITIES";
        }
        perCap[cap] = denyDecision(
          rule,
          reason,
          riskClassFor(cap),
          requiresHumanApprovalFor(cap)
        );
        denied.push(cap);
        continue;
      }
      if (request.verb !== "inspect") {
        perCap[cap] = denyDecision(
          "rule:day1:deny-non-inspect-verb",
          "day-1 phase-0 only verb 'inspect' is in allowlist; got verb '" + request.verb + "'",
          "high"
        );
        denied.push(cap);
        continue;
      }
      if (!DAY1_INSPECT_CAPABILITIES.includes(cap as (typeof DAY1_INSPECT_CAPABILITIES)[number])) {
        perCap[cap] = denyDecision(
          "rule:day1:deny-inspect-outside-allowlist",
          "capability '" + cap + "' not in DAY1_INSPECT_CAPABILITIES allowlist for verb 'inspect'",
          "medium"
        );
        denied.push(cap);
        continue;
      }
      if (
        request.expectedSideEffectClass !== undefined &&
        CAPABILITY_EFFECT_TABLE[cap].sideEffectClass !== request.expectedSideEffectClass
      ) {
        perCap[cap] = denyDecision(
          "rule:side-effect-class-mismatch",
          "expected sideEffectClass '" +
            String(request.expectedSideEffectClass) +
            "' but capability '" +
            cap +
            "' requires '" +
            CAPABILITY_EFFECT_TABLE[cap].sideEffectClass +
            "'",
          "high"
        );
        denied.push(cap);
        continue;
      }
      if (typeof request.commandHint === "string" && request.commandHint.length > 0) {
        const hint = request.commandHint;
        const dangerous = ["git commit", "git push", "rm -rf", "> ", "| ", ";", "&&", "||", "$(", "`"];
        let hit: string | null = null;
        for (const tok of dangerous) {
          if (hint.includes(tok)) { hit = tok; break; }
        }
        if (hit !== null) {
          perCap[cap] = denyDecision(
            "rule:day1:deny-command-not-on-allowlist",
            "commandHint contains forbidden token '" + hit + "'; only 'git status' / 'git diff' style readonly commands allowed",
            "critical"
          );
          denied.push(cap);
          continue;
        }
      }
      perCap[cap] = allowDecision("rule:day1:allow-inspect-readonly", cap);
      allowed.push(cap);
    }

    for (const rawCap of request.requestedCapabilities) {
      if (!isCapabilityId(rawCap)) {
        const capStr = rawCap as string;
        perCap[capStr] = denyDecision(
          "rule:unknown-capability",
          "unknown capability id: '" + capStr + "' is not in CAPABILITY_IDS",
          "high"
        );
        if (!denied.includes(capStr)) denied.push(capStr);
      }
    }

    const anyDeniedCritical = Object.values(perCap).some(
      (d) => d.outcome === "deny" && (d.riskClass === "critical" || d.riskClass === "high")
    );
    const someAllowed = allowed.length > 0;
    const noneRequested = request.requestedCapabilities.length === 0;

    let aggregate: PolicyDecisionRecord;
    if (noneRequested) {
      aggregate = denyDecision(
        "rule:default-deny-empty-request",
        "no capabilities requested; policy must have explicit scope; default deny",
        "medium"
      );
    } else if (someAllowed && !anyDeniedCritical && denied.length === 0) {
      const risk = allowed.reduce<RiskClass>((acc, c) => maxRisk(acc, riskClassFor(c)), "none");
      const needsHuman = allowed.some((c) => requiresHumanApprovalFor(c));
      aggregate = {
        outcome: "allow",
        reason:
          "all requested capabilities (" +
          allowed.join(",") +
          ") are in day-1 inspect allowlist; human approval = " +
          (needsHuman ? "yes" : "no"),
        matchedRule: "rule:day1:allow-inspect-readonly-aggregate",
        riskClass: risk,
        requiresHumanApproval: needsHuman,
      };
    } else if (denied.length > 0) {
      const worst = denied.reduce<RiskClass>(
        (acc, capKey) => {
          const pd = perCap[capKey];
          return maxRisk(acc, pd ? pd.riskClass : "medium");
        },
        "medium"
      );
      const ruleDenied = denied
        .map((capKey) => {
          const pd = perCap[capKey];
          return pd ? pd.matchedRule : "rule:default-deny";
        })
        .sort()
        .join("|");
      aggregate = {
        outcome: "deny",
        reason:
          denied.length +
          " of " +
          request.requestedCapabilities.length +
          " requested capabilities denied: " +
          denied.join(","),
        matchedRule: ruleDenied,
        riskClass: worst,
        requiresHumanApproval: anyDeniedCritical,
      };
    } else {
      aggregate = denyDecision(
        "rule:default-deny-fallback",
        "deny-by-default catch-all: no explicit allow matched; never reached in deterministic code",
        "high"
      );
    }

    const result: PolicyResult = {
      decision: Object.freeze(aggregate),
      perCapability: Object.freeze({ ...perCap } as PerCapabilityDecision),
      allowedCapabilities: Object.freeze(allowed.slice()),
      deniedCapabilities: Object.freeze(denied.slice() as unknown as CapabilityId[]),
      at: now,
    };

    if (this.#ledger !== null) {
      const evt = baseUnknownEventInput(request, now, {
        policyDecision: aggregate.outcome as "allow" | "deny" | "not_applicable",
        resultSummary: {
          outcome: aggregate.outcome,
          matchedRule: aggregate.matchedRule,
          reason: aggregate.reason,
          riskClass: aggregate.riskClass,
          requiresHumanApproval: aggregate.requiresHumanApproval,
          allowedCapabilities: allowed,
          deniedCapabilities: denied,
          authoritativeRuleId: this.#eventDecisionId,
        },
      });
      this.#ledger.append(evt);
    }

    return result;
  }
}
