import { randomUUID } from "node:crypto";
import type { AppendOnlyLedger } from "@menog/event-ledger";
import { DenyByDefaultPolicyEngine, type PolicyRequest, type PolicyResult } from "@menog/policy";
import type { Actor, PolicyDecision as MenogPolicyDecision } from "@menog/core";
import { ReadonlyExecutor } from "./executor.js";
import { validateReadonlyExec, resolveWorkspaceSafely, type ExecRequest, type ExecResult } from "./validate.js";
import type { AllowedCommandSpec } from "./allowlist.js";

export interface AuthoritativeExecGateOptions {
  readonly ledger?: AppendOnlyLedger | null;
  readonly policyEngine?: DenyByDefaultPolicyEngine | null;
  readonly executor?: ReadonlyExecutor | null;
  readonly actor?: Actor;
}

export interface GateOutcome {
  readonly ok: boolean;
  readonly phase: "validate" | "policy" | "cwd" | "execute" | "complete";
  readonly decision?: PolicyResult;
  readonly validationReason?: string;
  readonly exec?: ExecResult;
  readonly matchedCommand?: AllowedCommandSpec;
}

export class AuthoritativeExecGate {
  readonly #ledger: AppendOnlyLedger | null;
  readonly #engine: DenyByDefaultPolicyEngine;
  readonly #executor: ReadonlyExecutor;
  readonly #actor: Actor;

  public constructor(options: AuthoritativeExecGateOptions = {}) {
    this.#ledger = options.ledger ?? null;
    this.#executor = options.executor ?? new ReadonlyExecutor();
    this.#actor = options.actor ?? { type: "agent", id: "menog-cli-local" };
    if (this.#ledger !== null && options.policyEngine) {
      this.#engine = options.policyEngine;
    } else if (this.#ledger !== null) {
      this.#engine = DenyByDefaultPolicyEngine.with(this.#ledger);
    } else if (options.policyEngine) {
      this.#engine = options.policyEngine;
    } else {
      this.#engine = new DenyByDefaultPolicyEngine();
    }
  }

  public get policyEngine(): DenyByDefaultPolicyEngine {
    return this.#engine;
  }

  public async evaluateAndMaybeRun(req: ExecRequest): Promise<GateOutcome> {
    const workspaceCheck = resolveWorkspaceSafely(req.workspaceRoot);
    if (!workspaceCheck.ok) {
      return {
        ok: false,
        phase: "cwd",
        validationReason: workspaceCheck.reason,
      };
    }
    const v = validateReadonlyExec(req);
    if (!v.ok) {
      return {
        ok: false,
        phase: "validate",
        validationReason: v.reason,
      };
    }
    const policyReq: PolicyRequest = {
      requestId: req.requestId,
      actor: this.#actor,
      verb: "inspect",
      requestedCapabilities: v.requiredCapabilities ?? [],
      expectedSideEffectClass: "read",
      workspaceId: workspaceCheck.resolved,
      taskId: undefined,
      commandHint: v.sanitizedExecutable + " " + (v.sanitizedArgv ?? []).join(" "),
    };
    const decision = this.#engine.evaluate(policyReq);
    if (decision.decision.outcome !== "allow") {
      return {
        ok: false,
        phase: "policy",
        decision,
      };
    }
    const startedAt = Date.now();
    const exec: ExecResult = await this.#executor.run(req);
    if (this.#ledger !== null) {
      const summary: Record<string, unknown> = {};
      summary.terminationKind = exec.termination.kind;
      if (exec.termination.kind === "exit") summary.exitCode = exec.termination.code;
      if (exec.termination.kind === "signal") summary.signal = exec.termination.signal;
      if (exec.termination.kind === "timeout") summary.afterMs = exec.termination.afterMs;
      if (exec.termination.kind === "spawn-error") summary.spawnMessage = exec.termination.message;
      summary.durationMs = exec.durationMs;
      summary.stdoutBytes = exec.stdout.byteLength;
      summary.stderrBytes = exec.stderr.byteLength;
      summary.stdoutTruncated = exec.stdoutTruncated;
      summary.stderrTruncated = exec.stderrTruncated;
      summary.ok = exec.ok;
      summary.startedAt = startedAt;
      this.#ledger.append({
        eventId: "exec-" + randomUUID().replace(/-/g, "").slice(0, 24),
        timestamp: new Date().toISOString(),
        eventType: "exec_result",
        actor: { type: "runtime", id: "readonly-executor" },
        workspaceId: workspaceCheck.resolved,
        taskId: req.requestId,
        verb: "inspect",
        capability: (policyReq.requestedCapabilities as readonly string[]).slice().sort().join("+") || "none",
        policyDecision: decision.decision.outcome,
        inputSummary: {
          executable: v.sanitizedExecutable,
          argv: v.sanitizedArgv,
          workspace: workspaceCheck.resolved,
          commandSpecId: v.matchedSpec ? v.matchedSpec.id : null,
        },
        resultSummary: summary,
      });
    }
    return {
      ok: exec.ok,
      phase: "complete",
      decision,
      exec,
      matchedCommand: v.matchedSpec,
    };
  }

  public policyDecisionOnly(req: ExecRequest): GateOutcome {
    const workspaceCheck = resolveWorkspaceSafely(req.workspaceRoot);
    if (!workspaceCheck.ok) {
      return {
        ok: false,
        phase: "cwd",
        validationReason: workspaceCheck.reason,
      };
    }
    const v = validateReadonlyExec(req);
    if (!v.ok) {
      return {
        ok: false,
        phase: "validate",
        validationReason: v.reason,
      };
    }
    const policyReq: PolicyRequest = {
      requestId: req.requestId,
      actor: this.#actor,
      verb: "inspect",
      requestedCapabilities: v.requiredCapabilities ?? [],
      expectedSideEffectClass: "read",
      workspaceId: workspaceCheck.resolved,
      commandHint: v.sanitizedExecutable + " " + (v.sanitizedArgv ?? []).join(" "),
    };
    const decision = this.#engine.evaluate(policyReq);
    if (decision.decision.outcome !== "allow") {
      return {
        ok: false,
        phase: "policy",
        decision,
      };
    }
    return {
      ok: true,
      phase: "policy",
      decision,
      matchedCommand: v.matchedSpec,
    };
  }
}

export type { MenogPolicyDecision };
