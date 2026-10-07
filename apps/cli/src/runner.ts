import { mkdirSync, existsSync } from "node:fs";
import { normalize, resolve, isAbsolute, join } from "node:path";
import { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor, PolicyDecision as MenogPolicyDecision } from "@menog/core";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import { defaultVerbRegistry } from "@menog/verbs";
import {
  AuthoritativeExecGate,
  resolveWorkspaceSafely,
} from "@menog/runtime-linux";
import {
  INSPECT_FORMAT_VERSION,
  INSPECT_VERB_ID,
  MENOG_DIRNAME,
  LEDGER_FILENAME,
  type InspectExitStatus,
  type InspectReport,
  type InspectRunOptions,
  type InspectRunResult,
  type ParseArgsResult,
  type PolicySummary,
  type PolicySummaryInput,
} from "./types.js";
import {
  safeListTopLevel,
  runGitInspection,
  dedupe,
  type GitInspection,
  type NativeScan,
} from "./inspect.js";

export function normalizeWorkspaceArg(workspaceArg: string, workingCwd?: string): {
  readonly ok: boolean;
  readonly resolved?: string;
  readonly reason?: string;
} {
  if (typeof workspaceArg !== "string" || workspaceArg.length === 0) {
    return { ok: false, reason: "workspace argument is required" };
  }
  const base =
    workingCwd && typeof workingCwd === "string" && workingCwd.length > 0
      ? workingCwd
      : process.cwd();
  const cwdAbs = isAbsolute(base) ? normalize(resolve(base)) : normalize(resolve(process.cwd(), base));
  const wsAbs = isAbsolute(workspaceArg)
    ? normalize(resolve(workspaceArg))
    : normalize(resolve(cwdAbs, workspaceArg));
  const safe = resolveWorkspaceSafely(wsAbs, wsAbs);
  if (!safe.ok) {
    return { ok: false, reason: safe.reason ?? "workspace rejected by safe resolver" };
  }
  return { ok: true, resolved: safe.resolved };
}

export function parseArgs(argv: readonly string[]): ParseArgsResult {
  if (!Array.isArray(argv)) {
    return { ok: false, usageError: "argv must be an array" };
  }
  const rest = argv.slice();
  while (rest.length > 0) {
    const head = rest[0] as string;
    if (head.endsWith("node") || head.endsWith("node.exe") || head.endsWith("tsx") || head.endsWith("tsx.cmd") || head.endsWith("menog") || head.endsWith("menog.js") || head.endsWith("menog.ts") || head.endsWith("main.js") || head.endsWith("bin-main.js") || head.endsWith("bin-main.ts")) {
      rest.shift();
      continue;
    }
    if (head === "--" || head === "") {
      rest.shift();
      continue;
    }
    if (head.startsWith("--")) {
      return { ok: false, usageError: "menog v0 accepts no flags; only subcommand `inspect <workspace>`" };
    }
    break;
  }
  if (rest.length === 0) {
    return { ok: false, usageError: "usage: menog inspect <workspace>" };
  }
  const sub = rest[0] as string;
  if (sub !== "inspect") {
    return { ok: false, usageError: "unknown subcommand '" + sub + "'; only `inspect` is implemented in day-1 v0" };
  }
  if (rest.length < 2) {
    return { ok: false, usageError: "usage: menog inspect <workspace>" };
  }
  if (rest.length > 2) {
    return { ok: false, usageError: "too many arguments; only a single workspace path is accepted" };
  }
  const workspaceArg = rest[1] as string;
  return { ok: true, subcommand: "inspect", workspaceArg };
}

export function ensureMenogLedger(
  workspaceRoot: string,
  ledger: "memory" | "default" | { readonly kind: "dir"; readonly root: string } | unknown
): {
  readonly ledgerInstance: AppendOnlyLedger;
  readonly ledgerDir: string | null;
  readonly warnings: readonly string[];
} {
  const warnings: string[] = [];
  if (ledger === null || ledger === undefined || ledger === "memory") {
    return { ledgerInstance: AppendOnlyLedger.inMemory(), ledgerDir: null, warnings: Object.freeze(warnings) };
  }
  if (typeof ledger === "object" && ledger && "kind" in (ledger as { kind?: string }) && (ledger as { kind?: string }).kind === "dir") {
    const l = ledger as { readonly kind: "dir"; readonly root: string };
    const safeRoot = resolveWorkspaceSafely(l.root);
    if (!safeRoot.ok || !safeRoot.resolved) {
      warnings.push("ledger root rejected by safe resolver; falling back to in-memory");
      return { ledgerInstance: AppendOnlyLedger.inMemory(), ledgerDir: null, warnings: Object.freeze(warnings) };
    }
    try {
      return {
        ledgerInstance: AppendOnlyLedger.at(join(safeRoot.resolved, MENOG_DIRNAME, LEDGER_FILENAME)),
        ledgerDir: safeRoot.resolved,
        warnings: Object.freeze(warnings),
      };
    } catch (e) {
      warnings.push("could not open dir ledger file; in-memory fallback: " + String((e as Error).message));
      return { ledgerInstance: AppendOnlyLedger.inMemory(), ledgerDir: null, warnings: Object.freeze(warnings) };
    }
  }
  if (ledger === "default") {
    const wsSafe = resolveWorkspaceSafely(workspaceRoot);
    if (!wsSafe.ok || !wsSafe.resolved) {
      warnings.push("workspace rejected; using in-memory ledger for this run");
      return { ledgerInstance: AppendOnlyLedger.inMemory(), ledgerDir: null, warnings: Object.freeze(warnings) };
    }
    const ledgerDir = join(wsSafe.resolved, MENOG_DIRNAME);
    try {
      if (!existsSync(ledgerDir)) mkdirSync(ledgerDir, { recursive: true });
    } catch (e) {
      warnings.push("could not create .menog ledger dir; in-memory fallback: " + String((e as Error).message));
      return { ledgerInstance: AppendOnlyLedger.inMemory(), ledgerDir: null, warnings: Object.freeze(warnings) };
    }
    try {
      return {
        ledgerInstance: AppendOnlyLedger.at(join(ledgerDir, LEDGER_FILENAME)),
        ledgerDir: wsSafe.resolved,
        warnings: Object.freeze(warnings),
      };
    } catch (e) {
      warnings.push("could not open default ledger file; in-memory fallback: " + String((e as Error).message));
      return { ledgerInstance: AppendOnlyLedger.inMemory(), ledgerDir: null, warnings: Object.freeze(warnings) };
    }
  }
  return { ledgerInstance: AppendOnlyLedger.inMemory(), ledgerDir: null, warnings: Object.freeze(warnings) };
}

export function summarizePolicy(
  decisionLog: readonly PolicySummaryInput[]
): PolicySummary {
  const matchedRules: string[] = [];
  const w: string[] = [];
  let allowCount = 0;
  let denyCount = 0;
  for (const d of decisionLog) {
    if (d.decision.matchedRule && d.decision.matchedRule.length > 0) {
      matchedRules.push(d.decision.matchedRule);
    }
    if (d.decision.reason && d.decision.reason.length > 0) {
      w.push(d.decision.reason);
    }
    if (d.decision.outcome === "allow") allowCount++;
    else if (d.decision.outcome === "deny") denyCount++;
  }
  const decision: "allow" | "deny" = denyCount > 0 ? "deny" : "allow";
  return {
    decision,
    matchedRules: Object.freeze(dedupe(matchedRules)),
    warnings: Object.freeze(dedupe(w)),
    eventCount: decisionLog.length,
  } as const;
}

export async function runInspectWorkflow(
  options: InspectRunOptions
): Promise<InspectRunResult> {
  const startedAt = process.hrtime();
  const warningsArr: string[] = [];
  const actor: Actor = options.actor ?? { type: "agent", id: "menog-cli-local" };
  const taskId = options.taskId ?? "menog-inspect-" + Date.now().toString(36);

  const norm = normalizeWorkspaceArg(options.workspaceArg, options.workingCwd);
  if (!norm.ok || !norm.resolved) {
    const usageErr = "workspace path invalid: " + (norm.reason ?? "unknown");
    warningsArr.push(usageErr);
    return {
      exitStatus: 2,
      report: null,
      warnings: Object.freeze(warningsArr.slice()),
      stdoutText: "",
      stderrText: usageErr + "\n",
    };
  }
  const workspaceNormalized = norm.resolved;

  const ledgerModeRaw = options.ledger === undefined ? "default" : options.ledger;
  const { ledgerInstance, warnings: ledgerWarnings } = ensureMenogLedger(
    workspaceNormalized,
    ledgerModeRaw
  );
  for (const w of ledgerWarnings) warningsArr.push(w);

  const policyEngine = DenyByDefaultPolicyEngine.with(ledgerInstance);
  const gate = new AuthoritativeExecGate({
    ledger: ledgerInstance,
    policyEngine,
    actor,
  });

  const beforeIntentEvents = ledgerInstance.length;
  const verbRegistry = defaultVerbRegistry;
  const verbLookup = verbRegistry.get(INSPECT_VERB_ID);
  if (!verbLookup.found) {
    warningsArr.push("verb 'inspect' not registered; continuing with hard-coded capability set");
  }
  const decisionLog: PolicySummaryInput[] = [];

  let native: NativeScan;
  try {
    native = safeListTopLevel(workspaceNormalized, { maxDepth: 5, maxEntries: 20000 });
  } catch (e) {
    warningsArr.push("native workspace scan failed: " + String((e as Error).message));
    native = Object.freeze({
      manifests: Object.freeze([]),
      testFiles: 0,
      warnings: Object.freeze([]),
    });
  }
  for (const w of native.warnings) warningsArr.push(w);

  let git: GitInspection;
  try {
    git = await runGitInspection(gate, workspaceNormalized, taskId);
  } catch (e) {
    warningsArr.push("git inspection failed: " + String((e as Error).message));
    git = Object.freeze({
      isRepository: false,
      branch: null,
      status: "unknown",
      counts: Object.freeze({
        tracked: 0,
        modified: 0,
        stagedModified: 0,
        untracked: 0,
      }),
      warnings: Object.freeze([]),
    });
  }
  for (const w of git.warnings) warningsArr.push(w);

  const evts = ledgerInstance.events();
  const VALID_RISK_CLASSES: readonly string[] = Object.freeze([
    "none",
    "low",
    "medium",
    "high",
    "critical",
  ]);
  for (let i = beforeIntentEvents; i < evts.length; i++) {
    const e = evts[i]!;
    if (e.eventType === "policy_decision" && typeof e.resultSummary === "object" && e.resultSummary !== null) {
      const r = e.resultSummary as Record<string, unknown>;
      const outcomeRaw = r.outcome;
      const outcome = outcomeRaw === "allow" || outcomeRaw === "deny" ? outcomeRaw : undefined;
      if (outcome === "allow" || outcome === "deny") {
        const matchedRule = typeof r.matchedRule === "string" && r.matchedRule.length > 0 ? r.matchedRule : "";
        const reason = typeof r.reason === "string" && r.reason.length > 0 ? r.reason : "";
        const riskClassRaw = r.riskClass;
        const _riskClass =
          typeof riskClassRaw === "string" && VALID_RISK_CLASSES.includes(riskClassRaw)
            ? riskClassRaw
            : "medium";
        void _riskClass;
        const _requiresHumanApproval = typeof r.requiresHumanApproval === "boolean" ? r.requiresHumanApproval : false;
        void _requiresHumanApproval;
        decisionLog.push({
          decision: {
            outcome,
            matchedRule,
            reason,
          },
        });
      }
    }
  }

  const policy = summarizePolicy(decisionLog);
  for (const w of policy.warnings) warningsArr.push(w);

  const [sec, ns] = process.hrtime(startedAt);
  const durationMs = sec * 1000 + ns / 1e6;

  const allWarnings = Object.freeze(dedupe(warningsArr));
  const report: InspectReport = Object.freeze({
    formatVersion: INSPECT_FORMAT_VERSION,
    generatedAt: new Date().toISOString(),
    taskId,
    workspace: Object.freeze({
      path: options.workspaceArg,
      normalized: workspaceNormalized,
    }),
    git: Object.freeze({
      isRepository: git.isRepository,
      branch: git.branch,
      status: git.status,
      counts: Object.freeze({
        tracked: git.counts.tracked,
        modified: git.counts.modified,
        untracked: git.counts.untracked,
        stagedModified: git.counts.stagedModified,
      }),
    }),
    manifests: native.manifests,
    testFiles: native.testFiles,
    warnings: allWarnings,
    policy,
    eventCount: ledgerInstance.length - beforeIntentEvents,
    executionDurationMs: Math.floor(durationMs * 1000) / 1000,
  });

  const stdoutText = JSON.stringify(report, null, 2) + "\n";
  const exitStatus: InspectExitStatus = policy.decision === "deny" ? 1 : 0;

  return Object.freeze({
    exitStatus,
    report,
    warnings: allWarnings,
    stdoutText,
    stderrText: allWarnings.length === 0 ? "" : allWarnings.map((w) => "warning: " + w).join("\n") + "\n",
  });
}

export function cliMain(argv: readonly string[] = process.argv.slice(2)): number {
  const parsed = parseArgs(argv);
  if (!parsed.ok) {
    const msg = parsed.usageError ?? "usage: menog inspect <workspace>";
    process.stderr.write(msg + "\n");
    return 2;
  }
  const workingCwd = process.cwd();
  runInspectWorkflow({
    workspaceArg: parsed.workspaceArg!,
    workingCwd,
  })
    .then((res) => {
      process.stdout.write(res.stdoutText);
      if (res.stderrText) process.stderr.write(res.stderrText);
      process.exit(res.exitStatus);
    })
    .catch((err) => {
      process.stderr.write("fatal: menog inspect threw: " + String((err as Error).message ?? err) + "\n");
      process.exit(2);
    });
  return 0;
}

export type { MenogPolicyDecision };
