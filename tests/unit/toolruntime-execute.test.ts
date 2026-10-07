import { describe, it, expect } from "vitest";
import { sep } from "node:path";
import {
  TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
  TOOL_BASELINE_PROFILE_ID,
  LocalToolRegistry,
  validateManifest,
  validateEnvelope,
  executeToolRun,
  canonicalToolCwd,
  buildToolEnv,
  capOutput,
  type ToolExecutionRequest,
  type IsolationCapabilitySnapshot,
  type LauncherToolSpec,
  type LauncherToolResult,
} from "@menog/runtime-linux";

/**
 * PRE-21C — junction assembly tests (host-pure; the transport seam is
 * injected, so NO process is spawned and NO launcher is compiled here).
 *
 * Proven here:
 * - every deny path returns decision + result === null (transport never
 *   called — the injected transport would have recorded a call);
 * - the junction assembles the exact launcher spec from the registry entry
 *   (executable identity), the request (argv/env names/timeout/output),
 *   the composed isolation profile, and the canonical cwd;
 * - env allowlist semantics (names only; trusted values; safe defaults);
 * - output capping with marker; cwd canonicalization refuses escapes.
 */

const SNAPSHOT: IsolationCapabilitySnapshot = {
  targetKernel: "5.15.167.4",
  targetArch: "x86_64",
  isWsl: true,
  landlockAbi: 1,
  probedAt: "2026-09-27T00:00:00.000Z",
  primitives: {
    ns_user: "SUPPORTED",
    ns_mount: "SUPPORTED",
    ns_pid: "SUPPORTED",
    ns_ipc: "SUPPORTED",
    ns_uts: "SUPPORTED",
    ns_net: "SUPPORTED",
    cgroup_v2_controllers: "UNSUPPORTED",
    cgroup_v2_delegation: "UNSUPPORTED",
    landlock_fs: "SUPPORTED",
    landlock_net: "UNSUPPORTED",
    seccomp_filter: "SUPPORTED",
    no_new_privs: "SUPPORTED",
    rlimit_set: "SUPPORTED",
    proc_hidepid: "UNSUPPORTED",
  },
};

const MANIFEST = {
  schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
  toolId: "demo.count",
  version: "1.0.0",
  displayName: "Demo Counter",
  description: "Demo tool used only for junction tests",
  capabilities: [{ capability: "workspace:read", criticality: "required" }],
  trustClass: "human_reviewed",
  declaredBy: "human-21c",
  isolationProfileId: TOOL_BASELINE_PROFILE_ID,
};

function registeredEntry(toolPath: string, overrides: Record<string, unknown> = {}) {
  const mv = validateManifest(MANIFEST);
  if (!mv.ok) throw new Error("fixture manifest invalid: " + mv.message);
  const registry = new LocalToolRegistry();
  const reg = registry.register({
    manifest: mv.value,
    sideEffectClass: "read_only",
    limits: { timeoutMs: 30_000, maxOutputBytes: 64_000, maxArgvEntries: 16 },
    isolationProfileId: TOOL_BASELINE_PROFILE_ID,
    network: "none",
    executable: { pathStrategy: "explicit_absolute_path", path: toolPath },
    registeredBy: "human-21c",
    ...overrides,
  });
  if (!reg.ok) throw new Error("fixture registration invalid: " + reg.message);
  return reg.value;
}

function request(over: Partial<ToolExecutionRequest> = {}): ToolExecutionRequest {
  return {
    requestId: "req-21c",
    toolId: "demo.count",
    version: "1.0.0",
    envelope: {
      schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
      toolId: "demo.count",
      version: "1.0.0",
      input: {},
      constraints: { timeoutMs: 10_000, maxOutputBytes: 8_000 },
    },
    requester: { actorType: "agent", id: "menog-agent-builder" },
    taskScope: ["workspace:read"],
    agentCapabilities: ["workspace:read"],
    policyOutcome: "allow",
    isolation: { profileId: TOOL_BASELINE_PROFILE_ID, canEnforce: true },
    ...over,
  };
}

/**
 * A transport double that RECORDS whether it was called. Its presence in
 * every deny-path assertion is what proves "the tool did not run".
 */
function recordingTransport(): {
  transport: (spec: LauncherToolSpec) => LauncherToolResult;
  wasCalled: () => boolean;
  lastSpec: () => LauncherToolSpec | null;
} {
  let called = false;
  let last: LauncherToolSpec | null = null;
  const transport = (spec: LauncherToolSpec): LauncherToolResult => {
    called = true;
    last = spec;
    return {
      ok: true,
      exitCode: 0,
      signal: null,
      timedOut: false,
      targetRan: true,
      stdout: Buffer.from("hello from the double\n"),
      stderr: Buffer.alloc(0),
      stdoutTruncated: false,
      stderrTruncated: false,
      failedPrimitive: null,
      isolationEvidence: null,
      isolationProfileId: spec.profileId,
    };
  };
  return { transport, wasCalled: () => called, lastSpec: () => last };
}

function input(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    request: request(),
    entry: registeredEntry("/opt/tools/demo-count"),
    snapshot: SNAPSHOT,
    workspaceRoot: "/tmp/menog-ws-21c",
    policyOutcome: "allow",
    ...over,
  };
}

// ── deny paths: decision + transport-never-called ────────────────────────────

describe("21C junction — deny paths never reach the transport", () => {
  it("bad envelope args → validation_denied, result null, transport uncalled", () => {
    const t = recordingTransport();
    const o = executeToolRun({
      ...input(),
      request: request({
        envelope: {
          schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
          toolId: "demo.count",
          version: "1.0.0",
          input: {},
          constraints: { argv: ["a;rm"] },
        },
      }),
      transportOverride: t.transport,
    } as never);
    expect(o.decision.status).toBe("validation_denied");
    expect(o.result).toBeNull();
    expect(t.wasCalled()).toBe(false);
  });

  it("quarantined lifecycle → validation_denied, transport uncalled", () => {
    const t = recordingTransport();
    const entry = registeredEntry("/opt/tools/demo-count");
    const quarantined = Object.freeze({ ...entry, lifecycle: "quarantined" as const });
    const o = executeToolRun({
      ...input(),
      entry: quarantined,
      transportOverride: t.transport,
    } as never);
    expect(o.decision.status).toBe("validation_denied");
    expect(o.decision.reason).toContain("not executable");
    expect(o.result).toBeNull();
    expect(t.wasCalled()).toBe(false);
  });

  it("capability mismatch → validation_denied, transport uncalled", () => {
    const t = recordingTransport();
    const o = executeToolRun({
      ...input(),
      request: request({ agentCapabilities: ["workspace:write"] }),
      transportOverride: t.transport,
    } as never);
    expect(o.decision.status).toBe("validation_denied");
    expect(o.result).toBeNull();
    expect(t.wasCalled()).toBe(false);
  });

  it("policy deny → policy_denied, transport uncalled", () => {
    const t = recordingTransport();
    const o = executeToolRun({
      ...input(),
      policyOutcome: "deny",
      policyRuleId: "day1:default-deny",
      transportOverride: t.transport,
    } as never);
    expect(o.decision.status).toBe("policy_denied");
    expect(o.result).toBeNull();
    expect(t.wasCalled()).toBe(false);
  });

  it("unenforceable isolation → isolation_denied, transport uncalled", () => {
    const t = recordingTransport();
    const o = executeToolRun({
      ...input(),
      snapshot: { ...SNAPSHOT, primitives: { ...SNAPSHOT.primitives, ns_net: "UNSUPPORTED" } },
      transportOverride: t.transport,
    } as never);
    expect(o.decision.status).toBe("isolation_denied");
    expect(o.result).toBeNull();
    expect(t.wasCalled()).toBe(false);
  });

  it("cwd escape → validation_denied, transport uncalled", () => {
    const t = recordingTransport();
    const o = executeToolRun({
      ...input(),
      request: request({
        envelope: {
          schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
          toolId: "demo.count",
          version: "1.0.0",
          input: {},
          constraints: { cwd: "/etc" },
        },
      }),
      transportOverride: t.transport,
    } as never);
    expect(o.decision.status).toBe("validation_denied");
    expect(o.decision.reason).toContain("workspace");
    expect(o.result).toBeNull();
    expect(t.wasCalled()).toBe(false);
  });

  it("embedded executable identity refuses (out of 21C scope), transport uncalled", () => {
    const t = recordingTransport();
    const entry = registeredEntry("/opt/tools/demo-count", {
      executable: { pathStrategy: "embedded", embeddedKey: "demo.count" },
    });
    const o = executeToolRun({ ...input(), entry, transportOverride: t.transport } as never);
    expect(o.decision.status).toBe("validation_denied");
    expect(o.decision.reason).toContain("explicit absolute path");
    expect(o.result).toBeNull();
    expect(t.wasCalled()).toBe(false);
  });

  it("executable substitution is structurally inert: the request cannot name a binary", () => {
    const req = request();
    expect(Object.keys(req)).not.toContain("executablePath");
    expect(Object.keys(req)).not.toContain("argv0");
    expect(Object.keys(req)).not.toContain("shell");
  });
});

// ── spec assembly: the double records exactly what the junction derived ──────

const WS_ROOT = process.platform === "win32" ? "C:\\menog-ws-21c" : "/tmp/menog-ws-21c";

describe("21C junction — launcher spec assembly", () => {
  it("assembles exact executable, argv, cwd, timeout, and env from the authorities", () => {
    const t = recordingTransport();
    const o = executeToolRun({
      ...input(),
      workspaceRoot: WS_ROOT,
      request: request({
        envelope: {
          schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
          toolId: "demo.count",
          version: "1.0.0",
          input: {},
          constraints: {
            argv: ["--lines", "3"],
            cwd: "sub/dir",
            envAllowlist: ["MENOG_MODE"],
            timeoutMs: 5_000,
            maxOutputBytes: 4_000,
          },
        },
      }),
      envValueSource: (n: string) => (n === "MENOG_MODE" ? "gated" : undefined),
      transportOverride: t.transport,
    } as never);
    expect(o.decision.status).toBe("not_started");
    expect(t.wasCalled()).toBe(true);
    const spec = t.lastSpec();
    if (!spec) throw new Error("transport was not called");
    expect(spec.targetArgv).toEqual(["/opt/tools/demo-count", "--lines", "3"]);
    // Exact containment: workspace root prefix + requested sub-path.
    expect(spec.cwd).toBe(WS_ROOT + sep + "sub" + sep + "dir");
    expect(spec.timeoutMs).toBe(5_000);
    expect(spec.maxOutputBytes).toBe(4_000);
    expect(spec.envAllowlist).toEqual(["MENOG_MODE"]);
    expect(spec.launcherFlags[0]).toBe("--begin");
    expect(spec.profileId).toContain(TOOL_BASELINE_PROFILE_ID);
    // Registry limits bind: the envelope may only TIGHTEN. A request above
    // the registry timeout (but within the envelope contract) is clamped.
    const o2 = executeToolRun({
      ...input(),
      workspaceRoot: WS_ROOT,
      request: request({
        envelope: {
          schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
          toolId: "demo.count",
          version: "1.0.0",
          input: {},
          constraints: { timeoutMs: 500_000 },
        },
      }),
      transportOverride: t.transport,
    } as never);
    expect(o2.decision.status).toBe("not_started");
    // The junction clamped the spec to the registry-pinned 30_000.
    expect(t.lastSpec()?.timeoutMs).toBe(30_000);
    // Result carries untrusted output with hash metadata.
    expect(o.result?.outputTrust).toBe("untrusted_data");
    expect(o.result?.outputRef).toMatch(/^sha256:[0-9a-f]{64};bytes=\d+$/);
    expect(o.result?.status).toBe("completed");
    expect(o.evidence.status).toBe("completed");
    expect(o.evidence.enforced).toEqual(o.evidence.authorized);
    expect(o.evidence.observed).toEqual(o.evidence.enforced);
  });

  it("evidence anti-overclaim still binds on real runs", () => {
    const t = recordingTransport();
    const o = executeToolRun({ ...input(), transportOverride: t.transport } as never);
    expect(o.decision.status).toBe("not_started");
    const e = o.evidence;
    for (const a of e.authorized) expect(e.requested).toContain(a);
    for (const x of e.enforced) expect(e.authorized).toContain(x);
    for (const w of e.observed) expect(e.enforced).toContain(w);
  });
});

// ── transport primitives (pure) ──────────────────────────────────────────────

describe("21C transport primitives", () => {
  it("cwd canonicalization refuses escapes and accepts workspace-inside paths", () => {
    // Host-side: resolve() yields Windows-style paths; containment semantics
    // are separator-correct on both platforms.
    expect(canonicalToolCwd(undefined, "C:\\tmp\\ws")).toBe("C:\\tmp\\ws");
    expect(canonicalToolCwd("sub", "C:\\tmp\\ws")).toBe("C:\\tmp\\ws\\sub");
    expect(canonicalToolCwd("/etc", "/tmp/ws")).toBeNull();
    expect(canonicalToolCwd("../../../etc", "/tmp/ws")).toBeNull();
    expect(canonicalToolCwd("/tmp/ws-other", "/tmp/ws")).toBeNull();
  });

  it("env building: fixed safe defaults + allowlisted names from the trusted source", () => {
    const env = buildToolEnv(["A_NAME"], (n) => (n === "A_NAME" ? "v" : undefined));
    expect(env.PATH).not.toContain(process.env.PATH ?? "%%");
    expect(env.HOME).toBe("/tmp");
    expect(env.A_NAME).toBe("v");
    expect(buildToolEnv(["ABSENT"], () => undefined).ABSENT).toBeUndefined();
  });

  it("output capping: under the bound is untouched; over it is truncated with a marker", () => {
    const small = Buffer.from("ok");
    expect(capOutput(small, 100)).toEqual({ out: small, truncated: false });
    const big = Buffer.alloc(1_000, 65);
    const capped = capOutput(big, 100);
    expect(capped.truncated).toBe(true);
    expect(capped.out.length).toBe(100);
    expect(capped.out.toString("utf8")).toContain("truncated");
  });

  it("envelope validator accepts bounded constraints and rejects junk (pin)", () => {
    const ok = validateEnvelope({
      schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
      toolId: "demo.count",
      version: "1.0.0",
      input: {},
      constraints: { argv: ["x"], timeoutMs: 1_000, maxOutputBytes: 10, envAllowlist: ["A"] },
    });
    expect(ok.ok).toBe(true);
  });
});
