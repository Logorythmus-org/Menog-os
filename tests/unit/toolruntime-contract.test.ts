import { describe, it, expect } from "vitest";
import {
  TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
  LIFECYCLE_STATES,
  TOOL_EXECUTION_STATUSES,
  validateManifest,
  manifestHash,
  transitionLifecycle,
  isExecutableLifecycle,
  validateEnvelope,
  isCwdInsideWorkspace,
  gateToolExecution,
  buildToolEvidence,
  checkVersionDrift,
  type ToolExecutionRequest,
  type ToolManifest,
} from "@menog/runtime-linux";

/**
 * PRE-21A — governed tool runtime CONTRACT tests (no execution anywhere).
 *
 * Each test pins one frozen semantic or one threat class from
 * docs/security/PHASE21_TOOL_RUNTIME_THREAT_MODEL.md:
 *   T21-01 spoofing/substitution        T21-08 child escape (profile-gated)
 *   T21-02 capability inflation         T21-09 resource abuse (envelope bounds)
 *   T21-03 argv injection               T21-10 version drift
 *   T21-04 cwd escape                   T21-11 confused deputy (intersection)
 *   T21-05 env/secret leakage           T21-12 evidence spoofing
 *   T21-06 output prompt injection      T21-13 quarantine bypass
 *   T21-07 network (policy + profile)
 */

const HUMAN_MANIFEST = {
  schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
  toolId: "demo.echo",
  version: "1.2.3",
  displayName: "Demo Echo",
  description: "Bounded demo tool used only for contract tests",
  capabilities: [
    { capability: "workspace:read", criticality: "required" },
    { capability: "workspace:annotate", criticality: "optional" },
  ],
  trustClass: "human_reviewed",
  declaredBy: "human-21a",
  isolationProfileId: "exec-baseline",
};

function goodRequest(over: Partial<ToolExecutionRequest> = {}): ToolExecutionRequest {
  return {
    requestId: "req-1",
    toolId: "demo.echo",
    version: "1.2.3",
    envelope: {
      schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
      toolId: "demo.echo",
      version: "1.2.3",
      input: { text: "hi" },
      constraints: { argv: ["--flag"], timeoutMs: 5_000, maxOutputBytes: 64_000 },
    },
    requester: { actorType: "agent", id: "menog-agent-builder" },
    taskScope: ["workspace:read", "workspace:annotate"],
    agentCapabilities: ["workspace:read", "workspace:annotate"],
    policyOutcome: "allow",
    isolation: { profileId: "exec-baseline", canEnforce: true },
    ...over,
  };
}

function parsedManifest(over: Record<string, unknown> = {}): ToolManifest {
  const r = validateManifest({ ...HUMAN_MANIFEST, ...over });
  if (!r.ok) throw new Error("fixture manifest invalid: " + r.message);
  return r.value;
}

// ── vocabulary ───────────────────────────────────────────────────────────────

describe("21A contract vocabulary", () => {
  it("pins the schema version and closed vocabularies", () => {
    expect(TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION).toBe("menog-tool-runtime-contract/v0");
    expect(LIFECYCLE_STATES).toEqual(["registered", "enabled", "disabled", "quarantined", "retired"]);
    expect(TOOL_EXECUTION_STATUSES).toEqual([
      "not_started", "started", "completed", "failed", "timed_out",
      "policy_denied", "isolation_denied", "validation_denied",
    ]);
  });
});

// ── manifest: registration never authorizes (T21-02) ─────────────────────────

describe("21A manifests — requests, not grants", () => {
  it("parses a valid human_reviewed manifest and hashes it deterministically", () => {
    const m = parsedManifest();
    expect(m.toolId).toBe("demo.echo");
    expect(manifestHash(m)).toBe(manifestHash(parsedManifest()));
    expect(manifestHash(m)).not.toBe(manifestHash(parsedManifest({ description: "changed" })));
  });

  it("rejects malformed ids/versions (explicit versions; T21-10 shape)", () => {
    expect(validateManifest({ ...HUMAN_MANIFEST, toolId: "Bad Tool" }).ok).toBe(false);
    expect(validateManifest({ ...HUMAN_MANIFEST, version: "1.2" }).ok).toBe(false);
    expect(validateManifest({ ...HUMAN_MANIFEST, trustClass: "self_attested" }).ok).toBe(false);
    expect(validateManifest({ ...HUMAN_MANIFEST, capabilities: [] }).ok).toBe(true); // zero-capability tool is legal
  });

  it("capability inflation is inert: declared capabilities grant nothing by themselves", () => {
    // A manifest CLAIMS workspace:write; the gate still denies because task
    // scope and agent capabilities do not cover it. (T21-02)
    const m = parsedManifest({
      capabilities: [{ capability: "workspace:write", criticality: "required" }],
    });
    const d = gateToolExecution(goodRequest(), m, "enabled");
    expect(d.status).toBe("validation_denied");
    expect(d.plan).toBeUndefined();
  });

  it("agent_supplied manifests are accepted only as untrusted data (same gate)", () => {
    const m = parsedManifest({ trustClass: "agent_supplied", declaredBy: "menog-agent-builder" });
    const d = gateToolExecution(goodRequest({ policyOutcome: "deny" }), m, "enabled");
    expect(d.status).toBe("policy_denied");
  });
});

// ── lifecycle: quarantine bypass unrepresentable (T21-13) ────────────────────

describe("21A lifecycle state machine", () => {
  it("allows only the sanctioned transitions", () => {
    expect(transitionLifecycle("registered", "enabled").ok).toBe(true);
    expect(transitionLifecycle("enabled", "disabled").ok).toBe(true);
    expect(transitionLifecycle("disabled", "enabled").ok).toBe(true);
    expect(transitionLifecycle("disabled", "quarantined").ok).toBe(true);
    expect(transitionLifecycle("quarantined", "retired").ok).toBe(true);
    expect(transitionLifecycle("registered", "quarantined").ok).toBe(true);
  });

  it("quarantined cannot return to any executable state (T21-13)", () => {
    for (const to of ["registered", "enabled", "disabled"] as const) {
      const r = transitionLifecycle("quarantined", to);
      expect(r.ok).toBe(false);
    }
    expect(transitionLifecycle("retired", "enabled").ok).toBe(false);
    expect(transitionLifecycle("retired", "retired").ok).toBe(false);
  });

  it("quarantined/retired/disabled deny before any authority evaluation", () => {
    const m = parsedManifest();
    for (const state of ["disabled", "quarantined", "retired"] as const) {
      const d = gateToolExecution(goodRequest(), m, state);
      expect(d.status).toBe("validation_denied");
      expect(d.reason).toContain("not executable");
      expect(d.plan).toBeUndefined();
    }
    expect(isExecutableLifecycle("registered")).toBe(true);
    expect(isExecutableLifecycle("enabled")).toBe(true);
  });
});

// ── envelope: untrusted agent input (T21-03/04/05/09) ────────────────────────

describe("21A input envelope — untrusted data, can only reject", () => {
  it("rejects shell metacharacters in argv (T21-03)", () => {
    for (const bad of ["a;rm", "x|y", "`cmd`", "$(x)", "a>b", "a<b", "a&b"]) {
      const r = validateEnvelope({
        schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
        toolId: "demo.echo",
        version: "1.2.3",
        input: {},
        constraints: { argv: [bad] },
      });
      expect(r.ok, bad).toBe(false);
      if (!r.ok) expect(r.code).toBe("ARGS_FORBIDDEN");
    }
    // clean argv passes
    const ok = validateEnvelope({
      schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
      toolId: "demo.echo",
      version: "1.2.3",
      input: {},
      constraints: { argv: ["--flag", "value-with.dots_and-dashes"] },
    });
    expect(ok.ok).toBe(true);
  });

  it("constrains argv count/size, timeout, and output bounds (T21-09)", () => {
    const base = { schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION, toolId: "demo.echo", version: "1.2.3", input: {} };
    expect(validateEnvelope({ ...base, constraints: { argv: new Array(65).fill("a") } }).ok).toBe(false);
    expect(validateEnvelope({ ...base, constraints: { timeoutMs: 0 } }).ok).toBe(false);
    expect(validateEnvelope({ ...base, constraints: { timeoutMs: 600_001 } }).ok).toBe(false);
    expect(validateEnvelope({ ...base, constraints: { maxOutputBytes: 5_000_000 } }).ok).toBe(false);
    expect(validateEnvelope({ ...base, constraints: { timeoutMs: 1_000, maxOutputBytes: 1_000 } }).ok).toBe(true);
  });

  it("env allowlist accepts NAMES only — values never travel in envelopes (T21-05)", () => {
    const base = { schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION, toolId: "demo.echo", version: "1.2.3", input: {} };
    expect(validateEnvelope({ ...base, constraints: { envAllowlist: ["PATH", "MENOG_MODE"] } }).ok).toBe(true);
    for (const bad of ["path", "PATH=secret", "BAD-NAME", "A;B"]) {
      const r = validateEnvelope({ ...base, constraints: { envAllowlist: [bad] } });
      expect(r.ok, bad).toBe(false);
      if (!r.ok) expect(r.code).toBe("ENV_NAME_FORBIDDEN");
    }
  });

  it("cwd confinement: escape outside the authorized workspace is refused (T21-04)", () => {
    expect(isCwdInsideWorkspace("C:\\ws\\Menog-Os-V0\\sub", "C:\\ws\\Menog-Os-V0")).toBe(true);
    expect(isCwdInsideWorkspace("C:\\ws\\Menog-Os-V0\\..\\Elsewhere", "C:\\ws\\Menog-Os-V0")).toBe(false);
    expect(isCwdInsideWorkspace("/home/u/ws", "/home/u/ws")).toBe(true);
    expect(isCwdInsideWorkspace("/home/u/ws-other", "/home/u/ws")).toBe(false);
    expect(isCwdInsideWorkspace("/etc", "/home/u/ws")).toBe(false);
    expect(isCwdInsideWorkspace("/home/u/ws/../../etc", "/home/u/ws")).toBe(false);
  });
});

// ── the gate: full authority intersection (T21-01/02/07/11) ──────────────────

describe("21A gateToolExecution — the intersection can only deny", () => {
  it("produces a plan only when ALL five authorities line up", () => {
    const d = gateToolExecution(goodRequest(), parsedManifest(), "enabled");
    expect(d.status).toBe("not_started");
    expect(d.plan?.effectiveCapabilities.slice().sort()).toEqual(["workspace:annotate", "workspace:read"]);
    expect(d.plan?.isolationProfileId).toBe("exec-baseline");
  });

  it("spoofed identity across tool or version is denied (T21-01)", () => {
    const m = parsedManifest();
    expect(gateToolExecution(goodRequest({ toolId: "demo.other" }), m, "enabled").status).toBe("validation_denied");
    expect(gateToolExecution(goodRequest({ version: "9.9.9" }), m, "enabled").status).toBe("validation_denied");
    const spoofedEnvelope = goodRequest({
      envelope: { ...goodRequest().envelope, version: "0.0.1" },
    });
    expect(gateToolExecution(spoofedEnvelope, m, "enabled").status).toBe("validation_denied");
  });

  it("empty intersection denies before policy is consulted (T21-11)", () => {
    const d = gateToolExecution(
      goodRequest({ taskScope: ["workspace:read"], agentCapabilities: ["workspace:write"] }),
      parsedManifest(),
      "enabled"
    );
    expect(d.status).toBe("validation_denied");
    expect(d.reason).toContain("required capability 'workspace:read'");
  });

  it("policy deny never reaches a plan, even with permissive profiles (T21-07)", () => {
    const d = gateToolExecution(goodRequest({ policyOutcome: "deny", policyRuleId: "day1:default-deny" }), parsedManifest(), "enabled");
    expect(d.status).toBe("policy_denied");
    expect(d.plan).toBeUndefined();
    expect(d.reason).toContain("day1:default-deny");
  });

  it("isolation unenforceability denies after policy allow (allow is never sufficient)", () => {
    const d = gateToolExecution(
      goodRequest({ isolation: { profileId: "exec-baseline", canEnforce: false, reason: "required primitive UNSUPPORTED" } }),
      parsedManifest(),
      "enabled"
    );
    expect(d.status).toBe("isolation_denied");
    expect(d.plan).toBeUndefined();
    expect(d.reason).toContain("UNSUPPORTED");
  });

  it("status ordering: every deny status is distinct from every run status", () => {
    const m = parsedManifest();
    const statuses = [
      gateToolExecution(goodRequest({ policyOutcome: "deny" }), m, "enabled").status,
      gateToolExecution(goodRequest({ isolation: { profileId: "p", canEnforce: false } }), m, "enabled").status,
      gateToolExecution(goodRequest(), m, "quarantined").status,
    ];
    for (const s of statuses) {
      expect(["policy_denied", "isolation_denied", "validation_denied"]).toContain(s);
      expect(["not_started", "started", "completed", "failed", "timed_out"]).not.toContain(s);
    }
  });
});

// ── evidence: four layers, anti-overclaim (T21-12) ───────────────────────────

describe("21A evidence — requested ⊇ authorized ⊇ enforced ⊇ observed", () => {
  const base = {
    requestId: "req-ev",
    toolId: "demo.echo",
    version: "1.2.3",
    manifestHash: "deadbeef",
    status: "completed" as const,
    requested: ["workspace:read", "workspace:annotate"],
    authorized: ["workspace:read", "workspace:annotate"],
    enforced: ["workspace:read"],
    observed: ["workspace:read"],
    policyOutcome: "allow",
    isolationProfileId: "exec-baseline",
    recordedAt: "2026-09-27T00:00:00.000Z",
  };

  it("accepts consistent layering and hashes deterministically", () => {
    const a = buildToolEvidence(base);
    const b = buildToolEvidence(base);
    expect(a.ok).toBe(true);
    if (a.ok && b.ok) expect(a.value.evidenceHash).toBe(b.value.evidenceHash);
  });

  it("rejects overclaims in every direction (T21-12)", () => {
    expect(buildToolEvidence({ ...base, authorized: ["workspace:write"] }).ok).toBe(false); // write was never requested
    expect(buildToolEvidence({ ...base, enforced: ["workspace:write"] }).ok).toBe(false); // write was never authorized
    expect(buildToolEvidence({ ...base, observed: ["workspace:annotate"] }).ok).toBe(false); // observed ⊄ enforced (annotate never enforced)
  });

  it("denial statuses may not claim authorized capabilities", () => {
    expect(buildToolEvidence({ ...base, status: "policy_denied", enforced: [], observed: [] }).ok).toBe(false);
    expect(
      buildToolEvidence({ ...base, status: "isolation_denied", authorized: [], enforced: [], observed: [] }).ok
    ).toBe(true);
    expect(buildToolEvidence({ ...base, status: "not_started", enforced: ["workspace:read"], observed: [] }).ok).toBe(false);
  });
});

// ── version drift (T21-10) ───────────────────────────────────────────────────

describe("21A version drift", () => {
  it("same hash passes; any drift fails closed with MANIFEST_HASH_MISMATCH", () => {
    expect(checkVersionDrift({ toolId: "demo.echo", version: "1.2.3" }, "h1", "h1").ok).toBe(true);
    const r = checkVersionDrift({ toolId: "demo.echo", version: "1.2.3" }, "h1", "h2");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe("MANIFEST_HASH_MISMATCH");
      expect(r.message).toContain("demo.echo@1.2.3");
    }
  });
});
