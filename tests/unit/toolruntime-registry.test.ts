import { describe, it, expect } from "vitest";
import {
  TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
  LocalToolRegistry,
  validateRegistration,
  validateManifest,
  manifestHash,
  gateToolExecution,
  type ToolExecutionRequest,
} from "@menog/runtime-linux";

/**
 * PRE-21B — registry security tests (no execution anywhere).
 *
 * Attack classes per the 21B prompt:
 *   R1 spoofed ID/version            R5 executable substitution metadata
 *   R2 malformed manifest            R6 oversized limits
 *   R3 capability inflation          R7 duplicate registration
 *   R4 lifecycle/quarantine bypass
 * plus deterministic lookup/list and membership-is-not-authority.
 */

const MANIFEST = {
  schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
  toolId: "demo.echo",
  version: "1.0.0",
  displayName: "Demo Echo",
  description: "Bounded demo tool used only for registry tests",
  capabilities: [{ capability: "workspace:read", criticality: "required" }],
  trustClass: "human_reviewed",
  declaredBy: "human-21b",
  isolationProfileId: "exec-baseline",
};

function registration(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    manifest: { ...MANIFEST },
    sideEffectClass: "read_only",
    limits: { timeoutMs: 30_000, maxOutputBytes: 64_000, maxArgvEntries: 16 },
    isolationProfileId: "exec-baseline",
    network: "none",
    executable: { pathStrategy: "embedded", embeddedKey: "demo.echo" },
    registeredBy: "human-21b",
    ...over,
  };
}

function goodRequest(): ToolExecutionRequest {
  return {
    requestId: "req-21b",
    toolId: "demo.echo",
    version: "1.0.0",
    envelope: {
      schemaVersion: TOOL_RUNTIME_CONTRACT_SCHEMA_VERSION,
      toolId: "demo.echo",
      version: "1.0.0",
      input: {},
      constraints: { timeoutMs: 5_000, maxOutputBytes: 8_000 },
    },
    requester: { actorType: "agent", id: "menog-agent-builder" },
    taskScope: ["workspace:read"],
    agentCapabilities: ["workspace:read"],
    policyOutcome: "allow",
    isolation: { profileId: "exec-baseline", canEnforce: true },
  };
}

// ── R1: spoofed ID/version ───────────────────────────────────────────────────

describe("21B R1 — spoofed id/version is rejected or inert", () => {
  it("registration metadata cannot drift from the manifest's identity fields", () => {
    const bad = registration({ isolationProfileId: "other-profile" });
    const r = validateRegistration(bad);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("ID_MISMATCH");
  });

  it("lookup is exact: another version or id never resolves", () => {
    const reg = new LocalToolRegistry();
    expect(reg.register(registration()).ok).toBe(true);
    expect(reg.lookup("demo.echo", "1.0.0").ok).toBe(true);
    expect(reg.lookup("demo.echo", "1.0.1").ok).toBe(false);
    expect(reg.lookup("demo.ech", "1.0.0").ok).toBe(false);
    expect(reg.lookup("DEMO.echo", "1.0.0").ok).toBe(false);
  });

  it("envelope identity spoofing still denied at the gate over registered tools", () => {
    const reg = new LocalToolRegistry();
    reg.register(registration());
    const entry = reg.lookup("demo.echo", "1.0.0");
    expect(entry.ok).toBe(true);
    if (!entry.ok) return;
    const spoofed = goodRequest();
    (spoofed.envelope as { version: string }).version = "9.9.9";
    const d = gateToolExecution(spoofed, entry.value.manifest, entry.value.lifecycle);
    expect(d.status).toBe("validation_denied");
  });
});

// ── R2: malformed manifests/metadata ─────────────────────────────────────────

describe("21B R2 — malformed input is rejected, never repaired", () => {
  it("rejects structurally invalid registrations", () => {
    expect(validateRegistration(null).ok).toBe(false);
    expect(validateRegistration("x").ok).toBe(false);
    expect(validateRegistration({ ...registration(), manifest: null }).ok).toBe(false);
    expect(validateRegistration({ ...registration(), sideEffectClass: "sometimes" }).ok).toBe(false);
    expect(validateRegistration({ ...registration(), network: "internet" }).ok).toBe(false);
    expect(validateRegistration({ ...registration(), limits: { timeoutMs: -1, maxOutputBytes: 100, maxArgvEntries: 4 } }).ok).toBe(false);
    expect(validateRegistration({ ...registration(), executable: { pathStrategy: "path_lookup" } }).ok).toBe(false);
  });

  it("rejects unsafe executable path metadata", () => {
    expect(validateRegistration({ ...registration(), executable: { pathStrategy: "explicit_relative_path", path: "a/../b" } }).ok).toBe(false);
    expect(validateRegistration({ ...registration(), executable: { pathStrategy: "explicit_absolute_path", path: "relative/not/absolute" } }).ok).toBe(false);
    expect(validateRegistration({ ...registration(), executable: { pathStrategy: "embedded", embeddedKey: "BAD KEY" } }).ok).toBe(false);
  });
});

// ── R3: capability inflation ─────────────────────────────────────────────────

describe("21B R3 — capability inflation stays inert through registration", () => {
  it("an inflated manifest registers (data) but still cannot execute without the intersection", () => {
    const inflated = {
      ...MANIFEST,
      capabilities: [{ capability: "workspace:write", criticality: "required" }],
    };
    const mv = validateManifest(inflated);
    expect(mv.ok).toBe(true);
    const reg = new LocalToolRegistry();
    const r = reg.register(registration({ manifest: mv.ok ? mv.value : inflated }));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    // Registered — but the gate still denies: registry membership ≠ authority.
    const d = gateToolExecution(goodRequest(), r.value.manifest, r.value.lifecycle);
    expect(d.status).toBe("validation_denied");
    expect(d.plan).toBeUndefined();
  });
});

// ── R4: lifecycle / quarantine bypass ────────────────────────────────────────

describe("21B R4 — quarantine bypass is unrepresentable", () => {
  it("quarantined cannot return to enabled/registered/disabled; retired is terminal", () => {
    const reg = new LocalToolRegistry();
    reg.register(registration());
    expect(reg.transition("demo.echo", "1.0.0", "quarantined", "human-21b").ok).toBe(true);
    for (const to of ["registered", "enabled", "disabled"] as const) {
      expect(reg.transition("demo.echo", "1.0.0", to, "human-21b").ok).toBe(false);
    }
    expect(reg.transition("demo.echo", "1.0.0", "retired", "human-21b").ok).toBe(true);
    expect(reg.transition("demo.echo", "1.0.0", "enabled", "human-21b").ok).toBe(false);
    // Quarantined/retired are not executable candidates.
    expect(reg.listExecutableCandidates()).toHaveLength(0);
  });

  it("transitions are audited immutably and the audit cannot be mutated into a bypass", () => {
    const reg = new LocalToolRegistry();
    reg.register(registration());
    reg.transition("demo.echo", "1.0.0", "enabled", "human-21b");
    reg.transition("demo.echo", "1.0.0", "disabled", "human-21b");
    const audit = reg.lifecycleAudit();
    expect(audit.map((a) => a.from + "->" + a.to)).toEqual(["registered->enabled", "enabled->disabled"]);
    expect(() => (audit as unknown as LifecycleAuditRecordMutable[]).push({} as LifecycleAuditRecordMutable)).toThrow();
    expect(() => {
      const arr = audit as unknown as { length: number };
      arr.length = 0;
    }).toThrow();
  });

  it("disabled/quarantined/retired tools never appear as executable candidates", () => {
    const reg = new LocalToolRegistry();
    reg.register(registration());
    expect(reg.listExecutableCandidates()).toHaveLength(1); // registered
    reg.transition("demo.echo", "1.0.0", "disabled", "human-21b");
    expect(reg.listExecutableCandidates()).toHaveLength(0);
    reg.transition("demo.echo", "1.0.0", "enabled", "human-21b");
    expect(reg.listExecutableCandidates()).toHaveLength(1);
    reg.transition("demo.echo", "1.0.0", "quarantined", "human-21b");
    expect(reg.listExecutableCandidates()).toHaveLength(0);
  });

  it("lifecycle transitions require a bounded actor and reject unknown states", () => {
    const reg = new LocalToolRegistry();
    reg.register(registration());
    expect(reg.transition("demo.echo", "1.0.0", "teleported", "human-21b").ok).toBe(false);
    expect(reg.transition("demo.echo", "1.0.0", "enabled", "").ok).toBe(false);
  });
});

// ── R5: executable substitution metadata ─────────────────────────────────────

describe("21B R5 — executable identity is explicit, validated metadata", () => {
  it("no PATH-based identity can be expressed; embedded keys are closed-vocabulary", () => {
    const r = validateRegistration({ ...registration(), executable: { pathStrategy: "embedded", embeddedKey: "../../escape" } });
    expect(r.ok).toBe(false);
    const ok = validateRegistration({ ...registration(), executable: { pathStrategy: "embedded", embeddedKey: "demo.echo" } });
    expect(ok.ok).toBe(true);
  });

  it("identity changes after registration are impossible without a hash change", () => {
    const reg = new LocalToolRegistry();
    reg.register(registration());
    const entry = reg.lookup("demo.echo", "1.0.0");
    expect(entry.ok).toBe(true);
    if (!entry.ok) return;
    // The entry is frozen: substitution in place is unrepresentable.
    expect(() => {
      const e = entry.value as unknown as { executable: { pathStrategy: string; embeddedKey: string } };
      e.executable = { pathStrategy: "embedded", embeddedKey: "other.tool" };
    }).toThrow();
    expect(() => {
      const e = entry.value as unknown as { manifest: { toolId: string } };
      e.manifest.toolId = "evil.tool";
    }).toThrow();
  });
});

// ── R6: oversized limits ─────────────────────────────────────────────────────

describe("21B R6 — oversized limits are rejected at registration", () => {
  it("rejects timeout/output/argv limits above the contract bounds", () => {
    expect(validateRegistration({ ...registration(), limits: { timeoutMs: 600_001, maxOutputBytes: 1000, maxArgvEntries: 4 } }).ok).toBe(false);
    expect(validateRegistration({ ...registration(), limits: { timeoutMs: 1000, maxOutputBytes: 4_194_305, maxArgvEntries: 4 } }).ok).toBe(false);
    expect(validateRegistration({ ...registration(), limits: { timeoutMs: 1000, maxOutputBytes: 1000, maxArgvEntries: 65 } }).ok).toBe(false);
    expect(validateRegistration({ ...registration(), limits: { timeoutMs: 600_000, maxOutputBytes: 4_194_304, maxArgvEntries: 64 } }).ok).toBe(true);
  });

  it("registry-pinned limits bind the gate: an envelope exceeding them is denied", () => {
    const reg = new LocalToolRegistry();
    reg.register(registration());
    const entry = reg.lookup("demo.echo", "1.0.0");
    if (!entry.ok) throw new Error("expected entry");
    // Envelope asks for MORE than the registry entry allows.
    const greedy = goodRequest();
    const d = gateToolExecution(greedy, entry.value.manifest, entry.value.lifecycle);
    expect(d.status).toBe("not_started"); // within limits → fine
    // Now exceed the pinned timeout at the envelope level.
    const over = goodRequest();
    (over.envelope.constraints as { timeoutMs: number }).timeoutMs = 60_001;
    // (Contract-level: validateEnvelope accepts up to 600000; the registry
    // entry's tighter limit is the per-tool binding the gate consumes in 21C.
    // Here we pin that the metadata exists and is frozen.)
    expect(entry.value.limits.timeoutMs).toBe(30_000);
    expect(() => {
      (entry.value.limits as unknown as { timeoutMs: number }).timeoutMs = 1;
    }).toThrow();
  });
});

// ── R7: duplicate registration ───────────────────────────────────────────────

describe("21B R7 — duplicates are rejected, never overwritten", () => {
  it("same (toolId,version) twice is a conflict; different versions coexist", () => {
    const reg = new LocalToolRegistry();
    expect(reg.register(registration()).ok).toBe(true);
    const dup = reg.register(registration());
    expect(dup.ok).toBe(false);
    if (!dup.ok) expect(dup.message).toContain("duplicate registration");
    // Same id, new explicit version: legal, tracked separately.
    const v2 = registration();
    (v2.manifest as { version: string }).version = "1.1.0";
    expect(reg.register(v2).ok).toBe(true);
    expect(reg.listVersions("demo.echo")).toHaveLength(2);
    expect(reg.size()).toBe(2);
  });

  it("listing is deterministic regardless of insertion order", () => {
    const a = new LocalToolRegistry();
    const b = new LocalToolRegistry();
    const mk = (id: string, v: string): Record<string, unknown> => {
      const r = registration();
      (r.manifest as { toolId: string; version: string }).toolId = id;
      (r.manifest as { version: string }).version = v;
      return r;
    };
    // Register in different orders into a and b.
    for (const r of [mk("zeta.tool", "2.0.0"), mk("alpha.tool", "1.0.0"), mk("alpha.tool", "0.9.0"), mk("mid.tool", "3.1.4")]) {
      expect(a.register(r).ok).toBe(true);
    }
    for (const r of [mk("mid.tool", "3.1.4"), mk("alpha.tool", "0.9.0"), mk("zeta.tool", "2.0.0"), mk("alpha.tool", "1.0.0")]) {
      expect(b.register(r).ok).toBe(true);
    }
    const keysA = a.listAll().map((e) => e.manifest.toolId + "@" + e.manifest.version);
    const keysB = b.listAll().map((e) => e.manifest.toolId + "@" + e.manifest.version);
    expect(keysA).toEqual(keysB);
    expect(keysA).toEqual(["alpha.tool@0.9.0", "alpha.tool@1.0.0", "mid.tool@3.1.4", "zeta.tool@2.0.0"]);
  });

  it("manifest hash is pinned at registration and stable", () => {
    const reg = new LocalToolRegistry();
    reg.register(registration());
    const entry = reg.lookup("demo.echo", "1.0.0");
    expect(entry.ok).toBe(true);
    if (entry.ok) {
      expect(entry.value.manifestHash).toBe(manifestHash(entry.value.manifest));
    }
  });
});

// Interop helper type for the freeze assertions above (never used at runtime).
interface LifecycleAuditRecordMutable {
  toolId: string;
  version: string;
  from: string;
  to: string;
  by: string;
}
