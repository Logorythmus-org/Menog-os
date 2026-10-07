import { describe, it, expect } from "vitest";
import {
  VerbRegistry,
  INITIAL_VERBS,
  defaultVerbRegistry,
  type VerbContract,
} from "@menog/verbs";

describe("VerbRegistry — duplicate verb IDs rejected", () => {
  it("constructs with INITIAL_VERBS without duplicates", () => {
    const r = new VerbRegistry(INITIAL_VERBS);
    expect(r.size()).toBe(INITIAL_VERBS.length);
  });

  it("rejects registering a verb with an already-registered id", () => {
    const r = new VerbRegistry(INITIAL_VERBS);
    const duplicate: VerbContract = {
      id: "inspect",
      description: "duplicate",
      sideEffectClass: "read",
      requiredCapabilities: [],
      replayable: true,
      reversible: true,
      inputSchemaVersion: "0.0.1",
      outputSchemaVersion: "0.0.1",
    };
    const result = r.register(duplicate);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("duplicate verb id");
      expect(result.reason).toContain("inspect");
    }
    expect(r.size()).toBe(INITIAL_VERBS.length);
  });

  it("allows the same id to succeed in one registry and fail in an independent one only once", () => {
    const a = new VerbRegistry([]);
    const b = new VerbRegistry([]);
    const v: VerbContract = {
      id: "observe",
      description: "observe verb",
      sideEffectClass: "read",
      requiredCapabilities: [],
      replayable: true,
      reversible: true,
      inputSchemaVersion: "0.0.1",
      outputSchemaVersion: "0.0.1",
    };
    expect(a.register(v).ok).toBe(true);
    expect(b.register(v).ok).toBe(true);
    expect(a.register(v).ok).toBe(false);
  });
});

describe("VerbRegistry — unknown verb fails safely", () => {
  it("returns found=false with structured reason for a missing verb", () => {
    const r = defaultVerbRegistry;
    const result = r.get("does-not-exist");
    expect(result.found).toBe(false);
    if (!result.found) {
      expect(result.verbId).toBe("does-not-exist");
      expect(result.reason).toContain("unknown verb");
    }
  });

  it("rejects empty / non-string verb ids safely", () => {
    const r = defaultVerbRegistry;
    const empty = r.get("");
    expect(empty.found).toBe(false);
  });

  it("all initial verbs are registered and discoverable", () => {
    const r = defaultVerbRegistry;
    for (const v of INITIAL_VERBS) {
      const got = r.get(v.id);
      expect(got.found).toBe(true);
      if (got.found) {
        expect(got.verb.id).toBe(v.id);
      }
    }
  });
});

describe("VerbRegistry — inspect has no write/network/commit/privileged capability", () => {
  it("inspect declares only the four required capabilities with none of the forbidden", () => {
    const r = defaultVerbRegistry;
    const result = r.get("inspect");
    expect(result.found).toBe(true);
    if (!result.found) throw new Error("inspect missing");
    const inspect = result.verb;
    expect(inspect.executable).toBe(true);
    expect(inspect.sideEffectClass).toBe("read");
    expect([...inspect.requiredCapabilities].sort()).toEqual(
      [
        "workspace:list",
        "workspace:read-metadata",
        "git:status",
        "git:diff-read",
      ].sort()
    );
    const forbidden = [
      "workspace:write",
      "network:external",
      "git:commit",
      "process:privileged",
    ];
    for (const cap of forbidden) {
      expect(inspect.requiredCapabilities).not.toContain(cap);
    }
  });

  it("inspect sideEffectClass is 'read' (not write / network / system)", () => {
    const r = defaultVerbRegistry;
    const got = r.get("inspect");
    if (!got.found) throw new Error("inspect missing");
    expect(got.verb.sideEffectClass).toBe("read");
    expect(got.verb.sideEffectClass).not.toBe("write");
    expect(got.verb.sideEffectClass).not.toBe("network");
    expect(got.verb.sideEffectClass).not.toBe("system");
  });
});

describe("VerbRegistry — deterministic registry output", () => {
  it("list() returns verbs in registration order consistently", () => {
    const a = new VerbRegistry(INITIAL_VERBS);
    const b = new VerbRegistry(INITIAL_VERBS);
    expect(a.ids()).toEqual(b.ids());
    expect(a.list().map((v: { id: string }) => v.id)).toEqual(INITIAL_VERBS.map((v: { id: string }) => v.id));
  });

  it("deterministicFingerprint is stable across fresh registries with same input", () => {
    const a = new VerbRegistry(INITIAL_VERBS);
    const b = new VerbRegistry(INITIAL_VERBS);
    expect(a.deterministicFingerprint()).toBe(b.deterministicFingerprint());
  });

  it("fingerprint changes when a capability is altered (detects drift)", () => {
    const base = new VerbRegistry(INITIAL_VERBS);
    const custom = new VerbRegistry(INITIAL_VERBS.filter((v: { id: string }) => v.id !== "inspect"));
    const tamperedInspect: VerbContract = {
      id: "inspect",
      description: "tampered inspect",
      sideEffectClass: "write",
      requiredCapabilities: ["workspace:write"],
      replayable: false,
      reversible: false,
      inputSchemaVersion: "0.0.1",
      outputSchemaVersion: "0.0.1",
    };
    custom.register(tamperedInspect);
    expect(base.deterministicFingerprint()).not.toBe(custom.deterministicFingerprint());
  });

  it("verbatimVerb objects returned from list() are frozen", () => {
    const r = defaultVerbRegistry;
    const all = r.list();
    for (const v of all) {
      expect(Object.isFrozen(v)).toBe(true);
      expect(Object.isFrozen(v.requiredCapabilities)).toBe(true);
    }
  });
});
