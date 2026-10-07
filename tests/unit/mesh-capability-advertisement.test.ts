/**
 * PHASE 27D — Capability Advertisement Tests (UNTRUSTED REMOTE CLAIMS /
 * BOUNDED / VERSIONED / PROVENANCE-RICH / ADVERTISEMENT != GRANT).
 *
 * Pins the registry's laws structurally and behaviorally:
 *   · closed vocabularies + frozen bounds (pinned exact values);
 *   · provenance: unknown source refuses, evidence rules enforced;
 *   · shape/malformed inputs fail closed;
 *   · inflation (claim count + duplicates) refuses, never truncates;
 *   · secret / executable / forbidden material refuses — including
 *     JSON-NESTED smuggling parsed at depth;
 *   · frozen 27A composition (anonymous claim, closed claim vocabulary,
 *     unknown kind, capability-kind-only gate);
 *   · versioning: new ids start at 1, rotation is exactly +1 with fresher
 *     facts, replay is idempotent, same-version conflicts, stale versions,
 *     version gaps, claimant hijacks and stale rotation facts refuse;
 *   · rotation REPLACES the claim set (no union — claims never widen);
 *   · bounds refuse, never evict; refusals leave the registry unchanged;
 *   · deterministic snapshots/fingerprints; frozen records;
 *   · structural no-grant / no-widening literals and a pinned prototype
 *     method surface (no union/merge/grant method exists);
 *   · no network/store/clock surfaces (source scan + import pin).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  CAPABILITY_ADVERTISEMENT_SCHEMA_VERSION,
  CAPABILITY_ADVERTISEMENT_REFUSAL_CODES,
  ADVERTISEMENT_REGISTRY_BOUNDS,
  ADVERTISEMENT_PROVENANCE_SOURCES,
  CapabilityAdvertisementRegistry,
  type CapabilityAdvertisementDecision,
  type CapabilityAdvertisementInput,
  type CapabilityAdvertisementRefusalCode,
  type AdvertisementProvenance,
  type MeshAdvertisementKind,
  type MeshCapabilityClaim,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

/** Surfaces the 27D module must NEVER contain (structural no-socket pin). */
const FORBIDDEN_SURFACES: readonly string[] = Object.freeze([
  "child_process",
  "node:net",
  "node:http",
  "node:https",
  "node:dgram",
  "node:tls",
  "node:dns",
  "node:crypto",
  "WebSocket",
  "fetch(",
  "spawn(",
  "listen(",
  "createServer",
  "connect(",
  "createSocket",
  "createHash",
  "DatabaseSync",
  "acceptMutation",
  "setInterval",
  "setTimeout",
  "Date.now",
  "performance.now",
  ".persist(",
  "DurableStore",
  "PeerRegistry",
  "executeToolRun",
  "runIsolated",
  "toolJunction",
  "requireTool",
]);

/** The ONLY modules the 27D module may import (pinned). */
const ALLOWED_IMPORTS = Object.freeze([
  "./canonical.js",
  "./federationEgress.js",
  "./meshTopologyTrust.js",
]);

const NOW = 1_700_000_000_000;
const NODE_B = "node-" + "b".repeat(64);
const NODE_C = "node-" + "c".repeat(64);
const NODE_D = "node-" + "d".repeat(64);

const ADV = (over: Partial<CapabilityAdvertisementInput> = {}): CapabilityAdvertisementInput => ({
  advertisementId: "adv-1",
  claimingNodeId: NODE_B,
  kind: "capability_advertisement",
  capabilityClaims: ["claim_can_forward_proposals"],
  version: 1,
  detail: "reachable on the local lan",
  provenance: {
    source: "governed_evidence",
    evidenceId: "ev-1",
    recordedAtEpochMs: NOW,
  },
  observedAtEpochMs: NOW,
  ...over,
});

const OK_CODES = new Set(["advertisement_recorded", "advertisement_rotated", "advertisement_replayed"]);

/** Every successful decision must carry the structural no-grant literals. */
function expectNoGrant(d: CapabilityAdvertisementDecision): void {
  expect(d.ok).toBe(true);
  if (d.ok && OK_CODES.has(d.code)) {
    expect(d.grant).toBe("none");
    expect(d.capabilitiesWidened).toBe(false);
  }
}

/** Assert a closed-vocabulary refusal: explained, hashed, no grant field. */
function expectRefusal(
  d: CapabilityAdvertisementDecision,
  refusal: CapabilityAdvertisementRefusalCode,
): void {
  expect(d.ok).toBe(false);
  if (!d.ok) {
    expect(d.code).toBe("advertisement_refused");
    expect(d.refusal).toBe(refusal);
    expect(d.explanation.length).toBeGreaterThan(20);
    expect(d.explanation).toMatch(/refus/);
    expect(d.provenanceHash).toMatch(/^[0-9a-f]{64}$/);
    expect("grant" in d).toBe(false);
    expect("capabilitiesWidened" in d).toBe(false);
    expect(d.advertisementCount).toBeGreaterThanOrEqual(0);
  }
}

/** Assert a successful decision of the exact expected code (no-grant pinned). */
function expectOkCode(
  d: CapabilityAdvertisementDecision,
  code: "advertisement_recorded" | "advertisement_rotated" | "advertisement_replayed",
): void {
  expect(d.ok).toBe(true);
  if (d.ok) {
    expect(d.code).toBe(code);
    expectNoGrant(d);
    expect(d.explanation.length).toBeGreaterThan(0);
    expect(d.provenanceHash).toMatch(/^[0-9a-f]{64}$/);
  }
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("27D structure — closed vocabulary, frozen bounds, law surfaces", () => {
  it("forbidden surfaces list is pinned and the module contains none of them", () => {
    expect(FORBIDDEN_SURFACES).toEqual([
      "child_process",
      "node:net",
      "node:http",
      "node:https",
      "node:dgram",
      "node:tls",
      "node:dns",
      "node:crypto",
      "WebSocket",
      "fetch(",
      "spawn(",
      "listen(",
      "createServer",
      "connect(",
      "createSocket",
      "createHash",
      "DatabaseSync",
      "acceptMutation",
      "setInterval",
      "setTimeout",
      "Date.now",
      "performance.now",
      ".persist(",
      "DurableStore",
      "PeerRegistry",
      "executeToolRun",
      "runIsolated",
      "toolJunction",
      "requireTool",
    ]);
    const code = codeOnly(SRC("meshCapabilityAdvertisement.ts"));
    for (const forbidden of FORBIDDEN_SURFACES) {
      expect(code).not.toContain(forbidden);
    }
    expect(code).not.toContain(".persist(");
  });

  it("module imports ONLY the pinned local modules (no network, no store, no clock)", () => {
    const src = SRC("meshCapabilityAdvertisement.ts");
    const imports = [
      ...[...src.matchAll(/^import [^\n]* from "([^"]+)"/gm)].map((m) => m[1] as string),
      ...[...src.matchAll(/^\} from "([^"]+)"/gm)].map((m) => m[1] as string),
    ].sort();
    expect(imports).toEqual([...ALLOWED_IMPORTS].sort());
  });

  it("schema version and registry bounds are pinned frozen constants", () => {
    expect(CAPABILITY_ADVERTISEMENT_SCHEMA_VERSION).toBe(
      "menog-mesh-capability-advertisement/v0",
    );
    expect(ADVERTISEMENT_REGISTRY_BOUNDS).toEqual({
      maxAdvertisements: 64,
      maxAdvertisementsPerClaimant: 8,
      maxClaimsPerAdvertisement: 4,
      maxAdvertisementIdChars: 128,
      maxClaimantIdChars: 128,
      maxDetailChars: 512,
    });
    expect(Object.isFrozen(ADVERTISEMENT_REGISTRY_BOUNDS)).toBe(true);
  });

  it("provenance source vocabulary is a pinned frozen closed set", () => {
    expect([...ADVERTISEMENT_PROVENANCE_SOURCES]).toEqual([
      "local_configuration",
      "governed_evidence",
      "unknown_source",
    ]);
    expect(Object.isFrozen(ADVERTISEMENT_PROVENANCE_SOURCES)).toBe(true);
  });

  it("refusal vocabulary is a pinned frozen closed set (fail-closed, no silent handling)", () => {
    expect([...CAPABILITY_ADVERTISEMENT_REFUSAL_CODES]).toEqual([
      "refused_invalid_advertisement",
      "refused_wrong_advertisement_kind",
      "refused_unknown_advertisement_kind",
      "refused_unknown_provenance_source",
      "refused_invalid_provenance",
      "refused_oversize_field",
      "refused_claim_inflation",
      "refused_secret_material",
      "refused_executable_material",
      "refused_forbidden_material",
      "refused_anonymous_claim",
      "refused_unknown_capability_claim",
      "refused_claimant_mismatch",
      "refused_stale_version",
      "refused_version_conflict",
      "refused_version_gap",
      "refused_stale_fact",
      "refused_claimant_bound",
      "refused_registry_bound",
      "refused_unknown",
    ]);
    expect(Object.isFrozen(CAPABILITY_ADVERTISEMENT_REFUSAL_CODES)).toBe(true);
  });
});

// ── provenance ───────────────────────────────────────────────────────────────

describe("27D provenance — records enter ONLY from sanctioned sources", () => {
  it("unknown_source refuses (an unnamed channel is never recorded)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    const d = reg.record(
      ADV({ provenance: { source: "unknown_source", evidenceId: null, recordedAtEpochMs: NOW } }),
    );
    expectRefusal(d, "refused_unknown_provenance_source");
    expect(reg.advertisementCount).toBe(0);
  });

  it("a source outside the closed vocabulary refuses (no gossip, no discovery)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    const d = reg.record(
      ADV({
        provenance: {
          source: "gossip_channel" as unknown as AdvertisementProvenance["source"],
          evidenceId: null,
          recordedAtEpochMs: NOW,
        },
      }),
    );
    expectRefusal(d, "refused_unknown_provenance_source");
    expect(reg.advertisementCount).toBe(0);
  });

  it("missing provenance refuses (fail closed — never a default source)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    const input = ADV();
    const d = reg.record({
      ...input,
      provenance: undefined as unknown as AdvertisementProvenance,
    });
    expectRefusal(d, "refused_unknown_provenance_source");
    expect(reg.advertisementCount).toBe(0);
  });

  it("governed evidence MUST cite an evidence id (null or empty refuses)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(
      reg.record(ADV({ provenance: { source: "governed_evidence", evidenceId: null, recordedAtEpochMs: NOW } })),
      "refused_invalid_provenance",
    );
    expectRefusal(
      reg.record(ADV({ provenance: { source: "governed_evidence", evidenceId: "", recordedAtEpochMs: NOW } })),
      "refused_invalid_provenance",
    );
    expect(reg.advertisementCount).toBe(0);
  });

  it("local configuration MUST NOT pretend to cite evidence", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(
      reg.record(ADV({ provenance: { source: "local_configuration", evidenceId: "ev-9", recordedAtEpochMs: NOW } })),
      "refused_invalid_provenance",
    );
    expect(reg.advertisementCount).toBe(0);
  });

  it("local configuration with a null evidence id records normally", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    const d = reg.record(
      ADV({ provenance: { source: "local_configuration", evidenceId: null, recordedAtEpochMs: NOW } }),
    );
    expectOkCode(d, "advertisement_recorded");
    const stored = reg.get("adv-1");
    expect(stored?.provenance.source).toBe("local_configuration");
    expect(stored?.provenance.evidenceId).toBeNull();
  });

  it("non-finite or negative recorded time refuses", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(
      reg.record(ADV({ provenance: { source: "governed_evidence", evidenceId: "ev-1", recordedAtEpochMs: Number.NaN } })),
      "refused_invalid_provenance",
    );
    expectRefusal(
      reg.record(ADV({ provenance: { source: "governed_evidence", evidenceId: "ev-1", recordedAtEpochMs: -1 } })),
      "refused_invalid_provenance",
    );
    expect(reg.advertisementCount).toBe(0);
  });
});

// ── shape (fail closed) ──────────────────────────────────────────────────────

describe("27D shape — malformed advertisements fail closed", () => {
  it("non-integer, zero, and negative versions refuse", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    for (const version of [0, -3, 1.5]) {
      expectRefusal(reg.record(ADV({ version })), "refused_invalid_advertisement");
    }
    expect(reg.advertisementCount).toBe(0);
  });

  it("an empty advertisement id refuses", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(reg.record(ADV({ advertisementId: "" })), "refused_invalid_advertisement");
    expect(reg.advertisementCount).toBe(0);
  });

  it("a non-array claim payload refuses (claims are never coerced)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(
      reg.record(ADV({ capabilityClaims: "claim_can_forward_proposals" as unknown as readonly MeshCapabilityClaim[] })),
      "refused_invalid_advertisement",
    );
    expect(reg.advertisementCount).toBe(0);
  });

  it("non-finite or negative observation time refuses", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(reg.record(ADV({ observedAtEpochMs: Number.POSITIVE_INFINITY })), "refused_invalid_advertisement");
    expectRefusal(reg.record(ADV({ observedAtEpochMs: -1 })), "refused_invalid_advertisement");
    expect(reg.advertisementCount).toBe(0);
  });
});

// ── bounds + inflation ───────────────────────────────────────────────────────

describe("27D bounds — a caller may exceed a bound, never redefine one", () => {
  it("oversize id, claimant, or detail refuses (never truncates)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(
      reg.record(ADV({ advertisementId: "a".repeat(ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisementIdChars + 1) })),
      "refused_oversize_field",
    );
    expectRefusal(
      reg.record(ADV({ claimingNodeId: "c".repeat(ADVERTISEMENT_REGISTRY_BOUNDS.maxClaimantIdChars + 1) })),
      "refused_oversize_field",
    );
    expectRefusal(
      reg.record(ADV({ detail: "x".repeat(ADVERTISEMENT_REGISTRY_BOUNDS.maxDetailChars + 1) })),
      "refused_oversize_field",
    );
    expect(reg.advertisementCount).toBe(0);
  });

  it("claim-count inflation refuses (more claims can never look more capable)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(
      reg.record(
        ADV({
          capabilityClaims: [
            "claim_can_forward_proposals",
            "claim_reachable_on_local_lan",
            "claim_supports_framed_transport",
            "claim_topology_summary",
            "claim_can_forward_proposals",
          ],
        }),
      ),
      "refused_claim_inflation",
    );
    expect(reg.advertisementCount).toBe(0);
  });

  it("duplicate claims refuse (a claim set is bounded and duplicate-free)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(
      reg.record(ADV({ capabilityClaims: ["claim_can_forward_proposals", "claim_can_forward_proposals"] })),
      "refused_claim_inflation",
    );
    expect(reg.advertisementCount).toBe(0);
  });
});

// ── material rejection ───────────────────────────────────────────────────────

describe("27D material rejection — secret/executable material never rides in", () => {
  it("a secret-key-shaped field nested inside a JSON detail string refuses", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(reg.record(ADV({ detail: "{\"private_key\":\"AAAA\"}" })), "refused_secret_material");
    expect(reg.advertisementCount).toBe(0);
  });

  it("secret material nested inside a claim is parsed at depth and refuses", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(
      reg.record(
        ADV({
          capabilityClaims: ["{\"private_key\":\"AAAA\"}"] as unknown as readonly MeshCapabilityClaim[],
        }),
      ),
      "refused_secret_material",
    );
    expect(reg.advertisementCount).toBe(0);
  });

  it("a PEM private-key block refuses", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    const pem = "-----BEGIN " + "PRIVATE KEY-----";
    expectRefusal(reg.record(ADV({ detail: pem })), "refused_secret_material");
    expect(reg.advertisementCount).toBe(0);
  });

  it("executable shell material refuses (a claim is never a command)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(reg.record(ADV({ detail: "sh -c id" })), "refused_executable_material");
    expect(reg.advertisementCount).toBe(0);
  });

  it("local-path (forbidden) material refuses", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(reg.record(ADV({ detail: "/etc/menog/config" })), "refused_forbidden_material");
    expect(reg.advertisementCount).toBe(0);
  });
});

// ── frozen 27A composition ───────────────────────────────────────────────────

describe("27D composition — the frozen 27A advertisement contract decides claims", () => {
  it("an anonymous claim (empty claimant) refuses", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(reg.record(ADV({ claimingNodeId: "" })), "refused_anonymous_claim");
    expect(reg.advertisementCount).toBe(0);
  });

  it("a claim outside the closed 27A vocabulary refuses", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(
      reg.record(ADV({ capabilityClaims: ["claim_teleport"] as unknown as readonly MeshCapabilityClaim[] })),
      "refused_unknown_capability_claim",
    );
    expect(reg.advertisementCount).toBe(0);
  });

  it("the unknown_capability_claim sentinel refuses", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(
      reg.record(ADV({ capabilityClaims: ["unknown_capability_claim"] })),
      "refused_unknown_capability_claim",
    );
    expect(reg.advertisementCount).toBe(0);
  });

  it("the 27A unknown_advertisement kind refuses", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(reg.record(ADV({ kind: "unknown_advertisement" })), "refused_unknown_advertisement_kind");
    expect(reg.advertisementCount).toBe(0);
  });

  it("an unnamed kind refuses (fail closed — never rides through as DATA)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(
      reg.record(ADV({ kind: "mystery_advertisement" as MeshAdvertisementKind })),
      "refused_unknown",
    );
    expect(reg.advertisementCount).toBe(0);
  });

  it("a VALID but non-capability 27A kind refuses (capability claims ONLY)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(reg.record(ADV({ kind: "topology_advertisement" })), "refused_wrong_advertisement_kind");
    expect(reg.advertisementCount).toBe(0);
  });
});

// ── versioning ───────────────────────────────────────────────────────────────

describe("27D versioning — new ids start at 1, rotations advance by exactly one", () => {
  it("a NEW advertisement at a version > 1 refuses (no skipped origin)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectRefusal(reg.record(ADV({ advertisementId: "adv-new", version: 2 })), "refused_version_gap");
    expect(reg.advertisementCount).toBe(0);
  });

  it("a rotation to exactly +1 with strictly fresher facts records", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectOkCode(reg.record(ADV()), "advertisement_recorded");
    const d = reg.record(
      ADV({
        version: 2,
        capabilityClaims: ["claim_reachable_on_local_lan"],
        detail: "reachability confirmed",
        provenance: { source: "governed_evidence", evidenceId: "ev-2", recordedAtEpochMs: NOW + 1_000 },
        observedAtEpochMs: NOW + 1_000,
      }),
    );
    expectOkCode(d, "advertisement_rotated");
    if (d.ok) {
      expect(d.storedVersion).toBe(2);
    }
    expect(reg.advertisementCount).toBe(1);
    expect(reg.get("adv-1")?.version).toBe(2);
  });

  it("a rotation without strictly fresher provenance time refuses (stale fact)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    reg.record(ADV());
    expectRefusal(
      reg.record(
        ADV({
          version: 2,
          provenance: { source: "governed_evidence", evidenceId: "ev-2", recordedAtEpochMs: NOW },
          observedAtEpochMs: NOW + 1_000,
        }),
      ),
      "refused_stale_fact",
    );
    expect(reg.get("adv-1")?.version).toBe(1);
  });

  it("a rotation with an older observation refuses (stale fact)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    reg.record(ADV());
    expectRefusal(
      reg.record(
        ADV({
          version: 2,
          provenance: { source: "governed_evidence", evidenceId: "ev-2", recordedAtEpochMs: NOW + 1_000 },
          observedAtEpochMs: NOW - 1_000,
        }),
      ),
      "refused_stale_fact",
    );
    expect(reg.get("adv-1")?.version).toBe(1);
  });

  it("a version jump beyond +1 refuses (no unseen claim skips in)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    reg.record(ADV());
    expectRefusal(reg.record(ADV({ version: 3 })), "refused_version_gap");
    expect(reg.get("adv-1")?.version).toBe(1);
  });

  it("a same-version identical re-send replays idempotently (counts unchanged)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectOkCode(reg.record(ADV()), "advertisement_recorded");
    const fp = reg.fingerprint();
    const d = reg.record(ADV());
    expectOkCode(d, "advertisement_replayed");
    if (d.ok) {
      expect(d.storedVersion).toBe(1);
    }
    expect(reg.advertisementCount).toBe(1);
    expect(reg.fingerprint()).toBe(fp);
  });

  it("same-version DIFFERENT content refuses (first evidenced claim stands)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    reg.record(ADV());
    const fp = reg.fingerprint();
    expectRefusal(
      reg.record(ADV({ detail: "a different claim at the same version" })),
      "refused_version_conflict",
    );
    expect(reg.advertisementCount).toBe(1);
    expect(reg.fingerprint()).toBe(fp);
  });

  it("an older version refuses after rotation (a rotated-out claim never returns)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    reg.record(ADV());
    reg.record(
      ADV({
        version: 2,
        capabilityClaims: ["claim_reachable_on_local_lan"],
        provenance: { source: "governed_evidence", evidenceId: "ev-2", recordedAtEpochMs: NOW + 1_000 },
        observedAtEpochMs: NOW + 1_000,
      }),
    );
    expectRefusal(reg.record(ADV()), "refused_stale_version");
    const stored = reg.get("adv-1");
    expect([...(stored?.capabilityClaims ?? [])]).toEqual(["claim_reachable_on_local_lan"]);
  });

  it("another node can never re-claim a stored id (no hijack, no overwrite)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    reg.record(ADV());
    expectRefusal(reg.record(ADV({ claimingNodeId: NODE_C })), "refused_claimant_mismatch");
    expect(reg.get("adv-1")?.claimingNodeId).toBe(NODE_B);
  });
});

// ── rotation replaces claims (no union, ever) ────────────────────────────────

describe("27D rotation — the claim set is REPLACED, never unioned", () => {
  it("rotation drops the previous claims (claims never widen by accumulation)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectOkCode(
      reg.record(ADV({ capabilityClaims: ["claim_can_forward_proposals", "claim_topology_summary"] })),
      "advertisement_recorded",
    );
    expectOkCode(
      reg.record(
        ADV({
          version: 2,
          capabilityClaims: ["claim_reachable_on_local_lan"],
          detail: "narrowed to reachability",
          provenance: { source: "governed_evidence", evidenceId: "ev-2", recordedAtEpochMs: NOW + 1_000 },
          observedAtEpochMs: NOW + 1_000,
        }),
      ),
      "advertisement_rotated",
    );
    const stored = reg.get("adv-1");
    expect(stored).not.toBeNull();
    if (stored) {
      expect([...stored.capabilityClaims]).toEqual(["claim_reachable_on_local_lan"]);
      expect([...stored.capabilityClaims]).not.toContain("claim_can_forward_proposals");
      expect([...stored.capabilityClaims]).not.toContain("claim_topology_summary");
      expect(Object.isFrozen(stored)).toBe(true);
      expect(Object.isFrozen(stored.capabilityClaims)).toBe(true);
      expect(Object.isFrozen(stored.provenance)).toBe(true);
    }
    expect(reg.advertisementCount).toBe(1);
  });

  it("every refusal leaves the registry EXACTLY as it was", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectOkCode(reg.record(ADV()), "advertisement_recorded");
    const fp = reg.fingerprint();
    const before = reg.get("adv-1");
    expectRefusal(reg.record(ADV({ claimingNodeId: NODE_C })), "refused_claimant_mismatch");
    expectRefusal(reg.record(ADV({ detail: "conflicting content" })), "refused_version_conflict");
    expectRefusal(reg.record(ADV({ version: 9 })), "refused_version_gap");
    expectRefusal(reg.record(ADV({ advertisementId: "" })), "refused_invalid_advertisement");
    expect(reg.advertisementCount).toBe(1);
    expect(reg.fingerprint()).toBe(fp);
    expect(reg.get("adv-1")).toEqual(before);
  });
});

// ── registry bounds ──────────────────────────────────────────────────────────

describe("27D registry bounds — refuse, never evict, never grow past", () => {
  it("per-claimant bound: the 9th advertisement for one claimant refuses", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    for (let i = 0; i < ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisementsPerClaimant; i += 1) {
      expectOkCode(reg.record(ADV({ advertisementId: "adv-b-" + i })), "advertisement_recorded");
    }
    expect(reg.advertisementCount).toBe(ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisementsPerClaimant);
    const fp = reg.fingerprint();
    expectRefusal(
      reg.record(ADV({ advertisementId: "adv-b-" + ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisementsPerClaimant })),
      "refused_claimant_bound",
    );
    expect(reg.advertisementCount).toBe(ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisementsPerClaimant);
    expect(reg.fingerprint()).toBe(fp);
  });

  it("registry bound: a new advertisement at 64 refuses (never evict)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    const claimant = (i: number): string => ("node-" + i + "-peer-").padEnd(48, "p");
    let recorded = 0;
    for (let c = 0; c < 8; c += 1) {
      for (let a = 0; a < ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisementsPerClaimant; a += 1) {
        expectOkCode(
          reg.record(ADV({ advertisementId: "adv-fill-" + c + "-" + a, claimingNodeId: claimant(c) })),
          "advertisement_recorded",
        );
        recorded += 1;
      }
    }
    expect(recorded).toBe(ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisements);
    expect(reg.advertisementCount).toBe(ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisements);
    const fp = reg.fingerprint();
    expectRefusal(
      reg.record(ADV({ advertisementId: "adv-overflow", claimingNodeId: claimant(8) })),
      "refused_registry_bound",
    );
    expect(reg.advertisementCount).toBe(ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisements);
    expect(reg.fingerprint()).toBe(fp);
  });
});

// ── snapshot / fingerprint ───────────────────────────────────────────────────

describe("27D snapshot/fingerprint — deterministic read-only knowledge", () => {
  it("snapshot is canonically sorted and frozen regardless of insertion order", () => {
    const a = CapabilityAdvertisementRegistry.open();
    a.record(ADV({ advertisementId: "adv-3" }));
    a.record(ADV({ advertisementId: "adv-1", claimingNodeId: NODE_D }));
    a.record(ADV({ advertisementId: "adv-2" }));
    const b = CapabilityAdvertisementRegistry.open();
    b.record(ADV({ advertisementId: "adv-2" }));
    b.record(ADV({ advertisementId: "adv-1", claimingNodeId: NODE_D }));
    b.record(ADV({ advertisementId: "adv-3" }));
    const idsA = a.snapshot().map((r) => r.advertisementId);
    const idsB = b.snapshot().map((r) => r.advertisementId);
    expect(idsA).toEqual(["adv-1", "adv-2", "adv-3"]);
    expect(idsB).toEqual(idsA);
    expect(a.fingerprint()).toBe(b.fingerprint());
    const snap = a.snapshot();
    expect(Object.isFrozen(snap)).toBe(true);
    for (const stored of snap) {
      expect(Object.isFrozen(stored)).toBe(true);
      expect(Object.isFrozen(stored.capabilityClaims)).toBe(true);
      expect(Object.isFrozen(stored.provenance)).toBe(true);
      expect(stored.contentHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("fingerprints are deterministic, order-insensitive, pure, 64-hex", () => {
    const emptyA = CapabilityAdvertisementRegistry.open();
    const emptyB = CapabilityAdvertisementRegistry.open();
    expect(emptyA.fingerprint()).toBe(emptyB.fingerprint());
    expect(emptyA.fingerprint()).toMatch(/^[0-9a-f]{64}$/);
    const reg = CapabilityAdvertisementRegistry.open();
    expectOkCode(reg.record(ADV()), "advertisement_recorded");
    const first = reg.fingerprint();
    expect(reg.snapshot().length).toBe(1);
    expect(reg.fingerprint()).toBe(first);
    expect(reg.has("adv-1")).toBe(true);
    expect(reg.has("adv-missing")).toBe(false);
    expect(reg.get("adv-missing")).toBeNull();
  });
});

// ── structural law (no widening surface, no grant) ──────────────────────────

describe("27D structural law — ADVERTISEMENT != GRANT, no widening surface", () => {
  it("the registry prototype exposes ONLY the pinned method surface", () => {
    const methods = Object.getOwnPropertyNames(CapabilityAdvertisementRegistry.prototype).sort();
    expect(methods).toEqual([
      "advertisementCount",
      "constructor",
      "fingerprint",
      "get",
      "has",
      "record",
      "snapshot",
    ]);
    for (const name of methods) {
      expect(name).not.toMatch(/union|merge|grant|widen|execut|allow|authority|trust/i);
    }
    expect(typeof CapabilityAdvertisementRegistry.open).toBe("function");
  });

  it("instances carry NO own enumerable state fields (registry map is the only state)", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expect(Object.keys(reg)).toEqual([]);
  });

  it("every refusal code in the closed vocabulary carries an explanation", () => {
    const code = codeOnly(SRC("meshCapabilityAdvertisement.ts"));
    expect(CAPABILITY_ADVERTISEMENT_REFUSAL_CODES.length).toBe(20);
    for (const refusal of CAPABILITY_ADVERTISEMENT_REFUSAL_CODES) {
      expect(code).toContain(refusal + ":");
    }
  });

  it("record, replay, and rotation ALL carry grant 'none' and no widening", () => {
    const reg = CapabilityAdvertisementRegistry.open();
    expectNoGrant(reg.record(ADV()));
    expectNoGrant(reg.record(ADV()));
    expectNoGrant(
      reg.record(
        ADV({
          version: 2,
          provenance: { source: "governed_evidence", evidenceId: "ev-2", recordedAtEpochMs: NOW + 1_000 },
          observedAtEpochMs: NOW + 1_000,
        }),
      ),
    );
  });
});
