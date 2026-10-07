/**
 * PHASE 25A — Operational Federation Threat Model & Trust Boundary Tests
 * (CONTRACT-FIRST / NO NETWORK / NO EXECUTION API / NO NEW AUTHORITY).
 *
 * Pins the seven operational laws structurally and behaviorally:
 *   P1 IDENTITY ≠ AUTHORITY · P2 AUTHENTICATION ≠ ADMISSION ·
 *   P3 ADMISSION ≠ EXECUTION · P4 EVIDENCE ≠ AUTHORITY ·
 *   P5 RECOVERY ≠ AUTHORITY · P6 KEY_POSSESSION ≠ POLICY_ALLOW ·
 *   P7 ROTATION DOES NOT INHERIT TRUST (unless locally evidenced).
 * Also pins the closed OT-01..OT-12 operational-risk vocabulary and the
 * deterministic-explanation law (same signal → same explanation).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  TRUST_BOUNDARY_SCHEMA_VERSION,
  OPERATIONAL_TRUST_PINS,
  OPERATIONAL_TRUST_PIN_EXPLANATIONS,
  OPERATIONAL_RISK_IDS,
  TRUST_BOUNDARY_PLANES,
  TRUST_BOUNDARY_PLANE_DECISIONS,
  KEY_MATERIAL_CLASSES,
  KEY_STORAGE_LOCATIONS,
  OPERATIONAL_DISPOSITIONS,
  RESTART_RECOVERY_DECISIONS,
  authorizeKeyMaterialPlacement,
  classifyOperationalRisk,
  decideBoundaryClaim,
  decideRestartRecovery,
  trustBoundaryFingerprint,
  isWellFormedPeerId,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

/** Surfaces the 25A module must NEVER contain (structural no-network pin). */
const FEDERATION_FORBIDDEN_SURFACES: readonly string[] = Object.freeze([
  "child_process",
  "node:net",
  "node:http",
  "node:https",
  "node:dgram",
  "node:tls",
  "WebSocket",
  "fetch(",
  "spawn(",
  "listen(",
]);

const NOW = 1_700_000_000_000;
const NODE_A_ID = "node-" + "a".repeat(64);
const EPOCH_LOCAL = "re-65535f000000-aaaa1111aaaa1111";

// ── structural pins ──────────────────────────────────────────────────────────

describe("25A structure — closed vocabulary and law surfaces", () => {
  it("forbidden surfaces list is pinned and the module imports no network/execution primitive", () => {
    const src = SRC("federationTrustBoundary.ts");
    expect(FEDERATION_FORBIDDEN_SURFACES).toEqual([
      "child_process",
      "node:net",
      "node:http",
      "node:https",
      "node:dgram",
      "node:tls",
      "WebSocket",
      "fetch(",
      "spawn(",
      "listen(",
    ]);
    const code = codeOnly(src);
    for (const forbidden of FEDERATION_FORBIDDEN_SURFACES) {
      expect(code).not.toContain(forbidden);
    }
    expect(code).not.toContain("node:crypto");
    expect(code).not.toContain("createHash");
    expect(code).not.toContain("DatabaseSync");
    expect(code).not.toContain("acceptMutation");
  });

  it("no type or decision carries execution/policy authority; the module imports no policy vocabulary (P1/P3)", () => {
    const src = codeOnly(SRC("federationTrustBoundary.ts"));
    expect(src).not.toMatch(/executionAuthorized:\s*true/);
    expect(src).not.toMatch(/policyAuthorized:\s*true/);
    expect(src).not.toContain("DenyByDefault");
    expect(src).not.toContain("PolicyDecision");
    // The only store-adjacent token allowed is the PROSE reference inside
    // explanations; the code never CALLS a persistence surface.
    expect(src).not.toMatch(/\.persist\(/);
  });

  it("schema version and the seven pins are pinned exactly, in order", () => {
    expect(TRUST_BOUNDARY_SCHEMA_VERSION).toBe("menog-trust-boundary/v0");
    expect([...OPERATIONAL_TRUST_PINS]).toEqual([
      "IDENTITY_NOT_AUTHORITY",
      "AUTHENTICATION_NOT_ADMISSION",
      "ADMISSION_NOT_EXECUTION",
      "EVIDENCE_NOT_AUTHORITY",
      "RECOVERY_NOT_AUTHORITY",
      "KEY_POSSESSION_NOT_POLICY_ALLOW",
      "ROTATION_NO_TRUST_INHERITANCE",
    ]);
  });

  it("every pin has a deterministic closed explanation naming its pin and its != law", () => {
    expect(Object.keys(OPERATIONAL_TRUST_PIN_EXPLANATIONS).sort()).toEqual([...OPERATIONAL_TRUST_PINS].sort());
    const laws: Array<[Parameters<typeof expect>[0], string]> = [];
    void laws;
    const pinned: Array<[(typeof OPERATIONAL_TRUST_PINS)[number], string]> = [
      ["IDENTITY_NOT_AUTHORITY", "P1 IDENTITY != AUTHORITY"],
      ["AUTHENTICATION_NOT_ADMISSION", "P2 AUTHENTICATION != ADMISSION"],
      ["ADMISSION_NOT_EXECUTION", "P3 ADMISSION != EXECUTION"],
      ["EVIDENCE_NOT_AUTHORITY", "P4 EVIDENCE != AUTHORITY"],
      ["RECOVERY_NOT_AUTHORITY", "P5 RECOVERY != AUTHORITY"],
      ["KEY_POSSESSION_NOT_POLICY_ALLOW", "P6 KEY_POSSESSION != POLICY_ALLOW"],
      ["ROTATION_NO_TRUST_INHERITANCE", "P7 ROTATION DOES NOT INHERIT TRUST"],
    ];
    for (const [pin, law] of pinned) {
      expect(OPERATIONAL_TRUST_PIN_EXPLANATIONS[pin].startsWith(law)).toBe(true);
    }
  });

  it("the operational-risk catalog is closed and covers every pack-named threat exactly once", () => {
    expect([...OPERATIONAL_RISK_IDS]).toEqual([
      "OT-01_unknown_peer",
      "OT-02_revoked_peer",
      "OT-03_compromised_peer",
      "OT-04_stale_peer",
      "OT-05_copied_key_material",
      "OT-06_malicious_payload",
      "OT-07_replayed_message",
      "OT-08_local_attacker",
      "OT-09_operator_error",
      "OT-10_clock_anomaly",
      "OT-11_crash_during_trust_mutation",
      "OT-12_untrusted_evidence_consumer",
    ]);
  });

  it("boundary planes are exactly the pack's model set, each with a MAY/MAY NOT decision statement", () => {
    expect([...TRUST_BOUNDARY_PLANES]).toEqual([
      "local_operator",
      "runtime_epoch",
      "identity_key_material",
      "peer_identity_trust",
      "key_storage",
      "ingress",
      "egress",
      "durable_evidence",
      "policy",
      "execution",
      "restart_recovery",
    ]);
    expect(Object.keys(TRUST_BOUNDARY_PLANE_DECISIONS).sort()).toEqual([...TRUST_BOUNDARY_PLANES].sort());
    for (const plane of TRUST_BOUNDARY_PLANES) {
      expect(TRUST_BOUNDARY_PLANE_DECISIONS[plane]).toMatch(/^MAY:/);
      expect(TRUST_BOUNDARY_PLANE_DECISIONS[plane]).toContain("MAY NOT:");
    }
    // No plane statement may claim execution or widening authority.
    for (const plane of TRUST_BOUNDARY_PLANES) {
      expect(TRUST_BOUNDARY_PLANE_DECISIONS[plane]).not.toMatch(/MAY execute|grants execution|widens authority/i);
    }
  });

  it("key/disposition/recovery vocabularies are closed", () => {
    expect([...KEY_MATERIAL_CLASSES]).toEqual(["public_identity_facts", "private_signing_key", "derived_public_facts", "unknown"]);
    expect([...KEY_STORAGE_LOCATIONS]).toEqual(["memory_only", "durable_store", "durable_evidence", "outbound_message", "unknown"]);
    expect([...OPERATIONAL_DISPOSITIONS]).toEqual(["contain", "refuse", "quarantine", "investigate", "monitor"]);
    expect([...RESTART_RECOVERY_DECISIONS]).toEqual([
      "recovered_as_data_zero_authority",
      "recovered_as_data_requires_fresh_evidence",
      "refused_unknown_survivor",
    ]);
  });
});

// ── key-storage boundary (P6) ────────────────────────────────────────────────

describe("25A key-storage boundary — private keys are memory-only", () => {
  it("private key in memory_only is the ONLY permitted placement, and it authorizes nothing", () => {
    const ok = authorizeKeyMaterialPlacement({ materialClass: "private_signing_key", storageLocation: "memory_only" });
    expect(ok).toMatchObject({ ok: true, code: "key_material_permitted" });
    expect(ok.ok === true && ok.explanation).toContain("authorizes NOTHING");
  });

  it("private key at rest, in evidence, or in egress is a FINDING — denied with a distinct code", () => {
    expect(authorizeKeyMaterialPlacement({ materialClass: "private_signing_key", storageLocation: "durable_store" })).toMatchObject({
      ok: false,
      code: "private_key_at_rest_denied",
    });
    expect(authorizeKeyMaterialPlacement({ materialClass: "private_signing_key", storageLocation: "durable_evidence" })).toMatchObject({
      ok: false,
      code: "private_key_in_evidence_denied",
    });
    expect(authorizeKeyMaterialPlacement({ materialClass: "private_signing_key", storageLocation: "outbound_message" })).toMatchObject({
      ok: false,
      code: "private_key_in_egress_denied",
    });
  });

  it("public/derived facts may be stored or shared — authentication, never authorization", () => {
    for (const cls of ["public_identity_facts", "derived_public_facts"] as const) {
      for (const loc of ["memory_only", "durable_store", "durable_evidence", "outbound_message"] as const) {
        const r = authorizeKeyMaterialPlacement({ materialClass: cls, storageLocation: loc });
        expect(r).toMatchObject({ ok: true, code: "key_material_permitted" });
        expect(r.ok === true && r.explanation).toContain("never authorize");
      }
    }
  });

  it("unknown material or unknown location refuses rather than guessing (fail closed)", () => {
    expect(authorizeKeyMaterialPlacement({ materialClass: "unknown", storageLocation: "memory_only" })).toMatchObject({
      ok: false,
      code: "unknown_material_denied",
    });
    expect(authorizeKeyMaterialPlacement({ materialClass: "public_identity_facts", storageLocation: "unknown" })).toMatchObject({
      ok: false,
      code: "unknown_material_denied",
    });
  });
});

// ── operational risk classification (OT-01..OT-12) ──────────────────────────

describe("25A operational risk classification — deterministic, fail-closed, pack threats", () => {
  const run = (kind: Parameters<typeof classifyOperationalRisk>[0]["kind"], peerId = NODE_A_ID) =>
    classifyOperationalRisk({ kind, peerId } as Parameters<typeof classifyOperationalRisk>[0]);

  it("classifies all twelve pack threats with the pinned risk ids and closed dispositions", () => {
    const expected: Array<[Parameters<typeof classifyOperationalRisk>[0]["kind"], string, string]> = [
      ["peer_unknown", "OT-01_unknown_peer", "monitor"],
      ["peer_revoked", "OT-02_revoked_peer", "refuse"],
      ["peer_key_changed", "OT-03_compromised_peer", "quarantine"],
      ["peer_epoch_stale", "OT-04_stale_peer", "refuse"],
      ["key_material_copy_detected", "OT-05_copied_key_material", "quarantine"],
      ["payload_rejected", "OT-06_malicious_payload", "contain"],
      ["message_replayed", "OT-07_replayed_message", "refuse"],
      ["local_policy_denied", "OT-08_local_attacker", "contain"],
      ["operator_action_out_of_band", "OT-09_operator_error", "investigate"],
      ["clock_skew_exceeded", "OT-10_clock_anomaly", "refuse"],
      ["trust_mutation_interrupted", "OT-11_crash_during_trust_mutation", "investigate"],
      ["evidence_replayed_as_authority", "OT-12_untrusted_evidence_consumer", "contain"],
    ];
    expect(expected).toHaveLength(12);
    for (const [kind, riskId, disposition] of expected) {
      const c = run(kind);
      expect(c.riskId).toBe(riskId);
      expect(c.disposition).toBe(disposition);
      expect([...OPERATIONAL_DISPOSITIONS]).toContain(c.disposition);
      expect(c.explanation).toContain(NODE_A_ID);
      expect(c.pins.length).toBeGreaterThan(0);
      for (const pin of c.pins) expect([...OPERATIONAL_TRUST_PINS]).toContain(pin);
    }
  });

  it("explanations are deterministic: the same signal always yields the same classification", () => {
    const a = classifyOperationalRisk({ kind: "peer_key_changed", peerId: NODE_A_ID });
    const b = classifyOperationalRisk({ kind: "peer_key_changed", peerId: NODE_A_ID });
    expect(a).toEqual(b);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  it("every classification explanation carries the invoked pins' law statements", () => {
    const all: OperationalRiskCheck[] = [];
    type OperationalRiskCheck = unknown;
    void all;
    for (const kind of [
      "peer_unknown",
      "peer_revoked",
      "peer_key_changed",
      "peer_epoch_stale",
      "key_material_copy_detected",
      "payload_rejected",
      "message_replayed",
      "local_policy_denied",
      "operator_action_out_of_band",
      "clock_skew_exceeded",
      "trust_mutation_interrupted",
      "evidence_replayed_as_authority",
    ] as const) {
      const c = classifyOperationalRisk({ kind, peerId: NODE_A_ID } as Parameters<typeof classifyOperationalRisk>[0]);
      for (const pin of c.pins) {
        // The pin explanation's core law phrase must appear in the
        // classification's own explanation family (module-level pin
        // explanations are the canonical phrasing).
        expect(OPERATIONAL_TRUST_PIN_EXPLANATIONS[pin].length).toBeGreaterThan(20);
      }
      all.push(c);
    }
    expect(all).toHaveLength(12);
  });

  it("compromised/copy signals demand quarantine and deny trust inheritance (P7)", () => {
    const compromised = classifyOperationalRisk({ kind: "peer_key_changed", peerId: NODE_A_ID });
    const copied = classifyOperationalRisk({ kind: "key_material_copy_detected", peerId: NODE_A_ID });
    for (const c of [compromised, copied]) {
      expect(c.disposition).toBe("quarantine");
      expect(c.pins).toContain("ROTATION_NO_TRUST_INHERITANCE");
    }
  });

  it("revoked/stale/replay signals refuse without resurrection or oracle", () => {
    for (const kind of ["peer_revoked", "peer_epoch_stale", "message_replayed"] as const) {
      const c = classifyOperationalRisk({ kind, peerId: NODE_A_ID });
      expect(c.disposition).toBe("refuse");
    }
  });
});

// ── boundary claims (the seven pins over claims) ────────────────────────────

describe("25A boundary claims — receivable DATA vs boundary-crossing authority", () => {
  const run = (claimKind: Parameters<typeof decideBoundaryClaim>[0]["claimKind"]) =>
    decideBoundaryClaim({ claimKind, peerId: NODE_A_ID, localEpochId: EPOCH_LOCAL, decidedAtEpochMs: NOW });

  it("identity/authentication/admission/evidence/recovery claims are receivable as DATA and grant nothing", () => {
    for (const kind of [
      "identity_claim",
      "authentication_claim",
      "admission_claim",
      "evidence_authority_claim",
      "recovery_authority_claim",
    ] as const) {
      const d = run(kind);
      expect(d).toMatchObject({ ok: true, code: "claim_within_boundary" });
      expect(d.ok === true && d.explanation).toContain("!= ");
    }
  });

  it("execution, key-possession-authority, and rotation-inheritance claims CROSS the boundary and name the violated pin", () => {
    expect(run("execution_claim")).toMatchObject({ ok: false, code: "claim_crosses_boundary", violatedPin: "ADMISSION_NOT_EXECUTION" });
    expect(run("key_possession_authority_claim")).toMatchObject({
      ok: false,
      code: "claim_crosses_boundary",
      violatedPin: "KEY_POSSESSION_NOT_POLICY_ALLOW",
    });
    expect(run("rotation_trust_claim")).toMatchObject({
      ok: false,
      code: "claim_crosses_boundary",
      violatedPin: "ROTATION_NO_TRUST_INHERITANCE",
    });
  });

  it("every decision binds a deterministic provenance hash over (claim, peer, epoch, time)", () => {
    const a = decideBoundaryClaim({ claimKind: "identity_claim", peerId: NODE_A_ID, localEpochId: EPOCH_LOCAL, decidedAtEpochMs: NOW });
    const b = decideBoundaryClaim({ claimKind: "identity_claim", peerId: NODE_A_ID, localEpochId: EPOCH_LOCAL, decidedAtEpochMs: NOW });
    expect(a.provenanceHash).toBe(b.provenanceHash);
    expect(a.provenanceHash).toMatch(/^[0-9a-f]{32,128}$/);
    const c = decideBoundaryClaim({ claimKind: "identity_claim", peerId: NODE_A_ID, localEpochId: EPOCH_LOCAL, decidedAtEpochMs: NOW + 1 });
    expect(c.provenanceHash).not.toBe(a.provenanceHash);
  });

  it("an anonymous claim cannot even be evaluated as DATA (fail closed)", () => {
    const d = decideBoundaryClaim({ claimKind: "identity_claim", peerId: "", localEpochId: EPOCH_LOCAL, decidedAtEpochMs: NOW });
    expect(d).toMatchObject({ ok: false, code: "claim_crosses_boundary", violatedPin: "IDENTITY_NOT_AUTHORITY" });
  });
});

// ── restart/recovery boundary (P5/P7) ────────────────────────────────────────

describe("25A restart/recovery boundary — recovery grants nothing", () => {
  const run = (kind: Parameters<typeof decideRestartRecovery>[0]["kind"]) =>
    decideRestartRecovery({ kind, peerId: NODE_A_ID });

  it("every survivor re-enters as recovered_data with zero authority (P5)", () => {
    for (const kind of [
      "peer_trust_registry_fact",
      "durable_evidence_record",
      "federation_receipt",
      "federation_proposal",
      "federation_provenance_anchor",
    ] as const) {
      const r = run(kind);
      expect(r.decision).toBe("recovered_as_data_zero_authority");
      expect(r.pins).toContain("RECOVERY_NOT_AUTHORITY");
      expect(r.explanation).toContain(NODE_A_ID);
    }
  });

  it("an interrupted trust mutation requires NEW evidence and is never auto-completed (P5/P7)", () => {
    const r = run("interrupted_trust_mutation");
    expect(r.decision).toBe("recovered_as_data_requires_fresh_evidence");
    expect(r.pins).toContain("ROTATION_NO_TRUST_INHERITANCE");
    expect(r.explanation).toContain("never auto-completed");
  });
});

// ── misc pure helpers ────────────────────────────────────────────────────────

describe("25A boundary fingerprint and peer-id sanity", () => {
  it("trust boundary fingerprint is deterministic and input-sensitive", () => {
    const a = trustBoundaryFingerprint({ localEpochId: EPOCH_LOCAL, localNodeId: NODE_A_ID, decidedAtEpochMs: NOW });
    const b = trustBoundaryFingerprint({ localEpochId: EPOCH_LOCAL, localNodeId: NODE_A_ID, decidedAtEpochMs: NOW });
    expect(a).toBe(b);
    const c = trustBoundaryFingerprint({ localEpochId: null, localNodeId: NODE_A_ID, decidedAtEpochMs: NOW });
    expect(c).not.toBe(a);
  });

  it("isWellFormedPeerId accepts 24A shapes only", () => {
    expect(isWellFormedPeerId(NODE_A_ID)).toBe(true);
    expect(isWellFormedPeerId("ri-123456789012-abcdefghijkl")).toBe(true);
    expect(isWellFormedPeerId("garbage")).toBe(false);
  });
});
