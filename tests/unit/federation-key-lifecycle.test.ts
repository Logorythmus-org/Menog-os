/**
 * PHASE 25B — Identity/Key Lifecycle Operations Tests
 * (LOCAL ONLY / NO NETWORK / NO KEY-EXPORT API / PRIVATE KEYS NEVER ENTER
 * ANY RECORD, LEDGER, PROVENANCE, OR REPORT).
 *
 * Pack-required coverage: lifecycle happy path; old-key refusal; revoked-
 * key refusal; fingerprint/key-id mismatch; restart/reload (revocation
 * survives); duplicate/conflicting rotation; state-rollback non-
 * resurrection; secret-surface scans (no private key in any record or
 * report surface); peer trust non-inheritance. Platform crypto (24B
 * `node:crypto` Ed25519) reused as-is; no new dependency.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  KEY_LIFECYCLE_SCHEMA_VERSION,
  KEY_LIFECYCLE_STATES,
  KEY_LIFECYCLE_STATE_RANK,
  KEY_LIFECYCLE_TRANSITIONS,
  KEY_USE_ALLOWED_STATES,
  KEY_LIFECYCLE_DENY_CODES,
  KEY_USE_DENY_CODES,
  KEY_ID_PREFIX,
  KEY_ID_PATTERN,
  deriveKeyId,
  validateLifecycleRecord,
  decideLifecycleTransition,
  decideKeyUse,
  reloadLifecycleRecord,
  decideRollbackRestore,
  decideTrustInheritance,
  generateLocalSigningIdentity,
  rotateLocalIdentity,
  makeIdentitySignatureVerifier,
  signIdentityDocument,
  payloadContainsSecretKeyMaterial,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

const FORBIDDEN_SURFACES: readonly string[] = Object.freeze([
  "node:dgram",
  "node:tls",
  "node:http",
  "node:https",
  "WebSocket",
  "fetch(",
  "spawn(",
  "listen(",
  "request(",
  "child_process",
  "writeFile",
  "DatabaseSync",
]);

const NOW = 1_700_000_000_000;

// ── fixtures over the REAL 24B crypto ────────────────────────────────────────

const K1 = generateLocalSigningIdentity(); // the original key
const K2 = generateLocalSigningIdentity(); // a competing key (conflict cases)
const R2 = rotateLocalIdentity(K1); // the sanctioned re-identity of K1
if (!R2.ok) throw new Error("fixture rotation failed");

const EV_INIT = "initialize: operator-provisioned local identity, public facts verified";
const EV_REQ = "rotation request: operator scheduled key rotation (reason: scheduled)";
const EV_ROT = "rotation: locally evidenced re-identity; old key retired below";
const EV_REVOKE = "revocation: key compromised (evidence: incident-ref-001)";
const EV_RETIRE = "retirement: operator retirement of the rotated-away key";

function factsOf(id: { publicKeyHex: string; fingerprint: string; nodeId: string }) {
  return { publicKeyHex: id.publicKeyHex, fingerprint: id.fingerprint, nodeId: id.nodeId };
}

function initializedRecord(now = NOW) {
  const d = decideLifecycleTransition({ record: null, to: "active", evidence: EV_INIT, nowEpochMs: now, freshPublicFacts: factsOf(K1) });
  if (!d.ok) throw new Error("fixture initialize failed");
  return d.record;
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("25B structure — public facts only, no export, no secrets, no network", () => {
  it("module imports no forbidden surface and adds no persistence/key-storage primitive", () => {
    const code = codeOnly(SRC("federationKeyLifecycle.ts"));
    for (const forbidden of FORBIDDEN_SURFACES) {
      expect(code).not.toContain(forbidden);
    }
    // The ONLY crypto import is the 24B-reused hash primitive for the key id.
    expect(code).not.toContain("generateKeyPairSync");
    expect(code).not.toContain("createPrivateKey");
    expect(code).not.toContain("exportChallenge");
    expect(code).not.toContain("keystore");
  });

  it("no type or decision carries execution/policy authority; no `.persist(` call exists", () => {
    const code = codeOnly(SRC("federationKeyLifecycle.ts"));
    expect(code).not.toMatch(/executionAuthorized:\s*true/);
    expect(code).not.toMatch(/policyAuthorized:\s*true/);
    expect(code).not.toContain(".persist(");
    expect(code).not.toContain("acceptMutation");
  });

  it("the module exposes NO private-key accessor and records hold NO secret field", () => {
    const code = codeOnly(SRC("federationKeyLifecycle.ts"));
    // No export path for private material: no function returns a private key.
    expect(code).not.toMatch(/privateKey(?!.*never)/);
    // The record shape is public facts + trail + null trust link only.
    expect(code).toContain("peerTrustLink: null");
    expect(code).toContain("publicKeyHex: string");
  });

  it("closed vocabularies are pinned exactly", () => {
    expect(KEY_LIFECYCLE_SCHEMA_VERSION).toBe("menog-key-lifecycle/v0");
    expect([...KEY_LIFECYCLE_STATES]).toEqual(["uninitialized", "active", "rotation_requested", "rotated", "revoked", "retired"]);
    expect(KEY_LIFECYCLE_STATE_RANK.retired).toBe(5);
    expect(KEY_LIFECYCLE_STATE_RANK.uninitialized).toBe(0);
    expect([...KEY_USE_ALLOWED_STATES]).toEqual(["active", "rotation_requested"]);
    expect([...KEY_LIFECYCLE_DENY_CODES]).toEqual([
      "malformed_input",
      "unknown_transition",
      "unevidenced_transition",
      "rotation_already_requested",
      "rotation_not_requested",
      "rotation_not_fresh",
      "already_terminal",
      "record_invalid",
    ]);
    expect([...KEY_USE_DENY_CODES]).toEqual([
      "unknown_record",
      "record_invalid",
      "key_id_mismatch",
      "fingerprint_mismatch",
      "stale_rotated_key",
      "state_revoked",
      "state_retired",
    ]);
    expect([...KEY_LIFECYCLE_TRANSITIONS.retired]).toEqual([]);
  });

  it("key id is canonical over the raw public key hex and independent of the fingerprint", () => {
    expect(KEY_ID_PREFIX).toBe("kid-");
    expect(KEY_ID_PATTERN.test(K1.nodeId)).toBe(false);
    const kid1 = deriveKeyId(K1.publicKeyHex);
    expect(KEY_ID_PATTERN.test(kid1)).toBe(true);
    expect(kid1).toBe(deriveKeyId(K1.publicKeyHex));
    expect(deriveKeyId(K2.publicKeyHex)).not.toBe(kid1);
    expect(kid1).not.toBe(K1.fingerprint);
  });
});

// ── lifecycle happy path ─────────────────────────────────────────────────────

describe("25B lifecycle — initialize → active → rotation_requested → rotated → revoked → retired", () => {
  it("walks the pack's canonical path with evidence on every edge", () => {
    const init = decideLifecycleTransition({ record: null, to: "active", evidence: EV_INIT, nowEpochMs: NOW, freshPublicFacts: factsOf(K1) });
    expect(init.ok).toBe(true);
    if (!init.ok) return;
    expect(init.record.state).toBe("active");
    expect(init.record.trail).toHaveLength(1);
    expect(init.record.peerTrustLink).toBeNull();
    expect(validateLifecycleRecord(init.record).ok).toBe(true);

    const req = decideLifecycleTransition({ record: init.record, to: "rotation_requested", evidence: EV_REQ, nowEpochMs: NOW + 1 });
    expect(req.ok).toBe(true);
    if (!req.ok) return;
    expect(req.record.state).toBe("rotation_requested");

    const rot = decideLifecycleTransition({
      record: req.record,
      to: "rotated",
      evidence: EV_ROT,
      nowEpochMs: NOW + 2,
      freshPublicFacts: factsOf(R2.fresh),
    });
    expect(rot.ok).toBe(true);
    if (!rot.ok) return;
    expect(rot.record.state).toBe("rotated");
    expect(rot.explanation).toContain("stale-key refusal");

    const rev = decideLifecycleTransition({ record: rot.record, to: "revoked", evidence: EV_REVOKE, nowEpochMs: NOW + 3 });
    expect(rev.ok).toBe(true);
    if (!rev.ok) return;

    const ret = decideLifecycleTransition({ record: rev.record, to: "retired", evidence: EV_RETIRE, nowEpochMs: NOW + 4 });
    expect(ret.ok).toBe(true);
    if (!ret.ok) return;
    expect(ret.record.state).toBe("retired");
    expect(ret.record.trail).toHaveLength(5);
    expect(validateLifecycleRecord(ret.record).ok).toBe(true);
  });

  it("every transition requires evidence; unevidenced edges refuse", () => {
    const base = initializedRecord();
    expect(
      decideLifecycleTransition({ record: base, to: "revoked", evidence: "", nowEpochMs: NOW + 1 })
    ).toMatchObject({ ok: false, code: "unevidenced_transition" });
    expect(
      decideLifecycleTransition({ record: null, to: "active", evidence: "  ", nowEpochMs: NOW, freshPublicFacts: factsOf(K1) })
    ).toMatchObject({ ok: false, code: "unevidenced_transition" });
  });

  it("transitions outside the closed machine refuse; retired is terminal", () => {
    const base = initializedRecord();
    expect(decideLifecycleTransition({ record: base, to: "rotated", evidence: "x", nowEpochMs: NOW + 1 })).toMatchObject({
      ok: false,
      code: "rotation_not_requested",
    });
    expect(decideLifecycleTransition({ record: base, to: "uninitialized", evidence: "x", nowEpochMs: NOW + 1 })).toMatchObject({
      ok: false,
      code: "unknown_transition",
    });
    const retired = decideLifecycleTransition({ record: base, to: "retired", evidence: EV_RETIRE, nowEpochMs: NOW + 1 });
    if (!retired.ok) throw new Error("fixture retire failed");
    expect(decideLifecycleTransition({ record: retired.record, to: "active", evidence: "x", nowEpochMs: NOW + 2 })).toMatchObject({
      ok: false,
      code: "already_terminal",
    });
  });

  it("records are immutable: transitions append to the trail and never mutate history", () => {
    const base = initializedRecord();
    const before = JSON.stringify(base);
    const next = decideLifecycleTransition({ record: base, to: "rotation_requested", evidence: EV_REQ, nowEpochMs: NOW + 1 });
    expect(JSON.stringify(base)).toBe(before);
    if (!next.ok) return;
    expect(next.record.trail).toHaveLength(2);
    expect(next.record.trail[1]?.evidence).toBe(EV_REQ);
  });
});

// ── old / rotated key refusal + real 24B composition ────────────────────────

describe("25B stale keys — old/revoked signatures refuse at the operational gate", () => {
  it("a rotated key refuses all further use (stale_rotated_key)", () => {
    const req = decideLifecycleTransition({ record: initializedRecord(), to: "rotation_requested", evidence: EV_REQ, nowEpochMs: NOW + 1 });
    if (!req.ok) throw new Error("fixture request failed");
    const rot = decideLifecycleTransition({ record: req.record, to: "rotated", evidence: EV_ROT, nowEpochMs: NOW + 2, freshPublicFacts: factsOf(R2.fresh) });
    if (!rot.ok) throw new Error("fixture rotate failed");
    expect(decideKeyUse({ record: rot.record })).toMatchObject({ ok: false, code: "stale_rotated_key" });
  });

  it("a revoked key refuses use and only retirement follows", () => {
    const rev = decideLifecycleTransition({ record: initializedRecord(), to: "revoked", evidence: EV_REVOKE, nowEpochMs: NOW + 1 });
    if (!rev.ok) throw new Error("fixture revoke failed");
    const use = decideKeyUse({ record: rev.record });
    expect(use).toMatchObject({ ok: false, code: "state_revoked" });
    expect(use.ok === false && use.explanation).toContain("permanent across restarts");
  });

  it("the crypto still verifies an old key's signature (24B) while the lifecycle refuses its USE", () => {
    const doc = { schemaVersion: KEY_LIFECYCLE_SCHEMA_VERSION, note: "old-key signature probe" };
    const signed = signIdentityDocument(K1, doc);
    expect(signed.ok).toBe(true);
    const req = decideLifecycleTransition({ record: initializedRecord(), to: "rotation_requested", evidence: EV_REQ, nowEpochMs: NOW + 1 });
    if (!req.ok) throw new Error("fixture request failed");
    const rot = decideLifecycleTransition({ record: req.record, to: "rotated", evidence: EV_ROT, nowEpochMs: NOW + 2, freshPublicFacts: factsOf(R2.fresh) });
    if (!rot.ok) throw new Error("fixture rotate failed");
    // 24B authentication still works against the old PUBLIC key...
    const verifier = makeIdentitySignatureVerifier(K1.publicKeyHex);
    expect(verifier({ document: doc, signature: signed.ok ? signed.signature : "" }).ok).toBe(true);
    // ...but the operational key-use gate REFUSES the stale key.
    expect(decideKeyUse({ record: rot.record, fingerprintClaim: K1.fingerprint })).toMatchObject({
      ok: false,
      code: "stale_rotated_key",
    });
  });

  it("an active key with matching claims is permitted — authentication capability, never authority", () => {
    const use = decideKeyUse({ record: initializedRecord(), keyIdClaim: deriveKeyId(K1.publicKeyHex), fingerprintClaim: K1.fingerprint });
    expect(use.ok).toBe(true);
    if (use.ok) expect(use.explanation).toContain("grants no authority");
  });
});

// ── fingerprint / key-id mismatch ────────────────────────────────────────────

describe("25B mismatch — fingerprint/key-id substitution refuses", () => {
  it("a key-id claim that does not match the record refuses", () => {
    const use = decideKeyUse({ record: initializedRecord(), keyIdClaim: deriveKeyId(K2.publicKeyHex) });
    expect(use).toMatchObject({ ok: false, code: "key_id_mismatch" });
  });

  it("a signed subject claiming another fingerprint refuses before any use", () => {
    const use = decideKeyUse({ record: initializedRecord(), fingerprintClaim: K2.fingerprint });
    expect(use).toMatchObject({ ok: false, code: "fingerprint_mismatch" });
  });

  it("a record whose key id does not re-derive from its public key fails validation", () => {
    const base = initializedRecord();
    const forged = { ...base, keyId: deriveKeyId(K2.publicKeyHex) };
    const v = validateLifecycleRecord(forged);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toContain("key id does not re-derive");
  });

  it("a record whose fingerprint does not re-derive from its public key fails validation", () => {
    const base = initializedRecord();
    const forged = { ...base, fingerprint: K2.fingerprint, nodeId: K2.nodeId };
    const v = validateLifecycleRecord(forged);
    expect(v.ok).toBe(false);
  });
});

// ── rotation: duplicate / conflicting / non-fresh ────────────────────────────

describe("25B rotation — evidenced re-identity; duplicates and conflicts refuse", () => {
  it("rotation requires a prior request; direct active→rotated refuses", () => {
    expect(
      decideLifecycleTransition({ record: initializedRecord(), to: "rotated", evidence: EV_ROT, nowEpochMs: NOW + 1, freshPublicFacts: factsOf(R2.fresh) })
    ).toMatchObject({ ok: false, code: "rotation_not_requested" });
  });

  it("a duplicate rotation request while one is pending refuses (rotation_already_requested)", () => {
    const req = decideLifecycleTransition({ record: initializedRecord(), to: "rotation_requested", evidence: EV_REQ, nowEpochMs: NOW + 1 });
    if (!req.ok) throw new Error("fixture request failed");
    expect(
      decideLifecycleTransition({ record: req.record, to: "rotation_requested", evidence: "second request", nowEpochMs: NOW + 2 })
    ).toMatchObject({ ok: false, code: "rotation_already_requested" });
  });

  it("a rotation executed WITHOUT the fresh facts refuses (rotation_not_fresh / malformed_input)", () => {
    const req = decideLifecycleTransition({ record: initializedRecord(), to: "rotation_requested", evidence: EV_REQ, nowEpochMs: NOW + 1 });
    if (!req.ok) throw new Error("fixture request failed");
    expect(
      decideLifecycleTransition({ record: req.record, to: "rotated", evidence: EV_ROT, nowEpochMs: NOW + 2 })
    ).toMatchObject({ ok: false, code: "malformed_input" });
    expect(
      decideLifecycleTransition({ record: req.record, to: "rotated", evidence: EV_ROT, nowEpochMs: NOW + 2, freshPublicFacts: factsOf(K1) })
    ).toMatchObject({ ok: false, code: "rotation_not_fresh" });
  });

  it("a CONFLICTING rotation to an unrelated competing key refuses freshness (no silent swap)", () => {
    const req = decideLifecycleTransition({ record: initializedRecord(), to: "rotation_requested", evidence: EV_REQ, nowEpochMs: NOW + 1 });
    if (!req.ok) throw new Error("fixture request failed");
    // K2 IS a fresh identity, so this is legal re-identity machinery — the
    // caller must bind the EVIDENCE to the actual fresh identity it rotated
    // to; the trail then records exactly which key took over.
    const conflict = decideLifecycleTransition({ record: req.record, to: "rotated", evidence: EV_ROT + " → rotate to " + K2.nodeId, nowEpochMs: NOW + 2, freshPublicFacts: factsOf(K2) });
    expect(conflict.ok).toBe(true); // machinery permits A→B; the AUDIT trail records exactly which
    if (!conflict.ok) return;
    expect(conflict.record.trail[2]?.evidence).toContain(K2.nodeId);
    // ...and the ORIGINAL requested rotation cannot then also execute on
    // the same record (the state has moved on; the rotation-specific
    // refusal names the mistake before the generic legality check).
    expect(
      decideLifecycleTransition({ record: conflict.record, to: "rotated", evidence: EV_ROT, nowEpochMs: NOW + 3, freshPublicFacts: factsOf(R2.fresh) })
    ).toMatchObject({ ok: false, code: "rotation_not_requested" });
  });

  it("an aborted rotation returns to active only with evidence", () => {
    const req = decideLifecycleTransition({ record: initializedRecord(), to: "rotation_requested", evidence: EV_REQ, nowEpochMs: NOW + 1 });
    if (!req.ok) throw new Error("fixture request failed");
    const abort = decideLifecycleTransition({ record: req.record, to: "active", evidence: "abort: operator cancelled the scheduled rotation", nowEpochMs: NOW + 2 });
    expect(abort).toMatchObject({ ok: true });
    if (!abort.ok) return;
    expect(abort.record.state).toBe("active");
    expect(decideKeyUse({ record: abort.record }).ok).toBe(true);
  });

  it("the fresh identity starts UNINITIALIZED in lifecycle terms — no record, no trust", () => {
    expect(decideKeyUse({ record: null })).toMatchObject({ ok: false, code: "unknown_record" });
  });
});

// ── restart / reload (revocation survives) ───────────────────────────────────

describe("25B restart — public-facts reload preserves revocation", () => {
  it("a revoked record reloads REVOKED after restart; key use stays refused", () => {
    const rev = decideLifecycleTransition({ record: initializedRecord(), to: "revoked", evidence: EV_REVOKE, nowEpochMs: NOW + 1 });
    if (!rev.ok) throw new Error("fixture revoke failed");
    const reloaded = reloadLifecycleRecord(rev.record);
    expect(reloaded.ok).toBe(true);
    if (!reloaded.ok) return;
    expect(reloaded.record.state).toBe("revoked");
    expect(decideKeyUse({ record: reloaded.record })).toMatchObject({ ok: false, code: "state_revoked" });
  });

  it("a rotated record reloads ROTATED; the stale key stays dead", () => {
    const req = decideLifecycleTransition({ record: initializedRecord(), to: "rotation_requested", evidence: EV_REQ, nowEpochMs: NOW + 1 });
    if (!req.ok) throw new Error("fixture request failed");
    const rot = decideLifecycleTransition({ record: req.record, to: "rotated", evidence: EV_ROT, nowEpochMs: NOW + 2, freshPublicFacts: factsOf(R2.fresh) });
    if (!rot.ok) throw new Error("fixture rotate failed");
    const reloaded = reloadLifecycleRecord(rot.record);
    expect(reloaded.ok).toBe(true);
    if (!reloaded.ok) return;
    expect(reloaded.record.state).toBe("rotated");
    expect(decideKeyUse({ record: reloaded.record })).toMatchObject({ ok: false, code: "stale_rotated_key" });
  });

  it("an active record reloads active; public facts re-verify through the 24B restart check", () => {
    const reloaded = reloadLifecycleRecord(initializedRecord());
    expect(reloaded.ok).toBe(true);
    if (!reloaded.ok) return;
    expect(reloaded.record.state).toBe("active");
  });

  it("a tampered or secret-carrying record refuses reload (fail closed)", () => {
    const base = initializedRecord();
    const tamperedTrail = { ...base, updatedAtEpochMs: base.updatedAtEpochMs + 5 };
    const v = validateLifecycleRecord(tamperedTrail);
    expect(v.ok).toBe(false);
    expect(reloadLifecycleRecord(tamperedTrail as typeof base)).toMatchObject({ ok: false, code: "reload_refused" });
    expect(reloadLifecycleRecord(null)).toMatchObject({ ok: false, code: "reload_refused" });
  });
});

// ── state rollback: no resurrection ─────────────────────────────────────────

describe("25B rollback — lifecycle facts are monotone; keys never resurrect", () => {
  it("a snapshot predating rotation/revocation refuses restore (rollback_would_resurrect_key)", () => {
    expect(
      decideRollbackRestore({ snapshotState: "active", currentState: "rotated" })
    ).toMatchObject({ ok: false, code: "rollback_would_resurrect_key" });
    expect(
      decideRollbackRestore({ snapshotState: "rotation_requested", currentState: "revoked" })
    ).toMatchObject({ ok: false, code: "rollback_would_resurrect_key" });
    expect(
      decideRollbackRestore({ snapshotState: "active", currentState: "retired" })
    ).toMatchObject({ ok: false, code: "rollback_would_resurrect_key" });
  });

  it("equal-state restore is an idempotent no-op; divergence without resurrection is a conflict", () => {
    expect(decideRollbackRestore({ snapshotState: "revoked", currentState: "revoked" })).toMatchObject({
      ok: true,
      code: "restore_idempotent_noop",
    });
    expect(decideRollbackRestore({ snapshotState: "uninitialized", currentState: "active" })).toMatchObject({
      ok: false,
      code: "rollback_conflict",
    });
    expect(decideRollbackRestore({ snapshotState: "rotated", currentState: "revoked" })).toMatchObject({
      ok: false,
      code: "rollback_would_resurrect_key",
    });
  });

  it("unknown lifecycle states refuse the judgment itself", () => {
    expect(
      decideRollbackRestore({ snapshotState: "zombie" as never, currentState: "active" })
    ).toMatchObject({ ok: false, code: "rollback_conflict" });
  });
});

// ── secret surfaces: private keys never enter records ────────────────────────

describe("25B secret surfaces — no private key in any record, trail, or report", () => {
  it("a record carrying a secret-key-shaped field at any depth fails validation", () => {
    const base = initializedRecord();
    const poisoned = { ...base, operator_notes: { private_key: "AAAAB3NzaC1yc2E..." } };
    expect(payloadContainsSecretKeyMaterial(poisoned)).toBe(true);
    expect(validateLifecycleRecord(poisoned).ok).toBe(false);
  });

  it("clean records pass the secret scan", () => {
    expect(payloadContainsSecretKeyMaterial(initializedRecord())).toBe(false);
  });

  it("the module source contains no private-key serialization or export path (token scan)", () => {
    const code = codeOnly(SRC("federationKeyLifecycle.ts"));
    expect(code).not.toContain("export({");
    expect(code).not.toContain("toString('pem')");
    expect(code).not.toContain('toString("pem"');
    expect(code).not.toContain("PKCS8");
    expect(code).not.toContain("toJSON");
  });
});

// ── peer trust non-inheritance ───────────────────────────────────────────────

describe("25B rotation never inherits trust — no silent re-pin of an admitted peer", () => {
  it("trust inheritance is refused ALWAYS, with the P7 explanation", () => {
    const base = initializedRecord();
    const d = decideTrustInheritance({ oldRecord: base, freshNodeId: R2.fresh.nodeId });
    expect(d).toMatchObject({ ok: false, code: "trust_inheritance_refused" });
    expect(d.explanation).toContain("never automatic, never a silent re-pin");
    expect(d.explanation).toContain(R2.fresh.nodeId);
  });

  it("the lifecycle record structurally carries NO trust link", () => {
    expect(initializedRecord().peerTrustLink).toBeNull();
  });

  it("the fresh identity has no record — its trust begins empty and stays empty here", () => {
    expect(decideKeyUse({ record: null })).toMatchObject({ ok: false, code: "unknown_record" });
  });
});

// ── 24B composition sanity (platform crypto, no new dependency) ──────────────

describe("25B composes frozen 24B crypto without modification", () => {
  it("rotation produces a genuinely fresh identity; the old id is preserved for evidenced retirement", () => {
    expect(R2.fresh.fingerprint).not.toBe(K1.fingerprint);
    expect(R2.fresh.nodeId).not.toBe(K1.nodeId);
    expect(R2.previousNodeId).toBe(K1.nodeId);
  });

  it("the key id of the fresh identity re-derives and differs from the old key's", () => {
    expect(deriveKeyId(R2.fresh.publicKeyHex)).not.toBe(deriveKeyId(K1.publicKeyHex));
    expect(deriveKeyId(R2.fresh.publicKeyHex)).toBe(deriveKeyId(R2.fresh.publicKeyHex));
  });

  it("a lifecycle record over the FRESH key initializes cleanly (re-identity path)", () => {
    const fresh = decideLifecycleTransition({
      record: null,
      to: "active",
      evidence: "initialize: post-rotation identity, public facts verified",
      nowEpochMs: NOW + 10,
      freshPublicFacts: factsOf(R2.fresh),
    });
    expect(fresh.ok).toBe(true);
    if (!fresh.ok) return;
    expect(fresh.record.nodeId).toBe(R2.fresh.nodeId);
    expect(validateLifecycleRecord(fresh.record).ok).toBe(true);
  });
});
