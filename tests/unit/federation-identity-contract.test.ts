/**
 * PHASE 24A — Federation Trust Model & Node Identity Contract Tests
 * (CONTRACT-FIRST / NO NETWORK / NO EXECUTION API).
 *
 * Pins every 24A law structurally and behaviorally:
 *   L1  identity ≠ authority (no execution/policy fields; key substitution fails)
 *   L2  authentication ≠ authorization (valid signature still authority:"none")
 *   L3  peer admission ≠ execution permission (decision carries no execution field)
 *   L4  federation ≠ capability union (unknown fields refused; closed unions)
 *   L5  stale epochs fail (older epoch refused; rivals refused; 23A vocabulary reused)
 *   L6  quarantined/retired peers never resurrect (closed trust machine)
 *   L7  remote claims never broaden local Policy (no policy vocabulary imported)
 *   L8  replay/protocol/schema mismatch fail closed (message ids once-ever)
 *   L9  admitted facts are provenance-bound (deterministic canonical hash)
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  FEDERATION_PROTOCOL_VERSION,
  FEDERATION_IDENTITY_SCHEMA_VERSION,
  FEDERATION_MESSAGE_SCHEMA_VERSION,
  FEDERATION_CLOCK_SKEW_TOLERANCE_MS,
  FEDERATION_MAX_CLOCK_SKEW_TOLERANCE_MS,
  FEDERATION_MAX_LINEAGE_DEPTH,
  NODE_TRUST_STATES,
  PEER_TRUST_TRANSITIONS,
  NODE_ID_PATTERN,
  NODE_FINGERPRINT_PATTERN,
  RUNTIME_INSTANCE_ID_PATTERN,
  FEDERATION_MESSAGE_ID_PATTERN,
  PEER_ADMISSION_OUTCOMES,
  PEER_ADMISSION_DENY_CODES,
  FEDERATION_DECLARED_INTENTS,
  FEDERATION_MESSAGE_DENY_CODES,
  deriveNodeId,
  nodeIdMatchesFingerprint,
  makeRuntimeInstanceId,
  makeFederationMessageId,
  newInstanceEpochTracker,
  observeInstanceEpoch,
  isPeerTrustTransition,
  decideTrustTransition,
  validateNodeIdentityDocument,
  newMessageReplayTracker,
  validateSignedMessageContract,
  decidePeerAdmission,
  type NodeIdentityDocumentBody,
  type FederationMessageBody,
  type InstanceEpochTracker,
  type MessageReplayTracker,
} from "@menog/durable-state";
import { makeRuntimeEpochId, RUNTIME_EPOCH_ID_PATTERN } from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

// ── deterministic fixtures ───────────────────────────────────────────────────

const NOW = 1_700_000_000_000;
const SKEW = FEDERATION_CLOCK_SKEW_TOLERANCE_MS;
/**
 * Surfaces the 24A contract must NEVER contain (structural no-network /
 * no-execution pin, enforced below against the module source). This list
 * lives in the SUITE — deliberately not as module-source data — so the
 * repository-wide network-invariant scanner never sees the raw tokens in
 * package source, and so the pin itself cannot drift silently.
 */
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
const FP_A = "fp-sha256-" + "a".repeat(64);
const FP_B = "fp-sha256-" + "b".repeat(64);
const NODE_A = deriveNodeId(FP_A);
const NODE_B = deriveNodeId(FP_B);
if (!NODE_A.ok || !NODE_B.ok) throw new Error("fixture derivation failed");
const NODE_A_ID: string = NODE_A.nodeId;
const NODE_B_ID: string = NODE_B.nodeId;
const INSTANCE_A = makeRuntimeInstanceId(NOW, "instance-a");
const INSTANCE_B = makeRuntimeInstanceId(NOW, "instance-b");
void NODE_B_ID;
void INSTANCE_B;
const EPOCH_A1 = makeRuntimeEpochId(NOW, "aaaa1111aaaa1111");
const EPOCH_A2 = makeRuntimeEpochId(NOW + 1_000, "aaaa2222aaaa2222");
const EPOCH_B1 = makeRuntimeEpochId(NOW, "bbbb1111bbbb1111");

/** The always-true verifier: proves L2 (a VALID signature still grants none). */
const OK_VERIFIER = (): { ok: true } => ({ ok: true });

function identityBody(overrides: Partial<NodeIdentityDocumentBody> = {}): NodeIdentityDocumentBody {
  return {
    schemaVersion: FEDERATION_IDENTITY_SCHEMA_VERSION,
    nodeId: NODE_A_ID,
    fingerprint: FP_A,
    instanceId: INSTANCE_A,
    epochId: EPOCH_A1,
    protocolVersion: FEDERATION_PROTOCOL_VERSION,
    issuedAtEpochMs: NOW,
    ...overrides,
  };
}

function messageBody(overrides: Partial<FederationMessageBody> = {}): FederationMessageBody {
  return {
    schemaVersion: FEDERATION_MESSAGE_SCHEMA_VERSION,
    messageId: makeFederationMessageId(NOW, "msg0000000000001"),
    senderNodeId: NODE_A_ID,
    senderFingerprint: FP_A,
    senderInstanceId: INSTANCE_A,
    senderEpochId: EPOCH_A1,
    protocolVersion: FEDERATION_PROTOCOL_VERSION,
    payloadHash: "sha256-" + "5".repeat(64),
    declaredIntent: "evidence",
    correlationId: null,
    causationId: null,
    lineage: [],
    issuedAtEpochMs: NOW,
    ...overrides,
  };
}

function freshTrackers(): { epochTracker: InstanceEpochTracker; replayTracker: MessageReplayTracker } {
  return { epochTracker: newInstanceEpochTracker(), replayTracker: newMessageReplayTracker() };
}

// ── L1 + L9 structural pins ──────────────────────────────────────────────────

describe("24A structure — closed vocabulary and law surfaces", () => {
  it("forbidden surfaces list is pinned and the module imports no network/execution primitive", () => {
    const src = SRC("federationIdentity.ts");
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
    // The list lives in this suite, NOT as module-source data — so any
    // occurrence of a forbidden token in package source is a real hit.
    const code = codeOnly(src);
    for (const forbidden of FEDERATION_FORBIDDEN_SURFACES) {
      expect(code).not.toContain(forbidden);
    }
    expect(code).not.toContain("node:crypto");
    expect(code).not.toContain("createHash");
  });

  it("no type or decision in the module carries execution or policy authority (L1/L3/L7)", () => {
    const src = codeOnly(SRC("federationIdentity.ts"));
    expect(src).not.toMatch(/executionAuthorized:\s*true/);
    expect(src).not.toMatch(/policyAuthorized:\s*true/);
    expect(src).not.toContain("DenyByDefault");
    expect(src).not.toContain("PolicyDecision");
    expect(src).toContain('authority: "none"');
  });

  it("protocol and schema versions are pinned exactly", () => {
    expect(FEDERATION_PROTOCOL_VERSION).toBe("menog-federation/v1");
    expect(FEDERATION_IDENTITY_SCHEMA_VERSION).toBe("menog-federation-identity/v0");
    expect(FEDERATION_MESSAGE_SCHEMA_VERSION).toBe("menog-federation-message/v0");
    expect(FEDERATION_MAX_CLOCK_SKEW_TOLERANCE_MS).toBe(600_000);
    expect(FEDERATION_MAX_LINEAGE_DEPTH).toBe(16);
  });

  it("identity id shapes are pinned and factories are deterministic and injective", () => {
    expect(NODE_ID_PATTERN.test(NODE_A.nodeId)).toBe(true);
    expect(NODE_FINGERPRINT_PATTERN.test(FP_A)).toBe(true);
    expect(RUNTIME_INSTANCE_ID_PATTERN.test(INSTANCE_A)).toBe(true);
    expect(FEDERATION_MESSAGE_ID_PATTERN.test(makeFederationMessageId(NOW, "x"))).toBe(true);
    expect(makeRuntimeInstanceId(NOW, "r1")).toBe(makeRuntimeInstanceId(NOW, "r1"));
    expect(makeRuntimeInstanceId(NOW, "r1")).not.toBe(makeRuntimeInstanceId(NOW + 1, "r1"));
    expect(makeRuntimeInstanceId(NOW, "r1")).not.toBe(makeRuntimeInstanceId(NOW, "r2"));
  });

  it("declared intents are a closed, inert union", () => {
    expect([...FEDERATION_DECLARED_INTENTS]).toEqual(["task_proposal", "evidence", "response"]);
  });
});

// ── identity derivation (L1 key substitution) ────────────────────────────────

describe("24A NodeId derivation — identity is the fingerprint", () => {
  it("derives injectively and refuses malformed fingerprints", () => {
    expect(NODE_A.nodeId).toBe("node-" + "a".repeat(64));
    expect(deriveNodeId("fp-zz")).toEqual({
      ok: false,
      reason: "fingerprint missing or malformed — no NodeId is derived (fail closed)",
    });
    expect(deriveNodeId("not-a-fp").ok).toBe(false);
  });

  it("key substitution fails closed: same key keeps the NodeId claim true, a different key breaks it", () => {
    expect(nodeIdMatchesFingerprint(NODE_A.nodeId, FP_A)).toBe(true);
    expect(nodeIdMatchesFingerprint(NODE_A.nodeId, FP_B)).toBe(false);
  });
});

// ── instance/epoch relation (L5 + split-brain) ───────────────────────────────

describe("24A instance/epoch observation — stale epochs fail, split-brain refuses", () => {
  it("reuses the frozen 23A epoch id vocabulary", () => {
    expect(RUNTIME_EPOCH_ID_PATTERN.test(EPOCH_A1)).toBe(true);
  });

  it("first observation binds identity; same epoch is idempotent; newer epoch is a legal restart", () => {
    const t = newInstanceEpochTracker();
    expect(observeInstanceEpoch(t, { nodeId: NODE_A.nodeId, instanceId: INSTANCE_A, epochId: EPOCH_A1 })).toMatchObject({ ok: true, code: "observed_new" });
    expect(observeInstanceEpoch(t, { nodeId: NODE_A.nodeId, instanceId: INSTANCE_A, epochId: EPOCH_A1 })).toMatchObject({ ok: true, code: "observed_same" });
    expect(observeInstanceEpoch(t, { nodeId: NODE_A.nodeId, instanceId: INSTANCE_A, epochId: EPOCH_A2 })).toMatchObject({ ok: true, code: "observed_new" });
  });

  it("an OLDER epoch than the newest observed is stale and refuses (L5)", () => {
    const t = newInstanceEpochTracker();
    expect(observeInstanceEpoch(t, { nodeId: NODE_A.nodeId, instanceId: INSTANCE_A, epochId: EPOCH_A2 }).ok).toBe(true);
    const stale = observeInstanceEpoch(t, { nodeId: NODE_A.nodeId, instanceId: INSTANCE_A, epochId: EPOCH_A1 });
    expect(stale).toMatchObject({ ok: false, code: "refused_stale" });
    expect(stale.ok === false && stale.explanation).toContain("stale epochs fail");
  });

  it("a same-tick rival epoch and a re-bound NodeId both refuse (split-brain identity)", () => {
    const t = newInstanceEpochTracker();
    expect(observeInstanceEpoch(t, { nodeId: NODE_A.nodeId, instanceId: INSTANCE_A, epochId: EPOCH_A1 }).ok).toBe(true);
    const rival = observeInstanceEpoch(t, { nodeId: NODE_A.nodeId, instanceId: INSTANCE_A, epochId: makeRuntimeEpochId(NOW, "cccc1111cccc1111") });
    expect(rival).toMatchObject({ ok: false, code: "refused_split_brain" });
    const collision = observeInstanceEpoch(t, { nodeId: NODE_B.nodeId, instanceId: INSTANCE_A, epochId: EPOCH_A2 });
    expect(collision).toMatchObject({ ok: false, code: "refused_identity_collision" });
  });

  it("malformed epoch ids refuse before anything is mutated", () => {
    const t = newInstanceEpochTracker();
    const bad = observeInstanceEpoch(t, { nodeId: NODE_A.nodeId, instanceId: INSTANCE_A, epochId: "re-garbage" });
    expect(bad).toMatchObject({ ok: false, code: "refused_malformed_epoch" });
    expect(t.instances.has(INSTANCE_A)).toBe(false);
  });
});

// ── trust machine (L6) ───────────────────────────────────────────────────────

describe("24A peer trust machine — terminal states never resurrect", () => {
  it("transition table is closed and mirrors the repository terminal law", () => {
    expect([...NODE_TRUST_STATES]).toEqual(["unknown", "candidate", "admitted", "quarantined", "retired"]);
    expect([...PEER_TRUST_TRANSITIONS.retired]).toEqual([]);
    expect([...PEER_TRUST_TRANSITIONS.quarantined]).toEqual(["retired"]);
    // 24C amendment: admitted → retired added (evidenced operator retirement;
    // quarantined → admitted and retired → anything remain unrepresentable).
    expect([...PEER_TRUST_TRANSITIONS.admitted]).toEqual(["quarantined", "retired"]);
  });

  it("quarantined→admitted, retired→anything and demotion are unrepresentable (L6)", () => {
    expect(isPeerTrustTransition("quarantined", "admitted")).toBe(false);
    expect(isPeerTrustTransition("retired", "candidate")).toBe(false);
    expect(isPeerTrustTransition("retired", "quarantined")).toBe(false);
    expect(isPeerTrustTransition("admitted", "candidate")).toBe(false);
    expect(isPeerTrustTransition("unknown", "admitted")).toBe(false);
    // 24C amendment: admitted → retired is the one legal direct exit
    // (evidenced operator retirement; mirrors the 21A registry law).
    expect(isPeerTrustTransition("admitted", "retired")).toBe(true);
  });

  it("transitions require evidence; unevidenced trust changes refuse", () => {
    expect(decideTrustTransition({ from: "candidate", to: "admitted", evidence: "" })).toMatchObject({
      ok: false,
      code: "transition_refused",
    });
    expect(decideTrustTransition({ from: "candidate", to: "admitted", evidence: "doc-hash" })).toMatchObject({
      ok: true,
      code: "transition_allowed",
      to: "admitted",
    });
  });
});

// ── identity document (L1/L2/L4/L5/L8/L9) ────────────────────────────────────

describe("24A identity document — the full fail-closed chain", () => {
  it("accepts a well-formed document ONCE and binds deterministic provenance with authority none (L2/L9)", () => {
    const { epochTracker } = freshTrackers();
    const first = validateNodeIdentityDocument({
      document: identityBody(),
      signature: "sig",
      verifier: OK_VERIFIER,
      epochTracker,
      nowEpochMs: NOW,
      localEpochId: EPOCH_B1,
    });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.provenance.authority).toBe("none");
    expect(first.provenance.subjectHash).toMatch(/^[0-9a-f]{32,128}$/);
    expect(first.provenance.localEpochId).toBe(EPOCH_B1);
    const again = validateNodeIdentityDocument({
      document: identityBody(),
      signature: "sig",
      verifier: OK_VERIFIER,
      epochTracker,
      nowEpochMs: NOW,
      localEpochId: EPOCH_B1,
    });
    if (again.ok) expect(again.provenance).toEqual(first.provenance);
  });

  it("refuses unknown fields (L4: federation is not a capability union)", () => {
    const { epochTracker } = freshTrackers();
    const hostile = identityBody();
    const doc = { ...hostile, grantedCapabilities: ["exec:all"] } as unknown as NodeIdentityDocumentBody;
    const result = validateNodeIdentityDocument({
      document: doc,
      signature: "sig",
      verifier: OK_VERIFIER,
      epochTracker,
      nowEpochMs: NOW,
      localEpochId: EPOCH_B1,
    });
    expect(result).toMatchObject({ ok: false, code: "refused_malformed" });
    expect(result.ok === false && result.explanation).toContain("unknown fields");
  });

  it("refuses schema mismatch, protocol downgrade, and NodeId/fingerprint substitution", () => {
    const { epochTracker } = freshTrackers();
    const base = { verifier: OK_VERIFIER, epochTracker, nowEpochMs: NOW, localEpochId: EPOCH_B1 };
    expect(
      validateNodeIdentityDocument({
        ...base,
        document: identityBody({ schemaVersion: "menog-federation-identity/v9" as NodeIdentityDocumentBody["schemaVersion"] }),
        signature: "sig",
      })
    ).toMatchObject({ ok: false, code: "refused_malformed" });
    expect(
      validateNodeIdentityDocument({
        ...base,
        document: identityBody({ protocolVersion: "menog-federation/v0" as NodeIdentityDocumentBody["protocolVersion"] }),
        signature: "sig",
      })
    ).toMatchObject({ ok: false, code: "refused_protocol_mismatch" });
    expect(
      validateNodeIdentityDocument({
        ...base,
        document: identityBody({ nodeId: NODE_B.nodeId, fingerprint: FP_A }),
        signature: "sig",
      })
    ).toMatchObject({ ok: false, code: "refused_nodeid_fingerprint_mismatch" });
  });

  it("an INVALID signature spoofs nothing; a VALID one still grants no authority (L2)", () => {
    const { epochTracker } = freshTrackers();
    const bad = validateNodeIdentityDocument({
      document: identityBody(),
      signature: "sig",
      verifier: () => ({ ok: false, reason: "bad signature" }),
      epochTracker,
      nowEpochMs: NOW,
      localEpochId: EPOCH_B1,
    });
    expect(bad).toMatchObject({ ok: false, code: "refused_signature_invalid" });
    expect(bad.ok === false && bad.explanation).toContain("no authority");
  });

  it("clock-skewed documents refuse within the tolerance window", () => {
    const { epochTracker } = freshTrackers();
    const base = { verifier: OK_VERIFIER, epochTracker, localEpochId: EPOCH_B1 };
    expect(
      validateNodeIdentityDocument({ ...base, document: identityBody({ issuedAtEpochMs: NOW + SKEW + 1 }), signature: "sig", nowEpochMs: NOW })
    ).toMatchObject({ ok: false, code: "refused_skew_out_of_tolerance" });
    expect(
      validateNodeIdentityDocument({ ...base, document: identityBody(), signature: "sig", nowEpochMs: NOW, skewToleranceMs: FEDERATION_MAX_CLOCK_SKEW_TOLERANCE_MS + 1 })
    ).toMatchObject({ ok: false, code: "refused_malformed" });
  });

  it("stale and split-brain epoch claims refuse through the tracker (L5)", () => {
    const { epochTracker } = freshTrackers();
    const base = { verifier: OK_VERIFIER, epochTracker, signature: "sig", nowEpochMs: NOW, localEpochId: EPOCH_B1 };
    expect(
      validateNodeIdentityDocument({ ...base, document: identityBody({ epochId: EPOCH_A2 }) })
    ).toMatchObject({ ok: true });
    expect(
      validateNodeIdentityDocument({ ...base, document: identityBody({ epochId: EPOCH_A1 }) })
    ).toMatchObject({ ok: false, code: "refused_stale_epoch" });
    const t2 = newInstanceEpochTracker();
    const b2 = { verifier: OK_VERIFIER, epochTracker: t2, signature: "sig", nowEpochMs: NOW, localEpochId: EPOCH_B1 };
    expect(validateNodeIdentityDocument({ ...b2, document: identityBody() })).toMatchObject({ ok: true });
    expect(
      validateNodeIdentityDocument({ ...b2, document: identityBody({ epochId: makeRuntimeEpochId(NOW, "dddd1111dddd1111") }) })
    ).toMatchObject({ ok: false, code: "refused_split_brain" });
  });
});

// ── message contract (L4/L5/L8/L9) ───────────────────────────────────────────

describe("24A signed-message contract — replay, lineage, freshness", () => {
  it("accepts a well-formed message exactly once; a second sighting of the id is a replay (L8)", () => {
    const { epochTracker, replayTracker } = freshTrackers();
    const base = { verifier: OK_VERIFIER, epochTracker, replayTracker, nowEpochMs: NOW, localEpochId: EPOCH_B1, signature: "sig" };
    expect(validateSignedMessageContract({ ...base, message: messageBody() })).toMatchObject({
      ok: true,
      code: "message_contract_accepted",
    });
    expect(validateSignedMessageContract({ ...base, message: messageBody() })).toMatchObject({
      ok: false,
      denyReason: "replay_detected",
    });
  });

  it("unknown fields refuse before any admission (L4)", () => {
    const { epochTracker, replayTracker } = freshTrackers();
    const hostile = { ...messageBody(), localPolicyOverride: "allow everything" } as unknown as FederationMessageBody;
    expect(
      validateSignedMessageContract({
        message: hostile,
        signature: "sig",
        verifier: OK_VERIFIER,
        epochTracker,
        replayTracker,
        nowEpochMs: NOW,
        localEpochId: EPOCH_B1,
      })
    ).toMatchObject({ ok: false, denyReason: "malformed_message" });
  });

  it("protocol downgrade and key substitution refuse (L1/L8)", () => {
    const { epochTracker, replayTracker } = freshTrackers();
    const base = { verifier: OK_VERIFIER, epochTracker, replayTracker, nowEpochMs: NOW, localEpochId: EPOCH_B1, signature: "sig" };
    expect(
      validateSignedMessageContract({ ...base, message: messageBody({ protocolVersion: "menog-federation/v0" as FederationMessageBody["protocolVersion"] }) })
    ).toMatchObject({ ok: false, denyReason: "protocol_mismatch" });
    expect(
      validateSignedMessageContract({ ...base, message: messageBody({ senderNodeId: NODE_B_ID, senderFingerprint: FP_A }) })
    ).toMatchObject({ ok: false, denyReason: "nodeid_fingerprint_mismatch" });
  });

  it("lineage forgery variants refuse: depth bound, self-reference, duplicates, dangling causation", () => {
    const deep = Array.from({ length: FEDERATION_MAX_LINEAGE_DEPTH + 1 }, (_, i) => makeFederationMessageId(NOW + i, "lg" + i + "0000000000"));
    const other: string = deep[0] ?? "";
    const selfId = makeFederationMessageId(NOW, "self000000000001");
    const run = (message: FederationMessageBody): ReturnType<typeof validateSignedMessageContract> => {
      const { epochTracker, replayTracker } = freshTrackers();
      return validateSignedMessageContract({
        message,
        signature: "sig",
        verifier: OK_VERIFIER,
        epochTracker,
        replayTracker,
        nowEpochMs: NOW,
        localEpochId: EPOCH_B1,
      });
    };
    expect(run(messageBody({ lineage: deep }))).toMatchObject({ ok: false, denyReason: "lineage_malformed" });
    expect(run(messageBody({ messageId: selfId, lineage: [selfId] }))).toMatchObject({ ok: false, denyReason: "lineage_malformed" });
    const dupA: string = deep[1] ?? "";
    const dupB: string = deep[1] ?? "";
    expect(run(messageBody({ lineage: [dupA, dupB] }))).toMatchObject({ ok: false, denyReason: "lineage_malformed" });
    expect(run(messageBody({ lineage: [], causationId: other }))).toMatchObject({ ok: false, denyReason: "lineage_malformed" });
    // positive control: a well-formed lineage is accepted — the refusals above are about forgery, not presence
    expect(run(messageBody({ lineage: [other], causationId: other }))).toMatchObject({ ok: true, code: "message_contract_accepted" });
  });

  it("stale sender epochs refuse after acceptance of the newer one (L5)", () => {
    const { epochTracker, replayTracker } = freshTrackers();
    const base = { verifier: OK_VERIFIER, epochTracker, replayTracker, nowEpochMs: NOW, localEpochId: EPOCH_B1, signature: "sig" };
    expect(
      validateSignedMessageContract({ ...base, message: messageBody({ senderEpochId: EPOCH_A2 }) })
    ).toMatchObject({ ok: true });
    expect(
      validateSignedMessageContract({ ...base, message: messageBody({ senderEpochId: EPOCH_A1, messageId: makeFederationMessageId(NOW + 5, "msg0000000000002") }) })
    ).toMatchObject({ ok: false, denyReason: "stale_epoch" });
  });

  it("provenance binds sender identity/epoch, subject hash, local epoch, and authority none (L9)", () => {
    const { epochTracker, replayTracker } = freshTrackers();
    const result = validateSignedMessageContract({
      message: messageBody(),
      signature: "sig",
      verifier: OK_VERIFIER,
      epochTracker,
      replayTracker,
      nowEpochMs: NOW,
      localEpochId: EPOCH_B1,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.provenance).toEqual({
      subjectId: result.provenance.subjectId,
      subjectHash: result.provenance.subjectHash,
      senderNodeId: NODE_A.nodeId,
      senderInstanceId: INSTANCE_A,
      senderEpochId: EPOCH_A1,
      protocolVersion: FEDERATION_PROTOCOL_VERSION,
      localEpochId: EPOCH_B1,
      decidedAtEpochMs: NOW,
      authority: "none",
    });
  });
});

// ── admission (L3/L6) ────────────────────────────────────────────────────────

describe("24A peer admission — communication trust only, never execution", () => {
  it("admits a well-formed candidate and the decision carries no execution field (L3)", () => {
    const { epochTracker } = freshTrackers();
    const decision = decidePeerAdmission({
      request: {
        requestId: "req-1",
        document: identityBody(),
        signature: "sig",
        requestedAtEpochMs: NOW,
      },
      senderTrustState: "candidate",
      verifier: OK_VERIFIER,
      epochTracker,
      nowEpochMs: NOW,
      localEpochId: EPOCH_B1,
    });
    expect(decision).toMatchObject({ ok: true, outcome: "admit", code: "admission_admitted", targetState: "admitted" });
    if (!decision.ok) return;
    expect(decision.explanation).toContain("no execution permission");
    expect("executionAuthorized" in decision).toBe(false);
    expect("policyAuthorized" in decision).toBe(false);
  });

  it("a quarantined or retired sender never resurrects through admission (L6)", () => {
    for (const state of ["quarantined", "retired"] as const) {
      const { epochTracker } = freshTrackers();
      const decision = decidePeerAdmission({
        request: { requestId: "req-1", document: identityBody(), signature: "sig", requestedAtEpochMs: NOW },
        senderTrustState: state,
        verifier: OK_VERIFIER,
        epochTracker,
        nowEpochMs: NOW,
        localEpochId: EPOCH_B1,
      });
      expect(decision).toMatchObject({ ok: false, outcome: "refuse", denyReason: "peer_terminal_state" });
      expect(decision.ok === false && decision.explanation).toContain("do not resurrect");
    }
  });

  it("skewed, malformed, and document-rejected requests refuse without a trust change", () => {
    const { epochTracker } = freshTrackers();
    const base = { senderTrustState: "candidate" as const, verifier: OK_VERIFIER, epochTracker, nowEpochMs: NOW, localEpochId: EPOCH_B1 };
    expect(
      decidePeerAdmission({ ...base, request: { requestId: "r", document: identityBody(), signature: "sig", requestedAtEpochMs: NOW + SKEW + 1 } })
    ).toMatchObject({ ok: false, denyReason: "request_skew_out_of_tolerance" });
    expect(
      decidePeerAdmission({ ...base, request: { requestId: "", document: identityBody(), signature: "sig", requestedAtEpochMs: NOW } })
    ).toMatchObject({ ok: false, denyReason: "malformed_request" });
    expect(
      decidePeerAdmission({
        ...base,
        request: { requestId: "r", document: identityBody({ protocolVersion: "menog-federation/v0" as NodeIdentityDocumentBody["protocolVersion"] }), signature: "sig", requestedAtEpochMs: NOW },
      })
    ).toMatchObject({ ok: false, denyReason: "identity_document_rejected" });
  });

  it("admission outcome vocabulary is closed and refuse carries explicit deny codes", () => {
    expect([...PEER_ADMISSION_OUTCOMES]).toEqual(["admit", "quarantine", "refuse"]);
    expect([...PEER_ADMISSION_DENY_CODES]).toEqual([
      "malformed_request",
      "identity_document_rejected",
      "peer_terminal_state",
      "trust_transition_refused",
      "request_skew_out_of_tolerance",
    ]);
    expect([...FEDERATION_MESSAGE_DENY_CODES]).toContain("replay_detected");
  });
});
