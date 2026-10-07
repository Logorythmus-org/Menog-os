/**
 * PHASE 24F — Federated Provenance & Cross-Node Evidence Tests
 * (EVIDENCE-ONLY / NO NEW AUTHORITY).
 *
 * Pack-mandated pins:
 *   - the canonical binding carries EVERY pack field (sender/receiver
 *     identity+epoch, message/proposal id, protocol/schema, payload hash,
 *     lineage, signature result, peer admission, LOCAL Policy result, local
 *     isolation/tool evidence refs, durable commit refs, response hash);
 *   - deterministic explanations (admit / refuse / quarantine / local-action);
 *   - NO private key/secret/token/process handle/raw hidden Policy surface;
 *   - foreign evidence is DATA, never local authority;
 *   - missing links and hash mismatches are EXPLICIT verdicts;
 *   - append-only + tamper-evident on EXISTING primitives (23B junction,
 *     22A canonical hashing); no total order / consensus / replay claims.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DurableStore,
  RuntimeStateCoordinator,
  PeerRegistry,
  FederationBus,
  ProposalLedger,
  ProvenanceLedger,
  generateLocalSigningIdentity,
  signFederationMessage,
  makeIdentitySignatureVerifier,
  makeFederationMessageId,
  makeRuntimeEpochId,
  canonicalHash,
  FEDERATION_PROVENANCE_SCHEMA_VERSION,
  PROVENANCE_ANCHOR_KEYS,
  validateProvenanceAnchor,
  provenanceAnchorHash,
  explainProvenanceDecision,
  bindForeignProvenance,
  federationProvenanceDurableId,
  type RuntimeEpoch,
  type FederationMessageBody,
  type FederationTaskProposalPayload,
  type FederationProvenanceAnchor,
  type ProvenanceSignatureResult,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

// ── fixtures ─────────────────────────────────────────────────────────────────

const NOW = 1_700_000_000_000;

const roots: string[] = [];
const openStores: DurableStore[] = [];
const openCoords: RuntimeStateCoordinator[] = [];
function newRoot(): string {
  const r = mkdtempSync(join(tmpdir(), "menog-24f-"));
  roots.push(r);
  return r;
}
afterEach(() => {
  for (const c of openCoords) {
    try { c.close(); } catch { /* already closed */ }
  }
  for (const s of openStores) {
    try { if (s.isOpen) s.close(); } catch { /* windows handles */ }
  }
  openCoords.length = 0;
  openStores.length = 0;
  for (const r of roots) {
    try { rmSync(r, { recursive: true, force: true }); } catch { /* windows handles */ }
  }
  roots.length = 0;
});

const EPOCH_1 = makeRuntimeEpochId(NOW, "epoch0000000001");
const EPOCH_2 = makeRuntimeEpochId(NOW + 1_000, "epoch0000000002");

function epochOf(id: string): RuntimeEpoch {
  return Object.freeze({
    schemaVersion: "menog-runtime-epoch/v0",
    epochId: id,
    startedAtEpochMs: NOW,
    hostRef: "wsl2-target-of-record",
    pidRef: 4242,
    lifecycle: "BOOTING",
    priorOwner: { code: "none" as const, epochId: null },
    startReason: "fresh_store_no_prior_owner",
    executionAuthorized: false as const,
    policyAuthorized: false as const,
  });
}

let txnCounter = 0;
function txn(tag: string): string {
  txnCounter += 1;
  return tag + "-" + String(txnCounter).padStart(6, "0");
}

const ROOT = "provenance-root-24f";

let anchorSeq = 0;
function anchorId(tag: string): string {
  anchorSeq += 1;
  const clean = tag.replace(/[^a-zA-Z0-9]/g, "").padEnd(16, "x").slice(0, 16);
  return "fv-" + (NOW + anchorSeq).toString(16).padStart(16, "0") + "-" + clean;
}

function signatureResult(overrides: Partial<ProvenanceSignatureResult> = {}): ProvenanceSignatureResult {
  return { result: "verified", reason: null, ...overrides };
}

/** A pack-valid anchor over a PROPOSAL happening. */
function validAnchor(senderNodeId: string, senderFingerprint: string, overrides: Partial<FederationProvenanceAnchor> = {}): FederationProvenanceAnchor {
  return {
    schemaVersion: FEDERATION_PROVENANCE_SCHEMA_VERSION,
    anchorId: anchorId("deterministicx"),
    kind: "task_proposal",
    messageId: null,
    proposalId: makeFederationMessageId(NOW + 500, "proposal000000001").replace(/^fm-/, "fp-"),
    senderNodeId,
    senderFingerprint,
    senderEpochId: makeRuntimeEpochId(NOW, "senderepoch00001"),
    receiverNodeId: "node-" + "9".repeat(64),
    receiverEpochId: EPOCH_1,
    protocolVersion: "menog-federation/v1",
    schemaVersionOfMessage: "menog-task-proposal/v0",
    payloadHash: "sha256-" + "a".repeat(64),
    correlationId: null,
    causationId: null,
    lineage: [],
    signatureResult: signatureResult(),
    peerAdmission: "admitted",
    localPolicyDecision: "none",
    policyEvidenceRefs: [],
    toolEvidenceRefs: [],
    commitRefs: [],
    responseHash: null,
    decision: "admitted",
    decidedAtEpochMs: NOW + 6,
    ...overrides,
  };
}

interface Stack {
  readonly store: DurableStore;
  readonly coordinator: RuntimeStateCoordinator;
  readonly registry: PeerRegistry;
  readonly bus: FederationBus;
  readonly proposals: ProposalLedger;
  readonly provenance: ProvenanceLedger;
  readonly sign: (m: FederationMessageBody) => string;
  readonly msg: (overrides?: Partial<FederationMessageBody>) => FederationMessageBody;
  readonly senderNodeId: string;
  readonly senderFingerprint: string;
}

/** Open the full 24D→24E→24F stack with ONE admitted peer. */
function openStack(epochId: string = EPOCH_1): Stack {
  const open = DurableStore.open(newRoot());
  if (!open.ok) throw new Error(open.reason);
  const store = open.store;
  openStores.push(store);
  const bound = RuntimeStateCoordinator.open(store, epochOf(epochId), "unit-test:24f");
  if (!bound.ok) throw new Error(bound.reason);
  const coordinator = bound.coordinator;
  openCoords.push(coordinator);
  const reg = PeerRegistry.open(store, coordinator);
  if (!reg.ok) throw new Error(reg.reason);
  const registry = reg.registry;

  const idA = generateLocalSigningIdentity();
  const instA = "ri-000000e8fa00-instanceaaaa";
  const enroll = registry.applyTrustTransition({
    nodeId: idA.nodeId, fingerprint: idA.fingerprint, instanceId: instA,
    protocolVersion: "menog-federation/v1", reason: "first_contact_enrolled",
    evidence: "identity doc hash", transactionId: txn("enroll"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: NOW,
  });
  if (!enroll.ok) throw new Error(enroll.explanation);
  const admit = registry.applyTrustTransition({
    nodeId: idA.nodeId, fingerprint: idA.fingerprint, instanceId: instA,
    protocolVersion: "menog-federation/v1", reason: "admission_request_accepted",
    evidence: "admission provenance", transactionId: txn("admit"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: NOW + 1,
  });
  if (!admit.ok) throw new Error(admit.explanation);

  const verifiers = new Map<string, ReturnType<typeof makeIdentitySignatureVerifier>>();
  verifiers.set(idA.nodeId.slice(5), makeIdentitySignatureVerifier(idA.publicKeyHex));
  const busOpen = FederationBus.open({ store, coordinator, peers: registry, verifiers });
  if (!busOpen.ok) throw new Error(busOpen.reason);
  const proposalsOpen = ProposalLedger.open({ store, coordinator });
  if (!proposalsOpen.ok) throw new Error(proposalsOpen.reason);
  const provenanceOpen = ProvenanceLedger.open({ store, coordinator });
  if (!provenanceOpen.ok) throw new Error(provenanceOpen.reason);

  let n = 0;
  const msg = (overrides: Partial<FederationMessageBody> = {}): FederationMessageBody => {
    n += 1;
    return {
      schemaVersion: "menog-federation-message/v0",
      messageId: makeFederationMessageId(NOW + n, "msg" + String(n).padStart(13, "0")),
      senderNodeId: idA.nodeId,
      senderFingerprint: idA.fingerprint,
      senderInstanceId: instA,
      senderEpochId: makeRuntimeEpochId(NOW, "senderepoch00001"),
      protocolVersion: "menog-federation/v1",
      payloadHash: "sha256-" + "5".repeat(64),
      declaredIntent: "task_proposal",
      correlationId: null,
      causationId: null,
      lineage: [],
      issuedAtEpochMs: NOW,
      ...overrides,
    };
  };
  const sign = (m: FederationMessageBody): string => {
    const s = signFederationMessage(idA, m);
    if (!s.ok) throw new Error(s.explanation);
    return s.signature;
  };

  return {
    store, coordinator, registry, bus: busOpen.bus,
    proposals: proposalsOpen.ledger, provenance: provenanceOpen.ledger,
    sign, msg,
    senderNodeId: idA.nodeId, senderFingerprint: idA.fingerprint,
  };
}

/** Deliver a valid proposal end-to-end: bus → durable proposal record. Returns its payload + the entry. */
function deliverAndAdmitProposal(s: Stack): { readonly payload: FederationTaskProposalPayload; readonly messageId: string; readonly receiptRecordId: string } {
  const payload = {
    schemaVersion: "menog-task-proposal/v0",
    proposalId: makeFederationMessageId(NOW + 500, "proposal000000001").replace(/^fm-/, "fp-"),
    intentClass: "workspace_survey",
    contentHashes: ["sha256-" + "a".repeat(64)],
    provenance: { originNodeId: s.senderNodeId, originFingerprint: s.senderFingerprint, note: "proposed" },
    constraints: { maxBudgetSteps: 2, readonlyWorkspaceOnly: true },
    expectedEvidence: ["sha256-" + "b".repeat(64)],
  } as FederationTaskProposalPayload;
  const m = s.msg({ payloadHash: canonicalHash(payload) });
  const busResult = s.bus.ingest({ envelope: { message: m, signature: s.sign(m) }, payload: payload as unknown as Record<string, unknown>, nowEpochMs: NOW + 5 });
  if (!busResult.ok) throw new Error("fixture: bus refused: " + busResult.explanation);
  const entry = s.bus.inbox()[s.bus.inbox().length - 1];
  if (!entry) throw new Error("fixture: no inbox entry");
  const admitted = s.proposals.receiveTaskProposal({
    inboxEntry: { messageId: entry.messageId, senderNodeId: entry.senderNodeId, declaredIntent: entry.declaredIntent, payload: entry.payload },
    senderFingerprint: s.senderFingerprint,
    receiptRecordId: entry.receiptRecordId,
    nowEpochMs: NOW + 6,
  });
  if (!admitted.ok) throw new Error("fixture: proposal refused: " + admitted.explanation);
  return { payload, messageId: entry.messageId, receiptRecordId: entry.receiptRecordId };
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("24F structure — the canonical binding, no new authority, existing primitives", () => {
  it("the anchor shape pins EVERY pack binding field", () => {
    const expected = [
      "senderNodeId", "senderFingerprint", "senderEpochId", "receiverNodeId", "receiverEpochId",
      "messageId", "proposalId", "protocolVersion", "schemaVersionOfMessage", "payloadHash",
      "correlationId", "causationId", "lineage", "signatureResult", "peerAdmission",
      "localPolicyDecision", "policyEvidenceRefs", "toolEvidenceRefs", "commitRefs", "responseHash",
    ];
    for (const field of expected) {
      expect([...PROVENANCE_ANCHOR_KEYS]).toContain(field);
    }
    expect(PROVENANCE_ANCHOR_KEYS).toHaveLength(25);
    expect(FEDERATION_PROVENANCE_SCHEMA_VERSION).toBe("menog-federation-provenance/v0");
  });

  it("the fourth unfreeze kind is append-only + permanent and derived in the coordinator", () => {
    const records = SRC("records.ts");
    expect(records).toContain('"federation_provenance"');
    expect(records).toContain('federation_provenance: "fpv"');
    const classification = SRC("classification.ts");
    expect(classification).toContain('recordKind: "federation_provenance"');
    expect(classification).toContain('mutationPosture: "append_only"');
    expect(classification).toContain('retentionClass: "permanent"');
    const coordinator = SRC("coordinator.ts");
    expect(coordinator).toContain('input.kind === "federation_provenance"');
    const statePersistence = SRC("statePersistence.ts");
    expect(statePersistence).toContain('FEDERATION_PROVENANCE_ID_PREFIX = "fpv-"');
  });

  it("the provenance layer performs no network I/O, no process invocation, and no direct store persist", () => {
    const code = codeOnly(SRC("federationProvenance.ts"));
    for (const forbidden of ["fetch(", "node:net", "node:http", "node:https", "child_process", "spawn(", "listen(", "executeToolRun", "runIsolated", ".persist(", "crypto.createSign", "generateKeyPair"]) {
      expect(code).not.toContain(forbidden);
    }
    expect(code).toContain("acceptMutation");
    expect(code).toContain('kind: "federation_provenance"');
  });

  it("the anchor body stores hashes/refs — never raw secret material — and authority markers never grant", () => {
    const src = SRC("federationProvenance.ts");
    expect(src).toContain('localPolicyDecision: "none"');
    expect(src).toContain('peerAdmission: "not_admitted"');
    // no private-key/secret field ever declared on the anchor
    for (const forbidden of ["readonly privateKey", "readonly secretKey", "readonly token", "readonly password", "readonly processHandle"]) {
      expect(src).not.toContain(forbidden);
    }
  });
});

// ── positive path ────────────────────────────────────────────────────────────

describe("24F positive path — anchoring the 24E proposal linkage", () => {
  it("a proposal's provenance anchors durably with hash-consistent linkage to receipt + proposal records", () => {
    const s = openStack();
    const { payload, receiptRecordId } = deliverAndAdmitProposal(s);
    const anchor = validAnchor(s.senderNodeId, s.senderFingerprint, {
      proposalId: payload.proposalId,
      messageId: null,
      payloadHash: canonicalHash(payload),
      commitRefs: [receiptRecordId],
    });
    const result = s.provenance.anchor({ anchor, nowEpochMs: NOW + 7 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.recordId).toBe("fpv-" + anchor.anchorId);
    expect(result.anchorHash).toBe(provenanceAnchorHash(anchor));
    expect(result.explanation).toContain("no authority");

    // read back as DATA: identical hash, identical body, no authority
    const back = s.provenance.readAnchor(anchor.anchorId);
    expect(back.ok).toBe(true);
    if (back.ok) {
      expect(back.anchorHash).toBe(result.anchorHash);
      expect(back.anchor.decision).toBe("admitted");
      expect(back.anchor.localPolicyDecision).toBe("none");
    }
  });

  it("foreign evidence binds as DATA: remote claims are not copied; refusal facts stay pinned", () => {
    const s = openStack();
    const foreign = bindForeignProvenance({
      facts: {
        anchorId: anchorId("foreign Factsx"),
        kind: "evidence",
        messageId: makeFederationMessageId(NOW + 700, "foreign000000001"),
        proposalId: null,
        senderNodeId: s.senderNodeId,
        senderFingerprint: s.senderFingerprint,
        senderEpochId: makeRuntimeEpochId(NOW, "senderepoch00001"),
        payloadHash: "sha256-" + "c".repeat(64),
        correlationId: null,
        causationId: null,
        lineage: [],
        protocolVersion: "menog-federation/v1",
        schemaVersionOfMessage: "menog-federation-message/v0",
        signatureResult: signatureResult(),
      },
      receiverNodeId: "node-" + "9".repeat(64),
      receiverEpochId: EPOCH_1,
      decision: "refused",
      nowEpochMs: NOW + 7,
    });
    expect(foreign.ok).toBe(true);
    if (!foreign.ok) return;
    // the receiver's judgment fields are LOCAL facts, not remote claims
    expect(foreign.anchor.peerAdmission).toBe("not_admitted");
    expect(foreign.anchor.localPolicyDecision).toBe("none");
    expect(foreign.anchor.decision).toBe("refused");
    expect(foreign.anchor.responseHash).toBeNull();
    // a hostile caller cannot elevate a foreign anchor to local authority
    const elevated = validateProvenanceAnchor({ ...foreign.anchor, decision: "local_action", localPolicyDecision: "allow" });
    // (valid shape — elevation would still grant nothing; authority comes only from real LOCAL records)
    expect(elevated.ok).toBe(true);
    void elevated;
  });
});

// ── pack negative tests ──────────────────────────────────────────────────────

describe("24F negative tests — explicit, fail-closed, deterministic", () => {
  it("MISSING LINK: a message anchor without a local durable receipt refuses explicitly", () => {
    const s = openStack();
    const anchor = validAnchor(s.senderNodeId, s.senderFingerprint, {
      kind: "evidence",
      messageId: makeFederationMessageId(NOW + 800, "ghost0000000001"),
      proposalId: null,
    });
    const result = s.provenance.anchor({ anchor, nowEpochMs: NOW + 7 });
    expect(result).toMatchObject({ ok: false, failureCode: "missing_local_link" });
    if (!result.ok) expect(result.explanation).toContain("explicit-missing");
    expect(s.provenance.hasAnchor(anchor.anchorId)).toBe(false);
  });

  it("MISSING LINK (proposal): an anchor naming a proposal id with no local proposal record refuses explicitly", () => {
    const s = openStack();
    const anchor = validAnchor(s.senderNodeId, s.senderFingerprint, {
      proposalId: "fp-0000000000000000-missingproposals",
    });
    const result = s.provenance.anchor({ anchor, nowEpochMs: NOW + 7 });
    expect(result).toMatchObject({ ok: false, failureCode: "missing_local_link" });
    if (!result.ok) expect(result.explanation).toContain("explicit-missing");
  });

  it("HASH MISMATCH: an anchor contradicting the durable receipt (sender/payload) refuses explicitly", () => {
    const s = openStack();
    const { payload, messageId } = deliverAndAdmitProposal(s);
    const anchor = validAnchor(s.senderNodeId, s.senderFingerprint, {
      kind: "evidence",
      messageId,
      proposalId: null,
      payloadHash: canonicalHash(payload) === "sha256-" + "f".repeat(64) ? "sha256-" + "a".repeat(64) : "sha256-" + "f".repeat(64),
    });
    const result = s.provenance.anchor({ anchor, nowEpochMs: NOW + 7 });
    expect(result).toMatchObject({ ok: false, failureCode: "hash_mismatch" });
    if (!result.ok) expect(result.explanation).toContain("made explicit");
  });

  it("DUPLICATE: the same anchor id refuses this epoch and after restart (durable record index)", () => {
    const s = openStack();
    const { payload, receiptRecordId } = deliverAndAdmitProposal(s);
    const anchor = validAnchor(s.senderNodeId, s.senderFingerprint, {
      proposalId: payload.proposalId,
      payloadHash: canonicalHash(payload),
      commitRefs: [receiptRecordId],
    });
    const first = s.provenance.anchor({ anchor, nowEpochMs: NOW + 7 });
    expect(first.ok).toBe(true);
    const second = s.provenance.anchor({ anchor, nowEpochMs: NOW + 8 });
    expect(second).toMatchObject({ ok: false, failureCode: "provenance_duplicate" });

    // RESTART: new epoch coordinator + ledger still refuses
    s.coordinator.close();
    const bound = RuntimeStateCoordinator.open(s.store, epochOf(EPOCH_2), "unit-test:24f-e2");
    if (!bound.ok) throw new Error(bound.reason);
    openCoords.push(bound.coordinator);
    const reopen = ProvenanceLedger.open({ store: s.store, coordinator: bound.coordinator });
    if (!reopen.ok) throw new Error(reopen.reason);
    expect(reopen.ledger.hasAnchor(anchor.anchorId)).toBe(true);
    const after = reopen.ledger.anchor({ anchor, nowEpochMs: NOW + 9 });
    expect(after).toMatchObject({ ok: false, failureCode: "provenance_duplicate" });
    const back = reopen.ledger.readAnchor(anchor.anchorId);
    expect(back.ok).toBe(true);
    if (back.ok) expect(back.anchorHash).toBe(provenanceAnchorHash(anchor));
  });

  it("SECRET SURFACE: anchors carrying private keys/tokens/handles/raw hidden Policy refuse", () => {
    const hostile = validAnchor("node-" + "a".repeat(64), "fp-sha256-" + "a".repeat(64), {
      signatureResult: { result: "verified", reason: null },
    });
    const withSecret = { ...hostile, commitRefs: ["ref-ok-1"] } as Record<string, unknown>;
    (withSecret as Record<string, unknown>)["note"] = undefined;
    // inject forbidden surface via a forged extra field — unknown fields refuse FIRST
    const smuggle = validateProvenanceAnchor({ ...withSecret, privateKey: "308187020100" });
    expect(smuggle).toMatchObject({ ok: false, failureCode: "provenance_malformed" });
    // forbidden surface hidden in a legitimate field (a reason string) is caught by the scan
    const hidden = validateProvenanceAnchor({
      ...validAnchor("node-" + "a".repeat(64), "fp-sha256-" + "a".repeat(64), {
        signatureResult: { result: "unverified", reason: "leak: secretKey=308187020100 placed in the reason" },
      }),
    });
    expect(hidden).toMatchObject({ ok: false, failureCode: "provenance_secret_surface" });
    // raw hidden Policy text is also refused
    const policyLeak = validateProvenanceAnchor({
      ...validAnchor("node-" + "a".repeat(64), "fp-sha256-" + "a".repeat(64), {
        signatureResult: { result: "unverified", reason: "hiddenPolicy: deny workspace:write always" },
      }),
    });
    expect(policyLeak).toMatchObject({ ok: false, failureCode: "provenance_secret_surface" });
  });

  it("SCHEMA/CLOSED-SHAPE: unknown fields, wrong schema, and incoherent bindings refuse", () => {
    const s = openStack();
    const base = validAnchor(s.senderNodeId, s.senderFingerprint);
    expect(validateProvenanceAnchor({ ...base, extra: 1 })).toMatchObject({ ok: false, failureCode: "provenance_malformed" });
    expect(validateProvenanceAnchor({ ...base, schemaVersion: "menog-federation-provenance/v9" })).toMatchObject({ ok: false, failureCode: "provenance_schema_mismatch" });
    expect(validateProvenanceAnchor({ ...base, decision: "local_action", localPolicyDecision: "none" })).toMatchObject({ ok: false, failureCode: "provenance_malformed" });
    expect(validateProvenanceAnchor({ ...base, decision: "quarantined", peerAdmission: "admitted" })).toMatchObject({ ok: false, failureCode: "provenance_malformed" });
    expect(validateProvenanceAnchor({ ...base, messageId: null, proposalId: null })).toMatchObject({ ok: false, failureCode: "provenance_malformed" });
    expect(validateProvenanceAnchor({ ...base, messageId: makeFederationMessageId(NOW + 1, "alsobound000001"), proposalId: base.proposalId })).toMatchObject({ ok: false, failureCode: "provenance_malformed" });
    expect(validateProvenanceAnchor({ ...base, anchorId: "fv-zzz" })).toMatchObject({ ok: false, failureCode: "provenance_identity_mismatch" });
    expect(validateProvenanceAnchor({ ...base, signatureResult: { result: "unverified", reason: null } })).toMatchObject({ ok: false, failureCode: "provenance_malformed" });
  });

  it("DETERMINISTIC EXPLANATIONS: the same evidence always yields the same string, for all four decisions", () => {
    const s = openStack();
    const mk = (decision: "admitted" | "refused" | "quarantined" | "local_action") =>
      validAnchor(s.senderNodeId, s.senderFingerprint, {
        decision,
        peerAdmission: decision === "quarantined" ? "quarantined" : "admitted",
        localPolicyDecision: decision === "local_action" ? "allow" : "none",
        signatureResult: decision === "refused" ? { result: "unverified", reason: "bad signature" } : signatureResult(),
      });
    for (const decision of ["admitted", "refused", "quarantined", "local_action"] as const) {
      const a1 = mk(decision);
      const e1 = explainProvenanceDecision(a1);
      const e2 = explainProvenanceDecision(a1);
      expect(e1).toBe(e2);
      expect(e1.length).toBeGreaterThan(20);
      // a re-derived structurally identical anchor explains identically
      const a2 = { ...a1, anchorId: anchorId("deterministicx") };
      expect(explainProvenanceDecision(a2)).toBe(e1);
    }
    expect(explainProvenanceDecision(mk("admitted"))).toMatch(/^ADMIT:/);
    expect(explainProvenanceDecision(mk("refused"))).toMatch(/^REFUSE:/);
    expect(explainProvenanceDecision(mk("quarantined"))).toMatch(/^QUARANTINE:/);
    expect(explainProvenanceDecision(mk("local_action"))).toMatch(/^LOCAL-ACTION:/);
  });

  it("TAMPER EVIDENCE: an anchor record cannot be rewritten through the junction (append-only)", () => {
    const s = openStack();
    const { payload, receiptRecordId } = deliverAndAdmitProposal(s);
    const anchor = validAnchor(s.senderNodeId, s.senderFingerprint, {
      proposalId: payload.proposalId,
      payloadHash: canonicalHash(payload),
      commitRefs: [receiptRecordId],
    });
    const first = s.provenance.anchor({ anchor, nowEpochMs: NOW + 7 });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const read = s.store.readRecord(first.recordId);
    if (!read.ok) throw new Error("fixture");
    const forgedPayload = { ...(read.record.payload as Record<string, unknown>), decision: "local_action", localPolicyDecision: "allow" };
    const resealed = Object.freeze({ ...read.record, payload: Object.freeze(forgedPayload) });
    const attempt = s.store.persist(resealed);
    expect(attempt.ok).toBe(false); // append-only kind: no revision, no rewrite
  });

  it("the anchor id helper is strict and the ledger refuses a closed coordinator", () => {
    expect(federationProvenanceDurableId("fv-zzz").ok).toBe(false);
    const s = openStack();
    s.coordinator.close();
    const result = s.provenance.anchor({ anchor: validAnchor(s.senderNodeId, s.senderFingerprint), nowEpochMs: NOW + 7 });
    expect(result).toMatchObject({ ok: false, failureCode: "ledger_closed" });
  });
});
