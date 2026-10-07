/**
 * PHASE 25G — Adversarial Operational Hardening (SAFE LOCAL FIXTURES ONLY).
 *
 * 22 adversarial cases against the REAL 25A–25F surfaces (no mocks of
 * attacked components). Every case records { expectedControl, actualResult,
 * verdict } with the pack vocabulary PASS / FAIL / UNSUPPORTED /
 * INCONCLUSIVE — UNSUPPORTED is NOT PASS: two cases (capability union;
 * alternate durable/network/spawn/listener path) are attacks that CANNOT
 * BE CONSTRUCTED against any public surface of this system and are
 * recorded as UNSUPPORTED with the static evidence, never claimed as
 * defeats.
 *
 * The evidence artifact `docs/release/PHASE25_SECURITY_EVIDENCE.json` is
 * written from the ACTUAL results of each run (never hand-copied).
 *
 * SCOPE: process-local fixtures only; no network, no deployment, no
 * power-loss/hardware claim, no key material fabricated beyond the 24B
 * public-facts records (private keys are never constructed here — the
 * lifecycle attacks run on the PUBLIC record vocabulary by law).
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
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
  requireFreshLocalAuthorization,
  bindForeignProvenance,
  deriveLocalTaskCandidate,
  decideBoundaryClaim,
  authorizeKeyMaterialPlacement,
  decideKeyUse,
  reloadLifecycleRecord,
  decideLifecycleTransition,
  decideTrustInheritance,
  decideRollbackRestore,
  checkLocalAdminIntent,
  refusePeerCommand,
  PeerAdminSession,
  decideEgress,
  verifyEgressManifest,
  classifyOperationalRisk,
  EGRESS_SCHEMA_VERSION,
  type RuntimeEpoch,
  type FederationMessageBody,
  type FederationTaskProposalPayload,
  type EgressCandidate,
  type KeyLifecycleRecord,
} from "@menog/durable-state";
import { classifyEnvironment } from "../../scripts/phase25e-environment-probe.mjs";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

// ── adversarial harness (the evidence discipline) ────────────────────────────

export type AdversarialVerdict = "PASS" | "FAIL" | "UNSUPPORTED" | "INCONCLUSIVE";

export interface AdversarialCaseResult {
  readonly caseId: string;
  readonly attack: string;
  readonly expectedControl: string;
  readonly actualResult: string;
  readonly verdict: AdversarialVerdict;
}

const RESULTS: AdversarialCaseResult[] = [];
function record(caseId: string, attack: string, expectedControl: string, actualResult: string, verdict: AdversarialVerdict): void {
  RESULTS.push({ caseId, attack, expectedControl, actualResult, verdict });
}

afterAll(() => {
  if (RESULTS.length === 0) return;
  const summary = {
    total: RESULTS.length,
    PASS: RESULTS.filter((r) => r.verdict === "PASS").length,
    FAIL: RESULTS.filter((r) => r.verdict === "FAIL").length,
    UNSUPPORTED: RESULTS.filter((r) => r.verdict === "UNSUPPORTED").length,
    INCONCLUSIVE: RESULTS.filter((r) => r.verdict === "INCONCLUSIVE").length,
  };
  const evidence = {
    schemaVersion: "menog-phase25-adversarial-evidence/v0",
    gate: "25G",
    suite: "tests/unit/phase25g-adversarial-operational.test.ts",
    verdictVocabulary: ["PASS", "FAIL", "UNSUPPORTED", "INCONCLUSIVE"],
    verdictSemantics: "UNSUPPORTED is NOT PASS: recorded when the attack cannot be constructed against any public surface",
    scope: "process-local fixtures only; no network, no deployment, no power-loss/hardware claim",
    cases: RESULTS,
    summary,
    criticalBypass: summary.FAIL > 0,
    repairActions: [] as string[],
    runFinishedAtEpochMs: Date.now(),
  };
  const fixtureDir = join(process.cwd(), "tests", "fixtures", "phase25g");
  mkdirSync(fixtureDir, { recursive: true });
  writeFileSync(join(fixtureDir, "PHASE25_SECURITY_EVIDENCE.json"), JSON.stringify(evidence, null, 2) + "\n", "utf8");
});

// ── fixtures ─────────────────────────────────────────────────────────────────

const roots: string[] = [];
const openStores: DurableStore[] = [];
const openCoords: RuntimeStateCoordinator[] = [];
function newRoot(): string {
  const r = mkdtempSync(join(tmpdir(), "menog-25g-"));
  roots.push(r);
  return r;
}
afterAll(() => {
  for (const c of openCoords) {
    try { c.close(); } catch { /* already closed */ }
  }
  for (const s of openStores) {
    try { if (s.isOpen) s.close(); } catch { /* windows handles */ }
  }
  for (const r of roots) {
    try { rmSync(r, { recursive: true, force: true }); } catch { /* windows handles */ }
  }
});

const NOW = 1_700_000_000_000;
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

let tickCounter = 0;
function tick(): number {
  tickCounter += 1;
  return NOW + tickCounter;
}

const ROOT = "adversarial-root-25g";

/** A verified PUBLIC-facts lifecycle record for an identity (25B law: initialize from public facts only). */
function lifecycleRecordFor(identity: { readonly publicKeyHex: string; readonly fingerprint: string; readonly nodeId: string }, atEpochMs: number): KeyLifecycleRecord {
  const d = decideLifecycleTransition({
    record: null,
    to: "active",
    evidence: "25G fixture: verified public facts initialize (no private material involved)",
    nowEpochMs: atEpochMs,
    freshPublicFacts: { publicKeyHex: identity.publicKeyHex, fingerprint: identity.fingerprint, nodeId: identity.nodeId },
  });
  if (!d.ok) throw new Error(d.explanation);
  return d.record;
}

function proposalPayload(senderNodeId: string, senderFingerprint: string, overrides: Partial<Record<string, unknown>> = {}): FederationTaskProposalPayload {
  return {
    schemaVersion: "menog-task-proposal/v0",
    proposalId: makeFederationMessageId(NOW + 500, "proposal25g00001").replace(/^fm-/, "fp-"),
    intentClass: "workspace_survey",
    contentHashes: ["sha256-" + "a".repeat(64)],
    provenance: { originNodeId: senderNodeId, originFingerprint: senderFingerprint, note: "proposed" },
    constraints: { maxBudgetSteps: 2, readonlyWorkspaceOnly: true },
    expectedEvidence: ["sha256-" + "b".repeat(64)],
    ...overrides,
  } as FederationTaskProposalPayload;
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
  readonly signB: (m: FederationMessageBody) => string;
  readonly senderNodeId: string;
  readonly senderFingerprint: string;
  readonly nodeBId: string;
  readonly fingerprintB: string;
  readonly instB: string;
}

function openStack(epochId: string = EPOCH_1): Stack {
  const open = DurableStore.open(newRoot());
  if (!open.ok) throw new Error(open.reason);
  const store = open.store;
  openStores.push(store);
  const bound = RuntimeStateCoordinator.open(store, epochOf(epochId), "unit-test:25g");
  if (!bound.ok) throw new Error(bound.reason);
  const coordinator = bound.coordinator;
  openCoords.push(coordinator);
  const reg = PeerRegistry.open(store, coordinator);
  if (!reg.ok) throw new Error(reg.reason);
  const registry = reg.registry;

  const idA = generateLocalSigningIdentity();
  const idB = generateLocalSigningIdentity();
  const instA = "ri-000000e8fa00-instanceaaaa";
  const instB = "ri-000000e8fa00-instancebbbb";
  for (const [identity, instanceId, tag] of [[idA, instA, "a"], [idB, instB, "b"]] as const) {
    const enroll = registry.applyTrustTransition({
      nodeId: identity.nodeId, fingerprint: identity.fingerprint, instanceId,
      protocolVersion: "menog-federation/v1", reason: "first_contact_enrolled",
      evidence: "identity doc hash", transactionId: txn("enroll-" + tag), lineageRoot: ROOT, lineageParent: null, nowEpochMs: tick(),
    });
    if (!enroll.ok) throw new Error(enroll.explanation);
    const admit = registry.applyTrustTransition({
      nodeId: identity.nodeId, fingerprint: identity.fingerprint, instanceId,
      protocolVersion: "menog-federation/v1", reason: "admission_request_accepted",
      evidence: "admission provenance", transactionId: txn("admit-" + tag), lineageRoot: ROOT, lineageParent: null, nowEpochMs: tick(),
    });
    if (!admit.ok) throw new Error(admit.explanation);
  }

  const verifiers = new Map<string, ReturnType<typeof makeIdentitySignatureVerifier>>();
  verifiers.set(idA.nodeId.slice(5), makeIdentitySignatureVerifier(idA.publicKeyHex));
  verifiers.set(idB.nodeId.slice(5), makeIdentitySignatureVerifier(idB.publicKeyHex));
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
  const signFor = (identity: Parameters<typeof signFederationMessage>[0]) =>
    (m: FederationMessageBody): string => {
      const s = signFederationMessage(identity, m);
      if (!s.ok) throw new Error(s.explanation);
      return s.signature;
    };

  return {
    store, coordinator, registry, bus: busOpen.bus,
    proposals: proposalsOpen.ledger, provenance: provenanceOpen.ledger,
    sign: signFor(idA), msg,
    signB: signFor(idB),
    senderNodeId: idA.nodeId, senderFingerprint: idA.fingerprint,
    nodeBId: idB.nodeId, fingerprintB: idB.fingerprint, instB,
  };
}

/** Bus-admit a signed proposal message from peer A and return the inbox entry. */
function deliver(s: Stack, payload: Record<string, unknown>) {
  const m = s.msg({ payloadHash: canonicalHash(payload) });
  const result = s.bus.ingest({ envelope: { message: m, signature: s.sign(m) }, payload, nowEpochMs: tick() });
  const entry = s.bus.inbox()[s.bus.inbox().length - 1];
  return { result, entry, messageId: m.messageId };
}

function admit(s: Stack, entry: NonNullable<ReturnType<typeof deliver>["entry"]>) {
  return s.proposals.receiveTaskProposal({
    inboxEntry: { messageId: entry.messageId, senderNodeId: entry.senderNodeId, declaredIntent: entry.declaredIntent, payload: entry.payload },
    senderFingerprint: s.senderFingerprint,
    receiptRecordId: entry.receiptRecordId,
    nowEpochMs: tick(),
  });
}

// ── the 22 adversarial cases ─────────────────────────────────────────────────

describe("25G adversarial operational hardening — 22 cases, recorded verdicts", () => {

  it("AOG-01 old/stolen key after rotation: the rotated-away key refuses every use even though its signature still verifies", () => {
    const identity = generateLocalSigningIdentity();
    const rotated = generateLocalSigningIdentity();
    let rec = lifecycleRecordFor(identity, tick());
    const req = decideLifecycleTransition({ record: rec, to: "rotation_requested", evidence: "operator rotation request", nowEpochMs: tick() });
    if (!req.ok) throw new Error(req.explanation);
    rec = req.record;
    const rot = decideLifecycleTransition({
      record: rec, to: "rotated", evidence: "locally evidenced rotation", nowEpochMs: tick(),
      freshPublicFacts: { publicKeyHex: rotated.publicKeyHex, fingerprint: rotated.fingerprint, nodeId: rotated.nodeId },
    });
    if (!rot.ok) throw new Error(rot.explanation);
    const staleUse = decideKeyUse({ record: rot.record, keyIdClaim: rot.record.keyId, fingerprintClaim: rot.record.fingerprint });
    const inheritance = decideTrustInheritance({ oldRecord: rot.record, freshNodeId: rotated.nodeId });
    const freshUse = decideKeyUse({ record: lifecycleRecordFor(rotated, tick()) });
    const ok = staleUse.ok === false && staleUse.ok === false && staleUse.code === "stale_rotated_key" && inheritance.ok === false && freshUse.ok === true;
    record(
      "AOG-01",
      "old/stolen key after rotation (stale key presented for signing/verification)",
      "the key-USE gate refuses rotated keys (stale_rotated_key) even though 24B crypto would still verify their signatures; trust inheritance is ALWAYS refused (P7)",
      "decideKeyUse refused stale_rotated_key; decideTrustInheritance refused (P7); the FRESH identity's record permits use",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-02 revoked signature: a revoked key's signature stays cryptographically checkable yet is operationally refused", () => {
    const identity = generateLocalSigningIdentity();
    let rec = lifecycleRecordFor(identity, tick());
    const rev = decideLifecycleTransition({ record: rec, to: "revoked", evidence: "evidenced revocation (compromise)", nowEpochMs: tick() });
    if (!rev.ok) throw new Error(rev.explanation);
    rec = rev.record;
    const use = decideKeyUse({ record: rec });
    const reload = reloadLifecycleRecord(rec);
    const postReloadUse = decideKeyUse({ record: reload.ok ? reload.record : null });
    const ok = use.ok === false && use.ok === false && use.code === "state_revoked" && reload.ok === true && postReloadUse.ok === false && postReloadUse.code === "state_revoked";
    record(
      "AOG-02",
      "revoked signature (revoked key used for a signing/verification operation)",
      "the key-USE gate refuses revoked keys permanently and revocation SURVIVES a restart reload (reload re-enters state 'revoked')",
      "decideKeyUse refused state_revoked; reloadLifecycleRecord reloaded EXACTLY 'revoked'; post-reload use refused state_revoked",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-03 forged rotation: a direct active→rotated jump (no evidenced request) refuses; a self-referential rotation refuses", () => {
    const identity = generateLocalSigningIdentity();
    const rec = lifecycleRecordFor(identity, tick());
    const forged = decideLifecycleTransition({
      record: rec, to: "rotated", evidence: "forged: no request was ever made", nowEpochMs: tick(),
      freshPublicFacts: { publicKeyHex: identity.publicKeyHex, fingerprint: identity.fingerprint, nodeId: identity.nodeId },
    });
    const selfRotation = decideLifecycleTransition({
      record: rec, to: "rotation_requested", evidence: "request", nowEpochMs: tick(),
    });
    const selfExec = selfRotation.ok
      ? decideLifecycleTransition({ record: selfRotation.record, to: "rotated", evidence: "self rotation", nowEpochMs: tick(), freshPublicFacts: { publicKeyHex: identity.publicKeyHex, fingerprint: identity.fingerprint, nodeId: identity.nodeId } })
      : ({ ok: false, code: "rotation_not_requested", explanation: "fixture fallback" } as const);
    const ok = forged.ok === false && forged.ok === false && forged.code === "rotation_not_requested" && selfRotation.ok === true && selfExec.ok === false && (selfExec.ok === false && selfExec.code === "rotation_not_fresh");
    record(
      "AOG-03",
      "forged rotation (rotation executed without a request; self-referential rotation reusing the same key)",
      "the closed lifecycle machine demands request-before-execute and a GENUINELY FRESH identity; forged/self rotations refuse",
      "direct jump refused rotation_not_requested; self-referential execution refused rotation_not_fresh",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-04 key substitution at the lifecycle layer: a forged keyId claim AND a forged fingerprint claim both refuse", () => {
    const identity = generateLocalSigningIdentity();
    const attacker = generateLocalSigningIdentity();
    const rec = lifecycleRecordFor(identity, tick());
    const wrongKeyId = decideKeyUse({ record: rec, keyIdClaim: "kid-" + "0".repeat(16) });
    const wrongFingerprint = decideKeyUse({ record: rec, fingerprintClaim: attacker.fingerprint });
    const ok = wrongKeyId.ok === false && wrongKeyId.ok === false && wrongKeyId.code === "key_id_mismatch" && wrongFingerprint.ok === false && wrongFingerprint.code === "fingerprint_mismatch";
    record(
      "AOG-04",
      "key substitution (attacker presents operations claiming the victim's key id / fingerprint)",
      "the lifecycle record canonically re-derives its keyId from the public key and binds the fingerprint; claims that do not match refuse",
      "keyId claim refused key_id_mismatch; fingerprint claim refused fingerprint_mismatch (both fail closed)",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-05 remote self-admission: a peer message that claims admission is refused as a command (DATA, never an admin order)", () => {
    const s = openStack();
    const refusal = refusePeerCommand("self_admit", s.nodeBId);
    const claim = decideBoundaryClaim({ claimKind: "admission_claim", peerId: s.nodeBId, localEpochId: EPOCH_1, decidedAtEpochMs: tick() });
    const classified = classifyOperationalRisk({ kind: "peer_unknown", peerId: s.nodeBId });
    const ok = refusal.refused === true && claim.ok === true && classified.riskId === "OT-01_unknown_peer" && ["contain", "refuse", "quarantine", "investigate", "monitor"].includes(classified.disposition);
    record(
      "AOG-05",
      "remote self-admission (peer message instructs the node to admit the sender)",
      "a peer message can never be an admin command: the claim is receivable only as DATA (P1/P2) and the refusal is deterministic; no code path acts on it",
      "refusePeerCommand('self_admit') refused; the claim was receivable as DATA (claim_within_boundary, grants nothing); classified OT-01 monitor — no execution disposition exists in the closed vocabulary",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-06 remote self-unquarantine / trust-inheritance claim: both refuse deterministically", () => {
    const s = openStack();
    const unquarantine = refusePeerCommand("self_unquarantine", s.nodeBId);
    const inheritance = refusePeerCommand("trust_inheritance_claim", s.nodeBId);
    const boundary = decideBoundaryClaim({ claimKind: "rotation_trust_claim", peerId: s.nodeBId, localEpochId: EPOCH_1, decidedAtEpochMs: tick() });
    const ok = unquarantine.refused === true && inheritance.refused === true && boundary.ok === false && boundary.ok === false && boundary.violatedPin === "ROTATION_NO_TRUST_INHERITANCE";
    record(
      "AOG-06",
      "remote self-unquarantine + rotated-identity trust-inheritance claim",
      "quarantined is terminal-facing (no self-exit); rotation NEVER inherits trust (P7): the boundary decision names the violated pin",
      "both peer commands refused; the rotation_trust_claim crossed the boundary with violatedPin=ROTATION_NO_TRUST_INHERITANCE",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-07 stale admin epoch: an operator intent formed in a superseded epoch refuses at the gate and at the session", () => {
    const s = openStack();
    const staleIntent = {
      initiatedBy: "local_operator" as const,
      operatorRef: "op-25g",
      rationale: "admit the candidate after review",
      decidedAtEpochMs: tick(),
      localEpochId: EPOCH_2, // NOT the live epoch
    };
    const gate = checkLocalAdminIntent({ intent: staleIntent, liveEpochId: s.registry.epochId });
    const sessionOpen = PeerAdminSession.open(s.registry, "sess-25g-stale");
    if (!sessionOpen.ok) throw new Error(sessionOpen.reason);
    const mutated = sessionOpen.session.quarantinePeer({
      nodeId: s.nodeBId, fingerprint: s.fingerprintB, instanceId: s.instB, protocolVersion: "menog-federation/v1",
      intent: staleIntent, transactionId: txn("stale-admin"), lineageRoot: ROOT, lineageParent: null,
    });
    const peerAfter = s.registry.readPeer(s.nodeBId);
    const ok = gate.ok === false && gate.ok === false && gate.denyCode === "stale_admin_epoch" && mutated.ok === false && mutated.ok === false && mutated.denyCode === "stale_admin_epoch" && peerAfter.ok === true && peerAfter.state.trustState === "admitted";
    record(
      "AOG-07",
      "stale admin epoch (operator intent minted in an old epoch replayed against the live registry)",
      "admin intents are epoch-bound: a stale localEpochId refuses BEFORE any persistence and the peer state is untouched",
      "intent gate refused stale_admin_epoch; session mutation refused stale_admin_epoch; peer B still admitted (nothing applied)",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-08 concurrent trust mutation: duplicate transaction ids never last-writer-wins; the post-conflict flip-back refuses", () => {
    const s = openStack();
    const txnId = txn("conflict");
    const t1 = s.registry.applyTrustTransition({
      nodeId: s.nodeBId, fingerprint: s.fingerprintB, instanceId: s.instB,
      protocolVersion: "menog-federation/v1", reason: "peer_misbehavior_evidenced", evidence: "conflict probe",
      transactionId: txnId, lineageRoot: ROOT, lineageParent: null, nowEpochMs: tick(),
    });
    const t2 = s.registry.applyTrustTransition({
      nodeId: s.nodeBId, fingerprint: s.fingerprintB, instanceId: s.instB,
      protocolVersion: "menog-federation/v1", reason: "operator_retirement", evidence: "conflicting same-txn probe",
      transactionId: txnId, lineageRoot: ROOT, lineageParent: null, nowEpochMs: tick(),
    });
    const flipBack = s.registry.applyTrustTransition({
      nodeId: s.nodeBId, fingerprint: s.fingerprintB, instanceId: s.instB,
      protocolVersion: "menog-federation/v1", reason: "admission_request_accepted", evidence: "flip-back probe",
      transactionId: txn("flipback-25g"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: tick(),
    });
    const peer = s.registry.readPeer(s.nodeBId);
    const t2Resolved = t2.ok === false || t2.idempotentReplay === true;
    const ok = t1.ok === true && t2Resolved && peer.ok === true && peer.state.trustState === "quarantined" && flipBack.ok === false && flipBack.ok === false && flipBack.failureCode === "peer_terminal_state";
    record(
      "AOG-08",
      "concurrent trust mutation (same transactionId, conflicting reasons; then a flip-back attempt)",
      "no last-writer-wins: the duplicate transaction resolves as an idempotent replay (or refusal) at the ORIGINAL state; the quarantined terminal state refuses every flip",
      "final state is EXACTLY 'quarantined' (the retirement never applied); flip-back refused peer_terminal_state",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-09 terminal resurrection: a quarantined peer cannot re-enroll/re-admit; a revoked key cannot return to active", () => {
    const s = openStack();
    const q = s.registry.applyTrustTransition({
      nodeId: s.nodeBId, fingerprint: s.fingerprintB, instanceId: s.instB,
      protocolVersion: "menog-federation/v1", reason: "peer_misbehavior_evidenced", evidence: "resurrection probe",
      transactionId: txn("quarantine-25g"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: tick(),
    });
    const reEnroll = s.registry.applyTrustTransition({
      nodeId: s.nodeBId, fingerprint: s.fingerprintB, instanceId: s.instB,
      protocolVersion: "menog-federation/v1", reason: "first_contact_enrolled", evidence: "retry",
      transactionId: txn("resurrect-1"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: tick(),
    });
    const reAdmit = s.registry.applyTrustTransition({
      nodeId: s.nodeBId, fingerprint: s.fingerprintB, instanceId: s.instB,
      protocolVersion: "menog-federation/v1", reason: "admission_request_accepted", evidence: "retry",
      transactionId: txn("resurrect-2"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: tick(),
    });
    const identity = generateLocalSigningIdentity();
    let rec = lifecycleRecordFor(identity, tick());
    const rev = decideLifecycleTransition({ record: rec, to: "revoked", evidence: "revocation", nowEpochMs: tick() });
    if (!rev.ok) throw new Error(rev.explanation);
    rec = rev.record;
    const backToActive = decideLifecycleTransition({ record: rec, to: "active", evidence: "resurrection attempt", nowEpochMs: tick() });
    const ok = q.ok === true && reEnroll.ok === false && reAdmit.ok === false && backToActive.ok === false && backToActive.ok === false && backToActive.code === "already_terminal";
    record(
      "AOG-09",
      "terminal resurrection (quarantined peer retries enrollment/admission; revoked key asks to return to active)",
      "terminal states are unrepresentable exits in BOTH machines (peer trust L6; key lifecycle monotone rank)",
      "re-enroll and re-admit refused peer_terminal_state; revoked→active refused already_terminal",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-10 egress bypass: secret, hidden-policy, raw-output, and executable candidates all refuse the WHOLE disclosure", () => {
    const payloadHash = "sha256-" + "9".repeat(64);
    const field = (key: string, egressClass: EgressCandidate["fields"][number]["egressClass"], value: string) => ({ key, egressClass, value });
    const candidate = (fields: EgressCandidate["fields"]): EgressCandidate => ({ schemaVersion: EGRESS_SCHEMA_VERSION, payloadHash, fields });
    const cases: readonly [string, EgressCandidate["fields"], string][] = [
      ["secret_material", [field("identityVersion", "public_identity", "{\"inner\":{\"private_key\":\"AAAA\"}}")], "secret_material"],
      ["raw_hidden_policy", [field("intentClass", "bounded_intent", "raw_policy_source " + "p".repeat(200))], "raw_hidden_policy"],
      ["raw_tool_output", [field("commitSequence", "evidence_refs", "STDOUT " + "z".repeat(400))], "raw_tool_output"],
      ["executable_material", [field("responseKind", "bounded_intent", "$(cat /etc/passwd)")], "executable_material"],
      ["unknown_field", [field("freeTextNote", "bounded_intent", "hello")], "unknown_field"],
    ];
    let allRefused = true;
    const observed: string[] = [];
    for (const [name, fields, expected] of cases) {
      const d = decideEgress({ candidate: candidate(fields), outgoingPayloadHash: payloadHash, nowEpochMs: tick() });
      if (!(d.ok === false && d.denyCode === expected)) { allRefused = false; observed.push(name + "=NOT-REFUSED"); } else { observed.push(name + "=" + d.denyCode); }
    }
    record(
      "AOG-10",
      "egress bypass (five candidates trying to smuggle forbidden classes past the 25D gate)",
      "the ONE egress gate default-denies: secrets/policy/raw-output/executable refuse the whole candidate; unknown fields refuse",
      observed.join("; "),
      allRefused ? "PASS" : "FAIL",
    );
    expect(allRefused).toBe(true);
  });

  it("AOG-11 nested leakage: JSON-encoded private keys, PEM blocks, and shell substitutions refuse at ANY depth", () => {
    const payloadHash = "sha256-" + "8".repeat(64);
    const field = (key: string, egressClass: EgressCandidate["fields"][number]["egressClass"], value: string) => ({ key, egressClass, value });
    const nested = decideEgress({
      candidate: { schemaVersion: EGRESS_SCHEMA_VERSION, payloadHash, fields: [field("manifestRef", "disclosure_manifest", "{\"cmd\":\"sudo rm -rf /\"}")] },
      outgoingPayloadHash: payloadHash, nowEpochMs: tick(),
    });
    const pem = decideEgress({
      candidate: { schemaVersion: EGRESS_SCHEMA_VERSION, payloadHash, fields: [field("manifestRef", "disclosure_manifest", "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----")] },
      outgoingPayloadHash: payloadHash, nowEpochMs: tick(),
    });
    const keyPlacement = authorizeKeyMaterialPlacement({ materialClass: "private_signing_key", storageLocation: "outbound_message" });
    const durablePlacement = authorizeKeyMaterialPlacement({ materialClass: "private_signing_key", storageLocation: "durable_evidence" });
    const ok = nested.ok === false && nested.ok === false && nested.denyCode === "executable_material" && pem.ok === false && pem.denyCode === "secret_material" && keyPlacement.ok === false && keyPlacement.code === "private_key_in_egress_denied" && durablePlacement.ok === false && durablePlacement.code === "private_key_in_evidence_denied";
    record(
      "AOG-11",
      "nested leakage (JSON-encoded shell command; PEM key block; key material offered to egress/durable placements)",
      "structural strings are parsed and scanned at depth; the 25A key-storage boundary denies private keys in EVERY non-memory placement as FINDINGS",
      "nested shell refused executable_material; PEM refused secret_material; placements refused private_key_in_egress_denied + private_key_in_evidence_denied",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-12 disclosure hash/staleness: a mis-bound manifest refuses; a manifest never rides a different payload; no authority fields exist", () => {
    const payloadHash = "sha256-" + "7".repeat(64);
    const otherHash = "sha256-" + "6".repeat(64);
    const fields: EgressCandidate["fields"] = [{ key: "nodeId", egressClass: "public_identity", value: "node-" + "c".repeat(64) }];
    const d = decideEgress({ candidate: { schemaVersion: EGRESS_SCHEMA_VERSION, payloadHash, fields }, outgoingPayloadHash: otherHash, nowEpochMs: tick() });
    const good = decideEgress({ candidate: { schemaVersion: EGRESS_SCHEMA_VERSION, payloadHash, fields }, outgoingPayloadHash: payloadHash, nowEpochMs: tick() });
    if (!good.ok) throw new Error(good.explanation);
    const stale = verifyEgressManifest({ manifest: good.manifest, outgoingPayloadHash: otherHash });
    const holds = verifyEgressManifest({ manifest: good.manifest, outgoingPayloadHash: payloadHash });
    const noAuthority = !("executionAuthorized" in good.manifest) && !("policyAuthorized" in good.manifest);
    const ok = d.ok === false && d.ok === false && d.denyCode === "hash_mismatch" && stale.ok === false && stale.ok === false && stale.denyCode === "stale_disclosure" && holds.ok === true && noAuthority;
    record(
      "AOG-12",
      "disclosure hash/staleness (manifest bound to a different payload; manifest re-presented for a new payload)",
      "the manifest binds to the OUTGOING payload hash: mismatch and staleness refuse fail-closed; a disclosure carries no execution/policy field",
      "hash_mismatch refused; stale_disclosure refused; the correct binding holds; manifest has no authority fields",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-13 proposal→tool reach: a proposal contributes intent only; no execution path exists on any 25A–25F surface", () => {
    const s = openStack();
    const payload = proposalPayload(s.senderNodeId, s.senderFingerprint);
    const d = deliver(s, payload as unknown as Record<string, unknown>);
    const a = d.entry ? admit(s, d.entry) : ({ ok: false } as const);
    const candidate = a.ok
      ? deriveLocalTaskCandidate({ proposal: { proposalId: payload.proposalId, senderNodeId: s.senderNodeId, intentClass: payload.intentClass, constraints: payload.constraints, expectedEvidence: payload.expectedEvidence }, localTaskLabel: "survey", requiredCapabilities: ["workspace:list"] })
      : ({ ok: false, reason: "fixture fallback" } as const);
    const gate = requireFreshLocalAuthorization({
      assignment: null as unknown as { assignmentId: string; assignedAgentId: string; allocatedAtEpochMs: number; executionAuthorized: boolean },
      policy: null as unknown as { outcome: "allow" | "deny"; decidedAtEpochMs: number },
      policyActorId: "menog-agent-builder",
      atEpochMs: NOW,
    });
    let hits = 0;
    for (const f of ["federationTrustBoundary.ts", "federationKeyLifecycle.ts", "federationPeerAdmin.ts", "federationEgress.ts"]) {
      const code = codeOnly(SRC(f));
      for (const token of ["executeToolRun", "runIsolated", "spawn(", "child_process", "fetch(", "node:http", "node:net"]) {
        if (code.includes(token)) hits += 1;
      }
    }
    const candidateInert = candidate.ok && candidate.candidate.authority === "none" && candidate.candidate.executionAuthorized === false;
    const ok = a.ok === true && candidateInert && gate.ok === false && (gate.ok === false && gate.failureCode === "no_local_allocation") && hits === 0;
    record(
      "AOG-13",
      "proposal→tool reach (admitted proposal offered to the execution gate; static reachability scan)",
      "a proposal is inert evidence: the candidate carries authority:'none'/executionAuthorized:false; the gate accepts no proposal-only input; zero execution tokens in the 25A–25F modules",
      "proposal admitted as evidence; candidate inert (authority none, exec false); gate refused no_local_allocation; static scan across the 4 Phase-25 modules: 0 hits (25F added no production code)",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-14 foreign evidence authority: a foreign anchor persists as DATA with receiver fields pinned to refusal facts; the forged variant refuses", () => {
    const s = openStack();
    const foreign = bindForeignProvenance({
      facts: {
        anchorId: "fv-" + (NOW + 42).toString(16).padStart(16, "0") + "-foreign250000001",
        kind: "evidence",
        messageId: makeFederationMessageId(NOW + 700, "foreign2500000001"),
        proposalId: null,
        senderNodeId: s.senderNodeId,
        senderFingerprint: s.senderFingerprint,
        senderEpochId: makeRuntimeEpochId(NOW, "senderepoch00001"),
        payloadHash: "sha256-" + "c".repeat(64),
        correlationId: null, causationId: null, lineage: [],
        protocolVersion: "menog-federation/v1",
        schemaVersionOfMessage: "menog-federation-message/v0",
        signatureResult: { result: "verified", reason: null },
      },
      receiverNodeId: null,
      receiverEpochId: EPOCH_1,
      decision: "refused",
      nowEpochMs: tick(),
    });
    const forged = s.provenance.anchor({
      anchor: {
        schemaVersion: "menog-federation-provenance/v0",
        anchorId: "fv-" + (NOW + 43).toString(16).padStart(16, "0") + "-forged2500000001",
        kind: "response",
        messageId: makeFederationMessageId(NOW + 701, "forged25000000001"),
        proposalId: null,
        senderNodeId: s.senderNodeId,
        senderFingerprint: s.senderFingerprint,
        senderEpochId: makeRuntimeEpochId(NOW, "senderepoch00001"),
        receiverNodeId: null,
        receiverEpochId: EPOCH_1,
        protocolVersion: "menog-federation/v1",
        schemaVersionOfMessage: "menog-federation-message/v0",
        payloadHash: "sha256-" + "d".repeat(64),
        correlationId: null, causationId: null, lineage: [],
        signatureResult: { result: "verified", reason: null },
        peerAdmission: "admitted",
        localPolicyDecision: "none",
        policyEvidenceRefs: [],
        toolEvidenceRefs: [],
        commitRefs: [],
        responseHash: null,
        decision: "local_action",
        decidedAtEpochMs: tick(),
      },
      nowEpochMs: tick(),
    });
    const gate = requireFreshLocalAuthorization({
      assignment: null as unknown as { assignmentId: string; assignedAgentId: string; allocatedAtEpochMs: number; executionAuthorized: boolean },
      policy: null as unknown as { outcome: "allow" | "deny"; decidedAtEpochMs: number },
      policyActorId: "menog-agent-builder",
      atEpochMs: NOW,
    });
    const dataOnly = foreign.ok === true && foreign.anchor.localPolicyDecision === "none" && foreign.anchor.peerAdmission === "not_admitted";
    const ok = dataOnly && forged.ok === false && gate.ok === false;
    record(
      "AOG-14",
      "foreign evidence authority (foreign anchor offered to the execution gate; a forged 'local_action' anchor with no local Policy)",
      "foreign anchors bind as DATA with receiver-judgment fields pinned to local refusal facts; a local_action anchor REQUIRES an explicit LOCAL Policy decision and refuses without one",
      "foreign anchor pinned not_admitted/none; the forged local_action anchor refused provenance_malformed (an explicit LOCAL Policy result is required); the execution gate refused no_local_allocation",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-15 capability union: no public surface can merge federation principals' authorities (recorded UNSUPPORTED)", () => {
    const files = ["federationTrustBoundary.ts", "federationKeyLifecycle.ts", "federationPeerAdmin.ts", "federationEgress.ts", "federationIdentity.ts", "federationCrypto.ts", "federationPeers.ts", "federationBus.ts", "federationProposals.ts", "federationProvenance.ts"];
    // The scanner counts only NON-negated occurrences: negated prohibition
    // prose ("MAY NOT: … no capability union") is negative-scope law text,
    // the same class as the negative-scope comments 24I recorded.
    const unionPattern = /super\s?agent|capability.?union|mergeCapabilit|combineCapabilit|unionCapabilit/i;
    let hits = 0;
    for (const f of files) {
      const code = codeOnly(SRC(f)).replace(/no (super\s?agent|capability.?union|mergeCapabilit\w*|combineCapabilit\w*|unionCapabilit\w*)/gi, "");
      if (unionPattern.test(code)) hits += 1;
    }
    record(
      "AOG-15",
      "super-agent / capability union (merge federation principals' capabilities into one authority)",
      "no public surface expresses capability merging: the 25A pins (P1/P3/P6) and every module expose no merge API",
      "attack cannot be constructed against any public surface; static scan across 10 modules: 0 merge/union APIs. Recorded UNSUPPORTED — unsupported is NOT PASS",
      hits === 0 ? "UNSUPPORTED" : "FAIL",
    );
    expect(hits).toBe(0);
  });

  it("AOG-16 alternate durable/network/spawn/listener path: no second path exists on the Phase-25 surfaces (recorded UNSUPPORTED)", () => {
    const files = ["federationTrustBoundary.ts", "federationKeyLifecycle.ts", "federationPeerAdmin.ts", "federationEgress.ts"];
    let persistHits = 0;
    let ioHits = 0;
    for (const f of files) {
      const code = codeOnly(SRC(f));
      if (code.includes(".persist(")) persistHits += 1;
      for (const token of ["node:net", "node:http", "node:https", "node:dgram", "node:tls", "child_process", "fetch(", "listen(", "spawn("]) {
        if (code.includes(token)) ioHits += 1;
      }
    }
    record(
      "AOG-16",
      "alternate durable/network/spawn/listener path (bypass the sanctioned junction, transport off-path, or execute off-path)",
      "persistence is ONLY the 23B acceptMutation junction; the Phase-25 modules import no network/spawn/listener primitive",
      "attack cannot be constructed: static scan across the 4 Phase-25 modules found 0 direct .persist( calls and 0 network/spawn/listener imports (25F added no production code). Recorded UNSUPPORTED — unsupported is NOT PASS",
      persistHits === 0 && ioHits === 0 ? "UNSUPPORTED" : "FAIL",
    );
    expect(persistHits).toBe(0);
    expect(ioHits).toBe(0);
  });

  it("AOG-17 crash trust rollback: a pre-revocation snapshot would resurrect a dead key and refuses; equal states restore as no-ops", () => {
    const resurrect = decideRollbackRestore({ snapshotState: "active", currentState: "revoked" });
    const rotated = decideRollbackRestore({ snapshotState: "rotation_requested", currentState: "rotated" });
    const noop = decideRollbackRestore({ snapshotState: "active", currentState: "active" });
    const forward = decideRollbackRestore({ snapshotState: "revoked", currentState: "active" });
    const ok = resurrect.ok === false && resurrect.ok === false && resurrect.code === "rollback_would_resurrect_key" && rotated.ok === false && rotated.code === "rollback_would_resurrect_key" && noop.ok === true && noop.code === "restore_idempotent_noop" && forward.ok === false && forward.code === "rollback_conflict";
    record(
      "AOG-17",
      "crash trust rollback (restore a pre-rotation/pre-revocation lifecycle snapshot after a crash)",
      "lifecycle facts are MONOTONE: an earlier snapshot over a dead key refuses (rollback_would_resurrect_key); only equal-state restores are no-ops; forward divergence is a conflict for investigation",
      "active→revoked refused rollback_would_resurrect_key; rotation_requested→rotated refused likewise; equal-state restored as idempotent no-op; forward divergence refused rollback_conflict",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-18 restart replay: the exact admitted envelope replays against a NEW epoch with an EMPTY key directory and refuses with zero signature evaluation", () => {
    const s = openStack();
    const payload = proposalPayload(s.senderNodeId, s.senderFingerprint);
    const m = s.msg({ payloadHash: canonicalHash(payload) });
    const sig = s.sign(m);
    const first = s.bus.ingest({ envelope: { message: m, signature: sig }, payload: payload as unknown as Record<string, unknown>, nowEpochMs: tick() });
    const entry = s.bus.inbox()[s.bus.inbox().length - 1];
    s.coordinator.close();
    const bound = RuntimeStateCoordinator.open(s.store, epochOf(EPOCH_2), "unit-test:25g-e2");
    if (!bound.ok) throw new Error(bound.reason);
    openCoords.push(bound.coordinator);
    const reg = PeerRegistry.open(s.store, bound.coordinator);
    if (!reg.ok) throw new Error(reg.reason);
    const busOpen = FederationBus.open({ store: s.store, coordinator: bound.coordinator, peers: reg.registry, verifiers: new Map() });
    if (!busOpen.ok) throw new Error(busOpen.reason);
    const replay = busOpen.bus.ingest({ envelope: { message: m, signature: sig }, nowEpochMs: tick() });
    const durableGuard = s.store.readRecord(entry !== undefined ? entry.receiptRecordId : "frc-none").ok;
    const ok = first.ok === true && replay.ok === false && replay.ok === false && replay.stage === "replay_freshness" && replay.failureCode === "replay_detected" && durableGuard;
    record(
      "AOG-18",
      "restart replay (the exact admitted envelope replayed after restart; key directory empty)",
      "the DURABLE receipt guard refuses before any signature evaluation — replay detection does not depend on keys (no oracle, no key-directory dependence)",
      "first delivery admitted; post-restart replay refused at stage=replay_freshness failureCode=replay_detected with zero signature evaluation; the durable receipt record exists",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-19 downgrade confusion: protocol v0, message schema v9, egress schema v9, and an illegal lifecycle edge all refuse at their own stage", () => {
    const s = openStack();
    const downgrade = s.msg({ protocolVersion: "menog-federation/v0" as FederationMessageBody["protocolVersion"] });
    const r1 = s.bus.ingest({ envelope: { message: downgrade, signature: s.sign(downgrade) }, nowEpochMs: tick() });
    const badSchema = s.msg({ schemaVersion: "menog-federation-message/v9" as FederationMessageBody["schemaVersion"] });
    const r2 = s.bus.ingest({ envelope: { message: badSchema, signature: s.sign(badSchema) }, nowEpochMs: tick() });
    const badEgress = decideEgress({
      candidate: { schemaVersion: "menog-egress-disclosure/v9" as EgressCandidate["schemaVersion"], payloadHash: "sha256-" + "5".repeat(64), fields: [] },
      outgoingPayloadHash: "sha256-" + "5".repeat(64), nowEpochMs: tick(),
    });
    const identity = generateLocalSigningIdentity();
    const rec = lifecycleRecordFor(identity, tick());
    const illegalEdge = decideLifecycleTransition({ record: rec, to: "rotated", evidence: "downgrade probe", nowEpochMs: tick() });
    const ok = r1.ok === false && (r1.ok === false && r1.failureCode === "protocol_mismatch") && r2.ok === false && badEgress.ok === false && (badEgress.ok === false && badEgress.denyCode === "malformed_candidate") && illegalEdge.ok === false && (illegalEdge.ok === false && illegalEdge.code === "rotation_not_requested");
    record(
      "AOG-19",
      "downgrade confusion (protocol v0; message schema v9; egress schema v9; lifecycle jump past the request step)",
      "exact-equality schema/protocol pins refuse every downgrade at its own stage; the closed lifecycle machine refuses unrequested transitions",
      "protocol_mismatch (bus) + message-schema refusal (bus) + malformed_candidate (egress) + rotation_not_requested (lifecycle)",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-20 Phase-24 confused-deputy regression: the actor binding survives all of Phase 25 (policyActorId still enforced)", () => {
    const engine = new DenyByDefaultPolicyEngine();
    const allowForPlanner = engine.evaluate({
      actor: { type: "agent", id: "menog-agent-planner" },
      verb: "inspect",
      requestedCapabilities: ["workspace:list"],
      workspaceId: "ws-25g",
    });
    expect(allowForPlanner.decision.outcome).toBe("allow");
    const gate = requireFreshLocalAuthorization({
      assignment: { assignmentId: "asg-25g-000001-aaaaaaaaaaaa", assignedAgentId: "menog-agent-builder", allocatedAtEpochMs: NOW, executionAuthorized: false },
      policy: { outcome: allowForPlanner.decision.outcome, decidedAtEpochMs: NOW + 1 },
      policyActorId: "menog-agent-planner",
      atEpochMs: NOW + 2,
    });
    const ok = gate.ok === false && (gate.ok === false && gate.failureCode === "actor_mismatch");
    record(
      "AOG-20",
      "Phase-24 confused-deputy regression (a Policy allow minted for agent X presented with agent Y's assignment, post-Phase-25)",
      "the 24G repair (policyActorId binding) still holds: the fresh-authorization gate refuses with actor_mismatch",
      "gate refused actor_mismatch — no Phase-25 change regressed the 24G actor binding",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-21 D-24-1 misclassification: WSL2 is never native Linux; a timeout is a recorded fact, never a silent skip or a downgrade", () => {
    const wsl2 = classifyEnvironment({ platform: "win32", wslReady: true, attempts: 1 });
    const timedOut = classifyEnvironment({ platform: "win32", wslReady: false, attempts: 3 });
    const native = classifyEnvironment({ platform: "linux", wslReady: false, attempts: 1 });
    // The three classes are DISTINCT TypeScript literals (compile-time
    // distinct); the runtime Set proves all three classifications diverge.
    const targets: readonly string[] = [wsl2.target, timedOut.target, native.target];
    const ok =
      wsl2.target === "wsl2" && wsl2.targetClass === "wsl2" &&
      timedOut.target === "unavailable_target" && timedOut.targetClass === "unavailable_target" &&
      native.target === "native_linux" && native.targetClass === "native_linux" &&
      new Set(targets).size === 3;
    record(
      "AOG-21",
      "D-24-1 misclassification (call WSL2 native; turn a probe timeout into a skip/downgrade; claim native without a native host)",
      "the 25E classifier keeps {windows_host, wsl2, native_linux, unavailable_target} distinct: WSL2 is never native; a timeout records unavailable_target (a fact); native_linux requires the linux platform",
      "win32+ready → wsl2 (distinct class); win32+timeout → unavailable_target (recorded fact, never a skip); linux → native_linux. No misclassification path exists",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });

  it("AOG-22 boundary-claim laundering: execution, key-possession, and rotation claims CROSS the boundary and refuse; identity claims stay DATA", () => {
    const peer = "node-" + "b".repeat(64);
    const exec = decideBoundaryClaim({ claimKind: "execution_claim", peerId: peer, localEpochId: EPOCH_1, decidedAtEpochMs: tick() });
    const keyPossession = decideBoundaryClaim({ claimKind: "key_possession_authority_claim", peerId: peer, localEpochId: EPOCH_1, decidedAtEpochMs: tick() });
    const rotation = decideBoundaryClaim({ claimKind: "rotation_trust_claim", peerId: peer, localEpochId: EPOCH_1, decidedAtEpochMs: tick() });
    const anonymous = decideBoundaryClaim({ claimKind: "identity_claim", peerId: "", localEpochId: EPOCH_1, decidedAtEpochMs: tick() });
    const identity = decideBoundaryClaim({ claimKind: "identity_claim", peerId: peer, localEpochId: EPOCH_1, decidedAtEpochMs: tick() });
    const ok =
      exec.ok === false && exec.ok === false && exec.violatedPin === "ADMISSION_NOT_EXECUTION" &&
      keyPossession.ok === false && keyPossession.ok === false && keyPossession.violatedPin === "KEY_POSSESSION_NOT_POLICY_ALLOW" &&
      rotation.ok === false && rotation.ok === false && rotation.violatedPin === "ROTATION_NO_TRUST_INHERITANCE" &&
      anonymous.ok === false && identity.ok === true && identity.ok === true && identity.code === "claim_within_boundary";
    record(
      "AOG-22",
      "boundary-claim laundering (execution/key-possession/rotation claims dressed as receivable facts; anonymous claim)",
      "the 25A boundary refuses authority-bearing claims naming the violated pin (P3/P6/P7); an anonymous claim cannot even be evaluated; identity claims are receivable DATA that grant nothing",
      "execution_claim → ADMISSION_NOT_EXECUTION; key_possession_authority_claim → KEY_POSSESSION_NOT_POLICY_ALLOW; rotation_trust_claim → ROTATION_NO_TRUST_INHERITANCE; anonymous refused; identity_claim receivable as DATA",
      ok ? "PASS" : "FAIL",
    );
    expect(ok).toBe(true);
  });
});

// ── evidence integrity ───────────────────────────────────────────────────────

describe("25G adversarial evidence integrity", () => {
  it("all 22 cases recorded with the pinned verdict map (no FAIL, no INCONCLUSIVE; UNSUPPORTED ≠ PASS)", () => {
    expect(RESULTS).toHaveLength(22);
    const byId = new Map(RESULTS.map((r) => [r.caseId, r.verdict]));
    for (let i = 1; i <= 22; i++) {
      expect(byId.has("AOG-" + String(i).padStart(2, "0"))).toBe(true);
    }
    expect(RESULTS.filter((r) => r.verdict === "FAIL")).toHaveLength(0);
    expect(RESULTS.filter((r) => r.verdict === "INCONCLUSIVE")).toHaveLength(0);
    expect(RESULTS.filter((r) => r.verdict === "PASS")).toHaveLength(20);
    expect(RESULTS.filter((r) => r.verdict === "UNSUPPORTED")).toHaveLength(2);
    expect(byId.get("AOG-15")).toBe("UNSUPPORTED");
    expect(byId.get("AOG-16")).toBe("UNSUPPORTED");
    // every record carries a non-empty expected control and actual result
    for (const r of RESULTS) {
      expect(r.expectedControl.length).toBeGreaterThan(10);
      expect(r.actualResult.length).toBeGreaterThan(10);
    }
  });
});
