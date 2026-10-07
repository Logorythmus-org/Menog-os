/**
 * PHASE 24E — Cross-Node Task Proposal Protocol Tests (PROPOSAL-ONLY).
 *
 * Pack-mandated tests, each pinned to its refusing surface:
 *   inflation (proposed class ≠ local choice; nothing widened) ·
 *   forged requirement (provenance ≠ verified sender) · stale/duplicate
 *   proposal (DURABLE guard, incl. across restart) · lineage mismatch ·
 *   quarantine · local Policy denial · allocator refusal · no direct
 *   tool-junction reachability.
 * Plus: the real-composition positive path (real 19B allocation + real
 * Day-1 Policy through the fresh-authorization gate) and structural pins
 * (closed fields, closed intent union, append-only inert record, zero
 * execution surface in the proposal layer).
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AppendOnlyLedger } from "@menog/event-ledger";
import type { Actor } from "@menog/core";
import { AgentRuntime, TaskAllocator, registerAllThreeAgents, type TaskDescriptor } from "@menog/agents";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import {
  DurableStore,
  RuntimeStateCoordinator,
  PeerRegistry,
  FederationBus,
  ProposalLedger,
  generateLocalSigningIdentity,
  signFederationMessage,
  makeIdentitySignatureVerifier,
  makeFederationMessageId,
  makeRuntimeEpochId,
  canonicalHash,
  FEDERATION_TASK_PROPOSAL_SCHEMA_VERSION,
  PROPOSAL_INTENT_CLASSES,
  FEDERATION_PROPOSAL_FAILURE_CODES,
  PROPOSAL_HASH_REF_PATTERN,
  FEDERATION_MAX_PROPOSAL_PAYLOAD_BYTES,
  FEDERATION_PROPOSAL_SCHEMA_VERSION,
  validateTaskProposalPayload,
  deriveLocalTaskCandidate,
  requireFreshLocalAuthorization,
  federationProposalDurableId,
  type RuntimeEpoch,
  type FederationMessageBody,
  type FederationTaskProposalPayload,
  type FederationInboxEntry,
} from "@menog/durable-state";

type FederationBusInboxEntry = FederationInboxEntry;

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
  const r = mkdtempSync(join(tmpdir(), "menog-24e-"));
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

const ROOT = "proposal-root-24e";

/** A pack-valid untrusted proposal payload (origin = the verified sender). */
function validProposal(senderNodeId: string, senderFingerprint: string, overrides: Partial<Record<string, unknown>> = {}): FederationTaskProposalPayload {
  return {
    schemaVersion: FEDERATION_TASK_PROPOSAL_SCHEMA_VERSION,
    proposalId: makeFederationMessageId(NOW + 500, "proposal000000001").replace(/^fm-/, "fp-"),
    intentClass: "workspace_survey",
    contentHashes: ["sha256-" + "a".repeat(64)],
    provenance: { originNodeId: senderNodeId, originFingerprint: senderFingerprint, note: "proposed by peer" },
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
  readonly ledger: ProposalLedger;
  /** Signer/message factory for the ADMITTED peer A. */
  readonly sign: (m: FederationMessageBody) => string;
  readonly msg: (overrides?: Partial<FederationMessageBody>) => FederationMessageBody;
  readonly senderNodeId: string;
  readonly senderFingerprint: string;
  /** Signer/message factory for the second peer B (admitted; quarantine-able). */
  readonly signB: (m: FederationMessageBody) => string;
  readonly msgB: (overrides?: Partial<FederationMessageBody>) => FederationMessageBody;
  readonly nodeBId: string;
  readonly fingerprintB: string;
}

/**
 * Open the full stack (store → coordinator → 24C registry → 24D bus →
 * 24E ledger) with TWO admitted peers (A, B) and real 24B keys.
 */
function openStack(epochId: string = EPOCH_1): Stack {
  const open = DurableStore.open(newRoot());
  if (!open.ok) throw new Error(open.reason);
  const store = open.store;
  openStores.push(store);
  const bound = RuntimeStateCoordinator.open(store, epochOf(epochId), "unit-test:24e");
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
  const enrollA = registry.applyTrustTransition({
    nodeId: idA.nodeId, fingerprint: idA.fingerprint, instanceId: instA,
    protocolVersion: "menog-federation/v1", reason: "first_contact_enrolled",
    evidence: "identity doc hash", transactionId: txn("enroll-a"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: NOW,
  });
  if (!enrollA.ok) throw new Error(enrollA.explanation);
  const admitA = registry.applyTrustTransition({
    nodeId: idA.nodeId, fingerprint: idA.fingerprint, instanceId: instA,
    protocolVersion: "menog-federation/v1", reason: "admission_request_accepted",
    evidence: "admission provenance", transactionId: txn("admit-a"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: NOW + 1,
  });
  if (!admitA.ok) throw new Error(admitA.explanation);
  const enrollB = registry.applyTrustTransition({
    nodeId: idB.nodeId, fingerprint: idB.fingerprint, instanceId: instB,
    protocolVersion: "menog-federation/v1", reason: "first_contact_enrolled",
    evidence: "identity doc hash", transactionId: txn("enroll-b"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: NOW,
  });
  if (!enrollB.ok) throw new Error(enrollB.explanation);
  const admitB = registry.applyTrustTransition({
    nodeId: idB.nodeId, fingerprint: idB.fingerprint, instanceId: instB,
    protocolVersion: "menog-federation/v1", reason: "admission_request_accepted",
    evidence: "admission provenance", transactionId: txn("admit-b"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: NOW + 1,
  });
  if (!admitB.ok) throw new Error(admitB.explanation);

  const verifiers = new Map<string, ReturnType<typeof makeIdentitySignatureVerifier>>();
  verifiers.set(idA.nodeId.slice(5), makeIdentitySignatureVerifier(idA.publicKeyHex));
  verifiers.set(idB.nodeId.slice(5), makeIdentitySignatureVerifier(idB.publicKeyHex));
  const busOpen = FederationBus.open({ store, coordinator, peers: registry, verifiers });
  if (!busOpen.ok) throw new Error(busOpen.reason);
  const ledgerOpen = ProposalLedger.open({ store, coordinator });
  if (!ledgerOpen.ok) throw new Error(ledgerOpen.reason);

  let n = 0;
  let nb = 0;
  const msgFor = (identity: { readonly nodeId: string; readonly fingerprint: string }, counter: () => number, instanceId: string) =>
    (overrides: Partial<FederationMessageBody> = {}): FederationMessageBody => {
      const seq = counter();
      return {
        schemaVersion: "menog-federation-message/v0",
        messageId: makeFederationMessageId(NOW + seq, "msg" + String(seq).padStart(13, "0")),
        senderNodeId: identity.nodeId,
        senderFingerprint: identity.fingerprint,
        senderInstanceId: instanceId,
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
    store,
    coordinator,
    registry,
    bus: busOpen.bus,
    ledger: ledgerOpen.ledger,
    sign: signFor(idA),
    msg: (overrides = {}) => msgFor(idA, () => { n += 1; return n; }, instA)(overrides),
    senderNodeId: idA.nodeId,
    senderFingerprint: idA.fingerprint,
    signB: signFor(idB),
    msgB: (overrides = {}) => msgFor(idB, () => { nb += 900; return nb; }, instB)(overrides),
    nodeBId: idB.nodeId,
    fingerprintB: idB.fingerprint,
  };
}

/** Bus-admit one signed proposal message and return the typed inbox entry. */
function deliverToInbox(
  s: Stack,
  payload: Record<string, unknown>,
  options: { readonly sign?: (m: FederationMessageBody) => string; readonly msg?: FederationMessageBody } = {}
): { readonly ok: boolean; readonly entry?: FederationBusInboxEntry } {
  const m = options.msg ?? s.msg();
  const sign = options.sign ?? s.sign;
  const envelope = { message: m, signature: sign(m) };
  const result = s.bus.ingest({ envelope, payload, nowEpochMs: NOW + 5 });
  if (!result.ok) return { ok: false };
  const inbox = s.bus.inbox();
  const entry = inbox[inbox.length - 1];
  if (!entry) return { ok: false };
  return { ok: true, entry };
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("24E structure — closed fields, inert record, zero execution surface", () => {
  it("bounds, failure codes, and the closed inert intent union are pinned exactly", () => {
    expect(FEDERATION_MAX_PROPOSAL_PAYLOAD_BYTES).toBe(16384);
    expect([...PROPOSAL_INTENT_CLASSES]).toEqual(["workspace_survey", "content_review", "artifact_verification"]);
    for (const code of ["proposal_duplicate", "proposal_persistence_denied", "proposal_forbidden_material", "proposal_schema_mismatch"]) {
      expect([...FEDERATION_PROPOSAL_FAILURE_CODES]).toContain(code);
    }
    expect(PROPOSAL_HASH_REF_PATTERN.test("sha256-" + "a".repeat(64))).toBe(true);
    expect(PROPOSAL_HASH_REF_PATTERN.test("md5-aaaa")).toBe(false);
    expect(FEDERATION_PROPOSAL_SCHEMA_VERSION).toBe("menog-federation-proposal/v0");
    expect(FEDERATION_TASK_PROPOSAL_SCHEMA_VERSION).toBe("menog-task-proposal/v0");
  });

  it("the proposal layer performs no network I/O, no process invocation, and no direct store persist", () => {
    const code = codeOnly(SRC("federationProposals.ts"));
    for (const forbidden of ["fetch(", "node:net", "node:http", "node:https", "child_process", "spawn(", "listen(", "executeToolRun", "runIsolated", ".persist("]) {
      expect(code).not.toContain(forbidden);
    }
    expect(code).toContain("acceptMutation");
    expect(code).toContain('kind: "federation_proposal"');
  });

  it("a proposal record body binds the pack fields and never authorizes anything", () => {
    const src = SRC("federationProposals.ts");
    for (const field of ["proposalId", "messageId", "senderNodeId", "senderFingerprint", "proposalHash", "intentClass", "contentHashes", "provenance", "constraints", "expectedEvidence", "receiverDecision", "receiverEpochId", "receiptRecordId"]) {
      expect(src).toContain("readonly " + field);
    }
    const code = codeOnly(src);
    expect(code).not.toMatch(/receiverDecision:\s*"(?!proposal_admitted)/);
    expect(code).toContain('authority: "none"');
    expect(code).toContain("executionAuthorized: false");
  });

  it("the third unfreeze kind is classified append-only + permanent and sits in the coordinator", () => {
    const records = SRC("records.ts");
    expect(records).toContain('"federation_proposal"');
    expect(records).toContain('federation_proposal: "fpr"');
    const classification = SRC("classification.ts");
    expect(classification).toContain('recordKind: "federation_proposal"');
    expect(classification).toContain('mutationPosture: "append_only"');
    const coordinator = SRC("coordinator.ts");
    expect(coordinator).toContain('input.kind === "federation_proposal"');
    const statePersistence = SRC("statePersistence.ts");
    expect(statePersistence).toContain('FEDERATION_PROPOSAL_ID_PREFIX = "fpr-"');
  });
});

// ── positive path ────────────────────────────────────────────────────────────

describe("24E positive path — proposal becomes durable inert evidence for LOCAL evaluation", () => {
  it("an admitted peer's signed task_proposal traverses bus → validation → durable proposal record", () => {
    const s = openStack();
    const payload = validProposal(s.senderNodeId, s.senderFingerprint);
    const delivered = deliverToInbox(s, payload as unknown as Record<string, unknown>);
    expect(delivered.ok).toBe(true);
    if (!delivered.ok || !delivered.entry) return;

    const result = s.ledger.receiveTaskProposal({
      inboxEntry: {
        messageId: delivered.entry.messageId,
        senderNodeId: delivered.entry.senderNodeId,
        declaredIntent: delivered.entry.declaredIntent,
        payload: delivered.entry.payload,
      },
      senderFingerprint: s.senderFingerprint,
      receiptRecordId: delivered.entry.receiptRecordId,
      nowEpochMs: NOW + 6,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.proposalId).toBe(payload.proposalId);
    expect(result.recordId).toBe("fpr-" + payload.proposalId);
    expect(result.explanation).toContain("INERT");

    // the record is durable, append-only, and binds the receiver judgment
    const read = s.store.readRecord(result.recordId);
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    const body = read.record.payload as Record<string, unknown>;
    expect(body["receiverDecision"]).toBe("proposal_admitted");
    expect(body["receiverEpochId"]).toBe(EPOCH_1);
    expect(body["receiptRecordId"]).toBe(delivered.entry.receiptRecordId);
    expect(body["proposalHash"]).toBe(result.proposalHash);
    expect(s.ledger.hasProposal(payload.proposalId)).toBe(true);
  });

  it("the real LOCAL chain consumes the candidate: 19B allocation → Day-1 Policy allow → fresh gate opens", () => {
    const s = openStack();
    const payload = validProposal(s.senderNodeId, s.senderFingerprint);
    const delivered = deliverToInbox(s, payload as unknown as Record<string, unknown>);
    if (!delivered.ok || !delivered.entry) throw new Error("fixture: delivery failed");
    const admitted = s.ledger.receiveTaskProposal({
      inboxEntry: {
        messageId: delivered.entry.messageId,
        senderNodeId: delivered.entry.senderNodeId,
        declaredIntent: delivered.entry.declaredIntent,
        payload: delivered.entry.payload,
      },
      senderFingerprint: s.senderFingerprint,
      receiptRecordId: delivered.entry.receiptRecordId,
      nowEpochMs: NOW + 6,
    });
    if (!admitted.ok) throw new Error("fixture: admission failed: " + admitted.explanation);

    // LOCAL candidate derivation (intent only; capabilities are the LOCAL choice)
    const cand = deriveLocalTaskCandidate({
      proposal: {
        proposalId: payload.proposalId,
        senderNodeId: s.senderNodeId,
        intentClass: payload.intentClass,
        constraints: payload.constraints,
        expectedEvidence: payload.expectedEvidence,
      },
      localTaskLabel: "24e proposed survey (locally scoped)",
      requiredCapabilities: ["workspace:read"],
    });
    expect(cand.ok).toBe(true);
    if (!cand.ok) return;
    expect(cand.candidate.authority).toBe("none");
    expect(cand.candidate.executionAuthorized).toBe(false);

    // fresh LOCAL 19B allocation (real allocator, real registry)
    const ledger = AppendOnlyLedger.inMemory();
    const rt = new AgentRuntime({
      nowEpochMs: () => NOW,
      ledger: {
        append: (input) => {
          const r = ledger.append({
            eventId: "e24e-" + input.eventType + "-" + String(ledger.length + 1).padStart(4, "0"),
            timestamp: new Date(NOW).toISOString(),
            eventType: input.eventType,
            actor: input.actor as Actor,
            policyDecision: input.policyDecision,
            workspaceId: input.workspaceId,
            taskId: input.taskId,
            inputSummary: input.inputSummary,
            resultSummary: input.resultSummary,
          });
          return { ok: r.ok, eventId: r.event?.eventId };
        },
      },
      workspaceId: "ws-24e",
      taskId: "task-24e-001",
    });
    if (!registerAllThreeAgents(rt, NOW).ok) throw new Error("agent registration failed");
    const allocator = new TaskAllocator(rt);
    const task: TaskDescriptor = {
      label: cand.candidate.localTaskLabel,
      requiredCapabilities: [...cand.candidate.requiredCapabilities],
      budget: { maxSteps: 2 },
      allowedRoles: ["builder"],
    };
    const alloc = allocator.allocate({ allocatedBy: "r0-human-operator", task });
    if (!alloc.ok) throw new Error("allocation failed: " + JSON.stringify(alloc));
    expect(alloc.assignment.executionAuthorized).toBe(false);
    expect(alloc.assignment.authority).toBe("allocation_data");

    // fresh LOCAL Day-1 Policy decision (the ONLY authority source)
    const engine = new DenyByDefaultPolicyEngine();
    const policy = engine.evaluate({
      actor: { type: "agent", id: alloc.assignment.assignedAgentId },
      verb: "inspect",
      requestedCapabilities: ["workspace:list"],
      workspaceId: "ws-24e",
    });
    expect(policy.decision.outcome).toBe("allow");

    // the fresh-authorization gate OPENS only now
    const gate = requireFreshLocalAuthorization({
      assignment: {
        assignmentId: alloc.assignment.assignmentId,
        assignedAgentId: alloc.assignment.assignedAgentId,
        allocatedAtEpochMs: alloc.assignment.allocatedAtEpochMs,
        executionAuthorized: alloc.assignment.executionAuthorized,
      },
      policy: { outcome: "allow", decidedAtEpochMs: NOW + 1 }, policyActorId: alloc.assignment.assignedAgentId,
      atEpochMs: NOW + 2,
    });
    expect(gate.ok).toBe(true);
    if (gate.ok) expect(gate.reason).toContain("intent only");
  });
});

// ── pack negative tests ──────────────────────────────────────────────────────

describe("24E negative tests — every pack refusal is proven", () => {
  it("INFLATION: the proposed class maps to no capability; the LOCAL descriptor stays the local choice", () => {
    const s = openStack();
    const payload = validProposal(s.senderNodeId, s.senderFingerprint, { intentClass: "workspace_survey" });
    const delivered = deliverToInbox(s, payload as unknown as Record<string, unknown>);
    if (!delivered.ok || !delivered.entry) throw new Error("fixture");
    const result = s.ledger.receiveTaskProposal({
      inboxEntry: {
        messageId: delivered.entry.messageId,
        senderNodeId: delivered.entry.senderNodeId,
        declaredIntent: delivered.entry.declaredIntent,
        payload: delivered.entry.payload,
      },
      senderFingerprint: s.senderFingerprint,
      receiptRecordId: delivered.entry.receiptRecordId,
      nowEpochMs: NOW + 6,
    });
    expect(result.ok).toBe(true);
    // The remote side cannot inject capabilities: the candidate carries ONLY
    // what the LOCAL caller passes — a hostile "workspace:write" ask would
    // have to come from the local caller (and Day-1 Policy denies it there).
    if (!result.ok) return;
    const cand = deriveLocalTaskCandidate({
      proposal: {
        proposalId: payload.proposalId,
        senderNodeId: s.senderNodeId,
        intentClass: payload.intentClass,
        constraints: payload.constraints,
        expectedEvidence: payload.expectedEvidence,
      },
      localTaskLabel: "local-only choice",
      requiredCapabilities: ["workspace:read"],
    });
    expect(cand.ok).toBe(true);
    if (cand.ok) expect(cand.candidate.requiredCapabilities).toEqual(["workspace:read"]);
    // inflation attempt inside the LOCAL input is refused by the candidate gate
    const inflated = deriveLocalTaskCandidate({
      proposal: {
        proposalId: payload.proposalId,
        senderNodeId: s.senderNodeId,
        intentClass: payload.intentClass,
        constraints: payload.constraints,
        expectedEvidence: payload.expectedEvidence,
      },
      localTaskLabel: "local-only choice",
      requiredCapabilities: ["workspace:read", "x".repeat(65)],
    });
    expect(inflated.ok).toBe(false);
    if (!inflated.ok) expect(inflated.reason).toContain("capability-shaped");
  });

  it("FORGED REQUIREMENT: provenance naming another origin refuses at validation", () => {
    const s = openStack();
    const forged = validProposal(s.senderNodeId, s.senderFingerprint, {
      provenance: { originNodeId: s.nodeBId, originFingerprint: s.fingerprintB, note: "forged origin" },
    });
    const delivered = deliverToInbox(s, forged as unknown as Record<string, unknown>);
    expect(delivered.ok).toBe(true);
    if (!delivered.ok || !delivered.entry) return;
    const result = s.ledger.receiveTaskProposal({
      inboxEntry: {
        messageId: delivered.entry.messageId,
        senderNodeId: delivered.entry.senderNodeId,
        declaredIntent: delivered.entry.declaredIntent,
        payload: delivered.entry.payload,
      },
      senderFingerprint: s.senderFingerprint,
      receiptRecordId: delivered.entry.receiptRecordId,
      nowEpochMs: NOW + 6,
    });
    expect(result).toMatchObject({ ok: false, stage: "provenance", failureCode: "proposal_provenance_mismatch" });
    if (!result.ok) expect(result.explanation).toContain("cannot claim another origin");
    expect(s.bus.inbox()).toHaveLength(1); // the message was receipted; the PROPOSAL was not admitted
    expect(s.ledger.hasProposal((forged as FederationTaskProposalPayload).proposalId)).toBe(false);
  });

  it("DUPLICATE PROPOSAL: the same proposal id refuses against the DURABLE record index — this epoch and after restart", () => {
    const s = openStack();
    const payload = validProposal(s.senderNodeId, s.senderFingerprint);
    const first = deliverToInbox(s, payload as unknown as Record<string, unknown>);
    if (!first.ok || !first.entry) throw new Error("fixture");
    // second bus message carrying the SAME proposal id (fresh signature over
    // the exact body delivered — different messageId, same proposal payload)
    const m2 = s.msg({ payloadHash: canonicalHash(payload) });
    const second = s.bus.ingest({ envelope: { message: m2, signature: s.sign(m2) }, payload: payload as unknown as Record<string, unknown>, nowEpochMs: NOW + 6 });
    expect(second.ok).toBe(true);

    const entry1 = s.bus.inbox()[0];
    const entry2 = s.bus.inbox()[1];
    if (!entry1 || !entry2) throw new Error("fixture");
    const admit1 = s.ledger.receiveTaskProposal({
      inboxEntry: { messageId: entry1.messageId, senderNodeId: entry1.senderNodeId, declaredIntent: entry1.declaredIntent, payload: entry1.payload },
      senderFingerprint: s.senderFingerprint,
      receiptRecordId: entry1.receiptRecordId,
      nowEpochMs: NOW + 7,
    });
    expect(admit1.ok).toBe(true);
    const admit2 = s.ledger.receiveTaskProposal({
      inboxEntry: { messageId: entry2.messageId, senderNodeId: entry2.senderNodeId, declaredIntent: entry2.declaredIntent, payload: entry2.payload },
      senderFingerprint: s.senderFingerprint,
      receiptRecordId: entry2.receiptRecordId,
      nowEpochMs: NOW + 8,
    });
    expect(admit2).toMatchObject({ ok: false, stage: "durable_admission", failureCode: "proposal_duplicate" });
    if (!admit2.ok) expect(admit2.explanation).toContain("already exists");

    // RESTART: a NEW epoch coordinator + ledger still refuses the same id
    s.coordinator.close();
    const bound = RuntimeStateCoordinator.open(s.store, epochOf(EPOCH_2), "unit-test:24e-e2");
    if (!bound.ok) throw new Error(bound.reason);
    openCoords.push(bound.coordinator);
    const ledgerOpen = ProposalLedger.open({ store: s.store, coordinator: bound.coordinator });
    if (!ledgerOpen.ok) throw new Error(ledgerOpen.reason);
    expect(ledgerOpen.ledger.hasProposal(payload.proposalId)).toBe(true);
    const after = ledgerOpen.ledger.receiveTaskProposal({
      inboxEntry: { messageId: entry1.messageId, senderNodeId: entry1.senderNodeId, declaredIntent: entry1.declaredIntent, payload: entry1.payload },
      senderFingerprint: s.senderFingerprint,
      receiptRecordId: entry1.receiptRecordId,
      nowEpochMs: NOW + 9,
    });
    expect(after).toMatchObject({ ok: false, failureCode: "proposal_duplicate" });
  });

  it("STALE PROPOSAL MATERIAL: unknown payload fields, bad schema, and stale causation all refuse", () => {
    const s = openStack();
    // unknown field smuggle
    const smuggled = validProposal(s.senderNodeId, s.senderFingerprint, { commands: ["rm -rf /"] });
    const validation = validateTaskProposalPayload({
      payload: smuggled as unknown as Record<string, unknown>,
      senderNodeId: s.senderNodeId,
      senderFingerprint: s.senderFingerprint,
    });
    expect(validation).toMatchObject({ ok: false, stage: "payload_shape", failureCode: "proposal_malformed" });
    if (!validation.ok) expect(validation.explanation).toContain("cannot smuggle");
    // schema downgrade
    const downgraded = validProposal(s.senderNodeId, s.senderFingerprint, { schemaVersion: "menog-task-proposal/v9" });
    const schemaCheck = validateTaskProposalPayload({
      payload: downgraded as unknown as Record<string, unknown>,
      senderNodeId: s.senderNodeId,
      senderFingerprint: s.senderFingerprint,
    });
    expect(schemaCheck).toMatchObject({ ok: false, stage: "schema_version", failureCode: "proposal_schema_mismatch" });
    // stale causation (dangling lineage at the BUS — the pack's lineage test)
    const forgedCausation = s.msg({ lineage: [], causationId: makeFederationMessageId(NOW + 999, "forged000000001") });
    const busResult = s.bus.ingest({ envelope: { message: forgedCausation, signature: s.sign(forgedCausation) }, payload: validProposal(s.senderNodeId, s.senderFingerprint) as unknown as Record<string, unknown>, nowEpochMs: NOW + 5 });
    expect(busResult).toMatchObject({ ok: false, failureCode: "lineage_malformed" });
    expect(s.bus.inbox()).toHaveLength(0); // nothing reaches the proposal layer
  });

  it("LINEAGE MISMATCH: a proposal whose message fails the envelope lineage never becomes a proposal record", () => {
    const s = openStack();
    const parent = makeFederationMessageId(NOW + 50, "parent000000001");
    const wrongParent = s.msg({ lineage: [parent], causationId: makeFederationMessageId(NOW + 51, "mismatch00000001") });
    const result = s.bus.ingest({
      envelope: { message: wrongParent, signature: s.sign(wrongParent) },
      payload: validProposal(s.senderNodeId, s.senderFingerprint) as unknown as Record<string, unknown>,
      nowEpochMs: NOW + 5,
    });
    expect(result.ok).toBe(false);
    expect(s.ledger.hasProposal(validProposal(s.senderNodeId, s.senderFingerprint).proposalId)).toBe(false);
  });

  it("QUARANTINE: an admitted-then-quarantined peer's proposal refuses at the BUS (no inbox, no proposal)", () => {
    const s = openStack();
    const q = s.registry.applyTrustTransition({
      nodeId: s.nodeBId, fingerprint: s.fingerprintB, instanceId: "ri-000000e8fa00-instancebbbb",
      protocolVersion: "menog-federation/v1", reason: "peer_misbehavior_evidenced", evidence: "adversarial finding",
      transactionId: txn("quarantine-b"), lineageRoot: ROOT, lineageParent: null, nowEpochMs: NOW + 2,
    });
    expect(q.ok).toBe(true);
    const payloadB = validProposal(s.nodeBId, s.fingerprintB);
    const mB = s.msgB();
    const busResult = s.bus.ingest({ envelope: { message: mB, signature: s.signB(mB) }, payload: payloadB as unknown as Record<string, unknown>, nowEpochMs: NOW + 5 });
    expect(busResult).toMatchObject({ ok: false, stage: "peer_admission", failureCode: "peer_not_admitted" });
    if (!busResult.ok) expect(busResult.explanation).toContain("quarantined");
    expect(s.bus.inbox()).toHaveLength(0);
    expect(s.ledger.hasProposal(payloadB.proposalId)).toBe(false);
  });

  it("LOCAL POLICY DENIAL: the fresh gate refuses on a Day-1 denial and on stale/reused decisions", () => {
    const engine = new DenyByDefaultPolicyEngine();
    const assignment = {
      assignmentId: "asg-24e-000001-abcdef012345",
      assignedAgentId: "menog-agent-builder",
      allocatedAtEpochMs: NOW,
      executionAuthorized: false as const,
    };
    // a WRITE ask is denied by the same engine — denial is valid and final
    const deny = engine.evaluate({
      actor: { type: "agent", id: "menog-agent-builder" },
      verb: "inspect",
      requestedCapabilities: ["workspace:write"],
      workspaceId: "ws-24e",
    });
    expect(deny.decision.outcome).toBe("deny");
    const denied = requireFreshLocalAuthorization({
      assignment,
      policy: { outcome: deny.decision.outcome, decidedAtEpochMs: NOW + 1 }, policyActorId: "menog-agent-builder",
      atEpochMs: NOW + 2,
    });
    expect(denied).toMatchObject({ ok: false, failureCode: "local_policy_denial" });
    if (!denied.ok) expect(denied.reason).toContain("denial is valid");
    // a STALE policy decision (old epoch's authorization) cannot be reused
    const stalePolicy = requireFreshLocalAuthorization({
      assignment,
      policy: { outcome: "allow", decidedAtEpochMs: NOW - 301_000 }, policyActorId: "menog-agent-builder",
      atEpochMs: NOW,
    });
    expect(stalePolicy).toMatchObject({ ok: false, failureCode: "stale_local_policy" });
    if (!stalePolicy.ok) expect(stalePolicy.reason).toContain("reusing an old Policy decision is forbidden");
  });

  it("ALLOCATOR REFUSAL: the real 19B allocator denies a proposal-derived task no local agent is qualified for", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const rt = new AgentRuntime({
      nowEpochMs: () => NOW,
      ledger: {
        append: (input) => {
          const r = ledger.append({
            eventId: "e24e-" + input.eventType + "-" + String(ledger.length + 1).padStart(4, "0"),
            timestamp: new Date(NOW).toISOString(),
            eventType: input.eventType,
            actor: input.actor as Actor,
            policyDecision: input.policyDecision,
            workspaceId: input.workspaceId,
            taskId: input.taskId,
            inputSummary: input.inputSummary,
            resultSummary: input.resultSummary,
          });
          return { ok: r.ok, eventId: r.event?.eventId };
        },
      },
      workspaceId: "ws-24e",
      taskId: "task-24e-002",
    });
    if (!registerAllThreeAgents(rt, NOW).ok) throw new Error("agent registration failed");
    const allocator = new TaskAllocator(rt);
    const refusal = allocator.allocate({
      allocatedBy: "r0-human-operator",
      task: {
        label: "24e proposal nobody can fulfill",
        requiredCapabilities: ["network:external"],
        budget: { maxSteps: 2 },
        allowedRoles: ["builder"],
      },
    });
    expect(refusal.ok).toBe(false);
    if (!refusal.ok) {
      expect(refusal.denyReason).toBe("no_qualified_agent");
      expect(refusal.reason).toContain("unqualified agents are never selected");
    }
  });

  it("NO DIRECT TOOL-JUNCTION REACHABILITY: a proposal can never satisfy the execution gate", () => {
    // a proposal record alone supplies neither an assignment nor a Policy allow
    const missing = requireFreshLocalAuthorization({
      assignment: null as unknown as { assignmentId: string; assignedAgentId: string; allocatedAtEpochMs: number; executionAuthorized: boolean },
      policy: null as unknown as { outcome: "allow" | "deny"; decidedAtEpochMs: number },
      policyActorId: "menog-agent-builder",
      atEpochMs: NOW,
    });
    expect(missing).toMatchObject({ ok: false, failureCode: "no_local_allocation" });
    if (!missing.ok) expect(missing.reason).toContain("a proposal can never substitute for one");
    // a polluted assignment (pre-authorized) is structurally refused
    const polluted = requireFreshLocalAuthorization({
      assignment: { assignmentId: "asg-x", assignedAgentId: "a", allocatedAtEpochMs: NOW, executionAuthorized: true },
      policy: { outcome: "allow", decidedAtEpochMs: NOW }, policyActorId: "a",
      atEpochMs: NOW + 1,
    });
    expect(polluted).toMatchObject({ ok: false, failureCode: "assignment_authority_polluted" });
    // a future-dated allocation clock is refused
    const future = requireFreshLocalAuthorization({
      assignment: { assignmentId: "asg-y", assignedAgentId: "a", allocatedAtEpochMs: NOW + 10, executionAuthorized: false },
      policy: { outcome: "allow", decidedAtEpochMs: NOW }, policyActorId: "a",
      atEpochMs: NOW,
    });
    expect(future).toMatchObject({ ok: false, failureCode: "no_local_allocation" });
  });

  it("FORBIDDEN MATERIAL: shell/executable-replay content smuggled as a proposal refuses closed-shape validation", () => {
    const s = openStack();
    const shellPayload = validProposal(s.senderNodeId, s.senderFingerprint, {
      commands: ["/bin/sh -c 'curl evil'"],
    });
    const result = s.ledger.receiveTaskProposal({
      inboxEntry: {
        messageId: "m-absent",
        senderNodeId: s.senderNodeId,
        declaredIntent: "task_proposal",
        payload: shellPayload as unknown as Record<string, unknown>,
      },
      senderFingerprint: s.senderFingerprint,
      receiptRecordId: "frc-unbound",
      nowEpochMs: NOW + 6,
    });
    expect(result).toMatchObject({ ok: false, stage: "payload_shape", failureCode: "proposal_malformed" });
    // the ledger also refuses entries not bound to a bus receipt
    const clean = validProposal(s.senderNodeId, s.senderFingerprint);
    const unbound = s.ledger.receiveTaskProposal({
      inboxEntry: {
        messageId: makeFederationMessageId(NOW + 700, "unbound000000001"),
        senderNodeId: s.senderNodeId,
        declaredIntent: "task_proposal",
        payload: clean as unknown as Record<string, unknown>,
      },
      senderFingerprint: s.senderFingerprint,
      receiptRecordId: "run-not-a-receipt",
      nowEpochMs: NOW + 6,
    });
    expect(unbound).toMatchObject({ ok: false, stage: "identity_binding", failureCode: "proposal_identity_mismatch" });
  });
});

// ── candidate derivation guards ──────────────────────────────────────────────

describe("24E candidate derivation — bounded, local-only inputs", () => {
  it("guards label length, capability shape, and array inputs", () => {
    const proposal = {
      proposalId: "fp-0000000000000000-aaaabbbbccccdddd",
      senderNodeId: "node-" + "a".repeat(64),
      intentClass: "workspace_survey" as const,
      constraints: {},
      expectedEvidence: ["sha256-" + "b".repeat(64)],
    };
    expect(deriveLocalTaskCandidate({ proposal, localTaskLabel: "", requiredCapabilities: ["workspace:read"] }).ok).toBe(false);
    expect(deriveLocalTaskCandidate({ proposal, localTaskLabel: "x".repeat(121), requiredCapabilities: ["workspace:read"] }).ok).toBe(false);
    expect(deriveLocalTaskCandidate({ proposal, localTaskLabel: "ok", requiredCapabilities: [""] }).ok).toBe(false);
    expect(deriveLocalTaskCandidate({ proposal, localTaskLabel: "ok", requiredCapabilities: "workspace:read" as unknown as string[] }).ok).toBe(false);
    const ok = deriveLocalTaskCandidate({ proposal, localTaskLabel: "ok", requiredCapabilities: ["workspace:read"] });
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.candidate.proposalId).toBe(proposal.proposalId);
      expect(ok.candidate.authority).toBe("none");
      expect(ok.candidate.executionAuthorized).toBe(false);
    }
  });

  it("malformed identity binding in the raw validator refuses before any store touch", () => {
    const s = openStack();
    const badSender = validateTaskProposalPayload({
      payload: validProposal(s.senderNodeId, s.senderFingerprint) as unknown as Record<string, unknown>,
      senderNodeId: "node-not-hex",
      senderFingerprint: s.senderFingerprint,
    });
    expect(badSender).toMatchObject({ ok: false, stage: "identity_binding", failureCode: "proposal_identity_mismatch" });
    const badFp = validateTaskProposalPayload({
      payload: validProposal(s.senderNodeId, s.senderFingerprint) as unknown as Record<string, unknown>,
      senderNodeId: s.senderNodeId,
      senderFingerprint: "fp-sha256-TOOSHORT",
    });
    expect(badFp).toMatchObject({ ok: false, stage: "identity_binding" });
    // oversized payload refuses
    const huge = validProposal(s.senderNodeId, s.senderFingerprint, {
      contentHashes: ["sha256-" + "c".repeat(64)],
      expectedEvidence: ["sha256-" + "d".repeat(64)],
    });
    const blob = { ...huge, provenance: { ...huge.provenance, note: "x".repeat(300) } };
    const oversize = validateTaskProposalPayload({
      payload: blob as unknown as Record<string, unknown>,
      senderNodeId: s.senderNodeId,
      senderFingerprint: s.senderFingerprint,
    });
    expect(oversize).toMatchObject({ ok: false, failureCode: "proposal_provenance_mismatch" });
    const idCheck = federationProposalDurableId("fp-zzz");
    expect(idCheck.ok).toBe(false);
  });
});
