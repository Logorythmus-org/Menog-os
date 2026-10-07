/**
 * PHASE 24D — Authenticated Bounded Federation Message Bus
 * (IN-PROCESS FIXTURE ONLY / NO LAN·INTERNET·DISCOVERY / FAIL CLOSED).
 *
 * The bus IS the pack pipeline, each stage fail-closed. Deliberate
 * composition order (documented in the gate report): the DURABLE peer
 * admission check runs BEFORE signature/replay evaluation so a
 * non-admitted sender gets no signature oracle and cannot pollute the
 * once-ever replay cache; every pack stage is present and enforced:
 *
 *   1. signed envelope (shape)   bounded bytes, pinned id shapes, closed
 *                                declared-intent union
 *   2. peer admission (durable)  sender must be `admitted` in the 24C
 *                                registry; unknown/candidate/quarantined/
 *                                retired refuse (no signature oracle)
 *   3. signature + identity      24B real verification via the injected
 *                                port; the subject's fingerprint claim
 *                                must match the verifying key
 *   4. protocol/schema           exact `menog-federation/v1` + schema
 *   5. replay/freshness          24A once-ever message ids + skew window
 *   6. local message admission   the DECISION (24A contract validation)
 *   7. evidence/ledger           append-only `federation_receipt` record
 *                                persisted through the 23B junction; the
 *                                receipt recordId IS the message-id
 *                                commitment (durable replay guard)
 *   8. typed inbox               the ONLY visibility surface: untrusted
 *                                payload DATA for LOCAL evaluation (24E);
 *                                never a tool call, never a spawn
 *
 * Bounds are pinned constants (envelope bytes, payload bytes, batch size,
 * inbox depth); refusing to widen them is the point. The replay cache is
 * the 24A once-ever tracker rehydrated from durable receipts at open.
 *
 * Receipts bind (pack): sender fingerprint/epoch, message id, payload
 * hash, protocol, receiver decision, receiver epoch. Receipts never
 * invoke a tool, a process, Policy, the planner, or the launcher.
 * Persistence ONLY through the sanctioned 23B coordinator junction.
 * The `federation_receipt` kind is the SECOND 24-gate unfreeze event
 * (append-only evidence; same documented protocol as 24C's peer kind).
 */

import { canonicalHash, canonicalDurableJson } from "./canonical.js";
import {
  FEDERATION_MESSAGE_ID_PATTERN,
  FEDERATION_DECLARED_INTENTS,
  NODE_ID_PATTERN,
  newInstanceEpochTracker,
  newMessageReplayTracker,
  validateSignedMessageContract,
  type IdentitySignatureVerifier,
  type InstanceEpochTracker,
  type MessageReplayTracker,
  type FederationSignedMessage,
} from "./federationIdentity.js";
import type { PeerRegistry } from "./federationPeers.js";
import type { RuntimeStateCoordinator } from "./coordinator.js";
import { federationReceiptDurableId } from "./statePersistence.js";
import type { DurableStore } from "./store.js";

// ── bounds + schema (closed; refusing to widen is the point) ─────────────────

export const FEDERATION_BUS_SCHEMA_VERSION = "menog-federation-bus/v0" as const;
export type FederationBusSchemaVersion = typeof FEDERATION_BUS_SCHEMA_VERSION;

/** Max canonical envelope bytes (the signed body never carries the payload). */
export const FEDERATION_MAX_ENVELOPE_BYTES = 8192 as const;
/** Max payload object the inbox may expose per message. */
export const FEDERATION_MAX_PAYLOAD_BYTES = 65536 as const;
/** Max messages ingestible in one batch call. */
export const FEDERATION_MAX_BATCH = 32 as const;
/** Max inbox depth (oldest entries drop from the VIEW only). */
export const FEDERATION_MAX_INBOX_DEPTH = 256 as const;

/** Narrowed stage name (exhaustive stage reporting). */
export type BusStage =
  | "envelope_shape"
  | "peer_admission"
  | "signature"
  | "protocol_schema"
  | "replay_freshness"
  | "contract"
  | "receipt";

export const FEDERATION_BUS_FAILURE_CODES = Object.freeze([
  "bus_closed",
  "oversize_envelope",
  "malformed_envelope",
  "unknown_intent",
  "signature_stage_refused",
  "peer_not_admitted",
  "peer_registry_error",
  "protocol_mismatch",
  "replay_detected",
  "stale_epoch",
  "skew_out_of_tolerance",
  "lineage_malformed",
  "receipt_persistence_denied",
] as const);
export type FederationBusFailureCode = (typeof FEDERATION_BUS_FAILURE_CODES)[number];

export type BusIngestResult =
  | {
      readonly ok: true;
      readonly code: "message_admitted";
      readonly messageId: string;
      readonly senderNodeId: string;
      readonly receiptRecordId: string;
      readonly commitSequence: number;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code: "message_refused";
      readonly stage: BusStage;
      readonly failureCode: FederationBusFailureCode;
      readonly storeFailureCode: string | null;
      readonly explanation: string;
    };

export interface FederationInboxEntry {
  readonly messageId: string;
  readonly senderNodeId: string;
  readonly declaredIntent: string;
  readonly payloadHash: string;
  /** Untrusted DATA exposed for LOCAL evaluation (24E consumes this). */
  readonly payload: Readonly<Record<string, unknown>>;
  readonly receivedAtEpochMs: number;
  readonly receiptRecordId: string;
}

export class FederationBus {
  readonly #store: DurableStore;
  readonly #coordinator: RuntimeStateCoordinator;
  readonly #peers: PeerRegistry;
  readonly #verifiers: Map<string, IdentitySignatureVerifier>;
  readonly #replay: MessageReplayTracker;
  readonly #epochTracker: InstanceEpochTracker;
  readonly #epochId: string;
  #inbox: FederationInboxEntry[] = [];
  #closed: boolean = false;

  private constructor(
    store: DurableStore,
    coordinator: RuntimeStateCoordinator,
    peers: PeerRegistry,
    verifiers: Map<string, IdentitySignatureVerifier>,
    replay: MessageReplayTracker,
    epochTracker: InstanceEpochTracker,
  ) {
    this.#store = store;
    this.#coordinator = coordinator;
    this.#peers = peers;
    this.#verifiers = verifiers;
    this.#replay = replay;
    this.#epochTracker = epochTracker;
    this.#epochId = coordinator.epochId;
  }

  /**
   * Bind the bus to one epoch's coordinator + peer registry. `verifiers`
   * maps a peer's 64-hex NodeId tail to its 24B signature verifier (the
   * caller's key-directory seam; the bus never invents keys). The durable
   * replay guard is rehydrated from receipt records at open: every receipt
   * commits one message id, so replaying a delivered message after a
   * restart refuses at the durable cache.
   */
  public static open(input: {
    readonly store: DurableStore;
    readonly coordinator: RuntimeStateCoordinator;
    readonly peers: PeerRegistry;
    readonly verifiers: Map<string, IdentitySignatureVerifier>;
  }): { readonly ok: true; readonly bus: FederationBus } | { readonly ok: false; readonly reason: string } {
    if (input.coordinator.isClosed) return { ok: false, reason: "the coordinator for this epoch is closed" };
    if (input.peers.isClosed) return { ok: false, reason: "the peer registry for this epoch is closed" };
    const replay = newMessageReplayTracker();
    for (const recordId of input.store.listRecordIds("federation_receipt")) {
      const read = input.store.readRecord(recordId);
      if (read.ok) {
        const messageId = (read.record.payload as Record<string, unknown>)["messageId"];
        if (typeof messageId === "string") replay.seen.add(messageId);
      }
    }
    return {
      ok: true,
      bus: new FederationBus(input.store, input.coordinator, input.peers, input.verifiers, replay, newInstanceEpochTracker()),
    };
  }

  public get epochId(): string {
    return this.#epochId;
  }

  public get isClosed(): boolean {
    return this.#closed || this.#coordinator.isClosed;
  }

  /** The typed inbox view (bounded depth; oldest entries drop from the VIEW). */
  public inbox(): readonly FederationInboxEntry[] {
    return Object.freeze([...this.#inbox]);
  }

  /**
   * Ingest ONE signed message through the full pipeline. Fail-closed at
   * every stage. A refused message leaves NO durable trace and NO inbox
   * entry; the once-ever replay cache is consumed ONLY by messages from
   * admitted peers that reach the contract stage.
   */
  public ingest(input: {
    readonly envelope: FederationSignedMessage;
    readonly payload?: Readonly<Record<string, unknown>>;
    readonly nowEpochMs: number;
  }): BusIngestResult {
    if (this.isClosed) {
      return refuse("envelope_shape", "bus_closed", null, "the bus for this epoch is closed");
    }
    const env = input.envelope;
    // ── stage 1: envelope shape ──
    if (env === null || typeof env !== "object" || typeof env.signature !== "string" || env.signature.length === 0) {
      return refuse("envelope_shape", "malformed_envelope", null, "envelope is missing its message or signature — refusing");
    }
    const body = env.message as unknown as Record<string, unknown> | null;
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      return refuse("envelope_shape", "malformed_envelope", null, "message body is not an object — refusing");
    }
    for (const key of ["messageId", "senderNodeId", "senderFingerprint", "senderInstanceId", "senderEpochId"]) {
      const v = body[key];
      if (typeof v !== "string" || v.length === 0) {
        return refuse("envelope_shape", "malformed_envelope", null, "message body field '" + key + "' is missing — refusing");
      }
    }
    if (canonicalByteSize(env) > FEDERATION_MAX_ENVELOPE_BYTES) {
      return refuse("envelope_shape", "oversize_envelope", null, "envelope exceeds the pinned byte bound — refusing");
    }
    const messageId = body["messageId"] as string;
    const senderNodeId = body["senderNodeId"] as string;
    if (!NODE_ID_PATTERN.test(senderNodeId) || !FEDERATION_MESSAGE_ID_PATTERN.test(messageId)) {
      return refuse("envelope_shape", "malformed_envelope", null, "senderNodeId or messageId is not in the pinned shape — refusing");
    }
    if (
      typeof body["declaredIntent"] === "string" &&
      !(FEDERATION_DECLARED_INTENTS as readonly string[]).includes(body["declaredIntent"])
    ) {
      return refuse("envelope_shape", "unknown_intent", null, "declared intent is not in the closed union — refusing");
    }

    // ── stage 2: durable peer admission (BEFORE signature: no oracle) ──
    const peer = this.#peers.readPeer(senderNodeId);
    if (!peer.ok) {
      return refuse(
        "peer_admission",
        peer.failureCode === "peer_unknown" ? "peer_not_admitted" : "peer_registry_error",
        null,
        peer.reason,
      );
    }
    if (peer.state.trustState !== "admitted") {
      return refuse(
        "peer_admission",
        "peer_not_admitted",
        null,
        "sender trust state is '" + peer.state.trustState + "' — only admitted peers may deliver messages (fail closed)",
      );
    }

    // ── stage 2b: DURABLE replay guard (before signature: no oracle, no
    //    key-directory dependence). The receipt recordId IS the message-id
    //    commitment; if the row exists, this message was already admitted
    //    — possibly in a PREVIOUS epoch (the in-memory once-ever cache
    //    covers the within-epoch case at the contract stage).
    const receiptProbe = federationReceiptDurableId(messageId);
    if (receiptProbe.ok && this.#store.readRecord(receiptProbe.recordId).ok) {
      return refuse(
        "replay_freshness",
        "replay_detected",
        null,
        "a durable receipt already exists for this message id (admitted in this or a previous epoch) — REPLAY refused without any signature evaluation (fail closed)",
      );
    }

    // ── stages 3–6: the 24A contract pipeline (signature → protocol →
    //    skew → lineage → replay → epoch freshness), composing the 24B
    //    verifier from the caller's key directory.
    const verifier = this.#verifiers.get(this.#keyOf(senderNodeId));
    const contract = validateSignedMessageContract({
      message: env.message,
      signature: env.signature,
      verifier:
        verifier ??
        (() => ({ ok: false, reason: "no verifier registered for this sender (key directory has no entry)" })),
      replayTracker: this.#replay,
      epochTracker: this.#epochTracker,
      nowEpochMs: input.nowEpochMs,
      localEpochId: this.#epochId,
    });
    if (!contract.ok) {
      const [stage, failureCode] = stageMapping(contract.denyReason);
      return refuse(stage, failureCode, null, contract.explanation);
    }

    // ── stage 7: evidence/ledger — the append-only receipt, through the
    //    sanctioned junction. The receipt recordId IS the message-id
    //    commitment (durable replay guard across restarts).
    const receiptId = federationReceiptDurableId(messageId);
    if (!receiptId.ok) {
      return refuse("receipt", "malformed_envelope", null, receiptId.reason);
    }
    const receiptPayload: Record<string, unknown> = {
      receiptKind: "message_accepted" as const,
      messageId,
      senderNodeId,
      senderFingerprint: body["senderFingerprint"] as string,
      senderEpochId: body["senderEpochId"] as string,
      payloadHash: body["payloadHash"] as string,
      protocolVersion: body["protocolVersion"] as string,
      schemaVersion: body["schemaVersion"] as string,
      declaredIntent: body["declaredIntent"] as string,
      receiverDecision: "message_admitted" as const,
      receiverEpochId: this.#epochId,
      subjectHash: canonicalHash(env.message),
      decidedAtEpochMs: input.nowEpochMs,
    };
    const persisted = this.#coordinator.acceptMutation({
      kind: "federation_receipt",
      recordId: receiptId.recordId,
      revision: 1,
      supersedesRevision: null,
      payload: receiptPayload,
      transactionId: "frc-" + messageId,
      lineageRoot: messageId,
      lineageParent: (body["causationId"] as string | null) ?? null,
      createdAtEpochMs: input.nowEpochMs,
    });
    if (!persisted.ok) {
      return refuse(
        "receipt",
        persisted.code === "refused_pre_commit" && persisted.failureCode === "stale_epoch" ? "stale_epoch" : "receipt_persistence_denied",
        persisted.code === "refused_pre_commit" ? persisted.storeFailureCode : null,
        persisted.explanation,
      );
    }

    // ── stage 8: typed inbox — the ONLY visibility surface.
    const payload = input.payload ?? {};
    if (canonicalByteSize(payload) > FEDERATION_MAX_PAYLOAD_BYTES) {
      // The receipt stands (it bound the decision); the payload is not exposed.
      return refuse("receipt", "oversize_envelope", null, "payload exceeds the pinned inbox bound — receipt stands, payload not exposed");
    }
    this.#inbox = [
      ...this.#inbox.slice(-(FEDERATION_MAX_INBOX_DEPTH - 1)),
      Object.freeze({
        messageId,
        senderNodeId,
        declaredIntent: body["declaredIntent"] as string,
        payloadHash: body["payloadHash"] as string,
        payload: Object.freeze({ ...payload }),
        receivedAtEpochMs: input.nowEpochMs,
        receiptRecordId: receiptId.recordId,
      }),
    ];
    return {
      ok: true,
      code: "message_admitted",
      messageId,
      senderNodeId,
      receiptRecordId: receiptId.recordId,
      commitSequence: persisted.commitSequence,
      explanation:
        "message admitted through the full pipeline and receipted as append-only evidence; the payload is UNTRUSTED DATA in the typed inbox — it never invokes a tool, process, Policy, or the launcher",
    };
  }

  /** Ingest a bounded batch (each message independently; results in order). */
  public ingestBatch(input: {
    readonly envelopes: readonly FederationSignedMessage[];
    readonly nowEpochMs: number;
  }): readonly BusIngestResult[] {
    if (input.envelopes.length > FEDERATION_MAX_BATCH) {
      return [refuse("envelope_shape", "oversize_envelope", null, "batch exceeds the pinned size bound — refusing the whole batch")];
    }
    return input.envelopes.map((envelope) => this.ingest({ envelope, nowEpochMs: input.nowEpochMs }));
  }

  #keyOf(nodeId: string): string {
    return nodeId.startsWith("node-") ? nodeId.slice(5) : nodeId;
  }
}

function refuse(
  stage: BusStage,
  failureCode: FederationBusFailureCode,
  storeFailureCode: string | null,
  explanation: string
): BusIngestResult {
  return { ok: false, code: "message_refused", stage, failureCode, storeFailureCode, explanation };
}

/** Map a 24A contract deny reason onto the bus stage + failure code. */
function stageMapping(denyReason: string): [BusStage, FederationBusFailureCode] {
  switch (denyReason) {
    case "signature_invalid":
      return ["signature", "signature_stage_refused"];
    case "nodeid_fingerprint_mismatch":
      return ["signature", "signature_stage_refused"];
    case "protocol_mismatch":
      return ["protocol_schema", "protocol_mismatch"];
    case "replay_detected":
      return ["replay_freshness", "replay_detected"];
    case "skew_out_of_tolerance":
      return ["replay_freshness", "skew_out_of_tolerance"];
    case "lineage_malformed":
      return ["contract", "lineage_malformed"];
    default:
      return ["contract", "malformed_envelope"];
  }
}

/** Canonical byte size of a value (the pinned bounding discipline). */
function canonicalByteSize(value: unknown): number {
  return canonicalDurableJson(value).length;
}

/** The 24D receipt body (pack binding fields; deterministic). */
export interface FederationReceiptBody {
  readonly receiptKind: "message_accepted";
  readonly messageId: string;
  readonly senderNodeId: string;
  readonly senderFingerprint: string;
  readonly senderEpochId: string;
  readonly payloadHash: string;
  readonly protocolVersion: string;
  readonly schemaVersion: string;
  readonly declaredIntent: string;
  readonly receiverDecision: "message_admitted";
  readonly receiverEpochId: string;
  readonly subjectHash: string;
  readonly decidedAtEpochMs: number;
}
