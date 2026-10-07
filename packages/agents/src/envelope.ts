import { createHash } from "node:crypto";
import type {
  AgentBoundaryDenyReason,
  AgentBoundaryDisposition,
  AgentBoundaryReceipt,
  AgentBoundaryResult,
  AgentChannelPolicy,
  AgentEnvelope,
  AgentMessage,
  AgentProvenanceEntry,
  AgentQuarantineRecord,
} from "./types.js";
import {
  AGENTS_MAX_CHANNEL_HISTORY,
  AGENTS_MAX_PAYLOAD_CHARS,
  AGENTS_MAX_PROVENANCE_FIELDS,
  AGENTS_MAX_PROVENANCE_VALUE_CHARS,
  KNOWN_AGENT_MESSAGE_KINDS,
} from "./types.js";

/**
 * Phase 19C — message envelopes, channels, and the receiver boundary.
 *
 * 19A mediated WHO may talk to WHOM about WHAT. 19C adds the envelope
 * layer:
 *
 *   - CHANNELS: named routes with a frozen routing policy validated
 *     against the closed AGENT_ROUTING_RULES map (a channel cannot open a
 *     route the mediation layer forbids).
 *   - ENVELOPES: runtime-stamped wrappers carrying sender/receiver
 *     identity, channel identity, sequence, and the provenance chain.
 *     Sender identity is RE-STAMPED from the runtime's own registry — it
 *     is never taken from caller input (anti-spoofing).
 *   - RECEIVER BOUNDARY: every delivered envelope is UNTRUSTED INPUT at
 *     the receiver boundary. The boundary re-checks addressing, duplicate
 *     delivery, envelope integrity, provenance integrity, and hostile
 *     content BEFORE the receiver sees an "accepted" disposition.
 *
 * Envelopes, provenance entries, quarantine records, and receipts are
 * coordination/audit data: `authority: "mediation"`,
 * `executionAuthorized: false` everywhere.
 */

const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

/** Validate a channel policy against the closed mediation routing map. */
export function validateChannelPolicy(
  policy: AgentChannelPolicy
): { ok: true } | { ok: false; denyReason: "policy_invalid" | "route_not_allowed"; reason: string } {
  if (!policy || typeof policy !== "object") {
    return { ok: false, denyReason: "policy_invalid", reason: "policy must be an object" };
  }
  if (policy.maxPayloadChars !== undefined) {
    const m = policy.maxPayloadChars;
    if (typeof m !== "number" || !Number.isFinite(m) || m < 1 || m > AGENTS_MAX_PAYLOAD_CHARS) {
      return {
        ok: false,
        denyReason: "policy_invalid",
        reason: "maxPayloadChars must be in [1," + String(AGENTS_MAX_PAYLOAD_CHARS) + "]",
      };
    }
  }
  if (!Array.isArray(policy.allowedKinds) || policy.allowedKinds.length === 0) {
    return { ok: false, denyReason: "policy_invalid", reason: "allowedKinds must be a non-empty array" };
  }
  for (const k of policy.allowedKinds) {
    if (!(KNOWN_AGENT_MESSAGE_KINDS as readonly string[]).includes(k)) {
      return { ok: false, denyReason: "policy_invalid", reason: "allowedKinds entries must be known message kinds" };
    }
  }
  // route_not_allowed: the channel's kind must match its role pair and the
  // role pair must be routable in the closed mediation map for every
  // allowed kind.
  const expectedKind: Record<string, string> = {
    planner_builder: "planner>builder",
    builder_reviewer: "builder>reviewer",
    reviewer_planner: "reviewer>planner",
  };
  const pair = policy.fromRole + ">" + policy.toRole;
  if (policy.kind !== undefined && expectedKind[policy.kind] !== pair) {
    return {
      ok: false,
      denyReason: "route_not_allowed",
      reason: "channel kind '" + String(policy.kind) + "' does not match role pair '" + pair + "'",
    };
  }
  return { ok: true };
}

/** Re-check one message against a channel's frozen routing policy. */
export function channelPolicyAllows(
  policy: AgentChannelPolicy,
  kind: AgentMessage["kind"],
  fromAgentId: string,
  toAgentId: string,
  participants: readonly string[]
): { ok: true } | { ok: false; reason: string } {
  if (!participants.includes(fromAgentId)) {
    return { ok: false, reason: "sender '" + fromAgentId + "' is not a channel participant" };
  }
  if (!participants.includes(toAgentId)) {
    return { ok: false, reason: "receiver '" + toAgentId + "' is not a channel participant" };
  }
  if (!policy.allowedKinds.includes(kind)) {
    return { ok: false, reason: "kind '" + kind + "' is not in the channel's allowedKinds policy" };
  }
  return { ok: true };
}

/** Provenance chain integrity: complete canonical stages, bounded fields, intact stamps. */
export function validateProvenanceChain(
  provenance: readonly AgentProvenanceEntry[]
): { ok: true } | { ok: false; denyReason: AgentBoundaryDenyReason; reason: string } {
  if (!Array.isArray(provenance) || provenance.length === 0) {
    return { ok: false, denyReason: "provenance_broken", reason: "provenance chain is empty" };
  }
  // The canonical chain is COMPLETE: origin→mediation→delivery. A truncated
  // chain (e.g. missing the delivery stamp) is broken, not merely short.
  if (provenance.length !== 3) {
    return {
      ok: false,
      denyReason: "provenance_broken",
      reason:
        "provenance chain must contain exactly origin→mediation→delivery; got " +
        String(provenance.length) +
        " entry(ies)",
    };
  }
  if (provenance.length > AGENTS_MAX_PROVENANCE_FIELDS) {
    return {
      ok: false,
      denyReason: "provenance_broken",
      reason: "provenance chain exceeds " + String(AGENTS_MAX_PROVENANCE_FIELDS) + " entries",
    };
  }
  const expectedOrder = ["origin", "mediation", "delivery"] as const;
  for (let i = 0; i < provenance.length; i++) {
    const entry = provenance[i]!;
    if (entry.stage !== expectedOrder[i]) {
      return {
        ok: false,
        denyReason: "provenance_broken",
        reason:
          "provenance entry " + String(i) + " has stage '" + String(entry.stage) +
          "'; canonical chain order is origin→mediation→delivery",
      };
    }
    if (typeof entry.actorId !== "string" || entry.actorId.length === 0) {
      return { ok: false, denyReason: "provenance_broken", reason: "provenance actorId missing" };
    }
    if (typeof entry.actorType !== "string" || entry.actorType.length === 0) {
      return { ok: false, denyReason: "provenance_broken", reason: "provenance actorType missing" };
    }
    if (typeof entry.atEpochMs !== "number" || !Number.isFinite(entry.atEpochMs) || entry.atEpochMs < 0) {
      return { ok: false, denyReason: "provenance_broken", reason: "provenance atEpochMs invalid" };
    }
    if (!entry.detail || typeof entry.detail !== "object") {
      return { ok: false, denyReason: "provenance_broken", reason: "provenance detail missing" };
    }
    const entries = Object.entries(entry.detail);
    if (entries.length > AGENTS_MAX_PROVENANCE_FIELDS) {
      return { ok: false, denyReason: "provenance_broken", reason: "provenance detail exceeds field cap" };
    }
    for (const [k, v] of entries) {
      if (typeof k !== "string" || k.length === 0 || k.length > 64) {
        return { ok: false, denyReason: "provenance_broken", reason: "provenance detail keys must be 1..64 chars" };
      }
      if (
        (typeof v !== "string" && typeof v !== "number" && typeof v !== "boolean") ||
        (typeof v === "string" && v.length > AGENTS_MAX_PROVENANCE_VALUE_CHARS)
      ) {
        return {
          ok: false,
          denyReason: "provenance_broken",
          reason: "provenance detail value at '" + k + "' is not a bounded scalar",
        };
      }
    }
  }
  return { ok: true };
}

/** Envelope integrity: identity linkage, untrusted marker, authority pins. */
export function validateEnvelopeIntegrity(
  envelope: AgentEnvelope
): { ok: true } | { ok: false; denyReason: AgentBoundaryDenyReason; reason: string } {
  if (!envelope || typeof envelope !== "object") {
    return { ok: false, denyReason: "envelope_malformed", reason: "envelope must be an object" };
  }
  if (envelope.schemaVersion !== "menog-agents/v0") {
    return { ok: false, denyReason: "envelope_malformed", reason: "envelope schemaVersion mismatch" };
  }
  if (typeof envelope.envelopeId !== "string" || envelope.envelopeId.length === 0) {
    return { ok: false, denyReason: "envelope_malformed", reason: "envelopeId missing" };
  }
  if (typeof envelope.channelId !== "string" || envelope.channelId.length === 0) {
    return { ok: false, denyReason: "envelope_malformed", reason: "channelId missing" };
  }
  if (!envelope.message || typeof envelope.message !== "object") {
    return { ok: false, denyReason: "envelope_malformed", reason: "message missing" };
  }
  const m = envelope.message;
  if (m.authority !== "mediation" || m.executionAuthorized !== false) {
    return {
      ok: false,
      denyReason: "envelope_malformed",
      reason: "embedded message lacks the mediation authority pins",
    };
  }
  if (envelope.senderId !== m.fromAgentId || envelope.receiverId !== m.toAgentId) {
    return {
      ok: false,
      denyReason: "envelope_malformed",
      reason: "envelope sender/receiver does not match the embedded message routing",
    };
  }
  if (envelope.untrusted !== true) {
    return { ok: false, denyReason: "envelope_malformed", reason: "envelope must be marked untrusted" };
  }
  if (envelope.authority !== "mediation" || envelope.executionAuthorized !== false) {
    return { ok: false, denyReason: "envelope_malformed", reason: "envelope lacks the mediation authority pins" };
  }
  return { ok: true };
}

/** Canonical digest of a payload (quarantine records never carry raw text). */
export function envelopePayloadDigest(text: string): string {
  return sha256(text);
}

export interface BoundaryCheckInput {
  readonly envelope: AgentEnvelope;
  /** The identity invoking the boundary (must equal the envelope receiver). */
  readonly callerReceiverId: string;
  readonly receiverKnown: boolean;
  readonly alreadyDelivered: boolean;
  readonly channelHistoryCount: number;
  readonly contentScreen: { readonly ok: true } | { readonly ok: false; readonly reason: string };
}

/**
 * The receiver-boundary decision. Pure: given the same inputs it returns
 * the same disposition. Order matters and is deterministic:
 *   receiver known → addressed to receiver → not duplicate →
 *   envelope integrity → provenance integrity → channel capacity →
 *   content screen.
 */
export function decideBoundary(
  input: BoundaryCheckInput
): { disposition: AgentBoundaryDisposition; result: AgentBoundaryResult; quarantine: boolean } {
  const { envelope } = input;
  if (!input.receiverKnown) {
    return fail("receiver_unknown", "receiver is not a registered identity", false);
  }
  // Anti-interception: only the identity the envelope is addressed to may
  // run the boundary on it. A third party (even a registered agent) is
  // refused — envelope contents are addressed, not broadcast.
  if (input.callerReceiverId !== envelope.receiverId) {
    return fail("not_addressed_to_receiver", "envelope is addressed to a different receiver", false);
  }
  if (envelope.receiverId !== envelope.message.toAgentId) {
    return fail("not_addressed_to_receiver", "envelope is not addressed to this receiver", false);
  }
  if (input.alreadyDelivered) {
    return fail("duplicate_envelope", "this envelope was already delivered (replay refused)", true);
  }
  const integrity = validateEnvelopeIntegrity(envelope);
  if (!integrity.ok) {
    return fail(integrity.denyReason, integrity.reason, true);
  }
  const prov = validateProvenanceChain(envelope.provenance);
  if (!prov.ok) {
    return fail(prov.denyReason, prov.reason, true);
  }
  if (input.channelHistoryCount >= AGENTS_MAX_CHANNEL_HISTORY) {
    return fail("envelope_malformed", "channel history cap reached", true);
  }
  if (!input.contentScreen.ok) {
    return fail("content_refused", input.contentScreen.reason, true);
  }
  const receipt: AgentBoundaryReceipt = {
    receiptId: "rcp-" + envelope.envelopeId,
    envelopeId: envelope.envelopeId,
    receiverId: envelope.receiverId,
    disposition: "accepted",
    denyReason: null,
    atEpochMs: envelope.message.sentAtEpochMs,
    authority: "mediation",
    executionAuthorized: false,
  };
  return { disposition: "accepted", result: { ok: true, receipt }, quarantine: false };

  function fail(
    denyReason: AgentBoundaryDenyReason,
    reason: string,
    quarantine: boolean
  ): { disposition: AgentBoundaryDisposition; result: AgentBoundaryResult; quarantine: boolean } {
    return {
      disposition: quarantine ? "quarantined" : "refused",
      result: { ok: false, denyReason, reason },
      quarantine,
    };
  }
}

/** Build a quarantine record (digest-only, no raw payload text). */
export function buildQuarantineRecord(
  envelope: AgentEnvelope,
  denyReason: AgentBoundaryDenyReason,
  atEpochMs: number,
  sequence: number
): AgentQuarantineRecord {
  return {
    quarantineId:
      "qrt-" + String(sequence).padStart(6, "0") + "-" + sha256(envelope.envelopeId).slice(0, 12),
    atEpochMs,
    envelopeId: envelope.envelopeId,
    channelId: envelope.channelId,
    senderId: envelope.senderId,
    receiverId: envelope.receiverId,
    denyReason,
    payloadDigest: envelopePayloadDigest(envelope.message.payloadText),
    provenance: envelope.provenance,
    authority: "mediation",
    executionAuthorized: false,
  };
}
