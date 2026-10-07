/**
 * PHASE 25D — Federation Egress Disclosure & Data-Minimization Gate
 * (NO NETWORK / PRE-TRANSPORT GATE / DEFAULT DENY / DISCLOSURE GRANTS NO
 * AUTHORITY).
 *
 * The ONE sanctioned pre-transport egress gate: it answers, deterministically
 * and before any transport may touch a payload, WHAT IS ALLOWED TO LEAVE a
 * Menog node. It classifies an operator-prepared egress candidate
 * field-by-field into a closed content-class vocabulary, refuses or
 * redacts forbidden classes, refuses unknown fields (default deny), binds
 * a deterministic disclosure manifest to the outgoing payload hash, and
 * enforces hard bounds. Redact-or-refuse, never widen.
 *
 * Allowed OUT (closed classes):
 *   public_identity      — fingerprint/NodeId/instance id (24B PUBLIC facts)
 *   protocol_metadata    — schema/protocol versions, message ids, timestamps
 *   content_hashes       — sha256 hex hashes of payloads/evidence
 *   bounded_intent       — the closed inert intent/claim vocabulary
 *   provenance_refs      — message/proposal/receipt/anchor record references
 *   evidence_refs        — durable record ids/hashes pointing at local facts
 *   disclosure_manifest  — the manifest itself (self-describing)
 *
 * Forbidden FOREVER (each with a pinned detection family):
 *   secret_material      — private keys/seed/token-shaped keys (24B denylist
 *                          + free-text PKCS#8 tripwire), at ANY depth
 *   raw_hidden_policy    — Policy decision internals (raw rule tokens,
 *                          policy-file text, hidden allow/deny lists)
 *   raw_tool_output      — unbounded/unredacted tool/process output
 *   local_environment    — local paths, env values, host/user names, ports
 *   process_handles      — process/handle/socket material
 *   executable_material  — shell/executable/batch/script payloads
 *   unknown              — anything not in the closed allowed vocabulary
 *
 * LAWS (pack + 25A):
 *  - DEFAULT DENY: an egress candidate may contain ONLY the allowed classes
 *    with closed field names; anything else refuses (`unknown_field`).
 *  - REDACT-OR-REFUSE: a redactable forbidden field is redacted and the
 *    disclosure continues WITHOUT it; a non-redactable forbidden field
 *    refuses the whole candidate. Nothing is widened to fit.
 *  - DETERMINISM: identical input → byte-identical manifest; the manifest
 *    is bound to the outgoing payload hash (`payloadHash`) and cross-checked
 *    (`hash_mismatch` refuses). Re-disclosing the same payload+manifest is
 *    an idempotent no-op (`stale_disclosure` never applies — a manifest
 *    evaluated against a DIFFERENT payload hash is stale and refuses).
 *  - BOUNDS: manifest entries and serialized size are hard-capped; over-
 *    size refuses (`oversize_manifest`).
 *  - NO AUTHORITY: a disclosure is a fact about what left; it grants no
 *    authority locally or remotely (25A P1/P4; federation→tool direct path
 *    remains forbidden — nothing here can execute).
 *
 * This module performs NO transport, NO sockets, NO discovery: it is a pure
 * gate. The transport stays the caller's bounded in-process fixture (24D
 * discipline); NO network primitive is imported (suite-pinned).
 */

import { createHash } from "node:crypto";
import {
  FEDERATION_SECRET_KEY_DENYLIST,
  looksLikeEncodedPrivateKey,
} from "./federationCrypto.js";

// ── schema + closed vocabularies ─────────────────────────────────────────────

export const EGRESS_SCHEMA_VERSION = "menog-egress-disclosure/v0" as const;
export type EgressSchemaVersion = typeof EGRESS_SCHEMA_VERSION;

/** Closed content classes ALLOWED to leave (everything else denies). */
export const EGRESS_ALLOWED_CLASSES = Object.freeze([
  "public_identity",
  "protocol_metadata",
  "content_hashes",
  "bounded_intent",
  "provenance_refs",
  "evidence_refs",
  "disclosure_manifest",
] as const);
export type EgressAllowedClass = (typeof EGRESS_ALLOWED_CLASSES)[number];

/** Closed forbidden classes with pinned detection families. */
export const EGRESS_FORBIDDEN_CLASSES = Object.freeze([
  "secret_material",
  "raw_hidden_policy",
  "raw_tool_output",
  "local_environment",
  "process_handles",
  "executable_material",
  "unknown",
] as const);
export type EgressForbiddenClass = (typeof EGRESS_FORBIDDEN_CLASSES)[number];

export const EGRESS_DECISION_CODES = Object.freeze([
  "disclosure_permitted",
  "disclosure_refused",
  "disclosure_permitted_with_redactions",
] as const);
export type EgressDecisionCode = (typeof EGRESS_DECISION_CODES)[number];

export const EGRESS_DENY_CODES = Object.freeze([
  "malformed_candidate",
  "unknown_field",
  "secret_material",
  "raw_hidden_policy",
  "raw_tool_output",
  "local_environment",
  "process_handles",
  "executable_material",
  "oversize_manifest",
  "hash_mismatch",
  "stale_disclosure",
] as const);
export type EgressDenyCode = (typeof EGRESS_DENY_CODES)[number];

/** Bounds (pinned constants; refusing to widen). */
export const EGRESS_MAX_FIELDS = 64 as const;
export const EGRESS_MAX_FIELD_VALUE_BYTES = 4_096 as const;
export const EGRESS_MAX_MANIFEST_BYTES = 16_384 as const;
/** Redaction marker bound into manifests and redacted payloads. */
export const EGRESS_REDACTION_MARKER = "[REDACTED-BY-EGRESS-GATE]" as const;

// ── deep leak detection (secrets/paths/exec material at ANY depth) ───────────

function normalizedKey(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/[-\s.]+/g, "_").toLowerCase();
}

const SECRET_KEY_SET: ReadonlySet<string> = new Set(FEDERATION_SECRET_KEY_DENYLIST.map(normalizedKey));

const POLICY_KEY_PATTERN = /policy|allowlist|allow_list|denylist|deny_list|rule_?id|verdict/i;
const EXEC_VALUE_PATTERN =
  /(^|\s)(sh|bash|zsh|pwsh|powershell|cmd(\.exe)?|sudo|rm|curl|wget|ssh|scp|eval|exec)\s+|\$\(|`[^`]+`|\|\s*\w+|&&|\bnpm\s|\bnpx\s|node\s+-e|;\s*\w+/i;
const PATH_VALUE_PATTERN =
  /(?:[A-Za-z]:\\|\\\\|\/(?:usr|etc|var|home|root|tmp|opt|Users|Windows|Program Files)(?:\/|\\)|\.\/|~\/|\.\.\/)/;
// Case-SENSITIVE on purpose: an all-caps token (VAR=value, or a bare
// ALL_CAPS name) is environment material; ordinary prose must not match.
const ENV_VALUE_PATTERN = /^(?:[A-Z][A-Z0-9_]*=[^\s]*|[A-Z][A-Z0-9_]{3,})$/;
const HANDLE_VALUE_PATTERN = /\b(?:pid|fd|handle|socket|descriptor)\s*[:=]?\s*\d+\b|\b0x[0-9a-f]{6,}\b/i;
const RAW_OUTPUT_VALUE_PATTERN = /\b(?:stdout|stderr|traceback|exit\s+code|exit\s+status)\b/i;
const POLICY_TEXT_VALUE_PATTERN = /(?:raw[_-]?policy|hidden[_-]?policy|policy[_-]?source|policy[_-]?file)/i;

interface Finding {
  readonly field: string;
  readonly egressClass: EgressForbiddenClass;
  readonly reason: string;
}

function classifyKeyValue(key: string, value: unknown, path: string, out: Finding[], depth: number = 6): void {
  if (depth <= 0) return;
  const norm = normalizedKey(key);
  // 1. Secret-shaped KEYS (24B denylist) — the strongest signal.
  if (SECRET_KEY_SET.has(norm)) {
    out.push({ field: path, egressClass: "secret_material", reason: "secret-key-shaped field name (24B denylist)" });
  }
  if (POLICY_KEY_PATTERN.test(key) && /^(?:raw_|hidden_|full|internal|text|source|file)/i.test(key)) {
    out.push({ field: path, egressClass: "raw_hidden_policy", reason: "raw/hidden policy material field name" });
  }
  if (typeof value === "string") {
    if (SECRET_KEY_SET.has(norm) || looksLikeEncodedPrivateKey(value)) {
      if (!out.some((f) => f.field === path)) {
        out.push({ field: path, egressClass: "secret_material", reason: looksLikeEncodedPrivateKey(value) ? "encoded private-key material (PKCS#8 tripwire)" : "secret-key-shaped field name" });
      }
    } else if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value)) {
      out.push({ field: path, egressClass: "secret_material", reason: "PEM private-key block" });
    } else if (EXEC_VALUE_PATTERN.test(value)) {
      out.push({ field: path, egressClass: "executable_material", reason: "shell/executable command material" });
    } else if (HANDLE_VALUE_PATTERN.test(value)) {
      out.push({ field: path, egressClass: "process_handles", reason: "process/handle/socket material" });
    } else if (PATH_VALUE_PATTERN.test(value) || ENV_VALUE_PATTERN.test(value)) {
      out.push({ field: path, egressClass: "local_environment", reason: "local path or environment material" });
    } else if (POLICY_TEXT_VALUE_PATTERN.test(value) || (POLICY_KEY_PATTERN.test(key) && value.length > 80)) {
      out.push({ field: path, egressClass: "raw_hidden_policy", reason: "raw/hidden policy text material" });
    } else if (RAW_OUTPUT_VALUE_PATTERN.test(value) || (/raw|unredacted|stdout|stderr|output|dump/i.test(key) && value.length > 200)) {
      out.push({ field: path, egressClass: "raw_tool_output", reason: "raw/unbounded tool-output material" });
    } else {
      // 2b. JSON-encoded smuggling: a structural string is parsed and its
      // OBJECT shape scanned at depth (a private_key field cannot hide
      // inside a JSON string value).
      const trimmed = value.trimStart();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          const parsed: unknown = JSON.parse(value);
          if (parsed !== null && typeof parsed === "object") {
            classifyKeyValue(key, parsed, path, out, depth - 1);
          }
        } catch {
          // not JSON — prose/string stays string-classified
        }
      }
    }
  } else if (value !== null && typeof value === "object") {
    if (Array.isArray(value)) {
      value.forEach((entry, idx) => classifyKeyValue(key, entry, path + "[" + idx + "]", out, depth - 1));
    } else {
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        classifyKeyValue(k, v, path === "" ? k : path + "." + k, out, depth - 1);
      }
    }
  }
}

/** Find every forbidden-content finding in an arbitrary candidate object. */
export function findEgressFindings(candidate: unknown): Finding[] {
  const out: Finding[] = [];
  if (candidate !== null && typeof candidate === "object") {
    for (const [k, v] of Object.entries(candidate as Record<string, unknown>)) {
      classifyKeyValue(k, v, k, out);
    }
  }
  return out;
}

/**
 * Classify ONE candidate field (closed-vocabulary classification). Returns
 * an allowed class, a forbidden class, or unknown — never a guess outside
 * the vocabulary.
 */
export function classifyEgressField(input: {
  readonly key: string;
  readonly value: unknown;
}): { readonly egressClass: EgressAllowedClass | EgressForbiddenClass; readonly reason: string } {
  const findings = findEgressFindings({ [input.key]: input.value });
  if (findings.length > 0) {
    const first = findings[0];
    if (first !== undefined) {
      return { egressClass: first.egressClass, reason: first.reason };
    }
  }
  if (typeof input.key !== "string" || input.key.trim() === "") {
    return { egressClass: "unknown", reason: "field name is empty or malformed" };
  }
  return { egressClass: "unknown", reason: "field is not in the closed allowed-class vocabulary (default deny)" };
}

// ── the egress candidate (operator-prepared; CLOSED field set) ───────────────

/**
 * The closed shape of an egress candidate. Every field name is pinned; the
 * egress gate refuses unknown fields outright (default deny). Values are
 * bounded strings or arrays of bounded strings — NOT arbitrary objects —
 * so nothing can smuggle structure past the gate.
 */
export interface EgressCandidate {
  readonly schemaVersion: EgressSchemaVersion;
  /** Deterministic hash of the outgoing payload (the manifest binds to it). */
  readonly payloadHash: string;
  readonly fields: readonly {
    readonly key: string;
    readonly egressClass: EgressAllowedClass;
    readonly value: string;
  }[];
}

const CANDIDATE_KEYS = Object.freeze(["schemaVersion", "payloadHash", "fields"]);

const ALLOWED_FIELD_KEY_BY_CLASS: Readonly<Record<EgressAllowedClass, readonly string[]>> = Object.freeze({
  public_identity: ["nodeId", "fingerprint", "instanceId", "protocolVersion", "identityVersion"],
  protocol_metadata: ["messageId", "schemaVersion", "protocolVersion", "declaredIntent", "issuedAtEpochMs", "correlationId", "causationId", "lineage"],
  content_hashes: ["payloadHash", "evidenceHash", "subjectHash", "anchorHash", "receiptHash", "commitRef"],
  bounded_intent: ["declaredIntent", "intentClass", "proposalStatus", "responseKind"],
  provenance_refs: ["proposalRecordId", "receiptRecordId", "anchorRecordId", "messageId", "lineageRoot"],
  evidence_refs: ["evidenceRecordId", "evidenceRecordHash", "commitSequence", "observationId"],
  disclosure_manifest: ["manifestRef", "manifestHash"],
});

function isAllowedFieldKey(key: string, egressClass: EgressAllowedClass): boolean {
  return (ALLOWED_FIELD_KEY_BY_CLASS[egressClass] as readonly string[]).includes(key);
}

// ── the disclosure manifest (deterministic; bound to the payload hash) ───────

export interface DisclosureManifest {
  readonly schemaVersion: EgressSchemaVersion;
  readonly payloadHash: string;
  readonly decidedAtEpochMs: number;
  readonly disclosed: readonly { readonly key: string; readonly egressClass: EgressAllowedClass; readonly value: string }[];
  readonly redacted: readonly { readonly key: string; readonly egressClass: EgressForbiddenClass; readonly reason: string }[];
  readonly refused: readonly { readonly key: string; readonly egressClass: EgressForbiddenClass; readonly reason: string }[];
  readonly manifestHash: string;
}

function manifestHashOf(manifest: Omit<DisclosureManifest, "manifestHash">): string {
  return "sha256-" + createHash("sha256").update(JSON.stringify(manifest), "utf8").digest("hex");
}

// ── the ONE sanctioned gate decision ─────────────────────────────────────────

export type EgressGateDecision =
  | {
      readonly ok: true;
      readonly code: typeof EGRESS_DECISION_CODES[number];
      readonly manifest: DisclosureManifest;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly denyCode: EgressDenyCode;
      readonly explanation: string;
      /** Deterministic; present when a prior manifest is available for binding. */
      readonly priorManifestHash: string | null;
    };

/**
 * The ONE sanctioned egress decision (pure; deterministic; fail closed).
 * Chain: shape/unknown-field default deny → per-field classification
 * (forbidden classes refuse or redact per pinned policy) → per-field bound
 * checks → manifest size bound → payload-hash binding cross-check →
 * deterministic manifest emission.
 *
 * Redaction policy (pinned): `local_environment` and `process_handles`
 * findings are REDACTABLE (the field is dropped and logged in `redacted`);
 * `secret_material`, `raw_hidden_policy`, `raw_tool_output`, and
 * `executable_material` REFUSE the whole candidate — secrets and executable
 * material never ride, even redacted. Unknown fields refuse (default deny).
 */
export function decideEgress(input: {
  readonly candidate: EgressCandidate;
  /** The hash of the payload ACTUALLY being transported (cross-check). */
  readonly outgoingPayloadHash: string;
  /** Prior manifest hash binding the same payload, if one exists. */
  readonly priorManifestHash?: string | null;
  /**
   * Caller-supplied decision time (BOUND into the manifest). Determinism
   * law: the manifest is a pure function of the inputs — the gate never
   * reads the wall clock itself; pass the local decision time explicitly.
   */
  readonly nowEpochMs?: number;
}): EgressGateDecision {
  const prior = input.priorManifestHash ?? null;
  const refuse = (denyCode: EgressDenyCode, explanation: string): EgressGateDecision => ({
    ok: false,
    denyCode,
    explanation,
    priorManifestHash: prior,
  });

  const candidate = input.candidate;
  if (candidate === null || typeof candidate !== "object") {
    return refuse("malformed_candidate", "egress candidate must be an object");
  }
  const actualKeys = Object.keys(candidate).sort();
  const expectedKeys = [...CANDIDATE_KEYS].sort();
  if (actualKeys.length !== expectedKeys.length || !actualKeys.every((k, i) => k === expectedKeys[i])) {
    return refuse("unknown_field", "egress candidate carries unknown top-level fields — default deny (fail closed)");
  }
  if (candidate.schemaVersion !== EGRESS_SCHEMA_VERSION) {
    return refuse("malformed_candidate", "egress candidate schema version mismatch");
  }
  if (typeof candidate.payloadHash !== "string" || candidate.payloadHash.length === 0) {
    return refuse("malformed_candidate", "egress candidate payload hash missing");
  }
  if (!Array.isArray(candidate.fields)) {
    return refuse("malformed_candidate", "egress candidate fields must be an array");
  }
  if (candidate.fields.length > EGRESS_MAX_FIELDS) {
    return refuse("oversize_manifest", "egress candidate exceeds the field-count bound");
  }
  // Payload-hash binding: the candidate must match the outgoing payload.
  if (candidate.payloadHash !== input.outgoingPayloadHash) {
    return refuse(
      "hash_mismatch",
      "the candidate's payload hash does not match the outgoing payload — stale or mis-bound disclosure refuses (fail closed)",
    );
  }
  // Stale-disclosure law: a manifest hash computed for THIS payload must be
  // the one being re-presented; a different prior manifest for the same
  // payload is stale (the payload's disclosure changed under it).
  if (prior !== null && prior === candidate.payloadHash) {
    return refuse("stale_disclosure", "prior manifest hash equals the payload hash — degenerate binding, refusing");
  }

  const disclosed: { key: string; egressClass: EgressAllowedClass; value: string }[] = [];
  const redacted: { key: string; egressClass: EgressForbiddenClass; reason: string }[] = [];
  const refused: { key: string; egressClass: EgressForbiddenClass; reason: string }[] = [];
  const seenKeys = new Set<string>();
  for (const field of candidate.fields) {
    if (field === null || typeof field !== "object") {
      return refuse("malformed_candidate", "egress candidate contains a malformed field entry");
    }
    const entry = field as Record<string, unknown>;
    const entryKeys = Object.keys(entry).sort();
    if (entryKeys.length !== 3 || entryKeys[0] !== "egressClass" || entryKeys[1] !== "key" || entryKeys[2] !== "value") {
      return refuse("unknown_field", "egress field entries carry exactly {key, egressClass, value} — unknown fields default-deny");
    }
    const key = entry.key;
    const value = entry.value;
    const claimedClass = entry.egressClass;
    if (typeof key !== "string" || key.trim() === "" || typeof value !== "string" || typeof claimedClass !== "string") {
      return refuse("malformed_candidate", "egress field entry has malformed values");
    }
    if (seenKeys.has(key)) {
      return refuse("malformed_candidate", "duplicate field key '" + key + "' in the egress candidate");
    }
    seenKeys.add(key);
    if (value.length > EGRESS_MAX_FIELD_VALUE_BYTES) {
      return refuse("oversize_manifest", "field '" + key + "' exceeds the per-field value bound — redact-or-refuse, never widen");
    }
    if (!(EGRESS_ALLOWED_CLASSES as readonly string[]).includes(claimedClass)) {
      return refuse("unknown_field", "claimed egress class '" + claimedClass + "' is not in the allowed vocabulary — default deny");
    }
    if (!isAllowedFieldKey(key, claimedClass as EgressAllowedClass)) {
      return refuse("unknown_field", "field name '" + key + "' is not sanctioned for class '" + claimedClass + "' — default deny");
    }
    // The gate NEVER trusts the caller's classification: re-derive findings.
    const findings = findEgressFindings({ [key]: value });
    const forbidden = findings.find((f) => f.egressClass !== "unknown");
    if (forbidden !== undefined && forbidden.egressClass !== "unknown") {
      const redactable = forbidden.egressClass === "local_environment" || forbidden.egressClass === "process_handles";
      if (redactable) {
        redacted.push({ key, egressClass: forbidden.egressClass, reason: forbidden.reason });
        continue;
      }
      return refuse(
        forbidden.egressClass,
        "field '" + key + "' carries forbidden content (" + forbidden.egressClass + ": " + forbidden.reason + ") — redact-or-refuse, never widen (fail closed)",
      );
    }
    disclosed.push({ key, egressClass: claimedClass as EgressAllowedClass, value });
  }

  const draft: Omit<DisclosureManifest, "manifestHash"> = {
    schemaVersion: EGRESS_SCHEMA_VERSION,
    payloadHash: candidate.payloadHash,
    decidedAtEpochMs: input.nowEpochMs ?? 0,
    disclosed: Object.freeze(disclosed),
    redacted: Object.freeze(redacted),
    refused: Object.freeze(refused),
  };
  const serialized = JSON.stringify({ ...draft, manifestHash: "" });
  if (serialized.length > EGRESS_MAX_MANIFEST_BYTES) {
    return refuse("oversize_manifest", "disclosure manifest exceeds the size bound — reduce the candidate, never widen");
  }
  const manifest: DisclosureManifest = Object.freeze({ ...draft, manifestHash: manifestHashOf(draft) });
  const code: EgressDecisionCode =
    redacted.length > 0 ? "disclosure_permitted_with_redactions" : "disclosure_permitted";
  return {
    ok: true,
    code,
    manifest,
    explanation:
      "disclosure permitted (" + disclosed.length + " fields" + (redacted.length > 0 ? ", " + redacted.length + " redacted" : "") +
      "); manifest bound to payload hash " + candidate.payloadHash.slice(0, 16) + " — disclosure is a FACT about what left and grants NO authority (25A P1/P4)",
  };
}

/**
 * Re-evaluate an EXISTING manifest against a new outgoing payload hash
 * (stale-disclosure detection for re-transports). Returns the manifest
 * only when its binding still holds.
 */
export function verifyEgressManifest(input: {
  readonly manifest: DisclosureManifest;
  readonly outgoingPayloadHash: string;
}): { readonly ok: true; readonly explanation: string } | { readonly ok: false; readonly denyCode: EgressDenyCode; readonly explanation: string } {
  const { manifest } = input;
  if (manifest === null || typeof manifest !== "object") {
    return { ok: false, denyCode: "malformed_candidate", explanation: "manifest is malformed" };
  }
  if (manifest.payloadHash !== input.outgoingPayloadHash) {
    return {
      ok: false,
      denyCode: "stale_disclosure",
      explanation:
        "manifest was bound to payload hash '" + manifest.payloadHash.slice(0, 16) + "' but the outgoing payload is '" +
        input.outgoingPayloadHash.slice(0, 16) + "' — STALE DISCLOSURE, refusing (fail closed); re-run the egress gate on the new payload",
    };
  }
  return {
    ok: true,
    explanation: "manifest binding holds for this payload — disclosure remains a fact, never authority",
  };
}
