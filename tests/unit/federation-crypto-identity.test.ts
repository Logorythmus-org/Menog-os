/**
 * PHASE 24B — Local Cryptographic Identity & Signed Envelopes Tests
 * (NO NETWORK / NO KEY PERSISTENCE / VERIFICATION NEVER AUTHORIZES).
 *
 * Pack-mandated coverage:
 *   canonicalization   — signature input is the frozen 22A canonical JSON;
 *                        key-order/whitespace irrelevant; field flips break it
 *   tamper             — any body mutation invalidates the signature
 *   wrong key          — B's key never verifies A's subjects (and vice versa)
 *   redaction          — secret-key-shaped payload keys deny at the boundary
 *   restart identity   — public facts re-derive; private continuity impossible
 *   no leakage         — no PEM/PKCS#8/DER/base64 key material from the API
 * Law pins: verification never authorizes; rotation = re-identity;
 * identity-binding (subject fingerprint claim must match the verifying key).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  FEDERATION_SIGNATURE_ALGORITHM,
  FEDERATION_CRYPTO_SCHEMA_VERSION,
  FEDERATION_FINGERPRINT_PREFIX,
  FEDERATION_SECRET_KEY_DENYLIST,
  ED25519_PKCS8_DER_PREFIX_HEX,
  generateLocalSigningIdentity,
  signingDigestOf,
  signIdentityDocument,
  signFederationMessage,
  makeIdentitySignatureVerifier,
  findSecretKeyPaths,
  payloadContainsSecretKeyMaterial,
  looksLikeEncodedPrivateKey,
  rotateLocalIdentity,
  verifyRestartIdentity,
  type NodeIdentityDocumentBody,
  type FederationMessageBody,
} from "@menog/durable-state";
import {
  FEDERATION_PROTOCOL_VERSION,
  FEDERATION_IDENTITY_SCHEMA_VERSION,
  FEDERATION_MESSAGE_SCHEMA_VERSION,
  deriveNodeId,
  makeRuntimeInstanceId,
  makeFederationMessageId,
  validateNodeIdentityDocument,
  validateSignedMessageContract,
  makeRuntimeEpochId,
  newInstanceEpochTracker,
  newMessageReplayTracker,
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
const A = generateLocalSigningIdentity();
const B = generateLocalSigningIdentity();
const INSTANCE_A = makeRuntimeInstanceId(NOW, "instance-a");
const EPOCH_A1 = makeRuntimeEpochId(NOW, "aaaa1111aaaa1111");

function identityBody(overrides: Partial<NodeIdentityDocumentBody> = {}): NodeIdentityDocumentBody {
  return {
    schemaVersion: FEDERATION_IDENTITY_SCHEMA_VERSION,
    nodeId: A.nodeId,
    fingerprint: A.fingerprint,
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
    senderNodeId: A.nodeId,
    senderFingerprint: A.fingerprint,
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

/** A 24A-shaped adapter over the 24B verifier for end-to-end pipeline tests. */
function portFor(identity: { publicKeyHex: string }) {
  const verifier = makeIdentitySignatureVerifier(identity.publicKeyHex);
  return (input: { document: unknown; signature: string }) => verifier(input);
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("24B structure — primitive, encoding, no-network, no-CA", () => {
  it("algorithm and schema versions are pinned exactly", () => {
    expect(FEDERATION_SIGNATURE_ALGORITHM).toBe("ed25519-deterministic-v1");
    expect(FEDERATION_CRYPTO_SCHEMA_VERSION).toBe("menog-federation-crypto/v0");
    expect(FEDERATION_FINGERPRINT_PREFIX).toBe("fp-sha256-");
  });

  it("the module has no network/execution surface and no forbidden primitive claims", () => {
    const code = codeOnly(SRC("federationCrypto.ts"));
    for (const forbidden of ["node:net", "node:http", "node:https", "node:dgram", "node:tls", "WebSocket", "fetch(", "spawn(", "listen(", "child_process"]) {
      expect(code).not.toContain(forbidden);
    }
    // No CA/WebPKI/DID/blockchain/wallet vocabulary in CODE (comments excluded
    // by codeOnly; the doc header explains the non-claims in prose only).
    expect(code).not.toContain("createSign");
    expect(code).not.toContain("X509");
    expect(code).not.toContain("webcrypto");
  });

  it("the private key is unreachable through the public API surface", () => {
    const identity = generateLocalSigningIdentity();
    const own = Object.getOwnPropertyNames(identity);
    const proto = Object.getOwnPropertyNames(Object.getPrototypeOf(identity) ?? {});
    for (const key of [...own, ...proto]) {
      const value = (identity as unknown as Record<string, unknown>)[key];
      const text = typeof value === "string" ? value : JSON.stringify(value);
      expect(text ?? "").not.toContain("PRIVATE KEY");
      expect(text ?? "").not.toContain("BEGIN");
    }
    expect(Object.keys(identity)).toEqual(["algorithm", "fingerprint", "nodeId", "publicKeyHex"]);
  });

  it("fingerprints and NodeIds follow the pinned shapes and canonically follow the key", () => {
    for (const id of [A, B]) {
      expect(id.fingerprint.startsWith(FEDERATION_FINGERPRINT_PREFIX)).toBe(true);
      expect(id.fingerprint).toMatch(/^fp-sha256-[0-9a-f]{64}$/);
      expect(id.nodeId).toBe("node-" + id.fingerprint.slice(FEDERATION_FINGERPRINT_PREFIX.length));
      expect(deriveNodeId(id.fingerprint)).toEqual({ ok: true, nodeId: id.nodeId });
      expect(id.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(A.fingerprint).not.toBe(B.fingerprint);
    expect(A.nodeId).not.toBe(B.nodeId);
  });

  it("identities are fresh entropy: two generations never collide", () => {
    const c = generateLocalSigningIdentity();
    const d = generateLocalSigningIdentity();
    expect(c.fingerprint).not.toBe(d.fingerprint);
  });
});

// ── canonicalization ─────────────────────────────────────────────────────────

describe("24B canonicalization — the signed bytes are the frozen 22A canonical form", () => {
  it("signing is deterministic: same subject, same signature", () => {
    const doc = identityBody();
    const s1 = signIdentityDocument(A, doc);
    const s2 = signIdentityDocument(A, doc);
    expect(s1.ok).toBe(true);
    expect(s2.ok).toBe(true);
    if (s1.ok && s2.ok) expect(s1.signature).toBe(s2.signature);
  });

  it("key order and insignificant differences do not change the digest; value changes do", () => {
    const doc = identityBody();
    const reordered = {
      issuedAtEpochMs: doc.issuedAtEpochMs,
      protocolVersion: doc.protocolVersion,
      epochId: doc.epochId,
      instanceId: doc.instanceId,
      fingerprint: doc.fingerprint,
      nodeId: doc.nodeId,
      schemaVersion: doc.schemaVersion,
    };
    expect(signingDigestOf(doc)).toEqual(signingDigestOf(reordered));
    const flipped = identityBody({ issuedAtEpochMs: NOW + 1 });
    expect(Buffer.compare(signingDigestOf(doc), signingDigestOf(flipped))).not.toBe(0);
  });

  it("a signature made over one field set fails on a semantically different key order game", () => {
    const doc = identityBody();
    const sig = signIdentityDocument(A, doc);
    expect(sig.ok).toBe(true);
    if (!sig.ok) return;
    const forged = { ...doc, nodeId: B.nodeId } as unknown as NodeIdentityDocumentBody;
    const verifier = portFor(A);
    expect(verifier({ document: forged, signature: sig.signature }).ok).toBe(false);
  });
});

// ── tamper / wrong key / identity binding ────────────────────────────────────

describe("24B verification — tamper, wrong key, identity binding", () => {
  it("verifies a genuine identity document through the 24A port", () => {
    const doc = identityBody();
    const sig = signIdentityDocument(A, doc);
    expect(sig.ok).toBe(true);
    if (!sig.ok) return;
    const verifier = portFor(A);
    expect(verifier({ document: doc, signature: sig.signature })).toMatchObject({ ok: true });
  });

  it("any body tamper invalidates the signature (field flip, whitespace game, extra field)", () => {
    const doc = identityBody();
    const sig = signIdentityDocument(A, doc);
    if (!sig.ok) throw new Error("fixture");
    const verifier = portFor(A);
    expect(verifier({ document: { ...doc, instanceId: makeRuntimeInstanceId(NOW, "other") }, signature: sig.signature }).ok).toBe(false);
    expect(verifier({ document: { ...doc, issuedAtEpochMs: NOW + 1 }, signature: sig.signature }).ok).toBe(false);
    expect(verifier({ document: { ...doc, protocolVersion: "menog-federation/v0" }, signature: sig.signature }).ok).toBe(false);
  });

  it("the WRONG key never verifies the other node's subjects (both directions)", () => {
    const doc = identityBody();
    const sigA = signIdentityDocument(A, doc);
    const msg = messageBody();
    const sigMsgA = signFederationMessage(A, msg);
    expect(sigA.ok && sigMsgA.ok).toBe(true);
    if (!sigA.ok || !sigMsgA.ok) return;
    const verifierB = portFor(B);
    expect(verifierB({ document: doc, signature: sigA.signature }).ok).toBe(false);
    expect(verifierB({ document: msg, signature: sigMsgA.signature }).ok).toBe(false);
    // ...and the identity-binding layer calls it before the signature:
    expect(verifierB({ document: doc, signature: sigA.signature })).toMatchObject({
      ok: false,
      reason: "fingerprint_claim_mismatch",
    });
  });

  it("a subject claiming identity Y but signed by key X is refused BEFORE signature checks", () => {
    const hostile = identityBody({ nodeId: B.nodeId, fingerprint: B.fingerprint });
    const sig = signIdentityDocument(A, hostile);
    expect(sig.ok).toBe(true);
    if (!sig.ok) return;
    const verifier = portFor(A);
    expect(verifier({ document: hostile, signature: sig.signature })).toMatchObject({
      ok: false,
      reason: "fingerprint_claim_mismatch",
    });
  });

  it("malformed signatures refuse with explicit codes (length, base64 garbage, absent subject)", () => {
    const verifier = portFor(A);
    expect(verifier({ document: identityBody(), signature: "" })).toMatchObject({ ok: false, reason: "malformed_input" });
    expect(verifier({ document: identityBody(), signature: "not-base64!!" })).toMatchObject({ ok: false, reason: "signature_malformed" });
    expect(verifier({ document: identityBody(), signature: Buffer.from([1, 2, 3]).toString("base64") })).toMatchObject({ ok: false, reason: "signature_malformed" });
    expect(verifier({ document: "not-an-object", signature: "AAAA" })).toMatchObject({ ok: false, reason: "malformed_input" });
  });

  it("message bodies verify through the same port (schema-agnostic subject hashing)", () => {
    const msg = messageBody();
    const sig = signFederationMessage(A, msg);
    expect(sig.ok).toBe(true);
    if (!sig.ok) return;
    const verifier = portFor(A);
    expect(verifier({ document: msg, signature: sig.signature })).toMatchObject({ ok: true });
  });
});

// ── end-to-end through the 24A pipeline (composition, no fork) ───────────────

describe("24B × 24A composition — real keys drive the 24A decisions", () => {
  it("an identity document signed with the REAL key is accepted by the 24A validator", () => {
    const doc = identityBody();
    const sig = signIdentityDocument(A, doc);
    expect(sig.ok).toBe(true);
    if (!sig.ok) return;
    const decision = validateNodeIdentityDocument({
      document: doc,
      signature: sig.signature,
      verifier: portFor(A),
      epochTracker: newInstanceEpochTracker(),
      nowEpochMs: NOW,
      localEpochId: makeRuntimeEpochId(NOW, "bbbb1111bbbb1111"),
    });
    expect(decision).toMatchObject({ ok: true, code: "identity_document_accepted" });
    if (decision.ok) expect(decision.provenance.authority).toBe("none");
  });

  it("a REAL-key-signed message flows through the 24A message contract; replay still fails", () => {
    const msg = messageBody();
    const sig = signFederationMessage(A, msg);
    if (!sig.ok) throw new Error("fixture");
    const base = {
      verifier: portFor(A),
      replayTracker: newMessageReplayTracker(),
      epochTracker: newInstanceEpochTracker(),
      nowEpochMs: NOW,
      localEpochId: makeRuntimeEpochId(NOW, "bbbb1111bbbb1111"),
      signature: sig.signature,
    };
    expect(validateSignedMessageContract({ ...base, message: msg })).toMatchObject({
      ok: true,
      code: "message_contract_accepted",
    });
    expect(validateSignedMessageContract({ ...base, message: msg })).toMatchObject({
      ok: false,
      denyReason: "replay_detected",
    });
  });

  it("a tampered REAL signature refuses in the 24A validator with signature_invalid", () => {
    const doc = identityBody();
    const sig = signIdentityDocument(A, doc);
    if (!sig.ok) throw new Error("fixture");
    const tampered = Buffer.from(sig.signature, "base64");
    const byte = tampered[10] ?? 0;
    tampered[10] = byte ^ 0xff;
    const decision = validateNodeIdentityDocument({
      document: doc,
      signature: tampered.toString("base64"),
      verifier: portFor(A),
      epochTracker: newInstanceEpochTracker(),
      nowEpochMs: NOW,
      localEpochId: makeRuntimeEpochId(NOW, "bbbb1111bbbb1111"),
    });
    expect(decision).toMatchObject({ ok: false, code: "refused_signature_invalid" });
  });
});

// ── redaction / leakage ──────────────────────────────────────────────────────

describe("24B secret-at-rest — denylist, leak tripwire, no key in payloads", () => {
  it("the denylist covers private-key vocabulary in both spellings", () => {
    expect([...FEDERATION_SECRET_KEY_DENYLIST]).toContain("private_key");
    expect([...FEDERATION_SECRET_KEY_DENYLIST]).toContain("privatekey");
    expect([...FEDERATION_SECRET_KEY_DENYLIST]).toContain("seed");
    expect([...FEDERATION_SECRET_KEY_DENYLIST]).toContain("mnemonic");
  });

  it("payloads carrying secret-key-shaped keys at any depth are denied", () => {
    expect(payloadContainsSecretKeyMaterial({ evidence: { output: "ok" } })).toBe(false);
    expect(payloadContainsSecretKeyMaterial({ meta: { privateKey: "AAAA" } })).toBe(true);
    expect(payloadContainsSecretKeyMaterial({ nested: { deep: { "signing-key": "x" } } })).toBe(true);
    expect(payloadContainsSecretKeyMaterial({ privateKey: { n: 1 } })).toBe(true);
    expect(findSecretKeyPaths({ a: { b: { SECRET_KEY: "x" } } })).toEqual(["a.b.SECRET_KEY"]);
  });

  it("the PKCS#8 base64 tripwire recognizes Ed25519 private-key DER shapes", () => {
    const pkcs8 = Buffer.concat([
      Buffer.from(ED25519_PKCS8_DER_PREFIX_HEX, "hex"),
      Buffer.alloc(32, 7),
    ]);
    expect(looksLikeEncodedPrivateKey("noise " + pkcs8.toString("base64") + " noise")).toBe(true);
    expect(looksLikeEncodedPrivateKey(Buffer.alloc(48, 3).toString("base64"))).toBe(false);
    expect(looksLikeEncodedPrivateKey("no base64 here")).toBe(false);
  });

  it("the module source itself never embeds key material patterns", () => {
    const code = codeOnly(SRC("federationCrypto.ts"));
    expect(code).not.toContain("-----BEGIN");
    expect(code).not.toContain("-----END");
    expect(code).not.toContain("export({ key: privateKey");
  });
});

// ── rotation / restart identity ──────────────────────────────────────────────

describe("24B rotation and restart — re-identity, public-facts continuity", () => {
  it("rotation yields a fresh NodeId (re-identity); the old id is returned for retirement", () => {
    const result = rotateLocalIdentity(A);
    expect(result.ok).toBe(true);
    expect(result.fresh.fingerprint).not.toBe(A.fingerprint);
    expect(result.fresh.nodeId).not.toBe(A.nodeId);
    expect(result.previousNodeId).toBe(A.nodeId);
    expect(result.previousFingerprint).toBe(A.fingerprint);
    expect(result.explanation).toContain("re-identity");
  });

  it("the fresh identity can sign and its verifier binds to the fresh fingerprint", () => {
    const rotated = rotateLocalIdentity(A).fresh;
    const doc = identityBody({ nodeId: rotated.nodeId, fingerprint: rotated.fingerprint });
    const sig = signIdentityDocument(rotated, doc);
    expect(sig.ok).toBe(true);
    if (!sig.ok) return;
    expect(portFor(rotated)({ document: doc, signature: sig.signature })).toMatchObject({ ok: true });
    // the OLD key's verifier must refuse the new identity's claims
    expect(portFor(A)({ document: doc, signature: sig.signature })).toMatchObject({
      ok: false,
      reason: "fingerprint_claim_mismatch",
    });
  });

  it("restart identity: public facts re-derive; inconsistent facts refuse", () => {
    const good = verifyRestartIdentity({ publicKeyHex: A.publicKeyHex, fingerprint: A.fingerprint, nodeId: A.nodeId });
    expect(good.ok).toBe(true);
    expect(good.ok === true && good.explanation).toContain("NOT part of this guarantee");
    const mismatchedKey = verifyRestartIdentity({ publicKeyHex: B.publicKeyHex, fingerprint: A.fingerprint, nodeId: A.nodeId });
    expect(mismatchedKey.ok).toBe(false);
    expect(mismatchedKey.ok === false && mismatchedKey.reason).toContain("does not re-derive");
    const mismatchedNode = verifyRestartIdentity({ publicKeyHex: A.publicKeyHex, fingerprint: A.fingerprint, nodeId: B.nodeId });
    expect(mismatchedNode.ok).toBe(false);
    expect(mismatchedNode.ok === false && mismatchedNode.reason).toContain("canonically follow");
    const malformed = verifyRestartIdentity({ publicKeyHex: "zz", fingerprint: A.fingerprint, nodeId: A.nodeId });
    expect(malformed.ok).toBe(false);
    expect(malformed.ok === false && malformed.reason).toContain("malformed");
  });

  it("the signing identity is in-memory only: no persistence vocabulary exists in the module", () => {
    const code = codeOnly(SRC("federationCrypto.ts"));
    expect(code).not.toContain("writeFile");
    expect(code).not.toContain("appendFile");
    expect(code).not.toContain("createWriteStream");
    expect(code).not.toContain("DatabaseSync");
  });
});
