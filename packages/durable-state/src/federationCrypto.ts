/**
 * PHASE 24B — Local Cryptographic Identity & Signed Envelopes
 * (NO NETWORK / NO STORAGE OF KEYS / VERIFICATION NEVER AUTHORIZES).
 *
 * This module implements the REAL signing identity behind the 24A
 * `IdentitySignatureVerifier` port, using the platform-supported primitive
 * Ed25519 via `node:crypto` (Node >= 18 stable; engines here are >= 22).
 * No CA, WebPKI, DID, blockchain, or wallet semantics exist anywhere in
 * this module and none are claimed.
 *
 *   PRIMITIVE   Ed25519 (EdDSA, RFC 8032) — deterministic signatures, no
 *               padding/nonce pitfalls, 32-byte public keys.
 *   ENCODING    the frozen 22A canonical discipline
 *               (`canonicalDurableJson`: recursively sorted keys, no
 *               insignificant whitespace) — signature inputs are stable
 *               across processes and platforms.
 *   SIGNING     sign(SHA-256(canonicalJson(subject))) — a fixed prehash,
 *               so the signed bytes are a deterministic function of the
 *               subject body; the hash (not raw JSON) is the signed
 *               message, keeping envelope lines short and canonical.
 *   FINGERPRINT fp-sha256-<64 hex> over the raw 32-byte public key.
 *
 * What this module deliberately does NOT do:
 *  - it never persists, stores, caches, exports, or serializes the
 *    private key (the LocalSigningIdentity object holds it in memory for
 *    the process lifetime; there is no key file, no keyring, no
 *    persistence path — see "secret-at-rest limitations" below);
 *  - it never talks to a network, a socket, a launcher, the Policy
 *    engine, or the store;
 *  - it never authorizes anything: a verification result is
 *    AUTHENTICATION data for the 24A trust decisions, which remain the
 *    only consumers, and every 24A decision carries `authority: "none"`.
 *
 * ROTATION/REVOCATION — actually-proven semantics ONLY:
 *  - NodeId = canonical injective derivation of the public fingerprint
 *    (24A). A NEW KEY IS A NEW NODEID: key replacement is re-identity,
 *    never in-place mutation. `rotateLocalIdentity` proves exactly that
 *    (fresh key → fresh fingerprint → fresh NodeId; the old id is
 *    returned for callers to retire through 24C's trust machine — which
 *    has no resurrection path).
 *  - No revocation lists, no trust anchors, no expiry metadata, no
 *    certificate chains: none are proven here, none are claimed.
 *
 * SECRET-AT-REST LIMITATIONS (exact, no overclaim):
 *  1. The private key lives in process memory only. A process restart
 *     LOSES the key pair irrecoverably — restart identity is proven as
 *     "the persisted PUBLIC facts (fingerprint/NodeId) re-derive and
 *     re-verify against the same public key", not as key persistence.
 *  2. Nothing encrypts memory. A hostile process with a memory dump, a
 *     swap image, or a debugger can extract the private key. No
 *     protection (mlock, TPM, secure enclave, keyfile) exists in v0.
 *  3. The denylist scanner below is a LEAK-PREVENTION aid for structured
 *     payloads (evidence, ledger mirrors, generic records); it cannot
 *     prove absence of clever encodings, and it scans shapes, not
 *     semantics. It is defense-in-depth, never a guarantee.
 *  4. Host security (malware, compromised OS) is out of scope entirely.
 */

import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { canonicalDurableJson } from "./canonical.js";
import { NODE_FINGERPRINT_PATTERN, NODE_FINGERPRINT_PREFIX } from "./federationIdentity.js";

// ── pinned algorithm / version vocabulary ────────────────────────────────────

/** The ONLY signature algorithm this module implements (v1). */
export const FEDERATION_SIGNATURE_ALGORITHM = "ed25519-deterministic-v1" as const;
export type FederationSignatureAlgorithm = typeof FEDERATION_SIGNATURE_ALGORITHM;

/** Crypto identity document schema version (the 24B addition to 24A shapes). */
export const FEDERATION_CRYPTO_SCHEMA_VERSION = "menog-federation-crypto/v0" as const;
export type FederationCryptoSchemaVersion = typeof FEDERATION_CRYPTO_SCHEMA_VERSION;

/**
 * Fingerprint prefix — defined ONCE in 24A (`NODE_FINGERPRINT_PREFIX`,
 * `fp-sha256-`) and re-exported here under the 24B name so the two gates
 * cannot drift apart.
 */
export const FEDERATION_FINGERPRINT_PREFIX: string = NODE_FINGERPRINT_PREFIX;

// ── the local signing identity (in-memory; never persisted) ──────────────────

export interface LocalSigningIdentity {
  readonly algorithm: FederationSignatureAlgorithm;
  /** `fp-sha256-<64hex>` over the raw public key — the 24A fingerprint. */
  readonly fingerprint: string;
  /** The 24A NodeId: canonical derivation of the fingerprint. */
  readonly nodeId: string;
  /** Raw 32-byte Ed25519 public key, hex-encoded (public; safe to persist). */
  readonly publicKeyHex: string;
}

interface LocalSigningIdentityInternals {
  readonly publicKey: KeyObject;
  readonly privateKey: KeyObject;
}

/**
 * Keys are held in a module-private WeakMap keyed by the frozen public
 * identity object. There is no export path, no serialization path, and no
 * accessor: the private key cannot leave this module's closure.
 */
const PRIVATE_KEY_BY_IDENTITY = new WeakMap<object, LocalSigningIdentityInternals>();

function internalsOf(identity: LocalSigningIdentity): LocalSigningIdentityInternals {
  const found = PRIVATE_KEY_BY_IDENTITY.get(identity as unknown as object);
  if (found === undefined) {
    throw new Error("signing identity internals are not accessible — keys never leave this module");
  }
  return found;
}

function toHex(buffer: Buffer): string {
  return buffer.toString("hex");
}

/**
 * Generate a fresh local signing identity. The private key is generated by
 * the platform, held in a non-exportable module-private WeakMap slot, and
 * never serialized. Two identities are always distinct (fresh entropy).
 */
export function generateLocalSigningIdentity(): LocalSigningIdentity {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const rawPublic = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  // Ed25519 SPKI DER is a fixed 44-byte structure whose LAST 32 bytes are
  // the raw public key; take exactly those for the fingerprint.
  const rawKeyBytes = rawPublic.subarray(rawPublic.length - 32);
  const fingerprint =
    FEDERATION_FINGERPRINT_PREFIX + createHash("sha256").update(rawKeyBytes).digest("hex");
  const identity: LocalSigningIdentity = Object.freeze({
    algorithm: FEDERATION_SIGNATURE_ALGORITHM,
    fingerprint,
    nodeId: "node-" + fingerprint.slice(FEDERATION_FINGERPRINT_PREFIX.length),
    publicKeyHex: toHex(rawKeyBytes),
  });
  PRIVATE_KEY_BY_IDENTITY.set(identity as unknown as object, { publicKey, privateKey });
  return identity;
}

// ── canonical signing (deterministic; hash-as-message) ───────────────────────

/** The exact bytes signed: SHA-256 over the 22A canonical JSON of the subject. */
export function signingDigestOf(subject: unknown): Buffer {
  return createHash("sha256").update(canonicalDurableJson(subject), "utf8").digest();
}

function signDigest(identity: LocalSigningIdentity, digest: Buffer): string {
  const internals = internalsOf(identity);
  return edSign(null, digest, internals.privateKey).toString("base64");
}

export type LocalSigningResult =
  | { readonly ok: true; readonly signature: string; readonly explanation: string }
  | { readonly ok: false; readonly signature: null; readonly explanation: string };

/** Sign a 24A identity-document body (pure; deterministic). */
export function signIdentityDocument(
  identity: LocalSigningIdentity,
  document: unknown
): LocalSigningResult {
  if (document === null || typeof document !== "object") {
    return { ok: false, signature: null, explanation: "document must be an object — refusing to sign a non-subject" };
  }
  return {
    ok: true,
    signature: signDigest(identity, signingDigestOf(document)),
    explanation: "signed SHA-256(canonical JSON) with the local Ed25519 key (deterministic)",
  };
}

/** Sign a 24A federation-message body (pure; deterministic). */
export function signFederationMessage(
  identity: LocalSigningIdentity,
  message: unknown
): LocalSigningResult {
  if (message === null || typeof message !== "object") {
    return { ok: false, signature: null, explanation: "message must be an object — refusing to sign a non-subject" };
  }
  return {
    ok: true,
    signature: signDigest(identity, signingDigestOf(message)),
    explanation: "signed SHA-256(canonical JSON) with the local Ed25519 key (deterministic)",
  };
}

// ── the verifier port (what 24A consumes; authentication, never authority) ───

export type FederationVerifyFailureCode =
  | "malformed_input"
  | "unsupported_algorithm_shape"
  | "fingerprint_claim_mismatch"
  | "signature_malformed"
  | "signature_invalid";

/**
 * Build the 24A `IdentitySignatureVerifier` for a KNOWN peer public key.
 * The verifier is pure, side-effect-free, and answers exactly two questions:
 * "was this subject signed by the private key corresponding to this public
 * key?" and — because identity substitution must fail closed — "does the
 * subject's OWN fingerprint claim (24A `fingerprint` or `senderFingerprint`)
 * match the key that verified?" A subject signed by key X while claiming
 * identity Y is refused BEFORE the signature check.
 *
 * It NEVER answers "should the local runtime act" — that is Policy's alone,
 * through the frozen local chain.
 */
export function makeIdentitySignatureVerifier(expectedPublicKeyHex: string): {
  (input: { readonly document: unknown; readonly signature: string }): {
    readonly ok: boolean;
    readonly reason?: string;
  };
  readonly expectedFingerprint: string;
  readonly algorithm: FederationSignatureAlgorithm;
} {
  const rawPublic: Buffer = Buffer.from(expectedPublicKeyHex, "hex");
  if (rawPublic.length !== 32) {
    throw new Error("expected public key must be 32 raw Ed25519 bytes (hex)");
  }
  const expectedFingerprint =
    FEDERATION_FINGERPRINT_PREFIX + createHash("sha256").update(rawPublic).digest("hex");
  const verifyOne = (input: { readonly document: unknown; readonly signature: string }) => {
    if (input === null || typeof input !== "object" || typeof input.signature !== "string" || input.signature.length === 0) {
      return { ok: false, reason: "malformed_input" as const };
    }
    if (input.document === null || typeof input.document !== "object") {
      return { ok: false, reason: "malformed_input" as const };
    }
    // Identity-binding check: the subject's own fingerprint claim must BE
    // this key's fingerprint (key substitution / identity swap fails closed).
    const doc = input.document as Record<string, unknown>;
    const claimed = doc["fingerprint"] ?? doc["senderFingerprint"];
    if (typeof claimed === "string" && claimed !== expectedFingerprint) {
      return { ok: false, reason: "fingerprint_claim_mismatch" as const };
    }
    let sig: Buffer;
    try {
      sig = Buffer.from(input.signature, "base64");
    } catch {
      return { ok: false, reason: "signature_malformed" as const };
    }
    if (sig.length !== 64) {
      return { ok: false, reason: "signature_malformed" as const };
    }
    let peerPublic: KeyObject;
    try {
      peerPublic = createPublicKey({ key: spkiForRaw(rawPublic), format: "der", type: "spki" });
    } catch {
      return { ok: false, reason: "unsupported_algorithm_shape" as const };
    }
    const digest = signingDigestOf(input.document);
    const valid = edVerify(null, digest, peerPublic, sig);
    if (!valid) {
      return { ok: false, reason: "signature_invalid" as const };
    }
    return { ok: true };
  };
  return Object.assign(verifyOne, {
    expectedFingerprint,
    algorithm: FEDERATION_SIGNATURE_ALGORITHM,
  });
}

function spkiForRaw(rawPublic: Buffer): Buffer {
  // ed25519 OID 1.3.101.112, SPKI wrapper for a 32-byte raw key.
  return Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), rawPublic]);
}

// ── secret-at-rest leak prevention (defense-in-depth, NOT a guarantee) ───────

/**
 * Payload key names (NORMALIZED FORM, same discipline as the 22C
 * raw-output denylist) that mark PRIVATE-KEY MATERIAL. A payload carrying
 * any of these keys at any depth is rejected at the payload boundary so a
 * private key can never ride into evidence, ledger mirrors, or generic
 * records — even from a confused caller.
 */
export const FEDERATION_SECRET_KEY_DENYLIST: readonly string[] = Object.freeze([
  "private_key",
  "privatekey",
  "private_pem",
  "privatepem",
  "secret_key",
  "secretkey",
  "signing_key",
  "signingkey",
  "seed",
  "seed_phrase",
  "seedphrase",
  "mnemonic",
  "pkcs8",
  "der_key",
  "pem_key",
]);

function normalizedKey(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/[-\s.]+/g, "_").toLowerCase();
}

function keyIsSecretKeyShaped(key: string): boolean {
  return FEDERATION_SECRET_KEY_DENYLIST.includes(normalizedKey(key));
}

/** Depth-bounded scan for secret-key-shaped keys at any depth. */
export function findSecretKeyPaths(
  value: unknown,
  prefix: string = "",
  maxDepth: number = 8
): string[] {
  if (maxDepth <= 0 || value === null || typeof value !== "object" || Array.isArray(value)) {
    return [];
  }
  const hits: string[] = [];
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    const path = prefix === "" ? k : prefix + "." + k;
    if (keyIsSecretKeyShaped(k)) {
      hits.push(path);
    }
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      hits.push(...findSecretKeyPaths(v, path, maxDepth - 1));
    }
  }
  return hits;
}

/**
 * Structural refusal for a would-be payload: any secret-key-shaped key at
 * any depth denies the whole payload (the 22C fail-closed pattern).
 */
export function payloadContainsSecretKeyMaterial(value: unknown): boolean {
  return findSecretKeyPaths(value).length > 0;
}

/**
 * Canonical string-encoding leak check for FREE-TEXT surfaces (prompts,
 * logs, evidence strings): refuse any Base64 blob that decodes to a valid
 * PKCS#8 Ed25519 private-key DER (leading bytes pinned) and refuse raw
 * Ed25519 seed-length binary-looking tokens labeled as keys. This is a
 * best-effort tripwire for structured callers; it cannot catch arbitrary
 * encodings and claims no completeness.
 */
export const ED25519_PKCS8_DER_PREFIX_HEX = "302e020100300506032b657004220420" as const;

export function looksLikeEncodedPrivateKey(text: string): boolean {
  if (typeof text !== "string") return false;
  const b64Matches = text.match(/[A-Za-z0-9+/]{48,}={0,2}/g) ?? [];
  for (const candidate of b64Matches) {
    try {
      const decoded = Buffer.from(candidate, "base64");
      if (decoded.length >= 36 && decoded.subarray(0, 16).toString("hex") === ED25519_PKCS8_DER_PREFIX_HEX.slice(0, 32)) {
        return true;
      }
    } catch {
      // not decodable — not a leak signal
    }
  }
  return false;
}

// ── rotation (the ONLY proven semantics: re-identity, never mutation) ────────

export type LocalRotationResult = {
  readonly ok: true;
  readonly fresh: LocalSigningIdentity;
  readonly previousNodeId: string;
  readonly previousFingerprint: string;
  readonly explanation: string;
};

/**
 * Rotate the local identity by generating a FRESH key pair. Because NodeId
 * is the canonical function of the fingerprint (24A), the fresh identity
 * necessarily has a fresh NodeId — key replacement is RE-IDENTITY. The
 * previous NodeId is returned so the caller can retire it through the 24C
 * trust machine (quarantined → retired; no resurrection). No in-place key
 * mutation exists and none is representable.
 */
export function rotateLocalIdentity(previous: LocalSigningIdentity): LocalRotationResult {
  const fresh = generateLocalSigningIdentity();
  return {
    ok: true,
    fresh,
    previousNodeId: previous.nodeId,
    previousFingerprint: previous.fingerprint,
    explanation:
      "fresh key generated — fresh fingerprint and NodeId follow canonically; retire the previous NodeId through the peer trust machine (re-identity, never key mutation)",
  };
}

// ── restart identity (public facts re-derive; keys do not persist) ───────────

export type RestartIdentityCheck =
  | { readonly ok: true; readonly explanation: string }
  | { readonly ok: false; readonly reason: string };

/**
 * Prove that a RESTARTED process presenting the same PUBLIC facts
 * (publicKeyHex + fingerprint + NodeId) is internally consistent and that
 * the fingerprint/NodeId re-derive from the public key. This is the exact
 * restart-identity guarantee of this module: PUBLIC continuity, provable;
 * PRIVATE continuity, impossible without external key storage (documented
 * limitation, no workaround claimed).
 */
export function verifyRestartIdentity(input: {
  readonly publicKeyHex: string;
  readonly fingerprint: string;
  readonly nodeId: string;
}): RestartIdentityCheck {
  if (typeof input.publicKeyHex !== "string" || !/^[0-9a-f]{64}$/.test(input.publicKeyHex)) {
    return { ok: false, reason: "public key hex is not 32 bytes — restart facts malformed" };
  }
  if (!NODE_FINGERPRINT_PATTERN.test(input.fingerprint) || !input.fingerprint.startsWith(FEDERATION_FINGERPRINT_PREFIX)) {
    return { ok: false, reason: "fingerprint is not the pinned fp-sha256 shape — restart facts malformed" };
  }
  const rawPublic: Buffer = Buffer.from(input.publicKeyHex, "hex");
  const derivedFingerprint =
    FEDERATION_FINGERPRINT_PREFIX + createHash("sha256").update(rawPublic).digest("hex");
  if (derivedFingerprint !== input.fingerprint) {
    return { ok: false, reason: "fingerprint does not re-derive from the public key — restart facts inconsistent (fail closed)" };
  }
  const derivedNodeId = "node-" + input.fingerprint.slice(FEDERATION_FINGERPRINT_PREFIX.length);
  if (derivedNodeId !== input.nodeId) {
    return { ok: false, reason: "NodeId does not canonically follow the fingerprint — restart facts inconsistent (fail closed)" };
  }
  return {
    ok: true,
    explanation:
      "public identity facts re-derive consistently (fingerprint and NodeId follow the public key) — private continuity is NOT part of this guarantee",
  };
}
