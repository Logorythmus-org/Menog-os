/**
 * PHASE 27D — Capability Advertisement (UNTRUSTED REMOTE CLAIMS / BOUNDED /
 * VERSIONED / PROVENANCE-RICH / ADVERTISEMENT != GRANT / NO NETWORK).
 *
 * This module is the LOCAL registry for capability advertisements: bounded,
 * versioned, provenance-rich records of what some node CLAIMS it can do.
 * Every record is an UNTRUSTED REMOTE CLAIM recorded as DATA — the registry
 * stores claims, it never honors them.
 *
 * THE LAWS IT ENFORCES
 *   · ADVERTISEMENT != CAPABILITY GRANT (27A M5) — every successful decision
 *     carries grant: "none" as a STRUCTURAL LITERAL; the registry has no
 *     capability, authority, Policy, trust, or execution field on any
 *     record, no method that widens agent/tool/Policy/isolation capability,
 *     and no union/merge surface over claims (the prototype method set is
 *     pinned by tests; extra input fields are DROPPED, never stored).
 *   · CLAIMS CANNOT WIDEN — recording, rotating, or replaying claims changes
 *     only stored knowledge; rotation REPLACES the previous claim set
 *     outright (old claims are dropped, never accumulated).
 *   · BOUNDED — frozen constants cap total advertisements, per-claimant
 *     advertisements, claims per advertisement, and string field sizes.
 *     A caller may exceed a bound, never redefine one; refusals never
 *     evict, never grow past a bound.
 *   · VERSIONED — every advertisement carries an integer version >= 1.
 *     A NEW advertisement must start at version 1 (no gap). Rotation must
 *     be the IMMEDIATE next version (no skipped versions), must come from
 *     the same claiming node (no claimant hijack), and must carry strictly
 *     fresher provenance time than what is stored. Same-version re-sends
 *     are replays: identical content => idempotent no-op; different content
 *     => conflict refuses. Older versions are stale and refuse — a rotated-
 *     out claim never comes back.
 *   · PROVENANCE-RICH — records enter ONLY from local configuration or
 *     governed evidence (closed vocabulary; unknown_source refuses;
 *     governed evidence MUST cite its evidence id, local configuration
 *     MUST NOT pretend to), and every decision carries a provenance hash.
 *   · MATERIAL REJECTION — every string surface (ids, claims, detail,
 *     provenance) is scanned for secret material, executable material,
 *     and other forbidden content — including JSON-NESTED payloads parsed
 *     at depth, so a secret key cannot hide inside a JSON string — BEFORE
 *     anything is recorded; any finding refuses the whole advertisement.
 *   · 27A COMPOSITION — claim vocabulary and anonymity are decided by the
 *     frozen 27A advertisement decision; this registry adds bounds,
 *     versioning, rotation, replay and provenance on top and propagates
 *     27A refusals unchanged.
 *
 * SCOPE LAW: LOCAL-ONLY. No discovery/scanning/mDNS/broadcast/gossip
 * membership/WAN/Internet/cloud relay/NAT traversal/UPnP/tunnel/consensus/
 * global authority; no socket, no listener, no spawn, no clock (caller-
 * supplied epochs only), no store access (in-memory bounded registry only);
 * no alternate listener/spawn/persist/control path. Observability is
 * read-only (snapshot/fingerprint), never control.
 *
 * Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
 * Separation law: PEER != PATH != TOPOLOGY != TRUST != AUTHORITY != EXECUTION.
 */

import { canonicalHash } from "./canonical.js";
import { findEgressFindings } from "./federationEgress.js";
import {
  decideMeshAdvertisement,
  type MeshAdvertisementKind,
  type MeshCapabilityClaim,
  type MeshRefusalCode,
} from "./meshTopologyTrust.js";

/** Capability-advertisement registry schema version (27D). */
export const CAPABILITY_ADVERTISEMENT_SCHEMA_VERSION =
  "menog-mesh-capability-advertisement/v0" as const;
export type CapabilityAdvertisementSchemaVersion =
  typeof CAPABILITY_ADVERTISEMENT_SCHEMA_VERSION;

// ── frozen bounds (callers may exceed, never redefine) ───────────────────────

/**
 * Hard caps on the advertisement registry. Refusal, never eviction, past a
 * bound; a caller may send MORE, it can never redefine a bound.
 */
export const ADVERTISEMENT_REGISTRY_BOUNDS = Object.freeze({
  maxAdvertisements: 64,
  maxAdvertisementsPerClaimant: 8,
  maxClaimsPerAdvertisement: 4,
  maxAdvertisementIdChars: 128,
  maxClaimantIdChars: 128,
  maxDetailChars: 512,
});
export type AdvertisementBoundName =
  keyof typeof ADVERTISEMENT_REGISTRY_BOUNDS;

// ── provenance vocabulary (closed — the ONLY sanctioned sources) ─────────────

/**
 * The closed provenance sources for an advertisement RECORD (how the LOCAL
 * node came to hold the claim — NOT how much the claim is trusted). Same
 * law as the 27B topology graph: knowledge enters only from explicit local
 * configuration or governed evidence; `unknown_source` exists so an unnamed
 * source can be REFUSED (fail closed), never recorded.
 */
export const ADVERTISEMENT_PROVENANCE_SOURCES = Object.freeze([
  "local_configuration",
  "governed_evidence",
  "unknown_source",
] as const);
export type AdvertisementProvenanceSource =
  (typeof ADVERTISEMENT_PROVENANCE_SOURCES)[number];

/**
 * Provenance attached to every stored advertisement: which sanctioned
 * source produced the record, the evidence it cites (governed evidence
 * MUST cite one; local configuration MUST NOT pretend to), and the
 * caller-supplied time it was recorded.
 */
export interface AdvertisementProvenance {
  readonly source: AdvertisementProvenanceSource;
  readonly evidenceId: string | null;
  readonly recordedAtEpochMs: number;
}

// ── record vocabulary ────────────────────────────────────────────────────────

/**
 * Caller-supplied capability advertisement (input). `kind` is validated:
 * this registry stores capability advertisements ONLY — any other 27A kind
 * refuses before it can masquerade as a capability claim.
 */
export interface CapabilityAdvertisementInput {
  readonly advertisementId: string;
  readonly claimingNodeId: string;
  readonly kind: MeshAdvertisementKind;
  readonly capabilityClaims: readonly MeshCapabilityClaim[];
  readonly version: number;
  readonly detail: string;
  readonly provenance: AdvertisementProvenance;
  readonly observedAtEpochMs: number;
}

/**
 * A stored advertisement: the input fields PLUS the content hash binding
 * them together. No capability, authority, Policy, trust, or execution
 * field exists here — a stored claim is knowledge, never a grant.
 */
export interface StoredCapabilityAdvertisement
  extends CapabilityAdvertisementInput {
  readonly contentHash: string;
}

// ── refusal vocabulary (closed) ──────────────────────────────────────────────

/** Closed capability-advertisement refusal codes (fail-closed; no silent handling). */
export const CAPABILITY_ADVERTISEMENT_REFUSAL_CODES = Object.freeze([
  "refused_invalid_advertisement",
  "refused_wrong_advertisement_kind",
  "refused_unknown_advertisement_kind",
  "refused_unknown_provenance_source",
  "refused_invalid_provenance",
  "refused_oversize_field",
  "refused_claim_inflation",
  "refused_secret_material",
  "refused_executable_material",
  "refused_forbidden_material",
  "refused_anonymous_claim",
  "refused_unknown_capability_claim",
  "refused_claimant_mismatch",
  "refused_stale_version",
  "refused_version_conflict",
  "refused_version_gap",
  "refused_stale_fact",
  "refused_claimant_bound",
  "refused_registry_bound",
  "refused_unknown",
] as const);
export type CapabilityAdvertisementRefusalCode =
  (typeof CAPABILITY_ADVERTISEMENT_REFUSAL_CODES)[number];

// ── decisions ────────────────────────────────────────────────────────────────

/**
 * Outcome of recording one advertisement. Successful decisions carry
 * `grant: "none"` and `capabilitiesWidened: false` as STRUCTURAL LITERALS:
 * accepting a claim never grants anything and never widens any local
 * capability (ADVERTISEMENT != GRANT, no union — 27A M5 + 27D).
 */
export type CapabilityAdvertisementDecision =
  | {
      readonly ok: true;
      readonly code:
        | "advertisement_recorded"
        | "advertisement_rotated"
        | "advertisement_replayed";
      readonly grant: "none";
      readonly capabilitiesWidened: false;
      readonly advertisementCount: number;
      readonly storedVersion: number;
      readonly explanation: string;
      readonly provenanceHash: string;
    }
  | {
      readonly ok: false;
      readonly code: "advertisement_refused";
      readonly refusal: CapabilityAdvertisementRefusalCode;
      readonly advertisementCount: number;
      readonly explanation: string;
      readonly provenanceHash: string;
    };

// ── refusal explanations (every refusal is explained; no silent handling) ────

const REFUSAL_EXPLANATIONS: Readonly<
  Record<CapabilityAdvertisementRefusalCode, string>
> = Object.freeze({
  refused_invalid_advertisement:
    "invalid advertisement — refusing (fail closed); a malformed record cannot be bounded, versioned, or audited",
  refused_wrong_advertisement_kind:
    "wrong advertisement kind — refusing (fail closed); this registry stores capability advertisements ONLY (ADVERTISEMENT != GRANT applies to capability claims specifically)",
  refused_unknown_advertisement_kind:
    "unknown advertisement kind — refusing (fail closed) under the frozen 27A contract; an unnamed kind cannot ride through as DATA",
  refused_unknown_provenance_source:
    "unknown provenance source — refusing (fail closed); a record enters ONLY from explicit local configuration or governed evidence, so an unnamed source is never recorded (no discovery, no gossip, no unnamed channel)",
  refused_invalid_provenance:
    "invalid provenance — refusing (fail closed); governed evidence must cite its evidence id and local configuration must not pretend to",
  refused_oversize_field:
    "field over frozen bound — refusing (fail closed); a caller may exceed a bound, never redefine one; never truncate, never evict",
  refused_claim_inflation:
    "claim inflation — refusing (fail closed); claim sets are bounded and duplicate-free, so a claimant can never pad or repeat claims to appear more capable",
  refused_secret_material:
    "secret material in advertisement payload — refusing (fail closed); claims are DATA and secret material never rides into the registry, including nested inside JSON strings",
  refused_executable_material:
    "executable material in advertisement payload — refusing (fail closed); a claim is never a command",
  refused_forbidden_material:
    "forbidden material in advertisement payload — refusing (fail closed); local paths, handles, raw output, and policy text are not claim content",
  refused_anonymous_claim:
    "anonymous claim — refusing (fail closed) under the frozen 27A contract; an unattributed claim cannot even be evaluated as DATA",
  refused_unknown_capability_claim:
    "unknown capability claim — refusing (fail closed) under the frozen 27A contract; claims outside the closed vocabulary are never stored",
  refused_claimant_mismatch:
    "claimant mismatch — refusing (fail closed); an advertisement id belongs to its claiming node and can never be re-claimed by another node (no hijack, no overwrite)",
  refused_stale_version:
    "stale version — refusing (fail closed); an older version can never supersede stored knowledge, and a rotated-out claim never comes back",
  refused_version_conflict:
    "version conflict — refusing (fail closed); the same version with different content is a replay of a DIFFERENT claim and never overwrites what is stored",
  refused_version_gap:
    "version gap — refusing (fail closed); versions advance by exactly one, so no unseen claim can be skipped into the registry",
  refused_stale_fact:
    "stale rotation fact — refusing (fail closed); a rotation must carry strictly fresher provenance time and never-older observation time than what is stored",
  refused_claimant_bound:
    "per-claimant advertisement bound reached — refusing (fail closed); never evict, never grow past a frozen bound",
  refused_registry_bound:
    "registry advertisement bound reached — refusing (fail closed); never evict, never grow past a frozen bound",
  refused_unknown:
    "unmapped advertisement condition — refusing (fail closed)",
});

/** Map a frozen 27A refusal onto this registry's closed vocabulary. */
function mapMeshRefusal(
  refusal: MeshRefusalCode,
): CapabilityAdvertisementRefusalCode {
  switch (refusal) {
    case "refused_anonymous_claim":
      return "refused_anonymous_claim";
    case "refused_unknown_capability_claim":
      return "refused_unknown_capability_claim";
    case "refused_unknown_advertisement_kind":
      return "refused_unknown_advertisement_kind";
    default:
      return "refused_unknown";
  }
}

// ── provenance validation (pinned order step 1) ──────────────────────────────

/**
 * Validate provenance BEFORE anything else: the source must be in the
 * closed vocabulary (and not `unknown_source`), governed evidence must
 * cite an evidence id, local configuration must not pretend to, and the
 * recorded time must be a finite non-negative number. Returns the refusal
 * code, or null when valid.
 */
function validateAdvertisementProvenance(
  provenance: unknown,
): CapabilityAdvertisementRefusalCode | null {
  const candidate = provenance as Partial<AdvertisementProvenance> | null;
  if (
    candidate === null ||
    typeof candidate !== "object" ||
    typeof candidate.source !== "string" ||
    !(
      (ADVERTISEMENT_PROVENANCE_SOURCES as readonly string[]).includes(
        candidate.source,
      )
    ) ||
    candidate.source === "unknown_source"
  ) {
    return "refused_unknown_provenance_source";
  }
  if (candidate.source === "governed_evidence") {
    if (typeof candidate.evidenceId !== "string" || candidate.evidenceId.length === 0) {
      return "refused_invalid_provenance";
    }
  } else if (candidate.evidenceId !== null) {
    return "refused_invalid_provenance";
  }
  if (
    typeof candidate.recordedAtEpochMs !== "number" ||
    !Number.isFinite(candidate.recordedAtEpochMs) ||
    candidate.recordedAtEpochMs < 0
  ) {
    return "refused_invalid_provenance";
  }
  return null;
}

// ── the bounded, versioned registry ────────────────────────────────────────────────

/**
 * The capability-advertisement registry: ONE bounded in-memory state
 * object. Every mutation goes through `record`, which validates in a
 * pinned order (first match wins) and leaves the registry EXACTLY as it
 * was on any refusal. Claims are stored as UNTRUSTED DATA with
 * `grant: "none"` — recording one grants nothing and widens nothing.
 */
export class CapabilityAdvertisementRegistry {
  readonly #advertisements = new Map<string, StoredCapabilityAdvertisement>();

  private constructor() {}

  /**
   * Open an empty registry. Opening cannot fail: bounds and vocabularies
   * are frozen constants, so there is no configuration to reject.
   */
  static open(): CapabilityAdvertisementRegistry {
    return new CapabilityAdvertisementRegistry();
  }

  get advertisementCount(): number {
    return this.#advertisements.size;
  }

  has(advertisementId: string): boolean {
    return this.#advertisements.has(advertisementId);
  }

  get(advertisementId: string): StoredCapabilityAdvertisement | null {
    return this.#advertisements.get(advertisementId) ?? null;
  }

  /**
   * Record one capability advertisement (untrusted remote claim, DATA).
   * Pinned validation order (first match wins):
   *   1. provenance source in the closed vocabulary (unknown refuses)
   *   2. provenance shape (evidence rules + finite recorded time)
   *   3. record shape (ids, integer version >= 1, finite observed time,
   *      claims array, string detail — malformed refuses)
   *   4. field bounds (id/detail char caps; claim count cap and
   *      duplicate-free — inflation refuses)
   *   5. material scan over EVERY string surface (secret / executable /
   *      forbidden material refuses — including JSON-nested payloads,
   *      parsed at depth)
   *   6. frozen 27A decision (anonymous claim, closed claim vocabulary,
   *      unknown kind refuse) + capability-kind-only gate
   *   7. registry state:
   *      a. existing id from ANOTHER claimant => hijack refuses
   *      b. same version: identical content => replay idempotent;
   *         different content => conflict refuses
   *      c. lower version => stale refuses (rotated-out claims never return)
   *      d. version jump (not exactly +1) => gap refuses
   *      e. rotation (+1): strictly fresher provenance time and never-older
   *         observation time required, else stale fact refuses; the old
   *         claim set is REPLACED (never unioned)
   *      f. new id: version must be 1, per-claimant bound, then registry
   *         bound (refuse, never evict)
   *      g. record added
   * Any refusal leaves the registry EXACTLY as it was.
   */
  record(input: CapabilityAdvertisementInput): CapabilityAdvertisementDecision {
    const contentHash = canonicalHash({
      schemaVersion: CAPABILITY_ADVERTISEMENT_SCHEMA_VERSION,
      advertisementId: input.advertisementId,
      claimingNodeId: input.claimingNodeId,
      kind: input.kind,
      capabilityClaims: input.capabilityClaims,
      version: input.version,
      detail: input.detail,
      provenance: input.provenance,
      observedAtEpochMs: input.observedAtEpochMs,
    });
    const counts = (): { advertisementCount: number } => ({
      advertisementCount: this.#advertisements.size,
    });
    const refuse = (
      refusal: CapabilityAdvertisementRefusalCode,
      explanation?: string,
    ): CapabilityAdvertisementDecision => ({
      ok: false,
      code: "advertisement_refused",
      refusal,
      ...counts(),
      explanation: explanation ?? REFUSAL_EXPLANATIONS[refusal],
      provenanceHash: contentHash,
    });

    // 1–2. provenance (closed source + shape) before anything else
    const provenanceCheck = validateAdvertisementProvenance(input.provenance);
    if (provenanceCheck !== null) {
      return refuse(provenanceCheck);
    }
    // 3. record shape (claimingNodeId emptiness is 27A's law, step 6)
    if (
      typeof input.advertisementId !== "string" ||
      input.advertisementId.length === 0 ||
      typeof input.claimingNodeId !== "string" ||
      typeof input.kind !== "string" ||
      typeof input.detail !== "string" ||
      !Array.isArray(input.capabilityClaims) ||
      !Number.isSafeInteger(input.version) ||
      input.version < 1 ||
      typeof input.observedAtEpochMs !== "number" ||
      !Number.isFinite(input.observedAtEpochMs) ||
      input.observedAtEpochMs < 0
    ) {
      return refuse(
        "refused_invalid_advertisement",
        "malformed advertisement — refusing (fail closed); a malformed record cannot be bounded, versioned, or audited",
      );
    }
    // 4. frozen bounds — inflation refuses, never truncates
    if (
      input.advertisementId.length > ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisementIdChars ||
      input.claimingNodeId.length > ADVERTISEMENT_REGISTRY_BOUNDS.maxClaimantIdChars ||
      input.detail.length > ADVERTISEMENT_REGISTRY_BOUNDS.maxDetailChars
    ) {
      return refuse("refused_oversize_field");
    }
    if (
      input.capabilityClaims.length >
      ADVERTISEMENT_REGISTRY_BOUNDS.maxClaimsPerAdvertisement
    ) {
      return refuse(
        "refused_claim_inflation",
        "claim count over the frozen bound — refusing (fail closed); a claimant can never appear more capable by sending more claims",
      );
    }
    if (new Set(input.capabilityClaims).size !== input.capabilityClaims.length) {
      return refuse(
        "refused_claim_inflation",
        "duplicate claims in one advertisement — refusing (fail closed); repeated claims are inflation and never pad a claim set",
      );
    }
    // 5. material scan over every string surface (JSON-nested payloads are
    // parsed at depth by the egress classifier, so a secret key cannot hide
    // inside a JSON string)
    const findings = findEgressFindings({
      advertisementId: input.advertisementId,
      claimingNodeId: input.claimingNodeId,
      kind: input.kind,
      capabilityClaims: input.capabilityClaims,
      detail: input.detail,
      provenance: input.provenance,
    });
    const firstFinding = findings[0];
    if (firstFinding !== undefined) {
      if (firstFinding.egressClass === "secret_material") {
        return refuse(
          "refused_secret_material",
          "secret material in advertisement payload (" +
            firstFinding.field +
            ": " +
            firstFinding.reason +
            ") — refusing (fail closed); claims are DATA and secret material never rides into the registry",
        );
      }
      if (firstFinding.egressClass === "executable_material") {
        return refuse(
          "refused_executable_material",
          "executable material in advertisement payload (" +
            firstFinding.field +
            ": " +
            firstFinding.reason +
            ") — refusing (fail closed); a claim is never a command",
        );
      }
      return refuse(
        "refused_forbidden_material",
        "forbidden material in advertisement payload (" +
          firstFinding.field +
          ": " +
          firstFinding.reason +
          ") — refusing (fail closed)",
      );
    }
    // 6. frozen 27A contract: anonymity, closed claim vocabulary, known kind
    const meshDecision = decideMeshAdvertisement({
      advertisement: {
        advertisementId: input.advertisementId,
        kind: input.kind,
        claimingNodeId: input.claimingNodeId,
        capabilityClaims: input.capabilityClaims,
        observedAtEpochMs: input.observedAtEpochMs,
      },
      observedAtEpochMs: input.observedAtEpochMs,
    });
    if (!meshDecision.ok) {
      return refuse(mapMeshRefusal(meshDecision.refusal));
    }
    if (input.kind !== "capability_advertisement") {
      return refuse(
        "refused_wrong_advertisement_kind",
        "advertisement kind '" +
          input.kind +
          "' is a valid 27A kind but NOT a capability advertisement — refusing (fail closed); capability claims are the only claims this registry stores",
      );
    }
    // 7. registry state
    const existing = this.#advertisements.get(input.advertisementId);
    if (existing !== undefined) {
      if (existing.claimingNodeId !== input.claimingNodeId) {
        return refuse(
          "refused_claimant_mismatch",
          "advertisement '" +
            input.advertisementId +
            "' is owned by claimant '" +
            existing.claimingNodeId +
            "' but was presented by '" +
            input.claimingNodeId +
            "' — refusing (fail closed); an advertisement id can never be re-claimed by another node",
        );
      }
      if (input.version === existing.version) {
        if (contentHash === existing.contentHash) {
          return {
            ok: true,
            code: "advertisement_replayed",
            grant: "none",
            capabilitiesWidened: false,
            ...counts(),
            storedVersion: existing.version,
            explanation:
              "advertisement '" +
              input.advertisementId +
              "' re-presented at version " +
              existing.version +
              " with IDENTICAL content — replay is idempotent (no-op, counts unchanged); grant stays 'none' and nothing is widened",
            provenanceHash: contentHash,
          };
        }
        return refuse(
          "refused_version_conflict",
          "advertisement '" +
            input.advertisementId +
            "' is stored at version " +
            existing.version +
            " with DIFFERENT content — a same-version conflict refuses and never overwrites (fail closed; first evidenced claim stands)",
        );
      }
      if (input.version < existing.version) {
        return refuse(
          "refused_stale_version",
          "advertisement '" +
            input.advertisementId +
            "' presented at version " +
            input.version +
            " but version " +
            existing.version +
            " is stored — a stale version refuses (fail closed); a rotated-out claim never comes back",
        );
      }
      if (input.version > existing.version + 1) {
        return refuse(
          "refused_version_gap",
          "advertisement '" +
            input.advertisementId +
            "' jumps from stored version " +
            existing.version +
            " to " +
            input.version +
            " — refusing (fail closed); versions advance by exactly one so no unseen claim can skip into the registry",
        );
      }
      // rotation: exactly existing.version + 1, with fresher facts
      if (
        !(input.provenance.recordedAtEpochMs > existing.provenance.recordedAtEpochMs) ||
        input.observedAtEpochMs < existing.observedAtEpochMs
      ) {
        return refuse(
          "refused_stale_fact",
          "rotation of advertisement '" +
            input.advertisementId +
            "' does not carry strictly fresher provenance time and never-older observation time — refusing (fail closed); stale facts never rotate stored knowledge",
        );
      }
      const rotated: StoredCapabilityAdvertisement = Object.freeze({
        advertisementId: input.advertisementId,
        claimingNodeId: input.claimingNodeId,
        kind: input.kind,
        capabilityClaims: Object.freeze([...input.capabilityClaims]),
        version: input.version,
        detail: input.detail,
        provenance: Object.freeze({ ...input.provenance }),
        observedAtEpochMs: input.observedAtEpochMs,
        contentHash,
      });
      this.#advertisements.set(input.advertisementId, rotated);
      return {
        ok: true,
        code: "advertisement_rotated",
        grant: "none",
        capabilitiesWidened: false,
        ...counts(),
        storedVersion: input.version,
        explanation:
          "advertisement '" +
          input.advertisementId +
          "' rotated to version " +
          input.version +
          " — the previous claim set is REPLACED, never unioned (no capability accumulation); grant stays 'none'",
        provenanceHash: contentHash,
      };
    }
    // new advertisement id
    if (input.version !== 1) {
      return refuse(
        "refused_version_gap",
        "new advertisement '" +
          input.advertisementId +
          "' presented at version " +
          input.version +
          " — refusing (fail closed); a NEW advertisement must start at version 1 so its whole version history is observable",
      );
    }
    let claimantCount = 0;
    for (const stored of this.#advertisements.values()) {
      if (stored.claimingNodeId === input.claimingNodeId) {
        claimantCount += 1;
      }
    }
    if (
      claimantCount >= ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisementsPerClaimant
    ) {
      return refuse(
        "refused_claimant_bound",
        "claimant '" +
          input.claimingNodeId +
          "' already holds " +
          claimantCount +
          " advertisement(s) at the per-claimant bound " +
          ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisementsPerClaimant +
          " — refusing (fail closed); never evict, never grow past a frozen bound",
      );
    }
    if (this.#advertisements.size >= ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisements) {
      return refuse(
        "refused_registry_bound",
        "registry bound " +
          ADVERTISEMENT_REGISTRY_BOUNDS.maxAdvertisements +
          " reached — a new advertisement refuses (never evict, never grow past the frozen bound; a caller may exceed a bound, never redefine one)",
      );
    }
    const stored: StoredCapabilityAdvertisement = Object.freeze({
      advertisementId: input.advertisementId,
      claimingNodeId: input.claimingNodeId,
      kind: input.kind,
      capabilityClaims: Object.freeze([...input.capabilityClaims]),
      version: input.version,
      detail: input.detail,
      provenance: Object.freeze({ ...input.provenance }),
      observedAtEpochMs: input.observedAtEpochMs,
      contentHash,
    });
    this.#advertisements.set(input.advertisementId, stored);
    return {
      ok: true,
      code: "advertisement_recorded",
      grant: "none",
      capabilitiesWidened: false,
      ...counts(),
      storedVersion: input.version,
      explanation:
        "advertisement '" +
        input.advertisementId +
        "' recorded as UNTRUSTED REMOTE CLAIM DATA from " +
        input.provenance.source +
        " at version 1 — ADVERTISEMENT != GRANT: grant is 'none' by construction, no local capability widened, no claim unioned",
      provenanceHash: contentHash,
    };
  }

  /**
   * Frozen, canonically ordered snapshot (by advertisementId) — read-only
   * knowledge. Independent of insertion order: two registries holding the
   * same records snapshot identically and fingerprint identically.
   */
  snapshot(): readonly StoredCapabilityAdvertisement[] {
    const records = [...this.#advertisements.values()]
      .sort((a, b) =>
        a.advertisementId < b.advertisementId ? -1 : a.advertisementId > b.advertisementId ? 1 : 0,
      )
      .map((r) =>
        Object.freeze({
          ...r,
          capabilityClaims: Object.freeze([...r.capabilityClaims]),
          provenance: Object.freeze({ ...r.provenance }),
        }),
      );
    return Object.freeze(records);
  }

  /**
   * Deterministic canonical fingerprint of the registry's knowledge
   * (order-insensitive): identical records in any order, same fingerprint.
   * Pure; no I/O; no clock.
   */
  fingerprint(): string {
    const contentHashes = [...this.#advertisements.values()]
      .map((r) => r.contentHash)
      .sort();
    return canonicalHash({
      schemaVersion: CAPABILITY_ADVERTISEMENT_SCHEMA_VERSION,
      advertisementCount: this.#advertisements.size,
      contentHashes,
    });
  }
}
