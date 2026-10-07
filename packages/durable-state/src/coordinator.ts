/**
 * PHASE 23B — Runtime State Coordinator & Durability Barrier
 * (NARROW IMPLEMENTATION / FAIL-CLOSED).
 *
 * The ONE sanctioned live→durable coordination junction. It ORCHESTRATES
 * persistence of accepted live mutations through the frozen 22B store and
 * emits the frozen 23A DurabilityBarrier vocabulary. It is NEITHER Policy
 * NOR execution authority: it never evaluates policy, never executes
 * anything, never grants anything — persistence here grants no authority
 * (23A L1). There is no alternate persistence path: every live→durable
 * write flows through acceptMutation → store.persist → barrier → the 23A
 * admission law (scan-pinned by the 23B suite).
 *
 * Laws inherited from 23A and enforced HERE on live wiring:
 * - L4: durability is NEVER acknowledged before the formal barrier — the
 *   barrier is constructed ONLY from the store's own PersistDecision
 *   (`committed:true` + real commitSequence → acknowledged barrier;
 *   any denial/rollback/error → refused or ambiguous, never visible).
 * - L5: stale epochs/owners are rejected BEFORE any mutation is staged:
 *   the coordinator binds to one epoch at open, re-checks the durable
 *   ownership claim on every call, and refuses everything on mismatch.
 * - L8: derived kinds are refused (reusing the 23A runtime set).
 * - Durable failure has an explicit live-state outcome:
 *     typed pre-commit refusal → `refused_pre_commit` (nothing happened;
 *         the STORE's failure code is carried verbatim — no renaming)
 *     rollback / engine abort → `unknown_after_error` (never visible,
 *         never healed; 23E kill-window territory)
 * - The 23A `decideContinuity` law is the VISIBILITY admission: even a
 *   store-reported commit that fails the law is treated as unknown and
 *   never shown to a live surface (fail closed in the safe direction).
 * - Reused frozen Phase-22 semantics, no competing vocabulary: revision
 *   chains + transaction-replay denial are the STORE's (22A/22B) decisions;
 *   envelope sealing reuses the frozen 22A canonical hash (no new dialect).
 * - Binding: every accepted mutation is sealed to runtime epoch id,
 *   transaction id, source identity, lineage (lineageRoot/lineageParent)
 *   and the durable revision/content hash — all INSIDE the canonical
 *   envelope body, hence inside the content hash (tamper-evident).
 *
 * No spawn, no network, no replay: this module's only side effect is the
 * store transaction; the structural scan in the 23B suite pins the
 * vocabulary.
 */

import type {
  CommitSequence,
  DurableRecordEnvelope,
  DurableRecordEnvelopeBody,
  DurableRecordId,
  PersistDecision,
  RecordKind,
} from "./records.js";
import {
  DURABLE_RECORD_SCHEMA_VERSION,
} from "./records.js";
import {
  durableContentHash,
} from "./canonical.js";
import {
  DurableStore,
} from "./store.js";
import type {
  ContinuityRecordKind,
  DurabilityBarrier,
  LiveDurableMutation,
  RuntimeEpoch,
} from "./continuity.js";
import {
  DERIVED_CONTINUITY_KINDS,
  RUNTIME_EPOCH_ID_PATTERN,
  acknowledgedBarrier,
  advanceLiveDurableMutation,
  decideContinuity,
  makeDurabilityBarrier,
  makeLiveDurableMutation,
} from "./continuity.js";

// ── schema version ───────────────────────────────────────────────────────────

/** Coordinator contract version: bumped when THIS vocabulary changes. */
export const COORDINATOR_SCHEMA_VERSION = "menog-runtime-coordinator/v0" as const;
export type CoordinatorSchemaVersion = typeof COORDINATOR_SCHEMA_VERSION;

// ── closed vocabularies (23B-specific; 23A/22A vocabularies reused verbatim) ─

/** Outcomes mirror the 23A mutation-outcome union (same names, reused). */
export const COORDINATION_OUTCOMES = Object.freeze([
  "durable",
  "refused_pre_commit",
  "unknown_after_error",
] as const);
export type CoordinationOutcome = (typeof COORDINATION_OUTCOMES)[number];

/**
 * Coordinator-side failure codes (closed). The STORE's own failure codes
 * (22A `PersistFailureCode`) are carried verbatim on refused results —
 * no renaming, no parallel vocabulary.
 */
export const COORDINATION_FAILURE_CODES = Object.freeze([
  "coordinator_closed",
  "stale_epoch",
  "derived_kind_denied",
  "barrier_not_confirmed",
  "store_failure",
] as const);
export type CoordinationFailureCode = (typeof COORDINATION_FAILURE_CODES)[number];

/**
 * Runtime ownership as read from the durable layer, RELATIVE to the
 * viewer's epoch (closed union):
 * - `no_prior_owner`: no live-owner claim is recorded (fresh store).
 * - `owner_current`: the recorded claim belongs to the VIEWER's epoch id
 *   (the crash-resume special case — one process identity re-opening).
 * - `owner_other_live`: the recorded claim belongs to a DIFFERENT epoch id
 *   (or the viewer has no epoch identity). With no heartbeat protocol in
 *   v0, a crashed owner's claim is indistinguishable from a live one, so
 *   ANY other-id claim fails closed — the same epoch id is the ONLY resume
 *   path, exactly as 23A's `same_epoch_id` prior-owner code allows.
 */
export const RUNTIME_OWNERSHIP_CODES = Object.freeze([
  "no_prior_owner",
  "owner_current",
  "owner_other_live",
] as const);
export type RuntimeOwnershipCode = (typeof RUNTIME_OWNERSHIP_CODES)[number];

/** The pinned store_meta key for the live-owner claim (23B-owned). */
export const RUNTIME_OWNERSHIP_META_KEY = "runtime_live_owner_epoch";

// ── ownership read (the pre-mutation owner check) ────────────────────────────

export interface RuntimeOwnershipView {
  readonly code: RuntimeOwnershipCode;
  readonly ownerEpochId: string | null;
  readonly boundSourceIdentity: string | null;
}

/**
 * Read the durable ownership claim DIRECTLY from store_meta (one read,
 * no interpretation beyond the closed mapping). The epoch id is the
 * ownership key; the source string is bound evidence only.
 */
export function readRuntimeOwnership(
  store: DurableStore,
  viewerEpochId: string | null
): RuntimeOwnershipView {
  const raw = store.getMeta(RUNTIME_OWNERSHIP_META_KEY);
  if (raw === null) {
    return { code: "no_prior_owner", ownerEpochId: null, boundSourceIdentity: null };
  }
  const sep = raw.indexOf("|");
  const ownerEpochId = sep === -1 ? raw : raw.slice(0, sep);
  const boundSourceIdentity = sep === -1 ? null : raw.slice(sep + 1);
  if (viewerEpochId !== null && ownerEpochId === viewerEpochId) {
    return { code: "owner_current", ownerEpochId, boundSourceIdentity };
  }
  return { code: "owner_other_live", ownerEpochId, boundSourceIdentity };
}

// ── open result ──────────────────────────────────────────────────────────────

export type CoordinatorOpenResult =
  | {
      readonly ok: true;
      readonly coordinator: RuntimeStateCoordinator;
      readonly ownership: RuntimeOwnershipView;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly failureCode:
        | "coordinator_epoch_invalid"
        | "coordinator_epoch_mismatch"
        | "store_failure";
      readonly reason: string;
    };

// ── the coordinator ──────────────────────────────────────────────────────────

/**
 * The single live→durable coordination junction for ONE epoch over ONE
 * open store. Constructed ONLY through `RuntimeStateCoordinator.open`
 * (fail-closed); it holds NO authority and grants NONE.
 */
export class RuntimeStateCoordinator {
  readonly #store: DurableStore;
  readonly #epochId: string;
  readonly #sourceIdentity: string;
  #closed: boolean = false;

  private constructor(store: DurableStore, epochId: string, sourceIdentity: string) {
    this.#store = store;
    this.#epochId = epochId;
    this.#sourceIdentity = sourceIdentity;
  }

  /**
   * Bind the coordinator to one epoch over one open store. Fail-closed:
   * - the epoch id must be shape-valid (a coordinator with an unidentifiable
   *   owner can never distinguish stale from live epochs);
   * - an existing durable live-owner claim held by a DIFFERENT epoch id
   *   refuses the open (split-brain refused BEFORE any mutation);
   * - the claim key must be writable (store_failure otherwise).
   * An `owner_current` claim (same epoch id — the crash-resume special
   * case) or `no_prior_owner` is (re)bound to this epoch.
   */
  public static open(
    store: DurableStore,
    epoch: RuntimeEpoch,
    sourceIdentity: string
  ): CoordinatorOpenResult {
    if (!RUNTIME_EPOCH_ID_PATTERN.test(epoch.epochId)) {
      return { ok: false, failureCode: "coordinator_epoch_invalid", reason: "epoch id is missing or malformed — refusing to bind a coordinator to an unidentifiable owner" };
    }
    if (typeof sourceIdentity !== "string" || sourceIdentity.length === 0 || sourceIdentity.length > 128) {
      return { ok: false, failureCode: "coordinator_epoch_invalid", reason: "sourceIdentity must be a non-empty string of at most 128 chars" };
    }
    if (!store.isOpen) {
      return { ok: false, failureCode: "store_failure", reason: "store is closed — no coordinator can be bound" };
    }
    const ownership = readRuntimeOwnership(store, epoch.epochId);
    if (ownership.code === "owner_other_live") {
      return {
        ok: false,
        failureCode: "coordinator_epoch_mismatch",
        reason:
          "another epoch id still holds the durable live-owner claim — split-brain refused BEFORE any coordination (stale owners fail closed)",
      };
    }
    const wrote = store.setMeta(RUNTIME_OWNERSHIP_META_KEY, epoch.epochId + "|" + sourceIdentity);
    if (!wrote.ok) {
      return { ok: false, failureCode: "store_failure", reason: wrote.reason ?? "could not bind the live-owner claim" };
    }
    return {
      ok: true,
      coordinator: new RuntimeStateCoordinator(store, epoch.epochId, sourceIdentity),
      ownership,
      explanation:
        ownership.code === "owner_current"
          ? "coordinator bound; existing claim for this epoch accepted (crash-resume of one process identity)"
          : "coordinator bound; durable live-owner claim bound to this epoch",
    };
  }

  public get epochId(): string {
    return this.#epochId;
  }

  public get sourceIdentity(): string {
    return this.#sourceIdentity;
  }

  public get isClosed(): boolean {
    return this.#closed;
  }

  /**
   * THE sanctioned live→durable path (one junction; no alternate exists).
   * The payload is bound — INSIDE the sealed canonical envelope body, hence
   * inside the content hash — to: runtime epoch id, transaction id, source
   * identity, lineage (root + parent), and the durable revision/content
   * hash of the record itself.
   *
   * Durable failure is explicit on the live surface:
   * - typed pre-commit refusal → `refused_pre_commit` (store code verbatim);
   * - rollback / engine abort → `unknown_after_error` (never visible);
   * - committed → `durable`, admitted by the 23A law, formal barrier.
   */
  public acceptMutation(input: {
    readonly kind: ContinuityRecordKind;
    readonly recordId: DurableRecordId;
    readonly revision: number;
    readonly supersedesRevision: number | null;
    readonly payload: Readonly<Record<string, unknown>>;
    readonly transactionId: string;
    readonly lineageRoot: string;
    readonly lineageParent: string | null;
    readonly createdAtEpochMs: number;
  }): CoordinationResult {
    if (this.#closed) {
      return unknownOutcome(null, "coordinator_closed", "the coordinator for this epoch is closed — no further mutations are coordinated");
    }
    // The 23A mutation vocabulary is the ONLY representation of this intent.
    const mutation = makeLiveDurableMutation({
      mutationId: "mut-" + input.transactionId,
      epochId: this.#epochId,
      kind: input.kind,
      recordId: input.recordId,
      atEpochMs: input.createdAtEpochMs,
    });
    // L5 on live wiring: re-check the durable owner claim BEFORE staging.
    const ownership = readRuntimeOwnership(this.#store, this.#epochId);
    if (ownership.code === "owner_other_live") {
      return refusedOutcome(
        mutation,
        "stale_epoch",
        "the durable live-owner claim belongs to another epoch — refusing the mutation before any persistence (stale epoch/owner)",
      );
    }
    // L8 on live wiring: derived kinds never coordinate (the 23A runtime set).
    if (DERIVED_CONTINUITY_KINDS.has(input.kind)) {
      return refusedOutcome(
        mutation,
        "derived_kind_denied",
        "derived kinds are non-authoritative and can never be coordinated as live/durable mutations",
      );
    }
    // Seal the envelope: frozen 22A canonical vocabulary, binding fields
    // inside the hashed body. The store then applies the frozen 22A
    // decisions (revision chain, transaction replay, append-only refusal).
    const envelope = sealMutationEnvelope({
      kind: input.kind,
      recordId: input.recordId,
      revision: input.revision,
      supersedesRevision: input.supersedesRevision,
      transactionId: input.transactionId,
      createdAtEpochMs: input.createdAtEpochMs,
      epochId: this.#epochId,
      sourceIdentity: this.#sourceIdentity,
      lineageRoot: input.lineageRoot,
      lineageParent: input.lineageParent,
      payload: input.payload,
    });
    const decision = this.#store.persist(envelope);
    // Map the store's OWN decision onto the 23A outcomes; the barrier is
    // the ONLY acknowledgement path (L4).
    const barrier = barrierFromPersistDecision(
      "bar-" + input.transactionId,
      this.#epochId,
      decision,
    );
    if (decision.ok && decision.committed) {
      const advanced = advanceLiveDurableMutation(mutation, {
        kind: "barrier_confirmed",
        barrier,
      });
      // The 23A continuity decision is the VISIBILITY admission law. For a
      // committed mutation it must admit; any refusal here is an internal
      // invariant break, and the safe direction is "never visible".
      const admission = decideContinuity({
        epochId: this.#epochId,
        lifecycle: "LIVE",
        mutation: advanced,
      });
      if (!admission.ok || !acknowledgedBarrier(barrier)) {
        return unknownOutcome(
          mutation,
          "barrier_not_confirmed",
          "a store-reported commit failed the 23A admission law — treating the outcome as unknown and never visible (fail closed)",
        );
      }
      return {
        ok: true,
        code: "durable",
        epochId: this.#epochId,
        mutationId: mutation.mutationId,
        transactionId: decision.transactionId,
        commitSequence: decision.commitSequence,
        revision: decision.revision,
        contentHash: envelope.contentHash,
        barrier,
        mutation: advanced,
        explanation: "mutation coordinated through the single junction and acknowledged via the formal durability barrier",
      };
    }
    if (barrier.outcome === "ambiguous") {
      // Engine-level gray zone (abort/rollback/close): nothing is claimed.
      const advanced = advanceLiveDurableMutation(mutation, {
        kind: "store_error",
        reason: decision.ok ? "ambiguous store decision" : decision.reason,
      });
      return {
        ok: false,
        code: "unknown_after_error",
        epochId: this.#epochId,
        mutationId: mutation.mutationId,
        transactionId: decision.transactionId,
        failureCode: "store_failure",
        mutation: advanced,
        explanation: "the store transaction ended ambiguously — the mutation is never visible and never healed (23E owns the kill-window empirics)",
      };
    }
    // Typed pre-commit refusal: the store denied BEFORE any commit; its
    // failure code is carried verbatim (no renaming, no parallel vocabulary).
    const advanced = advanceLiveDurableMutation(mutation, {
      kind: "refused",
      reason: decision.reason,
    });
    return {
      ok: false,
      code: "refused_pre_commit",
      epochId: this.#epochId,
      mutationId: mutation.mutationId,
      transactionId: decision.transactionId,
      failureCode: "store_failure",
      storeFailureCode: decision.failureCode,
      mutation: advanced,
      explanation: decision.reason,
    };
  }

  /**
   * Read the latest revision of a coordinated record (minimal representative
   * live read surface). Returns the same typed failures the store returns
   * (not_found / quarantined / store_closed) — corruption is quarantined by
   * the STORE and surfaced verbatim, never healed here.
   */
  public readState(recordId: DurableRecordId) {
    return this.#store.readRecord(recordId);
  }

  /** Highest durable commit sequence confirmed through this store. */
  public get durablyConfirmedThrough(): CommitSequence {
    return this.#store.committedThrough;
  }

  /**
   * 23D — evidenced ownership transfer to a NEW runtime epoch after
   * recovery. The OLD epoch's claim is superseded BY EVIDENCE, not by
   * takeover: the transfer requires (a) the current claim to exist and
   * belong to the FROM epoch, (b) the TO epoch id to be shape-valid and
   * DIFFERENT (a NEW epoch — self-transfer is refused), and (c) a
   * non-empty justification. The new claim binds the FROM epoch's source
   * identity so the provenance of the supersession stays on record.
   * This is the ONLY path by which a new epoch may acquire a claim held
   * by another id — split-brain refusal remains the law everywhere else.
   */
  public transferOwnership(
    fromEpochId: string,
    toEpoch: RuntimeEpoch,
    justification: string
  ): { readonly ok: true; readonly ownership: RuntimeOwnershipView; readonly explanation: string }
    | { readonly ok: false; readonly code: "coordinator_closed" | "claim_not_current" | "epoch_not_new" | "epoch_invalid" | "justification_required" | "store_failure"; readonly reason: string } {
    if (this.#closed) {
      return { ok: false, code: "coordinator_closed", reason: "the coordinator for this epoch is closed" };
    }
    if (!RUNTIME_EPOCH_ID_PATTERN.test(toEpoch.epochId)) {
      return { ok: false, code: "epoch_invalid", reason: "the target epoch id is missing or malformed" };
    }
    if (toEpoch.epochId === fromEpochId) {
      return { ok: false, code: "epoch_not_new", reason: "ownership transfer requires a NEW epoch id (self-transfer is refused)" };
    }
    if (typeof justification !== "string" || justification.length === 0 || justification.length > 256) {
      return { ok: false, code: "justification_required", reason: "a bounded non-empty justification is required for the evidenced supersession" };
    }
    const ownership = readRuntimeOwnership(this.#store, fromEpochId);
    if (ownership.code !== "owner_current") {
      return { ok: false, code: "claim_not_current", reason: "the FROM epoch does not hold the durable live-owner claim — refusing to transfer an unheld or foreign claim" };
    }
    const wrote = this.#store.setMeta(
      RUNTIME_OWNERSHIP_META_KEY,
      toEpoch.epochId + "|" + this.#sourceIdentity,
    );
    if (!wrote.ok) {
      return { ok: false, code: "store_failure", reason: wrote.reason ?? "could not write the transferred claim" };
    }
    return {
      ok: true,
      ownership: readRuntimeOwnership(this.#store, toEpoch.epochId),
      explanation:
        "live-owner claim transferred from epoch " + fromEpochId + " to NEW epoch " +
        toEpoch.epochId + " (evidenced supersession; provenance source bound)",
    };
  }

  /**
   * Release ownership and unbind the coordinator. Idempotent. Closing does
   * NOT close the store (ownership of the store stays with the runtime);
   * it only removes the durable live-owner claim so a future epoch can
   * bind. After close, every mutation returns outcome `unknown_after_error`.
   */
  public close(): { ok: true } | { ok: false; reason: string } {
    if (this.#closed) return { ok: true };
    this.#closed = true;
    const cleared = this.#store.deleteMeta(RUNTIME_OWNERSHIP_META_KEY);
    if (!cleared.ok) {
      return { ok: false, reason: cleared.reason ?? "could not clear the live-owner claim" };
    }
    return { ok: true };
  }
}

// ── mutation envelope sealing (the binding seam) ─────────────────────────────

export type CoordinatedRecordKind = ContinuityRecordKind;

/**
 * Seal a coordinated mutation as a frozen 22A envelope. Binding fields are
 * carried INSIDE the payload (hence inside the canonical content hash):
 * runtime epoch id, transaction id, source identity, lineage root/parent,
 * and the coordinator's own contract version. A hostile payload carrying
 * its own `coordinatorBinding` key is overridden — the binding is applied
 * last, so the coordinator's binding always wins.
 */
export function sealMutationEnvelope(input: {
  readonly kind: CoordinatedRecordKind;
  readonly recordId: DurableRecordId;
  readonly revision: number;
  readonly supersedesRevision: number | null;
  readonly transactionId: string;
  readonly createdAtEpochMs: number;
  readonly epochId: string;
  readonly sourceIdentity: string;
  readonly lineageRoot: string;
  readonly lineageParent: string | null;
  readonly payload: Readonly<Record<string, unknown>>;
}): DurableRecordEnvelope {
  const durabilityClass =
    input.kind === "event_ledger_entry" ||
    input.kind === "tool_run_evidence" ||
    input.kind === "federation_receipt" ||
    input.kind === "federation_proposal" ||
    input.kind === "federation_provenance"
      ? "append_only"
      : "versioned_mutable";
  const body: DurableRecordEnvelopeBody = {
    schemaVersion: DURABLE_RECORD_SCHEMA_VERSION,
    recordId: input.recordId,
    recordKind: input.kind as RecordKind,
    durabilityClass,
    secretPolicy: "secret_free",
    authority: durabilityClass === "append_only" ? "durable_evidence" : "durable_state",
    revision: input.revision,
    supersedesRevision: input.supersedesRevision,
    createdAtEpochMs: input.createdAtEpochMs,
    transactionId: input.transactionId,
    payload: Object.freeze({
      ...input.payload,
      coordinatorBinding: {
        schemaVersion: COORDINATOR_SCHEMA_VERSION,
        epochId: input.epochId,
        sourceIdentity: input.sourceIdentity,
        lineageRoot: input.lineageRoot,
        lineageParent: input.lineageParent,
      },
    }),
  };
  const contentHash = durableContentHash(body);
  return Object.freeze({ ...body, contentHash });
}

// ── barrier construction (the ONLY ack path) ─────────────────────────────────

/**
 * Map the store's PersistDecision onto the frozen 23A barrier vocabulary —
 * honestly: `committed` ONLY for a real commit with a real commit sequence;
 * `rolled_back` for typed pre-commit denials (the store definitively refused
 * before/without any commit); `ambiguous` for engine-level gray outcomes
 * (abort/rollback/close). There is no fourth shape (L4).
 */
export function barrierFromPersistDecision(
  barrierId: string,
  epochId: string,
  decision: PersistDecision
): DurabilityBarrier {
  if (decision.ok && decision.committed) {
    return makeDurabilityBarrier({
      barrierId,
      epochId,
      outcome: "committed",
      commitSequence: decision.commitSequence,
      transactionId: decision.transactionId,
      atEpochMs: Date.now(),
    });
  }
  const engineGray =
    decision.ok || decision.failureCode === "transaction_aborted" || decision.failureCode === "store_closed";
  return makeDurabilityBarrier({
    barrierId,
    epochId,
    outcome: engineGray ? "ambiguous" : "rolled_back",
    commitSequence: null,
    transactionId: decision.transactionId ?? barrierId,
    atEpochMs: Date.now(),
  });
}

// ── result types ─────────────────────────────────────────────────────────────

/** Acknowledged coordination: durable, barrier-confirmed, visible-able. */
export type CoordinationResult =
  | {
      readonly ok: true;
      readonly code: "durable";
      readonly epochId: string;
      readonly mutationId: string;
      readonly transactionId: string;
      readonly commitSequence: CommitSequence;
      readonly revision: number;
      readonly contentHash: string;
      readonly barrier: DurabilityBarrier;
      readonly mutation: LiveDurableMutation;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code: "refused_pre_commit";
      readonly epochId: string;
      readonly mutationId: string;
      readonly transactionId: string | null;
      readonly failureCode: CoordinationFailureCode;
      /** The STORE's own typed failure code, carried verbatim (no renaming). */
      readonly storeFailureCode: string | null;
      readonly mutation: LiveDurableMutation;
      readonly explanation: string;
    }
  | {
      readonly ok: false;
      readonly code: "unknown_after_error";
      readonly epochId: string | null;
      readonly mutationId: string | null;
      readonly transactionId: string | null;
      readonly failureCode: CoordinationFailureCode;
      readonly mutation: LiveDurableMutation | null;
      readonly explanation: string;
    };

function refusedOutcome(
  mutation: LiveDurableMutation,
  failureCode: CoordinationFailureCode,
  explanation: string
): CoordinationResult {
  return {
    ok: false,
    code: "refused_pre_commit",
    epochId: mutation.epochId,
    mutationId: mutation.mutationId,
    transactionId: null,
    failureCode,
    storeFailureCode: null,
    mutation,
    explanation,
  };
}

function unknownOutcome(
  mutation: LiveDurableMutation | null,
  failureCode: CoordinationFailureCode,
  explanation: string
): CoordinationResult {
  return {
    ok: false,
    code: "unknown_after_error",
    epochId: mutation?.epochId ?? null,
    mutationId: mutation?.mutationId ?? null,
    transactionId: null,
    failureCode,
    mutation,
    explanation,
  };
}
