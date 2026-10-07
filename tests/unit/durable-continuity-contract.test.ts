/**
 * PHASE 23A — Runtime Continuity Contract & Property Tests
 * (CONTRACT-FIRST / NO LIVE WIRING).
 *
 * Pins every 23A law structurally and behaviorally:
 *   L1  persistence grants no execution authority
 *   L2  recovered state reuses no Policy authority
 *   L3  terminal/quarantined facts cannot resurrect (no surface here)
 *   L4  no acknowledgement before durable confirmation
 *   L5  ambiguous ownership / stale epochs fail closed
 *   L6  recovery→live is explicit and evidenced (READY never skipped)
 *   L7  no auto-resume (interruption re-enters only as recovered data)
 *   L8  derived state is non-authoritative (never a mutation/admission)
 *   L9  executable replay stays out of scope (no execution vocabulary)
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  // 23A vocabulary
  CONTINUITY_SCHEMA_VERSION,
  RUNTIME_EPOCH_SCHEMA_VERSION,
  RUNTIME_LIFECYCLE_STATES,
  RUNTIME_LIFECYCLE_REASONS,
  RUNTIME_TRANSITIONS,
  RUNTIME_EPOCH_ID_PATTERN,
  RUNTIME_EPOCH_END_REASONS,
  RUNTIME_EPOCH_PRIOR_OWNER_CODES,
  RUNTIME_BOOTSTRAP_DECISION_CODES,
  LIVE_DURABLE_MUTATION_PHASES,
  LIVE_DURABLE_MUTATION_OUTCOMES,
  DURABILITY_BARRIER_OUTCOMES,
  CONTINUITY_DECISION_CODES,
  LIVE_DURABLE_DENY_CODES,
  RECOVERY_BOOTSTRAP_DECISION_CODES,
  RECOVERY_BOOTSTRAP_DENY_CODES,
  DERIVED_CONTINUITY_KINDS,
  // 23A decisions
  makeRuntimeEpochId,
  makeRuntimeEpoch,
  checkStaleEpoch,
  makeLiveDurableMutation,
  advanceLiveDurableMutation,
  makeDurabilityBarrier,
  acknowledgedBarrier,
  decideContinuity,
  decisionStillFresh,
  decideRecoveryBootstrap,
  isRuntimeTransition,
  isLifecycleTransitionAllowed,
  advanceLifecycle,
  buildRuntimeContinuitySnapshot,
  // 22A (the frozen boundary 23A sits on)
  decideRecovery,
  type RecoveryRequest,
  type RecoverySnapshot,
  type LiveDurableMutation,
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

const EPOCH_A = makeRuntimeEpochId(1759100000000, "abcdef0123456789");
const EPOCH_B = makeRuntimeEpochId(1759100000001, "ffff010203040506");

function openEpoch(epochId = EPOCH_A) {
  const decision = makeRuntimeEpoch({
    schemaVersion: "menog-runtime-epoch/v0",
    epochId,
    startedAtEpochMs: 1759100000000,
    hostRef: "wsl2-target-of-record",
    pidRef: 4242,
    priorOwner: { code: "none", epochId: null },
    declaredEpochId: null,
  });
  if (!decision.ok) throw new Error(decision.explanation);
  return decision.epoch;
}

function cleanRecoveryDecision() {
  const request: RecoveryRequest = {
    mode: "load_committed_state",
    expectedStoreSchemaVersion: "menog-durable-store/v0",
    maxRecords: 1000,
    semantics: "no_execution",
  };
  const snapshot: RecoverySnapshot = {
    expectedStoreSchemaVersion: "menog-durable-store/v0",
    actualStoreSchemaVersion: "menog-durable-store/v0",
    committedThrough: 7,
    observedThrough: 7,
    totalRecordsScanned: 3,
    findings: [],
    scanTruncated: false,
  };
  return decideRecovery(snapshot, request);
}

function mutation(epochId = EPOCH_A, id = "mut-0001"): LiveDurableMutation {
  return makeLiveDurableMutation({
    mutationId: id,
    epochId,
    kind: "goal_lifecycle",
    recordId: "gol-continuity01",
    atEpochMs: 1759100000100,
  });
}

function confirmedBarrier(epochId = EPOCH_A, commitSequence = 8) {
  return makeDurabilityBarrier({
    barrierId: "bar-0001",
    epochId,
    outcome: "committed",
    commitSequence,
    transactionId: "tx-continuity01",
    atEpochMs: 1759100000200,
  });
}

// ── closed vocabularies ──────────────────────────────────────────────────────

describe("23A — closed vocabularies", () => {
  it("schema versions are pinned (v1: the 23D RECONCILED extension)", () => {
    expect(CONTINUITY_SCHEMA_VERSION).toBe("menog-runtime-continuity/v1");
    expect(RUNTIME_EPOCH_SCHEMA_VERSION).toBe("menog-runtime-epoch/v0");
  });

  it("the lifecycle is the closed six-state machine; READY cannot be skipped to LIVE", () => {
    expect([...RUNTIME_LIFECYCLE_STATES]).toEqual(["BOOTING", "RECOVERING", "RECONCILED", "READY", "LIVE", "RECOVERED"]);
    expect([...RUNTIME_TRANSITIONS.BOOTING]).toEqual(["RECOVERING"]);
    expect([...RUNTIME_TRANSITIONS.RECOVERING].sort()).toEqual(["RECONCILED", "RECOVERED"]);
    expect([...RUNTIME_TRANSITIONS.RECONCILED].sort()).toEqual(["READY", "RECOVERED"]);
    expect([...RUNTIME_TRANSITIONS.READY]).toEqual(["LIVE"]);
    expect([...RUNTIME_TRANSITIONS.LIVE]).toEqual(["RECOVERED"]);
    expect([...RUNTIME_TRANSITIONS.RECOVERED]).toEqual(["RECOVERING"]);
    expect(isRuntimeTransition("RECOVERED", "LIVE")).toBe(false);
    expect(isRuntimeTransition("BOOTING", "LIVE")).toBe(false);
    expect(isRuntimeTransition("READY", "RECOVERED")).toBe(false);
    expect(isRuntimeTransition("RECOVERING", "READY")).toBe(false); // RECONCILED is mandatory
  });

  it("the reason vocabulary is closed and decision/deny codes are closed", () => {
    expect([...RUNTIME_LIFECYCLE_REASONS].length).toBe(11);
    expect([...CONTINUITY_DECISION_CODES].length).toBe(9);
    expect([...LIVE_DURABLE_DENY_CODES].length).toBe(8);
    expect([...RECOVERY_BOOTSTRAP_DECISION_CODES].length).toBe(4);
    expect([...RECOVERY_BOOTSTRAP_DENY_CODES]).toEqual([
      "recovery_not_accepted",
      "epoch_mismatch",
      "epoch_not_open",
    ]);
  });

  it("derived kinds are the runtime L8 exclusion set", () => {
    expect([...DERIVED_CONTINUITY_KINDS].sort()).toEqual(["derived_index", "store_checkpoint"]);
  });
});

// ── L5: epoch admission fails closed ─────────────────────────────────────────

describe("23A L5 — epoch admission (ambiguous ownership / stale / split-brain fail closed)", () => {
  it("opens an epoch over a fresh store with no carried identity; epoch carries NO authority", () => {
    const d = makeRuntimeEpoch({
      schemaVersion: "menog-runtime-epoch/v0",
      epochId: EPOCH_A,
      startedAtEpochMs: 1759100000000,
      hostRef: "wsl2-target-of-record",
      pidRef: 4242,
      priorOwner: { code: "none", epochId: null },
      declaredEpochId: null,
    });
    expect(d.ok).toBe(true);
    if (d.ok) {
      expect(d.epoch.lifecycle).toBe("BOOTING");
      expect(d.epoch.executionAuthorized).toBe(false); // L1: identity ≠ authority
      expect(d.epoch.policyAuthorized).toBe(false);    // L2: no policy grant
      expect(d.epoch.startReason).toBe("fresh_store_no_prior_owner");
    }
  });

  it("refuses a malformed/empty epoch id", () => {
    expect(RUNTIME_EPOCH_ID_PATTERN.test("")).toBe(false);
    const d = makeRuntimeEpoch({
      schemaVersion: "menog-runtime-epoch/v0",
      epochId: "",
      startedAtEpochMs: 1759100000000,
      hostRef: "h",
      pidRef: 1,
      priorOwner: { code: "none", epochId: null },
      declaredEpochId: null,
    });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.code).toBe("epoch_refused_stale");
  });

  it("refuses a declared (carried) epoch id over a FRESH store — stale by definition", () => {
    const d = makeRuntimeEpoch({
      schemaVersion: "menog-runtime-epoch/v0",
      epochId: EPOCH_A,
      startedAtEpochMs: 1759100000000,
      hostRef: "h",
      pidRef: 1,
      priorOwner: { code: "none", epochId: null },
      declaredEpochId: EPOCH_A, // carried in, but the store never saw an owner
    });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.code).toBe("epoch_refused_stale");
  });

  it("refuses a mismatched declared epoch id (ambiguous identity)", () => {
    const d = makeRuntimeEpoch({
      schemaVersion: "menog-runtime-epoch/v0",
      epochId: EPOCH_A,
      startedAtEpochMs: 1759100000000,
      hostRef: "h",
      pidRef: 1,
      priorOwner: { code: "stale_claim_present", epochId: EPOCH_B },
      declaredEpochId: EPOCH_B,
    });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.code).toBe("epoch_refused_mismatch");
  });

  it("refuses a LIVE claim held by a DIFFERENT epoch id (split-brain refusal)", () => {
    const d = makeRuntimeEpoch({
      schemaVersion: "menog-runtime-epoch/v0",
      epochId: EPOCH_A,
      startedAtEpochMs: 1759100000000,
      hostRef: "h",
      pidRef: 1,
      priorOwner: { code: "live_claim_present", epochId: EPOCH_B },
      declaredEpochId: null,
    });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.code).toBe("epoch_refused_live_owner");
  });

  it("accepts re-ownership ONLY when the same epoch id released the claim (crash-restart resume of the SAME process identity is the special case)", () => {
    const d = makeRuntimeEpoch({
      schemaVersion: "menog-runtime-epoch/v0",
      epochId: EPOCH_A,
      startedAtEpochMs: 1759100000000,
      hostRef: "h",
      pidRef: 1,
      priorOwner: { code: "same_epoch_id", epochId: EPOCH_A },
      declaredEpochId: EPOCH_A,
    });
    expect(d.ok).toBe(true);
  });

  it("refuses an UNVERIFIABLE prior claim — ambiguous ownership fails closed (fail-closed gap F1)", () => {
    const d = makeRuntimeEpoch({
      schemaVersion: "menog-runtime-epoch/v0",
      epochId: EPOCH_A,
      startedAtEpochMs: 1759100000000,
      hostRef: "h",
      pidRef: 1,
      priorOwner: { code: "unverifiable", epochId: null },
      declaredEpochId: null,
    });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.code).toBe("epoch_refused_unverifiable");
      expect(RUNTIME_BOOTSTRAP_DECISION_CODES.includes(d.code)).toBe(true);
    }
  });

  it("refuses a live claim that cannot be attributed to an id (anonymous live claim)", () => {
    const d = makeRuntimeEpoch({
      schemaVersion: "menog-runtime-epoch/v0",
      epochId: EPOCH_A,
      startedAtEpochMs: 1759100000000,
      hostRef: "h",
      pidRef: 1,
      priorOwner: { code: "live_claim_present", epochId: null },
      declaredEpochId: null,
    });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.code).toBe("epoch_refused_unverifiable");
  });

  it("epoch ids are fresh per construction and never collide across restarts (property, 200 cases)", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const id = makeRuntimeEpochId(1759100000000 + i, `rnd-${i}-padding-padding`);
      expect(id).toMatch(RUNTIME_EPOCH_ID_PATTERN);
      seen.add(id);
    }
    expect(seen.size).toBe(200);
  });

  it("the stale-epoch predicate treats any other epoch as stale (L5)", () => {
    expect(checkStaleEpoch(EPOCH_A, EPOCH_A)).toBe(false);
    expect(checkStaleEpoch(EPOCH_A, EPOCH_B)).toBe(true);
  });
});

// ── L4: durability barrier is the ONLY ack path ──────────────────────────────

describe("23A L4 — no acknowledgement before durable confirmation", () => {
  it("a mutation starts at 'requested' with NO barrier and NO outcome", () => {
    const m = mutation();
    expect(m.phase).toBe("requested");
    expect(m.outcome).toBeNull();
    expect(m.barrier).toBeNull();
  });

  it("a confirmed barrier acknowledges; every other barrier shape does NOT", () => {
    expect(acknowledgedBarrier(confirmedBarrier())).toBe(true);
    expect(
      acknowledgedBarrier(makeDurabilityBarrier({ barrierId: "b", epochId: EPOCH_A, outcome: "rolled_back", commitSequence: null, transactionId: "t", atEpochMs: 1 }))
    ).toBe(false);
    expect(
      acknowledgedBarrier(makeDurabilityBarrier({ barrierId: "b", epochId: EPOCH_A, outcome: "ambiguous", commitSequence: null, transactionId: "t", atEpochMs: 1 }))
    ).toBe(false);
    // A 'committed' barrier WITHOUT a commit sequence is not an ack (the
    // sequence is the durable proof; its absence is not confirmable).
    expect(
      acknowledgedBarrier(makeDurabilityBarrier({ barrierId: "b", epochId: EPOCH_A, outcome: "committed", commitSequence: null, transactionId: "t", atEpochMs: 1 }))
    ).toBe(false);
  });

  it("a requested mutation is NEVER admitted (no barrier → fail closed)", () => {
    const d = decideContinuity({ epochId: EPOCH_A, lifecycle: "LIVE", mutation: mutation() });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.code).toBe("rejected_barrier_not_confirmed");
      expect(d.denyReason).toBe("durability_barrier_not_confirmed");
    }
  });

  it("an ambiguous/rolled-back barrier is NEVER admitted (the store errored; visibility would lie)", () => {
    const ambiguous = advanceLiveDurableMutation(mutation(), {
      kind: "store_error",
      reason: "sqlite busy",
    });
    expect(ambiguous.outcome).toBe("unknown_after_error");
    const d = decideContinuity({ epochId: EPOCH_A, lifecycle: "LIVE", mutation: ambiguous });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.denyReason).toBe("durability_barrier_not_confirmed");
  });

  it("a refusal stops the mutation pre-commit; it can never become visible", () => {
    const refused = advanceLiveDurableMutation(mutation(), { kind: "refused", reason: "secret_key_denied" });
    expect(refused.outcome).toBe("refused_pre_commit");
    expect(refused.barrier).toBeNull();
    const d = decideContinuity({ epochId: EPOCH_A, lifecycle: "LIVE", mutation: refused });
    expect(d.ok).toBe(false);
  });

  it("ONLY a barrier-confirmed mutation is admitted, and the commit sequence flows through (property over sequences)", () => {
    for (const seq of [1, 2, 41, 999999]) {
      const m = advanceLiveDurableMutation(mutation(EPOCH_A, `mut-${seq}`), {
        kind: "barrier_confirmed",
        barrier: confirmedBarrier(EPOCH_A, seq),
      });
      expect(m.phase).toBe("durable");
      expect(m.outcome).toBe("durable");
      const d = decideContinuity({ epochId: EPOCH_A, lifecycle: "LIVE", mutation: m });
      expect(d.ok).toBe(true);
      if (d.ok) expect(d.commitSequence).toBe(seq);
    }
  });

  it("terminal outcomes never advance (ambiguity cannot be healed afterwards)", () => {
    const errored = advanceLiveDurableMutation(mutation(), { kind: "store_error", reason: "x" });
    const later = advanceLiveDurableMutation(errored, {
      kind: "barrier_confirmed",
      barrier: confirmedBarrier(),
    });
    expect(later).toBe(errored); // same object; the late barrier is ignored
    expect(later.barrier).toBeNull();
  });

  it("a barrier from ANOTHER epoch is not recognized (L5)", () => {
    const m = advanceLiveDurableMutation(mutation(EPOCH_A), {
      kind: "barrier_confirmed",
      barrier: confirmedBarrier(EPOCH_B),
    });
    const d = decideContinuity({ epochId: EPOCH_A, lifecycle: "LIVE", mutation: m });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.denyReason).toBe("durability_barrier_not_recognized");
  });
});

// ── L1/L2/L5/L8: the LIVE-side continuity decision ───────────────────────────

describe("23A — continuity decisions (LIVE side)", () => {
  it("L1: the admitted decision carries no authority fields at all — admission ≠ authorization", () => {
    const m = advanceLiveDurableMutation(mutation(), { kind: "barrier_confirmed", barrier: confirmedBarrier() });
    const d = decideContinuity({ epochId: EPOCH_A, lifecycle: "LIVE", mutation: m });
    expect(d.ok).toBe(true);
    if (d.ok) {
      expect(Object.keys(d).sort()).toEqual([
        "code",
        "commitSequence",
        "epochId",
        "explanation",
        "mutationId",
        "ok",
      ]);
      expect(JSON.stringify(d)).not.toContain("executionAuthorized");
      expect(JSON.stringify(d)).not.toContain("policyAuthorized");
    }
  });

  it("L5: no epoch → nothing is admissible", () => {
    const d = decideContinuity({ epochId: null, lifecycle: "LIVE", mutation: mutation() });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.code).toBe("rejected_no_epoch");
  });

  it("L1/L2: only LIVE admits — BOOTING/RECOVERING/READY/RECOVERED all fail closed (property over states)", () => {
    const m = advanceLiveDurableMutation(mutation(), { kind: "barrier_confirmed", barrier: confirmedBarrier() });
    for (const state of RUNTIME_LIFECYCLE_STATES) {
      const d = decideContinuity({ epochId: EPOCH_A, lifecycle: state, mutation: m });
      if (state === "LIVE") expect(d.ok).toBe(true);
      else {
        expect(d.ok).toBe(false);
        if (!d.ok) expect(d.code).toBe("rejected_not_live");
      }
    }
  });

  it("L5: a mutation from a stale epoch is refused even under the live owner", () => {
    const stale = mutation(EPOCH_B);
    const d = decideContinuity({ epochId: EPOCH_A, lifecycle: "LIVE", mutation: stale });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.code).toBe("rejected_epoch_mismatch");
  });

  it("L8: derived kinds are refused at the boundary even through a hostile cast", () => {
    const hostile = {
      ...mutation(),
      kind: "derived_index" as unknown as LiveDurableMutation["kind"],
    };
    const d = decideContinuity({ epochId: EPOCH_A, lifecycle: "LIVE", mutation: hostile });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.code).toBe("rejected_derived_kind");
      expect(d.denyReason).toBe("derived_kind_denied");
    }
  });

  it("a past decision is stale once the epoch changes (L5)", () => {
    const m = advanceLiveDurableMutation(mutation(), { kind: "barrier_confirmed", barrier: confirmedBarrier() });
    const d = decideContinuity({ epochId: EPOCH_A, lifecycle: "LIVE", mutation: m });
    expect(decisionStillFresh(d, EPOCH_A)).toBe(true);
    expect(decisionStillFresh(d, EPOCH_B)).toBe(false);
  });
});

// ── L2/L6/L7: recovery bootstrap (READY side) ────────────────────────────────

describe("23A — recovery bootstrap (RECONCILED → READY)", () => {
  it("L2: READY admission carries EXACTLY the frozen 22A authority triple", () => {
    const d = decideRecoveryBootstrap({
      epochId: EPOCH_A,
      lifecycle: "RECONCILED",
      recoveryDecision: cleanRecoveryDecision(),
    });
    expect(d.ok).toBe(true);
    if (d.ok) {
      expect(d.authority).toBe("recovered_data");
      expect(d.executionAuthorized).toBe(false);
      expect(d.policyAuthorized).toBe(false);
    }
  });

  it("L2/L6: a REJECTED recovery decision can never bootstrap to READY", () => {
    const request: RecoveryRequest = {
      mode: "load_committed_state",
      expectedStoreSchemaVersion: "menog-durable-store/v0",
      maxRecords: 10,
      semantics: "no_execution",
    };
    const corrupted: RecoverySnapshot = {
      expectedStoreSchemaVersion: "menog-durable-store/v0",
      actualStoreSchemaVersion: "menog-durable-store/v0",
      committedThrough: 3,
      observedThrough: 3,
      totalRecordsScanned: 1,
      findings: [
        { recordId: "gol-bad000001", recordKind: "goal_lifecycle", integrityStatus: "integrity_failed", cause: null, alreadyQuarantined: false },
      ],
      scanTruncated: false,
    };
    const rejected = decideRecovery(corrupted, request);
    expect(rejected.code).toBe("accept_without_quarantined"); // quarantine, not rejection
    // A genuinely rejected recovery (schema mismatch):
    const schemaMismatch: RecoverySnapshot = { ...corrupted, actualStoreSchemaVersion: "menog-durable-store/v9" };
    const hard = decideRecovery(schemaMismatch, request);
    expect(hard.code).toBe("rejected_schema_mismatch");
    const d = decideRecoveryBootstrap({ epochId: EPOCH_A, lifecycle: "RECONCILED", recoveryDecision: hard });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.denyReason).toBe("recovery_not_accepted");
      expect(d.executionAuthorized).toBe(false);
      expect(d.policyAuthorized).toBe(false);
    }
  });

  it("L6: READY is reachable ONLY from RECONCILED (property over states)", () => {
    for (const state of RUNTIME_LIFECYCLE_STATES) {
      const d = decideRecoveryBootstrap({
        epochId: EPOCH_A,
        lifecycle: state,
        recoveryDecision: cleanRecoveryDecision(),
      });
      if (state === "RECONCILED") expect(d.ok).toBe(true);
      else {
        expect(d.ok).toBe(false);
        if (!d.ok) expect(d.denyReason).toBe("epoch_mismatch");
      }
    }
  });

  it("L6: no epoch → no bootstrap (fail closed)", () => {
    const d = decideRecoveryBootstrap({ epochId: null, lifecycle: "RECONCILED", recoveryDecision: cleanRecoveryDecision() });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.code).toBe("bootstrap_refused_epoch_not_open");
  });
});

// ── L6/L7: the explicit lifecycle machine ────────────────────────────────────

describe("23A — lifecycle transitions (explicit, evidenced)", () => {
  it("the healthy path BOOTING→RECOVERING→READY→LIVE applies; every skip is refused", () => {
    const epoch = openEpoch();
    const t1 = advanceLifecycle(epoch, "BOOTING", "RECOVERING", "recovery_started", 0);
    expect(t1.ok).toBe(true);
    const t2 = advanceLifecycle(epoch, "RECOVERING", "RECONCILED", "recovery_reconciled", 0, {
      kind: "recovery_decision",
      code: "accept_full_state",
    });
    expect(t2.ok).toBe(true);
    const t3 = advanceLifecycle(epoch, "RECONCILED", "READY", "recovery_decision_ready", 0, {
      kind: "recovery_decision",
      code: "accept_full_state",
    });
    expect(t3.ok).toBe(true);
    const t4 = advanceLifecycle(epoch, "READY", "LIVE", "lifecycle_transition", 0, {
      kind: "handoff_evidence",
      evidenceHash: "e".repeat(64),
    });
    expect(t4.ok).toBe(true);
    // Skips:
    expect(isLifecycleTransitionAllowed("BOOTING", "READY", "recovery_decision_ready")).toBe(false);
    expect(isLifecycleTransitionAllowed("BOOTING", "LIVE", "lifecycle_transition")).toBe(false);
    expect(isLifecycleTransitionAllowed("RECOVERING", "LIVE", "lifecycle_transition")).toBe(false);
    expect(isLifecycleTransitionAllowed("RECOVERING", "READY", "recovery_decision_ready")).toBe(false);
  });

  it("L6: RECOVERING→RECONCILED and RECONCILED→READY WITHOUT recovery-decision evidence are refused (unevidenced handoff gap F2)", () => {
    const epoch = openEpoch();
    const t = advanceLifecycle(epoch, "RECOVERING", "RECONCILED", "recovery_reconciled", 0);
    expect(t.ok).toBe(false);
    if (!t.ok) expect(t.explanation).toContain("requires recovery-decision evidence");
    const t2 = advanceLifecycle(epoch, "RECONCILED", "READY", "recovery_decision_ready", 0);
    expect(t2.ok).toBe(false);
    if (!t2.ok) expect(t2.explanation).toContain("requires recovery-decision evidence");
  });

  it("L6 (23D): READY→LIVE requires handoff evidence — a bare or recovery-decision evidence is refused", () => {
    const epoch = openEpoch();
    const bare = advanceLifecycle(epoch, "READY", "LIVE", "lifecycle_transition", 0);
    expect(bare.ok).toBe(false);
    if (!bare.ok) expect(bare.explanation).toContain("handoff evidence");
    const wrongKind = advanceLifecycle(epoch, "READY", "LIVE", "lifecycle_transition", 0, {
      kind: "recovery_decision",
      code: "accept_full_state",
    });
    expect(wrongKind.ok).toBe(false);
  });

  it("L6: RECOVERED→LIVE is refused for EVERY reason (re-entry must traverse RECOVERING)", () => {
    const epoch = openEpoch();
    for (const reason of RUNTIME_LIFECYCLE_REASONS) {
      expect(isLifecycleTransitionAllowed("RECOVERED", "LIVE", reason)).toBe(false);
    }
    const refused = advanceLifecycle(epoch, "RECOVERED", "LIVE", "lifecycle_transition", 0);
    expect(refused.ok).toBe(false);
  });

  it("L7: leaving LIVE lands in RECOVERED (never straight to any live-capable state)", () => {
    for (const reason of ["barrier_lost", "store_unavailable", "explicit_shutdown", "operator_pause"] as const) {
      expect(isLifecycleTransitionAllowed("LIVE", "RECOVERED", reason)).toBe(true);
    }
    expect(isLifecycleTransitionAllowed("LIVE", "RECOVERING", "store_unavailable")).toBe(false);
  });

  it("L7: no transition reason targets any live-capable state from a non-living state except the pinned machine edges", () => {
    // The only edge into LIVE:
    for (const from of RUNTIME_LIFECYCLE_STATES) {
      const edges = isLifecycleTransitionAllowed(from, "LIVE", "lifecycle_transition");
      expect(edges).toBe(from === "READY");
    }
  });

  it("reasons are pinned to their target states (a wrong reason for a legal edge is refused)", () => {
    expect(isLifecycleTransitionAllowed("RECOVERING", "RECONCILED", "recovery_started")).toBe(false);
    expect(isLifecycleTransitionAllowed("RECONCILED", "READY", "recovery_reconciled")).toBe(false);
    expect(isLifecycleTransitionAllowed("LIVE", "RECOVERED", "recovery_started")).toBe(false);
    expect(isLifecycleTransitionAllowed("BOOTING", "RECOVERING", "explicit_shutdown")).toBe(false);
  });

  it("the epoch end-reason vocabulary is closed and minimal", () => {
    expect([...RUNTIME_EPOCH_END_REASONS]).toEqual([
      "fresh_store_no_prior_owner",
      "prior_owner_released",
      "prior_owner_expired",
    ]);
    expect([...RUNTIME_EPOCH_PRIOR_OWNER_CODES]).toEqual([
      "none",
      "same_epoch_id",
      "live_claim_present",
      "stale_claim_present",
      "unverifiable",
    ]);
  });
});

// ── snapshot + structural pins ───────────────────────────────────────────────

describe("23A — continuity snapshot & structural pins", () => {
  it("the snapshot is recovered_data with no authority on every path (L2)", () => {
    const s = buildRuntimeContinuitySnapshot({
      epochId: EPOCH_A,
      lifecycle: "LIVE",
      lastKnownCommitSequence: 8,
      mutations: [],
      admittedRecoveredRecordCount: 3,
      atEpochMs: 1759100000300,
    });
    expect(s.authority).toBe("recovered_data");
    expect(s.executionAuthorized).toBe(false);
    expect(s.policyAuthorized).toBe(false);
    expect(s.mutations).toEqual([]);
  });

  it("barrier outcomes are the closed engine-honest set (committed/rolled_back/ambiguous)", () => {
    expect([...DURABILITY_BARRIER_OUTCOMES]).toEqual(["committed", "rolled_back", "ambiguous"]);
    expect([...LIVE_DURABLE_MUTATION_PHASES]).toEqual(["requested", "durable", "visible"]);
    expect([...LIVE_DURABLE_MUTATION_OUTCOMES]).toEqual(["durable", "refused_pre_commit", "unknown_after_error"]);
  });

  it("L9: the continuity module contains NO execution vocabulary (structural scan)", () => {
    const code = codeOnly(SRC("continuity.ts"));
    for (const forbidden of [
      "child_process",
      "spawn(",
      "spawnSync",
      "execFile",
      "fetch(",
      "http.request",
      "autoResume",
      "continueTask",
      "executeToolRun",
      "runToolInLauncher",
      "runIsolated",
      "generateRollbackPlan(",
      "generateReplayPlan(",
      "BEGIN IMMEDIATE",
      "node:sqlite",
    ]) {
      expect(code.includes(forbidden), "continuity.ts contains " + forbidden).toBe(false);
    }
    // The self-authorization dead-end is structural: the only self flag is
    // pinned false in the type system.
    expect(code).toContain("selfAuthorized: false");
    // The authority dead-ends are structural.
    expect((code.match(/executionAuthorized: false/g) ?? []).length).toBeGreaterThanOrEqual(6);
    expect(code.includes("executionAuthorized: true")).toBe(false);
    expect((code.match(/policyAuthorized: false/g) ?? []).length).toBeGreaterThanOrEqual(5);
    expect(code.includes("policyAuthorized: true")).toBe(false);
  });

  it("the barrel exports the 23A vocabulary; NO live wiring exists anywhere yet (23B is a later gate)", () => {
    const index = SRC("index.ts");
    expect(index).toContain("./continuity.js");
    const code = codeOnly(SRC("continuity.ts"));
    // No wiring imports: the contract layer must not even name the store,
    // the junction, or any runtime package.
    for (const forbidden of ["from \"./store.js\"", "@menog/policy", "@menog/planner", "@menog/agents", "@menog/runtime-linux", "DurableStore", "new DurableStore"]) {
      expect(code.includes(forbidden), "continuity.ts references " + forbidden).toBe(false);
    }
  });
});
