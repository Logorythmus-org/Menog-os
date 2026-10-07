import { describe, it, expect } from "vitest";
import type { Actor } from "@menog/core";
import type { MenogEventInput } from "@menog/core";
import { AppendOnlyLedger } from "@menog/event-ledger";
import { DenyByDefaultPolicyEngine } from "@menog/policy";
import {
  SEMANTIQ_SCHEMA_VERSION,
  SEMANTIQ_EVALUATION_DIMENSIONS,
  SEMANTIQ_PROVENANCE_SOURCES,
  SEMANTIQ_EVALUATION_VERDICTS,
  SEMANTIQ_MAX_EVENT_DIMENSIONS,
  SEMANTIQ_MAX_RECORDS,
  SEMANTIQ_VERDICT_PASS_THRESHOLD,
  SEMANTIQ_VERDICT_BORDERLINE_THRESHOLD,
  KNOWN_SEMANTIQ_EVENT_TYPES,
  KNOWN_SEMANTIQ_DENY_REASONS,
  validateEvaluationEvent,
  validateProvenance,
  validateDimensionScore,
  deriveVerdict,
  detectScoreConflicts,
  serializeEvaluationEvent,
  evaluationEventHash,
  snapScore,
  buildEvaluationRequestEvent,
  buildEvaluationResultEvent,
  buildEvaluationDeniedEvent,
  SemantiqEvaluationRecordStore,
  requestEvaluation,
  denyByDefaultSemantiqEmitter,
  type SemantiqDimensionScore,
  type SemantiqEvaluationProvenance,
  type SemantiqEvaluationRecord,
} from "@menog/semantiq";

const AGENT: Actor = { type: "agent", id: "agent-18b" };

function prov(overrides: Partial<SemantiqEvaluationProvenance> = {}): SemantiqEvaluationProvenance {
  return {
    source: "engine",
    actorId: AGENT.id,
    actorType: AGENT.type,
    derivedFrom: ["evt-18b-1"],
    engineId: "engine-18b",
    engineVersion: "0.1.0",
    ...overrides,
  };
}

function score(dimension: string, value: number, confidence = 0.9): SemantiqDimensionScore {
  return { dimension: dimension as SemantiqDimensionScore["dimension"], score: value, confidence };
}

const T0 = 1_830_000_000_000;

function isDenial(
  r: { ok: boolean }
): r is { ok: false; denyReason: string; reason: string } {
  return r.ok === false;
}

function appendEval(ledger: AppendOnlyLedger, id: string, type: string): void {
  const r = ledger.append({
    eventId: id,
    timestamp: new Date(T0).toISOString(),
    eventType: type,
    actor: { type: "runtime", id: "runtime-18b" },
    workspaceId: "ws-18b",
    verb: "inspect",
    policyDecision: "allow",
  } satisfies MenogEventInput);
  expect(r.ok).toBe(true);
}

// ---------------------------------------------------------------------------
// 18B-1 — Event schemas: closed unions, strict validation, fail-closed
// shapes, deterministic verdicts and hashes.
// ---------------------------------------------------------------------------

describe("18B-1 — event schemas (typed request/result/denied)", () => {
  it("18B-E1 the four evaluation dimensions are exactly the closed pinned union", () => {
    expect(SEMANTIQ_EVALUATION_DIMENSIONS).toEqual([
      "plan_quality",
      "task_completion",
      "policy_compliance",
      "reproducibility",
    ]);
    expect(Object.isFrozen(SEMANTIQ_EVALUATION_DIMENSIONS)).toBe(true);
    expect(SEMANTIQ_MAX_EVENT_DIMENSIONS).toBe(4);
  });

  it("18B-E2 evaluation_result joined the observable event types and conflict_unresolved the deny reasons (documented 18B deltas)", () => {
    expect(KNOWN_SEMANTIQ_EVENT_TYPES).toContain("evaluation_result");
    expect(KNOWN_SEMANTIQ_DENY_REASONS).toContain("conflict_unresolved");
  });

  it("18B-E3 verdicts and provenance sources are closed frozen unions", () => {
    expect(SEMANTIQ_EVALUATION_VERDICTS).toEqual(["pass", "borderline", "fail", "indeterminate"]);
    expect(SEMANTIQ_PROVENANCE_SOURCES).toEqual(["human", "engine", "derived_from_ledger", "mixed"]);
    expect(Object.isFrozen(SEMANTIQ_EVALUATION_VERDICTS)).toBe(true);
    expect(Object.isFrozen(SEMANTIQ_PROVENANCE_SOURCES)).toBe(true);
  });

  it("18B-E4 strict event validation accepts a valid result and rejects every malformed shape", () => {
    const good = buildEvaluationResultEvent({
      subject: "plan-18b",
      trigger: "manual",
      atEpochMs: T0,
      dimensions: [score("plan_quality", 0.9), score("policy_compliance", 0.8)],
      provenance: prov(),
    });
    expect(good.ok).toBe(true);
    if (!good.ok) return;
    expect(validateEvaluationEvent(good.event)).toBeNull();

    const bad: unknown[] = [
      null,
      42,
      { ...good.event, kind: "bogus" },
      { ...good.event, schemaVersion: "menog-semantiq/v2" },
      { ...good.event, authority: "execution_authority" },
      { ...good.event, executionAuthorized: true },
      { ...good.event, dimensions: [] },
      // Mean 0.85 ⇒ derived verdict is pass; claiming borderline is a
      // forgery the validator must reject.
      { ...good.event, verdict: "borderline" },
    ];
    for (const b of bad) expect(validateEvaluationEvent(b)).not.toBeNull();
  });

  it("18B-E5 score validation: pinned grid, bounds, bounded rationale, no duplicates", () => {
    expect(snapScore(0.30000000000000004)).toBe(0.3);
    expect(snapScore(1)).toBe(1);
    expect(snapScore(-0.1)).toBeNull();
    expect(snapScore(1.1)).toBeNull();
    expect(snapScore(Number.NaN)).toBeNull();
    expect(validateDimensionScore(score("plan_quality", 0.7))).toBeNull();
    expect(validateDimensionScore({ dimension: "bogus", score: 0.5, confidence: 0.5 } as never)).not.toBeNull();
    expect(validateDimensionScore(score("plan_quality", 0.55))).not.toBeNull();
    expect(validateDimensionScore(score("plan_quality", 0.5, Number.NaN))).not.toBeNull();
    expect(
      validateDimensionScore({ ...score("plan_quality", 0.5), rationale: "x".repeat(257) })
    ).not.toBeNull();
  });

  it("18B-E6 provenance validation: source/actor/derivedFrom bounds + cross-field coherence", () => {
    expect(validateProvenance(prov())).toBeNull();
    expect(validateProvenance({ ...prov(), source: "bogus" })).not.toBeNull();
    expect(validateProvenance({ ...prov(), engineId: undefined })).not.toBeNull();
    expect(validateProvenance({ ...prov(), source: "human", engineId: undefined, reviewerId: "human-1" })).toBeNull();
    expect(validateProvenance({ ...prov(), source: "human", reviewerId: "human-1" })).not.toBeNull();
    expect(validateProvenance({ ...prov(), derivedFrom: [] })).toBeNull();
    expect(validateProvenance({ ...prov(), actorId: "" })).not.toBeNull();
    const manyIds = Array.from({ length: 65 }, (_, i) => "e" + String(i));
    expect(validateProvenance({ ...prov(), derivedFrom: manyIds })).not.toBeNull();
  });

  it("18B-E7 verdict derivation is deterministic with pinned thresholds", () => {
    expect(SEMANTIQ_VERDICT_PASS_THRESHOLD).toBe(0.8);
    expect(SEMANTIQ_VERDICT_BORDERLINE_THRESHOLD).toBe(0.5);
    expect(deriveVerdict([])).toBe("indeterminate");
    expect(deriveVerdict([score("plan_quality", 0.9), score("task_completion", 0.8)])).toBe("pass");
    expect(deriveVerdict([score("plan_quality", 0.6), score("task_completion", 0.5)])).toBe("borderline");
    expect(deriveVerdict([score("plan_quality", 0.4), score("task_completion", 0.1)])).toBe("fail");
    // Mean exactly 0.8 (the threshold) is pass; strictly below is borderline.
    expect(deriveVerdict([score("plan_quality", 0.79), score("task_completion", 0.81)])).toBe("pass");
    expect(deriveVerdict([score("plan_quality", 0.79), score("task_completion", 0.79)])).toBe("borderline");
  });

  it("18B-E8 canonical serialization + hash are deterministic; any content change changes the hash", () => {
    const a = buildEvaluationResultEvent({
      subject: "hash-18b",
      trigger: "cli",
      atEpochMs: T0,
      dimensions: [score("reproducibility", 1), score("policy_compliance", 0.5)],
      provenance: prov(),
    });
    const b = buildEvaluationResultEvent({
      subject: "hash-18b",
      trigger: "cli",
      atEpochMs: T0,
      dimensions: [score("reproducibility", 1), score("policy_compliance", 0.5)],
      provenance: prov(),
    });
    expect(a.ok && b.ok).toBe(true);
    if (a.ok && b.ok) {
      expect(serializeEvaluationEvent(a.event)).toBe(serializeEvaluationEvent(b.event));
      expect(evaluationEventHash(a.event)).toBe(evaluationEventHash(b.event));
      expect(evaluationEventHash(a.event)).toMatch(/^[0-9a-f]{64}$/);
      const flipped = buildEvaluationResultEvent({
        subject: "hash-18b",
        trigger: "cli",
        atEpochMs: T0,
        dimensions: [score("reproducibility", 1), score("policy_compliance", 0.6)],
        provenance: prov(),
      });
      expect(flipped.ok).toBe(true);
      if (flipped.ok) expect(evaluationEventHash(a.event)).not.toBe(evaluationEventHash(flipped.event));
    }
  });

  it("18B-E9 authority pins are re-stamped by the builders regardless of caller input", () => {
    const r = buildEvaluationResultEvent({
      subject: "pins-18b",
      trigger: "manual",
      atEpochMs: T0,
      dimensions: [score("plan_quality", 1)],
      provenance: prov(),
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.event.authority).toBe("advisory_data");
      expect(r.event.executionAuthorized).toBe(false);
      expect(Object.isFrozen(r.event)).toBe(true);
      expect(Object.isFrozen(r.event.dimensions)).toBe(true);
      expect(Object.isFrozen(r.event.provenance)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// 18B-2 — Provenance: persisted, hash-anchored, insert-once (no rewrite),
// bounded store with fail-closed overflow.
// ---------------------------------------------------------------------------

describe("18B-2 — provenance persistence (insert-once, bounded, verifiable)", () => {
  it("18B-P1 records persist with content hashes and stable record ids", () => {
    const store = new SemantiqEvaluationRecordStore();
    const built = buildEvaluationResultEvent({
      subject: "prov-18b",
      trigger: "manual",
      atEpochMs: T0,
      dimensions: [score("task_completion", 0.9)],
      provenance: prov(),
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const persisted = store.persist(built.event);
    expect(persisted.ok).toBe(true);
    if (persisted.ok) {
      expect(persisted.record.contentHash).toMatch(/^[0-9a-f]{64}$/);
      expect(persisted.record.recordId).toBe(persisted.record.eventId);
      expect(store.length).toBe(1);
      expect(store.summary()).toEqual({ request: 0, result: 1, denied: 0 });
    }
  });

  it("18B-P2 insert-once: re-persisting an identical event is a duplicate denial (no provenance rewrite)", () => {
    const store = new SemantiqEvaluationRecordStore();
    const built = buildEvaluationDeniedEvent({
      subject: "once-18b",
      trigger: "manual",
      atEpochMs: T0,
      denyReason: "adapter_disabled",
      reason: "no engine",
      provenance: prov(),
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    expect(store.persist(built.event).ok).toBe(true);
    const second = store.persist(built.event);
    expect(isDenial(second) && second.denyReason).toBe("duplicate_record");
    expect(store.length).toBe(1);
  });

  it("18B-P3 the store accepts only schema-valid events (invalid_event denial)", () => {
    const store = new SemantiqEvaluationRecordStore();
    const forged = {
      ok: true,
      kind: "result",
      schemaVersion: SEMANTIQ_SCHEMA_VERSION,
      subject: "forged",
      trigger: "manual",
      evaluatedAtEpochMs: T0,
      dimensions: [],
      verdict: "pass",
      provenance: prov(),
      authority: "advisory_data",
      executionAuthorized: false,
    };
    const r = store.persist(forged as never);
    expect(isDenial(r) && r.denyReason).toBe("invalid_event");
    expect(store.length).toBe(0);
  });

  it("18B-P4 persisted provenance is immutable in memory: tamper attempts cannot rewrite a persisted record", () => {
    const store = new SemantiqEvaluationRecordStore();
    const built = buildEvaluationRequestEvent({
      subject: "tamper-18b",
      trigger: "manual",
      atEpochMs: T0,
      provenance: prov(),
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const persisted = store.persist(built.event);
    expect(persisted.ok).toBe(true);
    if (!persisted.ok) return;
    // The persisted event is deep-frozen: in-place tampering throws (strict
    // mode) and the persisted provenance is unchanged.
    let threw = false;
    try {
      (persisted.record.event as unknown as Record<string, unknown>)["subject"] = "tampered-after-persist";
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    const read = store.read();
    expect(read.records).toHaveLength(1);
    expect(read.records[0]!.event.subject).toBe("tamper-18b");
  });

  it("18B-P5 the store is bounded and fails closed at the cap (no silent eviction)", () => {
    const store = new SemantiqEvaluationRecordStore();
    let persisted = 0;
    for (let i = 0; i < SEMANTIQ_MAX_RECORDS + 5; i++) {
      const built = buildEvaluationRequestEvent({
        subject: "cap-18b-" + String(i),
        trigger: "manual",
        atEpochMs: T0,
        provenance: prov(),
      });
      if (!built.ok) continue;
      const r = store.persist(built.event);
      if (r.ok) persisted++;
      if (isDenial(r)) expect(r.denyReason).toBe("store_full");
    }
    expect(persisted).toBe(SEMANTIQ_MAX_RECORDS);
    expect(store.length).toBe(SEMANTIQ_MAX_RECORDS);
  });
});

// ---------------------------------------------------------------------------
// 18B-3 — Missing evaluator: typed, persisted, honest — never an error,
// never a guessed result.
// ---------------------------------------------------------------------------

describe("18B-3 — missing evaluator (typed denied events)", () => {
  it("18B-M1 requestEvaluation with zero contributions yields a persisted adapter_disabled denial", () => {
    const store = new SemantiqEvaluationRecordStore();
    const out = requestEvaluation(
      { subject: "missing-18b", trigger: "manual", atEpochMs: T0, context: { actor: AGENT } },
      store,
      []
    );
    expect(out.ok).toBe(true);
    if (out.ok && out.kind === "denied") {
      expect(out.event.denyReason).toBe("adapter_disabled");
      expect(out.event.verdict).toBe("indeterminate");
      expect(out.event.authority).toBe("advisory_data");
      expect(out.event.executionAuthorized).toBe(false);
      expect(store.summary()).toEqual({ request: 1, result: 0, denied: 1 });
    } else {
      expect.unreachable("expected a denied outcome");
    }
  });

  it("18B-M2 the missing-evaluator path is deterministic across repeated flows", () => {
    const run = (): { denyReason: string; hash: string } | null => {
      const store = new SemantiqEvaluationRecordStore();
      const out = requestEvaluation(
        { subject: "det-18b", trigger: "cli", atEpochMs: T0, context: { actor: AGENT } },
        store,
        []
      );
      if (out.ok && out.kind === "denied") {
        return { denyReason: out.event.denyReason, hash: out.record.contentHash };
      }
      return null;
    };
    const a = run();
    const b = run();
    expect(a).toEqual(b);
  });

  it("18B-M3 the adapter-level missing evaluator still denies with machine-readable state (18A surface intact)", async () => {
    const { buildSemantiqAdapter } = await import("@menog/semantiq");
    const a = buildSemantiqAdapter({});
    expect(a.state).toBe("unconfigured");
  });
});

// ---------------------------------------------------------------------------
// 18B-4 — Conflicting scores: exact detection, surfaced not resolved,
// machine never averages and never picks a winner.
// ---------------------------------------------------------------------------

describe("18B-4 — conflicting scores (surfaced, human-resolved)", () => {
  it("18B-C1 detectScoreConflicts is exact on the pinned grid and attributes engines", () => {
    const a = [score("plan_quality", 0.8), score("task_completion", 0.5)];
    const b = [score("plan_quality", 0.5), score("reproducibility", 0.5)];
    const c = detectScoreConflicts(a, b, "engine-A", "engine-B");
    expect(c).toHaveLength(1);
    expect(c[0]!.dimension).toBe("plan_quality");
    expect(c[0]!.scoreA).toBe(0.8);
    expect(c[0]!.scoreB).toBe(0.5);
    expect(c[0]!.engineIdA).toBe("engine-A");
    expect(c[0]!.engineIdB).toBe("engine-B");
    // Identical scores are NOT conflicts (0.30000000000000004 vs 0.3).
    const d = detectScoreConflicts(
      [{ dimension: "plan_quality", score: 0.30000000000000004, confidence: 1 }],
      [score("plan_quality", 0.3)],
      "A",
      "B"
    );
    expect(d).toHaveLength(0);
  });

  it("18B-C2 two conflicting engines produce a persisted conflict_unresolved denial (no result delivered)", () => {
    const store = new SemantiqEvaluationRecordStore();
    const out = requestEvaluation(
      { subject: "conflict-18b", trigger: "manual", atEpochMs: T0, context: { actor: AGENT } },
      store,
      [
        { engineId: "engine-A", engineVersion: "1.0.0", dimensions: [score("plan_quality", 0.8)] },
        { engineId: "engine-B", engineVersion: "1.0.0", dimensions: [score("plan_quality", 0.4)] },
      ]
    );
    expect(out.ok).toBe(true);
    if (out.ok && out.kind === "denied") {
      expect(out.event.denyReason).toBe("conflict_unresolved");
      expect(out.event.reason).toContain("plan_quality");
      expect(out.event.reason).toContain("human-only");
      expect(store.summary().result).toBe(0);
    } else {
      expect.unreachable("expected a conflict denial");
    }
  });

  it("18B-C3 agreeing engines deliver one result with mixed provenance listing every engine", () => {
    const store = new SemantiqEvaluationRecordStore();
    const out = requestEvaluation(
      { subject: "agree-18b", trigger: "manual", atEpochMs: T0, context: { actor: AGENT } },
      store,
      [
        { engineId: "engine-A", engineVersion: "1.0.0", dimensions: [score("plan_quality", 0.9)] },
        { engineId: "engine-B", engineVersion: "2.0.0", dimensions: [score("plan_quality", 0.9)] },
      ]
    );
    expect(out.ok).toBe(true);
    if (out.ok && out.kind === "result") {
      expect(out.event.verdict).toBe("pass");
      expect(out.event.provenance.source).toBe("mixed");
      expect(out.event.provenance.engineId).toBe("engine-A,engine-B");
      expect(out.event.provenance.engineVersion).toBe("1.0.0,2.0.0");
    } else {
      expect.unreachable("expected a result outcome");
    }
  });

  it("18B-C4 more than four engine contributions deny oversized_request (bounded surface)", () => {
    const store = new SemantiqEvaluationRecordStore();
    const many = Array.from({ length: 5 }, (_, i) => ({
      engineId: "engine-" + String(i),
      engineVersion: "1.0.0",
      dimensions: [score("plan_quality", 0.9)],
    }));
    const out = requestEvaluation(
      { subject: "many-18b", trigger: "manual", atEpochMs: T0, context: { actor: AGENT } },
      store,
      many
    );
    expect(out.ok).toBe(true);
    if (out.ok && out.kind === "denied") expect(out.event.denyReason).toBe("oversized_request");
  });

  it("18B-C5 conflicts never alter authority pins on any produced event", () => {
    const store = new SemantiqEvaluationRecordStore();
    const out = requestEvaluation(
      { subject: "pins-18b-c", trigger: "event_hook", atEpochMs: T0, context: { actor: AGENT } },
      store,
      [
        { engineId: "A", engineVersion: "1", dimensions: [score("policy_compliance", 1)] },
        { engineId: "B", engineVersion: "1", dimensions: [score("policy_compliance", 0)] },
      ]
    );
    if (out.ok) {
      expect(out.event.authority).toBe("advisory_data");
      expect(out.event.executionAuthorized).toBe(false);
      expect(validateEvaluationEvent(out.event)).toBeNull();
    }
  });
});

// ---------------------------------------------------------------------------
// 18B-5 — Ledger integration: evaluations are NOT ledger events; reads are
// policy-gated; writes deny-by-default; no shadowing.
// ---------------------------------------------------------------------------

describe("18B-5 — ledger integration (separate store, no shadowing)", () => {
  it("18B-L1 evaluation records persist next to — never inside — the ledger; the chain stays intact", () => {
    const ledger = AppendOnlyLedger.inMemory();
    appendEval(ledger, "evt-18b-l1", "verb_executed");
    const snapshot = JSON.stringify(ledger.events());
    const store = new SemantiqEvaluationRecordStore();
    const built = buildEvaluationResultEvent({
      subject: "ledger-18b",
      trigger: "manual",
      atEpochMs: T0,
      dimensions: [score("plan_quality", 0.9)],
      provenance: prov({ derivedFrom: ["evt-18b-l1"] }),
    });
    expect(built.ok).toBe(true);
    if (built.ok) expect(store.persist(built.event).ok).toBe(true);
    expect(JSON.stringify(ledger.events())).toBe(snapshot);
    expect(ledger.length).toBe(1);
    expect(ledger.verify().ok).toBe(true);
    expect(store.length).toBe(1);
  });

  it("18B-L2 provenance.derivedFrom anchors evaluations to real ledger event ids", () => {
    const ledger = AppendOnlyLedger.inMemory();
    appendEval(ledger, "evt-18b-l2", "algorithm_recommended");
    const evs = ledger.events();
    expect(evs[0]!.eventId).toBe("evt-18b-l2");
    const built = buildEvaluationResultEvent({
      subject: "anchor-18b",
      trigger: "manual",
      atEpochMs: T0,
      dimensions: [score("reproducibility", 0.7)],
      provenance: prov({ derivedFrom: [evs[0]!.eventId] }),
    });
    expect(built.ok).toBe(true);
    if (built.ok) {
      const store = new SemantiqEvaluationRecordStore();
      const persisted = store.persist(built.event);
      expect(persisted.ok).toBe(true);
      if (persisted.ok) {
        expect(persisted.record.event.provenance.derivedFrom).toEqual(["evt-18b-l2"]);
        expect(validateEvaluationEvent(persisted.record.event)).toBeNull();
      }
    }
  });

  it("18B-L3 evaluation events cannot be persisted AS ledger events (event-type mismatch is rejected by the ledger)", () => {
    const ledger = AppendOnlyLedger.inMemory();
    const built = buildEvaluationResultEvent({
      subject: "not-an-event-18b",
      trigger: "manual",
      atEpochMs: T0,
      dimensions: [score("plan_quality", 1)],
      provenance: prov(),
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const serialized = JSON.parse(JSON.stringify(built.event)) as Record<string, unknown>;
    // An evaluation payload is missing the ledger's required event fields;
    // appending it must fail rather than smuggle evaluations into the
    // execution-fact chain.
    const r = ledger.append(serialized as unknown as MenogEventInput);
    expect(r.ok).toBe(false);
    expect(ledger.length).toBe(0);
  });

  it("18B-L4 the deny-by-default emitter refuses everything except evaluation observability types", () => {
    const allowed: string[] = [];
    const emitter = denyByDefaultSemantiqEmitter((input: { eventType: string }) => {
      allowed.push(input.eventType);
      return { ok: true };
    });
    const emitInput = (eventType: string) => ({
      eventType,
      policyDecision: "not_applicable" as const,
      actor: AGENT,
      inputSummary: {},
      resultSummary: {},
    });
    expect(emitter.append(emitInput("verb_executed")).ok).toBe(false);
    expect(emitter.append(emitInput("policy.updated")).ok).toBe(false);
    expect(emitter.append(emitInput("evaluation_result")).ok).toBe(true);
    expect(allowed).toEqual(["evaluation_result"]);
  });
});

// ---------------------------------------------------------------------------
// 18B-6 — Authority separation: evaluation events stay distinct from
// runtime authority; policy stays the sole MAY-IT layer.
// ---------------------------------------------------------------------------

describe("18B-6 — authority separation (negative security tests)", () => {
  it("18B-A1 a forged result event claiming authority cannot pass validation or persist", () => {
    const store = new SemantiqEvaluationRecordStore();
    const forged = {
      ok: true,
      kind: "result",
      schemaVersion: SEMANTIQ_SCHEMA_VERSION,
      subject: "forged-authority",
      trigger: "manual",
      evaluatedAtEpochMs: T0,
      dimensions: [score("policy_compliance", 1)],
      verdict: "pass",
      provenance: prov(),
      authority: "execution_authority",
      executionAuthorized: true,
    };
    expect(validateEvaluationEvent(forged)).not.toBeNull();
    const r = store.persist(forged as never);
    expect(r.ok).toBe(false);
    expect(store.length).toBe(0);
  });

  it("18B-A2 score/verdict forgery is rejected: verdict must match deterministic derivation", () => {
    const built = buildEvaluationResultEvent({
      subject: "forge-verdict",
      trigger: "manual",
      atEpochMs: T0,
      dimensions: [score("plan_quality", 0.2)],
      provenance: prov(),
    });
    expect(built.ok).toBe(true);
    if (built.ok) {
      expect(built.event.verdict).toBe("fail");
      const forged = { ...built.event, verdict: "pass" };
      expect(validateEvaluationEvent(forged)).not.toBeNull();
    }
  });

  it("18B-A3 the policy engine stays the sole MAY-IT authority for evaluation verbs (Day-1 deny unchanged)", () => {
    const engine = new DenyByDefaultPolicyEngine();
    for (const verb of ["semantiq.evaluate", "evaluation.record", "evaluation.read", "semantiq.result.write"]) {
      const res = engine.evaluate({
        actor: AGENT,
        verb,
        requestedCapabilities: ["workspace:write"],
        workspaceId: "ws-18b",
      });
      expect(res.decision.outcome).toBe("deny");
    }
  });

  it("18B-A4 delivered result events serialize with no smuggled authority keys", () => {
    const store = new SemantiqEvaluationRecordStore();
    const out = requestEvaluation(
      { subject: "smuggle-18b", trigger: "manual", atEpochMs: T0, context: { actor: AGENT } },
      store,
      [{ engineId: "A", engineVersion: "1", dimensions: [score("task_completion", 0.2)] }]
    );
    expect(out.ok).toBe(true);
    if (out.ok) {
      const json = JSON.stringify(out.event);
      expect(json.includes('"executionAuthorized":true')).toBe(false);
      expect(json.includes("workspace:write")).toBe(false);
    }
  });

  it("18B-A5 provenance cannot be rewritten after persistence (insert-once holds across kinds)", () => {
    const store = new SemantiqEvaluationRecordStore();
    const first = buildEvaluationRequestEvent({
      subject: "immutable-18b",
      trigger: "manual",
      atEpochMs: T0,
      provenance: prov({ source: "engine" }),
    });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(store.persist(first.event).ok).toBe(true);
    // Same subject/kind, different provenance content ⇒ different hash ⇒
    // a DIFFERENT record id is created (append-only), the original stays.
    const rewritten = buildEvaluationRequestEvent({
      subject: "immutable-18b",
      trigger: "manual",
      atEpochMs: T0,
      provenance: prov({ source: "human", engineId: undefined, reviewerId: "human-9" }),
    });
    expect(rewritten.ok).toBe(true);
    if (rewritten.ok) {
      const r2 = store.persist(rewritten.event);
      expect(r2.ok).toBe(true);
      expect(store.length).toBe(2);
      const all = store.read().records;
      const sources = all.map((rec: SemantiqEvaluationRecord) => rec.event.provenance.source);
      expect(sources).toContain("engine");
      expect(sources).toContain("human");
    }
  });
});

// ---------------------------------------------------------------------------
// 18B-7 — Governance invariants (15E/16E/17E/18A pattern).
// ---------------------------------------------------------------------------

import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

function readDoc(relativePath: string): string {
  const full = path.resolve(process.cwd(), relativePath);
  expect(existsSync(full), "expected doc to exist: " + relativePath).toBe(true);
  return readFileSync(full, "utf8");
}

describe("18B-7 — governance invariants", () => {
  const PR_BLOCK_LINES = [
    "PR-01 HUMAN_DISPOSITION_PENDING",
    "PR-02 HOLD",
    "PR-03 HUMAN_DISPOSITION_PENDING",
    "PR-04 HOLD",
    "PR-05 HOLD",
  ];

  it("18B-V1 PR-01..PR-05 disposition block is verbatim in the 18B report", () => {
    const content = readDoc("docs/release/PROMPT_18B_REPORT.md").replace(/\s+/g, " ");
    for (const line of PR_BLOCK_LINES) {
      expect(content.includes(line), "missing " + line).toBe(true);
    }
  });

  it("18B-V2 authorization-not-granted lines are unchanged in the 18B report", () => {
    const content = readDoc("docs/release/PROMPT_18B_REPORT.md").replace(/\s+/g, " ");
    expect(content.includes("COMMIT AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(content.includes("PUSH AUTHORIZATION NOT GRANTED")).toBe(true);
    expect(content.includes("PUBLICATION AUTHORIZATION NOT GRANTED")).toBe(true);
  });

  it("18B-V3 no Phase-20 isolation primitives exist in the semantiq package source", () => {
    const srcRoot = path.resolve(process.cwd(), "packages/semantiq/src");
    const files = ["adapter.ts", "rules.ts", "types.ts", "index.ts", "events.ts", "records.ts", "requestFlow.ts"];
    const forbidden = /cgroup|seccomp|landlock|rootless|unshare|clone3/i;
    for (const f of files) {
      const full = path.join(srcRoot, f);
      expect(existsSync(full), "semantiq source file missing: " + f).toBe(true);
      expect(forbidden.test(readFileSync(full, "utf8")), "Phase-20 primitive in " + f).toBe(false);
    }
  });

  it("18B-V4 evaluations are documented as NOT ledger events (ADR-0007 §Decision 5 honored)", () => {
    const report = readDoc("docs/release/PROMPT_18B_REPORT.md");
    expect(report.includes("NOT ledger events")).toBe(true);
    expect(report.includes("OPTIONAL_EXTERNAL")).toBe(true);
  });

  it("18B-V5 the 18B report documents the additive union deltas and pins the schema version", () => {
    const report = readDoc("docs/release/PROMPT_18B_REPORT.md");
    expect(report.includes("conflict_unresolved")).toBe(true);
    expect(report.includes("evaluation_result")).toBe(true);
    expect(report.includes("menog-semantiq/v0")).toBe(true);
  });
});
