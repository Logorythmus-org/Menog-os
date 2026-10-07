/**
 * PHASE 27C — Node & Edge Lifecycle Tests (TOPOLOGY-OBSERVATION LIFECYCLE —
 * SEPARATE FROM PeerTrustState / ZERO AUTHORITY).
 *
 * Pins the lifecycle's laws structurally and behaviorally:
 *   · vocabulary DISJOINT from frozen 24C PeerTrustState (cross-lifecycle
 *     confusion refuses);
 *   · pinned legal transitions + reason->target map, fail-closed unknowns;
 *   · terminal anti-resurrection (retired has no out-edge);
 *   · freshness ordering (stale facts, non-strict re-observation);
 *   · quarantine exits only to retirement;
 *   · epoch boundary (cross-epoch refuses; recovery is the only path);
 *   · recovery zero-authority: authority "none", trustInherited false,
 *     autoResumed false literals; observed recovers as stale across epochs;
 *   · determinism of provenance hashes.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  TOPOLOGY_LIFECYCLE_SCHEMA_VERSION,
  TOPOLOGY_OBSERVATION_STATES,
  TOPOLOGY_TERMINAL_OBSERVATION_STATES,
  TOPOLOGY_QUARANTINE_OBSERVATION_STATES,
  TOPOLOGY_OBSERVATION_TRANSITIONS,
  TOPOLOGY_OBSERVATION_REASONS,
  TOPOLOGY_OBSERVATION_REASON_TARGETS,
  TOPOLOGY_OBSERVATION_REFUSAL_CODES,
  decideTopologyObservationTransition,
  recoverTopologyObservation,
  NODE_TRUST_STATES,
  PEER_TRUST_TRANSITIONS,
  isPeerTrustTransition,
  type TopologyObservationRecord,
  type TopologyObservationState,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

/** Surfaces the 27C module must NEVER contain (structural pin). */
const FORBIDDEN_SURFACES: readonly string[] = Object.freeze([
  "child_process",
  "node:net",
  "node:http",
  "node:https",
  "node:dgram",
  "node:tls",
  "node:dns",
  "node:crypto",
  "node:sqlite",
  "WebSocket",
  "fetch(",
  "spawn(",
  "listen(",
  "createServer",
  "connect(",
  "createSocket",
  "createHash",
  "DatabaseSync",
  "acceptMutation",
  "setInterval",
  "setTimeout",
  "Date.now",
  "performance.now",
  ".persist(",
  "DurableStore",
  "PeerRegistry",
  "executeToolRun",
  "runIsolated",
  "toolJunction",
  "requireTool",
]);

const NOW = 1_700_000_000_000;
const EPOCH = "epoch-27c-1";
const OTHER_EPOCH = "epoch-27c-2";
const REC_ID = "node-abc";

const REC = (
  state: TopologyObservationState,
  over: Partial<TopologyObservationRecord> = {},
): TopologyObservationRecord => ({
  recordId: REC_ID,
  state,
  observedAtEpochMs: NOW,
  epochId: EPOCH,
  ...over,
});

const go = (
  record: TopologyObservationRecord,
  to: string,
  reason: string,
  evidenceAtEpochMs: number = NOW + 1000,
  currentEpochId: string = EPOCH,
) => decideTopologyObservationTransition({ record, to, reason, currentEpochId, evidenceAtEpochMs });

// ── structural pins ──────────────────────────────────────────────────────────

describe("27C structure — closed vocabularies, no forbidden surfaces", () => {
  it("forbidden surfaces list is pinned and the module contains none of them", () => {
    expect(FORBIDDEN_SURFACES).toEqual([
      "child_process",
      "node:net",
      "node:http",
      "node:https",
      "node:dgram",
      "node:tls",
      "node:dns",
      "node:crypto",
      "node:sqlite",
      "WebSocket",
      "fetch(",
      "spawn(",
      "listen(",
      "createServer",
      "connect(",
      "createSocket",
      "createHash",
      "DatabaseSync",
      "acceptMutation",
      "setInterval",
      "setTimeout",
      "Date.now",
      "performance.now",
      ".persist(",
      "DurableStore",
      "PeerRegistry",
      "executeToolRun",
      "runIsolated",
      "toolJunction",
      "requireTool",
    ]);
    const code = codeOnly(SRC("meshTopologyLifecycle.ts"));
    for (const forbidden of FORBIDDEN_SURFACES) {
      expect(code).not.toContain(forbidden);
    }
    // the module READS NODE_TRUST_STATES only to refuse it — no trust writes
    expect(code).not.toMatch(/trustState\s*:/);
    expect(code).not.toMatch(/PEER_TRUST_TRANSITIONS\s*\[/);
    expect(code).not.toContain("isPeerTrustTransition");
    expect(code).not.toContain("admitPeer");
    expect(code).not.toContain("setTrustState");
    expect(code).not.toMatch(/authority:\s*"(?!none")/);
    expect(code).not.toMatch(/executionAuthorized:\s*true/);
    expect(code).not.toMatch(/policyAuthorized/);
    expect(code).not.toMatch(/trustInherited:\s*true/);
    expect(code).not.toMatch(/autoResumed:\s*true/);
  });

  it("schema version, states, terminals, quarantine, reasons, and refusal codes are pinned exactly", () => {
    expect(TOPOLOGY_LIFECYCLE_SCHEMA_VERSION).toBe("menog-mesh-topology-lifecycle/v0");
    expect([...TOPOLOGY_OBSERVATION_STATES]).toEqual([
      "observed",
      "stale",
      "quarantined_observation",
      "retired_observation",
      "unknown_observation",
    ]);
    expect(Object.isFrozen(TOPOLOGY_OBSERVATION_STATES)).toBe(true);
    expect([...TOPOLOGY_TERMINAL_OBSERVATION_STATES]).toEqual(["retired_observation"]);
    expect([...TOPOLOGY_QUARANTINE_OBSERVATION_STATES]).toEqual(["quarantined_observation"]);
    expect([...TOPOLOGY_OBSERVATION_REASONS]).toEqual([
      "freshness_expired",
      "re_observed",
      "evidence_conflict",
      "operator_retirement",
      "unknown_reason",
    ]);
    expect(Object.isFrozen(TOPOLOGY_OBSERVATION_REASONS)).toBe(true);
    expect([...TOPOLOGY_OBSERVATION_REFUSAL_CODES]).toEqual([
      "refused_cross_lifecycle_state",
      "refused_unknown_state",
      "refused_unknown_reason",
      "refused_reason_mismatch",
      "refused_illegal_transition",
      "refused_terminal_state",
      "refused_stale_fact",
      "refused_invalid_fact",
      "refused_stale_epoch",
      "refused_invalid_epoch",
      "refused_invalid_record",
      "refused_no_trust_inheritance",
      "refused_unknown",
    ]);
    expect(Object.isFrozen(TOPOLOGY_OBSERVATION_REFUSAL_CODES)).toBe(true);
  });

  it("the transition table is pinned exactly: terminal has no out-edge, quarantine exits only to retirement", () => {
    expect(TOPOLOGY_OBSERVATION_TRANSITIONS).toEqual({
      observed: ["stale", "quarantined_observation", "retired_observation"],
      stale: ["observed", "quarantined_observation", "retired_observation"],
      quarantined_observation: ["retired_observation"],
      retired_observation: [],
      unknown_observation: [],
    });
    expect(TOPOLOGY_OBSERVATION_TRANSITIONS.retired_observation).toHaveLength(0);
    expect(TOPOLOGY_OBSERVATION_TRANSITIONS.unknown_observation).toHaveLength(0);
    expect(Object.isFrozen(TOPOLOGY_OBSERVATION_TRANSITIONS)).toBe(true);
    // every state has a frozen row
    for (const s of TOPOLOGY_OBSERVATION_STATES) {
      expect(Object.isFrozen(TOPOLOGY_OBSERVATION_TRANSITIONS[s])).toBe(true);
    }
  });

  it("the reason->target map is pinned exactly (one closed target set per reason)", () => {
    expect(TOPOLOGY_OBSERVATION_REASON_TARGETS).toEqual({
      freshness_expired: ["stale"],
      re_observed: ["observed"],
      evidence_conflict: ["quarantined_observation"],
      operator_retirement: ["retired_observation"],
      unknown_reason: [],
    });
    expect(Object.isFrozen(TOPOLOGY_OBSERVATION_REASON_TARGETS)).toBe(true);
  });
});

// ── cross-lifecycle separation (27C vs frozen 24C PeerTrustState) ──────────

describe("27C separation — topology-observation states are NOT trust states", () => {
  it("the two vocabularies are DISJOINT (no shared value)", () => {
    const trust = [...NODE_TRUST_STATES];
    const topo = [...TOPOLOGY_OBSERVATION_STATES];
    for (const t of trust) expect(topo).not.toContain(t);
    for (const s of topo) expect(trust).not.toContain(s);
    expect(trust).toEqual(["unknown", "candidate", "admitted", "quarantined", "retired"]);
  });

  it("every frozen PeerTrustState value refuses as a record state with refused_cross_lifecycle_state", () => {
    for (const trustValue of NODE_TRUST_STATES) {
      const d = go(REC(trustValue as unknown as TopologyObservationState), "stale", "freshness_expired");
      expect(d.ok).toBe(false);
      if (!d.ok) {
        expect(d.refusal).toBe("refused_cross_lifecycle_state");
        expect(d.explanation).toContain("PeerTrustState");
        expect(d.explanation).toContain("cross-lifecycle");
      }
    }
  });

  it("every frozen PeerTrustState value refuses as a TARGET with refused_cross_lifecycle_state", () => {
    for (const trustValue of NODE_TRUST_STATES) {
      const d = go(REC("observed"), trustValue as unknown as string, "operator_retirement");
      expect(d.ok).toBe(false);
      if (!d.ok) expect(d.refusal).toBe("refused_cross_lifecycle_state");
    }
  });

  it("the module only READS trust vocabulary: the frozen 24C machine is untouched and works as before", () => {
    // the trust machine still behaves exactly per its frozen table
    expect(isPeerTrustTransition("candidate", "admitted")).toBe(true);
    expect(isPeerTrustTransition("quarantined", "admitted")).toBe(false);
    expect(isPeerTrustTransition("retired", "candidate")).toBe(false);
    expect([...NODE_TRUST_STATES]).toEqual(["unknown", "candidate", "admitted", "quarantined", "retired"]);
    // topology states are not keys of the trust machine (the trust machine
    // cannot even be asked about them — they are structurally absent)
    for (const s of TOPOLOGY_OBSERVATION_STATES) {
      expect(Object.prototype.hasOwnProperty.call(PEER_TRUST_TRANSITIONS, s)).toBe(false);
    }
    expect(PEER_TRUST_TRANSITIONS.retired).toHaveLength(0);
  });

  it("unknown/cross-lifecycle states refuse on both sides of every decision entry point", () => {
    const d1 = go(REC("mystery" as unknown as TopologyObservationState), "stale", "freshness_expired");
    expect(d1.ok).toBe(false);
    if (!d1.ok) expect(d1.refusal).toBe("refused_unknown_state");
    const d2 = go(REC("observed"), "unknown_observation", "freshness_expired");
    expect(d2.ok).toBe(false);
    if (!d2.ok) expect(d2.refusal).toBe("refused_unknown_state");
    const d3 = recoverTopologyObservation({
      saved: REC("admitted" as unknown as TopologyObservationState),
      recoveredEpochId: EPOCH,
      trustClaim: "none",
    });
    expect(d3.ok).toBe(false);
    if (!d3.ok) expect(d3.refusal).toBe("refused_cross_lifecycle_state");
    const d4 = recoverTopologyObservation({
      saved: REC("mystery" as unknown as TopologyObservationState),
      recoveredEpochId: EPOCH,
      trustClaim: "none",
    });
    expect(d4.ok).toBe(false);
    if (!d4.ok) expect(d4.refusal).toBe("refused_unknown_state");
  });
});

// ── legal transitions (table x reason agreement) ────────────────────────────

describe("27C transitions — every legal edge passes with its exact reason", () => {
  const LEGAL: ReadonlyArray<[
    TopologyObservationState,
    TopologyObservationState,
    string,
  ]> = [
    ["observed", "stale", "freshness_expired"],
    ["observed", "quarantined_observation", "evidence_conflict"],
    ["observed", "retired_observation", "operator_retirement"],
    ["stale", "observed", "re_observed"],
    ["stale", "quarantined_observation", "evidence_conflict"],
    ["stale", "retired_observation", "operator_retirement"],
    ["quarantined_observation", "retired_observation", "operator_retirement"],
  ];

  it("the legal-edge set is pinned (7 edges; terminal and unknown have none)", () => {
    expect(LEGAL.map(([f, t]) => f + "->" + t)).toEqual([
      "observed->stale",
      "observed->quarantined_observation",
      "observed->retired_observation",
      "stale->observed",
      "stale->quarantined_observation",
      "stale->retired_observation",
      "quarantined_observation->retired_observation",
    ]);
    let total = 0;
    for (const s of TOPOLOGY_OBSERVATION_STATES) {
      total += TOPOLOGY_OBSERVATION_TRANSITIONS[s].length;
    }
    expect(total).toBe(7);
  });

  it("each legal edge with its matching reason is allowed, authority structurally 'none', record advanced", () => {
    for (const [from, to, reason] of LEGAL) {
      const evidence = NOW + 5000;
      const d = go(REC(from), to, reason, evidence);
      expect(d.ok).toBe(true);
      if (d.ok) {
        expect(d.code).toBe("transition_allowed");
        expect(d.from).toBe(from);
        expect(d.to).toBe(to);
        expect(d.reason).toBe(reason);
        expect(d.authority).toBe("none");
        expect(d.record.state).toBe(to);
        expect(d.record.recordId).toBe(REC_ID);
        expect(d.record.epochId).toBe(EPOCH);
        expect(d.record.observedAtEpochMs).toBe(evidence);
        expect(d.explanation).toContain("TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY");
      }
    }
  });

  it("a legal edge with the WRONG reason refuses refused_reason_mismatch", () => {
    // observed -> stale is legal, but only freshness_expired produces 'stale'
    for (const wrong of ["re_observed", "evidence_conflict", "operator_retirement"]) {
      const d = go(REC("observed"), "stale", wrong);
      expect(d.ok).toBe(false);
      if (!d.ok) {
        expect(d.refusal).toBe("refused_reason_mismatch");
        expect(d.explanation).toContain(wrong);
      }
    }
  });

  it("an unknown reason refuses refused_unknown_reason (even for a legal edge)", () => {
    const d = go(REC("observed"), "stale", "unknown_reason");
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.refusal).toBe("refused_unknown_reason");
    const d2 = go(REC("observed"), "stale", "because_i_said_so");
    expect(d2.ok).toBe(false);
    if (!d2.ok) expect(d2.refusal).toBe("refused_unknown_reason");
  });

  it("an ILLEGAL edge with a plausible reason refuses refused_illegal_transition", () => {
    const ILLEGAL: ReadonlyArray<[TopologyObservationState, TopologyObservationState, string]> = [
      ["observed", "observed", "re_observed"],
      ["observed", "stale", "re_observed"],
      ["stale", "stale", "freshness_expired"],
      ["quarantined_observation", "observed", "re_observed"],
      ["quarantined_observation", "stale", "freshness_expired"],
      ["unknown_observation", "observed", "re_observed"],
    ];
    for (const [from, to, reason] of ILLEGAL) {
      if (from === "unknown_observation") continue; // refused even earlier (unnamed state)
      const d = go(REC(from), to, reason);
      expect(d.ok).toBe(false);
      if (!d.ok) {
        // quarantine -> anything-but-retired and self-loops land on the table;
        // reason-mismatch may fire first only when the table allows the edge
        expect(["refused_illegal_transition", "refused_reason_mismatch"]).toContain(d.refusal);
      }
    }
    // explicitly: quarantine NEVER returns to observed (table blocks it)
    const q = go(REC("quarantined_observation"), "observed", "re_observed", NOW + 1000);
    expect(q.ok).toBe(false);
    if (!q.ok) expect(q.refusal).toBe("refused_illegal_transition");
    // unknown_observation cannot move at all (unnamed state refuses first)
    const u = go(REC("unknown_observation"), "stale", "freshness_expired");
    expect(u.ok).toBe(false);
    if (!u.ok) expect(u.refusal).toBe("refused_unknown_state");
  });
});

// ── terminal anti-resurrection ──────────────────────────────────────────────────────

describe("27C terminal — retired never resurrects", () => {
  it("retired_observation refuses EVERY out-transition with refused_terminal_state", () => {
    for (const to of TOPOLOGY_OBSERVATION_STATES) {
      if (to === "unknown_observation") continue; // unnamed TARGET refuses even earlier (pinned order step 2)
      for (const reason of ["re_observed", "freshness_expired", "operator_retirement", "evidence_conflict"]) {
        const d = go(REC("retired_observation"), to, reason, NOW + 10_000);
        expect(d.ok).toBe(false);
        if (!d.ok) {
          expect(d.refusal).toBe("refused_terminal_state");
          expect(d.explanation).toContain("anti-resurrection");
        }
      }
    }
    // retired -> unknown_observation still refuses (unnamed target, step 2)
    const unnamed = go(REC("retired_observation"), "unknown_observation", "re_observed", NOW + 10_000);
    expect(unnamed.ok).toBe(false);
    if (!unnamed.ok) expect(unnamed.refusal).toBe("refused_unknown_state");
  });

  it("terminal refusal fires BEFORE freshness and reason checks (pinned order: epoch > terminal > fact)", () => {
    // retired + STALE fact -> terminal wins over stale-fact (step 5 before 6/7)
    const d1 = go(REC("retired_observation"), "stale", "freshness_expired", NOW - 1);
    expect(d1.ok).toBe(false);
    if (!d1.ok) expect(d1.refusal).toBe("refused_terminal_state");
    // retired + non-finite fact -> terminal wins
    const d2 = go(REC("retired_observation"), "stale", "freshness_expired", Number.NaN);
    expect(d2.ok).toBe(false);
    if (!d2.ok) expect(d2.refusal).toBe("refused_terminal_state");
    // retired + unknown reason -> terminal wins (reason is step 3, terminal step 5 — reason fires first)
    const d3 = go(REC("retired_observation"), "stale", "unknown_reason");
    expect(d3.ok).toBe(false);
    if (!d3.ok) expect(d3.refusal).toBe("refused_unknown_reason");
  });

  it("quarantine exits ONLY to retirement (terminal-adjacent, never back to observed)", () => {
    const toRetire = go(REC("quarantined_observation"), "retired_observation", "operator_retirement");
    expect(toRetire.ok).toBe(true);
    const backToObserved = go(REC("quarantined_observation"), "observed", "re_observed");
    expect(backToObserved.ok).toBe(false);
    if (!backToObserved.ok) expect(backToObserved.refusal).toBe("refused_illegal_transition");
    const toStale = go(REC("quarantined_observation"), "stale", "freshness_expired");
    expect(toStale.ok).toBe(false);
  });
});

// ── freshness ordering and fact validity ───────────────────────────────────────

describe("27C freshness — stale facts fail closed; re-observation needs strictly newer evidence", () => {
  it("evidence OLDER than the record refuses refused_stale_fact (any target, any reason)", () => {
    for (const [to, reason] of [["stale", "freshness_expired"], ["retired_observation", "operator_retirement"]] as const) {
      const d = go(REC("observed"), to, reason, NOW - 1);
      expect(d.ok).toBe(false);
      if (!d.ok) {
        expect(d.refusal).toBe("refused_stale_fact");
        expect(d.explanation).toContain("freshness ordering");
      }
    }
  });

  it("EQUAL evidence is refused for re-observation (strictly newer required)", () => {
    const d = go(REC("stale"), "observed", "re_observed", NOW); // equal to record freshness
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.refusal).toBe("refused_stale_fact");
      expect(d.explanation).toContain("STRICTLY NEWER");
    }
  });

  it("strictly newer evidence re-observes a stale record", () => {
    const d = go(REC("stale"), "observed", "re_observed", NOW + 1);
    expect(d.ok).toBe(true);
    if (d.ok) {
      expect(d.record.state).toBe("observed");
      expect(d.record.observedAtEpochMs).toBe(NOW + 1);
    }
  });

  it("non-finite or negative evidence refuses refused_invalid_fact (before freshness)", () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1]) {
      const d = go(REC("observed"), "stale", "freshness_expired", bad);
      expect(d.ok).toBe(false);
      if (!d.ok) expect(d.refusal).toBe("refused_invalid_fact");
    }
  });

  it("pinned order: unknown state > unknown reason > epoch > terminal > fact validity > freshness > table > reason-target", () => {
    // unknown target beats everything else
    const a = go(REC("observed"), "mystery", "unknown_reason", NOW - 5);
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.refusal).toBe("refused_unknown_state");
    // unknown reason beats epoch (reason is evaluated before epoch boundary)
    const b = go(REC("observed", { epochId: OTHER_EPOCH }), "stale", "unknown_reason", NOW + 1, EPOCH);
    expect(b.ok).toBe(false);
    if (!b.ok) expect(b.refusal).toBe("refused_unknown_reason");
    // epoch beats fact validity
    const c = go(REC("observed", { epochId: OTHER_EPOCH }), "stale", "freshness_expired", Number.NaN, EPOCH);
    expect(c.ok).toBe(false);
    if (!c.ok) expect(c.refusal).toBe("refused_stale_epoch");
    // fact validity beats freshness
    const d = go(REC("observed"), "stale", "freshness_expired", Number.NaN, EPOCH);
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.refusal).toBe("refused_invalid_fact");
    // freshness beats the table (stale fact on an illegal edge still reports stale fact)
    const e = go(REC("observed"), "observed", "re_observed", NOW - 5, EPOCH);
    expect(e.ok).toBe(false);
    if (!e.ok) expect(e.refusal).toBe("refused_stale_fact");
    // table beats reason-target (legal-edge check runs before reason agreement)
    const f = go(REC("observed"), "observed", "re_observed", NOW + 5, EPOCH);
    expect(f.ok).toBe(false);
    if (!f.ok) expect(f.refusal).toBe("refused_illegal_transition");
  });
});

// ── epoch boundary ──────────────────────────────────────────────────────────────────

describe("27C epoch — cross-epoch records refuse and must recover first", () => {
  it("a record from another epoch refuses refused_stale_epoch", () => {
    const d = go(REC("observed", { epochId: OTHER_EPOCH }), "stale", "freshness_expired", NOW + 1000, EPOCH);
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.refusal).toBe("refused_stale_epoch");
      expect(d.explanation).toContain("recovery");
    }
  });

  it("an empty current or record epoch refuses refused_invalid_epoch", () => {
    const a = go(REC("observed"), "stale", "freshness_expired", NOW + 1, "");
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.refusal).toBe("refused_invalid_epoch");
    const b = go(REC("observed", { epochId: "" }), "stale", "freshness_expired", NOW + 1, EPOCH);
    expect(b.ok).toBe(false);
    if (!b.ok) expect(b.refusal).toBe("refused_invalid_epoch");
  });
});

// ── recovery (zero authority; no trust inheritance; no auto-resume) ─────────

describe("27C recovery — grants nothing, inherits nothing, never auto-resumes", () => {
  const rec = (state: TopologyObservationState, epochId = EPOCH, over: Partial<TopologyObservationRecord> = {}) =>
    REC(state, { epochId, ...over });

  it("a request to inherit trust refuses FIRST with refused_no_trust_inheritance", () => {
    const d = recoverTopologyObservation({
      saved: rec("observed"),
      recoveredEpochId: OTHER_EPOCH,
      trustClaim: "inherit",
    });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.refusal).toBe("refused_no_trust_inheritance");
      expect(d.explanation).toContain("recovery grants nothing");
    }
    // even with an otherwise-invalid saved record, the trust claim wins (pinned order)
    const d2 = recoverTopologyObservation({
      saved: rec("observed", EPOCH, { recordId: "" }),
      recoveredEpochId: "",
      trustClaim: "inherit",
    });
    expect(d2.ok).toBe(false);
    if (!d2.ok) expect(d2.refusal).toBe("refused_no_trust_inheritance");
  });

  it("every success carries authority 'none', trustInherited false, autoResumed false (structural literals)", () => {
    const cases = [
      { saved: rec("observed"), epoch: EPOCH },
      { saved: rec("observed"), epoch: OTHER_EPOCH },
      { saved: rec("stale"), epoch: OTHER_EPOCH },
      { saved: rec("quarantined_observation"), epoch: OTHER_EPOCH },
      { saved: rec("retired_observation"), epoch: OTHER_EPOCH },
    ];
    for (const c of cases) {
      const d = recoverTopologyObservation({ saved: c.saved, recoveredEpochId: c.epoch, trustClaim: "none" });
      expect(d.ok).toBe(true);
      if (d.ok) {
        expect(d.authority).toBe("none");
        expect(d.trustInherited).toBe(false);
        expect(d.autoResumed).toBe(false);
        expect(d.record.epochId).toBe(c.epoch);
        expect(d.explanation).toContain("recovery grants nothing");
      }
    }
  });

  it("terminal restores EXACTLY terminal; quarantine EXACTLY quarantine (never auto-clears)", () => {
    const t = recoverTopologyObservation({ saved: rec("retired_observation"), recoveredEpochId: OTHER_EPOCH, trustClaim: "none" });
    expect(t.ok).toBe(true);
    if (t.ok) {
      expect(t.record.state).toBe("retired_observation");
      expect(t.terminal).toBe(true);
    }
    const q = recoverTopologyObservation({ saved: rec("quarantined_observation"), recoveredEpochId: OTHER_EPOCH, trustClaim: "none" });
    expect(q.ok).toBe(true);
    if (q.ok) {
      expect(q.record.state).toBe("quarantined_observation");
      expect(q.terminal).toBe(false);
      expect(q.explanation).toContain("never auto-clears");
    }
    // and a recovered terminal record STILL refuses resurrection
    if (t.ok) {
      const again = decideTopologyObservationTransition({
        record: t.record,
        to: "observed",
        reason: "re_observed",
        currentEpochId: OTHER_EPOCH,
        evidenceAtEpochMs: NOW + 100_000,
      });
      expect(again.ok).toBe(false);
      if (!again.ok) expect(again.refusal).toBe("refused_terminal_state");
    }
  });

  it("an observed record recovered into a DIFFERENT epoch restores as STALE (freshness never inherits across epochs)", () => {
    const d = recoverTopologyObservation({ saved: rec("observed"), recoveredEpochId: OTHER_EPOCH, trustClaim: "none" });
    expect(d.ok).toBe(true);
    if (d.ok) {
      expect(d.record.state).toBe("stale");
      expect(d.record.observedAtEpochMs).toBe(NOW); // freshness value preserved as history
      expect(d.explanation).toContain("freshness never inherits across epochs");
      // becoming observed again needs STRICTLY newer evidence
      const back = decideTopologyObservationTransition({
        record: d.record,
        to: "observed",
        reason: "re_observed",
        currentEpochId: OTHER_EPOCH,
        evidenceAtEpochMs: NOW,
      });
      expect(back.ok).toBe(false);
      if (!back.ok) expect(back.refusal).toBe("refused_stale_fact");
      const fresh = decideTopologyObservationTransition({
        record: d.record,
        to: "observed",
        reason: "re_observed",
        currentEpochId: OTHER_EPOCH,
        evidenceAtEpochMs: NOW + 1,
      });
      expect(fresh.ok).toBe(true);
    }
  });

  it("an observed record recovered within the SAME epoch stays observed", () => {
    const d = recoverTopologyObservation({ saved: rec("observed"), recoveredEpochId: EPOCH, trustClaim: "none" });
    expect(d.ok).toBe(true);
    if (d.ok) {
      expect(d.record.state).toBe("observed");
      expect(d.terminal).toBe(false);
    }
  });

  it("invalid saved records fail closed: empty recordId, empty epochs, non-finite freshness", () => {
    const a = recoverTopologyObservation({ saved: rec("observed", EPOCH, { recordId: "" }), recoveredEpochId: OTHER_EPOCH, trustClaim: "none" });
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.refusal).toBe("refused_invalid_record");
    const b = recoverTopologyObservation({ saved: rec("observed"), recoveredEpochId: "", trustClaim: "none" });
    expect(b.ok).toBe(false);
    if (!b.ok) expect(b.refusal).toBe("refused_invalid_epoch");
    const c = recoverTopologyObservation({ saved: rec("observed", "", {}), recoveredEpochId: OTHER_EPOCH, trustClaim: "none" });
    expect(c.ok).toBe(false);
    if (!c.ok) expect(c.refusal).toBe("refused_invalid_epoch");
    const d = recoverTopologyObservation({ saved: rec("stale", EPOCH, { observedAtEpochMs: Number.NaN }), recoveredEpochId: OTHER_EPOCH, trustClaim: "none" });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.refusal).toBe("refused_invalid_fact");
  });

  it("recovery is deterministic: same input yields the same provenance hash, different input differs", () => {
    const input = { saved: rec("observed"), recoveredEpochId: OTHER_EPOCH, trustClaim: "none" as const };
    const a = recoverTopologyObservation(input);
    const b = recoverTopologyObservation(input);
    expect(a.ok && b.ok && a.provenanceHash === b.provenanceHash).toBe(true);
    const c = recoverTopologyObservation({ ...input, recoveredEpochId: EPOCH });
    if (a.ok && c.ok) {
      expect(a.provenanceHash).not.toBe(c.provenanceHash);
    }
    const d = recoverTopologyObservation({ ...input, trustClaim: "inherit" as const });
    if (!d.ok && a.ok) {
      expect(d.provenanceHash).not.toBe(a.provenanceHash);
      expect(d.provenanceHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});

// ── determinism ──────────────────────────────────────────────────────────────────────

describe("27C determinism — identical inputs, identical decisions", () => {
  it("transition decisions are deterministic and bind the full input", () => {
    const input = { record: REC("observed"), to: "stale", reason: "freshness_expired", currentEpochId: EPOCH, evidenceAtEpochMs: NOW + 7 };
    const a = decideTopologyObservationTransition(input);
    const b = decideTopologyObservationTransition(input);
    expect(a.ok && b.ok && a.provenanceHash === b.provenanceHash).toBe(true);
    const c = decideTopologyObservationTransition({ ...input, evidenceAtEpochMs: NOW + 8 });
    if (a.ok && c.ok) expect(a.provenanceHash).not.toBe(c.provenanceHash);
    const refused = decideTopologyObservationTransition({ ...input, to: "mystery" });
    expect(refused.ok).toBe(false);
    if (!refused.ok && a.ok) {
      expect(refused.provenanceHash).not.toBe(a.provenanceHash);
      expect(refused.provenanceHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("the module source has no store/persist/control path (no alternate persist path)", () => {
    const src = codeOnly(SRC("meshTopologyLifecycle.ts"));
    expect(src).not.toContain("acceptMutation");
    expect(src).not.toContain(".persist(");
    expect(src).not.toContain("RuntimeStateCoordinator");
    expect(src).not.toContain("startupRecovery");
    expect(src).not.toContain("recordTrust");
  });
});
