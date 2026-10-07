/**
 * PHASE 27G — Partition & Reconciliation Tests (LOCAL WORLD-VIEWS /
 * NO CONSENSUS / ATTRIBUTABLE CONFLICTS / NO RESURRECTION /
 * NO AUTO-RESUME / DUPLICATE-VIEW IDEMPOTENCE).
 *
 * Pins the reconciler's laws structurally and behaviorally:
 *   · closed vocabularies + frozen bounds (pinned exact values);
 *   · structural no-consensus literals on EVERY success (authority
 *     "none", consensusReached/globalOrdering/autoResumed/
 *     trustTransferred false) and the fresh-LOCAL-allocation text;
 *   · no consensus/quorum/leader/authorize/admit token in module
 *     source (no network/store/clock/tool surface either);
 *   · export surface = exactly one pure function;
 *   · split/rejoin: exclusive knowledge attributed to its holder,
 *     agreements carry both attributions (local first), counts add up;
 *   · conflicts remain ATTRIBUTABLE: both states, both owners, both
 *     recorded times, resolution class — never a winner;
 *   · terminal facts never resurrect (even with FRESHER remote data —
 *     time never decides), quarantine never auto-clears on rejoin,
 *     non-terminal disagreements merge to unknown (no consensus =>
 *     no invented winner; unknown stays unknown);
 *   · inputs are never mutated; duplicate reconciliations are
 *     byte-identical (pure — duplicate proposals are no-ops);
 *   · fail-closed inputs: cross-epoch views/facts, self-contradicting
 *     (duplicate) views, unknown states, unsanctioned provenance,
 *     malformed shapes, frozen bounds;
 *   · merged output shape pinned (facts carry NO authority/trust
 *     field) and everything frozen.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  RECONCILIATION_SCHEMA_VERSION,
  RECONCILIATION_BOUNDS,
  RECONCILIATION_REFUSAL_CODES,
  reconcilePartitionViews,
  type ReconciliationDecision,
  type ReconciliationInput,
  type ReconciliationRefusalCode,
  type PartitionFact,
  type PartitionView,
  type TopologyProvenance,
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

/** Surfaces the 27G module must NEVER contain (structural no-socket pin). */
const FORBIDDEN_SURFACES: readonly string[] = Object.freeze([
  "child_process",
  "node:net",
  "node:http",
  "node:https",
  "node:dgram",
  "node:tls",
  "node:dns",
  "node:crypto",
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

/** The ONLY modules the 27G module may import (pinned). */
const ALLOWED_IMPORTS = Object.freeze([
  "./canonical.js",
  "./meshTopologyGraph.js",
  "./meshTopologyLifecycle.js",
]);

/** Law/consensus tokens that must never appear in the module's CODE. */
const FORBIDDEN_LAW_TOKENS: readonly string[] = Object.freeze([
  "isPeerTrustTransition",
  "PEER_TRUST_TRANSITIONS",
  "trustState",
  "policyEngine",
  "evaluatePolicy",
  "authorize(",
  "admit(",
  "granted",
  "Paxos",
  "quorum",
  "leaderElect",
]);

const NOW = 1_700_000_000_000;
const EPOCH = "epoch-27g";

const prov = (over: Partial<TopologyProvenance> = {}): TopologyProvenance => ({
  source: "governed_evidence",
  evidenceId: "ev-1",
  recordedAtEpochMs: NOW,
  ...over,
});

const fact = (
  subjectNodeId: string,
  state: TopologyObservationState,
  over: Partial<PartitionFact> = {},
): PartitionFact => ({
  subjectNodeId,
  state,
  provenance: prov(),
  epochId: EPOCH,
  ...over,
});

const view = (
  viewId: string,
  ownerNodeId: string,
  facts: readonly PartitionFact[],
  over: Partial<PartitionView> = {},
): PartitionView => ({
  viewId,
  ownerNodeId,
  epochId: EPOCH,
  facts,
  ...over,
});

const RECON = (
  localView: PartitionView,
  remoteView: PartitionView,
  over: Partial<ReconciliationInput> = {},
): ReconciliationInput => ({
  reconciliationId: "rec-1",
  localView,
  remoteView,
  ...over,
});

/** Every reconciled decision carries the structural no-consensus literals. */
function expectReconciled(d: ReconciliationDecision): void {
  expect(d.ok).toBe(true);
  if (d.ok) {
    expect(d.code).toBe("views_reconciled");
    expect(d.authority).toBe("none");
    expect(d.consensusReached).toBe(false);
    expect(d.globalOrdering).toBe(false);
    expect(d.autoResumed).toBe(false);
    expect(d.trustTransferred).toBe(false);
    expect(d.reconciliationHash).toMatch(/^[0-9a-f]{64}$/);
    expect(Object.isFrozen(d.merged)).toBe(true);
    expect(Object.isFrozen(d.merged.facts)).toBe(true);
    expect(Object.isFrozen(d.conflicts)).toBe(true);
    for (const mergedFact of d.merged.facts) {
      expect(Object.isFrozen(mergedFact)).toBe(true);
      expect(Object.isFrozen(mergedFact.attributions)).toBe(true);
      for (const attribution of mergedFact.attributions) {
        expect(Object.isFrozen(attribution)).toBe(true);
      }
    }
    for (const conflict of d.conflicts) {
      expect(Object.isFrozen(conflict)).toBe(true);
    }
    expect(d.explanation).toContain("NO consensus");
    expect(d.explanation).toContain("fresh LOCAL allocation");
  }
}

function expectRefusal(d: ReconciliationDecision, refusal: ReconciliationRefusalCode): void {
  expect(d.ok).toBe(false);
  if (!d.ok) {
    expect(d.code).toBe("reconciliation_refused");
    expect(d.refusal).toBe(refusal);
    expect(d.explanation.length).toBeGreaterThan(20);
    expect(d.explanation).toMatch(/refus/);
    expect(d.reconciliationHash).toMatch(/^[0-9a-f]{64}$/);
    expect("authority" in d).toBe(false);
    expect("consensusReached" in d).toBe(false);
    expect("merged" in d).toBe(false);
  }
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("27G structure — closed vocabulary, frozen bounds, no-consensus source", () => {
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
    const code = codeOnly(SRC("meshPartitionReconciliation.ts"));
    for (const forbidden of FORBIDDEN_SURFACES) {
      expect(code).not.toContain(forbidden);
    }
  });

  it("module imports ONLY the pinned local modules (no network, no store, no clock)", () => {
    const src = SRC("meshPartitionReconciliation.ts");
    const imports = [
      ...[...src.matchAll(/^import [^\n]* from "([^"]+)"/gm)].map((m) => m[1] as string),
      ...[...src.matchAll(/^\} from "([^"]+)"/gm)].map((m) => m[1] as string),
    ].sort();
    expect(imports).toEqual([...ALLOWED_IMPORTS].sort());
  });

  it("schema version and reconciliation bounds are pinned frozen constants", () => {
    expect(RECONCILIATION_SCHEMA_VERSION).toBe("menog-mesh-reconciliation/v0");
    expect(RECONCILIATION_BOUNDS).toEqual({
      maxFactsPerView: 64,
      maxViewIdChars: 128,
      maxNodeChars: 128,
      maxEvidenceIdChars: 128,
    });
    expect(Object.isFrozen(RECONCILIATION_BOUNDS)).toBe(true);
  });

  it("refusal vocabulary is a pinned frozen closed set (fail-closed, no silent handling)", () => {
    expect([...RECONCILIATION_REFUSAL_CODES]).toEqual([
      "refused_invalid_view",
      "refused_field_bound",
      "refused_epoch_mismatch",
      "refused_duplicate_fact",
      "refused_unknown_state",
      "refused_unknown_provenance_source",
      "refused_invalid_provenance",
      "refused_unknown",
    ]);
    expect(Object.isFrozen(RECONCILIATION_REFUSAL_CODES)).toBe(true);
  });

  it("every authority/consensus literal in source is structural (no trust/Policy/consensus token)", () => {
    const code = codeOnly(SRC("meshPartitionReconciliation.ts"));
    for (const match of code.matchAll(/authority:\s*"[^"]*"/g)) {
      expect(match[0]).toBe('authority: "none"');
    }
    expect(code).not.toContain("consensusReached: true");
    expect(code).not.toContain("globalOrdering: true");
    expect(code).not.toContain("autoResumed: true");
    expect(code).not.toContain("trustTransferred: true");
    for (const token of FORBIDDEN_LAW_TOKENS) {
      expect(code).not.toContain(token);
    }
  });

  it("export surface: exactly ONE pure reconcile function, no class, no authorize/approve export", () => {
    const code = codeOnly(SRC("meshPartitionReconciliation.ts"));
    const functions = [...code.matchAll(/^export function (\w+)/gm)].map((m) => m[1] as string);
    expect(functions).toEqual(["reconcilePartitionViews"]);
    expect(code).not.toContain("export class");
    const exportNames = [...code.matchAll(/^export (?:const|type|interface) (\w+)/gm)].map(
      (m) => m[1] as string,
    );
    for (const name of exportNames) {
      expect(name).not.toMatch(/authoriz|approv|admit|grant|leader|quorum/i);
    }
    expect(typeof reconcilePartitionViews).toBe("function");
  });
});

// ── helpers for behavioral suites (assert-then-return; index-safe) ───────────

/** Exactly one element — asserts the length first (noUncheckedIndexedAccess). */
function exactlyOne<T>(items: readonly T[]): T {
  expect(items.length).toBe(1);
  return items[0] as T;
}

/** n distinct well-formed facts (subjects n00, n01, …) for bound tests. */
function manyFacts(n: number): readonly PartitionFact[] {
  return Array.from({ length: n }, (_, i) => fact(`n${String(i).padStart(2, "0")}`, "observed"));
}

/** Deep-freeze a value so any mutation attempt throws in strict mode. */
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const key of Object.keys(value as Record<string, unknown>)) {
      deepFreeze((value as Record<string, unknown>)[key]);
    }
    Object.freeze(value);
  }
  return value;
}

// ── split / rejoin ───────────────────────────────────────────────────────────

describe("27G split/rejoin — exclusive knowledge stays with its holder, agreements carry both sides", () => {
  it("disjoint world-views merge with zero conflicts, exclusive counts per holder, sorted subjects", () => {
    const local = view("va", "node-a", [fact("n1", "observed"), fact("n2", "observed")]);
    const remote = view("vb", "node-b", [fact("n3", "stale"), fact("n4", "observed")]);
    const d = reconcilePartitionViews(RECON(local, remote));
    expectReconciled(d);
    if (!d.ok) return;
    expect(d.agreementCount).toBe(0);
    expect(d.conflicts).toHaveLength(0);
    expect(d.localExclusiveCount).toBe(2);
    expect(d.remoteExclusiveCount).toBe(2);
    expect(d.merged.facts.map((f) => f.subjectNodeId)).toEqual(["n1", "n2", "n3", "n4"]);
    // each side's exclusive claim is attributed to THAT side — and is NOT refreshed on rejoin
    const n3 = d.merged.facts.find((f) => f.subjectNodeId === "n3");
    expect(n3?.state).toBe("stale");
    expect(n3?.conflicted).toBe(false);
    expect(n3?.attributions).toHaveLength(1);
    expect(n3?.attributions[0]?.ownerNodeId).toBe("node-b");
    expect(n3?.attributions[0]?.source).toBe("governed_evidence");
    const n1 = d.merged.facts.find((f) => f.subjectNodeId === "n1");
    expect(n1?.attributions[0]?.ownerNodeId).toBe("node-a");
    // counts add up: agreement + conflicts + exclusives = merged facts
    expect(d.agreementCount + d.conflicts.length + d.localExclusiveCount + d.remoteExclusiveCount).toBe(
      d.merged.facts.length,
    );
  });

  it("a shared subject in agreement carries BOTH attributions (local first) and counts add up", () => {
    const local = view("va", "node-a", [fact("n1", "observed"), fact("n2", "observed")]);
    const remote = view("vb", "node-b", [fact("n1", "observed"), fact("n3", "stale")]);
    const d = reconcilePartitionViews(RECON(local, remote));
    expectReconciled(d);
    if (!d.ok) return;
    expect(d.agreementCount).toBe(1);
    expect(d.conflicts).toHaveLength(0);
    expect(d.localExclusiveCount).toBe(1);
    expect(d.remoteExclusiveCount).toBe(1);
    const shared = d.merged.facts.find((f) => f.subjectNodeId === "n1");
    expect(shared?.conflicted).toBe(false);
    expect(shared?.attributions).toHaveLength(2);
    expect(shared?.attributions.map((a) => a.ownerNodeId)).toEqual(["node-a", "node-b"]);
    expect(shared?.attributions.every((a) => a.state === "observed")).toBe(true);
    expect(d.agreementCount + d.conflicts.length + d.localExclusiveCount + d.remoteExclusiveCount).toBe(
      d.merged.facts.length,
    );
  });
});

// ── conflicts stay attributable ──────────────────────────────────────────────

describe("27G conflicts — attributable claims, never a winner", () => {
  it("disagreeing non-terminal claims merge to unknown_observation with BOTH claims fully attributed", () => {
    const local = view("va", "node-a", [fact("n1", "observed", { provenance: prov({ recordedAtEpochMs: NOW }) })]);
    const remote = view("vb", "node-b", [fact("n1", "stale", { provenance: prov({ recordedAtEpochMs: NOW + 5_000 }) })]);
    const d = reconcilePartitionViews(RECON(local, remote));
    expectReconciled(d);
    if (!d.ok) return;
    const mergedFact = exactlyOne(d.merged.facts);
    expect(mergedFact.state).toBe("unknown_observation"); // no consensus => no invented winner
    expect(mergedFact.conflicted).toBe(true);
    expect(mergedFact.attributions.map((a) => a.state)).toEqual(["observed", "stale"]);
    const conflict = exactlyOne(d.conflicts);
    expect(conflict.subjectNodeId).toBe("n1");
    expect(conflict.localState).toBe("observed");
    expect(conflict.remoteState).toBe("stale");
    expect(conflict.localOwnerNodeId).toBe("node-a");
    expect(conflict.remoteOwnerNodeId).toBe("node-b");
    expect(conflict.localRecordedAtEpochMs).toBe(NOW);
    expect(conflict.remoteRecordedAtEpochMs).toBe(NOW + 5_000);
    expect(conflict.resolution).toBe("no_consensus_unknown");
    expect(d.agreementCount).toBe(0);
    expect(d.conflicts).toHaveLength(d.merged.facts.filter((f) => f.conflicted).length);
  });

  it("the mirrored disagreement classifies identically (unknown vs observed too) — no side wins", () => {
    const mirrored = reconcilePartitionViews(
      RECON(view("va", "node-a", [fact("n1", "stale")]), view("vb", "node-b", [fact("n1", "observed")])),
    );
    expectReconciled(mirrored);
    if (mirrored.ok) {
      expect(exactlyOne(mirrored.merged.facts).state).toBe("unknown_observation");
      const c = exactlyOne(mirrored.conflicts);
      expect(c.localState).toBe("stale");
      expect(c.remoteState).toBe("observed");
      expect(c.resolution).toBe("no_consensus_unknown");
    }
    // an unknown claim against an observed claim stays unknown (unknown stays unknown)
    const unknownCase = reconcilePartitionViews(
      RECON(view("va", "node-a", [fact("n1", "unknown_observation")]), view("vb", "node-b", [fact("n1", "observed")])),
    );
    expectReconciled(unknownCase);
    if (unknownCase.ok) {
      expect(exactlyOne(unknownCase.merged.facts).state).toBe("unknown_observation");
      expect(exactlyOne(unknownCase.conflicts).resolution).toBe("no_consensus_unknown");
    }
  });
});

// ── anti-resurrection ────────────────────────────────────────────────────────

describe("27G anti-resurrection — terminal facts never come back; time never decides", () => {
  it("a FRESHER remote observed claim cannot resurrect a local retired fact", () => {
    const local = view("va", "node-a", [fact("n1", "retired_observation", { provenance: prov({ recordedAtEpochMs: NOW }) })]);
    const remote = view("vb", "node-b", [fact("n1", "observed", { provenance: prov({ recordedAtEpochMs: NOW + 60_000 }) })]);
    const d = reconcilePartitionViews(RECON(local, remote));
    expectReconciled(d);
    if (!d.ok) return;
    expect(exactlyOne(d.merged.facts).state).toBe("retired_observation");
    expect(exactlyOne(d.merged.facts).conflicted).toBe(true);
    const c = exactlyOne(d.conflicts);
    expect(c.resolution).toBe("terminal_retained");
    expect(c.remoteRecordedAtEpochMs).toBeGreaterThan(c.localRecordedAtEpochMs); // remote IS fresher — and still retained
    expect(c.localState).toBe("retired_observation");
    expect(c.remoteState).toBe("observed");
  });

  it("a FRESHER local observed claim cannot resurrect a remote retired fact either", () => {
    const d = reconcilePartitionViews(
      RECON(
        view("va", "node-a", [fact("n1", "observed", { provenance: prov({ recordedAtEpochMs: NOW + 60_000 }) })]),
        view("vb", "node-b", [fact("n1", "retired_observation", { provenance: prov({ recordedAtEpochMs: NOW }) })]),
      ),
    );
    expectReconciled(d);
    if (!d.ok) return;
    expect(exactlyOne(d.merged.facts).state).toBe("retired_observation");
    const c = exactlyOne(d.conflicts);
    expect(c.resolution).toBe("terminal_retained");
    expect(c.localState).toBe("observed");
    expect(c.remoteState).toBe("retired_observation");
  });

  it("swapping which side is fresher changes nothing (recorded times are attribution only)", () => {
    const a = reconcilePartitionViews(
      RECON(
        view("va", "node-a", [fact("n1", "retired_observation", { provenance: prov({ recordedAtEpochMs: 1_000 }) })]),
        view("vb", "node-b", [fact("n1", "observed", { provenance: prov({ recordedAtEpochMs: 9_000 }) })]),
      ),
    );
    const b = reconcilePartitionViews(
      RECON(
        view("va", "node-a", [fact("n1", "retired_observation", { provenance: prov({ recordedAtEpochMs: 9_000 }) })]),
        view("vb", "node-b", [fact("n1", "observed", { provenance: prov({ recordedAtEpochMs: 1_000 }) })]),
      ),
    );
    expectReconciled(a);
    expectReconciled(b);
    if (!a.ok || !b.ok) return;
    expect(exactlyOne(a.merged.facts).state).toBe("retired_observation");
    expect(exactlyOne(b.merged.facts).state).toBe("retired_observation");
    expect(exactlyOne(a.conflicts).resolution).toBe("terminal_retained");
    expect(exactlyOne(b.conflicts).resolution).toBe("terminal_retained");
  });
});

// ── quarantine never auto-clears ─────────────────────────────────────────────

describe("27G quarantine — rejoin is not a transition; quarantine never auto-clears", () => {
  it("a fresher remote quarantine is retained against a local observed claim", () => {
    const d = reconcilePartitionViews(
      RECON(
        view("va", "node-a", [fact("n1", "observed", { provenance: prov({ recordedAtEpochMs: NOW }) })]),
        view("vb", "node-b", [fact("n1", "quarantined_observation", { provenance: prov({ recordedAtEpochMs: NOW + 60_000 }) })]),
      ),
    );
    expectReconciled(d);
    if (!d.ok) return;
    expect(exactlyOne(d.merged.facts).state).toBe("quarantined_observation");
    const c = exactlyOne(d.conflicts);
    expect(c.resolution).toBe("quarantine_retained");
    expect(c.localState).toBe("observed");
    expect(c.remoteState).toBe("quarantined_observation");
    expect(c.remoteRecordedAtEpochMs).toBeGreaterThan(c.localRecordedAtEpochMs);
  });

  it("local quarantine is retained against stale and against unknown (quarantine precedes no-consensus unknown)", () => {
    const againstStale = reconcilePartitionViews(
      RECON(view("va", "node-a", [fact("n1", "quarantined_observation")]), view("vb", "node-b", [fact("n1", "stale")])),
    );
    expectReconciled(againstStale);
    if (againstStale.ok) {
      expect(exactlyOne(againstStale.merged.facts).state).toBe("quarantined_observation");
      expect(exactlyOne(againstStale.conflicts).resolution).toBe("quarantine_retained");
    }
    const againstUnknown = reconcilePartitionViews(
      RECON(view("va", "node-a", [fact("n1", "quarantined_observation")]), view("vb", "node-b", [fact("n1", "unknown_observation")])),
    );
    expectReconciled(againstUnknown);
    if (againstUnknown.ok) {
      expect(exactlyOne(againstUnknown.merged.facts).state).toBe("quarantined_observation");
      expect(exactlyOne(againstUnknown.conflicts).resolution).toBe("quarantine_retained");
    }
  });

  it("terminal outranks quarantine: retired vs quarantined classifies terminal_retained", () => {
    const d = reconcilePartitionViews(
      RECON(view("va", "node-a", [fact("n1", "retired_observation")]), view("vb", "node-b", [fact("n1", "quarantined_observation")])),
    );
    expectReconciled(d);
    if (!d.ok) return;
    expect(exactlyOne(d.merged.facts).state).toBe("retired_observation");
    expect(exactlyOne(d.conflicts).resolution).toBe("terminal_retained");
  });
});

// ── purity: no mutation, duplicates are no-ops ───────────────────────────────

describe("27G purity — inputs never mutated; duplicate proposals are byte-identical no-ops", () => {
  it("neither input view is ever mutated — success and refusal leave both sides byte-identical", () => {
    const input = deepFreeze(
      RECON(
        view("va", "node-a", [fact("n1", "observed"), fact("n2", "stale")]),
        view("vb", "node-b", [fact("n1", "stale"), fact("n3", "observed")]),
      ),
    );
    const before = JSON.stringify(input);
    expectReconciled(reconcilePartitionViews(input));
    expect(JSON.stringify(input)).toBe(before);
    // the refusal path is equally pure (cross-epoch views)
    const refusedInput = deepFreeze(
      RECON(
        view("va", "node-a", [fact("n1", "observed")]),
        view("vb", "node-b", [fact("n1", "observed")], { epochId: "epoch-other" }),
      ),
    );
    const refusedBefore = JSON.stringify(refusedInput);
    expectRefusal(reconcilePartitionViews(refusedInput), "refused_epoch_mismatch");
    expect(JSON.stringify(refusedInput)).toBe(refusedBefore);
  });

  it("two identical reconciliations (duplicate proposals) produce byte-identical decisions", () => {
    const build = () =>
      RECON(
        view("va", "node-a", [fact("n1", "observed"), fact("n2", "retired_observation")]),
        view("vb", "node-b", [fact("n1", "stale"), fact("n4", "observed")]),
      );
    const first = reconcilePartitionViews(build());
    const second = reconcilePartitionViews(build());
    expectReconciled(first);
    expectReconciled(second);
    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
    expect(second.reconciliationHash).toBe(first.reconciliationHash);
    // duplicates of a REFUSED reconciliation are equally identical (no drift)
    const refuseBuild = () =>
      RECON(
        view("va", "node-a", [fact("n1", "weird_state" as unknown as TopologyObservationState)]),
        view("vb", "node-b", []),
      );
    const r1 = reconcilePartitionViews(refuseBuild());
    const r2 = reconcilePartitionViews(refuseBuild());
    expectRefusal(r1, "refused_unknown_state");
    expectRefusal(r2, "refused_unknown_state");
    expect(JSON.stringify(r2)).toBe(JSON.stringify(r1));
    expect(r2.reconciliationHash).toBe(r1.reconciliationHash);
  });

  it("merged facts are deterministically sorted by subject regardless of input order", () => {
    const orderA = reconcilePartitionViews(
      RECON(
        view("va", "node-a", [fact("n9", "observed"), fact("n1", "observed"), fact("n5", "observed")]),
        view("vb", "node-b", [fact("n7", "observed"), fact("n3", "observed")]),
      ),
    );
    const orderB = reconcilePartitionViews(
      RECON(
        view("va", "node-a", [fact("n5", "observed"), fact("n9", "observed"), fact("n1", "observed")]),
        view("vb", "node-b", [fact("n3", "observed"), fact("n7", "observed")]),
      ),
    );
    expectReconciled(orderA);
    expectReconciled(orderB);
    if (!orderA.ok || !orderB.ok) return;
    const subjectsA = orderA.merged.facts.map((f) => f.subjectNodeId);
    const subjectsB = orderB.merged.facts.map((f) => f.subjectNodeId);
    expect(subjectsA).toEqual(["n1", "n3", "n5", "n7", "n9"]);
    expect(subjectsB).toEqual(subjectsA);
  });
});

// ── fail-closed inputs ───────────────────────────────────────────────────────

describe("27G fail-closed inputs — epoch, duplicates, vocabulary, provenance, shape, bounds", () => {
  it("cross-epoch views refuse (epoch substitution never reconciles)", () => {
    const d = reconcilePartitionViews(
      RECON(
        view("va", "node-a", [fact("n1", "observed")]),
        view("vb", "node-b", [fact("n1", "observed")], { epochId: "epoch-27h" }),
      ),
    );
    expectRefusal(d, "refused_epoch_mismatch");
  });

  it("a fact from ANOTHER epoch refuses inside an otherwise same-epoch view", () => {
    const d = reconcilePartitionViews(
      RECON(view("va", "node-a", [fact("n1", "observed", { epochId: "epoch-old" })]), view("vb", "node-b", [])),
    );
    expectRefusal(d, "refused_epoch_mismatch");
  });

  it("a view that contradicts itself (duplicate subject) refuses — local AND remote side", () => {
    const dupLocal = reconcilePartitionViews(
      RECON(view("va", "node-a", [fact("n1", "observed"), fact("n1", "stale")]), view("vb", "node-b", [])),
    );
    expectRefusal(dupLocal, "refused_duplicate_fact");
    const dupRemote = reconcilePartitionViews(
      RECON(view("va", "node-a", []), view("vb", "node-b", [fact("n1", "observed"), fact("n1", "observed")])),
    );
    expectRefusal(dupRemote, "refused_duplicate_fact");
  });

  it("an unnamed observation state refuses under the frozen 27C vocabulary", () => {
    const d = reconcilePartitionViews(
      RECON(view("va", "node-a", [fact("n1", "weird_state" as unknown as TopologyObservationState)]), view("vb", "node-b", [])),
    );
    expectRefusal(d, "refused_unknown_state");
  });

  it("unsanctioned provenance sources refuse (unknown_source, unnamed, and missing)", () => {
    const unknownSource = reconcilePartitionViews(
      RECON(view("va", "node-a", [fact("n1", "observed", { provenance: prov({ source: "unknown_source" }) })]), view("vb", "node-b", [])),
    );
    expectRefusal(unknownSource, "refused_unknown_provenance_source");
    const gossip = reconcilePartitionViews(
      RECON(
        view("va", "node-a", [
          fact("n1", "observed", {
            provenance: { source: "gossip", evidenceId: "ev-1", recordedAtEpochMs: NOW } as unknown as TopologyProvenance,
          }),
        ]),
        view("vb", "node-b", []),
      ),
    );
    expectRefusal(gossip, "refused_unknown_provenance_source");
    const missing = reconcilePartitionViews(
      RECON(
        view("va", "node-a", [
          fact("n1", "observed", {
            provenance: { evidenceId: "ev-1", recordedAtEpochMs: NOW } as unknown as TopologyProvenance,
          }),
        ]),
        view("vb", "node-b", []),
      ),
    );
    expectRefusal(missing, "refused_unknown_provenance_source");
  });

  it("provenance rules refuse: governed must cite, local must not, time must be finite and non-negative", () => {
    const cases: readonly { readonly input: ReconciliationInput; readonly refusal: ReconciliationRefusalCode }[] = [
      {
        input: RECON(view("va", "node-a", [fact("n1", "observed", { provenance: prov({ evidenceId: null }) })]), view("vb", "node-b", [])),
        refusal: "refused_invalid_provenance",
      },
      {
        input: RECON(view("va", "node-a", [fact("n1", "observed", { provenance: prov({ evidenceId: "" }) })]), view("vb", "node-b", [])),
        refusal: "refused_invalid_provenance",
      },
      {
        input: RECON(
          view("va", "node-a", [fact("n1", "observed", { provenance: prov({ source: "local_configuration", evidenceId: "ev-9" }) })]),
          view("vb", "node-b", []),
        ),
        refusal: "refused_invalid_provenance",
      },
      {
        input: RECON(view("va", "node-a", [fact("n1", "observed", { provenance: prov({ recordedAtEpochMs: Number.NaN }) })]), view("vb", "node-b", [])),
        refusal: "refused_invalid_provenance",
      },
      {
        input: RECON(view("va", "node-a", [fact("n1", "observed", { provenance: prov({ recordedAtEpochMs: -1 }) })]), view("vb", "node-b", [])),
        refusal: "refused_invalid_provenance",
      },
      {
        input: RECON(
          view("va", "node-a", [fact("n1", "observed", { provenance: prov({ recordedAtEpochMs: Number.POSITIVE_INFINITY }) })]),
          view("vb", "node-b", []),
        ),
        refusal: "refused_invalid_provenance",
      },
    ];
    for (const c of cases) {
      expectRefusal(reconcilePartitionViews(c.input), c.refusal);
    }
  });

  it("malformed shapes refuse (null view, missing facts, null fact, empty ids, empty subject)", () => {
    expectRefusal(reconcilePartitionViews(RECON(null as unknown as PartitionView, view("vb", "node-b", []))), "refused_invalid_view");
    expectRefusal(
      reconcilePartitionViews(RECON({ viewId: "va", ownerNodeId: "node-a", epochId: EPOCH } as unknown as PartitionView, view("vb", "node-b", []))),
      "refused_invalid_view",
    );
    expectRefusal(
      reconcilePartitionViews(RECON(view("va", "node-a", [null as unknown as PartitionFact]), view("vb", "node-b", []))),
      "refused_invalid_view",
    );
    expectRefusal(reconcilePartitionViews(RECON(view("", "node-a", []), view("vb", "node-b", []))), "refused_invalid_view");
    expectRefusal(reconcilePartitionViews(RECON(view("va", "", []), view("vb", "node-b", []))), "refused_invalid_view");
    expectRefusal(reconcilePartitionViews(RECON(view("va", "node-a", [fact("", "observed")]), view("vb", "node-b", []))), "refused_invalid_view");
  });

  it("frozen bounds refuse — never truncate: 65 facts and every oversize id", () => {
    const atBound = reconcilePartitionViews(RECON(view("va", "node-a", manyFacts(64)), view("vb", "node-b", [])));
    expectReconciled(atBound); // 64 = exactly at the bound reconciles
    expectRefusal(reconcilePartitionViews(RECON(view("va", "node-a", manyFacts(65)), view("vb", "node-b", []))), "refused_field_bound");
    expectRefusal(reconcilePartitionViews(RECON(view("va", "node-a", []), view("v".repeat(129), "node-b", []))), "refused_field_bound");
    expectRefusal(reconcilePartitionViews(RECON(view("va", "node-a", []), view("vb", "x".repeat(129), []))), "refused_field_bound");
    expectRefusal(
      reconcilePartitionViews(RECON(view("va", "node-a", [fact("x".repeat(129), "observed")]), view("vb", "node-b", []))),
      "refused_field_bound",
    );
    expectRefusal(
      reconcilePartitionViews(
        RECON(view("va", "node-a", [fact("n1", "observed", { provenance: prov({ evidenceId: "e".repeat(129) }) })]), view("vb", "node-b", [])),
      ),
      "refused_field_bound",
    );
  });

  it("every refusal is a closed-set code with an explained refus-al and no authority surface", () => {
    const bad: readonly ReconciliationInput[] = [
      RECON(null as unknown as PartitionView, view("vb", "node-b", [])),
      RECON(view("va", "node-a", manyFacts(65)), view("vb", "node-b", [])),
      RECON(view("va", "node-a", [fact("n1", "observed")]), view("vb", "node-b", [fact("n1", "observed")], { epochId: "epoch-27h" })),
      RECON(view("va", "node-a", [fact("n1", "observed"), fact("n1", "stale")]), view("vb", "node-b", [])),
      RECON(view("va", "node-a", [fact("n1", "weird_state" as unknown as TopologyObservationState)]), view("vb", "node-b", [])),
      RECON(view("va", "node-a", [fact("n1", "observed", { provenance: prov({ source: "unknown_source" }) })]), view("vb", "node-b", [])),
      RECON(view("va", "node-a", [fact("n1", "observed", { provenance: prov({ evidenceId: null }) })]), view("vb", "node-b", [])),
    ];
    const observed = new Set<string>();
    for (const input of bad) {
      const d = reconcilePartitionViews(input);
      expect(d.ok).toBe(false);
      if (d.ok) continue;
      expect((RECONCILIATION_REFUSAL_CODES as readonly string[]).includes(d.refusal)).toBe(true);
      observed.add(d.refusal);
      expect(d.explanation).toMatch(/refus/);
      expect(d.explanation.length).toBeGreaterThan(20);
      expect("authority" in d).toBe(false);
      expect("merged" in d).toBe(false);
      expect("consensusReached" in d).toBe(false);
      const json = JSON.stringify(d);
      expect(json).not.toMatch(/authority|consensusReached|trustTransferred|autoResumed|"merged"/);
    }
    // 7 of the 8 closed codes are reachable by construction; refused_unknown is the
    // unmapped catch-all (fail-closed by definition, never asserted as reachable).
    expect(observed.size).toBe(7);
  });
});

// ── output shape pin ─────────────────────────────────────────────────────────

describe("27G output shape — pinned keys, merged knowledge carries NO authority surface", () => {
  it("success decision, merged view, facts, attributions, and conflicts expose EXACTLY the pinned keys", () => {
    const d = reconcilePartitionViews(
      RECON(
        view("va", "node-a", [fact("n1", "observed"), fact("n2", "observed")]),
        view("vb", "node-b", [fact("n1", "stale"), fact("n3", "observed")]),
        { reconciliationId: "rec-shape" },
      ),
    );
    expectReconciled(d);
    if (!d.ok) return;
    expect(Object.keys(d).sort()).toEqual(
      [
        "ok",
        "code",
        "reconciliationId",
        "merged",
        "conflicts",
        "agreementCount",
        "localExclusiveCount",
        "remoteExclusiveCount",
        "authority",
        "consensusReached",
        "globalOrdering",
        "autoResumed",
        "trustTransferred",
        "explanation",
        "reconciliationHash",
      ].sort(),
    );
    expect(Object.keys(d.merged).sort()).toEqual(["viewId", "epochId", "facts"].sort());
    // EVERY merged fact and attribution exposes exactly the pinned keys (3 facts here)
    expect(d.merged.facts.length).toBe(3);
    for (const mergedFact of d.merged.facts) {
      expect(Object.keys(mergedFact).sort()).toEqual(["subjectNodeId", "state", "conflicted", "attributions"].sort());
      expect(mergedFact.attributions.length).toBeGreaterThan(0);
      for (const attribution of mergedFact.attributions) {
        expect(Object.keys(attribution).sort()).toEqual(
          ["ownerNodeId", "state", "source", "evidenceId", "recordedAtEpochMs"].sort(),
        );
      }
    }
    expect(Object.keys(exactlyOne(d.conflicts)).sort()).toEqual(
      [
        "subjectNodeId",
        "localState",
        "remoteState",
        "localOwnerNodeId",
        "remoteOwnerNodeId",
        "localRecordedAtEpochMs",
        "remoteRecordedAtEpochMs",
        "resolution",
      ].sort(),
    );
  });

  it("merged output JSON contains no authority/trust/grant/consensus/quorum/leader token anywhere", () => {
    const d = reconcilePartitionViews(
      RECON(
        view("va", "node-a", [fact("n1", "observed"), fact("n2", "observed")]),
        view("vb", "node-b", [fact("n1", "stale"), fact("n3", "observed")]),
      ),
    );
    expectReconciled(d);
    if (!d.ok) return;
    const json = JSON.stringify({ merged: d.merged, conflicts: d.conflicts });
    expect(json).not.toMatch(/authority/i);
    expect(json).not.toMatch(/trust/i);
    expect(json).not.toMatch(/grant/i);
    expect(json).not.toMatch(/quorum/i);
    expect(json).not.toMatch(/leader/i);
    // no consensus KEY or claim — the pinned label "no_consensus_unknown" is the
    // conflict VOCABULARY asserting the absence of consensus, not a consensus claim
    expect(json).not.toMatch(/consensusReached|"consensus"\s*:/);
    expect(json).not.toMatch(/autoResumed\s*:\s*true|globalOrdering\s*:\s*true/);
  });

  it("merged view identity: viewId = reconciliationId, epochId = view epoch, conflicts = conflicted count", () => {
    const d = reconcilePartitionViews(
      RECON(
        view("va", "node-a", [fact("n1", "observed"), fact("n2", "observed")]),
        view("vb", "node-b", [fact("n1", "stale"), fact("n3", "observed")]),
        { reconciliationId: "rec-identity" },
      ),
    );
    expectReconciled(d);
    if (!d.ok) return;
    expect(d.merged.viewId).toBe("rec-identity");
    expect(d.merged.epochId).toBe(EPOCH);
    expect(d.conflicts).toHaveLength(d.merged.facts.filter((f) => f.conflicted).length);
    expect(d.conflicts.length).toBeGreaterThan(0); // the batch must actually conflict
  });
});
