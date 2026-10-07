/**
 * PHASE 28D — EVIDENCE-TO-VISUAL SEMANTIC MAPPING
 * (SEMANTIC TOKENS ONLY / NO GRAPHICS BACKEND / RENDERER-NEUTRAL)
 *
 * The prompt's central law is one-directional: simplification may WEAKEN a
 * semantic claim, never strengthen one. That is easy to assert in prose and
 * easy to get wrong in code, so most of this suite attacks the module from the
 * renderer's side — asking "what could a dishonest renderer get away with?" —
 * and requires the answer to be a typed refusal.
 *
 * The tests fall into four kinds:
 *   1. BEHAVIOUR — what the builder, the tier ceiling and the coarsening gate do.
 *   2. THE EIGHT PROMOTIONS — each one tested against the specific mechanism
 *      its row in `GETIG_VISUAL_FORBIDDEN_PROMOTIONS` claims. An earlier draft
 *      of this gate asserted that every promotion was prevented by the target
 *      value being absent; that was false (`origin` and `current` both exist)
 *      and a test caught it. So each row now names its real mechanism and each
 *      is verified here.
 *   3. LAW AUDITS — scans over the emitted artefact, each paired with a
 *      SELF-TEST that plants a synthetic violation and proves the scan catches
 *      it. A scan that cannot fail reports PASS while matching nothing.
 *   4. INTEGRATION — real 28A frames built by the real 28A builder.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  buildGetigVisualMapping,
  planGetigPresentationCoarsening,
  refuseVisualSelectionToPermission,
  getigVisualSemanticRank,
  getigVisualPermittedTiers,
  buildGetigFrame,
  GETIG_VISUAL_AXES,
  GETIG_VISUAL_VALUES,
  GETIG_VISUAL_NON_COLLAPSIBLE_AXES,
  GETIG_VISUAL_FORBIDDEN_PROMOTIONS,
  GETIG_VISUAL_PRESENTATION_TIERS,
  GETIG_VISUAL_PRESENTATION_TIER_RANK,
  GETIG_VISUAL_REFUSAL_CODES,
  GETIG_VISUAL_BOUNDS,
  GETIG_VISUAL_SCHEMA_VERSION,
  type GetigVisualAxis,
  type GetigFrameInput,
} from "../../packages/durable-state/dist/index.js";

const SRC_PATH = join(process.cwd(), "packages", "durable-state", "src", "getigVisualMapping.ts");
const DTS_PATH = join(process.cwd(), "packages", "durable-state", "dist", "getigVisualMapping.d.ts");
const NOW = 1_700_000_000_000;
const EPOCH = "epoch-28d";

function readSourceOrThrow(path: string): string {
  const text = readFileSync(path, "utf8");
  if (text.length === 0) throw new Error(`audit input is empty: ${path}`);
  return text;
}

const hex = (d: string) => d.repeat(64);

const observer = {
  observerId: "observer-local-1",
  observerKind: "local_runtime" as const,
  epochId: EPOCH,
  isGlobalTruth: false as const,
};

const ent = (visibleId: string, over: Record<string, unknown> = {}) => ({
  visibleId,
  kind: "runtime_node" as const,
  label: `label-${visibleId}`,
  isRuntimeObject: false as const,
  grant: "none" as const,
  freshness: "current" as const,
  lifecycle: "observed" as const,
  provenanceRefs: [],
  representsRuntimeId: null,
  ...over,
});

const route = (routeId: string, over: Record<string, unknown> = {}) => ({
  routeId,
  originVisibleId: "n1",
  originFixed: true as const,
  forwarderVisibleIds: [] as string[],
  destinationVisibleId: "n3",
  freshness: "current" as const,
  provenanceRefs: [],
  admission: "none" as const,
  authorization: "none" as const,
  executionAuthorized: false as const,
  ...over,
});

const frame = (over: Record<string, unknown> = {}) => ({
  schemaVersion: "menog-getig/v0",
  frameId: "frame-a",
  observer,
  epochId: EPOCH,
  asOfEpochMs: NOW,
  sourceProjectionHash: hex("a"),
  canonicalVisibleHash: hex("b"),
  entities: [],
  relations: [],
  events: [],
  conflicts: [],
  refusals: [],
  routes: [],
  proposalFlows: [],
  authority: "none",
  controlPlane: "none",
  readOnly: true,
  replaySemantics: "visual_only_not_executable",
  globalTruth: false,
  visibleCapabilities: [],
  ...over,
});

const map = (over: Record<string, unknown> = {}, args: Record<string, unknown> = {}) =>
  buildGetigVisualMapping({ frameId: "mapping-1", frame: frame(over), ...args } as never);

function mapped(over: Record<string, unknown> = {}, args: Record<string, unknown> = {}) {
  const decision = map(over, args);
  if (!decision.ok) throw new Error(`expected a built mapping, got ${decision.refusal}: ${decision.explanation}`);
  return decision.mapping;
}

const valuesOn = (mapping: ReturnType<typeof mapped>, axis: GetigVisualAxis) =>
  mapping.tokens.filter((t) => t.axis === axis).map((t) => t.semanticValue);

// ── 1. behaviour ─────────────────────────────────────────────────────────────

describe("28D — mapping construction", () => {
  it("builds a deterministic mapping over the same frame", () => {
    const a = mapped({ entities: [ent("n1"), ent("n2")] });
    const b = mapped({ entities: [ent("n1"), ent("n2")] });
    expect(a.mappingHash).toBe(b.mappingHash);
    expect(a.tokenCount).toBe(b.tokenCount);
  });

  it("is insensitive to the order entities arrive in", () => {
    const forwards = mapped({ entities: [ent("n1"), ent("n2"), ent("n3")] });
    const backwards = mapped({ entities: [ent("n3"), ent("n2"), ent("n1")] });
    expect(forwards.mappingHash).toBe(backwards.mappingHash);
    expect(forwards.tokens.map((t) => t.tokenId)).toEqual(backwards.tokens.map((t) => t.tokenId));
  });

  it("freezes the mapping and every token", () => {
    const m = mapped({ entities: [ent("n1")] });
    expect(Object.isFrozen(m)).toBe(true);
    expect(Object.isFrozen(m.tokens)).toBe(true);
    expect(Object.isFrozen(m.tokens[0])).toBe(true);
    expect(Object.isFrozen(m.tokens[0]!.permittedPresentationTiers)).toBe(true);
  });

  it("carries every subject's semantic axes", () => {
    const m = mapped({
      entities: [ent("n1", { freshness: "stale", lifecycle: "quarantined" })],
      relations: [{ relationId: "r1", kind: "observed_edge", fromVisibleId: "n1", toVisibleId: "n2", trust: "none", provenanceRefs: [] }],
      events: [{ eventId: "ev1", kind: "observed_change", atEpochMs: NOW, subjectVisibleId: "n1", executable: false, action: "none", freshness: "current" }],
      refusals: [{ refusalId: "rf1", code: "refused_network_admission", subjectVisibleId: "n2", explanation: "not admitted" }],
      conflicts: [{ conflictId: "c1", kind: "observation_conflict", attributedToObserverId: "observer-local-1", subjectVisibleId: "n1", claims: [], resolution: "no_consensus_unknown", resolved: false }],
    });
    const axes = new Set(m.tokens.map((t) => t.axis));
    for (const axis of ["knowledge", "freshness", "lifecycle", "grant", "refusal", "conflict", "authority"]) {
      expect(axes.has(axis as GetigVisualAxis), `missing axis ${axis}`).toBe(true);
    }
    expect(valuesOn(m, "freshness")).toContain("stale");
    expect(valuesOn(m, "lifecycle")).toContain("quarantined");
    expect(valuesOn(m, "refusal")).toEqual(["refused"]);
    expect(valuesOn(m, "conflict")).toEqual(["conflict_visible"]);
  });

  it("does not mutate the frame it was given", () => {
    const f = frame({ entities: [ent("n1")] });
    const copy = JSON.stringify(f);
    map({ entities: [ent("n1")] });
    expect(JSON.stringify(f)).toBe(copy);
  });

  it("gives every token descriptive-only, zero-authority, non-mutating semantics", () => {
    const m = mapped({ entities: [ent("n1")], routes: [route("rt1")] });
    for (const token of m.tokens) {
      expect(token.claim).toBe("descriptive_only");
      expect(token.authority).toBe("none");
      expect(token.mutation).toBe("none");
      expect(token.executable).toBe(false);
    }
  });

  it("carries provenance as metadata only", () => {
    const m = mapped({
      entities: [
        ent("n1", {
          provenanceRefs: [{ refId: "ref-1", recordedAtEpochMs: NOW, sourceKind: "governed_evidence", evidenceId: "ev-1", confersTrust: false }],
        }),
      ],
    });
    expect(m.tokens[0]!.provenanceRefIds).toEqual(["ref-1"]);
    expect(m.tokens[0]!.authority).toBe("none");
    expect(m.tokens[0]!.claim).toBe("descriptive_only");
  });

  it("pins the mapping's own structural zeros", () => {
    const m = mapped({ entities: [ent("n1")] });
    expect(m.schemaVersion).toBe(GETIG_VISUAL_SCHEMA_VERSION);
    expect(m.rendererNeutral).toBe(true);
    expect(m.colorIsCanonicalMeaning).toBe(false);
    expect(m.graphicsBackend).toBe("none");
    expect(m.readOnly).toBe(true);
    expect(m.authority).toBe("none");
    expect(m.globalTruth).toBe(false);
    expect(m.strengthensSemanticClaims).toBe(false);
  });

  it("emits a partition token for every observed partition, and accepts the 27H field name", () => {
    // 28A's frame carries NO partition collection, so partitions arrive as
    // evidence. 27H names them `reconciliationId`, so both spellings must work
    // or a real upstream partition would produce no token at all.
    const m = mapped({}, {
      partitions: [
        { partitionId: "p-1", epochId: EPOCH, agreementCount: 1 },
        { reconciliationId: "rec-2", epochId: EPOCH, agreementCount: 0 },
      ],
    });
    const partitionTokens = m.tokens.filter((t) => t.axis === "partition");
    expect(partitionTokens.map((t) => t.semanticValue)).toEqual(["partitioned", "partitioned"]);
    expect(partitionTokens.map((t) => t.subjectVisibleId).sort()).toEqual(["p-1", "rec-2"]);
  });

  it("emits no partition token when none were observed, rather than inventing one", () => {
    const m = mapped({ entities: [ent("n1")] });
    expect(m.tokens.filter((t) => t.axis === "partition")).toEqual([]);
    // A frame carrying no partitions is not a frame whose partitions are hidden.
    expect(m.tokenCount).toBeGreaterThan(0);
  });

  it("refuses a partition record with no usable id rather than dropping it", () => {
    const decision = map({}, { partitions: [{ epochId: EPOCH }] });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_mapping_unknown_subject");
    const notAnObject = map({}, { partitions: ["p-1"] });
    expect(notAnObject.ok).toBe(false);
    const notAnArray = map({}, { partitions: "p-1" });
    expect(notAnArray.ok).toBe(false);
  });

  it("maps a subject whose freshness is absent to unknown, never to current", () => {
    const m = mapped({ entities: [{ ...ent("n1"), freshness: undefined }] });
    expect(valuesOn(m, "freshness")).toEqual(["unknown"]);
  });
});

describe("28D — the tier ceiling: an unknown fact can only be withheld", () => {
  it("publishes exactly the tiers at or below a value's own rank", () => {
    expect(getigVisualPermittedTiers(0)).toEqual(["withheld"]);
    expect(getigVisualPermittedTiers(1)).toEqual(["withheld", "minimal"]);
    expect(getigVisualPermittedTiers(2)).toEqual(["withheld", "minimal", "declared"]);
  });

  it("gives an unknown token only the withheld tier", () => {
    const m = mapped({ entities: [ent("n1", { freshness: "unknown" })] });
    const token = m.tokens.find((t) => t.axis === "freshness")!;
    expect(token.semanticValue).toBe("unknown");
    expect(token.semanticRank).toBe(0);
    expect(token.permittedPresentationTiers).toEqual(["withheld"]);
  });

  it("never lets a token list a tier above its own rank", () => {
    const m = mapped({
      entities: [ent("n1"), ent("n2", { freshness: "stale" }), ent("n3", { freshness: "unknown" })],
      routes: [route("rt1", { forwarderVisibleIds: ["n2"] })],
    });
    for (const token of m.tokens) {
      const worst = Math.max(...token.permittedPresentationTiers.map((t) => GETIG_VISUAL_PRESENTATION_TIER_RANK[t]));
      expect(worst, `${token.tokenId} permits a tier above its rank`).toBeLessThanOrEqual(token.semanticRank);
    }
  });

  it("orders every axis weakest claim to strongest", () => {
    expect(GETIG_VISUAL_VALUES.freshness).toEqual(["unknown", "stale", "current"]);
    expect(getigVisualSemanticRank("freshness", "unknown")).toBe(0);
    expect(getigVisualSemanticRank("freshness", "current")).toBe(2);
    // Unknown outranks nothing; it is the weakest claim on its axis.
    for (const axis of GETIG_VISUAL_AXES) {
      expect(getigVisualSemanticRank(axis, GETIG_VISUAL_VALUES[axis][0]!)).toBe(0);
    }
  });

  it("reports -1 for a value outside a closed vocabulary", () => {
    expect(getigVisualSemanticRank("freshness", "brand_new")).toBe(-1);
  });
});

// ── 2. the eight promotions, each against its stated mechanism ───────────────

describe("28D — forbidden promotion table is internally honest", () => {
  const allValues = Object.values(GETIG_VISUAL_VALUES).flat();

  it("names exactly the eight promotions the prompt requires", () => {
    expect(GETIG_VISUAL_FORBIDDEN_PROMOTIONS.map((p) => p.id).sort()).toEqual([
      "claim_to_granted",
      "conflict_to_hidden",
      "forwarder_to_origin",
      "observed_edge_to_admitted",
      "observer_view_to_global_truth",
      "route_to_authorized",
      "stale_to_current",
      "unknown_to_trusted",
    ]);
  });

  it("names a `from` value that exists on the axis it claims", () => {
    for (const promotion of GETIG_VISUAL_FORBIDDEN_PROMOTIONS) {
      const values = GETIG_VISUAL_VALUES[promotion.axis];
      expect(values, `${promotion.id} names an unknown axis`).toBeDefined();
      expect(values, `${promotion.id} names a from-value absent from its axis`).toContain(promotion.from);
    }
  });

  it("holds every row that claims `value_absent`", () => {
    for (const promotion of GETIG_VISUAL_FORBIDDEN_PROMOTIONS) {
      if (!promotion.prevented_by.includes("value_absent")) continue;
      expect(allValues, `${promotion.id} claims absence but ${promotion.strengthened_value} exists`).not.toContain(
        promotion.strengthened_value,
      );
    }
  });

  it("holds every row that claims a non-collapsible axis", () => {
    for (const promotion of GETIG_VISUAL_FORBIDDEN_PROMOTIONS) {
      if (!promotion.prevented_by.includes("axis_non_collapsible")) continue;
      expect(GETIG_VISUAL_NON_COLLAPSIBLE_AXES as readonly string[]).toContain(promotion.axis);
    }
  });

  it("holds every row that claims a permitted-tier ceiling", () => {
    for (const promotion of GETIG_VISUAL_FORBIDDEN_PROMOTIONS) {
      if (!promotion.prevented_by.includes("permitted_tier_ceiling")) continue;
      const from = getigVisualSemanticRank(promotion.axis, promotion.from);
      const to = getigVisualSemanticRank(promotion.axis, promotion.strengthened_value);
      expect(to, `${promotion.id} target is not strictly stronger than its source`).toBeGreaterThan(from);
    }
  });

  it("does not overclaim absence for the two promotions where the value genuinely exists", () => {
    // This test exists to pin the correction. `origin` is a real route role and
    // `current` is a real freshness; asserting they were "absent" would be the
    // same kind of false assurance this suite exists to catch.
    const forwarder = GETIG_VISUAL_FORBIDDEN_PROMOTIONS.find((p) => p.id === "forwarder_to_origin")!;
    const stale = GETIG_VISUAL_FORBIDDEN_PROMOTIONS.find((p) => p.id === "stale_to_current")!;
    expect(allValues).toContain(forwarder.strengthened_value);
    expect(allValues).toContain(stale.strengthened_value);
    expect(forwarder.prevented_by).not.toContain("value_absent");
    expect(stale.prevented_by).not.toContain("value_absent");
  });
});

describe("28D — unknown can never be presented as trusted", () => {
  it("has no trusted value on the knowledge axis", () => {
    expect(GETIG_VISUAL_VALUES.knowledge).not.toContain("trusted");
    expect(getigVisualSemanticRank("knowledge", "trusted")).toBe(-1);
  });

  it("refuses a mapping whose entity claims a freshness outside the vocabulary", () => {
    const decision = map({ entities: [ent("n1", { freshness: "trusted" })] });
    expect(decision.ok).toBe(false);
    if (decision.ok) return;
    expect(decision.refusal).toBe("refused_mapping_unknown_value");
    expect(decision.mapping).toBeNull();
  });

  it("denies global truth structurally, whatever the observer believes", () => {
    const m = mapped({ entities: [ent("n1")] });
    expect(m.globalTruth).toBe(false);
    expect(m.observerId).toBe("observer-local-1");
  });
});

describe("28D — a claim can never be presented as a grant", () => {
  it("has no granted value on the grant axis", () => {
    expect(GETIG_VISUAL_VALUES.grant).not.toContain("granted");
  });

  it("maps every entity's structural grant zero to grant_none", () => {
    const m = mapped({ entities: [ent("n1"), ent("n2", { grant: "full" })] });
    expect(valuesOn(m, "grant")).toEqual(["grant_none", "grant_none"]);
  });

  it("maps a drawn relation to grant_none, because a line is not trust", () => {
    const m = mapped({
      relations: [{ relationId: "r1", kind: "observed_edge", fromVisibleId: "n1", toVisibleId: "n2", trust: "full", provenanceRefs: [] }],
    });
    expect(valuesOn(m, "grant")).toEqual(["grant_none"]);
  });

  it("maps an event to grant_none, because showing an event never performs it", () => {
    const m = mapped({
      events: [{ eventId: "ev1", kind: "observed_change", atEpochMs: NOW, subjectVisibleId: "n1", executable: true, action: "spawn", freshness: "current" }],
    });
    expect(valuesOn(m, "grant")).toEqual(["grant_none"]);
  });
});

describe("28D — an observed edge is never admission", () => {
  it("defaults a route to not_admitted with no evidence supplied", () => {
    const m = mapped({ routes: [route("rt1")] });
    expect(valuesOn(m, "admission")).toEqual(["not_admitted"]);
  });

  it("emits admission only when explicit evidence is supplied", () => {
    const m = mapped({ routes: [route("rt1")] }, { admissionEvidence: { rt1: "ev-admission-1" } });
    const token = m.tokens.find((t) => t.axis === "admission")!;
    expect(token.semanticValue).toBe("admitted_explicit_evidence");
    // The evidence is named as metadata, and still confers nothing.
    expect(token.provenanceRefIds).toEqual(["ev-admission-1"]);
    expect(token.authority).toBe("none");
  });

  it("never treats evidence for one route as evidence for another", () => {
    const m = mapped({ routes: [route("rt1"), route("rt2")] }, { admissionEvidence: { rt1: "ev-1" } });
    const admissions = m.tokens.filter((t) => t.axis === "admission").map((t) => `${t.subjectVisibleId}=${t.semanticValue}`);
    expect(admissions.sort()).toEqual(["rt1=admitted_explicit_evidence", "rt2=not_admitted"]);
  });

  it("refuses an admission evidence map that names no such route", () => {
    // Not a refusal in the builder — an admission for an absent route simply
    // has no subject to attach to, and must not leak onto another subject.
    const m = mapped({ routes: [route("rt1")] }, { admissionEvidence: { rt9: "ev-9" } });
    expect(valuesOn(m, "admission")).toEqual(["not_admitted"]);
  });
});

describe("28D — a route is never authorization, and a forwarder is never an origin", () => {
  it("has no authorized value on the route_state axis", () => {
    expect(GETIG_VISUAL_VALUES.route_state).not.toContain("authorized");
  });

  it("defaults a route with no supplied state to unknown, never to planned", () => {
    const m = mapped({ routes: [route("rt1", { authorization: "granted" })] });
    expect(valuesOn(m, "route_state")).toEqual(["unknown"]);
  });

  it("uses a supplied route state verbatim, and refuses one outside the vocabulary", () => {
    const planned = mapped({ routes: [route("rt1")] }, { routeStates: { rt1: "planned" } });
    expect(valuesOn(planned, "route_state")).toEqual(["planned"]);
    const bad = map({ routes: [route("rt1")] }, { routeStates: { rt1: "authorized" } });
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.refusal).toBe("refused_mapping_unknown_value");
  });

  it("keeps origin, every forwarder and the destination as separate role tokens", () => {
    const m = mapped({ routes: [route("rt1", { forwarderVisibleIds: ["n2", "n4"] })] });
    const roleTokens = m.tokens.filter((t) => t.axis === "route_role");
    // Tokens are emitted in `tokenId` order, which is deterministic and is NOT
    // the order the roles appear in the frame. Both facts are asserted so a
    // future reordering cannot quietly change either.
    expect(roleTokens.map((t) => t.tokenId)).toEqual([
      "routes:rt1#destination:route_role:destination",
      "routes:rt1#forwarder:n2:route_role:forwarder",
      "routes:rt1#forwarder:n4:route_role:forwarder",
      "routes:rt1#origin:route_role:origin",
    ]);
    expect(roleTokens.map((t) => t.semanticValue).sort()).toEqual(["destination", "forwarder", "forwarder", "origin"]);
    // Every role token names its own subject, so no two can be confused.
    expect(new Set(roleTokens.map((t) => t.subjectVisibleId)).size).toBe(4);
  });

  it("refuses to collapse the role axis, which is how forwarder->origin would happen", () => {
    const m = mapped({ routes: [route("rt1", { forwarderVisibleIds: ["n2"] })] });
    for (const tier of GETIG_VISUAL_PRESENTATION_TIERS) {
      const decision = planGetigPresentationCoarsening(m, { axis: "route_role", tier });
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_mapping_suppression");
    }
  });

  it("refuses to collapse the conflict, refusal and partition axes too", () => {
    const m = mapped({
      conflicts: [{ conflictId: "c1", kind: "observation_conflict", attributedToObserverId: "observer-local-1", subjectVisibleId: "n1", claims: [], resolution: "no_consensus_unknown", resolved: false }],
      refusals: [{ refusalId: "rf1", code: "refused_network_admission", subjectVisibleId: "n2", explanation: "not admitted" }],
    });
    for (const axis of GETIG_VISUAL_NON_COLLAPSIBLE_AXES) {
      const decision = planGetigPresentationCoarsening(m, { axis, tier: "withheld" });
      expect(decision.ok, `${axis} was collapsed`).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_mapping_suppression");
    }
  });
});

describe("28D — stale can never be presented as current", () => {
  it("keeps the stale token's permitted tiers below the current tier", () => {
    const m = mapped({ entities: [ent("n1", { freshness: "stale" }), ent("n2", { freshness: "current" })] });
    const stale = m.tokens.find((t) => t.axis === "freshness" && t.subjectVisibleId === "n1")!;
    expect(stale.permittedPresentationTiers).toEqual(["withheld", "minimal"]);
    expect(stale.permittedPresentationTiers).not.toContain("declared");
  });

  it("refuses to draw a mixed current/stale axis at the current tier", () => {
    const m = mapped({ entities: [ent("n1", { freshness: "current" }), ent("n2", { freshness: "stale" })] });
    const decision = planGetigPresentationCoarsening(m, { axis: "freshness", tier: "declared" });
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.refusal).toBe("refused_mapping_strengthening");
      expect(decision.plan).toBeNull();
    }
  });

  it("permits drawing the same mixed axis at a tier at or below the weakest rank", () => {
    const m = mapped({ entities: [ent("n1", { freshness: "current" }), ent("n2", { freshness: "stale" })] });
    const withheld = planGetigPresentationCoarsening(m, { axis: "freshness", tier: "withheld" });
    const minimal = planGetigPresentationCoarsening(m, { axis: "freshness", tier: "minimal" });
    expect(withheld.ok).toBe(true);
    expect(minimal.ok).toBe(true);
    if (withheld.ok) expect(withheld.plan.ceilingRank).toBe(1);
  });

  it("reports the ceiling it enforced, so a renderer can see how far it may draw", () => {
    const m = mapped({ entities: [ent("n1", { freshness: "current" }), ent("n2", { freshness: "unknown" })] });
    const decision = planGetigPresentationCoarsening(m, { axis: "freshness", tier: "withheld" });
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    expect(decision.plan.ceilingRank).toBe(0);
    expect(decision.plan.underclaimsOnly).toBe(true);
    expect(decision.plan.entries).toHaveLength(2);
  });
});

describe("28D — conflict is never hidden", () => {
  it("emits a conflict token for every conflict in the frame", () => {
    const m = mapped({
      conflicts: [
        { conflictId: "c1", kind: "observation_conflict", attributedToObserverId: "observer-local-1", subjectVisibleId: "n1", claims: [], resolution: "no_consensus_unknown", resolved: false },
        { conflictId: "c2", kind: "observation_conflict", attributedToObserverId: "observer-local-1", subjectVisibleId: "n2", claims: [], resolution: "no_consensus_unknown", resolved: false },
      ],
    });
    expect(valuesOn(m, "conflict")).toEqual(["conflict_visible", "conflict_visible"]);
  });

  it("keeps a conflict visible even when the frame also marks it resolved", () => {
    // The mapping reports that a conflict exists. It does not adjudicate it.
    const m = mapped({
      conflicts: [{ conflictId: "c1", kind: "observation_conflict", attributedToObserverId: "observer-local-1", subjectVisibleId: "n1", claims: [], resolution: "terminal_retained", resolved: true }],
    });
    expect(valuesOn(m, "conflict")).toEqual(["conflict_visible"]);
  });
});

// ── 3. law audits, each with a self-test ─────────────────────────────────────

describe("28D — law audit: colour is never the canonical meaning", () => {
  const PRESENTATION_TOKENS = [
    "color", "colour", "hue", "saturation", "brightness", "lightness", "rgb", "hsl", "hexColor",
    "palette", "gradient", "texture", "material", "opacity", "alpha", "shader", "glow", "shade",
    "tint", "chroma", "luminance", "cssColor", "fillColor", "strokeColor",
  ];

  /** Strip comments so the audit reads the SURFACE, not the documentation
   *  about the surface. Scanning prose was tried first and immediately flagged
   *  this module's own "no colour, no hue" comment — the same false-positive
   *  class 28C hit with the word "three". */
  const stripComments = (text: string): string =>
    text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");

  /** Scan identifier-shaped tokens with word boundaries, as 28C established. */
  const scan = (text: string): string[] => {
    const lower = text.toLowerCase();
    return PRESENTATION_TOKENS.filter((token) => new RegExp(`\\b${token.toLowerCase()}\\b`).test(lower));
  };

  it("the colour scan actually detects a planted violation", () => {
    // Word-boundary scanning does not fire on a colour word buried inside a
    // longer identifier, which is correct: `fillColor` is its own token.
    expect(scan("const fillColor = computeHue(state)")).toEqual(["fillColor"]);
    expect(scan("material.roughness = 0.4")).toEqual(["material"]);
    expect(scan("const cssColor = 'hsl(0 0% 0%)'")).toContain("cssColor");
    // Bare appearance words, in any of the spellings, are all caught.
    expect(scan("pick a color for this node")).toEqual(["color"]);
    expect(scan("pick a colour for this node")).toEqual(["colour"]);
    expect(scan("lower the hue and the saturation")).toEqual(["hue", "saturation"]);
    expect(scan("apply a gradient overlay")).toEqual(["gradient"]);
    // False-positive guard: ordinary prose must not trip it.
    expect(scan("the token confers no authority and grants nothing")).toEqual([]);
  });

  it("finds no colour or styling token in the emitted declarations", () => {
    const surface = stripComments(readSourceOrThrow(DTS_PATH));
    // Guard against a vacuous pass: the stripped surface must still be real.
    expect(surface.length).toBeGreaterThan(500);
    expect(surface).toContain("buildGetigVisualMapping");
    const found = scan(surface);
    expect(found, `presentation tokens present in the public surface: ${found.join(", ")}`).toEqual([]);
  });

  it("the comment stripper actually removes comments, and the surface still has declarations", () => {
    const raw = readSourceOrThrow(DTS_PATH);
    const stripped = stripComments(raw);
    expect(raw.length).toBeGreaterThan(stripped.length);
    expect(raw).toContain("colour");
    expect(stripped).not.toContain("colour");
    expect([...stripped.matchAll(/export declare/g)].length).toBeGreaterThan(5);
  });

  it("names no presentation tier after an appearance", () => {
    for (const tier of GETIG_VISUAL_PRESENTATION_TIERS) {
      const found = scan(tier);
      expect(found, `tier "${tier}" is named after how it looks`).toEqual([]);
    }
  });

  it("declares colour is not canonical and no graphics backend is named", () => {
    const m = mapped({ entities: [ent("n1")] });
    expect(m.colorIsCanonicalMeaning).toBe(false);
    expect(m.graphicsBackend).toBe("none");
    expect(m.rendererNeutral).toBe(true);
  });
});

describe("28D — law audit: no execution, network, renderer or policy path", () => {
  const FORBIDDEN_CAPABILITY = [
    "child_process",
    "node:child_process",
    "execSync",
    "spawnSync",
    "node:worker_threads",
    "node:net",
    "node:http",
    "node:fs",
    "WebGPU",
    "GPUDevice",
    "three.js",
    "@babylonjs",
    "playcanvas",
    "requestAnimationFrame",
    "eval(",
    "new Function",
    "@menog/policy",
    "@menog/runtime-linux",
  ] as const;

  const scan = (text: string): string[] => {
    const lower = text.toLowerCase();
    return FORBIDDEN_CAPABILITY.filter((token) => {
      const t = token.toLowerCase();
      if (/^[a-z0-9_]+$/.test(t)) return new RegExp(`\\b${t}\\b`).test(lower);
      return lower.includes(t);
    });
  };

  it("the capability scan actually detects a planted violation", () => {
    expect(scan("const cp = require('node:child_process')")).toEqual(["child_process", "node:child_process"]);
    expect(scan("adapter = new GPUDevice()")).toEqual(["GPUDevice"]);
    expect(scan("import * as THREE from 'three.js'")).toEqual(["three.js"]);
    expect(scan("import { evaluate } from '@menog/policy'")).toEqual(["@menog/policy"]);
    // False-positive guard, established at 28C.
    expect(scan("the three axes are ordered")).toEqual([]);
  });

  it("finds no execution, network, renderer or policy capability in the source", () => {
    const found = scan(readSourceOrThrow(SRC_PATH));
    expect(found, `forbidden capabilities present: ${found.join(", ")}`).toEqual([]);
  });

  it("reports a non-empty audit input, so the scan cannot pass vacuously", () => {
    const text = readSourceOrThrow(SRC_PATH);
    expect(text.length).toBeGreaterThan(2_000);
    expect(text).toContain("buildGetigVisualMapping");
    expect(text).toContain("GETIG_VISUAL_FORBIDDEN_PROMOTIONS");
  });

  it("exports no mutating or executing function", () => {
    const decls = readSourceOrThrow(DTS_PATH);
    const exported = [...decls.matchAll(/export declare (?:function|const) (\w+)/g)].map((m) => m[1]!);
    expect(exported.length).toBeGreaterThan(0);
    const mutating = exported.filter((name) =>
      /^(apply|mutate|set|update|write|delete|remove|insert|patch|put|restore|resume|rewind|recover|replay|execute|run|spawn|spawnSync|admit|authorize|grant)$/i.test(name),
    );
    expect(mutating, `mutating/executing exports present: ${mutating.join(", ")}`).toEqual([]);
  });
});

describe("28D — law audit: every declared refusal code is reachable", () => {
  it("drives all eight codes from real inputs and gets each one back", () => {
    const produced = new Map<string, string>();
    const record = (name: string, decision: { ok: boolean; refusal?: string }) => {
      if (!decision.ok) produced.set(decision.refusal!, name);
    };

    record("frame invalid", buildGetigVisualMapping({ frameId: "m", frame: null } as never));
    record("unknown value", map({ entities: [ent("n1", { freshness: "invented" })] }));
    record("unknown subject", map({ entities: [{ kind: "runtime_node" }] }));
    const m = mapped({ entities: [ent("n1", { freshness: "current" }), ent("n2", { freshness: "stale" })] });
    record("unknown axis", planGetigPresentationCoarsening(m, { axis: "sparkle", tier: "declared" }));
    record("tier unknown", planGetigPresentationCoarsening(m, { axis: "freshness", tier: "chartreuse" }));
    record("strengthening", planGetigPresentationCoarsening(m, { axis: "freshness", tier: "declared" }));
    record("suppression", planGetigPresentationCoarsening(m, { axis: "conflict", tier: "withheld" }));
    record("selection", refuseVisualSelectionToPermission("tok"));

    const unreachable = GETIG_VISUAL_REFUSAL_CODES.filter((code) => !produced.has(code));
    expect(unreachable, `refusal codes no input can produce: ${unreachable.join(", ")}`).toEqual([]);
    expect(produced.size).toBe(GETIG_VISUAL_REFUSAL_CODES.length);
  });

  it("has no duplicate refusal codes", () => {
    expect(new Set(GETIG_VISUAL_REFUSAL_CODES).size).toBe(GETIG_VISUAL_REFUSAL_CODES.length);
  });
});

describe("28D — law audit: closed vocabularies", () => {
  it("declares an axis for every semantic dimension the prompt names", () => {
    for (const axis of [
      "knowledge", "freshness", "lifecycle", "grant", "route_state", "admission",
      "route_role", "refusal", "partition", "conflict", "authority",
    ]) {
      expect(GETIG_VISUAL_AXES as readonly string[]).toContain(axis);
    }
  });

  it("gives every axis a non-empty vocabulary with no duplicates", () => {
    for (const axis of GETIG_VISUAL_AXES) {
      const values = GETIG_VISUAL_VALUES[axis];
      expect(values.length, `axis ${axis} has no values`).toBeGreaterThan(0);
      expect(new Set(values).size, `axis ${axis} has duplicate values`).toBe(values.length);
    }
  });

  it("only ever emits axes and values from the closed vocabularies", () => {
    const m = mapped({
      entities: [ent("n1", { freshness: "stale", lifecycle: "retired" })],
      routes: [route("rt1", { forwarderVisibleIds: ["n2"] })],
      conflicts: [{ conflictId: "c1", kind: "observation_conflict", attributedToObserverId: "observer-local-1", subjectVisibleId: "n1", claims: [], resolution: "no_consensus_unknown", resolved: false }],
      refusals: [{ refusalId: "rf1", code: "refused_network_admission", subjectVisibleId: "n2", explanation: "not admitted" }],
    });
    for (const token of m.tokens) {
      expect(GETIG_VISUAL_AXES as readonly string[]).toContain(token.axis);
      expect(GETIG_VISUAL_VALUES[token.axis], `${token.tokenId} uses an undeclared axis`).toContain(token.semanticValue);
      for (const tier of token.permittedPresentationTiers) {
        expect(GETIG_VISUAL_PRESENTATION_TIERS as readonly string[]).toContain(tier);
      }
    }
  });

  it("names the four anomaly axes the prompt cares about", () => {
    expect([...GETIG_VISUAL_NON_COLLAPSIBLE_AXES].sort()).toEqual(["conflict", "partition", "refusal", "route_role"]);
  });

  it("bounds the token count", () => {
    expect(GETIG_VISUAL_BOUNDS.maxTokensPerMapping).toBeGreaterThan(0);
    const huge = { entities: Array.from({ length: 2_000 }, (_, i) => ent(`n${i}`)) };
    const decision = map(huge);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_mapping_frame_invalid");
  });
});

// ── 4. refusals and the selection guard ──────────────────────────────────────

describe("28D — mapping refusals", () => {
  it("refuses a non-object input", () => {
    const decision = buildGetigVisualMapping(null as never);
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.refusal).toBe("refused_mapping_frame_invalid");
      expect(decision.mapping).toBeNull();
    }
  });

  it("refuses a frame with no id or no observer", () => {
    expect(buildGetigVisualMapping({ frameId: "", frame: frame() } as never).ok).toBe(false);
    expect(buildGetigVisualMapping({ frameId: "m", frame: frame({ observer: undefined }) } as never).ok).toBe(false);
    expect(buildGetigVisualMapping({ frameId: "m", frame: frame({ epochId: "" }) } as never).ok).toBe(false);
  });

  it("refuses a subject with no usable id rather than emitting a nameless token", () => {
    const decision = map({ entities: [{ ...ent("n1"), visibleId: "" }] });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_mapping_unknown_subject");
  });

  it("refuses a route with no usable origin or destination", () => {
    expect(map({ routes: [route("rt1", { originVisibleId: "" })] }).ok).toBe(false);
    expect(map({ routes: [route("rt1", { destinationVisibleId: "" })] }).ok).toBe(false);
    expect(map({ routes: [route("rt1", { forwarderVisibleIds: [""] })] }).ok).toBe(false);
  });

  it("exposes no partial mapping on refusal", () => {
    const decision = map({ entities: [ent("n1", { freshness: "invented" })] });
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(Object.prototype.hasOwnProperty.call(decision, "mapping")).toBe(true);
      expect(decision.mapping).toBeNull();
      expect(decision.explanation).not.toBe(decision.refusal);
    }
  });

  it("refuses a coarsening request naming an unknown axis or tier", () => {
    const m = mapped({ entities: [ent("n1")] });
    const badAxis = planGetigPresentationCoarsening(m, { axis: "vibes", tier: "declared" });
    expect(badAxis.ok).toBe(false);
    if (!badAxis.ok) expect(badAxis.refusal).toBe("refused_mapping_unknown_axis");
    const badTier = planGetigPresentationCoarsening(m, { axis: "freshness", tier: "glossy" });
    expect(badTier.ok).toBe(false);
    if (!badTier.ok) expect(badTier.refusal).toBe("refused_mapping_tier_unknown");
  });

  it("refuses a coarsening of a mapping that was never built", () => {
    const decision = planGetigPresentationCoarsening({ tokens: "nope" }, { axis: "freshness", tier: "declared" });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_mapping_frame_invalid");
  });

  it("refuses to coarsen an axis the mapping does not carry", () => {
    const m = mapped({ entities: [ent("n1")] });
    const decision = planGetigPresentationCoarsening(m, { axis: "partition", tier: "withheld" });
    expect(decision.ok).toBe(false);
    // Suppression is checked first, because it is unconditional.
    if (!decision.ok) expect(decision.refusal).toBe("refused_mapping_suppression");
  });
});

describe("28D — visual selection is never runtime permission", () => {
  it("refuses for a real token id", () => {
    const result = refuseVisualSelectionToPermission("entities:n1:freshness:stale");
    expect(result.ok).toBe(false);
    expect(result.refusal).toBe("refused_mapping_selection_not_permission");
    expect(result.lookedAtTokenId).toBe("entities:n1:freshness:stale");
  });

  it("refuses for every intent, including ones that ask for authority", () => {
    const intents = [
      "admit this peer",
      "authorize this route",
      "grant this entity capability",
      "make this node the origin",
      "mark this fact current",
      "spawn a worker",
      "restore the previous state",
    ];
    for (const intent of intents) {
      const result = refuseVisualSelectionToPermission("tok", intent);
      expect(result.ok, `intent "${intent}" was permitted`).toBe(false);
      expect(result.conferredAuthority).toBe(false);
      expect(result.admittedPeer).toBe(false);
      expect(result.authorizedRoute).toBe(false);
      expect(result.mutatedRuntimeState).toBe(false);
    }
  });

  it("refuses for nonsense input rather than throwing", () => {
    expect(refuseVisualSelectionToPermission(null as never, undefined).ok).toBe(false);
    expect(refuseVisualSelectionToPermission("", "").ok).toBe(false);
  });

  it("names the law in its explanation", () => {
    expect(refuseVisualSelectionToPermission("t").explanation).toContain("VISIBILITY != AUTHORITY");
  });

  it("still refuses after selecting a token from a real mapping", () => {
    const m = mapped({ entities: [ent("n1", { freshness: "stale" })] });
    const token = m.tokens[0]!;
    expect(refuseVisualSelectionToPermission(token.tokenId, "admit").ok).toBe(false);
  });
});

// ── 5. integration: real 28A frames through the real 28D path ────────────────

describe("28D — integration with real 28A frames", () => {
  function realFrame(frameId: string, entities: GetigFrameInput["entities"], over: Record<string, unknown> = {}): GetigFrameInput {
    return {
      frameId,
      observer,
      epochId: EPOCH,
      asOfEpochMs: NOW,
      sourceProjectionHash: hex("1"),
      entities,
      ...over,
    } as GetigFrameInput;
  }

  function built(input: GetigFrameInput) {
    const decision = buildGetigFrame(input);
    if (!decision.ok) throw new Error(`28A refused: ${decision.refusal}`);
    return decision.frame;
  }

  it("maps a real 28A frame deterministically", () => {
    const frame28a = built(realFrame("frame-real", [ent("n1"), ent("n2", { freshness: "stale" })]));
    const a = buildGetigVisualMapping({ frameId: "mapping-real", frame: frame28a });
    const b = buildGetigVisualMapping({ frameId: "mapping-real", frame: frame28a });
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.mapping.mappingHash).toBe(b.mapping.mappingHash);
    expect(a.mapping.tokenCount).toBeGreaterThan(0);
    expect(a.mapping.observerId).toBe("observer-local-1");
    expect(a.mapping.epochId).toBe(EPOCH);
  });

  it("maps a real 28A frame whose quarantined and stale members keep their claims", () => {
    const frame28a = built(
      realFrame("frame-real", [
        ent("n1"),
        ent("n2", { freshness: "stale", lifecycle: "quarantined" }),
        ent("n3", { freshness: "unknown" }),
      ]),
    );
    const decision = buildGetigVisualMapping({ frameId: "mapping-real", frame: frame28a });
    expect(decision.ok).toBe(true);
    if (!decision.ok) return;
    const bySubject = new Map(
      decision.mapping.tokens.filter((t) => t.axis === "freshness").map((t) => [t.subjectVisibleId, t]),
    );
    expect(bySubject.get("n2")!.permittedPresentationTiers).toEqual(["withheld", "minimal"]);
    expect(bySubject.get("n3")!.permittedPresentationTiers).toEqual(["withheld"]);
    const lifecycle = decision.mapping.tokens.find((t) => t.axis === "lifecycle" && t.subjectVisibleId === "n2")!;
    expect(lifecycle.semanticValue).toBe("quarantined");
  });

  it("refuses a real frame carrying a freshness the vocabulary does not contain", () => {
    // 28A's own builder is what stops this, and it stops it with a specific
    // code rather than a generic one. 28D must not paper over it either.
    const rogue = { ...ent("n1") } as Record<string, unknown>;
    rogue.freshness = "quite_fresh";
    const decision = buildGetigFrame(realFrame("frame-real", [rogue as never]));
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_unknown_freshness");
  });
});