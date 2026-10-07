/**
 * PHASE 28D — out-of-suite smoke check against the BUILT artefact.
 *
 * Development probe, not a gate test. It exists so 28D behaviour can be shown
 * against `dist/` rather than only inside a suite that could be masking a stale
 * build. Every probe prints its own name and observed value, and the script
 * exits non-zero if any probe disagrees with what it prints.
 */
import {
  buildGetigVisualMapping,
  planGetigPresentationCoarsening,
  refuseVisualSelectionToPermission,
  getigVisualSemanticRank,
  getigVisualPermittedTiers,
  GETIG_VISUAL_AXES,
  GETIG_VISUAL_VALUES,
  GETIG_VISUAL_FORBIDDEN_PROMOTIONS,
  GETIG_VISUAL_NON_COLLAPSIBLE_AXES,
  GETIG_VISUAL_REFUSAL_CODES,
  GETIG_VISUAL_PRESENTATION_TIERS,
} from "../packages/durable-state/dist/index.js";

let failures = 0;
const check = (name, ok, observed) => {
  if (!ok) failures += 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}  ->  ${observed}`);
};

const hex = (d) => String(d).repeat(64);
const observer = { observerId: "observer-local-1", observerKind: "local_runtime", epochId: "ep-28d", isGlobalTruth: false };

const ent = (id, over = {}) => ({
  visibleId: id, kind: "runtime_node", label: `l-${id}`, isRuntimeObject: false, grant: "none",
  freshness: "current", lifecycle: "observed", provenanceRefs: [], representsRuntimeId: null, ...over,
});

const frame = (over = {}) => ({
  schemaVersion: "menog-getig/v0", frameId: "frame-a", observer, epochId: "ep-28d", asOfEpochMs: 1_700_000_000_000,
  sourceProjectionHash: hex("a"), canonicalVisibleHash: hex("b"),
  entities: [], relations: [], events: [], conflicts: [], refusals: [], routes: [], proposalFlows: [],
  authority: "none", controlPlane: "none", readOnly: true, replaySemantics: "visual_only_not_executable",
  globalTruth: false, visibleCapabilities: [], ...over,
});

const map = (over = {}, args = {}) => buildGetigVisualMapping({ frameId: "mapping-1", frame: frame(over), ...args });

// ── the mapping itself ───────────────────────────────────────────────────────
const m1 = map({ entities: [ent("n1"), ent("n2", { freshness: "stale" })] });
check("mapping builds", m1.ok, m1.ok ? `${m1.mapping.tokenCount} tokens` : m1.explanation);

if (m1.ok) {
  const m2 = map({ entities: [ent("n1"), ent("n2", { freshness: "stale" })] });
  check("mapping is deterministic", m2.ok && m2.mapping.mappingHash === m1.mapping.mappingHash,
    m1.mapping.mappingHash);
  check("mapping is frozen", Object.isFrozen(m1.mapping) && Object.isFrozen(m1.mapping.tokens));
  check("mapping names no colour", m1.mapping.colorIsCanonicalMeaning === false && m1.mapping.graphicsBackend === "none");
  check("mapping confers nothing",
    m1.mapping.readOnly === true && m1.mapping.authority === "none" && m1.mapping.globalTruth === false
    && m1.mapping.strengthensSemanticClaims === false);
}

// ── The eight promotions: each row's stated mechanism must actually hold ─────
const allValues = Object.values(GETIG_VISUAL_VALUES).flat();
const rowsMissingFrom = GETIG_VISUAL_FORBIDDEN_PROMOTIONS.filter(
  (p) => !(GETIG_VISUAL_VALUES[p.axis] ?? []).includes(p.from),
);
check("every promotion names a `from` value that really exists on its axis", rowsMissingFrom.length === 0,
  rowsMissingFrom.length === 0 ? "all 8" : rowsMissingFrom.map((p) => `${p.id}:${p.from}`).join(","));

const absentClaimed = GETIG_VISUAL_FORBIDDEN_PROMOTIONS.filter((p) => p.prevented_by.includes("value_absent"));
const absentLeaked = absentClaimed.filter((p) => allValues.includes(p.strengthened_value));
check("every row claiming `value_absent` really has an absent value", absentLeaked.length === 0,
  absentLeaked.length === 0 ? `${absentClaimed.length} rows verified` : absentLeaked.map((p) => p.id).join(","));

const nonCollapsibleClaimed = GETIG_VISUAL_FORBIDDEN_PROMOTIONS.filter((p) =>
  p.prevented_by.includes("axis_non_collapsible"));
const nonCollapsibleWrong = nonCollapsibleClaimed.filter((p) => !GETIG_VISUAL_NON_COLLAPSIBLE_AXES.includes(p.axis));
check("every row claiming a non-collapsible axis really names one", nonCollapsibleWrong.length === 0,
  nonCollapsibleWrong.length === 0 ? `${nonCollapsibleClaimed.length} rows verified` : nonCollapsibleWrong.map((p) => p.id).join(","));

const tierClaimed = GETIG_VISUAL_FORBIDDEN_PROMOTIONS.filter((p) => p.prevented_by.includes("permitted_tier_ceiling"));
const tierWrong = tierClaimed.filter(
  (p) => getigVisualSemanticRank(p.axis, p.strengthened_value) <= getigVisualSemanticRank(p.axis, p.from),
);
check("every row claiming a tier ceiling really has a strictly stronger target", tierWrong.length === 0,
  tierWrong.length === 0 ? `${tierClaimed.length} rows verified` : tierWrong.map((p) => p.id).join(","));
check("every promotion names an axis that exists",
  GETIG_VISUAL_FORBIDDEN_PROMOTIONS.every((p) => GETIG_VISUAL_AXES.includes(p.axis)));
check("the mapping structurally denies global truth",
  m1.ok && m1.mapping.globalTruth === false);

// ── LAYER 2: an unknown fact can only ever be drawn as withheld ───────────────
const unknown = map({ entities: [ent("n1", { freshness: "unknown" })] });
const unknownToken = unknown.ok
  ? unknown.mapping.tokens.find((t) => t.axis === "freshness")
  : undefined;
check("an unknown freshness may only be presented as withheld",
  unknownToken !== undefined && JSON.stringify(unknownToken.permittedPresentationTiers) === JSON.stringify(["withheld"]),
  unknownToken ? JSON.stringify(unknownToken.permittedPresentationTiers) : "no token");
check("ranks run weakest -> strongest", getigVisualSemanticRank("freshness", "unknown") === 0
  && getigVisualSemanticRank("freshness", "stale") === 1
  && getigVisualSemanticRank("freshness", "current") === 2,
  [0, 1, 2].map((_, i) => getigVisualSemanticRank("freshness", ["unknown", "stale", "current"][i])).join(","));
check("permitted tiers are exactly the tiers at or below the rank",
  JSON.stringify(getigVisualPermittedTiers(0)) === JSON.stringify(["withheld"])
  && JSON.stringify(getigVisualPermittedTiers(2)) === JSON.stringify([...GETIG_VISUAL_PRESENTATION_TIERS]),
  JSON.stringify(getigVisualPermittedTiers(1)));

// ── the coarsening gate ──────────────────────────────────────────────────────
const mixed = map({ entities: [ent("n1"), ent("n2", { freshness: "stale" })] });
if (mixed.ok) {
  const strong = planGetigPresentationCoarsening(mixed.mapping, { axis: "freshness", tier: "declared" });
  check("drawing a mixed current/stale axis as `declared` is refused",
    !strong.ok && strong.refusal === "refused_mapping_strengthening", strong.ok ? "approved" : strong.refusal);
  const weak = planGetigPresentationCoarsening(mixed.mapping, { axis: "freshness", tier: "withheld" });
  check("drawing the same axis as `withheld` is legal", weak.ok, weak.ok ? `ceiling rank ${weak.plan.ceilingRank}` : weak.refusal);
}
for (const axis of GETIG_VISUAL_NON_COLLAPSIBLE_AXES) {
  const r = planGetigPresentationCoarsening(mixed.mapping, { axis, tier: "withheld" });
  check(`"${axis}" may never be collapsed`,
    !r.ok && r.refusal === "refused_mapping_suppression", r.ok ? "APPROVED (wrong)" : r.refusal);
}

// ── admission and route state default to the honest answer ───────────────────
const routed = map({
  routes: [{
    routeId: "r1", originVisibleId: "n1", originFixed: true, forwarderVisibleIds: ["n2"],
    destinationVisibleId: "n3", freshness: "current", provenanceRefs: [],
    admission: "none", authorization: "none", executionAuthorized: false,
  }],
});
if (routed.ok) {
  const byAxis = (a) => routed.mapping.tokens.filter((t) => t.axis === a).map((t) => t.semanticValue);
  check("a route with no supplied state is `unknown`, never `planned`",
    JSON.stringify(byAxis("route_state")) === JSON.stringify(["unknown"]), JSON.stringify(byAxis("route_state")));
  check("a route with no admission evidence is not_admitted",
    JSON.stringify(byAxis("admission")) === JSON.stringify(["not_admitted"]), JSON.stringify(byAxis("admission")));
  check("origin, forwarder and destination are three separate role tokens",
    JSON.stringify(byAxis("route_role").sort()) === JSON.stringify(["destination", "forwarder", "origin"]),
    JSON.stringify(byAxis("route_role")));
} else {
  check("route mapping built", false, routed.explanation);
}

const admitted = map(
  { routes: [{ routeId: "r1", originVisibleId: "n1", originFixed: true, forwarderVisibleIds: [], destinationVisibleId: "n3", freshness: "current", provenanceRefs: [], admission: "none", authorization: "none", executionAuthorized: false }] },
  { admissionEvidence: { r1: "ev-admission-1" } },
);
check("explicit admission evidence is the only way to emit admitted",
  admitted.ok && admitted.mapping.tokens.some((t) => t.axis === "admission" && t.semanticValue === "admitted_explicit_evidence"),
  admitted.ok ? "emitted" : admitted.refusal);

// ── refusals ─────────────────────────────────────────────────────────────────
const refusals = [];
const r1 = buildGetigVisualMapping({ frameId: "m", frame: null });
refusals.push(["frame invalid", r1]);
const r2 = buildGetigVisualMapping({ frameId: "", frame: frame() });
refusals.push(["frame invalid (no id)", r2]);
const r3 = map({ entities: [{ ...ent("n1"), freshness: "brand_new" }] });
refusals.push(["unknown value", r3]);
const r4 = map({ entities: [{ kind: "runtime_node" }] });
refusals.push(["unknown subject", r4]);
const r5 = planGetigPresentationCoarsening(mixed.mapping, { axis: "colour", tier: "declared" });
refusals.push(["unknown axis", r5]);
const r6 = planGetigPresentationCoarsening(mixed.mapping, { axis: "freshness", tier: "chartreuse" });
refusals.push(["tier unknown", r6]);
const r7 = planGetigPresentationCoarsening(mixed.mapping, { axis: "freshness", tier: "declared" });
refusals.push(["strengthening", r7]);
const r8 = planGetigPresentationCoarsening(mixed.mapping, { axis: "conflict", tier: "withheld" });
refusals.push(["suppression", r8]);
const r9 = refuseVisualSelectionToPermission("tok", "admit the peer");
refusals.push(["selection", r9]);

const produced = new Set(refusals.filter(([, d]) => d.ok === false).map(([, d]) => d.refusal));
const unreachable = GETIG_VISUAL_REFUSAL_CODES.filter((c) => !produced.has(c));
check("every declared refusal code is reachable", unreachable.length === 0,
  unreachable.length === 0 ? `all ${GETIG_VISUAL_REFUSAL_CODES.length} produced` : `unreachable: ${unreachable.join(", ")}`);
check("selection confers nothing",
  r9.refusal === "refused_mapping_selection_not_permission" && r9.conferredAuthority === false
  && r9.admittedPeer === false && r9.authorizedRoute === false && r9.mutatedRuntimeState === false,
  r9.refusal);

console.log(`\n28D smoke: ${failures === 0 ? "ALL PASS" : `${failures} FAILURE(S)`}`);
process.exit(failures === 0 ? 0 : 1);