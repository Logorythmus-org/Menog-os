/**
 * PHASE 28J — END-TO-END GETIG SCENARIO (TESTS)
 *
 * The one rule these tests are built around:
 *
 *   THE SCENARIO DOES NOT GET TO GRADE ITS OWN HOMEWORK.
 *
 * `runGetigEndToEndScenario` reports `elements` and `proofs` for itself. If this
 * suite only checked those reports, a scenario that lied would pass. So every
 * law below is re-derived here from the RAW artifacts — the frames, views,
 * comparison, sequence, diff, mapping, graph, inspections and disclosure frame —
 * and the scenario's own verdict is only ever compared against that
 * independent reading.
 *
 * Where a check cannot be structural it says so in the test name. Pattern
 * screening is evidence about patterns, not proof of absence; the structural
 * claims here (closed zero literals, scalar-only disclosure, total refusal) are
 * the ones that do not depend on a pattern being clever enough.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  runGetigEndToEndScenario,
  refuseEndToEndScenario,
  GETIG_E2E_CHAIN,
  GETIG_E2E_PROOFS,
  GETIG_E2E_SCENARIO_ELEMENTS,
  GETIG_E2E_REFUSAL_CODES,
  GETIG_E2E_OBSERVATIONS,
  GETIG_E2E_INSTANTS,
  GETIG_E2E_EVIDENCE,
  GETIG_E2E_SCHEMA_VERSION,
  buildGetigFrame,
  buildGetigVisualMapping,
  inspect,
  type GetigEndToEndScenario,
  type GetigFrame,
} from "../../packages/durable-state/dist/index.js";

const SRC = join(process.cwd(), "packages", "durable-state", "src", "getigEndToEndScenario.ts");
const SOURCE = readFileSync(SRC, "utf8");

/**
 * Strip comments and string/template literals so a source scan reads CODE.
 *
 * Without this, every scan below trips over the module's own prose: it names
 * the forbidden verbs while explaining why they are absent, and one of its
 * attack payloads contains the literal text `execute(`. A scan that cannot
 * tell a comment from a call is not evidence about the code.
 *
 * Written as an explicit scanner rather than a chain of regular expressions so
 * that the escaping in the patterns is not itself a source of mistakes.
 */
const BACKTICK = String.fromCharCode(96);
const DQ = String.fromCharCode(34);
const SQ = String.fromCharCode(39);
const stripLiterals = (source: string): string => {
  let out = "";
  let i = 0;
  while (i < source.length) {
    const c = source[i]!;
    const two = source.slice(i, i + 2);
    if (two === "//") {
      while (i < source.length && source[i] !== String.fromCharCode(10)) i += 1;
      continue;
    }
    if (two === "/*") {
      i += 2;
      while (i < source.length && source.slice(i, i + 2) !== "*/") i += 1;
      i += 2;
      continue;
    }
    if (c === DQ || c === SQ || c === BACKTICK) {
      const quote = c;
      i += 1;
      while (i < source.length) {
        if (source[i] === "\\") { i += 2; continue; }
        if (source[i] === quote) { i += 1; break; }
        i += 1;
      }
      out += DQ + DQ;
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
};

const CODE = stripLiterals(SOURCE);
const PKG = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8")) as {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};

const decision = runGetigEndToEndScenario();
if (!decision.ok) {
  throw new Error(`28J scenario refused: ${decision.refusal} at ${decision.cause?.stage} (${decision.cause?.upstreamRefusal})`);
}
const S: GetigEndToEndScenario = decision.scenario;

const HEX64 = /^[0-9a-f]{64}$/;
const entityOf = (frame: GetigFrame, id: string) => frame.entities.find((e) => e.visibleId === id);
const proof = (name: string) => S.proofs.find((p) => p.proof === name);
const element = (name: string) => S.elements.find((e) => e.element === name);

describe("28J — the chain really ran, in order, over real upstream evidence", () => {
  it("declares the closed chain and every stage produced an artifact", () => {
    expect(GETIG_E2E_CHAIN).toEqual([
      "27h_observability_snapshot",
      "28b_entity_projection",
      "28a_getig_frame",
      "28d_visual_mapping",
      "28e_observer_view",
      "28e_view_comparison",
      "28c_frame_sequence",
      "28f_provenance_graph",
      "28g_inspection_runtime",
      "28h_disclosure_gate",
      "28i_adversarial_suite",
    ]);
    expect(S.chain).toEqual(GETIG_E2E_CHAIN);
    expect(S.schemaVersion).toBe(GETIG_E2E_SCHEMA_VERSION);
    for (const artifact of [
      S.frame, S.frameLater, S.frameRecovery, S.frameRemote,
      S.viewLocal, S.viewRemote, S.multiView, S.comparison,
      S.sequence, S.mapping, S.graph, S.trace, S.diff, S.disclosure,
    ]) {
      expect(artifact).toBeTruthy();
    }
    expect(S.successfulInspections).toBe(9);
  });

  it("built four DISTINCT frozen 27H snapshots, each carrying its own projection hash", () => {
    const hashes = [S.snapshotLocalHash, S.snapshotRemoteHash, S.snapshotLaterHash, S.snapshotRecoveryHash];
    for (const h of hashes) expect(h).toMatch(HEX64);
    expect(new Set(hashes).size).toBe(4);
  });

  it("each composed frame is bound to the upstream projection hash of its own snapshot", () => {
    expect(S.frame.sourceProjectionHash).toBe(S.snapshotLocalHash);
    expect(S.frameLater.sourceProjectionHash).toBe(S.snapshotLaterHash);
    expect(S.frameRecovery.sourceProjectionHash).toBe(S.snapshotRecoveryHash);
    expect(S.frameRemote.sourceProjectionHash).toBe(S.snapshotRemoteHash);
    for (const frame of [S.frame, S.frameLater, S.frameRecovery, S.frameRemote]) {
      expect(frame.sourceProjectionHash).toMatch(HEX64);
      expect(frame.canonicalVisibleHash).toMatch(HEX64);
      // The two hashes name different things on purpose; they must not coincide.
      expect(frame.sourceProjectionHash).not.toBe(frame.canonicalVisibleHash);
    }
  });

  it("runs deterministically: three independent runs produce one scenario hash", () => {
    const hashOf = (options?: unknown): string => {
      const r = runGetigEndToEndScenario(options);
      if (!r.ok) throw new Error(`refused: ${r.refusal}`);
      return r.scenario.scenarioHash;
    };
    expect(new Set([hashOf(), hashOf({}), hashOf()]).size).toBe(1);
    expect(hashOf()).toBe(S.scenarioHash);
  });
});

describe("28J — the composed artifact is read-only and confers nothing (structural)", () => {
  it("every frame carries the closed zero literals, not merely an absent grant", () => {
    for (const frame of [S.frame, S.frameLater, S.frameRecovery, S.frameRemote]) {
      expect(frame.authority).toBe("none");
      expect(frame.controlPlane).toBe(false);
      expect(frame.readOnly).toBe(true);
      expect(frame.globalTruth).toBe(false);
      expect(frame.visibleCapabilities).toEqual([]);
      expect(frame.replaySemantics).toBe("visual_only_not_executable");
      expect(frame.observer.isGlobalTruth).toBe(false);
      for (const e of frame.entities) {
        expect(e.isRuntimeObject).toBe(false);
        expect(e.grant).toBe("none");
      }
      for (const r of frame.relations) expect(r.trust).toBe("none");
      for (const ev of frame.events) {
        expect(ev.executable).toBe(false);
        expect(ev.action).toBe("none");
      }
      for (const route of frame.routes) {
        expect(route.admission).toBe("none");
        expect(route.authorization).toBe("none");
        expect(route.executionAuthorized).toBe(false);
        expect(route.originFixed).toBe(true);
      }
      for (const p of frame.proposalFlows) expect(p.endorsement).toBe("none");
    }
  });

  it("every downstream artifact re-imposes its own zero, independently of the frame", () => {
    expect(S.viewLocal.authority).toBe("none");
    expect(S.viewRemote.authority).toBe("none");
    expect(S.viewLocal.isGlobalTruth).toBe(false);
    expect(S.viewLocal.assertsConsensus).toBe(false);
    expect(S.multiView.synthesizesGlobalTruth).toBe(false);
    expect(S.multiView.terminalResurrected).toBe(false);
    expect(S.comparison.winnerDeclared).toBe(false);
    expect(S.comparison.consensusAsserted).toBe(false);
    expect(S.comparison.governedResolutionSupplied).toBe(false);
    expect(S.mapping.authority).toBe("none");
    expect(S.mapping.rendererNeutral).toBe(true);
    expect(S.mapping.graphicsBackend).toBe("none");
    expect(S.mapping.colorIsCanonicalMeaning).toBe(false);
    expect(S.mapping.strengthensSemanticClaims).toBe(false);
    expect(S.graph.authority).toBe("none");
    expect(S.graph.authorizes).toBe(false);
    expect(S.sequence.authority).toBe("none");
    expect(S.diff.authority).toBe("none");
    expect(S.disclosure.authority).toBe("none");
    for (const fact of [...S.viewLocal.facts, ...S.viewRemote.facts]) expect(fact.isGrant).toBe(false);
    for (const token of S.mapping.tokens) {
      expect(token.claim).toBe("descriptive_only");
      expect(token.authority).toBe("none");
      expect(token.mutation).toBe("none");
      expect(token.executable).toBe(false);
    }
  });

  it("the scenario artifact itself carries the zero and creates no action path", () => {
    expect(S.authority).toBe("none");
    expect(S.controlPlane).toBe(false);
    expect(S.readOnly).toBe(true);
    expect(S.createsActionPath).toBe(false);
    expect(S.grantsNothing).toBe(true);
    expect(S.globalTruth).toBe(false);
    expect(S.replaySemantics).toBe("visual_history_not_executable");
    expect(S.failedProofs).toEqual([]);
    expect(S.passedProofCount).toBe(S.proofCount);
  });
});

describe("28J — every scenario element the prompt names is present, and named", () => {
  it("declares a closed element set and reports on all of them", () => {
    expect(GETIG_E2E_SCENARIO_ELEMENTS).toHaveLength(13);
    expect(S.elementCount).toBe(13);
    expect(S.elements.map((e) => e.element)).toEqual([...GETIG_E2E_SCENARIO_ELEMENTS]);
    for (const e of S.elements) {
      expect(e.present, `${e.element} was not evidenced`).toBe(true);
      expect(e.evidence.length).toBeGreaterThan(0);
    }
  });

  it("multiple runtime mesh nodes: real 27H nodes became runtime_node representations", () => {
    const nodes = S.frame.entities.filter((e) => e.kind === "runtime_node").map((e) => e.visibleId);
    expect(nodes).toEqual(expect.arrayContaining(["node-local", "node-relay", "node-remote"]));
    for (const id of nodes) expect(entityOf(S.frame, id)!.representsRuntimeId).toBe(id);
  });

  it("agent, goal, task, proposal, tool, policy gate, boundary and memory are all represented", () => {
    const kinds = new Set<string>(S.frame.entities.map((e) => e.kind));
    for (const k of ["agent", "goal", "task", "proposal", "tool_reference", "policy_gate", "execution_boundary", "memory_reference", "evidence", "route"]) {
      expect(kinds.has(k), `missing entity kind ${k}`).toBe(true);
    }
    const tool = entityOf(S.frame, "tool:local-shell")!;
    expect(tool.kind).toBe("tool_reference");
    expect(tool.grant).toBe("none");
    expect(Object.keys(tool)).not.toContain("output");
  });

  it("explicit topology: observed edges and the partition relation are drawn, and a line is not trust", () => {
    expect(S.frame.relations.some((r) => r.kind === "observed_edge")).toBe(true);
    expect(S.frame.relations.some((r) => r.kind === "partitions_from")).toBe(true);
    expect(S.frame.relations.some((r) => r.kind === "forwarded_proposal")).toBe(true);
    for (const r of S.frame.relations) expect(r.trust).toBe("none");
    expect(S.graph.edges.every((e) => e.confersTrust === false && e.confersAuthority === false)).toBe(true);
  });

  it("a planned route exists and is not an admission, an authorization or a permission to execute", () => {
    const route = S.frame.routes.find((r) => r.routeId === "route-28j-1")!;
    expect(route).toBeTruthy();
    expect(route.admission).toBe("none");
    expect(route.authorization).toBe("none");
    expect(route.executionAuthorized).toBe(false);
    const routeToken = S.mapping.tokens.filter((t) => t.axis === "route_state" && t.subjectVisibleId === "route-28j-1");
    expect(routeToken[0]!.semanticValue).toBe("planned");
  });

  it("origin, forwarder and destination stay three separate roles", () => {
    const route = S.frame.routes.find((r) => r.routeId === "route-28j-1")!;
    expect(route.originVisibleId).toBe("node-local");
    expect(route.forwarderVisibleIds).toEqual(["node-relay"]);
    expect(route.destinationVisibleId).toBe("node-remote");
    const roles = S.mapping.tokens.filter((t) => t.axis === "route_role").map((t) => `${t.subjectVisibleId}=${t.semanticValue}`);
    expect(roles).toEqual(
      expect.arrayContaining(["route-28j-1#origin=origin", "route-28j-1#forwarder:node-relay=forwarder", "route-28j-1#destination=destination"]),
    );
  });

  it("a capability advertisement is shown as a claim with no grant", () => {
    expect(entityOf(S.frame, "agent:planner")!.grant).toBe("none");
    expect(entityOf(S.frame, "agent:planner")!.isRuntimeObject).toBe(false);
    const grants = S.mapping.tokens.filter((t) => t.axis === "grant");
    expect(grants.length).toBeGreaterThan(0);
    expect(new Set(grants.map((t) => t.semanticValue))).toEqual(new Set(["grant_none"]));
    const admission = S.mapping.tokens.filter((t) => t.axis === "admission");
    expect(admission.length).toBeGreaterThan(0);
    expect(new Set(admission.map((t) => t.semanticValue))).toEqual(new Set(["not_admitted"]));
  });

  it("policy gate and refusal state are visible content, not hidden errors", () => {
    expect(S.frame.entities.some((e) => e.kind === "policy_gate")).toBe(true);
    expect(S.frame.refusals.length).toBeGreaterThan(0);
    for (const r of S.frame.refusals) {
      expect(r.code).toMatch(/^refused_/);
      expect(r.explanation.length).toBeGreaterThan(0);
    }
    expect(S.mapping.tokens.filter((t) => t.axis === "refusal").length).toBe(S.frame.refusals.length);
  });

  it("partition and divergent observer views are both present and no winner is named", () => {
    expect(S.frame.conflicts.length).toBeGreaterThan(0);
    for (const c of S.frame.conflicts) {
      expect(c.resolved).toBe(false);
      expect(c.claims.length).toBeGreaterThanOrEqual(2);
    }
    expect(S.comparison.disagreements.length).toBeGreaterThan(0);
    expect(S.comparison.winnerDeclared).toBe(false);
    expect(S.mapping.tokens.some((t) => t.axis === "partition" && t.semanticValue === "partitioned")).toBe(true);
    expect(element("partition_and_divergent_observer_views")!.present).toBe(true);
  });

  it("restart/recovery produced a LATER frame in a NEW epoch and did not continue the timeline", () => {
    expect(S.frame.epochId).toBe(GETIG_E2E_INSTANTS.epochA);
    expect(S.frameRecovery.epochId).toBe(GETIG_E2E_INSTANTS.epochB);
    expect(S.frameRecovery.asOfEpochMs).toBeGreaterThan(S.frame.asOfEpochMs);
    expect(S.crossEpochSequenceRefusal.refused).toBe(true);
    expect(S.crossEpochSequenceRefusal.refusal).toBe("refused_sequence_frame_epoch_mismatch");
    expect(S.sequence.epochId).toBe(S.frame.epochId);
    expect(S.sequence.frameCount).toBe(2);
    // Recovery did NOT restore what was known before: the route is gone.
    expect(S.frame.routes.length).toBe(1);
    expect(S.frameRecovery.routes.length).toBe(0);
  });

  it("stale stays stale and unknown stays unknown across the timeline", () => {
    expect(entityOf(S.frame, "node-relay")!.freshness).toBe("stale");
    expect(entityOf(S.frameLater, "node-relay")!.lifecycle).toBe("retired");
    expect(entityOf(S.frameLater, "node-remote")!.freshness).toBe("unknown");
    expect(entityOf(S.frameLater, "node-remote")!.lifecycle).toBe("unknown");
    expect(entityOf(S.frame, "memory:session-log")!.provenanceRefs).toEqual([]);
    expect(S.graph.unknownProvenanceSubjects).toContain("memory:session-log");
  });

  it("provenance is traced, is metadata, and confers nothing", () => {
    expect(S.trace.hopCount).toBeGreaterThan(0);
    expect(S.trace.subjectVisibleId).toBe("node-remote");
    expect(S.graph.authorizes).toBe(false);
    expect(S.graph.nodes.every((n) => n.isEvidenceContent === false)).toBe(true);
    expect(S.graph.nodes.every((n) => n.confersTrust === false && n.confersAuthority === false)).toBe(true);
    // Law 11: the same subject asked two ways yields ONE answer.
    expect(JSON.stringify(S.trace)).toBe(JSON.stringify(S.traceByGraphKey));
    expect(S.trustRefusal.confersTrust).toBe(false);
    expect(S.trustRefusal.confersAuthority).toBe(false);
    expect(S.trustRefusal.authorizesExecution).toBe(false);
  });

  it("a timeline and a semantic diff exist, and the diff claims no cause", () => {
    expect(S.sequence.replaySemantics).toBe("visual_history_not_executable");
    expect(S.sequence.temporalOrderEstablished).toBe(true);
    expect(S.diff.entryCount).toBeGreaterThan(0);
    expect(S.diff.causalityClaimed).toBe(false);
    expect(S.diff.restoresRuntimeState).toBe(false);
    expect(S.diffAcrossRestart.causalityClaimed).toBe(false);
    expect(S.diffAcrossRestart.fromFrameId).toBe(S.frame.frameId);
    expect(S.diffAcrossRestart.toFrameId).toBe(S.frameRecovery.frameId);
    const diffText = JSON.stringify(S.diff);
    for (const word of ["cause", "causedBy", "because", "reason", "triggeredBy", "rootCause"]) {
      expect(diffText.includes(word), `diff mentioned ${word}`).toBe(false);
    }
  });

  it("read-only inspection, filter and compare all ran and all refused to mutate", () => {
    const ops = S.inspections.map((i) => i.operation).sort();
    expect(ops).toEqual(
      ["compare_views", "enumerate_refusals_conflicts", "expand_collapse", "filter", "focus", "inspect", "select", "timeline_navigate", "trace_provenance"].sort(),
    );
    expect(S.inspections.every((i) => i.ok)).toBe(true);
    expect(S.controlRefusal.ok).toBe(false);
    expect(S.controlRefusal.result).toBeNull();
    expect(S.controlRefusal.mutatedCanonicalState).toBe(false);
  });
});

describe("28J — the nine proofs, each re-derived here from the raw artifacts", () => {
  it("declares the closed proof set and every proof carries its own evidence string", () => {
    expect(GETIG_E2E_PROOFS).toEqual([
      "getig_adds_no_authority",
      "no_visual_to_runtime_action_path",
      "execution_still_requires_frozen_local_authority_chain",
      "visual_replay_is_non_executable",
      "observer_views_are_distinct",
      "conflict_stays_visible",
      "secrets_and_raw_content_absent",
      "hashes_consistent",
      "renderer_dependency_zero",
    ]);
    expect(S.proofs.map((p) => p.proof)).toEqual([...GETIG_E2E_PROOFS]);
    for (const p of S.proofs) {
      expect(p.holds, `${p.proof} did not hold`).toBe(true);
      expect(p.evidence.length).toBeGreaterThan(10);
    }
  });

  it("getig_adds_no_authority — no artifact in the chain carries any authority at all", () => {
    const all = [
      ...[S.frame, S.frameLater, S.frameRecovery, S.frameRemote].map((f) => f.authority),
      S.viewLocal.authority, S.viewRemote.authority, S.multiView.authority, S.comparison.authority,
      S.mapping.authority, S.graph.authority, S.sequence.authority, S.diff.authority, S.disclosure.authority,
      S.adversarial.authority,
    ];
    expect(all).toHaveLength(14);
    expect(all.every((a) => a === "none")).toBe(true);
    expect(S.adversarial.criticalBypass).toBe(false);
    expect(proof("getig_adds_no_authority")!.holds).toBe(true);
  });

  it("no_visual_to_runtime_action_path — nothing in the chain mutates anything", () => {
    expect(S.selectionRefusal.conferredAuthority).toBe(false);
    expect(S.selectionRefusal.admittedPeer).toBe(false);
    expect(S.selectionRefusal.authorizedRoute).toBe(false);
    expect(S.selectionRefusal.mutatedRuntimeState).toBe(false);
    expect(S.controlRefusal.ok).toBe(false);
    expect(S.controlRefusal.mutatedCanonicalState).toBe(false);
    expect(S.diff.restoresRuntimeState).toBe(false);
    expect(S.sequence.restoresRuntimeState).toBe(false);
    expect(S.sequence.resumesRuntimeState).toBe(false);
    expect(S.resumeRefusal.ok).toBe(false);
    // No module in the composed chain calls a runtime mutator.
    expect(CODE).not.toMatch(/\b(execute|spawn|fork|exec|kill|approve|admit|assign|dispatch)\s*\(/);
  });

  it("execution_still_requires_frozen_local_authority_chain — every adjacent refusal is refused", () => {
    expect(S.selectionRefusal.ok).toBe(false);
    expect(S.selectionRefusal.code).toBe("selection_refused");
    expect(S.synthesisRefusal.ok).toBe(false);
    expect(S.synthesisRefusal.code).toBe("synthesis_refused");
    expect(S.synthesisRefusal.winnerDeclared).toBe(false);
    expect(S.synthesisRefusal.consensusAsserted).toBe(false);
    expect(S.trustRefusal.ok).toBe(false);
    expect(S.trustRefusal.code).toBe("trust_refused");
    expect(S.resumeRefusal.ok).toBe(false);
    expect(S.crossEpochSequenceRefusal.refused).toBe(true);
    // The chain names prerequisites as VISIBLE SUBJECTS only; it carries no
    // decision, allocation, actor or isolation result of its own.
    const keys = new Set(Object.keys(S.frame));
    for (const key of ["actorId", "allocationId", "policyDecision", "isolationResult", "toolCall"]) {
      expect(keys.has(key)).toBe(false);
    }
    const json = JSON.stringify(S.frame);
    for (const claim of ['"grant": "full"', '"authorized": true', '"executionAuthorized": true', '"isGlobalTruth": true']) {
      expect(json.includes(claim)).toBe(false);
    }
  });

  it("visual_replay_is_non_executable — a timeline is a history, not a resume", () => {
    expect(S.frame.replaySemantics).toBe("visual_only_not_executable");
    expect(S.sequence.replaySemantics).toBe("visual_history_not_executable");
    expect(S.sequence.temporalOrderEstablished).toBe(true);
    expect(S.diff.causalityClaimed).toBe(false);
    expect(S.crossEpochSequenceRefusal.refusal).toBe("refused_sequence_frame_epoch_mismatch");
    const nav = inspect({
      query: { kind: "timeline_navigate", operation: "timeline_navigate" },
      view: S.viewLocal,
      sequence: S.sequence,
      graph: S.graph,
      binding: { frameId: S.frame.frameId, observerId: S.viewLocal.observerId, canonicalVisibleHash: S.frame.canonicalVisibleHash, viewHash: S.viewLocal.viewHash },
    });
    expect(nav.ok).toBe(true);
    if (nav.ok && "replaySemantics" in nav.result) {
      expect(nav.result.replaySemantics).toBe("visual_history_not_executable");
      expect(nav.result.resumesRuntimeState).toBe(false);
      expect(nav.result.restoresRuntimeState).toBe(false);
      expect(nav.result.controlPlane).toBe(false);
    }
  });

  it("observer_views_are_distinct — two vantages, two hashes, no merged world", () => {
    expect(S.viewLocal.viewHash).not.toBe(S.viewRemote.viewHash);
    expect(S.viewLocal.observerId).not.toBe(S.viewRemote.observerId);
    expect(S.viewLocal.observerKind).toBe("local_runtime");
    expect(S.viewRemote.observerKind).toBe("remote_runtime");
    expect(S.comparison.disagreements.length).toBeGreaterThan(0);
    expect(S.multiView.viewCount).toBe(2);
    expect(S.multiView.synthesizesGlobalTruth).toBe(false);
    expect(S.synthesisRefusal.isGlobalTruth).toBe(false);
    for (const entry of [...S.comparison.agreements, ...S.comparison.disagreements, ...S.comparison.unknownDifferences]) {
      expect(entry.freshnessDecidesNothing).toBe(true);
    }
  });

  it("conflict_stays_visible — across both frames, with collapse refused", () => {
    expect(S.frame.conflicts.length).toBeGreaterThan(0);
    expect(S.frameLater.conflicts.length).toBeGreaterThan(0);
    for (const frame of [S.frame, S.frameLater]) {
      for (const c of frame.conflicts) expect(c.resolved).toBe(false);
    }
    expect(S.mapping.tokens.some((t) => t.axis === "conflict" && t.semanticValue === "conflict_visible")).toBe(true);
    const suppression = S.coarseningSuppressionRefusal;
    expect(suppression.ok).toBe(false);
    if (!suppression.ok) expect(suppression.refusal).toBe("refused_mapping_suppression");
    expect(S.multiView.terminalResurrected).toBe(false);
  });

  it("secrets_and_raw_content_absent — scalar-only disclosure, and refusals that disclose nothing", () => {
    expect(S.disclosure.disclosesRawContent).toBe(false);
    expect(S.disclosure.disclosesPolicyText).toBe(false);
    expect(S.disclosure.redacted).toBe(false);
    for (const record of S.disclosure.records) {
      for (const value of Object.values(record.fields)) {
        expect(["string", "number", "boolean"]).toContain(typeof value);
      }
    }
    expect(S.disclosure.recordCount).toBe(3);
    expect(S.disclosureFields).toBeGreaterThan(0);
    for (const refused of [S.secretDisclosureRefusal, S.nestedValueDisclosureRefusal]) {
      expect(refused.ok).toBe(false);
      if (!refused.ok) {
        expect(refused.frame).toBeNull();
        expect(refused.manifest).toBeNull();
        expect(refused.partialFrameEmitted).toBe(false);
      }
    }
    // PATTERN-BASED, and labelled as such: evidence about patterns, not proof of
    // absence. The structural claim is the allowlist plus the scalar-only rule,
    // and both are asserted above.
    expect(SOURCE).not.toMatch(/(api[_-]?key|secret[_-]?key|password|BEGIN [A-Z ]*PRIVATE KEY)\s*[:=]\s*["'][^"']+/i);
    expect(CODE).not.toMatch(/(apiKey|api_key|secretKey|password|privateKey)/);
    expect(JSON.stringify(S.disclosure)).not.toMatch(/"(apiKey|secret|password|token|privateKey)"\s*:/i);
  });

  it("hashes_consistent — every downstream artifact is bound to the frame it describes", () => {
    expect(S.viewLocal.builtFromVisibleHash).toBe(S.frame.canonicalVisibleHash);
    expect(S.viewLocal.builtFromFrameId).toBe(S.frame.frameId);
    expect(S.graph.frameId).toBe(S.frame.frameId);
    expect(S.mapping.frameId).toBe(S.frame.frameId);
    expect(S.disclosure.canonicalVisibleHash).toBe(S.frame.canonicalVisibleHash);
    expect(S.disclosure.frameId).toBe(S.frame.frameId);
    expect(S.sequence.entries.map((e) => e.canonicalVisibleHash)).toEqual([S.frame.canonicalVisibleHash, S.frameLater.canonicalVisibleHash]);
    expect(S.sequence.entries.map((e) => e.sourceProjectionHash)).toEqual([S.snapshotLocalHash, S.snapshotLaterHash]);
    expect(S.diff.fromVisibleHash).toBe(S.frame.canonicalVisibleHash);
    expect(S.diff.toVisibleHash).toBe(S.frameLater.canonicalVisibleHash);
    for (const h of [S.frame.canonicalVisibleHash, S.viewLocal.viewHash, S.mapping.mappingHash, S.graph.graphHash, S.disclosure.disclosureFrameHash, S.scenarioHash]) {
      expect(h).toMatch(HEX64);
    }
  });

  it("renderer_dependency_zero — no graphics backend anywhere in the project", () => {
    expect(S.mapping.rendererNeutral).toBe(true);
    expect(S.mapping.graphicsBackend).toBe("none");
    expect(S.mapping.colorIsCanonicalMeaning).toBe(false);
    expect(S.mapping.strengthensSemanticClaims).toBe(false);
    const deps = Object.keys({ ...(PKG.dependencies ?? {}), ...(PKG.devDependencies ?? {}) });
    for (const forbidden of ["three", "@react-three/fiber", "playcanvas", "babylonjs", "@babylonjs/core", "unity", "playwright", "puppeteer"]) {
      expect(deps).not.toContain(forbidden);
    }
    expect(CODE).not.toMatch(/webgpu|gpuadapter|gpurenderpipeline|navigator\.gpu/i);
  });
});

describe("28J — every attempt that had to refuse, did", () => {
  it("records thirteen named refusals, each with a real upstream token", () => {
    expect(S.refusedAttempts).toHaveLength(13);
    const names = S.refusedAttempts.map((a) => a.name);
    expect(new Set(names).size).toBe(13);
    for (const a of S.refusedAttempts) {
      expect(a.refused, `${a.name} did not refuse`).toBe(true);
      expect(a.goal.length).toBeGreaterThan(5);
      expect(a.outcome).toMatch(/^refused_/);
      expect(a.outcome).not.toBe("UNEXPECTED_SUCCESS");
    }
  });

  it("names the specific laws the refusals cover", () => {
    const byName = new Map(S.refusedAttempts.map((a) => [a.name, a.outcome]));
    expect(byName.get("visual_selection_to_permission")).toBe("refused_mapping_selection_not_permission");
    expect(byName.get("inspection_as_control")).toBe("refused_query_operation_unknown");
    expect(byName.get("global_truth_synthesis")).toBe("refused_synthesis_not_permitted");
    expect(byName.get("provenance_as_trust")).toBe("refused_trust_not_granted");
    expect(byName.get("resume_from_past_frame")).toBe("refused_resume_not_permitted");
    expect(byName.get("cross_epoch_timeline")).toBe("refused_sequence_frame_epoch_mismatch");
    expect(byName.get("unknown_subject_inspection")).toBe("refused_subject_unknown");
    expect(byName.get("out_of_range_limit")).toBe("refused_limit_out_of_range");
    expect(byName.get("mutation_shaped_query")).toBe("refused_query_mutation_shape");
    expect(byName.get("coarsening_strengthens_claim")).toBe("refused_mapping_strengthening");
    expect(byName.get("coarsening_suppresses_conflict")).toBe("refused_mapping_suppression");
    expect(byName.get("disclosure_unallowlisted_name")).toBe("refused_disclosure_forbidden_field");
    expect(byName.get("disclosure_nested_structure")).toBe("refused_disclosure_nested_smuggling");
  });

  it("the coarsening that WAS legal is approved and only underclaims", () => {
    expect(S.coarseningApproved.ok).toBe(true);
    if (S.coarseningApproved.ok) {
      expect(S.coarseningApproved.plan.underclaimsOnly).toBe(true);
      expect(S.coarseningApproved.plan.tierRank).toBeLessThanOrEqual(S.coarseningApproved.plan.ceilingRank);
    }
  });
});

describe("28J — refusal vocabulary is closed, and none of it is dead", () => {
  it("declares thirteen codes and every one produces a TOTAL refusal with no scenario", () => {
    expect(GETIG_E2E_REFUSAL_CODES).toHaveLength(13);
    for (const code of GETIG_E2E_REFUSAL_CODES) {
      const r = refuseEndToEndScenario(code, "test_stage", "test_detail");
      expect(r.ok, `${code} did not refuse`).toBe(false);
      expect(r.code).toBe("end_to_end_scenario_refused");
      expect(r.refusal).toBe(code);
      expect(r.explanation).not.toBe(refuseEndToEndScenario("refused_e2e_input_invalid", "s", "d").explanation);
      expect(r.scenario).toBeNull();
      expect(r.partialScenarioEmitted).toBe(false);
      expect(r.authority).toBe("none");
      expect(r.readOnly).toBe(true);
      expect(r.cause).toEqual({ stage: "test_stage", upstreamRefusal: "test_detail" });
      expect(r.explanation).toContain("test_stage");
      expect(r.explanation).toContain("test_detail");
      expect(r.explanation.length).toBeGreaterThan(60);
    }
  });

  it("the runner refuses any attempt to hand it chosen evidence", () => {
    for (const bad of [42, "frame", [], { frame: S.frame }, { evidence: GETIG_E2E_EVIDENCE.localAtT0() }, null]) {
      const r = runGetigEndToEndScenario(bad);
      expect(r.ok, `accepted ${JSON.stringify(bad)?.slice(0, 40)}`).toBe(false);
      if (!r.ok) {
        expect(r.refusal).toBe("refused_e2e_input_invalid");
        expect(r.scenario).toBeNull();
      }
    }
  });

  it("accepts the empty options object and nothing else", () => {
    expect(runGetigEndToEndScenario({}).ok).toBe(true);
    expect(runGetigEndToEndScenario().ok).toBe(true);
    expect(runGetigEndToEndScenario(undefined).ok).toBe(true);
  });
});

describe("28J — the adversarial suite ran against this scenario's own artifacts", () => {
  it("seventeen attacks, twelve categories, nothing failed and nothing was counted as a pass", () => {
    expect(S.adversarial.caseCount).toBe(17);
    expect(S.adversarial.pass).toBe(17);
    expect(S.adversarial.fail).toBe(0);
    expect(S.adversarial.unsupported).toBe(0);
    expect(S.adversarial.inconclusive).toBe(0);
    expect(S.adversarial.criticalBypass).toBe(false);
    expect(S.adversarial.bypassedAttackIds).toEqual([]);
    expect(S.adversarial.criticalAttackIds).toEqual([]);
    expect(S.adversarial.unsupportedIsPass).toBe(false);
    expect(S.adversarial.mockCountedAsValidation).toBe(false);
    expect(S.adversarialRunHash).toMatch(HEX64);
  });

  it("covers every attack category the harness declares", () => {
    expect([...S.adversarial.categoriesCovered].sort()).toEqual(
      [
        "authority_inflation", "capability_union", "completeness_lie", "conflict_suppression",
        "disclosure_leak", "identity_substitution", "inspection_injection", "provenance_tampering",
        "replay_to_execution", "staleness_erosion", "timeline_tampering", "unsupported_as_pass",
      ].sort(),
    );
  });

  it("the same adversarial run reproduces the same hash on a second scenario", () => {
    const second = runGetigEndToEndScenario();
    expect(second.ok).toBe(true);
    if (second.ok) {
      expect(second.scenario.adversarialRunHash).toBe(S.adversarialRunHash);
      expect(second.scenario.scenarioHash).toBe(S.scenarioHash);
    }
  });
});

describe("28J — scope: this is not D-26-1 physical-LAN validation, and says so", () => {
  it("declares the scope structurally rather than only in a comment", () => {
    expect(S.physicalLanValidation).toBe(false);
    expect(S.singleProcess).toBe(true);
    expect(S.networkCallsMade).toBe(0);
    const observation = GETIG_E2E_OBSERVATIONS.find((o) => o.id === "28J-OBS-3")!;
    expect(observation.finding).toContain("D-26-1");
    expect(observation.severity).toBe("informational");
  });

  it("makes no network, filesystem, clock, environment or randomness call at all", () => {
    expect(CODE).not.toMatch(/\bfetch\s*\(|node:https?|node:net|node:dgram|XMLHttpRequest|WebSocket/);
    expect(CODE).not.toMatch(/node:fs|readFileSync|writeFileSync|process\.env/);
    expect(CODE).not.toMatch(/Date\.now|new Date\s*\(|performance\.now|Math\.random/);
    expect(CODE).not.toMatch(/\bsetTimeout\s*\(|\bsetInterval\s*\(/);
    expect(CODE).not.toMatch(/eval\s*\(|new Function\s*\(/);
  });

  it("contains no mock, stub or fixture branch — the chain has one path", () => {
    // PATTERN-BASED and deliberately narrow: it looks for a conditional mock
    // branch, which is the shape a mock would take here. It does not and cannot
    // prove the absence of deception; the structural claim is that the runner
    // takes no input at all, asserted above.
    expect(CODE).not.toMatch(/\b(mock|stub|fake|fixture|sinon|jest\.)\b/i);
    expect(SOURCE).not.toMatch(/\bmock[A-Z]\w*\s*=/);
  });
});

/**
 * 28J-OBS-1/2/4/5 are RECORDED defects, not claims. Each one is reproduced here
 * through the real modules so that a later reader can check the finding rather
 * than take it on trust — and so that if one is fixed, this suite fails and the
 * observation has to be retracted deliberately rather than quietly outliving its
 * cause.
 */
describe("28J — the recorded defects are reproduced here, not merely asserted", () => {
  const observation = (id: string) => GETIG_E2E_OBSERVATIONS.find((o) => o.id === id)!;

  it("OBS-1: 28A has no `remote_runtime` frame observer kind while 28E does", () => {
    expect(observation("28J-OBS-1").severity).toBe("non_blocking_defect");
    // The scenario declares the remote vantage honestly at frame level rather
    // than mislabelling it as local.
    expect(S.frameRemote.observer.observerKind).toBe("offline_reader");
    expect(S.frameRemote.observer.observerId).toBe(GETIG_E2E_INSTANTS.observerRemote);
    expect(S.viewRemote.observerKind).toBe("remote_runtime");
    // And 28A really does refuse the kind 28E would have accepted.
    const built = buildGetigFrame({
      frameId: "frame-obs-1",
      observer: { observerId: "o", observerKind: "remote_runtime" as never, epochId: "e", isGlobalTruth: false },
      epochId: "e",
      asOfEpochMs: 1,
      sourceProjectionHash: S.snapshotLocalHash,
    });
    expect(built.ok).toBe(false);
    if (!built.ok) expect(built.refusal).toMatch(/^refused_/);
  });

  it("OBS-2: 28E/28D/28F read a frame structurally and cannot tell a forged one from a built one", () => {
    expect(observation("28J-OBS-2").severity).toBe("non_blocking_defect");
    expect(observation("28J-OBS-2").finding).toContain("Tamper-detection");
    // The compensating control is structural: this gate's only runner takes no
    // evidence, so there is no argument a caller can pass to make the chain
    // describe something of their choosing.
    for (const bad of [{ frame: S.frame }, { frames: [S.frame] }, { snapshot: {} }, { evidence: null }, { epochId: "other" }]) {
      const r = runGetigEndToEndScenario(bad);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal).toBe("refused_e2e_input_invalid");
    }
  });

  it("OBS-4: 28A accepts lifecycle `unknown` and 28D refuses the whole mapping because of it", () => {
    expect(observation("28J-OBS-4").severity).toBe("non_blocking_defect");
    const unknownLifecycle = {
      ...S.frame,
      frameId: "frame-obs-4",
      entities: [
        {
          visibleId: "unknown-lifecycle-subject",
          kind: "agent" as const,
          label: "subject whose lifecycle is unknown",
          isRuntimeObject: false as const,
          grant: "none" as const,
          freshness: "current" as const,
          lifecycle: "unknown" as const,
          provenanceRefs: [],
          representsRuntimeId: null,
        },
      ],
      relations: [],
      events: [],
      refusals: [],
      conflicts: [],
      routes: [],
      proposalFlows: [],
    };
    const mapping = buildGetigVisualMapping({ frameId: "frame-obs-4", frame: unknownLifecycle });
    expect(mapping.ok).toBe(false);
    if (!mapping.ok) {
      expect(mapping.refusal).toBe("refused_mapping_unknown_value");
      expect(mapping.mapping).toBeNull();
    }
  });

  it("OBS-5: 28G refuses its 15 named action keys but silently ignores any other unknown key", () => {
    expect(observation("28J-OBS-5").severity).toBe("non_blocking_defect");
    const binding = { frameId: S.frame.frameId, observerId: S.viewLocal.observerId, canonicalVisibleHash: S.frame.canonicalVisibleHash, viewHash: S.viewLocal.viewHash };
    // A NAMED action is refused outright.
    const named = inspect({
      query: { kind: "select", operation: "select", subjectVisibleId: "node-remote", approve: true },
      view: S.viewLocal, sequence: S.sequence, graph: S.graph, binding,
    });
    expect(named.ok).toBe(false);
    if (!named.ok) expect(named.refusal).toBe("refused_selection_mutation_attempt");

    // An UNNAMED one is silently dropped and the read still succeeds. Pinned so
    // that a future fix to 28G has to update this test and the observation.
    const unnamed = inspect({
      query: { kind: "select", operation: "select", subjectVisibleId: "node-remote", approvePeer: true },
      view: S.viewLocal, sequence: S.sequence, graph: S.graph, binding,
    });
    expect(unnamed.ok).toBe(true);
    if (unnamed.ok) expect(unnamed.authority).toBe("none");
  });

  it("every observation carries a severity and an id, and none is blocking", () => {
    expect(GETIG_E2E_OBSERVATIONS.length).toBeGreaterThanOrEqual(4);
    const ids = GETIG_E2E_OBSERVATIONS.map((o) => o.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const o of GETIG_E2E_OBSERVATIONS) {
      expect(["informational", "non_blocking_defect"]).toContain(o.severity);
      expect(o.finding.length).toBeGreaterThan(40);
    }
    expect(S.observations).toHaveLength(GETIG_E2E_OBSERVATIONS.length);
  });
});

describe("28J — the closed vocabularies are what enforce this, not this gate's discipline", () => {
  it("28A refuses a hand-authored entity whose grant is not `none`", () => {
    // This is the control behind 28J-OBS-2. 28J's composed frame would be
    // worthless if a caller could simply write `grant: "requested"` into an
    // entity; the builder refuses instead, so the guarantee does not depend on
    // the scenario module being careful.
    const forged = buildGetigFrame({
      frameId: "frame-forged-grant",
      observer: { observerId: "o", observerKind: "local_runtime", epochId: "e", isGlobalTruth: false },
      epochId: "e",
      asOfEpochMs: 1,
      sourceProjectionHash: S.snapshotLocalHash,
      entities: [
        {
          visibleId: "forged",
          kind: "agent",
          label: "an entity that claims a grant",
          isRuntimeObject: false,
          grant: "requested",
          freshness: "current",
          lifecycle: "observed",
          provenanceRefs: [],
          representsRuntimeId: null,
        } as never,
      ],
    });
    expect(forged.ok).toBe(false);
    if (!forged.ok) {
      expect(forged.refusal).toMatch(/^refused_/);
      expect(forged.explanation.length).toBeGreaterThan(0);
    }
  });

  it("28A refuses a frame that declares itself the global truth", () => {
    const global = buildGetigFrame({
      frameId: "frame-global",
      observer: { observerId: "o", observerKind: "local_runtime", epochId: "e", isGlobalTruth: true } as never,
      epochId: "e",
      asOfEpochMs: 1,
      sourceProjectionHash: S.snapshotLocalHash,
    });
    expect(global.ok).toBe(false);
  });

  it("28A refuses an entity that claims to BE the runtime object it depicts", () => {
    const isRuntime = buildGetigFrame({
      frameId: "frame-is-runtime",
      observer: { observerId: "o", observerKind: "local_runtime", epochId: "e", isGlobalTruth: false },
      epochId: "e",
      asOfEpochMs: 1,
      sourceProjectionHash: S.snapshotLocalHash,
      entities: [
        {
          visibleId: "pretender",
          kind: "agent",
          label: "an entity that claims to be the runtime object",
          isRuntimeObject: true,
          grant: "none",
          freshness: "current",
          lifecycle: "observed",
          provenanceRefs: [],
          representsRuntimeId: null,
        } as never,
      ],
    });
    expect(isRuntime.ok).toBe(false);
  });
});
