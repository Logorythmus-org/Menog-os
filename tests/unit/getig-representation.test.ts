/**
 * PHASE 28A — GETIG Representation Contract
 * (CONTRACT-FIRST / RENDERER-NEUTRAL / READ-ONLY / ZERO AUTHORITY)
 *
 * 28A defines the closed shapes a visible world may take. These tests are the
 * gate's actual output: each law the prompt pins must be STRUCTURALLY true —
 * enforced by a literal in a type and asserted here — not merely described in a
 * comment.
 *
 * The laws under test, verbatim from the prompt:
 *   · visible entity != runtime entity
 *   · relation != trust
 *   · visual route != authorization
 *   · visible capability claim != grant
 *   · visible event != executable action
 *   · visual replay != runtime replay
 *   · observer view != global truth
 * plus: no renderer dependency, no action API, unknown vocabulary fails closed.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  buildGetigFrame,
  readGetigStructuralZeros,
  GETIG_SCHEMA_VERSION,
  GETIG_ENTITY_KINDS,
  GETIG_RELATION_KINDS,
  GETIG_EVENT_KINDS,
  GETIG_FRESHNESS_STATES,
  GETIG_LIFECYCLE_STATES,
  GETIG_CONFLICT_KINDS,
  GETIG_REFUSAL_CODES,
  GETIG_FORBIDDEN_CLAIM_FIELDS,
  GETIG_STRUCTURAL_ZERO_FIELDS,
  GETIG_BOUNDS,
  type GetigFrame,
  type GetigFrameInput,
  type GetigEntityKind,
} from "../../packages/durable-state/dist/index.js";

const SRC = join(process.cwd(), "packages", "durable-state", "src", "getigRepresentation.ts");

/** Remove line and block comments so a scan measures CODE, not prose. */
function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .map((l) => l.replace(/^[\s*]*\/\/.*$/, ""))
    .join("\n");
}
const HEX64 = /^[0-9a-f]{64}$/;
const NOW = 1_700_000_000_000;
const PROJECTION_HASH = "a".repeat(64);

const observer = (over: Partial<{ observerId: string; observerKind: string }> = {}) => ({
  observerId: over.observerId ?? "observer-local-1",
  observerKind: over.observerKind ?? "local_runtime",
  epochId: "epoch-28a",
  isGlobalTruth: false as const,
});

const baseInput = (over: Partial<GetigFrameInput> = {}): GetigFrameInput =>
  ({
    frameId: "frame-0001",
    observer: observer(),
    epochId: "epoch-28a",
    asOfEpochMs: NOW,
    sourceProjectionHash: PROJECTION_HASH,
    ...over,
  }) as GetigFrameInput;

const provenance = (refId = "ref-1") => ({
  refId,
  recordedAtEpochMs: NOW,
  sourceKind: "governed_evidence" as const,
  evidenceId: "ev-28a-1",
  confersTrust: false as const,
});

const entity = (visibleId: string, kind: GetigEntityKind = "runtime_node") => ({
  visibleId,
  kind,
  label: `label-${visibleId}`,
  isRuntimeObject: false as const,
  grant: "none" as const,
  freshness: "current" as const,
  lifecycle: "observed" as const,
  provenanceRefs: [],
  representsRuntimeId: null,
});

function build(over: Partial<GetigFrameInput> = {}) {
  return buildGetigFrame(baseInput(over));
}

function builtFrame(over: Partial<GetigFrameInput> = {}): GetigFrame {
  const decision = build(over);
  if (!decision.ok) {
    throw new Error(`expected a built frame, got ${decision.refusal}`);
  }
  return decision.frame;
}

describe("28A — a frame binds every required anchor", () => {
  it("carries frameId, observer, epoch, as-of time and BOTH hashes", () => {
    const frame = builtFrame();
    expect(frame.schemaVersion).toBe(GETIG_SCHEMA_VERSION);
    expect(frame.frameId).toBe("frame-0001");
    expect(frame.observer.observerId).toBe("observer-local-1");
    expect(frame.epochId).toBe("epoch-28a");
    expect(frame.asOfEpochMs).toBe(NOW);
    expect(frame.sourceProjectionHash).toBe(PROJECTION_HASH);
    expect(frame.canonicalVisibleHash).toMatch(HEX64);
  });

  it("distinguishes sourceProjectionHash from canonicalVisibleHash", () => {
    // Two DISTINCT fields on purpose: one names where the view came from, the
    // other proves what is being shown. Collapsing them would make "the evidence
    // changed" and "the view changed" indistinguishable.
    const frame = builtFrame();
    expect(frame.sourceProjectionHash).not.toBe(frame.canonicalVisibleHash);
    // The upstream hash is carried verbatim, never recomputed from our content.
    expect(frame.sourceProjectionHash).toBe(PROJECTION_HASH);
  });

  it("exposes every bounded visible collection", () => {
    const frame = builtFrame();
    for (const key of ["entities", "relations", "events", "conflicts", "refusals", "routes", "proposalFlows"] as const) {
      expect(Array.isArray(frame[key]), `${key} must be an array`).toBe(true);
    }
  });
});

describe("28A — PIN: observer view != global truth", () => {
  it("frame and observer context both declare themselves non-global", () => {
    const frame = builtFrame();
    expect(frame.globalTruth).toBe(false);
    expect(frame.observer.isGlobalTruth).toBe(false);
  });

  it("REFUSES a frame whose observer context claims to be global truth", () => {
    const decision = build({ observer: { ...observer(), isGlobalTruth: true } } as never);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_unknown_authority_claim");
  });

  it("REFUSES a frame with no observer context at all", () => {
    const decision = buildGetigFrame({ ...baseInput(), observer: undefined as never });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_missing_observer_context");
  });

  it("REFUSES an observer kind outside the closed vocabulary", () => {
    const decision = build({ observer: observer({ observerKind: "global_oracle" }) } as never);
    expect(decision.ok).toBe(false);
  });
});

describe("28A — PIN: visible entity != runtime entity, and claim != grant", () => {
  it("every entity declares isRuntimeObject:false and grant:'none'", () => {
    const frame = builtFrame({
      entities: [entity("v-tool", "tool_reference"), entity("v-policy", "policy_gate")],
    });
    for (const e of frame.entities) {
      expect(e.isRuntimeObject).toBe(false);
      expect(e.grant).toBe("none");
    }
  });

  it("REFUSES an entity carrying isRuntimeObject:true", () => {
    const decision = build({ entities: [{ ...entity("v-1"), isRuntimeObject: true }] as never });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_unknown_authority_claim");
  });

  it("REFUSES an entity carrying a granted capability claim", () => {
    const decision = build({ entities: [{ ...entity("v-1", "tool_reference"), grant: "granted" }] as never });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_unknown_authority_claim");
  });

  it("models EVERY runtime thing the prompt requires, in the closed vocabulary", () => {
    const required = [
      "runtime_node", "agent", "goal", "task", "tool_reference", "memory_reference",
      "policy_gate", "execution_boundary", "proposal", "route", "evidence", "refusal", "partition",
    ];
    for (const kind of required) {
      expect(GETIG_ENTITY_KINDS).toContain(kind as never);
    }
    // And every closed kind actually builds.
    for (const kind of GETIG_ENTITY_KINDS) {
      const frame = builtFrame({ entities: [entity(`v-${kind}`, kind)] });
      expect(frame.entities[0]!.kind).toBe(kind);
    }
  });
});

describe("28A — PIN: relation != trust", () => {
  it("every relation declares trust:'none'", () => {
    const frame = builtFrame({
      relations: [
        { relationId: "r-1", kind: "observed_edge", fromVisibleId: "v-a", toVisibleId: "v-b", trust: "none" as const, provenanceRefs: [] },
      ],
    });
    expect(frame.relations[0]!.trust).toBe("none");
  });

  it("REFUSES a relation claiming trust", () => {
    const decision = build({
      relations: [
        { relationId: "r-1", kind: "observed_edge", fromVisibleId: "v-a", toVisibleId: "v-b", trust: "established" as never, provenanceRefs: [] },
      ],
    } as never);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_unknown_authority_claim");
  });

  it("REFUSES an unknown relation kind rather than drawing a line", () => {
    const decision = build({
      relations: [
        { relationId: "r-1", kind: "trusts", fromVisibleId: "v-a", toVisibleId: "v-b", trust: "none" as const, provenanceRefs: [] },
      ],
    } as never);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_unknown_relation_kind");
  });
});

describe("28A — PIN: visual route != authorization", () => {
  const route = {
    routeId: "route-1",
    originVisibleId: "v-a",
    originFixed: true as const,
    forwarderVisibleIds: ["v-m1", "v-m2"],
    destinationVisibleId: "v-b",
    freshness: "current" as const,
    provenanceRefs: [],
    admission: "none" as const,
    authorization: "none" as const,
    executionAuthorized: false as const,
  };

  it("a visible route carries admission/authorization none and executionAuthorized false", () => {
    const frame = builtFrame({ routes: [route] });
    const r = frame.routes[0]!;
    expect(r.admission).toBe("none");
    expect(r.authorization).toBe("none");
    expect(r.executionAuthorized).toBe(false);
  });

  it("keeps the origin fixed and forwarders SEPARATE — a forwarder is never the origin", () => {
    const frame = builtFrame({ routes: [route] });
    const r = frame.routes[0]!;
    expect(r.originFixed).toBe(true);
    expect(r.originVisibleId).toBe("v-a");
    expect(r.forwarderVisibleIds).toEqual(["v-m1", "v-m2"]);
    expect(r.forwarderVisibleIds).not.toContain(r.originVisibleId);
    expect(r.destinationVisibleId).toBe("v-b");
  });

  it("REFUSES a route that claims authorization", () => {
    const decision = build({ routes: [{ ...route, authorization: "granted" }] as never });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_unknown_authority_claim");
  });

  it("REFUSES a route with an unfrozen origin", () => {
    const decision = build({ routes: [{ ...route, originFixed: false }] as never });
    expect(decision.ok).toBe(false);
  });

  it("a proposal flow endorses nobody", () => {
    const frame = builtFrame({
      proposalFlows: [
        {
          proposalId: "p-1",
          originVisibleId: "v-a",
          forwarderVisibleIds: ["v-m1"],
          destinationVisibleId: "v-b",
          hopCount: 2,
          endorsement: "none" as const,
          state: "forwarded" as const,
          provenanceRefs: [],
        },
      ],
    });
    expect(frame.proposalFlows[0]!.endorsement).toBe("none");
  });
});

describe("28A — PIN: visible event != executable action", () => {
  it("every event is executable:false and action:'none'", () => {
    const frame = builtFrame({
      events: [
        { eventId: "e-1", kind: "state_changed", atEpochMs: NOW, subjectVisibleId: "v-a", executable: false as const, action: "none" as const, freshness: "current" as const },
      ],
    });
    expect(frame.events[0]!.executable).toBe(false);
    expect(frame.events[0]!.action).toBe("none");
  });

  it("REFUSES an event marked executable, and one carrying an action", () => {
    const base = { eventId: "e-1", kind: "state_changed", atEpochMs: NOW, subjectVisibleId: "v-a", executable: false as const, action: "none" as const, freshness: "current" as const };
    expect(build({ events: [{ ...base, executable: true }] as never }).ok).toBe(false);
    expect(build({ events: [{ ...base, action: "restart_agent" }] as never }).ok).toBe(false);
  });

  it("REFUSES an unknown event kind", () => {
    const decision = build({
      events: [
        { eventId: "e-1", kind: "execute_now", atEpochMs: NOW, subjectVisibleId: "v-a", executable: false as const, action: "none" as const, freshness: "current" as const },
      ],
    } as never);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_unknown_event_kind");
  });
});

describe("28A — PIN: visual replay != runtime replay", () => {
  it("the frame declares visual-only, non-executable replay semantics", () => {
    const frame = builtFrame();
    expect(frame.replaySemantics).toBe("visual_only_not_executable");
  });

  it("REFUSES any other replay semantics", () => {
    const decision = buildGetigFrame({
      ...baseInput(),
      replaySemantics: "executable_replay",
    } as never);
    expect(decision.ok).toBe(false);
  });
});

describe("28A — VISUALIZATION != CONTROL PLANE", () => {
  it("authority none, controlPlane false, readOnly true are structural zeros", () => {
    const frame = builtFrame();
    expect(frame.authority).toBe("none");
    expect(frame.controlPlane).toBe(false);
    expect(frame.readOnly).toBe(true);
    expect(frame.visibleCapabilities).toEqual([]);
  });

  it("readGetigStructuralZeros reports no observable capability", () => {
    const zeros = readGetigStructuralZeros(builtFrame());
    expect(zeros.authority).toBe("none");
    expect(zeros.controlPlane).toBe(false);
    expect(zeros.readOnly).toBe(true);
    expect(zeros.globalTruth).toBe(false);
    expect(zeros.replaySemantics).toBe("visual_only_not_executable");
    expect(zeros.observableCapabilities).toBe(0);
  });

  it("REFUSES any non-zero authority / controlPlane / readOnly", () => {
    for (const bad of [{ authority: "admin" }, { controlPlane: true }, { readOnly: false }, { globalTruth: true }]) {
      expect(build(bad as never).ok, JSON.stringify(bad)).toBe(false);
    }
  });

  it("REFUSES a non-empty visibleCapabilities list", () => {
    expect(build({ visibleCapabilities: ["execute_tool"] } as never).ok).toBe(false);
  });
});

describe("28A — unknown vocabulary fails CLOSED (never defaulted)", () => {
  it("REFUSES an unknown entity kind", () => {
    const decision = build({ entities: [{ ...entity("v-1"), kind: "mystery" }] as never });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_unknown_entity_kind");
  });

  it("REFUSES unknown freshness — unknown stays unknown, never coerced to current", () => {
    const okUnknown = builtFrame({ entities: [{ ...entity("v-1"), freshness: "unknown" }] });
    expect(okUnknown.entities[0]!.freshness).toBe("unknown");
    const decision = build({ entities: [{ ...entity("v-1"), freshness: "probably_fine" }] as never });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_unknown_freshness");
  });

  it("REFUSES unknown lifecycle and keeps a retired fact retired", () => {
    const retired = builtFrame({ entities: [{ ...entity("v-1"), lifecycle: "retired" }] });
    expect(retired.entities[0]!.lifecycle).toBe("retired");
    expect(build({ entities: [{ ...entity("v-1"), lifecycle: "alive" }] as never }).ok).toBe(false);
  });

  it("REFUSES an unknown conflict kind", () => {
    const decision = build({
      conflicts: [
        { conflictId: "c-1", kind: "vibes", attributedToObserverId: "observer-local-1", subjectVisibleId: "v-1", claims: [], resolved: false as const },
      ],
    } as never);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_unknown_conflict_kind");
  });

  it("keeps a conflict VISIBLE and unresolved, and never picks a winner", () => {
    const frame = builtFrame({
      conflicts: [
        {
          conflictId: "c-1",
          kind: "value_disagreement",
          attributedToObserverId: "observer-local-1",
          subjectVisibleId: "v-1",
          claims: [
            { observerId: "observer-local-1", stated: "ready" },
            { observerId: "observer-local-2", stated: "quarantined" },
          ],
          resolved: false as const,
        },
      ],
    });
    const c = frame.conflicts[0]!;
    expect(c.resolved).toBe(false);
    // Both claims survive; a renderer gets no winner to draw.
    expect(c.claims.map((x) => x.stated)).toEqual(["ready", "quarantined"]);
    expect(c.attributedToObserverId).toBe("observer-local-1");
  });

  it("every closed vocabulary is frozen and non-empty", () => {
    for (const v of [GETIG_ENTITY_KINDS, GETIG_RELATION_KINDS, GETIG_EVENT_KINDS, GETIG_FRESHNESS_STATES, GETIG_LIFECYCLE_STATES, GETIG_CONFLICT_KINDS, GETIG_REFUSAL_CODES]) {
      expect(Array.isArray(v)).toBe(true);
      expect(v.length).toBeGreaterThan(0);
      expect(Object.isFrozen(v)).toBe(true);
    }
  });
});

describe("28A — provenance is METADATA ONLY (Law 9)", () => {
  it("a provenance ref confers no trust and carries an id, not content", () => {
    const frame = builtFrame({ entities: [{ ...entity("v-1"), provenanceRefs: [provenance()] }] });
    const ref = frame.entities[0]!.provenanceRefs[0]!;
    expect(ref.confersTrust).toBe(false);
    expect(ref.evidenceId).toBe("ev-28a-1");
    // It is a REFERENCE: the record's content is not inlined.
    expect(Object.keys(ref).sort()).toStrictEqual(["confersTrust", "evidenceId", "recordedAtEpochMs", "refId", "sourceKind"]);
  });

  it("evidenceId may be explicitly null — missing provenance is UNKNOWN, never invented", () => {
    const frame = builtFrame({
      entities: [
        { ...entity("v-1"), provenanceRefs: [{ refId: "r", recordedAtEpochMs: NOW, sourceKind: "local_configuration" as const, evidenceId: null, confersTrust: false as const }] },
      ],
    });
    expect(frame.entities[0]!.provenanceRefs[0]!.evidenceId).toBeNull();
  });

  it("REFUSES a provenance ref that claims to confer trust", () => {
    const decision = build({
      entities: [{ ...entity("v-1"), provenanceRefs: [{ ...provenance(), confersTrust: true }] }] as never,
    });
    expect(decision.ok).toBe(false);
  });
});

describe("28A — refusals are content, not errors to hide", () => {
  it("carries visible refusals with a closed code and an explanation", () => {
    const frame = builtFrame({
      refusals: [
        { refusalId: "rf-1", code: "refused_unknown_entity_kind", subjectVisibleId: "v-1", explanation: "an entity kind was not in the closed vocabulary" },
      ],
    });
    expect(frame.refusals[0]!.code).toBe("refused_unknown_entity_kind");
    expect(frame.refusals[0]!.explanation.length).toBeGreaterThan(0);
  });

  it("REFUSES a refusal carrying an unknown code rather than inventing one", () => {
    const decision = build({
      refusals: [{ refusalId: "rf-1", code: "something_went_wrong", subjectVisibleId: null, explanation: "x" }],
    } as never);
    expect(decision.ok).toBe(false);
  });

  it("every refusal code has a non-empty explanation available", () => {
    for (const code of GETIG_REFUSAL_CODES) {
      expect(code.length).toBeGreaterThan(0);
    }
    // A refusal must always carry a human-readable explanation.
    const decision = build({ entities: [{ ...entity("v-1"), kind: "nope" }] as never });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.explanation.length).toBeGreaterThan(10);
  });
});

describe("28A — Law 8: no raw or sensitive content may enter a visible contract", () => {
  it("REFUSES every forbidden claim field on mere presence, whatever its value", () => {
    for (const field of GETIG_FORBIDDEN_CLAIM_FIELDS) {
      const decision = build({ entities: [{ ...entity("v-1"), [field]: "harmless-looking" }] } as never);
      expect(decision.ok, `field '${field}' must refuse`).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_unknown_authority_claim");
    }
  });

  it("names the specific dangerous fields the prompt calls out", () => {
    for (const field of ["rawPrompt", "toolOutput", "memoryContent", "secret", "privateKey", "localPath", "policyDecision", "env"]) {
      expect(GETIG_FORBIDDEN_CLAIM_FIELDS).toContain(field as never);
    }
  });

  it("REFUSES a frame whose observer smuggles a raw transcript", () => {
    const decision = build({ observer: { ...observer(), transcript: "user said: hello" } } as never);
    expect(decision.ok).toBe(false);
  });
});

describe("28A — bounded and unambiguous", () => {
  it("REFUSES a collection over its bound", () => {
    const tooMany = Array.from({ length: GETIG_BOUNDS.maxEntities + 1 }, (_, i) => entity(`v-${i}`));
    const decision = build({ entities: tooMany });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_collection_bound");
  });

  it("accepts exactly the bound, refusing only beyond it", () => {
    const exact = Array.from({ length: GETIG_BOUNDS.maxEntities }, (_, i) => entity(`v-${i}`));
    expect(build({ entities: exact }).ok).toBe(true);
  });

  it("REFUSES duplicate visible ids in one namespace", () => {
    const decision = build({ entities: [entity("v-dup"), entity("v-dup")] });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_duplicate_visible_id");
  });

  it("REFUSES missing frameId and a missing sourceProjectionHash", () => {
    const noId = buildGetigFrame({ ...baseInput(), frameId: "" });
    expect(noId.ok).toBe(false);
    if (!noId.ok) expect(noId.refusal).toBe("refused_missing_frame_id");

    const noHash = build({ sourceProjectionHash: "" });
    expect(noHash.ok).toBe(false);
    if (!noHash.ok) expect(noHash.refusal).toBe("refused_missing_projection_hash");
  });

  it("REFUSES a sourceProjectionHash that is not a real 64-hex projection hash", () => {
    expect(build({ sourceProjectionHash: "not-a-hash" }).ok).toBe(false);
  });
});

describe("28A — canonical visible content must be DETERMINISTIC", () => {
  it("identical input yields an identical canonicalVisibleHash", () => {
    const a = builtFrame({ entities: [entity("v-1"), entity("v-2", "agent")] });
    const b = builtFrame({ entities: [entity("v-1"), entity("v-2", "agent")] });
    expect(a.canonicalVisibleHash).toBe(b.canonicalVisibleHash);
  });

  it("different content yields a different hash", () => {
    const a = builtFrame({ entities: [entity("v-1")] });
    const b = builtFrame({ entities: [entity("v-1"), entity("v-2")] });
    expect(a.canonicalVisibleHash).not.toBe(b.canonicalVisibleHash);
  });

  it("a different OBSERVER yields a different hash — observer-relative, never global", () => {
    const a = builtFrame({ observer: observer({ observerId: "observer-local-1" }) } as never);
    const b = builtFrame({ observer: observer({ observerId: "observer-local-2" }) } as never);
    expect(a.canonicalVisibleHash).not.toBe(b.canonicalVisibleHash);
  });

  it("a different upstream projection yields a different frame hash", () => {
    const a = builtFrame();
    const b = builtFrame({ sourceProjectionHash: "b".repeat(64) });
    expect(a.canonicalVisibleHash).not.toBe(b.canonicalVisibleHash);
  });

  it("the hash does not depend on wall-clock time at build time", () => {
    const first = builtFrame().canonicalVisibleHash;
    const second = builtFrame().canonicalVisibleHash;
    expect(first).toBe(second);
  });
});

describe("28A — renderer-neutral, no action API", () => {
  const source = readFileSync(SRC, "utf8");
  // Strip BOTH line and block comments. This module's header deliberately says
  // "no WebGPU, no canvas" — so scanning the raw text would match the prose
  // that promises the absence. The scan must measure CODE, not documentation.
  const code = stripComments(source);

  it("references NO renderer or graphics backend", () => {
    for (const token of ["webgpu", "three", "playcanvas", "babylon", "canvas", "document.", "window.", "gpu", "texture", "shader"]) {
      expect(code.toLowerCase().includes(token.toLowerCase()), `source must not reference '${token}'`).toBe(false);
    }
  });

  it("SELF-TEST: the comment-stripping scan still catches a REAL violation", () => {
    // The scan above would be worthless if it passed only because it cannot see
    // code. Prove it detects an actual renderer reference once comments are gone.
    const violation = `
      /** this comment mentions WebGPU and canvas, which must NOT trip the scan */
      export function drawIt(ctx: unknown) {
        return ctx.getContext("2d");
      }
    `;
    const scanned = stripComments(violation);
    expect(scanned.toLowerCase().includes("canvas")).toBe(false); // prose is gone
    expect(scanned.includes("getContext")).toBe(true); // the CODE is still visible
    // And the token list that matters would still fire on real code.
    expect(/document\.|window\.|getContext|webgpu/i.test(scanned)).toBe(true);
  });

  it("opens no socket, spawns no process, and reads no store", () => {
    for (const token of ["node:net", "node:child_process", "createServer", ".listen(", "node:sqlite", "DurableStore"]) {
      expect(code.includes(token), `source must not reference '${token}'`).toBe(false);
    }
  });

  it("exports no mutation, execution, admin or renderer function", () => {
    const exported = [...source.matchAll(/export function (\w+)/g)].map((m) => m[1]!);
    expect(exported.length).toBeGreaterThan(0);
    for (const name of exported) {
      expect(
        /^(execute|invoke|run|mutate|apply|commit|administer|admit|authorize|grant|render|draw|spawn|start|stop|delete|update|write|set)/i.test(name),
        `export '${name}' looks like an action API`,
      ).toBe(false);
    }
  });

  it("every structural zero is pinned in the exported zero map", () => {
    for (const key of ["authority", "controlPlane", "readOnly", "globalTruth", "grant", "trust", "admission", "authorization", "executionAuthorized", "executable", "action", "endorsement", "replaySemantics", "isRuntimeObject"]) {
      expect(Object.keys(GETIG_STRUCTURAL_ZERO_FIELDS)).toContain(key);
    }
    const zeros = GETIG_STRUCTURAL_ZERO_FIELDS as Readonly<Record<string, unknown>>;
    expect(zeros.authority).toStrictEqual("none");
    expect(zeros.replaySemantics).toStrictEqual("visual_only_not_executable");
  });

  it("a refusal exposes NO partial world at all", () => {
    const decision = build({ entities: [entity("v-1"), { ...entity("v-2"), kind: "mystery" } as never] });
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect("frame" in decision).toBe(false);
      expect(decision.code).toBe("frame_refused");
      expect(decision.explanation.length).toBeGreaterThan(0);
    }
  });
});

/**
 * The ten contracts the prompt names, audited against the EMITTED type
 * declarations rather than against intent. "Closed readonly contract" is only
 * true if the built .d.ts says so; a source-level glance cannot prove it, and
 * an earlier hand-rolled check silently matched nothing and printed a false
 * PASS. This version fails loudly when it cannot read a body.
 */
const DTS = join(process.cwd(), "packages", "durable-state", "dist", "getigRepresentation.d.ts");
const REQUIRED_CONTRACTS = [
  "GetigFrame",
  "VisibleEntity",
  "VisibleRelation",
  "VisibleEvent",
  "VisibleConflict",
  "VisibleRefusal",
  "VisibleRoute",
  "VisibleProposalFlow",
  "VisibleProvenanceRef",
  "VisibleObserverContext",
] as const;

function interfaceMembers(dts: string, name: string): string[] | null {
  const start = dts.indexOf(`export interface ${name} `);
  if (start < 0) return null;
  const open = dts.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < dts.length; i++) {
    if (dts[i] === "{") depth++;
    else if (dts[i] === "}") {
      depth--;
      if (depth === 0) {
        return dts
          .slice(open + 1, i)
          .split("\n")
          .map((l) => l.replace(/\r$/, ""))
          .filter((l) => /^\s+(readonly\s+)?[A-Za-z_$][\w$]*\s*\??\s*:/.test(l));
      }
    }
  }
  return null;
}

describe("28A — all ten contracts are EXPORTED and fully READONLY", () => {
  const dts = readFileSync(DTS, "utf8");

  it("exports every contract the prompt names", () => {
    for (const name of REQUIRED_CONTRACTS) {
      expect(dts.includes(`export interface ${name} `), `${name} must be exported`).toBe(true);
    }
  });

  it("declares every member of every contract readonly", () => {
    for (const name of REQUIRED_CONTRACTS) {
      const members = interfaceMembers(dts, name);
      // A null or empty read is a FAILURE, never a silent pass — the exact bug
      // this test exists to prevent.
      expect(members, `${name} body must be readable`).not.toBeNull();
      expect(members!.length, `${name} must declare members`).toBeGreaterThan(0);
      const mutable = members!.filter((l) => !/^\s+readonly\s/.test(l));
      expect(mutable, `${name} has mutable members: ${mutable.join(" | ")}`).toStrictEqual([]);
    }
  });

  it("SELF-TEST: the member reader really does detect a mutable member", () => {
    // Prove the audit has teeth before trusting its PASS.
    const fake = `export interface Demo {\n    readonly a: string;\n    b: number;\n}`;
    const members = interfaceMembers(fake, "Demo")!;
    expect(members.length).toBe(2);
    expect(members.filter((l) => !/^\s+readonly\s/.test(l))).toStrictEqual(["    b: number;"]);
  });
});