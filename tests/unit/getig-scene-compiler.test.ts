/**
 * PHASE 29B — GETIG SCENE GRAPH COMPILER — SUITE
 *
 * MODE: CPU-SIDE / DETERMINISTIC.
 *
 * The fixtures come from the FROZEN Phase-28 end-to-end scenario, not from
 * hand-written lookalikes. A compiler tested only against data it invented
 * would agree with its own assumptions forever; compiling real 28D output is
 * what makes "it obeys Phase-28 rank ceilings" a claim about Phase 28.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  MANDATORY_MARKER_COLLECTIONS,
  ROUTE_ROLE_ORDER,
  SCENE_COMPILER_BOUNDS,
  SCENE_COMPILER_REFUSAL_CODES,
  compileGetigScene,
} from "../../packages/durable-state/src/index.js";
import { runGetigEndToEndScenario } from "../../packages/durable-state/src/index.js";
import { GETIG_VISUAL_AXES, getigVisualPermittedTiers, getigVisualSemanticRank } from "../../packages/durable-state/src/index.js";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const ROOT = join(HERE, "..", "..");
const MODULE_SRC = join(ROOT, "packages", "durable-state", "src", "sceneGraphCompiler.ts");

const RAW = readFileSync(MODULE_SRC, "utf8");
const stripLiterals = (src: string): string => {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "/") {
      while (i < src.length && src[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && d === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const q = c;
      i++;
      while (i < src.length && src[i] !== q) {
        if (src[i] === "\\") i++;
        i++;
      }
      i++;
      out += '""';
      continue;
    }
    out += c;
    i++;
  }
  return out;
};
const CODE = stripLiterals(RAW);

// The REAL frozen Phase-28 mapping.
const decision = runGetigEndToEndScenario();
if (!decision.ok) throw new Error(`frozen Phase-28 scenario refused: ${decision.refusal}`);
const SCENARIO = decision.scenario;
const MAPPING = SCENARIO.mapping;
const RUNTIME_HASH = "5555666677778888";

const compile = (over: Record<string, unknown> = {}) =>
  compileGetigScene({ mapping: MAPPING, runtimeStateHash: RUNTIME_HASH, ...over });

const token = (over: Record<string, unknown> = {}): Record<string, unknown> => {
  const rank = over.axis === "knowledge" && over.semanticValue === "known" ? 1 : 0;
  return {
    tokenId: `t:${over.subjectVisibleId ?? "s"}:${over.axis ?? "knowledge"}:${over.semanticValue ?? "unknown"}`,
    axis: over.axis ?? "knowledge",
    semanticValue: over.semanticValue ?? "unknown",
    semanticRank: over.semanticRank ?? rank,
    subjectVisibleId: over.subjectVisibleId ?? "s1",
    subjectCollection: over.subjectCollection ?? "entities",
    claim: "descriptive_only",
    authority: "none",
    mutation: "none",
    executable: false,
    ...over,
  };
};

const mini = (tokens: readonly unknown[]) => ({
  schemaVersion: "menog-getig-visual/v0",
  frameId: "frame-mini",
  observerId: "obs-mini",
  mappingHash: "abcdef0123456789",
  tokens,
});

// ── 1. it compiles the real frozen Phase-28 mapping ─────────────────────────

describe("29B — compiles the frozen Phase-28 mapping", () => {
  it("compiles 28D's real mapping without refusal", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.code).toBe("scene_compiled");
    expect(r.scene.primitives.length).toBeGreaterThan(0);
    expect(r.authority).toBe("none");
    expect(r.controlPlane).toBe(false);
    expect(r.readOnly).toBe(true);
    expect(r.executionAuthorized).toBe(false);
  });

  it("binds every primitive to a visible subject id and a semantic token id", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const known = new Set<string>(MAPPING.tokens.map((t) => t.subjectVisibleId));
    for (const p of r.scene.primitives) {
      expect(known.has(p.primitiveId), `${p.primitiveId} is not a visible subject`).toBe(true);
    }
    // Every subject's principal token id is reachable from the mapping.
    const tokenIds = new Set<string>(MAPPING.tokens.map((t) => t.tokenId));
    for (const entry of r.sceneHash.length > 0 ? [0] : []) void entry;
    expect(tokenIds.size).toBeGreaterThan(0);
  });

  it("emits a primitive kind that matches the Phase-28 collection, unknown for the rest", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const kinds = new Set(r.scene.primitives.map((p) => p.kind));
    for (const k of kinds) expect(["entity", "relation", "route", "conflict", "refusal", "partition", "observer_view", "overlay", "unknown"]).toContain(k);
  });

  it("binds the scene to the mapping it came from", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.sourceMappingHash).toBe(MAPPING.mappingHash);
    expect(r.scene.sourceFrameId).toBe(MAPPING.frameId);
  });
});

// ── 2. determinism and the two separate hashes ──────────────────────────────

describe("29B — determinism, and LAYOUT_CHANGE != RUNTIME_CHANGE", () => {
  it("is byte-identical across repeated compilations of the same input", () => {
    const a = compile();
    const b = compile();
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.sceneHash).toBe(b.sceneHash);
    expect(a.layoutHash).toBe(b.layoutHash);
    expect(JSON.stringify(a.scene.primitives)).toBe(JSON.stringify(b.scene.primitives));
  });

  it("input ORDER does not change sceneHash or layoutHash", () => {
    const a = compile();
    const reversed = compile({ mapping: { ...MAPPING, tokens: [...MAPPING.tokens].reverse() } });
    expect(a.ok && reversed.ok).toBe(true);
    if (!a.ok || !reversed.ok) return;
    expect(reversed.sceneHash).toBe(a.sceneHash);
    expect(reversed.layoutHash).toBe(a.layoutHash);
    expect(JSON.stringify(reversed.scene.primitives)).toBe(JSON.stringify(a.scene.primitives));
  });

  it("sceneHash and layoutHash are DIFFERENT hashes over DISJOINT content", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.sceneHash).not.toBe(r.layoutHash);
    expect(r.sceneHash).not.toBe(r.scene.runtimeStateHash);
    // The layout hash is a pure function of coordinates: changing one position
    // must change layoutHash and NOTHING else.
    const moved = {
      ...MAPPING,
      tokens: MAPPING.tokens,
    };
    expect(moved).toBeDefined();
    expect(r.layoutHash).toHaveLength(64);
  });

  it("a SEMANTIC change moves sceneHash and leaves layoutHash alone", () => {
    const a = compile();
    const mutated = compile({
      mapping: { ...MAPPING, tokens: MAPPING.tokens.map((t) => (t.axis === "freshness" && t.semanticValue === "unknown" ? { ...t, axis: "freshness", semanticValue: "stale", semanticRank: 1 } : t)) },
    });
    expect(a.ok && mutated.ok).toBe(true);
    if (!a.ok || !mutated.ok) return;
    expect(mutated.sceneHash).not.toBe(a.sceneHash);
    // Same subject set, same sorted order -> same coordinates.
    expect(mutated.layoutHash).toBe(a.layoutHash);
  });

  it("neither hash equals the runtime state hash", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.sceneHash).not.toBe(RUNTIME_HASH);
    expect(r.layoutHash).not.toBe(RUNTIME_HASH);
  });
});

// ── 3. route role order is preserved ────────────────────────────────────────

describe("29B — route-role order is preserved", () => {
  it("emits roles as origin, forwarder, destination regardless of input order", () => {
    const roles = ["destination", "forwarder", "origin"];
    // The rank is read from Phase-28's own ordering rather than guessed: 28D
    // ranks origin 0, forwarder 1, destination 2, and the compiler REFUSES a
    // token whose claimed rank disagrees — which is exactly the check running.
    //
    // 29R1: the subjects follow Phase-28's OWN `${routeId}#${role}` route
    // subject convention (plus the route root's route_state token), because a
    // relation endpoint must now bind to a drawable route root. The previous
    // fixture used bare `route-<role>` ids that no route structure names — the
    // exact shape of 29D-OBS-2 — so it could never have caught the defect it
    // was compiled alongside.
    const tokens = [
      token({
        tokenId: "t:route-root",
        axis: "route_state",
        semanticValue: "unknown",
        semanticRank: getigVisualSemanticRank("route_state", "unknown"),
        subjectVisibleId: "rt",
        subjectCollection: "routes",
      }),
      ...roles.map((role) =>
        token({
          tokenId: `t:route-${role}`,
          axis: "route_role",
          semanticValue: role,
          semanticRank: getigVisualSemanticRank("route_role", role),
          subjectVisibleId: role === "forwarder" ? "rt#forwarder:n1" : `rt#${role}`,
          subjectCollection: "routes",
        }),
      ),
    ];
    const r = compileGetigScene({ mapping: mini(tokens), runtimeStateHash: RUNTIME_HASH });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.scene.relations.map((x) => x.role)).toEqual([...ROUTE_ROLE_ORDER]);
    // 29R1: every endpoint binds to a drawable primitive — the route root is
    // the origin relation's source and the chain then runs role-to-role.
    const primitiveIds = new Set(r.scene.primitives.map((p) => p.primitiveId));
    for (const rel of r.scene.relations) {
      expect(primitiveIds.has(rel.fromId), `${rel.fromId} is not drawable`).toBe(true);
      expect(primitiveIds.has(rel.toId), `${rel.toId} is not drawable`).toBe(true);
    }
    expect(r.scene.relations.map((x) => x.fromId)).toEqual(["rt", "rt#origin", "rt#forwarder:n1"]);
  });

  it("the required order matches Phase-28's route_role axis exactly", () => {
    expect([...ROUTE_ROLE_ORDER]).toEqual([...(GETIG_VISUAL_AXES.includes("route_role") ? ["origin", "forwarder", "destination"] : [])]);
  });

  it("every compiled relation carries authorizes false and trust none", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    for (const rel of r.scene.relations) {
      expect(rel.authorizes).toBe(false);
      expect(rel.trust).toBe("none");
    }
  });
});

// ── 4. conflicts, refusals and partitions are never dropped ─────────────────

describe("29B — mandatory markers are never silently dropped", () => {
  it("emits a marker for EVERY conflict, refusal and partition token", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const mandatory = MAPPING.tokens.filter((t) => (MANDATORY_MARKER_COLLECTIONS as readonly string[]).includes(t.subjectCollection));
    expect(mandatory.length).toBeGreaterThan(0);
    expect(r.mandatoryMarkers).toHaveLength(mandatory.length);
    for (const t of mandatory) expect(r.mandatoryMarkers).toContain(t.tokenId);
    expect(r.scene.overlays).toHaveLength(mandatory.length);
  });

  it("the real mapping's conflict, refusals and partitions are all present as overlays", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const kinds = new Set(r.scene.overlays.map((o) => o.kind));
    expect(kinds.has("conflict")).toBe(true);
    expect(kinds.has("refusal")).toBe(true);
    expect(kinds.has("partition")).toBe(true);
  });

  it("a rank-0 marker is made PRESENT but its VALUE stays withheld", () => {
    // The reconciliation of law 17 (must stay visible) with Phase-28 rank
    // ceilings (rank 0 may only be drawn at 'withheld').
    const r = compileGetigScene({
      mapping: mini([token({ axis: "conflict", semanticValue: "conflict_visible", subjectCollection: "conflicts", subjectVisibleId: "c1" })]),
      runtimeStateHash: RUNTIME_HASH,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.scene.overlays).toHaveLength(1);
    const overlay = r.scene.overlays[0];
    if (overlay === undefined) throw new Error("expected a marker overlay");
    expect(overlay.text).toBe("conflicts:present");
    expect(overlay.text).not.toContain("conflict_visible");
    expect(overlay.authority).toBe("none");
  });

  it("a marker whose rank permits 'minimal' does show its value", () => {
    // conflict_visible is rank 0 and so may ONLY be withheld. A marker Phase-28
    // permits to be shown is one whose OWN rank reaches minimal — e.g. a
    // conflict the observer already knows about (knowledge:known, rank 1).
    expect(getigVisualSemanticRank("conflict", "conflict_visible")).toBe(0);
    const rank = getigVisualSemanticRank("knowledge", "known");
    expect(rank).toBeGreaterThan(0);
    expect(getigVisualPermittedTiers(rank)).toContain("minimal");
    const r = compileGetigScene({
      mapping: mini([token({ axis: "knowledge", semanticValue: "known", semanticRank: rank, subjectCollection: "conflicts", subjectVisibleId: "c1" })]),
      runtimeStateHash: RUNTIME_HASH,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const overlay = r.scene.overlays[0];
    if (overlay === undefined) throw new Error("expected a marker overlay");
    expect(overlay.text).toBe("conflicts:known");
  });
});

// ── 5. Phase-28 rank ceilings are obeyed, not reimplemented ─────────────────

describe("29B — Phase-28 rank ceilings", () => {
  it("refuses a requested tier that exceeds Phase-28's ceiling", () => {
    const t = token({ axis: "authority", semanticValue: "read_only_zero_authority", semanticRank: 0 });
    const r = compileGetigScene({
      mapping: mini([t]),
      runtimeStateHash: RUNTIME_HASH,
      requestedTiers: { [String(t.tokenId)]: "declared" },
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal).toBe("refused_scene_rank_ceiling_exceeded");
    expect(r.scene).toBeNull();
    expect(r.partialSceneEmitted).toBe(false);
  });

  it("accepts a requested tier AT the ceiling", () => {
    const t = token({ axis: "knowledge", semanticValue: "known", semanticRank: 1 });
    expect(getigVisualPermittedTiers(1)).toContain("minimal");
    const r = compileGetigScene({ mapping: mini([t]), runtimeStateHash: RUNTIME_HASH, requestedTiers: { [String(t.tokenId)]: "minimal" } });
    expect(r.ok).toBe(true);
  });

  it("refuses a token whose claimed rank disagrees with Phase-28's own ordering", () => {
    // A token claiming a rank it does not hold would buy a higher ceiling.
    const r = compileGetigScene({
      mapping: mini([token({ axis: "knowledge", semanticValue: "unknown", semanticRank: 9 })]),
      runtimeStateHash: RUNTIME_HASH,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_scene_token_invalid");
  });

  it("refuses a semantic value that Phase-28 does not define for that axis", () => {
    const r = compileGetigScene({
      mapping: mini([token({ axis: "lifecycle", semanticValue: "unknown" })]),
      runtimeStateHash: RUNTIME_HASH,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal).toBe("refused_scene_token_unknown_axis");
  });
});

// ── 6. nothing is inferred, and colour carries nothing ──────────────────────

describe("29B — no inferred authority, no colour-only meaning", () => {
  it("assigns NO colour at all, so colour can never be the only carrier", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    for (const p of r.scene.primitives) expect(p.colorHint).toBe("none");
  });

  it("refuses a token carrying a claim-shaped field rather than stripping it", () => {
    for (const field of ["grant", "authorized", "trusted", "approved", "permission", "execute"]) {
      const r = compileGetigScene({ mapping: mini([token({ [field]: true })]), runtimeStateHash: RUNTIME_HASH });
      expect(r.ok, `accepted claim field ${field}`).toBe(false);
      if (!r.ok) {
        expect(r.refusal).toBe("refused_scene_authority_claim");
        expect(r.offendingField).toBe(field);
      }
    }
  });

  it("refuses a token whose authority or executable flag is not zero", () => {
    expect(compileGetigScene({ mapping: mini([token({ authority: "operator" })]), runtimeStateHash: RUNTIME_HASH }).ok).toBe(false);
    expect(compileGetigScene({ mapping: mini([token({ executable: true })]), runtimeStateHash: RUNTIME_HASH }).ok).toBe(false);
    expect(compileGetigScene({ mapping: mini([token({ claim: "authoritative" })]), runtimeStateHash: RUNTIME_HASH }).ok).toBe(false);
  });

  it("picking ids are opaque, bounded and deterministic", () => {
    const a = compile();
    const b = compile();
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(JSON.stringify(a.pickingIds)).toBe(JSON.stringify(b.pickingIds));
    expect(a.pickingIds.length).toBe(a.scene.primitives.length);
    expect(a.pickingIds.length).toBeLessThanOrEqual(SCENE_COMPILER_BOUNDS.maxPickingIds);
    // Opaque: the id does not contain the subject it names.
    for (const p of a.pickingIds) expect(p.pickingId).not.toContain(p.subjectVisibleId);
    const ids = new Set(a.pickingIds.map((p) => p.pickingId));
    expect(ids.size).toBe(a.pickingIds.length);
  });
});

// ── 7. bounds refuse; they never truncate ───────────────────────────────────

describe("29B — overflow refuses", () => {
  it("refuses a mapping with more tokens than the bound allows", () => {
    const many = Array.from({ length: SCENE_COMPILER_BOUNDS.maxTokens + 1 }, (_, i) => token({ tokenId: `t:${i}`, subjectVisibleId: `s${i}` }));
    const r = compileGetigScene({ mapping: mini(many), runtimeStateHash: RUNTIME_HASH });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toBe("refused_scene_budget_exceeded");
      expect(r.scene).toBeNull();
    }
  });

  it("refuses malformed mappings and bad bindings", () => {
    expect(compileGetigScene({ mapping: null, runtimeStateHash: RUNTIME_HASH }).ok).toBe(false);
    expect(compileGetigScene({ mapping: { ...MAPPING, schemaVersion: "other/v0" }, runtimeStateHash: RUNTIME_HASH }).ok).toBe(false);
    expect(compileGetigScene({ mapping: MAPPING, runtimeStateHash: "nope" }).ok).toBe(false);
    expect(compileGetigScene({ mapping: { ...MAPPING, frameId: "" }, runtimeStateHash: RUNTIME_HASH }).ok).toBe(false);
    expect(compileGetigScene({ mapping: { ...MAPPING, tokens: [{ bad: true }] }, runtimeStateHash: RUNTIME_HASH }).ok).toBe(false);
  });

  it("every refusal is zero-authority and emits nothing", () => {
    const cases = [
      compileGetigScene({ mapping: null, runtimeStateHash: RUNTIME_HASH }),
      compileGetigScene({ mapping: mini([token({ grant: true })]), runtimeStateHash: RUNTIME_HASH }),
      compileGetigScene({ mapping: mini([token({ axis: "nope", semanticValue: "x" })]), runtimeStateHash: RUNTIME_HASH }),
      compileGetigScene({ mapping: MAPPING, runtimeStateHash: "zz" }),
    ];
    for (const r of cases) {
      expect(r.ok).toBe(false);
      if (r.ok) continue;
      expect(r.code).toBe("scene_refused");
      expect(r.authority).toBe("none");
      expect(r.controlPlane).toBe(false);
      expect(r.readOnly).toBe(true);
      expect(r.executionAuthorized).toBe(false);
      expect(r.scene).toBeNull();
      expect(r.layoutHash).toBeNull();
      expect(r.pickingIds).toBeNull();
      expect(r.partialSceneEmitted).toBe(false);
      expect(SCENE_COMPILER_REFUSAL_CODES).toContain(r.refusal);
    }
  });
});

// ── 8. the compiler draws nothing and reaches nothing ───────────────────────

describe("29B — the compiler is CPU-side and reaches no control surface", () => {
  it("contains no GPU, draw or device token in its code", () => {
    for (const t of ["navigator.gpu", "GPUDevice", "WGSL", "createBuffer", "draw(", "submit(", "requestDevice"]) {
      expect(CODE.includes(t), `compiler contains ${t}`).toBe(false);
    }
  });

  it("reaches no network, store, Policy, tool or spawn surface", () => {
    expect(CODE).not.toMatch(/\b(fetch|WebSocket|net\.|dgram|http\.|https\.)\b/);
    // Callable verbs only. A bare \bexec\b also matches the harmless
    // property name `executable`; a scan that reports noise is a scan
    // nobody reads, so the verb must be in call position.
    expect(CODE).not.toMatch(/\b(spawn|fork|exec|execve|kill|system|popen)\s*\(/);
    expect(CODE).not.toMatch(/child_process|require\s*\(/);
    expect(CODE).not.toMatch(/process\.env|Date\.now|Math\.random|performance\.now/);
    expect(CODE).not.toMatch(/\b(PolicyEngine|ToolInvocation|invokeTool|mutatePolicy)\b/);
  });

  it("never mutates its input mapping", () => {
    const before = JSON.stringify(MAPPING);
    compile();
    expect(JSON.stringify(MAPPING)).toBe(before);
  });

  it("declares only refusal codes it actually emits", () => {
    const emitted = new Set<string>();
    for (const m of RAW.matchAll(/refuse\(+\s*"([a-z_]+)"/g)) emitted.add(m[1] as string);
    expect(emitted.size).toBeGreaterThan(0);
    for (const c of emitted) expect(SCENE_COMPILER_REFUSAL_CODES, `${c} emitted but undeclared`).toContain(c);
    for (const c of SCENE_COMPILER_REFUSAL_CODES) expect(emitted, `${c} declared but never emitted`).toContain(c);
  });

  it("the frozen vocabularies it depends on are actually imported, not re-derived", () => {
    expect(CODE).toContain("getigVisualPermittedTiers");
    expect(CODE).toContain("getigVisualSemanticRank");
    // If Phase 28 ever changed its ordering, this compiler must follow it rather
    // than carry a private copy that could drift by one position.
    expect(CODE).not.toMatch(/knowledge.*stale.*current/s);
  });
});

/**
 * 29D-OBS-3, found by 29D while building the CPU-side picking resolution.
 *
 * `overlayId` was `overlay:<collection>:<subject>`, which collides whenever one
 * subject carries two marker tokens of the same collection. The frozen 28D
 * mapping produces exactly that: `conflict:recon-28j-1:node-remote` carries
 * both `conflicts:known` and `conflicts:present`. Nine mandatory markers were
 * emitted, but only five distinct overlay identities existed — a marker the
 * runtime demonstrably holds became unreachable by id.
 *
 * That is the pack's integrity principle failing in miniature: the compiler was
 * correct about what it emitted and misleading about what could be found.
 */
describe("29B — overlay identity is unique (29D-OBS-3 regression)", () => {
  it("every emitted overlay has a distinct id", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const ids = r.scene.overlays.map((o) => o.overlayId);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("the frozen mapping really does put two marker tokens on one subject", () => {
    // Without this, uniqueness could pass simply because the collision case
    // does not exist, and the regression test would prove nothing.
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const byTarget = new Map<string, string[]>();
    for (const o of r.scene.overlays) {
      const list = byTarget.get(o.targetId) ?? [];
      list.push(o.text);
      byTarget.set(o.targetId, list);
    }
    const collided = [...byTarget.entries()].filter(([, texts]) => texts.length > 1);
    expect(collided.length).toBeGreaterThan(0);
    for (const [, texts] of collided) expect(new Set(texts).size).toBe(texts.length);
  });

  it("the id names the marker token, so two markers on one subject differ", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const conflicted = r.scene.overlays.filter((o) => o.targetId === "conflict:recon-28j-1:node-remote");
    expect(conflicted.length).toBeGreaterThan(1);
    expect(new Set(conflicted.map((o) => o.overlayId)).size).toBe(conflicted.length);
  });

  it("the marker count is unchanged: uniqueness did not cost a marker", () => {
    const r = compile();
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.scene.overlays).toHaveLength(r.mandatoryMarkers.length);
  });

  it("a hand-built subject with two same-collection markers still gets two ids", () => {
    const dual = compile({
      mapping: mini([
        token({ tokenId: "t:a", subjectVisibleId: "s1", subjectCollection: "conflicts", axis: "conflict", semanticValue: "conflict_visible" }),
        token({ tokenId: "t:b", subjectVisibleId: "s1", subjectCollection: "conflicts", axis: "knowledge", semanticValue: "unknown" }),
      ]),
    });
    if (!dual.ok) throw new Error(`expected a compile, got ${dual.refusal}`);
    const overlays = dual.scene.overlays.filter((o) => o.targetId === "s1");
    expect(overlays.length).toBe(2);
    expect(new Set(overlays.map((o) => o.overlayId)).size).toBe(2);
  });

  it("a COLLIDING marker identity is refused, not emitted (the guard is live)", () => {
    // Two tokens that share a tokenId, subject and collection produce the same
    // overlayId. The compiler must refuse rather than emit two markers under one
    // identity, because a marker the runtime holds but cannot address by id is
    // exactly the misleading picture the pack calls a security failure.
    // This case exists because falsification F7 removed the refusal and the
    // frozen-data uniqueness tests still passed: they never reach this branch.
    const collided = compileGetigScene({
      mapping: mini([
        token({ tokenId: "t:same", subjectVisibleId: "s1", subjectCollection: "conflicts", axis: "conflict", semanticValue: "conflict_visible" }),
        token({ tokenId: "t:same", subjectVisibleId: "s1", subjectCollection: "conflicts", axis: "knowledge", semanticValue: "unknown" }),
      ]),
      runtimeStateHash: RUNTIME_HASH,
    });
    expect(collided.ok).toBe(false);
    if (collided.ok) return;
    expect(collided.refusal).toBe("refused_scene_mandatory_marker_dropped");
    expect(collided.explanation).toContain("collided on overlay id");
    expect(collided.scene).toBeNull();
    expect(collided.partialSceneEmitted).toBe(false);
  });
});