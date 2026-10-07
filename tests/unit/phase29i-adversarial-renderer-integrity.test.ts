/**
 * PHASE 29I — ADVERSARIAL RENDERER INTEGRITY — REGRESSION SUITE
 *
 * MODE: ATTACK THE COMPLETE 29A–29H SURFACE / ZERO AUTHORITY / FAIL-CLOSED.
 *
 * Central laws under test:
 *   UNSUPPORTED != PASS
 *   INCONCLUSIVE != PASS
 *   RENDERED REALITY IS A MATERIALIZATION OF GETIG, NOT A SOURCE OF AUTHORITY
 *   ZERO CRITICAL BYPASS REQUIRED (computed from outcomes, never asserted)
 *
 * The attacks live in `phase29AdversarialCatalogue.ts` — a TABLE, not a test,
 * so the verdict map is produced by the same 28I harness that scored Phase 28's
 * attacks. This suite:
 *
 *   1. runs the whole catalogue through the harness and audits the verdict map
 *   2. pins the per-attack expected verdicts (54 attacks; exactly two are
 *      non-PASS: 29I-33 INCONCLUSIVE, 29I-44 UNSUPPORTED — both NON-BYPASS)
 *   3. proves the four-wide taxonomy never merges UNSUPPORTED/INCONCLUSIVE
 *      into PASS
 *   4. proves family coverage: the pack's 22 adversarial families are present
 *      set-equal, and every catalogue attack is referenced by a family
 *   5. runs the pack's two named static scans:
 *      29I-S-secret-scan and 29I-S-alternate-path-scan
 *      (each with planted POSITIVE CONTROLS that must fire, and comment/string
 *      decoys that must NOT fire)
 *
 * Everything here measures sources and real execution on disk; nothing is
 * hand-asserted as green without running it first.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import {
  PHASE29_ATTACK_CATALOGUE,
  PHASE29_ATTACK_FAMILIES,
  hashAdversarialRun,
  runAdversarialSuite,
} from "../../packages/durable-state/src/index.js";
import {
  ADVERSARIAL_VERDICTS,
  ATTACK_CATEGORIES,
} from "../../packages/durable-state/src/getigAdversarialHarness.js";
import type {
  AdversarialSummary,
  AttackOutcome,
} from "../../packages/durable-state/src/getigAdversarialHarness.js";

// ── run the catalogue once, through the real harness ─────────────────────────

const RUN = runAdversarialSuite(PHASE29_ATTACK_CATALOGUE);
const OUTCOMES: readonly AttackOutcome[] = RUN.outcomes;
const SUMMARY: AdversarialSummary = RUN.summary;

const outcomeById = new Map(OUTCOMES.map((o) => [o.attackId, o]));
const outcomeOf = (attackId: string): AttackOutcome => {
  const o = outcomeById.get(attackId);
  if (!o) throw new Error(`no outcome recorded for ${attackId}`);
  return o;
};

/** The ONLY two attacks whose honest verdict is not PASS. Neither is a bypass. */
const EXPECTED_NON_PASS = new Map<string, string>([
  ["29I-33-recovery-label-only-tamper", "INCONCLUSIVE"],
  ["29I-44-wgsl-source-compilation", "UNSUPPORTED"],
]);

/** The pack's 22 adversarial families, verbatim, for set-equality. */
const PACK_FAMILIES: readonly string[] = [
  "conflict/refusal/partition hiding",
  "stale→current",
  "unknown→trusted",
  "claim→grant",
  "route→authorization",
  "forwarder→origin",
  "observer-local→global truth",
  "layout/size/depth/color authority",
  "animation→execution",
  "visual replay→runtime replay",
  "stale GPU buffers",
  "frame/scene/hash mismatch",
  "semantic-token/instance mismatch",
  "picking substitution and picking→control escape",
  "provenance/explanation misbinding",
  "silent truncation/overflow",
  "malformed WGSL/shader input",
  "device-loss state resurrection",
  "resource leaks",
  "fake causality/chronology/consensus",
  "secret/raw-content leakage",
  "alternate network/spawn/persist/tool/control path",
];

/** The pack's two named static scans, referenced by family coverage records. */
const NAMED_SCANS = ["29I-S-secret-scan", "29I-S-alternate-path-scan"] as const;

// ── the 29E/29F source scanner (comments and strings stripped) ───────────────

const stripLiterals = (src: string): string => {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") i += 1;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i += 1;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      const q = c;
      i += 1;
      while (i < src.length && src[i] !== q) {
        if (src[i] === "\\") i += 1;
        i += 1;
      }
      i += 1;
      out += '""';
      continue;
    }
    out += c;
    i += 1;
  }
  return out;
};

/** The renderer/GPU modules the pack's law 18 covers (29D–29I). */
const RENDERER_MODULES: readonly string[] = [
  "gpuRenderPlan.ts",
  "gpuResourceLifecycle.ts",
  "renderFrameComposer.ts",
  "temporalTransitionPlanner.ts",
  "pickingResolver.ts",
  "phase29AdversarialCatalogue.ts",
];

const moduleSrc = (file: string): string =>
  readFileSync(new URL(`../../packages/durable-state/src/${file}`, import.meta.url), "utf8");
const moduleCode = (file: string): string => stripLiterals(moduleSrc(file));

/**
 * Code-position tokens a secret/raw-content leak would have to go through.
 * (Byte conversion for canonical hashing — `Buffer.from(view.buffer, …)` in
 * 29D — is hashing machinery, not secret access, so it is not on this list.)
 */
const SECRET_TOKENS: readonly string[] = [
  "process.env",
  "process.argv",
  "localStorage",
  "sessionStorage",
  "document.cookie",
  "apiKey",
  "api_key",
  "password",
  "passphrase",
  "credential",
  "privateKey",
  "BEGIN RSA",
  "rawPrompt",
  "toolOutput",
  "rawMemory",
  "atob(",
];

/** Code-position tokens an alternate network/spawn/persist path would need. */
const ALT_PATH_TOKENS: readonly string[] = [
  "node:child_process",
  "node:net",
  "node:http",
  "node:https",
  "node:fs",
  "child_process",
  "spawn(",
  "exec(",
  "execSync(",
  "fork(",
  "writeFile",
  "createWriteStream",
  "indexedDB",
  "fetch(",
  "XMLHttpRequest",
  "WebSocket",
  "sendBeacon",
  "eval(",
  "new Function(",
];

const hitsOf = (tokens: readonly string[], code: string): string[] =>
  tokens.filter((t) => code.includes(t));

// ═════════════════════════════════════════════════════════════════════════════
describe("29I-1 — the catalogue runs end-to-end and yields a verdict map", () => {
  it("every attack scored exactly once; ids are unique and well-formed", () => {
    expect(OUTCOMES.length).toBe(PHASE29_ATTACK_CATALOGUE.length);
    expect(SUMMARY.caseCount).toBe(PHASE29_ATTACK_CATALOGUE.length);
    expect(SUMMARY.caseCount).toBeGreaterThanOrEqual(50);
    const ids = OUTCOMES.map((o) => o.attackId);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^29I-\d{2}-[a-z0-9-]+$/);
    expect([...outcomeById.keys()].sort()).toEqual([...ids].sort());
  });

  it("ZERO CRITICAL BYPASS — computed by the harness from `bypassed`, never asserted", () => {
    expect(SUMMARY.criticalBypass).toBe(false);
    expect(SUMMARY.bypassedAttackIds).toEqual([]);
    expect(SUMMARY.criticalAttackIds).toEqual([]);
    expect(SUMMARY.fail).toBe(0);
    for (const o of OUTCOMES) {
      expect(o.bypassed, `${o.attackId} bypassed: ${o.observed}`).toBe(false);
      expect(o.critical, o.attackId).toBe(false);
    }
  });

  it("every outcome carries a non-empty, auditable `observed` string", () => {
    for (const o of OUTCOMES) {
      expect(o.observed.length, o.attackId).toBeGreaterThan(0);
      expect(o.observed.length).toBeLessThanOrEqual(1024);
    }
  });

  it("the verdict map is deterministic across two full runs (no clock, no randomness)", () => {
    const second = runAdversarialSuite(PHASE29_ATTACK_CATALOGUE);
    expect(second.summary).toEqual(SUMMARY);
    expect(hashAdversarialRun(second.outcomes)).toBe(hashAdversarialRun(OUTCOMES));
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29I-2 — the per-attack expected verdict table (54 attacks on real surfaces)", () => {
  it("each attack lands on its declared verdict: PASS, except 33 INCONCLUSIVE / 44 UNSUPPORTED", () => {
    for (const attack of PHASE29_ATTACK_CATALOGUE) {
      const expected = EXPECTED_NON_PASS.get(attack.attackId) ?? "PASS";
      const o = outcomeOf(attack.attackId);
      expect(o.verdict, `${attack.attackId}: ${o.observed}`).toBe(expected);
    }
  });

  it("the non-PASS set is exactly {29I-33, 29I-44} — nothing else escaped PASS", () => {
    const nonPass = OUTCOMES.filter((o) => o.verdict !== "PASS").map((o) => o.attackId).sort();
    expect(nonPass).toEqual([...EXPECTED_NON_PASS.keys()].sort());
  });

  it("29I-33 is INCONCLUSIVE and records the OBS-1 limitation honestly", () => {
    const o = outcomeOf("29I-33-recovery-label-only-tamper");
    expect(o.verdict).toBe("INCONCLUSIVE");
    expect(o.bypassed).toBe(false);
    expect(o.observed).toContain("29I-OBS-1");
    expect(o.observed).toContain("29J not executed");
  });

  it("29I-44 is UNSUPPORTED because no WGSL source or compiler exists here", () => {
    const o = outcomeOf("29I-44-wgsl-source-compilation");
    expect(o.verdict).toBe("UNSUPPORTED");
    expect(o.defence).toBe("unsupported");
    expect(o.bypassed).toBe(false);
    expect(o.observed).toContain("UNSUPPORTED != PASS");
  });

  it("PASS outcomes are blocked structurally or by refusal — never by chance", () => {
    for (const o of OUTCOMES) {
      if (o.verdict !== "PASS") continue;
      expect(["structural", "refusal"], o.attackId).toContain(o.defence);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29I-3 — verdict taxonomy is four-wide; UNSUPPORTED/INCONCLUSIVE never merge into PASS", () => {
  it("counts partition the catalogue exactly: pass + fail + unsupported + inconclusive = caseCount", () => {
    expect(SUMMARY.pass + SUMMARY.fail + SUMMARY.unsupported + SUMMARY.inconclusive).toBe(
      SUMMARY.caseCount,
    );
    expect(SUMMARY.pass).toBe(SUMMARY.caseCount - 2);
    expect(SUMMARY.unsupported).toBe(1);
    expect(SUMMARY.inconclusive).toBe(1);
    expect(SUMMARY.unsupportedAttackIds).toEqual(["29I-44-wgsl-source-compilation"]);
    expect(SUMMARY.inconclusiveAttackIds).toEqual(["29I-33-recovery-label-only-tamper"]);
  });

  it("structural flags stay false: UNSUPPORTED is not PASS, a mock is not validation", () => {
    expect(SUMMARY.unsupportedIsPass).toBe(false);
    expect(SUMMARY.mockCountedAsValidation).toBe(false);
    expect(SUMMARY.authority).toBe("none");
    expect(SUMMARY.readOnly).toBe(true);
  });

  it("every verdict is one of the four declared values", () => {
    for (const o of OUTCOMES) {
      expect([...ADVERSARIAL_VERDICTS], o.attackId).toContain(o.verdict);
    }
  });

  it("a PASS count that included 29I-33/29I-44 would be detected here", () => {
    const passIds = OUTCOMES.filter((o) => o.verdict === "PASS").map((o) => o.attackId);
    expect(passIds).not.toContain("29I-33-recovery-label-only-tamper");
    expect(passIds).not.toContain("29I-44-wgsl-source-compilation");
    expect(passIds.length).toBe(SUMMARY.pass);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29I-4 — family coverage: the pack's 22 families, set-equal and fully referenced", () => {
  it("family names are exactly the pack's 22, set-equal, no extras, no omissions", () => {
    const declared = PHASE29_ATTACK_FAMILIES.map((f) => f.family).sort();
    expect(declared).toEqual([...PACK_FAMILIES].sort());
    expect(new Set(declared).size).toBe(PACK_FAMILIES.length);
  });

  it("every family attackId exists in the catalogue AND every catalogue attack is referenced", () => {
    const catalogueIds = new Set(PHASE29_ATTACK_CATALOGUE.map((a) => a.attackId));
    const referenced = new Set<string>();
    for (const family of PHASE29_ATTACK_FAMILIES) {
      expect(family.attackIds.length, family.family).toBeGreaterThan(0);
      for (const id of family.attackIds) {
        expect(catalogueIds.has(id), `${family.family} references ${id}`).toBe(true);
        referenced.add(id);
      }
    }
    expect([...referenced].sort()).toEqual([...catalogueIds].sort());
  });

  it("the two named static scans are declared as co-coverage for their families", () => {
    const declaredScans = PHASE29_ATTACK_FAMILIES.flatMap((f) => f.coveredElsewhereInTests ?? []);
    expect([...declaredScans].sort()).toEqual([...NAMED_SCANS].sort());
  });

  it("all 12 harness attack categories are covered — coverage proof, not a score", () => {
    expect([...SUMMARY.categoriesCovered].sort()).toEqual([...ATTACK_CATEGORIES].sort());
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29I-S-secret-scan — no secret/raw prompt/tool output/private path in renderer/GPU sources", () => {
  it("none of the six renderer/GPU modules contains a secret/raw-content token in CODE", () => {
    for (const file of RENDERER_MODULES) {
      const hits = hitsOf(SECRET_TOKENS, moduleCode(file));
      expect(hits, `${file} leaks: ${hits.join(", ")}`).toEqual([]);
    }
  });

  it("POSITIVE CONTROL: the scan fires on a token really present in code position", () => {
    const planted = "const key = process.env.MENOG_API_KEY; fetch(api_key);";
    expect(hitsOf(SECRET_TOKENS, stripLiterals(planted))).toContain("process.env");
    expect(hitsOf(SECRET_TOKENS, stripLiterals(planted)).length).toBeGreaterThanOrEqual(2);
  });

  it("POSITIVE CONTROL: comments and string literals alone must NOT trip the scan", () => {
    const decoy = '// never read process.env or a password here\nconst s = "credential apiKey";\n';
    expect(hitsOf(SECRET_TOKENS, stripLiterals(decoy))).toEqual([]);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
describe("29I-S-alternate-path-scan — no alternate network/spawn/persist/control path", () => {
  it("none of the six modules contains a spawn/net/http/fs-write/eval token in CODE", () => {
    for (const file of RENDERER_MODULES) {
      const hits = hitsOf(ALT_PATH_TOKENS, moduleCode(file));
      expect(hits, `${file} opens an alternate path: ${hits.join(", ")}`).toEqual([]);
    }
  });

  it("the import surface is relative (or node:crypto) — nothing else can be pulled in", () => {
    for (const file of RENDERER_MODULES) {
      const specs = [...moduleSrc(file).matchAll(/from\s+"([^"]+)"/g)].map((m) => m[1]!);
      expect(specs.length, file).toBeGreaterThan(0);
      for (const spec of specs) {
        const allowed = spec.startsWith("./") || spec === "node:crypto";
        expect(allowed, `${file} imports ${spec}`).toBe(true);
        expect(spec.startsWith("node:"), `${file} imports ${spec}`).toBe(spec === "node:crypto");
      }
    }
  });

  it("POSITIVE CONTROL: the scan fires on a spawn import really present in code", () => {
    const planted = "spawn(cmd); execSync(job); writeFile(p, d);";
    const hits = hitsOf(ALT_PATH_TOKENS, stripLiterals(planted));
    expect(hits).toContain("spawn(");
    expect(hits).toContain("execSync(");
    expect(hits).toContain("writeFile");
    // The module-specifier side of an alternate path is caught by the import
    // surface test above, which reads RAW source (specifiers are strings).
    const plantedImport = 'import { spawn } from "node:child_process";';
    const specs = [...plantedImport.matchAll(/from\s+"([^"]+)"/g)].map((m) => m[1]!);
    expect(specs).toContain("node:child_process");
    expect(specs.some((s) => s.startsWith("./") || s === "node:crypto")).toBe(false);
  });

  it("POSITIVE CONTROL: comments mentioning a path must NOT trip the scan", () => {
    const decoy = "// could spawn() or fetch() here, but only in this comment\n";
    expect(hitsOf(ALT_PATH_TOKENS, stripLiterals(decoy))).toEqual([]);
  });
});
