/**
 * PHASE 28K — PHASE-28 AUDIT & FREEZE (TESTS)
 *
 * This is an AUDIT gate. It adds no feature and no runtime module: it verifies
 * the ten Phase-28 gates that came before it, so the freeze is a mechanical
 * claim rather than a promise.
 *
 * Every law in the 28K prompt's "Prove" list is checked here against the REAL
 * modules and the REAL composed scenario, not against prose in a report. Where a
 * check is pattern-based it says so in its name and its comment, because
 * pattern screening is evidence about patterns and not proof of absence.
 *
 * The source scans strip comments and string literals FIRST. A scan that cannot
 * tell a comment from a call is not evidence about code — and these modules
 * document their own laws in prose containing the very tokens being scanned for.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { runGetigEndToEndScenario } from "../../packages/durable-state/dist/index.js";

const ROOT = process.cwd();
const SRC_DIR = join(ROOT, "packages", "durable-state", "src");

const BACKTICK = String.fromCharCode(96);
const DQ = String.fromCharCode(34);
const SQ = String.fromCharCode(39);
const NL = String.fromCharCode(10);
const BS = String.fromCharCode(92);

/** Strip comments and string/template literals so a scan reads CODE, not prose. */
const stripLiterals = (source: string): string => {
  let out = "";
  let i = 0;
  while (i < source.length) {
    const c = source[i]!;
    const two = source.slice(i, i + 2);
    if (two === "//") {
      while (i < source.length && source[i] !== NL) i += 1;
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
        if (source[i] === BS + BS) {
          i += 2;
          continue;
        }
        if (source[i] === quote) {
          i += 1;
          break;
        }
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


/** The shape the 28K freeze record is required to have. */
interface FreezeRecord {
  readonly verdict: string;
  readonly scenarioHash: string;
  readonly adversarialRunHash: string;
  readonly perGateSuites: readonly { readonly gate: string; readonly tests: number }[];
  readonly artifacts: readonly { readonly path: string; readonly bytes: number; readonly sha256: string }[];
  readonly debt: readonly { readonly id: string; readonly severity: string; readonly finding: string }[];
  readonly verification: {
    readonly fullSuite: {
      readonly tests: number;
      readonly files: number;
      readonly baselineBefore28K: { readonly tests: number; readonly files: number };
      readonly addedBy28K: { readonly suite: string; readonly tests: number; readonly files: number };
    };
    readonly phase28Dedicated: { readonly tests: number; readonly files: number };
    readonly regressions: { readonly tests: number };
    readonly frozenAudit: { readonly byteIdentical: number; readonly drifted: number };
    readonly verifyLocal: { readonly overall: string; readonly errors: number };
  };
}

/** The eleven Phase-28 modules, read from disk and stripped. */
const PHASE28_MODULES = readdirSync(SRC_DIR)
  .filter((n) => /^getig.*\.ts$/.test(n))
  .sort();

const CODE = new Map(PHASE28_MODULES.map((n) => [n, stripLiterals(readFileSync(join(SRC_DIR, n), "utf8"))]));
const ALL_CODE = [...CODE.values()].join("\n");

const PHASE28_TESTS = [
  "getig-representation",
  "getig-entity-projection",
  "getig-temporal-frames",
  "getig-visual-mapping",
  "getig-observer-views",
  "getig-provenance",
  "getig-inspection-runtime",
  "getig-disclosure-gate",
  "getig-adversarial-visible-runtime",
  "getig-end-to-end-scenario",
];

/** One live end-to-end run: the composed Phase-28 world every audit reads. */
const decision = runGetigEndToEndScenario();
if (!decision.ok) {
  throw new Error(`28K audit cannot proceed: the 28J scenario refused ${decision.refusal} at ${decision.cause?.stage}`);
}
const S = decision.scenario;

/** Re-derive the frozen-baseline audit rather than trusting a recorded number. */
const frozenAudit = (): { exit: number; out: string } => {
  try {
    const out = execFileSync(process.execPath, ["scripts/phase28c-frozen-check.mjs"], {
      cwd: ROOT,
      encoding: "utf8",
      timeout: 120_000,
    });
    return { exit: 0, out };
  } catch (error) {
    const e = error as { status?: number; stdout?: string; stderr?: string };
    return { exit: e.status ?? 1, out: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
};
// ── 1. order and completeness ───────────────────────────────────────────────

describe("28K — the Phase-28 order is complete and every gate left evidence", () => {
  it("every one of the eleven Phase-28 modules exists on disk", () => {
    expect(PHASE28_MODULES).toEqual([
      "getigAdversarialCatalog.ts",
      "getigAdversarialHarness.ts",
      "getigDisclosureGate.ts",
      "getigEndToEndScenario.ts",
      "getigEntityProjection.ts",
      "getigInspectionRuntime.ts",
      "getigObserverViews.ts",
      "getigProvenance.ts",
      "getigRepresentation.ts",
      "getigTemporalFrames.ts",
      "getigVisualMapping.ts",
    ]);
    for (const name of PHASE28_MODULES) {
      expect(statSync(join(SRC_DIR, name)).size).toBeGreaterThan(1_000);
    }
  });

  it("every one of the ten Phase-28 suites exists on disk", () => {
    for (const name of PHASE28_TESTS) {
      const p = join(ROOT, "tests", "unit", `${name}.test.ts`);
      expect(statSync(p).size, `${name} is missing`).toBeGreaterThan(1_000);
    }
  });

  it("every gate 28A..28J has a written report in docs/release", () => {
    for (const gate of ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"]) {
      const p = join(ROOT, "docs", "release", `PROMPT_28${gate}_REPORT.md`);
      expect(statSync(p).size, `PROMPT_28${gate}_REPORT.md is missing`).toBeGreaterThan(500);
    }
  });

  it("the whole phase is exported from the package index", () => {
    const index = readFileSync(join(SRC_DIR, "index.ts"), "utf8");
    for (const name of PHASE28_MODULES) {
      expect(index, `${name} is not exported`).toContain(name.replace(/\.ts$/, ".js"));
    }
  });
});

// ── 2. the composed chain, read live ────────────────────────────────────────

describe("28K — visible world is projection, not authority (read from the live chain)", () => {
  it("no artifact in the composed chain carries authority, control plane or global truth", () => {
    const frames = [S.frame, S.frameLater, S.frameRecovery, S.frameRemote];
    for (const f of frames) {
      expect(f.authority).toBe("none");
      expect(f.controlPlane).toBe(false);
      expect(f.readOnly).toBe(true);
      expect(f.globalTruth).toBe(false);
      expect(f.visibleCapabilities).toEqual([]);
      expect(f.observer.isGlobalTruth).toBe(false);
    }
    for (const v of [S.viewLocal, S.viewRemote]) {
      expect(v.authority).toBe("none");
      expect(v.isGlobalTruth).toBe(false);
      expect(v.assertsConsensus).toBe(false);
    }
    expect(S.multiView.synthesizesGlobalTruth).toBe(false);
    expect(S.multiView.terminalResurrected).toBe(false);
    expect(S.comparison.winnerDeclared).toBe(false);
    expect(S.comparison.consensusAsserted).toBe(false);
    expect(S.authority).toBe("none");
    expect(S.controlPlane).toBe(false);
    expect(S.grantsNothing).toBe(true);
    expect(S.createsActionPath).toBe(false);
  });

  it("runtime state != observation != projection != visual representation != authority", () => {
    // Each layer names a DIFFERENT artifact and none of them is another.
    expect(S.frame.sourceProjectionHash).not.toBe(S.frame.canonicalVisibleHash);
    expect(S.viewLocal.viewHash).not.toBe(S.frame.canonicalVisibleHash);
    expect(S.mapping.mappingHash).not.toBe(S.viewLocal.viewHash);
    expect(S.graph.graphHash).not.toBe(S.mapping.mappingHash);
    expect(S.sequence.sequenceIdentity).not.toBe(S.graph.graphHash);
    expect(S.disclosure.disclosureFrameHash).not.toBe(S.sequence.sequenceIdentity);
    // And the final layer, pixels, does not exist here at all: graphicsBackend none.
    expect(S.mapping.graphicsBackend).toBe("none");
  });

  it("claim never grant, and route never authorization", () => {
    for (const frame of [S.frame, S.frameLater, S.frameRecovery, S.frameRemote]) {
      for (const e of frame.entities) expect(e.grant).toBe("none");
      for (const r of frame.relations) expect(r.trust).toBe("none");
      for (const p of frame.proposalFlows) expect(p.endorsement).toBe("none");
      for (const r of frame.routes) {
        expect(r.admission).toBe("none");
        expect(r.authorization).toBe("none");
        expect(r.executionAuthorized).toBe(false);
      }
      for (const ev of frame.events) {
        expect(ev.executable).toBe(false);
        expect(ev.action).toBe("none");
      }
    }
    for (const token of S.mapping.tokens) {
      expect(token.claim).toBe("descriptive_only");
      expect(token.authority).toBe("none");
      expect(token.executable).toBe(false);
      expect(token.mutation).toBe("none");
    }
    // The renderer-facing admission axis reads not_admitted with no evidence supplied.
    for (const t of S.mapping.tokens.filter((x) => x.axis === "admission")) {
      expect(t.semanticValue).toBe("not_admitted");
    }
  });

  it("forwarder is never origin — three separate roles on a non-collapsible axis", () => {
    const route = S.frame.routes.find((r) => r.routeId === "route-28j-1")!;
    expect(route.originFixed).toBe(true);
    expect(route.originVisibleId).not.toBe(route.forwarderVisibleIds[0]);
    expect(route.destinationVisibleId).not.toBe(route.originVisibleId);
    const roles = S.mapping.tokens.filter((t) => t.axis === "route_role");
    expect(roles.filter((t) => t.semanticValue === "origin")).toHaveLength(1);
    expect(roles.filter((t) => t.semanticValue === "forwarder")).toHaveLength(1);
    expect(roles.filter((t) => t.semanticValue === "destination")).toHaveLength(1);
    // The axis may not be collapsed, which is what prevents a forwarder being
    // drawn as an origin at all.
    expect(S.coarseningSuppressionRefusal.ok).toBe(false);
  });

  it("observer view is never global truth, and synthesis is refused", () => {
    expect(S.synthesisRefusal.ok).toBe(false);
    expect(S.synthesisRefusal.winnerDeclared).toBe(false);
    expect(S.synthesisRefusal.consensusAsserted).toBe(false);
    expect(S.synthesisRefusal.isGlobalTruth).toBe(false);
    for (const entry of [...S.comparison.agreements, ...S.comparison.disagreements, ...S.comparison.unknownDifferences]) {
      expect(entry.freshnessDecidesNothing).toBe(true);
    }
  });

  it("unknown stays unknown and stale stays stale; conflict stays visible", () => {
    expect(S.frame.entities.find((e) => e.visibleId === "node-relay")!.freshness).toBe("stale");
    expect(S.frameLater.entities.find((e) => e.visibleId === "node-remote")!.freshness).toBe("unknown");
    expect(S.frameLater.entities.find((e) => e.visibleId === "node-remote")!.lifecycle).toBe("unknown");
    expect(S.frame.entities.find((e) => e.visibleId === "memory:session-log")!.provenanceRefs).toEqual([]);
    for (const frame of [S.frame, S.frameLater]) {
      expect(frame.conflicts.length).toBeGreaterThan(0);
      for (const c of frame.conflicts) expect(c.resolved).toBe(false);
    }
    expect(S.graph.unknownProvenanceSubjects.length).toBeGreaterThan(0);
  });
});

// ── 3. replay, provenance, disclosure, inspection ────────────────────────────

describe("28K — visual replay never executes, and the readers stay read-only", () => {
  it("visual replay is a history, never a resume", () => {
    expect(S.frame.replaySemantics).toBe("visual_only_not_executable");
    expect(S.sequence.replaySemantics).toBe("visual_history_not_executable");
    expect(S.sequence.restoresRuntimeState).toBe(false);
    expect(S.sequence.resumesRuntimeState).toBe(false);
    expect(S.diff.restoresRuntimeState).toBe(false);
    expect(S.diff.causalityClaimed).toBe(false);
    expect(S.resumeRefusal.ok).toBe(false);
    // A restart opens a new epoch and does not continue the old timeline.
    expect(S.crossEpochSequenceRefusal.refusal).toBe("refused_sequence_frame_epoch_mismatch");
    expect(S.frameRecovery.epochId).not.toBe(S.frame.epochId);
  });

  it("provenance is attributable metadata and confers nothing", () => {
    expect(S.graph.nodes.every((n) => n.isEvidenceContent === false)).toBe(true);
    expect(S.graph.nodes.every((n) => n.confersTrust === false && n.confersAuthority === false)).toBe(true);
    expect(S.graph.edges.every((e) => e.confersTrust === false && e.confersAuthority === false)).toBe(true);
    expect(S.graph.authorizes).toBe(false);
    expect(S.trustRefusal.confersTrust).toBe(false);
    expect(S.trustRefusal.confersAuthority).toBe(false);
    expect(S.trustRefusal.authorizesExecution).toBe(false);
    for (const frame of [S.frame, S.frameLater, S.frameRecovery, S.frameRemote]) {
      for (const e of frame.entities) {
        for (const p of e.provenanceRefs) expect(p.confersTrust).toBe(false);
      }
    }
    // A subject with no citation is an explicit unknown node, never a blank.
    expect(S.graph.nodes.some((n) => n.kind === "unknown")).toBe(true);
  });

  it("disclosure is allowlisted, scalar-only, and a refusal discloses nothing", () => {
    expect(S.disclosure.disclosesRawContent).toBe(false);
    expect(S.disclosure.disclosesPolicyText).toBe(false);
    expect(S.disclosure.redacted).toBe(false);
    expect(S.disclosure.manifest.defaultDeny).toBe(true);
    for (const record of S.disclosure.records) {
      for (const value of Object.values(record.fields)) {
        expect(["string", "number", "boolean"]).toContain(typeof value);
      }
    }
    for (const refused of [S.secretDisclosureRefusal, S.nestedValueDisclosureRefusal]) {
      expect(refused.ok).toBe(false);
      if (!refused.ok) {
        expect(refused.frame).toBeNull();
        expect(refused.manifest).toBeNull();
        expect(refused.partialFrameEmitted).toBe(false);
      }
    }
  });

  it("inspection is read-only and exposes no operation outside its closed list", () => {
    expect(S.inspections.every((i) => i.ok)).toBe(true);
    expect(S.successfulInspections).toBe(9);
    expect(S.controlRefusal.ok).toBe(false);
    expect(S.controlRefusal.result).toBeNull();
    expect(S.controlRefusal.mutatedCanonicalState).toBe(false);
    for (const a of S.refusedAttempts) {
      expect(a.refused).toBe(true);
      expect(a.outcome).toMatch(/^refused_/);
      expect(a.outcome).not.toBe("UNEXPECTED_SUCCESS");
    }
    // A filter result is always marked incomplete rather than passed off as complete.
    expect(S.proofs.every((p) => p.holds)).toBe(true);
    expect(S.failedProofs).toEqual([]);
  });

  it("UNSUPPORTED is never PASS, and the adversarial run had no bypass", () => {
    const s = S.adversarial;
    expect(s.unsupportedIsPass).toBe(false);
    expect(s.mockCountedAsValidation).toBe(false);
    expect(s.criticalBypass).toBe(false);
    expect(s.fail).toBe(0);
    expect(s.pass + s.fail + s.unsupported + s.inconclusive).toBe(s.caseCount);
    expect(s.categoriesCovered.length).toBe(12);
  });
});

// ── 4. renderer-neutral, no control path, no discovery ──────────────────────

describe("28K — renderer-neutral, no control path, no discovery (source scans over CODE)", () => {
  it("no Phase-28 module references a graphics backend or WebGPU", () => {
    expect(ALL_CODE).not.toMatch(/webgpu|gpuadapter|gpudevice|gpurenderpipeline|gpubuffer|navigator\.gpu/i);
    expect(ALL_CODE).not.toMatch(/\b(three|playcanvas|babylon|unity|unreal)\b/i);
    expect(S.mapping.graphicsBackend).toBe("none");
    expect(S.mapping.rendererNeutral).toBe(true);
  });

  it("no Phase-28 module calls Policy, tools, isolation, peer admin or process control", () => {
    expect(ALL_CODE).not.toMatch(/\b(evaluatePolicy|requestAdmission|admitPeer|revokePeer|invokeTool|runTool|startProcess|spawnProcess|allocateActor)\s*\(/);
    expect(ALL_CODE).not.toMatch(/\b(execute|spawn|fork|exec|kill|dispatch|approve|assign)\s*\(/);
  });

  it("no Phase-28 module opens a listener, a network path or a store", () => {
    expect(ALL_CODE).not.toMatch(/\bfetch\s*\(|node:https?|node:net|node:dgram|node:tls|XMLHttpRequest|WebSocket/);
    expect(ALL_CODE).not.toMatch(/node:sqlite|node:fs|openStore|writeStore|readStore/);
    expect(ALL_CODE).not.toMatch(/\b(setInterval|setTimeout)\s*\(/);
  });

  it("no Phase-28 module reads a clock, the environment or randomness", () => {
    expect(ALL_CODE).not.toMatch(/Date\.now|new Date\s*\(|performance\.now|Math\.random|process\.env/);
  });

  it("no Phase-28 module reaches discovery, WAN, relay, NAT, gossip or consensus", () => {
    expect(ALL_CODE).not.toMatch(/\b(discover|discovery|relay|natTraversal|upnp|stun|turn|gossip|membership|quorum|raft|leader election|totalOrder|globalClock)\s*[(:]/i);
  });

  it("every Phase-28 module exports only readers: no mutator in callable position", () => {
    // The forbidden actions 28G declares by name must appear nowhere as a call
    // in ANY Phase-28 module, not only in 28G's own file.
    //
    // NOTE the double backslashes: "\b" in a JavaScript string is a BACKSPACE
    // character and "\s" collapses to the letter s, so a single-escaped version of
    // this line compiles cleanly and then throws "Unterminated group" at run time.
    // A regex built from a string needs its own escapes doubled.
    const forbidden = ["execute", "approve", "admit", "grant", "kill", "restart", "write_runtime_state", "auto_resume", "invoke_tool", "mutate_policy"];
    for (const verb of forbidden) {
      const re = new RegExp("\\b" + verb + "\\s*\\(");
      expect(re.source, `${verb} compiled to a nonsense pattern`).toBe(`\\b${verb}\\s*\\(`);
      for (const [name, code] of CODE) {
        expect(re.test(code), `${name} calls ${verb}()`).toBe(false);
      }
    }
  });
});

// ── 5. freshly re-run baselines, governance, and the freeze record itself ────

describe("28K — freshly re-derived baselines", () => {
  it(
    "the Phase-20..28 frozen baseline is still 66/66 byte-identical",
    () => {
      const { exit, out } = frozenAudit();
      const clean = out.replace(new RegExp(`${String.fromCharCode(27)}\[[0-9;]*m`, "g"), "");
      expect(exit, `frozen audit failed:\n${clean.slice(0, 600)}`).toBe(0);
      expect(clean).toMatch(/drifted\s*:\s*0/);
      expect(clean).toMatch(/missing\s*:\s*0/);
      expect(clean).toMatch(/byte-identical now\s*:\s*66/);
      expect(clean).toContain("FROZEN INTEGRITY: PASS (66/66 byte-identical)");
    },
    180_000,
  );

  it("dependency and lockfile state matches the 29R4-authorized baseline", () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = Object.keys({ ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) });
    for (const graphics of ["three", "@react-three/fiber", "playcanvas", "babylonjs", "@babylonjs/core", "unity", "unreal"]) {
      expect(deps, `${graphics} is a dependency`).not.toContain(graphics);
    }
    // SUPERSEDED AT GATE 29R4 (2026-10-05): the pre-authorization baseline was
    // 36 919 bytes with four devDependencies. The HUMAN explicitly authorized
    // exactly one addition — @webgpu/types@0.1.74, dev-only, zero runtime deps —
    // recorded in docs/release/PHASE29R4_TYPING_DECISION.json (prior record
    // archived byte-exact). The baseline moved ONCE, with authorization; it is
    // re-pinned here, and any further dependency change fails this audit again.
    expect(Object.keys(pkg.devDependencies ?? {}).sort()).toEqual(["@types/node", "@webgpu/types", "rimraf", "typescript", "vitest"]);
    expect(pkg.devDependencies?.["@webgpu/types"]).toBe("0.1.74");
    expect(pkg.dependencies ?? {}).toEqual({});
    expect(statSync(join(ROOT, "pnpm-lock.yaml")).size).toBe(37_174);
  });

  it("Git and publication authorization is unchanged", () => {
    const git = (args: string[]): string => {
      try {
        return execFileSync("git", args, { cwd: ROOT, encoding: "utf8", timeout: 30_000, stdio: ["ignore", "pipe", "ignore"] }).trim();
      } catch {
        return "";
      }
    };
    // 0 commits: `git rev-parse --verify HEAD` must fail. stderr is discarded so the
    // expected "Needed a single revision" fatal does not leak into the run log.
    expect(git(["rev-parse", "--verify", "HEAD"])).toBe("");
    expect(git(["remote"]).split("\n").filter(Boolean)).toHaveLength(0);
    expect(git(["tag"]).split("\n").filter(Boolean)).toHaveLength(0);
    expect(git(["stash", "list"]).split("\n").filter(Boolean)).toHaveLength(0);
    expect(git(["diff", "--cached", "--name-only"]).split("\n").filter(Boolean)).toHaveLength(0);
  });
});

describe("28K — debt is carried honestly, and the freeze record agrees with disk", () => {
  const FREEZE = join(ROOT, "docs", "release", "PHASE28_FINAL_EVIDENCE.json");
  const FREEZE_MD = join(ROOT, "docs", "release", "PHASE_28_FREEZE.md");
  const record = JSON.parse(readFileSync(FREEZE, "utf8")) as FreezeRecord;

  it("the three 28K outputs exist on disk", () => {
    expect(statSync(FREEZE).size).toBeGreaterThan(500);
    expect(statSync(FREEZE_MD).size).toBeGreaterThan(500);
    expect(statSync(join(ROOT, "docs", "release", "PROMPT_28K_REPORT.md")).size).toBeGreaterThan(500);
  });

  it("the verdict is one of the three the prompt allows, and names the debt", () => {
    expect([
      "PHASE28_FROZEN_READY_FOR_PHASE29_WEBGPU_RUNTIME_DESIGN",
      "PHASE28_FROZEN_WITH_NONBLOCKING_DEBT",
      "PHASE28_BLOCKED",
    ]).toContain(record.verdict);
    expect(record.verdict).toBe("PHASE28_FROZEN_WITH_NONBLOCKING_DEBT");
    expect(record.debt.length).toBeGreaterThanOrEqual(4);
    for (const d of record.debt) {
      expect(d.id).toMatch(/^28J-OBS-\d$/);
      expect(d.severity).toBe("non_blocking_defect");
      expect(d.finding.length).toBeGreaterThan(40);
    }
  });

  it("the record's live figures agree with the running system", () => {
    expect(record.scenarioHash).toBe(S.scenarioHash);
    expect(record.adversarialRunHash).toBe(S.adversarialRunHash);
    const v = record.verification;
    expect(v.phase28Dedicated.tests).toBe(575);
    expect(v.phase28Dedicated.files).toBe(10);
    // The full-suite total is bound to THIS file's own case count, measured from
    // this file's own bytes. Editing the audit suite therefore forces the
    // recorded total to be re-derived; it cannot silently drift.
    const selfCases = (readFileSync(join(ROOT, "tests/security/phase28k-freeze-audit.test.ts"), "utf8").match(/^\s*it\(/gm) ?? []).length;
    expect(selfCases).toBe(v.fullSuite.addedBy28K.tests);
    expect(v.fullSuite.addedBy28K.files).toBe(1);
    expect(v.fullSuite.tests).toBe(v.fullSuite.baselineBefore28K.tests + selfCases);
    expect(v.fullSuite.files).toBe(v.fullSuite.baselineBefore28K.files + 1);
    expect(v.frozenAudit.byteIdentical).toBe(66);
    expect(v.frozenAudit.drifted).toBe(0);
    expect(v.regressions.tests).toBe(60);
    expect(v.verifyLocal.overall).toBe("PASS");
    expect(v.verifyLocal.errors).toBe(0);
  });

  it("the record's per-gate suite figures sum to the Phase-28 total", () => {
    expect(record.perGateSuites).toHaveLength(10);
    expect(record.perGateSuites.reduce((n, g) => n + g.tests, 0)).toBe(575);
  });

  it("every artifact hash the record asserts is the hash on disk right now", () => {
    expect(record.artifacts.length).toBeGreaterThanOrEqual(21);
    for (const a of record.artifacts) {
      const abs = join(ROOT, a.path);
      expect(statSync(abs).size, `${a.path} size`).toBe(a.bytes);
      // A real SHA-256 of the file on disk, compared against the recorded prefix.
      // The 28J evidence record shipped a one-character hash error that a length
      // check could not catch; this compares content, not shape.
      const digest = createHash("sha256").update(readFileSync(abs)).digest("hex");
      expect(digest.startsWith(a.sha256), `${a.path} hash drifted`).toBe(true);
    }
  });

  it("the freeze markdown names the verdict, the four debts and the D-26-1 limitation", () => {
    const md = readFileSync(FREEZE_MD, "utf8");
    expect(md).toContain("PHASE28_FROZEN_WITH_NONBLOCKING_DEBT");
    for (const id of ["28J-OBS-1", "28J-OBS-2", "28J-OBS-4", "28J-OBS-5"]) {
      expect(md, `the freeze document omits ${id}`).toContain(id);
    }
    expect(md).toContain("D-26-1");
    expect(md).toContain("NOT GRANTED");
  });
});
