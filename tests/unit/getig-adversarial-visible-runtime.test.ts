/**
 * PHASE 28I — ADVERSARIAL VISIBLE RUNTIME
 *
 * This suite asserts the properties of the ADVERSARIAL RUN, not the properties
 * of the modules under attack. The attacks themselves live in the catalogue,
 * where each one declares what a bypass would be.
 *
 * The load-bearing assertions are negative: zero critical bypass, and a verdict
 * map that does not hide anything behind PASS.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  runAdversarialSuite,
  scoreAttack,
  hashAdversarialRun,
  ADVERSARIAL_VERDICTS,
  ATTACK_CATEGORIES,
  ADVERSARIAL_BOUNDS,
  ADVERSARIAL_SCHEMA_VERSION,
  type AttackInput,
} from "../../packages/durable-state/src/getigAdversarialHarness.js";
import { ATTACK_CATALOGUE } from "../../packages/durable-state/src/getigAdversarialCatalog.js";

const here = dirname(fileURLToPath(import.meta.url));
const CATALOGUE_PATH = join(here, "..", "..", "packages", "durable-state", "src", "getigAdversarialCatalog.ts");

const { outcomes, summary } = runAdversarialSuite(ATTACK_CATALOGUE);

// ── 1. the verdict map ───────────────────────────────────────────────────────

describe("28I — adversarial verdict map", () => {
  it("reports zero critical bypass, which is the only condition for 28I_PASS", () => {
    expect(summary.criticalBypass, `bypassed: ${summary.bypassedAttackIds.join(", ")}`).toBe(false);
    expect(summary.bypassedAttackIds).toEqual([]);
    expect(summary.criticalAttackIds).toEqual([]);
  });

  it("has no FAIL case", () => {
    expect(summary.fail, `failed attacks: ${outcomes.filter((o) => o.verdict === "FAIL").map((o) => o.attackId).join(", ")}`).toBe(0);
  });

  it("accounts for every case in exactly one verdict bucket", () => {
    expect(summary.pass + summary.fail + summary.unsupported + summary.inconclusive).toBe(summary.caseCount);
  });

  it("runs a catalogue at the scale the prompt requires", () => {
    expect(summary.caseCount).toBeGreaterThanOrEqual(30);
    expect(summary.caseCount).toBe(ATTACK_CATALOGUE.length);
  });

  it("covers every declared attack category", () => {
    for (const category of ATTACK_CATEGORIES) {
      expect(summary.categoriesCovered, `category not covered: ${category}`).toContain(category);
    }
    expect(summary.categoriesCovered.length).toBe(ATTACK_CATEGORIES.length);
  });

  it("has unique attack ids", () => {
    const ids = outcomes.map((o) => o.attackId);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("records a defence and an observation for every case", () => {
    for (const o of outcomes) {
      expect(o.observed.length).toBeGreaterThan(0);
      expect(["structural", "refusal", "unsupported", "none"]).toContain(o.defence);
      expect(o.description.length).toBeGreaterThan(0);
    }
  });

  it("is deterministic — the same catalogue yields the same hash", () => {
    const again = runAdversarialSuite(ATTACK_CATALOGUE);
    expect(hashAdversarialRun(again.outcomes)).toBe(hashAdversarialRun(outcomes));
  });

  it("declares the structural non-claims", () => {
    expect(summary.unsupportedIsPass).toBe(false);
    expect(summary.mockCountedAsValidation).toBe(false);
    expect(summary.authority).toBe("none");
    expect(summary.readOnly).toBe(true);
    expect(summary.schemaVersion).toBe(ADVERSARIAL_SCHEMA_VERSION);
  });
});

// ── 2. UNSUPPORTED is never PASS ─────────────────────────────────────────────

describe("28I — UNSUPPORTED is never PASS", () => {
  it("an attack declaring unsupported scores UNSUPPORTED, not PASS", () => {
    const outcome = scoreAttack({
      attackId: "probe-1",
      category: "unsupported_as_pass",
      description: "an attack the platform cannot express",
      run: () => ({ unsupported: true, observed: "no such capability here" }),
    });
    expect(outcome.verdict).toBe("UNSUPPORTED");
    expect(outcome.bypassed).toBe(false);
    expect(outcome.critical).toBe(false);
    expect(outcome.defence).toBe("unsupported");
  });

  it("an unsupported case is counted in its own bucket, never in pass", () => {
    const { summary: s } = runAdversarialSuite([
      { attackId: "a", category: "unsupported_as_pass", description: "d", run: () => ({ unsupported: true, observed: "x" }) },
      { attackId: "b", category: "unsupported_as_pass", description: "d", run: () => ({ bypassed: false, observed: "y" }) },
    ]);
    expect(s.unsupported).toBe(1);
    expect(s.pass).toBe(1);
    expect(s.caseCount).toBe(2);
    expect(s.unsupportedAttackIds).toEqual(["a"]);
  });

  it("an inconclusive case is not PASS and not a bypass", () => {
    const outcome = scoreAttack({
      attackId: "probe-2",
      category: "unsupported_as_pass",
      description: "an ambiguous outcome",
      run: () => ({ inconclusive: true, observed: "cannot tell" }),
    });
    expect(outcome.verdict).toBe("INCONCLUSIVE");
    expect(outcome.bypassed).toBe(false);
    expect(outcome.critical).toBe(false);
  });

  it("the taxonomy is exactly the four declared values", () => {
    expect([...ADVERSARIAL_VERDICTS]).toEqual(["PASS", "FAIL", "UNSUPPORTED", "INCONCLUSIVE"]);
  });
});

// ── 3. criticality is computed, not asserted ─────────────────────────────────

describe("28I — criticality is computed", () => {
  it("a bypass is FAIL and critical", () => {
    const outcome = scoreAttack({
      attackId: "probe-3",
      category: "authority_inflation",
      description: "an attack that succeeds",
      run: () => ({ bypassed: true, observed: "it worked" }),
    });
    expect(outcome.verdict).toBe("FAIL");
    expect(outcome.bypassed).toBe(true);
    expect(outcome.critical).toBe(true);
    expect(outcome.defence).toBe("none");
  });

  it("a non-bypass is never critical", () => {
    const outcome = scoreAttack({
      attackId: "probe-4",
      category: "authority_inflation",
      description: "an attack that fails",
      run: () => ({ bypassed: false, defence: "structural", observed: "blocked" }),
    });
    expect(outcome.critical).toBe(false);
    expect(outcome.verdict).toBe("PASS");
  });

  it("one bypass is enough to set criticalBypass, and it names the attack", () => {
    const { summary: s } = runAdversarialSuite([
      { attackId: "ok", category: "authority_inflation", description: "d", run: () => ({ bypassed: false, observed: "blocked" }) },
      { attackId: "bad", category: "disclosure_leak", description: "d", run: () => ({ bypassed: true, observed: "leaked" }) },
    ]);
    expect(s.criticalBypass).toBe(true);
    expect(s.bypassedAttackIds).toEqual(["bad"]);
    expect(s.pass).toBe(1);
    expect(s.fail).toBe(1);
  });

  it("an attack cannot choose its own verdict", () => {
    // The runner derives the verdict from the result; a stray `verdict` field on
    // the attack has no path into the outcome.
    const hostile = {
      attackId: "probe-5",
      category: "authority_inflation",
      description: "d",
      verdict: "PASS",
      run: () => ({ bypassed: true, observed: "actually a bypass" }),
    } as unknown as AttackInput;
    expect(scoreAttack(hostile).verdict).toBe("FAIL");
  });
});

// ── 4. harness bounds ────────────────────────────────────────────────────────

describe("28I — harness bounds", () => {
  it("refuses an over-long attack id", () => {
    const many: AttackInput[] = [
      {
        attackId: "x".repeat(ADVERSARIAL_BOUNDS.maxIdChars + 1),
        category: "authority_inflation",
        description: "d",
        run: () => ({ bypassed: false, observed: "o" }),
      },
    ];
    expect(() => runAdversarialSuite(many)).toThrow();
  });

  it("refuses an empty attack id", () => {
    const one: AttackInput[] = [
      { attackId: "", category: "authority_inflation", description: "d", run: () => ({ bypassed: false, observed: "o" }) },
    ];
    expect(() => runAdversarialSuite(one)).toThrow();
  });

  it("truncates an over-long observation rather than emitting it whole", () => {
    const outcome = scoreAttack({
      attackId: "probe-6",
      category: "authority_inflation",
      description: "d",
      run: () => ({ bypassed: false, observed: "x".repeat(ADVERSARIAL_BOUNDS.maxObservedChars + 500) }),
    });
    expect(outcome.observed.length).toBeLessThanOrEqual(ADVERSARIAL_BOUNDS.maxObservedChars + 16);
    expect(outcome.observed).toContain("[truncated]");
  });

  it("refuses a catalogue above the case bound", () => {
    const many: AttackInput[] = Array.from({ length: ADVERSARIAL_BOUNDS.maxCases + 1 }, (_v, i) => ({
      attackId: `a${i}`,
      category: "authority_inflation" as const,
      description: "d",
      run: () => ({ bypassed: false, observed: "o" }),
    }));
    expect(() => runAdversarialSuite(many)).toThrow();
  });
});

// ── 5. the catalogue is real, not a mock ─────────────────────────────────────

describe("28I — the attacks are real", () => {
  const source = readFileSync(CATALOGUE_PATH, "utf8");

  it("imports the real Phase-28 modules rather than stubs", () => {
    for (const module of [
      "getigRepresentation",
      "getigObserverViews",
      "getigTemporalFrames",
      "getigProvenance",
      "getigInspectionRuntime",
      "getigDisclosureGate",
    ]) {
      expect(source).toContain(`from "./${module}.js"`);
    }
  });

  it("builds its fixtures through the real builders, not by hand", () => {
    for (const builder of [
      "buildGetigFrame(",
      "buildGetigObserverView(",
      "buildGetigFrameSequence(",
      "buildGetigExplanationGraph(",
    ]) {
      expect(source).toContain(builder);
    }
  });

  it("declares no self-grading pass — every attack names what it attacked", () => {
    for (const o of outcomes) {
      expect(o.description.length).toBeGreaterThan(10);
      // A descriptive title alone is not enough; the wording must name the
      // property being defended, so a title like "executable material" cannot
      // pass while stating no expectation.
      expect(o.description).toMatch(/must|never|not\b|refuse|remain|stable|disjoint|may not|cannot/i);
    }
  });

  it("contains no mock or simulated validation claim", () => {
    expect(/mock(ed)? (the )?(webgpu|device|gpu)/i.test(source)).toBe(false);
    expect(source).not.toMatch(/simulateHardware|pretendAdapter|fakeDevice/i);
  });

  it("attacks the disclosure gate's real vocabulary rather than invented names", () => {
    // 28I-27 iterates the exported forbidden list, so the catalogue cannot drift
    // from the module it attacks.
    expect(source).toContain("DISCLOSURE_FORBIDDEN_FIELDS");
    expect(source).toContain("INSPECTION_FORBIDDEN_ACTIONS");
  });
});

// ── 6. coverage of the prompt's named attack classes ─────────────────────────

describe("28I — coverage of the prompt's named attack classes", () => {
  it("covers every class the 28I prompt lists", () => {
    const all = outcomes.map((o) => `${o.attackId} ${o.description}`).join(" ").toLowerCase();
    const required: [string, RegExp][] = [
      ["unknown -> trusted", /unknown -> trusted/],
      ["stale -> current", /stale -> current/],
      ["claim -> grant", /claim -> grant/],
      ["observed edge -> admission", /observed edge -> admission/],
      ["route -> authorization", /route -> authorization/],
      ["forwarder -> origin", /forwarder -> origin/],
      ["conflict suppression", /conflict suppression|conflict_suppression/],
      ["local view -> global truth", /local view -> global truth/],
      ["provenance stripping", /provenance stripping/],
      ["visual replay -> execution", /visual replay -> execution/],
      ["timeline tamper", /timeline tamper/],
      ["frame hash mismatch", /frame hash mismatch/],
      ["canonicalization collision", /canonicalization collision/],
      ["terminal resurrection", /terminal resurrection/],
      ["visual selection -> mutation", /visual selection -> mutation/],
      ["inspection action injection", /inspection action injection/],
      ["secret/key leakage", /secret\/key leakage/],
      ["nested raw payload", /nested raw payload/],
      ["memory/store leak", /memory\/store leak/],
      ["executable material", /executable material/],
      ["filtered-view-as-complete", /filtered-view-as-complete/],
      ["renderer-field-as-authority", /renderer-field-as-authority/],
      ["cross-epoch substitution", /cross-epoch substitution/],
      ["observer substitution", /observer substitution/],
      ["fake refusal removal", /fake refusal removal/],
      ["unsupported-as-pass", /unsupported-as-pass|pass must stay reachable|unsupported_as_pass/],
      ["capability union", /capability union/],
      ["authority tamper", /authority\/controlplane\/readonly (tacross|must remain)/],
    ];
    for (const [name, pattern] of required) {
      expect(pattern.test(all), `attack class not covered: ${name}`).toBe(true);
    }
  });
});
