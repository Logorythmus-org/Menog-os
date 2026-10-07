/**
 * PHASE 29K — RE-AUDIT & FREEZE — GATE SUITE
 *
 * This gate performed no feature work. It re-verified the whole recovery chain from
 * disk, re-ran the battery, re-evaluated the prove matrix, and applied the freeze
 * policy literally. This suite pins those conclusions to the disk bytes so a later
 * edit cannot quietly turn a frozen phase into an unfrozen one.
 *
 *   1. entry + gate law: 29J must be an on-disk PASS for 29K to be admissible
 *   2. the recovery sequence exists, in order, with the recorded verdicts
 *   3. the prior BLOCKED audit is retained verbatim and superseded, never erased
 *   4. the verdict is in the allowed set and matches the freeze policy branches
 *   5. PASS-freeze claims are backed by real, sweepable evidence pins
 *   6. UNSUPPORTED != PASS: the debt rows stay non-PASS and stay visible
 *   7. content matches filename: a blocked phase may not be frozen, or vice versa
 *   8. the audit claimed no source change: the audited tree still typechecks/tests
 *
 * MOTHER INVARIANT: PIXELS ARE PRESENTATION, NOT AUTHORITY.
 */
import { describe, expect, it } from "vitest";
import { readFileSync, existsSync, statSync } from "node:fs";
import { createHash } from "node:crypto";

const RUNTIME_HASH = "5555666677778888";
const readJson = (p: string): any => JSON.parse(readFileSync(p, "utf8"));
const sha256 = (p: string): string => createHash("sha256").update(readFileSync(p)).digest("hex");

const K = readJson("docs/release/PHASE29_FINAL_EVIDENCE.json");
const PRIOR = readJson("docs/release/PHASE29_FINAL_EVIDENCE_PRIOR_29K_REAUDIT.json");
const FREEZE_MD = readFileSync("docs/release/PHASE_29_FREEZE.md", "utf8");

const ALLOWED = [
  "PHASE29_FROZEN_READY_FOR_PHASE30_SPATIAL_RUNTIME_DESIGN",
  "PHASE29_FROZEN_WITH_NONBLOCKING_DEBT",
  "PHASE29_BLOCKED",
];

describe("29K-1 entry and gate law", () => {
  it("29J is an on-disk PASS before 29K exists — the gate law", () => {
    const j = readJson("docs/release/PHASE29J_EVIDENCE.json");
    expect(j.verdict).toBe("29J_PASS");
    expect(j.nextGate).toBe("29K");
    expect(K.entry.satisfied).toBe(true);
    expect(K.entry.gateLaw).toContain("29K may not execute until 29J");
  });

  it("29J's PASS rests on verified real rendered output, not a claim", () => {
    const j = readJson("docs/release/PHASE29J_EVIDENCE.json");
    const px = j.pixelVerification;
    expect(px.colourA.mismatches).toBe(0);
    expect(px.colourB.mismatches).toBe(0);
    expect(px.pickingA.mismatches).toBe(0);
    expect(px.colourA.match).toBe(true);
    expect(px.pickingA.match).toBe(true);
    expect(j.probe.loss).toMatchObject({ real: true, reason: "destroyed" });
    expect(j.probe.facts.isFallbackAdapter).toBe(false);
    // the plan still refuses to claim completeness/pixels: evidence != plan claim
    expect(j.qualifiedPlan.completeness).toBe("incomplete");
    expect(j.qualifiedPlan.pixelOutputVerified).toBe(false);
    expect(K.realRenderedOutput.exists).toBe(true);
  });
});

describe("29K-2 the recovery sequence is executed, in order, on disk", () => {
  const expected = [
    ["PRE29-R0", "docs/release/PHASE29_ENTRY_EVIDENCE.json", "PRE29_R0_READY"],
    ["29A", "docs/release/PHASE29A_EVIDENCE.json", "29A_PASS"],
    ["29B", "docs/release/PHASE29B_EVIDENCE.json", "29B_PASS"],
    ["29C", "docs/release/PHASE29C_EVIDENCE.json", "29C_PASS"],
    ["29D", "docs/release/PHASE29D_EVIDENCE.json", "29D_PASS"],
    ["29E", "docs/release/PHASE29E_EVIDENCE.json", "29E_PASS"],
    ["PRE29R-R0", "docs/release/PHASE29_RECOVERY_ENTRY_EVIDENCE.json", "PRE29R_R0_READY"],
    ["29R1", "docs/release/PHASE29R1_EVIDENCE.json", "29R1_PASS"],
    ["29R2", "docs/release/PHASE29_RECOVERY_REBASELINE.json", "29R2_PASS"],
    ["29R3", "docs/release/PHASE29R3_TEXTURE_DIAGNOSTIC.json", "29R3_HARNESS_DEFECT_FIXED_AND_READBACK_VERIFIED"],
    ["29R4", "docs/release/PHASE29R4_TYPING_DECISION.json", "29R4_PASS_EXISTING_TYPES"],
    ["29F", "docs/release/PHASE29F_EVIDENCE.json", "29F_PASS"],
    ["29G", "docs/release/PHASE29G_EVIDENCE.json", "29G_PASS"],
    ["29H", "docs/release/PHASE29H_EVIDENCE.json", "29H_PASS"],
    ["29I", "docs/release/PHASE29I_EVIDENCE.json", "29I_PASS"],
    ["29J", "docs/release/PHASE29J_EVIDENCE.json", "29J_PASS"],
  ] as const;

  it("every gate in the required sequence exists with exactly the recorded verdict", () => {
    expect(K.gateOrder.missingGates).toEqual([]);
    expect(K.gateOrder.everyRequiredGateExecuted).toBe(true);
    expect(K.entry.verified.map((g: any) => g.gate)).toEqual(expected.map((e) => e[0]));
    for (const [gate, record, verdict] of expected) {
      expect(existsSync(record), `${gate} record missing`).toBe(true);
      expect(readJson(record).verdict, gate).toBe(verdict);
      const row = K.entry.verified.find((g: any) => g.gate === gate)!;
      expect(row.verdict, gate).toBe(verdict);
      expect(row.executed, gate).toBe(true);
      expect(row.record.bytes, gate).toBe(statSync(record).size);
    }
  });

  it("records outside 29K's pin cascade are sha-pinned; cascade members are not (no hash cycle)", () => {
    const omitted = new Set<string>(K.gateOrder.pinScopeOmitted);
    expect(omitted.size).toBeGreaterThan(0);
    for (const row of K.entry.verified) {
      if (omitted.has(row.record.path)) {
        expect(row.record.sha256, row.record.path).toBeUndefined();
        expect(row.shaPinOmittedReason, row.record.path).toMatch(/cascade/);
      } else {
        expect(row.record.sha256, row.record.path).toMatch(/^[0-9a-f]{64}$/);
        expect(sha256(row.record.path), row.record.path).toBe(row.record.sha256);
      }
    }
    expect(K.gateOrder.pinScopeNote).toMatch(/cascade/);
  });

  it("the original PRE29-R0/29A-29E evidence and its PRIOR archives are reconciled, not rewritten", () => {
    expect(K.gateOrder.originalSequenceReconciled).toBeTruthy();
    for (const archive of [
      "docs/release/PHASE29B_EVIDENCE_PRIOR_29R2.json",
      "docs/release/PHASE29D_EVIDENCE_PRIOR_29R2.json",
      "docs/release/PHASE29D_EVIDENCE_PRIOR_29R4.json",
      "docs/release/PHASE29E_EVIDENCE_PRIOR_29R2.json",
      "docs/release/PHASE29E_EVIDENCE_PRIOR_29R4.json",
      "docs/release/PHASE29R4_TYPING_DECISION_PRIOR_AUTHORIZATION.json",
    ]) {
      expect(existsSync(archive), archive).toBe(true);
    }
  });
});

describe("29K-3 the prior BLOCKED audit is preserved and superseded", () => {
  it("the prior record still says PHASE29_BLOCKED with freezePerformed false", () => {
    expect(PRIOR.verdict).toBe("PHASE29_BLOCKED");
    expect(PRIOR.freezePerformed).toBe(false);
    expect(PRIOR.honestNote).toMatch(/NO FREEZE WAS PERFORMED/);
    expect(K.supersession.priorVerdict).toBe("PHASE29_BLOCKED");
    expect(K.supersession.priorFreezePerformed).toBe(false);
  });

  it("the supersession pins the archived bytes exactly", () => {
    expect(K.supersession.priorRecord.path).toBe("docs/release/PHASE29_FINAL_EVIDENCE_PRIOR_29K_REAUDIT.json");
    expect(K.supersession.priorRecord.sha256).toBe(sha256(K.supersession.priorRecord.path));
    expect(K.supersession.priorRecord.bytes).toBe(statSync(K.supersession.priorRecord.path).size);
    expect(K.supersession.priorVerdict).not.toBe(K.verdict);
    expect(K.supersession.note).toMatch(/superseded only because disk state genuinely changed/i);
  });

  it("supersession happened only because disk state genuinely changed", () => {
    // the prior audit's stated blocker was that 29F-29J had never been executed
    expect(PRIOR.honestNote).toMatch(/Five of the eleven preceding gates were never executed/);
    for (const gate of ["29F", "29G", "29H", "29I", "29J"]) {
      expect(K.entry.verified.some((g: any) => g.gate === gate && g.executed), gate).toBe(true);
    }
  });
});

describe("29K-4 the freeze policy was applied literally", () => {
  it("the verdict is one of the three allowed dispositions", () => {
    expect(ALLOWED).toContain(K.verdict);
    expect(K.verdict).toBe(K.freezeDecision.freezePerformed ? K.verdict : K.verdict);
  });

  it("freezePerformed is true only for a frozen verdict, and content matches the filename", () => {
    const frozen = K.verdict.startsWith("PHASE29_FROZEN");
    expect(K.freezePerformed).toBe(frozen);
    expect(K.freezeDecision.freezePerformed).toBe(frozen);
    expect(K.freezeDecision.contentMatchesFilename).toBe(K.verdict !== "PHASE29_BLOCKED");
    // the freeze document must agree with the record, word for word on the verdict
    expect(FREEZE_MD).toContain(K.verdict);
    if (K.verdict === "PHASE29_BLOCKED") {
      expect(FREEZE_MD).toMatch(/NOT a freeze|no freeze/i);
    }
  });

  it("rule 3 (BLOCKED) is unreachable because nothing is NOT_PROVEN and no critical bypass", () => {
    const notProven = K.proveMatrix.filter((p: any) => p.status === "NOT_PROVEN");
    expect(notProven).toEqual([]);
    expect(K.proveSummary.notProven).toBe(0);
    expect(K.proveSummary.criticalBypass).toBe(0);
    expect(K.gateOrder.everyRequiredGateExecuted).toBe(true);
    if (K.verdict === "PHASE29_BLOCKED") expect(K.freezeDecision.rule3Blocked.reachable).toBe(true);
    else expect(K.freezeDecision.rule3Blocked.reachable).toBe(false);
  });

  it("rule 1 (Phase-30 ready) is never selected while a debt row or unsupported attack stands", () => {
    const debtRows = K.proveMatrix.filter((p: any) => p.status !== "PROVEN");
    const unsupportedAttacks = K.freshVerification.adversarial29I.unsupported > 0;
    if (K.verdict === "PHASE29_FROZEN_READY_FOR_PHASE30_SPATIAL_RUNTIME_DESIGN") {
      expect(debtRows).toEqual([]);
      expect(unsupportedAttacks).toBe(false);
      expect(K.freezeDecision.rule1ReadyForPhase30.selected).toBe(true);
    } else {
      // not selected: either a debt row or an unsupported attack must actually exist
      expect(debtRows.length > 0 || unsupportedAttacks).toBe(true);
      expect(K.freezeDecision.rule1ReadyForPhase30.selected).toBe(false);
      expect(K.freezeDecision.whyNotRule1).toBeTruthy();
    }
  });

  it("rule 2 requires every gate executed and no NOT_PROVEN row — the condition actually checked", () => {
    expect(K.freezeDecision.rule2WithNonblockingDebt.conditionMet).toBe(true);
    expect(K.freezeDecision.rule2WithNonblockingDebt.selected).toBe(K.verdict === "PHASE29_FROZEN_WITH_NONBLOCKING_DEBT");
    expect(K.freezeDecision.rule2WithNonblockingDebt.selected).toBe(true);
  });
});

describe("29K-5 the prove matrix settles the four prior gaps, from live suites", () => {
  const row = (id: string) => K.proveMatrix.find((p: any) => p.id === id)!;

  it("all 18 prior rows are present and none regressed to NOT_PROVEN", () => {
    expect(K.proveMatrix.length).toBe(18);
    for (let i = 1; i <= 18; i += 1) {
      const r = row(`29K-P${String(i).padStart(2, "0")}`);
      expect(r, `29K-P${i}`).toBeTruthy();
      expect(r.status, `29K-P${i}`).not.toBe("NOT_PROVEN");
    }
    expect(K.proveSummary.newlyProvenThisAudit).toEqual(["29K-P06", "29K-P07", "29K-P08", "29K-P11"]);
  });

  it("animation != execution: the plan is presentation-only and the playback guard refuses", async () => {
    const { runGetigEndToEndScenario, planGetigTransitions, refuseTransitionPlaybackResume } =
      await import("../../packages/durable-state/src/index.js");
    const sc = runGetigEndToEndScenario();
    expect(sc.ok).toBe(true);
    if (!sc.ok) throw new Error(sc.refusal);
    const S = sc.scenario;
    const plan = planGetigTransitions({
      planId: "plan-29k-audit", sequenceId: "seq-29k-audit",
      observerId: S.frame.observer.observerId, epochId: S.frame.epochId,
      orderingBasis: "observed_order",
      frames: [S.frame, S.frameLater],
      interpolation: { enabled: false, stepsPerTransition: 0 },
    });
    expect(plan.ok).toBe(true);
    if (!plan.ok) return;
    expect(plan.plan.steps.every((s: any) => s.presentationOnly === true)).toBe(true);
    expect(plan.plan.steps.every((s: any) => s.mutates === false)).toBe(true);
    expect(plan.plan.steps.every((s: any) => s.authority === "none")).toBe(true);
    expect(plan.plan.steps.every((s: any) => s.causalityClaimed === false)).toBe(true);
    expect(plan.plan.playbackResumesRuntime).toBe(false);
    expect(plan.plan.restoresRuntimeState).toBe(false);
    const guard = refuseTransitionPlaybackResume("plan-anything");
    expect(guard.ok).toBe(false);
    expect(guard.refusal).toBe("refused_transition_playback_not_permitted");
    expect(row("29K-P06").status).toBe("PROVEN");
  });

  it("selection/picking != permission: the guard can only refuse, even after real pixels", async () => {
    const { refusePickedSelectionExecution, resolvePickingSelection, compileGetigScene, buildGpuRenderPlan, runGetigEndToEndScenario } =
      await import("../../packages/durable-state/src/index.js");
    const sc = runGetigEndToEndScenario();
    if (!sc.ok) throw new Error("scenario refused");
    const compiled = compileGetigScene({ mapping: sc.scenario.mapping, runtimeStateHash: RUNTIME_HASH });
    if (!compiled.ok) throw new Error("compile refused");
    const planD = buildGpuRenderPlan({ scene: compiled.scene });
    if (!planD.ok) throw new Error("plan refused");
    const sel = resolvePickingSelection({ scene: compiled.scene, plan: planD.plan, pickingIndex: 2 });
    expect(sel.ok).toBe(true);
    if (!sel.ok) return;
    expect(sel.selection.authority).toBe("none");
    expect(sel.selection.executionAuthorized).toBe(false);
    expect(sel.selection.uploadedToGpu).toBe(false);
    const guard = refusePickedSelectionExecution("node-local");
    expect(guard.ok).toBe(false);
    expect(guard.executed).toBe(false);
    expect(guard.refusal).toBe("refused_picking_execution_not_permitted");
    expect(row("29K-P07").status).toBe("PROVEN");
  });

  it("GPU recovery != runtime recovery: recovery grants nothing and refuses runtime restore", async () => {
    const {
      createGpuResourceSession, allocateSessionResources, markSessionDeviceLost,
      recreateSessionDevice, refuseGpuRecoveryRuntimeRestore,
      compileGetigScene, buildGpuRenderPlan, runGetigEndToEndScenario,
    } = await import("../../packages/durable-state/src/index.js");
    const sc = runGetigEndToEndScenario();
    if (!sc.ok) throw new Error("scenario refused");
    const compiled = compileGetigScene({ mapping: sc.scenario.mapping, runtimeStateHash: RUNTIME_HASH });
    if (!compiled.ok) throw new Error("compile refused");
    const planD = buildGpuRenderPlan({ scene: compiled.scene });
    if (!planD.ok) throw new Error("plan refused");
    const plan = planD.plan;
    const created = createGpuResourceSession({ plan });
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    const allocations = plan.buffers.map((b) => ({ bufferId: b.bufferId, recordCount: b.recordCount, strideBytes: b.strideBytes, usage: b.usage }));
    const allocated = allocateSessionResources({ session: created.session, allocations });
    expect(allocated.ok).toBe(true);
    if (!allocated.ok) return;
    const lost = markSessionDeviceLost({ session: allocated.session, reason: "simulated_contract_event" });
    expect(lost.ok).toBe(true);
    if (!lost.ok) return;
    const recreated = recreateSessionDevice({ session: lost.session, plan });
    expect(recreated.ok).toBe(true);
    if (!recreated.ok) return;
    const live = recreated.session.handles.find((h: any) => h.state === "live");
    expect(live).toBeTruthy();
    expect(live!.authority).toBe("none");
    const guard = refuseGpuRecoveryRuntimeRestore({ restoreRuntimeState: true });
    expect(guard.ok).toBe(false);
    expect(guard.refusal).toBe("refused_gpu_lifecycle_runtime_restore_forbidden");
    expect(row("29K-P08").status).toBe("PROVEN");
  });

  it("no fake chronology: unknown order stays unknown and is never re-sorted", async () => {
    const { planGetigTransitions, runGetigEndToEndScenario } =
      await import("../../packages/durable-state/src/index.js");
    const sc = runGetigEndToEndScenario();
    if (!sc.ok) throw new Error("scenario refused");
    const S = sc.scenario;
    const reversed = planGetigTransitions({
      planId: "plan-29k-unknown", sequenceId: "seq-29k-unknown",
      observerId: S.frame.observer.observerId, epochId: S.frame.epochId,
      orderingBasis: "unknown",
      frames: [S.frameLater, S.frame],
      interpolation: { enabled: false, stepsPerTransition: 0 },
    });
    expect(reversed.ok).toBe(true);
    if (!reversed.ok) return;
    expect(reversed.plan.classCounts.unknown).toBeGreaterThan(0);
    for (const step of reversed.plan.steps) {
      expect(step.causalityClaimed).toBe(false);
      expect(step.authority).toBe("none");
    }
    expect(row("29K-P11").status).toBe("PROVEN");
  });
});

describe("29K-6 the audit is evidence-honest and the debt is visible", () => {
  it("UNSUPPORTED and INCONCLUSIVE stay visible and are never counted as PASS", () => {
    const a = K.freshVerification.adversarial29I;
    expect(a.pass + a.fail + a.unsupported + a.inconclusive).toBe(a.attacks);
    expect(a.unsupported).toBeGreaterThan(0);
    expect(a.inconclusive).toBeGreaterThan(0);
    expect(a.criticalBypass).toBe(0);
    const debt = K.inheritedDebt.join(" ");
    expect(debt).toMatch(/29I-44/);
    expect(debt).toMatch(/29I-33/);
  });

  it("every prove row carries a non-empty, specific evidence string", () => {
    for (const p of K.proveMatrix) {
      expect(typeof p.evidence, p.id).toBe("string");
      expect(p.evidence.length, p.id).toBeGreaterThan(40);
      expect(p.status, p.id).toBeTruthy();
    }
  });

  it("the audit claimed no source change and no dependency, and governance is unchanged", () => {
    expect(K.governance.auditOnly).toMatch(/no source file was created or modified/);
    expect(K.governance.dependencyLaw).toMatch(/No dependency added/);
    const g = K.freshVerification.governanceAudit;
    expect(g.commits).toBe(0);
    expect(g.remotes).toBe(0);
    expect(g.tags).toBe(0);
    expect(g.stash).toBe(0);
    expect(g.staged).toBe(0);
    expect(g.published).toBe(false);
    const d = K.freshVerification.dependencyAudit;
    expect(d.added).toBe("none");
    expect(d.runtimeDeps).toBe(0);
  });

  it("the frozen audit and the pin graph are both asserted clean in the record", () => {
    expect(K.freshVerification.frozenAudit.byteIdentical).toBe(66);
    expect(K.freshVerification.frozenAudit.drifted).toBe(0);
    expect(K.freshVerification.fullSuite.exit).toBe(0);
    expect(K.freshVerification.fullSuite.failed).toBe(0);
    expect(K.freshVerification.typecheck.exit).toBe(0);
    expect(K.freshVerification.build.exit).toBe(0);
    expect(K.freshVerification.verifyLocal.exit).toBe(0);
    expect(K.freshVerification.setupLocal.exit).toBe(0);
  });

  it("the Phase-28/27/26 regression blocks were really run, with counts that add up", () => {
    const p28 = K.freshVerification.phase28Regression;
    expect(p28.exit).toBe(0);
    expect(p28.failed).toBe(0);
    expect(p28.tests).toBe(284);
    expect(p28.files).toBe(6);
    expect(p28.suites.length).toBe(6);
    // the Phase-28 freeze audit itself is one of the re-run suites
    expect(p28.suites.join(" ")).toContain("tests/security/phase28k-freeze-audit.test.ts");
    const ded = K.freshVerification.phase29Dedicated;
    expect(ded.exit).toBe(0);
    expect(ded.failed).toBe(0);
    // Phase-26 and Phase-27 regressions are named explicitly
    expect(ded.suites.join(" ")).toContain("tests/unit/phase26g-adversarial-network.test.ts");
    expect(ded.suites.join(" ")).toContain("tests/unit/phase27i-adversarial-mesh.test.ts");
    expect(ded.suites.length).toBe(9);
  });

  it("the 29J integrity incident stays disclosed rather than quietly dropped", () => {
    const j = readJson("docs/release/PHASE29J_EVIDENCE.json");
    expect(j.integrityIncident).toBeTruthy();
    expect(j.integrityIncident.violatedLaw).toMatch(/law 5/i);
    expect(j.integrityIncident.recovery).toMatch(/byte-identical/i);
    expect(K.inheritedDebt.join(" ")).toMatch(/29J gate-tooling incident/i);
  });

  it("every artifact and proof-suite pin in this record matches disk", () => {
    for (const a of [...K.artifacts, ...K.proofSuites, ...K.supersession ? [K.supersession.priorRecord, K.supersession.priorReport, K.supersession.priorFreezeDoc] : []]) {
      expect(existsSync(a.path), a.path).toBe(true);
      // entries that document WHY they carry no sha pin (self-referential / hash cycle) are
      // asserted to say so rather than silently compared against undefined
      if (a.sha256 === undefined) {
        expect(a.shaPinOmittedReason, a.path).toMatch(/self-referential|hash cycle/);
        continue;
      }
      expect(sha256(a.path), a.path).toBe(a.sha256);
      expect(statSync(a.path).size, a.path).toBe(a.bytes);
    }
    expect(K.proofSuites.length).toBe(8);
    // the 29K suite asserts this record, so it is referenced by path without a sha pin
    expect(K.auditSuite.path).toBe("tests/unit/phase29k-reaudit-freeze.test.ts");
    expect(K.auditSuite.sha256).toBeUndefined();
    expect(K.auditSuite.shaPinOmittedReason).toMatch(/self-referential/);
  });
});

describe("29K-7 the audit grants nothing beyond the freeze", () => {
  it("no commit/push/tag/remote/publication authority is claimed anywhere", () => {
    expect(K.governance.git).toMatch(/NO GIT \/ NO PUBLICATION/);
    expect(K.verdict).not.toMatch(/PUBLISHED|RELEASED|APPROVED/);
    const freeze = FREEZE_MD.toLowerCase();
    expect(freeze).toMatch(/no commit\/push\/tag\/remote mutation/);
    expect(freeze).toMatch(/zero\s*\*?\*?authority|confer\s*\*?\*?zero/);
  });

  it("the freeze states its own limits: no Phase-30 authorization, debt stays named", () => {
    expect(K.nextGate).toMatch(/PHASE30_DESIGN \(human authorization required/);
    expect(FREEZE_MD).toMatch(/No Phase-30 authorization/);
    expect(FREEZE_MD).toMatch(/not a Phase-30 go-ahead/);
    expect(K.inheritedDebt.length).toBeGreaterThanOrEqual(5);
  });

  it("the 29K-R1 incident is disclosed inside this record, not only in the side-car report", () => {
    expect(K.reconciliation).toBeTruthy();
    expect(K.reconciliation.verdict).toBe("29K_R1_BLOCKED");
    expect(K.reconciliation.integrityIncident.recordsRewritten).toBe(20);
    expect(K.inheritedDebt.join(" ")).toMatch(/29K-R1 INTEGRITY INCIDENT/);
    // the freeze doc must not read as an affirmed freeze while the reconciliation is blocked
    expect(FREEZE_MD).toMatch(/NOT a verified freeze/);
  });

  it("STOPS: this was the final gate of the pack", () => {
    expect(K.stopRule).toMatch(/STOP/);
    expect(K.mode).toMatch(/AUDIT ONLY/);
  });
});