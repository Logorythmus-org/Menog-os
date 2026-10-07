/**
 * PHASE 29K-R1 — FINAL FREEZE EVIDENCE RECONCILIATION — GUARD SUITE
 *
 * Audit-only. This gate changed no renderer, scene, GPU, picking, animation, lifecycle,
 * adversarial or WebGPU execution source, no dependency, and no historical record. It
 * corrected two factual inconsistencies in the CURRENT canonical Phase-29 freeze
 * artifacts, so it needs its own guard: a future freeze regeneration must not be able to
 * repeat either contradiction.
 *
 *   1. dependency truth: the freeze's inventory must match package.json + pnpm-lock.yaml +
 *      node_modules, measured from disk rather than asserted in prose
 *   2. @webgpu/types: authorization, install and verdict must come from the 29R4 record,
 *      and the typings must NOT be described as absent / unauthorized / not added
 *   3. debt identity: 29I-33 (sourceFrameId / label-binding) must never be labelled
 *      29C-OBS-1 (texture readback all zeros); the two are separate observations
 *   4. superseded observations must name their superseding gate: 29C-OBS-1 -> 29R3,
 *      29D-OBS-2 -> 29R1 / 29R2
 *   5. UNSUPPORTED != PASS and INCONCLUSIVE != PASS, still
 *   6. the freeze verdict matches the content, not the filename
 *
 * MOTHER INVARIANT: PIXELS ARE PRESENTATION, NOT AUTHORITY.
 */
import { describe, expect, it } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";

const readJson = (p: string): any => JSON.parse(readFileSync(p, "utf8"));
const sha256 = (p: string): string =>
  createHash("sha256").update(readFileSync(p)).digest("hex");

const K = readJson("docs/release/PHASE29_FINAL_EVIDENCE.json");
const R1 = readJson("docs/release/PHASE29K_R1_RECONCILIATION.json");
const R4 = readJson("docs/release/PHASE29R4_TYPING_DECISION.json");
const I = readJson("docs/release/PHASE29I_EVIDENCE.json");
const R3 = readJson("docs/release/PHASE29R3_TEXTURE_DIAGNOSTIC.json");
const PKG = readJson("package.json");
const FREEZE_MD = readFileSync("docs/release/PHASE_29_FREEZE.md", "utf8");
const REPORT_29K = readFileSync("docs/release/PROMPT_29K_REPORT.md", "utf8");
const REPORT_R1 = readFileSync("docs/release/PROMPT_29K_R1_REPORT.md", "utf8");
const LOCK = readFileSync("pnpm-lock.yaml", "utf8");

const debtText = K.inheritedDebt.join("\n");
const inheritedDebtRow = (id: string): string =>
  K.inheritedDebt.find((d: string) => d.includes(id)) ?? "";

describe("29K-R1-1 the freeze's dependency inventory is the disk's dependency inventory", () => {
  it("package.json and pnpm-lock.yaml hashes are measured, not remembered", () => {
    const dep = K.freshVerification.dependencyAudit;
    expect(sha256("package.json")).toBe(dep.packageJsonSha256);
    expect(sha256("pnpm-lock.yaml")).toBe(dep.lockSha256);
    expect(existsSync("package.json")).toBe(true);
  });

  it("dev/runtime dependency counts in the freeze equal the files", () => {
    const dep = K.freshVerification.dependencyAudit;
    expect(Object.keys(PKG.devDependencies ?? {}).length).toBe(dep.devDeps);
    expect(Object.keys(PKG.dependencies ?? {})).toHaveLength(0);
    expect(dep.runtimeDeps).toBe(0);
  });

  it("the recorded dependency inventory names @webgpu/types as a devDependency", () => {
    const dep = K.freshVerification.dependencyAudit;
    expect(dep.webgpuTypes).toBeTruthy();
    expect(dep.webgpuTypes.package).toBe("@webgpu/types");
    expect(dep.webgpuTypes.inPackageJson).toBe(true);
    expect(dep.webgpuTypes.exactVersion).toBe("0.1.74");
    expect(dep.webgpuTypes.dependencyKind).toBe("devDependency");
    expect(dep.webgpuTypes.runtime).toBe(false);
  });
});

describe("29K-R1-2 @webgpu/types matches the 29R4 evidence, not prose", () => {
  it("29R4 granted authorization, performed the install and passed the typing probe", () => {
    expect(R4.verdict).toBe("29R4_PASS_EXISTING_TYPES");
    expect(R4.authorization.granted).toBe(true);
    expect(R4.installProof.installPerformed).toBe(true);
    expect(R4.installProof.exit).toBe(0);
    expect(R4.installProof.package.exactPin).toBe(true);
    expect(R4.installProof.package.version).toBe("0.1.74");
    expect(R4.verificationRerun.probeB_withDomAndTypes.exit).toBe(0);
    expect(R4.verificationRerun.probeB_withDomAndTypes.errorCount).toBe(0);
    expect(R4.verificationRerun.probeB_withDomAndTypes.command).toContain(
      "--lib es2023,dom",
    );
    expect(R4.verificationRerun.probeB_withDomAndTypes.command).toContain(
      "--types @webgpu/types",
    );
    expect(R4.noRuntimeDependencyProof.packageJsonRuntimeDependencies).toBe("ABSENT");
  });

  it("package.json, the lockfile and the installed tree all agree on 0.1.74", () => {
    expect(PKG.devDependencies["@webgpu/types"]).toBe("0.1.74");
    expect(PKG.dependencies?.["@webgpu/types"]).toBeUndefined();
    expect(LOCK).toContain("'@webgpu/types':");
    expect(LOCK).toContain("'@webgpu/types@0.1.74':");
    expect(readJson("node_modules/@webgpu/types/package.json").version).toBe("0.1.74");
    // 29R4 recorded the same two hashes; a later mutation would break this equality
    expect(R4.installProof.packageJson.sha256).toBe(sha256("package.json"));
    expect(R4.installProof.pnpmLock.sha256).toBe(sha256("pnpm-lock.yaml"));
  });

  it("no artifact claims the typings are absent, unauthorized or not added", () => {
    const wrong = /webgpu\/?types[^.\n]{0,80}(not added|NOT authorized|unauthorized|absent)/i;
    const liveLines = (t: string): string[] =>
      t.split("\n").filter((l) => !/\[superseded text\]/.test(l));
    for (const [where, text] of [
      ["inheritedDebt", debtText],
      ["PHASE_29_FREEZE.md", FREEZE_MD],
      ["PROMPT_29K_REPORT.md", REPORT_29K],
      ["PROMPT_29K_R1_REPORT.md", REPORT_R1],
    ] as [string, string][]) {
      expect(liveLines(text).join("\n"), where).not.toMatch(wrong);
    }
    expect(debtText).not.toMatch(/WebGPU typings remain absent/i);
    expect(FREEZE_MD).not.toMatch(/WebGPU typings[^.\n]{0,40}absent/i);
    // the R1 report quotes the superseded wording only inside an explicitly marked
    // "[superseded text]" cell, so the quotation cannot be mistaken for a live claim
    for (const line of REPORT_R1.split("\n")) {
      if (!/remain absent by design|NOT authorized and was not added/i.test(line)) continue;
      expect(line).toMatch(/\[superseded text\]/);
    }
  });

  it("the freeze states the settled dependency truth explicitly", () => {
    expect(debtText).toMatch(/@webgpu\/types@0\.1\.74/);
    expect(debtText).toMatch(/devDependency/);
    expect(FREEZE_MD).toMatch(/authorized and installed/i);
    expect(FREEZE_MD).toMatch(/29R4_PASS_EXISTING_TYPES/);
    expect(K.reconciliation.dependencyTruth.verdict).toBe("29R4_PASS_EXISTING_TYPES");
    expect(K.reconciliation.dependencyTruth.runtimeDependencies).toBe(0);
    expect(K.reconciliation.dependencyTruth.mutatedDuring29KR1).toBe(false);
  });

  it("this gate mutated no dependency and the governance claim says so", () => {
    expect(K.governance.dependencyLaw).toMatch(/no dependency (added|changed|removed)/i);
    expect(K.reconciliation.dependencyStateChange).toBe("NONE");
    expect(R1.verdict).toBe("29K_R1_BLOCKED");
    expect(R1.dependencyTruth.mutatedDuring29KR1).toBe(false);
  });
});

describe("29K-R1-3 29I-33 and 29C-OBS-1 are two different debts", () => {
  it("the 29I evidence keeps 29I-33 as the label-binding / sourceFrameId question", () => {
    expect(I.verdictTaxonomy.expectedVerdicts["29I-33-recovery-label-only-tamper"]).toMatch(
      /INCONCLUSIVE/,
    );
    expect(I.verdictTaxonomy.expectedVerdicts["29I-44-wgsl-source-compilation"]).toMatch(
      /UNSUPPORTED/,
    );
    expect(I.honestNote).toMatch(/29I-33: the label-only sourceFrameId tamper surface/);
    const catalogue = readFileSync(
      "packages/durable-state/src/phase29AdversarialCatalogue.ts",
      "utf8",
    );
    const attack = catalogue.slice(
      catalogue.indexOf('attackId: "29I-33-recovery-label-only-tamper"'),
    ).slice(0, 900);
    expect(attack).toMatch(/sourceFrameId/);
    expect(attack).toMatch(/INCONCLUSIVE/);
  });

  it("no artifact labels 29I-33 as the texture-readback observation", () => {
    const mislabels: [string, string][] = [
      ["PHASE29_FINAL_EVIDENCE.json inheritedDebt", debtText],
      ["PHASE_29_FREEZE.md", FREEZE_MD],
      ["PROMPT_29K_REPORT.md", REPORT_29K],
      ["PROMPT_29K_R1_REPORT.md", REPORT_R1],
    ];
    // an explicit disambiguation ("this is NOT 29C-OBS-1") is required, not merely tolerated:
    // any line that names both must also say they are different
    const disambiguates = /\bnot\b|\bnever\b|distinct|separate|different|superseded text/i;
    for (const [where, text] of mislabels) {
      for (const line of text.split("\n")) {
        if (!line.includes("29I-33")) continue;
        if (line.includes("29C-OBS-1")) {
          expect(line, `${where}: names 29I-33 and 29C-OBS-1 without disambiguating`).toMatch(
            disambiguates,
          );
        } else {
          expect(line, where).not.toMatch(/texture[- ]readback|all[- ]zero/i);
        }
      }
    }
    // and the 29I-33 rows positively name the right subject
    const i33row = inheritedDebtRow("29I-33");
    expect(i33row).toMatch(/sourceFrameId/);
    expect(i33row).toMatch(/label-binding/);
    expect(i33row).toMatch(/PROVENANCE/);
  });

  it("the reconciliation table keeps the two identities separate with owners", () => {
    const rows = K.reconciliation.debtIdentityTable;
    const i33 = rows.find((r: any) => r.debt === "29I-33");
    const obs1 = rows.find((r: any) => r.debt === "29C-OBS-1");
    expect(i33.identity).toMatch(/sourceFrameId/);
    expect(i33.identity).toMatch(/label-binding/);
    expect(i33.status).toBe("INCONCLUSIVE");
    expect(i33.evidenceOwner).toBe("29I");
    expect(i33.supersededBy).toBeNull();
    expect(obs1.identity).toMatch(/texture readback/i);
    expect(obs1.status).toMatch(/ROOT-CAUSED/);
    expect(obs1.evidenceOwner).toMatch(/29C/);
    expect(obs1.supersededBy).toBe("29R3");
  });

  it("29I-33 was not silently upgraded: no later evidence re-executes that attack", () => {
    const j = readJson("docs/release/PHASE29J_EVIDENCE.json");
    const jText = JSON.stringify(j);
    expect(jText).not.toMatch(/29I-33/);
    const r3Text = JSON.stringify(R3);
    expect(r3Text).not.toMatch(/29I-33/);
    // 29J's own scope, and 29I's non-PASS set, are asserted by the 29I suite itself
    expect(I.verdictTaxonomy.counts.inconclusive).toBe(1);
    expect(I.verdictTaxonomy.counts.unsupported).toBe(1);
  });
});

describe("29K-R1-4 superseded observations name the gate that settled them", () => {
  it("29C-OBS-1 is root-caused by 29R3, and 29R3 says so from disk", () => {
    expect(R3.verdict).toBe("29R3_HARNESS_DEFECT_FIXED_AND_READBACK_VERIFIED");
    expect(R3.rootCause.established).toBe(true);
    expect(R3.rootCause.class).toMatch(/harness-side/);
    expect(R3.priorObservation.observationId).toBe("29C-OBS-1");
    expect(R3.priorObservation.priorStatus).toMatch(/OPEN/);
    const row = K.reconciliation.debtIdentityTable.find(
      (r: any) => r.debt === "29C-OBS-1",
    );
    expect(row.supersededBy).toBe("29R3");
    expect(debtText).toMatch(/29C-OBS-1[^\n]*29R3/);
  });

  it("29D-OBS-2 is repaired by 29R1 and rebaselined by 29R2", () => {
    const r1 = readJson("docs/release/PHASE29R1_EVIDENCE.json");
    const r2 = readJson("docs/release/PHASE29_RECOVERY_REBASELINE.json");
    expect(r1.verdict).toBe("29R1_PASS");
    expect(r2.verdict).toBe("29R2_PASS");
    expect(r1.postRepairState.relations.every((x: any) => x.bothResolve === true)).toBe(true);
    expect(r1.postRepairState.sceneHashUnchanged).toBe(true);
    const row = K.reconciliation.debtIdentityTable.find(
      (r: any) => r.debt === "29D-OBS-2",
    );
    expect(row.supersededBy).toBe("29R1/29R2");
    expect(debtText).toMatch(/29D-OBS-2[^\n]*29R1/);
  });

  it("neither settled observation is still described as an open unknown", () => {
    const open = /(29C-OBS-1|29D-OBS-2)[^\n]{0,120}(remains OPEN|still OPEN|unknown target limitation)/i;
    expect(open.test(debtText)).toBe(false);
    expect(open.test(FREEZE_MD)).toBe(false);
    expect(open.test(REPORT_R1)).toBe(false);
    // and the pack's entry record, which legitimately recorded them OPEN at its own time,
    // is untouched — history is not rewritten by a later reconciliation
    const entry = readJson("docs/release/PHASE29_RECOVERY_ENTRY_EVIDENCE.json");
    expect(entry.openBlockers.find((b: any) => b.id === "29C-OBS-1").status).toBe("OPEN");
    expect(entry.openBlockers.find((b: any) => b.id === "29D-OBS-2").status).toBe("OPEN");
  });
});

describe("29K-R1-5 UNSUPPORTED and INCONCLUSIVE are still not PASS", () => {
  it("29I-44 and 29I-33 remain non-PASS in the freeze and the 29I record", () => {
    expect(K.freshVerification.adversarial29I.pass).toBe(52);
    expect(K.freshVerification.adversarial29I.unsupported).toBe(1);
    expect(K.freshVerification.adversarial29I.inconclusive).toBe(1);
    expect(K.freshVerification.adversarial29I.fail).toBe(0);
    expect(K.freshVerification.adversarial29I.criticalBypass).toBe(0);
    expect(I.verdictTaxonomy.unsupportedIsPass).toBe(false);
    expect(I.verdictTaxonomy.inconclusiveIsPass).toBe(false);
    expect(debtText).toMatch(/29I-44[^\n]*UNSUPPORTED/);
    expect(debtText).toMatch(/29I-33[^\n]*INCONCLUSIVE/);
  });

  it("29J's real WGSL compilation did not rewrite 29I-44 into PASS", () => {
    const j = readJson("docs/release/PHASE29J_EVIDENCE.json");
    expect(j.verdict).toBe("29J_PASS");
    const jText = JSON.stringify(j);
    expect(jText).not.toMatch(/29I-44[^"]*"PASS"/);
    expect(FREEZE_MD).toMatch(/does \*\*not\*\* convert 29I-44 to PASS/);
    expect(K.freezeDecision.whyNotRule1).toMatch(/29I-44/);
  });

  it("reconciliation is not itself a verdict upgrade", () => {
    expect(R1.allowedVerdicts).toEqual(["29K_R1_RECONCILED_PASS", "29K_R1_BLOCKED"]);
    expect(R1.freezeVerdictBefore).toBe("PHASE29_FROZEN_WITH_NONBLOCKING_DEBT");
    expect(R1.freezeVerdictAfter).toBe("PHASE29_FROZEN_WITH_NONBLOCKING_DEBT");
    expect(R1.freezeVerdictUnchanged).toBe(true);
    expect(R1.phase30AuthorizationGranted).toBe(false);
  });

  it("the integrity incident is disclosed, measured and NOT downgraded", () => {
    const inc = R1.integrityIncident;
    expect(inc).toBeTruthy();
    expect(inc.id).toBe("29K-R1-INCIDENT-1");
    expect(inc.recordsRewritten).toBe(20);
    expect(inc.pinValuesRewritten).toBe(201);
    expect(inc.pinsThatChangedMeaning).toBe(10);
    expect(inc.recoveryAttempted.outcome).toBe("UNRECOVERED");
    expect(inc.violatedConstraints.join(" ")).toMatch(/Phase-20-28/);
    expect(inc.violatedConstraints.join(" ")).toMatch(/historical BLOCKED/);
    expect(inc.violatedConstraints.join(" ")).toMatch(/reinterpret historical/);
    // the Phase-28 baseline record is named explicitly: this is the policy's own BLOCKED condition
    expect(inc.recordsIncludingPhase28Baseline).toEqual([
      "docs/release/PHASE28_FINAL_EVIDENCE.json",
    ]);
    // the incident is also in the canonical record, not only in the side-car JSON
    expect(K.reconciliation.integrityIncident.recordsRewritten).toBe(20);
    expect(K.reconciliation.verdict).toBe("29K_R1_BLOCKED");
    expect(K.inheritedDebt.join(" ")).toMatch(/29K-R1 INTEGRITY INCIDENT/);
    // no pin anywhere in the rewritten records is now FALSE
    expect(inc.whatIsIntact.join(" ")).toMatch(/valid prefixes of their targets, so none is false/);
  });

  it("the freeze document says DISPUTED in its own text, not only in its filename", () => {
    expect(FREEZE_MD).toMatch(/29K_R1_BLOCKED/);
    expect(FREEZE_MD).toMatch(/NOT a verified freeze/);
    expect(FREEZE_MD).toMatch(/DISPUTED, not affirmed/);
    expect(FREEZE_MD).toMatch(/Integrity incident of 29K-R1/);
    expect(FREEZE_MD).toMatch(/does not re-affirm it/);
  });
});

describe("29K-R1-6 content matches filename, and no Phase-30 authority is implied", () => {
  it("the freeze verdict of record is unchanged and stated in the document, but NOT re-affirmed", () => {
    expect(K.verdict).toBe("PHASE29_FROZEN_WITH_NONBLOCKING_DEBT");
    expect(K.verdict).toBe(K.allowedVerdicts[1]);
    expect(K.freezePerformed).toBe(true);
    // the 29K-era verdict is still named in the document ...
    expect(FREEZE_MD).toMatch(/PHASE29_FROZEN_WITH_NONBLOCKING_DEBT/);
    // ... but the reconciliation that follows it is BLOCKED, so it is not affirmed
    expect(FREEZE_MD).toMatch(/Reconciliation verdict: \*\*29K_R1_BLOCKED\*\*/);
    expect(FREEZE_MD).toMatch(/No Phase-30 authorization/);
    expect(FREEZE_MD).toMatch(/NO PHASE-30 AUTHORIZATION GRANTED/);
    expect(K.nextGate).toMatch(/PHASE30_DESIGN \(human authorization required/);
  });

  it("the reconciliation report is explicit about its own limits", () => {
    expect(REPORT_R1).toMatch(/NO PHASE-30 AUTHORIZATION GRANTED/);
    expect(REPORT_R1).toMatch(/29K_R1_BLOCKED/);
    expect(REPORT_R1).toMatch(/PHASE29_FROZEN_WITH_NONBLOCKING_DEBT/);
    expect(REPORT_R1).toMatch(/STOP/);
    expect(REPORT_R1).toMatch(/Integrity incident of 29K-R1/);
    expect(REPORT_R1).toMatch(/What a human should decide/);
    expect(K.reconciliation.mode).toMatch(/EVIDENCE-RECONCILIATION/);
    expect(K.reconciliation.sourceFilesChanged).toBe(0);
  });

  it("the pre-reconciliation freeze text is preserved, not overwritten", () => {
    for (const a of [
      "docs/release/PHASE29_FINAL_EVIDENCE_PRIOR_29K_R1_RECONCILIATION.json",
      "docs/release/PHASE_29_FREEZE_PRIOR_29K_R1_RECONCILIATION.md",
      "docs/release/PROMPT_29K_REPORT_PRIOR_29K_R1_RECONCILIATION.md",
      "docs/release/PHASE29_FINAL_EVIDENCE_PRIOR_29K_REAUDIT.json",
      "docs/release/PHASE29J_EVIDENCE_PRIOR_29J_REEXEC.json",
      "docs/release/PHASE29R4_TYPING_DECISION_PRIOR_AUTHORIZATION.json",
    ]) {
      expect(existsSync(a), a).toBe(true);
    }
    const priorFreeze = readFileSync(
      "docs/release/PHASE_29_FREEZE_PRIOR_29K_R1_RECONCILIATION.md",
      "utf8",
    );
    // the superseded text is still readable exactly as it was written
    expect(priorFreeze).toMatch(/WebGPU typings\*\* remain absent by design/);
  });

  it("every reconciliation pin matches disk", () => {
    for (const a of R1.filesReconciled) {
      if (!a.sha256) continue;
      expect(sha256(a.path), a.path).toBe(a.sha256);
    }
    for (const a of R1.filesNotChanged) {
      expect(existsSync(a), a).toBe(true);
    }
    expect(R1.auditSuite.path).toBe("tests/unit/phase29k-r1-freeze-reconciliation.test.ts");
  });

  it("the record/reconciliation pin cycle is genuinely one-directional", () => {
    // the reconciliation JSON pins the record; the record references the JSON by path only
    expect(R1.filesReconciled.find((a: any) => a.path.endsWith("PHASE29_FINAL_EVIDENCE.json"))).toBeTruthy();
    expect(K.reconciliationRecord.path).toBe("docs/release/PHASE29K_R1_RECONCILIATION.json");
    expect(K.reconciliationRecord.sha256).toBeUndefined();
    expect(K.reconciliationRecord.shaPinOmittedReason).toMatch(/hash cycle/);
    // the record may list the JSON as an artifact, but never with a digest
    const listed = K.artifacts.filter((a: any) =>
      a.path.endsWith("PHASE29K_R1_RECONCILIATION.json"),
    );
    expect(listed.length).toBe(1);
    expect(listed[0].sha256).toBeUndefined();
    expect(listed[0].shaPinOmittedReason).toMatch(/hash cycle/);
  });
});