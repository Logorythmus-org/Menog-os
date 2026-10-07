/**
 * PHASE 28C — frozen-artifact re-verification.
 *
 * Re-hashes every pinned artifact recorded at the PRE28-R0 entry gate against
 * what is on disk now, so "frozen artifacts are byte-identical" is a measurement
 * rather than a memory.
 *
 * The baseline records its artifacts in THREE differently-shaped groups, and a
 * checker that only understands one of them under-reports and looks clean. All
 * three are walked here:
 *
 *   · frozen_artifact_integrity.results
 *       { "<path>": { recorded, observed, result } }                      — 17
 *   · phase27_artifacts_present_hashed_as_phase28_entry_baseline
 *       { "<path>": { bytes, sha256_16 } }                                — 49
 *       split across documentation / source_modules / test_suites /
 *       newly_pinned_phase27_artifacts
 *
 * It fails loudly in the ways that have bitten this project before:
 *   · baseline missing or unparseable -> throw, never "0 checked"
 *   · a pinned artifact missing on disk -> counted and reported
 *   · any group resolves to zero entries -> throw, because an empty group reads
 *     as a clean sweep when it is actually a broken reader
 *   · a baseline row without a usable path or hash -> throw
 */
import { readFileSync, existsSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";

const ROOT = process.cwd();
const EVIDENCE = join(ROOT, "docs", "release", "PHASE28_ENTRY_EVIDENCE.json");

if (!existsSync(EVIDENCE)) throw new Error(`frozen baseline is unreadable: ${EVIDENCE}`);
const evidence = JSON.parse(readFileSync(EVIDENCE, "utf8"));

const sha256 = (abs) => createHash("sha256").update(readFileSync(abs)).digest("hex");

const pinned = new Map(); // path -> { expected, bytes?, group }

const absorb = (group, rows, pathOf, hashOf, bytesOf) => {
  if (rows === null || typeof rows !== "object") {
    throw new Error(`baseline group "${group}" is missing or not an object — refusing to report a clean sweep`);
  }
  const entries = Object.entries(rows);
  if (entries.length === 0) throw new Error(`baseline group "${group}" is empty — a broken reader would look like a clean sweep`);
  for (const [key, row] of entries) {
    const rel = pathOf(key, row);
    const expected = hashOf(row);
    if (typeof rel !== "string" || typeof expected !== "string") {
      throw new Error(`baseline row in "${group}" has no usable path/hash: ${JSON.stringify([key, row])}`);
    }
    if (pinned.has(rel)) throw new Error(`artifact pinned twice with possibly different hashes: ${rel}`);
    pinned.set(rel, { expected, bytes: bytesOf(row), group });
  }
  return entries.length;
};

const integrity = evidence.frozen_artifact_integrity;
if (!integrity) throw new Error("baseline carries no frozen_artifact_integrity block");
const n1 = absorb(
  "frozen_artifact_integrity.results",
  integrity.results,
  (key) => key,
  (row) => row.recorded,
  () => undefined,
);

const baseline = evidence.phase27_artifacts_present_hashed_as_phase28_entry_baseline;
if (!baseline) throw new Error("baseline carries no phase27_artifacts_present_hashed_as_phase28_entry_baseline block");
// `newly_pinned_phase27_artifacts` is itself a nested block (a `note` string plus
// the same three sub-groups). Skipping one nesting level would silently drop 15
// pinned artifacts while still reporting a clean sweep — which is precisely the
// shape of failure this script exists to prevent, so it is walked at depth.
const absorbBaselineBlock = (block, prefix) => {
  let n = 0;
  for (const group of ["documentation", "source_modules", "test_suites"]) {
    n += absorb(`${prefix}.${group}`, block[group], (key) => key, (row) => row.sha256_16, (row) => row.bytes);
  }
  return n;
};

let n2 = absorbBaselineBlock(baseline, "phase27_baseline");
n2 += absorbBaselineBlock(baseline.newly_pinned_phase27_artifacts, "phase27_baseline.newly_pinned");

let matched = 0;
const drifted = [];
const missing = [];

for (const [rel, { expected, bytes, group }] of pinned) {
  const abs = join(ROOT, rel);
  if (!existsSync(abs)) {
    missing.push(`${rel} (${group})`);
    continue;
  }
  const actualFull = sha256(abs);
  const actualBytes = statSync(abs).size;
  const actual = actualFull.slice(0, expected.length);
  const bytesOk = bytes === undefined || bytes === actualBytes;
  if (actual === expected && bytesOk) matched += 1;
  else drifted.push({ rel, group, expected, actual, bytes, actualBytes });
}

console.log(`group A frozen_artifact_integrity.results        : ${n1}`);
console.log(`group B phase27 entry baseline (4 sub-groups)    : ${n2}`);
console.log(`total pinned artifacts                          : ${pinned.size}`);
console.log(`baseline declared checked                       : ${integrity.pinned_artifacts_checked}`);
console.log(`byte-identical now                              : ${matched}`);
console.log(`missing                                         : ${missing.length}`);
for (const m of missing) console.log(`   MISSING ${m}`);
console.log(`drifted                                         : ${drifted.length}`);
for (const d of drifted) {
  console.log(`   DRIFT ${d.rel} [${d.group}] recorded ${d.expected} (${d.bytes ?? "?"} B) vs actual ${d.actual} (${d.actualBytes} B)`);
}

if (matched !== pinned.size) {
  console.error(`\nFROZEN INTEGRITY: FAIL (${matched}/${pinned.size} byte-identical)`);
  process.exit(1);
}
console.log(`\nFROZEN INTEGRITY: PASS (${matched}/${pinned.size} byte-identical)`);