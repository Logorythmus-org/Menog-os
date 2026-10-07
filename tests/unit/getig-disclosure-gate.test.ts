/**
 * PHASE 28H — PRIVACY, REDACTION & VISIBLE-WORLD DISCLOSURE BOUNDARY
 *
 * Security tests. The prompt requires specifically: unknown fields default-deny,
 * nested smuggling must be tested, forbidden material must never be truncated
 * into apparently-safe semantics, the manifest must bind to the output frame,
 * and a refusal must return no partial frame.
 *
 * Every test here is adversarial: it supplies material the gate must refuse and
 * asserts the refusal is TOTAL (frame === null), not partial.
 */

import { describe, it, expect } from "vitest";

import {
  disclose,
  DISCLOSURE_CLASSES,
  DISCLOSURE_FORBIDDEN_FIELDS,
  DISCLOSURE_REFUSAL_CODES,
  DISCLOSURE_BOUNDS,
  DISCLOSURE_SCHEMA_VERSION,
  type GetigDisclosureDiscloseInput,
} from "../../packages/durable-state/src/getigDisclosureGate.js";

// The binding hash must have the shape of a content digest; `vh-1` is not one,
// and the gate now refuses it rather than accepting a claim it cannot check.
const BIND = { frameId: "frame-1", observerId: "obs-a", canonicalVisibleHash: "abcdef0123456789" };

const gate = (records: unknown, extra: Record<string, unknown> = {}) =>
  disclose({ ...BIND, records, ...extra } as GetigDisclosureDiscloseInput);

/** A record of plainly sanctioned fields — the positive control. */
const SAFE = {
  subjectVisibleId: "n1",
  lifecycle: "observed",
  freshness: "current",
  knowledge: "known",
  factCount: 1,
  isBarred: false,
};

// ── 1. the positive control ──────────────────────────────────────────────────

describe("28H — sanctioned material crosses the gate", () => {
  it("discloses a record of only-sanctioned fields", () => {
    const decision = gate([SAFE]);
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.frame.records).toHaveLength(1);
      expect(decision.frame.records[0]?.fields.subjectVisibleId).toBe("n1");
      expect(decision.partialFrameEmitted).toBe(false);
    }
  });

  it("reports no authority and read-only on the disclosed frame", () => {
    const decision = gate([SAFE]);
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.frame.authority).toBe("none");
      expect(decision.frame.readOnly).toBe(true);
      expect(decision.frame.disclosesRawContent).toBe(false);
      expect(decision.frame.disclosesPolicyText).toBe(false);
      expect(decision.frame.redacted).toBe(false);
    }
  });

  it("uses the declared schema version", () => {
    const decision = gate([SAFE]);
    expect(decision.ok).toBe(true);
    if (decision.ok) expect(decision.frame.schemaVersion).toBe(DISCLOSURE_SCHEMA_VERSION);
  });

  it("discloses nothing when there are no records", () => {
    const decision = gate([]);
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.frame.recordCount).toBe(0);
      expect(decision.frame.fieldCount).toBe(0);
    }
  });

  it("is deterministic — the same input yields the same hashes", () => {
    const a = gate([SAFE]);
    const b = gate([SAFE]);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    if (a.ok && b.ok) {
      expect(a.frame.disclosureFrameHash).toBe(b.frame.disclosureFrameHash);
      expect(a.frame.manifest.manifestHash).toBe(b.frame.manifest.manifestHash);
    }
  });
});

// ── 2. forbidden material is refused, never redacted ─────────────────────────

describe("28H — forbidden material", () => {
  it("refuses every declared forbidden field name", () => {
    for (const field of DISCLOSURE_FORBIDDEN_FIELDS) {
      const decision = gate([{ ...SAFE, [field]: "x" }]);
      expect(decision.ok, `field ${field} was disclosed`).toBe(false);
      if (!decision.ok) {
        expect(decision.frame).toBeNull();
        expect(decision.refusal).toBe("refused_disclosure_forbidden_field");
      }
    }
  });

  it("catches forbidden names whatever their spelling", () => {
    const variants = [
      "privateKey",
      "PRIVATE_KEY",
      "private-key",
      "PrivateKey",
      "p_r_i_v_a_t_e_k_e_y",
    ];
    for (const name of variants) {
      const decision = gate([{ ...SAFE, [name]: "x" }]);
      expect(decision.ok, `variant ${name} was disclosed`).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_forbidden_field");
    }
  });

  it("refuses a real-looking secret in an allowlisted field", () => {
    // The allowlist alone cannot catch this: the field name is sanctioned.
    const attacks: Record<string, string> = {
      fingerprint: "-----BEGIN RSA PRIVATE KEY-----",
      hashRef: "sk-abcdefghijklmnopqrstuvwx",
      subjectVisibleId: "C:\\Users\\someone\\.ssh\\id_rsa",
      frameId: "/home/user/private/notes.txt",
      labelLabelId: "sudo rm -rf /",
    };
    for (const [field, value] of Object.entries(attacks)) {
      const decision = gate([{ ...SAFE, [field]: value }]);
      expect(decision.ok, `secret leaked via ${field}`).toBe(false);
      if (!decision.ok) {
        expect(decision.frame).toBeNull();
        expect(decision.refusal).toBe("refused_disclosure_value_not_sanctioned");
      }
    }
  });

  it("refuses BOTH path separators, not only Windows-style", () => {
    // A Windows-only check lets `/home/user/.ssh/id_rsa` through, which is the
    // likelier shape on a Linux-native runtime. Both must be refused.
    const paths = [
      "C:\\Users\\me\\.ssh\\id_rsa",
      "/home/user/private/notes.txt",
      "/root/.aws/credentials",
      "../../etc/passwd",
      "etc/shadow",
      "\\\\server\\share\\secret",
    ];
    for (const value of paths) {
      const decision = gate([{ ...SAFE, frameId: value }]);
      expect(decision.ok, `path leaked: ${value}`).toBe(false);
      if (!decision.ok) expect(decision.frame).toBeNull();
    }
  });

  it("still accepts a genuine hex fingerprint after tightening the value rules", () => {
    // Guards the carve-out: over-tightening must not reject a sanctioned hash.
    const decision = gate([{ ...SAFE, fingerprint: "0123456789abcdef".repeat(4) }]);
    expect(decision.ok).toBe(true);
  });

  it("never returns a redacted skeleton — refusal is total", () => {
    // The prompt forbids truncating forbidden material into apparently-safe
    // semantics. A "***REDACTED***" field would be exactly that.
    const decision = gate([{ ...SAFE, token: "sk-secret-value" }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.frame).toBeNull();
      expect(decision.manifest).toBeNull();
      expect(decision.partialFrameEmitted).toBe(false);
      const serialised = JSON.stringify(decision);
      expect(serialised).not.toContain("REDACTED");
      expect(serialised).not.toContain("sk-secret-value");
      expect(serialised).not.toContain("n1"); // not even the safe fields
    }
  });

  it("names the offending field so the refusal is actionable", () => {
    const decision = gate([{ ...SAFE, password: "hunter2" }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.offendingField).toBe("password");
  });
});

// ── 3. unknown fields default-deny ───────────────────────────────────────────

describe("28H — unknown fields default-deny", () => {
  it("refuses a field nobody sanctioned", () => {
    for (const field of ["mysteryField", "somethingNew", "widgetCount", "zzz"]) {
      const decision = gate([{ ...SAFE, [field]: "x" }]);
      expect(decision.ok, `unknown field ${field} was disclosed`).toBe(false);
      if (!decision.ok) {
        expect(decision.refusal).toBe("refused_disclosure_unknown_field");
        expect(decision.frame).toBeNull();
      }
    }
  });

  it("distinguishes 'never heard of it' from 'explicitly forbidden'", () => {
    const unknown = gate([{ ...SAFE, brandNewThing: 1 }]);
    const forbidden = gate([{ ...SAFE, privateKey: "x" }]);
    expect(unknown.ok).toBe(false);
    expect(forbidden.ok).toBe(false);
    if (!unknown.ok && !forbidden.ok) {
      expect(unknown.refusal).toBe("refused_disclosure_unknown_field");
      expect(forbidden.refusal).toBe("refused_disclosure_forbidden_field");
    }
  });

  it("refuses a misspelling of a sanctioned field rather than passing it", () => {
    // `lifecyle` is almost `lifecycle`. Default-deny means almost is not enough.
    const decision = gate([{ ...SAFE, lifecyle: "observed" }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_unknown_field");
  });

  it("the allowlist and forbidden list are disjoint", () => {
    const allowed = new Set(DISCLOSURE_CLASSES.map((c) => c.toLowerCase()));
    for (const forbidden of DISCLOSURE_FORBIDDEN_FIELDS) {
      expect(allowed.has(forbidden.toLowerCase())).toBe(false);
    }
  });
});

// ── 4. nested smuggling ──────────────────────────────────────────────────────

describe("28H — nested smuggling", () => {
  it("refuses a forbidden field one level down", () => {
    const decision = gate([{ ...SAFE, meta: { prompt: "system: you are" } }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.refusal).toBe("refused_disclosure_nested_smuggling");
      expect(decision.frame).toBeNull();
    }
  });

  it("refuses smuggling several levels down", () => {
    const deep = { a: { b: { c: { d: { e: { privateKey: "-----BEGIN" } } } } } };
    const decision = gate([{ ...SAFE, meta: deep }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_nested_smuggling");
  });

  it("refuses smuggling hidden inside an array", () => {
    const decision = gate([{ ...SAFE, items: [{ lifecycle: "observed" }, { password: "x" }] }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_nested_smuggling");
  });

  it("refuses an array nested inside an array", () => {
    const decision = gate([{ ...SAFE, grid: [[{ token: "sk-x" }]] }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_nested_smuggling");
  });

  it("refuses even benign nested structure, because scalars only are provable", () => {
    // Structure with no forbidden name is still refused: the rule "the gate
    // emits scalars only" is checkable, "structure is safe" is not.
    const decision = gate([{ ...SAFE, meta: { lifecycle: "observed" } }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_nested_smuggling");
  });

  it("bounds recursion depth rather than crashing on a deep structure", () => {
    let nested: Record<string, unknown> = { prompt: "x" };
    for (let i = 0; i < 500; i += 1) nested = { deeper: nested };
    const decision = gate([{ ...SAFE, meta: nested }]);
    // Either a refusal or a depth marker — but never a thrown stack overflow.
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.frame).toBeNull();
  });

  it("names the nested path of the smuggling attempt", () => {
    const decision = gate([{ ...SAFE, meta: { inner: { secret: "x" } } }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.offendingField).toBe("meta");
  });

  it("refuses a prototype-pollution style key", () => {
    const decision = gate([{ ...SAFE, constructor: { prototype: { policyText: "grant all" } } }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.frame).toBeNull();
  });
});

// ── 5. values that are not sanctioned references ─────────────────────────────

describe("28H — unsanctioned values", () => {
  it("refuses a null or undefined value rather than disclosing an empty slot", () => {
    for (const value of [null, undefined]) {
      const decision = gate([{ ...SAFE, labelLabelId: value }]);
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_value_not_sanctioned");
    }
  });

  it("refuses a value type the gate does not disclose", () => {
    const decision = gate([{ ...SAFE, factCount: { nested: true } }]);
    expect(decision.ok).toBe(false);
  });

  it("refuses prose in a reference field", () => {
    const decision = gate([{ ...SAFE, subjectVisibleId: "the node that was retired last tuesday" }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_value_not_sanctioned");
  });

  it("refuses an over-long string", () => {
    const decision = gate([{ ...SAFE, labelLabelId: "x".repeat(DISCLOSURE_BOUNDS.maxStringChars + 1) }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.frame).toBeNull();
  });

  it("accepts an ordinary opaque id and a real fingerprint", () => {
    const ok = gate([{ ...SAFE, subjectVisibleId: "node:42", fingerprint: "a".repeat(64) }]);
    expect(ok.ok).toBe(true);
  });
});

// ── 6. bounds fail closed ────────────────────────────────────────────────────

describe("28H — bounds fail closed", () => {
  it("refuses too many records rather than truncating", () => {
    const many = Array.from({ length: DISCLOSURE_BOUNDS.maxRecords + 1 }, () => SAFE);
    const decision = gate(many);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_bounds_exceeded");
  });

  it("refuses a record with too many fields rather than truncating", () => {
    const wide: Record<string, number> = {};
    for (let i = 0; i <= DISCLOSURE_BOUNDS.maxFieldsPerRecord; i += 1) wide[`unknown${i}`] = 1;
    const decision = gate([wide]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_bounds_exceeded");
  });

  it("a refusal never returns a partial prefix of the records", () => {
    // 100 safe records followed by one poisoned record: a truncating gate
    // would leak the first 100. This one discloses none.
    const poisoned = [...Array.from({ length: 100 }, () => SAFE), { ...SAFE, secret: "x" }];
    const decision = gate(poisoned);
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.frame).toBeNull();
      expect(JSON.stringify(decision)).not.toContain("node:42");
    }
  });
});

// ── 7. manifest binding ──────────────────────────────────────────────────────

describe("28H — the manifest binds to its output frame", () => {
  it("binds to frame, observer and hash", () => {
    const decision = gate([SAFE]);
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      expect(decision.frame.manifest.frameId).toBe(BIND.frameId);
      expect(decision.frame.manifest.observerId).toBe(BIND.observerId);
      expect(decision.frame.manifest.canonicalVisibleHash).toBe(BIND.canonicalVisibleHash);
      expect(decision.frame.manifest.boundToFrame).toBe(true);
      expect(decision.frame.manifest.defaultDeny).toBe(true);
    }
  });

  it("the frame hash covers the manifest hash, so they cannot be swapped", () => {
    const decision = gate([SAFE]);
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      const a = decision.frame.disclosureFrameHash;
      const b = gate([{ ...SAFE, factCount: 2 }]);
      expect(b.ok).toBe(true);
      if (b.ok) expect(b.frame.disclosureFrameHash).not.toBe(a);
    }
  });

  it("different bindings produce different manifests", () => {
    const a = gate([SAFE]);
    const b = gate([SAFE], { frameId: "frame-2" });
    expect(a.ok && b.ok).toBe(true);
    if (a.ok && b.ok) expect(a.frame.manifest.manifestHash).not.toBe(b.frame.manifest.manifestHash);
  });

  it("refuses a disclosure with no binding", () => {
    for (const missing of ["frameId", "observerId", "canonicalVisibleHash"]) {
      const input: Record<string, unknown> = { ...BIND, records: [SAFE] };
      delete input[missing];
      const decision = disclose(input as GetigDisclosureDiscloseInput);
      expect(decision.ok, `missing ${missing} was allowed`).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_binding_missing");
    }
  });

  it("refuses an over-long binding id", () => {
    const decision = gate([SAFE], { frameId: "f".repeat(DISCLOSURE_BOUNDS.maxIdChars + 1) });
    expect(decision.ok).toBe(false);
    if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_binding_missing");
  });

  it("refuses a binding hash that is not a digest", () => {
    // A caller binding a disclosure to something that is not a hash is
    // claiming a frame identity it does not hold. An EMPTY hash is absence,
    // not mismatch, so it is asserted separately below.
    for (const hash of ["vh-1", "not-a-hash", "ZZZZ"]) {
      const decision = gate([SAFE], { canonicalVisibleHash: hash });
      expect(decision.ok, `bad binding hash accepted: ${String(hash)}`).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_binding_mismatch");
    }
    // An empty or non-string hash is ABSENT rather than mismatched — the gate
    // cannot have a binding it was not given — so it reports the missing code.
    for (const hash of ["", 12345, null]) {
      const decision = gate([SAFE], { canonicalVisibleHash: hash });
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_binding_missing");
    }
  });

  it("accepts a real digest-shaped binding hash", () => {
    expect(gate([SAFE]).ok).toBe(true);
    expect(gate([SAFE], { canonicalVisibleHash: "0".repeat(64) }).ok).toBe(true);
  });

  it("records every disclosed field in the manifest with its class", () => {
    const decision = gate([SAFE]);
    expect(decision.ok).toBe(true);
    if (decision.ok) {
      const names = decision.frame.manifest.fields.map((f) => f.fieldName);
      for (const key of Object.keys(SAFE)) expect(names).toContain(key);
      expect(decision.frame.manifest.fieldCount).toBe(Object.keys(SAFE).length);
    }
  });
});

// ── 8. malformed input ───────────────────────────────────────────────────────

describe("28H — malformed input", () => {
  it("refuses a non-array records value", () => {
    for (const records of [null, undefined, "nope", 42, {}]) {
      const decision = gate(records);
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_input_invalid");
    }
  });

  it("refuses a non-object record", () => {
    for (const record of [null, "x", 42, []]) {
      const decision = gate([record]);
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_input_invalid");
    }
  });

  it("refuses a non-object input", () => {
    for (const bad of [null, undefined, 42, "x", []]) {
      const decision = disclose(bad as unknown as GetigDisclosureDiscloseInput);
      expect(decision.ok).toBe(false);
      if (!decision.ok) expect(decision.refusal).toBe("refused_disclosure_input_invalid");
    }
  });

  it("never throws, whatever it is given", () => {
    const hostile: unknown[] = [
      null, undefined, 0, "", [], {}, NaN, Symbol.iterator.toString(),
      { records: [{}], frameId: {}, observerId: [], canonicalVisibleHash: null },
    ];
    for (const input of hostile) {
      expect(() => disclose(input as GetigDisclosureDiscloseInput)).not.toThrow();
    }
  });

  it("does not mutate its input records", () => {
    const input = [{ ...SAFE }];
    const before = JSON.stringify(input);
    gate(input);
    expect(JSON.stringify(input)).toBe(before);
  });
});

// ── 9. every refusal code is reachable ───────────────────────────────────────

describe("28H — every refusal code is reachable", () => {
  it("produces each declared code from a real input", () => {
    const produced = new Set<string>();
    const record = (d: ReturnType<typeof disclose>) => {
      if (!d.ok) produced.add(d.refusal);
    };

    record(disclose(null as unknown as GetigDisclosureDiscloseInput));
    record(gate("not-an-array"));
    record(gate([null]));
    record(gate([{ ...SAFE, secret: "x" }]));
    record(gate([{ ...SAFE, mysteryField: "x" }]));
    record(gate([{ ...SAFE, meta: { prompt: "x" } }]));
    record(gate([{ ...SAFE, labelLabelId: "C:\\secret\\path" }]));
    record(gate([{ ...SAFE, labelLabelId: null }]));
    record(gate(Array.from({ length: DISCLOSURE_BOUNDS.maxRecords + 1 }, () => SAFE)));

    const wide: Record<string, number> = {};
    for (let i = 0; i <= DISCLOSURE_BOUNDS.maxFieldsPerRecord; i += 1) wide[`x${i}`] = 1;
    record(gate([wide]));

    const unbound = { ...BIND, records: [SAFE] } as Record<string, unknown>;
    delete unbound.frameId;
    record(disclose(unbound as unknown as GetigDisclosureDiscloseInput));

    // Depth: a structure deeper than the bound gets its OWN code, so a
    // structurally hostile input is not misreported as mere smuggling. Every
    // wrapper is a SANCTIONED name so the scan really reaches the bound.
    let deep: Record<string, unknown> = { prompt: "x" };
    for (let i = 0; i < DISCLOSURE_BOUNDS.maxDepth + 20; i += 1) deep = { hashRef: deep };
    record(gate([{ ...SAFE, meta: deep }]));

    // Binding mismatch: a hash that is not a digest.
    record(gate([SAFE], { canonicalVisibleHash: "vh-1" }));

    // NO code is excused. A declared code that no input can produce is dead
    // vocabulary, and excusing one here would hide exactly that defect.
    for (const code of DISCLOSURE_REFUSAL_CODES) {
      expect(produced.has(code), `unreachable refusal code: ${code}`).toBe(true);
    }
  });

  it("reports a depth breach distinctly from ordinary smuggling", () => {
    // Every wrapper key here is SANCTIONED, so the scan keeps descending and
    // actually reaches the depth bound. Using an unrecognised wrapper name
    // would halt the walk at depth 1 and test nothing.
    let deep: Record<string, unknown> = { prompt: "x" };
    for (let i = 0; i < DISCLOSURE_BOUNDS.maxDepth + 20; i += 1) deep = { hashRef: deep };
    const decision = gate([{ ...SAFE, meta: deep }]);
    expect(decision.ok).toBe(false);
    if (!decision.ok) {
      expect(decision.refusal).toBe("refused_disclosure_depth_exceeded");
      expect(decision.frame).toBeNull();
    }
  });
});
