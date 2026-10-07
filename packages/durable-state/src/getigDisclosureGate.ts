/**
 * PHASE 28H — PRIVACY, REDACTION & VISIBLE-WORLD DISCLOSURE BOUNDARY
 * (DATA MINIMIZATION / DEFAULT DENY / ZERO-AUTHORITY)
 *
 * CENTRAL LAWS:
 *   DISCLOSURE != DISCLOSURE OF EVERYTHING
 *   UNKNOWN FIELD != SAFE FIELD
 *   REDACTION != SANITISATION
 *   A PARTIAL FRAME IS NOT A FRAME
 *
 * ── WHY THIS IS AN ALLOWLIST AND 28F WAS A DENYLIST ─────────────────────────
 *
 * 28F refuses records carrying KNOWN content-bearing field names. That is the
 * right call for provenance nodes, but it is structurally incapable of catching
 * a field nobody thought of. A denylist is a list of known dangers; every name
 * absent from it is silently treated as safe.
 *
 * Here that is exactly backwards. The prompt says "Unknown fields default-deny",
 * and for a disclosure boundary the only defensible reading is that the gate
 * reveals a name no one authorised. So:
 *
 *   DISCLOSURE_CLASSES is the complete set of things that may cross the gate.
 *   Anything else — unknown, newly invented, misspelled, or in a nested position
 *   no caller anticipated — is REFUSED, not passed through.
 *
 * The forbidden list still exists, and is checked too, but it is the SECOND line
 * of defence. The first is "is this name on the allowlist at all?"
 *
 * ── WHY NESTED SMUGGLING IS THE REAL ATTACK ─────────────────────────────────
 *
 * A gate that only inspects the top level of an object is theatre. The obvious
 * bypass is to nest the forbidden material one level down:
 *
 *   { meta: { kind: "frame", nested: { prompt: "…" } } }
 *
 * So the scan is RECURSIVE and depth-bounded, and it walks arrays and nested
 * objects alike. Depth is bounded rather than unbounded because an attacker-
 * controlled structure deep enough to blow the stack is itself a denial of
 * service, and a disclosure gate that can be crashed by its own input is not a
 * gate.
 *
 * ── WHY REDACTION IS REFUSAL, NOT REPAIR ────────────────────────────────────
 *
 * The prompt forbids truncating forbidden material into "apparently safe
 * semantics". That rules out the comfortable move of replacing a secret with
 * `"***REDACTED***"` and returning the record. A redacted record still discloses
 * THAT something was there, still occupies a slot, and looks like a successful
 * sanitisation — which is the failure mode being ruled out.
 *
 * So a forbidden field produces a REFUSAL and NO OUTPUT. `GetigDisclosureGateRefused`
 * carries `disclosed: null`, never a partially-redacted frame. There is no code
 * path that returns a frame containing a redaction marker.
 *
 * ── WHAT "SANCTIONED HASH REFERENCE" MEANS HERE ─────────────────────────────
 *
 * A fingerprint is allowed, and it is allowed ONLY as an opaque token the
 * caller already holds. This module never computes a hash OF forbidden material
 * — doing so would let a secret be recovered by dictionary attack from the
 * fingerprint, which is the same disclosure wearing a disguise. Fingerprints
 * pass through as opaque strings; this module has no hashing input path for
 * content at all.
 *
 * ── BINDING ─────────────────────────────────────────────────────────────────
 *
 * The disclosure manifest binds to the frame it discloses, carrying frameId,
 * observerId, canonicalVisibleHash and the manifest's own hash. A disclosure
 * that cannot name its frame is refused, because an unbound disclosure could be
 * presented as describing a different frame.
 */

import { canonicalHash } from "./canonical.js";

// ── the allowlist ────────────────────────────────────────────────────────────

/**
 * The COMPLETE set of field names that may cross the disclosure boundary.
 *
 * Every name is normalised the same way the matcher normalises candidates
 * (lowercase, alphanumerics only), so `private_key`, `privateKey` and
 * `PrivateKey` all collide with one entry rather than smuggling past it.
 */
export const DISCLOSURE_CLASSES = Object.freeze([
  // bounded opaque identifiers
  "subjectvisibleid",
  "subjectcollection",
  "factid",
  "frameid",
  "sequenceid",
  "viewid",
  "graphid",
  "nodeid",
  "edgeid",
  "proposalid",
  "routeid",
  "relationid",
  "eventid",
  "labellabelid",
  "overlayid",
  "pickingid",
  // sanctioned fingerprint references (opaque, pre-computed by the caller)
  "fingerprint",
  "hashref",
  "sourceprojectionhash",
  "canonicalvisiblehash",
  "viewhash",
  "sequenceidentity",
  // closed vocabularies
  "lifecycle",
  "freshness",
  "knowledge",
  "kind",
  "relation",
  "role",
  "divergencekind",
  "observerkind",
  "refusalcode",
  "order",
  // observer / epoch identity
  "observerid",
  "runtimeid",
  "epochid",
  // bounded structural metrics
  "count",
  "counts",
  "factcount",
  "nodecount",
  "edgecount",
  "subjectcount",
  "barredsubjectcount",
  "conflictcount",
  "rank",
  "depth",
  "position",
  "isbarred",
  "isterminal",
  "isgrant",
  "isfiltered",
  "iscomplete",
  "isglobaltruth",
  "bounded",
  "cyclebroken",
  "unknown",
] as const);
export type GetigDisclosureClass = (typeof DISCLOSURE_CLASSES)[number];

/**
 * The prompt's forbidden list, checked in ADDITION to the allowlist. It is
 * redundant by construction — nothing on the allowlist is forbidden — and the
 * redundancy is the point: it means adding a bad name to the allowlist in a
 * future edit is caught by this list rather than sailing through.
 */
export const DISCLOSURE_FORBIDDEN_FIELDS = Object.freeze([
  "privatekey",
  "secret",
  "token",
  "password",
  "credential",
  "apikey",
  "authorization",
  "cookie",
  "sessionid",
  "rawprompt",
  "rawtooloutput",
  "rawmemory",
  "hiddentext",
  "policystatement",
  "policyname",
  "policytext",
  "hiddenpolicyname",
  "rawstore",
  "storecontent",
  "localpath",
  "privatepath",
  "homepath",
  "env",
  "envvar",
  "environment",
  "freetext",
  "shell",
  "command",
  "exec",
  "executable",
  "unredactedpayload",
  "payload",
  "systemprompt",
] as const);
export type GetigDisclosureForbiddenField = (typeof DISCLOSURE_FORBIDDEN_FIELDS)[number];

export const DISCLOSURE_REFUSAL_CODES = Object.freeze([
  "refused_disclosure_input_invalid",
  "refused_disclosure_unknown_field",
  "refused_disclosure_forbidden_field",
  "refused_disclosure_nested_smuggling",
  "refused_disclosure_depth_exceeded",
  "refused_disclosure_bounds_exceeded",
  "refused_disclosure_binding_missing",
  "refused_disclosure_binding_mismatch",
  "refused_disclosure_value_not_sanctioned",
] as const);
export type GetigDisclosureRefusalCode = (typeof DISCLOSURE_REFUSAL_CODES)[number];

export const DISCLOSURE_BOUNDS = Object.freeze({
  maxFieldsPerRecord: 256,
  maxRecords: 4_096,
  maxArrayLength: 1_024,
  maxIdChars: 128,
  maxDepth: 32,
  maxStringChars: 512,
});

export const DISCLOSURE_SCHEMA_VERSION = "menog-getig-disclosure/v0" as const;

// ── shapes ───────────────────────────────────────────────────────────────────

/** The binding every disclosure carries. */
export interface GetigDisclosureBinding {
  readonly frameId: string;
  readonly observerId: string;
  readonly canonicalVisibleHash: string;
}

export interface GetigDisclosureField {
  readonly name: string;
  readonly class: GetigDisclosureClass;
  readonly valueType: "opaque_id" | "fingerprint" | "vocabulary" | "count" | "boolean";
}

export interface GetigDisclosureManifestEntry {
  readonly recordIndex: number;
  readonly fieldName: string;
  readonly disclosureClass: GetigDisclosureClass;
  readonly valueType: GetigDisclosureField["valueType"];
}

export interface GetigDisclosureManifest {
  readonly schemaVersion: typeof DISCLOSURE_SCHEMA_VERSION;
  readonly frameId: string;
  readonly observerId: string;
  readonly canonicalVisibleHash: string;
  readonly fields: readonly GetigDisclosureManifestEntry[];
  readonly fieldCount: number;
  readonly recordCount: number;
  readonly manifestHash: string;
  /** The disclosure names the frame it describes. */
  readonly boundToFrame: true;
  readonly defaultDeny: true;
  readonly authority: "none";
  readonly readOnly: true;
}

/**
 * A disclosed field. Every value is a scalar — an object or array value would
 * mean structure crossed the gate, and structure is where smuggling lives.
 */
export type GetigDisclosureDisclosedFieldValue = string | number | boolean;

export interface GetigDisclosureDisclosedRecord {
  readonly fields: Readonly<Record<string, GetigDisclosureDisclosedFieldValue>>;
  readonly fieldCount: number;
}

export interface GetigDisclosureFrame {
  readonly schemaVersion: typeof DISCLOSURE_SCHEMA_VERSION;
  readonly frameId: string;
  readonly observerId: string;
  readonly canonicalVisibleHash: string;
  readonly records: readonly GetigDisclosureDisclosedRecord[];
  readonly recordCount: number;
  readonly fieldCount: number;
  readonly manifest: GetigDisclosureManifest;
  readonly disclosureFrameHash: string;
  /** Structural: disclosing is not granting, and reveals no hidden material. */
  readonly disclosesRawContent: false;
  readonly disclosesPolicyText: false;
  readonly redacted: false;
  readonly authority: "none";
  readonly readOnly: true;
}

export type GetigDisclosureSucceeded = {
  readonly ok: true;
  readonly code: "disclosure_succeeded";
  readonly frame: GetigDisclosureFrame;
  /** No partial frame is ever emitted alongside a refusal. */
  readonly partialFrameEmitted: false;
  readonly authority: "none";
  readonly readOnly: true;
};

export type GetigDisclosureGateRefused = {
  readonly ok: false;
  readonly code: "disclosure_refused";
  readonly refusal: GetigDisclosureRefusalCode;
  readonly explanation: string;
  /** The field that caused the refusal, when one is identifiable. */
  readonly offendingField: string | null;
  /**
   * ALWAYS null on refusal. A refusal discloses nothing — not a redacted frame,
   * not a skeleton, not a count. This is the field that makes that structural.
   */
  readonly frame: null;
  readonly manifest: null;
  readonly partialFrameEmitted: false;
  readonly authority: "none";
  readonly readOnly: true;
};

export type GetigDisclosureDecision = GetigDisclosureSucceeded | GetigDisclosureGateRefused;

// ── helpers ──────────────────────────────────────────────────────────────────

/** Same normalisation 28F uses, so the two gates agree on what a name is. */
const normaliseField = (name: string): string => name.toLowerCase().replace(/[^a-z0-9]/g, "");

const ALLOWED = new Set<string>(DISCLOSURE_CLASSES);
const FORBIDDEN = new Set<string>(DISCLOSURE_FORBIDDEN_FIELDS);

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const refuse = (
  refusal: GetigDisclosureRefusalCode,
  explanation: string,
  offendingField: string | null = null,
): GetigDisclosureGateRefused => ({
  ok: false,
  code: "disclosure_refused",
  refusal,
  explanation,
  offendingField,
  frame: null,
  manifest: null,
  partialFrameEmitted: false,
  authority: "none",
  readOnly: true,
});

/**
 * Classify a single field name against the allowlist. Returns a refusal code
 * rather than a boolean so the caller can distinguish "never heard of it"
 * (default-deny) from "explicitly forbidden" (a recognised attack).
 */
const classify = (
  rawName: string,
): { ok: true; class: GetigDisclosureClass } | { ok: false; refusal: GetigDisclosureRefusalCode } => {
  const name = normaliseField(rawName);
  if (FORBIDDEN.has(name)) return { ok: false, refusal: "refused_disclosure_forbidden_field" };
  if (!ALLOWED.has(name)) return { ok: false, refusal: "refused_disclosure_unknown_field" };
  return { ok: true, class: name as GetigDisclosureClass };
};

/** Which sanctioned class a value belongs to, so the manifest can record it. */
const valueTypeOf = (v: GetigDisclosureDisclosedFieldValue): GetigDisclosureField["valueType"] => {
  if (typeof v === "boolean") return "boolean";
  if (typeof v === "number") return "count";
  if (/^[0-9a-f]{16,}$/i.test(v)) return "fingerprint";
  if (v.length > DISCLOSURE_BOUNDS.maxIdChars) return "vocabulary";
  return "opaque_id";
};

/**
 * Validate a value against the kind of thing its class promises.
 *
 * A string in a fingerprint slot that is obviously a path, or a shell line, is
 * refused rather than passed along: the ALLOWLIST alone cannot catch a
 * forbidden VALUE hiding in an allowed FIELD NAME. That is the other half of
 * nested smuggling — a field called `fingerprint` holding a path-shaped
 * secret value.
 */
const valueIsSanctioned = (name: string, v: GetigDisclosureDisclosedFieldValue): boolean => {
  const norm = normaliseField(name);
  if (typeof v !== "string") return true;
  if (v.length > DISCLOSURE_BOUNDS.maxStringChars) return false;

  // ── filesystem paths, BOTH separators ────────────────────────────────────
  // A platform-narrow check that only matched Windows paths would miss a POSIX home path as well, which is the
  // more likely shape on a Linux-native runtime, so BOTH separators are
  // refused. This single rule is what catches every path form: a measured
  // sweep of win-path / posix-path / posix-home / relative / url / shell values
  // showed the separator rule fires on all of them, which is why the narrower
  // drive-letter, traversal and root-directory rules that used to sit alongside
  // it were removed as dead weight rather than left in as false assurance.
  if (/[\\/]/.test(v)) return false;

  // Free-text and shell material is rejected wherever it appears, including in
  // an allowlisted field, because it is material rather than a reference.
  //
  // 28I bypassed this gate twice: `eval(payload)` and `AWS_SECRET_ACCESS_KEY=…`,
  // because the original pattern required whitespace after the verb. The list
  // below therefore allows the call form as well as the space form.
  //
  // It is deliberately SPLIT into two tiers. Tier 1 verbs are unambiguous — no
  // legitimate reference contains them. Tier 2 words (`node`, `sh`, `sc`, `del`,
  // `reg`) collide with real identifiers: `node:42` is a valid subject id, and
  // the 28I falsification sweep caught that treating them as bare words refused
  // it. Tier 2 therefore requires a following ARGUMENT (`node script.js`), which
  // is what distinguishes a command from an identifier.
  const TIER1 = /(^|[^a-z0-9])(rm|curl|wget|sudo|chmod|eval|exec|bash|zsh|powershell|schtasks|certutil|bitsadmin|taskkill|shred|mkfs|chown|chgrp|kill)([^a-z0-9]|$)/i;
  const TIER2 = /(^|[^a-z0-9])(sh|sc|del|reg|copy|rename|python|perl|node|dd|cmd)(\s|\(|\/)/i;
  if (TIER1.test(v) || TIER2.test(v)) return false;
  // Environment-variable assignment in ANY form: `FOO=bar`, `$FOO`, `%FOO%`.
  // 28I bypassed this with `AWS_SECRET_ACCESS_KEY=abc123`.
  if (/^[A-Z][A-Z0-9_]{2,}=/.test(v)) return false;
  if (/[$%][A-Z][A-Z0-9_]{2,}/.test(v)) return false;
  // Shell metacharacters and substitution: a reference contains none of these.
  // `:` and `-` and `.` are deliberately EXCLUDED from the class — namespaced
  // ids like `node:42` and dotted ids like `entity.node` are legitimate
  // references, and an over-tight rule that refused them would push callers
  // toward weaker representations. (Over-tightening was caught by the 28I
  // falsification sweep and is recorded as such.)
  if (/[|`$;<>]/.test(v)) return false;
  if (v.includes("-----BEGIN")) return false;
  if (/(^|[^a-z])(sk-|pk-|ghp_|xox[baprs]-)/i.test(v)) return false; // credential shapes
  // A base64 blob is refused, BUT a pure-hex digest is exactly what a sanctioned
  // fingerprint IS. Without this carve-out the rule would reject every real
  // hash — the base64 shape is distinguished by `+`, `/` or `=` and by
  // containing non-hex letters.
  const isHexDigest = /^[0-9a-f]{16,}$/i.test(v);
  if (!isHexDigest && /^[A-Za-z0-9+/]{40,}={0,2}$/.test(v)) return false;
  if (v.includes("://")) return false; // URL

  // A string in a *reference* field is a reference: no whitespace, no prose.
  if (
    /(fingerprint|hashref|subjectvisibleid|frameid|observerid|runtimeid|epochid|nodeid|edgeid|pickingid|overlayid|routeid|proposalid|viewid|graphid|sequenceid|relationid|eventid|factid)$/.test(
      norm,
    )
  ) {
    if (/\s/.test(v)) return false;
  }
  return true;
};

// ── the gate ─────────────────────────────────────────────────────────────────

export interface GetigDisclosureDiscloseInput {
  readonly frameId?: unknown;
  readonly observerId?: unknown;
  readonly canonicalVisibleHash?: unknown;
  /** The records to consider for disclosure. Read, never mutated. */
  readonly records?: unknown;
}

/**
 * Run the disclosure gate.
 *
 * Returns either a fully-disclosed frame bound to its source frame, or a
 * refusal that discloses nothing. There is no third outcome — in particular
 * there is no redacted-but-returned frame.
 */
export function disclose(input: GetigDisclosureDiscloseInput): GetigDisclosureDecision {
  if (!isRecord(input)) {
    return refuse("refused_disclosure_input_invalid", "disclosure input must be an object");
  }

  const frameId = typeof input.frameId === "string" ? input.frameId : null;
  const observerId = typeof input.observerId === "string" ? input.observerId : null;
  const canonicalVisibleHash = typeof input.canonicalVisibleHash === "string" ? input.canonicalVisibleHash : null;
  if (frameId === null || observerId === null || canonicalVisibleHash === null) {
    return refuse(
      "refused_disclosure_binding_missing",
      "a disclosure must bind to frameId, observerId and canonicalVisibleHash",
    );
  }
  for (const [label, value] of [["frameId", frameId], ["observerId", observerId]] as const) {
    if (value.length === 0 || value.length > DISCLOSURE_BOUNDS.maxIdChars) {
      return refuse("refused_disclosure_binding_missing", `binding ${label} is empty or over-long`);
    }
  }
  // ── BINDING INTEGRITY ────────────────────────────────────────────────────
  // An empty hash is ABSENCE, not a mismatch — the caller supplied no digest at
  // all — so it is judged by the same emptiness rule as frameId/observerId.
  if (canonicalVisibleHash.length === 0) {
    return refuse("refused_disclosure_binding_missing", "binding canonicalVisibleHash is empty");
  }
  // Otherwise the hash must LOOK like a digest. A caller binding a disclosure to
  // something that is not a hash is claiming a frame identity it does not hold;
  // accepting it would let a disclosure be presented as describing a frame it
  // was never derived from. This is a MISMATCH, distinct from absence.
  if (!/^[0-9a-f]{8,}$/i.test(canonicalVisibleHash)) {
    return refuse(
      "refused_disclosure_binding_mismatch",
      "canonicalVisibleHash does not have the shape of a content digest, so the disclosure cannot be bound to the frame it claims",
    );
  }

  const rawRecords = input.records;
  if (!Array.isArray(rawRecords)) {
    return refuse("refused_disclosure_input_invalid", "records must be an array");
  }
  if (rawRecords.length > DISCLOSURE_BOUNDS.maxRecords) {
    return refuse(
      "refused_disclosure_bounds_exceeded",
      `${rawRecords.length} records exceeds the disclosure bound of ${DISCLOSURE_BOUNDS.maxRecords}`,
    );
  }

  const manifestEntries: GetigDisclosureManifestEntry[] = [];
  const disclosed: GetigDisclosureDisclosedRecord[] = [];

  for (let recordIndex = 0; recordIndex < rawRecords.length; recordIndex += 1) {
    const record = rawRecords[recordIndex];
    if (!isRecord(record)) {
      return refuse(
        "refused_disclosure_input_invalid",
        `record ${recordIndex} is not an object`,
        `record[${recordIndex}]`,
      );
    }

    const keys = Object.keys(record);
    if (keys.length > DISCLOSURE_BOUNDS.maxFieldsPerRecord) {
      return refuse(
        "refused_disclosure_bounds_exceeded",
        `record ${recordIndex} holds ${keys.length} fields, above the bound of ${DISCLOSURE_BOUNDS.maxFieldsPerRecord}`,
      );
    }

    const out: Record<string, GetigDisclosureDisclosedFieldValue> = {};

    for (const key of keys) {
      const value = record[key];

      // NESTED STRUCTURE IS CHECKED BEFORE THE NAME IS CLASSIFIED.
      //
      // Order matters here. If the name were classified first, a smuggler would
      // only need an unrecognised WRAPPER name (`meta`, `extra`) to be told
      // "unknown field" instead of "nested smuggling" — and the report would
      // understate what was attempted. Checking the value first means any
      // structure, under any name, is recognised as smuggling.
      if (isRecord(value) || Array.isArray(value)) {
        const nested = findForbiddenNested(value, 1);
        // The scan distinguishes WHY it stopped. Collapsing a depth breach into
        // a generic smuggling refusal would UNDERSTATE a structurally hostile
        // input and leave `refused_disclosure_depth_exceeded` unreachable —
        // which is exactly the dead-vocabulary defect this gate's own reachability
        // test exists to prevent.
        if (nested === DEPTH_MARKER) {
          return refuse(
            "refused_disclosure_depth_exceeded",
            `field "${key}" nests deeper than the disclosure bound of ${DISCLOSURE_BOUNDS.maxDepth}`,
            key,
          );
        }
        if (nested === ARRAY_MARKER) {
          return refuse(
            "refused_disclosure_bounds_exceeded",
            `field "${key}" holds an array longer than the disclosure bound of ${DISCLOSURE_BOUNDS.maxArrayLength}`,
            key,
          );
        }
        if (nested !== null) {
          return refuse(
            "refused_disclosure_nested_smuggling",
            `field "${key}" contains forbidden or unsanctioned material nested at "${nested}"`,
            key,
          );
        }
        return refuse(
          "refused_disclosure_nested_smuggling",
          `field "${key}" carries nested structure; the disclosure gate emits sanctioned scalars only`,
          key,
        );
      }

      const classified = classify(key);
      if (!classified.ok) {
        // A forbidden or unknown field refuses the WHOLE gate. It is not
        // skipped, not redacted, and not disclosed.
        return refuse(
          classified.refusal,
          classified.refusal === "refused_disclosure_forbidden_field"
            ? `field "${key}" carries forbidden material`
            : `field "${key}" is not a sanctioned disclosure class; unknown fields default-deny`,
          key,
        );
      }

      if (value === null || value === undefined) {
        return refuse(
          "refused_disclosure_value_not_sanctioned",
          `field "${key}" has no value; absence is expressed by omitting the field, not by a null`,
          key,
        );
      }
      if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
        return refuse(
          "refused_disclosure_value_not_sanctioned",
          `field "${key}" holds a value type the gate does not disclose`,
          key,
        );
      }

      if (!valueIsSanctioned(key, value)) {
        return refuse(
          "refused_disclosure_value_not_sanctioned",
          `field "${key}" holds a value that is not a sanctioned reference or metric`,
          key,
        );
      }

      out[key] = value;
      manifestEntries.push({
        recordIndex,
        fieldName: key,
        disclosureClass: classified.class,
        valueType: valueTypeOf(value),
      });
    }

    disclosed.push({ fields: Object.freeze(out), fieldCount: keys.length });
  }

  const manifest: GetigDisclosureManifest = {
    schemaVersion: DISCLOSURE_SCHEMA_VERSION,
    frameId,
    observerId,
    canonicalVisibleHash,
    fields: manifestEntries,
    fieldCount: manifestEntries.length,
    recordCount: disclosed.length,
    manifestHash: canonicalHash({
      frameId,
      observerId,
      canonicalVisibleHash,
      fields: manifestEntries,
    }),
    boundToFrame: true,
    defaultDeny: true,
    authority: "none",
    readOnly: true,
  };

  const totalFields = disclosed.reduce((n, r) => n + r.fieldCount, 0);

  const frame: GetigDisclosureFrame = {
    schemaVersion: DISCLOSURE_SCHEMA_VERSION,
    frameId,
    observerId,
    canonicalVisibleHash,
    records: disclosed,
    recordCount: disclosed.length,
    fieldCount: totalFields,
    manifest,
    disclosureFrameHash: canonicalHash({
      frameId,
      observerId,
      canonicalVisibleHash,
      records: disclosed,
      manifestHash: manifest.manifestHash,
    }),
    // Structural, not a value to set.
    disclosesRawContent: false,
    disclosesPolicyText: false,
    redacted: false,
    authority: "none",
    readOnly: true,
  };

  return {
    ok: true,
    code: "disclosure_succeeded",
    frame,
    partialFrameEmitted: false,
    authority: "none",
    readOnly: true,
  };
}

/** Sentinels distinguishing "stopped because hostile" from "found bad material". */
const DEPTH_MARKER = "\u0000depth_exceeded";
const ARRAY_MARKER = "\u0000array_too_long";

/**
 * Depth-bounded recursive search for a forbidden or unknown field name inside a
 * nested structure. Used to NAME the smuggling attempt in the refusal, which a
 * plain "field carries structure" message would not.
 *
 * Depth is bounded: an attacker-supplied structure deep enough to exhaust the
 * stack is itself a denial of service, and the bound turns that into a refusal
 * instead of a crash. The bound is reported as its OWN refusal code rather than
 * being folded into the generic smuggling code.
 */
function findForbiddenNested(value: unknown, depth: number): string | null {
  if (depth > DISCLOSURE_BOUNDS.maxDepth) return DEPTH_MARKER;
  if (Array.isArray(value)) {
    if (value.length > DISCLOSURE_BOUNDS.maxArrayLength) return ARRAY_MARKER;
    for (let i = 0; i < value.length; i += 1) {
      const found = findForbiddenNested(value[i], depth + 1);
      // Sentinel results propagate UNWRAPPED. Prefixing them with a path (as a
      // real finding is) would make `"hashRef.…\0depth_exceeded"` never compare
      // equal to the marker, so the caller's branch would be dead code and the
      // depth breach would be misreported as ordinary smuggling.
      if (found === DEPTH_MARKER || found === ARRAY_MARKER) return found;
      if (found !== null) return `${i}.${found}`;
    }
    return null;
  }
  if (isRecord(value)) {
    for (const key of Object.keys(value)) {
      const norm = normaliseField(key);
      if (FORBIDDEN.has(norm)) return key;
      // Descend through ALLOWED names only. An unknown wrapper name is itself a
      // finding, but it is reported by the CALLER as nesting — descending past
      // it would let a smuggler choose a wrapper name that halts the walk at
      // depth 1, so the depth bound could never be reached and
      // `refused_disclosure_depth_exceeded` would stay dead vocabulary.
      if (ALLOWED.has(norm)) {
        const found = findForbiddenNested(value[key], depth + 1);
        if (found === DEPTH_MARKER || found === ARRAY_MARKER) return found;
        if (found !== null) return `${key}.${found}`;
      }
    }
  }
  return null;
}
