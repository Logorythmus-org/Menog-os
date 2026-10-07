/**
 * PHASE 26A — Transport Trust Model Tests
 * (CONTRACT-FIRST / NO SOCKET IMPLEMENTATION / NO NEW AUTHORITY).
 *
 * Pins the nine transport laws structurally and behaviorally:
 *   T1 REACHABILITY ≠ IDENTITY · T2 IDENTITY ≠ ADMISSION ·
 *   T3 ADMISSION ≠ AUTHORITY · T4 AUTHENTICATED SESSION ≠ EXECUTION ·
 *   T5 REMOTE MESSAGE ≠ LOCAL POLICY · T6 TRANSPORT SUCCESS ≠ APPLICATION
 *   ACCEPTANCE · T7 CONNECTION STATE ≠ TRUST STATE · T8 RECONNECT ≠ RE-
 *   ADMISSION · T9 NETWORK EVIDENCE ≠ AUTHORITY.
 * Also pins the closed endpoint/frame/session/refusal/close/scope
 * vocabularies, the TT-01..TT-18 threat catalog, pinned bounds, and the
 * deterministic-explanation law (same input → same output).
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  TRANSPORT_TRUST_SCHEMA_VERSION,
  TRANSPORT_TRUST_PINS,
  TRANSPORT_TRUST_PIN_EXPLANATIONS,
  TRANSPORT_ENDPOINT_CLASSES,
  TRANSPORT_FORBIDDEN_BIND_ADDRESSES,
  TRANSPORT_OUTCOMES,
  TRANSPORT_REFUSAL_CODES,
  TRANSPORT_CLOSE_REASONS,
  FRAME_DISPOSITIONS,
  TRANSPORT_BOUNDS,
  SESSION_STATES,
  SESSION_EVENTS,
  TRANSPORT_SCOPES,
  TRANSPORT_NON_SCOPES,
  TRANSPORT_THREAT_IDS,
  TRANSPORT_THREAT_DISPOSITIONS,
  decideEndpointDeclaration,
  decideFrame,
  decideSenderPace,
  decideSessionTransition,
  decideTransportScope,
  decideTransportClaim,
  classifyTransportThreat,
  transportTrustFingerprint,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

/** Surfaces the 26A module must NEVER contain (structural no-socket pin). */
const FORBIDDEN_SURFACES: readonly string[] = Object.freeze([
  "child_process",
  "node:net",
  "node:http",
  "node:https",
  "node:dgram",
  "node:tls",
  "node:dns",
  "WebSocket",
  "fetch(",
  "spawn(",
  "listen(",
  "createServer",
  "connect(",
]);

const NOW = 1_700_000_000_000;
const NODE_A = "node-" + "a".repeat(64);

// ── structural pins ──────────────────────────────────────────────────────────

describe("26A structure — closed vocabulary and law surfaces", () => {
  it("forbidden surfaces list is pinned and the module imports no socket/network/execution primitive", () => {
    expect(FORBIDDEN_SURFACES).toEqual([
      "child_process",
      "node:net",
      "node:http",
      "node:https",
      "node:dgram",
      "node:tls",
      "node:dns",
      "WebSocket",
      "fetch(",
      "spawn(",
      "listen(",
      "createServer",
      "connect(",
    ]);
    const code = codeOnly(SRC("federationTransportTrust.ts"));
    for (const forbidden of FORBIDDEN_SURFACES) {
      expect(code).not.toContain(forbidden);
    }
    expect(code).not.toContain("node:crypto");
    expect(code).not.toContain("createHash");
    expect(code).not.toContain("DatabaseSync");
    expect(code).not.toContain("acceptMutation");
    expect(code).not.toContain("createSocket");
  });

  it("no type or decision carries execution/policy authority; the module imports no policy vocabulary (T3/T4/T5)", () => {
    const src = codeOnly(SRC("federationTransportTrust.ts"));
    expect(src).not.toMatch(/executionAuthorized:\s*true/);
    expect(src).not.toMatch(/policyAuthorized:\s*true/);
    expect(src).not.toContain("DenyByDefault");
    expect(src).not.toContain("PolicyDecision");
    expect(src).not.toMatch(/\.persist\(/);
    expect(src).not.toContain("executeToolRun");
    expect(src).not.toContain("runIsolated");
  });

  it("schema version and the nine pins are pinned exactly, in order", () => {
    expect(TRANSPORT_TRUST_SCHEMA_VERSION).toBe("menog-transport-trust/v0");
    expect([...TRANSPORT_TRUST_PINS]).toEqual([
      "REACHABILITY_NOT_IDENTITY",
      "IDENTITY_NOT_ADMISSION",
      "ADMISSION_NOT_AUTHORITY",
      "AUTHENTICATED_SESSION_NOT_EXECUTION",
      "REMOTE_MESSAGE_NOT_LOCAL_POLICY",
      "TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE",
      "CONNECTION_STATE_NOT_TRUST_STATE",
      "RECONNECT_NOT_RE_ADMISSION",
      "NETWORK_EVIDENCE_NOT_AUTHORITY",
    ]);
  });

  it("every pin has a deterministic closed explanation naming its pin and its != law", () => {
    expect(Object.keys(TRANSPORT_TRUST_PIN_EXPLANATIONS).sort()).toEqual([...TRANSPORT_TRUST_PINS].sort());
    const pinned: Array<[TransportPin, string]> = [
      ["REACHABILITY_NOT_IDENTITY", "T1 REACHABILITY != IDENTITY"],
      ["IDENTITY_NOT_ADMISSION", "T2 IDENTITY != ADMISSION"],
      ["ADMISSION_NOT_AUTHORITY", "T3 ADMISSION != AUTHORITY"],
      ["AUTHENTICATED_SESSION_NOT_EXECUTION", "T4 AUTHENTICATED SESSION != EXECUTION"],
      ["REMOTE_MESSAGE_NOT_LOCAL_POLICY", "T5 REMOTE MESSAGE != LOCAL POLICY"],
      ["TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE", "T6 TRANSPORT SUCCESS != APPLICATION ACCEPTANCE"],
      ["CONNECTION_STATE_NOT_TRUST_STATE", "T7 CONNECTION STATE != TRUST STATE"],
      ["RECONNECT_NOT_RE_ADMISSION", "T8 RECONNECT != RE-ADMISSION"],
      ["NETWORK_EVIDENCE_NOT_AUTHORITY", "T9 NETWORK EVIDENCE != AUTHORITY"],
    ];
    for (const [pin, law] of pinned) {
      expect(TRANSPORT_TRUST_PIN_EXPLANATIONS[pin].startsWith(law)).toBe(true);
      expect(TRANSPORT_TRUST_PIN_EXPLANATIONS[pin]).toContain("!=");
    }
  });

  it("the closed vocabularies are pinned exactly (endpoint/outcome/refusal/close/frame/session/scope/threat)", () => {
    expect([...TRANSPORT_ENDPOINT_CLASSES]).toEqual(["loopback", "local_lan", "public", "discovery", "unknown"]);
    expect([...TRANSPORT_FORBIDDEN_BIND_ADDRESSES]).toEqual(["0.0.0.0", "::", "*", "[::]"]);
    expect([...TRANSPORT_OUTCOMES]).toEqual(["transport_connected", "transport_refused", "transport_timeout", "transport_reset"]);
    expect([...TRANSPORT_REFUSAL_CODES]).toEqual([
      "refused_public_bind",
      "refused_discovery_endpoint",
      "refused_unknown_endpoint_class",
      "refused_oversize",
      "refused_truncated",
      "refused_tampered",
      "refused_downgrade",
      "refused_replay",
      "refused_duplicate",
      "refused_reordered",
      "refused_half_closed_direction",
      "refused_stale_disclosure",
      "refused_slow_sender",
      "refused_flood",
      "refused_claim_crosses_boundary",
      "refused_out_of_transport_scope",
      "refused_unknown_scope",
      "refused_invalid_session_transition",
      "refused_anonymous_claim",
      "refused_unknown",
    ]);
    expect([...TRANSPORT_CLOSE_REASONS]).toEqual([
      "local_close",
      "remote_close",
      "authentication_failed",
      "protocol_violation",
      "timeout",
      "fault",
      "shutdown",
      "half_close_completed",
      "refused_by_gate",
    ]);
    expect([...FRAME_DISPOSITIONS]).toEqual([
      "frame_accepted",
      "refused_oversize",
      "refused_truncated",
      "refused_tampered",
      "refused_downgrade",
      "refused_replay",
      "refused_duplicate",
      "refused_reordered",
      "refused_half_closed_direction",
      "refused_stale_disclosure",
    ]);
    expect([...SESSION_STATES]).toEqual([
      "no_session",
      "connected",
      "authenticated",
      "half_closed_local",
      "half_closed_remote",
      "closed",
      "faulted",
    ]);
    expect([...SESSION_EVENTS]).toEqual([
      "connect",
      "authenticate_ok",
      "authenticate_fail",
      "local_half_close",
      "remote_half_close",
      "close",
      "fault",
      "reconnect",
    ]);
    expect([...TRANSPORT_SCOPES]).toEqual([
      "declare_local_endpoint",
      "open_local_connection",
      "send_bounded_frame",
      "receive_bounded_frame",
      "close_session",
      "record_network_evidence",
    ]);
    expect([...TRANSPORT_NON_SCOPES]).toEqual([
      "execute_tool",
      "choose_policy",
      "admit_peer",
      "grant_authority",
      "persist_record",
      "administer_peer",
      "discover_peers",
      "bind_public",
      "traverse_nat",
      "relay_cloud",
      "reach_internet",
    ]);
    expect([...TRANSPORT_THREAT_IDS]).toEqual([
      "TT-01_unknown_source",
      "TT-02_wrong_key",
      "TT-03_stale_session",
      "TT-04_replay",
      "TT-05_duplicate",
      "TT-06_truncation",
      "TT-07_oversize",
      "TT-08_slow_sender",
      "TT-09_flood",
      "TT-10_half_close_misuse",
      "TT-11_reorder",
      "TT-12_tamper",
      "TT-13_downgrade",
      "TT-14_stale_disclosure",
      "TT-15_peer_terminal_mid_session",
      "TT-16_public_bind",
      "TT-17_remote_admin",
      "TT-18_direct_tool",
    ]);
    expect([...TRANSPORT_THREAT_DISPOSITIONS]).toEqual(["refuse", "close_session", "monitor"]);
  });

  it("bounds are pinned constants with the exact recorded values (no widening)", () => {
    expect(TRANSPORT_BOUNDS).toEqual({
      maxFrameBytes: 8192,
      maxFramesPerWindow: 256,
      frameWindowMs: 1000,
      slowSenderMaxGapMs: 30000,
    });
    expect(Object.isFrozen(TRANSPORT_BOUNDS)).toBe(true);
  });
});

type TransportPin = (typeof TRANSPORT_TRUST_PINS)[number];

// ── endpoint decisions (T1, LOCAL NETWORK ONLY) ──────────────────────────────

describe("26A endpoint — LOCAL NETWORK ONLY at the contract layer", () => {
  it("loopback and local_lan are in scope; public and discovery refuse with exact codes (T1)", () => {
    const lo = decideEndpointDeclaration({ endpointClass: "loopback", bindAddress: "127.0.0.1", decidedAtEpochMs: NOW });
    expect(lo.ok).toBe(true);
    const lan = decideEndpointDeclaration({ endpointClass: "local_lan", bindAddress: "10.0.0.7", decidedAtEpochMs: NOW });
    expect(lan.ok).toBe(true);

    const pub = decideEndpointDeclaration({ endpointClass: "public", bindAddress: "203.0.113.9", decidedAtEpochMs: NOW });
    expect(pub.ok).toBe(false);
    if (!pub.ok) {
      expect(pub.refusal).toBe("refused_public_bind");
    }
    const disc = decideEndpointDeclaration({ endpointClass: "discovery", bindAddress: "10.0.0.7", decidedAtEpochMs: NOW });
    expect(disc.ok).toBe(false);
    if (!disc.ok) {
      expect(disc.refusal).toBe("refused_discovery_endpoint");
    }
  });

  it("a wildcard bind address refuses REGARDLESS of the declared class (address outranks label)", () => {
    for (const addr of ["0.0.0.0", "::", "*", "[::]"]) {
      const d = decideEndpointDeclaration({ endpointClass: "loopback", bindAddress: addr, decidedAtEpochMs: NOW });
      expect(d.ok).toBe(false);
      if (!d.ok) {
        expect(d.refusal).toBe("refused_public_bind");
      }
    }
  });

  it("endpoint decisions are deterministic: same inputs → identical decision and provenance hash; different inputs → different hash", () => {
    const a1 = decideEndpointDeclaration({ endpointClass: "loopback", bindAddress: "127.0.0.1", decidedAtEpochMs: NOW });
    const a2 = decideEndpointDeclaration({ endpointClass: "loopback", bindAddress: "127.0.0.1", decidedAtEpochMs: NOW });
    expect(a1).toEqual(a2);
    const b = decideEndpointDeclaration({ endpointClass: "loopback", bindAddress: "127.0.0.1", decidedAtEpochMs: NOW + 1 });
    expect(a1.provenanceHash).not.toBe(b.provenanceHash);
    expect(a1.provenanceHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ── frame decisions (T6/T7/T9, pinned precedence) ────────────────────────────

const GOOD_FRAME = {
  declaredBytes: 128,
  actualBytes: 128,
  sequence: 5,
  expectedSequence: 5,
  previouslyDelivered: false,
  integrityOk: true,
  protocolVersion: "menog-transport/v1",
  expectedProtocolVersion: "menog-transport/v1",
  disclosureFresh: true,
  halfClosedDirection: "none",
  frameDirection: "inbound",
} as const;

describe("26A frame — bounded deterministic decision", () => {
  it("a good frame is accepted as transport DATA only, never acceptance/authority/execution (T6/T7)", () => {
    const d = decideFrame({ ...GOOD_FRAME });
    expect(d.disposition).toBe("frame_accepted");
    expect(d.refusal).toBeNull();
    expect(d.pins).toContain("TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE");
    expect(d.pins).toContain("CONNECTION_STATE_NOT_TRUST_STATE");
    expect(d.explanation).toContain("NOT application acceptance");
  });

  it("oversize refuses against the PINNED bound (caller cannot widen it)", () => {
    const d = decideFrame({ ...GOOD_FRAME, declaredBytes: TRANSPORT_BOUNDS.maxFrameBytes + 1, actualBytes: 100 });
    expect(d.disposition).toBe("refused_oversize");
    expect(d.refusal).toBe("refused_oversize");
    // even declaring MORE than bound while sending the exact same bytes refuses:
    const d2 = decideFrame({
      ...GOOD_FRAME,
      declaredBytes: TRANSPORT_BOUNDS.maxFrameBytes + 1,
      actualBytes: TRANSPORT_BOUNDS.maxFrameBytes + 1,
    });
    expect(d2.disposition).toBe("refused_oversize");
    // exactly at the bound is fine:
    const d3 = decideFrame({
      ...GOOD_FRAME,
      declaredBytes: TRANSPORT_BOUNDS.maxFrameBytes,
      actualBytes: TRANSPORT_BOUNDS.maxFrameBytes,
    });
    expect(d3.disposition).toBe("frame_accepted");
  });

  it("truncation, tamper, downgrade, replay, duplicate, reorder, half-close, stale disclosure each refuse with their exact code", () => {
    expect(decideFrame({ ...GOOD_FRAME, actualBytes: 64 }).disposition).toBe("refused_truncated");
    expect(decideFrame({ ...GOOD_FRAME, integrityOk: false }).disposition).toBe("refused_tampered");
    expect(decideFrame({ ...GOOD_FRAME, protocolVersion: "menog-transport/v0" }).disposition).toBe("refused_downgrade");
    expect(decideFrame({ ...GOOD_FRAME, previouslyDelivered: true }).disposition).toBe("refused_replay");
    expect(decideFrame({ ...GOOD_FRAME, sequence: 4 }).disposition).toBe("refused_duplicate");
    expect(decideFrame({ ...GOOD_FRAME, sequence: 6 }).disposition).toBe("refused_reordered");
    expect(
      decideFrame({ ...GOOD_FRAME, halfClosedDirection: "local", frameDirection: "outbound" }).disposition
    ).toBe("refused_half_closed_direction");
    expect(
      decideFrame({ ...GOOD_FRAME, halfClosedDirection: "remote", frameDirection: "inbound" }).disposition
    ).toBe("refused_half_closed_direction");
    expect(decideFrame({ ...GOOD_FRAME, disclosureFresh: false }).disposition).toBe("refused_stale_disclosure");
  });

  it("check precedence is pinned: oversize wins over tamper wins over downgrade wins over replay", () => {
    const multi = decideFrame({
      ...GOOD_FRAME,
      declaredBytes: TRANSPORT_BOUNDS.maxFrameBytes + 1,
      actualBytes: TRANSPORT_BOUNDS.maxFrameBytes + 1,
      integrityOk: false,
      protocolVersion: "menog-transport/v0",
      previouslyDelivered: true,
    });
    expect(multi.disposition).toBe("refused_oversize");
    const noOversize = decideFrame({
      ...GOOD_FRAME,
      integrityOk: false,
      protocolVersion: "menog-transport/v0",
      previouslyDelivered: true,
    });
    expect(noOversize.disposition).toBe("refused_tampered");
    const noTamper = decideFrame({ ...GOOD_FRAME, protocolVersion: "menog-transport/v0", previouslyDelivered: true });
    expect(noTamper.disposition).toBe("refused_downgrade");
    const onlyReplay = decideFrame({ ...GOOD_FRAME, previouslyDelivered: true, sequence: 4 });
    expect(onlyReplay.disposition).toBe("refused_replay");
  });

  it("every frame refusal code is in the closed refusal vocabulary; accepted frames have null refusal", () => {
    const cases: Array<Parameters<typeof decideFrame>[0]> = [
      { ...GOOD_FRAME, declaredBytes: 99999, actualBytes: 99999 },
      { ...GOOD_FRAME, actualBytes: 1 },
      { ...GOOD_FRAME, integrityOk: false },
      { ...GOOD_FRAME, protocolVersion: "x" },
      { ...GOOD_FRAME, previouslyDelivered: true },
      { ...GOOD_FRAME, sequence: 1 },
      { ...GOOD_FRAME, sequence: 9 },
      { ...GOOD_FRAME, halfClosedDirection: "local", frameDirection: "outbound" },
      { ...GOOD_FRAME, disclosureFresh: false },
    ];
    for (const c of cases) {
      const d = decideFrame(c);
      expect(d.refusal).not.toBeNull();
      expect(TRANSPORT_REFUSAL_CODES as readonly string[]).toContain(d.refusal);
      expect(d.pins.length).toBeGreaterThan(0);
      for (const p of d.pins) {
        expect(TRANSPORT_TRUST_PINS as readonly string[]).toContain(p);
      }
    }
    expect(decideFrame({ ...GOOD_FRAME }).refusal).toBeNull();
  });

  it("sender pace: flood and slow sender refuse against pinned bounds; within bounds OK (T7)", () => {
    const ok = decideSenderPace({ framesInWindow: TRANSPORT_BOUNDS.maxFramesPerWindow - 1, msSinceLastFrame: 10 });
    expect(ok.ok).toBe(true);
    expect(ok.refusal).toBeNull();
    const flood = decideSenderPace({ framesInWindow: TRANSPORT_BOUNDS.maxFramesPerWindow, msSinceLastFrame: 10 });
    expect(flood.ok).toBe(false);
    expect(flood.refusal).toBe("refused_flood");
    const slow = decideSenderPace({ framesInWindow: 0, msSinceLastFrame: TRANSPORT_BOUNDS.slowSenderMaxGapMs + 1 });
    expect(slow.ok).toBe(false);
    expect(slow.refusal).toBe("refused_slow_sender");
    // determinism
    expect(decideSenderPace({ framesInWindow: 0, msSinceLastFrame: 10 })).toEqual(
      decideSenderPace({ framesInWindow: 0, msSinceLastFrame: 10 })
    );
  });
});

// ── session state machine (T2/T7/T8) ────────────────────────────────────────

describe("26A session — deterministic transport-fact state machine", () => {
  it("happy path: no_session → connect → authenticate_ok → close", () => {
    const s1 = decideSessionTransition({ state: "no_session", event: "connect" });
    expect(s1.ok).toBe(true);
    expect(s1.state).toBe("connected");
    expect(s1.trustCarried).toBe(false);
    expect(s1.freshAdmissionRequired).toBe(true);

    const s2 = decideSessionTransition({ state: "connected", event: "authenticate_ok" });
    expect(s2.ok).toBe(true);
    expect(s2.state).toBe("authenticated");
    expect(s2.trustCarried).toBe(false);
    expect(s2.freshAdmissionRequired).toBe(true);

    const s3 = decideSessionTransition({ state: "authenticated", event: "close" });
    expect(s3.ok).toBe(true);
    expect(s3.state).toBe("closed");
    expect(s3.closeReason).toBe("local_close");
    expect(s3.freshAdmissionRequired).toBe(false);
    expect(s3.trustCarried).toBe(false);
  });

  it("authentication failure closes with authentication_failed; half-close completes via the second half-close", () => {
    const fail = decideSessionTransition({ state: "connected", event: "authenticate_fail" });
    expect(fail.ok).toBe(true);
    expect(fail.state).toBe("closed");
    expect(fail.closeReason).toBe("authentication_failed");

    const h1 = decideSessionTransition({ state: "authenticated", event: "local_half_close" });
    expect(h1.state).toBe("half_closed_local");
    expect(h1.closeReason).toBeNull();
    const h2 = decideSessionTransition({ state: "half_closed_local", event: "remote_half_close" });
    expect(h2.state).toBe("closed");
    expect(h2.closeReason).toBe("half_close_completed");
    const h3 = decideSessionTransition({ state: "half_closed_remote", event: "local_half_close" });
    expect(h3.state).toBe("closed");
    expect(h3.closeReason).toBe("half_close_completed");
  });

  it("reconnect from closed/faulted starts a NEW session with ZERO trust carried and fresh admission required (T8)", () => {
    for (const from of ["closed", "faulted"] as const) {
      const r = decideSessionTransition({ state: from, event: "reconnect" });
      expect(r.ok).toBe(true);
      expect(r.state).toBe("connected");
      expect(r.trustCarried).toBe(false);
      expect(r.freshAdmissionRequired).toBe(true);
      expect(r.explanation).toContain("ZERO carried trust");
      // and reaching a usable state still requires fresh admission:
      const r2 = decideSessionTransition({ state: r.state, event: "authenticate_ok" });
      expect(r2.state).toBe("authenticated");
      expect(r2.freshAdmissionRequired).toBe(true);
    }
  });

  it("invalid transitions refuse WITHOUT changing state (fail closed)", () => {
    const cases: Array<{ state: (typeof SESSION_STATES)[number]; event: (typeof SESSION_EVENTS)[number] }> = [
      { state: "no_session", event: "authenticate_ok" },
      { state: "no_session", event: "close" },
      { state: "no_session", event: "reconnect" },
      { state: "no_session", event: "fault" },
      { state: "connected", event: "connect" },
      { state: "connected", event: "reconnect" },
      { state: "connected", event: "authenticate_ok" }, // placeholder — replaced below
      { state: "authenticated", event: "connect" },
      { state: "authenticated", event: "reconnect" },
      { state: "authenticated", event: "authenticate_ok" },
      { state: "authenticated", event: "authenticate_fail" },
      { state: "half_closed_local", event: "connect" },
      { state: "half_closed_local", event: "local_half_close" },
      { state: "closed", event: "close" },
      { state: "closed", event: "authenticate_ok" },
      { state: "faulted", event: "fault" },
    ];
    // 'connected + authenticate_ok' is LEGAL — swap it for a genuinely invalid one:
    const fixed = cases.filter((c) => !(c.state === "connected" && c.event === "authenticate_ok"));
    fixed.push({ state: "half_closed_remote", event: "remote_half_close" });
    for (const c of fixed) {
      const r = decideSessionTransition(c);
      expect(r.ok, c.state + "+" + c.event).toBe(false);
      expect(r.code).toBe("session_transition_refused");
      expect(r.state).toBe(c.state); // UNCHANGED
      expect(r.refusal).toBe("refused_invalid_session_transition");
      expect(r.trustCarried).toBe(false);
    }
  });

  it("every possible transition (7 states × 8 events) is deterministic, trust-free, and pins fresh admission on usable states", () => {
    const states = [...SESSION_STATES];
    const events = [...SESSION_EVENTS];
    const results = new Map<string, string>();
    for (const s of states) {
      for (const e of events) {
        const r = decideSessionTransition({ state: s, event: e });
        const key = s + "+" + e;
        // determinism across repeated evaluation
        const again = decideSessionTransition({ state: s, event: e });
        expect(r).toEqual(again);
        results.set(key, r.state);
        // structural laws on EVERY result:
        expect(r.trustCarried).toBe(false);
        const usable = r.state === "connected" || r.state === "authenticated" ||
          r.state === "half_closed_local" || r.state === "half_closed_remote";
        expect(r.freshAdmissionRequired).toBe(usable);
        // the state vocabulary contains no trust/admission/authority state:
        expect(["no_session", "connected", "authenticated", "half_closed_local", "half_closed_remote", "closed", "faulted"]).toContain(r.state);
        // refusal (when present) is in the closed vocabulary:
        if (r.refusal !== null) {
          expect(TRANSPORT_REFUSAL_CODES as readonly string[]).toContain(r.refusal);
        }
        // close reason (when present) is in the closed vocabulary:
        if (r.closeReason !== null) {
          expect(TRANSPORT_CLOSE_REASONS as readonly string[]).toContain(r.closeReason);
        }
      }
    }
    expect(results.size).toBe(56);
  });
});

// ── scope vocabulary (T3/T4/T5) ──────────────────────────────────────────────

describe("26A scope — closed MAY / MAY-NOT sets", () => {
  it("every MAY capability passes with a bounded explanation", () => {
    for (const cap of TRANSPORT_SCOPES) {
      const d = decideTransportScope({ capability: cap });
      expect(d.ok).toBe(true);
      if (d.ok) {
        expect(d.scope).toBe(cap);
        expect(d.explanation).toContain("executes nothing");
      }
    }
  });

  it("every MAY-NOT capability refuses naming its pin", () => {
    const expected: Record<string, string> = {
      execute_tool: "AUTHENTICATED_SESSION_NOT_EXECUTION",
      choose_policy: "REMOTE_MESSAGE_NOT_LOCAL_POLICY",
      admit_peer: "IDENTITY_NOT_ADMISSION",
      grant_authority: "ADMISSION_NOT_AUTHORITY",
      persist_record: "NETWORK_EVIDENCE_NOT_AUTHORITY",
      administer_peer: "ADMISSION_NOT_AUTHORITY",
      discover_peers: "REACHABILITY_NOT_IDENTITY",
      bind_public: "REACHABILITY_NOT_IDENTITY",
      traverse_nat: "REACHABILITY_NOT_IDENTITY",
      relay_cloud: "REACHABILITY_NOT_IDENTITY",
      reach_internet: "REACHABILITY_NOT_IDENTITY",
    };
    for (const cap of TRANSPORT_NON_SCOPES) {
      const d = decideTransportScope({ capability: cap });
      expect(d.ok).toBe(false);
      if (!d.ok) {
        expect(d.refusal).toBe("refused_out_of_transport_scope");
        expect(d.violatedPin).toBe(expected[cap]);
        expect(TRANSPORT_TRUST_PINS as readonly string[]).toContain(d.violatedPin ?? "");
      }
    }
  });

  it("unknown capabilities refuse with null pin (fail closed, no guessing)", () => {
    const d = decideTransportScope({ capability: "totally_new_capability" });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.refusal).toBe("refused_unknown_scope");
      expect(d.violatedPin).toBeNull();
    }
  });
});

// ── transport claims (the nine pins) ─────────────────────────────────────────

describe("26A claims — facts receivable as DATA, conflation claims refused", () => {
  it("the four fact claims are receivable as DATA and grant nothing (T1/T2/T3/T5)", () => {
    for (const kind of ["reachability_fact", "identity_fact", "admission_fact", "frame_data_fact"] as const) {
      const d = decideTransportClaim({ claimKind: kind, subject: NODE_A, decidedAtEpochMs: NOW });
      expect(d.ok).toBe(true);
      if (d.ok) {
        expect(d.code).toBe("claim_received_as_data");
        expect(d.explanation).toContain("DATA");
      }
    }
  });

  it("the six conflation claims refuse, each naming its exact violated pin (T4/T5/T6/T7/T8/T9)", () => {
    const expected: Array<[Parameters<typeof decideTransportClaim>[0]["claimKind"], string]> = [
      ["authenticated_session_execution_claim", "AUTHENTICATED_SESSION_NOT_EXECUTION"],
      ["remote_message_policy_claim", "REMOTE_MESSAGE_NOT_LOCAL_POLICY"],
      ["transport_success_acceptance_claim", "TRANSPORT_SUCCESS_NOT_APPLICATION_ACCEPTANCE"],
      ["connection_state_trust_claim", "CONNECTION_STATE_NOT_TRUST_STATE"],
      ["reconnect_readmission_claim", "RECONNECT_NOT_RE_ADMISSION"],
      ["network_evidence_authority_claim", "NETWORK_EVIDENCE_NOT_AUTHORITY"],
    ];
    for (const [kind, pin] of expected) {
      const d = decideTransportClaim({ claimKind: kind, subject: NODE_A, decidedAtEpochMs: NOW });
      expect(d.ok, kind).toBe(false);
      if (!d.ok) {
        expect(d.code).toBe("claim_crosses_boundary");
        expect(d.violatedPin).toBe(pin);
        expect(d.explanation).toContain(pin.split("_")[0] ?? pin.slice(0, 2));
      }
    }
  });

  it("an anonymous subject refuses before evaluation (fail closed)", () => {
    const d = decideTransportClaim({ claimKind: "identity_fact", subject: "", decidedAtEpochMs: NOW });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.violatedPin).toBe("REACHABILITY_NOT_IDENTITY");
      expect(d.explanation).toContain("anonymous");
    }
  });

  it("claim decisions are deterministic via the provenance hash", () => {
    const a = decideTransportClaim({ claimKind: "reconnect_readmission_claim", subject: NODE_A, decidedAtEpochMs: NOW });
    const b = decideTransportClaim({ claimKind: "reconnect_readmission_claim", subject: NODE_A, decidedAtEpochMs: NOW });
    expect(a).toEqual(b);
    if (!a.ok && !b.ok) {
      expect(a.provenanceHash).toBe(b.provenanceHash);
      expect(a.provenanceHash).toMatch(/^[0-9a-f]{64}$/);
    }
    const c = decideTransportClaim({ claimKind: "reconnect_readmission_claim", subject: NODE_A, decidedAtEpochMs: NOW + 1 });
    if (!a.ok && !c.ok) {
      expect(a.provenanceHash).not.toBe(c.provenanceHash);
    }
  });
});

// ── threat catalog TT-01..TT-18 ──────────────────────────────────────────────

describe("26A threats — closed catalog with deterministic dispositions", () => {
  it("all eighteen pack threats classify deterministically with closed dispositions, codes, and pins", () => {
    expect(TRANSPORT_THREAT_IDS.length).toBe(18);
    const expectedDispositions: Record<string, string> = {
      "TT-01_unknown_source": "refuse",
      "TT-02_wrong_key": "close_session",
      "TT-03_stale_session": "refuse",
      "TT-04_replay": "refuse",
      "TT-05_duplicate": "refuse",
      "TT-06_truncation": "refuse",
      "TT-07_oversize": "refuse",
      "TT-08_slow_sender": "close_session",
      "TT-09_flood": "close_session",
      "TT-10_half_close_misuse": "refuse",
      "TT-11_reorder": "refuse",
      "TT-12_tamper": "close_session",
      "TT-13_downgrade": "refuse",
      "TT-14_stale_disclosure": "refuse",
      "TT-15_peer_terminal_mid_session": "close_session",
      "TT-16_public_bind": "refuse",
      "TT-17_remote_admin": "refuse",
      "TT-18_direct_tool": "refuse",
    };
    for (const id of TRANSPORT_THREAT_IDS) {
      const c1 = classifyTransportThreat(id);
      const c2 = classifyTransportThreat(id);
      expect(c1, id).toEqual(c2); // deterministic
      expect(c1.threatId).toBe(id);
      expect(c1.disposition).toBe(expectedDispositions[id]);
      expect(TRANSPORT_THREAT_DISPOSITIONS as readonly string[]).toContain(c1.disposition);
      expect(TRANSPORT_REFUSAL_CODES as readonly string[]).toContain(c1.refusal);
      expect(c1.pins.length).toBeGreaterThan(0);
      for (const p of c1.pins) {
        expect(TRANSPORT_TRUST_PINS as readonly string[]).toContain(p);
      }
      expect(c1.explanation).toContain(id.split("_")[0] ?? id.slice(0, 4));
      expect(c1.explanation).toMatch(/T[1-9]/);
    }
  });

  it("the three pack-law threats refuse with the exact pin semantics (T1/T3/T4)", () => {
    const pub = classifyTransportThreat("TT-16_public_bind");
    expect(pub.refusal).toBe("refused_public_bind");
    expect(pub.pins).toContain("REACHABILITY_NOT_IDENTITY");
    const admin = classifyTransportThreat("TT-17_remote_admin");
    expect(admin.refusal).toBe("refused_out_of_transport_scope");
    expect(admin.pins).toContain("ADMISSION_NOT_AUTHORITY");
    expect(admin.explanation).toContain("no remote control plane");
    const tool = classifyTransportThreat("TT-18_direct_tool");
    expect(tool.refusal).toBe("refused_out_of_transport_scope");
    expect(tool.pins).toContain("AUTHENTICATED_SESSION_NOT_EXECUTION");
    expect(tool.explanation).toContain("Phase-21");
  });
});

// ── fingerprint (pure self-description) ──────────────────────────────────────

describe("26A fingerprint — deterministic self-description", () => {
  it("same inputs → identical hash; different inputs → different hash; no I/O", () => {
    const f1 = transportTrustFingerprint({ localNodeId: NODE_A, decidedAtEpochMs: NOW });
    const f2 = transportTrustFingerprint({ localNodeId: NODE_A, decidedAtEpochMs: NOW });
    expect(f1).toBe(f2);
    expect(f1).toMatch(/^[0-9a-f]{64}$/);
    const f3 = transportTrustFingerprint({ localNodeId: NODE_A, decidedAtEpochMs: NOW + 1 });
    expect(f1).not.toBe(f3);
    const f4 = transportTrustFingerprint({ localNodeId: null, decidedAtEpochMs: NOW });
    expect(f1).not.toBe(f4);
  });
});
