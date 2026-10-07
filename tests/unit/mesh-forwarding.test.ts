/**
 * PHASE 27F — Multi-Hop Proposal Forwarding Tests (GOVERNED / FORWARD !=
 * ENDORSE / ORIGIN IMMUTABLE / APPEND-ONLY PROVENANCE / BOUNDED HOP
 * BUDGET / REPLAY REFUSED).
 *
 * Pins the forwarding registry's laws structurally and behaviorally:
 *   · closed vocabularies + frozen bounds (pinned exact values);
 *   · structural zero-authority literals on EVERY success (authority
 *     "none", endorsement "none", originFixed true, capabilityWidened /
 *     admissionBypassed / executionAuthorized false) plus the 27A M4
 *     law text;
 *   · no endorse/approve/grant/authorize export surface, no trust/Policy
 *     token in module source (no network/store/clock either);
 *   · multi-hop chains preserve origin, destination, identity, and
 *     append-only provenance across every hop;
 *   · hop limits: budget within [1, maxHops] at birth, descends by
 *     EXACTLY one, exhausts at maxHops, never re-inflates;
 *   · origin substitution refused (incl. the composed 27A
 *     forwarder_origin_claim refusal naming FORWARDER_NOT_ORIGIN);
 *   · identity mutation (id ↔ hash binding) and destination mutation
 *     refused; provenance stripping refused, additions append;
 *   · replay: completed hops and repeat forwarders refuse; skipped hops
 *     refuse out-of-sequence; refusals leave the registry byte-identical;
 *   · 25D material scan over every string surface (secret / executable /
 *     forbidden material refuse — JSON-nested payloads parsed at depth);
 *   · bounded registry (64 proposals) refuses, never evicts;
 *   · deterministic snapshots/fingerprints; frozen records; no I/O.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  FORWARDING_SCHEMA_VERSION,
  FORWARDING_BOUNDS,
  FORWARDING_REFUSAL_CODES,
  ProposalForwardingRegistry,
  type ForwardDecision,
  type ForwardInput,
  type ForwardRefusalCode,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

/** Surfaces the 27F module must NEVER contain (structural no-socket pin). */
const FORBIDDEN_SURFACES: readonly string[] = Object.freeze([
  "child_process",
  "node:net",
  "node:http",
  "node:https",
  "node:dgram",
  "node:tls",
  "node:dns",
  "node:crypto",
  "WebSocket",
  "fetch(",
  "spawn(",
  "listen(",
  "createServer",
  "connect(",
  "createSocket",
  "createHash",
  "DatabaseSync",
  "acceptMutation",
  "setInterval",
  "setTimeout",
  "Date.now",
  "performance.now",
  ".persist(",
  "DurableStore",
  "PeerRegistry",
  "executeToolRun",
  "runIsolated",
  "toolJunction",
  "requireTool",
]);

/** The ONLY modules the 27F module may import (pinned). */
const ALLOWED_IMPORTS = Object.freeze([
  "./canonical.js",
  "./federationEgress.js",
  "./federationProposals.js",
  "./meshTopologyTrust.js",
]);

/** Law tokens that must never appear in the forwarding module's source. */
const FORBIDDEN_LAW_TOKENS: readonly string[] = Object.freeze([
  "isPeerTrustTransition",
  "PEER_TRUST_TRANSITIONS",
  "trustState",
  "policyEngine",
  "evaluatePolicy",
  "authorize(",
  "admit(",
  "granted",
]);

const NOW = 1_700_000_000_000;

/** 24E-canonical proposal ids (fp-<16hex>-<16alnum>) and hash refs. */
const FP_ID = "fp-0123456789abcdef-a1b2c3d4e5f6a7b8";
const FP_ID_2 = "fp-fedcba9876543210-b8a7f6e5d4c3b2a1";
const FP_HASH = "sha256-" + "a".repeat(64);
const FP_HASH_2 = "sha256-" + "b".repeat(64);

const FWD = (over: Partial<ForwardInput> = {}): ForwardInput => ({
  proposalId: FP_ID,
  proposalHash: FP_HASH,
  originNodeId: "node-origin",
  destinationNodeId: "node-dest",
  forwarderNodeId: "node-f1",
  hopIndex: 0,
  hopBudgetRemaining: 8,
  provenanceRefs: ["ev-1"],
  observedAtEpochMs: NOW,
  ...over,
});

/** Every success carries the structural zero-authority literals + law text. */
function expectForwarded(d: ForwardDecision): void {
  expect(d.ok).toBe(true);
  if (d.ok) {
    expect(d.code).toBe("proposal_forwarded");
    expect(d.authority).toBe("none");
    expect(d.endorsement).toBe("none");
    expect(d.originFixed).toBe(true);
    expect(d.capabilityWidened).toBe(false);
    expect(d.admissionBypassed).toBe(false);
    expect(d.executionAuthorized).toBe(false);
    expect(d.forwardHash).toMatch(/^[0-9a-f]{64}$/);
    expect(Object.isFrozen(d.forwarderChain)).toBe(true);
    expect(Object.isFrozen(d.provenanceRefs)).toBe(true);
    expect(d.explanation).toContain("FORWARD != ENDORSE");
    expect(d.explanation).toContain("fresh LOCAL allocation");
    expect(d.explanation).toContain("M4 FORWARDER != ORIGIN");
  }
}

function expectForwardRefusal(d: ForwardDecision, refusal: ForwardRefusalCode): void {
  expect(d.ok).toBe(false);
  if (!d.ok) {
    expect(d.code).toBe("forward_refused");
    expect(d.refusal).toBe(refusal);
    expect(d.explanation.length).toBeGreaterThan(20);
    expect(d.explanation).toMatch(/refus/);
    expect(d.forwardHash).toMatch(/^[0-9a-f]{64}$/);
    expect("authority" in d).toBe(false);
    expect("endorsement" in d).toBe(false);
    expect("executionAuthorized" in d).toBe(false);
  }
}

// ── structural pins ──────────────────────────────────────────────────────────

describe("27F structure — closed vocabulary, frozen bounds, zero-authority source", () => {
  it("forbidden surfaces list is pinned and the module contains none of them", () => {
    expect(FORBIDDEN_SURFACES).toEqual([
      "child_process",
      "node:net",
      "node:http",
      "node:https",
      "node:dgram",
      "node:tls",
      "node:dns",
      "node:crypto",
      "WebSocket",
      "fetch(",
      "spawn(",
      "listen(",
      "createServer",
      "connect(",
      "createSocket",
      "createHash",
      "DatabaseSync",
      "acceptMutation",
      "setInterval",
      "setTimeout",
      "Date.now",
      "performance.now",
      ".persist(",
      "DurableStore",
      "PeerRegistry",
      "executeToolRun",
      "runIsolated",
      "toolJunction",
      "requireTool",
    ]);
    const code = codeOnly(SRC("meshForwarding.ts"));
    for (const forbidden of FORBIDDEN_SURFACES) {
      expect(code).not.toContain(forbidden);
    }
  });

  it("module imports ONLY the pinned local modules (no network, no store, no clock)", () => {
    const src = SRC("meshForwarding.ts");
    const imports = [
      ...[...src.matchAll(/^import [^\n]* from "([^"]+)"/gm)].map((m) => m[1] as string),
      ...[...src.matchAll(/^\} from "([^"]+)"/gm)].map((m) => m[1] as string),
    ].sort();
    expect(imports).toEqual([...ALLOWED_IMPORTS].sort());
  });

  it("schema version and forwarding bounds are pinned frozen constants", () => {
    expect(FORWARDING_SCHEMA_VERSION).toBe("menog-mesh-forwarding/v0");
    expect(FORWARDING_BOUNDS).toEqual({
      maxHops: 8,
      maxTrackedProposals: 64,
      maxProvenanceRefs: 16,
      maxNodeIdChars: 128,
      maxProvenanceRefChars: 128,
    });
    expect(Object.isFrozen(FORWARDING_BOUNDS)).toBe(true);
  });

  it("refusal vocabulary is a pinned frozen closed set (fail-closed, no silent handling)", () => {
    expect([...FORWARDING_REFUSAL_CODES]).toEqual([
      "refused_invalid_forward",
      "refused_field_bound",
      "refused_secret_material",
      "refused_executable_material",
      "refused_forbidden_material",
      "refused_origin_substitution",
      "refused_identity_mutation",
      "refused_destination_mutation",
      "refused_provenance_stripped",
      "refused_replay",
      "refused_hop_out_of_sequence",
      "refused_hop_limit",
      "refused_registry_bound",
      "refused_unknown",
    ]);
    expect(Object.isFrozen(FORWARDING_REFUSAL_CODES)).toBe(true);
  });

  it("every authority/endorsement literal in source is the structural 'none'/false (no trust, no Policy token)", () => {
    const code = codeOnly(SRC("meshForwarding.ts"));
    for (const match of code.matchAll(/authority:\s*"[^"]*"/g)) {
      expect(match[0]).toBe('authority: "none"');
    }
    for (const match of code.matchAll(/endorsement:\s*"[^"]*"/g)) {
      expect(match[0]).toBe('endorsement: "none"');
    }
    expect(code).not.toContain("executionAuthorized: true");
    expect(code).not.toContain("capabilityWidened: true");
    expect(code).not.toContain("admissionBypassed: true");
    expect(code).not.toContain("originFixed: false");
    for (const token of FORBIDDEN_LAW_TOKENS) {
      expect(code).not.toContain(token);
    }
  });

  it("export surface: ONE registry class, pinned prototype methods, no endorse/approve/grant method", () => {
    const code = codeOnly(SRC("meshForwarding.ts"));
    const classes = [...code.matchAll(/^export class (\w+)/gm)].map((m) => m[1] as string);
    expect(classes).toEqual(["ProposalForwardingRegistry"]);
    expect(code).not.toContain("export function");
    const methods = Object.getOwnPropertyNames(ProposalForwardingRegistry.prototype).sort();
    expect(methods).toEqual([
      "constructor",
      "fingerprint",
      "forward",
      "get",
      "has",
      "proposalCount",
      "snapshot",
    ]);
    for (const name of methods) {
      expect(name).not.toMatch(/union|merge|endorse|approv|grant|trust|authoriz|admit/i);
    }
    expect(typeof ProposalForwardingRegistry.open).toBe("function");
    const exportNames = [...code.matchAll(/^export (?:const|type|interface) (\w+)/gm)].map(
      (m) => m[1] as string,
    );
    for (const name of exportNames) {
      expect(name).not.toMatch(/authoriz|approv|admit|grant|endorse/i);
    }
    const registry = ProposalForwardingRegistry.open();
    expect(Object.keys(registry)).toEqual([]);
  });
});

// ── governed multi-hop chain ──────────────────────────────────────────────────

describe("27F forwarding — governed multi-hop chain (zero-authority literals)", () => {
  it("a first forward records append-only knowledge with the budget decremented", () => {
    const registry = ProposalForwardingRegistry.open();
    const d = registry.forward(FWD());
    expectForwarded(d);
    expect(registry.proposalCount).toBe(1);
    expect(registry.has(FP_ID)).toBe(true);
    if (d.ok) {
      expect([...d.forwarderChain]).toEqual(["node-f1"]);
      expect([...d.provenanceRefs]).toEqual(["ev-1"]);
      expect(d.hopIndex).toBe(0);
      expect(d.hopBudgetRemaining).toBe(7); // 8 → 7: exactly one consumed
      expect(d.forwardCount).toBe(1);
      expect(d.originNodeId).toBe("node-origin");
      expect(d.destinationNodeId).toBe("node-dest");
      expect(d.proposalHash).toBe(FP_HASH);
    }
    const record = registry.get(FP_ID);
    expect(record).not.toBeNull();
    expect(Object.isFrozen(record)).toBe(true);
    if (record) {
      expect(Object.isFrozen(record.forwarderChain)).toBe(true);
      expect(Object.isFrozen(record.provenanceRefs)).toBe(true);
      expect(record.hopBudgetRemaining).toBe(7);
      expect(record.observedAtEpochMs).toBe(NOW);
    }
    expect(registry.get("fp-0000000000000000-0000000000000000")).toBeNull();
    expect(registry.has("fp-0000000000000000-0000000000000000")).toBe(false);
  });

  it("three hops accumulate forwarders and provenance while origin/identity stay fixed", () => {
    const registry = ProposalForwardingRegistry.open();
    const hop1 = registry.forward(FWD());
    expectForwarded(hop1);
    if (hop1.ok) {
      expect([...hop1.forwarderChain]).toEqual(["node-f1"]);
      expect(hop1.hopBudgetRemaining).toBe(7);
    }
    const hop2 = registry.forward(
      FWD({ forwarderNodeId: "node-f2", hopIndex: 1, hopBudgetRemaining: 7, provenanceRefs: ["ev-1", "ev-2"] }),
    );
    expectForwarded(hop2);
    if (hop2.ok) {
      expect([...hop2.forwarderChain]).toEqual(["node-f1", "node-f2"]);
      expect([...hop2.provenanceRefs]).toEqual(["ev-1", "ev-2"]);
      expect(hop2.hopBudgetRemaining).toBe(6);
      expect(hop2.forwardCount).toBe(2);
      expect(hop2.originNodeId).toBe("node-origin");
    }
    const hop3 = registry.forward(
      FWD({ forwarderNodeId: "node-f3", hopIndex: 2, hopBudgetRemaining: 6, provenanceRefs: ["ev-1", "ev-2", "ev-3"] }),
    );
    expectForwarded(hop3);
    const record = registry.get(FP_ID);
    expect(record).not.toBeNull();
    if (record) {
      expect([...record.forwarderChain]).toEqual(["node-f1", "node-f2", "node-f3"]);
      expect([...record.provenanceRefs]).toEqual(["ev-1", "ev-2", "ev-3"]);
      expect(record.originNodeId).toBe("node-origin"); // origin never moved
      expect(record.destinationNodeId).toBe("node-dest");
      expect(record.proposalHash).toBe(FP_HASH);
      expect(record.hopIndex).toBe(2);
      expect(record.hopBudgetRemaining).toBe(5);
      expect(record.forwardCount).toBe(3);
    }
  });

  it("identical sequences in fresh registries are byte-identical (pure, no clock)", () => {
    const build = (): { registry: ProposalForwardingRegistry; last: ForwardDecision } => {
      const registry = ProposalForwardingRegistry.open();
      registry.forward(FWD());
      const last = registry.forward(
        FWD({ forwarderNodeId: "node-f2", hopIndex: 1, hopBudgetRemaining: 7 }),
      );
      return { registry, last };
    };
    const a = build();
    const b = build();
    expectForwarded(a.last);
    expect(JSON.stringify(a.last)).toBe(JSON.stringify(b.last));
    expect(a.registry.fingerprint()).toBe(b.registry.fingerprint());
  });

  it("two proposals with DIFFERENT hashes coexist independently in one registry", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwarded(registry.forward(FWD()));
    expectForwarded(
      registry.forward(FWD({ proposalId: FP_ID_2, proposalHash: FP_HASH_2, forwarderNodeId: "node-f9" })),
    );
    expect(registry.proposalCount).toBe(2);
    const first = registry.get(FP_ID);
    const second = registry.get(FP_ID_2);
    expect(first?.proposalHash).toBe(FP_HASH);
    expect(second?.proposalHash).toBe(FP_HASH_2);
  });
});

// ── hop limits ───────────────────────────────────────────────────────────────

describe("27F hop budget — bounded at birth, descends by exactly one, never re-inflates", () => {
  it("a new proposal budget outside [1, maxHops] refuses hop_limit", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwardRefusal(
      registry.forward(FWD({ hopBudgetRemaining: FORWARDING_BOUNDS.maxHops + 1 })),
      "refused_hop_limit",
    );
    expectForwardRefusal(registry.forward(FWD({ hopBudgetRemaining: 0 })), "refused_hop_limit");
    expectForwardRefusal(registry.forward(FWD({ hopBudgetRemaining: -3 })), "refused_hop_limit");
    expect(registry.proposalCount).toBe(0);
  });

  it("a non-integer budget is malformed, not a hop problem", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwardRefusal(registry.forward(FWD({ hopBudgetRemaining: 1.5 })), "refused_invalid_forward");
    expect(registry.proposalCount).toBe(0);
  });

  it("eight hops consume the whole budget; the ninth refuses and nothing evicts", () => {
    const registry = ProposalForwardingRegistry.open();
    for (let hop = 0; hop < FORWARDING_BOUNDS.maxHops; hop += 1) {
      const d = registry.forward(
        FWD({
          forwarderNodeId: "node-f" + hop,
          hopIndex: hop,
          hopBudgetRemaining: FORWARDING_BOUNDS.maxHops - hop,
        }),
      );
      expectForwarded(d);
      if (d.ok) {
        expect(d.hopBudgetRemaining).toBe(FORWARDING_BOUNDS.maxHops - hop - 1);
      }
    }
    const record = registry.get(FP_ID);
    expect(record?.forwardCount).toBe(FORWARDING_BOUNDS.maxHops);
    expect(record?.hopBudgetRemaining).toBe(0);
    const fingerprint = registry.fingerprint();
    const exhausted = registry.forward(
      FWD({ forwarderNodeId: "node-f8", hopIndex: 8, hopBudgetRemaining: 0 }),
    );
    expectForwardRefusal(exhausted, "refused_hop_limit");
    expect(registry.proposalCount).toBe(1);
    expect(registry.fingerprint()).toBe(fingerprint);
  });

  it("a budget that fails to descend by exactly one refuses (no re-inflation, no skip)", () => {
    const registry = ProposalForwardingRegistry.open();
    registry.forward(FWD()); // budget 8 → stored 7
    const fingerprint = registry.fingerprint();
    for (const presented of [8, 9, 5, 0, -1]) {
      expectForwardRefusal(
        registry.forward(FWD({ forwarderNodeId: "node-f2", hopIndex: 1, hopBudgetRemaining: presented })),
        "refused_hop_limit",
      );
    }
    expect(registry.fingerprint()).toBe(fingerprint); // refusals change nothing
  });
});

// ── origin immutability (27A M4) ──────────────────────────────────────────────

describe("27F origin immutability — a forwarder can never be or replace the origin", () => {
  it("a forwarder presenting itself as origin refuses with the composed 27A pin text", () => {
    const registry = ProposalForwardingRegistry.open();
    const d = registry.forward(FWD({ forwarderNodeId: "node-origin" }));
    expectForwardRefusal(d, "refused_origin_substitution");
    if (!d.ok) {
      expect(d.explanation).toContain("M4 FORWARDER != ORIGIN");
      expect(d.explanation).toContain("crosses the boundary"); // 27A decideMeshClaim text
    }
    expect(registry.proposalCount).toBe(0);
  });

  it("a later hop that changes the recorded origin refuses and the record keeps the origin", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwarded(registry.forward(FWD()));
    const fingerprint = registry.fingerprint();
    const d = registry.forward(
      FWD({
        forwarderNodeId: "node-f2",
        hopIndex: 1,
        hopBudgetRemaining: 7,
        originNodeId: "node-evil",
      }),
    );
    expectForwardRefusal(d, "refused_origin_substitution");
    if (!d.ok) {
      expect(d.explanation).toContain("crosses the boundary");
    }
    expect(registry.get(FP_ID)?.originNodeId).toBe("node-origin");
    expect(registry.fingerprint()).toBe(fingerprint);
  });

  it("origin substitution outranks an out-of-sequence hop (pinned order)", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwarded(registry.forward(FWD()));
    const d = registry.forward(
      FWD({
        forwarderNodeId: "node-f2",
        hopIndex: 5, // also out of sequence
        hopBudgetRemaining: 7,
        originNodeId: "node-evil",
      }),
    );
    expectForwardRefusal(d, "refused_origin_substitution");
  });
});

// ── identity + destination immutability ──────────────────────────────────────

describe("27F identity — proposalId ↔ proposalHash binding and destination are fixed", () => {
  it("the same proposal id with a DIFFERENT hash refuses identity_mutation", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwarded(registry.forward(FWD()));
    const fingerprint = registry.fingerprint();
    expectForwardRefusal(
      registry.forward(
        FWD({ forwarderNodeId: "node-f2", hopIndex: 1, hopBudgetRemaining: 7, proposalHash: FP_HASH_2 }),
      ),
      "refused_identity_mutation",
    );
    expect(registry.get(FP_ID)?.proposalHash).toBe(FP_HASH);
    expect(registry.fingerprint()).toBe(fingerprint);
  });

  it("a DIFFERENT proposal id presenting an ALREADY-BOUND hash refuses identity_mutation", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwarded(registry.forward(FWD()));
    expectForwardRefusal(
      registry.forward(FWD({ proposalId: FP_ID_2 })), // same hash, new id
      "refused_identity_mutation",
    );
    expect(registry.proposalCount).toBe(1);
  });

  it("a changed destination refuses destination_mutation and the record keeps it", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwarded(registry.forward(FWD()));
    const fingerprint = registry.fingerprint();
    expectForwardRefusal(
      registry.forward(
        FWD({
          forwarderNodeId: "node-f2",
          hopIndex: 1,
          hopBudgetRemaining: 7,
          destinationNodeId: "node-elsewhere",
        }),
      ),
      "refused_destination_mutation",
    );
    expect(registry.get(FP_ID)?.destinationNodeId).toBe("node-dest");
    expect(registry.fingerprint()).toBe(fingerprint);
  });
});

// ── provenance append-only ────────────────────────────────────────────────────

describe("27F provenance — append-only history: additions allowed, stripping never", () => {
  it("dropping a recorded ref refuses provenance_stripped and history is unchanged", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwarded(registry.forward(FWD({ provenanceRefs: ["ev-1", "ev-2"] })));
    const fingerprint = registry.fingerprint();
    expectForwardRefusal(
      registry.forward(
        FWD({ forwarderNodeId: "node-f2", hopIndex: 1, hopBudgetRemaining: 7, provenanceRefs: ["ev-1"] }),
      ),
      "refused_provenance_stripped",
    );
    expect([...(registry.get(FP_ID)?.provenanceRefs ?? [])]).toEqual(["ev-1", "ev-2"]);
    expect(registry.fingerprint()).toBe(fingerprint);
  });

  it("new refs append in order and duplicates never pad the history", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwarded(registry.forward(FWD({ provenanceRefs: ["ev-1", "ev-2"] })));
    const d = registry.forward(
      FWD({
        forwarderNodeId: "node-f2",
        hopIndex: 1,
        hopBudgetRemaining: 7,
        provenanceRefs: ["ev-1", "ev-2", "ev-2", "ev-3"],
      }),
    );
    expectForwarded(d);
    expect([...(registry.get(FP_ID)?.provenanceRefs ?? [])]).toEqual(["ev-1", "ev-2", "ev-3"]);
    expect(registry.get(FP_ID)?.provenanceRefs.length).toBe(3);
  });
});

// ── replay + sequence ───────────────────────────────────────────────────────────

describe("27F replay context — completed hops and repeat forwarders refuse", () => {
  it("an identical re-forward refuses replay and the registry stays byte-identical", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwarded(registry.forward(FWD()));
    const fingerprint = registry.fingerprint();
    expectForwardRefusal(registry.forward(FWD()), "refused_replay");
    expect(registry.proposalCount).toBe(1);
    expect(registry.fingerprint()).toBe(fingerprint);
  });

  it("a forwarder already IN the chain can never forward the proposal again", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwarded(registry.forward(FWD()));
    // node-f1 (hop 0) tries to continue as if it were the next hop
    expectForwardRefusal(
      registry.forward(FWD({ forwarderNodeId: "node-f1", hopIndex: 1, hopBudgetRemaining: 7 })),
      "refused_replay",
    );
    expect(registry.get(FP_ID)?.forwardCount).toBe(1);
  });

  it("a hop BEHIND the recorded position is a replay; a hop AHEAD is out of sequence", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwarded(registry.forward(FWD()));
    // completed hop 0 re-presented (behind) → replay (checked before sequence)
    expectForwardRefusal(
      registry.forward(FWD({ forwarderNodeId: "node-f2", hopIndex: 0, hopBudgetRemaining: 7 })),
      "refused_replay",
    );
    // hop 3 with only 1 completed (ahead) → out of sequence
    expectForwardRefusal(
      registry.forward(FWD({ forwarderNodeId: "node-f2", hopIndex: 3, hopBudgetRemaining: 7 })),
      "refused_hop_out_of_sequence",
    );
    // a NEW proposal must start at hop 0
    expectForwardRefusal(
      registry.forward(FWD({ proposalId: FP_ID_2, proposalHash: FP_HASH_2, hopIndex: 2 })),
      "refused_hop_out_of_sequence",
    );
    expect(registry.proposalCount).toBe(1);
  });
});

// ── registry bound ────────────────────────────────────────────────────────────

describe("27F registry bound — refuse, never evict, recorded proposals still advance", () => {
  it("the 65th NEW proposal refuses; an already-recorded one continues", () => {
    const registry = ProposalForwardingRegistry.open();
    for (let index = 0; index < FORWARDING_BOUNDS.maxTrackedProposals; index += 1) {
      const d = registry.forward(
        FWD({
          proposalId: "fp-" + index.toString(16).padStart(16, "0") + "-cccccccccccccccc",
          proposalHash: "sha256-" + index.toString(16).padStart(64, "0"),
        }),
      );
      expectForwarded(d);
    }
    expect(registry.proposalCount).toBe(FORWARDING_BOUNDS.maxTrackedProposals);
    const fingerprint = registry.fingerprint();
    expectForwardRefusal(
      registry.forward(
        FWD({
          proposalId: "fp-" + FORWARDING_BOUNDS.maxTrackedProposals.toString(16).padStart(16, "0") + "-cccccccccccccccc",
          proposalHash: "sha256-" + FORWARDING_BOUNDS.maxTrackedProposals.toString(16).padStart(64, "0"),
        }),
      ),
      "refused_registry_bound",
    );
    expect(registry.fingerprint()).toBe(fingerprint);
    // a RECORDED proposal advances even at capacity (bound = new only)
    expectForwarded(
      registry.forward(
        FWD({
          proposalId: "fp-0000000000000000-cccccccccccccccc",
          proposalHash: "sha256-" + "0".repeat(64),
          forwarderNodeId: "node-f2",
          hopIndex: 1,
          hopBudgetRemaining: 7,
        }),
      ),
    );
    expect(registry.proposalCount).toBe(FORWARDING_BOUNDS.maxTrackedProposals);
  });
});

// ── material rejection (25D over the transport boundary) ────────────────────────

describe("27F material rejection — nothing unsafe rides the sanctioned transport", () => {
  it("a secret-key-shaped field nested inside JSON provenance refuses", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwardRefusal(
      registry.forward(FWD({ provenanceRefs: ["{\"private_key\":\"AAAA\"}"] })),
      "refused_secret_material",
    );
    expect(registry.proposalCount).toBe(0);
  });

  it("executable shell material in a ref refuses", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwardRefusal(
      registry.forward(FWD({ provenanceRefs: ["sh -c id"] })),
      "refused_executable_material",
    );
    expect(registry.proposalCount).toBe(0);
  });

  it("a local-path ref refuses as forbidden material", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwardRefusal(
      registry.forward(FWD({ provenanceRefs: ["/etc/menog/config"] })),
      "refused_forbidden_material",
    );
    expect(registry.proposalCount).toBe(0);
  });

  it("material outranks origin substitution (pinned order: data safety first)", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwardRefusal(
      registry.forward(
        FWD({ forwarderNodeId: "node-origin", provenanceRefs: ["sh -c id"] }),
      ),
      "refused_executable_material",
    );
  });
});

// ── malformed input + field bounds ───────────────────────────────────────────────

describe("27F input — malformed refuses, frozen bounds hold", () => {
  it("malformed forwards refuse invalid_forward (24E identity, distinct endpoints, safe types)", () => {
    const registry = ProposalForwardingRegistry.open();
    const bad: Partial<ForwardInput>[] = [
      { proposalId: "fp-short" },
      { proposalId: "not-an-fp-id" },
      { proposalHash: "sha256-zz" },
      { proposalHash: "a".repeat(64) },
      { originNodeId: "" },
      { destinationNodeId: "" },
      { forwarderNodeId: "" },
      { originNodeId: "node-x", destinationNodeId: "node-x" },
      { destinationNodeId: "node-origin", forwarderNodeId: "node-origin" },
      { hopIndex: -1 },
      { hopIndex: 1.5 },
      { hopBudgetRemaining: NaN },
      { provenanceRefs: [""] },
      { provenanceRefs: "ev-1" as unknown as readonly string[] },
      { observedAtEpochMs: Number.POSITIVE_INFINITY },
      { observedAtEpochMs: Number.NaN },
    ];
    for (const over of bad) {
      expectForwardRefusal(registry.forward(FWD(over)), "refused_invalid_forward");
    }
    expect(registry.proposalCount).toBe(0);
  });

  it("oversize fields and ref inflation refuse field_bound (never truncate)", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwardRefusal(
      registry.forward(FWD({ forwarderNodeId: "n".repeat(FORWARDING_BOUNDS.maxNodeIdChars + 1) })),
      "refused_field_bound",
    );
    const manyRefs = Array.from(
      { length: FORWARDING_BOUNDS.maxProvenanceRefs + 1 },
      (_, index) => "ev-" + index,
    );
    expectForwardRefusal(
      registry.forward(FWD({ provenanceRefs: manyRefs })),
      "refused_field_bound",
    );
    expectForwardRefusal(
      registry.forward(FWD({ provenanceRefs: ["ev-" + "x".repeat(FORWARDING_BOUNDS.maxProvenanceRefChars + 1)] })),
      "refused_field_bound",
    );
    expect(registry.proposalCount).toBe(0);
  });
});

// ── snapshot / fingerprint / refusal invariance ────────────────────────────────

describe("27F observability — deterministic frozen knowledge, refusals change nothing", () => {
  it("snapshots are canonically sorted and frozen regardless of insertion order", () => {
    const build = (ids: readonly string[]): ProposalForwardingRegistry => {
      const registry = ProposalForwardingRegistry.open();
      for (const id of ids) {
        const index = parseInt(id.slice(3, 19), 16);
        expectForwarded(
          registry.forward(
            FWD({ proposalId: id, proposalHash: "sha256-" + index.toString(16).padStart(64, "0") }),
          ),
        );
      }
      return registry;
    };
    const ids = [
      "fp-0000000000000002-cccccccccccccccc",
      "fp-0000000000000000-cccccccccccccccc",
      "fp-0000000000000001-cccccccccccccccc",
    ];
    const a = build(ids);
    const b = build([ids[2] as string, ids[1] as string, ids[0] as string]);
    const idsA = a.snapshot().map((record) => record.proposalId);
    const idsB = b.snapshot().map((record) => record.proposalId);
    expect(idsA).toEqual([
      "fp-0000000000000000-cccccccccccccccc",
      "fp-0000000000000001-cccccccccccccccc",
      "fp-0000000000000002-cccccccccccccccc",
    ]);
    expect(idsB).toEqual(idsA);
    expect(a.fingerprint()).toBe(b.fingerprint());
    const snapshot = a.snapshot();
    expect(Object.isFrozen(snapshot)).toBe(true);
    for (const record of snapshot) {
      expect(Object.isFrozen(record)).toBe(true);
      expect(Object.isFrozen(record.forwarderChain)).toBe(true);
      expect(Object.isFrozen(record.provenanceRefs)).toBe(true);
    }
  });

  it("every refusal class leaves the registry EXACTLY as it was", () => {
    const registry = ProposalForwardingRegistry.open();
    expectForwarded(registry.forward(FWD({ provenanceRefs: ["ev-1", "ev-2"] })));
    const fingerprint = registry.fingerprint();
    const before = registry.get(FP_ID);
    // full refs presented so provenance passes and REPLAY is the refusal
    expectForwardRefusal(
      registry.forward(FWD({ provenanceRefs: ["ev-1", "ev-2"] })),
      "refused_replay",
    );
    expectForwardRefusal(
      registry.forward(
        FWD({ forwarderNodeId: "node-f2", hopIndex: 1, hopBudgetRemaining: 7, originNodeId: "node-evil" }),
      ),
      "refused_origin_substitution",
    );
    expectForwardRefusal(
      registry.forward(
        FWD({ forwarderNodeId: "node-f2", hopIndex: 1, hopBudgetRemaining: 7, proposalHash: FP_HASH_2 }),
      ),
      "refused_identity_mutation",
    );
    expectForwardRefusal(
      registry.forward(
        FWD({ forwarderNodeId: "node-f2", hopIndex: 1, hopBudgetRemaining: 7, provenanceRefs: ["ev-1"] }),
      ),
      "refused_provenance_stripped",
    );
    expectForwardRefusal(
      registry.forward(FWD({ proposalId: "garbage" })),
      "refused_invalid_forward",
    );
    expect(registry.proposalCount).toBe(1);
    expect(registry.fingerprint()).toBe(fingerprint);
    expect(registry.get(FP_ID)).toEqual(before);
  });

  it("empty registries fingerprint identically (64-hex, pure)", () => {
    const a = ProposalForwardingRegistry.open();
    const b = ProposalForwardingRegistry.open();
    expect(a.fingerprint()).toBe(b.fingerprint());
    expect(a.fingerprint()).toMatch(/^[0-9a-f]{64}$/);
    expect(a.fingerprint()).toBe(a.fingerprint());
    expect(a.snapshot()).toEqual([]);
  });

  it("every refusal code in the closed vocabulary carries an explanation in source", () => {
    const code = codeOnly(SRC("meshForwarding.ts"));
    expect(FORWARDING_REFUSAL_CODES.length).toBe(14);
    for (const refusal of FORWARDING_REFUSAL_CODES) {
      expect(code).toContain(refusal + ":");
    }
  });
});
