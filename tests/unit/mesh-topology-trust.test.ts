/**
 * PHASE 27A — Mesh Trust Model Tests
 * (CONTRACT-FIRST / NO SOCKET / NO LISTENER / NO DISCOVERY / NO ROUTING
 * EXECUTION / NO NEW AUTHORITY).
 *
 * Pins the six mesh laws structurally and behaviorally:
 *   M1 EDGE != TRUST · M2 PATH != ADMISSION · M3 ROUTE != AUTHORIZATION ·
 *   M4 FORWARDER != ORIGIN · M5 ADVERTISEMENT != GRANT ·
 *   M6 TOPOLOGY KNOWLEDGE != MEMBERSHIP.
 * Also pins the closed Node/Edge/Path/Observation/Advertisement/Route/Hop/
 * Scope/Refusal vocabularies as exact-equality lists, the fail-closed
 * refusal of every unknown value, the zero-authority structurals
 * (membership "none", trust "none", admission "none", authority "none",
 * authorization "none", executionAuthorized false), and the deterministic-
 * explanation law (same input -> same output).
 *
 * Mother invariant: TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  MESH_TRUST_SCHEMA_VERSION,
  MESH_TRUST_PINS,
  MESH_TRUST_PIN_EXPLANATIONS,
  MESH_NODE_KINDS,
  MESH_EDGE_KINDS,
  MESH_PATH_STATES,
  MESH_OBSERVATION_KINDS,
  MESH_ADVERTISEMENT_KINDS,
  MESH_ADVERTISED_CAPABILITY_CLAIMS,
  MESH_ROUTE_STATES,
  MESH_HOP_ROLES,
  MESH_REFUSAL_CODES,
  MESH_SCOPES,
  MESH_NON_SCOPES,
  decideMeshScope,
  decideMeshNode,
  decideMeshEdge,
  decideMeshPath,
  decideMeshObservation,
  decideMeshAdvertisement,
  decideMeshRoute,
  decideMeshClaim,
  meshTrustFingerprint,
  type MeshNode,
  type MeshEdge,
  type MeshPath,
  type MeshObservation,
  type MeshAdvertisement,
  type MeshRoute,
  type MeshClaimKind,
} from "@menog/durable-state";

const SRC = (p: string): string =>
  readFileSync(join(process.cwd(), "packages", "durable-state", "src", p), "utf8");

function codeOnly(src: string): string {
  return src
    .split("\n")
    .filter((line) => !line.trim().startsWith("*") && !line.trim().startsWith("//") && !line.trim().startsWith("/*"))
    .join("\n");
}

/** Surfaces the 27A module must NEVER contain (structural no-socket pin). */
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
]);

const NOW = 1_700_000_000_000;
const NODE_A = "node-" + "a".repeat(64);
const NODE_B = "node-" + "b".repeat(64);

const NODE = (kind: MeshNode["kind"]): MeshNode => ({ nodeId: NODE_A, kind, observedAtEpochMs: NOW });
const EDGE = (kind: MeshEdge["kind"]): MeshEdge => ({ edgeId: "edge-1", fromNodeId: NODE_A, toNodeId: NODE_B, kind, observedAtEpochMs: NOW });
const PATH = (state: MeshPath["state"]): MeshPath => ({ pathId: "path-1", nodeIds: [NODE_A, NODE_B], state, observedAtEpochMs: NOW });
const OBSERVATION = (kind: MeshObservation["kind"]): MeshObservation => ({ observationId: "obs-1", kind, subjectNodeId: NODE_A, observedAtEpochMs: NOW });
const AD = (kind: MeshAdvertisement["kind"], claims: readonly (typeof MESH_ADVERTISED_CAPABILITY_CLAIMS)[number][]): MeshAdvertisement => ({
  advertisementId: "adv-1",
  kind,
  claimingNodeId: NODE_B,
  capabilityClaims: claims,
  observedAtEpochMs: NOW,
});
const ROUTE = (state: MeshRoute["state"], hops: MeshRoute["hops"]): MeshRoute => ({
  routeId: "route-1",
  state,
  origin: { nodeId: NODE_A, originFixed: true },
  hops,
  destination: { nodeId: NODE_B, role: "destination" },
  observedAtEpochMs: NOW,
});

// ── structural pins ──────────────────────────────────────────────────────────

describe("27A structure — closed vocabulary and law surfaces", () => {
  it("forbidden surfaces list is pinned and the module imports no socket/listener/discovery/execution primitive", () => {
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
    ]);
    const code = codeOnly(SRC("meshTopologyTrust.ts"));
    for (const forbidden of FORBIDDEN_SURFACES) {
      expect(code).not.toContain(forbidden);
    }
    expect(code).not.toContain(".persist(");
    expect(code).not.toContain("setInterval");
    expect(code).not.toContain("setTimeout");
    expect(code).not.toContain("Date.now");
    expect(code).not.toContain("performance.now");
  });

  it("no type or decision carries execution/policy authority; the module imports no policy or tool vocabulary (M3)", () => {
    const src = codeOnly(SRC("meshTopologyTrust.ts"));
    expect(src).not.toMatch(/executionAuthorized:\s*true/);
    expect(src).not.toMatch(/policyAuthorized:\s*true/);
    // \b guards so map keys like `gossip_membership:` / `grant_authority:`
    // (which name the pin they REFUSES) are not mistaken for decision fields.
    expect(src).not.toMatch(/\bauthorization:\s*"(?!none")/);
    expect(src).not.toMatch(/\bgrant:\s*"(?!none")/);
    expect(src).not.toMatch(/\btrust:\s*"(?!none")/);
    expect(src).not.toMatch(/\badmission:\s*"(?!none")/);
    expect(src).not.toMatch(/\bmembership:\s*"(?!none")/);
    expect(src).not.toMatch(/\bauthority:\s*"(?!none")/);
    expect(src).not.toContain("DenyByDefault");
    expect(src).not.toContain("PolicyDecision");
    expect(src).not.toContain("executeToolRun");
    expect(src).not.toContain("runIsolated");
    expect(src).not.toContain("toolJunction");
    expect(src).not.toContain("requireTool");
  });

  it("the module contains no discovery/gossip/relay/consensus capability outside the closed MAY-NOT refusal vocabulary", () => {
    const src = codeOnly(SRC("meshTopologyTrust.ts"));
    // The forbidden concepts appear only inside MESH_NON_SCOPES (refusal
    // names) and their pin map — never as accepted behavior or MAY entries.
    for (const token of ["discover_peers", "gossip_membership", "relay_cloud", "traverse_nat", "consensus_join", "reach_internet"]) {
      expect(MESH_SCOPES).not.toContain(token);
      expect(MESH_NON_SCOPES).toContain(token);
      const occurrences = src.split(token).length - 1;
      // exactly one appearance: the MAY-NOT list entry (pin map uses the key, not the token literal — keyed identically, counted here once each)
      expect(occurrences).toBeGreaterThanOrEqual(1);
      expect(occurrences).toBeLessThanOrEqual(2);
    }
  });

  it("schema version and the six pins are pinned exactly, in order", () => {
    expect(MESH_TRUST_SCHEMA_VERSION).toBe("menog-mesh-trust/v0");
    expect([...MESH_TRUST_PINS]).toEqual([
      "EDGE_NOT_TRUST",
      "PATH_NOT_ADMISSION",
      "ROUTE_NOT_AUTHORIZATION",
      "FORWARDER_NOT_ORIGIN",
      "ADVERTISEMENT_NOT_GRANT",
      "TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP",
    ]);
  });

  it("every pin has a deterministic closed explanation naming its pin and its != law", () => {
    expect(Object.keys(MESH_TRUST_PIN_EXPLANATIONS).sort()).toEqual([...MESH_TRUST_PINS].sort());
    const pinned: Array<[MeshPin, string]> = [
      ["EDGE_NOT_TRUST", "M1 EDGE != TRUST"],
      ["PATH_NOT_ADMISSION", "M2 PATH != ADMISSION"],
      ["ROUTE_NOT_AUTHORIZATION", "M3 ROUTE != AUTHORIZATION"],
      ["FORWARDER_NOT_ORIGIN", "M4 FORWARDER != ORIGIN"],
      ["ADVERTISEMENT_NOT_GRANT", "M5 ADVERTISEMENT != GRANT"],
      ["TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP", "M6 TOPOLOGY KNOWLEDGE != MEMBERSHIP"],
    ];
    for (const [pin, law] of pinned) {
      expect(MESH_TRUST_PIN_EXPLANATIONS[pin].startsWith(law)).toBe(true);
      expect(MESH_TRUST_PIN_EXPLANATIONS[pin]).toContain("!=");
    }
  });

  it("the closed vocabularies are pinned exactly (node/edge/path/observation/advertisement/capability/route/hop/refusal/scope)", () => {
    expect([...MESH_NODE_KINDS]).toEqual(["local_node", "admitted_node", "observed_node", "unknown_node"]);
    expect([...MESH_EDGE_KINDS]).toEqual(["configured_edge", "observed_edge", "advertised_edge", "unknown_edge"]);
    expect([...MESH_PATH_STATES]).toEqual(["path_open", "path_unverified", "path_blocked", "unknown_path"]);
    expect([...MESH_OBSERVATION_KINDS]).toEqual([
      "node_observed",
      "edge_observed",
      "path_observed",
      "route_observed",
      "origin_observed",
      "forwarder_observed",
      "destination_observed",
      "unknown_observation",
    ]);
    expect([...MESH_ADVERTISEMENT_KINDS]).toEqual([
      "capability_advertisement",
      "topology_advertisement",
      "route_advertisement",
      "unknown_advertisement",
    ]);
    expect([...MESH_ADVERTISED_CAPABILITY_CLAIMS]).toEqual([
      "claim_can_forward_proposals",
      "claim_reachable_on_local_lan",
      "claim_supports_framed_transport",
      "claim_topology_summary",
      "unknown_capability_claim",
    ]);
    expect([...MESH_ROUTE_STATES]).toEqual(["route_planned", "route_unverified", "route_unavailable", "unknown_route"]);
    expect([...MESH_HOP_ROLES]).toEqual(["origin", "forwarder", "destination", "unknown_role"]);
    expect([...MESH_REFUSAL_CODES]).toEqual([
      "refused_unknown_node_kind",
      "refused_unknown_edge_kind",
      "refused_unknown_path_state",
      "refused_unknown_observation_kind",
      "refused_unknown_advertisement_kind",
      "refused_unknown_capability_claim",
      "refused_capability_claim_grant",
      "refused_unknown_route_state",
      "refused_unknown_hop_role",
      "refused_forwarder_as_origin",
      "refused_claim_crosses_boundary",
      "refused_out_of_mesh_scope",
      "refused_unknown_mesh_scope",
      "refused_anonymous_claim",
      "refused_unknown",
    ]);
    expect([...MESH_SCOPES]).toEqual([
      "record_observation",
      "record_node",
      "record_edge",
      "record_path",
      "record_route",
      "receive_advertisement_as_data",
      "plan_route_over_recorded_topology",
      "summarize_topology_knowledge",
    ]);
    expect([...MESH_NON_SCOPES]).toEqual([
      "execute_tool",
      "choose_policy",
      "admit_peer",
      "grant_authority",
      "grant_capability",
      "persist_record",
      "administer_peer",
      "discover_peers",
      "bind_public",
      "traverse_nat",
      "relay_cloud",
      "reach_internet",
      "gossip_membership",
      "consensus_join",
      "forward_as_origin",
    ]);
    // every unknown sentinel exists in every entity vocabulary (fail-closed by construction)
    expect(MESH_NODE_KINDS).toContain("unknown_node");
    expect(MESH_EDGE_KINDS).toContain("unknown_edge");
    expect(MESH_PATH_STATES).toContain("unknown_path");
    expect(MESH_OBSERVATION_KINDS).toContain("unknown_observation");
    expect(MESH_ADVERTISEMENT_KINDS).toContain("unknown_advertisement");
    expect(MESH_ADVERTISED_CAPABILITY_CLAIMS).toContain("unknown_capability_claim");
    expect(MESH_ROUTE_STATES).toContain("unknown_route");
    expect(MESH_HOP_ROLES).toContain("unknown_role");
    // MAY and MAY-NOT are disjoint
    for (const s of MESH_SCOPES) expect(MESH_NON_SCOPES).not.toContain(s);
    for (const n of MESH_NON_SCOPES) expect(MESH_SCOPES).not.toContain(n);
  });

  it("the exported vocabularies are frozen (callers can never widen them)", () => {
    expect(Object.isFrozen(MESH_TRUST_PINS)).toBe(true);
    expect(Object.isFrozen(MESH_NODE_KINDS)).toBe(true);
    expect(Object.isFrozen(MESH_EDGE_KINDS)).toBe(true);
    expect(Object.isFrozen(MESH_PATH_STATES)).toBe(true);
    expect(Object.isFrozen(MESH_OBSERVATION_KINDS)).toBe(true);
    expect(Object.isFrozen(MESH_ADVERTISEMENT_KINDS)).toBe(true);
    expect(Object.isFrozen(MESH_ADVERTISED_CAPABILITY_CLAIMS)).toBe(true);
    expect(Object.isFrozen(MESH_ROUTE_STATES)).toBe(true);
    expect(Object.isFrozen(MESH_HOP_ROLES)).toBe(true);
    expect(Object.isFrozen(MESH_REFUSAL_CODES)).toBe(true);
    expect(Object.isFrozen(MESH_SCOPES)).toBe(true);
    expect(Object.isFrozen(MESH_NON_SCOPES)).toBe(true);
  });
});

type MeshPin = (typeof MESH_TRUST_PINS)[number];

// ── scope (MAY / MAY-NOT) ────────────────────────────────────────────────────

describe("27A mesh scope — closed MAY set, pin-mapped MAY-NOT, unknown refuses", () => {
  it("every MAY capability passes as knowledge-only scope", () => {
    for (const cap of MESH_SCOPES) {
      const d = decideMeshScope({ capability: cap });
      expect(d.ok).toBe(true);
      if (d.ok) {
        expect(d.scope).toBe(cap);
        expect(d.explanation).toContain("grants nothing");
      }
    }
  });

  it("every MAY-NOT capability refuses naming its pin", () => {
    const expected: Record<string, MeshPin> = {
      execute_tool: "ROUTE_NOT_AUTHORIZATION",
      choose_policy: "ROUTE_NOT_AUTHORIZATION",
      admit_peer: "PATH_NOT_ADMISSION",
      grant_authority: "ROUTE_NOT_AUTHORIZATION",
      grant_capability: "ADVERTISEMENT_NOT_GRANT",
      persist_record: "TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP",
      administer_peer: "ROUTE_NOT_AUTHORIZATION",
      discover_peers: "TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP",
      bind_public: "EDGE_NOT_TRUST",
      traverse_nat: "EDGE_NOT_TRUST",
      relay_cloud: "EDGE_NOT_TRUST",
      reach_internet: "EDGE_NOT_TRUST",
      gossip_membership: "TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP",
      consensus_join: "ROUTE_NOT_AUTHORIZATION",
      forward_as_origin: "FORWARDER_NOT_ORIGIN",
    };
    expect(Object.keys(expected).sort()).toEqual([...MESH_NON_SCOPES].sort());
    for (const cap of MESH_NON_SCOPES) {
      const d = decideMeshScope({ capability: cap });
      expect(d.ok).toBe(false);
      if (!d.ok) {
        expect(d.code).toBe("outside_mesh_scope");
        expect(d.refusal).toBe("refused_out_of_mesh_scope");
        expect(d.violatedPin).toBe(expected[cap]);
        expect(d.explanation).toContain(expected[cap]);
      }
    }
  });

  it("unknown capabilities refuse with null pin (fail closed)", () => {
    for (const cap of ["mdns_discovery", "auto_join", "become_member", "route_then_execute", "", "EXECUTE_TOOL"]) {
      const d = decideMeshScope({ capability: cap });
      expect(d.ok).toBe(false);
      if (!d.ok) {
        expect(d.refusal).toBe("refused_unknown_mesh_scope");
        expect(d.violatedPin).toBeNull();
      }
    }
  });
});

// ── entity decisions ─────────────────────────────────────────────────────────

describe("27A entity decisions — zero-authority structurals and fail-closed refusals", () => {
  it("every known node kind records membership structurally 'none' (M6)", () => {
    for (const kind of MESH_NODE_KINDS) {
      const d = decideMeshNode({ node: NODE(kind), observedAtEpochMs: NOW });
      if (kind === "unknown_node") {
        expect(d.ok).toBe(false);
        if (!d.ok) expect(d.refusal).toBe("refused_unknown_node_kind");
      } else {
        expect(d.ok).toBe(true);
        if (d.ok) {
          expect(d.kind).toBe(kind);
          expect(d.membership).toBe("none");
          expect(d.explanation).toContain("M6 TOPOLOGY KNOWLEDGE != MEMBERSHIP");
        }
      }
    }
  });

  it("every known edge kind records trust structurally 'none' (M1)", () => {
    for (const kind of MESH_EDGE_KINDS) {
      const d = decideMeshEdge({ edge: EDGE(kind), observedAtEpochMs: NOW });
      if (kind === "unknown_edge") {
        expect(d.ok).toBe(false);
        if (!d.ok) expect(d.refusal).toBe("refused_unknown_edge_kind");
      } else {
        expect(d.ok).toBe(true);
        if (d.ok) {
          expect(d.kind).toBe(kind);
          expect(d.trust).toBe("none");
          expect(d.explanation).toContain("M1 EDGE != TRUST");
        }
      }
    }
  });

  it("every known path state records admission structurally 'none' (M2)", () => {
    for (const state of MESH_PATH_STATES) {
      const d = decideMeshPath({ path: PATH(state), observedAtEpochMs: NOW });
      if (state === "unknown_path") {
        expect(d.ok).toBe(false);
        if (!d.ok) expect(d.refusal).toBe("refused_unknown_path_state");
      } else {
        expect(d.ok).toBe(true);
        if (d.ok) {
          expect(d.state).toBe(state);
          expect(d.admission).toBe("none");
          expect(d.explanation).toContain("M2 PATH != ADMISSION");
        }
      }
    }
  });

  it("every known observation kind records authority structurally 'none' (read-only, never control)", () => {
    for (const kind of MESH_OBSERVATION_KINDS) {
      const d = decideMeshObservation({ observation: OBSERVATION(kind), observedAtEpochMs: NOW });
      if (kind === "unknown_observation") {
        expect(d.ok).toBe(false);
        if (!d.ok) expect(d.refusal).toBe("refused_unknown_observation_kind");
      } else {
        expect(d.ok).toBe(true);
        if (d.ok) {
          expect(d.kind).toBe(kind);
          expect(d.authority).toBe("none");
          expect(d.explanation).toContain("read-only");
        }
      }
    }
  });

  it("every known advertisement kind is received as DATA with grant structurally 'none' (M5)", () => {
    for (const kind of MESH_ADVERTISEMENT_KINDS) {
      const d = decideMeshAdvertisement({
        advertisement: AD(kind, ["claim_can_forward_proposals"]),
        observedAtEpochMs: NOW,
      });
      if (kind === "unknown_advertisement") {
        expect(d.ok).toBe(false);
        if (!d.ok) {
          expect(d.refusal).toBe("refused_unknown_advertisement_kind");
          expect(d.violatedPin).toBe("ADVERTISEMENT_NOT_GRANT");
        }
      } else {
        expect(d.ok).toBe(true);
        if (d.ok) {
          expect(d.grant).toBe("none");
          expect(d.explanation).toContain("M5 ADVERTISEMENT != GRANT");
        }
      }
    }
  });

  it("unknown capability claims refuse even as DATA; known claims pass with grant 'none'", () => {
    const refused = decideMeshAdvertisement({
      advertisement: AD("capability_advertisement", ["unknown_capability_claim"]),
      observedAtEpochMs: NOW,
    });
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.refusal).toBe("refused_unknown_capability_claim");

    const allKnown = decideMeshAdvertisement({
      advertisement: AD("capability_advertisement", [
        "claim_can_forward_proposals",
        "claim_reachable_on_local_lan",
        "claim_supports_framed_transport",
        "claim_topology_summary",
      ]),
      observedAtEpochMs: NOW,
    });
    expect(allKnown.ok).toBe(true);
    if (allKnown.ok) expect(allKnown.grant).toBe("none");
  });

  it("an anonymous advertisement (no claiming node) refuses before evaluation (fail closed)", () => {
    const d = decideMeshAdvertisement({
      advertisement: { ...AD("capability_advertisement", ["claim_topology_summary"]), claimingNodeId: "" },
      observedAtEpochMs: NOW,
    });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.refusal).toBe("refused_anonymous_claim");
      expect(d.violatedPin).toBe("ADVERTISEMENT_NOT_GRANT");
    }
  });

  it("every known route state records authorization 'none' and executionAuthorized false (M3)", () => {
    const hops: MeshRoute["hops"] = [
      { hopIndex: 0, nodeId: NODE_A, role: "origin" },
      { hopIndex: 1, nodeId: NODE_B, role: "destination" },
    ];
    for (const state of MESH_ROUTE_STATES) {
      const d = decideMeshRoute({ route: ROUTE(state, hops), observedAtEpochMs: NOW });
      if (state === "unknown_route") {
        expect(d.ok).toBe(false);
        if (!d.ok) {
          expect(d.refusal).toBe("refused_unknown_route_state");
          expect(d.violatedPin).toBe("ROUTE_NOT_AUTHORIZATION");
        }
      } else {
        expect(d.ok).toBe(true);
        if (d.ok) {
          expect(d.state).toBe(state);
          expect(d.authorization).toBe("none");
          expect(d.executionAuthorized).toBe(false);
          expect(d.explanation).toContain("M3 ROUTE != AUTHORIZATION");
          expect(d.explanation).toContain("fresh LOCAL allocation");
        }
      }
    }
  });

  it("a forwarder recorded at the origin node refuses naming M4 (forwarder != origin)", () => {
    const d = decideMeshRoute({
      route: ROUTE("route_planned", [
        { hopIndex: 0, nodeId: NODE_A, role: "origin" },
        { hopIndex: 1, nodeId: NODE_A, role: "forwarder" },
        { hopIndex: 2, nodeId: NODE_B, role: "destination" },
      ]),
      observedAtEpochMs: NOW,
    });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.refusal).toBe("refused_forwarder_as_origin");
      expect(d.violatedPin).toBe("FORWARDER_NOT_ORIGIN");
      expect(d.explanation).toContain("M4 FORWARDER != ORIGIN");
    }
  });

  it("an unknown hop role refuses the whole route (fail closed — first match wins)", () => {
    const d = decideMeshRoute({
      route: ROUTE("route_planned", [
        { hopIndex: 0, nodeId: NODE_A, role: "origin" },
        { hopIndex: 1, nodeId: NODE_B, role: "unknown_role" },
      ]),
      observedAtEpochMs: NOW,
    });
    expect(d.ok).toBe(false);
    if (!d.ok) {
      expect(d.refusal).toBe("refused_unknown_hop_role");
      expect(d.violatedPin).toBe("ROUTE_NOT_AUTHORIZATION");
    }
  });

  it("a legitimate multi-hop route passes with authorization 'none' (knowledge only)", () => {
    const d = decideMeshRoute({
      route: ROUTE("route_planned", [
        { hopIndex: 0, nodeId: NODE_A, role: "origin" },
        { hopIndex: 1, nodeId: "node-c", role: "forwarder" },
        { hopIndex: 2, nodeId: NODE_B, role: "destination" },
      ]),
      observedAtEpochMs: NOW,
    });
    expect(d.ok).toBe(true);
    if (d.ok) {
      expect(d.authorization).toBe("none");
      expect(d.executionAuthorized).toBe(false);
    }
  });
});

// ── claim decisions (the six pins over one claim) ────────────────────────────

describe("27A claims — facts are DATA with authority 'none'; conflation claims refuse", () => {
  const FACTS: readonly MeshClaimKind[] = [
    "node_kind_fact",
    "edge_relation_fact",
    "path_state_fact",
    "observation_fact",
    "route_plan_fact",
    "capability_advertisement_fact",
  ];
  const CONFLATIONS: ReadonlyArray<[MeshClaimKind, MeshPin]> = [
    ["edge_trust_claim", "EDGE_NOT_TRUST"],
    ["path_admission_claim", "PATH_NOT_ADMISSION"],
    ["route_authorization_claim", "ROUTE_NOT_AUTHORIZATION"],
    ["forwarder_origin_claim", "FORWARDER_NOT_ORIGIN"],
    ["advertisement_grant_claim", "ADVERTISEMENT_NOT_GRANT"],
    ["topology_membership_claim", "TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP"],
  ];

  it("the claim kind sets are pinned exactly (6 fact kinds + 6 conflation kinds, one per pin)", () => {
    expect([...FACTS].sort()).toEqual([
      "capability_advertisement_fact",
      "edge_relation_fact",
      "node_kind_fact",
      "observation_fact",
      "path_state_fact",
      "route_plan_fact",
    ]);
    expect(CONFLATIONS.map(([k]) => k).sort()).toEqual([
      "advertisement_grant_claim",
      "edge_trust_claim",
      "forwarder_origin_claim",
      "path_admission_claim",
      "route_authorization_claim",
      "topology_membership_claim",
    ]);
    expect(CONFLATIONS.map(([, p]) => p).sort()).toEqual([...MESH_TRUST_PINS].sort());
  });

  it("every fact claim is received as DATA with authority structurally 'none'", () => {
    for (const kind of FACTS) {
      const d = decideMeshClaim({ claimKind: kind, subject: NODE_B, observedAtEpochMs: NOW });
      expect(d.ok).toBe(true);
      if (d.ok) {
        expect(d.code).toBe("claim_received_as_data");
        expect(d.authority).toBe("none");
        expect(d.explanation).toContain("DATA");
      }
    }
  });

  it("every conflation claim crosses the boundary naming its exact pin", () => {
    const lawOf: Record<MeshPin, string> = {
      EDGE_NOT_TRUST: "M1 EDGE != TRUST",
      PATH_NOT_ADMISSION: "M2 PATH != ADMISSION",
      ROUTE_NOT_AUTHORIZATION: "M3 ROUTE != AUTHORIZATION",
      FORWARDER_NOT_ORIGIN: "M4 FORWARDER != ORIGIN",
      ADVERTISEMENT_NOT_GRANT: "M5 ADVERTISEMENT != GRANT",
      TOPOLOGY_KNOWLEDGE_NOT_MEMBERSHIP: "M6 TOPOLOGY KNOWLEDGE != MEMBERSHIP",
    };
    for (const [kind, pin] of CONFLATIONS) {
      const d = decideMeshClaim({ claimKind: kind, subject: NODE_B, observedAtEpochMs: NOW });
      expect(d.ok).toBe(false);
      if (!d.ok) {
        expect(d.code).toBe("claim_crosses_boundary");
        expect(d.violatedPin).toBe(pin);
        // the explanation embeds the pin's closed != law, not the raw token
        expect(d.explanation).toContain(lawOf[pin]);
        expect(d.explanation).toContain("!=");
      }
    }
  });

  it("an anonymous claim refuses before evaluation (fail closed)", () => {
    const d = decideMeshClaim({ claimKind: "route_plan_fact", subject: "", observedAtEpochMs: NOW });
    expect(d.ok).toBe(false);
    if (!d.ok) expect(d.code).toBe("claim_crosses_boundary");
  });

  it("claim decisions are deterministic: same input yields the same provenance hash, different input differs", () => {
    const a1 = decideMeshClaim({ claimKind: "route_plan_fact", subject: NODE_A, observedAtEpochMs: NOW });
    const a2 = decideMeshClaim({ claimKind: "route_plan_fact", subject: NODE_A, observedAtEpochMs: NOW });
    const b = decideMeshClaim({ claimKind: "route_plan_fact", subject: NODE_B, observedAtEpochMs: NOW });
    expect(a1.ok && a2.ok && a1.provenanceHash === a2.provenanceHash).toBe(true);
    // a refused conflation claim still yields a deterministic provenance hash,
    // bound to a different claim kind than the accepted fact claim
    const aRef = decideMeshClaim({ claimKind: "route_authorization_claim", subject: NODE_A, observedAtEpochMs: NOW });
    expect(a1.ok).toBe(true);
    expect(aRef.ok).toBe(false);
    expect(a1.provenanceHash).not.toBe(aRef.provenanceHash);
    expect(aRef.provenanceHash).toMatch(/^[0-9a-f]{64}$/);
    expect(b.ok).toBe(true);
    if (b.ok && a1.ok) expect(b.provenanceHash).not.toBe(a1.provenanceHash);
  });

  it("entity decisions are deterministic: same facts yield the same provenance hash", () => {
    const e1 = decideMeshEdge({ edge: EDGE("observed_edge"), observedAtEpochMs: NOW });
    const e2 = decideMeshEdge({ edge: EDGE("observed_edge"), observedAtEpochMs: NOW });
    if (!e1.ok || !e2.ok) throw new Error("expected ok");
    expect(e1.provenanceHash).toBe(e2.provenanceHash);
    const e3 = decideMeshEdge({ edge: EDGE("configured_edge"), observedAtEpochMs: NOW });
    if (!e3.ok) throw new Error("expected ok");
    expect(e3.provenanceHash).not.toBe(e1.provenanceHash);
  });
});

// ── fingerprint ──────────────────────────────────────────────────────────────

describe("27A fingerprint — canonical self-description", () => {
  it("is deterministic and distinguishes local node and time", () => {
    const f1 = meshTrustFingerprint({ localNodeId: NODE_A, observedAtEpochMs: NOW });
    const f2 = meshTrustFingerprint({ localNodeId: NODE_A, observedAtEpochMs: NOW });
    expect(f1).toBe(f2);
    expect(meshTrustFingerprint({ localNodeId: NODE_B, observedAtEpochMs: NOW })).not.toBe(f1);
    expect(meshTrustFingerprint({ localNodeId: NODE_A, observedAtEpochMs: NOW + 1 })).not.toBe(f1);
    expect(meshTrustFingerprint({ localNodeId: null, observedAtEpochMs: NOW })).not.toBe(f1);
    expect(f1).toMatch(/^[0-9a-f]{64}$/);
  });
});
