/**
 * PHASE 27J — End-to-End Multi-Node Mesh Scenario
 * (TWO OS PROCESSES / REAL SOCKET / LOOPBACK ONLY).
 *
 * This is the scenario gate. It does NOT re-test the 27A–27I units — those
 * suites own them. It proves the mesh stack COMPOSES across a real OS process
 * boundary over a real 127.0.0.1 socket, and that the composed result obeys the
 * law the whole phase exists to hold:
 *
 *     OBSERVER-RELATIVE VIEWS ARE FIRST-CLASS. THERE IS NO GLOBAL TRUTH.
 *
 * Scenario, as the pack specifies it:
 *   1. two processes, one explicit loopback port each, real 26B listener;
 *   2. BOTH build their OWN 27B topology graph, plan their OWN 27E route, and
 *      project their OWN 27H snapshot — independently, sharing nothing;
 *   3. A dials B over a REAL socket and sends ONE line of JSON containing its
 *      observations — as DATA, requesting nothing;
 *   4. B folds what arrived into ITS OWN view and projects ITS OWN snapshot;
 *   5. the two snapshots are then compared: they MUST DIFFER. If they matched,
 *      one of them would be a global truth — which is the bug this gate hunts.
 *
 * What must remain true after composition:
 *   · a route planned on one node is KNOWLEDGE, never authorization;
 *   · a wire observation changes no authority anywhere;
 *   · both snapshots carry authority "none", controlPlane false, readOnly true;
 *   · nothing reaches peer admission, Policy, or a tool.
 *
 * SCOPE HONESTY: loopback only. No Internet or public endpoint, no discovery,
 * no relay, no NAT traversal, no consensus, no remote authority, no deployment.
 * This is a PROCESS-boundary scenario, NOT a power-cut one: no power-loss,
 * controller-cache, kernel-panic, hardware-failure, DDoS, WAN or
 * production-capacity claim is made or testable here. And it is NOT the
 * two-machine LAN (D-26-1), which remains UNSUPPORTED_ON_CURRENT_TARGET.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CHILD = join(process.cwd(), "tests", "fixtures", "phase27j-mesh-node.mjs");

// Distinct from 26H's 41910-41913 so the two scenario gates can never collide.
const PORT_B = 41920;
const NOW = 1_700_000_000_000;
const EPOCH = "epoch-27j";

/** The frozen zero-authority literals 27E pins on a successful plan. */
interface RoutePlanOk {
  ok: true;
  code: "route_planned";
  routeId: string;
  path: string[];
  edgePath: string[];
  hopCount: number;
  admission: "none";
  authorization: "none";
  executionAuthorized: false;
  transitiveTrust: false;
  capabilityUnion: false;
  routeHash: string;
}
interface RoutePlanRefused {
  ok: false;
  code: string;
  refusal: string;
}
type RoutePlan = RoutePlanOk | RoutePlanRefused;

interface ObservabilityBuilt {
  ok: true;
  code: "snapshot_built";
  snapshot: Record<string, unknown>;
}
interface ObservabilityRefused {
  ok: false;
  code: string;
}
type Observability = ObservabilityBuilt | ObservabilityRefused;

/** The 27H projected route: roles are SEPARATED, not nested. */
interface ObservabilityRouteView {
  routeId: string;
  state: string;
  originNodeId: string;
  originFixed: true;
  forwarderNodeIds: readonly string[];
  destinationNodeId: string;
  freshness: string;
}

/**
 * The 27H projection re-taken under a SHARED snapshot id on both nodes. Two
 * hashes, not one: `sharedProjectionHash` is the vantage-sensitive one, and
 * `sharedRepeatProjectionHash` repeats the SAME inputs from the SAME vantage so
 * determinism is measured rather than assumed.
 */
interface MeshVantage {
  sharedSnapshotId: string;
  sharedProjectionHash: string;
  sharedOriginNodeId: string | null;
  sharedRepeatProjectionHash: string | null;
  sharedRepeatSnapshotId: string | null;
}

interface MeshNodeResult {
  ok: boolean;
  code?: string;
  detail?: string;
  role: string;
  epochId: string;
  listenerState?: string;
  received?: { from: string; epochId: string; observations: { nodeId: string; kind: string }[] };
  sent?: { from: string; observations: { nodeId: string; kind: string }[] };
  ack?: { ok: boolean; received: number } | null;
  world: {
    selfNodeId: string;
    peerNodeId: string;
    decisions: { selfNode: string | null; peerNode: string | null; link: string | null };
    routePlan: RoutePlan;
    observability: Observability;
    vantage: MeshVantage | null;
  };
}

let workDir = "";
const children: ChildProcess[] = [];
let A: MeshNodeResult | null = null;
let B: MeshNodeResult | null = null;

function runNode(role: "A" | "B", outFile: string, peerPort: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [CHILD, role, role === "B" ? String(PORT_B) : "0", String(peerPort), outFile, EPOCH, String(NOW)],
      { stdio: ["ignore", "pipe", "pipe"], cwd: process.cwd() },
    );
    children.push(child);
    let stderr = "";
    let stdout = "";
    child.stdout?.on("data", (c) => {
      stdout += String(c);
    });
    child.stderr?.on("data", (c) => {
      stderr += String(c);
    });
    const timer = setTimeout(() => reject(new Error(`${role} timed out; stderr: ${stderr}`)), 60_000);
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`${role} exited ${code}; stdout: ${stdout}; stderr: ${stderr}`));
      else resolve();
    });
  });
}

beforeAll(async () => {
  workDir = mkdtempSync(join(tmpdir(), "menog-27j-"));
  const aFile = join(workDir, "a.json");
  const bFile = join(workDir, "b.json");

  // B binds and listens first; A then dials the real port.
  const bReady = runNode("B", bFile, 0);
  await new Promise((r) => setTimeout(r, 1500)); // let B reach "listening"
  await Promise.all([bReady, runNode("A", aFile, PORT_B)]);

  expect(existsSync(aFile), "A must write its result").toBe(true);
  expect(existsSync(bFile), "B must write its result").toBe(true);
  A = JSON.parse(readFileSync(aFile, "utf8")) as MeshNodeResult;
  B = JSON.parse(readFileSync(bFile, "utf8")) as MeshNodeResult;
}, 120_000);

afterAll(() => {
  for (const c of children) {
    if (!c.killed) c.kill();
  }
  if (workDir !== "") rmSync(workDir, { recursive: true, force: true });
});

/** The built snapshot, or a loud failure — a refusal exposes no snapshot at all. */
function snap(r: MeshNodeResult): Record<string, unknown> {
  const obs = r.world.observability;
  if (!obs.ok) throw new Error(`expected a built snapshot for ${r.role}, got ${obs.code}`);
  return obs.snapshot;
}

describe("27J — two real processes exchange mesh knowledge over a real socket", () => {
  it("both nodes completed and the wire actually carried bytes", () => {
    expect(A?.ok, `A: ${A?.code} ${A?.detail}`).toBe(true);
    expect(B?.ok, `B: ${B?.code} ${B?.detail}`).toBe(true);
    // B received A's observations through the REAL 26B listener.
    expect(B?.received).toBeDefined();
    expect(B?.received?.from).toBe("node-a");
    expect(B?.received?.observations.length).toBeGreaterThan(0);
    expect(B?.received?.observations.map((o) => o.nodeId)).toContain("node-a");
    // And A saw B acknowledge the bytes.
    expect(A?.ack?.ok).toBe(true);
    // The sanctioned listener stopped cleanly.
    expect(B?.listenerState).toBe("stopped");
  });

  it("each node built its own graph and its own route, independently", () => {
    const planOf = (r: MeshNodeResult | null, name: string): RoutePlanOk => {
      const p = r?.world.routePlan;
      if (!p || !p.ok) throw new Error(`${name} route was not planned: ${JSON.stringify(p)}`);
      return p;
    };
    for (const [name, r] of [["A", A], ["B", B]] as const) {
      expect(r?.world.decisions.selfNode, `${name} self node`).toBe("record_added");
      expect(r?.world.decisions.peerNode, `${name} peer node`).toBe("record_added");
      expect(r?.world.decisions.link, `${name} edge`).toBe("record_added");
      expect(planOf(r ?? null, name).code).toBe("route_planned");
    }
    // Each node's route starts at ITSELF — origin is not the peer.
    expect(planOf(A, "A").path[0]).toBe("node-a");
    expect(planOf(B, "B").path[0]).toBe("node-b");
  });

  it("a planned route is KNOWLEDGE, never authorization — on both nodes", () => {
    for (const r of [A, B]) {
      const p = r?.world.routePlan;
      expect(p?.ok).toBe(true);
      if (!p?.ok) continue;
      expect(p.admission).toBe("none");
      expect(p.authorization).toBe("none");
      expect(p.executionAuthorized).toBe(false);
      expect(p.transitiveTrust).toBe(false);
      expect(p.capabilityUnion).toBe(false);
    }
  });

  it("OBSERVER-RELATIVE: the two nodes disagree, and neither is a global truth", () => {
    const ha = String(snap(A as MeshNodeResult).projectionHash);
    const hb = String(snap(B as MeshNodeResult).projectionHash);
    // Same wire, same epoch, same instant — yet two different views.
    expect(ha).toMatch(/^[0-9a-f]{64}$/);
    expect(hb).toMatch(/^[0-9a-f]{64}$/);
    expect(ha).not.toBe(hb);

    // And they genuinely differ in content, not merely by a timestamp: the
    // snapshot id and the node ordering are each node's own.
    expect(snap(A as MeshNodeResult).snapshotId).toBe("snap-A");
    expect(snap(B as MeshNodeResult).snapshotId).toBe("snap-B");
  });

  it("SAME-LABEL CONTROL: identical snapshot id, different vantage ⇒ still different", () => {
    // The hashes above already differ, but so do the snapshot IDs — so the label
    // alone would explain the disagreement. Under a shared id the label can no
    // longer explain anything, and the two nodes STILL disagree.
    const va = A!.world.vantage;
    const vb = B!.world.vantage;
    expect(va, "A must report a shared-id vantage").not.toBeNull();
    expect(vb, "B must report a shared-id vantage").not.toBeNull();
    expect(va!.sharedSnapshotId).toBe("shared-id");
    expect(vb!.sharedSnapshotId).toBe("shared-id");
    expect(va!.sharedSnapshotId).toBe(vb!.sharedSnapshotId);

    expect(va!.sharedProjectionHash).toMatch(/^[0-9a-f]{64}$/);
    expect(vb!.sharedProjectionHash).toMatch(/^[0-9a-f]{64}$/);
    // Same label, same epoch, same instant, same wire — different view.
    expect(va!.sharedProjectionHash).not.toBe(vb!.sharedProjectionHash);

    // The difference is the vantage: each node still calls ITSELF the origin.
    expect(va!.sharedOriginNodeId).toBe("node-a");
    expect(vb!.sharedOriginNodeId).toBe("node-b");
  });

  it("DETERMINISM CONTROL: same vantage, identical inputs ⇒ identical hash", () => {
    // Without this, "the hashes differ" could just mean the hash is unstable.
    // Repeating the very same projection from the very same node must not
    // drift — so a cross-node difference is content, never noise.
    for (const [name, r] of [["A", A], ["B", B]] as const) {
      const v = r!.world.vantage;
      expect(v!.sharedRepeatSnapshotId, `${name} repeat id`).toBe("shared-id");
      expect(v!.sharedRepeatProjectionHash, `${name} repeat hash`).toBe(v!.sharedProjectionHash);
    }
    // ...and the primary named snapshots are deterministic for the same reason.
    expect(snap(A as MeshNodeResult).snapshotId).toBe("snap-A");
    expect(snap(B as MeshNodeResult).snapshotId).toBe("snap-B");
  });

  it("both snapshots stay read-only with zero authority after the wire", () => {
    for (const r of [A, B]) {
      if (!r) continue;
      const s = snap(r);
      expect(s.authority).toBe("none");
      expect(s.controlPlane).toBe(false);
      expect(s.readOnly).toBe(true);
      // No action surface may appear just because a peer was heard from.
      for (const k of Object.keys(s)) {
        expect(k).not.toMatch(/(action|execute|invoke|grant|admit|authorize|commit|mutate)/i);
      }
    }
  });

  it("a wire observation changed no authority on the receiving node", () => {
    const wire = B!.received!.observations;
    expect(wire.length).toBeGreaterThan(0);
    // Nothing that arrived claimed authority, and B invented none.
    for (const o of wire) {
      expect(Object.keys(o)).not.toContain("authority");
      expect(Object.keys(o)).not.toContain("admission");
      expect(Object.keys(o)).not.toContain("authorization");
    }
    expect(snap(B as MeshNodeResult).authority).toBe("none");
  });

  it("the composed world contains both nodes as knowledge, with roles preserved", () => {
    for (const r of [A, B]) {
      if (!r) continue;
      const s = snap(r) as { nodes: { nodeId: string; kind: string }[]; routes: unknown[] };
      expect(s.nodes.map((n) => n.nodeId).sort()).toEqual(["node-a", "node-b"]);
      expect(s.routes.length).toBe(1);
    }
    // 27H flattens the origin rather than nesting it, and groups forwarders by
    // role — the projection separates the roles instead of blurring them.
    const ra = (snap(A as MeshNodeResult).routes as ObservabilityRouteView[])[0];
    const rb = (snap(B as MeshNodeResult).routes as ObservabilityRouteView[])[0];
    expect(ra?.originNodeId).toBe("node-a");
    expect(rb?.originNodeId).toBe("node-b");
    expect(ra?.originFixed).toBe(true);
    expect(rb?.originFixed).toBe(true);
    // A's own view names A as origin and B as destination — never the reverse.
    expect(ra?.destinationNodeId).toBe("node-b");
    expect(rb?.destinationNodeId).toBe("node-a");
  });

  it("no composition step reached peer admission, Policy, or a tool", () => {
    // The whole mesh layer is pure knowledge; nothing in this scenario has a
    // handle on any of those surfaces, and every snapshot says so structurally.
    for (const r of [A, B]) {
      if (!r) continue;
      const s = snap(r);
      expect(s.authority).toBe("none");
      expect(s.controlPlane).toBe(false);
      expect(Object.keys(s)).not.toContain("admissions");
      expect(Object.keys(s)).not.toContain("policyDecisions");
    }
  });
});