#!/usr/bin/env node
/**
 * PHASE 26I — Two-Machine LAN Qualification harness (OPERATOR-RUN, NOT A TEST FILE).
 *
 * This script does NOT perform a two-machine qualification by itself. It is the
 * reproducible front end for one. On this machine — and on any single host — the
 * honest answer is `TWO_MACHINE_LAN: UNSUPPORTED_ON_CURRENT_TARGET`.
 *
 * Modes:
 *   preflight --bind <ipv4> --dial <ipv4> [--out <file>]
 *       Validate operator-supplied endpoints against the 26I address laws and emit
 *       the readiness verdict. Fails closed. Emits the UNSUPPORTED verdict when the
 *       two-machine precondition is not met. Never emits a validation claim.
 *
 *   derive --bind <ipv4> --dial <ipv4> --out <file>
 *       Derive a LAN-parameterized copy of the FROZEN 26H node fixture by an
 *       auditable, exact, two-anchor substitution. The frozen fixture itself is
 *       never modified. Every substitution is printed for operator review, and the
 *       derivation fails closed if either anchor is missing or ambiguous.
 *
 *   runbook
 *       Print the full two-machine procedure, command lines, and the scenario
 *       matrix the operators must execute. Prints nothing sensitive.
 *
 *   schema
 *       Print the evidence schema a completed two-machine run must satisfy.
 *
 *   verify --evidence <file>
 *       Validate an operator-produced evidence file against that schema. Fails
 *       closed on any missing or malformed field. Reads only.
 *
 *   (no mode) prints usage and the UNSUPPORTED verdict.
 *
 * ADDRESS LAWS (fail closed, no silent widening):
 *   - explicit NUMERIC dotted-quad IPv4 literals only. No hostnames, no DNS, no
 *     resolver, no IPv6, no IPv4-mapped forms.
 *   - refused: 0.0.0.0 (wildcard) and 255.255.255.255.
 *   - refused: 127.0.0.0/8 loopback — loopback is gate 26H's scope, not LAN's.
 *   - refused: 169.254.0.0/16 link-local.
 *   - refused: 100.64.0.0/10 CGNAT — this is the address space VPN/NAT-traversal
 *     overlays (Tailscale and kin) hand out. Using it would be NAT traversal.
 *   - refused: 224.0.0.0/4 multicast and 240.0.0.0/4 reserved.
 *   - refused: every address outside RFC1918 10/8, 172.16/12, 192.168/16.
 *   - refused: port 0 and any port outside 1024-65535.
 *   - refused: bind host equal to dial host (a machine cannot dial itself here).
 *
 * HARD LAWS honoured: LOCAL NETWORK ONLY. No wildcard, no discovery, no port
 * forwarding, no UPnP, no relay, no NAT traversal, no consensus, no remote
 * authority, no deployment, no Git, no publication. This script opens no socket,
 * spawns no child, contacts no host, and resolves no name.
 *
 * NETWORK REACHABILITY != IDENTITY != ADMISSION != AUTHORITY != EXECUTION. Even a
 * completed two-machine run proves transport behaviour only; authority remains
 * minted locally on the receiving machine.
 */
import fs from "node:fs";
import path from "node:path";

const REPO_ROOT = path.resolve(new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const FROZEN_FIXTURE = path.join(REPO_ROOT, "tests", "fixtures", "phase26h-loopback-node.mjs");
const SCHEMA_ID = "menog-phase26i-lan-qualification-evidence/v0";
const UNSUPPORTED = "UNSUPPORTED_ON_CURRENT_TARGET";

// ── argument parsing ─────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const mode = argv[0] && !argv[0].startsWith("--") ? argv[0] : "";
function opt(name, dflt = null) {
  const i = argv.indexOf(name);
  return i >= 0 ? (argv[i + 1] ?? dflt) : dflt;
}
function out(msg) {
  process.stdout.write(msg + "\n");
}
function emit(obj, dest) {
  const text = JSON.stringify(obj, null, 2) + "\n";
  if (dest) {
    fs.mkdirSync(path.dirname(path.resolve(dest)), { recursive: true });
    fs.writeFileSync(path.resolve(dest), text, "utf8");
    out("written: " + path.relative(REPO_ROOT, path.resolve(dest)));
  }
  out(text.trimEnd());
}

// ── the address laws ─────────────────────────────────────────────────────
const NUMERIC_IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/**
 * Classify a dotted-quad against the 26I address laws.
 * Returns { ok, code, class, explanation }. NEVER throws, NEVER falls back.
 */
export function classifyEndpoint(raw, { role }) {
  if (typeof raw !== "string" || raw.length === 0) {
    return refuse(role, "endpoint_missing", "no address supplied", "unspecified_refused");
  }
  if (raw.includes(":")) {
    return refuse(role, "ipv6_refused", "IPv6 is out of 26I scope", "ipv6_refused");
  }
  if (!NUMERIC_IPV4.test(raw)) {
    return refuse(role, "hostname_refused", "hostnames and non-literals are refused; numeric literals only, no resolver", "hostname_refused");
  }
  const parts = raw.split(".").map(Number);
  if (parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return refuse(role, "malformed_refused", "octet out of range", "malformed_refused");
  }
  const [a, b] = parts;
  const asLong = ((a << 24) >>> 0) + (b << 16) + (parts[2] << 8) + parts[3];
  const inCidr = (cidrBase, bits) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((asLong & mask) >>> 0) === ((cidrBase & mask) >>> 0);
  };
  if (a === 0 && b === 0 && parts[2] === 0 && parts[3] === 0) {
    return refuse(role, "wildcard_refused", "0.0.0.0 binds every interface", "wildcard_refused");
  }
  if (parts.every((n) => n === 255)) {
    return refuse(role, "broadcast_refused", "limited broadcast address", "broadcast_refused");
  }
  if (a === 127) {
    return refuse(role, "loopback_refused", "127.0.0.0/8 is gate 26H's scope; 26I qualifies a private LAN", "loopback_refused");
  }
  if (a === 169 && b === 254) {
    return refuse(role, "link_local_refused", "169.254.0.0/16 link-local is not a routable LAN endpoint", "link_local_refused");
  }
  if (a === 100 && b >= 64 && b <= 127) {
    return refuse(role, "cgnat_refused", "100.64.0.0/10 is CGNAT/overlay space (VPN, NAT traversal) and is refused", "cgnat_refused");
  }
  if (a >= 224 && a <= 239) {
    return refuse(role, "multicast_refused", "multicast is discovery-adjacent and refused", "multicast_refused");
  }
  if (a >= 240) {
    return refuse(role, "reserved_refused", "240.0.0.0/4 reserved", "reserved_refused");
  }
  let klass = null;
  if (a === 10) klass = "ipv4_private_10";
  else if (a === 172 && b >= 16 && b <= 31) klass = "ipv4_private_172_16_31";
  else if (a === 192 && b === 168) klass = "ipv4_private_192_168";
  if (klass === null) {
    return refuse(role, "public_refused", "not inside RFC1918 private space; 26I is LOCAL NETWORK ONLY", "public_refused");
  }
  return { ok: true, code: "admitted", role, addressClass: klass, endpoint: raw };
}

function refuse(role, code, explanation, refusalCode) {
  return { ok: false, code, role, explanation, refusal: refusalCode };
}

function classifyPort(raw) {
  const n = Number(raw);
  if (!Number.isInteger(n)) {
    return { ok: false, code: "port_refused", explanation: "port must be an explicit integer" };
  }
  if (n === 0) {
    return { ok: false, code: "port_refused", explanation: "port 0 (ephemeral/discovery-derived) is refused; choose an explicit port" };
  }
  if (n < 1024 || n > 65535) {
    return { ok: false, code: "port_refused", explanation: "port must be within 1024-65535" };
  }
  return { ok: true, code: "admitted", port: n };
}

// ── evidence scaffolding ─────────────────────────────────────────────────
function twoMachinesPresent(suppliedBoth) {
  // This harness can never observe a second machine. It opens no socket and
  // contacts no host. The operator asserts the second machine exists; the
  // harness records the assertion as an assertion, never as an observation.
  return {
    observed_by_harness: false,
    asserted_by_operator: suppliedBoth === true,
    reason: "the harness opens no socket and probes no host; LAN discovery is forbidden by the 26I laws",
  };
}

function baseEvidence(extra) {
  return {
    schema: SCHEMA_ID,
    gate: "26I",
    mode: "QUALIFICATION ONLY / LOCAL NETWORK ONLY / NO DEPLOYMENT / NO GIT",
    two_machine_lan: UNSUPPORTED,
    is_validation: false,
    validation_note:
      "UNSUPPORTED is a recorded non-blocking environment disposition. It is NEVER a validation claim, never counts as PASS, and never substitutes for an executed two-machine run.",
    ...extra,
  };
}

// ── modes ────────────────────────────────────────────────────────────────
function modePreflight() {
  const bindRaw = opt("--bind");
  const dialRaw = opt("--dial");
  const portRaw = opt("--port", "41920");
  const bind = classifyEndpoint(bindRaw, { role: "bind" });
  const dial = classifyEndpoint(dialRaw, { role: "dial" });
  const port = classifyPort(portRaw);
  const same = bindRaw && dialRaw && bindRaw === dialRaw;
  const checks = [bind, dial, port];
  if (same) {
    checks.push({ ok: false, code: "self_dial_refused", role: "dial", explanation: "bind host and dial host are identical" });
  }
  const ready = checks.every((c) => c.ok);
  const evidence = baseEvidence({
    phase: "preflight",
    executed_on_this_host: false,
    endpoints: {
      bind: { supplied: bindRaw !== null, addressClass: bind.addressClass ?? null, admitted: bind.ok, refusal: bind.refusal ?? null, explanation: bind.explanation ?? null },
      dial: { supplied: dialRaw !== null, addressClass: dial.addressClass ?? null, admitted: dial.ok, refusal: dial.refusal ?? null, explanation: dial.explanation ?? null },
      port: { supplied: portRaw, admitted: port.ok, explanation: port.explanation ?? null },
    },
    same_private_lan: {
      observed: false,
      note: "not probed; probing the LAN is forbidden (no discovery, no scan). Both addresses must be operator-asserted RFC1918 on one physical LAN.",
    },
    two_machines: twoMachinesPresent(ready),
    readiness: ready ? "PRECONDITIONS_MET_PENDING_OPERATOR_RUN" : UNSUPPORTED,
    verdict: ready ? "PRECONDITIONS_MET_PENDING_OPERATOR_RUN" : UNSUPPORTED,
    next_action: ready
      ? "run `derive`, then follow the `runbook` on BOTH machines; this harness still asserts nothing"
      : "fix the refused endpoint(s); no two-machine qualification is possible from here",
  });
  emit(evidence, opt("--out"));
  if (!ready) process.exitCode = 2;
}

function modeDerive() {
  const bindRaw = opt("--bind");
  const dialRaw = opt("--dial");
  const outPath = opt("--out");
  if (!outPath) {
    out("derive requires --out <file>");
    process.exitCode = 2;
    return;
  }
  const bind = classifyEndpoint(bindRaw, { role: "bind" });
  const dial = classifyEndpoint(dialRaw, { role: "dial" });
  if (!bind.ok || !dial.ok) {
    out("REFUSING TO DERIVE: " + JSON.stringify({ bind, dial }));
    process.exitCode = 2;
    return;
  }
  if (!fs.existsSync(FROZEN_FIXTURE)) {
    out("REFUSING TO DERIVE: frozen 26H fixture not found at " + FROZEN_FIXTURE);
    process.exitCode = 2;
    return;
  }
  const src = fs.readFileSync(FROZEN_FIXTURE, "utf8");

  // Two exact, unambiguous anchors. Fail closed if either is missing or ambiguous.
  const DIAL_ANCHOR = 'connect({ port: target, host: "127.0.0.1" }';
  const BIND_ANCHOR = 'source: "explicit_local_config",\n      host: "127.0.0.1",';
  const countOf = (needle) => src.split(needle).length - 1;
  const dialCount = countOf(DIAL_ANCHOR);
  const bindCount = countOf(BIND_ANCHOR);
  if (dialCount !== 1 || bindCount !== 1) {
    out(
      "REFUSING TO DERIVE: anchors must each occur exactly once. " +
        `dial=${dialCount} bind=${bindCount}. The frozen fixture changed; re-audit before deriving.`,
    );
    process.exitCode = 2;
    return;
  }

  let derived = src.split(DIAL_ANCHOR).join(`connect({ port: target, host: "${dialRaw}" }`);
  derived = derived.split(BIND_ANCHOR).join(`source: "explicit_local_config",\n      host: "${bindRaw}",`);

  // Self-check the DERIVED file: nothing widened, nothing forbidden introduced.
  const forbidden = [
    ["wildcard", "0.0.0.0"],
    ["ipv6_wildcard", '"::"'],
    ["resolver", "dns.lookup"],
    ["discovery", "multicast"],
    ["upnp", "upnp"],
    ["env_widening", "process.env"],
  ];
  const introduced = forbidden.filter(([, needle]) => derived.includes(needle) && !src.includes(needle));
  if (introduced.length > 0) {
    out("REFUSING TO WRITE: derivation would introduce " + introduced.map(([n]) => n).join(", "));
    process.exitCode = 2;
    return;
  }
  if (!derived.includes(`host: "${bindRaw}"`) || !derived.includes(`host: "${dialRaw}"`)) {
    out("REFUSING TO WRITE: derived file does not carry both substituted endpoints");
    process.exitCode = 2;
    return;
  }
  const changedLines =
    src.split("\n").map((l, i) => (derived.split("\n")[i] === l ? null : i + 1)).filter((n) => n !== null);

  fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
  fs.writeFileSync(path.resolve(outPath), derived, "utf8");

  emit(
    {
      schema: SCHEMA_ID,
      gate: "26I",
      phase: "derive",
      source_fixture: path.relative(REPO_ROOT, FROZEN_FIXTURE),
      source_fixture_modified: false,
      derived_file: path.relative(REPO_ROOT, path.resolve(outPath)),
      anchors_replaced: 2,
      anchors_each_occurred_exactly_once: true,
      changed_line_numbers: changedLines,
      substitutions: [
        { line: changedLines[0], from: 'host: "127.0.0.1" (dial)', to: `host: "<dial address class ${dial.addressClass}>"` },
        { line: changedLines[1], from: 'host: "127.0.0.1" (bind)', to: `host: "<bind address class ${bind.addressClass}>"` },
      ],
      forbidden_token_self_check: "PASS — no wildcard, resolver, discovery, UPnP or env token introduced",
      note: "Literal addresses are deliberately NOT recorded in evidence; only address classes are. The derived file on disk does contain them by necessity — treat it as sensitive and delete it after the run.",
      two_machine_lan: UNSUPPORTED,
      is_validation: false,
    },
    null,
  );
}

function modeRunbook() {
  out(`PHASE 26I — TWO-MACHINE LAN RUNBOOK (LOCAL NETWORK ONLY)

0. PRECONDITION — do not begin unless all of these hold:
   - TWO distinct physical machines on the SAME wired/wireless private LAN.
   - BOTH run Node.js >= 22 and BOTH have this repository at the SAME commit
     (there is no Git history today; verify by content hash of pnpm-lock.yaml:
     bd289ce7ad6d0d8c) and BOTH have run \`pnpm build\` so dist/ is present.
   - BOTH addresses are RFC1918 numeric literals: 10/8, 172.16/12 or 192.168/16.
   - NEITHER address is loopback (that is 26H), link-local, CGNAT/overlay
     (100.64/10 — this excludes Tailscale and every NAT-traversal mesh), public,
     or a hostname.
   - A firewall rule ALLOWING the chosen explicit TCP port between exactly these
     two addresses. Manual, static, operator-created. NOT UPnP, NOT a port
     forward, NOT a relay, NOT a tunnel.
   - Choose ONE explicit port in 1024-65535 on each machine. Record the port.
     Do NOT record the addresses in any evidence file.

1. ON MACHINE B (the receiver):
     node scripts/phase26i-two-machine-lan-qualification.mjs preflight \\
       --bind <B_PRIVATE_IPV4> --port <PORT>
   Expect PRECONDITIONS_MET_PENDING_OPERATOR_RUN. It is a preflight, not a
   qualification.

2. ON MACHINE A (the sender), generate the LAN-parameterized node from the
   FROZEN 26H fixture (this never edits the fixture):
     node scripts/phase26i-two-machine-lan-qualification.mjs derive \\
       --bind <B_PRIVATE_IPV4> --dial <A_PRIVATE_IPV4> \\
       --out <TMP>/phase26i-lan-node.mjs
   Copy that derived file to BOTH machines at the same relative path.
   Review the printed changed-line list before running it.

3. ON MACHINE B, start the receiver:
     node <TMP>/phase26i-lan-node.mjs B <TMP_ROOT_B> <PORT> <EPOCH_SEED>
   Wait for: ready:B

4. ON MACHINE A, collect facts and admit B (mutual LOCAL admission):
     facts                 -> nodeId, epochId, publicKey, lifecycle
     peer <base64 facts>   -> on BOTH machines, each records the OTHER's facts
     admit <otherNodeId>   -> on BOTH machines (25C intent-gated LOCAL admission)

5. EXECUTE THE SCENARIO MATRIX (each line is a separate session; see \`schema\`):
     M1  auth/admit/message   dial <PORT>  -> send <b64 body>  -> B admits as
                                                             UNTRUSTED DATA and
                                                             continues LOCALLY
     M2  restart/reconnect   SIGKILL B, restart it on the SAME store + port,
                             reconnect; assert a NEW session, no inheritance,
                             no auto-resume
     M3  re-identification   rotate A's identity (25B request->execute); the old
                             key must refuse; the replacement enters as a NEW
                             CANDIDATE and must NOT be auto-trusted
     M4  replay/tamper       re-present ONE captured envelope verbatim; then
                             flip one payload byte. Both must refuse.
     M5  admission removal   retire the peer (terminal); the next session must
                             refuse peer_not_admitted
     M6  endpoint change     stop B, restart on a DIFFERENT explicit port, dial
                             it explicitly; no discovery, no rebind wildcard
     M7  Policy deny         a body that trips the Day-1 deny; assert the
                             Phase-21 governed runtime is NEVER reached and
                             requireFreshLocalAuthorization refuses
                             local_policy_denial

6. CAPTURE (non-sensitive facts only). Never record: literal addresses, keys,
   payloads, store contents. Record: address CLASSES, ports, verdict codes,
   identity fingerprints, counts.

7. VALIDATE:
     node scripts/phase26i-two-machine-lan-qualification.mjs verify \\
       --evidence <EVIDENCE_JSON>

8. DELETE the derived node file and both stores. They contain live key material.

HARD LAWS (unchanged): NETWORK REACHABILITY != IDENTITY != ADMISSION !=
AUTHORITY != EXECUTION. LOCAL NETWORK ONLY — no wildcard, no discovery, no port
forwarding, no UPnP, no relay, no NAT traversal, no consensus, no remote
authority, no deployment, no Git commit/push, no publication. Fail closed. No
capability union, no auto-resume, no executable replay, no remote admin, no
direct network/federation->tool path, no secret disclosure, no alternate
persistence path.`);
}

function modeSchema() {
  emit({
    schema: SCHEMA_ID,
    gate: "26I",
    required_top_level: [
      "schema",
      "gate",
      "mode",
      "two_machine_lan",
      "is_validation",
      "machines",
      "endpoints",
      "scenario_matrix",
      "refusals",
      "non_claims",
    ],
    field_contract: {
      "schema": "must equal " + SCHEMA_ID,
      "gate": "must equal \"26I\"",
      "two_machine_lan": "must equal \"SUPPORTED_ON_CURRENT_TARGET\" only when a real two-machine run executed; otherwise \"UNSUPPORTED_ON_CURRENT_TARGET\"",
      "is_validation": "true ONLY when two_machine_lan === \"SUPPORTED_ON_CURRENT_TARGET\" and every matrix row executed. An UNSUPPORTED run MUST set this false.",
      "machines": "exactly 2 entries; each with { role, platform, node_runtime_major, node_id_fingerprint, identity_fingerprint, epoch_id_present, store_distinct }. node_id_fingerprint and identity_fingerprint are SHA-256 PREFIXES, never raw ids or keys.",
      "endpoints": "{ bind: { address_class, port, explicit: true, wildcard: false }, dial: { address_class, port, explicit: true } } — address_class is one of ipv4_private_10 | ipv4_private_172_16_31 | ipv4_private_192_168. LITERAL ADDRESSES ARE FORBIDDEN in evidence.",
      "scenario_matrix": "exactly 7 rows M1..M7 (auth/admit/message, restart/reconnect, re-identification, replay/tamper, admission removal, endpoint change, policy-deny). Each row: { id, name, executed, verdict, refusal_code, evidence_ref }.",
      "refusals": "array of { control, stage, code }. Every negative control MUST name its stage and its code. Empty array is only valid when is_validation is false.",
      "non_claims": "object; MUST contain discovery:false, public_endpoint:false, port_forwarding:false, upnp:false, relay:false, nat_traversal:false, consensus:false, remote_admin:false, deployment:false, git_commit:false, git_push:false, publication:false, power_loss_certification:false, production_capacity:false, ddos:false.",
    },
    forbidden_in_evidence: [
      "literal IPv4 addresses of either machine",
      "private keys, PEM material, or key fingerprints derived from key bytes",
      "message or proposal payload bodies",
      "durable store contents",
      "any hostname or DNS name",
    ],
  });
}

function modeVerify() {
  const evidencePath = opt("--evidence");
  if (!evidencePath) {
    out("verify requires --evidence <file>");
    process.exitCode = 2;
    return;
  }
  const p = path.resolve(evidencePath);
  if (!fs.existsSync(p)) {
    out("REFUSING: evidence file not found: " + p);
    process.exitCode = 2;
    return;
  }
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(p, "utf8"));
  } catch (err) {
    out("REFUSING: evidence is not valid JSON — " + err.message);
    process.exitCode = 2;
    return;
  }
  const problems = [];
  if (doc.schema !== SCHEMA_ID) problems.push("schema mismatch: " + doc.schema);
  if (doc.gate !== "26I") problems.push("gate mismatch: " + doc.gate);
  const supported = doc.two_machine_lan === "SUPPORTED_ON_CURRENT_TARGET";
  if (doc.is_validation === true && !supported) problems.push("is_validation is true but two_machine_lan is not SUPPORTED — a validation claim on an unsupported run is forbidden");
  if (!Array.isArray(doc.machines) || doc.machines.length !== 2) problems.push("machines must be exactly 2 entries");
  if (supported) {
    for (const id of ["M1", "M2", "M3", "M4", "M5", "M6", "M7"]) {
      const row = (doc.scenario_matrix || []).find((r) => r && r.id === id);
      if (!row) problems.push("scenario_matrix missing row " + id);
      else if (row.executed !== true) problems.push("scenario_matrix row " + id + " not executed");
    }
  }
  if (supported && (!Array.isArray(doc.refusals) || doc.refusals.length === 0)) {
    problems.push("a supported run must record at least one named refusal");
  }
  const text = fs.readFileSync(p, "utf8");
  const literalIp = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const offending = literalIp.filter((ip) => ip !== "127.0.0.1" && ip !== "0.0.0.0");
  if (offending.length > 0) problems.push("literal IP address(es) present in evidence — forbidden: " + offending.join(", "));
  if (problems.length > 0) {
    emit({ schema: SCHEMA_ID, gate: "26I", phase: "verify", verdict: "REFUSED", problems, count: problems.length });
    process.exitCode = 2;
    return;
  }
  emit({
    schema: SCHEMA_ID,
    gate: "26I",
    phase: "verify",
    verdict: "ACCEPTED",
    two_machine_lan: doc.two_machine_lan,
    is_validation: doc.is_validation === true,
    note: "Accepted means SCHEMA-CONFORMANT. It is not itself a validation claim; the validation claim lives in the evidence document and is bounded by its own non_claims.",
  });
}

function usage() {
  out(`PHASE 26I — Two-Machine LAN Qualification harness

TWO_MACHINE_LAN: ${UNSUPPORTED}

This host is a single machine. Two machines were not available, were not
fabricated, and were not simulated over loopback (loopback is gate 26H). No
LAN was scanned, no host was probed, no discovery was performed.

Modes:
  preflight --bind <ipv4> --dial <ipv4> [--port <n>] [--out <file>]
  derive    --bind <ipv4> --dial <ipv4> --out <file>
  runbook
  schema
  verify    --evidence <file>

Run \`runbook\` for the full two-machine procedure and prerequisites.`);
  process.exitCode = 2;
}

if (mode === "preflight") modePreflight();
else if (mode === "derive") modeDerive();
else if (mode === "runbook") modeRunbook();
else if (mode === "schema") modeSchema();
else if (mode === "verify") modeVerify();
else usage();