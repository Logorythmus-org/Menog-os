// PHASE 22A — durable-state trust model (contracts + pure decisions only).
// No backend, no I/O, no authority. Storage arrives in 22B.

export * from "./records.js";
export * from "./canonical.js";
export * from "./classification.js";
export * from "./persist.js";
export * from "./recovery.js";

// PHASE 22C — durable ledger & tool-evidence persistence (append-only
// integration). Structural mirrors + an injected ledger-hash port: the frozen
// @menog/event-ledger hash vocabulary is supplied by the caller, never
// re-implemented here.
export * from "./ledgerEvidence.js";

// PHASE 22D — durable memory, agent & task lifecycle state (STATE
// PERSISTENCE / NO AUTHORITY RESTORATION).
export * from "./statePersistence.js";

// PHASE 22E — startup recovery, reconciliation & schema migration
// (RECOVERY / NO EXECUTABLE REPLAY).
export * from "./startupRecovery.js";

// PHASE 23A — runtime continuity model & live/durable authority contract
// (CONTRACT-FIRST / NO LIVE WIRING). Pure vocabulary + fail-closed
// decisions; the 23B coordinator wires ON TOP of these laws.
export * from "./continuity.js";

// PHASE 23D — recovery bootstrap → live runtime handoff (STARTUP
// INTEGRATION / AUTHORITY SEPARATION). Explicit, evidenced pipeline:
// recovery first → classification → NEW epoch → views → LIVE on verified
// evidence. No reactivation, no auto-resume, hard/quarantine findings
// block LIVE.
export * from "./handoff.js";

// PHASE 23C — live memory, task, agent & registry continuity wiring
// (INTEGRATION / NO AUTO-RESUME). All writes through the 23B junction;
// views re-verify the 22D invariants; recovery bootstrap exposes facts.
export * from "./surfaceWiring.js";

// PHASE 23B — the runtime state coordinator & durability barrier (the ONE
// sanctioned live→durable junction; NEITHER Policy NOR execution authority).
export * from "./coordinator.js";

// PHASE 24A — federation trust model & node identity contract
// (CONTRACT-FIRST / NO NETWORK / NO EXECUTION API). Closed peer vocabulary
// + pure fail-closed decisions; the signature verifier is a caller-injected
// port (24B supplies the real one). Nothing here talks to a network or the
// launcher; identity/admission/trust never grant execution authority.
export * from "./federationIdentity.js";

// PHASE 24B — local cryptographic identity & signed envelopes (NO NETWORK
// / NO KEY PERSISTENCE / VERIFICATION NEVER AUTHORIZES). Real Ed25519
// signer/verifier behind the 24A port over the 22A canonical encoding;
// secret-key denylist; proven rotation = re-identity; public-facts restart
// continuity. No CA/WebPKI/DID/blockchain/wallet claims.
export * from "./federationCrypto.js";

// PHASE 24C — peer registry, admission & quarantine (LOCAL STATE MACHINE
// / SANCTIONED PERSISTENCE ONLY). The ONLY durable home for peer trust
// facts (new 22A kind peer_trust_registry); all writes through the 23B
// coordinator junction; terminal peers never resurrect; recovered peer
// facts are recovered_data (no authority).
export * from "./federationPeers.js";

// PHASE 24D — authenticated bounded federation message bus (IN-PROCESS
// FIXTURE ONLY / FAIL CLOSED). The pack pipeline over 24A/24B/24C:
// envelope shape → durable peer admission → real signature → protocol →
// replay/freshness → contract decision → append-only durable receipt →
// typed inbox. Receipts never invoke tools; payload stays untrusted DATA.
export * from "./federationBus.js";

// PHASE 24E — cross-node task proposal protocol (PROPOSAL-ONLY / FAIL
// CLOSED). Consumes 24D `task_proposal` inbox entries: strict untrusted-
// payload validation → durable inert `federation_proposal` record (third
// 22A unfreeze kind) → untrusted local candidate → the caller runs LOCAL
// allocation + LOCAL Policy fresh; `requireFreshLocalAuthorization` gates
// any Phase-20/21 execution. A proposal never grants capabilities, never
// chooses Policy, never invokes anything; no super-agent, no capability
// union; Policy can always deny.
export * from "./federationProposals.js";

// PHASE 24F — federated provenance & cross-node evidence (EVIDENCE-ONLY /
// NO NEW AUTHORITY). Durable tamper-evident BINDINGS of cross-node
// happenings over EXISTING primitives (22A append-only kind + 23B junction
// + 22A canonical hashing): proposal → receipt → candidate → allocation →
// policy → execution links with signature results, admission facts, payload
// hashes, lineage, commit refs, and response hashes — plus deterministic
// explanations for admit/refuse/quarantine/local-action. Foreign evidence
// is DATA, never local authority; missing links and hash mismatches are
// explicit; no total order, no consensus, no replay.
export * from "./federationProvenance.js";

// PHASE 25A — operational federation trust boundary (CONTRACT-FIRST / NO
// NETWORK / NO NEW AUTHORITY). Closed operational-risk vocabulary
// (OT-01..OT-12), boundary-plane decision model, key-storage boundary
// (private keys memory-only; durable/egress key material is a finding),
// and deterministic fail-closed decisions for ingress/egress/restart:
// IDENTITY != AUTHORITY, AUTHENTICATION != ADMISSION, ADMISSION !=
// EXECUTION, EVIDENCE != AUTHORITY, RECOVERY != AUTHORITY,
// KEY_POSSESSION != POLICY_ALLOW, rotation never inherits trust unless
// locally evidenced. Pure decisions with deterministic explanations.
export * from "./federationTrustBoundary.js";

// PHASE 25B — identity/key lifecycle operations (LOCAL ONLY / NO NETWORK /
// NO KEY-EXPORT API). Closed lifecycle state machine over the frozen 24B
// PUBLIC facts (initialize → active → rotation_requested → rotated →
// revoked → retired): evidenced transitions, stale/revoked-key refusal,
// revocation survives restart, rollback cannot resurrect keys, duplicate/
// conflicting rotations refuse, secret-shaped keys never enter any record,
// rotation never inherits trust (25A P7). Private keys are never received,
// held, exported, or observed by this layer; platform Ed25519 (24B) is
// reused as-is — no new dependency, no new durable kind, no schema change.
export * from "./federationKeyLifecycle.js";

// PHASE 25C — peer trust operations & local administration (NO REMOTE
// CONTROL PLANE). Narrow LOCAL admin layer over the frozen 24C registry:
// inspect/list, evidenced admit/quarantine/retire, re-identity relation
// recording, explain/history — every mutation intent-gated
// (local_operator only), epoch-checked (stale admin epochs fail), and
// delegated ONLY through the sanctioned 24C→23B junction (no direct-store
// bypass). A peer message can never be an admin command; terminal states
// never resurrect; a replacement identity starts as a new candidate.
export * from "./federationPeerAdmin.js";

// PHASE 25D — federation egress disclosure & data-minimization gate
// (NO NETWORK / PRE-TRANSPORT / DEFAULT DENY). The ONE sanctioned gate
// answering what may LEAVE a node: closed content classes (public identity
// / protocol metadata / hashes / bounded intent / provenance + evidence
// refs) vs forbidden classes (secrets/private keys, raw hidden Policy,
// raw tool output, local paths/env, process handles, executable material,
// unknown fields). Deep default-deny classification, redact-or-refuse
// (never widen), deterministic manifest bound to the outgoing payload
// hash, hard bounds, stale-disclosure detection. Disclosure grants no
// authority and performs no transport.
export * from "./federationEgress.js";

// PHASE 26A — transport trust model (CONTRACT-FIRST / NO SOCKET
// IMPLEMENTATION / NO NEW AUTHORITY). Closed endpoint/transport/frame/
// session/refusal/close/scope vocabularies with deterministic fail-closed
// decisions over caller-supplied facts: nine transport pins (reachability
// != identity, identity != admission, admission != authority,
// authenticated-session != execution, remote-message != local Policy,
// transport-success != application acceptance, connection-state != trust-
// state, reconnect != re-admission, network-evidence != authority), the
// closed TT-01..TT-18 threat catalog, pinned bounds, and the LOCAL NETWORK
// ONLY endpoint gate (public/discovery bind refuses at the contract layer).
// Pure decisions only — no sockets, no listener, no discovery, no crypto,
// no store access; 26B+ builds any real transport ON TOP of these laws.
export * from "./federationTransportTrust.js";
// PHASE 26B — the smallest explicit LOCAL endpoint/listener boundary
// (default no listener; loopback + explicit private numeric only; wildcard/
// public/hostname/discovery/env/auto-interface refused; bounded port/
// connections/queue; explicit start, idempotent stop; no shell/child/remote
// reconfiguration/forwarding). This is the FIRST real socket surface: the
// pure 26A trust contract stays the layer above it.
export * from "./endpointListenerBoundary.js";
// PHASE 26C — minimal binary-safe framed LOCAL socket transport: fixed
// 42-byte frame header (magic + version + type + length + required
// correlation only), frozen hard bounds (frame bytes, buffered unread,
// frames/window, connections, read/write/idle deadlines), length checked
// before any allocation, unknown version/type/malformed/oversize/truncated
// refuse and fault the session fail-closed; payload stays opaque DATA; no
// authentication, no federation, no clock, no I/O of its own.
export * from "./framedSocketTransport.js";
// PHASE 26D — authenticated session: binds the 26C framed transport to the
// frozen 24B/25B Ed25519 identity and key lifecycle. Three-message handshake
// (hello → reply → finish) binds protocol, NodeId, runtime epoch, active
// fingerprint/key-id, fresh per-session challenges and a canonical
// transcript hash; replayed transcripts, reused challenges, stale epochs,
// downgrades, old/rotated/revoked/retired keys and non-admitted
// fingerprints all refuse; current key/peer state is rechecked during the
// session so quarantine/retirement closes future ingress; endpoint facts
// are recorded evidence only (IP is never identity); private keys never
// appear on the wire or in evidence; authentication grants no authority.
export * from "./authenticatedSession.js";
// PHASE 26E — transport → federation ingress junction: THE ONE place live
// local-transport bytes become a federation message. The mandatory order is
// pinned and closed: frame validity (26A) → session binding (26D) → current
// key use (25B, live records, both sides) → current local admission (24C) →
// disclosure verification (25D where required) → frozen schema/version (24A
// closed body + version + claim scope) → authentication (24B Ed25519) →
// replay/receipt (24D durable) → untrusted inbox. Fail closed at the first
// stage, no fallback or widening; upstream codes are carried verbatim.
// Ingress grants nothing: the result is untrusted DATA with authority "none"
// and executionAuthorized false, and a closed authority-claim field set
// refuses any inbound allocation, Policy decision, actor binding, capability
// grant, or tool invocation. No store, no listener, no shell, no clock.
export * from "./transportIngressJunction.js";
// PHASE 26F — transport resilience & backpressure qualification: frozen
// bounds (queue depth, queued bytes, connections, reconnects, tracked
// resources, read/write/idle deadlines read from the 26C constants so the
// layers cannot drift), a closed failure catalog with exactly one
// transport disposition per class and NO resume/replay/execute entry, a
// reconnect decision that is always a NEW session inheriting nothing, a
// retry decision that can never bypass replay, and a resource ledger that
// makes "zero orphan handles/timers" checkable rather than claimed. No
// unbounded memory growth, deterministic idempotent close, no I/O, no
// socket, no timer, no wall clock, no store. DDoS/WAN/production-capacity/
// power-loss remain UNCLAIMED and are carried verbatim on every decision.
export * from "./transportResilience.js";
// PHASE 27A — the mesh trust model (contract-first, pure decisions): six
// mesh pins (edge != trust, path != admission, route != authorization,
// forwarder != origin, advertisement != grant, topology knowledge !=
// membership), closed Node/Edge/Path/Topology/Observation/Advertisement/
// Route/Hop/Origin/Forwarder/Destination vocabularies with fail-closed
// refusals, closed MAY/MAY-NOT mesh scope, and remote-claim handling in
// which every fact claim is DATA with authority 'none'. TOPOLOGY IS
// KNOWLEDGE, NOT AUTHORITY. No socket, no listener, no discovery, no
// routing execution, no store access, no clock; 27B+ builds real topology
// ON TOP of these laws.
export * from "./meshTopologyTrust.js";
// PHASE 27B — the explicit topology graph: ONE bounded, deterministic,
// LOCAL in-memory graph over the 27A contract. Records enter ONLY from
// explicit local configuration or governed evidence (closed provenance
// vocabulary, unknown source refuses); every node/edge carries provenance
// + epoch; duplicates are idempotent; conflicting, stale-epoch, malformed,
// unknown-kind, and dangling records refuse and change nothing; node/edge
// bounds are frozen constants (refuse, never evict). No discovery, no
// store, no clock, no Policy, no tool, and NO trust/admission/authority
// field exists on any record — topology and peer-trust state stay
// structurally separate. TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
export * from "./meshTopologyGraph.js";
// PHASE 27C — the topology-observation lifecycle, SEPARATE from
// PeerTrustState: closed 5-state machine (observed / stale /
// quarantined_observation / retired_observation / unknown_observation —
// disjoint from the frozen 24C trust vocabulary; every trust value
// refuses refused_cross_lifecycle_state), pinned transition table +
// reason->target map, terminal anti-resurrection (retired has NO
// out-edge), quarantine exits only to retirement, freshness ordering
// (stale facts and non-strict re-observation refuse), epoch boundary
// (cross-epoch records refuse and must recover first), and zero-authority
// recovery (authority "none", trustInherited false, autoResumed false as
// structural literals; observed recovers as STALE across epochs).
export * from "./meshTopologyLifecycle.js";
// PHASE 27D — capability advertisements as UNTRUSTED REMOTE CLAIMS ONLY:
// ONE bounded, versioned, provenance-rich LOCAL registry over the frozen
// 27A advertisement contract. ADVERTISEMENT != CAPABILITY GRANT — every
// decision carries grant "none" and capabilitiesWidened false as
// structural literals; claims can never widen agent/tool/Policy/
// isolation capability and are never unioned (rotation REPLACES the old
// claim set). Frozen bounds (total/per-claimant/claims/field sizes) with
// refuse-never-evict; integer versions advance by exactly one (new ids
// start at 1; stale versions, same-version conflicts, version gaps,
// claimant hijacks, and stale rotation facts all refuse); closed
// provenance vocabulary (local_configuration | governed_evidence |
// unknown_source refuses); every string surface scanned for secret /
// executable / forbidden material (JSON-nested payloads parsed at depth)
// before anything is recorded. In-memory only: no socket, no listener, no
// discovery, no clock, no store, no Policy, no tool. TOPOLOGY IS
// KNOWLEDGE, NOT AUTHORITY.
export * from "./meshCapabilityAdvertisement.js";
// PHASE 27E — bounded deterministic route & path planning over explicit
// topology: shortest-hop routes with lexicographic tie-breaks, loop and
// graph-explosion detection, observation overlay (stale/quarantined never
// route), composed with the frozen 27A path/route decisions. ROUTE !=
// AUTHORIZATION, PATH != ADMISSION: every success carries admission:
// "none", authorization: "none", executionAuthorized: false,
// transitiveTrust: false, capabilityUnion: false as structural literals.
// Pure knowledge: no socket, no listener, no spawn, no clock, no store,
// no Policy, no tool. TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
export * from "./meshRoutePlanning.js";
// PHASE 27F — governed logical multi-hop proposal forwarding over the
// existing sanctioned transport: immutable origin (27A M4 composed),
// binding proposalId ↔ proposalHash identity, append-only provenance,
// bounded descending hop budget, replay detection, 25D material scan.
// FORWARD != ENDORSE: every success carries authority: "none",
// endorsement: "none", originFixed: true, capabilityWidened: false,
// admissionBypassed: false, executionAuthorized: false as structural
// literals. Pure knowledge: no socket, no listener, no spawn, no clock,
// no store, no Policy, no tool. TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
export * from "./meshForwarding.js";
// PHASE 27G — partition & reconciliation of LOCAL world-views: pure
// merge that never mutates either view — conflicts stay ATTRIBUTABLE
// (both claims/owners/times), 27C terminal facts never resurrect
// (time never decides), quarantine never auto-clears on rejoin, and
// non-terminal disagreements merge to unknown (no consensus, no
// invented winner). Every success carries authority: "none",
// consensusReached/globalOrdering/autoResumed/trustTransferred:
// false as structural literals. Pure knowledge: no socket, no
// listener, no spawn, no clock, no store, no Policy, no tool, no
// consensus protocol. TOPOLOGY IS KNOWLEDGE, NOT AUTHORITY.
export * from "./meshPartitionReconciliation.js";
// PHASE 27H — Mesh Observability: deterministic, redacted, read-only
// topology/runtime projection for later GETIG visualization work.
// VISUALIZATION != CONTROL PLANE: no mutation/action surface, structural
// authority "none" / controlPlane false / readOnly true, unknown stays
// unknown; freshness and provenance are projected as METADATA only.
export * from "./meshObservability.js";
// PHASE 28A — the GETIG representation contract (contract-first,
// renderer-neutral, read-only, zero authority). Closed readonly shapes for
// every visible object, and the ONE pure builder that assembles them into a
// bounded deterministic frame. VISIBILITY != AUTHORITY: every authority-shaped
// field is pinned to a structural zero, an unknown vocabulary value REFUSES,
// and the frame exposes no mutation, action or execution surface. No renderer,
// no graphics, no WebGPU — that belongs to Phase 29.
export * from "./getigRepresentation.js";
// PHASE 28B — the runtime entity projection: maps a FROZEN Phase-27
// observability snapshot into a 28A GETIG frame. Pure, read-only, and
// deterministic: collection order is canonicalized so shuffled upstream input
// yields byte-identical visible content, while route HOP order is semantic and
// preserved. Invents nothing — unknown stays unknown, stale stays stale,
// retired stays retired, and conflicts stay visible and unresolved.
export * from "./getigEntityProjection.js";
// PHASE 28C — temporal frames & runtime timeline: immutable frame SEQUENCES
// and deterministic, causal-free semantic DIFFS. VISUAL HISTORY ONLY. There is
// no clock here and no global distributed-time claim: a sequence states an
// explicit ordering basis, keeps positions exactly as supplied, and says
// temporalOrderEstablished:false when order could not be established. The three
// identities — sourceProjectionHash, canonicalVisibleHash and the sequence's
// own identity — are never collapsed. Historical navigation can only refuse:
// VISUAL_REPLAY != EXECUTABLE_REPLAY.
export * from "./getigTemporalFrames.js";
// PHASE 28D — evidence-to-visual semantic mapping: renderer-neutral SEMANTIC
// TOKENS and nothing else. No graphics backend, no colour, no hue — because
// colour that carries the meaning makes two renderers with different palettes
// disagree about what the system claims. The central law is structural rather
// than advisory: the strengthened value of every forbidden promotion simply
// does not exist in any vocabulary, and each token publishes only the
// presentation tiers at or BELOW its own claim rank. A coarsening gate refuses
// any drawing that would present a weak fact as a strong one, and refuses to
// collapse the axes whose job is to stay individually visible.
export * from "./getigVisualMapping.js";
// PHASE 28E — observer-relative world views: MULTI-VIEW / NO GLOBAL TRUTH
// SYNTHESIS. Observer, runtime and epoch context is MANDATORY. Several
// observers' accounts are held side by side and compared with every
// disagreement ATTRIBUTED, while the comparison structurally refuses to name a
// winner — a fresher account is not a truer one, and absence is an UNKNOWN
// difference rather than a manufactured disagreement. Terminal facts are
// carried through, never visually resurrected. OBSERVER_VIEW != GLOBAL_TRUTH;
// RECONCILIATION != CONSENSUS.
export * from "./getigObserverViews.js";
// PHASE 28F — provenance & explanation graph: every visible object can answer
// WHY AM I SEEING THIS. Bounded and cycle-safe, so a self-referential graph
// terminates with a bounded trace instead of hanging. A provenance reference is
// METADATA about an evidence record and never the record: there is no field in
// which evidence content could be placed, and a record carrying one is refused
// rather than quietly sanitised. Missing provenance becomes an EXPLICIT unknown,
// never fabricated. Route roles are carried explicitly, and a route listing its
// own origin as a forwarder is refused as role substitution. EXPLAINATION !=
// AUTHORIZATION; PROVENANCE METADATA != EVIDENCE CONTENT.
export * from "./getigProvenance.js";
// PHASE 28G — the read-only inspection runtime. Nine closed query kinds over
// frozen 28E views, 28C sequences and 28F graphs, and no mutating operation at
// all: the read-only property is structural, not a per-call-site check. A
// filtered answer is a distinct type carrying isFiltered/isComplete markers, so
// a partial world can never be passed off as a whole one. INSPECTION != CONTROL.
export * from "./getigInspectionRuntime.js";
// PHASE 28H — the visible-world disclosure boundary. An ALLOWLIST, not 28F's
// denylist: unknown fields default-deny, nested structure is refused outright,
// and a refusal discloses NOTHING (frame is always null) rather than returning
// a redacted skeleton that would look like a successful sanitisation.
export * from "./getigDisclosureGate.js";
// PHASE 28I — the adversarial visible runtime. A TABLE of attacks with a
// four-wide verdict taxonomy in which UNSUPPORTED and INCONCLUSIVE are their
// own outcomes and are never counted as PASS. criticalBypass is computed from
// whether an attack achieved its stated goal, never asserted.
export * from "./getigAdversarialHarness.js";
export * from "./getigAdversarialCatalog.js";
// PHASE 28J — the end-to-end scenario. ONE fixed, caller-uncontrollable witness
// that runs 27H → 28B → 28A → 28D/28E/28C/28F → 28G → 28H → 28I in order over
// real frozen upstream evidence. It exposes no entry point that accepts a frame,
// so the chain cannot be graded on evidence a caller chose, and a refusal at any
// stage publishes nothing at all.
export * from "./getigEndToEndScenario.js";
// PHASE 29A — the WebGPU renderer trust contract, written BEFORE any GPU call
// exists so the authority boundary constrains the renderer rather than
// describing it. Ten closed readonly contracts, every success surface carrying
// authority:"none"/controlPlane:false/readOnly:true/executionAuthorized:false,
// unknown vocabulary failing CLOSED, and NO WebGPU token anywhere in the file.
export * from "./rendererTrustContract.js";
// PHASE 29B — the GETIG scene graph compiler. CPU-side and deterministic: it
// turns a Phase-28 (28D) visual mapping into an authority-free scene graph and
// draws nothing. Layout is a pure function of the SORTED subject set, so input
// order cannot change the picture; sceneHash covers semantics and layoutHash
// covers coordinates, which makes LAYOUT_CHANGE != RUNTIME_CHANGE testable
// rather than aspirational. Phase-28 rank ceilings are IMPORTED, never
// reimplemented, so the compiler cannot drift from the ordering it must obey.
export * from "./sceneGraphCompiler.js";
// PHASE 29C — WebGPU device & capability qualification. This module makes NO
// WebGPU call: it defines the shape of a probe observation and the rules for
// judging one, because the rules are the part that must be unfalsifiable. There
// is no bare PASS in the taxonomy, a software adapter can never reach hardware
// qualification, a submitted render is not a rendered one, and a readback that
// merely completed without matching its content is INCONCLUSIVE, never a pass.
export * from "./webgpuQualification.js";
// PHASE 29D — the GPU resource & render-plan layer. It translates a 29B
// GetigScene into explicit, bounded GPU descriptors and ALLOCATES NOTHING:
// there is no create*, submit(, draw( or navigator anywhere in the file. Every
// byte count is checked by checkedMul before its descriptor exists, every
// buffer declares a contents class from a vocabulary that has no member
// permitting text, an id or a claim, and the plan can only ever say
// completeness "incomplete" because 29C found no verified pixel readback.
// Silence is the failure mode it rules out: there is no truncation knob.
export * from "./gpuRenderPlan.js";
// PHASE 29E — runtime graph rendering, as FRAME COMPOSITION. It draws nothing:
// `rendered: false`, `pixelOutputVerified: false`, `completeness: "incomplete"`
// are literal types, because 29C measured this machine's texture readback
// returning all zeros and a submission would prove nothing. The semantic
// integrity rules ARE the gate, and they are structural: mandatory
// conflict/refusal/partition markers can only land in a last, non-occluding
// layer with depthCompare "none" everywhere, a rank-0 token is drawn as
// presence_only rather than as its value, and no colour is assigned anywhere.
export * from "./renderFrameComposer.js";
// PHASE 29F — temporal rendering & animation, as TRANSITION PLANNING. It plans
// presentation only: four closed classes (historical, observed_transition,
// interpolated_presentation, unknown), a deterministic canonical-hash plan and
// explicit bounds that refuse rather than truncate. Interpolated steps carry
// NULL evidence (no frame id, no visible hash, no diff), so a synthesised
// in-between picture can never be quoted as an observation; an unknown
// ordering basis refuses interpolation outright, so an unestablished order is
// never smoothed into a chronology. Route anchors must be 29R1's repaired real
// chain (route root -> origin -> forwarder -> destination) or the plan is
// refused, no rank is ever strengthened, and the only two navigation-adjacent
// exports can only REFUSE: playback never resumes runtime and animation cannot
// mutate GETIG. ANIMATION != LIVE EXECUTION; VISUAL_REPLAY != EXECUTABLE_REPLAY.
export * from "./temporalTransitionPlanner.js";
// PHASE 29G — picking & read-only interaction: the CPU half of picking. An
// opaque index (or pickingId) resolves to a visible subject against ONE scene:
// a stale plan, a foreign id or a substituted subject claim all REFUSE with no
// partial identity leaked, and every row must re-derive from sceneHash before
// it is trusted. Each selection carries the subject's mandatory markers AND the
// scene-wide conflict/refusal/partition inventory, so picking one thing cannot
// hide the others, and any action- or marker-suppression-shaped input refuses
// before it is considered. The only reachable follow-on is Phase-28's own
// read-only inspection (28G select, query constructed here) and explanation
// (28F), surfaced verbatim; the third export can only refuse. PICKING !=
// EXECUTION; SELECTION != PERMISSION.
export * from "./pickingResolver.js";
// PHASE 29H — GPU resource safety & device-loss recovery: a fail-closed
// lifecycle state machine over CONTRACT values (no real allocation, no GPU
// call, no clock). Caps are imported from 29D, never re-declared; sizes pass
// checkedMul before a handle exists; device loss atomically invalidates every
// live handle; recreation is the only road back from lost and reads ONLY the
// already-authorized plan bound to the session; repeated loss/recovery is
// bounded and cleanup sits outside that budget. Old handle != authority:
// every handle carries literal zeros whether live, invalidated or released.
// GPU_RECOVERY != RUNTIME_RECOVERY: inputs carrying agent/task/runtime fields
// refuse by name, simulated contract evidence is distinguished from real
// device evidence in explicit fields (29C-OBS-1 cited), and the only
// navigation-adjacent export can only refuse.
export * from "./gpuResourceLifecycle.js";
export * from "./phase29AdversarialCatalogue.js";
// PHASE 22B — the local transactional store (SQLite via node:sqlite).
export {
  DurableStore,
  STORE_DIR_NAME,
  STORE_FILE_NAME,
  type StoreOpenResult,
  type StoreOpenFailureCode,
  type ReadResult,
  type ReadFailure,
  type ReadFailureCode,
  type QuarantineRowView,
  type StoreCheckpointView,
  type CheckpointVerifyResult,
} from "./store.js";
