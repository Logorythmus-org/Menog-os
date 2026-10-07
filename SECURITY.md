# Security Policy — Menog OS

Classification: PUBLIC (SECURITY.md)
Generated: 2026-09-05 (PROMPT 11A §13)
Status: ACTIVE MINIMAL POLICY. No security contact channel is established yet
— see §Reporting, which states that plainly rather than advertising a
channel that does not work.

============================================================
Scope
============================================================

This SECURITY.md applies to the Menog OS open-core repository
and the `menog` CLI binary distributed from it. It covers:

  - packages/core, packages/shared, packages/verbs,
    packages/event-ledger, packages/policy, packages/runtime-linux,
    apps/cli, tests, documentation, CI/CD configuration,
    build toolchain, supply chain (pnpm-lock.yaml, npm deps).

It does NOT cover:
  - Downstream redistributions / forks (they must provide their
    own SECURITY.md).
  - Commercial/Private boundary modules (separate security
    disclosure policy, published with those modules).
  - Third-party dependencies (report to upstream maintainers;
    for supply-chain issues in the pnpm lockfile, report to
    Menog per below AND upstream).

============================================================
Severity Classifications (Disclosure)
============================================================

Per SECURITY_DISCLOSURE_POLICY.md these are the severity tiers.
The classification drives the SECURITY-EMBARGOED classification
and disclosure timeline.

  ┌──────────────────────────────────────────────────────────────┐
  │ Category            Definition                                │
  ├──────────────────────────────────────────────────────────────┤
  │ Normal bug          Not security-sensitive.                   │
  │                       Open a normal GitHub issue.             │
  ├──────────────────────────────────────────────────────────────┤
  │ Security            Security-sensitive non-critical bug       │
  │   Vulnerability       (e.g. crash on malformed input,        │
  │                       mis-typed event field, info leak with  │
  │                       low blast radius). Report via private   │
  │                       channel; 90-day standard disclosure.    │
  ├──────────────────────────────────────────────────────────────┤
  │ Sensitive Exploit   Policy bypass, capability escape,        │
  │                       secret-exfiltration, arbitrary exec    │
  │                       in deny-by-default runtime; any bug    │
  │                       that crosses a trust boundary.          │
  │                       SECURITY-EMBARGOED.                     │
  ├──────────────────────────────────────────────────────────────┤
  │ Zero-day-like        Actively exploited in the wild;          │
  │   Finding             weaponized PoC circulating;             │
  │                       widespread blast radius.                │
  │                       SECURITY-EMBARGOED; fast-track patch    │
  │                       and coordinated disclosure timeline.   │
  ├──────────────────────────────────────────────────────────────┤
  │ Agent Containment   Bypass of the deny-by-default policy     │
  │   Bypass              engine, AuthoritativeExecGate,         │
  │                       capability allowlist, workpace         │
  │                       sandbox (resolveWorkspaceSafely,       │
  │                       shell metachar filters).                │
  │                       SECURITY-EMBARGOED.                     │
  ├──────────────────────────────────────────────────────────────┤
  │ Policy Bypass       Any defect that causes policy_decision   │
  │                       event to be logged as "allow" when     │
  │                       the actual policy evaluation was DENY, │
  │                       or vice versa; ledger tampering.        │
  │                       SECURITY-EMBARGOED.                     │
  ├──────────────────────────────────────────────────────────────┤
  │ Secret Exposure     API keys, tokens, signing keys,          │
  │                       credentials, encrypted events plaintext │
  │                       leaked into logs, ledger, env dumps.    │
  │                       SECURITY-EMBARGOED.                     │
  ├──────────────────────────────────────────────────────────────┤
  │ Supply-chain        pnpm-lock.yaml compromise,                │
  │   Issue               malicious dep in transitive closure,    │
  │                       typosquat, install-script RCE,          │
  │                       provenance (SLSA) failure.              │
  │                       Evaluate severity; many are EMBARGOED.  │
  └──────────────────────────────────────────────────────────────┘

============================================================
Reporting
============================================================

For anything in Normal bug only:
  Open a GitHub issue on the canonical repository.

For ALL OTHER classifications (Security Vulnerability through
Supply-chain Issue):
  DO NOT file a public issue or PR. That would constitute
  premature public disclosure of SECURITY-EMBARGOED material,
  and violates IP_CLASSIFICATION_POLICY.md.

Report via ENCRYPTED, off-GitHub channel:

  Channel:                  NOT AVAILABLE.

    There is currently NO security contact address and NO OpenPGP key
    for this project. This file deliberately does not publish a
    placeholder address, a placeholder fingerprint, or a key-server
    pointer: a reporting channel that cannot receive a report is worse
    than an admitted gap, because it silently discards the disclosure
    and can create a false expectation of confidentiality.

    This gap is known and tracked. It closes when a human establishes a
    real mailbox plus a real OpenPGP key and records the fingerprint
    here. Until then, treat this section as UNAVAILABLE.

    What to do instead, while the channel is unavailable:
      Do NOT file a public issue or pull request for anything above
      §Normal bug — see the non-publication rule below. Hold the report
      privately and re-check this file; the channel is expected to be
      published before the first tagged release. If you believe the
      finding is already being exploited, say so explicitly when the
      channel opens so it can be fast-tracked.

  Please include:
    - Affected version / commit SHA.
    - Reproduction steps (as minimal as possible).
    - Expected vs. actual behavior.
    - Blast radius (local, network, multi-user).
    - Any PoC (code, script, payload).
    - Reporter contact details for coordination.

============================================================
Disclosure Timeline (DRAFT — standard coordinated disclosure)
============================================================

  Day 0      Reporter submits encrypted report.
  Day 1–7    Human security triage + classification. ACK sent.
  Day 7–30   Fix development in private branch.
  Day 30     Patch released; advisory published;
             SECURITY-EMBARGOED classification lifted → PUBLIC
             with published-advisory reference.

  Exceptions:
    - If the bug is already public or being actively
      exploited, the timeline is accelerated.
    - If the reporter requests and justifies a longer
      embargo, extend by negotiation.
    - If the reporter supplies a patch, credit them in the
      advisory.

============================================================
Bug Bounty
============================================================

  No bug bounty program is active as of 2026-09-05. Good-faith
  security research is encouraged and will be publicly
  credited in advisories when published. When a commercial
  bounty program exists, it will be linked here.

============================================================
Supported Versions
============================================================

  Pre-1.0: Only the latest tagged release + HEAD of main
  receive security patches. Backports are discretionary while
  the API is still unstable.

============================================================
Security-Research Safe Harbor
============================================================

Good-faith security research, including attempts to find and
report bugs in the deny-by-default runtime, policy engine,
ledger, capability system, and agent containment model, is
AUTHORIZED. The project will not initiate legal action
against good-faith researchers who:

  - Comply with this SECURITY.md disclosure process.
  - Do not access or exfiltrate third-party data.
  - Do not modify user data without consent.
  - Use their own isolated test workspaces, not production
    Menog deployments of third parties.

============================================================
Relationship to SECURITY_DISCLOSURE_POLICY.md
============================================================

This file is the end-user-facing short policy. The complete
IP/disclosure-classification workflow is documented in
docs/governance/SECURITY_DISCLOSURE_POLICY.md together with
the SECURITY-EMBARGOED disclosure class defined in
IP_CLASSIFICATION_POLICY.md.
