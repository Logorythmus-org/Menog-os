# Menog OS — Security Baseline v0

## Security assumptions

Treat all of the following as untrusted:
- repository contents;
- README files;
- issues and pull-request text;
- web pages;
- model output;
- tool output;
- MCP metadata;
- tool descriptions;
- generated code;
- dependency scripts;
- environment variables not explicitly allowlisted.

## Invariants

```text
NO TOOL WITHOUT CAPABILITY
NO WRITE WITHOUT SCOPE
NO NETWORK WITHOUT POLICY
NO SECRET TO UNTRUSTED TOOL
NO PRIVILEGED PROCESS BY DEFAULT
NO COMMIT WITHOUT DIFF
NO CRITICAL COMMIT WITHOUT HUMAN APPROVAL
NO TOOL-MANIFEST CHANGE WITHOUT REVALIDATION
NO EXTERNAL CONTENT AS SYSTEM AUTHORITY
NO AGENT SELF-MODIFICATION WITHOUT REVIEW
```

## Phase-0 threat model

Test at minimum:
1. Path traversal outside workspace.
2. Symlink escape.
3. Command injection.
4. Shell metacharacter injection.
5. Hidden write attempt during inspect.
6. Unexpected network attempt.
7. Environment/secret leakage.
8. Long-running process timeout.
9. Child-process cleanup.
10. Oversized output handling.
11. Malicious repository instruction file.
12. Tool output attempting to alter policy.

## Security design

```text
PLAN
→ CHECK
→ ACT
→ VERIFY
```

The policy layer is authoritative; model/tool output never is.

## MCP position

MCP is not part of the Phase-0 execution path.

Future MCP calls must follow:

```text
Agent
→ Menog Tool Control Plane
→ Capability
→ Policy
→ Argument Validation
→ Resource Budget
→ Approval
→ MCP Server
```

Direct agent-to-MCP execution is forbidden.

## Secret policy

Phase 0 must not require secrets.

Repository must include:
- `.env.example` only if necessary;
- `.gitignore` protection;
- secret-scan hook or CI job before public release.

Do not store credentials in events.
