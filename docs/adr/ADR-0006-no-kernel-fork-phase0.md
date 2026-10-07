# ADR-0006 — No Kernel Fork / No Custom Distro in Phase 0 (Unprivileged Linux Runtime)

- Status: Proposed
- Date: 2026-09-05

## Context

Menog OS is "Linux-native" but the definition of that term must not grow
beyond what Phase 0 can responsibly deliver. Prompt-pack explicitly defers
namespaces, cgroups v2, seccomp, Landlock, and rootless containers. Kernel
forks, custom distro images, and init systems are outside Phase-0 scope.

The threat model still requires a narrow, observable, unprivileged local
execution primitive. The question for this ADR is: what **is** the Linux
runtime in Phase 0, and what is it explicitly **not**?

## Decision

### 1. What the Linux runtime IS in Phase 0

A typed, unprivileged, local **child-process launcher** with the following
features (see LINUX_RUNTIME_CONTRACT.md):

| Feature | Phase-0 requirement |
|---|---|
| Invocation style | executable + `argv` array (explicit; no shell by default) |
| Working directory | Restricted to the resolved workspace root; no `..` escape |
| Environment | Strict allowlist; start empty and add only required POSIX vars |
| Timeout | Per-invocation wall-clock cap; SIGTERM → SIGKILL escalation |
| Output cap | Per-stream byte cap; truncate + record truncation |
| Exit status | Captured (code, signal name where applicable) |
| Stdout / stderr | Captured as buffered strings (respecting cap); never echoed to tty silently |
| Process cleanup | Whole-process-tree cleanup on timeout/abort (best-effort via process group) |
| Event emission | command.requested, command.started, command.{finished,failed} |
| Shell interpolation | **Off by default.** Opt-in shell wrapper only if explicitly authorized by policy for a specific verb — and `inspect` may never opt in. |
| Network | Not executed by inspect. Where enforceable, `unshare`/`firejail` style hints are future work; for Phase 0 we rely on command allowlist and policy. |

### 2. What the Linux runtime IS explicitly NOT in Phase 0

```text
NO Linux kernel fork
NO custom distro image build
NO init system / PID-1 management
NO namespaces (UTS/PID/NET/MOUNT/USER/IPC)
NO cgroups v2 integration
NO seccomp-BPF filter
NO Landlock rules
NO rootless container runtime (bubblewrap, runc, crun, kata, ...)
NO Docker / containerd / podman runtime socket
NO Dockerfile / compose / OCI image build
NO GPU device policy (no CUDA / ROCm / Vulkan / WebGPU)
NO daemonization or background process management
NO systemd unit installation
NO kernel module loading
NO /proc or /sys mutation from the runtime side
NO /dev access beyond stdin/stdout/stderr + explicitly allowed files (Phase 0: none)
```

### 3. Initial command allowlist for `inspect`

Per LINUX_RUNTIME_CONTRACT.md. Prefer native libraries for filesystem
inspection; spawn `git` only where native libraries cannot match.

```text
git status --short --branch
git diff --no-ext-diff
git diff --cached --no-ext-diff
git ls-files
```

Denied by default (see LINUX_RUNTIME_CONTRACT.md):
`sudo`, `su`, package managers, arbitrary shell strings, writes outside
workspace, network tooling, daemonization, background processes, device
access, `/proc` mutation, `/sys` mutation, `/dev` access except runtime
necessities.

### 4. Privilege posture

- The Linux runtime must operate without any of: setuid, sudo, su, root,
  `CAP_SYS_ADMIN`, `CAP_NET_*`, mount capabilities.
- If the invoking user happens to be root (not recommended), the runtime
  refuses to execute and emits `security.violation` with reason
  `privileged_user_refused`.

## Alternatives considered

1. **Jump straight to Landlock + seccomp + user namespaces** — rejected as
   Phase-0 scope. These add platform-specific code paths, test burden, and
   portability risk for zero immediate Day-1 functionality.
2. **Adopt `bubblewrap` as a hard dependency** — rejected; introduces an
   external binary dependency that must be audited and shipped. Future
   option.
3. **Use the shell by default for convenience** — rejected; shell
   interpolation is one of the Phase-0 threat-model targets (3 and 4).

## Security impact

- Smaller surface → fewer ways to escape or escalate.
- No shell by default blocks a whole command-injection class.
- Process-tree cleanup + timeout bound resource leaks from runaway
  children.
- Refusing to run as root / refusing `sudo`-prefix commands prevents
  accidental whole-system corruption.
- Open gap: without namespaces/Landlock, a motivated attacker who finds
  command-injection could still access the rest of the invoking user's
  files. Mitigated in Phase 0 by (a) no shell, (b) argv-only + strict
  allowlist, (c) workspace boundary checks, (d) deny tests.

## Reversibility

- Hardening features (namespaces, seccomp, Landlock, bubblewrap, cgroups
  v2) may be added **incrementally** with their own ADRs; they are
  additive and do not regress the unprivileged baseline.
- A future kernel fork or custom distro build would be a major boundary
  change and requires a superseding ADR that explicitly supersedes this
  one.
- Adding Docker socket access requires a new ADR and explicit policy flag;
  it is blocked by default.

## Evidence

- Linux boundary: [docs/ARCHITECTURE_BASELINE.md → Linux boundary](docs/ARCHITECTURE_BASELINE.md#L89-L106)
- Runtime contract: [docs/LINUX_RUNTIME_CONTRACT.md](docs/LINUX_RUNTIME_CONTRACT.md)
- Inspect allowlist + deny list: [docs/LINUX_RUNTIME_CONTRACT.md → Denied by default / Initial allowlist](docs/LINUX_RUNTIME_CONTRACT.md#L20-L48)
- Threat model: [docs/SECURITY_BASELINE.md → Phase-0 threat model](docs/SECURITY_BASELINE.md#L33-L47)
- Phase-0 exclusions: [docs/PROJECT_BASELINE.md → Phase-0 scope (Excluded)](docs/PROJECT_BASELINE.md#L39-L53)
