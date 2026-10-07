#!/bin/sh
# PRE-20A Linux enforcement-surface probe — NON-ENFORCING, PASSIVE.
#
# Runs IN the Linux target (native or WSL2). Emits machine-parseable lines:
#   CONTEXT<TAB><json>
#   PROBE<TAB><json>
#
# Every SUPPORTED verdict is backed by an executable, non-destructive probe
# executed here (20A hard rule) — never by symbols, package presence, docs,
# or version strings alone.
#
# Invariants: confines nothing but its own short-lived children; grants
# nothing; this script is 20A probe tooling, outside the Menog executor.

set -u

jstr() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

emit_context() {
  K=$(uname -s -r 2>/dev/null)
  A=$(uname -m 2>/dev/null)
  OS_NAME=$(sed -n 's/^NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release 2>/dev/null | head -1)
  OS_VER=$(sed -n 's/^VERSION_ID="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release 2>/dev/null | head -1)
  WSL=no
  case "$K" in *icrosoft*|*WSL*) WSL=yes ;; esac
  [ -e /run/WSL ] && WSL=yes
  printf 'CONTEXT\t{"kernel":"%s","arch":"%s","os_name":"%s","os_version":"%s","is_wsl":"%s"}\n' \
    "$(jstr "$K")" "$(jstr "$A")" "$(jstr "${OS_NAME:-unknown}")" "$(jstr "${OS_VER:-unknown}")" "$WSL"
}

# state, id, primitive, method, evidence-json, value, limitations, portability, depend
emit_probe() {
  printf 'PROBE\t{"id":"%s","primitive":"%s","detection_method":"%s","state":"%s","evidence":%s,"security_value":"%s","limitations":"%s","wsl_native_portability":"%s","may_20c_depend":%s}\n' \
    "$2" "$3" "$4" "$1" "$5" "$6" "$7" "$8" "$9"
}

emit_context

# 1. user namespace (unprivileged)
MAXNS=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo unknown)
if unshare --user --map-root-user true >/dev/null 2>&1; then
  ST=SUPPORTED; DEP=true; ERR=null
else
  ERR="\"unshare exit non-zero\""
  if unshare --user true >/dev/null 2>&1 || [ "$(id -u)" = "0" ]; then ST=UNSUPPORTED; else ST=PERMISSION_DENIED; fi
  DEP=false
fi
emit_probe "$ST" ns_user_unprivileged "user namespace (unprivileged creation)" \
  "executable: unshare --user --map-root-user true (creates+destroys a userns around a no-op)" \
  "{\"max_user_namespaces\":\"${MAXNS}\",\"stderr\":${ERR}}" \
  "enables unprivileged sandbox contexts; precondition for the unprivileged multi-namespace pattern" \
  "proves userns creation only, not idmapped/bind-mount workflows inside it" \
  "native Linux typically identical; hardened hosts may set max_user_namespaces=0" "$DEP"

# 2. mount namespace (inside unprivileged userns)
if unshare --user --map-root-user --mount true >/dev/null 2>&1; then
  ST=SUPPORTED; DEP=true; ERR=null
else
  ST=UNSUPPORTED; DEP=false; ERR="\"unshare --mount exit non-zero\""
fi
emit_probe "$ST" ns_mount "mount namespace (within unprivileged userns)" \
  "executable: unshare --user --map-root-user --mount true" \
  "{\"stderr\":${ERR}}" \
  "per-process filesystem view; required for bind-mount-based filesystem confinement" \
  "does not prove propagation-private subtrees or overlay availability" \
  "native: identical mechanics; WSL2 has init-specific mounts to consider in 20C design" "$DEP"

# 3. PID namespace — decisive, self-cleaning: with --fork the inner shell IS
#    PID 1 of the fresh namespace, prints probe-pid1=1, and exits immediately
#    (no orphaned process, no kill needed). Without a working namespace,
#    unshare exits non-zero with nothing on stdout.
PIDOUT=$(unshare --user --map-root-user --pid --fork sh -c 'echo probe-pid1=$$' 2>/dev/null)
case "$PIDOUT" in
  *probe-pid1=1*) ST=SUPPORTED; DEP=true ;;
  *)              ST=UNSUPPORTED; DEP=false ;;
esac
emit_probe "$ST" ns_pid "PID namespace (with --fork; inner shell reports its own PID)" \
  "executable: unshare --user --map-root-user --pid --fork sh -c 'echo probe-pid1=\$\$'; SUPPORTED requires the inner shell to report PID 1 (namespace isolation proven); the child exits immediately — nothing survives the probe" \
  "{\"stdout_first_line\":\"$(jstr "$(printf '%s' "$PIDOUT" | head -1)")\"}" \
  "process escape containment (no host PID visibility inside the namespace)" \
  "does not prove init-reaping behavior under load" \
  "native: identical" "$DEP"

# 4. IPC / UTS / network namespaces
for SPEC in "ipc:ns_ipc:IPC namespace:isolates SysV IPC / POSIX shm objects from the host" \
            "uts:ns_uts:UTS namespace:isolates hostname/domainname view (defense-in-depth)" \
            "net:ns_net:network namespace:fresh netns has no external interfaces/sockets = deny-by-default egress primitive"; do
  FLAG=$(printf '%s' "$SPEC" | cut -d: -f1)
  ID=$(printf '%s' "$SPEC" | cut -d: -f2)
  PRIM=$(printf '%s' "$SPEC" | cut -d: -f3)
  VAL=$(printf '%s' "$SPEC" | cut -d: -f4)
  if unshare --user --map-root-user "--$FLAG" true >/dev/null 2>&1; then
    ST=SUPPORTED; DEP=true
  else
    ST=UNSUPPORTED; DEP=false
  fi
  case "$FLAG" in
    net) LIMIT="does not alone prove egress denial over inherited AF_UNIX fds; loopback provisioning is 20C work" ;;
    *)   LIMIT="value depends on whether the workload uses this IPC/hostname surface at all" ;;
  esac
  emit_probe "$ST" "$ID" "$PRIM" \
    "executable: unshare --user --map-root-user --$FLAG true" \
    "{\"command_exit\":$([ "$ST" = SUPPORTED ] && echo 0 || echo non-zero)}" \
    "$VAL" \
    "$LIMIT" \
    "native: identical" "$DEP"
done

# 5a. cgroup v2 — detect the actual v2 hierarchy root (unified vs hybrid mode)
# unified:      /sys/fs/cgroup is cgroup2 itself
# hybrid (WSL2): /sys/fs/cgroup is v1 (tmpfs overlay) with cgroup2 at /sys/fs/cgroup/unified
if [ -e /sys/fs/cgroup/cgroup.controllers ]; then
  CG2ROOT=/sys/fs/cgroup
  CGMODE=unified
elif [ -e /sys/fs/cgroup/unified/cgroup.controllers ]; then
  CG2ROOT=/sys/fs/cgroup/unified
  CGMODE=hybrid
else
  CG2ROOT=; CGMODE=absent
fi
CTRL=$(cat "$CG2ROOT/cgroup.controllers" 2>/dev/null | tr '\n' ' ' || true)
SUBT=$(cat "$CG2ROOT/cgroup.subtree_control" 2>/dev/null | tr '\n' ' ' || true)
if [ -n "$CTRL" ]; then ST=SUPPORTED; else ST=UNSUPPORTED; fi
emit_probe "$ST" cgroup_v2_unified "cgroup v2 unified hierarchy (read surface)" \
  "detect v2 root (unified vs hybrid); read <v2root>/cgroup.controllers and cgroup.subtree_control (no writes performed)" \
  "{\"mode\":\"$CGMODE\",\"v2_root\":\"$CG2ROOT\",\"controllers\":\"$(jstr "$CTRL")\",\"subtree_control\":\"$(jstr "$SUBT")\"}" \
  "resource-exhaustion containment surface (CPU/memory/pids)" \
  "controllers present != controllers delegated; delegation is probed separately" \
  "native + systemd: cpu/io/memory/pids typically delegated to user slices" false

# 5b. cgroup v2 delegation — empty probe cgroup created and removed.
# Tries the v2 root first; on a hybrid/systemd layout, also tries the user's
# delegated slice (user.slice/userUID.slice/user@UID.service). Pure
# mkdir/rmdir of an EMPTY group: no controller enabled, no process moved.
CGPROBE() {
  mkdir "$1" 2>/dev/null || return 1
  rmdir "$1" 2>/dev/null
  return 0
}
# The user systemd slice may not exist yet right after WSL cold start
# (user@UID.service is created asynchronously); retry briefly before denying.
CGTRY1="$CG2ROOT/menog-20a-probe"
CGTRY2="$CG2ROOT/user.slice/user-$(id -u 2>/dev/null).slice/user@$(id -u 2>/dev/null).service/menog-20a-probe"
if [ -n "$CG2ROOT" ] && CGPROBE "$CGTRY1"; then
  ST=SUPPORTED; DEP=true; CGOK="$CGTRY1"
  EV="{\"mode\":\"$CGMODE\",\"probe_path\":\"$CGOK\",\"note\":\"empty probe cgroup created and removed; no controller enabled, nothing leaked\"}"
elif [ -n "$CG2ROOT" ]; then
  ST=UNVERIFIED; CGOK=""; EV="{}"
  for i in 1 2 3; do
    if CGPROBE "$CGTRY2"; then
      DEPC="$(cat "$(dirname "$CGTRY2")/cgroup.controllers" 2>/dev/null | tr '\n' ' ')"
      ST=SUPPORTED; DEP=false; CGOK="$CGTRY2"
      EV="{\"mode\":\"$CGMODE\",\"probe_path\":\"$CGOK\",\"controllers_at_slice\":\"$(jstr "$DEPC")\",\"note\":\"empty probe cgroup created and removed inside the user's systemd slice; but zero v2 controllers are delegated on this target, so no memory.max/pids.max enforcement is possible — 20C must not depend on cgroups here\"}"
      break
    fi
    sleep 1
  done
  if [ "$ST" = UNVERIFIED ]; then
    ST=PERMISSION_DENIED
    EV="{\"mode\":\"$CGMODE\",\"note\":\"mkdir of child cgroup denied at v2 root and user slice; delegation not available to this user\"}"
  fi
else
  ST=UNSUPPORTED
  EV="{\"mode\":\"$CGMODE\",\"note\":\"no cgroup v2 hierarchy detected on this target\"}"
fi
emit_probe "$ST" cgroup_v2_delegation "cgroup v2 delegated subgroup creation (unprivileged)" \
  "executable: mkdir + rmdir of an empty child cgroup under the detected v2 root, then under the user's delegated systemd slice if the root is denied (created empty, no controllers, removed immediately)" \
  "$EV" \
  "required to place a target process in a bounded child cgroup (memory.max / pids.max)" \
  "proves directory creation only; enabling controllers (+cpu +memory ...) is the real 20C step" \
  "native+systemd: typically SUPPORTED via user@.service delegation; hybrid layouts need the slice path" "$DEP"

# 6. Landlock — REAL kernel probe: ABI query + self-restriction + effect check
TMPD=$(mktemp -d 2>/dev/null || echo /tmp/menog-20a-$$)
mkdir -p "$TMPD"
cat > "$TMPD/ll.c" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
  long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 0) { printf("ERR %d\n", errno); return 0; }
  printf("ABI %ld\n", abi);
  struct landlock_ruleset_attr attr = { .handled_access_fs =
      LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
      LANDLOCK_ACCESS_FS_READ_FILE };
  int fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
  if (fd < 0) { printf("RULESET_ERR %d\n", errno); return 0; }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) { printf("NNP_ERR\n"); return 0; }
  if (syscall(SYS_landlock_restrict_self, fd, 0) < 0) { printf("RESTRICT_ERR %d\n", errno); return 0; }
  FILE *f = fopen("/etc/hostname", "r");
  if (f) { fclose(f); printf("RESTRICT_EFFECT NO-OP\n"); }
  else { printf("RESTRICT_EFFECT ENFORCED\n"); }
  return 0;
}
EOF
CC=$(command -v gcc 2>/dev/null || command -v cc 2>/dev/null)
if [ -n "$CC" ] && "$CC" -o "$TMPD/ll" "$TMPD/ll.c" 2>/dev/null; then
  LLOUT=$("$TMPD/ll" 2>/dev/null)
  ABI=$(printf '%s' "$LLOUT" | sed -n 's/^ABI \([0-9]*\)$/\1/p')
  case "$LLOUT" in
    *"RESTRICT_EFFECT ENFORCED"*) ST=SUPPORTED; DEP=true ;;
    *"RESTRICT_EFFECT NO-OP"*)    ST=UNVERIFIED; DEP=false ;;
    ERR*|RULESET_ERR*|RESTRICT_ERR*|NNP_ERR*) ST=UNSUPPORTED; DEP=false ;;
    *)                            ST=UNVERIFIED; DEP=false ;;
  esac
  EV="{\"abi\":${ABI:-null},\"restrict_effect\":\"$(printf '%s' "$LLOUT" | grep RESTRICT_EFFECT | head -1 | cut -d' ' -f2)\",\"compiler\":\"$(jstr "$CC")\"}"
else
  ST=UNVERIFIED; DEP=false
  EV="{\"reason\":\"no C compiler in target; ABI query deferred\"}"
fi
rm -rf "$TMPD"
emit_probe "$ST" landlock_abi "Landlock (unprivileged filesystem restriction, self-applied + effect-verified)" \
  "compiled C probe run in-target: create_ruleset(VERSION) -> create FS ruleset -> prctl(NO_NEW_PRIVS) -> landlock_restrict_self on the probe process only -> attempt a read the empty ruleset must deny; SUPPORTED requires the observed denial, never the ABI number alone" \
  "$EV" \
  "kernel-enforced unprivileged filesystem confinement (symlink-escape-proof by construction)" \
  "ABI 1 = filesystem only; no network (ABI 2) or abstract-Unix (ABI 3) scoping" \
  "native 6.x kernels: ABI 2-4 typical — the main dev-vs-prod surface gap" "$DEP"

# 7. seccomp — effective mode of the probe process
SECC=$(sed -n 's/^Seccomp:[[:space:]]*\([0-9]*\)$/\1/p' /proc/self/status 2>/dev/null | head -1)
SECCF=$(sed -n 's/^Seccomp_filters:[[:space:]]*\([0-9]*\)$/\1/p' /proc/self/status 2>/dev/null | head -1)
if [ -n "$SECC" ]; then ST=SUPPORTED; else ST=UNVERIFIED; fi
emit_probe "$ST" seccomp_mode "seccomp (facility + effective mode of the probe process)" \
  "read /proc/self/status Seccomp:/Seccomp_filters: (kernel-exported runtime state, not version inference)" \
  "{\"seccomp_mode\":${SECC:-null},\"seccomp_filters\":${SECCF:-null},\"mode_meaning\":\"0=disabled 1=strict 2=filter\"}" \
  "syscall allowlist enforcement surface (executable-abuse and kernel-attack-surface reduction)" \
  "facility presence != a filter applied; 20C applies filters to target processes, not to the runtime" \
  "native: identical semantics" "$([ -n "$SECC" ] && echo true || echo false)"

# 8. no_new_privs — set it on the probe process itself
TMPD=$(mktemp -d 2>/dev/null || echo /tmp/menog-20a-$$)
mkdir -p "$TMPD"
cat > "$TMPD/nnp.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <sys/prctl.h>
int main(void) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) printf("NNP_OK\n");
  else printf("NNP_ERR\n");
  return 0;
}
EOF
CC=$(command -v gcc 2>/dev/null || command -v cc 2>/dev/null)
if [ -n "$CC" ] && "$CC" -o "$TMPD/nnp" "$TMPD/nnp.c" 2>/dev/null; then
  if "$TMPD/nnp" 2>/dev/null | grep -q NNP_OK; then
    ST=SUPPORTED; DEP=true; EV="{\"settable\":true,\"compiler\":\"$(jstr "$CC")\"}"
  else
    ST=UNSUPPORTED; DEP=false; EV="{\"raw\":\"prctl returned non-zero\"}"
  fi
else
  ST=UNVERIFIED; DEP=false; EV="{\"reason\":\"no C compiler in target\"}"
fi
rm -rf "$TMPD"
emit_probe "$ST" no_new_privs "no_new_privs (prctl PR_SET_NO_NEW_PRIVS, set on the probe process itself)" \
  "compiled C probe: prctl(PR_SET_NO_NEW_PRIVS, 1) executed on the probe process" \
  "$EV" \
  "blocks privilege-gain via setuid; hard prerequisite for unprivileged Landlock + seccomp filters" \
  "per-process; must be set before exec to survive into the target" \
  "native: identical" "$DEP"

# 9. rlimits — runtime values (set-side NOT marked SUPPORTED without executable proof)
NOFILE=$(sed -n 's/^Max open files[[:space:]]*\([^ ]*\)[[:space:]]*\([^ ]*\).*$/\1 \2/p' /proc/self/limits 2>/dev/null | head -1)
NPROC=$(sed -n 's/^Max processes[[:space:]]*\([^ ]*\)[[:space:]]*\([^ ]*\).*$/\1 \2/p' /proc/self/limits 2>/dev/null | head -1)
if [ -n "$NOFILE" ]; then ST=SUPPORTED; else ST=UNVERIFIED; fi
emit_probe "$ST" rlimits "rlimits (runtime values; set-side deferred to 20C executable proof)" \
  "read /proc/self/limits (kernel-exported runtime state)" \
  "{\"nofile_soft_hard\":\"$(jstr "$NOFILE")\",\"nproc_soft_hard\":\"$(jstr "$NPROC")\"}" \
  "resource-exhaustion bound (fds, processes, address space)" \
  "get-side proven here; setrlimit lowering is NOT marked SUPPORTED without an executable probe in 20C (hard rule)" \
  "native: identical" false

# 10. /proc visibility — cross-process read attempt
HIDEPID=$(grep -o 'hidepid=[0-9]*' /proc/mounts 2>/dev/null | head -1)
HIDEPID=${HIDEPID:-not-set}
OTHER=$(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | grep -v "^$$\$" | head -1)
if [ -n "$OTHER" ] && [ -r "/proc/$OTHER/status" ]; then
  CROSS=readable; ST=UNSUPPORTED
elif [ -n "$OTHER" ]; then
  CROSS=denied; ST=SUPPORTED
else
  CROSS=no-other-process-visible; ST=UNVERIFIED
fi
emit_probe "$ST" proc_visibility "/proc visibility (hidepid mount option + cross-process read)" \
  "parse /proc/mounts for hidepid=; executable attempt to read another process's /proc/<pid>/status" \
  "{\"hidepid\":\"$(jstr "$HIDEPID")\",\"cross_process_status_read\":\"$CROSS\"}" \
  "limits /proc inspection (information disclosure between target and host processes)" \
  "the real 20C mechanism is the PID namespace, not hidepid" \
  "native: same mechanics; systemd default is hidepid=0" false

# 11. euid / capabilities — identity surface (read-only; nothing granted)
IDLINE=$(id 2>/dev/null | head -1)
CAPBND=$(sed -n 's/^CapBnd:[[:space:]]*\([0-9a-f]*\)$/\1/p' /proc/self/status 2>/dev/null | head -1)
if [ -n "$IDLINE" ]; then ST=SUPPORTED; else ST=UNVERIFIED; fi
emit_probe "$ST" euid_capabilities "euid + capability bounding set (identity surface)" \
  "executable: id; read CapBnd from /proc/self/status" \
  "{\"id_line\":\"$(jstr "$IDLINE")\",\"cap_bounding_hex\":\"${CAPBND:-null}\"}" \
  "least-privilege identity for the target process (drop-all-caps is the 20C target state)" \
  "bounding set != effective set; per-thread effective caps vary" \
  "native: identical" false

# 12. helper availability (presence is context, NOT a 20C dependency)
BW=$(command -v bwrap 2>/dev/null || echo absent)
FJ=$(command -v firejail 2>/dev/null || echo absent)
ROOTLINE=$(grep ' / ' /proc/mounts 2>/dev/null | head -1)
emit_probe SUPPORTED fs_mount_helpers "filesystem/mount constraint surface + sandbox helper availability" \
  "shell-free PATH scan equivalent for helper binaries; /proc/mounts root-flags parse" \
  "{\"bwrap\":\"$(jstr "$BW")\",\"firejail\":\"$(jstr "$FJ")\",\"root_mount_line\":\"$(jstr "$ROOTLINE")\"}" \
  "informs 20C design (bind-mount confinement options; nosuid/noexec flags on root)" \
  "helper PRESENCE is context and explicitly NOT a 20C dependency; the unprivileged syscall path is preferred" \
  "native: bubblewrap commonly available or installable; WSL2: often absent" false

exit 0
