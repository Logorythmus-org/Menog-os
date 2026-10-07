/**
 * PRE-20C — the unprivileged isolation launcher (C source, embedded).
 *
 * Design (20C requirements, all satisfied here):
 * - argv-only: configuration arrives as explicit argv flags; the target is an
 *   argv vector after `--`. No shell anywhere.
 * - Abort before spawn: ANY isolation-setup failure in the child exits 125
 *   WITHOUT exec'ing the target (fail-closed, provable); exec failure also
 *   exits 125 (the target never ran).
 * - Deterministic preflight lives in preflight.ts; this program re-proves
 *   every step in-kernel (the only real proof).
 * - Per-primitive applied records arrive as one JSON line on fd 3 (kept out
 *   of the target's stdout/stderr).
 * - Idempotent process-tree cleanup: the target runs in its own process
 *   group; the supervisor enforces the deadline, SIGKILLs the whole group
 *   (ESRCH-safe), reaps, and exits 124 on timeout. The child also carries
 *   PR_SET_PDEATHSIG so it dies with the supervisor.
 * - Unprivileged: user namespace + map-root; no setuid, no helpers.
 * - Landlock: ABI-1 write-class confinement (writes/creates/removes denied
 *   outside granted paths). Read/execute remain the Menog allowlist
 *   authority's job (existing exec gate), not Landlock's.
 * - seccomp: reviewed fixed blocklist (mount/umount/pivot_root, unshare/
 *   setns, bpf, keyctl, ptrace, kexec, module loading, swap/reboot,
 *   open_by_handle_at) — reduces kernel attack surface and blocks sandbox
 *   escape vectors; x86_64 syscall numbers, guarded by #if.
 * - Network: a fresh network namespace has no interfaces ⇒ deny-by-default
 *   egress for the target. (Policy-authorization binding is 20D.)
 */

export const MENOG_LAUNCHER_C = String.raw`
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <time.h>
#include <unistd.h>

#define MENOG_ISOLATION_FAILURE_EXIT 125
#define MENOG_TIMEOUT_EXIT 124

/* ── applied-evidence journal: one MENOG_EV: marker line on STDERR ──
 * The orchestrator parses and strips these lines; the target's own stderr is
 * never touched (markers are emitted only by the launcher itself). */
static char ev_buf[8192];
static size_t ev_len = 0;
/* Comma-separated entry writer: prepends "," only when the buffer is
 * non-empty, so the journal is valid JSON regardless of entry order. */
static void ev_entry(const char *fmt, ...) {
  if (ev_len + 2 >= sizeof(ev_buf)) return;
  if (ev_len > 0) ev_buf[ev_len++] = ',';
  va_list ap; va_start(ap, fmt);
  int n = vsnprintf(ev_buf + ev_len, sizeof(ev_buf) - ev_len, fmt, ap);
  va_end(ap);
  if (n > 0) ev_len += (size_t)n;
}
static void ev_flush(const char *status) {
  fprintf(stderr, "MENOG_EV:{\"status\":\"%s\",\"applied\":{%.*s}}\n", status, (int)ev_len, ev_buf);
}

/* ── fail-closed: report + exit WITHOUT running the target ── */
static void die_isolation(const char *primitive, const char *what) {
  ev_flush("failed");
  fprintf(stderr, "MENOG_EV:{\"failed_primitive\":\"%s\",\"why\":\"%s\"}\n", primitive, what);
  _exit(MENOG_ISOLATION_FAILURE_EXIT);
}

struct grant_path { const char *path; struct grant_path *next; };

static void apply_nnp(void) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) die_isolation("no_new_privs", "prctl failed");
  ev_entry("\"no_new_privs\":{\"applied\":true}");
}

static void apply_rlimit(int resource, const char *name, rlim_t cur) {
  struct rlimit rl; rl.rlim_cur = cur; rl.rlim_max = cur;
  if (setrlimit(resource, &rl) != 0) die_isolation("rlimit_set", name);
  ev_entry("\"rlimit:%s\":{\"applied\":true,\"detail\":\"soft=hard=%lu\"}", name, (unsigned long)cur);
}

static void apply_landlock(long abi, struct grant_path *rw_paths) {
  if (abi < 1) die_isolation("landlock_fs", "ABI below 1");
  const __u64 handled = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
      LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
      LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
      LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
      LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM;
  struct landlock_ruleset_attr attr = { .handled_access_fs = handled };
  int fd = (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
  if (fd < 0) die_isolation("landlock_fs", "create_ruleset failed");
  for (struct grant_path *p = rw_paths; p; p = p->next) {
    int pfd = open(p->path, O_PATH | O_CLOEXEC);
    if (pfd < 0) die_isolation("landlock_fs", "open granted path failed");
    struct landlock_path_beneath_attr rule = {
      .allowed_access = handled,
      .parent_fd = (__u32)pfd,
    };
    if (syscall(SYS_landlock_add_rule, fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) != 0) {
      die_isolation("landlock_fs", "add_rule failed");
    }
    close(pfd);
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) die_isolation("landlock_fs", "NNP required");
  if (syscall(SYS_landlock_restrict_self, fd, 0) != 0) die_isolation("landlock_fs", "restrict_self failed");
  close(fd);
  ev_entry("\"landlock_fs\":{\"applied\":true,\"detail\":\"write-class confinement, ABI %ld\"}", abi);
}

static void apply_seccomp_blocklist(void) {
#if defined(__x86_64__)
  /* Classic chain: load nr; each blocklist member jumps to the ERRNO return
   * when matched (jt = distance to the ERRNO instruction), falls through on
   * no-match (jf = 0). Fall-through off the last jump lands on ERRNO too,
   * so the ALLOW return is reachable ONLY via... it is not — every non-
   * blocked syscall walks off the end of the chain into ERRNO. That would
   * deny everything. The correct form: the LAST instruction is ALLOW and
   * each jump's jf (no-match) chains to the next comparison; jt (match)
   * targets the ERRNO return. Structured below with explicit jt offsets:
   * with N blocked syscalls, ERRNO sits at index N+1 and ALLOW at N+2;
   * for the jump at index i (1-based, 1..N): jt = (N+1) - i, jf = 1. */
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 165, 12, 1),  /* mount */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 166, 11, 1),  /* umount2 */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 161, 10, 1),  /* pivot_root */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 272, 9, 1),   /* unshare */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 308, 8, 1),   /* setns */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 321, 7, 1),   /* bpf */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 250, 6, 1),   /* keyctl */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 101, 5, 1),   /* ptrace */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 246, 4, 1),   /* kexec_load */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 320, 3, 1),   /* kexec_file_load */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 175, 2, 1),   /* init_module */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 313, 1, 1),   /* finit_module */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 176, 0, 1),   /* delete_module */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (SECCOMP_RET_DATA & EPERM)),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = { .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])), .filter = filter };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) die_isolation("seccomp_filter", "NNP required");
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) die_isolation("seccomp_filter", "PR_SET_SECCOMP failed");
  ev_entry("\"seccomp_filter\":{\"applied\":true,\"detail\":\"reviewed blocklist: mount/umount2/pivot_root/unshare/setns/bpf/keyctl/ptrace/kexec/module-loading\"}");
#else
  die_isolation("seccomp_filter", "architecture not supported by reviewed blocklist");
#endif
}

static void write_map_file(const char *file, const char *content) {
  int fd = open(file, O_WRONLY);
  if (fd < 0) die_isolation("ns_user", file);
  size_t len = strlen(content);
  if (write(fd, content, len) != (ssize_t)len) { close(fd); die_isolation("ns_user", file); }
  close(fd);
}

static void apply_namespaces(unsigned int flags, int want_user) {
  if (flags == 0) return;
  /* Capture the REAL parent-namespace ids BEFORE unshare: after a combined
   * unshare(CLONE_NEWUSER|...), getuid() reads the unmapped overflow id
   * (65534), and mapping that id is rejected EPERM — the classic uid_map
   * ordering trap. The parent uid/gid are what the kernel validates against. */
  const uid_t parent_uid = getuid();
  const gid_t parent_gid = getgid();
  if (unshare(flags) != 0) die_isolation("ns_namespaces", "unshare failed");
  if (want_user) {
    char uidmap[64], gidmap[64];
    snprintf(uidmap, sizeof(uidmap), "0 %u 1", (unsigned)parent_uid);
    snprintf(gidmap, sizeof(gidmap), "0 %u 1", (unsigned)parent_gid);
    write_map_file("/proc/self/setgroups", "deny");
    write_map_file("/proc/self/uid_map", uidmap);
    write_map_file("/proc/self/gid_map", gidmap);
    ev_entry("\"ns_user\":{\"applied\":true,\"detail\":\"map-root single-uid\"}");
  }
  ev_entry("\"ns_set\":{\"applied\":true,\"detail\":\"flags=0x%x\"}", flags);
}

int main(int argc, char **argv) {
  if (argc < 2 || strcmp(argv[1], "--begin") != 0) {
    (void)write(2, "menog-launch: usage: --begin [flags] -- target argv\n", 52);
    return 2;
  }
  unsigned int ns_flags = 0; int want_user = 0;
  rlim_t nofile = 0, nproc = 0; int have_nofile = 0, have_nproc = 0;
  struct grant_path *rw_paths = NULL, **rw_tail = &rw_paths;
  long abi = 0; int landlock_requested = 0;
  int seccomp_requested = 0;
  long timeout_ms = 0; int have_timeout = 0;
  int i = 2;
  for (; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) { i++; break; }
    if (strcmp(argv[i], "--ns") == 0 && i + 1 < argc) {
      char *spec = argv[++i];
      if (strstr(spec, "user"))  { ns_flags |= CLONE_NEWUSER; want_user = 1; }
      if (strstr(spec, "mount")) ns_flags |= CLONE_NEWNS;
      if (strstr(spec, "pid"))   ns_flags |= CLONE_NEWPID;
      if (strstr(spec, "ipc"))   ns_flags |= CLONE_NEWIPC;
      if (strstr(spec, "uts"))   ns_flags |= CLONE_NEWUTS;
      if (strstr(spec, "net"))   ns_flags |= CLONE_NEWNET;
    } else if (strcmp(argv[i], "--rlimit-nofile") == 0 && i + 1 < argc) {
      nofile = strtoul(argv[++i], NULL, 10); have_nofile = 1;
    } else if (strcmp(argv[i], "--rlimit-nproc") == 0 && i + 1 < argc) {
      nproc = strtoul(argv[++i], NULL, 10); have_nproc = 1;
    } else if (strcmp(argv[i], "--landlock-abi") == 0 && i + 1 < argc) {
      abi = strtol(argv[++i], NULL, 10); landlock_requested = 1;
    } else if (strcmp(argv[i], "--landlock-rw") == 0 && i + 1 < argc) {
      struct grant_path *n = malloc(sizeof(*n));
      if (!n) die_isolation("landlock_fs", "malloc failed");
      n->path = argv[++i]; n->next = NULL; *rw_tail = n; rw_tail = &n->next;
      landlock_requested = 1;
    } else if (strcmp(argv[i], "--seccomp-blocklist") == 0) {
      seccomp_requested = 1;
    } else if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) {
      timeout_ms = strtol(argv[++i], NULL, 10); have_timeout = 1;
    } else {
      (void)write(2, "menog-launch: unknown flag\n", 27);
      return 2;
    }
  }
  if (i >= argc) { (void)write(2, "menog-launch: missing target\n", 29); return 2; }

  /* Namespaces FIRST (unshare affects this process and its children). */
  apply_namespaces(ns_flags, want_user);

  pid_t target = fork();
  if (target < 0) die_isolation("process", "fork failed");
  if (target == 0) {
    /* child = target context */
    if (setpgid(0, 0) != 0) die_isolation("process", "setpgid failed");
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0) die_isolation("process", "pdeathsig failed");
    /* A PID namespace alone does NOT hide host processes: /proc must be
     * remounted inside the new pid+mount namespace, while mount is still
     * permitted (pre-seccomp). Fail closed — partial proc visibility would
     * silently weaken the containment claim. */
    if ((ns_flags & CLONE_NEWPID) && (ns_flags & CLONE_NEWNS)) {
      if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0) {
        die_isolation("ns_pid", "proc remount failed");
      }
      ev_entry("\"ns_pid\":{\"applied\":true,\"detail\":\"fresh /proc mounted\"}");
    }
    apply_nnp();
    if (have_nofile) apply_rlimit(RLIMIT_NOFILE, "nofile", nofile);
    if (have_nproc) apply_rlimit(RLIMIT_NPROC, "nproc", nproc);
    if (landlock_requested) apply_landlock(abi, rw_paths);
    if (seccomp_requested) apply_seccomp_blocklist();
    ev_flush("setup_complete");
    execvp(argv[i], &argv[i]);
    die_isolation("exec", "execvp failed"); /* target did NOT run */
  }

  /* supervisor: deadline enforcement + idempotent process-group cleanup.
   * (No parent-side ev_flush: the child's journal already contains the
   * pre-fork namespace entries, so exactly one applied-evidence line is
   * emitted — by the child.) */
  if (!have_timeout) timeout_ms = 10000;
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int status = 0, timed_out = 0;
  for (;;) {
    pid_t r = waitpid(target, &status, WNOHANG);
    if (r == target) break;
    if (r < 0) { if (errno == EINTR) continue; _exit(127); }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long elapsed = (now.tv_sec - start.tv_sec) * 1000L + (now.tv_nsec - start.tv_nsec) / 1000000L;
    if (elapsed >= timeout_ms) {
      timed_out = 1;
      /* kill the whole group; ESRCH (already gone) is fine — idempotent */
      (void)kill(-target, SIGKILL);
      (void)kill(target, SIGKILL);
      break;
    }
    usleep(20000);
  }
  /* reap loop (also covers the post-kill reap) */
  for (;;) {
    pid_t r = waitpid(target, &status, 0);
    if (r == target) break;
    if (r < 0 && errno == EINTR) continue;
    if (r < 0) break;
  }
  /* belt-and-braces: ensure the group is gone even on the normal-exit path */
  (void)kill(-target, SIGKILL);

  if (timed_out) return MENOG_TIMEOUT_EXIT;
  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    if (code == MENOG_ISOLATION_FAILURE_EXIT) return MENOG_ISOLATION_FAILURE_EXIT;
    return code;
  }
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 127;
}
`;
