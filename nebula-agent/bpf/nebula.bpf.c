// nebula.bpf.c — Nebula Sentinel kernel-side eBPF programs (CO-RE).
//
// Compile with:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//         -I/usr/include/$(uname -m)-linux-gnu \
//         -c bpf/nebula.bpf.c -o bpf/nebula.bpf.o
//
// Requires libbpf headers (vmlinux.h generated from BTF) for CO-RE. Generate
// vmlinux.h once on a representative kernel with:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
//
// CO-RE (Compile Once, Run Everywhere): field offsets are relocated at load
// time against the running kernel's BTF, so a single .bpf.o runs across kernel
// versions without recompilation. That is why this is the "safest" path for an
// uncertain fleet.
//
// What we attach to (all are stable tracepoints/LSM-free kprobes):
//   - tracepoint/sched/sched_process_exec   → process execution
//   - tracepoint/sched/sched_process_exit   → process exit
//   - kprobe/tcp_connect                    → outbound TCP connect (v4/v6)
//   - kprobe/__sys_bind / tracepoint bind   → socket bind
//   - tracepoint/syscalls/sys_enter_openat  → file open (filtered userspace)
//   - kprobe/security_kernel_read_file or tp module load → kernel module load
//   - tracepoint/syscalls/sys_enter_ptrace  → ptrace (injection/debugging)
//
// Events are pushed to a BPF ring buffer; userspace (aya) drains it.

// Use the full bpftool-generated vmlinux.h when present (build.rs defines
// NEBULA_HAVE_FULL_VMLINUX), otherwise fall back to the shipped minimal header
// so the object compiles with just clang — no bpftool / libbpf-dev required.
#ifdef NEBULA_HAVE_FULL_VMLINUX
#include "vmlinux.h"
#else
#include "vmlinux_min.h"
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "nebula_events.h"

char LICENSE[] SEC("license") = "GPL";

// Ring buffer — 256 KB. Userspace drains via aya RingBuf. Sized to absorb
// bursts (e.g. a fork storm) without dropping; on overflow we lose events
// rather than block the kernel, which is the correct safety tradeoff.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Optional config map so userspace can toggle event classes at runtime without
// reloading programs. index 0 = master enable, 1..=per-kind. 0 means "emit".
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} nebula_cfg SEC(".maps");

static __always_inline int kind_enabled(__u32 kind) {
    __u32 master_key = 0;
    __u32 *master = bpf_map_lookup_elem(&nebula_cfg, &master_key);
    if (master && *master != 0) return 0;          // master disable
    __u32 *en = bpf_map_lookup_elem(&nebula_cfg, &kind);
    if (en && *en != 0) return 0;                  // this kind disabled
    return 1;
}

// Fill the common identity fields (pid/ppid/uid/gid/comm/ts) on an event.
static __always_inline void fill_common(struct nebula_event *e, __u32 kind) {
    e->kind = kind;
    e->ts_ns = bpf_ktime_get_ns();

    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;                              // tgid = userspace PID

    __u64 ug = bpf_get_current_uid_gid();
    e->uid = (__u32)ug;
    e->gid = ug >> 32;

    // Parent tgid via current task_struct (CO-RE relocated).
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// ── Process execution ──────────────────────────────────────────────────
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    if (!kind_enabled(NEBULA_EVT_EXEC)) return 0;

    struct nebula_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, NEBULA_EVT_EXEC);
    e->ret = 0;
    e->family = 0; e->dport = 0; e->addr4 = 0;
    __builtin_memset(e->addr6, 0, sizeof(e->addr6));
    __builtin_memset(e->args, 0, sizeof(e->args));

    // Filename: the tracepoint carries a __data_loc offset to the filename.
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
                              (void *)ctx + fname_off);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── Process exit ───────────────────────────────────────────────────────
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    if (!kind_enabled(NEBULA_EVT_EXIT)) return 0;

    // Only emit for thread-group leaders (real process exit, not thread).
    __u64 id = bpf_get_current_pid_tgid();
    if ((id >> 32) != (id & 0xFFFFFFFF)) return 0;

    struct nebula_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, NEBULA_EVT_EXIT);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int code = BPF_CORE_READ(task, exit_code);
    e->ret = (code >> 8) & 0xff;                    // WEXITSTATUS
    e->family = 0; e->dport = 0; e->addr4 = 0;
    __builtin_memset(e->addr6, 0, sizeof(e->addr6));
    e->filename[0] = 0; e->args[0] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── Outbound TCP connect (IPv4 + IPv6) ─────────────────────────────────
SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk) {
    if (!kind_enabled(NEBULA_EVT_CONNECT)) return 0;

    struct nebula_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, NEBULA_EVT_CONNECT);
    e->ret = 0; e->filename[0] = 0; e->args[0] = 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e->family = family;
    // dport stored network-order in skc_dport; convert to host order.
    __u16 dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->dport = bpf_ntohs(dport_be);

    if (family == 2 /* AF_INET */) {
        e->addr4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memset(e->addr6, 0, sizeof(e->addr6));
    } else if (family == 10 /* AF_INET6 */) {
        BPF_CORE_READ_INTO(&e->addr6, sk,
            __sk_common.skc_v6_daddr.in6_u.u6_addr8);
        e->addr4 = 0;
    } else {
        e->addr4 = 0;
        __builtin_memset(e->addr6, 0, sizeof(e->addr6));
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── ptrace (process injection / anti-debug / credential theft) ─────────
SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx) {
    if (!kind_enabled(NEBULA_EVT_PTRACE)) return 0;

    struct nebula_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, NEBULA_EVT_PTRACE);
    // args[0]=request, args[1]=pid target. Stash target pid in ret for context.
    e->ret = (int)ctx->args[1];
    e->family = 0; e->dport = 0; e->addr4 = 0;
    __builtin_memset(e->addr6, 0, sizeof(e->addr6));
    e->filename[0] = 0; e->args[0] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ── Kernel module load (rootkit / LKM persistence) ─────────────────────
SEC("tracepoint/syscalls/sys_enter_init_module")
int handle_init_module(struct trace_event_raw_sys_enter *ctx) {
    if (!kind_enabled(NEBULA_EVT_MODULE_LOAD)) return 0;

    struct nebula_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, NEBULA_EVT_MODULE_LOAD);
    e->ret = 0;
    e->family = 0; e->dport = 0; e->addr4 = 0;
    __builtin_memset(e->addr6, 0, sizeof(e->addr6));
    e->filename[0] = 0; e->args[0] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Also catch finit_module (the modern module-load path used by modprobe).
SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_finit_module(struct trace_event_raw_sys_enter *ctx) {
    if (!kind_enabled(NEBULA_EVT_MODULE_LOAD)) return 0;

    struct nebula_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill_common(e, NEBULA_EVT_MODULE_LOAD);
    e->ret = 1;                                     // distinguish finit vs init
    e->family = 0; e->dport = 0; e->addr4 = 0;
    __builtin_memset(e->addr6, 0, sizeof(e->addr6));
    e->filename[0] = 0; e->args[0] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
