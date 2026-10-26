/* vmlinux_min.h — minimal CO-RE type definitions.
 *
 * This lets us compile nebula.bpf.c with ONLY clang — no bpftool, no
 * libbpf-dev, no full generated vmlinux.h. It declares exactly the kernel
 * structures and fields our programs read, each marked with
 * `preserve_access_index` so clang emits CO-RE relocations: at load time the
 * field offsets are fixed up against the TARGET kernel's BTF, so a single
 * object runs across kernel versions (Compile Once, Run Everywhere).
 *
 * IMPORTANT: these are partial definitions — only the fields we touch are
 * listed, in the right nesting. CO-RE relocates by NAME, not by the offsets
 * implied here, so the partial layout is fine as long as field *names* and
 * types match the real kernel. If you read a new field in nebula.bpf.c, add it
 * here too.
 *
 * If bpftool IS available at build time, build.rs prefers a real generated
 * vmlinux.h instead of this (more complete, future-proof). This minimal header
 * is the zero-extra-dependency fallback.
 */
#ifndef __VMLINUX_MIN_H__
#define __VMLINUX_MIN_H__

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef long long unsigned int __u64;
typedef int __s32;
typedef long long int __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef _Bool bool;

/* pt_regs — needed by BPF_KPROBE macros. The minimal path only reads kprobe
 * PARM1, so a forward-usable definition with the common x86_64 register fields
 * is enough; CO-RE doesn't relocate pt_regs (it's ABI-fixed per arch). For
 * non-x86 arches, prefer the bpftool-generated vmlinux.h (full definitions). */
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
    long unsigned int r15, r14, r13, r12, rbp, rbx;
    long unsigned int r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi;
    long unsigned int orig_rax, rip, cs, eflags, rsp, ss;
};
#else
/* Other arches: rely on bpftool-generated vmlinux.h instead of this header. */
struct pt_regs;
#endif

/* BPF map type enum values our programs use. */
enum {
    BPF_MAP_TYPE_ARRAY   = 2,
    BPF_MAP_TYPE_RINGBUF = 27,
};

/* ── task_struct: parent + identity + exit code ─────────────── */
struct task_struct {
    int                pid;
    int                tgid;
    struct task_struct *real_parent;
    struct task_struct *parent;
    unsigned int       exit_code;
};

/* ── sock common: address/port/family for tcp_connect ───────── */
struct in6_addr {
    union {
        __u8 u6_addr8[16];
    } in6_u;
};

struct sock_common {
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        struct {
            __be16 skc_dport;
            __u16  skc_num;
        };
    };
    short unsigned int  skc_family;
    struct in6_addr     skc_v6_daddr;
};

struct sock {
    struct sock_common __sk_common;
};

/* ── tracepoint context structs ─────────────────────────────── */
/* sched_process_exec carries a __data_loc to the filename string. */
struct trace_event_raw_sched_process_exec {
    struct {
        char _pad0[8];
    } ent;
    __u32 __data_loc_filename;
    __u32 pid;
    __u32 old_pid;
};

/* generic sched template (used for process exit) */
struct trace_event_raw_sched_process_template {
    struct {
        char _pad0[8];
    } ent;
    char  comm[16];
    __u32 pid;
    int   prio;
};

/* syscall enter tracepoint: args[6] holds the syscall arguments */
struct trace_event_raw_sys_enter {
    struct {
        char _pad0[8];
    } ent;
    long int    id;
    long unsigned int args[6];
};

#pragma clang attribute pop

#endif /* __VMLINUX_MIN_H__ */
