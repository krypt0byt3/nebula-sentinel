/* nebula_events.h — shared event layout between the BPF programs and the
 * userspace (aya) loader. BOTH sides MUST agree on this struct byte-for-byte,
 * so the Rust side mirrors it exactly (see collector/ebpf.rs `RawBpfEvent`).
 *
 * Keep this struct:
 *   - #[repr(C)] compatible (it is plain C),
 *   - free of pointers (only fixed-size fields cross the ring buffer),
 *   - padded predictably (we use fixed char arrays, no bitfields).
 */
#ifndef NEBULA_EVENTS_H
#define NEBULA_EVENTS_H

/* Event kinds — mirrors a subset of the Rust EventType enum. The userspace
 * loader maps these to crate::types::EventType. */
#define NEBULA_EVT_EXEC          1
#define NEBULA_EVT_EXIT          2
#define NEBULA_EVT_CONNECT       3
#define NEBULA_EVT_BIND          4
#define NEBULA_EVT_FILE_OPEN     5
#define NEBULA_EVT_MODULE_LOAD   6
#define NEBULA_EVT_PTRACE        7

#define NEBULA_COMM_LEN   16     /* matches kernel TASK_COMM_LEN */
#define NEBULA_ARGS_LEN   256    /* truncated argv capture */
#define NEBULA_PATH_LEN   256    /* truncated path/filename capture */

struct nebula_event {
    unsigned int  kind;          /* NEBULA_EVT_* */
    unsigned int  pid;           /* tgid (userspace PID) */
    unsigned int  ppid;          /* parent tgid */
    unsigned int  uid;           /* real uid */
    unsigned int  gid;           /* real gid */
    int           ret;           /* return/exit code where relevant */
    unsigned long long ts_ns;    /* bpf_ktime_get_ns at capture */

    char comm[NEBULA_COMM_LEN];          /* process name */
    char filename[NEBULA_PATH_LEN];      /* exec path / file path / module */
    char args[NEBULA_ARGS_LEN];          /* first args of argv (exec only) */

    /* Network fields (CONNECT/BIND). Stored network-byte-order; userspace
     * formats them. daddr is IPv4 in addr4, IPv6 in addr6 (family selects). */
    unsigned short family;       /* AF_INET=2, AF_INET6=10 */
    unsigned short dport;        /* destination port, host order set by bpf */
    unsigned int   addr4;        /* IPv4 daddr, network order */
    unsigned char  addr6[16];    /* IPv6 daddr */
};

#endif /* NEBULA_EVENTS_H */
