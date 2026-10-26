# Nebula Sentinel — eBPF backend

This directory holds the kernel-side eBPF programs that give the agent
**real-time, syscall-level visibility** instead of 5-second `/proc` polling.

## What it observes

| Program | Attach point | Detects |
|---|---|---|
| `handle_exec` | tracepoint `sched/sched_process_exec` | every process execution — including short-lived ones polling misses |
| `handle_exit` | tracepoint `sched/sched_process_exit` | process exit + exit code |
| `handle_tcp_connect` | kprobe `tcp_connect` | outbound TCP connects (IPv4/IPv6) at the moment they happen |
| `handle_ptrace` | tracepoint `syscalls/sys_enter_ptrace` | process injection / anti-debug / credential theft |
| `handle_init_module` / `handle_finit_module` | tracepoints | kernel module loads (rootkit / LKM persistence) |

All events are pushed to a BPF **ring buffer** and drained by the userspace
loader (`src/collector/ebpf.rs`), which decodes them into the same `RawEvent`
type the rest of the detection pipeline already consumes. Nothing downstream
changes — it just receives events in sub-millisecond real time.

## Why this closes the biggest blind spot

The default `procmon` backend snapshots `/proc` every 5s and diffs PIDs, so any
process that starts and exits within that window is **never seen** (droppers,
fast recon one-liners, transient exploit chains). eBPF observes the `execve`
*syscall itself*, so nothing is too fast to catch. It also sees connects and
ptrace at the source rather than reconstructing them after the fact.

## Building the BPF object (one-time, on a build host)

```bash
# Prereqs (Debian/Ubuntu):
sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r)

# Build the CO-RE object:
make -C bpf            # generates vmlinux.h from BTF, compiles nebula.bpf.o
sudo make -C bpf install   # → /usr/lib/nebula/nebula.bpf.o
```

**CO-RE (Compile Once, Run Everywhere):** the object is compiled once against
the build host's BTF and relocates field offsets at load time against each
target kernel's BTF. You do **not** rebuild per kernel version — one object runs
across the fleet (Linux 5.8+ with `CONFIG_DEBUG_INFO_BTF=y`, which nearly all
modern distro kernels ship).

## Building the agent with eBPF support

```bash
cargo build --release --features ebpf,yara
```

Without `--features ebpf` the agent still builds (no aya dependency, no BPF
toolchain needed) and the `ebpf` backend setting **cleanly falls back to
procmon** at runtime with a clear log line.

## Enabling it at runtime

In the agent config (`[collector]`):

```toml
[collector]
backend = "ebpf"     # was "procmon"
```

Requires `CAP_BPF` + `CAP_PERFMON` (or root). The systemd unit should grant:

```ini
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE
```

## Graceful degradation (by design)

The agent falls back to procmon, logging exactly why, when any of these are true:

- built without the `ebpf` feature,
- `/sys/kernel/btf/vmlinux` is missing (no BTF),
- `nebula.bpf.o` not found in `/usr/lib/nebula`, `./bpf`, or `.`,
- the verifier rejects a program, or no program attaches (kernel/permission).

So a mixed fleet is safe: modern hosts get real-time eBPF, everything else keeps
working on polling. Check the agent log at startup for which backend engaged.

## Keeping C and Rust in lockstep

`nebula_events.h` (C) and `RawBpfEvent` (in `src/collector/ebpf.rs`) describe the
**same struct** crossing the ring buffer. If you change one, change the other in
the same commit — a layout mismatch produces garbage events, not a compile error.
