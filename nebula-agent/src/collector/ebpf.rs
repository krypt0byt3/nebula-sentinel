// src/collector/ebpf.rs — userspace eBPF loader (aya).
//
// This is the userspace half of the eBPF backend. It is compiled into the agent
// only when the `ebpf` Cargo feature is enabled (it pulls in the `aya` crate).
// Without that feature, collector/mod.rs uses the no-op shim below so the agent
// still builds with zero BPF toolchain.
//
// Responsibilities:
//   1. Load the precompiled CO-RE object (bpf/nebula.bpf.o) — embedded at build
//      time, or loaded from disk as a fallback.
//   2. Attach the tracepoints/kprobes.
//   3. Drain the BPF ring buffer, decode each `nebula_event` (byte-compatible
//      with bpf/nebula_events.h) into a crate RawEvent, and forward it on `tx`.
//
// On ANY failure (kernel too old, no BTF, verifier rejection, missing privilege,
// object not found) the caller (collector/mod.rs) catches the error and falls
// back to procmon. We log loudly at each boundary so an operator knows exactly
// why eBPF didn't engage, instead of silently degrading.

use crate::types::{RawEvent, EventType};
use anyhow::{Result, Context, bail};
use chrono::Utc;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc;
use tracing::{info, warn, debug};
use uuid::Uuid;

// Event kinds — MUST match bpf/nebula_events.h.
const NEBULA_EVT_EXEC: u32 = 1;
const NEBULA_EVT_EXIT: u32 = 2;
const NEBULA_EVT_CONNECT: u32 = 3;
const NEBULA_EVT_BIND: u32 = 4;
const NEBULA_EVT_FILE_OPEN: u32 = 5;
const NEBULA_EVT_MODULE_LOAD: u32 = 6;
const NEBULA_EVT_PTRACE: u32 = 7;

const COMM_LEN: usize = 16;
const ARGS_LEN: usize = 256;
const PATH_LEN: usize = 256;

// Byte-for-byte mirror of `struct nebula_event` in bpf/nebula_events.h.
// #[repr(C)] guarantees the field order/layout matches the C struct so we can
// reinterpret ring-buffer bytes directly. If you change the C struct, change
// this in lockstep (and the constants above).
#[repr(C)]
#[derive(Clone, Copy)]
struct RawBpfEvent {
    kind: u32,
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    ret: i32,
    ts_ns: u64,
    comm: [u8; COMM_LEN],
    filename: [u8; PATH_LEN],
    args: [u8; ARGS_LEN],
    family: u16,
    dport: u16,
    addr4: u32,
    addr6: [u8; 16],
}

// Safety: RawBpfEvent is repr(C), all-POD (no padding-sensitive reads beyond the
// fixed arrays), and we only construct it by copying out of the ring buffer.
unsafe impl aya::Pod for RawBpfEvent {}

fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

fn map_kind(kind: u32) -> EventType {
    match kind {
        NEBULA_EVT_EXEC        => EventType::ProcessExec,
        NEBULA_EVT_EXIT        => EventType::ProcessExit,
        NEBULA_EVT_CONNECT     => EventType::NetworkConnect,
        NEBULA_EVT_BIND        => EventType::NetworkBind,
        NEBULA_EVT_FILE_OPEN   => EventType::FileOpen,
        NEBULA_EVT_MODULE_LOAD => EventType::ModuleLoad,
        NEBULA_EVT_PTRACE      => EventType::Ptrace,
        _                      => EventType::SyscallAnomalous,
    }
}

// Locate the compiled BPF object. Preference order:
//   1. Embedded at compile time (build.rs baked it in — the zero-install path).
//   2. /usr/lib/nebula/nebula.bpf.o (system install, e.g. via setup-ebpf.sh).
//   3. ./bpf/nebula.bpf.o or ./nebula.bpf.o (dev / run-from-repo).
fn load_bpf_object() -> Result<aya::Ebpf> {
    // 1. Embedded bytes — present when the agent was built with the BPF object
    //    baked in (build.rs sets nebula_bpf_embedded + NEBULA_BPF_OBJECT). This
    //    is the "nothing to install on the target" path.
    #[cfg(nebula_bpf_embedded)]
    {
        static OBJ: &[u8] = include_bytes!(env!("NEBULA_BPF_OBJECT"));
        info!("🔬 eBPF: loading embedded BPF object ({} bytes)", OBJ.len());
        match aya::Ebpf::load(OBJ) {
            Ok(bpf) => return Ok(bpf),
            Err(e) => {
                warn!("eBPF: embedded object failed to load ({}), trying on-disk fallbacks…", e);
            }
        }
    }

    // 2/3. Disk search (also the only path when not embedded).
    for path in ["/usr/lib/nebula/nebula.bpf.o", "bpf/nebula.bpf.o", "./nebula.bpf.o"] {
        if std::path::Path::new(path).exists() {
            info!("🔬 eBPF: loading BPF object from {}", path);
            return aya::Ebpf::load_file(path)
                .with_context(|| format!("loading BPF object {}", path));
        }
    }

    bail!("no BPF object available — build the agent with `--features ebpf` on a host with clang \
           (it auto-embeds), or run scripts/setup-ebpf.sh on this machine to install \
           /usr/lib/nebula/nebula.bpf.o");
}

/// Start the eBPF collector. Loads + attaches programs, then spawns a blocking
/// drain loop that forwards decoded events on `tx`. Returns Err on any setup
/// failure so the caller can fall back to procmon.
pub async fn start(
    tx: mpsc::Sender<RawEvent>,
    agent_id: String,
    hostname: String,
) -> Result<()> {
    use aya::programs::{TracePoint, KProbe};

    // BTF is required for CO-RE relocation.
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        bail!("BTF not available (/sys/kernel/btf/vmlinux missing) — kernel lacks CONFIG_DEBUG_INFO_BTF");
    }

    // Raising the memlock rlimit is needed on older kernels for map allocation.
    bump_memlock_rlimit();

    let mut bpf = load_bpf_object()?;

    // Attach programs. Each attach is best-effort within reason: if a specific
    // tracepoint/kprobe is unavailable on this kernel we log and continue with
    // whichever attached, rather than failing the whole backend. But we require
    // at least the exec tracepoint (the core capability) to consider eBPF "up".
    let mut attached = 0usize;

    // aya 0.13: program_mut(name) -> Option<&mut Program>; converting to the
    // concrete program type is TryInto on &mut Program -> Result<&mut T, _>.
    // load() then attach() each return Result; we handle them explicitly so a
    // single missing tracepoint/kprobe on this kernel doesn't kill the backend.
    macro_rules! attach_tp {
        ($prog:literal, $category:literal, $name:literal) => {{
            match bpf.program_mut($prog) {
                Some(prog) => {
                    let tp: Result<&mut TracePoint, _> = prog.try_into();
                    match tp {
                        Ok(tp) => {
                            if let Err(e) = tp.load() {
                                warn!("eBPF: load {} failed: {}", $prog, e);
                            } else if let Err(e) = tp.attach($category, $name) {
                                warn!("eBPF: attach {}/{} failed: {}", $category, $name, e);
                            } else {
                                attached += 1;
                                debug!("eBPF: attached tracepoint {}/{}", $category, $name);
                            }
                        }
                        Err(e) => warn!("eBPF: {} is not a tracepoint: {}", $prog, e),
                    }
                }
                None => warn!("eBPF: program {} not found in object", $prog),
            }
        }};
    }
    macro_rules! attach_kp {
        ($prog:literal, $fn:literal) => {{
            match bpf.program_mut($prog) {
                Some(prog) => {
                    let kp: Result<&mut KProbe, _> = prog.try_into();
                    match kp {
                        Ok(kp) => {
                            if let Err(e) = kp.load() {
                                warn!("eBPF: load {} failed: {}", $prog, e);
                            } else if let Err(e) = kp.attach($fn, 0) {
                                warn!("eBPF: attach kprobe {} failed: {}", $fn, e);
                            } else {
                                attached += 1;
                                debug!("eBPF: attached kprobe {}", $fn);
                            }
                        }
                        Err(e) => warn!("eBPF: {} is not a kprobe: {}", $prog, e),
                    }
                }
                None => warn!("eBPF: program {} not found in object", $prog),
            }
        }};
    }

    attach_tp!("handle_exec",          "sched",    "sched_process_exec");
    attach_tp!("handle_exit",          "sched",    "sched_process_exit");
    attach_tp!("handle_ptrace",        "syscalls", "sys_enter_ptrace");
    attach_tp!("handle_init_module",   "syscalls", "sys_enter_init_module");
    attach_tp!("handle_finit_module",  "syscalls", "sys_enter_finit_module");
    attach_kp!("handle_tcp_connect",   "tcp_connect");

    if attached == 0 {
        bail!("eBPF: no programs could be attached (kernel/permission mismatch)");
    }
    info!("🔬 eBPF: {} program(s) attached — real-time syscall monitoring active", attached);

    // Take the ring buffer and spawn the drain loop on a blocking thread.
    let ring = aya::maps::RingBuf::try_from(
        bpf.take_map("events").context("BPF object missing 'events' ring buffer map")?
    ).context("opening ring buffer")?;

    // Keep `bpf` alive for the life of the program (dropping it detaches). We
    // move it into the blocking task so the programs stay attached.
    tokio::task::spawn_blocking(move || {
        let _keep_alive = bpf;          // hold programs attached until task ends
        drain_loop(ring, tx, agent_id, hostname);
    });

    Ok(())
}

// Blocking drain loop: polls the ring buffer, decodes events, forwards them.
fn drain_loop(
    mut ring: aya::maps::RingBuf<aya::maps::MapData>,
    tx: mpsc::Sender<RawEvent>,
    agent_id: String,
    hostname: String,
) {
    use std::os::fd::AsRawFd;
    let fd = ring.as_raw_fd();
    let sz = std::mem::size_of::<RawBpfEvent>();
    info!("🔬 eBPF: draining ring buffer (event size {} bytes)", sz);

    loop {
        // Drain everything currently available.
        let mut got_any = false;
        while let Some(item) = ring.next() {
            got_any = true;
            let bytes: &[u8] = &item;
            if bytes.len() < sz {
                debug!("eBPF: short ring sample ({} < {})", bytes.len(), sz);
                continue;
            }
            // SAFETY: bytes originates from the kernel writing a RawBpfEvent;
            // we verified length and the type is repr(C) POD. Copy out (the
            // slice is only valid while `item` lives).
            let ev: RawBpfEvent = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const RawBpfEvent) };
            drop(item);

            if let Some(raw) = decode(&ev, &agent_id, &hostname) {
                if tx.try_send(raw).is_err() {
                    debug!("eBPF: event queue full, dropping pid={}", ev.pid);
                }
            }
        }
        if !got_any {
            // No data: poll the fd briefly to avoid a busy spin. We use a short
            // timeout so shutdown remains responsive.
            poll_fd(fd, 200);
        }
    }
}

// Decode a raw BPF event into the crate's RawEvent, enriching where cheap.
fn decode(ev: &RawBpfEvent, agent_id: &str, hostname: &str) -> Option<RawEvent> {
    let event_type = map_kind(ev.kind);
    let comm = cstr(&ev.comm);
    let filename = cstr(&ev.filename);
    let args = cstr(&ev.args);

    let (dest_ip, dest_port, proto) = if matches!(event_type, EventType::NetworkConnect | EventType::NetworkBind) {
        let ip = match ev.family {
            2  => Some(Ipv4Addr::from(u32::from_be(ev.addr4)).to_string()),
            10 => Some(Ipv6Addr::from(ev.addr6).to_string()),
            _  => None,
        };
        (ip, Some(ev.dport), Some("tcp".to_string()))
    } else {
        (None, None, None)
    };

    // For exec, prefer the captured filename as process_path; derive name from
    // comm (kernel-truncated to 15 chars) or the path's basename when longer.
    let process_path = if !filename.is_empty() { Some(filename.clone()) } else { None };
    let process_name = if !comm.is_empty() { comm.clone() } else {
        filename.rsplit('/').next().unwrap_or("").to_string()
    };

    let syscall = match ev.kind {
        NEBULA_EVT_EXEC        => Some("execve".to_string()),
        NEBULA_EVT_EXIT        => Some("exit".to_string()),
        NEBULA_EVT_CONNECT     => Some("connect".to_string()),
        NEBULA_EVT_BIND        => Some("bind".to_string()),
        NEBULA_EVT_FILE_OPEN   => Some("openat".to_string()),
        NEBULA_EVT_MODULE_LOAD => Some(if ev.ret == 1 { "finit_module".to_string() } else { "init_module".to_string() }),
        NEBULA_EVT_PTRACE      => Some("ptrace".to_string()),
        _                      => None,
    };

    let mut extra = HashMap::new();
    extra.insert("source".to_string(), serde_json::json!("ebpf"));
    extra.insert("ktime_ns".to_string(), serde_json::json!(ev.ts_ns));
    if ev.kind == NEBULA_EVT_PTRACE {
        extra.insert("ptrace_target_pid".to_string(), serde_json::json!(ev.ret));
    }

    Some(RawEvent {
        id:                Uuid::new_v4().to_string(),
        agent_id:          agent_id.to_string(),
        hostname:          hostname.to_string(),
        timestamp:         Utc::now(),
        event_type,
        pid:               ev.pid,
        ppid:              ev.ppid,
        uid:               ev.uid,
        gid:               ev.gid,
        process_name,
        process_path,
        command_line:      if args.is_empty() { None } else { Some(args) },
        parent_process:    None,         // resolved downstream if needed
        file_path:         if filename.is_empty() { None } else { Some(filename) },
        file_hash:         None,         // hashing happens downstream (off hot path)
        network_dest_ip:   dest_ip,
        network_dest_port: dest_port,
        network_proto:     proto,
        syscall,
        return_code:       if ev.kind == NEBULA_EVT_EXIT { Some(ev.ret as i64) } else { None },
        container_id:      None,
        namespace:         None,
        extra,
    })
}

// Raise RLIMIT_MEMLOCK to infinity — required for BPF map allocation on kernels
// before 5.11 (after that, memcg accounting removes the need, but raising is
// harmless). Best-effort; failure is logged, not fatal.
fn bump_memlock_rlimit() {
    let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("eBPF: could not raise RLIMIT_MEMLOCK (continuing; may fail on old kernels)");
    }
}

// Poll a raw fd for readability with a timeout (ms). Used to avoid busy-spinning
// the drain loop when the ring buffer is empty.
fn poll_fd(fd: std::os::fd::RawFd, timeout_ms: i32) {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    unsafe { libc::poll(&mut pfd, 1, timeout_ms); }
}
