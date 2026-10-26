// src/response/mod.rs — Response engine
//
// Executes defensive actions on the local host.
// Modes:
//   Detect  — log what would happen, no action taken
//   Protect — execute actions based on confidence thresholds
//   Audit   — log only, never act
//
// All firewall calls go through src/firewall/mod.rs which detects
// nftables / firewalld / ufw / iptables / /proc on Unix and selects the
// Windows Firewall (netsh advfirewall) backend on Windows.
// If no firewall tool exists, errors are surfaced explicitly.
//
// PLATFORM: every action here works on Linux, Windows and macOS. Process
// termination uses the native tool for the OS (`kill -9` vs `taskkill /F /T`),
// and every state file (quarantine dir, isolation marker, block log) is resolved
// through `platform::data_dir()` rather than a hardcoded /var/lib/nebula, which
// on Windows put the agent's state at a path that does not exist.

use crate::config::{ResponseConfig, AgentMode};
use crate::firewall::Firewall;
use crate::types::{ThreatEvent, RawEvent, ResponseAction};
use std::path::{Path, PathBuf};
use tracing::{info, warn, error};

// ── Platform-resolved state locations ─────────────────────────
// data_dir() is /var/lib/nebula on Linux, C:\ProgramData\NebulaSentinel on
// Windows, /Library/Application Support/NebulaSentinel on macOS.

fn quarantine_dir() -> PathBuf { crate::platform::data_dir().join("quarantine") }
fn isolation_marker() -> PathBuf { crate::platform::data_dir().join("ISOLATED") }
fn blocked_ip_log() -> PathBuf { crate::platform::data_dir().join("blocked_ips.log") }

/// PIDs that must never be killed. On Unix that is init (1); on Windows it is
/// the System Idle Process (0) and System (4) — terminating either bugchecks
/// the machine.
fn is_protected_pid(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    { pid == 0 || pid == 4 }
    #[cfg(not(target_os = "windows"))]
    { pid <= 1 }
}

#[derive(Clone)]
pub struct ResponseEngine {
    pub config:   ResponseConfig,
    pub mode:     AgentMode,
    pub firewall: Firewall,
}

impl ResponseEngine {
    pub fn new(config: ResponseConfig, mode: AgentMode, firewall: Firewall) -> Self {
        Self { config, mode, firewall }
    }

    pub async fn execute(&self, threat: &ThreatEvent, _event: &RawEvent) {
        match self.mode {
            AgentMode::Detect => {
                info!("🔍 [DETECT] Would: {} for '{}' ({:.1}%)",
                    threat.suggested_action, threat.threat_name, threat.confidence);
            }
            AgentMode::Protect => {
                self.execute_action(&threat.suggested_action, threat.confidence).await;
            }
            AgentMode::Audit => {
                info!("📋 [AUDIT] '{}' — no action", threat.threat_name);
            }
        }
    }

    pub async fn execute_action(&self, action: &ResponseAction, confidence: f32) {
        match action {
            ResponseAction::KillProcess(pid) => {
                if confidence >= self.config.auto_kill_threshold {
                    self.kill_process(*pid).await;
                }
            }
            ResponseAction::QuarantineFile(path) => {
                if confidence >= self.config.auto_quarantine_threshold {
                    self.quarantine_file(path).await;
                }
            }
            ResponseAction::IsolateHost => {
                if confidence >= self.config.auto_isolate_threshold {
                    self.isolate_host().await;
                }
            }
            ResponseAction::BlockIp(ip) => { self.block_ip(ip).await; }
            _ => {}
        }
    }

    pub async fn kill_process(&self, pid: u32) {
        if is_protected_pid(pid) {
            warn!("  KillProcess: refusing pid={} (protected system process)", pid); return;
        }
        warn!("⚡ [PROTECT] KILL pid={}", pid);

        // taskkill /F = force, /T = terminate the child tree too (malware on
        // Windows habitually re-spawns from a helper, so killing the tree is the
        // behaviour that actually contains it). On Unix, SIGKILL the pid.
        #[cfg(target_os = "windows")]
        let cmd = tokio::process::Command::new("taskkill")
            .args(["/F", "/T", "/PID", &pid.to_string()])
            .output().await;
        #[cfg(not(target_os = "windows"))]
        let cmd = tokio::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output().await;

        match cmd {
            Ok(o) if o.status.success() => warn!("  ✅ pid={} killed", pid),
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr);
                let err = if err.trim().is_empty() { String::from_utf8_lossy(&o.stdout).trim().to_string() }
                          else { err.trim().to_string() };
                warn!("  ⚠️  kill pid={}: {}", pid, err);
                // Linux last resort: make the kernel OOM-killer pick this process
                // first. No Windows equivalent, so it is Linux-gated.
                #[cfg(target_os = "linux")]
                let _ = std::fs::write(format!("/proc/{}/oom_score_adj", pid), "1000");
            }
            Err(e) => { error!("  ✗ kill failed: {}", e); }
        }
    }

    pub async fn quarantine_file(&self, path: &str) {
        if !Path::new(path).exists() { warn!("  QuarantineFile: {} not found", path); return; }
        let qdir = quarantine_dir();
        let _ = std::fs::create_dir_all(&qdir);
        // Flatten the source path into a single filename. Both separators are
        // replaced (a Windows path is C:\Users\… ) and the drive colon too,
        // since ':' is not legal in an NTFS filename and would make the rename
        // fail silently on every Windows quarantine.
        let safe_name = path
            .replace(['/', '\\'], "_")
            .replace(':', "_")
            .replace("..", "__");
        let dest = qdir.join(format!("{}.quarantine", safe_name));
        let result = std::fs::rename(path, &dest).or_else(|_| {
            std::fs::copy(path, &dest).map(|_| ())?;
            std::fs::remove_file(path)
        });
        match result {
            Ok(_)  => warn!("📦 [PROTECT] Quarantined {} → {}", path, dest.display()),
            Err(e) => error!("  ✗ Quarantine failed {}: {}", path, e),
        }
        let entry = format!("{} QUARANTINED: {}\n", chrono::Utc::now().to_rfc3339(), path);
        let _ = std::fs::OpenOptions::new().append(true).create(true)
            .open(qdir.join("MANIFEST.log"))
            .and_then(|mut f| { use std::io::Write; f.write_all(entry.as_bytes()) });
    }

    pub async fn block_ip(&self, ip: &str) {
        match self.firewall.block_ip(ip).await {
            Ok(_) => {
                let entry = format!("{} BLOCKED: {}\n", chrono::Utc::now().to_rfc3339(), ip);
                let _ = std::fs::OpenOptions::new().append(true).create(true)
                    .open(blocked_ip_log())
                    .and_then(|mut f| { use std::io::Write; f.write_all(entry.as_bytes()) });
            }
            Err(e) => error!("  ✗ block_ip {} failed (backend={}): {}", ip, self.firewall.backend, e),
        }
    }

    pub async fn unblock_ip(&self, ip: &str) {
        if let Err(e) = self.firewall.unblock_ip(ip).await {
            error!("  ✗ unblock_ip {} failed: {}", ip, e);
        }
    }

    pub async fn isolate_host(&self) {
        warn!("🔒 [PROTECT] *** ISOLATION *** backend={}", self.firewall.backend);
        if self.is_isolated() { info!("  Already isolated"); return; }
        match self.firewall.isolate(&self.config.isolation_allowlist).await {
            Ok(_) => {
                let _ = std::fs::create_dir_all(crate::platform::data_dir());
                let _ = std::fs::write(isolation_marker(), format!(
                    "ISOLATED at {}\nBackend: {}\nAllowlist: {:?}\n",
                    chrono::Utc::now().to_rfc3339(), self.firewall.backend,
                    self.config.isolation_allowlist));
            }
            Err(e) => error!("  ✗ Isolation failed: {}", e),
        }
    }

    pub async fn undo_isolation(&self) {
        warn!("🔓 [PROTECT] Removing isolation...");
        match self.firewall.undo_isolation().await {
            Ok(_) => { let _ = std::fs::remove_file(isolation_marker()); }
            Err(e) => error!("  ✗ Undo isolation failed: {}", e),
        }
    }

    pub fn is_isolated(&self) -> bool {
        isolation_marker().exists()
    }
}
