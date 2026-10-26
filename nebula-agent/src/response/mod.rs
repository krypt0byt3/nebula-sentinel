// src/response/mod.rs — Response engine
//
// Executes defensive actions on the local host.
// Modes:
//   Detect  — log what would happen, no action taken
//   Protect — execute actions based on confidence thresholds
//   Audit   — log only, never act
//
// All firewall calls go through src/firewall/mod.rs which detects
// nftables / firewalld / ufw / iptables / /proc at startup.
// If no firewall tool exists, errors are surfaced explicitly.

use crate::config::{ResponseConfig, AgentMode};
use crate::firewall::Firewall;
use crate::types::{ThreatEvent, RawEvent, ResponseAction};
use std::path::Path;
use tracing::{info, warn, error};

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
        if pid <= 1 {
            warn!("  KillProcess: refusing pid={}", pid); return;
        }
        warn!("⚡ [PROTECT] KILL pid={}", pid);
        match tokio::process::Command::new("kill").args(["-9", &pid.to_string()]).output().await {
            Ok(o) if o.status.success() => warn!("  ✅ pid={} killed", pid),
            Ok(o) => {
                warn!("  ⚠️  kill pid={}: {}", pid, String::from_utf8_lossy(&o.stderr).trim());
                let _ = std::fs::write(format!("/proc/{}/oom_score_adj", pid), "1000");
            }
            Err(e) => { error!("  ✗ kill failed: {}", e); }
        }
    }

    pub async fn quarantine_file(&self, path: &str) {
        if !Path::new(path).exists() { warn!("  QuarantineFile: {} not found", path); return; }
        let qdir = "/var/lib/nebula/quarantine";
        let _ = std::fs::create_dir_all(qdir);
        let safe_name = path.replace('/', "_").replace("..", "__");
        let dest = format!("{}/{}.quarantine", qdir, safe_name);
        let result = std::fs::rename(path, &dest).or_else(|_| {
            std::fs::copy(path, &dest).map(|_| ())?;
            std::fs::remove_file(path)
        });
        match result {
            Ok(_)  => warn!("📦 [PROTECT] Quarantined {} → {}", path, dest),
            Err(e) => error!("  ✗ Quarantine failed {}: {}", path, e),
        }
        let entry = format!("{} QUARANTINED: {}\n", chrono::Utc::now().to_rfc3339(), path);
        let _ = std::fs::OpenOptions::new().append(true).create(true)
            .open(format!("{}/MANIFEST.log", qdir))
            .and_then(|mut f| { use std::io::Write; f.write_all(entry.as_bytes()) });
    }

    pub async fn block_ip(&self, ip: &str) {
        match self.firewall.block_ip(ip).await {
            Ok(_) => {
                let entry = format!("{} BLOCKED: {}\n", chrono::Utc::now().to_rfc3339(), ip);
                let _ = std::fs::OpenOptions::new().append(true).create(true)
                    .open("/var/lib/nebula/blocked_ips.log")
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
                let _ = std::fs::write("/var/lib/nebula/ISOLATED", format!(
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
            Ok(_) => { let _ = std::fs::remove_file("/var/lib/nebula/ISOLATED"); }
            Err(e) => error!("  ✗ Undo isolation failed: {}", e),
        }
    }

    pub fn is_isolated(&self) -> bool {
        Path::new("/var/lib/nebula/ISOLATED").exists()
    }
}
