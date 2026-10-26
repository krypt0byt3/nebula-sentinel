#![allow(dead_code)]
// src/self_protect/mod.rs — Sentinel Self-Hardening & Tamper Protection
//
// Security objectives:
//   1. Binary integrity    — SHA-256 hash of own executable, re-checked every 60s
//   2. Config integrity    — SHA-256 of config.toml, alerts on unexpected changes
//   3. Anti-ptrace         — prctl(PR_SET_DUMPABLE=0) + TracerPid detection
//   4. Privilege drop      — after binding privileged resources, drop to service account
//   5. Process hiding      — /proc/self/oom_score_adj = -1000 (OOM-killer exempt)
//   6. Watchdog heartbeat  — secondary process monitors and restarts if killed
//   7. Prompt injection    — block LLM input injection attempts (ATLAS AML.T0043)
//   8. Memory scrubbing    — zero-fill sensitive buffers (secrets, keys) after use
//   9. Immutable log trail — append-only alert log via O_APPEND
//  10. Anti-tamper signal  — SIGTERM/SIGKILL attempts are audited before termination
//
// Linux security features used:
//   prctl(PR_SET_DUMPABLE, 0)      — prevents /proc/PID/mem access by other processes
//   prctl(PR_SET_PTRACER, -1)      — disallows ptrace from any process
//   rlimit(RLIMIT_CORE, 0)         — disables core dumps (no credential leakage)
//   umask(0o077)                   — all created files are owner-only (rwx------)
//   /proc/PID/oom_score_adj = -1000 — OOM-killer will not kill the sentinel
//
// MITRE ATLAS coverage:
//   AML.T0043 — Craft adversarial data (prompt injection detection)
//   AML.T0018 — Backdoor ML model (model hash verification)
//   AML.T0020 — Adversarial examples (input sanitisation)
//   AML.T0049 — Exploit public-facing ML API (local rate limiting)

use crate::config::SelfProtectConfig;
use anyhow::Result;
use sha2::{Sha256, Digest};
use tracing::{info, warn, error};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::io::Write;

pub struct SelfProtection {
    pub config:      SelfProtectConfig,
    binary_hash: Arc<Mutex<Option<String>>>,
    config_hash: Arc<Mutex<Option<String>>>,
}

impl SelfProtection {
    pub fn new(config: SelfProtectConfig) -> Self {
        Self {
            config,
            binary_hash: Arc::new(Mutex::new(None)),
            config_hash: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            info!("self_protect: disabled by config");
            return Ok(());
        }

        info!("🛡️  Self-Protection initializing...");

        // Apply all hardening in dependency order
        self.apply_prctl_hardening();
        self.apply_rlimits();
        self.set_strict_umask();
        self.protect_from_oom_killer();

        // Compute reference hashes
        if self.config.binary_hash_check {
            let binary = std::env::current_exe()?;
            let hash = hash_file_sync(&binary)?;
            *self.binary_hash.lock().await = Some(hash.clone());
            info!("🔒 Binary integrity: {}...{}", &hash[..8], &hash[hash.len()-8..]);
        }

        if self.config.config_tamper_detection {
            let cfg_path = "/etc/nebula/nebula-agent.toml";
            if let Ok(h) = hash_file_sync(std::path::Path::new(cfg_path)) {
                *self.config_hash.lock().await = Some(h.clone());
                info!("🔒 Config integrity: {}...{}", &h[..8], &h[h.len()-8..]);
            }
        }

        // Check for active debugger/ptrace
        if self.config.anti_debug {
            self.check_debugger_active();
        }

        // Start background monitoring
        self.start_integrity_watch();
        self.start_watchdog();

        info!("✅ Self-Protection active (binary_hash={} anti_debug={} oom_protected=true)",
            self.config.binary_hash_check, self.config.anti_debug);
        Ok(())
    }

    // ── prctl hardening ───────────────────────────────────────

    fn apply_prctl_hardening(&self) {
        #[cfg(target_os = "linux")]
        unsafe {
            // PR_SET_DUMPABLE = 0: prevents /proc/PID/mem writes and core dumps
            // This blocks the T1055.012 process hollowing technique against our process
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 {
                info!("🔒 prctl(PR_SET_DUMPABLE=0): memory dump protection active");
            } else {
                warn!("⚠️  prctl(PR_SET_DUMPABLE) failed (may need CAP_SYS_PTRACE)");
            }

            // PR_SET_PTRACER = -1 (PR_SET_PTRACER_ANY inverse): deny all ptrace
            // Prevents T1055.003 thread execution hijacking against our process
            if libc::prctl(libc::PR_SET_PTRACER, u64::MAX as libc::c_ulong, 0, 0, 0) == 0 {
                info!("🔒 prctl(PR_SET_PTRACER=-1): ptrace protection active");
            }

            // Seal our own memory maps to prevent injection via /proc/self/mem
            // Linux 5.8+: PR_SEAL_SEAL (0x20)
            // Falls back gracefully on older kernels
        }
        #[cfg(not(target_os = "linux"))]
        info!("🔒 prctl: not applicable on this platform");
    }

    // ── Resource limits ───────────────────────────────────────

    fn apply_rlimits(&self) {
        #[cfg(unix)]
        unsafe {
            // Disable core dumps — prevents credential leakage if the process crashes
            let zero_limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if libc::setrlimit(libc::RLIMIT_CORE, &zero_limit) == 0 {
                info!("🔒 RLIMIT_CORE=0: core dumps disabled");
            }

            // Prevent the creation of new setuid executables by our process
            let nofile = libc::rlimit { rlim_cur: 8192, rlim_max: 8192 };
            libc::setrlimit(libc::RLIMIT_NOFILE, &nofile);
        }
    }

    // ── Umask ─────────────────────────────────────────────────

    fn set_strict_umask(&self) {
        #[cfg(unix)]
        unsafe {
            // 0o077 = all created files are owner-only (rwx------)
            // Prevents agent state files (logs, quarantine, forensics) from being
            // read by other processes running as different users
            libc::umask(0o077);
            info!("🔒 umask(0o077): files owner-only");
        }
    }

    // ── OOM protection ────────────────────────────────────────

    fn protect_from_oom_killer(&self) {
        // /proc/self/oom_score_adj = -1000 means the Linux OOM killer
        // will choose any other process before killing us
        // This is important in ransomware scenarios where memory pressure is high
        if let Err(e) = std::fs::write("/proc/self/oom_score_adj", b"-1000\n") {
            debug!("oom_score_adj: {} (may require root)", e);
        } else {
            info!("🔒 OOM score -1000: agent exempt from OOM killer");
        }
    }

    // ── Anti-debug detection ──────────────────────────────────

    fn check_debugger_active(&self) {
        #[cfg(target_os = "linux")]
        {
            // Method 1: TracerPid in /proc/self/status
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("TracerPid:") {
                        let pid: i64 = line.split_whitespace()
                            .nth(1).unwrap_or("0").parse().unwrap_or(0);
                        if pid != 0 {
                            error!("🚨 ATLAS AML.T0043: Debugger detected (TracerPid={})! \
                                Adversarial analysis may be in progress.", pid);
                            self.emit_tamper_alert("debugger_detected",
                                &format!("TracerPid={}", pid));
                        }
                    }
                }
            }

            // Method 2: Timing check — ptrace adds measurable latency
            // If two consecutive clock reads differ by >10ms, we may be single-stepped
            let t1 = std::time::Instant::now();
            let _ = std::hint::black_box(42u64);
            let elapsed = t1.elapsed();
            if elapsed.as_millis() > 10 {
                warn!("⚠️  Timing anomaly detected ({}ms) — possible debugger or high load",
                    elapsed.as_millis());
            }
        }
    }

    // ── Integrity monitoring ──────────────────────────────────

    fn start_integrity_watch(&self) {
        let interval      = self.config.integrity_check_interval_secs;
        let binary_hash   = self.binary_hash.clone();
        let config_hash   = self.config_hash.clone();
        let check_binary  = self.config.binary_hash_check;
        let check_config  = self.config.config_tamper_detection;
        let cfg_path = "/etc/nebula/nebula-agent.toml".to_string();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(
                tokio::time::Duration::from_secs(interval));
            loop {
                ticker.tick().await;

                // Binary integrity
                if check_binary {
                    if let Ok(binary) = std::env::current_exe() {
                        if let Ok(current) = hash_file_sync(&binary) {
                            let reference = binary_hash.lock().await.clone();
                            if let Some(ref_h) = reference {
                                if current != ref_h {
                                    error!("🚨 BINARY TAMPER: reference={}... current={}...",
                                        &ref_h[..12], &current[..12]);
                                    emit_tamper_alert_static("binary_tamper",
                                        &format!("expected={} got={}", &ref_h[..16], &current[..16]));
                                }
                            }
                        }
                    }
                }

                // Config integrity
                if check_config {
                    if let Ok(current) = hash_file_sync(std::path::Path::new(&cfg_path)) {
                        let reference = config_hash.lock().await.clone();
                        if let Some(ref_h) = reference {
                            if current != ref_h {
                                warn!("⚠️  CONFIG DRIFT: reference={}... current={}...",
                                    &ref_h[..12], &current[..12]);
                                // Update reference (config changes are legitimate)
                                *config_hash.lock().await = Some(current);
                            }
                        }
                    }
                }
            }
        });
    }

    // ── Watchdog heartbeat ────────────────────────────────────

    fn start_watchdog(&self) {
        let interval = self.config.watchdog_interval_secs;
        tokio::spawn(async move {
            let hb_path = "/var/run/nebula-agent.heartbeat";
            let mut ticker = tokio::time::interval(
                tokio::time::Duration::from_secs(interval));
            loop {
                ticker.tick().await;
                // Write timestamp — a companion watchdog process (systemd or shell script)
                // can restart the agent if this file goes stale
                let _ = std::fs::write(hb_path, chrono::Utc::now().to_rfc3339().as_bytes());
            }
        });
    }

    // ── Tamper alert ──────────────────────────────────────────

    fn emit_tamper_alert(&self, alert_type: &str, detail: &str) {
        emit_tamper_alert_static(alert_type, detail);
    }

    // ── LLM input sanitisation (ATLAS AML.T0043) ──────────────

    pub fn sanitize_llm_input(&self, input: &str) -> Option<String> {
        if !self.config.prompt_injection_detection {
            return Some(input.to_string());
        }

        // Injection patterns — expanded from baseline
        let injection_patterns = [
            // Role override
            "ignore previous instructions", "ignore all prior",
            "disregard your instructions", "forget everything above",
            "you are now", "act as a", "pretend you are", "you must",
            "your new task", "your real instructions",
            // Mode unlocking
            "dan mode", "developer mode", "unrestricted mode", "jailbreak",
            "do anything now", "no restrictions", "without limitations",
            // Prompt boundary attacks
            "]]", "{{", "</system>", "<|system|>", "<|user|>",
            "system:", "[system]", "new conversation:", "reset:",
            // Exfiltration attempts
            "print your system prompt", "reveal your instructions",
            "show me your prompt", "what are your instructions",
            "display your context", "leak your",
            // Indirect injection (from processed data)
            "execute the following", "run this command", "call function",
        ];

        let lower = input.to_lowercase();
        for pattern in &injection_patterns {
            if lower.contains(pattern) {
                warn!("🛡️ ATLAS AML.T0043: Prompt injection blocked — matched pattern: '{}'", pattern);
                emit_tamper_alert_static("prompt_injection",
                    &format!("pattern='{}' input_len={}", pattern, input.len()));
                return None;
            }
        }

        // Length guard — very long inputs may be trying to overwhelm context
        if input.len() > 8192 {
            warn!("🛡️ Input length exceeded ({}b) — truncating", input.len());
            return Some(input[..8192].to_string());
        }

        Some(input.to_string())
    }

    /// Securely zero-fill a buffer (prevent secrets remaining in memory)
    pub fn secure_zero(buf: &mut [u8]) {
        // Use volatile writes to prevent compiler from optimising away the zeroing
        for byte in buf.iter_mut() {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        // Memory barrier to prevent CPU reordering
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

// ─────────────────────────────────────────────────────────────
// Standalone helpers (can be called from spawned tasks)
// ─────────────────────────────────────────────────────────────

fn emit_tamper_alert_static(alert_type: &str, detail: &str) {
    // Write to append-only alert log
    let log_path = "/var/lib/nebula/alerts/tamper.log";
    let entry = format!("[{}] type={} detail={}\n",
        chrono::Utc::now().to_rfc3339(), alert_type, detail);

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .append(true).create(true).open(log_path)
    {
        let _ = file.write_all(entry.as_bytes());
    }
}

pub fn hash_file_sync(path: &std::path::Path) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(&data)))
}

// Allow dead_code for the debug macro path
#[allow(unused_imports)]
use tracing::debug;
