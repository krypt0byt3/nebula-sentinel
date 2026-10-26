#![allow(dead_code)]
// src/nexus_client.rs — Nexus communication with offline queue + geo detection

use crate::config::NexusConfig;
use crate::types::{ThreatEvent, PostureReport, NexusCommand, DetectionRule};
use crate::offline_queue::OfflineQueue;
use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;

#[derive(Serialize)]
struct AgentRegistration {
    agent_id:     String,
    hostname:     String,
    version:      &'static str,
    mode:         String,
    platform:     String,
    kernel:       String,
    ip_addresses: Option<String>,
    /// Hex-encoded ed25519 public key for GOSSIP envelope verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    gossip_pubkey: Option<String>,
}

#[derive(Serialize)]
struct ATCEvent<T> {
    agent_id:   String,
    event_type: &'static str,
    payload:    T,
}

#[derive(Deserialize)]
struct NexusResponse {
    #[allow(dead_code)]
    status: String,
    #[serde(default)]
    commands: Vec<NexusCommand>,
    #[serde(default)]
    new_rules: Vec<serde_json::Value>,
    #[serde(default)]
    peers: Vec<PeerEntry>,
    #[serde(default)]
    malware_hashes: Vec<(String, String)>,
    #[serde(default)]
    ransom_extensions: Vec<String>,
    #[serde(default)]
    ransom_note_names: Vec<String>,
}

#[derive(Deserialize, Clone)]
pub struct PeerEntry {
    pub agent_id:    String,
    pub hostname:    String,
    pub gossip_addr: String,
}

pub struct NexusClient {
    config:    NexusConfig,
    agent_id:  String,
    client:    Client,
    // Offline queue — persists events when Nexus is unreachable
    queue:     Arc<OfflineQueue>,
    // Track connectivity state so we know when to attempt a drain
    connected: Arc<Mutex<bool>>,
    // Current location — updated on each successful heartbeat
    pub current_location: Arc<Mutex<Option<String>>>,
}

impl NexusClient {
    pub fn new(config: NexusConfig, agent_id: &str) -> Result<Self> {
        // Shared TLS policy (cert pinning when ca_cert_path is set; see tls.rs).
        let builder = crate::tls::nexus_http_builder(config.ca_cert_path.as_deref(), config.tls_verify)
            .timeout(Duration::from_secs(15))
            .user_agent("NebulaSentinel-Agent/0.4.0");

        let queue = Arc::new(OfflineQueue::new(None, None)?);
        // Note: len() is async, skip this at construction — queue reports on first drain

        info!("🌐 NexusClient: target={}", config.url);
        Ok(Self {
            client:           builder.build()?,
            config,
            agent_id:         agent_id.to_string(),
            queue,
            connected:        Arc::new(Mutex::new(false)),
            current_location: Arc::new(Mutex::new(None)),
        })
    }

    // ── Registration ──────────────────────────────────────────
    pub async fn register(&self, hostname: &str, mode: &str, gossip_pubkey: Option<String>) -> Result<()> {
        let ip = detect_local_ips();
        let reg = AgentRegistration {
            agent_id:     self.agent_id.clone(),
            hostname:     hostname.to_string(),
            version:      env!("CARGO_PKG_VERSION"),
            mode:         mode.to_string(),
            platform:     concat!(env!("NEBULA_TARGET_OS"), "-", env!("NEBULA_TARGET_ARCH")).to_string(),
            kernel:       get_kernel_version(),
            ip_addresses: Some(ip),
            gossip_pubkey,
        };
        match self.post("/api/agents/register", &reg).await {
            Ok(_)  => {
                *self.connected.lock().await = true;
                info!("✅ Registered with Nexus");
            }
            Err(e) => warn!("⚠️ Registration failed: {} (will retry)", e),
        }
        Ok(())
    }

    // ── Send threat (queue-first when buffering enabled) ──────
    pub async fn send_threat(&self, threat: &ThreatEvent) -> Result<()> {
        let envelope = ATCEvent {
            agent_id:   self.agent_id.clone(),
            event_type: "threat",
            payload:    threat,
        };
        let json = serde_json::to_string(&envelope)?;
        let location = self.current_location.lock().await.clone();

        // Queue-first mode: always buffer locally; the flush loop delivers it.
        // This guarantees the event survives a hung send or an agent restart.
        if self.config.buffer_events_locally {
            self.queue.push("threat", &json, location.as_deref()).await?;
            debug!("📥 Threat '{}' buffered locally", threat.threat_name);
            return Ok(());
        }

        match self.post("/api/atc/events", &envelope).await {
            Ok(_) => {
                info!("📤 Threat '{}' → Nexus", threat.threat_name);
                *self.connected.lock().await = true;
                Ok(())
            }
            Err(e) => {
                warn!("📦 Nexus unreachable — queueing threat '{}': {}", threat.threat_name, e);
                *self.connected.lock().await = false;
                self.queue.push("threat", &json, location.as_deref()).await?;
                Ok(())
            }
        }
    }

    // ── Send posture (queue-first when buffering enabled) ─────
    pub async fn send_posture(&self, report: &PostureReport) -> Result<()> {
        let json = serde_json::to_string(report)?;
        let location = self.current_location.lock().await.clone();

        if self.config.buffer_events_locally {
            self.queue.push("posture", &json, location.as_deref()).await?;
            debug!("📥 Posture report buffered locally");
            return Ok(());
        }

        match self.post("/api/atc/posture", report).await {
            Ok(_) => { *self.connected.lock().await = true; Ok(()) }
            Err(e) => {
                warn!("📦 Queueing posture report: {}", e);
                *self.connected.lock().await = false;
                self.queue.push("posture", &json, location.as_deref()).await?;
                Ok(())
            }
        }
    }

    /// Accessor for the agent's ID (used when building outbound manifests).
    pub fn agent_id(&self) -> String { self.agent_id.clone() }

    // ── Send a forensic bundle manifest (metadata only; bytes stay local) ──
    pub async fn send_forensic_manifest(&self, manifest: &serde_json::Value) -> Result<()> {
        match self.post("/api/atc/forensics/manifest", manifest).await {
            Ok(_) => { info!("🔬 Forensic manifest → Nexus"); Ok(()) }
            Err(e) => { warn!("Failed to send forensic manifest: {}", e); Err(e) }
        }
    }

    // ── Report a one-shot retro hunt's result so the Nexus marks it finished ──
    pub async fn report_retro_hunt(&self, hunt_id: &str, status: &str,
        matches: &[crate::retro::RetroMatch], sources: usize, hostname: &str,
        rule_name: &str) -> Result<()> {
        if hunt_id.is_empty() { return Ok(()); }
        // Send the actual match rows (source/line/content/timestamp), not just a
        // count — this is what populates the Nexus hunt-detail timeline. Cap the
        // payload so a noisy hunt can't produce an oversized request.
        let match_json: Vec<serde_json::Value> = matches.iter().take(2000).map(|m| serde_json::json!({
            "source_file":      m.source_file,
            "line_number":      m.line_number,
            "line_content":     m.line_content,
            "rule_name":        m.rule_name,
            "timestamp_approx": m.timestamp_approx.map(|t| t.to_rfc3339()),
        })).collect();
        let body = serde_json::json!({
            "agent_id": self.agent_id,
            "hostname": hostname,
            "hunt_id": hunt_id,
            "rule_name": rule_name,
            "status": status,
            "match_count": matches.len(),
            "sources_scanned": sources,
            "matches": match_json,
        });
        match self.post("/api/atc/retro/report", &body).await {
            Ok(_) => Ok(()),
            Err(e) => { warn!("Failed to report retro hunt completion: {}", e); Err(e) }
        }
    }

    // ── Report incremental progress of a long-running job (hunt, FIM, scan) ──
    // Generic so any long operation can drive a percent + phase. `progress` is
    // 0–100; `phase` is a short human label ("scanning files", "hashing", …).
    // Best-effort: failures are swallowed so progress never breaks the job.
    pub async fn report_progress(&self, job_kind: &str, job_id: &str, progress: u8, phase: &str, detail: &str) {
        if job_id.is_empty() { return; }
        let body = serde_json::json!({
            "agent_id": self.agent_id,
            "job_kind": job_kind,        // "retro" | "fim" | "scan" | …
            "job_id":   job_id,
            "progress": progress.min(100),
            "phase":    phase,
            "detail":   detail,
        });
        let _ = self.post("/api/atc/progress", &body).await;
    }

    // ── Upload one artifact's bytes (base64) in response to a fetch command ──
    pub async fn upload_forensic_artifact(&self, artifact_id: i64, path: &str) -> Result<()> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        // Bound the read to 64MB to avoid memory blowups on huge dumps.
        let meta = std::fs::metadata(path)?;
        if meta.len() > 64 * 1024 * 1024 {
            anyhow::bail!("artifact {} too large to upload ({} bytes)", path, meta.len());
        }
        let bytes = std::fs::read(path)?;
        let b64 = STANDARD.encode(&bytes);
        let body = serde_json::json!({
            "agent_id": self.agent_id,
            "artifact_id": artifact_id,
            "content_base64": b64,
        });
        self.post("/api/atc/forensics/artifact", &body).await?;
        info!("🔬 Uploaded forensic artifact {} ({} bytes) → Nexus", artifact_id, bytes.len());
        Ok(())
    }

    // ── Capture a file sample and upload it for analysis ──
    // `target` is either an absolute file path or a SHA-256 to locate. We resolve
    // to a readable file, hash it, and upload base64 bytes + metadata. Bounded to
    // 64MB. Reuses a dedicated samples endpoint so it's tracked separately from
    // forensic bundles.
    pub async fn upload_sample(&self, sample_id: &str, target: &str) -> Result<()> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use sha2::{Sha256, Digest};
        // Resolve the file: if target is an absolute path, use it directly.
        let path = if target.starts_with('/') && std::path::Path::new(target).is_file() {
            target.to_string()
        } else if target.len() == 64 && target.chars().all(|c| c.is_ascii_hexdigit()) {
            // SHA-256: search a bounded set of common roots for a matching file.
            match Self::find_file_by_hash(target) {
                Some(p) => p,
                None => anyhow::bail!("no file matching hash {} found in scanned roots", target),
            }
        } else {
            anyhow::bail!("target must be an absolute path or a SHA-256 hash");
        };
        let meta = std::fs::metadata(&path)?;
        if meta.len() > 64 * 1024 * 1024 {
            anyhow::bail!("sample {} too large ({} bytes)", path, meta.len());
        }
        let bytes = std::fs::read(&path)?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let b64 = STANDARD.encode(&bytes);
        let body = serde_json::json!({
            "agent_id":  self.agent_id,
            "sample_id": sample_id,
            "path":      path,
            "sha256":    sha256,
            "size":      bytes.len(),
            "content_base64": b64,
        });
        self.post("/api/atc/gossip/sample", &body).await?;
        info!("🧪 Uploaded sample {} ({} bytes) → Nexus", sample_id, bytes.len());
        Ok(())
    }

    // Locate a file matching a SHA-256 by scanning bounded common roots. Capped
    // to keep this from becoming a full-disk walk on every request.
    fn find_file_by_hash(hash: &str) -> Option<String> {
        use sha2::{Sha256, Digest};
        let roots = ["/tmp", "/var/tmp", "/dev/shm", "/home"];
        let mut scanned = 0usize;
        for root in roots {
            for entry in walkdir_bounded(root, &mut scanned, 20000) {
                if let Ok(bytes) = std::fs::read(&entry) {
                    if bytes.len() > 64 * 1024 * 1024 { continue; }
                    let h = format!("{:x}", Sha256::digest(&bytes));
                    if h.eq_ignore_ascii_case(hash) { return Some(entry); }
                }
            }
        }
        None
    }

    // ── Submit rule for approval (queue-first when buffering) ──
    pub async fn submit_rule_for_approval(&self, rule: &DetectionRule) -> Result<()> {
        let envelope = ATCEvent {
            agent_id:   self.agent_id.clone(),
            event_type: "rule_proposal",
            payload:    rule,
        };
        let json = serde_json::to_string(&envelope)?;
        let location = self.current_location.lock().await.clone();

        if self.config.buffer_events_locally {
            self.queue.push("rule_proposal", &json, location.as_deref()).await?;
            return Ok(());
        }

        match self.post("/api/atc/rules/propose", &envelope).await {
            Ok(_) => Ok(()),
            Err(_e) => {
                self.queue.push("rule_proposal", &json, location.as_deref()).await?;
                Ok(())
            }
        }
    }

    /// Public flush — drains the local event buffer to Nexus. Called on the
    /// flush-interval timer and after a successful heartbeat. Safe to call
    /// often; it no-ops when the queue is empty.
    pub async fn flush_events(&self) {
        self.drain_queue().await;
    }

    // ── Poll + heartbeat ──────────────────────────────────────
    pub async fn poll_commands(&self) -> Result<NexusPoll> {
        let url = format!("{}/api/atc/poll/{}", self.config.url, self.agent_id);
        let resp = self.client.get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send().await?;

        if !resp.status().is_success() {
            anyhow::bail!("poll returned {}", resp.status());
        }

        let nr: NexusResponse = resp.json().await?;
        let new_rules = nr.new_rules.iter().filter_map(rule_from_json).collect();
        Ok(NexusPoll { commands: nr.commands, new_rules, peers: nr.peers, malware_hashes: nr.malware_hashes, ransom_extensions: nr.ransom_extensions, ransom_note_names: nr.ransom_note_names })
    }

    /// Pull the converted OVAL JSON for `feed` (e.g. "debian_12") from Nexus and
    /// write it into `oval_dir` as `<feed>.json`, so the posture engine's
    /// check_oval (which reads .json files from that dir) picks it up. This is
    /// what makes OVAL work end-to-end without manually placing feed files:
    /// Nexus converts the distro XML once, agents sync the compact JSON.
    /// Returns the number of definitions written (0 if the feed is empty/absent).
    pub async fn sync_oval_feed(&self, feed: &str, oval_dir: &str) -> Result<usize> {
        let url = format!("{}/api/oval/feed/{}", self.config.url, feed);
        let resp = self.client.get(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("OVAL feed sync returned {}", resp.status());
        }
        let body = resp.text().await?;
        // Validate it parses as the expected shape before writing (don't overwrite
        // a good local feed with garbage / an empty "[]").
        let count = match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(serde_json::Value::Array(a)) => a.len(),
            _ => 0,
        };
        if count == 0 {
            return Ok(0); // nothing to write; leave any existing feed in place
        }
        std::fs::create_dir_all(oval_dir).ok();
        let path = std::path::Path::new(oval_dir).join(format!("{}.json", feed));
        std::fs::write(&path, body.as_bytes())?;
        Ok(count)
    }

    /// Heartbeat — also triggers queue drain and geo update on success.
    pub async fn heartbeat(&self) -> Result<()> {
        let url = format!("{}/api/atc/heartbeat/{}", self.config.url, self.agent_id);
        match self.client.post(&url)
            .header("X-Api-Key", &self.config.api_key)
            .send().await
        {
            Ok(resp) if resp.status().is_success() => {
                let was_offline = !*self.connected.lock().await;
                *self.connected.lock().await = true;

                if was_offline {
                    info!("✅ Nexus connectivity restored — draining offline queue");
                    self.drain_queue().await;
                }
                Ok(())
            }
            Ok(resp) => anyhow::bail!("heartbeat returned {}", resp.status()),
            Err(e) => {
                *self.connected.lock().await = false;
                let pending = self.queue.len().await;
                // Offline — log queue depth
                warn!("💤 Offline — {} events queued locally", pending);
                Err(e.into())
            }
        }
    }

    /// Drain the offline queue to Nexus.
    async fn drain_queue(&self) {
        let pending = self.queue.len().await;
        if pending == 0 { return; }

        info!("📦 Draining {} offline-queued events...", pending);
        let client  = self.client.clone();
        let url     = self.config.url.clone();
        let api_key = self.config.api_key.clone();
        let queue   = self.queue.clone();

        tokio::spawn(async move {
            queue.drain(|event_type, payload| {
                let client  = client.clone();
                let url     = url.clone();
                let api_key = api_key.clone();
                async move {
                    let endpoint = match event_type.as_str() {
                        "threat"        => "/api/atc/events",
                        "posture"       => "/api/atc/posture",
                        "rule_proposal" => "/api/atc/rules/propose",
                        _               => "/api/atc/events",
                    };
                    let resp = client.post(format!("{}{}", url, endpoint))
                        .header("X-Api-Key", &api_key)
                        .header("Content-Type", "application/json")
                        .body(payload)
                        .send().await?;
                    if resp.status().is_success() {
                        Ok(())
                    } else {
                        anyhow::bail!("drain send failed: {}", resp.status())
                    }
                }
            }).await;
        });
    }

    // ── Legacy syslog ─────────────────────────────────────────
    // NOTE: syslog forwarding is handled by `legacy::LegacyBridge` (full
    // CEF/LEEF/RFC5424 formatting + UDP/TCP delivery), which every detection is
    // routed through in the main loop. A former `send_syslog` stub here was dead,
    // caller-less, and duplicated that path, so it was removed.

    pub fn is_connected(&self) -> bool {
        self.connected.try_lock().map(|c| *c).unwrap_or(false)
    }

    async fn post<T: serde::Serialize>(&self, path: &str, body: &T) -> Result<String> {
        let url  = format!("{}{}", self.config.url, path);
        let resp = self.client.post(&url)
            .header("X-Api-Key", &self.config.api_key)
            .json(body).send().await?;
        let status = resp.status();
        let text   = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("Nexus {} → {}: {}", path, status, &text[..text.len().min(200)]);
        }
        Ok(text)
    }
}

pub struct NexusPoll {
    pub commands:  Vec<NexusCommand>,
    pub new_rules: Vec<DetectionRule>,
    pub peers:     Vec<PeerEntry>,
    /// Known-malicious file hashes (sha256, description) from the Nexus intel
    /// feed, pushed to populate the agent's local reputation blocklist.
    pub malware_hashes: Vec<(String, String)>,
    /// Known ransomware file extensions and ransom-note filenames from the Nexus
    /// intel feed — distributed so the ransomware detector learns new families
    /// fleet-wide without a rebuild.
    pub ransom_extensions: Vec<String>,
    pub ransom_note_names: Vec<String>,
}

/// Convert a Nexus rule JSON object into a DetectionRule, filling defaults
/// for any fields the Nexus doesn't send. Returns None if it can't be mapped.
fn rule_from_json(v: &serde_json::Value) -> Option<DetectionRule> {
    use crate::types::{RuleType, Severity};
    let rule_type = match v["rule_type"].as_str().unwrap_or("custom") {
        "yara" => RuleType::Yara, "sigma" => RuleType::Sigma,
        "wazuh" => RuleType::Wazuh, _ => RuleType::Custom,
    };
    let severity = match v["severity"].as_str().unwrap_or("medium").to_lowercase().as_str() {
        "critical" => Severity::Critical, "high" => Severity::High,
        "low" => Severity::Low, "info" | "informational" => Severity::Info,
        _ => Severity::Medium,
    };
    Some(DetectionRule {
        id:        v["id"].as_str()?.to_string(),
        rule_type,
        name:      v["name"].as_str().unwrap_or("Unnamed Rule").to_string(),
        severity,
        content:   v["content"].as_str().unwrap_or("").to_string(),
        generated_from_event: v["generated_from"].as_str().unwrap_or("").to_string(),
        generated_at: chrono::Utc::now(),
        approved:  v["approved"].as_bool().unwrap_or(false),
        deployed_to: Vec::new(),
        llm_reasoning: v["llm_reasoning"].as_str().unwrap_or("").to_string(),
    })
}

fn get_kernel_version() -> String {
    // Cross-platform: sysinfo reports the kernel/build version on every OS
    // (Linux kernel release, Windows build number, Darwin version). The previous
    // implementation read /proc/version, which only exists on Linux and returned
    // "unknown" on Windows/macOS.
    sysinfo::System::kernel_version()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            // Fallback to the Linux /proc source if sysinfo yields nothing.
            std::fs::read_to_string("/proc/version").ok()
                .and_then(|s| s.split_whitespace().nth(2).map(String::from))
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Collect all non-loopback IP addresses from this host.
fn detect_local_ips() -> String {
    // Cross-platform interface IP enumeration via sysinfo::Networks. This works
    // identically on Windows, Linux, and macOS. (The previous implementation
    // shelled out to `hostname -I`, a GNU coreutils flag that does not exist on
    // Windows or macOS, so those platforms reported no IP at all.)
    use sysinfo::Networks;
    let mut ips: Vec<String> = Vec::new();
    let networks = Networks::new_with_refreshed_list();
    for (iface_name, data) in &networks {
        // Skip the loopback interface (named "lo" on Linux/macOS; on Windows the
        // loopback addresses are filtered by the 127./::1 checks below anyway).
        if iface_name == "lo" { continue; }
        for addr in data.ip_networks() {
            let s = addr.addr.to_string();
            if s.starts_with("127.") || s == "::1" || s.starts_with("fe80") {
                continue; // loopback and link-local
            }
            if !ips.contains(&s) { ips.push(s); }
        }
    }
    ips.join(",")
}

// Bounded recursive file walk: returns file paths under `root`, incrementing
// `scanned` and stopping once `cap` files have been visited (across the whole
// search). Skips symlinks to avoid loops. Pure std — no walkdir dependency.
fn walkdir_bounded(root: &str, scanned: &mut usize, cap: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(root)];
    while let Some(dir) = stack.pop() {
        if *scanned >= cap { break; }
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            if *scanned >= cap { break; }
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() { continue; }
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                *scanned += 1;
                out.push(path.to_string_lossy().to_string());
            }
        }
    }
    out
}
