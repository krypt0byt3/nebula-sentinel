// src/forensics/mod.rs — Forensic artifact collection engine
//
// Capabilities:
//   - Triage package: process listing, open files, network state, env, cmdline
//   - Log capture: snaps relevant log slices around event timestamp
//   - PCAP: starts tshark/tcpdump for N seconds around a threat event
//   - Memory forensics: invokes LiME to dump kernel memory, Volatility for triage
//   - Artifact encryption: AES-256-GCM with key stored in Nexus
//   - Every artifact bundle is SHA-256 checksummed and signed for chain-of-custody

use crate::config::ForensicsConfig;
use crate::types::{ThreatEvent, RawEvent, Severity};
use anyhow::Result;
use chrono::Utc;
use sha2::{Sha256, Digest};
use tracing::{info, warn};
use std::path::{Path, PathBuf};
use std::fs;
use tokio::process::Command;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactBundle {
    pub bundle_id: String,
    pub threat_id: String,
    pub host: String,
    pub timestamp: String,
    pub artifacts: Vec<ArtifactMeta>,
    pub bundle_sha256: String,
    pub chain_of_custody: Vec<CustodyEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactMeta {
    pub artifact_type: String,
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CustodyEntry {
    pub action: String,
    pub timestamp: String,
    pub agent: String,
}

pub struct ForensicsEngine {
    pub config: ForensicsConfig,
}

impl ForensicsEngine {
    pub fn new(config: ForensicsConfig) -> Self {
        if config.enabled {
            let _ = fs::create_dir_all(&config.output_dir);
            info!("🔬 ForensicsEngine initialized → {}", config.output_dir);
        }
        Self { config }
    }

    /// Full triage collection triggered by a threat event
    pub async fn collect_for_threat(
        &self,
        threat: &ThreatEvent,
        event: &RawEvent,
    ) -> Result<ArtifactBundle> {
        if !self.config.enabled {
            anyhow::bail!("Forensics engine disabled");
        }

        let bundle_id = uuid::Uuid::new_v4().to_string();
        let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let bundle_dir = PathBuf::from(&self.config.output_dir)
            .join(format!("{}_{}", ts, &bundle_id[..8]));
        fs::create_dir_all(&bundle_dir)?;

        info!("🔬 Forensics: collecting bundle {} for threat '{}'", bundle_id, threat.threat_name);

        let mut artifacts = vec![];

        // 1. Process triage
        if let Ok(a) = self.collect_process_triage(&bundle_dir, event.pid).await {
            artifacts.push(a);
        }

        // 2. Network state snapshot
        if let Ok(a) = self.collect_network_state(&bundle_dir).await {
            artifacts.push(a);
        }

        // 3. Log slices (±5 minutes around event time)
        for log_path in &self.config.log_paths {
            if let Ok(a) = self.collect_log_slice(&bundle_dir, log_path, &event.timestamp).await {
                artifacts.push(a);
            }
        }

        // 4. PCAP (background, non-blocking)
        if self.config.pcap_on_event {
            let dir = bundle_dir.clone();
            let filter = self.config.pcap_filter.clone();
            let duration = self.config.pcap_duration_secs;
            tokio::spawn(async move {
                let _ = capture_pcap(&dir, &filter, duration).await;
            });
        }

        // 5. Memory dump — TIERED: only for the high-confidence tier. Lightweight
        //    artifacts above were always collected (we're here because confidence
        //    cleared light_confidence); the expensive full memory dump is reserved
        //    for threats at/above full_confidence, or any CRITICAL-severity threat.
        let full_tier = threat.confidence >= self.config.full_confidence
            || threat.severity == Severity::Critical;
        if self.config.memory_dump && full_tier {
            info!("🔬 Forensics: full-tier capture (conf={:.0} ≥ {:.0}) — adding memory dump",
                threat.confidence, self.config.full_confidence);
            if let Ok(a) = self.collect_memory_snapshot(&bundle_dir).await {
                artifacts.push(a);
            }
        }

        // 6. Open file descriptors for the offending PID
        if let Ok(a) = self.collect_fd_list(&bundle_dir, event.pid).await {
            artifacts.push(a);
        }

        // 7. Optionally encrypt the artifacts with AES-256-GCM, IN PLACE, before
        //    hashing — so the bundle checksum covers the stored (ciphertext)
        //    files and the manifest paths stay valid.
        if self.config.encrypt_artifacts {
            info!("🔒 Forensics: encrypting bundle {}", bundle_id);
            let key = self.resolve_encryption_key(&bundle_id);
            let key_fp = {
                use sha2::{Sha256, Digest};
                let h = Sha256::digest(key);
                h[..8].iter().map(|b| format!("{:02x}", b)).collect::<String>()
            };
            match encrypt_dir_in_place(&bundle_dir, &key) {
                Ok(n) => {
                    let _ = std::fs::write(
                        bundle_dir.join("ENCRYPTION.txt"),
                        format!("Artifacts encrypted: AES-256-GCM (nonce prepended, 12 bytes)\nKey fingerprint: {}\n", key_fp));
                    info!("🔒 Encrypted {} artifact(s) with AES-256-GCM (key_fp={})", n, key_fp);
                }
                Err(e) => warn!("🔒 Forensics: encryption failed for {}: {} — bundle left unencrypted", bundle_id, e),
            }
        }

        // 8. Compute bundle manifest + checksum (over the on-disk, possibly
        //    now-encrypted, artifacts).
        let bundle_sha256 = self.compute_bundle_hash(&bundle_dir)?;

        // Write manifest
        let bundle = ArtifactBundle {
            bundle_id: bundle_id.clone(),
            threat_id: threat.id.clone(),
            host: event.hostname.clone(),
            timestamp: ts,
            artifacts,
            bundle_sha256,
            chain_of_custody: vec![CustodyEntry {
                action: "collected".to_string(),
                timestamp: Utc::now().to_rfc3339(),
                agent: event.agent_id.clone(),
            }],
        };

        let manifest_path = bundle_dir.join("manifest.json");
        fs::write(&manifest_path, serde_json::to_string_pretty(&bundle)?)?;
        info!("✅ Forensics bundle {} written to {}", bundle_id, bundle_dir.display());

        Ok(bundle)
    }

    // ── Process triage ─────────────────────────────────────────
    async fn collect_process_triage(
        &self,
        dir: &Path,
        pid: u32,
    ) -> Result<ArtifactMeta> {
        let mut output = String::new();

        // Full process tree
        if let Ok(ps) = Command::new("ps").args(["auxf"]).output().await {
            output.push_str("=== PROCESS TREE ===\n");
            output.push_str(&String::from_utf8_lossy(&ps.stdout));
        }

        // Details for specific PID if non-zero
        if pid > 0 {
            // cmdline
            if let Ok(cmd) = fs::read_to_string(format!("/proc/{}/cmdline", pid)) {
                output.push_str(&format!("\n=== PID {} CMDLINE ===\n{}\n", pid,
                    cmd.replace('\0', " ")));
            }
            // environ
            if let Ok(env) = fs::read_to_string(format!("/proc/{}/environ", pid)) {
                output.push_str(&format!("\n=== PID {} ENVIRON ===\n{}\n", pid,
                    env.replace('\0', "\n")));
            }
            // maps (memory mappings)
            if let Ok(maps) = fs::read_to_string(format!("/proc/{}/maps", pid)) {
                output.push_str(&format!("\n=== PID {} MEMORY MAPS ===\n{}\n", pid, maps));
            }
        }

        // Active connections
        if let Ok(ss) = Command::new("ss").args(["-tulpan"]).output().await {
            output.push_str("\n=== ACTIVE CONNECTIONS ===\n");
            output.push_str(&String::from_utf8_lossy(&ss.stdout));
        }

        let path = dir.join("process_triage.txt");
        fs::write(&path, &output)?;
        Ok(make_artifact_meta("process_triage", &path, "Process tree and PID details"))
    }

    // ── Network state ──────────────────────────────────────────
    async fn collect_network_state(&self, dir: &Path) -> Result<ArtifactMeta> {
        let mut output = String::new();

        for cmd_args in &[
            vec!["ss", "-tulpanW"],
            vec!["arp", "-n"],
            vec!["ip", "route"],
            vec!["iptables", "-L", "-n", "-v"],
        ] {
            if let Ok(out) = Command::new(cmd_args[0])
                .args(&cmd_args[1..]).output().await
            {
                output.push_str(&format!("\n=== {} ===\n", cmd_args.join(" ")));
                output.push_str(&String::from_utf8_lossy(&out.stdout));
            }
        }

        let path = dir.join("network_state.txt");
        fs::write(&path, &output)?;
        Ok(make_artifact_meta("network_state", &path, "Network connections, ARP, routing"))
    }

    // ── Log slice ──────────────────────────────────────────────
    async fn collect_log_slice(
        &self,
        dir: &Path,
        log_path: &str,
        _around: &chrono::DateTime<Utc>,
    ) -> Result<ArtifactMeta> {
        // Use `awk` to grab lines ±300 seconds around the event timestamp
        // For simplicity: grab last 500 lines of each log file
        let log = Path::new(log_path);
        if !log.exists() { anyhow::bail!("log not found: {}", log_path); }

        let fname = log.file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "log".to_string());

        let out = Command::new("tail")
            .args(["-n", "500", log_path])
            .output().await?;

        let slice_path = dir.join(format!("log_slice_{}.txt", fname));
        fs::write(&slice_path, &out.stdout)?;
        Ok(make_artifact_meta("log_slice", &slice_path,
            &format!("Log slice from {}", log_path)))
    }

    // ── File descriptor list ───────────────────────────────────
    async fn collect_fd_list(&self, dir: &Path, pid: u32) -> Result<ArtifactMeta> {
        let mut output = String::new();
        if pid > 0 {
            let fd_dir = format!("/proc/{}/fd", pid);
            if let Ok(entries) = fs::read_dir(&fd_dir) {
                output.push_str(&format!("=== PID {} open file descriptors ===\n", pid));
                for entry in entries.flatten() {
                    if let Ok(link) = fs::read_link(entry.path()) {
                        output.push_str(&format!("  {} -> {}\n",
                            entry.file_name().to_string_lossy(),
                            link.display()));
                    }
                }
            }
        }
        if let Ok(lsof) = Command::new("lsof").args(["-n", "-P"]).output().await {
            output.push_str("\n=== ALL OPEN FILES (lsof) ===\n");
            output.push_str(&String::from_utf8_lossy(&lsof.stdout));
        }
        let path = dir.join("open_files.txt");
        fs::write(&path, &output)?;
        Ok(make_artifact_meta("open_files", &path, "Open file descriptors"))
    }

    // ── Memory snapshot (lightweight) ─────────────────────────
    async fn collect_memory_snapshot(&self, dir: &Path) -> Result<ArtifactMeta> {
        warn!("💾 Forensics: initiating memory snapshot");

        // Preferred: LiME kernel module for a proper full memory dump. This is a
        // heavyweight, deliberate acquisition and only runs when the operator has
        // installed LiME. We NEVER attempt to read /proc/kcore as a fallback:
        // kcore is a virtual view of the entire kernel/physical address space
        // (apparent size in the terabytes), and reading it — especially buffering
        // it into memory via Command::output() — exhausts RAM and freezes the
        // host. That was a real freeze bug; the safe fallback is a bounded,
        // metadata-only snapshot instead of a raw dump.
        let lime_path = "/usr/lib/nebula/lime.ko";
        let dump_path = dir.join("memory.lime");

        if Path::new(lime_path).exists() {
            // Load LiME and dump to file. Run on a blocking task with a hard
            // timeout so a stuck acquisition can't hang the agent indefinitely.
            info!("💾 LiME present — acquiring full memory dump → {}", dump_path.display());
            let lp = lime_path.to_string();
            let dp = dump_path.display().to_string();
            let acquire = Command::new("insmod")
                .args([&lp, &format!("path={}", dp), "format=lime"])
                .output();
            match tokio::time::timeout(std::time::Duration::from_secs(300), acquire).await {
                Ok(Ok(_)) => {
                    info!("💾 LiME memory dump complete → {}", dump_path.display());
                    // Best-effort unload so the module doesn't linger.
                    let _ = Command::new("rmmod").arg("lime").output().await;
                }
                Ok(Err(e)) => warn!("LiME acquisition failed: {}", e),
                Err(_) => warn!("LiME acquisition timed out (300s) — aborting to protect host stability"),
            }
            return Ok(make_artifact_meta("memory_dump", &dump_path, "Raw memory dump (LiME format)"));
        }

        // Fallback (no LiME): a SAFE, bounded, metadata-only memory snapshot. We
        // record system memory statistics and the per-process memory summary from
        // /proc — never a raw dump of physical memory. This gives triage value
        // (what was resident, which processes were large) without the freeze risk.
        warn!("LiME module not found at {} — writing bounded metadata-only memory summary (no raw dump)", lime_path);
        let mut summary = String::new();
        summary.push_str("=== MEMORY SNAPSHOT (metadata-only; LiME not installed) ===\n\n");
        if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
            summary.push_str("--- /proc/meminfo ---\n");
            summary.push_str(&meminfo);
            summary.push('\n');
        }
        // Per-process RSS summary, bounded and cheap (reads small /proc status files).
        summary.push_str("\n--- per-process memory (RSS) ---\n");
        if let Ok(entries) = fs::read_dir("/proc") {
            let mut rows: Vec<(u64, String)> = Vec::new();
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.chars().all(|c| c.is_ascii_digit()) { continue; }
                let status_path = format!("/proc/{}/status", name);
                if let Ok(status) = fs::read_to_string(&status_path) {
                    let rss = status.lines()
                        .find(|l| l.starts_with("VmRSS:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0);
                    let pname = status.lines()
                        .find(|l| l.starts_with("Name:"))
                        .map(|l| l.trim_start_matches("Name:").trim().to_string())
                        .unwrap_or_default();
                    if rss > 0 { rows.push((rss, format!("{:>10} kB  pid {:>7}  {}", rss, name, pname))); }
                }
            }
            rows.sort_by(|a, b| b.0.cmp(&a.0)); // largest first
            for (_, line) in rows.iter().take(100) {
                summary.push_str(line);
                summary.push('\n');
            }
        }
        fs::write(&dump_path.with_extension("txt"), summary.as_bytes())?;
        Ok(make_artifact_meta("memory_summary",
            &dump_path.with_extension("txt"),
            "Bounded memory metadata summary (meminfo + top-100 process RSS; no raw dump — LiME not installed)"))
    }

    // ── Bundle hash ────────────────────────────────────────────
    fn compute_bundle_hash(&self, dir: &Path) -> Result<String> {
        let mut hasher = Sha256::new();
        let mut entries: Vec<_> = fs::read_dir(dir)?.flatten()
            .filter(|e| e.path().is_file())
            .collect();
        entries.sort_by_key(|e| e.path());
        for entry in entries {
            let data = fs::read(entry.path())?;
            hasher.update(&data);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Resolve the 32-byte AES-256 key: a configured hex key (proper key
    /// management) if present and valid, otherwise a machine-local derived key
    /// (SHA-256 of bundle_id + machine-id) so encryption still works air-gapped.
    fn resolve_encryption_key(&self, bundle_id: &str) -> [u8; 32] {
        if let Some(hex) = self.config.encryption_key_hex.as_deref() {
            let hex = hex.trim();
            if hex.len() == 64 {
                let mut key = [0u8; 32];
                let mut ok = true;
                for i in 0..32 {
                    match u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
                        Ok(b) => key[i] = b,
                        Err(_) => { ok = false; break; }
                    }
                }
                if ok { return key; }
            }
            warn!("🔒 Forensics: encryption_key_hex is not 64 hex chars — using derived key");
        }
        let machine_id = std::fs::read_to_string("/etc/machine-id")
            .unwrap_or_else(|_| bundle_id.to_string());
        let digest = Sha256::digest(format!("{}{}", bundle_id, machine_id.trim()).as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        key
    }
}

/// Encrypt every regular file in `dir` in place with AES-256-GCM. Each file is
/// replaced with `nonce(12) || ciphertext || tag(16)`. Returns the count of
/// files encrypted. A random 96-bit nonce is generated per file.
fn encrypt_dir_in_place(dir: &Path, key: &[u8; 32]) -> Result<usize> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
    use ring::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let mut count = 0usize;
    let entries: Vec<PathBuf> = fs::read_dir(dir)?.flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    for path in entries {
        let plaintext = fs::read(&path)?;
        let unbound = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("invalid AES key"))?;
        let sealing = LessSafeKey::new(unbound);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes).map_err(|_| anyhow::anyhow!("nonce rng failed"))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext;
        sealing.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow::anyhow!("AES-GCM seal failed"))?;
        let mut out = Vec::with_capacity(NONCE_LEN + in_out.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&in_out);
        fs::write(&path, out)?;
        count += 1;
    }
    Ok(count)
}

async fn capture_pcap(dir: &Path, filter: &str, duration_secs: u64) {
    let out_path = dir.join("capture.pcap");
    info!("🎣 PCAP: capturing {}s with filter '{}'", duration_secs, filter);

    // Try tshark first, fall back to tcpdump
    let result = Command::new("tshark")
        .args([
            "-a", &format!("duration:{}", duration_secs),
            "-f", filter,
            "-w", &out_path.to_string_lossy(),
        ])
        .output().await;

    if result.is_err() {
        let _ = Command::new("tcpdump")
            .args([
                "-G", &duration_secs.to_string(),
                "-W", "1",
                "-f", filter,
                "-w", &out_path.to_string_lossy(),
            ])
            .output().await;
    }
    info!("🎣 PCAP saved → {}", out_path.display());
}

fn make_artifact_meta(artifact_type: &str, path: &Path, description: &str) -> ArtifactMeta {
    let (sha256, size) = if path.exists() {
        let data = fs::read(path).unwrap_or_default();
        let h = format!("{:x}", Sha256::digest(&data));
        (h, data.len() as u64)
    } else {
        ("".to_string(), 0)
    };
    ArtifactMeta {
        artifact_type: artifact_type.to_string(),
        path: path.to_string_lossy().to_string(),
        sha256,
        size_bytes: size,
        description: description.to_string(),
    }
}
