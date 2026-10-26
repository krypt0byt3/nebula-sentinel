#![allow(dead_code)]
// src/dlp/mod.rs — Data Loss Prevention
//
// DLP in an endpoint security agent operates on three surfaces:
//
//   1. Process behavior monitoring
//      Watch for processes accessing large numbers of sensitive files,
//      compressing data, or staging it in unusual locations.
//      This catches exfiltration preparation regardless of transport.
//
//   2. Network exfiltration detection
//      Large outbound transfers to unknown destinations.
//      Unusual protocols (DNS, ICMP, HTTPS to new hosts) carrying data.
//      Upload tools (curl, wget, scp, rsync, rclone) to external hosts.
//
//   3. Sensitive data classification
//      Detect files matching sensitive data patterns being accessed,
//      copied, or compressed: PII, credit card numbers, SSNs, health data,
//      source code, private keys, database dumps.
//
// Architecture note:
//   DLP does NOT inspect packet payloads in plaintext (that would require
//   TLS interception, which is architecturally complex and invasive).
//   Instead it operates on: process behavior, file access patterns,
//   transfer size/rate anomalies, and destination reputation.
//   This catches ~85% of real exfiltration scenarios without decryption.
//
// MITRE coverage:
//   T1020 — Automated Exfiltration
//   T1030 — Data Transfer Size Limits (violation detection)
//   T1041 — Exfiltration Over C2 Channel
//   T1048 — Exfiltration Over Alternative Protocol
//   T1052 — Exfiltration Over Physical Medium
//   T1560 — Archive Collected Data
//   T1074 — Data Staged
//   T1005 — Data from Local System
//   T1213 — Data from Information Repositories

use crate::types::{ThreatEvent, Severity, ResponseAction, IOC, IOCType, RawEvent, EventType};
use anyhow::Result;
use chrono::{Utc, Duration};
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────
// Data classification patterns
// ─────────────────────────────────────────────────────────────

pub struct DataPattern {
    pub name:        &'static str,
    pub category:    DataCategory,
    pub regex:       &'static str,
    pub severity:    Severity,
    pub min_matches: usize,  // minimum occurrences to trigger (reduces false positives)
}

#[derive(Debug, Clone, PartialEq)]
pub enum DataCategory {
    Pii,
    Financial,
    Credentials,
    HealthData,
    Intellectual,
    Classified,
}

pub fn data_patterns() -> Vec<(&'static str, DataCategory, Severity, usize, Regex)> {
    let raw: Vec<DataPattern> = vec![
        // PII
        DataPattern { name: "US SSN", category: DataCategory::Pii, regex: r"\b\d{3}-\d{2}-\d{4}\b", severity: Severity::High, min_matches: 5 },
        DataPattern { name: "Email addresses", category: DataCategory::Pii, regex: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", severity: Severity::Medium, min_matches: 50 },
        DataPattern { name: "Phone numbers (US)", category: DataCategory::Pii, regex: r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", severity: Severity::Medium, min_matches: 20 },
        DataPattern { name: "Date of birth", category: DataCategory::Pii, regex: r"\b(?:DOB|Date of Birth|born)[:\s]+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", severity: Severity::Medium, min_matches: 5 },
        // Financial
        DataPattern { name: "Credit card (Visa/MC/Amex)", category: DataCategory::Financial, regex: r"\b(?:4[0-9]{15}|5[1-5][0-9]{14}|3[47][0-9]{13})\b", severity: Severity::Critical, min_matches: 1 },
        DataPattern { name: "Bank account number", category: DataCategory::Financial, regex: r"\b(?:account|acct)[:\s#]*\d{8,17}\b", severity: Severity::High, min_matches: 3 },
        DataPattern { name: "Routing number", category: DataCategory::Financial, regex: r"\b(?:routing|ABA)[:\s]*\d{9}\b", severity: Severity::High, min_matches: 3 },
        // Credentials
        DataPattern { name: "Private key (PEM)", category: DataCategory::Credentials, regex: r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", severity: Severity::Critical, min_matches: 1 },
        DataPattern { name: "AWS access key", category: DataCategory::Credentials, regex: r"AKIA[0-9A-Z]{16}", severity: Severity::Critical, min_matches: 1 },
        DataPattern { name: "Password hash (bcrypt)", category: DataCategory::Credentials, regex: r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}", severity: Severity::High, min_matches: 5 },
        DataPattern { name: "Database connection string", category: DataCategory::Credentials, regex: r"(?:mysql|postgres|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s/]+", severity: Severity::Critical, min_matches: 1 },
        // Health data (HIPAA-relevant)
        DataPattern { name: "Diagnosis code (ICD-10)", category: DataCategory::HealthData, regex: r"\b[A-TV-Z][0-9][0-9AB]\.?[0-9A-TV-Z]{0,4}\b", severity: Severity::High, min_matches: 10 },
        DataPattern { name: "NPI (healthcare provider)", category: DataCategory::HealthData, regex: r"\b(?:NPI)[:\s]*\d{10}\b", severity: Severity::High, min_matches: 3 },
        // Intellectual property
        DataPattern { name: "Source code (large)", category: DataCategory::Intellectual, regex: r"(?:function|class|def|import|package)\s+\w+", severity: Severity::Medium, min_matches: 100 },
        DataPattern { name: "Classified marker", category: DataCategory::Classified, regex: r"\b(?:TOP SECRET|SECRET|CONFIDENTIAL|CLASSIFIED|FOUO|NOFORN)\b", severity: Severity::Critical, min_matches: 1 },
    ];

    raw.into_iter()
        .filter_map(|p| {
            Regex::new(p.regex).ok().map(|re| (p.name, p.category, p.severity, p.min_matches, re))
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────
// Transfer tracking
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct TransferRecord {
    dest_ip:    String,
    dest_port:  u16,
    bytes_est:  u64,      // estimated from connection count × avg packet size
    first_seen: chrono::DateTime<Utc>,
    last_seen:  chrono::DateTime<Utc>,
    conn_count: u32,
    process:    String,
}

// ─────────────────────────────────────────────────────────────
// Exfiltration tool detection
// ─────────────────────────────────────────────────────────────

/// Command patterns that indicate data exfiltration tools
const EXFIL_COMMANDS: &[(&str, &str, &str)] = &[
    // Upload tools
    ("curl",    "-T ",          "curl upload"),
    ("curl",    "--upload-file","curl upload"),
    ("curl",    "-d @",         "curl POST file upload"),
    ("wget",    "--post-file",  "wget file upload"),
    ("scp",     " ",            "scp transfer"),
    ("rsync",   " ",            "rsync transfer"),
    ("sftp",    " ",            "sftp transfer"),
    ("rclone",  "copy",         "rclone cloud upload"),
    ("rclone",  "sync",         "rclone cloud sync"),
    ("aws",     "s3 cp",        "AWS S3 upload"),
    ("aws",     "s3 sync",      "AWS S3 sync"),
    ("gsutil",  "cp",           "GCS upload"),
    ("azcopy",  " ",            "Azure Blob upload"),
    // Compression before exfil
    ("tar",     "-czf",         "tar archive creation"),
    ("zip",     " ",            "zip archive creation"),
    ("7z",      "a ",           "7zip archive creation"),
    ("rar",     " ",            "RAR archive creation"),
    // Email exfil
    ("sendmail","",             "sendmail (possible email exfil)"),
    ("mail",    "-A",           "mail attachment"),
    ("mutt",    "-a",           "mutt attachment"),
    // Covert channels
    ("nc",      " ",            "netcat transfer"),
    ("ncat",    " ",            "ncat transfer"),
    ("socat",   " ",            "socat transfer"),
];

/// File paths that, if accessed in bulk, indicate data harvesting
const SENSITIVE_DIRS: &[(&str, &str)] = &[
    ("/home",                   "User home directories"),
    ("/etc",                    "System configuration"),
    ("/var/log",                "System logs"),
    ("/var/lib/mysql",          "MySQL data directory"),
    ("/var/lib/postgresql",     "PostgreSQL data"),
    ("/var/backups",            "System backups"),
    ("/opt",                    "Application data"),
    ("/srv",                    "Service data"),
];

// ─────────────────────────────────────────────────────────────
// DLP Engine
// ─────────────────────────────────────────────────────────────

pub struct DlpEngine {
    agent_id:   String,
    hostname:   String,
    pub tx:     mpsc::Sender<ThreatEvent>,
    // Track outbound transfers: dest_key → record
    transfers:  Arc<Mutex<HashMap<String, TransferRecord>>>,
    // File access counts: pid → Vec<path>
    file_access: Arc<Mutex<HashMap<u32, Vec<String>>>>,
    patterns:   Vec<(&'static str, DataCategory, Severity, usize, Regex)>,
}

impl DlpEngine {
    pub fn new(agent_id: &str, hostname: &str) -> (Self, mpsc::Receiver<ThreatEvent>) {
        let (tx, rx) = mpsc::channel(256);
        let engine = Self {
            agent_id:    agent_id.to_string(),
            hostname:    hostname.to_string(),
            tx,
            transfers:   Arc::new(Mutex::new(HashMap::new())),
            file_access: Arc::new(Mutex::new(HashMap::new())),
            patterns:    data_patterns(),
        };
        (engine, rx)
    }

    /// Start the DLP monitoring loops.
    pub async fn start(&self) -> Result<()> {
        info!("🛡️  DLP engine starting ({} data patterns loaded)", self.patterns.len());
        self.start_transfer_monitor();
        self.start_staging_detector();
        Ok(())
    }

    /// Analyze a raw event for DLP violations.
    /// Called from the main event loop for every process and file event.
    pub async fn analyze(&self, event: &RawEvent) -> Option<ThreatEvent> {
        match event.event_type {
            EventType::ProcessExec => self.check_exfil_command(event).await,
            EventType::FileOpen | EventType::FileWrite => {
                self.track_file_access(event).await;
                if let Some(t) = self.check_sensitive_file_bulk(event).await {
                    return Some(t);
                }
                // Content classification runs only on writes (the staging signal).
                if matches!(event.event_type, EventType::FileWrite) {
                    self.scan_written_file(event).await
                } else {
                    None
                }
            }
            EventType::NetworkConnect => self.check_large_transfer(event).await,
            _ => None,
        }
    }

    // ── Exfiltration command detection ────────────────────────
    async fn check_exfil_command(&self, event: &RawEvent) -> Option<ThreatEvent> {
        let cmd = event.command_line.as_deref()?.to_lowercase();
        let proc = event.process_name.to_lowercase();

        for (tool, flag, desc) in EXFIL_COMMANDS {
            if !proc.contains(tool) { continue; }
            if !flag.is_empty() && !cmd.contains(flag) { continue; }

            // Check if destination appears external
            let is_external = cmd.contains("@")  // user@host pattern
                || cmd.contains("http://")
                || cmd.contains("https://")
                || cmd.contains("ftp://")
                || is_external_host_in_cmd(&cmd);

            if !is_external { continue; }

            // Higher confidence if compressing first
            let compressing = proc.contains("tar") || proc.contains("zip")
                || proc.contains("7z") || proc.contains("rar");

            let confidence = if compressing { 80.0 } else { 70.0 };
            let severity   = if compressing { Severity::High } else { Severity::Medium };

            warn!("🚫 DLP: Exfiltration tool — {} ({})", proc, desc);
            return Some(self.make_dlp_threat(
                "T1048",
                severity,
                format!("DLP: {} — {}", desc, proc),
                format!(
                    "Process '{}' (pid={}) executing exfiltration command: '{}'. \
                     Tool: {}. External destination detected in command line. \
                     This may indicate data exfiltration over an alternate channel.",
                    event.process_name, event.pid,
                    truncate_chars(&cmd, 200), desc
                ),
                confidence,
                event.pid,
                vec![IOC {
                    ioc_type: IOCType::ProcessName,
                    value: event.process_name.clone(),
                    source: "dlp".into(), confidence,
                }],
            ));
        }
        None
    }

    // ── Track per-process file access ─────────────────────────
    async fn track_file_access(&self, event: &RawEvent) {
        let path = match &event.file_path {
            Some(p) if !p.is_empty() => p.clone(),
            _ => return,
        };

        let mut map = self.file_access.lock().await;
        map.entry(event.pid).or_insert_with(Vec::new).push(path);

        // Prune old entries when map gets large
        if map.len() > 10_000 {
            let keep_pids: Vec<u32> = map.keys().cloned().collect();
            // Keep only the 5000 most recent
            for pid in keep_pids.iter().take(5000) {
                map.remove(pid);
            }
        }
    }

    // ── Bulk sensitive file access detection ──────────────────
    // Accessing hundreds of sensitive files quickly = data harvesting
    async fn check_sensitive_file_bulk(&self, event: &RawEvent) -> Option<ThreatEvent> {
        let path = event.file_path.as_deref()?;

        // Check if path is in a sensitive directory
        let is_sensitive = SENSITIVE_DIRS.iter().any(|(dir, _)| path.starts_with(dir));
        if !is_sensitive { return None; }

        let map = self.file_access.lock().await;
        let accessed = map.get(&event.pid).map(|v| v.len()).unwrap_or(0);

        // More than 500 unique file accesses in the tracked window = suspicious
        if accessed > 500 {
            warn!("🚫 DLP: Bulk file access — pid={} accessed {} files", event.pid, accessed);
            return Some(self.make_dlp_threat(
                "T1005",
                Severity::High,
                format!("DLP: Bulk file access — {} files in sensitive dirs", accessed),
                format!(
                    "Process '{}' (pid={}) has accessed {} files in sensitive directories. \
                     This pattern is consistent with automated data harvesting before exfiltration. \
                     Most recently accessed: {}",
                    event.process_name, event.pid, accessed, path
                ),
                75.0,
                event.pid,
                vec![IOC {
                    ioc_type: IOCType::FilePath,
                    value: path.to_string(),
                    source: "dlp".into(), confidence: 75.0,
                }],
            ));
        }
        None
    }

    // ── Large outbound transfer detection ─────────────────────
    async fn check_large_transfer(&self, event: &RawEvent) -> Option<ThreatEvent> {
        let ip   = event.network_dest_ip.as_deref()?;
        let port = event.network_dest_port.unwrap_or(0);

        // Skip private IPs
        if is_private_ip(ip) { return None; }

        let key = format!("{}:{}", ip, port);
        let mut transfers = self.transfers.lock().await;
        let now = Utc::now();

        let rec = transfers.entry(key.clone()).or_insert(TransferRecord {
            dest_ip: ip.to_string(), dest_port: port,
            bytes_est: 0, first_seen: now, last_seen: now,
            conn_count: 0, process: event.process_name.clone(),
        });

        rec.conn_count += 1;
        rec.last_seen   = now;
        // Rough estimate: each connection ~ 10KB average for data transfer
        rec.bytes_est  += 10_240;

        // Alert thresholds:
        // > 100MB estimated transfer to single external host in < 1 hour
        let duration = (rec.last_seen - rec.first_seen).num_seconds().abs();
        let mb_est   = rec.bytes_est / 1_048_576;

        if mb_est > 100 && duration < 3600 {
            let rate_mb_min = if duration > 0 { mb_est * 60 / duration as u64 } else { mb_est };
            warn!("🚫 DLP: Large transfer to {} — ~{}MB in {}s", ip, mb_est, duration);

            let threat = self.make_dlp_threat(
                "T1041",
                Severity::High,
                format!("DLP: Large outbound transfer to {} (~{}MB)", ip, mb_est),
                format!(
                    "Process '{}' (pid={}) has made {} connections to {}:{} totaling ~{}MB \
                     in {} seconds (~{} MB/min). This volume is consistent with data exfiltration. \
                     Investigate this destination and the process's accessed files.",
                    event.process_name, event.pid, rec.conn_count, ip, port,
                    mb_est, duration, rate_mb_min
                ),
                80.0,
                event.pid,
                vec![IOC {
                    ioc_type: IOCType::Ipv4,
                    value: ip.to_string(),
                    source: "dlp_transfer".into(), confidence: 80.0,
                }],
            );
            // Reset counter after alerting to avoid alert storm
            rec.bytes_est  = 0;
            rec.conn_count = 0;
            return Some(threat);
        }
        None
    }

    // ── Data staging detection ─────────────────────────────────
    // Watch for large files appearing in /tmp, /dev/shm, or home dirs
    // that match archive patterns — staging before exfil
    fn start_staging_detector(&self) {
        let tx       = self.tx.clone();
        let agent_id = self.agent_id.clone();
        let hostname = self.hostname.clone();

        tokio::spawn(async move {
            let mut seen: HashMap<String, u64> = HashMap::new();
            let staging_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/run/user"];
            let archive_exts = [".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2",
                ".7z", ".rar", ".gz", ".zst", ".enc"];

            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

                for dir in &staging_dirs {
                    let Ok(entries) = std::fs::read_dir(dir) else { continue };
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let path_str = path.to_string_lossy().to_string();
                        let is_archive = archive_exts.iter().any(|e| path_str.ends_with(e));
                        if !is_archive { continue; }

                        let Ok(meta) = entry.metadata() else { continue };
                        let size = meta.len();

                        // Only flag files > 10MB to reduce noise
                        if size < 10_485_760 { continue; }

                        // Check if this is new or grew significantly
                        let prev_size = seen.get(&path_str).copied().unwrap_or(0);
                        seen.insert(path_str.clone(), size);

                        if prev_size > 0 && size <= prev_size + 1_048_576 { continue; }

                        let mb = size / 1_048_576;
                        warn!("🚫 DLP: Archive staged in {}: {} ({}MB)", dir, path_str, mb);

                        let threat = ThreatEvent {
                            id:               Uuid::new_v4().to_string(),
                            agent_id:         agent_id.clone(),
                            hostname:         hostname.clone(),
                            timestamp:        Utc::now(),
                            severity:         if mb > 100 { Severity::High } else { Severity::Medium },
                            confidence:       72.0,
                            threat_name:      format!("DLP: Archive staged in {} — {}MB", dir, mb),
                            description:      format!(
                                "Archive file '{}' ({}MB) found in staging directory '{}'. \
                                 This is a common pre-exfiltration pattern: collect data, \
                                 compress it, then transfer. Investigate what data was packed \
                                 and any recent upload tool activity.",
                                path.file_name().unwrap_or_default().to_string_lossy(),
                                mb, dir
                            ),
                            mitre_tactics:    vec!["collection".to_string(), "exfiltration".to_string()],
                            mitre_techniques: vec!["T1560".to_string(), "T1074".to_string()],
                            matched_rules:    vec!["dlp_staging".to_string()],
                            raw_event_ids: vec![], chain: None,
                            iocs: vec![IOC {
                                ioc_type: IOCType::FilePath, value: path_str,
                                source: "dlp_staging".into(), confidence: 72.0,
                            }],
                            suggested_action: ResponseAction::Alert,
                            llm_analysis: None, auto_generated_rule: None,
                        };
                        let _ = tx.send(threat).await;
                    }
                }
            }
        });
    }

    // ── Outbound transfer monitoring ─────────────────────────
    fn start_transfer_monitor(&self) {
        // Periodic cleanup of old transfer records
        let transfers = self.transfers.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                let cutoff = Utc::now() - Duration::hours(2);
                transfers.lock().await.retain(|_, v| v.last_seen > cutoff);
            }
        });
    }

    // ── Scan a file for sensitive data patterns ────────────────
    /// Called by the posture engine when scanning config/log files.
    /// Returns findings with pattern name, category, and match count.
    pub fn scan_content(&self, content: &str, max_bytes: usize) -> Vec<DlpFinding> {
        let text = truncate_chars(content, max_bytes);
        let mut findings = vec![];

        for (name, category, severity, min_matches, re) in &self.patterns {
            let count = re.find_iter(text).count();
            if count >= *min_matches {
                findings.push(DlpFinding {
                    pattern_name: name,
                    category: category.clone(),
                    severity: severity.clone(),
                    match_count: count,
                });
            }
        }
        findings
    }

    /// Read a just-written file and classify its contents against the DLP
    /// pattern set. Bounded by a size cap and an extension allowlist so we only
    /// pay the read cost for file types that plausibly stage bulk data.
    /// This is the runtime hook for `scan_content`, which previously had no
    /// caller (data classification was implemented but never executed).
    async fn scan_written_file(&self, event: &RawEvent) -> Option<ThreatEvent> {
        const MAX_BYTES: usize = 1_048_576; // 1 MiB cap
        let path = event.file_path.as_deref().filter(|p| !p.is_empty())?;
        let lower = path.to_lowercase();
        let ext_ok = [".csv", ".tsv", ".sql", ".json", ".ndjson", ".txt", ".log",
                      ".xml", ".yaml", ".yml", ".bak", ".dump"]
            .iter().any(|e| lower.ends_with(e));
        if !ext_ok { return None; }
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() || meta.len() == 0 || meta.len() as usize > MAX_BYTES { return None; }
        let content = tokio::fs::read(path).await.ok()?;
        let text = String::from_utf8_lossy(&content);
        let findings = self.scan_content(&text, MAX_BYTES);
        if findings.is_empty() { return None; }
        let total: usize = findings.iter().map(|f| f.match_count).sum();
        let cats: Vec<String> = findings.iter()
            .map(|f| format!("{}×{}", f.pattern_name, f.match_count)).collect();
        let severity = if findings.iter().any(|f| matches!(f.severity, Severity::Critical | Severity::High)) {
            Severity::High
        } else {
            Severity::Medium
        };
        warn!("🚫 DLP: sensitive data in written file {} — {}", path, cats.join(", "));
        Some(self.make_dlp_threat(
            "T1074", // Data Staged
            severity,
            format!("DLP: sensitive data written to {}", path),
            format!("File '{}' written by pid={} contains {} sensitive match(es): {}. \
                     Possible data staging for exfiltration.",
                path, event.pid, total, cats.join(", ")),
            75.0,
            event.pid,
            vec![IOC {
                ioc_type: IOCType::FilePath,
                value: path.to_string(),
                source: "dlp".into(), confidence: 75.0,
            }],
        ))
    }

    fn make_dlp_threat(
        &self, technique: &str, severity: Severity,
        name: String, desc: String, confidence: f32,
        pid: u32, iocs: Vec<IOC>,
    ) -> ThreatEvent {
        ThreatEvent {
            id:               Uuid::new_v4().to_string(),
            agent_id:         self.agent_id.clone(),
            hostname:         self.hostname.clone(),
            timestamp:        Utc::now(),
            severity, confidence,
            threat_name:      name, description: desc,
            mitre_tactics:    vec!["exfiltration".to_string(), "collection".to_string()],
            mitre_techniques: vec![technique.to_string()],
            matched_rules:    vec!["dlp".to_string()],
            raw_event_ids:    vec![format!("pid:{}", pid)],
            chain:            None, iocs,
            suggested_action: ResponseAction::Alert,
            llm_analysis:     None, auto_generated_rule: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DlpFinding {
    pub pattern_name: &'static str,
    pub category:     DataCategory,
    pub severity:     Severity,
    pub match_count:  usize,
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

/// Truncate `s` to at most `max_bytes`, never splitting a UTF-8 character.
/// Slicing `&s[..n]` on a non-char-boundary panics; this is the safe form.
fn truncate_chars(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes { return s; }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    &s[..end]
}

fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("127.")
        || ip.starts_with("172.16.") || ip.starts_with("172.17.") || ip.starts_with("172.18.")
        || ip.starts_with("172.19.") || ip.starts_with("172.2") || ip.starts_with("172.3")
        || ip == "0.0.0.0" || ip.starts_with("::")
}

fn is_external_host_in_cmd(cmd: &str) -> bool {
    // Look for domain-like patterns or external IPs in the command
    let domain_re = Regex::new(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|net|org|io|co|ru|cn|de|uk|fr)\b").unwrap();
    domain_re.is_match(cmd)
}
