// src/ransomware/mod.rs — Ransomware-specific behavioral detection and prevention
//
// Approach: file system I/O pattern analysis — NOT command-line matching.
// Modern ransomware encrypts in-process; no openssl/gpg appears in the command line.
// What is always observable regardless of ransomware family:
//
//   1. Mass file rename with new extension (entropy spike in filenames)
//   2. Mass file overwrite — same inode, different content
//   3. One process writing to thousands of unique files in seconds
//   4. File entropy change: legitimate file (entropy ~3-5) → encrypted (~7.9)
//   5. Ransom note creation (README.txt, HOW_TO_DECRYPT.html, etc.)
//   6. Shadow copy deletion commands (already in anomaly engine — kept here too)
//   7. Backup software termination
//   8. Volume shadow service interaction
//
// MITRE coverage:
//   T1486 — Data Encrypted for Impact
//   T1490 — Inhibit System Recovery
//   T1485 — Data Destruction
//   T1489 — Service Stop
//
// Prevention strategy (Protect mode):
//   1. Detection fires early — kill process before significant files are encrypted
//   2. Quarantine the ransomware binary from disk
//   3. Alert Nexus immediately
//   4. Snapshot known-good file listing for recovery guidance

use crate::types::{ThreatEvent, Severity, ResponseAction, IOC, IOCType, RawEvent, EventType};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────
// Known ransomware file extensions
// ─────────────────────────────────────────────────────────────

// Built-in DEFAULT ransomware file extensions. These SEED the runtime set at
// startup so detection works out-of-the-box, but the live set is runtime-
// mutable and extended from the Nexus intel feed (see RansomwareDetector's
// ext_set) — so new families can be distributed fleet-wide without recompiling.
const DEFAULT_RANSOM_EXTENSIONS: &[&str] = &[
    // Modern families
    ".locked", ".encrypted", ".enc", ".crypt", ".crypted",
    ".crypto", ".pay2decrypt", ".R4ndom", ".WNCRY", ".wnry",
    // LockBit
    ".lockbit", ".lb3",
    // BlackCat / ALPHV
    ".syk", ".zxe",
    // Clop
    ".clop", ".ci_", ".CIop",
    // REvil / Sodinokibi
    ".sodinokibi", ".evp",
    // Dharma/Phobos
    ".dharma", ".phobos", ".id-",
    // Ryuk
    ".RYK",
    // Conti
    ".conti",
    // WannaCry
    ".WCRY", ".WNCRY",
    // DarkSide
    ".d79pq4",
    // Generic patterns
    ".r5a", ".r4a", ".aaa", ".abc", ".xyz.encrypted",
    ".locky", ".zepto", ".odin", ".shit", ".thor",
    ".cerber", ".cerber2", ".cerber3",
];

// Built-in DEFAULT ransom-note filenames (also runtime-extendable via intel).
const DEFAULT_RANSOM_NOTE_NAMES: &[&str] = &[
    "README.txt", "README.html", "HOW_TO_DECRYPT.txt", "HOW_TO_DECRYPT.html",
    "DECRYPT_FILES.txt", "DECRYPT_FILES.html", "HELP_DECRYPT.txt",
    "YOUR_FILES_ARE_ENCRYPTED.txt", "RECOVERY_KEY.txt",
    "HOW_TO_RESTORE_FILES.txt", "RANSOM_NOTE.txt", "IMPORTANT.txt",
    "DECRYPT_INSTRUCTION.txt", "FILES_ENCRYPTED.html",
    "Read_Me.txt", "ReadMe.txt", "readme_for_decrypt.txt",
    "@Please_Read_Me@.txt",  // WannaCry
    "HELP_RESTORE_FILES.txt",
    "NOTICE.txt",
];

// Backup/security tools ransomware kills before encrypting
const BACKUP_PROCESSES: &[&str] = &[
    "veeam", "backup", "acronis", "carbonite", "crashplan",
    "backupexec", "shadow", "vss", "wbengine",
];

// ─────────────────────────────────────────────────────────────
// Per-process file write tracker
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ProcessFileActivity {
    pid:            u32,
    process_name:   String,
    files_written:  Vec<String>,
    encrypted_ext_count: u32,
    ransom_note_found:   bool,
    first_seen:     chrono::DateTime<Utc>,
    last_seen:      chrono::DateTime<Utc>,
    alerted:        bool,
}

impl ProcessFileActivity {
    fn new(pid: u32, name: &str) -> Self {
        Self {
            pid, process_name: name.to_string(),
            files_written: vec![],
            encrypted_ext_count: 0, ransom_note_found: false,
            first_seen: Utc::now(), last_seen: Utc::now(),
            alerted: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Ransomware detector
// ─────────────────────────────────────────────────────────────

pub struct RansomwareDetector {
    agent_id:  String,
    hostname:  String,
    pub tx:    mpsc::Sender<ThreatEvent>,
    // Track file activity per process
    activity:  Arc<Mutex<HashMap<u32, ProcessFileActivity>>>,
    // Runtime-mutable known-ransomware indicators. Seeded from the DEFAULT_*
    // built-ins, then extended live from the Nexus intel feed — so new families
    // propagate fleet-wide without a rebuild. RwLock (std, sync) because reads
    // are hot (every file event) and writes are rare (intel sync). Extensions
    // are stored lowercased for case-insensitive matching.
    ext_set:   Arc<StdRwLock<HashSet<String>>>,
    note_set:  Arc<StdRwLock<HashSet<String>>>,
}

impl RansomwareDetector {
    pub fn new(agent_id: &str, hostname: &str) -> (Self, mpsc::Receiver<ThreatEvent>) {
        let (tx, rx) = mpsc::channel(256);
        let ext_set: HashSet<String> = DEFAULT_RANSOM_EXTENSIONS.iter()
            .map(|e| e.to_lowercase()).collect();
        let note_set: HashSet<String> = DEFAULT_RANSOM_NOTE_NAMES.iter()
            .map(|n| n.to_lowercase()).collect();
        (Self {
            agent_id:  agent_id.to_string(),
            hostname:  hostname.to_string(),
            tx,
            activity:  Arc::new(Mutex::new(HashMap::new())),
            ext_set:   Arc::new(StdRwLock::new(ext_set)),
            note_set:  Arc::new(StdRwLock::new(note_set)),
        }, rx)
    }

    // ── Runtime intel updates ────────────────────────────────────────────
    // Mirrors the reputation engine's blocklist pattern: the Arc'd detector is
    // updated live from the Nexus intel feed, so new ransomware families spread
    // fleet-wide without a rebuild.

    /// Add a single known-ransomware extension at runtime (e.g. ".akira").
    /// Normalizes to lowercase and ensures a leading dot. Returns true if new.
    pub fn add_ransom_extension(&self, ext: &str) -> bool {
        let mut e = ext.trim().to_lowercase();
        if e.is_empty() { return false; }
        if !e.starts_with('.') { e.insert(0, '.'); }
        match self.ext_set.write() {
            Ok(mut set) => set.insert(e),
            Err(_) => false,
        }
    }

    /// Add a known ransom-note filename at runtime. Returns true if new.
    pub fn add_ransom_note_name(&self, name: &str) -> bool {
        let n = name.trim().to_lowercase();
        if n.is_empty() { return false; }
        match self.note_set.write() {
            Ok(mut set) => set.insert(n),
            Err(_) => false,
        }
    }

    /// Bulk-load ransomware extensions from the Nexus intel feed. Returns the
    /// number newly added. Existing entries (incl. the built-in defaults) remain.
    pub fn load_ransom_extensions(&self, exts: &[String]) -> usize {
        exts.iter().filter(|e| self.add_ransom_extension(e)).count()
    }

    /// Bulk-load ransom-note names from the Nexus intel feed. Returns count added.
    pub fn load_ransom_note_names(&self, names: &[String]) -> usize {
        names.iter().filter(|n| self.add_ransom_note_name(n)).count()
    }

    /// Snapshot helpers (used for matching + status). Cheap clones of the small
    /// indicator sets; taken under a read lock.
    fn ext_snapshot(&self) -> HashSet<String> {
        self.ext_set.read().map(|s| s.clone()).unwrap_or_default()
    }
    fn note_snapshot(&self) -> HashSet<String> {
        self.note_set.read().map(|s| s.clone()).unwrap_or_default()
    }
    fn ext_count(&self) -> usize { self.ext_set.read().map(|s| s.len()).unwrap_or(0) }
    fn note_count(&self) -> usize { self.note_set.read().map(|s| s.len()).unwrap_or(0) }

    /// Return the matched runtime ransomware extension for `path` (for the alert
    /// description), or "unknown" if none match.
    fn ransom_ext_example(&self, path: &str) -> String {
        let p = path.to_lowercase();
        self.ext_snapshot().iter().find(|ext| p.ends_with(*ext))
            .cloned().unwrap_or_else(|| "unknown".to_string())
    }

    /// Start background monitors
    pub async fn start(&self) {
        info!("🔴 Ransomware detector: active ({} known extensions, {} note names — intel-extendable)",
            self.ext_count(), self.note_count());
        self.start_activity_sweeper();
    }

    /// Analyze a raw event — called from main event loop for every FileWrite event.
    pub async fn analyze(&self, event: &RawEvent) -> Option<ThreatEvent> {
        match event.event_type {
            EventType::FileWrite | EventType::FileOpen => {
                self.analyze_file_event(event).await
            }
            EventType::ProcessExec => {
                self.analyze_process_event(event).await
            }
            _ => None,
        }
    }

    async fn analyze_file_event(&self, event: &RawEvent) -> Option<ThreatEvent> {
        let path = event.file_path.as_deref()?;
        let filename = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let mut activity = self.activity.lock().await;
        let rec = activity.entry(event.pid).or_insert_with(|| {
            ProcessFileActivity::new(event.pid, &event.process_name)
        });

        rec.last_seen = Utc::now();

        // ── Check 1: Ransom note creation ──────────────────────
        let note_set = self.note_snapshot();
        let fname_lc = filename.to_lowercase();
        let is_ransom_note = note_set.contains(&fname_lc);
        if is_ransom_note && !rec.ransom_note_found {
            rec.ransom_note_found = true;
            warn!("🔴 RANSOMWARE: Ransom note created by pid={} ({}): {}",
                event.pid, event.process_name, path);

            return Some(self.make_ransomware_threat(
                Severity::Critical,
                96.0,
                format!("Ransomware: ransom note created by {} (pid={})",
                    event.process_name, event.pid),
                format!(
                    "Ransom note '{}' was created by process '{}' (pid={}). \
                     This is a definitive ransomware indicator. \
                     The process should be killed immediately and the affected \
                     directories examined for encrypted files.",
                    filename, event.process_name, event.pid
                ),
                event.pid,
                path,
                "T1486",
            ));
        }

        // ── Check 2: Known ransomware extension ───────────────
        let path_lc = path.to_lowercase();
        let has_ransom_ext = self.ext_snapshot().iter().any(|ext| path_lc.ends_with(ext));
        if has_ransom_ext {
            rec.encrypted_ext_count += 1;
            rec.files_written.push(path.to_string());

            // Alert after 3 files with ransom extensions — fast response
            if rec.encrypted_ext_count >= 3 && !rec.alerted {
                rec.alerted = true;
                warn!("🔴 RANSOMWARE: {} files with known ransom extensions by pid={} ({})",
                    rec.encrypted_ext_count, event.pid, event.process_name);

                return Some(self.make_ransomware_threat(
                    Severity::Critical,
                    97.0,
                    format!("Ransomware encrypting files: {} (pid={}) — {} files",
                        event.process_name, event.pid, rec.encrypted_ext_count),
                    format!(
                        "Process '{}' (pid={}) has written {} files with known \
                         ransomware extensions ({}). This is active ransomware encryption. \
                         Kill process immediately. Recently written: {}",
                        event.process_name, event.pid, rec.encrypted_ext_count,
                        self.ransom_ext_example(path),
                        rec.files_written.iter().take(5).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    ),
                    event.pid,
                    path,
                    "T1486",
                ));
            }
        }

        // ── Check 3: Mass file write rate ──────────────────────
        // One process writing > 100 unique files in 60 seconds
        // is unusual for all legitimate software
        if event.event_type == EventType::FileWrite {
            rec.files_written.push(path.to_string());
            let unique: std::collections::HashSet<_> = rec.files_written.iter().collect();
            let elapsed = (Utc::now() - rec.first_seen).num_seconds().max(1);
            let rate_per_min = unique.len() as i64 * 60 / elapsed;

            if unique.len() > 100 && rate_per_min > 200 && !rec.alerted {
                // Check if files are in user data directories (not /proc, /dev, /sys)
                let in_data_dir = path.starts_with("/home") || path.starts_with("/var/www")
                    || path.starts_with("/srv") || path.starts_with("/opt")
                    || path.starts_with("/media") || path.starts_with("/mnt");

                if in_data_dir {
                    // Verify file entropy spike on the last few files
                    let high_entropy = check_file_entropy(path);

                    if high_entropy {
                        rec.alerted = true;
                        warn!("🔴 RANSOMWARE: Mass high-entropy file writes by pid={} ({}) — {}/min",
                            event.pid, event.process_name, rate_per_min);

                        return Some(self.make_ransomware_threat(
                            Severity::Critical,
                            88.0,
                            format!("Ransomware pattern: mass encrypted file writes by {} (pid={})",
                                event.process_name, event.pid),
                            format!(
                                "Process '{}' (pid={}) is writing at {} files/min to data directories. \
                                 Recently written files have high entropy (>{:.1}/8.0) indicating \
                                 encryption. This matches ransomware I/O behavior. \
                                 Total files written: {}",
                                event.process_name, event.pid, rate_per_min,
                                7.5, unique.len()
                            ),
                            event.pid,
                            path,
                            "T1486",
                        ));
                    }
                }
            }
        }

        None
    }

    async fn analyze_process_event(&self, event: &RawEvent) -> Option<ThreatEvent> {
        let cmd = event.command_line.as_deref()?.to_lowercase();
        let proc = event.process_name.to_lowercase();

        // ── Backup tool termination (pre-encryption phase) ────
        let killing_backup = BACKUP_PROCESSES.iter().any(|b| {
            (cmd.contains("systemctl stop") || cmd.contains("taskkill") ||
             cmd.contains("net stop") || cmd.contains("sc stop")) &&
            cmd.contains(b)
        });

        if killing_backup {
            warn!("🔴 RANSOMWARE: Backup process being killed: {}", cmd);
            return Some(self.make_ransomware_threat(
                Severity::High,
                82.0,
                format!("Ransomware prep: backup service being stopped by {}", event.process_name),
                format!(
                    "Process '{}' is stopping backup/recovery services: '{}'. \
                     This is a standard pre-encryption step used by most ransomware families \
                     to prevent recovery. Monitor for subsequent file encryption activity.",
                    event.process_name, cmd
                ),
                event.pid,
                "",
                "T1489",
            ));
        }

        // ── Volume shadow / VSS interaction ───────────────────
        if cmd.contains("vssadmin") || cmd.contains("wbadmin") ||
           cmd.contains("diskshadow") || cmd.contains("schtasks /delete")
        {
            warn!("🔴 RANSOMWARE: Shadow copy/recovery deletion: {}", cmd);
            return Some(self.make_ransomware_threat(
                Severity::Critical,
                93.0,
                format!("Ransomware: inhibiting system recovery ({}) ", event.process_name),
                format!(
                    "Process '{}' is deleting volume shadow copies or backups: '{}'. \
                     This is the most reliable ransomware pre-encryption indicator. \
                     Remediation: block this process immediately and investigate \
                     how it arrived on the system.",
                    event.process_name, cmd
                ),
                event.pid,
                "",
                "T1490",
            ));
        }

        // ── chmod 000 on user files (destruction phase) ───────
        if (proc == "chmod" || cmd.contains("chmod")) &&
           cmd.contains("000") &&
           (cmd.contains("/home") || cmd.contains("/var/www") || cmd.contains("/srv"))
        {
            return Some(self.make_ransomware_threat(
                Severity::Critical,
                90.0,
                format!("Ransomware: mass file permission wipe by {}", event.process_name),
                "Mass chmod 000 on user data directories — ransomware or wiper destroying access to files."
                    .to_string(),
                event.pid, "", "T1485",
            ));
        }

        None
    }

    /// Periodic sweep: alert on processes that have been slowly encrypting
    /// (low rate — below per-event thresholds but accumulating over time)
    fn start_activity_sweeper(&self) {
        let activity = self.activity.clone();
        let tx = self.tx.clone();
        let agent_id = self.agent_id.clone();
        let hostname = self.hostname.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(
                tokio::time::Duration::from_secs(30)
            );
            loop {
                ticker.tick().await;
                let now = Utc::now();

                let mut map = activity.lock().await;

                // Clean up stale entries (process exited more than 5 min ago)
                map.retain(|_, v| {
                    (now - v.last_seen).num_seconds() < 300
                });

                // Check for slow ransomware (below per-event threshold but alarming over time)
                for (_pid, rec) in map.iter_mut() {
                    if rec.alerted { continue; }
                    if rec.encrypted_ext_count < 1 { continue; }

                    let elapsed_min = (now - rec.first_seen).num_minutes().max(1);
                    let rate_per_min = rec.encrypted_ext_count as i64 / elapsed_min;

                    // Even 5 ransom-extension files per minute is alarming
                    if rec.encrypted_ext_count >= 2 && elapsed_min >= 1 {
                        rec.alerted = true;
                        let threat = ThreatEvent {
                            id: Uuid::new_v4().to_string(),
                            agent_id: agent_id.clone(),
                            hostname: hostname.clone(),
                            timestamp: Utc::now(),
                            severity: Severity::Critical,
                            confidence: 92.0,
                            threat_name: format!(
                                "Ransomware (slow): {} encrypted files by {} (pid={})",
                                rec.encrypted_ext_count, rec.process_name, rec.pid
                            ),
                            description: format!(
                                "Process '{}' (pid={}) has encrypted {} files \
                                 with known ransomware extensions over {} minutes \
                                 (~{} files/min). Slow encryption to evade rate-based \
                                 detection. Kill process immediately.",
                                rec.process_name, rec.pid,
                                rec.encrypted_ext_count, elapsed_min, rate_per_min
                            ),
                            mitre_tactics:    vec!["impact".to_string()],
                            mitre_techniques: vec!["T1486".to_string()],
                            matched_rules:    vec!["ransomware_detector".to_string()],
                            raw_event_ids: vec![format!("pid:{}", rec.pid)],
                            chain: None,
                            iocs: vec![],
                            suggested_action: ResponseAction::KillProcess(rec.pid),
                            llm_analysis: None,
                            auto_generated_rule: None,
                        };
                        let _ = tx.send(threat).await;
                    }
                }
            }
        });
    }

    fn make_ransomware_threat(
        &self,
        severity: Severity,
        confidence: f32,
        name: String,
        desc: String,
        pid: u32,
        path: &str,
        technique: &str,
    ) -> ThreatEvent {
        let mut iocs = vec![];
        if !path.is_empty() {
            iocs.push(IOC {
                ioc_type: IOCType::FilePath,
                value: path.to_string(),
                source: "ransomware_detector".into(),
                confidence,
            });
        }

        ThreatEvent {
            id:               Uuid::new_v4().to_string(),
            agent_id:         self.agent_id.clone(),
            hostname:         self.hostname.clone(),
            timestamp:        Utc::now(),
            severity,
            confidence,
            threat_name:      name,
            description:      desc,
            mitre_tactics:    vec!["impact".to_string()],
            mitre_techniques: vec![technique.to_string()],
            matched_rules:    vec!["ransomware_detector".to_string(), "behavioral".to_string()],
            raw_event_ids:    vec![format!("pid:{}", pid)],
            chain:            None,
            iocs,
            // In protect mode, kill the process immediately
            suggested_action: ResponseAction::KillProcess(pid),
            llm_analysis:     None,
            auto_generated_rule: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────
// File entropy check
// ─────────────────────────────────────────────────────────────

/// Returns true if the file has high entropy (>= 7.5 / 8.0),
/// which indicates encryption or compression.
/// Reads only the first 65KB to stay fast.
fn check_file_entropy(path: &str) -> bool {
    let Ok(data) = std::fs::read(path) else { return false };
    let sample = &data[..data.len().min(65536)];
    if sample.len() < 512 { return false; }

    let mut freq = [0u64; 256];
    for &b in sample { freq[b as usize] += 1; }
    let len = sample.len() as f64;
    let entropy: f64 = freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum();

    entropy >= 7.5
}
