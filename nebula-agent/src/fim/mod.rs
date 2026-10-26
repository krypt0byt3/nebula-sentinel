// src/fim/mod.rs — Real-time File Integrity Monitoring
//
// Uses inotify (Linux) / FSEvents (macOS) via the `notify` crate.
// Zero-poll — kernel pushes events immediately when files change.
// Fires ThreatEvents with MITRE mappings on unauthorized modifications.

use crate::types::{ThreatEvent, Severity, ResponseAction, IOC, IOCType};
use anyhow::Result;
use chrono::Utc;
use notify::{Event, EventKind, RecursiveMode, Watcher, recommended_watcher};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};
use uuid::Uuid;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct WatchedPath {
    pub path:        String,
    pub severity:    Severity,
    pub technique:   &'static str,
    pub description: &'static str,
}

pub fn default_critical_paths() -> Vec<WatchedPath> {
    vec![
        WatchedPath { path: "/etc/ssh/sshd_config".into(),     severity: Severity::Critical, technique: "T1098.004", description: "SSH daemon config modified" },
        WatchedPath { path: "/root/.ssh/authorized_keys".into(),severity: Severity::Critical, technique: "T1098.004", description: "Root SSH authorized_keys modified" },
        WatchedPath { path: "/etc/ssh/".into(),                 severity: Severity::High,     technique: "T1098.004", description: "SSH directory modified" },
        WatchedPath { path: "/etc/sudoers".into(),              severity: Severity::Critical, technique: "T1548.003", description: "sudoers modified — privilege escalation" },
        WatchedPath { path: "/etc/sudoers.d/".into(),           severity: Severity::Critical, technique: "T1548.003", description: "sudoers.d entry modified" },
        WatchedPath { path: "/etc/passwd".into(),               severity: Severity::High,     technique: "T1136.001", description: "/etc/passwd modified — account change" },
        WatchedPath { path: "/etc/shadow".into(),               severity: Severity::Critical, technique: "T1003.008", description: "/etc/shadow modified — credential manipulation" },
        WatchedPath { path: "/etc/group".into(),                severity: Severity::High,     technique: "T1136.001", description: "/etc/group modified — membership change" },
        WatchedPath { path: "/etc/cron.d/".into(),              severity: Severity::High,     technique: "T1053.003", description: "Cron job added/modified" },
        WatchedPath { path: "/etc/cron.daily/".into(),          severity: Severity::High,     technique: "T1053.003", description: "Daily cron script modified" },
        WatchedPath { path: "/etc/crontab".into(),              severity: Severity::High,     technique: "T1053.003", description: "System crontab modified" },
        WatchedPath { path: "/var/spool/cron/".into(),          severity: Severity::High,     technique: "T1053.003", description: "User crontab modified" },
        WatchedPath { path: "/etc/systemd/system/".into(),      severity: Severity::High,     technique: "T1543.002", description: "Systemd service unit created/modified" },
        WatchedPath { path: "/etc/pam.d/".into(),               severity: Severity::Critical, technique: "T1556.003", description: "PAM config modified — authentication bypass" },
        WatchedPath { path: "/lib/security/".into(),            severity: Severity::Critical, technique: "T1556.003", description: "PAM module modified" },
        WatchedPath { path: "/etc/ld.so.preload".into(),        severity: Severity::Critical, technique: "T1574.006", description: "ld.so.preload modified — library injection/rootkit" },
        WatchedPath { path: "/etc/ld.so.conf".into(),           severity: Severity::High,     technique: "T1574.006", description: "Dynamic linker config modified" },
        WatchedPath { path: "/usr/bin/".into(),                 severity: Severity::High,     technique: "T1574.006", description: "System binary directory modified" },
        WatchedPath { path: "/usr/sbin/".into(),                severity: Severity::High,     technique: "T1574.006", description: "Sysadmin binary modified" },
        WatchedPath { path: "/bin/".into(),                     severity: Severity::High,     technique: "T1574.006", description: "Critical binary directory modified" },
        WatchedPath { path: "/etc/hosts".into(),                severity: Severity::High,     technique: "T1565.001", description: "/etc/hosts modified — DNS hijacking" },
        WatchedPath { path: "/etc/resolv.conf".into(),          severity: Severity::Medium,   technique: "T1565.001", description: "DNS resolver config modified" },
        WatchedPath { path: "/etc/hosts.allow".into(),          severity: Severity::High,     technique: "T1562.004", description: "TCP wrappers modified" },
        WatchedPath { path: "/boot/".into(),                    severity: Severity::Critical, technique: "T1542.003", description: "Boot directory modified — possible bootkit" },
        WatchedPath { path: "/etc/modules".into(),              severity: Severity::Critical, technique: "T1547.006", description: "Kernel modules list modified — rootkit persistence" },
        WatchedPath { path: "/etc/modprobe.d/".into(),          severity: Severity::High,     technique: "T1547.006", description: "Kernel module config modified" },
        WatchedPath { path: "/etc/profile".into(),              severity: Severity::High,     technique: "T1546.004", description: "/etc/profile modified — shell persistence" },
        WatchedPath { path: "/etc/profile.d/".into(),           severity: Severity::High,     technique: "T1546.004", description: "Profile.d script modified" },
        WatchedPath { path: "/etc/bash.bashrc".into(),          severity: Severity::High,     technique: "T1546.004", description: "Global bashrc modified" },
    ]
}

/// Download/temp "landing zones" — where downloaded malware first hits disk,
/// BEFORE it's executed or copied into a persistence location. Watching these
/// (in addition to the persistence paths above) is what lets the on-access scan
/// (hash blocklist + YARA) catch downloaded malware. Severity here is low because
/// a file merely APPEARING in Downloads is normal — the escalation comes from a
/// hash/YARA HIT during the on-access scan, not from the write itself.
///
/// User home dirs are enumerated at runtime so we cover every real user, not a
/// hardcoded one.
pub fn download_zone_paths() -> Vec<WatchedPath> {
    let mut zones: Vec<WatchedPath> = Vec::new();
    let mk = |p: String| WatchedPath {
        path: p, severity: Severity::Info, technique: "T1105",
        description: "File written to a download/temp zone (ingress tool transfer)",
    };

    #[cfg(not(target_os = "windows"))]
    {
        // System temp / shared-memory landing zones.
        for p in ["/tmp", "/var/tmp", "/dev/shm"] {
            if std::path::Path::new(p).exists() { zones.push(mk(p.to_string())); }
        }
        // Per-user Downloads (and the home dir root, where curl/wget often drop files).
        if let Ok(entries) = std::fs::read_dir("/home") {
            for e in entries.flatten() {
                let home = e.path();
                if home.is_dir() {
                    let dl = home.join("Downloads");
                    if dl.exists() { zones.push(mk(dl.to_string_lossy().to_string())); }
                }
            }
        }
        // root's Downloads too.
        if std::path::Path::new("/root/Downloads").exists() {
            zones.push(mk("/root/Downloads".to_string()));
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Per-user Downloads + Temp under C:\Users\*.
        if let Ok(entries) = std::fs::read_dir("C:\\Users") {
            for e in entries.flatten() {
                let base = e.path();
                if base.is_dir() {
                    for sub in ["Downloads", "AppData\\Local\\Temp"] {
                        let p = base.join(sub);
                        if p.exists() { zones.push(mk(p.to_string_lossy().to_string())); }
                    }
                }
            }
        }
        // System temp.
        if let Ok(t) = std::env::var("TEMP") {
            if std::path::Path::new(&t).exists() { zones.push(mk(t)); }
        }
        if std::path::Path::new("C:\\Windows\\Temp").exists() {
            zones.push(mk("C:\\Windows\\Temp".to_string()));
        }
    }

    zones
}

/// A file is worth scanning if it looks like executable/script/archive/office
/// content — the things malware actually ships as. Skips media/text/huge files so
/// watching busy dirs like /tmp doesn't turn into a scan storm.
pub fn is_scannable_file(path: &str) -> bool {
    const MAX_SCAN_BYTES: u64 = 100 * 1024 * 1024; // 100 MB cap
    let p = std::path::Path::new(path);
    // Size cap.
    if let Ok(md) = std::fs::metadata(p) {
        if !md.is_file() || md.len() == 0 || md.len() > MAX_SCAN_BYTES { return false; }
    } else {
        return false;
    }
    // Extension allowlist (fast path).
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    const SCAN_EXTS: &[&str] = &[
        "exe","dll","scr","sys","com","msi","cpl","ocx",          // Windows PE
        "sh","bash","py","pl","rb","php","ps1","psm1","vbs","js","jse","bat","cmd","wsf","hta", // scripts
        "zip","rar","7z","tar","gz","bz2","xz","cab","iso","img",  // archives/containers
        "doc","docm","xls","xlsm","ppt","pptm","rtf","pdf",        // office/doc (macro carriers)
        "jar","apk","elf","o","so","bin","dylib","dmg","deb","rpm", // more binaries
    ];
    if SCAN_EXTS.contains(&ext.as_str()) { return true; }
    // No/unknown extension: peek magic bytes (PE 'MZ', ELF, shebang, common archives).
    if let Ok(mut f) = std::fs::File::open(p) {
        use std::io::Read;
        let mut magic = [0u8; 4];
        if f.read(&mut magic).map(|n| n >= 2).unwrap_or(false) {
            if &magic[..2] == b"MZ" { return true; }                      // PE
            if &magic == b"\x7fELF" { return true; }                      // ELF
            if &magic[..2] == b"#!" { return true; }                      // shebang script
            if &magic[..2] == b"PK" { return true; }                      // zip/ooxml/jar
            if &magic == b"Rar!" { return true; }                         // rar
            if magic[..3] == [0x1f, 0x8b, 0x08] { return true; }          // gzip
        }
    }
    false
}

pub struct FimEngine {
    agent_id:  String,
    hostname:  String,
    pub tx:    mpsc::Sender<ThreatEvent>,
    baselines: Arc<Mutex<HashMap<String, String>>>,
}

impl FimEngine {
    pub fn new(agent_id: &str, hostname: &str) -> (Self, mpsc::Receiver<ThreatEvent>) {
        let (tx, rx) = mpsc::channel(256);
        (Self { agent_id: agent_id.to_string(), hostname: hostname.to_string(), tx, baselines: Arc::new(Mutex::new(HashMap::new())) }, rx)
    }

    pub async fn start(&self, extra_paths: Vec<String>) -> Result<()> {
        let mut watched = default_critical_paths();
        // Add download/temp landing zones so downloaded malware is scanned on
        // arrival (the on-access hash+YARA scan already runs on watched-file
        // changes; these paths are where downloads actually land).
        watched.extend(download_zone_paths());
        for p in &extra_paths {
            watched.push(WatchedPath { path: p.clone(), severity: Severity::Medium, technique: "T1565.001", description: "Custom watched path modified" });
        }

        // The `notify` crate picks the OS-native backend: inotify on Linux,
        // FSEvents on macOS, ReadDirectoryChangesW on Windows — so FIM works on
        // all three. Report the actual backend rather than always "inotify".
        let fim_backend = if cfg!(target_os = "windows") { "ReadDirectoryChangesW" }
            else if cfg!(target_os = "macos") { "FSEvents" }
            else { "inotify" };
        info!("📁 FIM: starting {} watch on {} paths", fim_backend, watched.len());

        // Baseline hashes for regular files
        for wp in &watched {
            let path = std::path::Path::new(&wp.path);
            if path.is_file() {
                if let Ok(data) = std::fs::read(path) {
                    let hash = format!("{:x}", Sha256::digest(&data));
                    self.baselines.lock().await.insert(wp.path.clone(), hash);
                }
            }
        }

        let (bridge_tx, mut bridge_rx) = mpsc::channel::<(String, EventKind)>(512);
        let watch_paths: Vec<String> = watched.iter().map(|w| w.path.clone()).collect();

        // Blocking watcher thread → async bridge
        let btx = bridge_tx.clone();
        tokio::task::spawn_blocking(move || {
            let (sync_tx, sync_rx) = std::sync::mpsc::channel();
            let mut watcher = match recommended_watcher(move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    for p in event.paths {
                        let _ = sync_tx.send((p.to_string_lossy().to_string(), event.kind));
                    }
                }
            }) {
                Ok(w) => w,
                Err(e) => { warn!("FIM watcher init failed: {}", e); return; }
            };

            for p in &watch_paths {
                let path = std::path::Path::new(p);
                if path.exists() {
                    let _ = watcher.watch(path, RecursiveMode::NonRecursive);
                }
            }

            loop {
                match sync_rx.recv() {
                    Ok((path, kind)) => { let _ = btx.blocking_send((path, kind)); }
                    Err(_) => break,
                }
            }
        });

        let tx = self.tx.clone();
        let agent_id = self.agent_id.clone();
        let hostname = self.hostname.clone();
        let baselines = self.baselines.clone();
        let watched_c = watched.clone();

        tokio::spawn(async move {
            while let Some((path, kind)) = bridge_rx.recv().await {
                if !matches!(kind, EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)) { continue; }

                let spec = watched_c.iter().find(|w| path.starts_with(&w.path) || path == w.path);
                let Some(spec) = spec else { continue };

                // Dedup: only fire if file content actually changed. Key on the
                // ACTUAL file path (not spec.path) — a watched directory like /tmp
                // or ~/Downloads holds many files under one spec, and keying on the
                // spec would make them all collide and mask each other.
                let changed = if std::path::Path::new(&path).is_file() {
                    if let Ok(data) = std::fs::read(&path) {
                        let cur = format!("{:x}", Sha256::digest(&data));
                        let prev = baselines.lock().await.get(&path).cloned();
                        let diff = prev.as_deref() != Some(&cur);
                        baselines.lock().await.insert(path.clone(), cur);
                        diff
                    } else { true }
                } else { true };

                if !changed { continue; }

                // For download/temp landing zones (T1105), a file merely appearing
                // is normal — we don't want to alert on every temp file. But we DO
                // want the on-access scan (hash blocklist + YARA, run in main.rs on
                // the emitted event's FilePath IOC) to check scannable files. So:
                // in a download zone, only emit if the file looks like something
                // malware ships as (exe/script/archive/office). The emitted event
                // is what drives the scan; a YARA/hash HIT then escalates it.
                // Non-download persistence paths always emit (integrity matters).
                let is_download_zone = spec.technique == "T1105";
                if is_download_zone {
                    if !matches!(kind, EventKind::Create(_) | EventKind::Modify(_)) { continue; }
                    if !is_scannable_file(&path) { continue; }
                }

                warn!("📁 FIM [{:?}] {} — {}", kind, path, spec.description);

                let _ = tx.send(ThreatEvent {
                    id:               Uuid::new_v4().to_string(),
                    agent_id:         agent_id.clone(),
                    hostname:         hostname.clone(),
                    timestamp:        Utc::now(),
                    severity:         spec.severity.clone(),
                    confidence:       match spec.severity { Severity::Critical => 95.0, Severity::High => 85.0, _ => 70.0 },
                    threat_name:      format!("{} — {}", spec.technique, spec.description),
                    description:      format!("FIM: {} was {:?}. Path: {}", spec.description, kind, path),
                    mitre_tactics:    vec!["persistence".to_string()],
                    mitre_techniques: vec![spec.technique.to_string()],
                    matched_rules:    vec!["fim_realtime".to_string()],
                    raw_event_ids:    vec![],
                    chain:            None,
                    iocs:             vec![IOC { ioc_type: IOCType::FilePath, value: path.clone(), source: "fim".into(), confidence: 90.0 }],
                    suggested_action: match spec.severity { Severity::Critical => ResponseAction::Alert, _ => ResponseAction::Monitor },
                    llm_analysis:     None,
                    auto_generated_rule: None,
                }).await;
            }
        });

        Ok(())
    }
}
