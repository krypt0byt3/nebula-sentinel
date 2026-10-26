#![allow(dead_code)]
// src/retro/mod.rs — Retro-hunting: one-shot historical scans for detection
// rules and IOCs.
//
// DESIGN: a retro hunt is a DISCRETE, ONE-SHOT job. It is NOT an ambient loop.
// Each call to `run_hunt` scans the relevant historical data ONCE, returns a
// HuntReport (status + matches + timing), and exits. Scheduling / re-runs are
// driven externally (operator on-demand or a Nexus schedule), never by this
// module looping on its own.
//
// PER-TYPE BEHAVIOUR (what each rule type can honestly hunt over):
//   - Sigma / log      → grep configured TEXT LOGS (auth.log, syslog, …).
//   - YARA             → run the real YARA engine over EXISTING FILES on disk
//                        (the only sound retro use case: scan what's already
//                        there). Routed to yara_scan, not the log grep.
//   - IOC / intel      → grep text logs for the indicator value AND, when the
//                        indicator is a file hash, match it against on-disk file
//                        hashes under the configured YARA scan roots.

use crate::config::RetroConfig;
use crate::types::{DetectionRule, IOC, IOCType, RuleType};
use regex::Regex;
use tracing::{info, warn, debug};
use std::path::Path;
use std::sync::Arc;
use rayon::prelude::*;
use chrono::Utc;
use sha2::{Sha256, Digest};
use sha1::Sha1;

/// Roots scanned for YARA file hunts and on-disk IOC-hash matching.
const DEFAULT_FILE_ROOTS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/home"];

/// Lifecycle status of a single hunt job.
#[derive(Debug, Clone, PartialEq)]
pub enum HuntStatus {
    Completed,
    Skipped,   // nothing to hunt over (e.g. network rule, no retained data)
    Failed,
}

impl HuntStatus {
    pub fn as_str(&self) -> &'static str {
        match self { HuntStatus::Completed => "completed", HuntStatus::Skipped => "skipped", HuntStatus::Failed => "failed" }
    }
}

/// Result of one discrete hunt job — reported back to the Nexus so the operator
/// sees a clear start→finish, not an open-ended process.
#[derive(Debug, Clone)]
pub struct HuntReport {
    pub status: HuntStatus,
    pub matches: Vec<RetroMatch>,
    pub sources_scanned: usize,
    pub reason: String,            // human-readable note (esp. for Skipped/Failed)
    pub duration_ms: u128,
}

impl HuntReport {
    fn skipped(reason: impl Into<String>) -> Self {
        HuntReport { status: HuntStatus::Skipped, matches: vec![], sources_scanned: 0, reason: reason.into(), duration_ms: 0 }
    }
}

#[derive(Debug, Clone)]
pub struct RetroMatch {
    pub source_file: String,
    pub line_number: usize,
    pub line_content: String,
    pub rule_name: String,
    pub timestamp_approx: Option<chrono::DateTime<Utc>>,
}

pub struct RetroHunter {
    config: RetroConfig,
    yara: Option<Arc<crate::yara_scan::YaraScanner>>,
}

impl RetroHunter {
    pub fn new(config: RetroConfig) -> Self {
        info!("🔍 RetroHunter initialized (lookback={}d threads={})",
            config.max_lookback_days, config.parallel_threads);
        Self { config, yara: None }
    }

    /// Attach the shared YARA scanner so YARA hunts use the real engine.
    pub fn with_yara(mut self, yara: Arc<crate::yara_scan::YaraScanner>) -> Self {
        self.yara = Some(yara);
        self
    }

    // ── One-shot rule hunt, dispatched by rule type ────────────────────
    // `progress` (optional) receives (percent, phase) updates during long scans
    // so the caller can forward them to the Nexus for a live progress bar.
    pub async fn run_rule_hunt(&self, rule: &DetectionRule) -> HuntReport {
        self.run_rule_hunt_with_progress(rule, None).await
    }

    pub async fn run_rule_hunt_with_progress(
        &self,
        rule: &DetectionRule,
        progress: Option<tokio::sync::mpsc::UnboundedSender<(u8, String)>>,
    ) -> HuntReport {
        let start = std::time::Instant::now();
        if !self.config.enabled {
            return HuntReport::skipped("retro hunting disabled in agent config");
        }
        info!("🔍 Retro-hunt START: rule '{}' (type {:?})", rule.name, rule.rule_type);

        let report = match rule.rule_type {
            RuleType::Yara => self.hunt_yara_files(&rule.name, progress).await,
            // Sigma, Wazuh, and anything else → historical text-log scan. The log
            // scan is a parallel sweep with no natural mid-progress, so bracket it
            // with coarse start/end updates — enough to move the UI progress bar
            // (previously it stayed at 0 for every non-YARA hunt).
            _ => {
                if let Some(ref p) = progress { let _ = p.send((5, "scanning logs".to_string())); }
                let r = self.hunt_logs(&rule.content, &rule.name).await;
                if let Some(ref p) = progress { let _ = p.send((100, "complete".to_string())); }
                r
            }
        };

        let mut report = report;
        report.duration_ms = start.elapsed().as_millis();
        info!("🔍 Retro-hunt END: rule '{}' status={} matches={} in {}ms",
            rule.name, report.status.as_str(), report.matches.len(), report.duration_ms);
        report
    }

    // ── One-shot IOC hunt ──────────────────────────────────────────────
    pub async fn run_ioc_hunt(&self, ioc: &IOC) -> HuntReport {
        let start = std::time::Instant::now();
        if !self.config.enabled {
            return HuntReport::skipped("retro hunting disabled in agent config");
        }
        info!("🔍 Retro-hunt START: IOC '{}' ({:?})", ioc.value, ioc.ioc_type);

        // Always grep the text logs for the indicator value.
        let mut report = self.hunt_logs(&regex::escape(&ioc.value), "ioc_hunt").await;

        // If the indicator is a file hash, also match on-disk files by hash.
        if matches!(ioc.ioc_type, IOCType::Md5 | IOCType::Sha1 | IOCType::Sha256) || is_hashlike(&ioc.value) {
            let hash_hits = hunt_file_hash(&ioc.value, DEFAULT_FILE_ROOTS, self.config.max_files_scanned);
            report.matches.extend(hash_hits);
        }

        report.duration_ms = start.elapsed().as_millis();
        if report.status != HuntStatus::Failed { report.status = HuntStatus::Completed; }
        info!("🔍 Retro-hunt END: IOC '{}' status={} matches={} in {}ms",
            ioc.value, report.status.as_str(), report.matches.len(), report.duration_ms);
        report
    }

    // ── Handler: historical TEXT-LOG scan (Sigma / generic / IOC) ──────
    async fn hunt_logs(&self, pattern: &str, label: &str) -> HuntReport {
        let sources = self.config.log_sources.clone();
        let pat = pattern.to_string();
        let name = label.to_string();
        let threads = self.config.parallel_threads.max(1);

        let (matches, scanned) = tokio::task::spawn_blocking(move || {
            let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
            let scanned = sources.len();
            let matches = pool.install(|| {
                sources.par_iter()
                    .flat_map(|s| scan_log_source(s, &pat, &name))
                    .collect::<Vec<RetroMatch>>()
            });
            (matches, scanned)
        }).await.unwrap_or((vec![], 0));

        if !matches.is_empty() {
            warn!("🕵️ Retro-hunt: {} historical log match(es) for '{}'", matches.len(), label);
        }
        HuntReport {
            status: HuntStatus::Completed, sources_scanned: scanned,
            reason: if scanned == 0 { "no log sources configured".into() } else { String::new() },
            matches, duration_ms: 0,
        }
    }

    // ── Handler: YARA file scan over existing on-disk files ────────────
    async fn hunt_yara_files(
        &self,
        rule_name: &str,
        progress: Option<tokio::sync::mpsc::UnboundedSender<(u8, String)>>,
    ) -> HuntReport {
        let scanner = match &self.yara {
            Some(s) => s.clone(),
            None => return HuntReport::skipped("YARA engine not available on this agent build"),
        };
        let roots: Vec<String> = DEFAULT_FILE_ROOTS.iter().map(|s| s.to_string()).collect();
        let cap = self.config.max_files_scanned;
        let name = rule_name.to_string();

        let (matches, scanned) = tokio::task::spawn_blocking(move || {
            if let Some(ref p) = progress { let _ = p.send((0, "enumerating files".to_string())); }
            let mut files: Vec<std::path::PathBuf> = Vec::new();
            for r in &roots { collect_files(Path::new(r), &mut files, cap); }
            let scanned = files.len();
            let total = scanned.max(1);
            let mut out = vec![];
            // Throttle progress sends to every ~2% so we don't flood the Nexus.
            let step = (total / 50).max(1);
            for (i, f) in files.into_iter().enumerate() {
                let hits = scanner.scan_file(&f.to_string_lossy());
                for h in hits {
                    out.push(RetroMatch {
                        source_file: f.to_string_lossy().to_string(),
                        line_number: 0,
                        line_content: format!("YARA rule matched: {}", h.rule_name),
                        rule_name: name.clone(),
                        timestamp_approx: file_mtime(&f),
                    });
                }
                if let Some(ref p) = progress {
                    if i % step == 0 || i + 1 == total {
                        let pct = (((i + 1) as f64 / total as f64) * 100.0) as u8;
                        let _ = p.send((pct.min(99), format!("scanning files {}/{}", i + 1, total)));
                    }
                }
            }
            if let Some(ref p) = progress { let _ = p.send((100, "complete".to_string())); }
            (out, scanned)
        }).await.unwrap_or((vec![], 0));

        if !matches.is_empty() {
            warn!("🧬 YARA retro-hunt: {} file match(es) for '{}'", matches.len(), rule_name);
        }
        HuntReport {
            status: HuntStatus::Completed, sources_scanned: scanned,
            reason: format!("scanned {} on-disk files under {:?}", scanned, DEFAULT_FILE_ROOTS),
            matches, duration_ms: 0,
        }
    }

}

// ── Free helpers ───────────────────────────────────────────────────────

fn is_hashlike(v: &str) -> bool {
    let n = v.len();
    (n == 32 || n == 40 || n == 64) && v.chars().all(|c| c.is_ascii_hexdigit())
}

fn file_mtime(p: &Path) -> Option<chrono::DateTime<Utc>> {
    std::fs::metadata(p).ok()
        .and_then(|m| m.modified().ok())
        .map(|t| chrono::DateTime::<Utc>::from(t))
}

/// Walk a directory collecting regular files, capped at `cap` to bound work.
fn collect_files(dir: &Path, out: &mut Vec<std::path::PathBuf>, cap: usize) {
    if out.len() >= cap { return; }
    let rd = match std::fs::read_dir(dir) { Ok(r) => r, Err(_) => return };
    for entry in rd.flatten() {
        if out.len() >= cap { return; }
        let p = entry.path();
        // Skip symlinks to avoid loops / escaping the root.
        let ft = match entry.file_type() { Ok(t) => t, Err(_) => continue };
        if ft.is_symlink() { continue; }
        if ft.is_dir() {
            collect_files(&p, out, cap);
        } else if ft.is_file() {
            out.push(p);
        }
    }
}

/// Hash on-disk files and compare against a target hash (md5/sha1/sha256 by len).
fn hunt_file_hash(target: &str, roots: &[&str], cap: usize) -> Vec<RetroMatch> {
    let target = target.to_lowercase();
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for r in roots { collect_files(Path::new(r), &mut files, cap); }
    // Pick the digest algorithm by the indicator's length so MD5 (32) and SHA-1
    // (40) indicators match on disk too, not just SHA-256 (64).
    let (algo, want_len): (&str, usize) = match target.len() {
        32 => ("MD5", 32),
        40 => ("SHA-1", 40),
        64 => ("SHA-256", 64),
        _  => return Vec::new(),   // not a recognized hash length
    };
    files.par_iter().filter_map(|f| {
        let data = std::fs::read(f).ok()?;
        let digest = match want_len {
            32 => format!("{:x}", md5::compute(&data)),
            40 => { let mut h = Sha1::new(); h.update(&data); format!("{:x}", h.finalize()) },
            _  => { let mut h = Sha256::new(); h.update(&data); format!("{:x}", h.finalize()) },
        };
        if digest == target {
            return Some(RetroMatch {
                source_file: f.to_string_lossy().to_string(),
                line_number: 0,
                line_content: format!("file {} matches IOC: {}", algo, target),
                rule_name: "ioc_file_hash".to_string(),
                timestamp_approx: file_mtime(f),
            });
        }
        None
    }).collect()
}

fn scan_log_source(source: &str, pattern: &str, rule_name: &str) -> Vec<RetroMatch> {
    let path = Path::new(source);
    let mut matches = vec![];
    if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let ep = entry.path();
                if ep.is_file() { matches.extend(scan_file(&ep, pattern, rule_name)); }
            }
        }
    } else if path.is_file() {
        matches.extend(scan_file(path, pattern, rule_name));
    }
    matches
}

fn scan_file(path: &Path, pattern: &str, rule_name: &str) -> Vec<RetroMatch> {
    let content = match std::fs::read_to_string(path) { Ok(c) => c, Err(_) => return vec![] };
    let regex_res = Regex::new(pattern);
    let mut out = vec![];
    for (line_num, line) in content.lines().enumerate() {
        let hit = match &regex_res {
            Ok(re) => re.is_match(line),
            Err(_) => line.contains(pattern),
        };
        if hit {
            debug!("retro: match in {}:{} for '{}'", path.display(), line_num + 1, rule_name);
            out.push(RetroMatch {
                source_file: path.to_string_lossy().to_string(),
                line_number: line_num + 1,
                line_content: line.chars().take(500).collect(),
                rule_name: rule_name.to_string(),
                timestamp_approx: None,
            });
        }
    }
    out
}
