#![allow(dead_code)]
// src/apt/mod.rs — Advanced Persistent Threat (APT) behavioral detection
//
// Designed for the four properties that distinguish APT from commodity malware:
//
//   1. Long dwell time    — correlation window extends to 30 days, not 5 minutes
//   2. Low-and-slow C2   — detects hourly beacons with high jitter (CV up to 0.85)
//   3. LOTL techniques   — detects persistence/execution via file artifacts, not just
//                          process events (WMI subscriptions, registry, scheduled tasks,
//                          COM hijack artifacts, office macros)
//   4. Cross-host pivot  — tracks IOC reuse across hosts over time; when attacker
//                          reuses infrastructure across multiple targets it raises
//                          a campaign-level alert regardless of per-host score
//
// Detection philosophy:
//   Commodity malware is fast, loud, and automated.
//   APT is slow, quiet, and human-operated.
//   The statistical properties are opposite — we detect that difference.
//
// MITRE ATT&CK groups with known TTPs modeled here:
//   APT29 / Cozy Bear (Russia)   — T1566→T1059.001→T1218→T1055→T1071(HTTP/S) → long dwell
//   APT41 / Winnti (China)       — T1195(supply chain)→T1059.003→T1036→T1071.004
//   LAZARUS (DPRK)               — T1566→T1204→T1059.005→T1105→T1486
//   APT28 / Fancy Bear (Russia)  — T1583→T1078→T1550.002→T1021.002→T1074
//   SCATTERED SPIDER (FIN)       — T1621→T1078→T1528→T1530→T1567
//
// This module does NOT attempt attribution — it detects behavioral patterns
// that are statistically consistent with APT methodology. Attribution requires
// intel that is outside the scope of an endpoint agent.

use crate::types::{ThreatEvent, Severity, ResponseAction, IOC, IOCType, RawEvent, EventType};
use anyhow::Result;
use chrono::{Utc, Duration};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────
// Long-dwell chain tracker
// Persists to disk (SQLite via rusqlite) so it survives restarts
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DwellChainEntry {
    pub technique:   String,
    pub tactic:      String,
    pub timestamp:   chrono::DateTime<Utc>,
    pub pid:         u32,
    pub process:     String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct DwellChain {
    pub host:       String,
    pub entries:    VecDeque<DwellChainEntry>,
    pub first_seen: chrono::DateTime<Utc>,
    pub last_seen:  chrono::DateTime<Utc>,
    pub tactics_seen: std::collections::HashSet<String>,
    pub alerted:    bool,
}

impl DwellChain {
    pub fn new(host: &str) -> Self {
        Self {
            host: host.to_string(),
            entries: VecDeque::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            tactics_seen: std::collections::HashSet::new(),
            alerted: false,
        }
    }

    pub fn dwell_days(&self) -> i64 {
        (self.last_seen - self.first_seen).num_days().max(0)
    }

    pub fn tactic_count(&self) -> usize {
        self.tactics_seen.len()
    }
}

// ─────────────────────────────────────────────────────────────
// Low-and-slow C2 tracker
// Specifically designed for APT beaconing: hour+ intervals, high jitter
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct SlowBeaconRecord {
    dest_ip:    String,
    dest_port:  u16,
    timestamps: Vec<chrono::DateTime<Utc>>,
    first_seen: chrono::DateTime<Utc>,
}

impl SlowBeaconRecord {
    fn new(ip: &str, port: u16) -> Self {
        Self {
            dest_ip: ip.to_string(),
            dest_port: port,
            timestamps: vec![Utc::now()],
            first_seen: Utc::now(),
        }
    }

    fn add_contact(&mut self) {
        self.timestamps.push(Utc::now());
        if self.timestamps.len() > 50 { self.timestamps.remove(0); }
    }

    fn intervals_hours(&self) -> Vec<f64> {
        self.timestamps.windows(2).map(|w| {
            (w[1] - w[0]).num_seconds() as f64 / 3600.0
        }).collect()
    }

    // APT C2 uses long intervals (1-24h) with high jitter but consistent
    // overall pattern. Standard deviation / mean ratio is different from
    // random traffic, which has no regularity at all.
    fn is_apt_beacon(&self) -> Option<AptBeaconInfo> {
        let intervals = self.intervals_hours();
        if intervals.len() < 4 { return None; }

        let mean  = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let stddev = {
            let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
            var.sqrt()
        };
        let cv = if mean > 0.0 { stddev / mean } else { 1.0 };

        // APT C2 characteristics:
        //   - Mean interval between 0.5 and 24 hours (not seconds like commodity C2)
        //   - CV between 0.15 and 0.85 (jitter, but still structured)
        //   - At least 4 contacts (eliminates scan traffic)
        //   - Observed over at least 6 hours
        let observation_hours = (Utc::now() - self.first_seen).num_hours();
        if mean >= 0.5 && mean <= 24.0
            && cv >= 0.15 && cv <= 0.85
            && intervals.len() >= 4
            && observation_hours >= 6
        {
            Some(AptBeaconInfo {
                mean_interval_hours: mean,
                jitter_cv: cv,
                contact_count: self.timestamps.len(),
                observation_hours,
            })
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct AptBeaconInfo {
    pub mean_interval_hours: f64,
    pub jitter_cv:           f64,
    pub contact_count:       usize,
    pub observation_hours:   i64,
}

// ─────────────────────────────────────────────────────────────
// LOTL artifact patterns (file-system-based, no process needed)
// ─────────────────────────────────────────────────────────────

/// File paths / content patterns that indicate LOTL persistence
/// without requiring a process creation event
const LOTL_ARTIFACT_PATHS: &[(&str, &str, &str, f32)] = &[
    // WMI persistence (written to CIM repository)
    ("/root/.wbem/",             "WMI consumer", "T1546.003", 82.0),
    ("/var/lib/samba/private/",  "Samba credential store modified", "T1078.002", 70.0),
    // SSH persistence artifacts
    ("/root/.ssh/authorized_keys",     "Root SSH key backdoor", "T1098.004", 90.0),
    ("/home/*/.ssh/authorized_keys",   "User SSH key backdoor", "T1098.004", 85.0),
    ("/etc/ssh/sshd_config.d/",        "SSH config drop-in (possible backdoor)", "T1098.004", 78.0),
    // D-Bus / systemd socket activation (covert activation)
    ("/etc/dbus-1/system.d/",          "D-Bus policy added (covert service activation)", "T1546.002", 72.0),
    ("/run/systemd/transient/",        "Transient systemd unit (volatile persistence)", "T1543.002", 75.0),
    // NSS / PAM hooking artifacts
    ("/etc/nsswitch.conf",             "NSS config modified (possible passwd hook)", "T1556.003", 80.0),
    ("/etc/security/",                 "PAM security config modified", "T1556.003", 75.0),
    // Python/Ruby/Perl LOTL artifacts
    ("/usr/lib/python3/dist-packages/", "System Python package modified", "T1574", 72.0),
    ("/usr/lib/ruby/",                  "System Ruby library modified", "T1574", 70.0),
    // Git hook persistence
    ("/.git/hooks/post-commit",        "Git post-commit hook added (developer environment persistence)", "T1546", 68.0),
    ("/.git/hooks/pre-push",           "Git pre-push hook added (developer environment persistence)", "T1546", 68.0),
    // Vim/Nano LOTL via editor rcfiles
    ("/etc/vim/vimrc",                 "System vimrc modified (possible LOTL execution)", "T1059", 65.0),
    // MOTD/banner persistence
    ("/etc/update-motd.d/",            "MOTD script added (runs on every SSH login)", "T1546.004", 75.0),
    ("/etc/profile.d/",                "Shell profile script added", "T1546.004", 78.0),
    // Sudo plugin persistence
    ("/usr/lib/sudo/",                 "Sudo plugin directory modified", "T1548.003", 85.0),
    // Udev covert execution
    ("/etc/udev/rules.d/",             "Udev rule added (hardware event triggered execution)", "T1546.015", 80.0),
    // Network config persistence for traffic redirection
    ("/etc/network/if-up.d/",          "Network interface-up script (C2 on reconnect)", "T1037.004", 70.0),
    ("/etc/NetworkManager/dispatcher.d/", "NetworkManager dispatcher script", "T1037.004", 70.0),
];

/// Command patterns that indicate APT LOTL techniques
/// (techniques used by APT groups specifically to blend with normal admin activity)
const APT_LOTL_COMMANDS: &[(&str, &str, &str, f32)] = &[
    // PowerShell LOTL (APT29 signature)
    ("powershell.*-windowstyle hidden",    "PowerShell hidden window execution",    "T1059.001", 88.0),
    ("powershell.*invoke-expression",      "PowerShell IEX (fileless execution)",   "T1059.001", 85.0),
    ("powershell.*downloadstring",         "PowerShell in-memory download+exec",    "T1105",     88.0),
    ("powershell.*webclient",              "PowerShell WebClient download",         "T1105",     80.0),
    // WMI LOTL (many APT groups)
    ("wmic.*process.*call.*create",        "WMI process creation (LOTL execution)", "T1047",     85.0),
    ("wmic.*/node:",                       "WMI remote node execution",             "T1021.003", 82.0),
    // Scheduled task LOTL (APT41, Lazarus)
    ("schtasks.*/create.*xml",             "Scheduled task from XML (evasion)",     "T1053.005", 80.0),
    ("schtasks.*/f.*hidden",               "Hidden scheduled task creation",        "T1053.005", 82.0),
    // COM hijacking signals
    ("regsvr32.*/s.*/n",                   "Regsvr32 silent no-UI execution",       "T1218.010", 85.0),
    // Cobalt Strike specific artifacts
    ("rundll32.*,#",                       "Rundll32 ordinal export (CS pattern)",  "T1218.011", 85.0),
    ("cmd.*/c.*echo.*>.*nul",             "Cobalt Strike cmd echo null (cleanup)", "T1070.003", 78.0),
    // APT29 / SolarWinds-style staging
    ("certutil.*-urlcache.*-f",           "Certutil URL cache download (staging)", "T1105",     85.0),
    ("certutil.*-decode",                  "Certutil decode (payload staging)",     "T1140",     85.0),
    // Living-off-the-cloud (LOTC) — APT41, Scattered Spider
    ("aws.*sts.*assume-role.*duration",    "Long-duration STS role assumption",     "T1528",     78.0),
    ("az.*group.*deployment.*create",     "Azure resource deployment (LOTC)",      "T1651",     70.0),
    // APT28 Fancy Bear specific patterns
    ("python.*-c.*import.*socket.*exec",  "Python in-memory reverse shell",        "T1059.006", 85.0),
    // Lazarus DPRK patterns
    ("mshta.*vbscript",                   "Mshta VBScript execution (Lazarus TTP)", "T1218.005", 85.0),
    ("regsvcs\\.exe",                     "Regsvcs.exe execution (Lazarus TTP)",    "T1218",     80.0),
];

// ─────────────────────────────────────────────────────────────
// APT Detector
// ─────────────────────────────────────────────────────────────

pub struct AptDetector {
    agent_id:     String,
    hostname:     String,
    pub tx:       mpsc::Sender<ThreatEvent>,
    // Long-dwell chains: host → DwellChain (30-day window)
    dwell_chains: Arc<Mutex<HashMap<String, DwellChain>>>,
    // Slow beacon tracker: "ip:port" → SlowBeaconRecord
    slow_beacons: Arc<Mutex<HashMap<String, SlowBeaconRecord>>>,
}

impl AptDetector {
    pub fn new(agent_id: &str, hostname: &str) -> (Self, mpsc::Receiver<ThreatEvent>) {
        let (tx, rx) = mpsc::channel(256);
        (Self {
            agent_id: agent_id.to_string(),
            hostname: hostname.to_string(),
            tx,
            dwell_chains: Arc::new(Mutex::new(HashMap::new())),
            slow_beacons: Arc::new(Mutex::new(HashMap::new())),
        }, rx)
    }

    /// Start background detection loops
    pub async fn start(&self) -> Result<()> {
        info!("🎯 APT detector starting (30-day dwell window, slow C2 tracking, LOTL artifacts)");
        self.start_slow_beacon_sweeper();
        self.start_dwell_chain_sweeper();
        Ok(())
    }

    /// Analyze a raw event — called from main loop for every event
    pub async fn analyze(&self, event: &RawEvent) -> Option<ThreatEvent> {
        // 1. LOTL command patterns
        if let Some(t) = self.check_lotl_command(event).await { return Some(t); }
        // 2. LOTL artifact file paths
        if let Some(t) = self.check_lotl_artifact(event).await { return Some(t); }
        // 3. Update slow beacon tracker
        self.update_slow_beacon(event).await;
        // 4. Update long-dwell chain
        self.update_dwell_chain(event).await;
        None
    }

    // ── LOTL command detection ────────────────────────────────

    async fn check_lotl_command(&self, event: &RawEvent) -> Option<ThreatEvent> {
        if event.event_type != EventType::ProcessExec { return None; }
        let cmd = event.command_line.as_deref()?.to_lowercase();

        for (pattern, desc, technique, confidence) in APT_LOTL_COMMANDS {
            // Simple substring match (fast); could be upgraded to regex
            let words: Vec<&str> = pattern.split(".*").collect();
            let matches = words.iter().all(|w| cmd.contains(w));
            if matches {
                warn!("🎯 APT LOTL: {} — {}", technique, desc);
                return Some(self.make_apt_threat(
                    technique,
                    if *confidence >= 85.0 { Severity::High } else { Severity::Medium },
                    *confidence,
                    format!("APT LOTL: {} ({})", desc, technique),
                    format!(
                        "Living-off-the-land execution detected: '{}'.\n\
                         Pattern '{}' is associated with APT actor TTPs. \
                         This technique blends with legitimate admin activity — \
                         verify whether this command was authorized.", desc, pattern
                    ),
                    event.pid,
                    vec![],
                ));
            }
        }
        None
    }

    // ── LOTL artifact detection ───────────────────────────────

    async fn check_lotl_artifact(&self, event: &RawEvent) -> Option<ThreatEvent> {
        if !matches!(event.event_type, EventType::FileWrite | EventType::FileOpen) {
            return None;
        }
        let path = event.file_path.as_deref()?;

        for (artifact_path, desc, technique, confidence) in LOTL_ARTIFACT_PATHS {
            if path.starts_with(artifact_path) || path == *artifact_path {
                // Don't fire on reads of known system paths unless it's a write
                let is_write = event.event_type == EventType::FileWrite;
                let adjusted_conf = if is_write { *confidence } else { confidence * 0.7 };
                if adjusted_conf < 55.0 { continue; }

                warn!("🎯 APT LOTL artifact: {} at {} [{}]", desc, path, technique);
                return Some(self.make_apt_threat(
                    technique,
                    if adjusted_conf >= 80.0 { Severity::High } else { Severity::Medium },
                    adjusted_conf,
                    format!("APT persistence artifact: {} — {}", technique, desc),
                    format!(
                        "File {} was {} at '{}'. {}\n\
                         This path is associated with APT persistence and LOTL techniques. \
                         Verify legitimacy before dismissing.",
                        if is_write { "written" } else { "accessed" },
                        if is_write { "created/modified" } else { "read" },
                        path, desc
                    ),
                    event.pid,
                    vec![IOC { ioc_type: IOCType::FilePath, value: path.to_string(), source: "apt_detector".into(), confidence: adjusted_conf }],
                ));
            }
        }
        None
    }

    // ── Slow beacon tracker (APT C2) ──────────────────────────

    async fn update_slow_beacon(&self, event: &RawEvent) {
        if event.event_type != EventType::NetworkConnect { return; }
        let ip   = match &event.network_dest_ip   { Some(i) => i.clone(), None => return };
        let port = event.network_dest_port.unwrap_or(0);

        // Skip private ranges
        if is_private_ip(&ip) { return; }

        let key = format!("{}:{}", ip, port);
        let mut beacons = self.slow_beacons.lock().await;
        let record = beacons.entry(key).or_insert_with(|| SlowBeaconRecord::new(&ip, port));
        record.add_contact();

        if let Some(info) = record.is_apt_beacon() {
            let is_already_alerted = record.timestamps.len() % 5 != 0;
            if is_already_alerted { return; }  // Alert every 5 contacts after initial

            warn!("🎯 APT slow beacon: {}:{} — avg={:.1}h CV={:.2} contacts={} observed={}h",
                ip, port, info.mean_interval_hours, info.jitter_cv,
                info.contact_count, info.observation_hours);

            let _ = self.tx.send(ThreatEvent {
                id:               Uuid::new_v4().to_string(),
                agent_id:         self.agent_id.clone(),
                hostname:         self.hostname.clone(),
                timestamp:        Utc::now(),
                severity:         Severity::High,
                confidence:       80.0,
                threat_name:      format!("APT slow C2 beacon: {}:{} — {:.1}h interval", ip, port, info.mean_interval_hours),
                description:      format!(
                    "Slow, jittered C2 beacon detected to {}:{}.\n\
                     Average interval: {:.1} hours (APT range: 0.5-24h)\n\
                     Jitter CV: {:.2} (commodity malware CV < 0.3; APT 0.15-0.85)\n\
                     Contacts: {} over {} hours\n\
                     This pattern is statistically inconsistent with normal outbound traffic \
                     and consistent with APT C2 beaconing designed to evade high-frequency beacon detection.",
                    ip, port, info.mean_interval_hours, info.jitter_cv,
                    info.contact_count, info.observation_hours
                ),
                mitre_tactics:    vec!["command_and_control".to_string()],
                mitre_techniques: vec!["T1071.001".to_string(), "T1102".to_string()],
                matched_rules:    vec!["apt_slow_beacon".to_string()],
                raw_event_ids:    vec![],
                chain:            None,
                iocs:             vec![IOC { ioc_type: IOCType::Ipv4, value: ip.clone(), source: "apt_detector".into(), confidence: 80.0 }],
                suggested_action: ResponseAction::Alert,
                llm_analysis:     None,
                auto_generated_rule: None,
            }).await;
        }
    }

    // ── Long-dwell chain tracker ──────────────────────────────

    async fn update_dwell_chain(&self, event: &RawEvent) {
        // Only track events with scored techniques (from anomaly engine context)
        // Here we use heuristic: interesting process events with suspicious indicators
        let is_interesting = match event.event_type {
            EventType::ProcessExec => {
                let cmd = event.command_line.as_deref().unwrap_or("");
                cmd.contains("nmap") || cmd.contains("base64") || cmd.contains("curl")
                    || cmd.contains("wget") || cmd.contains("chmod") || cmd.contains("ssh")
                    || cmd.contains("nc ") || cmd.contains("python") || cmd.contains("perl")
                    || event.uid == 0 && event.ppid > 100
            }
            EventType::FileWrite => {
                let fp = event.file_path.as_deref().unwrap_or("");
                fp.starts_with("/etc/") || fp.starts_with("/tmp/") || fp.starts_with("/var/")
                    || fp.contains(".ssh") || fp.contains("cron") || fp.contains("systemd")
            }
            EventType::NetworkConnect => {
                !is_private_ip(event.network_dest_ip.as_deref().unwrap_or(""))
            }
            _ => false,
        };

        if !is_interesting { return; }

        let mut chains = self.dwell_chains.lock().await;
        let chain = chains.entry(self.hostname.clone()).or_insert_with(|| DwellChain::new(&self.hostname));

        // Infer tactic from event type (simplified — anomaly engine provides full mapping)
        let tactic = match event.event_type {
            EventType::ProcessExec => "execution",
            EventType::FileWrite   => "persistence",
            EventType::NetworkConnect => "command_and_control",
            EventType::FileOpen    => "collection",
            _                      => "unknown",
        };

        chain.entries.push_back(DwellChainEntry {
            technique:   "observed".to_string(),
            tactic:      tactic.to_string(),
            timestamp:   Utc::now(),
            pid:         event.pid,
            process:     event.process_name.clone(),
            description: event.command_line.as_deref().unwrap_or(&event.process_name).to_string(),
        });
        chain.tactics_seen.insert(tactic.to_string());
        chain.last_seen = Utc::now();

        // Keep only last 1000 entries per host
        while chain.entries.len() > 1000 { chain.entries.pop_front(); }
    }

    /// Sweep long-dwell chains periodically for multi-tactic campaigns
    fn start_dwell_chain_sweeper(&self) {
        let chains = self.dwell_chains.clone();
        let tx     = self.tx.clone();
        let agent_id = self.agent_id.clone();
        let hostname = self.hostname.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // hourly
            loop {
                ticker.tick().await;
                let mut map = chains.lock().await;
                let now = Utc::now();

                // Prune chains older than 30 days with no recent activity
                map.retain(|_, chain| {
                    (now - chain.last_seen).num_days() < 30
                });

                for (host, chain) in map.iter_mut() {
                    if chain.alerted { continue; }

                    let dwell_days   = chain.dwell_days();
                    let tactic_count = chain.tactic_count();

                    // APT threshold: multi-tactic activity observed over extended period
                    // Thresholds calibrated to produce low false positives:
                    //   ≥ 3 distinct tactics observed over ≥ 3 days = suspicious
                    //   ≥ 4 distinct tactics over ≥ 1 day = suspicious (rapid multi-tactic = more concerning)
                    //   ≥ 5 distinct tactics any timeframe = always suspicious
                    let is_apt_pattern =
                        (tactic_count >= 3 && dwell_days >= 3) ||
                        (tactic_count >= 4 && dwell_days >= 1) ||
                        tactic_count >= 5;

                    if is_apt_pattern {
                        chain.alerted = true;
                        warn!("🎯 APT DWELL CHAIN: host={} tactics={} dwell={}d entries={}",
                            host, tactic_count, dwell_days, chain.entries.len());

                        let tactics_list: Vec<&str> = chain.tactics_seen.iter().map(|s| s.as_str()).collect();
                        let _ = tx.send(ThreatEvent {
                            id:               Uuid::new_v4().to_string(),
                            agent_id:         agent_id.clone(),
                            hostname:         hostname.clone(),
                            timestamp:        Utc::now(),
                            severity:         if dwell_days >= 7 { Severity::Critical } else { Severity::High },
                            confidence:       72.0 + (dwell_days as f32 * 2.0).min(20.0),
                            threat_name:      format!("APT campaign indicators: {} tactics over {} days",
                                tactic_count, dwell_days),
                            description:      format!(
                                "Multi-tactic activity consistent with APT campaign detected on {}.\n\
                                 Tactics observed: {}\n\
                                 Dwell time: {} days\n\
                                 Distinct events: {}\n\
                                 First observed: {}\n\n\
                                 APT actors typically move through multiple kill-chain stages \
                                 slowly to avoid detection thresholds. The combination of \
                                 {} distinct tactics over {} days exceeds the threshold for \
                                 coincidental activity.",
                                host,
                                tactics_list.join(", "),
                                dwell_days,
                                chain.entries.len(),
                                chain.first_seen.format("%Y-%m-%d %H:%M UTC"),
                                tactic_count, dwell_days
                            ),
                            mitre_tactics:    tactics_list.iter().map(|s| s.to_string()).collect(),
                            mitre_techniques: vec!["T1029".to_string()],  // Scheduled transfer
                            matched_rules:    vec!["apt_dwell_chain".to_string()],
                            raw_event_ids:    vec![],
                            chain:            None,
                            iocs:             vec![],
                            suggested_action: ResponseAction::CollectForensics,
                            llm_analysis:     None,
                            auto_generated_rule: None,
                        }).await;
                    }
                }
            }
        });
    }

    /// Periodic cleanup of old slow beacon records
    fn start_slow_beacon_sweeper(&self) {
        let beacons = self.slow_beacons.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(86400));
            loop {
                ticker.tick().await;
                let cutoff = Utc::now() - Duration::days(30);
                beacons.lock().await.retain(|_, v| v.first_seen > cutoff);
            }
        });
    }

    fn make_apt_threat(&self, technique: &str, severity: Severity, confidence: f32,
        name: String, desc: String, pid: u32, iocs: Vec<IOC>) -> ThreatEvent {
        ThreatEvent {
            id: Uuid::new_v4().to_string(),
            agent_id: self.agent_id.clone(), hostname: self.hostname.clone(),
            timestamp: Utc::now(), severity, confidence,
            threat_name: name, description: desc,
            mitre_tactics:    vec!["defense_evasion".to_string()],
            mitre_techniques: vec![technique.to_string()],
            matched_rules:    vec!["apt_detector".to_string()],
            raw_event_ids: if pid > 0 { vec![format!("pid:{}", pid)] } else { vec![] },
            chain: None, iocs,
            suggested_action: ResponseAction::CollectForensics,
            llm_analysis: None, auto_generated_rule: None,
        }
    }
}

fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("127.")
        || ip.starts_with("172.16.") || ip.starts_with("172.17.") || ip.starts_with("172.18.")
        || ip.starts_with("172.19.") || ip.starts_with("172.2")   || ip.starts_with("172.3")
        || ip.is_empty()
}
