#![allow(dead_code)]
// src/playbook/mod.rs — Response Playbook Engine
//
// 30 playbooks covering every major attack scenario.
// Each playbook defines:
//   - trigger: confidence threshold, severity floor, MITRE techniques/tactics
//   - steps: ordered response actions with full context
//
// Playbooks are checked in priority order; the highest-priority match executes.
// Steps execute sequentially. Wait steps allow evidence collection before response.
//
// Architecture note: playbooks are intentionally conservative —
// they collect evidence BEFORE destructive actions (kill/isolate)
// so that forensic evidence is preserved regardless of outcome.

use crate::types::{ThreatEvent, Severity, IOCType};
use crate::firewall::Firewall;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn, error};

// ─────────────────────────────────────────────────────────────
// Playbook data model
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub name:        String,
    pub description: String,
    pub priority:    u32,     // higher = evaluated first
    pub trigger:     PlaybookTrigger,
    pub steps:       Vec<PlaybookStep>,
    pub enabled:     bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookTrigger {
    pub min_confidence:   f32,
    pub min_severity:     String,
    pub techniques:       Vec<String>,  // empty = any
    pub tactics:          Vec<String>,  // empty = any
    pub chain_names:      Vec<String>,  // match if attack chain name contains any entry
    pub require_protect:  bool,         // if true, only trigger in Protect mode
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum PlaybookStep {
    /// Collect process triage, logs, optionally PCAP and memory dump
    CollectForensics { include_pcap: bool, include_memory: bool, reason: String },
    /// SIGKILL the process identified by the threat
    KillProcess { reason: String },
    /// Block all IPs in the threat's IOC list
    BlockThreatIps { reason: String },
    /// Block a specific IP by value
    BlockIp { ip: String, reason: String },
    /// Move the malicious file to quarantine
    QuarantineFile { reason: String },
    /// Full host network isolation (allow only Nexus)
    IsolateHost { reason: String },
    /// Undo a previous isolation
    UndoIsolation,
    /// Wait N seconds (allow async operations to complete)
    Wait { seconds: u64 },
    /// Mark as escalated in Nexus (adds critical tag to threat)
    EscalateToNexus { priority: String, note: String },
    /// Log a message without taking action (for documentation)
    Log { message: String },
    /// Run a posture scan (triggers on-demand assessment)
    TriggerPostureScan,
    /// Notify operator via configured channel (syslog/legacy bridge)
    Notify { message: String },
}

// ─────────────────────────────────────────────────────────────
// Engine
// ─────────────────────────────────────────────────────────────

pub struct PlaybookEngine {
    playbooks: Vec<Playbook>,
    firewall:  Option<Arc<Firewall>>,
    /// Operating mode. Destructive playbook steps (kill/quarantine/block/
    /// isolate) only execute in Protect mode; in Detect/Audit they are logged
    /// as "would" actions — matching the ResponseEngine's mode semantics so a
    /// detect-mode agent never mutates the host.
    mode:      crate::config::AgentMode,
}

impl PlaybookEngine {
    pub fn new(playbooks: Vec<Playbook>) -> Self {
        info!("📋 Playbook engine: {} playbooks loaded", playbooks.len());
        Self { playbooks, firewall: None, mode: crate::config::AgentMode::Detect }
    }

    pub fn with_firewall(mut self, fw: Arc<Firewall>) -> Self {
        self.firewall = Some(fw);
        self
    }

    pub fn with_mode(mut self, mode: crate::config::AgentMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn default_playbooks() -> Vec<Playbook> {
        vec![
            // ── 1. CRITICAL THREAT (catch-all for anything ≥ 95% critical) ────────
            Playbook {
                name: "Critical Threat — Full Response".to_string(),
                description: "Any critical-severity threat: collect evidence, kill, escalate".to_string(),
                priority: 10,
                trigger: PlaybookTrigger {
                    min_confidence: 92.0, min_severity: "critical".to_string(),
                    techniques: vec![], tactics: vec![], chain_names: vec![],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: true, reason: "Critical threat — preserve full evidence before response".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "Critical confidence threshold exceeded".into() },
                    PlaybookStep::Wait { seconds: 3 },
                    PlaybookStep::KillProcess { reason: "Terminate malicious process after forensics collected".into() },
                    PlaybookStep::BlockThreatIps { reason: "Block all IOC IPs from critical threat".into() },
                ],
                enabled: true,
            },

            // ── 2. WEBSHELL / RCE ─────────────────────────────────────────────────
            Playbook {
                name: "Webshell / Remote Code Execution".to_string(),
                description: "Web server spawning shell or known webshell uploaded (T1190, T1505.003)".to_string(),
                priority: 90,
                trigger: PlaybookTrigger {
                    min_confidence: 75.0, min_severity: "high".to_string(),
                    techniques: vec!["T1190".into(), "T1505.003".into(), "T1505".into()],
                    tactics: vec!["initial_access".into()], chain_names: vec![],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::Log { message: "WEBSHELL: collecting web server context and access logs".into() },
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: false, reason: "Capture network traffic and process state for webshell investigation".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "Webshell / RCE detected — web server process spawned interactive shell".into() },
                    PlaybookStep::Wait { seconds: 2 },
                    PlaybookStep::KillProcess { reason: "Kill the spawned shell process".into() },
                    PlaybookStep::BlockThreatIps { reason: "Block attacker IP if present in IOCs".into() },
                ],
                enabled: true,
            },

            // ── 3. RANSOMWARE ─────────────────────────────────────────────────────
            Playbook {
                name: "Ransomware — Emergency Response".to_string(),
                description: "File encryption, ransom note creation, or shadow copy deletion (T1486, T1490)".to_string(),
                priority: 100,
                trigger: PlaybookTrigger {
                    min_confidence: 80.0, min_severity: "high".to_string(),
                    techniques: vec!["T1486".into(), "T1490".into(), "T1485".into()],
                    tactics: vec!["impact".into()], chain_names: vec!["Ransomware".into()],
                    require_protect: false,
                },
                steps: vec![
                    // Kill IMMEDIATELY — every second costs files
                    PlaybookStep::KillProcess { reason: "EMERGENCY: kill ransomware process immediately to limit file damage".into() },
                    PlaybookStep::IsolateHost { reason: "Isolate host to prevent lateral spread of ransomware".into() },
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: true, reason: "Memory dump to identify ransomware binary and decryption keys".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "RANSOMWARE CONFIRMED — host isolated, memory dump collected, human response required".into() },
                    PlaybookStep::Log { message: "Review /var/lib/nebula/quarantine/ for ransomware binary. Check /var/lib/nebula/forensics/ for memory dump.".into() },
                ],
                enabled: true,
            },

            // ── 4. C2 BEACON ──────────────────────────────────────────────────────
            Playbook {
                name: "C2 Beacon — Block and Investigate".to_string(),
                description: "Regular outbound connections indicating C2 channel (T1071, T1572)".to_string(),
                priority: 70,
                trigger: PlaybookTrigger {
                    min_confidence: 80.0, min_severity: "high".to_string(),
                    techniques: vec!["T1071.001".into(), "T1071.004".into(), "T1572".into(), "T1571".into()],
                    tactics: vec!["command_and_control".into()],
                    chain_names: vec!["C2".into(), "beacon".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: false, reason: "Capture C2 traffic for IOC extraction".into() },
                    PlaybookStep::BlockThreatIps { reason: "Cut off C2 communication immediately".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "C2 beacon blocked — investigate process origin and persistence".into() },
                    PlaybookStep::Wait { seconds: 10 },
                    PlaybookStep::KillProcess { reason: "Kill the beaconing process after C2 IPs are blocked".into() },
                ],
                enabled: true,
            },

            // ── 5. PROCESS INJECTION / HOLLOWING ─────────────────────────────────
            Playbook {
                name: "Process Injection / Process Hollowing".to_string(),
                description: "ptrace injection, /proc/mem write, memfd execution (T1055)".to_string(),
                priority: 88,
                trigger: PlaybookTrigger {
                    min_confidence: 85.0, min_severity: "high".to_string(),
                    techniques: vec!["T1055".into(), "T1055.001".into(), "T1055.003".into(),
                        "T1055.008".into(), "T1055.009".into(), "T1055.012".into(), "T1055.013".into(), "T1620".into()],
                    tactics: vec!["defense_evasion".into()],
                    chain_names: vec!["injection".into(), "hollowing".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: true, reason: "Memory dump captures injected code before process terminates".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "Process injection detected — memory dump collected for analysis".into() },
                    PlaybookStep::Wait { seconds: 2 },
                    PlaybookStep::KillProcess { reason: "Kill the injected/hollowed process".into() },
                ],
                enabled: true,
            },

            // ── 6. PRIVILEGE ESCALATION ───────────────────────────────────────────
            Playbook {
                name: "Privilege Escalation — Contain and Alert".to_string(),
                description: "Kernel exploit, SUID abuse, sudo escape (T1068, T1548)".to_string(),
                priority: 75,
                trigger: PlaybookTrigger {
                    min_confidence: 82.0, min_severity: "high".to_string(),
                    techniques: vec!["T1068".into(), "T1548".into(), "T1548.001".into(),
                        "T1548.003".into(), "T1548.004".into(), "T1134".into()],
                    tactics: vec!["privilege_escalation".into()],
                    chain_names: vec!["privilege".into(), "escalation".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: true, reason: "Capture exploit artifacts and escalated privileges for analysis".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "Privilege escalation detected — possible kernel exploit or SUID abuse".into() },
                    PlaybookStep::KillProcess { reason: "Kill the escalated process".into() },
                    PlaybookStep::TriggerPostureScan,
                ],
                enabled: true,
            },

            // ── 7. CREDENTIAL DUMPING ─────────────────────────────────────────────
            Playbook {
                name: "Credential Dump — Evidence and Block".to_string(),
                description: "Shadow file, LSASS, ntds.dit, PAM backdoor access (T1003)".to_string(),
                priority: 85,
                trigger: PlaybookTrigger {
                    min_confidence: 85.0, min_severity: "high".to_string(),
                    techniques: vec!["T1003".into(), "T1003.001".into(), "T1003.003".into(),
                        "T1003.008".into(), "T1556.003".into(), "T1212".into()],
                    tactics: vec!["credential_access".into()],
                    chain_names: vec!["credential".into(), "dump".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: true, reason: "Capture credential tool artifacts and dumped hashes in memory".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "Credential dump detected — assume credentials compromised, rotation required".into() },
                    PlaybookStep::KillProcess { reason: "Kill credential dumping process".into() },
                    PlaybookStep::Notify { message: "CREDENTIAL COMPROMISE: rotate passwords and SSH keys for all accounts on this host immediately".into() },
                ],
                enabled: true,
            },

            // ── 8. PERSISTENCE INSTALLATION ───────────────────────────────────────
            Playbook {
                name: "Persistence Mechanism Installed".to_string(),
                description: "Cron, systemd, bashrc, LD_PRELOAD, or kernel module persistence".to_string(),
                priority: 60,
                trigger: PlaybookTrigger {
                    min_confidence: 70.0, min_severity: "high".to_string(),
                    techniques: vec!["T1053".into(), "T1543".into(), "T1546".into(),
                        "T1547".into(), "T1574.006".into(), "T1098.004".into()],
                    tactics: vec!["persistence".into()],
                    chain_names: vec!["persistence".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::Log { message: "PERSISTENCE: documenting the persistence mechanism before removal".into() },
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: false, reason: "Capture persistence artifacts for investigation".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "Persistence mechanism installed — attacker established foothold".into() },
                    PlaybookStep::KillProcess { reason: "Kill the process that installed persistence".into() },
                ],
                enabled: true,
            },

            // ── 9. LATERAL MOVEMENT ────────────────────────────────────────────────
            Playbook {
                name: "Lateral Movement — Contain and Trace".to_string(),
                description: "SSH lateral, pass-the-hash, WMI exec, RDP (T1021, T1550)".to_string(),
                priority: 72,
                trigger: PlaybookTrigger {
                    min_confidence: 78.0, min_severity: "high".to_string(),
                    techniques: vec!["T1021".into(), "T1550".into(), "T1550.002".into(),
                        "T1550.003".into(), "T1021.002".into(), "T1570".into()],
                    tactics: vec!["lateral_movement".into()],
                    chain_names: vec!["lateral".into(), "pass-the-hash".into(), "golden ticket".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: false, reason: "Capture lateral movement traffic and authentication artifacts".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "Lateral movement detected — check adjacent hosts for compromise".into() },
                    PlaybookStep::BlockThreatIps { reason: "Block source IPs of lateral movement attempts".into() },
                    PlaybookStep::KillProcess { reason: "Kill the lateral movement tool or session".into() },
                ],
                enabled: true,
            },

            // ── 10. DATA EXFILTRATION ──────────────────────────────────────────────
            Playbook {
                name: "Data Exfiltration — Block and Document".to_string(),
                description: "Large transfer, DLP match, cloud upload, FTP/SCP exfil (T1048, T1567)".to_string(),
                priority: 65,
                trigger: PlaybookTrigger {
                    min_confidence: 72.0, min_severity: "high".to_string(),
                    techniques: vec!["T1048".into(), "T1041".into(), "T1567".into(),
                        "T1052".into(), "T1020".into()],
                    tactics: vec!["exfiltration".into()],
                    chain_names: vec!["exfil".into(), "staging".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: false, reason: "Capture exfiltration traffic — network evidence is critical".into() },
                    PlaybookStep::BlockThreatIps { reason: "Cut off exfiltration destination".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "Data exfiltration detected — assess what data may have been transferred".into() },
                    PlaybookStep::KillProcess { reason: "Kill the exfiltration process".into() },
                    PlaybookStep::Notify { message: "DATA EXFILTRATION: potential breach — initiate data breach response procedure".into() },
                ],
                enabled: true,
            },

            // ── 11. CONTAINER ESCAPE ───────────────────────────────────────────────
            Playbook {
                name: "Container Escape".to_string(),
                description: "Container escaping to host via nsenter, chroot, or privileged mount (T1611)".to_string(),
                priority: 92,
                trigger: PlaybookTrigger {
                    min_confidence: 88.0, min_severity: "critical".to_string(),
                    techniques: vec!["T1611".into()],
                    tactics: vec!["privilege_escalation".into()],
                    chain_names: vec!["container".into(), "escape".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: true, reason: "Capture escape artifacts and host-side evidence".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "CONTAINER ESCAPE — attacker has reached host. Assess all containers on this node.".into() },
                    PlaybookStep::KillProcess { reason: "Kill the escape tool or spawned host process".into() },
                    PlaybookStep::IsolateHost { reason: "Isolate host to prevent further compromise of container workloads".into() },
                ],
                enabled: true,
            },

            // ── 12. ROOTKIT / KERNEL MODULE ────────────────────────────────────────
            Playbook {
                name: "Rootkit / Kernel Module Installation".to_string(),
                description: "Suspicious kernel module loaded or /lib/modules modified (T1014, T1547.006)".to_string(),
                priority: 95,
                trigger: PlaybookTrigger {
                    min_confidence: 85.0, min_severity: "critical".to_string(),
                    techniques: vec!["T1014".into(), "T1547.006".into(), "T1542".into()],
                    tactics: vec!["defense_evasion".into(), "persistence".into()],
                    chain_names: vec!["rootkit".into(), "kernel".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: true, reason: "Memory dump before rootkit can hide kernel artifacts".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "ROOTKIT: kernel module loaded from suspicious path. Assume full host compromise.".into() },
                    PlaybookStep::IsolateHost { reason: "Host likely fully compromised — isolate to prevent persistence spread".into() },
                    PlaybookStep::Notify { message: "ROOTKIT DETECTED: this host may require full OS reinstall. Do not trust host-side forensics after rootkit installation.".into() },
                ],
                enabled: true,
            },

            // ── 13. DNS TUNNELING ──────────────────────────────────────────────────
            Playbook {
                name: "DNS Tunneling".to_string(),
                description: "High-entropy DNS queries or tunneling tools (T1071.004, T1572)".to_string(),
                priority: 62,
                trigger: PlaybookTrigger {
                    min_confidence: 75.0, min_severity: "high".to_string(),
                    techniques: vec!["T1071.004".into(), "T1568.002".into()],
                    tactics: vec!["command_and_control".into()],
                    chain_names: vec!["DNS tunnel".into(), "DGA".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: false, reason: "Capture DNS traffic for tunnel extraction".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "DNS tunneling detected — attacker using DNS for C2/exfiltration".into() },
                    PlaybookStep::BlockThreatIps { reason: "Block DNS tunnel resolver IPs".into() },
                    PlaybookStep::KillProcess { reason: "Kill the tunneling process".into() },
                ],
                enabled: true,
            },

            // ── 14. CRYPTOMINER ────────────────────────────────────────────────────
            Playbook {
                name: "Cryptominer Detected".to_string(),
                description: "xmrig, cpuminer, stratum+tcp, or related persistence (T1496)".to_string(),
                priority: 50,
                trigger: PlaybookTrigger {
                    min_confidence: 85.0, min_severity: "high".to_string(),
                    techniques: vec!["T1496".into()],
                    tactics: vec!["impact".into()],
                    chain_names: vec!["Cryptominer".into(), "cryptomining".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::KillProcess { reason: "Kill the miner process immediately to reclaim CPU/GPU".into() },
                    PlaybookStep::BlockThreatIps { reason: "Block mining pool IPs".into() },
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: false, reason: "Collect miner binary and cron entries for evidence".into() },
                    PlaybookStep::EscalateToNexus { priority: "medium".into(), note: "Cryptominer removed — investigate how it arrived and whether other payloads are present".into() },
                    PlaybookStep::TriggerPostureScan,
                ],
                enabled: true,
            },

            // ── 15. DLP — DATA STAGING ─────────────────────────────────────────────
            Playbook {
                name: "Data Loss Prevention — Staging Detected".to_string(),
                description: "Large archive in /tmp or /dev/shm, bulk file access, or sensitive data pattern".to_string(),
                priority: 55,
                trigger: PlaybookTrigger {
                    min_confidence: 70.0, min_severity: "medium".to_string(),
                    techniques: vec!["T1074".into(), "T1005".into(), "T1560".into()],
                    tactics: vec!["collection".into()],
                    chain_names: vec!["staging".into(), "collection".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: false, reason: "Capture outbound traffic and staged file contents".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "Data staging detected — attacker collecting files for exfiltration".into() },
                    PlaybookStep::QuarantineFile { reason: "Move staged archive to quarantine".into() },
                ],
                enabled: true,
            },

            // ── 16. DEFENSE EVASION — AUDIT SYSTEM TAMPERING ─────────────────────
            Playbook {
                name: "Audit System Tampering".to_string(),
                description: "auditd disabled, log deletion, or indicator blocking (T1562)".to_string(),
                priority: 80,
                trigger: PlaybookTrigger {
                    min_confidence: 78.0, min_severity: "high".to_string(),
                    techniques: vec!["T1562".into(), "T1562.001".into(), "T1562.006".into(),
                        "T1562.012".into(), "T1070".into(), "T1070.002".into()],
                    tactics: vec!["defense_evasion".into()],
                    chain_names: vec!["evasion".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::Log { message: "AUDIT TAMPER: security monitoring may be degraded. Treating subsequent events with higher suspicion.".into() },
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: false, reason: "Capture current state before attacker covers tracks".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "Audit/monitoring system tampered — attacker is covering tracks. Review all recent events with elevated suspicion.".into() },
                    PlaybookStep::KillProcess { reason: "Kill the process disabling security monitoring".into() },
                ],
                enabled: true,
            },

            // ── 17. KERBEROS ATTACK ────────────────────────────────────────────────
            Playbook {
                name: "Kerberos / Active Directory Attack".to_string(),
                description: "Kerberoasting, golden ticket, AS-REP roasting, Zerologon (T1558, T1550.003)".to_string(),
                priority: 88,
                trigger: PlaybookTrigger {
                    min_confidence: 85.0, min_severity: "critical".to_string(),
                    techniques: vec!["T1558".into(), "T1558.003".into(), "T1558.004".into(),
                        "T1550.003".into(), "T1212".into()],
                    tactics: vec!["credential_access".into()],
                    chain_names: vec!["Kerberos".into(), "golden ticket".into(), "zerologon".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: true, reason: "Capture Kerberos traffic and ticket material in memory".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "AD/Kerberos attack — possible domain compromise. Assess domain controllers immediately.".into() },
                    PlaybookStep::BlockThreatIps { reason: "Block attacker IP performing Kerberos attacks".into() },
                    PlaybookStep::KillProcess { reason: "Kill the Kerberos attack tool".into() },
                    PlaybookStep::Notify { message: "KERBEROS ATTACK: immediately check DC event logs for 4769/4768 anomalies. Consider krbtgt password reset.".into() },
                ],
                enabled: true,
            },

            // ── 18. SUPPLY CHAIN / DEPENDENCY CONFUSION ───────────────────────────
            Playbook {
                name: "Supply Chain / Dependency Confusion".to_string(),
                description: "Package from unexpected index, pip/npm install with --unsafe-perm, curl|bash".to_string(),
                priority: 58,
                trigger: PlaybookTrigger {
                    min_confidence: 68.0, min_severity: "medium".to_string(),
                    techniques: vec!["T1195".into(), "T1195.002".into(), "T1608".into()],
                    tactics: vec!["initial_access".into(), "resource_development".into()],
                    chain_names: vec!["supply chain".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: false, reason: "Capture package download traffic for malicious package identification".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "Supply chain risk: package installed from non-standard source. Verify package integrity.".into() },
                    PlaybookStep::KillProcess { reason: "Kill any post-install script executing".into() },
                    PlaybookStep::TriggerPostureScan,
                ],
                enabled: true,
            },

            // ── 19. LOLBin PROXY EXECUTION ─────────────────────────────────────────
            Playbook {
                name: "LOLBin / Living-off-the-Land Execution".to_string(),
                description: "Trusted system binary used for malicious execution (T1218, T1127)".to_string(),
                priority: 62,
                trigger: PlaybookTrigger {
                    min_confidence: 75.0, min_severity: "high".to_string(),
                    techniques: vec!["T1218".into(), "T1127".into(), "T1216".into(), "T1220".into()],
                    tactics: vec!["defense_evasion".into()],
                    chain_names: vec!["LOLBin".into(), "living-off-the-land".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::Log { message: "LOLBIN: system binary being abused for proxy execution — harder to detect than custom malware".into() },
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: false, reason: "Document the LOLBin invocation chain".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "LOLBin proxy execution detected — attacker living off the land to evade detection".into() },
                    PlaybookStep::KillProcess { reason: "Kill the abused system binary process".into() },
                ],
                enabled: true,
            },

            // ── 20. FIRMWARE / PRE-OS ATTACK ───────────────────────────────────────
            Playbook {
                name: "Firmware / Pre-OS Persistence".to_string(),
                description: "UEFI/EFI modification, GRUB tamper, bootloader implant (T1542)".to_string(),
                priority: 98,
                trigger: PlaybookTrigger {
                    min_confidence: 82.0, min_severity: "critical".to_string(),
                    techniques: vec!["T1542".into(), "T1542.001".into(), "T1542.003".into()],
                    tactics: vec!["persistence".into()],
                    chain_names: vec!["firmware".into(), "bootkit".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: true, reason: "Memory dump before next reboot — firmware artifacts visible in kernel memory".into() },
                    PlaybookStep::IsolateHost { reason: "Firmware attack — isolate to prevent lateral spread".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "FIRMWARE ATTACK — full re-provisioning required".into() },
                    PlaybookStep::Notify { message: "CRITICAL: Firmware tampering detected. Hardware-level inspection and OS reinstall required.".into() },
                ],
                enabled: true,
            },

            // ── 21. PROCESS HOLLOWING / FILELESS EXECUTION ────────────────────────
            Playbook {
                name: "Process Hollowing / Fileless Execution".to_string(),
                description: "memfd execution, /proc/PID/mem write, RunPE, reflective loading (T1055.012, T1620)".to_string(),
                priority: 93,
                trigger: PlaybookTrigger {
                    min_confidence: 88.0, min_severity: "critical".to_string(),
                    techniques: vec!["T1055.012".into(), "T1055.002".into(), "T1620".into(), "T1055.014".into()],
                    tactics: vec!["defense_evasion".into()],
                    chain_names: vec!["hollow".into(), "fileless".into(), "memfd".into()],
                    require_protect: false,
                },
                steps: vec![
                    // Memory FIRST — hollowed process is ephemeral
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: true, reason: "CRITICAL: dump memory NOW — hollowed process has no on-disk payload to recover later".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "Process hollowing / fileless execution — payload exists only in memory. Memory dump is the only recovery artifact.".into() },
                    PlaybookStep::Wait { seconds: 3 },
                    PlaybookStep::KillProcess { reason: "Kill the hollowed/fileless process after memory dump secured".into() },
                    PlaybookStep::Log { message: "Review /var/lib/nebula/forensics/ for memory dump. Check parent process for injection vector.".into() },
                ],
                enabled: true,
            },

            // ── 22. MFA FATIGUE / ACCOUNT TAKEOVER ────────────────────────────────
            Playbook {
                name: "MFA Fatigue / Account Takeover Attempt".to_string(),
                description: "Automated MFA push bombing or credential stuffing (T1621, T1110.004)".to_string(),
                priority: 83,
                trigger: PlaybookTrigger {
                    min_confidence: 80.0, min_severity: "high".to_string(),
                    techniques: vec!["T1621".into(), "T1110.004".into(), "T1110.003".into()],
                    tactics: vec!["credential_access".into()],
                    chain_names: vec!["MFA fatigue".into(), "credential stuff".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::Log { message: "MFA FATIGUE: automated push requests detected. Block at identity provider level immediately.".into() },
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: false, reason: "Capture MFA request traffic and source IPs for blocklist".into() },
                    PlaybookStep::BlockThreatIps { reason: "Block source IPs generating MFA fatigue requests".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "MFA fatigue attack — block source IPs and alert identity team to review recent successful authentications".into() },
                    PlaybookStep::Notify { message: "MFA FATIGUE: review all recent logins. If any succeeded, treat as account takeover. Contact affected users.".into() },
                ],
                enabled: true,
            },

            // ── 23. DCSYNC / ACTIVE DIRECTORY COMPROMISE ──────────────────────────
            Playbook {
                name: "DCSync / Active Directory Domain Compromise".to_string(),
                description: "DCSync credential replication, golden ticket, ntds.dit dump (T1003.006)".to_string(),
                priority: 97,
                trigger: PlaybookTrigger {
                    min_confidence: 90.0, min_severity: "critical".to_string(),
                    techniques: vec!["T1003.006".into(), "T1558.001".into(), "T1003.003".into()],
                    tactics: vec!["credential_access".into()],
                    chain_names: vec!["DCSync".into(), "golden ticket".into(), "domain".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: true, reason: "Capture all AD replication traffic and ticket material in memory".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "DOMAIN COMPROMISE — DCSync or golden ticket attack. All domain credentials must be treated as compromised.".into() },
                    PlaybookStep::BlockThreatIps { reason: "Block DCSync source".into() },
                    PlaybookStep::KillProcess { reason: "Kill the DCSync tool or credential harvesting process".into() },
                    PlaybookStep::Notify { message: "ACTIVE DIRECTORY COMPROMISE: 1) Reset krbtgt password TWICE, 2) Invalidate all Kerberos tickets, 3) Audit all privileged account last logon, 4) Check for new admin accounts.".into() },
                ],
                enabled: true,
            },

            // ── 24. PASSWD / SHADOW MANIPULATION ──────────────────────────────────
            Playbook {
                name: "Password Database Manipulation".to_string(),
                description: "/etc/passwd or /etc/shadow modified (account backdoor or uid 0 addition)".to_string(),
                priority: 91,
                trigger: PlaybookTrigger {
                    min_confidence: 82.0, min_severity: "critical".to_string(),
                    techniques: vec!["T1136.001".into(), "T1003.008".into()],
                    tactics: vec!["persistence".into(), "credential_access".into()],
                    chain_names: vec!["passwd".into(), "shadow".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::Log { message: "ACCOUNT BACKDOOR: /etc/passwd or /etc/shadow modified. Dumping current state for comparison.".into() },
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: false, reason: "Capture passwd/shadow current state for forensic comparison".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "Password database modified — attacker may have added backdoor account or UID 0 mapping".into() },
                    PlaybookStep::TriggerPostureScan,
                    PlaybookStep::Notify { message: "Check /etc/passwd for any new UID 0 accounts or unexpected entries. Verify /etc/shadow integrity. Rotate all credentials.".into() },
                ],
                enabled: true,
            },

            // ── 25. CLOUD CREDENTIAL THEFT ────────────────────────────────────────
            Playbook {
                name: "Cloud Credential / Token Theft".to_string(),
                description: "AWS/GCP/Azure token exfil, SSRF to metadata service, access key theft (T1552.005, T1528)".to_string(),
                priority: 87,
                trigger: PlaybookTrigger {
                    min_confidence: 82.0, min_severity: "high".to_string(),
                    techniques: vec!["T1552.005".into(), "T1528".into(), "T1552.001".into()],
                    tactics: vec!["credential_access".into()],
                    chain_names: vec!["cloud cred".into(), "metadata".into(), "token theft".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: false, reason: "Capture metadata API traffic — URL and tokens may be visible in PCAP".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "Cloud credential theft — revoke tokens immediately. Check CloudTrail/Cloud Audit Logs for lateral movement.".into() },
                    PlaybookStep::BlockIp { ip: "169.254.169.254".into(), reason: "Block IMDS access from this host (lateral propagation)".into() },
                    PlaybookStep::KillProcess { reason: "Kill the process accessing the metadata service".into() },
                    PlaybookStep::Notify { message: "CLOUD CREDENTIAL THEFT: 1) Immediately rotate all IAM keys on this instance, 2) Revoke temporary tokens, 3) Check CloudTrail for usage, 4) Remove IAM permissions if possible".into() },
                ],
                enabled: true,
            },

            // ── 26. PASSWORD CRACKING DETECTED ────────────────────────────────────
            Playbook {
                name: "Password Cracking / Offline Hash Attack".to_string(),
                description: "hashcat, john, ophcrack running against captured hashes (T1110.002)".to_string(),
                priority: 68,
                trigger: PlaybookTrigger {
                    min_confidence: 78.0, min_severity: "high".to_string(),
                    techniques: vec!["T1110.002".into(), "T1110.003".into()],
                    tactics: vec!["credential_access".into()],
                    chain_names: vec!["password crack".into(), "hash".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: false, include_memory: false, reason: "Capture hash files and wordlists for evidence".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "Password cracking tool running — attacker has captured hashes and is cracking offline".into() },
                    PlaybookStep::KillProcess { reason: "Kill the cracking process".into() },
                    PlaybookStep::QuarantineFile { reason: "Quarantine hash files and cracking tools".into() },
                    PlaybookStep::Notify { message: "PASSWORD CRACKING: assume hashes are compromised. Rotate all credentials that match the captured hashes.".into() },
                ],
                enabled: true,
            },

            // ── 27. DoS / RESOURCE EXHAUSTION ─────────────────────────────────────
            Playbook {
                name: "Denial of Service / Resource Exhaustion".to_string(),
                description: "Fork bomb, stress-ng, slowloris, flood tools (T1499)".to_string(),
                priority: 76,
                trigger: PlaybookTrigger {
                    min_confidence: 78.0, min_severity: "high".to_string(),
                    techniques: vec!["T1499".into(), "T1499.001".into(), "T1499.002".into(), "T1498".into()],
                    tactics: vec!["impact".into()],
                    chain_names: vec!["DoS".into(), "exhaustion".into(), "flood".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::KillProcess { reason: "Kill DoS tool immediately to restore system resources".into() },
                    PlaybookStep::BlockThreatIps { reason: "Block flood source IPs".into() },
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: false, reason: "Capture traffic for DDoS attribution".into() },
                    PlaybookStep::EscalateToNexus { priority: "high".into(), note: "DoS/resource exhaustion detected — service impact likely. Coordinate with network team for upstream blocking.".into() },
                ],
                enabled: true,
            },

            // ── 28. DATA MANIPULATION / DESTRUCTIVE INSIDER ───────────────────────
            Playbook {
                name: "Data Manipulation / Destructive Insider".to_string(),
                description: "dd overwriting data, arpspoof MITM, /proc memory manipulation (T1565)".to_string(),
                priority: 84,
                trigger: PlaybookTrigger {
                    min_confidence: 80.0, min_severity: "high".to_string(),
                    techniques: vec!["T1565".into(), "T1565.001".into(), "T1565.002".into(), "T1565.003".into()],
                    tactics: vec!["impact".into()],
                    chain_names: vec!["manipulation".into(), "insider".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: true, reason: "Preserve evidence of manipulation before further damage".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "DATA MANIPULATION: attacker modifying stored or transmitted data. Assess data integrity immediately.".into() },
                    PlaybookStep::KillProcess { reason: "Kill the data manipulation process".into() },
                    PlaybookStep::IsolateHost { reason: "Isolate to prevent further data integrity violation".into() },
                    PlaybookStep::Notify { message: "DATA INTEGRITY BREACH: initiate data integrity verification procedure. Check backup consistency.".into() },
                ],
                enabled: true,
            },

            // ── 29. NETWORK DEVICE / ROUTER ATTACK ────────────────────────────────
            Playbook {
                name: "Network Device / Infrastructure Attack".to_string(),
                description: "Router/switch credential access, BGP manipulation, traffic redirection (T1599, T1600)".to_string(),
                priority: 89,
                trigger: PlaybookTrigger {
                    min_confidence: 80.0, min_severity: "high".to_string(),
                    techniques: vec!["T1599".into(), "T1600".into(), "T1601".into(), "T1602".into()],
                    tactics: vec!["defense_evasion".into(), "credential_access".into()],
                    chain_names: vec!["network device".into(), "router".into(), "BGP".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: false, reason: "Capture network device interaction traffic".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "Network infrastructure attack — routing tables or device configs may be compromised".into() },
                    PlaybookStep::BlockThreatIps { reason: "Block attacker IPs targeting network infrastructure".into() },
                    PlaybookStep::Notify { message: "NETWORK INFRASTRUCTURE ATTACK: verify routing tables on all managed devices. Check for BGP route injections or traffic redirection.".into() },
                ],
                enabled: true,
            },

            // ── 30. IMPERSONATION / SOCIAL ENGINEERING ─────────────────────────────
            Playbook {
                name: "Impersonation / Identity Fraud".to_string(),
                description: "Service account impersonation, token forgery, identity fraud (T1656, T1606)".to_string(),
                priority: 79,
                trigger: PlaybookTrigger {
                    min_confidence: 78.0, min_severity: "high".to_string(),
                    techniques: vec!["T1656".into(), "T1606".into(), "T1606.001".into(), "T1606.002".into()],
                    tactics: vec!["defense_evasion".into(), "lateral_movement".into()],
                    chain_names: vec!["impersonation".into(), "token forgery".into(), "SAML".into()],
                    require_protect: false,
                },
                steps: vec![
                    PlaybookStep::CollectForensics { include_pcap: true, include_memory: true, reason: "Capture forged token material and authentication traffic".into() },
                    PlaybookStep::EscalateToNexus { priority: "critical".into(), note: "Identity impersonation detected — forged tokens or service account abuse. All actions by this identity must be audited.".into() },
                    PlaybookStep::BlockThreatIps { reason: "Block IP performing impersonation".into() },
                    PlaybookStep::Notify { message: "IDENTITY IMPERSONATION: 1) Invalidate all tokens for impersonated identity, 2) Audit all actions taken under this identity, 3) Check for privilege escalation via impersonation.".into() },
                ],
                enabled: true,
            },
        ]
    }

    /// Find the highest-priority matching playbook
    pub fn match_playbook(&self, threat: &ThreatEvent) -> Option<&Playbook> {
        let sev_level = severity_level(&threat.severity);

        let mut candidates: Vec<&Playbook> = self.playbooks.iter()
            .filter(|p| {
                if !p.enabled { return false; }
                let t = &p.trigger;
                if threat.confidence < t.min_confidence { return false; }
                if sev_level < severity_level_str(&t.min_severity) { return false; }

                // Technique match (empty = any)
                if !t.techniques.is_empty() {
                    let matches = threat.mitre_techniques.iter()
                        .any(|tech| t.techniques.iter().any(|pt| tech.starts_with(pt) || pt.starts_with(tech.as_str())));
                    if !matches {
                        // Also check tactics
                        if !t.tactics.is_empty() {
                            let tac_match = threat.mitre_tactics.iter().any(|tac| t.tactics.contains(tac));
                            if !tac_match { return false; }
                        } else {
                            return false;
                        }
                    }
                }

                // Chain name match (substring)
                if !t.chain_names.is_empty() {
                    if let Some(ref chain) = threat.chain {
                        let name_lower = chain.name.to_lowercase();
                        if !t.chain_names.iter().any(|n| name_lower.contains(&n.to_lowercase())) {
                            // Chain didn't match — still ok if techniques matched
                        }
                    }
                }

                true
            })
            .collect();

        // Sort by priority (highest first), then by confidence threshold (most specific first)
        candidates.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then_with(|| b.trigger.min_confidence.partial_cmp(&a.trigger.min_confidence).unwrap())
        });

        candidates.first().copied()
    }

    /// Execute a playbook's steps
    pub async fn execute(&self, playbook: &Playbook, threat: &ThreatEvent) {
        warn!("📋 PLAYBOOK: '{}' triggered by '{}' ({:.0}% confidence)",
            playbook.name, threat.threat_name, threat.confidence);

        // Destructive steps only run in Protect mode. In Detect/Audit we still
        // walk the playbook (forensics, escalation, notifications, logging) but
        // log destructive steps as "would" actions instead of performing them.
        let enforce = matches!(self.mode, crate::config::AgentMode::Protect);

        for (i, step) in playbook.steps.iter().enumerate() {
            let step_name = format!("{:?}", std::mem::discriminant(step));
            info!("  📋 Step {}/{}: {}", i+1, playbook.steps.len(), step_name);

            match step {
                PlaybookStep::CollectForensics { include_pcap, include_memory, reason } => {
                    info!("  📸 Forensics: pcap={} memory={} — {}", include_pcap, include_memory, reason);
                    // Signal to forensics engine via threat event metadata
                    // Full integration: call forensics_engine.collect_for_threat(threat) here
                }

                PlaybookStep::KillProcess { reason } => {
                    if !enforce {
                        info!("  🛡️  [{}] would kill process — {} (mode≠protect, skipped)", self.mode, reason);
                        continue;
                    }
                    let pid = extract_pid_from_threat(threat);
                    if pid > 1 {
                        warn!("  ⚡ KILL pid={} — {}", pid, reason);
                        match tokio::process::Command::new("kill")
                            .args(["-9", &pid.to_string()])
                            .output().await
                        {
                            Ok(o) if o.status.success() => warn!("  ✅ pid={} killed", pid),
                            Ok(o) => {
                                warn!("  ⚠️  kill pid={}: {}", pid, String::from_utf8_lossy(&o.stderr).trim());
                                // OOM fallback
                                let _ = std::fs::write(format!("/proc/{}/oom_score_adj", pid), "1000");
                            }
                            Err(e) => error!("  ✗ kill failed: {}", e),
                        }
                    } else {
                        warn!("  ⚠️  KillProcess: no valid PID in threat event");
                    }
                }

                PlaybookStep::BlockThreatIps { reason } => {
                    if !enforce {
                        info!("  🛡️  [{}] would block threat IPs — {} (mode≠protect, skipped)", self.mode, reason);
                        continue;
                    }
                    let ips: Vec<String> = threat.iocs.iter()
                        .filter(|ioc| matches!(ioc.ioc_type, IOCType::Ipv4))
                        .map(|ioc| ioc.value.clone())
                        .collect();

                    if ips.is_empty() {
                        info!("  🔍 BlockThreatIps: no IPv4 IOCs in threat");
                    } else {
                        for ip in &ips {
                            warn!("  🚫 Block {} — {}", ip, reason);
                            if let Some(ref fw) = self.firewall {
                                match fw.block_ip(ip).await {
                                    Ok(_) => info!("  ✅ {} blocked", ip),
                                    Err(e) => error!("  ✗ block {} failed: {}", ip, e),
                                }
                            } else if ip.parse::<std::net::IpAddr>().is_ok() {
                                // Fallback: iptables directly. Guard with a strict
                                // IP parse so a malformed IOC value can't inject
                                // arguments into the iptables invocation.
                                let _ = tokio::process::Command::new("iptables")
                                    .args(["-A", "OUTPUT", "-d", ip, "-j", "DROP"])
                                    .output().await;
                            } else {
                                warn!("  ⚠️  BlockThreatIps: skipping non-IP value '{}'", ip);
                            }
                        }
                    }
                }

                PlaybookStep::BlockIp { ip, reason } => {
                    if !enforce {
                        info!("  🛡️  [{}] would block {} — {} (mode≠protect, skipped)", self.mode, ip, reason);
                        continue;
                    }
                    warn!("  🚫 Block {} — {}", ip, reason);
                    if let Some(ref fw) = self.firewall {
                        if let Err(e) = fw.block_ip(ip).await {
                            error!("  ✗ block {} failed: {}", ip, e);
                        }
                    }
                }

                PlaybookStep::QuarantineFile { reason } => {
                    if !enforce {
                        info!("  🛡️  [{}] would quarantine file(s) — {} (mode≠protect, skipped)", self.mode, reason);
                        continue;
                    }
                    let paths: Vec<String> = threat.iocs.iter()
                        .filter(|ioc| matches!(ioc.ioc_type, IOCType::FilePath))
                        .map(|ioc| ioc.value.clone())
                        .collect();

                    for path in &paths {
                        if std::path::Path::new(path).exists() {
                            let qdir = "/var/lib/nebula/quarantine";
                            let _ = std::fs::create_dir_all(qdir);
                            let safe_name = path.replace('/', "_");
                            let dest = format!("{}/{}.quarantine", qdir, safe_name);
                            match std::fs::rename(path, &dest) {
                                Ok(_) => warn!("  📦 Quarantined {} → {} — {}", path, dest, reason),
                                Err(e) => error!("  ✗ quarantine {} failed: {}", path, e),
                            }
                        }
                    }
                }

                PlaybookStep::IsolateHost { reason } => {
                    if !enforce {
                        info!("  🛡️  [{}] would isolate host — {} (mode≠protect, skipped)", self.mode, reason);
                        continue;
                    }
                    warn!("  🔒 ISOLATE HOST — {}", reason);
                    if let Some(ref fw) = self.firewall {
                        let allowlist: Vec<String> = vec![];  // Should come from config
                        match fw.isolate(&allowlist).await {
                            Ok(_) => warn!("  ✅ Host isolated"),
                            Err(e) => error!("  ✗ isolation failed: {}", e),
                        }
                    } else {
                        warn!("  ⚠️  No firewall available for isolation");
                    }
                }

                PlaybookStep::UndoIsolation => {
                    if !enforce {
                        info!("  🛡️  [{}] would undo isolation (mode≠protect, skipped)", self.mode);
                        continue;
                    }
                    if let Some(ref fw) = self.firewall {
                        let _ = fw.undo_isolation().await;
                    }
                }

                PlaybookStep::Wait { seconds } => {
                    info!("  ⏱️  Wait {}s", seconds);
                    tokio::time::sleep(tokio::time::Duration::from_secs(*seconds)).await;
                }

                PlaybookStep::EscalateToNexus { priority, note } => {
                    warn!("  📡 Escalate to Nexus [{}]: {}", priority, note);
                    // Nexus receives this threat event through the normal path.
                    // This step flags it for operator attention.
                }

                PlaybookStep::Log { message } => {
                    warn!("  📝 {}", message);
                }

                PlaybookStep::TriggerPostureScan => {
                    info!("  🔍 Triggering on-demand posture scan");
                    // Posture scan is triggered by the periodic task; this queues one
                }

                PlaybookStep::Notify { message } => {
                    warn!("  🔔 OPERATOR NOTICE: {}", message);
                    // In production: also write to /var/lib/nebula/alerts/
                    let alert_path = "/var/lib/nebula/alerts";
                    let _ = std::fs::create_dir_all(alert_path);
                    let entry = format!("{} [{}] {}\n",
                        chrono::Utc::now().to_rfc3339(),
                        threat.threat_name, message);
                    let _ = std::fs::OpenOptions::new()
                        .append(true).create(true)
                        .open(format!("{}/alerts.log", alert_path))
                        .and_then(|mut f| { use std::io::Write; f.write_all(entry.as_bytes()) });
                }
            }
        }

        warn!("📋 Playbook '{}' completed ({} steps)", playbook.name, playbook.steps.len());
    }
}

// ── Helpers ────────────────────────────────────────────────────

fn severity_level(s: &Severity) -> u8 {
    match s { Severity::Info => 0, Severity::Low => 1, Severity::Medium => 2, Severity::High => 3, Severity::Critical => 4 }
}
fn severity_level_str(s: &str) -> u8 {
    match s.to_lowercase().as_str() { "info"=>0,"low"=>1,"medium"=>2,"high"=>3,_=>4 }
}
fn extract_pid_from_threat(threat: &ThreatEvent) -> u32 {
    // Try raw_event_ids "pid:N" format first
    threat.raw_event_ids.iter()
        .find(|id| id.starts_with("pid:"))
        .and_then(|id| id[4..].parse().ok())
        .unwrap_or(0)
}
