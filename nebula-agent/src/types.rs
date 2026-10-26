// src/types.rs — Shared event and threat types for NebulaSentinel agent

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

// ── Raw collected event ────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub id: String,
    pub agent_id: String,
    pub hostname: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub process_name: String,
    pub process_path: Option<String>,
    pub command_line: Option<String>,
    pub parent_process: Option<String>,
    pub file_path: Option<String>,
    pub file_hash: Option<String>,
    pub network_dest_ip: Option<String>,
    pub network_dest_port: Option<u16>,
    pub network_proto: Option<String>,
    pub syscall: Option<String>,
    pub return_code: Option<i64>,
    pub container_id: Option<String>,
    pub namespace: Option<String>,
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ProcessExec,
    ProcessExit,
    FileOpen,
    FileWrite,
    FileDelete,
    NetworkConnect,
    NetworkBind,
    NetworkDns,
    SyscallAnomalous,
    ModuleLoad,
    UserAuth,
    UserSu,
    CronJob,
    DockerExec,
    RawPacket,
    MemoryMap,
    Ptrace,
    Simulated,
}

// ── Enriched threat event (what gets sent to Nexus) ───────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String,
    pub agent_id: String,
    pub hostname: String,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub confidence: f32,
    pub threat_name: String,
    pub description: String,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub matched_rules: Vec<String>,
    pub raw_event_ids: Vec<String>,
    pub chain: Option<AttackChain>,
    pub iocs: Vec<IOC>,
    pub suggested_action: ResponseAction,
    pub llm_analysis: Option<String>,
    pub auto_generated_rule: Option<DetectionRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info     => write!(f, "INFO"),
            Severity::Low      => write!(f, "LOW"),
            Severity::Medium   => write!(f, "MEDIUM"),
            Severity::High     => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ── Attack chain ──────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub name: String,
    pub stages: Vec<ChainStage>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStage {
    pub tactic: String,
    pub technique: String,
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub description: String,
}

// ── IOC ───────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOC {
    pub ioc_type: IOCType,
    pub value: String,
    pub source: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IOCType {
    Md5,
    Sha1,
    Sha256,
    Ipv4,
    Ipv6,
    Domain,
    Url,
    FilePath,
    ProcessName,
    RegistryKey,
    YaraRule,
}

// ── Response actions ──────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseAction {
    Monitor,
    Alert,
    KillProcess(u32),
    QuarantineFile(String),
    IsolateHost,
    BlockIp(String),
    CollectForensics,
    Rollback,
}

impl std::fmt::Display for ResponseAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseAction::Monitor          => write!(f, "MONITOR"),
            ResponseAction::Alert            => write!(f, "ALERT"),
            ResponseAction::KillProcess(p)  => write!(f, "KILL_PID:{}", p),
            ResponseAction::QuarantineFile(p) => write!(f, "QUARANTINE:{}", p),
            ResponseAction::IsolateHost      => write!(f, "ISOLATE_HOST"),
            ResponseAction::BlockIp(ip)     => write!(f, "BLOCK_IP:{}", ip),
            ResponseAction::CollectForensics => write!(f, "COLLECT_FORENSICS"),
            ResponseAction::Rollback         => write!(f, "ROLLBACK"),
        }
    }
}

// ── Auto-generated detection rule ────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub rule_type: RuleType,
    pub name: String,
    pub severity: Severity,
    pub content: String,
    pub generated_from_event: String,
    pub generated_at: DateTime<Utc>,
    pub approved: bool,           // false until human approves on Nexus
    pub deployed_to: Vec<String>, // agent IDs
    pub llm_reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleType {
    Yara,
    Sigma,
    Wazuh,
    Custom,
}

// ── Posture / vulnerability ───────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureReport {
    pub agent_id: String,
    pub hostname: String,
    pub timestamp: DateTime<Utc>,
    pub overall_score: f32,
    pub vulnerability_count: u32,
    pub vulnerabilities: Vec<Vulnerability>,
    pub compliance_scores: HashMap<String, f32>,
    pub hardening_recommendations: Vec<HardeningItem>,
    pub inventory_summary: Option<InventorySummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve: String,
    pub package: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub cvss_score: f32,
    pub severity: Severity,
    pub description: String,
    pub published: Option<DateTime<Utc>>,
    pub affected_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningItem {
    pub control_id: String,
    pub framework: String,
    pub title: String,
    pub status: ComplianceStatus,
    pub current_value: Option<String>,
    pub expected_value: String,
    pub remediation: String,
    pub auto_fixable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Pass,
    Fail,
    NotApplicable,
    Manual,
    Unknown,
}

// ── Inventory ─────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventorySummary {
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    pub mac_addresses: Vec<String>,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub domain: Option<String>,
    pub uptime_secs: u64,
    pub cpu_model: String,
    pub ram_mb: u64,
    pub installed_packages: u32,
    pub running_processes: u32,
    pub open_ports: Vec<u16>,
    pub users: Vec<String>,
    pub containers: Vec<ContainerInfo>,
    pub file_catalog_count: u64,
    #[serde(default)]
    pub package_list: Vec<PackageEntry>,
    #[serde(default)]
    pub process_list: Vec<ProcessEntry>,
    #[serde(default)]
    pub routes: Vec<RouteEntry>,
    #[serde(default)]
    pub arp_neighbors: Vec<ArpEntry>,
    #[serde(default)]
    pub network_peers: Vec<NetworkPeer>,
}

/// A remote endpoint this host has an active network connection with, with
/// process attribution and direction. Built from /proc/net/tcp{,6}.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPeer {
    pub remote_ip: String,
    pub remote_port: u16,
    pub proto: String,           // tcp / tcp6
    pub direction: String,       // inbound / outbound
    pub process: String,         // best-effort process name
    pub pid: u32,
    pub scope: String,           // internal / external
    pub state: String,           // ESTABLISHED, LISTEN, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageEntry {
    pub name: String,
    pub version: String,
    pub manager: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub id: String,
    pub image: String,
    pub status: String,
    pub created: Option<DateTime<Utc>>,
}

// ── Gossip message ────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub from_agent: String,
    pub from_hostname: String,
    pub timestamp: DateTime<Utc>,
    pub msg_type: GossipMsgType,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GossipMsgType {
    IocAlert,
    ThreatScore,
    PeerList,
    Heartbeat,
    RuleProposal,
}

// ── Nexus command (received from Nexus) ───────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NexusCommand {
    pub id: String,
    pub command: NexusCommandType,
    pub payload: Option<serde_json::Value>,
    pub issued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum NexusCommandType {
    // Diagnostics
    Ping,
    // Detection
    DeployRule,
    RunRetroHunt,
    // Posture & inventory
    RunPostureScan,
    RunInventory,
    // Forensics
    CollectForensics,
    FetchArtifact,
    CaptureSample,
    // Response actions (require protect mode or explicit override)
    IsolateHost,
    UndoIsolation,
    BlockIp,
    UnblockIp,
    KillProcess,
    QuarantineFile,
    // Configuration
    SetMode,
    UpdateConfig,
    ApplyPolicy,
}
