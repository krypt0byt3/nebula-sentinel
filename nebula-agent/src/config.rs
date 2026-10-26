use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    #[serde(default)]
    pub iac_paths: Option<Vec<String>>,
    /// VirusTotal API key for file-hash reputation lookups. When unset (the
    /// default), VirusTotal is disabled — the reputation engine relies on the
    /// local blocklist, YARA, and entropy heuristics only (air-gap safe).
    #[serde(default)]
    pub virustotal_api_key: Option<String>,
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default)]
    pub agent_id: String,
    /// Detected at runtime — linux | windows | macos
    #[serde(default = "default_platform")]
    pub platform: String,
    #[serde(default = "default_mode")]
    pub mode: AgentMode,

    #[serde(default = "default_nexus")]
    pub nexus: NexusConfig,
    #[serde(default = "default_llm")]
    pub llm: LLMConfig,
    #[serde(default = "default_collector")]
    pub collector: CollectorConfig,
    #[serde(default)]
    pub detection: DetectionConfig,
    #[serde(default = "default_anomaly")]
    pub anomaly: AnomalyConfig,
    #[serde(default = "default_rules")]
    pub rules: RulesConfig,
    #[serde(default = "default_response")]
    pub response: ResponseConfig,
    #[serde(default = "default_forensics")]
    pub forensics: ForensicsConfig,
    #[serde(default = "default_inventory")]
    pub inventory: InventoryConfig,
    #[serde(default = "default_posture")]
    pub posture: PostureConfig,
    #[serde(default = "default_hardening")]
    pub hardening: HardeningConfig,
    #[serde(default = "default_retro")]
    pub retro: RetroConfig,
    #[serde(default = "default_gossip")]
    pub gossip: GossipConfig,
    #[serde(default = "default_self_protect")]
    pub self_protect: SelfProtectConfig,
    #[serde(default = "default_memory")]
    pub memory: MemoryConfig,
    #[serde(default = "default_legacy")]
    pub legacy: LegacyConfig,
    #[serde(default = "default_branding")]
    pub branding: BrandingConfig,
}

fn default_mode() -> AgentMode { AgentMode::Detect }
fn default_hostname() -> String {
    // Try system hostname, fall back to /etc/hostname, then "unknown-host"
    sysinfo::System::host_name()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok()
            .map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "unknown-host".to_string())
}
fn default_platform() -> String { detect_platform() }
pub fn detect_platform() -> String {
    if cfg!(target_os = "windows") { "windows".to_string() }
    else if cfg!(target_os = "macos") { "macos".to_string() }
    else { "linux".to_string() }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AgentMode {
    Detect,
    Protect,
    Audit,
}

impl std::fmt::Display for AgentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentMode::Detect  => write!(f, "DETECT"),
            AgentMode::Protect => write!(f, "PROTECT"),
            AgentMode::Audit   => write!(f, "AUDIT"),
        }
    }
}

// ── Nexus ─────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NexusConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_nexus_url")]
    pub url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_report_interval")]
    pub report_interval_secs: u64,
    /// How often (seconds) to flush buffered events from the local DB to Nexus.
    /// Lower = fresher data on the Nexus; higher = fewer, larger batches.
    #[serde(default = "default_flush_interval")]
    pub event_flush_interval_secs: u64,
    /// Queue-first mode: when true, every event is written to the local SQLite
    /// buffer first and flushed to Nexus on the interval below. Guarantees no
    /// event is lost across restarts/outages, at the cost of up to one flush
    /// interval of delay before events appear on the Nexus.
    ///
    /// Default false: events send immediately (lowest latency for the SOC), and
    /// the local queue is still used automatically as failover when the Nexus is
    /// unreachable — so you get durability without the delay. Turn this on only
    /// if you specifically want every event batched through the local buffer.
    #[serde(default)]
    pub buffer_events_locally: bool,
    #[serde(default = "default_true")]
    pub tls_verify: bool,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    #[serde(default = "default_true")]
    pub atc_mode: bool,
    #[serde(default)]
    pub legacy_syslog_enabled: bool,
    #[serde(default)]
    pub legacy_syslog_host: String,
    #[serde(default = "default_514")]
    pub legacy_syslog_port: u16,
    #[serde(default = "default_udp")]
    pub legacy_syslog_proto: String,
}
fn default_report_interval() -> u64 { 30 }
fn default_flush_interval() -> u64 { 30 }
fn default_514() -> u16 { 514 }
fn default_udp() -> String { "udp".to_string() }
fn default_true() -> bool { true }
fn default_false() -> bool { false }
fn default_nexus_url() -> String { "https://127.0.0.1:9443".to_string() }
fn default_company() -> String { "NebulaSentinel".to_string() }
fn default_product() -> String { "NebulaSentinel Agent".to_string() }
fn default_tagline() -> String { "Autonomous Threat Cognition".to_string() }

// Section defaults: each builds the section entirely from its per-field serde
// defaults by deserializing an empty TOML table. This makes every section in
// AgentConfig optional, so a config file that omits a section (or is otherwise
// minimal) starts with sensible defaults instead of panicking with
// "missing field <section>". Every field in these structs has a serde default,
// so `from_str("")` cannot fail; the expect() documents that invariant.
fn default_nexus() -> NexusConfig { toml::from_str("").expect("NexusConfig all-defaulted") }
fn default_llm() -> LLMConfig { toml::from_str("").expect("LLMConfig all-defaulted") }
fn default_collector() -> CollectorConfig { toml::from_str("").expect("CollectorConfig all-defaulted") }
fn default_anomaly() -> AnomalyConfig { toml::from_str("").expect("AnomalyConfig all-defaulted") }
fn default_rules() -> RulesConfig { toml::from_str("").expect("RulesConfig all-defaulted") }
fn default_response() -> ResponseConfig { toml::from_str("").expect("ResponseConfig all-defaulted") }
fn default_inventory() -> InventoryConfig { toml::from_str("").expect("InventoryConfig all-defaulted") }
fn default_posture() -> PostureConfig { toml::from_str("").expect("PostureConfig all-defaulted") }
fn default_hardening() -> HardeningConfig { toml::from_str("").expect("HardeningConfig all-defaulted") }
fn default_retro() -> RetroConfig { toml::from_str("").expect("RetroConfig all-defaulted") }
fn default_gossip() -> GossipConfig { toml::from_str("").expect("GossipConfig all-defaulted") }
fn default_self_protect() -> SelfProtectConfig { toml::from_str("").expect("SelfProtectConfig all-defaulted") }
fn default_memory() -> MemoryConfig { toml::from_str("").expect("MemoryConfig all-defaulted") }
fn default_legacy() -> LegacyConfig { toml::from_str("").expect("LegacyConfig all-defaulted") }
fn default_branding() -> BrandingConfig { toml::from_str("").expect("BrandingConfig all-defaulted") }

// ── LLM ──────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LLMConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_local")]
    pub mode: String,
    #[serde(default = "default_ollama")]
    pub ollama_url: String,

    // Path to GGUF model file for embedded llama.cpp backend.
    // If None, auto-selected based on detected GPU VRAM.
    // Download models with: nebula-agent --download-model
    #[serde(default)]
    pub model_path: Option<String>,

    #[serde(default = "default_phi3")]
    pub model: String,
    #[serde(default = "default_phi3")]
    pub fallback_model: String,
    #[serde(default = "default_threshold")]
    pub confidence_threshold: u32,
    #[serde(default = "default_max_tokens")]
    pub max_context_tokens: u32,
    #[serde(default = "default_system_prompt")]
    pub system_prompt: String,

    // ── GPU / CPU compute mode ────────────────────────────────
    // "auto" = probe at startup; use GPU if found, fall back to CPU
    // "gpu"  = require GPU; abort if unavailable
    // "cpu"  = force CPU even when GPU is present
    #[serde(default = "default_compute_mode")]
    pub compute_mode: String,

    // Number of transformer layers to offload to GPU VRAM.
    // -1 = Ollama auto-selects based on available VRAM.
    //  0 = CPU only (overrides compute_mode).
    //  N = offload exactly N layers.
    #[serde(default = "default_neg_one")]
    pub gpu_layers: i32,

    // Detected or configured VRAM budget in MB.
    // Agent uses this when auto-selecting between model sizes on GPU.
    // 0 / absent = let probe determine it.
    #[serde(default)]
    pub gpu_vram_mb: Option<u64>,

    // Optional stronger model to use when GPU is available.
    // e.g. "phi3:medium" or "mistral:7b-instruct-q4_K_M"
    // If absent, the same `model` is used regardless of compute mode.
    #[serde(default)]
    pub gpu_model_override: Option<String>,

    // ── Remote ATC (NebulaCerebro) — OPTIONAL fallback tier ───────────────
    // When the local embedded model is unavailable (CPU-only host, no GGUF, or a
    // failed pre-flight), the agent can borrow inference from a remote endpoint
    // — the Nexus Whisper, a dedicated NebulaCerebro node, or any OpenAI-compatible
    // server (vLLM/Ollama/llama.cpp-server). This is a FALLBACK tier, NOT the
    // default: local always wins when present, preserving the edge-first design.
    //
    // remote_atc controls when the remote path is used:
    //   "off"      = never (default — pure local-or-legacy)
    //   "fallback" = only when local LLM is unavailable (recommended)
    //   "always"   = prefer remote even if a local model exists (thin-agent mode)
    #[serde(default = "default_remote_off")]
    pub remote_atc: String,
    // Base URL of the remote inference endpoint (OpenAI-compatible /v1/chat/completions).
    // e.g. "http://nebulacerebro.internal:8000" or the Nexus Whisper endpoint.
    #[serde(default)]
    pub remote_url: Option<String>,
    // Optional bearer token for the remote endpoint.
    #[serde(default)]
    pub remote_api_key: Option<String>,
    // Model name to request from the remote endpoint (server-side model id).
    #[serde(default = "default_phi3")]
    pub remote_model: String,
    // Per-request timeout (seconds) for remote inference. Kept short so a slow or
    // dead remote never stalls detection — on timeout we fall through to Legacy.
    #[serde(default = "default_remote_timeout")]
    pub remote_timeout_secs: u64,
}

fn default_remote_off() -> String { "off".to_string() }
fn default_remote_timeout() -> u64 { 20 }
fn default_local() -> String { "local".to_string() }
fn default_ollama() -> String { "http://localhost:11434".to_string() }
fn default_phi3() -> String { "phi3:mini".to_string() }
fn default_threshold() -> u32 { 70 }
fn default_max_tokens() -> u32 { 4096 }
fn default_compute_mode() -> String { "auto".to_string() }
fn default_neg_one() -> i32 { -1 }
fn default_system_prompt() -> String {
    "You are Nebula Whisper, an expert cybersecurity analyst. Reason step-by-step. Follow MITRE ATT&CK taxonomy. Output JSON when generating signatures.".to_string()
}

// ── Collector ─────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CollectorConfig {
    #[serde(default = "default_ebpf")]
    pub backend: String,
    #[serde(default = "default_ebpf_programs")]
    pub ebpf_programs: Vec<String>,
    #[serde(default)]
    pub etw_enabled: bool,
    #[serde(default = "default_audit_socket")]
    pub auditd_socket: String,
    #[serde(default = "default_buffer")]
    pub buffer_size: usize,
    #[serde(default = "default_queue_depth")]
    pub event_queue_depth: usize,
    #[serde(default = "default_dedup_window")]
    pub deduplicate_window_secs: u64,
    /// Suppress identical alerts (same threat_name + MITRE techniques + process)
    /// within `deduplicate_window_secs` before forwarding to the Nexus. On by
    /// default; set false to forward every firing (pre-dedup behavior).
    #[serde(default = "default_true")]
    pub dedup_enabled: bool,
}
fn default_ebpf() -> String { crate::platform::default_collector_backend().to_string() }
fn default_ebpf_programs() -> Vec<String> { vec!["execve".into(), "open".into(), "connect".into()] }
fn default_audit_socket() -> String { "/var/run/audispd_events".to_string() }
fn default_buffer() -> usize { 65536 }
fn default_queue_depth() -> usize { 4096 }
fn default_dedup_window() -> u64 { 60 }

// ── Detection-time suppression / allowlist ────────────────────
/// Operator-defined known-good rules applied at detection time — BEFORE the
/// dedup gate, response, forensics, and Nexus forwarding. Unlike the response
/// `isolation_allowlist` (which only guards destructive actions), these stop an
/// alert from being raised at all (or downgrade it to Info). A rule matches when
/// EVERY specified field matches; unspecified fields are wildcards. A rule with
/// no fields set matches nothing (guards against a blanket suppress-all).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DetectionConfig {
    #[serde(default)]
    pub suppress: Vec<SuppressionRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuppressionRule {
    /// Glob (`*` wildcard) on the originating process name (case-insensitive).
    #[serde(default)]
    pub process: Option<String>,
    /// Glob on the originating process path (case-insensitive).
    #[serde(default)]
    pub path: Option<String>,
    /// Exact MITRE technique id that must be among the threat's techniques.
    #[serde(default)]
    pub technique: Option<String>,
    /// Glob on the threat name (case-insensitive).
    #[serde(default)]
    pub threat_name: Option<String>,
    /// `"drop"` = discard the alert entirely; `"downgrade"` (default) = keep it
    /// but force severity Info + floor confidence so it drops out of the feed.
    #[serde(default = "default_suppress_action")]
    pub action: String,
    /// Free-text note surfaced in the alert/log so the suppression is auditable.
    #[serde(default)]
    pub reason: Option<String>,
}
fn default_suppress_action() -> String { "downgrade".to_string() }

// ── Anomaly ───────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnomalyConfig {
    #[serde(default = "default_true")]
    pub heuristic_enabled: bool,
    #[serde(default)]
    pub ml_enabled: bool,
    #[serde(default = "default_baseline_days")]
    pub baseline_window_days: u32,
    #[serde(default = "default_true")]
    pub chain_detection: bool,
    #[serde(default = "default_chain_window")]
    pub chain_window_secs: u64,
    #[serde(default = "default_confidence")]
    pub confidence_threshold: f32,
    #[serde(default)]
    pub chain_patterns: Vec<ChainPattern>,
}
fn default_baseline_days() -> u32 { 14 }
fn default_chain_window() -> u64 { 300 }
fn default_confidence() -> f32 { 60.0 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainPattern {
    pub name: String,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub min_confidence: f32,
}

// ── Rules ─────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RulesConfig {
    #[serde(default = "default_yara_dir")]
    pub yara_dir: String,
    #[serde(default = "default_sigma_dir")]
    pub sigma_dir: String,
    #[serde(default = "default_wazuh_dir")]
    pub wazuh_rules_dir: String,
    #[serde(default = "default_true")]
    pub auto_reload: bool,
    #[serde(default = "default_reload_interval")]
    pub reload_interval_secs: u64,
    #[serde(default = "default_true")]
    pub ai_rules_require_approval: bool,
}
fn default_yara_dir() -> String { "/etc/nebula/rules/yara".to_string() }
fn default_sigma_dir() -> String { "/etc/nebula/rules/sigma".to_string() }
fn default_wazuh_dir() -> String { "/etc/nebula/rules/wazuh".to_string() }
fn default_reload_interval() -> u64 { 60 }

// ── Response ──────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseConfig {
    #[serde(default = "default_kill_threshold")]
    pub auto_kill_threshold: f32,
    #[serde(default = "default_quarantine_threshold")]
    pub auto_quarantine_threshold: f32,
    #[serde(default = "default_isolate_threshold")]
    pub auto_isolate_threshold: f32,
    #[serde(default)]
    pub isolation_allowlist: Vec<String>,
    #[serde(default = "default_true")]
    pub rollback_enabled: bool,
    #[serde(default = "default_true")]
    pub snapshot_on_threat: bool,
}
fn default_kill_threshold() -> f32 { 95.0 }
fn default_quarantine_threshold() -> f32 { 90.0 }
fn default_isolate_threshold() -> f32 { 85.0 }

// ── Forensics ─────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ForensicsConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// Minimum threat confidence (0–100) required to trigger forensic capture.
    /// Like the response engine's thresholds — set higher to avoid capturing on
    /// legitimate-but-suspicious activity (e.g. an admin SSHing in and sudo-ing
    /// to root). Default 90: only high-fidelity detections trigger collection.
    #[serde(default = "default_forensics_threshold")]
    pub min_confidence: f32,
    /// TIERED FORENSICS POLICY. Lightweight artifacts (process triage, network
    /// state, log slices, open FDs, pcap) are cheap, so we grab them at a LOWER
    /// confidence than the expensive full memory dump. At/above `light_confidence`
    /// we collect the cheap artifacts; at/above `full_confidence` we ALSO take a
    /// full memory dump. This captures useful evidence earlier without paying the
    /// cost of a memory dump on every medium-confidence hit.
    #[serde(default = "default_forensics_light")]
    pub light_confidence: f32,
    #[serde(default = "default_forensics_full")]
    pub full_confidence: f32,
    /// Capture forensics BEFORE executing a destructive response (process kill,
    /// isolate). Ensures volatile state (process memory, /proc, open FDs) is
    /// captured while the process is still alive. Default true.
    #[serde(default = "default_true")]
    pub capture_before_response: bool,
    #[serde(default = "default_forensics_dir")]
    pub output_dir: String,
    #[serde(default = "default_true")]
    pub memory_dump: bool,
    #[serde(default = "default_true")]
    pub pcap_on_event: bool,
    #[serde(default = "default_pcap_duration")]
    pub pcap_duration_secs: u64,
    #[serde(default = "default_pcap_filter")]
    pub pcap_filter: String,
    #[serde(default = "default_true")]
    pub collect_logs: bool,
    #[serde(default = "default_log_paths")]
    pub log_paths: Vec<String>,
    #[serde(default = "default_artifact_size")]
    pub max_artifact_size_mb: u64,
    #[serde(default = "default_true")]
    pub encrypt_artifacts: bool,
    /// Optional 64-hex-char (32-byte) AES-256-GCM key for artifact encryption.
    /// When set, forensic artifacts are encrypted with this key (proper key
    /// management — store it in the Nexus / a KMS, not on the host). When unset,
    /// a weaker key derived from machine-id + bundle-id is used so encryption
    /// still functions air-gapped, but is only as strong as host-local secrets.
    #[serde(default)]
    pub encryption_key_hex: Option<String>,
}
fn default_forensics_dir() -> String { "/var/lib/nebula/forensics".to_string() }
fn default_pcap_duration() -> u64 { 60 }
fn default_forensics_threshold() -> f32 { 90.0 }
fn default_forensics_light() -> f32 { 70.0 }
fn default_forensics_full() -> f32 { 90.0 }
fn default_pcap_filter() -> String { "not port 53".to_string() }
fn default_log_paths() -> Vec<String> { vec!["/var/log".into()] }
fn default_artifact_size() -> u64 { 512 }

/// Build a ForensicsConfig entirely from per-field defaults. Used when the
/// config file omits the `[forensics]` section entirely (e.g. minimal Windows
/// configs) so the agent starts with forensics disabled rather than panicking.
fn default_forensics() -> ForensicsConfig {
    ForensicsConfig {
        enabled:                 default_false(),
        min_confidence:          default_forensics_threshold(),
        light_confidence:        default_forensics_light(),
        full_confidence:         default_forensics_full(),
        capture_before_response: default_true(),
        output_dir:              default_forensics_dir(),
        memory_dump:             default_true(),
        pcap_on_event:           default_true(),
        pcap_duration_secs:      default_pcap_duration(),
        pcap_filter:             default_pcap_filter(),
        collect_logs:            default_true(),
        log_paths:               default_log_paths(),
        max_artifact_size_mb:    default_artifact_size(),
        encrypt_artifacts:       default_true(),
        encryption_key_hex:      None,
    }
}

// ── Inventory ─────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InventoryConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_inv_interval")]
    pub scan_interval_secs: u64,
    #[serde(default = "default_sha256")]
    pub hash_algorithm: String,
    #[serde(default = "default_include_paths")]
    pub include_paths: Vec<String>,
    #[serde(default = "default_exclude_paths")]
    pub exclude_paths: Vec<String>,
    #[serde(default = "default_true")]
    pub track_installed_pkgs: bool,
    #[serde(default = "default_true")]
    pub track_processes: bool,
    #[serde(default = "default_true")]
    pub track_network_conns: bool,
    #[serde(default = "default_true")]
    pub track_users: bool,
    #[serde(default = "default_true")]
    pub track_containers: bool,
}
fn default_inv_interval() -> u64 { 3600 }
fn default_full_scan_age() -> i64 { 24 }
fn default_sha256() -> String { "sha256".to_string() }
fn default_include_paths() -> Vec<String> { vec!["/usr/bin".into(), "/bin".into(), "/etc".into()] }
fn default_exclude_paths() -> Vec<String> { vec!["/proc".into(), "/sys".into(), "/dev".into()] }

// ── Posture ───────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostureConfig {
    #[serde(default = "default_true")]
    pub oscal_enabled: bool,
    #[serde(default)]
    pub oscal_catalog_path: Option<String>,
    #[serde(default)]
    pub cis_benchmark_path: Option<String>,
    #[serde(default)]
    pub stig_content_path: Option<String>,
    #[serde(default = "default_nvd_path")]
    pub nvd_feed_path: String,
    #[serde(default = "default_oval_path")]
    pub oval_feed_path: String,
    #[serde(default = "default_inv_interval")]
    pub scan_interval_secs: u64,
    /// Smart-scan: on startup, skip the expensive full scan (file-catalog walk)
    /// if a recent full scan exists and the installed-package set is unchanged.
    /// Avoids redundant heavy work on agent reinstall/restart. Default true.
    #[serde(default = "default_true")]
    pub smart_scan: bool,
    /// Force a full scan if the last one is older than this many hours, even
    /// when the host appears unchanged. Default 24h.
    #[serde(default = "default_full_scan_age")]
    pub full_scan_max_age_hours: i64,
    #[serde(default = "default_true")]
    pub dependency_scan_enabled: bool,
    #[serde(default = "default_frameworks")]
    pub compliance_frameworks: Vec<String>,
    #[serde(default = "default_pkg_managers")]
    pub pkg_managers: Vec<String>,
}
fn default_nvd_path() -> String { "/var/lib/nebula/nvd/".to_string() }
fn default_oval_path() -> String { "/var/lib/nebula/oval/".to_string() }
fn default_frameworks() -> Vec<String> { vec!["nist_csf".into(), "cis_l2".into()] }
fn default_pkg_managers() -> Vec<String> { vec!["dpkg".into(), "rpm".into(), "cargo".into(), "pip".into()] }

// ── Hardening ─────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HardeningConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub auto_apply: bool,
    #[serde(default = "default_hardening_frameworks")]
    pub frameworks: Vec<String>,
    #[serde(default = "default_hardening_report")]
    pub report_path: String,
    #[serde(default = "default_true")]
    pub sshd_hardening: bool,
    #[serde(default = "default_true")]
    pub kernel_hardening: bool,
    #[serde(default = "default_true")]
    pub firewall_audit: bool,
}
fn default_hardening_frameworks() -> Vec<String> { vec!["cis_l2".into(), "stig".into()] }
fn default_hardening_report() -> String { "/var/lib/nebula/hardening/".to_string() }

// ── Retro-hunting ─────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RetroConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub on_new_rule: bool,
    #[serde(default = "default_log_sources")]
    pub log_sources: Vec<String>,
    #[serde(default)]
    pub evtx_paths: Vec<String>,
    #[serde(default = "default_lookback")]
    pub max_lookback_days: u32,
    #[serde(default = "default_threads")]
    pub parallel_threads: usize,
    #[serde(default = "default_max_files")]
    pub max_files_scanned: usize,
}
fn default_log_sources() -> Vec<String> { vec!["/var/log/auth.log".into(), "/var/log/syslog".into()] }
fn default_lookback() -> u32 { 90 }
fn default_threads() -> usize { 4 }
fn default_max_files() -> usize { 50_000 }

// ── Gossip ────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GossipConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_gossip_port")]
    pub port: u16,
    #[serde(default = "default_bind")]
    pub bind_addr: String,
    #[serde(default = "default_nexus_discovery")]
    pub discovery: String,
    #[serde(default)]
    pub static_peers: Vec<String>,
    /// Encrypt GOSSIP UDP datagrams. **Off by default** so the default state is
    /// honestly unencrypted rather than pretending to be on. To actually encrypt
    /// the mesh, set this to `true` AND provide `encryption_key` (all peers must
    /// share the same key). Setting `true` without a key logs a warning and sends
    /// PLAINTEXT — the key is what turns encryption on.
    #[serde(default = "default_false")]
    pub encryption: bool,
    /// Optional 64-hex-char (32-byte) pre-shared key for AES-256-GCM encryption
    /// of GOSSIP UDP datagrams. All peers must share the same key.
    #[serde(default)]
    pub encryption_key: Option<String>,
    #[serde(default = "default_gossip_interval")]
    pub gossip_interval_secs: u64,
    #[serde(default = "default_true")]
    pub share_iocs: bool,
    #[serde(default)]
    pub share_rules: bool,
    #[serde(default = "default_true")]
    pub share_threat_scores: bool,
}
fn default_gossip_port() -> u16 { 9999 }
fn default_bind() -> String { "0.0.0.0".to_string() }
fn default_nexus_discovery() -> String { "nexus".to_string() }
fn default_gossip_interval() -> u64 { 15 }

// ── Self-protect ──────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SelfProtectConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_report_interval")]
    pub watchdog_interval_secs: u64,
    #[serde(default = "default_integrity_interval")]
    pub integrity_check_interval_secs: u64,
    #[serde(default = "default_true")]
    pub binary_hash_check: bool,
    #[serde(default = "default_true")]
    pub config_tamper_detection: bool,
    #[serde(default = "default_true")]
    pub adversarial_input_detection: bool,
    #[serde(default = "default_true")]
    pub model_poisoning_detection: bool,
    #[serde(default = "default_true")]
    pub prompt_injection_detection: bool,
    #[serde(default = "default_true")]
    pub anti_debug: bool,
    #[serde(default = "default_true")]
    pub protect_pid: bool,
}
fn default_integrity_interval() -> u64 { 60 }

// ── Memory ────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MemoryConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub volatility_path: Option<String>,
    #[serde(default)]
    pub lime_module_path: Option<String>,
    #[serde(default = "default_true")]
    pub dump_on_critical: bool,
    #[serde(default = "default_true")]
    pub scan_running_procs: bool,
}

// ── Legacy ────────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LegacyConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_cef")]
    pub format: String,
    #[serde(default)]
    pub target: String,
}
fn default_cef() -> String { "cef".to_string() }

// ── Branding ──────────────────────────────────────────────────
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BrandingConfig {
    #[serde(default = "default_company")]
    pub company_name: String,
    #[serde(default = "default_product")]
    pub product_name: String,
    #[serde(default = "default_tagline")]
    pub tagline: String,
}

impl AgentConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut cfg: AgentConfig = toml::from_str(&content)?;
        // Establish a STABLE agent_id so the same host doesn't re-register as a
        // new instance on every restart. Priority:
        //   1. Explicit agent_id in the config file (operator-set).
        //   2. A previously-persisted id at /var/lib/nebula/agent_id.
        //   3. The host's /etc/machine-id (stable across reboots).
        //   4. A fresh UUID — which we then persist for next time.
        if cfg.agent_id.is_empty() {
            cfg.agent_id = Self::stable_agent_id();
        }
        // Apply a GOSSIP config override pushed by the Nexus (if any). This lets
        // operators control GOSSIP parameters fleet-wide; the override is written
        // by the UpdateConfig command handler and applied here at startup.
        if let Ok(raw) = std::fs::read_to_string("/var/lib/nebula/gossip_override.json") {
            if let Ok(ov) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(v) = ov["gossip_interval_secs"].as_u64() { cfg.gossip.gossip_interval_secs = v; }
                if let Some(v) = ov["share_iocs"].as_bool() { cfg.gossip.share_iocs = v; }
                if let Some(v) = ov["share_rules"].as_bool() { cfg.gossip.share_rules = v; }
                if let Some(v) = ov["share_threat_scores"].as_bool() { cfg.gossip.share_threat_scores = v; }
                if let Some(v) = ov["encryption"].as_bool() { cfg.gossip.encryption = v; }
            }
        }
        Ok(cfg)
    }

    fn stable_agent_id() -> String {
        let state_path_buf = crate::platform::agent_id_path();
        let state_path = state_path_buf.to_string_lossy().to_string();
        let state_path = state_path.as_str();
        // 2. Reuse a previously-persisted id (stable across restarts) — UNLESS it
        //    matches the old machine-id-only derivation, which collided across
        //    cloned hosts. Those are regenerated once with the improved scheme.
        if let Ok(saved) = std::fs::read_to_string(state_path) {
            let saved = saved.trim().to_string();
            if !saved.is_empty() {
                let is_stale_collision = std::fs::read_to_string("/etc/machine-id")
                    .ok()
                    .map(|mid| {
                        let old = format!("agent-{}",
                            &format!("{:x}", md5::compute(format!("nebula-agent:{}", mid.trim())))[..16]);
                        old == saved
                    })
                    .unwrap_or(false);
                if !is_stale_collision {
                    return saved;
                }
                // else: fall through to regenerate with hostname+MAC entropy
            }
        }
        // 3. Derive from machine-id + hostname + primary MAC. /etc/machine-id
        //    alone is NOT unique across cloned VMs / container images, so we mix
        //    in the hostname and first non-loopback MAC, which normally differ
        //    between clones. This stays stable across restarts AND survives a
        //    wipe of /var/lib (deterministic), while avoiding ID collisions.
        let machine_id = std::fs::read_to_string("/etc/machine-id")
            .map(|s| s.trim().to_string()).unwrap_or_default();
        let hostname = std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_default();
        let mac = Self::primary_mac();

        let seed = format!("nebula-agent:{}:{}:{}", machine_id, hostname, mac);
        // Only treat the derivation as trustworthy if we have at least one
        // genuinely host-specific component; otherwise fall back to random.
        let id = if !machine_id.is_empty() || !mac.is_empty() {
            let digest = format!("{:x}", md5::compute(&seed));
            format!("agent-{}", &digest[..16])
        } else {
            // 4. Fresh random UUID — nothing stable to derive from.
            format!("agent-{}", uuid::Uuid::new_v4().simple())
        };
        // Persist for next start (best-effort; dir may not exist yet).
        let _ = std::fs::create_dir_all("/var/lib/nebula");
        let _ = std::fs::write(state_path, &id);
        id
    }

    /// Best-effort: the MAC of the first non-loopback interface, read from
    /// /sys/class/net. Returns "" if none found.
    fn primary_mac() -> String {
        let Ok(entries) = std::fs::read_dir("/sys/class/net") else { return String::new() };
        let mut ifaces: Vec<String> = entries.flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n != "lo")
            .collect();
        ifaces.sort();   // deterministic ordering
        for iface in ifaces {
            if let Ok(mac) = std::fs::read_to_string(format!("/sys/class/net/{}/address", iface)) {
                let mac = mac.trim();
                // Skip all-zero / empty MACs (some virtual interfaces)
                if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    return mac.to_string();
                }
            }
        }
        String::new()
    }

    pub fn is_protect_mode(&self) -> bool {
        self.mode == AgentMode::Protect
    }
}
