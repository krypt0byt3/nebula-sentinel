// platform.rs — OS-specific paths and capabilities for the NebulaSentinel agent.
//
// The agent runs on Linux (primary), Windows, and macOS. File-system layout and
// available collectors differ per OS. This module centralizes those differences
// so the rest of the codebase can ask for "the data dir" or "the config path"
// without sprinkling cfg(target_os) everywhere.
//
// Layout:
//   Linux:   data /var/lib/nebula   config /etc/nebula
//   Windows: data + config under  C:\ProgramData\NebulaSentinel
//   macOS:   data /Library/Application Support/NebulaSentinel  config /etc/nebula

use std::path::PathBuf;

/// Base directory for persistent agent state (agent_id, queues, models, forensics).
pub fn data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        // %ProgramData% (machine-wide, survives user logout) — typically
        // C:\ProgramData. Fall back to a sane default if the env var is missing.
        let base = std::env::var("ProgramData")
            .unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(base).join("NebulaSentinel")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/NebulaSentinel")
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        PathBuf::from("/var/lib/nebula")
    }
}

/// Base directory for configuration files.
pub fn config_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("ProgramData")
            .unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(base).join("NebulaSentinel").join("config")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/nebula")
    }
}

/// The default config file path for this platform.
pub fn default_config_path() -> PathBuf {
    config_dir().join("config.toml")
}

/// Where the agent persists its assigned agent_id.
pub fn agent_id_path() -> PathBuf {
    data_dir().join("agent_id")
}

/// Directory for downloaded LLM model files.
///
/// `NEBULA_MODELS_DIR` (also set by `--models-dir`) overrides it, so an operator
/// can keep GGUFs on a data volume without editing the config. Everything that
/// looks for a model — download, auto-detect, `--model` name resolution — goes
/// through here, so the override applies uniformly.
pub fn models_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("NEBULA_MODELS_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir.trim());
        }
    }
    data_dir().join("models")
}

/// The default collector backend name for this platform. The richest source
/// that works out of the box: eBPF on Linux (if compiled), Windows Event Log on
/// Windows, procmon (cross-platform polling) as the universal fallback.
pub fn default_collector_backend() -> &'static str {
    #[cfg(target_os = "windows")]
    { "wineventlog" }
    #[cfg(target_os = "linux")]
    { "ebpf" }
    #[cfg(target_os = "macos")]
    { "procmon" }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    { "procmon" }
}

/// Human-readable platform label for logs / Nexus registration.
pub fn platform_label() -> &'static str {
    #[cfg(target_os = "windows")] { "windows" }
    #[cfg(target_os = "linux")]   { "linux" }
    #[cfg(target_os = "macos")]   { "macos" }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    { "unknown" }
}

/// Whether kernel-level syscall tracing (eBPF) is available on this platform.
/// Linux-only; used so the collector can honestly report capability rather than
/// silently behaving differently.
pub fn supports_ebpf() -> bool {
    cfg!(target_os = "linux")
}
