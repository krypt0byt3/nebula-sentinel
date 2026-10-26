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

/// Process-wide override for the models directory, set once from `--models-dir`
/// (see `set_models_dir_override`). A static rather than a threaded-through
/// parameter because model discovery happens deep inside the LLM backends —
/// every caller of `models_dir()` has to agree on the answer, including the
/// self-test child process and the downloader.
static MODELS_DIR_OVERRIDE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Point every models-dir lookup in this process at `dir`. First call wins;
/// returns the directory now in effect. Call before the LLM engine is built.
pub fn set_models_dir_override(dir: impl Into<PathBuf>) -> PathBuf {
    let dir = dir.into();
    MODELS_DIR_OVERRIDE.get_or_init(|| dir).clone()
}

/// Directory for downloaded LLM model files.
///
/// Precedence: `--models-dir` (via `set_models_dir_override`) → `NEBULA_MODELS_DIR`
/// → the platform default. Everything that looks for a model — download,
/// auto-detect, `--model` name resolution — goes through here, so the override
/// applies uniformly, including in the isolated LLM pre-flight child.
pub fn models_dir() -> PathBuf {
    if let Some(p) = MODELS_DIR_OVERRIDE.get() {
        return p.clone();
    }
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
