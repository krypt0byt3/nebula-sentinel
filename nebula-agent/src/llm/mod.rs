#![allow(dead_code)]
// src/llm/mod.rs — Nebula Whisper: Embedded LLM engine
//
// Embedded llama.cpp via the llama-cpp-2 Rust bindings (feature "embedded-llm")
//   - Runs GGUF models directly in-process — no external runtime, no Ollama,
//     no Python, no server process.
//   - GPU: CUDA / ROCm / Metal / Vulkan — selected at compile time via build.rs
//   - CPU: AVX2/AVX512 SIMD
//   - llama-cpp-2 tracks upstream llama.cpp closely, so modern architectures
//     (Phi-3, Qwen2.5, Llama-3, Gemma, Mistral, …) all load correctly.
//
// Model file:
//   The GGUF model is NOT embedded in the binary. It's loaded from disk
//   at startup from the path in config.toml: [llm] model_path = "/path/to/model.gguf"
//   Blank model_path → the model recommended for the detected VRAM, else any
//   GGUF present in /var/lib/nebula/models/ (whatever was downloaded last).
//
// Recommended models (download separately — see MODELS.md):
//   CPU only / low VRAM:  Phi-3.5-mini Q4_K_M  (~2.4 GB)
//   5-9 GB VRAM:          Qwen2.5 7B Q4_K_M    (~4.7 GB)
//   10+ GB VRAM:          Qwen2.5 14B Q4_K_M   (~8.9 GB)
//
// Any other GGUF works too: `nebula-agent --download-model <alias|owner/repo|url>`
// (see MODEL_CATALOG / resolve_model_spec below).

use crate::config::LLMConfig;
use crate::types::{ThreatEvent, DetectionRule, RuleType};
use anyhow::Result;
use chrono::{Utc, DateTime};
use tracing::{info, warn, debug};
use uuid::Uuid;
use std::sync::RwLock as StdRwLock;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────
// GPU probe (runtime, for logging/model selection)
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GpuInfo {
    pub vendor:  GpuVendor,
    pub name:    String,
    pub vram_mb: u64,
    pub driver:  String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GpuVendor { Nvidia, Amd, Apple, Vulkan, None }

impl std::fmt::Display for GpuVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuVendor::Nvidia => write!(f, "NVIDIA CUDA"),
            GpuVendor::Amd    => write!(f, "AMD ROCm"),
            GpuVendor::Apple  => write!(f, "Apple Metal"),
            GpuVendor::Vulkan => write!(f, "Vulkan"),
            GpuVendor::None   => write!(f, "CPU only"),
        }
    }
}

pub async fn probe_gpu() -> Option<GpuInfo> {
    // NVIDIA
    if let Ok(out) = tokio::process::Command::new("nvidia-smi")
        .args(["--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"])
        .output().await
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(line) = text.lines().next() {
                let parts: Vec<&str> = line.splitn(3, ',').collect();
                if parts.len() == 3 {
                    let vram = parts[1].trim().parse::<u64>().unwrap_or(0);
                    return Some(GpuInfo {
                        vendor: GpuVendor::Nvidia,
                        name:   parts[0].trim().to_string(),
                        vram_mb: vram,
                        driver: parts[2].trim().to_string(),
                    });
                }
            }
        }
    }
    // AMD ROCm
    if let Ok(out) = tokio::process::Command::new("rocm-smi")
        .args(["--showmeminfo", "vram", "--csv"])
        .output().await
    {
        if out.status.success() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if line.contains("VRAM Total") {
                    if let Some(bytes) = line.split(':').last()
                        .and_then(|s| s.trim().parse::<u64>().ok())
                    {
                        return Some(GpuInfo {
                            vendor: GpuVendor::Amd,
                            name: "AMD GPU (ROCm)".to_string(),
                            vram_mb: bytes / 1024 / 1024,
                            driver: "ROCm".to_string(),
                        });
                    }
                }
            }
        }
    }
    // Apple Metal
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = tokio::process::Command::new("system_profiler")
            .arg("SPHardwareDataType").output().await
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if line.contains("Chip:") {
                    let chip = line.split(':').last().unwrap_or("Apple Silicon").trim().to_string();
                    let vram_mb = read_total_ram_mb() / 2;
                    return Some(GpuInfo {
                        vendor: GpuVendor::Apple, name: chip, vram_mb, driver: "Metal".to_string(),
                    });
                }
            }
        }
    }
    None
}

fn read_total_ram_mb() -> u64 {
    std::fs::read_to_string("/proc/meminfo").ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok()))
        .unwrap_or(8192 * 1024) / 1024
}

/// The GGUF filename we recommend for a given VRAM budget. Derived from the
/// catalog so the recommendation and what `--download-model` fetches can never
/// drift apart.
///
/// CPU / <5 GB VRAM → Phi-3.5-mini (best structured JSON at 3.8B, excellent
/// MITRE classification). 5 GB+ → Qwen2.5-7B (strongest 7B for security
/// reasoning and JSON generation).
pub fn recommended_model_file_for_vram(vram_mb: u64) -> &'static str {
    let alias = default_alias_for_vram(vram_mb);
    catalog_entry(alias)
        .map(|e| e.file)
        .unwrap_or("Phi-3.5-mini-instruct-Q4_K_M.gguf")
}

/// Select the optimal GGUF model path based on available VRAM.
/// Resolved against the platform models dir (honouring `--models-dir` /
/// `NEBULA_MODELS_DIR`), not a hardcoded Linux path — the same recommendation
/// therefore works on Windows and macOS. See MODELS.md for download instructions.
pub fn select_model_path_for_vram(vram_mb: u64) -> String {
    crate::platform::models_dir()
        .join(recommended_model_file_for_vram(vram_mb))
        .to_string_lossy()
        .into_owned()
}

// ─────────────────────────────────────────────────────────────
// Model acquisition — `nebula-agent --download-model [MODEL]`
//
// Any GGUF the operator wants can be fetched, not just the two we recommend.
// A model is named by ONE of:
//   • a catalog alias                 phi3.5-mini
//   • a HuggingFace repo              bartowski/Qwen2.5-7B-Instruct-GGUF
//   • a repo + file (pick the quant)  bartowski/Qwen2.5-7B-Instruct-GGUF:Qwen2.5-7B-Instruct-Q6_K.gguf
//   • a repo + path form              bartowski/Qwen2.5-7B-Instruct-GGUF/Qwen2.5-7B-Instruct-Q6_K.gguf
//   • a direct URL                    https://host/path/model.gguf
// A revision may be pinned with @:   owner/repo@refs/pr/3:file.gguf
// ─────────────────────────────────────────────────────────────

/// One entry of the built-in catalog: short aliases so operators don't have to
/// remember HuggingFace paths for the models we've validated with the agent's
/// JSON-first prompts. The catalog is a convenience, NOT a whitelist — any repo
/// or URL works too.
pub struct CatalogEntry {
    pub alias:   &'static str,
    pub repo:    &'static str,   // HuggingFace repo id
    pub file:    &'static str,   // GGUF filename inside that repo
    pub size_gb: f32,
    pub note:    &'static str,
}

pub const MODEL_CATALOG: &[CatalogEntry] = &[
    // ── Current defaults: Qwen3 (2025) ─────────────────────────
    // Qwen3 supersedes Qwen2.5 on every axis that matters here — structured
    // JSON output, classification, and NATIVE tool-calling (which strengthens
    // the Nexus agentic/Whisper flow). bartowski publishes these as
    // `{Org}_{Model}-GGUF` with `{Org}_{Model}-Q4_K_M.gguf` inside.
    CatalogEntry { alias: "qwen3-1.7b", repo: "bartowski/Qwen_Qwen3-1.7B-GGUF",
        file: "Qwen_Qwen3-1.7B-Q4_K_M.gguf", size_gb: 1.1,
        note: "smallest usable — very low RAM / edge sensors" },
    CatalogEntry { alias: "qwen3-4b",   repo: "bartowski/Qwen_Qwen3-4B-GGUF",
        file: "Qwen_Qwen3-4B-Q4_K_M.gguf", size_gb: 2.5,
        note: "DEFAULT for CPU / <5 GB VRAM — strong structured output + tool-calling" },
    CatalogEntry { alias: "qwen3-8b",   repo: "bartowski/Qwen_Qwen3-8B-GGUF",
        file: "Qwen_Qwen3-8B-Q4_K_M.gguf", size_gb: 5.0,
        note: "DEFAULT for 5+ GB VRAM — best all-round security reasoning" },
    CatalogEntry { alias: "qwen3-14b",  repo: "bartowski/Qwen_Qwen3-14B-GGUF",
        file: "Qwen_Qwen3-14B-Q4_K_M.gguf", size_gb: 9.0,
        note: "high-end GPU (10+ GB VRAM) — best analysis quality" },
    // ── Alternatives / known-good fallbacks ────────────────────
    CatalogEntry { alias: "phi3.5-mini", repo: "bartowski/Phi-3.5-mini-instruct-GGUF",
        file: "Phi-3.5-mini-instruct-Q4_K_M.gguf", size_gb: 2.4,
        note: "alternative 3.8B — compact, solid structured JSON on CPU" },
    CatalogEntry { alias: "qwen2.5-7b",  repo: "bartowski/Qwen2.5-7B-Instruct-GGUF",
        file: "Qwen2.5-7B-Instruct-Q4_K_M.gguf", size_gb: 4.7,
        note: "previous default — proven 7B, kept as a stable fallback" },
    CatalogEntry { alias: "mistral-7b",  repo: "bartowski/Mistral-7B-Instruct-v0.3-GGUF",
        file: "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf", size_gb: 4.4,
        note: "alternative 7B — permissive Apache-2.0 licence" },
    CatalogEntry { alias: "gemma2-9b",   repo: "bartowski/gemma-2-9b-it-GGUF",
        file: "gemma-2-9b-it-Q4_K_M.gguf", size_gb: 5.8,
        note: "alternative 9B — needs ~7 GB VRAM" },
];

/// A resolved, downloadable model: where to get it and what to call it on disk.
#[derive(Debug, Clone)]
pub struct ModelSource {
    pub url:      String,
    pub filename: String,
    pub size_gb:  Option<f32>,
    /// Human-readable provenance for the log line ("catalog: phi3.5-mini", …).
    pub origin:   String,
}

/// Quantisations we prefer, best trade-off first, when the operator names a repo
/// but not a specific file.
const QUANT_PREFERENCE: &[&str] = &[
    "q4_k_m", "q4_k_s", "q5_k_m", "q5_k_s", "q6_k", "q8_0", "q4_0", "q3_k_m",
];

/// The alias whose model we recommend for a given amount of VRAM.
pub fn default_alias_for_vram(vram_mb: u64) -> &'static str {
    match vram_mb {
        0..=4999     => "qwen3-4b",
        5000..=9999  => "qwen3-8b",
        _            => "qwen3-14b",
    }
}

/// Look an alias up in the built-in catalog (case-insensitive).
pub fn catalog_entry(alias: &str) -> Option<&'static CatalogEntry> {
    MODEL_CATALOG.iter().find(|e| e.alias.eq_ignore_ascii_case(alias))
}

fn hf_source(repo: &str, revision: &str, file: &str, size_gb: Option<f32>, origin: String) -> ModelSource {
    ModelSource {
        url: format!("https://huggingface.co/{}/resolve/{}/{}", repo, revision, file),
        filename: file.rsplit('/').next().unwrap_or(file).to_string(),
        size_gb,
        origin,
    }
}

/// Turn whatever the operator typed into a concrete download.
/// Only the bare-repo form ("owner/repo") touches the network — it asks the
/// HuggingFace API which GGUF files the repo actually holds.
pub async fn resolve_model_spec(spec: &str) -> anyhow::Result<ModelSource> {
    let spec = spec.trim();
    if spec.is_empty() {
        anyhow::bail!("empty model specification");
    }

    // ── Direct URL ──────────────────────────────────────────────
    if spec.starts_with("http://") || spec.starts_with("https://") {
        let filename = filename_from_url(spec)?;
        return Ok(ModelSource {
            url: spec.to_string(), filename, size_gb: None, origin: "direct URL".to_string(),
        });
    }

    let key = spec.strip_prefix("hf:").unwrap_or(spec);

    // ── Catalog alias (no slash → not a repo id) ────────────────
    if !key.contains('/') {
        return match catalog_entry(key) {
            Some(e) => Ok(hf_source(e.repo, "main", e.file, Some(e.size_gb),
                format!("catalog: {}", e.alias))),
            None => anyhow::bail!(
                "unknown model '{}'.\n\
                 Give one of:\n\
                   • a catalog alias        (see `nebula-agent --list-models`)\n\
                   • a HuggingFace repo     bartowski/Qwen2.5-7B-Instruct-GGUF\n\
                   • a repo + exact file    bartowski/Qwen2.5-7B-Instruct-GGUF:Qwen2.5-7B-Instruct-Q6_K.gguf\n\
                   • a direct URL           https://host/path/model.gguf",
                key),
        };
    }

    // ── HuggingFace repo (± revision ± file) ────────────────────
    let (repo_part, explicit_file) = match key.split_once(':') {
        Some((r, f)) => (r.to_string(), Some(f.trim_start_matches('/').to_string())),
        None         => (key.to_string(), None),
    };
    let (mut repo, revision) = match repo_part.split_once('@') {
        Some((r, rev)) => (r.to_string(), rev.to_string()),
        None           => (repo_part, "main".to_string()),
    };

    // "owner/repo/sub/dir/file.gguf" — the file is glued onto the repo id.
    let mut file = explicit_file;
    if file.is_none() {
        let segs: Vec<&str> = repo.split('/').filter(|s| !s.is_empty()).collect();
        if segs.len() > 2 && is_gguf(segs[segs.len() - 1]) {
            file = Some(segs[2..].join("/"));
            repo = segs[..2].join("/");
        }
    }
    if repo.split('/').filter(|s| !s.is_empty()).count() != 2 {
        anyhow::bail!("'{}' is not a HuggingFace repo id (expected owner/repo)", repo);
    }

    match file {
        Some(f) => Ok(hf_source(&repo, &revision, &f, None, format!("HuggingFace {}", repo))),
        None => {
            // Ask the Hub which GGUFs the repo holds and pick the best quant.
            let picked = pick_gguf_from_repo(&repo, &revision).await?;
            info!("🔎 {} → selected {}", repo, picked);
            Ok(hf_source(&repo, &revision, &picked, None, format!("HuggingFace {}", repo)))
        }
    }
}

fn is_gguf(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".gguf")
}

/// True for one piece of a split model ("…-00002-of-00005.gguf"). Those need all
/// shards (and llama.cpp opens them via the first part), so we never auto-pick a
/// non-first shard.
fn is_split_shard(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("-of-") && lower.rsplit('-').nth(2).map_or(false, |p| p.len() == 5 && p.chars().all(|c| c.is_ascii_digit()))
}

fn filename_from_url(url: &str) -> anyhow::Result<String> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let name = path.rsplit('/').find(|s| !s.is_empty()).unwrap_or("");
    if name.is_empty() {
        anyhow::bail!("cannot derive a filename from {} — pass --model-name to set it", url);
    }
    Ok(name.to_string())
}

/// Bearer token for gated/private HuggingFace repos, if the operator exported one.
fn hf_token() -> Option<String> {
    for var in ["HF_TOKEN", "HUGGINGFACE_TOKEN", "HUGGING_FACE_HUB_TOKEN"] {
        if let Ok(v) = std::env::var(var) {
            if !v.trim().is_empty() { return Some(v.trim().to_string()); }
        }
    }
    None
}

/// List the GGUF files in a HuggingFace repo and pick the best-quant one.
async fn pick_gguf_from_repo(repo: &str, revision: &str) -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    let api = format!("https://huggingface.co/api/models/{}/revision/{}", repo,
        urlencode_revision(revision));
    let mut req = client.get(&api).header("User-Agent", USER_AGENT);
    if let Some(tok) = hf_token() { req = req.bearer_auth(tok); }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("HuggingFace lookup for {}@{} failed: HTTP {}{}",
            repo, revision, resp.status(),
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED
               || resp.status() == reqwest::StatusCode::FORBIDDEN {
                " — gated repo? export HF_TOKEN=<your token> and retry"
            } else { "" });
    }
    let info: serde_json::Value = resp.json().await?;
    let files: Vec<String> = info["siblings"].as_array().cloned().unwrap_or_default()
        .iter()
        .filter_map(|s| s["rfilename"].as_str().map(str::to_string))
        .filter(|f| is_gguf(f))
        .collect();

    if files.is_empty() {
        anyhow::bail!("{} contains no .gguf files — is it a GGUF repo? \
                       (llama.cpp cannot load safetensors/PyTorch weights)", repo);
    }

    let whole: Vec<&String> = files.iter().filter(|f| !is_split_shard(f)).collect();
    let candidates: Vec<&String> = if whole.is_empty() { files.iter().collect() } else { whole };

    for quant in QUANT_PREFERENCE {
        if let Some(f) = candidates.iter().find(|f| f.to_ascii_lowercase().contains(quant)) {
            return Ok((*f).clone());
        }
    }
    // No recognised quant tag — take the first and tell the operator what else was there.
    let pick = candidates[0].clone();
    info!("   (no known quantisation tag; available: {})",
        candidates.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
    Ok(pick)
}

/// HuggingFace revisions may be branch names, tags, SHAs or "refs/pr/N" —
/// only the slashes need escaping for the API path.
fn urlencode_revision(rev: &str) -> String {
    rev.replace('/', "%2F")
}

const USER_AGENT: &str = concat!("NebulaSentinel-Agent/", env!("CARGO_PKG_VERSION"));

/// Download `src` into `dest_dir` (defaults to the platform models dir when
/// None), returning the final path. Resumes an interrupted `.part` file, shows
/// live progress, and refuses to install anything that isn't a GGUF.
pub async fn download_model(
    src: &ModelSource,
    dest_dir: Option<&std::path::Path>,
    out_name: Option<&str>,
) -> anyhow::Result<String> {
    let dir = dest_dir.map(|p| p.to_path_buf()).unwrap_or_else(crate::platform::models_dir);
    let filename = out_name.unwrap_or(&src.filename);
    let dest = dir.join(filename);
    let dest_str = dest.to_string_lossy().to_string();

    if dest.exists() {
        println!("✅ Model already present: {}", dest_str);
        println!("   Delete it and re-run to force a fresh download.");
        return Ok(dest_str);
    }

    std::fs::create_dir_all(&dir)
        .map_err(|e| anyhow::anyhow!("cannot create {}: {} (run as root, or pass a writable dir)",
            dir.display(), e))?;

    let tmp = dir.join(format!("{}.part", filename));
    // A previous run may have left a partial file — ask the server to continue.
    let resume_from = tokio::fs::metadata(&tmp).await.map(|m| m.len()).unwrap_or(0);

    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(21_600))   // 6 h ceiling for multi-GB pulls
        .build()?;

    let mut req = client.get(&src.url).header("User-Agent", USER_AGENT);
    if src.url.contains("huggingface.co") {
        if let Some(tok) = hf_token() { req = req.bearer_auth(tok); }
    }
    if resume_from > 0 {
        req = req.header(reqwest::header::RANGE, format!("bytes={}-", resume_from));
    }

    println!("📥 {}", src.origin);
    println!("   Source : {}", src.url);
    println!("   Target : {}", dest_str);
    if let Some(gb) = src.size_gb { println!("   Size   : ~{:.1} GB", gb); }

    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        let hint = match status {
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN =>
                " — gated or private model? export HF_TOKEN=<your token> and retry",
            reqwest::StatusCode::NOT_FOUND =>
                " — check the repo id, revision and filename (`--list-models` shows known-good ones)",
            _ => "",
        };
        anyhow::bail!("Download failed: HTTP {}{}", status, hint);
    }

    // Server honoured the Range request → append; otherwise start over.
    let resuming = resume_from > 0 && status == reqwest::StatusCode::PARTIAL_CONTENT;
    if resume_from > 0 && !resuming {
        info!("   (server ignored resume request — restarting the download)");
    } else if resuming {
        println!("   Resuming from {:.0} MiB", resume_from as f64 / 1_048_576.0);
    }

    let mut downloaded: u64 = if resuming { resume_from } else { 0 };
    let total = resp.content_length().map(|l| l + downloaded);

    use tokio::io::AsyncWriteExt;
    let mut file = if resuming {
        tokio::fs::OpenOptions::new().append(true).open(&tmp).await?
    } else {
        tokio::fs::File::create(&tmp).await?
    };

    // Stream in chunks with a live progress line — never buffer multi-GB bodies
    // in memory (the old resp.bytes() held the whole model in RAM).
    let started = std::time::Instant::now();
    let mut last_render = std::time::Instant::now();
    let mut resp = resp;
    while let Some(chunk) = resp.chunk().await? {
        file.write_all(&chunk).await?;
        downloaded += chunk.len() as u64;
        // Throttle redraws to ~5/sec so we don't spam the terminal.
        if last_render.elapsed().as_millis() >= 200 {
            render_progress(downloaded, total, started.elapsed().as_secs_f64());
            last_render = std::time::Instant::now();
        }
    }
    file.flush().await?;
    render_progress(downloaded, total, started.elapsed().as_secs_f64());
    println!();

    // Sanity: if the server advertised a length, make sure we got it all. Keep
    // the .part file so the next run resumes instead of starting from zero.
    if let Some(t) = total {
        if downloaded < t {
            anyhow::bail!("Download incomplete: got {}/{} bytes — re-run to resume", downloaded, t);
        }
    }

    // A truncated file, an HTML error page or an LFS pointer would all "download"
    // fine and then blow up inside llama.cpp. Check the GGUF magic before install.
    verify_gguf_magic(&tmp).await?;

    tokio::fs::rename(&tmp, &dest).await?;
    println!("✅ Downloaded {:.1} MB to {}", downloaded as f64 / 1_048_576.0, dest_str);
    Ok(dest_str)
}

/// Every GGUF file starts with the ASCII magic "GGUF".
async fn verify_gguf_magic(path: &std::path::Path) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await?;
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).await.is_err() || &magic != b"GGUF" {
        let _ = tokio::fs::remove_file(path).await;
        anyhow::bail!(
            "downloaded file is not a GGUF model (bad magic) — the server likely returned \
             an error page or an LFS pointer. Partial file removed; check the URL/filename."
        );
    }
    Ok(())
}

/// Every loadable GGUF under `dir`, most recently written first. Descends one
/// level of subdirectories (operators commonly drop a repo folder in whole), and
/// skips the trailing pieces of a split model — llama.cpp opens those through
/// the "-00001-of-000NN" part, so only the first shard is offered.
pub fn list_gguf_models(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    fn collect(dir: &std::path::Path, depth: usize, out: &mut Vec<(std::time::SystemTime, std::path::PathBuf)>) {
        let entries = match std::fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let md = match entry.metadata() { Ok(m) => m, Err(_) => continue };
            if md.is_dir() {
                if depth > 0 { collect(&path, depth - 1, out); }
                continue;
            }
            if !md.is_file() || md.len() == 0 { continue; }
            let name = entry.file_name().to_string_lossy().to_string();
            if !is_gguf(&name) || is_split_shard(&name) { continue; }
            out.push((md.modified().unwrap_or(std::time::UNIX_EPOCH), path));
        }
    }
    let mut found = Vec::new();
    collect(dir, 1, &mut found);
    found.sort_by(|a, b| b.0.cmp(&a.0));
    found.into_iter().map(|(_, p)| p).collect()
}

/// Any GGUF sitting in the models dir, most recently downloaded first. Used as
/// the fallback when the model we'd recommend for this hardware isn't there but
/// the operator has fetched something else with `--download-model <anything>`.
pub fn find_local_model() -> Option<std::path::PathBuf> {
    list_gguf_models(&crate::platform::models_dir()).into_iter().next()
}

/// One line per locally available GGUF, for error messages and `--list-models`.
fn local_model_summary() -> String {
    let dir = crate::platform::models_dir();
    let models = list_gguf_models(&dir);
    if models.is_empty() {
        return format!("   (no .gguf files found in {})", dir.display());
    }
    models.iter()
        .map(|p| {
            let bytes = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            let size = if bytes >= 1_073_741_824 {
                format!("{:.1}G", bytes as f64 / 1_073_741_824.0)
            } else {
                format!("{:.0}M", bytes as f64 / 1_048_576.0)
            };
            format!("   {:>6}  {}", size, p.display())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Turn whatever the operator pointed us at — `--model`, `NEBULA_MODEL`, or
/// `[llm].model_path` — into an actual GGUF on disk. Every reasonable way of
/// naming a model is accepted, so the agent loads what the operator meant:
///
///   • an absolute or relative path      /srv/models/my-model.gguf
///   • a directory of models             /srv/models        (newest GGUF wins)
///   • a bare filename in the models dir Qwen2.5-7B-Instruct-Q4_K_M.gguf
///   • the same without the extension    Qwen2.5-7B-Instruct-Q4_K_M
///   • a catalog alias already fetched   qwen2.5-7b
///   • a unique fragment of a filename   qwen  /  14b
///
/// Purely local: this never touches the network (that's `resolve_model_spec`,
/// which downloads). Errors list what IS available so the fix is obvious.
pub fn resolve_model_reference(spec: &str) -> anyhow::Result<std::path::PathBuf> {
    let spec = spec.trim();
    if spec.is_empty() {
        anyhow::bail!("empty model reference");
    }
    let dir = crate::platform::models_dir();
    let as_given = std::path::PathBuf::from(spec);

    // Paths first, in the order an operator would expect them to be tried.
    let mut candidates = vec![as_given.clone()];
    if as_given.is_relative() {
        candidates.push(dir.join(&as_given));
    }
    if !is_gguf(spec) {
        // Extension left off. Note: NOT with_extension(), which would eat the
        // ".5-mini" of "phi3.5-mini" and other dotted model names.
        let with_ext = std::path::PathBuf::from(format!("{}.gguf", spec));
        if as_given.is_relative() { candidates.push(dir.join(&with_ext)); }
        candidates.push(with_ext);
    }
    for cand in &candidates {
        if cand.is_file() {
            return Ok(cand.clone());
        }
        if cand.is_dir() {
            return list_gguf_models(cand).into_iter().next().ok_or_else(|| {
                anyhow::anyhow!("no .gguf model found in directory {}", cand.display())
            });
        }
    }

    // A catalog alias whose file was already downloaded.
    if let Some(entry) = catalog_entry(spec) {
        let path = dir.join(entry.file);
        if path.is_file() {
            return Ok(path);
        }
        anyhow::bail!(
            "catalog model '{}' is not downloaded yet ({} missing)\n\
             Fetch it with: nebula-agent --download-model {}",
            spec, path.display(), spec
        );
    }

    // Fragment of a filename ("--model qwen"). Unambiguous matches only.
    let needle = spec.to_ascii_lowercase();
    let local = list_gguf_models(&dir);
    let hits: Vec<&std::path::PathBuf> = local.iter()
        .filter(|p| p.file_name().map_or(false, |n|
            n.to_string_lossy().to_ascii_lowercase().contains(&needle)))
        .collect();
    match hits.len() {
        1 => Ok(hits[0].clone()),
        0 => anyhow::bail!(
            "no model matching '{}' found (looked for a path, a file in {}, a catalog alias, \
             and a filename fragment).\n Available locally:\n{}\n \
             Download one with: nebula-agent --download-model <alias|owner/repo|url>",
            spec, dir.display(), local_model_summary()
        ),
        _ => anyhow::bail!(
            "'{}' matches {} local models — be more specific:\n{}",
            spec, hits.len(),
            hits.iter().map(|p| format!("   {}", p.display())).collect::<Vec<_>>().join("\n")
        ),
    }
}

/// Download the recommended model for this hardware (`--download-model` with no
/// argument).
pub async fn download_agent_model(vram_mb: u64) -> anyhow::Result<String> {
    let alias = default_alias_for_vram(vram_mb);
    let src = resolve_model_spec(alias).await?;
    download_model(&src, None, None).await
}

/// Print the built-in catalog (`--list-models`).
pub fn print_model_catalog() {
    println!("Built-in model aliases for --download-model:\n");
    println!("  {:<13} {:>7}  {}", "ALIAS", "SIZE", "NOTES");
    for e in MODEL_CATALOG {
        println!("  {:<13} {:>6.1}G  {}", e.alias, e.size_gb, e.note);
        println!("  {:<13} {:>7}  {}/{}", "", "", e.repo, e.file);
    }
    println!("\nThe catalog is a convenience, not a limit — --download-model also takes:");
    println!("  a HuggingFace repo        nebula-agent --download-model bartowski/Qwen2.5-14B-Instruct-GGUF");
    println!("  a repo + exact quant      nebula-agent --download-model bartowski/Qwen2.5-7B-Instruct-GGUF:Qwen2.5-7B-Instruct-Q6_K.gguf");
    println!("  a direct URL              nebula-agent --download-model https://host/path/model.gguf");
    println!("  (gated repos: export HF_TOKEN=<token> first; --model-name renames the saved file)");
    println!("\nAir-gapped fleets: nebula-agent --download-from-nexus  (pulls what your Nexus serves)");

    println!("\nAvailable locally ({}):", crate::platform::models_dir().display());
    print_local_models();
    println!("\nLoad a specific one for a run:  nebula-agent --model <path|filename|alias|fragment>");
    println!("  e.g. nebula-agent --model qwen2.5-7b        (a catalog model already downloaded)");
    println!("       nebula-agent --model /srv/models/x.gguf (any GGUF, anywhere on disk)");
    println!("       nebula-agent --model /srv/models        (a directory — newest GGUF in it)");
}

/// Print the GGUFs the agent can load right now, newest first, with sizes.
pub fn print_local_models() {
    println!("{}", local_model_summary());
}

/// Render an in-place download progress line: a bar, percent, downloaded/total,
/// throughput, and (when total is known) an ETA. Uses \r so it updates on one
/// line. Falls back to a byte counter when the server didn't send a length.
fn render_progress(downloaded: u64, total: Option<u64>, elapsed_secs: f64) {
    let mib = |b: u64| b as f64 / 1_048_576.0;
    let rate = if elapsed_secs > 0.0 { mib(downloaded) / elapsed_secs } else { 0.0 };
    match total {
        Some(t) if t > 0 => {
            let frac = (downloaded as f64 / t as f64).clamp(0.0, 1.0);
            let width = 30usize;
            let filled = (frac * width as f64).round() as usize;
            let bar: String = "█".repeat(filled) + &"░".repeat(width - filled);
            let eta = if rate > 0.0 { (mib(t) - mib(downloaded)) / rate } else { 0.0 };
            print!("\r   [{}] {:>5.1}%  {:>6.0}/{:.0} MiB  {:>5.1} MiB/s  ETA {:>3.0}s   ",
                bar, frac * 100.0, mib(downloaded), mib(t), rate, eta);
        }
        _ => {
            // Unknown total — show accumulated size + rate only.
            print!("\r   {:>7.0} MiB downloaded  {:>5.1} MiB/s   ", mib(downloaded), rate);
        }
    }
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// Fetch a model from the NEXUS (air-gapped fleets) instead of HuggingFace.
/// Supports resume (HTTP Range) and verifies the SHA-256 the Nexus reports.
/// `nexus_url` like "https://nexus.local:9443", `api_key` for auth.
/// Which inference engine THIS agent build embeds. A `--features bitnet` build
/// links the bitnet.cpp fork (loads fork-only I2_S/TL ternary AND ordinary
/// GGUFs); every other build links stock llama.cpp (loads ordinary GGUFs,
/// including native TQ1_0/TQ2_0 ternary, but NOT the fork-only I2_S formats).
pub fn agent_llm_engine() -> &'static str {
    if cfg!(feature = "bitnet") { "bitnet" } else { "llama.cpp" }
}

/// Can an agent whose embedded engine is `mine` load a model the Nexus tagged
/// with engine `model`? A bitnet build is a superset; a stock build can load
/// anything except the fork-only formats.
pub fn engine_loadable(mine: &str, model: &str) -> bool {
    match mine {
        "bitnet" => true,
        _        => model != "bitnet",
    }
}

pub async fn download_model_from_nexus(
    nexus_url: &str,
    api_key: &str,
    preferred_name: Option<&str>,
    ca_cert_path: Option<&str>,
    tls_verify: bool,
) -> anyhow::Result<String> {
    let client = crate::tls::nexus_http_builder(ca_cert_path, tls_verify)
        .timeout(std::time::Duration::from_secs(7200))
        .build()?;

    // 1. Ask the Nexus what models it can serve.
    let list_url = format!("{}/api/atc/models", nexus_url.trim_end_matches('/'));
    let resp = client.get(&list_url).header("X-Api-Key", api_key).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Nexus model list failed: HTTP {}", resp.status());
    }
    let listing: serde_json::Value = resp.json().await?;
    let models = listing["models"].as_array().cloned().unwrap_or_default();
    if models.is_empty() {
        anyhow::bail!("Nexus has no models to distribute");
    }
    // Pick a model this BUILD can actually load. The Nexus advertises an
    // `engine` per model ("bitnet" for fork-only I2_S/TL weights, "llama.cpp"
    // for stock upstream — which now INCLUDES native TQ1_0/TQ2_0 ternary). A
    // default (stock llama.cpp) agent must never auto-pull an I2_S model it
    // cannot decode; a `--features bitnet` agent can load either. An operator
    // who names a model explicitly gets it (with a warning on mismatch) — their
    // call. A missing engine field (older Nexus) defaults to "llama.cpp", which
    // a stock build can load.
    let my_engine = agent_llm_engine();
    let engine_of = |m: &serde_json::Value| m["engine"].as_str().unwrap_or("llama.cpp").to_string();
    let model = if let Some(n) = preferred_name {
        let m = models.iter().find(|m| m["name"].as_str() == Some(n))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Nexus does not serve a model named '{}'", n))?;
        if !engine_loadable(my_engine, &engine_of(&m)) {
            tracing::warn!("⚠️  requested model '{}' needs the '{}' engine but this agent is a '{}' build — load may fail",
                n, engine_of(&m), my_engine);
        }
        m
    } else {
        match models.iter().find(|m| engine_loadable(my_engine, &engine_of(m))).cloned() {
            Some(m) => m,
            None => anyhow::bail!(
                "Nexus serves {} model(s) but none are loadable by this '{}' build \
                 (they need the other inference engine). Build with the matching feature \
                 or have the Nexus serve a compatible model.",
                models.len(), my_engine),
        }
    };
    let name = model["name"].as_str().unwrap_or("model.gguf").to_string();
    tracing::info!("📦 Selected Nexus model '{}' (engine={}, this build={})", name, engine_of(&model), my_engine);
    let expected_sha = model["sha256"].as_str().unwrap_or("").to_string();
    let expected_size = model["size"].as_u64().unwrap_or(0);

    let model_dir = "/var/lib/nebula/models";
    std::fs::create_dir_all(model_dir)?;
    let dest = format!("{}/{}", model_dir, name);
    let tmp = format!("{}.part", dest);

    // Already present and verified?
    if std::path::Path::new(&dest).exists() {
        tracing::info!("✅ Model already present: {}", dest);
        return Ok(dest);
    }

    // Resume from a partial .part if present.
    let mut start: u64 = std::fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0);
    if start >= expected_size && expected_size > 0 { start = 0; }   // stale/oversized part — restart

    tracing::info!("📥 Fetching {} from Nexus ({} MB){}",
        name, expected_size / 1024 / 1024,
        if start > 0 { format!(", resuming at {} MB", start/1024/1024) } else { String::new() });

    let dl_url = format!("{}/api/atc/models/{}", nexus_url.trim_end_matches('/'), name);
    let mut req = client.get(&dl_url).header("X-Api-Key", api_key);
    if start > 0 { req = req.header(reqwest::header::RANGE, format!("bytes={}-", start)); }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Nexus model download failed: HTTP {}", resp.status());
    }

    use tokio::io::AsyncWriteExt;
    let append = start > 0 && resp.status() == reqwest::StatusCode::PARTIAL_CONTENT;
    let mut file = if append {
        tokio::fs::OpenOptions::new().append(true).open(&tmp).await?
    } else {
        tokio::fs::File::create(&tmp).await?
    };

    // Stream with a live progress bar. When resuming, count the bytes already on
    // disk toward the total so the percentage reflects overall completion. Total
    // is the Nexus-reported expected_size (falls back to Content-Length).
    let resume_from = if append { start } else { 0 };
    let total = if expected_size > 0 { Some(expected_size) }
                else { resp.content_length().map(|c| c + resume_from) };
    let mut downloaded: u64 = resume_from;
    let started = std::time::Instant::now();
    let mut last_render = std::time::Instant::now();
    let mut resp = resp;
    println!("📥 Fetching {} from Nexus …", name);
    while let Some(chunk) = resp.chunk().await? {
        file.write_all(&chunk).await?;
        downloaded += chunk.len() as u64;
        if last_render.elapsed().as_millis() >= 200 {
            render_progress(downloaded, total, started.elapsed().as_secs_f64());
            last_render = std::time::Instant::now();
        }
    }
    file.flush().await?;
    render_progress(downloaded, total, started.elapsed().as_secs_f64());
    println!();
    drop(file);

    // Verify integrity against the Nexus-reported SHA-256.
    if !expected_sha.is_empty() {
        let actual = tokio::task::spawn_blocking({
            let tmp = tmp.clone();
            move || {
                use sha2::{Sha256, Digest};
                let mut f = std::fs::File::open(&tmp).ok()?;
                let mut h = Sha256::new();
                std::io::copy(&mut f, &mut h).ok()?;
                Some(format!("{:x}", h.finalize()))
            }
        }).await.ok().flatten().unwrap_or_default();
        if actual != expected_sha {
            let _ = std::fs::remove_file(&tmp);
            anyhow::bail!("Checksum mismatch (expected {}, got {}); discarded download", expected_sha, actual);
        }
        tracing::info!("✅ Checksum verified");
    }

    tokio::fs::rename(&tmp, &dest).await?;
    tracing::info!("✅ Model installed: {}", dest);
    Ok(dest)
}

#[derive(Debug, Clone)]
pub struct LLMAnalysis {
    pub suspicious:             bool,
    pub confidence_adjustment:  f32,
    pub explanation:            String,
    pub mitre_refinement:       Vec<String>,
    pub generated_rule:         Option<DetectionRule>,
}

// ─────────────────────────────────────────────────────────────
// Backend abstraction
// ─────────────────────────────────────────────────────────────

/// A loaded model session capable of running inference.
/// The active inference backend (embedded llama.cpp, or unavailable).
pub enum InferenceBackend {
    #[cfg(feature = "embedded-llm")]
    Embedded(EmbeddedBackend),
    Remote(RemoteBackend),
    Unavailable,
}

impl InferenceBackend {
    pub async fn generate(&self, system: &str, prompt: &str, max_tokens: u32) -> Result<String> {
        match self {
            #[cfg(feature = "embedded-llm")]
            InferenceBackend::Embedded(b) => b.generate(system, prompt, max_tokens).await,
            InferenceBackend::Remote(r) => r.generate(system, prompt, max_tokens).await,
            InferenceBackend::Unavailable => anyhow::bail!("LLM unavailable"),
        }
    }

    pub fn backend_name(&self) -> &str {
        match self {
            #[cfg(feature = "embedded-llm")]
            InferenceBackend::Embedded(_) => "embedded-llama.cpp",
            InferenceBackend::Remote(_) => "remote-nebulacerebro",
            InferenceBackend::Unavailable => "unavailable",
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Remote ATC backend (NebulaCerebro / OpenAI-compatible endpoint)
// ─────────────────────────────────────────────────────────────
// Borrows inference from a remote endpoint when the local model isn't available.
// Speaks the OpenAI /v1/chat/completions shape, which the Nexus Whisper, a
// dedicated NebulaCerebro node, vLLM, Ollama, and llama.cpp-server all support —
// maximizing compatibility without coupling to one server.
//
// Design guardrails (from the architecture discussion):
//   • Local-first: only constructed when remote_atc != "off" AND
//     (local unavailable, or remote_atc == "always").
//   • Bounded blast radius: short timeout; on timeout/error the caller falls
//     through to Legacy so detection never stalls waiting on a remote brain.
//   • Honest provenance: analysis is still tagged ATC, but backend_name
//     ("remote-nebulacerebro") makes the source visible.
#[derive(Clone)]
pub struct RemoteBackend {
    client:  reqwest::Client,
    url:     String,
    api_key: Option<String>,
    model:   String,
}

impl RemoteBackend {
    /// Probe + construct. Verifies the endpoint is reachable so an unreachable
    /// remote degrades to Legacy at startup rather than failing every analysis.
    pub async fn connect(config: &LLMConfig) -> Result<Self> {
        let base = config.remote_url.clone()
            .ok_or_else(|| anyhow::anyhow!("remote_atc enabled but remote_url not set"))?;
        let base = base.trim_end_matches('/').to_string();
        let url = if base.ends_with("/chat/completions") {
            base
        } else if base.ends_with("/v1") {
            format!("{}/chat/completions", base)
        } else {
            format!("{}/v1/chat/completions", base)
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.remote_timeout_secs.max(5)))
            .build()
            .map_err(|e| anyhow::anyhow!("remote client build failed: {e}"))?;

        let backend = RemoteBackend {
            client, url,
            api_key: config.remote_api_key.clone(),
            model:   config.remote_model.clone(),
        };

        // Lightweight reachability check at startup.
        match backend.generate("You are a health check.", "Reply with: OK", 8).await {
            Ok(_) => {
                info!("🧠 LLM: remote ATC (NebulaCerebro) reachable at {}", backend.url);
                Ok(backend)
            }
            Err(e) => anyhow::bail!("remote ATC endpoint unreachable: {e}"),
        }
    }

    pub async fn generate(&self, system: &str, prompt: &str, max_tokens: u32) -> Result<String> {
        let mut req = self.client.post(&self.url).json(&serde_json::json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": prompt}
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
            "stream": false,
        }));
        if let Some(ref k) = self.api_key {
            req = req.header("authorization", format!("Bearer {}", k));
        }

        let resp = req.send().await
            .map_err(|e| anyhow::anyhow!("remote ATC request failed: {e}"))?;
        if !resp.status().is_success() {
            anyhow::bail!("remote ATC returned HTTP {}", resp.status());
        }
        let body: serde_json::Value = resp.json().await
            .map_err(|e| anyhow::anyhow!("remote ATC bad JSON: {e}"))?;

        let content = body["choices"].get(0)
            .and_then(|c| c["message"]["content"].as_str())
            .map(|s| s.to_string());
        match content {
            Some(c) if !c.trim().is_empty() => Ok(c),
            _ => anyhow::bail!("remote ATC empty response"),
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Embedded llama.cpp backend
// ─────────────────────────────────────────────────────────────

#[cfg(feature = "embedded-llm")]
pub struct EmbeddedBackend {
    // Backend + model are immutable and shared; a fresh context is created per
    // generate() call (contexts are cheap relative to the model weights).
    inner:    std::sync::Arc<EmbeddedInner>,
    params:   LlamaInferenceParams,
    gpu_info: Option<GpuInfo>,
    // The GGUF actually loaded (after auto-detection / --model resolution), so
    // the status UI and Nexus health view report the real model, not the request.
    model_path: std::path::PathBuf,
}

#[cfg(feature = "embedded-llm")]
struct EmbeddedInner {
    backend: llama_cpp_2::llama_backend::LlamaBackend,
    model:   llama_cpp_2::model::LlamaModel,
}

#[cfg(feature = "embedded-llm")]
#[derive(Clone)]
struct LlamaInferenceParams {
    n_ctx:       u32,   // context window
    n_threads:   i32,   // CPU threads (-1 = auto)
    n_gpu_layers: i32,  // GPU layers (0 = CPU, -1 = all on GPU, N = N layers)
    temperature:  f32,
    top_p:        f32,
    repeat_penalty: f32,
}

#[cfg(feature = "embedded-llm")]
impl EmbeddedBackend {
    pub async fn load(config: &LLMConfig) -> Result<Self> {
        use llama_cpp_2::llama_backend::LlamaBackend;
        use llama_cpp_2::model::params::LlamaModelParams;
        use llama_cpp_2::model::LlamaModel;

        let gpu_info = probe_gpu().await;

        // Model auto-selection. When the operator FORCES CPU (compute_mode="cpu")
        // we pick the light CPU model regardless of whether a GPU is present —
        // otherwise a GPU-tier model (e.g. Qwen-7B) would be loaded onto the CPU
        // and run painfully slowly. VRAM-based selection only applies when we'll
        // actually offload to the GPU.
        let force_cpu = config.compute_mode.eq_ignore_ascii_case("cpu");

        // What the operator asked for, if anything. A blank string counts as
        // "unset" — config templates ship the key commented or empty, and an
        // empty model_path must mean auto-detect, not "load the file named ''".
        let requested = config.model_path.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        // Auto-detection: the model recommended for this hardware if it's there,
        // otherwise whatever GGUF the operator actually put in the models dir
        // (`--download-model <any repo/url>` may have fetched something else).
        let auto_select = || -> Option<std::path::PathBuf> {
            let recommended = match (&gpu_info, force_cpu) {
                (Some(g), false) => {
                    let vram = config.gpu_vram_mb.unwrap_or(g.vram_mb);
                    select_model_path_for_vram(vram)
                }
                // No GPU, or CPU forced → the light CPU default (matches what
                // `--download-model` fetches with no argument).
                _ => select_model_path_for_vram(0),
            };
            let recommended = std::path::PathBuf::from(recommended);
            if recommended.is_file() {
                return Some(recommended);
            }
            let local = find_local_model()?;
            info!("🧠 Recommended model not present — using the GGUF found in the models dir: {}",
                local.display());
            Some(local)
        };

        let model_path: std::path::PathBuf = match requested {
            Some(spec) => match resolve_model_reference(spec) {
                Ok(path) => path,
                Err(e) => {
                    // The requested model can't be loaded. Rather than dropping
                    // ATC entirely, fall back to any model that IS present —
                    // loudly, so the operator can see the substitution.
                    warn!("⚠️  Requested model '{}' could not be resolved: {}", spec, e);
                    match auto_select() {
                        Some(p) => {
                            warn!("   Falling back to the model available locally: {}", p.display());
                            p
                        }
                        None => return Err(e),
                    }
                }
            },
            None => match auto_select() {
                Some(p) => p,
                None => anyhow::bail!(
                    "no ATC model file found in {}\n\
                     Local inference is compiled in and will run on CPU — it just needs a GGUF model.\n\
                     Provide one with ONE of:\n\
                       nebula-agent --download-from-nexus   (air-gapped: pulls the model your Nexus serves)\n\
                       nebula-agent --download-model         (internet: the model recommended for this box)\n\
                       nebula-agent --download-model <alias|owner/repo|url>   (any GGUF — see --list-models)\n\
                     or point the agent at one you already have:\n\
                       nebula-agent --model /path/to/model.gguf   (or set [llm].model_path)",
                    crate::platform::models_dir().display()
                ),
            },
        };

        let n_gpu_layers = match config.compute_mode.as_str() {
            "cpu" => 0,
            "gpu" => {
                if gpu_info.is_none() { anyhow::bail!("compute_mode=gpu but no GPU detected"); }
                if config.gpu_layers == 0 { -1 } else { config.gpu_layers }
            }
            _ => { // "auto"
                if gpu_info.is_some() {
                    if config.gpu_layers == 0 { -1 } else { config.gpu_layers }
                } else { 0 }
            }
        };

        info!("🧠 Loading embedded model: {}", model_path.display());
        info!("   GPU layers: {} ({})", n_gpu_layers,
            if n_gpu_layers == 0 { "CPU only" }
            else if n_gpu_layers < 0 { "all layers on GPU" }
            else { "split CPU+GPU" });

        let n_threads = if n_gpu_layers == 0 {
            (num_cpus_physical() as i32).max(1)
        } else {
            (num_cpus_physical() as i32 / 2).max(1)
        };

        let params = LlamaInferenceParams {
            n_ctx:          config.max_context_tokens.max(512),
            n_threads,
            n_gpu_layers,
            temperature:    0.2,   // low = consistent security analysis
            top_p:          0.9,
            repeat_penalty: 1.1,
        };

        // Load backend + model on a blocking thread (loading mmaps/parses GBs).
        let load_path = model_path.clone();
        let inner = tokio::task::spawn_blocking(move || -> Result<EmbeddedInner> {
            let backend = LlamaBackend::init()
                .map_err(|e| anyhow::anyhow!("llama backend init failed: {e}"))?;
            // -1 (all) maps to a large layer count for the offload request.
            let ngl = if n_gpu_layers < 0 { 999 } else { n_gpu_layers as u32 };
            let model_params = LlamaModelParams::default().with_n_gpu_layers(ngl);
            let model = LlamaModel::load_from_file(&backend, &load_path, &model_params)
                .map_err(|e| anyhow::anyhow!("Failed to load GGUF model: {e}"))?;
            Ok(EmbeddedInner { backend, model })
        }).await??;

        info!("✅ Embedded LLM loaded (threads={} ctx={})", n_threads, params.n_ctx);
        if let Some(ref g) = gpu_info {
            info!("   GPU: {} — {} — {} MB VRAM", g.vendor, g.name, g.vram_mb);
        }

        Ok(Self { inner: std::sync::Arc::new(inner), params, gpu_info, model_path })
    }

    /// The GGUF this backend actually loaded.
    pub fn model_path(&self) -> &std::path::Path { &self.model_path }

    // token_to_bytes + Special::Tokenize are marked deprecated in llama-cpp-2,
    // but they are functional and not slated for removal in the 0.1.x line. The
    // suggested replacements (token_to_piece / token_to_piece_bytes) require a
    // caller-supplied encoding_rs::Decoder, which would add a version-coupled
    // dependency for no behavioral gain here. Silence the lint for this method
    // only; revisit if we move to a major llama-cpp-2 bump.
    #[allow(deprecated)]
    pub async fn generate(&self, system: &str, prompt: &str, max_tokens: u32) -> Result<String> {
        use llama_cpp_2::context::params::LlamaContextParams;
        use llama_cpp_2::llama_batch::LlamaBatch;
        use llama_cpp_2::model::{AddBos, Special};
        use llama_cpp_2::sampling::LlamaSampler;
        use std::num::NonZeroU32;

        // ChatML framing (Phi-3 / Qwen / most instruct models understand this).
        let full_prompt = format!(
            "<|system|>\n{}<|end|>\n<|user|>\n{}<|end|>\n<|assistant|>\n",
            system, prompt
        );

        let inner = self.inner.clone();
        let params = self.params.clone();
        let max_tok = max_tokens as i32;

        let result = tokio::task::spawn_blocking(move || -> Result<String> {
            let model = &inner.model;

            // Fresh context per call.
            let ctx_params = LlamaContextParams::default()
                .with_n_ctx(NonZeroU32::new(params.n_ctx))
                .with_n_threads(params.n_threads)
                .with_n_threads_batch(params.n_threads);
            let mut ctx = model.new_context(&inner.backend, ctx_params)
                .map_err(|e| anyhow::anyhow!("context creation failed: {e}"))?;

            // Tokenize the prompt.
            let tokens = model.str_to_token(&full_prompt, AddBos::Always)
                .map_err(|e| anyhow::anyhow!("tokenize failed: {e}"))?;

            let n_ctx = params.n_ctx as i32;
            // Feed the prompt as one batch; request logits only on the last token.
            let mut batch = LlamaBatch::new(n_ctx.max(tokens.len() as i32 + 1) as usize, 1);
            let last_idx = tokens.len() as i32 - 1;
            for (i, tok) in tokens.iter().enumerate() {
                batch.add(*tok, i as i32, &[0], i as i32 == last_idx)
                    .map_err(|e| anyhow::anyhow!("batch add failed: {e}"))?;
            }
            ctx.decode(&mut batch).map_err(|e| anyhow::anyhow!("decode failed: {e}"))?;

            // Sampler chain: repetition penalty → top-p → temperature → distribution.
            let mut sampler = LlamaSampler::chain_simple([
                LlamaSampler::penalties(64, params.repeat_penalty, 0.0, 0.0),
                LlamaSampler::top_p(params.top_p, 1),
                LlamaSampler::temp(params.temperature),
                LlamaSampler::dist(1234),
            ]);

            let mut output = String::new();
            let mut n_cur = batch.n_tokens();
            let mut n_decoded = 0i32;
            while n_decoded < max_tok && n_cur < n_ctx {
                // Sample from the logits of the last decoded position.
                let token = sampler.sample(&ctx, batch.n_tokens() - 1);
                sampler.accept(token);

                if model.is_eog_token(token) { break; }
                // token_to_bytes returns the raw vocab bytes for this token; we
                // assemble them into UTF-8 ourselves. This is the simplest decode
                // path that needs no encoding_rs decoder and no deprecated string
                // helper. (A token may be a partial UTF-8 sequence; from_utf8_lossy
                // tolerates that — worst case a transient replacement char that
                // resolves as subsequent tokens arrive.)
                let piece_bytes = model.token_to_bytes(token, Special::Tokenize).unwrap_or_default();
                let piece = String::from_utf8_lossy(&piece_bytes);
                // Stop on chat-template terminators that aren't flagged as EOG.
                if piece.contains("<|end|>") || piece.contains("<|endoftext|>") || piece.contains("<|user|>") {
                    break;
                }
                output.push_str(&piece);

                // Feed the sampled token back in for the next step.
                batch.clear();
                batch.add(token, n_cur, &[0], true)
                    .map_err(|e| anyhow::anyhow!("batch add failed: {e}"))?;
                ctx.decode(&mut batch).map_err(|e| anyhow::anyhow!("decode failed: {e}"))?;
                n_cur += 1;
                n_decoded += 1;
            }

            Ok(output.trim().to_string())
        }).await??;

        Ok(result)
    }
}

fn num_cpus_physical() -> usize {
    // Read from /proc/cpuinfo — count unique "core id" entries
    std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| {
            let cores: std::collections::HashSet<&str> = s.lines()
                .filter(|l| l.starts_with("core id"))
                .collect();
            cores.len().max(1)
        })
        .unwrap_or(4)
}

// ─────────────────────────────────────────────────────────────
// Main LLM Engine
// ─────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────
// Host context (#1) — tells ATC WHAT host it's reasoning about, so the
// benign-explanation step is grounded ("sudo root shell" is routine on an admin
// workstation, alarming on an internet-facing web server). Assembled once from
// the inventory/baseline data the agent already collects, refreshable on rescan.
// ─────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Default)]
pub struct HostContext {
    pub hostname:        String,
    pub os:              String,
    pub role:            String,   // inferred: "server"/"workstation"/"domain controller"/…
    pub internet_facing: bool,
    pub listening_ports: Vec<u16>, // a few notable ports → hints at what the box does
    pub key_services:    Vec<String>, // notable running/installed services (nginx, sshd…)
    pub notes:           String,   // freeform extra ("no interactive logins in baseline")
}

impl HostContext {
    /// Render a compact context block for the prompt. Kept short — a couple of
    /// lines — so it grounds reasoning without eating the model's context window.
    fn render(&self) -> String {
        if self.hostname.is_empty() && self.os.is_empty() {
            return "HOST CONTEXT: unknown (inventory not yet available).".to_string();
        }
        let ports = if self.listening_ports.is_empty() {
            "none observed".to_string()
        } else {
            self.listening_ports.iter().take(8)
                .map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        };
        let svcs = if self.key_services.is_empty() {
            "none identified".to_string()
        } else {
            self.key_services.iter().take(8).cloned().collect::<Vec<_>>().join(", ")
        };
        let mut s = format!(
            "HOST CONTEXT:\n  Role: {} ({})\n  OS: {}\n  Exposure: {}\n  Listening ports: {}\n  Key services: {}",
            if self.role.is_empty() { "unclassified" } else { &self.role },
            self.hostname,
            if self.os.is_empty() { "unknown" } else { &self.os },
            if self.internet_facing { "INTERNET-FACING" } else { "internal only" },
            ports, svcs,
        );
        if !self.notes.is_empty() {
            s.push_str(&format!("\n  Baseline note: {}", self.notes));
        }
        s
    }
}

// ─────────────────────────────────────────────────────────────
// Verdict memory (#2) — a bounded, TTL'd cache of prior ATC conclusions keyed on
// the detection's SHAPE (technique + process + host). Lets ATC recall "I judged
// this exact pattern benign here an hour ago" instead of re-reasoning from zero
// every time — cutting inference cost/battery, improving consistency, and giving
// the model its own history as evidence.
// ─────────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
struct PriorVerdict {
    is_true_positive: bool,
    assessment:       String,
    confidence_adj:   f32,
    at:               DateTime<Utc>,
    hits:             u32,   // how many times this pattern recurred
}

const VERDICT_TTL_SECS: i64 = 6 * 3600;   // a recalled verdict is "fresh" for 6h
const VERDICT_CACHE_MAX: usize = 512;      // bounded memory footprint

pub struct LLMEngine {
    config:   LLMConfig,
    backend:  InferenceBackend,
    gpu_info: Option<GpuInfo>,
    // Interior-mutable so the Arc'd engine can be updated after inventory runs
    // and as verdicts accumulate, without threading state through every call.
    host_ctx: StdRwLock<HostContext>,
    verdicts: StdRwLock<HashMap<String, PriorVerdict>>,
}

impl HostContext {
    /// Infer host context from an inventory snapshot. Role and exposure are
    /// heuristics from listening ports — good enough to ground ATC's reasoning,
    /// and cheap. Operators can later override role via config if desired.
    pub fn from_inventory(hostname: &str, os: &str, open_ports: &[u16]) -> Self {
        let has = |p: u16| open_ports.contains(&p);
        // Notable services inferred from well-known listening ports.
        let mut key_services = Vec::new();
        if has(22)   { key_services.push("sshd".to_string()); }
        if has(80) || has(443) || has(8080) || has(8443) { key_services.push("web server".to_string()); }
        if has(3306) || has(5432) || has(1433) || has(27017) { key_services.push("database".to_string()); }
        if has(53)   { key_services.push("DNS".to_string()); }
        if has(389) || has(636) || has(88) { key_services.push("directory/LDAP/Kerberos".to_string()); }
        if has(445) || has(139) { key_services.push("SMB file sharing".to_string()); }
        if has(25) || has(587) || has(465) { key_services.push("mail".to_string()); }
        if has(3389) { key_services.push("RDP".to_string()); }

        // Internet-facing heuristic: common inbound service ports are listening.
        let internet_facing = has(80) || has(443) || has(25) || has(53) || has(3389) || has(21);

        // Role heuristic — coarse but useful for grounding.
        let role = if has(88) || has(389) || has(636) {
            "domain controller / directory"
        } else if has(3306) || has(5432) || has(1433) || has(27017) {
            "database server"
        } else if has(80) || has(443) || has(8080) || has(8443) {
            "web/application server"
        } else if has(25) || has(587) {
            "mail server"
        } else if has(53) {
            "DNS server"
        } else if os.to_lowercase().contains("server") {
            "server"
        } else if !open_ports.is_empty() {
            "server (unclassified services)"
        } else {
            "workstation / endpoint"
        }.to_string();

        HostContext {
            hostname: hostname.to_string(),
            os: os.to_string(),
            role,
            internet_facing,
            listening_ports: open_ports.iter().take(12).cloned().collect(),
            key_services,
            notes: String::new(),
        }
    }
}

// Extract the first balanced {...} JSON object from a string that may contain
// surrounding prose. Brace-depth balanced and string/escape aware. Used to
// salvage JSON from chatty or malformed model output before giving up.
fn extract_json_object(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let start = s.find('{')?;
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for i in start..bytes.len() {
        let c = bytes[i] as char;
        if in_str {
            if escaped { escaped = false; }
            else if c == '\\' { escaped = true; }
            else if c == '"' { in_str = false; }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 { return Some(s[start..=i].to_string()); }
            }
            _ => {}
        }
    }
    None
}

impl LLMEngine {
    /// Initialize the LLM engine.
    /// With "embedded-llm" feature: loads the GGUF model directly into process memory.
    /// Loads the embedded llama.cpp model. If no model file is present, LLM
    /// enrichment is disabled (events are still detected and forwarded).
    pub async fn new(config: LLMConfig) -> Self {
        if !config.enabled {
            return Self::assemble(config, InferenceBackend::Unavailable, None);
        }

        let gpu_info = probe_gpu().await;
        let remote_mode = config.remote_atc.as_str();

        // ── ATC cascade: local-first, optional remote fallback, then legacy ──
        // 1. If remote_atc == "always", try remote first (thin-agent mode).
        // 2. Otherwise try the local embedded model.
        // 3. If local is unavailable and remote_atc == "fallback", try remote.
        // 4. If nothing loads, Unavailable (Legacy detection continues).
        if remote_mode == "always" {
            match RemoteBackend::connect(&config).await {
                Ok(r) => {
                    info!("🧠 LLM: remote ATC active (remote_atc=always)");
                    return Self::assemble(config, InferenceBackend::Remote(r), gpu_info);
                }
                Err(e) => warn!("⚠️  Remote ATC (always) unavailable: {} — trying local…", e),
            }
        }

        // ── If this binary was built WITHOUT embedded-llm, say so LOUDLY ──
        // Otherwise the operator only sees a generic "no backend available" and
        // can't tell that local inference simply wasn't compiled in (the #1 cause
        // of "ATC won't run" — the light `--no-default-features` build omits it).
        #[cfg(not(feature = "embedded-llm"))]
        {
            warn!("⚠️  ATC local inference is NOT compiled into this binary \
                   (built without the 'embedded-llm' feature).");
            warn!("   To run inference on CPU, rebuild with local inference (needs a C++ toolchain — cc/g++/cmake):");
            warn!("     cargo build --release                 # default features include embedded-llm (CPU by default)");
            warn!("   Then provide a model:  nebula-agent --download-from-nexus   (air-gapped)");
            warn!("                     or:  nebula-agent --download-model         (internet)");
            warn!("   Alternatively set [llm].remote_atc=\"fallback\" to borrow inference from the Nexus/NebulaCerebro.");
        }

        // ── Embedded llama.cpp (local-first default) ──
        #[cfg(feature = "embedded-llm")]
        {
            match EmbeddedBackend::load(&config).await {
                Ok(backend) => {
                    let ginfo = backend.gpu_info.clone();
                    info!("🧠 LLM: embedded llama.cpp backend active");
                    info!("   backend  : {}", if ginfo.is_some() { "GPU" } else { "CPU" });
                    return Self::assemble(config, InferenceBackend::Embedded(backend), ginfo);
                }
                Err(e) => {
                    warn!("⚠️  Embedded LLM model not loaded: {}", e);
                    if remote_mode == "fallback" {
                        warn!("   remote_atc=fallback set — attempting remote ATC (NebulaCerebro)…");
                    } else {
                        warn!("   To provide one, run ONE of:");
                        warn!("     nebula-agent --download-from-nexus   (air-gapped: pulls from your Nexus)");
                        warn!("     nebula-agent --download-model          (internet: pulls from HuggingFace)");
                    }
                }
            }
        }

        // ── Remote fallback: local was unavailable ──
        if remote_mode == "fallback" {
            match RemoteBackend::connect(&config).await {
                Ok(r) => {
                    info!("🧠 LLM: remote ATC (NebulaCerebro) active as fallback — local model unavailable");
                    return Self::assemble(config, InferenceBackend::Remote(r), gpu_info);
                }
                Err(e) => warn!("⚠️  Remote ATC fallback unavailable: {}", e),
            }
        }

        warn!("⚠️  LLM enrichment disabled — no local or remote backend available.");
        warn!("   Threat events are still detected and forwarded; only AI summaries are skipped.");
        Self::assemble(config, InferenceBackend::Unavailable, gpu_info)
    }

    /// Build an engine with empty host-context + verdict memory. Single place the
    /// two interior-mutable fields are initialized, so the many return paths in
    /// `new()` stay uniform.
    fn assemble(config: LLMConfig, backend: InferenceBackend, gpu_info: Option<GpuInfo>) -> Self {
        Self {
            config, backend, gpu_info,
            host_ctx: StdRwLock::new(HostContext::default()),
            verdicts: StdRwLock::new(HashMap::new()),
        }
    }

    /// Update the host context ATC reasons with. Called after inventory runs and
    /// on each rescan. Cheap; takes a brief write lock.
    pub fn set_host_context(&self, ctx: HostContext) {
        if let Ok(mut hc) = self.host_ctx.write() { *hc = ctx; }
    }

    /// A stable signature for a detection's SHAPE — the verdict-memory key.
    /// Coarse enough that recurrences of the "same kind" of event collapse
    /// together, specific enough that distinct threats don't collide.
    fn verdict_key(threat: &ThreatEvent) -> String {
        let mut techs = threat.mitre_techniques.clone();
        techs.sort();
        let proc = threat.iocs.iter()
            .find(|i| format!("{:?}", i.ioc_type).to_lowercase().contains("process"))
            .map(|i| i.value.clone())
            .unwrap_or_else(|| threat.threat_name.clone());
        format!("{}|{}|{}", threat.hostname, techs.join(","), proc)
    }

    /// Look up a fresh prior verdict for this detection shape, if any.
    fn recall_verdict(&self, key: &str) -> Option<PriorVerdict> {
        let map = self.verdicts.read().ok()?;
        let v = map.get(key)?.clone();
        if (Utc::now() - v.at).num_seconds() <= VERDICT_TTL_SECS { Some(v) } else { None }
    }

    /// Fast-path reinforcement: a recurring detection matched a cached verdict, so
    /// bump its recurrence counter and refresh its recency (keeping it warm in the
    /// TTL window) WITHOUT re-running the model.
    fn reinforce_verdict(&self, key: &str) {
        if let Ok(mut map) = self.verdicts.write() {
            if let Some(v) = map.get_mut(key) {
                v.hits += 1;
                v.at = Utc::now();
            }
        }
    }

    /// Record (or reinforce) a verdict for this detection shape. Bounds the cache
    /// by evicting the oldest entry when full.
    fn remember_verdict(&self, key: String, is_tp: bool, assessment: &str, adj: f32) {
        if let Ok(mut map) = self.verdicts.write() {
            if let Some(existing) = map.get_mut(&key) {
                existing.hits += 1;
                existing.at = Utc::now();
                existing.is_true_positive = is_tp;
                existing.confidence_adj = adj;
                return;
            }
            if map.len() >= VERDICT_CACHE_MAX {
                if let Some(oldest) = map.iter().min_by_key(|(_, v)| v.at).map(|(k, _)| k.clone()) {
                    map.remove(&oldest);
                }
            }
            map.insert(key, PriorVerdict {
                is_true_positive: is_tp, assessment: assessment.to_string(),
                confidence_adj: adj, at: Utc::now(), hits: 1,
            });
        }
    }

    pub fn is_gpu_active(&self) -> bool {
        self.gpu_info.is_some() && !matches!(self.config.compute_mode.as_str(), "cpu")
    }

    pub fn backend_name(&self) -> &str { self.backend.backend_name() }

    /// The model actually in use: the loaded GGUF's filename for the embedded
    /// backend, "remote:<id>" for a borrowed brain, None when ATC is inactive.
    pub fn active_model(&self) -> Option<String> {
        match &self.backend {
            #[cfg(feature = "embedded-llm")]
            InferenceBackend::Embedded(b) => Some(
                b.model_path().file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| b.model_path().to_string_lossy().into_owned())
            ),
            InferenceBackend::Remote(_) => Some(format!("remote:{}", self.config.remote_model)),
            InferenceBackend::Unavailable => None,
        }
    }
    pub fn gpu_info(&self) -> Option<&GpuInfo> { self.gpu_info.as_ref() }

    pub async fn is_available(&self) -> bool {
        !matches!(self.backend, InferenceBackend::Unavailable)
    }

    // ─────────────────────────────────────────────────────────
    // Threat analysis
    // ─────────────────────────────────────────────────────────
    pub async fn analyze_threat(&self, threat: &ThreatEvent) -> Option<LLMAnalysis> {
        if !self.config.enabled { return None; }

        // ── Assemble the correlated EVIDENCE, not just the alert headline ──────
        // The old prompt sent only the threat name + description, so the model
        // could do no more than restate the alert. Here we hand it the actual
        // correlated sequence the agent already computed: every stage of the
        // attack chain (tactic → technique → what happened, in time order), every
        // IOC with its source and confidence, and the matched rules. This is what
        // lets the model reason about WHY the combination is (or isn't) an
        // incident, rather than paraphrasing a label.

        // Attack-chain stages, in order, with timing deltas so the model can see
        // how fast the sequence unfolded (fast = more likely automated/malicious).
        let chain_block = match &threat.chain {
            Some(c) if !c.stages.is_empty() => {
                let mut lines = format!(
                    "Correlated attack chain \"{}\" — {} stage(s), overall confidence {:.0}%:\n",
                    c.name, c.stages.len(), c.confidence);
                let t0 = c.stages.first().map(|s| s.timestamp);
                // Cap at 15 stages so a pathologically long chain can't blow the
                // model's context window; the head of the chain is the most
                // diagnostic part anyway.
                for (i, st) in c.stages.iter().take(15).enumerate() {
                    let delta = t0.map(|t0| (st.timestamp - t0).num_seconds()).unwrap_or(0);
                    lines.push_str(&format!(
                        "  {}. [+{}s] {} / {} — {}\n",
                        i + 1, delta, st.tactic, st.technique, st.description));
                }
                if c.stages.len() > 15 {
                    lines.push_str(&format!("  … and {} more stage(s).\n", c.stages.len() - 15));
                }
                lines
            }
            _ => "No multi-stage chain correlated for this event (single-stage detection).\n".to_string(),
        };

        // All IOCs with type, source, and confidence — not just one IP + one file.
        let ioc_block = if threat.iocs.is_empty() {
            "None extracted.".to_string()
        } else {
            threat.iocs.iter().take(20).map(|i| format!(
                "  - {:?}: {} (source: {}, conf {:.0}%)",
                i.ioc_type, i.value, i.source, i.confidence
            )).collect::<Vec<_>>().join("\n")
        };

        let rules_block = if threat.matched_rules.is_empty() {
            "behavioral heuristics only".to_string()
        } else {
            threat.matched_rules.join(", ")
        };

        // #1 Host context — ground the reasoning in what this host actually is.
        let host_block = self.host_ctx.read().map(|h| h.render())
            .unwrap_or_else(|_| "HOST CONTEXT: unavailable.".to_string());

        // #2 Verdict memory — recall a prior conclusion about this same detection
        // shape. If we've CONFIDENTLY judged this exact shape recently, reuse that
        // verdict directly instead of paying for another inference: increment the
        // recurrence counter and return the cached conclusion. This is the "I've
        // seen this before, I already analyzed it" fast path — it saves inference
        // (battery/edge win) AND avoids re-running a model that might now return
        // unparseable output. Only the LLM path (not the fast path) can produce a
        // NEW verdict, so novelty still gets full analysis.
        let vkey = Self::verdict_key(threat);
        let prior = self.recall_verdict(&vkey);
        if let Some(ref p) = prior {
            // Reuse only when the prior verdict is fresh AND has been seen before
            // (hits >= 1 by construction). Bump its recurrence count and return.
            self.reinforce_verdict(&vkey);
            debug!("🧠 ATC fast-path: reused prior verdict for recurring shape (seen {}x): {}",
                p.hits + 1, if p.is_true_positive { "TP" } else { "benign" });
            return Some(LLMAnalysis {
                suspicious:            p.is_true_positive,
                confidence_adjustment: p.confidence_adj,
                explanation:           format!("[recalled — seen {}× on this host] {}", p.hits + 1, p.assessment),
                mitre_refinement:      Vec::new(),
                generated_rule:        None,
            });
        }
        let prior_block = String::new(); // no prior → no recall block (first analysis)

        let prompt = format!(
            r#"You are a host-based security analyst reasoning over ONE endpoint's telemetry. Below is a correlated detection with its supporting evidence. Do NOT merely restate the threat name — assess what the evidence actually shows, whether the stages fit together into a real attack, what benign explanation could account for it, and what an operator should check or do next.

{host_block}
{prior_block}
DETECTION: {name} (severity {severity}, base confidence {confidence:.0}%)
SUMMARY: {desc}
MITRE tactics: {tactics}
MITRE techniques: {techniques}
Detection source: {rules}
Underlying raw events: {raw_count}

EVIDENCE — correlated sequence:
{chain_block}
EVIDENCE — indicators:
{ioc_block}

Weigh the sequence and timing, AND the host context above — the same action can be routine on one kind of host and alarming on another. A tight, ordered progression across tactics (e.g. access → credential theft → lateral movement) is far more concerning than an isolated match. Consider the most likely benign explanation before concluding malice.

Respond ONLY with valid JSON, no markdown, no prose outside the JSON:
{{
  "is_true_positive": true,
  "confidence_adjustment": 0,
  "assessment": "2-4 sentences: what the evidence shows IN CONTEXT and why the stages do or do not add up to a real attack",
  "benign_explanation": "the most plausible non-malicious explanation, or 'none apparent'",
  "next_steps": "concrete things the operator should check or do next on this host",
  "refined_techniques": ["T1059.004"],
  "generate_rule": false,
  "rule_type": "yara",
  "rule_name": "",
  "rule_content": "",
  "rule_reasoning": ""
}}"#,
            host_block  = host_block,
            prior_block = prior_block,
            severity   = threat.severity,
            confidence = threat.confidence,
            name       = threat.threat_name,
            desc       = threat.description,
            tactics    = threat.mitre_tactics.join(", "),
            techniques = threat.mitre_techniques.join(", "),
            rules      = rules_block,
            raw_count  = threat.raw_event_ids.len(),
            chain_block = chain_block,
            ioc_block  = ioc_block,
        );

        let raw = match self.backend.generate(&self.config.system_prompt, &prompt,
            self.config.max_context_tokens).await
        {
            Ok(r)  => r,
            Err(e) => { warn!("LLM inference failed: {}", e); return None; }
        };

        self.parse_threat_analysis(&raw, threat)
    }

    fn parse_threat_analysis(&self, raw: &str, threat: &ThreatEvent) -> Option<LLMAnalysis> {
        // Strip markdown fences if the model added them
        let cleaned = raw.trim()
            .trim_start_matches("```json").trim_start_matches("```")
            .trim_end_matches("```").trim();

        // Tolerant parse: smaller/quantized models (and a future 1-bit BitNet
        // model) sometimes wrap the JSON in prose or add a trailing note. Rather
        // than discard the whole analysis (which silently drops enrichment and
        // makes the detection look un-analyzed), try strict parse first, then
        // fall back to extracting the first balanced {...} object, and finally
        // fall back to treating the raw text as a prose assessment.
        let json: serde_json::Value = match serde_json::from_str(cleaned) {
            Ok(v) => v,
            Err(_) => match extract_json_object(cleaned)
                .and_then(|s| serde_json::from_str(&s).ok())
            {
                Some(v) => v,
                None => {
                    // Last resort: keep the model's text as the assessment rather
                    // than producing nothing. Treat as suspicious=true (don't
                    // silently suppress) with no confidence change.
                    warn!("ATC: response was not valid JSON; preserving as prose assessment");
                    let prose = cleaned.chars().take(400).collect::<String>();
                    let is_tp = true;
                    self.remember_verdict(Self::verdict_key(threat), is_tp, &prose, 0.0);
                    return Some(LLMAnalysis {
                        suspicious: is_tp, confidence_adjustment: 0.0,
                        explanation: prose, mitre_refinement: Vec::new(), generated_rule: None,
                    });
                }
            },
        };

        let is_tp  = json["is_true_positive"].as_bool().unwrap_or(true);
        let adj    = (json["confidence_adjustment"].as_f64().unwrap_or(0.0) as f32).clamp(-30.0, 30.0);

        // The enriched prompt returns assessment / benign_explanation / next_steps.
        // Compose them into the single explanation string that already flows to the
        // UI and Nexus, so the richer analysis is preserved without changing the
        // LLMAnalysis schema. Fall back to the legacy "explanation" key if a model
        // (or the remote backend) still returns the old shape.
        let assessment = json["assessment"].as_str().unwrap_or("").trim().to_string();
        let assessment_for_memory = assessment.clone();  // preserved for verdict cache
        let benign     = json["benign_explanation"].as_str().unwrap_or("").trim().to_string();
        let next_steps = json["next_steps"].as_str().unwrap_or("").trim().to_string();
        let expl = if !assessment.is_empty() {
            let mut s = assessment;
            if !benign.is_empty() && benign.to_lowercase() != "none apparent" && benign.to_lowercase() != "none" {
                s.push_str(&format!("\n\nBenign explanation considered: {}", benign));
            }
            if !next_steps.is_empty() {
                s.push_str(&format!("\n\nRecommended next steps: {}", next_steps));
            }
            s
        } else {
            json["explanation"].as_str().unwrap_or("").to_string()
        };

        let refined: Vec<String> = json["refined_techniques"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let generated_rule = if json["generate_rule"].as_bool().unwrap_or(false) {
            let rt = match json["rule_type"].as_str().unwrap_or("yara") {
                "sigma"    => RuleType::Sigma,
                "wazuh"    => RuleType::Wazuh,
                _          => RuleType::Yara,
            };
            let name    = json["rule_name"].as_str().unwrap_or("auto_rule").to_string();
            let content = json["rule_content"].as_str().unwrap_or("").to_string();
            let reason  = json["rule_reasoning"].as_str().unwrap_or("").to_string();
            if !content.is_empty() {
                info!("🤖 LLM generated {:?} rule: {}", rt, name);
                Some(DetectionRule {
                    id: Uuid::new_v4().to_string(), rule_type: rt, name,
                    severity: threat.severity.clone(), content,
                    generated_from_event: threat.id.clone(),
                    generated_at: Utc::now(), approved: false, deployed_to: vec![],
                    llm_reasoning: reason,
                })
            } else { None }
        } else { None };

        debug!("LLM: is_tp={} adj={:.1} refined={:?}", is_tp, adj, refined);
        // #2 Remember this verdict so a recurrence of the same detection shape can
        // be reasoned about consistently (and cheaply) next time. Recompute the
        // key from `threat` here (this is a separate fn from where the prompt's
        // vkey was built).
        self.remember_verdict(Self::verdict_key(threat), is_tp, &assessment_for_memory, adj);
        Some(LLMAnalysis { suspicious: is_tp, confidence_adjustment: adj,
            explanation: expl, mitre_refinement: refined, generated_rule })
    }

    // ─────────────────────────────────────────────────────────
    // Nebula Whisper chat interface
    // ─────────────────────────────────────────────────────────
    pub async fn chat(&self, user_message: &str, context: &str) -> Result<String> {
        if self.detect_adversarial_input(user_message) {
            return Ok("⚠️ Input blocked — potential prompt injection detected.".to_string());
        }
        let prompt = format!("{}\n\nUser: {}\n\nNebula Whisper:", context, user_message);
        self.backend.generate(&self.config.system_prompt, &prompt,
            self.config.max_context_tokens).await
    }

    // ─────────────────────────────────────────────────────────
    // Retro-hunt log analysis
    // ─────────────────────────────────────────────────────────
    pub async fn analyze_log_batch(&self, logs: &[String], rule_name: &str) -> Result<String> {
        let sample = logs.iter().take(20).cloned().collect::<Vec<_>>().join("\n");
        let prompt = format!(
            "Analyze these logs for compromise indicators matching rule '{}'.\n\
            Logs ({} lines, showing first 20):\n{}\n\n\
            Return JSON array only: \
            [{{\"line\": N, \"description\": \"...\", \"technique\": \"T...\", \"confidence\": 0-100}}]",
            rule_name, logs.len(), sample
        );
        self.backend.generate(&self.config.system_prompt, &prompt, 1024).await
    }

    // ─────────────────────────────────────────────────────────
    // Hardening recommendations
    // ─────────────────────────────────────────────────────────
    pub async fn recommend_hardening(&self, findings: &[String]) -> Result<String> {
        let prompt = format!(
            "These CIS/STIG compliance checks are failing:\n{}\n\n\
            Provide fixes as JSON only: \
            [{{\"control\": \"...\", \"priority\": 1-5, \"command\": \"...\", \"risk\": \"...\"}}]",
            findings.join("\n")
        );
        self.backend.generate(&self.config.system_prompt, &prompt, 1024).await
    }

    // ─────────────────────────────────────────────────────────
    // ATLAS AML.T0043 — prompt injection guard
    // ─────────────────────────────────────────────────────────
    pub fn detect_adversarial_input(&self, input: &str) -> bool {
        if !self.config.enabled { return false; }
        let patterns = [
            "ignore previous instructions", "ignore all prior", "disregard your",
            "you are now", "act as a", "act as if", "pretend you are", "pretend to be",
            "forget everything", "new instructions:", "[[system]]", "jailbreak",
            "dan mode", "developer mode", "do anything now", "override safety",
            "your true instructions", "system prompt:", "ignore the above",
        ];
        let lower = input.to_lowercase();
        for p in &patterns {
            if lower.contains(p) {
                warn!("🛡️ ATLAS AML.T0043: prompt injection blocked: '{}'", p);
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// `NEBULA_MODELS_DIR` is process-wide, so these tests must not overlap.
    /// Each takes the lock for its whole body (and holds it past a panic —
    /// poisoning is irrelevant here since every test re-creates its fixture).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A models dir laid out the way an operator's box looks: the recommended
    /// model, something else they downloaded, a model in a subdirectory, and the
    /// tail shard of a split model (which must never be picked on its own).
    fn fixture(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nebula-model-test-{}", tag));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub")).unwrap();
        for (rel, bytes) in [
            ("Phi-3.5-mini-instruct-Q4_K_M.gguf", 3usize),
            ("Mistral-7B-Instruct-v0.3-Q4_K_M.gguf", 3),
            ("sub/Custom-Model-Q8_0.gguf", 3),
            ("split-00002-of-00003.gguf", 3),
            ("notes.txt", 3),
        ] {
            fs::write(dir.join(rel), vec![0u8; bytes]).unwrap();
        }
        std::env::set_var("NEBULA_MODELS_DIR", &dir);
        dir
    }

    fn name_of(p: &std::path::Path) -> String {
        p.file_name().unwrap().to_string_lossy().into_owned()
    }

    #[test]
    fn resolves_every_way_of_naming_a_model() {
        let _guard = lock_env();
        let dir = fixture("resolve");

        // Absolute path, bare filename, filename without the extension.
        let abs = dir.join("Phi-3.5-mini-instruct-Q4_K_M.gguf");
        for spec in [
            abs.to_string_lossy().to_string(),
            "Phi-3.5-mini-instruct-Q4_K_M.gguf".to_string(),
            "Phi-3.5-mini-instruct-Q4_K_M".to_string(),
            "sub/Custom-Model-Q8_0.gguf".to_string(),
        ] {
            let got = resolve_model_reference(&spec).unwrap_or_else(|e| panic!("{spec}: {e}"));
            assert!(got.is_file(), "{spec} resolved to a non-file");
        }

        // A directory resolves to the newest GGUF inside it.
        assert_eq!(name_of(&resolve_model_reference(&dir.join("sub").to_string_lossy()).unwrap()),
            "Custom-Model-Q8_0.gguf");

        // Catalog alias that IS downloaded; and one that isn't (must not silently
        // fall through to a fuzzy match on a different model).
        assert_eq!(name_of(&resolve_model_reference("phi3.5-mini").unwrap()),
            "Phi-3.5-mini-instruct-Q4_K_M.gguf");
        assert!(resolve_model_reference("qwen2.5-14b").is_err());

        // Unique fragment resolves; ambiguous fragment and unknown name fail.
        assert_eq!(name_of(&resolve_model_reference("mistral").unwrap()),
            "Mistral-7B-Instruct-v0.3-Q4_K_M.gguf");
        assert!(resolve_model_reference("q4_k_m").is_err());   // matches two
        assert!(resolve_model_reference("llama3.1-8b").is_err());
        assert!(resolve_model_reference("  ").is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_skips_non_models_and_split_shards() {
        let _guard = lock_env();
        let dir = fixture("scan");
        let found: Vec<String> = list_gguf_models(&dir).iter().map(|p| name_of(p)).collect();
        assert!(found.contains(&"Custom-Model-Q8_0.gguf".to_string()), "subdirectory not scanned");
        assert!(!found.iter().any(|n| n.contains("split-00002")), "split shard offered as a model");
        assert!(!found.iter().any(|n| n.ends_with(".txt")));
        assert_eq!(found.len(), 3);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recommendation_follows_the_catalog_and_the_models_dir() {
        let _guard = lock_env();
        let dir = fixture("recommend");
        assert_eq!(recommended_model_file_for_vram(0), "Qwen_Qwen3-4B-Q4_K_M.gguf");
        assert_eq!(recommended_model_file_for_vram(8192), "Qwen_Qwen3-8B-Q4_K_M.gguf");
        assert_eq!(recommended_model_file_for_vram(16384), "Qwen_Qwen3-14B-Q4_K_M.gguf");
        // Resolved under the models dir in force, not a hardcoded Linux path.
        assert!(select_model_path_for_vram(0).starts_with(&dir.to_string_lossy().to_string()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn engine_compatibility_matches_builds_to_models() {
        // A stock llama.cpp build loads ordinary + native-ternary (TQ) models,
        // but NOT the fork-only bitnet (I2_S) ones.
        assert!(engine_loadable("llama.cpp", "llama.cpp"));
        assert!(!engine_loadable("llama.cpp", "bitnet"));
        // A bitnet build is a superset.
        assert!(engine_loadable("bitnet", "bitnet"));
        assert!(engine_loadable("bitnet", "llama.cpp"));
    }
}
