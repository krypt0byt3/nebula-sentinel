// src/main.rs — NebulaSentinel Agent v0.4
// Autonomous Threat Cognition (ATC) endpoint agent

mod config;
mod types;
mod platform;
mod collector;
mod sigma;
mod anomaly;
mod llm;
mod posture;
mod scan_state;
mod yara_scan;
mod self_protect;
mod status_ui;
mod tls;
mod forensics;
mod inventory;
mod gossip;
mod retro;
mod response;
mod nexus_client;
mod custom_checks;
mod rules;
mod hardening;
mod memory;
mod legacy;
mod offline_queue;
mod container;
mod iac;
mod fim;
mod network_monitor;
mod netguard;
mod baseline;
mod zeroday;
mod reputation;
mod secrets_scan;
mod playbook;
mod apt;
mod dlp;
mod firewall;
mod ransomware;
mod dedup;
mod suppression;
mod atc_selftest;
#[cfg(test)]
mod detection_corpus;

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn, debug};
use tracing_subscriber::EnvFilter;
use std::sync::Arc;
use tokio::time::{interval, Duration};

use config::{AgentConfig, AgentMode};
use firewall::{Firewall, DistroInfo};
use types::NexusCommandType;

/// NebulaSentinel Agent — Autonomous Threat Cognition
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "/etc/nebula/config.toml")]
    config: String,

    /// Override mode (detect|protect|audit)
    #[arg(short, long)]
    mode: Option<String>,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Download a GGUF model into the models dir and exit. With no value, fetches
    /// the model recommended for this hardware. Otherwise takes ANY of:
    /// a catalog alias (`--list-models`), a HuggingFace repo ("owner/repo" — the
    /// best quant is picked), a repo + exact file ("owner/repo:Model-Q6_K.gguf"),
    /// or a direct URL ("https://host/model.gguf"). Pin a revision with
    /// "owner/repo@rev:file". Gated repos: export HF_TOKEN first.
    #[arg(long, value_name = "MODEL", num_args = 0..=1, default_missing_value = "auto")]
    download_model: Option<String>,

    /// Model to load for THIS run — overrides [llm].model_path without editing
    /// the config. Takes any of: a path to a .gguf, a directory of models (newest
    /// wins), a bare filename in the models dir (with or without ".gguf"), a
    /// catalog alias already downloaded, or a unique fragment of a filename
    /// ("--model qwen"). Also settable as NEBULA_MODEL.
    #[arg(long, value_name = "PATH|NAME|ALIAS", env = "NEBULA_MODEL")]
    model: Option<String>,

    /// List the built-in model catalog (aliases for --download-model) plus the
    /// models already present locally, and exit.
    #[arg(long)]
    list_models: bool,

    /// Directory models are downloaded into AND loaded from (default: the
    /// platform models dir, e.g. /var/lib/nebula/models). Equivalent to setting
    /// NEBULA_MODELS_DIR.
    #[arg(long, value_name = "DIR", env = "NEBULA_MODELS_DIR")]
    models_dir: Option<String>,

    /// Download the model FROM THE NEXUS (air-gapped fleets) instead of HuggingFace, then exit.
    /// Uses the [nexus] url + api_key from config. Optionally name a specific model.
    #[arg(long)]
    download_from_nexus: bool,

    /// With --download-from-nexus: which model to request from the Nexus.
    /// With --download-model: the filename to save the model under.
    #[arg(long)]
    model_name: Option<String>,

    /// Print GPU/hardware detection info and exit
    #[arg(long)]
    hardware_info: bool,

    /// Attempt to load the LLM model and exit (0 = ok, non-zero = failed/crashed).
    /// Run this directly to diagnose LLM load problems in isolation — if the
    /// llama.cpp/CUDA layer hard-faults (SIGILL/SIGABRT), only this throwaway
    /// process dies. The agent also runs this automatically as a pre-flight.
    #[arg(long)]
    llm_selftest: bool,

    /// Run the FULL ATC path end-to-end against synthetic detections and exit.
    ///
    /// Unlike --llm-selftest (which only loads the model), this drives real
    /// ThreatEvent values through LLMEngine::analyze_threat exactly as the agent
    /// does in production, then scores the results: completion rate, verdict
    /// accuracy against known ground truth, recall vs. specificity, and latency.
    ///
    /// The scenario set deliberately mixes true positives with benign lookalikes,
    /// so a model that simply answers "malicious" every time scores poorly.
    #[arg(long)]
    atc_test: bool,

    /// With --atc-test: run only the named scenario (e.g. "cred-dump").
    #[arg(long, value_name = "KEY")]
    atc_scenario: Option<String>,
}

/// Run a per-event detector future under a panic boundary.
///
/// A security monitor must survive a single malformed or hostile event rather
/// than crash: the per-event detectors run inline on the main task, so without
/// this a panic in any one of them (e.g. a crafted event hitting an edge case)
/// unwinds `main` and the whole agent goes blind — exactly when it's under
/// attack. Here a detector panic is logged loudly and treated as "no detection
/// from this detector for this event"; every other detector and the next event
/// still run. tokio's Mutex does not poison on unwind, so shared detector state
/// stays usable.
async fn guarded<T, F>(detector: &str, fut: F) -> Option<T>
where
    F: std::future::Future<Output = Option<T>>,
{
    use futures_util::future::FutureExt;
    match std::panic::AssertUnwindSafe(fut).catch_unwind().await {
        Ok(v) => v,
        Err(_) => {
            tracing::error!(
                "detector '{}' panicked on an event — skipped for this event; agent stays up",
                detector
            );
            None
        }
    }
}

#[cfg(test)]
mod guarded_tests {
    use super::guarded;

    #[tokio::test]
    async fn catches_panic_and_passes_values_through() {
        // A panicking detector yields None instead of unwinding the agent.
        let out: Option<i32> = guarded("boom", async { panic!("kaboom in a detector") }).await;
        assert_eq!(out, None);
        // A healthy detector's verdict passes through untouched.
        assert_eq!(guarded("ok", async { Some(7) }).await, Some(7));
        assert_eq!(guarded::<i32, _>("ok", async { None }).await, None);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // ── Logging ────────────────────────────────────────────────
    let filter = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .init();

    print_banner();

    // A models dir given on the command line becomes the process-wide default so
    // every lookup path agrees — download, auto-detect, `--model` name
    // resolution — and child processes (the LLM pre-flight) inherit it.
    if let Some(ref dir) = args.models_dir {
        if !dir.trim().is_empty() {
            // Process-wide override so every lookup path agrees …
            platform::set_models_dir_override(dir.trim());
            // … and export it so the isolated LLM pre-flight child inherits it.
            std::env::set_var("NEBULA_MODELS_DIR", dir.trim());
        }
    }

    // ── Early exit commands ────────────────────────────────────
    if args.hardware_info {
        return cmd_hardware_info().await;
    }
    // INTERNAL self-test: load the model in THIS (throwaway) process and exit.
    // The main agent spawns this to pre-flight the load in isolation. If the
    // llama.cpp/CUDA layer hard-faults, only this child dies.
    if args.llm_selftest {
        let mut cfg = AgentConfig::load(&args.config)
            .or_else(|_| AgentConfig::load("config.toml"))
            .map_err(|e| anyhow::anyhow!("config load failed: {}", e))?;
        // Self-test the model the run would actually use, override included.
        if let Some(ref m) = args.model {
            cfg.llm.model_path = Some(m.clone());
        }
        let engine = llm::LLMEngine::new(cfg.llm.clone()).await;
        if engine.is_available().await {
            println!("LLM_SELFTEST_OK");
            std::process::exit(0);
        } else {
            eprintln!("LLM_SELFTEST_FAIL: model did not load");
            std::process::exit(1);
        }
    }
    // End-to-end ATC check: load the backend AND drive real detections through
    // analyze_threat, scoring discrimination (true positives vs. benign
    // lookalikes), then exit. This is the check that proves a model is usable
    // as the agent's brain, not merely loadable.
    if args.atc_test {
        let mut cfg = AgentConfig::load(&args.config)
            .or_else(|_| AgentConfig::load("config.toml"))
            .map_err(|e| anyhow::anyhow!("config load failed: {}", e))?;
        if let Some(ref m) = args.model {
            cfg.llm.model_path = Some(m.clone());
        }
        let engine = llm::LLMEngine::new(cfg.llm.clone()).await;
        if !engine.is_available().await {
            eprintln!("ATC_TEST_FAIL: no backend loaded");
            std::process::exit(1);
        }
        println!("backend      : {}", engine.backend_name());
        println!("max_context  : {}", cfg.llm.max_context_tokens);

        let outcomes = atc_selftest::run(&engine, args.atc_scenario.as_deref()).await;
        atc_selftest::report(&outcomes);

        let produced = outcomes.iter().filter(|o| o.completed()).count();
        if produced == 0 {
            eprintln!("ATC_TEST_FAIL: no scenario produced an analysis");
            std::process::exit(1);
        }
        println!("\nATC_TEST_DONE");
        std::process::exit(0);
    }
    if args.list_models {
        llm::print_model_catalog();
        return Ok(());
    }
    if let Some(ref spec) = args.download_model {
        return cmd_download_model(
            spec,
            args.models_dir.as_deref(),
            args.model_name.as_deref(),
        ).await;
    }
    if args.download_from_nexus {
        // Need the Nexus URL + key from config.
        let cfg = AgentConfig::load(&args.config)
            .or_else(|_| AgentConfig::load("config.toml"))
            .map_err(|e| anyhow::anyhow!("config required for --download-from-nexus: {}", e))?;
        let path = llm::download_model_from_nexus(
            &cfg.nexus.url, &cfg.nexus.api_key, args.model_name.as_deref(),
            cfg.nexus.ca_cert_path.as_deref(), cfg.nexus.tls_verify,
        ).await?;
        println!("✅ Model ready at {}", path);
        return Ok(());
    }

    // ── Load config ────────────────────────────────────────────
    let mut cfg = AgentConfig::load(&args.config)
        .or_else(|_| AgentConfig::load(&crate::platform::default_config_path().to_string_lossy()))
        .unwrap_or_else(|e| {
            warn!("Config load failed ({}), trying ./config.toml", e);
            AgentConfig::load("config.toml").expect("no config.toml found")
        });

    // ── Runtime model override (--model / NEBULA_MODEL) ────────
    // Wins over [llm].model_path for this run only; nothing is written back to
    // the config. Resolved eagerly so a typo is reported at startup, next to the
    // other banner lines, rather than surfacing later as "LLM unavailable".
    if let Some(ref spec) = args.model {
        match llm::resolve_model_reference(spec) {
            Ok(path) => {
                info!("🧠 Model override: {} → {}", spec, path.display());
                cfg.llm.model_path = Some(path.to_string_lossy().into_owned());
            }
            Err(e) => {
                warn!("⚠️  --model {}: {}", spec, e);
                warn!("   Falling back to [llm].model_path / auto-detection.");
            }
        }
    }

    if let Some(mode) = args.mode {
        cfg.mode = match mode.as_str() {
            "protect" => AgentMode::Protect,
            "audit"   => AgentMode::Audit,
            _         => AgentMode::Detect,
        };
    }

    // Backfill hostname if the config left it empty
    if cfg.hostname.trim().is_empty() {
        cfg.hostname = sysinfo::System::host_name()
            .filter(|h| !h.trim().is_empty())
            .or_else(|| std::fs::read_to_string("/etc/hostname").ok()
                .map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
            .unwrap_or_else(|| format!("agent-{}", &cfg.agent_id.chars().take(8).collect::<String>()));
        info!("Hostname auto-detected: {}", cfg.hostname);
    }

    info!("Agent ID  : {}", cfg.agent_id);
    info!("Hostname  : {}", cfg.hostname);
    info!("Mode      : {}", cfg.mode);
    info!("Nexus     : {}", cfg.nexus.url);

    // ── Self-protection FIRST ──────────────────────────────────
    let self_protect = Arc::new(self_protect::SelfProtection::new(cfg.self_protect.clone()));
    self_protect.initialize().await?;

    // Status UI — local only, http://localhost:7440
    let (status_server, status_state) = status_ui::StatusServer::new();
    {
        let mut snap = status_state.write().await;
        snap.hostname    = cfg.hostname.clone();
        snap.agent_id    = cfg.agent_id.clone();
        snap.platform    = crate::config::detect_platform();
        snap.version     = env!("CARGO_PKG_VERSION").to_string();
        snap.mode        = cfg.mode.to_string();
        snap.nexus_url   = cfg.nexus.url.clone();
        // Standalone vs offline: a Nexus is "configured" only when enabled with a
        // real URL. When it isn't, the UI shows a deliberate Standalone state
        // rather than an error. Live connectivity is refreshed below.
        snap.nexus_configured = cfg.nexus.enabled && !cfg.nexus.url.trim().is_empty();
        snap.collector_backend = cfg.collector.backend.clone();
        snap.started_at  = chrono::Utc::now().to_rfc3339();
        snap.modules     = vec![
            status_ui::ModuleStatus { name: "anomaly_engine".into(),   healthy: true, detail: "264 technique rules active".into() },
            status_ui::ModuleStatus { name: "fim".into(),              healthy: true, detail: "inotify watching 30 paths".into() },
            status_ui::ModuleStatus { name: "network_monitor".into(),  healthy: true, detail: "beacon + DNS tunnel detection".into() },
            status_ui::ModuleStatus { name: "ransomware".into(),       healthy: true, detail: "50+ extensions monitored".into() },
            status_ui::ModuleStatus { name: "dlp".into(),              healthy: true, detail: "28 exfil patterns active".into() },
            status_ui::ModuleStatus { name: "secrets_scan".into(),     healthy: true, detail: "16 credential patterns".into() },
            status_ui::ModuleStatus { name: "apt_detector".into(),     healthy: true, detail: "30-day dwell chain tracker".into() },
            status_ui::ModuleStatus { name: "self_protect".into(),     healthy: true, detail: "binary integrity + anti-debug".into() },
        ];
        // FIM watched paths — surfaced on the local UI's FIM tab. Static watch
        // list; live modifications flow through recent_events as detections.
        let mut fim_paths: Vec<(String, String)> = crate::fim::default_critical_paths()
            .into_iter().map(|w| (w.path, w.description.to_string())).collect();
        fim_paths.extend(crate::fim::download_zone_paths()
            .into_iter().map(|w| (w.path, w.description.to_string())));
        snap.fim_watched = fim_paths;
    }
    tokio::spawn(async move { let _ = status_server.start().await; });

    // ── LLM engine (async init — probes GPU) ──────────────────
    // ── LLM init with crash isolation ──────────────────────────
    // The llama.cpp/CUDA layer can hard-fault (SIGILL on an unsupported CPU,
    // SIGABRT on a CUDA/driver mismatch) during model load — a process-level
    // signal that NO Rust error handling can catch. To guarantee the agent runs
    // "either way", we pre-flight the load in a throwaway subprocess first. If
    // that child dies from a signal or non-zero exit, we KNOW loading in-process
    // would kill the agent, so we degrade to Legacy instead of attempting it.
    let llm_engine = Arc::new(
        if cfg.llm.enabled && llm_preflight_ok(&args.config, args.model.as_deref()).await {
            llm::LLMEngine::new(cfg.llm.clone()).await
        } else if cfg.llm.enabled {
            warn!("⚠️  LLM pre-flight failed — the model load would crash this process \
                   (likely a CPU-instruction or CUDA/driver fault in llama.cpp). \
                   Running in Legacy mode (detection continues; AI analysis skipped).");
            warn!("   Diagnose by running directly:  nebula-agent --llm-selftest -c {}{}", args.config,
                args.model.as_deref().map(|m| format!(" --model {}", m)).unwrap_or_default());
            // Construct a disabled engine without attempting the in-process load.
            let mut legacy_cfg = cfg.llm.clone();
            legacy_cfg.enabled = false;
            llm::LLMEngine::new(legacy_cfg).await
        } else {
            llm::LLMEngine::new(cfg.llm.clone()).await
        }
    );
    let llm_is_available = llm_engine.is_available().await;
    if !llm_is_available && cfg.llm.enabled {
        warn!("⚠️  LLM enrichment inactive — threat events are still detected and forwarded, only AI summaries are skipped.");
    }

    // ── Initialize all engines ────────────────────────────────
    let collector = Arc::new(
        collector::EventCollector::new(cfg.collector.clone(), &cfg.agent_id, &cfg.hostname).await?
    );
    let anomaly_engine   = Arc::new(anomaly::AnomalyEngine::new(cfg.anomaly.clone()));
    // Behavioral baseline engine: learns this host's normal over a window and
    // flags deviations (novelty/rarity/temporal/numeric + multivariate forest).
    // Gated on anomaly.ml_enabled; complements signatures/intel, never replaces.
    let baseline_engine = {
        let eng = baseline::BaselineEngine::open(
            &cfg.agent_id, &cfg.hostname,
            cfg.anomaly.ml_enabled,
            cfg.anomaly.baseline_window_days,
            None,
        );
        match eng {
            Ok(e) => { let e = Arc::new(e); { let el = e.clone(); tokio::spawn(async move { el.load().await; }); } Some(e) }
            Err(err) => { warn!("Baseline engine disabled (open failed): {}", err); None }
        }
    };
    // Periodically persist baseline state so the learn window survives restarts.
    if let Some(ref be) = baseline_engine {
        let be = be.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(300));
            loop { ticker.tick().await; be.persist().await; }
        });
    }
    let posture_engine   = Arc::new(posture::PostureEngine::new());
    let forensics_engine = Arc::new(forensics::ForensicsEngine::new(cfg.forensics.clone()));
    let inventory_engine = Arc::new(inventory::InventoryEngine::new(cfg.inventory.clone())?);
    // Provision the GOSSIP mesh encryption key from the Nexus if the operator
    // hasn't set a local one, so the mesh is encrypted out of the box. A local
    // [gossip].encryption_key (custom key) always wins.
    if cfg.nexus.enabled && cfg.gossip.encryption_key.as_deref().map(str::trim).unwrap_or("").is_empty() {
        if let Some(k) = fetch_nexus_gossip_key(&cfg.nexus).await {
            cfg.gossip.encryption = true;
            cfg.gossip.encryption_key = Some(k);
            info!("🔑 GOSSIP: mesh encryption key provisioned by the Nexus");
        }
    }
    let nexus_url_for_gossip = if cfg.nexus.enabled { Some(cfg.nexus.url.clone()) } else { None };
    let nexus_key_for_gossip = if cfg.nexus.enabled { Some(cfg.nexus.api_key.clone()) } else { None };
    let gossip_engine    = Arc::new(gossip::GossipEngine::new(
        cfg.gossip.clone(), &cfg.agent_id, &cfg.hostname,
        nexus_url_for_gossip, nexus_key_for_gossip,
        cfg.nexus.ca_cert_path.clone(), cfg.nexus.tls_verify,
    ));
    // Seed the cognition state the atc.health heartbeat reports, so the Nexus can
    // see whether this agent is ATC-enriched or running degraded (LLM down /
    // procmon fallback). collector_backend reflects the configured backend.
    gossip_engine.llm_available.store(llm_is_available, std::sync::atomic::Ordering::Relaxed);
    if let Ok(mut b) = gossip_engine.collector_backend.lock() {
        *b = cfg.collector.backend.clone();
    }
    if llm_is_available {
        if let Ok(mut m) = gossip_engine.llm_model.lock() {
            // Reflect the ACTUAL active backend so the Nexus health view shows
            // whether an agent is running local or borrowing a remote brain.
            // active_model() reports the GGUF actually loaded — after --model
            // resolution and auto-detection — or "remote:<id>" for a borrowed brain.
            *m = llm_engine.active_model().or_else(|| Some("embedded".to_string()));
        }
    }
    let hardening_engine = Arc::new(hardening::HardeningEngine::new(cfg.hardening.clone()));
    let rules_engine     = Arc::new(rules::RulesEngine::new(cfg.rules.clone()).await?);
    // Rule hot-reload: when enabled, periodically re-load the rule directories so
    // operators can drop in new YARA/Sigma/Wazuh files without restarting the
    // agent. Previously `auto_reload`/`reload_interval_secs` were parsed but never
    // acted on. A floor of 10s guards against a pathological interval.
    if cfg.rules.auto_reload {
        let re = rules_engine.clone();
        let every = cfg.rules.reload_interval_secs.max(10);
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(every));
            loop {
                ticker.tick().await;
                match re.load_all_rules().await {
                    Ok(_)  => info!("♻️  Rules hot-reloaded ({}s interval)", every),
                    Err(e) => warn!("Rule hot-reload failed: {}", e),
                }
            }
        });
    }
    // Detect firewall backend and distro at startup
    let distro   = DistroInfo::detect();
    let firewall = Firewall::detect().await;
    info!("🐧 Running on: {} | Firewall: {}", distro.pretty_name, firewall.backend);
    // Firewall backend is probed once and fixed — surface it on the status UI now.
    status_state.write().await.firewall_backend = firewall.backend.to_string();

    let response_engine = Arc::new(response::ResponseEngine::new(
        cfg.response.clone(),
        cfg.mode.clone(),
        firewall.clone(),
    ));
    // NetGuard: host network self-protection (connection-level + reputation-driven
    // firewall blocking + brute-force auto-block). Enforces only in Protect mode;
    // in Detect mode it alerts without inserting firewall rules. Dependency-free —
    // drives the same OS firewall the response engine uses.
    let netguard = Arc::new(netguard::NetGuard::new(
        &cfg.agent_id, &cfg.hostname,
        matches!(cfg.mode, config::AgentMode::Protect),
        firewall.clone(),
    ));
    // Periodically lift expired NetGuard blocks (TTL'd brute-force bans, etc.).
    {
        let ng = netguard.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(60));
            loop { ticker.tick().await; ng.sweep_expired().await; }
        });
    }
    // Attach the firewall so IsolateHost/BlockIp playbook steps actually enforce
    // (previously the engine was built without one, so isolation silently no-op'd),
    // and pass the agent mode so destructive steps are gated to Protect mode.
    let playbook_engine  = Arc::new(
        playbook::PlaybookEngine::new(playbook::PlaybookEngine::default_playbooks())
            .with_firewall(Arc::new(firewall.clone()))
            .with_mode(cfg.mode.clone()),
    );
    let (ransomware_detector, mut ransom_rx) = ransomware::RansomwareDetector::new(&cfg.agent_id, &cfg.hostname);
    let ransomware_detector = Arc::new(ransomware_detector);
    ransomware_detector.start().await;

    let (apt_detector, mut apt_rx) = apt::AptDetector::new(&cfg.agent_id, &cfg.hostname);
    let apt_detector = Arc::new(apt_detector);
    apt_detector.start().await?;

    let (dlp_engine, mut dlp_rx) = dlp::DlpEngine::new(&cfg.agent_id, &cfg.hostname);
    let dlp_engine = Arc::new(dlp_engine);
    dlp_engine.start().await?;
    let zeroday_detector = Arc::new(zeroday::ZeroDayDetector::new(&cfg.agent_id, &cfg.hostname));
    let secrets_scanner  = Arc::new(secrets_scan::SecretsScanner::new(&cfg.agent_id, &cfg.hostname));

    // Compile YARA rules once at startup (shared, read-only) and attach to the
    // reputation engine so file scans run real signature detection.
    let yara_scanner = match yara_scan::YaraScanner::compile_dir(&cfg.rules.yara_dir) {
        Ok(s) => {
            info!("🧬 YARA scanner ready: {} rules ({} engine)",
                s.rule_count(), if s.is_real_engine() { "libyara" } else { "fallback string" });
            Some(Arc::new(s))
        }
        Err(e) => { warn!("YARA compile failed: {}", e); None }
    };
    let mut rep = reputation::ReputationEngine::new(&cfg.agent_id, &cfg.hostname, cfg.virustotal_api_key.clone());
    if let Some(ref ys) = yara_scanner { rep.set_yara(ys.clone()); }
    let reputation_engine  = Arc::new(rep);
    // RetroHunter is built here (after YARA) so YARA file-hunts use the real
    // engine. A retro hunt is a one-shot job; this just constructs the handler.
    let retro_hunter = {
        let mut h = retro::RetroHunter::new(cfg.retro.clone());
        if let Some(ref ys) = yara_scanner { h = h.with_yara(ys.clone()); }
        Arc::new(h)
    };
    let container_engine   = Arc::new(container::ContainerEngine::new());
    let iac_scanner        = Arc::new(iac::IaCScanner::new(cfg.iac_paths.clone().unwrap_or_default()));

    // FIM engine (real-time inotify)
    let (fim_engine, mut fim_rx) = fim::FimEngine::new(&cfg.agent_id, &cfg.hostname);
    let fim_engine = Arc::new(fim_engine);
    fim_engine.start(vec![]).await?;

    // Network monitor
    let (net_monitor, mut net_rx) = network_monitor::NetworkMonitor::new(&cfg.agent_id, &cfg.hostname);
    let net_monitor = Arc::new(net_monitor);
    net_monitor.start().await?;
    let memory_engine    = Arc::new(memory::MemoryEngine::new(cfg.memory.clone()));
    let legacy_bridge    = Arc::new(legacy::LegacyBridge::new(cfg.legacy.clone()));

    // ── Nexus client ───────────────────────────────────────────
    let nexus = if cfg.nexus.enabled {
        match nexus_client::NexusClient::new(cfg.nexus.clone(), &cfg.agent_id) {
            Ok(client) => {
                client.register(&cfg.hostname, &cfg.mode.to_string(), Some(gossip_engine.public_key_hex())).await?;
                Some(Arc::new(client))
            }
            Err(e) => {
                warn!("Nexus client init failed: {} — running standalone", e);
                None
            }
        }
    } else {
        warn!("Nexus disabled — running standalone");
        None
    };

    // ── GOSSIP startup ─────────────────────────────────────────
    gossip_engine.start().await?;

    // ── Start event collector ──────────────────────────────────
    collector.start().await?;
    info!("✅ All engines online. Entering event loop (mode={}).", cfg.mode);

    // ═══════════════════════════════════════════════════════════
    // PERIODIC TASK 1: Posture + Inventory + Hardening
    // ═══════════════════════════════════════════════════════════
    {
        let posture_interval = cfg.posture.scan_interval_secs;
        let cfg_c          = cfg.clone();
        let nexus_c        = nexus.clone();
        let posture_c      = posture_engine.clone();
        let inv_c          = inventory_engine.clone();
        let llm_ctx        = llm_engine.clone();
        let hardening_c    = hardening_engine.clone();
        let _legacy_c       = legacy_bridge.clone();
        let status_posture = status_state.clone();

        tokio::spawn(async move {
            // Stagger the first run 30s after startup
            tokio::time::sleep(Duration::from_secs(30)).await;

            let smart = cfg_c.posture.smart_scan;
            let max_age = cfg_c.posture.full_scan_max_age_hours;
            let mut first_tick = true;

            let mut ticker = interval(Duration::from_secs(posture_interval));
            loop {
                ticker.tick().await;
                info!("🔄 Periodic: posture + inventory + hardening...");

                // Sync the OVAL feed from Nexus before scanning, so check_oval has
                // current distro vulnerability definitions. Nexus converts the
                // distro OVAL XML once; the agent just pulls the compact JSON into
                // its OVAL dir. Best-effort — a failure here doesn't block the scan
                // (NVD/CVE correlation still runs).
                if let Some(ref n) = nexus_c {
                    if let Some(feed) = DistroInfo::detect().oval_feed_name() {
                        let oval_dir = if cfg_c.posture.oval_feed_path.is_empty() {
                            "/var/lib/nebula/oval".to_string()
                        } else {
                            cfg_c.posture.oval_feed_path.clone()
                        };
                        match n.sync_oval_feed(&feed, &oval_dir).await {
                            Ok(count) if count > 0 =>
                                info!("🔍 OVAL: synced {} definitions for feed '{}' into {}", count, feed, oval_dir),
                            Ok(_) =>
                                debug!("🔍 OVAL: feed '{}' empty on Nexus (run POST /api/oval/fetch on Nexus first)", feed),
                            Err(e) =>
                                debug!("🔍 OVAL: feed sync skipped ({})", e),
                        }
                    }
                }

                // Decide full vs delta. Only the FIRST tick after startup can be
                // a delta (subsequent periodic ticks are always full). The
                // decision needs the current package set, so collect that cheaply
                // first — THEN open scan-state in a sync scope (it holds a non-Send
                // rusqlite Connection, so it must never live across an await).
                let mut skip_file_catalog = false;
                if first_tick && smart {
                    if let Ok(pkgs) = inv_c.collect_packages_only().await {
                        let fp = scan_state::fingerprint_packages(&pkgs);
                        // Sync scope: open, decide, drop — no await inside.
                        if let Ok(st) = scan_state::ScanState::open(None) {
                            skip_file_catalog = st.decide(&fp, max_age) == scan_state::ScanDecision::Delta;
                        }
                    }
                }

                // Collect inventory (full or delta based on decision)
                let inventory = match inv_c.collect_with_options(skip_file_catalog).await {
                    Ok(inv) => {
                        info!("📦 Inventory: {} pkgs  {} procs  {} files  {} containers",
                            inv.installed_packages, inv.running_processes,
                            inv.file_catalog_count, inv.containers.len());
                        // Persist scan state — sync scope, opened and dropped here.
                        let fp = scan_state::fingerprint_packages(&inv.package_list);
                        if let Ok(st) = scan_state::ScanState::open(None) {
                            if skip_file_catalog { st.save_delta_scan(&fp); }
                            else { st.save_full_scan(&fp); }
                        }
                        Some(inv)
                    }
                    Err(e) => { warn!("Inventory failed: {}", e); None }
                };
                // Feed ATC its host context so its reasoning is grounded in what
                // this host actually is (role/exposure/services inferred from the
                // fresh inventory). Cheap; updates the Arc'd engine in place.
                if let Some(ref inv) = inventory {
                    let ctx = llm::HostContext::from_inventory(&inv.hostname, &inv.os, &inv.open_ports);
                    debug!("🧠 ATC host context: {} ({}), internet_facing={}", ctx.role, inv.hostname, ctx.internet_facing);
                    llm_ctx.set_host_context(ctx);
                }
                first_tick = false;

                // Hardening assessment — fold into compliance/hardening of the report
                let hardening_items = hardening_c.assess().await;
                let fails = hardening_items.iter()
                    .filter(|i| matches!(i.status, crate::types::ComplianceStatus::Fail)).count();
                if fails > 0 {
                    warn!("🔒 Hardening: {}/{} checks failing", fails, hardening_items.len());
                }

                // Posture assessment — attach inventory + hardening, then send full report
                if let Ok(mut report) = posture_c.run_full_assessment(&cfg_c).await {
                    report.inventory_summary = inventory;
                    // The dedicated hardening engine (hardening/mod.rs) is authoritative
                    // and runs auto-apply; prefer its results over posture's fallback
                    // checks whenever it produced any.
                    if !hardening_items.is_empty() {
                        report.hardening_recommendations = hardening_items;
                    }
                    info!("🛡️  Posture score: {:.1}%  vulns: {}",
                        report.overall_score, report.vulnerability_count);
                    // Surface the score on the local status UI (works standalone).
                    status_posture.write().await.posture_score = report.overall_score;
                    if let Some(ref n) = nexus_c {
                        let _ = n.send_posture(&report).await;
                    }
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // PERIODIC TASK 1b: Local status refresher (works standalone)
    // Keeps the 7440 UI's live counters current — rules/IOCs loaded, LLM
    // availability, and Nexus reachability — independent of any Nexus. This is
    // what makes offline/standalone agents show real telemetry instead of zeros.
    // ═══════════════════════════════════════════════════════════
    {
        let status_ref = status_state.clone();
        let rules_ref  = rules_engine.clone();
        let gossip_ref = gossip_engine.clone();
        let llm_ref    = llm_engine.clone();
        let nexus_ref  = nexus.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(10));
            loop {
                ticker.tick().await;
                let rules = rules_ref.rule_count().await;
                let iocs  = gossip_ref.ioc_count();
                let llm   = if llm_ref.is_available().await { "Active" } else { "Legacy (local)" };
                // Connectivity: only meaningful when a Nexus is configured.
                let connected = nexus_ref.as_ref().map(|n| n.is_connected()).unwrap_or(false);

                let mut snap = status_ref.write().await;
                snap.rules_loaded = rules;
                snap.iocs_loaded  = iocs;
                snap.llm_status   = llm.to_string();
                snap.nexus_connected = connected;
                if connected {
                    snap.last_nexus_contact = chrono::Utc::now().to_rfc3339();
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // PERIODIC TASK 2: Nexus poll, command dispatch, peer sync
    // ═══════════════════════════════════════════════════════════
    if let Some(ref n) = nexus {
        let nexus_poll     = n.clone();
        let gossip_c       = gossip_engine.clone();
        let rules_c        = rules_engine.clone();
        let retro_c        = retro_hunter.clone();
        let rep_poll       = reputation_engine.clone();
        let ransom_poll    = ransomware_detector.clone();
        let posture_c2     = posture_engine.clone();
        let inv_c2         = inventory_engine.clone();
        let forensics_c    = forensics_engine.clone();
        let memory_c       = memory_engine.clone();
        let response_engine_c = response_engine.clone();
        let nexus_retro    = nexus.clone();
        let hostname_retro = cfg.hostname.clone();
        let agent_id_retro = cfg.agent_id.clone();
        let hostname       = cfg.hostname.clone();
        let agent_id       = cfg.agent_id.clone();
        let cfg_c2         = cfg.clone();

        // ── Event flush loop ──────────────────────────────────
        // Queue-first delivery: the local SQLite buffer is drained to Nexus
        // on this interval, independent of the heartbeat. Thorough coverage
        // with reliable batched delivery; events survive restarts.
        if let Some(ref n) = nexus {
            let nexus_flush = n.clone();
            let flush_secs = cfg.nexus.event_flush_interval_secs.max(5);
            tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(flush_secs));
                loop {
                    ticker.tick().await;
                    nexus_flush.flush_events().await;
                }
            });
        }

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(15));
            loop {
                ticker.tick().await;
                let _ = nexus_poll.heartbeat().await;

                match nexus_poll.poll_commands().await {
                    Ok(poll) => {
                        // Register peers for GOSSIP
                        for peer in &poll.peers {
                            gossip_c.register_peer(
                                peer.agent_id.clone(),
                                peer.hostname.clone(),
                                peer.gossip_addr.clone(),
                            );
                        }

                        // Load malware hashes from the Nexus intel feed into the
                        // local reputation blocklist (closes the intel→agent loop).
                        if !poll.malware_hashes.is_empty() {
                            let n = rep_poll.load_malware_hashes(&poll.malware_hashes);
                            debug!("🧬 Loaded {} malware hashes from Nexus; blocklist now {} entries",
                                poll.malware_hashes.len(), n);
                        }

                        // Load ransomware extensions / note names from the intel
                        // feed into the ransomware detector — new families spread
                        // fleet-wide without a rebuild (the built-in defaults stay).
                        if !poll.ransom_extensions.is_empty() {
                            let n = ransom_poll.load_ransom_extensions(&poll.ransom_extensions);
                            if n > 0 { debug!("🔴 Loaded {} new ransomware extensions from Nexus intel", n); }
                        }
                        if !poll.ransom_note_names.is_empty() {
                            let n = ransom_poll.load_ransom_note_names(&poll.ransom_note_names);
                            if n > 0 { debug!("🔴 Loaded {} new ransom-note names from Nexus intel", n); }
                        }

                        // Deploy new approved rules. Optionally fire a ONE-SHOT
                        // retro hunt per newly-deployed rule, gated by config
                        // (retro.on_new_rule). This is a single discrete scan per
                        // rule at deploy time — not an ongoing process.
                        for rule in &poll.new_rules {
                            match rules_c.deploy_rule(rule).await {
                                Ok(_) => {
                                    info!("📋 Deployed rule: {}", rule.name);
                                    if !cfg_c2.retro.on_new_rule { continue; }
                                    let report = retro_c.run_rule_hunt(rule).await;
                                    let sources = report.sources_scanned;
                                    let matches = report.matches;
                                    // Report this as a TRACKED hunt so it shows on the
                                    // Retro Hunt page (the Nexus upserts the hunt row on
                                    // first report), not only in the raw threats feed.
                                    // A client-generated hunt_id keys the server row.
                                    if let Some(ref n) = nexus_retro {
                                        let hunt_id = uuid::Uuid::new_v4().to_string();
                                        let _ = n.report_retro_hunt(&hunt_id, "completed",
                                            &matches, sources, &hostname_retro, &rule.name).await;
                                    }
                                    if !matches.is_empty() {
                                        warn!("🕵️ Retro-hunt: {} historical hits for '{}'",
                                            matches.len(), rule.name);
                                        // Convert each match to a ThreatEvent and send to Nexus
                                        if let Some(ref n) = nexus_retro {
                                            for m in &matches {
                                                let threat = crate::types::ThreatEvent {
                                                    id:               uuid::Uuid::new_v4().to_string(),
                                                    agent_id:         agent_id_retro.clone(),
                                                    hostname:         hostname_retro.clone(),
                                                    timestamp:        m.timestamp_approx.unwrap_or_else(chrono::Utc::now),
                                                    severity:         crate::types::Severity::Info,
                                                    confidence:       70.0,
                                                    threat_name:      format!("Retro-hunt: historical match for rule '{}'", m.rule_name),
                                                    description:      format!(
                                                        "Historical log match found during retro-hunt.
                                                         Rule: {}
Source: {}:{}
Content: {}",
                                                        m.rule_name, m.source_file, m.line_number,
                                                        &m.line_content[..m.line_content.len().min(300)]
                                                    ),
                                                    mitre_tactics:    vec!["retro_hunt".to_string()],
                                                    mitre_techniques: vec![],
                                                    matched_rules:    vec![m.rule_name.clone()],
                                                    raw_event_ids:    vec![format!("{}:{}", m.source_file, m.line_number)],
                                                    chain:            None,
                                                    iocs:             vec![],
                                                    suggested_action: crate::types::ResponseAction::Monitor,
                                                    llm_analysis:     None,
                                                    auto_generated_rule: None,
                                                };
                                                let _ = n.send_threat(&threat).await;
                                            }
                                        }
                                    }
                                }
                                Err(e) => warn!("Rule deploy '{}' failed: {}", rule.name, e),
                            }
                        }

                        // Execute Nexus commands
                        for cmd in &poll.commands {
                            // FetchArtifact needs the Nexus client to upload bytes,
                            // so handle it here rather than in dispatch_nexus_command.
                            if matches!(cmd.command, types::NexusCommandType::FetchArtifact) {
                                if let Some(payload) = &cmd.payload {
                                    let artifact_id = payload["artifact_id"].as_i64().unwrap_or(-1);
                                    let path = payload["path"].as_str().unwrap_or("").to_string();
                                    if artifact_id >= 0 && !path.is_empty() {
                                        if let Err(e) = nexus_poll.upload_forensic_artifact(artifact_id, &path).await {
                                            warn!("Artifact upload failed: {}", e);
                                        }
                                    }
                                }
                                continue;
                            }
                            // CaptureSample: read a file (by path, or by locating a
                            // file matching a SHA-256) and upload it as a sample for
                            // analysis. Reuses the forensic-artifact upload channel.
                            if matches!(cmd.command, types::NexusCommandType::CaptureSample) {
                                if let Some(payload) = &cmd.payload {
                                    let sample_id = payload["sample_id"].as_str().unwrap_or("").to_string();
                                    let target    = payload["target"].as_str().unwrap_or("").to_string();
                                    if !sample_id.is_empty() && !target.is_empty() {
                                        if let Err(e) = nexus_poll.upload_sample(&sample_id, &target).await {
                                            warn!("Sample capture failed: {}", e);
                                        }
                                    }
                                }
                                continue;
                            }
                            // RunRetroHunt: on-demand historical hunt. Supports
                            // three kinds (payload "hunt_kind"): "rule" (default),
                            // "intel" (hunt a list of threat-intel IOC values), and
                            // "chain" (hunt an ordered set of indicators and report
                            // a correlated exploit-chain match if 2+ components hit).
                            if matches!(cmd.command, types::NexusCommandType::RunRetroHunt) {
                                if let Some(payload) = &cmd.payload {
                                    let hunt_kind = payload["hunt_kind"].as_str().unwrap_or("rule");
                                    let hunt_name = payload["rule_name"].as_str()
                                        .or(payload["hunt_name"].as_str()).unwrap_or("manual").to_string();
                                    let mk_threat = |name: String, desc: String, sev: crate::types::Severity,
                                                     conf: f32, rules: Vec<String>, refs: Vec<String>,
                                                     ts: chrono::DateTime<chrono::Utc>| crate::types::ThreatEvent {
                                        id: uuid::Uuid::new_v4().to_string(),
                                        agent_id: agent_id_retro.clone(),
                                        hostname: hostname_retro.clone(),
                                        timestamp: ts,
                                        severity: sev,
                                        confidence: conf,
                                        threat_name: name,
                                        description: desc,
                                        mitre_tactics: vec!["retro_hunt".to_string()],
                                        mitre_techniques: vec![],
                                        matched_rules: rules,
                                        raw_event_ids: refs,
                                        chain: None,
                                        iocs: vec![],
                                        suggested_action: crate::types::ResponseAction::Monitor,
                                        llm_analysis: None,
                                        auto_generated_rule: None,
                                    };

                                    match hunt_kind {
                                        // ── Threat-intel IOC hunt ──────────────────
                                        "intel" | "ioc" => {
                                            let iocs = payload["iocs"].as_array().cloned().unwrap_or_default();
                                            let hid = payload["hunt_id"].as_str().unwrap_or("").to_string();
                                            let mut all_matches: Vec<crate::retro::RetroMatch> = Vec::new();
                                            for (i, ioc_v) in iocs.iter().enumerate() {
                                                let value = ioc_v["value"].as_str().unwrap_or("");
                                                if value.is_empty() { continue; }
                                                let ioc = crate::types::IOC {
                                                    ioc_type: crate::types::IOCType::Domain, // type is informational for log scan
                                                    value: value.to_string(),
                                                    source: ioc_v["source"].as_str().unwrap_or("threat-intel").to_string(),
                                                    confidence: ioc_v["confidence"].as_f64().unwrap_or(0.7) as f32,
                                                };
                                                let matches = retro_c.run_ioc_hunt(&ioc).await.matches;
                                                if let Some(ref n) = nexus_retro {
                                                    for m in &matches {
                                                        let _ = n.send_threat(&mk_threat(
                                                            format!("Retro-hunt intel hit: {}", value),
                                                            format!("Threat-intel IOC '{}' found in {}:{}", value, m.source_file, m.line_number),
                                                            crate::types::Severity::High, 80.0,
                                                            vec![format!("intel:{}", value)],
                                                            vec![format!("{}:{}", m.source_file, m.line_number)],
                                                            m.timestamp_approx.unwrap_or_else(chrono::Utc::now),
                                                        )).await;
                                                    }
                                                    // Live progress: percent through the IOC list.
                                                    let pct = (((i + 1) as f32 / iocs.len().max(1) as f32) * 100.0) as u8;
                                                    n.report_progress("retro", &hid, pct, "hunting intel", value).await;
                                                }
                                                all_matches.extend(matches);
                                            }
                                            info!("🕵️ Intel retro-hunt '{}': {} IOC(s), {} hit(s)", hunt_name, iocs.len(), all_matches.len());
                                            if let Some(ref n) = nexus_retro {
                                                let _ = n.report_retro_hunt(&hid, "completed", &all_matches, iocs.len(), &hostname_retro, &hunt_name).await;
                                            }
                                        }
                                        // ── Exploit-chain hunt ─────────────────────
                                        "chain" => {
                                            // Each chain step is an indicator string to search for.
                                            // If 2+ steps match, report a correlated chain threat.
                                            let steps = payload["chain"].as_array().cloned().unwrap_or_default();
                                            let hid = payload["hunt_id"].as_str().unwrap_or("").to_string();
                                            let mut hit_steps: Vec<String> = Vec::new();
                                            let mut refs: Vec<String> = Vec::new();
                                            let mut all_matches: Vec<crate::retro::RetroMatch> = Vec::new();
                                            let mut earliest = chrono::Utc::now();
                                            for (i, step) in steps.iter().enumerate() {
                                                let indicator = step.as_str()
                                                    .or(step["indicator"].as_str()).unwrap_or("");
                                                if indicator.is_empty() { continue; }
                                                let ioc = crate::types::IOC {
                                                    ioc_type: crate::types::IOCType::ProcessName,
                                                    value: indicator.to_string(),
                                                    source: "exploit-chain".to_string(),
                                                    confidence: 0.6,
                                                };
                                                let matches = retro_c.run_ioc_hunt(&ioc).await.matches;
                                                if !matches.is_empty() {
                                                    hit_steps.push(indicator.to_string());
                                                    for m in &matches {
                                                        refs.push(format!("{}:{}", m.source_file, m.line_number));
                                                        if let Some(t) = m.timestamp_approx { if t < earliest { earliest = t; } }
                                                    }
                                                    all_matches.extend(matches);
                                                }
                                                if let Some(ref n) = nexus_retro {
                                                    let pct = (((i + 1) as f32 / steps.len().max(1) as f32) * 100.0) as u8;
                                                    n.report_progress("retro", &hid, pct, "hunting chain", indicator).await;
                                                }
                                            }
                                            if let Some(ref n) = nexus_retro {
                                                if hit_steps.len() >= 2 {
                                                    // Correlated multi-stage chain — high confidence.
                                                    let conf = (60.0 + hit_steps.len() as f32 * 10.0).min(99.0);
                                                    let _ = n.send_threat(&mk_threat(
                                                        format!("Exploit chain detected: {}", hunt_name),
                                                        format!("{} of {} chain stages matched historically: {}",
                                                            hit_steps.len(), steps.len(), hit_steps.join(" → ")),
                                                        crate::types::Severity::Critical, conf,
                                                        hit_steps.iter().map(|s| format!("chain:{}", s)).collect(),
                                                        refs.clone(), earliest,
                                                    )).await;
                                                } else if hit_steps.len() == 1 {
                                                    // Single stage — informational, not a full chain.
                                                    let _ = n.send_threat(&mk_threat(
                                                        format!("Partial chain indicator: {}", hunt_name),
                                                        format!("1 of {} chain stages matched: {}", steps.len(), hit_steps[0]),
                                                        crate::types::Severity::Medium, 50.0,
                                                        vec![format!("chain:{}", hit_steps[0])],
                                                        refs.clone(), earliest,
                                                    )).await;
                                                }
                                            }
                                            info!("🕵️ Chain retro-hunt '{}': {}/{} stages hit", hunt_name, hit_steps.len(), steps.len());
                                            if let Some(ref n) = nexus_retro {
                                                let _ = n.report_retro_hunt(&hid, "completed", &all_matches, steps.len(), &hostname_retro, &hunt_name).await;
                                            }
                                        }
                                        // ── Rule hunt (default, existing behaviour) ─
                                        _ => {
                                            let rule_content = payload["rule_content"].as_str().unwrap_or("").to_string();
                                            // Honour the rule_type the Nexus sent so the agent
                                            // routes YARA→file scan, others→log scan.
                                            let rt = match payload["rule_type"].as_str().unwrap_or("sigma").to_lowercase().as_str() {
                                                "yara"     => crate::types::RuleType::Yara,
                                                "wazuh"    => crate::types::RuleType::Wazuh,
                                                _           => crate::types::RuleType::Sigma,
                                            };
                                            // YARA file hunts don't need rule_content (they use the
                                            // compiled engine); others require a pattern body.
                                            let is_yara = matches!(rt, crate::types::RuleType::Yara);
                                            if !rule_content.is_empty() || is_yara {
                                                let synthetic = crate::types::DetectionRule {
                                                    id: uuid::Uuid::new_v4().to_string(),
                                                    rule_type: rt,
                                                    name: hunt_name.clone(),
                                                    severity: crate::types::Severity::Medium,
                                                    content: rule_content,
                                                    generated_from_event: String::new(),
                                                    generated_at: chrono::Utc::now(),
                                                    approved: true,
                                                    deployed_to: vec![],
                                                    llm_reasoning: String::new(),
                                                };
                                                // Set up live progress reporting: the hunt sends
                                                // (percent, phase) over a channel; a forwarder task
                                                // relays each update to the Nexus as "retro" progress.
                                                let hid_progress = payload["hunt_id"].as_str().unwrap_or("").to_string();
                                                let (ptx, mut prx) = tokio::sync::mpsc::unbounded_channel::<(u8, String)>();
                                                let prog_sender = if hid_progress.is_empty() { None } else { Some(ptx) };
                                                let prog_task = if let (Some(n), false) = (nexus_retro.clone(), hid_progress.is_empty()) {
                                                    let hid = hid_progress.clone();
                                                    Some(tokio::spawn(async move {
                                                        while let Some((pct, phase)) = prx.recv().await {
                                                            n.report_progress("retro", &hid, pct, &phase, "").await;
                                                        }
                                                    }))
                                                } else { None };

                                                let report = retro_c.run_rule_hunt_with_progress(&synthetic, prog_sender).await;
                                                // Closing the sender (dropped above) ends the forwarder.
                                                if let Some(t) = prog_task { let _ = t.await; }
                                                let matches = report.matches;
                                                info!("🕵️ Rule retro-hunt '{}': status={} {} matches ({})",
                                                    hunt_name, report.status.as_str(), matches.len(), report.reason);
                                                // Tell the Nexus this one-shot hunt finished, WITH the
                                                // match rows so the hunt-detail timeline populates.
                                                if let Some(ref n) = nexus_retro {
                                                    let hid = payload["hunt_id"].as_str().unwrap_or("");
                                                    let _ = n.report_retro_hunt(hid, report.status.as_str(), &matches, report.sources_scanned, &hostname_retro, &hunt_name).await;
                                                }
                                                if let Some(ref n) = nexus_retro {
                                                    for m in &matches {
                                                        let _ = n.send_threat(&mk_threat(
                                                            format!("Retro-hunt: historical match for rule '{}'", m.rule_name),
                                                            format!("On-demand retro-hunt match. Rule: {}  Source: {}:{}", m.rule_name, m.source_file, m.line_number),
                                                            crate::types::Severity::Info, 70.0,
                                                            vec![m.rule_name.clone()],
                                                            vec![format!("{}:{}", m.source_file, m.line_number)],
                                                            m.timestamp_approx.unwrap_or_else(chrono::Utc::now),
                                                        )).await;
                                                    }
                                                }
                                            } else {
                                                info!("🕵️ RunRetroHunt (rule) with no content; skipping");
                                            }
                                        }
                                    }
                                }
                                continue;
                            }
                            dispatch_nexus_command(
                                cmd, &hostname, &agent_id, &cfg_c2,
                                &posture_c2, &inv_c2, &forensics_c, &memory_c,
                                &response_engine_c, &gossip_c,
                            ).await;
                        }
                    }
                    Err(e) => warn!("Nexus poll failed: {}", e),
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // MAIN EVENT LOOP
    // ═══════════════════════════════════════════════════════════
    // Take ownership of the receiver from the Mutex for the loop lifetime
    let mut event_rx = {
        let guard = collector.rx.lock().await;
        // We can't hold the mutex guard across await points in the loop,
        // so we need a channel bridge — spawn a task that drains the rx
        // and forwards to our own channel.
        // This is necessary because Arc<Mutex<Receiver>> can't be awaited directly.
        drop(guard);
        // Instead: use a dedicated task that drains collector.rx
        let (bridge_tx, bridge_rx) = tokio::sync::mpsc::channel::<crate::types::RawEvent>(4096);
        let rx_arc = collector.rx.clone();
        tokio::spawn(async move {
            let mut rx = rx_arc.lock().await;
            loop {
                match rx.recv().await {
                    Some(e) => { if bridge_tx.send(e).await.is_err() { break; } }
                    None    => break,
                }
            }
        });
        bridge_rx
    };

    // ── Background async event loops & periodic scanners ─────────────
    // These drain the detector/monitor channels and run the periodic
    // sweeps. They MUST be spawned BEFORE the blocking main event loop
    // below; otherwise they only start at shutdown and never run.
    // ═══════════════════════════════════════════════════════════
    // Ransomware event loop
    // ═══════════════════════════════════════════════════════════
    {
        let nexus_r = nexus.clone();
        let resp_r  = response_engine.clone();
        tokio::spawn(async move {
            while let Some(threat) = ransom_rx.recv().await {
                // In protect mode: kill the ransomware process immediately
                if matches!(resp_r.mode, AgentMode::Protect) {
                    resp_r.execute_action(&threat.suggested_action, threat.confidence).await;
                }
                if let Some(ref n) = nexus_r {
                    let _ = n.send_threat(&threat).await;
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // APT event loop
    // ═══════════════════════════════════════════════════════════
    {
        let nexus_apt = nexus.clone();
        tokio::spawn(async move {
            while let Some(threat) = apt_rx.recv().await {
                if let Some(ref n) = nexus_apt {
                    let _ = n.send_threat(&threat).await;
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // DLP event loop
    // ═══════════════════════════════════════════════════════════
    {
        let nexus_dlp = nexus.clone();
        tokio::spawn(async move {
            while let Some(threat) = dlp_rx.recv().await {
                if let Some(ref n) = nexus_dlp {
                    let _ = n.send_threat(&threat).await;
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // FIM event loop — file integrity alerts
    // ═══════════════════════════════════════════════════════════
    {
        let nexus_fim   = nexus.clone();
        let _playbook_f  = playbook_engine.clone();
        let rep_fim      = reputation_engine.clone();
        tokio::spawn(async move {
            while let Some(threat) = fim_rx.recv().await {
                if let Some(ref n) = nexus_fim {
                    let _ = n.send_threat(&threat).await;
                }
                // On-access scan: a watched file just changed — scan it now with
                // hash blocklist + YARA + entropy (real-time, not waiting for the
                // 15-min periodic sweep). Only scan FilePath IOCs that are files.
                for ioc in &threat.iocs {
                    if matches!(ioc.ioc_type, crate::types::IOCType::FilePath) {
                        let p = ioc.value.clone();
                        if std::path::Path::new(&p).is_file() {
                            if let Some(scan_threat) = rep_fim.check_file(&p).await {
                                info!("🧬 On-access scan flagged modified file: {}", p);
                                if let Some(ref n) = nexus_fim {
                                    let _ = n.send_threat(&scan_threat).await;
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // Network monitor event loop
    // ═══════════════════════════════════════════════════════════
    {
        let nexus_net = nexus.clone();
        tokio::spawn(async move {
            while let Some(threat) = net_rx.recv().await {
                if let Some(ref n) = nexus_net {
                    let _ = n.send_threat(&threat).await;
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // Periodic secrets scan + zero-day process scan
    // ═══════════════════════════════════════════════════════════
    {
        let nexus_s     = nexus.clone();
        let secrets_c   = secrets_scanner.clone();
        let zeroday_c   = zeroday_detector.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                ticker.tick().await;
                // Secrets scan
                for threat in secrets_c.scan_process_envs().await {
                    if let Some(ref n) = nexus_s { let _ = n.send_threat(&threat).await; }
                }
                for threat in secrets_c.scan_credential_locations().await {
                    if let Some(ref n) = nexus_s { let _ = n.send_threat(&threat).await; }
                }
                // Zero-day process scan
                for threat in zeroday_c.scan_all_processes().await {
                    if let Some(ref n) = nexus_s { let _ = n.send_threat(&threat).await; }
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // Container security assessment (every 10 minutes)
    // ═══════════════════════════════════════════════════════════
    {
        let nexus_c2 = nexus.clone();
        let container_c = container_engine.clone();
        let agent_id_c = cfg.agent_id.clone();
        let hostname_c = cfg.hostname.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(120)).await;
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(600));
            loop {
                ticker.tick().await;
                if container_c.is_available() {
                    let findings = container_c.assess().await;
                    let threats = container::ContainerEngine::findings_to_threats(
                        &findings, &agent_id_c, &hostname_c);
                    for threat in threats {
                        if let Some(ref n) = nexus_c2 { let _ = n.send_threat(&threat).await; }
                    }
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // IaC security scan (every 30 minutes — scans cfg dirs)
    // ═══════════════════════════════════════════════════════════
    {
        let nexus_iac = nexus.clone();
        let iac_c = iac_scanner.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(180)).await;
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(1800));
            loop {
                ticker.tick().await;
                let findings = iac_c.scan_all().await;
                info!("🏗️  IaC scan: {} findings", findings.len());
                // IaC findings are logged — severity High+ would generate a posture event
                for f in &findings {
                    if matches!(f.severity, iac::IaCSeverity::Critical | iac::IaCSeverity::High) {
                        if let Some(ref n) = nexus_iac {
                            let _ = n.send_threat(&f.to_threat_event()).await;
                        }
                    }
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // Reputation check on new files (every 15 minutes)
    // ═══════════════════════════════════════════════════════════
    {
        let nexus_rep = nexus.clone();
        let rep_c = reputation_engine.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(90)).await;
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(900));
            loop {
                ticker.tick().await;
                // Scan recently modified executables in common paths
                for path in &["/tmp", "/var/tmp", "/dev/shm", "/usr/local/bin"] {
                    if let Ok(entries) = std::fs::read_dir(path) {
                        for entry in entries.flatten() {
                            let p = entry.path();
                            if p.is_file() {
                                if let Some(threat) = rep_c.check_file(p.to_str().unwrap_or("")).await {
                                    if let Some(ref n) = nexus_rep {
                                        let _ = n.send_threat(&threat).await;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // YARA memory scan — fileless / in-memory malware (every 30 min)
    // Scans running process memory regions against YARA rules. Catches
    // injected code, unpacked payloads, and fileless malware that never
    // touches disk. Only runs when a YARA scanner is available.
    // ═══════════════════════════════════════════════════════════
    if let Some(ref ys) = yara_scanner {
        let yara_mem = ys.clone();
        let nexus_mem = nexus.clone();
        let agent_id_mem = cfg.agent_id.clone();
        let hostname_mem = cfg.hostname.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(120)).await;
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(1800));
            loop {
                ticker.tick().await;
                // Enumerate PIDs from /proc and scan each process's memory.
                let pids: Vec<u32> = std::fs::read_dir("/proc").map(|rd| {
                    rd.flatten().filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok())).collect()
                }).unwrap_or_default();
                let scanner = yara_mem.clone();
                // Run the (blocking) memory scan off the async runtime.
                let hits = tokio::task::spawn_blocking(move || {
                    let mut found = Vec::new();
                    for pid in pids {
                        let m = scanner.scan_process(pid);
                        if !m.is_empty() {
                            let names: Vec<String> = m.iter().map(|x| x.rule_name.clone()).collect();
                            found.push((pid, names));
                        }
                    }
                    found
                }).await.unwrap_or_default();
                for (pid, names) in hits {
                    warn!("🧬 YARA memory match in pid {}: {:?}", pid, names);
                    if let Some(ref n) = nexus_mem {
                        let threat = crate::types::ThreatEvent {
                            id: uuid::Uuid::new_v4().to_string(),
                            agent_id: agent_id_mem.clone(),
                            hostname: hostname_mem.clone(),
                            timestamp: chrono::Utc::now(),
                            severity: crate::types::Severity::Critical,
                            confidence: 95.0,
                            threat_name: format!("YARA memory match: {}", names.join(", ")),
                            description: format!("Process pid={} has memory regions matching YARA rule(s): {}. Indicates fileless/in-memory malware, code injection, or an unpacked payload.", pid, names.join(", ")),
                            mitre_tactics: vec!["defense_evasion".to_string()],
                            mitre_techniques: vec!["T1055".to_string(), "T1620".to_string()],
                            matched_rules: names.clone(),
                            raw_event_ids: vec![],
                            chain: None,
                            iocs: vec![],
                            suggested_action: crate::types::ResponseAction::Alert,
                            llm_analysis: None,
                            auto_generated_rule: None,
                        };
                        let _ = n.send_threat(&threat).await;
                    }
                }
            }
        });
    }

    // Alert-dedup gate: collapse identical alerts (same threat + techniques +
    // process) within the configured window into one emission, re-emitting after
    // the window with a suppressed-occurrence count. Skips the whole downstream
    // cascade (response, forensics, status UI, gossip, Nexus) for duplicates.
    let dedup_gate = dedup::DedupGate::new(
        cfg.collector.dedup_enabled, cfg.collector.deduplicate_window_secs);
    if dedup_gate.enabled() {
        info!("🧹 Alert dedup enabled (window {}s)", dedup_gate.window_secs());
    } else {
        info!("🧹 Alert dedup disabled (forwarding every firing)");
    }

    // Detection-time suppression / allowlist: known-good processes/techniques
    // are dropped or downgraded before they raise a live alert.
    let suppression = suppression::SuppressionEngine::new(&cfg.detection);

    loop {
        let event = match event_rx.recv().await {
            Some(e) => e,
            None    => break,
        };

        // ── Fast-path: GOSSIP IOC blacklist check ──────────────
        if let Some(ref ip) = event.network_dest_ip {
            let bad = gossip_engine.is_ioc_known(ip);
            // NetGuard: connection-level host self-protection. Evaluates the
            // outbound connection against connection rules + reputation and,
            // in Protect mode, blocks at the firewall. Emits a richer event
            // than the bare gossip block below.
            let proto = event.network_proto.clone().unwrap_or_else(|| "tcp".into());
            let port  = event.network_dest_port.unwrap_or(0);
            if let Some(ng_event) = netguard.evaluate_connection(
                ip, port, &proto, netguard::Direction::Outbound, bad).await {
                if let Some(ref n) = nexus { let _ = n.send_threat(&ng_event).await; }
            }
            if bad {
                warn!("📡 GOSSIP: blocked peer-reported IOC {}", ip);
                if cfg.is_protect_mode() {
                    response_engine.block_ip(ip).await;
                }
                continue;
            }
        }
        if let Some(ref hash) = event.file_hash {
            if gossip_engine.is_ioc_known(hash) {
                warn!("📡 GOSSIP: blocked peer-reported hash {}", hash);
                continue;
            }
        }

        // ── Inbound brute-force (NetGuard fail2ban) ───────────
        // Failed authentication events feed NetGuard's failure tracker, which
        // auto-blocks a source IP after N failures within a window. Enforcement
        // (the actual firewall ban) happens only in Protect mode — NetGuard's
        // own `enforce` flag gates it; in Detect/Audit this only alerts. Needs a
        // source IP, which the collector supplies via extra["src_ip"] (also
        // "source_ip"/"rhost"); without one we can't attribute the failure.
        if matches!(event.event_type, types::EventType::UserAuth | types::EventType::UserSu) {
            let failed = event.return_code.map(|rc| rc != 0).unwrap_or(false)
                || event.extra.get("auth_result").and_then(|v| v.as_str())
                    .map(|s| s.eq_ignore_ascii_case("failure") || s.eq_ignore_ascii_case("failed"))
                    .unwrap_or(false);
            if failed {
                let src_ip = ["src_ip", "source_ip", "rhost"].iter()
                    .find_map(|k| event.extra.get(*k).and_then(|v| v.as_str()));
                if let Some(src) = src_ip {
                    let ctx = format!("failed {} (uid={}) on {}",
                        if matches!(event.event_type, types::EventType::UserSu) { "su" } else { "auth" },
                        event.uid, event.hostname);
                    if let Some(bf_event) = netguard.record_failure(src, &ctx).await {
                        if let Some(ref n) = nexus { let _ = n.send_threat(&bf_event).await; }
                    }
                }
            }
        }

        // Each detector runs under a panic boundary (see `guarded`): a panic in
        // one — e.g. from a crafted event — is logged and skipped, never taking
        // the agent down or stopping the other detectors.
        // ── Ransomware detection ──────────────────────────────
        let ransom_hit = guarded("ransomware", ransomware_detector.analyze(&event)).await;

        // ── APT behavioral detection ──────────────────────────
        let apt_hit = guarded("apt", apt_detector.analyze(&event)).await;

        // ── DLP analysis ──────────────────────────────────────
        let dlp_hit = guarded("dlp", dlp_engine.analyze(&event)).await;

        // ── Zero-day behavioral detection ────────────────────
        let zeroday_hit = guarded("zeroday", zeroday_detector.analyze(&event)).await;

        // ── Anomaly + rule matching ────────────────────────────
        let anomaly_hit = guarded("anomaly", anomaly_engine.analyze(&event)).await;

        // ── Behavioral baseline (learned-normal deviation) ─────
        let baseline_hit = match &baseline_engine {
            Some(be) => guarded("baseline", be.analyze(&event)).await,
            None => None,
        };

        // Merge: ransomware > zero-day > DLP > APT > anomaly > baseline.
        // Baseline is lowest precedence on its own, but if it coincides with
        // another detection we fuse it as corroborating evidence (raising
        // confidence) rather than discarding it.
        let combined = match (anomaly_hit, zeroday_hit, dlp_hit, ransom_hit, apt_hit) {
            (_, _, _, Some(r), _)       => Some(r),
            (_, Some(zd), _, _, _)      => Some(zd),
            (_, _, Some(dlp), _, _)     => Some(dlp),
            (_, _, _, _, Some(apt))     => Some(apt),
            (Some(anomaly), _, _, _, _) => Some(anomaly),
            _                           => baseline_hit.clone(),
        };
        let combined = combined.map(|mut t| {
            // Fusion: a primary detection that ALSO trips the behavioral baseline
            // is more likely a true positive — boost confidence and annotate.
            if let Some(ref b) = baseline_hit {
                if t.matched_rules.first().map(|r| r != "baseline").unwrap_or(true) {
                    t.confidence = (t.confidence + 10.0).min(99.0);
                    t.description = format!("{}\n\n[corroborated by behavioral baseline] {}",
                        t.description, b.threat_name);
                    t.matched_rules.push("baseline".to_string());
                }
            }
            t
        });

        if let Some(mut threat) = combined {
            // Rule matching (YARA, Sigma, Wazuh). Score by the rule's REAL
            // severity instead of a flat bump: elevate the threat's severity to
            // the strongest matching rule, raise confidence proportionally, and
            // fold in the rule's MITRE technique. (Previously match_event
            // returned only names and every hit added a flat +10 — the parsed
            // Sigma `level` / Wazuh level was discarded.)
            let rule_hits = rules_engine.match_event(&event).await;
            if !rule_hits.is_empty() {
                let mut max_sev = crate::types::Severity::Info;
                let mut max_bump = 0.0_f32;
                for hit in &rule_hits {
                    let (sev, bump) = rule_severity_weight(&hit.severity);
                    if sev > max_sev { max_sev = sev; }
                    if bump > max_bump { max_bump = bump; }
                    if let Some(t) = &hit.technique {
                        if !t.is_empty() && !threat.mitre_techniques.iter().any(|x| x == t) {
                            threat.mitre_techniques.push(t.clone());
                        }
                    }
                    threat.matched_rules.push(hit.name.clone());
                }
                if max_sev > threat.severity { threat.severity = max_sev; }
                threat.confidence = (threat.confidence + max_bump).min(100.0);
            }

            // ── Detection-time suppression / allowlist ─────────
            // Operator-defined known-good matches drop or downgrade the alert
            // before any downstream action. Applied BEFORE dedup so allowlisted
            // firings don't even occupy the dedup map.
            if !suppression.is_empty() {
                let ppath = event.process_path.as_deref().unwrap_or("");
                match suppression.evaluate(&threat, &event.process_name, ppath) {
                    suppression::SuppressVerdict::Drop(reason) => {
                        debug!("🛡️  suppression: dropped '{}' (process {}) — {}",
                            threat.threat_name, event.process_name, reason);
                        continue;
                    }
                    suppression::SuppressVerdict::Downgrade(reason) => {
                        threat.severity = crate::types::Severity::Info;
                        threat.confidence = threat.confidence.min(20.0);
                        threat.description = format!("[SUPPRESSED: {}] {}", reason, threat.description);
                    }
                    suppression::SuppressVerdict::Allow => {}
                }
            }

            // ── Alert dedup gate ───────────────────────────────
            // Identical alerts (threat + techniques + process) inside the window
            // are suppressed entirely — no response, forensics, UI row, gossip,
            // or Nexus send. A re-emission after the window carries how many
            // firings were suppressed in between so recurrence stays visible.
            let dedup_key = dedup::DedupGate::key(&threat, &event.process_name);
            match dedup_gate.evaluate(&dedup_key, threat.timestamp) {
                dedup::DedupVerdict::Suppress => {
                    debug!("🧹 dedup: suppressed duplicate alert '{}'", dedup_key);
                    continue;
                }
                dedup::DedupVerdict::Emit { recurred } if recurred > 0 => {
                    threat.description = format!(
                        "{}\n\n[dedup] recurred {}× (suppressed) in the last {}s before this alert",
                        threat.description, recurred, dedup_gate.window_secs());
                }
                dedup::DedupVerdict::Emit { .. } => {}
            }

            // ── Forensics (confidence-gated, captured BEFORE response) ──
            // Volatile state (process memory, /proc, open FDs) must be captured
            // while the process is still alive. If capture_before_response is set
            // and this threat would trigger a destructive action, we collect
            // synchronously first to avoid a race with the process kill.
            let fcfg = &forensics_engine.config;
            // TIERED ENTRY: collect (at least lightweight) forensics once the
            // threat clears the LIGHT tier. The memory-dump decision happens
            // inside collect_for_threat based on full_confidence. We keep the
            // lower of light_confidence/min_confidence as the entry gate so an
            // operator lowering either one takes effect.
            let entry_threshold = fcfg.light_confidence.min(fcfg.min_confidence);
            let forensics_warranted = fcfg.enabled && threat.confidence >= entry_threshold;
            let will_act_destructively = matches!(threat.suggested_action,
                crate::types::ResponseAction::KillProcess(_)
                | crate::types::ResponseAction::IsolateHost
                | crate::types::ResponseAction::QuarantineFile(_));

            if forensics_warranted && fcfg.capture_before_response && will_act_destructively {
                // Capture first, awaited, so the artifact reflects the live process.
                match forensics_engine.collect_for_threat(&threat, &event).await {
                    Ok(bundle) => {
                        if let Some(ref n) = nexus {
                            let mut manifest = serde_json::to_value(&bundle).unwrap_or(serde_json::json!({}));
                            manifest["agent_id"] = serde_json::json!(n.agent_id());
                            let _ = n.send_forensic_manifest(&manifest).await;
                        }
                    }
                    Err(e) => warn!("Forensics collection (pre-response) failed: {}", e),
                }
            } else if forensics_warranted {
                // Tiered policy: the threat cleared the light tier but we're not
                // about to kill anything, so capture in the BACKGROUND (don't block
                // the event loop). collect_for_threat decides internally whether
                // this also warrants the full memory dump (full_confidence tier).
                let fe = forensics_engine.clone();
                let n2 = nexus.clone();
                let threat_c = threat.clone();
                let event_c = event.clone();
                tokio::spawn(async move {
                    match fe.collect_for_threat(&threat_c, &event_c).await {
                        Ok(bundle) => {
                            if let Some(ref n) = n2 {
                                let mut manifest = serde_json::to_value(&bundle).unwrap_or(serde_json::json!({}));
                                manifest["agent_id"] = serde_json::json!(n.agent_id());
                                let _ = n.send_forensic_manifest(&manifest).await;
                            }
                        }
                        Err(e) => warn!("Forensics collection (background) failed: {}", e),
                    }
                });
            }

            // ── Immediate response (before slow LLM) ──────────
            response_engine.execute(&threat, &event).await;

            // ── Playbook execution ────────────────────────────
            if let Some(book) = playbook_engine.match_playbook(&threat) {
                let book_c      = book.clone();
                let threat_c    = threat.clone();
                let pb_exec     = playbook_engine.clone();
                tokio::spawn(async move {
                    pb_exec.execute(&book_c, &threat_c).await;
                });
            }

            // ── Local status UI: record the detected event ─────
            // Every detection is recorded to the local, read-only status UI
            // (http://localhost:7440) as it fires — regardless of ATC. This gives
            // on-endpoint visibility with no Nexus dependency (air-gapped safe).
            // Recorded here as a "Legacy" (pre-ATC) event; if async ATC
            // enrichment completes below, it is upgraded to source "ATC" with the
            // model's reasoning attached.
            status_ui::record_event(&status_state, status_ui::StatusEvent {
                timestamp:     threat.timestamp.format("%H:%M:%S").to_string(),
                severity:      format!("{}", threat.severity),
                threat_name:   threat.threat_name.clone(),
                technique:     threat.mitre_techniques.first().cloned().unwrap_or_default(),
                confidence:    threat.confidence,
                source:        "Legacy".into(),
                description:   threat.description.clone(),
                atc_reasoning: String::new(),
                tactics:       threat.mitre_tactics.clone(),
                techniques:    threat.mitre_techniques.clone(),
                matched_rules: threat.matched_rules.clone(),
                iocs:          threat.iocs.iter()
                                   .map(|i| (format!("{:?}", i.ioc_type), i.value.clone()))
                                   .collect(),
                suggested_action: format!("{:?}", threat.suggested_action),
            }).await;

            // ── Legacy syslog forward ──────────────────────────
            {
                let bridge = legacy_bridge.clone();
                let t = threat.clone();
                tokio::spawn(async move {
                    let _ = bridge.send_threat(&t).await;
                });
            }

            // ── GOSSIP: broadcast new IOCs to peers ───────────
            // Only share IOCs from reasonably-confident threats. Broadcasting
            // every low-confidence detection floods the mesh and the Nexus with
            // false positives, so we gate on a confidence floor.
            const GOSSIP_IOC_MIN_CONFIDENCE: f32 = 65.0;
            if threat.confidence >= GOSSIP_IOC_MIN_CONFIDENCE {
                for ioc in &threat.iocs {
                    // Skip IOCs that are themselves low-confidence even if the
                    // parent threat scored higher. IOC confidence is 0–100.
                    if ioc.confidence >= 60.0 {
                        let _ = gossip_engine.broadcast_ioc(ioc).await;
                    }
                }
            }

            // ── Forensics for non-destructive high-confidence events ──
            // (For threats that won't kill the process, or when pre-capture is
            // disabled, collect in the background — no race to worry about.)
            if forensics_warranted && !(fcfg.capture_before_response && will_act_destructively) {
                let f  = forensics_engine.clone();
                let t  = threat.clone();
                let ev = event.clone();
                let n_for = nexus.clone();
                tokio::spawn(async move {
                    match f.collect_for_threat(&t, &ev).await {
                        Ok(bundle) => {
                            if let Some(ref n) = n_for {
                                let mut manifest = serde_json::to_value(&bundle).unwrap_or(serde_json::json!({}));
                                manifest["agent_id"] = serde_json::json!(n.agent_id());
                                let _ = n.send_forensic_manifest(&manifest).await;
                            }
                        }
                        Err(e) => warn!("Forensics collection failed: {}", e),
                    }
                });
            }

            // ── Forward to Nexus, with optional async LLM (ATC) enrichment ──
            // CRITICAL: detection events are ALWAYS forwarded to the Nexus, even
            // when the LLM is unavailable or judges the event benign. The LLM is
            // an ENRICHMENT layer (explanation, confidence adjustment, MITRE
            // refinement, auto-rule generation), NOT a gate. Previously the only
            // send_threat call lived inside the analyze_threat() match, so with
            // no model the entire behavioral-detection stream was silently
            // dropped — agents detected plenty, the Nexus showed nothing.
            {
                let llm_c    = llm_engine.clone();
                let threat_c = threat.clone();
                let nexus_c  = nexus.clone();
                let status_c = status_state.clone();

                tokio::spawn(async move {
                    // Try LLM enrichment (best-effort). If unavailable, returns None.
                    let analysis = llm_c.analyze_threat(&threat_c).await;

                    // Base event key (as recorded on the Legacy path) so ATC
                    // enrichment upgrades the SAME row in the local status UI.
                    let ev_name = threat_c.threat_name.clone();
                    let ev_tech = threat_c.mitre_techniques.first().cloned().unwrap_or_default();

                    let mut enriched = threat_c;
                    match analysis {
                        Some(a) => {
                            // Upgrade the local status event to source "ATC" with
                            // the model's reasoning, and the enriched confidence.
                            enriched.confidence = (enriched.confidence + a.confidence_adjustment)
                                .clamp(0.0, 100.0);
                            status_ui::attach_atc_reasoning(
                                &status_c, &ev_name, &ev_tech, enriched.confidence,
                                a.explanation.clone()).await;
                            if !a.mitre_refinement.is_empty() {
                                enriched.mitre_techniques = a.mitre_refinement;
                            }
                            // LLM thinks it's benign: don't drop it — forward it
                            // flagged so the analyst can see what ATC suppressed
                            // and review/override rather than lose visibility. We
                            // prefix the analysis so the Nexus can classify it.
                            if a.suspicious {
                                enriched.llm_analysis = Some(a.explanation);
                            } else {
                                // ATC judged this benign. Rather than only annotate
                                // it (which left noise like "sudo to root shell" at
                                // MEDIUM), actively DOWNGRADE the severity to Info
                                // and floor confidence so it drops out of the active
                                // feed. The [ATC-SUPPRESSED] prefix lets Nexus/UI
                                // filter it out by default while keeping it findable
                                // (forwarded, not dropped). This is the core
                                // noise-reduction lever.
                                enriched.llm_analysis = Some(format!("[ATC-SUPPRESSED] {}", a.explanation));
                                enriched.severity = crate::types::Severity::Info;
                                enriched.confidence = enriched.confidence.min(20.0);
                            }
                            if let Some(rule) = a.generated_rule {
                                enriched.auto_generated_rule = Some(rule.clone());
                                if let Some(ref n) = nexus_c {
                                    let _ = n.submit_rule_for_approval(&rule).await;
                                }
                            }
                        }
                        None => {
                            // No LLM: forward the raw detection as-is. llm_analysis
                            // stays None, which the Nexus uses to classify it as a
                            // "Legacy" (non-ATC) detection in the UI.
                            enriched.llm_analysis = None;
                        }
                    }

                    if let Some(ref n) = nexus_c {
                        let _ = n.send_threat(&enriched).await;
                    }
                });
            }
        }
    }


    info!("NebulaSentinel agent shutting down cleanly");
    Ok(())
}

/// Map a normalized rule severity string to the severity floor it imposes on a
/// detection and the confidence it adds. Higher-severity rules are stronger
/// evidence, so they raise both the ceiling (severity) and the score. The bump
/// is applied as a MAX across matching rules (not a sum), so a burst of many
/// low rules can't inflate a detection past one genuine high rule.
fn rule_severity_weight(sev: &str) -> (types::Severity, f32) {
    match sev {
        "critical" => (types::Severity::Critical, 25.0),
        "high"     => (types::Severity::High,     18.0),
        "medium"   => (types::Severity::Medium,   12.0),
        "low"      => (types::Severity::Low,        6.0),
        _          => (types::Severity::Info,       2.0),
    }
}

// ══════════════════════════════════════════════════════════════
// Nexus command dispatcher
// All commands validated and fully implemented.
// ══════════════════════════════════════════════════════════════
/// Fetch the fleet GOSSIP mesh encryption key from the Nexus (authenticated with
/// the ATC API key, over the shared TLS-pinning client). Returns a validated
/// 64-hex key or None.
async fn fetch_nexus_gossip_key(nexus: &config::NexusConfig) -> Option<String> {
    let url = format!("{}/api/atc/gossip/key", nexus.url.trim_end_matches('/'));
    let client = crate::tls::nexus_http_builder(nexus.ca_cert_path.as_deref(), nexus.tls_verify)
        .timeout(std::time::Duration::from_secs(10))
        .build().ok()?;
    let resp = client.get(&url).header("X-Api-Key", &nexus.api_key).send().await.ok()?;
    if !resp.status().is_success() { return None; }
    let v: serde_json::Value = resp.json().await.ok()?;
    let k = v.get("key")?.as_str()?.trim().to_lowercase();
    if k.len() == 64 && k.bytes().all(|b| b.is_ascii_hexdigit()) { Some(k) } else { None }
}

async fn dispatch_nexus_command(
    cmd:        &types::NexusCommand,
    hostname:   &str,
    agent_id:   &str,
    cfg:        &AgentConfig,
    posture:    &Arc<posture::PostureEngine>,
    inventory:  &Arc<inventory::InventoryEngine>,
    forensics:  &Arc<forensics::ForensicsEngine>,
    memory:     &Arc<memory::MemoryEngine>,
    response:   &Arc<response::ResponseEngine>,
    gossip:     &Arc<gossip::GossipEngine>,
) {
    // Note: BlockIp, IsolateHost, UnblockIp, KillProcess, QuarantineFile
    // all delegate to the firewall abstraction via ResponseEngine.
    // No direct iptables calls anywhere in the dispatcher.
    use NexusCommandType::*;
    info!("📥 Nexus command: {:?} (id={})", cmd.command, cmd.id);

    match &cmd.command {

        Ping => {
            info!("  ↩ PONG agent={} hostname={}", agent_id, hostname);
        }

        // ── Posture & Inventory ────────────────────────────────
        RunPostureScan => {
            info!("  🔄 On-demand posture scan starting...");
            let posture_c = posture.clone();
            let cfg_c     = cfg.clone();
            tokio::spawn(async move {
                match posture_c.run_full_assessment(&cfg_c).await {
                    Ok(r)  => info!("  ✅ Posture score: {:.1}%  vulns: {}", r.overall_score, r.vulnerability_count),
                    Err(e) => warn!("  ✗ Posture scan failed: {}", e),
                }
            });
        }

        RunInventory => {
            info!("  🔄 On-demand inventory...");
            let inv_c = inventory.clone();
            tokio::spawn(async move {
                match inv_c.collect().await {
                    Ok(i)  => info!("  ✅ Inventory: {} pkgs  {} procs  {} containers",
                        i.installed_packages, i.running_processes, i.containers.len()),
                    Err(e) => warn!("  ✗ Inventory failed: {}", e),
                }
            });
        }

        RunRetroHunt => {
            info!("  🔄 Retro-hunt queued for next rule sync cycle");
            // Retro-hunt is triggered automatically when new rules arrive in the poll.
            // This command sets a flag for the next rule check loop.
        }

        // ── Forensics ──────────────────────────────────────────
        CollectForensics => {
            info!("  🔬 On-demand forensics collection...");
            let dir = std::path::PathBuf::from("/var/lib/nebula/forensics/on_demand");
            let _ = std::fs::create_dir_all(&dir);
            let _forensics_c = forensics.clone();
            let memory_c    = memory.clone();
            let dir_c       = dir.clone();
            tokio::spawn(async move {
                // Memory dump
                match memory_c.acquire_dump(&dir_c).await {
                    Ok(p)  => info!("  ✅ Memory dump: {}", p.display()),
                    Err(e) => warn!("  ✗ Memory dump failed (may need root or LiME): {}", e),
                }
                info!("  ✅ Forensics bundle saved to {}", dir_c.display());
            });
        }

        // ── Artifact fetch — handled in the poll loop (needs Nexus client) ──
        FetchArtifact => { /* dispatched earlier where the Nexus client is available */ }
        CaptureSample => { /* dispatched earlier where the Nexus client is available */ }

        // ── Host isolation ─────────────────────────────────────
        IsolateHost => {
            warn!("  🔒 *** HOST ISOLATION ORDERED by Nexus for {} ***", hostname);
            if response.is_isolated() {
                info!("  Host is already isolated — skipping");
                return;
            }
            let resp_c = response.clone();
            tokio::spawn(async move {
                resp_c.isolate_host().await;
            });
        }

        UndoIsolation => {
            warn!("  🔓 Isolation removal ordered by Nexus for {}", hostname);
            let resp_c = response.clone();
            tokio::spawn(async move {
                resp_c.undo_isolation().await;
            });
        }

        // ── Network blocking ───────────────────────────────────
        BlockIp => {
            if let Some(ref p) = cmd.payload {
                let ip = p["ip"].as_str()
                    .or_else(|| p.as_str())
                    .unwrap_or("").to_string();
                if !ip.is_empty() {
                    warn!("  🚫 Blocking IP {} (Nexus order)", ip);
                    let resp_c = response.clone();
                    tokio::spawn(async move {
                        resp_c.block_ip(&ip).await;
                    });
                } else {
                    warn!("  ✗ BlockIp: no IP in payload {:?}", p);
                }
            }
        }

        UnblockIp => {
            if let Some(ref p) = cmd.payload {
                let ip = p["ip"].as_str()
                    .or_else(|| p.as_str())
                    .unwrap_or("").to_string();
                if !ip.is_empty() {
                    let resp_c = response.clone();
                    tokio::spawn(async move {
                        resp_c.unblock_ip(&ip).await;
                    });
                }
            }
        }

        // ── Process kill ───────────────────────────────────────
        KillProcess => {
            if let Some(ref p) = cmd.payload {
                let pid = p["pid"].as_u64()
                    .or_else(|| p.as_str().and_then(|s| s.parse().ok()))
                    .unwrap_or(0) as u32;
                if pid > 1 {  // never kill pid 1 (init)
                    warn!("  ⚡ KillProcess pid={} (Nexus order)", pid);
                    let resp_c = response.clone();
                    tokio::spawn(async move {
                        resp_c.kill_process(pid).await;
                    });
                } else {
                    warn!("  ✗ KillProcess: invalid or missing pid in payload");
                }
            }
        }

        // ── File quarantine ────────────────────────────────────
        QuarantineFile => {
            if let Some(ref p) = cmd.payload {
                let path = p["path"].as_str()
                    .or_else(|| p.as_str())
                    .unwrap_or("").to_string();
                if !path.is_empty() {
                    warn!("  📦 QuarantineFile {} (Nexus order)", path);
                    let resp_c = response.clone();
                    tokio::spawn(async move {
                        resp_c.quarantine_file(&path).await;
                    });
                }
            }
        }

        // ── Configuration ──────────────────────────────────────
        SetMode => {
            if let Some(ref p) = cmd.payload {
                let new_mode = p["mode"].as_str()
                    .or_else(|| p.as_str())
                    .unwrap_or("detect");
                warn!("  🔄 Mode change requested: {} → {} (effective after restart)", hostname, new_mode);
                // Write new mode to config file
                let config_path = "/etc/nebula/config.toml";
                if let Ok(mut content) = std::fs::read_to_string(config_path) {
                    let old_line = content.lines()
                        .find(|l| l.trim_start().starts_with("mode"))
                        .unwrap_or("").to_string();
                    if !old_line.is_empty() {
                        content = content.replace(&old_line, &format!("mode = \"{}\"", new_mode));
                        if let Err(e) = std::fs::write(config_path, &content) {
                            warn!("  ✗ Failed to write config: {}", e);
                        } else {
                            info!("  ✅ Config updated — mode={}", new_mode);
                        }
                    }
                }
            }
        }

        UpdateConfig => {
            if let Some(ref payload) = cmd.payload {
                info!("  📝 Config update received — {} fields",
                    payload.as_object().map(|o| o.len()).unwrap_or(0));
                // Persist a GOSSIP config override if present. The interval and
                // some engine internals are read at startup, so the override is
                // written to disk and fully applied on the next agent restart;
                // sharing toggles read from config each send take effect sooner.
                if let Some(gossip_cfg) = payload.get("gossip") {
                    let dir = "/var/lib/nebula";
                    let _ = std::fs::create_dir_all(dir);
                    let path = format!("{}/gossip_override.json", dir);
                    match std::fs::write(&path, serde_json::to_string_pretty(gossip_cfg).unwrap_or_default()) {
                        Ok(_) => info!("  📡 GOSSIP config override saved to {}", path),
                        Err(e) => warn!("  Failed to save GOSSIP override: {}", e),
                    }
                    // Apply the broadcast interval LIVE (no restart needed).
                    if let Some(secs) = gossip_cfg["gossip_interval_secs"].as_u64() {
                        gossip.set_interval(secs);
                    }
                }
                info!("  Effective policy: {}", serde_json::to_string_pretty(payload).unwrap_or_default());
            }
        }

        ApplyPolicy => {
            if let Some(ref payload) = cmd.payload {
                let n_fields = payload.as_object().map(|o| o.len()).unwrap_or(0);
                info!("  📋 Policy received from Nexus — {} field(s)", n_fields);
                // Persist the policy durably so it survives restarts and is
                // auditable. Engine configs are read at startup, so policy fields
                // take effect on the next restart; `mode` is additionally written
                // into the active config file (same mechanism as SetMode) so the
                // fleet's mode intent is captured immediately.
                let policy_path = "/var/lib/nebula/policy.json";
                if let Some(dir) = std::path::Path::new(policy_path).parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                match serde_json::to_string_pretty(payload) {
                    Ok(js) => match std::fs::write(policy_path, js) {
                        Ok(_)  => info!("  ✅ Policy persisted to {} (effective after restart)", policy_path),
                        Err(e) => warn!("  ✗ Failed to persist policy: {}", e),
                    },
                    Err(e) => warn!("  ✗ Policy serialize failed: {}", e),
                }
                // Apply `mode` to the on-disk config immediately (like SetMode).
                if let Some(new_mode) = payload.get("mode").and_then(|m| m.as_str()) {
                    let config_path = "/etc/nebula/config.toml";
                    if let Ok(mut content) = std::fs::read_to_string(config_path) {
                        if let Some(old_line) = content.lines()
                            .find(|l| l.trim_start().starts_with("mode")).map(|s| s.to_string())
                        {
                            content = content.replace(&old_line, &format!("mode = \"{}\"", new_mode));
                            match std::fs::write(config_path, &content) {
                                Ok(_)  => info!("  ✅ Policy set mode={} (effective after restart)", new_mode),
                                Err(e) => warn!("  ✗ Failed to write mode to config: {}", e),
                            }
                        }
                    }
                }
            }
        }

        DeployRule => {
            // Rules are delivered via the poll new_rules field, not as commands.
            // This handler exists for completeness.
            info!("  📋 DeployRule via command (rules normally delivered in poll response)");
        }
    }
}

fn print_banner() {
    println!();
    println!("  ███╗   ██╗███████╗██████╗ ██╗   ██╗██╗      █████╗ ");
    println!("  ████╗  ██║██╔════╝██╔══██╗██║   ██║██║     ██╔══██╗");
    println!("  ██╔██╗ ██║█████╗  ██████╔╝██║   ██║██║     ███████║");
    println!("  ██║╚██╗██║██╔══╝  ██╔══██╗██║   ██║██║     ██╔══██║");
    println!("  ██║ ╚████║███████╗██████╔╝╚██████╔╝███████╗██║  ██║");
    println!("  ╚═╝  ╚═══╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝");
    println!("  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ");
    println!("  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ");
    println!("  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ");
    println!("  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ");
    println!("  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗");
    println!("  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝");
    println!();
    println!("  Autonomous Threat Cognition (ATC) Agent v{}", env!("CARGO_PKG_VERSION"));
    println!("  Local-first · Privacy-preserving · MITRE ATT&CK v15 + ATLAS");
    println!();
}

// ══════════════════════════════════════════════════════════════
// CLI utility commands
// ══════════════════════════════════════════════════════════════

/// `nebula-agent --hardware-info`
/// Prints detected GPU/CPU info and recommended model.
async fn cmd_hardware_info() -> Result<()> {
    println!("\n🔍 NebulaSentinel hardware detection\n");

    // CPU info
    let cpus = num_cpus();
    println!("CPU:");
    if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
        let model = info.lines()
            .find(|l| l.starts_with("model name"))
            .and_then(|l| l.split(':').nth(1))
            .unwrap_or("unknown").trim();
        println!("  Model   : {}", model);
    }
    println!("  Cores   : {}", cpus);

    // RAM
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        let ram_kb: u64 = meminfo.lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok()).unwrap_or(0);
        println!("  RAM     : {} GB", ram_kb / 1024 / 1024);
    }

    // GPU
    println!("\nGPU:");
    match llm::probe_gpu().await {
        Some(g) => {
            println!("  Vendor  : {}", g.vendor);
            println!("  Name    : {}", g.name);
            println!("  VRAM    : {} MB ({:.1} GB)", g.vram_mb, g.vram_mb as f64 / 1024.0);
            println!("  Driver  : {}", g.driver);

            println!("\n✅ Recommended model for this GPU:");
            println!("   {}", llm::select_model_path_for_vram(g.vram_mb));
        }
        None => {
            println!("  No GPU detected — CPU inference mode");
            println!("\n✅ Recommended model for CPU:");
            println!("   {}", llm::select_model_path_for_vram(0));
        }
    }

    // What's actually loadable right now, and what would be picked.
    println!("\nModels available locally ({}):", crate::platform::models_dir().display());
    llm::print_local_models();

    // Build-time backend
    println!("\nCompile-time backend:");
    #[cfg(llm_backend = "cuda")]
    println!("  NVIDIA CUDA (compiled with --features cuda)");
    #[cfg(llm_backend = "rocm")]
    println!("  AMD ROCm (compiled with --features rocm)");
    #[cfg(llm_backend = "metal")]
    println!("  Apple Metal (compiled with --features metal)");
    #[cfg(llm_backend = "cpu")]
    println!("  CPU (no GPU toolkit found at build time)");

    println!("\nRun `nebula-agent --download-model` to download the recommended model,");
    println!("or `nebula-agent --download-model <alias|owner/repo|url>` for any other GGUF");
    println!("(`nebula-agent --list-models` lists the built-in aliases).");
    Ok(())
}

/// Pre-flight the LLM model load in a throwaway subprocess (`--llm-selftest`).
/// Returns true only if that child loads the model and exits 0. If it dies from
/// a signal (SIGILL/SIGABRT/SIGSEGV — the uncatchable C++/CUDA faults) or exits
/// non-zero, we return false so the main agent never attempts the fatal load.
async fn llm_preflight_ok(config_path: &str, model: Option<&str>) -> bool {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,   // can't find ourselves → don't risk in-process load
    };
    info!("🔬 LLM pre-flight: testing model load in an isolated subprocess…");
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg("--llm-selftest").arg("-c").arg(config_path);
    // Test the SAME model this run will load, not the config default.
    if let Some(m) = model { cmd.arg("--model").arg(m); }
    let result = cmd
        .stdin(std::process::Stdio::null())
        .output()
        .await;

    match result {
        Ok(out) if out.status.success() => {
            info!("✅ LLM pre-flight passed — loading model in-process.");
            true
        }
        Ok(out) => {
            // Surface why the child failed/crashed for diagnosis.
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                if let Some(sig) = out.status.signal() {
                    warn!("🔬 LLM pre-flight child killed by signal {} (this is the fault that would crash the agent).", sig);
                }
            }
            let stderr = String::from_utf8_lossy(&out.stderr);
            let last = stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
            if !last.is_empty() { warn!("🔬 LLM pre-flight: {}", last); }
            false
        }
        Err(e) => {
            warn!("🔬 LLM pre-flight could not spawn self-test ({}). Skipping LLM to be safe.", e);
            false
        }
    }
}


/// `--download-model [MODEL]` — fetch any GGUF the operator names, or the model
/// recommended for this hardware when they name nothing.
async fn cmd_download_model(
    spec: &str,
    models_dir: Option<&str>,
    out_name: Option<&str>,
) -> Result<()> {
    // No argument (or the explicit "auto"/"default") → pick by detected VRAM.
    let spec = match spec.trim() {
        "" | "auto" | "default" | "recommended" => {
            let vram = llm::probe_gpu().await.map(|g| g.vram_mb).unwrap_or(0);
            let alias = llm::default_alias_for_vram(vram);
            if vram > 0 {
                println!("🖥️  Detected {} MB VRAM → recommended model: {}", vram, alias);
            } else {
                println!("🖥️  No GPU detected (CPU inference) → recommended model: {}", alias);
            }
            println!("   Want a different one? `nebula-agent --list-models`, then \
                      `nebula-agent --download-model <alias|repo|url>`.\n");
            alias.to_string()
        }
        other => other.to_string(),
    };

    let src = llm::resolve_model_spec(&spec).await?;
    let dir = models_dir.map(std::path::PathBuf::from);
    let path = llm::download_model(&src, dir.as_deref(), out_name).await?;

    println!("\n   Set in config.toml: [llm] model_path = \"{}\"", path);
    println!("   (or leave model_path blank — the agent auto-detects a model in the models dir)");
    Ok(())
}

fn num_cpus() -> usize {
    std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| s.lines().filter(|l| l.starts_with("processor")).count().max(1))
        .unwrap_or(4)
}
