# NebulaSentinel `nebula-agent` — Core & Configuration

> Scope: agent bootstrap, event loop, Nexus/ATC protocol, TLS pinning, config
> schema, platform paths, offline queue, scan-state, legacy syslog bridge, and
> the local status dashboard. Reflects the **current** source in
> `/nebulasentinel/nebula-agent/src`.

The agent is a single Tokio binary (`src/main.rs:96` `#[tokio::main]`). Product
self-description: "NebulaSentinel Agent v0.4 — Autonomous Threat Cognition (ATC)
endpoint agent" (`src/main.rs:1`). MITRE ATT&CK v15 + ATLAS aligned.

---

## 1. `src/main.rs` — Startup, Event Loop, Command Dispatch

### 1.1 Purpose
Wires every engine, spawns all background tasks, then runs the blocking event
loop that consumes collector events and fuses detections.

### 1.2 CLI arguments (`Args`, `src/main.rs:56-94`, `clap`)
| Flag | Field | Behavior |
|------|-------|----------|
| `-c, --config <PATH>` | `config` | Config path, default `/etc/nebula/config.toml` (`:60`). |
| `-m, --mode <detect\|protect\|audit>` | `mode` | Overrides config `mode` (`:64`, applied `:153`). Unknown → Detect. |
| `-v, --verbose` | `verbose` | Sets tracing filter to `debug` else `info` (`:101`). |
| `--download-model [MODEL]` | `download_model: Option<String>` | Downloads a GGUF into the models dir and exits (`:150`, impl `cmd_download_model` `:2134`). No value (clap `default_missing_value="auto"`) → the model recommended for the detected VRAM. Otherwise **any** of: catalog alias, HuggingFace repo (`owner/repo` — best quant auto-picked via the Hub API), repo + file (`owner/repo:Model-Q6_K.gguf` or `owner/repo/sub/dir/Model.gguf`), or a direct `http(s)://…` URL. Revision pinning with `owner/repo@rev:file`; `hf:` prefix accepted. `HF_TOKEN`/`HUGGINGFACE_TOKEN`/`HUGGING_FACE_HUB_TOKEN` → bearer auth for gated repos. |
| `--model <PATH\|NAME\|ALIAS>` | `model` (env `NEBULA_MODEL`) | Model to load for THIS run — overrides `[llm].model_path` without touching the config; nothing is written back. Resolved locally (never downloads) by `llm::resolve_model_reference`, which accepts a path to a `.gguf`, a **directory** of models (newest wins), a bare filename in the models dir (with or without `.gguf`), a catalog alias already downloaded, or a unique **fragment** of a filename (`--model qwen`). Resolved eagerly at startup so a typo warns immediately; an unresolvable value falls back to `[llm].model_path`/auto-detect rather than killing ATC. Also passed to the `--llm-selftest` pre-flight child so the pre-flight tests the same model. |
| `--list-models` | `list_models` | Prints the built-in catalog (`MODEL_CATALOG`) **and the GGUFs present locally** (size + path), then exits (impl `llm::print_model_catalog`). |
| `--models-dir <DIR>` | `models_dir` (env `NEBULA_MODELS_DIR`) | Directory models are downloaded into **and loaded from**; default `crate::platform::models_dir()`. Exported into the environment at startup so every lookup path (download, auto-detect, `--model` name resolution) and the pre-flight child agree on it. |
| `--download-from-nexus` | | Pulls the model FROM the Nexus (air-gapped) using `[nexus]` url/api_key/ca_cert_path/tls_verify, then exits (`:159`). |
| `--model-name <NAME>` | `model_name` | With `--download-from-nexus`: which model to request. With `--download-model`: the filename to save under (`:99`). |
| `--hardware-info` | | Prints GPU/CPU/VRAM + recommended model and exits (`:110`, impl `cmd_hardware_info` `:1826`). |
| `--llm-selftest` | | INTERNAL: loads the LLM in this throwaway process; prints `LLM_SELFTEST_OK`/exit 0 or `LLM_SELFTEST_FAIL`/exit 1 (`:116`). |

Early-exit commands are checked before the main config load, in the order:
hardware-info → llm-selftest → list-models → download-model → download-from-nexus.

### 1.3 Operating modes (`AgentMode`, `src/config.rs:72-88`)
`Detect` (default) — log/notify only. `Protect` — auto-remediation enabled
(kills, quarantine, isolation, NetGuard/firewall enforcement). `Audit` — like
detect. Display strings are upper-case (`DETECT`/`PROTECT`/`AUDIT`).
`is_protect_mode()` (`config.rs:754`) and `matches!(cfg.mode, Protect)` gate
every destructive path.

### 1.4 Startup sequence (present-tense, in order)
1. Parse args, init tracing, `print_banner()` (`:98-107`, banner `:1800`).
2. Handle early-exit commands (`:110-143`).
3. **Load config** (`:146`): tries `--config`, then `platform::default_config_path()`, then `./config.toml`, else panics (`:150`). Applies `--mode` override. Backfills `hostname` from `sysinfo`→`/etc/hostname`→`agent-<id8>` if empty (`:162`).
4. **Self-protection first** (`:177`): `SelfProtection::new(...).initialize()` — before anything else.
5. **Status UI**: builds `StatusServer`, seeds the snapshot (hostname, agent_id, platform, version, mode, nexus_url, `nexus_configured`, `collector_backend`, started_at, a static module list, FIM watched paths), then `tokio::spawn`s the server (127.0.0.1:7440). Live counters are refreshed separately (see §9).
6. **LLM engine with crash isolation** (`:219-238`): if `llm.enabled`, first runs `llm_preflight_ok()` (`:1889`) which spawns `self --llm-selftest` in a subprocess. Only if the child exits 0 does it load the model in-process; otherwise it builds a disabled engine and degrades to "Legacy" (detection continues, AI enrichment skipped). Signals (SIGILL/SIGABRT) that no Rust handler can catch are thus contained to the throwaway child.
7. **Engine construction** (`:241-399`): collector, anomaly, baseline (gated on `anomaly.ml_enabled`; spawns load + a 300s persist ticker `:261`), posture, forensics, inventory, gossip, hardening, rules, firewall/distro detect, response, netguard (+60s expiry sweeper), playbook (firewall + mode attached), ransomware, apt, dlp, zeroday, secrets, YARA scanner (compiled once from `rules.yara_dir`), reputation (given `virustotal_api_key` + YARA), retro hunter, container, iac, fim (inotify), network monitor, memory, legacy bridge.
8. **Rule hot-reload** (`:303-316`): if `rules.auto_reload`, spawns a ticker at `max(reload_interval_secs, 10)`s calling `rules_engine.load_all_rules()`.
9. **Gossip seeding** (`:281-296`): stores `llm_available`, `collector_backend`, and active `llm_model` (`remote:<model>` vs local path/`embedded`) into the gossip engine for the `atc.health` heartbeat.
10. **Nexus client** (`:402-416`): only if `nexus.enabled`. On success calls `register(hostname, mode, Some(gossip_pubkey))` (registration is awaited and may fail-soft). On construction error → standalone.
11. **Gossip start** (`:419`), **collector start** (`:422`).
12. Logs "All engines online. Entering event loop."

### 1.5 Background tasks — spawned BEFORE the blocking loop
The blocking main loop (`:1201`) drains collector events forever, so **every**
periodic/async task is spawned first (comment at `:935`). Spawn order:

- **Periodic Task 1 — Posture+Inventory+Hardening** (`:428-541`): first run staggered 30s, then every `posture.scan_interval_secs`. Syncs OVAL feed from Nexus, decides full vs delta scan via `scan_state` (first tick + `smart_scan` only), collects inventory, feeds `llm::HostContext`, runs hardening `assess()`, runs posture `run_full_assessment`, sends report to Nexus.
- **Event flush loop** (`:569-579`): every `max(event_flush_interval_secs, 5)`s calls `nexus.flush_events()`.
- **Poll/command loop** (`:581-906`): every **15s** (hard-coded). Sends heartbeat, then `poll_commands()`. Processes: gossip peer registration, malware-hash blocklist load, ransomware ext/note-name intel load, new-rule deploy (+ optional one-shot retro hunt if `retro.on_new_rule`), then per-command dispatch. `FetchArtifact`, `CaptureSample`, and `RunRetroHunt` are handled **inline here** (they need the Nexus client); all others go to `dispatch_nexus_command()`.
- **Main event bridge** (`:913-933`): spawns a task draining `collector.rx` (behind `Arc<Mutex<Receiver>>`) into a local `mpsc(4096)` channel so the loop can own a receiver without holding the mutex across awaits.
- Ransomware (`:942`), APT (`:961`), DLP (`:975`), FIM (`:989` — also runs on-access reputation scan of changed files), network-monitor (`:1021`) event loops → forward threats to Nexus.
- Periodic **secrets + zero-day** scan (`:1035`): 60s stagger, then hourly.
- **Container** assessment (`:1062`): 120s stagger, then every 600s.
- **IaC** scan (`:1087`): 180s stagger, then every 1800s; sends Critical/High findings.
- **Reputation** file scan (`:1112`): 90s stagger, then every 900s over `/tmp`, `/var/tmp`, `/dev/shm`, `/usr/local/bin`.
- **YARA memory scan** (`:1145`): 120s stagger, then every 1800s; enumerates `/proc` PIDs, scans process memory (fileless malware, T1055/T1620), emits Critical threats.

### 1.6 Main event loop (`:1201-1529`)
Per raw event, in order:
1. **Gossip IOC fast-path** (`:1207`): if dest IP known-bad → NetGuard evaluate + (Protect) `block_ip`; `continue`. Same for known-bad `file_hash` (`:1228`).
2. **Inbound brute-force** (`:1242`): failed `UserAuth`/`UserSu` events feed `netguard.record_failure(src_ip,...)` (src from `extra["src_ip"|"source_ip"|"rhost"]`).
3. Run **ransomware, APT, DLP, zero-day, anomaly, baseline** analyzers (`:1262-1280`).
4. **Merge/precedence** (`:1286`): ransomware > zero-day > DLP > APT > anomaly > baseline. A baseline hit coinciding with a primary detection **fuses** as corroboration (+10 confidence, annotation) rather than being dropped (`:1294`).
5. **Rule matching** (`:1310`): YARA/Sigma/Wazuh hits add matched rules and +10 confidence.
6. **Forensics (confidence-gated, tiered)** (`:1321`): entry gate = `min(light_confidence, min_confidence)`. If a destructive action is pending AND `capture_before_response`, capture synchronously first; else capture in background. Full memory dump decided internally at `full_confidence`.
7. **Immediate response** (`:1370`) → **playbook** (`:1373`) → **status UI record** as source "Legacy" (`:1389`) → **legacy syslog** forward (`:1408`) → **gossip IOC broadcast** for threats ≥65 confidence / IOCs ≥60 (`:1420`).
8. **Async ATC enrichment + forward** (`:1461-1527`): spawns a task that calls `llm.analyze_threat()`. **Threats are ALWAYS forwarded to Nexus regardless of LLM availability** — the LLM is enrichment, not a gate. If ATC judges benign it is DOWNGRADED to Info/≤20 confidence with an `[ATC-SUPPRESSED]` prefix (forwarded, not dropped). Suppression/enrichment upgrades the same status-UI row to source "ATC" (`:1483`). Auto-generated rules are submitted for approval (`:1508`).

### 1.7 Nexus command dispatch (`dispatch_nexus_command`, `:1540-1798`)
All 18 `NexusCommandType` variants (`types.rs:363-387`) are implemented:
`Ping`, `RunPostureScan`, `RunInventory`, `RunRetroHunt` (flagged; real work in
poll loop), `CollectForensics` (memory dump to `/var/lib/nebula/forensics/on_demand`),
`FetchArtifact`/`CaptureSample` (poll loop), `IsolateHost`/`UndoIsolation`,
`BlockIp`/`UnblockIp`, `KillProcess` (never pid ≤1), `QuarantineFile`, `SetMode`
(rewrites `mode=` line in `/etc/nebula/config.toml`, effective after restart),
`UpdateConfig` (persists `gossip_override.json`; applies gossip interval live),
`ApplyPolicy` (persists `/var/lib/nebula/policy.json`; applies `mode` live to
config file), `DeployRule` (rules normally arrive via poll `new_rules`).
Response commands delegate to `ResponseEngine`/firewall — no direct iptables.

### 1.8 Limitations
- Poll interval is hard-coded 15s; `report_interval_secs` is not used to drive it.
- `SetMode`/`ApplyPolicy` config edits are naive line replacements and take effect only after restart.
- YARA memory scan, reputation scan, secrets scan enumerate Linux `/proc` and fixed Unix paths (Linux-oriented).

---

## 2. `src/config.rs` — Configuration Schema

`AgentConfig::load()` (`:653`) reads TOML, then: assigns a **stable agent_id**
if empty (`:662`, priority: config → persisted `/var/lib/nebula/agent_id` →
`machine-id + hostname + primary MAC` md5 → random UUID; stale machine-id-only
IDs are regenerated `:690`), and applies a Nexus-pushed
`/var/lib/nebula/gossip_override.json` override (`:668`).

**Every section is optional** — each `default_*()` deserializes an empty TOML
table so a missing section falls back to per-field serde defaults (`:142-162`).

### 2.1 Top-level `AgentConfig` (`:3-54`)
| Key | Type | Default |
|-----|------|---------|
| `iac_paths` | `Option<Vec<String>>` | `None` |
| `virustotal_api_key` | `Option<String>` | `None` (VT disabled; local blocklist/YARA/entropy only — air-gap safe) **[recently added]** |
| `hostname` | String | system hostname → `/etc/hostname` → `unknown-host` |
| `agent_id` | String | `""` → stable-id logic |
| `platform` | String | detected: `linux`/`windows`/`macos` |
| `mode` | AgentMode | `Detect` |
| plus sections | — | `nexus, llm, collector, anomaly, rules, response, forensics, inventory, posture, hardening, retro, gossip, self_protect, memory, legacy, branding` |

### 2.2 `[nexus]` `NexusConfig` (`:91-134`)
| Key | Default |
|-----|---------|
| `enabled` | `true` |
| `url` | `https://127.0.0.1:9443` |
| `api_key` | `""` |
| `report_interval_secs` | `30` |
| `event_flush_interval_secs` | `30` |
| `buffer_events_locally` | `false` (immediate send; queue is automatic failover) |
| `tls_verify` | `true` |
| `ca_cert_path` | `None` |
| `atc_mode` | `true` |
| `legacy_syslog_enabled` | `false` |
| `legacy_syslog_host` | `""` |
| `legacy_syslog_port` | `514` |
| `legacy_syslog_proto` | `udp` |

### 2.3 `[llm]` `LLMConfig` (`:165-244`)
`enabled=true`, `mode=local`, `ollama_url=http://localhost:11434`,
`model_path=None`, `model=phi3:mini`, `fallback_model=phi3:mini`,
`confidence_threshold=70`, `max_context_tokens=4096`, `system_prompt`=Nebula
Whisper prompt, `compute_mode=auto`, `gpu_layers=-1`, `gpu_vram_mb=None`,
`gpu_model_override=None`. Remote ATC (NebulaCerebro) fallback tier:
`remote_atc=off` (`off`/`fallback`/`always`), `remote_url=None`,
`remote_api_key=None`, `remote_model=phi3:mini`, `remote_timeout_secs=20`.

### 2.4 `[collector]` `CollectorConfig`
`backend`=platform default (`ebpf` Linux / `wineventlog` Windows / `procmon`
macOS, via `platform::default_collector_backend`), `ebpf_programs=[execve,open,connect]`,
`etw_enabled=false`, `auditd_socket=/var/run/audispd_events`,
`buffer_size=65536`, `event_queue_depth=4096`.
- **`deduplicate_window_secs=60`** — alert-dedup window (**now live**; was parsed
  but unused, and the default was 5). Identical alerts (same threat + MITRE
  techniques + process) within this window are suppressed at the source and the
  alert re-emits afterward with a `recurred N×` note. Set `0` to disable.
- **`dedup_enabled=true`** — master switch for the dedup gate; `false` forwards
  every firing (pre-dedup behavior). See `src/dedup/mod.rs`.

### 2.4a `[detection]` `DetectionConfig` — suppression / allowlist
Operator-defined known-good rules applied at **detection time**, before dedup,
response, forensics, and Nexus forwarding (`src/suppression/mod.rs`). Each
`[[detection.suppress]]` entry matches when **every** specified field matches
(unspecified = wildcard; an all-empty rule is ignored):

| Field | Match |
|---|---|
| `process` | glob (`*`) on process name, case-insensitive |
| `path` | glob on process path |
| `technique` | exact MITRE id that must be present on the threat |
| `threat_name` | glob on the threat name |
| `action` | `drop` (discard) or `downgrade` (force `Info` + floor confidence); default `downgrade` |
| `reason` | free-text note surfaced in the alert/log |

Distinct from the response `isolation_allowlist` (which only guards destructive
actions) — this stops an alert being raised at all. Empty by default.

### 2.5 `[anomaly]` `AnomalyConfig`
`heuristic_enabled=true`, `ml_enabled=false`, `baseline_window_days=14`,
`chain_detection=true`, `chain_window_secs=300`, `confidence_threshold=60.0`,
`chain_patterns=[]` (each `ChainPattern`: name, tactics, techniques, min_confidence).

### 2.6 `[rules]` `RulesConfig` (`:315-333`)
`yara_dir=/etc/nebula/rules/yara`, `sigma_dir=/etc/nebula/rules/sigma`,
`wazuh_rules_dir=/etc/nebula/rules/wazuh`, `auto_reload=true`,
`reload_interval_secs=60`, `ai_rules_require_approval=true`.
**[`auto_reload`/`reload_interval_secs` recently wired** into the hot-reload
loop `main.rs:303`; previously parsed but unused.] Note: `suricata_rules_dir`/
`snort_rules_dir` appear in the sample TOML but are **not** fields of `RulesConfig`
(ignored on parse).

### 2.7 `[response]` `ResponseConfig` (`:336-353`)
`auto_kill_threshold=95.0`, `auto_quarantine_threshold=90.0`,
`auto_isolate_threshold=85.0`, `isolation_allowlist=[]`, `rollback_enabled=true`,
`snapshot_on_threat=true`.

### 2.8 `[forensics]` `ForensicsConfig` (`:356-437`)
`enabled=false`, `min_confidence=90.0`, `light_confidence=70.0`,
`full_confidence=90.0`, `capture_before_response=true`,
`output_dir=/var/lib/nebula/forensics`, `memory_dump=true`, `pcap_on_event=true`,
`pcap_duration_secs=60`, `pcap_filter="not port 53"`, `collect_logs=true`,
`log_paths=["/var/log"]`, `max_artifact_size_mb=512`, `encrypt_artifacts=true`,
`encryption_key_hex=None` **[recently added:** optional 64-hex (32-byte)
AES-256-GCM key; unset → weaker machine-id+bundle-id-derived key, still air-gap
functional]. `default_forensics()` builds explicitly from field defaults (`:419`).

### 2.9 `[inventory]` `InventoryConfig` (`:440-467`)
`enabled=true`, `scan_interval_secs=3600`, `hash_algorithm=sha256`,
`include_paths=[/usr/bin,/bin,/etc]`, `exclude_paths=[/proc,/sys,/dev]`,
`track_installed_pkgs/processes/network_conns/users/containers=true`.

### 2.10 `[posture]` `PostureConfig` (`:470-505`)
`oscal_enabled=true`, `oscal_catalog_path=None`, `cis_benchmark_path=None`,
`stig_content_path=None`, `nvd_feed_path=/var/lib/nebula/nvd/`,
`oval_feed_path=/var/lib/nebula/oval/`, `scan_interval_secs=3600`,
`smart_scan=true`, `full_scan_max_age_hours=24`, `dependency_scan_enabled=true`,
`compliance_frameworks=[nist_csf,cis_l2]`, `pkg_managers=[dpkg,rpm,cargo,pip]`.

### 2.11 `[hardening]` (`:508-526`)
`enabled=false`, `auto_apply=false`, `frameworks=[cis_l2,stig]`,
`report_path=/var/lib/nebula/hardening/`, `sshd_hardening/kernel_hardening/firewall_audit=true`.

### 2.12 `[retro]` `RetroConfig` (`:529-549`)
`enabled=false`, `on_new_rule=true`, `log_sources=[/var/log/auth.log,/var/log/syslog]`,
`evtx_paths=[]`, `max_lookback_days=90`, `parallel_threads=4`, `max_files_scanned=50000`.

### 2.13 `[gossip]` `GossipConfig` (`:552-586`)
`enabled=true`, `port=9999`, `bind_addr=0.0.0.0`, `discovery=nexus`,
`static_peers=[]`, `encryption=true`, `encryption_key=None`
**[recently added:** optional 64-hex (32-byte) PSK; AES-256-GCM applied only when
`encryption=true` AND key set — opt-in, all peers must share it; unset → plaintext
as before], `gossip_interval_secs=15`, `share_iocs=true`, `share_rules=false`,
`share_threat_scores=true`.

### 2.14 `[self_protect]` (`:589-612`)
`enabled=true`, `watchdog_interval_secs=30`, `integrity_check_interval_secs=60`,
`binary_hash_check/config_tamper_detection/adversarial_input_detection/model_poisoning_detection/prompt_injection_detection/anti_debug/protect_pid=true`.

### 2.15 `[memory]` (`:615-627`)
`enabled=false`, `volatility_path=None`, `lime_module_path=None`,
`dump_on_critical=true`, `scan_running_procs=true`.

### 2.16 `[legacy]` (`:630-639`)
`enabled=false`, `format=cef`, `target=""`.

### 2.17 `[branding]` (`:642-650`)
`company_name=NebulaSentinel`, `product_name=NebulaSentinel Agent`,
`tagline=Autonomous Threat Cognition`.

> **Config-vs-code gap:** the shipped `config.toml`/`nebula-agent.toml.example`
> include an `[offline_queue]` section (`enabled/db_path/max_size_mb/geo_annotate`)
> that is **not** a field of `AgentConfig` — it is parsed-and-ignored; the offline
> queue uses its own defaults (platform data dir, 500MB cap). The three
> recently-added keys (`virustotal_api_key`, `[forensics].encryption_key_hex`,
> `[gossip].encryption_key`) are **absent** from the sample files but honored if added.

---

## 3. `src/nexus_client.rs` — ATC / Nexus HTTP Protocol

### 3.1 Purpose
All agent→Nexus HTTP(S) communication, offline durability, and geo annotation.

### 3.2 Key types
- `NexusClient` (`:61`): holds `NexusConfig`, `agent_id`, reqwest `Client`, `Arc<OfflineQueue>`, `connected: Arc<Mutex<bool>>`, `current_location`.
- `AgentRegistration` (`:15`): agent_id, hostname, version, mode, platform (`NEBULA_TARGET_OS-ARCH` build env), kernel (`sysinfo::kernel_version`), ip_addresses, **`gossip_pubkey`** (ed25519 hex, skipped if None).
- `NexusResponse`/`NexusPoll` (`:36,461`): commands, new_rules, peers, malware_hashes `Vec<(sha256,desc)>`, ransom_extensions, ransom_note_names.
- `PeerEntry` (`:54`): agent_id, hostname, gossip_addr.

### 3.3 Endpoints (all POST via `post()` `:447` unless noted; auth header `X-Api-Key`)
| Method | Endpoint | Notes |
|--------|----------|-------|
| `register` (`:95`) | `POST /api/agents/register` | Now includes `gossip_pubkey`. Sets `connected` on success; fail-soft. |
| `send_threat` (`:118`) | `POST /api/atc/events` | Envelope `{agent_id,event_type:"threat",payload}`. Queue-first if `buffer_events_locally`; else send, queue on failure. |
| `send_posture` (`:151`) | `POST /api/atc/posture` | Same queue-first pattern. |
| `send_forensic_manifest` (`:176`) | `POST /api/atc/forensics/manifest` | Metadata only; bytes stay local. |
| `report_retro_hunt` (`:184`) | `POST /api/atc/retro/report` | Marks a one-shot hunt finished. |
| `report_progress` (`:203`) | `POST /api/atc/progress` | Generic percent+phase for long jobs; best-effort. |
| `upload_forensic_artifact` (`:217`) | `POST /api/atc/forensics/artifact` | base64 bytes; capped 64MB. |
| `upload_sample` (`:241`) | `POST /api/atc/gossip/sample` | Resolves path or SHA-256 (bounded walk of /tmp,/var/tmp,/dev/shm,/home ≤20000 files), 64MB cap. |
| `submit_rule_for_approval` (`:295`) | `POST /api/atc/rules/propose` | Queue-first capable. |
| `poll_commands` (`:326`) | `GET /api/atc/poll/{agent_id}` | Returns commands/rules/peers/intel. |
| `sync_oval_feed` (`:347`) | `GET /api/oval/feed/{feed}` | Writes `<feed>.json` into oval dir; validates JSON array; 0-count leaves local feed intact. |
| `heartbeat` (`:372`) | `POST /api/atc/heartbeat/{agent_id}` | On recovery from offline, drains the queue. |

### 3.4 Offline queue integration
`flush_events()`→`drain_queue()` (`:321,400`): spawns a task draining the
SQLite queue, routing by event_type to `/api/atc/events|posture|rules/propose`.
`heartbeat` flips `connected` and triggers a drain on reconnect. `is_connected()`
via non-blocking try_lock.

### 3.5 Helpers
`rule_from_json` (`:477`) maps Nexus rule JSON→`DetectionRule`.
`get_kernel_version` (`:502`), `detect_local_ips` (`:518`, sysinfo Networks,
skips loopback/link-local), `walkdir_bounded` (`:544`, symlink-skipping std walk).

### 3.6 TLS — `nexus_http_builder`
Constructed in `NexusClient::new` (`:76`) via `crate::tls::nexus_http_builder(ca_cert_path, tls_verify)`
+ 15s timeout + UA `NebulaSentinel-Agent/0.4.0`.

### 3.7 Limitations
- Upload/sample sizes capped at 64MB. `find_file_by_hash` bounded to fixed roots.
- No mTLS client-cert code path yet (sample TOML references it as future).

---

## 4. `src/tls.rs` — Shared Cert-Pinning Helper

`nexus_http_builder(ca_cert_path, tls_verify) -> ClientBuilder` (`:26`). One
policy for ALL agent HTTPS clients (gossip, model download, posture imports):
- **`ca_cert_path` set & valid PEM** → certificate **pinning**: adds it as the only root and disables built-in roots (`tls_built_in_root_certs(false)`, `:34`). Even a public-CA-signed attacker cert fails. Works with the Nexus self-signed cert.
- Invalid/unreadable PEM → warns, falls through to `tls_verify` behavior.
- **No pin, `tls_verify=false`** → `danger_accept_invalid_certs(true)` (explicit, logged, lab/dev only, `:48`).
- **No pin, `tls_verify=true`** (default) → standard system-trust; the self-signed Nexus is REJECTED until pinned or verify disabled (intentional).

---

## 5. `src/platform.rs` — OS Paths & Capabilities
Centralizes per-OS layout. `data_dir()`: Linux `/var/lib/nebula`, Windows
`%ProgramData%\NebulaSentinel`, macOS `/Library/Application Support/NebulaSentinel`.
`config_dir()`: `/etc/nebula` (non-Windows). `default_config_path()`,
`agent_id_path()` (`data_dir/agent_id`), `models_dir()`.
`default_collector_backend()`: `ebpf` (Linux) / `wineventlog` (Windows) /
`procmon` (macOS/other). `platform_label()`, `supports_ebpf()` (Linux-only).

---

## 6. `src/offline_queue/` — Persistent Event Buffer
SQLite (`queued_events`, WAL) at `data_dir()/offline_queue.db`, default cap
500MB, drain batch 50 (`:21-22`). `QueuedEvent`: id, event_type
(`threat|posture|rule_proposal`), payload, queued_at, retry_count, location.
`push` (`:69`) inserts and evicts the oldest 100 rows when over cap. `drain`
(`:110`) sends oldest-first via a caller closure; **on the first send failure it
stops immediately** (increments retry_count, leaves events in order) so it never
burns retries against a down Nexus. Eviction on cap is the only way an undelivered
event is dropped. Survives reboots; geo-annotates events with location captured
at enqueue time (roaming agents).

---

## 7. `src/scan_state/` — Redundant-Scan Avoidance
SQLite single-row table at `data_dir()/scan_state.db` storing last full-scan
timestamp + installed-package fingerprint + last scan kind. `ScanDecision::{Full,Delta}`.
`decide(fingerprint, max_age_hours)` (`:106`) → **Full** if no prior state, last
full scan ≥ max_age, or fingerprint changed; else **Delta** (skips the expensive
file-catalog walk). `fingerprint_packages` (`:136`) hashes sorted `name@version`
pairs. Used on the first periodic tick when `posture.smart_scan` is on
(`main.rs:480`). The `rusqlite::Connection` is non-Send, so it is only opened in
synchronous scopes that never span an await.

---

## 8. `src/legacy/` — Legacy Syslog Bridge
`LegacyBridge` (`:12`) formats every detection (main loop `:1408`) into SIEM
formats and transmits over UDP/TCP. Gated on `legacy.enabled`.
- Formats (`legacy.format`): `cef` (ArcSight, `:39`), `leef` (QRadar, `:67`), `syslog_rfc5424` (`:88`, also the fallback). Severity mapped to numeric per format.
- Transmit (`:109`): `udp://host:port` (bind ephemeral, send_to) or `tcp://host:port` (connect + newline-terminated). Unknown target → warn. (TLS listed in header comment but transmit handles udp/tcp only.)

---

## 9. `src/status_ui/` — Local Dashboard (127.0.0.1:7440)
Read-only Axum server bound **only** to loopback (`:124`), unreachable from the
network. Auto-refreshes every 15s; no external network dependency (air-gap safe).
- Routes (`:119`): `GET /` (HTML), `GET /api/status` (JSON), `GET /health`.
- `StatusSnapshot`: hostname, agent_id, platform, version, mode, posture_score, `nexus_configured`, nexus_connected/url/last_contact, `collector_backend`, active_threats, `recent_events` (ring buffer, `MAX_RECENT_EVENTS=200`), modules, firewall_backend, llm_status, rules/iocs_loaded, started_at, `fim_watched`.
- `StatusEvent`: timestamp, severity, threat_name, technique, confidence, **source** ("ATC" vs "Legacy"), description, atc_reasoning, tactics, techniques, matched_rules, iocs, suggested_action.
- `record_event` inserts newest-first; `attach_atc_reasoning` upgrades the matching row to source "ATC" once async LLM enrichment completes.
- UI: pure-CSS tabs (Events grouped by MITRE tactic via `<details>`, File Integrity, Posture, Modules) — no JS. Loads Google Fonts via external `<link>` (only external dependency; degrades gracefully offline).

### Standalone / offline mode
The dashboard shows a **three-state** Nexus indicator so a server-less or
disconnected agent reads as a normal operating state, not a failure:

| State | Meaning | Style |
|---|---|---|
| **Standalone** | no Nexus configured (`[nexus].enabled=false` or empty URL) — `nexus_configured=false` | blue, informational |
| **Connected** | configured Nexus reachable (last heartbeat succeeded) | green |
| **Offline** | configured Nexus currently unreachable | amber (not red) |

Standalone/Offline states render an explanatory banner reassuring that local
detection, rules, and forensics continue (and, offline, that events are queued
for sync on reconnect).

### Live telemetry refresher
A dedicated periodic task (**PERIODIC TASK 1b** in `main.rs`, every 10s) keeps the
snapshot's live counters current **independent of any Nexus**, so standalone
agents show real numbers instead of zeros: `rules_loaded` (`RulesEngine::rule_count`),
`iocs_loaded` (`GossipEngine::ioc_count`), `llm_status` (`is_available`), and
`nexus_connected`/`last_nexus_contact` (`NexusClient::is_connected`). `posture_score`
is refreshed by the posture task; `firewall_backend` and `collector_backend` are
set once at startup (both are probed/fixed). The Posture tab's left card is
titled **Local Detection** and lists collector, firewall, rules, IOCs, and LLM.
- `GET /api/status` adds a derived `nexus_state` (`standalone`/`connected`/`offline`) plus `nexus_configured`, `collector_backend`, and `last_nexus_contact`.

---

## 10. External Interactions (summary)
- **Nexus** over HTTPS (pinned/verified per §4): registration, ATC events/posture/forensics manifests, poll (commands, rules, peers, intel feeds), heartbeat, OVAL feed sync, artifact/sample upload, progress/retro reporting.
- **GOSSIP mesh** UDP :9999 (peer IOC sharing, ed25519-signed envelopes; optional PSK AES-256-GCM).
- **Ollama / remote NebulaCerebro** for LLM inference (optional).
- **HuggingFace** for `--download-model` (or Nexus for air-gapped model pull).
- **OS firewall** (via ResponseEngine/NetGuard), **inotify** (FIM), **/proc** (memory/zero-day/secrets scans), **package managers** (inventory/posture).
- Local files: `/var/lib/nebula/{agent_id, offline_queue.db, scan_state.db, forensics/, models/, policy.json, gossip_override.json}`.
