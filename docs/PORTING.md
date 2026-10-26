# Incremental port tracker — sentinel_v2 → nebula-agent

The consolidated agent is the **nebula-agent** line (promoted to v2.0.0). The old
`sentinel_v2` sibling was **not** carried over as a crate, because stock
llama.cpp now runs ternary models natively, making its 48 MB BitNet.cpp fork
obsolete (and `sentinel_v2`'s own ATC self-test scored those models 0%
specificity).

However, `sentinel_v2` carried genuinely-new capabilities that nebula-agent
lacked. They are **not lost** — the full `sentinel_v2` tree is preserved in the
archive repo under the git tag **`pre-reorg-snapshot`** (path `sentinel_v2/`).
This file tracks porting them in, deliberately, so the port doesn't collide with
in-flight Windows work already underway in nebula-agent.

## Status

### ✅ Done
- **ATC self-test harness** — `src/atc_selftest.rs` + `--atc-test` /
  `--atc-scenario` CLI. Drives real `ThreatEvent`s through
  `LLMEngine::analyze_threat` and scores completion / verdict accuracy / recall
  vs. specificity / latency. (The BitNet token-stats hook was dropped — stock
  llama.cpp doesn't expose it.)
- **Windows hardening breadth** — ported from sentinel_v2 (verified supersets,
  no body-vs-body collisions):
  - `response/mod.rs` — `taskkill /F /T` process-tree kill, `is_protected_pid`,
    platform-resolved quarantine/isolation/blocked-IP paths (hardcoded
    `/var/lib/nebula` → `platform::data_dir()`; non-Windows behavior preserved).
  - `forensics/mod.rs` — Windows twins for every collector (`wevtutil` Event Log
    export, `tasklist`/`netstat -ano`/`ipconfig` triage, metadata-only memory
    snapshot); `capture_pcap` now tshark → tcpdump (Unix) / pktmon (Windows).
  - `network_monitor/mod.rs` — Windows DNS via `wevtutil` on
    `Microsoft-Windows-DNS-Client/Operational` (+ `Get-DnsClientCache` fallback).
  - `platform.rs` — `set_models_dir_override` + `models_dir()` override, wired
    into `main`'s `--models-dir`.
  - ⚠️ The `#[cfg(windows)]` code is parsed and ported verbatim but was only
    **type-checked on the non-Windows paths here**. A Windows build must verify it.

- **LLM parse-robustness** (`src/llm/mod.rs`) — folded the output-salvage layer
  into `parse_threat_analysis` without disturbing the Qwen3 catalog / engine-aware
  selection: `json_prose` (flatten non-string fields), `verdict_from_prose`
  (leading-word verdict), tolerant `json_bool`, `collect_technique_ids` /
  `is_mitre_technique_id` (recover + validate MITRE IDs from nested JSON and
  `next_steps`), and a `has_gguf_magic` guard in `list_gguf_models`. +5 unit tests.

### ⏳ Remaining
- **LLM extras (deferred, optional)** — `AtcPromptVariant` (env-selectable prompt
  styles to A/B the 0%-specificity anchoring problem; inert unless
  `NEBULA_ATC_PROMPT` is set — deferred to avoid disturbing the current default
  prompt wording), and `raw_generate` + `--llm-inference-test` (a raw "does the
  backend emit text" check; `--atc-test` already covers the full path). Skipped by
  design: `is_ternary_model_name` / `REQUIRED_ENGINE` (would regress
  TQ-under-stock-llama.cpp support) and the `MAX_RESPONSE_TOKENS` cap (a
  bitnet-only fix).
- **`platform.rs` config-path overrides** — `set_active_config_path` /
  `active_config_path` (fixes a Windows in-place config-write bug). Deferred: only
  useful once the mode-change handlers (SetMode/ApplyPolicy) call
  `active_config_path()` instead of a hardcoded path — caller wiring in `main`
  and the handlers, out of scope of the file-level port.
- **`collector/windows_parse.rs`** — the unit-testable Event Log XML parser.
  Deferred with the `collector/windows.rs` rewiring (nebula-agent's `windows.rs`
  has its own inline parsing; swapping it for the testable module is the real win
  and is Windows-gated).

## Explicitly NOT porting

- The BitNet.cpp fork (`sentinel_v2/third_party/`, `csrc/`, `src/llm/bitnet.rs`,
  the `bitnet` feature, `nebula-bitnet-sidecar.sh`) — obsolete; stock llama.cpp
  covers ternary (`TQ1_0`/`TQ2_0`). See `docs/TERNARY_MODELS.md`.

## Unrelated known issue

Two pre-existing `baseline::features` tests fail (`encoded_blob_detected`,
`name_randomness_flags_hashlike`) — they predate the reorg and touch fleet-wide
baseline scoring, so they're left for deliberate review rather than a blind fix.
