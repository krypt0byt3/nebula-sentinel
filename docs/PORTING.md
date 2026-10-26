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

## To port (ranked)

1. **Windows hardening breadth** (the main gap). From `sentinel_v2/src`:
   - `response/mod.rs` — Windows process-tree kill (`taskkill /F /T`), Windows
     Firewall (`netsh advfirewall`), `is_protected_pid`, platform-aware
     quarantine/isolation/blocked-IP paths.
   - `network_monitor/mod.rs` — Windows DNS monitoring for DGA/fast-flux via
     `wevtutil` on `Microsoft-Windows-DNS-Client/Operational`.
   - `forensics/mod.rs` — Windows Event Log channel export via `wevtutil`,
     Windows fd-list and metadata-only memory snapshot.
   - `platform.rs` — `set_models_dir_override`, `set_active_config_path`,
     `active_config_path` runtime overrides.
   - `collector/windows_parse.rs` — Event Log XML parsing factored into a
     unit-testable module (new file; wire into `collector/windows.rs`).
   - ⚠️ Reconcile with nebula-agent's own in-flight Windows work
     (`docs/agent/08_windows.md`, `platform.rs`) before overwriting anything.

2. **ATC self-test harness** — `sentinel_v2/src/atc_selftest.rs` (636 LOC) +
   the `--atc-test` / `--atc-scenario` CLI. Clean, self-contained add; it is the
   harness that measures model discrimination against labelled scenarios.

3. **LLM prompt-robustness** — from `sentinel_v2/src/llm/mod.rs`:
   `AtcPromptVariant`, `verdict_from_prose`, tolerant `json_bool`,
   `collect_technique_ids` / `is_mitre_technique_id` (MITRE recovery from nested
   JSON), `raw_generate` + `--llm-inference-test`, `--list-models`. Port
   selectively and reconcile with this repo's engine-aware / Qwen3 selection
   logic — `llm/mod.rs` is the one real merge-conflict zone (both sides rewrote
   it heavily).

## Explicitly NOT porting

- The BitNet.cpp fork (`sentinel_v2/third_party/`, `csrc/`, `src/llm/bitnet.rs`,
  the `bitnet` feature, `nebula-bitnet-sidecar.sh`) — obsolete; stock llama.cpp
  covers ternary (`TQ1_0`/`TQ2_0`). See `docs/TERNARY_MODELS.md`.

## Unrelated known issue

Two pre-existing `baseline::features` tests fail (`encoded_blob_detected`,
`name_randomness_flags_hashlike`) — they predate the reorg and touch fleet-wide
baseline scoring, so they're left for deliberate review rather than a blind fix.
