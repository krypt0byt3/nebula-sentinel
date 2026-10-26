# NebulaSentinel Agent — Embedded LLM & GOSSIP Mesh

Current-state technical manual for the `nebula-agent` embedded LLM engine (`src/llm/`)
and the GOSSIP inter-agent mesh (`src/gossip/`). Documents present behavior as read
from source at `/nebulasentinel/nebula-agent`.

Source of record:
- `src/llm/mod.rs`
- `src/gossip/mod.rs`
- `src/gossip/envelope_bridge.rs`
- `src/config.rs` (`LLMConfig` @ line 166, `GossipConfig` @ line 553)
- `src/main.rs` (wiring)
- `MODELS.md`, `Cargo.toml`
- `../nebula-gossip/src/signing.rs` (canonical envelope + signing crate)

---

## Module 1 — Embedded LLM ("Nebula Whisper" / ATC)

### Purpose

Runs a local Large Language Model **in-process** to enrich threat detections with
reasoning: a true/false-positive verdict, a confidence adjustment, a plain-language
assessment (with benign explanation and next steps), MITRE technique refinement, and
optional auto-generated detection rules. The LLM is strictly an **enrichment layer, not
a gate** — threats are always detected and forwarded to the Nexus even when the LLM is
absent or judges the event benign (`src/main.rs:1453-1460`).

The engine is branded internally as "Nebula Whisper"; the enriched analysis path is
called **ATC** (as opposed to **Legacy** = raw detector output with no LLM).

### Capabilities

**Backends** (`InferenceBackend` enum, `src/llm/mod.rs:391`):
1. `Embedded(EmbeddedBackend)` — in-process llama.cpp via the `llama-cpp-2` crate
   (v0.1), gated on the `embedded-llm` Cargo feature (in the default feature set).
   Loads GGUF models directly into process memory — no Ollama, no Python, no server
   process, no network socket. `backend_name()` = `"embedded-llama.cpp"`.
2. `Remote(RemoteBackend)` — "NebulaCerebro" remote ATC; speaks the OpenAI
   `/v1/chat/completions` shape (compatible with Nexus Whisper, a dedicated
   NebulaCerebro node, vLLM, Ollama, llama.cpp-server). `backend_name()` =
   `"remote-nebulacerebro"`.
3. `Unavailable` — no backend; enrichment disabled, detection continues (Legacy).

**Compute backends (compile-time):** CUDA (NVIDIA), ROCm/HIPBLAS (AMD), Metal (Apple),
Vulkan; and **CPU (the default)**. GPU backends must be enabled on the `llama-cpp-2`
dependency at build time (e.g. the `cuda` feature).

### Running ATC on CPU (the default) — build & provisioning

CPU inference is the out-of-the-box configuration and needs **no GPU and no special
flags** — but it does need two things that are the usual reasons "ATC won't run":

1. **The `embedded-llm` feature must be compiled in.** It is in the **default** feature
   set, so `cargo build --release` includes it (needs a C++ toolchain: `cc`/`g++`/`cmake`).
   The light build `--no-default-features --features ebpf-stub,inventory,gossip` used for
   quick compile-checks **omits it** — such a binary has no inference at all and now logs a
   loud "ATC local inference is NOT compiled into this binary" warning at startup.
2. **A GGUF model must be present** in `<models_dir>` (default `/var/lib/nebula/models/`).
   Provide one with `nebula-agent --download-from-nexus` (air-gapped) or
   `--download-model [alias|owner/repo|owner/repo:file.gguf|url]` (internet — any GGUF).
   Missing model → the agent logs "ATC model file not found" and continues in Legacy.

**SIMD baseline / "Illegal instruction" (SIGILL):** the CPU baseline is chosen by
`llama-cpp-sys-2` from Rust's target features, **not** by a Cargo feature or `build.rs`.
The default x86-64 target compiles a **portable SSE2 build** (`GGML_NATIVE=OFF`) that runs
on any x86-64 including AVX-less QEMU VMs — so a default `cargo build --release` is already
SIGILL-safe. For a faster (non-portable) AVX2 binary on modern bare-metal:
`RUSTFLAGS="-C target-feature=+avx2,+fma,+f16c" cargo build --release` (SIGILLs on non-AVX2
CPUs). The `cpu-portable`/`cpu-avx2`/`legacy_cpu`/`modern_cpu` Cargo features are now just
`embedded-llm` aliases — they do **not** by themselves change the SIMD baseline (an older
`build.rs` tried to via `env::set_var`, but that ran after the llama.cpp compile and was a
no-op; it has been removed).

**CPU compute mode:** with `compute_mode="auto"` (default) and no GPU, `n_gpu_layers`
resolves to `0` (all layers on CPU); threads = physical core count. Set `compute_mode="cpu"`
to force CPU even when a GPU is present — this also makes model auto-selection pick the
light **Phi-3.5-mini** model (the one `--download-model` fetches with no argument) instead
of a GPU-tier model, so it won't try to load a 7B model onto the CPU.

**GPU probe (`probe_gpu`, runtime, `src/llm/mod.rs:58`):** shells out to `nvidia-smi`
(name/VRAM/driver), then `rocm-smi` (VRAM), then on macOS `system_profiler` (Apple
Silicon; VRAM estimated as half of total RAM). Used for logging and VRAM-based model
auto-selection. `GpuVendor`: Nvidia / Amd / Apple / Vulkan / None.

**Which GGUF gets loaded.** `EmbeddedBackend::load` resolves the model in this order:

1. **What was asked for** — `--model <PATH|NAME|ALIAS>` / `NEBULA_MODEL` (which override
   `[llm].model_path` for the run) or `[llm].model_path` itself. A **blank/whitespace**
   value counts as unset, so an empty key in a config template means auto-detect rather
   than "load the file named `''`".
2. **Auto-detection** — the model recommended for the detected VRAM if that file exists,
   else `find_local_model()`: the most recently written `.gguf` in the models dir. So a
   model pulled with `--download-model <anything>` is used without editing any config.
3. Only when the models dir holds no GGUF at all does the load fail — with a hint listing
   every way to provide one. Detection continues in Legacy mode.

An operator-supplied model is resolved by `resolve_model_reference` (local only — it never
downloads), which accepts every reasonable way of naming a model:

| Form | Example |
|---|---|
| Absolute or relative path | `/srv/models/my-model.gguf` |
| Directory of models | `/srv/models` → newest GGUF inside |
| Bare filename in the models dir | `Qwen2.5-7B-Instruct-Q4_K_M.gguf` |
| …without the extension | `Qwen2.5-7B-Instruct-Q4_K_M` |
| Catalog alias already downloaded | `qwen2.5-7b` |
| Unique fragment of a filename | `qwen`, `14b` |

Ambiguous fragments and unknown names are refused with the list of what IS available; the
loader then falls back to auto-detection rather than dropping ATC entirely, logging the
substitution at WARN.

**VRAM-based recommendation (`recommended_model_file_for_vram` / `select_model_path_for_vram`)**
— the filename comes from `MODEL_CATALOG`, so the recommendation and what `--download-model`
fetches cannot drift apart, and it is joined to the **platform models dir** (so it is
correct on Windows/macOS, and honours `--models-dir` / `NEBULA_MODELS_DIR`):

| VRAM budget (MB) | Recommended model (under `<models_dir>/`) |
|---|---|
| 0–4999 (CPU / low VRAM, or `compute_mode="cpu"`) | `Phi-3.5-mini-instruct-Q4_K_M.gguf` |
| 5000+ (GPU) | `Qwen2.5-7B-Instruct-Q4_K_M.gguf` |

`list_gguf_models()` backs both auto-detection and `--list-models`: it scans the models dir
plus **one level of subdirectories**, newest first, skipping empty files and the trailing
pieces of split models (`…-00002-of-00005.gguf` — llama.cpp opens those through the first
shard).

**Recommended models (`MODELS.md`):**
- **Phi-3.5-mini-instruct Q4_K_M** (~2.4 GB, 3.8B) — default for CPU / low-VRAM; best
  structured-JSON output and MITRE classification at its size.
- **Qwen2.5-7B-Instruct Q4_K_M** (~4.7 GB, needs ~5 GB VRAM) — best open-weight 7B for
  structured output / security reasoning. Preferred over Mistral 7B and Llama 3.x
  (worse structured-JSON instruction following per MODELS.md).
- Performance reference (from MODELS.md): Phi-3.5 ~7–12 s on CPU; Qwen2.5-7B ~0.7–2 s
  on RTX 4090/3060; Metal ~2.5–4 s on M2 Pro. Analysis runs async — threats are
  forwarded immediately, analysis follows.

**Model download — `--download-model [MODEL]` fetches ANY GGUF:**
- `cmd_download_model()` (`src/main.rs:2134`). With no argument (clap
  `default_missing_value="auto"`, also `default`/`recommended`) it probes the GPU and uses
  `default_alias_for_vram()` — `phi3.5-mini` (≤4999 MB VRAM) or `qwen2.5-7b` (else).
- `resolve_model_spec(spec)` (`src/llm/mod.rs:248`) turns the argument into a `ModelSource`
  `{url, filename, size_gb, origin}`:
  | Form | Example | Resolution |
  |---|---|---|
  | catalog alias | `qwen2.5-14b` | `MODEL_CATALOG` (`:183`), 7 curated entries — offline |
  | HF repo | `bartowski/Qwen2.5-14B-Instruct-GGUF` | `pick_gguf_from_repo()` (`:346`) lists `siblings` via `GET /api/models/{repo}/revision/{rev}`, skips split shards, picks by `QUANT_PREFERENCE` (Q4_K_M→Q4_K_S→Q5_K_M→Q5_K_S→Q6_K→Q8_0→Q4_0→Q3_K_M) |
  | repo + file | `owner/repo:Model-Q6_K.gguf` or `owner/repo/sub/Model.gguf` | direct `resolve/{rev}/` URL — offline |
  | direct URL | `https://host/model.gguf` | used as-is; filename from the path |
  Optional `hf:` prefix; `@rev` pins a branch/tag/SHA/`refs/pr/N` (slash-escaped for the API).
  Unknown alias → error listing the accepted forms.
- `download_model(src, dest_dir, out_name)` (`src/llm/mod.rs:401`) — streams to
  `<name>.part` with a live progress bar/ETA (never buffers the body in RAM),
  **resumes** via HTTP `Range` when a `.part` is present (falls back to a restart if the
  server ignores it), keeps the `.part` on a short read so the next run resumes, verifies
  the **GGUF magic** before install (`verify_gguf_magic` `:510` — rejects HTML error pages
  and LFS pointers), then renames into place. Skips work if the target already exists.
  30 s connect / 6 h total timeout. `--models-dir` overrides the destination,
  `--model-name` the filename. `HF_TOKEN`/`HUGGINGFACE_TOKEN`/`HUGGING_FACE_HUB_TOKEN` is
  sent as bearer auth to `huggingface.co` (gated/private repos); 401/403 and 404 responses
  carry targeted hints.
- `--list-models` → `print_model_catalog()` (`src/llm/mod.rs:551`); `download_agent_model(vram_mb)`
  (`:544`) = resolve default alias + download.
- `--download-from-nexus` → `download_model_from_nexus()` for air-gapped
  fleets: lists models from `GET {nexus}/api/atc/models`, downloads
  `GET {nexus}/api/atc/models/{name}` with `X-Api-Key`, supports **HTTP Range resume**
  from a `.part` file, and verifies the Nexus-reported **SHA-256** (discards on
  mismatch). 7200 s timeout; uses the shared Nexus TLS builder (`crate::tls`).

  **Engine-aware selection.** bitnet.cpp and upstream llama.cpp cannot load each
  other's weights — a `--features bitnet` build needs ternary I2_S/TL1/TL2 files
  and a default build cannot open them at all. The agent therefore requests
  `GET /api/atc/models?engine={bitnet|llama.cpp}` (`llm::REQUIRED_ENGINE`, a
  compile-time constant) and the Nexus returns only what this build can load.
  An older Nexus that ignores the parameter is detected by the absence of
  `filtered_engine` in the response, and the agent filters client-side using
  each entry's `engine` field, falling back to the filename convention
  (`is_ternary_model_name`) when that field is absent too.

  `--model-name` selects a specific model, but only among those this engine can
  load: naming an incompatible model fails immediately with the list of
  compatible ones, rather than downloading gigabytes that fail at load. With no
  name, the first compatible model is taken. When nothing is compatible the
  error says which engine this build needs, instead of the previous generic
  "Nexus has no models to distribute".

**Inference parameters (`LlamaInferenceParams`, embedded, line 597):** temperature 0.2
(low, for consistent analysis), top_p 0.9, repeat_penalty 1.1, `n_ctx` =
`max_context_tokens` (min 512). Sampler chain: penalties(64) → top_p → temp → dist(1234)
(line 677). Threads = physical core count on CPU, half on GPU. `n_gpu_layers` resolved
from `compute_mode` + `gpu_layers` (line 572): `cpu`→0, `gpu`→require GPU (−1=all if
`gpu_layers==0`), `auto`→GPU if present else CPU. −1 maps to 999 offload layers.

**Prompt framing:** ChatML (`<|system|>…<|end|><|user|>…<|end|><|assistant|>`, line
642), understood by Phi-3 / Qwen / most instruct models. A fresh llama context is
created per `generate()` call (contexts are cheap vs. the shared model weights). Manual
token decode via `token_to_bytes` + `from_utf8_lossy`; stops on EOG or on chat
terminators (`<|end|>`, `<|endoftext|>`, `<|user|>`).

**Fused-evidence threat prompt (`analyze_threat`, line 1052):** does NOT merely restate
the alert. It fuses the correlated attack chain (stages in time order with `+Ns` deltas,
capped at 15), all IOCs (type/source/confidence, capped at 20), matched rules, raw-event
count, and a **host-context** block. Requests strict JSON:
`is_true_positive`, `confidence_adjustment` (clamped ±30), `assessment`,
`benign_explanation`, `next_steps`, `refined_techniques[]`, and optional
`generate_rule` / `rule_type` (yara|sigma|wazuh) / `rule_name` / `rule_content` /
`rule_reasoning`.

**JSON verdict parsing (`parse_threat_analysis`, line 1192):** tolerant three-stage
parse — (1) strict `serde_json` after stripping markdown fences; (2) fall back to
`extract_json_object()` (brace-depth-balanced, string/escape-aware extraction of the
first `{…}`); (3) last resort, keep the raw text (first 400 chars) as a prose
assessment marked suspicious=true rather than dropping enrichment. Assessment +
benign_explanation + next_steps are composed into the single `explanation` string;
legacy `explanation` key still honored.

**Host context (`HostContext`, line 745):** grounds reasoning in what the host *is*
(role, internet-facing, listening ports, key services). Inferred from an inventory
snapshot via `HostContext::from_inventory()` (well-known-port heuristics → sshd / web /
database / DNS / LDAP-Kerberos / SMB / mail / RDP; role classification; internet-facing
if 80/443/25/53/3389/21 listen). Wired in `src/main.rs:509-512`: rebuilt each inventory
rescan and pushed via `set_host_context()` into the Arc'd engine (`StdRwLock`).

**Verdict-memory cache (`PriorVerdict`, line 796):** bounded, TTL'd cache of prior ATC
conclusions keyed on the detection's **shape** (`verdict_key` = `hostname | sorted
techniques | process`, line 986). TTL = 6 h (`VERDICT_TTL_SECS`), max 512 entries
(`VERDICT_CACHE_MAX`, oldest evicted when full). On a fresh cache hit, ATC takes a
**fast path** (`recall_verdict` + `reinforce_verdict`): returns the cached verdict,
bumps a recurrence counter, and **skips inference entirely** (saves battery/edge cost,
avoids re-running a model that might now return unparseable output). Only the full LLM
path produces new verdicts, so novelty still gets full analysis. Every parsed verdict is
stored via `remember_verdict()`.

**Other LLM entry points:**
- `chat(user_message, context)` (line 1289) — Nebula Whisper conversational interface.
- `analyze_log_batch(logs, rule_name)` (line 1301) — retro-hunt log analysis → JSON array.
- `recommend_hardening(findings)` (line 1316) — CIS/STIG fix suggestions → JSON array.
- `detect_adversarial_input(input)` (line 1329) — **ATLAS AML.T0043 prompt-injection
  guard**: blocks ~19 known jailbreak/override phrases ("ignore previous instructions",
  "jailbreak", "developer mode", "system prompt:", …) before the message reaches the
  model. Applied on the `chat()` path.

**Remote ATC cascade (`LLMEngine::new`, line 904):** local-first with configurable
remote fallback, controlled by `remote_atc`:
1. `remote_atc == "always"` → try remote first (thin-agent mode).
2. Otherwise try the local embedded model.
3. If local unavailable and `remote_atc == "fallback"` → try remote.
4. If nothing loads → `Unavailable` (Legacy continues; detection never blocked).

`RemoteBackend::connect` (line 444) normalizes the base URL to
`…/v1/chat/completions`, builds a client with `remote_timeout_secs` (min 5), and does a
lightweight reachability probe at startup ("Reply with: OK") so an unreachable remote
degrades to Legacy at boot rather than failing every analysis. Requests use
temperature 0.2, `stream:false`, optional `Authorization: Bearer` from `remote_api_key`.

**`--llm-selftest` crash isolation (`src/main.rs:88-93, 116-128, 1885`):** the llama.cpp
/ CUDA layer can hard-fault with an uncatchable process signal (SIGILL on unsupported
CPU instructions, SIGABRT on CUDA/driver mismatch, SIGSEGV) during model load. To
guarantee the agent runs "either way", the main process **pre-flights the load in a
throwaway subprocess** (`llm_preflight_ok`, line 1889): it re-execs itself with
`--llm-selftest -c <config>`, which loads the model and prints `LLM_SELFTEST_OK` / exits
0 on success. If the child dies from a signal or non-zero exit, the parent logs the
signal/stderr and degrades to Legacy **without ever attempting the fatal in-process
load** (`src/main.rs:220-234`). Operators can run `--llm-selftest` directly to diagnose.

### Key types

- `LLMEngine` — the engine (`config`, `backend`, `gpu_info`, interior-mutable
  `host_ctx` + `verdicts`). Methods: `new`, `analyze_threat`, `chat`,
  `analyze_log_batch`, `recommend_hardening`, `set_host_context`, `is_available`,
  `is_gpu_active`, `backend_name`, `gpu_info`, `detect_adversarial_input`.
- `InferenceBackend` (enum), `EmbeddedBackend`, `RemoteBackend`, `EmbeddedInner`.
- `LLMAnalysis` — result: `suspicious`, `confidence_adjustment`, `explanation`,
  `mitre_refinement`, `generated_rule: Option<DetectionRule>`.
- `HostContext`, `PriorVerdict`, `GpuInfo`, `GpuVendor`, `LlamaInferenceParams`.

### Entry points + main.rs wiring

- CLI flags: `--download-model` `src/main.rs:73`; `--download-from-nexus`
  `src/main.rs:78`; `--model-name` `src/main.rs:82`; `--hardware-info`
  `src/main.rs:86`; `--llm-selftest` `src/main.rs:93`.
- `--llm-selftest` handler `src/main.rs:116`; `--download-model` `src/main.rs:129`;
  `--download-from-nexus` `src/main.rs:132`.
- Crash-isolated engine init `src/main.rs:219-234`; `llm_preflight_ok`
  `src/main.rs:1889`; `cmd_download_model` `src/main.rs:1930`.
- Host-context feed on inventory rescan `src/main.rs:509-512`.
- Async ATC enrichment spawn `src/main.rs:1461-1483` (`analyze_threat` @ 1469);
  detections forwarded to Nexus regardless (comment @ 1453).

### Config keys — `[llm]` (`LLMConfig`, `src/config.rs:166`)

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Enable LLM enrichment. |
| `mode` | `"local"` | Legacy mode string. |
| `ollama_url` | `http://localhost:11434` | Legacy Ollama URL (embedded backend is default). |
| `model_path` | *(none)* | Model to load: path, directory, filename, catalog alias or filename fragment (see resolution table above). Blank or unset → auto-selected by VRAM. Overridden per-run by `--model` / `NEBULA_MODEL`. |
| `model` | `"phi3:mini"` | Model name label. |
| `fallback_model` | `"phi3:mini"` | Fallback label. |
| `confidence_threshold` | `70` | Confidence threshold. |
| `max_context_tokens` | `4096` | Context window / max tokens (min 512 for `n_ctx`). |
| `system_prompt` | *(Nebula Whisper analyst prompt)* | System prompt. |
| `compute_mode` | `"auto"` | `auto` \| `gpu` (require GPU) \| `cpu` (force CPU). |
| `gpu_layers` | `-1` | GPU layers to offload; 0=CPU, −1=all, N=N layers. |
| `gpu_vram_mb` | *(none)* | Override probed VRAM budget for model selection. |
| `gpu_model_override` | *(none)* | Optional stronger model when GPU present. |
| `remote_atc` | `"off"` | `off` \| `fallback` \| `always` (remote ATC cascade). |
| `remote_url` | *(none)* | OpenAI-compatible `/v1/chat/completions` base URL. |
| `remote_api_key` | *(none)* | Bearer token for remote endpoint. |
| `remote_model` | `"phi3:mini"` | Server-side model id to request. |
| `remote_timeout_secs` | `20` | Per-request remote timeout (min 5); on timeout → Legacy. |

### External interactions

- **HuggingFace** (`bartowski` / `microsoft` GGUF repos) for internet model download.
- **Nexus** `GET /api/atc/models[?engine=…]` and `/api/atc/models/{name}`
  (X-Api-Key) for air-gapped model distribution, with SHA-256 verification and
  engine-aware filtering.
- **Nexus** `POST /api/agents/register` additionally reports `llm_engine`
  (`bitnet` | `llama.cpp` | `remote` | `none`, from `LLMEngine::engine_kind()`)
  and `llm_backend`, so the Nexus can show which weights each host needs and
  warn when an engine in the fleet has no model published.
- **Remote ATC** OpenAI-compatible `POST /v1/chat/completions` (Bearer auth).
- **GPU tooling**: `nvidia-smi`, `rocm-smi`, `system_profiler` (probe).
- **Filesystem**: `/var/lib/nebula/models/`, `/proc/cpuinfo`, `/proc/meminfo`.

### Limitations

- GGUF model is **not** embedded in the binary — must be downloaded/placed separately.
- GPU backend is a **compile-time** choice on `llama-cpp-2`; a CPU-built binary won't
  use the GPU regardless of `compute_mode`. (CPU is the default and needs no flags — see
  "Running ATC on CPU" above.)
- `token_to_bytes` / `Special::Tokenize` are deprecated in `llama-cpp-2` (used
  deliberately; partial UTF-8 tokens tolerated via lossy decode → transient replacement
  chars possible).
- Prompt-injection guard is applied on the `chat()` path (not on `analyze_threat`
  evidence, which is machine-assembled telemetry).
- Fast-path recall can return a stale verdict for up to 6 h if a benign-looking shape
  later turns malicious with identical technique+process+host signature.
- Remote model download from HuggingFace verifies only Content-Length, not a hash
  (Nexus path verifies SHA-256).

---

## Module 2 — GOSSIP mesh (`src/gossip/`)

"GOSSIP = Generative Observable Security Sharing Intelligence Protocol"
(logged at `src/gossip/mod.rs:168`).

### Purpose

A UDP peer-to-peer mesh for inter-agent threat awareness: agents exchange **heartbeats**
(liveness/peer-sighting), **IOC alerts** (shared threat intel), and **threat scores**.
It also carries the canonical `nebula_gossip::Envelope` control-plane path to the Nexus
(signed `atc.health` heartbeats and signed `ioc.alert` envelopes) that populate the
Nexus "Ecosystem" view. Peer sightings let the Nexus distinguish an agent that is
*network-alive but Nexus-unreachable* (stale) from one that is *truly offline*.

### Capabilities

**Two message planes:**
1. **Legacy UDP `GossipMessage`** (JSON over UDP, `src/types::GossipMessage`) —
   agent↔agent. Types (`GossipMsgType`): `Heartbeat`, `IocAlert`, `ThreatScore`.
   Broadcast to known peers on the configured port.
2. **Canonical `nebula_gossip::Envelope`** (ecosystem wire format) — agent→Nexus over
   HTTPS `POST {nexus}/api/atc/gossip/envelope`. Built by `envelope_bridge.rs`:
   `health_envelope` (`atc.health`, TTL 120 s — *silence is the alert*),
   `ioc_to_envelope` (`ioc.alert`, TTL 86 400 s), `threat_to_envelope` (`atc.alert`,
   TTL 2 592 000 s). Reverse: `envelope_to_ioc` recovers an IOC from a received
   `ioc.alert`.

**Envelope SIGNING (ed25519) — current security feature:**
- A **persistent ed25519 keypair** is loaded or created at startup
  (`load_or_create_keypair`, `src/gossip/mod.rs:86`). Stored hex-encoded (32-byte
  secret) at **`/var/lib/nebula/gossip_ed25519.key`**, created with **mode 0600** on
  Unix. `key_id` = **`agent_id`**. If the file can't be persisted, an ephemeral key is
  used for the run (warns).
- **Every outgoing envelope is signed** via `nebula_gossip::signing::sign(&mut env,
  &keypair)` at **both** send sites:
  - health heartbeat → `src/gossip/mod.rs:342`
  - IOC envelope → `src/gossip/mod.rs:480`
- The agent's **public key is registered with the Nexus** so it can verify signatures:
  `GossipEngine::public_key_hex()` (`src/gossip/mod.rs:208`, hex of `public_bytes()`) is
  passed into `NexusClient::register(hostname, mode, Some(pubkey))`
  (`src/main.rs:405`), sent as `gossip_pubkey` in the registration body
  (`src/nexus_client.rs:95-106`).
- Signing crate: `nebula_gossip::signing::{Keypair, sign, verify}`
  (`../nebula-gossip/src/signing.rs`): `Keypair::generate` / `from_secret_bytes`,
  `public_bytes() -> [u8;32]`, `public_b64()` (used only in the startup log line).

**UDP encryption (AES-256-GCM) — optional PSK:**
- Enabled only when `[gossip].encryption == true` **AND** a valid 64-hex-char (32-byte)
  `encryption_key` is set (`resolve_gossip_key`, line 115). If `encryption` is true but
  the key is missing/invalid, the agent **warns and sends PLAINTEXT** (line 172).
- `gossip_seal` (line 127): `ring` AES-256-GCM → wire = `nonce(12) || ciphertext ||
  tag(16)`, random nonce per datagram. `gossip_open` (line 143): decrypts; returns
  `None` on truncation / wrong key / tamper, so the receiver silently drops the packet.
- Encryption is applied to both the heartbeat broadcast and the `broadcast_ioc` path;
  the receive loop decrypts first when a key is set (line 243). All peers must share the
  same PSK. (Note: this encrypts the peer-to-peer UDP plane; the Nexus HTTPS envelope
  plane is protected by TLS, and envelopes are separately ed25519-signed.)

**Heartbeat + peer sighting (`start`, line 212):** spawns a receive loop and a broadcast
loop.
- *Receive loop* (line 232): decrypts (if PSK), parses `GossipMessage`, updates the
  local peer table (`handle_gossip_local`), and — only for new/stale peers (>60 s since
  last seen, line 530) — reports the sighting to Nexus
  `POST /api/atc/gossip/peer_seen` (`GossipPeerReport`, X-Api-Key). IocAlert messages
  add the IOC to the local `ioc_blacklist`; ThreatScore updates the peer's score.
- *Broadcast loop* (line 307): sleeps `interval_secs` (live-adjustable), sends a
  `Heartbeat` `GossipMessage` to every known peer, then emits a **signed `atc.health`
  envelope** to the Nexus reflecting cognition state (`healthy`/`degraded`,
  `llm_available`, `llm_model`, `collector_backend`); logs delivery/rejection so an
  empty Ecosystem tab is diagnosable.

**IOC broadcast (`broadcast_ioc`, line 373):** gated on `enabled` + `share_iocs`.
- **Validation (`is_valid_ioc`, line 420):** rejects empty/>2048-char values, private/
  loopback/link-local/broadcast/documentation/unspecified/0.x IPs, `localhost`,
  `.local`/`.internal`/`.lan`/`.arpa` domains, hashes of implausible length (not
  32/40/64 hex) and all-zero hashes. Front line against false-positive flooding.
- **Dedup:** an IOC is re-broadcast at most once per **`REBROADCAST_TTL_SECS` = 3600 s**
  (`broadcast_cache`, line 384) — fixes the "sends same IOCs over and over" behavior.
- Broadcasts the `IocAlert` (sealed if PSK) to all peers, then calls
  `report_ioc_to_nexus` (line 451): (1) legacy direct report
  `POST /api/atc/gossip/ioc` (X-Api-Key) for the fleet IOC list, and (2) a **signed
  `ioc.alert` envelope** `POST /api/atc/gossip/envelope` (Bearer) for the Ecosystem
  stream.
- Caller gating (`src/main.rs:1416-1429`): only threats with confidence ≥ 65 and
  per-IOC confidence ≥ 60 are broadcast.

**Live interval control:** `interval_secs` is an `AtomicU64` read each broadcast tick;
`set_interval()` (line 201) lets the Nexus change GOSSIP frequency without restart.
A Nexus config push (`gossip_override.json`) is applied via `set_interval` on receipt
(`src/main.rs:1746`) and re-read at startup (`src/config.rs:668`).

**Cognition state for health envelopes (seeded in `src/main.rs:281-296`):**
`llm_available: AtomicBool`, `collector_backend: Mutex<String>` (default `"procmon"`,
set to configured backend), `llm_model: Mutex<Option<String>>` (from
`LLMEngine::active_model()`: the filename of the GGUF **actually** loaded — after
`--model` resolution and auto-detection — `remote:<model>` for a borrowed brain, else
`"embedded"`). Surfaces silently-degraded
(LLM-down / procmon-fallback) agents to the Nexus via `cognition.mode` = `atc`/`legacy`.

### Key types

- `GossipEngine` (line 44) — the engine (config, agent_id, hostname, `peers`
  DashMap, `ioc_blacklist` DashMap, Nexus URL/key/TLS policy, `enc_key: Option<[u8;32]>`,
  `keypair: Arc<Keypair>`, `interval_secs`, `broadcast_cache`, cognition fields).
- `PeerInfo` (line 24) — agent_id, hostname, addr, last_seen, threat_score.
- `GossipPeerReport` (line 34) — sighting payload to Nexus.
- Free fns: `load_or_create_keypair`, `resolve_gossip_key`, `gossip_seal`,
  `gossip_open`, `handle_gossip_local`.
- `envelope_bridge`: `ioc_to_envelope`, `threat_to_envelope`, `health_envelope`,
  `envelope_to_ioc`, `ioc_type_str`, `sev`, `origin`. Canonical types from
  `nebula_gossip`: `Envelope`, `MsgType`, `Origin`, `Severity`, and payloads
  `IocPayload` / `AtcPayload` / `AtcCognition` / `AtcDetector` / `AtcEntity`.

### Entry points + main.rs wiring

- `mod gossip` declared `src/main.rs:19`.
- Engine construction `src/main.rs:273-277` (`GossipEngine::new` with cfg, agent_id,
  hostname, Nexus URL/key, CA path, TLS-verify).
- Cognition seed `src/main.rs:281-296`.
- Public key → registration `src/main.rs:405` (`NexusClient::register(..., Some(
  gossip_engine.public_key_hex()))`; sent as `gossip_pubkey`,
  `src/nexus_client.rs:95`).
- `gossip_engine.start()` `src/main.rs:419`.
- Peer registration from Nexus roster `src/main.rs:591` (`register_peer`).
- IOC known-checks `src/main.rs:1209, 1229` (`is_ioc_known`).
- IOC broadcast on detection `src/main.rs:1426` (`broadcast_ioc`).
- Live interval override on Nexus config push `src/main.rs:1746` (`set_interval`).

### Config keys — `[gossip]` (`GossipConfig`, `src/config.rs:553`)

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Enable the GOSSIP mesh. |
| `port` | `9999` | UDP listen port. |
| `bind_addr` | `"0.0.0.0"` | UDP bind address. |
| `discovery` | `"nexus"` | Peer discovery source. |
| `static_peers` | `[]` | Static peer list. |
| `encryption` | `false` | Enable AES-256-GCM UDP encryption (also needs a valid `encryption_key`). |
| `encryption_key` | *(none)* | 64-hex-char (32-byte) PSK; without it → PLAINTEXT. |
| `gossip_interval_secs` | `15` | Heartbeat/broadcast interval (live-adjustable, min 1). |
| `share_iocs` | `true` | Broadcast discovered IOCs to peers/Nexus. |
| `share_rules` | `false` | Share detection rules. |
| `share_threat_scores` | `true` | Share threat scores. |

Note: `encryption` defaults to `false`. To encrypt the mesh, set `encryption = true`
**and** a shared `encryption_key` on every peer; `true` without a key runs **plaintext**
(warns at startup) — the key is what turns encryption on.

### External interactions

- **Peers**: UDP datagrams on `port` (JSON `GossipMessage`, optionally AES-256-GCM
  sealed).
- **Nexus (HTTPS, via shared TLS builder `crate::tls::nexus_http_builder`)**:
  - `POST /api/atc/gossip/peer_seen` — peer sighting (X-Api-Key).
  - `POST /api/atc/gossip/ioc` — legacy direct IOC report (X-Api-Key).
  - `POST /api/atc/gossip/envelope` — signed `atc.health` and `ioc.alert` envelopes
    (Bearer auth).
  - `POST /api/agents/register` — carries `gossip_pubkey` for signature verification.
- **Filesystem**: `/var/lib/nebula/gossip_ed25519.key` (0600),
  `/var/lib/nebula/gossip_override.json`.
- **Crates**: `nebula_gossip` (envelopes + ed25519 signing), `ring` (AES-256-GCM),
  `dashmap`, `hex`.

### Limitations

- UDP encryption is symmetric PSK only (all peers share one key); no per-peer keys, no
  key rotation mechanism in-agent.
- The peer-to-peer UDP `GossipMessage` plane is **not ed25519-signed** — signing applies
  to the canonical Nexus envelopes; UDP integrity/authenticity rely on the optional
  AES-256-GCM PSK (GCM tag). Without a key, UDP is unauthenticated plaintext.
- `broadcast_ioc` opens a fresh ephemeral UDP socket per call (not the listen socket).
- Peers are only broadcast to once known; discovery relies on the Nexus roster
  (`register_peer`) / heartbeats — no autonomous LAN multicast discovery here.
- Received `ioc.alert` envelopes are convertible back to IOCs (`envelope_to_ioc`), but
  the inbound UDP path parses only the legacy `GossipMessage` shape.
