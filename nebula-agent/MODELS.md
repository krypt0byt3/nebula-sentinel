# NebulaSentinel Agent — Model Guide

The agent uses embedded llama.cpp (via the `llama_cpp` Rust crate).
The model loads directly into the agent's process memory at startup.
No separate server process. No network socket.

## Downloading a model — `--download-model`

`--download-model` fetches **any** GGUF, not just the two we recommend:

```bash
nebula-agent --download-model                     # the model recommended for this box (VRAM-detected)
nebula-agent --list-models                        # the built-in aliases below
nebula-agent --download-model qwen2.5-14b         # a catalog alias
nebula-agent --download-model bartowski/Qwen2.5-14B-Instruct-GGUF          # any HF repo — best quant auto-picked
nebula-agent --download-model bartowski/Qwen2.5-7B-Instruct-GGUF:Qwen2.5-7B-Instruct-Q6_K.gguf   # exact quant
nebula-agent --download-model https://internal.mirror/models/custom.gguf   # any direct URL
nebula-agent --download-from-nexus                # air-gapped: whatever your Nexus serves
```

Modifiers:

| Flag / env | Effect |
|---|---|
| `--model-name <FILE>` | Save under a different filename. |
| `--models-dir <DIR>` | Use a models dir other than `/var/lib/nebula/models` — for downloads **and** loading (same as `NEBULA_MODELS_DIR`). |
| `owner/repo@<rev>:file.gguf` | Pin a branch, tag, commit or `refs/pr/N`. |
| `HF_TOKEN=<token>` | Access gated or private HuggingFace repos. |

Behaviour worth knowing: downloads stream to `<name>.gguf.part` with a live
progress bar and **resume** on re-run (HTTP Range), the GGUF magic is verified
before the file is installed (an error page or LFS pointer is rejected instead
of blowing up later inside llama.cpp), and when only a repo is given the quant
is chosen in the order Q4_K_M → Q4_K_S → Q5_K_M → Q5_K_S → Q6_K → Q8_0 →
Q4_0 → Q3_K_M. Split/sharded GGUFs are skipped by auto-pick — name one
explicitly if you really want it.

Point `[llm] model_path` at the file, or leave it blank: the agent loads the
model recommended for its VRAM if present, otherwise the most recently
downloaded GGUF in the models dir — so whatever you pulled just works.

## Choosing a model at run time — `--model`

`--model` overrides `[llm] model_path` for that run only; nothing is written back
to the config. Handy for A/B-ing models on a box, or for running an agent against
a model kept outside the models dir.

```bash
nebula-agent --model /srv/models/Qwen2.5-14B-Instruct-Q4_K_M.gguf   # any GGUF, anywhere
nebula-agent --model /srv/models                                    # a directory — newest GGUF in it
nebula-agent --model Qwen2.5-7B-Instruct-Q4_K_M.gguf                # a filename in the models dir
nebula-agent --model Qwen2.5-7B-Instruct-Q4_K_M                     # …extension optional
nebula-agent --model qwen2.5-7b                                     # a catalog alias you already downloaded
nebula-agent --model qwen                                           # a unique fragment of a filename
NEBULA_MODEL=qwen2.5-14b nebula-agent                               # same thing via the environment
nebula-agent --models-dir /srv/models --model qwen                  # look somewhere else entirely
```

`nebula-agent --list-models` and `--hardware-info` both print the GGUFs available
locally (size + path), so you can see exactly what `--model` can name.

Resolution is **local only** — `--model` never downloads (that's `--download-model`).
Rules worth knowing:

- An ambiguous fragment (`--model q4_k_m` when two models match) or an unknown name
  is refused with a list of what IS available.
- A model that can't be resolved does **not** kill ATC: the agent logs the failure
  at WARN and falls back to auto-detection, so the sensor keeps its brain.
- The same value is passed to the crash-isolated pre-flight (`--llm-selftest`), so
  the pre-flight tests the model the run will actually load.
- Split GGUFs (`…-00002-of-00005.gguf`) are never auto-picked — name the first shard.

### Built-in aliases

| Alias | Size | Notes |
|---|---|---|
| `qwen3-1.7b` | 1.1 GB | smallest usable — very low RAM / edge sensors |
| `qwen3-4b` | 2.5 GB | **default** for CPU / <5 GB VRAM — strong structured output + tool-calling |
| `qwen3-8b` | 5.0 GB | **default** for 5+ GB VRAM — best all-round security reasoning |
| `qwen3-14b` | 9.0 GB | high-end GPU (10+ GB VRAM) — best analysis quality |
| `phi3.5-mini` | 2.4 GB | alternative 3.8B — compact, solid structured JSON on CPU |
| `qwen2.5-7b` | 4.7 GB | previous default — proven 7B, kept as a stable fallback |
| `mistral-7b` | 4.4 GB | alternative 7B — permissive Apache-2.0 licence |
| `gemma2-9b` | 5.8 GB | alternative 9B — needs ~7 GB VRAM |

For **ternary (1.58-bit)** ATC models — including TQ2_0 Bonsai/Qwen3 conversions
that run on the stock engine — see [`TERNARY_MODELS.md`](../TERNARY_MODELS.md).

## Recommended models

### CPU / low-VRAM (default)

**Qwen3-4B Q4_K_M** — ~2.5 GB
Strong structured-JSON output and MITRE ATT&CK classification at 4B, with native
tool-calling (which the Nexus agentic / Whisper flow uses). On a very low-RAM
box, drop to `qwen3-1.7b`, or use `phi3.5-mini` for the smallest solid
structured-output model.

```bash
nebula-agent --download-model            # auto-picks by detected VRAM
nebula-agent --download-model qwen3-4b   # or by name
```

### GPU with 5+ GB VRAM

**Qwen3-8B Q4_K_M** — ~5.0 GB (needs ~5–6 GB VRAM)
Best all-round open-weight model this size for structured output, security
reasoning, rule synthesis and tool-calling. 10+ GB VRAM → `qwen3-14b`.

```bash
nebula-agent --download-model qwen3-8b
```

## Why Qwen3 (not Qwen2.5 / Llama 3.x / Mistral)?

Qwen3 supersedes Qwen2.5 on the axes that matter here — structured output,
classification and **native tool-calling** — and tool-calling directly
strengthens the Nexus agentic/Whisper actions. Qwen2.5-7B is kept as a proven
fallback (`qwen2.5-7b`). Llama 3.x and Mistral 7B remain available as
alternatives but trail on structured-JSON instruction following at equivalent
sizes, which is what a JSON-only security agent depends on.

## Performance reference

| Hardware               | Model             | Analysis time |
|------------------------|-------------------|---------------|
| 8-core Intel i7        | Phi-3.5-mini Q4   | ~12s (CPU)    |
| AMD EPYC 16-core       | Phi-3.5-mini Q4   | ~7s  (CPU)    |
| RTX 3060 12GB          | Qwen2.5-7B Q4     | ~2s  (GPU)    |
| RTX 4090               | Qwen2.5-7B Q4     | ~0.7s (GPU)   |
| Apple M2 Pro 16GB      | Phi-3.5-mini Q4   | ~2.5s (Metal) |
| Apple M2 Pro 16GB      | Qwen2.5-7B Q4     | ~4s  (Metal)  |

LLM analysis runs async — threats are forwarded immediately, analysis follows.
