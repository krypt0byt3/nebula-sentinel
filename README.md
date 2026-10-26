# NebulaSentinel

**Autonomous Threat Cognition (ATC) endpoint agent** — a self-contained, Rust
security sensor that detects, reasons about, and responds to host threats
locally, with an embedded LLM for on-device analysis and no external runtime.

This repository is a Cargo workspace with two crates:

| Crate | What it is |
|---|---|
| [`nebula-agent`](nebula-agent/) | The agent itself — collection, detection, response, forensics, and embedded LLM analysis. |
| [`nebula-gossip`](nebula-gossip/) | The shared **GOSSIP** wire protocol: the ecosystem envelope, ATC event types, dedup, and ed25519 signing. The single source of truth for the on-wire format. |

The agent reports to a central **Nexus** server over the authenticated GOSSIP/ATC
channel. The Nexus is maintained separately; this repository is the agent and the
shared protocol only.

## Highlights

- **Embedded LLM, no external dependency.** Inference runs in-process via
  `llama-cpp-2` (stock llama.cpp compiled into the binary). No Ollama, no Python,
  no server process. GGUF models are loaded from disk at runtime. Modern
  architectures (Qwen3, Phi-3.5, Gemma 2, Mistral) and **native ternary**
  (`TQ1_0`/`TQ2_0`) models are supported — see [`TERNARY_MODELS.md`](docs/TERNARY_MODELS.md).
- **Layered detection** — behavioral anomaly scoring mapped to MITRE ATT&CK,
  Sigma rules, pure-Rust YARA (`yara-x`, no system `libyara`), secrets scanning,
  baseline/feature drift, and host network self-protection (`netguard`).
- **Low-noise by design** — a suppression → dedup → confidence-gated pipeline,
  corroboration-damped anomaly scoring, placeholder/entropy-gated secret
  detection, and protected-address guards so automated response never severs a
  host's own internal network.
- **Portable builds** — a SIGILL-safe SSE baseline runs on virtually any x86-64
  host (including AVX-less VMs); opt into AVX2/CUDA/Metal where the hardware
  allows.

## Build

Requires a recent stable Rust toolchain. The default build compiles the embedded
llama.cpp and therefore needs a C++ toolchain (and CMake):

```bash
# Full default build (embedded LLM; needs a C++ toolchain)
cargo build --release --bin nebula-agent

# Lightweight build — no embedded LLM, no C++ toolchain required
cargo build --release --bin nebula-agent \
  --no-default-features --features "gossip,inventory,ebpf-stub"
```

Optional features: `yara` (pure-Rust YARA engine), `ebpf` (kernel syscall
monitoring via `aya`), `cuda` (NVIDIA GPU inference), `full-linux` (pcap + memory
forensics). See [`nebula-agent/BUILD.md`](nebula-agent/BUILD.md) and the build
matrix in [`docs/`](docs/) for the full matrix and GPU/SIMD notes.

## Documentation

Architecture, configuration, the GOSSIP protocol, model guidance, and per-feature
design notes live in [`docs/`](docs/).

## License

Licensed under the **GNU Affero General Public License v3.0 or later**
(AGPL-3.0-or-later). See [`LICENSE`](LICENSE). Running a modified version of this
agent as part of a network service obliges you to make your modified source
available to the users of that service.
