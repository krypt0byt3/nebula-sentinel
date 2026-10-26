# Building Nebula Sentinel

This guide covers building the **agent** (`nebula-agent`) and the **server**
(`nexus-server`). If you only want to protect a single host, you only need the
agent — see [RUNNING.md](RUNNING.md) for standalone mode.

---

## Prerequisites

- **Rust** (stable, recent). Install via [rustup](https://rustup.rs).
- **A C++ toolchain** — required for the default build, because the embedded
  local model compiles `llama.cpp` from source.
  - Linux: `build-essential`, `cmake`, `clang` (clang ≥ 18 recommended)
  - macOS: Xcode command-line tools (`xcode-select --install`)
  - Windows: MSVC build tools + CMake
- **(Optional) GPU toolkit** if you want GPU-accelerated inference — CUDA (NVIDIA),
  ROCm (AMD), or Metal (automatic on macOS).

> **No C++ toolchain?** You can build the agent *without* the embedded model (no
> local ATC) — see "Building without a local model" below.

---

## Quick build (agent, CPU, self-contained)

The default build embeds `llama.cpp` for local inference and targets your build
host's CPU:

```bash
cd nebula-agent
cargo build --release
```

The binary lands at `target/release/nebula-agent`.

> ⚠️ **Important for VMs and mixed hardware — read the CPU baseline section
> below.** A default build targets the *build machine's* CPU. If you run that
> binary on a less-capable CPU (e.g. a conservative QEMU VM), it will crash with
> `Illegal instruction (SIGILL)`. This is the single most common build gotcha.

---

## CPU instruction baseline (avoiding SIGILL)

`llama.cpp` compiles for a CPU instruction set. By default it targets the build
host, which crashes if the *run* host is less capable. Two Cargo features pin a
known baseline instead:

| Feature | Baseline | Use when |
|---------|----------|----------|
| `cpu-portable` | SSE2 / SSE4.2 | Runs on virtually any x86-64, including conservative QEMU VMs with no AVX. **Slowest, most compatible.** Use for VMs and unknown targets. |
| `cpu-avx2` | AVX2 + FMA | ~2–4× faster CPU inference, but **SIGILLs on any CPU/VM without AVX2.** Use on modern bare-metal only. |

Example — a maximally-compatible build for running inside a VM:

```bash
cargo build --release --features cpu-portable,yara
```

If you see `Illegal instruction (core dumped)` at runtime, rebuild with
`cpu-portable`. You can confirm the mismatch first with `--llm-selftest` (see
[RUNNING.md](RUNNING.md)).

---

## GPU-accelerated inference

GPU backend is selected by **environment variables at build time** (not Cargo
features), with the default embedded-llm build:

```bash
# NVIDIA CUDA
LLAMA_CUDA=1 cargo build --release --features embedded-llm

# AMD ROCm
LLAMA_HIPBLAS=1 cargo build --release --features embedded-llm

# Apple Metal — automatic on macOS, no env var needed
cargo build --release

# CPU only — the default, no env var needed
cargo build --release
```

> On battery-powered laptops, expect significant power draw from sustained local
> inference (see the performance notes in the README). GPU is generally more
> stable than CPU under load; both are demanding on battery.

---

## Feature flags reference

The default feature set is: `ebpf-stub`, `inventory`, `gossip`, `embedded-llm`.

| Feature | What it does |
|---------|--------------|
| `embedded-llm` | Compiles `llama.cpp` into the agent for local inference (**default**, needs C++ toolchain). |
| `gossip` | Peer-to-peer intelligence sharing (GOSSIP). |
| `inventory` | Host inventory/posture collection. |
| `ebpf-stub` | eBPF collection stub. |
| `yara` | YARA scanning engine (recommended). |
| `cpu-portable` | Pin CPU baseline to SSE2/SSE4.2 (see above). |
| `cpu-avx2` | Pin CPU baseline to AVX2/FMA (see above). |

### Building without a local model (no C++ toolchain)

If you can't (or don't want to) compile `llama.cpp`, build without embedded
inference. The agent still detects, records events, and forwards — it just has no
local ATC enrichment (it runs at ATC-0/legacy, or can use a remote model if
configured):

```bash
cargo build --release --no-default-features --features ebpf-stub,inventory,gossip
```

---

## Building the server (Nexus) — optional

Only needed for fleet mode. A single host does not need Nexus.

```bash
cd nexus-server
cargo build --release --features yara
```

---

## Recommended builds by target

| Target | Command |
|--------|---------|
| Modern bare-metal workstation/server (CPU) | `cargo build --release --features cpu-avx2,yara` |
| VM / unknown / mixed fleet (CPU) | `cargo build --release --features cpu-portable,yara` |
| NVIDIA GPU host | `LLAMA_CUDA=1 cargo build --release --features embedded-llm,yara` |
| macOS (Apple Silicon) | `cargo build --release --features yara` |
| No C++ toolchain (no local ATC) | `cargo build --release --no-default-features --features ebpf-stub,inventory,gossip` |

---

## Verifying the build

After building, confirm the local inference path works on the target host before
relying on it:

```bash
./target/release/nebula-agent --hardware-info   # what the agent detects about the host
./target/release/nebula-agent --llm-selftest    # confirms local inference runs (catches SIGILL)
```

If `--llm-selftest` reports `Illegal instruction`, rebuild with `cpu-portable`
(see the CPU baseline section). If it reports GPU layers as expected and completes
a generation, the local ATC path is working.
