# NebulaSentinel Agent — Build Flags Reference

A guide to the Cargo feature flags for compiling `nebula-agent`, what each does,
and which combinations to use for common deployment targets. All flags are defined
in `nebula-agent/Cargo.toml`; this document summarizes them.

---

## Quick-pick: which build do I want?

| Target | Command |
|--------|---------|
| **QEMU / old CPU / max compatibility** | `cargo build --release --features cpu-portable,yara` |
| **Modern bare-metal (fast CPU inference)** | `cargo build --release --features cpu-avx2,yara` |
| **NVIDIA GPU box** | `cargo build --release --features cuda,yara` |
| **No local LLM (smallest, no C++ toolchain)** | `cargo build --release --no-default-features --features ebpf-stub,inventory,gossip,yara` |
| **Full Linux kernel-level features** | `cargo build --release --features full-linux,ebpf` |

> Always build `--release` for deployment. Debug builds are far slower and larger.

---

## The default build

```
default = ["ebpf-stub", "inventory", "gossip", "embedded-llm"]
```

Running `cargo build --release` with no `--features` gives you: the embedded
llama.cpp LLM (local inference, no external Ollama/server process), inventory
collection, GOSSIP intelligence sharing, and the eBPF stub (procmon fallback).
This is the recommended, self-contained configuration — **but** it compiles
llama.cpp for the *build host's* CPU, which can cause "Illegal instruction"
(SIGILL) crashes if you then run the binary on a less-capable CPU (e.g. a QEMU
VM). For that reason, prefer explicitly choosing a CPU baseline (below).

---

## CPU inference baseline (pick exactly one for a CPU agent)

These control which CPU instruction set llama.cpp is compiled against. They exist
to solve the SIGILL problem: they make `build.rs` target a **known baseline**
instead of the build machine's native CPU.

### `cpu-portable`
- **Baseline:** SSE2 / SSE4.2 — no AVX, AVX2, FMA, or BMI required.
- **Outcome:** Runs on virtually **any** x86-64, including the conservative
  "QEMU Virtual CPU version 2.5+" model that lacks AVX. **Slowest, most compatible.**
- **Use for:** VMs, older hardware, mixed/unknown fleets where compatibility matters
  more than speed.

### `cpu-avx2`
- **Baseline:** AVX2 + FMA.
- **Outcome:** ~2–4× faster CPU inference — **but SIGILLs on any CPU/VM without
  AVX2.**
- **Use for:** modern bare-metal only, where you know every host has AVX2.

Both imply `embedded-llm`.

---

## GPU acceleration

### `cuda`
- **What:** Enables the llama-cpp-2 CUDA backend so the embedded model runs on an
  NVIDIA GPU. Implies `embedded-llm`.
- **Build host needs:** CUDA toolkit + `nvcc` on PATH, `CUDA_PATH`/`CUDA_HOME` set.
- **Runtime host needs:** NVIDIA driver + `libcudart`/`libcublas`.
- **Verify:** the build prints **"NVIDIA CUDA backend ENABLED"**. If you instead
  see "CPU build", the feature didn't take. Keep `compute_mode="auto"` and
  `gpu_layers=-1` in `config.toml`.
- **Command:** `cargo build --release --features cuda`

> ROCm (AMD) and Metal (macOS) are controlled at build time via environment
> variables rather than a Cargo feature:
> - **ROCm:** `LLAMA_HIPBLAS=1 cargo build --release --features embedded-llm`
> - **Metal:** automatic on macOS (no flag needed)
> - **CUDA (alt):** `LLAMA_CUDA=1 cargo build --release --features embedded-llm`

---

## Detection / capability features

### `embedded-llm`
- Compiles llama.cpp **into** the agent for local, in-process inference (the ATC
  analyst). Requires a **C++ toolchain** on the build host. ON by default.
- To build **without** it (no local LLM, no C++ toolchain needed):
  `--no-default-features --features ebpf-stub,inventory,gossip`

### `yara`
- Real YARA scanning via the **pure-Rust `yara-x`** engine — **no external C
  library** (libyara) required. Recommended for any build that does memory/file
  scanning.
- **Command:** `cargo build --release --features yara`

### `ebpf`
- **Real** kernel-level syscall monitoring via `aya` (pure-Rust BPF loader).
  Compiles `src/collector/ebpf.rs`.
- **Runtime needs:** the compiled CO-RE object `bpf/nebula.bpf.o` present, Linux
  **5.8+** with BTF, and `CAP_BPF`/root.
- Without it, the agent still builds and the "ebpf" backend cleanly **falls back to
  procmon** (5-second `/proc` polling) at runtime.
- **Command:** `cargo build --release --features ebpf,yara`

### `ebpf-stub`
- The no-op counterpart to `ebpf` (part of `default`). Provides the eBPF backend
  interface without the real kernel loader — the agent uses procmon polling.

### `inventory`
- Software/package/network inventory collection (Windows + Linux). Part of `default`.

### `gossip`
- The GOSSIP peer-to-peer threat-intelligence sharing layer. Part of `default`.

### `full-linux`
- Bundles optional kernel-level extras: `nix`, `pnet`, `pcap`, `memmap2`, `yara`.
- **Requires `libpcap-dev`** on the build host (for the `pcap` dependency).
- **Command:** `cargo build --release --features full-linux,ebpf`

---

## Windows builds

Windows agents are CPU-based (no eBPF; kernel features are Linux-only). A typical
Windows build:

```
cargo build --release --target x86_64-pc-windows-msvc --features cpu-portable,yara
```

Use `cpu-portable` unless you're certain the target Windows hosts have AVX2, in
which case `cpu-avx2` is faster. eBPF/pcap features are ignored/unavailable on
Windows; the agent uses its Windows-native collectors (Event Log, `netstat`,
`Get-HotFix`, ReadDirectoryChangesW, etc.).

---

## Important warnings

- **Never build deployment binaries with `--all-features`.** It force-enables the
  CUDA backend and pulls in `libpcap`, producing a binary that **fails to start** on
  any host without the CUDA runtime and libpcap installed.
- **Match the CPU baseline to the *least* capable host** in a fleet. If any target
  is a plain VM, use `cpu-portable` — a `cpu-avx2` binary will SIGILL there.
- **`--release` always** for anything you deploy.

---

## Common combinations at a glance

```bash
# Maximum compatibility (VMs, old CPUs, unknown fleet) — CPU LLM + YARA
cargo build --release --features cpu-portable,yara

# Fast modern CPU (known AVX2 everywhere) — CPU LLM + YARA
cargo build --release --features cpu-avx2,yara

# NVIDIA GPU host — GPU LLM + YARA
cargo build --release --features cuda,yara

# Full Linux kernel-level detection — real eBPF + pcap + YARA
cargo build --release --features full-linux,ebpf

# No local LLM at all (smallest binary, no C++ toolchain required)
cargo build --release --no-default-features --features ebpf-stub,inventory,gossip,yara

# Windows, portable CPU baseline
cargo build --release --target x86_64-pc-windows-msvc --features cpu-portable,yara
```
