# Building the Nebula Agent

The agent embeds llama.cpp directly (via `llama-cpp-2`) — there is **no separate
llama.cpp or llama-server to install**. The inference engine is compiled into the
agent binary.

## Recommended build (portable, runs on any host)

```sh
cargo build --release --features yara
```

This produces a **CPU-only, statically self-contained** binary. llama.cpp is
compiled in with CPU SIMD (AVX2/AVX-512 auto-detected). The only runtime
dependency is glibc — it will start on any comparable Linux host with no extra
packages.

## ⚠ Do NOT build deployment binaries with `--all-features`

`--all-features` turns on **everything**, which causes two runtime problems:

1. It enables the `llama-cpp-2` **CUDA** backend. The resulting binary
   dynamically links `libcudart` / `libcublas` and requires an NVIDIA driver.
   On a host without the CUDA runtime, the binary **fails to start** — which
   looks like "llama.cpp isn't installed" but is really a missing shared
   library (`libcudart.so.NN: cannot open shared object file`).
2. It pulls in `pcap`, which dynamically links `libpcap.so`. Hosts without
   `libpcap` installed get the same kind of load failure.

Use explicit features instead (`--features yara`, plus `full-linux` only on
hosts where you've installed `libpcap-dev`).

## GPU acceleration (advanced, opt-in)

Only do this if the **target** hosts have the matching GPU runtime installed.

- **NVIDIA CUDA** — build host needs the CUDA toolkit; every run host needs the
  CUDA runtime + driver:
  ```sh
  cargo build --release --features yara \
    --config 'dependencies.llama-cpp-2.features=["cuda"]'
  ```
- **Apple Metal** — automatic on macOS, no runtime install needed.
- **AMD ROCm / Vulkan** — enable the corresponding `llama-cpp-2` feature; run
  hosts need the ROCm runtime or Vulkan loader respectively.

A GPU binary is **not portable** to hosts lacking that runtime. For a mixed
fleet, ship the CPU build everywhere and a GPU build only to GPU hosts.

## Runtime: providing a model

The GGUF model is **not** in the binary. Place one at the configured path
(`[llm] model_path`; blank = the model recommended for the detected VRAM, else
any GGUF found in `/var/lib/nebula/models/`) or fetch one:

```sh
nebula-agent --download-from-nexus   # air-gapped: pulls from your Nexus
nebula-agent --download-model        # internet: the model recommended for this hardware
nebula-agent --list-models           # built-in aliases
nebula-agent --download-model qwen2.5-14b                        # any catalog alias
nebula-agent --download-model bartowski/Qwen2.5-14B-Instruct-GGUF  # any HF repo (best quant picked)
nebula-agent --download-model https://host/path/model.gguf         # any direct URL
```

See MODELS.md for the exact-quant / pinned-revision / gated-repo (`HF_TOKEN`)
forms, `--model-name` and `--models-dir`.

If no model is present the agent still runs — threat events are detected and
forwarded; only the AI summaries are skipped.

## "Illegal instruction" / SIGILL — especially when the LLM runs

If the agent starts but crashes with `Illegal instruction` (syslog:
`trap invalid opcode ... in nebula-agent`), the binary contains CPU SIMD
instructions the run host doesn't support. This very often fires **only when the
embedded LLM runs**, because llama.cpp's inference kernels are the heaviest SIMD
code path — the rest of the agent may run fine right up until inference starts.

### The common cause: VMs with no AVX

The **default QEMU/KVM CPU model** (`QEMU Virtual CPU version 2.5+`) exposes only
`SSE … SSE4.2` — it has **no AVX, AVX2, or FMA**. A llama.cpp build compiled for
AVX2 will SIGILL on such a VM the instant it does inference. Check your CPU:

```sh
grep -o -E 'avx2?|fma|sse4_2' /proc/cpuinfo | sort -u
```

If you see only `sse4_2` (no `avx`/`avx2`), you need an SSE-only build.

### The fix (already the default in this repo)

`.cargo/config.toml` sets a portable **SSE4.2 baseline** so the binary runs on
bare metal and on default QEMU VMs alike:

```
CMAKE_ARGS = "-DGGML_NATIVE=OFF -DGGML_AVX=OFF -DGGML_AVX2=OFF -DGGML_AVX512=OFF -DGGML_FMA=OFF -DGGML_F16C=OFF"
```

`GGML_NATIVE=OFF` is the critical part — without it llama.cpp uses `-march=native`
and bakes in the *build* machine's instructions. Make sure `.cargo/config.toml`
is present when you build, then rebuild from clean (`cargo clean -p llama-cpp-sys-2`
or `rm -rf target`) so the C++ recompiles with the new flags.

### Performance vs. portability

SSE-only inference is slower than AVX2. Two ways to get the speed back:

- **Give the VM a real CPU**: with libvirt/QEMU use `host-passthrough` (or a CPU
  model that includes AVX2). Then you can flip `GGML_AVX2=ON -DGGML_FMA=ON` in
  `.cargo/config.toml` for a large speedup — but that binary will SIGILL on any
  host/VM lacking AVX2.
- **Keep the SSE baseline** for a mixed fleet; it always runs.

## Quick checklist if the agent won't start

```sh
ldd ./target/release/nebula-agent | grep "not found"
```

- `libcudart.so` / `libcublas.so` not found → CUDA build on a non-CUDA host.
  Rebuild with `--features yara` (no `--all-features`).
- `libpcap.so` not found → `pcap` feature on a host without libpcap.
  Rebuild without `full-linux`, or `apt install libpcap0.8`.
- Starts but logs "Embedded LLM model not loaded" → no GGUF model present;
  see "providing a model" above. (This is non-fatal.)
