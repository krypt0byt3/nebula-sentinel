// build.rs — NebulaSentinel Agent build script
//
// Responsibilities:
//   1. Detect GPU hardware at compile time → set feature flags for llama.cpp
//   2. Print cargo directives so llama.cpp links the right backends
//   3. Emit helpful messages if CUDA/ROCm headers are missing

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Register the custom cfg we may set below so Rust 1.80+ doesn't warn about
    // an "unexpected cfg" (the loader uses #[cfg(nebula_bpf_embedded)]).
    println!("cargo:rustc-check-cfg=cfg(nebula_bpf_embedded)");

    // ── eBPF: compile + embed the CO-RE object (feature-gated) ──────────
    // When building with --features ebpf, try to compile bpf/nebula.bpf.o and
    // embed it into the binary so there is NOTHING to install on the target.
    // This is fully NON-FATAL: if clang or the libbpf headers are missing, we
    // print a warning, skip embedding, and the agent falls back to its runtime
    // disk search (and then procmon) — the normal build still succeeds.
    #[cfg(feature = "ebpf")]
    maybe_build_bpf();

    // ── Emit platform info as compile-time env vars ──────────
    // Used by main.rs to register platform with Nexus and for binary naming
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "linux".to_string());
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());
    println!("cargo:rustc-env=NEBULA_TARGET_OS={}", os);
    println!("cargo:rustc-env=NEBULA_TARGET_ARCH={}", arch);
    println!("cargo:warning=Building nebula-agent for {}/{}", os, arch);

    // For Windows: link to WinAPI subsystem
    if os == "windows" {
        println!("cargo:warning=Windows target: process snapshot via TlHelp32, Event Log collector enabled");
    }
    // For macOS: link system frameworks
    if os == "macos" {
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=SystemConfiguration");
        println!("cargo:warning=macOS target: FSEvents FIM, EndpointSecurity API collector enabled");
    }
    println!("cargo:rerun-if-env-changed=CUDA_PATH");
    println!("cargo:rerun-if-env-changed=ROCM_PATH");
    println!("cargo:rerun-if-env-changed=NEBULA_LLM_BACKEND");

    // Allow manual override via env: NEBULA_LLM_BACKEND=cuda|rocm|metal|cpu
    if let Ok(backend) = std::env::var("NEBULA_LLM_BACKEND") {
        match backend.to_lowercase().as_str() {
            "cuda"  => { println!("cargo:rustc-cfg=llm_backend=\"cuda\"");  return; }
            "rocm"  => { println!("cargo:rustc-cfg=llm_backend=\"rocm\"");  return; }
            "metal" => { println!("cargo:rustc-cfg=llm_backend=\"metal\""); return; }
            "cpu"   => { println!("cargo:rustc-cfg=llm_backend=\"cpu\"");   return; }
            _       => {}
        }
    }

    // ── macOS / Apple Silicon → Metal ────────────────────────
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-cfg=llm_backend=\"metal\"");
        println!("cargo:warning=NebulaSentinel LLM: Apple Metal backend selected (macOS)");
        return;
    }

    // ── NVIDIA CUDA ────────────────────────────────────────────
    // CUDA linkage is driven ENTIRELY by the llama-cpp-2 `cuda` Cargo feature
    // (enabled explicitly, or accidentally via `--all-features`). build.rs does
    // NOT auto-select it. We only emit an accurate banner + a portability
    // warning so a CUDA-linked binary is never produced silently.
    let cuda_feature_on = std::env::var("CARGO_FEATURE_CUDA").is_ok();
    let has_nvcc = std::process::Command::new("nvcc").arg("--version")
        .output().map(|o| o.status.success()).unwrap_or(false);
    let cuda_path = std::env::var("CUDA_PATH")
        .or_else(|_| std::env::var("CUDA_HOME"))
        .unwrap_or_default();

    if cuda_feature_on {
        println!("cargo:rustc-cfg=llm_backend=\"cuda\"");
        // Compile the CUDA backend. STATIC cudart is the default and is what we
        // link here (libcudart_static.a exists on this system — see link paths
        // below). GGML_CUDA=ON / LLAMA_CUDA=ON: both names set for llama.cpp
        // version safety. AVX2 CPU fallback since a CUDA host almost certainly
        // has AVX2.
        std::env::set_var("CMAKE_ARGS",
            "-DGGML_NATIVE=OFF -DGGML_AVX=ON -DGGML_AVX2=ON -DGGML_FMA=ON -DGGML_F16C=ON \
             -DGGML_CUDA=ON -DLLAMA_CUDA=ON");
        std::env::set_var("CFLAGS",   "-march=x86-64-v3");
        std::env::set_var("CXXFLAGS", "-march=x86-64-v3");
        if !cuda_path.is_empty() {
            std::env::set_var("CUDAToolkit_ROOT", &cuda_path);
            std::env::set_var("CUDA_PATH", &cuda_path);
            let nvcc = if os == "windows" {
                format!("{}\\bin\\nvcc.exe", cuda_path)
            } else {
                format!("{}/bin/nvcc", cuda_path)
            };
            if std::path::Path::new(&nvcc).exists() {
                std::env::set_var("CUDACXX", &nvcc);
            }
        }

        // ── LINK-SEARCH PATHS ────────────────────────────────────────────
        // The linker needs the directory containing libcudart_static.a (and
        // cublas etc.). The static lib's location VARIES by install method:
        //   - runfile toolkit:  $CUDA_PATH/lib64
        //   - distro packages:  /usr/lib/x86_64-linux-gnu   ← common, and where
        //                        this system actually has it
        //   - targets layout:   $CUDA_PATH/targets/x86_64-linux/lib
        // We add ALL plausible locations that EXIST, unconditionally (not just
        // when CUDA_PATH is set — the earlier bug only checked $CUDA_PATH/lib64
        // and missed /usr/lib/x86_64-linux-gnu, so the build failed even though
        // the file was present).
        if os == "windows" {
            if !cuda_path.is_empty() {
                println!("cargo:rustc-link-search=native={}\\lib\\x64", cuda_path);
            }
        } else {
            let mut candidates: Vec<String> = vec![
                "/usr/lib/x86_64-linux-gnu".to_string(),
                "/usr/local/cuda/lib64".to_string(),
            ];
            if !cuda_path.is_empty() {
                candidates.push(format!("{}/lib64", cuda_path));
                candidates.push(format!("{}/lib", cuda_path));
                candidates.push(format!("{}/lib64/stubs", cuda_path));
                candidates.push(format!("{}/targets/x86_64-linux/lib", cuda_path));
                candidates.push(format!("{}/targets/x86_64-linux/lib/stubs", cuda_path));
            }
            let mut found_cudart = false;
            for dir in &candidates {
                if std::path::Path::new(dir).exists() {
                    println!("cargo:rustc-link-search=native={}", dir);
                    if std::path::Path::new(&format!("{}/libcudart_static.a", dir)).exists() {
                        found_cudart = true;
                        println!("cargo:warning=NebulaSentinel LLM: found libcudart_static.a in {}", dir);
                    }
                }
            }
            if !found_cudart {
                println!("cargo:warning=  ⚠ libcudart_static.a not found in the usual dirs. If linking");
                println!("cargo:warning=  ⚠ fails, run: find /usr /opt -name libcudart_static.a  and tell us the path.");
            }
        }

        println!("cargo:warning=NebulaSentinel LLM: NVIDIA CUDA backend ENABLED (static cudart).");
        println!("cargo:warning=  ⚠ Requires an NVIDIA driver on every host that runs this binary.");
        if !cuda_path.is_empty() {
            println!("cargo:rustc-env=CUDA_PATH={}", cuda_path);
        }
        return;
    }
    if has_nvcc {
        // Toolkit present but feature off — fine, just a heads-up in case the
        // operator intended GPU (they must enable the llama-cpp-2 cuda feature).
        println!("cargo:warning=NebulaSentinel LLM: CUDA toolkit detected but CUDA backend NOT enabled (CPU build).");
        println!("cargo:warning=  To build with GPU, enable the llama-cpp-2 'cuda' feature (see Cargo.toml notes).");
    }

    // ── AMD ROCm ───────────────────────────────────────────────
    // Same rule as CUDA: gated on the llama-cpp-2 `rocm`/`hipblas` feature, not
    // on toolchain presence. A ROCm-linked binary needs the ROCm runtime present.
    if std::env::var("CARGO_FEATURE_ROCM").is_ok() || std::env::var("CARGO_FEATURE_HIPBLAS").is_ok() {
        println!("cargo:rustc-cfg=llm_backend=\"rocm\"");
        println!("cargo:warning=NebulaSentinel LLM: AMD ROCm backend ENABLED.");
        println!("cargo:warning=  ⚠ PORTABILITY: requires the ROCm runtime on every host that runs this binary.");
        return;
    }

    // ── Vulkan (Intel Arc, etc.) ───────────────────────────────
    if std::env::var("CARGO_FEATURE_VULKAN").is_ok() {
        println!("cargo:rustc-cfg=llm_backend=\"vulkan\"");
        println!("cargo:warning=NebulaSentinel LLM: Vulkan backend ENABLED.");
        println!("cargo:warning=  ⚠ PORTABILITY: requires the Vulkan loader (libvulkan) on every host that runs this binary.");
        return;
    }

    // ── CPU backend (default) — SIMD baseline is controlled by Rust target
    //    features, NOT by this script ────────────────────────────────────────
    // llama-cpp-sys-2's OWN build script (a dependency, so it runs BEFORE this
    // one) derives the ggml SIMD baseline from CARGO_CFG_TARGET_FEATURE:
    //   • default x86-64 target → SSE2 only + GGML_NATIVE=OFF → a PORTABLE binary
    //     that runs on any x86-64 incl. AVX-less QEMU VMs (no "Illegal
    //     instruction"/SIGILL). This is the safe default; no flags needed.
    //   • for a FASTER AVX2 binary (modern bare-metal only), raise the Rust
    //     target features so llama-cpp-sys-2 turns on GGML_AVX2/FMA/F16C:
    //         RUSTFLAGS="-C target-feature=+avx2,+fma,+f16c" cargo build --release
    //     (or `-C target-cpu=x86-64-v3`). That binary SIGILLs on non-AVX2 CPUs.
    //
    // NOTE: a previous version tried to force the baseline here via
    // std::env::set_var("CMAKE_ARGS"/"CFLAGS", …). That was a NO-OP: this build
    // script runs AFTER the llama.cpp compile, so its env vars never reached it.
    // Baseline is therefore controlled via RUSTFLAGS (above), which the sys crate
    // actually reads — the SSE2 default already makes CPU mode SIGILL-safe on VMs.
    let avx2_feature = std::env::var("CARGO_FEATURE_CPU_AVX2").is_ok();
    if avx2_feature {
        println!("cargo:warning=NebulaSentinel LLM: NOTE — the cpu-avx2/modern_cpu feature does NOT \
                  by itself force AVX2. For AVX2 speed build with \
                  RUSTFLAGS=\"-C target-feature=+avx2,+fma,+f16c\"; otherwise this is a portable SSE2 CPU build.");
    } else {
        println!("cargo:warning=NebulaSentinel LLM: CPU build (portable SSE2 baseline — runs on any x86-64, incl. AVX-less VMs).");
    }
    println!("cargo:rustc-cfg=llm_backend=\"cpu\"");

    // Check for BLAS (OpenBLAS / MKL) for accelerated matrix ops on CPU
    let has_openblas = std::path::Path::new("/usr/lib/libopenblas.so").exists()
        || std::path::Path::new("/usr/local/lib/libopenblas.so").exists();
    if has_openblas {
        println!("cargo:warning=NebulaSentinel LLM: OpenBLAS detected — matrix ops accelerated");
        println!("cargo:rustc-cfg=has_blas");
    } else {
        println!("cargo:warning=NebulaSentinel LLM: No BLAS found. Install libopenblas-dev for faster CPU inference.");
    }
}

// ───────────────────────────────────────────────────────────────────────
// eBPF object compilation + embedding (only compiled with --features ebpf)
// ───────────────────────────────────────────────────────────────────────
#[cfg(feature = "ebpf")]
fn maybe_build_bpf() {
    use std::path::Path;
    use std::process::Command;

    println!("cargo:rerun-if-changed=bpf/nebula.bpf.c");
    println!("cargo:rerun-if-changed=bpf/nebula_events.h");
    println!("cargo:rerun-if-changed=bpf/vmlinux_min.h");

    // Only meaningful when building FOR Linux (BPF is Linux-only).
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        println!("cargo:warning=eBPF: target OS is {} — skipping BPF embed (Linux only).", target_os);
        return;
    }

    // 1. Need clang to compile to the BPF target.
    let clang = which("clang");
    if clang.is_none() {
        println!("cargo:warning=eBPF: clang not found on build host — NOT embedding BPF object.");
        println!("cargo:warning=  Install clang (apt install clang) to bake eBPF into the binary,");
        println!("cargo:warning=  or run scripts/setup-ebpf.sh on the target. Agent will use procmon meanwhile.");
        return;
    }
    let clang = clang.unwrap();

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let obj_path = format!("{}/nebula.bpf.o", out_dir);
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default().as_str() {
        "x86_64"  => "x86",
        "aarch64" => "arm64",
        other     => { println!("cargo:warning=eBPF: arch {} untested, trying x86 macros.", other); "x86" }
    };

    // 2. Decide on the vmlinux header. Prefer a bpftool-generated full header
    //    (most complete); fall back to the shipped minimal header (clang-only).
    let mut defines: Vec<String> = Vec::new();
    let full_vmlinux = format!("{}/vmlinux.h", out_dir);
    let mut have_full = false;
    // Escape hatch: NEBULA_BPF_MINIMAL=1 forces the bundled minimal header even
    // when bpftool is available. The minimal header yields a much smaller, simpler
    // object (tiny .BTF) — useful if the full kernel-BTF object trips aya's parser.
    let force_minimal = std::env::var("NEBULA_BPF_MINIMAL").map(|v| v == "1").unwrap_or(false);
    println!("cargo:rerun-if-env-changed=NEBULA_BPF_MINIMAL");
    if force_minimal {
        println!("cargo:warning=eBPF: NEBULA_BPF_MINIMAL=1 set — forcing bundled minimal header.");
    }
    if !force_minimal {
    if let Some(bpftool) = which("bpftool") {
        if Path::new("/sys/kernel/btf/vmlinux").exists() {
            // bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
            if let Ok(output) = Command::new(&bpftool)
                .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
                .output()
            {
                if output.status.success() && !output.stdout.is_empty() {
                    if std::fs::write(&full_vmlinux, &output.stdout).is_ok() {
                        have_full = true;
                        defines.push("-DNEBULA_HAVE_FULL_VMLINUX".to_string());
                        println!("cargo:warning=eBPF: generated full vmlinux.h from build-host BTF.");
                    }
                }
            }
        }
    }
    }
    if !have_full {
        println!("cargo:warning=eBPF: using bundled minimal vmlinux header (clang-only path).");
    }

    // 3. Compile the CO-RE object.
    //    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I<bpf> -I<out> -c nebula.bpf.c -o obj
    let mut cmd = Command::new(&clang);
    cmd.args(["-O2", "-g", "-Wall", "-target", "bpf"])
       .arg(format!("-D__TARGET_ARCH_{}", arch))
       .arg("-Ibpf")                 // nebula_events.h, vmlinux_min.h
       .arg(format!("-I{}", out_dir)) // generated vmlinux.h (if any)
       .args(&defines)
       .args(["-c", "bpf/nebula.bpf.c", "-o", &obj_path]);
    // Help clang find libbpf headers if they're in a non-default include dir.
    for inc in ["/usr/include", "/usr/local/include"] {
        if Path::new(&format!("{}/bpf/bpf_helpers.h", inc)).exists() {
            cmd.arg(format!("-I{}", inc));
        }
    }

    match cmd.output() {
        Ok(out) if out.status.success() => {
            // Strip DWARF debug info but KEEP the .BTF section (needed for CO-RE).
            // IMPORTANT: only llvm-strip is safe here. Plain GNU `strip` does NOT
            // understand that .BTF is special and will remove it, which makes aya
            // fail to load (no BTF → CO-RE can't relocate). We therefore require
            // llvm-strip and pass --keep-section=.BTF defensively. If llvm-strip
            // isn't available we leave the object UNSTRIPPED rather than risk GNU
            // strip nuking the BTF — an unstripped object with valid BTF loads,
            // it's just larger.
            if let Some(stripper) = which("llvm-strip").or_else(|| which("llvm-strip-18"))
                .or_else(|| which("llvm-strip-17")).or_else(|| which("llvm-strip-16"))
                .or_else(|| which("llvm-strip-15")).or_else(|| which("llvm-strip-14")) {
                let s = Command::new(&stripper)
                    .args(["--strip-debug", "--keep-section=.BTF", "--keep-section=.BTF.ext", &obj_path])
                    .output();
                match s {
                    Ok(so) if so.status.success() => {
                        let sz = std::fs::metadata(&obj_path).map(|m| m.len()).unwrap_or(0);
                        println!("cargo:warning=eBPF: stripped DWARF, kept .BTF ({}) — object now {} KB", stripper, sz / 1024);
                    }
                    Ok(so) => {
                        let e = String::from_utf8_lossy(&so.stderr);
                        println!("cargo:warning=eBPF: llvm-strip failed ({}) — embedding unstripped object (still valid, just larger).", e.lines().next().unwrap_or(""));
                    }
                    Err(e) => println!("cargo:warning=eBPF: could not run llvm-strip ({}) — embedding unstripped.", e),
                }
            } else {
                println!("cargo:warning=eBPF: llvm-strip not found — embedding UNSTRIPPED object (valid, ~1MB). Install llvm for a smaller object. NOT using GNU strip (it would remove .BTF).");
            }

            // Diagnostics: dump the section headers so we can confirm .BTF is
            // present and the object is a BPF ELF if loading still fails.
            if let Some(objdump) = which("llvm-objdump").or_else(|| which("llvm-objdump-18"))
                .or_else(|| which("llvm-objdump-17")) {
                if let Ok(d) = Command::new(&objdump).args(["-h", &obj_path]).output() {
                    let txt = String::from_utf8_lossy(&d.stdout);
                    let has_btf = txt.contains(".BTF");
                    let has_progs = txt.contains("tracepoint") || txt.contains("kprobe") || txt.contains("sched");
                    println!("cargo:warning=eBPF: object sections — .BTF present: {}, program sections present: {}", has_btf, has_progs);
                    if !has_btf {
                        println!("cargo:warning=eBPF: ⚠️  NO .BTF section — CO-RE relocation will fail. Compiled without -g or BTF was stripped.");
                    }
                }
            }

            println!("cargo:rustc-env=NEBULA_BPF_OBJECT={}", obj_path);
            println!("cargo:rustc-cfg=nebula_bpf_embedded");
            println!("cargo:warning=eBPF: ✅ compiled and EMBEDDED nebula.bpf.o into the agent.");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!("cargo:warning=eBPF: clang failed to compile BPF object — NOT embedding (agent falls back to procmon).");
            // Surface the first couple of error lines to help diagnose (often a
            // missing <bpf/bpf_helpers.h> → install libbpf-dev).
            for line in stderr.lines().take(6) {
                println!("cargo:warning=eBPF:   {}", line);
            }
            if stderr.contains("bpf_helpers.h") || stderr.contains("bpf/bpf_") {
                println!("cargo:warning=eBPF:   → looks like libbpf headers are missing: apt install libbpf-dev");
            }
        }
        Err(e) => {
            println!("cargo:warning=eBPF: could not run clang ({}) — NOT embedding.", e);
        }
    }
}

// Minimal `which`: find an executable on PATH. Returns full path if found.
#[cfg(feature = "ebpf")]
fn which(bin: &str) -> Option<String> {
    let path = std::env::var("PATH").ok()?;
    for dir in path.split(':') {
        let candidate = format!("{}/{}", dir, bin);
        if std::path::Path::new(&candidate).is_file() {
            return Some(candidate);
        }
    }
    None
}
