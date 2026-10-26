# build-cpu-gpu.ps1 — Build separate CPU and GPU nebula-agent binaries on Windows.
#
# WHY THIS SCRIPT EXISTS (read before editing):
#   1. The embedded LLM links llama.cpp, a native C++ library. Cargo does NOT
#      always rebuild native artifacts when only env-vars/backends change, so
#      building CPU then GPU in the SAME target/ dir can yield a binary that is
#      neither correctly CPU nor correctly GPU. We give each variant its OWN
#      target directory (--target-dir) so their artifacts never collide.
#   2. .cargo/config.toml pins a CPU/SSE baseline via CMAKE_ARGS for the CPU
#      build (the SIGILL fix). For the GPU build we OVERRIDE those so we don't
#      bake a deliberately-slow CPU path into the GPU binary.
#   3. Cargo always names the binary "nebula-agent". We rename the outputs to
#      nebula-agent-cpu.exe / nebula-agent-gpu.exe afterward.
#
# PREREQUISITES for the GPU build (CPU build needs none of these):
#   - Visual Studio with the MSVC C++ toolchain
#   - CUDA Toolkit for Windows, with nvcc on PATH and CUDA_PATH set
#   - The CUDA Toolkit version must be compatible with your Visual Studio version
#
# USAGE:
#   .\build-cpu-gpu.ps1            # builds both
#   .\build-cpu-gpu.ps1 -CpuOnly  # CPU only
#   .\build-cpu-gpu.ps1 -GpuOnly  # GPU only

param(
    [switch]$CpuOnly,
    [switch]$GpuOnly
)

$ErrorActionPreference = "Stop"
$OutDir = "dist"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# The binary Cargo produces (release profile).
$BinName = "nebula-agent.exe"

function Build-Cpu {
    Write-Host "=== Building CPU agent (portable SSE4.2 baseline) ===" -ForegroundColor Cyan
    # Uses the CPU baseline already pinned in .cargo/config.toml.
    cargo build --release `
        --features cpu-portable,yara `
        --target-dir target-cpu
    $src = "target-cpu\release\$BinName"
    $dst = "$OutDir\nebula-agent-cpu.exe"
    Copy-Item $src $dst -Force
    Write-Host "  -> $dst" -ForegroundColor Green
}

function Build-Gpu {
    Write-Host "=== Building GPU agent (CUDA) ===" -ForegroundColor Cyan
    # Override the CPU-only CMAKE_ARGS from .cargo/config.toml so the GPU binary
    # isn't compiled against the deliberately-slow SSE baseline. CUDA itself is
    # enabled by the `cuda` Cargo feature. We let GGML use a reasonable CPU
    # fallback (AVX2) since a CUDA-capable host almost certainly has AVX2.
    $env:CMAKE_ARGS = "-DGGML_NATIVE=OFF -DGGML_AVX=ON -DGGML_AVX2=ON -DGGML_FMA=ON -DGGML_CUDA=ON"
    $env:CFLAGS   = ""
    $env:CXXFLAGS = ""
    try {
        cargo build --release `
            --features cuda,yara `
            --target-dir target-gpu
    } finally {
        Remove-Item Env:\CMAKE_ARGS -ErrorAction SilentlyContinue
        Remove-Item Env:\CFLAGS    -ErrorAction SilentlyContinue
        Remove-Item Env:\CXXFLAGS  -ErrorAction SilentlyContinue
    }
    $src = "target-gpu\release\$BinName"
    $dst = "$OutDir\nebula-agent-gpu.exe"
    Copy-Item $src $dst -Force
    Write-Host "  -> $dst" -ForegroundColor Green
    Write-Host "  NOTE: verify the build log printed 'NVIDIA CUDA backend ENABLED'." -ForegroundColor Yellow
    Write-Host "        If it said 'CPU build', the cuda feature did not take." -ForegroundColor Yellow
}

if (-not $GpuOnly) { Build-Cpu }
if (-not $CpuOnly) { Build-Gpu }

Write-Host "`nDone. Binaries in .\$OutDir\" -ForegroundColor Green
Get-ChildItem $OutDir
