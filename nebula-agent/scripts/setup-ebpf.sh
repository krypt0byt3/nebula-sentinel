#!/usr/bin/env bash
# setup-ebpf.sh — one-command eBPF enablement for Nebula Sentinel.
#
# Use this ONLY if your agent was NOT built with the BPF object embedded
# (i.e. the build host lacked clang). It installs the toolchain, compiles the
# CO-RE BPF object on THIS machine, and installs it where the agent looks.
#
# If you built the agent with `--features ebpf` on a host that had clang, the
# object is already baked into the binary and you do NOT need this script.
#
# Usage:  sudo ./scripts/setup-ebpf.sh
#
# Safe to re-run. Exits non-zero on failure with a clear message.
set -euo pipefail

NEBULA_LIB=/usr/lib/nebula
BPF_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bpf" 2>/dev/null && pwd || true)"

say()  { printf '\033[1;36m>>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (sudo). Installing packages + writing to ${NEBULA_LIB}."

# 0. Sanity: this kernel must support BPF + BTF.
[ -e /sys/kernel/btf/vmlinux ] || die "No BTF (/sys/kernel/btf/vmlinux). Kernel needs CONFIG_DEBUG_INFO_BTF=y (most distro kernels 5.8+ have it). eBPF can't run here; the agent will use procmon."

# 1. Locate the BPF source. It ships in the repo's bpf/ dir. If you only have a
#    binary, drop the bpf/ directory next to this script or set BPF_SRC_DIR.
if [ -z "${BPF_SRC_DIR}" ] || [ ! -f "${BPF_SRC_DIR}/nebula.bpf.c" ]; then
    die "BPF source not found. Expected bpf/nebula.bpf.c next to the agent. Set BPF_SRC_DIR=/path/to/bpf and re-run."
fi
say "Using BPF source in ${BPF_SRC_DIR}"

# 2. Install toolchain (clang + libbpf headers; bpftool optional but preferred).
install_pkgs() {
    if   command -v apt-get >/dev/null; then
        apt-get update -qq
        apt-get install -y clang llvm libbpf-dev || true
        apt-get install -y "linux-tools-$(uname -r)" bpftool 2>/dev/null || true
    elif command -v dnf >/dev/null; then
        dnf install -y clang llvm libbpf-devel bpftool || true
    elif command -v yum >/dev/null; then
        yum install -y clang llvm libbpf-devel bpftool || true
    elif command -v zypper >/dev/null; then
        zypper install -y clang llvm libbpf-devel bpftool || true
    elif command -v pacman >/dev/null; then
        pacman -Sy --noconfirm clang llvm libbpf bpf || true
    else
        die "Unknown package manager. Install manually: clang, llvm, libbpf headers (and bpftool)."
    fi
}
command -v clang >/dev/null || { say "Installing toolchain…"; install_pkgs; }
command -v clang >/dev/null || die "clang still not found after install attempt. Install it manually and re-run."
ok "clang present: $(command -v clang)"

# 3. Build the object.
ARCH=$(uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
DEFS=""
INCS="-I${BPF_SRC_DIR}"
# Prefer a real generated vmlinux.h when bpftool is available.
if command -v bpftool >/dev/null; then
    say "Generating vmlinux.h from kernel BTF (bpftool)…"
    if bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${BPF_SRC_DIR}/vmlinux.h" 2>/dev/null \
       && [ -s "${BPF_SRC_DIR}/vmlinux.h" ]; then
        DEFS="-DNEBULA_HAVE_FULL_VMLINUX"
        ok "Generated full vmlinux.h"
    else
        say "bpftool dump failed — using bundled minimal header."
    fi
else
    say "bpftool not present — using bundled minimal vmlinux header (clang-only)."
fi
# Help clang find libbpf headers.
for d in /usr/include /usr/local/include "/usr/include/$(uname -m)-linux-gnu"; do
    [ -f "$d/bpf/bpf_helpers.h" ] && INCS="$INCS -I$d"
done

say "Compiling nebula.bpf.o (arch=${ARCH})…"
clang -O2 -g -Wall -target bpf "-D__TARGET_ARCH_${ARCH}" $DEFS $INCS \
    -c "${BPF_SRC_DIR}/nebula.bpf.c" -o "${BPF_SRC_DIR}/nebula.bpf.o" \
    || die "clang failed. If the error mentions bpf/bpf_helpers.h, install libbpf-dev (Debian) / libbpf-devel (RHEL)."
# Strip DWARF debug info but keep .BTF (CO-RE). Without this the object is ~1MB
# of debug sections and aya rejects it with "error parsing ELF data".
say "Stripping DWARF (keeping .BTF)…"
if command -v llvm-strip >/dev/null; then
    llvm-strip -g "${BPF_SRC_DIR}/nebula.bpf.o" || true
elif command -v strip >/dev/null; then
    strip -g "${BPF_SRC_DIR}/nebula.bpf.o" || true
else
    say "no llvm-strip/strip found — object may be too large for aya. Install llvm."
fi
ok "Compiled $(du -h "${BPF_SRC_DIR}/nebula.bpf.o" | cut -f1) object"

# 4. Install.
install -d "${NEBULA_LIB}"
install -m 0644 "${BPF_SRC_DIR}/nebula.bpf.o" "${NEBULA_LIB}/nebula.bpf.o"
ok "Installed ${NEBULA_LIB}/nebula.bpf.o"

cat <<EOF

$(ok "eBPF object is ready.")
Next:
  1. Ensure the agent config has  backend = "ebpf"  under [collector].
  2. Ensure the agent runs with CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE (or root).
     For systemd:  AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_PTRACE
  3. Restart the agent. Look for:  "✅ eBPF backend active"
EOF
