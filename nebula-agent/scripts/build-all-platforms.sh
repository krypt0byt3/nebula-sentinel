#!/usr/bin/env bash
# scripts/build-all-platforms.sh — Cross-platform release builds
#
# Produces platform-stamped binaries in dist/:
#   nebula-agent-linux-x86_64
#   nebula-agent-linux-aarch64
#   nebula-agent-windows-x86_64.exe
#   nebula-agent-macos-x86_64
#   nebula-agent-macos-aarch64
#
# Requirements:
#   All platforms: Rust stable + cross (cargo install cross)
#   Windows:       x86_64-pc-windows-gnu target + MinGW
#   macOS cross:   Apple SDK or osxcross (macOS builds need macOS host or osxcross)
#
# Usage:
#   ./scripts/build-all-platforms.sh           # all platforms
#   ./scripts/build-all-platforms.sh linux     # Linux only
#   ./scripts/build-all-platforms.sh windows   # Windows only
#   ./scripts/build-all-platforms.sh macos     # macOS only

set -euo pipefail
DIST="dist"
mkdir -p "$DIST"

build_target() {
    local TARGET="$1" NAME="$2"
    echo "Building $NAME (target: $TARGET)..."
    if command -v cross &>/dev/null; then
        cross build --release --target "$TARGET"
    else
        cargo build --release --target "$TARGET"
    fi
    local EXT=""; [[ "$TARGET" == *"windows"* ]] && EXT=".exe"
    cp "target/$TARGET/release/nebula-agent${EXT}" "$DIST/${NAME}${EXT}"
    echo "  → $DIST/${NAME}${EXT} ($(du -sh "$DIST/${NAME}${EXT}" | cut -f1))"
}

BUILD_LINUX=true; BUILD_WINDOWS=true; BUILD_MACOS=true
[[ "${1:-}" == "linux" ]]   && { BUILD_WINDOWS=false; BUILD_MACOS=false; }
[[ "${1:-}" == "windows" ]] && { BUILD_LINUX=false;   BUILD_MACOS=false; }
[[ "${1:-}" == "macos" ]]   && { BUILD_LINUX=false;   BUILD_WINDOWS=false; }

$BUILD_LINUX   && build_target "x86_64-unknown-linux-gnu"  "nebula-agent-linux-x86_64"
$BUILD_LINUX   && build_target "aarch64-unknown-linux-gnu" "nebula-agent-linux-aarch64"
$BUILD_WINDOWS && build_target "x86_64-pc-windows-gnu"     "nebula-agent-windows-x86_64"
if $BUILD_MACOS; then
    [[ "$(uname)" == "Darwin" ]] && {
        build_target "x86_64-apple-darwin"  "nebula-agent-macos-x86_64"
        build_target "aarch64-apple-darwin" "nebula-agent-macos-aarch64"
    } || echo "macOS targets require macOS host or osxcross"
fi

echo "=== Build complete ===" && ls -lh "$DIST"/
