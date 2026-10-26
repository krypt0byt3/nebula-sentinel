# NebulaSentinel — Build and Deploy Guide
# Nexus (server) + Sentinel (agent)

---

## Overview

You will:
1. Build the Nexus binary on a Linux build machine
2. Deploy Nexus on your server
3. Build the Sentinel binary (same machine or cross-compile)
4. Deploy Sentinels on every endpoint

Both components are single self-contained binaries. No Docker required,
no runtime dependencies beyond the binary and a config file.

---

## Part 1: Prerequisites

### 1.1 Install Rust

Do this on your BUILD machine (can be the same as the Nexus server):

```bash
# Install rustup (Rust toolchain manager)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Verify
rustc --version    # should show 1.78.0 or newer
cargo --version
```

### 1.2 Install system build dependencies

**Ubuntu / Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    cmake \
    git \
    curl \
    wget \
    clang \
    libclang-dev
```

**RHEL / Rocky / AlmaLinux:**
```bash
sudo dnf groupinstall "Development Tools" -y
sudo dnf install -y \
    openssl-devel \
    sqlite-devel \
    cmake \
    git \
    curl \
    wget \
    clang \
    clang-devel
```

**macOS (for building the macOS agent):**
```bash
xcode-select --install
brew install cmake pkg-config openssl
```

---

## Part 2: Build the Nexus

### 2.1 Get the source

```bash
# Extract the release zip you received
unzip nebulasentinel_v23b_final.zip -d nebulasentinel
cd nebulasentinel/nexus-server
```

### 2.2 Build in release mode

```bash
cargo build --release
```

This will:
- Download all dependencies automatically from crates.io (~200 packages)
- Compile everything with full optimization (LTO, strip)
- Take 5–15 minutes on first build (cached on subsequent builds)

The output binary is at:
```
target/release/nexus-server
```

Verify it built correctly:
```bash
./target/release/nexus-server --version
# Should print: nexus-server 0.3.0
```

### 2.3 Optional: build with GPU support for Whisper

If your Nexus server has an NVIDIA GPU and you want local LLM inference:

```bash
# Install CUDA toolkit first (if not already installed)
# https://developer.nvidia.com/cuda-downloads

# Then build with CUDA feature
cargo build --release --features cuda
```

For AMD GPU (ROCm):
```bash
cargo build --release --features rocm
```

For Apple Silicon (Metal — macOS only):
```bash
cargo build --release --features metal
```

---

## Part 3: Deploy the Nexus

### 3.1 Create directory structure on the server

```bash
# Run these as root on your Nexus server
sudo useradd -r -s /sbin/nologin -d /var/lib/nexus nexus

sudo mkdir -p \
    /usr/local/bin \
    /var/lib/nexus \
    /var/lib/nexus/certs \
    /var/lib/nexus/models \
    /var/lib/nexus/dist \
    /etc/nexus

sudo chown -R nexus:nexus /var/lib/nexus
sudo chmod 750 /var/lib/nexus
```

### 3.2 Copy the binary

```bash
# From your build machine, copy to the server
scp target/release/nexus-server user@your-nexus-server:/tmp/

# On the Nexus server:
sudo cp /tmp/nexus-server /usr/local/bin/nexus-server
sudo chmod 750 /usr/local/bin/nexus-server
sudo chown nexus:nexus /usr/local/bin/nexus-server
```

### 3.3 Create the configuration file

```bash
sudo nano /etc/nexus/nexus.toml
```

Paste the following — this is the minimum working configuration:

```toml
# /etc/nexus/nexus.toml

db_path         = "/var/lib/nexus/nexus.db"
api_master_key  = "CHANGE_ME_IN_PRODUCTION"

# TLS: use self-signed cert automatically generated on first start
self_signed_cert = true
# To use your own cert:
# tls_cert_path = "/etc/nexus/certs/server.crt"
# tls_key_path  = "/etc/nexus/certs/server.key"

bind_addr  = "0.0.0.0"
atc_port   = 9443    # Agents connect here
mgmt_port  = 8443    # Operators (UI + API)
http_port  = 8080    # Dev mode only (--http-only flag)

agent_stale_after_secs         = 300
agent_offline_after_secs       = 1800
staleness_check_interval_secs  = 60

geo_enabled        = true
require_agent_cert = false

[llm]
# Start with mock for testing. Switch to llamacpp once you download a model.
provider = "mock"
# provider = "llamacpp"
# llamaserver_bin = "/usr/local/bin/llama-server"
# model_path = "/var/lib/nexus/models/Qwen2.5-7B-Instruct-Q4_K_M.gguf"
n_parallel       = 4
n_gpu_layers     = -1
n_ctx            = 4096
llamaserver_addr = "127.0.0.1"
llamaserver_port = 18080
atlas_guard      = true

[auth]
provider      = "local"
session_hours = 8
# jwt_secret set via NEXUS_JWT_SECRET environment variable
```

### 3.4 Create the environment secrets file

```bash
sudo nano /etc/nexus/environment
```

```bash
# /etc/nexus/environment
# Generate JWT secret: openssl rand -base64 48

NEXUS_JWT_SECRET=REPLACE_WITH_openssl_rand_-base64_48_OUTPUT
NEXUS_ADMIN_PASSWORD=ChooseAStrongPassword123!

# Cloud LLM (uncomment whichever you use):
# ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# XAI_API_KEY=xai-...
```

```bash
sudo chmod 640 /etc/nexus/environment
sudo chown nexus:nexus /etc/nexus/environment

# Generate and set a real JWT secret right now:
JWT=$(openssl rand -base64 48)
sudo sed -i "s|REPLACE_WITH_openssl_rand_-base64_48_OUTPUT|$JWT|" /etc/nexus/environment
```

### 3.5 Create the systemd service

```bash
sudo tee /etc/systemd/system/nexus.service << 'UNIT'
[Unit]
Description=NebulaSentinel Nexus
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nexus
Group=nexus
EnvironmentFile=/etc/nexus/environment
ExecStart=/usr/local/bin/nexus-server --config /etc/nexus/nexus.toml
WorkingDirectory=/var/lib/nexus
Restart=on-failure
RestartSec=5
TimeoutStartSec=30

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/nexus /etc/nexus
ProtectHome=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

StandardOutput=journal
StandardError=journal
SyslogIdentifier=nexus

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
```

### 3.6 Open firewall ports

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 8443/tcp comment "Nexus operator UI"
sudo ufw allow 9443/tcp comment "Nexus agent ATC"
sudo ufw reload

# firewalld (RHEL/Rocky)
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --permanent --add-port=9443/tcp
sudo firewall-cmd --reload

# iptables (any Linux)
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9443 -j ACCEPT
```

### 3.7 Start the Nexus

```bash
sudo systemctl start nexus
sudo systemctl enable nexus

# Check it started cleanly
sudo systemctl status nexus
```

You should see output like:
```
INFO  nexus_server: NebulaSentinel Nexus starting
INFO  nexus_server::db: Database initialised (18 tables)
WARN  nexus_server::auth: Created default admin account (username: admin)
INFO  nexus_server: ATC port (agents): 0.0.0.0:9443
INFO  nexus_server: MGMT port (ops):   0.0.0.0:8443
INFO  nexus_server: Nexus ready
```

If it fails:
```bash
sudo journalctl -u nexus -n 50 --no-pager
```

### 3.8 Verify and log in

Open `https://YOUR-NEXUS-IP:8443` in a browser.

Accept the self-signed certificate warning. Log in:
- **Username:** `admin`
- **Password:** whatever you set in `NEXUS_ADMIN_PASSWORD`

**Immediately change the admin password** after first login:
Settings → Users & Auth → Change Password

### 3.9 Copy the Nexus TLS certificate to use on agents

The Nexus auto-generates a self-signed cert at `/var/lib/nexus/certs/nexus.crt`.
You need to copy this to each agent host so they can verify the Nexus connection.

```bash
# From the Nexus server, find the cert
sudo cat /var/lib/nexus/certs/nexus.crt

# Or copy it to your build machine
scp nexus-user@your-nexus:/var/lib/nexus/certs/nexus.crt ./nexus-ca.pem
```

---

## Part 4: Optional — Download a real LLM model for Whisper

Skip this if you are testing with `provider = "mock"`. Come back when you are ready to enable Nebula Whisper AI analysis.

### 4.1 Install llama-server

```bash
# Option A: Pre-built binary from llama.cpp releases
# https://github.com/ggerganov/llama.cpp/releases
# Download the linux-x86_64 release, extract llama-server

sudo cp llama-server /usr/local/bin/llama-server
sudo chmod +x /usr/local/bin/llama-server

# Option B: Build from source
git clone https://github.com/ggerganov/llama.cpp
cd llama.cpp
cmake -B build -DLLAMA_CUDA=ON   # or -DLLAMA_METAL=ON for macOS
cmake --build build --config Release -j $(nproc)
sudo cp build/bin/llama-server /usr/local/bin/
```

### 4.2 Download a model

Choose based on your hardware:

| Hardware | Model | Size | Command |
|---|---|---|---|
| CPU only | Phi-3.5-mini-Q4 | 2.4 GB | See below |
| 5+ GB VRAM | Qwen2.5-7B-Q4 | 4.7 GB | See below |
| 9+ GB VRAM | Qwen2.5-14B-Q4 | 8.7 GB | See below |

```bash
# CPU only — works on any modern server
sudo -u nexus wget -P /var/lib/nexus/models/ \
  "https://huggingface.co/microsoft/Phi-3.5-mini-instruct-gguf/resolve/main/Phi-3.5-mini-instruct-Q4_K_M.gguf"

# 5+ GB VRAM GPU
sudo -u nexus wget -P /var/lib/nexus/models/ \
  "https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF/resolve/main/qwen2.5-7b-instruct-q4_k_m.gguf"

# 9+ GB VRAM GPU (recommended)
sudo -u nexus wget -P /var/lib/nexus/models/ \
  "https://huggingface.co/Qwen/Qwen2.5-14B-Instruct-GGUF/resolve/main/qwen2.5-14b-instruct-q4_k_m.gguf"
```

### 4.3 Update nexus.toml to use the model

Edit `/etc/nexus/nexus.toml`, change the `[llm]` section:

```toml
[llm]
provider        = "llamacpp"
llamaserver_bin = "/usr/local/bin/llama-server"
model_path      = "/var/lib/nexus/models/qwen2.5-7b-instruct-q4_k_m.gguf"
n_parallel      = 4
n_gpu_layers    = -1
n_ctx           = 4096
llamaserver_addr = "127.0.0.1"
llamaserver_port = 18080
atlas_guard     = true
```

Restart Nexus:
```bash
sudo systemctl restart nexus
```

---

## Part 5: Build the Sentinel (Agent)

### 5.1 Navigate to the agent directory

```bash
cd ../nebula-agent   # from nebulasentinel/nebula-agent
```

### 5.2 Build for the current platform

```bash
cargo build --release
```

Output binary: `target/release/nebula-agent`

### 5.3 Build for other platforms (cross-compilation)

Install the `cross` tool for cross-compilation:

```bash
cargo install cross
# cross requires Docker — install Docker if not present:
# https://docs.docker.com/engine/install/
```

**Linux ARM64** (Raspberry Pi 4, AWS Graviton, Oracle Ampere):
```bash
rustup target add aarch64-unknown-linux-gnu
cross build --release --target aarch64-unknown-linux-gnu
# Output: target/aarch64-unknown-linux-gnu/release/nebula-agent
```

**Windows x86_64:**
```bash
rustup target add x86_64-pc-windows-gnu
cross build --release --target x86_64-pc-windows-gnu
# Output: target/x86_64-pc-windows-gnu/release/nebula-agent.exe
```

**macOS Apple Silicon** (requires macOS host or osxcross):
```bash
rustup target add aarch64-apple-darwin
# On macOS:
cargo build --release --target aarch64-apple-darwin
```

### 5.4 Stamp binaries with platform name

Rename each binary so operators know which one to use:

```bash
cp target/release/nebula-agent                                    nebula-agent-linux-x86_64
cp target/aarch64-unknown-linux-gnu/release/nebula-agent          nebula-agent-linux-aarch64
cp target/x86_64-pc-windows-gnu/release/nebula-agent.exe          nebula-agent-windows-x86_64.exe
```

### 5.5 Host binaries on Nexus for one-line deployment

Copy the binaries to the Nexus distribution directory so agents can be
downloaded directly from the Nexus server:

```bash
scp nebula-agent-linux-x86_64   nexus-user@your-nexus:/var/lib/nexus/dist/
scp nebula-agent-linux-aarch64  nexus-user@your-nexus:/var/lib/nexus/dist/
# etc.
```

Once in place, the Nexus serves them at:
```
GET https://your-nexus:8443/api/install              # list available platforms
GET https://your-nexus:8443/api/install/linux-x86_64  # download binary
GET https://your-nexus:8443/api/install/linux-x86_64.sh  # install script
```

---

## Part 6: Deploy Sentinels

### 6.1 Method A: One-line install (recommended)

Once binaries are on the Nexus, install any agent in one command:

```bash
# On the target host (as root):
curl -sSfk "https://YOUR-NEXUS-IP:8443/api/install/linux-x86_64.sh" | \
  NEXUS_ATC_URL="https://YOUR-NEXUS-IP:9443" sudo bash
```

This downloads the binary, creates directories, writes the config, installs
the systemd unit, and starts the service automatically.

Check it worked:
```bash
sudo systemctl status nebula-agent
sudo journalctl -u nebula-agent -f
```

The agent should appear in the Nexus UI under **Sentinels** within 15 seconds.

---

### 6.2 Method B: Manual install (step by step)

Use this if Method A doesn't work or you need custom configuration.

**Step 1 — Copy the binary to the target host:**
```bash
scp nebula-agent-linux-x86_64 user@target-host:/tmp/
ssh user@target-host
```

**Step 2 — Install on the target host:**
```bash
# All of these run as root on the target host
sudo cp /tmp/nebula-agent-linux-x86_64 /usr/local/bin/nebula-agent
sudo chmod 750 /usr/local/bin/nebula-agent
```

**Step 3 — Create directories:**
```bash
sudo mkdir -p \
    /etc/nebula \
    /etc/nebula/certs \
    /etc/nebula/rules/yara \
    /etc/nebula/rules/sigma \
    /etc/nebula/rules/suricata \
    /etc/nebula/rules/snort \
    /etc/nebula/rules/wazuh \
    /var/lib/nebula \
    /var/lib/nebula/quarantine \
    /var/lib/nebula/forensics \
    /var/lib/nebula/alerts

sudo useradd -r -s /sbin/nologin -d /var/lib/nebula nebula-agent 2>/dev/null || true
sudo chown -R nebula-agent:nebula-agent /var/lib/nebula
```

**Step 4 — Copy the Nexus TLS certificate:**
```bash
# Copy the nexus-ca.pem you saved in Step 3.9
sudo cp nexus-ca.pem /etc/nebula/certs/nexus-ca.pem
sudo chmod 644 /etc/nebula/certs/nexus-ca.pem
```

**Step 5 — Write the agent config:**
```bash
sudo tee /etc/nebula/nebula-agent.toml << 'TOML'
# /etc/nebula/nebula-agent.toml

hostname = ""         # Leave blank to auto-detect from system hostname
agent_id  = ""        # Leave blank — auto-generated and persisted on first run
mode      = "detect"  # detect | protect | audit

[nexus]
enabled              = true
url                  = "https://YOUR-NEXUS-IP:9443"
tls_verify           = true
ca_cert_path         = "/etc/nebula/certs/nexus-ca.pem"
report_interval_secs = 15

[llm]
enabled = true
mode    = "nexus_proxy"   # Relay LLM queries to Nexus Whisper (no local model needed)

[collector]
backend = "procmon"   # procmon works without eBPF — use "ebpf" if your kernel supports it

[anomaly]
heuristic_enabled    = true
chain_detection      = true
chain_window_secs    = 300
confidence_threshold = 60.0

[rules]
yara_dir          = "/etc/nebula/rules/yara"
sigma_dir         = "/etc/nebula/rules/sigma"
suricata_rules_dir = "/etc/nebula/rules/suricata"
snort_rules_dir   = "/etc/nebula/rules/snort"
wazuh_rules_dir   = "/etc/nebula/rules/wazuh"
auto_reload       = true

[response]
auto_kill_threshold       = 95.0
auto_quarantine_threshold = 90.0
auto_isolate_threshold    = 85.0

[forensics]
enabled    = true
output_dir = "/var/lib/nebula/forensics"

[retro]
enabled     = true
on_new_rule = true
log_sources = ["/var/log/auth.log", "/var/log/syslog"]

[self_protect]
enabled                      = true
binary_hash_check            = true
config_tamper_detection      = true
anti_debug                   = true
protect_pid                  = true
prompt_injection_detection   = true
watchdog_interval_secs       = 30
integrity_check_interval_secs = 60

[gossip]
enabled = true
port    = 9999
TOML

# Replace YOUR-NEXUS-IP with the actual IP or hostname
sudo sed -i "s/YOUR-NEXUS-IP/ACTUAL-NEXUS-IP-OR-HOSTNAME/" /etc/nebula/nebula-agent.toml
```

**Step 6 — Create the systemd service:**
```bash
sudo tee /etc/systemd/system/nebula-agent.service << 'UNIT'
[Unit]
Description=NebulaSentinel Agent
Documentation=https://nebulasentinel.io
After=network-online.target auditd.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/nebula-agent \
    --config /etc/nebula/nebula-agent.toml
WorkingDirectory=/var/lib/nebula
Restart=on-failure
RestartSec=10
TimeoutStartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nebula-agent

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable nebula-agent
sudo systemctl start nebula-agent
```

**Step 7 — Verify:**
```bash
# Check service status
sudo systemctl status nebula-agent

# Watch live logs
sudo journalctl -u nebula-agent -f

# Check local status UI (open in browser on the host itself)
curl http://localhost:7443/api/status
```

You should see in the logs:
```
INFO  nebula_agent: NebulaSentinel agent starting
INFO  nebula_agent::collector: procmon collector started
INFO  nebula_agent::fim: inotify FIM watching 30 paths
INFO  nebula_agent::nexus_client: Registered with Nexus (agent-id: xxxx)
INFO  nebula_agent: Agent ready — polling Nexus every 15 seconds
```

Within 15 seconds, the agent appears in the Nexus UI → Sentinels tab.

---

## Part 7: Ansible — Deploy to Many Hosts at Once

For 10+ hosts, use this Ansible playbook:

```bash
# Create inventory file
cat > inventory.ini << 'EOF'
[servers]
prod-web-01 ansible_host=10.0.1.10
prod-web-02 ansible_host=10.0.1.11
db-primary  ansible_host=10.0.2.10

[all:vars]
ansible_user=ubuntu
ansible_become=yes

---

## Troubleshooting: cargo build fails with "HTTP2 framing layer" / crates.io download errors

If `cargo build` fails with an error like:

```
error: failed to get `asn1-rs` as a dependency ...
Caused by: download of as/n1/asn1-rs failed
Caused by: curl failed
Caused by: [16] Error in the HTTP2 framing layer
```

This is a **network transport problem**, not a code problem — cargo's libcurl HTTP/2
path is failing to reach crates.io. Both project folders now ship a
`.cargo/config.toml` that works around it by:

- using the **sparse** registry protocol,
- fetching git deps with the **git CLI** (`git-fetch-with-cli = true`),
- disabling HTTP **multiplexing**, and
- retrying failed downloads.

If you still hit the error, try these in order:

```bash
# 1. Force the sparse protocol globally for this shell
export CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_HTTP_MULTIPLEXING=false

# 2. Clear a possibly-corrupt registry cache
rm -rf ~/.cargo/registry/index/*
cargo build --release

# 3. If you are behind a proxy or have flaky connectivity, vendor deps once
#    on a machine WITH working network, then build offline:
cargo vendor vendor/                # creates a local copy of all crates
# add the printed [source] block to .cargo/config.toml, then:
cargo build --release --offline
```

---

## Configuration templates

Each component ships a commented template **inside its own folder**:

| Component | Template file | Copy to |
|-----------|---------------|---------|
| Nexus     | `nexus-server/nexus.toml.example`        | `nexus.toml` (or `/etc/nexus/nexus.toml`) |
| Agent     | `nebula-agent/nebula-agent.toml.example` | `config.toml` (or `/etc/nebula/config.toml`) |

```bash
# Nexus
cd nexus-server
cp nexus.toml.example nexus.toml
nano nexus.toml          # set api_master_key, paths, LLM model_path

# Agent
cd ../nebula-agent
cp nebula-agent.toml.example config.toml
nano config.toml         # set nexus.url, hostname (auto-detected if blank), mode
```

The Nexus looks for `nexus.toml` in its working directory by default, or pass
`--config /path/to/nexus.toml`. The "Config load failed, using defaults" warning
means it couldn't find the file at the expected path — copy the template there.

---

## llama-server install: CPU vs GPU on Linux

`--setup` downloads the prebuilt **Linux CPU** build of `llama-server` from the
llama.cpp GitHub releases (asset `llama-bXXXX-bin-ubuntu-x64.zip`). This is correct
even on CUDA machines, because **llama.cpp does not publish prebuilt Linux GPU
binaries** — the only CUDA assets in their releases are *Windows* DLL bundles
(`...-bin-win-cudart-...`), which contain no Linux binary. (An earlier build of the
setup mistakenly matched that Windows package on Linux, producing the
"binary not found in extracted archive. Contents: [cudart64_12.dll, ...]" error.)

The CPU build works on your 14B model but won't use the GPU. For GPU acceleration,
build llama.cpp from source:

```bash
git clone https://github.com/ggerganov/llama.cpp
cd llama.cpp
cmake -B build -DGGML_CUDA=ON          # NVIDIA; use -DGGML_HIPBLAS=ON for AMD ROCm
cmake --build build --target llama-server -j$(nproc)
sudo cp build/bin/llama-server /usr/local/bin/
# copy the shared libs too so the binary can find them:
sudo cp build/bin/*.so /usr/local/lib/ 2>/dev/null; sudo ldconfig
```

Then set `n_gpu_layers = -1` in `nexus.toml [llm]` to offload all layers to the GPU.

The setup also copies the build's shared libraries (`libllama.so`, `libggml*.so`)
into `/usr/local/lib` and runs `ldconfig`, so the CPU binary it installs can run.
If `llama-server --version` fails after install, run `ldd /usr/local/bin/llama-server`
to find any missing library.

---

## GPU acceleration: automatic CUDA build (v25r+)

As of v25r, `nexus-server --setup` automatically builds llama-server **from source
with CUDA** when it detects:
  1. an NVIDIA GPU (via nvidia-smi / driver), AND
  2. the CUDA compiler `nvcc` on PATH (install with `sudo apt install nvidia-cuda-toolkit`).

When both are present, setup clones llama.cpp to `/var/lib/nexus/llama-build`,
configures with `-DGGML_CUDA=ON`, compiles the `llama-server` target, and installs
the binary plus all backend libraries (including the critical `libggml-cuda.so`)
to `/usr/local/bin` and `/usr/local/lib`. It verifies the CUDA backend is present
before declaring success.

If `nvcc` is missing, setup installs the prebuilt CPU binary and prints the one
command needed to enable GPU support (`sudo apt install nvidia-cuda-toolkit`,
then re-run `--setup`).

The compile uses up to 4 parallel jobs. On low-RAM machines (≤16 GB) the CUDA
compile step can be memory-hungry; if it gets OOM-killed, build manually with
fewer jobs:

```bash
cd /var/lib/nexus/llama-build/llama.cpp
cmake --build build --config Release -j2 --target llama-server
```

Verify offload after install:

```bash
/usr/local/bin/llama-server --model /var/lib/nexus/models/<model>.gguf \
  --host 127.0.0.1 --port 18080 --n-gpu-layers -1
# look for: "ggml_cuda_init: found 1 CUDA devices" and "offloaded N/N layers to GPU"
# and confirm VRAM use in `nvidia-smi`
```

---

## OSCAL continuous control assessment (v25v+)

NebulaSentinel ingests NIST OSCAL catalogs and continuously assesses fleet
hardening posture against their controls.

**Workflow:**
1. Download an OSCAL catalog JSON (e.g. NIST SP 800-53 Rev5) from
   https://github.com/usnistgov/oscal-content (the `.../nist.gov/SP800-53/rev5/json/`
   catalog files).
2. Compliance tab → OSCAL Control Assessment → **Import Catalog** → select the JSON.
   The Nexus flattens all controls/enhancements into `oscal_controls`.
3. The Nexus ships built-in mappings from common 800-53 controls (AC-6, SC-5,
   SC-7, SC-39, SI-7, SI-16, CM-6, CM-7, …) to the agent's hardening checks.
   Add or override mappings via `POST /api/oscal/mappings {control_id, check_id}`.
4. The assessment rolls up each control across the fleet:
   - **satisfied** — all mapped checks pass on all reporting hosts
   - **not-satisfied** — all mapped checks fail
   - **partially-satisfied** — mixed pass/fail across hosts
   - **not-assessed** — no mapped checks, or no posture data yet
5. **Export Results** produces a standards-shaped OSCAL `assessment-results`
   JSON document (findings with target objective-ids + status), suitable for
   ingestion by GRC tooling.

**API:**
- `GET  /api/oscal/catalogs` — list imported catalogs
- `POST /api/oscal/catalogs/import` — body = raw OSCAL catalog JSON
- `GET  /api/oscal/catalogs/:id/controls` — controls in a catalog
- `GET  /api/oscal/catalogs/:id/assess` — fleet assessment + summary
- `GET  /api/oscal/catalogs/:id/results` — OSCAL assessment-results document
- `GET/POST/DELETE /api/oscal/mappings` — manage control→check mappings

To widen coverage, add more agent hardening checks (in nebula-agent
`src/posture/mod.rs`) and map them to the relevant controls.

---

## Malware detection enhancements (v26f)

### Real YARA scanning (pure Rust — no external dependencies)
The agent does genuine YARA evaluation via **yara-x** (the official pure-Rust
YARA rewrite by VirusTotal). NO libyara, NO C library, NO system dependency:
- **Default build**: lightweight string-matcher fallback.
- **`--features yara`**: full yara-x engine — string sets, hex patterns with
  wildcards, regex, and condition logic. Compiles from source and statically
  links like any other Rust crate. Build: `cargo build --release --features yara`

Three scan surfaces:
- **On-access**: when FIM detects a watched file changed, it's scanned immediately
  (hash blocklist + YARA + entropy) — no waiting for the periodic sweep.
- **Periodic file scan**: /tmp, /var/tmp, /dev/shm, /usr/local/bin every 15 min.
- **Memory scan**: every 30 min, scans running process memory via /proc/<pid>/mem
  for fileless/injected malware (MITRE T1055/T1620).

Drop .yar/.yara rules in `yara_dir` (default /etc/nebula/rules/yara).

### Intel → agent hash feed
The Nexus poll response now ships up to 500 SHA-256 malware hashes from the IOC
catalog (MalwareBazaar, etc.) to each agent, populating the local reputation
blocklist for fast offline hash matching. The blocklist updates at runtime as
new intel arrives — no agent restart needed.

### Nexus File Integrity view
New "File Integrity" tab (Detection group) and `/api/fim/events` endpoint surface
fleet-wide FIM events: which host, which file, severity, MITRE technique, and time.
Baselines are SHA-256 and held both agent-side and (via reported events) on the
Nexus, so a compromised agent can't silently rewrite integrity history.

---

## Expanded hardening + package descriptions (v26g)

### Hardening checks expanded + OSCAL mapping fixed
- `posture/mod.rs` hardening checks expanded from 6 to ~40 (SSH, sysctl
  network/memory, mount options, auditd, dangerous services, file perms, umask).
- **Critical OSCAL fix**: the built-in OSCAL control→check mappings now use the
  exact control IDs the agent's hardening engine actually emits
  (`sysctl:<key>`, `sshd:<Key>`, `file:<name>`, `svc:<name>`, `pam:<setting>`).
  Previously they used unprefixed IDs that never matched, so OSCAL reported
  everything "not-assessed". Now controls correlate correctly (AC-3/6/7/12/17,
  IA-2/5, SC-5/7/39, SI-7/16, CM-6/7, AU).
- `seed_mappings` now upserts idempotently on every startup (INSERT OR IGNORE),
  so corrected/new mappings take effect without wiping operator-added mappings.

### Package descriptions
- The agent now captures each package's description locally — no external
  lookup — via `dpkg-query -f '${binary:Summary}'` and `rpm --qf '%{SUMMARY}'`.
- Stored in `pkg_catalog.description` (with a migration for existing DBs),
  flows through `PackageEntry` → inventory → Nexus, and is shown in the Packages
  tab (as a subtitle under each package name and in the expanded detail row).
