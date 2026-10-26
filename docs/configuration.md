# Configuration & Deployment Reference

> The authoritative, current reference for configuring and running NebulaSentinel after the fix + security-hardening releases. Covers ports, the Nexus environment file, `nexus.toml`, the agent config, agent↔Nexus key matching, and every recently-added knob. See also **[Security Review & Hardening](91_SECURITY_REVIEW.md)** for *why* the fail-closed requirements exist.

## Ports & processes

| Port | Component | Purpose | Auth |
|------|-----------|---------|------|
| `9443` | Nexus | **ATC** — agents send telemetry / poll commands | **API key** (`X-Api-Key`) + TLS; optional mTLS |
| `8443` | Nexus | Operator UI / management API (~150 routes) | JWT + **RBAC** (admin for `/api/*` writes) |
| `7440` | Agent | Local read-only status dashboard | localhost only |
| `9999` | Agent | GOSSIP peer mesh (UDP) | optional AES-256-GCM PSK |

## Nexus — required configuration

### `/etc/nexus/environment` (secrets)

The Nexus **loads this file itself at startup** (also loaded by systemd via `EnvironmentFile=`). Format is `KEY=value`, one per line; single/double quotes are stripped; `#` comments ignored. Existing env vars are never overridden. Override the path with `NEXUS_ENV_FILE`.

| Variable | Required | Purpose |
|----------|----------|---------|
| `NEXUS_JWT_SECRET` | **Yes** | Signs session JWTs. ≥32 bytes, not the placeholder — **the Nexus refuses to boot otherwise.** |
| `NEXUS_API_MASTER_KEY` | **Yes** | ATC agent-channel key (port 9443). Must be non-placeholder — **fail-closed.** Overrides `api_master_key` in `nexus.toml`. |
| `NEXUS_ADMIN_PASSWORD` | No | Initial admin password. If unset, a **random** password is generated and printed **once** to stdout (never logged). |
| `NEXUS_DB_ENCRYPTION_KEY` | No | 64-hex (32-byte) AES-256-GCM key; when set, TOTP secrets are encrypted at rest. |
| `NEBULA_LLM_API_KEY` / `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / … | No | LLM provider key (only if using a cloud provider). |
| `NEXUS_LDAP_BIND_PW` | No | LDAP service-account password (if `[auth]` uses LDAP). |
| `NVD_API_KEY` | No | Speeds up NVD CVE ingestion. |

Generate any key with: `openssl rand -base64 48`

**Two fail-closed checks** (both must be satisfied or the Nexus exits at startup):
1. `NEXUS_JWT_SECRET` set, ≥32 bytes, ≠ placeholder.
2. ATC key (`NEXUS_API_MASTER_KEY` **or** top-level `api_master_key` in `nexus.toml`) ≠ unset/placeholder.

### `nexus.toml` (non-secret settings)

Top-level fields (before any `[section]` — a top-level key placed under a section like `[llm]` becomes `llm.api_master_key` and is ignored):

```toml
# api_master_key = "..."     # prefer NEXUS_API_MASTER_KEY in the env file instead
db_path          = "/var/lib/nexus/nexus.db"
bind_addr        = "0.0.0.0"
atc_port         = 9443
mgmt_port        = 8443
self_signed_cert = true       # auto-generate a self-signed cert on first run
require_agent_cert = false    # set true + agent_ca_cert_path for mTLS on 9443
tls_san = []                  # extra cert SAN names/IPs (see TLS pinning below)
gossip_require_signed = false # true = reject GOSSIP envelopes that fail signature
                              #        verification (turn on once the fleet is fully
                              #        updated; agents sign automatically)

[llm]   # provider, model, endpoints
[auth]  # provider (local/ldap/oidc), role mappings, session hours
```

## LLM inference & multi-GPU (Nexus)

The Nexus server-side LLM (which powers **Whisper**) runs, by default, a managed local `llama-server` process. GPU behavior is set in `nexus.toml` under `[llm]`:

```toml
[llm]
provider     = "llamacpp"     # managed local llama-server (default)
n_gpu_layers = -1             # -1 = offload all layers to GPU, 0 = CPU only
# ── Multi-GPU (needs a CUDA/HIP-built llama-server) ──
split_mode   = "layer"        # "layer" (spread layers across all GPUs) | "row" | "none" (single GPU)
tensor_split = "0.5,0.5"      # per-GPU proportion (e.g. two equal GPUs); omit = VRAM-proportional
main_gpu     = 0              # primary GPU for small tensors / KV cache
```

- **Automatic:** with a CUDA/HIP-built `llama-server` and multiple GPUs visible, llama.cpp already **layer-splits across all of them** by default — you don't have to set anything. Use `CUDA_VISIBLE_DEVICES` to limit which GPUs are used.
- **Tunable:** `split_mode` / `tensor_split` / `main_gpu` let you control the split; unset fields fall back to llama.cpp defaults. These flags are ignored on a CPU-only build. They're also settable from the UI under **Settings → LLM** (Multi-GPU) — the UI writes them into `nexus.toml`.
- **Hot-reload:** saving LLM settings from **Settings → LLM** (or `PATCH /api/settings/llm`) applies them **live** for the managed `llama-server` — model, `n_gpu_layers`, and the multi-GPU knobs restart the local server in place, no Nexus restart. Switching the `provider` to/from an external backend (`vllm`/`ollama`/cloud) still needs a Nexus restart; the API response's `hot_reloaded` flag tells you which happened.
- **External servers:** set `provider = "vllm"` / `"ollama"` (or any OpenAI-compatible endpoint) to delegate to a server you run — e.g. **vLLM `--tensor-parallel-size N`** for true tensor parallelism — where multi-GPU is that server's concern.

## Agent — configuration (`/etc/nebula/config.toml`)

```toml
mode = "detect"                 # detect | protect | audit  (see Core Lifecycle)
virustotal_api_key = "..."      # optional; enables VirusTotal reputation (off if unset)

[collector]
# Alert deduplication (noise reduction). Identical alerts — same threat name +
# MITRE techniques + process — that fire repeatedly within the window are
# suppressed at the source; the alert re-emits after the window with a
# "recurred N×" note. Skips the full downstream cascade for duplicates.
dedup_enabled           = true  # default on; false = forward every firing
deduplicate_window_secs = 60    # suppression window in seconds (0 also disables)

# ── Detection-time allowlist / suppression ──
# Known-good matches are dropped or downgraded BEFORE any response, forensics,
# dedup, or Nexus forwarding. A rule matches only when EVERY specified field
# matches (unspecified = wildcard); an all-empty rule is ignored. Fields
# process/path/threat_name are globs (`*`), case-insensitive; technique is an
# exact MITRE id that must be present on the threat.
[[detection.suppress]]
process     = "MsMpEng.exe"      # Windows Defender scanner
action      = "drop"             # "drop" (discard) | "downgrade" (force Info)
reason      = "known AV scanner"

[[detection.suppress]]
path        = "/opt/backup/*"    # approved backup agent tree
technique   = "T1005"            # only when flagged for data-from-local-system
action      = "downgrade"
reason      = "scheduled backup, expected file access"

[nexus]
url         = "https://<nexus-host>:9443"
api_key     = "<MUST EQUAL the Nexus NEXUS_API_MASTER_KEY>"
tls_verify  = true
ca_cert_path = "/etc/nebula/certs/nexus.pem"   # pin the Nexus cert (recommended)

[rules]
auto_reload         = true      # hot-reload rule dirs without restart
reload_interval_secs = 300

[forensics]
encrypt_artifacts  = true
encryption_key_hex = "..."      # optional 64-hex AES-256-GCM key (else machine-derived)

[gossip]
enabled        = true
port           = 9999
encryption     = false          # off by default; set true AND encryption_key to encrypt the mesh
encryption_key = "..."          # 64-hex PSK, same on all peers (required for encryption; else plaintext)
```

### Agent ↔ Nexus key matching (common first-run gotcha)

The agent's `[nexus] api_key` **must exactly equal** the Nexus's `NEXUS_API_MASTER_KEY`. If they differ, the agent gets **401 on port 9443** (that's the ATC auth working as intended).

### TLS pinning

The default Nexus cert is self-signed. Point the agent's `[nexus] ca_cert_path` at the Nexus's cert PEM to **pin** it (trusts only that cert; rejects anything else). If you can't pin, set `tls_verify = false` explicitly (logged, lab-only).

**Hostname/SAN must match.** With `tls_verify = true`, the hostname in the agent's `[nexus] url` must appear in the Nexus cert's SAN. The auto-generated cert covers `nexus`, `localhost`, `127.0.0.1`, the Nexus's **system hostname**, and a concrete `bind_addr` automatically. If agents connect by any other name/IP (e.g. `nexus.corp.local`), add it to the Nexus config and **regenerate the cert**:

```toml
# nexus.toml (top-level)
tls_san = ["nexus.corp.local", "10.0.0.5"]
```
```bash
rm /var/lib/nexus/certs/nexus.crt   # force regeneration on next start
# then restart the Nexus and copy the new cert to agents' ca_cert_path
```
Symptom of a mismatch: the agent log shows a TLS `NotValidForName`/`certificate` error and the 7440 UI shows Nexus **Offline** (amber). Note that "Offline" (configured Nexus unreachable) and "Standalone" (no Nexus configured) are both normal states — the agent keeps detecting locally and the dashboard shows live standalone telemetry (rules, IOCs, LLM, collector, posture) either way.

## GOSSIP mesh encryption key

The agent↔agent GOSSIP mesh (UDP :9999) is encrypted with a shared AES-256-GCM PSK. You don't have to configure anything for a fleet — it works out of the box:

- **Default (fleet):** on first request the **Nexus generates a fleet PSK**, persists it (`settings.gossip_psk`), and hands it to each agent over the authenticated, TLS-pinned ATC channel (`GET /api/atc/gossip/key`). All agents converge on the same key and the mesh is encrypted automatically.
- **Custom fleet key (Nexus):** set `NEXUS_GOSSIP_KEY` in `/etc/nexus/environment` to pin a key you control (not persisted; overrides the generated one):
  ```bash
  # generate a 32-byte (64-hex) key
  openssl rand -hex 32
  # /etc/nexus/environment
  NEXUS_GOSSIP_KEY='<64 hex chars>'
  ```
- **Custom per-agent key:** set `[gossip].encryption_key` in the agent config. A local key **always wins** — the agent skips the Nexus fetch. Use this for standalone agents (no Nexus) or to segment a subset of peers onto their own key. All peers that must talk to each other need the **same** key.
- **Standalone agents** (no Nexus) are plaintext unless you set a local `[gossip].encryption_key`.

Rotate by changing `NEXUS_GOSSIP_KEY` (or `settings.gossip_psk`) and restarting agents; all peers must share the new key simultaneously.

## Operating modes (agent)

`detect` (default — logs the response it *would* take) · `protect` (active enforcement; destructive playbook/response actions run only here) · `audit` (silent log-only) · **Legacy** (automatic fallback when the embedded LLM fails to load — detection continues, AI enrichment skipped). Full detail in **[Core Lifecycle](agent__01_core_lifecycle.html)**.

## Building

Non-workspace multi-crate repo — build each crate separately (a C++ toolchain is needed for the agent's default embedded llama.cpp):

```bash
cd /nebulasentinel/nexus-server && cargo build --release
cd /nebulasentinel/nebula-agent && cargo build --release
# Agent without the embedded LLM (no C++ toolchain):
#   cargo build --release --no-default-features --features ebpf-stub,inventory,gossip
```

## Launch

- **systemd** — ensure the Nexus unit has `EnvironmentFile=/etc/nexus/environment`, then `sudo systemctl daemon-reload && sudo systemctl restart nexus`.
- **Directly** — the Nexus self-loads `/etc/nexus/environment`, so `./nexus-server` works; or source it into your shell first: `set -a; . /etc/nexus/environment; set +a`.

## First-run checklist

1. `openssl rand -base64 48` → set `NEXUS_JWT_SECRET` and `NEXUS_API_MASTER_KEY` in `/etc/nexus/environment`.
2. (Optional) `NEXUS_ADMIN_PASSWORD`, `NEXUS_DB_ENCRYPTION_KEY`.
3. Build + start the Nexus; note the generated admin password if you didn't set one.
4. On each agent, set `[nexus] url`, `api_key` (= `NEXUS_API_MASTER_KEY`), and `ca_cert_path` (pin the Nexus cert).
5. Start agents in `detect` mode; move to `protect` once tuned.
