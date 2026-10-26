# Architecture & Data Flow

## What NebulaSentinel is

NebulaSentinel is a Rust-based EDR / security platform built around **Autonomous Threat Cognition (ATC)**: a local LLM runs *inside the agent process* and enriches detections on the host itself, so raw evidence never leaves the machine (air-gap / sovereign-ready). The LLM is an **enrichment layer, not a gate** — a wrong or unavailable verdict degrades analysis quality but never suppresses a detection; detection always forwards.

## Components

| Component | Language | Role |
|-----------|----------|------|
| **nebula-agent** | Rust | Host agent: telemetry collection → parallel detection engines → correlation/fusion → embedded-LLM ATC enrichment → response. Runs standalone or fleet-managed. |
| **nexus-server** | Rust (axum + SQLite) | Central server: dual-TLS API, fleet management, rule/intel distribution, compliance, reporting, server-side LLM (Whisper), threat modeling. Optional. |
| **nebula-gossip** | Rust (crate) | Shared GOSSIP wire envelope (`schema: gossip/1`), payload types, and ed25519 signing used by both components. |

## Deployment topologies

- **Standalone** (`[nexus].enabled = false`): the agent detects, enriches with its local LLM, records to the localhost status UI (7440), and enforces — no server required.
- **Fleet**: agents register with a Nexus, forward enriched telemetry over the ATC channel, receive rules/intel/commands, and share indicators over GOSSIP. An offline queue buffers events when the Nexus is unreachable and drains on reconnect.

## Ports

| Port | Bind | Purpose |
|------|------|---------|
| `9443` | Nexus | ATC channel — agents forward enriched telemetry / poll commands (API-key auth) |
| `8443` | Nexus | Operator UI / management API (JWT + RBAC) |
| `7440` | Agent (127.0.0.1) | Local read-only status dashboard |
| `9999` | Agent | GOSSIP peer mesh (UDP) |

## Agent pipeline

```
 collectors (eBPF / audit / wineventlog / procmon)
        │  RawEvent stream
        ▼
 detection engines (run inline, fixed precedence):
   ransomware > zero-day > DLP > APT > anomaly > baseline
   + rules (YARA / Sigma / Wazuh), reputation, network, FIM
        │  ThreatEvent (merged)
        ▼
 alert-dedup gate ── collapse identical alerts within a window
        │  (duplicates dropped; recurrence counted)
        ▼
 ATC enrichment (embedded llama.cpp)  ── async, best-effort
        │  ± confidence, MITRE refinement, auto rules
        ▼
 response (Detect / Protect / Audit) ── kill / quarantine / isolate / block
        │
        ├─▶ local status UI (7440)
        ├─▶ Nexus (ATC channel, always-forward)
        └─▶ GOSSIP (signed envelopes to peers + Nexus)
```

**Noise reduction.** Layers that keep the operator feed signal-dense without ever discarding a genuine detection:

- **Detection-time allowlist** (`[detection] suppress`, applied first): operator-defined known-good matches on `process` / `path` / `technique` / `threat_name` (glob, all-specified-must-match). Action `drop` discards the alert entirely; `downgrade` forces it to `Info`/low-confidence for the record. This encodes *known-benign* (a backup agent, an AV scanner) — distinct from the response `isolation_allowlist`, which only guards destructive actions.
- **Alert-dedup gate** (before enrichment): identical alerts — same `threat_name` + MITRE techniques + process — that fire repeatedly within `deduplicate_window_secs` (default 60s) are suppressed at the source, skipping the entire downstream cascade (response, forensics, status UI, gossip, Nexus). After the window the alert re-emits with a `recurred N×` note, so a persistent threat stays visible without flooding. Tunable via `[collector] dedup_enabled` / `deduplicate_window_secs`.
- **ATC benign-suppression** (during enrichment): when the LLM judges an alert benign it is *downgraded* to `Info` (confidence floored, `[ATC-SUPPRESSED]` prefix) rather than dropped — the Nexus/UI filter it out of the active feed by default but it stays findable for review.

**Detection fidelity.** Rule matches (YARA / Sigma / Wazuh) are scored by the rule's **declared severity**, not a flat bump: the strongest matching rule elevates the threat's severity floor, raises confidence proportionally (critical +25 → info +2, applied as a max not a sum), and folds in the rule's MITRE technique.

Background loops (FIM on-access scanning, network beacon detection, periodic scanners for secrets/container/IaC/reputation/YARA-memory) and the detector channel drains run as async tasks spawned **before** the blocking main event loop, so they are live throughout the agent's runtime.

## Protocols

- **ATC channel** (`/api/atc/*`, `/api/agents/register`): the agent registers (including its GOSSIP public key), streams enriched `ThreatEvent`s and posture, and **polls** for queued commands, new rules (OS-aware deltas), and intel (IOC blocklist). Authenticated by API key; optional mTLS.
- **GOSSIP** (`schema: gossip/1`): a single JSON `Envelope` (identity + provenance + trust + payload) with 11 message types. Agents **sign** envelopes with a persistent ed25519 key; the Nexus **verifies** against a registered-key registry. Facts/IOCs propagate freely; executable rules are gated to human review. Corroboration rises as independent origins report the same `dedup_key`.

## Operating modes (agent)

`detect` (default — logs the response it *would* take, no action) · `protect` (active enforcement) · `audit` (silent log-only) · **Legacy** (automatic fallback when the embedded LLM fails to load — detection continues, AI enrichment skipped).

## Build & feature flags (summary)

- The agent's default build compiles **embedded llama.cpp** (`embedded-llm`); use `cpu-portable` / `cpu-avx2` to pick a safe CPU baseline (avoids SIGILL from `-march=native`). Other Cargo features: `cuda`, `yara` (pure-Rust yara-x), `ebpf` / `ebpf-stub`, `inventory`, `gossip`.
- Cross-platform, including a Windows agent (`wineventlog` collector).
- Both components pin security-critical crates and gate crypto behind the gossip crate's default-on `signing` feature.

See the **[Configuration & Deployment](91_CONFIGURATION.md)** reference for setup, and the **[Security Model](90_SECURITY_MODEL.md)** for the trust boundaries.
