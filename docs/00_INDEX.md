# NebulaSentinel — System Documentation

> Current-state technical documentation for the NebulaSentinel platform, generated from the live source. Every manual uses `path:line` references back to the code.

NebulaSentinel is a Rust-based EDR / security platform built around **Autonomous Threat Cognition (ATC)** — a local LLM enriches detections on the host itself, so raw evidence never leaves the machine. Detection always runs and forwards; the LLM only enriches.

Start with **[Architecture & Data Flow](01_architecture.html)** for the big picture, **[Security Model](90_SECURITY_MODEL.html)** for the trust boundaries, and **[Configuration & Deployment](91_CONFIGURATION.html)** to run it.

## Components

| Component | Role |
|-----------|------|
| **nebula-agent** | Host agent: collection → parallel detection → correlation → embedded-LLM enrichment → response. Standalone or fleet-managed. |
| **nexus-server** | Central server (axum + SQLite): dual-TLS API, fleet management, rule/intel distribution, compliance, reporting, server-side LLM, threat modeling. |
| **nebula-gossip** | Shared crate: the signed GOSSIP wire envelope + ed25519 signing used by both. |

## Ports

`9443` ATC (agent → Nexus, API-key auth) · `8443` MGMT (operator UI/API, JWT + RBAC) · `7440` agent local status UI (localhost) · `9999` GOSSIP mesh (UDP).

## Operating modes (agent)

`detect` (default — logs the response it *would* take) · `protect` (active enforcement) · `audit` (silent log-only) · **Legacy** (auto-fallback when the embedded LLM can't load; detection continues, enrichment skipped).

## Capability map

### Agent — detection
Engines run inline with fixed precedence **ransomware > zero-day > DLP > APT > anomaly > baseline**; baseline fuses as corroboration.

- **Anomaly** — MITRE ATT&CK heuristics (base + extended + v15), 0–100 capped score, 35 attack-chain patterns, ATLAS ML techniques.
- **Ransomware** — file-I/O based (extensions, canaries, entropy ≥7.5, mass-write rate); auto-kills in Protect mode.
- **Zero-day** — exploitation-by-effect via process ancestry + `/proc/PID/maps` scanning (Linux).
- **APT** — long-dwell chain correlation + statistical slow-C2 beacon detection.
- **Baseline** — unsupervised ML (Welford + Half-Space Forest, 14-dim); off unless `anomaly.ml_enabled`.
- **FIM / DLP / Secrets** — integrity monitoring with on-access YARA; DLP exfil-command, bulk-access, large-transfer, and **content classification** (`scan_content` on writes); 16 credential regexes.
- **YARA** — pure-Rust yara-x, file + process-memory scanning.
- **Sigma** — **full multi-category** evaluator (process/network/dns/file/image-load/auth) with field aliases and `contains`/`startswith`/`endswith`/`re`/`all` modifiers.
- **Network** — beacon (coefficient-of-variation), DNS-tunnel entropy, DGA/fast-flux, cloud-metadata access.
- **Reputation** — SHA-256 blocklist (live from Nexus), YARA, ELF entropy; **VirusTotal** when `virustotal_api_key` is set.

### Agent — collection, response, enrichment
- **Collectors** — eBPF (aya/CO-RE) · auditd · Windows event log · universal procmon fallback.
- **Containers / Inventory / Forensics** — Trivy/Grype CVE scan + runtime **drift detection**; SQLite asset catalog; confidence-tiered evidence bundles **encrypted with AES-256-GCM**.
- **Response** — Detect/Protect/Audit gating; kill ≥95 / quarantine ≥90 / isolate ≥85; firewall auto-detected (nftables → firewalld → ufw → iptables → WindowsFirewall).
- **NetGuard** — reputation-driven blocking + fail2ban brute-force auto-block (Protect-gated).
- **Playbooks** — 30 MITRE-triggered playbooks; firewall attached, destructive steps **gated to Protect mode**.
- **Embedded LLM** — in-process llama.cpp (Phi-3.5-mini / Qwen2.5-7B, VRAM auto-select), verdict-memory cache, crash-isolated pre-flight, `remote_atc` cascade.

### Nexus
- **API** — dual-TLS: ATC agent endpoints (API-key authenticated) + operator/MGMT endpoints (JWT + **RBAC**, admin-gated writes).
- **Auth** — local/argon2, LDAP, OIDC, PIV mTLS, TOTP (encrypted at rest), WebAuthn; **fail-closed** on placeholder JWT/API secrets; self-loads `/etc/nexus/environment`.
- **Intel & rules** — 5 IOC feeds → agent blocklist; proposal→approval→OS-aware delta rule delivery; deterministic Suricata synthesis; MITRE ATLAS guard; STRIDE/DREAD threat modeling.
- **Whisper** — agentic LLM operator: an LLM tool-use loop reads platform data (agents, threats, rules, IOCs) and **proposes** agent actions (isolate, forensics, block, deploy rule, …) that the admin **confirms** before they run; actions flow through the normal command queue (agent mode-gating still applies).
- **Compliance & reporting** — OSCAL (NIST 800-53/171), OVAL, benchmark import (quick-xml 0.41); ~10 HTML/JSON report generators (**HTML-escaped**); Slack/Email/Webhook/PagerDuty/Teams notifications.
- **GOSSIP** — verifies signed envelopes against a key registry (`sig_ok` = real verification); optional hard-reject; verified badge in the Ecosystem UI.

## The manuals

| Section | Pages |
|---------|-------|
| **Overview** | System Overview (this page), Architecture & Data Flow |
| **Agent** | Core & Configuration · Detection (Behavioral) · Detection (Files & Rules) · Network Defense · Response, Posture & Hardening · Collection & Forensics · Embedded LLM & GOSSIP |
| **Nexus** | Core, API & Auth · Intel, Rules & Synthesis · Compliance & Reporting |
| **Gossip** | GOSSIP Protocol & Signing |
| **Security** | Security Model |
| **Operations** | Configuration & Deployment |
