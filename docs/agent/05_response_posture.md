# NebulaSentinel Agent — Response, Posture, Hardening & Orchestration

Fresh, current-state technical documentation of the `nebula-agent` defensive
action, posture-assessment, hardening, self-protection, and IaC/retro modules.
Sourced directly from `/nebulasentinel/nebula-agent/src`.

This manual covers the "act and assess" half of the agent: what it does after a
threat is detected (response engine, playbooks), how it measures the host's
security posture (compliance frameworks, vulnerability scanning), how it advises
and applies system hardening, how it protects itself from tampering, and how it
scans infrastructure-as-code and hunts historical data.

---

## 0. Cross-cutting concept: Agent modes

Three operating modes are defined in `config.rs:74` (`AgentMode`), parsed from
config `mode` (snake_case: `detect` | `protect` | `audit`):

| Mode | Response engine behaviour | Playbook destructive steps |
|------|---------------------------|----------------------------|
| `Detect`  | Logs "would" action, takes no action | Logged as "would", skipped |
| `Protect` | Executes actions subject to confidence thresholds | Executed |
| `Audit`   | Logs threat name only, never acts | (engine default is Detect) |

Both the `ResponseEngine` and the `PlaybookEngine` honour this mode so a
detect-mode agent never mutates the host. The mode is passed into the playbook
engine explicitly via `.with_mode(...)` (see §2).

---

## 1. `response/` — Response Engine

**File:** `src/response/mod.rs`

### Purpose
Executes defensive actions on the local host after a threat is confirmed. Modes
gate whether actions run; confidence thresholds gate *which* destructive actions
run in Protect mode. All network blocking is delegated to the firewall
abstraction (`src/firewall/mod.rs`).

### Key types
- `ResponseEngine { config: ResponseConfig, mode: AgentMode, firewall: Firewall }`
  — `Clone`; constructed with `ResponseEngine::new(config, mode, firewall)`.
- Actions dispatched from `crate::types::ResponseAction` (`types.rs:149`):
  `Monitor`, `Alert`, `KillProcess(u32)`, `QuarantineFile(String)`,
  `IsolateHost`, `BlockIp(String)`, `CollectForensics`, `Rollback`.

### Capabilities — response actions & thresholds
`execute(threat, event)` dispatches by mode. In Protect mode, `execute_action`
enforces per-action confidence gates (`execute_action`, `response/mod.rs:46`):

| Action | Threshold gate | Config key (default) | Implementation |
|--------|----------------|----------------------|----------------|
| `KillProcess(pid)` | `confidence >= auto_kill_threshold` | `auto_kill_threshold` = **95.0** | `kill -9 <pid>`; refuses `pid <= 1`; on failure writes `/proc/<pid>/oom_score_adj = 1000` as OOM fallback |
| `QuarantineFile(path)` | `confidence >= auto_quarantine_threshold` | `auto_quarantine_threshold` = **90.0** | Moves file to `/var/lib/nebula/quarantine/<sanitized>.quarantine` (rename, else copy+remove); appends to `MANIFEST.log` |
| `IsolateHost` | `confidence >= auto_isolate_threshold` | `auto_isolate_threshold` = **85.0** | Delegates to `firewall.isolate(isolation_allowlist)`; writes marker `/var/lib/nebula/ISOLATED`; idempotent (checks `is_isolated()`) |
| `BlockIp(ip)` | **no threshold gate** — always acts in Protect | — | `firewall.block_ip(ip)`; logs to `/var/lib/nebula/blocked_ips.log` |
| `Monitor` / `Alert` / `CollectForensics` / `Rollback` | — | — | No-op in `execute_action` (`_ => {}`) — handled elsewhere in the pipeline |

Other methods: `unblock_ip`, `undo_isolation` (removes `ISOLATED` marker),
`is_isolated()` (checks marker file).

### Config keys (`ResponseConfig`, `config.rs:337`)
| Key | Default | Meaning |
|-----|---------|---------|
| `auto_kill_threshold` | `95.0` | Min confidence to SIGKILL |
| `auto_quarantine_threshold` | `90.0` | Min confidence to quarantine a file |
| `auto_isolate_threshold` | `85.0` | Min confidence to isolate the host |
| `isolation_allowlist` | `[]` | IPs allowed through during isolation (should include the Nexus) |
| `rollback_enabled` | `true` | (parsed; consumed elsewhere) |
| `snapshot_on_threat` | `true` | (parsed; consumed elsewhere) |

### Entry points + main.rs wiring
- Constructed: `src/main.rs:322` — `ResponseEngine::new(cfg.response.clone(), cfg.mode.clone(), firewall.clone())`.
- Firewall/distro detected first at `src/main.rs:318-320`.
- Invoked in the main threat pipeline: `response_engine.execute(&threat, &event)` at **`src/main.rs:1370`** (runs before the slow LLM enrichment).
- Ransomware fast-path: `resp_r.execute_action(...)` at `src/main.rs:949` (only when mode is Protect).
- Direct `block_ip` from a Nexus command dispatch: `src/main.rs:1223`.

### External interactions
- `kill(1)` via `tokio::process`; `/proc/<pid>/oom_score_adj` writes.
- Local state under `/var/lib/nebula/` (quarantine dir + manifests, `ISOLATED`, `blocked_ips.log`).
- Firewall backend (nftables/firewalld/ufw/iptables/Windows) for block/isolate.

### Limitations
- `KillProcess` uses `kill -9` by PID; no cgroup-freeze; a fork-bombing parent may respawn children.
- Quarantine sanitizes `/` and `..` in names but is a flat directory; no encryption of quarantined files here.
- BlockIp has no confidence gate — any Protect-mode BlockIp action executes.
- Confidence is on a 0–100 scale throughout.

---

## 2. `playbook/` — Response Playbook Engine

**File:** `src/playbook/mod.rs`

### Purpose
Scenario-driven, multi-step orchestrated response. **30 built-in playbooks**
each with a trigger (confidence floor, severity floor, MITRE technique/tactic,
attack-chain-name match) and an ordered list of steps. Playbooks are
deliberately conservative — they collect forensic evidence *before* destructive
actions so evidence survives regardless of outcome.

### Key types
- `Playbook { name, description, priority: u32, trigger: PlaybookTrigger, steps: Vec<PlaybookStep>, enabled }`
- `PlaybookTrigger { min_confidence: f32, min_severity: String, techniques: Vec<String>, tactics: Vec<String>, chain_names: Vec<String>, require_protect: bool }`
- `PlaybookStep` (tagged enum, `#[serde(tag="action")]`): `CollectForensics{include_pcap,include_memory,reason}`, `KillProcess{reason}`, `BlockThreatIps{reason}`, `BlockIp{ip,reason}`, `QuarantineFile{reason}`, `IsolateHost{reason}`, `UndoIsolation`, `Wait{seconds}`, `EscalateToNexus{priority,note}`, `Log{message}`, `TriggerPostureScan`, `Notify{message}`.
- `PlaybookEngine { playbooks, firewall: Option<Arc<Firewall>>, mode: AgentMode }`.

### Firewall attachment & mode gating (the important current behaviour)
The engine is built and then decorated with two builder methods:
- `with_firewall(Arc<Firewall>)` (`playbook/mod.rs:95`) — attaches the real
  firewall so `IsolateHost`/`BlockIp`/`BlockThreatIps` steps actually enforce.
  Without it, `BlockThreatIps` falls back to a direct `iptables -A OUTPUT`
  (guarded by a strict IP parse to prevent argument injection), and
  `IsolateHost` warns "no firewall available".
- `with_mode(AgentMode)` (`playbook/mod.rs:100`) — sets the operating mode. In
  `execute()` (`playbook/mod.rs:809`), `enforce = matches!(mode, Protect)`.
  **Destructive steps (`KillProcess`, `BlockThreatIps`, `BlockIp`,
  `QuarantineFile`, `IsolateHost`, `UndoIsolation`) run only when
  `enforce` is true.** In Detect/Audit they log a `"would ..."` line and
  `continue`. Non-destructive steps (`CollectForensics`, `EscalateToNexus`,
  `Log`, `Wait`, `TriggerPostureScan`, `Notify`) always execute so the playbook
  still produces evidence and operator alerts in Detect mode.

Note: `PlaybookEngine::new()` defaults `mode` to `Detect` and `firewall` to
`None`; both are overridden by the builders at wiring time.

### Step execution details
- `KillProcess`: PID extracted from `threat.raw_event_ids` in `pid:N` form
  (`extract_pid_from_threat`); `kill -9`, OOM fallback on failure; skips `pid <= 1`.
- `BlockThreatIps`: blocks every `IOCType::Ipv4` IOC on the threat.
- `QuarantineFile`: quarantines every `IOCType::FilePath` IOC (rename into `/var/lib/nebula/quarantine/`).
- `IsolateHost`: calls `firewall.isolate(&[])` — **note the allowlist is empty here** (a code comment flags "Should come from config"); unlike the ResponseEngine, which passes `isolation_allowlist`.
- `Wait`: `tokio::time::sleep`.
- `Notify`: appends to `/var/lib/nebula/alerts/alerts.log`.
- `EscalateToNexus` / `TriggerPostureScan`: currently log/flag only — the threat already flows to Nexus by the normal path; posture scan is driven by the periodic task.
- `CollectForensics`: currently logs intent (`pcap`/`memory` flags + reason); full forensics is driven by the pipeline's forensics engine (see §on forensics in the detection manual).

### Matching (`match_playbook`, `playbook/mod.rs:760`)
Filters enabled playbooks where `confidence >= min_confidence` and
`severity >= min_severity`; technique match (prefix-aware `starts_with` both
directions) OR tactic match; then sorts by `priority` DESC, then
`min_confidence` DESC, and returns the single highest-priority match. Chain-name
matching is computed but currently non-blocking (does not exclude candidates).

### Enumerated playbooks (priority / min-conf / min-sev)
Selection is by **priority** (higher first), NOT the numeric order below.

| # | Name | Prio | MinConf | MinSev | Key MITRE |
|---|------|------|---------|--------|-----------|
| 1 | Critical Threat — Full Response | 10 | 92 | critical | (catch-all) |
| 2 | Webshell / RCE | 90 | 75 | high | T1190, T1505.003 |
| 3 | Ransomware — Emergency Response | 100 | 80 | high | T1486, T1490, T1485 |
| 4 | C2 Beacon — Block and Investigate | 70 | 80 | high | T1071.*, T1572 |
| 5 | Process Injection / Hollowing | 88 | 85 | high | T1055.* , T1620 |
| 6 | Privilege Escalation | 75 | 82 | high | T1068, T1548 |
| 7 | Credential Dump | 85 | 85 | high | T1003.* |
| 8 | Persistence Installed | 60 | 70 | high | T1053/1543/1546/1547 |
| 9 | Lateral Movement | 72 | 78 | high | T1021, T1550 |
| 10 | Data Exfiltration | 65 | 72 | high | T1048, T1567 |
| 11 | Container Escape | 92 | 88 | critical | T1611 |
| 12 | Rootkit / Kernel Module | 95 | 85 | critical | T1014, T1542 |
| 13 | DNS Tunneling | 62 | 75 | high | T1071.004, T1568.002 |
| 14 | Cryptominer | 50 | 85 | high | T1496 |
| 15 | DLP — Data Staging | 55 | 70 | medium | T1074, T1005, T1560 |
| 16 | Audit System Tampering | 80 | 78 | high | T1562, T1070 |
| 17 | Kerberos / AD Attack | 88 | 85 | critical | T1558.* |
| 18 | Supply Chain / Dependency Confusion | 58 | 68 | medium | T1195 |
| 19 | LOLBin Proxy Execution | 62 | 75 | high | T1218, T1127 |
| 20 | Firmware / Pre-OS Persistence | 98 | 82 | critical | T1542.* |
| 21 | Process Hollowing / Fileless | 93 | 88 | critical | T1055.012, T1620 |
| 22 | MFA Fatigue / Account Takeover | 83 | 80 | high | T1621, T1110.004 |
| 23 | DCSync / AD Domain Compromise | 97 | 90 | critical | T1003.006, T1558.001 |
| 24 | passwd/shadow Manipulation | 91 | 82 | critical | T1136.001, T1003.008 |
| 25 | Cloud Credential / Token Theft | 87 | 82 | high | T1552.005, T1528 (blocks IMDS 169.254.169.254) |
| 26 | Password Cracking / Offline Hash | 68 | 78 | high | T1110.002 |
| 27 | DoS / Resource Exhaustion | 76 | 78 | high | T1499, T1498 |
| 28 | Data Manipulation / Destructive Insider | 84 | 80 | high | T1565.* |
| 29 | Network Device / Infrastructure Attack | 89 | 80 | high | T1599–T1602 |
| 30 | Impersonation / Identity Fraud | 79 | 78 | high | T1656, T1606 |

Highest-priority playbooks are Ransomware (100), Firmware (98), DCSync (97),
Rootkit (95). Ransomware and a few others kill *first* then isolate; most others
collect forensics first.

### Entry points + main.rs wiring
- Built at **`src/main.rs:347-351`**:
  `PlaybookEngine::new(PlaybookEngine::default_playbooks()).with_firewall(Arc::new(firewall.clone())).with_mode(cfg.mode.clone())`.
- Matched + executed in the threat pipeline: `playbook_engine.match_playbook(&threat)` at **`src/main.rs:1373`**, then spawned `pb_exec.execute(&book_c, &threat_c)` at `src/main.rs:1378` (runs after the immediate ResponseEngine action).

### Limitations
- `IsolateHost` playbook step passes an empty allowlist (risk of self-lockout from the Nexus); the ResponseEngine path uses the configured allowlist.
- `EscalateToNexus`, `TriggerPostureScan`, `CollectForensics` steps are largely signalling/logging in this module; the heavy lifting is in the pipeline.
- Playbooks are hardcoded (`default_playbooks()`); there is no file-based playbook loader wired in.

---

## 3. `posture/` — Posture Assessment Engine

**File:** `src/posture/mod.rs`

### Purpose
Produces a `PostureReport`: an overall 0–100 score from per-framework compliance
scores minus a vulnerability penalty, plus a list of vulnerabilities and
hardening recommendations. Compliance frameworks are scored by concrete local
checks; vulnerabilities come from local OVAL/NVD feed files and dependency
auditors.

### Key types
- `PostureEngine` (unit struct; `new()`), `run_full_assessment(&AgentConfig) -> Result<PostureReport>`.
- `PostureReport` (from `types`): `overall_score`, `vulnerability_count`, `vulnerabilities`, `compliance_scores: HashMap<String,f32>`, `hardening_recommendations: Vec<HardeningItem>`, `inventory_summary`.
- Internal: `NvdEntry`, `OvalDefinition`, `InstalledPkg`.

### Capabilities

**Scoring** (`run_full_assessment`):
`overall_score = clamp(compliance_avg - vuln_penalty, 0, 100)`.
- `vuln_penalty` = Σ per-severity weights capped at 60: Critical 15, High 8, Medium 3, Low 1.
- `compliance_avg` = mean of per-framework scores (100 if none).
- A `vuln_count == 0` result is logged explicitly as normal (fleet CVE correlation runs on the Nexus from reported inventory), so 0 isn't read as a fault.

**Compliance frameworks** (`assess_framework`) — each returns a % from concrete checks:
| Framework key | Checks (examples) |
|---------------|-------------------|
| `nist_csf` | 5 core functions: inventory.db exists, firewall active, agent running, config exists, backup (assumed) |
| `cis_l1` / `cis_l2` | mount `noexec`/`nosuid`, avahi/cups off, ip_forward=0, send_redirects=0, rsyslog, sshd PermitRootLogin/PermitEmptyPasswords; L2 adds Protocol 2 + `kernel.randomize_va_space=2` |
| `pci_dss` | firewall, sshd root login, auditd, fail2ban, rp_filter, (encryption assumed) |
| `soc2` | auditd, agent, sshd root login, sudoers, (+1 assumed) |
| `iso27001` | firewall, auditd, sshd root login, tcp_syncookies (+2 assumed) |
| `disa_stig` | sshd root/MaxAuthTries/ClientAlive, ASLR, protected hard/symlinks, passwd perms (+1) |
| `hipaa` | auditd, sshd root login, firewall (+2 assumed) |
| (unknown) | 70.0 default |

**Vulnerability scanning** (`scan_vulnerabilities`):
1. Installed packages via `dpkg-query`.
2. OVAL: reads JSON files in the OVAL dir (per-distro path derived from `DistroInfo::detect()` if `oval_feed_path` empty). Uses segment-aware `version_lt` (fixes the old lexical bug that ordered 1.10 < 1.9).
3. NVD: reads JSON files in `nvd_feed_path`, matches `affected_packages`, dedups by CVE.
4. Dependency scan (if `dependency_scan_enabled`): shells out to `cargo audit --json` and `pip-audit --format json`.
5. Sorted by CVSS descending. `cvss_to_severity`: ≥9 Critical, ≥7 High, ≥4 Medium, >0 Low.

**Hardening items for the report** (`check_hardening_items`): on Windows delegates
to `crate::hardening::windows::assess()`; on Linux emits ~40 `HardeningItem`s
(SSH, sysctl/kernel, mount options, auditd/rsyslog, service attack-surface,
cron/file perms, umask) each evaluated by `assess_hardening_item`.

**Imported (operator-supplied) benchmark checks** — the pinned-TLS fetch:
`fetch_imported_checks(nexus_url, ca_cert_path, tls_verify)` GETs
`{nexus}/api/atc/imported-checks` using **`crate::tls::nexus_http_builder(...)`**
(the shared pinned-TLS helper, `src/tls.rs`) with a 10s timeout, then folds the
results through `crate::custom_checks::evaluate_all` into the hardening list.
Failures are non-fatal (agent runs built-in checks only). The tool ships no
proprietary benchmark content — definitions come from the Nexus.

### Config keys (`PostureConfig`, `config.rs:471`)
| Key | Default |
|-----|---------|
| `oscal_enabled` | `true` |
| `oscal_catalog_path` / `cis_benchmark_path` / `stig_content_path` | `None` |
| `nvd_feed_path` | `/var/lib/nebula/nvd/` |
| `oval_feed_path` | `/var/lib/nebula/oval/` |
| `scan_interval_secs` | (shared inventory-interval default) |
| `smart_scan` | `true` |
| `full_scan_max_age_hours` | `24` |
| `dependency_scan_enabled` | `true` |
| `compliance_frameworks` | `["nist_csf", "cis_l2"]` |
| `pkg_managers` | `["dpkg","rpm","cargo","pip"]` |

TLS-fetch inputs come from `[nexus]`: `nexus.url`, `nexus.ca_cert_path`, `nexus.tls_verify`.

### Entry points + main.rs wiring
- Constructed: `PostureEngine::new()` at **`src/main.rs:268`**.
- Periodic task interval `cfg.posture.scan_interval_secs` at `src/main.rs:429`, ticker at `src/main.rs:446`.
- `run_full_assessment(&cfg)` called at **`src/main.rs:525`** (and `src/main.rs:1570`); hardening items folded in, inventory attached, and `nexus.send_posture(&report)` at `src/main.rs:536`.

### External interactions
`dpkg-query`, `cargo audit`, `pip-audit`, `systemctl is-active`; reads
`/etc/ssh/sshd_config`, `/proc/sys/*`, `/proc/mounts`, file perms; HTTPS to the
Nexus (`/api/atc/imported-checks`, `send_posture`).

### Limitations
- Local CVE scanning only finds anything if OVAL/NVD JSON feed files are present or dependency manifests exist; primary CVE correlation is Nexus-side.
- Several compliance sub-checks are "assumed pass" (`pass += 1/2`) — encryption-at-rest, backups — so scores are optimistic on those controls.
- OVAL/NVD parsers consume pre-converted JSON, not raw XML feeds.
- Package inventory here is dpkg-only (rpm not enumerated in `get_installed_packages`).

---

## 4. `hardening/` — Hardening Advisor & Auto-Remediation

**Files:** `src/hardening/mod.rs`, `src/hardening/windows.rs` (Windows STIG/CIS submodule)

### Purpose
Assesses the host against CIS/STIG-style controls and can **auto-apply** the
safe, reversible fixes. Distinct from posture's report-oriented checks: this
engine is authoritative for hardening and its results override posture's
fallback checks when non-empty (`main.rs:527-532`).

### Key types
- `HardeningEngine { config: HardeningConfig }`; `assess() -> Vec<HardeningItem>`.
- `HardeningItem` (from `types`): `control_id`, `framework`, `title`, `status: ComplianceStatus`, `current_value`, `expected_value`, `remediation`, `auto_fixable`.

### Capabilities — Linux check groups (`assess_linux`)
| Group | Method | Examples | auto_fixable |
|-------|--------|----------|--------------|
| Kernel/sysctl | `check_kernel_params` | ASLR=2, tcp_syncookies=1, ip_forward=0, send_redirects=0, accept_source_route=0, protected hard/symlinks=1, dmesg_restrict=1, kptr_restrict=2, bpf_jit_harden=2 | yes |
| SSH daemon | `check_ssh` (gated on `sshd_hardening`) | PermitRootLogin no, PermitEmptyPasswords no, MaxAuthTries 3, ClientAliveInterval 300, ClientAliveCountMax 0, Protocol 2, X11Forwarding no, UsePAM yes, LoginGraceTime 60 | no |
| Filesystem | `check_filesystem` | /tmp, /var/tmp, /dev/shm mounted noexec,nodev,nosuid; /etc/passwd 644; /etc/shadow 640 | passwd/shadow: yes; mounts: no |
| Services | `check_services` | avahi-daemon, cups, nfs-server, rpcbind, telnet, rsh-server, ypbind should be inactive | no (unsafe to auto-disable) |
| User/PAM | `check_user_policies` | PASS_MAX_DAYS ≤ 90, PASS_MIN_DAYS ≥ 1 | no |
| Firewall | `check_firewall_installed` | nft/iptables/firewall-cmd/ufw present; distro-aware install remediation | no |

Windows path (`assess_windows` → `windows::assess()`) runs registry/secedit/
auditpol-based STIG/CIS checks instead of the Linux sysctl/sshd/mount checks.

**Auto-apply** (`assess()` when `config.auto_apply`): for each `Fail` item that
is `auto_fixable`, calls `apply_item`:
- `sysctl:*` → `sysctl -w key=value`
- `file:passwd_perms` → `chmod 644 /etc/passwd`
- `file:shadow_perms` → `chmod 640 /etc/shadow`

### Config keys (`HardeningConfig`, `config.rs:509`)
| Key | Default |
|-----|---------|
| `enabled` | `false` |
| `auto_apply` | `false` |
| `frameworks` | `["cis_l2", "stig"]` |
| `report_path` | `/var/lib/nebula/hardening/` |
| `sshd_hardening` | `true` |
| `kernel_hardening` | `true` |
| `firewall_audit` | `true` |

(`assess()` early-returns empty if `!enabled`.)

### Entry points + main.rs wiring
- Constructed: `HardeningEngine::new(cfg.hardening.clone())` at **`src/main.rs:297`**.
- Called in posture periodic task: `hardening_c.assess().await` at **`src/main.rs:517`**; results override `report.hardening_recommendations` at `src/main.rs:530-531`.

### External interactions
`sysctl`, `chmod`, `systemctl is-active`, `which`; reads `/proc/sys/*`,
`/proc/mounts`, `/etc/ssh/sshd_config`, `/etc/login.defs`, file metadata.

### Limitations
- Only sysctl and passwd/shadow perms are auto-fixed; SSH, mounts, services, PAM are advisory (require manual remediation), by design.
- `frameworks`/`kernel_hardening`/`firewall_audit` config keys don't granularly gate which checks run (only `enabled` and `sshd_hardening` gate).
- Service-disable is intentionally never auto-applied (too dangerous).

---

## 5. `self_protect/` — Self-Hardening & Tamper Protection

**File:** `src/self_protect/mod.rs`

### Purpose
Protects the agent process itself: binary/config integrity, anti-debug/anti-dump,
OOM exemption, privilege/umask hardening, a watchdog heartbeat, LLM prompt-
injection filtering (ATLAS AML.T0043), and an append-only tamper log.

### Key types
- `SelfProtection { config: SelfProtectConfig, binary_hash, config_hash }`; `initialize() -> Result<()>`.
- Free helpers: `hash_file_sync(path)`, `emit_tamper_alert_static(type, detail)`.

### Capabilities
- **Binary integrity**: SHA-256 of own executable at startup; re-checked every `integrity_check_interval_secs`; mismatch → `binary_tamper` alert.
- **Config integrity**: SHA-256 of `/etc/nebula/nebula-agent.toml`; drift logged and reference updated (config changes treated as legitimate).
- **Anti-debug (`check_debugger_active`)**: reads `TracerPid` in `/proc/self/status` (non-zero → ATLAS AML.T0043 alert) + a timing check (>10ms → anomaly warning).
- **Anti-dump / prctl (`apply_prctl_hardening`, Linux)**: `PR_SET_DUMPABLE=0` (blocks `/proc/PID/mem` writes, defeats hollowing against the agent) and `PR_SET_PTRACER=-1` (deny all ptrace).
- **Rlimits (`apply_rlimits`)**: `RLIMIT_CORE=0` (no core dumps → no credential leak), `RLIMIT_NOFILE=8192`.
- **Umask (`set_strict_umask`)**: `umask(0o077)` — all agent files owner-only.
- **OOM exemption (`protect_from_oom_killer`)**: writes `/proc/self/oom_score_adj = -1000` so the agent survives memory pressure (important during ransomware).
- **Watchdog (`start_watchdog`)**: writes `/var/run/nebula-agent.heartbeat` every `watchdog_interval_secs` for an external supervisor (systemd/script) to detect staleness.
- **Prompt-injection filter (`sanitize_llm_input`)**: matches a blocklist (role-override, mode-unlock/jailbreak, prompt-boundary tokens, exfiltration, indirect-injection phrases); a hit blocks the input (returns `None`) and logs `prompt_injection`; inputs > 8192 bytes are truncated.
- **Secure zeroing (`secure_zero`)**: volatile-write zero-fill + `SeqCst` fence for sensitive buffers.
- **Tamper log**: append-only `/var/lib/nebula/alerts/tamper.log` (O_APPEND).

### Config keys (`SelfProtectConfig`, `config.rs:590`)
| Key | Default |
|-----|---------|
| `enabled` | `true` |
| `watchdog_interval_secs` | `60` |
| `integrity_check_interval_secs` | `60` |
| `binary_hash_check` | `true` |
| `config_tamper_detection` | `true` |
| `adversarial_input_detection` | `true` |
| `model_poisoning_detection` | `true` |
| `prompt_injection_detection` | `true` |
| `anti_debug` | `true` |
| `protect_pid` | `true` |

### Entry points + main.rs wiring
- Constructed + started early: `SelfProtection::new(cfg.self_protect.clone())` at **`src/main.rs:177`**, then `self_protect.initialize().await?` at `src/main.rs:178` (before most other engines).

### External interactions
`/proc/self/status`, `/proc/self/oom_score_adj`, libc `prctl`/`setrlimit`/`umask`,
`/etc/nebula/nebula-agent.toml`, `/var/run/nebula-agent.heartbeat`,
`/var/lib/nebula/alerts/tamper.log`.

### Limitations
- prctl/OOM/rlimit hardening is Linux-only (no-op or partial elsewhere); some need root/`CAP_SYS_PTRACE`.
- Config path is hardcoded to `/etc/nebula/nebula-agent.toml`.
- The watchdog only writes a heartbeat; actual restart requires an external supervisor.
- Prompt-injection detection is substring/blocklist-based (evadable; may false-positive on benign text).

---

## 6. `custom_checks/` — Imported Benchmark Check Executor

**File:** `src/custom_checks/mod.rs`

### Purpose
Runs operator-imported, normalized benchmark checks (XCCDF/OVAL/YAML parsed
Nexus-side into engine-agnostic JSON) using the same primitives as the built-in
hardening engine. Ships only the executor; no proprietary benchmark content.

### Key types
- `ImportedCheck { id, title, benchmark, control_id: Option, kind, target, expected, remediation, severity }`.
- `evaluate_all(&[ImportedCheck]) -> Vec<HardeningItem>` → per-check `evaluate_one`.

### Capabilities — supported `kind`s
| kind | Primitive |
|------|-----------|
| `sysctl` | reads `/proc/sys/<key>`; token-wise comparison for multi-value sysctls |
| `file_perm` | POSIX mode ≤ expected octal (parses `0o`/octal forms) |
| `service_enabled` / `service_disabled` | `systemctl is-enabled` |
| `sshd` | directive parse of `/etc/ssh/sshd_config` (case-insensitive) |
| `mount_option` | option present in `/proc/mounts` entry |
| `file_exists` / `file_absent` | path existence |
| (other) | `NotApplicable` |

Imported checks are **advisory-only: `auto_fixable = false` always** (third-party
remediation is not vetted). `control_id` is prefixed `imported:<id>` unless a
mapped control id is supplied (for OSCAL rollup). Missing targets map to
`NotApplicable`, not `Fail`.

### External interactions / wiring
Invoked from posture's `run_full_assessment` via `crate::custom_checks::evaluate_all`
after `fetch_imported_checks` (see §3). No direct main.rs construction.

### Limitations
- Check breadth limited to the eight primitives above; richer XCCDF logic isn't executed locally.
- Unix-only for `file_perm` (returns `NotApplicable` elsewhere).

---

## 7. `iac/` — Infrastructure-as-Code Security Scanner

**File:** `src/iac/mod.rs`

### Purpose
Scans IaC (Terraform, Kubernetes YAML, CloudFormation, Dockerfiles) with native
Rust pattern checks plus optional delegation to external scanners, emitting
`IaCFinding`s that convert to `ThreatEvent`s (confidence 75.0).

### Key types
- `IaCScanner { scan_paths: Vec<String>, use_external_tools: bool }`; `scan_all() -> Vec<IaCFinding>`.
- `IaCFinding { file, line, resource, rule_id, title, description, severity: IaCSeverity, mitre_id, remediation, scanner }`; `to_threat_event()`.
- `IaCSeverity`: Critical | High | Medium | Low | Info.

### Capabilities — native checks
- **Dockerfile** (DF001–DF008): privileged/sudo/chmod 777 in RUN; curl|bash; uncleaned package cache; `ADD` with remote URL; secret in ENV; `:latest`; sshd in image; missing `USER` (runs as root).
- **Terraform** (TF001–TF008): public S3 ACL; `0.0.0.0/0` ingress (Critical on 22/3389/3306/5432/6379); unencrypted storage; IAM wildcard `*`; hardcoded credentials; CloudTrail log-validation off; VPC without flow logs; S3 backend without encryption.
- **Kubernetes YAML** (K8S001–K8S010): privileged; hostPID; hostNetwork; allowPrivilegeEscalation; runAsUser 0/root; literal secret value; ReadWriteMany PVC; default service account; `:latest`; missing resource limits.
- **CloudFormation** (CFN001–CFN003): S3 missing PublicAccessBlock; RDS unencrypted; SG opening 22/3389/3306/5432 to `0.0.0.0/0`.

### Capabilities — external scanner delegation (when `use_external_tools`, default true)
| Scanner | Invocation | rule_id |
|---------|-----------|---------|
| Checkov | `checkov -d <path> -o json --quiet` (parses `results.failed_checks`) | `CHECKOV` |
| tfsec | `tfsec <path> --format json --no-color` (only if `.tf` present) | `TFSEC` |
| Trivy config | `trivy config --format json --quiet <path>` (parses Misconfigurations) | `TRIVY-CONFIG` |
| kube-linter | `kube-linter lint <path> --format json` | `KUBELINTER` |

Findings are deduped by `(file, rule_id, line)`. File discovery walks recursively
(`walk_iac_files`), skipping `.git`, `node_modules`, `.terraform`, `vendor`,
`__pycache__`.

### Config keys / wiring
- `iac_paths: Option<Vec<String>>` (`config.rs:6`) — the scan roots (empty if unset).
- Constructed: `IaCScanner::new(cfg.iac_paths.clone().unwrap_or_default())` at **`src/main.rs:387`**.
- Periodic scan every **30 min** (180s initial delay) at `src/main.rs:1090-1105`; Critical/High findings are sent to the Nexus as threat events via `f.to_threat_event()`.

### Limitations
- Native checks are line/regex/substring heuristics (susceptible to false positives/negatives); external tools give richer coverage but must be installed.
- `to_threat_event()` uses a fixed confidence (75.0) and default tactic `initial_access` / technique `T1190` when no MITRE id is set.
- The separate empty `src/iac_scanner/` directory is not part of this module.

---

## 8. `retro/` — Retro-Hunting (one-shot historical scans)

**File:** `src/retro/mod.rs`

### Purpose
Runs **discrete, one-shot** historical hunts for a detection rule or an IOC over
retained data. Explicitly not an ambient loop — each call scans once, returns a
`HuntReport`, and exits. Re-runs are driven externally (operator/Nexus).

### Key types
- `RetroHunter { config: RetroConfig, yara: Option<Arc<YaraScanner>> }`; builder `with_yara(...)`.
- `HuntReport { status: HuntStatus, matches: Vec<RetroMatch>, sources_scanned, reason, duration_ms }`.
- `HuntStatus`: Completed | Skipped | Failed. `RetroMatch { source_file, line_number, line_content, rule_name, timestamp_approx }`.

### Capabilities — per rule/IOC type
- **YARA rule** (`run_rule_hunt` → `hunt_yara_files`): runs the real YARA engine over existing on-disk files under `DEFAULT_FILE_ROOTS = ["/tmp","/var/tmp","/dev/shm","/home"]`, capped at `max_files_scanned`; skips symlinks; emits throttled progress (~every 2%) via an optional mpsc sender. Skips if no YARA engine on the build.
- **Sigma / Wazuh / generic** (`hunt_logs`): parallel (rayon, `parallel_threads`) regex/substring grep of configured `log_sources` (files or directories).
- **IOC** (`run_ioc_hunt`): always greps text logs for the (regex-escaped) value; if the indicator is a hash (`Md5`/`Sha1`/`Sha256` or hash-like length), also matches on-disk files by SHA-256 under the default roots (md5/sha1 only matched via log grep).

### Config keys (`RetroConfig`, `config.rs:530`)
| Key | Default |
|-----|---------|
| `enabled` | `false` |
| `on_new_rule` | `true` (auto-hunt each newly deployed rule; now **reported as a tracked hunt** — a client-generated `hunt_id` + `rule_name` is sent to `/api/atc/retro/report`, which upserts a `retro_hunts` row so it appears on the Nexus Retro Hunt page, not only in the threats feed) |
| `log_sources` | `["/var/log/auth.log","/var/log/syslog"]` |
| `evtx_paths` | `[]` |
| `max_lookback_days` | `90` |
| `parallel_threads` | `4` |
| `max_files_scanned` | `50000` |

(All hunts return `Skipped` immediately if `!enabled`.)

### Entry points + main.rs wiring
- Built after YARA so file-hunts use the real engine: `RetroHunter::new(cfg.retro.clone())` + `.with_yara(...)` at **`src/main.rs:381-385`**.
- Invoked from the Nexus poll/command loop: `run_rule_hunt` (`src/main.rs:627`), `run_ioc_hunt` (`src/main.rs:747`, `786`), `run_rule_hunt_with_progress` (`src/main.rs:865`, forwards progress to the Nexus for a live bar).

### Limitations
- File roots for YARA/hash hunts are hardcoded (`DEFAULT_FILE_ROOTS`), not config-driven.
- Only SHA-256 is computed for on-disk hash matching; md5/sha1 indicators rely on log grep.
- `evtx_paths`/`max_lookback_days` are parsed but not applied to filtering in the Linux text-log/YARA paths here.

---

## 9. Supporting: `firewall/` and `tls.rs`

These are shared dependencies of the above modules.

### `firewall/mod.rs` — Firewall abstraction
- `Firewall { backend: FirewallBackend }`, `detect()` probes once at startup;
  priority **nftables → firewalld → ufw → iptables → /proc fallback** (Windows
  always `WindowsFirewall`). `FirewallBackend::None` degrades gracefully with
  explicit, actionable warnings.
- API: `block_ip`, `unblock_ip`, `isolate(allowlist)`, `undo_isolation` — each
  dispatches to the backend. Isolation always allows loopback + established
  connections (prevents SSH lockout) plus the allowlist; iptables sets DROP
  policy *before* flushing to avoid an open window.
- `validate_ip` accepts only a canonical `IpAddr` or valid CIDR — closes the
  prior firewall-rule DSL/argument-injection hole.
- `DistroInfo::detect()` provides distro family, package manager, install
  command, and OVAL feed name/URL (consumed by posture and hardening).
- Wiring: `Firewall::detect()` at `src/main.rs:319`; cloned into the
  ResponseEngine (§1), NetGuard (`main.rs:331`), and PlaybookEngine (§2).

### `tls.rs` — Pinned TLS client builder
`nexus_http_builder(ca_cert_path, tls_verify) -> ClientBuilder` is the single
policy for all agent→Nexus HTTPS:
- `ca_cert_path` set → **certificate pinning**: trust only that PEM as root,
  drop the built-in root store.
- unset + `tls_verify=false` → verification disabled (explicit, logged, lab-only).
- unset + `tls_verify=true` (default) → standard system-trust (self-signed Nexus
  is rejected until pinned or explicitly opted out).

This is the helper posture's `fetch_imported_checks` uses (§3) — the specific
behaviour the task flagged: imported-checks fetch goes through the pinned TLS
helper, not a hardcoded `danger_accept_invalid_certs(true)`.

---

## Appendix: Orchestration summary (main.rs wiring at a glance)

| Engine | Constructed | Invoked |
|--------|-------------|---------|
| SelfProtection | `main.rs:177` | `initialize()` `main.rs:178` |
| PostureEngine | `main.rs:268` | `run_full_assessment` `main.rs:525` (interval `posture.scan_interval_secs`, `main.rs:429/446`) |
| HardeningEngine | `main.rs:297` | `assess()` `main.rs:517` |
| ResponseEngine | `main.rs:322` | `execute()` `main.rs:1370`; `execute_action()` `main.rs:949` (ransomware) |
| PlaybookEngine | `main.rs:347` (`with_firewall`, `with_mode`) | `match_playbook` `main.rs:1373`, `execute` `main.rs:1378` |
| RetroHunter | `main.rs:381` (`with_yara`) | `run_rule_hunt`/`run_ioc_hunt` `main.rs:627/747/786/865` |
| IaCScanner | `main.rs:387` | `scan_all()` `main.rs:1095` (30-min loop) |
| Firewall | `main.rs:319` | shared into Response/NetGuard/Playbook |

Threat pipeline order per detection (`main.rs` ~1350–1380): forensics (spawned) →
`ResponseEngine::execute` (immediate, mode+threshold gated) → `PlaybookEngine`
match + spawned `execute` (mode gated) → local status UI record → async LLM/ATC
enrichment.
