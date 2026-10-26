# NebulaSentinel Agent — Windows Platform Support

Current-state documentation of how the agent behaves on Windows: which
collectors and response actions are available, which are not and why, the
audit-policy prerequisites for full telemetry, and the file-system layout.

Sourced from `/nebulasentinel/sentinel_v2/src` — `platform.rs`,
`collector/windows.rs`, `collector/windows_parse.rs`, `hardening/windows.rs`,
`response/mod.rs`, `firewall/mod.rs`, `forensics/mod.rs`,
`network_monitor/mod.rs`, `inventory/mod.rs`.

---

## 0. Design rule: no Win32 FFI

Every Windows-specific capability is reached through a tool that ships with the
operating system, or through the `sysinfo` crate:

| Need | Mechanism |
|---|---|
| Security telemetry | `wevtutil` (Event Log XML) |
| Process / network enumeration | `sysinfo`, `netstat`, `tasklist` |
| Registry & policy reads | `reg query`, `net user`, `auditpol` |
| Response actions | `taskkill`, `netsh advfirewall` |
| Software inventory | `powershell` over the Uninstall hives |
| DNS visibility | `wevtutil` / `Get-DnsClientCache` |

Consequences:

* The Windows build contains **no `unsafe` of its own** and needs no C toolchain
  beyond what the embedded LLM already requires.
* `cargo check --target x86_64-pc-windows-gnu` succeeds from a Linux host, so
  platform regressions are caught in CI without a Windows runner.
* There is **no `winapi` / `windows-sys` dependency**. A `winapi` optional
  dependency was previously declared but never enabled by any feature and never
  imported by any module; it was removed because it implied an FFI surface the
  agent does not have.

---

## 1. Collection

### 1.1 Backend selection

`platform::default_collector_backend()` returns `wineventlog` on Windows,
`ebpf` on Linux, `procmon` elsewhere. `platform::supports_ebpf()` is
`cfg!(target_os = "linux")`, so the agent reports its own capability honestly
rather than advertising kernel tracing it cannot do.

The `wineventlog` backend runs the Event Log poller **and** procmon together:
the Event Log supplies audited security events, procmon supplies continuous
process visibility even when audit policy is off.

### 1.2 Event Log mapping (`collector/windows.rs`)

Records are polled with `wevtutil` and translated into the same `RawEvent`
stream the Linux backends produce, so anomaly, rules, GOSSIP, LLM and reputation
run unchanged.

| Event | Channel | `EventType` | Signal |
|---|---|---|---|
| 4688 | Security | `ProcessExec` | Process creation |
| 4624 / 4625 | Security | `UserAuth` | Logon success / failure (`return_code` 0/1) |
| 4672 | Security | `UserSu` | Special privileges assigned |
| 4720 | Security | `UserSu` | Local account created — T1136.001 |
| 4728 / 4732 / 4756 | Security | `UserSu` | Added to a privileged group — T1098 |
| 4698 | Security | `CronJob` | Scheduled task created — T1053.005 |
| 1102 | Security | `SyscallAnomalous` | Audit log cleared — T1070.001 |
| 7045 / 4697 | System / Security | `ModuleLoad` | Service installed |

Each record carries:

* **The time Windows recorded**, parsed from `<TimeCreated SystemTime='…'/>`
  (100-nanosecond precision, single-quoted attribute on a self-closing element),
  not the time the agent happened to poll. Correlation and the forensic timeline
  therefore match what Windows actually logged.
* **`windows_sid` / `windows_domain` / `windows_event_id` / `windows_channel`**
  in `extra`. The SID is what `anomaly::is_windows_system_sid` uses to
  distinguish a SYSTEM-context action from an interactive user's.

### 1.3 Startup priming

The collector records the current head of each channel **before** it emits
anything (`prime_channel`). Without that step the high-water mark starts at zero
and the first poll treats up to 50 records already sitting in the log as new,
replaying historical logons and process starts as fresh detections on every
agent restart.

### 1.4 The parser is tested on every platform

`collector/windows.rs` is `#![cfg(target_os = "windows")]`, which meant the XML
parsing — the riskiest part — could not be compiled, let alone tested, anywhere
else. The pure parsing now lives in `collector/windows_parse.rs`, which is **not**
`cfg`-gated and carries unit tests covering field extraction, both attribute
quote styles, hex and decimal PID decoding, timestamp parsing, and the event-ID
mapping including the persistence and evasion IDs. A `cargo test` on Linux
exercises all of it. Only the `wevtutil`/`reg` process plumbing stays
Windows-only.

---

## 2. Detection

| Engine | Windows | Note |
|---|---|---|
| Behavioral baseline / anomaly forest | ✅ | Platform-independent |
| Sigma / YARA / Wazuh rules | ✅ | Platform-independent |
| Ransomware canary + mass-modification | ✅ | Platform-independent |
| Netguard, dedup, suppression | ✅ | Platform-independent |
| Secrets scan, DLP | ✅ | File-content scanning |
| FIM | ✅ | `ReadDirectoryChangesW` via `notify`; watch zones are `C:\Users\*\Downloads` and `…\AppData\Local\Temp` |
| Connection tracking | ✅ | `netstat -n -p tcp` |
| Cloud-metadata access (T1552.005) | ✅ | Flagged by the cross-platform connection tracker (the Linux `/proc/net/tcp` fast path is skipped as redundant) |
| DNS tunneling (T1071.004) / DGA (T1568.002) | ✅ | See §3 |
| Container / K8s | ⚠️ | Works if `docker` / `kubectl` / `crictl` are on PATH |
| eBPF syscall tracing | ❌ | Linux kernel facility |

---

## 3. DNS visibility

The tunneling and DGA heuristics need a stream of resolved names. The Linux
sources (`journalctl -u systemd-resolved`, `/var/log/syslog`) return nothing on
Windows, which silently disabled both detections. Windows now uses, in order:

1. **`Microsoft-Windows-DNS-Client/Operational`, event 3006** — the real query
   stream, and the higher-fidelity source. **Disabled by default:**
   ```powershell
   wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true
   ```
2. **`Get-DnsClientCache`** — the resolver cache. Always present, needs no
   configuration, and holds what was recently resolved, which is sufficient for
   the entropy and unique-subdomain-count heuristics. Entries persist for their
   TTL so a domain can appear on several polls; the heuristics tolerate repeats.

---

## 4. Response actions

| Action | Windows implementation |
|---|---|
| `KillProcess(pid)` | `taskkill /F /T /PID` — `/T` terminates the child tree, which is what actually contains malware that re-spawns from a helper |
| `QuarantineFile(path)` | Move to `%ProgramData%\NebulaSentinel\quarantine`; both separators **and the drive colon** are flattened out of the filename, since `:` is illegal in an NTFS filename |
| `BlockIp(ip)` | `netsh advfirewall firewall add rule` — one inbound, one outbound |
| `IsolateHost` | Allowlist rules added **first**, then `netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound` — so the agent never races itself off the network |
| `undo_isolation` | Restores `blockinbound,allowoutbound`. Individually named `NebulaSentinel-Isolate-Allow-*` rules are deliberately left in place: `netsh` has no safe wildcard delete and `delete rule name=all` would wipe the operator's entire ruleset |

Protected PIDs differ by platform: Unix refuses PID ≤ 1; Windows refuses PID 0
(System Idle) and 4 (System) — terminating either bugchecks the machine.

All of these require the agent to be running elevated (SYSTEM or Administrator).

---

## 5. Hardening & posture

`hardening::windows::assess()` evaluates DISA STIG / CIS Windows controls from
the registry (`reg query`) and account policy (`net user`), mapping results onto
the shared `HardeningItem` type so they flow through the existing posture
pipeline and the Nexus Compliance UI unchanged:

UAC enabled · UAC admin consent on the secure desktop · SMBv1 disabled ·
LSASS `RunAsPPL` · `NoLMHash` · `RestrictAnonymous` · PowerShell script-block
logging · WinRM basic auth disabled · Defender real-time protection · WDigest
credential caching disabled · built-in Guest account disabled.

`posture::check_hardening_items` dispatches to this on Windows instead of the
Linux SSH/sysctl catalog, so the posture sub-tab shows Windows-relevant controls
rather than checks that are meaningless on the host.

`auto_fixable` is `false` for every Windows control by design — these want
operator review, not an agent silently rewriting the registry.

Software inventory (and therefore CVE correlation) reads the Uninstall registry
hives — `HKLM\…\Uninstall\*`, `HKLM\WOW6432Node\…`, `HKCU\…` — de-duplicating
applications that appear in more than one hive.

---

## 6. Forensics

| Artifact | Windows source |
|---|---|
| `process_triage.txt` | `tasklist /v`, `Win32_Process` detail for the subject PID, its loaded modules (where an injected or side-loaded DLL shows), `netstat -ano` |
| `network_state.txt` | `netstat -ano`, `arp -a`, `route print`, `ipconfig /all`, `ipconfig /displaydns`, `netsh advfirewall show allprofiles` |
| `eventlog_*.txt` | `wevtutil` export. A configured `/var/log/auth.log` maps to **Security** and `/var/log/syslog` to **System**; any other value is treated as a channel name. A real file on disk is tailed directly. |
| `open_files.txt` | Mapped image files for the PID, its network handles from `netstat`, `openfiles` output when the operator has enabled handle accounting |
| `memory.txt` | Bounded metadata: memory lines from `systeminfo` plus the top-100 processes by working set |
| `capture.pcap` | `tshark` when Wireshark is installed, otherwise `pktmon` → `etl2pcap` |

Two limitations are surfaced explicitly rather than hidden:

* **No raw memory image.** That requires a kernel acquisition driver (WinPmem,
  Comae) which the agent does not ship. The artifact is named `memory_summary`,
  never `memory_dump`, and `memory::acquire_dump` fails with the reason and the
  remedy instead of walking a LiME/`kcore` path that cannot exist on Windows.
* **`pktmon` has no BPF filter syntax.** If a non-empty `pcap_filter` is
  configured and the agent falls back to `pktmon`, it logs that the filter is
  being ignored and captures unfiltered. If `etl2pcap` conversion fails the raw
  `.etl` is retained as evidence.

PCAP outcome is now reported honestly — the old code logged "PCAP saved"
unconditionally, including when no capture tool existed.

---

## 7. File-system layout and identity

`platform::data_dir()` / `platform::config_dir()` resolve every persistent
location. No module hardcodes `/var/lib/nebula` or `/etc/nebula` any more —
that previously put the quarantine directory, isolation marker, blocked-IP log,
GOSSIP signing key, GOSSIP override, policy snapshot, tamper log, alert log,
OVAL cache, NVD cache, hardening reports and rule directories at paths that
cannot exist on Windows.

| | Windows | Linux | macOS |
|---|---|---|---|
| Data | `%ProgramData%\NebulaSentinel` | `/var/lib/nebula` | `/Library/Application Support/NebulaSentinel` |
| Config | `…\NebulaSentinel\config` | `/etc/nebula` | `/etc/nebula` |
| Models | `…\NebulaSentinel\models` | `/var/lib/nebula/models` | `…/NebulaSentinel/models` |

### 7.1 Config resolution

`main::resolve_config_path` picks the first candidate that exists: `--config`,
then the platform config path, then `.\config.toml`. The chosen path is
published via `platform::set_active_config_path` and used by:

* **`self_protect` config-tamper hashing.** It previously hashed a hardcoded
  `/etc/nebula/nebula-agent.toml`, a file that exists in no default install on
  any platform — so config-tamper detection silently never armed. It now hashes
  the file actually in force and warns loudly if it cannot.
* **`SetMode` and `ApplyPolicy` command handlers**, which rewrite `mode` in the
  config file. These wrote to a hardcoded `/etc/nebula/config.toml`, so a
  Nexus-issued mode change against a Windows agent reported success and changed
  nothing.

### 7.2 Agent identity

`agent_id` derives from machine identity + hostname + primary MAC.

| Component | Windows | Linux (unchanged) | macOS |
|---|---|---|---|
| Machine identity | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | `/etc/machine-id` | `IOPlatformUUID` via `ioreg` |
| Hostname | `sysinfo` (COMPUTERNAME) | `/etc/hostname` | `sysinfo` |
| MAC | `sysinfo`, lowest interface name | `/sys/class/net/*/address` | `sysinfo` |

Previously Windows and macOS had no source for any of these, which pushed
identity derivation onto its random-UUID branch: wiping the data directory
re-registered the host as a brand-new agent. The Linux derivation is byte-for-byte
unchanged, so existing Linux agent IDs are unaffected.

---

## 8. Self-protection

| Measure | Windows |
|---|---|
| Binary hash integrity | ✅ |
| Config hash integrity | ✅ (against the resolved config path — §7.1) |
| Watchdog + tamper alert log | ✅ (`…\NebulaSentinel\alerts\tamper.log`) |
| Prompt-injection guard (ATLAS AML.T0043) | ✅ |
| `prctl(PR_SET_DUMPABLE/PR_SET_PTRACER)` | ❌ Linux primitive |
| `RLIMIT_CORE` / `umask` | ❌ Unix primitives |
| `oom_score_adj` | ❌ Linux-only |

---

## 9. Limitations

- **No kernel-level syscall tracing.** eBPF is Linux-only and no ETW kernel
  provider is wired. Process visibility on Windows is Event Log 4688 plus
  procmon polling.
- **4688 without command-line auditing is much weaker.** Most content rules match
  on the command line. The agent emits a one-time warning when the registry value
  `ProcessCreationIncludeCmdLine_Enabled` does not look enabled.
- **Response actions need elevation.** `netsh` firewall changes and `taskkill`
  against another user's process both require SYSTEM or Administrator.
- **`undo_isolation` leaves the allow rules behind** — see §4.
- **No full memory acquisition** — see §6.
- **Self-protection is weaker than on Linux** — see §8.

For build instructions, the audit-policy commands and a troubleshooting table,
see `sentinel_v2/WINDOWS.md`.
