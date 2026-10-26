# NebulaSentinel `nebula-agent` — File / Data / Rule Detection Content

Technical manual for the detection-content subsystems of the `nebula-agent`
(crate version `0.4.0`). This documents the **current** source under
`/nebulasentinel/nebula-agent/src/`. Path/line references point at the exact
wiring in `main.rs` and the module sources.

Scope covered:

- `fim/` — File Integrity Monitoring (real-time, on-access hash + YARA)
- `dlp/` — Data-Loss Prevention (exfil command / bulk access / large transfer / content classification)
- `secrets_scan/` — credential/secret regexes
- `yara_scan/` — the yara-x (pure-Rust) engine
- `sigma/` — full multi-category Sigma evaluator
- `rules/` — YARA/Sigma/Wazuh loading, hot-reload, Nexus rule sync
- `reputation/` — SHA-256 blocklist, YARA, entropy, config-gated VirusTotal

All detection modules emit the shared `crate::types::ThreatEvent`, which is
forwarded to Nexus via `nexus.send_threat(...)`.

---

## Cross-cutting: how detection content is fed events

Two feed paths exist:

1. **Synchronous per-event analysis.** The main event loop pulls each
   `RawEvent` and calls the DLP engine (`dlp_engine.analyze(&event)`,
   `main.rs:1268`) and the rules engine (`rules_engine.match_event(&event)`,
   `main.rs:1310`). `RawEvent`/`EventType` are defined in `src/types.rs:37`
   (variants: `ProcessExec, FileOpen, FileWrite, FileDelete, NetworkConnect,
   NetworkBind, NetworkDns, ModuleLoad, UserAuth, UserSu, …`).

2. **Self-driven engines** with their own `mpsc` channels and background tasks:
   FIM (`fim_rx`), DLP staging/transfer sweeps, plus periodic timers for
   secrets, reputation, and YARA memory scans.

---

## 1. `fim/` — File Integrity Monitoring

**Source:** `src/fim/mod.rs` (306 lines)

### Purpose
Real-time file-integrity monitoring using the OS-native filesystem-notification
backend (no polling). Fires `ThreatEvent`s on unauthorized modification of
security-critical files, and doubles as the trigger for on-access malware
scanning of files landing in download/temp zones.

### Capabilities
- **Backend auto-selection** via the `notify` crate: `inotify` (Linux),
  `FSEvents` (macOS), `ReadDirectoryChangesW` (Windows). The chosen backend is
  logged (`fim/mod.rs:188`).
- **Critical persistence path set** — `default_critical_paths()`
  (`fim/mod.rs:26`) hardcodes ~30 watched paths, each with a `Severity` and a
  MITRE technique. Highlights:
  - SSH: `/etc/ssh/sshd_config`, `/root/.ssh/authorized_keys`, `/etc/ssh/` → `T1098.004`
  - Privilege: `/etc/sudoers`, `/etc/sudoers.d/` → `T1548.003`
  - Accounts: `/etc/passwd` (`T1136.001`), `/etc/shadow` (`T1003.008`), `/etc/group`
  - Cron/persistence: `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/crontab`, `/var/spool/cron/` → `T1053.003`
  - Services: `/etc/systemd/system/` → `T1543.002`
  - Auth modules: `/etc/pam.d/`, `/lib/security/` → `T1556.003`
  - Linker/rootkit: `/etc/ld.so.preload`, `/etc/ld.so.conf` → `T1574.006`
  - Binaries: `/usr/bin/`, `/usr/sbin/`, `/bin/` → `T1574.006`
  - Network hijack: `/etc/hosts`, `/etc/resolv.conf`, `/etc/hosts.allow` → `T1565.001` / `T1562.004`
  - Boot/kernel: `/boot/` (`T1542.003`), `/etc/modules`, `/etc/modprobe.d/` (`T1547.006`)
  - Shell persistence: `/etc/profile`, `/etc/profile.d/`, `/etc/bash.bashrc` → `T1546.004`
- **Download/temp landing zones** — `download_zone_paths()` (`fim/mod.rs:69`),
  enumerated at runtime (`Severity::Info`, `T1105`): `/tmp`, `/var/tmp`,
  `/dev/shm`; every `/home/*/Downloads`; `/root/Downloads`. On Windows:
  `C:\Users\*\Downloads`, `C:\Users\*\AppData\Local\Temp`, `%TEMP%`,
  `C:\Windows\Temp`.
- **Scannable-file gate** — `is_scannable_file()` (`fim/mod.rs:127`) filters
  events in download zones. 100 MB cap; extension allowlist covering Windows PE
  (`exe,dll,scr,sys,com,msi,cpl,ocx`), scripts
  (`sh,bash,py,pl,rb,php,ps1,psm1,vbs,js,jse,bat,cmd,wsf,hta`), archives
  (`zip,rar,7z,tar,gz,bz2,xz,cab,iso,img`), office/doc macro carriers
  (`doc,docm,xls,xlsm,ppt,pptm,rtf,pdf`), and more binaries
  (`jar,apk,elf,o,so,bin,dylib,dmg,deb,rpm`). No/unknown extension falls back to
  magic-byte sniffing: `MZ`, `\x7fELF`, `#!`, `PK`, `Rar!`, gzip `1f 8b 08`.
- **Baselining + content dedup** — SHA-256 baseline is computed at startup for
  each watched regular file; on each event the current SHA-256 is compared, and
  the event is dropped if content is unchanged. The dedup map is **keyed on the
  actual file path** (not the spec path) so many files under one watched dir
  don't collide (`fim/mod.rs:254`).
- **Emit policy** — persistence paths always emit on Create/Modify/Remove;
  download zones only emit on Create/Modify **and** when `is_scannable_file`
  passes (so a merely-appearing temp file is not an alert — the emitted event's
  `FilePath` IOC is what drives the downstream on-access scan).
- **Confidence** derived from severity: Critical 95, High 85, else 70. Suggested
  action: `Alert` for Critical, else `Monitor`. Every event carries a
  `FilePath` IOC (`source: "fim"`) and matched rule `fim_realtime`.

### Key types
- `WatchedPath { path, severity, technique, description }` (`fim/mod.rs:18`)
- `FimEngine { agent_id, hostname, tx, baselines: Arc<Mutex<HashMap<path,sha256>>> }` (`fim/mod.rs:162`)

### Entry points + wiring
- `FimEngine::new()` → `main.rs:390`
- `fim_engine.start(vec![])` → `main.rs:392` (the `extra_paths` arg is passed
  empty; custom paths would be tagged `T1565.001`, `Severity::Medium`).
- FIM event loop → `main.rs:989`: forwards each `ThreatEvent` to Nexus, then for
  each `FilePath` IOC that is a real file, runs the **on-access scan**
  `reputation_engine.check_file(&p)` (`main.rs:1005`) — hash blocklist + YARA +
  entropy in real time, without waiting for the 15-min sweep.
- Architecture: a `spawn_blocking` watcher thread bridges the sync `notify`
  callback to an async channel (`fim/mod.rs:209`); watches are `NonRecursive`.

### Config keys
None dedicated. `start()` takes `extra_paths` (currently empty at the call site).

### External interactions
`notify` crate → OS kernel; SHA-256 via `sha2`; emits into `main.rs` FIM loop →
`reputation_engine` and Nexus.

### Limitations
- Watches are **non-recursive** — subdirectories created after start under a
  watched dir are not auto-watched.
- Startup baselines cover only paths that are regular files at boot; new files
  get baselined on first event.
- Reads the whole file into memory to hash on every change (fine for config
  files; download-zone files are gated by size/type first).
- No inode/rename tracking beyond what `notify` surfaces.

---

## 2. `dlp/` — Data-Loss Prevention

**Source:** `src/dlp/mod.rs` (596 lines)

### Purpose
Detect data exfiltration and staging from **behavioral signals** — process
command lines, file-access patterns, transfer volume, and written-file content —
without TLS interception or packet payload inspection.

### Capabilities — four detection paths
`analyze(&RawEvent)` (`dlp/mod.rs:203`) dispatches by event type:

1. **Exfil-command detection** — `check_exfil_command` (`dlp/mod.rs:224`), on
   `EventType::ProcessExec`. Matches process name + a required flag substring
   from the `EXFIL_COMMANDS` table (`dlp/mod.rs:122`, ~28 entries):
   - Upload tools: `curl -T`/`--upload-file`/`-d @`, `wget --post-file`, `scp`,
     `rsync`, `sftp`, `rclone copy`/`sync`, `aws s3 cp`/`sync`, `gsutil cp`,
     `azcopy`
   - Compression-before-exfil: `tar -czf`, `zip`, `7z a`, `rar`
   - Email exfil: `sendmail`, `mail -A`, `mutt -a`
   - Covert channels: `nc`, `ncat`, `socat`
   - Fires only if an **external destination** is present in the command line
     (`@`, `http://`, `https://`, `ftp://`, or a domain via
     `is_external_host_in_cmd`, TLDs `com,net,org,io,co,ru,cn,de,uk,fr`).
     Confidence 80/High if compressing, else 70/Medium. → `T1048`.

2. **Bulk sensitive-file access** — `check_sensitive_file_bulk`
   (`dlp/mod.rs:294`), on `FileOpen`/`FileWrite`. Per-PID file-access counts are
   accumulated in `track_file_access` (`dlp/mod.rs:273`); if a path is under a
   `SENSITIVE_DIRS` entry (`dlp/mod.rs:153`: `/home`, `/etc`, `/var/log`,
   `/var/lib/mysql`, `/var/lib/postgresql`, `/var/backups`, `/opt`, `/srv`) and
   the PID has **>500** tracked accesses, emits `T1005` / High / conf 75. The
   access map self-prunes above 10 000 PIDs.

3. **Large outbound transfer** — `check_large_transfer` (`dlp/mod.rs:330`), on
   `NetworkConnect`. Skips private IPs (`is_private_ip`). Per `dest:port` it
   accumulates a `TransferRecord`, **estimating ~10 KB per connection** (this is
   a heuristic estimate, not measured bytes). Alerts when est. `>100 MB` to one
   external host in `<1 h` → `T1041` / High / conf 80, then resets the counter
   to avoid alert storms. Old records reaped hourly (`start_transfer_monitor`,
   `dlp/mod.rs:463`; 2 h cutoff).

4. **Content classification of written files** — `scan_written_file`
   (`dlp/mod.rs:501`), on `FileWrite` **only** (the staging signal). **This is
   the live wiring of `scan_content`** (previously implemented but never
   called). It reads the just-written file (1 MiB cap; extension allowlist
   `.csv .tsv .sql .json .ndjson .txt .log .xml .yaml .yml .bak .dump`), runs
   `scan_content` (`dlp/mod.rs:478`) against the compiled data-pattern set, and
   emits `T1074` (Data Staged) when findings exist. Severity High if any
   Critical/High pattern hit, else Medium; conf 75.

   **Data classification patterns** — `data_patterns()` (`dlp/mod.rs:71`), each
   with a `min_matches` threshold to cut false positives:
   | Pattern | Category | Severity | min_matches |
   |---|---|---|---|
   | US SSN `\d{3}-\d{2}-\d{4}` | Pii | High | 5 |
   | Email addresses | Pii | Medium | 50 |
   | US phone numbers | Pii | Medium | 20 |
   | Date of birth (DOB/born) | Pii | Medium | 5 |
   | Credit card (Visa/MC/Amex) | Financial | Critical | 1 |
   | Bank account number | Financial | High | 3 |
   | Routing/ABA number | Financial | High | 3 |
   | Private key (PEM) | Credentials | Critical | 1 |
   | AWS access key `AKIA…` | Credentials | Critical | 1 |
   | bcrypt hash | Credentials | High | 5 |
   | DB connection string (mysql/postgres/mongodb/redis) | Credentials | Critical | 1 |
   | ICD-10 diagnosis code | HealthData | High | 10 |
   | NPI | HealthData | High | 3 |
   | Source code (function/class/def/import/package) | Intellectual | Medium | 100 |
   | Classified marker (TOP SECRET/…/NOFORN) | Classified | Critical | 1 |

5. **Data-staging detector** (background) — `start_staging_detector`
   (`dlp/mod.rs:391`). Every 30 s, scans `/tmp`, `/dev/shm`, `/var/tmp`,
   `/run/user` for archive files (`.zip .tar .tar.gz .tgz .tar.bz2 .7z .rar .gz
   .zst .enc`) `>10 MB`; alerts on new or significantly grown archives →
   `T1560`+`T1074`, High if `>100 MB` else Medium, conf 72.

### Key types
- `DataPattern`, `DataCategory` (Pii/Financial/Credentials/HealthData/Intellectual/Classified) (`dlp/mod.rs:53`)
- `TransferRecord` (`dlp/mod.rs:107`), `DlpFinding` (`dlp/mod.rs:564`)
- `DlpEngine { agent_id, hostname, tx, transfers, file_access, patterns }` (`dlp/mod.rs:168`)

### Entry points + wiring
- `DlpEngine::new()` → `main.rs:360`; `dlp_engine.start()` → `main.rs:362`
  (launches transfer-monitor + staging-detector tasks).
- Per-event: `dlp_engine.analyze(&event)` → `main.rs:1268` (result merged in the
  combined-detection match at `main.rs:1289`).
- DLP threat channel loop → `main.rs:976` forwards `dlp_rx` events to Nexus.

### Config keys
None dedicated (thresholds are in-code constants).

### External interactions
Filesystem reads (written-file scan, staging sweep); `regex` for pattern
compile/match; consumes `RawEvent`s from the collector; emits to the DLP Nexus
loop. Note `#![allow(dead_code)]` at top — `scan_content`/`DlpFinding` remain
`pub` for the posture engine too.

### Limitations
- **No packet payload / TLS inspection** by design (documented in the module
  header, `dlp/mod.rs:21`) — catches ~85% of exfil scenarios behaviorally.
- Transfer volume is **estimated** at a flat 10 KB/connection, not measured — a
  coarse heuristic prone to over/under-count.
- Content classification only runs on writes with allowlisted extensions and
  ≤1 MiB; binary/compressed/encrypted staged data is not classified.
- Staging/sensitive-dir paths are Linux-centric.

---

## 3. `secrets_scan/` — Runtime Secret / Credential Scanning

**Source:** `src/secrets_scan/mod.rs` (253 lines)

### Purpose
Find exposed credentials at **runtime** — in process environment variables and
on-disk credential files — catching what IaC/source scanning misses.

### Capabilities
- **15 credential regexes** — `default_patterns()` (`secrets_scan/mod.rs:20`),
  each with a MITRE technique and severity (compiled once; bad regexes silently
  dropped):
  - AWS Access Key `AKIA[0-9A-Z]{16}` (Critical, T1552.001)
  - AWS Secret Key `aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}` (Critical)
  - GitHub Token `ghp_…{36}` / GitHub App Token `ghs_…{36}` (Critical)
  - Anthropic API Key `sk-ant-[A-Za-z0-9\-]{40,}` (Critical, T1552.001)
  - OpenAI API Key `sk-[A-Za-z0-9]{48}` (Critical)
  - RSA / EC / generic PRIVATE KEY PEM headers (Critical, T1552.004)
  - Password in env `(?i)(password|passwd|pwd)\s*=\s*[^\s'"]{6,}` (High)
  - Database URL `(mysql|postgres|mongodb|redis)://user:pass@` (Critical)
  - Slack Token `xox[baprs]-…` (High)
  - JWT `eyJ….….…` (Medium)
  - Google API Key `AIza…{35}` (High)
  - Azure SAS Token (High)
  - Stripe Secret Key `sk_live_…{24}` (Critical)
- **Process-env scan** — `scan_process_envs()` (`secrets_scan/mod.rs:138`) walks
  `/proc/<pid>/environ`, resolves `comm`, one alert per process per pattern.
- **File scan** — `scan_file()` (`secrets_scan/mod.rs:170`): skips binary
  extensions (`is_binary_path`) and excluded prefixes (`/proc/ /sys/ /dev/ /run/
  /tmp/.mount`), and files `>10 MB`.
- **Credential-location sweep** — `scan_credential_locations()`
  (`secrets_scan/mod.rs:193`): `/root/.aws/{credentials,config}`,
  `/home/*/.aws/credentials`, `/etc/environment`, and common `.env` locations
  (`/etc/.env`, `/.env`, `/opt/app/.env`, `/var/www/.env`, `/app/.env`,
  `/srv/.env`).
- All findings: conf 90, `credential_access` tactic, matched rule
  `secrets_scanner`, action `Alert`.

### Key types
- `SecretPattern { name, pattern, technique, severity }` (`secrets_scan/mod.rs:13`)
- `SecretsScanner { agent_id, hostname, patterns: Vec<(SecretPattern, Regex)> }` (`secrets_scan/mod.rs:121`)

### Entry points + wiring
- `SecretsScanner::new()` → `main.rs:364`.
- Periodic task (`main.rs:1035`): 60 s initial delay, then hourly — runs
  `scan_process_envs()` (`main.rs:1045`) and `scan_credential_locations()`
  (`main.rs:1048`), forwarding each to Nexus.

### Config keys
None.

### External interactions
`/proc` (Linux-only env scan), filesystem reads, `regex`, Nexus.

### Limitations
- Env scan is **Linux `/proc`-only**.
- File scanning is invoked only through the fixed credential-location list
  (no arbitrary directory walk from the scheduler).
- Regex-only — no entropy/validation, so revoked/dummy keys still alert.

---

## 4. `yara_scan/` — YARA (yara-x) Engine

**Source:** `src/yara_scan/mod.rs` (245 lines)

### Purpose
Real YARA malware scanning of files and process memory using **yara-x**, the
pure-Rust engine (no libyara C dependency), with a substring-matcher fallback
when the engine isn't compiled in.

### Capabilities
- **Two build modes**, gated by the `yara` Cargo feature (`Cargo.toml:267`
  `yara = ["yara-x"]`; **not** in `default`, but included in `full-linux`,
  `Cargo.toml:280`):
  - With `yara`: compiles all `.yar`/`.yara` sources via `yara_x::Compiler`,
    evaluates full YARA (string sets, hex/wildcards, regex, condition logic).
    Bad rule files are skipped individually rather than failing the set
    (`yara_scan/mod.rs:88`).
  - Without: `extract_yara_strings` pulls quoted string literals (≥4 chars) and
    a rule "matches" only if **all** its keywords appear in the data
    (`scan_bytes_fallback`, `yara_scan/mod.rs:149`) — far weaker.
- **Recursive rule discovery** — `compile_dir(dir)` (`yara_scan/mod.rs:43`) via
  `collect_yara_sources` walks subdirs for `.yar`/`.yara`.
- **Scan surfaces:**
  - `scan_file(path)` / `scan_bytes(&[u8])` (`yara_scan/mod.rs:101`,`:110`) — a
    fresh `yara_x::Scanner` per scan (cheap; avoids `Sync` issues under `Arc`).
  - `scan_process(pid)` (Linux, `yara_scan/mod.rs:169`) — parses
    `/proc/<pid>/maps`, reads readable/anonymous/heap/stack/`rwx`/executable
    regions from `/proc/<pid>/mem`, bounds each region read to 16 MB. Catches
    fileless/injected/unpacked code. No-op on non-Linux.
- **Rich match metadata** — `YaraMatch` (`yara_scan/mod.rs:34`) captures
  `rule_name`, tags, and typed metadata rendered to strings
  (String/Bytes/Integer/Float/Bool), so alerts can surface a rule's
  description/author/reference (consumed by the reputation engine).

### Key types
- `YaraScanner { rules: Option<yara_x::Rules>, fallback, rule_count, real_engine }` (`yara_scan/mod.rs:22`)
- `YaraMatch { rule_name, tags, meta }`

### Entry points + wiring
- `YaraScanner::compile_dir(&cfg.rules.yara_dir)` → `main.rs:368`, wrapped in
  `Arc`, logging real-engine vs fallback (`main.rs:370`).
- Attached to reputation (`rep.set_yara(...)`, `main.rs:377`) and RetroHunter
  (`main.rs:383`).
- **Memory-scan task** (`main.rs:1145`, only when a scanner exists): 120 s delay,
  then every 30 min, enumerates `/proc` PIDs and runs `scan_process` off-thread
  via `spawn_blocking`; hits become Critical (conf 95) `defense_evasion`
  ThreatEvents to Nexus.

### Config keys
- Rule directory: `rules.yara_dir` (default `/etc/nebula/rules/yara`).

### External interactions
`yara-x` (feature-gated), `/proc/<pid>/{maps,mem}`, filesystem.

### Limitations
- Default build ships the **weak fallback matcher** (AND-of-string-literals) —
  full engine requires building with `--features yara` (or `full-linux`).
- Memory scanning is Linux-only and skips regions `>16 MB`.
- Fallback loses hex patterns, regex, and condition logic entirely.

---

## 5. `sigma/` — Multi-Category Sigma Evaluator

**Source:** `src/sigma/mod.rs` (701 lines, with unit tests)

### Purpose
Evaluate Sigma detection rules against the agent's **structured `RawEvent`s**
(not bytes). Phase 2 is a full multi-category evaluator — a real parser +
condition engine, not keyword flattening.

### Capabilities
- **Logsource categories** (mapped from `EventType` in
  `rules::sigma_categories`, `rules/mod.rs:398`):
  | Sigma category | EventType |
  |---|---|
  | `process_creation` | `ProcessExec` |
  | `network_connection` | `NetworkConnect` / `NetworkBind` |
  | `dns_query` / `dns` | `NetworkDns` |
  | `file_event` / `file_access` | `FileOpen` |
  | `file_event` / `file_change` | `FileWrite` |
  | `file_event` / `file_delete` | `FileDelete` |
  | `image_load` / `driver_load` | `ModuleLoad` |
  | `authentication` | `UserAuth` |

  Any other category → `applies_to` returns false (safe no-match).
- **Match modifiers** (`field_matcher`, `sigma/mod.rs:181`): `contains`,
  `startswith`, `endswith`, `re` (regex), `all` (AND across the value list),
  and a rare inline `not`. Matching is case-insensitive except `re` (honors the
  pattern). `base64`/`base64offset` are explicitly **flagged unsupported** so a
  rule is never mis-evaluated.
- **Value semantics:** a field's value list is OR by default, AND with `|all`
  (`eval_matcher`, `sigma/mod.rs:394`). A selection's field-matchers are AND;
  a bare keyword list matches if ANY keyword appears in the event's searchable
  text (`eval_selection`, `sigma/mod.rs:374`).
- **Condition engine** (`eval_condition`, `sigma/mod.rs:426`): recursive-descent
  parser over `and`/`or`/`not` + parentheses; quantifier expansion
  (`expand_quantifiers`, `sigma/mod.rs:439`) for `all of them`, `1 of them`,
  `N of them`, `all of prefix*`, `1 of prefix*`. Unparseable → false (safe).
- **Field aliasing** (`SigmaEvent::field`, `sigma/mod.rs:251`) maps
  Sysmon/Windows and Linux/ECS names to `RawEvent` fields, e.g.
  `Image|image|process.executable|NewProcessName`, `CommandLine|process.command_line`,
  `ParentImage|process.parent.executable`, `DestinationIp|dest_ip|destination.ip|DstIp`,
  `DestinationPort|DstPort`, `DestinationHostname|destination.domain`,
  `QueryName|dns.question.name|DnsQuery`, `TargetFilename|file.path|TargetObject`,
  `Hashes|md5|sha1|sha256|Imphash`, `ImageLoaded|dll.path|ImagePath`,
  `User|TargetUserName|SubjectUserName`. Uncollected fields resolve to absent →
  never match, never panic.
- **Applicability gating** (`applies_to`, `sigma/mod.rs:335`): unsupported rules
  and category mismatches never apply; `logsource.product` must match the OS (or
  be absent → OS-agnostic).
- **Explicitly unsupported (marked, never mis-evaluated):** aggregations
  (`| count`, `near`) and `timeframe` → rule flagged `unsupported`
  (`sigma/mod.rs:121`,`:132`); base64 modifiers.
- **Unit tests** (`sigma/mod.rs:540`): `simple_contains`, `and_not_condition`,
  `one_of_them`, `network_connection_rule`, `dns_query_rule`, `file_event_rule`,
  `aggregation_marked_unsupported`.

### Key types
- `SigmaRule` (title/id/level/category/product/service/selections/condition/tags/unsupported) (`sigma/mod.rs:42`)
- `Selection`, `FieldMatcher`, `MatchOp` (Equals/Contains/StartsWith/EndsWith/Regex) (`sigma/mod.rs:59`–`:77`)
- `SigmaEvent<'a>` — borrowed field-mapped view (`sigma/mod.rs:222`)
- Back-compat `ProcEvent` + `applies_to_proc`/`matches_proc` retained.

### Entry points + wiring
- `parse_sigma(yaml)` → parsing (`sigma/mod.rs:100`).
- Driven by the rules engine: `rules::RulesEngine::match_event` builds a
  `SigmaEvent` from each `RawEvent` and calls `sig.applies_to(...)` +
  `sig.matches(...)` (`rules/mod.rs:132`). Called from the main loop at
  `main.rs:1310`.

### Config keys
Rules loaded from `rules.sigma_dir` (default `/etc/nebula/rules/sigma`).

### External interactions
`serde_yaml` (parse), `regex` (`re` modifier). No network/FS at eval time.

### Limitations
- No aggregation/timeframe/count/near correlation (marked unsupported).
- No base64 decoding.
- DNS query name and destination hostname aren't first-class `RawEvent` fields —
  pulled best-effort from `event.extra` (`rules/mod.rs:102`); absent → no match.
- `N of them` for N>1 is approximated as OR (at-least-one) — may over-match
  (documented, rare in practice; `sigma/mod.rs:474`).

---

## 6. `rules/` — Rule Loading, Hot-Reload, Nexus Sync

**Source:** `src/rules/mod.rs` (522 lines)

### Purpose
Central detection-rules engine that loads YARA, Sigma, and Wazuh rules from disk,
evaluates events against all of them, hot-reloads on change, and accepts rules
pushed from Nexus.

### Capabilities
- **Three loaders** (`load_all_rules`, `rules/mod.rs:46`):
  - **Sigma** (`load_sigma_rules`, `:153`): walks `.yml`/`.yaml`; validates the
    file actually contains `title:` + `detection:` (rejects arbitrary
    YAML/CI/workflow files, `:174`); does the **proper** `sigma::parse_sigma`
    for real evaluation and also extracts legacy keywords/patterns as fallback.
    MITRE technique derived from `attack.tXXXX` tags; prefers the real parser's
    title/level/id over legacy extraction.
  - **YARA** (`load_yara_rules`, `:241`): `.yar`/`.yara` via `parse_yara_basic`
    (`:274`) — extracts rule name + string literals as keywords (this is the
    *rules-engine* lightweight path; the heavy engine is `yara_scan`).
  - **Wazuh** (`load_wazuh_rules`, `:257`): `.xml` via regex extraction of
    `<rule id/level>`, `<match>`, `<description>` (`parse_wazuh_xml`, `:312`);
    level→severity mapping (≥13 critical, ≥9 high, ≥7 medium, else low).
- **Evaluation** (`match_event`, `rules/mod.rs:79`): for each rule, if it's a
  Sigma rule whose category applies, use the **real Sigma evaluator** and skip
  the legacy path; otherwise flatten the event to a string (`event_to_string`)
  and do keyword/regex matching (`rule_matches`). Returns a `Vec<RuleHit>` —
  each hit carrying the rule **name + normalized severity + MITRE technique**.
- **Scoring** (`main.rs`, post-merge): the caller scores by the strongest hit,
  not a flat bump. `rule_severity_weight` maps the rule's declared level to a
  severity floor + confidence bump — **critical +25, high +18, medium +12, low
  +6, info +2** — applied as a **max** across all matching rules (so a burst of
  low rules can't inflate a detection past one genuine high rule). The strongest
  rule severity elevates the threat's `severity`, and the rule's technique is
  folded into `mitre_techniques`. (`normalize_severity` canonicalizes Sigma's
  `informational`/`low`/…/`critical` and arbitrary casing.) Previously
  `match_event` returned bare names and every hit added a flat `+10`, discarding
  the parsed Sigma `level` / Wazuh level entirely.
- **Hot-reload** (`main.rs:303`): when `rules.auto_reload` is true, a ticker
  re-runs `load_all_rules()` every `reload_interval_secs` (floored at 10 s), so
  operators drop in new files without a restart.
- **Nexus rule sync / deploy** — `deploy_rule(&DetectionRule)` (`rules/mod.rs:61`)
  is **idempotent** (skips if a rule with the same name is loaded). Driven by the
  agent poll loop: `rules_c.deploy_rule(rule)` for each `poll.new_rules`
  (`main.rs:623`), optionally firing a one-shot retro hunt per new rule. The
  poll also loads Nexus intel: `rep_poll.load_malware_hashes` (`main.rs:601`).
  Nexus-directed rule *hunts* route by `rule_type` (`yara`/`wazuh`/`sigma`) at
  `main.rs:829`.
- `compile_detection_rule` (`rules/mod.rs:358`) turns a Nexus `DetectionRule`
  into a `CompiledRule` (keyword extraction from `content:`/`= "…"` lines).

### Key types
- `CompiledRule { id, name, rule_type, patterns, keywords, severity, technique, sigma: Option<SigmaRule> }` (`rules/mod.rs`)
- `RuleHit { name, severity, technique }` — the scored match returned by `match_event`.
- `RulesEngine { config: RulesConfig, rules: Arc<RwLock<Vec<CompiledRule>>> }` (`rules/mod.rs`)
- `SigmaDoc` (legacy extraction shape)

### Entry points + wiring
- `RulesEngine::new(cfg.rules.clone())` → `main.rs`.
- `match_event` → returns `Vec<RuleHit>`, scored into the detection post-merge.
- Hot-reload spawn → `main.rs:303`; Nexus deploy → `main.rs:623`.

### Config keys (`RulesConfig`, `config.rs:316`)
| Key | Default | Meaning |
|---|---|---|
| `yara_dir` | `/etc/nebula/rules/yara` | YARA rule dir |
| `sigma_dir` | `/etc/nebula/rules/sigma` | Sigma rule dir |
| `wazuh_rules_dir` | `/etc/nebula/rules/wazuh` | Wazuh XML rule dir |
| `auto_reload` | `true` | enable hot-reload |
| `reload_interval_secs` | `60` (floored to 10) | reload cadence |
| `ai_rules_require_approval` | `true` | AI-generated rules need approval |

### External interactions
Filesystem (rule dirs), `serde_yaml`, `regex`; Nexus poll (`new_rules`,
`malware_hashes`) and rule-hunt commands.

### Limitations
- The rules-engine YARA/Wazuh paths are **string/regex approximations**, not the
  real YARA engine (that lives in `yara_scan`) or a real XML/Wazuh decoder.
- Legacy fallback matching is keyword/regex substring on a flattened event
  string — coarse for non-Sigma rules.
- Sigma rules of unsupported categories silently fall through to the legacy
  keyword path.

---

## 7. `reputation/` — Binary Reputation

**Source:** `src/reputation/mod.rs` (234 lines)

### Purpose
When a new/changed executable is seen, decide if it's malicious via a layered
check: local hash blocklist → YARA signature → entropy → suspicious-path
heuristic → (optional) VirusTotal.

### Capabilities — `check_file(path)` (`reputation/mod.rs:66`), in order:
1. **Local SHA-256 blocklist** (fast, no network): `blocklist` is an
   `RwLock<HashMap<sha256, desc>>` (`reputation/mod.rs:22`), populated at runtime
   from the Nexus IOC feed via `load_malware_hashes` (`:50`) / `add_blocklist_hash`
   (`:43`). Hit → Critical, conf 99, `T1027.007`.
2. **YARA signature scan** (if a scanner is attached via `set_yara`, `:39`):
   `scanner.scan_bytes(&data)`; on match, pulls
   description/author/reference from rule metadata into the alert →
   Critical, conf 95, `T1027.007`.
3. **Entropy** (`file_entropy`, `:211`): Shannon entropy `>7.2` on an ELF `>4096`
   bytes → Medium, conf 65, `T1027` (packing/obfuscation).
4. **Suspicious-path unpackaged ELF**: `is_suspicious_path` (`/tmp`, `/dev/shm`,
   `/var/tmp`, `/run`, hidden home paths, …) + not owned by dpkg/rpm
   (`is_owned_by_package`, `:228`) → Medium, conf 55, `T1027.007`.
5. **VirusTotal** (`check_virustotal`, `:157`) — **config-gated**: only runs when
   `vt_api_key` is `Some` (respects air-gap). Queries VT API v3, alerts when
   `malicious >= 3` engines → Critical if ≥10 else High; confidence scales with
   detection %.
- All reputation threats suggest `ResponseAction::QuarantineFile(path)` and carry
  Sha256 + FilePath IOCs (`make_rep_threat`, `:191`).

### Key types
- `ReputationEngine { agent_id, hostname, vt_api_key: Option<String>, blocklist: RwLock<HashMap>, yara: Option<Arc<YaraScanner>> }` (`reputation/mod.rs:16`)

### Entry points + wiring
- `ReputationEngine::new(&agent_id, &hostname, cfg.virustotal_api_key.clone())`
  → `main.rs:376`; YARA attached at `main.rs:377`.
- **On-access** from the FIM loop: `rep_fim.check_file(&p)` (`main.rs:1005`).
- **Periodic sweep** (`main.rs:1112`): 90 s delay, then every 15 min, scans files
  in `/tmp`, `/var/tmp`, `/dev/shm`, `/usr/local/bin`.
- Nexus intel refresh: `rep_poll.load_malware_hashes(&poll.malware_hashes)`
  (`main.rs:601`).

### Config keys
| Key | Default | Meaning |
|---|---|---|
| `virustotal_api_key` | `None` (`config.rs:11`, `Option<String>`) | Enables VT lookups; absent → VT disabled (air-gap-safe) |

(YARA rule dir shared via `rules.yara_dir`.)

### External interactions
`sha2` hashing; `yara_scan::YaraScanner`; `dpkg`/`rpm` subprocess for package
ownership; VirusTotal API v3 over HTTPS (`reqwest`, 10 s timeout) only when keyed.

### Limitations
- Entropy/suspicious-path heuristics are ELF-only (Linux); `is_owned_by_package`
  shells out to `dpkg`/`rpm`.
- VT lookups need connectivity + a valid key and are subject to VT rate limits;
  disabled by default.
- Reads whole files into memory to hash/scan.

---

## Appendix — Build features affecting detection

- `yara = ["yara-x"]` (`Cargo.toml:267`) — enables the **real** YARA engine.
  **Not** in `default` (`Cargo.toml:201` = `ebpf-stub, inventory, gossip,
  embedded-llm`); included in `full-linux` (`Cargo.toml:280`). Without it, both
  `yara_scan` and the reputation YARA step run the substring fallback.
- Default rule directories all live under `/etc/nebula/rules/{yara,sigma,wazuh}`.
