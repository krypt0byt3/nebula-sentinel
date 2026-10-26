# NebulaSentinel nebula-agent — Behavioral Detection Engines

Current-state technical reference for the behavioral detection subsystem of the
NebulaSentinel endpoint agent (`nebula-agent`). This document describes what the
code does today, sourced from `/nebulasentinel/nebula-agent/src`.

Scope: the five behavioral engines and how the main event loop merges their
verdicts —
- `anomaly/` — MITRE ATT&CK heuristic engine
- `apt/` — long-dwell correlation and slow-C2 beacon detection
- `baseline/` — unsupervised ML (Welford stats + Half-Space Forest), ML-gated
- `ransomware/` — file-I/O ransomware detection and prevention
- `zeroday/` — exploitation-by-effect and `/proc/PID/maps` shellcode scanning

Detection outputs from all engines are normalized to a single `ThreatEvent`
(`src/types.rs`) carrying severity, confidence, MITRE tactics/techniques, IOCs,
and a `suggested_action` (`Monitor` / `Alert` / `CollectForensics` /
`KillProcess(pid)` / `IsolateHost`).

---

## 0. Detector precedence and merge (main loop)

Every collected `RawEvent` is passed through the synchronous `analyze()` of each
engine, then merged. Precedence, highest first:

> **ransomware > zero-day > DLP > APT > anomaly > baseline**

Wiring (`src/main.rs`):

| Step | Call | `path:line` |
|------|------|-------------|
| Ransomware | `ransomware_detector.analyze(&event).await` | `src/main.rs:1262` |
| APT | `apt_detector.analyze(&event).await` | `src/main.rs:1265` |
| DLP | `dlp_engine.analyze(&event).await` | `src/main.rs:1268` |
| Zero-day | `zeroday_detector.analyze(&event).await` | `src/main.rs:1271` |
| Anomaly | `anomaly_engine.analyze(&event).await` | `src/main.rs:1274` |
| Baseline | `baseline_engine.analyze(&event).await` (if `Some`) | `src/main.rs:1277-1280` |

The merge is a single `match` over the five primary options
(`src/main.rs:1286-1293`):

```rust
let combined = match (anomaly_hit, zeroday_hit, dlp_hit, ransom_hit, apt_hit) {
    (_, _, _, Some(r), _)       => Some(r),        // ransomware wins
    (_, Some(zd), _, _, _)      => Some(zd),        // then zero-day
    (_, _, Some(dlp), _, _)     => Some(dlp),       // then DLP
    (_, _, _, _, Some(apt))     => Some(apt),       // then APT
    (Some(anomaly), _, _, _, _) => Some(anomaly),   // then anomaly
    _                           => baseline_hit.clone(), // baseline last
};
```

**Baseline fusion** (`src/main.rs:1294-1306`): baseline is lowest precedence on
its own, but when a higher-precedence engine also fires AND the baseline fired on
the same event, the baseline is folded in as corroborating evidence — confidence
`+10` (capped 99), a `[corroborated by behavioral baseline]` note appended to the
description, and `"baseline"` pushed onto `matched_rules`.

After the merge, the surviving `ThreatEvent` passes through, in order:

1. **Rules engine** (YARA/Sigma/Wazuh): matches are now scored by the rule's
   **declared severity** — the strongest matching rule elevates the threat's
   severity floor, adds a severity-scaled confidence bump (critical +25 → info
   +2, applied as a max not a sum), and folds in the rule's MITRE technique.
   (Previously any match added a flat `+10` and the parsed Sigma `level` / Wazuh
   level was discarded.) See **[Detection — Files & Rules](agent__03_detection_content_rules.html)**.
2. **Detection-time suppression / allowlist** (`src/suppression/mod.rs`): operator
   `[detection.suppress]` rules matching known-good `process`/`path`/`technique`/
   `threat_name` either **drop** the alert entirely or **downgrade** it to
   `Info`/low-confidence — applied *before* dedup so allowlisted firings never
   occupy the dedup map.
3. **Alert-dedup gate** (`src/dedup/mod.rs`): identical alerts (same
   `threat_name` + MITRE techniques + process) within `deduplicate_window_secs`
   (default 60s) are suppressed at the source — skipping forensics, response,
   status UI, gossip, and the Nexus send. The alert re-emits after the window
   with a `recurred N×` note so recurrence stays visible.

A suppressed (dropped) or deduplicated alert short-circuits the loop iteration;
otherwise the survivor is routed to confidence-gated forensics and the response
engine.

**Important — two emission paths.** The precedence merge only governs the
*synchronous* `analyze()` return values. Three engines (ransomware, APT, DLP)
also own an `mpsc` channel and background sweeper tasks that emit `ThreatEvent`s
directly into dedicated event loops, bypassing the merge:
- Ransomware channel loop: `src/main.rs:942-956` (in **Protect** mode it calls
  `execute_action` on the threat's `suggested_action` immediately — this is the
  ransomware auto-kill path).
- APT channel loop: `src/main.rs:961-970` (forward to Nexus only).
- DLP channel loop: `src/main.rs:975+`.

---

## 1. `anomaly/` — MITRE ATT&CK heuristic engine

**File:** `src/anomaly/mod.rs` (2745 lines)

### Purpose
Signature-free behavioral scoring of every event against a large hand-written
MITRE ATT&CK v15 heuristic rule base, plus multi-stage attack-chain correlation.
This is the primary "does this command/file/network action look like a known
technique" engine.

### Rule sets and how they combine
The engine evaluates three rule structs, but callers must invoke only two of
them because of internal chaining:

1. **`MitreRules::evaluate`** (`src/anomaly/mod.rs:70`) — the main body (TA0043
   Reconnaissance through TA0040 Impact, plus a MITRE ATLAS adversarial-AI/ML
   block). Its **final line appends `MitreRulesExtended` internally**
   (`src/anomaly/mod.rs:1296`: `hits.extend(MitreRulesExtended::evaluate(event))`).
2. **`MitreRulesExtended::evaluate`** (`src/anomaly/mod.rs:1771`) — full T1055
   process-injection suite, T1218 LOLBins, expanded T1562 impair-defenses,
   T1140 deobfuscation, T1037/T1176/T1185/T1528/T1649/T1654 and CVE-tagged
   exploit strings (Log4Shell, ProxyLogon/Shell, Follina, Spring4Shell,
   CitrixBleed, PAN-OS CVE-2024-3400, regreSSHion CVE-2024-6387).
3. **`MitreRulesV15Complete::evaluate`** (`src/anomaly/mod.rs:2251`) — deep
   T1055 subs, full credential-access (DCSync T1003.006, LSA secrets, cached
   DCC2, `/proc/PID/mem` cred dump T1003.007), T1071.001-.003 protocol-C2,
   persistence, defense-evasion, impact (T1499 DoS, fork bomb), discovery,
   containers (T1609/T1612), cloud/IAM (T1621 MFA fatigue, T1651, T1656, T1659),
   collection, and lateral movement (PtH T1550.002, WinRM T1021.006).

`AnomalyEngine::analyze` (`src/anomaly/mod.rs:1583`) calls **`MitreRules`** (which
pulls in Extended) then **`MitreRulesV15Complete`** — see
`src/anomaly/mod.rs:1606-1607`. A code comment there explicitly warns not to call
`MitreRulesExtended` a third time, or extended hits would be double-counted into
the summed score.

> Note on rule counts: the source header and `AnomalyEngine::new` log advertise
> "196 ATT&CK heuristics" (`src/anomaly/mod.rs:1575`), while the main.rs status
> line reports `"264 technique rules active"` (`src/main.rs:192`). These are
> descriptive banner figures; the authoritative behavior is the union of the
> three rule structs above.

### Scoring and severity
- Each matched heuristic is a `TechniqueHit { score, tactic, technique, sub,
  description }` (`src/anomaly/mod.rs:21`), created by helper `h(...)`
  (`src/anomaly/mod.rs:1302`). Individual scores range roughly 15–98.
- Aggregate score = **sum of all hit scores, capped at 100.0**
  (`src/anomaly/mod.rs:1611`).
- If `score < confidence_threshold` (default 60.0) the event is dropped
  (`src/anomaly/mod.rs:1612`).
- `score_to_severity` (`src/anomaly/mod.rs:1746`): ≥90 Critical, ≥75 High,
  ≥50 Medium, ≥25 Low, else Info.
- `response_action` (`src/anomaly/mod.rs:1754`): Critical→`IsolateHost`,
  High→`KillProcess(pid)`, Medium→`Alert`, else `Monitor`.

### Self-exclusion
`analyze` never scores the agent's own process or its direct children (match by
PID/PPID) or by name `nebula-agent`/`nebula-agent.exe`
(`src/anomaly/mod.rs:1593-1600`). Without this the agent flags itself while doing
YARA memory sweeps and `/proc` walks.

### Platform awareness
`current_platform()` resolves at compile time via `cfg!`
(`src/anomaly/mod.rs:49`). The T1078 "unexpected privileged process" rule is
platform-split (`src/anomaly/mod.rs:272-302`): on Linux/macOS it flags `uid==0`
outside a daemon allowlist (score 50); on Windows it uses the user SID (system
SIDs S-1-5-18/19/20 via `is_windows_system_sid`, `src/anomaly/mod.rs:62`) against
a ~30-name system-process allowlist and only scores 35 (review, not critical).
This exists because the collector reports `uid=0` for every Windows process,
which previously false-fired CRITICAL on `lsass.exe` every boot. Related LSASS
guard: the credential-dump rule requires an actual dumping indicator in the
command line, not merely `lsass.exe` running (`src/anomaly/mod.rs:410-418`).

### Tactic / technique coverage (representative, not exhaustive)
All 14 ATT&CK tactics plus an ATLAS `ml_attack` pseudo-tactic:

- **TA0043 Reconnaissance** — T1595/T1596/T1590/T1591/T1598 (nmap, shodan, DNS,
  gophish/evilginx).
- **TA0042 Resource Development** — T1587/T1583/T1588/T1608/T1660 (msfvenom,
  Cobalt Strike beacon, ngrok, searchsploit, BGP hijack).
- **TA0001 Initial Access** — T1190 (webshell: web server spawning shell,
  PHP eval), T1566 spearphishing, T1133, T1505.003, T1195 supply chain
  (pipe-to-shell), CVE exploit strings.
- **TA0002 Execution** — T1059 (.001 PowerShell encoded, .003 Wine cmd, .004
  Unix shell/`/dev/tcp`, .005 wscript, .006 python/perl/ruby, .007 node, .009
  cloud API, .010 AutoHotKey), T1203, T1204, T1569, T1610 privileged container,
  T1609 container exec, GTFOBins (vim `:!`, `find -exec`, `less !`).
- **TA0003 Persistence** — T1053 cron/at/anacron/schtasks, T1136, T1098.004 SSH
  keys, T1543, T1546 (.003/.004/.005 trap/.013/.015 udev), T1547 (rc.local,
  kernel module, user systemd), T1505.003 webshell, T1574 (LD_PRELOAD,
  ld.so.conf.d, site-packages), T1542 firmware/GRUB.
- **TA0004 Privilege Escalation** — T1055.008 ptrace, T1068 (DirtyCow, PwnKit,
  DirtyPipe), T1078, T1548 (sudo/SUID/pkexec), T1134 tokens/capabilities,
  T1611 container escape (nsenter, cgroup write, unshare, overlay).
- **TA0005 Defense Evasion** — T1027 obfuscation, T1036 masquerade (svchost,
  double-extension), T1055 full injection suite incl. `/proc/PID/mem` writes
  (score 95-97), T1070 log/history clearing/timestomp, T1222 chattr/setfacl,
  T1497 sandbox, T1562 (SELinux, firewall, auditd, ETW/PatchGuard, TLS
  downgrade, Linux audit T1562.012), T1620 memfd fileless, T1218 LOLBins,
  T1220 XSL, T1140 certutil/base64, T1480 guardrails, T1553 trust, T1014
  rootkit, T1656 impersonation.
- **TA0006 Credential Access** — T1003 (.001 mimikatz/LSASS, .003 NTDS.dit,
  .004 LSA, .005 DCC2, .006 DCSync, .007 `/proc` mem, .008 /etc/shadow),
  T1110 (.001-.004 brute/crack/spray/stuffing), T1040 sniffing, T1187
  Responder/NTLM relay, T1212 (Zerologon, PetitPotam), T1552, T1556 PAM,
  T1558 Kerberoast/AS-REP, T1606 JWT/Golden SAML, T1621 MFA fatigue,
  T1649 ADCS/Certipy.
- **TA0007 Discovery** — T1082/T1083/T1057/T1069/T1087/T1046/T1049/T1518/
  T1016/T1120/T1526/T1613/T1654 (host, files, processes, groups, accounts,
  network/service scan, cloud, containers, log enum).
- **TA0008 Lateral Movement** — T1021 (.001 RDP, .002 SMB/PsExec, .003
  DCOM/WMI, .004 SSH, .005 VNC, .006 WinRM), T1047 WMI, T1550 (.002 PtH,
  .003 golden/silver ticket), T1570, T1534, T1599/T1600/T1601 network device.
- **TA0009 Collection** — T1005/T1039/T1056 keylogger/T1074 staging/T1113
  screen/T1115 clipboard/T1213/T1530/T1602/T1565.002 MITM.
- **TA0011 Command & Control** — T1071 (C2 ports 4444/1337/31337, DNS port 53,
  protocol subs), T1095 raw/ICMP, T1105 curl/wget download, T1132 encoding,
  T1219 remote-access sw, T1571 non-standard port, T1572 tunneling
  (SSH -R/-L/-D, iodine/dns2tcp/dnscat, chisel/ligolo/socat), T1573, T1568 DGA,
  T1659 content injection.
- **TA0010 Exfiltration** — T1048 (curl -T, ftp put, nc), T1052 dd raw disk,
  T1567 cloud upload.
- **TA0040 Impact** — T1485 destruction, T1486 mass encryption, T1489 service
  stop, T1490 shadow/backup deletion, T1491 defacement, T1496 cryptominer
  (xmrig/stratum), T1498/T1499 DoS (hping3, slowloris, fork bomb), T1529
  shutdown, T1565 data manipulation, T1653 power settings, T1657 financial
  (wallet.dat, seed phrase).
- **MITRE ATLAS `ml_attack`** (`src/anomaly/mod.rs:758-848`) — AML.T0040 (ML
  inference API abuse), AML.T0043 adversarial input, AML.T0051 prompt-injection
  via file, AML.T0057 model backdoor (.gguf/.safetensors/.pt/.pkl writes,
  Ollama tampering), AML.T0016 model exfil, AML.T0018 training-data poisoning,
  AML.T0048 LLM probing patterns, AML.T0054 jailbreak.

### Attack-chain correlation
- 35 built-in `ChainPattern`s in `all_chain_patterns()`
  (`src/anomaly/mod.rs:1307-1555`): Web-to-Shell, spearphish→PowerShell,
  cred-dump→lateral, Log4Shell→persistence, ransomware (T1490→T1486),
  cryptominer, PtH, Kerberoast→golden ticket, DNS tunneling, DCSync→golden
  ticket, container-escape, process-hollowing→C2→lateral, MFA-fatigue→cloud,
  insider data-staging, etc.
- `update_chains` (`src/anomaly/mod.rs:1674`): per-host `ActiveChain`s tracked in
  a `DashMap`, pruned to `chain_window_secs` (default 300s). A chain fires when
  `chain_conf = score * (matched/required) >= min_confidence` AND at least **2**
  required techniques matched (`src/anomaly/mod.rs:1730`). Configured
  `chain_patterns` are merged with the built-ins before matching
  (`src/anomaly/mod.rs:1636-1639`).

### Key types
`MitreRules`, `MitreRulesExtended`, `MitreRulesV15Complete`, `TechniqueHit`,
`AnomalyEngine`, `ActiveChain`, `Platform`, `ChainPattern` (in
`src/config.rs`), `AttackChain`/`ChainStage` (in `src/types.rs`).

### Entry point + wiring
- Constructed: `AnomalyEngine::new(cfg.anomaly.clone())` — `src/main.rs:244`.
- Invoked per event: `src/main.rs:1274`. Returns `Option<ThreatEvent>`; feeds the
  precedence merge (fifth priority).

### Config keys + defaults (`[anomaly]`, `src/config.rs:286-304`)
| Key | Default | Effect |
|-----|---------|--------|
| `heuristic_enabled` | `true` | Master switch; `analyze` returns `None` if false (`src/anomaly/mod.rs:1584`). |
| `ml_enabled` | `false` | Gates the **baseline** engine (§3), not the heuristics. |
| `baseline_window_days` | `14` | Passed to the baseline engine's learn window. |
| `chain_detection` | `true` | Enables chain correlation. |
| `chain_window_secs` | `300` | Chain correlation window. |
| `confidence_threshold` | `60.0` | Minimum aggregate score to emit. |
| `chain_patterns` | `[]` | Operator-supplied extra chains, merged with the 35 built-ins. |

### External interactions
Reads `RawEvent`s from the collector; emitted `ThreatEvent`s are forwarded to
Nexus and drive forensics/response downstream. No direct network or disk I/O in
the engine itself (pure in-memory scoring + `DashMap` chain state).

### Limitations
- Substring/`to_lowercase` command-line matching — evadable by obfuscation the
  string checks don't cover, and prone to false positives on benign commands
  containing keywords.
- Summed-then-capped scoring means several low-value discovery hits on one event
  can stack toward the 60 threshold.
- Chain state is in-memory only (lost on restart) and per-host.
- Network-port C2 heuristics are noisy on hosts with legitimate high-port
  outbound traffic.

---

## 2. `apt/` — long-dwell correlation & slow-C2 detection

**File:** `src/apt/mod.rs` (578 lines)

### Purpose
Detect Advanced Persistent Threat behavior by its *statistical* signature —
slow, quiet, human-operated — which is the opposite of commodity malware. Four
detection surfaces: LOTL command patterns, LOTL file artifacts, low-and-slow C2
beaconing, and multi-tactic long-dwell chains. Explicitly does **not** attempt
actor attribution (header comment models APT29/41/28, Lazarus, Scattered Spider
TTPs for reference only).

### Capabilities
1. **LOTL command patterns** — `check_lotl_command` (`src/apt/mod.rs:286`) over
   `APT_LOTL_COMMANDS` (`src/apt/mod.rs:207-235`), ~24 patterns matched as
   `.*`-split substring-AND. Confidence 70-88, e.g.:
   - `powershell … -windowstyle hidden` → T1059.001 (88)
   - `powershell … downloadstring` → T1105 (88)
   - `wmic … process … call … create` → T1047 (85)
   - `schtasks … /create … xml` → T1053.005 (80)
   - `regsvr32 … /s … /n` (Squiblydoo) → T1218.010 (85)
   - `certutil … -urlcache … -f` → T1105 (85)
   - `mshta … vbscript` (Lazarus) → T1218.005 (85)
   - `aws … sts … assume-role … duration` → T1528 (78)

   ≥85 confidence → `Severity::High`, else `Medium`. Action:
   `CollectForensics`.
2. **LOTL file artifacts** — `check_lotl_artifact` (`src/apt/mod.rs:317`) over
   `LOTL_ARTIFACT_PATHS` (`src/apt/mod.rs:171-203`), ~21 path prefixes.
   Writes score full confidence; reads are down-weighted `×0.7` and dropped
   below 55. Covers WMI consumer, root/user `authorized_keys` (T1098.004, 90/85),
   `sshd_config.d/`, D-Bus policy, transient systemd units, `nsswitch.conf`/PAM
   (T1556.003), system Python/Ruby libs (T1574), git hooks, `update-motd.d/`,
   `profile.d/`, sudo plugins, udev rules (T1546.015), NetworkManager dispatcher
   (T1037.004). ≥80 → High. Emits a `FilePath` IOC.
3. **Slow-C2 beacon** — `update_slow_beacon` (`src/apt/mod.rs:354`). Tracks
   outbound `NetworkConnect` to public IPs keyed `ip:port` in
   `SlowBeaconRecord` (last 50 contacts). `is_apt_beacon`
   (`src/apt/mod.rs:123`) computes inter-arrival intervals (hours), mean, and
   jitter coefficient-of-variation (CV = stddev/mean). Fires when: mean interval
   **0.5-24h**, **CV 0.15-0.85**, **≥4 contacts**, observed **≥6h**. Alerts on
   every 5th qualifying contact. Severity High, confidence 80, techniques
   T1071.001 + T1102, action `Alert`. Emitted via `tx` channel (not the merge).
4. **Long-dwell multi-tactic chain** — `update_dwell_chain`
   (`src/apt/mod.rs:408`) records "interesting" events per host into a
   `DwellChain` (up to 1000 entries, tactics inferred from event type). The
   hourly `start_dwell_chain_sweeper` (`src/apt/mod.rs:460`) prunes chains idle
   >30 days and alerts when: **≥3 tactics over ≥3 days**, OR **≥4 tactics over
   ≥1 day**, OR **≥5 tactics any time** (`src/apt/mod.rs:489-492`). Severity
   Critical if dwell ≥7 days else High; confidence `72 + min(dwell_days*2, 20)`;
   action `CollectForensics`. Emitted via `tx` channel.

### Key types
`AptDetector`, `DwellChain` / `DwellChainEntry`, `SlowBeaconRecord`,
`AptBeaconInfo`. State: `dwell_chains: HashMap<host, DwellChain>` and
`slow_beacons: HashMap<"ip:port", SlowBeaconRecord>` behind `tokio::Mutex`.

### Entry points + wiring
- Constructed: `apt::AptDetector::new(...)` → `(detector, apt_rx)` at
  `src/main.rs:356-357`; `apt_detector.start().await?` (spawns the two sweepers)
  at `src/main.rs:358`.
- Per-event: `apt_detector.analyze(&event).await` at `src/main.rs:1265` — runs
  LOTL command → LOTL artifact → beacon update → dwell update
  (`src/apt/mod.rs:272-282`); only LOTL matches return synchronously (4th merge
  priority). Beacon/dwell alerts go through the channel loop
  (`src/main.rs:961-970`).

### Config keys + defaults
None specific to APT — no `AptConfig`. Thresholds (30-day windows, CV band,
tactic/dwell counts) are hard-coded constants. Instantiated with `agent_id` and
`hostname` only.

### External interactions
Forwards its channel `ThreatEvent`s to Nexus (`src/main.rs:965`). The header
comment mentions SQLite persistence of dwell chains, but the current
`AptDetector` keeps chain/beacon state **in memory only** — it does not survive
restart despite the 30-day window intent.

### Limitations
- Dwell-chain tactic inference is coarse (mapped from event type, not from the
  anomaly engine's real technique classification).
- Beacon detection needs ≥6h and ≥4 contacts, so genuinely slow campaigns take a
  long time to surface; also skips all RFC1918/private destinations.
- LOTL command matching is `.*`-split substring-AND — order-insensitive and
  evadable.
- In-memory state contradicts the persistence claim in the module header.

---

## 3. `baseline/` — unsupervised behavioral ML (ML-gated)

**Files:** `src/baseline/mod.rs` (432), `src/baseline/features.rs` (256)

### Purpose
Learn what is *normal* for this specific host over a rolling window, then flag
statistically significant deviations — with no neural net/GPU, fully explainable
(each anomaly carries observed-vs-expected reasons). Runs alongside the
signature/heuristic engines; its value is corroboration (see baseline fusion §0).
**Disabled unless `anomaly.ml_enabled = true`.**

### Capabilities (five deviation dimensions)
1. **Novelty** — entity never seen (new process, new parent→child lineage, new
   uid, new process→dest-IP pair).
2. **Rarity** — known entity but `count < 5`.
3. **Temporal** — entity with `count > 50` active in an hour whose historical
   frequency `< rarity_floor` (default 0.01).
4. **Numeric** — Welford online mean/variance + EWMA z-score on continuous
   signals (e.g. dest port), z gated to `n ≥ 30` (`RunningStats`,
   `src/baseline/mod.rs:56-77`).
5. **Multivariate** — **Half-Space Forest** (`HalfSpaceForest` /`HsTree`,
   `src/baseline/mod.rs:104-182`): online random-split trees over a 14-dim
   feature vector, reference/current mass windows rolled every 256 observations,
   returns a z-score of the raw forest score. Flags when `|z| > z_threshold`
   (default 3.5).

Per-entity evaluation `eval_entity` (`src/baseline/mod.rs:350`) sums a per-signal
score; `analyze` (`src/baseline/mod.rs:264`) takes the max across entities and
the forest.

### Feature vector (`src/baseline/features.rs`, `FEATURE_DIMS = 14`)
`extract` (`src/baseline/features.rs:149`) produces normalized [0,1] dims:
hour-of-day, root boolean, command-line Shannon entropy, arg count, cmd length,
`command_suspicion` (offensive-marker count), `has_encoded_blob` (≥40-char
base64 run), `path_suspicion` (HOT `/tmp`,`Temp`,`Downloads` = 1.0 / COLD system
dirs = 0.0), `name_randomness` (digit-ratio + name entropy), name length,
`lineage_hash` (FNV-1a of parent→child), dest-IP present, dest-port, file-path
present. Unit-tested at file bottom.

### Maturity & scoring
- `maturity()` (`src/baseline/mod.rs:258`) = elapsed / learn window, clamped 1.0.
  During learning (`maturity < 1.0`) it suppresses weak signals: returns `None`
  if `max_score < 2.0` (`src/baseline/mod.rs:319`).
- `confidence = (max_score/4).min(1)*100 * (0.4 + 0.6*maturity)`, capped 95
  (`src/baseline/mod.rs:321-322`).
- Severity: ≥80 High, ≥55 Medium, ≥30 Low, else Info. Action is always
  `Monitor`; technique list empty; tactic tagged `discovery`
  (`src/baseline/mod.rs:323-347`).

### Persistence
SQLite at `platform::data_dir()/baseline.db`
(`/var/lib/nebula/baseline.db` on Linux, `C:\ProgramData\NebulaSentinel\...` on
Windows). Tables `baseline_profiles` and `baseline_meta` (records `started_at`
so the learn window accrues across restarts). `open`/`persist`/`load`/`summary`
at `src/baseline/mod.rs:198-431`. `main.rs` persists periodically
(`src/main.rs:261`).

### Env-var tunables (read in `open`, `src/baseline/mod.rs:243-254`)
| Env var | Default | Meaning |
|---------|---------|---------|
| `NEBULA_ANOMALY_TREES` | 25 | forest tree count |
| `NEBULA_ANOMALY_DEPTH` | 8 | tree depth / resolution |
| `NEBULA_ANOMALY_ZTHRESH` | 3.5 | std-devs to flag an outlier |
| `NEBULA_ANOMALY_RARITY` | 0.01 | temporal rarity floor |

### Key types
`BaselineEngine`, `RunningStats` (Welford+EWMA), `EntityProfile` (hour/DOW
histograms), `HalfSpaceForest`, `HsTree`.

### Entry points + wiring
- Constructed conditionally: `baseline::BaselineEngine::open(agent_id, hostname,
  cfg.anomaly.ml_enabled, cfg.anomaly.baseline_window_days, ...)` —
  `src/main.rs:248-259`. On open failure it logs and disables (`None`).
  The `enabled` flag is `cfg.anomaly.ml_enabled` (`src/main.rs:251`).
- Per-event: `src/main.rs:1277-1280`; `analyze` returns `None` immediately if
  `!self.enabled` (`src/baseline/mod.rs:265`). Lowest merge precedence; also used
  for fusion boost.

### Config keys + defaults
Gated by `anomaly.ml_enabled` (default **false**); window from
`anomaly.baseline_window_days` (config default **14**; module doc comment says
21 — the config value wins). Forest/threshold tuning via the env vars above.

### External interactions
Local SQLite only; no network. Consumes `RawEvent`s, emits `ThreatEvent`s into
the merge.

### Limitations
- Off by default (requires `ml_enabled`).
- Cold-start: low confidence and suppressed weak signals until the learn window
  matures.
- Always `Monitor` action and empty technique list — designed as corroboration,
  not a standalone blocker.
- Entity profiles are unbounded in memory (one per distinct process/lineage/
  uid/dest key) between persist cycles.

---

## 4. `ransomware/` — file-I/O detection & prevention

**File:** `src/ransomware/mod.rs` (559 lines)

### Purpose
Detect ransomware by **file-system I/O patterns**, not command lines (modern
ransomware encrypts in-process, so no `openssl`/`gpg` appears on the cmdline).
Highest merge precedence, and the only engine with an inline auto-kill path in
Protect mode.

### Capabilities
File events (`analyze_file_event`, `src/ransomware/mod.rs:233`):
1. **Ransom-note creation** — filename matches the runtime note set → Critical,
   confidence **96**, T1486, fires on first note (`:251`).
2. **Known ransom extension** — path ends with a known extension; alerts after
   **≥3** such files from one PID → Critical, confidence **97**, T1486
   (`:277-304`).
3. **Mass high-entropy write rate** — one process writing **>100 unique files**
   at **>200/min** into user-data dirs (`/home`, `/var/www`, `/srv`, `/opt`,
   `/media`, `/mnt`) AND `check_file_entropy` on the file ≥7.5/8.0 → Critical,
   confidence **88**, T1486 (`:307-351`). Entropy uses Shannon over the first
   64KB, requiring ≥512 bytes (`check_file_entropy`, `src/ransomware/mod.rs:545`).

Process events (`analyze_process_event`, `src/ransomware/mod.rs:356`):
4. **Backup/security-tool termination** (`BACKUP_PROCESSES`: veeam, acronis,
   vss, wbengine, …) via systemctl/taskkill/net stop/sc stop → High, conf 82,
   T1489 (`:361-383`).
5. **Shadow-copy / recovery deletion** (`vssadmin`, `wbadmin`, `diskshadow`,
   `schtasks /delete`) → Critical, conf 93, T1490 (`:386-405`).
6. **Mass `chmod 000`** on user data dirs → Critical, conf 90, T1485
   (`:408-420`).

**Slow-ransomware sweeper** — `start_activity_sweeper` (`src/ransomware/mod.rs:427`),
30s ticker: stale entries (process gone >5min) pruned; a process with **≥2**
ransom-extension files over ≥1 min → Critical, conf **92**, `KillProcess(pid)`.
Emitted via `tx` channel.

All synchronous detections set `suggested_action = KillProcess(pid)`
(`make_ransomware_threat`, `src/ransomware/mod.rs:531`).

### Auto-kill (Protect mode)
Threats sent to the channel are handled by the ransomware event loop
(`src/main.rs:942-956`): in `AgentMode::Protect` it calls
`resp_r.execute_action(&threat.suggested_action, threat.confidence)` immediately,
then forwards to Nexus. Synchronous `analyze` hits win the merge (top priority)
and are killed via the shared downstream response path.

### Runtime-extendable intel
Extension/note sets seed from `DEFAULT_RANSOM_EXTENSIONS`
(`src/ransomware/mod.rs:45`, ~40 families: LockBit, BlackCat, Clop, REvil, Ryuk,
Conti, WannaCry, DarkSide, etc.) and `DEFAULT_RANSOM_NOTE_NAMES` (`:74`), stored
lowercased in `Arc<StdRwLock<HashSet>>`. Live-extended from the Nexus intel feed
via `add_ransom_extension` / `load_ransom_extensions` /
`load_ransom_note_names` (`:163-192`) — new families propagate fleet-wide with no
rebuild. Loaded from intel in the poll loop (`src/main.rs:606-611`).

### Key types
`RansomwareDetector`, `ProcessFileActivity` (per-PID write tracker),
free fn `check_file_entropy`.

### Entry points + wiring
- Constructed: `ransomware::RansomwareDetector::new(...)` → `(detector, ransom_rx)`
  at `src/main.rs:352-353`; `.start().await` (spawns sweeper) at `src/main.rs:354`.
- Per-event: `src/main.rs:1262` (top merge priority). Only `FileWrite`/`FileOpen`
  and `ProcessExec` events are analyzed (`src/ransomware/mod.rs:222-231`).

### Config keys + defaults
No dedicated config struct; auto-kill gated on global `cfg.mode == Protect`.
Thresholds (3 files, >100/>200-per-min, entropy 7.5, ≥2 slow) are hard-coded.

### External interactions
Reads target files from disk for entropy sampling; pulls extension/note intel
from Nexus; emits kill actions through the response engine in Protect mode.

### Limitations
- Rate/entropy path only counts writes into a fixed set of user-data dir
  prefixes (Linux-oriented; `/home`, `/var/www`, etc.) — encryption elsewhere is
  caught only by known-extension/note heuristics.
- `check_file_entropy` reads the just-written file synchronously (I/O on the
  event path) and can miss if the file is already gone.
- Known-extension detection depends on intel freshness for novel families.

---

## 5. `zeroday/` — exploitation-by-effect & memory scanning

**File:** `src/zeroday/mod.rs` (299 lines)

### Purpose
Detect zero-day exploitation with no signature by looking at *effects* that hold
regardless of the specific CVE: impossible process ancestry, shellcode memory
regions, sensitive-file access by service accounts, and fileless (deleted-on-disk
/ memfd) execution. Second-highest merge precedence.

### Capabilities
1. **Anomalous process ancestry** — `ANOMALOUS_ANCESTRY`
   (`src/zeroday/mod.rs:52-87`), ~30 parent→child pairs that have no legitimate
   use, e.g. `nginx`/`apache2`/`httpd`/`tomcat`/`php-fpm`/`node`/`ruby` → shell
   (T1190 webshell/RCE), `java` → bash (T1059.004 deserialization), `mysqld`/
   `postgres`/`mongod` → shell (T1190 UDF/injection), `postfix`/`exim` → shell,
   `evince`/`libreoffice`/`acroread` → shell (T1204.002 malicious document),
   `runc`/`containerd` → nsenter (T1611 escape), `chromium`/`firefox` → bash
   (T1203 browser exploit), `sshd` → `bash -i` (T1078 auth bypass). Parent name
   resolved from an in-memory process cache. Match → **Critical**, confidence
   90, `KillProcess` (`analyze`, `src/zeroday/mod.rs:135-170`).
2. **Sensitive-file access by unexpected process** — `SENSITIVE_FILE_ACCESS`
   (`src/zeroday/mod.rs:100-107`): e.g. `nginx`/`apache`/`www-data`/`sshd`/
   `mysqld` reading `/etc/shadow`, `/etc/passwd`, or `/proc/self/mem`
   (T1003.008 / T1055). On `FileOpen`/`FileWrite` → Critical, conf 90
   (`:172-189`).
3. **Live shellcode memory scan** — on `MemoryMap` events, `scan_process_maps`
   (`src/zeroday/mod.rs:278`) parses `/proc/PID/maps` against `SUSPICIOUS_MAPS`
   (`:90-97`): `rwx` anonymous / `[heap]` / `[stack]` / `/dev/shm` / `/tmp`
   mappings (T1055 shellcode/heap-spray/fileless), and `r-xp (deleted)` mappings
   (T1027.007 fileless payload). Known JIT engines (`libjvm`, `libv8`, `libjs`,
   `mono`) are skipped to cut false positives. Match → Critical, conf 90.
4. **Proactive process sweep** — `scan_all_processes`
   (`src/zeroday/mod.rs:211`) walks all of `/proc`, runs `scan_process_maps` on
   every PID, and flags **deleted-on-disk executables** (`/proc/PID/exe` link
   ending ` (deleted)`) → High, T1027.007. Called on a periodic schedule
   (`src/main.rs:1051-1052`), not per-event.

All `make_zeroday_threat` outputs (`src/zeroday/mod.rs:253`) carry
`suggested_action = KillProcess(pid)`, tactics `initial_access` + `execution`,
matched rules `zeroday_behavioral` + `process_ancestry`.

### Key types
`ZeroDayDetector`, `ProcessInfo` (pid→name/ppid/parent cache), free fn
`scan_process_maps`.

### Entry points + wiring
- Constructed: `zeroday::ZeroDayDetector::new(...)` at `src/main.rs:363`.
- Per-event: `src/main.rs:1271` (2nd merge priority).
- Periodic sweep: `zeroday_c.scan_all_processes().await` at `src/main.rs:1052`
  (results sent to Nexus in that loop).

### Config keys + defaults
None — no config struct; ancestry/map/file tables are hard-coded constants.

### External interactions
Reads `/proc/<pid>/{comm,exe,maps}` from procfs; emits `KillProcess` threats into
the merge and the periodic-scan loop.

### Limitations
- **Linux-only** for memory/procfs scanning (`/proc/PID/maps`, `/proc/PID/exe`);
  no Windows equivalent in this module.
- Ancestry detection depends on the collector delivering `ProcessExec` events and
  on the parent already being in the in-memory cache (parent name is empty if the
  parent PID wasn't observed).
- Fixed allow/deny lists; a legitimate but unusual parent→child pair (e.g. a web
  app that genuinely shells out) will false-fire at Critical/kill.
- JIT allowlist is name-substring based and could be spoofed.

---

## Cross-cutting notes

- **ThreatEvent** is the shared currency; `suggested_action` determines response
  (`Monitor`/`Alert`/`CollectForensics`/`KillProcess`/`IsolateHost`).
- **Protect vs Detect mode** (`config::AgentMode`, resolved `src/main.rs:155`)
  gates enforcement: ransomware auto-kill (`src/main.rs:948`), NetGuard firewall
  blocking (`src/main.rs:1222`), and destructive playbook steps only act in
  Protect mode.
- **Forensics** are confidence-gated and captured *before* a destructive action
  when `capture_before_response` is set, to avoid racing the process kill
  (`src/main.rs:1316-1348`).
- Only ransomware, APT, and DLP own side channels/sweepers that emit outside the
  precedence merge; anomaly, zero-day (per-event), and baseline emit only through
  their synchronous `analyze` return into the merge.
