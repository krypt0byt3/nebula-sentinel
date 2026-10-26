# NebulaSentinel Agent — Network Monitoring & Defense

Current-state technical reference for the three network-facing modules of the
`nebula-agent`: `network_monitor`, `netguard`, and `firewall`. All descriptions
below reflect the code as it exists in `src/` today.

Source files:
- `/nebulasentinel/nebula-agent/src/network_monitor/mod.rs` (433 lines)
- `/nebulasentinel/nebula-agent/src/netguard/mod.rs` (245 lines)
- `/nebulasentinel/nebula-agent/src/firewall/mod.rs` (763 lines)
- Wiring: `/nebulasentinel/nebula-agent/src/main.rs`

How they relate: `firewall` is the low-level enforcement abstraction (adds/removes
kernel rules). `netguard` is a policy layer *on top of* `firewall` that decides
*when* to block (connection rules, reputation, brute-force tracking). `network_monitor`
is a passive *detection-only* sensor that emits `ThreatEvent`s but never blocks.

---

## 1. `network_monitor` — Passive traffic analysis sensor

### Purpose
Continuous, dependency-light network telemetry analysis to catch patterns that
per-event anomaly scoring misses: C2 beacons, DNS tunneling, DGA/fast-flux, and
cloud-metadata credential theft. It is **detection only** — every finding is sent
as a `ThreatEvent` down the mpsc channel; it never touches the firewall.

### Data sources
- Linux: `/proc/net/tcp` and `/proc/net/tcp6` (ESTABLISHED state `01`), parsed as
  little-endian hex addresses (`parse_hex_addr`, `mod.rs:312`).
- Windows: `netstat -n -p tcp`, parsing the foreign-address column of ESTABLISHED
  rows (`read_windows_connections`, `mod.rs:265`). No admin required.
- DNS: `journalctl -u systemd-resolved --since "30 seconds ago"`, falling back to
  parsing the last 1000 lines of `/var/log/syslog` for `named`/`dnsmasq`
  `query[...]` entries (`read_recent_dns_queries`, `mod.rs:336`).
- Loopback / `0.0.0.0` / `::1` are skipped at parse time.

### Capabilities — detection algorithms & thresholds

**1. C2 beacon detection** (`start_connection_tracker`, `mod.rs:78`)
- Polls established connections **every 10 seconds**.
- Per destination `ip:port` it keeps a rolling window of up to **20** inter-poll
  intervals (seconds between observations, only counted if > 0.5s apart).
- Once ≥ **5** intervals are recorded, computes the **coefficient of variation**
  (CV = stddev/mean, population variance; `coefficient_of_variation`, `mod.rs:393`).
- Fires when **CV < 0.3** AND average interval **> 5.0s and < 300.0s** AND
  connection `count ≥ 10`, provided the destination is not "known good".
- MITRE **T1071.001**, Severity High, confidence 85.0. Emits an IPv4 IOC
  (confidence 80.0, source `beacon_detector`).
- "Known good" (`is_known_good_ip`, `mod.rs:401`): RFC-1918 (`10.`, `192.168.`,
  `172.16`–`172.3x` via prefix matches), `127.`, and public resolvers
  `8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1`.
- A `count > 50` to a non-known-good IP only logs a debug line (no event).

**2. DNS tunneling detection** (`start_dns_monitor`, `mod.rs:156`)
- DNS loop runs **every 30 seconds**.
- Computes **Shannon entropy** over the full domain string (`shannon_entropy`,
  `mod.rs:383`) and the length of the first (left-most) DNS label.
- Fires when **entropy > 3.8** AND **first-label length > 30**.
- MITRE **T1071.004**, Severity High, confidence 80.0. Domain IOC (confidence 75.0).
- Retains a rolling buffer of the last **10,000** DNS queries.

**3. DGA / fast-flux detection** (same DNS loop, `mod.rs:191`)
- Derives the parent domain (`splitn(3,'.').skip(1)`), counts how many of the
  currently-observed domains end with that parent.
- Fires when **> 20** unique subdomains share a parent within the 30s window AND
  the parent is not a CDN (`is_cdn_domain`, `mod.rs:409`: cloudflare, fastly,
  akamai, amazonaws, azureedge, cloudfront, googleapis, gstatic).
- MITRE **T1568.002**, Severity High, confidence 75.0. Domain IOC (confidence 70.0).

**4. Cloud-metadata access** — two independent paths:
- In the 10s connection loop: any established connection to `169.254.169.254`
  raises MITRE **T1552.005**, Severity **High**, confidence 90.0 (`mod.rs:140`).
- Linux-only fast-path (`start_metadata_monitor`, `mod.rs:220`): every **5
  seconds** greps raw `/proc/net/tcp` for `FEA9FEA9`/`fea9fea9` (169.254.169.254
  little-endian). Raises MITRE **T1552.005**, Severity **Critical**, confidence
  95.0. Skipped on Windows (`#[cfg(not(target_os = "windows"))]`) because the
  connection tracker already covers it there.

### Key types
- `NetworkMonitor` — owns `tx: mpsc::Sender<ThreatEvent>`, plus `Arc<Mutex<...>>`
  maps for tracked connections and DNS history.
- `TrackedConn` — dest ip/port, first/last seen, count, `intervals: Vec<f64>`,
  bytes_sent (currently always 0).
- `DnsQuery` — domain, query_type (hard-coded `"A"`), timestamp, response_len.
- All events built by `make_network_threat` (`mod.rs:415`): tactic
  `command_and_control`, matched rule `network_monitor`, suggested action
  `ResponseAction::Alert`.

### Entry points & main.rs wiring
- Constructed: `network_monitor::NetworkMonitor::new(...)` → `(monitor, net_rx)`
  at `main.rs:395`.
- Started: `net_monitor.start().await?` at `main.rs:397`, which spawns the three
  background tasks (`start()`, `mod.rs:64`).
- Consumed: a dedicated task drains `net_rx` and forwards every threat to Nexus
  via `n.send_threat(&threat)` — `main.rs:1024`.
- Health surfaced in the status UI as module `network_monitor` /
  "beacon + DNS tunnel detection" (`main.rs:194`).

### External interactions
- Filesystem: `/proc/net/tcp{,6}`, `/proc/sys/...` not used here; `/var/log/syslog`.
- Subprocesses: `netstat` (Windows), `journalctl` (Linux DNS).
- Outbound: threat events → Nexus.

### Limitations
- Purely observational — never blocks (that is `netguard`/`firewall`'s job).
- `bytes_sent` is never populated, so the "large sustained transfer / exfil"
  path is effectively inert (only a debug log at count > 50).
- Beacon CV needs ≥ 5 samples at ≥ 10s cadence → slow beacons (> 300s) and very
  fast ones (< ~5s) are outside the detection band; intervals are poll-derived,
  not true connection timestamps.
- DNS parsing is best-effort log scraping; if neither systemd-resolved nor
  dnsmasq/named logging is present, DNS detection sees nothing.
- All thresholds are hard-coded constants (no config or per-host tuning).
- Only IPv4 established connections are parsed from `/proc/net/tcp*` (IPv6 hex
  addresses are not decoded; the metadata fast-path is a raw substring match).

---

## 2. `netguard` — Host network self-protection (policy + fail2ban)

### Purpose
Protects *this host* (not a network) via three connection-level controls that
compile to firewall drop rules. It is the reputation-driven / connection-level
alternative to a packet-inspection IDS and requires no external dependency —
it drives the OS firewall through the `firewall` module and reuses reputation /
gossip IOC data supplied by the caller.

### Three protection layers
1. **Outbound C2/exfil blocking** — host reaching a known-bad IP is dropped.
2. **Inbound brute-force / scan auto-block** — fail2ban-style: N failures from one
   source IP within a window → temporary block.
3. **Connection rules** — operator/default rules over direction + port + proto +
   reputation that resolve to Block or Alert.

All blocks are TTL-tracked so they can be auto-lifted, and every action becomes a
`ThreatEvent`.

### Capabilities

**Default connection rules** (`default_rules`, `mod.rs:95`):
- "Block outbound to known-bad IP (C2/exfil)" — Outbound, `require_bad_reputation`,
  action Block.
- "Block inbound from known-bad IP" — Inbound, `require_bad_reputation`, Block.
- Additional rules can be appended via `add_rule` (`mod.rs:110`).

**Connection evaluation** (`evaluate_connection`, `mod.rs:114`):
- Guard: returns None if disabled or `peer_ip` fails `IpAddr` parse (`valid_ip`,
  `mod.rs:112`).
- Matches direction (Both matches any), optional port, optional proto
  (case-insensitive), and `require_bad_reputation`.
- A rule with action Block **actually blocks only when `enforce` is true** (Protect
  mode). When it blocks it calls `self.block(peer_ip, rule.name, ttl = bf_ban_secs)`.
- Emits a `ThreatEvent`: blocked → Severity High, confidence 85.0, action
  `BlockIp(ip)`; otherwise Severity Medium, confidence 60.0, action `Monitor`
  (description distinguishes "alert" vs "alert (detect mode)").

**Brute-force / fail2ban tracker** (`record_failure`, `mod.rs:149`):
- Per-source-IP `FailTracker{count, first_seen, last_seen}`.
- If the gap since `last_seen` exceeds the window, the counter resets.
- Increments on each failure; when `count ≥ bf_threshold` it fires and resets the
  counter to 0.
- On fire, blocks (only if `enforce`) with reason `"brute-force: <context>"` and
  TTL `bf_ban_secs`. Event: Severity High, confidence 80.0, action `BlockIp`
  (Protect) or `Monitor` (Detect).

**Defaults (hard-coded in `new`, `mod.rs:78`):**
- `bf_threshold = 5` failures
- `bf_window_secs = 300` (5-minute rolling window)
- `bf_ban_secs = 3600` (1-hour ban / block TTL)
- `enabled = true` always; `enforce` = caller-supplied (Protect mode).

**Block bookkeeping:**
- `block` (`mod.rs:179`): validates IP, dedupes against active blocks, calls
  `firewall.block_ip(ip)`, and records an `ActiveBlock{ip, reason, blocked_at,
  expires_at}` on success. Failures are logged, not fatal.
- `sweep_expired` (`mod.rs:198`): removes blocks whose `expires_at ≤ now` by
  calling `firewall.unblock_ip(ip)`.
- `active_blocks` (`mod.rs:214`): returns `(ip, reason)` list.

### Key types
- `NetGuard` — agent/hostname, `enabled`, `enforce`, owned `Firewall`, `rules`,
  `blocks` and `failures` maps (both `Arc<Mutex<HashMap>>`), and the three bf_* knobs.
- `ConnRule` — name, `Direction`, optional port/proto, `require_bad_reputation`,
  optional `rate_limit: (u32,u64)` (declared but not evaluated yet), `ConnAction`.
- `Direction { Inbound, Outbound, Both }`, `ConnAction { Block, Alert }`.
- `ActiveBlock`, `FailTracker`.
- Events via `mk_event` (`mod.rs:219`): tactic `command_and_control`, technique
  `T1071`, matched rule `netguard`, raw id `netguard:<ip>`.

### Entry points & main.rs wiring
- Constructed: `netguard::NetGuard::new(&agent_id, &hostname, matches!(cfg.mode,
  AgentMode::Protect), firewall.clone())` at `main.rs:331` — the Protect-mode
  boolean is what sets `enforce`.
- Expiry sweeper: a task ticks every **60s** calling `ng.sweep_expired()` —
  `main.rs:339–342`.
- **Outbound hook** (main event loop): for any event carrying
  `network_dest_ip`, computes `bad = gossip_engine.is_ioc_known(ip)` then calls
  `netguard.evaluate_connection(ip, port, proto, Direction::Outbound, bad)` —
  `main.rs:1216`. Proto defaults to `"tcp"`, port to `0`. Returned event is sent
  to Nexus. (Note: the separate gossip block path at `main.rs:1220` also blocks
  bad IPs via `response_engine`.)
- **Inbound brute-force hook** (main event loop, `main.rs:1242`): on
  `EventType::UserAuth` or `EventType::UserSu`, determines failure via
  `return_code != 0` OR `extra["auth_result"] == "failure"/"failed"`. If failed,
  extracts the source IP from `extra["src_ip"]` / `"source_ip"` / `"rhost"`
  (`main.rs:1248`), builds a context string, and calls
  `netguard.record_failure(src, &ctx)` at `main.rs:1254`; a returned event is
  forwarded to Nexus. Without a source IP the failure cannot be attributed and is
  ignored.

### External interactions
- Drives the `firewall` module (`block_ip` / `unblock_ip`).
- Consumes gossip/reputation verdict (`bad_reputation` bool passed in by caller).
- Emits `ThreatEvent`s to Nexus.

### Limitations
- Enforcement is entirely gated on Protect mode; in Detect/Audit it only alerts.
- `rate_limit` on `ConnRule` is defined but not enforced anywhere.
- Inbound rules exist in the default set, but the only wired call site passes
  `Direction::Outbound`; inbound protection in practice comes from the
  brute-force path, not from inbound connection-rule evaluation.
- Failure detection depends on the collector populating `src_ip`/`source_ip`/
  `rhost` and a meaningful `return_code`/`auth_result`.
- Thresholds are compile-time constants (5 / 300s / 3600s), not configurable.
- Block dedupe means an already-blocked IP won't refresh its TTL.

---

## 3. `firewall` — Cross-platform enforcement abstraction

### Purpose
A single API (`block_ip`, `unblock_ip`, `isolate`, `undo_isolation`) that detects
the host's available firewall tooling once at startup and dispatches to the right
backend, degrading gracefully (with actionable remediation logs) when no tool
exists. Used by both `netguard` and the response/playbook engines.

### Capabilities — backend auto-detection
`Firewall::detect()` (`mod.rs:69`) → `probe()` (`mod.rs:90`) selects in strict
priority order:
1. **Windows** (`#[cfg(target_os="windows")]`): always `WindowsFirewall`
   (`netsh advfirewall`). Present regardless of elevation; adding rules needs admin.
2. **nftables** — if `nft` binary exists AND `nft list ruleset` succeeds
   (`nft_kernel_ok`). Preferred on all Linux.
3. **firewalld** — if `firewall-cmd` exists AND `firewall-cmd --state` == running.
4. **ufw** — if `ufw` binary exists.
5. **iptables** — if `iptables` binary exists.
6. **None** — no tool; `block_ip` errors and warns, `isolate` uses `/proc` fallback.

`with_backend()` allows constructing from a known backend without probing.
`is_available()` returns `backend != None`.

### Capabilities — operations per backend

**block_ip / unblock_ip** (bidirectional src+dst drop):
- **nftables** (`mod.rs:175`): ensures `inet nebula` table + input/output chains
  (priority 100, policy accept), adds `ip saddr <ip> drop` / `ip daddr <ip> drop`.
  Unblock **flushes both nebula chains** (removes *all* per-IP blocks, not just one).
- **firewalld** (`mod.rs:245`): rich rules dropping source and destination
  `<ip>/32`; unblock removes the same rich rules.
- **ufw** (`mod.rs:295`): `ufw deny from <ip>` and `deny ... to <ip>`; unblock via
  `ufw delete deny ...`.
- **iptables** (`mod.rs:341`): `-A` DROP on INPUT/OUTPUT/FORWARD for `-s` and `-d`;
  adds ip6tables rules if `ip6tables` exists. Unblock uses matching `-D`.
- **Windows** (`mod.rs:409`): paired `dir=out`/`dir=in` block rules named
  `NebulaSentinel-Block-<ip>-{out,in}` scoped by `remoteip`; unblock deletes by name.
- **None**: `no_firewall_warn` returns Err with install advice.

**isolate(allowlist)** — block everything except loopback + established + allowlist:
- **nftables** (`mod.rs:203`): atomic rebuild — delete+recreate `inet nebula`,
  chains with **policy drop** (priority 0), allow `iif/oif lo`, allow
  `ct state established,related`, then per-allowlist `ip saddr/daddr accept`.
- **firewalld** (`mod.rs:267`): `--set-default-zone=drop`, add `lo` to trusted,
  add allowlist source-accept rich rules.
- **ufw** (`mod.rs:311`): `--force reset`, default deny incoming+outgoing, allow
  loopback, allow allowlist in/out, `--force enable`.
- **iptables** (`mod.rs:364`): **sets `-P DROP` policy BEFORE flushing** (comment
  notes the ordering avoids an all-allow window), inserts loopback ACCEPT,
  ESTABLISHED,RELATED conntrack ACCEPT, then allowlist ACCEPTs at positions 3+.
- **Windows** (`mod.rs:436`): adds allowlist allow-rules
  (`NebulaSentinel-Isolate-Allow-<ip>-{in,out}`) *first*, then flips all profiles
  to `blockinbound,blockoutbound`.
- **None** → `proc_isolate` (`mod.rs:483`): PARTIAL — cannot block specific IPs;
  writes `/proc/sys` to disable IPv4/IPv6 forwarding, disable send/accept ICMP
  redirects, enable `log_martians`. Logs a CRITICAL warning.

**undo_isolation:**
- nftables: `delete table inet nebula`.
- firewalld: `--set-default-zone=public`.
- ufw: `--force reset` + `default allow`.
- iptables: `-P ACCEPT` + flush INPUT/OUTPUT/FORWARD.
- Windows (`mod.rs:463`): restores default policy `blockinbound,allowoutbound`
  (Windows default); deliberately does NOT bulk-delete rules (no safe wildcard
  delete) — the named allow-rules are left for Nexus/operator to remove.
- None → `proc_undo_isolation`: re-enable forwarding.

Isolation always keeps the Nexus/allowlist reachable so the host can be
un-isolated remotely, and preserves established connections to avoid SSH lockout.

### IP validation
`validate_ip` (`mod.rs:745`) — **strict**: accepts a bare `IpAddr` (v4 or v6), or
`<addr>/<prefix>` CIDR where the prefix ≤ 32 (v4) / ≤ 128 (v6). Everything else is
rejected. The comment notes this replaced a loose `ip.contains(':')` check that
allowed firewall-rule DSL injection. `block_ip`/`unblock_ip` validate up front;
`isolate` validates each allowlist entry (Windows) or trims/skips blanks.
`netguard::valid_ip` is a separate, stricter check (bare `IpAddr` only, no CIDR).

### Key types
- `Firewall { pub backend: FirewallBackend }` — `Clone`, cloned freely to share.
- `FirewallBackend { Nftables, Firewalld, Ufw, Iptables, WindowsFirewall, None }`
  with `Display`.
- `DistroInfo` / `DistroFamily` — distro detection (`detect`, `mod.rs:547`) via
  `/etc/os-release` (or sysinfo on Windows/macOS), yielding recommended firewall
  package, package manager, and install command. Also exposes
  `is_package_installed`, `oval_feed_url`, and `oval_feed_name` (maps distro →
  Nexus OVAL feed key, e.g. `ubuntu_2204`, `debian_12`, `rhel_9`). Used by setup,
  hardening, and vulnerability scanning rather than blocking itself.
- Internal `run(bin, args)` helper (`mod.rs:733`) returns Err on non-zero exit,
  surfacing stderr; previously-swallowed "No such file" errors now propagate.

### Entry points & main.rs wiring
- `DistroInfo::detect()` at `main.rs:318`; `Firewall::detect().await` at
  `main.rs:319`; startup log at `main.rs:320`.
- The single detected `Firewall` is cloned into: the `ResponseEngine`
  (`main.rs:325`), `NetGuard` (`main.rs:334`), and the `PlaybookEngine` via
  `.with_firewall(...)` (`main.rs:349`).
- `IsolateHost` / `BlockIp` / `UnblockIp` response actions delegate through the
  ResponseEngine to this abstraction (`main.rs:1552`, and the `IsolateHost` arm at
  `main.rs:1618` with `isolate_host()` at `main.rs:1626`).
- `DistroInfo::detect().oval_feed_name()` is also used for OVAL feed sync
  (`main.rs:457`).

### External interactions
- Subprocesses via tokio `Command`: `which`, `nft`, `firewall-cmd`, `ufw`,
  `iptables`, `ip6tables`, `netsh`.
- Filesystem: `/etc/os-release` (distro), `/proc/sys/net/...` (None-backend
  fallback isolation).

### Limitations
- Requires elevated privileges to actually mutate rules (Windows netsh, Linux
  root); without them the underlying commands fail and errors are surfaced.
- nftables **unblock flushes the whole nebula chain** — unblocking one IP clears
  all nftables-added blocks (documented as the simple/reliable trade-off vs.
  parsing rule handles).
- Isolation semantics differ per backend (ufw `--force reset` wipes the operator's
  entire ruleset; firewalld toggles default zones; Windows leaves named allow-rules
  behind on undo).
- `None` backend can only reduce forwarding/redirects — it cannot block or truly
  isolate specific peers.
- Backend is detected once at startup and cached; runtime tooling changes are not
  re-probed.
