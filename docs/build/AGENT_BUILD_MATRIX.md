# NebulaSentinel Agent — Build Matrix (CPU/GPU target selection)

The agent's embedded LLM must be compiled for a CPU/GPU target. Pick ONE row.
The wrong CPU baseline is what causes "Illegal instruction (core dumped)" / SIGILL:
a binary built with AVX/AVX2 crashes on a CPU (or QEMU VM) that lacks those
instructions. These build profiles target a KNOWN baseline instead of the build
host's CPU.

## Build commands

| Goal                                   | Command                                                        | Runs on |
|----------------------------------------|----------------------------------------------------------------|---------|
| Max compatibility (VMs, old CPUs)      | `cargo build --release --features ebpf,cpu-portable`           | Any x86-64, incl. default QEMU VMs (SSE4.2 baseline, no AVX) |
| Fast CPU (modern bare metal)           | `cargo build --release --features ebpf,cpu-avx2`               | CPUs with AVX2+FMA only (SIGILLs without AVX2) |
| NVIDIA GPU                             | `cargo build --release --features ebpf,cuda`                   | Hosts with NVIDIA driver + CUDA runtime |
| No local LLM (thin agent)              | `cargo build --release --no-default-features --features ebpf-stub,inventory,gossip` | Anywhere; uses remote ATC or Legacy |

(Add `,yara` to any of the above to include YARA scanning.)

## Which to use

- **Your QEMU test VM** ("QEMU Virtual CPU version 2.5+", no AVX): `cpu-portable`.
  This is the SIGILL fix — the VM CPU has only sse/sse2/ssse3/sse4_1/sse4_2.
- **Your physical test machine** (if it has AVX2 — check `grep avx2 /proc/cpuinfo`):
  `cpu-avx2` for ~2-4x faster inference. If it lacks AVX2, use `cpu-portable`.
- **The A2 GPU VM**: `cuda` — runs math on the GPU, sidesteps CPU-SIMD entirely.
  Needs the full CUDA toolkit on the build host (for the `cudart_static` link) and
  the NVIDIA runtime at run time.

## Verifying the build targeted the right thing

Watch the build warnings:
- `CPU baseline = PORTABLE (SSE4.2, no AVX/BMI)` → cpu-portable active (VM-safe)
- `CPU baseline = AVX2+FMA (fast)` → cpu-avx2 active (modern CPUs only)
- `NVIDIA CUDA backend ENABLED` → cuda active

Then confirm the model actually loads on the target:
```
nebula-agent --llm-selftest -c /etc/nebula/config.toml
```
`LLM_SELFTEST_OK` = success. A SIGILL here means the baseline is still too high
for this CPU (use cpu-portable).

## ROCm (AMD) — NOT YET SUPPORTED

The build has a `rocm`/`hipblas` hook in build.rs but it is unsupported/untested.
Do not rely on it. CUDA (NVIDIA) and CPU are the supported LLM backends today.

## Note on flag mechanism

The CPU baseline is enforced two ways for reliability: `.cargo/config.toml [env]`
sets `CMAKE_ARGS` + `CFLAGS`/`CXXFLAGS`, and `build.rs` also sets them
programmatically per the selected feature. The decisive flag is `GGML_NATIVE=OFF`,
which stops llama.cpp from adding `-march=native` (the source of the SIGILL).

---

# Windows Agent

The agent now compiles and runs on Windows (x86_64-pc-windows-msvc). The entire
detection pipeline (anomaly engine, rules, GOSSIP, embedded/remote LLM, reputation,
Nexus client) is cross-platform and works unchanged. Windows-specific pieces:

## What's Windows-native
- **Collector:** `backend = "wineventlog"` reads the Windows Security/System event
  logs (process creation 4688, logons 4624/4625, privilege use 4672, service
  installs 7045/4697) via `wevtutil`, plus continuous process polling. This is the
  Windows equivalent of the Linux eBPF/auditd sources.
- **Paths:** state under `C:\ProgramData\NebulaSentinel`, config under
  `...\config`, models under `...\models`.

## Building for Windows
Cross-compile from Linux (needs the mingw or MSVC target) or build natively on
Windows with the MSVC toolchain. The LLM CPU baseline features apply the same way:

```
# Native on Windows (recommended), portable CPU baseline:
cargo build --release --target x86_64-pc-windows-msvc --features cpu-portable

# NVIDIA GPU on Windows (needs CUDA toolkit + driver):
cargo build --release --target x86_64-pc-windows-msvc --features cuda
```

Note: do NOT use `--features ebpf` on Windows — eBPF is Linux-only. The collector
automatically uses wineventlog/procmon instead.

## What is NOT yet on Windows (honest scope)
This is a working first Windows agent, not feature-parity with Linux. Cleanly
skipped / no-op on Windows for now:
- eBPF kernel tracing (Linux-only by nature) → wineventlog+procmon instead
- auditd backend (Linux-only)
- LiME memory forensics (Linux kernel module)
- CIS/STIG posture checks that read /etc, /proc, sysctl (return "not applicable")
- POSIX file-mode compliance checks (N/A on NTFS ACL model)

## Planned Windows follow-ons
- Native ETW (Event Tracing for Windows) collector for lower-latency, richer
  telemetry than the wevtutil polling approach (same RawEvent contract).
- Windows CIS benchmark posture checks (registry/secpol based).
- Windows FIM via USN journal or ReadDirectoryChangesW.
- Windows service installer + auto-start as a Windows Service.

## v28bu — Sentinels detail data + Nexus refresh fixes

- **Nexus auto-refresh no longer clears the display.** The loaders blanked each
  table to an empty placeholder on *every* refresh (the silent-refresh path set
  innerHTML to '', wiping rows before the fetch returned). Replaced the fragile
  `loadingRow()` return-'' trick with `setLoadingRows(el, cols)`, which leaves
  existing rows untouched during a background refresh and only shows "Loading…"
  on user-driven loads. Also made the modal-open guard generic (any
  `.modal-overlay` shown), so the suppression modal and future modals pause
  refresh automatically.
- **Windows Sentinel IP no longer disappears.** `receive_posture` unconditionally
  wrote os_version/kernel/ip_addresses from the posture inventory, so a report
  with an empty field erased the good value captured at registration. Now uses
  `COALESCE(NULLIF(?,''), existing)` so empty/missing inventory fields never
  clobber existing data. IP is also stored as the full comma-joined list
  (consistent with registration) instead of only the first address.
- **Agent inventory IP hardening + diagnostics.** Inventory IP enumeration now
  filters loopback/link-local/APIPA by address (not just the "lo" interface name,
  which doesn't exist on Windows) and logs a "🌐 Inventory: N interfaces, M
  routable IPs" line so a missing IP can be diagnosed as collection-side vs
  storage-side from the agent console.

## v28bx — Platform-aware anomaly engine (Windows lsass false-positive fixed)

Root cause found from Windows agent logs: the anomaly engine's heuristics were
written for Linux and the T1078 "unexpected uid=0" rule fired on EVERY Windows
process — because the collector reports uid=0 for all Windows processes (Windows
has no numeric uid), and the rule's allowlist was Linux daemon names. This made
lsass.exe (and everything else) trigger a CRITICAL detection and a bogus DCSync
domain-compromise playbook on every boot.

Fix: added platform awareness (`current_platform()` via compile-time cfg!) to the
anomaly module. The T1078 privileged-process heuristic is now platform-specific:
- Linux/macOS: unchanged (uid==0 with Linux daemon allowlist).
- Windows: uses the real privilege signal — the user SID in extra["user_sid"]
  (SYSTEM = S-1-5-18/19/20) — with a Windows system-process allowlist, and only
  a LOW score (35, "review") for a non-allowlisted SYSTEM process, never an
  automatic CRITICAL.
Other uid==0 checks in the engine are naturally guarded by Linux-only command
strings (dkms, bpf, su root) or Linux paths (/proc/*/mem) and don't misfire on
Windows.

KNOWN STILL-OPEN (separate builds, need runtime data):
- Windows package/process collection: the cfg(windows) code exists but the log
  shows the Linux path running (pkg=apt-get, /proc polling). Platform detection
  in inventory/firewall/collector still defaults to Linux — next build.
- Windows network monitor still reads /proc/net.
- GOSSIP envelope stream fed by mesh, not direct (Ecosystem tab empty).

## v28bz — Two more Windows false positives fixed (lsass dump + python staging)

From v28bx Windows logs: the uid=0 lsass FP is GONE (v28bx worked). Two new FPs:

1. T1003.001 "LSASS / /proc memory credential dump" fired on lsass.exe itself,
   score 92 → bogus DCSync playbook. Root cause: the trigger was
   `fpath.contains("lsass")`, which matches the LSASS process's OWN path
   (...\lsass.exe) on every boot. Fixed: now requires an actual dump indicator in
   the command line (comsvcs/minidump/procdump/nanodump/createdump/rundll32 +
   lsass) or a non-lsass process reading /proc/<pid>/mem. lsass.exe merely
   running no longer triggers it.

2. T1608 "Staging HTTP server" fired on Store python3.exe (score summed to 100 →
   supply-chain playbook). `python -m http.server` is ubiquitous in benign dev,
   so it's a FP on any workstation. Fixed: now only flags when serving from a
   suspicious location (temp/system dirs) or paired with payload-like artifacts
   (.sh/.ps1/payload/beacon). A plain local http.server is treated as dev
   activity, not a threat.

STILL PENDING (the real root cause, its own careful build): the agent still runs
Linux code paths on Windows — Distro=Unknown pkg=apt-get, procmon polling /proc,
FIM inotify, NetworkMonitor /proc/net, /var/lib/nebula paths. Platform awareness
(added to the anomaly engine in v28bx) needs extending into inventory/collector/
firewall/fim/network modules. That's what will populate the empty Windows
Packages/Processes/Network sub-tabs and stop the remaining Linux-ism log noise.

## v28ca — Platform awareness extended across the agent (the root-cause build)

The durable fix for the "agent runs Linux code paths on Windows" root cause that
was producing the recurring false positives and empty Windows sub-tabs. Extended
platform awareness (started in the anomaly engine, v28bx) into the data/collector/
network/firewall layers:

- **DB paths** (baseline, offline_queue, scan_state): were hardcoded to
  /var/lib/nebula, so on Windows they wrote to \var\lib\nebula on C:. Now use
  crate::platform::data_dir() → C:\ProgramData\NebulaSentinel on Windows. Removed
  the stale DEFAULT_DB_PATH consts. (inventory already used data_dir; only its log
  string was wrong — fixed.)
- **Network monitor**: connection tracker read only /proc/net/tcp (empty on
  Windows → dead Network sub-tab + no beacon/C2 detection). Added a cross-platform
  reader — Windows uses `netstat -n -p tcp` for ESTABLISHED connections; Linux
  path unchanged. Gated the redundant Linux-only /proc/net metadata monitor off on
  Windows (the cross-platform tracker already flags 169.254.169.254). parse_hex_addr
  gated to non-windows.
- **Distro/firewall detect()**: read /etc/os-release and defaulted to
  "Debian/apt-get" on Windows → the bogus "🐧 Distro: Unknown pkg=apt-get" line.
  Now returns a real Windows/macOS DistroInfo (family=Windows, pkg=windows,
  firewall=Windows Firewall) via os_version(). Added Windows/MacOS DistroFamily
  variants (allow(dead_code) for cross-platform variants).
- **Misleading log strings** corrected so Windows logs stop implying Linux:
  procmon "polling /proc" → "polling process table (sysinfo)"; FIM "inotify" →
  reports real notify backend (ReadDirectoryChangesW on Windows, FSEvents on
  macOS); network "proc/net" → "netstat" on Windows. (FIM already worked on
  Windows via the cross-platform `notify` crate — only the label was wrong.)

STILL NOT DONE (genuine features, not bugs): Windows firewall *control*
(block_ip/isolate) — currently degrades gracefully to "none"; Windows STIG
hardening; GOSSIP envelope-vs-mesh; OS-aware rule targeting; group-by-OS.

## v28cb — The four deferred features (firewall control, GOSSIP fix, OS-aware rules, Windows STIG foundation)

Implemented the items deferred from v28ca. Four distinct pieces, each validated:

1. **Windows firewall control** (agent, src/firewall/mod.rs): added FirewallBackend::
   WindowsFirewall, selected on Windows via probe(). block_ip/unblock_ip/isolate/
   undo_isolation now dispatch to win_* methods using `netsh advfirewall firewall`
   with a "NebulaSentinel-" rule-name prefix so we only ever touch our own rules.
   SAFETY: deliberately does NOT bulk-delete rules on undo (a `delete rule name=all`
   would wipe the operator's entire ruleset) — restores default policy instead.
   Requires the agent to run elevated; netsh errors are surfaced, not swallowed.

2. **GOSSIP envelope fix** (agent, src/gossip/mod.rs): IOCs were sent only via the
   direct /api/atc/gossip/ioc path + UDP mesh; the Ecosystem stream reads
   gossip_envelopes, which only ever got health envelopes → empty tab. report_ioc_
   to_nexus now ALSO emits the IOC as a canonical envelope to /api/atc/gossip/
   envelope via the existing envelope_bridge::ioc_to_envelope. IOCs now appear in
   the Ecosystem stream without needing a mesh peer.

3. **OS-aware rule targeting + group-by-OS** (nexus db+api+main+ui):
   - rules table gains target_os column (any|linux|windows|macos) + migration.
   - list_rules_for_platform() filters delivery by agent OS; poll_commands uses it
     with get_agent_platform() (normalizes windows-x86_64 → windows etc.), so a
     Windows agent never receives Linux rules and vice versa.
   - POST /api/rules/:id/target-os + set_rule_os_handler to set it; UI adds a
     per-rule OS dropdown in the rules table (setRuleOs) with 🌐/🐧/🪟/🍎 labels.
   - fleet_packages now carries `manager` per package; Packages view gains a
     "Group by OS" option (pkgOsLabel maps manager→OS).

4. **Windows STIG hardening** (agent, NEW src/hardening/windows.rs): assess() now
   dispatches per-platform (assess_windows / assess_linux). windows.rs is a
   data-driven table of 10 registry STIG/CIS controls (UAC EnableLUA, UAC admin
   prompt, SMBv1, RunAsPPL/LSASS-PPL, NoLMHash, RestrictAnonymous, PowerShell
   ScriptBlockLogging, WinRM AllowBasic, Defender realtime, WDigest) via `reg
   query`, plus a guest-account check via `net user guest`. All auto_fixable=false
   (conservative — Windows fixes want operator review). FOUNDATION: adding the full
   STIG catalog later is just more REG_CHECKS rows. Linux check methods/helpers +
   DistroInfo import gated to cfg(not(windows)) so no dead-code warnings on Windows.

All: brace-balanced (api baseline 3), orphan-clean, routes unique, UI JS node-check OK.

## v28cc — Windows hardening now shows Windows STIGs; Network sub-tab populated; warning fixed

From v28cb Windows logs: platform work confirmed working (C:\ProgramData DBs,
netstat, ReadDirectoryChangesW, windows-firewall backend). Three issues fixed:

1. **Hardening sub-tab showed LINUX items on Windows.** Root cause: TWO problems.
   (a) config-windows.toml had [hardening] enabled=false, so the dedicated
   platform-aware HardeningEngine (with the v28cb Windows STIGs) returned empty
   and never ran assess_windows(). Set enabled=true. (b) posture/mod.rs
   check_hardening_items() is a SEPARATE hardcoded-Linux hardening path that fills
   report.hardening_recommendations; gated it to cfg(not(windows)) so it returns
   empty on Windows and the Windows STIG engine's items win. Now the Windows agent
   shows the 11 Windows registry/account STIG items from hardening/windows.rs.

2. **Network sub-tab empty on Windows.** The sub-tab reads inventory fields
   network_peers/arp_neighbors/routes, collected by collect_network_peers (/proc/
   net/tcp), collect_arp (ip neigh), collect_routes (ip route) — all Linux-only.
   Added Windows implementations: collect_routes_windows (`route print -4`),
   collect_arp_windows (`arp -a`), collect_network_peers_windows (`netstat -n -o`
   + sysinfo PID→name). parse_proc_addr gated to non-windows.

3. **Warning:** service_is_active (systemctl helper) wasn't gated → dead-code
   warning on Windows. Gated to cfg(not(windows)); its only caller (check_services)
   was already gated.

NOTE: netstat/arp/route parsing is locale-sensitive on Windows; if a section
comes back empty, need a sample of the raw command output to adjust the parser.

## v28cd — Fix v28cc Windows compile error (sysinfo refresh_processes API)

v28cc failed to compile on Windows: E0061 at inventory/mod.rs:435 —
`sys.refresh_processes()` was called with 0 args, but sysinfo 0.32's
refresh_processes() requires (ProcessesToUpdate, bool). Root cause: my new
collect_network_peers_windows used a bare refresh_processes() that doesn't exist
in this version. Fixed by using System::new_all() (which populates the process
list on construction — the same proven pattern used at inventory/mod.rs:86 and in
collect_process_list), dropping the explicit refresh entirely. Now read-only
(`let sys`, no mut). Verified: no bare refresh_processes() anywhere; all sysinfo
usage (processes().iter(), pid.as_u32(), name().to_string_lossy()) matches the
existing working call sites. Cosmetic/compile-fix only — no behavior change from
v28cc's intent (Windows network peers still collected via netstat -n -o).

## v28ce — GOSSIP delivery logging, PASTA threat modeling, richer CVE detail

Three issues from user report:

1. **GOSSIP tab empty.** Verified end-to-end: agent builds envelopes with correct
   schema (gossip/1), Nexus ingest/query/UI all structurally correct. The failure
   is at runtime and the agent was SWALLOWING the envelope-POST result
   (`let _ = req.send()`). Added explicit success/HTTP-error/transport-error
   logging to BOTH envelope send sites (health envelope in the gossip loop, IOC
   envelope in report_ioc_to_nexus). Next run's agent log will now say WHY
   envelopes aren't landing (TLS? HTTP 4xx? connection refused?) instead of failing
   invisibly. This is the diagnostic that unblocks the empty-tab question.

2. **PASTA produced no details (only STRIDE/DREAD worked).** Root cause:
   analyze_system IGNORED the methodology param and always returned raw STRIDE
   (DREAD "worked" only because DREAD scores ride on STRIDE threats). Implemented
   generate_pasta_analysis() — a real 7-stage PASTA structure (business objectives,
   technical scope, decomposition, threat analysis, vuln analysis, attack modeling,
   risk & impact) populated from the inferred components + STRIDE-derived threats
   ranked by DREAD. analyze_system now dispatches on methodology and returns
   pasta_analysis; persisted via new optional ThreatModel.pasta_analysis field
   (round-trips through full_json). UI: renderPastaStages() shows the 7 stages in
   the model detail; methodology detection tolerant of array-or-string.

3. **Per-agent CVE sub-tab needed more detail.** Enriched the CVE rows with an
   inline description snippet (≤140 chars), a severity label under the CVSS score,
   and an "actively exploited" flag for KEV — so CVEs are understandable at a glance
   without opening the modal. Threaded cwe + published from cve_catalog through the
   correlation finding (8-arity tuple) and added Weakness (CWE) + Published date to
   the showCveDetail modal.

All: brace-balanced (api baseline 3), orphan-clean, tuple arity consistent, UI JS
node-check OK.

## v28cf — ATC enrichment: reason over correlated evidence, not restate the alert

User (with embedded LLM now working in-process on newer hardware) observed the ATC
"analysis" was just a reiteration of the alert name. Correct: the old analyze_threat
prompt sent only threat_name + description + one IP + one file, and collapsed the
attack chain to just chain.name — so the model could only paraphrase the label.

Level-1 fix (self-contained, uses data already on the ThreatEvent):
- Rewrote analyze_threat to assemble the correlated EVIDENCE the agent already
  computes: every AttackChain stage in time order (tactic → technique →
  description, with +Ns timing deltas so the model can judge how fast the sequence
  unfolded), ALL IOCs with type/source/confidence (was: 1 IP + 1 file), matched
  rules, and raw-event count. Chain capped at 15 stages, IOCs at 20, to protect the
  4096-tok context window.
- Changed the ASK from "one-to-two sentence assessment" (which invited
  restatement) to real analysis: assessment-in-context, benign_explanation (forces
  the model to consider non-malicious causes → noise reduction), and next_steps.
  System prompt already "expert analyst, reason step-by-step" — good fit.
- parse_threat_analysis composes assessment + benign_explanation + next_steps into
  the existing LLMAnalysis.explanation field (no schema change; richer output flows
  to UI/Nexus unchanged). Backward-compatible fallback to the legacy "explanation"
  key if a model returns the old shape.

This is Level 1 of the 3-level plan discussed. Level 2 (assemble host context:
process tree, recent events, baseline deviation at analysis time) and Level 3
(incident aggregation — correlate many detections into one incident + one analysis,
the biggest noise-reduction win) remain as future deliberate work, Level 3 to get a
design note first.

## v28cg — Fix v28ce Nexus compile error (json! macro block-expression)

v28ce failed to compile Nexus: "unexpected end of macro invocation" at
threat_model/mod.rs:692. Root cause: the PASTA Stage 4 "by_category" value used an
inline `{ let mut m = HashMap::new(); for ...; m }` block INSIDE serde_json::json!.
The json! macro parses `{ }` as a JSON object literal, not a Rust block expression,
so the `let`/`for` statements were invalid macro tokens. Fixed by computing
by_category into a local HashMap<String,i32> BEFORE the macro and referencing the
bare variable as the value (HashMap implements Serialize → serializes to a JSON
object). Verified no sibling block-as-value patterns remain; the if/else
expressions elsewhere in the macro are valid (if/else is an expression). Compile-fix
only, no behavior change from v28ce/v28cf intent.

## v28ch — Fix v28ce Nexus compile error (product_index tuple arity)

v28ce failed to compile Nexus: E0308 at api/mod.rs:4143 and :4174 — the CVE-detail
work added cwe + published to the correlation tuple (push site and read site both
8-arity), but the product_index HashMap DECLARATION at line 4117 still specified a
6-element tuple type. Fixed the declaration to
Vec<(String,String,String,Option<f64>,String,bool,String,String)>. All three sites
(declare/push/read) now agree at 8 elements; verified every loop-bound var is used
(no unused warnings). Compile-fix only.

## v28ci — GOSSIP TLS fix (root cause!), Threat Feed click, dark reports, ATC noise reduction

Big batch from user's 13-item report. Did the highest-value cluster this build:

1. **GOSSIP empty — ROOT CAUSE FOUND & FIXED.** Agent log: "failed to POST IOC
   envelope: error sending request" = TLS handshake failure, not HTTP rejection.
   Both GOSSIP clients (health envelope line 190, IOC line 329) used naked
   reqwest::Client::new() with TLS verification ON, but Nexus uses a self-signed
   cert. The main NexusClient + posture + llm clients all use
   danger_accept_invalid_certs(true); GOSSIP didn't. Fixed both to match. This is
   why the Ecosystem tab was ALWAYS empty (health envelopes failed silently too).

2. **Threat Feed click did nothing.** showThreatDetail targeted a
   'threat-detail-panel' element that doesn't exist → silent no-op. Rewrote as a
   rich modal (severity, host, tactics/techniques, matched rules, IOCs, and the
   full ATC Analysis prominently). Added fmtArr() helper for array-or-string fields.

3. **Reports PDF white.** User asked twice for platform colors. Converted the print
   CSS from the light/paper theme to the dark platform palette (bg #0a0e14, accent
   #00e5a0, dark cards/tables, severity chips). print-color-adjust:exact retained
   (required for browsers to honor dark bg in PDF).

4. **ATC not robust (benign sudo flagged MEDIUM).** The benign-verdict path only
   PREFIXED [ATC-SUPPRESSED] but forwarded at original severity. Now when ATC
   judges benign (!suspicious), it DOWNGRADES severity → Info and floors confidence
   ≤20, so noise like "sudo to root shell" drops out of the active feed. (Chose
   severity-downgrade over a new status field to avoid a 29-site ThreatEvent
   construction ripple.)

All validated: braces balanced, UI JS node-check OK.

DEFERRED (see tracker in message) — NOT done this build: Timeline graph, Windows
package descriptions, OS-tagged rules in Retro/Rules UI + rule removal, Compliance
Frameworks/OSCAL depth, Windows STIG in posture sub-tab, OVAL, Conjecture UX,
threat-model STRIDE/PASTA autogen wiring, Atlas Guard OWASP Top 10.

## v28cj — Bug cluster: Compliance Frameworks, Windows STIGs in posture, Retro OS filter

Continued the tracker (bug cluster from the 13-item report):

4. **Compliance Frameworks tab empty — FIXED.** compliance_summary returned only
   {org_compliance, agent_count} but the UI read d.frameworks (never present).
   Endpoint now emits a `frameworks` array (id/name/score/host_count/assessed),
   including known-but-unassessed frameworks (NIST 800-53/171, CIS, STIG, PCI,
   HIPAA, ISO 27001, SOC2) so the grid shows the full catalog + which have data.

5. **Windows posture showed Linux items — FIXED.** v28cc gated posture
   check_hardening_items to return empty on Windows, but the Windows STIG items
   (dedicated HardeningEngine) never got folded into the posture report → sub-tab
   showed Linux/stale. Now on Windows, check_hardening_items returns
   crate::hardening::windows::assess() (made `pub mod windows`), so the posture
   sub-tab shows real Windows registry/account STIG items.

3. **Retro Hunt OS filtering — ADDED.** Couldn't easily avoid scanning Windows
   hosts with Linux rules. Added an OS filter dropdown (All/Any/Windows/Linux/macOS)
   + "Group by OS" to the retro rule selector, both keyed on the target_os field
   from v28cb. (Rule removal already exists: "Clear" button deselects retro rules;
   deleteRule permanently removes in the Rules tab.)

9. **STRIDE/PASTA — VERIFIED working** (no change needed): analyze_system dispatches
   on methodology (v28ce/cg), StrideCategory serializes lowercase and the UI's
   strideLabel handles it, PASTA renders stages. The original "only DREAD" report
   predated the v28ce fix.

All: brace-balanced (api 3), orphan-clean, UI JS OK.

## v28ck — UI polish batch: Timeline graph, Conjecture UX, Windows pkg descriptions

1. **Timeline (#1)** — was all events on one horizontal line (y=95 fixed), spaced by
   index, colored by severity = "red/yellow dots on one line". Rewrote as a proper
   time(x) vs severity(y) scatter: 4 severity lanes (Critical→Low) with shaded
   bands + labels, a time x-axis with 5 date/time ticks (auto month/day vs HH:MM
   based on span), dots placed at (timestamp, severity-lane). Up to 300 events.

2. **Conjecture (#8)** — clumsy: Forecast defaulted to "Techniques from Attribution
   tab" scope, forcing a two-step (run Attribution first, then Forecast). Made
   "Whole fleet — recent detections" the default scope (needs no prior input) in
   both the dropdown and runForecast(), and conjectureSubTab now AUTO-RUNS a fleet
   forecast when the Forecast tab opens (once, if no results shown). Open → result.

3. **Windows package descriptions (#2)** — the "description" was just the bare
   Publisher (vendor name). Windows has no true package description, but enhanced
   scan_packages_windows to also pull Comments + InstallDate: description now
   prefers the installer's Comments field (closest to a real description), else
   composes "Published by {publisher} · installed YYYY-MM-DD". No schema change
   (reused description column).

All: brace-balanced, orphan-clean, UI JS node-check OK. UI-polish batch complete.
Remaining big items: OVAL (#7), OSCAL auto-assess (#6), Atlas Guard OWASP (#10) —
each needs a design note first.

## v28cl — FIM click detail + OVAL Phase 1 (version compare + visibility) + design note

1. **FIM sub-tab click did nothing** (Sentinels → FIM). loadAgentFim rendered rows
   with NO onclick (same class as the Threat Feed bug). Added showFimDetail(i)
   modal (path, host, change type, technique, hashes from IOCs, ATC analysis if
   present) + row onclick + event stash. (Global FIM section already had
   toggleFimDetail — only the per-sentinel sub-tab was missing it.)

2. **OVAL (#7) — found ALREADY PARTIALLY IMPLEMENTED**, not greenfield. Wrote
   OVAL_DESIGN.md documenting the real state + 3 gaps (no XML feed ingestion, naive
   version compare, no visibility) and a phased plan. Implemented Phase 1:
   - **Proper version comparison**: replaced the lexical string compare
     (`pkg.version < fixed` — wrongly ordered "1.10" < "1.9") with a segment-aware
     version_cmp/version_lt (epoch-aware, numeric segments compared numerically,
     numeric outranks alpha). Benefits the whole vuln pipeline, not just OVAL.
   - **Visibility logging**: check_oval now logs matched count / empty-dir hint so
     "OVAL not configured" is distinguishable from "OVAL ran, 0 matches".
   Phase 2 (real OVAL XML→JSON converter, Nexus-side) deferred to its own build —
   deliberately NOT attempting full OVAL XML parsing in one turn.

All: brace-balanced, orphan-clean, UI JS OK, version_cmp logic-reviewed.

Remaining big items: OVAL Phase 2 (XML converter), OSCAL auto-assess (#6), Atlas
Guard OWASP (#10).

## v28cm — OSCAL Phase 1: Windows STIG → NIST 800-53 mappings (make Windows fleets assessable)

Investigated OSCAL like OVAL — found nexus-server/src/oscal/mod.rs (~530 lines) is
ALREADY substantially built: catalog ingestion, control→check mappings,
auto-assessment (assess_fleet rolls up mapped checks vs latest hardening results →
satisfied/not-satisfied/partial/not-assessed), OSCAL results export, full API.

Wrote OSCAL_DESIGN.md. Root cause why OSCAL "has no use":
  (a) a NIST catalog must be imported first (manual), and
  (b) the 67 built-in mappings were LINUX-ONLY (sshd:*, sysctl:*, svc:*) — the
      Windows STIG items produce control_ids like `reg:System\EnableLUA`,
      `account:guest` which were mapped to ZERO controls → every control
      "not-assessed" on a Windows fleet.

Implemented Phase 1: added 18 Windows STIG → NIST 800-53 mappings (UAC→AC-6/CM-7,
LSASS PPL→SC-39/IA-5, SMBv1→CM-7/SC-7, PowerShell logging→AU-2/AU-12, WDigest→IA-5,
guest→AC-2, etc.). Verified each check_id EXACTLY matches the agent's
HardeningItem.control_id format (`reg:{last-path-seg}\{name}` / `account:{name}`),
and confirmed the data path: agent hardening_recommendations → posture_reports.
hardening column → assess_fleet. Status serialization ("pass"/"fail" snake_case)
already matches assess_fleet's expectations. Total mappings 67 → 85.

Phase 2 (catalog seeding + UI import→assess→export guidance) and Phase 3 (deeper
mapping coverage) deferred to their own builds.

FIX EARLIER: v28cl also shipped OVAL_DESIGN.md + OVAL Phase 1 (version compare +
visibility) and the FIM sub-tab click detail.

All: brace-balanced (api 3), orphan-clean, UI JS OK, check_ids verified against
agent output.

## v28cn — Atlas Guard OWASP Top 10 expansion (Phase 1: injection + SSRF)

Investigated Atlas Guard: it's the NEXUS's self-protection layer (src/atlas/mod.rs,
~295 lines) defending the Nexus's own AI/API surface against MITRE ATLAS
adversarial-ML techniques (prompt injection, jailbreak, model API abuse, payload
poisoning, auth brute-force, response scrubbing). NOT a web-app scanner (that's Red
Nebula). So "add OWASP Top 10" = harden the Nexus's own web/API surface alongside
the ATLAS AI defenses.

Wrote ATLAS_OWASP_DESIGN.md (honest mapping of which OWASP categories a runtime
guard can actually enforce vs which are design/process or handled elsewhere).

Implemented Phase 1 (self-contained, additive):
- check_injection(input, ip) — A03: signature detection of SQLi / XSS / command
  injection in user-supplied strings. Returns true if SAFE (mirrors
  check_prompt_injection). Emits an AtlasEvent with technique="OWASP-A03".
- check_ssrf(url, ip) — A10: blocks user-supplied URLs targeting RFC1918 /
  loopback / link-local / cloud-metadata (169.254.169.254) / .internal/.local.
  Ready to gate any server-side fetch.
- OWASP findings reuse AtlasEvent (technique="OWASP-Axx") so they flow through the
  existing event log / stats / techniques_seen automatically.
- Wired check_injection into the Whisper query path (alongside the existing
  prompt-injection check). check_ssrf is a pub method ready for fetch call sites.
- UI: added an "OWASP Top 10 Coverage" section to the Atlas Guard tab (A03/A10/A07/
  A09 cards) with an honest note that it's defense-in-depth, not a WAF, and that
  A02/A04/A06 are covered by TLS config / the vuln pipeline.

Phase 2 (security headers middleware + misconfig) and Phase 3 (access-control /
IDOR anomaly detection) deferred to their own builds.

All: brace-balanced (api 3, atlas 0, whisper 0), orphan-clean, UI JS OK.
This completes design-note-first investigation of ALL big items. Remaining phased
work: OVAL P2 (XML converter), OSCAL P2 (catalog seed + UI), Atlas P2/P3.

## v28co — OSCAL Phase 2: one-click NIST catalog fetch + import→assess→export guidance

The Phase 1 (v28cm) Windows mappings made OSCAL assessable, but the operator still
had to manually find + download the catalog JSON from GitHub. Phase 2 removes that:

- NEW endpoint POST /api/oscal/catalogs/fetch { catalog } — server-side downloads a
  known NIST catalog (800-53 rev5/rev4, 800-171 rev2) from the official
  usnistgov/oscal-content repo (raw.githubusercontent.com is on the Nexus network
  allowlist) and ingests it via the existing ingest_catalog. Curated URL allowlist;
  60s timeout (catalogs are multi-MB); clear error if the Nexus can't reach GitHub
  (air-gapped → use Import File instead).
- oscal_fetch_catalog handler + route registered.
- UI: "Load NIST 800-53" one-click button (oscalFetchNist) with progress state;
  renamed the file path to "Import File"; rewrote the empty state as a clear 3-step
  guide (Load → Assess → Export) with the honest "not-assessed = no automatable
  evidence" caveat inline.

Now OSCAL is self-service: click Load NIST 800-53 → auto-assess → Export Results.
Air-gapped fleets still use Import File. Phase 3 (deeper non-hardening mappings)
deferred.

All: brace-balanced (api 3), orphan-clean, route unique, UI JS OK.

## v28cp — Fix test-reported bugs: Threat Feed 404, modal CSS (FIM+Threat clicks), Timeline

From user testing of v28co. Two real bugs + two Timeline issues:

1. **Threat Feed click → 404.** showThreatDetail fetched /api/threats/:id but that
   route DIDN'T EXIST (only the list /api/threats). Added db::get_threat(id) +
   get_threat_handler + route /api/threats/:id. (Also imported OptionalExtension
   for .optional().)

2. **FIM click did nothing + Threat modal wouldn't show — ROOT CAUSE: missing CSS.**
   Both modals create <div class="modal-overlay">, but `.modal-overlay`/`.modal-card`/
   `.modal-head`/`.modal-body` had NO CSS defined (only referenced in JS) — so the
   modal rendered invisibly with no position/z-index. Added the modal CSS classes.
   This fixes FIM detail, Threat Feed detail, AND the suppression modal at once.

3. **Timeline window dropdown did nothing.** `tl-win` value was read and shown in
   the title but events were never filtered by it. Added the ms-cutoff filter +
   an onchange handler so changing the window actually re-filters.

4. **Timeline dots now clickable** → pivot to that threat's detail modal
   (timelineDotClick → showThreatDetail). Stashes events in window._timelineEvents.

DEFERRED to next build (from test feedback): Sentinels status/OS filtering+grouping,
per-agent CSV export (cves/threats/packages), installed Windows KBs in package view.
Answered in message: how to validate OVAL P1, how OSCAL assessment triggers.

All: brace-balanced (api 3, db 0, main 0), route unique, UI JS OK.

## v28cq — Sentinels status/OS filtering, per-agent CSV export, Windows KBs

Three enhancements from test feedback:

1. **Sentinels status/OS filtering.** Grouping already existed; added dedicated
   status filter (online/stale/offline) + OS filter (windows/linux/macos) dropdowns
   to the toolbar, wired into filterAgents (combines with search + updates count).

2. **Per-agent CSV export.** Added client-side exportRowsCsv() (proper CSV quoting)
   + wrappers exportAgentCves/Fim/Packages/Threats pulling from the already-stashed
   window._agentCves/_agentFimEvents/_agentPkgs/_agentThreats. Added CSV buttons to
   the CVE, FIM, Packages, and Threats sub-tab panes. Filenames use the hostname.
   Stashed _agentThreats (wasn't before). NOTE: fixed a brace error I introduced in
   exportCsv during editing (removed then restored the closing brace).

3. **Windows installed KBs.** scan_packages_windows now also runs Get-HotFix and
   stores each KB in pkg_catalog with manager='windows-kb' (version empty,
   description = "Windows {Update|Security Update} · installed {date}"). Shows in
   the package view; pkgOsLabel maps windows-kb → 🪟 Windows so OS-grouping works.
   Directly useful for patch/vuln assessment.

All: agent inventory brace-balanced + orphan-clean, Nexus UI JS OK.

## v28cr — Fix Retro Hunt 404 (router mis-placement) + 5 Windows dead-code warnings

From v28cq Windows testing (network capture confirmed working):

1. **Retro Hunt report → 404 (real bug).** The agent POSTs completion to
   /api/atc/retro/report with AGENT credentials via the ATC path, but the route was
   registered in build_mgmt_router (USER-auth router), so the agent's request never
   matched → 404 "Failed to report retro hunt completion". ROOT CAUSE: four
   agent-facing ATC routes were in the wrong router. Moved to build_atc_router
   (agent-reachable): /api/atc/retro/report, /api/atc/forensics/manifest,
   /api/atc/progress, /api/atc/forensics/artifact. The last three were failing
   silently too (agent uses `let _ =`), so retro was the only visible symptom.
   Removed the mgmt-router duplicates; verified no duplicate routes remain.

2. **5 Windows dead-code warnings.** posture/mod.rs Linux-only helpers
   (assess_hardening_item, check_file_mode_at_most, check_sshd_max_auth_tries,
   is_package_installed, check_umask_hardened) weren't gated — their only callers
   are in the cfg(not windows) Linux branch of check_hardening_items, so they're
   dead on Windows. Gated all five with cfg(not(target_os="windows")). Windows build
   now warning-clean.

All: main.rs + posture brace-balanced, no dup routes, orphan-clean.

## v28cs — OVAL Phase 2: real OVAL XML → JSON converter (Nexus-side)

Implemented the substantive OVAL piece from OVAL_DESIGN.md Phase 2. NEW module
nexus-server/src/oval/mod.rs:
- parse_oval_xml(xml) — streaming quick-xml parser (0.36, matching the proven
  bench_import pattern: Reader::from_str + config_mut().trim_text + read_event_into).
  Parses the TARGETED SUBSET of the OVAL schema that expresses package-version
  tests: <definition> metadata (CVE via reference source=CVE, severity) +
  <criterion test_ref> → dpkginfo/rpminfo _test → _object (package <name>) →
  _state (fixed <evr>). Builds 4 maps (definitions/tests/objects/states) in one
  pass, then joins them into compact OvalDef {id,cve,package,fixed_version,severity}
  — field-for-field identical to the agent's OvalDefinition, so the JSON round-trips
  straight into check_oval. Everything outside this subset is ignored (not a full
  OVAL implementation, by design).
- Join logic verified against a realistic Debian OVAL sample: produces
  {cve:CVE-2022-1234, package:libfoo, fixed_version:0:1.2.3-4, severity:High} — the
  epoch-aware evr feeds correctly into Phase 1's version_lt.

NEW endpoints:
- POST /api/oval/fetch {feed} — download a curated distro OVAL XML feed
  (debian_11/12 plain-XML; ubuntu feeds are .bz2 → guarded with a clear "not wired
  yet" message since decompression isn't handled), convert, store in oval_feeds
  table. (mgmt router)
- GET /api/oval/feed/:feed — serve converted JSON for an agent's feed dir. (atc
  router, agent-reachable)
- GET /api/oval/feeds — list converted feeds + counts. (mgmt router)

DEFERRED: bz2 decompression for Ubuntu feeds; agent-side auto-sync of served JSON
into the OVAL dir; a UI surface (endpoints are API-drivable now). rpm/RHEL feeds
work via the same rpminfo_* element handling but aren't in the curated URL list yet.

All: oval/api/main brace-balanced (api 3), routes unique, orphan-clean, quick-xml
API matches existing working usage, join logic validated.

## v28ct — Fix v28cr compile error (fabricated route handler)

v28cr failed to compile Nexus: E0425 "cannot find value detected_chains in module
api" at main.rs:524. ROOT CAUSE: when removing the mis-routed forensics/artifact
line from the mgmt router in v28cr, I REPLACED it with a fabricated route
`.route("/api/attack/chains/detected", get(api::detected_chains))` — but
api::detected_chains never existed. The forensics/artifact route had been correctly
MOVED to the atc router; the mgmt line should simply have been deleted, not
replaced with an invented route. Removed the bogus line. Audited ALL api::
handlers referenced in routes against their definitions — no other missing
handlers. Compile-fix only.

LESSON: when deleting a line during a str_replace, delete it — don't substitute a
guessed replacement. Structural validation (brace/route-uniqueness) doesn't catch
a syntactically-valid reference to a nonexistent symbol.

All: main brace-balanced, no dup routes, all route handlers verified to exist.

## v28cu — CPU baseline as proper feature flags (fix config.toml vs build.rs conflict) + friendly aliases

User asked to make the "CPU fix" its own feature flag (modern_cpu/legacy_cpu/cuda).
INVESTIGATION found build.rs ALREADY implements per-feature CPU baseline selection
(CARGO_FEATURE_CPU_AVX2 → AVX2, else → portable SSE), BUT .cargo/config.toml had a
static [env] block hardcoding SSE CMAKE_ARGS/CFLAGS/CXXFLAGS that OVERRODE build.rs
→ --features cpu-avx2 silently still produced an SSE binary (latent bug).

Fixes:
1. Removed the static CMAKE_ARGS/CFLAGS/CXXFLAGS from .cargo/config.toml [env]
   (kept the network/registry settings). build.rs is now the single source of
   truth. Default (no feature) still → portable SSE, so unflagged builds stay
   SIGILL-safe on QEMU VMs.
2. build.rs CUDA branch now sets CMAKE_ARGS with -DGGML_CUDA=ON -DLLAMA_CUDA=ON
   (both names for version safety) + AVX2 CPU fallback — previously it set the
   backend cfg but NOT the CMake define, so a GPU build could silently compile
   CPU-only.
3. Added friendly alias features: legacy_cpu → cpu-portable, modern_cpu → cpu-avx2.

Now the three-way selection works as the user wanted:
  --features legacy_cpu (or cpu-portable, or nothing)  → SSE4.2 (VMs/old, the fix)
  --features modern_cpu (or cpu-avx2)                  → AVX2+FMA (modern)
  --features cuda                                      → GPU (GGML_CUDA=ON)

All: build.rs brace-balanced, config.toml valid TOML, all baselines set in build.rs.
CAVEAT: CUDA build not verifiable in this env; GGML_CUDA vs LLAMA_CUDA define name
is version-dependent (set both). Structural validation only.

## v28cv — Fix CUDA link error: emit CUDA library search paths

--features cuda,yara reached linking then failed: "could not find native static
library cudart_static, perhaps an -L flag is missing?" This CONFIRMS the CUDA
backend compiled (nvcc ran) — failure is purely at final link: llama-cpp-sys-2
tells the linker to link cudart_static but nothing emitted a link-search PATH.

Fix: build.rs CUDA branch now emits cargo:rustc-link-search=native for the CUDA
lib dir when CUDA_PATH/CUDA_HOME is set:
  Windows: $CUDA_PATH\lib\x64
  Linux:   $CUDA_PATH/lib64, /lib, /lib64/stubs
If CUDA_PATH is unset: warns loudly with the fix + probes /usr/local/cuda/lib64
and /usr/lib/x86_64-linux-gnu on Linux.

CAVEAT (told user): root cause is env-specific. If CUDA_PATH is unset on their
machine, they must set it. If only the DYNAMIC cudart exists (not the static
.a/.lib), we'd need to switch llama.cpp to dynamic CUDA runtime
(-DCMAKE_CUDA_RUNTIME_LIBRARY=Shared) — deferred pending their diagnostic output.
Structural validation only; no CUDA toolchain here.

## v28cw — CUDA link fix (attempt 2): dynamic runtime + cmake toolkit root

v28cv's link-search fix DIDN'T work because the cudart_static error comes from
llama-cpp-sys-2's OWN link step (error literally says "could not compile
llama-cpp-sys-2"), and cargo:rustc-link-search emitted by nebula-agent's build.rs
does NOT propagate to a dependency's linking. Wrong stage targeted (my error).

Correct approach — reach the cmake build INSIDE llama-cpp-sys-2 via CMAKE_ARGS +
env (the same mechanism our CPU baseline flags already use successfully):
1. -DCMAKE_CUDA_RUNTIME_LIBRARY=Shared + -DGGML_STATIC=OFF → link DYNAMIC libcudart
   instead of cudart_static, sidestepping the missing static lib entirely.
2. Set CUDAToolkit_ROOT + CUDACXX (nvcc path) from CUDA_PATH so cmake's
   FindCUDAToolkit locates the toolkit (it reads these, not just CUDA_PATH).

CAVEAT (told user): still env-dependent + not verifiable here. If dynamic runtime
still fails, likely a deeper toolkit/cmake-version issue; asked user to report the
FULL error incl any cmake output above the cargo line, and confirm
libcudart.so/.lib exists. Structural validation only.

## v28cx — CUDA: force dynamic cudart (libcudart_static.a is ABSENT on user's system)

DECISIVE DIAGNOSIS: user confirmed CUDA_PATH=/usr/local/cuda is set correctly, but
`ls /usr/local/cuda/lib64/libcudart_static.a` → No such file. The static CUDA
runtime is simply NOT INSTALLED (common on runtime-only / distro-package CUDA).
No link-search can fix a file that doesn't exist. Previous v28cv (link-search) and
v28cw (cmake Shared flag) couldn't work because the static link is requested and
the static lib is absent.

Fix: force DYNAMIC cudart via the vars the sys-crate/cmake actually read, added to
the CUDA branch of build.rs:
  CMAKE_ARGS += -DGGML_CUDA_USE_STATIC=OFF -DCUDA_USE_STATIC_CUDA_RUNTIME=OFF
  env CUDA_USE_STATIC_CUDA_RUNTIME=OFF
  env CMAKE_CUDA_RUNTIME_LIBRARY=Shared
(plus the earlier -DGGML_STATIC=OFF -DCMAKE_CUDA_RUNTIME_LIBRARY=Shared)

FALLBACK if this still fails (told user): install the static lib —
`sudo apt install cuda-cudart-static-12-x` matching their CUDA version, or the full
toolkit .run installer — then the ORIGINAL static link just works.

Could NOT inspect llama-cpp-sys-2 source (crates.io 403, github blocked in env), so
this targets the documented CUDA static-runtime toggles. Structural validation only.

## v28cy — CUDA static link FIXED: add the real link path (/usr/lib/x86_64-linux-gnu)

User's `find` located the file: /usr/lib/x86_64-linux-gnu/libcudart_static.a — it
EXISTS, just not in $CUDA_PATH/lib64 where the build looked. So it was a pure path
problem all along (my earlier attempts checked $CUDA_PATH/lib64 only, or forced
dynamic which the sys-crate ignored).

Fix: reverted the dynamic-runtime forcing (user prefers static/future-proof for the
GPU runtime is moot here since the static lib exists), and rewrote the CUDA branch
link-search to ALWAYS add /usr/lib/x86_64-linux-gnu + /usr/local/cuda/lib64 +
$CUDA_PATH/{lib64,lib,stubs,targets/x86_64-linux/lib} — every plausible dir that
EXISTS, unconditionally (the earlier bug only added $CUDA_PATH/lib64 when CUDA_PATH
was set, missing the distro-package path). Also logs which dir actually contains
libcudart_static.a, and warns with the `find` command if none do.

Fixed a scope bug: used target_os (defined later at line 232) in the CUDA branch
where only `os` (line 26) is in scope — corrected to `os`.

This points at a CONFIRMED-EXISTING file, unlike v28cv/cw/cx. Structural validation
only (no CUDA toolchain here).

## v28cz — CUDA link fix (ROOT CAUSE finally correct): global rustflags -L

CRITICAL REALIZATION after 4 failed build.rs attempts: the error "could not compile
llama-cpp-sys-2" means the cudart_static link fails at THAT DEPENDENCY's link step.
cargo:rustc-link-search emitted from nebula-agent's build.rs does NOT propagate to
a dependency's linking — it only affects nebula-agent's own final link. So ALL my
build.rs link-search attempts (v28cv/cy) landed on the wrong crate. Empirically
confirmed 3x.

CORRECT MECHANISM: a GLOBAL linker search path via rustflags, which applies to
EVERY crate's link including llama-cpp-sys-2. Added to .cargo/config.toml:
  [target.x86_64-unknown-linux-gnu]
  rustflags = ["-L","native=/usr/lib/x86_64-linux-gnu","-L","native=/usr/local/cuda/lib64"]
(/usr/lib/x86_64-linux-gnu is where the user's `find` located libcudart_static.a.)

Also gave user the immediate no-rebuild option:
  export RUSTFLAGS="-L /usr/lib/x86_64-linux-gnu" && cargo build --release --features cuda,yara

The build.rs link-search paths from v28cy are left in (harmless, help nebula-agent's
own link) but the rustflags is what fixes the dependency. Structural validation only.

## v28da — On-download malware scanning: add download/temp zones to FIM watch list

User noted downloaded-malware detection seemed absent. INVESTIGATION found the
scan pipeline is ALREADY COMPLETE: yara_scan has scan_file/scan_bytes/scan_process;
reputation.check_file does hash-blocklist + YARA scan_bytes + entropy; main.rs FIM
loop already runs check_file on watched-file changes (real-time on-access scan).
The gap: FIM's default_critical_paths watches PERSISTENCE/integrity locations
(/etc/ssh, /etc/cron*, /usr/bin, sudoers, systemd...) but NOT download landing
zones — so downloaded malware sitting in ~/Downloads or /tmp was never scanned
until executed/copied into a watched path. Wrote DOWNLOAD_SCAN_DESIGN.md.

Fix (extends existing machinery, no new engine, no ClamAV):
1. download_zone_paths() — enumerates at runtime: Linux /tmp,/var/tmp,/dev/shm +
   /home/*/Downloads + /root/Downloads; Windows C:\Users\*\{Downloads,AppData\
   Local\Temp} + %TEMP% + C:\Windows\Temp. Tagged T1105, Severity::Info.
2. is_scannable_file() — extension allowlist (PE/scripts/archives/office/binaries)
   + magic-byte sniff (MZ/ELF/shebang/PK/Rar/gzip) + 100MB size cap, so watching
   busy dirs like /tmp doesn't cause a scan storm.
3. FIM loop: download-zone (T1105) events only emit for Create/Modify of scannable
   files — the emitted event drives the existing on-access hash+YARA scan; a HIT
   escalates. Persistence paths still always emit.
4. Fixed a latent dedup bug: baseline was keyed on spec.path, which for a watched
   DIRECTORY (like /tmp) would collide all files under one key — changed to key on
   the actual file path.

Full path verified: FIM download-zone event → main.rs on-access → check_file →
hash-blocklist (Critical) + YARA scan_bytes (Critical) → Nexus.

All: fim brace-balanced, orphan-clean. Multi-user + cross-platform. Structural
validation only.

## v28db — OS auto-classification for rules (activates the existing OS-aware delivery) + Sigma design note

USER QUESTION: make YARA rule deployment OS-smart (Linux sigs → Linux); status of
Sigma. INVESTIGATION: OS-aware DELIVERY already fully built & correct —
db::list_rules_for_platform filters (target_os='any' OR target_os=agent_os),
get_agent_platform normalizes windows-x86_64→windows etc., wired into agent poll.
THE GAP: every rule defaulted to target_os='any' on import — nothing auto-detected
OS from content, so the mechanism was dormant (everything shipped everywhere).

Fix — detect_rule_os(content, rule_type, source) helper, called at all 4 rule-insert
sites (feed sync, git/zip import, 2x auto/agent rule paths). Signals in priority:
  1. source-feed path (sigmahq:rules/windows/... , win_/lnx_ prefixes)
  2. Sigma logsource `product:` (authoritative)
  3. YARA module imports (pe/dotnet→win, elf→linux, macho→macos)
  4. content-pattern weighted vote (registry/HKEY/.exe vs /etc//proc/ vs /Library/)
Conservative: needs a clear signal, else 'any' (ambiguous cross-platform rules
still reach all agents). Explicit target_os in a request is still respected;
detection is only the fallback. Logic verified 9/9 against real Sigma+YARA samples
(incl. correct 'any' for ambiguous).

Also added POST /api/rules/redetect-os {only_any} — bulk re-classify EXISTING rules
(imported before this) from content/source; only_any=true (default) never overrides
an operator-set OS. Returns scanned/reclassified/by_os counts.

SIGMA status (verified): Nexus ingests/stores/distributes/now-OS-classifies Sigma,
but the AGENT does NOT evaluate Sigma rules at all (grep: zero refs) — they're inert
data on the endpoint. Wrote SIGMA_EVAL_DESIGN.md scoping agent-side Sigma evaluation
as its own phased subsystem (Sigma is an event-matching engine, not a scanner:
needs a condition-grammar parser + field mapping + event-stream wiring — the largest
new subsystem discussed; deferred, design-only). OS-classification means the
distribution side is ready for when Sigma eval exists.

All: api brace 3, orphan-clean, routes unique, detection logic validated 9/9.

## v28dc — OVAL Phase 2b (part 1): agent-side auto-sync of converted feed → end-to-end

Completes OVAL so it produces findings without manual file placement. The Nexus
converter (v28cs) made the JSON; the agent now PULLS it.

Agent changes:
- nexus_client::sync_oval_feed(feed, oval_dir) — GET /api/oval/feed/:feed, validate
  it's a non-empty JSON array, write to <oval_dir>/<feed>.json (the format+location
  check_oval already reads). Won't overwrite a good local feed with an empty "[]".
- DistroInfo::oval_feed_name() — maps the agent's distro to the Nexus feed key
  (debian_11/12, ubuntu_2204/2404). NOTE: Ubuntu is classified under
  DistroFamily::Debian (no Ubuntu variant), so disambiguated on the name field —
  fixed an initial compile error where I referenced nonexistent DistroFamily::Ubuntu.
- main.rs posture loop: before each scan, if Nexus enabled + distro maps to a feed,
  sync_oval_feed into the oval dir (/var/lib/nebula/oval or configured path).
  Best-effort — failure doesn't block the scan; logs synced count / empty-feed hint.

End-to-end now: Nexus POST /api/oval/fetch converts XML→JSON → agent syncs JSON each
posture cycle → check_oval matches vs installed pkgs w/ epoch-aware version_lt.

STILL PENDING (Phase 2b part 2): bz2 decompression for Ubuntu feeds. DELIBERATELY
not done — would need a bzip2 crate (C dep libbz2, or unverifiable pure-Rust
bzip2-rs), and I can't compile-test new deps here. Debian feeds are plain XML and
work today. Ubuntu feeds still return the "bz2 not wired" message from Nexus until
that's added (recommend adding bzip2-rs deliberately with a real build test). Also
still pending: OVAL UI surface.

All: nexus_client/firewall/main brace-balanced, orphan-clean. Structural validation
only.

## v28dd — Atlas Guard OWASP Phase 2: security-headers middleware + verbose-error leak detection (A05)

Extends Atlas Guard's OWASP self-protection (Phase 1 = A03 injection + A10 SSRF) to
A05 Security Misconfiguration.

1. security_headers_middleware (main.rs) — axum from_fn layer applied globally on the
   mgmt router (after cors). Sets on EVERY response: X-Content-Type-Options=nosniff,
   X-Frame-Options=DENY, Referrer-Policy, Strict-Transport-Security (1yr),
   Permissions-Policy (locks geolocation/mic/camera/usb), and a CSP tuned for the
   single-file inline-script UI (script/style 'unsafe-inline', object-src 'none',
   frame-ancestors 'none', connect-src 'self'). Used axum from_fn (not tower-http
   set-header) to avoid enabling an unverifiable new tower-http feature.
2. AtlasGuard::check_response_leakage(body, path) — A05 detective control: scans a
   char-boundary-safe 4KB prefix of a response for internal-leak markers (Rust panic/
   backtrace text, absolute source paths, src/*.rs refs, rusqlite/SQL errors, Option
   unwrap verbiage). Logs an OWASP-A05 AtlasEvent (Medium, blocked=false — detective,
   doesn't rewrite) so the operator can tighten over-sharing error handlers.
   Fixed a real panic risk: &body[..4096] on a &str panics on a non-char-boundary;
   now truncates on a char boundary.
3. UI: added A05 coverage card to the existing OWASP Top 10 grid in the ATLAS Guard tab.

All: atlas/main brace-balanced, orphan-clean, UI JS valid (386KB script), A05 card
present. Structural validation only. check_response_leakage is available for wiring
into error-response paths (not yet auto-called on every response — that's a follow-up
if you want active leak scanning vs the header hardening which IS active now).

## v28de — OSCAL Phase 3: map controls to vuln/posture signals (beyond hardening)

Extends OSCAL compliance evidence beyond HardeningItem results so more NIST controls
get real pass/fail instead of "not-assessed".

- New builtin_mappings (Phase 3 block) → SYNTHETIC checks:
    ra-5, si-2 → vuln:no-open-cves       (Vulnerability Monitoring / Flaw Remediation)
    ra-5, si-2 → vuln:no-critical-cves   (Critical/High severity remediation)
    ca-7       → posture:reporting        (Continuous Monitoring)
- assess_fleet step 3b — populates check_pass/check_fail for those synthetic checks
  from each agent's LATEST posture report: posture:reporting (reported at all=pass),
  vuln:no-open-cves (vuln_count==0 pass / >0 fail), vuln:no-critical-cves (scan the
  vulnerabilities JSON for Critical/High severity → fail, else pass).
- seed_mappings runs every startup w/ INSERT OR IGNORE, so the new mappings appear on
  upgrade automatically (no migration needed).

FIM-integrity signal (si-7) noted as further extension — FIM flows as ThreatEvents,
not in posture_reports, so it needs a different evidence source; deferred. Kept this
build to the directly-available posture vuln data.

All: oscal brace-balanced, orphan-clean, 5 new mappings + evidence block, no dups.
Structural validation only.

## v28df — OVAL UI surface (makes the OVAL feature operable without curl)

The OVAL converter (v28cs) + agent auto-sync (v28dc) worked but were API-only.
Added a UI panel so operators can drive it.

UI (Vulnerabilities tab): collapsible "OVAL Distro Feeds" card with:
- Fetch buttons: Debian 12/11 (work), Ubuntu 22.04/24.04 (labeled bz2-not-wired).
- Status line showing convert progress/result/errors (surfaces the Nexus JSON
  {error}/{definitions} responses).
- A table listing converted feeds + definition counts + last-converted time (from
  GET /api/oval/feeds).
JS: toggleOvalPanel / loadOvalFeeds / ovalFetch — POST /api/oval/fetch {feed},
GET /api/oval/feeds. Reuses existing esc()/apij()/btn-sm/dt helpers.

All: UI JS valid (388KB script). Structural validation only. bz2 Ubuntu decompression
+ OSCAL SI-7-via-FIM still pending (each needs plumbing/deps deferred earlier).

## v28dg — OVAL bz2 decompression + Atlas Guard Phase 3 (access control)

### 1. OVAL bz2 decompression (Ubuntu feeds now work)
oval_fetch_feed: for .bz2 URLs, fetch bytes and decompress via NEW decompress_bz2()
helper — shells out to system `bunzip2 -c` (spawn_blocking, stdin-writer thread to
avoid large-input deadlock). Chosen over a bzip2 crate: bunzip2 is universally
present on Linux, needs NO new Rust dependency (couldn't verify a bzip2 crate builds
here anyway), can't break the build. Clear error if bunzip2 missing. Debian (plain
XML) path unchanged. UI: Ubuntu buttons re-enabled, tooltips/desc updated to note the
bunzip2 requirement.

### 2. Atlas Guard OWASP Phase 3 — A01 Broken Access Control
AtlasGuard::check_access_control(auth_agent, target_agent, resource_id, ip):
- Cross-principal IDOR: auth_agent != target_agent (from path) → log OWASP-A01
  High, blocked=true, deny.
- Enumeration: per-principal rolling 60s window (new access_tracker field +
  AccessWindow struct); >50 distinct resource IDs → log OWASP-A01 Medium detective
  (once per window). 
Fixed a self-inflicted brace bug: the str_replace that added check_access_control
accidentally dropped the scrub_response fn signature (brace delta -1) — caught by
validation, restored the signature.

HONEST STATUS: detection logic built + correct, but NOT yet wired into routes. The
cross-agent IDOR check needs a per-agent authenticated identity to compare against
the path agent_id — agent auth today is a SHARED API key (no per-agent identity), so
that check can't be meaningfully enforced without per-agent auth (larger
prerequisite). Enumeration detection IS wireable now (needs only principal + resource
id). Wiring deferred pending that decision.

All: atlas/api brace-balanced (api 3), orphan-clean, UI JS valid. Structural only.

## v28dh — Cosmetic: fix two nonexistent Tabler icon names (v3.0.0)

User reported the OVAL refresh button icon and the top-left NebulaSentinel shield
were missing. DIAGNOSIS: the UI loads Tabler Icons webfont v3.0.0 from CDN. Only
these two icon NAMES were blank while sibling shields (shield-check/exclamation/lock/
half) rendered fine — proving the font loads and the two names simply don't exist in
v3.0.0 (Tabler renamed icons between versions).
- ti-refresh     → ti-reload        (refresh renamed to reload in Tabler v3; 20→ replaced,
                                      incl. JS template strings + the refresh-spin element)
- ti-shield-bolt → ti-shield-check  (shield-bolt absent in v3.0.0; shield-check already
                                      renders elsewhere on the page; 4 replaced incl. logo,
                                      Sentinels nav, agent cards)
Chose ti-reload / ti-shield-check because both are ALREADY used elsewhere on the page
and confirmed rendering — no guessing at names that might also be missing. refresh-spin
id preserved so the spin animation still works.
All: UI JS valid, zero leftover ti-refresh/ti-shield-bolt.

## v28di — Fix CSP blocking icon/font CDNs (broke ALL Tabler icons + custom fonts)

ROOT CAUSE of the missing icons (v28dh treated a symptom): the v28dd security-headers
CSP set `style-src 'self' 'unsafe-inline'` with no font-src. The UI loads TWO external
stylesheets (Google Fonts Inter/JetBrains Mono + Tabler icons-webfont from jsDelivr)
plus their font files. The CSP BLOCKED both external stylesheets and all fonts →
every Tabler icon and the custom fonts failed. Console showed the exact CSP
violations for fonts.googleapis.com and cdn.jsdelivr.net stylesheets.

Fix: CSP now allows those specific origins:
  style-src … https://fonts.googleapis.com https://cdn.jsdelivr.net
  font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:
(v28dh's ti-reload/ti-shield-check renames are harmless and kept; those names are
valid too. The real fix is the CSP.)

FLAGGED to user: allowing CDNs means the UI breaks if Nexus is AIR-GAPPED (no
internet → CDN fonts fail). Given the on-device/offline thesis, recommended a
follow-up to self-host the fonts/icons locally (bundle into ui/) so the CSP can go
back to 'self'-only AND the UI works offline. Not done this build (needs the font/
icon assets vendored); offered as next step.

Also noted (separate, pre-existing): a gossip health poll 404
(/api/gossip/env...type=atc.health) visible in console — cosmetic background poll,
distinct from the icon issue; left for a separate look if desired.

All: main brace-balanced. Structural only.

## v28dj — Vendor fonts/icons locally: zero external CDN, air-gap-ready UI

User: "have everything the platform needs without reaching external CDNs." The UI's
ONLY external deps were 2 stylesheets (Google Fonts Inter/JetBrains Mono + Tabler
icons webfont from jsDelivr) + their font files. Everything else with https:// is
placeholder text / user links (fine).

Changes:
1. NEW /assets/*path route in main.rs — serves ui/assets/ locally with correct MIME
   types (css/woff2/woff/ttf/svg/js/png), 7-day cache, path-traversal guard.
   /assets/ already in the public auth-skip list.
2. UI <link> tags → local: /assets/fonts/fonts.css + /assets/tabler-icons/
   tabler-icons.css (removed the 2 CDN <link>s + preconnect).
3. CSP LOCKED BACK to strict 'self' (removed the CDN allowances from v28di) —
   font-src 'self' data:, style-src 'self' 'unsafe-inline'. Fully air-gapped.
4. ui/assets/vendor-assets.sh — run ONCE on an internet-connected machine to fetch
   the real Tabler CSS+woff2 and Google Fonts CSS+woff2 and rewrite their URLs to
   local paths. Ships the populated ui/assets/ with the Nexus thereafter.
5. Placeholder fonts.css + tabler-icons.css so the UI degrades gracefully (system
   fonts, blank glyphs) and contacts NO CDN even before the script is run.

HONEST LIMITATION: couldn't fetch the binary font files in THIS env (npm 403,
github/codeload blocked), so the actual woff2 files aren't in the zip — the
vendor-assets.sh script fetches them on the user's machine (one command). Everything
else (route, CSP, UI links, script, fallbacks) is done and validated.

All: main brace-balanced, orphan-clean, UI JS valid, zero CDN refs in UI or CSP.

## v28dk — Expand OVAL feed coverage (RHEL/SUSE/Oracle + more versions) + cosmetic redesign

### Feed expansion (4 → 12 feeds)
oval_fetch_feed curated list now covers: debian_11/12/13, ubuntu_2004/2204/2404,
rhel_8/9, suse_15, opensuse_15, oracle_8/9. The parser already handled rpminfo
(RHEL/SUSE/Oracle use it), so this is URL wiring + one new decompressor.
- Added gz decompression via flate2 (already a dep, in-process — no external tool)
  for the SUSE .gz feeds, alongside the existing bz2 (bunzip2) path.
- Dropped an Amazon Linux .rss feed I'd briefly added — wrong format (RSS, not OVAL);
  wouldn't parse. Honest not to ship a broken button.
- Agent oval_feed_name() expanded: Ubuntu 20.04, Debian 13, RHEL/CentOS/Rocky/Alma
  (DistroFamily::Rhel → rhel_8/9), SUSE/openSUSE (Suse → suse_15/opensuse_15),
  Oracle (name-based → oracle_8/9). Verified variant names Rhel/Suse exist.

### Cosmetic redesign of the OVAL panel
Replaced the flat button-row + plain table with:
- A distro-family grid (Debian/Ubuntu/RHEL/SUSE/Oracle cards, each with a
  brand-colored dot and version chips) — new CSS: .oval-fam-grid/.oval-fam/
  .oval-dot/.oval-chip (hover→accent, .loading, .done states).
- Per-chip loading/done visual state on fetch.
- A feed-count badge in the header + chevron that flips on expand/collapse.
- Converted feeds shown as styled rows (.oval-feed-row) with shield-check icon +
  tabular def counts, instead of a bare table.
- Status line with contextual icons (loader/check/warn/x).

All: api brace 3, firewall brace-balanced, UI JS valid, 12 chips + 24 CSS refs.
Structural only. Feed URLs are best-effort canonical distro OVAL endpoints — user
should confirm each fetches (some vendors move paths); easy to adjust the match arm.

## v28dl — Atomic Red Team efficacy harness + Sigma agent-side evaluation (Phase 1)

### 1. Atomic Red Team detection-efficacy harness (nebula-art-harness.py)
Standalone Python tool (shipped to outputs). For each MITRE technique: records
start time → runs the Atomic Red Team test (Invoke-AtomicTest via pwsh) → polls
Nexus /api/threats for a detection tagged with that technique → scores DETECTED/
PARTIAL/MISSED → runs ART cleanup. Prints coverage rate + per-tactic breakdown +
missed-technique backlog, writes JSON report. Curated --starter-set across 10
tactics, or --techniques T1055,... Correlates on ThreatEvent.mitre_techniques
(which ART organizes by). Safety: isolated disposable VM only. Syntax-validated.

### 2. Sigma agent-side evaluation — Phase 1 (NEW src/sigma/mod.rs)
Turns Sigma rules from inert data into REAL detection. INVESTIGATION found existing
rules/mod.rs Sigma handling was CRUDE — flattened rules to keywords/regex, IGNORING
condition logic + field-specificity (false positives + missed real logic). Built a
proper evaluator:
- parse_sigma() — serde_yaml (already a dep!) → typed SigmaRule (selections,
  condition, logsource, tags). Marks aggregation rules (count/near/timeframe)
  Unsupported so they never mis-evaluate.
- Selection parsing: field|modifier matchers (contains/startswith/endswith/re/
  equals), list=OR, keyword lists; base64 flagged unsupported.
- Field map: Image/CommandLine/ParentImage/User → RawEvent (Linux+Windows names).
- Condition evaluator: recursive-descent and/or/not + parens + quantifier expansion
  (all of them / 1 of them / N of / all of sel* / 1 of sel*). 
- Wired into RulesEngine::match_event: Sigma rules with an evaluable
  process_creation def use the REAL matcher; others fall through to legacy. Added
  sigma field to CompiledRule (None for yara/wazuh).
- 4 Rust unit tests in-module + condition logic mirror-verified 13/13 in Python.
NO new deps (serde_yaml + regex already present). Scope: process_creation only
(Phase 1); other categories = Phase 2.

All: sigma brace 0/orphan-clean, rules brace baseline +1 (pre-existing, confirmed
vs v28dk), main 0. Structural + logic validation; compile on user hardware.

## v28dm — Fix dead_code warning on SigmaRule (use the parsed metadata properly)

Compile warning: SigmaRule fields title/id/level/tags "never read". They were parsed
but discarded — the matcher only used selections/condition. Rather than #[allow], the
RIGHT fix: make the properly-parsed Sigma metadata the source of truth for the
CompiledRule (it reads rule structure more accurately than the legacy keyword-scan
parse_sigma_yaml). In parse_sigma_file, when the proper parse succeeds:
- name  ← SigmaRule.title (fallback to legacy doc.title if empty/placeholder)
- level ← SigmaRule.level (severity)
- technique ← derived from SigmaRule.tags (attack.tXXXX → Txxxx), fallback legacy
- id    ← SigmaRule.id (fallback legacy)
Now all four fields are genuinely read → warning cleared AND detection metadata is
more accurate (correct severity + MITRE technique on Sigma-sourced detections).
Borrow-checked: match &sigma produces owned clones, then sigma moved into the struct
(no overlapping borrow). rules brace +1 (pre-existing baseline), orphan-clean.

Note: agent COMPILED SUCCESSFULLY at v28dl — this was a warning, not an error. Sigma
engine confirmed building on user hardware (8m23s release build).

## v28dn — Four fixes: forensics freeze, threat-model tabs, GOSSIP 404, Whisper history

### 1. CRITICAL — forensics memory-capture freeze (agent)
ROOT CAUSE: forensics/mod.rs collect_memory_snapshot fallback (no LiME) ran
`cat /proc/kcore` via Command::output() — kcore is a virtual view of the ENTIRE
kernel/physical address space (apparent size TBs); output() buffers it all into RAM
→ exhausts memory, freezes the host. And the result was discarded (`let _maps`).
FIX: removed the kcore read entirely. LiME path now has a 300s timeout + rmmod
cleanup. No-LiME fallback is now a SAFE bounded metadata-only summary (/proc/meminfo +
top-100 process RSS from /proc/*/status) — triage value, zero freeze risk.

### 2. Threat modeling — STRIDE/PASTA showed nothing, only DREAD (nexus UI)
ROOT CAUSE: the sub-tabs filtered the MODELS LIST by creation-methodology, so if you
only made STRIDE models, DREAD/PASTA tabs were empty. But every threat carries a
STRIDE category AND a DREAD score, and PASTA is a structural re-view — all three
views are always derivable from the same data.
FIX: renderTMList no longer over-filters (all models shown under all tabs). New
renderTMThreatsByMethodology renders per active tab: STRIDE=grouped by category,
DREAD=risk-scored table sorted by DREAD total (+ D·R·E·A·D dims), PASTA=7 stages
(renderPastaStages, or renderPastaFromThreats built client-side for older models).
Switching tabs re-renders the open model.

### 3. GOSSIP Ecosystem Intelligence Stream 404 (nexus)
ROOT CAUSE: /api/gossip/envelopes was registered on the ATC router (agent-auth), but
the UI calls it with user/session auth → auth mismatch → 404. FIX: moved the route
to the mgmt router (user-auth), next to the other /api/gossip/* read endpoints.

### 4. Nebula Whisper chat history (nexus)
Whisper already kept multi-turn context IN MEMORY per session, but (a) the UI never
sent a session_id so every message started fresh, and (b) sessions were lost on
restart. FIXES:
- DB: new whisper_history table + save/load/list/delete fns (transcript as JSON).
- whisper_query: loads from DB if not cached; persists after every turn (title from
  first user msg, turn_count). 
- New endpoints (mgmt): GET /api/whisper/history, GET+DELETE /api/whisper/history/:id.
- UI: session_id now tracked (_whisperSession) so multi-turn works; history sidebar
  with New-chat, past-conversation list, click-to-reload, delete. loadWhisper opens it.

All: main/api(3)/db/forensics brace-balanced, orphan-clean, UI JS valid.

## WHISPER MODEL SUPPORT (answer to user question)
Whisper's LLM is fully configurable (llm/mod.rs LlmProviderConfig.provider):
- LOCAL/self-hosted (recommended, on-thesis): "llamacpp" (embedded), "ollama"
  (ollama_url), "vllm" (OpenAI-compatible — points at Jetson Thor / GX10!), or any
  OpenAI-compatible /v1/chat/completions endpoint.
- CLOUD (for orgs w/ SLA): "anthropic" (Claude), "openai" (GPT-4o), "xai", "google",
  "azure". API key via env var only, TLS, key never logged.
So YES — Whisper can leverage the user's existing vLLM inference boxes by setting
provider="vllm" + vllm_url. Same NebulaCerebro remote tier ATC uses.

## v28do — Overview dashboard: Priority Actions + per-area widgets (legibility overhaul)

User feedback: platform produces lots of data, overwhelming to newcomers; wants a
powerful/flexible/customizable Overview. INVESTIGATION: the dashboard infra was
actually well-built (widget registry, edit mode w/ move/remove, layout persistence
via /api/dashboard, add-widget picker auto-populated from registry) — the gap was
WHICH widgets existed + the component-oriented default. So: extended, didn't rebuild.

New widgets (all auto-appear in the Customize picker):
- ⭐ priority_actions — FLAGSHIP. Unifies signals from threats + vulnerabilities(KEV)
  + compliance failures + Atlas events into ONE severity-ranked list (top 10, worst
  first), each row click-through to its tab (show(tab)). Confident "Fleet nominal"
  empty state. This is the "what needs me now" layer that makes the platform legible.
- fleet_summary — plain-language situational read (HEALTHY/ELEVATED/CRITICAL + counts).
- vuln_summary — findings, KEV count, critical, OVAL feeds converted.
- compliance_summary — % controls passing gauge + pass/fail/assessed.
- atlas_summary — control-plane attacks blocked / injection attempts / events.
- rules_summary — total/enabled/Sigma/YARA/pending-approval.

Default layout changed to LEAD with what matters:
  ['priority_actions','fleet_summary','kpis','severity_split','feed','threat_trend']
(was component-oriented ['kpis','ecosystem_health','feed','threat_trend','agent_status']).
Full depth still one Customize click away — layering, not removal (power users keep
every OVAL def / Atlas event).

Fixed: my priority-action rows used nav() → corrected to show() (the real tab switcher;
section ids threats/vulns/compliance/atlas verified). All 8 endpoints used verified to
exist. Widgets follow the dynamic-widget contract (async fn(card)); dispatch calls
w.render(body) w/ error handling. UI JS valid. Nexus-UI-only change.

## v28dp — Overview: make EVERYTHING a real widget (fix empty panels + reset)

User reported 3 symptoms; all ONE root cause. The Overview used a fragile "template"
widget kind: kpis + feed were static HTML in a hidden #dash-templates div, physically
MOVED into the layout by the renderer. This caused: (1) not everything was a real
widget, (2) empty movable panels in edit mode (orphaned/duplicated wrappers when the
moved node's state got inconsistent), (3) reset didn't visually restore (re-ran the
same stateful node-moving).

FIX — eliminated the template mechanism entirely:
- Converted kpis + feed to proper self-contained dynamic widgets (dashRenderKpis /
  dashRenderFeed) that emit the same element IDs loadOverview() populates. KPI grid
  clears its card className (it's a grid, not a card).
- Deleted the #dash-templates static HTML block and the template-move + template-hide
  code in renderDashboard. Widget dispatch is now uniform (dynamic/chart only).
- renderDashboard now calls loadOverview() after rendering (sets _dashRendered=true
  first to avoid mutual re-entry) so KPIs/feed populate.
- Added the new priority/summary widgets to dashRefreshDynamics map so they stay
  current on the refresh tick.
Result: 15 dynamic + 4 chart widgets, ZERO template. No empty panels; reset works
(pure re-render, no stateful DOM shuffling). UI JS valid. Nexus-UI-only.

## v28dq — Threat modeling auto-generate: make it methodology-aware (real STRIDE/PASTA/DREAD)

v28dn fixed the RENDERING but not GENERATION. User: auto-generate from a sentinel
always produced DREAD, nothing for PASTA/STRIDE. ROOT CAUSE: analyze_agent
(threat_model/mod.rs) ignored methodology entirely — took only agent_id, generated
threats (which DO carry both STRIDE cats + DREAD scores), and returned them with no
methodology tag and no pasta_analysis. And the UI's two auto-gen call sites never
SENT the selected methodology.

FIXES:
- Backend analyze_agent: reads body["methodology"] (default STRIDE). When PASTA,
  calls the EXISTING-but-unwired ThreatModelEngine::generate_pasta_analysis(...) to
  build the 7-stage structure. Returns "methodology" + "pasta_analysis" in the JSON.
- UI: both /threat-models/analyze-agent calls (generateAgentThreatModel +
  loadAgentThreatModel) now send methodology:_tmMethodology.
- UI: auto-generate PREVIEW is now methodology-aware — new
  renderTMThreatsByMethodologyStandalone (STRIDE=grouped by category, DREAD=scored
  table w/ D·R·E·A·D dims); PASTA=renderPastaStages(d.pasta_analysis). Shows the
  active methodology label.

Note: every generated threat already carries stride + dread, so STRIDE/DREAD were
always derivable — the fix is tagging + the PASTA 7-stage build + sending the choice.
threat_model brace-balanced, orphan-clean, UI JS valid.

## v28dr — Whisper: fix broken layout + make robust & feature-rich (nexus UI)

BROKEN ROOT CAUSE: the v28dn history-sidebar redesign added new flex CSS (.w-wrap
flex:1, .w-msgs flex, .w-in-wrap bottom-anchored) but the OLD whisper CSS was still
present and CONFLICTING: .w-wrap{height:340px}, .w-msgs{...}, .w-in-wrap{margin-top:
10px}. The stale height:340px + margin-top broke the flex column → chat area collapsed
and the input floated UP (user's exact symptom). FIX: removed the 3 stale duplicate
rules; only the correct flex rules remain → input back at the BOTTOM.

Robustness + features added:
- Input is now an auto-growing TEXTAREA (Enter=send, Shift+Enter=newline, grows to
  140px). Was a single-line input.
- _whisperBusy guard (no overlapping sends) + send button shows spinner + disables
  input while in flight (whisperSetSending).
- Robust error UX: errors show inline with the real message + a one-click Retry
  button (whisperRetry re-sends last query). apij throws on non-OK; now handled
  gracefully instead of a bare "Error:".
- Per-response Copy button (whisperCopy, hover-reveal), Export-conversation to .txt
  (whisperExport, header button).
- whisperNewChat now re-shows the example-prompt hint (whisperShowHint); examples
  wired to whisperFillExample.
- History sidebar failure is isolated (own try/catch) — can't break the chat.

CSS added: textarea.w-in styling, .w-msg-tools/.w-tool-btn, focus/disabled states.
UI JS valid. Nexus-UI-only (reload to apply). Backend whisper contract unchanged +
intact (WhisperQuery{query,session_id}; response{response,session_id}).

## v28ds — Whisper messages-disappear bug (auto-refresh wiping the chat)

ROOT CAUSE (real one this time): the global auto-refresh loop (refreshCurrentData,
every 30s) calls the current section's loader. For whisper that's loadWhisper(),
which DESTROYED all .w-msg elements ("start fresh each session"). So every 30s — or
right after a send if the tick landed then — the entire conversation (user prompt +
LLM response) got wiped. That's why both the prompt AND the response "disappeared."

TWO-LAYER FIX:
1. Added 'whisper' to NO_AUTO_REFRESH — a chat must never be silently auto-refreshed.
2. Rewrote loadWhisper() to NEVER destroy an in-progress conversation. It now only
   refreshes the history sidebar and shows the hint if the pane is genuinely empty.
   Messages clear ONLY on explicit New chat.
UI JS valid. Nexus-UI-only (reload to apply).

## MODEL PARAMETERS — how the embedded engine handles per-model config (answer)
[llm] section in nexus.toml → LlmProviderConfig (src/llm/mod.rs). Per-model knobs:
- provider (llamacpp/anthropic/openai/xai/google/azure/mock)
- model_path (GGUF for local) — quantization is BAKED INTO the GGUF (q4_K_M etc.),
  chosen at model-file selection, not a runtime flag.
- n_ctx (context window per slot), n_parallel (slots), n_gpu_layers (-1 auto/0 CPU)
- model (cloud model id string), max_tokens, temperature
- llamaserver_addr/port, api_key (env preferred), azure_endpoint/api_version
Context window = n_ctx. Chat template comes from the GGUF metadata (llama-server reads
it). Tool calling / reasoning parser: NOT currently a config knob — Whisper does its
own intent parsing/tool dispatch server-side; it doesn't rely on OpenAI-style function
calling from the model. So adding a new local model = drop a GGUF + set model_path +
n_ctx; a new cloud model = set provider + model + key.

## v28dt — Anomaly ML: high-signal feature engineering (the real robustness upgrade)

CONTEXT: assessed the anomaly engine honestly. The Half-Space Forest algorithm is
sound (streaming isolation-forest-family, Welford+EWMA, maturity-gated, persisted,
wired live) but its FEATURES were the ceiling — the old 8-dim vector fed near-noise
(raw pid, bare string lengths, uid diluted to /65535). No ONNX exists (that memory =
commented-out Candle LLM deps). Advised AGAINST ONNX/neural (needs labeled data +
training pipeline + heavier runtime, and narrows detection vs unsupervised). Highest-
leverage = better features. Implemented that.

NEW: src/baseline/features.rs — pure-Rust, unit-tested (7 tests), FEATURE_DIMS=14:
- Shannon ENTROPY of command line (obfuscation/encoded payloads)
- command-line ARGUMENT signal (operator-requested): arg count, suspicion-marker
  count (-enc/iex/downloadstring/certutil/curl|sh/base64 -d/... stacked = higher),
  encoded-blob shape (long base64 run)
- executable PATH CATEGORY (/tmp, AppData\Temp, downloads = 1.0; /usr/bin, Program
  Files = 0.0) — strong low-noise signal
- PRIVILEGE as boolean (uid==0) not diluted continuous
- process NAME randomness (digit ratio + entropy → hash-like dropped malware)
- lineage FNV hash (parent→child in stable feature-space region)
- retained: hour-of-day, name length, net ip/port presence, file presence

Wiring: baseline/mod.rs uses features::extract (was Self::features, removed);
HalfSpaceForest built with FEATURE_DIMS. SAFE: forest state is NOT persisted (rebuilt
each boot), so the 8→14 dim change needs no migration and can't panic on old DBs; the
persisted entity profiles (hour hist, Welford) are feature-width-independent.

BONUS: thresholds/geometry now env-tunable (no rebuild) for per-env calibration:
NEBULA_ANOMALY_TREES/DEPTH/ZTHRESH/RARITY (defaults 25/8/3.5/0.01).

VALIDATION: both files brace-balanced + orphan-clean; vector width == FEATURE_DIMS==14
verified; test RawEvent matches real struct (all 23 fields). CAVEAT: 7 unit tests
written + logic-checked but NOT run (no rustc here) — user compiles. Structural
validation can't catch a type slip; if compile errors, likely a trivial import/type.

HONEST FRAMING: this moves the engine from "signature + noisy stats" toward real
behavioral detection by fixing the SIGNAL, not by adding model complexity. It is NOT
yet MEASURED — false-positive rate on real telemetry still unknown (ART harness is the
instrument). "Better features on good ML" > "fancy ML on bad features."

## v28du — Ransomware: intel-fed extensions (de-hardcode, #2 from advice)

Converted the hardcoded RANSOM_EXTENSIONS / RANSOM_NOTE_NAMES const arrays into a
runtime-mutable, intel-fed set — mirroring the reputation engine's RwLock blocklist
pattern. Behavioral entropy/velocity detection UNCHANGED (that's the real engine;
extensions are corroboration).

- Consts renamed DEFAULT_RANSOM_EXTENSIONS / DEFAULT_RANSOM_NOTE_NAMES — now SEED the
  runtime set at startup so nothing regresses / works out-of-box.
- RansomwareDetector gained ext_set + note_set: Arc<StdRwLock<HashSet<String>>>
  (hot reads every file event, rare writes on intel sync; extensions lowercased).
- New runtime methods: add_ransom_extension (normalizes: lowercases, ensures leading
  dot), add_ransom_note_name, load_ransom_extensions/note_names (bulk, returns #new),
  ext/note_snapshot + counts, ransom_ext_example (was free fn has_ransom_ext_examples).
- 3 usage sites now read the runtime set. start() logs live counts.
- Intel path: NexusPoll + raw poll response gained ransom_extensions +
  ransom_note_names (#[serde(default)] → old Nexus = empty vec, graceful). main.rs
  poll loop clones ransom_poll = ransomware_detector.clone() and loads them alongside
  malware_hashes. Closes intel→agent loop for ransomware families.

NEXUS TODO (not built): Nexus must SEND ransom_extensions/ransom_note_names in the
agent poll response (like malware_hashes) + a UI/store for operator-curated ransomware
extensions. Agent side is ready + backward-compatible.

VALIDATION: ransomware/nexus_client/main all brace-balanced + orphan-clean; no leftover
const refs; call site confirmed inside &self method. CAVEAT: structural only, user
compiles. RwLock read-lock in a hot path is fine (no await held across it).

## v28dv — Fix compile error: missing Timelike import in features.rs

E0599: `.hour()` not found on DateTime — the method comes from the chrono Timelike
trait, which wasn't in scope in the new src/baseline/features.rs (v28dt). Added
`use chrono::Timelike;`. Verified it's the ONLY trait-dependent call in the file
(no Datelike/other Timelike methods); test module already fully-qualifies
chrono::Utc::now() + EventType. Classic trait-in-scope error that structural
validation can't catch — flagged as a known caveat at v28dt. One-line fix.

## v28dw — ATC enhancements: host context (#1) + verdict memory (#2)

Both improve ATC reasoning quality. Agent-side (llm/mod.rs + main.rs).

#1 HOST CONTEXT — ATC was context-blind (knew hostname, not what the host IS). Added:
- HostContext struct {hostname, os, role, internet_facing, listening_ports,
  key_services, notes} + .render() compact prompt block.
- HostContext::from_inventory(hostname, os, open_ports) — infers role/exposure/
  services from listening ports (22→sshd, 80/443→web, 3306/5432→db, 88/389→DC, etc.;
  internet_facing heuristic; coarse role). 
- LLMEngine gained host_ctx: StdRwLock<HostContext> (interior-mutable so the Arc'd
  engine updates after inventory without threading state). set_host_context() setter.
- main.rs periodic loop: after inventory, llm_ctx.set_host_context(from_inventory(...)).
- Prompt now leads with the HOST CONTEXT block; "weigh ... AND the host context —
  same action routine on one host, alarming on another."

#2 VERDICT MEMORY — ATC re-reasoned identical benign patterns from scratch every time.
Added a bounded TTL cache:
- PriorVerdict {is_tp, assessment, adj, at, hits}; verdicts: StdRwLock<HashMap>.
- verdict_key = host|sorted-techniques|process (coarse shape, collapses recurrences).
- recall_verdict (6h TTL) injected as PRIOR ATC VERDICT block ("seen N times, assessed
  BENIGN/TP — stay consistent unless evidence changed"). remember_verdict after each
  analysis (reinforces hits, evicts oldest at 512 cap).
Benefits: consistency, cheaper inference (battery/edge-aligned), model reasons w/ own
history.

REFACTOR: 5 LLMEngine Self{} construction sites → Self::assemble() helper (inits the 2
new interior-mutable fields uniformly). imports: chrono DateTime, std RwLock, HashMap.

VALIDATION: llm + main brace-balanced, orphan-clean; format! placeholders==bindings
(13/13, old {hostname} arg removed); HostContext pub + used; recall/remember wired;
debug in scope. CAVEAT: structural only — user compiles. Role inference is heuristic
(port-based); operator config override not added (future). Verdict memory is in-process
(clears on restart, like the pre-existing forest) — intentional.

## v28dx — Fix E0425: vkey out of scope in parse_threat_analysis

v28dw split ATC across two fns: analyze_threat (builds prompt, defines vkey) calls
parse_threat_analysis (handles the LLM response). My remember_verdict call landed in
parse_threat_analysis but referenced vkey from analyze_threat — different scope.
FIX: recompute the key in-place via Self::verdict_key(threat) — `threat` is already a
param of parse_threat_analysis (has &self too, so the method call works). vkey in
analyze_threat is now only borrowed by recall_verdict (no unused warning).
Verified: assessment_for_memory + the call both inside parse_threat_analysis;
verdict_key(&ThreatEvent)->String matches; brace-balanced, orphan-clean. One-line fix.
Classic cross-function scope slip that structural validation can't catch.

## v28dy — ATC verdict memory: actually SHORT-CIRCUIT (+ tolerant JSON parse)

User feedback: v28dw verdict memory only injected a prior verdict into the prompt but
STILL ran the LLM every time — it wasn't the "I've seen this, reuse it, increment
counter" fast path the user (correctly) envisioned. Also the user saw more "Legacy"-
looking un-enriched detections. ROOT CAUSE of that: parse_threat_analysis did
`serde_json::from_str(cleaned).ok()?` — malformed model JSON → None → analysis silently
dropped → detection looks un-analyzed.

TWO FIXES:
1. FAST PATH (the real #2): analyze_threat now, on a FRESH cached verdict for the same
   shape, calls reinforce_verdict (hits+1, refresh recency) and RETURNS the cached
   LLMAnalysis immediately — no inference. Saves compute/battery (edge thesis) and
   sidesteps JSON fragility for recurrences. Only the LLM path mints NEW verdicts, so
   novelty still gets full analysis. New reinforce_verdict() method.
2. TOLERANT PARSE: strict parse → fall back to extract_json_object() (brace-balanced,
   string/escape-aware first {...} extractor) → last resort keep prose as the
   assessment (suspicious=true, adj 0) instead of dropping. Fixes the "Legacy"/
   un-enriched symptom AND hardens ATC for small/quantized/BitNet models. Records the
   verdict in all paths.

VALIDATION: LLMAnalysis fields match (5/5); reinforce_verdict + extract_json_object
defined+wired; orphan-clean. NOTE: the brace-counter script reported +1 — FALSE
POSITIVE from '{' / '}' CHAR LITERALS in extract_json_object (2×'{' lit, 1×'}' lit +
the real brace on that arm). Real balance = 0, verified by adjusting for char literals.
Lesson logged: the naive brace counter miscounts char-literal braces.
CAVEAT: structural only — user compiles.

## v28dz — Model download: live progress bar (was silent + buffered whole file to RAM)

--download-model showed NO progress on a multi-GB download. ROOT CAUSE: both download
paths (download_agent_model = HuggingFace, download_model_from_nexus = air-gapped) used
`resp.bytes().await?` which buffers the ENTIRE 2-5 GB file into memory, then printed one
line at the end. So: no progress AND a big RAM spike.

FIX: stream both paths via reqwest Response::chunk() (base API, no new feature/dep),
writing chunk-by-chunk. New render_progress(downloaded, total, elapsed) draws an
in-place \r line: [████░░] 62.3%  2910/4700 MiB  38.4 MiB/s  ETA 47s — throttled to
~5 redraws/sec. Falls back to a byte counter when Content-Length is unknown. Nexus path
accounts for the RESUME offset (start bytes) so % reflects overall completion, and total
prefers the Nexus-reported expected_size. Added incomplete-download guard (removes .part
+ errors if downloaded < total) on the HF path; nexus path already sha256-verifies.

VALIDATION: both paths stream (2× resp.chunk), render_progress 5× (1 def + 2×2 calls),
no resp.bytes() left, brace-balanced (adjusted for the known extract_json_object char-
literal false positive), orphan-clean. reqwest chunk() confirmed in base API (json+
rustls-tls features unchanged). CAVEAT: structural only — user compiles. Memory win is a
bonus: no more holding the whole GGUF in RAM during download.

## v28ea — Nexus performance: DB indexes + frontend JS extraction (perceived slowness)

User: Nexus heavy/slow to load. Investigated → 3 findings, implemented the 2 real ones.

FIX #1 — DB indexes (biggest server-side win). threats + posture_reports are queried
with ORDER BY timestamp DESC / WHERE timestamp>=? on EVERY dashboard/trend load but had
NO timestamp index → full-table scan+sort, degrading as history grows. Added (IF NOT
EXISTS, safe on live DBs, created next boot):
  idx_threats_timestamp, idx_threats_agent_ts, idx_posture_timestamp,
  idx_posture_agent_ts, idx_iocs_value, idx_iocs_active.

FIX #2 — extract 409KB inline JS → cacheable /assets/app.js. index.html was a 648KB
single file with one 419K inline <script> the browser re-parsed every load. Extracted
byte-exact to ui/assets/app.js (served by existing /assets route, correct text/
javascript MIME, in the PUBLIC auth-skip list so it loads pre-login), replaced with
<script src="/assets/app.js" defer>. index.html 648K→227K (65% smaller initial parse);
app.js now browser-CACHED across loads/refreshes. defer is safe: runs after parse,
before DOMContentLoaded, so the 2 internal DOMContentLoaded listeners + 300 inline
onclick handlers all still fire correctly. node --check app.js = valid; key fns
(loadOverview/show/apij/whisper/renderDashboard) confirmed intact; not truncated.

FIX #3 — parallelize dashboard loads: INVESTIGATED, NOT NEEDED. loadOverview already
uses a single consolidated /api/dashboard call + background async IIFE for vulns; widgets
already render concurrently; boot has no serial-await chain. Forcing a change = risk for
no gain, so deliberately skipped (honest call).

SYSTEM REQS (grounded, not invented): Rust+embedded-SQLite = lightweight. ~2 vCPU /
2-4GB RAM comfortable for a modest fleet. Real scaling pressure is DB size/query patterns
(→ indexes matter more than hardware), not CPU/RAM. Hundreds of agents → eventually
SQLite single-writer limit → migrate to Postgres (future, not now).

VALIDATION: db+main brace-balanced (0/0); index SQL string closed (line 532 )?;);
app.js valid+intact; /assets public confirmed; zero inline scripts remain. Nexus-only
(db change needs recompile; UI change is index.html + new app.js — both ship in ui/).
CAVEAT: structural only — user compiles. The 5 backup .part guards etc. unaffected.

## v28eb — #2 False-positive telemetry + #3 finish the Nexus intel loop (Nexus)

#3 INTEL LOOP (closes what v28du started agent-side):
- poll_commands (api/mod.rs) now SENDS ransom_extensions + ransom_note_names in the
  agent poll response, read from operator-curated settings keys (JSON arrays via the
  existing /api/settings). Absent settings → empty vecs → agents keep built-in
  defaults (fully backward-compatible). The agent side (v28du) already receives+loads.
- UI: new "Ransomware Intel" settings sub-tab (stab-intel) with two textareas
  (extensions + note names) + Save & Distribute. loadRansomIntel/saveRansomIntel
  normalize (trim/dedupe/blank-strip) and persist via /api/settings.

#2 FALSE-POSITIVE TELEMETRY:
- Backend: POST /api/threats/:id/disposition (whitelisted: false_positive/
  true_positive/benign/open → threats.status; audited; lock scoped before audit to
  avoid deadlock). GET /api/fp-stats computes FP rate over JUDGED (fp+tp) detections
  (benign is a separate bucket), + pending_review + per-detector noisiest breakdown.
  Reuses existing threats.status column — no schema change.
- UI: dashboard "Detection Quality" widget (dashRenderFpRate, registered in
  DASH_WIDGETS) — big FP-rate % (green<10/amber<25/red), TP/FP/benign/pending
  counts, noisiest-detectors list. Threat-detail modal gained TP/FP/Benign
  disposition buttons (setDisposition) feeding the metric; the old "mark FP" button
  relabeled "Suppress future alerts like this" (that creates a suppression RULE — a
  distinct action from labeling disposition).

BUG CAUGHT DURING BUILD: inserting dashRenderFpRate accidentally consumed the
one-line dashChartHeader() definition (used by 17 chart widgets) — JS still PARSED
(the orphaned brace closed cleanly) but the fn was undefined → would break 17 widgets
at runtime. Caught by checking call-count vs def-count, not just node --check.
Restored dashChartHeader. Lesson: syntax-valid ≠ semantically intact; verify
definitions survive, not just that it parses.

VALIDATION: app.js valid; dashChartHeader 1 def/17 calls; api brace +3 (baseline),
main 0, orphan-clean; db::audit signature matched; disposition lock scoped before
audit. Nexus-only (api+main recompile; ships index.html + app.js). CAVEAT: structural
only — user compiles.

## v28ec — Fix change-password (field-name mismatch → silent deserialize failure)

BUG: change-password silently did nothing. ROOT CAUSE: UI sent {current_password,
new_password} but the backend ChangePasswordRequest struct (auth/mod.rs) required
{old_password, new_password}. Plain #[derive(Deserialize)] with no default → the
whole request failed to deserialize, axum rejected it before the handler ran, so the
password never changed and the failure was quiet.

TWO-PART FIX:
1. UI (app.js): send old_password instead of current_password (matches contract;
   works on reload, no recompile).
2. Backend (auth/mod.rs): added #[serde(alias = "current_password")] on old_password
   so the endpoint tolerates BOTH names defensively — this class of mismatch can't
   silently recur.

The change_password impl itself was correct (Argon2 verify old → validate strength →
hash → update; handles LDAP; no deadlock). Only the field name blocked it. After the
fix, real failures (wrong current pw / weak new pw) now surface their actual error in
the alert instead of failing silently.

VALIDATION: app.js valid; auth brace-balanced + orphan-clean; both sides confirmed.
Nexus-only. UI part works on reload; the serde alias needs recompile (defensive, not
required for the fix to work).

## v28ed — Fix duplicate auto-generated rules in Nexus (CONFIRMED bug)

CONFIRMED: ATC-proposed rules duplicated in Nexus. ROOT CAUSE: propose_rule
(api/mod.rs) built a RuleRow and called db::insert_rule with NO dedup check, and
the id defaulted to a fresh Uuid::new_v4() every time — so INSERT OR REPLACE (keyed
on id) never collapsed anything. When an agent re-proposed the same rule (after a
restart clears ATC verdict memory, or multiple agents independently detect the same
novel threat), Nexus inserted a brand-new row each time + fired a "new rule pending
review" notification each time. A content_hash column + insert_rule_with_hash existed
(for bulk-repo-import dedup) but were unused on the auto-propose path.

FIX (four parts):
1. propose_rule now computes sha256_hex(content), checks `SELECT 1 FROM rules WHERE
   content_hash=?` and returns {"status":"duplicate_ignored"} if found — skips both
   the insert AND the spurious notification.
2. When the proposal carries no id, id is now derived as `auto-{first16(hash)}` so
   identical content ⇒ identical id ⇒ collapses at the DB layer too (backstop).
3. propose_rule switched from insert_rule to insert_rule_with_hash (persists the hash
   so future dedup lookups work).
4. insert_rule_with_hash switched INSERT → INSERT OR IGNORE (race-safe; a dup id or
   content_hash can't create a second row). Also benefits bulk-repo import.
Plus: idx_rules_content_hash index (fast dedup lookup); one-time startup cleanup that
collapses PRE-EXISTING duplicate auto_generated rules (keeps earliest rowid per
content, guarded to source LIKE 'auto_generated:%' so operator/repo rules are never
touched; idempotent).

VALIDATION: api brace +3 (baseline), db 0, orphan-clean; Uuid still used (17×, no
unused import); cleanup guarded to auto_generated in both DELETE + subquery; wiring
confirmed. Nexus-only, needs recompile. Existing dupes cleaned on next startup.
CAVEAT: structural only — user compiles.

## v28ee — Local status UI now shows detected events (Legacy + ATC)

FEATURE (agent): The local read-only status UI (http://localhost:7440, bound to
127.0.0.1 only) now displays every event the agent detects, live, with NO Nexus
dependency — useful for air-gapped/sovereign visibility and for demoing the agent
on release. The status server + recent_events buffer + UI card already existed but
were only seeded once at startup; the detection loop never fed them. This wires
detections into the buffer as they fire.

Implementation:
- StatusEvent extended: + confidence, source ("Legacy"|"ATC"), description,
  atc_reasoning.
- status_ui::record_event() — bounded ring buffer (MAX_RECENT_EVENTS=200, newest
  first); also keeps active_threats in sync with live event count.
- status_ui::attach_atc_reasoning() — when async ATC (LLM) enrichment completes,
  it UPGRADES the same event row from source "Legacy" to "ATC", attaches the
  model's reasoning, and updates confidence. Matched by threat_name+technique.
- main.rs: record_event() called at the detection-finalize point (before the
  Legacy syslog forward), so EVERY detection is captured regardless of ATC.
  attach_atc_reasoning() called inside the existing LLM enrichment task.
- UI: events now render a source badge (ATC=green / Legacy=blue), confidence %,
  description, and an expandable ATC-reasoning block (left-border callout).
  Both Legacy-path and ATC-enriched events are shown, as requested.

Design notes: in-memory ring buffer only (full history lives in Nexus / local
log). Local-only, read-only — no new network attack surface. active_threats now
tracks live event count (was static from startup).

VALIDATION: main.rs braces 0 (baseline 0), status_ui/mod.rs 0, orphan-clean;
StatusEvent construction matches all 8 struct fields; a.explanation cloned before
later moves (no double-move); status_state is Arc (cheap clone into task).
Agent-only, needs recompile. CAVEAT: structural only — user compiles.

## v28ef — Local status UI: expandable events + grouping by tactic

FEATURE (agent): The local status UI (http://localhost:7440) events list is now
(1) expandable — click any event to see full detail, and (2) grouped by MITRE
tactic. Builds on v28ee (which added the events to the UI).

Expandable detail per event (click to expand, native <details>/<summary>, NO JS):
- full technique list (not just the first), all tactics, matched rules/engines
- INDICATORS section: each IOC with its type + value — this is where file paths,
  hashes, IPs, domains surface (the user's specific ask)
- suggested response action
- ATC reasoning callout (when present)
- description

Grouping: events grouped by first MITRE tactic ("Uncategorized" if none). Groups
ordered by worst severity within, then event count. Each group header shows a
severity dot + tactic name + event count, and is itself collapsible (open by
default).

Implementation:
- StatusEvent extended: + tactics, techniques, matched_rules, iocs (Vec<(type,
  value)>), suggested_action. record_event() in main.rs populates them from the
  ThreatEvent (which already carries mitre_tactics, mitre_techniques,
  matched_rules, iocs, suggested_action).
- status_ui/mod.rs: new render_events_grouped() (grouping + ordering) and
  render_one_event() (expandable row with detail body); esc() helper. All output
  is HTML-escaped. Pure HTML <details>/<summary> — no JavaScript, no new deps.

BUG CAUGHT DURING DEV: inserting the helpers before render_status_html consumed
its `fn render_status_html(` signature line (brace count stayed balanced, so a
shallow check passed, but it would not compile — function body was orphaned).
Restored the signature with #[allow(clippy::too_many_arguments)]. Lesson:
signature loss keeps braces balanced; verify function DEFINITIONS exist, not just
brace balance.

VALIDATION: status_ui braces 0, main.rs 0; all 7 functions present incl restored
render_status_html; new format! strings use inline style='...' (0 literal
CSS-brace blocks, compile-safe); all HTML structure elements confirmed present;
record_event populates all new fields. Agent-only, needs recompile.
CAVEAT: structural only — user compiles.

DOCS ADDED: docs/ARCHITECTURE.md, docs/BUILDING.md, docs/RUNNING.md (how it works
/ how to build incl CPU-baseline SIGILL guidance / how to run incl standalone
quickstart). For the open-source release.

## v28eg — Local status UI: tabbed dashboard (Events / FIM / Posture / Modules)

FEATURE (agent): The local status UI (http://localhost:7440) is now a tabbed
dashboard, mirroring the visual language of Nexus's Sentinels view but scoped to
THIS host and the standalone/air-gapped case (NOT a Nexus clone — deliberately
the lightweight local subset).

Tabs (pure CSS, hidden radio + :checked sibling panels — NO JavaScript):
- Events    — the grouped/expandable detection stream (from v28ef).
- File Integrity — FIM watched-paths list for this host (real data: pulled from
  fim::default_critical_paths() + download_zone_paths()). Note tells the user live
  modifications appear as detections in the Events tab (true — FIM changes flow
  through as ThreatEvents).
- Posture   — posture score (large), firewall backend, rules/IOCs loaded, LLM/ATC
  status, + System card (agent id, Nexus status/url, last contact, started).
- Modules   — module health cards.

SCOPE DISCIPLINE (deliberate): did NOT add a Vulnerabilities tab or replicate
Nexus's fleet-management depth. Each tab answers "something about THIS host,
useful WHEN THERE'S NO NEXUS." Fleet aggregation / vuln remediation tracking /
historical trends stay Nexus's job — avoids duplicating Nexus UI on every agent
and keeps the agent lean. Posture findings (beyond the score) NOT surfaced yet —
snapshot holds score only; full findings would need posture-engine state wired
into the snapshot (deferred, not built to avoid over-reach).

Implementation:
- StatusSnapshot += fim_watched: Vec<(String,String)> (path, description), seeded
  at startup in main.rs from the fim module's public path functions.
- status_ui/mod.rs: CSS-only tab styles added to <style>; body restructured into
  4 radio-driven tab panels; fim_html builder added; all format placeholders
  verified against args.

VALIDATION: status_ui braces 0, main.rs 0; fim_watched wired (struct + seed +
render + format arg); 4 tab radios + 5 panels present; ALL 27 template
placeholders have matching format args (CSS braces confirmed escaped {{ }}, 0 real
single-brace problems); rendered mock confirms tabs switch (CSS :checked) and
events group+expand — verified via screenshots. Agent-only, needs recompile.
CAVEAT: structural only — user compiles.
