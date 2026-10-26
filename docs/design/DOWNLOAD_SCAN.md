# On-Download Malware Scanning — Design Note (v1)

## The question

The agent is behavioral/heuristic-first. Does it scan **downloaded files** on disk
for known malware (signatures), and if not, can we leverage the existing YARA
engine (not ClamAV) to do so?

## What already exists (verified in code)

More is built than expected. The full on-access scan pipeline is present:

- **YARA engine** (`yara_scan/mod.rs`): `scan_file(path)`, `scan_bytes(data)`,
  `scan_process(pid)` all implemented. Its own doc calls `scan_file` "on-disk
  malware (the classic AV use case)."
- **Reputation `check_file(path)`** (`reputation/mod.rs`): on a file it computes
  SHA-256 and checks (1) the local **hash blocklist** (known-malicious hashes),
  then (2) runs **YARA `scan_bytes`** for malware-family detection, plus entropy
  checks. Emits a ThreatEvent on a hit.
- **Real-time trigger** (`main.rs` FIM loop): when a watched file changes, it
  already calls `check_file()` on it — an "on-access scan … real-time, not waiting
  for the periodic sweep." Hits are sent to Nexus.
- **FIM** (`fim/mod.rs`): inotify/FSEvents kernel-push file-change events; reads
  the file bytes (for its dedup hash) — the same bytes a scan needs.

So the FIM → hash-blocklist → YARA → ThreatEvent → Nexus pipeline is COMPLETE and
real-time. This is not a missing feature.

## The actual gap

**FIM's default watch list covers persistence/integrity locations, NOT download
landing zones.** It watches `/etc/ssh`, `/etc/cron*`, `/etc/sudoers*`, `/etc/pam.d`,
`/etc/systemd/system`, `/usr/bin`, `/usr/sbin`, `/etc/ld.so.preload`, `/root/.ssh`,
etc. — where malware installs itself for persistence. It does **not** watch where
downloaded malware first lands:

- Linux/macOS: `~/Downloads`, `/tmp`, `/var/tmp`, `/dev/shm`, `/home/*/Downloads`
- Windows: `%USERPROFILE%\Downloads`, `%TEMP%`, `C:\Users\*\Downloads`

Consequence: a malicious file downloaded to `~/Downloads` is NOT scanned until it's
executed or copied into a watched persistence path. The "downloaded malware isn't
detected" observation is exactly this: right pipeline, wrong (missing) paths.

## Proposed fix (small, reuses everything)

### 1. Add download/temp landing zones to FIM's watched paths
Add a set of "download zone" paths to `default_critical_paths()` (or a parallel
list), tagged with a technique like T1105 (Ingress Tool Transfer) and a lower
default severity than persistence tampering (a file appearing in Downloads is
normal; a YARA/hash HIT on it is what escalates). Cover the OS-appropriate dirs
above. Enumerate real user home dirs on Linux (`/home/*`) and Windows
(`C:\Users\*`) rather than hardcoding one user.

### 2. Scan policy (avoid noise / cost)
The on-access `check_file` already runs on change. To keep it sane in high-churn
dirs like `/tmp`:
- **Type filter**: only scan files whose extension or magic bytes look executable/
  script/archive/office (PE `MZ`, ELF `\x7fELF`, shebang, `.ps1/.js/.vbs/.bat/.sh`,
  `.zip/.rar/.7z`, OLE/OOXML). Skip obvious media/text.
- **Size cap**: skip files above a threshold (e.g. 100 MB) — YARA on huge files is
  slow and low-value.
- **Debounce**: a download in progress fires many Modify events; the existing
  content-hash dedup in FIM already suppresses repeats, but scanning should prefer
  the settled file. (FIM's dedup largely covers this.)

### 3. Severity model
- File merely appears in a download zone → Info/Low (or don't emit at all; just
  scan silently).
- Hash-blocklist hit → Critical (known malware).
- YARA hit → High/Critical per rule severity.
Only hits produce meaningful alerts; mere presence does not spam the feed.

## Scope for THIS build
Items 1–3: add download/temp watch zones (Linux + Windows, multi-user), with a
type+size scan filter so the existing on-access scan covers downloaded files
without flooding on `/tmp` churn. No new engine, no ClamAV — purely extending the
watch scope + a scan filter over machinery that already works.

## Explicitly NOT doing
- ClamAV / libclamav — disregarded per decision (heavy C dep, separate signature
  distribution, weaker detection than a curated YARA feed).
- A new scanning subsystem — unnecessary; `check_file` already does it.

## Honest caveats
- Signature/hash detection is a KNOWN-threats layer. A freshly-compiled custom
  payload won't match a hash or public YARA rule — that's what the behavioral/ATC
  layer is for. Defense-in-depth: this closes the "known malware downloaded and
  sitting on disk" gap specifically.
- Quality depends on the YARA rule feed. Nexus already distributes rules; a curated
  malware-rule feed served through that channel is the follow-up that makes this
  layer strong (keeps rules current without a ClamAV-style freshclam mechanism).
- Watching `/tmp` and Downloads adds event volume. The type+size filter keeps the
  scan cost bounded; if it proves heavy on a busy host, the watch set is tunable.
