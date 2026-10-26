# NebulaSentinel Agent — Collection, Containers, Inventory & Forensics

Technical manual for the telemetry-collection and evidence subsystems of `nebula-agent`.
Covers `src/collector/`, `bpf/` + `build.rs`, `src/container/`, `src/inventory/`, and
`src/forensics/`. Documents the current source at `/nebulasentinel/nebula-agent`.

All backends feed one common structure — `crate::types::RawEvent` — so every downstream
consumer (anomaly, rules, gossip, LLM, reputation, forensics trigger) works identically
regardless of which collection backend produced the event.

---

## 1. Collector — `src/collector/`

### Purpose
The event-collection engine. Emits a unified `RawEvent` stream from whatever OS-level
telemetry source is available, selected at runtime by `[collector].backend`. Any richer
backend that fails to engage falls back — loudly logged — to `procmon`, so the agent is
always collecting *something*.

### Files
- `src/collector/mod.rs` — the `EventCollector`, backend dispatch, procmon/auditd/simulated
  backends, `/proc/net/tcp` network sweep, audit-record parser.
- `src/collector/ebpf.rs` — userspace aya loader (compiled only with `--features ebpf`).
- `src/collector/windows.rs` — Windows Event Log poller (compiled only on Windows).

### Capabilities — telemetry sources (backends)
Dispatched in `EventCollector::start()` (`mod.rs:57`) on `config.backend`:

| Backend | Source | Platform | Notes |
|---|---|---|---|
| `ebpf` | aya + CO-RE BPF object; kprobes/tracepoints | Linux 5.8+ w/ BTF | Sub-ms syscall visibility. Falls back to procmon on any failure. |
| `procmon` | `sysinfo` process-table polling every 5 s | Cross-platform | Universal fallback. Emits `ProcessExec` for new PIDs; SHA-256 hashes the exe. |
| `audit` | auditd Unix socket (`audispd_events`) | Linux only | Parses `EXECVE`/`SYSCALL`/`PATH` records; falls back if socket absent. |
| `wineventlog` | Windows Event Log via `wevtutil` **plus** procmon | Windows | Runs both together; on non-Windows degrades to procmon. |
| `simulated` | Deterministic attack scenarios | Any | Test/demo: webshell, C2 download, privesc, cred access, beacon, lateral movement. |

Platform default backend (`platform::default_collector_backend`): Linux → `ebpf`,
Windows → `wineventlog`, macOS/other → `procmon`.

**procmon details** (`mod.rs:147`): tracks known PIDs in a `DashMap`, emits one
`ProcessExec` per newly-seen PID with name, cmdline, ppid, uid (or Windows SID in
`extra["user_sid"]`), parent name, exe path, and SHA-256 of the exe. Prunes exited PIDs.
Also runs the `/proc/net/tcp` sweep each cycle. Non-blocking `try_send` — drops on full queue.

**Network sweep** (`emit_network_events`, `mod.rs:464`): reads `/proc/net/tcp`, emits
`NetworkConnect` for ESTABLISHED (`state 01`) rows with a non-private remote IP (skips
127./10./192.168./172./0.0.0.0). Used by procmon each cycle, and by the eBPF backend on a
separate 10 s loop (the connect kprobe doesn't cover already-listening sockets).

**Windows Event Log** (`windows.rs`): shells out to `wevtutil qe`, parses XML, high-watermarks
per channel on `EventRecordID`. Mapped events:
`4688`→ProcessExec, `4624`/`4625`→UserAuth (return_code 1 on failed), `4672`→UserSu,
`7045`/`4697`→ModuleLoad. Warns once if process-command-line auditing appears disabled.
Best-effort — degrades rather than dies.

### Capabilities — eBPF programs (kernel side)
Compiled from `bpf/nebula.bpf.c`; attached in `ebpf.rs::start` (`ebpf.rs:198`):

| Rust attach | Hook | Event kind |
|---|---|---|
| `handle_exec` | tracepoint `sched/sched_process_exec` | `ProcessExec` (captures filename via `__data_loc`) |
| `handle_exit` | tracepoint `sched/sched_process_exit` | `ProcessExit` (leader-only; WEXITSTATUS in `ret`) |
| `handle_ptrace` | tracepoint `syscalls/sys_enter_ptrace` | `Ptrace` (target pid stashed in `ret`) |
| `handle_init_module` | tracepoint `syscalls/sys_enter_init_module` | `ModuleLoad` (`ret=0`) |
| `handle_finit_module` | tracepoint `syscalls/sys_enter_finit_module` | `ModuleLoad` (`ret=1`) |
| `handle_tcp_connect` | kprobe `tcp_connect` | `NetworkConnect` (IPv4 `addr4` / IPv6 `addr6`, `family` selects) |

Attach is tolerant: a missing tracepoint/kprobe on a given kernel is logged and skipped;
the backend is considered "up" if **at least one** program attached (`attached == 0` → bail).
Events flow through a 256 KB `BPF_MAP_TYPE_RINGBUF` named `events`; a runtime config array
map `nebula_cfg` allows toggling event classes (index 0 = master, 1..=per-kind).

### Key types
- `EventCollector` — `config`, `agent_id`, `hostname`, and an `mpsc` channel
  (`tx`/`rx`; `rx` is `Arc<Mutex<Receiver>>` so the main loop can drain it). Channel depth =
  `event_queue_depth.max(1024)`.
- `RawEvent` (`src/types.rs:9`) — the universal event record: ids, timestamp, `event_type`,
  pid/ppid/uid/gid, process name/path/cmdline/parent, file path + hash, network dst
  ip/port/proto, syscall, return_code, container_id, namespace, and an `extra`
  `HashMap<String, serde_json::Value>`.
- `EventType` (`src/types.rs:37`) — `ProcessExec, ProcessExit, FileOpen, FileWrite,
  FileDelete, NetworkConnect, NetworkBind, NetworkDns, SyscallAnomalous, ModuleLoad,
  UserAuth, UserSu, CronJob, DockerExec, RawPacket, MemoryMap, Ptrace, Simulated`.
- `RawBpfEvent` (`ebpf.rs:48`, `#[repr(C)]`) — byte-for-byte mirror of `struct nebula_event`
  in `bpf/nebula_events.h`; the ring-buffer bytes are read directly into it.

### Entry points + main.rs wiring
- Construct: `collector::EventCollector::new(...)` — `src/main.rs:242`.
- Backend name recorded for status: `*b = cfg.collector.backend.clone()` — `src/main.rs:283`.
- Start: `collector.start().await?` — `src/main.rs:422`.
- Drain: the main event loop locks `collector.rx` (`src/main.rs:914`, `rx_arc` at `:922`) and
  processes each `RawEvent`.

### Config keys + defaults (`[collector]`, `config.rs:261`)
| Key | Default | Meaning |
|---|---|---|
| `backend` | platform default (`ebpf`/`wineventlog`/`procmon`) | Selected backend. |
| `ebpf_programs` | `["execve","open","connect"]` | Informational program list. |
| `etw_enabled` | `false` | (reserved) |
| `auditd_socket` | `/var/run/audispd_events` | auditd af_unix socket path. |
| `buffer_size` | `65536` | |
| `event_queue_depth` | `4096` | mpsc channel depth (floored at 1024). |
| `deduplicate_window_secs` | `5` | |

### External interactions
`/proc/net/tcp`, auditd socket, `sysinfo`, `wevtutil`/`reg` (Windows), the kernel BPF
subsystem (`/sys/kernel/btf/vmlinux`, ring buffer, `setrlimit(RLIMIT_MEMLOCK)`).

### Limitations
- procmon is poll-based (5 s) — short-lived processes between polls are missed; only new PIDs
  emit events (no exit events).
- eBPF requires BTF and the `ebpf` feature compiled in; without either it silently uses procmon.
- The `/proc/net/tcp` sweep is IPv4-only and skips RFC-1918/loopback destinations, capped at 100 lines.
- auditd `EXECVE` parse buffers by serial but ppid/paths are not fully correlated.
- Windows command lines require the "Include command line in process creation events" audit policy.

---

## 2. eBPF programs & build — `bpf/` + `build.rs`

### Purpose
Kernel-side CO-RE (Compile Once, Run Everywhere) BPF programs and the build machinery that
compiles + embeds them, so a single object runs across kernel versions and — ideally — with
nothing to install on the target.

### Files
- `bpf/nebula.bpf.c` — the BPF programs (see program table above).
- `bpf/nebula_events.h` — the shared `struct nebula_event` wire layout (kind, pid, ppid, uid,
  gid, ret, ts_ns, comm[16], filename[256], args[256], family, dport, addr4, addr6[16]).
  Both C and Rust (`RawBpfEvent`) must match this byte-for-byte.
- `bpf/vmlinux_min.h` — bundled minimal type header for the clang-only path.
- `bpf/Makefile`, `bpf/README.md` — manual build instructions.

### How they're built (`build.rs::maybe_build_bpf`, `build.rs:222`)
Only when building with `--features ebpf` **and** target OS = linux:
1. Requires `clang`; if absent, warns and skips embedding (agent uses procmon).
2. vmlinux header: if `bpftool` + `/sys/kernel/btf/vmlinux` present, dumps a full `vmlinux.h`
   and defines `-DNEBULA_HAVE_FULL_VMLINUX`; otherwise uses the bundled `vmlinux_min.h`.
   `NEBULA_BPF_MINIMAL=1` forces the minimal header.
3. Compiles `clang -O2 -g -target bpf -D__TARGET_ARCH_{x86|arm64} ... -c nebula.bpf.c`.
4. Strips DWARF with **llvm-strip** (`--keep-section=.BTF --keep-section=.BTF.ext`) — never GNU
   `strip` (it would nuke `.BTF` and break CO-RE). Leaves the object unstripped if llvm-strip
   is missing.
5. On success sets `rustc-env=NEBULA_BPF_OBJECT=<path>` and `rustc-cfg=nebula_bpf_embedded`,
   baking the object into the binary via `include_bytes!`.

### How they're loaded (`ebpf.rs::load_bpf_object`, `ebpf.rs:91`)
Preference order: (1) embedded bytes (`#[cfg(nebula_bpf_embedded)]`), (2)
`/usr/lib/nebula/nebula.bpf.o`, (3) `bpf/nebula.bpf.o` or `./nebula.bpf.o`. `start()` checks BTF,
bumps `RLIMIT_MEMLOCK`, attaches programs, takes the `events` ring buffer, and spawns a blocking
`drain_loop` that `poll()`s the fd and decodes each sample into a `RawEvent`.

Note: `build.rs::main` also handles unrelated LLM/GPU backend selection (CUDA/ROCm/Vulkan/Metal/CPU)
— out of scope here but shares the file.

### Limitations
- Linux-only; x86_64/aarch64 arch macros (others default to x86 with a warning).
- The C source references `bind`/`openat`/file-open in comments but only exec/exit/ptrace/
  module-load/tcp_connect are actually attached in `ebpf.rs`. `NEBULA_EVT_BIND`/`FILE_OPEN`
  kinds exist in the header but no live program emits them.
- Full-vmlinux objects can occasionally trip aya's parser (hence the `NEBULA_BPF_MINIMAL` escape hatch).

---

## 3. Container security — `src/container/mod.rs`

### Purpose
Container & Kubernetes security engine. Five conceptual layers: image CVE scanning, runtime
config inspection, namespace/isolation checks, K8s admission posture, and runtime filesystem
drift detection.

### Capabilities — scanners & checks
- **Image CVE scan** (`scan_image`, `container/mod.rs:539`): tries **Trivy** first
  (`trivy image --format json`), falls back to **Grype** (`grype -o json`). Produces
  `ImageVulnerability` (CVE, package, version, fixed_version, severity, CVSS, layer, scanner).
- **Runtime config inspection** (`inspect_runtime_config`, `:251`) flags: privileged mode,
  dangerous capabilities (SYS_ADMIN/SYS_PTRACE/SYS_MODULE = Critical, NET_ADMIN/SYS_RAWIO = High,
  etc.), sensitive host-path mounts (`/`, `/etc`, `/proc`, `/sys`, `/etc/kubernetes`, …),
  host network mode, host PID mode, running as root, and secret-looking env var **keys**
  (values are never read).
- **Exposed Docker socket**: world-accessible `/var/run/docker.sock` (mode `& 0o007`), and
  `docker.sock` mounted inside a container (container-in-container escape).
- **Drift detection** (`detect_drift`, `:654`) — **now wired into `assess()`** (`:173`). Runs
  `docker diff <id>`, treats Added/Changed files not in the image as drift (ignoring
  `/tmp`, `/var/log`, `/var/run`, `/run`, `.pid`, `.log`). Non-empty result emits a
  `DriftDetected` finding with **MITRE T1525** (Implant Internal Image), severity Medium,
  sampling up to 10 paths. `baseline_container` (`:632`) can snapshot a container's file hashes
  via `docker exec ... sha256sum` (available but not called from `assess`).
- **Kubernetes posture** (`check_kubernetes_posture`, `:695`) when `kubectl` is available:
  privileged pods/init-containers, runAsRoot, `hostNetwork`, `hostPID`, and ClusterRoleBindings
  granting `cluster-admin` to non-system ServiceAccounts.

### Full assessment flow (`assess`, `container/mod.rs:161`)
1. `list_containers` (docker `ps` + inspect; containerd via `crictl`).
2. `inspect_runtime_config` per container.
3. `detect_drift` per container → `DriftDetected`/T1525.
4. Docker-socket exposure checks (host perms + in-container mounts).
5. K8s posture if `kubectl_available`.

### Key types
- `ContainerEngine` — docker/containerd socket paths, `image_scan` flag, and a `baseline`
  map (`container_id → {path → sha256}`) for drift.
- `ContainerRuntime`, `MountInfo`, `ImageVulnerability`, `ContainerFinding`,
  `ContainerFindingType` (enum incl. `DriftDetected`, `VulnerableImage`, `ExposedDockerSocket`,
  `PrivilegedServiceAccount`, `RbacMisconfiguration`, …).

### Entry points + main.rs wiring
- Construct: `container::ContainerEngine::new()` — `src/main.rs:386`.
- Periodic loop (first run +120 s, then every **600 s**) — `src/main.rs:1067`. If
  `container_c.is_available()`, calls `assess()` (`:1073`), converts High/Critical findings via
  `ContainerEngine::findings_to_threats` (`:1074`), and forwards each to Nexus.

### Config keys + defaults
No dedicated `[container]` config struct. `ContainerEngine::new()` hard-codes:
`docker_socket = /var/run/docker.sock`, `containerd_socket = /run/containerd/containerd.sock`,
`image_scan = true`. Availability also checks `/run/crio/crio.sock`.

### External interactions
Shells out to `docker` (ps/inspect/diff/exec), `crictl`, `kubectl`, `trivy`, `grype`; reads
Docker socket file permissions.

### Limitations
- CLI-based (not the Docker API/bollard); requires those binaries on PATH.
- `findings_to_threats` only forwards High/Critical, and sets `KillProcess(0)` (pid 0) for
  Critical — a signal, not an actionable kill target.
- `scan_image` and `baseline_container` are implemented but not invoked by the periodic loop.
- Env-var secret detection is key-name heuristic only.

---

## 4. Inventory — `src/inventory/mod.rs`

### Purpose
System inventory and a persistent file/package/process catalog backed by SQLite. Produces an
`InventorySummary` for Nexus and maintains a hash catalog for change tracking.

### Capabilities
- **SQLite catalog** at `<data_dir>/inventory.db` (Linux `/var/lib/nebula`, Windows
  `%ProgramData%\NebulaSentinel`, macOS `/Library/Application Support/NebulaSentinel`). Tables:
  `file_catalog` (path, sha256, size, timestamps), `process_history` (pid, name, cmdline, user,
  first/last seen), `pkg_catalog` (name, version, manager, description, installed_at). Includes
  an idempotent `ALTER TABLE ... ADD COLUMN description` migration.
- **Packages** (`scan_packages`, `:534`): `dpkg-query`, `rpm`, `pip3`; on Windows the three
  Uninstall registry hives via PowerShell (manager `windows`) plus hotfixes via `Get-HotFix`
  (manager `windows-kb`). `collect_packages_only` (`:60`) is a lightweight package-only refresh
  used for smart-scan fingerprinting.
- **File catalog** (`catalog_files`, `:752`): recursively walks `include_paths` (depth ≤ 8,
  honoring `exclude_paths`), SHA-256 hashes each file **in parallel via rayon**, upserts. Skipped
  entirely on a delta scan (`skip_file_catalog`) — the prior DB count is reused.
- **Open ports** (`scan_open_ports`): LISTEN sockets (`state 0A`) from `/proc/net/tcp{,6}`.
- **Containers** (`scan_containers`): `docker ps -a` and `podman ps -a` → `ContainerInfo`.
- **Network context**: routes (`ip route` / Windows `route print`), ARP/neighbors
  (`ip neigh` / `arp -a`), and active **network peers** (`/proc/net/tcp{,6}` with socket-inode →
  `/proc/<pid>/fd` process attribution, or Windows `netstat -n -o`), with direction (inbound/
  outbound) and scope (internal/external) heuristics.
- **Host facts**: hostname, OS/kernel/arch, routable IPs & MACs (filtering loopback/link-local),
  CPU model, RAM, users, process count + full process tree (cross-platform via `sysinfo`), domain
  (from `/etc/resolv.conf`).

### Key types
- `InventoryEngine` — `config` + `Mutex<rusqlite::Connection>`. Note: the `std::sync::MutexGuard`
  is `!Send`, so DB work is carefully scoped to drop the guard before any `.await`.
- `InventorySummary`, `PackageEntry`, `ProcessEntry`, `ContainerInfo`, `RouteEntry`, `ArpEntry`,
  `NetworkPeer` (all in `src/types.rs`).

### Entry points + main.rs wiring
- Construct: `inventory::InventoryEngine::new(cfg.inventory.clone())?` — `src/main.rs:270`.
- Primary path: `collect_with_options(skip_file_catalog)` inside the periodic posture/inventory
  task — `src/main.rs:491`. Smart-scan decides full vs delta via `scan_state` package
  fingerprinting (`:479`–`:500`; `ScanDecision::Delta` skips the file catalog); scan cadence is
  driven by `[posture].scan_interval_secs`, not `[inventory].scan_interval_secs`.
- Also `collect()` (full) at `src/main.rs:1581`.

### Config keys + defaults (`[inventory]`, `config.rs:441`)
| Key | Default |
|---|---|
| `enabled` | `true` |
| `scan_interval_secs` | `3600` |
| `hash_algorithm` | `sha256` |
| `include_paths` | `["/usr/bin","/bin","/etc"]` |
| `exclude_paths` | `["/proc","/sys","/dev"]` |
| `track_installed_pkgs` / `track_processes` / `track_network_conns` / `track_users` / `track_containers` | `true` |

### External interactions
SQLite DB file; `dpkg-query`/`rpm`/`pip3`/PowerShell; `docker`/`podman`; `ip`/`route`/`arp`/
`netstat`; `/proc/net/*`, `/proc/<pid>/*`, `/etc/resolv.conf`.

### Limitations
- File hashing reads entire files — expensive on large `include_paths` (mitigated by delta scans).
- Peer/port parsing is `/proc`-based on Unix (IPv6 rendering is byte-order-approximate,
  "good enough for identification"); Windows uses `netstat`.
- Several `track_*` config flags exist but the collector largely gathers all categories regardless.
- Catalog walk depth capped at 8.

---

## 5. Forensics — `src/forensics/mod.rs`

### Purpose
Confidence-tiered forensic evidence collection triggered by a threat event. Produces a bundle
directory of triage artifacts, optionally encrypts them in place with AES-256-GCM, and writes a
SHA-256-checksummed manifest with a chain-of-custody record.

### Capabilities — artifacts (`collect_for_threat`, `:63`)
Collected into `<output_dir>/<UTC-timestamp>_<bundle8>/`:
1. **Process triage** (`process_triage.txt`): `ps auxf`, plus `/proc/<pid>/{cmdline,environ,maps}`
   and `ss -tulpan`.
2. **Network state** (`network_state.txt`): `ss -tulpanW`, `arp -n`, `ip route`, `iptables -L`.
3. **Log slices**: last 500 lines of each `log_paths` entry (`log_slice_<name>.txt`).
4. **PCAP** (background, non-blocking): `tshark` for `pcap_duration_secs` with `pcap_filter`,
   falling back to `tcpdump`. Only when `pcap_on_event`.
5. **Memory** (`collect_memory_snapshot`, `:294`) — **tiered**: only for the full tier
   (`confidence ≥ full_confidence` OR severity Critical) and when `memory_dump` is on. Prefers
   **LiME** (`/usr/lib/nebula/lime.ko` → `insmod`, 300 s hard timeout, then `rmmod`). If LiME is
   absent it writes a **bounded metadata-only** summary (`/proc/meminfo` + top-100 RSS) — it
   deliberately never reads `/proc/kcore` (that previously froze hosts).
6. **Open file descriptors** (`open_files.txt`): `/proc/<pid>/fd` links + `lsof -n -P`.

### Capabilities — AES-256-GCM encryption
When `encrypt_artifacts` is true (step 7, `:131`): `encrypt_dir_in_place` (`:420`) encrypts
**every regular file in the bundle in place** using **`ring`** (`AES_256_GCM`, `LessSafeKey`,
`seal_in_place_append_tag`). A fresh random 96-bit nonce per file; each file becomes
`nonce(12) || ciphertext || tag(16)`. An `ENCRYPTION.txt` records the scheme and an 8-byte key
fingerprint. Encryption happens **before** hashing so the bundle checksum covers the ciphertext
and manifest paths stay valid. On failure the bundle is left unencrypted (warned).

**Key resolution** (`resolve_encryption_key`, `:392`): uses `[forensics].encryption_key_hex` if
it's a valid 64-hex-char (32-byte) key; otherwise derives a machine-local key =
`SHA-256(bundle_id + /etc/machine-id)` so encryption still works air-gapped (only as strong as
host-local secrets).

### Chain-of-custody & manifest
`compute_bundle_hash` (`:376`) SHA-256s all files in the bundle (sorted) into `bundle_sha256`.
`manifest.json` (`ArtifactBundle`) records bundle/threat ids, host, timestamp, per-artifact
`ArtifactMeta` (type, path, sha256, size, description), the bundle hash, and a
`chain_of_custody` vector (initial `"collected"` entry with agent id + RFC-3339 timestamp).

### Tiered trigger logic (in main.rs)
- **Entry gate**: `entry_threshold = light_confidence.min(min_confidence)`; forensics warranted
  when `enabled && threat.confidence >= entry_threshold` — `src/main.rs:1327`.
- **Pre-response capture**: if `capture_before_response` and the threat will act destructively
  (KillProcess/IsolateHost/QuarantineFile), collect **synchronously** first so volatile state
  reflects the live process — `src/main.rs:1334` → `collect_for_threat` at `:1336`.
- **Background capture**: otherwise spawn collection in the background — `:1355` and `:1439`.
- The **memory-dump (full) tier** decision is made *inside* `collect_for_threat`
  (`full_confidence` or Critical), independent of the entry gate.
- Manifests are forwarded to Nexus via `send_forensic_manifest`.

### Key types
`ForensicsEngine { config }`, `ArtifactBundle`, `ArtifactMeta`, `CustodyEntry`.

### Entry points + main.rs wiring
- Construct: `forensics::ForensicsEngine::new(cfg.forensics.clone())` — `src/main.rs:269`.
- Invoked: `forensics_engine.collect_for_threat(&threat, &event)` — `src/main.rs:1336`, `:1356`, `:1440`.

### Config keys + defaults (`[forensics]`, `config.rs:357`)
| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master switch (forensics off by default). |
| `min_confidence` | `90.0` | Legacy threshold; combined with `light_confidence` for the entry gate. |
| `light_confidence` | `70.0` | Cheap artifacts collected at/above this. |
| `full_confidence` | `90.0` | Memory dump added at/above this (or Critical). |
| `capture_before_response` | `true` | Capture synchronously before a destructive action. |
| `output_dir` | `/var/lib/nebula/forensics` | Bundle root. |
| `memory_dump` | `true` | Enable the full-tier memory artifact. |
| `pcap_on_event` | `true` | Capture PCAP on trigger. |
| `pcap_duration_secs` | `60` | |
| `pcap_filter` | `not port 53` | BPF capture filter. |
| `collect_logs` | `true` | |
| `log_paths` | `["/var/log"]` | Log slice sources. |
| `max_artifact_size_mb` | `512` | (declared; not enforced in the collectors reviewed) |
| `encrypt_artifacts` | `true` | AES-256-GCM in-place encryption. |
| `encryption_key_hex` | `None` | 64-hex-char AES-256 key; else machine-derived. |

### External interactions
`ps`, `ss`, `arp`, `ip`, `iptables`, `tail`, `lsof`, `tshark`/`tcpdump`, `insmod`/`rmmod` (LiME);
reads `/proc/*` and `/etc/machine-id`; `ring` for crypto; posts manifests to Nexus.

### Limitations
- Most collectors are Linux/`/proc`-specific — limited value on Windows/macOS.
- Log slicing grabs the last 500 lines regardless of event time (the `_around` timestamp is
  currently unused; the "±5 min" in comments is not implemented).
- `max_artifact_size_mb` is configured but not enforced by the reviewed collectors.
- Without a configured `encryption_key_hex`, the derived key is only as strong as
  `/etc/machine-id` + bundle id (host-local secret).
- No raw physical memory dump without LiME (by design — the fallback is metadata-only).
