// src/inventory/mod.rs — System inventory and file catalog

use crate::config::InventoryConfig;
use crate::types::{InventorySummary, ContainerInfo};
use anyhow::Result;
use sha2::{Sha256, Digest};
use sysinfo::{System, Networks, Users};
use tracing::{info, debug};
use std::path::Path;
use rusqlite::{Connection, params};
use rayon::prelude::*;

pub struct InventoryEngine {
    config: InventoryConfig,
    db: std::sync::Mutex<Connection>,
}

impl InventoryEngine {
    pub fn new(config: InventoryConfig) -> Result<Self> {
        let data = crate::platform::data_dir();
        std::fs::create_dir_all(&data)?;
        let conn = Connection::open(data.join("inventory.db"))?;
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS file_catalog (
                path TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER,
                modified_at TEXT,
                first_seen TEXT,
                last_seen TEXT
            );
            CREATE TABLE IF NOT EXISTS process_history (
                pid INTEGER,
                name TEXT,
                cmdline TEXT,
                user TEXT,
                first_seen TEXT,
                last_seen TEXT,
                PRIMARY KEY (pid, first_seen)
            );
            CREATE TABLE IF NOT EXISTS pkg_catalog (
                name TEXT,
                version TEXT,
                manager TEXT,
                description TEXT,
                installed_at TEXT,
                PRIMARY KEY (name, manager)
            );
        ")?;
        // Migration: add description column to pkg_catalog if upgrading from an
        // older schema (ignore error if it already exists).
        let _ = conn.execute("ALTER TABLE pkg_catalog ADD COLUMN description TEXT", []);
        info!("📦 InventoryEngine initialized (catalog DB: {})", data.join("inventory.db").display());
        Ok(Self { config, db: std::sync::Mutex::new(conn) })
    }

    /// Lightweight package-only enumeration for smart-scan fingerprinting.
    /// Refreshes the package catalog from the system and returns the list —
    /// no process tree, no file-catalog walk, no container scan.
    pub async fn collect_packages_only(&self) -> Result<Vec<crate::types::PackageEntry>> {
        let list = {
            let conn = self.db.lock().unwrap();
            let _ = self.scan_packages(&conn);  // refresh pkg_catalog from system
            conn.prepare("SELECT name,version,manager,COALESCE(description,'') FROM pkg_catalog ORDER BY name")
                .and_then(|mut s| {
                    let rows = s.query_map([], |r| Ok(crate::types::PackageEntry {
                        name: r.get(0)?, version: r.get(1)?, manager: r.get(2)?, description: r.get(3)?,
                    }))?;
                    Ok(rows.filter_map(|r| r.ok()).collect::<Vec<_>>())
                }).unwrap_or_default()
            // guard drops here
        };
        Ok(list)
    }

    pub async fn collect(&self) -> Result<InventorySummary> {
        self.collect_with_options(false).await
    }

    /// Collect inventory. When `skip_file_catalog` is true, the expensive
    /// recursive file-hashing walk is skipped (delta scan) — packages,
    /// processes, network, and containers are still collected since they're
    /// cheap and the signals that actually change between scans.
    pub async fn collect_with_options(&self, skip_file_catalog: bool) -> Result<InventorySummary> {
        info!("🔍 Running system inventory{}...", if skip_file_catalog { " (delta — skipping file catalog)" } else { "" });
        let mut sys = System::new_all();
        sys.refresh_all();

        // ── Hostname & network ─────────────────────────────────
        let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
        let os = format!("{} {}",
            System::long_os_version().unwrap_or_else(|| "Linux".to_string()),
            System::os_version().unwrap_or_default());
        let kernel = System::kernel_version().unwrap_or_else(|| "unknown".to_string());
        let arch = std::env::consts::ARCH.to_string();
        let uptime = System::uptime();

        // IP and MAC addresses (cross-platform via sysinfo::Networks).
        let mut ip_addresses = vec![];
        let mut mac_addresses = vec![];
        let networks = Networks::new_with_refreshed_list();
        for (iface_name, data) in &networks {
            if iface_name == "lo" { continue; }   // Unix loopback by name
            for addr in data.ip_networks() {
                let s = addr.addr.to_string();
                // Filter loopback, link-local (IPv6 fe80::, IPv4 APIPA 169.254.),
                // and unspecified — these aren't useful routable identities and on
                // Windows the loopback iface isn't named "lo" so we must filter by
                // address, not interface name.
                if s.starts_with("127.") || s == "::1"
                   || s.starts_with("fe80") || s.starts_with("169.254.")
                   || s == "0.0.0.0" || s == "::" {
                    continue;
                }
                if !ip_addresses.contains(&s) { ip_addresses.push(s); }
            }
            let mac = data.mac_address().to_string();
            if mac != "00:00:00:00:00:00" && !mac_addresses.contains(&mac) {
                mac_addresses.push(mac);
            }
        }
        // Diagnostic: surfaces whether interface enumeration actually yielded a
        // routable IP. If this logs an empty list on a host that clearly has
        // network connectivity, the platform's sysinfo network backend is the
        // culprit (and we fall back to other signals server-side).
        tracing::info!("🌐 Inventory: {} interface(s), {} routable IP(s): {}",
            networks.len(), ip_addresses.len(),
            if ip_addresses.is_empty() { "<none>".to_string() } else { ip_addresses.join(", ") });

        // ── CPU / RAM ──────────────────────────────────────────
        let cpu_model = sys.cpus().first()
            .map(|c| c.brand().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let ram_mb = sys.total_memory() / 1024 / 1024;

        // ── Users ──────────────────────────────────────────────
        let user_list = Users::new_with_refreshed_list();
        let users: Vec<String> = user_list.iter()
            .map(|u| format!("{} (uid:{:?})", u.name(), u.id()))
            .collect();

        // ── Processes ─────────────────────────────────────────
        let running_processes = sys.processes().len() as u32;
        {
            // Record process snapshot to DB — done in inner scope so conn drops immediately
            let conn = self.db.lock().unwrap();
            for (pid, proc_) in sys.processes() {
                let name = proc_.name().to_string_lossy().into_owned();
                let cmd = proc_.cmd().iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect::<Vec<_>>().join(" ");
                let user = proc_.user_id()
                    .and_then(|uid| user_list.iter().find(|u| u.id() == uid))
                    .map(|u| u.name().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let now = chrono::Utc::now().to_rfc3339();
                let _ = conn.execute(
                    "INSERT OR IGNORE INTO process_history (pid,name,cmdline,user,first_seen,last_seen)
                     VALUES (?1,?2,?3,?4,?5,?5)",
                    params![pid.as_u32(), name.as_str(), cmd.as_str(), user.as_str(), now],
                );
            }
        } // conn drops here

        // ── Synchronous DB work — must complete before any .await ─
        // std::sync::MutexGuard is !Send, so it MUST be dropped before
        // any await point or tokio::spawn will refuse to compile.
        let (pkg_count, catalog_count) = {
            let conn = self.db.lock().unwrap();
            let pkg  = self.scan_packages(&conn).unwrap_or(0);
            let cat  = if skip_file_catalog {
                // Reuse the prior catalog count from the DB instead of re-walking.
                conn.query_row("SELECT COUNT(*) FROM file_catalog", [], |r| r.get::<_,i64>(0))
                    .map(|n| n as u64).unwrap_or(0)
            } else {
                self.catalog_files(&conn).unwrap_or(0)
            };
            (pkg, cat)
            // conn guard drops here at end of block
        };

        // ── Open ports (via /proc/net/tcp) ─────────────────────
        let open_ports = self.scan_open_ports();

        // ── Containers (async — no MutexGuard in scope) ────────
        let containers = self.scan_containers().await;

        info!("✅ Inventory complete: {} processes, {} pkgs, {} files, {} containers",
            running_processes, pkg_count, catalog_count, containers.len());

        // ── Collect package + process lists for the Nexus ──────
        let package_list = {
            let conn = self.db.lock().unwrap();
            conn.prepare("SELECT name,version,manager,COALESCE(description,'') FROM pkg_catalog ORDER BY name")
                .and_then(|mut s| {
                    let rows = s.query_map([], |r| Ok(crate::types::PackageEntry {
                        name: r.get(0)?, version: r.get(1)?, manager: r.get(2)?, description: r.get(3)?,
                    }))?;
                    Ok(rows.filter_map(|r| r.ok()).collect::<Vec<_>>())
                }).unwrap_or_default()
        };
        let process_list = self.collect_process_list(&sys);
        let routes = Self::collect_routes();
        let arp_neighbors = Self::collect_arp();
        let network_peers = Self::collect_network_peers();

        Ok(InventorySummary {
            hostname,
            ip_addresses,
            mac_addresses,
            os,
            kernel,
            arch,
            domain: Self::get_domain(),
            uptime_secs: uptime,
            cpu_model,
            ram_mb,
            installed_packages: pkg_count,
            running_processes,
            open_ports,
            users,
            containers,
            file_catalog_count: catalog_count,
            package_list,
            process_list,
            routes,
            arp_neighbors,
            network_peers,
        })
    }

    /// Parse the kernel routing table. Linux uses `ip route`; Windows uses
    /// `route print`.
    fn collect_routes() -> Vec<crate::types::RouteEntry> {
        #[cfg(target_os = "windows")]
        { return Self::collect_routes_windows(); }
        #[cfg(not(target_os = "windows"))]
        {
        let mut routes = Vec::new();
        if let Ok(out) = std::process::Command::new("ip").args(["route"]).output() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                // e.g. "default via 10.0.0.1 dev eth0" or "10.0.0.0/24 dev eth0 ..."
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() { continue; }
                let destination = parts[0].to_string();
                let gateway = parts.iter().position(|&p| p == "via")
                    .and_then(|i| parts.get(i+1)).map(|s| s.to_string()).unwrap_or_else(|| "direct".to_string());
                let interface = parts.iter().position(|&p| p == "dev")
                    .and_then(|i| parts.get(i+1)).map(|s| s.to_string()).unwrap_or_default();
                routes.push(crate::types::RouteEntry { destination, gateway, interface });
            }
        }
        routes
        }
    }

    /// Windows IPv4 routing table via `route print -4`. The active-routes section
    /// has columns: Network Destination | Netmask | Gateway | Interface | Metric.
    #[cfg(target_os = "windows")]
    fn collect_routes_windows() -> Vec<crate::types::RouteEntry> {
        let mut routes = Vec::new();
        let Ok(out) = std::process::Command::new("route").args(["print", "-4"]).output() else {
            return routes;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let mut in_active = false;
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with("Active Routes:") { in_active = true; continue; }
            if t.starts_with("Persistent Routes:") || t.starts_with("Default Gateway:") { in_active = false; }
            if !in_active { continue; }
            let f: Vec<&str> = t.split_whitespace().collect();
            // Skip the header row ("Network Destination ...") and separators.
            if f.len() < 4 || f[0] == "Network" || t.starts_with('=') { continue; }
            // f[0]=dest f[1]=netmask f[2]=gateway f[3]=interface
            let destination = if f[1] != "255.255.255.255" { format!("{}/{}", f[0], f[1]) } else { f[0].to_string() };
            let gateway = if f[2].eq_ignore_ascii_case("On-link") { "direct".to_string() } else { f[2].to_string() };
            routes.push(crate::types::RouteEntry {
                destination, gateway, interface: f[3].to_string(),
            });
            if routes.len() >= 200 { break; }
        }
        routes
    }

    /// Parse the ARP/neighbor table. Linux uses `ip neigh`; Windows uses `arp -a`.
    fn collect_arp() -> Vec<crate::types::ArpEntry> {
        #[cfg(target_os = "windows")]
        { return Self::collect_arp_windows(); }
        #[cfg(not(target_os = "windows"))]
        {
        let mut neighbors = Vec::new();
        if let Ok(out) = std::process::Command::new("ip").args(["neigh"]).output() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                // e.g. "10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() { continue; }
                let ip = parts[0].to_string();
                let mac = parts.iter().position(|&p| p == "lladdr")
                    .and_then(|i| parts.get(i+1)).map(|s| s.to_string()).unwrap_or_default();
                let interface = parts.iter().position(|&p| p == "dev")
                    .and_then(|i| parts.get(i+1)).map(|s| s.to_string()).unwrap_or_default();
                if !mac.is_empty() {
                    neighbors.push(crate::types::ArpEntry { ip, mac, interface });
                }
            }
        }
        neighbors
        }
    }

    /// Windows ARP table via `arp -a`. Output groups entries under each interface:
    ///   Interface: 10.255.255.211 --- 0x5
    ///     Internet Address      Physical Address      Type
    ///     10.255.255.1          aa-bb-cc-dd-ee-ff     dynamic
    #[cfg(target_os = "windows")]
    fn collect_arp_windows() -> Vec<crate::types::ArpEntry> {
        let mut neighbors = Vec::new();
        let Ok(out) = std::process::Command::new("arp").args(["-a"]).output() else {
            return neighbors;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let mut current_if = String::new();
        for line in text.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("Interface:") {
                // "10.255.255.211 --- 0x5" → take the IP as the interface label
                current_if = rest.split_whitespace().next().unwrap_or("").to_string();
                continue;
            }
            let f: Vec<&str> = t.split_whitespace().collect();
            if f.len() < 3 { continue; }
            if f[0] == "Internet" { continue; } // header row
            // f[0]=ip f[1]=mac(aa-bb-..) f[2]=type
            let ip = f[0].to_string();
            let mac = f[1].replace('-', ":");
            // Skip broadcast/multicast noise.
            if mac.starts_with("ff:ff") || ip.ends_with(".255") { continue; }
            if mac.len() >= 11 {
                neighbors.push(crate::types::ArpEntry {
                    ip, mac, interface: current_if.clone(),
                });
            }
            if neighbors.len() >= 200 { break; }
        }
        neighbors
    }

    /// Collect active network peers (remote endpoints) from /proc/net/tcp{,6},
    /// with process attribution via socket inode → /proc/<pid>/fd. Captures both
    /// inbound and outbound, internal and external, so operators can see exactly
    /// which devices a host has interacted with.
    fn collect_network_peers() -> Vec<crate::types::NetworkPeer> {
        #[cfg(target_os = "windows")]
        { return Self::collect_network_peers_windows(); }
        #[cfg(not(target_os = "windows"))]
        {
        use std::collections::HashMap;
        // Build inode → (pid, process_name) map from /proc/<pid>/fd socket links.
        let mut inode_proc: HashMap<String, (u32, String)> = HashMap::new();
        if let Ok(procs) = std::fs::read_dir("/proc") {
            for p in procs.flatten() {
                let pid = match p.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                    Some(v) => v, None => continue,
                };
                let name = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                    .map(|s| s.trim().to_string()).unwrap_or_default();
                let fd_dir = format!("/proc/{}/fd", pid);
                if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                    for fd in fds.flatten() {
                        if let Ok(link) = std::fs::read_link(fd.path()) {
                            let s = link.to_string_lossy();
                            if let Some(rest) = s.strip_prefix("socket:[") {
                                if let Some(inode) = rest.strip_suffix(']') {
                                    inode_proc.insert(inode.to_string(), (pid, name.clone()));
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut peers: Vec<crate::types::NetworkPeer> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (path, proto) in [("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")] {
            let content = match std::fs::read_to_string(path) { Ok(c) => c, Err(_) => continue };
            for line in content.lines().skip(1) {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 10 { continue; }
                let local = Self::parse_proc_addr(f[1], proto);
                let remote = Self::parse_proc_addr(f[2], proto);
                let state = f[3];
                let inode = f[9];
                let (rip, rport) = match remote { Some(v) => v, None => continue };
                // Skip the unspecified remote (listeners) unless it's a LISTEN row
                let st_name = match state {
                    "01" => "ESTABLISHED", "0A" => "LISTEN", "06" => "TIME_WAIT",
                    "08" => "CLOSE_WAIT", "02" => "SYN_SENT", _ => "OTHER",
                };
                // For LISTEN sockets the remote is 0.0.0.0 — not a peer, skip.
                if st_name == "LISTEN" { continue; }
                if rip == "0.0.0.0" || rip == "::" || rip.is_empty() { continue; }
                // Direction heuristic: if our local port is well-known/low and the
                // remote port is high/ephemeral, it's likely inbound; else outbound.
                let lport = local.as_ref().map(|(_, p)| *p).unwrap_or(0);
                let direction = if lport != 0 && lport < 1024 && rport >= 1024 { "inbound" } else { "outbound" };
                let scope = if rip.starts_with("127.") || rip.starts_with("10.")
                    || rip.starts_with("192.168.") || rip.starts_with("172.")
                    || rip.starts_with("169.254.") || rip.starts_with("fe80")
                    || rip == "::1" { "internal" } else { "external" };
                let (pid, process) = inode_proc.get(inode).cloned().unwrap_or((0, String::new()));
                let key = format!("{}:{}:{}:{}", rip, rport, proto, process);
                if !seen.insert(key) { continue; }
                peers.push(crate::types::NetworkPeer {
                    remote_ip: rip, remote_port: rport, proto: proto.to_string(),
                    direction: direction.to_string(), process, pid,
                    scope: scope.to_string(), state: st_name.to_string(),
                });
                if peers.len() >= 500 { break; }
            }
        }
        peers
        }
    }

    /// Windows active-connection peers via `netstat -n -o` (numeric + owning PID),
    /// with process names resolved from sysinfo. Captures TCP connections with a
    /// real remote endpoint; direction is inferred from local vs remote port.
    #[cfg(target_os = "windows")]
    fn collect_network_peers_windows() -> Vec<crate::types::NetworkPeer> {
        use std::collections::{HashMap, HashSet};
        // pid → process name, from sysinfo. System::new_all() populates the
        // process list on construction (same pattern as the inventory collector
        // above), so no separate refresh call is needed — and this avoids the
        // version-specific refresh_processes* argument differences.
        let sys = System::new_all();
        let pid_name: HashMap<u32, String> = sys.processes().iter()
            .map(|(pid, p)| (pid.as_u32(), p.name().to_string_lossy().to_string()))
            .collect();

        let mut peers = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let Ok(out) = std::process::Command::new("netstat").args(["-n", "-o", "-p", "tcp"]).output() else {
            return peers;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            // Proto  Local            Foreign           State        PID
            if f.len() < 5 || f[0] != "TCP" { continue; }
            let local = f[1];
            let foreign = f[2];
            let state = f[3];
            let pid: u32 = f[4].parse().unwrap_or(0);
            if state == "LISTENING" { continue; }

            let split_hostport = |s: &str| -> Option<(String, u16)> {
                let idx = s.rfind(':')?;
                let ip = s[..idx].trim_matches(|c| c == '[' || c == ']').to_string();
                let port = s[idx+1..].parse::<u16>().ok()?;
                Some((ip, port))
            };
            let (rip, rport) = match split_hostport(foreign) { Some(v) => v, None => continue };
            let lport = split_hostport(local).map(|(_, p)| p).unwrap_or(0);
            if rip == "0.0.0.0" || rip == "::" || rip.is_empty() || rip.starts_with("127.") || rip == "::1" {
                continue;
            }
            let direction = if lport != 0 && lport < 1024 && rport >= 1024 { "inbound" } else { "outbound" };
            let scope = if rip.starts_with("10.") || rip.starts_with("192.168.")
                || rip.starts_with("172.") || rip.starts_with("169.254.")
                || rip.starts_with("fe80") { "internal" } else { "external" };
            let process = pid_name.get(&pid).cloned().unwrap_or_default();
            let key = format!("{}:{}:{}", rip, rport, process);
            if !seen.insert(key) { continue; }
            peers.push(crate::types::NetworkPeer {
                remote_ip: rip, remote_port: rport, proto: "tcp".to_string(),
                direction: direction.to_string(), process, pid,
                scope: scope.to_string(), state: state.to_string(),
            });
            if peers.len() >= 500 { break; }
        }
        peers
    }

    /// Parse a /proc/net/tcp{,6} hex address "0100007F:1F90" → ("127.0.0.1", 8080).
    #[cfg(not(target_os = "windows"))]
    fn parse_proc_addr(hex: &str, proto: &str) -> Option<(String, u16)> {
        let parts: Vec<&str> = hex.splitn(2, ':').collect();
        if parts.len() != 2 { return None; }
        let port = u16::from_str_radix(parts[1], 16).ok()?;
        if proto == "tcp" && parts[0].len() == 8 {
            let n = u32::from_str_radix(parts[0], 16).ok()?;
            Some((format!("{}.{}.{}.{}", n&0xFF, (n>>8)&0xFF, (n>>16)&0xFF, (n>>24)&0xFF), port))
        } else if proto == "tcp6" && parts[0].len() == 32 {
            // IPv6: 32 hex chars, little-endian per 32-bit word. Render compact.
            let bytes: Vec<u8> = (0..16).filter_map(|i| u8::from_str_radix(&parts[0][i*2..i*2+2], 16).ok()).collect();
            if bytes.len() != 16 { return None; }
            // Group into 8 hextets (the kernel stores words little-endian; for
            // display we keep byte order as-is — good enough for identification).
            let h: Vec<String> = (0..8).map(|i| format!("{:x}", ((bytes[i*2] as u16) << 8) | bytes[i*2+1] as u16)).collect();
            Some((h.join(":"), port))
        } else { None }
    }

    /// Collect a process list with PID/PPID/name/user for the process tree.
    /// Build the process list from sysinfo (cross-platform: Windows, Linux,
    /// macOS). The previous implementation walked /proc, which only exists on
    /// Linux — so on Windows the detailed process tree was empty even though the
    /// process *count* (from sysinfo) was correct, producing the UI's
    /// "Process list not available… requires a newer agent build" message.
    fn collect_process_list(&self, sys: &System) -> Vec<crate::types::ProcessEntry> {
        let mut procs = Vec::new();
        for (pid, proc_) in sys.processes() {
            let user = proc_.user_id()
                .map(|u| {
                    // Unix: numeric uid. Windows: SID string. Either way, render
                    // a human-meaningful identifier.
                    #[cfg(unix)]    { format!("uid:{}", **u) }
                    #[cfg(windows)] { u.to_string() }
                    #[cfg(not(any(unix, windows)))] { let _ = u; "unknown".to_string() }
                })
                .unwrap_or_else(|| "unknown".to_string());
            procs.push(crate::types::ProcessEntry {
                pid:  pid.as_u32(),
                ppid: proc_.parent().map(|p| p.as_u32()).unwrap_or(0),
                name: proc_.name().to_string_lossy().to_string(),
                user,
            });
        }
        procs
    }

    fn scan_packages(&self, conn: &Connection) -> Result<u32> {
        let mut count = 0u32;
        // dpkg — capture the short summary as description
        if let Ok(output) = std::process::Command::new("dpkg-query")
            .args(["-W", "-f=${Package}\t${Version}\t${binary:Summary}\n"])
            .output()
        {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let parts: Vec<&str> = line.splitn(3, '\t').collect();
                if parts.len() >= 2 {
                    let desc = parts.get(2).copied().unwrap_or("");
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO pkg_catalog (name,version,manager,description,installed_at) VALUES (?1,?2,'dpkg',?3,datetime('now'))",
                        params![parts[0], parts[1], desc],
                    );
                    count += 1;
                }
            }
        }
        // rpm — capture summary as description
        if let Ok(output) = std::process::Command::new("rpm")
            .args(["-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{SUMMARY}\n"])
            .output()
        {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let parts: Vec<&str> = line.splitn(3, '\t').collect();
                if parts.len() >= 2 {
                    let desc = parts.get(2).copied().unwrap_or("");
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO pkg_catalog (name,version,manager,description,installed_at) VALUES (?1,?2,'rpm',?3,datetime('now'))",
                        params![parts[0], parts[1], desc],
                    );
                    count += 1;
                }
            }
        }
        // pip
        if let Ok(output) = std::process::Command::new("pip3")
            .args(["list", "--format=freeze"])
            .output()
        {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let parts: Vec<&str> = line.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO pkg_catalog (name,version,manager,installed_at) VALUES (?1,?2,'pip',datetime('now'))",
                        params![parts[0], parts[1].trim_start_matches('=')],
                    );
                    count += 1;
                }
            }
        }

        // Windows installed software — enumerate the three "Uninstall" registry
        // hives (native 64-bit, 32-bit WOW6432Node, and per-user). This is where
        // Add/Remove Programs reads from and captures essentially all installed
        // applications, far more than the handful pip would report. We shell out
        // to PowerShell with Get-ItemProperty and emit tab-separated
        // Name<TAB>Version so the parse below is identical in spirit to dpkg/rpm.
        #[cfg(windows)]
        {
            count += self.scan_packages_windows(conn);
        }

        Ok(count)
    }

    /// Windows-only: read installed software from the Uninstall registry hives.
    #[cfg(windows)]
    fn scan_packages_windows(&self, conn: &Connection) -> u32 {
        let mut count = 0u32;
        // PowerShell one-liner: gather DisplayName/DisplayVersion/Publisher plus
        // Comments and InstallDate where present. Windows has no true package
        // "description" like Linux managers, but the Comments field (when an
        // installer populates it) is the closest equivalent; otherwise we compose
        // a useful line from Publisher + install date rather than showing only the
        // bare vendor name.
        let ps = r#"
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  ForEach-Object { "$($_.DisplayName)`t$($_.DisplayVersion)`t$($_.Publisher)`t$($_.Comments)`t$($_.InstallDate)" }
"#;
        if let Ok(output) = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps])
            .output()
        {
            use std::collections::HashSet;
            let mut seen: HashSet<String> = HashSet::new();
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let parts: Vec<&str> = line.splitn(5, '\t').collect();
                if parts.is_empty() || parts[0].trim().is_empty() { continue; }
                let name = parts[0].trim();
                // De-dupe: the same app can appear in multiple hives.
                if !seen.insert(name.to_string()) { continue; }
                let version   = parts.get(1).map(|s| s.trim()).unwrap_or("");
                let publisher = parts.get(2).map(|s| s.trim()).unwrap_or("");
                let comments  = parts.get(3).map(|s| s.trim()).unwrap_or("");
                let installed = parts.get(4).map(|s| s.trim()).unwrap_or("");

                // Build the best available description: prefer the installer's
                // Comments; otherwise compose from publisher + install date.
                let description = if !comments.is_empty() && comments != "\u{0}" {
                    comments.to_string()
                } else if !publisher.is_empty() {
                    if installed.len() == 8 {
                        // InstallDate is YYYYMMDD.
                        format!("Published by {} · installed {}-{}-{}",
                            publisher, &installed[0..4], &installed[4..6], &installed[6..8])
                    } else {
                        format!("Published by {}", publisher)
                    }
                } else {
                    String::new()
                };

                let _ = conn.execute(
                    "INSERT OR REPLACE INTO pkg_catalog (name,version,manager,description,installed_at) VALUES (?1,?2,'windows',?3,datetime('now'))",
                    params![name, version, description],
                );
                count += 1;
            }
        }

        // Also collect installed Windows updates (KBs / hotfixes) via Get-HotFix.
        // These are OS patches, not apps — we store them with manager='windows-kb'
        // so they're distinguishable and filterable in the package view. Knowing
        // which KBs are present is directly useful for patch/vuln assessment.
        let kb_ps = r#"Get-HotFix | ForEach-Object { "$($_.HotFixID)`t$($_.Description)`t$($_.InstalledOn)" }"#;
        if let Ok(kout) = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", kb_ps])
            .output()
        {
            for line in String::from_utf8_lossy(&kout.stdout).lines() {
                let parts: Vec<&str> = line.splitn(3, '\t').collect();
                let kb = parts.first().map(|s| s.trim()).unwrap_or("");
                if kb.is_empty() || !kb.starts_with("KB") { continue; }
                let kind = parts.get(1).map(|s| s.trim()).unwrap_or("Update");
                let installed = parts.get(2).map(|s| s.trim()).unwrap_or("");
                let desc = if installed.is_empty() {
                    format!("Windows {} ({})", kind, kb)
                } else {
                    format!("Windows {} · installed {}", kind, installed)
                };
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO pkg_catalog (name,version,manager,description,installed_at) VALUES (?1,'','windows-kb',?2,datetime('now'))",
                    params![kb, desc],
                );
                count += 1;
            }
        }
        count
    }

    fn scan_open_ports(&self) -> Vec<u16> {
        let mut ports = vec![];
        for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines().skip(1) {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() >= 4 && fields[3] == "0A" { // LISTEN state
                        if let Some(local) = fields.get(1) {
                            let hex_port = &local[local.len().saturating_sub(4)..];
                            if let Ok(port) = u16::from_str_radix(hex_port, 16) {
                                if !ports.contains(&port) { ports.push(port); }
                            }
                        }
                    }
                }
            }
        }
        ports.sort();
        ports
    }

    async fn scan_containers(&self) -> Vec<ContainerInfo> {
        let mut containers = vec![];
        // Docker
        if let Ok(output) = tokio::process::Command::new("docker")
            .args(["ps", "-a", "--format", "{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.CreatedAt}}"])
            .output().await
        {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let parts: Vec<&str> = line.splitn(4, '\t').collect();
                if parts.len() >= 3 {
                    containers.push(ContainerInfo {
                        id: parts[0].to_string(),
                        image: parts[1].to_string(),
                        status: parts[2].to_string(),
                        created: None,
                    });
                }
            }
        }
        // Podman (same API)
        if let Ok(output) = tokio::process::Command::new("podman")
            .args(["ps", "-a", "--format", "{{.ID}}\t{{.Image}}\t{{.Status}}"])
            .output().await
        {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let parts: Vec<&str> = line.splitn(3, '\t').collect();
                if parts.len() >= 3 {
                    containers.push(ContainerInfo {
                        id: format!("podman:{}", parts[0]),
                        image: parts[1].to_string(),
                        status: parts[2].to_string(),
                        created: None,
                    });
                }
            }
        }
        containers
    }

    fn catalog_files(&self, conn: &Connection) -> Result<u64> {
        let mut total = 0u64;
        let include = self.config.include_paths.clone();
        let exclude = self.config.exclude_paths.clone();

        for base in &include {
            let files = Self::walk_dir(base, &exclude);
            let now = chrono::Utc::now().to_rfc3339();

            // Hash files in parallel using rayon
            let hashed: Vec<(String, String, u64)> = files.par_iter()
                .filter_map(|path| {
                    let data = std::fs::read(path).ok()?;
                    let size = data.len() as u64;
                    let hash = format!("{:x}", Sha256::digest(&data));
                    Some((path.clone(), hash, size))
                })
                .collect();

            for (path, hash, size) in &hashed {
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO file_catalog (path,sha256,size_bytes,modified_at,first_seen,last_seen)
                     VALUES (?1,?2,?3,datetime('now'),
                       COALESCE((SELECT first_seen FROM file_catalog WHERE path=?1), ?4),
                       ?4)",
                    params![path, hash, size, now],
                );
                total += 1;
            }
        }
        debug!("file catalog: {} files hashed", total);
        Ok(total)
    }

    fn walk_dir(base: &str, exclude: &[String]) -> Vec<String> {
        let mut files = vec![];
        let _ = walkdir_collect(Path::new(base), exclude, &mut files, 0);
        files
    }

    fn get_domain() -> Option<String> {
        std::fs::read_to_string("/etc/resolv.conf").ok()
            .and_then(|c| {
                c.lines()
                    .find(|l| l.starts_with("search ") || l.starts_with("domain "))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .map(String::from)
            })
    }
}

fn walkdir_collect(path: &Path, exclude: &[String], out: &mut Vec<String>, depth: usize) -> Result<()> {
    if depth > 8 { return Ok(()); }
    let path_str = path.to_string_lossy().to_string();
    if exclude.iter().any(|e| path_str.starts_with(e.as_str())) {
        return Ok(());
    }
    if path.is_file() {
        out.push(path_str);
        return Ok(());
    }
    if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let _ = walkdir_collect(&entry.path(), exclude, out, depth + 1);
            }
        }
    }
    Ok(())
}
