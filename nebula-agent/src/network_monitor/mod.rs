#![allow(dead_code)]
// src/network_monitor/mod.rs — Continuous network traffic analysis
//
// What this catches that anomaly scoring misses:
//   - C2 beacon patterns (regular small outbound connections at fixed intervals)
//   - DNS tunneling (high-entropy subdomains, long queries, unusual record types)
//   - Data exfiltration (large sustained outbound to unknown IPs)
//   - TLS to unusual destinations (self-signed certs, new cert for known domain)
//   - Cloud metadata service abuse (169.254.169.254 — T1552.005)
//
// Implementation: reads from /proc/net/tcp, /proc/net/udp, and DNS query logs.
// For full packet-level analysis, the pcap feature flag enables deep inspection.

use crate::types::{ThreatEvent, Severity, ResponseAction, IOC, IOCType};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn, debug};
use uuid::Uuid;

/// Tracked connection for beacon detection
#[derive(Debug, Clone)]
struct TrackedConn {
    dest_ip:       String,
    dest_port:     u16,
    first_seen:    chrono::DateTime<Utc>,
    last_seen:     chrono::DateTime<Utc>,
    count:         u32,
    intervals:     Vec<f64>,  // seconds between connections
    bytes_sent:    u64,
}

/// DNS query record
#[derive(Debug, Clone)]
struct DnsQuery {
    domain:       String,
    query_type:   String,
    timestamp:    chrono::DateTime<Utc>,
    response_len: usize,
}

pub struct NetworkMonitor {
    agent_id:    String,
    hostname:    String,
    pub tx:      mpsc::Sender<ThreatEvent>,
    connections: Arc<Mutex<HashMap<String, TrackedConn>>>,
    dns_queries: Arc<Mutex<Vec<DnsQuery>>>,
}

impl NetworkMonitor {
    pub fn new(agent_id: &str, hostname: &str) -> (Self, mpsc::Receiver<ThreatEvent>) {
        let (tx, rx) = mpsc::channel(256);
        (Self {
            agent_id: agent_id.to_string(),
            hostname: hostname.to_string(),
            tx,
            connections: Arc::new(Mutex::new(HashMap::new())),
            dns_queries: Arc::new(Mutex::new(Vec::new())),
        }, rx)
    }

    pub async fn start(&self) -> Result<()> {
        let net_src = if cfg!(target_os = "windows") { "netstat" } else { "/proc/net" };
        info!("🌐 NetworkMonitor starting ({} polling + DNS analysis)", net_src);

        // Connection tracker — polls /proc/net/tcp every 10s
        self.start_connection_tracker();
        // DNS analysis — systemd-resolved/syslog on Linux, the DNS-Client
        // operational channel or the resolver cache on Windows.
        self.start_dns_monitor();
        // Cloud metadata monitor — watches for 169.254.169.254 access
        self.start_metadata_monitor();

        Ok(())
    }

    fn start_connection_tracker(&self) {
        let tx       = self.tx.clone();
        let conns    = self.connections.clone();
        let agent_id = self.agent_id.clone();
        let hostname = self.hostname.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                ticker.tick().await;

                let current = read_proc_net_connections();
                let now = Utc::now();
                let mut map = conns.lock().await;

                for (key, (ip, port)) in &current {
                    let entry = map.entry(key.clone()).or_insert(TrackedConn {
                        dest_ip: ip.clone(), dest_port: *port,
                        first_seen: now, last_seen: now,
                        count: 0, intervals: vec![], bytes_sent: 0,
                    });

                    let secs_since = (now - entry.last_seen).num_seconds() as f64;
                    if secs_since > 0.5 {
                        entry.intervals.push(secs_since);
                        if entry.intervals.len() > 20 { entry.intervals.remove(0); }
                    }
                    entry.last_seen = now;
                    entry.count += 1;

                    // ── Beacon detection ─────────────────────────
                    // C2 beacons have regular intervals (low coefficient of variation)
                    if entry.intervals.len() >= 5 {
                        let cv = coefficient_of_variation(&entry.intervals);
                        let avg = entry.intervals.iter().sum::<f64>() / entry.intervals.len() as f64;

                        // Regular interval (CV < 0.3) with short period (< 300s) = beacon
                        if cv < 0.3 && avg < 300.0 && avg > 5.0 && entry.count >= 10 {
                            // Check if destination is a known-good service
                            if !is_known_good_ip(ip) {
                                warn!("📡 Beacon detected: {}:{} avg={:.0}s cv={:.2} count={}",
                                    ip, port, avg, cv, entry.count);

                                let _ = tx.send(make_network_threat(
                                    &agent_id, &hostname,
                                    "T1071.001",
                                    Severity::High,
                                    format!("C2 beacon pattern to {}:{}", ip, port),
                                    format!("Regular outbound connection to {}:{} — avg interval {:.0}s, CV={:.2}, count={}. Consistent timing indicates automated C2 beacon.", ip, port, avg, cv, entry.count),
                                    85.0,
                                    vec![IOC { ioc_type: IOCType::Ipv4, value: ip.clone(), source: "beacon_detector".into(), confidence: 80.0 }],
                                )).await;
                            }
                        }
                    }

                    // ── Large sustained transfer ──────────────────
                    if entry.count > 50 && !is_known_good_ip(ip) {
                        debug!("High connection count to {}: {}", ip, entry.count);
                    }
                }

                // Cloud metadata service access (T1552.005)
                if current.values().any(|(ip, _)| ip == "169.254.169.254") {
                    let _ = tx.send(make_network_threat(
                        &agent_id, &hostname,
                        "T1552.005",
                        Severity::High,
                        "Cloud metadata service access detected".to_string(),
                        "Connection to 169.254.169.254 (instance metadata API). This is the primary technique for cloud credential theft on EC2/GCE/Azure.".to_string(),
                        90.0,
                        vec![IOC { ioc_type: IOCType::Ipv4, value: "169.254.169.254".into(), source: "network_monitor".into(), confidence: 95.0 }],
                    )).await;
                }
            }
        });
    }

    fn start_dns_monitor(&self) {
        let tx       = self.tx.clone();
        let queries  = self.dns_queries.clone();
        let agent_id = self.agent_id.clone();
        let hostname = self.hostname.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                ticker.tick().await;

                // Read recent DNS from systemd-resolved or /var/log/syslog
                let recent_domains = read_recent_dns_queries();
                let mut q = queries.lock().await;

                for domain in &recent_domains {
                    // ── DNS tunneling detection ───────────────────
                    // Tunneling tools use very long subdomains or high-entropy labels
                    let entropy = shannon_entropy(domain);
                    let label_len = domain.split('.').next().unwrap_or("").len();

                    if entropy > 3.8 && label_len > 30 {
                        warn!("🌐 DNS tunneling: {} (entropy={:.2}, label_len={})",
                            domain, entropy, label_len);
                        let _ = tx.send(make_network_threat(
                            &agent_id, &hostname,
                            "T1071.004",
                            Severity::High,
                            format!("DNS tunneling pattern: {}", safe_prefix(domain, 60)),
                            format!("High-entropy DNS query detected: '{}'. Entropy={:.2}, label_len={}. Consistent with DNS tunneling tools (iodine, dnscat2, etc.)", domain, entropy, label_len),
                            80.0,
                            vec![IOC { ioc_type: IOCType::Domain, value: domain.clone(), source: "dns_monitor".into(), confidence: 75.0 }],
                        )).await;
                    }

                    // Excessive unique subdomains for same parent domain (fast-flux/DGA)
                    let parent = domain.splitn(3, '.').skip(1).collect::<Vec<_>>().join(".");
                    let subdomain_count = recent_domains.iter().filter(|d| d.ends_with(&parent)).count();
                    if subdomain_count > 20 && !is_cdn_domain(&parent) {
                        let _ = tx.send(make_network_threat(
                            &agent_id, &hostname,
                            "T1568.002",
                            Severity::High,
                            format!("DGA/fast-flux DNS: {} unique subdomains of {}", subdomain_count, parent),
                            format!("{} unique subdomains queried for {} in 30 seconds — consistent with DGA malware or fast-flux C2.", subdomain_count, parent),
                            75.0,
                            vec![IOC { ioc_type: IOCType::Domain, value: parent.clone(), source: "dns_monitor".into(), confidence: 70.0 }],
                        )).await;
                    }

                    q.push(DnsQuery {
                        domain: domain.clone(),
                        query_type: "A".into(),
                        timestamp: Utc::now(),
                        response_len: domain.len(),
                    });
                }

                // Keep last 10,000 queries
                if q.len() > 10_000 { let drain_to = q.len() - 10_000; q.drain(..drain_to); }
            }
        });
    }

    fn start_metadata_monitor(&self) {
        // Linux-only fast-path: watch /proc/net/tcp directly for the metadata IP
        // (169.254.169.254 = FEA9FEA9 in little-endian hex). On Windows this file
        // doesn't exist and the cross-platform connection tracker above already
        // flags 169.254.169.254, so we skip this redundant loop there.
        #[cfg(not(target_os = "windows"))]
        {
            let tx       = self.tx.clone();
            let agent_id = self.agent_id.clone();
            let hostname = self.hostname.clone();

            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(5));
                loop {
                    ticker.tick().await;
                    if let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") {
                        if tcp.contains("FEA9FEA9") || tcp.contains("fea9fea9") {
                            let _ = tx.send(make_network_threat(
                                &agent_id, &hostname,
                                "T1552.005",
                                Severity::Critical,
                                "Active connection to cloud metadata service (169.254.169.254)".to_string(),
                                "Active TCP connection to instance metadata service detected in /proc/net/tcp. This is the primary cloud credential theft vector.".to_string(),
                                95.0,
                                vec![IOC { ioc_type: IOCType::Ipv4, value: "169.254.169.254".into(), source: "metadata_monitor".into(), confidence: 99.0 }],
                            )).await;
                        }
                    }
                }
            });
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────

fn read_proc_net_connections() -> HashMap<String, (String, u16)> {
    #[cfg(target_os = "windows")]
    { read_windows_connections() }
    #[cfg(not(target_os = "windows"))]
    { read_proc_net_connections_linux() }
}

/// Windows established-TCP enumeration via `netstat -n -p tcp`. No extra deps,
/// works without admin. Parses the foreign address column for ESTABLISHED rows.
#[cfg(target_os = "windows")]
fn read_windows_connections() -> HashMap<String, (String, u16)> {
    let mut conns = HashMap::new();
    let Ok(out) = std::process::Command::new("netstat").args(["-n", "-p", "tcp"]).output() else {
        return conns;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Format:  TCP    192.168.1.5:52344   93.184.216.34:443   ESTABLISHED
        if f.len() < 4 || f[0] != "TCP" { continue; }
        if f[3] != "ESTABLISHED" { continue; }
        let foreign = f[2];
        // Split host:port from the right (IPv6 has colons too).
        if let Some(idx) = foreign.rfind(':') {
            let ip = foreign[..idx].trim_matches(|c| c == '[' || c == ']').to_string();
            if let Ok(port) = foreign[idx+1..].parse::<u16>() {
                if ip.starts_with("127.") || ip == "0.0.0.0" || ip == "::1" || ip.is_empty() {
                    continue;
                }
                conns.insert(format!("{}:{}", ip, port), (ip, port));
            }
        }
    }
    conns
}

#[cfg(not(target_os = "windows"))]
fn read_proc_net_connections_linux() -> HashMap<String, (String, u16)> {
    let mut conns = HashMap::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = std::fs::read_to_string(path) else { continue };
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 { continue; }
            // state 01 = ESTABLISHED
            if fields[3] != "01" { continue; }
            let remote = fields[2];
            if let Some((ip, port)) = parse_hex_addr(remote) {
                let key = format!("{}:{}", ip, port);
                conns.insert(key, (ip, port));
            }
        }
    }
    conns
}

#[cfg(not(target_os = "windows"))]
fn parse_hex_addr(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.splitn(2, ':').collect();
    if parts.len() != 2 { return None; }

    let ip_hex = parts[0];
    let port = u16::from_str_radix(parts[1], 16).ok()?;

    // Parse as little-endian IPv4
    if ip_hex.len() == 8 {
        let n = u32::from_str_radix(ip_hex, 16).ok()?;
        let b1 = n & 0xFF;
        let b2 = (n >> 8) & 0xFF;
        let b3 = (n >> 16) & 0xFF;
        let b4 = (n >> 24) & 0xFF;
        let ip = format!("{}.{}.{}.{}", b1, b2, b3, b4);
        // Skip local/unroutable
        if ip.starts_with("127.") || ip == "0.0.0.0" { return None; }
        Some((ip, port))
    } else {
        None
    }
}

/// Recently-resolved domains, used by the DNS tunneling / DGA heuristics.
///
/// Windows has no syslog and no journal, so both Linux sources below return
/// nothing there — which silently disabled DNS tunneling (T1071.004) and
/// DGA/fast-flux (T1568.002) detection on every Windows agent. Two sources are
/// used instead, in order of fidelity:
///
///   1. `Microsoft-Windows-DNS-Client/Operational` event 3006 — the actual
///      query stream, but the channel is DISABLED by default. Operators who
///      want full DNS visibility should enable it:
///        wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true
///   2. `Get-DnsClientCache` — the resolver cache. Always available with no
///      configuration, and it holds what was recently resolved, which is
///      sufficient for the entropy/subdomain-count heuristics. Entries persist
///      for their TTL, so a domain can be seen on more than one poll; the
///      callers treat repeats as harmless.
#[cfg(target_os = "windows")]
fn read_recent_dns_queries() -> Vec<String> {
    let mut domains = vec![];

    // 1. The DNS client operational channel, when the operator has enabled it.
    if let Ok(out) = std::process::Command::new("wevtutil")
        .args(["qe", "Microsoft-Windows-DNS-Client/Operational",
               "/q:*[System[(EventID=3006)]]", "/c:200", "/rd:true", "/f:text"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if let Some(d) = extract_domain_from_log(line) { domains.push(d); }
            }
        }
    }

    // 2. Resolver cache — always available.
    if domains.is_empty() {
        if let Ok(out) = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                   "Get-DnsClientCache | Select-Object -ExpandProperty Entry"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let d = line.trim().trim_end_matches('.');
                // Skip the header/underline rows PowerShell emits and anything
                // that is not plausibly a hostname.
                if d.len() > 3 && d.contains('.') && !d.starts_with('-')
                    && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
                {
                    domains.push(d.to_ascii_lowercase());
                }
            }
        }
    }

    domains.sort();
    domains.dedup();
    domains
}

#[cfg(not(target_os = "windows"))]
fn read_recent_dns_queries() -> Vec<String> {
    // Try systemd-resolved journal
    let mut domains = vec![];

    if let Ok(out) = std::process::Command::new("journalctl")
        .args(["-u", "systemd-resolved", "--since", "30 seconds ago", "--no-pager", "-q"])
        .output()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if line.contains("QUERY") || line.contains("query[A]") {
                if let Some(domain) = extract_domain_from_log(line) {
                    domains.push(domain);
                }
            }
        }
    }

    // Fallback: parse /var/log/syslog for named/dnsmasq entries
    if domains.is_empty() {
        if let Ok(content) = std::fs::read_to_string("/var/log/syslog") {
            let _cutoff = Utc::now() - chrono::Duration::seconds(30);
            for line in content.lines().rev().take(1000) {
                if line.contains("query[") || line.contains("QUERY:") {
                    if let Some(domain) = extract_domain_from_log(line) {
                        domains.push(domain);
                    }
                }
            }
        }
    }

    domains
}

fn extract_domain_from_log(line: &str) -> Option<String> {
    // Parse "query[A] example.com from 1.2.3.4" style
    if let Some(start) = line.find("] ") {
        let rest = &line[start+2..];
        let domain = rest.split_whitespace().next()?;
        if domain.contains('.') && domain.len() > 3 {
            return Some(domain.trim_end_matches('.').to_string());
        }
    }
    None
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    for b in s.bytes() { freq[b as usize] += 1; }
    let len = s.len() as f64;
    freq.iter().filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum()
}

/// Byte-prefix of `s` up to `max` bytes, floored to a UTF-8 char boundary.
/// DNS query names come from resolver logs (attacker-influenceable), so
/// truncating for display goes through here — `&domain[..max]` would panic on a
/// multibyte char straddling the cut.
fn safe_prefix(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    &s[..end]
}

#[cfg(test)]
mod safe_prefix_tests {
    use super::safe_prefix;

    #[test]
    fn never_panics_on_multibyte_dns_name() {
        // A high-entropy label with multibyte chars across the 60-byte cut (the
        // DNS-tunneling display truncation) must not panic.
        let d = format!("{}é🚀.example.com", "a1b2c3".repeat(12));
        for n in 0..=d.len() + 4 {
            let p = safe_prefix(&d, n);
            assert!(d.starts_with(p));
            assert!(d.is_char_boundary(p.len()));
        }
        assert_eq!(safe_prefix("host", 60), "host");
    }
}

fn coefficient_of_variation(v: &[f64]) -> f64 {
    if v.len() < 2 { return 1.0; }
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    if mean == 0.0 { return 1.0; }
    let variance = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / v.len() as f64;
    variance.sqrt() / mean
}

fn is_known_good_ip(ip: &str) -> bool {
    // RFC-1918 private ranges and common CDN/DNS
    ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.16.")
        || ip.starts_with("172.17.") || ip.starts_with("172.18.") || ip.starts_with("172.19.")
        || ip.starts_with("172.2") || ip.starts_with("172.3") || ip.starts_with("127.")
        || ip == "8.8.8.8" || ip == "8.8.4.4" || ip == "1.1.1.1" || ip == "1.0.0.1"
}

fn is_cdn_domain(domain: &str) -> bool {
    let cdns = ["cloudflare.com", "fastly.com", "akamai", "amazonaws.com",
        "azureedge.net", "cloudfront.net", "googleapis.com", "gstatic.com"];
    cdns.iter().any(|c| domain.contains(c))
}

fn make_network_threat(
    agent_id: &str, hostname: &str,
    technique: &str, severity: Severity,
    name: String, desc: String, confidence: f32,
    iocs: Vec<IOC>,
) -> ThreatEvent {
    ThreatEvent {
        id: Uuid::new_v4().to_string(),
        agent_id: agent_id.to_string(), hostname: hostname.to_string(),
        timestamp: Utc::now(), severity, confidence,
        threat_name: name, description: desc,
        mitre_tactics:    vec!["command_and_control".to_string()],
        mitre_techniques: vec![technique.to_string()],
        matched_rules:    vec!["network_monitor".to_string()],
        raw_event_ids: vec![], chain: None, iocs,
        suggested_action: ResponseAction::Alert,
        llm_analysis: None, auto_generated_rule: None,
    }
}
