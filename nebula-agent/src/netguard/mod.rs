#![allow(dead_code)]
// src/netguard/mod.rs — Host network self-protection.
//
// GOAL: protect THIS host from network-based attacks — not monitor a network.
// This is the connection-level / reputation-driven alternative to packet-
// inspection IDS (Suricata/Snort). It needs NO external dependency: it drives
// the host firewall (nftables/iptables/etc.) that's part of the base OS via the
// existing `firewall` module, and reuses the existing `reputation` data.
//
// THREE PROTECTION LAYERS:
//   1. Outbound C2/exfil blocking — when the host tries to reach a known-bad IP
//      (from the threat-intel blocklist), drop it at the kernel. Stops malware
//      already on the host from calling home, which is the highest-value control.
//   2. Inbound brute-force / scan auto-block (fail2ban-style) — repeated failed
//      auth or connection floods from one source IP within a window -> temp block.
//   3. Connection rules — operator-defined rules over the 5-tuple + direction +
//      reputation + rate that compile to firewall drop rules.
//
// All blocks are tracked with an expiry so they can be auto-lifted, and every
// action is reported as a ThreatEvent through the normal pipeline.

use crate::firewall::Firewall;
use crate::types::{ThreatEvent, Severity, ResponseAction};
use std::collections::HashMap;
use std::sync::Arc;
use std::net::IpAddr;
use chrono::{DateTime, Utc};
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Direction { Inbound, Outbound, Both }

#[derive(Debug, Clone)]
pub struct ConnRule {
    pub name:        String,
    pub direction:   Direction,
    pub port:        Option<u16>,
    pub proto:       Option<String>,
    pub require_bad_reputation: bool,
    pub rate_limit:  Option<(u32, u64)>,
    pub action:      ConnAction,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnAction { Block, Alert }

#[derive(Debug, Clone)]
struct ActiveBlock {
    ip:         String,
    reason:     String,
    blocked_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
struct FailTracker {
    count:      u32,
    first_seen: DateTime<Utc>,
    last_seen:  DateTime<Utc>,
}

pub struct NetGuard {
    agent_id:   String,
    hostname:   String,
    enabled:    bool,
    enforce:    bool,
    firewall:   Firewall,
    rules:      Vec<ConnRule>,
    blocks:     Arc<Mutex<HashMap<String, ActiveBlock>>>,
    failures:   Arc<Mutex<HashMap<String, FailTracker>>>,
    bf_threshold:   u32,
    bf_window_secs: u64,
    bf_ban_secs:    u64,
}

impl NetGuard {
    pub fn new(agent_id: &str, hostname: &str, enforce: bool, firewall: Firewall) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            hostname: hostname.to_string(),
            enabled: true,
            enforce,
            firewall,
            rules: Self::default_rules(),
            blocks: Arc::new(Mutex::new(HashMap::new())),
            failures: Arc::new(Mutex::new(HashMap::new())),
            bf_threshold: 5,
            bf_window_secs: 300,
            bf_ban_secs: 3600,
        }
    }

    fn default_rules() -> Vec<ConnRule> {
        vec![
            ConnRule {
                name: "Block outbound to known-bad IP (C2/exfil)".into(),
                direction: Direction::Outbound, port: None, proto: None,
                require_bad_reputation: true, rate_limit: None, action: ConnAction::Block,
            },
            ConnRule {
                name: "Block inbound from known-bad IP".into(),
                direction: Direction::Inbound, port: None, proto: None,
                require_bad_reputation: true, rate_limit: None, action: ConnAction::Block,
            },
        ]
    }

    pub fn add_rule(&mut self, rule: ConnRule) { self.rules.push(rule); }

    fn valid_ip(ip: &str) -> bool { ip.parse::<IpAddr>().is_ok() }

    /// IPs we must NEVER automatically firewall-block, because a false positive
    /// here causes an outage rather than mere alert noise: loopback, RFC1918 /
    /// ULA private space, link-local, unspecified, broadcast and multicast.
    /// These cover the host's own gateways, internal service mesh, monitoring
    /// collectors and DHCP — exactly the addresses a brute-force or reputation
    /// false positive would otherwise sever. Detection/alerting still happens;
    /// only the auto-block action is withheld.
    fn protected_ip(ip: &str) -> bool {
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local()
                    || v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast()
            }
            Ok(IpAddr::V6(v6)) => {
                let seg0 = v6.segments()[0];
                v6.is_loopback() || v6.is_unspecified() || v6.is_multicast()
                    || (seg0 & 0xfe00) == 0xfc00   // ULA fc00::/7
                    || (seg0 & 0xffc0) == 0xfe80    // link-local fe80::/10
            }
            Err(_) => false,
        }
    }

    pub async fn evaluate_connection(
        &self,
        peer_ip: &str,
        port: u16,
        proto: &str,
        direction: Direction,
        bad_reputation: bool,
    ) -> Option<ThreatEvent> {
        if !self.enabled || !Self::valid_ip(peer_ip) { return None; }

        for rule in &self.rules {
            if rule.direction != Direction::Both && rule.direction != direction { continue; }
            if let Some(p) = rule.port { if p != port { continue; } }
            if let Some(ref pr) = rule.proto { if !pr.eq_ignore_ascii_case(proto) { continue; } }
            if rule.require_bad_reputation && !bad_reputation { continue; }

            let blocked = matches!(rule.action, ConnAction::Block) && self.enforce
                && !Self::protected_ip(peer_ip);
            if blocked {
                self.block(peer_ip, &rule.name, Some(self.bf_ban_secs)).await;
            }
            return Some(self.mk_event(
                if blocked { format!("Blocked {} connection: {}", dir_str(direction), peer_ip) }
                else { format!("Suspicious {} connection: {}", dir_str(direction), peer_ip) },
                format!("Rule '{}' matched {}:{} ({}). reputation_bad={} action={}",
                    rule.name, peer_ip, port, proto, bad_reputation,
                    if blocked { "BLOCKED" } else if self.enforce { "alert" } else { "alert (detect mode)" }),
                if blocked { Severity::High } else { Severity::Medium },
                if blocked { 85.0 } else { 60.0 },
                peer_ip,
                if blocked { ResponseAction::BlockIp(peer_ip.to_string()) } else { ResponseAction::Monitor },
            ));
        }
        None
    }

    pub async fn record_failure(&self, src_ip: &str, context: &str) -> Option<ThreatEvent> {
        if !self.enabled || !Self::valid_ip(src_ip) { return None; }
        let now = Utc::now();
        let mut fired = false;
        {
            let mut f = self.failures.lock().await;
            let entry = f.entry(src_ip.to_string()).or_insert(FailTracker {
                count: 0, first_seen: now, last_seen: now,
            });
            if (now - entry.last_seen).num_seconds() as u64 > self.bf_window_secs {
                entry.count = 0; entry.first_seen = now;
            }
            entry.count += 1;
            entry.last_seen = now;
            if entry.count >= self.bf_threshold { fired = true; entry.count = 0; }
        }
        if !fired { return None; }

        let blocked = self.enforce && !Self::protected_ip(src_ip);
        if blocked { self.block(src_ip, &format!("brute-force: {}", context), Some(self.bf_ban_secs)).await; }
        Some(self.mk_event(
            format!("Brute-force source auto-blocked: {}", src_ip),
            format!("{} reached {} failed attempts within {}s ({}). {}",
                src_ip, self.bf_threshold, self.bf_window_secs, context,
                if blocked { format!("Blocked for {}s.", self.bf_ban_secs) } else { "Detect mode - not blocked.".to_string() }),
            Severity::High, 80.0, src_ip,
            if blocked { ResponseAction::BlockIp(src_ip.to_string()) } else { ResponseAction::Monitor },
        ))
    }

    async fn block(&self, ip: &str, reason: &str, ttl_secs: Option<u64>) {
        if !Self::valid_ip(ip) { return; }
        // Defense in depth: even if a caller's guard is missed, never let an
        // internal/loopback/private address reach the firewall backend.
        if Self::protected_ip(ip) {
            warn!("NetGuard refusing to auto-block protected/internal IP {} ({})", ip, reason);
            return;
        }
        {
            let blocks = self.blocks.lock().await;
            if blocks.contains_key(ip) { return; }
        }
        match self.firewall.block_ip(ip).await {
            Ok(_) => {
                let expires_at = ttl_secs.map(|s| Utc::now() + chrono::Duration::seconds(s as i64));
                self.blocks.lock().await.insert(ip.to_string(), ActiveBlock {
                    ip: ip.to_string(), reason: reason.to_string(),
                    blocked_at: Utc::now(), expires_at,
                });
                warn!("NetGuard blocked {} ({}) backend={}", ip, reason, self.firewall.backend);
            }
            Err(e) => warn!("NetGuard block of {} failed: {}", ip, e),
        }
    }

    pub async fn sweep_expired(&self) {
        let now = Utc::now();
        let expired: Vec<String> = {
            let blocks = self.blocks.lock().await;
            blocks.values()
                .filter(|b| b.expires_at.map(|e| e <= now).unwrap_or(false))
                .map(|b| b.ip.clone()).collect()
        };
        for ip in expired {
            if self.firewall.unblock_ip(&ip).await.is_ok() {
                self.blocks.lock().await.remove(&ip);
                info!("NetGuard lifted expired block on {}", ip);
            }
        }
    }

    pub async fn active_blocks(&self) -> Vec<(String, String)> {
        self.blocks.lock().await.values()
            .map(|b| (b.ip.clone(), b.reason.clone())).collect()
    }

    fn mk_event(&self, name: String, desc: String, sev: Severity, conf: f32,
                ip: &str, action: ResponseAction) -> ThreatEvent {
        ThreatEvent {
            id: Uuid::new_v4().to_string(),
            agent_id: self.agent_id.clone(),
            hostname: self.hostname.clone(),
            timestamp: Utc::now(),
            severity: sev,
            confidence: conf,
            threat_name: name,
            description: desc,
            mitre_tactics: vec!["command_and_control".to_string()],
            mitre_techniques: vec!["T1071".to_string()],
            matched_rules: vec!["netguard".to_string()],
            raw_event_ids: vec![format!("netguard:{}", ip)],
            chain: None,
            iocs: vec![],
            suggested_action: action,
            llm_analysis: None,
            auto_generated_rule: None,
        }
    }
}

fn dir_str(d: Direction) -> &'static str {
    match d { Direction::Inbound => "inbound", Direction::Outbound => "outbound", Direction::Both => "" }
}

#[cfg(test)]
mod protected_tests {
    use super::NetGuard;

    #[test]
    fn internal_addresses_are_protected() {
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.9.9",
                   "169.254.1.1", "0.0.0.0", "255.255.255.255", "224.0.0.1",
                   "::1", "fe80::1", "fc00::1", "fd12:3456::1"] {
            assert!(NetGuard::protected_ip(ip), "{ip} must be protected");
        }
    }

    #[test]
    fn public_addresses_are_blockable() {
        for ip in ["8.8.8.8", "1.1.1.1", "203.0.113.7", "2606:4700:4700::1111"] {
            assert!(!NetGuard::protected_ip(ip), "{ip} must be blockable");
        }
    }

    #[test]
    fn garbage_is_not_protected() {
        assert!(!NetGuard::protected_ip("not-an-ip"));
    }
}
