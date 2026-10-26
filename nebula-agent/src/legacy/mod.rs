// src/legacy/mod.rs — Legacy syslog bridge
// Formats: CEF (ArcSight), LEEF (QRadar), RFC5424 syslog
// Protocols: UDP, TCP, TLS

use crate::config::LegacyConfig;
use crate::types::{ThreatEvent, Severity};
use anyhow::Result;
use chrono::Utc;
use tracing::{info, debug, warn};
use tokio::net::UdpSocket;

pub struct LegacyBridge {
    config: LegacyConfig,
}

impl LegacyBridge {
    pub fn new(config: LegacyConfig) -> Self {
        if config.enabled {
            info!("📡 Legacy syslog bridge: format={} target={}", config.format, config.target);
        }
        Self { config }
    }

    pub async fn send_threat(&self, threat: &ThreatEvent) -> Result<()> {
        if !self.config.enabled { return Ok(()); }

        let msg = match self.config.format.as_str() {
            "cef"           => self.format_cef(threat),
            "leef"          => self.format_leef(threat),
            "syslog_rfc5424" => self.format_rfc5424(threat),
            _               => self.format_rfc5424(threat),
        };

        self.transmit(&msg).await
    }

    // ── CEF (Common Event Format — ArcSight) ───────────────────
    // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
    fn format_cef(&self, t: &ThreatEvent) -> String {
        let sev = match t.severity {
            Severity::Critical => "10",
            Severity::High     => "8",
            Severity::Medium   => "5",
            Severity::Low      => "3",
            _                  => "1",
        };
        let ts = Utc::now().format("%b %d %H:%M:%S").to_string();
        let ext = format!(
            "src={} dhost={} msg={} cs1={} cs1Label=MITRETechniques cs2={} cs2Label=Confidence",
            t.iocs.first().map(|i| i.value.as_str()).unwrap_or("0.0.0.0"),
            t.hostname,
            t.description.replace('|', "\\|").replace('=', "\\="),
            t.mitre_techniques.join(","),
            t.confidence as u32,
        );
        format!(
            "{} {} CEF:0|NebulaSentinel|NebulaSentinel Agent|0.3.0|{}|{}|{}|{}",
            ts, t.hostname,
            t.id,
            t.threat_name.replace('|', "\\|"),
            sev,
            ext,
        )
    }

    // ── LEEF (Log Event Extended Format — IBM QRadar) ──────────
    fn format_leef(&self, t: &ThreatEvent) -> String {
        let sev = match t.severity {
            Severity::Critical => "10",
            Severity::High     => "8",
            Severity::Medium   => "5",
            Severity::Low      => "3",
            _                  => "1",
        };
        let ts = Utc::now().format("%b %d %Y %H:%M:%S").to_string();
        format!(
            "LEEF:2.0|NebulaSentinel|Agent|0.3.0|{}|\tdevTime={}\tdevTimeFormat=MMM dd yyyy HH:mm:ss\tsev={}\tsrc={}\tdst={}\tcat={}\tusrName=unknown",
            t.threat_name,
            ts,
            sev,
            t.iocs.first().map(|i| i.value.as_str()).unwrap_or("0.0.0.0"),
            t.hostname,
            t.mitre_techniques.first().map(String::as_str).unwrap_or("T0000"),
        )
    }

    // ── RFC5424 syslog ─────────────────────────────────────────
    fn format_rfc5424(&self, t: &ThreatEvent) -> String {
        let pri = match t.severity {
            Severity::Critical => 2,  // CRIT
            Severity::High     => 3,  // ERR
            Severity::Medium   => 4,  // WARNING
            _                  => 6,  // INFO
        };
        let facility = 1; // user-level messages
        let priority = facility * 8 + pri;
        let ts = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        let structured = format!(
            "[nebula@52550 threatId=\"{}\" severity=\"{}\" confidence=\"{:.0}\" techniques=\"{}\"]",
            t.id, t.severity, t.confidence, t.mitre_techniques.join(",")
        );
        format!(
            "<{}>{} {} nebula-agent {} - {} {}",
            priority, ts, t.hostname, t.id, structured, t.description
        )
    }

    // ── Transmit ───────────────────────────────────────────────
    async fn transmit(&self, msg: &str) -> Result<()> {
        let target = &self.config.target;

        if target.starts_with("udp://") {
            let addr = target.trim_start_matches("udp://");
            let sock = UdpSocket::bind("0.0.0.0:0").await?;
            sock.send_to(msg.as_bytes(), addr).await?;
            debug!("syslog UDP → {}: {}...{}", addr, &msg[..20.min(msg.len())], "");
        } else if target.starts_with("tcp://") {
            let addr = target.trim_start_matches("tcp://");
            use tokio::io::AsyncWriteExt;
            let mut stream = tokio::net::TcpStream::connect(addr).await?;
            stream.write_all(format!("{}\n", msg).as_bytes()).await?;
            debug!("syslog TCP → {}", addr);
        } else {
            // Local syslog socket
            warn!("Legacy: unknown target format: {}", target);
        }
        Ok(())
    }
}
