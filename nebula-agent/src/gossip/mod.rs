#![allow(dead_code)]
// src/gossip/mod.rs — GOSSIP protocol: inter-agent threat awareness
//
// New in v4: peer sighting reports
//   When agent A receives a GOSSIP heartbeat from agent B, it tells Nexus
//   "I can see agent B". Nexus uses this to differentiate:
//     - Agent unreachable to Nexus but alive on the network (stale, not offline)
//     - Agent truly unreachable by anyone (offline)

use crate::config::GossipConfig;
use crate::types::{GossipMessage, GossipMsgType, IOC};

// Bridge to the canonical nebula-gossip envelope (ecosystem-wide wire format).
pub mod envelope_bridge;
use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{info, warn, debug};
use std::sync::Arc;
use dashmap::DashMap;
use chrono::Utc;
use serde::Serialize;

// ── Peer registry ──────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub agent_id:   String,
    pub hostname:   String,
    pub addr:       String,
    pub last_seen:  chrono::DateTime<Utc>,
    pub threat_score: f32,
}

// Sent to Nexus when we receive a GOSSIP message from a peer
#[derive(Serialize)]
struct GossipPeerReport {
    reporter_agent_id:   String,
    reporter_hostname:   String,
    seen_agent_id:       String,
    seen_hostname:       String,
    last_gossip_contact: String,
    gossip_addr:         String,
}

pub struct GossipEngine {
    config:     GossipConfig,
    agent_id:   String,
    hostname:   String,
    peers:      Arc<DashMap<String, PeerInfo>>,
    pub ioc_blacklist: Arc<DashMap<String, IOC>>,
    // Nexus URL and API key for peer sighting reports
    nexus_url:  Option<String>,
    nexus_key:  Option<String>,
    // Shared TLS policy for Nexus HTTP calls (cert pin path + verify flag).
    nexus_ca_path:    Option<String>,
    nexus_tls_verify: bool,
    // Resolved AES-256-GCM key for GOSSIP UDP encryption (Some only when
    // config.encryption is true and a valid 32-byte key was configured).
    enc_key:          Option<[u8; 32]>,
    // Persistent ed25519 keypair used to sign outgoing envelopes (key_id =
    // agent_id). The public key is registered with the Nexus so it can verify.
    keypair:          Arc<nebula_gossip::signing::Keypair>,
    // Live-adjustable broadcast interval (seconds). Shared so the Nexus can
    // change the GOSSIP frequency without restarting the agent — the heartbeat
    // loop reads this each iteration.
    pub interval_secs: Arc<std::sync::atomic::AtomicU64>,
    // Dedup cache: IOC value → last time we broadcast it. Prevents re-sending
    // the same IOC every detection cycle (the "sends same IOCs over and over"
    // bug). An IOC is re-broadcast only after REBROADCAST_TTL_SECS so genuinely
    // persistent threats still refresh occasionally, without flooding.
    broadcast_cache: Arc<DashMap<String, chrono::DateTime<Utc>>>,
    // Cognition state for the atc.health heartbeat. The agent updates these as
    // the LLM comes up/down and the collector backend is chosen, so the health
    // envelope reports whether ATC is actually enriching or silently degraded.
    pub llm_available: Arc<std::sync::atomic::AtomicBool>,
    pub collector_backend: Arc<std::sync::Mutex<String>>,
    pub llm_model: Arc<std::sync::Mutex<Option<String>>>,
}

// Re-broadcast the same IOC at most once per this window.
const REBROADCAST_TTL_SECS: i64 = 3600;

// ── GOSSIP UDP encryption (AES-256-GCM) ───────────────────────
/// Load the agent's persistent gossip signing key from `path`, or generate one
/// and persist it (hex-encoded 32-byte secret, mode 0600 on unix). key_id is the
/// agent_id so the Nexus can associate the public key with the agent.
fn load_or_create_keypair(agent_id: &str, path: &str) -> nebula_gossip::signing::Keypair {
    use nebula_gossip::signing::Keypair;
    if let Ok(s) = std::fs::read_to_string(path) {
        if let Ok(v) = hex::decode(s.trim()) {
            if v.len() == 32 {
                let mut b = [0u8; 32];
                b.copy_from_slice(&v);
                return Keypair::from_secret_bytes(&b, agent_id);
            }
        }
    }
    let kp = Keypair::generate(agent_id);
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if std::fs::write(path, hex::encode(kp.signing.to_bytes())).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
    } else {
        warn!("🔑 GOSSIP: could not persist signing key to {} (using an ephemeral key this run)", path);
    }
    kp
}

/// Resolve the datagram encryption key from config: Some only when encryption
/// is enabled AND a valid 64-hex-char (32-byte) key is configured.
fn resolve_gossip_key(cfg: &crate::config::GossipConfig) -> Option<[u8; 32]> {
    if !cfg.encryption { return None; }
    let hex = cfg.encryption_key.as_deref()?.trim();
    if hex.len() != 64 { return None; }
    let mut k = [0u8; 32];
    for i in 0..32 {
        k[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(k)
}

/// Encrypt a datagram: returns `nonce(12) || ciphertext || tag(16)`.
fn gossip_seal(key: &[u8; 32], plaintext: &[u8]) -> Option<Vec<u8>> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
    use ring::rand::{SecureRandom, SystemRandom};
    let sealing = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).ok()?);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce_bytes).ok()?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    sealing.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out).ok()?;
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&in_out);
    Some(out)
}

/// Decrypt a datagram produced by `gossip_seal`. Returns None on any failure
/// (truncated, wrong key, tampered) so the caller can drop the packet.
fn gossip_open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
    if blob.len() < NONCE_LEN { return None; }
    let (nb, ct) = blob.split_at(NONCE_LEN);
    let opening = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).ok()?);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(nb);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = ct.to_vec();
    let pt = opening.open_in_place(nonce, Aad::empty(), &mut in_out).ok()?;
    Some(pt.to_vec())
}

impl GossipEngine {
    pub fn new(
        config:    GossipConfig,
        agent_id:  &str,
        hostname:  &str,
        nexus_url: Option<String>,
        nexus_key: Option<String>,
        nexus_ca_path:    Option<String>,
        nexus_tls_verify: bool,
    ) -> Self {
        info!("📡 GOSSIP engine: enabled={} port={} discovery={}",
            config.enabled, config.port, config.discovery);
        info!("   GOSSIP = Generative Observable Security Sharing Intelligence Protocol");
        let interval_secs = Arc::new(std::sync::atomic::AtomicU64::new(
            config.gossip_interval_secs.max(1)));
        let enc_key = resolve_gossip_key(&config);
        if config.encryption && enc_key.is_none() {
            warn!("📡 GOSSIP: encryption=true but no valid encryption_key set — sending PLAINTEXT");
        } else if enc_key.is_some() {
            info!("🔒 GOSSIP: AES-256-GCM datagram encryption enabled");
        }
        let keypair = Arc::new(load_or_create_keypair(agent_id, "/var/lib/nebula/gossip_ed25519.key"));
        info!("🔑 GOSSIP: envelope signing key {} (pubkey {}…)",
            agent_id, &keypair.public_b64()[..keypair.public_b64().len().min(12)]);
        Self {
            config,
            agent_id:  agent_id.to_string(),
            hostname:  hostname.to_string(),
            peers:     Arc::new(DashMap::new()),
            ioc_blacklist: Arc::new(DashMap::new()),
            nexus_url,
            nexus_key,
            nexus_ca_path,
            nexus_tls_verify,
            enc_key,
            keypair,
            interval_secs,
            broadcast_cache: Arc::new(DashMap::new()),
            llm_available: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            collector_backend: Arc::new(std::sync::Mutex::new("procmon".to_string())),
            llm_model: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Update the broadcast interval live (applied on the next heartbeat tick).
    pub fn set_interval(&self, secs: u64) {
        self.interval_secs.store(secs.max(1), std::sync::atomic::Ordering::Relaxed);
        info!("📡 GOSSIP broadcast interval updated to {}s (live)", secs.max(1));
    }

    /// Hex-encoded ed25519 public key for this agent, registered with the Nexus
    /// so it can verify the agent's signed envelopes.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.keypair.public_bytes())
    }

    /// Number of IOCs currently in the shared blocklist (for the local status UI).
    pub fn ioc_count(&self) -> usize {
        self.ioc_blacklist.len()
    }

    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled {
            info!("GOSSIP disabled by config");
            return Ok(());
        }

        let bind = format!("{}:{}", self.config.bind_addr, self.config.port);
        info!("📡 GOSSIP listening on {}", bind);

        let socket      = Arc::new(UdpSocket::bind(&bind).await?);
        let peers       = self.peers.clone();
        let ioc_bl      = self.ioc_blacklist.clone();
        let agent_id    = self.agent_id.clone();
        let hostname    = self.hostname.clone();
        let nexus_url   = self.nexus_url.clone();
        let nexus_key   = self.nexus_key.clone();

        // ── Receive loop ───────────────────────────────────────
        let recv_sock = socket.clone();
        let enc_key = self.enc_key;   // Copy; also captured by the send loop below
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let http_client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build().unwrap();

            loop {
                match recv_sock.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        // Decrypt first when a PSK is configured; drop packets
                        // that fail authentication (wrong key / tampered).
                        let decoded: Option<Vec<u8>> = match enc_key {
                            Some(ref k) => gossip_open(k, &buf[..len]),
                            None        => Some(buf[..len].to_vec()),
                        };
                        let Some(bytes) = decoded else { continue };
                        if let Ok(msg) = serde_json::from_slice::<GossipMessage>(&bytes) {
                            // Update local peer table
                            let is_new_or_stale = handle_gossip_local(
                                &msg, src.to_string(), &peers, &ioc_bl
                            ).await;

                            // Report this sighting to Nexus so it can update
                            // the agent's last_seen and status there too.
                            // Only report on heartbeats (not every IOC flood).
                            if is_new_or_stale {
                                if let (Some(ref url), Some(ref key)) = (&nexus_url, &nexus_key) {
                                    let report = GossipPeerReport {
                                        reporter_agent_id:   agent_id.clone(),
                                        reporter_hostname:   hostname.clone(),
                                        seen_agent_id:       msg.from_agent.clone(),
                                        seen_hostname:       msg.from_hostname.clone(),
                                        last_gossip_contact: Utc::now().to_rfc3339(),
                                        gossip_addr:         src.to_string(),
                                    };
                                    let url_c = format!("{}/api/atc/gossip/peer_seen", url);
                                    let key_c = key.clone();
                                    let client_c = http_client.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = client_c.post(&url_c)
                                            .header("X-Api-Key", &key_c)
                                            .json(&report).send().await
                                        {
                                            debug!("GOSSIP peer report to Nexus failed: {}", e);
                                        } else {
                                            debug!("📡 GOSSIP: reported sighting of {} to Nexus",
                                                report.seen_hostname);
                                        }
                                    });
                                }
                            }
                        }
                    }
                    Err(e) => warn!("GOSSIP recv error: {}", e),
                }
            }
        });

        // ── Heartbeat broadcast loop ───────────────────────────
        let send_sock   = socket.clone();
        let peers2      = self.peers.clone();
        let agent_id2   = self.agent_id.clone();
        let hostname2   = self.hostname.clone();
        let interval2   = self.interval_secs.clone();
        let llm_avail2  = self.llm_available.clone();
        let backend2    = self.collector_backend.clone();
        let model2      = self.llm_model.clone();
        let nexus_url2  = self.nexus_url.clone();
        let nexus_key2  = self.nexus_key.clone();
        let keypair2    = self.keypair.clone();
        let http2       = crate::tls::nexus_http_builder(self.nexus_ca_path.as_deref(), self.nexus_tls_verify)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        tokio::spawn(async move {
            loop {
                // Read the (live-adjustable) interval each iteration so the
                // Nexus can change broadcast frequency without a restart.
                let secs = interval2.load(std::sync::atomic::Ordering::Relaxed).max(1);
                tokio::time::sleep(tokio::time::Duration::from_secs(secs)).await;
                let hb = GossipMessage {
                    from_agent:    agent_id2.clone(),
                    from_hostname: hostname2.clone(),
                    timestamp:     Utc::now(),
                    msg_type:      GossipMsgType::Heartbeat,
                    payload:       serde_json::json!({"status": "healthy"}),
                };
                if let Ok(data) = serde_json::to_vec(&hb) {
                    let wire = match enc_key {
                        Some(ref k) => match gossip_seal(k, &data) { Some(c) => c, None => continue },
                        None        => data,
                    };
                    for peer in peers2.iter() {
                        let _ = send_sock.send_to(&wire, &peer.addr).await;
                    }
                }

                // Emit a canonical atc.health envelope to the Nexus. Its short
                // TTL (120s) means the Nexus treats SILENCE as the alert, and
                // cognition.mode reveals a silently-degraded (LLM-down) agent.
                if let Some(ref url) = nexus_url2 {
                    let llm_up = llm_avail2.load(std::sync::atomic::Ordering::Relaxed);
                    let backend = backend2.lock().map(|b| b.clone()).unwrap_or_else(|_| "unknown".into());
                    let model = model2.lock().ok().and_then(|m| m.clone());
                    let mut env = envelope_bridge::health_envelope(
                        &agent_id2,
                        if llm_up { "healthy" } else { "degraded" },
                        llm_up, model, &backend,
                    );
                    let _ = nebula_gossip::signing::sign(&mut env, &keypair2);
                    if let Ok(body) = env.to_vec() {
                        let mut req = http2.post(format!("{}/api/atc/gossip/envelope", url))
                            .header("content-type", "application/json")
                            .body(body);
                        if let Some(ref k) = nexus_key2 {
                            req = req.header("authorization", format!("Bearer {}", k));
                        }
                        // Log outcome so envelope-delivery problems are diagnosable
                        // rather than silently swallowed (this is what makes the
                        // Ecosystem tab populate — if it's empty, the reason shows
                        // here).
                        match req.send().await {
                            Ok(resp) if resp.status().is_success() => {
                                tracing::debug!("📡 GOSSIP: health envelope delivered to Nexus");
                            }
                            Ok(resp) => {
                                tracing::warn!("📡 GOSSIP: Nexus rejected health envelope: HTTP {}", resp.status());
                            }
                            Err(e) => {
                                tracing::warn!("📡 GOSSIP: failed to POST health envelope to Nexus: {}", e);
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn broadcast_ioc(&self, ioc: &IOC) -> Result<()> {
        if !self.config.enabled || !self.config.share_iocs { return Ok(()); }

        // ── Validation: don't broadcast junk or obvious false positives ──
        if !Self::is_valid_ioc(ioc) {
            debug!("📡 GOSSIP: skipping invalid/unshareable IOC '{}'", ioc.value);
            return Ok(());
        }

        // ── Dedup: skip if we broadcast this exact IOC recently ──────────
        let now = Utc::now();
        if let Some(last) = self.broadcast_cache.get(&ioc.value) {
            if now.signed_duration_since(*last).num_seconds() < REBROADCAST_TTL_SECS {
                return Ok(());  // already shared within the TTL window
            }
        }
        self.broadcast_cache.insert(ioc.value.clone(), now);

        let msg = GossipMessage {
            from_agent:    self.agent_id.clone(),
            from_hostname: self.hostname.clone(),
            timestamp:     now,
            msg_type:      GossipMsgType::IocAlert,
            payload:       serde_json::to_value(ioc)?,
        };
        let data = serde_json::to_vec(&msg)?;
        let wire = match self.enc_key {
            Some(ref k) => gossip_seal(k, &data).unwrap_or(data),
            None        => data,
        };
        let sock = UdpSocket::bind(format!("{}:0", self.config.bind_addr)).await?;

        for peer in self.peers.iter() {
            let _ = sock.send_to(&wire, &peer.addr).await;
        }
        if self.peers.len() > 0 {
            info!("📡 GOSSIP: broadcast IOC {} to {} peers", ioc.value, self.peers.len());
        }
        // Also report the IOC to the Nexus so it appears in the fleet-wide
        // GOSSIP IOC view (best-effort; failure doesn't block peer broadcast).
        self.report_ioc_to_nexus(ioc).await;
        Ok(())
    }

    /// Validate an IOC before sharing — rejects values that are empty, private/
    /// reserved IPs, loopback, RFC1918 ranges, localhost, or obviously-benign
    /// hashes. This is the front line against false positives flooding the mesh.
    fn is_valid_ioc(ioc: &IOC) -> bool {
        let v = ioc.value.trim();
        if v.is_empty() || v.len() > 2048 { return false; }
        // IP-shaped values: reject private/reserved/loopback (not threat intel).
        if let Ok(ip) = v.parse::<std::net::IpAddr>() {
            return match ip {
                std::net::IpAddr::V4(a) => {
                    !(a.is_private() || a.is_loopback() || a.is_link_local()
                      || a.is_broadcast() || a.is_documentation() || a.is_unspecified()
                      || a.octets()[0] == 0)
                }
                std::net::IpAddr::V6(a) => !(a.is_loopback() || a.is_unspecified()),
            };
        }
        // Domains/hosts that are obviously local are not shareable intel.
        let lower = v.to_lowercase();
        if lower == "localhost" || lower.ends_with(".local") || lower.ends_with(".internal")
           || lower.ends_with(".lan") || lower.ends_with(".arpa") {
            return false;
        }
        // Hash-shaped values: must be a plausible hex digest length.
        if lower.chars().all(|c| c.is_ascii_hexdigit()) {
            let n = lower.len();
            if !(n == 32 || n == 40 || n == 64) { return false; }
            // All-zero hashes are placeholders, not real IOCs.
            if lower.chars().all(|c| c == '0') { return false; }
        }
        true
    }

    /// Report a discovered IOC to the Nexus for the fleet-wide view.
    async fn report_ioc_to_nexus(&self, ioc: &IOC) {
        let (Some(url), Some(key)) = (self.nexus_url.as_ref(), self.nexus_key.as_ref()) else { return };
        let client = crate::tls::nexus_http_builder(self.nexus_ca_path.as_deref(), self.nexus_tls_verify)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        // (1) Legacy direct IOC report — feeds the fleet-wide GOSSIP IOC list.
        let body = serde_json::json!({
            "value":             ioc.value,
            "ioc_type":          format!("{:?}", ioc.ioc_type),
            "source":            ioc.source,
            "confidence":        ioc.confidence,
            "from_hostname":     self.hostname,
            "reporter_hostname": self.hostname,
        });
        let endpoint = format!("{}/api/atc/gossip/ioc", url);
        let _ = client.post(&endpoint)
            .header("X-Api-Key", key)
            .json(&body)
            .timeout(std::time::Duration::from_secs(5))
            .send().await;

        // (2) Canonical GOSSIP envelope — feeds the Ecosystem stream. Previously
        // only health envelopes reached /api/atc/gossip/envelope, so the
        // Ecosystem tab never showed agent IOCs even though they were flowing
        // through the direct path above. Emitting the IOC as an envelope here is
        // what makes it appear in the ecosystem control-plane view.
        let mut env = envelope_bridge::ioc_to_envelope(ioc, &self.agent_id);
        let _ = nebula_gossip::signing::sign(&mut env, &self.keypair);
        if let Ok(env_body) = env.to_vec() {
            let ep = format!("{}/api/atc/gossip/envelope", url);
            match client.post(&ep)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", key))
                .body(env_body)
                .timeout(std::time::Duration::from_secs(5))
                .send().await
            {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => tracing::warn!("📡 GOSSIP: Nexus rejected IOC envelope: HTTP {}", resp.status()),
                Err(e) => tracing::warn!("📡 GOSSIP: failed to POST IOC envelope: {}", e),
            }
        }
    }

    pub fn register_peer(&self, agent_id: String, hostname: String, addr: String) {
        if agent_id == self.agent_id { return; }
        self.peers.insert(agent_id.clone(), PeerInfo {
            agent_id, hostname: hostname.clone(), addr: addr.clone(),
            last_seen: Utc::now(), threat_score: 0.0,
        });
        info!("📡 GOSSIP: registered peer {} @ {}", hostname, addr);
    }

    pub fn is_ioc_known(&self, value: &str) -> bool {
        self.ioc_blacklist.contains_key(value)
    }

    pub fn peer_count(&self) -> usize { self.peers.len() }

    /// Returns a snapshot of current peer health for logging/reporting.
    pub fn peer_summary(&self) -> Vec<(String, String, chrono::DateTime<Utc>)> {
        self.peers.iter()
            .map(|p| (p.agent_id.clone(), p.hostname.clone(), p.last_seen))
            .collect()
    }
}

/// Handle an incoming GOSSIP message and update the local peer table.
/// Returns true if this is a new peer or a peer we haven't seen recently
/// (threshold: 60s), meaning it's worth reporting to Nexus.
async fn handle_gossip_local(
    msg:    &GossipMessage,
    src:    String,
    peers:  &DashMap<String, PeerInfo>,
    ioc_bl: &DashMap<String, IOC>,
) -> bool {
    let now = Utc::now();
    let report_threshold = chrono::Duration::seconds(60);

    let should_report = match peers.get(&msg.from_agent) {
        None => true,  // new peer
        Some(p) => now.signed_duration_since(p.last_seen) > report_threshold,
    };

    peers.entry(msg.from_agent.clone()).and_modify(|p| {
        p.last_seen = now;
    }).or_insert(PeerInfo {
        agent_id:     msg.from_agent.clone(),
        hostname:     msg.from_hostname.clone(),
        addr:         src,
        last_seen:    now,
        threat_score: 0.0,
    });

    match msg.msg_type {
        GossipMsgType::IocAlert => {
            if let Ok(ioc) = serde_json::from_value::<IOC>(msg.payload.clone()) {
                info!("📡 GOSSIP: IOC {} from {} → local blacklist",
                    ioc.value, msg.from_hostname);
                ioc_bl.insert(ioc.value.clone(), ioc);
            }
        }
        GossipMsgType::ThreatScore => {
            if let Some(score) = msg.payload["score"].as_f64() {
                peers.entry(msg.from_agent.clone()).and_modify(|p| {
                    p.threat_score = score as f32;
                });
            }
        }
        GossipMsgType::Heartbeat => {
            debug!("GOSSIP: heartbeat from {}", msg.from_hostname);
        }
        _ => {}
    }

    should_report
}
