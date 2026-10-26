//! # nebula-gossip
//!
//! The shared GOSSIP protocol for the NebulaSentinel ecosystem. One envelope,
//! many transports: agents, Cortex, Dopamine, Nexus, Red Nebula, and Synapse all
//! emit and consume byte-identical [`Envelope`]s regardless of whether the
//! message travels over agent↔agent UDP, the Nexus poll cycle, or Synapse's
//! cross-customer channel.
//!
//! This crate is the single source of truth for the wire format described in
//! `GOSSIP_ENVELOPE_SPEC.md`. It provides:
//!   - [`Envelope`] — the universal message wrapper (identity, provenance, trust).
//!   - [`MsgType`] + payloads ([`payload::IocPayload`], [`payload::AtcPayload`]).
//!   - Deterministic [`Envelope::dedup_key`] derivation for collapsing duplicates.
//!   - ed25519 signing/verification (feature `signing`, on by default).
//!
//! ## Minimal example
//! ```
//! use nebula_gossip::{Envelope, Origin, MsgType, Severity, payload::*};
//!
//! let env = Envelope::builder(
//!     MsgType::AtcObservable,
//!     Origin::component("nebula-agent", "agent-7f3a"),
//! )
//! .confidence(40)
//! .severity(Severity::Info)
//! .ttl_secs(604_800)
//! .payload_atc(AtcPayload::observable("new_process_hash", "First-seen SHA-256"))
//! .build();
//!
//! assert_eq!(env.msg_type, MsgType::AtcObservable);
//! assert!(env.dedup_key.starts_with("atc:"));
//! ```

pub mod msgtype;
pub mod payload;
#[cfg(feature = "signing")]
pub mod signing;

pub use msgtype::MsgType;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Current envelope schema string. Bump on breaking wire changes.
pub const SCHEMA: &str = "gossip/1";

/// Severity scale shared by every message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Severity {
    fn default() -> Self { Severity::Info }
}

/// Which ecosystem component originated or relayed a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Component {
    NebulaAgent,
    Cortex,
    Dopamine,
    Nexus,
    RedNebula,
    Synapse,
    /// Forward-compatibility: an unknown component name is preserved verbatim
    /// rather than rejected, so a newer component doesn't break older parsers.
    #[serde(untagged)]
    Other(String),
}

impl Component {
    pub fn as_str(&self) -> &str {
        match self {
            Component::NebulaAgent => "nebula-agent",
            Component::Cortex => "cortex",
            Component::Dopamine => "dopamine",
            Component::Nexus => "nexus",
            Component::RedNebula => "red-nebula",
            Component::Synapse => "synapse",
            Component::Other(s) => s.as_str(),
        }
    }
    pub fn parse(s: &str) -> Component {
        match s {
            "nebula-agent" => Component::NebulaAgent,
            "cortex" => Component::Cortex,
            "dopamine" => Component::Dopamine,
            "nexus" => Component::Nexus,
            "red-nebula" => Component::RedNebula,
            "synapse" => Component::Synapse,
            other => Component::Other(other.to_string()),
        }
    }
}

/// Who originated a message. `tenant` is the hard isolation boundary; Synapse may
/// only cross it for explicitly shareable indicator types (see spec §6a).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    pub component: Component,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
}

impl Origin {
    /// Convenience for the common single-tenant case.
    pub fn component(component: &str, id: &str) -> Origin {
        Origin { component: Component::parse(component), id: id.to_string(), tenant: None, site: None }
    }
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Origin {
        self.tenant = Some(tenant.into());
        self
    }
    pub fn with_site(mut self, site: impl Into<String>) -> Origin {
        self.site = Some(site.into());
        self
    }
}

/// A signed record appended by each relayer. Lets a receiver trace the path a
/// message took and detect untrusted relay hops / poisoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relay {
    pub component: Component,
    pub id: String,
    pub ts: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// Cross-source corroboration: how many *independent* origins reported the same
/// `dedup_key`, and the first/last time it was seen anywhere. The Nexus updates
/// this as it merges duplicates — higher counts mean higher trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Corroboration {
    pub independent_sources: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl Corroboration {
    pub fn single(now: DateTime<Utc>) -> Corroboration {
        Corroboration { independent_sources: 1, first_seen: now, last_seen: now }
    }
}

/// The ed25519 signature over the canonical envelope (see `signing` module).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub alg: String,        // "ed25519"
    pub key_id: String,     // which key signed (rotation-friendly)
    pub value: String,      // base64 signature
}

/// The universal GOSSIP message. Every component emits and consumes this exact
/// shape. `payload` is a free-form JSON value whose schema is determined by
/// `msg_type` — use the typed accessors in [`payload`] to read/write it safely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    // ── Identity ───────────────────────────────────────────────
    pub schema: String,
    pub msg_id: String,
    pub msg_type: MsgType,
    pub dedup_key: String,

    // ── Provenance ─────────────────────────────────────────────
    pub origin: Origin,
    #[serde(default)]
    pub relays: Vec<Relay>,
    pub corroboration: Corroboration,

    // ── Trust ──────────────────────────────────────────────────
    pub confidence: u8,      // 0–100
    #[serde(default)]
    pub severity: Severity,
    pub ttl_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<Signature>,

    // ── Timing ─────────────────────────────────────────────────
    pub created_at: DateTime<Utc>,

    // ── Payload ────────────────────────────────────────────────
    pub payload: serde_json::Value,
}

impl Envelope {
    /// Start building an envelope. Fills schema/msg_id/created_at/corroboration
    /// with sensible defaults; you set type/origin/payload and optionally tune
    /// confidence, severity, and TTL.
    pub fn builder(msg_type: MsgType, origin: Origin) -> EnvelopeBuilder {
        EnvelopeBuilder::new(msg_type, origin)
    }

    /// Whether this message has expired relative to `now` (created_at + ttl).
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        let age = now.signed_duration_since(self.created_at).num_seconds();
        age >= 0 && (age as u64) >= self.ttl_secs
    }

    /// Append a relay record (call when forwarding a message you received).
    /// Unsigned — prefer `add_relay_signed` so receivers can validate the hop.
    pub fn add_relay(&mut self, component: Component, id: impl Into<String>, now: DateTime<Utc>) {
        self.relays.push(Relay { component, id: id.into(), ts: now, sig: None });
    }

    /// Append a relay record and **sign** it with the relayer's key, so a
    /// receiver can verify (via `signing::verify_relay`) that this hop was added
    /// by the claimed relayer and bound to this message.
    #[cfg(feature = "signing")]
    pub fn add_relay_signed(&mut self, component: Component, id: impl Into<String>,
                            now: DateTime<Utc>, kp: &crate::signing::Keypair) {
        let mut relay = Relay { component, id: id.into(), ts: now, sig: None };
        crate::signing::sign_relay(&self.msg_id, &mut relay, kp);
        self.relays.push(relay);
    }

    /// Parse from JSON bytes (e.g. a UDP datagram or HTTP body).
    pub fn from_slice(bytes: &[u8]) -> Result<Envelope, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Serialize to JSON bytes for transport.
    pub fn to_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

/// Fluent builder for [`Envelope`]. Derives the `dedup_key` from the payload when
/// possible, so callers don't have to construct it by hand.
pub struct EnvelopeBuilder {
    msg_type: MsgType,
    origin: Origin,
    confidence: u8,
    severity: Severity,
    ttl_secs: u64,
    payload: serde_json::Value,
    dedup_key: Option<String>,
    created_at: DateTime<Utc>,
}

impl EnvelopeBuilder {
    fn new(msg_type: MsgType, origin: Origin) -> Self {
        EnvelopeBuilder {
            msg_type,
            origin,
            confidence: 50,
            severity: Severity::Info,
            ttl_secs: 86_400,
            payload: serde_json::Value::Null,
            dedup_key: None,
            created_at: Utc::now(),
        }
    }
    pub fn confidence(mut self, c: u8) -> Self { self.confidence = c.min(100); self }
    pub fn severity(mut self, s: Severity) -> Self { self.severity = s; self }
    pub fn ttl_secs(mut self, t: u64) -> Self { self.ttl_secs = t; self }
    pub fn created_at(mut self, ts: DateTime<Utc>) -> Self { self.created_at = ts; self }
    /// Override the auto-derived dedup key.
    pub fn dedup_key(mut self, k: impl Into<String>) -> Self { self.dedup_key = Some(k.into()); self }

    /// Set a raw JSON payload (advanced; prefer the typed setters below).
    pub fn payload_json(mut self, v: serde_json::Value) -> Self { self.payload = v; self }

    /// Set an IOC payload; auto-derives dedup_key as `ioc:<type>:<value>`.
    pub fn payload_ioc(mut self, p: payload::IocPayload) -> Self {
        self.dedup_key.get_or_insert_with(|| p.dedup_key());
        self.payload = serde_json::to_value(p).unwrap_or(serde_json::Value::Null);
        self
    }

    /// Set an ATC payload; auto-derives dedup_key from the origin + category.
    pub fn payload_atc(mut self, p: payload::AtcPayload) -> Self {
        let key = p.dedup_key(&self.origin.id);
        self.dedup_key.get_or_insert(key);
        self.payload = serde_json::to_value(p).unwrap_or(serde_json::Value::Null);
        self
    }

    pub fn build(self) -> Envelope {
        let dedup_key = self.dedup_key.unwrap_or_else(|| {
            // Fallback: hash the payload so identical payloads collapse.
            format!("{}:{}", self.msg_type.as_str(), payload::short_hash(&self.payload.to_string()))
        });
        Envelope {
            schema: SCHEMA.to_string(),
            msg_id: new_msg_id(),
            msg_type: self.msg_type,
            dedup_key,
            origin: self.origin,
            relays: Vec::new(),
            corroboration: Corroboration::single(self.created_at),
            confidence: self.confidence,
            severity: self.severity,
            ttl_secs: self.ttl_secs,
            sig: None,
            created_at: self.created_at,
            payload: self.payload,
        }
    }
}

/// Time-sortable message ID. We use UUIDv4 with a timestamp prefix so IDs are
/// roughly orderable without requiring a ULID dependency. Format:
/// `<unix_millis_hex>-<uuid>`.
fn new_msg_id() -> String {
    let millis = Utc::now().timestamp_millis().max(0) as u64;
    format!("{:011x}-{}", millis, uuid::Uuid::new_v4())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{IocPayload, AtcPayload};

    #[test]
    fn ioc_envelope_dedup_key() {
        let env = Envelope::builder(MsgType::IocAlert, Origin::component("dopamine", "dop-1"))
            .payload_ioc(IocPayload::new("sha256", "abcd1234"))
            .build();
        assert_eq!(env.dedup_key, "ioc:sha256:abcd1234");
        assert_eq!(env.schema, "gossip/1");
        assert!(!env.msg_id.is_empty());
    }

    #[test]
    fn atc_observable_roundtrips() {
        let env = Envelope::builder(MsgType::AtcObservable, Origin::component("nebula-agent", "a1"))
            .confidence(40)
            .payload_atc(AtcPayload::observable("new_process_hash", "first seen"))
            .build();
        let bytes = env.to_vec().unwrap();
        let back = Envelope::from_slice(&bytes).unwrap();
        assert_eq!(back.msg_type, MsgType::AtcObservable);
        assert_eq!(back.confidence, 40);
        assert!(back.dedup_key.starts_with("atc:"));
    }

    #[test]
    fn expiry() {
        let now = Utc::now();
        let mut env = Envelope::builder(MsgType::AtcHealth, Origin::component("nexus", "n1"))
            .ttl_secs(120)
            .created_at(now - chrono::Duration::seconds(200))
            .payload_atc(AtcPayload::health("healthy"))
            .build();
        env.created_at = now - chrono::Duration::seconds(200);
        assert!(env.is_expired(now));
    }

    #[test]
    fn unknown_component_preserved() {
        let o = Origin::component("future-thing", "x");
        assert_eq!(o.component.as_str(), "future-thing");
    }
}
