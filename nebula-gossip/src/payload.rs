//! Typed payloads for the GOSSIP envelope. The envelope's `payload` field is a
//! free-form JSON value whose schema is keyed to `msg_type`; these structs are
//! the canonical shapes so every component reads/writes them identically.
//!
//! Two payloads matter most and are fully typed here:
//!   - [`IocPayload`]  — the shared indicator schema (`ioc.alert` / `ioc.false_positive`).
//!   - [`AtcPayload`]  — the three ATC tiers (`atc.observable` / `atc.alert` / `atc.health`).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Short hex hash of a string — used to derive a dedup key from an arbitrary
/// payload when no natural key exists. 16 hex chars (64 bits) is plenty for
/// collision-avoidance within a dedup window.
pub fn short_hash(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(16);
    for b in digest.iter().take(8) {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

// ───────────────────────────── IOC payload ─────────────────────────────

/// What a receiver MAY do with an indicator. Advisory, not mandatory — the
/// `auto_enforce` flag gates whether action can be taken without human review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enforcement {
    /// observe | alert | block | quarantine
    pub recommended_action: String,
    /// May a receiver act WITHOUT human review? Cross-tenant defaults to false.
    pub auto_enforce: bool,
    /// same_host | same_tenant | ecosystem
    pub scope: String,
}

impl Default for Enforcement {
    fn default() -> Self {
        Enforcement { recommended_action: "alert".into(), auto_enforce: false, scope: "same_tenant".into() }
    }
}

/// Optional context explaining why something is an IOC.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IocContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub malware_family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_techniques: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_chain_phase: Option<String>,
}

/// The single IOC schema every component uses. This is what makes a Dopamine
/// honeypot hit and an agent detection look identical on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IocPayload {
    /// md5|sha1|sha256|ipv4|ipv6|domain|url|file_path|process_name|registry_key|yara_rule|ja3|user_agent|email
    pub ioc_type: String,
    pub value: String,
    #[serde(default)]
    pub context: IocContext,
    #[serde(default)]
    pub enforcement: Enforcement,
}

impl IocPayload {
    pub fn new(ioc_type: &str, value: &str) -> IocPayload {
        IocPayload {
            ioc_type: ioc_type.to_string(),
            value: value.to_string(),
            context: IocContext::default(),
            enforcement: Enforcement::default(),
        }
    }
    pub fn with_context(mut self, ctx: IocContext) -> IocPayload {
        self.context = ctx;
        self
    }
    pub fn with_enforcement(mut self, e: Enforcement) -> IocPayload {
        self.enforcement = e;
        self
    }
    /// Stable dedup key: `ioc:<type>:<value>`. Two reports of the same indicator
    /// collapse to one logical record regardless of who reported them.
    pub fn dedup_key(&self) -> String {
        format!("ioc:{}:{}", self.ioc_type, self.value)
    }
}

// ───────────────────────────── ATC payloads ────────────────────────────

/// Which ATC fidelity tier a payload is. Serialized lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtcTier {
    Observable,
    Alert,
    Health,
}

/// The entity an ATC event concerns (process/file/connection/user/etc.).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtcEntity {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

/// Which engine produced an ATC event, and whether the local LLM enriched it.
/// `source = "atc"` means LLM-enriched; `"legacy"` means raw detector output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtcDetector {
    pub engine: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub source: String,   // "atc" | "legacy"
}

impl Default for AtcDetector {
    fn default() -> Self {
        AtcDetector { engine: "unknown".into(), rule: None, source: "legacy".into() }
    }
}

/// Cognition state carried by `atc.health` — the part that catches a *silently
/// degraded* agent (LLM down, or eBPF fell back to procmon).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtcCognition {
    pub llm_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_model: Option<String>,
    /// "atc" (LLM enriching) | "legacy" (raw only)
    pub mode: String,
}

/// Unified ATC payload across all three tiers. Fields not relevant to a tier are
/// simply omitted (skip_serializing_if), so an observable stays lean while an
/// alert carries full detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtcPayload {
    pub tier: AtcTier,

    // Observable + Alert
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity: Option<AtcEntity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector: Option<AtcDetector>,
    /// benign | unknown | suspicious | malicious
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,

    // Observable
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<String>,

    // Alert
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_techniques: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_analysis: Option<String>,

    // Health
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,            // healthy | degraded | unhealthy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cognition: Option<AtcCognition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_backend: Option<String>, // "ebpf" | "procmon"
}

impl AtcPayload {
    /// Low-fidelity observation (not a threat). `category` is e.g.
    /// "new_process_hash"; `observation` is a human-readable note.
    pub fn observable(category: &str, observation: &str) -> AtcPayload {
        AtcPayload {
            tier: AtcTier::Observable,
            category: Some(category.to_string()),
            entity: None,
            detector: None,
            disposition: Some("benign".into()),
            observation: Some(observation.to_string()),
            threat_name: None,
            mitre_techniques: Vec::new(),
            llm_analysis: None,
            status: None,
            cognition: None,
            collector_backend: None,
        }
    }

    /// High-fidelity confirmed threat. `category` e.g. "process_injection".
    pub fn alert(category: &str, threat_name: &str) -> AtcPayload {
        AtcPayload {
            tier: AtcTier::Alert,
            category: Some(category.to_string()),
            entity: None,
            detector: None,
            disposition: Some("malicious".into()),
            observation: None,
            threat_name: Some(threat_name.to_string()),
            mitre_techniques: Vec::new(),
            llm_analysis: None,
            status: None,
            cognition: None,
            collector_backend: None,
        }
    }

    /// Liveness/operational status. `status` is healthy|degraded|unhealthy.
    pub fn health(status: &str) -> AtcPayload {
        AtcPayload {
            tier: AtcTier::Health,
            category: None,
            entity: None,
            detector: None,
            disposition: None,
            observation: None,
            threat_name: None,
            mitre_techniques: Vec::new(),
            llm_analysis: None,
            status: Some(status.to_string()),
            cognition: None,
            collector_backend: None,
        }
    }

    pub fn with_entity(mut self, e: AtcEntity) -> AtcPayload { self.entity = Some(e); self }
    pub fn with_detector(mut self, d: AtcDetector) -> AtcPayload { self.detector = Some(d); self }
    pub fn with_cognition(mut self, c: AtcCognition) -> AtcPayload { self.cognition = Some(c); self }

    /// Dedup key derived from origin + tier + category/entity. For health it's
    /// one-per-origin (so the latest health replaces the prior); for
    /// observable/alert it keys on category + entity so the same finding
    /// collapses while distinct ones don't.
    pub fn dedup_key(&self, origin_id: &str) -> String {
        match self.tier {
            AtcTier::Health => format!("atc:health:{}", origin_id),
            _ => {
                let cat = self.category.as_deref().unwrap_or("event");
                let ent = self.entity.as_ref().and_then(|e| {
                    e.path.clone().or_else(|| e.pid.map(|p| p.to_string())).or_else(|| e.name.clone())
                }).unwrap_or_default();
                format!("atc:{}:{}:{}", origin_id, cat, ent)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_dedup_key() {
        let p = IocPayload::new("sha256", "deadbeef");
        assert_eq!(p.dedup_key(), "ioc:sha256:deadbeef");
    }

    #[test]
    fn atc_health_dedup_is_per_origin() {
        let h = AtcPayload::health("healthy");
        assert_eq!(h.dedup_key("agent-1"), "atc:health:agent-1");
    }

    #[test]
    fn atc_alert_dedup_includes_entity() {
        let a = AtcPayload::alert("process_injection", "Reflective inject")
            .with_entity(AtcEntity { entity_type: Some("process".into()), pid: Some(4412), ..Default::default() });
        assert_eq!(a.dedup_key("agent-1"), "atc:agent-1:process_injection:4412");
    }

    #[test]
    fn short_hash_is_stable_and_hex() {
        let h = short_hash("hello");
        assert_eq!(h.len(), 16);
        assert_eq!(h, short_hash("hello"));
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn observable_serializes_lean() {
        // Observable should not carry alert/health-only fields.
        let p = AtcPayload::observable("new_process_hash", "first seen");
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("threat_name").is_none());
        assert!(v.get("status").is_none());
        assert_eq!(v["tier"], "observable");
    }
}
