// src/gossip/envelope_bridge.rs — converts the agent's legacy IOC / threat
// types into canonical nebula-gossip Envelopes (and back), so agent↔agent and
// agent→Nexus traffic speaks the shared ecosystem format described in
// GOSSIP_ENVELOPE_SPEC.md.
//
// We deliberately keep this as a BRIDGE rather than ripping out the working
// transport: the existing UDP/HTTP paths still carry bytes; this just changes
// what those bytes ARE (canonical envelopes) and gives a clean place to convert
// for any code still using the legacy structs.

use crate::types::{IOC, IOCType, ThreatEvent, Severity as AgentSeverity};
use nebula_gossip::{Envelope, MsgType, Origin, Severity};
use nebula_gossip::payload::{IocPayload, AtcPayload, AtcEntity, AtcDetector, AtcCognition, AtcTier};

/// Map the agent's IOCType enum to the protocol's string ioc_type vocabulary.
pub fn ioc_type_str(t: &IOCType) -> &'static str {
    match t {
        IOCType::Md5 => "md5",
        IOCType::Sha1 => "sha1",
        IOCType::Sha256 => "sha256",
        IOCType::Ipv4 => "ipv4",
        IOCType::Ipv6 => "ipv6",
        IOCType::Domain => "domain",
        IOCType::Url => "url",
        IOCType::FilePath => "file_path",
        IOCType::ProcessName => "process_name",
        IOCType::RegistryKey => "registry_key",
        IOCType::YaraRule => "yara_rule",
    }
}

/// Map agent severity → protocol severity.
pub fn sev(s: &AgentSeverity) -> Severity {
    match s {
        AgentSeverity::Info => Severity::Info,
        AgentSeverity::Low => Severity::Low,
        AgentSeverity::Medium => Severity::Medium,
        AgentSeverity::High => Severity::High,
        AgentSeverity::Critical => Severity::Critical,
    }
}

/// Build the agent's Origin (single-tenant; tenant/site can be added later from
/// config when multi-tenant deployments arrive).
pub fn origin(agent_id: &str) -> Origin {
    Origin::component("nebula-agent", agent_id)
}

/// Convert a legacy IOC into an `ioc.alert` envelope.
pub fn ioc_to_envelope(ioc: &IOC, agent_id: &str) -> Envelope {
    let confidence = ioc.confidence.clamp(0.0, 100.0) as u8;
    let payload = IocPayload::new(ioc_type_str(&ioc.ioc_type), &ioc.value);
    Envelope::builder(MsgType::IocAlert, origin(agent_id))
        .confidence(confidence)
        .severity(if confidence >= 80 { Severity::High } else { Severity::Medium })
        .ttl_secs(86_400)
        .payload_ioc(payload)
        .build()
}

/// Convert a detected ThreatEvent into an `atc.alert` envelope. `llm_present`
/// distinguishes ATC (LLM-enriched) from Legacy (raw detector) at the protocol
/// level via detector.source.
pub fn threat_to_envelope(t: &ThreatEvent, agent_id: &str) -> Envelope {
    let source = if t.llm_analysis.is_some() { "atc" } else { "legacy" };
    let detector = AtcDetector {
        engine: "rules+behavior".to_string(),
        rule: t.matched_rules.first().cloned(),
        source: source.to_string(),
    };
    let mut atc = AtcPayload::alert(
        &t.threat_name.replace(' ', "_").to_lowercase(),
        &t.threat_name,
    ).with_detector(detector);
    atc.mitre_techniques = t.mitre_techniques.clone();
    atc.llm_analysis = t.llm_analysis.clone();
    if let Some(ev) = t.raw_event_ids.first() {
        atc.entity = Some(AtcEntity { name: Some(ev.clone()), ..Default::default() });
    }

    Envelope::builder(MsgType::AtcAlert, origin(agent_id))
        .confidence(t.confidence.clamp(0.0, 100.0) as u8)
        .severity(sev(&t.severity))
        .ttl_secs(2_592_000)
        .payload_atc(atc)
        .build()
}

/// Build an `atc.health` heartbeat envelope carrying cognition + collector state.
/// This is the message whose ABSENCE tells the Nexus an agent went dark, and
/// whose `cognition.mode` reveals a silently-degraded (LLM-down / procmon
/// fallback) agent.
pub fn health_envelope(
    agent_id: &str,
    status: &str,
    llm_available: bool,
    llm_model: Option<String>,
    collector_backend: &str,
) -> Envelope {
    let mut atc = AtcPayload::health(status);
    atc.cognition = Some(AtcCognition {
        llm_available,
        llm_model,
        mode: if llm_available { "atc".into() } else { "legacy".into() },
    });
    atc.collector_backend = Some(collector_backend.to_string());

    Envelope::builder(MsgType::AtcHealth, origin(agent_id))
        .confidence(100)
        .severity(Severity::Info)
        .ttl_secs(120)   // short: silence = the alert
        .payload_atc(atc)
        .build()
}

/// Extract an IOC back out of an `ioc.alert` envelope (for received peer gossip).
pub fn envelope_to_ioc(env: &Envelope) -> Option<IOC> {
    if env.msg_type != MsgType::IocAlert { return None; }
    let p: IocPayload = serde_json::from_value(env.payload.clone()).ok()?;
    let ioc_type = match p.ioc_type.as_str() {
        "md5" => IOCType::Md5,
        "sha1" => IOCType::Sha1,
        "sha256" => IOCType::Sha256,
        "ipv4" => IOCType::Ipv4,
        "ipv6" => IOCType::Ipv6,
        "domain" => IOCType::Domain,
        "url" => IOCType::Url,
        "file_path" => IOCType::FilePath,
        "process_name" => IOCType::ProcessName,
        "registry_key" => IOCType::RegistryKey,
        "yara_rule" => IOCType::YaraRule,
        _ => return None,
    };
    Some(IOC {
        ioc_type,
        value: p.value,
        source: format!("gossip:{}", env.origin.id),
        confidence: env.confidence as f32,
    })
}

#[allow(dead_code)]
fn _tier_marker(_t: AtcTier) {}   // keep AtcTier import meaningful if unused elsewhere
