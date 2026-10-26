//! GOSSIP message taxonomy. `msg_type` is a dotted namespace `<domain>.<kind>`;
//! the wire form is the dotted string (e.g. `"atc.alert"`).

use serde::{Deserialize, Serialize};

/// The set of message types every component agrees on. Serialized as the dotted
/// string form. `Other` preserves forward-compatibility: a newer message type
/// won't break an older parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum MsgType {
    /// A shareable indicator (hash/IP/domain/etc.).
    IocAlert,
    /// Retraction: an IOC is benign, stop acting on it.
    IocFalsePositive,
    /// Low-fidelity observation, not a threat (ATC Observable).
    AtcObservable,
    /// High-fidelity confirmed threat (ATC Alert).
    AtcAlert,
    /// Liveness / operational status (ATC Health check).
    AtcHealth,
    /// Entity reputation update (IP/host/user risk).
    ReputationScore,
    /// Peer sighting (topology / mesh membership).
    PeerSeen,
    /// Suggested detection rule for Nexus approval.
    RuleProposal,
    /// Curated, distributed intelligence (Nexus→fleet / cross-customer).
    IntelAdvisory,
    /// A captured sample is available for pull.
    SampleAvailable,
    /// An assessment finding (Red Nebula) — can seed a retro hunt.
    AssessmentFinding,
    /// Unknown/future type, preserved verbatim.
    Other(String),
}

impl MsgType {
    pub fn as_str(&self) -> &str {
        match self {
            MsgType::IocAlert => "ioc.alert",
            MsgType::IocFalsePositive => "ioc.false_positive",
            MsgType::AtcObservable => "atc.observable",
            MsgType::AtcAlert => "atc.alert",
            MsgType::AtcHealth => "atc.health",
            MsgType::ReputationScore => "reputation.score",
            MsgType::PeerSeen => "peer.seen",
            MsgType::RuleProposal => "rule.proposal",
            MsgType::IntelAdvisory => "intel.advisory",
            MsgType::SampleAvailable => "sample.available",
            MsgType::AssessmentFinding => "assessment.finding",
            MsgType::Other(s) => s.as_str(),
        }
    }

    /// The `<domain>` portion (`atc`, `ioc`, …) — handy for routing/filtering.
    pub fn domain(&self) -> &str {
        let s = self.as_str();
        s.split('.').next().unwrap_or(s)
    }

    /// True for the three ATC tiers.
    pub fn is_atc(&self) -> bool {
        matches!(self, MsgType::AtcObservable | MsgType::AtcAlert | MsgType::AtcHealth)
    }
}

impl From<String> for MsgType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "ioc.alert" => MsgType::IocAlert,
            "ioc.false_positive" => MsgType::IocFalsePositive,
            "atc.observable" => MsgType::AtcObservable,
            "atc.alert" => MsgType::AtcAlert,
            "atc.health" => MsgType::AtcHealth,
            "reputation.score" => MsgType::ReputationScore,
            "peer.seen" => MsgType::PeerSeen,
            "rule.proposal" => MsgType::RuleProposal,
            "intel.advisory" => MsgType::IntelAdvisory,
            "sample.available" => MsgType::SampleAvailable,
            "assessment.finding" => MsgType::AssessmentFinding,
            _ => MsgType::Other(s),
        }
    }
}

impl From<MsgType> for String {
    fn from(m: MsgType) -> String {
        m.as_str().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_roundtrip() {
        for m in [
            MsgType::IocAlert, MsgType::AtcObservable, MsgType::AtcAlert,
            MsgType::AtcHealth, MsgType::IntelAdvisory, MsgType::AssessmentFinding,
        ] {
            let s = m.as_str().to_string();
            let back: MsgType = s.clone().into();
            assert_eq!(back.as_str(), s);
        }
    }

    #[test]
    fn domain_extraction() {
        assert_eq!(MsgType::AtcAlert.domain(), "atc");
        assert_eq!(MsgType::IocAlert.domain(), "ioc");
        assert!(MsgType::AtcHealth.is_atc());
        assert!(!MsgType::IocAlert.is_atc());
    }

    #[test]
    fn unknown_preserved() {
        let m: MsgType = "future.kind".to_string().into();
        assert_eq!(m.as_str(), "future.kind");
        assert_eq!(m.domain(), "future");
    }
}
