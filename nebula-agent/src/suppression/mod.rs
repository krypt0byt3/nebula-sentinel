//! Detection-time suppression / allowlist.
//!
//! Applied BEFORE the dedup gate and the whole downstream cascade (response,
//! forensics, status UI, gossip, Nexus). Where dedup collapses *repetition* of
//! an otherwise-real alert, this layer encodes operator knowledge that a given
//! `(process / path / technique / threat_name)` is *known-good* — a backup
//! agent, an AV scanner, an approved admin tool — and should never raise a live
//! alert (or should only ever appear downgraded for the record).
//!
//! Each rule matches when EVERY specified field matches; unspecified fields are
//! wildcards. A rule with no fields is inert (it matches nothing) so a
//! misconfigured empty entry can't silence the whole sensor.

use crate::config::{DetectionConfig, SuppressionRule};
use crate::types::ThreatEvent;
use regex::Regex;
use tracing::{info, warn};

/// What the engine decided for one candidate alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuppressVerdict {
    /// No rule matched — forward normally.
    Allow,
    /// Discard the alert entirely. Carries the matched rule's reason.
    Drop(String),
    /// Keep the alert but force it to Info / low confidence. Carries the reason.
    Downgrade(String),
}

struct CompiledRule {
    process: Option<Regex>,
    path: Option<Regex>,
    technique: Option<String>,
    threat_name: Option<Regex>,
    drop: bool,
    reason: String,
}

pub struct SuppressionEngine {
    rules: Vec<CompiledRule>,
}

impl SuppressionEngine {
    pub fn new(cfg: &DetectionConfig) -> Self {
        let mut rules = Vec::new();
        for (i, r) in cfg.suppress.iter().enumerate() {
            match compile(r) {
                Some(c) => rules.push(c),
                None => warn!("⚠️  suppression rule #{} is empty (no match fields) — ignored", i),
            }
        }
        if !rules.is_empty() {
            info!("🛡️  Detection suppression: {} allowlist rule(s) active", rules.len());
        }
        Self { rules }
    }

    pub fn is_empty(&self) -> bool { self.rules.is_empty() }

    /// Evaluate a threat + its originating process. Returns the first matching
    /// rule's verdict, or `Allow`.
    pub fn evaluate(&self, threat: &ThreatEvent, process_name: &str, process_path: &str) -> SuppressVerdict {
        for r in &self.rules {
            if let Some(re) = &r.process {
                if !re.is_match(process_name) { continue; }
            }
            if let Some(re) = &r.path {
                if !re.is_match(process_path) { continue; }
            }
            if let Some(tech) = &r.technique {
                if !threat.mitre_techniques.iter().any(|t| t.eq_ignore_ascii_case(tech)) { continue; }
            }
            if let Some(re) = &r.threat_name {
                if !re.is_match(&threat.threat_name) { continue; }
            }
            // All specified fields matched.
            return if r.drop {
                SuppressVerdict::Drop(r.reason.clone())
            } else {
                SuppressVerdict::Downgrade(r.reason.clone())
            };
        }
        SuppressVerdict::Allow
    }
}

fn compile(r: &SuppressionRule) -> Option<CompiledRule> {
    let process     = r.process.as_deref().and_then(glob_to_regex);
    let path        = r.path.as_deref().and_then(glob_to_regex);
    let threat_name = r.threat_name.as_deref().and_then(glob_to_regex);
    let technique   = r.technique.as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Inert rule (nothing to match on) → reject so it can't suppress everything.
    if process.is_none() && path.is_none() && threat_name.is_none() && technique.is_none() {
        return None;
    }
    let drop = r.action.trim().eq_ignore_ascii_case("drop");
    let reason = r.reason.clone().unwrap_or_else(|| "allowlisted".to_string());
    Some(CompiledRule { process, path, technique, threat_name, drop, reason })
}

/// Compile a simple `*`-wildcard glob to an anchored, case-insensitive regex.
/// Returns None for an empty/whitespace pattern (treated as "field unset").
fn glob_to_regex(glob: &str) -> Option<Regex> {
    let g = glob.trim();
    if g.is_empty() { return None; }
    let mut re = String::with_capacity(g.len() + 8);
    re.push_str("(?i)^");
    for ch in g.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            // Escape regex metacharacters so a glob is treated literally.
            c if "\\.+()[]{}^$|".contains(c) => { re.push('\\'); re.push(c); }
            c => re.push(c),
        }
    }
    re.push('$');
    Regex::new(&re).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SuppressionRule;
    use crate::types::{ThreatEvent, Severity, ResponseAction};
    use chrono::Utc;

    fn rule(process: Option<&str>, technique: Option<&str>, threat_name: Option<&str>, action: &str) -> SuppressionRule {
        SuppressionRule {
            process: process.map(String::from),
            path: None,
            technique: technique.map(String::from),
            threat_name: threat_name.map(String::from),
            action: action.to_string(),
            reason: Some("test".into()),
        }
    }

    fn threat(name: &str, techniques: &[&str]) -> ThreatEvent {
        ThreatEvent {
            id: "1".into(), agent_id: "a".into(), hostname: "h".into(), timestamp: Utc::now(),
            severity: Severity::High, confidence: 80.0, threat_name: name.into(),
            description: String::new(), mitre_tactics: vec![],
            mitre_techniques: techniques.iter().map(|s| s.to_string()).collect(),
            matched_rules: vec![], raw_event_ids: vec![], chain: None, iocs: vec![],
            suggested_action: ResponseAction::Alert, llm_analysis: None, auto_generated_rule: None,
        }
    }

    fn eng(rules: Vec<SuppressionRule>) -> SuppressionEngine {
        SuppressionEngine::new(&DetectionConfig { suppress: rules })
    }

    #[test]
    fn process_glob_drop() {
        let e = eng(vec![rule(Some("MsMpEng*"), None, None, "drop")]);
        let t = threat("Suspicious scan", &["T1059"]);
        assert!(matches!(e.evaluate(&t, "MsMpEng.exe", ""), SuppressVerdict::Drop(_)));
    }

    #[test]
    fn all_fields_must_match() {
        // Rule requires BOTH process and technique; only process matches → Allow.
        let e = eng(vec![rule(Some("backup*"), Some("T1003"), None, "downgrade")]);
        let t = threat("Cred access", &["T1059"]);
        assert_eq!(e.evaluate(&t, "backup-agent", ""), SuppressVerdict::Allow);
    }

    #[test]
    fn technique_and_process_match_downgrade() {
        let e = eng(vec![rule(Some("backup*"), Some("t1003"), None, "downgrade")]);
        let t = threat("Cred access", &["T1003"]); // case-insensitive technique
        assert!(matches!(e.evaluate(&t, "backup-agent", ""), SuppressVerdict::Downgrade(_)));
    }

    #[test]
    fn empty_rule_is_inert() {
        let e = eng(vec![rule(None, None, None, "drop")]);
        assert!(e.is_empty());
        let t = threat("anything", &["T1"]);
        assert_eq!(e.evaluate(&t, "whatever", ""), SuppressVerdict::Allow);
    }

    #[test]
    fn no_rules_allows() {
        let e = eng(vec![]);
        let t = threat("x", &[]);
        assert_eq!(e.evaluate(&t, "p", ""), SuppressVerdict::Allow);
    }
}
