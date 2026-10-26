#![allow(dead_code)]
// src/rules/mod.rs — Detection rules engine
// Supports: YARA, Sigma (regex-based), Wazuh (XML/JSON)

use crate::config::RulesConfig;
use crate::types::{RawEvent, DetectionRule, EventType};
use anyhow::Result;
use regex::Regex;
use tracing::{info, debug};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A rule match carried out of the engine with its severity/technique intact,
/// so the caller can score the detection by the rule's real weight instead of a
/// flat bump. `severity` is the rule's declared level, normalized lowercase
/// ("critical" | "high" | "medium" | "low" | "info").
#[derive(Debug, Clone)]
pub struct RuleHit {
    pub name: String,
    pub severity: String,
    pub technique: Option<String>,
}

// ── In-memory compiled rule ────────────────────────────────────
#[derive(Debug, Clone)]
struct CompiledRule {
    id: String,
    name: String,
    rule_type: String,
    patterns: Vec<Regex>,
    keywords: Vec<String>,
    severity: String,
    technique: Option<String>,
    /// For Sigma rules: the properly-parsed rule for real condition/field
    /// evaluation (None for non-Sigma or unparseable rules, which fall back to
    /// the legacy keyword/pattern path).
    sigma: Option<crate::sigma::SigmaRule>,
}

impl CompiledRule {
    fn to_hit(&self) -> RuleHit {
        RuleHit {
            name: self.name.clone(),
            severity: normalize_severity(&self.severity),
            technique: self.technique.clone(),
        }
    }
}

/// Normalize a rule's declared level to one of the canonical severity strings.
/// Accepts Sigma levels (`informational`/`low`/`medium`/`high`/`critical`) and
/// arbitrary casing; anything unrecognized maps to `info`.
pub fn normalize_severity(s: &str) -> String {
    match s.trim().to_lowercase().as_str() {
        "critical" | "crit"            => "critical",
        "high"                         => "high",
        "medium" | "med" | "moderate"  => "medium",
        "low"                          => "low",
        _                              => "info",
    }.to_string()
}

pub struct RulesEngine {
    config: RulesConfig,
    rules: Arc<RwLock<Vec<CompiledRule>>>,
}

impl RulesEngine {
    pub async fn new(config: RulesConfig) -> Result<Self> {
        let engine = Self {
            config: config.clone(),
            rules: Arc::new(RwLock::new(vec![])),
        };
        engine.load_all_rules().await?;
        Ok(engine)
    }

    // ── Load all rules from configured directories ─────────────
    pub async fn load_all_rules(&self) -> Result<()> {
        let loaded;
        let mut all = vec![];

        all.extend(self.load_sigma_rules(&self.config.sigma_dir).await);
        all.extend(self.load_yara_rules(&self.config.yara_dir).await);
        all.extend(self.load_wazuh_rules(&self.config.wazuh_rules_dir).await);

        loaded = all.len(); let _ = loaded;
        *self.rules.write().await = all;
        info!("📋 Rules engine: {} rules loaded (yara+sigma+wazuh)", loaded);
        Ok(())
    }

    // ── Deploy a new rule from Nexus ───────────────────────────
    pub async fn deploy_rule(&self, rule: &DetectionRule) -> Result<()> {
        // Idempotent: if a rule with this name is already loaded, skip silently.
        // The Nexus now only sends genuinely-new rules, but this guards against
        // duplicates (and the non-stop "Deployed rule" log spam) if a rule is
        // ever re-delivered for any reason.
        {
            let existing = self.rules.read().await;
            if existing.iter().any(|r| r.name == rule.name) {
                return Ok(());
            }
        }
        let compiled = compile_detection_rule(rule)?;
        self.rules.write().await.push(compiled);
        info!("📋 Deployed rule: {} ({:?})", rule.name, rule.rule_type);
        Ok(())
    }

    /// Number of rules currently loaded (for the local status UI).
    pub async fn rule_count(&self) -> usize {
        self.rules.read().await.len()
    }

    // ── Match an event against all loaded rules ─────────────────
    pub async fn match_event(&self, event: &RawEvent) -> Vec<RuleHit> {
        let event_str = event_to_string(event);
        let rules = self.rules.read().await;
        let mut hits = vec![];

        // Build the field-mapped Sigma view of this event once (used by proper
        // Sigma eval). The category set derives from the event's EventType.
        let os = if cfg!(target_os = "windows") { "windows" }
                 else if cfg!(target_os = "macos") { "macos" } else { "linux" };
        let cats = sigma_categories(&event.event_type);

        // Owned bindings the borrowed SigmaEvent references live for this scope.
        let dest_port = event.network_dest_port.map(|p| p.to_string()).unwrap_or_default();
        let uid_str = event.uid.to_string();
        // For authentication events the username lives in `process_name`
        // (e.g. Windows TargetUserName); elsewhere fall back to the uid string.
        let user_str: &str = match event.event_type {
            EventType::UserAuth | EventType::UserSu if !event.process_name.is_empty()
                => &event.process_name,
            _ => &uid_str,
        };
        // DNS query name / destination hostname aren't first-class RawEvent fields;
        // pull them best-effort from `extra` (empty ⇒ absent ⇒ never matches).
        let query_name = ["query", "query_name", "dns_query", "QueryName"].iter()
            .find_map(|k| event.extra.get(*k).and_then(|v| v.as_str()))
            .unwrap_or("").to_string();
        let dest_hostname = ["dest_hostname", "destination_hostname", "DestinationHostname"].iter()
            .find_map(|k| event.extra.get(*k).and_then(|v| v.as_str()))
            .unwrap_or("").to_string();

        let sev = crate::sigma::SigmaEvent {
            category:        cats.first().copied().unwrap_or(""),
            image:           event.process_path.as_deref().unwrap_or(&event.process_name),
            command_line:    event.command_line.as_deref().unwrap_or(""),
            parent_image:    event.parent_process.as_deref().unwrap_or(""),
            user:            user_str,
            dest_ip:         event.network_dest_ip.as_deref().unwrap_or(""),
            dest_port:       &dest_port,
            dest_hostname:   &dest_hostname,
            protocol:        event.network_proto.as_deref().unwrap_or(""),
            query_name:      &query_name,
            target_filename: event.file_path.as_deref().unwrap_or(""),
            file_hash:       event.file_hash.as_deref().unwrap_or(""),
            // For module/driver loads the loaded image path is carried in
            // process_path (ebpf) or ImagePath→process_path (Windows service).
            image_loaded:    event.process_path.as_deref()
                                 .or(event.file_path.as_deref()).unwrap_or(""),
        };

        for rule in rules.iter() {
            // Proper Sigma evaluation: if this is a Sigma rule whose parsed
            // logsource category matches this event's category, use the real
            // condition/field matcher instead of the legacy keyword flattening.
            if let Some(sig) = &rule.sigma {
                if sig.applies_to(cats, os) {
                    if sig.matches(&sev) {
                        debug!("Sigma match: {} on {}", rule.name, event.process_name);
                        hits.push(rule.to_hit());
                    }
                    continue; // evaluated properly — don't also run legacy path
                }
                // Not an evaluable rule for this event (other category /
                // unsupported) → fall through to legacy keyword match so
                // nothing is lost.
            }
            if rule_matches(rule, &event_str) {
                debug!("Rule match: {} on {}", rule.name, event.process_name);
                hits.push(rule.to_hit());
            }
        }
        hits
    }

    // ── Sigma loader ───────────────────────────────────────────
    async fn load_sigma_rules(&self, dir: &str) -> Vec<CompiledRule> {
        let mut rules = vec![];
        let path = Path::new(dir);
        if !path.exists() { return rules; }

        // Walk .yml files
        for entry in walkdir(path, &["yml", "yaml"]) {
            match self.parse_sigma_file(&entry).await {
                Ok(r) => rules.push(r),
                Err(e) => debug!("Sigma parse error {}: {}", entry, e),
            }
        }
        rules
    }

    async fn parse_sigma_file(&self, path: &str) -> Result<CompiledRule> {
        let content = std::fs::read_to_string(path)?;
        // Validate this is actually a Sigma rule, not arbitrary YAML (CI config,
        // GitHub workflow, Sigma config file, etc.). A Sigma rule needs at least
        // title + detection. This prevents non-rule YAML from polluting the set.
        let lc = content.to_lowercase();
        if !(lc.contains("title:") && lc.contains("detection:")) {
            anyhow::bail!("not a Sigma rule (missing title/detection)");
        }
        let doc = parse_sigma_yaml(&content);

        let mut patterns = vec![];
        let mut keywords = vec![];

        // Extract detection keywords from simplified Sigma YAML (legacy fallback
        // path — used only if proper parsing fails).
        for keyword in &doc.detection_keywords {
            if let Ok(_re) = Regex::new(&regex::escape(keyword)) {
                keywords.push(keyword.clone());
            }
        }
        for pattern in &doc.detection_patterns {
            if let Ok(re) = Regex::new(pattern) {
                patterns.push(re);
            }
        }

        // Proper Sigma parse for real condition/field evaluation. If it parses and
        // is a process_creation rule we can evaluate, we'll use it in match_event;
        // otherwise we fall back to the legacy keyword/pattern match above.
        let sigma = crate::sigma::parse_sigma(&content);

        // Prefer the properly-parsed Sigma metadata over the legacy keyword-scan
        // extraction — the real parser reads the rule's structure (title, level,
        // and the attack.tXXXX tags) accurately. Fall back to the legacy `doc`
        // values only when the proper parse is unavailable.
        let (name, severity, technique) = match &sigma {
            Some(s) => {
                // Derive the MITRE technique from the rule's tags (attack.tXXXX),
                // normalized to an uppercase Txxxx id; fall back to legacy.
                let tech = s.tags.iter()
                    .find_map(|t| {
                        let tl = t.to_lowercase();
                        tl.strip_prefix("attack.t")
                          .filter(|rest| rest.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
                          .map(|rest| format!("T{}", rest.to_uppercase()))
                    })
                    .or_else(|| doc.mitre_technique.clone());
                let title = if s.title.is_empty() || s.title == "untitled sigma rule" {
                    doc.title.clone()
                } else {
                    s.title.clone()
                };
                (title, s.level.clone(), tech)
            }
            None => (doc.title.clone(), doc.level.clone(), doc.mitre_technique.clone()),
        };

        Ok(CompiledRule {
            id: sigma.as_ref().and_then(|s| s.id.clone()).unwrap_or(doc.id),
            name,
            rule_type: "sigma".to_string(),
            patterns,
            keywords,
            severity,
            technique,
            sigma,
        })
    }

    // ── YARA loader ────────────────────────────────────────────
    // Note: full YARA engine requires `yara` feature flag (links libyara).
    // This path uses pure-Rust pattern extraction — no C dependency required.
    async fn load_yara_rules(&self, dir: &str) -> Vec<CompiledRule> {
        let mut rules = vec![];
        let path = Path::new(dir);
        if !path.exists() { return rules; }

        for entry in walkdir(path, &["yar", "yara"]) {
            if let Ok(content) = std::fs::read_to_string(&entry) {
                if let Some(rule) = parse_yara_basic(&content, &entry) {
                    rules.push(rule);
                }
            }
        }
        rules
    }

    // ── Wazuh loader ───────────────────────────────────────────
    async fn load_wazuh_rules(&self, dir: &str) -> Vec<CompiledRule> {
        let mut rules = vec![];
        let path = Path::new(dir);
        if !path.exists() { return rules; }

        for entry in walkdir(path, &["xml"]) {
            if let Ok(content) = std::fs::read_to_string(&entry) {
                rules.extend(parse_wazuh_xml(&content, &entry));
            }
        }
        rules
    }

}

// ── Parsers ────────────────────────────────────────────────────

fn parse_yara_basic(content: &str, path: &str) -> Option<CompiledRule> {
    // Extract rule name and string patterns from YARA syntax
    let mut rule_name = String::new();
    let mut keywords = vec![];

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("rule ") {
            rule_name = line.trim_start_matches("rule ")
                .split('{').next()
                .unwrap_or("unknown")
                .trim()
                .to_string();
        }
        // Extract string literals: $s1 = "pattern" or $s2 = /regex/
        if line.starts_with('$') && line.contains(" = \"") {
            if let Some(start) = line.find('"') {
                if let Some(end) = line[start+1..].find('"') {
                    keywords.push(line[start+1..start+1+end].to_string());
                }
            }
        }
    }

    if rule_name.is_empty() { return None; }

    Some(CompiledRule {
        id: format!("yara:{}", path),
        name: rule_name,
        rule_type: "yara".to_string(),
        patterns: vec![],
        keywords,
        severity: "high".to_string(),
        technique: None,
        sigma: None,
    })
}

fn parse_wazuh_xml(content: &str, _path: &str) -> Vec<CompiledRule> {
    let mut rules = vec![];
    // Simple regex-based XML extraction (real: use quick-xml)
    let rule_re = Regex::new(r#"<rule id="(\d+)"[^>]*level="(\d+)"[^>]*>"#).unwrap();
    let match_re = Regex::new(r#"<match>([^<]+)</match>"#).unwrap();
    let desc_re  = Regex::new(r#"<description>([^<]+)</description>"#).unwrap();

    for rule_block in content.split("<rule ") {
        let id = rule_re.captures(&format!("<rule {}", rule_block))
            .and_then(|c| c.get(1)).map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let level: u8 = rule_re.captures(&format!("<rule {}", rule_block))
            .and_then(|c| c.get(2))
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(5);

        let keywords: Vec<String> = match_re.captures_iter(rule_block)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();

        let name = desc_re.captures(rule_block)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| format!("wazuh_rule_{}", id));

        if !id.is_empty() && !keywords.is_empty() {
            let severity = if level >= 13 { "critical" }
                else if level >= 9 { "high" }
                else if level >= 7 { "medium" }
                else { "low" };

            rules.push(CompiledRule {
                id: format!("wazuh:{}", id),
                name,
                rule_type: "wazuh".to_string(),
                patterns: vec![],
                keywords,
                severity: severity.to_string(),
                technique: None,
                sigma: None,
            });
        }
    }
    rules
}

fn compile_detection_rule(rule: &DetectionRule) -> Result<CompiledRule> {
    let patterns = vec![];
    let keywords: Vec<String> = rule.content.lines()
        .filter(|l| l.contains("content:") || l.contains("= \""))
        .filter_map(|l| {
            let start = l.find('"').unwrap_or(0);
            let end = l[start+1..].find('"').unwrap_or(0);
            if end > 0 { Some(l[start+1..start+1+end].to_string()) } else { None }
        })
        .collect();

    Ok(CompiledRule {
        id: rule.id.clone(),
        name: rule.name.clone(),
        rule_type: format!("{:?}", rule.rule_type).to_lowercase(),
        patterns,
        keywords,
        severity: format!("{}", rule.severity),
        technique: None,
        sigma: None,
    })
}

fn rule_matches(rule: &CompiledRule, event_str: &str) -> bool {
    let lower = event_str.to_lowercase();
    // Any keyword match
    if rule.keywords.iter().any(|k| lower.contains(&k.to_lowercase())) {
        return true;
    }
    // Any regex match
    if rule.patterns.iter().any(|p| p.is_match(event_str)) {
        return true;
    }
    false
}

/// Map a RawEvent's EventType to the Sigma logsource categories it can satisfy.
/// A Sigma rule is only evaluated against an event whose category set contains
/// the rule's `logsource.category`. EventTypes the agent can't express as any
/// Sigma category return an empty slice (those rules fall back to legacy match).
fn sigma_categories(et: &EventType) -> &'static [&'static str] {
    match et {
        EventType::ProcessExec    => &["process_creation"],
        // A connect or a bind are both "network_connection" in Sigma terms.
        EventType::NetworkConnect  => &["network_connection"],
        EventType::NetworkBind     => &["network_connection"],
        EventType::NetworkDns      => &["dns_query", "dns"],
        // file_event is the umbrella category; the change/delete variants let a
        // rule scope to the specific operation if it wants to.
        EventType::FileOpen        => &["file_event", "file_access"],
        EventType::FileWrite       => &["file_event", "file_change"],
        EventType::FileDelete      => &["file_event", "file_delete"],
        // Kernel module / driver / service load.
        EventType::ModuleLoad      => &["image_load", "driver_load"],
        EventType::UserAuth        => &["authentication"],
        _ => &[],
    }
}

fn event_to_string(event: &RawEvent) -> String {
    format!(
        "{} {} {} {} {} {} {} {}",
        event.process_name,
        event.command_line.as_deref().unwrap_or(""),
        event.file_path.as_deref().unwrap_or(""),
        event.network_dest_ip.as_deref().unwrap_or(""),
        event.file_hash.as_deref().unwrap_or(""),
        event.parent_process.as_deref().unwrap_or(""),
        event.syscall.as_deref().unwrap_or(""),
        event.container_id.as_deref().unwrap_or(""),
    )
}

fn walkdir(base: &Path, extensions: &[&str]) -> Vec<String> {
    let mut files = vec![];
    let Ok(entries) = std::fs::read_dir(base) else { return files };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(walkdir(&path, extensions));
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if extensions.contains(&ext) {
                files.push(path.to_string_lossy().to_string());
            }
        }
    }
    files
}

// ── Real serde_yaml Sigma parser ──────────────────────────────
use serde_yaml;

struct SigmaDoc {
    id: String,
    title: String,
    level: String,
    detection_keywords: Vec<String>,
    detection_patterns: Vec<String>,
    mitre_technique: Option<String>,
}

fn parse_sigma_yaml(content: &str) -> SigmaDoc {
    let mut doc = SigmaDoc {
        id: uuid::Uuid::new_v4().to_string(),
        title: String::new(),
        level: "medium".to_string(),
        detection_keywords: vec![],
        detection_patterns: vec![],
        mitre_technique: None,
    };

    let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(content) else {
        return doc;
    };

    if let Some(t) = yaml["title"].as_str() { doc.title = t.to_string(); }
    if let Some(l) = yaml["level"].as_str() { doc.level = l.to_string(); }
    if let Some(id) = yaml["id"].as_str()   { doc.id    = id.to_string(); }

    // MITRE technique from tags array
    if let Some(tags) = yaml["tags"].as_sequence() {
        for tag in tags {
            if let Some(s) = tag.as_str() {
                if s.starts_with("attack.t") || s.starts_with("attack.T") {
                    doc.mitre_technique = Some(s.trim_start_matches("attack.").to_uppercase());
                    break;
                }
            }
        }
    }

    // Walk detection section for keywords
    if let Some(det) = yaml.get("detection") {
        extract_sigma_strings(det, &mut doc.detection_keywords, &mut doc.detection_patterns);
    }

    doc
}

fn extract_sigma_strings(
    val: &serde_yaml::Value,
    keywords: &mut Vec<String>,
    patterns: &mut Vec<String>,
) {
    match val {
        serde_yaml::Value::String(s) => {
            if s.starts_with('/') && s.ends_with('/') {
                // PCRE-style regex in Sigma
                patterns.push(s.trim_matches('/').to_string());
            } else if !s.is_empty() && s != "condition" {
                keywords.push(s.clone());
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            for v in seq { extract_sigma_strings(v, keywords, patterns); }
        }
        serde_yaml::Value::Mapping(map) => {
            for (k, v) in map {
                if k.as_str().map(|s| s == "condition").unwrap_or(false) { continue; }
                extract_sigma_strings(v, keywords, patterns);
            }
        }
        _ => {}
    }
}
