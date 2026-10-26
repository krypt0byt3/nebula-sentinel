#![allow(dead_code)]
// src/reputation/mod.rs — Binary reputation checking
//
// When the inventory engine catalogs a new executable, this module checks:
//   1. Local blocklist (known-malicious hashes from Nexus IOC feed)
//   2. File entropy (high entropy executables may be packed/obfuscated)
//   3. Compiler/linker artifacts (stripped binaries from unusual paths)
//   4. VirusTotal (if API key configured — optional, can disable for air-gap)

use crate::types::{ThreatEvent, Severity, ResponseAction, IOC, IOCType};
use chrono::Utc;
use sha2::{Sha256, Digest};
use tracing::{warn, debug};
use uuid::Uuid;

pub struct ReputationEngine {
    agent_id:     String,
    hostname:     String,
    vt_api_key:   Option<String>,
    // Local blocklist: sha256 → description. RwLock so the Arc'd engine can be
    // updated at runtime from the Nexus intel feed.
    blocklist:    std::sync::RwLock<std::collections::HashMap<String, String>>,
    // Optional YARA scanner (shared, read-only after compile)
    yara:         Option<std::sync::Arc<crate::yara_scan::YaraScanner>>,
}

impl ReputationEngine {
    pub fn new(agent_id: &str, hostname: &str, vt_api_key: Option<String>) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            hostname: hostname.to_string(),
            vt_api_key,
            blocklist: std::sync::RwLock::new(std::collections::HashMap::new()),
            yara: None,
        }
    }

    /// Attach a compiled YARA scanner so check_file also runs signature scanning.
    pub fn set_yara(&mut self, scanner: std::sync::Arc<crate::yara_scan::YaraScanner>) {
        self.yara = Some(scanner);
    }

    pub fn add_blocklist_hash(&self, hash: &str, description: &str) {
        if let Ok(mut bl) = self.blocklist.write() {
            bl.insert(hash.to_lowercase(), description.to_string());
        }
    }

    /// Bulk-load malware hashes from the Nexus intel feed. Returns count added.
    pub fn load_malware_hashes(&self, hashes: &[(String, String)]) -> usize {
        if let Ok(mut bl) = self.blocklist.write() {
            for (h, desc) in hashes {
                bl.insert(h.to_lowercase(), desc.clone());
            }
            bl.len()
        } else { 0 }
    }

    /// Number of hashes currently in the local blocklist.
    #[allow(dead_code)]
    pub fn blocklist_len(&self) -> usize {
        self.blocklist.read().map(|b| b.len()).unwrap_or(0)
    }

    /// Check a file's reputation. Returns Some(ThreatEvent) if suspicious.
    pub async fn check_file(&self, path: &str) -> Option<ThreatEvent> {
        let data = std::fs::read(path).ok()?;
        let hash = format!("{:x}", Sha256::digest(&data));

        // 1. Local blocklist (fast path — no network)
        let blocked = self.blocklist.read().ok().and_then(|bl| bl.get(&hash).cloned());
        if let Some(desc) = blocked {
            warn!("🔴 Reputation: BLOCKED hash {} at {} — {}", &hash[..12], path, desc);
            return Some(self.make_rep_threat(
                path, &hash, "T1027.007",
                Severity::Critical,
                format!("Blocked hash: {}", &desc),
                format!("File {} matches known-malicious hash {}. {}", path, &hash[..16], desc),
                99.0,
            ));
        }

        // 1b. YARA signature scan (real malware-family detection)
        if let Some(ref scanner) = self.yara {
            let matches = scanner.scan_bytes(&data);
            if let Some(m) = matches.first() {
                let names: Vec<String> = matches.iter().map(|x| x.rule_name.clone()).collect();
                warn!("🧬 YARA: {} matched rule(s) {:?}", path, names);
                // Pull human-readable context from the matched rule's metadata
                // (description/author/threat_level/reference) when present.
                let meta_lookup = |keys: &[&str]| -> Option<String> {
                    m.meta.iter().find(|(k, _)| keys.contains(&k.as_str())).map(|(_, v)| v.clone())
                };
                let desc = meta_lookup(&["description", "desc", "info"]);
                let author = meta_lookup(&["author", "Author"]);
                let reference = meta_lookup(&["reference", "ref", "url"]);
                let mut detail = format!(
                    "File {} matched YARA rule(s): {}. This is a signature-confirmed malware detection.",
                    path, names.join(", "));
                if let Some(d) = &desc { detail.push_str(&format!(" — {}", d)); }
                if let Some(a) = &author { detail.push_str(&format!(" (rule by {})", a)); }
                if let Some(r) = &reference { detail.push_str(&format!(" [ref: {}]", r)); }
                let summary = match &desc {
                    Some(d) => format!("YARA match: {} — {}", m.rule_name, d),
                    None => format!("YARA match: {}", m.rule_name),
                };
                return Some(self.make_rep_threat(
                    path, &hash, "T1027.007",
                    Severity::Critical,
                    summary,
                    detail,
                    95.0,
                ));
            }
        }

        // 2. Entropy check (high entropy = likely packed/encrypted)
        let entropy = file_entropy(&data);
        if entropy > 7.2 && data.len() > 4096 {
            // Only flag executables (ELF magic: 7f 45 4c 46)
            if data.starts_with(b"\x7fELF") {
                warn!("⚠️  Reputation: high-entropy ELF {}: entropy={:.2}", path, entropy);
                return Some(self.make_rep_threat(
                    path, &hash, "T1027",
                    Severity::Medium,
                    format!("High-entropy executable: {}", path),
                    format!("ELF binary at {} has entropy {:.2}/8.0 — consistent with packing, encryption, or obfuscation. May indicate malware attempting to evade static analysis.", path, entropy),
                    65.0,
                ));
            }
        }

        // 3. Executable from suspicious path with no known package owner
        if is_suspicious_path(path) && data.starts_with(b"\x7fELF") {
            if !is_owned_by_package(path) {
                debug!("Suspicious unpackaged ELF: {}", path);
                return Some(self.make_rep_threat(
                    path, &hash, "T1027.007",
                    Severity::Medium,
                    format!("Unknown executable in suspicious location: {}", path),
                    format!("ELF binary at {} is not owned by any installed package and is in a commonly-abused directory. Manual review recommended.", path),
                    55.0,
                ));
            }
        }

        // 4. VirusTotal lookup (optional, requires API key, respects air-gap)
        if let Some(ref key) = self.vt_api_key {
            if let Some(threat) = self.check_virustotal(&hash, path, key).await {
                return Some(threat);
            }
        }

        None
    }

    async fn check_virustotal(&self, hash: &str, path: &str, api_key: &str) -> Option<ThreatEvent> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build().ok()?;

        let resp = client
            .get(format!("https://www.virustotal.com/api/v3/files/{}", hash))
            .header("x-apikey", api_key)
            .send().await.ok()?;

        if !resp.status().is_success() { return None; }

        let body: serde_json::Value = resp.json().await.ok()?;
        let stats = &body["data"]["attributes"]["last_analysis_stats"];
        let malicious = stats["malicious"].as_u64().unwrap_or(0);
        let total     = (stats["malicious"].as_u64().unwrap_or(0)
            + stats["suspicious"].as_u64().unwrap_or(0)
            + stats["undetected"].as_u64().unwrap_or(0)
            + stats["harmless"].as_u64().unwrap_or(0)) as f64;

        if malicious >= 3 {
            let pct = (malicious as f64 / total * 100.0) as u32;
            warn!("🔴 VirusTotal: {}/{} engines flagged {} as malicious", malicious, total as u64, path);
            return Some(self.make_rep_threat(
                path, hash, "T1027",
                if malicious >= 10 { Severity::Critical } else { Severity::High },
                format!("VirusTotal: {}/{} detections for {}", malicious, total as u64, std::path::Path::new(path).file_name().unwrap_or_default().to_string_lossy()),
                format!("{} AV engines flagged {} as malicious ({}% detection rate). Hash: {}", malicious, path, pct, hash),
                (50.0 + pct as f32 * 0.4).min(95.0),
            ));
        }
        None
    }

    fn make_rep_threat(&self, path: &str, hash: &str, technique: &str, severity: Severity, name: String, desc: String, confidence: f32) -> ThreatEvent {
        ThreatEvent {
            id: Uuid::new_v4().to_string(),
            agent_id: self.agent_id.clone(), hostname: self.hostname.clone(),
            timestamp: Utc::now(), severity, confidence,
            threat_name: name, description: desc,
            mitre_tactics:    vec!["defense_evasion".to_string()],
            mitre_techniques: vec![technique.to_string()],
            matched_rules:    vec!["reputation_engine".to_string()],
            raw_event_ids: vec![], chain: None,
            iocs: vec![
                IOC { ioc_type: IOCType::Sha256, value: hash.to_string(), source: "reputation".into(), confidence },
                IOC { ioc_type: IOCType::FilePath, value: path.to_string(), source: "reputation".into(), confidence },
            ],
            suggested_action: ResponseAction::QuarantineFile(path.to_string()),
            llm_analysis: None, auto_generated_rule: None,
        }
    }
}

fn file_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    freq.iter().filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum()
}

fn is_suspicious_path(path: &str) -> bool {
    path.starts_with("/tmp/") || path.starts_with("/dev/shm/") ||
    path.starts_with("/var/tmp/") || path.starts_with("/run/") ||
    (path.starts_with("/home/") && path.contains("/.")) ||
    path.contains("/proc/") || path.ends_with("/.hidden")
}

fn is_owned_by_package(path: &str) -> bool {
    // dpkg -S path
    std::process::Command::new("dpkg").args(["-S", path])
        .output().map(|o| o.status.success()).unwrap_or(false)
    || std::process::Command::new("rpm").args(["-qf", path])
        .output().map(|o| o.status.success()).unwrap_or(false)
}
