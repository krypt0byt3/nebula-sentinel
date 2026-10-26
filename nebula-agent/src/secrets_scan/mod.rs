// src/secrets_scan/mod.rs — Runtime secrets and credential scanning
//
// Scans files, environment variables, and process memory for exposed credentials.
// Catches what IaC scanning misses: secrets deployed at runtime, not in source.

use crate::types::{ThreatEvent, Severity, ResponseAction};
use chrono::Utc;
use regex::Regex;
use tracing::warn;
use uuid::Uuid;

/// A secret pattern to search for
pub struct SecretPattern {
    pub name:      &'static str,
    pub pattern:   &'static str,
    pub technique: &'static str,
    pub severity:  Severity,
}

pub fn default_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "AWS Access Key",
            pattern: "AKIA[0-9A-Z]{16}",
            technique: "T1552.001",
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "AWS Secret Key",
            pattern: "aws_secret_access_key\\s*=\\s*[A-Za-z0-9/+=]{40}",
            technique: "T1552.001",
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "GitHub Token",
            pattern: "ghp_[A-Za-z0-9]{36}",
            technique: "T1552.001",
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "GitHub App Token",
            pattern: "ghs_[A-Za-z0-9]{36}",
            technique: "T1552.001",
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Anthropic API Key",
            pattern: "sk-ant-[A-Za-z0-9\\-]{40,}",
            technique: "T1552.001",
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "OpenAI API Key",
            pattern: "sk-[A-Za-z0-9]{48}",
            technique: "T1552.001",
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "RSA Private Key",
            pattern: "-----BEGIN RSA PRIVATE KEY-----",
            technique: "T1552.004",
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "EC Private Key",
            pattern: "-----BEGIN EC PRIVATE KEY-----",
            technique: "T1552.004",
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Private Key (generic)",
            pattern: "-----BEGIN PRIVATE KEY-----",
            technique: "T1552.004",
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Password in env",
            pattern: "(?i)(password|passwd|pwd)\\s*=\\s*[^\\s'\"]{6,}",
            technique: "T1552.001",
            severity: Severity::High,
        },
        SecretPattern {
            name: "Database URL",
            pattern: "(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@",
            technique: "T1552.001",
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "Slack Token",
            pattern: "xox[baprs]-[0-9A-Za-z\\-]{10,}",
            technique: "T1552.001",
            severity: Severity::High,
        },
        SecretPattern {
            name: "JWT Token",
            pattern: "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
            technique: "T1552.001",
            severity: Severity::Medium,
        },
        SecretPattern {
            name: "Google API Key",
            pattern: "AIza[0-9A-Za-z_\\-]{35}",
            technique: "T1552.001",
            severity: Severity::High,
        },
        SecretPattern {
            name: "Azure SAS Token",
            pattern: "sv=[0-9]{4}-[0-9]{2}-[0-9]{2}&.*sig=",
            technique: "T1552.001",
            severity: Severity::High,
        },
        SecretPattern {
            name: "Stripe Secret Key",
            pattern: "sk_live_[0-9A-Za-z]{24}",
            technique: "T1552.001",
            severity: Severity::Critical,
        },
    ]
}

pub struct SecretsScanner {
    agent_id: String,
    hostname: String,
    patterns: Vec<(SecretPattern, Regex)>,
}

impl SecretsScanner {
    pub fn new(agent_id: &str, hostname: &str) -> Self {
        let compiled = default_patterns().into_iter()
            .filter_map(|p| {
                Regex::new(p.pattern).ok().map(|re| (p, re))
            })
            .collect();
        Self { agent_id: agent_id.to_string(), hostname: hostname.to_string(), patterns: compiled }
    }

    /// Decide whether a regex hit is a REAL secret worth alerting on, as opposed
    /// to a placeholder / example / test fixture — the classic secret-scanner
    /// false positive. We look at the matched text itself (not just "did the
    /// pattern match"), reject obvious placeholders for every pattern, and for
    /// the low-precision, high-recall patterns (a bare `password=…`, a 40-char
    /// AWS secret value) additionally require real Shannon entropy so that
    /// `password=changeme` or a row of `AAAA…` padding doesn't fire.
    fn accept(&self, p: &SecretPattern, re: &Regex, text: &str) -> bool {
        let Some(m) = re.find(text) else { return false };
        let hit = m.as_str();
        if looks_like_placeholder(hit) { return false; }
        if entropy_gated(p.name) && shannon_entropy_per_char(hit) < MIN_SECRET_ENTROPY {
            return false;
        }
        true
    }

    /// Scan environment variables of all running processes
    pub async fn scan_process_envs(&self) -> Vec<ThreatEvent> {
        let mut threats = vec![];
        let Ok(procs) = std::fs::read_dir("/proc") else { return threats };

        for entry in procs.flatten() {
            let name = entry.file_name();
            let pid_str = name.to_string_lossy();
            let Ok(pid) = pid_str.parse::<u32>() else { continue };

            let env_path = format!("/proc/{}/environ", pid);
            let Ok(env_data) = std::fs::read(&env_path) else { continue };
            let env_str = String::from_utf8_lossy(&env_data);

            let proc_name = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                .unwrap_or_default().trim().to_string();

            for (pattern, re) in &self.patterns {
                if self.accept(pattern, re, &env_str) {
                    warn!("🔑 Secret found in pid={} ({}) env: {}", pid, proc_name, pattern.name);
                    threats.push(self.make_secret_threat(
                        pattern,
                        format!("Process environment variable — pid={} ({})", pid, proc_name),
                        format!("{} found in environment variables of process {} (pid={}). Process environment is readable via /proc/{}/environ by any process with read access.", pattern.name, proc_name, pid, pid),
                    ));
                    break; // one alert per process per pattern
                }
            }
        }
        threats
    }

    /// Scan a specific file for secrets
    pub fn scan_file(&self, path: &str) -> Vec<ThreatEvent> {
        let mut threats = vec![];

        // Skip binary files, large files, and excluded paths
        if is_binary_path(path) || is_excluded_path(path) { return threats; }

        let Ok(content) = std::fs::read_to_string(path) else { return threats };
        if content.len() > 10_000_000 { return threats; } // skip files > 10MB

        for (pattern, re) in &self.patterns {
            if self.accept(pattern, re, &content) {
                warn!("🔑 Secret found in file {}: {}", path, pattern.name);
                threats.push(self.make_secret_threat(
                    pattern,
                    format!("{} in {}", pattern.name, path),
                    format!("{} detected in file {}. This credential should be rotated immediately and removed from the file.", pattern.name, path),
                ));
            }
        }
        threats
    }

    /// Scan common credential file locations
    pub async fn scan_credential_locations(&self) -> Vec<ThreatEvent> {
        let locations = [
            "/root/.aws/credentials",
            "/root/.aws/config",
            "/home/*/.aws/credentials",
            "/etc/environment",
            "/etc/.env",
            "/.env",
            "/opt/app/.env",
            "/var/www/.env",
            "/app/.env",
            "/srv/.env",
        ];

        let mut threats = vec![];
        for loc in &locations {
            if loc.contains('*') {
                // Expand glob-like patterns
                if let Ok(entries) = std::fs::read_dir("/home") {
                    for entry in entries.flatten() {
                        let p = entry.path().join(".aws/credentials");
                        if p.exists() {
                            threats.extend(self.scan_file(&p.to_string_lossy()));
                        }
                    }
                }
            } else if std::path::Path::new(loc).exists() {
                threats.extend(self.scan_file(loc));
            }
        }
        threats
    }

    fn make_secret_threat(&self, pattern: &SecretPattern, name: String, desc: String) -> ThreatEvent {
        ThreatEvent {
            id: Uuid::new_v4().to_string(),
            agent_id: self.agent_id.clone(), hostname: self.hostname.clone(),
            timestamp: Utc::now(),
            severity:  pattern.severity.clone(),
            confidence: 90.0,
            threat_name: name, description: desc,
            mitre_tactics:    vec!["credential_access".to_string()],
            mitre_techniques: vec![pattern.technique.to_string()],
            matched_rules:    vec!["secrets_scanner".to_string()],
            raw_event_ids: vec![], chain: None, iocs: vec![],
            suggested_action: ResponseAction::Alert,
            llm_analysis: None, auto_generated_rule: None,
        }
    }
}

fn is_binary_path(path: &str) -> bool {
    let binary_exts = [".so", ".o", ".a", ".elf", ".bin", ".pyc", ".class", ".jar",
        ".png", ".jpg", ".gif", ".zip", ".gz", ".tar", ".db", ".sqlite"];
    binary_exts.iter().any(|e| path.ends_with(e))
}

fn is_excluded_path(path: &str) -> bool {
    let excluded = ["/proc/", "/sys/", "/dev/", "/run/", "/tmp/.mount"];
    excluded.iter().any(|e| path.starts_with(e))
}

/// Minimum Shannon entropy (bits per character) a gated match must have to be
/// treated as a real secret. Random base64/hex credentials run ~4–6 bits/char;
/// placeholders and prose run lower. Deliberately conservative — a secret
/// scanner's false NEGATIVE is worse than its false positive, so we only use
/// this to cut the obviously-synthetic matches.
const MIN_SECRET_ENTROPY: f64 = 2.5;

/// Patterns loose enough (high recall, low precision) to warrant entropy gating
/// on top of the placeholder filter. Structured, prefixed tokens (AKIA…, ghp_…,
/// sk-ant-…, PEM headers) are already high-precision and are NOT gated.
fn entropy_gated(pattern_name: &str) -> bool {
    matches!(pattern_name, "AWS Secret Key" | "Password in env")
}

/// True if the matched text is an obvious placeholder / example / redaction
/// rather than a live credential. High-precision substring + shape checks.
fn looks_like_placeholder(hit: &str) -> bool {
    let h = hit.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "example", "changeme", "change_me", "placeholder", "your_", "your-",
        "yourkey", "yourtoken", "redacted", "dummy", "notreal", "sample",
        "insert_", "fixme", "foobar", "xxxx", "<", "...", "testkey", "test_key",
        "replace", "secret_key_here", "token_here",
    ];
    if MARKERS.iter().any(|m| h.contains(m)) { return true; }
    // A long run of a single repeated character is padding, not a secret
    // (e.g. `aws_secret_access_key = AAAAAAAA…`).
    if let Some(longest) = longest_single_char_run(hit) {
        if longest >= 16 { return true; }
    }
    false
}

fn longest_single_char_run(s: &str) -> Option<usize> {
    let mut best = 0usize;
    let mut cur = 0usize;
    let mut prev: Option<char> = None;
    for c in s.chars() {
        if Some(c) == prev { cur += 1; } else { cur = 1; prev = Some(c); }
        if cur > best { best = cur; }
    }
    (best > 0).then_some(best)
}

/// Shannon entropy in bits per character over the matched string.
fn shannon_entropy_per_char(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut freq = std::collections::HashMap::new();
    let mut n = 0u64;
    for b in s.bytes() { *freq.entry(b).or_insert(0u64) += 1; n += 1; }
    let n = n as f64;
    -freq.values().map(|&c| {
        let p = c as f64 / n;
        p * p.log2()
    }).sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> SecretsScanner { SecretsScanner::new("a", "h") }

    fn fires(text: &str) -> bool {
        let s = scanner();
        s.patterns.iter().any(|(p, re)| s.accept(p, re, text))
    }

    #[test]
    fn real_aws_access_key_fires() {
        // A realistic access-key id (structured, not entropy-gated).
        assert!(fires("key = AKIA1B2C3D4E5F6G7H8I"));
    }

    #[test]
    fn placeholder_password_is_suppressed() {
        assert!(!fires("password=changeme"));
        assert!(!fires("PASSWORD = your_password_here"));
        assert!(!fires("passwd = example"));
    }

    #[test]
    fn real_high_entropy_password_fires() {
        assert!(fires("password = J8x!q2Vd9pLm4Zt7"));
    }

    #[test]
    fn padding_run_is_not_a_secret() {
        assert!(!fires("aws_secret_access_key = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    #[test]
    fn structured_tokens_bypass_entropy_gate() {
        // A GitHub token shape with low char-variety still fires (not gated),
        // but an obvious placeholder marker still suppresses it.
        assert!(fires("ghp_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(!fires("ghp_your_token_here_aaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn entropy_helper_sane() {
        assert!(shannon_entropy_per_char("aaaaaaaa") < 1.0);
        assert!(shannon_entropy_per_char("J8x!q2Vd9pLm4Zt7") > 3.0);
    }
}
