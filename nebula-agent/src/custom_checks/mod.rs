// src/custom_checks/mod.rs — Executor for imported benchmark checks.
//
// The Nexus parses user-supplied benchmark content (XCCDF/OVAL datastreams or a
// simple YAML format) into a NORMALIZED, engine-agnostic JSON check schema and
// pushes it to agents. This module runs those checks using the same primitives
// the built-in hardening engine uses (sysctl read, file-perm test, service
// state, sshd directive, mount option).
//
// IMPORTANT (licensing): this tool ships NO proprietary benchmark content. The
// check DEFINITIONS are imported at runtime from content the operator supplies
// and are stored in the operator's own database. NebulaSentinel ships only the
// executor (this module) and the parser (Nexus side). See docs/COMPLIANCE.md.

use serde::{Deserialize, Serialize};
use crate::types::{HardeningItem, ComplianceStatus};

/// A single normalized check, as received from the Nexus. Engine-agnostic: the
/// `kind` selects which primitive evaluates it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedCheck {
    /// Stable id, e.g. "xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space"
    pub id: String,
    /// Human title.
    pub title: String,
    /// Source benchmark name (for display/attribution), e.g. "SSG RHEL9 STIG".
    #[serde(default)]
    pub benchmark: String,
    /// Optional NIST/other control id this maps to (for OSCAL rollup).
    #[serde(default)]
    pub control_id: Option<String>,
    /// The check kind: sysctl | file_perm | service_disabled | service_enabled |
    /// sshd | mount_option | file_exists | file_absent
    pub kind: String,
    /// Target of the check (sysctl key, file path, service name, sshd directive, mount point).
    pub target: String,
    /// Expected value (sysctl value, octal mode like "0640", sshd value, mount option).
    #[serde(default)]
    pub expected: String,
    /// Remediation hint (informational only — imported checks are NEVER auto-applied).
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub severity: Option<String>,
}

/// Evaluate a batch of imported checks into HardeningItems that flow through the
/// same posture-reporting path as built-in checks.
pub fn evaluate_all(checks: &[ImportedCheck]) -> Vec<HardeningItem> {
    checks.iter().map(evaluate_one).collect()
}

fn evaluate_one(c: &ImportedCheck) -> HardeningItem {
    let (status, current) = match c.kind.as_str() {
        "sysctl"          => eval_sysctl(&c.target, &c.expected),
        "file_perm"       => eval_file_perm(&c.target, &c.expected),
        "service_disabled"=> eval_service(&c.target, false),
        "service_enabled" => eval_service(&c.target, true),
        "sshd"            => eval_sshd(&c.target, &c.expected),
        "mount_option"    => eval_mount(&c.target, &c.expected),
        "file_exists"     => eval_file_exists(&c.target, true),
        "file_absent"     => eval_file_exists(&c.target, false),
        other => (ComplianceStatus::NotApplicable, Some(format!("unsupported check kind '{}'", other))),
    };
    HardeningItem {
        // Prefix the control_id so imported checks are distinguishable and the
        // OSCAL rollup can still match via the optional mapped control_id.
        control_id: c.control_id.clone().unwrap_or_else(|| format!("imported:{}", c.id)),
        framework: if c.benchmark.is_empty() { "Imported".into() } else { c.benchmark.clone() },
        title: c.title.clone(),
        status,
        current_value: current,
        expected_value: c.expected.clone(),
        remediation: c.remediation.clone(),
        // Imported checks are advisory-only: never auto-fixed, because we don't
        // vet third-party remediation commands for safety.
        auto_fixable: false,
    }
}

fn pass_fail(ok: bool) -> ComplianceStatus {
    if ok { ComplianceStatus::Pass } else { ComplianceStatus::Fail }
}

fn eval_sysctl(key: &str, expected: &str) -> (ComplianceStatus, Option<String>) {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    match std::fs::read_to_string(&path) {
        Ok(v) => {
            let v = v.trim().to_string();
            // Compare token-wise so "1\t2\t3" style multi-value sysctls match loosely.
            let ok = v == expected.trim() || v.split_whitespace().eq(expected.split_whitespace());
            (pass_fail(ok), Some(v))
        }
        Err(_) => (ComplianceStatus::NotApplicable, Some("sysctl not present".into())),
    }
}

fn eval_file_perm(path: &str, expected_mode: &str) -> (ComplianceStatus, Option<String>) {
    #[cfg(not(unix))]
    {
        let _ = (path, expected_mode);
        return (ComplianceStatus::NotApplicable, Some("POSIX file modes are not applicable on this platform".to_string()));
    }
    #[cfg(unix)]
    {
    use std::os::unix::fs::PermissionsExt;
    let want = u32::from_str_radix(expected_mode.trim_start_matches("0o").trim_start_matches('0'), 8)
        .or_else(|_| u32::from_str_radix(expected_mode, 8))
        .unwrap_or(0o644);
    match std::fs::metadata(path) {
        Ok(m) => {
            let mode = m.permissions().mode() & 0o777;
            (pass_fail(mode <= want), Some(format!("{:04o}", mode)))
        }
        Err(_) => (ComplianceStatus::NotApplicable, Some("file not found".into())),
    }
    }  // end #[cfg(unix)]
}

fn eval_service(name: &str, want_enabled: bool) -> (ComplianceStatus, Option<String>) {
    // Synchronous probe via systemctl is-enabled (avoids needing async here).
    let out = std::process::Command::new("systemctl")
        .args(["is-enabled", name]).output();
    let enabled = match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            s.trim() == "enabled"
        }
        Err(_) => false,
    };
    let ok = enabled == want_enabled;
    (pass_fail(ok), Some(if enabled { "enabled".into() } else { "disabled/absent".into() }))
}

fn eval_sshd(key: &str, expected: &str) -> (ComplianceStatus, Option<String>) {
    match std::fs::read_to_string("/etc/ssh/sshd_config") {
        Ok(content) => {
            let found = content.lines().find_map(|l| {
                let l = l.trim();
                if l.starts_with('#') || l.is_empty() { return None; }
                let mut parts = l.splitn(2, char::is_whitespace);
                let k = parts.next()?.to_lowercase();
                if k == key.to_lowercase() { Some(parts.next().unwrap_or("").trim().to_string()) } else { None }
            });
            match found {
                Some(v) => (pass_fail(v.eq_ignore_ascii_case(expected.trim())), Some(v)),
                None => (ComplianceStatus::Fail, Some("not set".into())),
            }
        }
        Err(_) => (ComplianceStatus::NotApplicable, Some("sshd_config not found".into())),
    }
}

fn eval_mount(mount: &str, option: &str) -> (ComplianceStatus, Option<String>) {
    match std::fs::read_to_string("/proc/mounts") {
        Ok(c) => {
            let line = c.lines().find(|l| {
                l.split_whitespace().nth(1) == Some(mount)
            });
            match line {
                Some(l) => {
                    let opts = l.split_whitespace().nth(3).unwrap_or("");
                    let ok = opts.split(',').any(|o| o == option);
                    (pass_fail(ok), Some(opts.to_string()))
                }
                None => (ComplianceStatus::NotApplicable, Some("mount not present".into())),
            }
        }
        Err(_) => (ComplianceStatus::NotApplicable, None),
    }
}

fn eval_file_exists(path: &str, want_exists: bool) -> (ComplianceStatus, Option<String>) {
    let exists = std::path::Path::new(path).exists();
    (pass_fail(exists == want_exists), Some(if exists { "present".into() } else { "absent".into() }))
}
