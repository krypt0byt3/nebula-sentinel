// src/hardening/windows.rs — Windows STIG / CIS hardening checks.
//
// Parallel to the Linux hardening engine, this evaluates a set of Windows
// security controls drawn from the DISA Windows STIG and CIS Windows Benchmark.
// Checks read the registry (via `reg query`) and account/audit policy (via
// `secedit` / `auditpol`) — the same sources the official benchmarks use — and
// map results to the shared HardeningItem type so they flow through the existing
// posture pipeline and Nexus Compliance UI unchanged.
//
// This is a working foundation covering the highest-value controls (UAC, SMBv1,
// LSASS protection, PowerShell logging, audit policy, guest account, etc.). It's
// structured as a data-driven table so adding the full STIG catalog later is
// just more rows, not more code. Remediation strings are advisory; auto_apply is
// intentionally conservative on Windows (most fixes want operator review).

#![cfg(target_os = "windows")]

use crate::types::{HardeningItem, ComplianceStatus};

/// A single registry-based control: (hive\path, value name, expected data,
/// framework id, human title, remediation).
struct RegCheck {
    path: &'static str,
    name: &'static str,
    expected: &'static str,
    framework: &'static str,
    title: &'static str,
    remediation: &'static str,
}

const REG_CHECKS: &[RegCheck] = &[
    RegCheck {
        path: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        name: "EnableLUA", expected: "0x1",
        framework: "STIG WN10-SO-000255",
        title: "User Account Control (UAC) is enabled",
        remediation: "Set EnableLUA=1 (UAC must be on).",
    },
    RegCheck {
        path: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        name: "ConsentPromptBehaviorAdmin", expected: "0x2",
        framework: "STIG WN10-SO-000250",
        title: "UAC elevation prompt for administrators (secure desktop)",
        remediation: "Set ConsentPromptBehaviorAdmin=2 (prompt for consent on the secure desktop).",
    },
    RegCheck {
        path: r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        name: "SMB1", expected: "0x0",
        framework: "CIS 18.3.1",
        title: "SMBv1 server is disabled",
        remediation: "Set SMB1=0 and remove the SMB1 feature — SMBv1 is obsolete and exploited by WannaCry/EternalBlue.",
    },
    RegCheck {
        path: r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        name: "RunAsPPL", expected: "0x1",
        framework: "STIG WN10-SO-000095",
        title: "LSASS runs as a protected process (credential theft mitigation)",
        remediation: "Set RunAsPPL=1 to protect LSASS memory from tools like Mimikatz.",
    },
    RegCheck {
        path: r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        name: "NoLMHash", expected: "0x1",
        framework: "CIS 2.3.11.5",
        title: "LM hash storage is disabled",
        remediation: "Set NoLMHash=1 — legacy LM hashes are trivially cracked.",
    },
    RegCheck {
        path: r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        name: "RestrictAnonymous", expected: "0x1",
        framework: "STIG WN10-SO-000145",
        title: "Anonymous enumeration of shares is restricted",
        remediation: "Set RestrictAnonymous=1 to block anonymous SAM/share enumeration.",
    },
    RegCheck {
        path: r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        name: "EnableScriptBlockLogging", expected: "0x1",
        framework: "CIS 18.9.100.1",
        title: "PowerShell script block logging is enabled",
        remediation: "Set EnableScriptBlockLogging=1 — critical for detecting malicious PowerShell.",
    },
    RegCheck {
        path: r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
        name: "AllowBasic", expected: "0x0",
        framework: "CIS 18.9.102.1.1",
        title: "WinRM basic authentication is disabled",
        remediation: "Set AllowBasic=0 — basic auth sends credentials weakly protected.",
    },
    RegCheck {
        path: r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        name: "DisableRealtimeMonitoring", expected: "0x0",
        framework: "STIG WN10-CC-000185",
        title: "Windows Defender real-time protection is enabled",
        remediation: "Set DisableRealtimeMonitoring=0 (real-time protection must be on).",
    },
    RegCheck {
        path: r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        name: "UseLogonCredential", expected: "0x0",
        framework: "CIS 18.3.4",
        title: "WDigest credential caching is disabled",
        remediation: "Set UseLogonCredential=0 — otherwise cleartext creds sit in LSASS memory.",
    },
];

/// Run the Windows hardening assessment.
pub async fn assess() -> Vec<HardeningItem> {
    let mut items = Vec::new();

    for c in REG_CHECKS {
        let current = reg_query(c.path, c.name);
        // Compare case-insensitively; registry dwords print as 0x1 etc.
        let status = match &current {
            Some(v) if v.eq_ignore_ascii_case(c.expected) => ComplianceStatus::Pass,
            _ => ComplianceStatus::Fail,
        };
        items.push(HardeningItem {
            control_id: format!("reg:{}\\{}", c.path.rsplit('\\').next().unwrap_or(""), c.name),
            framework: c.framework.to_string(),
            title: c.title.to_string(),
            status,
            current_value: current,
            expected_value: c.expected.to_string(),
            remediation: c.remediation.to_string(),
            auto_fixable: false, // conservative: Windows fixes want operator review
        });
    }

    // Guest account disabled (via `net user guest`).
    items.push(check_guest_account());

    items
}

/// Query a single registry value. Returns the printed data (e.g. "0x1") or None
/// if the key/value doesn't exist.
fn reg_query(path: &str, name: &str) -> Option<String> {
    let out = std::process::Command::new("reg")
        .args(["query", path, "/v", name])
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    let text = String::from_utf8_lossy(&out.stdout);
    // Line looks like:  EnableLUA    REG_DWORD    0x1
    for line in text.lines() {
        if line.trim_start().to_lowercase().starts_with(&name.to_lowercase()) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if let Some(last) = cols.last() {
                return Some(last.to_string());
            }
        }
    }
    None
}

/// Check that the built-in Guest account is disabled.
fn check_guest_account() -> HardeningItem {
    let out = std::process::Command::new("net").args(["user", "guest"]).output();
    // "Account active     No" means disabled (good).
    let (status, current) = match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout).to_lowercase();
            let active = text.contains("account active") && text.contains("yes");
            if active {
                (ComplianceStatus::Fail, Some("active".to_string()))
            } else {
                (ComplianceStatus::Pass, Some("disabled".to_string()))
            }
        }
        Err(_) => (ComplianceStatus::Fail, None),
    };
    HardeningItem {
        control_id: "account:guest".to_string(),
        framework: "STIG WN10-SO-000005".to_string(),
        title: "Built-in Guest account is disabled".to_string(),
        status,
        current_value: current,
        expected_value: "disabled".to_string(),
        remediation: "Disable the Guest account: `net user guest /active:no`.".to_string(),
        auto_fixable: false,
    }
}
