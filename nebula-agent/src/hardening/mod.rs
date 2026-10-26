// src/hardening/mod.rs — System hardening advisor and auto-remediation

use crate::config::HardeningConfig;
#[cfg(not(target_os = "windows"))]
use crate::firewall::DistroInfo;
use crate::types::{HardeningItem, ComplianceStatus};
use anyhow::Result;
use tracing::{info, warn};
use tokio::process::Command;

#[cfg(target_os = "windows")]
pub mod windows;

pub struct HardeningEngine {
    config: HardeningConfig,
}

impl HardeningEngine {
    pub fn new(config: HardeningConfig) -> Self {
        info!("🔒 HardeningEngine initialized (auto_apply={})", config.auto_apply);
        Self { config }
    }

    /// Windows STIG/CIS assessment — delegates to the windows submodule.
    #[cfg(target_os = "windows")]
    async fn assess_windows(&self) -> Vec<HardeningItem> {
        info!("🔒 Running Windows STIG/CIS hardening checks (registry + policy)...");
        windows::assess().await
    }

    pub async fn assess(&self) -> Vec<HardeningItem> {
        if !self.config.enabled { return vec![]; }
        info!("🔒 Running hardening assessment...");

        // Platform dispatch: Windows uses a parallel STIG/CIS check set (registry,
        // secedit, auditpol) rather than the Linux sysctl/sshd/mount checks, which
        // are meaningless on Windows.
        #[cfg(target_os = "windows")]
        let items = self.assess_windows().await;

        #[cfg(not(target_os = "windows"))]
        let items = self.assess_linux().await;

        let fail_count = items.iter().filter(|i| matches!(i.status, ComplianceStatus::Fail)).count();
        info!("🔒 Hardening: {}/{} checks passing", items.len() - fail_count, items.len());

        if self.config.auto_apply {
            for item in items.iter().filter(|i| matches!(i.status, ComplianceStatus::Fail) && i.auto_fixable) {
                warn!("⚙️ Auto-applying hardening: {}", item.title);
                let _ = self.apply_item(item).await;
            }
        }

        items
    }

    #[cfg(not(target_os = "windows"))]
    async fn assess_linux(&self) -> Vec<HardeningItem> {
        let mut items = vec![];
        items.extend(self.check_kernel_params().await);
        items.extend(self.check_ssh().await);
        items.extend(self.check_filesystem().await);
        items.extend(self.check_services().await);
        items.extend(self.check_user_policies().await);
        items.extend(self.check_firewall_installed().await);
        items
    }

    // ── Kernel parameter checks ────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    async fn check_kernel_params(&self) -> Vec<HardeningItem> {
        let checks = vec![
            ("kernel.randomize_va_space", "2",
             "ASLR — Address Space Layout Randomization",
             "sysctl -w kernel.randomize_va_space=2", true),
            ("net.ipv4.tcp_syncookies", "1",
             "SYN cookies (SYN flood protection)",
             "sysctl -w net.ipv4.tcp_syncookies=1", true),
            ("net.ipv4.ip_forward", "0",
             "IPv4 forwarding disabled",
             "sysctl -w net.ipv4.ip_forward=0", true),
            ("net.ipv4.conf.all.send_redirects", "0",
             "ICMP redirects disabled",
             "sysctl -w net.ipv4.conf.all.send_redirects=0", true),
            ("net.ipv4.conf.all.accept_source_route", "0",
             "Source routing disabled",
             "sysctl -w net.ipv4.conf.all.accept_source_route=0", true),
            ("fs.protected_hardlinks", "1",
             "Protected hardlinks",
             "sysctl -w fs.protected_hardlinks=1", true),
            ("fs.protected_symlinks", "1",
             "Protected symlinks",
             "sysctl -w fs.protected_symlinks=1", true),
            ("kernel.dmesg_restrict", "1",
             "dmesg restricted to privileged users",
             "sysctl -w kernel.dmesg_restrict=1", true),
            ("kernel.kptr_restrict", "2",
             "Kernel pointer restriction",
             "sysctl -w kernel.kptr_restrict=2", true),
            ("net.core.bpf_jit_harden", "2",
             "BPF JIT hardening",
             "sysctl -w net.core.bpf_jit_harden=2", true),
        ];

        let mut items = vec![];
        for (key, expected, title, remediation, auto_fixable) in checks {
            let current = read_sysctl(key);
            let status = if current.as_deref() == Some(expected) {
                ComplianceStatus::Pass
            } else {
                ComplianceStatus::Fail
            };
            items.push(HardeningItem {
                control_id: format!("sysctl:{}", key),
                framework: "CIS/STIG".to_string(),
                title: title.to_string(),
                status,
                current_value: current,
                expected_value: expected.to_string(),
                remediation: remediation.to_string(),
                auto_fixable,
            });
        }
        items
    }

    // ── SSH daemon checks ──────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    async fn check_ssh(&self) -> Vec<HardeningItem> {
        if !self.config.sshd_hardening { return vec![]; }

        let checks = vec![
            ("PermitRootLogin", "no", "Root login via SSH disabled", false),
            ("PermitEmptyPasswords", "no", "Empty password SSH login disabled", false),
            ("MaxAuthTries", "3", "SSH max auth tries ≤ 3", false),
            ("ClientAliveInterval", "300", "SSH client alive interval 300s", false),
            ("ClientAliveCountMax", "0", "SSH client alive count max 0", false),
            ("Protocol", "2", "SSH Protocol 2 only", false),
            ("X11Forwarding", "no", "X11 forwarding disabled", false),
            ("UsePAM", "yes", "PAM authentication enabled", false),
            ("LoginGraceTime", "60", "Login grace time 60s", false),
        ];

        let mut items = vec![];
        for (key, expected, title, auto_fixable) in checks {
            let is_set = check_sshd_setting(key, expected);
            items.push(HardeningItem {
                control_id: format!("sshd:{}", key),
                framework: "CIS SSH".to_string(),
                title: title.to_string(),
                status: if is_set { ComplianceStatus::Pass } else { ComplianceStatus::Fail },
                current_value: None,
                expected_value: expected.to_string(),
                remediation: format!("Add '{} {}' to /etc/ssh/sshd_config then restart sshd", key, expected),
                auto_fixable,
            });
        }
        items
    }

    // ── Filesystem checks ──────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    async fn check_filesystem(&self) -> Vec<HardeningItem> {
        let checks = vec![
            ("/tmp",     "noexec", "nodev", "nosuid", "CIS 1.1.3"),
            ("/var/tmp", "noexec", "nodev", "nosuid", "CIS 1.1.8"),
            ("/dev/shm", "noexec", "nodev", "nosuid", "CIS 1.1.15"),
        ];

        let mut items = vec![];
        for (mount, opt1, opt2, opt3, control) in checks {
            let has_opts = check_mount_options(mount, &[opt1, opt2, opt3]);
            items.push(HardeningItem {
                control_id: format!("mount:{}", mount.replace('/', "_")),
                framework: control.to_string(),
                title: format!("{} mounted with {},{},{}", mount, opt1, opt2, opt3),
                status: if has_opts { ComplianceStatus::Pass } else { ComplianceStatus::Fail },
                current_value: None,
                expected_value: format!("{},{},{}", opt1, opt2, opt3),
                remediation: format!("Add {},{},{} to {} in /etc/fstab", opt1, opt2, opt3, mount),
                auto_fixable: false,
            });
        }

        // /etc/passwd permissions
        let passwd_ok = check_file_perms("/etc/passwd", 0o644);
        items.push(HardeningItem {
            control_id: "file:passwd_perms".to_string(),
            framework: "CIS 6.1.2".to_string(),
            title: "/etc/passwd permissions 644".to_string(),
            status: if passwd_ok { ComplianceStatus::Pass } else { ComplianceStatus::Fail },
            current_value: None,
            expected_value: "0644".to_string(),
            remediation: "chmod 644 /etc/passwd".to_string(),
            auto_fixable: true,
        });

        // /etc/shadow permissions
        let shadow_ok = check_file_perms("/etc/shadow", 0o640);
        items.push(HardeningItem {
            control_id: "file:shadow_perms".to_string(),
            framework: "CIS 6.1.3".to_string(),
            title: "/etc/shadow permissions 640 or stricter".to_string(),
            status: if shadow_ok { ComplianceStatus::Pass } else { ComplianceStatus::Fail },
            current_value: None,
            expected_value: "0640".to_string(),
            remediation: "chmod 640 /etc/shadow && chown root:shadow /etc/shadow".to_string(),
            auto_fixable: true,
        });

        items
    }

    // ── Service audit ──────────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    async fn check_services(&self) -> Vec<HardeningItem> {
        // Services that should NOT be running in a hardened system
        let unwanted = vec![
            ("avahi-daemon", "Avahi mDNS/DNS-SD disabled (network exposure)"),
            ("cups",         "CUPS print service disabled (unless needed)"),
            ("nfs-server",   "NFS server disabled (unless needed)"),
            ("rpcbind",      "rpcbind disabled (RPC port mapper)"),
            ("telnet",       "telnet disabled (use SSH)"),
            ("rsh-server",   "rsh disabled (use SSH)"),
            ("ypbind",       "NIS/YP client disabled"),
        ];

        let mut items = vec![];
        for (svc, title) in unwanted {
            let running = service_is_active(svc).await;
            items.push(HardeningItem {
                control_id: format!("svc:{}", svc),
                framework: "CIS 2.x".to_string(),
                title: title.to_string(),
                status: if !running { ComplianceStatus::Pass } else { ComplianceStatus::Fail },
                current_value: Some(if running { "active".to_string() } else { "inactive".to_string() }),
                expected_value: "inactive/disabled".to_string(),
                remediation: format!("systemctl disable --now {}", svc),
                auto_fixable: false, // dangerous to auto-disable services
            });
        }
        items
    }

    // ── User / PAM policies ────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    async fn check_user_policies(&self) -> Vec<HardeningItem> {
        let mut items = vec![];

        // Password aging
        let passwd_max_ok = check_login_defs("PASS_MAX_DAYS", 90);
        items.push(HardeningItem {
            control_id: "pam:pass_max_days".to_string(),
            framework: "CIS 5.4.1.1".to_string(),
            title: "Password max age ≤ 90 days".to_string(),
            status: if passwd_max_ok { ComplianceStatus::Pass } else { ComplianceStatus::Fail },
            current_value: None,
            expected_value: "90".to_string(),
            remediation: "Set PASS_MAX_DAYS 90 in /etc/login.defs".to_string(),
            auto_fixable: false,
        });

        let passwd_min_ok = check_login_defs("PASS_MIN_DAYS", 1);
        items.push(HardeningItem {
            control_id: "pam:pass_min_days".to_string(),
            framework: "CIS 5.4.1.2".to_string(),
            title: "Password min age ≥ 1 day".to_string(),
            status: if passwd_min_ok { ComplianceStatus::Pass } else { ComplianceStatus::Fail },
            current_value: None,
            expected_value: "1".to_string(),
            remediation: "Set PASS_MIN_DAYS 1 in /etc/login.defs".to_string(),
            auto_fixable: false,
        });

        items
    }

    // ── Auto-apply remediation ─────────────────────────────────
    // ── Distro-aware firewall installation check ─────────────
    #[cfg(not(target_os = "windows"))]
    async fn check_firewall_installed(&self) -> Vec<HardeningItem> {
        let distro = DistroInfo::detect();
        let has_nft = Command::new("which").arg("nft").output().await.map(|o| o.status.success()).unwrap_or(false);
        let has_ipt = Command::new("which").arg("iptables").output().await.map(|o| o.status.success()).unwrap_or(false);
        let has_fwd = Command::new("which").arg("firewall-cmd").output().await.map(|o| o.status.success()).unwrap_or(false);
        let has_ufw = Command::new("which").arg("ufw").output().await.map(|o| o.status.success()).unwrap_or(false);
        let ok = has_nft || has_ipt || has_fwd || has_ufw;
        vec![HardeningItem {
            control_id:    "CIS-3.5.1".to_string(),
            framework:     "CIS".to_string(),
            title:         "Firewall tool installed".to_string(),
            status:        if ok { ComplianceStatus::Pass } else { ComplianceStatus::Fail },
            current_value: Some(if has_nft { "nftables".into() } else if has_fwd { "firewalld".into() } else if has_ufw { "ufw".into() } else if has_ipt { "iptables".into() } else { "none — NebulaSentinel network blocking will not work".into() }),
            expected_value: "nftables (recommended)".to_string(),
            remediation:   format!("{} {}", distro.install_cmd, distro.firewall_pkg),
            auto_fixable:  false,
        }]
    }

    async fn apply_item(&self, item: &HardeningItem) -> Result<()> {
        if item.control_id.starts_with("sysctl:") {
            let key = item.control_id.trim_start_matches("sysctl:");
            let val = &item.expected_value;
            Command::new("sysctl")
                .args(["-w", &format!("{}={}", key, val)])
                .output().await?;
            info!("✅ Applied: sysctl -w {}={}", key, val);
        }
        if item.control_id == "file:passwd_perms" {
            Command::new("chmod").args(["644", "/etc/passwd"]).output().await?;
        }
        if item.control_id == "file:shadow_perms" {
            Command::new("chmod").args(["640", "/etc/shadow"]).output().await?;
        }
        Ok(())
    }
}

// ── Helper functions (Linux) ───────────────────────────────────
// Only used by the Linux check methods; gated so they don't warn as dead code
// on Windows builds (which use the windows submodule instead).
#[cfg(not(target_os = "windows"))]
fn read_sysctl(key: &str) -> Option<String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

#[cfg(not(target_os = "windows"))]
fn check_sshd_setting(key: &str, expected: &str) -> bool {
    std::fs::read_to_string("/etc/ssh/sshd_config")
        .map(|c| c.lines().any(|l| {
            let l = l.trim();
            !l.starts_with('#') && l.to_lowercase().starts_with(&key.to_lowercase())
                && l.to_lowercase().contains(&expected.to_lowercase())
        }))
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn check_mount_options(mount: &str, options: &[&str]) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|c| c.lines().any(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() < 4 || parts[1] != mount { return false; }
            options.iter().all(|opt| parts[3].split(',').any(|o| o == *opt))
        }))
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn check_file_perms(path: &str, expected_mode: u32) -> bool {
    #[cfg(not(unix))]
    { let _ = (path, expected_mode); return false; }
    #[cfg(unix)]
    {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o777 <= expected_mode)
        .unwrap_or(false)
    }
}

#[cfg(not(target_os = "windows"))]
async fn service_is_active(name: &str) -> bool {
    tokio::process::Command::new("systemctl")
        .args(["is-active", "--quiet", name])
        .status().await
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn check_login_defs(key: &str, max_val: u32) -> bool {
    std::fs::read_to_string("/etc/login.defs")
        .map(|c| c.lines().any(|l| {
            let l = l.trim();
            if l.starts_with('#') { return false; }
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() < 2 || parts[0] != key { return false; }
            parts[1].parse::<u32>().map(|v| v <= max_val).unwrap_or(false)
        }))
        .unwrap_or(false)
}
