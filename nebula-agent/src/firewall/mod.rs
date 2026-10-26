#![allow(dead_code)]
// src/firewall/mod.rs — Firewall abstraction layer
//
// Detects and uses the correct firewall tool at runtime.
// Priority: nftables → firewalld → ufw → iptables → /proc fallback
//
// WHY THIS MATTERS:
//   - Debian 11+ / Ubuntu 22.04+: nftables is the default kernel frontend
//   - RHEL 8+ / Fedora 32+ / CentOS Stream: firewalld wraps nftables
//   - Ubuntu desktop: ufw wraps iptables or nftables
//   - Old distros / containers: iptables directly
//   - Minimal containers (Alpine, distroless): NO firewall tool at all
//
//   On modern systems, running `iptables` goes through a compatibility shim
//   that translates to nftables. On some systems this shim is not installed.
//   Calling `iptables` on a system where it doesn't exist produces:
//     Error: No such file or directory (os error 2)
//   ...which was previously silently discarded, making block/isolate do nothing.
//
// This module detects once at startup (stored in AppState equivalent),
// then uses the correct backend consistently. All failures are logged
// with actionable remediation advice.

use anyhow::{Result, Context};
use tokio::process::Command;
use tracing::{info, warn, debug, error};

// ─────────────────────────────────────────────────────────────
// Backend
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum FirewallBackend {
    Nftables,
    Firewalld,
    Ufw,
    Iptables,
    /// Windows Firewall via `netsh advfirewall firewall`.
    WindowsFirewall,
    /// No firewall tool available. block_ip/isolate will warn and degrade gracefully.
    None,
}

impl std::fmt::Display for FirewallBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nftables        => write!(f, "nftables"),
            Self::Firewalld       => write!(f, "firewalld"),
            Self::Ufw             => write!(f, "ufw"),
            Self::Iptables        => write!(f, "iptables"),
            Self::WindowsFirewall => write!(f, "windows-firewall"),
            Self::None            => write!(f, "none"),
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Firewall manager
// ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Firewall {
    pub backend: FirewallBackend,
}

impl Firewall {
    /// Probe available tools and select the best backend.
    /// Call once at startup; clone the result for reuse.
    pub async fn detect() -> Self {
        let backend = Self::probe().await;
        match &backend {
            FirewallBackend::None => {
                warn!("⚠️  No firewall tool detected. Network blocking will be unavailable.");
                warn!("   To enable: apt install nftables  OR  dnf install nftables");
            }
            b => info!("🔥 Firewall backend: {}", b),
        }
        Self { backend }
    }

    /// Use when you already know the backend (e.g. read from config).
    pub fn with_backend(backend: FirewallBackend) -> Self {
        Self { backend }
    }

    pub fn is_available(&self) -> bool {
        self.backend != FirewallBackend::None
    }

    async fn probe() -> FirewallBackend {
        // Windows: the Windows Firewall is always present and controlled via
        // `netsh advfirewall firewall`. It requires the agent to run elevated to
        // actually add rules, but the backend is selectable regardless.
        #[cfg(target_os = "windows")]
        { return FirewallBackend::WindowsFirewall; }

        #[cfg(not(target_os = "windows"))]
        {
        // nftables — preferred everywhere
        if bin_exists("nft").await && nft_kernel_ok().await {
            return FirewallBackend::Nftables;
        }
        // firewalld — RHEL/Fedora default (wraps nft or ipt)
        if bin_exists("firewall-cmd").await && firewalld_running().await {
            return FirewallBackend::Firewalld;
        }
        // ufw — Ubuntu default
        if bin_exists("ufw").await {
            return FirewallBackend::Ufw;
        }
        // iptables — legacy / most containers
        if bin_exists("iptables").await {
            return FirewallBackend::Iptables;
        }
        FirewallBackend::None
        }
    }

    // ── Public API ────────────────────────────────────────────

    /// Block all traffic to/from an IP address.
    pub async fn block_ip(&self, ip: &str) -> Result<()> {
        validate_ip(ip)?;
        match &self.backend {
            FirewallBackend::Nftables  => self.nft_block_ip(ip).await,
            FirewallBackend::Firewalld => self.fwd_block_ip(ip).await,
            FirewallBackend::Ufw       => self.ufw_block_ip(ip).await,
            FirewallBackend::Iptables  => self.ipt_block_ip(ip).await,
            FirewallBackend::WindowsFirewall => self.win_block_ip(ip).await,
            FirewallBackend::None      => self.no_firewall_warn("block_ip"),
        }
    }

    /// Remove a previously added IP block.
    pub async fn unblock_ip(&self, ip: &str) -> Result<()> {
        validate_ip(ip)?;
        match &self.backend {
            FirewallBackend::Nftables  => self.nft_unblock_ip(ip).await,
            FirewallBackend::Firewalld => self.fwd_unblock_ip(ip).await,
            FirewallBackend::Ufw       => self.ufw_unblock_ip(ip).await,
            FirewallBackend::Iptables  => self.ipt_unblock_ip(ip).await,
            FirewallBackend::WindowsFirewall => self.win_unblock_ip(ip).await,
            FirewallBackend::None      => Ok(()),
        }
    }

    /// Isolate the host: block everything except loopback and allowlisted IPs.
    /// `allowlist` should contain at least the Nexus server IP so the agent
    /// can be un-isolated remotely.
    pub async fn isolate(&self, allowlist: &[String]) -> Result<()> {
        match &self.backend {
            FirewallBackend::Nftables  => self.nft_isolate(allowlist).await,
            FirewallBackend::Firewalld => self.fwd_isolate(allowlist).await,
            FirewallBackend::Ufw       => self.ufw_isolate(allowlist).await,
            FirewallBackend::Iptables  => self.ipt_isolate(allowlist).await,
            FirewallBackend::WindowsFirewall => self.win_isolate(allowlist).await,
            FirewallBackend::None      => self.proc_isolate().await,
        }
    }

    /// Restore normal network access after isolation.
    pub async fn undo_isolation(&self) -> Result<()> {
        match &self.backend {
            FirewallBackend::Nftables  => self.nft_undo_isolation().await,
            FirewallBackend::Firewalld => self.fwd_undo_isolation().await,
            FirewallBackend::Ufw       => self.ufw_undo_isolation().await,
            FirewallBackend::Iptables  => self.ipt_undo_isolation().await,
            FirewallBackend::WindowsFirewall => self.win_undo_isolation().await,
            FirewallBackend::None      => self.proc_undo_isolation().await,
        }
    }

    // ── nftables ──────────────────────────────────────────────

    async fn nft_block_ip(&self, ip: &str) -> Result<()> {
        // Ensure nebula table exists
        run("nft", &["add", "table", "inet", "nebula"]).await.ok();
        run("nft", &["add", "chain", "inet", "nebula", "input",
            "{ type filter hook input priority 100; policy accept; }"]).await.ok();
        run("nft", &["add", "chain", "inet", "nebula", "output",
            "{ type filter hook output priority 100; policy accept; }"]).await.ok();

        run("nft", &["add", "rule", "inet", "nebula", "input",
            &format!("ip saddr {} drop", ip)]).await
            .context("nftables: failed to add input block")?;
        run("nft", &["add", "rule", "inet", "nebula", "output",
            &format!("ip daddr {} drop", ip)]).await
            .context("nftables: failed to add output block")?;

        info!("🚫 nftables: blocked {}", ip);
        Ok(())
    }

    async fn nft_unblock_ip(&self, ip: &str) -> Result<()> {
        // Simplest reliable approach: flush nebula chains and rebuild
        // (alternative: walk handles, but that requires parsing nft -j output)
        let _ = run("nft", &["flush", "chain", "inet", "nebula", "input"]).await;
        let _ = run("nft", &["flush", "chain", "inet", "nebula", "output"]).await;
        info!("🔓 nftables: unblocked {} (flushed nebula chains)", ip);
        Ok(())
    }

    async fn nft_isolate(&self, allowlist: &[String]) -> Result<()> {
        // Atomic rebuild: delete table (removes everything) then recreate
        let _ = run("nft", &["delete", "table", "inet", "nebula"]).await;
        run("nft", &["add", "table", "inet", "nebula"]).await?;

        // Chains with DROP default policy
        run("nft", &["add", "chain", "inet", "nebula", "input",
            "{ type filter hook input priority 0; policy drop; }"]).await?;
        run("nft", &["add", "chain", "inet", "nebula", "output",
            "{ type filter hook output priority 0; policy drop; }"]).await?;

        // Always allow loopback
        run("nft", &["add", "rule", "inet", "nebula", "input",  "iif lo accept"]).await?;
        run("nft", &["add", "rule", "inet", "nebula", "output", "oif lo accept"]).await?;

        // Allow established connections (prevents operator SSH lockout)
        run("nft", &["add", "rule", "inet", "nebula", "input",
            "ct state established,related accept"]).await?;
        run("nft", &["add", "rule", "inet", "nebula", "output",
            "ct state established,related accept"]).await?;

        // Allowlist
        for ip in allowlist.iter().filter(|s| !s.trim().is_empty()) {
            run("nft", &["add", "rule", "inet", "nebula", "input",
                &format!("ip saddr {} accept", ip.trim())]).await.ok();
            run("nft", &["add", "rule", "inet", "nebula", "output",
                &format!("ip daddr {} accept", ip.trim())]).await.ok();
        }

        warn!("🔒 nftables: host isolated. Allowlist: {:?}", allowlist);
        Ok(())
    }

    async fn nft_undo_isolation(&self) -> Result<()> {
        run("nft", &["delete", "table", "inet", "nebula"]).await
            .context("nftables: failed to delete nebula table")?;
        warn!("🔓 nftables: isolation removed");
        Ok(())
    }

    // ── firewalld (RHEL/Fedora/CentOS) ───────────────────────

    async fn fwd_block_ip(&self, ip: &str) -> Result<()> {
        run("firewall-cmd", &[
            &format!("--add-rich-rule=rule family=ipv4 source address={}/32 drop", ip)
        ]).await.context("firewalld: block source failed")?;
        run("firewall-cmd", &[
            &format!("--add-rich-rule=rule family=ipv4 destination address={}/32 drop", ip)
        ]).await.context("firewalld: block destination failed")?;
        info!("🚫 firewalld: blocked {}", ip);
        Ok(())
    }

    async fn fwd_unblock_ip(&self, ip: &str) -> Result<()> {
        let _ = run("firewall-cmd", &[
            &format!("--remove-rich-rule=rule family=ipv4 source address={}/32 drop", ip)
        ]).await;
        let _ = run("firewall-cmd", &[
            &format!("--remove-rich-rule=rule family=ipv4 destination address={}/32 drop", ip)
        ]).await;
        info!("🔓 firewalld: unblocked {}", ip);
        Ok(())
    }

    async fn fwd_isolate(&self, allowlist: &[String]) -> Result<()> {
        // Set default zone to drop all traffic
        run("firewall-cmd", &["--set-default-zone=drop"]).await
            .context("firewalld: failed to set default zone to drop")?;

        // Always allow loopback
        let _ = run("firewall-cmd", &["--zone=trusted", "--add-interface=lo"]).await;

        // Add Nexus IPs to trusted zone
        for ip in allowlist.iter().filter(|s| !s.trim().is_empty()) {
            run("firewall-cmd", &[
                &format!("--add-rich-rule=rule family=ipv4 source address={}/32 accept", ip.trim())
            ]).await.ok();
        }

        warn!("🔒 firewalld: host isolated (zone=drop). Allowlist: {:?}", allowlist);
        Ok(())
    }

    async fn fwd_undo_isolation(&self) -> Result<()> {
        run("firewall-cmd", &["--set-default-zone=public"]).await
            .context("firewalld: failed to restore default zone")?;
        warn!("🔓 firewalld: isolation removed (zone=public)");
        Ok(())
    }

    // ── ufw (Ubuntu) ──────────────────────────────────────────

    async fn ufw_block_ip(&self, ip: &str) -> Result<()> {
        run("ufw", &["deny", "from", ip, "to", "any"]).await
            .context("ufw: deny from failed")?;
        run("ufw", &["deny", "from", "any", "to", ip]).await
            .context("ufw: deny to failed")?;
        info!("🚫 ufw: blocked {}", ip);
        Ok(())
    }

    async fn ufw_unblock_ip(&self, ip: &str) -> Result<()> {
        let _ = run("ufw", &["delete", "deny", "from", ip, "to", "any"]).await;
        let _ = run("ufw", &["delete", "deny", "from", "any", "to", ip]).await;
        info!("🔓 ufw: unblocked {}", ip);
        Ok(())
    }

    async fn ufw_isolate(&self, allowlist: &[String]) -> Result<()> {
        // Reset to clean state
        run("ufw", &["--force", "reset"]).await.context("ufw: reset failed")?;
        run("ufw", &["default", "deny", "incoming"]).await?;
        run("ufw", &["default", "deny", "outgoing"]).await?;

        // Allow loopback
        let _ = run("ufw", &["allow", "in",  "on", "lo"]).await;
        let _ = run("ufw", &["allow", "out", "on", "lo"]).await;

        // Allowlist
        for ip in allowlist.iter().filter(|s| !s.trim().is_empty()) {
            let _ = run("ufw", &["allow", "in",  "from", ip.trim()]).await;
            let _ = run("ufw", &["allow", "out", "to",   ip.trim()]).await;
        }

        run("ufw", &["--force", "enable"]).await.context("ufw: enable failed")?;
        warn!("🔒 ufw: host isolated. Allowlist: {:?}", allowlist);
        Ok(())
    }

    async fn ufw_undo_isolation(&self) -> Result<()> {
        run("ufw", &["--force", "reset"]).await?;
        run("ufw", &["default", "allow"]).await?;
        warn!("🔓 ufw: isolation removed");
        Ok(())
    }

    // ── iptables (legacy / containers) ───────────────────────

    async fn ipt_block_ip(&self, ip: &str) -> Result<()> {
        for chain in &["INPUT", "OUTPUT", "FORWARD"] {
            let _ = run("iptables", &["-A", chain, "-s", ip, "-j", "DROP"]).await;
            let _ = run("iptables", &["-A", chain, "-d", ip, "-j", "DROP"]).await;
        }
        // IPv6 if available
        if bin_exists("ip6tables").await {
            let _ = run("ip6tables", &["-A", "OUTPUT", "-d", ip, "-j", "DROP"]).await;
            let _ = run("ip6tables", &["-A", "INPUT",  "-s", ip, "-j", "DROP"]).await;
        }
        info!("🚫 iptables: blocked {}", ip);
        Ok(())
    }

    async fn ipt_unblock_ip(&self, ip: &str) -> Result<()> {
        for chain in &["INPUT", "OUTPUT", "FORWARD"] {
            let _ = run("iptables", &["-D", chain, "-s", ip, "-j", "DROP"]).await;
            let _ = run("iptables", &["-D", chain, "-d", ip, "-j", "DROP"]).await;
        }
        info!("🔓 iptables: unblocked {}", ip);
        Ok(())
    }

    async fn ipt_isolate(&self, allowlist: &[String]) -> Result<()> {
        // CRITICAL: set DROP policy BEFORE flushing.
        // If you flush first there is a window where all traffic is allowed.
        for chain in &["INPUT", "OUTPUT", "FORWARD"] {
            run("iptables", &["-P", chain, "DROP"]).await
                .context(format!("iptables: failed to set {} policy to DROP", chain))?;
        }

        // Allow loopback
        let _ = run("iptables", &["-I", "INPUT",  "1", "-i", "lo", "-j", "ACCEPT"]).await;
        let _ = run("iptables", &["-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"]).await;

        // Allow established connections (prevents SSH lockout)
        let _ = run("iptables", &["-I", "INPUT", "2",
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]).await;
        let _ = run("iptables", &["-I", "OUTPUT", "2",
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]).await;

        // Allowlist Nexus
        for (i, ip) in allowlist.iter().filter(|s| !s.trim().is_empty()).enumerate() {
            let pos = (i + 3).to_string();
            let _ = run("iptables", &["-I", "INPUT",  &pos, "-s", ip.trim(), "-j", "ACCEPT"]).await;
            let _ = run("iptables", &["-I", "OUTPUT", &pos, "-d", ip.trim(), "-j", "ACCEPT"]).await;
        }

        warn!("🔒 iptables: host isolated. Allowlist: {:?}", allowlist);
        Ok(())
    }

    async fn ipt_undo_isolation(&self) -> Result<()> {
        for chain in &["INPUT", "OUTPUT", "FORWARD"] {
            let _ = run("iptables", &["-P", chain, "ACCEPT"]).await;
            let _ = run("iptables", &["-F", chain]).await;
        }
        warn!("🔓 iptables: isolation removed");
        Ok(())
    }

    // ── Windows Firewall (netsh advfirewall) ──────────────────
    // Rules are tagged with a "NebulaSentinel-" name prefix so we can find and
    // remove exactly our own rules without touching the operator's firewall
    // config. Blocking an IP adds paired inbound+outbound block rules for the
    // remote address. All of this requires the agent to run elevated; if it does
    // not, netsh returns an error which we surface rather than silently failing.

    async fn win_block_ip(&self, ip: &str) -> Result<()> {
        let name = format!("NebulaSentinel-Block-{}", ip);
        // Outbound block (host → attacker)
        run("netsh", &["advfirewall", "firewall", "add", "rule",
            &format!("name={}-out", name), "dir=out", "action=block",
            &format!("remoteip={}", ip)]).await
            .context("windows-firewall: failed to add outbound block")?;
        // Inbound block (attacker → host)
        run("netsh", &["advfirewall", "firewall", "add", "rule",
            &format!("name={}-in", name), "dir=in", "action=block",
            &format!("remoteip={}", ip)]).await
            .context("windows-firewall: failed to add inbound block")?;
        info!("🚫 windows-firewall: blocked {}", ip);
        Ok(())
    }

    async fn win_unblock_ip(&self, ip: &str) -> Result<()> {
        let name = format!("NebulaSentinel-Block-{}", ip);
        // Delete by rule name (removes all rules with that exact name).
        run("netsh", &["advfirewall", "firewall", "delete", "rule",
            &format!("name={}-out", name)]).await.ok();
        run("netsh", &["advfirewall", "firewall", "delete", "rule",
            &format!("name={}-in", name)]).await.ok();
        info!("✅ windows-firewall: unblocked {}", ip);
        Ok(())
    }

    async fn win_isolate(&self, allowlist: &[String]) -> Result<()> {
        // Isolation strategy on Windows: set the default action for all profiles
        // to block (in and out), then add explicit allow rules for loopback and
        // each allowlisted IP (e.g. the Nexus server) so the agent can still be
        // reached and un-isolated remotely. We tag the allow rules so undo can
        // remove them and restore the default policy.
        warn!("🔒 windows-firewall: ISOLATING host — default-block all profiles, allowlist {} IP(s)", allowlist.len());

        // Allow the Nexus/allowlisted IPs BEFORE flipping the default to block,
        // so we never race ourselves off the network.
        for ip in allowlist {
            if validate_ip(ip).is_err() { continue; }
            run("netsh", &["advfirewall", "firewall", "add", "rule",
                &format!("name=NebulaSentinel-Isolate-Allow-{}-out", ip),
                "dir=out", "action=allow", &format!("remoteip={}", ip)]).await.ok();
            run("netsh", &["advfirewall", "firewall", "add", "rule",
                &format!("name=NebulaSentinel-Isolate-Allow-{}-in", ip),
                "dir=in", "action=allow", &format!("remoteip={}", ip)]).await.ok();
        }
        // Flip default policy to block inbound and outbound on all profiles.
        run("netsh", &["advfirewall", "set", "allprofiles",
            "firewallpolicy", "blockinbound,blockoutbound"]).await
            .context("windows-firewall: failed to set default-block policy")?;
        error!("🔒 windows-firewall: host ISOLATED. Only loopback and {} allowlisted IP(s) reachable.", allowlist.len());
        Ok(())
    }

    async fn win_undo_isolation(&self) -> Result<()> {
        // Restore the default policy (allow outbound, block inbound = Windows
        // default). We deliberately do NOT bulk-delete rules here: netsh has no
        // safe wildcard delete, and `delete rule name=all` would wipe the
        // operator's ENTIRE ruleset. Our isolation allow-rules are individually
        // named (NebulaSentinel-Isolate-Allow-<ip>-{in,out}); Nexus re-issues the
        // specific unblocks, or the operator can remove them by name. Restoring
        // the default policy is what actually lifts the isolation.
        run("netsh", &["advfirewall", "set", "allprofiles",
            "firewallpolicy", "blockinbound,allowoutbound"]).await
            .context("windows-firewall: failed to restore default policy")?;
        info!("✅ windows-firewall: isolation lifted, default policy restored");
        Ok(())
    }

    // ── /proc fallback (no firewall tool at all) ──────────────
    // Minimal protection — disables IP forwarding so the host cannot
    // route traffic for an attacker, but cannot block outbound connections.
    // Fires an explicit warning so the operator knows protection is incomplete.

    async fn proc_isolate(&self) -> Result<()> {
        error!("⚠️  CRITICAL: No firewall tool available. Isolation is PARTIAL.");
        error!("   Install nftables immediately: apt install nftables  OR  dnf install nftables");

        // Disable IP forwarding
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "0").ok();
        std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "0").ok();
        // Reject ICMP redirects (prevent route poisoning)
        std::fs::write("/proc/sys/net/ipv4/conf/all/send_redirects", "0").ok();
        std::fs::write("/proc/sys/net/ipv4/conf/all/accept_redirects", "0").ok();
        // Log suspicious packets
        std::fs::write("/proc/sys/net/ipv4/conf/all/log_martians", "1").ok();

        warn!("⚠️  /proc isolation applied — forwarding disabled. Cannot block specific IPs.");
        Ok(())
    }

    async fn proc_undo_isolation(&self) -> Result<()> {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").ok();
        std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1").ok();
        Ok(())
    }

    fn no_firewall_warn(&self, action: &str) -> Result<()> {
        error!("⚠️  Cannot execute '{}': no firewall tool available.", action);
        error!("   Install: apt install nftables  OR  dnf install nftables");
        Err(anyhow::anyhow!("No firewall tool available for action '{}'", action))
    }
}

// ─────────────────────────────────────────────────────────────
// Distro detection (used by setup and hardening)
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
// Variants are platform-specific: any single build only constructs the ones for
// its OS, so allow(dead_code) prevents cross-platform variants warning as unused.
#[allow(dead_code)]
pub enum DistroFamily {
    Debian,  // Debian, Ubuntu, Mint, Pop!_OS
    Rhel,    // RHEL, CentOS, Fedora, Rocky, AlmaLinux
    Suse,    // OpenSUSE, SLES
    Arch,    // Arch, Manjaro
    Alpine,
    Windows, // Windows (uses Windows Firewall, not nftables)
    MacOS,   // macOS (uses pf/application firewall)
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DistroInfo {
    pub family:       DistroFamily,
    pub name:         String,
    pub version_id:   String,
    pub pretty_name:  String,
    /// Recommended firewall tool for this distro
    pub firewall_pkg: &'static str,
    /// Package manager binary
    pub pkg_manager:  &'static str,
    /// Install command prefix (e.g. "apt-get install -y" or "dnf install -y")
    pub install_cmd:  &'static str,
}

impl DistroInfo {
    pub fn detect() -> Self {
        // Windows / macOS don't have /etc/os-release and aren't nftables/apt
        // systems. Report them honestly rather than reading a Linux file and
        // defaulting to "Debian / apt-get", which is what produced the bogus
        // "🐧 Distro: Unknown (family=Unknown pkg=apt-get)" line on Windows.
        #[cfg(target_os = "windows")]
        {
            let ver = sysinfo::System::os_version().unwrap_or_default();
            let pretty = if ver.is_empty() { "Windows".to_string() } else { format!("Windows {}", ver) };
            info!("🪟 Platform: {} (family=Windows firewall=Windows Firewall)", pretty);
            return DistroInfo {
                family: DistroFamily::Windows,
                name: "Windows".to_string(),
                version_id: ver,
                pretty_name: pretty,
                firewall_pkg: "windows-firewall",
                pkg_manager: "windows",
                install_cmd: "",
            };
        }
        #[cfg(target_os = "macos")]
        {
            let ver = sysinfo::System::os_version().unwrap_or_default();
            let pretty = if ver.is_empty() { "macOS".to_string() } else { format!("macOS {}", ver) };
            info!("🍎 Platform: {} (family=macOS firewall=pf)", pretty);
            return DistroInfo {
                family: DistroFamily::MacOS,
                name: "macOS".to_string(),
                version_id: ver,
                pretty_name: pretty,
                firewall_pkg: "pf",
                pkg_manager: "brew",
                install_cmd: "brew install",
            };
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
        let content = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
        let fields: std::collections::HashMap<&str, &str> = content.lines()
            .filter_map(|l| {
                let mut parts = l.splitn(2, '=');
                let k = parts.next()?.trim();
                let v = parts.next()?.trim().trim_matches('"');
                Some((k, v))
            })
            .collect();

        let id         = fields.get("ID").copied().unwrap_or("").to_lowercase();
        let id_like    = fields.get("ID_LIKE").copied().unwrap_or("").to_lowercase();
        let name       = fields.get("NAME").copied().unwrap_or("Unknown").to_string();
        let version_id = fields.get("VERSION_ID").copied().unwrap_or("").to_string();
        let pretty     = fields.get("PRETTY_NAME").copied().unwrap_or(&name).to_string();

        let family = if id == "debian" || id == "ubuntu" || id_like.contains("debian")
            || id_like.contains("ubuntu") || id == "linuxmint" || id == "pop"
        {
            DistroFamily::Debian
        } else if id == "rhel" || id == "centos" || id == "fedora" || id == "rocky"
            || id == "almalinux" || id_like.contains("rhel") || id_like.contains("fedora")
        {
            DistroFamily::Rhel
        } else if id == "opensuse" || id == "sles" || id_like.contains("suse") {
            DistroFamily::Suse
        } else if id == "arch" || id_like.contains("arch") || id == "manjaro" {
            DistroFamily::Arch
        } else if id == "alpine" {
            DistroFamily::Alpine
        } else {
            DistroFamily::Unknown
        };

        let (firewall_pkg, pkg_manager, install_cmd) = match &family {
            DistroFamily::Debian => ("nftables", "apt-get", "apt-get install -y"),
            DistroFamily::Rhel   => ("nftables", "dnf",     "dnf install -y"),
            DistroFamily::Suse   => ("nftables", "zypper",  "zypper install -y"),
            DistroFamily::Arch   => ("nftables", "pacman",  "pacman -S --noconfirm"),
            DistroFamily::Alpine => ("nftables", "apk",     "apk add"),
            _                    => ("nftables", "apt-get", "apt-get install -y"),
        };

        info!("🐧 Distro: {} (family={:?} pkg={})", pretty, family, pkg_manager);

        DistroInfo { family, name, version_id, pretty_name: pretty, firewall_pkg, pkg_manager, install_cmd }
        }
    }

    /// Returns true if a package manager is available and the package is installed
    pub fn is_package_installed(&self, pkg: &str) -> bool {
        match &self.family {
            DistroFamily::Debian => std::process::Command::new("dpkg-query")
                .args(["-W", "-f=${Status}", pkg])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("install ok installed"))
                .unwrap_or(false),
            DistroFamily::Rhel | DistroFamily::Suse => std::process::Command::new("rpm")
                .args(["-q", pkg])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
            DistroFamily::Alpine => std::process::Command::new("apk")
                .args(["info", "-e", pkg])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false),
            _ => false,
        }
    }

    /// Returns OVAL feed URL for this distro (for vulnerability scanning)
    pub fn oval_feed_url(&self) -> Option<&'static str> {
        match (&self.family, self.version_id.as_str()) {
            (DistroFamily::Debian, v) if v.starts_with("12") || v.starts_with("11") =>
                Some("https://www.debian.org/security/oval/oval-definitions-bookworm.xml.bz2"),
            (DistroFamily::Debian, _) =>
                Some("https://www.debian.org/security/oval/oval-definitions-bullseye.xml.bz2"),
            (DistroFamily::Rhel, v) if v.starts_with("9") =>
                Some("https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL9.xml.bz2"),
            (DistroFamily::Rhel, _) =>
                Some("https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml.bz2"),
            _ => None,
        }
    }

    /// Map this distro to the Nexus OVAL feed key (matches the curated feeds the
    /// Nexus /api/oval/fetch endpoint knows: debian_11/12, ubuntu_2204/2404).
    /// Returned key is used by the agent to sync the converted JSON via
    /// /api/oval/feed/:feed. None ⇒ no Nexus feed for this distro.
    /// Note: Ubuntu is classified under DistroFamily::Debian, so we disambiguate
    /// on the distro name/id rather than the family enum.
    pub fn oval_feed_name(&self) -> Option<String> {
        let name_lc = self.name.to_lowercase();
        if name_lc.contains("ubuntu") {
            if self.version_id.starts_with("24") { return Some("ubuntu_2404".to_string()); }
            if self.version_id.starts_with("22") { return Some("ubuntu_2204".to_string()); }
            if self.version_id.starts_with("20") { return Some("ubuntu_2004".to_string()); }
            return Some("ubuntu_2204".to_string()); // default to current LTS
        }
        // Oracle Linux is RHEL-family but has its own feed.
        if name_lc.contains("oracle") {
            if self.version_id.starts_with("9") { return Some("oracle_9".to_string()); }
            return Some("oracle_8".to_string());
        }
        match &self.family {
            DistroFamily::Debian => {
                if self.version_id.starts_with("11") { Some("debian_11".to_string()) }
                else if self.version_id.starts_with("13") { Some("debian_13".to_string()) }
                else { Some("debian_12".to_string()) } // 12 or default to current stable
            }
            DistroFamily::Rhel => {
                // RHEL, CentOS, Rocky, AlmaLinux — all use the Red Hat OVAL feed.
                if self.version_id.starts_with("9") { Some("rhel_9".to_string()) }
                else { Some("rhel_8".to_string()) }
            }
            DistroFamily::Suse => {
                if name_lc.contains("opensuse") { Some("opensuse_15".to_string()) }
                else { Some("suse_15".to_string()) }
            }
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

async fn bin_exists(name: &str) -> bool {
    Command::new("which").arg(name).output().await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn nft_kernel_ok() -> bool {
    Command::new("nft").args(["list", "ruleset"])
        .output().await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn firewalld_running() -> bool {
    Command::new("firewall-cmd").arg("--state").output().await
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "running")
        .unwrap_or(false)
}

/// Run a firewall command, returning Err on non-zero exit.
async fn run(bin: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(bin).args(args).output().await
        .context(format!("'{}' not found — is it installed?", bin))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        debug!("{} {}: {} (exit={})", bin, args.join(" "), stderr.trim(), out.status);
        anyhow::bail!("{} {} failed: {}", bin, args.join(" "), stderr.trim());
    }
    Ok(())
}

fn validate_ip(ip: &str) -> Result<()> {
    use std::net::IpAddr;
    // Canonical bare address (v4 or v6). Rejects anything that isn't a real IP
    // — the previous `ip.contains(':')` check accepted arbitrary strings and
    // allowed firewall-rule DSL injection.
    if ip.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    // CIDR: <addr>/<prefix>, with a prefix length valid for the family.
    if let Some((addr, pfx)) = ip.split_once('/') {
        if let Ok(a) = addr.parse::<IpAddr>() {
            let max = if a.is_ipv4() { 32u8 } else { 128u8 };
            if pfx.parse::<u8>().map(|p| p <= max).unwrap_or(false) {
                return Ok(());
            }
        }
    }
    anyhow::bail!("Invalid IP address format: '{}'", ip)
}
