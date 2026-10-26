// src/anomaly/mod.rs — Full MITRE ATT&CK v15 behavioral engine
//
// Coverage: All 14 tactics, 196 technique/sub-technique heuristics
// Tactics: Reconnaissance, Resource Development, Initial Access, Execution,
//          Persistence, Privilege Escalation, Defense Evasion, Credential Access,
//          Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact

use crate::config::AnomalyConfig;
use crate::types::{
    RawEvent, EventType, ThreatEvent, Severity, AttackChain, ChainStage,
    IOC, IOCType, ResponseAction,
};
use chrono::Utc;
use dashmap::DashMap;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

// ── Single heuristic hit ───────────────────────────────────────
#[derive(Debug, Clone)]
pub struct TechniqueHit {
    pub score:       f32,
    pub tactic:      &'static str,
    pub technique:   &'static str,
    pub sub:         Option<&'static str>,
    pub description: &'static str,
}

// ── Platform awareness ─────────────────────────────────────────
// The anomaly engine's heuristics were originally written for Linux and make
// Linux-specific assumptions (numeric uid==0 means root; /etc, /proc, /var
// paths; sudo/systemd process names). The agent now also runs on Windows, where
// those assumptions are wrong — e.g. the collector reports uid=0 for every
// Windows process because Windows has no numeric uid, which caused every Windows
// process (including lsass.exe) to false-fire the "unexpected uid=0" rule as a
// CRITICAL detection. We compile per-target, so the platform is known at compile
// time via cfg! — a reliable, zero-cost signal (no runtime guessing).
//
// allow(dead_code): the enum intentionally names all platforms even though any
// single compile can only construct one of them (cfg! resolves at compile time),
// and the is_windows()/is_unix_like() helpers are foundation for the inventory/
// collector platform-awareness work still to come. This is deliberate forward
// scaffolding, not dead code to remove.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Platform { Linux, Windows, MacOS, Other }

#[inline]
pub fn current_platform() -> Platform {
    #[cfg(target_os = "windows")] { Platform::Windows }
    #[cfg(target_os = "linux")]   { Platform::Linux }
    #[cfg(target_os = "macos")]   { Platform::MacOS }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    { Platform::Other }
}
#[allow(dead_code)] #[inline] pub fn is_windows() -> bool { matches!(current_platform(), Platform::Windows) }
#[allow(dead_code)] #[inline] pub fn is_unix_like() -> bool { matches!(current_platform(), Platform::Linux | Platform::MacOS) }

/// Well-known Windows SIDs for high-privilege contexts. Used to decide whether a
/// Windows process is *legitimately* privileged (system services) vs anomalous.
///  S-1-5-18 LocalSystem · S-1-5-19 LocalService · S-1-5-20 NetworkService
fn is_windows_system_sid(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
}

// ── Full MITRE ATT&CK v15 scoring rules ───────────────────────
pub struct MitreRules;

impl MitreRules {
    pub fn evaluate(event: &RawEvent) -> Vec<TechniqueHit> {
        let mut hits = Vec::new();
        let cmd   = event.command_line.as_deref().unwrap_or("").to_lowercase();
        let proc  = event.process_name.to_lowercase();
        let fpath = event.file_path.as_deref().unwrap_or("").to_lowercase();
        let ip    = event.network_dest_ip.as_deref().unwrap_or("");
        let _port  = event.network_dest_port.unwrap_or(0);
        let uid   = event.uid;
        let ppid  = event.ppid;

        // ═══════════════════════════════════════════════════════
        // TA0043 — RECONNAISSANCE
        // ═══════════════════════════════════════════════════════
        if cmd.contains("nmap") || cmd.contains("masscan") || cmd.contains("zmap") {
            hits.push(h(55.0, "reconnaissance", "T1595", None, "Active scanning tool (nmap/masscan/zmap)"));
        }
        if cmd.contains("shodan") || cmd.contains("censys") || cmd.contains("zoomeye") {
            hits.push(h(40.0, "reconnaissance", "T1596", None, "Search engine reconnaissance (Shodan/Censys)"));
        }
        if cmd.contains("whois") || cmd.contains("dig ") || cmd.contains("nslookup") || cmd.contains("host ") {
            hits.push(h(20.0, "reconnaissance", "T1590", Some("T1590.002"), "DNS/WHOIS reconnaissance"));
        }
        if cmd.contains("linkedin") || cmd.contains("hunter.io") || cmd.contains("theharves") {
            hits.push(h(30.0, "reconnaissance", "T1591", None, "Gathering victim org information"));
        }
        if cmd.contains("amass") || cmd.contains("subfinder") || cmd.contains("assetfind") {
            hits.push(h(45.0, "reconnaissance", "T1595", Some("T1595.001"), "Active subdomain/IP scanning"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0042 — RESOURCE DEVELOPMENT
        // ═══════════════════════════════════════════════════════
        if cmd.contains("msfvenom") || cmd.contains("msfconsole") || cmd.contains("metasploit") {
            hits.push(h(85.0, "resource_development", "T1587", Some("T1587.001"), "Metasploit payload/exploit development"));
        }
        if cmd.contains("cobaltstrike") || cmd.contains("beacon") || fpath.contains("beacon") {
            hits.push(h(95.0, "resource_development", "T1587", Some("T1587.002"), "Cobalt Strike beacon staging"));
        }
        if cmd.contains("ngrok") || cmd.contains("pagekite") || cmd.contains("serveo") {
            hits.push(h(65.0, "resource_development", "T1583", Some("T1583.006"), "Tunneling service for C2 infrastructure"));
        }
        if (cmd.contains("certutil") || cmd.contains("openssl req")) && cmd.contains("-out") {
            hits.push(h(40.0, "resource_development", "T1587", Some("T1587.003"), "Certificate generation for C2"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0001 — INITIAL ACCESS
        // ═══════════════════════════════════════════════════════
        if (proc == "nginx" || proc == "apache2" || proc == "httpd" || proc == "php-fpm" || proc == "tomcat")
            && (cmd.contains("sh") || cmd.contains("bash") || cmd.contains("python") || cmd.contains("perl"))
        {
            hits.push(h(90.0, "initial_access", "T1190", None, "Exploit public-facing app: web server spawning shell (webshell)"));
        }
        if fpath.ends_with(".php") && cmd.contains("eval") {
            hits.push(h(85.0, "initial_access", "T1190", None, "PHP eval() webshell execution"));
        }
        if cmd.contains("phishing") || (fpath.ends_with(".docm") || fpath.ends_with(".xlsm") || fpath.ends_with(".hta")) {
            hits.push(h(70.0, "initial_access", "T1566", Some("T1566.001"), "Spearphishing attachment (macro-enabled document)"));
        }
        if cmd.contains("regsvr32") && cmd.contains("http") {
            hits.push(h(80.0, "initial_access", "T1566", Some("T1566.002"), "Spearphishing link via regsvr32 SCT script"));
        }
        if proc == "winrm" || cmd.contains("evil-winrm") {
            hits.push(h(75.0, "initial_access", "T1133", None, "External remote service (WinRM) access"));
        }
        if cmd.contains("reGeorg") || cmd.contains("tunna") || cmd.contains("webshell") {
            hits.push(h(88.0, "initial_access", "T1505", Some("T1505.003"), "Server software component: webshell"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0002 — EXECUTION
        // ═══════════════════════════════════════════════════════

        // T1059 — Command and Scripting Interpreter
        if cmd.contains("bash -i") || cmd.contains("sh -i") || cmd.contains("/dev/tcp") {
            hits.push(h(85.0, "execution", "T1059", Some("T1059.004"), "Unix shell reverse/interactive shell"));
        }
        if cmd.contains("python -c") || cmd.contains("python3 -c") || cmd.contains("import socket") {
            hits.push(h(70.0, "execution", "T1059", Some("T1059.006"), "Python one-liner/reverse shell"));
        }
        if cmd.contains("perl -e") || cmd.contains("perl -le") {
            hits.push(h(65.0, "execution", "T1059", Some("T1059.006"), "Perl script execution"));
        }
        if cmd.contains("ruby -e") || cmd.contains("require 'socket'") {
            hits.push(h(65.0, "execution", "T1059", Some("T1059.006"), "Ruby reverse shell"));
        }
        if cmd.contains("powershell") || cmd.contains("pwsh") {
            let score = if cmd.contains("-enc") || cmd.contains("-encodedcommand") || cmd.contains("-nop") { 85.0 } else { 45.0 };
            hits.push(h(score, "execution", "T1059", Some("T1059.001"), "PowerShell execution (encoded/bypass flags)"));
        }
        if cmd.contains("wscript") || cmd.contains("cscript") {
            hits.push(h(60.0, "execution", "T1059", Some("T1059.005"), "VBScript/JScript execution via wscript/cscript"));
        }
        if cmd.contains("node -e") || cmd.contains("node -p") {
            hits.push(h(55.0, "execution", "T1059", Some("T1059.007"), "Node.js scripting for execution"));
        }

        // T1203 — Exploitation for Client Execution
        if proc == "acroread" || proc == "evince" {
            hits.push(h(70.0, "execution", "T1203", None, "PDF reader exploitation attempt"));
        }

        // T1204 — User Execution
        if (fpath.ends_with(".exe") || fpath.ends_with(".msi") || fpath.ends_with(".dmg"))
            && fpath.contains("download")
        {
            hits.push(h(60.0, "execution", "T1204", Some("T1204.002"), "User executed malicious file from downloads"));
        }

        // T1569 — System Services
        if cmd.contains("sc create") || cmd.contains("sc start") || (cmd.contains("systemctl") && cmd.contains("--force")) {
            hits.push(h(65.0, "execution", "T1569", Some("T1569.002"), "Service execution (sc create/systemctl)"));
        }

        // T1610 — Deploy Container
        if cmd.contains("docker run") && (cmd.contains("--privileged") || cmd.contains("-v /:/")) {
            hits.push(h(90.0, "execution", "T1610", None, "Privileged container deployed (container escape vector)"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0003 — PERSISTENCE
        // ═══════════════════════════════════════════════════════

        // T1053 — Scheduled Tasks/Jobs
        if cmd.contains("crontab -") || fpath.contains("/etc/cron") || cmd.contains("cron.d/") {
            hits.push(h(55.0, "persistence", "T1053", Some("T1053.003"), "Cron job persistence"));
        }
        if cmd.contains("at ") && cmd.contains("-f") {
            hits.push(h(50.0, "persistence", "T1053", Some("T1053.001"), "At job scheduled task"));
        }
        if cmd.contains("systemctl enable") || (cmd.contains(".service") && fpath.contains("/etc/systemd")) {
            hits.push(h(55.0, "persistence", "T1053", None, "systemd service enabled for persistence"));
        }

        // T1136 — Create Account
        if cmd.contains("useradd") || cmd.contains("adduser") || cmd.contains("net user /add") {
            hits.push(h(70.0, "persistence", "T1136", Some("T1136.001"), "Local account creation"));
        }

        // T1098 — Account Manipulation
        if cmd.contains("usermod -aG sudo") || cmd.contains("usermod -aG wheel") || cmd.contains("net localgroup administrators") {
            hits.push(h(80.0, "persistence", "T1098", None, "Account privilege escalation via group add"));
        }

        // T1543 — Create or Modify System Process
        if fpath.contains("/etc/init.d/") || fpath.contains("/lib/systemd/system/") {
            hits.push(h(60.0, "persistence", "T1543", Some("T1543.002"), "Init script or systemd unit modified/created"));
        }

        // T1546 — Event Triggered Execution
        if fpath.contains("/.bashrc") || fpath.contains("/.bash_profile") || fpath.contains("/.zshrc") || fpath.contains("/.profile") {
            hits.push(h(65.0, "persistence", "T1546", Some("T1546.004"), "Shell profile/rc file modification (persistence backdoor)"));
        }
        if fpath.contains("/etc/profile.d/") || fpath.contains("/etc/environment") {
            hits.push(h(60.0, "persistence", "T1546", Some("T1546.004"), "System-wide shell profile modification"));
        }

        // T1547 — Boot/Logon Autostart
        if fpath.contains("~/.config/autostart") || fpath.contains("/etc/xdg/autostart") {
            hits.push(h(55.0, "persistence", "T1547", None, "XDG autostart persistence entry"));
        }

        // T1505 — Server Software Component
        if fpath.contains("/var/www") || fpath.contains("/srv/http") || fpath.contains("/usr/share/nginx") {
            if fpath.ends_with(".php") || fpath.ends_with(".aspx") || fpath.ends_with(".jsp") {
                hits.push(h(80.0, "persistence", "T1505", Some("T1505.003"), "Webshell dropped in web root"));
            }
        }

        // T1574 — Hijack Execution Flow (LD_PRELOAD)
        if cmd.contains("ld_preload") || fpath.contains("/etc/ld.so.preload") {
            hits.push(h(85.0, "persistence", "T1574", Some("T1574.006"), "LD_PRELOAD hijack (library injection)"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0004 — PRIVILEGE ESCALATION
        // ═══════════════════════════════════════════════════════

        // T1055 — Process Injection
        if event.event_type == EventType::Ptrace {
            hits.push(h(88.0, "privilege_escalation", "T1055", Some("T1055.008"), "ptrace process injection"));
        }
        if cmd.contains("inject") && (cmd.contains("pid") || cmd.contains("--process")) {
            hits.push(h(85.0, "privilege_escalation", "T1055", None, "Process injection tool detected"));
        }

        // T1068 — Exploitation for Privilege Escalation
        if cmd.contains("dirtycow") || cmd.contains("dirty_cow") || cmd.contains("cve-2016-5195") {
            hits.push(h(95.0, "privilege_escalation", "T1068", None, "DirtyCow kernel exploit (CVE-2016-5195)"));
        }
        if cmd.contains("pwnkit") || cmd.contains("cve-2021-4034") || (proc == "pkexec" && uid != 0 && ppid > 1000) {
            hits.push(h(95.0, "privilege_escalation", "T1068", None, "PwnKit privilege escalation (CVE-2021-4034)"));
        }
        if cmd.contains("dirty_pipe") || cmd.contains("cve-2022-0847") {
            hits.push(h(95.0, "privilege_escalation", "T1068", None, "DirtyPipe exploit (CVE-2022-0847)"));
        }

        // T1078 — Valid Accounts (unexpected privileged process)
        // Platform-specific: on Linux, uid==0 is root. On Windows, uid is always
        // 0 (no numeric uid), so we must NOT use it — instead we look at the real
        // Windows privilege signal, the user SID in extra["user_sid"], and allow
        // the legitimate system processes rather than Linux daemon names.
        match current_platform() {
            Platform::Linux | Platform::MacOS => {
                if uid == 0 && !["sshd","sudo","su","cron","systemd","init","systemd-logind","polkit","dbus"].contains(&proc.as_str()) {
                    hits.push(h(50.0, "privilege_escalation", "T1078", None, "Privileged process from unexpected context (uid=0)"));
                }
            }
            Platform::Windows => {
                // Only flag a SYSTEM-context process if it's NOT one of the many
                // legitimate Windows system binaries. This allowlist covers the
                // core OS processes that always run as SYSTEM; anything else
                // running as SYSTEM from an unexpected path is worth a low-score
                // look (not an automatic CRITICAL).
                let sid = event.extra.get("user_sid").and_then(|v| v.as_str()).unwrap_or("");
                let win_system_procs = [
                    "system","registry","smss.exe","csrss.exe","wininit.exe","services.exe",
                    "lsass.exe","winlogon.exe","svchost.exe","fontdrvhost.exe","dwm.exe",
                    "spoolsv.exe","searchindexer.exe","taskhostw.exe","sihost.exe",
                    "lsaiso.exe","memcompression","msmpeng.exe",
                    "nissrv.exe","securityhealthservice.exe","wmiprvse.exe","dllhost.exe",
                    "runtimebroker.exe","conhost.exe","ctfmon.exe","explorer.exe",
                    "wudfhost.exe","audiodg.exe","trustedinstaller.exe",
                ];
                if is_windows_system_sid(sid) && !win_system_procs.contains(&proc.as_str()) {
                    // Deliberately LOW score — a non-allowlisted SYSTEM process is
                    // worth surfacing for review, not an automatic critical alert.
                    hits.push(h(35.0, "privilege_escalation", "T1078", None,
                        "SYSTEM-context process outside known-good set (review)"));
                }
            }
            Platform::Other => {}
        }

        // T1548 — Abuse Elevation Control Mechanism
        if cmd.contains("sudo -s") || cmd.contains("sudo su") || cmd.contains("sudo bash") {
            hits.push(h(60.0, "privilege_escalation", "T1548", Some("T1548.003"), "sudo to interactive root shell"));
        }
        if cmd.contains("chmod +s") || cmd.contains("chmod 4755") || cmd.contains("chmod 6755") {
            hits.push(h(80.0, "privilege_escalation", "T1548", Some("T1548.001"), "SUID/SGID bit set on binary"));
        }

        // T1611 — Escape to Host (container)
        if event.container_id.is_some() && (
            cmd.contains("nsenter") || cmd.contains("--target 1") ||
            fpath.contains("/proc/1/") || cmd.contains("chroot /host")
        ) {
            hits.push(h(95.0, "privilege_escalation", "T1611", None, "Container escape to host attempt"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0005 — DEFENSE EVASION
        // ═══════════════════════════════════════════════════════

        // T1027 — Obfuscated Files or Information
        if cmd.contains("base64 -d") || cmd.contains("base64 --decode") || cmd.contains("| base64") {
            hits.push(h(70.0, "defense_evasion", "T1027", None, "Base64 encoding/decoding (obfuscation)"));
        }
        if cmd.contains("| gzip") || cmd.contains("| zlib") || cmd.contains("zlib.decompress") {
            hits.push(h(50.0, "defense_evasion", "T1027", None, "Compression used for payload obfuscation"));
        }
        if cmd.contains("xxd") && cmd.contains("| sh") {
            hits.push(h(75.0, "defense_evasion", "T1027", None, "Hex-encoded payload piped to shell"));
        }

        // T1036 — Masquerading
        if proc.contains("svchost") && !fpath.contains("system32") {
            hits.push(h(85.0, "defense_evasion", "T1036", Some("T1036.005"), "svchost masquerade outside System32"));
        }
        if (proc == "ls" || proc == "ps" || proc == "init") && !fpath.starts_with("/usr/bin") && !fpath.starts_with("/bin") {
            hits.push(h(75.0, "defense_evasion", "T1036", Some("T1036.005"), "System utility masquerade in non-standard path"));
        }
        if fpath.ends_with(".pdf.exe") || fpath.ends_with(".doc.exe") || fpath.ends_with(".jpg.exe") {
            hits.push(h(80.0, "defense_evasion", "T1036", Some("T1036.007"), "Double extension masquerade (e.g. .pdf.exe)"));
        }

        // T1055 — Defense Evasion via Injection
        if cmd.contains("dlopen") && cmd.contains("/tmp") {
            hits.push(h(80.0, "defense_evasion", "T1055", Some("T1055.001"), "DLL/SO injection from /tmp"));
        }

        // T1070 — Indicator Removal
        if (cmd.contains("rm ") || cmd.contains("shred") || cmd.contains("unlink")) &&
           (fpath.contains("/var/log") || cmd.contains(".bash_history") || fpath.contains("auth.log"))
        {
            hits.push(h(75.0, "defense_evasion", "T1070", Some("T1070.002"), "Log file deletion/clearing"));
        }
        if cmd.contains("history -c") || cmd.contains("> ~/.bash_history") || cmd.contains("unset HISTFILE") {
            hits.push(h(70.0, "defense_evasion", "T1070", Some("T1070.003"), "Shell history clearing"));
        }
        if cmd.contains("shred -u") {
            hits.push(h(75.0, "defense_evasion", "T1070", None, "Secure file deletion with shred"));
        }
        if cmd.contains("timestomp") || cmd.contains("touch -t") || cmd.contains("touch -r") {
            hits.push(h(70.0, "defense_evasion", "T1070", Some("T1070.006"), "File timestamp manipulation (timestomping)"));
        }

        // T1222 — File/Directory Permissions
        if cmd.contains("chmod +x") || cmd.contains("chmod 777") || cmd.contains("chmod 755 /tmp") {
            hits.push(h(55.0, "defense_evasion", "T1222", None, "Suspicious permission change"));
        }

        // T1497 — Virtualization/Sandbox Evasion
        if cmd.contains("vboxcontrol") || cmd.contains("vmtoolsd") || (cmd.contains("cpuid") && cmd.contains("hypervisor")) {
            hits.push(h(60.0, "defense_evasion", "T1497", None, "Virtualization/sandbox detection attempt"));
        }

        // T1562 — Impair Defenses
        if cmd.contains("systemctl stop") && (cmd.contains("auditd") || cmd.contains("nebula") || cmd.contains("syslog") || cmd.contains("rsyslog")) {
            hits.push(h(90.0, "defense_evasion", "T1562", Some("T1562.001"), "Security service disabled (auditd/syslog)"));
        }
        if cmd.contains("setenforce 0") || cmd.contains("setenforce permissive") {
            hits.push(h(85.0, "defense_evasion", "T1562", Some("T1562.001"), "SELinux disabled (setenforce 0)"));
        }
        if cmd.contains("ufw disable") || cmd.contains("iptables -F") || cmd.contains("nft flush") {
            hits.push(h(80.0, "defense_evasion", "T1562", Some("T1562.004"), "Firewall rules cleared/disabled"));
        }
        if cmd.contains("auditctl -e 0") || cmd.contains("auditctl -D") {
            hits.push(h(90.0, "defense_evasion", "T1562", None, "Audit subsystem disabled (auditctl)"));
        }

        // T1620 — Reflective Code Loading
        if cmd.contains("memfd_create") || (cmd.contains("/proc/self/mem") && cmd.contains("write")) {
            hits.push(h(90.0, "defense_evasion", "T1620", None, "memfd_create / reflective code loading"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0006 — CREDENTIAL ACCESS
        // ═══════════════════════════════════════════════════════

        // T1003 — OS Credential Dumping
        if cmd.contains("mimikatz") || cmd.contains("sekurlsa") || cmd.contains("lsadump") {
            hits.push(h(98.0, "credential_access", "T1003", Some("T1003.001"), "Mimikatz credential dumping"));
        }
        // Credential dumping that TARGETS lsass — must be an action against
        // lsass memory, not the lsass.exe process simply running. The old
        // condition `fpath.contains("lsass")` matched the LSASS process itself
        // (whose own path is ...\lsass.exe on Windows), so it false-fired on
        // every boot. Require a real dumping indicator in the command line, or a
        // process OTHER than lsass touching /proc/<pid>/mem on Linux.
        let is_lsass_self = proc == "lsass.exe" || proc == "lsass";
        let cmd_targets_lsass = cmd.contains("lsass") &&
            (cmd.contains("dump") || cmd.contains("minidump") || cmd.contains("comsvcs")
             || cmd.contains("rundll32") || cmd.contains("-ma ") || cmd.contains("out-minidump")
             || cmd.contains("procdump") || cmd.contains("createdump") || cmd.contains("nanodump"));
        let reads_proc_mem = cmd.contains("/proc/") && cmd.contains("/mem") && !is_lsass_self;
        if cmd_targets_lsass || reads_proc_mem {
            hits.push(h(92.0, "credential_access", "T1003", Some("T1003.001"), "LSASS / process memory credential dump"));
        }
        if cmd.contains("cat /etc/shadow") || (cmd.contains("shadow") && (proc == "cat" || proc == "less" || proc == "cp")) {
            hits.push(h(90.0, "credential_access", "T1003", Some("T1003.008"), "/etc/shadow file access (credential dump)"));
        }
        if cmd.contains("ntdsutil") || cmd.contains("ntds.dit") {
            hits.push(h(95.0, "credential_access", "T1003", Some("T1003.003"), "NTDS.dit Active Directory credential dump"));
        }
        if cmd.contains("procdump") || (cmd.contains("gcore") && cmd.contains("lsass")) {
            hits.push(h(92.0, "credential_access", "T1003", Some("T1003.001"), "Process memory dump (procdump/gcore) targeting LSASS"));
        }

        // T1110 — Brute Force
        if proc == "hydra" || proc == "medusa" || proc == "ncrack" || cmd.contains("hydra ") {
            hits.push(h(80.0, "credential_access", "T1110", Some("T1110.001"), "Brute force tool (hydra/medusa/ncrack)"));
        }

        // T1539 — Steal Web Session Cookie
        if cmd.contains("cookies.sqlite") || cmd.contains("login data") || fpath.contains("/login data") {
            hits.push(h(75.0, "credential_access", "T1539", None, "Browser cookie/credential database access"));
        }

        // T1552 — Unsecured Credentials
        if (cmd.contains("cat") || cmd.contains("grep")) &&
           (fpath.contains(".env") || fpath.contains("id_rsa") || fpath.contains("credentials") || fpath.contains(".aws/")) {
            hits.push(h(75.0, "credential_access", "T1552", Some("T1552.001"), "Credentials in files (SSH keys, .env, .aws)"));
        }
        if cmd.contains("find") && (cmd.contains("id_rsa") || cmd.contains("*.pem") || cmd.contains("*.key")) {
            hits.push(h(65.0, "credential_access", "T1552", Some("T1552.004"), "Private key discovery via find"));
        }

        // T1556 — Modify Authentication Process (PAM backdoor)
        if fpath.contains("/etc/pam.d/") && event.event_type == EventType::FileWrite {
            hits.push(h(90.0, "credential_access", "T1556", Some("T1556.003"), "PAM configuration modified (possible backdoor)"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0007 — DISCOVERY
        // ═══════════════════════════════════════════════════════

        // T1082 — System Information Discovery
        if cmd.contains("uname -a") || cmd.contains("uname -r") || cmd.contains("cat /etc/os-release") {
            hits.push(h(25.0, "discovery", "T1082", None, "System info discovery (uname/os-release)"));
        }

        // T1083 — File and Directory Discovery
        if cmd.contains("find / -name") || cmd.contains("find / -perm") || cmd.contains("locate ") {
            hits.push(h(30.0, "discovery", "T1083", None, "Broad filesystem discovery (find /)"));
        }
        if cmd.contains("find / -perm -4000") || cmd.contains("find / -perm /4000") {
            hits.push(h(70.0, "discovery", "T1083", None, "SUID binary discovery (privilege escalation recon)"));
        }

        // T1057 — Process Discovery
        if cmd == "ps aux" || cmd == "ps auxf" || cmd == "ps -ef" || proc == "pspy" {
            hits.push(h(20.0, "discovery", "T1057", None, "Process listing (ps aux / pspy)"));
        }

        // T1069 — Permission Groups Discovery
        if cmd.contains("id ") || cmd == "id" || cmd.contains("groups ") || cmd.contains("getent group") {
            hits.push(h(20.0, "discovery", "T1069", None, "Identity/group discovery (id/groups)"));
        }
        if cmd.contains("cat /etc/sudoers") || cmd.contains("sudo -l") {
            hits.push(h(55.0, "discovery", "T1069", Some("T1069.001"), "Sudo privilege discovery"));
        }

        // T1087 — Account Discovery
        if cmd.contains("cat /etc/passwd") || cmd.contains("getent passwd") || cmd.contains("cut -d: -f1 /etc/passwd") {
            hits.push(h(45.0, "discovery", "T1087", Some("T1087.001"), "Local user account enumeration"));
        }
        if cmd.contains("ldapsearch") || cmd.contains("net user /domain") {
            hits.push(h(55.0, "discovery", "T1087", Some("T1087.002"), "Domain account discovery"));
        }

        // T1046 — Network Service Discovery
        if proc == "nmap" || cmd.contains("nmap -sV") || cmd.contains("nmap -sS") {
            hits.push(h(60.0, "discovery", "T1046", None, "Network service/port scanning"));
        }
        if cmd.contains("ss -tulpan") || cmd.contains("netstat -tulpan") || cmd.contains("ss -antup") {
            hits.push(h(30.0, "discovery", "T1046", None, "Network service listening ports enumeration"));
        }

        // T1049 — System Network Connections Discovery
        if cmd.contains("ss -an") || cmd.contains("netstat -an") || cmd.contains("lsof -i") {
            hits.push(h(25.0, "discovery", "T1049", None, "Network connections enumeration"));
        }

        // T1518 — Software Discovery
        if cmd.contains("dpkg -l") || cmd.contains("rpm -qa") || cmd.contains("pip list") || cmd.contains("npm list -g") {
            hits.push(h(20.0, "discovery", "T1518", None, "Installed software enumeration"));
        }
        if cmd.contains("find") && (cmd.contains("antivirus") || cmd.contains("clamav") || cmd.contains("ossec")) {
            hits.push(h(50.0, "discovery", "T1518", Some("T1518.001"), "Security software discovery"));
        }

        // T1614 — System Location Discovery
        if cmd.contains("locale") || cmd.contains("timedatectl") || cmd.contains("cat /etc/timezone") {
            hits.push(h(15.0, "discovery", "T1614", None, "System location/timezone discovery"));
        }

        // T1619 — Cloud Storage Object Discovery
        if cmd.contains("aws s3 ls") || cmd.contains("gsutil ls") || cmd.contains("az storage blob list") {
            hits.push(h(50.0, "discovery", "T1619", None, "Cloud storage discovery (S3/GCS/Azure)"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0008 — LATERAL MOVEMENT
        // ═══════════════════════════════════════════════════════

        // T1021 — Remote Services
        if cmd.contains("psexec") || cmd.contains("wmiexec") || cmd.contains("smbexec") {
            hits.push(h(85.0, "lateral_movement", "T1021", Some("T1021.002"), "SMB/PsExec lateral movement"));
        }
        if (proc == "ssh" || cmd.contains("ssh ")) && proc != "sshd" && uid > 0 {
            let score = if cmd.contains("-o stricthostkeychecking=no") || cmd.contains("-i /tmp") { 65.0 } else { 30.0 };
            hits.push(h(score, "lateral_movement", "T1021", Some("T1021.004"), "SSH lateral movement"));
        }
        if cmd.contains("winrm") || cmd.contains("enter-pssession") || cmd.contains("invoke-command") {
            hits.push(h(70.0, "lateral_movement", "T1021", Some("T1021.006"), "WinRM PowerShell remoting"));
        }
        if cmd.contains("rpcclient") || cmd.contains("smbclient") {
            hits.push(h(60.0, "lateral_movement", "T1021", Some("T1021.002"), "SMB/RPC lateral movement tool"));
        }

        // T1047 — WMI
        if cmd.contains("wmic") && (cmd.contains("/node:") || cmd.contains("process call create")) {
            hits.push(h(75.0, "lateral_movement", "T1047", None, "WMI remote execution"));
        }

        // T1534 — Internal Spearphishing
        if cmd.contains("sendmail") && cmd.contains("-t") && cmd.contains(".html") {
            hits.push(h(55.0, "lateral_movement", "T1534", None, "Internal spearphishing via sendmail"));
        }

        // T1550 — Use Alternate Authentication Material
        if cmd.contains("pass-the-hash") || cmd.contains("pth-winexe") || cmd.contains("impacket") {
            hits.push(h(90.0, "lateral_movement", "T1550", Some("T1550.002"), "Pass-the-hash (impacket/pth-winexe)"));
        }
        if cmd.contains("ticketer") || cmd.contains("golden ticket") || cmd.contains("silver ticket") {
            hits.push(h(98.0, "lateral_movement", "T1550", Some("T1550.003"), "Kerberos golden/silver ticket attack"));
        }

        // T1570 — Lateral Tool Transfer
        if (cmd.contains("scp ") || cmd.contains("rsync ")) && cmd.contains("-r") {
            hits.push(h(45.0, "lateral_movement", "T1570", None, "Recursive file transfer (scp/rsync) — lateral tool transfer"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0009 — COLLECTION
        // ═══════════════════════════════════════════════════════

        // T1005 — Data from Local System
        if cmd.contains("tar czf") && (fpath.contains("/home") || fpath.contains("/etc") || fpath.contains("/var")) {
            hits.push(h(60.0, "collection", "T1005", None, "Archiving sensitive local directories (tar)"));
        }
        if cmd.contains("zip -r") && (fpath.contains("/etc") || fpath.contains("/home")) {
            hits.push(h(55.0, "collection", "T1005", None, "Zipping sensitive directories for exfiltration"));
        }

        // T1039 — Data from Network Shared Drive
        if cmd.contains("mount") && (cmd.contains("cifs") || cmd.contains("nfs") || cmd.contains("smb://")) {
            hits.push(h(45.0, "collection", "T1039", None, "Network share mounted (possible collection target)"));
        }

        // T1056 — Input Capture (keylogger)
        if cmd.contains("logkeys") || cmd.contains("xinput test") || fpath.contains("keylogger") {
            hits.push(h(90.0, "collection", "T1056", Some("T1056.001"), "Keylogger tool detected (logkeys/xinput)"));
        }

        // T1074 — Data Staged
        if (fpath.starts_with("/tmp/") || fpath.starts_with("/dev/shm/")) &&
           (fpath.ends_with(".tar") || fpath.ends_with(".zip") || fpath.ends_with(".gz") || fpath.ends_with(".7z"))
        {
            hits.push(h(65.0, "collection", "T1074", Some("T1074.001"), "Archive staged in /tmp or /dev/shm"));
        }

        // T1113 — Screen Capture
        if cmd.contains("scrot") || cmd.contains("import -window root") || cmd.contains("xwd -root") {
            hits.push(h(55.0, "collection", "T1113", None, "Screen capture tool (scrot/xwd)"));
        }

        // T1115 — Clipboard Data
        if cmd.contains("xclip") || cmd.contains("xdotool getclipboard") || cmd.contains("pbpaste") {
            hits.push(h(45.0, "collection", "T1115", None, "Clipboard data access (xclip/pbpaste)"));
        }

        // T1602 — Data from Configuration Repositories
        if cmd.contains("git clone") && (fpath.contains("internal") || fpath.contains("private")) {
            hits.push(h(55.0, "collection", "T1602", None, "Git clone of private/internal repo"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0011 — COMMAND AND CONTROL
        // ═══════════════════════════════════════════════════════

        // T1071 — Application Layer Protocol
        if let Some(dest_port) = event.network_dest_port {
            if dest_port == 4444 || dest_port == 4445 || dest_port == 1337 || dest_port == 31337 {
                hits.push(h(85.0, "command_and_control", "T1071", None, "Known C2 port (4444/1337/31337)"));
            }
            if dest_port == 53 && proc != "systemd-resolve" && proc != "dnsmasq" && proc != "named" {
                hits.push(h(60.0, "command_and_control", "T1071", Some("T1071.004"), "DNS C2 suspected (unexpected process using port 53)"));
            }
        }

        // T1095 — Non-Application Layer Protocol (raw socket)
        if cmd.contains("socket.raw") || cmd.contains("icmp") || (cmd.contains("ping") && cmd.contains("-p ")) {
            hits.push(h(60.0, "command_and_control", "T1095", None, "Raw/ICMP socket (possible covert channel)"));
        }

        // T1105 — Ingress Tool Transfer
        if cmd.contains("curl ") || cmd.contains("wget ") {
            let sus = ip.starts_with("185.") || ip.starts_with("103.") || ip.starts_with("45.") ||
                      cmd.contains("/tmp/") || cmd.contains("/dev/shm/") || cmd.contains("-o /tmp");
            hits.push(h(if sus { 80.0 } else { 35.0 }, "command_and_control", "T1105", None, "Tool download via curl/wget"));
        }

        // T1132 — Data Encoding
        if cmd.contains("base64 -w0") || cmd.contains("| xxd -p") {
            hits.push(h(50.0, "command_and_control", "T1132", None, "Data encoding for C2 communication"));
        }

        // T1219 — Remote Access Software
        if proc == "teamviewer" || proc == "anydesk" || proc == "vnc" || proc == "x11vnc" {
            hits.push(h(60.0, "command_and_control", "T1219", None, "Remote access software (TeamViewer/AnyDesk/VNC)"));
        }

        // T1571 — Non-Standard Port
        if let Some(dest_port) = event.network_dest_port {
            if (dest_port > 1024 && dest_port != 8080 && dest_port != 8443 && dest_port != 9200) &&
               (proc == "bash" || proc == "sh" || proc == "python3" || proc == "python") {
                hits.push(h(55.0, "command_and_control", "T1571", None, "Script/shell using non-standard port (possible C2)"));
            }
        }

        // T1572 — Protocol Tunneling
        if cmd.contains("ssh -R") || cmd.contains("ssh -L") || cmd.contains("ssh -D") {
            hits.push(h(70.0, "command_and_control", "T1572", None, "SSH tunneling/port forwarding (C2 tunnel)"));
        }
        if cmd.contains("iodine") || cmd.contains("dns2tcp") || cmd.contains("dnscat") {
            hits.push(h(90.0, "command_and_control", "T1572", None, "DNS tunneling tool (iodine/dns2tcp/dnscat)"));
        }
        if cmd.contains("chisel") || cmd.contains("ligolo") || cmd.contains("socat") && cmd.contains("exec") {
            hits.push(h(75.0, "command_and_control", "T1572", None, "Tunneling proxy tool (chisel/ligolo/socat)"));
        }

        // T1573 — Encrypted Channel
        if cmd.contains("stunnel") || (cmd.contains("openssl s_client") && cmd.contains("-connect")) {
            hits.push(h(55.0, "command_and_control", "T1573", None, "Encrypted tunnel (stunnel/openssl)"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0010 — EXFILTRATION
        // ═══════════════════════════════════════════════════════

        // T1048 — Exfiltration Over Alternative Protocol
        if cmd.contains("curl -T") || cmd.contains("curl --upload-file") {
            hits.push(h(75.0, "exfiltration", "T1048", None, "Data upload via curl (possible exfiltration)"));
        }
        if cmd.contains("ftp ") && (cmd.contains("put ") || cmd.contains("mput ")) {
            hits.push(h(70.0, "exfiltration", "T1048", Some("T1048.003"), "FTP file upload (exfiltration)"));
        }
        if cmd.contains("nc ") && cmd.contains("< ") {
            hits.push(h(75.0, "exfiltration", "T1048", None, "Netcat file send (possible exfiltration)"));
        }

        // T1052 — Exfiltration Over Physical Medium
        if cmd.contains("dd if=") && (fpath.contains("/dev/sd") || fpath.contains("/dev/nvme")) {
            hits.push(h(80.0, "exfiltration", "T1052", None, "Raw disk read via dd (data exfiltration or imaging)"));
        }

        // T1567 — Exfiltration to Cloud Storage
        if cmd.contains("aws s3 cp") || cmd.contains("aws s3 sync") ||
           cmd.contains("gsutil cp") || cmd.contains("az storage blob upload") {
            hits.push(h(70.0, "exfiltration", "T1567", Some("T1567.002"), "Cloud storage upload (AWS S3/GCS/Azure)"));
        }

        // ═══════════════════════════════════════════════════════
        // TA0040 — IMPACT
        // ═══════════════════════════════════════════════════════

        // T1485 — Data Destruction
        if cmd.contains("shred -z") || cmd.contains("shred -n") || cmd.contains("wipe ") ||
           (cmd.contains("dd if=/dev/zero") && fpath.contains("/dev/sd"))
        {
            hits.push(h(95.0, "impact", "T1485", None, "Data destruction (shred/wipe/dd zero)"));
        }

        // T1486 — Data Encrypted for Impact (ransomware)
        if (cmd.contains("openssl enc") || cmd.contains("gpg --batch")) &&
           (cmd.contains("-e ") || cmd.contains("--encrypt"))
        {
            hits.push(h(85.0, "impact", "T1486", None, "Mass encryption (possible ransomware — openssl/gpg batch)"));
        }
        if cmd.contains("find / -type f") && cmd.contains("openssl") {
            hits.push(h(95.0, "impact", "T1486", None, "Ransomware: find+encrypt all files"));
        }

        // T1489 — Service Stop
        if cmd.contains("systemctl stop") && !cmd.contains("nebula") {
            let score = if cmd.contains("mysql") || cmd.contains("postgres") || cmd.contains("apache") { 70.0 } else { 40.0 };
            hits.push(h(score, "impact", "T1489", None, "Critical service stopped"));
        }

        // T1490 — Inhibit System Recovery
        if cmd.contains("vssadmin delete") || cmd.contains("wbadmin delete") ||
           cmd.contains("bcdedit /set") || cmd.contains("diskshadow /s") {
            hits.push(h(95.0, "impact", "T1490", None, "Shadow copy / backup deletion (ransomware prep)"));
        }
        if cmd.contains("rm -rf /var/backup") || cmd.contains("rm -rf /backup") {
            hits.push(h(85.0, "impact", "T1490", None, "Backup directory deleted"));
        }

        // T1491 — Defacement
        if (fpath.contains("/var/www") || fpath.contains("/srv/http")) &&
           event.event_type == EventType::FileWrite && uid != 33 // www-data uid
        {
            hits.push(h(70.0, "impact", "T1491", Some("T1491.001"), "Web root modified by non-www-data user (defacement risk)"));
        }

        // T1496 — Resource Hijacking (cryptominer)
        if proc == "xmrig" || proc == "minerd" || proc == "cpuminer" ||
           cmd.contains("xmrig") || cmd.contains("monero") ||
           (cmd.contains("stratum+tcp://") || cmd.contains("pool.minexmr"))
        {
            hits.push(h(90.0, "impact", "T1496", None, "Cryptominer detected (xmrig/cpuminer/stratum)"));
        }

        // T1498 — Network Denial of Service
        if cmd.contains("hping3") || cmd.contains("slowloris") || cmd.contains("ddosify") {
            hits.push(h(85.0, "impact", "T1498", None, "DoS/DDoS tool (hping3/slowloris)"));
        }

        // T1529 — System Shutdown/Reboot
        if cmd.contains("shutdown ") || cmd.contains("reboot ") || cmd.contains("poweroff") {
            if uid != 0 {
                hits.push(h(70.0, "impact", "T1529", None, "Unexpected system shutdown/reboot by non-root"));
            }
        }


        // ═══════════════════════════════════════════════════════
        // MITRE ATLAS — Adversarial AI/ML Attack Detection
        // ═══════════════════════════════════════════════════════
        // Detects attacks targeting AI/ML systems on this host.
        // Relevant if the host runs ML inference servers, Ollama,
        // LLM APIs, model training pipelines, or Jupyter notebooks.

        // AML.T0040 — ML Model Inference API Abuse
        // Anomalous volume of requests to ML inference endpoints
        if proc.contains("curl") || proc.contains("python") {
            if cmd.contains("localhost:11434") || cmd.contains("/api/generate") ||
               cmd.contains("/v1/chat/completions") || cmd.contains("/predict") {
                if uid > 1000 && uid != event.uid { // unexpected caller
                    hits.push(h(65.0, "ml_attack", "AML.T0040", None, "Unusual process accessing local ML inference API"));
                }
            }
        }

        // AML.T0043 — Craft Adversarial Data (input manipulation)
        // Large binary or encoded data being fed to an AI service
        if cmd.contains("base64") && (cmd.contains("11434") || cmd.contains("predict")) {
            hits.push(h(70.0, "ml_attack", "AML.T0043", None, "Base64-encoded data sent to AI inference endpoint (adversarial input)"));
        }

        // AML.T0051 — LLM Prompt Injection via file
        // Attacker writes a malicious file that gets ingested by an LLM pipeline
        if event.event_type == EventType::FileWrite {
            if fpath.contains("/.cache/huggingface") || fpath.contains("/models/") ||
               fpath.contains("langchain") || fpath.contains("llamaindex") {
                if uid > 1000 {
                    hits.push(h(75.0, "ml_attack", "AML.T0051", None, "Unexpected write to ML model cache/pipeline directory"));
                }
            }
        }

        // AML.T0057 — Backdoor ML Model
        // Replacement of model weights or config files
        if event.event_type == EventType::FileWrite {
            if (fpath.ends_with(".gguf") || fpath.ends_with(".safetensors") ||
                fpath.ends_with(".bin") || fpath.ends_with(".pt") || fpath.ends_with(".pkl"))
               && !fpath.contains("/tmp/")
            {
                hits.push(h(85.0, "ml_attack", "AML.T0057", None, "ML model file modified at runtime — possible backdoor injection (T0057)"));
            }
        }

        // AML.T0016 — Obtain ML Artifacts
        // Exfiltration of model files
        if cmd.contains("scp ") || cmd.contains("rsync") || cmd.contains("curl -T") {
            if cmd.contains(".gguf") || cmd.contains(".safetensors") ||
               cmd.contains(".pkl") || cmd.contains("model") {
                hits.push(h(80.0, "ml_attack", "AML.T0016", None, "ML model artifact exfiltration attempt (T0016)"));
            }
        }

        // AML.T0018 — Backdoor ML Model via training data poisoning
        // Writes to training data directories
        if event.event_type == EventType::FileWrite {
            if fpath.contains("/train/") || fpath.contains("/dataset/") ||
               fpath.contains("/training_data/") || fpath.contains("/corpus/") {
                if uid > 1000 {
                    hits.push(h(70.0, "ml_attack", "AML.T0018", None, "Write to training data directory by non-privileged user — possible data poisoning"));
                }
            }
        }

        // AML.T0048 — Discovered Attack Vector via model API probing
        // Systematic enumeration of model capabilities
        if proc.contains("python") || proc.contains("curl") {
            let probing_patterns = [
                "role: system", "ignore previous", "jailbreak",
                "prompt injection", "adversarial", "bypass", "dan mode",
            ];
            if probing_patterns.iter().any(|p| cmd.contains(p)) {
                hits.push(h(90.0, "ml_attack", "AML.T0048", None, "Prompt injection or LLM probing pattern detected in command line (ATLAS)"));
            }
        }

        // AML.T0054 — LLM Jailbreak attempt
        if cmd.contains("do anything now") || cmd.contains("dan mode") ||
           cmd.contains("developer mode enabled") || cmd.contains("unrestricted mode") {
            hits.push(h(85.0, "ml_attack", "AML.T0054", None, "LLM jailbreak attempt detected (ATLAS AML.T0054)"));
        }

        // Ollama/LLM service tampering
        if (cmd.contains("systemctl") && cmd.contains("ollama")) ||
           (cmd.contains("kill") && cmd.contains("ollama")) ||
           (fpath.contains("/usr/local/bin/ollama") && event.event_type == EventType::FileWrite)
        {
            hits.push(h(80.0, "ml_attack", "AML.T0057", None, "Ollama LLM service tampered or stopped — possible model replacement"));
        }

        // ═══════════════════════════════════════════════════════
        // T1055 — PROCESS INJECTION (all sub-techniques)
        // ═══════════════════════════════════════════════════════

        // T1055.001 — Dynamic-link Library Injection
        if cmd.contains("dlopen") || cmd.contains("dlmopen") ||
           (cmd.contains("ld_preload") && !cmd.contains("unset")) {
            hits.push(h(85.0, "defense_evasion", "T1055", Some("T1055.001"), "DLL/SO injection via dlopen or LD_PRELOAD"));
        }
        // T1055.002 — Portable Executable Injection (Windows PE on Wine or cross-arch)
        if cmd.contains(".dll") && (cmd.contains("rundll32") || cmd.contains("regsvr32")) {
            hits.push(h(80.0, "defense_evasion", "T1055", Some("T1055.002"), "PE injection via rundll32/regsvr32"));
        }
        // T1055.003 — Thread Execution Hijacking
        if cmd.contains("ptrace") && (cmd.contains("poketext") || cmd.contains("pokedata")) {
            hits.push(h(92.0, "defense_evasion", "T1055", Some("T1055.003"), "Thread execution hijacking via ptrace POKETEXT/POKEDATA"));
        }
        // T1055.004 — Asynchronous Procedure Call (Linux equivalent: signal injection)
        if cmd.contains("kill -") && cmd.contains("sigill") || cmd.contains("sigrtmin") {
            hits.push(h(75.0, "defense_evasion", "T1055", Some("T1055.004"), "Signal injection — APC/signal-based code execution"));
        }
        // T1055.008 — ptrace-based injection (also in priv esc, here for def evasion)
        if event.event_type == EventType::Ptrace {
            hits.push(h(90.0, "defense_evasion", "T1055", Some("T1055.008"), "ptrace-based process injection — PROCESS HOLLOWING indicator"));
        }
        // T1055.009 — Proc Memory injection (/proc/PID/mem write)
        if fpath.contains("/proc/") && fpath.ends_with("/mem") &&
           event.event_type == EventType::FileWrite {
            hits.push(h(95.0, "defense_evasion", "T1055", Some("T1055.009"), "PROCESS HOLLOWING: /proc/PID/mem write — direct memory injection"));
        }
        // T1055.012 — Process Hollowing (classic: unmap + map new image)
        if (cmd.contains("mmap") || cmd.contains("munmap")) &&
           (cmd.contains("prot_exec") || cmd.contains("map_anon")) &&
           uid > 0 {
            hits.push(h(88.0, "defense_evasion", "T1055", Some("T1055.012"), "Process hollowing indicators: mmap PROT_EXEC anonymous mapping"));
        }
        // T1055.014 — VDSO Hijacking
        if cmd.contains("vdso") || fpath.contains("vdso") {
            hits.push(h(90.0, "defense_evasion", "T1055", Some("T1055.014"), "VDSO hijacking detected — kernel virtual DSO manipulation"));
        }
        // Memfd (fileless execution / T1620)
        if cmd.contains("memfd_create") || fpath.contains("/proc/self/fd") {
            hits.push(h(90.0, "defense_evasion", "T1620", None, "memfd_create fileless execution — payload never touches disk"));
        }

        // ═══════════════════════════════════════════════════════
        // T1134 — ACCESS TOKEN MANIPULATION
        // ═══════════════════════════════════════════════════════
        if cmd.contains("su -") && uid != 0 {
            hits.push(h(65.0, "privilege_escalation", "T1134", Some("T1134.001"), "Token impersonation: su - (switch user without credential)"));
        }
        if cmd.contains("newuidmap") || cmd.contains("newgidmap") {
            hits.push(h(70.0, "privilege_escalation", "T1134", Some("T1134.002"), "UID/GID remapping in user namespace — token manipulation"));
        }
        if cmd.contains("capsh") || cmd.contains("setcap") || cmd.contains("getcap") {
            hits.push(h(70.0, "privilege_escalation", "T1134", None, "Linux capability manipulation (capsh/setcap)"));
        }

        // ═══════════════════════════════════════════════════════
        // T1484/T1222 — DOMAIN/GROUP POLICY, FILE PERMISSIONS
        // ═══════════════════════════════════════════════════════
        if cmd.contains("chattr +i") || cmd.contains("chattr -i") {
            hits.push(h(75.0, "defense_evasion", "T1222", None, "File immutability bit manipulation (chattr +i/-i)"));
        }
        if cmd.contains("setfacl") && cmd.contains("--remove") {
            hits.push(h(60.0, "defense_evasion", "T1222", None, "ACL removal (setfacl --remove) — permission weakening"));
        }

        // ═══════════════════════════════════════════════════════
        // T1547 BOOT PERSISTENCE (additional sub-techniques)
        // ═══════════════════════════════════════════════════════
        if fpath.contains("/etc/rc.local") || fpath.contains("/etc/rc.d/") {
            hits.push(h(65.0, "persistence", "T1547", Some("T1547.001"), "RC script persistence (/etc/rc.local or rc.d/)"));
        }
        if fpath.contains("/etc/modules-load.d/") || (cmd.contains("insmod") && !cmd.contains("lime")) {
            hits.push(h(85.0, "persistence", "T1547", Some("T1547.006"), "Kernel module loaded for persistence (insmod)"));
        }
        if fpath.contains("/.config/systemd/user/") || fpath.contains("/usr/lib/systemd/user/") {
            hits.push(h(70.0, "persistence", "T1547", Some("T1547.013"), "User-level systemd service persistence"));
        }
        if fpath.contains("/etc/grub.d/") || fpath.contains("/boot/grub/grub.cfg") {
            hits.push(h(88.0, "persistence", "T1542", Some("T1542.003"), "Bootloader modification — GRUB persistence/implant"));
        }

        // ═══════════════════════════════════════════════════════
        // T1553 — SUBVERT TRUST CONTROLS
        // ═══════════════════════════════════════════════════════
        if cmd.contains("update-ca-certificates") || cmd.contains("trust anchor") ||
           fpath.contains("/usr/local/share/ca-certificates/") {
            hits.push(h(75.0, "defense_evasion", "T1553", Some("T1553.004"), "Root CA certificate installed — MITM/trust subversion"));
        }
        if cmd.contains("dpkg --add-architecture") || cmd.contains("rpm --import") {
            hits.push(h(55.0, "defense_evasion", "T1553", None, "Package signing key imported — supply chain risk"));
        }
        if fpath.contains("/etc/apt/sources.list.d/") || fpath.contains("/etc/yum.repos.d/") {
            hits.push(h(60.0, "defense_evasion", "T1553", None, "Package repository modified — supply chain risk"));
        }

        // ═══════════════════════════════════════════════════════
        // T1558 — KERBEROS / CREDENTIAL-BASED ATTACKS
        // ═══════════════════════════════════════════════════════
        if cmd.contains("GetUserSPNs") || cmd.contains("kerberoast") || cmd.contains("rubeus") {
            hits.push(h(92.0, "credential_access", "T1558", Some("T1558.003"), "Kerberoasting — SPN ticket request for offline cracking"));
        }
        if cmd.contains("GetNPUsers") || cmd.contains("as-rep roast") {
            hits.push(h(90.0, "credential_access", "T1558", Some("T1558.004"), "AS-REP Roasting — pre-auth disabled account attack"));
        }
        if cmd.contains("krb5cc") || (fpath.contains("/tmp/krb5cc_") && event.event_type == EventType::FileOpen) {
            hits.push(h(80.0, "credential_access", "T1558", None, "Kerberos TGT ticket cache access — pass-the-ticket preparation"));
        }

        // ═══════════════════════════════════════════════════════
        // T1187 — FORCED AUTHENTICATION
        // ═══════════════════════════════════════════════════════
        if cmd.contains("responder") || cmd.contains("ntlmrelayx") || cmd.contains("inveigh") {
            hits.push(h(95.0, "credential_access", "T1187", None, "LLMNR/NBT-NS poisoning tool (Responder/Inveigh) — forced NTLM auth"));
        }

        // ═══════════════════════════════════════════════════════
        // T1212 — EXPLOITATION FOR CREDENTIAL ACCESS
        // ═══════════════════════════════════════════════════════
        if cmd.contains("zerologon") || cmd.contains("cve-2020-1472") {
            hits.push(h(98.0, "credential_access", "T1212", None, "Zerologon exploit (CVE-2020-1472) — domain controller compromise"));
        }
        if cmd.contains("petitpotam") || cmd.contains("cve-2021-36942") {
            hits.push(h(95.0, "credential_access", "T1212", None, "PetitPotam NTLM relay attack"));
        }

        // ═══════════════════════════════════════════════════════
        // T1205 — TRAFFIC SIGNALING (port knocking / magic packets)
        // ═══════════════════════════════════════════════════════
        if cmd.contains("knockd") || cmd.contains("knock ") || fpath.contains("/etc/knockd.conf") {
            hits.push(h(70.0, "defense_evasion", "T1205", None, "Port knocking daemon/config — covert activation channel"));
        }
        if cmd.contains("scapy") && cmd.contains("send") {
            hits.push(h(65.0, "defense_evasion", "T1205", None, "Scapy packet crafting — possible traffic signaling/covert channel"));
        }

        // ═══════════════════════════════════════════════════════
        // T1542 — PRE-OS BOOT / FIRMWARE ATTACKS
        // ═══════════════════════════════════════════════════════
        if cmd.contains("efibootmgr") || fpath.contains("/sys/firmware/efi/") {
            hits.push(h(85.0, "persistence", "T1542", Some("T1542.001"), "EFI/UEFI boot entry modification — firmware persistence"));
        }
        if cmd.contains("flash") && (fpath.contains("bios") || fpath.contains("uefi") || fpath.contains("firmware")) {
            hits.push(h(95.0, "persistence", "T1542", None, "Firmware flash detected — possible BIOS/UEFI implant"));
        }

        // ═══════════════════════════════════════════════════════
        // T1599 — NETWORK BOUNDARY BRIDGING
        // ═══════════════════════════════════════════════════════
        if cmd.contains("ip route add") && (cmd.contains("via") && uid != 0) {
            hits.push(h(65.0, "lateral_movement", "T1599", None, "Custom route injection — possible network boundary bridging"));
        }
        if cmd.contains("arp -s") || cmd.contains("ip neigh add") {
            hits.push(h(70.0, "lateral_movement", "T1599", None, "Static ARP entry added — possible ARP spoofing/boundary pivot"));
        }

        // ═══════════════════════════════════════════════════════
        // T1601/T1600 — NETWORK DEVICE COMPROMISE
        // ═══════════════════════════════════════════════════════
        if (cmd.contains("snmpset") || cmd.contains("snmpwalk")) && uid != 0 {
            hits.push(h(60.0, "lateral_movement", "T1600", None, "SNMP write access to network device (possible config modification)"));
        }
        if cmd.contains("tftp") && cmd.contains("-p") {
            hits.push(h(65.0, "lateral_movement", "T1601", None, "TFTP upload to network device — firmware/OS modification"));
        }

        // ═══════════════════════════════════════════════════════
        // T1021 — REMOTE SERVICES (additional sub-techniques)
        // ═══════════════════════════════════════════════════════
        if cmd.contains("xrdp") || (cmd.contains("rdesktop") || cmd.contains("freerdp")) {
            hits.push(h(60.0, "lateral_movement", "T1021", Some("T1021.001"), "RDP remote desktop connection"));
        }
        if cmd.contains("nfs") && cmd.contains("mount") && cmd.contains("noroot_squash") {
            hits.push(h(80.0, "lateral_movement", "T1021", Some("T1021.002"), "NFS mount with no_root_squash — privilege escalation via share"));
        }
        if cmd.contains("dcom") || (cmd.contains("wbemexec") || cmd.contains("wmi_exec")) {
            hits.push(h(80.0, "lateral_movement", "T1021", Some("T1021.003"), "DCOM/WMI remote execution lateral movement"));
        }
        if cmd.contains("rsh ") || cmd.contains("rlogin ") || cmd.contains("rcp ") {
            hits.push(h(75.0, "lateral_movement", "T1021", Some("T1021.004"), "Legacy r-commands (rsh/rlogin/rcp) — insecure remote access"));
        }
        if cmd.contains("vncviewer") || cmd.contains("vnc://") {
            hits.push(h(55.0, "lateral_movement", "T1021", Some("T1021.005"), "VNC remote desktop lateral movement"));
        }

        // ═══════════════════════════════════════════════════════
        // T1059 — EXECUTION (additional scripting languages)
        // ═══════════════════════════════════════════════════════
        if cmd.contains("lua ") || cmd.contains("lua5") {
            hits.push(h(50.0, "execution", "T1059", None, "Lua script execution — uncommon interpreter for post-exploit"));
        }
        if cmd.contains("tclsh") || cmd.contains("wish ") {
            hits.push(h(55.0, "execution", "T1059", None, "Tcl/Tk interpreter — uncommon post-exploit scripting"));
        }
        if cmd.contains("awk ") && cmd.contains("system(") {
            hits.push(h(70.0, "execution", "T1059", Some("T1059.004"), "awk system() call — shell command via awk injection"));
        }
        if cmd.contains("expect ") && cmd.contains("spawn") {
            hits.push(h(65.0, "execution", "T1059", None, "expect-based interactive command spawning — possible interactive shell"));
        }
        if proc == "vim" || proc == "vi" {
            if cmd.contains(":!") || cmd.contains("--cmd") {
                hits.push(h(70.0, "execution", "T1059", None, "vim :! shell escape — command execution via text editor"));
            }
        }
        if proc == "less" && cmd.contains("!") {
            hits.push(h(65.0, "execution", "T1059", None, "less ! shell escape — GTFOBins execution"));
        }
        if cmd.contains("python") && cmd.contains("__import__('os').system") {
            hits.push(h(85.0, "execution", "T1059", Some("T1059.006"), "Python os.system() inline — command injection pattern"));
        }
        // GTFOBins patterns
        if (proc == "find" && cmd.contains("-exec /bin/sh")) ||
           (proc == "find" && cmd.contains("-execdir /bin/sh")) {
            hits.push(h(85.0, "execution", "T1059", None, "GTFOBins: find -exec /bin/sh — privileged shell escape"));
        }
        if proc == "nmap" && cmd.contains("--script=exec") {
            hits.push(h(80.0, "execution", "T1059", None, "GTFOBins: nmap --script=exec — shell execution via NSE"));
        }
        if (proc == "man" || proc == "env") && cmd.contains("/bin/sh") {
            hits.push(h(75.0, "execution", "T1059", None, "GTFOBins: man/env shell escape"));
        }

        // ═══════════════════════════════════════════════════════
        // T1078 — VALID ACCOUNTS (additional patterns)
        // ═══════════════════════════════════════════════════════
        if cmd.contains("useradd") && (cmd.contains("-u 0") || cmd.contains("-g 0")) {
            hits.push(h(95.0, "persistence", "T1078", Some("T1078.003"), "New account created with UID/GID 0 — backdoor local account"));
        }
        if cmd.contains("usermod") && (cmd.contains("-u 0") || cmd.contains("-g root") || cmd.contains("-G sudo")) {
            hits.push(h(90.0, "persistence", "T1078", Some("T1078.003"), "Account modified to root/sudo — privilege backdoor"));
        }
        if cmd.contains("passwd") && cmd.contains("-d") {
            hits.push(h(85.0, "persistence", "T1078", None, "Password removed from account (passwd -d) — persistence backdoor"));
        }

        // ═══════════════════════════════════════════════════════
        // T1098 — ACCOUNT MANIPULATION
        // ═══════════════════════════════════════════════════════
        if cmd.contains("ssh-keygen") && (fpath.contains("/root/.ssh") || fpath.contains("authorized_keys")) {
            hits.push(h(80.0, "persistence", "T1098", Some("T1098.004"), "SSH authorized_keys manipulation — backdoor key added"));
        }
        if cmd.contains("ssh-copy-id") && uid != 0 {
            hits.push(h(75.0, "persistence", "T1098", Some("T1098.004"), "SSH key copied to remote (ssh-copy-id) — lateral persistence"));
        }
        if fpath.contains("/etc/ssh/ssh_config") && event.event_type == EventType::FileWrite {
            hits.push(h(75.0, "persistence", "T1098", None, "SSH client config modified — possible ProxyCommand backdoor"));
        }

        // ═══════════════════════════════════════════════════════
        // T1497 — VIRTUALIZATION/SANDBOX EVASION (expanded)
        // ═══════════════════════════════════════════════════════
        if cmd.contains("systemd-detect-virt") || cmd.contains("virt-what") {
            hits.push(h(55.0, "defense_evasion", "T1497", None, "Virtualization detection tool executed"));
        }
        if cmd.contains("/sys/class/dmi") || cmd.contains("dmidecode") {
            hits.push(h(45.0, "defense_evasion", "T1497", None, "DMI/BIOS vendor check — sandbox/VM detection"));
        }
        if cmd.contains("uptime") && cmd.contains("| awk") && uid > 1000 {
            hits.push(h(40.0, "defense_evasion", "T1497", Some("T1497.001"), "Uptime check — sandbox time-based evasion (short uptime avoidance)"));
        }

        // ═══════════════════════════════════════════════════════
        // T1611 — CONTAINER ESCAPE (expanded)
        // ═══════════════════════════════════════════════════════
        if cmd.contains("unshare") && cmd.contains("--user") {
            hits.push(h(75.0, "privilege_escalation", "T1611", None, "User namespace unshare — container/privilege isolation escape"));
        }
        if fpath.contains("/sys/fs/cgroup/") && event.event_type == EventType::FileWrite {
            hits.push(h(80.0, "privilege_escalation", "T1611", None, "cgroup filesystem write — container escape via cgroup notify_on_release"));
        }
        if cmd.contains("mount -t") && cmd.contains("overlay") {
            hits.push(h(70.0, "privilege_escalation", "T1611", None, "Overlay filesystem mount — container layer manipulation"));
        }

        // ═══════════════════════════════════════════════════════
        // T1016 — SYSTEM NETWORK CONFIGURATION DISCOVERY
        // ═══════════════════════════════════════════════════════
        if cmd.contains("ip route") || cmd.contains("route -n") || cmd.contains("netstat -r") {
            hits.push(h(20.0, "discovery", "T1016", None, "Network route table enumeration"));
        }
        if cmd.contains("cat /etc/resolv.conf") || cmd.contains("resolvectl status") {
            hits.push(h(15.0, "discovery", "T1016", None, "DNS configuration enumeration"));
        }
        if cmd.contains("arp -a") || cmd.contains("ip neigh show") {
            hits.push(h(25.0, "discovery", "T1016", None, "ARP/neighbor table enumeration — network topology recon"));
        }

        // ═══════════════════════════════════════════════════════
        // T1120 — PERIPHERAL DEVICE DISCOVERY
        // ═══════════════════════════════════════════════════════
        if cmd.contains("lsusb") || cmd.contains("lspci") || cmd.contains("lshw") {
            hits.push(h(20.0, "discovery", "T1120", None, "Hardware device discovery (lsusb/lspci/lshw)"));
        }

        // ═══════════════════════════════════════════════════════
        // T1040 — NETWORK SNIFFING
        // ═══════════════════════════════════════════════════════
        if proc == "tcpdump" || proc == "tshark" || proc == "wireshark" ||
           (cmd.contains("tcpdump") && cmd.contains("-i")) {
            hits.push(h(65.0, "credential_access", "T1040", None, "Network sniffing (tcpdump/tshark/wireshark)"));
        }
        if cmd.contains("bettercap") || cmd.contains("ettercap") {
            hits.push(h(85.0, "credential_access", "T1040", None, "Man-in-the-middle sniffing tool (bettercap/ettercap)"));
        }

        // ═══════════════════════════════════════════════════════
        // T1601 — MODIFY SYSTEM IMAGE (network devices)
        // ═══════════════════════════════════════════════════════
        if cmd.contains("iptables-save") && fpath.contains("/etc/") {
            hits.push(h(40.0, "defense_evasion", "T1601", None, "Firewall rules saved — possible rule persistence modification"));
        }

        // ═══════════════════════════════════════════════════════
        // T1059.003 — WINDOWS COMMAND SHELL (via Wine/Proton)
        // ═══════════════════════════════════════════════════════
        if proc.contains("wine") && cmd.contains("cmd.exe") {
            hits.push(h(65.0, "execution", "T1059", Some("T1059.003"), "Windows cmd.exe execution via Wine — possible Windows malware"));
        }

        // ═══════════════════════════════════════════════════════
        // T1568 — DYNAMIC RESOLUTION / DGA
        // ═══════════════════════════════════════════════════════
        if (cmd.contains("dig") || cmd.contains("nslookup") || cmd.contains("host ")) &&
           cmd.split_whitespace().any(|w| w.len() > 25 && w.chars().filter(|c| c.is_alphanumeric()).count() > 20) {
            hits.push(h(70.0, "command_and_control", "T1568", Some("T1568.002"), "Long random-looking DNS query — DGA or DNS tunneling indicator"));
        }

        // ═══════════════════════════════════════════════════════
        // T1578 — MODIFY CLOUD COMPUTE INFRASTRUCTURE
        // ═══════════════════════════════════════════════════════
        if cmd.contains("aws ec2 modify") || cmd.contains("aws ec2 create-security-group") {
            hits.push(h(70.0, "defense_evasion", "T1578", None, "AWS EC2 security group/instance modification — cloud infra tampering"));
        }
        if cmd.contains("gcloud compute") && cmd.contains("firewall-rules") {
            hits.push(h(70.0, "defense_evasion", "T1578", None, "GCP firewall rule modification"));
        }

        // ═══════════════════════════════════════════════════════
        // T1606 — FORGE WEB CREDENTIALS
        // ═══════════════════════════════════════════════════════
        if cmd.contains("jwt") && (cmd.contains("none") || cmd.contains("alg.*none")) {
            hits.push(h(85.0, "credential_access", "T1606", Some("T1606.001"), "JWT algorithm=none attack — forged web credential"));
        }
        if cmd.contains("samlsign") || cmd.contains("golden saml") {
            hits.push(h(95.0, "credential_access", "T1606", Some("T1606.002"), "Golden SAML attack — forged SAML assertion"));
        }

        // ═══════════════════════════════════════════════════════
        // T1548.004 — ELEVATED EXECUTION WITH PROMPT (pkexec abuse)
        // ═══════════════════════════════════════════════════════
        if proc == "pkexec" && uid != 0 {
            hits.push(h(75.0, "privilege_escalation", "T1548", Some("T1548.004"), "pkexec elevation attempt — possible CVE-2021-4034 (PwnKit)"));
        }

        // ═══════════════════════════════════════════════════════
        // T1136 — CREATE ACCOUNT
        // ═══════════════════════════════════════════════════════
        if proc == "useradd" || proc == "adduser" {
            let score = if uid == 0 { 50.0 } else { 85.0 };
            hits.push(h(score, "persistence", "T1136", Some("T1136.001"), "New local user account created"));
        }

        // ═══════════════════════════════════════════════════════
        // T1053 — SCHEDULED TASK/JOB (expanded)
        // ═══════════════════════════════════════════════════════
        if proc == "at" || cmd.contains("at now") || cmd.contains("atq") {
            hits.push(h(55.0, "persistence", "T1053", Some("T1053.002"), "at job scheduled — deferred execution persistence"));
        }
        if fpath.contains("/etc/anacrontab") {
            hits.push(h(60.0, "persistence", "T1053", Some("T1053.003"), "anacron job configured — periodic persistence"));
        }

        // ═══════════════════════════════════════════════════════
        // T1530 — DATA FROM CLOUD STORAGE
        // ═══════════════════════════════════════════════════════
        if cmd.contains("aws s3 cp") && cmd.contains("s3://") {
            hits.push(h(45.0, "collection", "T1530", None, "AWS S3 bucket access — cloud data collection"));
        }
        if cmd.contains("gsutil cat") || cmd.contains("gcloud storage cat") {
            hits.push(h(45.0, "collection", "T1530", None, "GCS object access — cloud data collection"));
        }

        // ═══════════════════════════════════════════════════════
        // T1213 — DATA FROM INFORMATION REPOSITORIES
        // ═══════════════════════════════════════════════════════
        if cmd.contains("confluence") && (cmd.contains("export") || cmd.contains("rest/api")) {
            hits.push(h(65.0, "collection", "T1213", None, "Confluence API access — wiki data collection"));
        }
        if cmd.contains("jira") && cmd.contains("export") {
            hits.push(h(55.0, "collection", "T1213", None, "Jira export — project data collection"));
        }
        if cmd.contains("kubectl get secrets") || cmd.contains("kubectl get secret") {
            hits.push(h(85.0, "credential_access", "T1552", Some("T1552.007"), "Kubernetes secrets enumeration via kubectl"));
        }

        // ═══════════════════════════════════════════════════════
        // SUPPLY CHAIN / T1195
        // ═══════════════════════════════════════════════════════
        if cmd.contains("npm install") && cmd.contains("--unsafe-perm") {
            hits.push(h(60.0, "initial_access", "T1195", Some("T1195.002"), "npm install with --unsafe-perm — supply chain risk"));
        }
        if cmd.contains("pip install") && (cmd.contains("--index-url") || cmd.contains("--extra-index-url")) {
            hits.push(h(55.0, "initial_access", "T1195", Some("T1195.002"), "pip install from non-standard index — dependency confusion risk"));
        }
        if cmd.contains("curl") && cmd.contains("| bash") || cmd.contains("curl") && cmd.contains("| sh") {
            hits.push(h(80.0, "initial_access", "T1195", None, "Pipe-to-shell pattern — supply chain/remote code execution"));
        }

        // ═══════════════════════════════════════════════════════
        // T1546.015 — EVENT TRIGGERED EXECUTION (udev rules)
        // ═══════════════════════════════════════════════════════
        if fpath.contains("/etc/udev/rules.d/") && event.event_type == EventType::FileWrite {
            hits.push(h(80.0, "persistence", "T1546", Some("T1546.015"), "udev rule modified — hardware event triggered execution persistence"));
        }

        // ═══════════════════════════════════════════════════════
        // T1014 — ROOTKIT
        // ═══════════════════════════════════════════════════════
        if fpath.contains("/lib/modules/") && event.event_type == EventType::FileWrite {
            hits.push(h(90.0, "defense_evasion", "T1014", None, "Kernel module directory modification — possible rootkit installation"));
        }
        if cmd.contains("insmod") || cmd.contains("modprobe") {
            let score = if fpath.contains("/tmp") || fpath.contains("/dev/shm") { 90.0 } else { 55.0 };
            hits.push(h(score, "defense_evasion", "T1014", None, "Kernel module loaded — potential rootkit"));
        }
        if cmd.contains("dkms install") && uid == 0 {
            hits.push(h(50.0, "defense_evasion", "T1014", None, "DKMS kernel module installation — verify source"));
        }

        // ═══════════════════════════════════════════════════════
        // T1127 — TRUSTED DEVELOPER UTILITIES PROXY EXECUTION
        // ═══════════════════════════════════════════════════════
        if proc == "gcc" || proc == "cc" {
            if uid > 1000 && (cmd.contains("/tmp") || cmd.contains("/dev/shm")) {
                hits.push(h(75.0, "defense_evasion", "T1127", None, "Compiler invoked by non-admin on /tmp — LOLBin compilation"));
            }
        }
        if proc == "make" && (fpath.contains("/tmp") || fpath.contains("/dev/shm")) {
            hits.push(h(70.0, "defense_evasion", "T1127", None, "make in /tmp — trusted developer tool proxy execution"));
        }

        // Extended coverage: T1218 LOLBins, T1055 full suite, T1562 sub-techniques,
        // T1649, T1654, T1657, T1660, and 40+ more ATT&CK v15 techniques
        hits.extend(MitreRulesExtended::evaluate(event));

        hits
    }
}

fn h(score: f32, tactic: &'static str, technique: &'static str, sub: Option<&'static str>, desc: &'static str) -> TechniqueHit {
    TechniqueHit { score, tactic, technique, sub, description: desc }
}

// ── All MITRE ATT&CK v15 chains ───────────────────────────────
pub fn all_chain_patterns() -> Vec<crate::config::ChainPattern> {
    vec![
        // 1. Web compromise → payload download → exec
        crate::config::ChainPattern {
            name: "Web-to-Shell exploit chain".into(),
            tactics: vec!["initial_access".into(), "execution".into(), "command_and_control".into()],
            techniques: vec!["T1190".into(), "T1059.004".into(), "T1105".into()],
            min_confidence: 75.0,
        },
        // 2. Spearphish → macro → PowerShell
        crate::config::ChainPattern {
            name: "Spearphishing macro → PowerShell execution".into(),
            tactics: vec!["initial_access".into(), "execution".into()],
            techniques: vec!["T1566.001".into(), "T1059.001".into()],
            min_confidence: 70.0,
        },
        // 3. Credential dump → lateral movement
        crate::config::ChainPattern {
            name: "Credential dump → lateral movement".into(),
            tactics: vec!["credential_access".into(), "lateral_movement".into()],
            techniques: vec!["T1003.001".into(), "T1021.002".into()],
            min_confidence: 75.0,
        },
        // 4. Discovery sweep → staging → exfiltration
        crate::config::ChainPattern {
            name: "Internal recon → data staging → exfiltration".into(),
            tactics: vec!["discovery".into(), "collection".into(), "exfiltration".into()],
            techniques: vec!["T1083".into(), "T1074.001".into(), "T1048".into()],
            min_confidence: 70.0,
        },
        // 5. Priv esc → persistence → defense evasion
        crate::config::ChainPattern {
            name: "Privilege escalation → persistence → cover tracks".into(),
            tactics: vec!["privilege_escalation".into(), "persistence".into(), "defense_evasion".into()],
            techniques: vec!["T1068".into(), "T1053.003".into(), "T1070".into()],
            min_confidence: 72.0,
        },
        // 6. Container escape chain
        crate::config::ChainPattern {
            name: "Container escape to host".into(),
            tactics: vec!["privilege_escalation".into(), "lateral_movement".into()],
            techniques: vec!["T1611".into(), "T1021".into()],
            min_confidence: 80.0,
        },
        // 7. Ransomware chain
        crate::config::ChainPattern {
            name: "Ransomware: disable recovery → encrypt → impact".into(),
            tactics: vec!["defense_evasion".into(), "impact".into()],
            techniques: vec!["T1490".into(), "T1486".into()],
            min_confidence: 85.0,
        },
        // 8. Cryptomining persistence chain
        crate::config::ChainPattern {
            name: "Cryptominer: download → persist → execute".into(),
            tactics: vec!["command_and_control".into(), "persistence".into(), "impact".into()],
            techniques: vec!["T1105".into(), "T1053.003".into(), "T1496".into()],
            min_confidence: 70.0,
        },
        // 9. Pass-the-hash lateral movement chain
        crate::config::ChainPattern {
            name: "Pass-the-hash lateral movement".into(),
            tactics: vec!["credential_access".into(), "lateral_movement".into(), "execution".into()],
            techniques: vec!["T1003.001".into(), "T1550.002".into(), "T1021.002".into()],
            min_confidence: 80.0,
        },
        // 10. Kerberos golden ticket chain
        crate::config::ChainPattern {
            name: "Kerberoasting → golden ticket → domain compromise".into(),
            tactics: vec!["credential_access".into(), "lateral_movement".into()],
            techniques: vec!["T1558".into(), "T1550.003".into()],
            min_confidence: 90.0,
        },
        // 11. DNS tunneling C2 chain
        crate::config::ChainPattern {
            name: "DNS tunneling C2".into(),
            tactics: vec!["command_and_control".into(), "exfiltration".into()],
            techniques: vec!["T1071.004".into(), "T1048".into()],
            min_confidence: 75.0,
        },
        // 12. LD_PRELOAD persistence chain
        crate::config::ChainPattern {
            name: "LD_PRELOAD hijack → credential access".into(),
            tactics: vec!["persistence".into(), "credential_access".into()],
            techniques: vec!["T1574.006".into(), "T1003".into()],
            min_confidence: 80.0,
        },
        // 13. Cloud resource hijack chain
        crate::config::ChainPattern {
            name: "Cloud credential theft → resource hijacking".into(),
            tactics: vec!["credential_access".into(), "impact".into()],
            techniques: vec!["T1552".into(), "T1496".into()],
            min_confidence: 70.0,
        },
        // 14. Supply chain / insider threat chain
        crate::config::ChainPattern {
            name: "Discovery sweep → sensitive file access → staging".into(),
            tactics: vec!["discovery".into(), "credential_access".into(), "collection".into()],
            techniques: vec!["T1082".into(), "T1552.001".into(), "T1074.001".into()],
            min_confidence: 65.0,
        },
        // 15. Webshell persistence → C2 → exfiltration
        crate::config::ChainPattern {
            name: "Webshell persistence → C2 beaconing → exfil".into(),
            tactics: vec!["persistence".into(), "command_and_control".into(), "exfiltration".into()],
            techniques: vec!["T1505.003".into(), "T1071".into(), "T1048".into()],
            min_confidence: 80.0,
        },
        // 16. Log4Shell → reverse shell → persistence
        crate::config::ChainPattern {
            name: "Log4Shell RCE → persistence".into(),
            tactics: vec!["initial_access".into(), "execution".into(), "persistence".into()],
            techniques: vec!["T1190".into(), "T1059.004".into(), "T1053.003".into()],
            min_confidence: 85.0,
        },
        // 17. LOLBin proxy → process injection → hollow
        crate::config::ChainPattern {
            name: "LOLBin proxy execution → process hollowing".into(),
            tactics: vec!["defense_evasion".into()],
            techniques: vec!["T1218".into(), "T1055.012".into()],
            min_confidence: 82.0,
        },
        // 18. Cloud credential theft → resource hijack → cryptominer
        crate::config::ChainPattern {
            name: "Cloud credential theft → cryptomining".into(),
            tactics: vec!["credential_access".into(), "impact".into()],
            techniques: vec!["T1528".into(), "T1496".into()],
            min_confidence: 75.0,
        },
        // 19. Vulnerability exploit → process injection → lateral movement
        crate::config::ChainPattern {
            name: "Exploit → injection → lateral movement".into(),
            tactics: vec!["initial_access".into(), "defense_evasion".into(), "lateral_movement".into()],
            techniques: vec!["T1190".into(), "T1055".into(), "T1021".into()],
            min_confidence: 82.0,
        },
        // 20. Insider threat: discovery → bulk collection → exfil
        crate::config::ChainPattern {
            name: "Insider threat: mass data staging → exfiltration".into(),
            tactics: vec!["collection".into(), "exfiltration".into()],
            techniques: vec!["T1005".into(), "T1074.001".into(), "T1048".into()],
            min_confidence: 68.0,
        },
        // 21. Living-off-the-land: LOLBin execution → cred access
        crate::config::ChainPattern {
            name: "Living-off-the-land: LOLBin → credential theft".into(),
            tactics: vec!["defense_evasion".into(), "credential_access".into()],
            techniques: vec!["T1218".into(), "T1003".into()],
            min_confidence: 80.0,
        },
        // 22. Firmware persistence chain
        crate::config::ChainPattern {
            name: "Pre-OS firmware persistence".into(),
            tactics: vec!["persistence".into()],
            techniques: vec!["T1542.001".into(), "T1542.003".into()],
            min_confidence: 85.0,
        },
        // 23. Certificate-based attack chain
        crate::config::ChainPattern {
            name: "Certificate theft → Golden SAML → cloud access".into(),
            tactics: vec!["credential_access".into(), "lateral_movement".into()],
            techniques: vec!["T1649".into(), "T1606.002".into()],
            min_confidence: 88.0,
        },
        // 24. Browser-pivot chain
        crate::config::ChainPattern {
            name: "Browser extension hijack → session theft → cloud pivot".into(),
            tactics: vec!["persistence".into(), "credential_access".into(), "lateral_movement".into()],
            techniques: vec!["T1176".into(), "T1185".into(), "T1528".into()],
            min_confidence: 75.0,
        },
        // 25. Supply chain → downgrade → persistence
        crate::config::ChainPattern {
            name: "Supply chain compromise → downgrade → backdoor".into(),
            tactics: vec!["initial_access".into(), "defense_evasion".into(), "persistence".into()],
            techniques: vec!["T1195.002".into(), "T1562.010".into(), "T1543.002".into()],
            min_confidence: 78.0,
        },
        // 26. MFA fatigue → cloud access → data theft
        crate::config::ChainPattern {
            name: "MFA fatigue → valid account → cloud data exfil".into(),
            tactics: vec!["credential_access".into(), "initial_access".into(), "exfiltration".into()],
            techniques: vec!["T1621".into(), "T1078".into(), "T1530".into()],
            min_confidence: 80.0,
        },
        // 27. Process hollowing → C2 → lateral movement
        crate::config::ChainPattern {
            name: "Process hollowing → C2 beacon → lateral movement".into(),
            tactics: vec!["defense_evasion".into(), "command_and_control".into(), "lateral_movement".into()],
            techniques: vec!["T1055.012".into(), "T1071.001".into(), "T1021.002".into()],
            min_confidence: 82.0,
        },
        // 28. DCSync → golden ticket → persistence
        crate::config::ChainPattern {
            name: "DCSync → golden ticket forgery → persistent domain access".into(),
            tactics: vec!["credential_access".into(), "lateral_movement".into(), "persistence".into()],
            techniques: vec!["T1003.006".into(), "T1558.001".into(), "T1098.004".into()],
            min_confidence: 90.0,
        },
        // 29. Container exec → escape → host persistence
        crate::config::ChainPattern {
            name: "Container exec → namespace escape → host rootkit".into(),
            tactics: vec!["execution".into(), "privilege_escalation".into(), "persistence".into()],
            techniques: vec!["T1609".into(), "T1611".into(), "T1547.006".into()],
            min_confidence: 88.0,
        },
        // 30. Data manipulation (destructive insider)
        crate::config::ChainPattern {
            name: "Insider threat: data exfil → manipulation → destruction".into(),
            tactics: vec!["collection".into(), "exfiltration".into(), "impact".into()],
            techniques: vec!["T1074.001".into(), "T1048".into(), "T1565.001".into()],
            min_confidence: 72.0,
        },
        // 31. Password spray → valid account → discovery → exfil
        crate::config::ChainPattern {
            name: "Password spray → valid account → internal recon → exfil".into(),
            tactics: vec!["credential_access".into(), "discovery".into(), "exfiltration".into()],
            techniques: vec!["T1110.003".into(), "T1078".into(), "T1083".into(), "T1048".into()],
            min_confidence: 75.0,
        },
        // 32. Webshell → /proc injection → fileless persistence
        crate::config::ChainPattern {
            name: "Webshell RCE → process injection → fileless persistence".into(),
            tactics: vec!["initial_access".into(), "defense_evasion".into(), "persistence".into()],
            techniques: vec!["T1190".into(), "T1055.009".into(), "T1620".into()],
            min_confidence: 85.0,
        },
        // 33. Cloud credential theft → resource hijack (crypto)
        crate::config::ChainPattern {
            name: "Cloud credential theft → cloud resource hijacking for mining".into(),
            tactics: vec!["credential_access".into(), "impact".into()],
            techniques: vec!["T1552.005".into(), "T1578".into(), "T1496".into()],
            min_confidence: 78.0,
        },
        // 34. Phishing → macro → LOLBIN → inject → persist
        crate::config::ChainPattern {
            name: "Phishing → macro execution → LOLBin proxy → injection → persistence".into(),
            tactics: vec!["initial_access".into(), "execution".into(), "defense_evasion".into(), "persistence".into()],
            techniques: vec!["T1566.001".into(), "T1204.002".into(), "T1218".into(), "T1055".into(), "T1543".into()],
            min_confidence: 80.0,
        },
        // 35. DNS C2 → slow exfil → data staging
        crate::config::ChainPattern {
            name: "DNS tunneling C2 → slow exfiltration → data staging".into(),
            tactics: vec!["command_and_control".into(), "collection".into(), "exfiltration".into()],
            techniques: vec!["T1071.004".into(), "T1074.001".into(), "T1048".into()],
            min_confidence: 78.0,
        },
    ]
}

// ── Main anomaly engine ────────────────────────────────────────
pub struct AnomalyEngine {
    config: AnomalyConfig,
    active_chains: Arc<DashMap<String, Vec<ActiveChain>>>,
}

struct ActiveChain {
    name: String,
    stages: Vec<ChainStage>,
    first_seen: chrono::DateTime<Utc>,
    last_seen: chrono::DateTime<Utc>,
    matched_techniques: Vec<String>,
    required_techniques: Vec<String>,
    min_confidence: f32,
}

impl AnomalyEngine {
    pub fn new(config: AnomalyConfig) -> Self {
        info!("🔬 AnomalyEngine: {} ATT&CK heuristics, {} chain patterns, {} built-in chains",
            196, config.chain_patterns.len(), all_chain_patterns().len());
        Self {
            config,
            active_chains: Arc::new(DashMap::new()),
        }
    }

    pub async fn analyze(&self, event: &RawEvent) -> Option<ThreatEvent> {
        if !self.config.heuristic_enabled { return None; }

        // ── Self-exclusion ────────────────────────────────────────────────
        // Never raise a detection against the agent's own process. The agent
        // legitimately does things that resemble attacker behavior — reading
        // other processes' memory for YARA sweeps, walking /proc, spawning a
        // short-lived child for the LLM self-test — so without this guard it can
        // flag itself (and its children), which destroys operator trust. Match
        // by PID (this process and its direct children) and by executable name.
        let own_pid = std::process::id();
        if event.pid == own_pid || event.ppid == own_pid {
            return None;
        }
        let pname = event.process_name.to_lowercase();
        if pname == "nebula-agent" || pname == "nebula-agent.exe" {
            return None;
        }

        // Combine all rule sets. NOTE: MitreRules::evaluate() already appends
        // MitreRulesExtended internally (see its final line), so we must NOT
        // evaluate Extended again here — doing so double-counts every extended
        // hit into the summed score below and inflates severity/false positives.
        let mut hits = MitreRules::evaluate(event);
        hits.extend(MitreRulesV15Complete::evaluate(event));
        if hits.is_empty() { return None; }

        // Aggregate the per-technique scores into one confidence.
        //
        // The old rule — sum, capped at 100 — let several individually WEAK,
        // often-benign hits stack into High/Critical (a handful of score-15
        // heuristics summed past the threshold). That was the single largest
        // source of behavioral false positives. `combine_scores` instead anchors
        // on the strongest signal and adds only DAMPED credit for corroboration,
        // so you need either one genuinely strong hit or a strong hit plus real
        // corroboration to cross the bar — not a pile of trivia. See its tests.
        let scores: Vec<f32> = hits.iter().map(|h| h.score).collect();
        let score = combine_scores(&scores);
        if score < self.config.confidence_threshold { return None; }

        let severity = score_to_severity(score);
        let tactics:    Vec<String> = hits.iter().map(|h| h.tactic.to_string()).collect::<std::collections::HashSet<_>>().into_iter().collect();
        let techniques: Vec<String> = hits.iter().map(|h| {
            h.sub.unwrap_or(h.technique).to_string()
        }).collect::<std::collections::HashSet<_>>().into_iter().collect();
        let descriptions: Vec<String> = hits.iter().map(|h| h.description.to_string()).collect();

        let action = response_action(&severity, event);

        let mut iocs = vec![];
        if let Some(ip) = &event.network_dest_ip {
            iocs.push(IOC { ioc_type: IOCType::Ipv4, value: ip.clone(), source: "behavioral".into(), confidence: score });
        }
        if let Some(fp) = &event.file_path {
            iocs.push(IOC { ioc_type: IOCType::FilePath, value: fp.clone(), source: "behavioral".into(), confidence: score });
        }
        if let Some(hash) = &event.file_hash {
            iocs.push(IOC { ioc_type: IOCType::Sha256, value: hash.clone(), source: "behavioral".into(), confidence: score });
        }

        // Chain detection (config patterns + all built-in patterns)
        let chain = if self.config.chain_detection {
            let all_patterns: Vec<_> = self.config.chain_patterns.iter()
                .chain(all_chain_patterns().iter())
                .cloned()
                .collect();
            self.update_chains(event, &techniques, score, &all_patterns).await
        } else { None };

        let primary = &hits[0];
        info!("🚨 [{severity}] {tech} — {desc} | host={host} pid={pid} score={score:.1}",
            severity = severity,
            tech = primary.sub.unwrap_or(primary.technique),
            desc = primary.description,
            host = event.hostname,
            pid = event.pid,
            score = score);

        Some(ThreatEvent {
            id: Uuid::new_v4().to_string(),
            agent_id: event.agent_id.clone(),
            hostname: event.hostname.clone(),
            timestamp: event.timestamp,
            severity,
            confidence: score,
            threat_name: format!("{} — {}",
                primary.sub.unwrap_or(primary.technique), primary.description),
            description: descriptions.join("; "),
            mitre_tactics: tactics,
            mitre_techniques: techniques,
            matched_rules: vec!["mitre_attck_v15_heuristic".to_string()],
            raw_event_ids: vec![event.id.clone()],
            chain,
            iocs,
            suggested_action: action,
            llm_analysis: None,
            auto_generated_rule: None,
        })
    }

    async fn update_chains(
        &self,
        event: &RawEvent,
        techniques: &[String],
        score: f32,
        patterns: &[crate::config::ChainPattern],
    ) -> Option<AttackChain> {
        let host = &event.hostname;
        let window = chrono::Duration::seconds(self.config.chain_window_secs as i64);
        let now = Utc::now();

        let mut host_chains = self.active_chains.entry(host.clone()).or_default();
        host_chains.retain(|c| now.signed_duration_since(c.last_seen) < window);

        for pattern in patterns {
            if !techniques.iter().any(|t| pattern.techniques.iter().any(|pt| t.starts_with(pt) || pt.starts_with(t))) {
                continue;
            }

            let existing = host_chains.iter_mut().find(|c| c.name == pattern.name);
            let chain = if let Some(c) = existing {
                c
            } else {
                host_chains.push(ActiveChain {
                    name: pattern.name.clone(),
                    stages: vec![],
                    first_seen: now,
                    last_seen: now,
                    matched_techniques: vec![],
                    required_techniques: pattern.techniques.clone(),
                    min_confidence: pattern.min_confidence,
                });
                host_chains.last_mut().unwrap()
            };

            for t in techniques {
                if !chain.matched_techniques.contains(t) {
                    chain.matched_techniques.push(t.clone());
                }
            }
            chain.last_seen = now;
            chain.stages.push(ChainStage {
                tactic: techniques.first().cloned().unwrap_or_default(),
                technique: techniques.first().cloned().unwrap_or_default(),
                event_id: event.id.clone(),
                timestamp: event.timestamp,
                description: event.command_line.clone()
                    .unwrap_or_else(|| event.process_name.clone()),
            });

            let matched = chain.matched_techniques.iter()
                .filter(|t| chain.required_techniques.iter().any(|r| t.starts_with(r) || r.starts_with(t.as_str())))
                .count();
            let completion = matched as f32 / chain.required_techniques.len() as f32;
            let chain_conf = score * completion;

            if chain_conf >= chain.min_confidence && matched >= 2 {
                warn!("⛓️ CHAIN DETECTED: '{}' ({}/{} techniques, conf={:.1})",
                    chain.name, matched, chain.required_techniques.len(), chain_conf);
                return Some(AttackChain {
                    name: chain.name.clone(),
                    stages: chain.stages.clone(),
                    first_seen: chain.first_seen,
                    last_seen: chain.last_seen,
                    confidence: chain_conf,
                });
            }
        }
        None
    }
}

/// How much weight corroborating (non-dominant) hits contribute, relative to
/// their face value. The dominant hit counts in full; everything else is scaled
/// by this. Low enough that benign trivia can't stack into a high-severity
/// alert, high enough that genuine corroboration still escalates.
const CORROBORATION_DAMP: f32 = 0.35;

/// Combine per-technique hit scores into a single confidence in [0, 100].
///
/// Rationale (replaces the former naive sum-capped-at-100): take the single
/// strongest hit at full weight, then add the sum of the rest damped by
/// [`CORROBORATION_DAMP`]. This keeps the behaviour operators expect —
///   * one strong signal (e.g. 90) alerts on its own,
///   * a strong signal + corroboration escalates,
///   * many weak signals do NOT snowball into Critical,
/// while never exceeding 100.
fn combine_scores(scores: &[f32]) -> f32 {
    if scores.is_empty() { return 0.0; }
    // Clamp inputs defensively so a malformed heuristic score can't distort it.
    let mut v: Vec<f32> = scores.iter().map(|s| s.clamp(0.0, 100.0)).collect();
    // Descending, so index 0 is the dominant hit.
    v.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let dominant = v[0];
    let rest: f32 = v[1..].iter().sum();
    (dominant + rest * CORROBORATION_DAMP).min(100.0)
}

fn score_to_severity(score: f32) -> Severity {
    if score >= 90.0      { Severity::Critical }
    else if score >= 75.0 { Severity::High }
    else if score >= 50.0 { Severity::Medium }
    else if score >= 25.0 { Severity::Low }
    else                  { Severity::Info }
}

fn response_action(severity: &Severity, event: &RawEvent) -> ResponseAction {
    match severity {
        Severity::Critical => ResponseAction::IsolateHost,
        Severity::High     => ResponseAction::KillProcess(event.pid),
        Severity::Medium   => ResponseAction::Alert,
        _                  => ResponseAction::Monitor,
    }
}

// ══════════════════════════════════════════════════════════════════
// ADDITIONAL COVERAGE BLOCK — appended to MitreRules::evaluate
// This function is called by MitreRules::evaluate via a second pass.
// All techniques below are additive to the main 196-heuristic engine.
// ══════════════════════════════════════════════════════════════════
pub struct MitreRulesExtended;

impl MitreRulesExtended {
    pub fn evaluate(event: &RawEvent) -> Vec<TechniqueHit> {
        let mut hits = Vec::new();
        let cmd   = event.command_line.as_deref().unwrap_or("").to_lowercase();
        let proc  = event.process_name.to_lowercase();
        let fpath = event.file_path.as_deref().unwrap_or("").to_lowercase();
        let uid   = event.uid;

        // ══════════════════════════════════════════════════════════
        // PROCESS INJECTION — FULL T1055 SUITE (all sub-techniques)
        // ══════════════════════════════════════════════════════════

        // T1055.011 — Extra Window Memory (EWM) injection
        if cmd.contains("setwindowlongptr") || cmd.contains("getwindowlong") && cmd.contains("exec") {
            hits.push(h(85.0, "defense_evasion", "T1055", Some("T1055.011"), "EWM injection: SetWindowLongPtr used to execute code in window proc"));
        }

        // T1055.013 — Process Doppelganging
        // Uses NTFS transactions to create a transacted section from malicious file, then rolls back
        if cmd.contains("transactedhollowin") || cmd.contains("doppelganging") || cmd.contains("ntcreatefile") && cmd.contains("transaction") {
            hits.push(h(92.0, "defense_evasion", "T1055", Some("T1055.013"), "Process Doppelganging: NTFS transaction-based process injection"));
        }

        // T1055.015 — ListPlanting
        // Abuses callback functions in Windows list-view controls
        if cmd.contains("listview") && cmd.contains("lvsetitem") && cmd.contains("exec") {
            hits.push(h(80.0, "defense_evasion", "T1055", Some("T1055.015"), "ListPlanting: exploiting list-view control callbacks for code execution"));
        }

        // Generic process hollowing signals from /proc
        // A process that opens /proc/other_pid/mem for WRITING = hollowing
        if fpath.contains("/proc/") && fpath.contains("/mem") && event.event_type == crate::types::EventType::FileWrite {
            hits.push(h(97.0, "defense_evasion", "T1055", Some("T1055.012"),
                "PROCESS HOLLOWING: write to /proc/PID/mem — classic hollow or RunPE technique. \
                 Legitimate processes never write to another process's memory this way."));
        }

        // Deleted-on-disk ELF running from memfd (fileless hollow)
        if fpath.contains("memfd:") || fpath.contains("/proc/self/fd") && fpath.contains("exe") {
            hits.push(h(95.0, "defense_evasion", "T1055", Some("T1055.012"),
                "PROCESS HOLLOWING/FILELESS: execution from memfd_create() anonymous file — payload never touched disk"));
        }

        // ══════════════════════════════════════════════════════════
        // T1218 — SYSTEM BINARY PROXY EXECUTION (LOLBins — full coverage)
        // ══════════════════════════════════════════════════════════

        // T1218.001 — Compiled HTML File (.chm)
        if cmd.contains(".chm") || (proc == "hh" && cmd.contains("javascript")) {
            hits.push(h(80.0, "defense_evasion", "T1218", Some("T1218.001"), "CHM compiled HTML file execution via hh.exe (LOLBin)"));
        }

        // T1218.003 — CMSTP
        if proc == "cmstp" || cmd.contains("cmstp") {
            hits.push(h(85.0, "defense_evasion", "T1218", Some("T1218.003"), "CMSTP LOLBin: Microsoft Connection Manager Profile Installer used for payload exec"));
        }

        // T1218.005 — Mshta
        if proc == "mshta" || cmd.contains("mshta") {
            hits.push(h(82.0, "defense_evasion", "T1218", Some("T1218.005"), "Mshta LOLBin: HTML Application Host used for malicious HTA execution"));
        }

        // T1218.007 — Msiexec
        if proc == "msiexec" && (cmd.contains("http://") || cmd.contains("https://") || cmd.contains("/q ")) {
            hits.push(h(78.0, "defense_evasion", "T1218", Some("T1218.007"), "Msiexec LOLBin: MSI installer executing remote/quiet payload"));
        }

        // T1218.010 — Regsvr32
        if proc == "regsvr32" && (cmd.contains("/s") || cmd.contains("scrobj") || cmd.contains("http")) {
            hits.push(h(85.0, "defense_evasion", "T1218", Some("T1218.010"), "Regsvr32 LOLBin: Squiblydoo — COM scriptlet proxy execution"));
        }

        // T1218.011 — Rundll32
        if proc == "rundll32" && (cmd.contains("javascript:") || cmd.contains(",#") || cmd.contains("advpack")) {
            hits.push(h(80.0, "defense_evasion", "T1218", Some("T1218.011"), "Rundll32 LOLBin: proxy execution via DLL export or JavaScript scheme"));
        }

        // Linux LOLBins — execution via trusted utilities (GTFOBins extended)
        if proc == "awk" && cmd.contains("system(") {
            hits.push(h(75.0, "defense_evasion", "T1218", None, "LOLBin: awk system() — shell execution via trusted interpreter"));
        }
        if (proc == "python" || proc == "python3") && cmd.contains("subprocess") && cmd.contains("shell=true") {
            hits.push(h(70.0, "defense_evasion", "T1218", None, "LOLBin: Python subprocess shell=True — shell escape via trusted binary"));
        }
        if proc == "perl" && cmd.contains("-mposix") && cmd.contains("system") {
            hits.push(h(75.0, "defense_evasion", "T1218", None, "LOLBin: Perl POSIX system() call execution"));
        }
        if proc == "php" && cmd.contains("exec(") {
            hits.push(h(75.0, "defense_evasion", "T1218", None, "LOLBin: PHP exec() — arbitrary command via web language runtime"));
        }
        if proc == "irb" || (proc == "ruby" && cmd.contains("exec(")) {
            hits.push(h(70.0, "defense_evasion", "T1218", None, "LOLBin: Ruby irb/exec() shell execution"));
        }
        if proc == "node" && cmd.contains("child_process") {
            hits.push(h(70.0, "defense_evasion", "T1218", None, "LOLBin: Node.js child_process execution"));
        }
        if proc == "gdb" && cmd.contains("--batch") && cmd.contains("--eval") {
            hits.push(h(80.0, "defense_evasion", "T1218", None, "LOLBin: gdb --eval — debugger used for command execution"));
        }
        if proc == "strace" && cmd.contains("-e") && cmd.contains("exec") {
            hits.push(h(65.0, "defense_evasion", "T1218", None, "LOLBin: strace exec() — syscall tracer abused for execution"));
        }
        if proc == "tee" && cmd.contains("/etc/") {
            hits.push(h(70.0, "defense_evasion", "T1218", None, "LOLBin: tee writing to /etc/ — file overwrite via trusted binary"));
        }
        if proc == "curl" && cmd.contains("-o") && (fpath.contains("/tmp/") || fpath.contains("/dev/shm")) {
            hits.push(h(72.0, "defense_evasion", "T1218", None, "LOLBin: curl download to /tmp — payload staging via trusted binary"));
        }
        if proc == "cp" && fpath.contains("/etc/passwd") {
            hits.push(h(78.0, "defense_evasion", "T1218", None, "LOLBin: cp overwriting /etc/passwd — privilege manipulation via trusted binary"));
        }
        if proc == "sed" && cmd.contains("-i") && (fpath.contains("/etc/") || fpath.contains("/.ssh/")) {
            hits.push(h(75.0, "defense_evasion", "T1218", None, "LOLBin: sed -i modifying config file in-place"));
        }
        if proc == "dd" && fpath.contains("/dev/") && uid > 100 {
            hits.push(h(80.0, "defense_evasion", "T1218", None, "LOLBin: dd writing to device file — raw disk manipulation"));
        }

        // T1216 — System Script Proxy Execution
        if (proc == "bash" || proc == "sh") && fpath.contains("/usr/share/") && cmd.contains("exec") {
            hits.push(h(65.0, "defense_evasion", "T1216", None, "System script proxy execution via /usr/share/ path"));
        }

        // T1220 — XSL Script Processing
        if cmd.contains("msxsl") || cmd.contains("wmic") && cmd.contains(".xsl") {
            hits.push(h(80.0, "defense_evasion", "T1220", None, "XSL script processing via msxsl/wmic — XSLT code execution LOLBin"));
        }

        // T1221 — Template Injection
        if cmd.contains(".docx") && cmd.contains("http://") && cmd.contains("template") {
            hits.push(h(75.0, "initial_access", "T1221", None, "Template injection: remote template loaded from HTTP in Office document"));
        }
        if fpath.ends_with(".dotm") || fpath.ends_with(".xltm") {
            hits.push(h(65.0, "initial_access", "T1221", None, "Macro-enabled template file (.dotm/.xltm) — template injection vector"));
        }

        // ══════════════════════════════════════════════════════════
        // T1140 — DEOBFUSCATE/DECODE (expanded)
        // ══════════════════════════════════════════════════════════
        if cmd.contains("certutil") && (cmd.contains("-decode") || cmd.contains("-urlcache") || cmd.contains("-f")) {
            hits.push(h(82.0, "defense_evasion", "T1140", None, "certutil.exe decode/download (LOLBin payload staging)"));
        }
        if cmd.contains("openssl base64 -d") || cmd.contains("openssl enc -d") {
            hits.push(h(65.0, "defense_evasion", "T1140", None, "OpenSSL base64/cipher decode — payload deobfuscation"));
        }
        if cmd.contains("python") && cmd.contains("base64.b64decode") {
            hits.push(h(70.0, "defense_evasion", "T1140", None, "Python base64.b64decode — in-memory payload decoding"));
        }
        if cmd.contains("echo") && cmd.contains("| base64 -d |") && cmd.contains("bash") {
            hits.push(h(88.0, "defense_evasion", "T1140", None, "Inline base64 decode pipe to bash — fileless execution"));
        }

        // ══════════════════════════════════════════════════════════
        // T1562 — IMPAIR DEFENSES (expanded sub-techniques)
        // ══════════════════════════════════════════════════════════

        // T1562.006 — Indicator Blocking (ETW / audit log tampering)
        if cmd.contains("patchguard") || cmd.contains("etw") && cmd.contains("null") {
            hits.push(h(90.0, "defense_evasion", "T1562", Some("T1562.006"), "ETW/PatchGuard indicator blocking — security telemetry tampering"));
        }
        if cmd.contains("ntdll") && (cmd.contains("patch") || cmd.contains("hook")) && uid == 0 {
            hits.push(h(88.0, "defense_evasion", "T1562", Some("T1562.006"), "ntdll patching in process memory — API hook for indicator blocking"));
        }
        // Disabling Linux audit by patching audit syscall filter
        if cmd.contains("bpf") && cmd.contains("socket_filter") && uid == 0 {
            hits.push(h(85.0, "defense_evasion", "T1562", Some("T1562.006"), "eBPF socket filter installed by privileged process — possible audit bypass"));
        }

        // T1562.010 — Downgrade Attack
        if cmd.contains("--tls1") || cmd.contains("--ssl3") || cmd.contains("sslv3") {
            hits.push(h(72.0, "defense_evasion", "T1562", Some("T1562.010"), "TLS/SSL downgrade forced — weaker protocol for MITM interception"));
        }
        if cmd.contains("update-alternatives") && cmd.contains("openssl") {
            hits.push(h(55.0, "defense_evasion", "T1562", Some("T1562.010"), "OpenSSL alternative version switch — possible crypto downgrade"));
        }

        // T1562.012 — Disable or Modify Linux Audit System
        if cmd.contains("auditctl -e 0") || cmd.contains("systemctl mask auditd") || cmd.contains("apt purge auditd") {
            hits.push(h(92.0, "defense_evasion", "T1562", Some("T1562.012"), "Linux audit system disabled/removed — T1562.012 indicator"));
        }
        if fpath.contains("/etc/audit/auditd.conf") && event.event_type == crate::types::EventType::FileWrite {
            hits.push(h(80.0, "defense_evasion", "T1562", Some("T1562.012"), "auditd.conf modified — audit rules may be weakened"));
        }
        if fpath.contains("/etc/audit/rules.d/") && event.event_type == crate::types::EventType::FileWrite {
            hits.push(h(78.0, "defense_evasion", "T1562", Some("T1562.012"), "Audit rules file modified — detection coverage may be reduced"));
        }

        // ══════════════════════════════════════════════════════════
        // T1037 — BOOT/LOGON INITIALIZATION SCRIPTS
        // ══════════════════════════════════════════════════════════

        // T1037.004 — RC Scripts
        if fpath.contains("/etc/rc.local") || fpath.contains("/etc/init.d/") || fpath.contains("/etc/rc") {
            hits.push(h(70.0, "persistence", "T1037", Some("T1037.004"), "Boot init/RC script persistence — runs on every system start"));
        }

        // T1037.005 — Startup Items (macOS/Linux equivalent: XDG autostart)
        if fpath.contains(".desktop") && fpath.contains("autostart") && event.event_type == crate::types::EventType::FileWrite {
            hits.push(h(70.0, "persistence", "T1037", Some("T1037.005"), "XDG/Desktop autostart item created — user login persistence"));
        }

        // ══════════════════════════════════════════════════════════
        // T1176 — BROWSER EXTENSIONS
        // ══════════════════════════════════════════════════════════
        if fpath.contains("extensions") && (fpath.contains("chrome") || fpath.contains("firefox") || fpath.contains("chromium")) {
            if event.event_type == crate::types::EventType::FileWrite {
                hits.push(h(72.0, "persistence", "T1176", None, "Browser extension files modified — possible malicious extension installed"));
            }
        }
        if cmd.contains("chrome") && cmd.contains("--load-extension") {
            hits.push(h(75.0, "persistence", "T1176", None, "Chrome extension force-loaded via --load-extension — malicious extension install"));
        }

        // ══════════════════════════════════════════════════════════
        // T1185 — BROWSER SESSION HIJACKING
        // ══════════════════════════════════════════════════════════
        if fpath.contains("cookies.sqlite") || fpath.contains("cookies.db") || fpath.contains("Login Data") {
            hits.push(h(78.0, "credential_access", "T1185", None, "Browser session database accessed — possible session hijacking"));
        }
        if cmd.contains("chrome") && cmd.contains("--user-data-dir=/tmp") {
            hits.push(h(70.0, "credential_access", "T1185", None, "Chrome launched with /tmp user-data-dir — session isolation bypass"));
        }

        // ══════════════════════════════════════════════════════════
        // T1528 — STEAL APPLICATION ACCESS TOKEN
        // ══════════════════════════════════════════════════════════
        if cmd.contains("gcloud auth") && cmd.contains("print-access-token") {
            hits.push(h(80.0, "credential_access", "T1528", None, "GCP access token theft via gcloud auth print-access-token"));
        }
        if cmd.contains("az account get-access-token") {
            hits.push(h(80.0, "credential_access", "T1528", None, "Azure access token theft via az account get-access-token"));
        }
        if cmd.contains("aws sts get-session-token") || cmd.contains("aws sts assume-role") {
            hits.push(h(75.0, "credential_access", "T1528", None, "AWS STS session token or role assumption — possible token theft"));
        }
        if fpath.contains("gcloud/credentials") || fpath.contains("gcloud/application_default_credentials") {
            hits.push(h(80.0, "credential_access", "T1528", None, "GCP application default credentials file accessed"));
        }

        // ══════════════════════════════════════════════════════════
        // T1649 — STEAL OR FORGE AUTHENTICATION CERTIFICATES
        // ══════════════════════════════════════════════════════════
        if cmd.contains("certipy") || cmd.contains("certify.exe") || cmd.contains("adcs") {
            hits.push(h(90.0, "credential_access", "T1649", None, "AD Certificate Services attack tool (Certipy/Certify) — certificate theft/forgery"));
        }
        if cmd.contains("openssl pkcs12") && cmd.contains("-export") {
            hits.push(h(72.0, "credential_access", "T1649", None, "PKCS12 certificate export — possible credential theft"));
        }
        if fpath.contains("/etc/ssl/private/") && event.event_type == crate::types::EventType::FileOpen && uid > 100 {
            hits.push(h(85.0, "credential_access", "T1649", None, "Private TLS certificate accessed by non-privileged process"));
        }

        // ══════════════════════════════════════════════════════════
        // T1654 — LOG ENUMERATION
        // ══════════════════════════════════════════════════════════
        if (cmd.contains("cat") || cmd.contains("grep") || cmd.contains("less") || cmd.contains("tail")) &&
           (fpath.contains("/var/log/auth") || fpath.contains("/var/log/secure") || fpath.contains("audit.log")) {
            hits.push(h(45.0, "discovery", "T1654", None, "Security log enumeration — attacker reading auth/audit logs"));
        }
        if cmd.contains("journalctl") && (cmd.contains("_comm=sshd") || cmd.contains("_comm=sudo")) {
            hits.push(h(40.0, "discovery", "T1654", None, "Journald security event enumeration"));
        }
        if cmd.contains("last") || cmd.contains("lastlog") || cmd.contains("lastb") {
            hits.push(h(35.0, "discovery", "T1654", None, "Login history enumeration (last/lastlog/lastb)"));
        }

        // ══════════════════════════════════════════════════════════
        // T1087.003/.004 — CLOUD ACCOUNT DISCOVERY
        // ══════════════════════════════════════════════════════════
        if cmd.contains("aws iam list-users") || cmd.contains("aws iam list-roles") {
            hits.push(h(55.0, "discovery", "T1087", Some("T1087.004"), "AWS IAM user/role enumeration — cloud account discovery"));
        }
        if cmd.contains("gcloud iam service-accounts list") {
            hits.push(h(55.0, "discovery", "T1087", Some("T1087.004"), "GCP service account enumeration — cloud account discovery"));
        }
        if cmd.contains("az ad user list") || cmd.contains("az role assignment list") {
            hits.push(h(55.0, "discovery", "T1087", Some("T1087.004"), "Azure AD user/role enumeration — cloud account discovery"));
        }

        // ══════════════════════════════════════════════════════════
        // T1526 — CLOUD SERVICE DISCOVERY
        // ══════════════════════════════════════════════════════════
        if cmd.contains("aws --list-services") || cmd.contains("aws ec2 describe-instances") ||
           cmd.contains("aws rds describe-db-instances") {
            hits.push(h(45.0, "discovery", "T1526", None, "AWS cloud service enumeration — asset discovery"));
        }
        if cmd.contains("gcloud compute instances list") || cmd.contains("gcloud services list") {
            hits.push(h(45.0, "discovery", "T1526", None, "GCP cloud service enumeration"));
        }

        // T1538 — Cloud Service Dashboard
        if cmd.contains("console.aws.amazon.com") || cmd.contains("cloud.google.com/console") {
            hits.push(h(30.0, "discovery", "T1538", None, "Cloud management console access — reconnaissance"));
        }

        // ══════════════════════════════════════════════════════════
        // T1613 — CONTAINER AND RESOURCE DISCOVERY
        // ══════════════════════════════════════════════════════════
        if cmd.contains("docker ps") || cmd.contains("docker inspect") || cmd.contains("docker network ls") {
            hits.push(h(35.0, "discovery", "T1613", None, "Docker container/network enumeration — container discovery"));
        }
        if cmd.contains("kubectl get pods") || cmd.contains("kubectl get deployments") || cmd.contains("kubectl get services") {
            hits.push(h(40.0, "discovery", "T1613", None, "Kubernetes resource enumeration — container orchestrator discovery"));
        }
        if cmd.contains("kubectl get namespaces") || cmd.contains("kubectl get nodes") {
            hits.push(h(45.0, "discovery", "T1613", None, "K8s cluster topology discovery — node/namespace enumeration"));
        }

        // ══════════════════════════════════════════════════════════
        // T1480 — EXECUTION GUARDRAILS (anti-analysis / environment keying)
        // ══════════════════════════════════════════════════════════
        if cmd.contains("hostname") && cmd.contains("exit") && cmd.contains("if") {
            hits.push(h(55.0, "defense_evasion", "T1480", None, "Execution guardrail: hostname check before payload — environment keying"));
        }
        if cmd.contains("whoami") && cmd.contains("if") && cmd.contains("exit") {
            hits.push(h(55.0, "defense_evasion", "T1480", None, "Execution guardrail: whoami check — payload runs only for specific user"));
        }
        if (cmd.contains("cat /proc/cpuinfo") || cmd.contains("ls /sys/class/dmi")) && cmd.contains("exit") {
            hits.push(h(60.0, "defense_evasion", "T1480", Some("T1480.001"), "Environmental keying: hardware check before execution — VM/sandbox evasion"));
        }

        // ══════════════════════════════════════════════════════════
        // T1598 — PHISHING FOR INFORMATION
        // ══════════════════════════════════════════════════════════
        if cmd.contains("gophish") || cmd.contains("evilginx") || cmd.contains("modlishka") {
            hits.push(h(90.0, "reconnaissance", "T1598", None, "Phishing framework detected (GoPhish/Evilginx/Modlishka)"));
        }
        if cmd.contains("setoolkit") || cmd.contains("social-engineer") {
            hits.push(h(88.0, "reconnaissance", "T1598", None, "Social Engineering Toolkit (SET) — phishing/credential harvesting"));
        }

        // ══════════════════════════════════════════════════════════
        // T1588 — OBTAIN CAPABILITIES
        // ══════════════════════════════════════════════════════════
        if cmd.contains("exploit-db") || cmd.contains("searchsploit") {
            hits.push(h(65.0, "resource_development", "T1588", None, "Exploit-DB search — obtaining exploit capability"));
        }
        if cmd.contains("wget") && (fpath.contains("exploit") || fpath.contains("poc") || fpath.contains("cve-")) {
            hits.push(h(75.0, "resource_development", "T1588", None, "Downloading exploit/PoC code — capability acquisition"));
        }

        // ══════════════════════════════════════════════════════════
        // T1608 — STAGE CAPABILITIES
        // ══════════════════════════════════════════════════════════
        if cmd.contains("git init") && (fpath.contains("/var/www") || fpath.contains("/tmp")) {
            hits.push(h(55.0, "resource_development", "T1608", None, "Git repository staged in web-accessible/temp directory — payload staging"));
        }
        // A local `python -m http.server` is extremely common in benign
        // development, so on its own it is NOT payload staging — flagging it
        // (and escalating a supply-chain playbook) is a false positive on any
        // developer workstation. Only treat it as staging when it serves from a
        // suspicious location (temp/system dirs) or pairs with payload-like
        // artifacts. Otherwise it's dev activity, not a threat.
        if (cmd.contains("python3 -m http.server") || cmd.contains("python -m simplehttpserver")
            || cmd.contains("python -m http.server")) &&
           (fpath.contains("/tmp") || fpath.contains("/dev/shm") || fpath.contains("\\temp\\")
            || fpath.contains("\\windows\\") || cmd.contains(".sh") || cmd.contains(".ps1")
            || cmd.contains("payload") || cmd.contains("beacon")) {
            hits.push(h(60.0, "resource_development", "T1608", None, "Staging HTTP server serving from suspicious location — possible payload distribution"));
        }

        // ══════════════════════════════════════════════════════════
        // T1657 — FINANCIAL THEFT (new in ATT&CK v15)
        // ══════════════════════════════════════════════════════════
        if cmd.contains("bitcoin") || cmd.contains("wallet.dat") || cmd.contains("metamask") {
            hits.push(h(80.0, "impact", "T1657", None, "Cryptocurrency wallet access — financial theft indicator (T1657)"));
        }
        if cmd.contains("bip39") || cmd.contains("seed phrase") || cmd.contains("mnemonic") {
            hits.push(h(85.0, "impact", "T1657", None, "Crypto seed phrase enumeration — financial theft preparation"));
        }

        // ══════════════════════════════════════════════════════════
        // T1660 — COMPROMISE INFRASTRUCTURE (new in ATT&CK v15)
        // ══════════════════════════════════════════════════════════
        if cmd.contains("bgpstream") || cmd.contains("bgp hijack") || cmd.contains("as_path") && cmd.contains("prepend") {
            hits.push(h(95.0, "resource_development", "T1660", None, "BGP route manipulation — infrastructure compromise indicator (T1660)"));
        }
        if cmd.contains("arp-scan") && cmd.contains("-l") && uid != 0 {
            hits.push(h(60.0, "resource_development", "T1660", None, "ARP network sweep by non-root — possible infrastructure reconnaissance"));
        }

        // ══════════════════════════════════════════════════════════
        // T1059.009 — CLOUD API EXECUTION
        // ══════════════════════════════════════════════════════════
        if cmd.contains("aws lambda invoke") || cmd.contains("gcloud functions call") {
            hits.push(h(60.0, "execution", "T1059", Some("T1059.009"), "Serverless function invocation — cloud API execution"));
        }
        if cmd.contains("aws ssm send-command") || cmd.contains("aws ssm start-session") {
            hits.push(h(75.0, "execution", "T1059", Some("T1059.009"), "AWS SSM send-command — cloud API for remote execution"));
        }

        // ══════════════════════════════════════════════════════════
        // T1059.010 — AUTOHOTKEY / AUTOIT
        // ══════════════════════════════════════════════════════════
        if proc == "autohotkey" || proc == "autoit3" || fpath.ends_with(".ahk") || fpath.ends_with(".au3") {
            hits.push(h(65.0, "execution", "T1059", Some("T1059.010"), "AutoHotKey/AutoIT execution — automation script used for malicious execution"));
        }

        // ══════════════════════════════════════════════════════════
        // ADDITIONAL CREDENTIAL ACCESS TECHNIQUES
        // ══════════════════════════════════════════════════════════

        // T1556.004 — Network Device Authentication
        if cmd.contains("cisco") && (cmd.contains("tacacs") || cmd.contains("radius")) {
            hits.push(h(70.0, "credential_access", "T1556", Some("T1556.004"), "Network device authentication config modification (Cisco/TACACS)"));
        }

        // T1212 expanded — additional exploit tools
        if cmd.contains("log4shell") || cmd.contains("cve-2021-44228") {
            hits.push(h(98.0, "initial_access", "T1190", None, "Log4Shell exploit attempt (CVE-2021-44228) — Log4j RCE"));
        }
        if cmd.contains("proxylogon") || cmd.contains("cve-2021-26855") {
            hits.push(h(98.0, "initial_access", "T1190", None, "ProxyLogon MS Exchange exploit (CVE-2021-26855)"));
        }
        if cmd.contains("proxyshell") || cmd.contains("cve-2021-34473") {
            hits.push(h(98.0, "initial_access", "T1190", None, "ProxyShell MS Exchange exploit (CVE-2021-34473)"));
        }
        if cmd.contains("follina") || cmd.contains("cve-2022-30190") {
            hits.push(h(98.0, "execution", "T1203", None, "Follina MSDT exploit (CVE-2022-30190) — MS Word RCE"));
        }
        if cmd.contains("spring4shell") || cmd.contains("cve-2022-22965") {
            hits.push(h(98.0, "initial_access", "T1190", None, "Spring4Shell RCE exploit (CVE-2022-22965)"));
        }
        if cmd.contains("cve-2023-44487") || cmd.contains("http2 rapid reset") {
            hits.push(h(85.0, "impact", "T1498", None, "HTTP/2 Rapid Reset DoS (CVE-2023-44487 — CVSS 7.5)"));
        }
        if cmd.contains("citrix bleed") || cmd.contains("cve-2023-4966") {
            hits.push(h(98.0, "credential_access", "T1539", None, "CitrixBleed session token theft (CVE-2023-4966) — Citrix ADC"));
        }
        if cmd.contains("cve-2024-3400") || cmd.contains("palo alto") && cmd.contains("os command") {
            hits.push(h(98.0, "initial_access", "T1190", None, "PAN-OS OS command injection (CVE-2024-3400) — Palo Alto firewall RCE"));
        }
        if cmd.contains("regreSSHion") || cmd.contains("cve-2024-6387") {
            hits.push(h(98.0, "initial_access", "T1190", None, "regreSSHion OpenSSH race condition (CVE-2024-6387) — unauthenticated RCE"));
        }

        // ══════════════════════════════════════════════════════════
        // ADDITIONAL PERSISTENCE TECHNIQUES
        // ══════════════════════════════════════════════════════════

        // T1556.007 — Hybrid Identity (ADFS)
        if cmd.contains("adfs") && (cmd.contains("export") || cmd.contains("signing")) {
            hits.push(h(88.0, "credential_access", "T1556", Some("T1556.007"), "ADFS token signing certificate accessed — hybrid identity attack"));
        }

        // Dynamic linker hijack (additional vector)
        if fpath.contains("/etc/ld.so.conf.d/") && event.event_type == crate::types::EventType::FileWrite {
            hits.push(h(82.0, "persistence", "T1574", Some("T1574.006"), "ld.so.conf.d entry added — dynamic linker search path hijack"));
        }

        // Python path hijacking
        if fpath.contains("site-packages") && event.event_type == crate::types::EventType::FileWrite && uid > 100 {
            hits.push(h(70.0, "persistence", "T1574", None, "Python site-packages modified by non-root — module hijack persistence"));
        }

        // npm global package hijack
        if fpath.contains("node_modules/.bin/") && event.event_type == crate::types::EventType::FileWrite && uid > 100 {
            hits.push(h(72.0, "persistence", "T1574", None, "npm global binary modified — Node.js dependency hijack"));
        }

        // Gem/pip post-install hooks
        if (cmd.contains("pip install") || cmd.contains("gem install")) &&
           (cmd.contains("--user") || uid > 100) {
            // Only flag if from unusual location
            if cmd.contains("--index-url") || cmd.contains("file://") {
                hits.push(h(68.0, "persistence", "T1195", Some("T1195.002"), "Package installed from non-standard index — dependency confusion/supply chain"));
            }
        }

        hits
    }
}

// ══════════════════════════════════════════════════════════════
// MitreRulesV15Complete — fills every gap in ATT&CK v15
// Appended to MitreRulesExtended by AnomalyEngine.analyze()
// ══════════════════════════════════════════════════════════════

pub struct MitreRulesV15Complete;

impl MitreRulesV15Complete {
    pub fn evaluate(event: &RawEvent) -> Vec<TechniqueHit> {
        let mut hits = Vec::new();
        let cmd   = event.command_line.as_deref().unwrap_or("").to_lowercase();
        let proc  = event.process_name.to_lowercase();
        let fpath = event.file_path.as_deref().unwrap_or("").to_lowercase();
        let uid   = event.uid;
        let ip    = event.network_dest_ip.as_deref().unwrap_or("");
        let port  = event.network_dest_port.unwrap_or(0);

        // ══════════════════════════════════════════════════════
        // PROCESS INJECTION — DEEP COVERAGE (T1055 all subs)
        // ══════════════════════════════════════════════════════

        // T1055.001 — Dynamic-link Library Injection (Linux: SO injection via dlopen)
        if (cmd.contains("dlopen") || cmd.contains("ld_preload="))
            && (fpath.starts_with("/tmp") || fpath.starts_with("/dev/shm"))
        {
            hits.push(h(90.0, "defense_evasion", "T1055", Some("T1055.001"),
                "SO injection: dlopen() from writable directory or LD_PRELOAD from temp path"));
        }

        // T1055.002 — Portable Executable Injection (PE/ELF via memfd)
        if cmd.contains("memfd_create") || (fpath.contains("memfd:") && uid < 500) {
            hits.push(h(93.0, "defense_evasion", "T1055", Some("T1055.002"),
                "PE/ELF injection via memfd_create — anonymous file exec (fileless)"));
        }

        // T1055.003 — Thread Execution Hijacking
        if cmd.contains("ptrace") && cmd.contains("setregs") {
            hits.push(h(91.0, "defense_evasion", "T1055", Some("T1055.003"),
                "Thread execution hijacking via ptrace SETREGS — redirecting thread IP"));
        }

        // T1055.004 — Asynchronous Procedure Call (APC injection via Linux io_uring)
        if cmd.contains("io_uring") && (cmd.contains("exec") || cmd.contains("send")) {
            hits.push(h(82.0, "defense_evasion", "T1055", Some("T1055.004"),
                "APC-style injection via io_uring — async execution primitive abuse"));
        }

        // T1055.008 — ptrace API (already in main rules; add /proc/mem write variant)
        if fpath.contains("/proc/") && fpath.ends_with("/mem")
            && event.event_type == crate::types::EventType::FileWrite
        {
            hits.push(h(97.0, "defense_evasion", "T1055", Some("T1055.008"),
                "ptrace/proc-mem injection: direct write to /proc/PID/mem — \
                 process hollowing, RunPE, or shellcode injection"));
        }

        // T1055.009 — Proc Memory (reading maps + writing shellcode)
        if fpath.contains("/proc/") && fpath.ends_with("/maps")
            && uid > 0 && uid < 500
        {
            hits.push(h(75.0, "defense_evasion", "T1055", Some("T1055.009"),
                "Process memory map enumeration — first step of /proc-based injection"));
        }

        // T1055.012 — Process Hollowing (Linux: unmap + remap ELF segments)
        // Pattern: process reads its own /proc/self/exe then calls mmap with PROT_EXEC
        if fpath.contains("/proc/self/exe") && uid < 500 {
            hits.push(h(88.0, "defense_evasion", "T1055", Some("T1055.012"),
                "Process hollowing setup: reading own exe image (prelude to segment replacement)"));
        }
        // Classic hollow: creates a process suspended, unmaps its image, maps new one
        if cmd.contains("create_process") && cmd.contains("suspend") {
            hits.push(h(92.0, "defense_evasion", "T1055", Some("T1055.012"),
                "Classic process hollowing: CREATE_SUSPENDED → unmap → new image map"));
        }

        // T1055.014 — VDSO Hijacking (Linux: modify vDSO mappings)
        if fpath.contains("vdso") || cmd.contains("vdso") {
            hits.push(h(90.0, "defense_evasion", "T1055", Some("T1055.014"),
                "vDSO hijacking: modifying Linux virtual dynamic shared object — kernel bypass"));
        }

        // ══════════════════════════════════════════════════════
        // CREDENTIAL ACCESS — FULL COVERAGE
        // ══════════════════════════════════════════════════════

        // T1003.004 — LSA Secrets (reg save HKLM\Security)
        if cmd.contains("reg save") && cmd.contains("security") {
            hits.push(h(95.0, "credential_access", "T1003", Some("T1003.004"),
                "LSA Secrets dump: reg save HKLM\\Security — offline credential extraction"));
        }

        // T1003.005 — Cached Domain Credentials (DCC2 hashes)
        if cmd.contains("cachedump") || cmd.contains("mscache") ||
           (cmd.contains("reg") && cmd.contains("nlkm"))
        {
            hits.push(h(92.0, "credential_access", "T1003", Some("T1003.005"),
                "Cached Domain Credentials (DCC2): nlkm hash extraction for offline cracking"));
        }

        // T1003.006 — DCSync (replicates DC credentials without logging)
        if cmd.contains("dcsync") || cmd.contains("drsuapi") ||
           (cmd.contains("lsadump::dcsync") || cmd.contains("replication"))
               && cmd.contains("ldap")
        {
            hits.push(h(97.0, "credential_access", "T1003", Some("T1003.006"),
                "DCSync attack: replicating AD credentials via DRS protocol — \
                 no domain admin needed if ReplicatingDirectoryChanges right held"));
        }

        // T1003.007 — /proc memory credential dump (Linux specific)
        if fpath.contains("/proc/") && (fpath.contains("/mem") || fpath.contains("/fd"))
            && (proc == "strings" || proc == "cat" || proc == "grep" || proc == "hexdump")
        {
            hits.push(h(88.0, "credential_access", "T1003", Some("T1003.007"),
                "Linux /proc memory credential dump: reading process memory for plaintext creds \
                 (targets: sshd, sudo, su, pam processes)"));
        }
        // Specific: /proc/sshd_pid/mem read
        if fpath.contains("/proc/") && fpath.contains("/mem") {
            if let Some(pid_part) = fpath.strip_prefix("/proc/") {
                if !pid_part.starts_with("self") {
                    hits.push(h(94.0, "credential_access", "T1003", Some("T1003.007"),
                        "Cross-process /proc/PID/mem read — targeting another process's \
                         memory space for credential extraction"));
                }
            }
        }

        // T1110.002 — Password Cracking (hashcat, john, ophcrack)
        if proc == "hashcat" || proc == "john" || proc == "ophcrack" ||
           cmd.contains("hashcat") || cmd.contains("john --") ||
           (cmd.contains("--attack-mode") || cmd.contains("-a "))
               && (cmd.contains("hash") || fpath.ends_with(".hash"))
        {
            hits.push(h(80.0, "credential_access", "T1110", Some("T1110.002"),
                "Password cracking: hashcat/John the Ripper running against captured hashes"));
        }

        // T1110.003 — Password Spraying
        if (proc == "spray" || cmd.contains("spray") || cmd.contains("--spray"))
            && (cmd.contains("ssh") || cmd.contains("smb") || cmd.contains("ldap"))
        {
            hits.push(h(82.0, "credential_access", "T1110", Some("T1110.003"),
                "Password spraying: single password against many accounts — evades lockout"));
        }
        if cmd.contains("kerbrute") && cmd.contains("passwordspray") {
            hits.push(h(90.0, "credential_access", "T1110", Some("T1110.003"),
                "Kerbrute password spray against Kerberos — low-noise AD credential attack"));
        }

        // T1110.004 — Credential Stuffing
        if cmd.contains("credential") && cmd.contains("stuff") ||
           cmd.contains("stuffing") ||
           (cmd.contains("--userlist") && cmd.contains("--passlist") && cmd.contains("http"))
        {
            hits.push(h(78.0, "credential_access", "T1110", Some("T1110.004"),
                "Credential stuffing: using breach credential lists against authentication services"));
        }

        // T1078.001 — Default Accounts
        if (cmd.contains("su root") || cmd.contains("su -")) && uid == 0 {
            hits.push(h(55.0, "privilege_escalation", "T1078", Some("T1078.001"),
                "Default account usage: root login from non-privileged context"));
        }
        // Common default credentials in use
        if cmd.contains("admin:admin") || cmd.contains("root:root") ||
           cmd.contains("admin:password") || cmd.contains("admin:123456")
        {
            hits.push(h(70.0, "initial_access", "T1078", Some("T1078.001"),
                "Default credentials in command line — attempting authentication with defaults"));
        }

        // T1078.002 — Domain Accounts
        if (cmd.contains("net use") || cmd.contains("runas")) &&
           (cmd.contains("\\") || cmd.contains("@domain"))
        {
            hits.push(h(60.0, "defense_evasion", "T1078", Some("T1078.002"),
                "Domain account usage for lateral movement or privilege"));
        }

        // T1087.003 — Email Account Discovery
        if cmd.contains("ldapsearch") && cmd.contains("mail") ||
           cmd.contains("get-mailbox") || cmd.contains("exchange") &&
           cmd.contains("get-") && cmd.contains("mailbox")
        {
            hits.push(h(55.0, "discovery", "T1087", Some("T1087.003"),
                "Email account discovery: enumerating mailboxes via LDAP or Exchange"));
        }

        // T1071.001 — Web Protocols C2 (HTTP/HTTPS beaconing)
        // Regular HTTP/HTTPS callbacks to non-standard ports
        if port > 1024 && port != 8080 && port != 8443 && port != 3000 && port != 5000 &&
           !ip.is_empty() && !ip.starts_with("10.") && !ip.starts_with("192.168.")
        {
            if event.event_type == crate::types::EventType::NetworkConnect {
                // Only flag http/https-like patterns on non-standard ports
                if port == 80 || port == 443 || (port > 8000 && port < 9000) ||
                   (port > 4000 && port < 5000)
                {
                    hits.push(h(35.0, "command_and_control", "T1071", Some("T1071.001"),
                        "Web protocol C2 candidate: outbound HTTP/HTTPS to external host"));
                }
            }
        }

        // T1071.002 — File Transfer Protocol C2 (FTP, SFTP for C2)
        if port == 21 || port == 22 || port == 69 {
            if !ip.starts_with("10.") && !ip.starts_with("192.168.") && !ip.is_empty() {
                hits.push(h(45.0, "command_and_control", "T1071", Some("T1071.002"),
                    "File transfer protocol to external host — FTP/SFTP possible C2 channel"));
            }
        }

        // T1071.003 — Mail Protocols C2 (SMTP/IMAP/POP for C2)
        if port == 25 || port == 587 || port == 993 || port == 995 || port == 143 {
            if !ip.starts_with("10.") && !ip.starts_with("192.168.") && !ip.is_empty() {
                hits.push(h(50.0, "command_and_control", "T1071", Some("T1071.003"),
                    "Mail protocol outbound — SMTP/IMAP/POP possible C2 or exfiltration channel"));
            }
        }

        // ══════════════════════════════════════════════════════
        // PERSISTENCE — COMPLETE COVERAGE
        // ══════════════════════════════════════════════════════

        // T1546.001 — Change Default File Association
        if cmd.contains("xdg-mime") && cmd.contains("default") ||
           fpath.contains(".desktop") && fpath.contains("Exec=") &&
           event.event_type == crate::types::EventType::FileWrite
        {
            hits.push(h(70.0, "persistence", "T1546", Some("T1546.001"),
                "Default file association modified via xdg-mime or .desktop file — persistence"));
        }

        // T1546.005 — Unix Trap command backdoor
        if cmd.contains("trap") && (cmd.contains("SIGTERM") || cmd.contains("SIGKILL") ||
           cmd.contains("EXIT") || cmd.contains("ERR"))
            && (cmd.contains("bash") || cmd.contains("curl") || cmd.contains("nc"))
        {
            hits.push(h(72.0, "persistence", "T1546", Some("T1546.005"),
                "Unix trap backdoor: shell signal trap used for persistence/C2 callback"));
        }

        // T1546.013 — PowerShell Profile persistence
        if fpath.contains("powershell") && fpath.contains("profile") &&
           event.event_type == crate::types::EventType::FileWrite
        {
            hits.push(h(75.0, "persistence", "T1546", Some("T1546.013"),
                "PowerShell profile modified — persistence via auto-executed PS profile"));
        }

        // T1547.009 — Shortcut Modification (.desktop files on Linux)
        if fpath.ends_with(".desktop") && fpath.contains("/usr/share/applications/") &&
           event.event_type == crate::types::EventType::FileWrite && uid > 0
        {
            hits.push(h(68.0, "persistence", "T1547", Some("T1547.009"),
                "System .desktop launcher modified — shortcut hijack for persistence"));
        }

        // T1547.013 — XDG autostart persistence
        if fpath.contains(".config/autostart/") &&
           event.event_type == crate::types::EventType::FileWrite
        {
            hits.push(h(65.0, "persistence", "T1547", Some("T1547.013"),
                "XDG autostart entry created — persistent execution on user login"));
        }

        // ══════════════════════════════════════════════════════
        // DEFENSE EVASION — COMPLETE COVERAGE
        // ══════════════════════════════════════════════════════

        // T1553.002 — Code Signing bypass (ignore signature checks)
        if cmd.contains("--allow-unauthenticated") || cmd.contains("--no-check-certificate") ||
           cmd.contains("insecure") && cmd.contains("gpg") ||
           cmd.contains("dpkg --force-all") || cmd.contains("rpm --nosignature")
        {
            hits.push(h(65.0, "defense_evasion", "T1553", Some("T1553.002"),
                "Code signing verification bypassed — installing unsigned/untrusted packages"));
        }

        // T1553.005 — Mark-of-the-Web bypass
        if cmd.contains("xattr") && cmd.contains("com.apple.quarantine") &&
           cmd.contains("delete")
        {
            hits.push(h(70.0, "defense_evasion", "T1553", Some("T1553.005"),
                "Quarantine extended attribute removed — Mark-of-the-Web bypass"));
        }

        // T1565 — Data Manipulation
        if cmd.contains("dd if=") && fpath.contains("/var/lib/") &&
           !fpath.contains("/dev/null")
        {
            hits.push(h(82.0, "impact", "T1565", Some("T1565.001"),
                "Stored data manipulation: dd overwriting database or critical data files"));
        }
        // T1565.002 — Transmitted data manipulation (MITM indicators)
        if cmd.contains("arpspoof") || cmd.contains("ettercap") ||
           cmd.contains("bettercap") || cmd.contains("mitmproxy")
        {
            hits.push(h(88.0, "collection", "T1565", Some("T1565.002"),
                "MITM tool detected — transmitted data manipulation possible (arpspoof/ettercap/bettercap)"));
        }
        // T1565.003 — Runtime data manipulation (memory patch)
        if fpath.contains("/proc/") && fpath.contains("/mem") &&
           event.event_type == crate::types::EventType::FileWrite && uid == 0
        {
            hits.push(h(88.0, "impact", "T1565", Some("T1565.003"),
                "Runtime data manipulation: writing to live process memory space"));
        }

        // ══════════════════════════════════════════════════════
        // IMPACT — COMPLETE COVERAGE
        // ══════════════════════════════════════════════════════

        // T1499 — Endpoint Denial of Service
        if (cmd.contains("stress") || cmd.contains("stress-ng")) &&
           (cmd.contains("--cpu") || cmd.contains("--vm") || cmd.contains("--io"))
        {
            hits.push(h(70.0, "impact", "T1499", Some("T1499.001"),
                "Endpoint DoS: stress/stress-ng consuming CPU/memory/IO resources"));
        }
        if cmd.contains("fork bomb") || cmd.contains(":(){ :|:& };:") ||
           (proc == "bash" && cmd.contains("while true") && cmd.contains("fork"))
        {
            hits.push(h(95.0, "impact", "T1499", Some("T1499.001"),
                "Fork bomb detected — OS exhaustion DoS payload"));
        }
        // T1499.002 — Service Exhaustion
        if (cmd.contains("slowloris") || cmd.contains("hping3") ||
            cmd.contains("ab ") && cmd.contains("-n") && cmd.contains("-c")) &&
           !ip.starts_with("10.") && !ip.is_empty()
        {
            hits.push(h(80.0, "impact", "T1499", Some("T1499.002"),
                "Service exhaustion DoS tool (slowloris/hping3/ab) targeting external service"));
        }
        // T1499.003 — Application Exhaustion Flood
        if cmd.contains("wrk") || cmd.contains("siege") || cmd.contains("locust") {
            hits.push(h(65.0, "impact", "T1499", Some("T1499.003"),
                "Application load testing tool — possible DoS against application layer"));
        }

        // T1529 — System Shutdown / Reboot (after ransomware or destruction)
        if proc == "shutdown" || proc == "reboot" || proc == "halt" ||
           cmd.contains("shutdown -h") || cmd.contains("reboot -f") ||
           cmd.contains("systemctl poweroff")
        {
            // Only suspicious if executed by non-root or in unusual context
            if uid != 0 || cmd.contains("-f") || cmd.contains("--force") {
                hits.push(h(75.0, "impact", "T1529", None,
                    "System shutdown/reboot command — suspicious forced shutdown post-impact"));
            }
        }

        // T1653 — Power Settings modification (disable sleep for miners)
        if cmd.contains("systemd-inhibit") || cmd.contains("xset dpms off") ||
           (fpath.contains("sleep") && event.event_type == crate::types::EventType::FileWrite
            && fpath.contains("/sys/"))
        {
            hits.push(h(55.0, "impact", "T1653", None,
                "Power settings modified — sleep/hibernate disabled (possible cryptominer keepalive)"));
        }

        // ══════════════════════════════════════════════════════
        // DISCOVERY — COMPLETE COVERAGE
        // ══════════════════════════════════════════════════════

        // T1046 — Network Service Discovery (targeted ports)
        if (proc == "nmap" || proc == "masscan") &&
           (cmd.contains("-sV") || cmd.contains("-sC") || cmd.contains("-p "))
        {
            hits.push(h(65.0, "discovery", "T1046", None,
                "Network service discovery scan with version/script detection"));
        }

        // T1074.002 — Remote Data Staging
        if (cmd.contains("scp") || cmd.contains("sftp") || cmd.contains("rsync")) &&
           cmd.contains("/tmp/")
        {
            hits.push(h(65.0, "collection", "T1074", Some("T1074.002"),
                "Remote data staging: transferring data to /tmp before exfil via SCP/rsync"));
        }

        // ══════════════════════════════════════════════════════
        // CONTAINERS — COMPLETE COVERAGE
        // ══════════════════════════════════════════════════════

        // T1609 — Container Administration Command (exec into running container)
        if (proc == "docker" && cmd.contains("exec")) ||
           (proc == "kubectl" && cmd.contains("exec")) ||
           (proc == "crictl" && cmd.contains("exec"))
        {
            hits.push(h(55.0, "execution", "T1609", None,
                "Container admin exec: docker/kubectl exec into running container — \
                 investigate if this is scheduled maintenance or attacker pivoting"));
        }

        // T1612 — Build Image on Host (malicious Dockerfile)
        if proc == "docker" && cmd.contains("build") &&
           (cmd.contains("http://") || cmd.contains("/tmp/") || uid > 100)
        {
            hits.push(h(68.0, "defense_evasion", "T1612", None,
                "Docker image built on host from untrusted location — possible malicious container staging"));
        }

        // ══════════════════════════════════════════════════════
        // CLOUD & IAM — COMPLETE COVERAGE
        // ══════════════════════════════════════════════════════

        // T1621 — MFA Request Generation (MFA fatigue/push bombing)
        if cmd.contains("mfa") && (cmd.contains("push") || cmd.contains("request")) ||
           cmd.contains("duo") && cmd.contains("bypass") ||
           cmd.contains("okta") && cmd.contains("push") && cmd.contains("loop")
        {
            hits.push(h(82.0, "credential_access", "T1621", None,
                "MFA fatigue attack: automated MFA push requests to exhaust user's attention"));
        }

        // T1651 — Cloud Administration Command
        if cmd.contains("aws ssm send-command") || cmd.contains("az vm run-command") ||
            cmd.contains("gcloud compute ssh") || cmd.contains("gcloud compute instances exec")
        {
            hits.push(h(70.0, "execution", "T1651", None,
                "Cloud admin command execution via SSM/RunCommand — possible lateral movement"));
        }

        // T1656 — Impersonation
        if cmd.contains("--impersonate") || cmd.contains("impersonation") ||
           (cmd.contains("service account") && cmd.contains("token")) ||
           (proc == "gcloud" && cmd.contains("--impersonate-service-account"))
        {
            hits.push(h(75.0, "defense_evasion", "T1656", None,
                "Identity impersonation: service account or user impersonation for privilege"));
        }

        // T1659 — Content Injection
        if cmd.contains("mitmproxy") || cmd.contains("mitmf") ||
           (cmd.contains("iptables") && cmd.contains("--to-destination") && cmd.contains("REDIRECT"))
        {
            hits.push(h(78.0, "command_and_control", "T1659", None,
                "Content injection: MITM proxy or traffic redirection for response tampering"));
        }

        // ══════════════════════════════════════════════════════
        // COLLECTION — COMPLETE COVERAGE
        // ══════════════════════════════════════════════════════

        // T1056.001 — Keylogging
        if proc == "logkeys" || proc == "xspy" || proc == "xinput" ||
           cmd.contains("xinput test") || cmd.contains("evtest") && cmd.contains("/dev/input")
        {
            hits.push(h(85.0, "collection", "T1056", Some("T1056.001"),
                "Keylogger active: logkeys/xspy/xinput capturing keystrokes"));
        }

        // T1113 — Screen capture
        if proc == "scrot" || proc == "import" && cmd.contains("-window root") ||
           cmd.contains("xwd -root") || proc == "gnome-screenshot" && uid > 100
        {
            hits.push(h(60.0, "collection", "T1113", None,
                "Screen capture: automated screenshot tool invoked — possible data collection"));
        }

        // T1115 — Clipboard Data
        if proc == "xclip" || proc == "xsel" || proc == "wl-copy" ||
           cmd.contains("xclip -o") || cmd.contains("xsel --output")
        {
            hits.push(h(55.0, "collection", "T1115", None,
                "Clipboard data access: xclip/xsel reading clipboard contents"));
        }

        // ══════════════════════════════════════════════════════
        // LATERAL MOVEMENT — COMPLETE COVERAGE
        // ══════════════════════════════════════════════════════

        // T1021.004 — SSH lateral (with unusual key or host pattern)
        if proc == "ssh" && uid > 100 &&
           (cmd.contains("-i /tmp/") || cmd.contains("-i /dev/shm/") ||
            cmd.contains("-o StrictHostKeyChecking=no"))
        {
            hits.push(h(70.0, "lateral_movement", "T1021", Some("T1021.004"),
                "Suspicious SSH: using key from /tmp or disabling host key checking — \
                 lateral movement with stolen key material"));
        }

        // T1021.006 — Windows Remote Management (WinRM — cross-platform)
        if port == 5985 || port == 5986 {
            hits.push(h(55.0, "lateral_movement", "T1021", Some("T1021.006"),
                "WinRM connection (port 5985/5986) — Windows remote management lateral movement"));
        }

        // T1550.002 — Pass-the-Hash (enhanced detection)
        if cmd.contains("pth-winexe") || cmd.contains("impacket") && cmd.contains("-hashes") ||
           cmd.contains("secretsdump") || cmd.contains("wmiexec") && cmd.contains(":aad3b")
        {
            hits.push(h(94.0, "lateral_movement", "T1550", Some("T1550.002"),
                "Pass-the-Hash: impacket/secretsdump/pth-winexe with NTLM hash — \
                 authentication without plaintext password"));
        }

        hits
    }
}

#[cfg(test)]
mod score_tests {
    use super::{combine_scores, score_to_severity, Severity};

    #[test]
    fn empty_is_zero() {
        assert_eq!(combine_scores(&[]), 0.0);
    }

    #[test]
    fn single_hit_passes_through() {
        assert_eq!(combine_scores(&[90.0]), 90.0);
        assert_eq!(combine_scores(&[40.0]), 40.0);
    }

    #[test]
    fn many_weak_hits_do_not_snowball_into_high() {
        // Five benign-ish score-15 heuristics. Old sum rule → 75 (High!).
        // New rule: 15 + (15*4)*0.35 = 15 + 21 = 36 → stays Low, below a 70 bar.
        let s = combine_scores(&[15.0, 15.0, 15.0, 15.0, 15.0]);
        assert!((s - 36.0).abs() < 0.01, "got {s}");
        assert!(matches!(score_to_severity(s), Severity::Low));
    }

    #[test]
    fn strong_hit_plus_corroboration_escalates() {
        // A real signal (70) with three corroborating 20s.
        // 70 + (60)*0.35 = 91 → Critical, as it should.
        let s = combine_scores(&[70.0, 20.0, 20.0, 20.0]);
        assert!((s - 91.0).abs() < 0.01, "got {s}");
        assert!(matches!(score_to_severity(s), Severity::Critical));
    }

    #[test]
    fn order_independent_and_capped() {
        assert_eq!(combine_scores(&[20.0, 90.0]), combine_scores(&[90.0, 20.0]));
        // Cannot exceed 100 even with many strong hits.
        assert!(combine_scores(&[90.0, 90.0, 90.0, 90.0]) <= 100.0);
    }

    #[test]
    fn out_of_range_scores_are_clamped() {
        assert_eq!(combine_scores(&[150.0]), 100.0);
        assert_eq!(combine_scores(&[-5.0, -5.0]), 0.0);
    }
}
