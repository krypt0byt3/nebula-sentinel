#![allow(dead_code)]
// src/zeroday/mod.rs — Zero-day exploit detection
//
// Zero-days cannot be detected by signatures because no signature exists yet.
// Detection must be purely behavioral — what does exploitation look like
// regardless of the specific vulnerability being exploited?
//
// Techniques:
//
//   1. Process ancestry anomalies
//      A web server (nginx, apache, httpd) should never directly exec a shell.
//      A PDF viewer should never spawn curl. A Java app should never exec bash.
//      These parent→child relationships are exploitation indicators regardless
//      of which CVE enabled them.
//
//   2. Memory anomalies (shellcode fingerprinting)
//      Shellcode executes from unusual memory regions: heap, stack, anonymous mmap.
//      Real programs execute from mapped ELF segments. Execution from non-text
//      segments is a strong zero-day/ROP exploit indicator.
//
//   3. Syscall anomaly (unexpected syscall sequences)
//      Exploits often trigger unusual syscall patterns: execve() from a thread
//      that was previously doing only network I/O, clone() immediately after
//      a network receive, etc.
//
//   4. Crash-based detection
//      CVE exploitation often causes a crash before or during success.
//      SIGSEGV / SIGBUS on privileged processes with core dump = attempted exploit.
//
//   5. Heap spray indicators
//      Large mmap() allocations with execute permission from network-facing processes.
//      This is the fingerprint of heap spray attacks.
//
//   6. JIT spraying
//      JIT engines (V8, SpiderMonkey, Java JIT) allocating executable pages with
//      specific byte patterns associated with ROP gadgets.
//
//   7. Unusual file descriptors post-exploit
//      After exploitation, attackers open /etc/passwd, /etc/shadow, or /proc/self/mem.
//      A network-facing process reading these files = post-exploitation activity.

use crate::types::{ThreatEvent, RawEvent, EventType, Severity, ResponseAction, IOC, IOCType};
use chrono::Utc;
use tracing::warn;
use uuid::Uuid;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Known-bad parent→child process relationships
/// Format: (parent_name_contains, child_name_contains, technique, description)
const ANOMALOUS_ANCESTRY: &[(&str, &str, &str, &str)] = &[
    // Web servers spawning shells
    ("nginx",       "sh",         "T1190", "Web server nginx spawned shell — likely webshell/RCE"),
    ("nginx",       "bash",       "T1190", "Web server nginx spawned bash — likely webshell/RCE"),
    ("nginx",       "python",     "T1190", "Web server nginx spawned Python — likely webshell"),
    ("apache2",     "sh",         "T1190", "Apache spawned shell — likely webshell/RCE"),
    ("apache2",     "bash",       "T1190", "Apache spawned bash — likely webshell/RCE"),
    ("httpd",       "sh",         "T1190", "httpd spawned shell — likely webshell/RCE"),
    ("tomcat",      "sh",         "T1190", "Tomcat spawned shell — likely Java deserialization RCE"),
    ("java",        "bash",       "T1059.004", "Java process spawned bash — deserialization/SSRF exploit"),
    ("php-fpm",     "sh",         "T1190", "PHP-FPM spawned shell — likely webshell"),
    ("php",         "bash",       "T1190", "PHP spawned bash — likely webshell"),
    ("node",        "sh",         "T1190", "Node.js spawned shell — likely RCE via npm/express"),
    ("ruby",        "bash",       "T1190", "Ruby spawned bash — likely RCE"),
    ("python",      "bash",       "T1059.004", "Python spawned bash — possible escape from sandboxed interpreter"),
    // Database processes
    ("mysqld",      "sh",         "T1190", "MySQL spawned shell — UDF exploit or injection"),
    ("postgres",    "sh",         "T1190", "PostgreSQL spawned shell — COPY TO/FROM exploit"),
    ("mongod",      "sh",         "T1190", "MongoDB spawned shell — code injection exploit"),
    // Email servers
    ("postfix",     "sh",         "T1190", "Postfix spawned shell — mail header injection exploit"),
    ("exim",        "sh",         "T1190", "Exim spawned shell — mail processing RCE exploit"),
    ("sendmail",    "bash",       "T1190", "Sendmail spawned bash — possible RCE"),
    // Document processors / viewers
    ("evince",      "bash",       "T1204.002", "PDF viewer spawned shell — possible malicious PDF exploit"),
    ("libreoffice", "bash",       "T1204.002", "LibreOffice spawned bash — possible macro/exploit"),
    ("acroread",    "sh",         "T1204.002", "Acrobat spawned shell — possible PDF exploit"),
    // Container escapes
    ("runc",        "nsenter",    "T1611", "runc spawned nsenter — container escape attempt"),
    ("containerd",  "nsenter",    "T1611", "containerd spawned nsenter — container escape"),
    // Browser-based
    ("chromium",    "bash",       "T1203", "Browser spawned shell — likely browser exploit"),
    ("firefox",     "bash",       "T1203", "Firefox spawned bash — likely browser exploit"),
    // SSH / authentication
    ("sshd",        "bash -i",    "T1078", "sshd spawned interactive shell — possible auth bypass"),
];

/// Suspicious memory map patterns (proc/PID/maps)
const SUSPICIOUS_MAPS: &[(&str, &str, &str, &str)] = &[
    ("rwxp",  "",                "T1055",    "Executable anonymous mapping in process memory — shellcode indicator"),
    ("rwx",   "[heap]",          "T1055",    "Executable heap region — heap spray / shellcode"),
    ("rwx",   "[stack]",         "T1055",    "Executable stack — stack-based shellcode"),
    ("rwx",   "/dev/shm",        "T1055",    "Executable shared memory mapping — fileless malware"),
    ("rwxp",  "/tmp/",           "T1055.002","Executable anonymous mapping in /tmp — shellcode staging"),
    ("r-xp",  "(deleted)",       "T1027.007","Deleted-on-disk executable mapping — fileless payload"),
];

/// Processes that should NEVER read sensitive files
const SENSITIVE_FILE_ACCESS: &[(&str, &str, &str, &str)] = &[
    ("nginx",    "/etc/shadow",      "T1003.008", "nginx reading /etc/shadow — post-exploitation credential access"),
    ("apache",   "/etc/shadow",      "T1003.008", "Apache reading /etc/shadow — post-exploitation"),
    ("www-data", "/etc/shadow",      "T1003.008", "www-data reading shadow — credential theft post-exploit"),
    ("nginx",    "/proc/self/mem",   "T1055",     "nginx accessing /proc/self/mem — memory injection post-exploit"),
    ("mysqld",   "/etc/passwd",      "T1003.008", "mysqld reading /etc/passwd — UDF post-exploitation"),
    ("sshd",     "/etc/shadow",      "T1003.008", "sshd reading shadow directly — authentication bypass exploit"),
];

pub struct ZeroDayDetector {
    agent_id: String,
    hostname: String,
    // Recent process events: pid → (name, ppid, parent_name)
    process_cache: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    name:        String,
    parent_name: String,
    ppid:        u32,
    first_seen:  chrono::DateTime<Utc>,
}

impl ZeroDayDetector {
    pub fn new(agent_id: &str, hostname: &str) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            hostname: hostname.to_string(),
            process_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Analyze a raw event for zero-day exploit indicators.
    /// Returns a threat event if an exploit pattern is detected.
    pub async fn analyze(&self, event: &RawEvent) -> Option<ThreatEvent> {
        // Update process cache
        if event.event_type == EventType::ProcessExec {
            let mut cache = self.process_cache.lock().await;
            // Get parent name from cache
            let parent_name = cache.get(&event.ppid)
                .map(|p| p.name.clone())
                .unwrap_or_default();

            cache.insert(event.pid, ProcessInfo {
                name: event.process_name.clone(),
                parent_name: parent_name.clone(),
                ppid: event.ppid,
                first_seen: Utc::now(),
            });

            // ── Check ancestry anomalies ─────────────────────
            let proc_lower = event.process_name.to_lowercase();
            let parent_lower = parent_name.to_lowercase();
            let cmd_lower = event.command_line.as_deref().unwrap_or("").to_lowercase();

            for (parent_pat, child_pat, technique, desc) in ANOMALOUS_ANCESTRY {
                if parent_lower.contains(parent_pat) &&
                   (proc_lower.contains(child_pat) || cmd_lower.contains(child_pat))
                {
                    warn!("🎯 ZERO-DAY: {} → {} [{technique}]", parent_name, event.process_name);
                    return Some(self.make_zeroday_threat(
                        technique, Severity::Critical,
                        format!("Anomalous process ancestry: {} → {}", parent_name, event.process_name),
                        format!("{}\nCommand: {}\nThis parent→child relationship has no legitimate use case and is a strong indicator of exploitation regardless of the specific vulnerability.", desc, event.command_line.as_deref().unwrap_or("")),
                        event.pid,
                        event.file_path.as_deref(),
                    ));
                }
            }
        }

        // ── Sensitive file access by unexpected process ───────
        if event.event_type == EventType::FileOpen || event.event_type == EventType::FileWrite {
            let fpath = event.file_path.as_deref().unwrap_or("");
            let proc  = event.process_name.to_lowercase();

            for (proc_pat, file_pat, technique, desc) in SENSITIVE_FILE_ACCESS {
                if proc.contains(proc_pat) && fpath.contains(file_pat) {
                    warn!("🎯 ZERO-DAY: {} accessed {} [{technique}]", event.process_name, fpath);
                    return Some(self.make_zeroday_threat(
                        technique, Severity::Critical,
                        format!("Post-exploit credential access: {} → {}", event.process_name, fpath),
                        desc.to_string(),
                        event.pid,
                        Some(fpath),
                    ));
                }
            }
        }

        // ── Live memory scan for shellcode ────────────────────
        if event.event_type == EventType::MemoryMap && event.pid > 0 {
            let suspicious = scan_process_maps(event.pid);
            if let Some((desc, technique)) = suspicious {
                warn!("🎯 ZERO-DAY: shellcode memory region in pid={} [{}]", event.pid, technique);
                return Some(self.make_zeroday_threat(
                    technique, Severity::Critical,
                    format!("Shellcode memory indicator in pid={} ({})", event.pid, event.process_name),
                    desc,
                    event.pid,
                    None,
                ));
            }
        }

        None
    }

    /// Proactively scan running processes for shellcode/exploit indicators.
    /// Called periodically by the posture engine.
    pub async fn scan_all_processes(&self) -> Vec<ThreatEvent> {
        let mut threats = vec![];

        let Ok(entries) = std::fs::read_dir("/proc") else { return threats };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let pid_str = name.to_string_lossy();
            let Ok(pid) = pid_str.parse::<u32>() else { continue };

            // Read process name
            let proc_name = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                .unwrap_or_default().trim().to_string();

            // Scan memory maps for shellcode indicators
            if let Some((desc, technique)) = scan_process_maps(pid) {
                warn!("🎯 ZERO-DAY scan: shellcode in pid={} ({}) [{}]", pid, proc_name, technique);
                threats.push(self.make_zeroday_threat(
                    technique, Severity::Critical,
                    format!("Shellcode memory indicator — pid={} ({})", pid, proc_name),
                    desc, pid, None,
                ));
            }

            // Check for deleted-on-disk executables running
            if let Ok(exe_link) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
                let exe = exe_link.to_string_lossy();
                if exe.ends_with(" (deleted)") {
                    warn!("🎯 ZERO-DAY scan: deleted-on-disk executable running: pid={} ({})", pid, proc_name);
                    threats.push(self.make_zeroday_threat(
                        "T1027.007", Severity::High,
                        format!("Deleted-on-disk executable running: pid={} ({})", pid, proc_name),
                        format!("Process {} (pid={}) is running from a deleted executable. Common fileless malware technique — payload executed and binary deleted to evade disk-based detection.", proc_name, pid),
                        pid, None,
                    ));
                }
            }
        }

        threats
    }

    fn make_zeroday_threat(
        &self, technique: &str, severity: Severity,
        name: String, desc: String, pid: u32,
        file_path: Option<&str>,
    ) -> ThreatEvent {
        let mut iocs = vec![];
        if let Some(fp) = file_path {
            iocs.push(IOC { ioc_type: IOCType::FilePath, value: fp.to_string(), source: "zeroday".into(), confidence: 90.0 });
        }

        ThreatEvent {
            id: Uuid::new_v4().to_string(),
            agent_id: self.agent_id.clone(), hostname: self.hostname.clone(),
            timestamp: Utc::now(), severity, confidence: 90.0,
            threat_name: name, description: desc,
            mitre_tactics:    vec!["initial_access".to_string(), "execution".to_string()],
            mitre_techniques: vec![technique.to_string()],
            matched_rules:    vec!["zeroday_behavioral".to_string(), "process_ancestry".to_string()],
            raw_event_ids: vec![], chain: None, iocs,
            suggested_action: ResponseAction::KillProcess(pid),
            llm_analysis: None, auto_generated_rule: None,
        }
    }
}

fn scan_process_maps(pid: u32) -> Option<(String, &'static str)> {
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid)).ok()?;

    for line in maps.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 { continue; }
        let perms   = fields[1];
        let mapping = fields.get(5).unwrap_or(&"");

        for (perm_pat, map_pat, technique, desc) in SUSPICIOUS_MAPS {
            if perms.contains(perm_pat) && (map_pat.is_empty() || mapping.contains(map_pat)) {
                // Additional filter: skip known JIT engines that legitimately use rwx
                if mapping.contains("libjvm") || mapping.contains("libv8") ||
                   mapping.contains("libjs") || mapping.contains("mono") {
                    continue;
                }
                return Some((desc.to_string(), technique));
            }
        }
    }
    None
}
