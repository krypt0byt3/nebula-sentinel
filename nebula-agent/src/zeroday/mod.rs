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
//
// ── Confidence tiering (noise reduction) ────────────────────────────────────
// Not every behavioral pattern is equally damning, yet this module used to stamp
// every hit with confidence 90 + Critical + KillProcess. That conflates a
// near-certain compromise (a web server spawning a shell) with routine activity
// that merely *resembles* exploitation — an interpreter shelling out (`python →
// bash` is everyday automation), an interactive SSH login (`sshd → bash -i` IS a
// normal login shell), or a process running from a binary that was updated under
// it (any `apt upgrade` leaves `(deleted)` exe links). Each pattern now carries
// its own confidence, and the response engine already gates KillProcess /
// Quarantine / Isolate on `confidence >= threshold` (see response/mod.rs). So a
// weak signal (e.g. 55) can never escalate to a destructive auto-response the way
// a uniform 90 could once an operator lowered `auto_kill_threshold` to 90 — while
// genuine server/DB-compromise patterns (90+) still reach KillProcess. Severity
// and suggested action are both derived from the per-pattern confidence via
// `tier()`.

use crate::types::{ThreatEvent, RawEvent, EventType, Severity, ResponseAction, IOC, IOCType};
use chrono::Utc;
use tracing::warn;
use uuid::Uuid;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Known-bad parent→child process relationships.
/// Format: (parent_name_contains, child_name_contains, technique, confidence, description)
/// Confidence encodes signal quality: server/DB/mail/document-viewer → shell is
/// near-certain exploitation (90+); an interpreter or SSH login shelling out is
/// common and legitimate, so it only warrants an alert (45–70).
const ANOMALOUS_ANCESTRY: &[(&str, &str, &str, f32, &str)] = &[
    // Web servers spawning shells — near-certain webshell/RCE.
    ("nginx",       "sh",         "T1190", 95.0, "Web server nginx spawned shell — likely webshell/RCE"),
    ("nginx",       "bash",       "T1190", 95.0, "Web server nginx spawned bash — likely webshell/RCE"),
    ("nginx",       "python",     "T1190", 92.0, "Web server nginx spawned Python — likely webshell"),
    ("apache2",     "sh",         "T1190", 95.0, "Apache spawned shell — likely webshell/RCE"),
    ("apache2",     "bash",       "T1190", 95.0, "Apache spawned bash — likely webshell/RCE"),
    ("httpd",       "sh",         "T1190", 95.0, "httpd spawned shell — likely webshell/RCE"),
    ("tomcat",      "sh",         "T1190", 93.0, "Tomcat spawned shell — likely Java deserialization RCE"),
    ("php-fpm",     "sh",         "T1190", 95.0, "PHP-FPM spawned shell — likely webshell"),
    ("php",         "bash",       "T1190", 92.0, "PHP spawned bash — likely webshell"),
    // Interpreters shelling out — extremely common in legitimate automation,
    // build scripts, and deploy hooks. Alert only; never auto-kill.
    ("java",        "bash",       "T1059.004", 60.0, "Java process spawned bash — possible deserialization/SSRF exploit, but also common in build/deploy tooling"),
    ("node",        "sh",         "T1190",     68.0, "Node.js spawned shell — possible RCE via npm/express, but also common in build tooling"),
    ("ruby",        "bash",       "T1190",     65.0, "Ruby spawned bash — possible RCE, but also common in rake/deploy tasks"),
    ("python",      "bash",       "T1059.004", 55.0, "Python spawned bash — possible sandbox escape, but shelling out is routine for Python automation"),
    // Database processes spawning shells — UDF/injection exploits.
    ("mysqld",      "sh",         "T1190", 95.0, "MySQL spawned shell — UDF exploit or injection"),
    ("postgres",    "sh",         "T1190", 95.0, "PostgreSQL spawned shell — COPY TO/FROM exploit"),
    ("mongod",      "sh",         "T1190", 93.0, "MongoDB spawned shell — code injection exploit"),
    // Email servers spawning shells — mail-processing RCE.
    ("postfix",     "sh",         "T1190", 90.0, "Postfix spawned shell — mail header injection exploit"),
    ("exim",        "sh",         "T1190", 90.0, "Exim spawned shell — mail processing RCE exploit"),
    ("sendmail",    "bash",       "T1190", 85.0, "Sendmail spawned bash — possible RCE"),
    // Document processors / viewers — should never exec a shell.
    ("evince",      "bash",       "T1204.002", 90.0, "PDF viewer spawned shell — possible malicious PDF exploit"),
    ("libreoffice", "bash",       "T1204.002", 88.0, "LibreOffice spawned bash — possible macro/exploit"),
    ("acroread",    "sh",         "T1204.002", 90.0, "Acrobat spawned shell — possible PDF exploit"),
    // Container escapes — nsenter has some legitimate tooling uses, so alert.
    ("runc",        "nsenter",    "T1611", 80.0, "runc spawned nsenter — possible container escape attempt"),
    ("containerd",  "nsenter",    "T1611", 78.0, "containerd spawned nsenter — possible container escape"),
    // Browser-based — browsers can legitimately invoke handlers; alert.
    ("chromium",    "bash",       "T1203", 75.0, "Browser spawned shell — possible browser exploit"),
    ("firefox",     "bash",       "T1203", 75.0, "Firefox spawned bash — possible browser exploit"),
    // SSH / authentication — an interactive login shell is NORMAL. This is a very
    // weak signal on its own, so it only ever alerts and never auto-kills a login.
    ("sshd",        "bash -i",    "T1078", 45.0, "sshd spawned interactive shell — usually a normal login, occasionally auth-bypass"),
];

/// Suspicious memory map patterns (proc/PID/maps).
/// Format: (perms_contains, mapping_contains, technique, confidence, description)
/// JIT engines and interpreters legitimately allocate rwx pages, and this is a
/// live-memory heuristic, so all confidences stay below the auto-kill gate — a
/// shellcode-shaped mapping alerts for investigation, it does not kill blind.
const SUSPICIOUS_MAPS: &[(&str, &str, &str, f32, &str)] = &[
    ("rwxp",  "",                "T1055",    78.0, "Executable anonymous mapping in process memory — shellcode indicator"),
    ("rwx",   "[heap]",          "T1055",    80.0, "Executable heap region — heap spray / shellcode"),
    ("rwx",   "[stack]",         "T1055",    85.0, "Executable stack — stack-based shellcode"),
    ("rwx",   "/dev/shm",        "T1055",    76.0, "Executable shared memory mapping — fileless malware"),
    ("rwxp",  "/tmp/",           "T1055.002",80.0, "Executable anonymous mapping in /tmp — shellcode staging"),
    ("r-xp",  "(deleted)",       "T1027.007",70.0, "Deleted-on-disk executable mapping — fileless payload"),
];

/// Processes that should NEVER read sensitive files.
/// Format: (process_contains, file_contains, technique, confidence, description)
const SENSITIVE_FILE_ACCESS: &[(&str, &str, &str, f32, &str)] = &[
    ("nginx",    "/etc/shadow",      "T1003.008", 92.0, "nginx reading /etc/shadow — post-exploitation credential access"),
    ("apache",   "/etc/shadow",      "T1003.008", 92.0, "Apache reading /etc/shadow — post-exploitation"),
    ("www-data", "/etc/shadow",      "T1003.008", 92.0, "www-data reading shadow — credential theft post-exploit"),
    ("nginx",    "/proc/self/mem",   "T1055",     90.0, "nginx accessing /proc/self/mem — memory injection post-exploit"),
    ("mysqld",   "/etc/passwd",      "T1003.008", 85.0, "mysqld reading /etc/passwd — UDF post-exploitation"),
    // sshd reads /etc/shadow during normal PAM password authentication, so this
    // is a weak signal and must not auto-kill a legitimate login daemon.
    ("sshd",     "/etc/shadow",      "T1003.008", 45.0, "sshd reading shadow — usually normal PAM auth, occasionally bypass exploit"),
];

/// Map a per-pattern confidence onto a severity and a response action. Destructive
/// containment (KillProcess) is reserved for high-confidence behavioral
/// signatures (>= 90) so a false positive never kills a legitimate process; weaker
/// heuristics only Alert. This mirrors the response engine's own confidence gate
/// (`auto_kill_threshold` defaults to 95): a 55-confidence `python → bash` can
/// never escalate to a kill, where the old uniform 90 could once an operator
/// lowered the threshold.
fn tier(confidence: f32, pid: u32) -> (Severity, ResponseAction) {
    if confidence >= 90.0 {
        (Severity::Critical, ResponseAction::KillProcess(pid))
    } else if confidence >= 75.0 {
        (Severity::High, ResponseAction::Alert)
    } else {
        (Severity::Medium, ResponseAction::Alert)
    }
}

/// Does the spawned child match an ancestry rule's `child_pat`?
///
/// `child_pat` is either a command fragment (contains a space, e.g. `"bash -i"`)
/// or a process-name stem (e.g. `"sh"`, `"python"`). The old test was a plain
/// substring over both the process name and the command line, which
/// over-matched badly: `"sh"` matched `ssh`/`sshd`/`bash`/`dash`/`flush`, so an
/// nginx worker launching `ssh` looked like a webshell. This matches a
/// process-name stem only as a **prefix of the executable basename** — of the
/// process name and of the command's argv[0] — so `"sh"` matches `sh` and
/// `/bin/sh -c …` but not `ssh`/`bash`, while version-suffixed interpreters
/// (`python3`, `nodejs`) still match their stem. Command fragments keep the
/// substring test so `"bash -i"` still works.
fn child_matches(proc_lower: &str, cmd_lower: &str, child_pat: &str) -> bool {
    if child_pat.contains(' ') {
        return cmd_lower.contains(child_pat);
    }
    let basename_has_stem = |s: &str| {
        s.rsplit(['/', '\\']).next().unwrap_or(s).starts_with(child_pat)
    };
    basename_has_stem(proc_lower)
        || cmd_lower.split_whitespace().next().map(basename_has_stem).unwrap_or(false)
}

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

            for (parent_pat, child_pat, technique, confidence, desc) in ANOMALOUS_ANCESTRY {
                if parent_lower.contains(parent_pat) &&
                   child_matches(&proc_lower, &cmd_lower, child_pat)
                {
                    warn!("🎯 ZERO-DAY: {} → {} [{technique}] ({:.0}%)", parent_name, event.process_name, confidence);
                    return Some(self.make_zeroday_threat(
                        technique, *confidence,
                        format!("Anomalous process ancestry: {} → {}", parent_name, event.process_name),
                        format!("{}\nCommand: {}\nThis parent→child relationship is a possible exploitation indicator regardless of the specific vulnerability.", desc, event.command_line.as_deref().unwrap_or("")),
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

            for (proc_pat, file_pat, technique, confidence, desc) in SENSITIVE_FILE_ACCESS {
                if proc.contains(proc_pat) && fpath.contains(file_pat) {
                    warn!("🎯 ZERO-DAY: {} accessed {} [{technique}] ({:.0}%)", event.process_name, fpath, confidence);
                    return Some(self.make_zeroday_threat(
                        technique, *confidence,
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
            if let Some((desc, technique, confidence)) = suspicious {
                warn!("🎯 ZERO-DAY: shellcode memory region in pid={} [{}] ({:.0}%)", event.pid, technique, confidence);
                return Some(self.make_zeroday_threat(
                    technique, confidence,
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
            if let Some((desc, technique, confidence)) = scan_process_maps(pid) {
                warn!("🎯 ZERO-DAY scan: shellcode in pid={} ({}) [{}] ({:.0}%)", pid, proc_name, technique, confidence);
                threats.push(self.make_zeroday_threat(
                    technique, confidence,
                    format!("Shellcode memory indicator — pid={} ({})", pid, proc_name),
                    desc, pid, None,
                ));
            }

            // Check for deleted-on-disk executables running. This is a real
            // fileless-malware technique, but it is ALSO what a running process
            // looks like after its package is updated under it (apt/dnf/yum
            // upgrade), which is routine — so it alerts for review rather than
            // killing a process whose only sin may be a mid-flight upgrade.
            if let Ok(exe_link) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
                let exe = exe_link.to_string_lossy();
                if exe.ends_with(" (deleted)") {
                    warn!("🎯 ZERO-DAY scan: deleted-on-disk executable running: pid={} ({})", pid, proc_name);
                    threats.push(self.make_zeroday_threat(
                        "T1027.007", 60.0,
                        format!("Deleted-on-disk executable running: pid={} ({})", pid, proc_name),
                        format!("Process {} (pid={}) is running from a deleted executable. This can be fileless malware (payload executed then unlinked to evade disk scans) — but also occurs normally when a package is upgraded while the process runs. Correlate before acting.", proc_name, pid),
                        pid, None,
                    ));
                }
            }
        }

        threats
    }

    fn make_zeroday_threat(
        &self, technique: &str, confidence: f32,
        name: String, desc: String, pid: u32,
        file_path: Option<&str>,
    ) -> ThreatEvent {
        let (severity, suggested_action) = tier(confidence, pid);

        let mut iocs = vec![];
        if let Some(fp) = file_path {
            iocs.push(IOC { ioc_type: IOCType::FilePath, value: fp.to_string(), source: "zeroday".into(), confidence });
        }

        ThreatEvent {
            id: Uuid::new_v4().to_string(),
            agent_id: self.agent_id.clone(), hostname: self.hostname.clone(),
            timestamp: Utc::now(), severity, confidence,
            threat_name: name, description: desc,
            mitre_tactics:    vec!["initial_access".to_string(), "execution".to_string()],
            mitre_techniques: vec![technique.to_string()],
            matched_rules:    vec!["zeroday_behavioral".to_string(), "process_ancestry".to_string()],
            raw_event_ids: vec![], chain: None, iocs,
            suggested_action,
            llm_analysis: None, auto_generated_rule: None,
        }
    }
}

fn scan_process_maps(pid: u32) -> Option<(String, &'static str, f32)> {
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid)).ok()?;

    for line in maps.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 { continue; }
        let perms   = fields[1];
        let mapping = fields.get(5).unwrap_or(&"");

        for (perm_pat, map_pat, technique, confidence, desc) in SUSPICIOUS_MAPS {
            if perms.contains(perm_pat) && (map_pat.is_empty() || mapping.contains(map_pat)) {
                // Additional filter: skip known JIT engines that legitimately use rwx
                if mapping.contains("libjvm") || mapping.contains("libv8") ||
                   mapping.contains("libjs") || mapping.contains("mono") {
                    continue;
                }
                return Some((desc.to_string(), technique, *confidence));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_event(pid: u32, ppid: u32, name: &str, cmd: &str) -> RawEvent {
        RawEvent {
            id: Uuid::new_v4().to_string(),
            agent_id: "a".into(), hostname: "h".into(),
            timestamp: Utc::now(),
            event_type: EventType::ProcessExec,
            pid, ppid, uid: 0, gid: 0,
            process_name: name.into(),
            process_path: None,
            command_line: Some(cmd.into()),
            parent_process: None,
            file_path: None, file_hash: None,
            network_dest_ip: None, network_dest_port: None, network_proto: None,
            syscall: None, return_code: None,
            container_id: None, namespace: None,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn tier_reserves_kill_for_high_confidence() {
        // High-confidence server compromise → Critical + a kill the response
        // engine can act on.
        assert!(matches!(tier(95.0, 42), (Severity::Critical, ResponseAction::KillProcess(42))));
        assert!(matches!(tier(90.0, 42), (Severity::Critical, ResponseAction::KillProcess(42))));
        // Mid-tier → High, alert only (no destructive auto-response).
        assert!(matches!(tier(80.0, 42), (Severity::High, ResponseAction::Alert)));
        // Weak heuristic → Medium, alert only.
        assert!(matches!(tier(55.0, 42), (Severity::Medium, ResponseAction::Alert)));
    }

    #[tokio::test]
    async fn web_server_spawning_shell_is_high_confidence_kill() {
        let d = ZeroDayDetector::new("a", "h");
        // Seed the parent (nginx) so the child's ppid resolves to it.
        let _ = d.analyze(&exec_event(100, 1, "nginx", "nginx: worker")).await;
        let t = d.analyze(&exec_event(200, 100, "bash", "bash -c id")).await
            .expect("nginx → bash must be detected");
        assert!(t.confidence >= 90.0, "web-server→shell should be high confidence, got {}", t.confidence);
        assert!(matches!(t.severity, Severity::Critical));
        assert!(matches!(t.suggested_action, ResponseAction::KillProcess(200)));
    }

    #[tokio::test]
    async fn interpreter_shelling_out_alerts_but_never_auto_kills() {
        let d = ZeroDayDetector::new("a", "h");
        // python is a parent of bash — routine automation, not a kill-worthy event.
        let _ = d.analyze(&exec_event(300, 1, "python", "python3 deploy.py")).await;
        let t = d.analyze(&exec_event(400, 300, "bash", "bash build.sh")).await
            .expect("python → bash still surfaces as a low-confidence alert");
        assert!(t.confidence < 75.0, "interpreter→shell should be low confidence, got {}", t.confidence);
        assert!(!matches!(t.suggested_action, ResponseAction::KillProcess(_)),
            "a weak signal must never suggest an auto-kill");
        // And it stays below the default auto_kill_threshold (95) and even a
        // tightened operator threshold of 90, so it can never escalate to a kill.
        assert!(t.confidence < 90.0);
    }

    #[tokio::test]
    async fn normal_ssh_login_shell_is_not_kill_worthy() {
        let d = ZeroDayDetector::new("a", "h");
        let _ = d.analyze(&exec_event(500, 1, "sshd", "sshd: user [priv]")).await;
        let t = d.analyze(&exec_event(600, 500, "bash", "bash -i")).await
            .expect("sshd → interactive shell matches the pattern");
        // It matches, but as the weakest tier — a normal interactive login must
        // not be auto-killed.
        assert!(t.confidence < 75.0, "sshd→bash -i is normally a login, got {}", t.confidence);
        assert!(!matches!(t.suggested_action, ResponseAction::KillProcess(_)));
    }

    #[tokio::test]
    async fn substring_lookalikes_do_not_false_match() {
        // nginx launching `ssh` must NOT trip the nginx→"sh" rule: "ssh" is not
        // a shell. The old substring match (`"ssh".contains("sh")`) fired here.
        let d = ZeroDayDetector::new("a", "h");
        let _ = d.analyze(&exec_event(100, 1, "nginx", "nginx: worker")).await;
        assert!(
            d.analyze(&exec_event(200, 100, "ssh", "ssh backup@host")).await.is_none(),
            "nginx → ssh must not match the shell rule"
        );
        // But nginx launching a real shell via an absolute path still matches.
        let d2 = ZeroDayDetector::new("a", "h");
        let _ = d2.analyze(&exec_event(300, 1, "nginx", "nginx: worker")).await;
        let hit = d2.analyze(&exec_event(400, 300, "sh", "/bin/sh -c id")).await
            .expect("nginx → /bin/sh must still be caught");
        assert!(hit.confidence >= 90.0);
    }

    #[test]
    fn child_matches_stem_prefix_not_substring() {
        // process-name stems match as basename prefixes, not substrings
        assert!(child_matches("sh", "/bin/sh -c id", "sh"));
        assert!(child_matches("python3", "python3 x.py", "python"));  // version suffix ok
        assert!(child_matches("bash", "/bin/bash", "bash"));
        assert!(!child_matches("ssh", "ssh host", "sh"));              // the old false match
        assert!(!child_matches("bash", "bash x", "sh"));
        // command fragments (with a space) keep the substring test
        assert!(child_matches("bash", "bash -i", "bash -i"));
        assert!(!child_matches("bash", "bash -c id", "bash -i"));
    }
}
