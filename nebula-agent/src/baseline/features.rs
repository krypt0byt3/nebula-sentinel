// src/baseline/features.rs — High-signal feature extraction for the streaming
// anomaly engine.
//
// WHY THIS EXISTS: the anomaly engine's Half-Space Forest is only as good as the
// signal it's fed. The original 8-dim vector included near-noise dimensions (raw
// pid, bare string lengths) that diluted the model. This module replaces them
// with features that actually carry threat signal — the things a human analyst
// looks at first:
//
//   • command-line ENTROPY (obfuscated/encoded payloads are high-entropy)
//   • command-line ARGUMENT structure (token count, encoding & download markers,
//     suspicious flag combinations) — first-class, per the operator's request
//   • executable PATH CATEGORY (running from /tmp, download dirs, AppData\Temp is
//     a strong, low-noise signal vs running from /usr/bin or Program Files)
//   • PRIVILEGE as a boolean (root/admin) rather than a diluted continuous uid
//   • process NAME-CHARACTER entropy (random-looking names = dropped malware)
//   • temporal signal (hour-of-day, kept — it's genuinely useful)
//
// All pure Rust, no dependencies, fixed cost per event. Designed to be unit
// tested in isolation (see tests at the bottom).

use crate::types::RawEvent;
use chrono::Timelike;  // brings `.hour()` into scope for the event timestamp

/// The width of the feature vector produced by `extract`. The Half-Space Forest
/// MUST be constructed with this many dimensions. Kept as a public constant so
/// the two can never silently drift apart.
pub const FEATURE_DIMS: usize = 14;

/// Shannon entropy (in bits per symbol, 0.0–8.0 for bytes) of a string. High
/// entropy indicates encoding, compression, or obfuscation — base64 blobs,
/// packed payloads, and random tokens all score high; ordinary English/paths
/// score low. This is one of the single most useful signals for spotting
/// obfuscated command lines.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    let mut n = 0u32;
    for b in s.bytes() { counts[b as usize] += 1; n += 1; }
    let n_f = n as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 { continue; }
        let p = c as f64 / n_f;
        h -= p * p.log2();
    }
    h
}

/// Categorize an executable path by how suspicious its LOCATION is. Malware
/// characteristically runs from world-writable or user-writable transient
/// locations; legitimate software runs from system directories. Returns a value
/// in [0,1] where higher = more suspicious.
pub fn path_suspicion(path: Option<&str>) -> f64 {
    let p = match path { Some(p) => p.to_lowercase(), None => return 0.5 }; // unknown = neutral-high
    // Strongly suspicious: transient / user-writable execution locations.
    const HOT: &[&str] = &[
        "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/",
        "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\downloads\\",
        "/downloads/", "\\programdata\\", "\\users\\public\\",
        "\\recycle", "/.cache/", "\\temp\\",
    ];
    // Normal: system-managed locations.
    const COLD: &[&str] = &[
        "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/local/bin/",
        "\\windows\\system32\\", "\\program files\\", "\\program files (x86)\\",
        "/opt/", "\\windows\\syswow64\\",
    ];
    if HOT.iter().any(|h| p.contains(h)) { return 1.0; }
    if COLD.iter().any(|c| p.contains(c)) { return 0.0; }
    0.4 // anything else — mildly notable but not damning
}

/// Count of "suspicious" tokens in a command line — encoding flags, download
/// primitives, execution-policy bypasses, and living-off-the-land markers.
/// Returns a normalized [0,1] score based on how many distinct markers appear.
pub fn command_suspicion(cmd: &str) -> f64 {
    let c = cmd.to_lowercase();
    // Each marker is a well-known offensive pattern. We count DISTINCT hits so a
    // command line stacking several (e.g. encoded + hidden + download) scores
    // higher — that stacking is itself the signal.
    const MARKERS: &[&str] = &[
        "-enc", "-encodedcommand", "frombase64string", "-nop", "-noprofile",
        "-w hidden", "-windowstyle hidden", "-exec bypass", "executionpolicy bypass",
        "iex", "invoke-expression", "downloadstring", "downloadfile", "webclient",
        "certutil", "bitsadmin", "mshta", "regsvr32", "rundll32",
        "curl ", "wget ", "/dev/tcp/", "nc -e", "ncat", "base64 -d", "base64 --decode",
        "chmod +x", "chmod 777", "; rm -rf", "&& rm -rf", "python -c", "perl -e",
        "eval(", "$(", "|sh", "| sh", "|bash", "| bash",
    ];
    let mut hits = 0u32;
    for m in MARKERS { if c.contains(m) { hits += 1; } }
    // 3+ distinct markers saturates to 1.0 (already very suspicious).
    (hits as f64 / 3.0).min(1.0)
}

/// Whether a command line carries an encoded/base64-ish long token — a common
/// payload-delivery shape independent of the specific flag used.
pub fn has_encoded_blob(cmd: &str) -> f64 {
    // Look for a long run of base64 characters (>= 40 chars) — encoded payloads
    // and packed blobs look like this; ordinary arguments do not.
    let mut run = 0usize;
    let mut max_run = 0usize;
    for ch in cmd.chars() {
        if ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' {
            run += 1;
            if run > max_run { max_run = run; }
        } else {
            run = 0;
        }
    }
    if max_run >= 40 { 1.0 } else { (max_run as f64 / 40.0).min(1.0) }
}

/// A stable 0..1 hash of the parent→child lineage pair. This gives the forest a
/// numeric handle on lineage so that a consistent parent/child relationship
/// occupies a stable region of feature space, while a novel pairing lands
/// elsewhere. (Novelty/rarity of the pairing is ALSO tracked separately by the
/// entity-profile path; this feature lets the multivariate model factor lineage
/// into combination anomalies.)
pub fn lineage_hash(parent: Option<&str>, child: &str) -> f64 {
    let p = parent.unwrap_or("");
    // FNV-1a — cheap, deterministic, good spread.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in p.bytes().chain(b"\x00".iter().copied()).chain(child.bytes()) {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    (h % 100_000) as f64 / 100_000.0
}

/// Fraction of digits in a process name — dropped malware frequently uses
/// random or hash-like names ("x7f3a2.exe", "8842.tmp"). Legit binaries rarely
/// do. Returns [0,1].
pub fn name_randomness(name: &str) -> f64 {
    if name.is_empty() { return 0.0; }
    let stem = name.split('.').next().unwrap_or(name);
    if stem.is_empty() { return 0.0; }
    let digits = stem.chars().filter(|c| c.is_ascii_digit()).count();
    // Combine digit ratio with per-character entropy (normalized to ~4 bits).
    let digit_ratio = digits as f64 / stem.len() as f64;
    let ent = shannon_entropy(stem) / 4.0;
    ((digit_ratio + ent.min(1.0)) / 2.0).clamp(0.0, 1.0)
}

/// Extract the full high-signal feature vector for an event. Length is always
/// `FEATURE_DIMS`. Every value is normalized to [0,1] so no single dimension
/// dominates the Half-Space partitioning by scale.
pub fn extract(e: &RawEvent) -> Vec<f64> {
    let norm = |v: f64, max: f64| (v / max).clamp(0.0, 1.0);
    let cmd = e.command_line.as_deref().unwrap_or("");
    let cmd_len = cmd.len();
    let arg_count = cmd.split_whitespace().count();

    let v = vec![
        // ── temporal ──
        norm(e.timestamp.hour() as f64, 23.0),
        // ── privilege (boolean, not diluted) ──
        if e.uid == 0 { 1.0 } else { 0.0 },
        // ── command-line signal (the operator's priority) ──
        (shannon_entropy(cmd) / 8.0).clamp(0.0, 1.0),   // obfuscation
        norm(arg_count as f64, 30.0),                    // argument count
        norm(cmd_len as f64, 4096.0),                    // length (kept, de-emphasized)
        command_suspicion(cmd),                          // offensive markers
        has_encoded_blob(cmd),                           // base64/packed payload shape
        // ── execution location ──
        path_suspicion(e.process_path.as_deref()),
        // ── process identity ──
        name_randomness(&e.process_name),
        norm(e.process_name.len() as f64, 64.0),
        // ── lineage ──
        lineage_hash(e.parent_process.as_deref(), &e.process_name),
        // ── network context ──
        if e.network_dest_ip.is_some() { 1.0 } else { 0.0 },
        norm(e.network_dest_port.unwrap_or(0) as f64, 65535.0),
        // ── file context ──
        if e.file_path.is_some() { 1.0 } else { 0.0 },
    ];
    debug_assert_eq!(v.len(), FEATURE_DIMS, "feature vector width must equal FEATURE_DIMS");
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_ranges() {
        assert!(shannon_entropy("") == 0.0);
        assert!(shannon_entropy("aaaaaaaa") < 0.01);          // single symbol → ~0
        let random = "aB3xR9pQ7zL2mK5vN8wC4tY6uI0oP1sD"; // mixed → high
        assert!(shannon_entropy(random) > 4.0);
        // English/paths sit in the middle, below encoded blobs.
        assert!(shannon_entropy("/usr/bin/bash --login") < shannon_entropy(random));
    }

    #[test]
    fn path_suspicion_classifies() {
        assert_eq!(path_suspicion(Some("/tmp/evil.sh")), 1.0);
        assert_eq!(path_suspicion(Some("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe")), 1.0);
        assert_eq!(path_suspicion(Some("/usr/bin/ls")), 0.0);
        assert_eq!(path_suspicion(Some("C:\\Program Files\\App\\a.exe")), 0.0);
        assert_eq!(path_suspicion(None), 0.5);
    }

    #[test]
    fn command_suspicion_stacks() {
        assert_eq!(command_suspicion("ls -la"), 0.0);
        // A single marker registers but doesn't saturate.
        let one = command_suspicion("powershell -nop");
        assert!(one > 0.0 && one < 1.0);
        // Stacked offensive markers saturate.
        let many = command_suspicion("powershell -nop -w hidden -enc AAAA iex downloadstring");
        assert_eq!(many, 1.0);
    }

    #[test]
    fn encoded_blob_detected() {
        assert_eq!(has_encoded_blob("echo hello world"), 0.0);
        assert_eq!(has_encoded_blob("powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA"), 1.0);
    }

    #[test]
    fn name_randomness_flags_hashlike() {
        assert!(name_randomness("bash") < 0.3);
        assert!(name_randomness("systemd") < 0.3);
        assert!(name_randomness("x7f3a29b.exe") > 0.4);
        assert!(name_randomness("8842847.tmp") > 0.4);
    }

    #[test]
    fn lineage_is_stable_and_spread() {
        // Deterministic.
        assert_eq!(lineage_hash(Some("bash"), "ls"), lineage_hash(Some("bash"), "ls"));
        // Different pairs land in different places (very high probability).
        assert_ne!(lineage_hash(Some("word.exe"), "powershell.exe"),
                   lineage_hash(Some("explorer.exe"), "cmd.exe"));
    }

    #[test]
    fn feature_vector_width_is_stable() {
        use crate::types::{RawEvent, EventType};
        use std::collections::HashMap;
        let e = RawEvent {
            id: "x".into(), agent_id: "a".into(), hostname: "h".into(),
            timestamp: chrono::Utc::now(), event_type: EventType::ProcessExec,
            pid: 100, ppid: 1, uid: 0, gid: 0,
            process_name: "bash".into(), process_path: Some("/usr/bin/bash".into()),
            command_line: Some("bash -c ls".into()), parent_process: Some("systemd".into()),
            file_path: None, file_hash: None, network_dest_ip: None,
            network_dest_port: None, network_proto: None, syscall: None,
            return_code: None, container_id: None, namespace: None, extra: HashMap::new(),
        };
        assert_eq!(extract(&e).len(), FEATURE_DIMS);
    }
}
