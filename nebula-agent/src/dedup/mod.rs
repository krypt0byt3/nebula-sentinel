//! Alert deduplication gate.
//!
//! The detection pipeline can fire the *same* logical alert many times in quick
//! succession — a beaconing process re-tripping the network monitor every loop, a
//! credential-dump heuristic matching every syscall, a Sigma rule hitting a tight
//! log burst. Before this gate, each firing produced a full downstream cascade
//! (response action, forensics capture, status-UI row, gossip broadcast, and a
//! Nexus `send_threat`), flooding the operator feed with near-identical rows.
//!
//! The gate collapses identical alerts within a sliding window into a single
//! emission, then re-emits after the window with an occurrence count so the
//! operator still learns the alert recurred (and how often) without the spam.
//!
//! Identity is `threat_name | sorted(mitre_techniques) | process_name`. Severity
//! and confidence are deliberately excluded so confidence drift doesn't fragment
//! one recurring alert into several.

use std::collections::HashMap;
use std::sync::Mutex;
use chrono::{DateTime, Duration, Utc};

use crate::types::ThreatEvent;

/// Above this many tracked keys we opportunistically prune stale entries so the
/// map can't grow without bound on a long-running, high-cardinality host.
const PRUNE_THRESHOLD: usize = 4096;

/// The gate's decision for one candidate alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupVerdict {
    /// Forward this alert. `recurred` is how many identical firings were
    /// suppressed since the previous emission (0 for a first-seen alert).
    Emit { recurred: u32 },
    /// Drop this alert — an identical one emitted within the window.
    Suppress,
}

struct Entry {
    /// When we last *emitted* (forwarded) this key.
    last_emit: DateTime<Utc>,
    /// When we last *saw* this key at all (emit or suppress) — drives pruning.
    last_seen: DateTime<Utc>,
    /// Identical firings suppressed since `last_emit`.
    suppressed: u32,
}

/// A time-windowed alert-deduplication gate. Cheap to clone-share via `Arc`.
pub struct DedupGate {
    enabled: bool,
    window: Duration,
    window_secs: u64,
    inner: Mutex<HashMap<String, Entry>>,
}

impl DedupGate {
    pub fn new(enabled: bool, window_secs: u64) -> Self {
        // A zero window would disable suppression while still paying map costs;
        // treat it as "off" for clarity.
        let enabled = enabled && window_secs > 0;
        Self {
            enabled,
            window: Duration::seconds(window_secs as i64),
            window_secs,
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool { self.enabled }
    pub fn window_secs(&self) -> u64 { self.window_secs }

    /// Build the dedup identity key for a threat + its originating process.
    pub fn key(threat: &ThreatEvent, process_name: &str) -> String {
        let mut techniques = threat.mitre_techniques.clone();
        techniques.sort();
        format!("{}|{}|{}", threat.threat_name, techniques.join(","), process_name)
    }

    /// Decide whether to emit or suppress `key` at time `now`.
    ///
    /// First sight of a key emits. A repeat within `window` of the last emission
    /// is suppressed (and counted). A repeat *after* the window emits again and
    /// reports how many were suppressed in between, then resets the counter.
    pub fn evaluate(&self, key: &str, now: DateTime<Utc>) -> DedupVerdict {
        if !self.enabled {
            return DedupVerdict::Emit { recurred: 0 };
        }
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Opportunistic prune: only when the map is large, and only entries we
        // haven't seen for well past the window (so an active key is never lost).
        if map.len() > PRUNE_THRESHOLD {
            let cutoff = self.window * 2;
            map.retain(|_, e| now.signed_duration_since(e.last_seen) < cutoff);
        }

        match map.get_mut(key) {
            Some(e) => {
                e.last_seen = now;
                if now.signed_duration_since(e.last_emit) < self.window {
                    e.suppressed = e.suppressed.saturating_add(1);
                    DedupVerdict::Suppress
                } else {
                    let recurred = e.suppressed;
                    e.last_emit = now;
                    e.suppressed = 0;
                    DedupVerdict::Emit { recurred }
                }
            }
            None => {
                map.insert(key.to_string(), Entry { last_emit: now, last_seen: now, suppressed: 0 });
                DedupVerdict::Emit { recurred: 0 }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
    }

    #[test]
    fn first_sight_emits() {
        let g = DedupGate::new(true, 60);
        assert_eq!(g.evaluate("k", t(0)), DedupVerdict::Emit { recurred: 0 });
    }

    #[test]
    fn repeats_within_window_suppressed_then_reemit_with_count() {
        let g = DedupGate::new(true, 60);
        assert_eq!(g.evaluate("k", t(0)),  DedupVerdict::Emit { recurred: 0 });
        assert_eq!(g.evaluate("k", t(2)),  DedupVerdict::Suppress);
        assert_eq!(g.evaluate("k", t(40)), DedupVerdict::Suppress);
        // Past the window: re-emit, reporting the 2 suppressed in between.
        assert_eq!(g.evaluate("k", t(61)), DedupVerdict::Emit { recurred: 2 });
        // Counter resets after the re-emission.
        assert_eq!(g.evaluate("k", t(62)), DedupVerdict::Suppress);
    }

    #[test]
    fn distinct_keys_are_independent() {
        let g = DedupGate::new(true, 60);
        assert_eq!(g.evaluate("a", t(0)), DedupVerdict::Emit { recurred: 0 });
        assert_eq!(g.evaluate("b", t(1)), DedupVerdict::Emit { recurred: 0 });
    }

    #[test]
    fn disabled_always_emits() {
        let g = DedupGate::new(false, 60);
        assert_eq!(g.evaluate("k", t(0)), DedupVerdict::Emit { recurred: 0 });
        assert_eq!(g.evaluate("k", t(1)), DedupVerdict::Emit { recurred: 0 });
    }

    #[test]
    fn zero_window_disables() {
        let g = DedupGate::new(true, 0);
        assert!(!g.enabled());
        assert_eq!(g.evaluate("k", t(0)), DedupVerdict::Emit { recurred: 0 });
        assert_eq!(g.evaluate("k", t(0)), DedupVerdict::Emit { recurred: 0 });
    }
}
