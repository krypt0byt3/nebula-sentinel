//! Persistent scan state — lets the agent avoid redundant full scans across
//! restarts/reinstalls.
//!
//! The problem: every time the agent starts, the first periodic tick runs a
//! FULL inventory (package enumeration, process tree, file-catalog walk),
//! hardening assessment, and posture scan. On a reinstall where the host hasn't
//! changed, that heavy work is wasted and taxes the system.
//!
//! The fix: persist a small state record to the agent's SQLite DB —
//!   - last full-scan timestamp
//!   - an inventory fingerprint (hash of the installed-package set)
//! On startup we load it. If recent state exists AND the current package
//! fingerprint matches, the first tick does a lightweight DELTA scan (skip the
//! expensive file-catalog walk) instead of a full one. A full scan is forced
//! when state is missing, stale (older than a threshold), or the fingerprint
//! has changed (packages added/removed/upgraded).

use anyhow::Result;
use rusqlite::{Connection, params};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use chrono::{Utc, DateTime};
use tracing::{info, debug};

// The default DB path is computed per-platform at open time via
// crate::platform::data_dir() (see `open`), so there is no hardcoded const.

pub struct ScanState {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct StoredState {
    pub last_full_scan: Option<DateTime<Utc>>,
    pub inventory_fingerprint: Option<String>,
    pub last_scan_kind: Option<String>,
}

/// What kind of scan the startup logic decided to run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanDecision {
    /// First run, stale state, or host changed — do everything.
    Full,
    /// Recent state and unchanged fingerprint — skip the heavy file walk.
    Delta,
}

impl ScanState {
    pub fn open(path: Option<&str>) -> Result<Self> {
        let default_path = crate::platform::data_dir().join("scan_state.db").to_string_lossy().to_string();
        let p = path.unwrap_or(&default_path);
        if let Some(parent) = std::path::Path::new(p).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(p)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scan_state (
                id                     INTEGER PRIMARY KEY CHECK (id = 1),
                last_full_scan         TEXT,
                inventory_fingerprint  TEXT,
                last_scan_kind         TEXT,
                updated_at             TEXT
            );"
        )?;
        info!("🗃️  Scan-state store opened: {}", p);
        Ok(Self { conn })
    }

    pub fn load(&self) -> StoredState {
        self.conn.query_row(
            "SELECT last_full_scan, inventory_fingerprint, last_scan_kind FROM scan_state WHERE id=1",
            [],
            |r| Ok(StoredState {
                last_full_scan: r.get::<_,Option<String>>(0)?
                    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
                inventory_fingerprint: r.get::<_,Option<String>>(1)?,
                last_scan_kind: r.get::<_,Option<String>>(2)?,
            }),
        ).unwrap_or(StoredState { last_full_scan: None, inventory_fingerprint: None, last_scan_kind: None })
    }

    pub fn save_full_scan(&self, fingerprint: &str) {
        let now = Utc::now().to_rfc3339();
        let _ = self.conn.execute(
            "INSERT INTO scan_state (id,last_full_scan,inventory_fingerprint,last_scan_kind,updated_at)
             VALUES (1,?1,?2,'full',?1)
             ON CONFLICT(id) DO UPDATE SET last_full_scan=?1, inventory_fingerprint=?2, last_scan_kind='full', updated_at=?1",
            params![now, fingerprint],
        );
    }

    pub fn save_delta_scan(&self, fingerprint: &str) {
        let now = Utc::now().to_rfc3339();
        // A delta scan does NOT update last_full_scan — only the fingerprint and marker.
        let _ = self.conn.execute(
            "UPDATE scan_state SET inventory_fingerprint=?1, last_scan_kind='delta', updated_at=?2 WHERE id=1",
            params![fingerprint, now],
        );
    }

    /// Decide whether the startup tick should do a full or delta scan.
    ///   - no prior state            -> Full
    ///   - last full scan is stale   -> Full (forces periodic full refresh)
    ///   - fingerprint changed       -> Full (host packages changed)
    ///   - otherwise                 -> Delta
    pub fn decide(&self, current_fingerprint: &str, max_age_hours: i64) -> ScanDecision {
        let state = self.load();
        if let Some(ref kind) = state.last_scan_kind {
            debug!("scan-state: previous scan kind was '{}'", kind);
        }
        let last = match state.last_full_scan {
            Some(t) => t,
            None => { debug!("scan-state: no prior full scan — full"); return ScanDecision::Full; }
        };
        let age_hours = (Utc::now() - last).num_hours();
        if age_hours >= max_age_hours {
            info!("🔄 scan-state: last full scan {}h ago (≥{}h) — full scan", age_hours, max_age_hours);
            return ScanDecision::Full;
        }
        match state.inventory_fingerprint {
            Some(fp) if fp == current_fingerprint => {
                info!("⚡ scan-state: host unchanged since full scan {}h ago — delta scan (skipping file-catalog walk)", age_hours);
                ScanDecision::Delta
            }
            _ => {
                info!("🔄 scan-state: package fingerprint changed — full scan");
                ScanDecision::Full
            }
        }
    }
}

/// Compute a cheap, stable fingerprint of the installed-package set.
/// Sorted name@version pairs hashed — changes when anything is added,
/// removed, or upgraded, which is exactly when a full rescan is warranted.
pub fn fingerprint_packages(packages: &[crate::types::PackageEntry]) -> String {
    let mut items: Vec<String> = packages.iter()
        .map(|p| format!("{}@{}", p.name, p.version))
        .collect();
    items.sort();
    let mut hasher = DefaultHasher::new();
    items.join("\n").hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
