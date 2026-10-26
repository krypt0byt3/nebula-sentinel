#![allow(dead_code)]
// src/baseline/mod.rs — Behavioral baselining & unsupervised anomaly detection.
//
// GOAL: learn what is NORMAL for this specific host over a configurable window
// (default 21 days), then flag statistically significant deviations — WITHOUT a
// neural network, AVX, or a GPU. Everything here is pure-Rust, CPU-cheap, and
// EXPLAINABLE (every anomaly carries the reason + observed-vs-expected numbers).
// It runs ALONGSIDE the existing signatures / intel / gossip / NetGuard — the
// fusion of behavioral + known-bad is what makes a detection high-confidence.
//
// DETECTION DIMENSIONS (all from data the agent already collects):
//   1. Novelty   — entity never seen before (new binary, new parent→child,
//                  new dest IP, new user).
//   2. Rarity    — entity seen, but this context is rare.
//   3. Temporal  — activity in a time-of-day bucket historically quiet for it.
//   4. Numeric   — continuous signals outside the learned distribution (Welford
//                  mean/variance z-score + EWMA trend).
//   5. Multivariate — Half-Space Trees: an online unsupervised detector that
//                  catches odd COMBINATIONS of features. Pure Rust, fixed memory.
//
// MATURITY: during the learn window the engine observes and records but scores
// conservatively, reporting a maturity % so operators know when to trust it.
// PERSISTENCE: state lives in local SQLite so the learn window accrues across
// restarts.

use crate::types::{RawEvent, ThreatEvent, Severity, ResponseAction};
use anyhow::Result;
use chrono::{DateTime, Utc, Timelike, Datelike};
use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use uuid::Uuid;

pub mod features;

/// Read a usize from an env var, falling back to `default` if unset/unparseable.
fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
/// Read an f64 from an env var, falling back to `default` if unset/unparseable.
fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Platform-correct default path for the baseline DB. On Linux this is
/// /var/lib/nebula/baseline.db; on Windows C:\ProgramData\NebulaSentinel\...,
/// via the central platform module — so the agent never writes to a bogus
/// \var\lib\nebula path on the current drive on Windows.
fn default_db_path() -> String {
    crate::platform::data_dir().join("baseline.db").to_string_lossy().to_string()
}

#[derive(Debug, Clone, Default)]
pub struct RunningStats {
    pub n:    u64,
    pub mean: f64,
    pub m2:   f64,
    pub ewma: f64,
}

impl RunningStats {
    pub fn update(&mut self, x: f64) {
        self.n += 1;
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        self.m2 += delta * (x - self.mean);
        self.ewma = if self.n == 1 { x } else { 0.05 * x + 0.95 * self.ewma };
    }
    pub fn variance(&self) -> f64 { if self.n < 2 { 0.0 } else { self.m2 / (self.n - 1) as f64 } }
    pub fn stddev(&self) -> f64 { self.variance().sqrt() }
    pub fn zscore(&self, x: f64) -> f64 {
        let sd = self.stddev();
        if self.n < 30 || sd < 1e-9 { 0.0 } else { (x - self.mean) / sd }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EntityProfile {
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen:  Option<DateTime<Utc>>,
    pub count:      u64,
    pub hour_hist:  [u64; 24],
    pub dow_hist:   [u64; 7],
    pub numeric:    RunningStats,
}

impl EntityProfile {
    fn observe(&mut self, ts: DateTime<Utc>, numeric: Option<f64>) {
        if self.first_seen.is_none() { self.first_seen = Some(ts); }
        self.last_seen = Some(ts);
        self.count += 1;
        self.hour_hist[ts.hour() as usize] += 1;
        self.dow_hist[ts.weekday().num_days_from_monday() as usize] += 1;
        if let Some(v) = numeric { self.numeric.update(v); }
    }
    fn hour_frequency(&self, hour: usize) -> f64 {
        if self.count == 0 { return 0.0; }
        self.hour_hist[hour] as f64 / self.count as f64
    }
}

struct HsTree {
    depth:     usize,
    split_dim: Vec<usize>,
    split_val: Vec<f64>,
    mass_ref:  Vec<u64>,
    mass_cur:  Vec<u64>,
    nodes:     usize,
}

impl HsTree {
    fn new(dims: usize, depth: usize, rng: &mut u64) -> Self {
        let nodes = (1usize << (depth + 1)) - 1;
        let mut split_dim = vec![0usize; nodes];
        let mut split_val = vec![0.5f64; nodes];
        for i in 0..nodes {
            split_dim[i] = (xorshift(rng) as usize) % dims.max(1);
            split_val[i] = 0.25 + (xorshift(rng) as f64 / u64::MAX as f64) * 0.5;
        }
        Self { depth, split_dim, split_val, mass_ref: vec![0; nodes], mass_cur: vec![0; nodes], nodes }
    }
    fn leaf_path(&self, x: &[f64]) -> Vec<usize> {
        let mut idx = 0usize;
        let mut path = vec![0usize];
        for _ in 0..self.depth {
            let d = self.split_dim[idx];
            let go_right = x.get(d).copied().unwrap_or(0.0) >= self.split_val[idx];
            idx = 2 * idx + 1 + if go_right { 1 } else { 0 };
            if idx >= self.nodes { break; }
            path.push(idx);
        }
        path
    }
    fn learn(&mut self, x: &[f64]) {
        for n in self.leaf_path(x) { self.mass_cur[n] += 1; }
    }
    fn score(&self, x: &[f64]) -> f64 {
        let mut s = 0.0;
        for (depth, n) in self.leaf_path(x).iter().enumerate() {
            let m = self.mass_ref[*n] as f64;
            s += (1.0 / (1.0 + m)) * (depth as f64 + 1.0);
        }
        s
    }
    fn roll_window(&mut self) {
        self.mass_ref = self.mass_cur.clone();
        self.mass_cur = vec![0; self.nodes];
    }
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *state = x; x
}

pub struct HalfSpaceForest {
    trees:       Vec<HsTree>,
    seen:        u64,
    window_size: u64,
    score_stats: RunningStats,
}

impl HalfSpaceForest {
    pub fn new(dims: usize, n_trees: usize, depth: usize) -> Self {
        let mut rng = 0x9E3779B97F4A7C15u64;
        let trees = (0..n_trees).map(|_| HsTree::new(dims, depth, &mut rng)).collect();
        Self { trees, seen: 0, window_size: 256, score_stats: RunningStats::default() }
    }
    pub fn observe(&mut self, x: &[f64]) -> f64 {
        let raw: f64 = self.trees.iter().map(|t| t.score(x)).sum::<f64>() / self.trees.len().max(1) as f64;
        for t in self.trees.iter_mut() { t.learn(x); }
        self.score_stats.update(raw);
        self.seen += 1;
        if self.seen % self.window_size == 0 {
            for t in self.trees.iter_mut() { t.roll_window(); }
        }
        self.score_stats.zscore(raw)
    }
}

pub struct BaselineEngine {
    agent_id:    String,
    hostname:    String,
    enabled:     bool,
    learn_secs:  i64,
    started_at:  DateTime<Utc>,
    profiles:    Arc<Mutex<HashMap<String, EntityProfile>>>,
    forest:      Arc<Mutex<HalfSpaceForest>>,
    conn:        Arc<Mutex<Connection>>,
    z_threshold: f64,
    rarity_floor: f64,
}

impl BaselineEngine {
    pub fn open(agent_id: &str, hostname: &str, enabled: bool, learn_days: u32, db_path: Option<&str>) -> Result<Self> {
        let default_path = default_db_path();
        let p = db_path.unwrap_or(&default_path);
        if let Some(parent) = std::path::Path::new(p).parent() { let _ = std::fs::create_dir_all(parent); }
        let conn = Connection::open(p)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS baseline_profiles (
                key         TEXT PRIMARY KEY,
                first_seen  TEXT,
                last_seen   TEXT,
                count       INTEGER NOT NULL DEFAULT 0,
                hour_hist   TEXT,
                dow_hist    TEXT,
                stat_n      INTEGER DEFAULT 0,
                stat_mean   REAL DEFAULT 0,
                stat_m2     REAL DEFAULT 0,
                stat_ewma   REAL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS baseline_meta (
                id          INTEGER PRIMARY KEY CHECK (id=1),
                started_at  TEXT
            );"
        )?;
        let started_at: DateTime<Utc> = match conn.query_row(
            "SELECT started_at FROM baseline_meta WHERE id=1", [], |r| r.get::<_,String>(0)) {
            Ok(s) => DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)).unwrap_or_else(|_| Utc::now()),
            Err(_) => {
                let now = Utc::now();
                let _ = conn.execute("INSERT OR REPLACE INTO baseline_meta (id, started_at) VALUES (1, ?1)",
                    rusqlite::params![now.to_rfc3339()]);
                now
            }
        };
        info!("🧠 Baseline engine opened: {} (learn window {}d)", p, learn_days);

        Ok(Self {
            agent_id: agent_id.to_string(),
            hostname: hostname.to_string(),
            enabled,
            learn_secs: learn_days as i64 * 86400,
            started_at,
            profiles: Arc::new(Mutex::new(HashMap::new())),
            // Forest sensitivity and geometry are tunable via env so operators can
            // calibrate signal-to-noise per environment without a rebuild. Defaults
            // are conservative (chosen to favor precision over recall).
            //   NEBULA_ANOMALY_TREES   (default 25)   — more trees = smoother score
            //   NEBULA_ANOMALY_DEPTH   (default 8)    — tree depth / resolution
            //   NEBULA_ANOMALY_ZTHRESH (default 3.5)  — std-devs to flag an outlier
            //   NEBULA_ANOMALY_RARITY  (default 0.01) — rarity floor for temporal
            forest: Arc::new(Mutex::new(HalfSpaceForest::new(
                features::FEATURE_DIMS,
                env_usize("NEBULA_ANOMALY_TREES", 25),
                env_usize("NEBULA_ANOMALY_DEPTH", 8),
            ))),
            conn: Arc::new(Mutex::new(conn)),
            z_threshold: env_f64("NEBULA_ANOMALY_ZTHRESH", 3.5),
            rarity_floor: env_f64("NEBULA_ANOMALY_RARITY", 0.01),
        })
    }

    pub fn maturity(&self) -> f64 {
        let elapsed = (Utc::now() - self.started_at).num_seconds().max(0) as f64;
        (elapsed / self.learn_secs as f64).min(1.0)
    }
    fn is_learning(&self) -> bool { self.maturity() < 1.0 }

    pub async fn analyze(&self, event: &RawEvent) -> Option<ThreatEvent> {
        if !self.enabled { return None; }
        let ts = event.timestamp;
        let maturity = self.maturity();
        let mut reasons: Vec<String> = Vec::new();
        let mut max_score = 0.0f64;

        let mut profiles = self.profiles.lock().await;

        if !event.process_name.is_empty() {
            let key = format!("proc:{}", event.process_name);
            let (novel, rare, temporal, sc) = Self::eval_entity(&mut profiles, &key, ts, None, self.rarity_floor);
            if novel { reasons.push(format!("process '{}' never seen before on this host", event.process_name)); }
            if rare { reasons.push(format!("process '{}' is rare here", event.process_name)); }
            if temporal { reasons.push(format!("process '{}' active at an unusual hour ({}:00)", event.process_name, ts.hour())); }
            max_score = max_score.max(sc);
        }

        if let Some(parent) = &event.parent_process {
            if !parent.is_empty() && !event.process_name.is_empty() {
                let key = format!("lineage:{}>{}", parent, event.process_name);
                let (novel, rare, _t, sc) = Self::eval_entity(&mut profiles, &key, ts, None, self.rarity_floor);
                if novel { reasons.push(format!("new process lineage: {} -> {}", parent, event.process_name)); }
                if rare { reasons.push(format!("rare process lineage: {} -> {}", parent, event.process_name)); }
                max_score = max_score.max(sc * 1.2);
            }
        }

        {
            let key = format!("uid:{}", event.uid);
            let (novel, _r, temporal, sc) = Self::eval_entity(&mut profiles, &key, ts, None, self.rarity_floor);
            if novel { reasons.push(format!("user uid={} active for the first time", event.uid)); }
            if temporal { reasons.push(format!("user uid={} active at an unusual hour ({}:00)", event.uid, ts.hour())); }
            max_score = max_score.max(sc);
        }

        if let Some(ip) = &event.network_dest_ip {
            let key = format!("dest:{}:{}", event.process_name, ip);
            let (novel, _r, _t, sc) = Self::eval_entity(&mut profiles, &key, ts, event.network_dest_port.map(|p| p as f64), self.rarity_floor);
            if novel { reasons.push(format!("process '{}' contacted new destination {}", event.process_name, ip)); }
            max_score = max_score.max(sc);
        }

        drop(profiles);

        let feats = features::extract(event);
        let forest_z = { let mut f = self.forest.lock().await; f.observe(&feats) };
        if forest_z.abs() > self.z_threshold {
            reasons.push(format!("multivariate behavior outlier (forest z={:.1})", forest_z));
            max_score = max_score.max(forest_z.abs() / self.z_threshold);
        }

        if reasons.is_empty() { return None; }

        let learning = maturity < 1.0;
        if learning && max_score < 2.0 { return None; }

        let base_conf = (max_score / 4.0).min(1.0) * 100.0;
        let confidence = (base_conf * (0.4 + 0.6 * maturity)).min(95.0) as f32;
        let severity = if confidence >= 80.0 { Severity::High }
            else if confidence >= 55.0 { Severity::Medium }
            else if confidence >= 30.0 { Severity::Low } else { Severity::Info };

        Some(ThreatEvent {
            id: Uuid::new_v4().to_string(),
            agent_id: self.agent_id.clone(),
            hostname: self.hostname.clone(),
            timestamp: ts,
            severity,
            confidence,
            threat_name: format!("Behavioral anomaly: {}", reasons[0]),
            description: format!(
                "Host behavioral baseline flagged a deviation (maturity {:.0}%).\nObservations:\n - {}",
                maturity * 100.0, reasons.join("\n - ")),
            mitre_tactics: vec!["discovery".to_string()],
            mitre_techniques: vec![],
            matched_rules: vec!["baseline".to_string()],
            raw_event_ids: vec![event.id.clone()],
            chain: None,
            iocs: vec![],
            suggested_action: ResponseAction::Monitor,
            llm_analysis: None,
            auto_generated_rule: None,
        })
    }

    fn eval_entity(
        profiles: &mut HashMap<String, EntityProfile>,
        key: &str, ts: DateTime<Utc>, numeric: Option<f64>, rarity_floor: f64,
    ) -> (bool, bool, bool, f64) {
        let existed = profiles.contains_key(key);
        let prof = profiles.entry(key.to_string()).or_default();
        let novel = !existed;
        let rare = !novel && prof.count < 5;
        let temporal = !novel && prof.count > 50 && prof.hour_frequency(ts.hour() as usize) < rarity_floor;
        let znum = numeric.map(|v| prof.numeric.zscore(v).abs()).unwrap_or(0.0);

        let mut score = 0.0;
        if novel { score += 1.5; }
        if rare { score += 1.0; }
        if temporal { score += 1.5; }
        score += (znum / 3.5).min(2.0);

        prof.observe(ts, numeric);
        (novel, rare, temporal, score)
    }

    pub async fn persist(&self) {
        let profiles = self.profiles.lock().await;
        let conn = self.conn.lock().await;
        for (key, p) in profiles.iter() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO baseline_profiles
                 (key, first_seen, last_seen, count, hour_hist, dow_hist, stat_n, stat_mean, stat_m2, stat_ewma)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                rusqlite::params![
                    key,
                    p.first_seen.map(|t| t.to_rfc3339()),
                    p.last_seen.map(|t| t.to_rfc3339()),
                    p.count as i64,
                    serde_json::to_string(&p.hour_hist.to_vec()).unwrap_or_default(),
                    serde_json::to_string(&p.dow_hist.to_vec()).unwrap_or_default(),
                    p.numeric.n as i64, p.numeric.mean, p.numeric.m2, p.numeric.ewma,
                ]);
        }
        info!("🧠 Baseline persisted: {} entity profiles", profiles.len());
    }

    pub async fn load(&self) {
        let conn = self.conn.lock().await;
        let mut profiles = self.profiles.lock().await;
        let mut stmt = match conn.prepare(
            "SELECT key, first_seen, last_seen, count, hour_hist, dow_hist, stat_n, stat_mean, stat_m2, stat_ewma FROM baseline_profiles") {
            Ok(s) => s, Err(_) => return,
        };
        let rows = stmt.query_map([], |r| {
            let hour: Vec<u64> = serde_json::from_str(&r.get::<_,String>(4).unwrap_or_default()).unwrap_or_default();
            let dow: Vec<u64> = serde_json::from_str(&r.get::<_,String>(5).unwrap_or_default()).unwrap_or_default();
            let mut hh = [0u64;24]; for (i,v) in hour.iter().take(24).enumerate() { hh[i]=*v; }
            let mut dh = [0u64;7];  for (i,v) in dow.iter().take(7).enumerate()  { dh[i]=*v; }
            Ok((r.get::<_,String>(0)?, EntityProfile {
                first_seen: r.get::<_,Option<String>>(1)?.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
                last_seen:  r.get::<_,Option<String>>(2)?.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
                count: r.get::<_,i64>(3)? as u64,
                hour_hist: hh, dow_hist: dh,
                numeric: RunningStats {
                    n: r.get::<_,i64>(6)? as u64, mean: r.get::<_,f64>(7)?,
                    m2: r.get::<_,f64>(8)?, ewma: r.get::<_,f64>(9)?,
                },
            }))
        });
        if let Ok(rows) = rows {
            let mut n = 0;
            for row in rows.flatten() { profiles.insert(row.0, row.1); n += 1; }
            info!("🧠 Baseline loaded: {} entity profiles", n);
        }
    }

    pub async fn summary(&self) -> serde_json::Value {
        let profiles = self.profiles.lock().await;
        serde_json::json!({
            "maturity": self.maturity(),
            "learning": self.is_learning(),
            "entities_tracked": profiles.len(),
            "started_at": self.started_at.to_rfc3339(),
            "learn_window_days": self.learn_secs / 86400,
        })
    }
}
