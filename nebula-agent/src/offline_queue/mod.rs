#![allow(dead_code)]
// src/offline_queue/mod.rs — Persistent offline event queue for roaming agents
//
// When a laptop agent can't reach Nexus (plane, hotel WiFi, VPN gap),
// all events are stored locally in SQLite. When connectivity resumes,
// the queue is drained in order. Events survive reboots.
//
// Geo-annotation: if the agent is on a public IP when an event fires,
// that location is baked into the queued event so Nexus receives full
// context even after a delay.

use anyhow::Result;
use rusqlite::{Connection, params};
use chrono::Utc;
use tracing::{info, warn, debug};
use std::sync::Arc;
use tokio::sync::Mutex;

// The default DB path is computed per-platform at open time via
// crate::platform::data_dir() (see `new`), so there is no hardcoded const.
const DEFAULT_MAX_MB:  u64 = 500;
const DRAIN_BATCH:     usize = 50;

#[derive(Debug, Clone)]
pub struct QueuedEvent {
    pub id:          String,
    pub event_type:  String,   // "threat" | "posture" | "rule_proposal"
    pub payload:     String,
    pub queued_at:   String,
    pub retry_count: u32,
    pub location:    Option<String>,
}

pub struct OfflineQueue {
    db:     Arc<Mutex<Connection>>,
    max_mb: u64,
}

impl OfflineQueue {
    pub fn new(db_path: Option<&str>, max_mb: Option<u64>) -> Result<Self> {
        let data_dir = crate::platform::data_dir();
        let default_path = data_dir.join("offline_queue.db").to_string_lossy().to_string();
        let path = db_path.unwrap_or(&default_path);
        let parent = std::path::Path::new(path).parent().unwrap_or(data_dir.as_path());
        std::fs::create_dir_all(parent)?;

        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(r#"
            CREATE TABLE IF NOT EXISTS queued_events (
                id          TEXT PRIMARY KEY,
                event_type  TEXT NOT NULL,
                payload     TEXT NOT NULL,
                queued_at   TEXT NOT NULL,
                retry_count INTEGER DEFAULT 0,
                location    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_queued_at ON queued_events(queued_at);
        "#)?;

        info!("📦 Offline queue initialized: {} (max {} MB)", path, max_mb.unwrap_or(DEFAULT_MAX_MB));
        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            max_mb: max_mb.unwrap_or(DEFAULT_MAX_MB),
        })
    }

    /// Push an event into the offline queue.
    pub async fn push(&self, event_type: &str, payload: &str, location: Option<&str>) -> Result<()> {
        let id  = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        let conn = self.db.lock().await;
        conn.execute(
            "INSERT INTO queued_events (id,event_type,payload,queued_at,location)
             VALUES (?1,?2,?3,?4,?5)",
            params![id, event_type, payload, now, location],
        )?;

        // Evict oldest events if over size cap
        let pages:     i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap_or(0);
        let page_size: i64 = conn.query_row("PRAGMA page_size",  [], |r| r.get(0)).unwrap_or(4096);
        let size_mb = (pages * page_size) as u64 / 1024 / 1024;

        if size_mb > self.max_mb {
            let evicted = conn.execute(
                "DELETE FROM queued_events WHERE id IN (
                    SELECT id FROM queued_events ORDER BY queued_at ASC LIMIT 100
                )", [],
            )?;
            warn!("📦 Queue cap ({} MB) — evicted {} oldest events", size_mb, evicted);
        }

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM queued_events", [], |r| r.get(0)
        ).unwrap_or(0);
        debug!("📦 Queued {} (total: {})", event_type, count);
        Ok(())
    }

    pub async fn len(&self) -> usize {
        let conn = self.db.lock().await;
        conn.query_row("SELECT COUNT(*) FROM queued_events", [], |r| r.get::<_,i64>(0))
            .unwrap_or(0) as usize
    }

    /// Drain queued events to Nexus.
    /// `sender` is called with (event_type, payload_json).
    /// Returns true if the queue is now empty, false if Nexus is still unreachable.
    pub async fn drain<F, Fut>(&self, sender: F) -> bool
    where
        F: Fn(String, String) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let total = self.len().await;
        if total == 0 { return true; }
        info!("📦 Draining {} queued events...", total);

        let mut sent   = 0usize;

        loop {
            // Fetch next batch
            let batch: Vec<QueuedEvent> = {
                let conn = self.db.lock().await;
                let mut stmt = match conn.prepare(
                    "SELECT id,event_type,payload,queued_at,retry_count,location
                     FROM queued_events ORDER BY queued_at ASC LIMIT ?1"
                ) { Ok(s) => s, Err(_) => break };

                stmt.query_map(params![DRAIN_BATCH as i64], |row| {
                    Ok(QueuedEvent {
                        id:          row.get(0)?,
                        event_type:  row.get(1)?,
                        payload:     row.get(2)?,
                        queued_at:   row.get(3)?,
                        retry_count: row.get(4)?,
                        location:    row.get(5)?,
                    })
                }).unwrap().filter_map(|r| r.ok()).collect()
            };

            if batch.is_empty() { break; }

            for ev in &batch {
                match sender(ev.event_type.clone(), ev.payload.clone()).await {
                    Ok(_) => {
                        let conn = self.db.lock().await;
                        let _ = conn.execute(
                            "DELETE FROM queued_events WHERE id=?1", params![ev.id]
                        );
                        sent += 1;
                    }
                    Err(_e) => {
                        // Nexus is unreachable (or rejecting). Do NOT drop the event —
                        // thorough coverage means we keep it and retry on the next flush.
                        // Stop draining immediately: continuing would just fail on every
                        // remaining event and burn retry counters pointlessly. Events stay
                        // in the DB in order; the size cap (eviction of oldest) is the only
                        // thing that ever removes an undelivered event.
                        let conn = self.db.lock().await;
                        let _ = conn.execute(
                            "UPDATE queued_events SET retry_count=retry_count+1 WHERE id=?1",
                            params![ev.id]
                        );
                        drop(conn);
                        if sent > 0 {
                            info!("📦 Flushed {} events; Nexus now unreachable, {} remain buffered", sent, total - sent);
                        } else {
                            debug!("📦 Nexus unreachable — {} events remain buffered for next flush", total);
                        }
                        return false;
                    }
                }
            }
        }

        if sent > 0 { info!("📦 Drained {} events to Nexus", sent); }
        true
    }
}
