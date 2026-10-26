// src/status_ui/mod.rs — Sentinel local status web UI
//
// Minimal read-only HTTP server bound ONLY to 127.0.0.1:7440.
// Not reachable from the network. Open http://localhost:7440 on the
// sentinel host itself to see live agent status without Nexus access.
//
// Displays: mode, posture score, Nexus connection, active threats,
//           recent events, module health, firewall backend, LLM status.
// Auto-refreshes every 15 seconds.
// JSON API at /api/status for scripting.

use anyhow::Result;
use axum::{routing::get, Router, response::Html, extract::State};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

#[derive(Debug, Clone, Default)]
pub struct StatusSnapshot {
    pub hostname:           String,
    pub agent_id:           String,
    pub platform:           String,
    pub version:            String,
    pub mode:               String,
    pub posture_score:      f32,
    /// Whether a Nexus is configured at all. When false the agent is a deliberate
    /// **standalone** deployment (not an error); when true but `nexus_connected`
    /// is false, it is **offline** (configured Nexus currently unreachable).
    pub nexus_configured:   bool,
    pub nexus_connected:    bool,
    pub nexus_url:          String,
    pub last_nexus_contact: String,
    /// Event source the collector is reading from (ebpf / auditd / wineventlog …).
    pub collector_backend:  String,
    pub active_threats:     usize,
    pub recent_events:      Vec<StatusEvent>,
    pub modules:            Vec<ModuleStatus>,
    pub firewall_backend:   String,
    pub llm_status:         String,
    pub rules_loaded:       usize,
    pub iocs_loaded:        usize,
    pub started_at:         String,
    /// FIM: paths being monitored on this host (path, description). Static
    /// watch-list config; live change events flow through recent_events.
    pub fim_watched:        Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct StatusEvent {
    pub timestamp:   String,
    pub severity:    String,
    pub threat_name: String,
    pub technique:   String,
    pub confidence:  f32,
    /// "ATC" when the event carries local LLM reasoning, "Legacy" when it was
    /// detected without ATC enrichment (LLM unavailable / degraded mode).
    pub source:      String,
    pub description: String,
    /// ATC (local LLM) reasoning, when present. Empty on Legacy-path events.
    pub atc_reasoning: String,
    // ── Expandable detail (populated from the ThreatEvent) ──────────────
    /// MITRE tactic(s) — also used as a grouping key.
    pub tactics:        Vec<String>,
    /// Full technique list (the `technique` field above is just the first).
    pub techniques:     Vec<String>,
    /// Detection engine(s)/rule(s) that matched.
    pub matched_rules:  Vec<String>,
    /// Indicators of compromise: (type, value) — file paths, hashes, IPs, etc.
    pub iocs:           Vec<(String, String)>,
    /// Suggested response action (human-readable).
    pub suggested_action: String,
}

/// Maximum number of recent events retained in the in-memory ring buffer shown
/// on the local status UI. Full history lives in Nexus / the local log, not here.
pub const MAX_RECENT_EVENTS: usize = 200;

/// Record a detected event into the status snapshot's recent-events ring buffer
/// (newest first, bounded). Local-only; safe to call from the detection loop.
pub async fn record_event(state: &StatusState, ev: StatusEvent) {
    let mut snap = state.write().await;
    snap.recent_events.insert(0, ev);
    snap.recent_events.truncate(MAX_RECENT_EVENTS);
    snap.active_threats = snap.recent_events.len();
}

/// Attach ATC reasoning to the most recent matching event (same threat_name +
/// technique) once async LLM enrichment completes, and mark its source "ATC".
/// If no match is found (e.g. buffer rotated), records nothing — the base event
/// already captured the detection.
pub async fn attach_atc_reasoning(state: &StatusState, threat_name: &str,
                                  technique: &str, confidence: f32, reasoning: String) {
    let mut snap = state.write().await;
    if let Some(ev) = snap.recent_events.iter_mut()
        .find(|e| e.threat_name == threat_name && e.technique == technique && e.source != "ATC") {
        ev.source = "ATC".into();
        ev.confidence = confidence;
        ev.atc_reasoning = reasoning;
    }
}

#[derive(Debug, Clone, Default)]
pub struct ModuleStatus {
    pub name:    String,
    pub healthy: bool,
    pub detail:  String,
}

pub type StatusState = Arc<RwLock<StatusSnapshot>>;

pub struct StatusServer {
    pub state: StatusState,
}

impl StatusServer {
    pub fn new() -> (Self, StatusState) {
        let state = Arc::new(RwLock::new(StatusSnapshot::default()));
        (Self { state: state.clone() }, state)
    }

    pub async fn start(self) -> Result<()> {
        let state = self.state.clone();
        let state2 = state.clone();

        let app = Router::new()
            .route("/",           get(root_handler).with_state(state))
            .route("/api/status", get(api_handler).with_state(state2))
            .route("/health",     get(|| async { "ok" }));

        let addr = "127.0.0.1:7440";
        info!("🖥️  Sentinel status UI: http://{} (local only, read-only)", addr);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}


fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Render the recent-events list grouped by MITRE tactic, with each event as an
/// expandable row. Uses native <details>/<summary> so no JavaScript is required.
/// Events with no tactic are collected under "Uncategorized". Groups are ordered
/// by highest severity within them, then by event count.
fn render_events_grouped(events: &[StatusEvent]) -> String {
    use std::collections::BTreeMap;
    // Group key = first tactic, or "Uncategorized".
    let mut groups: BTreeMap<String, Vec<&StatusEvent>> = BTreeMap::new();
    for e in events {
        let key = e.tactics.first().cloned()
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| "Uncategorized".to_string());
        groups.entry(key).or_default().push(e);
    }
    // Order groups by worst severity inside (Critical first), then by count.
    let sev_rank = |s: &str| match s {
        "Critical" => 4, "High" => 3, "Medium" => 2, "Low" => 1, _ => 0 };
    let mut ordered: Vec<(String, Vec<&StatusEvent>)> = groups.into_iter().collect();
    ordered.sort_by(|a, b| {
        let amax = a.1.iter().map(|e| sev_rank(&e.severity)).max().unwrap_or(0);
        let bmax = b.1.iter().map(|e| sev_rank(&e.severity)).max().unwrap_or(0);
        bmax.cmp(&amax).then(b.1.len().cmp(&a.1.len()))
    });

    ordered.iter().map(|(tactic, evs)| {
        // Group header: tactic name + count + worst-severity dot.
        let worst = evs.iter().map(|e| sev_rank(&e.severity)).max().unwrap_or(0);
        let dot = match worst { 4 => "#ff1f4a", 3 => "#ff4d6a", 2 => "#ffb830", 1 => "#7b8fff", _ => "#4a6080" };
        let body: String = evs.iter().map(|e| render_one_event(e)).collect();
        format!(
            "<details open style='margin-bottom:6px'>\
               <summary style='cursor:pointer;list-style:none;display:flex;align-items:center;gap:8px;\
                 padding:6px 8px;background:rgba(255,255,255,.03);border-radius:6px;font-size:11px;\
                 font-weight:700;letter-spacing:.03em;text-transform:uppercase;color:#9fb0d0'>\
                 <span style='width:7px;height:7px;border-radius:50%;background:{dot}'></span>\
                 <span style='flex:1'>{tactic}</span>\
                 <span style='color:#4a6080;font-weight:600'>{n} event{plural}</span>\
               </summary>\
               <div style='padding:2px 0 4px 4px'>{body}</div>\
             </details>",
            dot = dot, tactic = esc(tactic), n = evs.len(),
            plural = if evs.len() == 1 { "" } else { "s" }, body = body)
    }).collect::<Vec<_>>().join("")
}

/// Render a single event as an expandable row: a one-line summary that expands to
/// show full detail (all techniques, matched rules, IOCs with file paths/hashes,
/// suggested action, and ATC reasoning).
fn render_one_event(e: &StatusEvent) -> String {
    let sc = match e.severity.as_str() {
        "Critical" => "#ff1f4a", "High" => "#ff4d6a", "Medium" => "#ffb830", _ => "#7b8fff" };
    let (src_label, src_color, src_bg) = if e.source == "ATC" {
        ("ATC", "#00e5a0", "rgba(0,229,160,.10)")
    } else {
        ("Legacy", "#7b8fff", "rgba(123,143,255,.10)")
    };
    let conf = if e.confidence > 0.0 { format!("{:.0}%", e.confidence) } else { "–".into() };

    // ── Detail body (shown when expanded) ──────────────────────────────
    let mut detail = String::new();
    if !e.description.trim().is_empty() {
        detail.push_str(&format!(
            "<div style='font-size:11.5px;color:#c3cee0;line-height:1.5;margin:2px 0 6px'>{}</div>",
            esc(&e.description)));
    }
    // key/value detail rows
    let mut kv = |label: &str, val: String| {
        if !val.trim().is_empty() {
            detail.push_str(&format!(
                "<div style='display:flex;gap:8px;font-size:11px;padding:1px 0'>\
                   <span style='color:#4a6080;min-width:96px'>{}</span>\
                   <span style='color:#c3cee0;font-family:monospace;word-break:break-all'>{}</span></div>",
                label, val));
        }
    };
    if !e.techniques.is_empty()    { kv("Techniques", esc(&e.techniques.join(", "))); }
    if !e.tactics.is_empty()       { kv("Tactics",    esc(&e.tactics.join(", "))); }
    if !e.matched_rules.is_empty() { kv("Matched by", esc(&e.matched_rules.join(", "))); }
    if !e.suggested_action.trim().is_empty() && e.suggested_action != "None" {
        kv("Suggested",  esc(&e.suggested_action));
    }
    // IOCs — this is where file paths, hashes, IPs surface.
    if !e.iocs.is_empty() {
        let items: String = e.iocs.iter().map(|(t, v)| format!(
            "<div style='display:flex;gap:8px;font-size:11px;padding:1px 0'>\
               <span style='color:#7b8fff;min-width:96px;font-family:monospace'>{}</span>\
               <span style='color:#e6e9ef;font-family:monospace;word-break:break-all'>{}</span></div>",
            esc(t), esc(v))).collect();
        detail.push_str(&format!(
            "<div style='margin-top:6px'><div style='color:#4a6080;font-size:10px;\
               text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px'>Indicators</div>{}</div>",
            items));
    }
    // ATC reasoning callout
    if !e.atc_reasoning.trim().is_empty() {
        detail.push_str(&format!(
            "<div style='font-size:11px;color:#9fb0d0;line-height:1.5;padding:6px 0 2px 8px;\
               border-left:2px solid rgba(0,229,160,.35);margin:6px 0 2px 2px'>\
               <span style='color:#00e5a0;font-weight:700;font-size:9px;text-transform:uppercase;\
               letter-spacing:.05em'>ATC reasoning</span><br>{}</div>",
            esc(&e.atc_reasoning)));
    }

    format!(
        "<details style='border-bottom:1px solid rgba(255,255,255,.06)'>\
           <summary style='cursor:pointer;list-style:none;display:flex;align-items:center;gap:9px;padding:7px 4px'>\
             <span style='color:#4a6080;font-size:10px'>▸</span>\
             <span style='font-size:9px;padding:2px 7px;border-radius:20px;font-weight:700;color:{sc};background:rgba(255,255,255,.05)'>{sev}</span>\
             <span style='font-size:9px;padding:2px 7px;border-radius:20px;font-weight:700;color:{src_color};background:{src_bg}'>{src_label}</span>\
             <span style='flex:1;font-size:12px'>{name}</span>\
             <span style='font-family:monospace;font-size:10px;color:#8fa;opacity:.8'>{conf}</span>\
             <span style='font-family:monospace;font-size:10px;color:#7b8fff'>{tech}</span>\
             <span style='font-family:monospace;font-size:10px;color:#4a6080'>{ts}</span>\
           </summary>\
           <div style='padding:2px 8px 10px 24px'>{detail}</div>\
         </details>",
        sc=sc, sev=esc(&e.severity), src_label=src_label, src_color=src_color, src_bg=src_bg,
        name=esc(&e.threat_name), conf=conf, tech=esc(&e.technique), ts=esc(&e.timestamp), detail=detail)
}


#[allow(clippy::too_many_arguments)]
fn render_status_html(
    s: &StatusSnapshot,
    mode_color: &str,
    posture_color: &str,
    modules_html: &str,
    threats_html: &str,
) -> String {
    // Three-state Nexus indicator. Standalone (no Nexus configured) and Offline
    // (configured but unreachable) are BOTH normal operating states — the agent
    // keeps detecting locally either way — so neither is styled as a hard error.
    let (nexus_status, nexus_color) = if !s.nexus_configured {
        ("Standalone", "#7b8fff")               // deliberate no-Nexus deployment
    } else if s.nexus_connected {
        ("Connected",  "#00e5a0")               // healthy uplink
    } else {
        ("Offline",    "#ffb830")               // configured Nexus unreachable
    };
    let threat_color = if s.active_threats > 0 { "#ff4d6a" } else { "#00e5a0" };

    // Banner shown while operating without a live Nexus uplink — reassures that
    // local detection continues and points at the standalone telemetry below.
    let offline_banner = if s.nexus_configured && !s.nexus_connected {
        format!("<div style='background:rgba(255,184,48,.08);border:1px solid rgba(255,184,48,.3);\
            border-radius:9px;padding:11px 14px;margin-bottom:16px;font-size:12px;color:#ffca66'>\
            <b>Offline mode</b> — the configured Nexus (<span style='font-family:monospace'>{}</span>) \
            is unreachable. Detection, rules, and forensics continue locally; events are queued and \
            will sync when the uplink returns. Live standalone telemetry is shown below.</div>",
            esc(&s.nexus_url))
    } else if !s.nexus_configured {
        "<div style='background:rgba(123,143,255,.08);border:1px solid rgba(123,143,255,.3);\
            border-radius:9px;padding:11px 14px;margin-bottom:16px;font-size:12px;color:#9fb0d0'>\
            <b>Standalone mode</b> — no Nexus is configured. This agent runs fully autonomously; \
            all detection and telemetry below is local to this host.</div>".to_string()
    } else {
        String::new()
    };

    // FIM watched-paths list for the File Integrity tab.
    let fim_html = if s.fim_watched.is_empty() {
        "<div style='color:#4a6080;font-size:12px'>No watched paths configured.</div>".to_string()
    } else {
        s.fim_watched.iter().map(|(path, desc)| format!(
            "<div style='display:flex;gap:10px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.06)'>\
               <span style='font-family:monospace;font-size:11px;color:#c3cee0;flex:1;word-break:break-all'>{}</span>\
               <span style='font-size:10px;color:#4a6080'>{}</span></div>",
            esc(path), esc(desc))).collect::<Vec<_>>().join("")
    };

    format!(r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="15">
<title>NebulaSentinel — {hostname}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',sans-serif;background:#05080d;color:#dae8ff;font-size:13px;line-height:1.5;padding:24px;max-width:980px;margin:0 auto}}
.hdr{{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;padding-bottom:14px;border-bottom:1px solid rgba(44,80,160,.2)}}
.brand{{display:flex;align-items:center;gap:10px}}
.bname{{font-size:15px;font-weight:700;background:linear-gradient(135deg,#00cfff,#7b8fff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.kpis{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:18px}}
.kpi{{background:#0d1520;border:1px solid rgba(44,80,160,.18);border-radius:9px;padding:12px 14px}}
.kv{{font-size:22px;font-weight:700;line-height:1;margin-bottom:4px}}
.kl{{font-size:9px;color:#4a6080;text-transform:uppercase;letter-spacing:.1em}}
.g2{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}}
.card{{background:#0d1520;border:1px solid rgba(44,80,160,.18);border-radius:9px;padding:14px 16px}}
.ct{{font-size:11.5px;font-weight:600;color:#00cfff;margin-bottom:10px}}
.row{{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.06)}}
.row:last-child{{border:none}}
.rk{{font-size:10.5px;color:#4a6080}}.rv{{font-size:11px;font-weight:500;font-family:monospace}}
.note{{font-size:10px;color:#4a6080;text-align:center;margin-top:16px}}
/* Pure-CSS tabs (no JS): hidden radios drive :checked sibling panels */
.tabs input[type=radio]{{display:none}}
.tabnav{{display:flex;gap:4px;border-bottom:1px solid rgba(44,80,160,.18);margin-bottom:14px}}
.tablabel{{cursor:pointer;padding:8px 16px;font-size:11.5px;font-weight:600;color:#4a6080;border-bottom:2px solid transparent;margin-bottom:-1px}}
.tablabel:hover{{color:#9fb0d0}}
.tabpanel{{display:none}}
#t-events:checked~.tabnav label[for=t-events],
#t-fim:checked~.tabnav label[for=t-fim],
#t-posture:checked~.tabnav label[for=t-posture],
#t-modules:checked~.tabnav label[for=t-modules]{{color:#00cfff;border-bottom-color:#00cfff}}
#t-events:checked~#p-events,
#t-fim:checked~#p-fim,
#t-posture:checked~#p-posture,
#t-modules:checked~#p-modules{{display:block}}
</style>
</head>
<body>
<div class="hdr">
  <div class="brand">
    <div style="width:36px;height:36px;background:rgba(0,207,255,.12);border:1px solid rgba(0,207,255,.3);border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px">🛡</div>
    <div><div class="bname">NebulaSentinel</div><div style="font-size:10px;color:#4a6080">{hostname} · {platform} · {version}</div></div>
  </div>
  <div style="font-size:10px;color:#4a6080">Auto-refresh 15s · <a href="/api/status" style="color:#00cfff">JSON</a></div>
</div>
{offline_banner}
<div class="kpis">
  <div class="kpi"><div class="kv" style="color:{mode_color}">{mode}</div><div class="kl">Mode</div></div>
  <div class="kpi"><div class="kv" style="color:{posture_color}">{posture:.0}%</div><div class="kl">Posture</div></div>
  <div class="kpi"><div class="kv" style="color:{nexus_color}">{nexus_status}</div><div class="kl">Nexus</div></div>
  <div class="kpi"><div class="kv" style="color:{threat_color}">{threats}</div><div class="kl">Active Threats</div></div>
  <div class="kpi"><div class="kv" style="color:#00cfff">{rules}</div><div class="kl">Rules</div></div>
</div>
<div class="tabs">
  <input type="radio" name="tab" id="t-events" checked>
  <input type="radio" name="tab" id="t-fim">
  <input type="radio" name="tab" id="t-posture">
  <input type="radio" name="tab" id="t-modules">
  <div class="tabnav">
    <label class="tablabel" for="t-events">Events</label>
    <label class="tablabel" for="t-fim">File Integrity</label>
    <label class="tablabel" for="t-posture">Posture</label>
    <label class="tablabel" for="t-modules">Modules</label>
  </div>

  <div class="tabpanel" id="p-events">
    <div class="card"><div class="ct">Detected Events (grouped by tactic)</div>{threats_html}</div>
  </div>

  <div class="tabpanel" id="p-fim">
    <div class="card">
      <div class="ct">Monitored Paths</div>
      <div style="font-size:11px;color:#4a6080;margin-bottom:8px">File-integrity watch list on this host. Modifications appear as detections in the Events tab.</div>
      {fim_html}
    </div>
  </div>

  <div class="tabpanel" id="p-posture">
    <div class="g2">
      <div class="card">
        <div class="ct">Local Detection</div>
        <div style="font-size:40px;font-weight:700;color:{posture_color};line-height:1;margin:6px 0 10px">{posture:.0}%</div>
        <div class="row"><span class="rk">Collector</span><span class="rv">{collector}</span></div>
        <div class="row"><span class="rk">Firewall</span><span class="rv">{firewall}</span></div>
        <div class="row"><span class="rk">Rules loaded</span><span class="rv">{rules}</span></div>
        <div class="row"><span class="rk">IOCs loaded</span><span class="rv">{iocs}</span></div>
        <div class="row"><span class="rk">LLM (ATC)</span><span class="rv">{llm}</span></div>
      </div>
      <div class="card">
        <div class="ct">System</div>
        <div class="row"><span class="rk">Agent ID</span><span class="rv" style="color:#00cfff;font-size:10px">{agent_id}</span></div>
        <div class="row"><span class="rk">Nexus</span><span class="rv" style="color:{nexus_color}">{nexus_status}</span></div>
        <div class="row"><span class="rk">Nexus URL</span><span class="rv" style="font-size:10px">{nexus_url}</span></div>
        <div class="row"><span class="rk">Last contact</span><span class="rv">{last_contact}</span></div>
        <div class="row"><span class="rk">Started</span><span class="rv" style="font-size:10px">{started}</span></div>
      </div>
    </div>
  </div>

  <div class="tabpanel" id="p-modules">
    <div class="card"><div class="ct">Modules</div>{modules_html}</div>
  </div>
</div>
<div class="note">NebulaSentinel Status UI · Read-only · 127.0.0.1:7440 only</div>
</body>
</html>"###,
        hostname=s.hostname, platform=s.platform, version=s.version,
        mode=s.mode.to_uppercase(), mode_color=mode_color,
        posture=s.posture_score, posture_color=posture_color,
        nexus_status=nexus_status, nexus_color=nexus_color,
        threats=s.active_threats, threat_color=threat_color,
        rules=s.rules_loaded, agent_id=s.agent_id,
        nexus_url=if s.nexus_url.is_empty() { "—".into() } else { esc(&s.nexus_url) },
        last_contact=if s.last_nexus_contact.is_empty() { "never".into() } else { esc(&s.last_nexus_contact) },
        firewall=if s.firewall_backend.is_empty() { "detecting…".into() } else { esc(&s.firewall_backend) },
        llm=if s.llm_status.is_empty() { "—".into() } else { esc(&s.llm_status) },
        collector=if s.collector_backend.is_empty() { "—".into() } else { esc(&s.collector_backend) },
        iocs=s.iocs_loaded, started=s.started_at,
        offline_banner=offline_banner,
        modules_html=modules_html, threats_html=threats_html,
        fim_html=fim_html,
    )
}

async fn root_handler(State(state): State<StatusState>) -> Html<String> {
    let s = state.read().await.clone();
    let mode_color = match s.mode.as_str() {
        "protect" => "#ff4d6a", "detect" => "#00cfff",
        "audit"   => "#ffb830", _        => "#4a6080",
    };
    let posture_color = if s.posture_score >= 80.0 { "#00e5a0" }
        else if s.posture_score >= 60.0 { "#ffb830" } else { "#ff4d6a" };

    let threats_html = if s.recent_events.is_empty() {
        "<div style='color:#4a6080;font-size:12px;padding:10px 0'>No recent threat events.</div>".into()
    } else {
        render_events_grouped(&s.recent_events)
    };

    let modules_html = s.modules.iter().map(|m| {
        let dot = if m.healthy { "#00e5a0" } else { "#ff4d6a" };
        format!("<div style='display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.06)'>
          <div style='width:7px;height:7px;border-radius:50%;background:{dot};flex-shrink:0'></div>
          <span style='font-size:11.5px;font-weight:500;min-width:140px'>{name}</span>
          <span style='font-size:10.5px;color:#4a6080'>{det}</span>
        </div>", dot=dot, name=m.name, det=m.detail)
    }).collect::<Vec<_>>().join("");

    Html(render_status_html(&s, &mode_color, &posture_color, &modules_html, &threats_html))
}

async fn api_handler(State(state): State<StatusState>) -> axum::Json<serde_json::Value> {
    let s = state.read().await;
    // Derived tri-state so scripts don't have to combine the two booleans.
    let nexus_state = if !s.nexus_configured { "standalone" }
        else if s.nexus_connected { "connected" } else { "offline" };
    axum::Json(serde_json::json!({
        "hostname": s.hostname, "agent_id": s.agent_id, "platform": s.platform,
        "mode": s.mode, "posture_score": s.posture_score,
        "nexus_state": nexus_state,
        "nexus_configured": s.nexus_configured, "nexus_connected": s.nexus_connected,
        "last_nexus_contact": s.last_nexus_contact,
        "active_threats": s.active_threats,
        "rules_loaded": s.rules_loaded, "iocs_loaded": s.iocs_loaded,
        "collector_backend": s.collector_backend,
        "firewall_backend": s.firewall_backend, "llm_status": s.llm_status,
    }))
}
