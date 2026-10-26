// collector/windows.rs — Windows Event Log collector backend.
//
// The richer native event source on Windows. Polls the Security / System logs
// for security-relevant events and translates them into the agent's RawEvent
// stream — the same stream the Linux eBPF/procmon backends feed, so the entire
// downstream pipeline (anomaly, rules, gossip, LLM, reputation) works unchanged.
//
// Implementation choice: we shell out to `wevtutil` (built into every Windows
// install since Vista) and parse its XML output, rather than binding the Win32
// EvtQuery FFI directly. Rationale: wevtutil is rock-solid, requires no unsafe
// FFI, and gives structured XML. A future iteration can swap in the ETW/EvtQuery
// API for lower latency if needed — the RawEvent contract stays the same.
//
// Mapped events (Security log unless noted):
//   4688  process creation            -> ProcessExec
//   4624  successful logon            -> UserAuth
//   4625  failed logon                -> UserAuth (return_code = 1)
//   4672  special privileges assigned -> UserSu  (privilege escalation signal)
//   7045  service installed (System)  -> ModuleLoad
//   4697  service installed (Security)-> ModuleLoad
//
// NOTE: 4688 command-line capture requires the "Include command line in process
// creation events" audit policy (and process-creation auditing) to be enabled.
// Without it, process names are captured but command lines may be empty — we log
// a one-time hint so the operator can enable richer telemetry.

#![cfg(target_os = "windows")]

use crate::types::{RawEvent, EventType};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Start the Windows Event Log collector. Polls the relevant channels on an
/// interval and emits RawEvents. Non-fatal: if wevtutil is unavailable or a
/// query fails, it logs and keeps polling (degrades rather than dies).
pub async fn start(
    tx: mpsc::Sender<RawEvent>,
    agent_id: String,
    hostname: String,
    poll_secs: u64,
) -> Result<()> {
    info!("🔬 Windows Event Log collector: polling Security/System every {}s", poll_secs);

    // One-time capability hint.
    if !command_line_auditing_likely_enabled() {
        warn!("⚠️  Windows: process command-line auditing may be disabled. For full \
               telemetry enable 'Audit Process Creation' + 'Include command line in \
               process creation events' via Group Policy. Process names are still captured.");
    }

    tokio::task::spawn_blocking(move || {
        // Track the most recent EventRecordID we've seen per channel so each poll
        // only emits NEW events (wevtutil returns newest-first; we high-watermark).
        let mut last_record: HashMap<&str, u64> = HashMap::new();

        loop {
            // Security channel — the bulk of security-relevant events.
            poll_channel("Security", &["4688", "4624", "4625", "4672", "4697"],
                         &tx, &agent_id, &hostname, &mut last_record);
            // System channel — service installs (7045) live here.
            poll_channel("System", &["7045"],
                         &tx, &agent_id, &hostname, &mut last_record);

            std::thread::sleep(std::time::Duration::from_secs(poll_secs.max(2)));
        }
    });

    Ok(())
}

/// Query one channel for a set of event IDs and emit any not seen before.
fn poll_channel(
    channel: &'static str,
    event_ids: &[&str],
    tx: &mpsc::Sender<RawEvent>,
    agent_id: &str,
    hostname: &str,
    last_record: &mut HashMap<&'static str, u64>,
) {
    // Build an XPath query: (EventID=4688 or EventID=4624 or …)
    let id_clause = event_ids.iter()
        .map(|id| format!("EventID={}", id))
        .collect::<Vec<_>>()
        .join(" or ");
    let query = format!("*[System[({})]]", id_clause);

    // wevtutil qe <channel> /q:<query> /f:xml /c:50 /rd:true
    //   /rd:true = reverse direction (newest first), /c:50 = cap per poll.
    let output = std::process::Command::new("wevtutil")
        .args(["qe", channel, &format!("/q:{}", query), "/f:xml", "/c:50", "/rd:true"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.trim().is_empty() {
                warn!("Windows EventLog: wevtutil {} query failed: {}", channel, err.trim());
            }
            return;
        }
        Err(e) => {
            warn!("Windows EventLog: cannot run wevtutil ({}). Falling back to procmon only.", e);
            return;
        }
    };

    let xml = String::from_utf8_lossy(&output.stdout);
    let high_water = last_record.get(channel).copied().unwrap_or(0);
    let mut new_high = high_water;
    let mut emitted = 0u32;

    // wevtutil emits one <Event>…</Event> per record, concatenated. Split on the
    // closing tag so we can parse each independently (the records are not wrapped
    // in a single root element).
    for chunk in xml.split("</Event>") {
        if !chunk.contains("<Event") { continue; }
        let record = format!("{}</Event>", chunk);

        let record_id = extract_tag(&record, "EventRecordID")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        // Skip records at or below the high-water mark (already emitted).
        if record_id != 0 && record_id <= high_water { continue; }
        new_high = new_high.max(record_id);

        if let Some(event) = parse_event(&record, agent_id, hostname) {
            // Best-effort send; if the channel is full we drop rather than block.
            if tx.try_send(event).is_ok() { emitted += 1; }
        }
    }

    if new_high > high_water { last_record.insert(channel, new_high); }
    if emitted > 0 {
        info!("🔬 Windows EventLog[{}]: {} new event(s)", channel, emitted);
    }
}

/// Parse a single Windows event XML record into a RawEvent.
fn parse_event(xml: &str, agent_id: &str, hostname: &str) -> Option<RawEvent> {
    let event_id = extract_tag(xml, "EventID")?;
    // EventData carries <Data Name="...">value</Data> pairs.
    let data = extract_event_data(xml);
    let get = |k: &str| data.get(k).cloned().unwrap_or_default();

    let mut extra: HashMap<String, serde_json::Value> = HashMap::new();
    extra.insert("windows_event_id".into(), serde_json::json!(event_id));
    extra.insert("windows_channel".into(), serde_json::json!(extract_tag(xml, "Channel").unwrap_or_default()));

    let base = |event_type: EventType| RawEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: agent_id.to_string(),
        hostname: hostname.to_string(),
        timestamp: Utc::now(),
        event_type,
        pid: 0, ppid: 0, uid: 0, gid: 0,
        process_name: String::new(),
        process_path: None,
        command_line: None,
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
        extra: extra.clone(),
    };

    match event_id.as_str() {
        // ── Process creation ──
        "4688" => {
            let mut e = base(EventType::ProcessExec);
            // NewProcessName = full image path; ProcessId is hex in 4688.
            let image = get("NewProcessName");
            e.process_name = image.rsplit('\\').next().unwrap_or(&image).to_string();
            e.process_path = if image.is_empty() { None } else { Some(image) };
            e.parent_process = {
                let p = get("ParentProcessName");
                if p.is_empty() { None } else { Some(p.rsplit('\\').next().unwrap_or(&p).to_string()) }
            };
            e.command_line = {
                let c = get("CommandLine");
                if c.is_empty() { None } else { Some(c) }
            };
            e.pid  = parse_hex_or_dec(&get("NewProcessId"));
            e.ppid = parse_hex_or_dec(&get("ProcessId"));
            e.syscall = Some("4688".into());
            Some(e)
        }
        // ── Logon success / failure ──
        "4624" | "4625" => {
            let mut e = base(EventType::UserAuth);
            e.process_name = get("TargetUserName");
            e.command_line = Some(format!(
                "logon type {} from {} ({})",
                get("LogonType"),
                if get("IpAddress").is_empty() { "local".into() } else { get("IpAddress") },
                if event_id == "4625" { "FAILED" } else { "success" },
            ));
            e.network_dest_ip = { let ip = get("IpAddress"); if ip.is_empty() || ip == "-" { None } else { Some(ip) } };
            e.return_code = Some(if event_id == "4625" { 1 } else { 0 });
            e.syscall = Some(event_id.to_string());
            Some(e)
        }
        // ── Special privileges assigned (privilege-escalation signal) ──
        "4672" => {
            let mut e = base(EventType::UserSu);
            e.process_name = get("SubjectUserName");
            e.command_line = Some("special privileges assigned to new logon".into());
            e.syscall = Some("4672".into());
            Some(e)
        }
        // ── Service installed (System 7045 or Security 4697) ──
        "7045" | "4697" => {
            let mut e = base(EventType::ModuleLoad);
            let svc = if !get("ServiceName").is_empty() { get("ServiceName") } else { get("ServiceFileName") };
            e.process_name = svc;
            e.process_path = { let p = get("ImagePath"); if p.is_empty() { Some(get("ServiceFileName")) } else { Some(p) } };
            e.command_line = Some(format!("service installed: {}", get("ServiceFileName")));
            e.syscall = Some(event_id.to_string());
            Some(e)
        }
        _ => None,
    }
}

// ── Minimal XML helpers (avoid a heavy XML dep for this fixed, simple schema) ──

/// Extract the text content of the first <Tag>…</Tag> occurrence.
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    // Handle both <Tag>val</Tag> and <Tag Attr='x'>val</Tag>.
    let open_simple = format!("<{}>", tag);
    let open_attr   = format!("<{} ", tag);
    let close       = format!("</{}>", tag);
    let start = if let Some(i) = xml.find(&open_simple) {
        i + open_simple.len()
    } else if let Some(i) = xml.find(&open_attr) {
        // find the end of the opening tag '>'
        let after = &xml[i..];
        let gt = after.find('>')? + i + 1;
        gt
    } else {
        return None;
    };
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

/// Parse all <Data Name="Key">Value</Data> pairs from EventData.
fn extract_event_data(xml: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<Data Name=") {
        rest = &rest[i..];
        // Name attribute value (handles ' or ").
        let name = {
            let after = &rest["<Data Name=".len()..];
            let quote = after.chars().next().unwrap_or('"');
            let after = &after[1..];
            match after.find(quote) {
                Some(end) => after[..end].to_string(),
                None => break,
            }
        };
        // Value between > and </Data>
        let val = match (rest.find('>'), rest.find("</Data>")) {
            (Some(gt), Some(close)) if close > gt => rest[gt + 1..close].trim().to_string(),
            _ => String::new(),
        };
        if !name.is_empty() { map.insert(name, val); }
        // Advance past this Data element.
        if let Some(close) = rest.find("</Data>") { rest = &rest[close + "</Data>".len()..]; }
        else { break; }
    }
    map
}

/// Windows 4688 encodes PIDs as hex (e.g. "0x1a4"). Handle both hex and decimal.
fn parse_hex_or_dec(s: &str) -> u32 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse::<u32>().unwrap_or(0)
    }
}

/// Heuristic: check whether process-creation command-line auditing appears on.
/// Best-effort — queries the registry value that governs it. Never fails hard.
fn command_line_auditing_likely_enabled() -> bool {
    let out = std::process::Command::new("reg")
        .args(["query",
               r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
               "/v", "ProcessCreationIncludeCmdLine_Enabled"])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).contains("0x1"),
        Err(_) => false,
    }
}
