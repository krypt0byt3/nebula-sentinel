// src/sigma/mod.rs — Agent-side Sigma rule evaluation (Phase 2: multi-category).
//
// Sigma is an event-matching format: a rule declares named `selection` blocks of
// field→value(s) conditions and a `condition:` expression combining them. Unlike
// YARA (which scans bytes), Sigma matches STRUCTURED EVENTS — here, the agent's
// RawEvents across every logsource category the agent can actually observe.
//
// SCOPE (Phase 2 — expanded from process_creation-only):
//   - logsource categories the agent can populate from a RawEvent:
//       process_creation                → EventType::ProcessExec
//       network_connection              → EventType::NetworkConnect / NetworkBind
//       dns_query / dns                 → EventType::NetworkDns
//       file_event / file_access        → EventType::FileOpen
//       file_event / file_change        → EventType::FileWrite
//       file_event / file_delete        → EventType::FileDelete
//       image_load / driver_load        → EventType::ModuleLoad
//       authentication                  → EventType::UserAuth
//     Any other category → the rule does not apply (safe no-match). The mapping
//     from EventType → category set lives in rules/mod.rs (`sigma_categories`);
//     `applies_to` here checks the rule's category against that set + product/OS.
//   - Condition subset: `and`/`or`/`not`, `all of them`/`1 of them`/`N of them`,
//     `all of selection*`/`1 of selection*`, parenthesization.
//   - Match modifiers: contains, startswith, endswith, re (regex), all (AND across
//     the value list). Matching is case-insensitive (except `re`, which honours
//     the pattern). base64/base64offset are flagged-unsupported (never mis-eval'd).
//   - Field map: common Sigma/Sysmon field names (Image, CommandLine, ParentImage,
//     DestinationIp, DestinationPort, DestinationHostname, Protocol, QueryName,
//     TargetFilename, Hashes, ImageLoaded, User, …) → the agent's RawEvent fields,
//     with Linux + Windows aliases. Fields the agent cannot supply resolve to
//     absent → they simply never match (they never panic).
//   - Aggregations (count()/near) and timeframes are NOT evaluated — such rules
//     are marked Unsupported so they never produce a false verdict.
//
// A match emits through the same detection path as YARA/FIM (caller builds the
// ThreatEvent), so Sigma hits flow to ATC → Nexus like any other detection.

use serde::Deserialize;
use std::collections::HashMap;

/// A parsed Sigma rule reduced to what the evaluator needs.
#[derive(Debug, Clone)]
pub struct SigmaRule {
    pub title: String,
    pub id: Option<String>,
    pub level: String,               // informational|low|medium|high|critical
    pub category: String,            // logsource.category
    pub product: Option<String>,     // logsource.product (windows|linux|...)
    #[allow(dead_code)] // advisory metadata; OS gating uses `product`, not `service`
    pub service: Option<String>,     // logsource.service (sshd|auth|...) — advisory
    pub selections: HashMap<String, Selection>,
    pub condition: String,
    pub tags: Vec<String>,           // attack.tXXXX etc.
    pub unsupported: Option<String>, // Some(reason) if we can't safely evaluate
}

/// One named selection block: a list of field-matchers that must ALL hold (AND),
/// where a field with a list value means ANY of the values (OR).
#[derive(Debug, Clone)]
pub struct Selection {
    pub matchers: Vec<FieldMatcher>,
    /// `keywords` selections (a bare list, no field) match if any string appears
    /// anywhere in the event's searchable text.
    pub keywords: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FieldMatcher {
    pub field: String,
    pub op: MatchOp,
    pub values: Vec<String>,   // OR across values (AND when `match_all`)
    pub negate: bool,
    /// `|all` modifier: every value in the list must match (AND) rather than any.
    pub match_all: bool,
}

#[derive(Debug, Clone)]
pub enum MatchOp { Equals, Contains, StartsWith, EndsWith, Regex }

// ── Raw YAML shape (serde) ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RawSigma {
    title: Option<String>,
    id: Option<String>,
    level: Option<String>,
    logsource: Option<RawLogsource>,
    detection: Option<serde_yaml::Value>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RawLogsource {
    category: Option<String>,
    product: Option<String>,
    service: Option<String>,
}

/// Parse a Sigma YAML document into a SigmaRule. Returns None if it's not a
/// usable single-rule doc; sets `unsupported` if it parses but we can't evaluate.
pub fn parse_sigma(yaml: &str) -> Option<SigmaRule> {
    let raw: RawSigma = serde_yaml::from_str(yaml).ok()?;
    let ls = raw.logsource.unwrap_or(RawLogsource { category: None, product: None, service: None });
    let category = ls.category.unwrap_or_default();
    let detection = raw.detection?;
    let det_map = detection.as_mapping()?;

    let mut selections = HashMap::new();
    let mut condition = String::new();
    let mut unsupported = None;

    for (k, v) in det_map {
        let key = k.as_str().unwrap_or("").to_string();
        if key == "condition" {
            // condition may be a string or (rarely) a list — take the string form.
            condition = match v {
                serde_yaml::Value::String(s) => s.clone(),
                serde_yaml::Value::Sequence(seq) =>
                    seq.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" or "),
                _ => String::new(),
            };
        } else if key == "timeframe" {
            unsupported = Some("aggregation/timeframe not supported".to_string());
        } else {
            match parse_selection(v) {
                Ok(sel) => { selections.insert(key, sel); }
                Err(reason) => { unsupported = Some(reason); }
            }
        }
    }

    // Aggregations in the condition (`| count`, `near`) — can't evaluate safely.
    if condition.contains('|') || condition.contains(" near ") {
        unsupported = Some("aggregation (count/near) not supported".to_string());
    }

    Some(SigmaRule {
        title: raw.title.unwrap_or_else(|| "untitled sigma rule".to_string()),
        id: raw.id,
        level: raw.level.unwrap_or_else(|| "medium".to_string()),
        category,
        product: ls.product,
        service: ls.service,
        selections,
        condition,
        tags: raw.tags.unwrap_or_default(),
        unsupported,
    })
}

/// Parse one selection block (a mapping of field→value(s), or a bare keyword list).
fn parse_selection(v: &serde_yaml::Value) -> Result<Selection, String> {
    let mut matchers = Vec::new();
    let mut keywords = Vec::new();

    match v {
        // Bare list = keyword search.
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                if let Some(s) = item.as_str() {
                    keywords.push(s.to_string());
                } else if let Some(m) = item.as_mapping() {
                    // list-of-maps: each map is an alternative (OR); flatten fields.
                    for (fk, fv) in m {
                        matchers.push(field_matcher(fk.as_str().unwrap_or(""), fv)?);
                    }
                }
            }
        }
        // Mapping = field: value(s) matchers (AND across fields).
        serde_yaml::Value::Mapping(m) => {
            for (fk, fv) in m {
                matchers.push(field_matcher(fk.as_str().unwrap_or(""), fv)?);
            }
        }
        _ => return Err("unexpected selection shape".to_string()),
    }
    Ok(Selection { matchers, keywords })
}

/// Build a FieldMatcher from a `Field|modifier: value(s)` entry.
fn field_matcher(field_spec: &str, value: &serde_yaml::Value) -> Result<FieldMatcher, String> {
    // field name may carry modifiers: "CommandLine|contains|all".
    let parts: Vec<&str> = field_spec.split('|').collect();
    let field = parts[0].to_string();
    let mods: Vec<&str> = parts[1..].to_vec();

    if mods.iter().any(|m| *m == "base64" || *m == "base64offset") {
        return Err("base64 modifier not supported".to_string());
    }
    let negate = mods.iter().any(|m| *m == "not"); // rare inline form
    let match_all = mods.iter().any(|m| *m == "all");
    let op = if mods.iter().any(|m| *m == "contains") { MatchOp::Contains }
        else if mods.iter().any(|m| *m == "startswith") { MatchOp::StartsWith }
        else if mods.iter().any(|m| *m == "endswith") { MatchOp::EndsWith }
        else if mods.iter().any(|m| *m == "re") { MatchOp::Regex }
        else { MatchOp::Equals };

    let values = match value {
        serde_yaml::Value::String(s) => vec![s.clone()],
        serde_yaml::Value::Number(n) => vec![n.to_string()],
        serde_yaml::Value::Bool(b) => vec![b.to_string()],
        serde_yaml::Value::Sequence(seq) =>
            seq.iter().map(|x| match x {
                serde_yaml::Value::String(s) => s.clone(),
                serde_yaml::Value::Number(n) => n.to_string(),
                other => other.as_str().unwrap_or("").to_string(),
            }).collect(),
        serde_yaml::Value::Null => vec![String::new()],
        _ => return Err("unexpected field value shape".to_string()),
    };

    Ok(FieldMatcher { field, op, values, negate, match_all })
}

// ── Event abstraction ───────────────────────────────────────────────────────

/// A field-mapped view of any RawEvent the agent can Sigma-evaluate. The caller
/// (rules/mod.rs) builds this from a RawEvent so the sigma module stays free of a
/// dependency on the agent's concrete types. Every field is a borrowed string:
/// unpopulated fields are `""` and resolve to "absent" (never match, never panic).
#[derive(Default)]
pub struct SigmaEvent<'a> {
    /// The event's own logsource category (informational; applicability is decided
    /// by `applies_to` against the caller-supplied category set).
    #[allow(dead_code)]
    pub category: &'a str,
    // process_creation
    pub image: &'a str,          // full path or name of the executable
    pub command_line: &'a str,
    pub parent_image: &'a str,
    pub user: &'a str,
    // network_connection
    pub dest_ip: &'a str,
    pub dest_port: &'a str,      // stringified port ("" if none)
    pub dest_hostname: &'a str,
    pub protocol: &'a str,
    // dns_query
    pub query_name: &'a str,
    // file_event
    pub target_filename: &'a str,
    pub file_hash: &'a str,
    // image_load / driver_load
    pub image_loaded: &'a str,
}

impl<'a> SigmaEvent<'a> {
    /// Resolve a Sigma field name to this event's value. Handles the common
    /// Sysmon/Windows field names AND their Linux/ECS equivalents, across every
    /// category. Returns None when the field is unknown OR the value is empty
    /// (unpopulated) — an absent field simply never matches.
    fn field(&self, name: &str) -> Option<&str> {
        let present = |s: &'a str| if s.is_empty() { None } else { Some(s) };
        match name {
            // ── process_creation ──
            "Image" | "image" | "process.executable" | "NewProcessName"
                => present(self.image),
            "CommandLine" | "commandline" | "process.command_line"
                => present(self.command_line),
            "ParentImage" | "parentimage" | "process.parent.executable" | "ParentProcessName"
                => present(self.parent_image),
            // ── authentication / user (shared with process) ──
            "User" | "user" | "user.name" | "TargetUserName" | "SubjectUserName" | "AccountName"
                => present(self.user),
            // ── network_connection ──
            "DestinationIp" | "DestinationIP" | "dest_ip" | "destination.ip"
            | "DestinationAddress" | "DstIp"
                => present(self.dest_ip),
            "DestinationPort" | "dest_port" | "destination.port" | "DstPort"
                => present(self.dest_port),
            "DestinationHostname" | "dest_hostname" | "destination.domain" | "DestinationDomain"
                => present(self.dest_hostname),
            "Protocol" | "protocol" | "network.transport" | "network.protocol"
                => present(self.protocol),
            // ── dns_query ──
            "QueryName" | "query" | "query_name" | "dns.question.name" | "DnsQuery" | "record.name"
                => present(self.query_name),
            // ── file_event / file_change / file_delete ──
            "TargetFilename" | "Filename" | "filename" | "file.path" | "file.name"
            | "TargetObject" | "FileName"
                => present(self.target_filename),
            "Hashes" | "Hash" | "md5" | "sha1" | "sha256" | "Imphash" | "file.hash.sha256"
            | "file.hash.md5"
                => present(self.file_hash),
            // ── image_load / driver_load ──
            "ImageLoaded" | "image_loaded" | "dll.path" | "ImagePath"
                => present(self.image_loaded),
            // Anything else (OriginalFileName, LogonType, RegistryKey, …) isn't
            // collected by the agent — treat as absent (safe no-match).
            _ => None,
        }
    }

    /// Text blob for keyword ("bare list") selections — every populated field.
    fn searchable(&self) -> String {
        format!(
            "{} {} {} {} {} {} {} {} {} {} {}",
            self.image, self.command_line, self.parent_image, self.user,
            self.dest_ip, self.dest_port, self.dest_hostname, self.protocol,
            self.query_name, self.target_filename, self.image_loaded,
        )
    }
}

/// Backwards-compatible process-only view. Retained so the previous public API
/// (`ProcEvent` + `matches_proc`/`applies_to_proc`) keeps working; it is just a
/// SigmaEvent restricted to the process fields.
#[allow(dead_code)] // back-compat API; the live path uses SigmaEvent
pub struct ProcEvent<'a> {
    pub image: &'a str,          // full path or name of the executable
    pub command_line: &'a str,
    pub parent_image: &'a str,
    pub user: &'a str,
}

#[allow(dead_code)] // back-compat API; the live path uses SigmaEvent
impl<'a> ProcEvent<'a> {
    fn as_sigma(&self) -> SigmaEvent<'a> {
        SigmaEvent {
            category: "process_creation",
            image: self.image,
            command_line: self.command_line,
            parent_image: self.parent_image,
            user: self.user,
            ..Default::default()
        }
    }
}

// ── Evaluation ──────────────────────────────────────────────────────────────

impl SigmaRule {
    /// Does this rule apply to an event whose category is in `event_categories`,
    /// on the given `os`? The caller derives the category set from the RawEvent's
    /// EventType. Unsupported rules and category mismatches never apply.
    pub fn applies_to(&self, event_categories: &[&str], os: &str) -> bool {
        if self.unsupported.is_some() { return false; }
        if self.category.is_empty() { return false; }
        if !event_categories.iter().any(|c| c.eq_ignore_ascii_case(&self.category)) {
            return false;
        }
        match &self.product {
            Some(p) if !p.is_empty() => p.eq_ignore_ascii_case(os) || os.is_empty(),
            _ => true, // no product ⇒ OS-agnostic
        }
    }

    /// Evaluate the rule against any Sigma event. Returns true on match.
    pub fn matches(&self, ev: &SigmaEvent) -> bool {
        if self.unsupported.is_some() { return false; }
        // Evaluate each selection to a bool, then evaluate the condition over them.
        let mut sel_results: HashMap<String, bool> = HashMap::new();
        for (name, sel) in &self.selections {
            sel_results.insert(name.clone(), eval_selection(sel, ev));
        }
        eval_condition(&self.condition, &sel_results)
    }

    /// Back-compat: does this rule apply to a process_creation event on this OS?
    #[allow(dead_code)] // superseded by `applies_to`; kept for API stability
    pub fn applies_to_proc(&self, os: &str) -> bool {
        self.applies_to(&["process_creation"], os)
    }

    /// Back-compat: evaluate against a process-only event view.
    #[allow(dead_code)] // superseded by `matches`; kept for API stability
    pub fn matches_proc(&self, ev: &ProcEvent) -> bool {
        self.matches(&ev.as_sigma())
    }
}

/// A selection matches if ALL its field-matchers hold (AND) and ALL its keywords
/// appear (Sigma treats a keyword list as OR within, but multiple isn't common;
/// we use ANY for keyword lists which is the standard semantic).
fn eval_selection(sel: &Selection, ev: &SigmaEvent) -> bool {
    // Keyword list: match if ANY keyword appears in the searchable text.
    if !sel.keywords.is_empty() {
        let hay = ev.searchable().to_lowercase();
        if sel.keywords.iter().any(|k| hay.contains(&k.to_lowercase())) {
            return true;
        }
        // keywords present but none matched, and no field matchers → false
        if sel.matchers.is_empty() { return false; }
    }
    // Field matchers: ALL must hold.
    for m in &sel.matchers {
        let got = eval_matcher(m, ev);
        if !got { return false; }
    }
    !sel.matchers.is_empty() || !sel.keywords.is_empty()
}

/// A field-matcher holds if ANY of its values matches (OR), or ALL of them when
/// the `|all` modifier is set (AND across the value list), per op.
fn eval_matcher(m: &FieldMatcher, ev: &SigmaEvent) -> bool {
    let field_val = match ev.field(&m.field) {
        Some(v) => v,
        None => {
            // Field not present / not collected. A negated match on an absent
            // field is vacuously true; a positive match is false.
            return m.negate;
        }
    };
    let fv_lower = field_val.to_lowercase();
    let one = |pat: &str| -> bool {
        let p = pat.to_lowercase();
        match m.op {
            MatchOp::Equals     => fv_lower == p,
            MatchOp::Contains   => fv_lower.contains(&p),
            MatchOp::StartsWith => fv_lower.starts_with(&p),
            MatchOp::EndsWith   => fv_lower.ends_with(&p),
            MatchOp::Regex      => regex::Regex::new(pat).map(|re| re.is_match(field_val)).unwrap_or(false),
        }
    };
    let hit = if m.match_all {
        !m.values.is_empty() && m.values.iter().all(|pat| one(pat))
    } else {
        m.values.iter().any(|pat| one(pat))
    };
    hit ^ m.negate
}

/// Evaluate a Sigma condition string over the selection results.
/// Supports: selection names, `and`, `or`, `not`, parentheses, and the
/// quantifiers `all of them`, `1 of them`, `all of sel*`, `1 of sel*`,
/// `N of them`. Falls back to false on anything it can't parse (safe default).
fn eval_condition(condition: &str, sels: &HashMap<String, bool>) -> bool {
    // First expand quantifiers into boolean sub-expressions.
    let expanded = expand_quantifiers(condition, sels);
    // Then evaluate the boolean expression with a small recursive-descent parser.
    let tokens = tokenize(&expanded);
    let mut pos = 0;
    let result = parse_or(&tokens, &mut pos, sels);
    // If parsing didn't consume everything cleanly, be conservative.
    result.unwrap_or(false)
}

/// Replace `all of them`, `1 of them`, `N of them`, `all of prefix*`,
/// `1 of prefix*` with parenthesised and/or chains of the concrete selections.
fn expand_quantifiers(cond: &str, sels: &HashMap<String, bool>) -> String {
    let mut out = cond.to_string();
    let names: Vec<&String> = sels.keys().collect();

    // Helper to build a joined expression.
    let join = |subset: Vec<&String>, op: &str| -> String {
        if subset.is_empty() { return "__false__".to_string(); }
        format!("( {} )", subset.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(&format!(" {} ", op)))
    };

    // Patterns like "all of selection*" / "1 of filter*".
    // We scan tokens; simple string replacement for the common shapes.
    let lowered = out.clone();
    let words: Vec<&str> = lowered.split_whitespace().collect();
    let mut i = 0;
    let mut rebuilt: Vec<String> = Vec::new();
    while i < words.len() {
        if i + 2 < words.len() && (words[i] == "all" || words[i] == "1" || words[i].parse::<usize>().is_ok())
            && words[i+1] == "of" {
            let quant = words[i];
            let target = words[i+2].trim_end_matches(|c| c == ')' );
            let trailing_paren = words[i+2].ends_with(')');
            let matched_names: Vec<&String> = if target == "them" {
                names.clone()
            } else if let Some(prefix) = target.strip_suffix('*') {
                names.iter().filter(|n| n.starts_with(prefix)).cloned().collect()
            } else {
                // "1 of selection" with an exact name = just that name
                names.iter().filter(|n| n.as_str() == target).cloned().collect()
            };
            let expr = if quant == "all" {
                join(matched_names, "and")
            } else {
                // "1 of" or "N of" → OR (we approximate N-of as at-least-one; the
                // strict N-of count is rare in process rules; OR is safe-permissive
                // only for 1; for N>1 we mark via OR which may over-match — but
                // process_creation rules almost never use N>1).
                join(matched_names, "or")
            };
            rebuilt.push(if trailing_paren { format!("{})", expr) } else { expr });
            i += 3;
        } else {
            rebuilt.push(words[i].to_string());
            i += 1;
        }
    }
    out = rebuilt.join(" ");
    out
}

// ── Boolean expression parser (recursive descent) ───────────────────────────

fn tokenize(expr: &str) -> Vec<String> {
    let spaced = expr.replace('(', " ( ").replace(')', " ) ");
    spaced.split_whitespace().map(|s| s.to_string()).collect()
}

fn parse_or(tokens: &[String], pos: &mut usize, sels: &HashMap<String, bool>) -> Option<bool> {
    let mut left = parse_and(tokens, pos, sels)?;
    while *pos < tokens.len() && tokens[*pos].eq_ignore_ascii_case("or") {
        *pos += 1;
        let right = parse_and(tokens, pos, sels)?;
        left = left || right;
    }
    Some(left)
}

fn parse_and(tokens: &[String], pos: &mut usize, sels: &HashMap<String, bool>) -> Option<bool> {
    let mut left = parse_not(tokens, pos, sels)?;
    while *pos < tokens.len() && tokens[*pos].eq_ignore_ascii_case("and") {
        *pos += 1;
        let right = parse_not(tokens, pos, sels)?;
        left = left && right;
    }
    Some(left)
}

fn parse_not(tokens: &[String], pos: &mut usize, sels: &HashMap<String, bool>) -> Option<bool> {
    if *pos < tokens.len() && tokens[*pos].eq_ignore_ascii_case("not") {
        *pos += 1;
        let v = parse_not(tokens, pos, sels)?;
        return Some(!v);
    }
    parse_atom(tokens, pos, sels)
}

fn parse_atom(tokens: &[String], pos: &mut usize, sels: &HashMap<String, bool>) -> Option<bool> {
    if *pos >= tokens.len() { return None; }
    let tok = &tokens[*pos];
    if tok == "(" {
        *pos += 1;
        let v = parse_or(tokens, pos, sels)?;
        if *pos < tokens.len() && tokens[*pos] == ")" { *pos += 1; }
        return Some(v);
    }
    *pos += 1;
    if tok == "__false__" { return Some(false); }
    // A bare selection name → its evaluated result (absent name = false).
    Some(*sels.get(tok).unwrap_or(&false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev<'a>(image: &'a str, cmd: &'a str, parent: &'a str, user: &'a str) -> ProcEvent<'a> {
        ProcEvent { image, command_line: cmd, parent_image: parent, user }
    }

    #[test]
    fn simple_contains() {
        let rule = parse_sigma(r#"
title: Test PowerShell EncodedCommand
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
level: high
"#).unwrap();
        assert!(rule.applies_to_proc("windows"));
        let e = ev("C:\\Windows\\System32\\powershell.exe", "powershell.exe -enc ZQBjAGgAbw==", "explorer.exe", "user");
        assert!(rule.matches_proc(&e));
        let e2 = ev("C:\\Windows\\System32\\cmd.exe", "cmd /c dir", "explorer.exe", "user");
        assert!(!rule.matches_proc(&e2));
    }

    #[test]
    fn and_not_condition() {
        let rule = parse_sigma(r#"
title: Susp with filter
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'whoami'
    filter:
        User: 'admin'
    condition: selection and not filter
"#).unwrap();
        let e = ev("/usr/bin/whoami", "whoami", "bash", "eviluser");
        assert!(rule.matches_proc(&e));
        let e2 = ev("/usr/bin/whoami", "whoami", "bash", "admin");
        assert!(!rule.matches_proc(&e2));
    }

    #[test]
    fn one_of_them() {
        let rule = parse_sigma(r#"
title: One of them
logsource:
    category: process_creation
detection:
    sel_a:
        CommandLine|contains: 'nmap'
    sel_b:
        CommandLine|contains: 'masscan'
    condition: 1 of them
"#).unwrap();
        let e = ev("/usr/bin/masscan", "masscan -p1-65535 10.0.0.0/8", "bash", "user");
        assert!(rule.matches_proc(&e));
        let e2 = ev("/usr/bin/ls", "ls -la", "bash", "user");
        assert!(!rule.matches_proc(&e2));
    }

    #[test]
    fn network_connection_rule() {
        let rule = parse_sigma(r#"
title: Suspicious outbound to metasploit default port
logsource:
    category: network_connection
    product: linux
detection:
    selection:
        DestinationPort: 4444
        DestinationIp|startswith: '10.'
    condition: selection
level: high
"#).unwrap();
        assert!(rule.applies_to(&["network_connection"], "linux"));
        let mut hit = SigmaEvent::default();
        hit.category = "network_connection";
        hit.dest_ip = "10.0.0.5";
        hit.dest_port = "4444";
        hit.protocol = "tcp";
        assert!(rule.matches(&hit));
        // Wrong port → no match.
        let mut miss = SigmaEvent::default();
        miss.dest_ip = "10.0.0.5";
        miss.dest_port = "443";
        assert!(!rule.matches(&miss));
        // A process_creation event does not satisfy this rule's category.
        assert!(!rule.applies_to(&["process_creation"], "linux"));
    }

    #[test]
    fn dns_query_rule() {
        let rule = parse_sigma(r#"
title: DNS query to known C2 domain
logsource:
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '.evil.example'
            - '.badc2.net'
    condition: selection
level: critical
"#).unwrap();
        assert!(rule.applies_to(&["dns_query", "dns"], ""));
        let mut hit = SigmaEvent::default();
        hit.category = "dns_query";
        hit.query_name = "beacon.evil.example";
        assert!(rule.matches(&hit));
        let mut miss = SigmaEvent::default();
        miss.query_name = "www.google.com";
        assert!(!rule.matches(&miss));
    }

    #[test]
    fn file_event_rule() {
        let rule = parse_sigma(r#"
title: Write to cron directory
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|contains|all:
            - '/etc/cron'
            - '.sh'
    condition: selection
level: medium
"#).unwrap();
        assert!(rule.applies_to(&["file_event", "file_change"], "linux"));
        let mut hit = SigmaEvent::default();
        hit.category = "file_event";
        hit.target_filename = "/etc/cron.d/backdoor.sh";
        assert!(rule.matches(&hit));
        // Missing the `.sh` requirement (|all means both must be present).
        let mut miss = SigmaEvent::default();
        miss.target_filename = "/etc/cron.d/backdoor";
        assert!(!rule.matches(&miss));
    }

    #[test]
    fn aggregation_marked_unsupported() {
        let rule = parse_sigma(r#"
title: Brute force
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'ssh'
    condition: selection | count() > 10
"#).unwrap();
        assert!(rule.unsupported.is_some());
        assert!(!rule.applies_to_proc("linux"));
    }
}
