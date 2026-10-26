//! Real YARA scanning — files and process memory.
//!
//! When built with the `yara` feature (links libyara), this compiles and
//! evaluates full YARA rules: string sets, hex patterns with wildcards, regex,
//! and condition logic. Without the feature, it falls back to a lightweight
//! substring matcher so the default build still works (no C dependency).
//!
//! Two scan surfaces:
//!   - scan_file(path)        — on-disk malware (the classic AV use case)
//!   - scan_process(pid)      — in-memory / fileless malware via /proc/<pid>/mem
//!
//! YARA is the industry-standard malware-detection format; wiring the real
//! engine (not just string extraction) is what makes the agent's signature
//! detection genuinely effective against packed/obfuscated samples.

use anyhow::Result;
use std::path::Path;
use tracing::info;
#[cfg(feature = "yara")]
use tracing::{warn, debug};

/// Fallback matcher: shortest literal that counts toward a match. Literals
/// below this are too common to be evidence on their own.
const MIN_KEYWORD_LEN: usize = 6;
/// Fallback matcher: a single literal this long is specific enough to fire a
/// rule on its own; otherwise two or more qualifying literals are required.
const STRONG_SINGLE_LEN: usize = 10;

pub struct YaraScanner {
    #[cfg(feature = "yara")]
    rules: Option<yara_x::Rules>,
    /// Fallback string patterns (rule_name -> keywords) used when the real
    /// engine isn't compiled in. Far weaker than real YARA but better than nothing.
    fallback: Vec<(String, Vec<String>)>,
    rule_count: usize,
    real_engine: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]  // tags/meta populated for future use; only rule_name consumed today
pub struct YaraMatch {
    pub rule_name: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, String)>,
}

impl YaraScanner {
    /// Compile all .yar/.yara rules under `dir`. Returns a scanner that uses
    /// the real engine when available.
    pub fn compile_dir(dir: &str) -> Result<Self> {
        let path = Path::new(dir);
        let mut sources: Vec<(String, String)> = Vec::new();
        if path.exists() {
            collect_yara_sources(path, &mut sources);
        }
        info!("🧬 YARA: found {} rule file(s) in {}", sources.len(), dir);

        #[cfg(feature = "yara")]
        {
            // Compile every rule source with the pure-Rust yara-x engine.
            match Self::compile_real(&sources) {
                Ok(rules) => {
                    let n = sources.len();
                    info!("🧬 YARA: compiled {} rule files with yara-x (pure-Rust engine, no C deps)", n);
                    return Ok(Self { rules: Some(rules), fallback: Vec::new(), rule_count: n, real_engine: true });
                }
                Err(e) => {
                    warn!("🧬 YARA: yara-x compilation failed ({}); using fallback matcher", e);
                }
            }
        }

        // Fallback: extract string literals for substring matching.
        let fallback = sources.iter()
            .filter_map(|(name, src)| {
                let kws = extract_yara_strings(src);
                if kws.is_empty() { None } else { Some((name.clone(), kws)) }
            })
            .collect::<Vec<_>>();
        let n = fallback.len();
        Ok(Self {
            #[cfg(feature = "yara")]
            rules: None,
            fallback,
            rule_count: n,
            real_engine: false,
        })
    }

    #[cfg(feature = "yara")]
    fn compile_real(sources: &[(String, String)]) -> Result<yara_x::Rules> {
        // yara-x: add all sources to a Compiler, then build Rules.
        let mut compiler = yara_x::Compiler::new();
        for (name, src) in sources {
            if let Err(e) = compiler.add_source(src.as_str()) {
                // Skip individual bad rule files rather than failing the whole set.
                warn!("🧬 YARA: skipping {} (compile error: {})", name, e);
            }
        }
        Ok(compiler.build())
    }

    pub fn rule_count(&self) -> usize { self.rule_count }
    pub fn is_real_engine(&self) -> bool { self.real_engine }

    /// Scan a file's bytes. Returns all matching rules.
    #[allow(dead_code)]
    pub fn scan_file(&self, path: &str) -> Vec<YaraMatch> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        self.scan_bytes(&data)
    }

    /// Scan raw bytes (used for both files and memory regions).
    pub fn scan_bytes(&self, data: &[u8]) -> Vec<YaraMatch> {
        #[cfg(feature = "yara")]
        {
            if let Some(ref rules) = self.rules {
                // yara-x: a Scanner is created per scan from the compiled Rules
                // (cheap; avoids Sync concerns when shared via Arc).
                let mut scanner = yara_x::Scanner::new(rules);
                match scanner.scan(data) {
                    Ok(results) => {
                        return results.matching_rules().map(|r| {
                            // Capture both metadata keys AND values. yara-x metadata
                            // values are typed (string/int/bool/float/bytes); render
                            // each to a readable string so alerts can surface the
                            // rule's description/author/threat_level/reference fields.
                            let meta: Vec<(String, String)> = r.metadata().into_iter().map(|(k, v)| {
                                let val = match v {
                                    yara_x::MetaValue::String(s) => s.to_string(),
                                    yara_x::MetaValue::Bytes(b) => String::from_utf8_lossy(b.as_ref()).to_string(),
                                    yara_x::MetaValue::Integer(i) => i.to_string(),
                                    yara_x::MetaValue::Float(f) => f.to_string(),
                                    yara_x::MetaValue::Bool(b) => b.to_string(),
                                };
                                (k.to_string(), val)
                            }).collect();
                            YaraMatch {
                                rule_name: r.identifier().to_string(),
                                tags: r.metadata().into_iter().map(|(k, _)| k.to_string()).collect(),
                                meta,
                            }
                        }).collect();
                    }
                    Err(e) => { debug!("YARA scan error: {}", e); return Vec::new(); }
                }
            }
        }
        // Fallback substring matcher
        self.scan_bytes_fallback(data)
    }

    fn scan_bytes_fallback(&self, data: &[u8]) -> Vec<YaraMatch> {
        // Degraded matcher used ONLY when the real `yara` engine isn't compiled
        // in. The naive version ("all of a rule's string literals appear
        // anywhere") is a notorious false-positive source — short or common
        // literals match benign files and, worse, arbitrary process memory.
        //
        // We keep the AND-of-strings shape but require the surviving signal to
        // be SPECIFIC: only literals of at least MIN_KEYWORD_LEN bytes count,
        // and a rule fires only when it still has enough of them (either two or
        // more distinct keywords, or a single long one of STRONG_SINGLE_LEN+).
        // A rule whose literals are all short no longer fires in fallback mode —
        // it needs the real engine. This trades a little recall in the
        // non-`yara` build for far fewer spurious alerts.
        let mut hits = Vec::new();
        for (name, kws) in &self.fallback {
            let specific: Vec<&String> = kws.iter()
                .filter(|kw| kw.len() >= MIN_KEYWORD_LEN)
                .collect();
            let specific_enough = specific.len() >= 2
                || specific.iter().any(|kw| kw.len() >= STRONG_SINGLE_LEN);
            if !specific_enough { continue; }

            if specific.iter().all(|kw| {
                let needle = kw.as_bytes();
                data.windows(needle.len()).any(|w| w == needle)
            }) {
                hits.push(YaraMatch { rule_name: name.clone(), tags: vec![], meta: vec![] });
            }
        }
        hits
    }

    /// Scan a process's memory via /proc/<pid>/mem (Linux). Reads readable
    /// regions from /proc/<pid>/maps and scans each. Catches fileless malware
    /// that never touches disk.
    #[cfg(target_os = "linux")]
    pub fn scan_process(&self, pid: u32) -> Vec<YaraMatch> {
        use std::io::{Read, Seek, SeekFrom};
        let maps = match std::fs::read_to_string(format!("/proc/{}/maps", pid)) {
            Ok(m) => m, Err(_) => return Vec::new(),
        };
        let mem_path = format!("/proc/{}/mem", pid);
        let mut mem = match std::fs::File::open(&mem_path) {
            Ok(f) => f, Err(_) => return Vec::new(),
        };
        let mut all_hits = Vec::new();
        for line in maps.lines() {
            // Format: start-end perms offset dev inode pathname
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 { continue; }
            let perms = parts[1];
            // Only scan readable, non-file-backed (anonymous) or heap/stack regions
            // — that's where injected/unpacked code lives.
            if !perms.starts_with('r') { continue; }
            let region = parts.get(5).copied().unwrap_or("");
            let interesting = region.is_empty() || region == "[heap]" || region == "[stack]"
                || region.contains("rwx");
            if !interesting && !perms.contains('x') { continue; }
            let bounds: Vec<&str> = parts[0].split('-').collect();
            if bounds.len() != 2 { continue; }
            let (start, end) = match (u64::from_str_radix(bounds[0], 16), u64::from_str_radix(bounds[1], 16)) {
                (Ok(s), Ok(e)) => (s, e), _ => continue,
            };
            let size = (end - start) as usize;
            // Bound per-region read to 16MB to avoid huge allocations
            if size == 0 || size > 16 * 1024 * 1024 { continue; }
            if mem.seek(SeekFrom::Start(start)).is_err() { continue; }
            let mut buf = vec![0u8; size];
            if mem.read_exact(&mut buf).is_ok() {
                let mut hits = self.scan_bytes(&buf);
                all_hits.append(&mut hits);
            }
        }
        all_hits
    }

    #[cfg(not(target_os = "linux"))]
    pub fn scan_process(&self, _pid: u32) -> Vec<YaraMatch> { Vec::new() }
}

fn collect_yara_sources(dir: &Path, out: &mut Vec<(String, String)>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                collect_yara_sources(&p, out);
            } else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if ext == "yar" || ext == "yara" {
                    if let Ok(content) = std::fs::read_to_string(&p) {
                        out.push((p.to_string_lossy().to_string(), content));
                    }
                }
            }
        }
    }
}

/// Extract quoted string literals from YARA source for the fallback matcher.
fn extract_yara_strings(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        let l = line.trim();
        if l.starts_with('$') && l.contains(" = \"") {
            if let Some(start) = l.find('"') {
                if let Some(end) = l[start+1..].find('"') {
                    let s = &l[start+1..start+1+end];
                    if s.len() >= 4 { out.push(s.to_string()); }  // skip tiny noise
                }
            }
        }
    }
    out
}

#[cfg(all(test, not(feature = "yara")))]
mod fallback_tests {
    use super::*;

    fn scanner(fallback: Vec<(String, Vec<String>)>) -> YaraScanner {
        YaraScanner { fallback, rule_count: 0, real_engine: false }
    }
    fn rule(name: &str, kws: &[&str]) -> (String, Vec<String>) {
        (name.into(), kws.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn short_common_literals_do_not_fire() {
        // All literals below MIN_KEYWORD_LEN → rule can't fire in fallback mode.
        let s = scanner(vec![rule("r", &["cmd", "/bin", "sh"])]);
        assert!(s.scan_bytes_fallback(b"this has cmd and /bin and sh in it").is_empty());
    }

    #[test]
    fn two_specific_literals_fire_when_both_present() {
        let s = scanner(vec![rule("r", &["EvilBeacon", "c2-callback"])]);
        assert_eq!(s.scan_bytes_fallback(b"...EvilBeacon...c2-callback...").len(), 1);
        // Only one present → no fire.
        assert!(s.scan_bytes_fallback(b"...EvilBeacon only...").is_empty());
    }

    #[test]
    fn one_strong_literal_is_enough() {
        let s = scanner(vec![rule("r", &["MZ", "ThisIsAVeryUniqueMalwareString"])]);
        assert_eq!(s.scan_bytes_fallback(b"junk ThisIsAVeryUniqueMalwareString junk").len(), 1);
    }
}
