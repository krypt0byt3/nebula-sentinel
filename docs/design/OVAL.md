# OVAL Integration — Design Note (v1)

## What OVAL is and why it matters here

OVAL (Open Vulnerability and Assessment Language) is a standardized XML schema for
describing machine-checkable vulnerability/configuration tests. Distros publish
OVAL feeds (Debian, Ubuntu, RHEL, SUSE) that say, precisely, "package X before
version Y on release Z is vulnerable to CVE-N." This is more precise than
NVD-CPE matching because it encodes the *distro's own* fixed-version data
(including backported fixes), which NVD often gets wrong for Linux packages.

## Current state (what already exists in the codebase)

OVAL is **partially implemented** in `nebula-agent/src/posture/mod.rs`:
- `OvalDefinition` struct (package, fixed_version, cve, severity, id).
- `check_oval(oval_dir, packages)` — scans a directory, loads definitions,
  matches against installed packages, emits `Vulnerability` records.
- Wired into `scan_vulnerabilities()` (OVAL tried first, then NVD fallback).
- Config field `oval_feed_path`; default dir `/var/lib/nebula/oval/`.

### The three gaps that make it appear "unused"
1. **No feed ingestion.** `check_oval` only reads *pre-converted JSON*
   (`Vec<OvalDefinition>`), not real OVAL XML. Nothing fetches or converts the
   distro XML feeds, so the dir is empty in practice → OVAL silently returns [].
2. **Naive version comparison.** `pkg.version.as_str() < fixed_version` is a
   lexical string compare — wrong for real versions ("1.10" < "1.9" lexically;
   epoch/revision suffixes ignored). Produces false positives and misses.
3. **No visibility.** Nothing in Nexus shows whether OVAL ran, how many defs
   were loaded, or that a vuln came from OVAL vs NVD. So the operator can't tell
   it exists.

## Proposed approach (phased, each shippable)

### Phase 1 — Make the existing path work + visible (small, low-risk)
- **Proper version comparison.** Replace the string compare with a real
  dpkg/rpm-style version compare (epoch:upstream-revision, numeric segment
  aware). This is the single highest-value fix — it makes *both* OVAL and the
  existing NVD matching more accurate.
- **Log + report OVAL status.** Emit "OVAL: loaded N definitions from M files,
  matched K vulns" and tag each OVAL-sourced `Vulnerability` with `source:
  "oval"` so the Nexus Vulnerabilities view can show provenance.
- **Seed mechanism.** Document (and add a helper) for placing converted OVAL
  JSON in the feed dir, and have the Nexus serve OVAL feeds to agents the same
  way it serves NVD/models (air-gapped fleets can't each hit distro mirrors).

### Phase 2 — Real OVAL XML ingestion (medium, the substantive piece)
- Add an **OVAL XML → OvalDefinition converter**. The OVAL schema is large, but
  we only need the `<definition>` → `<criteria>` → `dpkginfo_test`/`rpminfo_test`
  → `evr` (epoch-version-release) subset that expresses "package < fixed". Parse
  with `quick-xml` (already a common Rust dep), extract (package, fixed_evr, cve,
  severity), ignore the rest of the schema.
- Run conversion **Nexus-side** (not on every agent): Nexus downloads distro OVAL
  XML, converts to the compact JSON, and serves it. Agents just consume JSON.
  This keeps the agent small and the heavy parsing centralized.

### Phase 3 — Windows (later)
- Windows has no OVAL equivalent in common use; its vuln detection stays
  NVD-CPE-based (already working via the Nexus correlation). OVAL is a
  Linux-family enhancement. Say so explicitly so it's not a perceived gap.

## Scope decision for the FIRST build
Phase 1 only. It's self-contained, low-risk, and delivers real value (correct
version comparison helps everything), and it makes OVAL *visible* so you can
confirm it's working before we invest in XML parsing. Phase 2 (the converter) is
its own build. I will NOT attempt full OVAL XML parsing in one turn — that's how
subtle bugs get in.

## Honest caveat
OVAL's value is real but Linux-specific and feed-dependent. Without the distro
XML feeds converted and present, it produces nothing — so Phase 1's seed/serve
mechanism is what actually turns it on. The biggest *accuracy* win (version
comparison) benefits the whole vuln pipeline, not just OVAL.
