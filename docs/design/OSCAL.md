# OSCAL Auto-Assessment — Design Note (v1)

## What OSCAL is and the goal

OSCAL (Open Security Controls Assessment Language) is NIST's machine-readable
format for security control catalogs (e.g. SP 800-53 Rev 5), profiles/baselines,
and assessment results. The goal here: import a NIST catalog, automatically
assess which controls the fleet satisfies (from real agent posture/hardening
data), and export standards-shaped OSCAL assessment-results — i.e. a real,
evidence-backed compliance report rather than a checklist someone fills in by
hand.

## Current state (already substantially built)

`nexus-server/src/oscal/mod.rs` (~530 lines) already implements:
- **Catalog ingestion** — parse an OSCAL catalog JSON (SP 800-53), store controls
  (`ingest_catalog`, `oscal_catalogs`/`oscal_controls` tables). Handles wrapped
  and bare catalog forms; rejects profiles with a helpful message.
- **Control→check mappings** — `oscal_mappings` table + `builtin_mappings()` (~67
  curated pairs), seeded idempotently at startup.
- **Auto-assessment** — `assess_fleet()` rolls up each control's mapped checks
  against the latest hardening results across all agents → satisfied /
  not-satisfied / partially-satisfied / not-assessed, with failing hosts.
- **Results export** — `build_assessment_results()` emits an OSCAL
  assessment-results document.
- **API + routes** — import, list controls, assess, export, manage mappings.

So the engine exists and is sound. Why it "has no use":

### The gaps
1. **A catalog must be imported first** (manual). With no catalog, there are no
   controls to assess → empty. Needs a clear in-UI path + ideally a Nexus-served
   default NIST catalog.
2. **Mappings are Linux-only.** The 67 built-in mappings use Linux check IDs
   (`sshd:*`, `sysctl:*`, `svc:*`). The Windows STIG items produce IDs like
   `reg:System\EnableLUA` and `account:guest` — NONE are mapped. So a Windows
   fleet gets 0 coverage: every control shows "not-assessed."
3. **Discoverability.** The OSCAL sub-tab doesn't guide the operator to
   import → assess → export, so it reads as inert.

## Proposed approach (phased)

### Phase 1 — Windows STIG → NIST mappings + status alignment (small, high-value)
Add built-in mappings from the Windows STIG check IDs (from hardening/windows.rs)
to their NIST 800-53 controls. Each Windows STIG control already cites its NIST/CIS
basis; e.g.:
- `reg:System\EnableLUA` (UAC) → AC-6 (Least Privilege) / CM-7
- `reg:Lsa\RunAsPPL` (LSASS PPL) → SC-39 / IA-5
- `account:guest` (guest disabled) → AC-2 (Account Management)
- SMBv1 disabled → CM-7 (Least Functionality) / SC-7
- PowerShell ScriptBlockLogging → AU-2 / AU-12 (Audit)
- WDigest disabled → IA-5 (Authenticator Management)
This makes a Windows fleet actually assessable against NIST. Verify the agent's
ComplianceStatus serialization ("pass"/"fail", snake_case) matches assess_fleet's
expectations (it does).

### Phase 2 — Catalog seeding + UI guidance (medium)
- Nexus ships/serves a default SP 800-53 Rev5 catalog (or a one-click "download
  from usnistgov/oscal-content" fetch), so the operator doesn't hunt for JSON.
- OSCAL sub-tab: a clear 3-step affordance (Import catalog → Run assessment →
  Export results), with the current assessment KPIs front and centre.

### Phase 3 — Deeper mapping coverage (ongoing)
- Expand mappings beyond the hardening checks to vuln/FIM/config signals, so more
  of the 1000+ controls get real evidence instead of "not-assessed".

## Scope for THIS build
Phase 1 only: add the Windows STIG→NIST mappings so Windows fleets get real OSCAL
coverage, and confirm status alignment. Self-contained, low-risk, directly fixes
"OSCAL has no use" for the Windows systems the operator is testing. Phases 2–3 are
their own builds.

## Honest caveat
Auto-assessment is only as good as the mappings and the evidence. It legitimately
assesses controls that map to a concrete agent check; it will honestly report
"not-assessed" for controls with no automatable evidence (much of 800-53 is
policy/process, not machine-checkable). The report should make that distinction
clear rather than implying full coverage.
