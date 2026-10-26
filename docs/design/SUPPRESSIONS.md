# NebulaSentinel — Suppressions (False-Positive Management) Design

**Status:** implemented in v28bs
**Goal:** Let analysts mark detections as false positives and create *scoped,
auditable, optionally-expiring* suppression rules so the same benign activity
doesn't re-alert — without ever creating permanent, invisible blind spots.

## Principles

1. **Suppress, don't delete.** A suppressed threat is still recorded (status =
   `suppressed`), so suppression is fully auditable. You can always see what was
   hidden and why. Nothing is silently dropped.
2. **Scoped, never global-by-accident.** Every suppression has an explicit scope:
   a single host, a host-group (by hostname prefix/pattern), or fleet-wide. The
   default the UI offers is the *narrowest* scope that fits, so one noisy server
   doesn't blind the whole fleet.
3. **Auditable.** Who created it, when, why (required justification), and what it
   has matched since. A suppression is a security decision and is treated as one.
4. **Expiring by default.** The UI defaults to a 30-day expiry with an option for
   "never" (which requires explicit selection). Expired suppressions stop matching
   and surface for review, preventing blind-spot accumulation.
5. **Evaluated at ingestion.** Suppression matching happens in `receive_atc_event`
   the moment a threat arrives: a match sets status `suppressed` and skips the
   alert notification, so the analyst's Threats feed stays clean in real time.

## Match model

A suppression matches a threat when ALL of its set (non-null) criteria match AND
the scope matches. Criteria (any subset may be set; unset = wildcard):

- `threat_name`  — exact match on the detection name (e.g. "LOLBin: mshta")
- `technique`    — MITRE technique/sub-technique id (e.g. "T1218.005"); matches if
                   present in the threat's technique list
- `process_name` — matches the process IOC / threat process (substring, lowercased)
- `ioc_value`    — matches any IOC value on the threat (exact)

Scope:
- `scope_type` = `host` | `group` | `fleet`
- `scope_value`:
  - host  → exact agent_id OR exact hostname
  - group → hostname glob/prefix (e.g. "web-*", "corp-lab")
  - fleet → ignored (matches all)

At least one *criterion* must be set (we refuse to create a suppression that
matches everything — that would be an off-switch, not a suppression).

## Data model

```sql
CREATE TABLE suppressions (
    id            TEXT PRIMARY KEY,
    threat_name   TEXT,            -- nullable criterion
    technique     TEXT,            -- nullable criterion
    process_name  TEXT,            -- nullable criterion (stored lowercased)
    ioc_value     TEXT,            -- nullable criterion
    scope_type    TEXT NOT NULL,   -- host | group | fleet
    scope_value   TEXT,            -- per scope_type (null for fleet)
    reason        TEXT NOT NULL,   -- required justification
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT,            -- null = never
    enabled       INTEGER NOT NULL DEFAULT 1,
    match_count   INTEGER NOT NULL DEFAULT 0,  -- how many threats it has caught
    last_matched  TEXT             -- timestamp of most recent match
);
```

## API surface

- `GET    /api/suppressions`              — list (with computed `active` flag)
- `POST   /api/suppressions`              — create (admin/analyst; validates
                                            ≥1 criterion, required reason)
- `DELETE /api/suppressions/:id`          — remove
- `POST   /api/suppressions/:id/toggle`   — enable/disable without deleting
- `POST   /api/threats/:id/suppress`      — convenience: from a threat, create a
                                            suppression pre-filled from that threat
                                            and retro-mark this threat suppressed

## Ingestion-time evaluation

In `receive_atc_event`, after building `ThreatRow` and before insert:
`suppression_matches(db, &row)` → if Some(supp): set `row.status =
"suppressed"`, bump that suppression's `match_count`/`last_matched`, and skip the
notification dispatch. The threat is still inserted (auditable) but never alerts.

Active = `enabled = 1 AND (expires_at IS NULL OR expires_at > now)`.

## UI

New left-nav section **Suppressions** (icon: filter-off). Shows a table of all
suppressions with: scope, criteria summary, reason, created-by/when, expiry
(with a live "expires in N days" / "expired" / "never" badge), match count, and
enable/disable + delete actions. A "New Suppression" modal with scope selector
(defaulting to the narrowest), criteria fields, required reason, and expiry
selector (30 days default).

From the **Threats** feed, each threat gets a "Suppress" action that opens the
same modal pre-filled from that threat (name, technique, process, scope=host for
that host) — the common path. Suppressed threats are filterable in the feed and
shown with a muted "suppressed" badge rather than hidden, so they remain visible
to anyone who looks.

## What this deliberately does NOT do

- It does not stop the *agent* from detecting — suppression is Nexus-side, so the
  raw detection is still recorded for audit/forensics and can be un-suppressed.
- It does not auto-create suppressions from ML/heuristics — every suppression is
  an explicit, justified human decision. (Auto-tuning suggestions could be a
  future GOSSIP/Synapse-fed enhancement, but creation stays human-gated.)

## FP-rate analytics (added after initial Suppressions ship)

A second sub-tab in the Suppressions section, **FP-Rate Analytics**, turns the
suppression signal into tuning data. FP rate = suppressed ÷ total detections,
computed per:

- **Detection name** (`threat_name`) — most actionable; identifies the specific
  noisy detection to retune or retire.
- **Engine** (`matched_rules` entries) — highlights whole noisy subsystems
  (e.g. `reputation_engine`, `baseline`).
- **MITRE technique** (`mitre_techniques` entries).

API: `GET /api/metrics/fp-rate?window=<7|30|90|all>&min=<n>`. `window` bounds the
time range (default 30 days); `min` filters out dimensions with too few
detections to be meaningful (default 2) — a 1/1 "100% FP" entry is noise, not
signal. Results are sorted noisiest-first (fp_rate desc, then total desc).

Computation lives in `db::fp_rate_report` (aggregates in Rust because
matched_rules/mitre_techniques are stored as JSON arrays). The FP signal is
`status='suppressed'`; if richer analyst verdicts (true-positive/benign) are
added later, the rate denominator/numerator can be refined without changing the
API shape.

