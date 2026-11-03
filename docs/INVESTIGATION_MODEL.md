# Investigation model — entities, pivots, cases, correlated risk

**Status:** design proposal (2026-11-02). Not yet implemented. This note
describes how to turn the Nexus from a set of parallel data tables into an
investigation surface an analyst can *flow* through, and names the storage
substrate that supports it without turning NebulaSentinel into a SIEM/log lake.

---

## 1. The problem

Today the Nexus UI is organised **by data type** — separate toolbared sections
for Threats, Detection Rules, IOCs, Forensics, Posture (Assessed Agents /
Failing Hosts), Agents, Hosts. The SQLite schema mirrors it one-to-one:
`threats`, `posture_reports`, `iocs`, `forensic_bundles`, `gossip_samples` are
parallel tables keyed by their own ids, with `agent_id` / `hostname` as loose
string links and IOCs embedded inside each `ThreatEvent`.

The data needed for an investigation is all present. What is missing is any
**join** between these tables and any **pivot** in the UI. An analyst who sees a
suspicious binary has to manually carry its hash to the IOC section, its host to
the Posture section, its technique to a mental MITRE model, and reassemble the
story in their head. The product is making the analyst be the correlation
engine. That is the clumsiness — it is structural, not cosmetic.

## 2. The model

Analysts do not think in tables; they think in **investigations that pivot
across entities**. Reorganise around that:

1. **Entities are first-class, linkable objects.** `host`, `binary` (by hash),
   `ip` / `domain`, `user`, `detection`, `ioc`. Each has a profile view that
   aggregates everything known about it *across all the current tables*.
2. **Every value is a pivot.** From any entity, one click to related entities
   (binary → hosts it ran on → network peers → users). The investigation is a
   walk across edges, not a tour of tabs. This single change removes most of the
   friction.
3. **A case is the container.** An investigation is a timeline + an entity graph
   + a running **correlated severity**. It starts from a detection and accretes
   entities as the analyst pivots.

### The scenario, mapped

> Suspicious binary (`binary` entity, keyed by hash) → pivot to its **network
> edges** → pivot to **other hosts** sharing that edge (blast radius) → **MITRE
> chain stage** + campaign cluster → each host's **posture** → **role /
> criticality** → **case risk = fuse(signal, blast_radius, asset_criticality,
> chain_stage, exposure)**, shown with its contributing factors.

Every step above is an edge-walk or a join over data NebulaSentinel already
collects (see §5). Nothing here requires new detection.

## 3. Entities and edges

An entity is a normalised thing with a stable identity. An edge is a typed,
timestamped relationship between two entities, stamped with the detection or
event that created it (its provenance). Pivots are edge-walks; correlation is
edge density.

| Entity | Identity key | Backfilled from |
|--------|--------------|-----------------|
| `host` | agent_id / hostname | `agents`, `posture_reports` |
| `binary` | file hash (sha256) | `threats.iocs` (FilePath/Hash), `forensic_artifacts` |
| `ip` / `domain` | address / fqdn | `threats.iocs` (network), `gossip_samples` |
| `user` | uid / username@host | `threats.raw_event_ids` context |
| `detection` | threat id | `threats` |
| `ioc` | type + value | `iocs` |

Edge types (not exhaustive): `ran_on` (binary→host), `connected_to`
(host→ip/host), `authenticated_as` (user→host), `triggered` (entity→detection),
`seen_on` (ioc→host), `same_campaign` (detection→detection).

## 4. Schema (SQLite now)

SQLite with recursive CTEs is sufficient for entity-graph pivots at single-node
scale — **do not reach for a graph database yet** (see §8). Minimal shape:

```sql
CREATE TABLE IF NOT EXISTS entities (
    id          TEXT PRIMARY KEY,         -- stable synthetic id
    kind        TEXT NOT NULL,            -- host|binary|ip|domain|user|detection|ioc
    natural_key TEXT NOT NULL,            -- hash, fqdn, agent_id, …
    attrs       TEXT NOT NULL DEFAULT '{}', -- JSON: role, os, reputation, …
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(kind, natural_key)
);

CREATE TABLE IF NOT EXISTS edges (
    src        TEXT NOT NULL REFERENCES entities(id),
    dst        TEXT NOT NULL REFERENCES entities(id),
    kind       TEXT NOT NULL,             -- ran_on|connected_to|…
    via        TEXT,                      -- provenance: detection/event id
    confidence REAL NOT NULL DEFAULT 1.0,
    ts         TEXT NOT NULL,
    PRIMARY KEY (src, dst, kind, ts)
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src, kind);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst, kind);

CREATE TABLE IF NOT EXISTS cases (
    id         TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'open',
    risk       REAL,                      -- correlated severity (§6)
    risk_why   TEXT,                      -- JSON: contributing factors
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_entities (
    case_id   TEXT NOT NULL REFERENCES cases(id),
    entity_id TEXT NOT NULL REFERENCES entities(id),
    added_at  TEXT NOT NULL,
    PRIMARY KEY (case_id, entity_id)
);
```

A one-hop pivot ("everything connected to this entity") is a single query; a
bounded N-hop blast-radius walk is a recursive CTE over `edges`. The same
`entities`/`edges` tables are the schema the query language and Nebula Whisper
query against — "show me everything connected to this hash" is an edge-walk
(see §9).

## 5. Backfill — no new collection

The entity/edge layer is populated from data that already exists, so it ships
with zero changes to agent telemetry:

- `threats.iocs` (each `IOC { ioc_type, value, source, confidence }`) → `binary`
  / `ip` / `domain` entities + `triggered` / `seen_on` edges.
- `threats.{agent_id, hostname}` → `host` entity + `ran_on` edge.
- `threats.mitre_techniques` / `chain` → chain-stage attribute + `same_campaign`
  edges between detections sharing techniques/infra/timing.
- `gossip_samples` → cross-host `seen_on` edges (the blast-radius signal; the APT
  module's cross-host IOC reuse already produces this).
- `posture_reports` → host `exposure` attributes.
- `HostContext` (`llm::HostContext::from_inventory` → `role`, `internet_facing`)
  → host `asset_criticality` attribute.

## 6. Correlated severity

A single detection has `confidence` and `severity`. **Incident** risk is a
*fusion* over the case, distinct from any one event:

```
case_risk = w1·signal          (detection confidence × severity weight)
          + w2·blast_radius     (# distinct hosts sharing the edge/IOC)
          + w3·asset_criticality(host role / internet_facing — HostContext)
          + w4·chain_stage      (furthest MITRE tactic reached in the case)
          + w5·exposure         (unpatched CVEs / hardening fails — posture)
```

**Non-negotiable design rules for the score:**

- **Transparent.** Always render the *why* ("3 internet-facing DB hosts,
  kill-chain at Impact, CVE-2024-xxxx unpatched"), never a bare number. Store it
  in `cases.risk_why`. A risk score analysts cannot interrogate is worse than
  none.
- **Tunable.** Weights live in `settings`, not hard-coded.
- **Not an auto-response driver by default.** A *fused* score must not trigger
  destructive playbooks on its own; destructive response stays gated by the
  per-detection confidence tiering that already governs KillProcess/Quarantine.
  Correlated risk prioritises analyst attention; it does not widen the blast
  radius of automation.

## 7. UI reorganisation

- **Collapse** the Threats / IOC / Forensics / Posture sections' per-row detail
  into **entity profile views**. The sections remain as *lists/entry points*,
  but a click opens an entity, not a modal dead-end.
- **Make every hash, IP, host, and user a pivot link** throughout the UI. This
  one change removes most of the reported clunkiness on its own.
- **Case workspace**: timeline + entity graph (simple force / columnar layout,
  rendered client-side — no graph DB needed) + the risk panel with its factors.
- Nebula Whisper gains a "start a case from this" / "add to case" action,
  consistent with its existing propose-then-confirm pattern.

## 8. Storage substrate & scaling path

The guiding principle, and the thing that keeps NebulaSentinel from degrading
into a SIEM: **the correlated-state store (entities, edges, cases, detections) is
the crown jewel and stays hot and transactional; raw events are at most an
optional, cheap, columnar *cold* tier queried on demand — never the centre of
gravity.** Product identity lives in the correlation layer, not in log volume.

**Tier A — primary state (OLTP): the entity/edge/case graph + curated
detections.**
- *Now:* **SQLite** (current). Embedded, zero-ops, recursive CTEs cover graph
  walks. Good to single-node, moderate concurrency.
- *Enterprise upgrade (multi-node Nexus, concurrent writers, HA, scale RBAC):*
  **PostgreSQL** — recursive CTEs, JSONB for `attrs`, mature ops. If true graph
  traversal ever dominates, the **Apache AGE** extension adds openCypher *on
  Postgres* — graph queries without adding a graph database. One database, not a
  zoo. (Embedded-graph alternative if ever wanted: **KùzuDB** — "DuckDB for
  graphs", Cypher, Rust-friendly — but only if traversal becomes the dominant
  workload.)

**Tier B — analytical / raw events (OLAP): only if the raw-event fork is taken
(sensor-mode ingestion, SIEM-style retro-hunt at volume).** SQLite will *not*
hold a firehose; this is a *separate* tier behind the same query surface so it
never dilutes Tier A.
- **DuckDB** — embeddable (fits the single-binary ethos), Parquet-native,
  fast analytical scans, zero-ops. The lean first choice; great for retro-hunts
  over historical events.
- **ClickHouse** — the heavyweight OSS columnar store for genuine event-scale
  analytics. More ops; the answer only at real firehose volume.
- **Parquet on object storage** (e.g. **MinIO** for on-prem S3) — cheap cold
  floor; query with DuckDB/ClickHouse.

**Tier C — ingestion pipe (only if sensor-mode / agentless firehose happens):**
- **Vector** (Rust, OSS) — telemetry/log pipeline routing; strongly aligned with
  the Rust stack and the agentless ingestion lane.
- **Redpanda** (Kafka-compatible, single-binary, no JVM) — buffer/bus if a
  durable event queue is needed. **NATS** if a lighter pub/sub fits.

**Search (Tier B-adjacent) — only if full-text log search becomes a product
goal** (consistent with *not* being a SIEM, treat as opt-in):
- **Quickwit** (Rust, object-storage-backed log search, low cost) or
  **OpenSearch** (the OSS Elasticsearch fork).

**Recommendation:** keep Tier A on SQLite now; add the entity/edge/case tables
there. Treat Postgres (+AGE if needed) as the sole enterprise upgrade for Tier
A. Add Tier B **only** when a concrete raw-event requirement lands, and prefer
DuckDB/Parquet before ClickHouse. Resist adding any Tier B/C component
speculatively — each one is ops surface that pulls the product toward "log repo"
and away from "correlation engine".

## 9. Why this is one investment, not three features

Three recent threads converge on the *same* substrate:

- **Sensor mode** (more telemetry *in*) → produces entities/edges.
- **Query language / Nebula Whisper** (*ask* questions) → queries entities/edges;
  Whisper compiles NL to the query language and shows the compiled query
  (propose-then-confirm), with the entity graph as its target schema.
- **Investigation flow** (this doc: *pivot / correlate / score*) → consumes
  entities/edges, and cases hold the correlated risk.

Building the entity + edge + case model once unlocks all three.

## 10. Sequenced rollout

Each stage ships value on its own:

1. **Entity + edge tables**, backfilled from existing `threats` / `iocs` /
   `gossip_samples` / `posture_reports` (no new collection).
2. **Entity profile views + make every value a pivot.** ← kills most of the
   clunkiness by itself.
3. **Case container** (timeline + entity list + add/remove).
4. **Correlated risk score** over the case, with its transparent "why".
5. (Later, if needed) Tier B raw-event store behind the same query surface.

## 11. Honest cautions

- **No graph DB yet.** SQLite edges + recursive CTEs are enough at this scale;
  Postgres+AGE is the upgrade if graph traversal ever dominates. A graph DB is
  ops surface you do not need today.
- **Do not overclaim attribution.** Hash-matching "same binary" is true and
  cheap. "Same *attacker*" is attribution — hard, and trust-eroding when wrong.
  Call it **campaign / cluster correlation** ("these detections share
  infrastructure / TTPs / timing"), not attacker identification.
- **Keep raw events off the critical path.** They are a cold convenience tier,
  not the product. The moment raw-log storage becomes the centre of gravity,
  NebulaSentinel is a SIEM — which is explicitly not the goal.
