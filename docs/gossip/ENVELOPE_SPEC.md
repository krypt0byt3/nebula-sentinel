# GOSSIP Protocol — Ecosystem Envelope & ATC Event Specification

**Status:** Draft v1
**Scope:** The canonical message format spoken by every NebulaSentinel ecosystem
component — Nebula Agents, Cortex, Dopamine, Nexus, Red Nebula, and Synapse.

The goal: one envelope, many transports. A honeypot hit, a host detection, a
network flow alert, and a cross-customer advisory all produce **structurally
identical** messages that any component can parse, verify, correlate, and act on.
Transport varies by relationship; the language does not.

---

## 1. Design principles

1. **Transport-agnostic envelope.** The same JSON envelope rides over agent↔agent
   UDP, the Nexus poll cycle, and Synapse's cross-customer channel. Components
   never special-case "where did this come from" to parse it.
2. **Provenance is mandatory, not optional.** Every message carries who
   originated it, who relayed it, and how many independent sources have seen it.
   This is the foundation of trust and the defense against injection.
3. **Signed at origin.** The originator signs the envelope. Relayers add their own
   signed relay record. A receiver can always answer "who actually said this?"
4. **Idempotent by ID.** Every message has a stable ID and a dedup key so the same
   indicator seen 50 times produces one logical record, not 50.
5. **TTL everywhere.** Intelligence ages out. No indicator lives forever without
   re-affirmation.
6. **Backward-compatible evolution.** The current agent `GossipMessage`
   (`from_agent`, `from_hostname`, `timestamp`, `msg_type`, `payload`) maps onto
   the new envelope's core fields — this is an extension, not a rewrite.

---

## 2. The envelope

Every GOSSIP message, from any component, has this shape:

```jsonc
{
  // ── Identity ────────────────────────────────────────────────
  "schema": "gossip/1",              // envelope schema version
  "msg_id": "01J9Z3K8...ULID",       // globally unique, time-sortable (ULID/UUIDv7)
  "msg_type": "ioc.alert",           // see §3 message taxonomy
  "dedup_key": "ioc:sha256:abcd...", // stable key for collapsing duplicates

  // ── Provenance ──────────────────────────────────────────────
  "origin": {
    "component": "nebula-agent",     // agent | cortex | dopamine | nexus | red-nebula | synapse
    "id": "agent-7f3a...",           // stable component instance ID
    "tenant": "customer-acme",       // isolation boundary (null for single-tenant)
    "site": "dc-east"                // optional logical location
  },
  "relays": [                        // appended each hop; empty if direct
    { "component": "nexus", "id": "nexus-01", "ts": "2026-06-19T15:04:05Z", "sig": "..." }
  ],
  "corroboration": {
    "independent_sources": 3,        // how many distinct origins reported this dedup_key
    "first_seen": "2026-06-18T22:10:00Z",
    "last_seen":  "2026-06-19T15:04:05Z"
  },

  // ── Trust ───────────────────────────────────────────────────
  "confidence": 85,                  // 0–100, origin's confidence
  "severity": "high",                // info | low | medium | high | critical
  "ttl_secs": 86400,                 // after this, receivers should expire it
  "sig": {
    "alg": "ed25519",
    "key_id": "agent-7f3a-2026",     // which key signed (rotation-friendly)
    "value": "base64..."             // signature over canonical envelope (minus sig)
  },

  // ── Timing ──────────────────────────────────────────────────
  "created_at": "2026-06-19T15:04:05Z",

  // ── Payload (shape determined by msg_type) ──────────────────
  "payload": { /* see §3 */ }
}
```

### Field notes

- **`msg_id`** — use ULID or UUIDv7 so IDs sort by time; helps ordering without a
  clock-sync dependency.
- **`dedup_key`** — the collapse key. For an IOC it's `ioc:<type>:<value>`; for an
  ATC alert it's `atc:<agent>:<rule>:<entity>`. Two messages with the same
  dedup_key are the same logical fact; receivers merge them and bump
  `corroboration`.
- **`origin.tenant`** — the hard isolation boundary. Synapse MUST sanitize and
  may only cross tenants for explicitly shareable indicator types (see §6).
- **`relays`** — each relayer appends a signed record. This is how a receiver
  detects "this came through a path I don't trust" and how you trace poisoning.
- **`sig`** — signature over the canonical (sorted-key, relay-and-sig-excluded)
  serialization. Receivers verify against the origin's known public key.

---

## 3. Message taxonomy

`msg_type` is a dotted namespace: `<domain>.<kind>`. Core set:

| `msg_type`            | Emitted by                | Meaning |
|-----------------------|---------------------------|---------|
| `ioc.alert`           | any                       | A shareable indicator (hash/IP/domain/etc.) |
| `ioc.false_positive`  | nexus, agent              | Retraction: this IOC is benign, stop acting on it |
| `atc.observable`      | agent, cortex, dopamine   | Low-fidelity observation, not a threat (your "ATC Events") |
| `atc.alert`           | agent, cortex, dopamine   | High-fidelity confirmed threat (your "ATC Alerts") |
| `atc.health`          | any component             | Liveness/operational status (your "ATC Health check") |
| `reputation.score`    | agent, cortex             | Entity reputation update (IP/host/user risk) |
| `peer.seen`           | agent, cortex, dopamine   | Peer sighting (topology/mesh membership) |
| `rule.proposal`       | agent, dopamine           | Suggested detection rule for Nexus approval |
| `intel.advisory`      | synapse, nexus            | Curated, distributed intelligence (Nexus→fleet / cross-customer) |
| `sample.available`    | agent, dopamine           | A captured sample is available for pull |

The **payload schema is keyed to `msg_type`** — §4 and §5 define the two that
matter most: the IOC payload and the ATC payloads.

---

## 4. The IOC payload (shared schema)

Used by `ioc.alert`, `ioc.false_positive`, and embedded in advisories. This is the
single IOC schema every component uses — the thing that makes a Dopamine hit and
an agent detection look identical on the wire.

```jsonc
"payload": {
  "ioc_type": "sha256",        // md5|sha1|sha256|ipv4|ipv6|domain|url|file_path|process_name|registry_key|yara_rule|ja3|user_agent|email
  "value": "abcd1234...",
  "context": {                 // optional, why this is an IOC
    "malware_family": "Emotet",
    "campaign": null,
    "mitre_techniques": ["T1059.001"],
    "description": "C2 beacon hash observed by honeypot",
    "kill_chain_phase": "command-and-control"
  },
  "enforcement": {             // what receivers MAY do — advisory, not mandatory
    "recommended_action": "block",   // observe | alert | block | quarantine
    "auto_enforce": false,           // may a receiver act WITHOUT human review?
    "scope": "same_tenant"           // same_host | same_tenant | ecosystem
  }
}
```

The `enforcement` block is critical for the trust model: an indicator can *suggest*
"block," but `auto_enforce: false` means a human (or the Nexus policy) must approve
before it takes blocking action. Cross-tenant/Synapse-distributed IOCs default to
`auto_enforce: false`.

---

## 5. ATC events — the three fidelity tiers

Your model (Observables / Alerts / Health) is exactly right. Mapping it to the
envelope: all three are `atc.*` message types sharing one payload shape with a
`tier` discriminator. This keeps ATC reporting consistent across agent, Cortex,
and Dopamine — they all emit the same structure.

### 5a. ATC Observable — `atc.observable`

Low-fidelity, "noticed but not alarming." New process hash, first-seen binary,
unusual-but-benign connection. High volume, low severity. These build the baseline
and provide correlation fuel, but don't page anyone.

```jsonc
{
  "schema": "gossip/1",
  "msg_id": "01J9Z...",
  "msg_type": "atc.observable",
  "dedup_key": "atc:agent-7f3a:new_process_hash:/usr/bin/foo",
  "origin": { "component": "nebula-agent", "id": "agent-7f3a", "tenant": "customer-acme" },
  "confidence": 40,
  "severity": "info",
  "ttl_secs": 604800,
  "created_at": "2026-06-19T15:04:05Z",
  "payload": {
    "tier": "observable",
    "category": "new_process_hash",
    "entity": { "type": "process", "name": "foo", "path": "/usr/bin/foo", "pid": 4412 },
    "observation": "First time this SHA-256 has executed on this host.",
    "evidence": {
      "sha256": "abcd...",
      "parent": "/usr/bin/bash",
      "user": "deploy",
      "signed": false
    },
    "detector": { "engine": "baseline", "rule": null, "source": "atc" },
    "disposition": "benign"        // benign | unknown | suspicious
  }
}
```

### 5b. ATC Alert — `atc.alert`

High-fidelity, confirmed or high-probability threat. Low volume, high severity.
These page, correlate, and may trigger response.

```jsonc
{
  "schema": "gossip/1",
  "msg_id": "01J9Z...",
  "msg_type": "atc.alert",
  "dedup_key": "atc:agent-7f3a:T1055:pid-4412",
  "origin": { "component": "nebula-agent", "id": "agent-7f3a", "tenant": "customer-acme" },
  "confidence": 92,
  "severity": "high",
  "ttl_secs": 2592000,
  "created_at": "2026-06-19T15:04:05Z",
  "payload": {
    "tier": "alert",
    "category": "process_injection",
    "threat_name": "Reflective code injection into systemd",
    "entity": { "type": "process", "name": "systemd", "pid": 1, "injected_by_pid": 4412 },
    "mitre": { "tactics": ["TA0004"], "techniques": ["T1055"] },
    "evidence": {
      "raw_event_ids": ["ev-91a2", "ev-91a3"],
      "ptrace_target": 1,
      "memory_region": "rwx anonymous mapping"
    },
    "detector": { "engine": "ebpf+rules", "rule": "rule-injection-001", "source": "atc" },
    "iocs": [ { "ioc_type": "sha256", "value": "abcd..." } ],
    "suggested_action": { "recommended_action": "quarantine", "auto_enforce": false },
    "llm_analysis": "ATC enrichment: behavior consistent with...",  // null if no LLM
    "disposition": "malicious"
  }
}
```

Note `detector.source`: `"atc"` when the local LLM enriched it, `"legacy"` when
it's raw detector output (this is the ATC-vs-Legacy distinction, now first-class
in the protocol rather than a UI-only inference).

### 5c. ATC Health — `atc.health`

Liveness and operational validation. Every component emits this on a heartbeat so
the Nexus knows the fleet's cognition layer is actually working — including whether
the LLM is up, the collector backend in use, and detection rates. This is how you
catch "the agent went quiet" or "ATC degraded to legacy mode."

```jsonc
{
  "schema": "gossip/1",
  "msg_id": "01J9Z...",
  "msg_type": "atc.health",
  "dedup_key": "atc:health:agent-7f3a",
  "origin": { "component": "nebula-agent", "id": "agent-7f3a", "tenant": "customer-acme" },
  "confidence": 100,
  "severity": "info",
  "ttl_secs": 120,                 // short — a stale health msg means "gone dark"
  "created_at": "2026-06-19T15:04:05Z",
  "payload": {
    "tier": "health",
    "status": "healthy",           // healthy | degraded | unhealthy
    "uptime_secs": 84213,
    "cognition": {
      "llm_available": true,       // is ATC (LLM) actually running?
      "llm_model": "qwen2.5-7b",
      "mode": "atc"                // "atc" (LLM enriching) | "legacy" (raw only)
    },
    "collector": { "backend": "ebpf", "events_per_min": 1240 },  // or "procmon"
    "detection": { "alerts_last_hour": 3, "observables_last_hour": 410 },
    "queues": { "offline_backlog": 0 },
    "version": "0.4.0"
  }
}
```

The short `ttl_secs` (120) is deliberate: the absence of a fresh `atc.health` is
itself the signal. If the Nexus hasn't seen one in 2× the interval, the component
is presumed dark and you alert on *silence* — the failure mode that silent agents
otherwise hide.

---

## 6. Transport & trust rules per relationship

Same envelope, different transport and different default trust by edge:

| Edge | Transport | Default `auto_enforce` | Notes |
|---|---|---|---|
| Agent ↔ Agent | UDP gossip (peer-to-peer) | false | Epidemic spread; survives Nexus outage. Signed; receivers verify peer keys. |
| Agent → Nexus | HTTPS (existing report path) | — | Telemetry. Nexus is collector + correlator. |
| Nexus → Fleet | **Poll cycle** (pull, not broadcast) | policy-controlled | Authoritative distribution. NOT UDP broadcast (avoids fleet-wide blast radius). |
| Dopamine → Nexus/Cortex | HTTPS | false | Honeypot intel; high value but treat as untrusted-source until corroborated. |
| Cortex ↔ Nexus | HTTPS | policy-controlled | Cortex is a bidirectional peer: contributes network IOCs, consumes host IOCs to enforce inline. |
| Red Nebula → Nexus/Cortex | HTTPS | false | Assessment findings; informational, rarely auto-enforce. |
| Synapse ↔ Nexus | HTTPS (cross-customer) | **always false** | Cross-tenant. Mandatory sanitization (§6a) + customer-side validation before enforcing. |

### 6a. Cross-tenant sanitization (Synapse)

Before any indicator crosses a tenant boundary via Synapse:
- Strip internal-only context (internal hostnames, RFC1918 IPs, usernames, paths).
- Only `ioc_type` values on an allow-list may cross (hashes, public IPs, public
  domains, YARA, JA3 — NOT file paths, process names, internal identifiers).
- Re-sign as Synapse with `origin.component = synapse`; preserve the original
  origin in `corroboration` as count, not identity.
- `auto_enforce` forced to `false`; receiving tenant decides enforcement.

---

## 7. Does the Nexus-as-hub mean integrations for everything?

Short answer: **yes, but only one integration each, against this spec — not N²
point-to-point integrations.** That's the payoff of the shared envelope.

Each component implements exactly two things:
1. **Emit** GOSSIP envelopes for its events (sign + send to the bus/Nexus).
2. **Consume** envelopes relevant to it (verify + act per its role).

Cortex consumes `ioc.alert` to enforce inline; Red Nebula consumes `atc.alert` and
`intel.advisory` to expand its test corpus; Dopamine emits `atc.alert` +
`ioc.alert`; Synapse consumes everything shareable and re-emits sanitized
`intel.advisory`. Because they all speak one envelope, adding a new component is
*one* adapter, not one-per-existing-component. The Nexus is the hub that
normalizes, correlates, de-duplicates by `dedup_key`, and re-distributes — so
intelligence has a single source of truth instead of diverging across direct
links.

---

## 8. What this buys you

- **Correlation:** one `dedup_key` namespace means the Nexus can stitch a Dopamine
  hit + an agent alert + a Cortex flow into one incident automatically.
- **Trust:** signing + provenance + corroboration counts make injection detectable
  and poisoning traceable/revocable.
- **Consistency:** ATC events look the same whether they come from an agent, Cortex,
  or Dopamine — exactly the ecosystem consistency you're after.
- **Resilience:** gossip stays peer-to-peer (survives Nexus down); distribution
  stays pull-based (no broadcast blast radius).
