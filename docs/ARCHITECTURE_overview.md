# How Nebula Sentinel Works

Nebula Sentinel is an endpoint security agent that performs **Autonomous Threat
Cognition (ATC)** — language-model reasoning that runs *on the endpoint itself*,
inside the agent, to interpret detections locally rather than shipping telemetry
to a cloud or SOC backend.

This document explains the concept and the moving parts. For building, see
[BUILDING.md](BUILDING.md); for running, see [RUNNING.md](RUNNING.md).

---

## The core idea

Endpoint security has always split into two jobs:

- **Detection** — noticing that *something* happened (a suspicious process, a file
  change, a network connection). This runs on the host.
- **Interpretation** — deciding what it *means* (real attack or benign admin
  activity?). Traditionally this happens elsewhere: a human analyst, a SIEM, or
  increasingly a cloud LLM.

Nebula Sentinel moves interpretation **onto the endpoint**. When the detection
engines fire, a local language model reasons over the correlated evidence and
produces an enriched verdict — all without the detection data ever leaving the
host. That is ATC.

### Three properties that define ATC

1. **On-device.** The model runs in the agent process, on the host's own
   hardware. Detection evidence never leaves the machine. This is what makes it
   viable in air-gapped, sovereign, and regulated environments where telemetry
   *cannot* leave.
2. **Enrichment, not a gate.** ATC does not decide whether an alert fires.
   Detections are recorded and forwarded regardless of whether ATC runs or
   succeeds. A wrong or missing verdict degrades *quality*, never causes alert
   *loss*. This is a deliberate safety property.
3. **Reasons over correlated evidence.** ATC receives the fused detection — the
   correlated signals, indicators, and host context — not a single isolated log
   line.

### What ATC is not

- **Not a detector.** ATC sits *after* detection. It cannot catch what the
  detection engines miss; it improves the quality of alerts that already fired.
- **Not a cloud service with a cache.** The reasoning genuinely runs locally.
- **Not autonomous response.** ATC reasons and enriches. Taking action is a
  separate concern (see ATR below).

---

## The pipeline

```
  Collection            Detection engines          Fusion        Cognition      Output
  ┌───────────┐      ┌──────────────────────┐    ┌────────┐    ┌─────────┐   ┌──────────┐
  │ process   │      │ behavioral (ATT&CK)  │    │        │    │  ATC    │   │ local UI │
  │ network   │─────▶│ anomaly baseline     │───▶│ corre- │───▶│ (local  │──▶│ (:7440)  │
  │ files     │      │ ransomware / APT     │    │ lation │    │  LLM    │   │ Nexus    │
  │ memory    │      │ YARA / Sigma / rep.  │    │ + fuse │    │ reason) │   │ (opt.)   │
  │ inventory │      │ DLP / NetGuard / FIM │    │        │    │         │   │ response │
  └───────────┘      └──────────────────────┘    └────────┘    └─────────┘   └──────────┘
```

1. **Collection** gathers host telemetry — process and network events, file and
   memory activity, inventory and posture.
2. **Detection engines** run in parallel: behavioral (MITRE ATT&CK mapping,
   anomaly baseline, ransomware, APT-chain), signature/intel (YARA, Sigma,
   reputation, zero-day heuristics), and data/network (DLP, NetGuard, file
   integrity monitoring).
3. **Correlation and fusion** combine engine outputs into a single verdict —
   corroborating detections raise confidence.
4. **ATC** reasons over the fused verdict with the local model and enriches it
   (adjusted confidence, an explanation). This step is enrichment; it does not
   gate the alert.
5. **Output**: every detection is recorded to the local status UI, forwarded to
   Nexus if one is configured, and — separately — may trigger a response action.

> The grouping above is conceptual. In the real code the engines corroborate
> through the fusion step rather than emitting fully independent alerts, and some
> engines (e.g. reputation) act as confidence modifiers rather than primary
> detectors.

---

## Standalone vs. fleet (Nexus)

Nebula Sentinel runs in two modes, and **Nexus is optional**:

- **Standalone.** The agent runs entirely on its own — detects, reasons locally
  with ATC, records events to the local UI, and can respond — with no server and
  no network dependency. This is the air-gapped / sovereign configuration. Set
  `nexus.enabled = false`.
- **Fleet.** The agent connects to a central **Nexus** server for fleet-wide
  visibility, rule distribution, and coordinated management. If Nexus is
  configured but temporarily unreachable, events buffer in an offline queue and
  drain when connectivity returns.

Detection, ATC, local event recording, GOSSIP, and response all function in
standalone mode. Nexus adds fleet coordination; it is not required for the agent
to protect a host.

---

## Local visibility

Every detected event is recorded to a **read-only local status UI** at
`http://localhost:7440`, bound to `127.0.0.1` only (not reachable from the
network). Events show severity, technique, confidence, and — once ATC enrichment
completes — the model's reasoning. Events are tagged:

- **Legacy** — detected without ATC enrichment (LLM unavailable / degraded).
- **ATC** — enriched with local model reasoning.

This gives on-endpoint visibility with no Nexus dependency, which is exactly what
the air-gapped case needs.

---

## GOSSIP (fleet intelligence sharing)

GOSSIP (Generative Observable Security Sharing Intelligence Protocol) is a
decentralized, gossip/epidemic-style protocol that lets agents share threat
intelligence peer-to-peer, so detection converges across a fleet.

- **Indicators of compromise (IOCs)** generated from local reasoning propagate
  freely between peers (gated by a confidence floor to avoid flooding the mesh
  with false positives).
- **Detection rules** are *proposed* from local reasoning but adopted through
  review rather than automatic fleet-wide activation.

The distinction is deliberate: facts and indicators propagate; executable logic
is gated. Gossip protocols themselves are long-established prior art; GOSSIP
applies them to on-device reasoning agents with this propagate-vs-gate
discipline.

---

## Autonomous Threat Response (ATR)

The agent contains response mechanisms — network blocking, host isolation, file
quarantine, process termination. Today these fire on **deterministic detection
confidence thresholds** gated by the agent's mode (see [RUNNING.md](RUNNING.md)),
a conventional automated-response model.

**ATR** — response driven by the *ATC reasoning itself* — is a **partially built,
deliberately unexploited capability under active research.** Local models can
produce inconsistent or empty output, and a wrong autonomous action can terminate
a legitimate process or sever connectivity, causing real impact. For that reason,
reasoning-driven response is not enabled by default and human-in-the-loop is the
recommended posture. In the ATC Capability Model, ATR corresponds to the higher
autonomy levels (ATC-4/ATC-5), which are described but not enabled by default.

---

## The ATC Capability Model (ATC-0 – ATC-5)

A maturity scale for how much interpretive autonomy an endpoint has:

| Level | Name | Cognition | Response |
|-------|------|-----------|----------|
| ATC-0 | No cognition | Signatures/rules only (legacy) | — |
| ATC-1 | Assisted interpretation | Model explains; human decides all | — |
| ATC-2 | Partial cognition | Model enriches and prioritizes | — |
| ATC-3 | Conditional autonomy | Reasons and enriches | Deterministic signals only, human-gated |
| ATC-4 | High autonomy | Reasoning drives response in bounded domains | Reasoning-driven (research) |
| ATC-5 | Full autonomy | Reasoning drives response, no human gate | Reasoning-driven (research) |

Nebula Sentinel operates at **ATC-3**: it reasons and enriches, and its response
actions fire on deterministic confidence — not on the LLM verdict. ATC-4/5 are
described by the model but deliberately not enabled (this is the ATR research
frontier).
