# Agent-Side Sigma Evaluation — Design Note (v1)

## The question / current status

YARA rules are evaluated on the agent (memory + on-disk file scanning). **Sigma
rules are NOT.** Verified: Nexus ingests, parses, stores, distributes, and now
OS-classifies Sigma rules — but a grep of the agent found zero Sigma evaluation.
Sigma rules currently flow through the pipeline as inert data; nothing on the
endpoint matches them against anything.

This note scopes what it would take to make Sigma rules actually *do* something on
the agent.

## What Sigma is (and why it's different from YARA)

- **YARA** matches byte/string patterns against *file or memory content*. It answers
  "does this blob contain these patterns?"
- **Sigma** is a detection format for *log/event data*. A Sigma rule describes a
  pattern over structured events — process creation, network connections, registry
  writes, auth events — via a `detection:` block with named selections and a
  `condition:` combining them. It answers "does this stream of events match this
  behavioral pattern?"

So Sigma isn't a scanner — it's an **event-matching engine**. Evaluating Sigma on
the agent means feeding the agent's own telemetry (which it already collects) through
a Sigma matcher.

## What the agent already produces (the inputs Sigma needs)

The agent already has the event sources Sigma rules target:
- **Process creation** — procmon / eBPF collector.
- **Network connections** — network_monitor.
- **File events** — FIM (inotify/FSEvents).
- **Windows events** — Event Log collection.
- **Auth / credential access** — secrets_scan, various collectors.

So the telemetry exists. The gap is a **Sigma matcher** that maps a rule's
`logsource` + `detection` to these event streams and evaluates the `condition`.

## The hard parts (why this is a real subsystem, not a wiring job)

1. **Sigma's condition grammar.** `condition:` supports `and/or/not`, `1 of them`,
   `all of selection*`, `(sel1 and sel2) or sel3`, aggregations (`count() > N`),
   and near-misses. A correct evaluator needs a small parser + evaluator for this
   mini-language. The aggregation/correlation subset is the hardest.
2. **Field mapping.** Sigma field names (e.g. `Image`, `CommandLine`,
   `TargetFilename`, `DestinationIp`) follow Sysmon/Windows conventions. Mapping
   them to the agent's own event field names (especially on Linux) requires a
   translation layer — this is exactly what "Sigma backends" do in the ecosystem.
3. **Match modifiers.** `contains`, `startswith`, `endswith`, `re` (regex),
   `base64`, `|all` — each selection value can carry modifiers that change matching
   semantics.
4. **logsource routing.** A rule's `logsource.category` (process_creation,
   network_connection, file_event…) determines which event stream it applies to.

## Proposed approach (phased)

### Phase 1 — Core matcher for the highest-value category (process_creation)
- Parse Sigma YAML into a typed structure (title, logsource, detection map,
  condition string).
- Implement a condition evaluator for the COMMON subset: `and/or/not`, `1 of`,
  `all of`, `N of`, parenthesization. Defer aggregations (`count()`) to a later
  phase — flag rules that use them as "unsupported" rather than silently
  mis-evaluating.
- Implement match modifiers: `contains/startswith/endswith/re` + case handling.
- Field-map for `process_creation` (Image, CommandLine, ParentImage, User) to the
  agent's process events, with a Linux/Windows field-name translation table.
- Wire the procmon/eBPF process event stream through the matcher; a match emits a
  ThreatEvent (same path as YARA/FIM hits → ATC → Nexus).

### Phase 2 — More categories
- network_connection (→ network_monitor), file_event (→ FIM), registry_event
  (Windows). Each is another field-map + stream wiring; the matcher core is reused.

### Phase 3 — Aggregations / correlation
- `count() by X > N` style rules need windowed state. This is the correlation
  engine subset — significant, deferred until the stateless matcher is proven.

## Scope decision
This note is scoping only — no implementation yet. Phase 1 alone is a meaningful
build (parser + condition evaluator + modifiers + one category wired). It should be
its own focused effort with careful validation, because a detection engine that
silently mis-evaluates is worse than none (false confidence). Recommend building it
only after deciding it's worth the surface area vs. leaning on YARA + behavioral/ATC
for now.

## Honest assessment / recommendation
- Sigma evaluation is genuinely valuable — it's the standard behavioral-detection
  format and there's a huge public rule corpus (SigmaHQ). Making the agent evaluate
  it turns that corpus into live detection.
- But it's the **largest** single new subsystem discussed so far (a mini
  language + field mapping + multi-stream wiring), and doing it *badly* creates
  false confidence. It deserves its own multi-build effort with real sample-rule
  validation, not a rushed pass.
- Interim value already delivered: OS-classification (this build) ensures that once
  Sigma evaluation exists, Windows Sigma rules only go to Windows agents — so the
  distribution side is ready and waiting.
- Suggested trigger to build: when you want the agent to act on the SigmaHQ corpus
  directly rather than translating select Sigma rules into YARA/custom rules by hand.
