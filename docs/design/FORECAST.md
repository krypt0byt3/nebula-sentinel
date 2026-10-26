# Forecast / Conjecture — Design Note

**Status:** Draft for review (not yet implemented)
**Surprise finding:** Most of this already exists. The Nexus already ships a
`conjecture` module (`src/conjecture/mod.rs`), a `/api/conjecture` route, and a
"Conjecture" tab. This note documents what's there, where it falls short of the
"forecast the next TTP" vision, and how to evolve it safely — rather than building
a parallel feature.

---

## 1. What already exists (and is good)

`ConjectureEngine` takes observed TTPs and produces, per candidate threat actor, a
`ConjectureResult` containing:

- **Attribution with honest confidence** — `probability_pct`, `confidence_tier`
  (high | medium | low | speculative), and a transparent `ScoreBreakdown`
  (technique_overlap, tactic_coverage, sequence_score, recency_weight, ioc_boost,
  profile_quality). This is exactly the "show your work" honesty the feature needs.
- **`outlier_techniques`** — observed techniques that DON'T fit the group. Crucial
  for honesty: it shows where the attribution is imperfect.
- **`next_stage: Vec<NextStagePrediction>`** — already predicts what comes next,
  each with `tactic`, `techniques`, `probability`, `rationale`, `mitigations`, and
  `urgency` (immediate | hours | days).
- Actor context: aliases, origin, motivation, consistent_malware, sectors.

So the predictive engine your idea calls for is **already implemented**. The bones
are right, including the safety-conscious bits (confidence tiers, outliers,
per-prediction mitigations).

---

## 2. Gaps against the "forecast the next TTP" vision

What's missing or weak relative to what you described — and the safe-framing
concerns from our discussion:

**G1 — It's actor-first, not kill-chain-first.** The current output leads with
"which group is this" and hangs next-stage predictions off each group. Per our
discussion, that's the *seductive but dangerous* ordering — attribution from a few
techniques is unreliable, and leading with it invites the false-precision trap.
The fix isn't to remove attribution; it's to **lead with kill-chain progression**
(high-confidence, actor-independent) and present actor attribution as caveated
context beneath it.

**G2 — No fleet-wide / aggregate forecast.** The engine analyzes a supplied set of
TTPs (currently driven from a single view's techniques). There's no "across all
recent detections on this host / fleet, here's where things are heading" rollup.

**G3 — Predictions don't terminate in a defensive worklist.** Each
`NextStagePrediction` has `mitigations`, but they're per-actor-prediction. The
"so here's what to harden NOW" consolidated checklist — the thing that makes a
forecast valuable even when wrong — isn't surfaced as the headline output.

**G4 — LLM not in the loop.** This is rule/data-driven today (good for
determinism). Your vision adds LLM narration. The right role for the LLM is
*explaining and prioritizing* the rule-derived projection in plain language —
NOT inventing actor behavior. The structured engine stays the source of truth;
the LLM is the narrator grounded in it.

**G5 — Actor profile coverage.** `build_actor_profiles()` is a hand-maintained
list. Its breadth determines attribution quality. Worth knowing how many groups
it covers and whether it should be a bundled, updatable ATT&CK-groups dataset
(like Red Nebula's bundled advisory DB) rather than inline code.

---

## 3. Proposed evolution — a "Forecast" sub-tab framing

Keep the engine; reframe the *presentation* and add the consolidation layer. The
guiding principle from our discussion: **forecasts must widen the defender's view,
not narrow it.** Every projection ends in "what to watch / harden," never in
"who to blame, with false confidence."

### 3a. Reorder the output: kill-chain first, actor second

```
┌─ FORECAST (this host / fleet) ───────────────────────────────┐
│                                                               │
│  KILL-CHAIN POSITION  (high confidence — actor-independent)   │
│  Observed tactics:  Initial Access → Execution                │
│  Likely next phases: Persistence, Priv-Esc, Defense Evasion   │
│  Techniques to watch: T1547, T1053, T1055, T1027 …            │
│  ▸ each with "why" (sequence logic) + urgency                 │
│                                                               │
│  DEFENSIVE WORKLIST  (the actionable payoff)                  │
│  ☐ Audit persistence mechanisms (cron, systemd, run keys)     │
│  ☐ Review priv-esc paths (sudo, SUID, capabilities)           │
│  ☐ Deploy detections: <specific rules to synthesize>          │
│                                                               │
│  ─────────────────────────────────────────────────────────   │
│  ASSOCIATED ACTORS  (context — explicitly caveated)           │
│  ⚠ Low/Med attribution: these TTPs overlap several groups     │
│  • APT-X  (42%, medium)  matched: T1059,T1190  outliers: …    │
│  • APT-Y  (28%, low)     …                                    │
│  "Techniques observed overlap with toolsets of these groups;  │
│   this is NOT a confirmation that a specific actor is present" │
└───────────────────────────────────────────────────────────────┘
```

The kill-chain block and the defensive worklist are the **headline** — both are
high-confidence and actionable regardless of attribution accuracy. The actor block
is **below the fold**, visually subordinate, and carries an explicit caveat banner
whenever attribution confidence is below "high" (which, with a few generic
techniques, it usually will be).

### 3b. Add the consolidated defensive worklist

New aggregation over all candidate predictions: dedance the per-actor `mitigations`
+ next-stage `techniques` into ONE prioritized, deduplicated checklist sorted by
urgency. This is the artifact an operator actually uses. Bonus: each "deploy
detection" item can link into the **rule synthesis** we already built — forecast a
technique, synthesize a candidate Suricata/host rule, queue it for approval. That
closes a real loop: *prediction → pre-emptive detection.*

### 3c. Fleet + host scopes

- **Host forecast:** TTPs from one sentinel's recent detections (drives the
  per-sentinel investigation).
- **Fleet forecast:** TTPs aggregated across all recent detections — "where is the
  campaign against us heading overall." Same engine, wider input set.

### 3d. LLM narration (grounded, optional)

After the engine produces the structured forecast, optionally pass it to Whisper
to generate a 2–3 sentence plain-language brief: "Activity so far is consistent
with the early phases of an intrusion (access + execution). The most likely next
move is establishing persistence; prioritize auditing cron/systemd and deploying
the listed detections." The LLM **only narrates the structured result** — it is
given the engine's output and told to explain/prioritize, never to invent actor
behavior or techniques not in the data. If the LLM is unavailable, the structured
forecast stands on its own (graceful degradation, same as everywhere else).

---

## 4. The safety guardrails (non-negotiable, from our discussion)

1. **Lead with the kill chain, not the actor.** Attribution is context, never the
   headline.
2. **Caveat banner whenever attribution < high confidence.** Explicit text that
   overlapping TTPs match multiple groups and this is not actor confirmation.
3. **Every forecast terminates in a hardening worklist.** A prediction that ends
   in "audit X, deploy Y" is valuable even when the specific projection is wrong.
4. **Show uncertainty as a range, never a single confident call.** Multiple
   candidate next-techniques with probabilities, not "Next: T1486, 87%."
5. **Honest data provenance.** Label actor mappings as "techniques historically
   associated with these groups," not "the actor in your network is X."
6. **Name it "Forecast."** Forecast implies probabilistic ranges (like weather);
   it sets the right expectation versus "Projection" (straight-line certainty).
   Could rename the existing "Conjecture" tab to "Forecast," or keep Conjecture as
   the engine name and surface it as the Forecast tab.

---

## 5. Implementation shape (when you're ready)

Mostly evolution of existing code, not new infrastructure:

- **Engine (`conjecture/mod.rs`):** add a `kill_chain_projection()` that produces
  the actor-independent next-phase view from observed tactics + ATT&CK
  tactic-sequence logic; add a `consolidated_worklist()` that dedupes mitigations +
  watch-techniques across results into one prioritized list.
- **API:** extend `/api/conjecture` (or add `/api/forecast`) to return
  `{ kill_chain, worklist, actors }` with the actor block already confidence-sorted
  and caveated; add a `scope=host|fleet` param.
- **UI:** restructure the Conjecture tab (or new Forecast tab) into the layout in
  §3a — kill-chain + worklist headline, actors subordinate with caveat banner.
  Optionally a "Generate brief" button for the LLM narration.
- **Rule-synth bridge:** worklist "deploy detection" items call the existing
  `/api/rules/synthesize` path where the technique maps to a network/host signature.
- **Data:** review `build_actor_profiles()` coverage; consider moving to a bundled,
  updatable ATT&CK-groups dataset if breadth is thin.

---

## 6. Honest verdict

The engine you imagined largely exists and was thoughtfully built. The work isn't
"build a forecast feature" — it's **reframe the existing Conjecture feature so it
leads with high-confidence kill-chain projection and a hardening worklist, with
actor attribution demoted to caveated context.** That single reordering is the
difference between a tool that widens the defender's view (good) and one that
projects false certainty about which adversary is present (the trap). Same data,
same engine — the safety is almost entirely in presentation and emphasis.
