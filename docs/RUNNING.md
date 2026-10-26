# Running Nebula Sentinel

This guide covers running the agent — starting with the fastest path: a fully
**standalone** agent that needs no server, no cloud, and no account.

Assumes you've built the agent ([BUILDING.md](BUILDING.md)). For the concepts,
see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Quickstart: standalone in 5 minutes

Standalone mode runs the agent entirely on one host — it detects, reasons locally
with ATC, and shows you what it finds — with **no Nexus server required.** This is
the air-gapped / sovereign configuration.

**1. Create a minimal config** at `/etc/nebula/config.toml` (or anywhere, and pass
`--config`):

```toml
mode = "detect"

[nexus]
enabled = false        # ← standalone: no server needed

[llm]
enabled = true         # local ATC reasoning
mode = "local"
# model_path is optional — if omitted, a model is auto-selected by GPU VRAM.
# Download one first with:  nebula-agent --download-model
```

**2. (First run only) download a local model:**

```bash
./nebula-agent --download-model
```

**3. Run the agent:**

```bash
sudo ./nebula-agent --config /etc/nebula/config.toml
```

(Root/admin is needed for full host telemetry — process, network, file, and
memory collection.)

**4. Watch it work — open the local status UI:**

```
http://localhost:7440
```

You'll see detected events stream in live, tagged **Legacy** (detected without
ATC) or **ATC** (enriched with local model reasoning), each with severity,
technique, confidence, and — for ATC events — the model's reasoning. The UI is
read-only and bound to `127.0.0.1` only; it is not reachable from the network.

That's a complete, self-contained endpoint agent: detecting, reasoning locally,
and visible — with nothing leaving the host.

---

## Agent modes

Set with `mode` in config or `--mode` on the command line:

| Mode | Behavior |
|------|----------|
| `detect` | Detect, reason, record, and forward. **Does not take response actions.** Safe default for evaluation. |
| `protect` | Detect + enabled response actions (block, isolate, quarantine, terminate) on deterministic confidence thresholds. |
| `audit` | Observe and record only; minimal footprint. |

> Start in `detect` mode when first evaluating the agent. Only move to `protect`
> once you trust its detections on your workload — response actions have real
> consequences (blocking traffic, isolating the host). See the ATR discussion in
> [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Command-line reference

```
nebula-agent [OPTIONS]

  -c, --config <PATH>       Config file (default: /etc/nebula/config.toml)
  -m, --mode <MODE>         Override mode: detect | protect | audit
  -v, --verbose             Verbose logging
      --model <PATH|NAME>   Model to load for this run (overrides [llm] model_path).
                            A .gguf path, a directory of models, a filename in the
                            models dir, a catalog alias, or a unique fragment of a
                            filename. Env: NEBULA_MODEL
      --models-dir <DIR>    Directory models are downloaded into and loaded from
                            (default /var/lib/nebula/models). Env: NEBULA_MODELS_DIR
      --download-model      Download a local inference model, then exit
      --list-models         List the model catalog + models present locally, then exit
      --download-from-nexus Download the model from the configured Nexus
      --model-name <NAME>   Specific model to download
      --hardware-info       Print detected host hardware, then exit
      --llm-selftest        Run a local-inference self-test, then exit
```

Useful before a first run:

```bash
./nebula-agent --hardware-info    # what the agent sees about this host
./nebula-agent --llm-selftest     # confirm local ATC inference works (catches SIGILL)
```

If `--llm-selftest` crashes with `Illegal instruction`, your build's CPU baseline
is too high for this host — rebuild with `cpu-portable` (see [BUILDING.md](BUILDING.md)).

---

## Connecting to a fleet (Nexus) — optional

To manage many agents centrally, point them at a Nexus server. Enable it in
config:

```toml
mode = "detect"

[nexus]
enabled = true
url = "https://nexus.example.internal:8443"
api_key = "..."            # issued by your Nexus

[llm]
enabled = true
mode = "local"
```

With Nexus enabled, the agent registers on start, forwards detections, and polls
for distributed rules and commands. **If Nexus is temporarily unreachable, events
buffer in an offline queue and drain automatically when connectivity returns** —
detection and local ATC continue uninterrupted in the meantime.

Even in fleet mode, the local status UI at `http://localhost:7440` still shows
that host's own events.

---

## Local inference options

Under `[llm]`:

| Field | Meaning |
|-------|---------|
| `enabled` | Turn local ATC reasoning on/off. With it off, the agent runs at ATC-0 (detection only). |
| `mode` | `local` for on-device inference (the default and the point of ATC). |
| `model_path` | The local GGUF to load — a path, a directory of models, a filename in the models dir, a catalog alias, or a unique fragment of a filename. If blank/omitted, one is auto-selected by detected GPU VRAM (falling back to whatever GGUF is in the models dir). `--model` overrides it per run. |
| `model` | Model identifier to use. |
| `confidence_threshold` | Minimum confidence for ATC to act on / surface reasoning. |

Download a model with `--download-model` before the first run if you haven't
supplied `model_path`.

> **Performance note.** Sustained local inference is compute-intensive. On
> laptops it draws significant battery; on workstations and servers with
> uninterrupted power the load is more sustainable. GPU inference is generally
> more stable than CPU under sustained load.

---

## Verifying it's working

1. `http://localhost:7440` loads and shows agent status (modules, posture, mode).
2. Generate benign-but-noticeable activity on the host; events appear in the UI.
3. Events tagged **ATC** (not just Legacy) confirm local reasoning is running. If
   you only ever see **Legacy**, local inference isn't active — check `[llm]
   enabled`, that a model is present, and run `--llm-selftest`.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `Illegal instruction (core dumped)` | CPU baseline mismatch — rebuild with `cpu-portable` ([BUILDING.md](BUILDING.md)). |
| Only **Legacy** events, never **ATC** | Local inference not running — check `[llm] enabled = true`, model present, `--llm-selftest`. |
| Status UI won't load | Confirm the agent is running; the UI is `127.0.0.1:7440` only (not remote). Access it *on the host* or via an SSH tunnel. |
| No events at all | Agent likely needs root/admin for full telemetry; check it started cleanly with `--verbose`. |
| Nexus events not arriving | Check `url`/`api_key`; if Nexus is down, events queue locally and drain on reconnect. |
