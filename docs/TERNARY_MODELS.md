# Ternary (1.58-bit) Models on NebulaSentinel

Status: 2026-10 — practical guide to running ternary ATC models on the engine
the fleet already ships. Supersedes the "ternary = BitNet.cpp fork only"
assumption baked into the earlier `sentinel_v2 --features bitnet` work.

## TL;DR

There are now **two** ways to run ternary weights, and they use **different
engines**:

| Format (ggml type) | Example models | Engine that loads it | NebulaSentinel path |
|---|---|---|---|
| `TQ1_0` / `TQ2_0` (34/35) | TriLM, BitNet-b1.58 re-quants, **TQ2_0 Bonsai conversions** | **stock llama.cpp** (upstream PR #8151) | default `embedded-llm` agent **and** Nexus `llama-server` — **no fork** |
| `I2_S` / `TL1` / `TL2` (36/37/38) | Microsoft `BitNet-b1.58-2B-4T`, TII Falcon3 `-i2_s` | bitnet.cpp **fork** | `sentinel_v2 --features bitnet` only |
| PrismML native `PQ2_0` (group-128) | Bonsai 2 *native* GGUFs | PrismML's llama.cpp **fork** | not integrated (see below) |

**Upshot:** you do **not** need a new engine to run strong ternary models.
Stock llama.cpp reads `TQ1_0`/`TQ2_0` natively, and the agent + Nexus already
embed stock llama.cpp (`llama-cpp-2` ≥ 0.1.x). The GGUF engine-router
(`nexus-server/src/gguf/mod.rs`) now classifies `TQ*` as `engine = "llama.cpp"`
and only the fork-only `I2_S`/`TL*` formats as `engine = "bitnet"`, so a default
agent will accept a TQ2_0 model and refuse an I2_S one it can't decode.

## Why this matters

Our own `sentinel_v2` ATC self-test (`BITNET_QUICKREF.md §8`) found the *engine*
was correct but every ternary model we tried (Falcon3 3B/7B/10B i2_s, BitNet-2B)
scored **0% specificity** — it flagged every benign event as malicious. Those
were weak, from-scratch 1.58-bit models. The newer class — **Bonsai 2**
(PrismML), ternary quantizations of **Qwen3** retaining a reported ~98% of the
parent — is a different proposition, and adds vision + tool-calling. The point
of this doc is to let you *evaluate that claim on our own harness cheaply*,
before committing to any engine integration.

## Step 1 — Benchmark before you integrate (cheap, no code)

Run a candidate ternary model through the existing ATC self-test over an HTTP
`llama-server`, exactly like the managed Nexus tier. No agent rebuild needed.

```bash
# A TQ2_0 model that stock llama.cpp can serve (community Bonsai conversion, or
# any BitNet-b1.58 re-quantized to TQ2_0 — see Step 3). Example placeholder:
MODEL=/var/lib/nebula/models/Bonsai-TQ2_0.gguf

# Stock llama-server (the same binary the Nexus manages):
llama-server --model "$MODEL" --host 127.0.0.1 --port 8081 --ctx-size 8192 &

# Point the self-test harness at it and compare specificity to the 0% baseline:
sentinel-v2 --atc-test --atc-endpoint http://127.0.0.1:8081
```

Decision rule: if specificity is still near-zero, **stop** — ternary isn't ready
for ATC verdicts and the Falcon3 conclusion stands. If it jumps (say >70%),
proceed to Step 2.

## Step 2 — Serve it fleet-wide from the Nexus (low effort)

The Nexus already manages a `llama-server` child process
(`nexus-server/src/llm/mod.rs`) and distributes models to agents over the ATC
channel. To serve a TQ2_0 ternary model to the whole fleet:

1. Drop the `.gguf` where the Nexus serves models and point `[llm] model_path`
   at it (or `nexus-server --download-model <repo-or-url>`).
2. Restart / hot-reload. `/api/atc/models` will advertise it with
   `engine: "llama.cpp"` and `ternary: true` (verified by the GGUF header
   reader, not the filename).
3. Agents calling `--download-from-nexus` now auto-select it: a default
   (stock) agent accepts `engine: "llama.cpp"` models (incl. TQ ternary) and
   **skips** any `engine: "bitnet"` model it cannot load
   (`llm::download_model_from_nexus`).

No fork, no new binary — this is the recommended adoption path.

## Step 3 — Producing a TQ2_0 GGUF yourself

If you have a ternary/BitNet HF checkpoint but no TQ2_0 GGUF:

```bash
# From a llama.cpp checkout (stock upstream):
python convert_hf_to_gguf.py <hf_model_dir> --outtype tq2_0 --outfile model-f16.gguf
./llama-quantize model-f16.gguf model-TQ2_0.gguf TQ2_0
```

`TQ2_0` (2.06 bpw) is faster than `TQ1_0` (1.69 bpw) because it keeps 2-bit
alignment; prefer it unless RAM is the hard constraint.

## What is NOT done (and the tradeoff)

**Bonsai 2's *native* format** (PrismML's group-128 `PQ2_0` + a Hadamard
activation transform) is **not** loadable by stock llama.cpp or bitnet.cpp — it
needs PrismML's own llama.cpp fork. Two consequences:

- The easy path above uses a **TQ2_0 conversion** of a Bonsai/Qwen3-ternary
  model (community-converted or self-converted), which trades a little of
  PrismML's claimed quality for running on the engine we already ship.
- Integrating PrismML's fork for the *native* format is a real cost: in the
  **embedded agent** it collides with the existing engines (bitnet.cpp and
  stock llama.cpp both export the same `llama_*`/`ggml_*` symbols — see the
  `compile_error!` guard in `sentinel_v2/src/llm/bitnet.rs`), so a *second* fork
  can only live behind its own mutually-exclusive feature, or as an out-of-process
  `llama-server` sidecar (the lower-risk option — the Nexus tier already works
  this way). Defer it until Step 1 proves the quality is worth it, and prefer
  the sidecar over static-linking a third fork into the agent.

## References

- llama.cpp ternary types (TQ1_0/TQ2_0): ggml-org/llama.cpp PR #8151.
- PrismML Bonsai 2 (27B + 2B/4B/9B), Apache-2.0: https://prismml.com/news/bonsai-2-27b
- Native-format discussion (group-128, not upstream): ggml-org/llama.cpp Discussion #22019.
- Our engine router + routing tests: `nexus-server/src/gguf/mod.rs`.
- Our ternary-engine benchmark conclusion: `sentinel_v2/BITNET_QUICKREF.md §8`.
