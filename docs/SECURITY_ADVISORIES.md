# Dependency security advisories (RUSTSEC) — triage

`cargo audit` runs in CI (`.github/workflows/ci.yml`). This file records the
triage decision for every advisory it reports, so the audit signal is actionable
rather than noise. Last triaged: **2026-10-29**.

## ✅ Fixed (within-range patch bumps, `cargo update --precise`)

These were plain patch bumps inside the existing semver ranges — no manifest
change, verified by CI build + tests:

| Crate | Was → Now | Advisories cleared | Impact |
|-------|-----------|--------------------|--------|
| `rustls` | 0.23.43 → 0.23.46 | RUSTSEC-2026-0348, -0349, -0346, -0285 | Pre-auth 1 GiB alloc (DoS), classical-KEX downgrade, TLS secrets in `Debug`, handshake level-crossing |
| `rustls-webpki` | 0.103.13 → 0.103.16 | RUSTSEC-2026-0382 | Certificate verification may accept distrusted intermediates |
| `quinn-proto` | 0.11.17 → 0.11.18 | RUSTSEC-2026-0343, -0340, -0338 | Three **remote-peer-can-panic** DoS bugs (datagram accounting, ACK-delay, zero-length STREAM frames) |

The `quinn-proto` panics are a direct resilience win: a remote peer could crash
the QUIC endpoint. The `rustls` fixes harden the agent↔Nexus TLS channel.

## ⏳ Deferred — need a review (NOT auto-bumped)

These require a major/transitive bump that could change behavior, so they are
deliberately left for a reviewed change rather than an unattended one:

- **`wasmtime` 43.0.2 (many advisories: RUSTSEC-2026-0379, -0316, -0222, -0327,
  -0362, -0269, -0359, -0363, …).** Pulled transitively by `yara-x` (which
  compiles YARA rules to WASM). The fixed ranges skip 43.x (they are `<37` or
  `>=48`), so the only fix is bumping `yara-x` to a release that depends on
  wasmtime 48+/49+ — a major transitive change that must be validated against
  YARA scanning behavior. **Reachability is low**: in `yara-x` the WASM modules
  are generated from *operator-authored* YARA rules, not attacker-controlled
  input, so the sandbox-escape / malicious-module advisories do not map to a
  realistic attacker path here. `nebula-agent/Cargo.toml` already documents an
  earlier deliberate `yara-x` 0.13→1 bump done specifically to move off an older
  vulnerable wasmtime; the next bump belongs in that same managed lane.
  → **Action:** bump `yara-x` when a release targeting wasmtime ≥48 is available;
  re-run the YARA scan tests.

- **`crypto-bigint` 0.5.5 → needs ≥0.7.6 (RUSTSEC-2026-0387, constant-time
  variability).** A major (0.5→0.7) transitive bump; cannot be done within range.
  → **Action:** track upstream (arrives when the pulling crate updates).

- **`rsa` 0.9.10 (RUSTSEC-2023-0071, Marvin timing side-channel).** **No fixed
  upgrade is available** from upstream. Transitive. → **Action:** monitor for a
  fixed release; assess whether the pulling dependency can drop `rsa`.

## How to re-triage

```sh
cargo install cargo-audit --locked   # once
cargo audit                          # from the workspace root
```

Fix anything whose solution is a version inside the current semver range with a
`cargo update -p <crate> --precise <ver>`, then rebuild + test. For the rest,
update this file with the decision. The CI audit job is **informational** today;
once this list is empty or every remaining entry is intentionally accepted, it
can be made a hard gate (set `continue-on-error: false`, and add `--ignore
<ID>` flags for the accepted ones with a pointer to this file).
