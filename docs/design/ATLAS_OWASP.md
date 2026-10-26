# Atlas Guard — OWASP Top 10 Expansion — Design Note (v1)

## What Atlas Guard is today

Atlas Guard (`nexus-server/src/atlas/mod.rs`, ~295 lines) is the Nexus server's
**self-protection** layer. It defends the Nexus's own AI/API attack surface
against MITRE ATLAS (Adversarial Threat Landscape for AI Systems) techniques:
- Prompt injection (AML.T0051), jailbreak (T0054), prompt extraction (T0056)
- Model inference API abuse (T0040) — rate limiting on Whisper
- Adversarial data / malicious payloads (T0043) — ATC payload validation
- API key brute-force (T0048) — auth-failure lockout
- Response scrubbing to prevent system-prompt / secret leakage

It exposes clean check methods (`check_prompt_injection`, `validate_atc_payload`,
`scrub_response`, rate limiters, `record_auth_failure`) via `AppState.atlas`, and
surfaces events/stats at `/api/atlas/events` and `/api/atlas/stats`.

## The request

Expand Atlas Guard so it protects not only against ATLAS (AI-specific) attacks but
also the **OWASP Top 10** — the web-application risk categories. This is about
hardening the Nexus's *own* web/API surface (it is a web app with a REST API and a
browser UI), sitting alongside the existing ATLAS AI defenses. It is NOT a
web-app *scanner* for other targets (that's Red Nebula's job).

## OWASP Top 10 (2021) — which categories Atlas Guard can meaningfully defend

Not all ten are code-level runtime defenses; several are design/process. Honest
mapping of what a runtime guard layer can actually enforce:

| OWASP | Category | Atlas Guard action (runtime-enforceable?) |
|-------|----------|-------------------------------------------|
| A01 | Broken Access Control | Partial — detect IDOR-ish patterns, enforce auth on state-changing routes, flag privilege anomalies |
| A02 | Cryptographic Failures | Design-level (TLS, hashing) — guard can flag plaintext-secret patterns in payloads |
| A03 | Injection (SQLi/XSS/cmd) | **Yes** — input validation: detect SQLi/XSS/command-injection signatures in request bodies/params |
| A04 | Insecure Design | Design-level — not a runtime guard concern |
| A05 | Security Misconfiguration | Partial — detect missing security headers, verbose errors, debug endpoints |
| A06 | Vulnerable Components | Handled elsewhere (the vuln/CVE pipeline) |
| A07 | Auth Failures | **Yes** — already partly done (brute-force lockout); extend to weak-session / credential-stuffing detection |
| A08 | Data Integrity Failures | Partial — payload integrity validation (already have ATC payload validation) |
| A09 | Logging/Monitoring Failures | **Yes** — Atlas already logs security events; ensure OWASP events are logged too |
| A10 | SSRF | **Yes** — detect/deny outbound-fetch requests to internal ranges in any user-supplied URL |

**Runtime-enforceable, highest value:** A03 (injection), A10 (SSRF), A07 (auth),
A01 (access control), A05 (misconfig headers). These are where a guard layer adds
real protection.

## Proposed approach (phased)

### Phase 1 — Injection + SSRF detection (small, high-value, self-contained)
Add to AtlasGuard:
- `check_injection(input) -> Option<OwaspFinding>` — signature-based detection of
  SQLi (`' OR 1=1`, `UNION SELECT`, `;--`), XSS (`<script`, `onerror=`,
  `javascript:`), and command injection (`; rm -rf`, `$(...)`, backticks,
  `&&`/`||` with shell metachars) in request strings.
- `check_ssrf(url) -> bool` — deny user-supplied URLs targeting RFC1918/loopback/
  link-local/metadata (169.254.169.254) ranges.
Both emit an `OwaspEvent` (parallel to `AtlasEvent`) so they show in the guard's
event stream and stats. Categorize by OWASP id (A03/A10).

### Phase 2 — Security headers + misconfig (medium)
- A middleware that sets defensive response headers (CSP, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, HSTS) and a check that flags verbose error
  leakage. Wire as an axum layer.

### Phase 3 — Access-control anomaly detection (larger)
- Detect IDOR / horizontal-privilege patterns (an agent id accessing another's
  data, sequential-id enumeration). Needs per-principal request modeling.

## Scope for THIS build
Phase 1: injection + SSRF detection methods on AtlasGuard, emitting OWASP events
into the existing event/stats stream, plus a unified `OwaspFinding` type and the
detection signatures. Wire injection-checking into the highest-risk input path
(the Whisper/query endpoint and any user-supplied-string handler already routed
through check_prompt_injection). Self-contained, low-risk, additive.

## Honest caveats
- Signature-based injection detection catches common patterns, not all — it's
  defense-in-depth, not a WAF replacement, and parameterized queries remain the
  real fix. The guard flags/blocks obvious attacks and logs them.
- Several OWASP categories (A02, A04, A06) are design/process or handled by other
  subsystems; the guard honestly covers the runtime-enforceable subset rather than
  claiming all ten.
- This protects the NEXUS's own surface. Assessing *other* web apps for OWASP is
  Red Nebula's DAST role, separate from this.
