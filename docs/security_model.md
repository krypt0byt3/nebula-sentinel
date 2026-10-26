# Security Model

How NebulaSentinel authenticates and protects its channels, data, and control planes as currently implemented. This is a reference for the *current* posture (not a review or changelog).

## Trust boundaries at a glance

| Channel | Port | Direction | Transport | Authentication | Authorization |
|---------|------|-----------|-----------|----------------|---------------|
| ATC | 9443 | agent → Nexus | TLS (opt. mTLS) | **API key** (`X-Api-Key`, constant-time) | per-agent (shared key) |
| MGMT | 8443 | operator → Nexus | TLS | **JWT** (HS256) via 6 auth methods | **RBAC** (admin for `/api/*` writes) |
| GOSSIP (envelope) | 9443 | agent → Nexus | TLS + HTTP | ed25519 **envelope signature** verified against a key registry | corroboration + `sig_ok` |
| GOSSIP (mesh) | 9999 | agent ↔ agent | UDP | optional AES-256-GCM PSK | — |
| Status UI | 7440 | localhost | HTTP | localhost-only, read-only | — |

## Agent ↔ Nexus TLS

- **Cert pinning (agent side).** All agent HTTP clients route through `nebula-agent/src/tls.rs::nexus_http_builder`. When `[nexus].ca_cert_path` is set, that certificate becomes the **sole trust anchor** (built-in roots dropped) — an attacker's cert, even one signed by a public CA, is rejected. Without a pin, `[nexus].tls_verify` (default `true`) governs; `tls_verify = false` is an explicit, logged opt-out.
- **Self-signed cert SAN (Nexus side).** The auto-generated cert (`get_or_generate_tls_cert`) includes `nexus`, `localhost`, `127.0.0.1`, the system hostname, a concrete `bind_addr`, and any `tls_san` entries — so hostname/IP-based agent URLs pass verification. Regenerate by deleting `/var/lib/nexus/certs/nexus.crt`.
- **Optional mTLS** on the ATC listener via `require_agent_cert` + `agent_ca_cert_path`.

## ATC channel authentication (9443)

- The ATC router applies `atc_api_key_auth`: every endpoint (except `/health`) requires `X-Api-Key` (or `Authorization: Bearer`) matching the Nexus's `api_master_key`, compared in **constant time**.
- The key resolves from **`NEXUS_API_MASTER_KEY`** (env, recommended — loaded from `/etc/nexus/environment`) or a top-level `api_master_key` in `nexus.toml`. The Nexus **refuses to start** while the key is unset or the placeholder.
- Each agent sets the matching value in `[nexus].api_key`.

## Nexus operator authentication (8443)

- **Six mechanisms:** local (argon2id), LDAP/LDAPS, OIDC, PIV/CAC mTLS, TOTP, WebAuthn/FIDO2.
- **JWT:** HS256, 3-role model (admin / analyst / readonly). The signing secret is **`NEXUS_JWT_SECRET`**; the Nexus **fails closed** if it is unset, the placeholder, or shorter than 32 bytes.
- **Initial admin:** password from `NEXUS_ADMIN_PASSWORD`, or a **randomly generated** one printed once to stdout (never a known constant, never logged).
- **TOTP secrets at rest:** encrypted with AES-256-GCM (via `ring`) when `NEXUS_DB_ENCRYPTION_KEY` is set; plaintext otherwise (backward-compatible).

## Authorization (RBAC)

- `mgmt_rbac_middleware` runs inner to the JWT layer and **default-denies** state-changing methods (`POST`/`PUT`/`PATCH`/`DELETE`) on `/api/*` to non-admins, with a small self-service allowlist (logout, TOTP enroll/verify/disable, WebAuthn). Reads and self-service writes remain open to any authenticated user. Widen the allowlist to grant analyst writes.

## GOSSIP security

- **Envelope signing.** Each agent holds a **persistent ed25519 keypair** (`/var/lib/nebula/gossip_ed25519.key`, mode `0600`, `key_id = agent_id`) and signs every outgoing envelope. The public key is uploaded to the Nexus at registration and stored in the `agent_gossip_keys` registry.
- **Verification.** `ingest_gossip_envelope` verifies the origin signature against the registered key; the stored `sig_ok` reflects a **real ed25519 verification**. The `/api/gossip/envelopes` API and the Ecosystem UI surface a **verified / unverified** badge per envelope.
- **Hard enforcement (optional).** `gossip_require_signed = true` in `nexus.toml` makes the Nexus **reject** unverified envelopes instead of storing them (default `false` for rolling deployments).
- **Signed relay hops.** `sign_relay` / `verify_relay` / `Envelope::add_relay_signed` bind each relay hop's signature to the message `msg_id`.
- **UDP mesh encryption.** The agent↔agent mesh is sealed with AES-256-GCM (`gossip_seal`/`gossip_open`) using a shared 64-hex PSK; packets that fail authentication are dropped. Key resolution, in precedence order: (1) a local `[gossip].encryption_key` (**custom key** — always wins); (2) a **fleet key provisioned by the Nexus** — fetched at startup over the authenticated + TLS-pinned ATC channel (`GET /api/atc/gossip/key`) so a fleet is encrypted **out of the box**; (3) if `[gossip].encryption = true` but no key is available, it logs a warning and sends plaintext. Standalone agents (no Nexus) need a local key to encrypt. (The canonical envelope path to the Nexus is ed25519-signed regardless.)

## Data-at-rest protection

- **Forensic bundles.** Artifacts are encrypted **in place** with AES-256-GCM (via `ring`) before the bundle hash is computed, using `[forensics].encryption_key_hex` (proper key management) or a machine-derived key. Layout per file: `nonce(12) ‖ ciphertext ‖ tag(16)`.

## Agent self-protection

`self_protect` applies anti-debug / anti-dump / integrity measures (prctl anti-ptrace, core-dump suppression, `umask 077`, OOM exemption, SHA-256 binary/config integrity timers, watchdog, and a prompt-injection input filter).

## Secrets & key material

| Secret | Where | Purpose |
|--------|-------|---------|
| `NEXUS_JWT_SECRET` | `/etc/nexus/environment` | JWT signing (fail-closed) |
| `NEXUS_API_MASTER_KEY` | `/etc/nexus/environment` | ATC channel key (fail-closed); = agent `[nexus].api_key` |
| `NEXUS_ADMIN_PASSWORD` | `/etc/nexus/environment` | initial admin (else random) |
| `NEXUS_DB_ENCRYPTION_KEY` | `/etc/nexus/environment` | TOTP-at-rest encryption |
| `[nexus].ca_cert_path` | agent config | Nexus cert pin |
| `[forensics].encryption_key_hex` | agent config | forensic bundle encryption |
| `[gossip].encryption_key` | agent config | GOSSIP UDP PSK |
| `gossip_ed25519.key` | agent host (`0600`) | GOSSIP envelope signing (private) |
| `virustotal_api_key` | agent config | VirusTotal lookups |

## Known limitations / hardening roadmap

Documented honestly for planning; these are **not** yet enforced:

- **MFA is not enforced in the login state machine** (TOTP/WebAuthn are available but a password login currently yields a full session).
- **OIDC** signature verification does not cover ES256/EdDSA and can fall through to unverified claims; **LDAP** simple-bind lacks an empty-password guard.
- **No session/JWT revocation** — disabled/demoted users keep valid tokens until expiry.
- **Nexus → agent commands are unsigned** (kill/quarantine/isolate/block, `CaptureSample`/`FetchArtifact`) — security rests on the ATC channel; a spoofed/compromised Nexus is high-impact. `QuarantineFile`/`CaptureSample` also lack a path allowlist.
- **SSRF egress guards** are missing on rule-feed sync, git import, and notification webhooks.
- **GOSSIP datagram replay-window** protection (stale-timestamp / seen-`msg_id`) is not yet implemented.
