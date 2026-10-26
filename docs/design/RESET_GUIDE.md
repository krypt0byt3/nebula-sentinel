# NebulaSentinel — Starting Fresh (Reset Guide)

This wipes accumulated runtime data so you get a clean slate for testing (e.g.
before an ART run). Read the "Decide first" section — "start fresh" can mean three
different things, and the safe procedure differs.

> ⚠️ These operations are destructive and mostly irreversible. Stop the services
> first, and if you care about anything (forensic bundles, a tuned baseline, the
> operator account), back it up before deleting. When in doubt, MOVE to a
> `.bak` folder instead of `rm`.

---

## Decide first: what does "fresh" mean for you?

**A. Clear operational DATA, keep identity & models (RECOMMENDED for ART / test runs).**
   Wipes threats, detections, posture history, baseline learning, chat history,
   offline queue — but keeps the agent's identity, the TLS certs, the operator
   login, and the (large) model files. Fastest, least disruptive. This is almost
   certainly what you want.

**B. Full re-provision (new identities).** Also deletes agent IDs and certs, so
   agents re-enroll from scratch and you rebuild trust. Use only if you're
   changing the enrollment/PKI or genuinely starting the deployment over.

**C. Nuke everything including models.** Only if you're reclaiming disk or
   changing models. You'll re-download/re-place multi-GB GGUF files afterward.

---

## What lives where (verified from the code)

### Nexus  (base: `/var/lib/nexus/`)
| Path | Contents | Wipe in A? | Wipe in B? |
|---|---|---|---|
| `nexus.db` | **Everything**: agents, threats, posture (incl. vuln + compliance JSON), iocs, rules, whisper_history, dashboard layouts, users | ✅ (or selective) | ✅ |
| `nexus.toml` | Config | ❌ keep | ❌ keep |
| `certs/` | TLS / agent-auth certs | ❌ keep | ✅ delete |
| `models/` | GGUF model files (large) | ❌ keep | ❌ keep (unless C) |
| `dist/`, `llama-build/`, `llama-server.log` | Build artifacts + LLM log | optional | optional |

### Agent  (base: `/var/lib/nebula/`  •  Windows: `C:\ProgramData\NebulaSentinel\`)
| Path | Contents | Wipe in A? | Wipe in B? |
|---|---|---|---|
| `baseline.db` | Learned per-host normal (the ML baseline) | ✅ | ✅ |
| `offline_queue.db` | Unsent detections queued while disconnected | ✅ | ✅ |
| `forensics/` | Captured forensic bundles | ✅ (back up first if needed) | ✅ |
| `quarantine/` | Quarantined files | ✅ (⚠ real malware may be here) | ✅ |
| `alerts/`, `blocked_ips.log`, `*.log` | Local logs | ✅ | ✅ |
| `oval/`, `nvd/`, `hardening/` | Cached feeds (re-sync automatically) | optional | ✅ |
| `agent_id.*` | **The agent's identity** | ❌ keep | ✅ delete → re-enrolls |
| `gossip_override.json` | Runtime GOSSIP interval override | optional | ✅ |
| `models/` | GGUF model files (large) | ❌ keep | ❌ keep (unless C) |
| `ISOLATED` | Host-isolation marker (if present, host is isolated!) | ✅ (see note) | ✅ |

> **`ISOLATED` note:** if this file exists the agent has network-isolated the host.
> Deleting it is part of lifting isolation — make sure that's intended.

> **`quarantine/` note:** may contain live malware samples. Don't just delete into
> a synced folder; handle per your policy.

---

## Procedure A — Clear operational data (recommended)

### 1. Stop everything first (prevents re-writing during wipe)
```bash
# Nexus host
sudo systemctl stop nexus            # or however you run it

# Each agent host
sudo systemctl stop nebula-agent     # Linux
# Windows:  Stop-Service NebulaAgent
```

### 2. Nexus — two options

**Option A1 — selective wipe (keep users, rules, dashboards):** clears activity but
keeps your account and configuration. Run against a STOPPED Nexus:
```bash
sqlite3 /var/lib/nexus/nexus.db <<'SQL'
DELETE FROM threats;
DELETE FROM posture_reports;    -- holds posture + vuln + compliance results (JSON)
DELETE FROM iocs;               -- collected indicators
DELETE FROM whisper_history;
DELETE FROM forensic_bundles;
DELETE FROM forensic_artifacts;
DELETE FROM retro_hunts;
DELETE FROM retro_matches;
DELETE FROM gossip_envelopes;
DELETE FROM gossip_samples;
DELETE FROM agent_connectivity;
DELETE FROM commands;
DELETE FROM audit_log;
DELETE FROM agents;             -- agents re-register on reconnect
VACUUM;
SQL
```
> **Kept intentionally:** `users`, `api_keys`, `rules`, `settings`, `suppressions`,
> `policies`, `playbooks`, `compliance_frameworks`, `cve_catalog` (the NVD feed
> cache — large, re-usable), `intel_feeds`/`ioc_feeds` (your feed config).
> Vulnerabilities and compliance results are stored as JSON *inside*
> `posture_reports`, so clearing that table clears them too — there is no separate
> `vulnerabilities` or `compliance_results` table.
>
> See the real table list first: `sqlite3 /var/lib/nexus/nexus.db ".tables"`
> If `sqlite3` errors on a table, just remove that line and re-run.

**Option A2 — full DB reset (simplest; loses users/rules/dashboards too):**
```bash
sudo mv /var/lib/nexus/nexus.db /var/lib/nexus/nexus.db.bak.$(date +%s)
# Nexus recreates a fresh schema on next start; you'll re-run first-time setup.
```

### 3. Agent — wipe runtime state, keep identity
```bash
# Linux — on each agent host
cd /var/lib/nebula
sudo rm -f baseline.db offline_queue.db
sudo rm -rf forensics/* quarantine/* alerts/*
sudo rm -f blocked_ips.log *.log
# keep: agent_id.*, certs, models/, nexus.toml
```
```powershell
# Windows — on each agent host
cd C:\ProgramData\NebulaSentinel
Remove-Item baseline.db, offline_queue.db -ErrorAction SilentlyContinue
Remove-Item forensics\*, quarantine\*, alerts\* -Recurse -Force -ErrorAction SilentlyContinue
```

### 4. Restart
```bash
sudo systemctl start nexus
sudo systemctl start nebula-agent
```

The agent keeps its identity and reconnects; Nexus sees it re-register clean. The
baseline ML restarts its learn window from zero (expected — see caveat below).

---

## Procedure B — Full re-provision (new identities)

Do everything in A, **plus**:
```bash
# Nexus
sudo rm -rf /var/lib/nexus/certs/*          # forces new PKI
sudo mv /var/lib/nexus/nexus.db /var/lib/nexus/nexus.db.bak.$(date +%s)

# Each agent
sudo rm -f /var/lib/nebula/agent_id.*       # forces re-enrollment
sudo rm -f /var/lib/nebula/gossip_override.json
sudo rm -rf /var/lib/nebula/oval/* /var/lib/nebula/nvd/* /var/lib/nebula/hardening/*
```
Then re-run your enrollment / first-time-setup flow. Agents generate new IDs and
re-establish trust with Nexus.

---

## Procedure C — Reclaim disk (include models)
Everything in B, plus `sudo rm -rf /var/lib/nexus/models/* /var/lib/nebula/models/*`.
You must re-place the GGUF files before the LLM/ATC tier will start again.

---

## Important caveats

- **Baseline cold-start:** wiping `baseline.db` resets the anomaly engine's learned
  normal. It re-enters its learn window (default 21 days) and scores conservatively
  until mature. For an ART run that's usually fine — you're testing signatures +
  behavioral rules, and a half-trained baseline won't hurt catch-rate — but know
  that the *statistical* layer won't be at full strength immediately after a wipe.

- **Order matters:** always STOP services before deleting their databases. Deleting
  a live SQLite file (esp. with WAL) can corrupt state or leave `-wal`/`-shm`
  siblings. If you see `baseline.db-wal` / `nexus.db-wal` after stopping, delete
  those too.

- **Back up before you wipe** anything you might want: forensic bundles
  (`forensics/`), a well-tuned `baseline.db`, or the operator account (in
  `nexus.db`). `mv` to a `.bak` is safer than `rm`.

- **For a clean ART baseline specifically:** Procedure A is ideal. Wipe Nexus
  threats/detections and the agent's `baseline.db` + `offline_queue.db` so your
  ART results reflect only what THIS run produced, with no stale detections
  polluting the per-technique scoring.
```
