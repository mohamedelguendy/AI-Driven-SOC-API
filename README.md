# AI-Driven SOC — Backend

FastAPI + PostgreSQL backend for the AI-Driven Security Operations Center
graduation project. Handles login/roles, alert ingestion, incident triage,
the AI recommendation approval workflow (tier1 → tier2 → tier3), and
response execution via firewall/EDR adapters.

## Stack

- **Python / FastAPI** — the API
- **PostgreSQL** (Docker) — the database
- **JWT + Argon2** — auth
- **requests** — threat intel lookups (AbuseIPDB / VirusTotal) and firewall APIs

## Project structure

```
back-end/
  app/
    main.py                   # entry point: routers + background workers
    config.py                 # loads and validates .env
    db.py                     # PostgreSQL connection pool
    security.py               # password hashing + JWT
    deps.py                   # auth dependency + role checks
    schemas.py                # request/response models
    alert_classifier.py       # rule-based alert classifier (suggestion only)
    evidence_validation.py    # confirms an AI report's cited evidence is real
    intel_lookup.py           # IP reputation lookups (AbuseIPDB / VirusTotal), cached
    expiry.py                 # queues reverts for expired temporary actions
    action_jobs.py            # durable, retryable execution/revert worker
    l1_report_format.py       # renders an L1 report as the plain-text handoff
    adapters/
      firewall.py             # simulated firewall (FIREWALL_MODE=simulated)
      secure_firewall.py      # Cisco Secure Firewall via FMC (FIREWALL_MODE=fmc)
      meraki.py               # Cisco Meraki MX (FIREWALL_MODE=meraki)
      edr.py                  # simulated EDR
    routers/
      auth.py                 # POST /auth/login, GET /auth/me
      alerts.py               # POST /alerts/ingest
      incidents.py            # incident queue, tier1 triage, notes, escalate, resolve
      l1_reports.py           # AI-drafted L1 reports; tier1 approval = triage
      recommendations.py      # AI recommendations + approve/reject (tier2/tier3 impact rule)
      actions.py              # list actions, manual revert
      analysis.py             # POST /analysis/classify, /analysis/validate-evidence
      threat_intel.py         # GET /threat-intel/{ip}, GET /threat-intel
  scripts/
    ingest_common.py          # shared checkpointing and retry-safe alert delivery
    ingest_suricata.py        # feeds Suricata eve.json alerts into /alerts/ingest
    ingest_zeek.py            # feeds Zeek conn.log (filtered) into /alerts/ingest
    ingest_edr.py             # feeds EDR agent alerts into /alerts/ingest
    ingest_ids_engine.py      # feeds brute-force/port-scan alerts into /alerts/ingest
  tests/                      # unit tests + PostgreSQL workflow tests
  migration/                  # incremental DB changes (run after the base schema)
  back-end schema proto 2.sql # full database schema
  docker-compose.yml          # runs PostgreSQL locally
  create_user.py              # CLI to create an analyst account
  run.py                      # starts the server AND opens /docs automatically
  .env.example                # template for your own .env (never commit .env)
```

## Setup (first time on a new machine)

1. **Install:** Python 3.12+ (check "Add to PATH" on Windows), Docker Desktop, VS Code
2. **Clone the repo** (don't download a zip)
3. From `back-end/`:
   ```bash
   python -m venv .venv
   .venv\Scripts\Activate.ps1      # Windows
   pip install -r requirements.txt
   ```
4. **Create your `.env`:** copy `.env.example` to `.env` and replace the
   placeholders. `JWT_SECRET`, `INGEST_API_KEY`, and `AI_API_KEY` must each be
   at least 32 characters; generate separate, unique random values for them
   (run `python -c "import secrets; print(secrets.token_urlsafe(48))"` once per key).
   The app and the tests both read `.env` on startup, so create it first.
   `JWT_EXPIRE_MINUTES` must be between 1 and 1440. The two threat-intel keys
   are optional. Set `POSTGRES_PASSWORD` and use the same password in
   `DATABASE_URL`; Docker Compose reads it from `.env`. Keep the host as
   `127.0.0.1`: the database only listens on IPv4 loopback, and `localhost`
   can resolve to IPv6 first and hang.
5. **Start the database:**
   ```bash
   docker compose up -d
   ```
6. **Load the schema** (first time only):
   ```bash
   Get-Content "back-end schema proto 2.sql" | docker exec -i soc_db psql -U soc -d soc
   ```
7. **Apply migrations** (after the schema, in order; 001–003 are already part of
   the schema file, so start at 004. Each one is safe to re-run):
   ```bash
   Get-Content migration/004_add_threat_intel.sql | docker exec -i soc_db psql -U soc -d soc
   Get-Content migration/005_action_jobs.sql | docker exec -i soc_db psql -U soc -d soc
   Get-Content migration/006_login_rate_limits.sql | docker exec -i soc_db psql -U soc -d soc
   Get-Content migration/007_alert_ingest_idempotency.sql | docker exec -i soc_db psql -U soc -d soc
   Get-Content migration/008_action_job_leases.sql | docker exec -i soc_db psql -U soc -d soc
   Get-Content migration/009_evidence_and_triage_time.sql | docker exec -i soc_db psql -U soc -d soc
   Get-Content migration/010_l1_reports.sql | docker exec -i soc_db psql -U soc -d soc
   ```
8. **Create a user:**
   ```bash
   python create_user.py
   ```
9. **Run it:**
   ```bash
   python run.py
   ```
   Opens `http://127.0.0.1:8000/docs` automatically.

## Tests

The PostgreSQL regression tests use a separate database URL and create/drop
an isolated schema. Set `TEST_DATABASE_URL` to a disposable
PostgreSQL database before running them; do not point it at production:

```powershell
docker exec soc_db psql -U soc -d soc -c "CREATE DATABASE soc_test OWNER soc"   # once
$env:TEST_DATABASE_URL = "postgresql://soc:<POSTGRES_PASSWORD>@127.0.0.1:5432/soc_test"
python -m unittest discover -s tests -v
```

The tests are skipped when `TEST_DATABASE_URL` is not set. The login API
limits an IP/username pair to 10 attempts per 15-minute window.

## Roles

- **tier1** — triages new incidents (confirms real / dismisses false positives)
- **tier2** — investigates, can approve low-impact firewall/EDR actions
- **tier3** — handles escalations, can approve high-impact actions
- **admin** — everything

## Key endpoints

| Endpoint | Purpose |
|---|---|
| `POST /alerts/ingest` | Security pipeline sends events here (needs `X-API-Key`: `INGEST_API_KEY`) |
| `GET /incidents` | Incident queue |
| `POST /incidents/{id}/triage` | Tier1 confirms or dismisses a new incident by hand |
| `POST /l1-reports` | AI submits an L1 report draft (needs `X-API-Key`: `AI_API_KEY`) |
| `GET /l1-reports/{id}/text` | The report as a plain-text handoff document |
| `POST /l1-reports/{id}/approve` | Tier1 approves (optionally corrects) the draft; this triages the incident |
| `POST /l1-reports/{id}/reject` | Tier1 sends the draft back with a comment |
| `POST /l1-reports/{id}/notes` | An analyst adds a note to a report (`/notes/ai` for the AI agent) |
| `GET /l1-reports/metrics` | Review counts, AI verdict agreement, MTTA |
| `POST /analysis/classify` | Rule-based severity/priority suggestion for tier1 |
| `GET /threat-intel/{ip}` | IP reputation (AbuseIPDB / VirusTotal), cached 1 hour |
| `POST /recommendations` | AI submits a recommendation (needs `X-API-Key`: `AI_API_KEY`); `evidence_alert_ids` must name alerts of that incident, or it's rejected with 422 |
| `POST /analysis/validate-evidence` | Confirms an AI report's cited alert IDs are real |
| `POST /recommendations/{id}/approve` | Tier2 (low-impact) / tier3 (any) approve and queue execution. Returns 409 if tier1 hasn't triaged the incident yet, or if an identical action is already pending |
| `POST /actions/{id}/revert` | Queue a manual reversal or retry a failed reversal |
| `GET /actions?active_only=true` | Successfully applied actions still in effect |

## Feeding real security tools into the pipeline

The scripts in `scripts/` run on whatever machine has Suricata, Zeek, your
EDR agent, or the custom IDS engine, and forward their alerts into
`/alerts/ingest`:

```bash
python scripts/ingest_suricata.py --backend http://YOUR-IP:8000
python scripts/ingest_zeek.py --source /path/to/conn.log --backend http://YOUR-IP:8000
python scripts/ingest_edr.py --source /path/to/edr_alerts.jsonl --backend http://YOUR-IP:8000
python scripts/ingest_ids_engine.py --source /path/to/ids_alerts.jsonl --backend http://YOUR-IP:8000
```

Reusing an `Idempotency-Key` with the same payload returns the original result;
reusing it with a different payload returns HTTP 409.

Feeders persist file offsets under `~/.soc-ingest` (override with
`--state-file`) and retry network/server failures without advancing the
checkpoint. They send a stable `Idempotency-Key` for each source line, so
install migration 007 before enabling them. Use `--replay` to start at the
beginning of a log. Internal targets default to RFC1918 IPv4 ranges; override
them with the comma-separated `INTERNAL_NETWORK_CIDRS` setting.

⚠️ Don't run `ingest_suricata.py` and an `ids_engine.py`-fed
`ingest_ids_engine.py` together if the IDS engine is also processing
Suricata's own events — that double-ingests Suricata alerts. See the
docstring in `ingest_ids_engine.py`.

## L1 reports

For every new incident the AI drafts a tier 1 triage report. A tier 1 analyst
reviews it, and approving it *is* the triage decision. The report combines
what real SOC escalation tickets have in common:

| Part | What it holds |
|---|---|
| Header | incident/report IDs, status, TLP, category, attacker type, detected/triaged times, severity, priority, confidence |
| Executive summary | two or three plain sentences |
| Five Ws | who, what, when, where, why (filled from the evidence if the AI leaves them out) |
| Verdict | true/false positive, confidence, and the reasoning |
| Detection | triggering rules and tools, alert counts, activity window |
| Timeline (UTC) | the AI's events merged with platform events (incident opened, draft, review) |
| Affected assets and impact | hosts/users and their criticality; business impact, data exposure, CIA affected |
| Indicators and MITRE ATT&CK | IOCs with context and reputation; technique IDs (e.g. `T1110.001`) |
| Evidence | the cited alerts plus raw log excerpts |
| Investigation steps and context checks | what was checked and what it showed (known FP? maintenance window? recent alerts?) |
| Enrichment | backend-verified: IP reputation (public IPs only), first seen, alerts in the last 7 days, other incidents |
| Actions, next steps, open questions | what L1 already did, response actions, recommendations, what tier 2 should find out |
| Notifications / FP tuning | who must be told; for false positives, the pattern and tuning advice |
| Notes | timestamped notes the AI agent or analysts add at any time; they can't be edited or deleted |

Flow:

1. The AI sends `POST /l1-reports`. Only `incident_id`, `evidence_alert_ids`,
   `verdict`, `confidence`, `severity`, `summary` and the matching reason
   (`escalation_reason` or `false_positive_reason`) are required; every other
   part is optional. Cited alerts must belong to the incident, unknown fields
   are rejected, and only one draft per incident can await review at a time.
2. Tier 1 reads `GET /l1-reports/{id}/text` and either approves it with
   `POST /l1-reports/{id}/approve` or sends it back with
   `POST /l1-reports/{id}/reject` and a comment. To correct the draft while
   approving, send the changed fields: `{"changes": {"severity": 2}, "comment": "..."}`.
3. Approval triages the incident: a true positive goes to tier 2
   (`investigating`), a false positive is `closed`. The incident takes the
   report's severity and summary.
4. Anyone can add context later: the AI agent with
   `POST /l1-reports/{id}/notes/ai`, analysts with `POST /l1-reports/{id}/notes`
   (body: `{"body": "..."}`).

The AI's original draft is kept next to the approved version, so
`GET /l1-reports/metrics` can show how often tier 1 agreed with the AI.

Example draft:

```json
{
  "incident_id": 1042,
  "evidence_alert_ids": [8812, 8820, 8821],
  "verdict": "true_positive",
  "confidence": "high",
  "severity": 2,
  "category": "brute_force",
  "attacker": "external",
  "summary": "External IP made 312 failed SSH logins against srv-web-01, then logged in as 'deploy'.",
  "affected_assets": [{"hostname": "srv-web-01", "ip": "10.20.1.15", "user": "deploy", "role": "public web server", "criticality": "high"}],
  "indicators": [{"type": "ip", "value": "203.0.113.45", "context": "brute-force source"}],
  "mitre_attack": [{"technique_id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"}],
  "timeline": [{"time": "2026-10-30T14:08:41Z", "event": "Successful login as deploy", "source": "auth.log"}],
  "investigation_steps": [{"check": "Reviewed auth.log on srv-web-01", "result": "312 failures, then one success"}],
  "context_checks": [{"check": "Maintenance window", "result": "None scheduled"}],
  "impact": {"data_exposure": "suspected", "data_types": ["credentials"], "cia_affected": ["confidentiality"]},
  "log_excerpts": [{"source": "auth.log", "excerpt": "Accepted password for deploy from 203.0.113.45 port 51122 ssh2"}],
  "recommended_actions": ["Block 203.0.113.45", "Isolate srv-web-01", "Reset credentials for deploy"],
  "open_questions": ["Did the session run any commands?"],
  "notifications": [{"audience": "Asset owner", "reason": "Service account may be compromised"}],
  "escalation_reason": "Successful login after brute force plus an outbound connection suggests a live session."
}
```

## Dry run vs live

With `FIREWALL_MODE=fmc` or `meraki`, `FIREWALL_EXECUTION_MODE` decides whether
blocks are really enforced:

- `dry_run` (default): logs in and reads the firewall's current state, so it
  proves credentials and setup work, but skips every write. Action results
  start with `[DRY RUN - no change made]`.
- `live`: blocks and unblocks for real.

## Metrics

Incidents store `created_at`, `triaged_at` (set when tier1 confirms or
dismisses) and `resolved_at`. MTTA = `triaged_at - created_at`;
MTTR = `resolved_at - created_at`.

## Cisco Secure Firewall

Set `FIREWALL_MODE=fmc` to block IPs on Cisco Secure Firewall (FTD) through
its Firewall Management Center (FMC 7.0 or later). The backend adds and
removes IPs in an FMC **dynamic object**. Dynamic object changes reach the
firewalls without a policy deployment, so the SOC never deploys policy and
never pushes anyone else's pending changes.

One-time setup on the FMC:

1. Create a dedicated API user for the SOC with permission to edit objects.
2. Create a dynamic object of type IP named `SOC-Blocked-IPs` (or whatever
   you set in `FMC_DYNAMIC_OBJECT`). Use it only for the SOC: a revert
   removes the IP even if someone also added it by hand.
3. At the top of the access control policy, add two Block rules: one with
   the dynamic object as the source (traffic from the attacker), one with it
   as the destination (traffic to the attacker). Deploy once.

| Setting | Purpose |
|---|---|
| `FMC_HOST` | FMC address, e.g. `https://fmc.example.local` |
| `FMC_USERNAME` / `FMC_PASSWORD` | The SOC's API user |
| `FMC_DYNAMIC_OBJECT` | Name of the dynamic object (default `SOC-Blocked-IPs`) |
| `FMC_VERIFY_TLS` | Leave `true`; for a self-signed FMC certificate set `FMC_CA_BUNDLE` to its CA file instead of disabling checks |

Only `block_ip` is supported (single IPs and CIDR ranges); other firewall
action types are rejected with 422 while `FIREWALL_MODE=fmc`. For a free
FMC to test against, use an FMCv evaluation license or a Cisco DevNet
Secure Firewall sandbox.

## Cisco Meraki firewall

Set `FIREWALL_MODE=meraki` to send approved firewall actions to Meraki MX
appliances through the Dashboard API instead of simulating them:

| Setting | Purpose |
|---|---|
| `MERAKI_API_KEY` | Dashboard API key of an account with write access to the networks below |
| `MERAKI_NETWORK_IDS` | Comma-separated network IDs that blocks are applied to |
| `MERAKI_BLOCK_INBOUND` | `true` (default) also adds deny rules to the MX inbound firewall rules, blocking traffic from the attacker as well as to it |

Supported firewall actions (any other `action_type` is rejected with 422):

- `block_ip` (IP or CIDR): deny rule at the top of the L3 outbound rules with
  the target as destination and, if inbound blocking is on, in the inbound
  rules with the target as source. Single IPs are scored as `single_ip`,
  ranges as `subnet`, whatever the AI claims.
- `block_port` (1-65535): TCP and UDP deny rules for that destination port.

Every rule's comment contains `[soc-action-<id>]`. Retries never add a rule
twice, and a revert (manual or on expiry) removes only rules with that tag,
never rules created by hand in the Dashboard. Don't edit tagged rules by hand
while the action is active, and don't change `MERAKI_BLOCK_INBOUND` while
actions are active (reverts only clean the rule sets currently enabled).

Meraki replaces a network's whole rule list on each update. The backend
serializes its own updates per network, but a Dashboard edit made at the same
moment can still be overwritten. Try it on a test network first.

## Status

EDR execution is currently simulated (logged, not sent to a real device)
— pending access details from the security team. Firewall execution is
simulated unless `FIREWALL_MODE` is `fmc` or `meraki`, and even then only
enforced when `FIREWALL_EXECUTION_MODE=live`. Approvals and
reversions are durable queued jobs; the worker retries failures up to eight
times with exponential backoff and renews its database lease while an adapter
call is active. A failed reversal can be retried by calling the same revert
endpoint again. A real executor must honor the stable idempotency key included
in its command to prevent duplicated side effects.
