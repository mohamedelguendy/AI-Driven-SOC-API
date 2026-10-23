# AI-Driven SOC — Backend

FastAPI + PostgreSQL backend for the AI-Driven Security Operations Center
graduation project. Handles login/roles, alert ingestion, incident triage,
the AI recommendation approval workflow (tier1 → tier2 → tier3), and
response execution via firewall/EDR adapters.

## Stack

- **Python / FastAPI** — the API
- **PostgreSQL** (Docker) — the database
- **JWT + Argon2** — auth
- **requests** — threat intel lookups (AbuseIPDB / VirusTotal)

## Project structure

```
back-end/
  app/
    main.py                 # entry point, wires routers together, starts the expiry job
    config.py                # loads .env
    db.py                     # PostgreSQL connection pool
    security.py              # password hashing + JWT
    deps.py                    # auth dependency + role checks
    schemas.py               # request/response models
    analysis.py              # rule-based alert classifier (suggestion only)
    evidence_validation.py   # confirms an AI report's cited evidence is real
    threat_intel.py          # IP reputation lookups (AbuseIPDB / VirusTotal), cached
    expiry.py                 # background job: auto-reverts expired temporary actions
    adapters/
      firewall.py             # simulated firewall execute()/revert()
      edr.py                  # simulated EDR execute()/revert()
    routers/
      auth.py                  # POST /auth/login, GET /auth/me
      alerts.py                # POST /alerts/ingest
      incidents.py             # incident queue, tier1 triage, notes, escalate, resolve
      recommendations.py      # AI recommendations + approve/reject (tier2/tier3 impact rule)
      actions.py                # list actions, manual revert
      analysis.py               # POST /analysis/classify, /analysis/validate-evidence
      threat_intel.py          # GET /threat-intel/{ip}, GET /threat-intel
  scripts/
    ingest_suricata.py        # feeds Suricata eve.json alerts into /alerts/ingest
    ingest_zeek.py             # feeds Zeek conn.log (filtered) into /alerts/ingest
    ingest_edr.py               # feeds EDR agent alerts into /alerts/ingest
    ingest_ids_engine.py      # feeds brute-force/port-scan alerts into /alerts/ingest
  schema.sql                  # full database schema
  migration/                   # incremental DB changes (run in order, once each)
  docker-compose.yml          # runs PostgreSQL locally
  create_user.py               # CLI to create an analyst account
  run.py                        # starts the server AND opens /docs automatically
  .env.example                  # template for your own .env (never commit .env)
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
4. **Create your `.env`:** copy `.env.example` to `.env` and fill in real values
   (the two threat-intel keys are optional)
5. **Start the database:**
   ```bash
   docker compose up -d
   ```
6. **Load the schema** (first time only):
   ```bash
   Get-Content schema.sql | docker exec -i soc_db psql -U soc -d soc
   ```
7. **Apply all migrations, in order:**
   ```bash
   Get-Content migration/001_add_tier1.sql | docker exec -i soc_db psql -U soc -d soc
   Get-Content migration/002_add_tier1.sql | docker exec -i soc_db psql -U soc -d soc
   Get-Content migration/003_add_cve_cvss.sql | docker exec -i soc_db psql -U soc -d soc
   Get-Content migration/004_add_threat_intel.sql | docker exec -i soc_db psql -U soc -d soc
   ```
8. **Create a user:**
   ```bash
   python create_user.py
   ```
9. **Run it:**
   ```bash
   python run.py
   ```
   Opens `http://localhost:8000/docs` automatically.

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
| `POST /incidents/{id}/triage` | Tier1 confirms or dismisses a new incident |
| `POST /analysis/classify` | Rule-based severity/priority suggestion for tier1 |
| `GET /threat-intel/{ip}` | IP reputation (AbuseIPDB / VirusTotal), cached 1 hour |
| `POST /recommendations` | AI submits a recommendation (needs `X-API-Key`: `AI_API_KEY`) |
| `POST /analysis/validate-evidence` | Confirms an AI report's cited alert IDs are real |
| `POST /recommendations/{id}/approve` | Tier2 (low-impact) / tier3 (any) approve + execute |
| `POST /actions/{id}/revert` | Manually undo an action |
| `GET /actions?active_only=true` | What's currently blocked/isolated |

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

⚠️ Don't run `ingest_suricata.py` and an `ids_engine.py`-fed
`ingest_ids_engine.py` together if the IDS engine is also processing
Suricata's own events — that double-ingests Suricata alerts. See the
docstring in `ingest_ids_engine.py`.

## Status

Firewall/EDR execution is currently simulated (logged, not sent to a real
device) — pending access details from the security team.