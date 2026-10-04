# AI-Driven SOC — Backend

FastAPI + PostgreSQL backend for the AI-Driven Security Operations Center
graduation project. Handles login/roles, alert ingestion, incident triage,
and the AI recommendation approval workflow (tier1 → tier2 → tier3).

## Stack

- **Python / FastAPI** — the API
- **PostgreSQL** (Docker) — the database
- **JWT + Argon2** — auth

## Project structure
back-end/
app/
main.py # entry point, wires routers together
config.py # loads .env
db.py # PostgreSQL connection pool
security.py # password hashing + JWT
deps.py # auth dependency + role checks
schemas.py # request/response models
routers/
auth.py # POST /auth/login, GET /auth/me
alerts.py # POST /alerts/ingest
incidents.py # incident queue, triage, notes, escalate, resolve
recommendations.py # AI recommendations + approve/reject
schema.sql # full database schema
migration/ # incremental DB changes (run in order, once each)
docker-compose.yml # runs PostgreSQL locally
create_user.py # CLI to create an analyst account
.env.example # template for your own .env (never commit .env)


## Setup (first time on a new machine)

1. **Install:** Python 3.12+ (check "Add to PATH" on Windows), Docker Desktop, VS Code
2. **Clone the repo** (don't download a zip)
3. From `back-end/`:
```bash
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -r requirements.txt
```
4. **Create your `.env`:** copy `.env.example` to `.env` and fill in real values
5. **Start the database:**
```bash
   docker compose up -d
```
6. **Load the schema** (first time only):
```bash
   Get-Content schema.sql | docker exec -i soc_db psql -U soc -d soc
```
7. **Apply any migrations**, in order:
```bash
   Get-Content migration/001_add_tier1.sql | docker exec -i soc_db psql -U soc -d soc
   Get-Content migration/002_add_tier1.sql | docker exec -i soc_db psql -U soc -d soc
```
8. **Create a user:**
```bash
   python create_user.py
```
9. **Run it:**
```bash
   python -m uvicorn app.main:app --reload
```
10. Open `http://localhost:8000/docs`

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
| `POST /recommendations` | AI submits a recommendation (needs `X-API-Key`: `AI_API_KEY`) |
| `POST /recommendations/{id}/approve` | Tier2 (low-impact) / tier3 (any) approve + execute |

## Status

Firewall/EDR execution is currently simulated (logged, not sent to a real
device) — pending access details from the security team.

