import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import action_jobs, expiry
from .db import pool
from .routers import actions, alerts, analysis, auth, incidents, recommendations, threat_intel


@asynccontextmanager
async def lifespan(app: FastAPI):
    stop_event = threading.Event()
    workers = [
        expiry.start(stop_event),
        action_jobs.start(stop_event),
    ]
    try:
        yield
    finally:
        stop_event.set()
        for worker in workers:
            worker.join(timeout=10)
        pool.close()


app = FastAPI(title="AI-Driven SOC API", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(recommendations.router)
app.include_router(actions.router)
app.include_router(threat_intel.router)
app.include_router(analysis.router)


@app.get("/health")
def health():
    with pool.connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "database": "connected"}