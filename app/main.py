import threading
from contextlib import asynccontextmanager
 
from fastapi import FastAPI
 
from . import expiry
from .db import pool
from .routers import actions, alerts, auth, incidents, recommendations
 
_expiry_stop = threading.Event()
 
 
@asynccontextmanager
async def lifespan(app: FastAPI):
    expiry.start(_expiry_stop)  # auto-reverts expired temporary blocks in the background
    yield
    _expiry_stop.set()
    pool.close()  # close the database pool cleanly on shutdown
 
 
app = FastAPI(title="AI-Driven SOC API", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(recommendations.router)
app.include_router(actions.router)
 
 
@app.get("/health")
def health():
    with pool.connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "database": "connected"}
 