from contextlib import asynccontextmanager
 
from fastapi import FastAPI
 
from .db import pool
from .routers import alerts, auth, incidents, recommendations
 
 
@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    pool.close()  # close the database pool cleanly on shutdown
 
 
app = FastAPI(title="AI-Driven SOC API", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(recommendations.router)
 
 
@app.get("/health")
def health():
    with pool.connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "database": "connected"}
 