from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.config import settings
from server.api.auth import router as auth_router
from server.api.detection import router as detection_router
from server.api.incidents import router as incidents_router
from server.api.policies import router as policies_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown


app = FastAPI(
    title="SentinelDLP",
    description="Data Loss Prevention Server",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Routers ---
app.include_router(auth_router)
app.include_router(detection_router)
app.include_router(incidents_router)
app.include_router(policies_router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "sentinel-dlp-server"}
