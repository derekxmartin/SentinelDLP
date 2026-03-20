from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.config import settings
from server.api.auth import router as auth_router
from server.api.detection import router as detection_router
from server.api.dictionaries import router as dictionaries_router
from server.api.identifiers import router as identifiers_router
from server.api.incidents import router as incidents_router
from server.api.policies import router as policies_router
from server.api.response_rules import router as response_rules_router
from server.api.search import router as search_router
from server.api.system import router as system_router
from server.api.fingerprints import router as fingerprints_router
from server.api.network_settings import router as network_settings_router
from server.api.users import router as users_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup — launch gRPC server alongside FastAPI
    from server.grpc_server import serve as grpc_serve

    grpc_server = await grpc_serve(port=settings.grpc_port)
    yield
    # Shutdown
    await grpc_server.stop(grace=5)


app = FastAPI(
    title="AkesoDLP",
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
app.include_router(dictionaries_router)
app.include_router(identifiers_router)
app.include_router(fingerprints_router)
app.include_router(incidents_router)
app.include_router(network_settings_router)
app.include_router(policies_router)
app.include_router(response_rules_router)
app.include_router(search_router)
app.include_router(system_router)
app.include_router(users_router)


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "akeso-dlp-server"}
