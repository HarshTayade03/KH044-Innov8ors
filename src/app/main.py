"""
main.py — FastAPI application entrypoint.

Responsibilities:
1. Create the FastAPI app with metadata.
2. Initialize the SQLite database on startup.
3. Register all API routers.
4. Serve the static analyst dashboard at root /.
5. Expose /health endpoint.

Decision log:
- Lifespan context manager (not @app.on_event) used for startup/shutdown —
  this is the FastAPI 0.93+ recommended approach.
- StaticFiles mounts AFTER routers so /docs and /api routes take precedence.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
import os

from src.app.config import settings
from src.app.database import init_db

# Import all API routers
from src.app.api.ingestion import router as ingestion_router
from src.app.api.findings import router as findings_router
from src.app.api.clusters import router as clusters_router
from src.app.api.validation import router as validation_router
from src.app.api.cases import router as cases_router
from src.app.api.dashboard import router as dashboard_router
from src.app.api.benchmarks import router as benchmarks_router
from src.app.api.audit import router as audit_router
from src.app.api.threat_intel import router as threat_intel_router
from src.app.api.remediation import router as remediation_router
from src.app.api.integrations import router as integrations_router
from src.app.api.docker_validation import router as docker_validation_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: initialize DB on startup, clean up on shutdown."""
    # ── Startup ──────────────────────────────────────────────────────────────
    print(f"[startup] {settings.app_name} v{settings.app_version} starting...")
    init_db()
    print("[startup] Offline lab validation is available; real sandbox execution is disabled.")
    print(f"[startup] KEV source: {'UNSUPPORTED live mode' if settings.kev_live else settings.kev_data_path}")
    print(f"[startup] EPSS source: {'UNSUPPORTED live mode' if settings.epss_live else settings.epss_data_path}")
    print("[startup] Ready.")
    yield
    # ── Shutdown ──────────────────────────────────────────────────────────────
    print("[shutdown] Application stopping.")


# ─── Application Instance ─────────────────────────────────────────────────────
app = FastAPI(
    title=settings.app_name,
    description=(
        "An AI-assisted vulnerability triage and prioritization platform. "
        "Normalizes findings from multiple scanners, deduplicates via semantic AI, "
        "scores risk using labeled local feeds and provides controlled offline validation. "
        "Analyst review and audit history remain the final decision layer."
    ),
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ─── API Routes ───────────────────────────────────────────────────────────────
# All routes prefixed with /api/v1

app.include_router(ingestion_router,  prefix="/api/v1")
app.include_router(findings_router,   prefix="/api/v1")
app.include_router(clusters_router,   prefix="/api/v1")
app.include_router(validation_router, prefix="/api/v1")
app.include_router(cases_router,      prefix="/api/v1")
app.include_router(dashboard_router,  prefix="/api/v1")
app.include_router(benchmarks_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")
app.include_router(threat_intel_router, prefix="/api/v1")
app.include_router(remediation_router, prefix="/api/v1")
app.include_router(integrations_router, prefix="/api/v1")
app.include_router(docker_validation_router, prefix="/api/v1")

# Dashboard assets are local so the validation console works without a CDN.
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


# ─── Core Endpoints ───────────────────────────────────────────────────────────

@app.get("/health", tags=["System"], summary="Health check")
async def health():
    """
    Returns application health status and version.
    Use this to verify the server is running and the DB is initialized.
    """
    from src.app.database import get_table_names
    tables = get_table_names()
    return JSONResponse({
        "status": "ok",
        "version": settings.app_version,
        "app": settings.app_name,
        "database": settings.database_path,
        "tables_initialized": len(tables),
        "sandbox_enabled": settings.sandbox_enabled,
        "validation_status": "offline_lab_simulator",
        "threat_intelligence_mode": "unsupported_live" if settings.kev_live or settings.epss_live else "mock",
        "model_download_allowed": settings.model_allow_download,
    })


@app.get("/", include_in_schema=False)
async def serve_landing():
    """Serve the public product landing page."""
    return FileResponse(os.path.join(static_dir, "landing.html"))


@app.get("/console", include_in_schema=False)
async def serve_console():
    """Serve the authenticated-style local analyst workspace."""
    response = FileResponse(os.path.join(static_dir, "index.html"))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.get("/documentation", include_in_schema=False)
async def serve_documentation():
    """Serve the product documentation page."""
    return FileResponse(os.path.join(static_dir, "documentation.html"))


# ─── Entry Point ──────────────────────────────────────────────────────────────
# Run with: python -m uvicorn src.app.main:app --reload --port 8000
