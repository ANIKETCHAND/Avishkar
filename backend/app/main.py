"""
FastAPI Application Entry Point
=================================
Main FastAPI application with CORS, logging, and all routes configured.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from typing import Optional
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from .api.endpoints import router

# ─────────────────────────── Logging Setup ───────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logger = logging.getLogger(__name__)

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize storage directories on startup."""
    import os
    storage_dir = Path(os.environ.get("SCAN_STORAGE_DIR", "storage/scans"))
    storage_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Confused Deputy API Detector v1.0.0 started")
    logger.info("Storage directory: %s", storage_dir.resolve())
    logger.info("API docs: http://localhost:8000/docs")
    yield

# ─────────────────────────── App Definition ──────────────────────────────

app = FastAPI(
    title="Confused Deputy API Detector",
    description=(
        "A specialized static analyzer for detecting potential confused-deputy "
        "authorization risks across FastAPI microservice boundaries.\n\n"
        "**Security Note:** Uploaded code is NEVER executed. "
        "All analysis is performed via static Python AST parsing."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ─────────────────────────── CORS ────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ─────────────────────────── Routes ──────────────────────────────────────

# ─────────────────────────── Routes ──────────────────────────────────────

app.include_router(router)

# Discover frontend dist directory if compiled
current_file = Path(__file__).resolve()
possible_dist_dirs = [
    current_file.parent.parent.parent / "frontend" / "dist",
    current_file.parent.parent / "frontend" / "dist",
    Path("frontend/dist"),
]

dist_dir: Optional[Path] = None
for d in possible_dist_dirs:
    if d.exists() and (d / "index.html").exists():
        dist_dir = d
        break

if dist_dir:
    assets_dir = dist_dir / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_spa_root():
        return FileResponse(dist_dir / "index.html")

    @app.exception_handler(404)
    async def spa_fallback(request: Request, exc):
        path = request.url.path
        if path.startswith("/api/") or path in ("/docs", "/openapi.json", "/redoc"):
            return JSONResponse(status_code=404, content={"detail": "Not Found"})
        if dist_dir and (dist_dir / "index.html").exists():
            return FileResponse(dist_dir / "index.html")
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return JSONResponse({
            "name": "Confused Deputy API Detector",
            "version": "1.0.0",
            "docs": "/docs",
            "health": "/api/v1/health",
            "description": "Static analyzer for confused deputy authorization risks in FastAPI microservices",
        })
