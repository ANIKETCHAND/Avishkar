"""
FastAPI REST API Endpoints — Phase 10
=======================================
Exposes the analysis pipeline via REST endpoints:

POST /api/v1/scan           — Upload ZIP and start analysis
POST /api/v1/scan/demo      — Run demo benchmark (vulnerable or secure)
GET  /api/v1/scans/{id}     — Retrieve scan result
GET  /api/v1/scans          — List recent scans
GET  /api/v1/scans/{id}/export/html  — Download HTML report
DELETE /api/v1/scans/{id}   — Delete a scan

All inputs validated via Pydantic.
Uploaded files never executed.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response

from ..ingestion.unpacker import unpack_zip, unpack_directory, create_zip_from_directory, IngestionError
from ..engine.risk_engine import run_analysis
from ..reporting.html_report import generate_html_report
from ..models.schemas import ScanResult, ScanSummaryResponse, STATUS_COMPLETED, STATUS_FAILED

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Analysis"])

# ─────────────────────────── Storage Configuration ───────────────────────

def _get_storage_dir() -> Path:
    """Get the scan storage directory, creating it if needed."""
    storage_env = os.environ.get("SCAN_STORAGE_DIR")
    if storage_env:
        storage = Path(storage_env)
    elif os.environ.get("VERCEL"):
        storage = Path("/tmp/scans")
    else:
        storage = Path("storage/scans")
    try:
        storage.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return storage


def _scan_path(scan_id: str) -> Path:
    return _get_storage_dir() / f"{scan_id}.json"


def _save_scan(scan_result: ScanResult) -> None:
    """Persist scan result to JSON file."""
    path = _scan_path(scan_result.scan_id)
    path.write_text(
        scan_result.model_dump_json(indent=2),
        encoding="utf-8",
    )


def _load_scan(scan_id: str) -> Optional[ScanResult]:
    """Load a scan result from JSON file."""
    path = _scan_path(scan_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return ScanResult.model_validate(data)
    except Exception as e:
        logger.error("Failed to load scan %s: %s", scan_id, e)
        return None


# ─────────────────────────── Endpoints ───────────────────────────────────

@router.post(
    "/scan",
    response_model=ScanResult,
    summary="Upload ZIP and run analysis",
    description=(
        "Upload a ZIP archive containing Python/FastAPI microservices. "
        "The system safely extracts and statically analyzes the code "
        "for potential confused deputy authorization vulnerabilities. "
        "**Never executes uploaded code.**"
    ),
)
async def create_scan(
    file: UploadFile = File(..., description="ZIP archive of Python/FastAPI microservices"),
    project_name: Optional[str] = Form(None, description="Optional project name override"),
) -> ScanResult:
    """Upload and analyze a microservices ZIP archive."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    if not file.filename.endswith(".zip"):
        raise HTTPException(
            status_code=400,
            detail="Only .zip archives are supported. Please package your microservices as a ZIP file.",
        )

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    storage_dir = _get_storage_dir()
    upload_path = storage_dir / scan_id / "upload.zip"
    upload_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # ── Save uploaded file ────────────────────────────────────────────
        content = await file.read()

        # Check size before writing (50 MB limit)
        max_size = 50 * 1024 * 1024
        if len(content) > max_size:
            raise HTTPException(
                status_code=413,
                detail=f"Archive too large. Maximum size is 50 MB. Got {len(content) / (1024*1024):.1f} MB.",
            )

        upload_path.write_bytes(content)
        logger.info("Uploaded ZIP: %s (%d bytes)", file.filename, len(content))

        # ── Safe extraction ───────────────────────────────────────────────
        try:
            extraction = unpack_zip(upload_path, storage_dir, scan_id)
        except IngestionError as e:
            raise HTTPException(status_code=422, detail=f"Archive validation failed: {e}")

        if not extraction.python_files:
            raise HTTPException(
                status_code=422,
                detail="No Python (.py) files found in the uploaded archive. "
                       "Please upload a ZIP containing Python/FastAPI microservices.",
            )

        # ── Run analysis ──────────────────────────────────────────────────
        name = project_name or file.filename
        scan_result = run_analysis(
            python_files=extraction.python_files,
            workspace_root=extraction.workspace_dir,
            project_name=name,
            scan_id=scan_id,
        )

        # ── Persist result ────────────────────────────────────────────────
        _save_scan(scan_result)
        logger.info("Scan %s complete: %d findings", scan_id, len(scan_result.findings))

        return scan_result

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Scan %s failed: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")


@router.post(
    "/scan/demo",
    response_model=ScanResult,
    summary="Run demo benchmark",
    description=(
        "Run the built-in benchmark against either the 'vulnerable' or 'secure' demo project. "
        "Vulnerable benchmark should trigger CD-001 and CD-002. "
        "Secure benchmark should yield 0 findings."
    ),
)
async def run_demo_scan(demo_type: str = Form(..., description="'vulnerable' or 'secure'")) -> ScanResult:
    """Run the demo benchmark analysis."""
    if demo_type not in ("vulnerable", "secure"):
        raise HTTPException(
            status_code=400,
            detail="demo_type must be 'vulnerable' or 'secure'",
        )

    # Find demo directory relative to this file
    api_file = Path(__file__)
    # Walk up to project root
    project_root = api_file.parent
    for _ in range(10):
        if (project_root / "demo").exists():
            break
        project_root = project_root.parent

    demo_dir = project_root / "demo" / demo_type

    if not demo_dir.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Demo directory not found: {demo_dir}. "
                   "Ensure the demo/ directory is present in the project.",
        )

    scan_id = f"scan_demo_{demo_type}_{uuid.uuid4().hex[:8]}"
    storage_dir = _get_storage_dir()

    try:
        extraction = unpack_directory(demo_dir, storage_dir, scan_id)

        if not extraction.python_files:
            raise HTTPException(
                status_code=422,
                detail=f"No Python files found in demo/{demo_type}",
            )

        scan_result = run_analysis(
            python_files=extraction.python_files,
            workspace_root=extraction.workspace_dir,
            project_name=f"demo-{demo_type}",
            scan_id=scan_id,
        )

        _save_scan(scan_result)
        return scan_result

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Demo scan failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Demo scan failed: {e}")


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResult,
    summary="Get scan result",
)
async def get_scan(scan_id: str) -> ScanResult:
    """Retrieve a scan result by ID."""
    # Validate scan_id format to prevent path traversal
    if not scan_id.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan_result = _load_scan(scan_id)
    if not scan_result:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    return scan_result


@router.get(
    "/scans",
    response_model=List[ScanSummaryResponse],
    summary="List recent scans",
)
async def list_scans(limit: int = 20) -> List[ScanSummaryResponse]:
    """List recent scan summaries (up to limit)."""
    storage_dir = _get_storage_dir()
    scan_files = sorted(
        storage_dir.glob("scan_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:limit]

    summaries: List[ScanSummaryResponse] = []
    for scan_file in scan_files:
        try:
            data = json.loads(scan_file.read_text(encoding="utf-8"))
            scan_result = ScanResult.model_validate(data)
            summaries.append(ScanSummaryResponse(
                scan_id=scan_result.scan_id,
                project_name=scan_result.project.project_name,
                scan_status=scan_result.project.scan_status,
                total_services=len(scan_result.services),
                total_endpoints=len(scan_result.endpoints),
                total_findings=len(scan_result.findings),
                scan_duration_seconds=scan_result.scan_duration_seconds,
                uploaded_at=scan_result.project.uploaded_at,
            ))
        except Exception as e:
            logger.warning("Could not load scan file %s: %s", scan_file.name, e)

    return summaries


@router.get(
    "/scans/{scan_id}/export/html",
    response_class=HTMLResponse,
    summary="Download HTML audit report",
)
async def export_html_report(scan_id: str) -> HTMLResponse:
    """Generate and download a standalone HTML audit report."""
    if not scan_id.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    scan_result = _load_scan(scan_id)
    if not scan_result:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    html_content = generate_html_report(scan_result)

    return HTMLResponse(
        content=html_content,
        headers={
            "Content-Disposition": f'attachment; filename="confused_deputy_report_{scan_id}.html"',
        },
    )


@router.delete(
    "/scans/{scan_id}",
    summary="Delete a scan result",
)
async def delete_scan(scan_id: str) -> Dict[str, str]:
    """Delete a scan result and its workspace files."""
    if not scan_id.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    storage_dir = _get_storage_dir()
    scan_file = _scan_path(scan_id)
    scan_workspace = storage_dir / scan_id

    deleted = False
    if scan_file.exists():
        scan_file.unlink()
        deleted = True
    if scan_workspace.exists():
        shutil.rmtree(scan_workspace, ignore_errors=True)
        deleted = True

    if not deleted:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    return {"message": f"Scan {scan_id} deleted successfully"}


@router.get("/health", tags=["System"], summary="Health check")
async def health() -> Dict[str, Any]:
    """System health check endpoint."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "description": "Confused Deputy API Detector for Microservices",
    }
