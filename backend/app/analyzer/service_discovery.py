"""
Service Discovery Module — Phase 4
=====================================
Groups Python source files into distinct microservice entities based on:
- Directory structure (each subdirectory with a FastAPI() instance = 1 service)
- FastAPI() or APIRouter() instantiation points
- Presence of main.py / app.py / server.py entry points

Assigns:
- service_id: unique slug
- name: human-readable service name
- path: relative root directory
- privilege_level: inferred from routes and auth patterns
- entry_points: list of main Python files

SECURITY: Never executes any uploaded code.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from ..models.schemas import (
    Service,
    PRIVILEGE_UNKNOWN, PRIVILEGE_PUBLIC, PRIVILEGE_USER,
    PRIVILEGE_SERVICE, PRIVILEGE_ADMIN,
    CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH,
    PRIVILEGE_RANK,
)
from .ast_visitor import FileAnalysisResult, SENSITIVE_KEYWORDS

logger = logging.getLogger(__name__)

# ─────────────────────────── Constants ────────────────────────────────────

# Files that indicate a service entry point
ENTRY_POINT_NAMES: frozenset[str] = frozenset({
    "main.py", "app.py", "server.py", "application.py",
    "run.py", "wsgi.py", "asgi.py",
})

# Admin route patterns for privilege inference
ADMIN_ROUTE_PATTERNS: List[str] = ["admin", "superuser", "root", "sudo", "manage"]

# Service-level route patterns
SERVICE_ROUTE_PATTERNS: List[str] = ["internal", "service", "rpc", "grpc", "inter"]

# User-level auth dependency names
USER_AUTH_PATTERNS: List[str] = [
    "get_current_user", "verify_token", "verify_jwt", "oauth2",
    "httpbearer", "login_required", "authenticated",
]

# Service auth patterns
SERVICE_AUTH_PATTERNS: List[str] = [
    "verify_service", "service_key", "service_token", "internal_auth",
    "x-service", "api_key",
]


def _slugify(name: str) -> str:
    """Convert a directory name to a valid service ID slug."""
    name = re.sub(r"[^a-z0-9\-_]", "-", name.lower())
    name = re.sub(r"-+", "-", name).strip("-")
    return name


def _infer_privilege_level(
    results: List[FileAnalysisResult],
) -> tuple[str, str]:
    """
    Infer the privilege level of a service from its AST analysis results.

    Returns:
        Tuple of (privilege_level, confidence).
    """
    has_auth_deps = False
    has_admin_routes = False
    has_service_routes = False
    has_user_auth = False
    has_service_auth = False
    has_public_only = True
    has_any_auth = False

    for result in results:
        for route in result.routes:
            if route.has_authentication:
                has_any_auth = True
                has_public_only = False

            # Check route path for admin patterns
            path_lower = route.path.lower()
            if any(p in path_lower for p in ADMIN_ROUTE_PATTERNS):
                has_admin_routes = True
            if any(p in path_lower for p in SERVICE_ROUTE_PATTERNS):
                has_service_routes = True

            # Check auth dep names
            for dep in route.auth_deps + route.depends:
                dep_lower = dep.lower()
                if any(p in dep_lower for p in USER_AUTH_PATTERNS):
                    has_user_auth = True
                if any(p in dep_lower for p in SERVICE_AUTH_PATTERNS):
                    has_service_auth = True

    # Infer privilege
    if has_admin_routes and has_any_auth:
        return PRIVILEGE_ADMIN, CONFIDENCE_MEDIUM
    elif has_service_auth or (has_service_routes and not has_user_auth):
        return PRIVILEGE_SERVICE, CONFIDENCE_MEDIUM
    elif has_user_auth or (has_any_auth and not has_service_routes):
        return PRIVILEGE_USER, CONFIDENCE_HIGH
    elif has_public_only:
        return PRIVILEGE_PUBLIC, CONFIDENCE_LOW
    else:
        return PRIVILEGE_UNKNOWN, CONFIDENCE_LOW


def discover_services(
    ast_results: List[FileAnalysisResult],
    workspace_root: Path,
) -> List[Service]:
    """
    Discover distinct microservices from AST analysis results.

    Strategy:
    1. Group files by their top-level directory within the workspace.
    2. A group becomes a service if it contains a FastAPI() instantiation
       or has an entry point file (main.py, app.py, etc.).
    3. Single-directory projects are treated as one service.

    Args:
        ast_results: List of file analysis results from AST parsing.
        workspace_root: The extracted workspace root path.

    Returns:
        List of discovered Service objects.
    """
    # ── Group files by top-level directory ──────────────────────────────────
    groups: Dict[str, List[FileAnalysisResult]] = {}

    for result in ast_results:
        if result.parse_error and not result.routes and not result.app_definitions:
            continue

        file_path = Path(result.file_path)
        # Determine the service root directory
        # If the file is at top level or only 1 level deep, use root
        parts = file_path.parts

        if len(parts) <= 1:
            service_dir = "."
        else:
            service_dir = parts[0]

        if service_dir not in groups:
            groups[service_dir] = []
        groups[service_dir].append(result)

    # ── Check if top-level groups should be split further ───────────────────
    # If a group dir has subdirectories each with their own FastAPI() instance,
    # split them into separate services.
    expanded_groups: Dict[str, List[FileAnalysisResult]] = {}

    for group_dir, results in groups.items():
        # Find subdirectory splits — each subdir with its own FastAPI()
        sub_services: Dict[str, List[FileAnalysisResult]] = {}

        for result in results:
            file_path = Path(result.file_path)
            parts = file_path.parts

            if group_dir == ".":
                sub_dir = "."
            elif len(parts) > 2:
                sub_dir = str(Path(*parts[:2]))
            else:
                sub_dir = group_dir

            if sub_dir not in sub_services:
                sub_services[sub_dir] = []
            sub_services[sub_dir].append(result)

        # Only split if sub-dirs each independently have FastAPI() instances
        has_fastapi_per_subdir = {
            sub: any(r.app_definitions for r in sub_results)
            for sub, sub_results in sub_services.items()
        }

        if sum(has_fastapi_per_subdir.values()) > 1:
            expanded_groups.update(sub_services)
        else:
            expanded_groups[group_dir] = results

    # ── Build Service objects ────────────────────────────────────────────────
    services: List[Service] = []
    seen_ids: Set[str] = set()

    for group_dir, results in expanded_groups.items():
        # Skip groups with no routes AND no FastAPI definitions
        has_content = any(r.app_definitions or r.routes for r in results)
        if not has_content:
            continue

        # Service name from directory
        dir_name = Path(group_dir).name if group_dir != "." else "root-service"
        service_name = dir_name.replace("_", "-").replace(" ", "-")

        service_id = f"svc_{_slugify(dir_name)}"
        # Handle duplicates
        counter = 1
        base_id = service_id
        while service_id in seen_ids:
            service_id = f"{base_id}_{counter}"
            counter += 1
        seen_ids.add(service_id)

        # Find entry points
        entry_points: List[str] = []
        for result in results:
            fname = Path(result.file_path).name
            if fname in ENTRY_POINT_NAMES:
                entry_points.append(result.file_path)
            elif result.app_definitions:
                if result.file_path not in entry_points:
                    entry_points.append(result.file_path)

        privilege_level, confidence = _infer_privilege_level(results)

        services.append(Service(
            service_id=service_id,
            name=service_name,
            path=group_dir,
            privilege_level=privilege_level,
            confidence=confidence,
            entry_points=entry_points,
        ))

    logger.info("Service discovery: found %d services", len(services))
    for svc in services:
        logger.debug("  Service: %s (%s) privilege=%s", svc.service_id, svc.name, svc.privilege_level)

    return services
