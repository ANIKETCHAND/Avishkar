"""
Service Discovery Module — Engine v2.0.0
=========================================
Discovers microservice boundaries and infers explainable privilege levels:
- Multi-source clustering: directory structure, entry points, FastAPI/APIRouter instances
- Docker Compose parsing (docker-compose.yml / compose.yaml) for declared service topologies
- Multi-signal privilege inference (PUBLIC < USER < SERVICE < ADMIN < UNKNOWN)
- Stores explainable privilege rationale and calibrated confidence

SECURITY: Never executes uploaded code.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ..models.schemas import (
    Service,
    PRIVILEGE_UNKNOWN, PRIVILEGE_PUBLIC, PRIVILEGE_USER,
    PRIVILEGE_SERVICE, PRIVILEGE_ADMIN,
    CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH,
    PRIVILEGE_RANK,
)
from .ast_visitor import FileAnalysisResult

logger = logging.getLogger(__name__)

# Files indicating service entry points
ENTRY_POINT_NAMES: frozenset[str] = frozenset({
    "main.py", "app.py", "server.py", "application.py",
    "run.py", "wsgi.py", "asgi.py",
})

ADMIN_ROUTE_PATTERNS: List[str] = ["admin", "superuser", "root", "sudo", "manage"]
SERVICE_ROUTE_PATTERNS: List[str] = ["internal", "service", "rpc", "grpc", "inter", "private", "system"]
USER_AUTH_PATTERNS: List[str] = [
    "get_current_user", "verify_user", "oauth2", "httpbearer",
    "login_required", "authenticated", "user_claims", "current_user",
]
SERVICE_AUTH_PATTERNS: List[str] = [
    "verify_service", "service_key", "service_token", "internal_auth",
    "x-service", "x_service", "api_key", "internal_token", "server_key",
    "check_token", "header:x_service", "header:x-service", "service_authenticator",
]


def _slugify(name: str) -> str:
    name = re.sub(r"[^a-z0-9\-_]", "-", name.lower())
    name = re.sub(r"-+", "-", name).strip("-")
    return name


def _parse_docker_compose_services(workspace_root: Path) -> Dict[str, str]:
    """
    Statically inspect docker-compose.yml / compose.yaml to extract service names
    and their mapped build contexts / paths without third-party dependencies.
    """
    compose_files = [
        workspace_root / "docker-compose.yml",
        workspace_root / "docker-compose.yaml",
        workspace_root / "compose.yml",
        workspace_root / "compose.yaml",
    ]
    compose_map: Dict[str, str] = {}

    for comp_file in compose_files:
        if not comp_file.is_file():
            continue
        try:
            content = comp_file.read_text(encoding="utf-8", errors="replace")
            # Lightweight regex parser for service declarations and build contexts
            current_service = None
            for line in content.splitlines():
                # Detect service key e.g. "  order-service:"
                match_svc = re.match(r"^\s{2,4}([a-zA-Z0-9_\-]+):\s*$", line)
                if match_svc and match_svc.group(1) not in ("version", "services", "networks", "volumes"):
                    current_service = match_svc.group(1)
                    continue

                if current_service:
                    match_build = re.search(r"build:\s*['\"]?([^'\"#\n]+)['\"]?", line)
                    if match_build:
                        raw_path = match_build.group(1).strip().lstrip("./")
                        compose_map[current_service] = raw_path
                        current_service = None
        except Exception as e:
            logger.debug("Could not parse compose file %s: %s", comp_file, e)

    return compose_map


def _infer_privilege_level(
    results: List[FileAnalysisResult],
) -> Tuple[str, str, str]:
    """
    Infer privilege level using combined semantic signals:
    - Route paths and prefixes
    - Parameter declarations and annotations
    - Authentication dependencies
    - Semantic authorization checks

    Returns:
        Tuple of (privilege_level, confidence, rationale).
    """
    has_admin_routes = False
    has_service_routes = False
    has_user_auth = False
    has_service_auth = False
    has_any_auth = False
    has_public_only = True

    admin_signals: List[str] = []
    service_signals: List[str] = []
    user_signals: List[str] = []

    for result in results:
        if result.has_service_credential_params:
            has_service_auth = True
            has_any_auth = True
            has_public_only = False
            service_signals.append("Service credential parameter declared in service function signature")

        for route in result.routes:
            if route.has_authentication:
                has_any_auth = True
                has_public_only = False

            path_lower = route.path.lower()
            if any(p in path_lower for p in ADMIN_ROUTE_PATTERNS):
                has_admin_routes = True
                admin_signals.append(f"Route path '{route.path}' contains admin prefix")
            if any(p in path_lower for p in SERVICE_ROUTE_PATTERNS):
                has_service_routes = True
                service_signals.append(f"Route path '{route.path}' contains internal service prefix")

            for dep in route.auth_deps + route.depends:
                dep_lower = dep.lower()
                if any(p in dep_lower for p in SERVICE_AUTH_PATTERNS) or "service" in dep_lower:
                    has_service_auth = True
                    service_signals.append(f"Service credential dependency '{dep}'")
                elif any(p in dep_lower for p in USER_AUTH_PATTERNS) or "user" in dep_lower:
                    has_user_auth = True
                    user_signals.append(f"User authentication dependency '{dep}'")

            for check in route.authz_checks:
                check_lower = check.lower()
                if any(p in check_lower for p in ["admin", "superuser"]):
                    has_admin_routes = True
                    admin_signals.append(f"Admin check in handler: '{check}'")
                elif any(p in check_lower for p in ["service_key", "service_token", "x_service", "x-service"]):
                    has_service_auth = True
                    service_signals.append(f"Service credential check: '{check}'")
                elif any(p in check_lower for p in ["user", "jwt", "owner"]):
                    has_user_auth = True
                    user_signals.append(f"User ownership check: '{check}'")

    # Determine privilege with explainable rationale
    if has_admin_routes and (has_any_auth or has_service_auth):
        rationale = f"Elevated administrative privilege inferred: {'; '.join(admin_signals[:2])}"
        return PRIVILEGE_ADMIN, CONFIDENCE_MEDIUM, rationale

    if has_service_auth or has_service_routes:
        reasons = service_signals if service_signals else ["Internal service routes or service credentials"]
        rationale = f"Internal service privilege inferred: {'; '.join(reasons[:2])}"
        return PRIVILEGE_SERVICE, CONFIDENCE_HIGH if has_service_auth else CONFIDENCE_MEDIUM, rationale

    if has_user_auth or has_any_auth:
        reasons = user_signals if user_signals else ["User-facing routes with user authentication guards"]
        rationale = f"User privilege boundary inferred: {'; '.join(reasons[:2])}"
        return PRIVILEGE_USER, CONFIDENCE_HIGH, rationale

    if has_public_only:
        return PRIVILEGE_PUBLIC, CONFIDENCE_LOW, "No authentication guards detected; endpoints appear publicly accessible."

    return PRIVILEGE_UNKNOWN, CONFIDENCE_LOW, "Insufficient static evidence to definitively classify privilege boundary."


def discover_services(
    ast_results: List[FileAnalysisResult],
    workspace_root: Path,
) -> List[Service]:
    """
    Discover distinct microservices from AST analysis results and repository metadata.
    Clusters files by directory, Docker Compose definitions, and FastAPI/APIRouter instances.
    """
    compose_map = _parse_docker_compose_services(workspace_root)
    groups: Dict[str, List[FileAnalysisResult]] = {}

    for result in ast_results:
        if result.parse_error and not result.routes and not result.app_definitions and not result.router_definitions:
            continue

        file_path = Path(result.file_path)
        parts = file_path.parts

        service_dir = "." if len(parts) <= 1 else parts[0]

        if service_dir not in groups:
            groups[service_dir] = []
        groups[service_dir].append(result)

    # Sub-directory splitting for multi-service repos under a single folder
    expanded_groups: Dict[str, List[FileAnalysisResult]] = {}

    for group_dir, results in groups.items():
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

        has_fastapi_per_subdir = {
            sub: any(r.app_definitions for r in sub_results)
            for sub, sub_results in sub_services.items()
        }

        if sum(has_fastapi_per_subdir.values()) > 1:
            expanded_groups.update(sub_services)
        else:
            expanded_groups[group_dir] = results

    # Build Service objects
    services: List[Service] = []
    seen_ids: Set[str] = set()

    for group_dir, results in expanded_groups.items():
        has_content = any(r.app_definitions or r.router_definitions or r.routes for r in results)
        if not has_content:
            continue

        dir_name = Path(group_dir).name if group_dir != "." else "root-service"
        service_name = dir_name.replace("_", "-").replace(" ", "-")

        # Check if Docker Compose declared an explicit name for this path
        for declared_svc_name, build_path in compose_map.items():
            if build_path and (build_path == group_dir or group_dir.endswith(build_path)):
                service_name = declared_svc_name
                break

        service_id = f"svc_{_slugify(dir_name)}"
        counter = 1
        base_id = service_id
        while service_id in seen_ids:
            service_id = f"{base_id}_{counter}"
            counter += 1
        seen_ids.add(service_id)

        entry_points: List[str] = []
        for result in results:
            fname = Path(result.file_path).name
            if fname in ENTRY_POINT_NAMES:
                entry_points.append(result.file_path)
            elif result.app_definitions:
                if result.file_path not in entry_points:
                    entry_points.append(result.file_path)

        privilege_level, confidence, rationale = _infer_privilege_level(results)

        services.append(Service(
            service_id=service_id,
            name=service_name,
            path=group_dir,
            privilege_level=privilege_level,
            confidence=confidence,
            entry_points=entry_points,
            privilege_reason=rationale,
        ))

    logger.info("Service discovery: identified %d services", len(services))
    return services
