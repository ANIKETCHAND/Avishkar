"""
Semantic Python AST Visitor — Upgraded
=======================================
Robust AST analyzer for FastAPI microservices:
- Structural AST inspection without arbitrary code execution
- APIRouter & FastAPI tracking with router-level & app-level dependencies and prefixes
- Comprehensive HTTP client detection (httpx, requests, aiohttp, client instances, aliases)
- Lightweight intra-function data-flow and taint-style tracking for headers and URLs
- Semantic authorization detection (comparisons, 403/401 rejection paths, role checks, helpers)
- Precise sensitive operation classification (method + semantic intent, rejecting read-only false positives)
- Complete secret scrubbing with [REDACTED_SECRET]
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────── Constants ────────────────────────────────────

HTTP_METHODS: frozenset[str] = frozenset({"get", "post", "put", "delete", "patch", "head", "options"})

FASTAPI_APP_CLASSES: frozenset[str] = frozenset({"FastAPI", "APIRouter"})

# Known auth dependency name indicators (used as one of multiple signals)
AUTH_DEP_KEYWORDS: frozenset[str] = frozenset({
    "auth", "token", "jwt", "user", "bearer", "oauth2", "login", "security",
    "credential", "session", "identity", "principal", "admin", "role",
})

# Authorization check function indicators
AUTHZ_CHECK_KEYWORDS: frozenset[str] = frozenset({
    "owner", "ownership", "authorize", "authorization", "permission", "permit",
    "role", "roles", "admin", "superuser", "verify", "validate", "check", "assert",
    "owns", "allowed", "can_", "is_authorized", "is_permitted",
})

# Identity headers to track
IDENTITY_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "x-user-id",
    "x-user-role",
    "x-user-email",
    "x-forwarded-user",
    "x-original-user",
    "x-jwt",
    "x-access-token",
    "x-authenticated-user",
})

# Service credential headers
SERVICE_CREDENTIAL_HEADERS: frozenset[str] = frozenset({
    "x-service-key",
    "x-service-token",
    "x-api-key",
    "x-internal-key",
    "x-service-secret",
    "x-internal-token",
    "x-server-token",
})

# HTTP client library base modules
HTTP_CLIENT_MODULES: frozenset[str] = frozenset({"httpx", "requests", "aiohttp", "urllib"})

# HTTP client factory/class names
HTTP_CLIENT_CLASSES: frozenset[str] = frozenset({
    "client", "asyncclient", "session", "clientsession",
})

# Sensitive state-changing operation keywords (only applicable to mutating HTTP methods)
SENSITIVE_ACTION_KEYWORDS: frozenset[str] = frozenset({
    "refund", "void", "cancel", "charge", "debit", "credit", "transfer", "payout", "withdraw",
    "delete", "remove", "destroy", "purge", "revoke", "reset", "grant", "sudo",
    "elevate", "change_password", "reset_password", "update_role", "set_role",
})

# Secret patterns for redaction
SECRET_PATTERNS: List[re.Pattern] = [
    re.compile(r"bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE),
    re.compile(r"['\"]?(?:password|secret|key|token|api_key)\s*['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE),
    re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
]


# ─────────────────────────── Data Classes ─────────────────────────────────

@dataclass
class RouteDefinition:
    """Represents a discovered FastAPI route handler."""
    method: str
    path: str
    handler_name: str
    line_start: int
    line_end: int
    depends: List[str] = field(default_factory=list)
    auth_deps: List[str] = field(default_factory=list)
    authz_checks: List[str] = field(default_factory=list)
    has_authentication: bool = False
    is_sensitive: bool = False
    app_var: str = "app"
    is_async: bool = False
    router_prefix: str = ""
    rejection_paths: List[str] = field(default_factory=list)


@dataclass
class HttpCallDefinition:
    """Represents a discovered outgoing HTTP client call."""
    method: str
    url: str
    line: int
    passed_headers: List[str] = field(default_factory=list)
    has_authorization_header: bool = False
    has_service_token: bool = False
    has_user_id_header: bool = False
    client_module: str = ""
    raw_code: str = ""
    source_handler: str = ""


@dataclass
class RouterDefinition:
    """Represents an APIRouter instantiation."""
    var_name: str
    prefix: str = ""
    dependencies: List[str] = field(default_factory=list)
    line: int = 0


@dataclass
class FastAPIAppDefinition:
    """Represents a FastAPI() instantiation."""
    var_name: str
    type_name: str = "FastAPI"
    dependencies: List[str] = field(default_factory=list)
    line: int = 0


@dataclass
class FileAnalysisResult:
    """Complete analysis result for a single Python file."""
    file_path: str
    app_definitions: List[FastAPIAppDefinition] = field(default_factory=list)
    router_definitions: List[RouterDefinition] = field(default_factory=list)
    routes: List[RouteDefinition] = field(default_factory=list)
    http_calls: List[HttpCallDefinition] = field(default_factory=list)
    import_aliases: Dict[str, str] = field(default_factory=dict)
    module_constants: Dict[str, str] = field(default_factory=dict)
    has_service_credential_params: bool = False
    parse_error: Optional[str] = None
    parse_error_line: Optional[int] = None


# ─────────────────────────── Secret Redaction ─────────────────────────────

def redact_secrets(code: str) -> str:
    """Replace sensitive credentials and tokens with [REDACTED_SECRET]."""
    for pattern in SECRET_PATTERNS:
        code = pattern.sub("[REDACTED_SECRET]", code)
    return code


# ─────────────────────────── AST Visitor ──────────────────────────────────

class FastAPIVisitor(ast.NodeVisitor):
    """
    Semantic AST visitor that extracts routes, dependencies, client calls,
    and intra-function data flow relationships.
    """

    def __init__(self, source_lines: List[str]) -> None:
        self.source_lines = source_lines
        self.app_definitions: List[FastAPIAppDefinition] = []
        self.router_definitions: Dict[str, RouterDefinition] = {}
        self.routes: List[RouteDefinition] = []
        self.http_calls: List[HttpCallDefinition] = []
        self.import_aliases: Dict[str, str] = {}
        self.module_constants: Dict[str, str] = {}
        self.client_instances: Set[str] = set()
        self.has_service_credential_params: bool = False

        self._fastapi_vars: Set[str] = set()
        self._router_vars: Set[str] = set()

    # ── 1. Import Tracking ───────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            key = alias.asname or alias.name
            self.import_aliases[key] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            key = alias.asname or alias.name
            self.import_aliases[key] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    # ── 2. Top-Level Assignments & Router Registrations ───────────────────

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check module-level string constants
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.module_constants[target.id] = node.value.value

        # Check FastAPI() and APIRouter() calls
        if isinstance(node.value, ast.Call):
            call_name = self._resolve_call_name(node.value.func)
            base_name = call_name.split(".")[-1]

            if base_name == "FastAPI":
                deps = self._extract_call_dependencies(node.value)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._fastapi_vars.add(target.id)
                        self.app_definitions.append(FastAPIAppDefinition(
                            var_name=target.id,
                            dependencies=deps,
                            line=node.lineno,
                        ))
            elif base_name == "APIRouter":
                prefix = self._extract_router_prefix(node.value)
                deps = self._extract_call_dependencies(node.value)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._router_vars.add(target.id)
                        self.router_definitions[target.id] = RouterDefinition(
                            var_name=target.id,
                            prefix=prefix,
                            dependencies=deps,
                            line=node.lineno,
                        )

            # Check HTTP client instance creations: client = httpx.Client(), requests.Session()
            if self._is_http_client_instantiation(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.client_instances.add(target.id)

        self.generic_visit(node)

    # ── 3. Router Inclusions (app.include_router) ─────────────────────────

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            call_name = self._resolve_call_name(node.value.func)
            if call_name.endswith("include_router"):
                self._handle_include_router(node.value)
        self.generic_visit(node)

    def _handle_include_router(self, call_node: ast.Call) -> None:
        """Process app.include_router(router, prefix="...", dependencies=[...])."""
        router_var = None
        if call_node.args:
            first_arg = call_node.args[0]
            if isinstance(first_arg, ast.Name):
                router_var = first_arg.id

        if not router_var or router_var not in self.router_definitions:
            return

        # Merge prefix
        prefix = ""
        for kw in call_node.keywords:
            if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                prefix = str(kw.value.value)

        # Merge dependencies
        deps = self._extract_call_dependencies(call_node)

        router_def = self.router_definitions[router_var]
        if prefix:
            router_def.prefix = prefix + router_def.prefix
        router_def.dependencies.extend(deps)

    # ── 4. Function Analysis (Sync and Async Handlers) ────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._analyze_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._analyze_function(node, is_async=True)

    def _analyze_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None:
        """Analyze route decorators, dependencies, intra-function data flow, and HTTP calls."""
        routes_found: List[RouteDefinition] = []

        # ── a. Check route decorators ────────────────────────────────────
        for decorator in node.decorator_list:
            route = self._extract_route_decorator(decorator, node, is_async)
            if route:
                routes_found.append(route)

        # ── b. Extract parameters and dependencies ───────────────────────
        param_depends: List[str] = []
        auth_deps: List[str] = []
        user_identity_params: Set[str] = set()

        # Check all function parameters for service credential indicators
        for arg in node.args.args + node.args.kwonlyargs:
            arg_lower = arg.arg.lower()
            if any(k in arg_lower for k in ["service_token", "service_key", "x_service", "x-service", "internal_token", "internal_key"]):
                self.has_service_credential_params = True

        for arg, default in self._get_args_with_defaults(node):
            if default is None:
                continue

            dep_name = self._extract_depends(default)
            if dep_name:
                param_depends.append(dep_name)
                if self._is_auth_dependency(dep_name):
                    auth_deps.append(dep_name)
                    user_identity_params.add(arg.arg)

            # Check Header(...) parameters for identity or credentials
            if self._is_header_param(default):
                arg_lower = arg.arg.lower()
                if any(k in arg_lower for k in ["auth", "token", "jwt", "user", "key", "secret"]):
                    user_identity_params.add(arg.arg)
                    auth_deps.append(f"header:{arg.arg}")

        # Also inspect annotations
        for arg in node.args.args + node.args.kwonlyargs:
            if arg.annotation:
                ann_str = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
                if self._is_auth_dependency(ann_str):
                    auth_deps.append(ann_str)
                    user_identity_params.add(arg.arg)

        # ── c. Semantic authorization and rejection paths ────────────────
        authz_checks, rejection_paths = self._find_semantic_authz(node)

        # ── d. Lightweight intra-function data flow tracking ─────────────
        local_env = self._build_local_data_flow(node, user_identity_params)

        # ── e. Discover HTTP client calls using data flow ─────────────────
        http_calls = self._find_http_calls_with_data_flow(node, local_env)
        for call in http_calls:
            call.source_handler = node.name
        self.http_calls.extend(http_calls)

        # ── f. Finalize route metadata with router-level context ──────────
        for route in routes_found:
            # Check if route is attached to an APIRouter with router-level dependencies
            router_def = self.router_definitions.get(route.app_var)
            combined_depends = list(param_depends)
            combined_auth_deps = list(auth_deps)

            if router_def:
                combined_depends.extend(router_def.dependencies)
                for dep in router_def.dependencies:
                    if self._is_auth_dependency(dep):
                        combined_auth_deps.append(dep)
                if router_def.prefix and not route.path.startswith(router_def.prefix):
                    route.path = router_def.prefix.rstrip("/") + "/" + route.path.lstrip("/")
                    route.router_prefix = router_def.prefix

            route.depends = combined_depends
            route.auth_deps = combined_auth_deps
            route.authz_checks = authz_checks
            route.rejection_paths = rejection_paths
            route.has_authentication = bool(combined_auth_deps)
            route.line_end = self._get_function_end_line(node)
            self.routes.append(route)

        self.generic_visit(node)

    # ── 5. Route Decorator Extraction ────────────────────────────────────

    def _extract_route_decorator(
        self,
        decorator: ast.expr,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        is_async: bool,
    ) -> Optional[RouteDefinition]:
        if not isinstance(decorator, ast.Call):
            return None

        call_name = self._resolve_call_name(decorator.func)
        parts = call_name.split(".")
        if len(parts) < 2:
            return None

        app_var = parts[0]
        method_name = parts[-1].lower()

        # Handle @app.get, @router.post, @app.api_route, etc.
        method: Optional[str] = None
        if method_name in HTTP_METHODS:
            method = method_name.upper()
        elif method_name in {"api_route", "route"}:
            # Check methods kwarg e.g. methods=["POST"]
            for kw in decorator.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            method = elt.value.upper()
                            break
            if not method:
                method = "GET"

        if method is None:
            return None

        # Extract path
        path = "/"
        if decorator.args:
            first_arg = decorator.args[0]
            val = self._resolve_constant_or_name(first_arg)
            if val:
                path = val
        elif decorator.keywords:
            for kw in decorator.keywords:
                if kw.arg == "path":
                    val = self._resolve_constant_or_name(kw.value)
                    if val:
                        path = val
                    break

        is_sensitive = self._is_sensitive_operation(method, path, func_node.name)

        return RouteDefinition(
            method=method,
            path=path,
            handler_name=func_node.name,
            line_start=func_node.lineno,
            line_end=func_node.lineno,
            app_var=app_var,
            is_sensitive=is_sensitive,
            is_async=is_async,
        )

    # ── 6. Semantic Authorization & Rejection Paths ───────────────────────

    def _find_semantic_authz(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> Tuple[List[str], List[str]]:
        """
        Analyze AST nodes inside the function for semantic authorization:
        1. Compare operations checking user/owner identity.
        2. Raise statements rejecting with 401/403 HTTP status.
        3. Helper function calls validating permissions.
        4. Role and permission checks.
        """
        checks: List[str] = []
        rejections: List[str] = []

        for child in ast.walk(func_node):
            # ── a. Check explicit comparisons (e.g. order.user_id != user.id) ────
            if isinstance(child, ast.Compare):
                expr_str = ast.unparse(child) if hasattr(ast, "unparse") else ""
                expr_lower = expr_str.lower()
                has_user_identity = any(k in expr_lower for k in ["user", "sub", "uid", "subject", "principal", "account"])
                has_resource_ownership = any(k in expr_lower for k in ["owner", "id", "created_by", "belong", "author"])

                if has_user_identity and has_resource_ownership:
                    checks.append(f"ownership-check: {expr_str[:60]}")
                elif any(k in expr_lower for k in ["role", "roles", "admin", "is_admin", "permission", "scope"]):
                    checks.append(f"role-check: {expr_str[:60]}")

            # ── b. Check 401/403 HTTP rejection paths ─────────────────────────────
            if isinstance(child, ast.Raise) and child.exc:
                exc_str = ast.unparse(child.exc) if hasattr(ast, "unparse") else ""
                exc_lower = exc_str.lower()
                if "403" in exc_lower or "forbidden" in exc_lower:
                    rejections.append(f"403-rejection: {exc_str[:60]}")
                elif "401" in exc_lower or "unauthorized" in exc_lower:
                    rejections.append(f"401-rejection: {exc_str[:60]}")

            # ── c. Check authorization helper calls ──────────────────────────────
            if isinstance(child, ast.Call):
                call_name = self._resolve_call_name(child.func)
                name_lower = call_name.lower().split(".")[-1]

                if any(kw in name_lower for kw in AUTHZ_CHECK_KEYWORDS):
                    checks.append(f"authz-call: {call_name}")

        return list(dict.fromkeys(checks)), list(dict.fromkeys(rejections))

    # ── 7. Intra-Function Data Flow Tracking ─────────────────────────────

    def _build_local_data_flow(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        user_identity_params: Set[str],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Track local variable assignments to resolve dictionary construction,
        header merging, URL variables, and HTTP client instances within the function body.
        """
        local_env: Dict[str, Any] = {}
        local_clients: Set[str] = set(self.client_instances)

        for stmt in ast.walk(func_node):
            if isinstance(stmt, ast.Assign):
                target_name = None
                if stmt.targets and isinstance(stmt.targets[0], ast.Name):
                    target_name = stmt.targets[0].id

                if target_name and isinstance(stmt.value, ast.Call) and self._is_http_client_instantiation(stmt.value):
                    local_clients.add(target_name)

                if not target_name:
                    continue

                # ── a. Dictionary literal: headers = {"Authorization": token} ────
                if isinstance(stmt.value, ast.Dict):
                    dict_info = self._analyze_dict_node(stmt.value, user_identity_params, local_env)
                    local_env[target_name] = dict_info

                # ── b. Variable alias: req_headers = headers ──────────────────────
                elif isinstance(stmt.value, ast.Name):
                    source_var = stmt.value.id
                    if source_var in local_env:
                        local_env[target_name] = dict(local_env[source_var])
                    elif source_var in user_identity_params:
                        local_env[target_name] = {"is_user_identity": True}

                # ── c. String constant or concatenated URL ────────────────────────
                elif isinstance(stmt.value, (ast.Constant, ast.JoinedStr, ast.BinOp)):
                    url_val = self._resolve_string_expr(stmt.value)
                    if url_val:
                        local_env[target_name] = {"string_val": url_val}

            # ── With / AsyncWith: async with httpx.AsyncClient() as client: ────
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    if isinstance(item.context_expr, ast.Call) and self._is_http_client_instantiation(item.context_expr):
                        if isinstance(item.optional_vars, ast.Name):
                            local_clients.add(item.optional_vars.id)

            # ── Subscript assignment: headers["X-User-Id"] = user.id ──────────
            elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Subscript):
                sub = stmt.targets[0]
                if isinstance(sub.value, ast.Name) and isinstance(sub.slice, ast.Constant):
                    dict_var = sub.value.id
                    key_name = str(sub.slice.value).lower()
                    if dict_var in local_env and "headers" in local_env[dict_var]:
                        local_env[dict_var]["headers"].append(key_name)
                        if key_name == "authorization":
                            local_env[dict_var]["has_auth"] = True
                        elif key_name in SERVICE_CREDENTIAL_HEADERS:
                            local_env[dict_var]["has_service_token"] = True
                        elif key_name in {"x-user-id", "x-user-role"}:
                            local_env[dict_var]["has_user_id"] = True

        local_env["__client_instances__"] = local_clients
        return local_env

    def _analyze_dict_node(
        self,
        dict_node: ast.Dict,
        user_identity_params: Set[str],
        local_env: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Analyze a Dict AST node including keys, values, and unpacked sub-dicts."""
        headers: List[str] = []
        has_auth = False
        has_service_token = False
        has_user_id = False

        for k, v in zip(dict_node.keys, dict_node.values):
            if k is None:
                # Dictionary unpacking: {**base_headers, ...}
                if isinstance(v, ast.Name) and v.id in local_env:
                    unpacked = local_env[v.id]
                    headers.extend(unpacked.get("headers", []))
                    if unpacked.get("has_auth"):
                        has_auth = True
                    if unpacked.get("has_service_token"):
                        has_service_token = True
                    if unpacked.get("has_user_id"):
                        has_user_id = True
                continue

            key_str = self._resolve_string_expr(k)
            if not key_str:
                if isinstance(k, ast.Name):
                    key_str = k.id
                else:
                    continue

            key_lower = key_str.lower()
            headers.append(key_lower)

            # Check what value is assigned
            val_unparsed = ast.unparse(v).lower() if hasattr(ast, "unparse") else ""
            flows_from_user_param = any(p.lower() in val_unparsed for p in user_identity_params)

            if key_lower == "authorization":
                has_auth = True
            elif key_lower in SERVICE_CREDENTIAL_HEADERS:
                has_service_token = True
            elif key_lower in {"x-user-id", "x-user-role"}:
                has_user_id = True

            # If service token header is explicitly set
            if any(tok in val_unparsed for tok in ["service_token", "service_key", "internal_token", "secret_key"]):
                has_service_token = True

        return {
            "headers": list(dict.fromkeys(headers)),
            "has_auth": has_auth,
            "has_service_token": has_service_token,
            "has_user_id": has_user_id,
        }

    # ── 8. HTTP Client Call Discovery ────────────────────────────────────

    def _find_http_calls_with_data_flow(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        local_env: Dict[str, Any],
    ) -> List[HttpCallDefinition]:
        """Extract all outgoing HTTP client calls using local environment resolution."""
        calls: List[HttpCallDefinition] = []

        for child in ast.walk(func_node):
            if not isinstance(child, ast.Call):
                continue

            call = self._extract_http_call(child, local_env)
            if call:
                calls.append(call)

        return calls

    def _extract_http_call(
        self,
        node: ast.Call,
        local_env: Dict[str, Any],
    ) -> Optional[HttpCallDefinition]:
        """Extract HTTP client call from node, supporting httpx, requests, aiohttp, and aliases."""
        func = node.func
        call_name = self._resolve_call_name(func)
        parts = call_name.split(".")
        if len(parts) < 2:
            # Standalone call e.g. post(...) from `from httpx import post`
            if len(parts) == 1 and parts[0].lower() in HTTP_METHODS:
                orig_mod = self.import_aliases.get(parts[0], "")
                if any(m in orig_mod.lower() for m in HTTP_CLIENT_MODULES):
                    method_name = parts[0].lower()
                    client_module = orig_mod.split(".")[0]
                else:
                    return None
            else:
                return None
        else:
            obj_name = parts[0]
            method_name = parts[-1].lower()

            if method_name not in HTTP_METHODS and method_name not in {"request", "send"}:
                return None

            # Check if obj_name is a known client instance or module
            is_client = False
            client_module = ""

            resolved_obj = self.import_aliases.get(obj_name, obj_name)
            for mod in HTTP_CLIENT_MODULES:
                if mod in resolved_obj.lower():
                    is_client = True
                    client_module = mod
                    break

            local_clients = local_env.get("__client_instances__", set()) if local_env else set()
            if not is_client and (
                obj_name in self.client_instances
                or obj_name in local_clients
                or "client" in obj_name.lower()
                or "session" in obj_name.lower()
            ):
                is_client = True
                client_module = "httpx"

            if not is_client:
                return None

        # ── Extract URL ──────────────────────────────────────────────────
        url = ""
        if node.args:
            url = self._resolve_string_expr(node.args[0], local_env)
        else:
            for kw in node.keywords:
                if kw.arg == "url":
                    url = self._resolve_string_expr(kw.value, local_env)
                    break

        if not url:
            url = "<dynamic>"

        # ── Extract Headers with Data Flow ───────────────────────────────
        passed_headers: List[str] = []
        has_auth = False
        has_service_token = False
        has_user_id = False

        for kw in node.keywords:
            if kw.arg == "headers":
                if isinstance(kw.value, ast.Dict):
                    info = self._analyze_dict_node(kw.value, set(), local_env)
                    passed_headers.extend(info["headers"])
                    has_auth = info["has_auth"]
                    has_service_token = info["has_service_token"]
                    has_user_id = info["has_user_id"]
                elif isinstance(kw.value, ast.Name):
                    var_name = kw.value.id
                    if var_name in local_env:
                        info = local_env[var_name]
                        passed_headers.extend(info.get("headers", []))
                        has_auth = info.get("has_auth", False)
                        has_service_token = info.get("has_service_token", False)
                        has_user_id = info.get("has_user_id", False)
                    else:
                        passed_headers.append(f"<var:{var_name}>")

        # Source line
        raw_code = ""
        if self.source_lines and node.lineno <= len(self.source_lines):
            raw_code = redact_secrets(self.source_lines[node.lineno - 1].strip())

        return HttpCallDefinition(
            method=method_name.upper() if method_name not in {"request", "send"} else "GET",
            url=url,
            line=node.lineno,
            passed_headers=list(dict.fromkeys(passed_headers)),
            has_authorization_header=has_auth,
            has_service_token=has_service_token,
            has_user_id_header=has_user_id,
            client_module=client_module,
            raw_code=raw_code,
        )

    # ── 9. Expression Resolvers ──────────────────────────────────────────

    def _resolve_string_expr(self, node: ast.expr, local_env: Optional[Dict[str, Any]] = None) -> str:
        """Resolve string expression with variable and f-string support."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value

        if isinstance(node, ast.Name):
            # Check local env first, then module constants
            if local_env and node.id in local_env and "string_val" in local_env[node.id]:
                return local_env[node.id]["string_val"]
            if node.id in self.module_constants:
                return self.module_constants[node.id]
            return f"{{{node.id}}}"

        if isinstance(node, ast.JoinedStr):
            parts = []
            for val in node.values:
                if isinstance(val, ast.Constant):
                    parts.append(str(val.value))
                elif isinstance(val, ast.FormattedValue):
                    sub = self._resolve_string_expr(val.value, local_env)
                    parts.append(sub if sub else "{...}")
            return "".join(parts)

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve_string_expr(node.left, local_env)
            right = self._resolve_string_expr(node.right, local_env)
            return f"{left}{right}"

        return ""

    def _resolve_constant_or_name(self, node: ast.expr) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in self.module_constants:
            return self.module_constants[node.id]
        return None

    def _resolve_call_name(self, node: ast.expr) -> str:
        """Resolve full function call path (e.g. app.get or httpx.post)."""
        if isinstance(node, ast.Name):
            return self.import_aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._resolve_call_name(node.value)
            return f"{base}.{node.attr}"
        return ""

    def _extract_depends(self, node: ast.expr) -> Optional[str]:
        """Extract dependency function name from Depends(func) or Security(func)."""
        if not isinstance(node, ast.Call):
            return None

        func_name = self._resolve_call_name(node.func).split(".")[-1].lower()
        if func_name not in {"depends", "security"}:
            return None

        if node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, (ast.Name, ast.Attribute)):
                return self._resolve_call_name(first_arg).split(".")[-1]
        elif node.keywords:
            for kw in node.keywords:
                if kw.arg == "dependency" and isinstance(kw.value, (ast.Name, ast.Attribute)):
                    return self._resolve_call_name(kw.value).split(".")[-1]

        return func_name

    def _is_header_param(self, node: ast.expr) -> bool:
        """Check if parameter default is Header(...)."""
        if not isinstance(node, ast.Call):
            return False
        return self._resolve_call_name(node.func).split(".")[-1] == "Header"

    def _is_auth_dependency(self, name: str) -> bool:
        lower = name.lower()
        return any(k in lower for k in AUTH_DEP_KEYWORDS)

    def _is_sensitive_operation(self, method: str, path: str, handler_name: str) -> bool:
        """
        Check if an endpoint represents a sensitive state mutation.
        Read-only methods (GET, HEAD, OPTIONS) are NEVER sensitive state mutations.
        """
        method_upper = method.upper()
        if method_upper in {"GET", "HEAD", "OPTIONS"}:
            return False

        if method_upper == "DELETE":
            return True

        # For POST, PUT, PATCH: check path segments and handler name
        combined = f"{path.lower()} {handler_name.lower()}"
        return any(kw in combined for kw in SENSITIVE_ACTION_KEYWORDS)

    def _extract_router_prefix(self, call_node: ast.Call) -> str:
        for kw in call_node.keywords:
            if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                return str(kw.value.value)
        return ""

    def _extract_call_dependencies(self, call_node: ast.Call) -> List[str]:
        deps: List[str] = []
        for kw in call_node.keywords:
            if kw.arg == "dependencies" and isinstance(kw.value, (ast.List, ast.Tuple)):
                for elt in kw.value.elts:
                    dep = self._extract_depends(elt)
                    if dep:
                        deps.append(dep)
        return deps

    def _is_http_client_instantiation(self, call_node: ast.Call) -> bool:
        name = self._resolve_call_name(call_node.func).lower()
        return any(cls in name for cls in HTTP_CLIENT_CLASSES) and any(mod in name for mod in HTTP_CLIENT_MODULES)

    def _get_args_with_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        args = node.args.args
        defaults = [None] * (len(args) - len(node.args.defaults)) + list(node.args.defaults)
        pairs = list(zip(args, defaults))

        kwonly = node.args.kwonlyargs
        kw_defaults = node.args.kw_defaults
        for arg, default in zip(kwonly, kw_defaults):
            pairs.append((arg, default))

        return pairs

    def _get_function_end_line(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
        return max((getattr(c, "lineno", node.lineno) for c in ast.walk(node)), default=node.lineno)


# ─────────────────────────── Public Functions ─────────────────────────────

def analyze_file(file_path: Path, workspace_root: Path) -> FileAnalysisResult:
    """Parse a single Python file and extract AST metadata."""
    relative_path = str(file_path.relative_to(workspace_root))
    result = FileAnalysisResult(file_path=relative_path)

    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        result.parse_error = f"Could not read file: {e}"
        return result

    try:
        tree = ast.parse(source, filename=relative_path)
    except SyntaxError as e:
        result.parse_error = f"SyntaxError: {e.msg}"
        result.parse_error_line = e.lineno
        logger.warning("AST parse error in %s (line %s): %s", relative_path, e.lineno, e.msg)
        return result
    except Exception as e:
        result.parse_error = f"Unexpected parse error: {e}"
        logger.warning("Unexpected parse error in %s: %s", relative_path, e)
        return result

    source_lines = source.splitlines()
    visitor = FastAPIVisitor(source_lines)
    visitor.visit(tree)

    result.app_definitions = visitor.app_definitions
    result.router_definitions = list(visitor.router_definitions.values())
    result.routes = visitor.routes
    result.http_calls = visitor.http_calls
    result.import_aliases = visitor.import_aliases
    result.module_constants = visitor.module_constants
    result.has_service_credential_params = visitor.has_service_credential_params

    return result


def analyze_files(python_files: List[Path], workspace_root: Path) -> Tuple[List[FileAnalysisResult], List[Dict]]:
    """Analyze multiple Python files with error aggregation."""
    results: List[FileAnalysisResult] = []
    errors: List[Dict] = []

    for file_path in python_files:
        result = analyze_file(file_path, workspace_root)
        results.append(result)
        if result.parse_error:
            errors.append({
                "file": result.file_path,
                "error": result.parse_error,
                "line": result.parse_error_line,
            })

    return results, errors
