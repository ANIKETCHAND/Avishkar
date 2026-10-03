"""
Semantic Python AST Visitor — Engine v2.0.0
============================================
Advanced semantic AST analyzer for FastAPI microservices:
- Pure static AST inspection without arbitrary code execution
- First-pass module function cataloging for bounded interprocedural helper analysis
- Semantic authorization verification (comparisons, 401/403 rejection paths, DB ownership filters)
- Discrimination between empty mock helpers (def verify(): pass) vs real authorization enforcement
- Precise sensitive state-mutation classification (POST/PUT/PATCH/DELETE + DB mutations)
- Read-only verbs (GET/HEAD/OPTIONS) are guaranteed non-sensitive
- Identity provenance tracking (USER_JWT_VERIFIED, SERVICE_CREDENTIAL, UNVERIFIED_USER_HEADER, etc.)
- Multi-client discovery across httpx, requests, aiohttp, client instances, and aliases
- Complete secret scrubbing with [REDACTED_SECRET]
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models.ir import (
    IdentityProvenance, AuthenticationState, AuthorizationState,
    AuthorizationType, SecurityControlKind, SourceLocation,
    AuthorizationCheck, ResourceOwnershipCheck, SensitiveOperationEvidence,
    DataFlowFact,
)

logger = logging.getLogger(__name__)

# ─────────────────────────── Constants ────────────────────────────────────

HTTP_METHODS: frozenset[str] = frozenset({"get", "post", "put", "delete", "patch", "head", "options", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})
MUTATING_HTTP_METHODS: frozenset[str] = frozenset({"post", "put", "patch", "delete", "POST", "PUT", "PATCH", "DELETE"})
READONLY_HTTP_METHODS: frozenset[str] = frozenset({"get", "head", "options", "GET", "HEAD", "OPTIONS"})

FASTAPI_APP_CLASSES: frozenset[str] = frozenset({"FastAPI", "APIRouter"})

# Known auth dependency name indicators (treated as one of multiple signals)
AUTH_DEP_KEYWORDS: frozenset[str] = frozenset({
    "auth", "token", "jwt", "user", "bearer", "oauth2", "login", "security",
    "credential", "session", "identity", "principal", "admin", "role",
})

# Identity headers
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

# Database state mutation call attributes
DB_MUTATION_METHODS: frozenset[str] = frozenset({
    "delete", "delete_one", "delete_many", "commit", "add", "add_all",
    "update", "update_one", "update_many", "insert", "insert_one", "insert_many",
    "remove", "drop", "truncate", "execute",
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
    """Represents a discovered FastAPI route handler with semantic security context."""
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
    authn_state: AuthenticationState = AuthenticationState.AUTHENTICATION_UNKNOWN
    authz_state: AuthorizationState = AuthorizationState.AUTHORIZATION_UNKNOWN
    authz_type: AuthorizationType = AuthorizationType.UNKNOWN
    ownership_checks: List[ResourceOwnershipCheck] = field(default_factory=list)
    sensitive_evidence: Optional[SensitiveOperationEvidence] = None


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
    provenance: IdentityProvenance = IdentityProvenance.UNKNOWN
    data_flow_facts: List[DataFlowFact] = field(default_factory=list)


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
    and performs bounded intra- and inter-procedural data-flow and ownership analysis.
    """

    def __init__(self, source_lines: List[str], file_path: str = "") -> None:
        self.source_lines = source_lines
        self.file_path = file_path
        self.app_definitions: List[FastAPIAppDefinition] = []
        self.router_definitions: Dict[str, RouterDefinition] = {}
        self.routes: List[RouteDefinition] = []
        self.http_calls: List[HttpCallDefinition] = []
        self.import_aliases: Dict[str, str] = {}
        self.module_constants: Dict[str, str] = {}
        self.client_instances: Set[str] = set()
        self.has_service_credential_params: bool = False

        # Function catalog for interprocedural analysis
        self.module_functions: Dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}

        self._fastapi_vars: Set[str] = set()
        self._router_vars: Set[str] = set()

    # ── Pass 1: Catalog Module Functions ──────────────────────────────────

    def catalog_module_functions(self, tree: ast.AST) -> None:
        """First pass: index all top-level functions for helper call resolution."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.module_functions[node.name] = node

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

        prefix = ""
        for kw in call_node.keywords:
            if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                prefix = str(kw.value.value)

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
                if any(k in arg_lower for k in ["service_token", "service_key", "x_service", "x-service", "internal_token", "internal_key"]):
                    self.has_service_credential_params = True
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

        # ── c. Semantic authorization, rejection paths, and ownership checks ──
        authz_checks, rejection_paths, ownership_checks, authz_type, authz_state = (
            self._find_semantic_authz_and_ownership(node)
        )

        # ── d. Lightweight intra- and bounded inter-procedural data flow ─────
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
            route.authn_state = (
                AuthenticationState.AUTHENTICATION_PRESENT
                if combined_auth_deps
                else AuthenticationState.AUTHENTICATION_ABSENT
            )
            route.authz_state = authz_state
            route.authz_type = authz_type
            route.ownership_checks = ownership_checks
            route.line_end = self._get_function_end_line(node)

            # Classify sensitive operation with DB mutation support
            db_mutated = self._detect_db_mutation(node)
            is_sensitive, sens_evidence = self._evaluate_sensitive_operation(
                route.method, route.path, node.name, node.lineno, db_mutated
            )
            route.is_sensitive = is_sensitive
            route.sensitive_evidence = sens_evidence

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

        method: Optional[str] = None
        if method_name in HTTP_METHODS:
            method = method_name.upper()
        elif method_name in {"api_route", "route"}:
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

        return RouteDefinition(
            method=method,
            path=path,
            handler_name=func_node.name,
            line_start=func_node.lineno,
            line_end=func_node.lineno,
            app_var=app_var,
            is_sensitive=False,  # Evaluated in _analyze_function
            is_async=is_async,
        )

    # ── 6. Semantic Authorization, Rejection Paths & Ownership ─────────────

    def _find_semantic_authz_and_ownership(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> Tuple[List[str], List[str], List[ResourceOwnershipCheck], AuthorizationType, AuthorizationState]:
        """
        Analyze AST nodes inside the function (and local helpers) for semantic authorization:
        1. Compare operations validating resource ownership (order.user_id == user.id).
        2. Raise statements rejecting with 401/403 HTTP status.
        3. Database queries constraining ownership (filter(Model.user_id == user.id)).
        4. Resolved helper function calls (ignoring empty mock functions).
        5. Role and permission checks.
        """
        checks: List[str] = []
        rejections: List[str] = []
        ownership_checks: List[ResourceOwnershipCheck] = []
        authz_type = AuthorizationType.UNKNOWN
        authz_state = AuthorizationState.AUTHORIZATION_ABSENT

        # Check for rejection statements (HTTP 401 / 403)
        for child in ast.walk(func_node):
            if isinstance(child, ast.Raise) and child.exc:
                exc_str = ast.unparse(child.exc) if hasattr(ast, "unparse") else ""
                exc_lower = exc_str.lower()
                if "403" in exc_lower or "forbidden" in exc_lower:
                    rejections.append(f"403-rejection: {exc_str[:60]}")
                elif "401" in exc_lower or "unauthorized" in exc_lower:
                    rejections.append(f"401-rejection: {exc_str[:60]}")

            # ── a. Explicit comparisons (e.g. order.user_id != user.id) ────
            elif isinstance(child, ast.Compare):
                expr_str = ast.unparse(child) if hasattr(ast, "unparse") else ""
                expr_lower = expr_str.lower()

                has_user = any(k in expr_lower for k in [
                    "user", "sub", "uid", "principal", "account", "current_user", "caller_id"
                ])
                has_owner = any(k in expr_lower for k in [
                    "owner", "id", "created_by", "belong", "customer_id", "author"
                ])

                if has_user and has_owner:
                    checks.append(f"ownership-check: {expr_str[:60]}")
                    authz_type = AuthorizationType.USER_OWNERSHIP
                    authz_state = AuthorizationState.AUTHORIZATION_PRESENT

                    # Create structured ResourceOwnershipCheck
                    left_str = ast.unparse(child.left) if hasattr(ast, "unparse") else "resource"
                    comp_op = type(child.ops[0]).__name__ if child.ops else "=="
                    ownership_checks.append(ResourceOwnershipCheck(
                        resource_id_symbol=left_str,
                        principal_id_symbol="user.id",
                        comparison_operator=comp_op,
                        has_rejection_branch=bool(rejections),
                        location=SourceLocation(
                            file_path=self.file_path,
                            start_line=child.lineno,
                            end_line=child.lineno,
                            snippet=expr_str,
                        ),
                        is_verified=True,
                        evidence_text=f"Direct ownership validation expression: {expr_str}",
                    ))
                elif any(k in expr_lower for k in ["role", "roles", "admin", "is_admin", "permission", "scope"]):
                    checks.append(f"role-check: {expr_str[:60]}")
                    if authz_type == AuthorizationType.UNKNOWN:
                        authz_type = AuthorizationType.ROLE_CHECK
                    authz_state = AuthorizationState.AUTHORIZATION_PRESENT

            # ── b. Database query ownership filters ───────────────────────
            elif isinstance(child, ast.Call):
                call_name = self._resolve_call_name(child.func)
                call_lower = call_name.lower()

                if "filter" in call_lower or "where" in call_lower:
                    arg_str = " ".join(ast.unparse(a) for a in child.args) if hasattr(ast, "unparse") else ""
                    arg_lower = arg_str.lower()
                    if ("user" in arg_lower or "owner" in arg_lower) and "==" in arg_str:
                        checks.append(f"db-ownership-filter: {arg_str[:60]}")
                        authz_type = AuthorizationType.USER_OWNERSHIP
                        authz_state = AuthorizationState.AUTHORIZATION_PRESENT

                # ── c. Helper function call with body analysis ────────────
                base_name = call_name.split(".")[-1]
                if base_name in self.module_functions and base_name != func_node.name:
                    helper_func = self.module_functions[base_name]
                    is_real_helper, helper_checks, helper_rejections = self._analyze_helper_function(helper_func)

                    if is_real_helper:
                        checks.extend(helper_checks)
                        rejections.extend(helper_rejections)
                        if any("ownership" in c for c in helper_checks):
                            authz_type = AuthorizationType.USER_OWNERSHIP
                            authz_state = AuthorizationState.AUTHORIZATION_PRESENT
                        elif helper_checks and authz_state != AuthorizationState.AUTHORIZATION_PRESENT:
                            authz_type = AuthorizationType.PERMISSION_CHECK
                            authz_state = AuthorizationState.AUTHORIZATION_PRESENT

        return (
            list(dict.fromkeys(checks)),
            list(dict.fromkeys(rejections)),
            ownership_checks,
            authz_type,
            authz_state,
        )

    def _analyze_helper_function(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> Tuple[bool, List[str], List[str]]:
        """
        Interprocedural helper inspection:
        Verifies if helper is a real authorization guard or an empty mock (def verify(): pass).
        """
        # Check if function body is non-trivial (not just 'pass' or docstring)
        non_trivial_stmts = [
            s for s in func.body
            if not isinstance(s, ast.Pass) and not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
        ]
        if not non_trivial_stmts:
            return False, [], []  # Empty mock! Must NOT count as authorization evidence

        helper_checks: List[str] = []
        helper_rejections: List[str] = []

        for child in ast.walk(func):
            if isinstance(child, ast.Raise) and child.exc:
                exc_str = ast.unparse(child.exc) if hasattr(ast, "unparse") else ""
                exc_lower = exc_str.lower()
                if "403" in exc_lower or "forbidden" in exc_lower:
                    helper_rejections.append(f"helper-403: {func.name}")
                elif "401" in exc_lower or "unauthorized" in exc_lower:
                    helper_rejections.append(f"helper-401: {func.name}")

            elif isinstance(child, ast.Compare):
                expr_str = ast.unparse(child) if hasattr(ast, "unparse") else ""
                expr_lower = expr_str.lower()
                if any(k in expr_lower for k in ["user", "sub", "uid"]) and any(k in expr_lower for k in ["owner", "id"]):
                    helper_checks.append(f"helper-ownership: {func.name}")
                elif any(k in expr_lower for k in ["role", "permission", "admin"]):
                    helper_checks.append(f"helper-role: {func.name}")

            elif isinstance(child, ast.Return) and child.value:
                ret_str = ast.unparse(child.value) if hasattr(ast, "unparse") else ""
                ret_lower = ret_str.lower()
                if any(k in ret_lower for k in ["owner", "user", "authorized", "permitted"]):
                    helper_checks.append(f"helper-authz-return: {func.name}")

        is_real = bool(helper_checks or helper_rejections)
        return is_real, helper_checks, helper_rejections

    # ── 7. Intra- and Inter-Procedural Data Flow Tracking ─────────────────

    def _build_local_data_flow(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        user_identity_params: Set[str],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Track local variable assignments to resolve dictionary construction,
        header merging, URL variables, HTTP client instances, and helper returns.
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

                # ── b. Helper call returning headers: headers = build_headers(...)
                elif isinstance(stmt.value, ast.Call):
                    call_name = self._resolve_call_name(stmt.value.func)
                    base_name = call_name.split(".")[-1]
                    if base_name in self.module_functions:
                        helper_node = self.module_functions[base_name]
                        dict_info = self._analyze_helper_return_dict(helper_node, user_identity_params, local_env)
                        if dict_info:
                            local_env[target_name] = dict_info

                # ── c. Variable alias: req_headers = headers ──────────────────────
                elif isinstance(stmt.value, ast.Name):
                    source_var = stmt.value.id
                    if source_var in local_env:
                        local_env[target_name] = dict(local_env[source_var])
                    elif source_var in user_identity_params:
                        local_env[target_name] = {"is_user_identity": True}

                # ── d. String constant or concatenated URL ────────────────────────
                elif isinstance(stmt.value, (ast.Constant, ast.JoinedStr, ast.BinOp)):
                    url_val = self._resolve_string_expr(stmt.value, local_env)
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

    def _analyze_helper_return_dict(
        self,
        helper_func: ast.FunctionDef | ast.AsyncFunctionDef,
        user_identity_params: Set[str],
        caller_env: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Inspect a helper function to extract any dictionary returned as headers."""
        for child in ast.walk(helper_func):
            if isinstance(child, ast.Return) and isinstance(child.value, ast.Dict):
                return self._analyze_dict_node(child.value, user_identity_params, caller_env)
        return None

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
        provenance = IdentityProvenance.UNKNOWN

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

            key_str = self._resolve_string_expr(k, local_env)
            if not key_str:
                if isinstance(k, ast.Name):
                    key_str = k.id
                else:
                    continue

            key_lower = key_str.lower()
            headers.append(key_lower)

            val_unparsed = ast.unparse(v).lower() if hasattr(ast, "unparse") else ""
            flows_from_user_param = any(p.lower() in val_unparsed for p in user_identity_params)

            if key_lower == "authorization":
                has_auth = True
                if "jwt" in val_unparsed or "bearer" in val_unparsed or flows_from_user_param:
                    provenance = IdentityProvenance.USER_JWT_VERIFIED
            elif key_lower in SERVICE_CREDENTIAL_HEADERS:
                has_service_token = True
                if provenance == IdentityProvenance.UNKNOWN:
                    provenance = IdentityProvenance.SERVICE_CREDENTIAL
            elif key_lower in {"x-user-id", "x-user-role"}:
                has_user_id = True
                if not flows_from_user_param:
                    provenance = IdentityProvenance.UNVERIFIED_USER_HEADER

        return {
            "headers": headers,
            "has_auth": has_auth,
            "has_service_token": has_service_token,
            "has_user_id": has_user_id,
            "provenance": provenance,
        }

    # ── 8. HTTP Client Call Discovery ─────────────────────────────────────

    def _find_http_calls_with_data_flow(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        local_env: Dict[str, Any],
    ) -> List[HttpCallDefinition]:
        """Extract HTTP client calls, resolving headers, URLs, and client variables."""
        calls: List[HttpCallDefinition] = []
        known_clients: Set[str] = local_env.get("__client_instances__", set(self.client_instances))

        for stmt in ast.walk(func_node):
            if not isinstance(stmt, ast.Call):
                continue

            client_mod, method_name = self._resolve_http_call_target(stmt.func, known_clients)
            if not client_mod or not method_name:
                continue

            url = self._extract_call_url(stmt, local_env)
            passed_headers, has_auth, has_svc_token, has_uid, provenance = self._extract_call_headers(stmt, local_env)

            raw_code = ""
            if 0 < stmt.lineno <= len(self.source_lines):
                raw_code = redact_secrets(self.source_lines[stmt.lineno - 1].strip())

            calls.append(HttpCallDefinition(
                method=method_name.upper(),
                url=url,
                line=stmt.lineno,
                passed_headers=passed_headers,
                has_authorization_header=has_auth,
                has_service_token=has_svc_token,
                has_user_id_header=has_uid,
                client_module=client_mod,
                raw_code=raw_code,
                provenance=provenance,
            ))

        return calls

    def _resolve_http_call_target(
        self,
        func_expr: ast.expr,
        known_clients: Set[str],
    ) -> Tuple[Optional[str], Optional[str]]:
        """Identify if a Call node is an outgoing HTTP client call."""
        if not isinstance(func_expr, ast.Attribute):
            if isinstance(func_expr, ast.Name):
                aliased = self.import_aliases.get(func_expr.id, func_expr.id)
                parts = aliased.split(".")
                if len(parts) >= 2 and parts[-2] in HTTP_CLIENT_MODULES and parts[-1].lower() in HTTP_METHODS:
                    return parts[-2], parts[-1].lower()
            return None, None

        method_name = func_expr.attr.lower()
        if method_name not in HTTP_METHODS and method_name != "request":
            return None, None

        base = func_expr.value

        if isinstance(base, ast.Name):
            var_name = base.id
            if var_name in HTTP_CLIENT_MODULES:
                return var_name, method_name
            if var_name in self.import_aliases:
                aliased = self.import_aliases[var_name]
                if any(mod in aliased for mod in HTTP_CLIENT_MODULES):
                    return aliased, method_name
            if var_name in known_clients or "client" in var_name.lower() or "session" in var_name.lower():
                return "client_instance", method_name

        if isinstance(base, ast.Attribute):
            full_path = self._resolve_call_name(base)
            for mod in HTTP_CLIENT_MODULES:
                if mod in full_path:
                    return mod, method_name

        return None, None

    def _extract_call_url(self, call_node: ast.Call, local_env: Dict[str, Any]) -> str:
        """Extract URL from first argument or 'url' keyword."""
        if call_node.args:
            url_val = self._resolve_string_expr(call_node.args[0], local_env)
            if url_val:
                return url_val
        for kw in call_node.keywords:
            if kw.arg == "url":
                url_val = self._resolve_string_expr(kw.value, local_env)
                if url_val:
                    return url_val
        return "<dynamic>"

    def _extract_call_headers(
        self,
        call_node: ast.Call,
        local_env: Dict[str, Any],
    ) -> Tuple[List[str], bool, bool, bool, IdentityProvenance]:
        """Extract header names and identity flags from headers argument."""
        headers_expr: Optional[ast.expr] = None
        for kw in call_node.keywords:
            if kw.arg == "headers":
                headers_expr = kw.value
                break

        if not headers_expr:
            return [], False, False, False, IdentityProvenance.NO_IDENTITY

        if isinstance(headers_expr, ast.Dict):
            info = self._analyze_dict_node(headers_expr, set(), local_env)
            return (
                info["headers"],
                info["has_auth"],
                info["has_service_token"],
                info["has_user_id"],
                info["provenance"],
            )

        if isinstance(headers_expr, ast.Name):
            var_name = headers_expr.id
            if var_name in local_env and isinstance(local_env[var_name], dict):
                info = local_env[var_name]
                return (
                    info.get("headers", []),
                    info.get("has_auth", False),
                    info.get("has_service_token", False),
                    info.get("has_user_id", False),
                    info.get("provenance", IdentityProvenance.UNKNOWN),
                )
            return [f"<var:{var_name}>"], False, False, False, IdentityProvenance.UNKNOWN

        return ["<dynamic>"], False, False, False, IdentityProvenance.UNKNOWN

    # ── 9. State Mutation & DB Analysis ───────────────────────────────────

    def _detect_db_mutation(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Detect direct database mutations (db.delete, db.commit, update_one, etc.)."""
        for child in ast.walk(func_node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                attr_lower = child.func.attr.lower()
                if attr_lower in DB_MUTATION_METHODS:
                    base_name = self._resolve_call_name(child.func.value).lower()
                    if any(k in base_name for k in ["db", "session", "collection", "cursor", "repo", "query"]):
                        return True
        return False

    def _evaluate_sensitive_operation(
        self,
        method: str,
        path: str,
        handler_name: str,
        line: int,
        db_mutated: bool,
    ) -> Tuple[bool, Optional[SensitiveOperationEvidence]]:
        """
        Precise sensitive operation reasoning:
        Read-only methods (GET, HEAD, OPTIONS) are NEVER sensitive mutations.
        Mutating methods (POST, PUT, PATCH, DELETE) are sensitive if they perform
        a critical business action or execute direct DB state mutation.
        """
        method_upper = method.upper()
        if method_upper in READONLY_HTTP_METHODS:
            return False, None

        is_sensitive = False
        evidence_text = ""

        if method_upper == "DELETE":
            is_sensitive = True
            evidence_text = f"HTTP DELETE method on '{path}' performs destructive resource deletion."
        else:
            combined = f"{path.lower()} {handler_name.lower()}"
            matched_kw = next((kw for kw in SENSITIVE_ACTION_KEYWORDS if kw in combined), None)
            if matched_kw:
                is_sensitive = True
                evidence_text = f"Mutating HTTP {method_upper} matches critical sensitive action keyword '{matched_kw}'."
            elif db_mutated:
                is_sensitive = True
                evidence_text = f"Mutating HTTP {method_upper} executes direct database state mutation."

        if not is_sensitive:
            return False, None

        evidence = SensitiveOperationEvidence(
            operation_type="state_mutation",
            http_method=method_upper,
            target_path=path,
            handler_name=handler_name,
            location=SourceLocation(
                file_path=self.file_path,
                start_line=line,
                end_line=line,
                snippet=f"{method_upper} {path}",
            ),
            confidence="HIGH",
            evidence_text=evidence_text,
            db_mutation_detected=db_mutated,
        )
        return True, evidence

    # ── 10. Expression Resolvers ──────────────────────────────────────────

    def _resolve_string_expr(self, node: ast.expr, local_env: Optional[Dict[str, Any]] = None) -> str:
        """Resolve string expression with variable, f-string, and concatenation support."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value

        if isinstance(node, ast.Name):
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
        call_name = self._resolve_call_name(node.func)
        base = call_name.split(".")[-1]
        if base in {"Depends", "Security"}:
            if node.args:
                return self._resolve_call_name(node.args[0])
            for kw in node.keywords:
                if kw.arg == "dependency":
                    return self._resolve_call_name(kw.value)
        return None

    def _is_header_param(self, node: ast.expr) -> bool:
        if not isinstance(node, ast.Call):
            return False
        return self._resolve_call_name(node.func).split(".")[-1] == "Header"

    def _is_auth_dependency(self, name: str) -> bool:
        lower = name.lower()
        return any(k in lower for k in AUTH_DEP_KEYWORDS)

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
        if hasattr(node, "end_lineno") and node.end_lineno:
            return node.end_lineno
        last_line = node.lineno
        for child in ast.walk(node):
            if hasattr(child, "lineno") and child.lineno > last_line:
                last_line = child.lineno
        return last_line


# ─────────────────────────── File Analysis ────────────────────────────────

def analyze_file(file_path: Path, workspace_root: Path) -> FileAnalysisResult:
    """Analyze a single Python file using FastAPIVisitor with two-pass cataloging."""
    relative_path = str(file_path.relative_to(workspace_root))
    result = FileAnalysisResult(file_path=relative_path)

    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
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
    visitor = FastAPIVisitor(source_lines, file_path=relative_path)

    # Pass 1: Catalog module functions for interprocedural inspection
    visitor.catalog_module_functions(tree)

    # Pass 2: Full AST traversal
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
