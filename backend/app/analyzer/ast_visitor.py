"""
Python AST Visitor — Phase 3
==============================
Parses Python source files using the standard `ast` module to extract:
- FastAPI application instances (FastAPI(), APIRouter())
- Route decorators (@app.get, @app.post, @router.delete, etc.)
- FastAPI Depends() and Security() guards
- Outgoing HTTP client calls (httpx, requests, aiohttp)
- Header dictionaries passed to HTTP calls
- Identity-related headers (Authorization, X-User-Id, X-Service-Token, etc.)
- String URL literals
- Function definitions and line ranges

SECURITY: Never executes uploaded code. Uses only ast.parse() on string content.
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

# HTTP method names for route decorators
HTTP_METHODS: frozenset[str] = frozenset({"get", "post", "put", "delete", "patch", "head", "options"})

# FastAPI app variable patterns
FASTAPI_APP_PATTERNS: frozenset[str] = frozenset({"FastAPI", "APIRouter"})

# Authentication dependency indicators
AUTH_DEPENDENCY_PATTERNS: List[str] = [
    "oauth2passwordbearer", "httpbearer", "httpauthorizationscheme",
    "get_current_user", "get_current_active_user", "get_user",
    "verify_token", "verify_jwt", "require_auth", "authenticated_user",
    "auth_required", "login_required", "jwt_required",
    "security", "authenticate",
]

# Authorization check indicators
AUTHZ_PATTERNS: List[str] = [
    "verify_user_owner", "verify_owner", "check_ownership",
    "require_role", "verify_role", "has_role", "check_role",
    "is_admin", "require_admin", "verify_admin",
    "check_permission", "has_permission", "require_permission",
    "verify_user_jwt", "verify_service_key", "verify_service_token",
    "ownership", "authorize", "authorization",
]

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
})

# Service credential headers
SERVICE_CREDENTIAL_HEADERS: frozenset[str] = frozenset({
    "x-service-key",
    "x-service-token",
    "x-api-key",
    "x-internal-key",
    "x-service-secret",
    "x-internal-token",
})

# HTTP client libraries and their call patterns
HTTP_CLIENT_MODULES: frozenset[str] = frozenset({"httpx", "requests", "aiohttp"})

# Sensitive operation keywords
SENSITIVE_KEYWORDS: List[str] = [
    "refund", "delete", "admin", "password", "role", "grant",
    "reset", "revoke", "sudo", "privilege", "payment", "charge",
    "withdraw", "transfer", "debit", "credit", "void", "cancel_payment",
    "token_refresh", "password_reset", "user_delete", "account_delete",
]

# Secret patterns for redaction
SECRET_PATTERNS: List[re.Pattern] = [
    re.compile(r"bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE),
    re.compile(r"['\"]?(?:password|secret|key|token|api_key)\s*['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE),
    re.compile(r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*"),  # JWT
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI-style keys
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
    depends: List[str] = field(default_factory=list)        # Depends() arg names
    auth_deps: List[str] = field(default_factory=list)      # Auth-related deps
    authz_checks: List[str] = field(default_factory=list)   # Explicit authz checks found in body
    has_authentication: bool = False
    is_sensitive: bool = False
    app_var: str = "app"                                     # Variable name of the FastAPI app/router


@dataclass
class HttpCallDefinition:
    """Represents a discovered outgoing HTTP client call."""
    method: str               # GET, POST, etc.
    url: str                  # URL string (may be partial/template)
    line: int
    passed_headers: List[str] = field(default_factory=list)
    has_authorization_header: bool = False
    has_service_token: bool = False
    has_user_id_header: bool = False
    client_module: str = ""   # "httpx", "requests", "aiohttp"
    raw_code: str = ""        # Source line for evidence


@dataclass
class FastAPIAppDefinition:
    """Represents a discovered FastAPI() or APIRouter() instantiation."""
    var_name: str   # e.g., "app" or "router"
    type_name: str  # "FastAPI" or "APIRouter"
    line: int


@dataclass
class FileAnalysisResult:
    """Complete analysis result for a single Python file."""
    file_path: str
    app_definitions: List[FastAPIAppDefinition] = field(default_factory=list)
    routes: List[RouteDefinition] = field(default_factory=list)
    http_calls: List[HttpCallDefinition] = field(default_factory=list)
    import_aliases: Dict[str, str] = field(default_factory=dict)  # alias -> module
    parse_error: Optional[str] = None
    parse_error_line: Optional[int] = None


# ─────────────────────────── Secret Redaction ─────────────────────────────

def redact_secrets(code: str) -> str:
    """
    Replace potential secrets/tokens in code snippets with [REDACTED_SECRET].
    Applied before storing evidence or rendering in UI.
    """
    for pattern in SECRET_PATTERNS:
        code = pattern.sub("[REDACTED_SECRET]", code)
    return code


# ─────────────────────────── AST Visitor ──────────────────────────────────

class FastAPIVisitor(ast.NodeVisitor):
    """
    Custom AST NodeVisitor that extracts FastAPI routes, dependencies,
    and outgoing HTTP calls from Python source code.

    Never executes any code — operates purely on AST structure.
    """

    def __init__(self, source_lines: List[str]) -> None:
        self.source_lines = source_lines
        self.app_definitions: List[FastAPIAppDefinition] = []
        self.routes: List[RouteDefinition] = []
        self.http_calls: List[HttpCallDefinition] = []
        self.import_aliases: Dict[str, str] = {}  # alias -> module/name

        # Track known FastAPI app/router variable names
        self._fastapi_vars: Set[str] = set()
        self._current_function: Optional[str] = None
        self._current_function_routes: List[RouteDefinition] = []

    # ── Import Analysis ──────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        """Track import aliases for HTTP client library detection."""
        for alias in node.names:
            key = alias.asname or alias.name
            self.import_aliases[key] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from-import aliases."""
        module = node.module or ""
        for alias in node.names:
            key = alias.asname or alias.name
            self.import_aliases[key] = f"{module}.{alias.name}"
        self.generic_visit(node)

    # ── FastAPI App Detection ────────────────────────────────────────────

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect FastAPI() and APIRouter() instantiation assignments."""
        if isinstance(node.value, ast.Call):
            func = node.value.func
            type_name = None

            if isinstance(func, ast.Name) and func.id in FASTAPI_APP_PATTERNS:
                type_name = func.id
            elif isinstance(func, ast.Attribute) and func.attr in FASTAPI_APP_PATTERNS:
                type_name = func.attr

            if type_name:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._fastapi_vars.add(target.id)
                        self.app_definitions.append(FastAPIAppDefinition(
                            var_name=target.id,
                            type_name=type_name,
                            line=node.lineno,
                        ))

        self.generic_visit(node)

    # ── Route Decorator Analysis ─────────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Inspect function definitions for FastAPI route decorators."""
        self._analyze_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Inspect async function definitions for FastAPI route decorators."""
        self._analyze_function(node)

    def _analyze_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Core function analysis for routes and HTTP calls."""
        routes_found: List[RouteDefinition] = []

        # ── a. Detect route decorators ───────────────────────────────────
        for decorator in node.decorator_list:
            route = self._extract_route_decorator(decorator, node)
            if route:
                routes_found.append(route)

        # ── b. Detect Depends() and Security() in function parameters ────
        depends_names: List[str] = []
        auth_deps: List[str] = []

        for arg in node.args.defaults + node.args.kw_defaults:
            if arg is None:
                continue
            dep = self._extract_depends(arg)
            if dep:
                depends_names.append(dep)
                if self._is_auth_dependency(dep):
                    auth_deps.append(dep)

        for arg in node.args.args + node.args.kwonlyargs:
            # Check annotations for auth patterns
            if arg.annotation:
                ann_str = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
                if self._is_auth_dependency(ann_str):
                    auth_deps.append(ann_str)

        # ── c. Detect authorization checks in function body ──────────────
        authz_checks = self._find_authz_checks(node)

        # ── d. Detect HTTP client calls in function body ─────────────────
        http_calls = self._find_http_calls(node)
        self.http_calls.extend(http_calls)

        # ── e. Finalize route metadata ───────────────────────────────────
        for route in routes_found:
            route.depends = depends_names
            route.auth_deps = auth_deps
            route.authz_checks = authz_checks
            route.has_authentication = bool(auth_deps)
            route.line_end = self._get_function_end_line(node)
            self.routes.append(route)

        # ── f. Associate HTTP calls with most recent route ───────────────
        self.generic_visit(node)

    def _extract_route_decorator(
        self,
        decorator: ast.expr,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> Optional[RouteDefinition]:
        """
        Extract route info from @app.get("/path") style decorators.
        Returns RouteDefinition or None if not a route decorator.
        """
        if not isinstance(decorator, ast.Call):
            return None

        func = decorator.func
        method: Optional[str] = None
        app_var: str = "app"
        path: str = "/"

        # @app.get("/path") or @router.post("/path")
        if isinstance(func, ast.Attribute):
            attr = func.attr.lower()
            if attr in HTTP_METHODS:
                method = attr.upper()
                if isinstance(func.value, ast.Name):
                    app_var = func.value.id

        if method is None:
            return None

        # Extract path argument (first positional arg)
        if decorator.args:
            first_arg = decorator.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                path = first_arg.value
        elif decorator.keywords:
            for kw in decorator.keywords:
                if kw.arg == "path" and isinstance(kw.value, ast.Constant):
                    path = kw.value.value

        # Check if sensitive
        is_sensitive = self._is_sensitive_operation(method, path)

        return RouteDefinition(
            method=method,
            path=path,
            handler_name=func_node.name,
            line_start=func_node.lineno,
            line_end=func_node.lineno,  # Updated later
            app_var=app_var,
            is_sensitive=is_sensitive,
        )

    def _extract_depends(self, node: ast.expr) -> Optional[str]:
        """
        Extract the dependency function name from Depends(func) or Security(func).
        Returns the dependency name as a string, or None.
        """
        if not isinstance(node, ast.Call):
            return None

        func = node.func
        call_name = ""

        if isinstance(func, ast.Name):
            call_name = func.id
        elif isinstance(func, ast.Attribute):
            call_name = func.attr

        if call_name.lower() not in {"depends", "security"}:
            return None

        # Extract the dependency argument
        if node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Name):
                return arg.id
            elif isinstance(arg, ast.Attribute):
                return f"{ast.unparse(arg)}" if hasattr(ast, "unparse") else arg.attr
        elif node.keywords:
            for kw in node.keywords:
                if kw.arg == "dependency" and isinstance(kw.value, ast.Name):
                    return kw.value.id

        return call_name  # Return the Depends name itself as fallback

    def _is_auth_dependency(self, dep_name: str) -> bool:
        """Check if a dependency name suggests an authentication/authorization guard."""
        lower = dep_name.lower()
        return any(pattern in lower for pattern in AUTH_DEPENDENCY_PATTERNS + AUTHZ_PATTERNS)

    def _find_authz_checks(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> List[str]:
        """
        Find explicit authorization checks in function body.
        Looks for function calls matching authz patterns.
        """
        checks: List[str] = []
        for child in ast.walk(func_node):
            if isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if name and any(p in name.lower() for p in AUTHZ_PATTERNS):
                    checks.append(name)
            # Also check IF conditions for ownership patterns
            if isinstance(child, (ast.Compare, ast.BoolOp)):
                expr_str = ast.unparse(child) if hasattr(ast, "unparse") else ""
                if any(p in expr_str.lower() for p in ["owner", "ownership", "verify_user"]):
                    checks.append(f"if-check: {expr_str[:60]}")
        return list(dict.fromkeys(checks))  # Deduplicate preserving order

    def _find_http_calls(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> List[HttpCallDefinition]:
        """
        Find all outgoing HTTP client calls (httpx, requests, aiohttp) in function body.
        """
        calls: List[HttpCallDefinition] = []

        for child in ast.walk(func_node):
            if not isinstance(child, ast.Call):
                continue

            call = self._extract_http_call(child)
            if call:
                calls.append(call)

        return calls

    def _extract_http_call(self, node: ast.Call) -> Optional[HttpCallDefinition]:
        """
        Attempt to extract an HTTP client call from a Call AST node.
        Handles: httpx.get/post/put/delete/patch, requests.get/post,
                 httpx.AsyncClient.get, etc.
        """
        func = node.func
        module_name = ""
        method_name = ""

        if isinstance(func, ast.Attribute):
            attr = func.attr.lower()
            if attr in HTTP_METHODS or attr in {"request", "send"}:
                method_name = attr
                # Check the object
                if isinstance(func.value, ast.Name):
                    module_name = func.value.id
                elif isinstance(func.value, ast.Attribute):
                    module_name = ast.unparse(func.value) if hasattr(ast, "unparse") else func.value.attr
                else:
                    module_name = ast.unparse(func.value) if hasattr(ast, "unparse") else ""
        elif isinstance(func, ast.Name):
            # Standalone function call — unlikely for HTTP but handle it
            return None

        # Check if this is actually an HTTP client call
        is_http_client = False
        client_module = ""
        for mod in HTTP_CLIENT_MODULES:
            if mod in module_name.lower():
                is_http_client = True
                client_module = mod
                break

        if not is_http_client:
            return None

        # Extract URL (first positional argument usually)
        url = ""
        if node.args:
            first_arg = node.args[0]
            url = self._extract_string_value(first_arg)
        else:
            for kw in node.keywords:
                if kw.arg == "url":
                    url = self._extract_string_value(kw.value)
                    break

        if not url:
            url = "<dynamic>"

        # Extract headers
        passed_headers: List[str] = []
        has_auth = False
        has_service_token = False
        has_user_id = False

        for kw in node.keywords:
            if kw.arg == "headers":
                headers = self._extract_headers_dict(kw.value)
                passed_headers.extend(headers)
                for h in headers:
                    h_lower = h.lower()
                    if h_lower == "authorization":
                        has_auth = True
                    elif h_lower in SERVICE_CREDENTIAL_HEADERS:
                        has_service_token = True
                    elif h_lower in {"x-user-id", "x-user-role"}:
                        has_user_id = True

        # Get raw source line
        raw_code = ""
        if self.source_lines and node.lineno <= len(self.source_lines):
            raw_code = self.source_lines[node.lineno - 1].strip()
            raw_code = redact_secrets(raw_code)

        return HttpCallDefinition(
            method=method_name.upper() if method_name not in {"request", "send"} else "GET",
            url=url,
            line=node.lineno,
            passed_headers=passed_headers,
            has_authorization_header=has_auth,
            has_service_token=has_service_token,
            has_user_id_header=has_user_id,
            client_module=client_module,
            raw_code=raw_code,
        )

    def _extract_string_value(self, node: ast.expr) -> str:
        """Extract string value from an AST node if it's a constant string."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.JoinedStr):
            # f-string — extract the template parts we can
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                else:
                    parts.append("{...}")
            return "".join(parts)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._extract_string_value(node.left)
            right = self._extract_string_value(node.right)
            return f"{left}{right}"
        return ""

    def _extract_headers_dict(self, node: ast.expr) -> List[str]:
        """
        Extract header names from a dictionary literal.
        Returns list of header name strings (lowercase).
        """
        headers: List[str] = []

        if isinstance(node, ast.Dict):
            for key in node.keys:
                if key is None:
                    continue
                key_str = self._extract_string_value(key)
                if key_str:
                    headers.append(key_str)
                elif isinstance(key, ast.Name):
                    headers.append(key.id)

        elif isinstance(node, ast.Name):
            # Variable reference — we can't resolve it statically
            headers.append(f"<var:{node.id}>")

        elif isinstance(node, ast.Call):
            # dict() call or dict.update pattern — capture what we can
            pass

        return headers

    def _is_sensitive_operation(self, method: str, path: str) -> bool:
        """Check if an endpoint is a sensitive state-changing operation."""
        if method.upper() == "DELETE":
            return True
        path_lower = path.lower()
        return any(kw in path_lower for kw in SENSITIVE_KEYWORDS)

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Get the function name from a Call node."""
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            return func.attr
        return None

    def _get_function_end_line(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
        """Get the last line number of a function definition."""
        return max(
            (getattr(child, "lineno", node.lineno) for child in ast.walk(node)),
            default=node.lineno,
        )


# ─────────────────────────── Public API ───────────────────────────────────

def analyze_file(file_path: Path, workspace_root: Path) -> FileAnalysisResult:
    """
    Parse a single Python file and extract FastAPI routes, HTTP calls, etc.

    Args:
        file_path: Absolute path to the Python file.
        workspace_root: Root of the extracted workspace (for relative paths).

    Returns:
        FileAnalysisResult with all extracted metadata.
    """
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
    result.routes = visitor.routes
    result.http_calls = visitor.http_calls
    result.import_aliases = visitor.import_aliases

    return result


def analyze_files(python_files: List[Path], workspace_root: Path) -> Tuple[List[FileAnalysisResult], List[Dict]]:
    """
    Analyze multiple Python files.

    Args:
        python_files: List of Python file paths.
        workspace_root: Root workspace directory.

    Returns:
        Tuple of (successful results, parse errors list).
    """
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

    logger.info(
        "AST analysis: %d files parsed, %d errors",
        len(results),
        len(errors),
    )

    return results, errors
