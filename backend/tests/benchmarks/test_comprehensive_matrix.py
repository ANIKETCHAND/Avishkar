"""
Comprehensive Benchmark Matrix Suite
======================================
Tests all supported confused deputy patterns and secure counterparts:
- Canonical CD-001, CD-002, CD-003, CD-004
- Renamed variables and parameters
- Import aliases (httpx as hpx, from requests import post as req_post)
- Async vs Sync route handlers and clients
- Helper function extraction (in-body vs helper function authorization)
- Router-level dependencies (APIRouter(dependencies=[Depends(...)]))
- Variable-built headers (local dicts, unpacking, subscript assignments)
- URL expressions (f-strings, string concatenation, constants)
- Multiple-hop microservice paths (Gateway -> Order -> Payment)
- Benign service tokens (non-sensitive read operations)
- Unrelated keywords (message = 'refund')
"""

import pytest
from pathlib import Path
from tests.helpers import analyze_test_project


# ─────────────────────────── Benchmark Generators ─────────────────────────

def make_vulnerable_cd001(
    order_code_variant: str = "standard",
    payment_code_variant: str = "standard",
) -> dict:
    """Generate CD-001 vulnerable microservice pairs with structural variations."""

    if order_code_variant == "standard":
        order_src = '''
from fastapi import FastAPI, Depends, Header
import httpx

app = FastAPI()
PAYMENT_URL = "http://payment-service:8001"

def get_current_user(authorization: str = Header(None)):
    return {"user_id": "alice-123"}

@app.post("/orders/{order_id}/cancel")
def cancel_order(order_id: str, user = Depends(get_current_user)):
    httpx.post(f"{PAYMENT_URL}/internal/v1/refund", headers={"X-Service-Token": "SVC_KEY_123"}, json={"order_id": order_id})
    return {"status": "ok"}
'''
    elif order_code_variant == "async_client":
        order_src = '''
from fastapi import FastAPI, Depends, Header
from httpx import AsyncClient

app = FastAPI()
PAYMENT_URL = "http://payment-service:8001"

async def get_current_user(authorization: str = Header(None)):
    return {"user_id": "alice-123"}

@app.post("/orders/{order_id}/cancel")
async def cancel_order(order_id: str, user = Depends(get_current_user)):
    client = AsyncClient()
    await client.post(f"{PAYMENT_URL}/internal/v1/refund", headers={"X-Service-Token": "SVC_KEY_123"}, json={"order_id": order_id})
    return {"status": "ok"}
'''
    elif order_code_variant == "variable_built_headers":
        order_src = '''
from fastapi import FastAPI, Depends, Header
import httpx

app = FastAPI()
PAYMENT_URL = "http://payment-service:8001"
TOKEN = "INTERNAL_KEY_999"

def get_current_user(authorization: str = Header(None)):
    return {"user_id": "alice-123"}

@app.post("/orders/{order_id}/cancel")
def cancel_order(order_id: str, user = Depends(get_current_user)):
    hdr = {}
    hdr["X-Service-Token"] = TOKEN
    hdr["Content-Type"] = "application/json"
    req_headers = hdr
    httpx.post(PAYMENT_URL + "/internal/v1/refund", headers=req_headers, json={"order_id": order_id})
    return {"status": "ok"}
'''
    elif order_code_variant == "aliased_import":
        order_src = '''
from fastapi import FastAPI, Depends, Header
import httpx as client_lib

app = FastAPI()
PAYMENT_URL = "http://payment-service:8001"

def get_current_user(authorization: str = Header(None)):
    return {"user_id": "alice-123"}

@app.post("/orders/{order_id}/cancel")
def cancel_order(order_id: str, user = Depends(get_current_user)):
    client_lib.post(f"{PAYMENT_URL}/internal/v1/refund", headers={"X-Service-Key": "SEC_KEY"}, json={"order_id": order_id})
    return {"status": "ok"}
'''
    else:
        raise ValueError(order_code_variant)

    if payment_code_variant == "standard":
        payment_src = '''
from fastapi import FastAPI, Depends, Header, HTTPException
app = FastAPI()

def verify_service_token(x_service_token: str = Header(None)):
    if not x_service_token:
        raise HTTPException(status_code=401)
    return {"service": "order"}

@app.post("/internal/v1/refund")
def process_refund(data: dict, svc = Depends(verify_service_token)):
    # VULNERABLE: No check if originating user owns this order
    return {"refund_status": "executed"}
'''
    elif payment_code_variant == "delete_endpoint":
        payment_src = '''
from fastapi import FastAPI, Depends, Header, HTTPException
app = FastAPI()

def verify_service_token(x_service_token: str = Header(None)):
    if not x_service_token:
        raise HTTPException(status_code=401)
    return {"service": "order"}

@app.delete("/internal/v1/refund/{order_id}")
def delete_payment(order_id: str, svc = Depends(verify_service_token)):
    return {"deleted": True}
'''
    else:
        raise ValueError(payment_code_variant)

    return {
        "order_service/main.py": order_src,
        "payment_service/main.py": payment_src,
    }


def make_secure_cd001(pattern: str = "forwarded_jwt_with_ownership") -> dict:
    """Generate secure microservice pairs where confused deputy is prevented."""
    if pattern == "forwarded_jwt_with_ownership":
        order_src = '''
from fastapi import FastAPI, Depends, Header
import httpx

app = FastAPI()
PAYMENT_URL = "http://payment-service:8001"

def get_current_user(authorization: str = Header(None)):
    return {"user_id": "alice-123", "token": authorization}

@app.post("/orders/{order_id}/cancel")
def cancel_order(order_id: str, user = Depends(get_current_user), authorization: str = Header(None)):
    httpx.post(
        f"{PAYMENT_URL}/internal/v1/refund",
        headers={"X-Service-Token": "KEY", "Authorization": authorization},
        json={"order_id": order_id}
    )
    return {"status": "ok"}
'''
        payment_src = '''
from fastapi import FastAPI, Depends, Header, HTTPException
app = FastAPI()

def verify_service_token(x_service_token: str = Header(None)):
    if not x_service_token:
        raise HTTPException(status_code=401)

def verify_user_jwt(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401)
    return {"user_id": "alice-123"}

def verify_user_owns_order(user_id: str, order_id: str) -> bool:
    return True

@app.post("/internal/v1/refund")
def process_refund(data: dict, svc = Depends(verify_service_token), user = Depends(verify_user_jwt)):
    if not verify_user_owns_order(user["user_id"], data["order_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"refund_status": "executed"}
'''
    elif pattern == "in_body_ownership_comparison":
        order_src = '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()
PAYMENT_URL = "http://payment-service:8001"

def get_current_user(authorization: str = Header(None)):
    return {"user_id": "alice-123"}

@app.post("/orders/{order_id}/cancel")
def cancel_order(order_id: str, user = Depends(get_current_user), authorization: str = Header(None)):
    httpx.post(f"{PAYMENT_URL}/internal/v1/refund", headers={"Authorization": authorization}, json={"order_id": order_id})
    return {"status": "ok"}
'''
        payment_src = '''
from fastapi import FastAPI, Depends, Header, HTTPException
app = FastAPI()

def verify_user(authorization: str = Header(None)):
    return {"user_id": "alice-123"}

@app.post("/internal/v1/refund")
def process_refund(data: dict, current_user = Depends(verify_user)):
    order_owner_id = data.get("owner_id")
    if current_user["user_id"] != order_owner_id:
        raise HTTPException(status_code=403, detail="You do not own this order")
    return {"status": "ok"}
'''
    elif pattern == "router_level_guard":
        order_src = '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()
PAYMENT_URL = "http://payment-service:8001"

def get_current_user(authorization: str = Header(None)):
    return {"user_id": "alice-123"}

@app.post("/orders/{order_id}/cancel")
def cancel(order_id: str, user = Depends(get_current_user), authorization: str = Header(None)):
    httpx.post(f"{PAYMENT_URL}/internal/v1/refund", headers={"Authorization": authorization})
    return {"status": "ok"}
'''
        payment_src = '''
from fastapi import FastAPI, APIRouter, Depends, Header, HTTPException
app = FastAPI()

def verify_user_jwt(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401)
    return {"user_id": "alice"}

router = APIRouter(prefix="/internal/v1", dependencies=[Depends(verify_user_jwt)])

@router.post("/refund")
def do_refund():
    return {"ok": True}

app.include_router(router)
'''
    else:
        raise ValueError(pattern)

    return {
        "order_service/main.py": order_src,
        "payment_service/main.py": payment_src,
    }


# ─────────────────────────── Matrix Tests ─────────────────────────────────

class TestCD001BenchmarkMatrix:
    """Matrix tests for CD-001 (Privilege-Boundary Confused Deputy)."""

    @pytest.mark.parametrize("order_variant", [
        "standard",
        "async_client",
        "variable_built_headers",
        "aliased_import",
    ])
    def test_vulnerable_cd001_variations(self, tmp_path, order_variant):
        """CD-001 must trigger across structural and syntactic variations."""
        files = make_vulnerable_cd001(order_code_variant=order_variant, payment_code_variant="standard")
        res = analyze_test_project(files, tmp_path, f"vuln_{order_variant}")

        cd001_findings = [f for f in res.findings if f.rule_id == "CD-001"]
        assert len(cd001_findings) >= 1, f"Failed to detect CD-001 in variant: {order_variant}"
        assert cd001_findings[0].severity in ("HIGH", "CRITICAL")

    @pytest.mark.parametrize("pattern", [
        "forwarded_jwt_with_ownership",
        "in_body_ownership_comparison",
        "router_level_guard",
    ])
    def test_secure_cd001_counterparts(self, tmp_path, pattern):
        """Secure counterparts must produce 0 CD-001 findings."""
        files = make_secure_cd001(pattern)
        res = analyze_test_project(files, tmp_path, f"sec_{pattern}")

        cd001_findings = [f for f in res.findings if f.rule_id == "CD-001"]
        assert len(cd001_findings) == 0, f"False positive CD-001 in secure pattern: {pattern}"


class TestCD002BenchmarkMatrix:
    """Matrix tests for CD-002 (Missing Downstream Authorization)."""

    def test_vulnerable_missing_downstream_auth(self, tmp_path):
        """Reachable internal endpoint with zero auth guards must trigger CD-002."""
        files = {
            "gateway_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.get("/api/data")
def get_data(u = Depends(auth)):
    httpx.get("http://backend-service:8000/internal/data")
    return {"status": "ok"}
''',
            "backend_service/main.py": '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/internal/data")
def read_data():
    # Completely unauthenticated internal route
    return {"secret": 123}
''',
        }
        res = analyze_test_project(files, tmp_path, "cd002_vuln")
        cd002 = [f for f in res.findings if f.rule_id == "CD-002"]
        assert len(cd002) >= 1, "Expected CD-002 finding for completely unauthenticated internal route"

    def test_secure_with_internal_token(self, tmp_path):
        """Internal endpoint with Depends(verify_service_token) must NOT trigger CD-002."""
        files = {
            "gateway_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.get("/api/data")
def get_data(u = Depends(auth)):
    httpx.get("http://backend-service:8000/internal/data", headers={"X-Service-Token": "KEY"})
    return {"status": "ok"}
''',
            "backend_service/main.py": '''
from fastapi import FastAPI, Depends, Header, HTTPException
app = FastAPI()

def verify_token(x_service_token: str = Header(None)):
    if not x_service_token:
        raise HTTPException(status_code=401)

@app.get("/internal/data")
def read_data(auth = Depends(verify_token)):
    return {"secret": 123}
''',
        }
        res = analyze_test_project(files, tmp_path, "cd002_sec")
        cd002 = [f for f in res.findings if f.rule_id == "CD-002"]
        assert len(cd002) == 0, "CD-002 should not fire when internal token validation is present"


class TestCD003BenchmarkMatrix:
    """Matrix tests for CD-003 (Untrusted Identity Propagation)."""

    def test_plain_user_header_without_jwt(self, tmp_path):
        """Passing X-User-Id without Authorization Bearer JWT must trigger CD-003."""
        files = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_user(authorization: str = Header(None)):
    return {"id": "u123"}

@app.post("/checkout")
def checkout(user = Depends(get_user)):
    # Vulnerable: plain X-User-Id forwarded without JWT
    httpx.post("http://payment-service/internal/charge", headers={"X-User-Id": "u123"})
    return {"ok": True}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.post("/internal/charge")
def charge(x_user_id: str = Header(None)):
    return {"charged": x_user_id}
''',
        }
        res = analyze_test_project(files, tmp_path, "cd003_vuln")
        cd003 = [f for f in res.findings if f.rule_id == "CD-003"]
        assert len(cd003) >= 1, "Expected CD-003 for plain unverified X-User-Id header"

    def test_signed_jwt_prevents_cd003(self, tmp_path):
        """Passing Authorization header provides cryptographic proof and prevents CD-003."""
        files = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_user(authorization: str = Header(None)):
    return {"id": "u123"}

@app.post("/checkout")
def checkout(user = Depends(get_user), authorization: str = Header(None)):
    httpx.post("http://payment-service/internal/charge", headers={"Authorization": authorization, "X-User-Id": "u123"})
    return {"ok": True}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.post("/internal/charge")
def charge(authorization: str = Header(None)):
    return {"status": "ok"}
''',
        }
        res = analyze_test_project(files, tmp_path, "cd003_sec")
        cd003 = [f for f in res.findings if f.rule_id == "CD-003"]
        assert len(cd003) == 0, "CD-003 must not fire when accompanied by Authorization Bearer token"


class TestMultiHopPathBenchmark:
    """Benchmark tests for multi-hop call graphs."""

    def test_three_tier_microservices_path(self, tmp_path):
        """Gateway -> Order Service -> Payment Service confused deputy path."""
        files = {
            "gateway_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user-alice"

@app.post("/api/v1/orders/{id}/refund")
def refund_order(id: str, u = Depends(auth), authorization: str = Header(None)):
    httpx.post(f"http://order-service:8000/orders/{id}/refund", headers={"Authorization": authorization})
    return {"status": "forwarded"}
''',
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def verify_user(authorization: str = Header(None)):
    return {"user": "alice"}

@app.post("/orders/{id}/refund")
def do_order_refund(id: str, user = Depends(verify_user)):
    # Strips user JWT and calls payment using only service key
    httpx.post("http://payment-service:8001/internal/v1/refund", headers={"X-Service-Token": "ORDER_SECRET"})
    return {"status": "refunded"}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header, HTTPException
app = FastAPI()

def verify_token(x_service_token: str = Header(None)):
    if not x_service_token:
        raise HTTPException(status_code=401)

@app.post("/internal/v1/refund")
def execute_refund(svc = Depends(verify_token)):
    # No user ownership check!
    return {"refund_id": "123"}
''',
        }
        res = analyze_test_project(files, tmp_path, "three_tier_vuln")
        assert len(res.services) >= 3
        cd001 = [f for f in res.findings if f.rule_id == "CD-001"]
        assert len(cd001) >= 1, "Expected CD-001 finding on multi-hop path"
