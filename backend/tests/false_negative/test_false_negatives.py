"""
False Negative Resistance Test Suite
======================================
Tests complex, obfuscated, and non-trivial code constructs to ensure
the static analyzer does NOT miss real vulnerabilities:
- Imported function aliases (from httpx import post as custom_post)
- Async context manager client instances (async with httpx.AsyncClient() as client:)
- Obfuscated/variable-built header dictionaries with updates and unpacking
- APIRouter prefixes and sub-router hierarchies
- Sync requests client calls (requests.delete, requests.post)
- Non-standard handler names (reversal, void_transaction, cancel_payment)
"""

import pytest
from tests.helpers import analyze_test_project


class TestFalseNegativeResistance:
    """Ensures complex and varied code patterns are correctly detected."""

    def test_async_with_client_session_detected(self, tmp_path):
        """async with httpx.AsyncClient() as client: client.post(...) must be detected."""
        files = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.post("/cancel")
async def cancel(u = Depends(auth)):
    async with httpx.AsyncClient() as client:
        await client.post("http://payment-service:8001/internal/refund", headers={"X-Service-Token": "SEC_KEY"})
    return {"status": "cancelled"}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def verify_token(x_service_token: str = Header(None)):
    return True

@app.post("/internal/refund")
def do_refund(s = Depends(verify_token)):
    # Vulnerable: missing ownership verification
    return {"status": "ok"}
'''
        }
        res = analyze_test_project(files, tmp_path, "fn_async_with")
        cd001 = [f for f in res.findings if f.rule_id == "CD-001"]
        assert len(cd001) >= 1, "Failed to detect CD-001 inside async with httpx.AsyncClient() block"

    def test_aliased_imported_function_call(self, tmp_path):
        """from httpx import post as dispatch_http: dispatch_http(...) must be detected."""
        files = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
from httpx import post as dispatch_http
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.post("/cancel")
def cancel(u = Depends(auth)):
    dispatch_http("http://payment-service:8001/internal/refund", headers={"X-Service-Token": "SEC_KEY"})
    return {"status": "cancelled"}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def verify_token(x_service_token: str = Header(None)):
    return True

@app.post("/internal/refund")
def do_refund(s = Depends(verify_token)):
    return {"status": "ok"}
'''
        }
        res = analyze_test_project(files, tmp_path, "fn_aliased_call")
        cd001 = [f for f in res.findings if f.rule_id == "CD-001"]
        assert len(cd001) >= 1, "Failed to detect CD-001 when HTTP client function is aliased on import"

    def test_requests_library_sync_calls(self, tmp_path):
        """requests.delete(...) must be detected as a sensitive client call."""
        files = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import requests
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.post("/cancel")
def cancel(u = Depends(auth)):
    requests.delete("http://payment-service:8001/internal/payments/123", headers={"X-Service-Token": "SEC_KEY"})
    return {"status": "cancelled"}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def verify_token(x_service_token: str = Header(None)):
    return True

@app.delete("/internal/payments/{id}")
def delete_payment(id: str, s = Depends(verify_token)):
    return {"deleted": id}
'''
        }
        res = analyze_test_project(files, tmp_path, "fn_requests_sync")
        cd001 = [f for f in res.findings if f.rule_id == "CD-001"]
        assert len(cd001) >= 1, "Failed to detect CD-001 using synchronous requests.delete call"

    def test_router_prefix_route_matching(self, tmp_path):
        """APIRouter(prefix='/internal') routes must correctly resolve target path."""
        files = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.post("/cancel")
def cancel(u = Depends(auth)):
    httpx.post("http://payment-service:8001/internal/refund", headers={"X-Service-Token": "SEC_KEY"})
    return {"status": "cancelled"}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, APIRouter, Depends, Header
app = FastAPI()
router = APIRouter(prefix="/internal")

def verify_token(x_service_token: str = Header(None)):
    return True

@router.post("/refund")
def do_refund(s = Depends(verify_token)):
    return {"ok": True}

app.include_router(router)
'''
        }
        res = analyze_test_project(files, tmp_path, "fn_router_prefix")
        cd001 = [f for f in res.findings if f.rule_id == "CD-001"]
        assert len(cd001) >= 1, "Failed to match call to route under APIRouter with prefix"
