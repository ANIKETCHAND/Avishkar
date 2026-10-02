"""
False Positive / Adversarial Test Suite
========================================
Adversarial cases designed to fool naive keyword-matching SAST tools:
- message = "refund" (string literal or variable name must NOT trigger CD-001)
- Code comments containing "vulnerable", "refund", "admin"
- Read-only endpoints (GET /refund/policy, GET /admin/faq)
- Unused service token constants in files
- Benign service-to-service calls to non-sensitive endpoints (e.g. GET /catalog/items)
- Dead code / uncalled helper functions
- Sensitive endpoints with proper ownership verification
"""

import pytest
from tests.helpers import analyze_test_project


class TestFalsePositiveResistance:
    """Verifies that the detector does not trigger false positives on adversarial non-vulnerable code."""

    def test_message_equals_refund_not_flagged(self, tmp_path):
        """Variable with string 'refund' must NOT cause CD-001."""
        files = {
            "order_service/main.py": '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/status")
def get_status():
    message = "refund"
    status_text = f"Processing {message}"
    return {"status": status_text}
'''
        }
        res = analyze_test_project(files, tmp_path, "fp_message_refund")
        assert len(res.findings) == 0, f"False positive triggered by message='refund': {res.findings}"

    def test_read_only_refund_policy_not_sensitive(self, tmp_path):
        """GET /refund/policy is read-only documentation and must NOT be flagged as sensitive mutation."""
        files = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.get("/faq")
def faq(u = Depends(auth)):
    httpx.get("http://payment-service:8001/refund/policy", headers={"X-Service-Token": "KEY"})
    return {"info": "read"}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.get("/refund/policy")
def get_policy(x_service_token: str = Header(None)):
    return {"policy": "Refunds permitted within 30 days."}
'''
        }
        res = analyze_test_project(files, tmp_path, "fp_read_only_refund")
        cd001 = [f for f in res.findings if f.rule_id == "CD-001"]
        assert len(cd001) == 0, "GET /refund/policy should not trigger CD-001 as it is not a sensitive mutation"

    def test_unused_service_token_constant(self, tmp_path):
        """Unused service token constant must NOT trigger any finding."""
        files = {
            "service_a/main.py": '''
from fastapi import FastAPI
app = FastAPI()

SERVICE_KEY = "SECRET_UNUSED_TOKEN_12345"

@app.get("/hello")
def hello():
    return {"hello": "world"}
'''
        }
        res = analyze_test_project(files, tmp_path, "fp_unused_token")
        assert len(res.findings) == 0

    def test_comment_with_vulnerable_keywords(self, tmp_path):
        """Comments mentioning security terms must NOT influence AST findings."""
        files = {
            "service_a/main.py": '''
from fastapi import FastAPI
app = FastAPI()

# WARNING: Potential confused deputy vulnerability if refund endpoint is called
# Ensure service token is never leaked to payment service!
@app.get("/items")
def items():
    return []
'''
        }
        res = analyze_test_project(files, tmp_path, "fp_comments")
        assert len(res.findings) == 0

    def test_benign_service_call_to_non_sensitive_endpoint(self, tmp_path):
        """Service token call to fetch catalog items (non-sensitive read) must NOT trigger CD-001."""
        files = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.get("/orders/estimate")
def estimate(u = Depends(auth)):
    # Call catalog service to get exchange rates
    httpx.get("http://catalog-service:8000/rates/current", headers={"X-Service-Token": "KEY"})
    return {"rate": 1.0}
''',
            "catalog_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def verify_token(x_service_token: str = Header(None)):
    return True

@app.get("/rates/current")
def get_rate(auth = Depends(verify_token)):
    return {"USD": 1.0}
'''
        }
        res = analyze_test_project(files, tmp_path, "fp_benign_call")
        cd001 = [f for f in res.findings if f.rule_id == "CD-001"]
        assert len(cd001) == 0, "Non-sensitive read operation must not trigger CD-001"

    def test_properly_authorized_downstream_endpoint(self, tmp_path):
        """Downstream endpoint with explicit user ownership check must NOT trigger CD-001."""
        files = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_user(authorization: str = Header(None)):
    return "alice"

@app.post("/cancel")
def cancel(user = Depends(get_user), authorization: str = Header(None)):
    httpx.post("http://payment-service/internal/refund", headers={"Authorization": authorization})
    return {"ok": True}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header, HTTPException
app = FastAPI()

def verify_user_jwt(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401)
    return {"sub": "alice"}

@app.post("/internal/refund")
def do_refund(user = Depends(verify_user_jwt)):
    # Explicit ownership check
    if not verify_user_owns_order(user["sub"], "order-123"):
        raise HTTPException(status_code=403)
    return {"refunded": True}

def verify_user_owns_order(user_id, order_id):
    return True
'''
        }
        res = analyze_test_project(files, tmp_path, "fp_proper_auth")
        cd001 = [f for f in res.findings if f.rule_id == "CD-001"]
        assert len(cd001) == 0
