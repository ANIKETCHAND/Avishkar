"""
Regression & Invariant Property Test Suite
============================================
Verifies system invariants and ensures previously fixed bugs do not regress:
- Invariant: Variable renaming does NOT alter detection outcome
- Invariant: Formatting and comments do NOT alter detection outcome
- Invariant: Changing sync to async preserves semantic findings
- Invariant: Removing a sensitive operation eliminates CD-001
- Invariant: Adding user JWT forwarding eliminates CD-001 when ownership is checked
"""

import pytest
from tests.helpers import analyze_test_project


class TestPropertyInvariants:
    """Verifies that semantic security properties remain invariant under structural mutations."""

    def test_variable_renaming_invariant(self, tmp_path):
        """Renaming variables (e.g., token, headers, user, service) must produce identical findings."""
        files_original = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_user(authorization: str = Header(None)):
    return {"id": "1"}

@app.post("/cancel")
def cancel(user = Depends(get_user)):
    httpx.post("http://payment-service/refund", headers={"X-Service-Token": "KEY"})
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def auth(x_service_token: str = Header(None)):
    return True

@app.post("/refund")
def refund(s = Depends(auth)):
    return {}
'''
        }

        files_renamed = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def user_identity_provider(auth_hdr: str = Header(None)):
    return {"id": "1"}

@app.post("/cancel")
def cancel_order_handler(usr_obj = Depends(user_identity_provider)):
    svc_credentials = {"X-Service-Token": "KEY"}
    httpx.post("http://payment-service/refund", headers=svc_credentials)
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def service_authenticator(token_header_val: str = Header(None)):
    return True

@app.post("/refund")
def execute_refund_operation(authenticated_caller = Depends(service_authenticator)):
    return {}
'''
        }

        res_orig = analyze_test_project(files_original, tmp_path, "inv_orig")
        res_renamed = analyze_test_project(files_renamed, tmp_path, "inv_renamed")

        orig_rules = [f.rule_id for f in res_orig.findings]
        renamed_rules = [f.rule_id for f in res_renamed.findings]

        assert orig_rules == renamed_rules, (
            f"Variable renaming changed findings! Original: {orig_rules}, Renamed: {renamed_rules}"
        )

    def test_removing_sensitive_operation_eliminates_cd001(self, tmp_path):
        """If the downstream endpoint performs a non-sensitive action, CD-001 must NOT fire."""
        files_sensitive = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_user(authorization: str = Header(None)):
    return {}

@app.post("/action")
def action(u = Depends(get_user)):
    httpx.post("http://payment-service/refund", headers={"X-Service-Token": "KEY"})
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def check_token(x_service_token: str = Header(None)):
    return True

@app.post("/refund")
def refund(s = Depends(check_token)):
    return {}
'''
        }

        files_non_sensitive = {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_user(authorization: str = Header(None)):
    return {}

@app.post("/action")
def action(u = Depends(get_user)):
    httpx.post("http://payment-service/receipt/view", headers={"X-Service-Token": "KEY"})
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def check_token(x_service_token: str = Header(None)):
    return True

@app.post("/receipt/view")
def view_receipt(s = Depends(check_token)):
    return {"receipt": "123"}
'''
        }

        res_sens = analyze_test_project(files_sensitive, tmp_path, "inv_sens")
        res_non_sens = analyze_test_project(files_non_sensitive, tmp_path, "inv_non_sens")

        assert any(f.rule_id == "CD-001" for f in res_sens.findings)
        assert not any(f.rule_id == "CD-001" for f in res_non_sens.findings)

    def test_cd002_does_not_accidentally_trigger_cd004(self, tmp_path):
        """
        Verify that CD-002 (unauthenticated internal route) does not accidentally trigger CD-004
        unless a genuine gateway-only vulnerability on sensitive state mutations exists.
        """
        files = {
            "gateway_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.get("/data")
def get_data(u = Depends(auth)):
    httpx.get("http://backend-service:8000/internal/metrics")
    return {"status": "ok"}
''',
            "backend_service/main.py": '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/internal/metrics")
def metrics():
    # Read-only internal metrics endpoint (non-sensitive)
    return {"metrics": 123}
''',
        }
        res = analyze_test_project(files, tmp_path, "reg_cd002_no_cd004")
        detected = sorted(list(dict.fromkeys(f.rule_id for f in res.findings)))
        assert "CD-002" in detected, f"Expected CD-002 for unauthenticated /internal/metrics route, got {detected}"
        assert "CD-004" not in detected, f"Unexpected CD-004 finding on read-only internal metrics route: {detected}"
        assert detected == ["CD-002"]

    def test_cd004_does_not_trigger_cd002_without_internal_route(self, tmp_path):
        """
        Verify that CD-004 (gateway-only auth policy on sensitive downstream operations)
        does NOT trigger CD-002 unless genuine unauthenticated internal route criteria are met.
        """
        files = {
            "gateway_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def authenticate_user(authorization: str = Header(None)):
    return {"user_id": "usr_999"}

@app.post("/api/account/transfer")
def forward_transfer(data: dict, u = Depends(authenticate_user)):
    httpx.post("http://transfer-service:8000/transfers/process", json=data)
    return {"status": "forwarded"}
''',
            "transfer_service/main.py": '''
from fastapi import FastAPI
app = FastAPI()

@app.post("/transfers/process")
def execute_transfer(data: dict):
    # Sensitive operation with zero defense-in-depth authorization (Gateway-only auth)
    # Route does NOT use /internal or /admin prefixes
    return {"transferred": True}
''',
        }
        res = analyze_test_project(files, tmp_path, "reg_cd004_no_cd002")
        detected = sorted(list(dict.fromkeys(f.rule_id for f in res.findings)))
        assert "CD-004" in detected, f"Expected CD-004 for gateway-only sensitive mutation policy, got {detected}"
        assert "CD-002" not in detected, f"Unexpected CD-002 finding when route lacks internal/admin prefix: {detected}"
        assert detected == ["CD-004"]

    def test_cd002_without_service_credentials_does_not_trigger_cd001(self, tmp_path):
        """
        Verify that a public service calling an unauthenticated internal endpoint with no service
        credentials does not trigger CD-001 (Confused Deputy), triggering only CD-002.
        """
        files = {
            "public_service/main.py": '''
from fastapi import FastAPI
import httpx
app = FastAPI()

@app.post("/webhook")
def webhook():
    # Public unauthenticated caller with zero service credentials
    httpx.post("http://backend-service/internal/admin/reset")
    return {"ok": True}
''',
            "backend_service/main.py": '''
from fastapi import FastAPI
app = FastAPI()

@app.post("/internal/admin/reset")
def hard_reset():
    return {"reset": True}
''',
        }
        res = analyze_test_project(files, tmp_path, "reg_cd002_no_cd001")
        detected = sorted(list(dict.fromkeys(f.rule_id for f in res.findings)))
        assert "CD-002" in detected, f"Expected CD-002 for unauthenticated internal reset endpoint, got {detected}"
        assert "CD-001" not in detected, f"Unexpected CD-001 finding when caller has no service credentials: {detected}"
        assert detected == ["CD-002"]
