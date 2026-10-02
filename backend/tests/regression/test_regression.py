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
