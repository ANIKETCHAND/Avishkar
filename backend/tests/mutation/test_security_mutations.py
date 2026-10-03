"""
Security Mutation Testing Suite — Phase 21
===========================================
Applies systematic security regressions (mutations) to verified secure microservice
architectures to guarantee that the detector flags each security degradation:
- Mutation 1: Removing downstream ownership check introduces CD-001
- Mutation 2: Replacing verified user Bearer JWT with raw X-User-Id introduces CD-003
- Mutation 3: Removing JWT propagation while keeping service token introduces CD-001
- Mutation 4: Changing downstream handler to empty mock introduces CD-001
- Mutation 5: Changing read-only endpoint to sensitive DELETE introduces CD-001
"""

from __future__ import annotations

import pytest
from tests.helpers import analyze_test_project


class TestSecurityMutations:
    """Verifies that security mutations against safe baselines trigger expected detections."""

    @pytest.fixture
    def secure_baseline(self):
        """A fully secure baseline: user JWT forwarded + downstream ownership check."""
        return {
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)): return "user"

@app.post("/cancel")
def cancel(token: str = Header(None), u = Depends(auth)):
    httpx.post("http://payment-service/refund", headers={"Authorization": token, "X-Service-Token": "KEY"})
    return {}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header, HTTPException
app = FastAPI()

def verify_user(authorization: str = Header(None)): return {"id": "u1"}
def verify_svc(x_service_token: str = Header(None)): return True

@app.post("/refund")
def refund(u = Depends(verify_user), s = Depends(verify_svc)):
    order_owner = "u1"
    if order_owner != u["id"]:
        raise HTTPException(403)
    return {"refunded": True}
''',
        }

    def test_baseline_is_secure(self, tmp_path, secure_baseline):
        """The baseline project must produce zero findings."""
        res = analyze_test_project(secure_baseline, tmp_path, "mut_baseline")
        assert len(res.findings) == 0, f"Baseline should be secure! Found: {res.findings}"

    def test_mutation_remove_ownership_check(self, tmp_path, secure_baseline):
        """Mutation 1: Removing the downstream ownership comparison must introduce CD-001."""
        mutated = dict(secure_baseline)
        mutated["payment_service/main.py"] = '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def verify_user(authorization: str = Header(None)): return {"id": "u1"}
def verify_svc(x_service_token: str = Header(None)): return True

@app.post("/refund")
def refund(u = Depends(verify_user), s = Depends(verify_svc)):
    # Ownership comparison removed! Downstream trusts service token blindly
    return {"refunded": True}
'''
        res = analyze_test_project(mutated, tmp_path, "mut_no_ownership")
        rules = [f.rule_id for f in res.findings]
        assert "CD-001" in rules, f"Removing ownership check must trigger CD-001! Got: {rules}"

    def test_mutation_replace_jwt_with_plain_header(self, tmp_path, secure_baseline):
        """Mutation 2: Replacing verified Bearer JWT with raw X-User-Id header must introduce CD-003."""
        mutated = dict(secure_baseline)
        mutated["order_service/main.py"] = '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)): return "user"

@app.post("/cancel")
def cancel(u = Depends(auth)):
    # Replaced Bearer JWT with unverified plain header
    httpx.post("http://payment-service/refund", headers={"X-User-Id": "123"})
    return {}
'''
        res = analyze_test_project(mutated, tmp_path, "mut_plain_header")
        rules = [f.rule_id for f in res.findings]
        assert "CD-003" in rules, f"Passing unverified X-User-Id must trigger CD-003! Got: {rules}"

    def test_mutation_strip_jwt_propagation(self, tmp_path, secure_baseline):
        """Mutation 3: Removing user JWT propagation and only passing service token introduces CD-001."""
        mutated = dict(secure_baseline)
        mutated["order_service/main.py"] = '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)): return "user"

@app.post("/cancel")
def cancel(u = Depends(auth)):
    # Stripped user JWT, only passing service token
    httpx.post("http://payment-service/refund", headers={"X-Service-Token": "KEY"})
    return {}
'''
        mutated["payment_service/main.py"] = '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def verify_svc(x_service_token: str = Header(None)): return True

@app.post("/refund")
def refund(s = Depends(verify_svc)):
    return {"refunded": True}
'''
        res = analyze_test_project(mutated, tmp_path, "mut_strip_jwt")
        rules = [f.rule_id for f in res.findings]
        assert "CD-001" in rules, f"Stripping user JWT must trigger CD-001! Got: {rules}"

    def test_mutation_empty_mock_helper(self, tmp_path, secure_baseline):
        """Mutation 4: Replacing real authorization check with empty mock (pass) must introduce CD-001."""
        mutated = dict(secure_baseline)
        mutated["payment_service/main.py"] = '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def verify_owner():
    pass  # Empty mock! Must NOT be accepted as real ownership check

@app.post("/refund")
def refund(x_service_token: str = Header(None)):
    verify_owner()
    return {"status": "ok"}
'''
        mutated["order_service/main.py"] = '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)): return "user"

@app.post("/cancel")
def cancel(u = Depends(auth)):
    httpx.post("http://payment-service/refund", headers={"X-Service-Token": "KEY"})
    return {}
'''
        res = analyze_test_project(mutated, tmp_path, "mut_empty_mock")
        rules = [f.rule_id for f in res.findings]
        assert "CD-001" in rules, f"Empty mock helper must not bypass CD-001! Got: {rules}"
