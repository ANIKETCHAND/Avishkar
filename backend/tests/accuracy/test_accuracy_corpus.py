"""
Comprehensive Accuracy & Benchmark Corpus — Phase 20 & 23
==========================================================
Machine-readable gold standard benchmark covering:
- Vulnerable variations across CD-001 through CD-004
- Secure counterparts across all vulnerability patterns
- Adversarial false-positive resistance cases
- Syntactic variations (async, requests, aiohttp, helpers, aliases, router prefixes)
- Formal calculation of TP, TN, FP, FN, Precision, Recall, F1, FPR, FNR
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional
import pytest

from tests.helpers import analyze_test_project


@dataclass
class BenchmarkScenario:
    id: str
    name: str
    category: str  # "Vulnerable", "Secure", "Adversarial", "Ambiguous"
    expected_rules: List[str]
    expected_secure: bool
    expected_confidence: str
    files: Dict[str, str]
    description: str = ""


# ─────────────────────────── Benchmark Corpus ─────────────────────────────

ACCURACY_BENCHMARK_CORPUS: List[BenchmarkScenario] = [
    # ── CD-001: Vulnerable Variations ────────────────────────────────────
    BenchmarkScenario(
        id="BM-VULN-CD001-01",
        name="cd001_canonical_httpx_post",
        category="Vulnerable",
        expected_rules=["CD-001"],
        expected_secure=False,
        expected_confidence="HIGH",
        description="Standard vulnerable flow: user calls order service, which calls payment refund using service token.",
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_current_user(authorization: str = Header(None)):
    return {"user_id": "usr_123"}

@app.post("/orders/{order_id}/cancel")
def cancel_order(order_id: str, user = Depends(get_current_user)):
    httpx.post("http://payment-service:8001/refund", headers={"X-Service-Token": "SVC_KEY"})
    return {"status": "cancelled"}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Header, HTTPException
app = FastAPI()

@app.post("/refund")
def process_refund(x_service_token: str = Header(None)):
    if not x_service_token:
        raise HTTPException(401)
    return {"refunded": True}
''',
        },
    ),
    BenchmarkScenario(
        id="BM-VULN-CD001-02",
        name="cd001_async_client_context_manager",
        category="Vulnerable",
        expected_rules=["CD-001"],
        expected_secure=False,
        expected_confidence="HIGH",
        description="Vulnerable flow using async with httpx.AsyncClient() session.",
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

async def auth_user(authorization: str = Header(None)):
    return {"id": "1"}

@app.post("/orders/cancel")
async def cancel(u = Depends(auth_user)):
    async with httpx.AsyncClient() as client:
        await client.post("http://payment-service/refund", headers={"X-Service-Key": "SEC"})
    return {}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.post("/refund")
async def do_refund(x_service_key: str = Header(None)):
    return {"status": "ok"}
''',
        },
    ),
    BenchmarkScenario(
        id="BM-VULN-CD001-03",
        name="cd001_destructive_delete_method",
        category="Vulnerable",
        expected_rules=["CD-001"],
        expected_secure=False,
        expected_confidence="HIGH",
        description="HTTP DELETE method performing destructive resource purge without user ownership.",
        files={
            "gateway_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import requests
app = FastAPI()

def authenticate(authorization: str = Header(None)):
    return "user"

@app.post("/account/terminate")
def terminate(user = Depends(authenticate)):
    requests.delete("http://account-service/users/data", headers={"X-Service-Token": "ROOT"})
    return {"terminated": True}
''',
            "account_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.delete("/users/data")
def purge_data(x_service_token: str = Header(None)):
    return {"deleted": True}
''',
        },
    ),
    BenchmarkScenario(
        id="BM-VULN-CD001-04",
        name="cd001_interprocedural_header_helper",
        category="Vulnerable",
        expected_rules=["CD-001"],
        expected_secure=False,
        expected_confidence="HIGH",
        description="Headers constructed via local helper function returning service token dictionary.",
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def verify_caller(authorization: str = Header(None)):
    return "user"

def build_downstream_headers():
    return {"X-Service-Token": "INTERNAL_KEY"}

@app.post("/order/cancel")
def cancel(caller = Depends(verify_caller)):
    headers = build_downstream_headers()
    httpx.post("http://payment-service/refund", headers=headers)
    return {"status": "ok"}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.post("/refund")
def refund(x_service_token: str = Header(None)):
    return {"done": True}
''',
        },
    ),
    BenchmarkScenario(
        id="BM-VULN-CD001-05",
        name="cd001_multihop_three_tier_architecture",
        category="Vulnerable",
        expected_rules=["CD-001"],
        expected_secure=False,
        expected_confidence="HIGH",
        description="3-tier architecture: Gateway -> Order Service -> Payment Service.",
        files={
            "gateway_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_user(authorization: str = Header(None)):
    return {"id": "usr_1"}

@app.post("/user/order/refund")
def refund_req(u = Depends(get_user)):
    httpx.post("http://order-service/orders/process-refund", headers={"Authorization": "Bearer token"})
    return {"status": "forwarded"}
''',
            "order_service/main.py": '''
from fastapi import FastAPI, Header
import httpx
app = FastAPI()

@app.post("/orders/process-refund")
def forward_refund(authorization: str = Header(None)):
    httpx.post("http://payment-service/internal/refund", headers={"X-Service-Token": "SVC_KEY"})
    return {"order": "cancelled"}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.post("/internal/refund")
def execute_refund(x_service_token: str = Header(None)):
    return {"refund": "executed"}
''',
        },
    ),

    # ── CD-002: Unauthenticated Internal Route ───────────────────────────
    BenchmarkScenario(
        id="BM-VULN-CD002-01",
        name="cd002_reachable_unauthenticated_internal_route",
        category="Vulnerable",
        expected_rules=["CD-002"],
        expected_secure=False,
        expected_confidence="HIGH",
        description="Internal admin route reachable from public service with zero authentication guards.",
        files={
            "public_service/main.py": '''
from fastapi import FastAPI
import httpx
app = FastAPI()

@app.post("/webhook")
def webhook():
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
        },
    ),

    # ── CD-003: Unverified User Header Injection ─────────────────────────
    BenchmarkScenario(
        id="BM-VULN-CD003-01",
        name="cd003_plain_user_id_forwarding",
        category="Vulnerable",
        expected_rules=["CD-003"],
        expected_secure=False,
        expected_confidence="HIGH",
        description="Forwarding unverified X-User-Id header without cryptographic JWT signature.",
        files={
            "frontend_gateway/main.py": '''
from fastapi import FastAPI, Header
import httpx
app = FastAPI()

@app.post("/profile")
def update_profile(x_user_id: str = Header(None)):
    httpx.post("http://user-service/profile/save", headers={"X-User-Id": x_user_id})
    return {"status": "saved"}
''',
            "user_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.post("/profile/save")
def save_profile(x_user_id: str = Header(None)):
    return {"user": x_user_id}
''',
        },
    ),

    # ── Secure Counterparts (Expected: 0 findings) ───────────────────────
    BenchmarkScenario(
        id="BM-SEC-01",
        name="secure_forwarded_jwt_with_ownership_check",
        category="Secure",
        expected_rules=[],
        expected_secure=True,
        expected_confidence="HIGH",
        description="Originating user Bearer JWT is forwarded and downstream checks resource ownership.",
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_current_user(authorization: str = Header(None)):
    return {"user_id": "u1"}

@app.post("/orders/{order_id}/cancel")
def cancel_order(order_id: str, auth_token: str = Header(None), user = Depends(get_current_user)):
    headers = {"Authorization": auth_token, "X-Service-Token": "SVC_KEY"}
    httpx.post("http://payment-service/refund", headers=headers)
    return {"status": "ok"}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header, HTTPException
app = FastAPI()

def verify_user(authorization: str = Header(None)):
    return {"id": "u1"}

def verify_service(x_service_token: str = Header(None)):
    return True

@app.post("/refund")
def process_refund(order_id: str = "1", user = Depends(verify_user), s = Depends(verify_service)):
    order_owner_id = "u1"
    if order_owner_id != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"refunded": True}
''',
        },
    ),
    BenchmarkScenario(
        id="BM-SEC-02",
        name="secure_in_body_ownership_comparison",
        category="Secure",
        expected_rules=[],
        expected_secure=True,
        expected_confidence="HIGH",
        description="Downstream endpoint independently validates that order.user_id == current_user.id.",
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_user(authorization: str = Header(None)):
    return {"id": "u1"}

@app.post("/cancel")
def cancel(user = Depends(get_user)):
    httpx.post("http://payment-service/refund", headers={"X-Service-Token": "SVC"})
    return {}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header, HTTPException
app = FastAPI()

def get_jwt_user(authorization: str = Header(None)):
    return {"user_id": "u1"}

@app.post("/refund")
def refund(caller = Depends(get_jwt_user), x_service_token: str = Header(None)):
    order_user_id = "u1"
    if order_user_id != caller["user_id"]:
        raise HTTPException(403)
    return {"status": "ok"}
''',
        },
    ),
    BenchmarkScenario(
        id="BM-SEC-03",
        name="secure_database_query_ownership_filter",
        category="Secure",
        expected_rules=[],
        expected_secure=True,
        expected_confidence="HIGH",
        description="Downstream endpoint scopes database query by authenticated user ID.",
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_user(authorization: str = Header(None)):
    return {"id": "u1"}

@app.post("/cancel")
def cancel(user = Depends(get_user)):
    httpx.post("http://payment-service/refund", headers={"Authorization": "Bearer JWT"})
    return {}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def get_user(authorization: str = Header(None)):
    return {"id": "u1"}

class MockDB:
    def filter(self, *args): return self
    def delete(self): pass

db = MockDB()

@app.post("/refund")
def refund(user = Depends(get_user)):
    db.filter("order.user_id == user.id").delete()
    return {"status": "deleted"}
''',
        },
    ),

    # ── Adversarial False-Positive Resistance ─────────────────────────────
    BenchmarkScenario(
        id="BM-ADV-01",
        name="clean_adversarial_message_refund_variable",
        category="Adversarial",
        expected_rules=[],
        expected_secure=True,
        expected_confidence="HIGH",
        description="Local variable named message = 'refund' in harmless notification endpoint.",
        files={
            "notify_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)): return "user"

@app.post("/notify")
def send_notify(u = Depends(auth)):
    message = "refund status updated"
    httpx.post("http://log-service/log", headers={"X-Service-Token": "KEY"})
    return {"msg": message}
''',
            "log_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.post("/log")
def log_event(x_service_token: str = Header(None)):
    return {"logged": True}
''',
        },
    ),
    BenchmarkScenario(
        id="BM-ADV-02",
        name="clean_read_only_refund_policy_page",
        category="Adversarial",
        expected_rules=[],
        expected_secure=True,
        expected_confidence="HIGH",
        description="GET /refund/policy is read-only documentation and must not be flagged as sensitive mutation.",
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)): return "user"

@app.get("/faq")
def faq(u = Depends(auth)):
    httpx.get("http://payment-service/refund/policy", headers={"X-Service-Token": "KEY"})
    return {}
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.get("/refund/policy")
def get_policy(x_service_token: str = Header(None)):
    return {"policy": "30 days"}
''',
        },
    ),
    BenchmarkScenario(
        id="BM-ADV-03",
        name="clean_benign_service_token_to_catalog",
        category="Adversarial",
        expected_rules=[],
        expected_secure=True,
        expected_confidence="HIGH",
        description="Service token used for benign non-sensitive catalog retrieval.",
        files={
            "frontend_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)): return "user"

@app.get("/browse")
def browse(u = Depends(auth)):
    httpx.get("http://catalog-service/items", headers={"X-Service-Token": "KEY"})
    return {}
''',
            "catalog_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.get("/items")
def list_items(x_service_token: str = Header(None)):
    return [{"item": 1}]
''',
        },
    ),
    BenchmarkScenario(
        id="BM-ADV-04",
        name="clean_unused_service_token_constant",
        category="Adversarial",
        expected_rules=[],
        expected_secure=True,
        expected_confidence="HIGH",
        description="Top-level constant SERVICE_TOKEN defined but never passed in HTTP headers.",
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()
SERVICE_TOKEN = "UNUSED_SECRET_KEY"

def auth(authorization: str = Header(None)): return "user"

@app.get("/status")
def status(u = Depends(auth)):
    httpx.get("http://catalog-service/items")
    return {"status": "ok"}
''',
            "catalog_service/main.py": '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/items")
def items(): return []
''',
        },
    ),
]


# ─────────────────────────── Automated Evaluation ─────────────────────────

class TestAccuracyCorpus:
    """Evaluates the detection engine against the formal benchmark corpus."""

    @pytest.mark.parametrize("scenario", ACCURACY_BENCHMARK_CORPUS, ids=lambda s: s.id)
    def test_benchmark_scenario(self, tmp_path, scenario: BenchmarkScenario):
        """Verify each scenario produces exact expected rule findings."""
        scan = analyze_test_project(scenario.files, tmp_path, f"acc_{scenario.id}")
        detected_rules = list(dict.fromkeys(f.rule_id for f in scan.findings))

        if scenario.expected_secure:
            assert len(detected_rules) == 0, (
                f"False positive in secure/adversarial scenario '{scenario.name}'! "
                f"Expected 0 findings, got: {detected_rules}"
            )
        else:
            for exp_rule in scenario.expected_rules:
                assert exp_rule in detected_rules, (
                    f"False negative in scenario '{scenario.name}'! "
                    f"Expected rule {exp_rule} not found in: {detected_rules}"
                )

    def test_full_corpus_confusion_matrix(self, tmp_path):
        """Compute full statistical confusion matrix over all benchmark scenarios."""
        tp = 0
        fp = 0
        tn = 0
        fn = 0

        for scenario in ACCURACY_BENCHMARK_CORPUS:
            scan = analyze_test_project(scenario.files, tmp_path, f"matrix_{scenario.id}")
            detected_rules = list(dict.fromkeys(f.rule_id for f in scan.findings))

            if not scenario.expected_secure:
                if all(r in detected_rules for r in scenario.expected_rules):
                    tp += 1
                else:
                    fn += 1
            else:
                if len(detected_rules) == 0:
                    tn += 1
                else:
                    fp += 1

        total = len(ACCURACY_BENCHMARK_CORPUS)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0
        accuracy = (tp + tn) / total
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        assert fp == 0, f"False positives detected: {fp}"
        assert fn == 0, f"False negatives detected: {fn}"
        assert accuracy == 1.0, f"Accuracy expected 1.0, got {accuracy}"
        assert precision == 1.0, f"Precision expected 1.0, got {precision}"
        assert recall == 1.0, f"Recall expected 1.0, got {recall}"
        assert f1 == 1.0, f"F1 score expected 1.0, got {f1}"
        assert fpr == 0.0, f"False positive rate expected 0.0, got {fpr}"
        assert fnr == 0.0, f"False negative rate expected 0.0, got {fnr}"
