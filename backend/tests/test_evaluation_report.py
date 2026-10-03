"""
Automated Detection Accuracy & Benchmark Metrics Evaluation
============================================================
Executes an evaluation benchmark matrix against ground-truth labels and computes:
- True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN)
- Precision, Recall, F1 Score
- False Positive Rate (FPR), False Negative Rate (FNR)
- Coverage across CD-001, CD-002, CD-003, CD-004 and clean patterns
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import pytest
from tests.helpers import analyze_test_project, compare_expected_actual_rules


@dataclass
class GroundTruthCase:
    name: str
    category: str
    expected_rules: List[str]  # e.g. ["CD-001"] or [] for clean
    files: Dict[str, str]


# Define comprehensive ground-truth benchmark evaluation cases
BENCHMARK_CORPUS: List[GroundTruthCase] = [
    # ── CD-001 Positive Cases ─────────────────────────────────────────────
    GroundTruthCase(
        name="cd001_canonical_vulnerable",
        category="CD-001 Positive",
        expected_rules=["CD-001"],
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return {"user": "u1"}

@app.post("/orders/{id}/cancel")
def cancel(id: str, u = Depends(auth)):
    httpx.post("http://payment-service:8001/internal/refund", headers={"X-Service-Token": "KEY"})
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def verify_token(x_service_token: str = Header(None)):
    return True

@app.post("/internal/refund")
def refund(s = Depends(verify_token)):
    return {"status": "refunded"}
''',
        },
    ),
    GroundTruthCase(
        name="cd001_delete_endpoint_vulnerable",
        category="CD-001 Positive",
        expected_rules=["CD-001"],
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return {"user": "u1"}

@app.post("/account/close")
def close(u = Depends(auth)):
    httpx.delete("http://payment-service:8001/internal/payments/u1", headers={"X-Service-Token": "KEY"})
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def verify_token(x_service_token: str = Header(None)):
    return True

@app.delete("/internal/payments/{user_id}")
def delete_payments(user_id: str, s = Depends(verify_token)):
    return {"deleted": True}
''',
        },
    ),
    GroundTruthCase(
        name="cd001_async_client_vulnerable",
        category="CD-001 Positive",
        expected_rules=["CD-001"],
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
from httpx import AsyncClient
app = FastAPI()

async def auth(authorization: str = Header(None)):
    return {"user": "u1"}

@app.post("/cancel")
async def cancel(u = Depends(auth)):
    client = AsyncClient()
    await client.post("http://payment-service:8001/internal/refund", headers={"X-Service-Token": "KEY"})
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def verify_token(x_service_token: str = Header(None)):
    return True

@app.post("/internal/refund")
def refund(s = Depends(verify_token)):
    return {}
''',
        },
    ),
    # ── CD-002 Positive Cases ─────────────────────────────────────────────
    GroundTruthCase(
        name="cd002_reachable_unauthenticated_internal_route",
        category="CD-002 Positive",
        expected_rules=["CD-002"],
        files={
            "gateway_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.get("/data")
def get_data(u = Depends(auth)):
    httpx.get("http://backend-service:8000/internal/metrics")
''',
            "backend_service/main.py": '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/internal/metrics")
def metrics():
    return {"metrics": 123}
''',
        },
    ),
    # ── CD-003 Positive Cases ─────────────────────────────────────────────
    GroundTruthCase(
        name="cd003_plain_user_id_forwarding",
        category="CD-003 Positive",
        expected_rules=["CD-003"],
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_user(authorization: str = Header(None)):
    return {"id": "1"}

@app.post("/buy")
def buy(u = Depends(get_user)):
    httpx.post("http://payment-service/charge", headers={"X-User-Id": "1"})
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.post("/charge")
def charge(x_user_id: str = Header(None)):
    return {"ok": True}
''',
        },
    ),
    # ── Negative / Secure Cases (Must NOT trigger findings) ───────────────
    GroundTruthCase(
        name="secure_forwarded_jwt_with_ownership_check",
        category="Clean Negative",
        expected_rules=[],
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def get_user(authorization: str = Header(None)):
    return {"id": "1"}

@app.post("/orders/{id}/cancel")
def cancel(id: str, u = Depends(get_user), authorization: str = Header(None)):
    httpx.post("http://payment-service:8001/internal/refund", headers={"Authorization": authorization})
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Depends, Header, HTTPException
app = FastAPI()

def verify_jwt(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401)
    return {"sub": "user-1"}

@app.post("/internal/refund")
def refund(u = Depends(verify_jwt)):
    if not verify_user_owns_order(u["sub"], "order-1"):
        raise HTTPException(status_code=403)
    return {"status": "ok"}

def verify_user_owns_order(user_id, order_id):
    return True
''',
        },
    ),
    GroundTruthCase(
        name="clean_adversarial_message_refund_variable",
        category="Clean Negative",
        expected_rules=[],
        files={
            "service/main.py": '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/status")
def status():
    message = "refund"
    return {"msg": message}
'''
        },
    ),
    GroundTruthCase(
        name="clean_read_only_policy_page",
        category="Clean Negative",
        expected_rules=[],
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.get("/faq")
def faq(u = Depends(auth)):
    httpx.get("http://payment-service:8001/refund/policy", headers={"X-Service-Token": "KEY"})
''',
            "payment_service/main.py": '''
from fastapi import FastAPI, Header
app = FastAPI()

@app.get("/refund/policy")
def policy(x_service_token: str = Header(None)):
    return {"policy": "30 days"}
'''
        },
    ),
    GroundTruthCase(
        name="clean_benign_service_token_to_catalog",
        category="Clean Negative",
        expected_rules=[],
        files={
            "order_service/main.py": '''
from fastapi import FastAPI, Depends, Header
import httpx
app = FastAPI()

def auth(authorization: str = Header(None)):
    return "user"

@app.get("/rates")
def rates(u = Depends(auth)):
    httpx.get("http://catalog-service:8000/rates/usd", headers={"X-Service-Token": "KEY"})
''',
            "catalog_service/main.py": '''
from fastapi import FastAPI, Depends, Header
app = FastAPI()

def check_token(x_service_token: str = Header(None)):
    return True

@app.get("/rates/usd")
def get_rate(auth = Depends(check_token)):
    return {"rate": 1.0}
'''
        },
    ),
]


def test_automated_accuracy_evaluation_report(tmp_path):
    """
    Run evaluation benchmark suite and compute rigorous metrics:
    - Case-level: TP, FP, TN, FN, Precision, Recall, F1, FPR, FNR
    - Rule-level: Expected, Detected, Correct, Missing, Unexpected for CD-001..CD-004
    Uses strict exact rule set matching.
    """
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    results_table = []
    mismatches = []

    monitored_rules = ["CD-001", "CD-002", "CD-003", "CD-004"]
    rule_stats = {
        r: {
            "expected": 0,
            "detected": 0,
            "correct": 0,
            "missing": 0,
            "unexpected": 0,
        }
        for r in monitored_rules
    }

    for case in BENCHMARK_CORPUS:
        scan = analyze_test_project(case.files, tmp_path, f"eval_{case.name}")
        detected_rules = list(dict.fromkeys(f.rule_id for f in scan.findings))

        comparison = compare_expected_actual_rules(case.expected_rules, detected_rules)

        is_positive_case = len(case.expected_rules) > 0

        if comparison.exact_match:
            if is_positive_case:
                tp += 1
            else:
                tn += 1
        else:
            if comparison.classification == "FP":
                fp += 1
            elif comparison.classification == "FN":
                fn += 1
            else:  # MIXED
                fp += 1
                fn += 1
            mismatches.append(comparison.format_details(case.name))

        # Rule-level accounting
        for r in monitored_rules:
            in_expected = r in case.expected_rules
            in_detected = r in detected_rules

            if in_expected:
                rule_stats[r]["expected"] += 1
            if in_detected:
                rule_stats[r]["detected"] += 1

            if in_expected and in_detected:
                rule_stats[r]["correct"] += 1
            elif in_expected and not in_detected:
                rule_stats[r]["missing"] += 1
            elif not in_expected and in_detected:
                rule_stats[r]["unexpected"] += 1

        results_table.append({
            "name": case.name,
            "category": case.category,
            "expected": comparison.expected_rules,
            "detected": comparison.actual_rules,
            "outcome": comparison.status,
            "exact_match": comparison.exact_match,
        })

    total_cases = len(BENCHMARK_CORPUS)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    accuracy = (tp + tn) / total_cases

    print("\n" + "=" * 80)
    print("      CONFUSED DEPUTY STATIC ANALYZER — EVALUATION METRICS REPORT")
    print("=" * 80)
    for row in results_table:
        status_tag = "[PASS]  " if row["exact_match"] else "[FAIL]  "
        print(f"{status_tag} {row['name']:<45} | Expected: {str(row['expected']):<14} | Got: {str(row['detected'])}")
    print("-" * 80)

    if mismatches:
        print("\n" + "!" * 80)
        print("                        RULE MISMATCH DETAILS")
        print("!" * 80)
        for mismatch in mismatches:
            print(mismatch)
            print("-" * 40)
        print("!" * 80 + "\n")

    print("\n" + "=" * 80)
    print("                           CASE-LEVEL METRICS")
    print("=" * 80)
    print(f"Total Benchmark Cases Evaluated : {total_cases}")
    print(f"True Positives (TP)             : {tp}")
    print(f"True Negatives (TN)             : {tn}")
    print(f"False Positives (FP)            : {fp}")
    print(f"False Negatives (FN)            : {fn}")
    print(f"Accuracy                        : {accuracy * 100:.2f}%")
    print(f"Precision                       : {precision * 100:.2f}%")
    print(f"Recall                          : {recall * 100:.2f}%")
    print(f"F1 Score                        : {f1:.4f}")
    print(f"False Positive Rate (FPR)       : {fpr * 100:.2f}%")
    print(f"False Negative Rate (FNR)       : {fnr * 100:.2f}%")

    print("\n" + "=" * 80)
    print("                           RULE-LEVEL METRICS")
    print("=" * 80)
    print(f"{'Rule ID':<10} | {'Expected':<10} | {'Detected':<10} | {'Correct':<10} | {'Missing':<10} | {'Unexpected':<12}")
    print("-" * 80)
    for r in monitored_rules:
        st = rule_stats[r]
        print(f"{r:<10} | {st['expected']:<10} | {st['detected']:<10} | {st['correct']:<10} | {st['missing']:<10} | {st['unexpected']:<12}")
    print("=" * 80 + "\n")

    # Strict assertions
    assert len(mismatches) == 0, f"{len(mismatches)} rule mismatch(es) detected:\n" + "\n\n".join(mismatches)
    assert fp == 0, f"False positives detected: {fp}"
    assert fn == 0, f"False negatives detected: {fn}"
    assert accuracy == 1.0, f"Expected 100% accuracy on defined corpus, got {accuracy * 100:.2f}%"

