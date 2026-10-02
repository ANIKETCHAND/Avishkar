"""
Payment Service - VULNERABLE Demo
===================================
This service demonstrates the Confused Deputy vulnerability.
It validates service-to-service calls via X-Service-Key but:
  1. Does NOT verify if the requesting user actually owns the resource
  2. Does NOT cryptographically validate the X-User-Id header
  3. Executes privileged financial operations based on service trust alone

NOTE: This is SYNTHETIC benchmark code for security analysis testing only.
      It is intentionally vulnerable. Do NOT deploy this.
"""

from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
from typing import Optional

app = FastAPI(
    title="Payment Service (VULNERABLE Demo)",
    description="Vulnerable demo: trusts service token without user ownership validation",
    version="1.0.0",
)

VALID_SERVICE_KEYS = {"ORDER_SVC_HARDCODED_SECRET_KEY_12345"}


# ---------------------------------------------------------------------------
# Auth model
# ---------------------------------------------------------------------------

class ServiceAuth(BaseModel):
    service_name: str


def verify_service_key(x_service_key: Optional[str] = Header(None)) -> ServiceAuth:
    """Validate service-to-service token."""
    if not x_service_key or x_service_key not in VALID_SERVICE_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Service-Key")
    return ServiceAuth(service_name="order-service")


# ---------------------------------------------------------------------------
# Payment models
# ---------------------------------------------------------------------------

class RefundRequest(BaseModel):
    order_id: str
    reason: Optional[str] = None


class RefundResponse(BaseModel):
    refund_id: str
    order_id: str
    status: str
    message: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """Health check (public)."""
    return {"status": "ok", "service": "payment-service"}


@app.post("/internal/v1/refund")
def process_refund(
    request: RefundRequest,
    service: ServiceAuth = Depends(verify_service_key),
    x_user_id: Optional[str] = Header(None),
) -> RefundResponse:
    """
    Process a financial refund.

    VULNERABLE: Validates service key (X-Service-Key) but does NOT:
    - Verify that x_user_id actually owns order_id in the database
    - Validate x_user_id cryptographically (it's a plain unverified header)
    - Perform any resource-level ownership check

    An attacker who can call Order Service can trigger refunds for
    ANY order_id by manipulating the order_id parameter, as Payment
    Service trusts Order Service's word without re-validating ownership.
    """
    # VULNERABLE: No ownership check — trusts upstream service blindly
    # Should verify: does x_user_id own order_id?
    # Instead, directly executes the refund for any order_id provided

    # Simulated database operation (in real code this would hit a DB)
    refund_id = f"REF-{request.order_id}-001"

    return RefundResponse(
        refund_id=refund_id,
        order_id=request.order_id,
        status="PROCESSED",
        message=f"Refund processed for order {request.order_id}. User ownership NOT verified.",
    )


@app.get("/internal/v1/payments/{order_id}")
def get_payment(
    order_id: str,
    service: ServiceAuth = Depends(verify_service_key),
):
    """
    Retrieve payment record.
    VULNERABLE: No user ownership check for the payment record.
    """
    return {
        "order_id": order_id,
        "amount": 150.00,
        "status": "PAID",
    }


@app.delete("/internal/v1/payments/{order_id}")
def void_payment(
    order_id: str,
    service: ServiceAuth = Depends(verify_service_key),
):
    """
    Void/delete a payment record.
    VULNERABLE: Service token grants full delete access without
    verifying whether the requesting user owns this payment.
    This is a sensitive DELETE operation with no user authorization.
    """
    # Simulated privileged DB delete
    return {
        "order_id": order_id,
        "status": "VOIDED",
        "message": "Payment record deleted. No user ownership check performed.",
    }


@app.post("/internal/v1/admin/grant-refund")
def admin_grant_refund(
    order_id: str,
    amount: float,
    service: ServiceAuth = Depends(verify_service_key),
):
    """
    Admin-level refund grant endpoint.
    VULNERABLE: Accessible via service token from Order Service —
    no admin role check, no user ownership validation.
    """
    return {
        "order_id": order_id,
        "granted_amount": amount,
        "status": "ADMIN_REFUND_GRANTED",
    }
