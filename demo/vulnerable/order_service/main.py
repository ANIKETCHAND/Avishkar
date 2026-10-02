"""
Order Service - VULNERABLE Demo
================================
This service demonstrates a Confused Deputy vulnerability.
The Order Service authenticates the user but calls Payment Service
using only a service-level token, WITHOUT forwarding user identity.
Payment Service then executes a refund without checking if the
original user owns the resource — the classic Confused Deputy flaw.

NOTE: This is SYNTHETIC benchmark code for security analysis testing only.
      It is intentionally vulnerable. Do NOT deploy this.
"""

from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
import httpx

app = FastAPI(
    title="Order Service (VULNERABLE Demo)",
    description="Vulnerable demo: calls Payment Service with service token only",
    version="1.0.0",
)

PAYMENT_SERVICE_URL = "http://payment-service:8001"
SERVICE_TOKEN = "ORDER_SVC_HARDCODED_SECRET_KEY_12345"


# ---------------------------------------------------------------------------
# Simple auth model (simulates a real auth system)
# ---------------------------------------------------------------------------

class User(BaseModel):
    user_id: str
    username: str
    role: str = "user"


def get_current_user(authorization: Optional[str] = Header(None)) -> User:
    """Validate user JWT. Returns a User object if valid."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    # In real code, JWT would be validated here
    # For demo purposes we simulate a resolved user
    return User(user_id="user-1042", username="alice", role="user")


# ---------------------------------------------------------------------------
# Order models
# ---------------------------------------------------------------------------

class CancelOrderRequest(BaseModel):
    reason: Optional[str] = "User requested cancellation"


class OrderResponse(BaseModel):
    order_id: str
    status: str
    message: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """Health check endpoint (public)."""
    return {"status": "ok", "service": "order-service"}


@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: str, user: User = Depends(get_current_user)):
    """Get order details. Requires user authentication."""
    return {
        "order_id": order_id,
        "user_id": user.user_id,
        "status": "ACTIVE",
        "amount": 150.00,
    }


@app.post("/api/v1/orders/{order_id}/cancel")
def cancel_order(
    order_id: str,
    request: CancelOrderRequest,
    user: User = Depends(get_current_user),
) -> OrderResponse:
    """
    Cancel order and trigger refund via Payment Service.

    VULNERABLE: Uses hardcoded X-Service-Key to call Payment Service.
    Does NOT forward user JWT or user_id in a verifiable way.
    Payment Service trusts the service token and processes the refund
    without verifying the user actually owns the order.
    """
    # VULNERABLE: Calling Payment Service with only the service token
    # The user identity (user_id) is passed as a plain header, not as
    # a signed JWT — Payment Service cannot cryptographically verify
    # whether this user_id was forged by a malicious Order Service instance.
    response = httpx.post(
        f"{PAYMENT_SERVICE_URL}/internal/v1/refund",
        headers={
            "X-Service-Key": SERVICE_TOKEN,
            "X-User-Id": user.user_id,  # Unverified plain header — not a signed JWT
        },
        json={
            "order_id": order_id,
            "reason": request.reason,
        },
        timeout=10.0,
    )

    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Payment Service returned: {response.status_code}",
        )

    return OrderResponse(
        order_id=order_id,
        status="CANCELLED",
        message="Order cancelled and refund initiated",
    )


@app.delete("/api/v1/orders/{order_id}")
def delete_order(order_id: str, user: User = Depends(get_current_user)):
    """
    Delete an order record.

    VULNERABLE: Calls admin endpoint on Payment Service to void the payment
    using only a service token — no downstream ownership check.
    """
    response = httpx.delete(
        f"{PAYMENT_SERVICE_URL}/internal/v1/payments/{order_id}",
        headers={
            "X-Service-Key": SERVICE_TOKEN,
        },
        timeout=10.0,
    )

    if response.status_code not in (200, 204):
        raise HTTPException(status_code=502, detail="Failed to delete payment record")

    return {"order_id": order_id, "status": "DELETED"}
