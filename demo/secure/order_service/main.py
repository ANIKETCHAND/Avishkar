"""
Order Service - SECURE Demo
=============================
This service demonstrates the secure pattern for inter-service calls.
The Order Service:
  1. Authenticates the user via JWT
  2. Forwards the user's Authorization JWT token downstream to Payment Service
  3. Payment Service can then cryptographically verify the user identity

This prevents the Confused Deputy vulnerability by ensuring downstream
services receive verifiable user identity, not just a service credential.

NOTE: This is SYNTHETIC benchmark code for security analysis testing only.
"""

from fastapi import FastAPI, Depends, HTTPException, Header, Request
from pydantic import BaseModel
from typing import Optional
import httpx

app = FastAPI(
    title="Order Service (SECURE Demo)",
    description="Secure demo: forwards user JWT to Payment Service",
    version="1.0.0",
)

PAYMENT_SERVICE_URL = "http://payment-service:8001"
SERVICE_TOKEN = "ORDER_SVC_INTERNAL_SERVICE_TOKEN"


# ---------------------------------------------------------------------------
# Auth model
# ---------------------------------------------------------------------------

class User(BaseModel):
    user_id: str
    username: str
    role: str = "user"


def get_current_user(authorization: Optional[str] = Header(None)) -> User:
    """Validate user JWT. Returns a User object if valid."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    # In production: validate JWT signature, expiry, and claims
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
    return {"status": "ok", "service": "order-service-secure"}


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
    authorization: Optional[str] = Header(None),
) -> OrderResponse:
    """
    Cancel order and trigger refund via Payment Service.

    SECURE: Forwards the user's Authorization Bearer JWT downstream.
    Payment Service can then:
    1. Cryptographically verify the JWT signature
    2. Extract user_id from the JWT claims
    3. Verify the user owns the order before processing refund

    This is NOT a confused deputy because Payment Service can independently
    verify the user's identity and resource ownership.
    """
    # SECURE: Forward the original user JWT to Payment Service
    # Payment Service can verify this JWT independently
    response = httpx.post(
        f"{PAYMENT_SERVICE_URL}/internal/v1/refund",
        headers={
            "X-Service-Token": SERVICE_TOKEN,     # Service identity for routing/auth
            "Authorization": authorization,        # FORWARDED user JWT for ownership check
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
        message="Order cancelled and refund initiated with user verification",
    )


@app.delete("/api/v1/orders/{order_id}")
def delete_order(
    order_id: str,
    user: User = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
):
    """
    Delete an order record.

    SECURE: Passes user JWT downstream so Payment Service can
    validate ownership before voiding the payment.
    """
    response = httpx.delete(
        f"{PAYMENT_SERVICE_URL}/internal/v1/payments/{order_id}",
        headers={
            "X-Service-Token": SERVICE_TOKEN,
            "Authorization": authorization,  # User JWT forwarded for ownership verification
        },
        timeout=10.0,
    )

    if response.status_code not in (200, 204):
        raise HTTPException(status_code=502, detail="Failed to delete payment record")

    return {"order_id": order_id, "status": "DELETED"}
