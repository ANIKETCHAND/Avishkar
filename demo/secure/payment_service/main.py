"""
Payment Service - SECURE Demo
================================
This service demonstrates the secure downstream authorization pattern.
It:
  1. Validates the incoming service token (service identity)
  2. Validates the forwarded user JWT (user identity)
  3. Verifies the user owns the requested resource before executing
     any sensitive operation (ownership check / end-to-end authorization)

This eliminates the Confused Deputy risk because Payment Service
independently re-validates user authority, not just service authority.

NOTE: This is SYNTHETIC benchmark code for security analysis testing only.
"""

from fastapi import FastAPI, Depends, HTTPException, Header
from pydantic import BaseModel
from typing import Optional

app = FastAPI(
    title="Payment Service (SECURE Demo)",
    description="Secure demo: validates user JWT and ownership before any refund",
    version="1.0.0",
)

VALID_SERVICE_TOKENS = {"ORDER_SVC_INTERNAL_SERVICE_TOKEN"}


# ---------------------------------------------------------------------------
# Auth models
# ---------------------------------------------------------------------------

class ServiceAuth(BaseModel):
    service_name: str


class UserClaims(BaseModel):
    user_id: str
    username: str
    role: str = "user"


def verify_service_token(x_service_token: Optional[str] = Header(None)) -> ServiceAuth:
    """Validate service-to-service token."""
    if not x_service_token or x_service_token not in VALID_SERVICE_TOKENS:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Service-Token")
    return ServiceAuth(service_name="order-service")


def verify_user_jwt(authorization: Optional[str] = Header(None)) -> UserClaims:
    """
    Validate the forwarded user JWT.
    In production: verify JWT signature, expiry, and extract claims.
    This is a cryptographic verification — cannot be forged by the upstream service.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid user Authorization header. "
                   "User identity must be forwarded by upstream service.",
        )
    # Production implementation: jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
    return UserClaims(user_id="user-1042", username="alice", role="user")


def verify_user_owns_order(user_id: str, order_id: str) -> bool:
    """
    SECURE: Check that user_id is the owner of order_id.
    In production: query database to confirm ownership.
    Returns True only if the user legitimately owns this resource.
    """
    # Simulated ownership lookup
    # In production: SELECT * FROM orders WHERE id=order_id AND user_id=user_id
    ownership_map = {
        "ORDER-001": "user-1042",
        "ORDER-002": "user-9999",
    }
    return ownership_map.get(order_id) == user_id


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
    return {"status": "ok", "service": "payment-service-secure"}


@app.post("/internal/v1/refund")
def process_refund(
    request: RefundRequest,
    service: ServiceAuth = Depends(verify_service_token),
    user: UserClaims = Depends(verify_user_jwt),
) -> RefundResponse:
    """
    Process a financial refund.

    SECURE: This endpoint:
    1. Validates the service token (confirms caller is a trusted internal service)
    2. Validates the forwarded user JWT (confirms user identity cryptographically)
    3. Checks resource ownership (confirms this user owns the order)
    4. Only then executes the refund

    This implements end-to-end user authorization, eliminating the
    Confused Deputy vulnerability.
    """
    # SECURE: Verify user owns the order before processing refund
    if not verify_user_owns_order(user.user_id, request.order_id):
        raise HTTPException(
            status_code=403,
            detail=f"User {user.user_id} does not own order {request.order_id}. "
                   "Refund denied.",
        )

    refund_id = f"REF-{request.order_id}-SECURE-001"

    return RefundResponse(
        refund_id=refund_id,
        order_id=request.order_id,
        status="PROCESSED",
        message=f"Refund processed after verifying ownership for user {user.user_id}.",
    )


@app.get("/internal/v1/payments/{order_id}")
def get_payment(
    order_id: str,
    service: ServiceAuth = Depends(verify_service_token),
    user: UserClaims = Depends(verify_user_jwt),
):
    """
    Retrieve payment record.
    SECURE: Verifies user owns the payment record before returning it.
    """
    if not verify_user_owns_order(user.user_id, order_id):
        raise HTTPException(
            status_code=403,
            detail=f"User {user.user_id} does not own order {order_id}.",
        )

    return {
        "order_id": order_id,
        "amount": 150.00,
        "status": "PAID",
        "owner_verified": True,
    }


@app.delete("/internal/v1/payments/{order_id}")
def void_payment(
    order_id: str,
    service: ServiceAuth = Depends(verify_service_token),
    user: UserClaims = Depends(verify_user_jwt),
):
    """
    Void/delete a payment record.
    SECURE: Verifies user owns the payment before deletion.
    """
    if not verify_user_owns_order(user.user_id, order_id):
        raise HTTPException(
            status_code=403,
            detail=f"User {user.user_id} is not authorized to delete order {order_id}.",
        )

    return {
        "order_id": order_id,
        "status": "VOIDED",
        "message": f"Payment record deleted after verifying ownership for user {user.user_id}.",
    }
