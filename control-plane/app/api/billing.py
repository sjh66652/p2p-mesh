"""Billing API routes - subscription management and invoicing."""

import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.services import billing_service
from app.schemas.traffic import SubscriptionResponse, InvoiceResponse

router = APIRouter()


class CreateSubscriptionRequest(BaseModel):
    plan: str = Field(..., description="free, pro, or enterprise")
    payment_method: str | None = None


@router.get("/subscriptions")
async def list_subscriptions(
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all subscriptions for the current user."""
    subs = await billing_service.get_user_subscriptions(db, user.id)
    return {"subscriptions": subs, "total": len(subs)}


@router.post("/subscriptions", status_code=status.HTTP_201_CREATED)
async def create_subscription(
    data: CreateSubscriptionRequest,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new subscription for the current user."""
    try:
        sub = await billing_service.create_subscription(
            db,
            user.id,
            plan=data.plan,
            payment_method=data.payment_method,
        )
        return {"id": str(sub.id), "plan": sub.plan, "status": sub.status}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/subscriptions/{sub_id}/cancel")
async def cancel_subscription(
    sub_id: str,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cancel an active subscription."""
    try:
        sub = await billing_service.cancel_subscription(
            db, user.id, uuid.UUID(sub_id)
        )
        return {"id": str(sub.id), "status": sub.status}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/invoices")
async def list_invoices(
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all invoices for the current user."""
    invoices = await billing_service.get_user_invoices(db, user.id)
    return {"invoices": invoices, "total": len(invoices)}


@router.get("/plans")
async def list_plans():
    """List available billing plans and pricing."""
    return {
        "plans": [
            {
                "name": "free",
                "price_cents": 0,
                "features": [
                    "1 device",
                    "1 MB/s bandwidth",
                    "P2P connections",
                    "Community support",
                ],
            },
            {
                "name": "pro",
                "price_cents": 999,
                "features": [
                    "10 devices",
                    "Unlimited bandwidth",
                    "P2P + Relay",
                    "Priority support",
                ],
            },
            {
                "name": "enterprise",
                "price_cents": 4999,
                "features": [
                    "Unlimited devices",
                    "Unlimited bandwidth",
                    "Dedicated relay nodes",
                    "SLA guarantee",
                    "24/7 support",
                    "Custom regions",
                ],
            },
        ]
    }
