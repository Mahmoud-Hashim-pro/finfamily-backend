"""
FinFamily Data Isolation & Authorization Policies
==================================================
Centralized enforcement helpers to guarantee strict tenant (family) boundaries.
Prevents cross-family data leakage and unauthorized cross-family access
across all API resources (children, wallets, missions, card purchases, savings goals).

Executes single-roundtrip joined queries to prevent N+1 overhead and supports
anti-enumeration mode (hide_existence) where appropriate.
"""

from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from db.models import User, UserRole, Wallet, Mission, CardPurchase, SavingsGoal


def require_family_child(
    db: Session,
    family_id: str,
    child_id: str,
    for_update: bool = False,
    hide_existence: bool = False,
) -> User:
    """
    Verifies that the requested child exists and strictly belongs to the given family_id.
    """
    q = db.query(User).filter(User.id == child_id)
    if for_update:
        q = q.with_for_update()
    child = q.first()

    if not child or child.role != UserRole.child:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Child not found in your family",
        )
    if child.family_id != family_id:
        if hide_existence:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Child not found in your family",
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Child belongs to another family",
        )
    return child


def require_family_wallet(
    db: Session,
    family_id: str,
    wallet_id: str,
    for_update: bool = False,
    hide_existence: bool = False,
) -> Wallet:
    """
    Single-roundtrip joined verification that the requested wallet exists and
    strictly belongs to an owner in the specified family.
    """
    q = (
        db.query(Wallet, User.family_id)
        .outerjoin(User, Wallet.owner_id == User.id)
        .filter(Wallet.id == wallet_id)
    )
    if for_update:
        q = q.with_for_update()
    row = q.first()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found",
        )

    wallet, owner_family_id = row
    if not owner_family_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet owner not found",
        )

    if owner_family_id != family_id:
        if hide_existence:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Wallet not found in your family",
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Wallet belongs to another family",
        )
    return wallet


def require_family_mission(
    db: Session,
    family_id: str,
    mission_id: str,
    for_update: bool = False,
    hide_existence: bool = False,
) -> Mission:
    """
    Verifies that the requested mission exists and strictly belongs to the given family_id.
    """
    q = db.query(Mission).filter(Mission.id == mission_id)
    if for_update:
        q = q.with_for_update()
    mission = q.first()

    if not mission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mission not found",
        )
    if mission.family_id != family_id:
        if hide_existence:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Mission not found in your family",
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Mission belongs to another family",
        )
    return mission


def require_family_purchase(
    db: Session,
    family_id: str,
    purchase_id: str,
    for_update: bool = False,
    hide_existence: bool = False,
) -> CardPurchase:
    """
    Verifies that the requested card purchase exists and strictly belongs to the given family_id.
    """
    q = db.query(CardPurchase).filter(CardPurchase.id == purchase_id)
    if for_update:
        q = q.with_for_update()
    purchase = q.first()

    if not purchase:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Purchase request not found",
        )
    if purchase.family_id != family_id:
        if hide_existence:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Purchase request not found in your family",
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Purchase belongs to another family",
        )
    return purchase


def require_family_goal(
    db: Session,
    family_id: str,
    goal_id: str,
    for_update: bool = False,
    hide_existence: bool = False,
) -> SavingsGoal:
    """
    Single-roundtrip joined verification that the savings goal exists and belongs to the family.
    """
    q = (
        db.query(SavingsGoal, User.family_id)
        .outerjoin(Wallet, SavingsGoal.wallet_id == Wallet.id)
        .outerjoin(User, Wallet.owner_id == User.id)
        .filter(SavingsGoal.id == goal_id)
    )
    if for_update:
        q = q.with_for_update()
    row = q.first()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Savings goal not found",
        )

    goal, goal_family_id = row
    if not goal_family_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Savings goal wallet owner not found",
        )

    if goal_family_id != family_id:
        if hide_existence:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Savings goal not found in your family",
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Savings goal belongs to another family",
        )
    return goal
