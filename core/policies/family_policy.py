"""
FinFamily Data Isolation & Authorization Policies
==================================================
Centralized enforcement helpers to guarantee strict tenant (family) boundaries.
Prevents cross-family data leakage and unauthorized cross-family access
across all API resources (children, wallets, missions, card purchases, savings goals).
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
) -> User:
    """
    Verifies that the requested child exists and strictly belongs to the given family_id.

    Raises:
        HTTPException 404: If the child does not exist or has a non-child role.
        HTTPException 403: If the child belongs to another family.
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
) -> Wallet:
    """
    Verifies that the requested wallet exists and strictly belongs to an owner
    associated with the given family_id.

    Raises:
        HTTPException 404: If the wallet or its owner does not exist.
        HTTPException 403: If the wallet owner belongs to another family.
    """
    q = db.query(Wallet).filter(Wallet.id == wallet_id)
    if for_update:
        q = q.with_for_update()
    wallet = q.first()

    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found",
        )

    owner = db.query(User).filter(User.id == wallet.owner_id).first()
    if not owner:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet owner not found",
        )

    if owner.family_id != family_id:
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
) -> Mission:
    """
    Verifies that the requested mission exists and strictly belongs to the given family_id.

    Raises:
        HTTPException 404: If the mission does not exist.
        HTTPException 403: If the mission belongs to another family.
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
) -> CardPurchase:
    """
    Verifies that the requested card purchase exists and strictly belongs to the given family_id.

    Raises:
        HTTPException 404: If the card purchase does not exist.
        HTTPException 403: If the purchase belongs to another family.
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
) -> SavingsGoal:
    """
    Verifies that the requested savings goal exists and strictly belongs to the
    given family_id via its parent wallet and owner.

    Raises:
        HTTPException 404: If the savings goal or its wallet does not exist.
        HTTPException 403: If the savings goal belongs to another family.
    """
    q = db.query(SavingsGoal).filter(SavingsGoal.id == goal_id)
    if for_update:
        q = q.with_for_update()
    goal = q.first()

    if not goal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Savings goal not found",
        )

    wallet = db.query(Wallet).filter(Wallet.id == goal.wallet_id).first()
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Savings goal wallet not found",
        )

    owner = db.query(User).filter(User.id == wallet.owner_id).first()
    if not owner or owner.family_id != family_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Savings goal belongs to another family",
        )
    return goal
