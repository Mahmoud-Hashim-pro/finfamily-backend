from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import User
from core.security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    try:
        payload = decode_access_token(credentials.credentials)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    # BUG-001 (P0): Reject temporary MFA challenge / pending tokens on all normal endpoints
    if (
        payload.get("role") == "mfa_pending"
        or payload.get("type") == "mfa_challenge"
        or payload.get("mfa_pending") is True
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA verification required",
        )

    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
        )

    # BUG-009 (P1): Verify token_version matches user.token_version
    token_version = payload.get("token_version")
    user_token_version = getattr(user, "token_version", 1) or 1
    if token_version is None or token_version != user_token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )

    # FF-02 & FF-10: Centrally reject deactivated accounts across all protected endpoints
    if hasattr(user, "is_active") and not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is deactivated. Contact administration to restore access.",
        )

    return user


def require_parent(user: User = Depends(get_current_user)) -> User:
    role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
    if role_str != "parent":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Parent access only",
        )
    return user


def require_child(user: User = Depends(get_current_user)) -> User:
    role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
    if role_str != "child":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Child access only",
        )
    return user