import os
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import HTTPException, Request, status
from jose import JWTError, jwt

SECRET_KEY = "dev-queue-secret-change-in-production"
ALGORITHM  = "HS256"
EXPIRES_SECONDS = 3600  # 1 hour

# True when running on Render — controls cookie Secure + SameSite flags
IS_PROD = bool(os.getenv("RENDER"))

Role = Literal["VISITOR", "WRITER", "ADMIN"]

ROLE_PERMISSIONS: dict[Role, list[str]] = {
    "VISITOR": ["READ"],
    "WRITER":  ["READ", "WRITE"],
    "ADMIN":   ["READ", "WRITE", "DELETE"],
}


def create_token(username: str, role: Role) -> str:
    payload = {
        "sub":         username,
        "role":        role,
        "permissions": ROLE_PERMISSIONS[role],
        "exp":         datetime.now(timezone.utc) + timedelta(seconds=EXPIRES_SECONDS),
        "iat":         datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


def require(permission: str):
    """Dependency factory — reads JWT from httpOnly cookie and checks permission."""
    def dependency(request: Request) -> dict:
        token = request.cookies.get("token")
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
            )
        payload = decode_token(token)
        if permission not in payload.get("permissions", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required",
            )
        return payload
    return dependency
