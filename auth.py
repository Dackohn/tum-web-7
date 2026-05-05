from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

SECRET_KEY = "dev-queue-secret-change-in-production"
ALGORITHM  = "HS256"
EXPIRES_SECONDS = 60  # short-lived for demo purposes

Role = Literal["VISITOR", "WRITER", "ADMIN"]

ROLE_PERMISSIONS: dict[Role, list[str]] = {
    "VISITOR": ["READ"],
    "WRITER":  ["READ", "WRITE"],
    "ADMIN":   ["READ", "WRITE", "DELETE"],
}

bearer_scheme = HTTPBearer()


def create_token(role: Role) -> str:
    permissions = ROLE_PERMISSIONS[role]
    payload = {
        "sub":         "user",
        "role":        role,
        "permissions": permissions,
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
            headers={"WWW-Authenticate": "Bearer"},
        )


def require(permission: str):
    """Dependency factory — injects the decoded payload and checks permission."""
    def dependency(
        creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    ) -> dict:
        payload = decode_token(creds.credentials)
        if permission not in payload.get("permissions", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required",
            )
        return payload
    return dependency
