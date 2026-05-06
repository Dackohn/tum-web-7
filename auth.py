import os
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

SECRET_KEY = "dev-queue-secret-change-in-production"
ALGORITHM  = "HS256"
EXPIRES_SECONDS = 60

# True when running on Render — controls cookie Secure + SameSite flags
IS_PROD = bool(os.getenv("RENDER"))

Role = Literal["VISITOR", "WRITER", "ADMIN"]

ROLE_PERMISSIONS: dict[Role, list[str]] = {
    "VISITOR": ["READ"],
    "WRITER":  ["READ", "WRITE"],
    "ADMIN":   ["READ", "WRITE", "DELETE"],
}

# auto_error=False so missing header doesn't immediately 401 — we check cookie first
bearer_scheme = HTTPBearer(auto_error=False)


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
            headers={"WWW-Authenticate": "Bearer"},
        )


def require(permission: str):
    """
    Dependency that accepts either:
    - httpOnly cookie 'token'  (browser app via POST /login)
    - Authorization: Bearer … (Swagger UI / API clients via POST /token)
    """
    def dependency(
        request: Request,
        creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    ) -> dict:
        token = request.cookies.get("token")
        if not token and creds:
            token = creds.credentials
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated — use POST /login (cookie) or POST /token (Bearer)",
                headers={"WWW-Authenticate": "Bearer"},
            )
        payload = decode_token(token)
        if permission not in payload.get("permissions", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required",
            )
        return payload
    return dependency
