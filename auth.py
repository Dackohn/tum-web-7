import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

SECRET_KEY      = "dev-queue-secret-change-in-production"
ALGORITHM       = "HS256"
EXPIRES_SECONDS = 60
APP_VERSION     = "2.0.0"

IS_PROD = bool(os.getenv("RENDER"))

Role = Literal["VISITOR", "WRITER", "ADMIN"]

ROLE_PERMISSIONS: dict[Role, list[str]] = {
    "VISITOR": ["READ"],
    "WRITER":  ["READ", "WRITE"],
    "ADMIN":   ["READ", "WRITE", "DELETE"],
}

# Use bcrypt in production — SHA-256 is fine for a dev/lab environment
def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

USERS: dict[str, dict] = {
    "alice":   {"password_hash": _hash("alice123"),   "role": "ADMIN"},
    "bob":     {"password_hash": _hash("bob123"),     "role": "WRITER"},
    "charlie": {"password_hash": _hash("charlie123"), "role": "VISITOR"},
}


def verify_credentials(username: str, password: str) -> Optional[dict]:
    """Returns the user record if credentials are valid, otherwise None."""
    user = USERS.get(username)
    if not user:
        return None
    if not secrets.compare_digest(user["password_hash"], _hash(password)):
        return None
    return user


bearer_scheme = HTTPBearer(auto_error=False)


def create_token(username: str, role: Role) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub":         username,
        "role":        role,
        "permissions": ROLE_PERMISSIONS[role],
        "app_version": APP_VERSION,
        "iat":         now,
        "exp":         now + timedelta(seconds=EXPIRES_SECONDS),
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
    Accepts either an httpOnly cookie 'token' (POST /login)
    or an Authorization: Bearer … header (POST /token / Swagger UI).
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
