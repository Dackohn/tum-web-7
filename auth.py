import os
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

import bcrypt
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

bearer_scheme = HTTPBearer(auto_error=False)

# Default accounts seeded on first startup
DEFAULT_USERS = [
    ("alice",   "alice123",   "ADMIN"),
    ("bob",     "bob123",     "WRITER"),
    ("charlie", "charlie123", "VISITOR"),
]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def seed_default_users():
    """Insert default users if the users table is empty."""
    from storage import get_user, save_user
    for username, password, role in DEFAULT_USERS:
        if not get_user(username):
            save_user(username, hash_password(password), role)


def verify_credentials(username: str, password: str) -> Optional[dict]:
    from storage import get_user
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


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
                detail="Not authenticated",
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
