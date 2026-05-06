from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel

from auth import (
    APP_VERSION,
    EXPIRES_SECONDS,
    IS_PROD,
    ROLE_PERMISSIONS,
    Role,
    create_token,
    require,
    verify_credentials,
)

router = APIRouter(tags=["auth"])


# ── Helpers ──────────────────────────────────────────────────────────────────

def _set_cookie(response: Response, token: str):
    response.set_cookie(
        key="token",
        value=token,
        httponly=True,
        secure=IS_PROD,
        samesite="none" if IS_PROD else "lax",
        max_age=EXPIRES_SECONDS,
        path="/",
    )


def _clear_cookie(response: Response):
    response.delete_cookie(
        key="token",
        httponly=True,
        secure=IS_PROD,
        samesite="none" if IS_PROD else "lax",
        path="/",
    )


def _require_valid_user(username: str, password: str) -> dict:
    user = verify_credentials(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    return user


# ── Schemas ──────────────────────────────────────────────────────────────────

class TokenRequest(BaseModel):
    username: str
    password: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"username": "alice",   "password": "alice123"},
                {"username": "bob",     "password": "bob123"},
                {"username": "charlie", "password": "charlie123"},
            ]
        }
    }


class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    username:     str
    role:         Role
    permissions:  list[str]
    expires_in:   int
    app_version:  str


class LoginRequest(BaseModel):
    username: str
    password: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"username": "alice",   "password": "alice123"},
                {"username": "bob",     "password": "bob123"},
                {"username": "charlie", "password": "charlie123"},
            ]
        }
    }


class LoginResponse(BaseModel):
    username:    str
    role:        Role
    permissions: list[str]
    expires_in:  int
    app_version: str


class MeResponse(BaseModel):
    username:    str
    role:        Role
    permissions: list[str]
    app_version: str
    issued_at:   datetime
    expires_at:  datetime


# ── Swagger / API-client token (Bearer) ──────────────────────────────────────

@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Get a Bearer JWT (for Swagger UI / API clients)",
    description=(
        "Returns a signed JWT. Click **Authorize** in Swagger and paste it as a Bearer token.\n\n"
        "**Available users:**\n\n"
        "| Username | Password | Role |\n"
        "|----------|----------|------|\n"
        "| alice | alice123 | ADMIN |\n"
        "| bob | bob123 | WRITER |\n"
        "| charlie | charlie123 | VISITOR |\n\n"
        "| Role | Permissions |\n"
        "|------|-------------|\n"
        "| VISITOR | READ |\n"
        "| WRITER  | READ, WRITE |\n"
        "| ADMIN   | READ, WRITE, DELETE |"
    ),
)
def get_token(body: TokenRequest) -> TokenResponse:
    user = _require_valid_user(body.username, body.password)
    role: Role = user["role"]
    token = create_token(username=body.username, role=role)
    return TokenResponse(
        access_token=token,
        username=body.username,
        role=role,
        permissions=ROLE_PERMISSIONS[role],
        expires_in=EXPIRES_SECONDS,
        app_version=APP_VERSION,
    )


# ── Browser session (httpOnly cookie) ────────────────────────────────────────

@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Log in — sets an httpOnly session cookie",
    description="Authenticates against the user registry. The role is determined server-side from the user record.",
)
def login(body: LoginRequest, response: Response) -> LoginResponse:
    user = _require_valid_user(body.username, body.password)
    role: Role = user["role"]
    token = create_token(username=body.username, role=role)
    _set_cookie(response, token)
    return LoginResponse(
        username=body.username,
        role=role,
        permissions=ROLE_PERMISSIONS[role],
        expires_in=EXPIRES_SECONDS,
        app_version=APP_VERSION,
    )


@router.post("/logout", summary="Clear the session cookie")
def logout(response: Response):
    _clear_cookie(response)
    return {"message": "Logged out successfully"}


@router.get(
    "/me",
    response_model=MeResponse,
    summary="Current session info",
    description=(
        "Returns the identity and capabilities encoded in the active token.\n\n"
        "`app_version` lets consumers detect tokens issued by an older API version."
    ),
)
def me(payload: dict = Depends(require("READ"))) -> MeResponse:
    return MeResponse(
        username=payload["sub"],
        role=payload["role"],
        permissions=payload["permissions"],
        app_version=payload.get("app_version", "unknown"),
        issued_at=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
        expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
    )
