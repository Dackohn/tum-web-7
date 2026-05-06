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
    hash_password,
    require,
    verify_credentials,
)
from storage import delete_user, get_user, list_users, save_user

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


# ── User management (ADMIN only) ─────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str = ""
    password: str = ""
    role:     Role = "VISITOR"

    model_config = {
        "json_schema_extra": {
            "examples": [{"username": "dave", "password": "dave123", "role": "WRITER"}]
        }
    }


class UserOut(BaseModel):
    username: str
    role:     Role
    permissions: list[str]


def _require_admin(payload: dict = Depends(require("DELETE"))) -> dict:
    if payload["role"] != "ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return payload


@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user (ADMIN only)",
    description="Creates a new user account. Only users with the ADMIN role can call this.",
)
def register(body: RegisterRequest, payload: dict = Depends(_require_admin)) -> UserOut:
    if not body.username.strip() or not body.password:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="Username and password are required")
    if get_user(body.username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"User '{body.username}' already exists")
    save_user(body.username.strip(), hash_password(body.password), body.role)
    return UserOut(
        username=body.username.strip(),
        role=body.role,
        permissions=ROLE_PERMISSIONS[body.role],
    )


@router.get(
    "/users",
    response_model=list[UserOut],
    summary="List all users (ADMIN only)",
)
def get_users(_: dict = Depends(_require_admin)) -> list[UserOut]:
    return [
        UserOut(username=u["username"], role=u["role"], permissions=ROLE_PERMISSIONS[u["role"]])
        for u in list_users()
    ]


@router.delete(
    "/users/{username}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a user (ADMIN only)",
)
def remove_user(username: str, payload: dict = Depends(_require_admin)):
    if username == payload["sub"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Cannot delete your own account")
    if not get_user(username):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"User '{username}' not found")
    delete_user(username)
