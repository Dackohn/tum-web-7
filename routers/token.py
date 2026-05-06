from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

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
from storage import delete_user, get_user, list_workspace_members, save_user

router = APIRouter(tags=["auth"])


# ── Cookie helpers ────────────────────────────────────────────────────────────

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


# ── Schemas ───────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=40)
    password: str = Field(..., min_length=4)

    model_config = {
        "json_schema_extra": {
            "examples": [{"username": "alice", "password": "alice123"}]
        }
    }


class AddMemberRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=40)
    password: str = Field(..., min_length=4)
    role:     Role = "VISITOR"

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"username": "bob",     "password": "bob123",     "role": "WRITER"},
                {"username": "charlie", "password": "charlie123", "role": "VISITOR"},
            ]
        }
    }


class CredentialsRequest(BaseModel):
    username: str
    password: str

    model_config = {
        "json_schema_extra": {
            "examples": [{"username": "alice", "password": "alice123"}]
        }
    }


class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    username:     str
    role:         Role
    workspace:    str
    permissions:  list[str]
    expires_in:   int
    app_version:  str


class SessionResponse(BaseModel):
    username:    str
    role:        Role
    workspace:   str
    permissions: list[str]
    expires_in:  int
    app_version: str


class MeResponse(BaseModel):
    username:    str
    role:        Role
    workspace:   str
    permissions: list[str]
    app_version: str
    issued_at:   datetime
    expires_at:  datetime


class MemberOut(BaseModel):
    username:    str
    role:        Role
    permissions: list[str]


# ── Open registration (creates an ADMIN workspace) ───────────────────────────

@router.post(
    "/register",
    response_model=SessionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new admin workspace",
    description=(
        "Open endpoint — no auth required. Creates an **ADMIN** account and a personal "
        "workspace. The workspace name equals the username. Returns a session cookie so "
        "the user is logged in immediately after registering."
    ),
)
def register(body: RegisterRequest, response: Response) -> SessionResponse:
    if get_user(body.username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"Username '{body.username}' is already taken.")
    save_user(body.username, hash_password(body.password), "ADMIN", workspace=body.username)
    token = create_token(body.username, "ADMIN", workspace=body.username)
    _set_cookie(response, token)
    return SessionResponse(
        username=body.username,
        role="ADMIN",
        workspace=body.username,
        permissions=ROLE_PERMISSIONS["ADMIN"],
        expires_in=EXPIRES_SECONDS,
        app_version=APP_VERSION,
    )


# ── Login (cookie) ────────────────────────────────────────────────────────────

@router.post(
    "/login",
    response_model=SessionResponse,
    summary="Log in — sets an httpOnly session cookie",
)
def login(body: CredentialsRequest, response: Response) -> SessionResponse:
    user = verify_credentials(body.username, body.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid username or password.")
    token = create_token(body.username, user["role"], workspace=user["workspace"])
    _set_cookie(response, token)
    return SessionResponse(
        username=body.username,
        role=user["role"],
        workspace=user["workspace"],
        permissions=ROLE_PERMISSIONS[user["role"]],
        expires_in=EXPIRES_SECONDS,
        app_version=APP_VERSION,
    )


# ── Token (Bearer, for Swagger) ───────────────────────────────────────────────

@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Get a Bearer JWT (Swagger UI / API clients)",
    description=(
        "Returns a signed JWT in the response body for use with Swagger's **Authorize** button.\n\n"
        "Register first via **POST /register**, then use those credentials here."
    ),
)
def get_token(body: CredentialsRequest) -> TokenResponse:
    user = verify_credentials(body.username, body.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid username or password.")
    token = create_token(body.username, user["role"], workspace=user["workspace"])
    return TokenResponse(
        access_token=token,
        username=body.username,
        role=user["role"],
        workspace=user["workspace"],
        permissions=ROLE_PERMISSIONS[user["role"]],
        expires_in=EXPIRES_SECONDS,
        app_version=APP_VERSION,
    )


# ── Logout ────────────────────────────────────────────────────────────────────

@router.post("/logout", summary="Clear the session cookie")
def logout(response: Response):
    _clear_cookie(response)
    return {"message": "Logged out successfully"}


# ── Session info ──────────────────────────────────────────────────────────────

@router.get("/me", response_model=MeResponse, summary="Current session info")
def me(payload: dict = Depends(require("READ"))) -> MeResponse:
    return MeResponse(
        username=payload["sub"],
        role=payload["role"],
        workspace=payload["workspace"],
        permissions=payload["permissions"],
        app_version=payload.get("app_version", "unknown"),
        issued_at=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
        expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
    )


# ── Workspace member management (ADMIN only) ──────────────────────────────────

def _require_admin(payload: dict = Depends(require("DELETE"))) -> dict:
    if payload["role"] != "ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return payload


@router.post(
    "/members",
    response_model=MemberOut,
    status_code=status.HTTP_201_CREATED,
    summary="Add a member to your workspace (ADMIN only)",
    description="Adds a WRITER or VISITOR to the current admin's workspace. They share the admin's data.",
)
def add_member(body: AddMemberRequest, payload: dict = Depends(_require_admin)) -> MemberOut:
    if body.role == "ADMIN":
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="Use POST /register to create admin accounts.")
    if get_user(body.username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"Username '{body.username}' is already taken.")
    workspace = payload["workspace"]
    save_user(body.username, hash_password(body.password), body.role, workspace=workspace)
    return MemberOut(
        username=body.username,
        role=body.role,
        permissions=ROLE_PERMISSIONS[body.role],
    )


@router.get(
    "/members",
    response_model=list[MemberOut],
    summary="List workspace members",
    description="Returns all users (including the admin) who belong to the current workspace.",
)
def get_members(payload: dict = Depends(require("READ"))) -> list[MemberOut]:
    return [
        MemberOut(username=m["username"], role=m["role"], permissions=ROLE_PERMISSIONS[m["role"]])
        for m in list_workspace_members(payload["workspace"])
    ]


@router.delete(
    "/members/{username}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a member from your workspace (ADMIN only)",
)
def remove_member(username: str, payload: dict = Depends(_require_admin)):
    if username == payload["sub"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Cannot remove yourself.")
    member = get_user(username)
    if not member or member["workspace"] != payload["workspace"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Member '{username}' not found in your workspace.")
    delete_user(username)
