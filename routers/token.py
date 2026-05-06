from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel

from auth import IS_PROD, EXPIRES_SECONDS, Role, ROLE_PERMISSIONS, create_token, require

router = APIRouter(tags=["auth"])


# ── Shared helpers ──────────────────────────────────────────────────────────

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


# ── Schemas ─────────────────────────────────────────────────────────────────

class TokenRequest(BaseModel):
    role: Role = "WRITER"

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"role": "VISITOR"},
                {"role": "WRITER"},
                {"role": "ADMIN"},
            ]
        }
    }


class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    role:         Role
    permissions:  list[str]
    expires_in:   int


class LoginRequest(BaseModel):
    username: str
    role:     Role = "WRITER"

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"username": "alice", "role": "ADMIN"},
                {"username": "bob",   "role": "VISITOR"},
            ]
        }
    }


class LoginResponse(BaseModel):
    username:    str
    role:        Role
    permissions: list[str]
    expires_in:  int


class MeResponse(BaseModel):
    username:    str
    role:        Role
    permissions: list[str]


# ── Swagger / API-client token (Bearer) ─────────────────────────────────────

@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Get a Bearer JWT (for Swagger UI / API clients)",
    description=(
        "Returns a signed JWT in the response body. "
        "Click **Authorize** in Swagger and paste it as a Bearer token.\n\n"
        "| Role | Permissions |\n"
        "|------|-------------|\n"
        "| VISITOR | READ |\n"
        "| WRITER  | READ, WRITE |\n"
        "| ADMIN   | READ, WRITE, DELETE |"
    ),
)
def get_token(body: TokenRequest) -> TokenResponse:
    token = create_token(role=body.role, username="swagger-user")
    return TokenResponse(
        access_token=token,
        role=body.role,
        permissions=ROLE_PERMISSIONS[body.role],
        expires_in=EXPIRES_SECONDS,
    )


# ── Browser session (httpOnly cookie) ───────────────────────────────────────

@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Log in — sets an httpOnly session cookie",
    description="Username is used to scope data — two users with different names never see each other's resources.",
)
def login(body: LoginRequest, response: Response) -> LoginResponse:
    token = create_token(username=body.username, role=body.role)
    _set_cookie(response, token)
    return LoginResponse(
        username=body.username,
        role=body.role,
        permissions=ROLE_PERMISSIONS[body.role],
        expires_in=EXPIRES_SECONDS,
    )


@router.post("/logout", summary="Clear the session cookie")
def logout(response: Response):
    _clear_cookie(response)
    return {"message": "logged out"}


@router.get(
    "/me",
    response_model=MeResponse,
    summary="Get current session info",
    description="Returns 401 if no valid session cookie or Bearer token is present.",
)
def me(payload: dict = Depends(require("READ"))) -> MeResponse:
    return MeResponse(
        username=payload["sub"],
        role=payload["role"],
        permissions=payload["permissions"],
    )
