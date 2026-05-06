from fastapi import APIRouter, Response
from pydantic import BaseModel

from auth import IS_PROD, EXPIRES_SECONDS, Role, ROLE_PERMISSIONS, create_token

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    role: Role = "WRITER"

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"username": "alice", "role": "ADMIN"},
                {"username": "bob", "role": "VISITOR"},
            ]
        }
    }


class LoginResponse(BaseModel):
    username:    str
    role:        Role
    permissions: list[str]
    expires_in:  int


def _set_cookie(response: Response, token: str):
    response.set_cookie(
        key="token",
        value=token,
        httponly=True,
        secure=IS_PROD,
        samesite="none" if IS_PROD else "lax",
        max_age=EXPIRES_SECONDS,
    )


@router.post("/login", response_model=LoginResponse, summary="Log in — sets a session cookie")
def login(body: LoginRequest, response: Response) -> LoginResponse:
    token = create_token(body.username, body.role)
    _set_cookie(response, token)
    return LoginResponse(
        username=body.username,
        role=body.role,
        permissions=ROLE_PERMISSIONS[body.role],
        expires_in=EXPIRES_SECONDS,
    )


@router.post("/logout", summary="Clear the session cookie")
def logout(response: Response):
    response.delete_cookie(
        "token",
        secure=IS_PROD,
        samesite="none" if IS_PROD else "lax",
    )
    return {"message": "logged out"}
