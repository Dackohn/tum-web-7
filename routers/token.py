from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from auth import EXPIRES_SECONDS, Role, create_token

router = APIRouter()


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


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Get a JWT",
    description=(
        "Returns a signed JWT for the requested role. "
        "Pass the token as `Authorization: Bearer <token>` on all other requests.\n\n"
        "| Role | Permissions |\n"
        "|------|-------------|\n"
        "| VISITOR | READ |\n"
        "| WRITER  | READ, WRITE |\n"
        "| ADMIN   | READ, WRITE, DELETE |"
    ),
)
def get_token(body: TokenRequest) -> TokenResponse:
    from auth import ROLE_PERMISSIONS
    token = create_token(body.role)
    return TokenResponse(
        access_token=token,
        role=body.role,
        permissions=ROLE_PERMISSIONS[body.role],
        expires_in=EXPIRES_SECONDS,
    )
