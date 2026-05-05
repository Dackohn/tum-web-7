from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import token, resources, folders

app = FastAPI(
    title="Dev Queue API",
    description="REST API for the Dev Queue learning tracker. Use POST /token to get a JWT, then pass it as `Authorization: Bearer <token>` on every other request.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:4173",
        "https://dackohn.github.io",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(token.router, tags=["auth"])
app.include_router(resources.router, prefix="/resources", tags=["resources"])
app.include_router(folders.router, prefix="/folders", tags=["folders"])


@app.get("/", include_in_schema=False)
def root():
    return {"message": "Dev Queue API — see /docs for Swagger UI"}
