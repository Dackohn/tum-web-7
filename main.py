from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import token, resources, folders
from auth import seed_default_users
from storage import init_db

app = FastAPI(
    title="Dev Queue API",
    description="REST API for the Dev Queue learning tracker. Use POST /login to get a session cookie, then call any endpoint.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:4173",
        "https://dackohn.github.io",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(token.router, tags=["auth"])
app.include_router(resources.router, prefix="/resources", tags=["resources"])
app.include_router(folders.router, prefix="/folders", tags=["folders"])


@app.on_event("startup")
def startup():
    init_db()
    seed_default_users()


@app.get("/", include_in_schema=False)
def root():
    return {"message": "Dev Queue API — see /docs for Swagger UI"}
