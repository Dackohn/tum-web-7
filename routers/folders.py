from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from auth import require
from storage import get_folders, get_resources

router = APIRouter()


# ── Schemas ────────────────────────────────────────────────────────────────

class FolderIn(BaseModel):
    name:  str   = Field(..., min_length=1, max_length=200)
    color: str   = Field("#6366f1", pattern=r"^#[0-9a-fA-F]{6}$")

    model_config = {
        "json_schema_extra": {
            "examples": [{"name": "NLP Track", "color": "#06b6d4"}]
        }
    }


class FolderOut(FolderIn):
    id:            str
    createdAt:     str
    resource_count: int = 0


class PaginatedFolders(BaseModel):
    items:  list[FolderOut]
    total:  int
    limit:  int
    offset: int


# ── Helpers ────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_or_404(folder_id: str) -> dict[str, Any]:
    store = get_folders()
    if folder_id not in store:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    return store[folder_id]


def _with_count(folder: dict) -> dict:
    count = sum(1 for r in get_resources().values() if r.get("folderId") == folder["id"])
    return {**folder, "resource_count": count}


# ── Routes ─────────────────────────────────────────────────────────────────

@router.get(
    "",
    response_model=PaginatedFolders,
    summary="List folders (pipelines)",
    description="Returns a paginated list of all folders with a resource count for each.",
)
def list_folders(
    limit:  int = Query(20, ge=1, le=200),
    offset: int = Query(0,  ge=0),
    _: dict = Depends(require("READ")),
):
    items = [_with_count(f) for f in get_folders().values()]
    items.sort(key=lambda f: f["createdAt"], reverse=True)
    return PaginatedFolders(items=items[offset:offset+limit], total=len(items), limit=limit, offset=offset)


@router.get("/{folder_id}", response_model=FolderOut, summary="Get a folder")
def get_folder(folder_id: str, _: dict = Depends(require("READ"))):
    return _with_count(_get_or_404(folder_id))


@router.post(
    "",
    response_model=FolderOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a folder (pipeline)",
)
def create_folder(body: FolderIn, _: dict = Depends(require("WRITE"))):
    store = get_folders()
    folder = {
        "id":        str(uuid4()),
        "name":      body.name.strip(),
        "color":     body.color,
        "createdAt": now_iso(),
    }
    store[folder["id"]] = folder
    return _with_count(folder)


@router.put("/{folder_id}", response_model=FolderOut, summary="Update a folder")
def update_folder(folder_id: str, body: FolderIn, _: dict = Depends(require("WRITE"))):
    existing = _get_or_404(folder_id)
    updated = {**existing, "name": body.name.strip(), "color": body.color}
    get_folders()[folder_id] = updated
    return _with_count(updated)


@router.delete(
    "/{folder_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a folder",
    description="Deletes the folder. Resources that belonged to it are set to unfiled (folderId = null).",
)
def delete_folder(folder_id: str, _: dict = Depends(require("DELETE"))):
    _get_or_404(folder_id)
    del get_folders()[folder_id]
    for r in get_resources().values():
        if r.get("folderId") == folder_id:
            r["folderId"] = None
