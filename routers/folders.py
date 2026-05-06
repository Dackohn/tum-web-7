from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from auth import require
from storage import delete_folder, get_folders, get_resources, nullify_folder_ref, save_folder

router = APIRouter()


# ── Schemas ────────────────────────────────────────────────────────────────

class FolderIn(BaseModel):
    name:  str = Field(..., min_length=1, max_length=200)
    color: str = Field("#6366f1", pattern=r"^#[0-9a-fA-F]{6}$")

    model_config = {
        "json_schema_extra": {
            "examples": [{"name": "NLP Track", "color": "#06b6d4"}]
        }
    }


class FolderOut(FolderIn):
    id:             str
    createdAt:      str
    resource_count: int = 0


class PaginatedFolders(BaseModel):
    items:  list[FolderOut]
    total:  int
    limit:  int
    offset: int


# ── Helpers ────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_or_404(workspace: str, folder_id: str) -> dict[str, Any]:
    store = get_folders(workspace)
    if folder_id not in store:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Folder not found")
    return store[folder_id]


def _with_count(workspace: str, folder: dict) -> dict:
    count = sum(1 for r in get_resources(workspace).values() if r.get("folderId") == folder["id"])
    return {**folder, "resource_count": count}


# ── Routes ─────────────────────────────────────────────────────────────────

@router.get("", response_model=PaginatedFolders, summary="List folders")
def list_folders(
    limit:   int  = Query(20, ge=1, le=200),
    offset:  int  = Query(0,  ge=0),
    payload: dict = Depends(require("READ")),
):
    workspace = payload["workspace"]
    items = [_with_count(workspace, f) for f in get_folders(workspace).values()]
    items.sort(key=lambda f: f["createdAt"], reverse=True)
    return PaginatedFolders(items=items[offset:offset+limit], total=len(items), limit=limit, offset=offset)


@router.get("/{folder_id}", response_model=FolderOut, summary="Get a folder")
def get_folder(folder_id: str, payload: dict = Depends(require("READ"))):
    workspace = payload["workspace"]
    return _with_count(workspace, _get_or_404(workspace, folder_id))


@router.post("", response_model=FolderOut, status_code=status.HTTP_201_CREATED, summary="Create a folder")
def create_folder(body: FolderIn, payload: dict = Depends(require("WRITE"))):
    workspace = payload["workspace"]
    folder = {
        "id":        str(uuid4()),
        "name":      body.name.strip(),
        "color":     body.color,
        "createdAt": now_iso(),
    }
    save_folder(workspace, folder)
    return _with_count(workspace, folder)


@router.put("/{folder_id}", response_model=FolderOut, summary="Update a folder")
def update_folder(folder_id: str, body: FolderIn, payload: dict = Depends(require("WRITE"))):
    workspace = payload["workspace"]
    existing = _get_or_404(workspace, folder_id)
    updated = {**existing, "name": body.name.strip(), "color": body.color}
    save_folder(workspace, updated)
    return _with_count(workspace, updated)


@router.delete(
    "/{folder_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a folder",
    description="Deletes the folder and sets folderId=null on all its resources.",
)
def delete_folder_route(folder_id: str, payload: dict = Depends(require("DELETE"))):
    workspace = payload["workspace"]
    _get_or_404(workspace, folder_id)
    nullify_folder_ref(workspace, folder_id)
    delete_folder(workspace, folder_id)
