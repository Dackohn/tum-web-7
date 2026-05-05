from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from auth import require
from storage import get_resources

router = APIRouter()

STATUS_VALUES = {"queued", "in-progress", "done"}
CATEGORY_VALUES = {"article", "video", "docs", "course", "book", "podcast", "other"}


# ── Schemas ────────────────────────────────────────────────────────────────

class ResourceIn(BaseModel):
    title:    str = Field(..., min_length=1, max_length=500)
    url:      str = ""
    category: str = Field("article", pattern="^(article|video|docs|course|book|podcast|other)$")
    status:   str = Field("queued",  pattern="^(queued|in-progress|done)$")
    tags:     list[str] = []
    notes:    str = ""
    rating:   int = Field(0, ge=0, le=5)
    starred:  bool = False
    folderId: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "title": "Practical Deep Learning for Coders",
                "url": "https://course.fast.ai",
                "category": "course",
                "status": "queued",
                "tags": ["deep-learning", "pytorch"],
                "notes": "Top-down approach — start with working code.",
                "rating": 0,
                "starred": True,
                "folderId": None,
            }]
        }
    }


class ResourceOut(ResourceIn):
    id:        str
    createdAt: str
    updatedAt: str


class PaginatedResources(BaseModel):
    items:  list[ResourceOut]
    total:  int
    limit:  int
    offset: int


# ── Helpers ────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_or_404(resource_id: str) -> dict[str, Any]:
    store = get_resources()
    if resource_id not in store:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
    return store[resource_id]


# ── Routes ─────────────────────────────────────────────────────────────────

@router.get(
    "",
    response_model=PaginatedResources,
    summary="List resources",
    description="Returns a paginated list of all resources. Use `limit` and `offset` for pagination.",
)
def list_resources(
    limit:  int  = Query(20, ge=1, le=200, description="Max items to return"),
    offset: int  = Query(0,  ge=0,         description="Items to skip"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    category: Optional[str]      = Query(None, description="Filter by category"),
    _: dict = Depends(require("READ")),
):
    items = list(get_resources().values())

    if status_filter:
        items = [r for r in items if r["status"] == status_filter]
    if category:
        items = [r for r in items if r["category"] == category]

    items.sort(key=lambda r: r["createdAt"], reverse=True)

    return PaginatedResources(
        items=items[offset : offset + limit],
        total=len(items),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{resource_id}",
    response_model=ResourceOut,
    summary="Get a resource",
)
def get_resource(resource_id: str, _: dict = Depends(require("READ"))):
    return _get_or_404(resource_id)


@router.post(
    "",
    response_model=ResourceOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a resource",
)
def create_resource(body: ResourceIn, _: dict = Depends(require("WRITE"))):
    store = get_resources()
    ts = now_iso()
    resource = {
        "id":        str(uuid4()),
        "createdAt": ts,
        "updatedAt": ts,
        **body.model_dump(),
        "tags": [t.strip().lower() for t in body.tags if t.strip()],
        "rating": body.rating if body.status == "done" else 0,
    }
    store[resource["id"]] = resource
    return resource


@router.put(
    "/{resource_id}",
    response_model=ResourceOut,
    summary="Update a resource",
)
def update_resource(resource_id: str, body: ResourceIn, _: dict = Depends(require("WRITE"))):
    existing = _get_or_404(resource_id)
    updated = {
        **existing,
        **body.model_dump(),
        "id":        resource_id,
        "createdAt": existing["createdAt"],
        "updatedAt": now_iso(),
        "tags": [t.strip().lower() for t in body.tags if t.strip()],
        "rating": body.rating if body.status == "done" else 0,
    }
    get_resources()[resource_id] = updated
    return updated


@router.delete(
    "/{resource_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a resource",
)
def delete_resource(resource_id: str, _: dict = Depends(require("DELETE"))):
    _get_or_404(resource_id)
    del get_resources()[resource_id]
