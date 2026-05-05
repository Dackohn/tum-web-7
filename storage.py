from typing import Any

# Simple in-memory store that mirrors the localStorage shape used by the
# React frontend. Keys are entity ids (str UUIDs).

_resources: dict[str, dict[str, Any]] = {}
_folders:   dict[str, dict[str, Any]] = {}


def get_resources() -> dict:
    return _resources


def get_folders() -> dict:
    return _folders
