import json
import sqlite3
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path("devqueue.db")


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username      TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS resources (
                id       TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                data     TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS folders (
                id       TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                data     TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_res_user ON resources(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fol_user ON folders(username)")


# ── Users ────────────────────────────────────────────────────────────────────

def get_user(username: str) -> Optional[dict]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT username, password_hash, role FROM users WHERE username = ?", (username,)
        ).fetchone()
    return dict(row) if row else None


def save_user(username: str, password_hash: str, role: str):
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )


def list_users() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute("SELECT username, role FROM users ORDER BY username").fetchall()
    return [dict(r) for r in rows]


def delete_user(username: str):
    with _conn() as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))


# ── Resources ───────────────────────────────────────────────────────────────

def get_resources(username: str) -> dict[str, Any]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, data FROM resources WHERE username = ?", (username,)
        ).fetchall()
    return {row["id"]: json.loads(row["data"]) for row in rows}


def save_resource(username: str, resource: dict):
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO resources (id, username, data) VALUES (?, ?, ?)",
            (resource["id"], username, json.dumps(resource)),
        )


def delete_resource(username: str, resource_id: str):
    with _conn() as conn:
        conn.execute(
            "DELETE FROM resources WHERE id = ? AND username = ?",
            (resource_id, username),
        )


# ── Folders ─────────────────────────────────────────────────────────────────

def get_folders(username: str) -> dict[str, Any]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, data FROM folders WHERE username = ?", (username,)
        ).fetchall()
    return {row["id"]: json.loads(row["data"]) for row in rows}


def save_folder(username: str, folder: dict):
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO folders (id, username, data) VALUES (?, ?, ?)",
            (folder["id"], username, json.dumps(folder)),
        )


def delete_folder(username: str, folder_id: str):
    with _conn() as conn:
        conn.execute(
            "DELETE FROM folders WHERE id = ? AND username = ?",
            (folder_id, username),
        )


def nullify_folder_ref(username: str, folder_id: str):
    """Set folderId=null on all resources that belonged to the deleted folder."""
    for r in get_resources(username).values():
        if r.get("folderId") == folder_id:
            r["folderId"] = None
            save_resource(username, r)
