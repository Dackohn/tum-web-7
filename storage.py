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
                role          TEXT NOT NULL,
                workspace     TEXT NOT NULL DEFAULT ''
            )
        """)
        # Add workspace column to existing DBs that predate this schema
        try:
            conn.execute("ALTER TABLE users ADD COLUMN workspace TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass
        # Backfill workspace = username for ADMIN rows that have an empty workspace
        conn.execute("UPDATE users SET workspace = username WHERE role = 'ADMIN' AND workspace = ''")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS resources (
                id        TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                data      TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS folders (
                id        TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                data      TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_res_ws  ON resources(workspace)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fol_ws  ON folders(workspace)")


# ── Users ────────────────────────────────────────────────────────────────────

def get_user(username: str) -> Optional[dict]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT username, password_hash, role, workspace FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def save_user(username: str, password_hash: str, role: str, workspace: str):
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, password_hash, role, workspace) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, workspace),
        )


def list_workspace_members(workspace: str) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT username, role, workspace FROM users WHERE workspace = ? ORDER BY username",
            (workspace,),
        ).fetchall()
    return [dict(r) for r in rows]


def delete_user(username: str):
    with _conn() as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))


# ── Resources ────────────────────────────────────────────────────────────────

def get_resources(workspace: str) -> dict[str, Any]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, data FROM resources WHERE workspace = ?", (workspace,)
        ).fetchall()
    return {row["id"]: json.loads(row["data"]) for row in rows}


def save_resource(workspace: str, resource: dict):
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO resources (id, workspace, data) VALUES (?, ?, ?)",
            (resource["id"], workspace, json.dumps(resource)),
        )


def delete_resource(workspace: str, resource_id: str):
    with _conn() as conn:
        conn.execute(
            "DELETE FROM resources WHERE id = ? AND workspace = ?",
            (resource_id, workspace),
        )


# ── Folders ──────────────────────────────────────────────────────────────────

def get_folders(workspace: str) -> dict[str, Any]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, data FROM folders WHERE workspace = ?", (workspace,)
        ).fetchall()
    return {row["id"]: json.loads(row["data"]) for row in rows}


def save_folder(workspace: str, folder: dict):
    with _conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO folders (id, workspace, data) VALUES (?, ?, ?)",
            (folder["id"], workspace, json.dumps(folder)),
        )


def delete_folder(workspace: str, folder_id: str):
    with _conn() as conn:
        conn.execute(
            "DELETE FROM folders WHERE id = ? AND workspace = ?",
            (folder_id, workspace),
        )


def nullify_folder_ref(workspace: str, folder_id: str):
    for r in get_resources(workspace).values():
        if r.get("folderId") == folder_id:
            r["folderId"] = None
            save_resource(workspace, r)
