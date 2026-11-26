"""Admin backup and audit log (split from app/main.py in the Phase 3 completion work).

Mechanical move only: handler code is unchanged, only the
decorators changed from @app.* to @router.*.
"""

import asyncio
import json
import os
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from ..auth import get_current_user
from ..database import DATABASE_URL, SessionLocal, engine, get_db
from ..dependencies import ADMIN_ROLE, ALL_ROLES, require_role
from ..models import (
    AuditLog,
    Broadcast,
    CheckIn,
    Message,
    SOSEvent,
    User,
    UserSession,
)
from ..rate_limit import limiter
from ..security import (
    broadcast_canonical_string,
    contains_control_characters,
    hash_session_token,
    sign_broadcast,
    verify_broadcast_signature,
)
from ..websocket import issue_ws_ticket, manager, redeem_ws_ticket
from .. import crud, schemas
from ..helpers import (
    _audit_login_event,
    _check_register_rate_limit,
    _check_write_rate_limit,
    _client_ip,
    _idempotency_replay,
    _pagination,
    _save_idempotency,
    _session_still_valid,
    _sign_broadcast,
    security,
)

router = APIRouter()

@router.get("/api/admin/backup")
def download_backup(
    current_user: User = Depends(require_role(ADMIN_ROLE)),
):
    """Audit fix (5): download a consistent SQLite backup.

    A plain copy of nirapodnet.db while the server runs can miss
    WAL data. This uses SQLite's online backup API into a temp
    file, so the download is a consistent snapshot. PostgreSQL
    deployments must use pg_dump instead (this endpoint says so
    rather than silently handing out a wrong file), and an
    in-memory database has nothing to back up.
    """
    if not DATABASE_URL.startswith("sqlite"):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Backup endpoint is SQLite-only; "
            "use pg_dump for PostgreSQL",
        )

    source_path = DATABASE_URL[len("sqlite:///"):]
    if not source_path or source_path == ":memory:":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="In-memory database has no file to back up",
        )

    tmp = tempfile.NamedTemporaryFile(
        suffix=".db", delete=False
    )
    tmp_path = tmp.name
    tmp.close()

    source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
    try:
        dest = sqlite3.connect(tmp_path)
        try:
            source.backup(dest)
        finally:
            dest.close()
    finally:
        source.close()

    filename = (
        "nirapodnet-backup-"
        + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        + ".db"
    )

    def _cleanup(path: str):
        try:
            os.unlink(path)
        except OSError:
            pass

    return FileResponse(
        tmp_path,
        media_type="application/octet-stream",
        filename=filename,
        background=BackgroundTask(_cleanup, tmp_path),
    )


# -----------------------
# Audit Log API
# -----------------------

@router.get(
    "/api/audit-logs",
    response_model=list[schemas.AuditLogResponse],
)
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(
            "operator",
            "admin",
        )
    ),
):
    return crud.get_audit_logs(
        db,
        limit=limit,
    )