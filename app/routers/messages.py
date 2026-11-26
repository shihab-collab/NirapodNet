"""Chat messages (split from app/main.py in the Phase 3 completion work).

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

@router.post("/messages", response_model=schemas.MessageResponse)
def create_message(
    message: schemas.MessageCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(
            "user",
            "rescue",
            "responder",
            "operator",
            "admin",
        )
    ),
    idempotency_key: str | None = Header(default=None),
):
    _check_write_rate_limit(db, current_user)

    replay = _idempotency_replay(
        db, current_user, "POST /messages", idempotency_key
    )

    if replay is not None:
        return replay

    message.sender_id = current_user.id

    created = crud.create_message(db, message)
    body = schemas.MessageResponse.model_validate(created).model_dump(
        mode="json"
    )
    _save_idempotency(
        db, current_user, "POST /messages", idempotency_key, 200, body
    )

    return created


@router.get("/messages", response_model=list[schemas.MessageResponse])
def list_messages(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Audit fix (4): bounded list, and crud.get_messages loads the
    # sender with joinedload instead of one query per message.
    limit, offset = _pagination(limit, offset)
    return crud.get_messages(db, limit=limit, offset=offset)
