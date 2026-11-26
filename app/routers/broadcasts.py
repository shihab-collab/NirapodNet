"""Emergency broadcasts (split from app/main.py in the Phase 3 completion work).

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
    broadcast_alert,
    broadcast_sos,
    _sign_broadcast,
    security,
)

router = APIRouter()

@router.post(
    "/api/broadcasts",
    response_model=schemas.BroadcastResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_broadcast(
    broadcast: schemas.BroadcastCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(
            "operator",
            "admin",
        )
    ),
    idempotency_key: str | None = Header(default=None),
):
    _check_write_rate_limit(db, current_user)

    replay = _idempotency_replay(
        db, current_user, "POST /api/broadcasts", idempotency_key
    )

    if replay is not None:
        return replay

    created = crud.create_broadcast(
        db,
        issued_by=current_user.id,
        broadcast=broadcast,
        commit=False,
    )

    # Phase 3: sign the broadcast before it is delivered.
    created = _sign_broadcast(db, created, commit=False)

    crud.log_audit(
        db,
        actor_id=current_user.id,
        action="broadcast_created",
        entity_type="broadcast",
        entity_id=str(created.id),
        detail=(
            f"type={created.type} "
            f"priority={created.priority}"
        ),
        commit=False,
    )

    # Audit fix (10): broadcast + signature + audit commit
    # together; delivery happens only after that commit.
    db.commit()
    db.refresh(created)

    await broadcast_alert(
        {
            "type": "broadcast",
            "id": created.id,
            "broadcast_type": created.type,
            "message": created.message,
            "priority": created.priority,
            "issued_by": created.issued_by,
            "created_at": created.created_at.isoformat(),
            "signature": created.signature,
        }
    )

    body = schemas.BroadcastResponse.model_validate(
        created
    ).model_dump(mode="json")
    _save_idempotency(
        db, current_user, "POST /api/broadcasts",
        idempotency_key, 201, body,
    )

    return created


@router.get(
    "/api/broadcasts",
    response_model=list[schemas.BroadcastResponse],
)
def list_broadcasts(
    after_id: int | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    limit, offset = _pagination(limit, offset)
    return crud.get_broadcasts(
        db,
        after_id=after_id,
        limit=limit,
        offset=offset,
    )


@router.get("/api/broadcasts/{broadcast_id}/verify")
def verify_broadcast(
    broadcast_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Phase 3: check a stored broadcast's HMAC signature.

    Returns valid=False for broadcasts created before Phase 3
    (no signature stored) and for any broadcast whose stored
    fields no longer match its signature.
    """
    broadcast = (
        db.query(Broadcast)
        .filter(Broadcast.id == broadcast_id)
        .first()
    )

    if broadcast is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Broadcast not found",
        )

    canonical = broadcast_canonical_string(
        broadcast.id,
        broadcast.issued_by,
        broadcast.type,
        broadcast.message,
        broadcast.priority,
        broadcast.created_at.isoformat(),
    )

    return {
        "id": broadcast.id,
        "signature_present": broadcast.signature is not None,
        "valid": verify_broadcast_signature(
            canonical, broadcast.signature
        ),
    }
