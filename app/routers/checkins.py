"""Safety check-ins (split from app/main.py in the Phase 3 completion work).

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

@router.post(
    "/api/checkins",
    response_model=schemas.CheckInResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_checkin(
    checkin: schemas.CheckInCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    idempotency_key: str | None = Header(default=None),
):
    _check_write_rate_limit(db, current_user)

    replay = _idempotency_replay(
        db, current_user, "POST /api/checkins", idempotency_key
    )

    if replay is not None:
        return replay

    created = crud.create_checkin(
        db,
        user_id=current_user.id,
        checkin=checkin,
        commit=False,
    )

    if created is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Broadcast not found",
        )

    crud.log_audit(
        db,
        actor_id=current_user.id,
        action="checkin_created",
        entity_type="checkin",
        entity_id=str(created["id"]),
        detail=f"status={created['status']}",
        commit=False,
    )

    db.commit()

    body = schemas.CheckInResponse.model_validate(
        created
    ).model_dump(mode="json")
    _save_idempotency(
        db, current_user, "POST /api/checkins",
        idempotency_key, 201, body,
    )

    return created


@router.get(
    "/api/checkins/me",
    response_model=list[schemas.CheckInResponse],
)
def list_my_checkins(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    limit, offset = _pagination(limit, offset)
    return crud.get_user_checkins(
        db,
        user_id=current_user.id,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/api/checkins/summary",
    response_model=schemas.CheckInSummaryResponse,
)
def get_checkin_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(
            "rescue",
            "responder",
            "operator",
            "admin",
        )
    ),
):
    return crud.get_checkin_summary(db)


@router.get(
    "/api/checkins",
    response_model=list[schemas.CheckInResponse],
)
def list_checkins(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role(
            "rescue",
            "responder",
            "operator",
            "admin",
        )
    ),
):
    limit, offset = _pagination(limit, offset)
    return crud.get_checkins(db, limit=limit, offset=offset)
