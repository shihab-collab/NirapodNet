"""SOS incidents (split from app/main.py in the Phase 3 completion work).

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
    "/api/sos",
    response_model=schemas.SOSResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_sos(
    sos: schemas.SOSCreate,
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
        db, current_user, "POST /api/sos", idempotency_key
    )

    if replay is not None:
        return replay

    incident = crud.create_sos(
        db=db,
        user_id=current_user.id,
        sos=sos,
        commit=False,
    )

    crud.log_audit(
        db,
        actor_id=current_user.id,
        action="sos_created",
        entity_type="sos",
        entity_id=incident.incident_id,
        detail=f"emergency_type={incident.emergency_type}",
        commit=False,
    )

    # Audit fix (10): incident + audit commit together; the live
    # broadcast is sent only after that commit, so a crash cannot
    # leave a broadcast for an SOS that was never stored.
    db.commit()
    db.refresh(incident)

    await broadcast_sos(
        db,
        {
            "type": "sos",
            "incident_id": incident.incident_id,
            "user_id": incident.user_id,
            "emergency_type": incident.emergency_type,
            "latitude": (
                float(incident.latitude)
                if incident.latitude is not None
                else None
            ),
            "longitude": (
                float(incident.longitude)
                if incident.longitude is not None
                else None
            ),
            "description": incident.description,
            "status": incident.status,
            "created_at": incident.created_at.isoformat(),
        },
    )

    body = schemas.SOSResponse.model_validate(incident).model_dump(
        mode="json"
    )
    _save_idempotency(
        db, current_user, "POST /api/sos", idempotency_key, 201, body
    )

    return incident


@router.get(
    "/api/sos",
    response_model=list[schemas.SOSResponse],
)
def list_sos(
    status_filter: str | None = Query(
        default=None,
        alias="status",
    ),
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
    allowed_statuses = {
        "OPEN",
        "RESPONDING",
        "ON-SCENE",
        "RESOLVED",
    }

    if (
        status_filter is not None
        and status_filter not in allowed_statuses
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid SOS status",
        )

    limit, offset = _pagination(limit, offset)
    return crud.get_sos_events(
        db,
        status_filter=status_filter,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/api/sos/{incident_id}/history",
    response_model=list[schemas.SOSStatusHistoryResponse],
)
def get_sos_history(
    incident_id: str,
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
    incident = crud.get_sos_by_incident_id(
        db,
        incident_id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOS incident not found",
        )

    return crud.get_sos_history(
        db,
        incident,
    )


@router.patch(
    "/api/sos/{incident_id}/status",
    response_model=schemas.SOSResponse,
)
async def update_sos_status(
    incident_id: str,
    update: schemas.SOSStatusUpdate,
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
    incident = crud.get_sos_by_incident_id(
        db,
        incident_id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOS incident not found",
        )

    updated = crud.update_sos_status(
        db=db,
        incident=incident,
        new_status=update.status,
        changed_by=current_user.id,
        commit=False,
    )

    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Invalid SOS status transition",
        )

    crud.log_audit(
        db,
        actor_id=current_user.id,
        action="sos_status_changed",
        entity_type="sos",
        entity_id=updated.incident_id,
        detail=f"status set to {updated.status}",
        commit=False,
    )

    db.commit()
    db.refresh(updated)

    await broadcast_sos(
        db,
        {
            "type": "sos_status",
            "incident_id": updated.incident_id,
            "status": updated.status,
            "changed_by": current_user.id,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
        },
    )

    return updated
