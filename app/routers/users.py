"""User and admin user management (split from app/main.py in the Phase 3 completion work).

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

@router.get(
    "/users",
    response_model=list[schemas.UserResponse],
)
def list_users(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends
    (require_role("admin")
     ),
):
    limit, offset = _pagination(limit, offset)
    return crud.get_users(db, limit=limit, offset=offset)


@router.get(
    "/api/admin/users",
    response_model=list[schemas.UserResponse],
)
def list_admin_users(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(ADMIN_ROLE)),
):
    limit, offset = _pagination(limit, offset)
    return crud.get_users(db, limit=limit, offset=offset)


@router.patch(
    "/api/admin/users/{user_id}/role",
    response_model=schemas.UserResponse,
)
def update_user_role(
    user_id: int,
    role_update: schemas.RoleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(ADMIN_ROLE)),
):
    if role_update.role not in ALL_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role",
        )

    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    user.role = role_update.role
    db.flush()

    # Phase 3: a token issued under the old role must not keep
    # working. All of this user's sessions are invalidated, so
    # the user must log in again under the new role.
    # Audit fix (10): role change, session invalidation and the
    # audit entry now commit together, not in three commits.
    crud.delete_sessions_for_user(db, user.id, commit=False)

    crud.log_audit(
        db,
        actor_id=current_user.id,
        action="user_role_updated",
        entity_type="user",
        entity_id=str(user.id),
        detail=f"{user.username} role set to {user.role}",
        commit=False,
    )

    db.commit()
    db.refresh(user)

    return user
