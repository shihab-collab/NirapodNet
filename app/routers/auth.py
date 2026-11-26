"""Registration, login and sessions (split from app/main.py in the Phase 3 completion work).

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

@router.post("/users", response_model=schemas.UserResponse)
def create_user(
    request: Request,
    user: schemas.UserCreate,
    db: Session = Depends(get_db)
):
    # Legacy Phase 1 path, kept working (Phase 1 regression test)
    # but rate-limited exactly like /api/register; see docs/API.md.
    _check_register_rate_limit(request)
    return crud.create_user(db, user)


@router.post(
    "/api/register",
    response_model=schemas.UserResponse,
    status_code=201,
)
def register_user(
    request: Request,
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
):
    _check_register_rate_limit(request)
    existing = (
        db.query(User)
        .filter(User.username == user.username)
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    return crud.create_user(db, user)


@router.post(
    "/api/login",
    response_model=schemas.LoginResponse,
)
def login_user(
    request: Request,
    credentials: schemas.LoginRequest,
    db: Session = Depends(get_db),
):
    # Phase 3: count every login attempt, success or not, per
    # IP + username. The limit is env-tunable for tests; the
    # default (10/minute) is high enough for normal use and
    # low enough to slow credential stuffing on one account
    # without blocking other accounts on the same LAN IP.
    login_limit = int(
        os.environ.get("NIRAPODNET_LOGIN_RATE_LIMIT", "10")
    )
    login_key = f"login:{_client_ip(request)}:{credentials.username}"

    if not limiter.allow(login_key, login_limit, 60):
        _audit_login_event(
            db, credentials.username, "login_rate_limited"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts",
            headers={"Retry-After": "60"},
        )

    user = crud.authenticate_user(
        db,
        credentials.username,
        credentials.password,
    )

    if user is None:
        _audit_login_event(db, credentials.username, "login_failed")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(hours=24)
    )

    session, token = crud.create_session(
        db,
        user_id=user.id,
        expires_at=expires_at,
    )

    return {
        "token": token,
        "user": user,
        "expires_at": session.expires_at,
    }


@router.post("/api/logout")
def logout_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials

    crud.delete_session(db, token)

    return {
        "message": "Logged out successfully"
    }


@router.get(
    "/api/sessions",
    response_model=list[schemas.SessionResponse],
)
def list_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Audit fix (10): list your own live sessions.

    There is no device name stored (the schema never had one),
    so a session is identified only by its expiry and the first
    8 characters of its token hash. That is enough to count
    sessions and to revoke all others with the endpoint below.
    """
    return [
        {
            "token_preview": session.token[:8],
            "expires_at": session.expires_at,
        }
        for session in crud.list_sessions(db, current_user.id)
    ]


@router.delete("/api/sessions")
def revoke_other_sessions(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke every session of yours except the current one."""
    revoked = crud.delete_other_sessions(
        db,
        current_user.id,
        hash_session_token(credentials.credentials),
    )
    return {"revoked_sessions": revoked}


@router.post("/api/ws-ticket")
def create_ws_ticket(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user),
):
    """Issue a one-time WebSocket ticket (audit fix 3).

    The frontend exchanges its Bearer token for this ticket and
    connects with /ws?ticket=... instead of /ws?token=... . The
    ticket is single-use and expires in 60 seconds, so a ticket
    that lands in an access log is already useless. The old
    /ws?token= path still works for Phase 1/2 clients, but the
    frontend no longer uses it.
    """
    return {
        "ticket": issue_ws_ticket(
            current_user.id,
            hash_session_token(credentials.credentials),
        ),
        "expires_in_seconds": 60,
    }


@router.get(
    "/api/me",
    response_model=schemas.UserResponse,
)
def get_me(
    current_user: User = Depends(get_current_user),
):
    return current_user
