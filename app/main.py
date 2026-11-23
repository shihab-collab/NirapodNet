from pathlib import Path
from fastapi import FastAPI, Request, Depends, Query, Header
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
)
from starlette.background import BackgroundTask
from fastapi.security import (HTTPAuthorizationCredentials,HTTPBearer,)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

import asyncio
import json
import os
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Query, status
from .dependencies import require_role
from .auth import get_current_user
from .rate_limit import limiter
from .security import (
    broadcast_canonical_string,
    hash_session_token,
    sign_broadcast,
    verify_broadcast_signature,
)

from .database import DATABASE_URL, engine, get_db
from .models import Base
from . import schemas, crud

from fastapi import WebSocket, WebSocketDisconnect
from .websocket import (
    issue_ws_ticket,
    manager,
    redeem_ws_ticket,
)
from .database import SessionLocal
from .models import (Base,User,Message,UserSession,SOSEvent,Broadcast,CheckIn,AuditLog,)
from .dependencies import ALL_ROLES, require_role, ADMIN_ROLE
BASE_DIR = Path(__file__).resolve().parent

security = HTTPBearer()

app = FastAPI(title="NirapodNet")

# Phase 3: security headers on every response. CSP keeps
# script-src to 'self' (the template loads only /static/app.js);
# style-src keeps 'unsafe-inline' because the template itself
# uses inline style attributes for show/hide -- removing those
# attributes is a follow-up, not a silent break of the UI.
# HSTS is only sent over HTTPS: sending it over plain LAN HTTP
# would tell browsers to force HTTPS on later visits and break
# the plain-HTTP LAN deployment.
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(self)"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


@app.on_event("startup")
async def _warn_plain_http():
    # Audit fix (1): plain HTTP is the LAN default, so the warning
    # must be visible at startup, not only in README. The server
    # cannot tell from inside the app whether uvicorn was given
    # --ssl-certfile, so NIRAPODNET_HTTPS=1 is the explicit opt-out:
    # set it when (and only when) the server really runs behind TLS.
    if os.environ.get("NIRAPODNET_HTTPS") != "1":
        print(
            "WARNING: NirapodNet is running over plain HTTP. "
            "Passwords and session tokens travel unencrypted on "
            "the LAN. Use only a trusted LAN, or run with TLS: "
            "see README 'Run on LAN over HTTPS'."
        )


def _pagination(limit: int, offset: int):
    # Audit fix (4): one place for the list bounds, so no list
    # endpoint can silently return every row again.
    return max(1, min(limit, 500)), max(0, offset)


def _check_register_rate_limit(request: Request):
    # Audit fix (2): open registration was unlimited, so anyone on
    # the LAN could spam accounts. Default 30/hour per IP, env
    # tunable (NIRAPODNET_REGISTER_RATE_LIMIT); the same key is
    # used by POST /users and POST /api/register, so spamming
    # through the legacy path does not bypass it.
    limit = int(os.environ.get("NIRAPODNET_REGISTER_RATE_LIMIT", "30"))
    if not limiter.allow(f"register:{_client_ip(request)}", limit, 3600):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registrations from this address",
            headers={"Retry-After": "3600"},
        )


def _session_still_valid(db: Session, token_hash: str) -> bool:
    # Audit fix (10): a WebSocket must not outlive its session.
    # Checked on every message, not only at connect time, so
    # logout, expiry and role-change revocation all cut a live
    # connection at the next message. expire_all() first: the
    # session behind a long-lived socket was loaded in this
    # DB session, and logout deletes the row through another
    # DB session, so without expiring the identity map the
    # check would keep seeing the stale, deleted row.
    db.expire_all()
    session = (
        db.query(UserSession)
        .filter(UserSession.token == token_hash)
        .first()
    )
    if session is None:
        return False
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return session.expires_at > now


def _client_ip(request: Request) -> str:
    # TestClient and direct LAN clients have no trusted proxy
    # in front of them, so X-Forwarded-For is never trusted:
    # it is client-controlled and would let an attacker rotate
    # rate-limit keys at will.
    if request.client is not None:
        return request.client.host

    return "unknown"


def _check_write_rate_limit(user: User):
    # 120 writes per minute per user: far above normal emergency
    # use, far below a flooding client. Phase 2 regression
    # traffic stays well under this.
    if not limiter.allow(f"write:{user.id}", 120, 60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": "60"},
        )


def _idempotency_replay(db: Session, user: User, endpoint: str, key):
    """Return a stored replay response, or None to proceed."""
    if not key:
        return None

    record = crud.get_idempotency_record(db, user.id, endpoint, key)

    if record is None:
        return None

    return JSONResponse(
        status_code=record.response_status,
        content=json.loads(record.response_body),
    )


def _save_idempotency(db: Session, user: User, endpoint: str, key,
                      status_code: int, body: dict):
    if not key:
        return

    existing = crud.get_idempotency_record(db, user.id, endpoint, key)

    if existing is not None:
        return

    crud.save_idempotency_record(
        db,
        user_id=user.id,
        endpoint=endpoint,
        idempotency_key=key,
        response_status=status_code,
        response_body=json.dumps(body),
    )


def _sign_broadcast(db: Session, created, commit: bool = True):
    """Sign a broadcast and persist its signature."""
    canonical = broadcast_canonical_string(
        created.id,
        created.issued_by,
        created.type,
        created.message,
        created.priority,
        created.created_at.isoformat(),
    )
    created.signature = sign_broadcast(canonical)
    if commit:
        db.commit()
        db.refresh(created)
    else:
        db.flush()
    return created

# Create SQLite tables on startup
Base.metadata.create_all(bind=engine)


def _migrate_broadcast_signature():
    """Phase 3 upgrade: add Broadcast.signature to old databases.

    create_all only creates missing tables, it never adds a
    column to an existing table. Without this migration, a
    database created before Phase 3 would fail every
    broadcast query with "no such column: signature".
    New databases already have the column, so this is a
    no-op for them.
    """
    with engine.connect() as conn:
        columns = [
            row[1]
            for row in conn.exec_driver_sql(
                "PRAGMA table_info(broadcasts)"
            )
        ]

        if columns and "signature" not in columns:
            conn.exec_driver_sql(
                "ALTER TABLE broadcasts "
                "ADD COLUMN signature VARCHAR(128)"
            )
            conn.commit()


_migrate_broadcast_signature()


def _bootstrap_admin():
    """Create the first admin account from environment variables.

    Set NIRAPODNET_ADMIN_USERNAME and NIRAPODNET_ADMIN_PASSWORD before
    starting the server to bootstrap the first admin. Without both
    variables this is a no-op, so existing deployments are unaffected.
    The password is never changed for an account that already exists;
    an existing account with the bootstrap username is only promoted
    to the admin role.
    """
    import os

    from .security import hash_password

    username = os.environ.get("NIRAPODNET_ADMIN_USERNAME", "").strip()
    password = os.environ.get("NIRAPODNET_ADMIN_PASSWORD", "")

    if not username or len(password) < 8:
        return

    db = SessionLocal()

    try:
        existing = (
            db.query(User)
            .filter(User.username == username)
            .first()
        )

        if existing is None:
            admin = User(
                username=username,
                password_hash=hash_password(password),
                role=ADMIN_ROLE,
            )
            db.add(admin)
            db.flush()
            db.add(
                AuditLog(
                    actor_id=admin.id,
                    action="admin_bootstrapped",
                    entity_type="user",
                    entity_id=str(admin.id),
                    detail="admin account created via environment bootstrap",
                )
            )
            db.commit()
        elif existing.role != ADMIN_ROLE:
            existing.role = ADMIN_ROLE
            db.add(
                AuditLog(
                    actor_id=existing.id,
                    action="admin_bootstrapped",
                    entity_type="user",
                    entity_id=str(existing.id),
                    detail="account promoted to admin via environment bootstrap",
                )
            )
            db.commit()
    finally:
        db.close()


_bootstrap_admin()

# Static files
app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static"
)

templates = Jinja2Templates(directory=BASE_DIR / "templates")

# -----------------------
# HTML Pages
# -----------------------

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={}
    )


# -----------------------
# System API
# -----------------------

@app.get("/api")
def api_status():
    return {
        "system": "NirapodNet",
        "status": "online"
    }


# -----------------------
# User API
# -----------------------

@app.post("/users", response_model=schemas.UserResponse)
def create_user(
    request: Request,
    user: schemas.UserCreate,
    db: Session = Depends(get_db)
):
    # Legacy Phase 1 path, kept working (Phase 1 regression test)
    # but rate-limited exactly like /api/register; see docs/API.md.
    _check_register_rate_limit(request)
    return crud.create_user(db, user)


@app.post(
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


@app.post(
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


@app.post("/api/logout")
def logout_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials

    crud.delete_session(db, token)

    return {
        "message": "Logged out successfully"
    }


@app.get(
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


@app.delete("/api/sessions")
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


@app.post("/api/ws-ticket")
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


@app.get(
    "/api/me",
    response_model=schemas.UserResponse,
)
def get_me(
    current_user: User = Depends(get_current_user),
):
    return current_user


@app.get(
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


@app.get(
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


@app.patch(
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


@app.get("/api/rbac/user")
def rbac_user_test(
    current_user: User = Depends(
        require_role(
            "user",
            "rescue",
            "responder",
            "operator",
            "admin",
        )
    ),
):
    return {
        "message": "User-level access granted",
        "user": current_user.username,
        "role": current_user.role,
    }


@app.get("/api/rbac/rescue")
def rbac_rescue_test(
    current_user: User = Depends(
        require_role(
            "rescue",
            "responder",
            "operator",
            "admin",
        )
    ),
):
    return {
        "message": "Rescue-level access granted",
        "user": current_user.username,
        "role": current_user.role,
    }


@app.get("/api/rbac/operator")
def rbac_operator_test(
    current_user: User = Depends(
        require_role(
            "operator",
            "admin",
        )
    ),
):
    return {
        "message": "Operator-level access granted",
        "user": current_user.username,
        "role": current_user.role,
    }


@app.get("/api/rbac/admin")
def rbac_admin_test(
    current_user: User = Depends(
        require_role("admin")
    ),
):
    return {
        "message": "Admin-level access granted",
        "user": current_user.username,
        "role": current_user.role,
    }


# -----------------------
# Message API
# -----------------------

@app.post("/messages", response_model=schemas.MessageResponse)
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
    _check_write_rate_limit(current_user)

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


@app.get("/messages", response_model=list[schemas.MessageResponse])
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


@app.post(
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
    _check_write_rate_limit(current_user)

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


@app.get(
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


@app.get(
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


@app.patch(
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


async def broadcast_sos(
    db: Session,
    message: dict,
):
    # Audit fix (4): recipients are fetched in one query, not one
    # per live connection.
    disconnected = []
    user_ids = list(manager.active_connections.values())
    recipients = {
        user.id: user.role
        for user in db.query(User).filter(User.id.in_(user_ids)).all()
    } if user_ids else {}

    for connection, user_id in manager.active_connections.items():
        if recipients.get(user_id) not in {
            "rescue",
            "responder",
            "operator",
            "admin",
        }:
            continue

        try:
            await connection.send_json(message)
        except Exception:
            disconnected.append(connection)

    for connection in disconnected:
        manager.disconnect(connection)


async def broadcast_alert(message: dict):
    disconnected = []

    for connection in list(manager.active_connections.keys()):
        try:
            await connection.send_json(message)
        except Exception:
            disconnected.append(connection)

    for connection in disconnected:
        manager.disconnect(connection)


@app.post(
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
    _check_write_rate_limit(current_user)

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


@app.get(
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


@app.get("/api/broadcasts/{broadcast_id}/verify")
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


# -----------------------
# Check-In API
# -----------------------

@app.post(
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
    _check_write_rate_limit(current_user)

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


@app.get(
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


@app.get(
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


@app.get(
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


# -----------------------
# Admin Backup API
# -----------------------

@app.get("/api/admin/backup")
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

@app.get(
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


@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str | None = Query(default=None),
    ticket: str | None = Query(default=None),
):
    """Live chat socket.

    Audit fix (3): prefer a one-time ticket
    (POST /api/ws-ticket, then /ws?ticket=...) over the session
    token in the URL. The token query still works for Phase 1/2
    clients, but the frontend no longer sends it.
    Audit fix (6): disconnect happens in `finally`, so a broken
    JSON frame or any other error cannot leave a dead connection
    in active_connections. Audit fix (10): the session behind
    the connection is re-checked on every message.
    """
    db = SessionLocal()
    session_token_hash: str | None = None
    user = None

    try:
        if ticket is not None:
            payload = redeem_ws_ticket(ticket)
            if payload is not None:
                session_token_hash = payload["session_token_hash"]
                candidate = (
                    db.query(User)
                    .filter(User.id == payload["user_id"])
                    .first()
                )
                if (
                    candidate is not None
                    and _session_still_valid(db, session_token_hash)
                ):
                    user = candidate
        elif token is not None:
            session_token_hash = hash_session_token(token)
            user = crud.get_session_user(db, token)

        if user is None:
            await websocket.close(code=1008)
            return

        await manager.connect(websocket, user.id)

        last_seq: int | None = None

        while True:
            # Session validity is checked before every message,
            # so logout / expiry / role-change revocation cuts
            # this connection at the next message, not never.
            if not _session_still_valid(db, session_token_hash):
                await websocket.close(code=1008)
                break

            try:
                # Audit fix (10): a live socket must also die
                # when its session expires while it is idle, not
                # only at the next message. Waiting at most 30
                # seconds per receive lets the loop come back to
                # the session check above even with no traffic.
                data = await asyncio.wait_for(
                    websocket.receive_json(), timeout=30
                )
            except WebSocketDisconnect:
                break
            except asyncio.TimeoutError:
                continue
            except Exception:
                # Audit fix (6): a broken JSON frame is an error
                # frame, not a leaked connection and not a crash
                # of the whole handler.
                try:
                    await websocket.send_json({
                        "type": "error",
                        "error": "Invalid message",
                    })
                except Exception:
                    break
                continue

            # Re-check after the receive, not only before it:
            # logout can land while this loop is blocked waiting
            # for a frame, and that frame must not be processed
            # and acked after the session is already gone.
            if not _session_still_valid(db, session_token_hash):
                await websocket.close(code=1008)
                break

            if not isinstance(data, dict):
                await websocket.send_json({
                    "type": "error",
                    "error": "Invalid message",
                })
                continue

            # Phase 3: 30 messages per 10 seconds per connection.
            if not limiter.allow(f"ws:{id(websocket)}", 30, 10):
                await websocket.send_json({
                    "type": "error",
                    "error": "Rate limit exceeded",
                })
                continue

            client_id = data.get("client_id")
            content = data.get("content")

            if (
                not isinstance(client_id, str)
                or not isinstance(content, str)
                or not 1 <= len(client_id) <= 100
                or not 1 <= len(content) <= 2000
            ):
                await websocket.send_json({
                    "type": "error",
                    "error": "Invalid message",
                })
                continue

            from .security import contains_control_characters

            if contains_control_characters(content):
                await websocket.send_json({
                    "type": "error",
                    "error": "Invalid message",
                })
                continue

            if "seq" in data:
                seq = data.get("seq")
                if (
                    not isinstance(seq, int)
                    or isinstance(seq, bool)
                    or (last_seq is not None and seq <= last_seq)
                ):
                    await websocket.send_json({
                        "type": "error",
                        "error": "Stale or replayed sequence",
                    })
                    continue
                last_seq = seq

            if "ts" in data:
                ts = data.get("ts")
                if (
                    not isinstance(ts, (int, float))
                    or isinstance(ts, bool)
                    or abs(time.time() - float(ts)) > 300
                ):
                    await websocket.send_json({
                        "type": "error",
                        "error": "Stale timestamp",
                    })
                    continue

            existing = (
                db.query(Message)
                .filter(
                    Message.sender_id == user.id,
                    Message.client_id == client_id,
                )
                .first()
            )

            if existing:
                await websocket.send_json({
                    "type": "ack",
                    "client_id": client_id,
                    "message_id": existing.id,
                    "sender_id": existing.sender_id,
                    "sender": user.username,
                    "content": existing.content,
                    "timestamp": existing.timestamp.isoformat(),
                })
                continue

            message = Message(
                client_id=client_id,
                sender_id=user.id,
                content=content,
            )
            db.add(message)
            db.commit()
            db.refresh(message)

            await websocket.send_json({
                "type": "ack",
                "client_id": client_id,
                "message_id": message.id,
                "sender_id": user.id,
                "sender": user.username,
                "content": content,
                "timestamp": message.timestamp.isoformat(),
            })

            await manager.broadcast(
                {
                    "type": "message",
                    "client_id": client_id,
                    "id": message.id,
                    "sender": user.username,
                    "sender_id": user.id,
                    "content": content,
                    "timestamp": message.timestamp.isoformat(),
                },
                exclude=websocket,
            )
    except WebSocketDisconnect:
        pass
    finally:
        # Audit fix (6): every exit path disconnects. The old code
        # only disconnected on WebSocketDisconnect, so any other
        # error left the connection in active_connections until a
        # broadcast to it failed.
        manager.disconnect(websocket)
        db.close()
