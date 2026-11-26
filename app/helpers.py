"""Shared helpers for the routers (split from app/main.py).

Rate-limit checks, session validation, idempotency, broadcast
signing, the startup broadcast-signature migration and the
first-admin bootstrap. The migration and bootstrap are only
defined here; main.py calls them after create_all, in the
same order as before the split.
"""

import json
import os
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from .database import SessionLocal, engine
from .dependencies import ADMIN_ROLE
from .models import AuditLog, User, UserSession
from .rate_limit import limiter
from .security import broadcast_canonical_string, sign_broadcast
from .websocket import manager
from . import crud

security = HTTPBearer()

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


def _audit_login_event(db: Session, username: str, action: str):
    # Phase 3 completion: failed logins and login rate-limit
    # hits are audit-logged, so a credential-stuffing attempt
    # leaves a trace an admin can see. The audit entry needs
    # an existing account as its actor (actor_id is a foreign
    # key), so attempts for unknown usernames cannot be
    # attributed and are not logged here -- they are still
    # rate-limited. Never log a password or token.
    user = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )
    if user is not None:
        crud.log_audit(
            db,
            actor_id=user.id,
            action=action,
            entity_type="user",
            entity_id=str(user.id),
            detail=f"{action} for {username}",
        )


def _check_write_rate_limit(db: Session, user: User):
    # 120 writes per minute per user: far above normal emergency
    # use, far below a flooding client. Phase 2 regression
    # traffic stays well under this. Env-tunable for tests
    # (NIRAPODNET_WRITE_RATE_LIMIT). A hit is audit-logged so
    # a flooding client leaves a trace.
    limit = int(os.environ.get("NIRAPODNET_WRITE_RATE_LIMIT", "120"))
    if not limiter.allow(f"write:{user.id}", limit, 60):
        crud.log_audit(
            db,
            actor_id=user.id,
            action="rate_limit_hit",
            entity_type="user",
            entity_id=str(user.id),
            detail=f"write rate limit ({limit}/minute)",
        )
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
