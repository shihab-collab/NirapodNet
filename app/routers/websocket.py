"""WebSocket endpoint (split from app/main.py in the Phase 3 completion work).

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

@router.websocket("/ws")
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

            from ..security import contains_control_characters

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
