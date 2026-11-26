"""HTML pages and role probes (split from app/main.py in the Phase 3 completion work).

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

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")

@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={}
    )


# -----------------------
# System API
# -----------------------

@router.get("/api")
def api_status():
    return {
        "system": "NirapodNet",
        "status": "online"
    }


# -----------------------
# User API
# -----------------------

@router.get("/api/rbac/user")
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


@router.get("/api/rbac/rescue")
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


@router.get("/api/rbac/operator")
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


@router.get("/api/rbac/admin")
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
