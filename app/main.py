"""NirapodNet — FastAPI application entry point.

Thin since the Phase 3 completion work: routes live in
app/routers/ and shared helpers in app/helpers.py. Startup
order is the same as before the split: create tables, run
the broadcast-signature migration, bootstrap the first
admin, then mount static files and include the routers.
"""

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from .database import engine
from .helpers import _bootstrap_admin, _migrate_broadcast_signature
from .models import Base
from .routers import (
    admin,
    auth,
    broadcasts,
    checkins,
    core,
    messages,
    sos,
    users,
    websocket,
)

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="NirapodNet")


# Phase 3: security headers on every response. CSP keeps
# script-src to 'self' (the template loads only /static/app.js).
# style-src is 'self' only since the Phase 3 completion work:
# show/hide uses the .hidden class in style.css, not inline
# style attributes, so 'unsafe-inline' is gone. JavaScript
# setting element.style.display still works: CSP style-src
# does not block CSSOM style changes, only inline attributes
# and <style> elements.
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
        "style-src 'self'; "
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


# Create SQLite tables on startup
Base.metadata.create_all(bind=engine)

_migrate_broadcast_signature()
_bootstrap_admin()

# Static files
app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static"
)

app.include_router(core.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(messages.router)
app.include_router(sos.router)
app.include_router(broadcasts.router)
app.include_router(checkins.router)
app.include_router(admin.router)
app.include_router(websocket.router)
