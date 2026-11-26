"""NirapodNet automated checks (Phase 3 completion, 2026-11-25).

Run from the repository root with the project dependencies plus
httpx and websockets installed:

    pip install -r requirements.txt httpx websockets
    python tests/run_phase3_completion_checks.py

Covers the Phase 3 completion work under Path A (TLS limit
accepted, user decision 2026-11-25): failed-login and
rate-limit audit logging, CSP without 'unsafe-inline', and
the documentation of the accepted E2E limit and the new
audit-fix endpoints. Uses a temporary database and a
bootstrap admin, so it never touches a real nirapodnet.db.
It exits with code 0 only when every check passes.
"""

import os
import sys
import tempfile

_tmpdir = tempfile.mkdtemp(prefix="nirapodnet-completion-")
_db_path = os.path.join(_tmpdir, "test.db")
os.environ["NIRAPODNET_DB"] = "sqlite:///" + _db_path
os.environ["NIRAPODNET_ADMIN_USERNAME"] = "bossadmin"
os.environ["NIRAPODNET_ADMIN_PASSWORD"] = "adminpass123"
os.environ["NIRAPODNET_SIGNING_KEY"] = "completion-test-signing-key"
os.environ["NIRAPODNET_LOGIN_RATE_LIMIT"] = "3"
os.environ["NIRAPODNET_WRITE_RATE_LIMIT"] = "3"

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)

try:
    from fastapi.testclient import TestClient
except ImportError:
    print("httpx is required: pip install httpx websockets")
    raise

from app.main import app  # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"{'PASS' if cond else 'FAIL'}: {name} {detail}")


def audit_actions(c, headers):
    r = c.get("/api/audit-logs?limit=500", headers=headers)
    if r.status_code != 200:
        return []
    return r.json()


with TestClient(app, raise_server_exceptions=False) as c:
    # ---------- Setup: two users + admin ----------
    for username in ("alice", "carol"):
        r = c.post(
            "/api/register",
            json={"username": username, "password": "password123"},
        )
        check(f"COMPLETION register {username}", r.status_code == 201)

    r = c.post(
        "/api/login",
        json={"username": "bossadmin", "password": "adminpass123"},
    )
    check("COMPLETION admin login", r.status_code == 200)
    HA = {"Authorization": f"Bearer {r.json()['token']}"}

    # ---------- Failed login is audit-logged (known account) ----------
    r = c.post(
        "/api/login",
        json={"username": "alice", "password": "wrongpassword"},
    )
    check("COMPLETION wrong password -> 401", r.status_code == 401)
    audit = audit_actions(c, HA)
    check(
        "COMPLETION audit log has login_failed for alice",
        any(
            e.get("action") == "login_failed"
            and "alice" in (e.get("detail") or "")
            for e in audit
        ),
    )

    # ---------- Unknown username: 401, but no attributable audit row ----------
    r = c.post(
        "/api/login",
        json={"username": "ghostuser", "password": "wrongpassword"},
    )
    check("COMPLETION unknown user -> 401", r.status_code == 401)
    audit = audit_actions(c, HA)
    check(
        "COMPLETION no login_failed row for unknown user",
        not any(
            e.get("action") == "login_failed"
            and "ghostuser" in (e.get("detail") or "")
            for e in audit
        ),
    )

    # ---------- Login rate limit is audit-logged ----------
    # Limit is 3/minute for carol; attempts 1-3 are 401s,
    # the 4th must be 429 with a login_rate_limited entry.
    statuses = []
    for _ in range(4):
        r = c.post(
            "/api/login",
            json={"username": "carol", "password": "wrongpassword"},
        )
        statuses.append(r.status_code)
    check(
        "COMPLETION carol login attempts 401,401,401,429",
        statuses == [401, 401, 401, 429],
        str(statuses),
    )
    audit = audit_actions(c, HA)
    check(
        "COMPLETION audit log has login_rate_limited for carol",
        any(
            e.get("action") == "login_rate_limited"
            and "carol" in (e.get("detail") or "")
            for e in audit
        ),
    )

    # ---------- Write rate limit is audit-logged ----------
    r = c.post(
        "/api/login",
        json={"username": "alice", "password": "password123"},
    )
    check("COMPLETION alice login", r.status_code == 200)
    H = {"Authorization": f"Bearer {r.json()['token']}"}
    statuses = []
    for i in range(4):
        r = c.post(
            "/messages",
            json={"client_id": f"completion-{i}", "content": "hi"},
            headers=H,
        )
        statuses.append(r.status_code)
    check(
        "COMPLETION alice writes 200/201 x3 then 429",
        statuses[:3] and all(s in (200, 201) for s in statuses[:3])
        and statuses[3] == 429,
        str(statuses),
    )
    audit = audit_actions(c, HA)
    check(
        "COMPLETION audit log has rate_limit_hit for alice",
        any(e.get("action") == "rate_limit_hit" for e in audit),
    )

    # ---------- CSP has no 'unsafe-inline', template has no style= ----------
    r = c.get("/")
    csp = r.headers.get("Content-Security-Policy", "")
    check(
        "COMPLETION CSP header has no unsafe-inline",
        "unsafe-inline" not in csp and "style-src 'self'" in csp,
        csp,
    )
    check(
        "COMPLETION served page has no style= attribute",
        'style="' not in r.text and "style='" not in r.text,
    )
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    css = open(os.path.join(root, "app", "static", "style.css")).read()
    check("COMPLETION style.css has .hidden class", ".hidden" in css)

    # ---------- Docs: E2E accepted limit + new endpoints ----------
    security_md = open(
        os.path.join(root, "docs", "SECURITY.md"), encoding="utf-8"
    ).read()
    check(
        "COMPLETION docs record Path A E2E decision",
        "Path A" in security_md
        and "accepted" in security_md.lower()
        and "End-to-end encryption is not implemented" in security_md,
    )
    api_md = open(
        os.path.join(root, "docs", "API.md"), encoding="utf-8"
    ).read()
    check(
        "COMPLETION API docs cover sessions, ws-ticket, backup",
        "ws-ticket" in api_md
        and "/api/sessions" in api_md
        and "/api/admin/backup" in api_md,
    )
    readme = open(
        os.path.join(root, "README.md"), encoding="utf-8"
    ).read()
    check(
        "COMPLETION README is honest about no E2E",
        "no end-to-end encryption yet" in readme,
    )

failed = [name for name, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} completion checks passed")
if failed:
    print("FAILED:", failed)
    sys.exit(1)
