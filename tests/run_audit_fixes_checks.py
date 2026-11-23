"""NirapodNet automated checks (audit fixes, 2026-11-03).

Run from the repository root with the project dependencies plus
httpx and websockets installed:

    pip install -r requirements.txt httpx websockets
    python tests/run_audit_fixes_checks.py

The script uses a temporary database and a bootstrap admin, so it
never touches a real nirapodnet.db. It exits with code 0 only when
every check passes. It does not test a live PostgreSQL server
(none is available in this environment); the PostgreSQL fix is
checked by code inspection of app/database.py plus the SQLite
WAL check below, and is stated as such in the report.
"""

import os
import sqlite3
import sys
import tempfile

_tmpdir = tempfile.mkdtemp(prefix="nirapodnet-audit-")
_db_path = os.path.join(_tmpdir, "test.db")
os.environ["NIRAPODNET_DB"] = "sqlite:///" + _db_path
os.environ["NIRAPODNET_ADMIN_USERNAME"] = "bossadmin"
os.environ["NIRAPODNET_ADMIN_PASSWORD"] = "adminpass123"
os.environ["NIRAPODNET_SIGNING_KEY"] = "audit-test-signing-key"
os.environ["NIRAPODNET_REGISTER_RATE_LIMIT"] = "6"

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


def login(c, username, password="password123"):
    return c.post(
        "/api/login",
        json={"username": username, "password": password},
    )


with TestClient(app, raise_server_exceptions=False) as c:
    # ---------- Registration rate limit (audit 2) ----------
    for username in ("alice", "bob", "carol", "dave", "erin", "frank"):
        r = c.post(
            "/api/register",
            json={"username": username, "password": "password123"},
        )
        check(f"AUDIT register {username}", r.status_code == 201)

    r = c.post(
        "/api/register",
        json={"username": "spamuser", "password": "password123"},
    )
    check(
        "AUDIT 7th registration from same IP -> 429",
        r.status_code == 429
        and r.headers.get("Retry-After") == "3600",
        str(r.status_code),
    )

    # ---------- Logins ----------
    r = login(c, "bossadmin", "adminpass123")
    check("AUDIT admin login", r.status_code == 200)
    HA = {"Authorization": f"Bearer {r.json()['token']}"}
    admin_id = r.json()["user"]["id"]

    r = login(c, "alice")
    check("AUDIT alice login", r.status_code == 200)
    alice_token = r.json()["token"]
    HAlice = {"Authorization": f"Bearer {alice_token}"}
    alice_id = r.json()["user"]["id"]

    r = login(c, "bob")
    check("AUDIT bob login", r.status_code == 200)
    bob_token = r.json()["token"]
    HBob = {"Authorization": f"Bearer {bob_token}"}
    bob_id = r.json()["user"]["id"]

    # ---------- sender_id is ignored (audit 10) ----------
    r = c.post(
        "/messages",
        json={
            "client_id": "audit-msg-1",
            "sender_id": 9999,
            "content": "hello from alice",
        },
        headers=HAlice,
    )
    check(
        "AUDIT message sender forced to session user, not body",
        r.status_code == 200
        and r.json()["sender_id"] == alice_id
        and r.json()["sender"] == "alice",
        str(r.json()),
    )

    for i in range(2, 5):
        r = c.post(
            "/messages",
            json={
                "client_id": f"audit-msg-{i}",
                "content": f"msg {i}",
            },
            headers=HAlice,
        )
        check(f"AUDIT message {i} without sender_id", r.status_code == 200)

    # ---------- Pagination + cap (audit 4) ----------
    r = c.get("/messages?limit=2", headers=HAlice)
    check(
        "AUDIT /messages limit=2 returns 2",
        r.status_code == 200 and len(r.json()) == 2,
        str(len(r.json())) if r.status_code == 200 else str(r.status_code),
    )
    r = c.get("/messages?limit=2&offset=2", headers=HAlice)
    check(
        "AUDIT /messages offset=2 returns remaining 2",
        r.status_code == 200 and len(r.json()) == 2,
    )
    r = c.get("/messages?limit=9999", headers=HAlice)
    check(
        "AUDIT /messages limit above cap -> 422",
        r.status_code == 422,
        str(r.status_code),
    )
    r = c.get("/api/admin/users?limit=1", headers=HA)
    check(
        "AUDIT /api/admin/users limit=1 returns 1",
        r.status_code == 200 and len(r.json()) == 1,
    )

    # ---------- SQLite WAL (audit 5) ----------
    con = sqlite3.connect(_db_path)
    try:
        mode = con.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        con.close()
    check("AUDIT SQLite journal_mode is wal", mode == "wal", mode)

    # ---------- Promote alice to operator, atomic role + audit ----------
    users = {u["username"]: u["id"] for u in c.get(
        "/api/admin/users", headers=HA).json()}
    r = c.patch(
        f"/api/admin/users/{users['alice']}/role",
        json={"role": "operator"},
        headers=HA,
    )
    check("AUDIT promote alice to operator", r.status_code == 200)
    # Old session must be dead after the role change (Phase 3 rule).
    r = c.get("/api/me", headers=HAlice)
    check("AUDIT old alice session dead after role change",
          r.status_code in (401, 403))
    r = login(c, "alice")
    check("AUDIT alice re-login after role change", r.status_code == 200)
    HAlice = {"Authorization": f"Bearer {r.json()['token']}"}
    alice_token = r.json()["token"]

    # ---------- SOS + atomic audit (audit 10) ----------
    r = c.post(
        "/api/sos",
        json={"emergency_type": "flood", "description": "audit sos"},
        headers=HAlice,
    )
    check("AUDIT SOS create as operator", r.status_code == 201)
    incident_id = r.json()["incident_id"] if r.status_code == 201 else ""
    r = c.get("/api/sos?limit=1", headers=HAlice)
    check(
        "AUDIT /api/sos limit=1 returns 1",
        r.status_code == 200 and len(r.json()) == 1,
    )
    r = c.get("/api/audit-logs?limit=500", headers=HA)
    audit = r.json() if r.status_code == 200 else []
    check(
        "AUDIT audit log contains sos_created for this incident",
        any(
            e["action"] == "sos_created" and e["entity_id"] == incident_id
            for e in audit
        ),
    )
    check(
        "AUDIT audit log contains user_role_updated for alice",
        any(
            e["action"] == "user_role_updated"
            and e["entity_id"] == str(users["alice"])
            for e in audit
        ),
    )

    # ---------- Sessions list / revoke others (audit 10) ----------
    r = login(c, "bob")
    bob_token_2 = r.json()["token"]
    HBob2 = {"Authorization": f"Bearer {bob_token_2}"}
    r = c.get("/api/sessions", headers=HBob2)
    check(
        "AUDIT bob has 2 sessions listed",
        r.status_code == 200 and len(r.json()) == 2,
        str(r.json()) if r.status_code == 200 else str(r.status_code),
    )
    r = c.delete("/api/sessions", headers=HBob2)
    check(
        "AUDIT revoke other sessions removes 1",
        r.status_code == 200 and r.json().get("revoked_sessions") == 1,
        str(r.json()),
    )
    r = c.get("/api/me", headers=HBob)
    check("AUDIT old bob session dead after revoke-others",
          r.status_code in (401, 403))

    # ---------- Admin backup (audit 5) ----------
    r = c.get("/api/admin/backup", headers=HA)
    check(
        "AUDIT admin backup is a SQLite file",
        r.status_code == 200
        and r.content[:15] == b"SQLite format 3",
        str(r.status_code),
    )
    r = c.get("/api/admin/backup", headers=HAlice)
    # Alice is operator, not admin: backup is admin-only.
    check("AUDIT backup as operator -> 403", r.status_code == 403)

    # ---------- WebSocket ticket (audit 3) ----------
    r = c.post("/api/ws-ticket", headers=HAlice)
    check("AUDIT ws-ticket issued", r.status_code == 200)
    ticket = r.json()["ticket"] if r.status_code == 200 else ""
    check(
        "AUDIT ws-ticket is not the session token",
        ticket and ticket != alice_token,
    )
    try:
        with c.websocket_connect(f"/ws?ticket={ticket}") as ws:
            ws.send_json({
                "client_id": "audit-ws-1",
                "content": "ticket hello",
                "seq": 1,
                "ts": __import__("time").time(),
            })
            ack = ws.receive_json()
        check(
            "AUDIT WS via ticket acks",
            ack.get("type") == "ack",
            str(ack),
        )
    except Exception as exc:  # noqa: BLE001
        check("AUDIT WS via ticket acks", False, repr(exc))

    # Ticket reuse must fail: the ticket was consumed on first use.
    try:
        with c.websocket_connect(f"/ws?ticket={ticket}") as ws:
            ws.receive_json()
        check("AUDIT reused WS ticket rejected", False, "connected")
    except Exception:
        check("AUDIT reused WS ticket rejected", True)

    # ---------- WebSocket broken JSON does not kill the socket (6) ----------
    r = c.post("/api/ws-ticket", headers=HAlice)
    ticket2 = r.json()["ticket"]
    try:
        with c.websocket_connect(f"/ws?ticket={ticket2}") as ws:
            ws.send_text("this is not json{")
            err = ws.receive_json()
            ws.send_json({
                "client_id": "audit-ws-2",
                "content": "after bad frame",
                "seq": 1,
                "ts": __import__("time").time(),
            })
            ack = ws.receive_json()
        check(
            "AUDIT broken JSON -> error frame, then ack",
            err.get("type") == "error" and ack.get("type") == "ack",
            f"{err} / {ack}",
        )
    except Exception as exc:  # noqa: BLE001
        check("AUDIT broken JSON -> error frame, then ack", False, repr(exc))

    # ---------- WebSocket dies when its session is revoked (10) ----------
    r = login(c, "frank")
    frank_token = r.json()["token"]
    HFrank = {"Authorization": f"Bearer {frank_token}"}
    try:
        with c.websocket_connect(f"/ws?token={frank_token}") as ws:
            # Logout revokes the session behind this connection.
            c.post("/api/logout", headers=HFrank)
            ws.send_json({
                "client_id": "audit-ws-3",
                "content": "after logout",
            })
            ws.receive_json()
        check("AUDIT WS closed after logout", False, "still open")
    except Exception:
        check("AUDIT WS closed after logout", True)

    # ---------- File checks: README marks, real SECURITY.md (8, 9) ----------
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    readme = open(os.path.join(root, "README.md"), encoding="utf-8").read()
    check(
        "AUDIT README marks implemented vs planned",
        "Implemented" in readme and "Planned" in readme
        and "Run on LAN over HTTPS" in readme
        and "plain HTTP" in readme,
    )
    security_md = open(
        os.path.join(root, "SECURITY.md"), encoding="utf-8").read()
    check(
        "AUDIT root SECURITY.md is real, not the template",
        "5.1.x" not in security_md
        and "Reporting a Vulnerability" in security_md
        and "main" in security_md,
    )
    db_py = open(os.path.join(
        root, "app", "database.py"), encoding="utf-8").read()
    check(
        "AUDIT database.py only passes check_same_thread for SQLite",
        'if _is_sqlite:' in db_py
        and db_py.count('check_same_thread') == 2,
        # One in the comment, one in the SQLite branch.
    )

failed = [name for name, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} audit checks passed")
if failed:
    print("FAILED:", failed)
    sys.exit(1)
