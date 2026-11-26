# NirapodNet — Security Architecture and Threat Model (Phase 3, in progress)

This document is the Phase 3 security record. It states what is
implemented, what is deliberately not claimed, and what remains
open. It is written for a single-server LAN deployment: one
uvicorn process, SQLite on the server, no reverse proxy, no
public internet in the normal case.

## What Phase 3 adds

- **Security headers on every response:** `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy:
  no-referrer`, a restrictive `Permissions-Policy`, and a
  Content-Security-Policy (`script-src 'self'`, `connect-src
  'self' ws: wss:`, `frame-ancestors 'none'`). `style-src`
  is `'self'` only since the Phase 3 completion work:
  show/hide uses the `.hidden` class in `style.css`
  instead of inline `style` attributes, so the CSP no
  longer allows `'unsafe-inline'`.
  `Strict-Transport-Security` is sent only over HTTPS, so a
  plain-HTTP LAN deployment is not told to force HTTPS later.
- **Session tokens are stored hashed:** the database holds
  SHA-256 of the token, never the token itself. The plain
  token is returned once at login. A leaked database does not
  by itself give a usable Bearer token. Sessions expire after
  24 hours, logout deletes the session, at most 5 live
  sessions per user are kept, and changing a user's role
  invalidates all of that user's sessions.
- **Rate limiting (in-memory, per process):** login attempts
  are limited per IP + username (default 10/minute,
  `NIRAPODNET_LOGIN_RATE_LIMIT` to tune), authenticated
  writes are limited to 120/minute per user, and a WebSocket
  connection is limited to 30 messages per 10 seconds.
  Exceeding a limit returns 429 with `Retry-After: 60`.
  The limiter is per-process: it fits one uvicorn process
  and is not shared across processes. `X-Forwarded-For` is
  never trusted for rate-limit keys, because it is
  client-controlled.
- **Replay protection:**
  - REST: `POST /messages`, `POST /api/sos`,
    `POST /api/broadcasts` and `POST /api/checkins` accept
    an optional `Idempotency-Key` header. The first response
    for (user, endpoint, key) is stored and returned again
    on retry, instead of creating a second entity. Without
    the header, behaviour is unchanged.
  - WebSocket: messages already had per-sender `client_id`
    deduplication (Phase 1/2). Phase 3 adds optional `seq`
    (strictly increasing per connection) and `ts` (unix
    seconds, within 5 minutes of server time). When a
    client sends them, a replayed sequence or stale
    timestamp is rejected with an error frame. They are
    optional so older clients keep working; the shipped
    frontend sends them.
  - Messages, SOS and broadcasts already had pydantic
    length/range validation (Phase 2); Phase 3 adds
    control-character rejection and whitespace stripping
    for usernames, message content, broadcast fields and
    SOS descriptions.
- **Broadcast signing:** every new broadcast is signed
  with HMAC-SHA256 over
  `id|issued_by|type|message|priority|created_at`, and the
  signature is returned in the API response and in the live
  WebSocket payload. `GET /api/broadcasts/{id}/verify`
  (authenticated) recomputes the signature and reports
  `valid` and `signature_present`. Broadcasts created
  before Phase 3 have no signature and report
  `valid: false`.
- **Rendering:** the frontend already renders user content
  with `textContent`, not `innerHTML`, so stored message
  text is not executed as HTML. Server-side control-
  character rejection is defence in depth.
- **Transport:** the frontend already chooses `wss:` when
  the page is served over HTTPS and `ws:` otherwise, so
  serving the app over TLS (below) automatically upgrades
  the WebSocket. The WebSocket token is still sent as a
  query parameter for compatibility with existing clients;
  that token can appear in server logs, which is a known
  residual risk (see below).

## Signing key

Set `NIRAPODNET_SIGNING_KEY` in the environment before
starting the server. Without it, the server generates an
ephemeral key per process: signatures made before a
restart will not verify after it. For a real deployment,
set the environment variable and keep it with the same
care as a password. It is never returned by any API.

## Running over TLS (WSS)

NirapodNet itself does not bundle certificates, and no
certificate is checked into this repository. To serve
over TLS, run uvicorn with your own certificate, for
example:

```
uvicorn app.main:app --host 0.0.0.0 --port 8000 \
  --ssl-certfile /path/to/cert.pem \
  --ssl-keyfile /path/to/key.pem
```

When the page is HTTPS, browsers will use `wss:` for the
WebSocket automatically. Plain-HTTP LAN use remains
supported, but traffic on that LAN is then visible to
anyone on the same network: that is a deployment choice,
not something the code can fix without TLS.

**LAN WSS test — passed 2026-11-25 (user's PC):** the
server ran with a self-signed certificate for the LAN IP
(`openssl req -x509`, CN and SAN `192.168.1.19`) and
`NIRAPODNET_HTTPS=1`. A second device on the same WiFi
(`192.168.1.2`) opened `https://192.168.1.19:8000`,
accepted the self-signed certificate warning, registered,
logged in, got a one-time WS ticket and connected — the
server log shows `WebSocket /ws?ticket=... [accepted]`
from `192.168.1.2`. SOS creation, check-ins, SOS status
changes and broadcasts were then used from both devices
(`192.168.1.19` and `192.168.1.2`). The certificate
(`cert.pem`, `key.pem`) is never committed: it is ignored
in `.gitignore`, and each deployment makes its own.

## Threat model

Assumed attacker: someone on the same LAN, or someone
who obtains a copy of the server database, or a
misbehaving authenticated user. Not assumed: physical
theft of the server, or an attacker who already holds
the signing key or an admin password.

| Threat | Mitigation in Phase 3 | Residual risk |
| --- | --- | --- |
| Credential stuffing on login | Per-IP+username rate limit, argon2 password hashing (Phase 2) | No CAPTCHA, no lockout; a slow distributed attack is still possible |
| Stolen database | Session tokens stored hashed; passwords argon2-hashed | Message, SOS and broadcast content are stored in clear text in SQLite |
| Flood / DoS by one client | Write and WebSocket rate limits | No process-level or proxy-level limits; a LAN flood can still saturate the single server |
| Duplicate SOS/broadcast on retry | Idempotency-Key, WS seq/ts, client_id dedup | Without Idempotency-Key, a retried POST still creates a second entity |
| Tampered stored broadcast | HMAC signature + verify endpoint | HMAC is symmetric: verification goes through the server, which holds the key; this is not public-key verification |
| XSS via message content | textContent rendering, control-character rejection, CSP | None known; CSP style-src is 'self' only since the Phase 3 completion work |
| Clickjacking | X-Frame-Options + frame-ancestors 'none' | None known |
| Session reuse after role change | Role change invalidates all sessions | A token is still usable until the role change happens |
| Token in WebSocket URL | Documented; no change yet | Token may appear in logs; a header-based WS auth is a follow-up |

## What Phase 3 does NOT claim

- **End-to-end encryption is not implemented.** Messages
  are encrypted in transit only when the deployment uses
  TLS, and they are stored in clear text on the server.
  True per-user end-to-end encryption for a group LAN
  chat needs key distribution, key recovery and a
  client-side crypto design that would change the
  offline-first UX; that design is deferred, not
  pretended. Do not describe NirapodNet as
  "end-to-end encrypted" on the basis of Phase 3.
  **Decision (2026-11-25, user chose Path A):** the
  TLS-only limit is accepted as the Phase 3 outcome.
  No end-to-end encryption code is written in Phase 3,
  and this limit stays documented here, in README.md
  and in PROGRESS.md. If end-to-end encryption is ever
  needed, it is a new phase of work, not a hidden part
  of Phase 3.
- **Public-key broadcast verification is not
  implemented.** The HMAC signature proves, through the
  server, that stored fields match what the server
  signed. It does not let an offline client verify a
  broadcast without trusting the server.
- **No formal OWASP Top 10 audit has been performed.**
  The checklist in the next section is a self-review
  against the implemented controls, not an external
  penetration test. A penetration test remains a
  Phase 4 item.

## OWASP Top 10 self-review (Phase 3)

- Broken Access Control: RBAC on every endpoint (Phase
  2), plus session invalidation on role change.
- Cryptographic Failures: argon2 passwords, hashed
  session tokens, HMAC broadcast signatures, TLS
  documented; clear-text storage is disclosed above.
- Injection: pydantic validation, SQLAlchemy parameters
  (no raw SQL strings with user input), control-character
  rejection.
- Insecure Design: rate limits, idempotency, threat
  model in this document.
- Security Misconfiguration: security headers, no
  debug or default admin in code (bootstrap needs env
  vars and a password of at least 8 characters).
- Vulnerable Components: pinned `pwdlib[argon2]` and
  other requirements (Phase 2); no new third-party
  dependency is added by Phase 3.
- Identification and Authentication Failures: 24-hour
  sessions, logout, 5-session cap, login rate limit.
- Software and Data Integrity Failures: broadcast
  signatures; no signed updates or plugins exist.
- Logging and Monitoring Failures: audit logs for
  critical actions (Phase 2) cover broadcasts, SOS,
  check-ins, role changes and bootstrap; failed logins
  and login/write rate-limit hits for known accounts
  are now also audited (Phase 3 completion work).
  Attempts for unknown usernames cannot be attributed
  to an account, so they are rate-limited but not
  audit-logged.
- Server-Side Request Forgery: the app makes no
  outbound requests on behalf of users.

## Audit fixes (2026-11-23, commit 91cb13a)

A ten-item security audit found further issues after
the Phase 3 core work; they were fixed and pushed as
one commit (owner `shihab-collab`):

- **Plain-HTTP warning:** the server prints a warning
  at startup unless `NIRAPODNET_HTTPS=1`, and the
  README has a "Run on LAN over HTTPS" section.
- **Registration rate limit:** 30/hour per IP by
  default (`NIRAPODNET_REGISTER_RATE_LIMIT`), on both
  `/users` and `/api/register`.
- **WebSocket tickets:** the frontend exchanges its
  Bearer token for a one-time ticket
  (`POST /api/ws-ticket`, 60 seconds, single use) and
  connects with `/ws?ticket=...` instead of the
  session token in the URL.
- **Pagination:** every list endpoint takes
  `limit`/`offset` (limit capped at 500), and the
  N+1 sender lookups were removed.
- **SQLite WAL:** journal mode WAL with a 30-second
  busy timeout; `check_same_thread` is only passed
  for SQLite, so a PostgreSQL URL no longer crashes
  engine creation.
- **Sessions:** `GET /api/sessions` lists live
  sessions, `DELETE /api/sessions` revokes all other
  sessions; a WebSocket is re-checked on every
  message and closed when its session is revoked or
  expires, including while idle (30-second recheck).
- **Admin backup:** `GET /api/admin/backup` returns
  a consistent SQLite backup file (admin only).
- **Atomic audit:** SOS, broadcast, check-in and role
  changes commit the action and its audit entry
  together, so a crash cannot leave an action
  without its audit record.
- **Real SECURITY.md:** the repository root
  `SECURITY.md` is a real policy now (supported
  version is `main`), not the template with fake
  version numbers.

## Open follow-ups (not hidden)

1. Per-user end-to-end encryption design. **Accepted
   limitation (2026-11-25, user decision, Path A):**
   not built in Phase 3; revisit as a new phase only
   if it is ever needed (see above).
2. Public-key (asymmetric) broadcast signing, to
   replace or complement HMAC. **Kept as HMAC in
   Phase 3:** the server is the only signer, so a
   symmetric signature fits; public-key verification
   is deferred to a later phase.
3. Header-based WebSocket authentication, so the
   token does not travel in the URL. **Partly done
   (2026-11-23):** the frontend now uses a one-time
   WS ticket (60 seconds, single use) instead of the
   session token in the URL; the legacy `/ws?token=`
   path still works for older clients, so the token
   can still appear in logs for those clients.
4. Audit logging for failed logins and rate-limit
   hits. **Done in the Phase 3 completion work:**
   failed logins and login/write rate-limit hits for
   known accounts are written to the audit log (see
   "Logging" below). Attempts for unknown usernames
   cannot be attributed to an account, so they are
   rate-limited but not audit-logged.
5. Removing inline `style` attributes so CSP can
   drop `'unsafe-inline'`. **Done in the Phase 3
   completion work:** the template uses a `.hidden`
   class instead of `style` attributes, and the CSP
   no longer allows `'unsafe-inline'`.
6. A real penetration test (Phase 4).
