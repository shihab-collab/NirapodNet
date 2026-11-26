# NirapodNet — API and Message Format

This document describes the local network communication protocol as
implemented in Phase 1 (core prototype), Phase 2 (emergency
system) and Phase 3 (security, in progress). It covers the REST
endpoints and the WebSocket message formats. FastAPI also serves
interactive documentation at `/docs` while the server is running.

## Authentication

- Register: `POST /api/register` with `{"username", "password"}`
  (username 3–50 chars, password 8–128 chars). Returns `201`, or
  `409` when the username is taken.
- Login: `POST /api/login` with the same body. Returns
  `{"token", "user": {"id", "username", "role"}, "expires_at"}`.
  Sessions expire after 24 hours. Only the hash of the token
  is stored (Phase 3); the plain token is returned once at
  login. At most 5 live sessions per user are kept.
- Authenticated requests send the token as
  `Authorization: Bearer <token>`.
- Logout: `POST /api/logout` invalidates the current session.
- Current user: `GET /api/me`.
- Sessions: `GET /api/sessions` lists your live sessions
  (`token_preview` is the first 8 characters of the stored
  token hash, plus `expires_at`); `DELETE /api/sessions`
  revokes all of your other sessions and reports
  `revoked_sessions`. Changing a user's role invalidates
  all of that user's sessions.
- WebSocket ticket: `POST /api/ws-ticket` exchanges the
  current Bearer token for a one-time ticket (60 seconds,
  single use) to connect with `/ws?ticket=...` instead of
  putting the session token in the URL. The old
  `/ws?token=...` path still works for older clients.

## Phase 3 security notes

- Every response carries security headers (CSP,
  `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`; HSTS only over
  HTTPS). See `docs/SECURITY.md` for the threat model.
- Rate limits return `429` with `Retry-After: 60`:
  login 10/minute per IP + username (tunable with
  `NIRAPODNET_LOGIN_RATE_LIMIT`), authenticated writes
  120/minute per user (tunable with
  `NIRAPODNET_WRITE_RATE_LIMIT`), WebSocket 30 messages
  per 10 seconds per connection. Registration is limited
  to 30/hour per IP by default (tunable with
  `NIRAPODNET_REGISTER_RATE_LIMIT`, `Retry-After: 3600`).
  Failed logins and login/write rate-limit hits for
  known accounts are written to the audit log; attempts
  for unknown usernames cannot be attributed to an
  account, so they are rate-limited but not logged.
- `POST /messages`, `POST /api/sos`,
  `POST /api/broadcasts` and `POST /api/checkins`
  accept an optional `Idempotency-Key` header. Repeating
  the same key for the same user and endpoint returns
  the original response instead of creating a second
  entity.
- Broadcasts created in Phase 3 carry a `signature`
  field. `GET /api/broadcasts/{id}/verify`
  (authenticated) reports `signature_present` and
  `valid` for a stored broadcast.
- List endpoints take `limit` (default 100, maximum
  500) and `offset` (default 0) and never return every
  row: `GET /users`, `GET /api/admin/users`,
  `GET /messages`, `GET /api/sos`, `GET /api/broadcasts`,
  `GET /api/checkins`, `GET /api/checkins/me`.
- The CSP no longer allows `'unsafe-inline'` (Phase 3
  completion work): show/hide uses the `.hidden` class
  in `style.css`, not inline `style` attributes.
- End-to-end encryption is not implemented (accepted
  limitation, user decision 2026-11-25, Path A):
  messages are protected by TLS in transit only. See
  `docs/SECURITY.md`.

### Roles

| Role | Tier |
|------|------|
| `user` | Regular user |
| `rescue` / `responder` | Responder tier (same permissions; `responder` is the roadmap name, `rescue` the original name) |
| `operator` | Operator |
| `admin` | Administrator |

Only an admin can change roles:
`PATCH /api/admin/users/{user_id}/role` with `{"role": "<role>"}`.
The first admin is bootstrapped with the
`NIRAPODNET_ADMIN_USERNAME` and `NIRAPODNET_ADMIN_PASSWORD`
environment variables at server startup (password minimum 8
characters); without them, startup behaviour is unchanged.

## REST endpoints

| Method and path | Who | Purpose |
|---|---|---|
| `GET /` | public | Web UI |
| `GET /api` | public | System status |
| `POST /users` | public | Legacy Phase 1 user creation (idempotent, no session) |
| `POST /api/register` | public | Create an account |
| `POST /api/login` | public | Log in, returns a session token |
| `POST /api/logout` | any session | Log out |
| `GET /api/me` | any session | Current user |
| `GET /api/sessions` | any session | List your live sessions |
| `DELETE /api/sessions` | any session | Revoke all your other sessions |
| `POST /api/ws-ticket` | any session | One-time WebSocket ticket (60s, single use) |
| `GET /api/admin/backup` | admin | Download a SQLite backup file |
| `GET /users`, `GET /api/admin/users` | admin | List users (paginated) |
| `PATCH /api/admin/users/{user_id}/role` | admin | Change a user's role |
| `GET /api/rbac/user|rescue|operator|admin` | by tier | Role probe endpoints |
| `POST /messages` | any role | Post a message (sender is taken from the session) |
| `GET /messages` | any session | Message history, oldest first |
| `POST /api/sos` | any role | Create an SOS (see below) |
| `GET /api/sos?status=` | responder, operator, admin | List SOS incidents |
| `GET /api/sos/{incident_id}/history` | responder, operator, admin | SOS status history |
| `PATCH /api/sos/{incident_id}/status` | responder, operator, admin | Advance an SOS status |
| `POST /api/broadcasts` | operator, admin | Create an emergency broadcast |
| `GET /api/broadcasts?after_id=` | any session | List broadcasts (optionally only after an id) |
| `GET /api/broadcasts/{id}/verify` | any session | Check a broadcast's Phase 3 signature |
| `POST /api/checkins` | any session | Send a safety check-in |
| `GET /api/checkins/me` | any session | Own check-in history |
| `GET /api/checkins` | responder, operator, admin | All check-ins |
| `GET /api/checkins/summary` | responder, operator, admin | Per-status counts, latest check-in per user |
| `GET /api/audit-logs?limit=` | operator, admin | Audit log (1–500 entries) |

### SOS

Create body:

```json
{
  "emergency_type": "flood | medical | fire | trapped | other",
  "latitude": -90 to 90, or null,
  "longitude": -180 to 180, or null,
  "description": "optional, up to 2000 chars"
}
```

Each SOS gets an incident id (`INC-<year>-<5 digits>`) and starts as
`OPEN`. Status changes must follow
`OPEN → RESPONDING → ON-SCENE → RESOLVED`; any other transition is
rejected with `409`.

### Broadcasts

Create body:

```json
{
  "type": "e.g. Flood Warning",
  "message": "up to 5000 chars",
  "priority": "critical | high | medium | low"
}
```

`info` and `warning` are also accepted as legacy aliases from the
first Phase 2 iteration. In Phase 2 a broadcast targets the whole
local network; geographic targeting arrives with the geospatial
layer in Phase 6.

### Check-ins

Create body:

```json
{
  "status": "SAFE | NEED_HELP | NOT_AT_LOCATION | UNABLE_TO_RESPOND",
  "broadcast_id": "optional id of the broadcast being answered"
}
```

## WebSocket protocol

Preferred: `POST /api/ws-ticket` with the Bearer token,
then connect with `ws://<host>:8000/ws?ticket=<ticket>`.
The ticket is single-use and expires in 60 seconds, so a
ticket that lands in a server log is already useless.
Legacy clients may still connect with
`ws://<host>:8000/ws?token=<session token>`. An invalid or
expired ticket/token closes the connection with code
`1008`. The session behind a connection is re-checked on
every message and while idle (30-second recheck), so
logout, expiry or role-change revocation closes a live
connection; a broken JSON frame returns an error frame
instead of killing the socket.

Client → server (chat message):

```json
{"client_id": "unique per message, 1-100 chars", "content": "1-2000 chars"}
```

Optional Phase 3 fields: `"seq"` (strictly increasing
integer per connection) and `"ts"` (unix seconds, within
5 minutes of server time). When sent, a replayed sequence
or stale timestamp is rejected with an error frame. The
shipped frontend sends both. Messages outside the length
limits are rejected with an error frame and
are not stored. A repeated `client_id` from the same sender returns
the original acknowledgement instead of storing a duplicate.

Server → client frames:

| `type` | Meaning | Extra fields |
|---|---|---|
| `ack` | Your message was stored | `client_id`, `message_id`, `sender_id`, `sender`, `content`, `timestamp` |
| `message` | Another user's message | `client_id`, `id`, `sender_id`, `sender`, `content`, `timestamp` |
| `sos` | New SOS (responder tier and above only) | `incident_id`, `user_id`, `emergency_type`, `latitude`, `longitude`, `description`, `status`, `created_at` |
| `sos_status` | SOS status changed (responder tier and above only) | `incident_id`, `status`, `changed_by`, `timestamp` |
| `broadcast` | New emergency broadcast (all users) | `id`, `broadcast_type`, `message`, `priority`, `issued_by`, `created_at`, `signature` (Phase 3) |
| `error` | Your last frame was invalid | `error` |
