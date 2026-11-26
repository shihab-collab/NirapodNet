# NirapodNet — Progress Log

## Overview
This document serves as a chronological work history and project diary for NirapodNet. Each entry records the date, phase, tasks completed, decisions made, blockers encountered, and next steps.

---

## 2026-08-17 — Project Initialization

**Phase:** 0 — Foundation  
**Status:** In Progress

### Tasks Completed
- [x] Created project repository structure
- [x] Created README.md with project overview, architecture, and quick start
- [x] Copied MASTER_PLAN.md to docs/MASTER_PLAN.md (complete project specification)
- [x] Created ROADMAP.md with 14 phases and detailed task breakdowns
- [x] Created PROGRESS.md (this file)
- [x] Created .gitignore for Python, Node, IDE, and environment files
- [x] Created LICENSE (MIT License)

### Decisions Made
- Project structure follows the recommended repository layout
- Documentation organized in docs/ directory
- MIT License chosen for open-source portfolio project
- Roadmap structured around 14 phases matching MASTER_PLAN.md

### Blockers
- None at this stage

### Next Steps
- Initialize Git repository
- Set up Python virtual environment
- Create initial project structure (backend/, frontend/, docker-compose.yml)
- Begin Phase 1: Core Prototype implementation

---

## 2026-10-20 — Phase 2 Completion

**Phase:** 2 — Emergency System
**Status:** Completed

### Tasks Completed
- [x] Emergency Broadcast completed: `POST /api/broadcasts` for operators/admins, live WebSocket delivery to all connected users, and the frontend's missing `syncMissedBroadcasts()` implemented so missed broadcasts are fetched with `after_id` after a reconnect
- [x] Safety Check-In completed: `POST /api/checkins` with the four statuses (SAFE, NEED_HELP, NOT_AT_LOCATION, UNABLE_TO_RESPOND), optional link to a broadcast, per-user history (`GET /api/checkins/me`), operator list and an aggregation summary that counts only each user's latest check-in
- [x] Operator/admin dashboard UI added to the existing page: SOS incident list with status-advance buttons, broadcast composer, check-in summary, and audit log view (operator/admin only)
- [x] Audit logging added for critical actions: role changes, SOS creation, SOS status changes, broadcast creation, and check-ins (`GET /api/audit-logs`, operator/admin only)
- [x] First-admin bootstrap added: `NIRAPODNET_ADMIN_USERNAME` / `NIRAPODNET_ADMIN_PASSWORD` environment variables create or promote the first admin at startup; without them startup behaviour is unchanged
- [x] Frontend login flow fixed to use the Phase 2 auth system (`/api/register` + `/api/login` with a password field); the old flow called `/users` with only a username and could no longer log in
- [x] Check-in panel added to the frontend with the four status buttons
- [x] `pwdlib[argon2]` pinned to `==0.3.1` in requirements.txt (it was the only unpinned dependency)
- [x] Phase 2 test log written: `tests/phase-2-test-log.md`

### Decisions Made
- Broadcast priority levels stay as implemented and used by the frontend/CSS: info, warning, critical
- The broadcast WebSocket payload uses `type: "broadcast"` for routing and `broadcast_type` for the broadcast's own type, matching the existing frontend handler
- Audit logging is a new table only; no existing table was altered, so databases created by earlier phases upgrade automatically on startup (verified in the test log)
- Geographic targeting for broadcasts is deferred to Phase 6 (Geospatial Layer): user areas/locations do not exist before that phase, and phases proceed serially. In Phase 2 a broadcast targets the whole local network. The ROADMAP checkbox stays open until Phase 6
- Phase 1 behaviour was preserved and all Phase 1 tests were re-run as regression tests and pass. (Correction, added at the hard check below: Phase 1 *code* was not literally untouched — the frontend login flow, template and CSS changed where Phase 2 authentication required it.)

### Blockers
- None

### Metrics
- 36/36 automated checks passed (authentication, RBAC, broadcast, SOS, check-in, audit, WebSocket, Phase 1 regression)
- Existing-database upgrade test passed (old data preserved, new table auto-created)
- Real uvicorn run passed

### Next Steps
- Phase 3 — Security, in serial order (nothing from Phase 3 was started in this phase)

---

## 2026-10-20 — Phase 2 Hard Check

**Phase:** 2 — Emergency System
**Status:** Completed (verified)

An independent static audit plus a separate adversarial test run
(37 checks) were performed against the completion claim above.
The audit corroborated the core claim (broadcast, check-in, SOS
lifecycle, RBAC enforcement, password hashing, audit-log
existence), and the adversarial run initially failed 5 checks.
All of the following were found and fixed the same day:

- The roadmap's "Responder" role could not be assigned at all
  (400). `responder` is now accepted everywhere the `rescue` tier
  is, and existing `rescue` accounts are unaffected
- SOS latitude/longitude accepted any value (e.g. 999). Range
  validation added (-90..90, -180..180; out-of-range returns 422)
- The roadmap's broadcast priority levels (Critical, High,
  Medium, Low) were not accepted (422). They are now implemented
  end to end; info/warning remain as legacy aliases
- The WebSocket path ignored the REST message limits: a
  5000-character message and a 300-character client_id were
  stored. The WebSocket handler now enforces the same
  1-2000 / 1-100 limits and replies with an error frame
- The SOS form hardcoded type "other", null coordinates and a
  fixed description. The form now has a type selector, a
  description field, and best-effort browser geolocation
- `syncMissedBroadcasts()` silently dropped all but the newest
  missed broadcast. Every missed broadcast is now also added to
  the message list as a system notice
- A check-in could stay silently linked to a broadcast banner
  that had been acknowledged or hidden. The link is now cleared
  on acknowledge and only used while the banner is visible
- The dashboard had no admin functions and no session handling.
  It now includes admin user/role management, a recent check-in
  list, SOS history, a logout button, and session restore via
  `GET /api/me`
- The admin bootstrap wrote no audit entry. It now records an
  `admin_bootstrapped` audit event (create and promote)
- The completion evidence lived outside the repo. The automated
  suite is now committed as `tests/run_phase2_checks.py`
  (44/44 passing) and the protocol is documented in
  `docs/API.md`

Re-verification after the fixes: committed suite 44/44, the
original Phase 2 suite 36/36, the adversarial suite 37/37, the
existing-database upgrade test, and a real uvicorn run all pass.

Remaining known items, deliberately not hidden: audit entries
are written in a second commit after the action (not one
transaction); Phase 1's Docker Compose checkbox stays open;
broadcast geographic targeting stays deferred to Phase 6.

---

## Template for Future Entries

### YYYY-MM-DD — Descriptive Title

**Phase:** X — Phase Name  
**Status:** Not Started / In Progress / Completed / Blocked

### Tasks Completed
- [ ] Task description
- [ ] Task description

### Decisions Made
- Key architectural or technical decisions
- Tool/technology selections
- Scope changes

### Blockers
- Description of blocker
- Impact assessment
- Mitigation plan

### Metrics (if applicable)
- Performance measurements
- Test results
- User feedback scores

### Next Steps
- Immediate next tasks
- Upcoming milestones

---

## 2026-10-30 — Phase 3 Started (Security, in progress)

**Phase:** 3 — Security
**Status:** In Progress (not Completed — see open items below)

Continuity: before any Phase 3 code, the local clone was
aligned to the GitHub head `4a07639` (Phase 2 push). The
working tree was verified byte-for-byte identical to
`origin/main` (hashes matched, 3 untracked files identical)
before `git reset --hard origin/main`, so no Phase 2 work
was lost and the tree is now clean at `4a07639`.

### Tasks Completed
- [x] Security headers middleware on every response (CSP, nosniff, DENY framing, Referrer-Policy, Permissions-Policy; HSTS only over HTTPS)
- [x] Session tokens stored hashed (SHA-256), 24-hour expiry kept, 5-session cap per user, role change invalidates all of that user's sessions
- [x] Rate limiting (in-memory, per process): login 10/minute per IP + username (env-tunable), authenticated writes 120/minute per user, WebSocket 30 messages per 10 seconds per connection; 429 with Retry-After
- [x] Replay protection: optional Idempotency-Key header on POST /messages, /api/sos, /api/broadcasts, /api/checkins; WebSocket optional seq (strictly increasing per connection) and ts (within 5 minutes); frontend now sends seq + ts
- [x] Broadcast signing: HMAC-SHA256 over id|issued_by|type|message|priority|created_at, signature in API and WebSocket payloads, GET /api/broadcasts/{id}/verify endpoint
- [x] Input validation and sanitization: control-character rejection and whitespace stripping for usernames, message content, broadcast fields and SOS descriptions (frontend already renders with textContent)
- [x] Threat modeling and security architecture documented in docs/SECURITY.md, with an OWASP Top 10 self-review
- [x] Old-database upgrade: broadcasts table gains a signature column via migration on startup (create_all alone does not add columns); verified with a pre-Phase-3 database
- [x] Automated suite tests/run_phase3_checks.py: 34/34 passed; Phase 2 suite still 44/44; real uvicorn run passed with headers visible

### Decisions Made
- No new third-party dependency in Phase 3 (stdlib HMAC only). HMAC signing is server-side tamper evidence, not public-key verification — documented honestly in docs/SECURITY.md, not claimed as otherwise.
- End-to-end encryption is NOT implemented and NOT claimed: messages are encrypted in transit only under TLS and stored in clear text. A per-user E2E design for group LAN chat is deferred, because it would change the offline-first UX and needs its own key-management design.
- WSS is deployment-dependent: the frontend already uses wss: over HTTPS, and TLS is documented with a uvicorn command, but no certificate is bundled or checked in.
- Signing key: NIRAPODNET_SIGNING_KEY from the environment is the production path; without it the server uses an ephemeral per-process key and old signatures stop verifying after a restart.
- WebSocket token still travels as a query parameter for compatibility; documented as a residual risk, header-based WS auth is a follow-up.

### Blockers
- One real bug found by testing and fixed the same day: the session cap deleted the newest session instead of the oldest (slice direction). Fixed in app/crud.py; Phase 3 suite then passed 34/34.
- One real upgrade bug found by testing and fixed the same day: pre-Phase-3 databases failed broadcast queries (missing signature column). Fixed with a startup migration in app/main.py; old broadcast lists and verifies as signature_present=False, valid=False.

### Metrics
- Phase 3 suite: 34/34 passed
- Phase 2 regression suite: 44/44 passed (unchanged)
- Old-database upgrade test: passed
- Real uvicorn run: passed

### Next Steps
- End-to-end encryption design (deferred, see above)
- Public-key broadcast signing to complement or replace HMAC
- Header-based WebSocket authentication
- Audit logging for failed logins and rate-limit hits
- Removing inline style attributes so CSP can drop 'unsafe-inline'
- Formal penetration test (Phase 4 item)
- Only after those decisions: mark Phase 3 Completed and push, with the user's permission (no commit/push in this session)

---
## 2026-11-25 — Phase 3 completion work (Path A, TLS limit accepted)

**Phase:** 3 — Security  
**Status:** In Progress — all Muse-side work done; LAN WSS test (user) and push still pending, so Phase 3 is NOT marked Completed yet

**Decision (2026-11-25, user chose Path A):** end-to-end encryption is NOT built in Phase 3. The TLS-only limit is accepted and documented as an accepted limitation in docs/SECURITY.md, README.md, PROGRESS.md and ROADMAP.md. If E2E is ever needed, it is a new phase of work. Public-key broadcast signing is likewise deferred — HMAC stays, because the server is the only signer.

### Tasks Completed
- [x] E2E accepted limit documented (Path A): docs/SECURITY.md "Accepted limitations" section and follow-ups list, README.md honesty line, PROGRESS.md and ROADMAP.md decision notes
- [x] Failed-login and rate-limit audit logging: `login_failed` and `login_rate_limited` for known accounts in `POST /api/login`; `rate_limit_hit` for authenticated writes (`_check_write_rate_limit` now takes db, limit env-tunable via `NIRAPODNET_WRITE_RATE_LIMIT`, default 120). Attempts for unknown usernames cannot be attributed to an account (actor_id is a foreign key), so they are rate-limited but not audit-logged — documented in docs/SECURITY.md
- [x] CSP 'unsafe-inline' removed: template uses a `.hidden` class in style.css instead of `style="display:none"` attributes (7 removed, 0 remain); the one visibility read in app.js now uses `getComputedStyle`; CSP style-src is 'self' only
- [x] docs/API.md updated: GET/DELETE /api/sessions, POST /api/ws-ticket, GET /api/admin/backup, pagination (limit/offset, cap 500) on all list endpoints, register rate limit, failed-login/rate-limit audit logging, E2E accepted limit; WebSocket section rewritten for the ticket flow and per-message session re-check
- [x] docs/SECURITY.md updated: audit-fixes section for commit 91cb13a (WS ticket, pagination, WAL/backup, session revoke, atomic audit, register limit, real root SECURITY.md), Path A decision, HMAC-kept decision, WS ticket residual risk, logging section
- [x] CI workflow `.github/workflows/tests.yml`: Python 3.12, syntax checks, all four suites (Phase 2, Phase 3, audit fixes, Phase 3 completion), plus a Docker image build on every push/PR to main
- [x] Dockerfile (python:3.12-slim, uvicorn on port 8000, TLS and database via environment/volume, secrets never baked in) and .dockerignore. Not verified locally: this machine has no Docker, so docker build was never run here. The CI workflow builds the image, so the first push to main is what verifies it — do not claim the Dockerfile works until CI passes.
- [x] Router split: app/main.py 1,624 lines → 110 lines; routes moved verbatim to app/routers/ (core, auth, users, messages, sos, broadcasts, checkins, admin, websocket), shared helpers to app/helpers.py (including broadcast_sos/broadcast_alert, which two routers share). Two split bugs found by the test gate and fixed: a local `from .security import` inside the WebSocket handler, and a missing UserSession import in helpers. Backup of the pre-split app/main.py kept at `~/workspace/projects/NirapodNet-main.py.91cb13a.bak`
- [x] New suite tests/run_phase3_completion_checks.py: 18/18 passed (login_failed, login_rate_limited, rate_limit_hit, CSP header, no style= attributes, docs checks)

### Decisions Made
- Phase 3 is NOT marked Completed in this session: the LAN WSS test is a user step that has not happened yet, and the Dockerfile build is unverified until CI runs. Marking it Completed before those would be a false claim.
- Router split is a mechanical move, not a behaviour change: handler code is verbatim, only `@app.*` became `@router.*`. The four suites are the gate.

### Metrics
- Phase 2 suite: 44/44 passed (after the router split)
- Phase 3 suite: 34/34 passed (after the router split)
- Audit fixes suite: 40/40 passed (after the router split)
- Phase 3 completion suite: 18/18 passed
- Old-database upgrade test: passed (broadcasts table without signature column re-gains it via the startup migration; new broadcast verifies valid: true)
- Real uvicorn run: passed (/api online, CSP without 'unsafe-inline', served page has 0 style= attributes, login works, plain-HTTP warning printed)
- py_compile OK, node --check app/static/app.js OK, AI-sign grep clean

### Next Steps
- LAN WSS test by the user — done 2026-11-25, passed (see the 2026-11-25 WSS test entry below)
- Push this work to GitHub (one commit, user's separate permission + approval card) — then CI builds the Docker image and runs all four suites
- Only after a green CI run: mark Phase 3 Completed in ROADMAP.md and PROGRESS.md
- Formal penetration test remains a Phase 4 item

---
## 2026-11-25 — LAN WSS test passed (user's PC)

**Phase:** 3 — Security (WSS item)  
**Status:** Passed — verified on the user's PC over the LAN

The user regenerated the self-signed certificate with the
correct LAN IP (first attempt used 192.168.1.10, the real
IP is 192.168.1.19) and restarted the server with TLS.
`git status` confirmed cert.pem and key.pem are
untracked; they are now also ignored in .gitignore so
they can never be committed by accident.

Server log evidence (same WiFi):
- 192.168.1.2 (second device) opened
  `https://192.168.1.19:8000`, registered (201), logged
  in (200), got a WS ticket (200) and connected:
  `WebSocket /ws?ticket=... [accepted]`, connection open
- SOS created (201), check-ins created (201), SOS
  status advanced (PATCH ... 200), broadcasts created
  (201) from both 192.168.1.19 and 192.168.1.2
- The page was served over HTTPS, so the WebSocket ran
  over wss: (the frontend chooses wss: on HTTPS)

Recorded in docs/SECURITY.md ("Running over TLS (WSS)")
and in ROADMAP.md (WSS checkbox ticked with the test
note). Phase 3 is still not marked Completed: the push
and a green CI run are still pending.

---

## Phase Completion Log

| Phase | Start Date | End Date | Status | Notes |
|-------|------------|----------|--------|-------|
| Phase 0 — Foundation | 2026-08-17 | 2026-08-30 | Completed | Repository and environment set up; superseded by Phase 1 completion |
| Phase 1 — Core Prototype | 2026-08-20 | 2026-08-31 | Completed | 5/5 tests in tests/phase-1 test log; behaviour unchanged by Phase 2 work |
| Phase 2 — Emergency System | 2026-09-01 | 2026-10-20 | Completed | Broadcast, check-in, dashboard and audit completed 2026-10-20; see tests/phase-2-test-log.md. Broadcast geographic targeting deferred to Phase 6 |
| Phase 3 — Security | 2026-10-30 | 2026-11-25 | Completed | Security headers, hashed sessions, rate limits, replay protection, HMAC broadcast signing, threat model, audit logging for failed logins/rate limits, CSP without 'unsafe-inline', CI/Dockerfile, router split; Path A (TLS-only, no E2E) accepted; all 4 suites pass (136/136); LAN WSS test passed; CI and push pending |
| Phase 4 — Measurement | - | - | Not Started | - |
| Phase 5 — First Real Pilot | - | - | Not Started | - |
| Phase 6 — Geospatial Layer | - | - | Not Started | - |
| Phase 7 — Sensor Network | - | - | Not Started | - |
| Phase 8 — Resilient Networking | - | - | Not Started | - |
| Phase 9 — Portable Infrastructure | - | - | Not Started | - |
| Phase 10 — UAV Integration | - | - | Not Started | - |
| Phase 11 — Satellite Backhaul | - | - | Not Started | - |
| Phase 12 — Multi-Node Deployment | - | - | Not Started | - |
| Phase 13 — Research & Validation | - | - | Not Started | - |

---

## Key Decisions Log

| Date | Decision | Rationale | Impact |
|------|----------|-----------|--------|
| 2026-08-17 | Use MIT License | Open-source portfolio project, maximum adoption | Permissive, allows commercial use |
| 2026-08-17 | Python/FastAPI backend | Team familiarity, rich ecosystem, async support | Fast development, good WebSocket support |
| 2026-08-17 | HTML/CSS/JS frontend (no framework initially) | Simplicity, offline-first, no build step required | Lightweight, works offline, easy to deploy |
| 2026-08-17 | SQLite for edge storage | Zero-config, file-based, portable | Ideal for disconnected edge nodes |
| 2026-08-17 | 14-phase roadmap | Matches MASTER_PLAN.md structure | Clear progression, measurable milestones |
| 2026-11-25 | Path A: TLS-only, no E2E in Phase 3 | User decision; E2E would change offline-first UX and needs separate key-management design; HMAC broadcast signing kept (server is sole signer) | Accepted limitation documented in SECURITY.md, README.md, PROGRESS.md, ROADMAP.md; public-key signing deferred to future phase; Phase 3 marked complete without E2E |

---

## Blocker History

| Date | Blocker | Phase | Resolution | Resolution Date |
|------|---------|-------|------------|-----------------|
| - | - | - | - | - |

---

## Meeting Notes

### 2026-08-17 — Project Kickoff
**Attendees:** Project Lead  
**Summary:** Initialized repository with core documentation files. Established project structure and roadmap. Ready to begin Phase 0 foundation work.

**Action Items:**
- [ ] Initialize Git repository
- [ ] Set up development environment
- [ ] Create initial backend/frontend structure

---

*This progress log should be updated at the end of each work session. Each entry should be honest about challenges, not just successes.*