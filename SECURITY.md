# Security Policy

## Supported Versions

NirapodNet has no versioned releases. Security fixes are made on the
`main` branch only, so the supported version is the current `main`
branch. If you run an older commit, update to the latest `main` first
and check whether the issue is still present there.

## Reporting a Vulnerability

Please report a security issue by opening an issue on the project
repository, https://github.com/shihab09999/NirapodNet/issues, with the
title starting with `[security]`. Describe the affected commit or
`main` checkout, the steps to reproduce, and the impact you observed.
Do not include passwords, tokens, or other people's personal data in
the report, and do not post a working exploit against a live deployment
run by someone else.

There is no fixed response timeline: this is a small community safety
project maintained in the maintainer's own time, so a report is
reviewed as soon as possible but no turnaround is guaranteed. If a
report is accepted, the fix lands on `main` and is described in the
commit message; if it is declined, the reason is given on the issue.

## Known Limits

Honest limits of the current `main` branch, so a reporter does not
have to rediscover them:

- Messages are protected in transit by TLS only when the server is
  run over HTTPS. There is no end-to-end encryption yet, and messages
  are stored in clear text in the database.
- Broadcast signing is HMAC with a server-side key, not public-key
  verification.
- Session tokens are stored hashed, but a WebSocket ticket or token
  sent in a URL can appear in server access logs.
