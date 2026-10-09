# ADR 0007 — Public source, private deployment

- Status: Accepted · 2026-10-09

## Context

- The source code is published as open source (GPL-3.0, ADR 0006).
- For now the Cloudflare Worker and the Firebase project serve only the
  maintainer's own devices. Opening the service to others is a later decision
  (free-tier quota is shared by all groups, ADR 0004).

## Decision

- **Nothing deployment-specific is committed:** the Worker URL, the Cloudflare
  account id, `google-services.json`, the FCM service-account key and the
  admission token live in git-ignored local files, Worker secrets and CI secrets.
  The repository ships placeholders; a build from a clean checkout needs its own
  server.
- **The server admits only the operator's groups:** when `GROUP_CREATE_TOKEN` is
  set, creating a group requires that token (protocol §6.1, "Operator admission").
  Existing groups are already restricted to their members.

## Consequences

- Others can read, audit and build the code, and run their own deployment.
- The maintainer's quota cannot be consumed by strangers creating groups.
- Opening the service later means unsetting the token (or issuing tokens), plus a
  privacy notice for FCM/Cloudflare metadata.
- ✗ The token is embedded in the maintainer's builds; anyone holding such a
  build can extract it. Acceptable: it only grants group creation.
