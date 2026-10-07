# Security policy

Security is a primary goal of this project. The design assumes the server,
relays, push provider and network are **untrusted**; see
[`docs/threat-model.md`](docs/threat-model.md) for what we defend against and
what is out of scope.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's private vulnerability
reporting ("Security" tab → "Report a vulnerability") on this repository.

Include: affected component (core / windows-agent / windows-ui / android /
server), version or commit, reproduction steps, and impact. We aim to
acknowledge reports within 7 days and to ship fixes for confirmed issues as
fast as the severity requires.

## Scope

In scope: the wire protocol and cryptography (`docs/protocol.md`), membership
log validation, pairing, the Windows agent's local attack surface (named pipe,
toast activation, clipboard/file handling), the Android app's exported
components, and the Cloudflare Worker.

Out of scope: attacks that require code execution as the same OS user (such
code can already read the user's files and clipboard), and denial of service
by the server operator (documented as accepted in the threat model).

## Supported versions

Until the first public release, only the `main` branch is supported.
