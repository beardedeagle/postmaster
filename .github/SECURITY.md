# Security Policy

## Supported versions

postmaster is pre-1.0 and ships from a single line of development.
Security fixes land on the latest release and on `main`; there are no
separately maintained release branches. Always run the latest release.

| Version          | Supported |
| ---------------- | --------- |
| latest release   | ✅        |
| `main`           | ✅        |
| older tags       | ❌        |

## Reporting a vulnerability

**This project handles secrets.** Private keys, decrypted environment
values, and systemd/nix-darwin credentials are core to its purpose.

Please report security issues **privately** — do **not** open a public
issue, pull request, or discussion for anything security-sensitive.

Preferred channels (either is fine):

1. **GitHub private advisory (recommended).**
   Open a report at
   [security advisories](https://github.com/beardedeagle/postmaster/security/advisories/new).
   This keeps the discussion private and allows coordinated disclosure.

2. **Email.** Write to <randy@heroictek.com>.

Please include as much of the following as you can:

- A description of the vulnerability and its potential impact.
- Steps to reproduce (or a minimal proof-of-concept if safe to share).
- Affected versions / commits.
- Any suggested mitigation or fix.

We will acknowledge receipt quickly and work with you on a fix and
disclosure timeline.
