# Security policy

## Supported versions

Postmaster is unreleased. `main` is the supported development line;
there are no released versions or separately maintained release branches.

| Version          | Supported |
| ---------------- | --------- |
| `main`           | Yes       |

## Reporting a vulnerability

**This project handles secrets.** Private keys, decrypted environment
values, and systemd/nix-darwin credentials are core to its purpose.

Report security issues **privately**. Do **not** open a public
issue, pull request, or discussion for anything security-sensitive.

Preferred channels (either is fine):

1. **GitHub private advisory (recommended).**
   Open a report at
   [security advisories](https://github.com/beardedeagle/postmaster/security/advisories/new).
   This keeps the discussion private and allows coordinated disclosure.

2. **Email.** Write to <randy@heroictek.com>.

Include the following where available:

- A description of the vulnerability and its potential impact.
- Steps to reproduce (or a minimal proof-of-concept if safe to share).
- Affected versions / commits.
- Any suggested mitigation or fix.

We'll acknowledge the report and work with you on a fix and disclosure
timeline.
