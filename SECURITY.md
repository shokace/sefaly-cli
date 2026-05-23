# Security Policy

Sefaly's CLI handles end-to-end-encrypted key material on the user's
behalf. Issues that compromise the confidentiality, integrity, or
availability of that material are taken seriously.

## Reporting a vulnerability

Please report security issues **privately**, NOT via a public GitHub
issue:

- Email **`security@sefaly.com`**
- Or use GitHub's private vulnerability reporting (Security tab →
  Report a vulnerability)

Include:

- A description of the issue
- Steps to reproduce, ideally a minimal proof-of-concept
- Your assessment of the impact
- Suggested mitigation if you have one

We aim to acknowledge new reports within 3 business days and to land
a fix within 30 days for high-impact issues. We'll keep you in the
loop on status; please do not publicly disclose the issue before a fix
is released.

## Scope

In scope:

- The CLI binary itself (this repo)
- Its interaction with the Sefaly API (auth, file operations,
  credential storage)
- The wire formats implemented in `internal/cryptox/` (a dedicated
  `docs/CRYPTO_SPEC.md` is planned; the source is authoritative
  until it lands)
- The OS-keychain integrations (macOS Keychain, Linux Secret Service,
  Windows Credential Manager)

Out of scope:

- The Sefaly web app (closed-source, separate disclosure channel)
- Social engineering, physical attacks
- Denial of service via excessive resource consumption

## Recognition

We'll credit reporters who want it (after the issue is fixed and
disclosure has happened). No formal bug bounty yet — that may change
once the project matures.
