# Security Policy

## Supported Versions

Only the `main` branch receives security fixes at this stage — there is no
LTS/backport policy yet.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, use GitHub's private vulnerability reporting (Security tab →
"Report a vulnerability") on this repository. If that's unavailable, open a
minimal public issue asking for a private contact channel without
describing the vulnerability itself.

Please include:
- A clear description of the vulnerability and its impact
- Steps to reproduce (config snippets, request examples, etc.)
- The affected version/commit

We aim to acknowledge reports within 5 business days.

## Scope

In scope: the CyberNom application code in this repository (`cmd/`,
`internal/`), the provided Dockerfile/Compose/nginx configs.

Out of scope: vulnerabilities in third-party dependencies (please report
those upstream — we'll track the fix via a dependency bump), and issues
that require an attacker to already have admin credentials or root on the
host.
