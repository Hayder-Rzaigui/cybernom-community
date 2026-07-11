<div align="center">

# CyberNom Community Edition

**A free, open-source Threat Intelligence & Security Monitoring platform — single binary, no external services beyond Postgres.**

[![License: MIT](https://img.shields.io/badge/license-MIT-3F6E66)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.22%2B-3F6E66)](go.mod)
[![Postgres](https://img.shields.io/badge/postgres-16%2B-3F6E66)](migrations/0001_init.sql)
[![Security Policy](https://img.shields.io/badge/security-policy-3F6E66)](SECURITY.md)
[![Enterprise available](https://img.shields.io/badge/enterprise-available-orange)](#-cybernom-enterprise)
[![GitHub stars](https://img.shields.io/github/stars/Hayder-Rzaigui/cybernom-community?style=social)](https://github.com/Hayder-Rzaigui/cybernom-community/stargazers)

Author: **Hayder Rzaigui**

</div>

![CyberNom Dashboard](docs/screenshot.png)

-----

**The problem:** SOC teams end up stitching together a threat-intel feed reader, a keyword alerter, an M365 posture checker, and an auth layer on top of all of it — usually as three separate half-finished scripts with no login screen. CyberNom is that whole stack, in one Go binary, with real authentication from the first line of code.

**Quick start** (full detail in [Installation](#installation) below):

```bash
git clone https://github.com/Hayder-Rzaigui/cybernom-community.git && cd cybernom-community
cp .env.example .env   # set CYBERNOM_JWT_SIGNING_KEY and CYBERNOM_DB_PASSWORD
cp config/config.yaml.example config/config.yaml
cd deployments && docker compose --env-file ../.env up -d --build
```

CyberNom fuses two lineages into one hardened, single-binary service:

- **Internal posture visibility** — Microsoft 365, via strictly read-only Microsoft Graph access
- **External threat intelligence** — RSS, JSON APIs, websites, and `.onion` sources via Tor, with regex/keyword alerting

It exists to fix the shared weakness both source concepts had — **no built-in authentication** — while keeping what each did well: read-only least-privilege Graph access on one side, broad multi-source ingestion on the other.

This is the **Community Edition**: the complete open-source core, free and unrestricted, MIT-licensed, and structured to build standalone out of the box with a plain `go build`.

-----

## Table of Contents

- [High-performance core](#high-performance-core)
- [Installation](#installation)
- [Dashboard](#dashboard)
- [Configuration](#configuration)
- [API Overview](#api-overview)
- [Threat Model](#threat-model)
- [Community vs. Enterprise](#community-vs-enterprise)
- [CyberNom Enterprise](#-cybernom-enterprise)
- [License](#license)

-----

## High-performance core

Everything below ships in the single `cybernom` binary — no extra services to run besides Postgres and, optionally, Tor.

|Category              |Capability                                                                                                                                          |
|----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
|**Ingestion**         |RSS/Atom, generic JSON APIs, plain website scraping, `.onion` sources exclusively via Tor — 24 pre-built feeds included                             |
|**Alerting**          |Literal or regex keyword rules, severity levels, tag-based filtering                                                                                |
|**Regex safety**      |Built on Go’s RE2 engine — structurally immune to catastrophic backtracking, plus pattern-length/input-length/timeout limits as defense in depth    |
|**Dashboard**         |Built-in web UI at `/dashboard` — live alert feed, severity breakdown, one-click acknowledge, no separate frontend to deploy                        |
|**Notifications**     |Discord webhook, Slack webhook, Telegram, Email (SMTP) — each with independent minimum-severity thresholds                                          |
|**M365 posture**      |Read-only Microsoft Graph collector: security alerts, risky sign-ins — write scopes are rejected at startup                                         |
|**Auth**              |Built-in JWT access/refresh tokens, bcrypt password hashing, 2-role RBAC (`admin`/`viewer`), per-IP and per-username rate limiting on auth endpoints|
|**Compliance exports**|CSV export of alerts and audit log, JSON SLA/MTTR summary report                                                                                    |
|**Ops**               |Structured JSON logging with automatic secret redaction, graceful shutdown, health/readiness probes, Docker Compose one-command deploy              |

**Design principle:** every external feed source is treated as adversarial input; only the CyberNom process and its configuration are trusted. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full breakdown, including the seven threat classes this build defends against (ReDoS, missing auth, secrets at rest, SSRF via redirects, Graph least-privilege, onion→clearnet leakage, and injection).

-----

## Installation

### Native (recommended)

Requires Go 1.22+ and a Postgres 16+ instance.

```bash
git clone https://github.com/Hayder-Rzaigui/cybernom-community.git
cd cybernom-community
go mod tidy
go mod download

psql "postgres://cybernom:yourpassword@localhost:5432/cybernom" -f migrations/0001_init.sql
psql "postgres://cybernom:yourpassword@localhost:5432/cybernom" -f migrations/0002_dashboard_metrics.sql
psql "postgres://cybernom:yourpassword@localhost:5432/cybernom" -f migrations/0003_feeds.sql

cp config/config.yaml.example config/config.yaml
export CYBERNOM_DB_PASSWORD="yourpassword"
export CYBERNOM_JWT_SIGNING_KEY="$(openssl rand -hex 32)"

go build -o bin/cybernom ./cmd/cybernom
./bin/cybernom -config config/config.yaml -log-pretty
```

No build tags needed — a plain `go build` always produces the Community binary.

### Docker

```bash
git clone https://github.com/Hayder-Rzaigui/cybernom-community.git
cd cybernom-community

# 1. Configure secrets
cp .env.example .env
# edit .env — set CYBERNOM_JWT_SIGNING_KEY (openssl rand -hex 32) and CYBERNOM_DB_PASSWORD

mkdir -p secrets
echo -n "your-db-password-here" > secrets/db_password.txt

# 2. Configure feeds/keywords/notifications
cp config/config.yaml.example config/config.yaml
# edit config/config.yaml to taste

# 3. Bring up the stack (Postgres, Tor, CyberNom, nginx reverse proxy)
cd deployments
docker compose --env-file ../.env up -d --build

# 4. Verify
curl -k https://localhost:8443/healthz
```

### Creating your first admin user

```bash
./bin/cybernom -config config/config.yaml -init-admin
```

-----

## Dashboard

<!-- Tip: scripts/seed_demo_data.sql populates a realistic-looking alert set (spread across 7 days, healthy SLA compliance) for exactly this kind of screenshot — see the script header for usage. -->

Open **`http://<listen_address>/dashboard`** (or `https://localhost:8443/dashboard` behind the bundled nginx proxy):

- Sign in with any account created via `POST /api/v1/users`
- Live-updating table of triggered alerts, refreshed every 20 seconds
- Filter by severity, one-click **Acknowledge**
- Connection indicator shows whether the dashboard is reaching the API

-----

## Configuration

CyberNom reads structural configuration from `config/config.yaml` and **all secrets from environment variables** — no secret ever belongs in the YAML file. See [`config/config.yaml.example`](config/config.yaml.example) and [`.env.example`](.env.example) for the full reference.

-----

## API Overview

|Method     |Path                                                       |Role         |Purpose                                     |
|-----------|-----------------------------------------------------------|-------------|--------------------------------------------|
|GET        |`/dashboard`                                               |—            |Web UI for browsing and acknowledging alerts|
|POST       |`/api/v1/auth/login`                                       |—            |Exchange username/password for a token pair |
|GET        |`/api/v1/alerts`                                           |admin, viewer|List triggered keyword alerts               |
|POST       |`/api/v1/alerts/{id}/ack` | `/resolve`                     |admin, viewer|Triage an alert                             |
|GET        |`/api/v1/dashboard-metrics`                                |admin, viewer|Aggregate widget data                       |
|GET        |`/api/v1/export/alerts.csv` | `/audit.csv` | `/report.json`|admin, viewer|Compliance exports                          |
|GET        |`/api/v1/graph/security-alerts` | `/risky-signins`         |admin, viewer|M365 posture data                           |
|POST       |`/api/v1/users`                                            |admin        |Create a user                               |
|POST/DELETE|`/api/v1/feeds`                                            |admin        |Manage threat feeds                         |
|GET        |`/api/v1/audit`                                            |admin, viewer|Audit log                                   |

-----

## Threat Model

Full document: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

-----

## Community vs. Enterprise

CyberNom Community is a complete, production-capable platform on its own. **CyberNom Enterprise** builds on the exact same core and adds the features SOC teams ask for once they’re running this at scale across a real security team, with real compliance obligations:

|Feature                                                           |Community                |Enterprise                                                                                                                                                                                                                                                                     |
|------------------------------------------------------------------|:-----------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|Core ingestion (RSS/JSON/website/`.onion`), regex/keyword alerting|✅                        |✅                                                                                                                                                                                                                                                                              |
|Built-in dashboard, JWT auth, bcrypt, rate limiting               |✅                        |✅                                                                                                                                                                                                                                                                              |
|Discord / Slack / Telegram / Email notifications                  |✅                        |✅                                                                                                                                                                                                                                                                              |
|Microsoft Graph posture collector (read-only)                     |✅                        |✅                                                                                                                                                                                                                                                                              |
|Compliance exports (CSV / SLA-MTTR report)                        |✅                        |✅                                                                                                                                                                                                                                                                              |
|Role model                                                        |2 roles (Admin, Viewer)  |**4-tier RBAC** — Admin, SOC Tier 1, SOC Tier 2, Compliance Auditor                                                                                                                                                                                                            |
|Feed management granularity                                       |Admin only               |SOC Tier 2 can toggle feeds; Admin retains create/delete                                                                                                                                                                                                                       |
|**STIX/TAXII 2.1 feed ingestion**                                 |❌                        |✅ Poll any TAXII 2.1 collection (bearer or basic auth) straight into the same alert pipeline as RSS/JSON/website sources. Cursor-based polling designed to never silently drop data on a failed fetch. *Built and code-reviewed; not yet verified against a live TAXII server.*|
|**Automatic IOC extraction**                                      |❌                        |✅ IPs, domains, and file hashes pulled from every alert, deduplicated into a shared catalog, enriched via VirusTotal + AbuseIPDB                                                                                                                                               |
|**Alert clustering / Incidents**                                  |❌                        |✅ Related alerts (same CVE, or high title/snippet similarity) auto-group into a single Incident with full audit trail of every constituent alert                                                                                                                               |
|**SIEM / Syslog forwarding**                                      |❌                        |✅ RFC 5424 syslog + Splunk / Sentinel / generic webhook, wired into every verified alert                                                                                                                                                                                       |
|**Encrypted secrets vault**                                       |❌                        |✅ AES-256-GCM at-rest encryption for SIEM credentials and integration tokens                                                                                                                                                                                                   |
|Visual Regex Builder (IOC playground)                             |❌                        |✅                                                                                                                                                                                                                                                                              |
|Dashboard Incidents & IOCs tabs                                   |❌                        |✅ Dedicated views for triaging clustered incidents and browsing the extracted-IOC catalog with reputation status                                                                                                                                                               |
|SOC UX (dark/light theme, audible critical-alert chime)           |❌                        |✅                                                                                                                                                                                                                                                                              |
|Support                                                           |Community (GitHub issues)|Commercial support & SLA                                                                                                                                                                                                                                                       |
|License                                                           |MIT, free forever        |Commercial license                                                                                                                                                                                                                                                             |

Full technical detail on every Enterprise feature — endpoints, env vars, migrations, exact RBAC scoping — lives in `ENTERPRISE.md` inside the Enterprise Edition package.

-----

## 🔒 CyberNom Enterprise

**CyberNom Enterprise is commercially available** for SOC teams and organizations that need granular RBAC, outbound SIEM integration, and an encrypted secrets vault on top of everything in Community — plus STIX/TAXII feed ingestion, automatic IOC extraction with reputation enrichment, and alert clustering into Incidents.

It’s built for teams who need to:

- Route verified alerts straight into Splunk, Microsoft Sentinel, or any generic SIEM/webhook endpoint
- Pull structured threat intel directly from any STIX/TAXII 2.1 collection, alongside RSS/JSON/website sources
- Automatically extract, deduplicate, and enrich IOCs (IPs, domains, hashes) across every alert via VirusTotal and AbuseIPDB
- Cut through alert fatigue by auto-clustering related alerts (shared CVE or high text similarity) into a single Incident with full drill-down audit trail
- Segment access across SOC Tier 1/2 analysts, admins, and compliance auditors instead of a flat admin/viewer split
- Keep integration credentials encrypted at rest rather than in plaintext config
- Get commercial support with an SLA instead of best-effort community issues

**Interested in a commercial license or volume pricing?**

📧 **[hayder.rzaiguii@gmail.com](mailto:hayder.rzaiguii@gmail.com)**

When reaching out, include your team size and which Enterprise feature (SIEM forwarding, RBAC tiers, secrets vault, TAXII ingestion, IOC enrichment, alert clustering) is the priority — it helps us scope the right license tier and get back to you with pricing quickly.

-----

## License

MIT — see [`LICENSE`](LICENSE). Copyright © 2026 Hayder Rzaigui.

CyberNom Enterprise is a separate commercial product built on top of this codebase; see the comparison table above. Enterprise source is licensed separately and is not distributed under this MIT license.