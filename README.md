# Vulnora — Security Intelligence Platform

> A real-data, evidence-first foundation for managing software-supply-chain vulnerabilities across a company portfolio. This repository is an early **functional release**, **not** an audited enterprise product.

## What works

- Account creation, password sign-in, HMAC-signed HTTP-only sessions, rate-limited failed logins.
- Workspace creation, tenant-scoped project and finding queries, server-enforced member roles.
- Public GitHub repository discovery via GitHub SPDX SBOM, with npm/Composer root lockfile fallbacks.
- Manual project creation and upload of npm, Composer, pnpm, Yarn v1 lockfiles and SPDX/CycloneDX JSON.
- Exact ecosystem/version matching using live OSV `/v1/querybatch`, followed by advisory-detail lookups.
- CISA KEV and FIRST EPSS best-effort enrichment; explanatory risk prioritization and honest Unknown states.
- Idempotent findings, audit events, per-project scan history, manual status updates, members, test evidence, comments, release records and CSV exports.
- Persian RTL and English LTR dashboard, responsive desktop/mobile layout, light/dark mode.
- Daily cron-worker endpoint with bearer authentication and a queue database table.

## Known gaps (do not treat as implemented)

- **Private GitHub**: GitHub App configuration, installation OAuth flow, private-repository access and Dependabot integration are not yet implemented. Public repositories only.
- **All ecosystems**: Python/Go/Java/.NET, nested monorepo lockfiles, pnpm peer dependency graph, Yarn Berry, dependency graph edges, and Docker are future work.
- **Production deployment versions**: manual release records are not verified against running environments.
- **Scan scale**: a scan caps at 200 packages; asynchronous Vercel `after()` still has a serverless duration limit, with a daily cron retry for stuck jobs. Use a real queue/worker for enterprise scan volume.
- **CVSS**: numerical CVSS parsing, reconciliation of conflicting advisories, complete vendor data/versions fixed, and NVD enrichment remain future work. Severity is Unknown if no label is provided by an authoritative record.
- **Operations**: production-grade password reset/email verification, invitation verification, password policy audit, MFA, enterprise SSO, robust Redis-based global rate limiting, CSP nonce, durable queue, scan retry backoff, full PDF reports, automatic patch PRs, and full E2E tests are not yet delivered.
- **Demo data**: none. Security views are empty until a real source is added and successfully scanned.

## Tech stack

Next.js 16.4.6 App Router, React 19.3.1, strict TypeScript, PostgreSQL (Neon-compatible) via `postgres`, Zod, OSV API, CISA KEV, FIRST EPSS, GitHub REST, Vitest. Native CSS design system with Lucide icons and bundled Vazirmatn/Inter font packages.

## Installation

```bash
cp .env.example .env.local
npm install
# Create a PostgreSQL database and execute db/001_init.sql and db/002_login_throttle.sql.
npm run dev
```

Set a random 64-character hex `SESSION_SECRET` and `CRON_SECRET`. Do not commit these secrets. `DATABASE_URL` must point to the dedicated database with TLS. Set `NEXT_PUBLIC_APP_URL` to the origin for documentation/reference only; origin validation uses the actual request host.

## How to use

1. Create an account and an isolated workspace.
2. Add a manual project or a public GitHub repository (`https://github.com/owner/repo`).
3. Upload a compatible SBOM/lockfile, or let a GitHub scan import SPDX dependencies.
4. Queue a scan. The server process invokes OSV for exact versions. Consult **Scan Center** to see success or errors.
5. Review findings and evidence. Risk reasons describe available signals; unknown or unverifiable facts are not invented.

### Security cautions

The repository never executes dependency files or commands downloaded from untrusted repositories. It does not automatically modify source code, open PRs, or upgrade packages. Source versions are not considered evidence of what is deployed to production. Cross-workspace access checks are enforced on each protected route. For production, review and harden rate limits, CSP, authentication and logs, then commission a security audit.

### Vercel

A daily Vercel cron is declared in `vercel.json`. Hobby is personal, non-commercial only and cannot run hourly scans; for paid/company use, choose an appropriate commercial plan and provision an external durable worker for jobs beyond serverless runtime limits. No paid service is provisioned by this project automatically.

## Tests

```bash
npm run lint
npm test
npm run build
```

**Do not claim a test passed unless its command has actually succeeded.** Integration tests need live external APIs and a throwaway database.

## Architecture

`src/lib/dependencies.ts` — pure parser and version-evidence normalization.

`src/lib/intelligence.ts` — discovery, OSV matching, enrichment, persistence, idempotent scan process.

`src/lib/risk.ts` — explainable prioritization and Unknown handling.

`src/lib/auth.ts` — session validation and tenant access checks.

`src/app/api/**` — validated, authenticated boundaries.

`src/components/**` — responsive product interface.

`db/**` — independently auditable SQL migrations.

## License

All rights reserved. Obtain permission before commercial redistribution.
