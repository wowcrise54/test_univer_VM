# Project agent instructions

## Mandatory skill restriction

- For every task in this repository, use **only** the `graphify` skill.
- Do not invoke, read, or apply any other skill, even if another skill would normally be mandatory or recommended.
- Use the existing `graphify-out/graph.json` as the first source for questions about the codebase.
- Run `graphify query`, `graphify path`, or `graphify explain` before broad manual exploration when the graph can answer the question.
- If Graphify does not contain enough evidence, inspect the relevant source files directly and state that the graph was insufficient.
- Do not rebuild or update the graph unless the user explicitly requests it.

## Subagents

Reusable project subagent profiles live in `.agents/` as TOML files. Each profile declares its own model, reasoning effort, scope, and instructions:

- `backend.toml` — `gpt-5.6-sol`, FastAPI endpoints, services, schemas, background jobs, MP VM integration.
- `frontend.toml` — `gpt-5.6-terra`, React UI, routes, state, accessibility, and API integration.
- `tests.toml` — `gpt-5.6-terra`, pytest, Vitest, Playwright, regression coverage, and test diagnostics.
- `database.toml` — `gpt-5.6-sol`, PostgreSQL schema, migrations, queries, persistence, and transaction safety.
- `docker-infrastructure.toml` — `gpt-5.6-terra`, Docker Compose, runtime configuration, networking, and deployment diagnostics.
- `security-review.toml` — `gpt-5.6-sol`, authentication, RBAC, validation, secret handling, and security review.
- `code-review.toml` — `gpt-5.6-sol`, evidence-led review for correctness, regressions, and maintainability.
- `investigator.toml` — `gpt-5.6-sol`, read-only tracing, root-cause investigation, and architecture discovery.
- `documentation.toml` — `gpt-5.6-luna`, README, runbooks, API contracts, and operator documentation.

## Delegation rules

- The root agent remains responsible for integration, final verification, and the final user-facing report.
- Delegate only concrete, bounded work that matches a profile.
- A subagent must read this file and its assigned profile before acting.
- A subagent must also obey the mandatory restriction to use only `graphify`.
- Do not assign overlapping write scopes to agents running concurrently.
- At most seven subagents may run concurrently in this environment; use additional batches when needed.
- Prefer read-only investigation before edits. Preserve unrelated user changes.
- Do not create commits, branches, pull requests, or destructive changes unless the user explicitly requests them.
- Report exact files changed and verification commands run. Never claim a test passed without current command output.

## Project boundaries

- Backend entry points and orchestration are primarily under `app/`, including `app/main.py`, `app/db.py`, `app/api/schemas.py`, and `app/services/`.
- Frontend code is under `src/`; preserve existing routes, RBAC, accessibility, responsive behavior, and API contracts.
- Backend tests are under `tests/`; frontend and browser tests follow the scripts declared in `package.json`.
- Database work must preserve PostgreSQL parameter typing, transaction boundaries, migrations, and existing persisted-data compatibility.
- Docker work must preserve the intended host/container connectivity model and must not expose credentials in logs or committed files.
- Treat scan, postprocess, asset-card, vulnerability, and remediation workflows as operator-critical paths.
