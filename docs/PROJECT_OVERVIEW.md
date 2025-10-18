# CloudArena Project Overview

This document captures the current architecture, feature set, and outstanding work for the CloudArena prototype. Treat it as the authoritative snapshot for future iterations or AI-assisted development.

## 1. Product Vision

CloudArena aims to orchestrate guided cloud security exercises against an AWS sandbox. Operators trigger “runs” from a lightweight dashboard; the system gathers environment facts, determines safe techniques to execute (Stratus simulations and SDK-based audits), runs them through Celery workers, and aggregates telemetry into human-readable reports.

Key objectives:

- **Experience** – provide a turnkey UI and API for launching attack simulations and viewing results.
- **Safety** – restrict techniques to read-only audits or controlled Stratus detonations inside a managed sandbox.
- **Insight** – map findings to MITRE ATT&CK content and produce remediation-focused reports.
- **Extensibility** – allow new techniques and adapters to be onboarded via catalog YAML.

## 2. Runtime Architecture

```
+-----------------------+      +-------------------------+
|   FastAPI Application |      |       Celery Worker     |
|-----------------------|      |-------------------------|
| - Routes (REST + UI)  |      | - execute_runbook task  |
| - Auth (Auth0 + JWT)  | ---> | - Timeout enforcement   |
| - Report rendering    |      | - SDK/Stratus adapters  |
| - Run/fact planning   |      +-------------------------+
| - SQLite persistence  |
+-----------------------+
           ^
           |
           v
+-----------------------+
|      Redis Broker     |
+-----------------------+

Supporting assets: Stratus CLI, AWS credentials, Auth0 tenant, catalog definitions, SQLite database.
```

## 3. Configuration Surface

Configuration is managed with `pydantic-settings` in `app/settings.py`. Important fields (all sourced from `.env` or environment variables):

| Setting | Purpose |
|---------|---------|
| `ENV`, `REGION`, `ARENA_ACCOUNT_ID` | Project mode and allowed AWS account/region. |
| `DATABASE_URL` | SQLite path; using `/data` when running in Docker. |
| `AUTH_TOKEN` | Static bearer token for internal API calls (still honored for tests and automation). |
| `AUTH0_*` (issuer, audience, domain, JWKS, client id/secret, callback) | Auth0 integration for API validation and UI login. |
| `SESSION_SECRET`, `SESSION_COOKIE_*` | Cookie signing for UI sessions. |
| `AWS_PROFILE` | Host profile mapped into containers for boto3. |
| `API_BASE_URL` | Where workers post run events (defaults to `http://api:8000`). |
| `CELERY_RESULT_BACKEND`, `REDIS_URL` | Celery connectivity. |
| `GEMINI_API_KEY` | Optional LLM summarizer for reports. |

The `.env` file currently contains real-looking Auth0 secrets; rotate or replace before sharing.

## 4. Core Modules and Responsibilities

### 4.1 Entry Points
- `app/main.py` – creates the FastAPI app, wires routers, and initializes the SQLite database.
- `docker-compose.yml` – runs three services: `redis`, `api` (FastAPI under Uvicorn), and `worker` (Celery worker).
- `docker/Dockerfile.api`, `docker/Dockerfile.worker` – install dependencies and copy the `app` package.

### 4.2 Authentication (`app/auth.py`, `app/routes/auth_ui.py`)
- Validates access tokens via Auth0 JWKS.
- Retains support for static bearer tokens (`AUTH_TOKEN` or the legacy `"changeme-internal-token"`).
- Implements session cookie management for browser UI, with `/login`, `/auth/callback`, and `/logout` handlers (`app/routes/auth_ui.py`) that perform Auth0’s authorization-code flow and store `sub`, `name`, `email` in the session.
- Provides `require_auth` dependency used by all protected endpoints.

### 4.3 Planner (`app/planner/planner.py`, `app/planner/schema.py`, `catalog/techniques/*`)
- Loads YAML technique specs (id, requirements, severity, adapter mapping).
- Constructs runbooks by checking catalog requirements against gathered facts.
- Currently prioritizes Stratus S3 simulations followed by SDK audits for S3 policies, EC2 security groups, IAM key age, KMS rotation, IAM enum, and ECR enum.

### 4.4 Fact Gathering (`app/routes/facts.py`)
- Uses boto3 to fetch AWS account ID, active region, S3 bucket access posture, and service capability flags (IAM, EC2, KMS, ECR).
- Called during run creation when the client does not supply facts explicitly.
- Returns JSON consumed both by planner and reporting.

### 4.5 Persistent Store (`app/store.py`)
- Wraps SQLite access via two tables: `runs` and `events`.
- Inserts the runbook JSON and event payloads, handles JSON encoding/decoding, and ensures schema creation (WAL mode).

### 4.6 Workers (`app/workers/tasks.py`, `app/workers/celery_app.py`)
- `execute_runbook` Celery task iterates through runbook steps, posts lifecycle events (`queued`, `running`, `ok`, `error`), and captures artifacts (stdout logs, CloudTrail URIs, finding counts).
- `_step_timeout` enforces per-step timeouts using `SIGALRM` when available; automatically disables itself when invoked off the main thread (e.g., Celery eager mode/tests).
- Integrates adapters:
  - SDK adapter (`app/adapters/sdk.py`): boto3-based checks for IAM roles, ECR repositories, EC2 security groups, KMS rotation, IAM key age, and S3 public policies.
  - Stratus adapter (`app/adapters/stratus.py`): shells out to the `stratus` CLI using `catalog/techniques_map.yaml`.
- `_post_event` pushes events back to the API using `API_BASE_URL`.
- `get_bearer_token` fetches Auth0 client-credential tokens for worker-to-API communication or falls back to `AUTH_TOKEN`.

### 4.7 Routes & UI
- `app/routes/runs.py` – validates AWS identity/region, triggers planner, persists run, schedules `execute_runbook`, and seeds an initial `run.created` event.
- `app/routes/events.py` – accepts event ingestion (`POST /events`) and exposes list view (`GET /events/{run_id}`) used by API clients and HTMX.
- `app/routes/reports.py` – builds markdown reports by combining event stream and facts via `app/reporter/reporter.py`.
- `app/routes/ui.py` – HTMX-driven operator interface (dashboard, run detail, report generation) requiring authentication.
- `app/routes/health.py`, `app/routes/auth_test.py` – health check and auth test endpoints.
- Templates (`app/templates/*.html`) – base layout, dashboard, run detail, events partial (auto-refresh via HTMX).

### 4.8 Reporting (`app/reporter/reporter.py`)
- Aggregates run-step events, ranks severities, formats findings into markdown tables, summarizes S3 inventory, and lists top risks. Optional Gemini integration rewrites narrative sections when `GEMINI_API_KEY` is set.

### 4.9 Tests (`tests/`)
- Unit tests cover planner ordering, SDK audits, facts detection, reporter output, and Gemini fallback.
- Integration tests validate Auth0 token acquisition, run flow (with monkeypatched adapters/events), and event route responses.
- Fixtures (`tests/conftest.py`, `tests/integration/conftest.py`) configure SQLite temp databases, Celery eager mode, and injected environment values.

## 5. Execution Flow (End-to-End)

1. **User login**: Visiting `/ui` redirects to `/login`. Auth0 authenticates the user and redirects back to `/auth/callback`, which exchanges the code for tokens, retrieves profile data, and drops a signed session cookie.
2. **Run creation**: From the UI (or via API `POST /runs`), the server:
   - Ensures the caller’s AWS account and region match configured expectations using `sts.get_caller_identity`.
   - Gathers facts (unless supplied).
   - Builds a runbook using planner logic and catalog requirements.
   - Stores the run and enqueues `execute_runbook` in Celery.
   - Emits a `run.created` event for UI consistency.
3. **Task execution**: Celery worker processes the runbook:
   - Posts `queued` and `running` events for each step.
   - Executes Stratus or SDK techniques with timeout guardrails.
   - Captures stdout and derived artifacts (finding counts, CloudTrail URIs).
   - Posts `ok` or `error` events containing summaries, severities, findings, and details.
4. **Event streaming**: UI polls `/events/{run_id}` via HTMX every two seconds, rendering the new events table.
5. **Reporting**: User requests a report (`POST /reports/{run_id}` or UI button), triggering facts retrieval (if needed) and rendering markdown summarizing the run.

## 6. API Summary

| Method & Path | Auth | Description |
|---------------|------|-------------|
| `GET /healthz` | None | Liveness probe. |
| `GET /auth/test` | Auth | Echoes the subject, used for debugging. |
| `POST /runs` | Auth | Creates a run, gathers facts, plans runbook, schedules execution. |
| `GET /events/{run_id}` | Auth | Returns event stream (JSON or HTML fragment for HTMX). |
| `POST /events` | Auth | Worker ingestion endpoint for step/run events. |
| `POST /reports/{run_id}` | Auth | Generates markdown report. |
| `GET /facts` | Auth | Returns gathered AWS facts (mostly for debugging/testing). |
| `GET /ui` | Auth | Dashboard. |
| `POST /ui/runs` | Auth | Create run from UI form. |
| `GET /ui/runs/{run_id}` | Auth | Run detail view with live event feed. |
| `POST /ui/runs/{run_id}/reports` | Auth | Render report inside UI. |
| `GET /login`, `/auth/callback`, `/logout` | Public entrypoints for Auth0 browser flow. |

## 7. Current Limitations & Outstanding Work

1. **Sandbox isolation**
   - Needs LocalStack or mocked AWS resources for fully self-contained demos.
   - Stratus CLI is not bundled in the worker container; Stratus techniques currently fail unless installed manually.
2. **Auth zero-trust posture**
   - `/logout` only clears the local session. Optionally redirect to Auth0 logout endpoint to terminate IdP session.
   - No role-based access control; everything post-auth is permitted.
3. **Telemetry & observability**
   - No metrics (Prometheus) or structured logging pipeline beyond Python logging.
   - Event ingestion lacks deduplication or idempotency safeguards.
4. **UI polish**
   - HTMX polling lacks progress indicators, error states, or manual refresh controls.
   - Markdown report is displayed raw; consider Markdown-to-HTML conversion or PDF export.
5. **Resilience**
   - `_post_event` currently raises on HTTP failures without retries or dead-letter handling.
   - Celery task lacks retry/backoff for transient AWS or network errors.
6. **Catalog evolution**
   - Planner uses static ordering and limited requirement checks. No goal-based prioritization or risk scoring beyond severity heuristics.
7. **Secrets management**
   - `.env` is committed with placeholder secrets. Need to adopt `.env.example` and pull actual secrets from a vault or CI system.
8. **Testing gaps**
   - No end-to-end test covering the Auth0 UI login flow.
   - Missing contract tests for Stratus adapter path (currently stubbed in integration tests).
9. **Infrastructure automation**
   - README references Terraform modules but none are present in the repo snapshot.
   - Need deployment scripts for packaging Docker images and provisioning cloud resources.

## 8. Roadmap Suggestions for Full E2E Flow

1. **Self-contained AWS simulation**
   - Introduce LocalStack to docker-compose for IAM, S3, EC2, KMS, ECR endpoints.
   - Seed data representing public buckets, stale IAM keys, etc., so techniques produce realistic findings.
   - Update `gather_facts` and SDK adapter to point at LocalStack endpoints when running locally.
2. **Stratus integration**
   - Extend worker Dockerfile to install the Stratus CLI and its dependencies.
   - Expand `catalog/techniques_map.yaml` to cover more Stratus simulations.
   - Handle Stratus artifacts (JSON output, cleanup logs) in worker events.
3. **UI improvements**
   - Convert Markdown reports to rendered HTML (e.g., `markdown2`).
   - Add run status badges, filtering, and historical insight.
   - Provide in-UI configuration hints (auth token, AWS profile) for operators.
4. **Security hardening**
   - Implement RBAC (e.g., admin vs. read-only roles derived from Auth0 claims).
   - Force HTTPS in production, set `SESSION_COOKIE_SECURE=1`, and tighten same-site policy if cross-domain flows are introduced.
   - Integrate Auth0 logout redirect to fully terminate sessions.
5. **Operational maturity**
   - Add structured logging (JSON), correlation IDs for run events, and metrics (Celery task duration, planner latency).
   - Introduce background job to purge stale runs/events or archive to long-term storage.
6. **Developer tooling**
   - Provide `make` targets or scripts for `docker compose up/down`, database resets, and running selective test suites.
   - Document how to provision Auth0 application settings and rotate secrets.
7. **Content expansion**
   - Add more technique YAMLs with richer metadata (remediation guidance, estimated duration, dependencies).
   - Implement planner predicates (e.g., only run KMS rotation audit when kms service flag is true **and** keys exist).

## 9. Reference Checklist for Contributors/AI Agents

- [ ] Update `.env.example` and document required secrets.
- [ ] Ensure worker images bundle Stratus CLI and handle failure modes gracefully.
- [ ] Integrate LocalStack or other simulation to run “attacks” entirely inside Docker.
- [ ] Add Auth0 logout redirect and optionally refresh token rotation.
- [ ] Improve reporting presentation and consider PDF/HTML export.
- [ ] Enrich planner logic with goals weighting and dependency ordering.
- [ ] Add end-to-end tests covering Auth0 session cookies and full run lifecycle.
- [ ] Design structured telemetry (logs, metrics) and configure for both local and production deployment.

Keep this document updated as modules evolve so automated assistants and new contributors can quickly understand the system’s state and priorities.

