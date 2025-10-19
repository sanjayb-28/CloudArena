# CloudArena

CloudArena is a modular platform for orchestrating agentic security exercises inside a fully managed AWS sandbox. The project combines Python-based planning and execution bots, curated ATT&CK-based content, and automated reporting to help teams practice cloud defense safely and reproduce findings consistently.

## Project Goals

- Spin up ephemeral AWS environments that mirror production-like stacks without risking real assets.
- Drive scenario execution through adaptive Python agents that evaluate the environment and select safe simulation actions.
- Map detections, attacker behaviors, and defensive gaps to MITRE ATT&CK techniques.
- Produce human-friendly remediation reports backed by Gemini-generated narratives.
- Integrate Auth0 for authentication while keeping the stack lightweight (FastAPI, SQLite, Redis) so teams can demo without extra cloud services.
- Provide optional Gemini-powered summaries but fall back to deterministic Markdown output when no LLM key is configured.
- Capture and persist run artifacts locally so findings remain reviewable even after the hackathon environment is torn down.

## Repository Layout

- `aws/terraform/` – Terraform modules and stacks that provision and tear down the AWS sandbox.
- `app/` – Python application layer orchestrating agents, planners, adapters, ingestion, reporting, and UI routes.
- `catalog/` – ATT&CK technique definitions and remediation guidance referenced by the planner and reporters.
- `docker/` – Container definitions and local development helpers.
- `docs/` – Living product overview and operational notes (see `docs/PROJECT_OVERVIEW.md`).

## AWS Prerequisites

- Access to an AWS sandbox account that can be safely automated for detection exercises.
- An IAM principal (or AWS SSO profile) with permissions to create and destroy the resources defined in `aws/terraform/` (AdministratorAccess is easiest for local testing).
- A configured AWS CLI profile named `arena` (or align `AWS_PROFILE` in `.env`).

## Secret Management & Configuration

1. Copy `.env.example` to `.env` and fill in the values for your Auth0 tenant, Gemini API key, and generated worker `AUTH_TOKEN`. The example file is intentionally safe to commit; keep your populated `.env` out of version control.
2. For shared environments, store sensitive values in a secret manager (AWS Secrets Manager or SSM Parameter Store) and inject them at deploy time instead of relying on flat files.
3. Rotate `AUTH_TOKEN`, `SESSION_SECRET`, and Auth0 client credentials regularly, and revoke tokens when testing sessions are complete.
4. The optional `AUTH0_LOGOUT_REDIRECT_URL` controls where users land after Auth0 terminates their session; default is the dashboard.
5. Configure a remote Terraform state backend (e.g., S3 + DynamoDB) before collaborating; the repository no longer stores `terraform.tfstate` files.

## Getting Started

1. Install prerequisites (Python 3.11+, Docker) and authenticate the CLI with the AWS sandbox account defined above.
2. Build and launch the stack with `docker compose up --build`. The worker image bootstraps the Stratus CLI during build, so the first build requires outbound internet access.
3. Browse to `http://localhost:8000/ui`, authenticate via Auth0, create a run, and observe the event stream and generated report.
4. Consult `docs/PROJECT_OVERVIEW.md` for deeper architecture details, operational guidance, and the current roadmap.

Auth0 setup cheat sheet: create a Regular Web Application, add `http://localhost:8000/auth/callback` to its allowed callbacks, configure a logout URL (e.g., `http://localhost:8000/`), create/verify an API with Identifier `https://cloudarena.api` (or your chosen audience), and copy the app’s client ID/secret into `.env`. No machine-to-machine client is required—the worker authenticates with the static `AUTH_TOKEN`.

## Quick Demo Flow

- Clone the repo and copy `.env.example` to `.env`, filling in Auth0, `AUTH_TOKEN`, and AWS profile values.
- Run `docker compose up --build` with AWS sandbox credentials available.
- Visit `http://localhost:8000/ui`, authenticate, and start a run with a descriptive goal (e.g., “assess public s3 exposure”).
- Observe the UI timeline as SDK and Stratus results stream in, then generate the Markdown report for your team.
- When finished, use the **Clear Runs** button (or `POST /ui/runs/clear`) and run `terraform destroy` in `aws/terraform/` if you provisioned real resources.

## Contributing

Community contributions are welcome. See `CONTRIBUTING.md` for guidelines on filing issues, proposing enhancements, and submitting patches. All contributors are expected to adhere to the `CODE_OF_CONDUCT.md`.

## License

CloudArena is licensed under the Apache License, Version 2.0. See `LICENSE` for the full text.
