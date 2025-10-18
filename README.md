# CloudArena

CloudArena is a modular platform for orchestrating agentic security exercises inside a fully managed AWS sandbox. The project combines Python-based planning and execution bots, curated ATT&CK-based content, and automated reporting to help teams practice cloud defense safely.

## Project Goals

- Spin up ephemeral AWS environments that mirror production-like stacks without risking real assets.
- Drive scenario execution through adaptive Python agents that evaluate the environment and select safe simulation actions.
- Map detections, attacker behaviors, and defensive gaps to MITRE ATT&CK techniques.
- Produce human-friendly remediation reports backed by Gemini-generated narratives.
- Integrate Auth0 for authentication, with optional Snowflake telemetry storage and DigitalOcean Gradient™ LLM fallback tracks.

## Repository Layout

- `aws/terraform/` – Terraform modules and stacks that provision and tear down the AWS sandbox.
- `app/` – Python application layer orchestrating agents, planners, adapters, ingestion, reporting, and UI routes.
- `catalog/` – ATT&CK technique definitions and remediation guidance referenced by the planner and reporters.
- `docker/` – Container definitions and local development helpers.
- `docs/` – Living product overview and operational notes (see `docs/PROJECT_OVERVIEW.md`).

## Getting Started

1. Install prerequisites (Python 3.11+, Docker) and authenticate the CLI with the AWS sandbox account defined in `ARENA_ACCOUNT_ID`.
2. Populate `.env` with Auth0 configuration (`AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_CALLBACK_URL`, `SESSION_SECRET`) and generate a strong `AUTH_TOKEN` value for the worker to use when posting events.
3. Build and launch the stack with `docker compose up --build`. The worker image bootstraps the Stratus CLI during build, so the first build requires outbound internet access.
4. Browse to `http://localhost:8000/ui`, authenticate via Auth0, create a run, and observe the event stream and generated report.
5. Consult `docs/PROJECT_OVERVIEW.md` for deeper architecture details, operational guidance, and the current roadmap.

Auth0 setup cheat sheet: create a Regular Web Application, add `http://localhost:8000/auth/callback` to its allowed callbacks, create/verify an API with Identifier `https://cloudarena.api` (or your chosen audience), and copy the app’s client ID/secret into `.env`. No machine-to-machine client is required—the worker authenticates with the static `AUTH_TOKEN`.

## Contributing

Community contributions are welcome. See `CONTRIBUTING.md` for guidelines on filing issues, proposing enhancements, and submitting patches. All contributors are expected to adhere to the `CODE_OF_CONDUCT.md`.

## License

CloudArena is licensed under the Apache License, Version 2.0. See `LICENSE` for the full text.
