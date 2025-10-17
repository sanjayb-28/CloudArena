# CloudArena

CloudArena is a modular platform for orchestrating agentic security exercises inside a fully managed AWS sandbox. The project combines infrastructure automation (Terraform), Python-based planning and execution bots, curated ATT&CK-based content, and automated reporting to help teams practice cloud defense safely.

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
- `tests/` – Automated test suites covering infrastructure modules and application logic.

## Getting Started

1. Install prerequisites (Terraform, Python 3.11+, Docker) and authenticate with AWS and Auth0.
2. Copy environment templates (to be added) and configure credentials for the sandbox.
3. Use the forthcoming `make` targets or Terraform wrappers to bootstrap the infrastructure and supporting services.
4. Launch the application workers to begin planning, executing, and reporting on cloud security scenarios.

## Contributing

Community contributions are welcome. See `CONTRIBUTING.md` for guidelines on filing issues, proposing enhancements, and submitting patches. All contributors are expected to adhere to the `CODE_OF_CONDUCT.md`.

## License

CloudArena is licensed under the Apache License, Version 2.0. See `LICENSE` for the full text.
