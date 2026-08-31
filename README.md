# Keycloak API Key Bridge

Keycloak API Key Bridge is a FastAPI service for issuing, revoking, and
validating API keys whose effective permissions remain bounded by live Keycloak
entitlements. It stores user-managed keys in SQLite and returns a versioned
authorization decision for AgentGateway.

API keys are shown only when created. Stored credentials are hashed, grants are
immutable, and validation intersects each grant with the principal's current
`resource_access.agentgateway.roles` permissions.

## API

| Endpoint | Authentication | Purpose |
| --- | --- | --- |
| `GET /live` | None | Dependency-independent liveness check |
| `GET /health` | None | Database and Keycloak readiness check |
| `GET /me` | Keycloak bearer JWT | Current user identity |
| `GET /permissions` | Keycloak bearer JWT | Current AgentGateway permissions |
| `POST /api_keys` | Keycloak bearer JWT | Create an expiring API key |
| `GET /api_keys` | Keycloak bearer JWT | List active API keys |
| `POST /api_keys/{key_id}/revoke` | Keycloak bearer JWT | Revoke an API key |
| `GET /validate`, `POST /validate` | API key | Return an authorization decision |
| `GET /metrics` | None | Prometheus metrics |

Management JWTs must target the configured bridge client and use the configured
issuer. A user with the Keycloak realm role `api-key-admin` may manage another
user's keys. API keys can be supplied to `/validate` through `x-api-key` or a
bearer authorization header.

## Requirements

- Python 3.12
- [uv](https://docs.astral.sh/uv/)
- A Keycloak confidential client with permission to resolve live principal
  entitlements

## Configuration

All settings use the `KEYCLOAK_API_KEY_BRIDGE_` prefix. See
[`.env.example`](.env.example) for the complete non-secret example. The
Keycloak URL, realm, issuer, client ID, and client secret must all be configured
before the readiness check succeeds.

The default database is `sqlite:///data/api_keys.db`. Production credentials,
managed-key grants, and verifiers must come from a secret manager or secret
volume and must not be committed to the repository.

## Development

Install the locked development environment and run the quality checks:

```bash
uv sync --frozen --dev
uv lock --check
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen ty check
uv run --frozen pytest
uv build
```

Run the service after exporting the required environment variables:

```bash
uv run --frozen keycloak-api-key-bridge
```

## Container

Build the locked production image locally:

```bash
docker build -t keycloak-api-key-bridge:local .
```

The container runs as an unprivileged user, listens on port `8000`, and writes
SQLite data under `/app/data`. Release images are published to
`ghcr.io/neurwerk/k8s-stack-keycloak-api-key-bridge` only from explicit `v*`
Git tags.

The Dockerfile keeps version tags for readability and pins their OCI image
indexes by digest. When updating the Dockerfile frontend, uv, or Python image,
inspect the authoritative registry manifest and confirm that the selected index
contains a `linux/amd64` manifest before replacing both the version and digest:

```bash
docker buildx imagetools inspect docker/dockerfile:<version>
docker buildx imagetools inspect ghcr.io/astral-sh/uv:<version>
docker buildx imagetools inspect python:<version>-slim
docker build --check .
docker build --platform linux/amd64 -t keycloak-api-key-bridge:validation .
```

## Security

Review [SECURITY.md](SECURITY.md) before reporting a vulnerability. Do not put
credentials, API keys, JWTs, database files, or managed-key material in an
issue or pull request.

## License

This project is available under the [MIT License](LICENSE).
