# Keycloak API Key Bridge

Keycloak API Key Bridge is a FastAPI service for issuing, revoking, and
validating API keys whose effective permissions remain bounded by live Keycloak
entitlements. It stores user-managed keys in PostgreSQL and returns a versioned
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
bearer authorization header. Validation failures retain their `detail` and also
return the message as `error.message` for OpenAI-compatible clients.

On successful validation, the internal `x-agentgateway-auth-context` response
header contains a compact version-1 JSON decision with `contract_version`,
`principal_id`, `permissions`, `groups`, and optional additive `credential_id`
and `credential_kind` fields. The credential kind is `user_api_key` or
`managed_api_key`. User-key IDs are their stored UUIDs; managed-key IDs in the
header are stable UUIDs derived from the validated managed grant's client ID and
key ID. The response body still contains the original managed grant ID. Neither
the header nor the body exposes the raw key. Failed validation has no context
header, and a context over 64 KiB fails closed with HTTP 503.

## Requirements

- Python 3.12
- [uv](https://docs.astral.sh/uv/)
- A dedicated `api_key_bridge` database and role on `postgres-operations`
- A Keycloak confidential client with permission to resolve live principal
  entitlements

## Configuration

All settings use the `KEYCLOAK_API_KEY_BRIDGE_` prefix. See
[`.env.example`](.env.example) for the complete non-secret example. The
Keycloak URL, realm, issuer, client ID, and client secret must all be configured
before the readiness check succeeds.

Production uses only PostgreSQL. Supply `POSTGRES_HOST`, `POSTGRES_PORT`,
`POSTGRES_DATABASE`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` with the common
`KEYCLOAK_API_KEY_BRIDGE_` prefix. The defaults for port, database, and role
are `5432`, `api_key_bridge`, and `api_key_bridge`. A password containing URL
punctuation works as-is; no URL encoding is needed. Store passwords and managed
key verifiers in a secret manager or Secret volume, never in Git.

`MANAGED_REGISTRATIONS` is a JSON array of objects with `grant_file` and
`verifier_file` paths (with the common prefix). It defaults to `[]`, so the
bridge can run without managed keys. Each grant keeps the version-2 format.
All listed files are reloaded on each validation request; unreadable or invalid
registrations fail validation closed. An empty verifier disables its registration
during rotation. Duplicate active verifier hashes also fail validation closed,
even for unrelated keys. Replace the old primary/secondary file settings with
this list when updating the chart and bridge image together.

Provision the dedicated role and empty database on `postgres-operations` before
starting the bridge, grant that role table/index creation rights in its own
database, and deliver the matching password to the bridge. Run
`keycloak-api-key-bridge-init-db` with these same settings before starting the
application (the chart runs it on each Pod start). It creates schema version 3
in an empty database or verifies the exact compatible schema on repeat runs.
Unknown or incompatible tables and versions fail without migration or replacement;
it will not import SQLite data. Service startup also rejects a missing or
incompatible schema. PostgreSQL access uses a
pool of at most five connections per process (two-second checkout timeout),
three-second connection timeout and up to three startup attempts. Each user-key
creation holds a PostgreSQL per-user transaction lock through the quota check
and insert, including when the user has no keys yet.

The chart must supply these environment variables, allow bridge egress to the
operations PostgreSQL Pod port `9712` (Service port `5432`), and allow ingress
from the bridge Pod. Remove the old SQLite PVC and `DATABASE_URL` setting from
the deployment contract. No SQLite database needs migration: there are no live
user keys. This repository does not provision PostgreSQL roles, Secrets, or
network policy.

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

Controller tests use isolated, in-memory SQLite fixtures. For the PostgreSQL
quota/concurrency and schema test, set `BRIDGE_TEST_POSTGRES_URL` to a fresh,
empty, disposable **local** `postgresql+psycopg://` database. The test drops its
tables afterward. This test is skipped when the variable is unset.

For a disposable local server, set `BRIDGE_DEV_POSTGRES_PASSWORD` in your shell
and run `docker compose up -d postgres`. Compose binds only `127.0.0.1:55432`
and stores data in temporary memory. Point the integration test at the empty
`api_key_bridge` database using `BRIDGE_TEST_POSTGRES_URL`; URL-encode special
password characters in this **test-only** URL. Run `docker compose down` when
finished. For normal service startup, use the separate `POSTGRES_*` settings
instead and run the bootstrap command first.

Run the service after exporting the required environment variables:

```bash
uv run --frozen keycloak-api-key-bridge
```

## Container

Build the locked production image locally:

```bash
docker build -t keycloak-api-key-bridge:local .
```

The container runs as an unprivileged user and listens on port `8000`.
Release images are published to
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
