# Development

## Checks

Run commands from this repository's root. Install `uv` and GNU Make; use the Python version selected by [`.python-version`](../../.python-version). [`pyproject.toml`](../../pyproject.toml) defines the supported Python range and dependencies, and [`uv.lock`](../../uv.lock) locks them.

```bash
uv sync --frozen
make check
```

[`Makefile`](../../Makefile) checks the lockfile, Ruff lint and formatting, `ty` types, pytest, and an sdist/wheel build in a temporary directory. `make test` runs pytest alone. `make build` builds the local Docker image and requires Docker.

The normal tests use in-memory SQLite and mocked Keycloak calls; no running Keycloak or PostgreSQL is required. `tests/test_api_keys.py` contains an opt-in PostgreSQL concurrency test selected by `BRIDGE_TEST_POSTGRES_URL`. That test requires an empty disposable local database and drops its bridge tables afterward. Leave this variable unset for checks that must not access a database. SQLite is a test-only override, not a service storage option.

## Local service

The service needs PostgreSQL and a separately configured development Keycloak realm with the [required clients and permissions](../operations/README.md#keycloak-prerequisites). The supplied [`compose.yaml`](../../compose.yaml) starts only a temporary PostgreSQL server; its data directory uses tmpfs.

From the repository root, start the local database with a development-only password:

```bash
read -r -s -p 'Local database password: ' BRIDGE_DEV_POSTGRES_PASSWORD
export BRIDGE_DEV_POSTGRES_PASSWORD
docker compose up -d --wait postgres
export KEYCLOAK_API_KEY_BRIDGE_POSTGRES_HOST=127.0.0.1
export KEYCLOAK_API_KEY_BRIDGE_POSTGRES_PORT=55432
export KEYCLOAK_API_KEY_BRIDGE_POSTGRES_PASSWORD="$BRIDGE_DEV_POSTGRES_PASSWORD"
```

Export the five required Keycloak settings listed in [operations](../operations/README.md#settings) for the development realm, including its bridge-client secret. [`.env.example`](../../.env.example) names most settings, but `Settings` does not load a `.env` file automatically. The default database and user match Compose.

Initialize this disposable database, then start the server:

```bash
uv run --frozen keycloak-api-key-bridge-init-db
uv run --frozen keycloak-api-key-bridge
```

In another terminal, `curl --fail http://127.0.0.1:8000/live` checks the process and `curl --fail http://127.0.0.1:8000/health` checks database and Keycloak readiness. Interactive API documentation is disabled; endpoint behavior is described in [architecture](../architecture/README.md#http-surface). Stop the service with Ctrl-C and use `docker compose down` from the repository root to remove the disposable database container.

## Image publication

[`Dockerfile`](../../Dockerfile) installs frozen production dependencies and runs the service as a non-root user. The [workflow](../../.github/workflows/build-push.yaml) runs `make check` on pull requests, `main`, and release tags. Approved `vX.Y.Z` tags must match the package and lockfile versions, checked by [`scripts/verify_release_tag.py`](../../scripts/verify_release_tag.py); tag workflows publish a Linux amd64 image and a GitHub Release containing its digest. Publishing an image does not update the Base chart's image pin or adopt it for a client. Follow the shared [image-release procedure](https://github.com/neurwerk/docs/blob/main/dev/operations/image-releases.md).
