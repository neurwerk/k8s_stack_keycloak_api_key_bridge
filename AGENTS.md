# keycloak_api_key_bridge

REST API to create and manage API keys backed by SQLite, with Keycloak auth
verification. Minimal surface: no dashboard or deploy directory.

## What it does

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /live` | none | Dependency-independent liveness probe |
| `GET /health` | none | Readiness probe |
| `GET /me` | Bearer JWT | Authenticated user info |
| `GET /permissions` | Bearer JWT | Current AgentGateway permissions (self or `?user_id=` for `api-key-admin`) |
| `POST /api_keys` | Bearer JWT | Create API key (self or `target_user_id` JSON field for `api-key-admin`) |
| `POST /api_keys/{key_id}/revoke` | Bearer JWT | Revoke a key (admin may revoke any) |
| `GET /api_keys` | Bearer JWT | List active keys (self or via `?user_id=`) |
| `GET`/`POST /validate` | API key | Return a versioned authorization decision for AgentGateway |

Settings are via `KEYCLOAK_API_KEY_BRIDGE_*` env vars.

## Project structure

```
src/keycloak_api_key_bridge/
├── config/
│   ├── settings.py      # Pydantic BaseSettings (KEYCLOAK_API_KEY_BRIDGE_ prefix)
│   └── database.py      # SQLAlchemy ApiKey model + CRUD classmethods
├── lib/
│   ├── jwks.py          # Hot-refreshing JWKS cache for JWT validation
│   ├── keycloak.py      # Keycloak Admin client and live entitlements
│   └── permissions.py   # AgentGateway permission contract validation
├── controllers/
│   ├── health.py         # GET /live and dependency-aware GET /health
│   └── api_keys.py       # CRUD endpoints + /me + /validate
└── main.py               # FastAPI app factory + uvicorn entry point
```

## Local development

```bash
# Install dependencies
uv sync --frozen --dev

# Run linting
uv run --frozen ruff check .
uv run --frozen ruff format --check .

# Run type checking
uv run --frozen ty check

# Run tests (in-memory SQLite)
uv run --frozen pytest -v
```

All four checks (Ruff lint and format, ty, and pytest) should pass before committing.

## API-key contract

- `POST /api_keys` requires a non-empty explicit `permissions` grant and
  `expires_in_days` from 1 through 365. It never supplies a default expiry.
- The requested grant must be a subset of the target principal's current
  `resource_access.agentgateway.roles`. Validation intersects the immutable
  grant with those current permissions.
- `GET /permissions` returns exactly `{"permissions": [...]}` with sorted,
  valid current AgentGateway permissions. A caller may inspect another user only
  with the `api-key-admin` realm role.
- API keys support create, list, and revoke only. Grants and expiry cannot be
  changed or renewed.
- SQLite uses schema version 2. The chart provisions
  `auth-keycloak-api-key-bridge-v2-pvc`; an unversioned or incompatible manually
  attached database fails startup rather than being created over or migrated.

## Building and pushing

### Image

`ghcr.io/neurwerk/k8s-stack-keycloak-api-key-bridge` (GHCR).

### Releasing

1. Open a release issue and make the package and lockfile version changes on a
   dedicated branch.
2. Run `make check`, then open a pull request that links the release issue and
   records the results.
3. After required CI and review complete, obtain explicit authorization and
   squash-merge the pull request.
4. After separate release authorization, update local `main`, create the exact
   tag from the merged commit, and push only that tag:
   ```bash
   git switch main
   git pull --ff-only origin main
   git tag v0.x.x
   git push origin v0.x.x
   ```
5. GitHub Actions builds and pushes `:0.x.x` and `:0.x` AMD64 images to GHCR.
6. Update the image pin in `base/charts/keycloak-api-key-bridge/` through its
   own reviewed issue and pull request.

Do not push release preparation directly to `main`, combine the branch push
with the tag push, or treat merge authorization as release authorization.

### GitHub Actions

Only a `v*` tag builds and pushes the `linux/amd64` image. Branch pushes do not
publish images.

### Local build

```bash
docker build -t keycloak-api-key-bridge:local .
```

## Repository

`git@github.com:neurwerk/k8s_stack_keycloak_api_key_bridge.git`
