# Operations

## Deployment ownership

The [Base bridge deployment](https://github.com/neurwerk/k8s_stack_base/blob/main/charts/keycloak-api-key-bridge/templates/deployment.yaml) supplies database and OIDC credentials through Secrets, runs the database initialization command before the service, and configures `/live` and `/health` probes. Its [values](https://github.com/neurwerk/k8s_stack_base/blob/main/charts/keycloak-api-key-bridge/values.yaml) own the image pin and deployment settings. Selected add-ons supply managed-key grant ConfigMaps and verifier Secrets through `authKeycloakApiKeyBridge.managedRegistrations`; Base registers none by default.

Use the selected platform revision for deployment decisions. Credential preparation belongs to the shared [OpenBao procedure](https://github.com/neurwerk/docs/blob/main/dev/operations/openbao.md), and adoption and recovery approval belong to the shared [upgrade procedure](https://github.com/neurwerk/docs/blob/main/dev/operations/upgrades.md).

## Keycloak prerequisites

Configure the realm's reachable server URL separately from its exact token issuer. The bridge needs a confidential client with service accounts enabled, its client secret, and Admin REST access to read users, groups, client roles, and service-account users. The [Base OIDC job](https://github.com/neurwerk/k8s_stack_base/blob/main/charts/keycloak/oidc/keycloak-api-key-bridge/templates/job.yaml) assigns `realm-management` roles `view-users`, `query-clients`, and `view-clients`.

The configured gateway client must exist and hold the roles used for grants. Management tokens need the bridge-client audience; administrator tokens need the `api-key-admin` realm role. Managed registrations additionally need their named service-account clients and assigned gateway roles. Discovery JWTs need the gateway audience and an approved authorized-party client. Keycloak must publish usable RS256 signing keys with key IDs.

## Settings

All environment names use the prefix `KEYCLOAK_API_KEY_BRIDGE_`; the table gives the suffix. [`config/settings.py`](../../src/keycloak_api_key_bridge/config/settings.py) is authoritative for defaults and validation. Environment changes require a new process; managed file contents reload per validation request.

| Suffix | Purpose and default |
| --- | --- |
| `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_ISSUER` | Required server URL, realm, and exact JWT issuer. |
| `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET` | Required bridge client and private credential. |
| `AGENTGATEWAY_CLIENT_ID` | Role lookup and discovery audience; defaults to `agentgateway`. |
| `GATEWAY_CALLER_OIDC_CLIENTS` | JSON array of approved discovery JWT `azp` values; defaults to `["agentgateway"]`. |
| `KEYCLOAK_TIMEOUT_SECONDS` | Per-request HTTP timeout; default 1, greater than 0 and at most 5 seconds. |
| `JWKS_REFRESH_INTERVAL_SECONDS` | Signing-key refresh; default 10, range 1–300 seconds. |
| `JWKS_RETRY_INTERVAL_SECONDS` | Failed-refresh retry; default 5, range 1–60 seconds. |
| `ENTITLEMENT_CACHE_TTL_SECONDS` | Enabled-principal state cache; default 30, range 1–300 seconds. |
| `NEGATIVE_ENTITLEMENT_CACHE_TTL_SECONDS` | Missing/disabled-principal cache; default 5, range 1–60 seconds. |
| `POSTGRES_HOST`, `POSTGRES_PASSWORD` | Required database host and private password. |
| `POSTGRES_PORT` | Default 5432. |
| `POSTGRES_DATABASE`, `POSTGRES_USER` | Both default to `api_key_bridge`. |
| `MAX_KEYS_PER_USER` | Stored personal-key quota; default 20, range 1–100. |
| `MANAGED_REGISTRATIONS` | JSON array of `grant_file`/`verifier_file` path pairs; defaults to `[]`. |
| `HOST`, `PORT`, `LOG_LEVEL` | Defaults: `0.0.0.0`, `8000`, `info`. |

The chart exposes only a subset of application settings. Check its rendered environment rather than assuming every application setting has a corresponding chart value.

## Managed registration files

Each registration has a public grant file with exactly these fields:

```json
{
  "version": 2,
  "id": "example-service-key",
  "name": "example-service",
  "principal": {"kind": "service_account", "client_id": "example-service"},
  "permissions": ["llm:invoke", "model:example:invoke"]
}
```

The verifier file contains the secret's 64-character lowercase hexadecimal SHA-256 digest, or blank content to disable the slot. IDs, names, and client IDs are at most 128 characters, start with an ASCII letter or digit, and otherwise allow letters, digits, `.`, `_`, and `-`. Permissions must be unique, nonempty, and use the [supported namespace](../architecture/README.md#responsibilities). The grant parser rejects extra fields and older combined descriptors.

For an approved rotation, the registration owner can provide old and new slots during overlap, then disable the old verifier after consumers switch. Active verifiers must differ. Removal of an expected file produces 503 rather than disabling the slot. Check that all configured pairs are readable and valid; the service does not validate them during readiness checks. Personal-key revoke endpoints do not change these files.

## Verification and failures

| Observation | Meaning and next check |
| --- | --- |
| `/live` returns 200 | Process responds; dependencies are not tested. |
| `/health` returns 200 | Database `SELECT 1`, cached JWKS availability, and authenticated Keycloak gateway-client lookup succeeded. This does not prove every principal lookup or managed registration works. |
| `/health` reports `database: error` | Check configured database connectivity and credential delivery. |
| `/health` reports Keycloak `misconfigured` or `unavailable` | Check required settings, JWKS reachability, service-client authentication, and Admin REST permissions. |
| Validation returns 401 | Check header mode, key expiry/revocation, and principal enabled state. |
| Validation returns 503 | Check Keycloak readiness and managed files; a bad managed slot also blocks personal keys. |
| Creation returns 409 | Revoke an unneeded stored key, including expired entries, before creating a replacement. |

`/metrics` exposes Prometheus HTTP metrics. Validation responses include a request ID; rejection logs include that ID, error code, and status. Unknown-key logs use a digest prefix rather than the credential. Use these fields for correlation without recording authorization headers or creation-response secrets.

With authorized test access, create a temporary personal key through Studio, check its listed grant and expiry, and verify a permitted request through the selected gateway binding. Revoke it and separately verify rejection through that same path. A healthy bridge or an invalid-random-key denial alone does not verify revocation. Account or role changes have the [cache boundaries](../architecture/README.md#keycloak-state-and-errors) described in architecture.

## Storage and recovery

The bridge requires a dedicated PostgreSQL database. [`config/database.py`](../../src/keycloak_api_key_bridge/config/database.py) defines the expected schema marker, tables, columns, and constraints. Service startup verifies them; it never creates tables. `keycloak-api-key-bridge-init-db` initializes an empty database or verifies an already matching schema under an advisory lock. It does not migrate an incompatible database or import SQLite keys.

For schema failure, compare the selected image with the database's supported schema and obtain a compatible migration or restore plan; rerunning initialization does not repair an unknown schema. Key secrets cannot be reconstructed from stored hashes, so a lost personal secret requires a replacement key. Restoring an older database can restore rows that were subsequently revoked; recovery must account for those credentials before resuming acceptance. Managed-key recovery belongs to the grant/verifier delivery owner, separately from personal-key database recovery.
