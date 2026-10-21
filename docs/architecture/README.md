# Architecture

## Responsibilities

[`main.py`](../../src/keycloak_api_key_bridge/main.py) creates a FastAPI application with a PostgreSQL connection pool, a pooled Keycloak client, a background signing-key cache, and a managed-key file reader. [`controllers/api_keys.py`](../../src/keycloak_api_key_bridge/controllers/api_keys.py) owns the HTTP endpoints and authorization decisions.

| Component | Responsibility |
| --- | --- |
| Keycloak | User and service-account identity, enabled state, groups, email, and AgentGateway client-role mappings. |
| Bridge | Personal-key issuance and storage; key-to-principal resolution; intersection of a key's grant with the principal's permissions. |
| Studio | User-facing key management; forwards the caller's JWT to the bridge. Its model-discovery API asks the bridge for caller permissions. |
| AgentGateway | Uses bridge decisions for API-key authentication and enforces the permissions required by the selected route and destination. |
| Base and selected add-ons | Provision Keycloak clients, database access, Secret delivery, managed registrations, and gateway policies. |

The bridge does not assign Keycloak roles or select gateway routes. A successful key validation can return an empty permission list; it is not permission to invoke any destination. The permission syntax is limited by [`lib/permissions.py`](../../src/keycloak_api_key_bridge/lib/permissions.py) to `llm:invoke`, `model:<id>:invoke`, `mcp:<id>:invoke`, `application:<id>:invoke`, and `provider:<id>:company-use`.

## Personal-key lifecycle

1. A caller supplies a Keycloak JWT in `Authorization: Bearer …`. The bridge verifies RS256, signing-key ID, configured issuer, bridge-client audience, expiry, issued-at claim, and a nonempty subject. Management does not separately check an approved `azp` client list or re-read the caller's realm roles.
2. `POST /api_keys` accepts `name`, `permissions`, `expires_in_days`, and optional `target_user_id`. The grant must contain 1–128 unique valid permissions, all present in the target's cached Keycloak permissions. Expiry is 1–365 days. Names are 1–64 characters, start with an ASCII letter or digit, and otherwise allow letters, digits, `.`, `_`, and `-`.
3. [`config/database.py`](../../src/keycloak_api_key_bridge/config/database.py) generates the secret with `secrets.token_urlsafe(32)`. PostgreSQL stores its SHA-256 digest, eight-character prefix, UUID, owner, optional acting administrator, timestamps, and fixed grant. Only the creation response returns the full secret; listing cannot recover it.
4. Each validation checks the stored digest, expiry, and revoked flag, then returns the intersection of the stored grant and the owner's cached permissions. Key records themselves are not cached by the bridge.
5. `POST /api_keys/{key_id}/revoke` deletes the row and commits. Subsequent database lookups reject it. This does not cancel a request already authorized, revoke provider credentials, or end OIDC sessions. There is no renewal or grant-edit endpoint; create a replacement key instead.

Callers may manage their own keys. The `api-key-admin` realm role in the verified token permits targeting another user and revoking any personal key. Creating for another user still requires that target's permissions; the administrator's own invocation permissions are not the grant ceiling. The role is evaluated from the token, so removing it in Keycloak does not rewrite an already issued token.

The per-user quota counts stored rows, including expired keys. Expired keys remain visible in the bounded list until revoked. PostgreSQL transaction-scoped advisory locking serializes creation for an owner across service instances. Revocation deletes metadata too; the database is not a retained revocation audit log.

## Managed keys

[`lib/managed_api_keys.py`](../../src/keycloak_api_key_bridge/lib/managed_api_keys.py) reloads every configured grant/verifier pair on each key-validation request, before looking up personal keys. A grant names a Keycloak service-account client and fixed permissions; its separate verifier is a lowercase SHA-256 digest. Matching uses `hmac.compare_digest`. Managed secrets are issued and delivered outside this service, not through `/api_keys`.

The bridge resolves the client's service-account user and intersects the grant with that user's cached permissions. The identity is the service account, not the person who provisioned the key. Managed keys have no expiry field and are not listed or revoked through the personal-key API. Once a changed file is visible to the process, a blank verifier disables that slot; rotating to a different verifier stops matching the old secret unless another slot still accepts it. Kubernetes projection adds its own delivery delay.

Unreadable, incomplete, malformed, or duplicate active verifier configuration causes key validation to return 503, including for personal keys. All slots are loaded before matching; one valid slot does not conceal another broken slot.

## HTTP surface

| Endpoint | Credential and result |
| --- | --- |
| `GET /me` | Management JWT; returns subject and realm. |
| `GET /permissions?user_id=…` | Management JWT; returns the target's cached valid gateway permissions. Defaults to self; another target needs `api-key-admin`. |
| `GET /api_keys?user_id=…` | Management JWT; bounded metadata list, with the same target rule. |
| `POST /api_keys` | Management JWT; creates a personal key and returns its secret once. |
| `POST /api_keys/{key_id}/revoke` | Management JWT; owner or `api-key-admin` deletes the key. |
| `GET` or `POST /validate/neurwerk` | Exactly one `X-Neurwerk-Authorization: Bearer <key>` header. No provider-header fallback. |
| `GET` or `POST /validate/proxy` | Exactly one `Proxy-Authorization: Basic …` header. The decoded password is the key; a nonempty username is required but never selects identity. |
| `POST /gateway/caller-permissions` | Returns effective key permissions or verified gateway-audience JWT roles for Studio discovery. |

Both validation routes return credential and principal metadata, permissions, groups, email, and `x-agentgateway-auth-context` for the gateway. Headers are bounded; duplicate or malformed identity headers are rejected. The application does not require a second workload credential for these routes. The deployment and gateway own network exposure and trusted-header handling. There is no `/validate` route.

Caller-permission discovery prefers the dedicated Neurwerk header. It tries key validation first and attempts JWT verification only when that lookup reports an invalid or expired key. Without the dedicated header, it accepts one `Authorization` header as a JWT. JWT discovery requires the gateway audience and an `azp` in `gateway_caller_oidc_clients`; permissions come from the token's gateway client roles, without a fresh principal lookup.

## Keycloak state and errors

[`lib/keycloak.py`](../../src/keycloak_api_key_bridge/lib/keycloak.py) uses client credentials to query users, composite gateway client roles, full group paths, and service-account users. Positive and negative principal results have separate per-process TTLs. Creation and `/permissions` use that cache too. Role removal, account disabling, and group changes therefore need not affect a key immediately; grant intersection also allows a restored role to become effective again within the key's original grant.

[`lib/jwks.py`](../../src/keycloak_api_key_bridge/lib/jwks.py) refreshes signing keys in the background. Failed refreshes clear signing keys and principal entitlements. Authorization lookup failures also invalidate signing keys. Requests fail with 503 after such a failure is observed; successful cached state can still be used before an outage is detected. An unknown JWT signing-key ID triggers a refresh.

Validation returns 401 for malformed credentials, unknown/expired keys, or a missing/disabled principal; 503 represents unavailable Keycloak state or managed configuration. Validation errors include an error code and request ID, also returned as `x-request-id`. Management uses 403 for denied targeting or grants, 404 for an unavailable target or missing owned key, 409 for quota exhaustion, and 422 for invalid request bodies. Database exceptions outside readiness are not translated into this structured validation error format.

Integration sources: [Studio key proxy](https://github.com/neurwerk/k8s_stack_studio/blob/main/apps/api/src/k8s_stack_studio/controllers/api_keys.py), [Studio discovery](https://github.com/neurwerk/k8s_stack_studio/blob/main/apps/api/src/k8s_stack_studio/controllers/model_discovery.py), and [Base gateway admission policies](https://github.com/neurwerk/k8s_stack_base/blob/main/charts/agentgateway/templates/ai-admission.yaml). Use the revisions selected for the deployment when checking compatibility.
