"""Controller tests for JWT authentication and authorization decisions."""

import base64
import time
from collections.abc import Generator
from unittest.mock import ANY

import prometheus_client
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jose import jwt

from keycloak_api_key_bridge.config.database import ApiKey
from keycloak_api_key_bridge.config.settings import AuthInfo
from keycloak_api_key_bridge.controllers.api_keys import CurrentUser, get_current_user
from keycloak_api_key_bridge.lib.keycloak import (
    KeycloakUnavailableError,
    PrincipalEntitlements,
)
from keycloak_api_key_bridge.main import create_app

_KEYCLOAK_URL = "https://keycloak.example"
_ISSUER = f"{_KEYCLOAK_URL}/realms/test"
_BRIDGE_AUDIENCE = "keycloak-api-key-bridge"


def _int_to_b64url(value: int) -> str:
    """Encode an RSA integer as an unpadded base64url value."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _rsa_private_jwk(key: rsa.RSAPrivateKey) -> dict[str, str]:
    """Convert a generated RSA test key to the JWK form python-jose accepts."""
    private = key.private_numbers()
    public = private.public_numbers
    return {
        "kty": "RSA",
        "n": _int_to_b64url(public.n),
        "e": _int_to_b64url(public.e),
        "d": _int_to_b64url(private.d),
        "p": _int_to_b64url(private.p),
        "q": _int_to_b64url(private.q),
        "dp": _int_to_b64url(private.dmp1),
        "dq": _int_to_b64url(private.dmq1),
        "qi": _int_to_b64url(private.iqmp),
    }


_SIGNING_KEY = _rsa_private_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048))


def _jwks() -> dict[str, list[dict[str, str]]]:
    """Return the public half of the signing key as a Keycloak-like JWKS."""
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-kid",
                "alg": "RS256",
                "use": "sig",
                "n": _SIGNING_KEY["n"],
                "e": _SIGNING_KEY["e"],
            }
        ]
    }


def _management_token(
    *,
    user_id: str = "user-a",
    audience: str | list[str] | None = _BRIDGE_AUDIENCE,
    issuer: str = _ISSUER,
    roles: list[str] | None = None,
    azp: str | None = None,
    include_exp: bool = True,
    include_iat: bool = True,
    expires_in_seconds: int = 300,
    signing_key: dict[str, str] | None = None,
) -> str:
    """Create a signed management token with selectively controlled claims."""
    now = int(time.time())
    claims: dict[str, object] = {"sub": user_id, "iss": issuer}
    if audience is not None:
        claims["aud"] = audience
    if include_iat:
        claims["iat"] = now
    if include_exp:
        claims["exp"] = now + expires_in_seconds
    if roles is not None:
        claims["realm_access"] = {"roles": roles}
    if azp is not None:
        claims["azp"] = azp
    return jwt.encode(
        claims,
        signing_key or _SIGNING_KEY,
        algorithm="RS256",
        headers={"kid": "test-kid"},
    )


def _authorization_header(token: str) -> dict[str, str]:
    """Return the HTTP header used by bridge management endpoints."""
    return {"Authorization": f"Bearer {token}"}


class FakeKeycloakClient:
    """Configurable current-entitlement provider for controller tests."""

    def __init__(self) -> None:
        self.entitlements: dict[str, PrincipalEntitlements | None] = {
            "user-a": PrincipalEntitlements(frozenset({"llm:invoke", "mcp:brave:invoke"})),
            "user-b": PrincipalEntitlements(frozenset({"llm:invoke"})),
        }
        self.failure = False
        self.unavailable_calls = 0

    def get_principal_entitlements(self, principal_id: str) -> PrincipalEntitlements | None:
        if self.failure:
            raise KeycloakUnavailableError("test outage")
        return self.entitlements.get(principal_id)

    def close(self) -> None:
        pass

    def mark_unavailable(self) -> None:
        self.unavailable_calls += 1


class AvailableJWKSCache:
    """Minimal ready Keycloak state for API-key controller tests."""

    def __init__(self) -> None:
        self.available = True

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def is_available(self) -> bool:
        return self.available

    def invalidate(self) -> None:
        self.available = False


class StaticJWKSCache:
    """Minimal cache that supplies a fixed signing key to authentication tests."""

    def __init__(self, keys: dict[str, dict[str, str]]) -> None:
        self._keys = keys

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def is_available(self) -> bool:
        return True

    def get_key(self, kid: str) -> dict[str, str] | None:
        return self._keys.get(kid)

    def refresh(self) -> bool:
        return False


@pytest.fixture(autouse=True)
def clear_prometheus_registry() -> Generator[None, None, None]:
    collectors = list(prometheus_client.REGISTRY._collector_to_names)
    for collector in collectors:
        prometheus_client.REGISTRY.unregister(collector)
    yield


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    app = create_app(database_url="sqlite://")
    app.state.auth_info = AuthInfo("", "", "", "")
    app.state.kc_client = FakeKeycloakClient()
    app.state.keycloak_configured = True
    app.state.jwks_cache = AvailableJWKSCache()
    app.dependency_overrides[get_current_user] = lambda: CurrentUser("user-a", frozenset())
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def jwt_client() -> Generator[TestClient, None, None]:
    """Return a bridge client that verifies signed tokens through the real dependency."""
    app = create_app(database_url="sqlite://")
    app.state.auth_info = AuthInfo(
        _KEYCLOAK_URL,
        "test",
        _BRIDGE_AUDIENCE,
        "test-secret",
        _ISSUER,
    )
    app.state.keycloak_configured = True
    app.state.jwks_cache = StaticJWKSCache({"test-kid": _jwks()["keys"][0]})
    app.state.kc_client = FakeKeycloakClient()
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.mark.parametrize(
    "audience",
    [pytest.param(None, id="missing"), pytest.param("another-service", id="wrong")],
)
def test_management_jwt_rejects_missing_or_wrong_audience(
    jwt_client: TestClient, audience: str | None
) -> None:
    response = jwt_client.get(
        "/me", headers=_authorization_header(_management_token(audience=audience))
    )
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("audience", "azp"),
    [
        pytest.param(_BRIDGE_AUDIENCE, None, id="single-audience"),
        pytest.param(
            ["realm-management", "agentgateway", _BRIDGE_AUDIENCE],
            "studio",
            id="studio-audiences",
        ),
    ],
)
def test_management_jwt_accepts_configured_string_or_studio_audience_list(
    jwt_client: TestClient, audience: str | list[str], azp: str | None
) -> None:
    response = jwt_client.get(
        "/me", headers=_authorization_header(_management_token(audience=audience, azp=azp))
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"user_id": "user-a", "realm": "test"}


def test_management_jwt_retains_issuer_expiry_issued_at_and_signature_validation(
    jwt_client: TestClient,
) -> None:
    untrusted_key = _rsa_private_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    rejected_tokens = [
        _management_token(issuer=f"{_KEYCLOAK_URL}/realms/another"),
        _management_token(include_exp=False),
        _management_token(include_iat=False),
        _management_token(expires_in_seconds=-1),
        _management_token(signing_key=untrusted_key),
    ]

    for token in rejected_tokens:
        response = jwt_client.get("/me", headers=_authorization_header(token))
        assert response.status_code == 401


def test_user_key_validation_returns_grant_entitlement_intersection(client: TestClient) -> None:
    created = client.post(
        "/api_keys",
        json={
            "name": "cli",
            "permissions": ["llm:invoke", "mcp:brave:invoke"],
            "expires_in_days": 30,
        },
    )
    assert created.status_code == 200, created.text
    key = created.json()["api_key"]

    validated = client.get("/validate", headers={"x-api-key": key})
    assert validated.status_code == 200, validated.text
    assert validated.json() == {
        "contract_version": 1,
        "credential": {
            "id": created.json()["id"],
            "kind": "user_api_key",
            "name": "cli",
            "expires_at": ANY,
        },
        "principal": {"kind": "user", "id": "user-a"},
        "permissions": ["llm:invoke", "mcp:brave:invoke"],
    }

    client.app.state.kc_client.entitlements["user-a"] = PrincipalEntitlements(
        frozenset({"llm:invoke"})
    )
    restricted = client.get("/validate", headers={"x-api-key": key})
    assert restricted.status_code == 200
    assert restricted.json()["permissions"] == ["llm:invoke"]


def test_create_rejects_permissions_not_in_live_entitlements(client: TestClient) -> None:
    response = client.post(
        "/api_keys",
        json={"name": "cli", "permissions": ["model:restricted:invoke"], "expires_in_days": 30},
    )
    assert response.status_code == 403


def test_validate_uses_401_for_disabled_principal_and_503_for_keycloak_outage(
    client: TestClient,
) -> None:
    created = client.post(
        "/api_keys", json={"name": "cli", "permissions": ["llm:invoke"], "expires_in_days": 30}
    )
    key = created.json()["api_key"]
    client.app.state.kc_client.entitlements["user-a"] = None
    assert client.get("/validate", headers={"x-api-key": key}).status_code == 401

    client.app.state.kc_client.failure = True
    assert client.get("/validate", headers={"x-api-key": key}).status_code == 503


def test_studio_administrator_token_can_manage_a_target_users_subset(
    jwt_client: TestClient,
) -> None:
    admin_headers = _authorization_header(
        _management_token(
            user_id="admin",
            audience=["realm-management", "agentgateway", _BRIDGE_AUDIENCE],
            azp="studio",
            roles=["api-key-admin"],
        )
    )
    response = jwt_client.post(
        "/api_keys",
        json={
            "name": "target",
            "target_user_id": "user-b",
            "permissions": ["llm:invoke"],
            "expires_in_days": 30,
        },
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    assert jwt_client.get("/api_keys?user_id=user-b", headers=admin_headers).status_code == 200

    denied = jwt_client.post(
        "/api_keys",
        json={
            "name": "target-denied",
            "target_user_id": "user-b",
            "permissions": ["mcp:brave:invoke"],
            "expires_in_days": 30,
        },
        headers=admin_headers,
    )
    assert denied.status_code == 403


def test_renew_endpoint_is_absent(client: TestClient) -> None:
    assert client.post("/api_keys/id/renew").status_code == 404


def test_create_requires_bounded_expiry(client: TestClient) -> None:
    missing = client.post("/api_keys", json={"name": "cli", "permissions": ["llm:invoke"]})
    assert missing.status_code == 422

    for expires_in_days in (0, 366):
        response = client.post(
            "/api_keys",
            json={"name": "cli", "permissions": ["llm:invoke"], "expires_in_days": expires_in_days},
        )
        assert response.status_code == 422


@pytest.mark.parametrize(
    "permissions",
    [
        pytest.param([], id="empty"),
        pytest.param(["invalid:permission"], id="invalid-namespace"),
        pytest.param(["llm:invoke", "llm:invoke"], id="duplicate"),
    ],
)
def test_create_requires_an_explicit_valid_non_empty_grant(
    client: TestClient, permissions: list[str]
) -> None:
    response = client.post(
        "/api_keys",
        json={"name": "cli", "permissions": permissions, "expires_in_days": 30},
    )
    assert response.status_code == 422


def test_api_key_quota_rejects_creation_until_a_key_is_revoked(client: TestClient) -> None:
    client.app.state.max_keys_per_user = 2
    created = [
        client.post(
            "/api_keys",
            json={"name": name, "permissions": ["llm:invoke"], "expires_in_days": 30},
        )
        for name in ("first", "second")
    ]
    assert all(response.status_code == 200 for response in created)

    limited = client.post(
        "/api_keys", json={"name": "third", "permissions": ["llm:invoke"], "expires_in_days": 30}
    )
    assert limited.status_code == 409
    assert limited.json() == {
        "detail": "API key limit reached; revoke an existing key before creating another"
    }

    revoked = client.post(f"/api_keys/{created[0].json()['id']}/revoke")
    assert revoked.status_code == 200
    replacement = client.post(
        "/api_keys",
        json={"name": "replacement", "permissions": ["llm:invoke"], "expires_in_days": 30},
    )
    assert replacement.status_code == 200


def test_list_api_keys_is_bounded_by_the_configured_quota(client: TestClient) -> None:
    with client.app.state.db_factory() as session:
        for index in range(25):
            ApiKey.create_key(
                session,
                name=f"cli-{index}",
                user_id="user-a",
                permissions=["llm:invoke"],
                validity_days=30,
                max_keys_per_user=100,
            )
        expected_ids = [key["id"] for key in ApiKey.list_keys(session, "user-a", limit=20)]

    listed = client.get("/api_keys")
    assert listed.status_code == 200
    assert [key["id"] for key in listed.json()] == expected_ids
    assert len(listed.json()) == 20
    assert all(key["permissions"] == ["llm:invoke"] for key in listed.json())
    assert all(key["expires_at"] for key in listed.json())


def test_permissions_returns_only_sorted_current_agentgateway_permissions(
    client: TestClient,
) -> None:
    client.app.state.kc_client.entitlements["user-a"] = PrincipalEntitlements(
        frozenset({"mcp:brave:invoke", "not-a-permission", "llm:invoke"})
    )

    response = client.get("/permissions")

    assert response.status_code == 200
    assert response.json() == {"permissions": ["llm:invoke", "mcp:brave:invoke"]}


def test_permissions_allows_only_api_key_admin_to_target_another_user(
    jwt_client: TestClient,
) -> None:
    self_headers = _authorization_header(_management_token(user_id="user-a"))
    assert jwt_client.get("/permissions?user_id=user-b", headers=self_headers).status_code == 403

    admin_headers = _authorization_header(
        _management_token(user_id="admin", roles=["api-key-admin"])
    )
    response = jwt_client.get("/permissions?user_id=user-b", headers=admin_headers)
    assert response.status_code == 200
    assert response.json() == {"permissions": ["llm:invoke"]}


def test_validate_401_is_recorded_in_aggregate_metrics(client: TestClient) -> None:
    assert client.get("/validate", headers={"x-api-key": "not-a-valid-key"}).status_code == 401

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert 'http_requests_total{handler="/validate",method="GET",status="401"} 1.0' in metrics.text
