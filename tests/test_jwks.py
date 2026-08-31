"""JWKS refresh and signed management-JWT tests."""

from __future__ import annotations

import base64
import time
from collections.abc import Generator
from typing import cast

import prometheus_client
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jose import jwt

from keycloak_api_key_bridge.config.settings import AuthInfo
from keycloak_api_key_bridge.lib.jwks import Jwk, JWKSCache
from keycloak_api_key_bridge.lib.keycloak import KeycloakClient, KeycloakUnavailableError
from keycloak_api_key_bridge.main import create_app


def _base64url(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _signing_key(kid: str) -> tuple[dict[str, object], bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    document: dict[str, object] = {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": _base64url(public_numbers.n),
        "e": _base64url(public_numbers.e),
    }
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return document, private_pem


def _token(private_pem: bytes, kid: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": "user-a",
            "aud": "test-client",
            "iss": "https://keycloak.example/realms/test",
            "iat": now,
            "exp": now + 3600,
        },
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


class FetchingKeycloakClient:
    """Script Keycloak JWKS responses without live network traffic."""

    def __init__(self, responses: list[dict[str, object] | Exception]) -> None:
        self.responses = responses
        self.calls = 0
        self.unavailable_calls = 0

    def fetch_jwks(self) -> dict[str, object]:
        self.calls += 1
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def mark_unavailable(self) -> None:
        self.unavailable_calls += 1


class ScriptedJWKSCache:
    """Synchronous cache double for request-level refresh behavior."""

    def __init__(
        self,
        keys: list[dict[str, object]],
        refreshes: list[list[dict[str, object]] | Exception],
    ) -> None:
        self._keys = {cast(str, key["kid"]): key for key in keys}
        self._refreshes = refreshes
        self.refresh_calls = 0

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def is_available(self) -> bool:
        return self._keys is not None

    def get_key(self, kid: str) -> Jwk | None:
        return self._keys.get(kid) if self._keys is not None else None

    def refresh(self) -> bool:
        self.refresh_calls += 1
        response = self._refreshes.pop(0)
        if isinstance(response, Exception):
            self._keys = None
            return False
        self._keys = {cast(str, key["kid"]): key for key in response}
        return True

    def invalidate(self) -> None:
        self._keys = None

    def restore(self, keys: list[dict[str, object]]) -> None:
        self._keys = {cast(str, key["kid"]): key for key in keys}


class AvailabilityKeycloakClient:
    """Keycloak availability double that clears state on authorization failure."""

    def __init__(self, available: bool) -> None:
        self.available = available
        self.unavailable_calls = 0

    def health_check(self) -> None:
        if not self.available:
            self.mark_unavailable()
            raise KeycloakUnavailableError("Keycloak down")

    def mark_unavailable(self) -> None:
        self.unavailable_calls += 1

    def close(self) -> None:
        pass


@pytest.fixture(autouse=True)
def clear_prometheus_registry() -> Generator[None, None, None]:
    collectors = list(prometheus_client.REGISTRY._collector_to_names)
    for collector in collectors:
        prometheus_client.REGISTRY.unregister(collector)
    yield


def _app_with_cache(cache: ScriptedJWKSCache):
    app = create_app(database_url="sqlite://")
    app.state.auth_info = AuthInfo(
        server_url="https://keycloak.example",
        realm="test",
        client_id="test-client",
        client_secret="test-secret",
        issuer="https://keycloak.example/realms/test",
    )
    app.state.keycloak_configured = True
    app.state.jwks_cache = cache
    return app


def test_background_cache_retries_initial_fetch() -> None:
    key, _ = _signing_key("key-a")
    client = FetchingKeycloakClient([RuntimeError("Keycloak down"), {"keys": [key]}])
    cache = JWKSCache(
        cast(KeycloakClient, client), refresh_interval_seconds=1, retry_interval_seconds=0.01
    )
    cache.start()
    try:
        deadline = time.monotonic() + 1
        while not cache.is_available() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert cache.is_available()
        assert client.calls == 2
    finally:
        cache.stop()


def test_failed_refresh_discards_previously_cached_keys() -> None:
    key, _ = _signing_key("key-a")
    client = FetchingKeycloakClient([{"keys": [key]}, RuntimeError("Keycloak down")])
    cache = JWKSCache(
        cast(KeycloakClient, client), refresh_interval_seconds=10, retry_interval_seconds=5
    )

    assert cache.refresh()
    assert cache.get_key("key-a") == key
    assert not cache.refresh()
    assert not cache.is_available()
    assert cache.get_key("key-a") is None
    assert client.unavailable_calls == 1


def test_refresh_ignores_non_signing_and_unsupported_keys() -> None:
    key, _ = _signing_key("key-a")
    client = FetchingKeycloakClient(
        [
            {
                "keys": [
                    {"kid": "encryption", "kty": "RSA", "alg": "RSA-OAEP", "use": "enc"},
                    {"kid": "elliptic", "kty": "EC", "alg": "ES256", "use": "sig"},
                    key,
                ]
            }
        ]
    )
    cache = JWKSCache(
        cast(KeycloakClient, client), refresh_interval_seconds=10, retry_interval_seconds=5
    )

    assert cache.refresh()
    assert cache.get_key("key-a") == key
    assert cache.get_key("encryption") is None
    assert cache.get_key("elliptic") is None


def test_refresh_fails_closed_without_supported_signing_keys() -> None:
    client = FetchingKeycloakClient(
        [{"keys": [{"kid": "elliptic", "kty": "EC", "alg": "ES256", "use": "sig"}]}]
    )
    cache = JWKSCache(
        cast(KeycloakClient, client), refresh_interval_seconds=10, retry_interval_seconds=5
    )

    assert not cache.refresh()
    assert not cache.is_available()
    assert client.unavailable_calls == 1


def test_unknown_kid_refresh_accepts_new_signing_key() -> None:
    key_a, _ = _signing_key("key-a")
    key_b, private_b = _signing_key("key-b")
    cache = ScriptedJWKSCache([key_a], [[key_a, key_b]])

    with TestClient(_app_with_cache(cache), raise_server_exceptions=False) as client:
        response = client.get(
            "/me", headers={"Authorization": f"Bearer {_token(private_b, 'key-b')}"}
        )

    assert response.status_code == 200, response.text
    assert cache.refresh_calls == 1


def test_removed_key_is_rejected_after_refresh() -> None:
    key_a, private_a = _signing_key("key-a")
    key_b, _ = _signing_key("key-b")
    cache = ScriptedJWKSCache([key_b], [[key_b]])

    with TestClient(_app_with_cache(cache), raise_server_exceptions=False) as client:
        response = client.get(
            "/me", headers={"Authorization": f"Bearer {_token(private_a, 'key-a')}"}
        )

    assert response.status_code == 401, response.text
    assert cache.refresh_calls == 1


def test_unknown_kid_returns_503_when_keycloak_refresh_fails() -> None:
    key_a, _ = _signing_key("key-a")
    key_b, private_b = _signing_key("key-b")
    cache = ScriptedJWKSCache([key_a], [RuntimeError("Keycloak down")])

    with TestClient(_app_with_cache(cache), raise_server_exceptions=False) as client:
        response = client.get(
            "/me", headers={"Authorization": f"Bearer {_token(private_b, 'key-b')}"}
        )

    assert response.status_code == 503, response.text
    assert cache.refresh_calls == 1


def test_health_requires_keycloak_but_liveness_does_not() -> None:
    app = create_app(database_url="sqlite://")

    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/live").status_code == 200
        readiness = client.get("/health")
        validation = client.get("/validate", headers={"x-api-key": "test-key"})

    assert readiness.status_code == 503
    assert readiness.json()["checks"]["keycloak"] == "misconfigured"
    assert validation.status_code == 503


def test_authorization_health_failure_invalidates_jwks_until_recovery() -> None:
    key, _ = _signing_key("key-a")
    cache = ScriptedJWKSCache([key], [])
    app = _app_with_cache(cache)
    keycloak = AvailabilityKeycloakClient(available=False)
    app.state.kc_client = keycloak

    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.get("/health").status_code == 503
        assert not cache.is_available()
        assert keycloak.unavailable_calls == 1
        assert client.get("/validate", headers={"x-api-key": "test-key"}).status_code == 503

        keycloak.available = True
        cache.restore([key])
        assert client.get("/health").status_code == 200
        assert client.get("/validate", headers={"x-api-key": "test-key"}).status_code == 401
