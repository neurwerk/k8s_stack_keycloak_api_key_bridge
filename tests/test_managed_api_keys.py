"""Unit tests for managed descriptors and Keycloak entitlement caching."""

import base64
import hashlib
import json
import time
from pathlib import Path

import httpx
import pytest

from keycloak_api_key_bridge.config.settings import AuthInfo
from keycloak_api_key_bridge.lib.keycloak import KeycloakClient
from keycloak_api_key_bridge.lib.managed_api_keys import (
    ManagedApiKeyConfigurationError,
    ManagedApiKeyValidator,
)


def write_grant(path: Path, key_id: str = "dify-primary") -> None:
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "id": key_id,
                "name": "dify-agentgateway",
                "principal": {"kind": "service_account", "client_id": "dify-agentgateway"},
                "permissions": ["llm:invoke"],
            }
        ),
        encoding="utf-8",
    )


def write_verifier(path: Path, key_value: str) -> None:
    path.write_text(hashlib.sha256(key_value.encode()).hexdigest(), encoding="utf-8")


def service_token() -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"exp": time.time() + 3600}).encode()).rstrip(
        b"="
    )
    return f"header.{payload.decode()}.signature"


def test_validator_hot_reloads_grant_and_verifier(tmp_path: Path) -> None:
    grant = tmp_path / "primary.json"
    verifier = tmp_path / "primary.sha256"
    write_grant(grant)
    write_verifier(verifier, "first")
    validator = ManagedApiKeyValidator(
        primary_grant_file=str(grant), primary_verifier_file=str(verifier)
    )
    assert validator.match("first") is not None

    write_verifier(verifier, "second")
    assert validator.match("first") is None
    matched = validator.match("second")
    assert matched is not None
    assert matched.principal_client_id == "dify-agentgateway"
    assert matched.permissions == ("llm:invoke",)


def test_validator_rejects_legacy_combined_descriptor(tmp_path: Path) -> None:
    grant = tmp_path / "primary.json"
    verifier = tmp_path / "primary.sha256"
    grant.write_text(
        '{"version":1,"id":"legacy","name":"legacy","principal":{},'
        '"permissions":["llm:invoke"],"verifier":"' + "a" * 64 + '"}',
        encoding="utf-8",
    )
    write_verifier(verifier, "secret")
    with pytest.raises(ManagedApiKeyConfigurationError):
        ManagedApiKeyValidator(
            primary_grant_file=str(grant), primary_verifier_file=str(verifier)
        ).match("secret")


def test_validator_accepts_primary_and_secondary_during_rotation(tmp_path: Path) -> None:
    primary_grant = tmp_path / "primary.json"
    primary_verifier = tmp_path / "primary.sha256"
    secondary_grant = tmp_path / "secondary.json"
    secondary_verifier = tmp_path / "secondary.sha256"
    write_grant(primary_grant)
    write_grant(secondary_grant, "dify-secondary")
    write_verifier(primary_verifier, "old-key")
    write_verifier(secondary_verifier, "new-key")
    validator = ManagedApiKeyValidator(
        primary_grant_file=str(primary_grant),
        primary_verifier_file=str(primary_verifier),
        secondary_grant_file=str(secondary_grant),
        secondary_verifier_file=str(secondary_verifier),
    )

    assert validator.match("old-key") is not None
    assert validator.match("new-key") is not None

    secondary_verifier.write_text("", encoding="utf-8")
    assert validator.match("old-key") is not None
    assert validator.match("new-key") is None


def test_validator_rejects_incomplete_or_invalid_primary_slot(tmp_path: Path) -> None:
    grant = tmp_path / "primary.json"
    verifier = tmp_path / "primary.sha256"
    write_grant(grant)

    with pytest.raises(ManagedApiKeyConfigurationError, match="incomplete"):
        ManagedApiKeyValidator(primary_grant_file=str(grant)).match("secret")

    verifier.write_text("", encoding="utf-8")
    with pytest.raises(ManagedApiKeyConfigurationError, match="invalid verifier"):
        ManagedApiKeyValidator(
            primary_grant_file=str(grant), primary_verifier_file=str(verifier)
        ).match("secret")


def test_keycloak_client_caches_current_entitlements() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": service_token()})
        if request.url.path.endswith("/users/user-1"):
            return httpx.Response(200, json={"enabled": True})
        if request.url.path.endswith("/clients"):
            return httpx.Response(200, json=[{"id": "agentgateway-id"}])
        if request.url.path.endswith("/composite"):
            return httpx.Response(200, json=[{"name": "llm:invoke"}, {"name": "ignored"}])
        raise AssertionError(request.url)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = KeycloakClient(
        AuthInfo("https://keycloak.test", "test", "bridge", "secret"), client=http_client
    )
    first = client.get_principal_entitlements("user-1")
    second = client.get_principal_entitlements("user-1")
    assert first is not None
    assert second is not None
    assert first.permissions == frozenset({"llm:invoke"})
    assert second.permissions == frozenset({"llm:invoke"})
    assert sum(url.endswith("/users/user-1") for url in calls) == 1
    client.close()


def test_keycloak_client_discards_entitlements_when_marked_unavailable() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": service_token()})
        if request.url.path.endswith("/users/user-1"):
            return httpx.Response(200, json={"enabled": True})
        if request.url.path.endswith("/clients"):
            return httpx.Response(200, json=[{"id": "agentgateway-id"}])
        if request.url.path.endswith("/composite"):
            return httpx.Response(200, json=[{"name": "llm:invoke"}])
        raise AssertionError(request.url)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = KeycloakClient(
        AuthInfo("https://keycloak.test", "test", "bridge", "secret"), client=http_client
    )
    try:
        assert client.get_principal_entitlements("user-1") is not None
        client.mark_unavailable()
        assert client.get_principal_entitlements("user-1") is not None
        assert sum(url.endswith("/users/user-1") for url in calls) == 2
    finally:
        client.close()


def test_keycloak_health_check_uses_an_authenticated_authorization_request() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": service_token()})
        if request.url.path.endswith("/clients"):
            assert request.headers["authorization"].startswith("Bearer ")
            return httpx.Response(200, json=[{"id": "agentgateway-id"}])
        raise AssertionError(request.url)

    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    client = KeycloakClient(
        AuthInfo("https://keycloak.test", "test", "bridge", "secret"), client=http_client
    )
    try:
        client.health_check()
        assert any(url.endswith("/clients?clientId=agentgateway") for url in calls)
    finally:
        client.close()
