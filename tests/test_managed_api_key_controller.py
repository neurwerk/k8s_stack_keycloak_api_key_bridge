"""Controller tests for managed machine-principal authorization decisions."""

import hashlib
import json
from collections.abc import Generator
from pathlib import Path

import prometheus_client
import pytest
from fastapi.testclient import TestClient

from keycloak_api_key_bridge.config.settings import AuthInfo, Settings
from keycloak_api_key_bridge.lib.keycloak import PrincipalEntitlements
from keycloak_api_key_bridge.main import create_app


@pytest.fixture(autouse=True)
def clear_prometheus_registry() -> Generator[None, None, None]:
    collectors = list(prometheus_client.REGISTRY._collector_to_names)
    for collector in collectors:
        prometheus_client.REGISTRY.unregister(collector)
    yield


class FakeKeycloakClient:
    def close(self) -> None:
        pass

    def get_service_account_user_id(self, client_id: str) -> str | None:
        return "dify-service-account" if client_id == "dify-agentgateway" else None

    def get_principal_entitlements(self, principal_id: str) -> PrincipalEntitlements | None:
        if principal_id != "dify-service-account":
            return None
        return PrincipalEntitlements(frozenset({"llm:invoke"}))


class AvailableJWKSCache:
    """Minimal ready Keycloak state for managed-key controller tests."""

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def is_available(self) -> bool:
        return True


def write_grant(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "id": "dify-primary",
                "name": "dify-agentgateway",
                "principal": {"kind": "service_account", "client_id": "dify-agentgateway"},
                "permissions": ["llm:invoke"],
            }
        ),
        encoding="utf-8",
    )


def test_managed_key_uses_its_dedicated_machine_principal(tmp_path: Path) -> None:
    grant = tmp_path / "primary.json"
    verifier = tmp_path / "primary.sha256"
    write_grant(grant)
    verifier.write_text(hashlib.sha256(b"managed-secret").hexdigest(), encoding="utf-8")
    app = create_app(
        settings=Settings(
            database_url="sqlite://",
            managed_primary_grant_file=str(grant),
            managed_primary_verifier_file=str(verifier),
        )
    )
    app.state.auth_info = AuthInfo("", "", "", "")
    app.state.kc_client = FakeKeycloakClient()
    app.state.keycloak_configured = True
    app.state.jwks_cache = AvailableJWKSCache()
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/validate", headers={"x-api-key": "managed-secret"})

    assert response.status_code == 200
    assert response.json()["principal"] == {"kind": "service_account", "id": "dify-service-account"}
    assert response.json()["permissions"] == ["llm:invoke"]


def test_invalid_managed_verifier_returns_generic_unavailable_error(tmp_path: Path) -> None:
    grant = tmp_path / "primary.json"
    verifier = tmp_path / "primary.sha256"
    write_grant(grant)
    verifier.write_text("invalid", encoding="utf-8")
    app = create_app(
        settings=Settings(
            database_url="sqlite://",
            managed_primary_grant_file=str(grant),
            managed_primary_verifier_file=str(verifier),
        )
    )
    app.state.auth_info = AuthInfo("", "", "", "")
    app.state.kc_client = FakeKeycloakClient()
    app.state.keycloak_configured = True
    app.state.jwks_cache = AvailableJWKSCache()
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/validate", headers={"x-api-key": "managed-secret"})

    assert response.status_code == 503
    assert response.json() == {"detail": "Managed credential configuration unavailable"}
