"""Controller tests for managed machine-principal authorization decisions."""

import hashlib
import json
import uuid
from collections.abc import Generator
from pathlib import Path

import prometheus_client
import pytest
from fastapi.testclient import TestClient

from keycloak_api_key_bridge.config.settings import AuthInfo, ManagedRegistration, Settings
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
        return "service-account" if client_id == "service-agentgateway" else None

    def get_principal_entitlements(self, principal_id: str) -> PrincipalEntitlements | None:
        if principal_id != "service-account":
            return None
        return PrincipalEntitlements(frozenset({"llm:invoke"}), frozenset())


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
                "id": "service-primary",
                "name": "service-agentgateway",
                "principal": {"kind": "service_account", "client_id": "service-agentgateway"},
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
        database_url="sqlite://",
        settings=Settings(
            managed_registrations=[
                ManagedRegistration(grant_file=str(grant), verifier_file=str(verifier))
            ],
        ),
    )
    app.state.auth_info = AuthInfo("", "", "", "")
    app.state.kc_client = FakeKeycloakClient()
    app.state.keycloak_configured = True
    app.state.jwks_cache = AvailableJWKSCache()
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/validate", headers={"x-api-key": "managed-secret"})
        repeated = client.post("/validate", headers={"Authorization": "Bearer managed-secret"})

    assert response.status_code == 200
    assert response.json() == {
        "contract_version": 1,
        "credential": {
            "id": "service-primary",
            "kind": "managed_api_key",
            "name": "service-agentgateway",
            "expires_at": None,
        },
        "principal": {"kind": "service_account", "id": "service-account"},
        "permissions": ["llm:invoke"],
        "groups": [],
    }
    expected_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            "keycloak-api-key-bridge/managed/service-agentgateway/service-primary",
        )
    )
    assert json.loads(response.headers["x-agentgateway-auth-context"]) == {
        "contract_version": response.json()["contract_version"],
        "principal_id": response.json()["principal"]["id"],
        "permissions": response.json()["permissions"],
        "groups": [],
        "credential_id": expected_id,
        "credential_kind": "managed",
    }
    assert repeated.status_code == 200
    assert (
        repeated.headers["x-agentgateway-auth-context"]
        == response.headers["x-agentgateway-auth-context"]
    )
    assert "managed-secret" not in response.headers["x-agentgateway-auth-context"]


def test_invalid_managed_verifier_returns_generic_unavailable_error(tmp_path: Path) -> None:
    grant = tmp_path / "primary.json"
    verifier = tmp_path / "primary.sha256"
    write_grant(grant)
    verifier.write_text("invalid", encoding="utf-8")
    app = create_app(
        database_url="sqlite://",
        settings=Settings(
            managed_registrations=[
                ManagedRegistration(grant_file=str(grant), verifier_file=str(verifier))
            ],
        ),
    )
    app.state.auth_info = AuthInfo("", "", "", "")
    app.state.kc_client = FakeKeycloakClient()
    app.state.keycloak_configured = True
    app.state.jwks_cache = AvailableJWKSCache()
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/validate", headers={"x-api-key": "managed-secret"})

    assert response.status_code == 503
    assert "x-agentgateway-auth-context" not in response.headers
    assert response.json() == {
        "detail": "Managed credential configuration unavailable",
        "error": {"message": "Managed credential configuration unavailable"},
    }
