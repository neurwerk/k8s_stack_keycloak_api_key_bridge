"""Pooled, fail-closed Keycloak client for authorization lookups."""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
from dataclasses import dataclass

import httpx

from keycloak_api_key_bridge.config.settings import AuthInfo
from keycloak_api_key_bridge.lib.permissions import is_valid_permission

logger = logging.getLogger(__name__)


class KeycloakUnavailableError(RuntimeError):
    """Keycloak could not answer an authorization-critical request."""


@dataclass(frozen=True)
class PrincipalEntitlements:
    """The current AgentGateway permissions of an enabled Keycloak principal."""

    permissions: frozenset[str]


class KeycloakClient:
    """Resolve current principal state and AgentGateway client-role entitlements."""

    def __init__(
        self,
        auth: AuthInfo,
        *,
        agentgateway_client_id: str = "agentgateway",
        timeout_seconds: float = 1.0,
        entitlement_cache_ttl_seconds: int = 30,
        negative_cache_ttl_seconds: int = 5,
        client: httpx.Client | None = None,
    ) -> None:
        self._base = f"{auth.server_url.rstrip('/')}/admin/realms/{auth.realm}"
        self._auth = auth
        self._agentgateway_client_id = agentgateway_client_id
        self._entitlement_cache_ttl_seconds = entitlement_cache_ttl_seconds
        self._negative_cache_ttl_seconds = negative_cache_ttl_seconds
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
        self._token: str | None = None
        self._token_expiry = 0.0
        self._client_ids: dict[str, str] = {}
        self._entitlement_cache: dict[str, tuple[float, PrincipalEntitlements | None]] = {}
        self._lock = threading.Lock()

    def close(self) -> None:
        """Close pooled outbound connections during application shutdown."""
        self._client.close()

    def fetch_jwks(self) -> dict:
        """Fetch the realm JWKS document."""
        url = (
            f"{self._auth.server_url.rstrip('/')}/realms/{self._auth.realm}"
            "/protocol/openid-connect/certs"
        )
        try:
            response = self._client.get(url)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise KeycloakUnavailableError("could not fetch Keycloak JWKS") from exc
        if not isinstance(data, dict):
            raise KeycloakUnavailableError("Keycloak JWKS response is not an object")
        return data

    def health_check(self) -> None:
        """Verify the authenticated Keycloak authorization path is available."""
        try:
            response = self._client.get(
                f"{self._base}/clients",
                params={"clientId": self._agentgateway_client_id},
                headers=self._headers(),
            )
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            self.mark_unavailable()
            raise KeycloakUnavailableError("could not verify Keycloak authorization") from exc
        if not isinstance(data, list) or not data:
            self.mark_unavailable()
            raise KeycloakUnavailableError("Keycloak authorization client is unavailable")

    def mark_unavailable(self) -> None:
        """Discard authorization state after Keycloak becomes unavailable."""
        with self._lock:
            self._entitlement_cache.clear()
            self._token = None
            self._token_expiry = 0.0

    def get_principal_entitlements(self, principal_id: str) -> PrincipalEntitlements | None:
        """Return current permissions for an enabled principal, or ``None`` if unavailable.

        A ``None`` result means Keycloak successfully reported a missing or
        disabled principal. Transport and server failures raise
        :class:`KeycloakUnavailableError` so callers can return ``503`` rather
        than confusing an authorization outage with an invalid credential.
        """
        now = time.monotonic()
        with self._lock:
            cached = self._entitlement_cache.get(principal_id)
            if cached is not None and now < cached[0]:
                return cached[1]

        value = self._fetch_principal_entitlements(principal_id)
        ttl = (
            self._entitlement_cache_ttl_seconds
            if value is not None
            else self._negative_cache_ttl_seconds
        )
        with self._lock:
            self._entitlement_cache[principal_id] = (time.monotonic() + ttl, value)
        return value

    def get_service_account_user_id(self, client_id: str) -> str | None:
        """Resolve the service-account user ID for a confidential client."""
        client_uuid = self._get_client_uuid(client_id)
        try:
            response = self._client.get(
                f"{self._base}/clients/{client_uuid}/service-account-user",
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            raise KeycloakUnavailableError("could not resolve Keycloak service account") from exc
        if response.status_code == 404:
            return None
        try:
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise KeycloakUnavailableError("could not read Keycloak service account") from exc
        user_id = data.get("id") if isinstance(data, dict) else None
        return user_id if isinstance(user_id, str) and user_id else None

    def _fetch_principal_entitlements(self, principal_id: str) -> PrincipalEntitlements | None:
        user = self._get_user(principal_id)
        if user is None or not user.get("enabled", False):
            return None
        client_uuid = self._get_client_uuid(self._agentgateway_client_id)
        try:
            response = self._client.get(
                f"{self._base}/users/{principal_id}/role-mappings/clients/{client_uuid}/composite",
                headers=self._headers(),
            )
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise KeycloakUnavailableError("could not resolve Keycloak role mappings") from exc
        if not isinstance(data, list):
            raise KeycloakUnavailableError("Keycloak role-mapping response is not a list")
        permissions = frozenset(
            role["name"]
            for role in data
            if isinstance(role, dict)
            and isinstance(role.get("name"), str)
            and is_valid_permission(role["name"])
        )
        return PrincipalEntitlements(permissions=permissions)

    def _get_user(self, user_id: str) -> dict | None:
        try:
            response = self._client.get(f"{self._base}/users/{user_id}", headers=self._headers())
        except httpx.HTTPError as exc:
            raise KeycloakUnavailableError("could not resolve Keycloak user") from exc
        if response.status_code == 404:
            return None
        try:
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise KeycloakUnavailableError("could not read Keycloak user") from exc
        if not isinstance(data, dict):
            raise KeycloakUnavailableError("Keycloak user response is not an object")
        return data

    def _get_client_uuid(self, client_id: str) -> str:
        with self._lock:
            cached = self._client_ids.get(client_id)
            if cached is not None:
                return cached
        try:
            response = self._client.get(
                f"{self._base}/clients",
                params={"clientId": client_id},
                headers=self._headers(),
            )
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise KeycloakUnavailableError("could not resolve Keycloak client") from exc
        if not isinstance(data, list) or not data or not isinstance(data[0], dict):
            raise KeycloakUnavailableError(f"Keycloak client '{client_id}' does not exist")
        client_uuid = data[0].get("id")
        if not isinstance(client_uuid, str) or not client_uuid:
            raise KeycloakUnavailableError(f"Keycloak client '{client_id}' has no ID")
        with self._lock:
            self._client_ids[client_id] = client_uuid
        return client_uuid

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token()}"}

    def _get_token(self) -> str:
        with self._lock:
            if self._token is not None and time.time() < self._token_expiry - 60:
                return self._token
            self._acquire_token()
            if self._token is None:
                raise KeycloakUnavailableError("Keycloak token response has no access token")
            return self._token

    def _acquire_token(self) -> None:
        url = (
            f"{self._auth.server_url.rstrip('/')}/realms/{self._auth.realm}"
            "/protocol/openid-connect/token"
        )
        try:
            response = self._client.post(
                url,
                data={
                    "client_id": self._auth.client_id,
                    "client_secret": self._auth.client_secret,
                    "grant_type": "client_credentials",
                },
            )
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise KeycloakUnavailableError("could not acquire Keycloak service token") from exc
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise KeycloakUnavailableError("Keycloak token response has no access token")
        expiry = _decode_jwt_expiry(token)
        if expiry <= time.time():
            raise KeycloakUnavailableError("Keycloak service token has an invalid expiry")
        self._token = token
        self._token_expiry = expiry


def _decode_jwt_expiry(token: str) -> float:
    """Read the unverified ``exp`` claim needed only for client-token caching."""
    try:
        encoded = token.split(".")[1]
        encoded += "=" * ((4 - len(encoded) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded))
        expiry = float(payload["exp"])
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return 0.0
    return expiry
