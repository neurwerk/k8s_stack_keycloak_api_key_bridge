"""Fail-closed in-memory cache for Keycloak signing keys."""

from __future__ import annotations

import logging
import threading
from collections.abc import Mapping
from typing import cast

from keycloak_api_key_bridge.lib.keycloak import KeycloakClient

logger = logging.getLogger(__name__)

Jwk = dict[str, object]


class JWKSCache:
    """Refresh Keycloak signing keys without serving them after a failed refresh."""

    def __init__(
        self,
        client: KeycloakClient,
        *,
        refresh_interval_seconds: float,
        retry_interval_seconds: float,
    ) -> None:
        self._client = client
        self._refresh_interval_seconds = refresh_interval_seconds
        self._retry_interval_seconds = retry_interval_seconds
        self._keys: dict[str, Jwk] | None = None
        self._lock = threading.Lock()
        self._refresh_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start periodic refreshes, including an immediate initial fetch."""
        with self._lock:
            if self._thread is not None:
                return
            self._thread = threading.Thread(target=self._run, daemon=True, name="jwks-refresh")
            self._thread.start()

    def stop(self) -> None:
        """Stop refreshing before the shared Keycloak client is closed."""
        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None:
            thread.join()

    def refresh(self) -> bool:
        """Fetch and replace the signing keys, clearing them on any failure."""
        with self._refresh_lock:
            try:
                keys = _parse_jwks(self._client.fetch_jwks())
            except Exception:
                logger.warning(
                    "Keycloak JWKS refresh failed; authentication is unavailable", exc_info=True
                )
                self._client.mark_unavailable()
                self.invalidate()
                return False
            with self._lock:
                self._keys = keys
            logger.info("Keycloak JWKS refreshed with %d signing keys", len(keys))
            return True

    def get_key(self, kid: str) -> Jwk | None:
        """Return the current signing key for *kid*, if Keycloak is available."""
        with self._lock:
            return None if self._keys is None else self._keys.get(kid)

    def is_available(self) -> bool:
        """Return whether the latest Keycloak JWKS refresh succeeded."""
        with self._lock:
            return self._keys is not None

    def invalidate(self) -> None:
        """Prevent authenticated operations from using a previously fetched JWKS."""
        with self._lock:
            self._keys = None

    def _run(self) -> None:
        while not self._stop.is_set():
            succeeded = self.refresh()
            delay = self._refresh_interval_seconds if succeeded else self._retry_interval_seconds
            self._stop.wait(delay)


def _parse_jwks(document: Mapping[str, object]) -> dict[str, Jwk]:
    """Return uniquely identified RSA signing keys from a Keycloak JWKS document."""
    raw_keys = document.get("keys")
    if not isinstance(raw_keys, list):
        raise ValueError("JWKS has no keys list")

    keys: dict[str, Jwk] = {}
    for raw_key in raw_keys:
        if not isinstance(raw_key, dict):
            raise ValueError("JWKS contains a non-object key")
        if raw_key.get("use") not in (None, "sig"):
            continue
        if raw_key.get("kty") != "RSA" or raw_key.get("alg") != "RS256":
            continue
        kid = raw_key.get("kid")
        if not isinstance(kid, str) or not kid:
            raise ValueError("JWKS signing key has no kid")
        if not isinstance(raw_key.get("n"), str) or not isinstance(raw_key.get("e"), str):
            raise ValueError("JWKS RSA signing key is incomplete")
        if kid in keys:
            raise ValueError("JWKS contains duplicate signing key identifiers")
        keys[kid] = cast(Jwk, raw_key)

    if not keys:
        raise ValueError("JWKS has no usable signing keys")
    return keys
