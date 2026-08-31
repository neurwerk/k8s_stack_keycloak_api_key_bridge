"""Validate hot-reloaded managed API-key grants and secret verifiers."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path

from keycloak_api_key_bridge.lib.permissions import is_valid_permission

_VERIFIER_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CLIENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ManagedApiKeyConfigurationError(Exception):
    """A configured managed API-key slot cannot be read safely."""


@dataclass(frozen=True)
class ManagedApiKey:
    """Metadata from a matched managed API-key descriptor."""

    slot: str
    key_id: str
    name: str
    principal_client_id: str
    permissions: tuple[str, ...]


@dataclass(frozen=True)
class _ManagedApiKeyVerifier:
    key: ManagedApiKey
    verifier: str


class ManagedApiKeyValidator:
    """Load and validate primary and secondary managed API-key slots."""

    def __init__(
        self,
        primary_grant_file: str = "",
        primary_verifier_file: str = "",
        secondary_grant_file: str = "",
        secondary_verifier_file: str = "",
    ) -> None:
        self._files = (
            ("primary", primary_grant_file, primary_verifier_file),
            ("secondary", secondary_grant_file, secondary_verifier_file),
        )

    def match(self, key_value: str) -> ManagedApiKey | None:
        """Return a matching descriptor after reloading configured slot files."""
        verifiers = [
            verifier
            for slot, grant_file, verifier_file in self._files
            if (verifier := self._load_slot(slot, grant_file, verifier_file)) is not None
        ]
        candidate = hashlib.sha256(key_value.encode()).hexdigest()
        for verifier in verifiers:
            if hmac.compare_digest(candidate, verifier.verifier):
                return verifier.key
        return None

    @staticmethod
    def _load_slot(slot: str, grant_file: str, verifier_file: str) -> _ManagedApiKeyVerifier | None:
        if not grant_file and not verifier_file:
            return None
        if not grant_file or not verifier_file:
            raise ManagedApiKeyConfigurationError(f"managed slot {slot} is incomplete")
        try:
            grant_content = Path(grant_file).read_text(encoding="utf-8")
            verifier_content = Path(verifier_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise ManagedApiKeyConfigurationError(f"managed slot {slot} is unreadable") from exc
        if not verifier_content.strip() and slot == "secondary":
            return None
        return _ManagedApiKeyVerifier(
            key=_parse_grant(slot, grant_content),
            verifier=_parse_verifier(slot, verifier_content),
        )


def _parse_grant(slot: str, content: str) -> ManagedApiKey:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ManagedApiKeyConfigurationError(
            f"managed slot {slot} grant is not valid JSON"
        ) from exc
    required_fields = {"version", "id", "name", "principal", "permissions"}
    if not isinstance(data, dict) or set(data) != required_fields:
        raise ManagedApiKeyConfigurationError(f"managed slot {slot} grant has invalid fields")
    if data["version"] != 2:
        raise ManagedApiKeyConfigurationError(
            f"managed slot {slot} grant has an unsupported version"
        )
    key_id = data["id"]
    name = data["name"]
    principal = data["principal"]
    permissions = data["permissions"]
    if not isinstance(key_id, str) or _KEY_ID_PATTERN.fullmatch(key_id) is None:
        raise ManagedApiKeyConfigurationError(f"managed slot {slot} has an invalid id")
    if not isinstance(name, str) or _KEY_ID_PATTERN.fullmatch(name) is None:
        raise ManagedApiKeyConfigurationError(f"managed slot {slot} has an invalid name")
    if not isinstance(principal, dict) or set(principal) != {"kind", "client_id"}:
        raise ManagedApiKeyConfigurationError(f"managed slot {slot} has an invalid principal")
    client_id = principal.get("client_id")
    if principal.get("kind") != "service_account" or not isinstance(client_id, str):
        raise ManagedApiKeyConfigurationError(f"managed slot {slot} has an invalid principal")
    if _CLIENT_ID_PATTERN.fullmatch(client_id) is None:
        raise ManagedApiKeyConfigurationError(f"managed slot {slot} has an invalid client ID")
    if (
        not isinstance(permissions, list)
        or not permissions
        or not all(
            isinstance(permission, str) and is_valid_permission(permission)
            for permission in permissions
        )
        or len(set(permissions)) != len(permissions)
    ):
        raise ManagedApiKeyConfigurationError(f"managed slot {slot} has invalid permissions")
    return ManagedApiKey(
        slot=slot,
        key_id=key_id,
        name=name,
        principal_client_id=client_id,
        permissions=tuple(sorted(permissions)),
    )


def _parse_verifier(slot: str, content: str) -> str:
    verifier = content.strip()
    if _VERIFIER_PATTERN.fullmatch(verifier) is None:
        raise ManagedApiKeyConfigurationError(f"managed slot {slot} has an invalid verifier")
    return verifier
