"""Application settings and Keycloak authentication configuration."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


@dataclass(frozen=True)
class AuthInfo:
    """Keycloak OIDC configuration bundled for dependency injection."""

    server_url: str
    realm: str
    client_id: str
    client_secret: str
    issuer: str = ""


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Prefix: ``KEYCLOAK_API_KEY_BRIDGE_``.
    """

    model_config = SettingsConfigDict(
        env_prefix="KEYCLOAK_API_KEY_BRIDGE_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    keycloak_url: str = ""
    keycloak_realm: str = ""
    keycloak_issuer: str = ""
    keycloak_client_id: str = ""
    keycloak_client_secret: str = ""
    agentgateway_client_id: str = "agentgateway"
    keycloak_timeout_seconds: float = Field(default=1.0, gt=0, le=5)
    jwks_refresh_interval_seconds: int = Field(default=10, ge=1, le=300)
    jwks_retry_interval_seconds: int = Field(default=5, ge=1, le=60)
    entitlement_cache_ttl_seconds: int = Field(default=30, ge=1, le=300)
    negative_entitlement_cache_ttl_seconds: int = Field(default=5, ge=1, le=60)

    database_url: str = "sqlite:///data/api_keys.db"
    max_keys_per_user: int = Field(default=20, ge=1, le=100)

    managed_primary_grant_file: str = ""
    managed_primary_verifier_file: str = ""
    managed_secondary_grant_file: str = ""
    managed_secondary_verifier_file: str = ""

    host: str = "0.0.0.0"
    port: int = 8000

    log_level: str = "info"


def build_auth_info(settings: Settings) -> AuthInfo:
    """Build an :class:`AuthInfo` from settings."""
    return AuthInfo(
        server_url=settings.keycloak_url,
        issuer=settings.keycloak_issuer,
        realm=settings.keycloak_realm,
        client_id=settings.keycloak_client_id,
        client_secret=settings.keycloak_client_secret,
    )
