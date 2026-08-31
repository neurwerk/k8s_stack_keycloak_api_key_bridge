"""FastAPI application entry point for the Keycloak API Key bridge service."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import version as get_version

import uvicorn
from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator

from keycloak_api_key_bridge.config.database import create_engine_and_session_factory
from keycloak_api_key_bridge.config.settings import Settings, build_auth_info
from keycloak_api_key_bridge.controllers.api_keys import router as api_keys_router
from keycloak_api_key_bridge.controllers.health import router as health_router
from keycloak_api_key_bridge.lib.jwks import JWKSCache
from keycloak_api_key_bridge.lib.keycloak import KeycloakClient
from keycloak_api_key_bridge.lib.managed_api_keys import ManagedApiKeyValidator

logger = logging.getLogger(__name__)


def create_app(database_url: str | None = None, settings: Settings | None = None) -> FastAPI:
    """Build and configure the FastAPI application.

    *database_url*, when provided, overrides the ``DATABASE_URL`` setting
    (useful for in-memory SQLite during tests).
    """
    settings = settings or Settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    @asynccontextmanager
    async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
        jwks_cache = getattr(_app.state, "jwks_cache", None)
        if jwks_cache is not None:
            jwks_cache.start()
        try:
            yield
        finally:
            if jwks_cache is not None:
                jwks_cache.stop()
            engine = getattr(_app.state, "db_engine", None)
            if engine is not None:
                engine.dispose()
                logger.info("Database engine disposed")
            kc_client = getattr(_app.state, "kc_client", None)
            if kc_client is not None:
                kc_client.close()
                logger.info("Keycloak HTTP client closed")

    app = FastAPI(
        title="Keycloak API Key Bridge",
        version=get_version("keycloak-api-key-bridge"),
        docs_url=None,
        redoc_url=None,
        lifespan=_lifespan,
    )

    db_url = database_url if database_url is not None else settings.database_url
    app.state.db_engine, app.state.db_factory = create_engine_and_session_factory(db_url)
    app.state.auth_info = build_auth_info(settings)
    app.state.max_keys_per_user = settings.max_keys_per_user
    app.state.managed_api_keys = ManagedApiKeyValidator(
        primary_grant_file=settings.managed_primary_grant_file,
        primary_verifier_file=settings.managed_primary_verifier_file,
        secondary_grant_file=settings.managed_secondary_grant_file,
        secondary_verifier_file=settings.managed_secondary_verifier_file,
    )

    # ── Singleton KeycloakClient ──────────────────────────────────────────
    # Created once at startup so the admin token (client_credentials) is cached
    # for the pod lifetime. Without this, every /validate call acquires a fresh
    # token (~170 ms) and user lookup (~170 ms), totalling ~340 ms which exceeds
    # the AgentGateway extAuthz 200 ms timeout.
    app.state.keycloak_configured = all(
        (
            app.state.auth_info.server_url,
            app.state.auth_info.realm,
            app.state.auth_info.issuer,
            app.state.auth_info.client_id,
            app.state.auth_info.client_secret,
        )
    )
    if not app.state.keycloak_configured:
        logger.error("Keycloak configuration is incomplete; bridge is unavailable")
    app.state.kc_client = (
        KeycloakClient(
            app.state.auth_info,
            agentgateway_client_id=settings.agentgateway_client_id,
            timeout_seconds=settings.keycloak_timeout_seconds,
            entitlement_cache_ttl_seconds=settings.entitlement_cache_ttl_seconds,
            negative_cache_ttl_seconds=settings.negative_entitlement_cache_ttl_seconds,
        )
        if app.state.keycloak_configured
        else None
    )

    # ── JWKS cache ─────────────────────────────────────────────────────────
    app.state.jwks_cache = (
        JWKSCache(
            app.state.kc_client,
            refresh_interval_seconds=settings.jwks_refresh_interval_seconds,
            retry_interval_seconds=settings.jwks_retry_interval_seconds,
        )
        if app.state.kc_client is not None
        else None
    )

    app.include_router(health_router)
    app.include_router(api_keys_router)

    # ── Prometheus metrics ─────────────────────────────────────────────────
    # Register after routers so the /metrics endpoint is added to the final
    # route table.
    Instrumentator(
        should_group_status_codes=False,
        should_ignore_untemplated=True,
        should_respect_env_var=False,
        should_instrument_requests_inprogress=True,
        excluded_handlers=["/health", "/metrics"],
        inprogress_name="http_requests_inprogress",
        inprogress_labels=True,
    ).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

    return app


def main() -> None:
    """CLI entry point — start the server with uvicorn."""
    settings = Settings()
    uvicorn.run(
        "keycloak_api_key_bridge.main:create_app",
        host=settings.host,
        port=settings.port,
        factory=True,
        log_level=settings.log_level,
    )
