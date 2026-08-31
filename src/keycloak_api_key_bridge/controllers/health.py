from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from keycloak_api_key_bridge.lib.keycloak import KeycloakUnavailableError

router = APIRouter()


@router.get("/live")
def live_check() -> dict[str, str]:
    """Liveness probe independent of external dependencies."""
    return {"status": "ok"}


@router.get("/health", response_model=None)
def health_check(request: Request) -> dict | JSONResponse:
    """Readiness probe — verifies the database and Keycloak JWKS availability.

    Returns 200 when the service is ready to serve traffic, 503 otherwise.
    """
    checks: dict[str, str] = {}

    # ── Database ──────────────────────────────────────────────────────────
    try:
        factory = request.app.state.db_factory
        with factory() as session:
            session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "checks": checks},
        )

    # ── Keycloak ──────────────────────────────────────────────────────────
    cache = request.app.state.jwks_cache
    kc_client = request.app.state.kc_client
    if not request.app.state.keycloak_configured or cache is None or kc_client is None:
        checks["keycloak"] = "misconfigured"
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "checks": checks},
        )
    if not cache.is_available():
        checks["keycloak"] = "unavailable"
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "checks": checks},
        )
    try:
        kc_client.health_check()
    except KeycloakUnavailableError:
        cache.invalidate()
        checks["keycloak"] = "unavailable"
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "checks": checks},
        )
    checks["keycloak"] = "ok"

    return {"status": "ok", "checks": checks}
