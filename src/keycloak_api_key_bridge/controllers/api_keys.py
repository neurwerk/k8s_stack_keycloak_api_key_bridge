"""API-key management and trusted authorization-decision endpoints."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Generator
from dataclasses import dataclass
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from keycloak_api_key_bridge.config.database import ApiKey, ApiKeyLimitError
from keycloak_api_key_bridge.config.settings import AuthInfo
from keycloak_api_key_bridge.lib.jwks import JWKSCache
from keycloak_api_key_bridge.lib.keycloak import (
    KeycloakClient,
    KeycloakUnavailableError,
    PrincipalEntitlements,
)
from keycloak_api_key_bridge.lib.managed_api_keys import (
    ManagedApiKey,
    ManagedApiKeyConfigurationError,
    ManagedApiKeyValidator,
)
from keycloak_api_key_bridge.lib.permissions import is_valid_permission

logger = logging.getLogger(__name__)

router = APIRouter()

ADMIN_ROLE_NAME = "api-key-admin"
_KEY_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"


class CreateApiKeyRequest(BaseModel):
    """Immutable API-key grant and bounded expiry requested by a user."""

    name: str = Field(pattern=_KEY_NAME_PATTERN)
    permissions: list[str] = Field(min_length=1, max_length=128)
    expires_in_days: int = Field(ge=1, le=365)
    target_user_id: str | None = None

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, permissions: list[str]) -> list[str]:
        """Reject duplicate or non-contract permission names before persistence."""
        if len(set(permissions)) != len(permissions):
            raise ValueError("permissions must not contain duplicates")
        if any(not is_valid_permission(permission) for permission in permissions):
            raise ValueError("permissions must use the AgentGateway permission namespace")
        return sorted(permissions)


@dataclass(frozen=True)
class CurrentUser:
    """Verified Keycloak token data used by management endpoints."""

    user_id: str
    realm_roles: frozenset[str]


def get_db(request: Request) -> Generator[Session, None, None]:
    """Yield a per-request database session."""
    session = request.app.state.db_factory()
    try:
        yield session
    finally:
        session.close()


def get_auth_info(request: Request) -> AuthInfo:
    """Return the configured Keycloak contract."""
    return request.app.state.auth_info


def get_kc_client(request: Request) -> KeycloakClient | None:
    """Return the shared pooled Keycloak client."""
    return request.app.state.kc_client


def get_managed_api_keys(request: Request) -> ManagedApiKeyValidator:
    """Return the hot-reloading managed-key descriptor validator."""
    return request.app.state.managed_api_keys


def get_max_keys_per_user(request: Request) -> int:
    """Return the configured maximum number of stored keys per user."""
    return request.app.state.max_keys_per_user


def get_current_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> CurrentUser:
    """Validate a management JWT and return its stable realm-role identity."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    cache = request.app.state.jwks_cache
    if not request.app.state.keycloak_configured or cache is None or not cache.is_available():
        raise HTTPException(status_code=503, detail="Keycloak authentication is unavailable")
    token = authorization.removeprefix("Bearer ")
    try:
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise HTTPException(status_code=401, detail="Token missing signing key identifier")
    signing_key = cache.get_key(kid)
    if signing_key is None:
        if not cache.refresh():
            raise HTTPException(status_code=503, detail="Keycloak authentication is unavailable")
        signing_key = cache.get_key(kid)
        if signing_key is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    try:
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=request.app.state.auth_info.client_id,
            issuer=request.app.state.auth_info.issuer,
            options={"require_aud": True, "require_exp": True, "require_iat": True},
        )
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    user_id = payload.get("sub")
    if not isinstance(user_id, str) or not user_id:
        raise HTTPException(status_code=401, detail="Token missing 'sub' claim")
    realm_access = payload.get("realm_access")
    roles = realm_access.get("roles", []) if isinstance(realm_access, dict) else []
    return CurrentUser(
        user_id=user_id,
        realm_roles=frozenset(role for role in roles if isinstance(role, str)),
    )


def _resolve_target_user_id(
    target_user_id: str | None, current_user: CurrentUser
) -> tuple[str, str | None]:
    """Return target identity and optional acting administrator identity."""
    if target_user_id is None or target_user_id == current_user.user_id:
        return current_user.user_id, None
    if ADMIN_ROLE_NAME not in current_user.realm_roles:
        raise HTTPException(status_code=403, detail="Admin role required")
    return target_user_id, current_user.user_id


def _entitlements_or_error(
    kc: KeycloakClient | None,
    principal_id: str,
    *,
    missing_status: int,
    jwks_cache: JWKSCache,
) -> PrincipalEntitlements:
    """Resolve live entitlements and translate Keycloak states to HTTP errors."""
    if kc is None:
        raise HTTPException(status_code=503, detail="Keycloak authorization unavailable")
    try:
        entitlements = kc.get_principal_entitlements(principal_id)
    except KeycloakUnavailableError as exc:
        kc.mark_unavailable()
        jwks_cache.invalidate()
        raise HTTPException(status_code=503, detail="Keycloak authorization unavailable") from exc
    if entitlements is None:
        raise HTTPException(status_code=missing_status, detail="Keycloak principal is unavailable")
    return entitlements


@router.get("/me")
def me(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    auth_info: Annotated[AuthInfo, Depends(get_auth_info)],
) -> dict[str, str]:
    """Return information about the currently authenticated user."""
    return {"user_id": current_user.user_id, "realm": auth_info.realm}


@router.get("/permissions")
def get_permissions(
    request: Request,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    kc: Annotated[KeycloakClient | None, Depends(get_kc_client)],
    query_user_id: Annotated[str | None, Query(alias="user_id")] = None,
) -> dict[str, list[str]]:
    """Return only the target principal's current valid AgentGateway permissions."""
    target_user_id, _ = _resolve_target_user_id(query_user_id, current_user)
    entitlements = _entitlements_or_error(
        kc,
        target_user_id,
        missing_status=404,
        jwks_cache=request.app.state.jwks_cache,
    )
    return {
        "permissions": sorted(
            permission for permission in entitlements.permissions if is_valid_permission(permission)
        )
    }


@router.post("/api_keys")
def create_api_key(
    request: Request,
    body: CreateApiKeyRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    kc: Annotated[KeycloakClient | None, Depends(get_kc_client)],
    max_keys_per_user: Annotated[int, Depends(get_max_keys_per_user)],
) -> dict[str, str | list[str]]:
    """Create an expiring key with an immutable subset of live entitlements."""
    target_user_id, created_by = _resolve_target_user_id(body.target_user_id, current_user)
    entitlements = _entitlements_or_error(
        kc,
        target_user_id,
        missing_status=404,
        jwks_cache=request.app.state.jwks_cache,
    )
    requested_permissions = frozenset(body.permissions)
    if not requested_permissions.issubset(entitlements.permissions):
        raise HTTPException(
            status_code=403, detail="Requested permissions are not currently granted"
        )
    try:
        key_id, key_value = ApiKey.create_key(
            db,
            name=body.name,
            user_id=target_user_id,
            permissions=body.permissions,
            validity_days=body.expires_in_days,
            created_by_user_id=created_by,
            max_keys_per_user=max_keys_per_user,
        )
    except ApiKeyLimitError as exc:
        raise HTTPException(
            status_code=409,
            detail="API key limit reached; revoke an existing key before creating another",
        ) from exc
    logger.info("Created key %s for user %s", key_id, target_user_id)
    return {
        "id": key_id,
        "api_key": key_value,
        "key_prefix": key_value[:8],
        "permissions": body.permissions,
    }


@router.post("/api_keys/{key_id}/revoke")
def revoke_api_key(
    key_id: str,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, str]:
    """Revoke an existing key owned by the caller or an API-key administrator."""
    if ADMIN_ROLE_NAME in current_user.realm_roles:
        revoked = ApiKey.revoke_key_as_admin(db, key_id)
    else:
        revoked = ApiKey.revoke_key(db, key_id, current_user.user_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="Key not found")
    logger.info("Revoked key %s requested by user %s", key_id, current_user.user_id)
    return {"detail": "Key revoked"}


@router.get("/api_keys")
def list_api_keys(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    max_keys_per_user: Annotated[int, Depends(get_max_keys_per_user)],
    query_user_id: Annotated[str | None, Query(alias="user_id")] = None,
) -> list[dict]:
    """List a bounded set of keys for the caller or an authorized target user."""
    target_user_id, _ = _resolve_target_user_id(query_user_id, current_user)
    return ApiKey.list_keys(db, target_user_id, max_keys_per_user)


@router.get("/validate")
@router.post("/validate")
def validate_key(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="x-api-key")] = None,
    db: Session = Depends(get_db),
    kc: KeycloakClient | None = Depends(get_kc_client),
    managed_api_keys: ManagedApiKeyValidator = Depends(get_managed_api_keys),
) -> JSONResponse:
    """Validate a credential and return a versioned trusted authorization decision."""
    cache = request.app.state.jwks_cache
    if not request.app.state.keycloak_configured or cache is None or not cache.is_available():
        raise HTTPException(status_code=503, detail="Keycloak authorization unavailable")
    key_value = x_api_key or _bearer_api_key(request)
    if not key_value:
        raise HTTPException(status_code=401, detail="An API key must be passed as a header")
    try:
        managed_key = managed_api_keys.match(key_value)
    except ManagedApiKeyConfigurationError as exc:
        logger.error("Managed API-key configuration is invalid")
        raise HTTPException(
            status_code=503, detail="Managed credential configuration unavailable"
        ) from exc
    if managed_key is not None:
        return _managed_key_response(managed_key, kc, cache)

    key = ApiKey.get_key(db, key_value)
    if key is None:
        logger.warning(
            "Validation failed for unknown credential hash=%s", _key_hash_prefix(key_value)
        )
        raise HTTPException(status_code=401, detail="Invalid or expired key")
    entitlements = _entitlements_or_error(
        kc,
        key["user_id"],
        missing_status=401,
        jwks_cache=cache,
    )
    permissions = sorted(set(key["permissions"]).intersection(entitlements.permissions))
    return _decision_response(
        credential_id=key["id"],
        credential_kind="user_api_key",
        credential_name=key["name"],
        expires_at=key["expires_at"],
        principal_kind="user",
        principal_id=key["user_id"],
        permissions=permissions,
    )


def _bearer_api_key(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "")
    return authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else None


def _managed_key_response(
    managed_key: ManagedApiKey, kc: KeycloakClient | None, jwks_cache: JWKSCache
) -> JSONResponse:
    """Resolve a managed descriptor's machine principal and current permissions."""
    if kc is None:
        raise HTTPException(status_code=503, detail="Keycloak authorization unavailable")
    try:
        principal_id = kc.get_service_account_user_id(managed_key.principal_client_id)
    except KeycloakUnavailableError as exc:
        kc.mark_unavailable()
        jwks_cache.invalidate()
        raise HTTPException(status_code=503, detail="Keycloak authorization unavailable") from exc
    if principal_id is None:
        raise HTTPException(status_code=401, detail="Managed credential principal unavailable")
    entitlements = _entitlements_or_error(
        kc,
        principal_id,
        missing_status=401,
        jwks_cache=jwks_cache,
    )
    permissions = sorted(set(managed_key.permissions).intersection(entitlements.permissions))
    return _decision_response(
        credential_id=managed_key.key_id,
        credential_kind="managed_api_key",
        credential_name=managed_key.name,
        expires_at=None,
        principal_kind="service_account",
        principal_id=principal_id,
        permissions=permissions,
    )


def _decision_response(
    *,
    credential_id: str,
    credential_kind: str,
    credential_name: str,
    expires_at: str | None,
    principal_kind: str,
    principal_id: str,
    permissions: list[str],
) -> JSONResponse:
    """Return the stable body consumed as AgentGateway extAuth metadata."""
    return JSONResponse(
        {
            "contract_version": 1,
            "credential": {
                "id": credential_id,
                "kind": credential_kind,
                "name": credential_name,
                "expires_at": expires_at,
            },
            "principal": {"kind": principal_kind, "id": principal_id},
            "permissions": permissions,
        }
    )


def _key_hash_prefix(key_value: str) -> str:
    """Return a non-secret correlation value for authentication-failure logs."""
    return hashlib.sha256(key_value.encode()).hexdigest()[:12]
