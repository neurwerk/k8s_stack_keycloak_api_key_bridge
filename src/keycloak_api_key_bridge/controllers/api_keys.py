"""API-key management and trusted authorization-decision endpoints."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import re
import uuid
from collections.abc import Generator
from dataclasses import dataclass
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select, tuple_
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
_MAX_AUTHORIZATION_HEADER_LENGTH = 8192
_AUTHORIZATION_PATTERN = re.compile(r"([A-Za-z]+) +([A-Za-z0-9._~+/-]+=*)")


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
    payload = _verified_token(request, authorization, request.app.state.auth_info.client_id)
    user_id = payload.get("sub")
    if not isinstance(user_id, str) or not user_id:
        raise HTTPException(status_code=401, detail="Token missing 'sub' claim")
    realm_access = payload.get("realm_access")
    roles = realm_access.get("roles", []) if isinstance(realm_access, dict) else []
    return CurrentUser(
        user_id=user_id,
        realm_roles=frozenset(role for role in roles if isinstance(role, str)),
    )


def _verified_token(request: Request, authorization: str | None, audience: str) -> dict:
    """Verify a signed Keycloak token for one audience."""
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
            audience=audience,
            issuer=request.app.state.auth_info.issuer,
            options={"require_aud": True, "require_exp": True, "require_iat": True},
        )
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    return payload


class GatewayCallerPermissionsRequest(BaseModel):
    """Select an enabled discovery binding, never a caller-supplied OIDC client."""

    model_config = ConfigDict(extra="forbid", strict=True)

    binding_id: str = Field(min_length=1)


@router.post("/gateway/caller-permissions")
def gateway_caller_permissions(
    request: Request,
    body: GatewayCallerPermissionsRequest,
    db: Session = Depends(get_db),
    kc: KeycloakClient | None = Depends(get_kc_client),
    managed_api_keys: ManagedApiKeyValidator = Depends(get_managed_api_keys),
) -> dict[str, list[str]]:
    """Return effective permissions for a key or a verified gateway-audience token."""
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")
    approved_clients = request.app.state.gateway_caller_oidc_clients_by_binding.get(body.binding_id)
    if approved_clients is None:
        raise HTTPException(status_code=403, detail="Unknown or disabled discovery binding")
    if "x-neurwerk-authorization" in request.headers:
        credential = _dedicated_api_key(request, "neurwerk")
        try:
            decision = _validate_key(request, credential, db, kc, managed_api_keys)
            return {"permissions": json.loads(bytes(decision.body))["permissions"]}
        except HTTPException as exc:
            if exc.status_code != 401 or exc.detail != "Invalid or expired key":
                raise
        authorization = f"Bearer {credential}"
    else:
        values = request.headers.getlist("authorization")
        authorization = values[0] if len(values) == 1 else None
    client_id = request.app.state.agentgateway_client_id
    payload = _verified_token(request, authorization, client_id)
    if not isinstance(payload.get("sub"), str) or not payload["sub"]:
        raise HTTPException(status_code=401, detail="Invalid gateway identity")
    azp = payload.get("azp")
    if not isinstance(azp, str) or (azp != client_id and azp not in approved_clients):
        raise HTTPException(status_code=403, detail="Client not approved for gateway access")
    access = payload.get("resource_access", {})
    if not isinstance(access, dict):
        raise HTTPException(status_code=403, detail="Invalid gateway permissions")
    gateway = access.get(client_id, {})
    if not isinstance(gateway, dict):
        raise HTTPException(status_code=403, detail="Invalid gateway permissions")
    roles = gateway.get("roles", [])
    if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
        raise HTTPException(status_code=403, detail="Invalid gateway permissions")
    return {"permissions": sorted({role for role in roles if is_valid_permission(role)})}


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


class UsageKeyReference(BaseModel):
    """A non-secret key ID with its recorded principal and credential kind."""

    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(min_length=1, max_length=255)
    user_id: str = Field(min_length=1, max_length=255)
    kind: Literal["personal", "managed"]


class UsageKeyMetadataRequest(BaseModel):
    """Bound metadata work independently of the number of usage records."""

    model_config = ConfigDict(extra="forbid", strict=True)

    keys: list[UsageKeyReference] = Field(max_length=500)


class UsageKeyMetadata(UsageKeyReference):
    """Allowlisted display metadata, without prefixes, grants, hashes or secrets."""

    name: str


@router.post("/usage/key-metadata", response_model=list[UsageKeyMetadata])
def usage_key_metadata(
    body: UsageKeyMetadataRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    managed_api_keys: Annotated[ManagedApiKeyValidator, Depends(get_managed_api_keys)],
    kc: Annotated[KeycloakClient | None, Depends(get_kc_client)],
) -> JSONResponse:
    """Resolve exact owned IDs in bulk; usage administration grants no key management."""
    is_admin = "langfuse-admin" in current_user.realm_roles
    if not is_admin and any(
        key.user_id != current_user.user_id or key.kind != "personal" for key in body.keys
    ):
        raise HTTPException(status_code=403, detail="Usage metadata is self-only")
    personal_ids = {(key.id, key.user_id) for key in body.keys if key.kind == "personal"}
    rows = db.execute(
        select(ApiKey.id, ApiKey.user_id, ApiKey.name).where(
            tuple_(ApiKey.id, ApiKey.user_id).in_(personal_ids)
        )
    ).all()
    names = {(row.id, row.user_id, "personal"): row.name for row in rows}
    if is_admin and any(key.kind == "managed" for key in body.keys):
        names.update(_managed_usage_names(body.keys, managed_api_keys, kc))
    result = [
        UsageKeyMetadata(**key.model_dump(), name=names[(key.id, key.user_id, key.kind)])
        for key in body.keys
        if (key.id, key.user_id, key.kind) in names
    ]
    return JSONResponse(
        content=[key.model_dump() for key in result], headers={"Cache-Control": "no-store"}
    )


def _managed_usage_names(
    references: list[UsageKeyReference],
    validator: ManagedApiKeyValidator,
    kc: KeycloakClient | None,
) -> dict[tuple[str, str, str], str]:
    """Match current descriptors to normalized gateway IDs and actual service owners."""
    if kc is None:
        raise HTTPException(status_code=503, detail="Managed key metadata unavailable")
    requested = {(key.id, key.user_id) for key in references if key.kind == "managed"}
    owners: dict[str, str | None] = {}
    names: dict[tuple[str, str, str], str] = {}
    try:
        for key in validator.metadata():
            identity = key.context_credential_id
            if not any(key_id == identity for key_id, _ in requested):
                continue
            client_id = key.principal_client_id
            if client_id not in owners:
                owners[client_id] = kc.get_service_account_user_id(client_id)
            owner = owners[client_id]
            if owner is not None and (identity, owner) in requested:
                names[(identity, owner, "managed")] = key.name
    except (ManagedApiKeyConfigurationError, KeycloakUnavailableError) as exc:
        raise HTTPException(status_code=503, detail="Managed key metadata unavailable") from exc
    return names


@router.get("/validate/neurwerk")
@router.post("/validate/neurwerk")
@router.delete("/validate/neurwerk")
def validate_neurwerk_key(
    request: Request,
    db: Session = Depends(get_db),
    kc: KeycloakClient | None = Depends(get_kc_client),
    managed_api_keys: ManagedApiKeyValidator = Depends(get_managed_api_keys),
) -> JSONResponse:
    """Validate only the dedicated Neurwerk bearer key, without credential fallback."""
    return _validation_response(request, db, kc, managed_api_keys, mode="neurwerk")


@router.get("/validate/proxy")
@router.post("/validate/proxy")
@router.delete("/validate/proxy")
def validate_proxy_key(
    request: Request,
    db: Session = Depends(get_db),
    kc: KeycloakClient | None = Depends(get_kc_client),
    managed_api_keys: ManagedApiKeyValidator = Depends(get_managed_api_keys),
) -> JSONResponse:
    """Validate only the proxy Basic password; its username never selects identity."""
    return _validation_response(request, db, kc, managed_api_keys, mode="proxy")


def _validation_response(
    request: Request,
    db: Session,
    kc: KeycloakClient | None,
    managed_api_keys: ManagedApiKeyValidator,
    *,
    mode: Literal["neurwerk", "proxy"],
) -> JSONResponse:
    """Share key validation and error serialization across explicit credential modes."""
    request_ids = request.headers.getlist("x-request-id")
    request_id = (
        request_ids[0]
        if len(request_ids) == 1 and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", request_ids[0])
        else uuid.uuid4().hex
    )
    try:
        key_value = _dedicated_api_key(request, mode)
        response = _validate_key(request, key_value, db, kc, managed_api_keys)
    except HTTPException as exc:
        code = {
            401: "authentication_failed",
            503: "authentication_unavailable",
        }.get(exc.status_code, "authentication_failed")
        logger.warning(
            "Key validation rejected request_id=%s code=%s status=%d",
            request_id,
            code,
            exc.status_code,
        )
        response = JSONResponse(
            status_code=exc.status_code,
            content={
                "detail": exc.detail,
                "error": {"message": str(exc.detail), "code": code, "request_id": request_id},
            },
            headers=exc.headers,
        )
    response.headers["x-request-id"] = request_id
    return response


def _validate_key(
    request: Request,
    key_value: str | None,
    db: Session,
    kc: KeycloakClient | None,
    managed_api_keys: ManagedApiKeyValidator,
) -> JSONResponse:
    cache = request.app.state.jwks_cache
    if not request.app.state.keycloak_configured or cache is None or not cache.is_available():
        raise HTTPException(status_code=503, detail="Keycloak authorization unavailable")
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
    permissions = sorted(
        permission
        for permission in set(key["permissions"]).intersection(entitlements.permissions)
        if is_valid_permission(permission)
    )
    return _decision_response(
        credential_id=key["id"],
        credential_kind="user_api_key",
        credential_name=key["name"],
        expires_at=key["expires_at"],
        principal_kind="user",
        principal_id=key["user_id"],
        permissions=permissions,
        groups=sorted(entitlements.groups),
        account_email=entitlements.account_email,
    )


def _dedicated_api_key(request: Request, mode: Literal["neurwerk", "proxy"]) -> str:
    """Read exactly one bounded identity header, rejecting ambiguous encodings."""
    header_name, expected_scheme = (
        ("x-neurwerk-authorization", "bearer")
        if mode == "neurwerk"
        else ("proxy-authorization", "basic")
    )
    values = request.headers.getlist(header_name)
    invalid = HTTPException(status_code=401, detail="Invalid authentication credentials")
    if len(values) != 1 or len(values[0]) > _MAX_AUTHORIZATION_HEADER_LENGTH:
        raise invalid
    match = _AUTHORIZATION_PATTERN.fullmatch(values[0])
    if match is None or match[1].lower() != expected_scheme:
        raise invalid
    token = match[2]
    if mode == "neurwerk":
        return token

    # Bound the encoded input before decoding, and reject noncanonical padding,
    # invalid UTF-8, control characters and incomplete username:password pairs.
    try:
        decoded = base64.b64decode(token, validate=True)
        user_pass = decoded.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise invalid from None
    username, _, key_value = user_pass.partition(":")
    if (
        base64.b64encode(decoded).decode("ascii") != token
        or not username
        or not key_value
        or any(ord(char) < 32 or ord(char) == 127 for char in user_pass)
    ):
        raise invalid
    return key_value


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
    permissions = sorted(
        permission
        for permission in set(managed_key.permissions).intersection(entitlements.permissions)
        if is_valid_permission(permission)
    )
    return _decision_response(
        credential_id=managed_key.key_id,
        credential_kind="managed_api_key",
        context_credential_id=managed_key.context_credential_id,
        credential_name=managed_key.name,
        expires_at=None,
        principal_kind="service_account",
        principal_id=principal_id,
        permissions=permissions,
        groups=sorted(entitlements.groups),
        account_email=entitlements.account_email,
    )


def _decision_response(
    *,
    credential_id: str,
    credential_kind: str,
    context_credential_id: str | None = None,
    credential_name: str,
    expires_at: str | None,
    principal_kind: str,
    principal_id: str,
    permissions: list[str],
    groups: list[str],
    account_email: str | None,
) -> JSONResponse:
    """Return the stable decision body and bounded trusted gateway projection."""
    auth_context = json.dumps(
        {
            "contract_version": 1,
            "principal_id": principal_id,
            "account_email": account_email,
            "permissions": permissions,
            "groups": groups,
            "credential_id": context_credential_id or credential_id,
            "credential_kind": "personal" if credential_kind == "user_api_key" else "managed",
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )
    # ASCII serialization makes character count equal the header value's byte size.
    if len(auth_context) > 64 * 1024:
        raise HTTPException(status_code=503, detail="Authorization context unavailable")
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
            "account_email": account_email,
            "permissions": permissions,
            "groups": groups,
        },
        headers={"x-agentgateway-auth-context": auth_context},
    )


def _key_hash_prefix(key_value: str) -> str:
    """Return a non-secret correlation value for authentication-failure logs."""
    return hashlib.sha256(key_value.encode()).hexdigest()[:12]
