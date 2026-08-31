"""Persistence tests for immutable, expiring API-key grants."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from keycloak_api_key_bridge.config.database import (
    ApiKey,
    ApiKeyLimitError,
    DatabaseSchemaError,
    create_engine_and_session_factory,
)


def test_created_key_persists_immutable_permissions_and_expiry() -> None:
    engine, factory = create_engine_and_session_factory("sqlite://")
    try:
        with factory() as session:
            key_id, plaintext = ApiKey.create_key(
                session,
                name="cli",
                user_id="user-1",
                permissions=["llm:invoke", "mcp:brave:invoke"],
                validity_days=30,
            )
            key = ApiKey.get_key(session, plaintext)

        assert key is not None
        assert key["id"] == key_id
        assert key["permissions"] == ["llm:invoke", "mcp:brave:invoke"]
        assert key["expires_at"] is not None
    finally:
        engine.dispose()


def test_revoked_and_expired_keys_do_not_validate() -> None:
    engine, factory = create_engine_and_session_factory("sqlite://")
    try:
        with factory() as session:
            key_id, plaintext = ApiKey.create_key(
                session,
                name="cli",
                user_id="user-1",
                permissions=["llm:invoke"],
                validity_days=1,
            )
            assert ApiKey.revoke_key(session, key_id, "user-1")
            assert ApiKey.get_key(session, plaintext) is None
            assert session.get(ApiKey, key_id) is None

            expired_id, expired_plaintext = ApiKey.create_key(
                session,
                name="expired",
                user_id="user-1",
                permissions=["llm:invoke"],
                validity_days=1,
            )
            expired = session.get(ApiKey, expired_id)
            assert expired is not None
            expired.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            session.commit()
            assert ApiKey.get_key(session, expired_plaintext) is None
    finally:
        engine.dispose()


def test_concurrent_creation_cannot_exceed_user_key_limit(tmp_path) -> None:
    engine, factory = create_engine_and_session_factory(f"sqlite:///{tmp_path / 'api-keys.db'}")

    def create_key(index: int) -> bool:
        session = factory()
        try:
            ApiKey.create_key(
                session,
                name=f"cli-{index}",
                user_id="user-1",
                permissions=["llm:invoke"],
                validity_days=30,
                max_keys_per_user=2,
            )
            return True
        except ApiKeyLimitError:
            return False
        finally:
            session.close()

    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            created = list(executor.map(create_key, range(8)))

        assert created.count(True) == 2
        with factory() as session:
            assert len(ApiKey.list_keys(session, "user-1", limit=20)) == 2
    finally:
        engine.dispose()


def test_existing_unversioned_api_key_schema_fails_closed(tmp_path) -> None:
    database = tmp_path / "legacy-api-keys.db"
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE api_keys (id TEXT PRIMARY KEY)")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(DatabaseSchemaError, match="new schema-v2 volume"):
        create_engine_and_session_factory(f"sqlite:///{database}")
