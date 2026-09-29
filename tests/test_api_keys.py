"""Persistence tests for immutable, expiring API-key grants."""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url

from keycloak_api_key_bridge.config import database
from keycloak_api_key_bridge.config.database import (
    ApiKey,
    ApiKeyLimitError,
    DatabaseSchemaError,
    bootstrap_schema,
    create_engine_and_session_factory,
)


def test_created_key_persists_immutable_permissions_and_expiry() -> None:
    engine, factory = create_engine_and_session_factory("sqlite://", allow_sqlite_for_tests=True)
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
    engine, factory = create_engine_and_session_factory("sqlite://", allow_sqlite_for_tests=True)
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


def test_bootstrap_rechecks_schema_without_postgres(monkeypatch: pytest.MonkeyPatch) -> None:
    # SQLite supplies a real inspector and transactions; only the PostgreSQL
    # advisory-lock statement and engine construction are replaced here.
    engine = create_engine("sqlite://")

    @event.listens_for(engine, "before_cursor_execute", retval=True)
    def replace_advisory_lock(connection, cursor, statement, parameters, context, executemany):
        if "pg_advisory_xact_lock" in statement:
            return "SELECT 1", parameters
        return statement, parameters

    monkeypatch.setattr(database, "create_engine", lambda *args, **kwargs: engine)
    monkeypatch.setattr(engine, "dispose", lambda: None)
    url = make_url("postgresql+psycopg://localhost/api_key_bridge")
    try:
        bootstrap_schema(url)
        bootstrap_schema(url)
        with engine.begin() as connection:
            connection.execute(text("UPDATE bridge_schema_version SET version = 999"))
        with pytest.raises(DatabaseSchemaError, match="version"):
            bootstrap_schema(url)
        with engine.begin() as connection:
            connection.execute(text("UPDATE bridge_schema_version SET version = 3"))
            connection.execute(text("CREATE TABLE unexpected (id INTEGER)"))
        with pytest.raises(DatabaseSchemaError, match="Missing or incompatible"):
            bootstrap_schema(url)
    finally:
        monkeypatch.undo()
        engine.dispose()


def test_concurrent_creation_cannot_exceed_user_key_limit() -> None:
    # Opt-in PostgreSQL integration: set this to an empty, disposable local database.
    database_url = os.environ.get("BRIDGE_TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("Set BRIDGE_TEST_POSTGRES_URL to a disposable local PostgreSQL database")
    url = make_url(database_url)
    with pytest.raises(DatabaseSchemaError, match="Missing"):
        create_engine_and_session_factory(url)
    # Both starters see the same empty database; the lock must serialize them.
    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(bootstrap_schema, (url, url)))
    # The same init command also runs on every restart.
    bootstrap_schema(url)
    engine, factory = create_engine_and_session_factory(url)

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
        bootstrap_schema(url)
        with factory() as session:
            assert len(ApiKey.list_keys(session, "user-1", limit=20)) == 2
            first = ApiKey.list_keys(session, "user-1")[0]["id"]
            assert ApiKey.revoke_key(session, first, "user-1")
            assert len(ApiKey.list_keys(session, "user-1")) == 1
            assert ApiKey.get_key(session, "invalid") is None
            _, plaintext = ApiKey.create_key(
                session, "replacement", "user-1", ["llm:invoke"], 1, max_keys_per_user=2
            )
            replacement = ApiKey.get_key(session, plaintext)
            assert replacement is not None
            assert replacement["permissions"] == ["llm:invoke"]
        with engine.begin() as connection:
            connection.execute(text("UPDATE bridge_schema_version SET version = 999"))
        with pytest.raises(DatabaseSchemaError, match="version"):
            bootstrap_schema(url)
        with pytest.raises(DatabaseSchemaError, match="version"):
            create_engine_and_session_factory(url)
        with engine.begin() as connection:
            connection.execute(text("UPDATE bridge_schema_version SET version = 3"))

    finally:
        engine.dispose()
        cleanup = create_engine(url)
        try:
            with cleanup.begin() as connection:
                connection.execute(text("DROP TABLE api_keys, bridge_schema_version"))
        finally:
            cleanup.dispose()


def test_production_rejects_sqlite() -> None:
    with pytest.raises(ValueError, match="PostgreSQL"):
        create_engine_and_session_factory("sqlite://")


def test_missing_postgres_credentials_fail_before_connection() -> None:
    from keycloak_api_key_bridge.config.settings import Settings

    with pytest.raises(ValueError, match="host, database, user and password"):
        Settings(postgres_host="", postgres_password="").postgres_url()


def test_postgres_password_is_encoded_by_driver_not_string_interpolation() -> None:
    from keycloak_api_key_bridge.config.settings import Settings

    url = Settings(postgres_host="localhost", postgres_password="p@ss:/?#").postgres_url()
    assert url.password == "p@ss:/?#"
    assert "p@ss" not in str(url)
