import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import JSON, Boolean, DateTime, Engine, String, create_engine, func, inspect, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


class ApiKeyLimitError(Exception):
    """Raised when a user has reached their stored API-key limit."""


class DatabaseSchemaError(RuntimeError):
    """Raised when a database is not the bridge's explicitly supported schema."""


SCHEMA_VERSION = 2
_SCHEMA_VERSION_TABLE = "bridge_schema_version"
_EXPECTED_TABLES = frozenset({"api_keys", _SCHEMA_VERSION_TABLE})
_EXPECTED_API_KEY_COLUMNS = frozenset(
    {
        "id",
        "key_hash",
        "key_prefix",
        "name",
        "user_id",
        "created_by_user_id",
        "created_at",
        "permissions",
        "expires_at",
        "revoked",
    }
)


class SchemaVersion(Base):
    """Singleton marker that identifies the SQLite schema expected by this bridge."""

    __tablename__ = _SCHEMA_VERSION_TABLE

    version: Mapped[int] = mapped_column(primary_key=True)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    created_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    permissions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    @classmethod
    def create_key(
        cls,
        session: Session,
        name: str,
        user_id: str,
        permissions: list[str],
        validity_days: int,
        created_by_user_id: str | None = None,
        max_keys_per_user: int = 20,
    ) -> tuple[str, str]:
        """Persist a new API key and return its public ID and secret value.

        Permission grants are immutable. *created_by_user_id*, when set, records
        an administrator creating a key on behalf of another user.
        """
        # The immediate transaction serializes quota checks across worker threads.
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        try:
            stored_key_count = session.scalar(
                select(func.count()).select_from(cls).where(cls.user_id == user_id)
            )
            if stored_key_count is not None and stored_key_count >= max_keys_per_user:
                raise ApiKeyLimitError

            key_id = str(uuid.uuid4())
            key_value = secrets.token_urlsafe(32)
            now = datetime.now(UTC)
            expires = now + timedelta(days=validity_days)
            api_key = cls(
                id=key_id,
                key_hash=_hash_key(key_value),
                key_prefix=key_value[:8],
                name=name,
                user_id=user_id,
                created_by_user_id=created_by_user_id,
                created_at=now,
                permissions=permissions,
                expires_at=expires,
            )
            session.add(api_key)
            session.commit()
            return key_id, key_value
        except Exception:
            session.rollback()
            raise

    @classmethod
    def _fetch_owned_key(cls, session: Session, key_id: str, user_id: str) -> "ApiKey | None":
        """Look up a key by id and return it only if owned by *user_id*."""
        key = session.get(cls, key_id)
        if key is None or key.user_id != user_id:
            return None
        return key

    @classmethod
    def _fetch_any_key(cls, session: Session, key_id: str) -> "ApiKey | None":
        """Look up a key by id — no ownership check (admin use only)."""
        return session.get(cls, key_id)

    @classmethod
    def revoke_key(cls, session: Session, key_id: str, user_id: str) -> bool:
        """Revoke a key by id.  Only the key owner may revoke."""
        key = cls._fetch_owned_key(session, key_id, user_id)
        if key is None:
            return False
        session.delete(key)
        session.commit()
        return True

    @classmethod
    def revoke_key_as_admin(cls, session: Session, key_id: str) -> bool:
        """Revoke a key by id — no ownership check (admin use only)."""
        key = cls._fetch_any_key(session, key_id)
        if key is None:
            return False
        session.delete(key)
        session.commit()
        return True

    @classmethod
    def list_keys(cls, session: Session, user_id: str, limit: int = 20) -> list[dict]:
        """Return a bounded, stable list of keys for a user as dicts."""
        keys = (
            session.query(cls)
            .filter(cls.user_id == user_id, cls.revoked.is_(False))
            .order_by(cls.created_at.desc(), cls.id.desc())
            .limit(limit)
            .all()
        )
        return [_key_to_dict(k) for k in keys]

    @classmethod
    def get_key(cls, session: Session, key_value: str) -> dict | None:
        """Look up a key value and return its info dict if valid."""
        key = session.query(cls).filter(cls.key_hash == _hash_key(key_value)).one_or_none()
        if key is None or key.revoked:
            return None
        if key.expires_at is not None:
            now = datetime.now(UTC)
            expires = key.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if now >= expires:
                return None
        return _key_to_dict(key)


def _key_to_dict(key: ApiKey) -> dict:
    return {
        "id": key.id,
        "key_prefix": key.key_prefix,
        "name": key.name,
        "user_id": key.user_id,
        "created_by_user_id": key.created_by_user_id,
        "created_at": key.created_at.isoformat(),
        "permissions": list(key.permissions),
        "expires_at": key.expires_at.isoformat(),
        "revoked": key.revoked,
    }


def _hash_key(key_value: str) -> str:
    """Return the SHA-256 digest used as the API-key database lookup value."""
    return hashlib.sha256(key_value.encode()).hexdigest()


def create_engine_and_session_factory(database_url: str) -> tuple[Engine, sessionmaker[Session]]:
    """Return a configured ``(engine, sessionmaker)`` tuple bound to *database_url*."""
    connect_args: dict = {}
    if database_url.startswith("sqlite"):
        # Allow SQLite connections from multiple threads (uvicorn --workers).
        connect_args["check_same_thread"] = False

    engine_options: dict = {}
    if database_url in {"sqlite://", "sqlite:///:memory:"}:
        # TestClient serves requests on another thread. A static pool keeps an
        # in-memory database shared by application setup and request sessions.
        engine_options["poolclass"] = StaticPool

    engine = create_engine(
        database_url,
        connect_args=connect_args,
        pool_pre_ping=True,
        **engine_options,
    )
    try:
        _initialize_schema(engine)
    except Exception:
        engine.dispose()
        raise

    return engine, sessionmaker(bind=engine)


def _initialize_schema(engine: Engine) -> None:
    """Create a fresh schema or reject every unversioned/incompatible database.

    The chart deliberately provisions a fresh schema-v2 PVC rather than
    migrating the pre-versioned bridge database. A manually attached database
    must prove that it is this exact schema before it can serve credentials.
    """
    inspector = inspect(engine)
    tables = set(inspector.get_table_names()) - {"sqlite_sequence"}
    if not tables:
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            session.add(SchemaVersion(version=SCHEMA_VERSION))
            session.commit()
        return

    if tables != _EXPECTED_TABLES:
        raise DatabaseSchemaError(
            "Unsupported API-key database schema; use a new schema-v2 volume instead of reusing it"
        )

    api_key_columns = {column["name"] for column in inspector.get_columns(ApiKey.__tablename__)}
    version_columns = {column["name"] for column in inspector.get_columns(_SCHEMA_VERSION_TABLE)}
    if api_key_columns != _EXPECTED_API_KEY_COLUMNS or version_columns != {"version"}:
        raise DatabaseSchemaError(
            "Unsupported API-key database schema; use a new schema-v2 volume instead of reusing it"
        )

    with Session(engine) as session:
        versions = list(session.scalars(select(SchemaVersion.version)))
    if versions != [SCHEMA_VERSION]:
        raise DatabaseSchemaError(
            "Unsupported API-key database schema version; use a new schema-v2 volume instead"
        )
