from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from pathlib import Path
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.app.core.config import settings

database_url = settings.database_url
# Neon commonly provides a generic PostgreSQL URL. This project uses the
# psycopg (v3) driver, so make the driver explicit instead of letting
# SQLAlchemy select the legacy psycopg2 dialect.
if database_url.startswith("postgres://"):
    database_url = "postgresql+psycopg://" + database_url[len("postgres://"):]
elif database_url.startswith("postgresql://"):
    database_url = "postgresql+psycopg://" + database_url[len("postgresql://"):]

is_sqlite = database_url.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {"connect_timeout": settings.database_connect_timeout_seconds}
pool_args = {} if is_sqlite else {
    "pool_size": settings.database_pool_size,
    "max_overflow": settings.database_max_overflow,
    "pool_timeout": settings.database_pool_timeout_seconds,
    "pool_pre_ping": True,
}
engine = create_engine(database_url, connect_args=connect_args, **pool_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def run_migrations():
    migration_dir=Path(__file__).resolve().parents[2] / "migrations"
    with engine.begin() as connection:
        advisory_lock = False
        if connection.dialect.name == "postgresql":
            # Vercel can initialize several cold-start instances together.
            # Serialize migrations so concurrent startup transactions cannot
            # deadlock while creating or seeding the shared schema.
            connection.exec_driver_sql("SELECT pg_advisory_lock(781923406)")
            advisory_lock = True
        try:
            for path in sorted(migration_dir.glob("*.sql")):
                for statement in path.read_text(encoding="utf-8").split(";"):
                    if not statement.strip():
                        continue
                    try:
                        # Use a savepoint so an expected duplicate-object error
                        # does not poison PostgreSQL's surrounding transaction.
                        with connection.begin_nested():
                            connection.execute(text(statement))
                    except SQLAlchemyError as exc:
                        # Migrations are intentionally idempotent because the
                        # application runs them at startup. SQLite and older
                        # PostgreSQL migrations do not share ADD COLUMN IF NOT
                        # EXISTS syntax, so ignore only duplicate-object errors.
                        message = str(exc).lower()
                        if "duplicate column" not in message and "already exists" not in message:
                            raise
            _install_ledger_guards(connection)
        finally:
            if advisory_lock:
                connection.exec_driver_sql("SELECT pg_advisory_unlock(781923406)")

def _install_ledger_guards(connection):
    """Install database-side append-only guards after migrations.

    The application ORM guards are defense in depth. These triggers also stop
    ordinary application-role UPDATE/DELETE statements. A production DBA must
    additionally run the database-specific permission hardening for the app
    role; the database owner/migration role remains trusted.
    """
    dialect = connection.dialect.name
    if dialect == "sqlite":
        connection.exec_driver_sql("DROP TRIGGER IF EXISTS trg_threat_ledger_no_update")
        connection.exec_driver_sql("DROP TRIGGER IF EXISTS trg_threat_ledger_no_delete")
        connection.exec_driver_sql("CREATE TRIGGER trg_threat_ledger_no_update BEFORE UPDATE ON threat_append_only_ledger_events WHEN OLD.event_hash <> 'pending' BEGIN SELECT RAISE(ABORT, 'append-only ledger events cannot be updated'); END")
        connection.exec_driver_sql("CREATE TRIGGER trg_threat_ledger_no_delete BEFORE DELETE ON threat_append_only_ledger_events BEGIN SELECT RAISE(ABORT, 'append-only ledger events cannot be deleted'); END")
    elif dialect == "postgresql":
        connection.exec_driver_sql("CREATE OR REPLACE FUNCTION threat_ledger_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF TG_OP = 'UPDATE' AND OLD.event_hash = 'pending' THEN RETURN NEW; END IF; RAISE EXCEPTION 'append-only ledger events cannot be changed'; END; $$")
        connection.exec_driver_sql("DROP TRIGGER IF EXISTS trg_threat_ledger_no_update ON threat_append_only_ledger_events")
        connection.exec_driver_sql("DROP TRIGGER IF EXISTS trg_threat_ledger_no_delete ON threat_append_only_ledger_events")
        connection.exec_driver_sql("CREATE TRIGGER trg_threat_ledger_no_update BEFORE UPDATE ON threat_append_only_ledger_events FOR EACH ROW EXECUTE FUNCTION threat_ledger_immutable()")
        connection.exec_driver_sql("CREATE TRIGGER trg_threat_ledger_no_delete BEFORE DELETE ON threat_append_only_ledger_events FOR EACH ROW EXECUTE FUNCTION threat_ledger_immutable()")
