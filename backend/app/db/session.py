from sqlalchemy import create_engine, text
from pathlib import Path
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.app.core.config import settings

is_sqlite = settings.database_url.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {"connect_timeout": settings.database_connect_timeout_seconds}
pool_args = {} if is_sqlite else {
    "pool_size": settings.database_pool_size,
    "max_overflow": settings.database_max_overflow,
    "pool_timeout": settings.database_pool_timeout_seconds,
    "pool_pre_ping": True,
}
engine = create_engine(settings.database_url, connect_args=connect_args, **pool_args)
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
        for path in sorted(migration_dir.glob("*.sql")):
            for statement in path.read_text(encoding="utf-8").split(";"):
                if statement.strip(): connection.execute(text(statement))
