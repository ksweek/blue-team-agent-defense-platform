from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine.url import make_url
from sqlalchemy.orm import Session, sessionmaker

from ..core.config import PROJECT_ROOT, settings

database_url = settings.database_url
parsed_url = make_url(database_url)
is_sqlite = parsed_url.get_backend_name() == "sqlite"

engine_kwargs: dict[str, object] = {
    "echo": settings.database_echo,
    "pool_pre_ping": settings.database_pool_pre_ping,
}

if is_sqlite:
    database_name = parsed_url.database
    if database_name and database_name != ":memory:":
        database_path = Path(database_name)
        if not database_path.is_absolute():
            database_path = (PROJECT_ROOT / database_path).resolve()
            parsed_url = parsed_url.set(database=database_path.as_posix())
            database_url = parsed_url.render_as_string(hide_password=False)
        database_path.parent.mkdir(parents=True, exist_ok=True)
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(database_url, **engine_kwargs)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, class_=Session)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def ping_database() -> None:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
