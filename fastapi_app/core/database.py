from sqlmodel import SQLModel, create_engine, Session
from sqlalchemy import event
from .config import settings

# Only echo SQL in debug mode to prevent information disclosure
engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    connect_args={"check_same_thread": False}
)

# SQLCipher encryption: set the encryption key on every connection
if settings.DATABASE_KEY:
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute(f"PRAGMA key = '{settings.DATABASE_KEY}'")
        cursor.close()

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
