from sqlalchemy import create_engine

from config import DATABASE_URL
from database.models import Base


engine = create_engine(
    DATABASE_URL,
    echo=False
)


def initialize_database():
    Base.metadata.create_all(engine)

    print("Assessment database initialized successfully.")