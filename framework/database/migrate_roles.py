from sqlalchemy import text

from database.database import engine


with engine.begin() as connection:

    connection.execute(
        text(
            """
            ALTER TABLE endpoints
            ADD COLUMN discovered_as VARCHAR(50)
            DEFAULT 'anonymous'
            NOT NULL
            """
        )
    )

print("Endpoint role column added successfully.")