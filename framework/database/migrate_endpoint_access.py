from sqlalchemy import text

from database.database import engine


with engine.begin() as connection:

    connection.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS endpoint_access (
                id INTEGER PRIMARY KEY,
                endpoint_id INTEGER NOT NULL,
                role VARCHAR(50) NOT NULL,
                status_code INTEGER,
                discovered_by VARCHAR(100),
                FOREIGN KEY(endpoint_id)
                    REFERENCES endpoints(id)
            )
            """
        )
    )

print("Endpoint access table created successfully.")