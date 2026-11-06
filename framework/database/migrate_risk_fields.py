
import sqlite3

DATABASE_PATH = "assessment.db"

NEW_COLUMNS = {
    "risk_score": "REAL",
    "risk_severity": "VARCHAR(50)",
    "risk_factors": "TEXT",
    "risk_method": "VARCHAR(100)",
}


def migrate():
    connection = sqlite3.connect(DATABASE_PATH)

    try:
        cursor = connection.cursor()

        existing_columns = {
            row[1]
            for row in cursor.execute(
                "PRAGMA table_info(findings)"
            ).fetchall()
        }

        if not existing_columns:
            raise RuntimeError(
                "The findings table does not exist. "
                "Check that you are running this from framework/."
            )

        for column_name, column_type in NEW_COLUMNS.items():
            if column_name in existing_columns:
                print(f"Already exists: {column_name}")
                continue

            cursor.execute(
                f"ALTER TABLE findings "
                f"ADD COLUMN {column_name} {column_type}"
            )

            print(f"Added column: {column_name}")

        connection.commit()
        print("Risk-field migration completed successfully.")

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    migrate()
