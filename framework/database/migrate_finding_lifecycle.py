from database.database import engine
from database.models import Base, FindingStatusHistory


def main():
    FindingStatusHistory.__table__.create(
        bind=engine,
        checkfirst=True,
    )
    print("Finding lifecycle migration complete.")
    print("Created or verified: finding_status_history")
    print("Existing findings and evidence were not modified.")


if __name__ == "__main__":
    main()
