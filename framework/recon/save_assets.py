from sqlalchemy.orm import Session

from database.database import engine
from database.models import Asset


def save_assets(assessment_id, host, assets):

    with Session(engine) as session:

        for asset_data in assets:

            existing_asset = session.query(Asset).filter_by(
                assessment_id=assessment_id,
                host=host,
                port=asset_data["port"],
                protocol=asset_data["protocol"]
            ).first()

            if existing_asset:
                existing_asset.state = asset_data["state"]
                existing_asset.service = asset_data["service"]
                existing_asset.version = asset_data["version"]
                existing_asset.discovered_by = "nmap"

            else:
                asset = Asset(
                    assessment_id=assessment_id,
                    host=host,
                    port=asset_data["port"],
                    protocol=asset_data["protocol"],
                    state=asset_data["state"],
                    service=asset_data["service"],
                    version=asset_data["version"],
                    discovered_by="nmap"
                )

                session.add(asset)

        session.commit()