# in src/models.py
from datetime import datetime, timezone  # Make sure timezone is imported
from typing import Any

from sqlalchemy import DateTime, TypeDecorator


# --- This is the new custom type ---
class AwareDateTime(TypeDecorator):
    """
    A custom SQLAlchemy type that ensures datetime objects are always timezone-aware (UTC).

    On the way in (to the DB):
    - If a naive datetime is provided, it's assumed to be UTC.
    - It's stored as a timezone-aware datetime in the DB.

    On the way out (from the DB):
    - The naive datetime read from the DB is correctly interpreted as UTC
      and converted to a timezone-aware object.

    Usage would be:
    `Field(sa_column=Column(AwareDateTime))`
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        """Ran when retrieving data from the database."""
        if value is not None:
            return value.replace(tzinfo=timezone.utc)
        return None
