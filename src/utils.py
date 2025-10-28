from datetime import datetime, timezone


def datetime_utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)
