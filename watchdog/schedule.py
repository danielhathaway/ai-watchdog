from . import store

MIN_MINUTES = 5
MAX_MINUTES = 10080


def read(db):
    return store.property_get(db, "check_schedule", {"interval_minutes": 0, "next_at": None})


def save(db, interval_minutes, now):
    if type(interval_minutes) is not int or (
        interval_minutes != 0 and not MIN_MINUTES <= interval_minutes <= MAX_MINUTES
    ):
        raise ValueError("Choose 0 to turn off recurring checks or an interval of 5 to 10,080 minutes.")
    existing = read(db)
    if existing["interval_minutes"] == interval_minutes:
        return existing
    updated = {"interval_minutes": interval_minutes, "next_at": now + interval_minutes * 60 if interval_minutes else None}
    store.property_set(db, "check_schedule", updated)
    return updated


def advance(db, occurrence, now):
    if occurrence is None or read(db) != occurrence:
        return
    period = occurrence["interval_minutes"] * 60
    due = occurrence["next_at"]
    next_at = due + (max(0, (now - due) // period) + 1) * period
    store.property_set(db, "check_schedule", {**occurrence, "next_at": next_at})
