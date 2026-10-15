from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


MIN_SCHEDULE_INTERVAL_SECONDS = 300
MAX_SEARCH_DAYS = 366 * 5


@dataclass(frozen=True)
class CronField:
    values: frozenset[int]
    wildcard: bool


@dataclass(frozen=True)
class CronSchedule:
    expression: str
    minute: CronField
    hour: CronField
    day_of_month: CronField
    month: CronField
    day_of_week: CronField


def _number(value: str, minimum: int, maximum: int, label: str) -> int:
    if not value.isdigit():
        raise ValueError(f"cron {label} contains an invalid value")
    result = int(value)
    if result < minimum or result > maximum:
        raise ValueError(
            f"cron {label} must be between {minimum} and {maximum}"
        )
    return result


def _field(
    document: str,
    minimum: int,
    maximum: int,
    label: str,
    *,
    sunday_alias: bool = False,
) -> CronField:
    if not document or len(document) > 128:
        raise ValueError(f"cron {label} is invalid")
    values: set[int] = set()
    for segment in document.split(","):
        if not segment:
            raise ValueError(f"cron {label} contains an empty list item")
        parts = segment.split("/")
        if len(parts) > 2:
            raise ValueError(f"cron {label} contains an invalid step")
        base = parts[0]
        step = 1
        if len(parts) == 2:
            step = _number(parts[1], 1, maximum - minimum + 1, f"{label} step")
        if base == "*":
            start, end = minimum, maximum
        elif "-" in base:
            bounds = base.split("-")
            if len(bounds) != 2:
                raise ValueError(f"cron {label} contains an invalid range")
            start = _number(bounds[0], minimum, maximum, label)
            end = _number(bounds[1], minimum, maximum, label)
            if start > end:
                raise ValueError(f"cron {label} ranges must be ascending")
        else:
            start = _number(base, minimum, maximum, label)
            end = maximum if len(parts) == 2 else start
        values.update(range(start, end + 1, step))
    if sunday_alias:
        values = {0 if value == 7 else value for value in values}
    return CronField(values=frozenset(values), wildcard=document == "*")


def parse_cron(expression: str) -> CronSchedule:
    normalized = " ".join(expression.strip().split())
    parts = normalized.split(" ")
    if len(parts) != 5:
        raise ValueError("cron expression must contain exactly five fields")
    return CronSchedule(
        expression=normalized,
        minute=_field(parts[0], 0, 59, "minute"),
        hour=_field(parts[1], 0, 23, "hour"),
        day_of_month=_field(parts[2], 1, 31, "day-of-month"),
        month=_field(parts[3], 1, 12, "month"),
        day_of_week=_field(
            parts[4],
            0,
            7,
            "day-of-week",
            sunday_alias=True,
        ),
    )


def timezone_info(name: str) -> ZoneInfo:
    if not name or len(name) > 64:
        raise ValueError("schedule timezone is invalid")
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"schedule timezone {name!r} is unavailable") from exc


def _day_matches(schedule: CronSchedule, value: date) -> bool:
    if value.month not in schedule.month.values:
        return False
    day_of_month = value.day in schedule.day_of_month.values
    cron_weekday = (value.weekday() + 1) % 7
    day_of_week = cron_weekday in schedule.day_of_week.values
    if schedule.day_of_month.wildcard and schedule.day_of_week.wildcard:
        return True
    if schedule.day_of_month.wildcard:
        return day_of_week
    if schedule.day_of_week.wildcard:
        return day_of_month
    return day_of_month or day_of_week


def _utc_candidates(
    schedule: CronSchedule,
    zone: ZoneInfo,
    local_date: date,
) -> list[datetime]:
    candidates: set[datetime] = set()
    for hour in sorted(schedule.hour.values):
        for minute in sorted(schedule.minute.values):
            naive = datetime.combine(local_date, time(hour=hour, minute=minute))
            for fold in (0, 1):
                localized = naive.replace(tzinfo=zone, fold=fold)
                candidate = localized.astimezone(UTC)
                round_trip = candidate.astimezone(zone)
                if round_trip.replace(tzinfo=None) == naive:
                    candidates.add(candidate)
    return sorted(candidates)


def next_cron_occurrence(
    expression: str | CronSchedule,
    timezone_name: str,
    after: datetime,
) -> datetime:
    schedule = expression if isinstance(expression, CronSchedule) else parse_cron(expression)
    zone = timezone_info(timezone_name)
    if after.tzinfo is None:
        after = after.replace(tzinfo=UTC)
    after = after.astimezone(UTC)
    start_date = after.astimezone(zone).date()
    for offset in range(MAX_SEARCH_DAYS + 1):
        local_date = start_date + timedelta(days=offset)
        if not _day_matches(schedule, local_date):
            continue
        for candidate in _utc_candidates(schedule, zone, local_date):
            if candidate > after:
                return candidate
    raise ValueError("cron expression has no occurrence within five years")


def validate_cron_schedule(
    expression: str,
    timezone_name: str,
    *,
    after: datetime,
) -> tuple[str, datetime]:
    schedule = parse_cron(expression)
    timezone_info(timezone_name)
    occurrence = next_cron_occurrence(schedule, timezone_name, after)
    previous = occurrence
    for _ in range(15):
        following = next_cron_occurrence(schedule, timezone_name, previous)
        if (following - previous).total_seconds() < MIN_SCHEDULE_INTERVAL_SECONDS:
            raise ValueError("Workflow schedules must be at least five minutes apart")
        previous = following
    return schedule.expression, occurrence
