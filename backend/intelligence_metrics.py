"""Shared counting units and bounded Ecuador calendar series."""
from collections import defaultdict
from datetime import date, timedelta

from sqlalchemy import func, select


def observable_totals(rows):
    return select(
        func.count(func.distinct(rows.id_ioc)).label("observables"),
        func.count().label("observaciones"),
        func.count(func.distinct(rows.id_evento)).label("eventos"),
        func.count(func.distinct(rows.id_sesion)).label("sesiones"),
        func.count(func.distinct(rows.id_ioc)).filter(rows.verificable).label("verificables"),
    )


def technique_count(rows):
    return func.count(func.distinct(rows.codigo_tecnica))


def calendar_series(rows, day_key, zero, *, start=None, end=None, maximum_days=366):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row[day_key]].append(row)
    if not grouped and not (start and end):
        return [], {"desde": None, "hasta": None, "limitada": False}
    first, last = start or min(grouped), end or max(grouped)
    effective = date.fromordinal(max(first.toordinal(), last.toordinal() - maximum_days + 1))
    series = []
    day = effective
    while day <= last:
        series.extend(grouped.get(day) or [{day_key: day, **zero}])
        if day == last:
            break
        day += timedelta(days=1)
    return series, {"desde": effective, "hasta": last, "limitada": effective != first}
