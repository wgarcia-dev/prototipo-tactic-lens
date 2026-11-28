import json
import re
import sqlite3
from typing import Protocol


class EventStore(Protocol):
    def query(self, sql: str) -> list[dict]: ...


def quote(name):
    return '"' + name.replace('"', '""') + '"'


class SQLiteStore:
    def __init__(self, events, fields):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.create_function("regexp", 2, lambda p, v: v is not None and re.search(p, str(v)) is not None)
        fields = sorted(set(fields) | {k for e in events for k in e if not k.startswith("_")}
                        | {"id_evento", "timestamp"})
        if len({f.casefold() for f in fields}) != len(fields):
            raise ValueError("Case-colliding event fields")
        self.connection.execute("CREATE TABLE logs (" + ",".join(quote(f) for f in fields) + ")")
        sql = "INSERT INTO logs VALUES (" + ",".join("?" for _ in fields) + ")"
        def scalar(v):
            return json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
        self.connection.executemany(sql, [[scalar(e.get(f)) for f in fields] for e in events])
        self.connection.execute("CREATE UNIQUE INDEX event_identity ON logs(id_evento)")
        self.connection.execute("PRAGMA query_only=ON")

    def query(self, sql):
        return [dict(row) for row in self.connection.execute(sql)]

    def close(self):
        self.connection.close()
