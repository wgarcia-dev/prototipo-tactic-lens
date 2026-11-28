from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def rules():
    return ROOT / "rules"


@pytest.fixture
def event():
    def make(identity=1, seconds=0, **fields):
        row = {"id_evento": identity,
               "timestamp": (datetime(2026, 11, 27, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat(),
               "eventid": "cowrie.command.input", "input": "echo harmless",
               "id_sesion": "session-1", "id_honeypot": "honeypot-1",
               "instance_type": "shell", "src_ip": "192.0.2.1", "protocol": "ssh"}
        row.update(fields)
        return row
    return make
