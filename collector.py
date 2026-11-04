"""Run on Ubuntu beside Cowrie. Standard library only."""
import glob
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

LOG = Path(os.getenv("COWRIE_LOG", "/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json"))
STATE = Path(os.getenv("COLLECTOR_STATE", str(LOG.parent / ".cowrie_ingest_state.json")))
URL = os.getenv("INGEST_URL", "http://192.168.56.1:8000/api/ingesta/eventos")
KEY = os.getenv("INGEST_API_KEY")


def save(state):
    temp = STATE.with_suffix(STATE.suffix + ".tmp")
    temp.write_text(json.dumps(state), encoding="utf-8")
    os.replace(temp, STATE)


def candidates():
    paths = [Path(p) for p in glob.glob(str(LOG) + "*") if Path(p).is_file()]
    return [p for p in paths if p.name == LOG.name or p.name.startswith(LOG.name + ".")]


def find_file(state):
    paths = candidates()
    if state.get("inode") is not None:
        for path in paths:
            info = path.stat()
            if [info.st_dev, info.st_ino] == state["inode"]:
                return path
    return LOG if LOG.exists() else None


def next_file(state):
    path = find_file(state)
    if path is None:
        return None, None
    info = path.stat()
    inode = [info.st_dev, info.st_ino]
    offset = state.get("offset", 0) if state.get("inode") == inode else 0
    if info.st_size < offset:
        offset = 0
    return path, {"inode": inode, "offset": offset}


def send(events):
    payload = json.dumps({"eventos": events}).encode("utf-8")
    request = urllib.request.Request(URL, data=payload, headers={"Content-Type": "application/json", "X-API-Key": KEY}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return 200 <= response.status < 300


def heartbeat():
    root = URL.rsplit("/", 1)[0]
    request = urllib.request.Request(root + "/heartbeat", data=b"{}", headers={"Content-Type": "application/json", "X-API-Key": KEY}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return 200 <= response.status < 300


def main():
    import fcntl
    if not KEY:
        raise SystemExit("INGEST_API_KEY requerida")
    lock_path = STATE.with_suffix(STATE.suffix + ".lock")
    lock = lock_path.open("a+")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("Ya existe un recolector usando este estado")
    state = json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}
    last_heartbeat = 0.0
    while True:
        if time.monotonic() - last_heartbeat >= 20:
            try:
                heartbeat()
                last_heartbeat = time.monotonic()
            except (urllib.error.URLError, TimeoutError) as exc:
                print(f"Sin conexión al backend: {type(exc).__name__}")
        path, current = next_file(state)
        if path is None:
            time.sleep(2)
            continue
        batch = []
        end = current["offset"]
        with path.open("rb") as stream:
            stream.seek(end)
            while len(batch) < 100:
                start = stream.tell()
                line = stream.readline()
                if not line or not line.endswith(b"\n"):
                    break
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("JSON no es objeto")
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                    # A complete malformed line is retained for operator repair.
                    print(f"JSON inválido en {path}:{start}; esperando corrección")
                    batch = []
                    break
                source = f"{current['inode'][0]}:{current['inode'][1]}:{start}:" + hashlib.sha256(line).hexdigest()
                event["_collector"] = {"source_id": source}
                batch.append(event)
                end = stream.tell()
        if batch:
            try:
                if send(batch):
                    state = {"inode": current["inode"], "offset": end}
                    save(state)
            except (urllib.error.URLError, TimeoutError) as exc:
                print(f"Envío pendiente: {type(exc).__name__}")
        elif current != state and end == current["offset"]:
            state = current
            save(state)
        # Once a rotated file is drained, the next iteration moves to the active file.
        if path != LOG and path.stat().st_size <= state.get("offset", 0) and LOG.exists():
            active = LOG.stat()
            state = {"inode": [active.st_dev, active.st_ino], "offset": 0}
            save(state)
        time.sleep(2)


if __name__ == "__main__":
    main()
