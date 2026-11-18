"""Run the existing FastAPI app locally with a graceful file-based shutdown."""
from pathlib import Path
import os
import threading
from dotenv import load_dotenv
import uvicorn


def main():
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    load_dotenv(root/'.env')
    for key in ('INGEST_TRANSPORT', 'INGEST_DEMO_LOCAL_IP', 'INGEST_DEMO_UBUNTU_IP'):
        os.environ.pop(key, None)
    stop = Path(__file__).resolve().parents[1]/'.local/runtime/backend.stop'
    stop.unlink(missing_ok=True)
    server = uvicorn.Server(uvicorn.Config('backend.api:app', host='127.0.0.1', port=8000,
        proxy_headers=False, access_log=False, ws_max_size=1024, ws_max_queue=4,
        ws_ping_interval=20, ws_ping_timeout=20))

    def watch():
        while not server.should_exit:
            if stop.exists():
                server.should_exit = True
                return
            threading.Event().wait(0.25)

    threading.Thread(target=watch, daemon=True).start()
    server.run()


if __name__ == '__main__':
    main()
