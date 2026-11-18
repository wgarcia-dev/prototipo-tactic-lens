"""Existing FastAPI app in a loopback-only development process, without Ubuntu."""
import os
from pathlib import Path
from dotenv import load_dotenv
import uvicorn


def main():
    root=Path(__file__).resolve().parents[1]
    os.chdir(root);load_dotenv(root/'.env')
    for key in ('INGEST_TRANSPORT','INGEST_DEMO_LOCAL_IP','INGEST_DEMO_UBUNTU_IP'):os.environ.pop(key,None)
    uvicorn.run('backend.api:app',host='127.0.0.1',port=8000,proxy_headers=False,access_log=False,
                ws_max_size=1024,ws_max_queue=4,ws_ping_interval=20,ws_ping_timeout=20)


if __name__=='__main__':main()
