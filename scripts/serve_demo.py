"""One existing FastAPI app, bound only to loopback and the selected LAN IP."""
import argparse
from contextlib import ExitStack, contextmanager
import os
import socket

from dotenv import load_dotenv
import uvicorn

from backend.ingest_transport import private_ipv4, validate_demo_settings


@contextmanager
def bound_listeners(local_ip):
    with ExitStack() as stack:
        listeners = []
        for address in ('127.0.0.1', local_ip):
            listener = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind((address, 8000))
            listener.listen(128)
            listener.setblocking(False)
            listeners.append(listener)
        yield listeners


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local-ip', required=True, type=private_ipv4)
    parser.add_argument('--ubuntu-ip', required=True, type=private_ipv4)
    parser.add_argument('--check-ports', action='store_true')
    args = parser.parse_args()
    load_dotenv()
    os.environ.update(INGEST_TRANSPORT='demo-http', INGEST_DEMO_LOCAL_IP=args.local_ip,
                      INGEST_DEMO_UBUNTU_IP=args.ubuntu_ip)
    validate_demo_settings()
    if args.check_ports:
        # CIM can report obsolete listeners owned by PID 0 after shutdown.
        # Probe the same exclusive binds used by the server instead.
        try:
            with bound_listeners(args.local_ip):
                pass
        except OSError:
            raise SystemExit('Puerto 8000 ocupado o interfaz no disponible; detenga el backend anterior.') from None
        return
    # The dedicated key is created and ACL-protected by Iniciar-DemoHTTP.ps1.
    from pathlib import Path
    import re
    key = (Path(__file__).resolve().parents[1]/'.local/demo-http/ingest.key').read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{43,128}', key):
        raise SystemExit('Clave exclusiva de demostración no válida')
    os.environ['INGEST_API_KEY'] = key
    with bound_listeners(args.local_ip) as listeners:
        # Do not trust X-Forwarded-For from the LAN client.
        server = uvicorn.Server(uvicorn.Config('backend.api:app', proxy_headers=False, access_log=False))
        server.run(sockets=listeners)


if __name__ == '__main__':
    main()
