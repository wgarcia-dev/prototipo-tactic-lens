"""Restrict the temporary LAN listener without changing browser authentication."""
import ipaddress
import os

from starlette.responses import JSONResponse

MACHINE_PATHS = {'/api/ingesta/eventos', '/api/ingesta/heartbeat'}


def private_ipv4(value):
    address = ipaddress.ip_address(value)
    if address.version != 4 or not any(address in ipaddress.ip_network(net) for net in
                                      ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
        raise ValueError('Se requiere una IPv4 de red privada')
    return str(address)


def validate_demo_settings():
    mode = os.getenv('INGEST_TRANSPORT', '')
    if mode and mode != 'demo-http':
        raise RuntimeError('INGEST_TRANSPORT no válido')
    if mode:
        if os.getenv('AUTH_ENV', 'production') != 'development':
            raise RuntimeError('HTTP de demostración no está permitido en producción')
        local = private_ipv4(os.environ['INGEST_DEMO_LOCAL_IP'])
        remote = private_ipv4(os.environ['INGEST_DEMO_UBUNTU_IP'])
        if local == remote:
            raise RuntimeError('Las dos laptops deben tener direcciones distintas')


class IngestTransportMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'websocket':
            peer = (scope.get('client') or ('', 0))[0]
            try:
                local = ipaddress.ip_address(peer).is_loopback
            except ValueError:
                local = False
            if (os.getenv('INGEST_TRANSPORT') == 'demo-http' and not local) or (not local and scope.get('scheme') != 'wss'):
                return await send({'type': 'websocket.close', 'code': 1008})
            return await self.app(scope, receive, send)
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        peer = (scope.get('client') or ('', 0))[0]
        try:
            local = ipaddress.ip_address(peer).is_loopback
        except ValueError:
            local = False
        demo = os.getenv('INGEST_TRANSPORT') == 'demo-http'
        path = scope['path']
        permitted = True
        if demo and not local:
            # This extra boundary also protects against overly broad preexisting
            # firewall rules. The LAN listener exposes no login, docs or UI APIs.
            permitted = (os.getenv('AUTH_ENV') == 'development'
                         and peer == os.getenv('INGEST_DEMO_UBUNTU_IP')
                         and path in MACHINE_PATHS | {'/api/health'}
                         and scope['method'] == ('GET' if path == '/api/health' else 'POST'))
        elif not local and path in MACHINE_PATHS and scope.get('scheme') != 'https':
            permitted = False
        if not permitted:
            return await JSONResponse({'detail': 'Transporte no autorizado'}, status_code=403)(scope, receive, send)
        return await self.app(scope, receive, send)
