"""Read-only local readiness verification; no login, paid LLM, email or sensor."""
import asyncio
import json
import os
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from sqlalchemy import text
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from scripts.portability import ROOT, check, engine_for


def local_url(value):
    parsed = urlparse(value)
    if (parsed.scheme != 'http' or parsed.hostname not in {'127.0.0.1', 'localhost', '::1'}
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {'', '/'}):
        raise ValueError('El verificador admite solo una URL HTTP local sin credenciales')
    return value.rstrip('/')


async def socket_boundary(base):
    # A real TCP handshake checks the endpoint and auth boundary without creating
    # a login/session, exposing cookies or changing last-activity data in the DB.
    rejected=False
    try:
        async with connect(base.replace('http://', 'ws://', 1) + '/api/monitor/ws',
                           origin='http://127.0.0.1:5173', subprotocols=['tacticlens.monitor.v1'],
                           proxy=None, open_timeout=5, close_timeout=2) as ws:
            try:
                await asyncio.wait_for(ws.recv(), timeout=5)
            except ConnectionClosed as exc:
                rejected=exc.rcvd is not None and exc.rcvd.code==4401
    except InvalidStatus as exc:
        # ASGI rejects a socket closed before accept() with HTTP 403.
        rejected=exc.response.status_code==403
    if not rejected:
        raise RuntimeError('WebSocket no rechazo la falta de autenticacion correctamente')
    return {'endpoint_accesible': True, 'sin_sesion_rechazado': True,
            'sesion_mfa_real': 'Comprobar en el navegador; no se omite MFA'}


def verify(backend='http://127.0.0.1:8000', frontend='http://127.0.0.1:5173'):
    backend, frontend = local_url(backend), local_url(frontend)
    database = check(model=True)
    if not any(c['version'] == '20.1' for c in database['catalogo']):
        raise RuntimeError('No se encontro el catalogo Enterprise 20.1 restaurado')
    embeddings = database['embeddings']
    if not embeddings['vigentes'] or embeddings['vigentes'] != embeddings['vectores'] or embeddings['dimension'] != 384:
        raise RuntimeError('Catalogo/embeddings incompletos o incompatibles')
    engine = engine_for()
    try:
        with engine.connect() as conn:
            conn.execute(text('SET TRANSACTION READ ONLY'))
            historical = dict(conn.execute(text('''SELECT
                (SELECT count(*) FROM honeypot.sesion) sesiones,
                (SELECT count(*) FROM honeypot.evento) eventos,
                (SELECT count(*) FROM honeypot.ioc) iocs,
                (SELECT count(*) FROM honeypot.observacion_ioc) observaciones,
                (SELECT count(*) FROM honeypot.analisis_llm) analisis,
                (SELECT count(*) FROM honeypot.mapeo_mitre) mapeos''')).mappings().one())
            if not historical['sesiones'] or not historical['eventos']:
                raise RuntimeError('No hay historicos restaurados para continuar el desarrollo')
        from backend.rag.retrieval import search
        candidates = search(engine, 'system information discovery operating system uname', k=5)
        codes = [row['codigo_tecnica'] for row in candidates['resultados']]
        if not codes:
            raise RuntimeError('El buscador hibrido no devolvio candidatos')
    finally:
        engine.dispose()
    with httpx.Client(timeout=6, trust_env=False, follow_redirects=False) as client:
        health = client.get(backend + '/api/health')
        health.raise_for_status()
        if health.json().get('contrato_ingesta') != 'tacticlens.ingesta.v2':
            raise RuntimeError('Backend no reconocido')
        page = client.get(frontend + '/')
        page.raise_for_status()
        if 'TacticLens' not in page.text:
            raise RuntimeError('Frontend no reconocido')
        proxy = client.get(frontend + '/api/health')
        proxy.raise_for_status()
        if proxy.json().get('contrato_ingesta') != 'tacticlens.ingesta.v2':
            raise RuntimeError('Proxy React no llega a FastAPI local')
        guarded = ('/api/auth/me', '/api/sesiones', '/api/iocs', '/api/mitre/catalogo',
                   '/api/mitre/mapeos', '/api/auth/admin/usuarios',
                   '/api/analisis/00000000-0000-0000-0000-000000000000')
        for path in guarded:
            if client.get(backend + path).status_code != 401:
                raise RuntimeError('Una ruta privada no rechazo la falta de sesion: ' + path)
        specification = client.get(backend + '/openapi.json')
        specification.raise_for_status()
        route = specification.json()['paths'].get('/api/sesiones/{id_sesion}/mitre/candidatos', {})
        if 'post' not in route:
            raise RuntimeError('No existe el endpoint de candidatos MITRE')
    socket = asyncio.run(socket_boundary(backend))
    configured = bool(os.getenv('LLM_API_KEY'))
    provider = os.getenv('LLM_PROVIDER', '').lower()
    if provider != 'deepseek' or not configured:
        raise RuntimeError('Falta configurar DeepSeek en el .env privado; no se llamo al proveedor')
    return {'correcto': True, 'postgresql': database, 'historicos': historical,
            'candidatos_locales': codes, 'backend': 'disponible', 'frontend_y_proxy': 'disponibles',
            'rutas_privadas_protegidas': len(guarded), 'websocket': socket,
            'deepseek': {'proveedor': provider, 'clave_presente': configured, 'llamadas_realizadas': 0},
            'alcance': 'Lecturas y limites de acceso. La sesion MFA autenticada se comprueba en navegador o tests aislados.'}


if __name__ == '__main__':
    load_dotenv(ROOT / '.env')
    try:
        print(json.dumps(verify(), ensure_ascii=False, indent=2, default=str))
    except Exception as exc:
        # Never display HTTP bodies, connection URLs or library exception data.
        print('Verificacion incompleta (' + type(exc).__name__ + '); revise arranque, .env privado y guia de migracion.')
        raise SystemExit(1)
