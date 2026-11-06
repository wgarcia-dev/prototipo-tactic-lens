"""Central, fail-closed boundary for private modules and all browser writes."""
import hmac

from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from .config import CSRF_COOKIE
from .routes import csrf_serializer
from .store import AuthError, authorize_request, rate, transaction

MACHINE_ROUTES = {"/api/ingesta/eventos", "/api/ingesta/heartbeat"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def check_request(request):
    path = request.url.path
    if not path.startswith("/api/") or path in MACHINE_ROUTES:
        return
    if request.method not in SAFE_METHODS:
        settings = request.app.state.auth_settings
        origin = request.headers.get("origin", "")
        cookie, supplied = request.cookies.get(CSRF_COOKIE, ""), request.headers.get("x-csrf-token", "")
        if origin not in settings.origins or not cookie or not hmac.compare_digest(cookie.encode(), supplied.encode()):
            raise AuthError(403, "Solicitud no válida. Recargue la página e intente nuevamente.")
        try:
            csrf_serializer(request).loads(cookie, max_age=28800)
        except (BadSignature, SignatureExpired):
            raise AuthError(403, "La protección de la página expiró. Recárguela.") from None
        if path.startswith("/api/auth/"):
            with transaction(request) as conn:
                if path == "/api/auth/password/fortaleza":
                    rate(conn, request, "fortaleza_ip", ip_limit=300)
                else:
                    rate(conn, request, "autenticacion_ip", ip_limit=120)
    if not path.startswith("/api/auth/") and path != "/api/health":
        authorize_request(request)


class AuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request = Request(scope)

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend([(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
                                (b"referrer-policy", b"no-referrer")])
                message = {**message, "headers": headers}
            await send(message)

        try:
            await run_in_threadpool(check_request, request)
        except AuthError as exc:
            return await JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)(scope, receive, secure_send)

        if request.url.path.startswith("/api/auth/") and request.method not in SAFE_METHODS:
            # Bound memory and validation cost even for chunked requests without Content-Length.
            parts, size = [], 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                part = message.get("body", b"")
                size += len(part)
                if size > 16384:
                    return await JSONResponse({"detail": "Solicitud demasiado grande"}, status_code=413)(scope, receive, secure_send)
                parts.append(part)
                if not message.get("more_body", False):
                    break
            original_receive, delivered = receive, False

            async def body_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": b"".join(parts), "more_body": False}
                return await original_receive()

            receive = body_receive
        return await self.app(scope, receive, secure_send)
