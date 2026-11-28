"""Execution bounds and safe failure metadata for an individual analysis."""
import asyncio
from concurrent.futures import ThreadPoolExecutor, TimeoutError as WorkerTimeout
from contextvars import ContextVar, copy_context
from math import isfinite
import os
from threading import BoundedSemaphore
from time import monotonic
from urllib.parse import urlsplit

import httpx


EXPIRED_MESSAGE = "Tiempo de analisis agotado"
DEFAULT_ATTEMPT_SECONDS = 300
_deadline = ContextVar("analysis_deadline", default=None)
_stages = ThreadPoolExecutor(max_workers=8, thread_name_prefix="tacticlens-analysis")
_slots = BoundedSemaphore(8)


class AnalysisFailure(Exception):
    def __init__(self, phase, code, message, retryable, status=502):
        super().__init__(message)
        self.phase, self.code, self.retryable, self.status = phase, code, retryable, status

    def public(self, attempt_id=None):
        return {"id_analisis": str(attempt_id) if attempt_id else None, "fase": self.phase,
                "codigo": self.code, "mensaje": str(self), "reintentable": self.retryable}


def configuration_failure(message):
    return AnalysisFailure("configuracion", "configuracion_invalida", message, False, 503)


def positive_seconds(name, default, maximum=3600):
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        value = 0
    if not isfinite(value) or not 0 < value <= maximum:
        raise configuration_failure(f"Revise el valor de {name}.")
    return value


def provider_configuration():
    provider, model, key = (os.getenv("LLM_PROVIDER", "openai"), os.getenv("LLM_MODEL", ""),
                            os.getenv("LLM_API_KEY", ""))
    base = (os.getenv("LLM_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
    try:
        url = urlsplit(base)
        if (not url.hostname or url.scheme != "https" or url.username is not None or url.password is not None
                or url.query or url.fragment):
            raise ValueError
        _ = url.port
    except ValueError:
        raise configuration_failure("Configure una URL HTTPS válida para el proveedor LLM.") from None
    if (not provider.strip() or not model.strip() or not key.strip() or len(provider) > 80 or len(model) > 120
            or any(c.isspace() for c in provider + model + key)):
        raise configuration_failure("Configure el proveedor, modelo y clave LLM en el servidor.")
    return base, model, key, positive_seconds("LLM_TIMEOUT_SECONDS", 60)


def expired(phase):
    return AnalysisFailure(phase, "plazo_agotado", EXPIRED_MESSAGE, True, 504)


def remaining(phase, cap=None):
    end = _deadline.get()
    if end is None:
        return cap
    seconds = end - monotonic()
    if seconds <= 0:
        raise expired(phase)
    return seconds if cap is None else min(seconds, cap)


def post_provider(url, *, headers, json, timeout):
    """Apply one wall-clock deadline to the whole HTTP exchange."""
    async def request():
        async with asyncio.timeout(timeout):
            async with httpx.AsyncClient(timeout=timeout) as client:
                return await client.post(url, headers=headers, json=json)

    try:
        return asyncio.run(request())
    except TimeoutError:
        raise httpx.ReadTimeout("Provider wall-clock deadline exceeded") from None


class AttemptBudget:
    def __init__(self, seconds):
        self.end = monotonic() + seconds

    def left(self, phase):
        seconds = self.end - monotonic()
        if seconds <= 0:
            raise expired(phase)
        return seconds

    def run(self, phase, function):
        if not _slots.acquire(timeout=self.left(phase)):
            raise expired(phase)
        token = _deadline.set(self.end)
        try:
            context = copy_context()
            future = _stages.submit(context.run, function)
        except BaseException:
            _slots.release()
            raise
        finally:
            _deadline.reset(token)
        future.add_done_callback(lambda _: _slots.release())
        try:
            return future.result(timeout=self.left(phase))
        except WorkerTimeout:
            future.cancel()
            raise expired(phase) from None
