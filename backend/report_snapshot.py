"""Signed report identities without storing a second copy of evidence."""
from datetime import datetime, timezone
import hmac
import os
from uuid import UUID

from fastapi import HTTPException
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .analysis_state import digest
from .session_report import ecuador_time


def signer(settings):
    return URLSafeTimedSerializer(settings.secret, salt="tacticlens-informe-v1")


def snapshot_ttl():
    try:
        return max(1, min(3600, int(os.getenv("REPORT_SNAPSHOT_TTL_SECONDS", "900"))))
    except ValueError:
        return 900


def load_snapshot(settings, token, session_id, analysis_id, actor):
    try:
        data = signer(settings).loads(token, max_age=snapshot_ttl())
        if data["sesion"] != str(session_id) or data["actor"] != actor:
            raise ValueError
        saved = UUID(data["analisis"])
        if analysis_id is not None and saved != analysis_id:
            raise ValueError
        datetime.fromisoformat(data["generado_en"])
        return data, saved
    except SignatureExpired:
        raise HTTPException(410, "La vista previa venció. Actualice el informe antes de exportarlo.") from None
    except (BadSignature, KeyError, TypeError, ValueError):
        raise HTTPException(409, "La versión solicitada no está disponible. Abra una nueva vista previa.") from None


def finalize_report(settings, report, actor, snapshot=None):
    checksum = digest(report)
    if snapshot:
        if not hmac.compare_digest(snapshot["huella"], checksum):
            raise HTTPException(409, "La información del informe cambió. Actualice la vista previa antes de exportar.")
        data = snapshot
    else:
        data = {"sesion": report["id_sesion"], "analisis": report["id_analisis"], "actor": actor,
                "huella": checksum, "generado_en": datetime.now(timezone.utc).isoformat()}
    generation = datetime.fromisoformat(data["generado_en"])
    version = checksum[:16]
    report["metadata"] += [("Versión del informe", version), ("Generado (Ecuador)", ecuador_time(generation))]
    report.update(snapshot_id=version, generado_en=data["generado_en"])
    return report, signer(settings).dumps(data) if not snapshot else None
