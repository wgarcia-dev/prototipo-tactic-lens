"""Opt-in minimal diagnostic stages, stored outside the repository."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from threading import Lock
import time
from uuid import UUID

from .analysis_semantics import OPERATIONS, PHASE_NAMES, SAFE_ACTION_TOOLS
from .sensitive import sensitive_field
from .terminal_evidence import SAFE_DIAGNOSTICS, PROVENANCE

# Free-form text and observable values are never serialized. The representation
# preserves field presence, container shape, event IDs and bounded classifications.
ENUMS = frozenset({
    "intento","registrado","resultado_observado","resultado_en_honeypot","efecto_verificado","fallido","no_determinable",
    "contexto","contextual","desconocido","abstencion","observable","indicador_sospechoso","no_evaluable",
    "S0","S1","S2","S3","S4","CF0","CF1","CF2","CF3","solicitado","transferido","mencionado",
    "ausente_cita","evidencia_insuficiente","citas_no_sustentadas","sin_evidencia_determinista",
    "comparacion_literal","respuesta_incompleta","citas_no_admitidas","relacion_sustentada","diligencia_sustentada",
    "fallo_registrado","salida_contextual",
})
CLASSIFICATION_KEYS = {"estado","estado_resultado","grado","grado_evidencia","clasificacion","causa","motivo_codigo","nivel","estado_validacion"}
RULE_KEYS = {"codigo","codigo_mitre","codigo_tecnica","codigo_tactica","regla","reglas_aplicadas","reglas_validacion"}
COUNT_KEYS = {"aceptadas","rechazadas","duplicadas","eventos_snapshot","eventos_en_prompt","total_eventos","total_comandos",
              "salidas_estructuradas","salidas_con_texto","fallos_registrados","salidas_enviadas","salidas_con_extracto",
              "fallos_enviados","salidas_reducidas","evidencias_no_enviadas"}
OPERATIONS_TRACE = {item[0] for item in OPERATIONS.values()} | {"orden_sin_semantica","registro_auxiliar","descarga_registrada"}
SAFE_KEYS = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.-]{0,75}$|^[0-9]{1,20}$")
DECISION_PATH = re.compile(r"(?:acciones\[\d{1,4}\]\.descripcion|fases\[\d{1,4}\]\.(?:observado|interpretacion|resultado)\.\d{1,4}|hipotesis\.propuestas\[\d{1,4}\]\.relacion|recomendaciones\[\d{1,4}\]\.enfoque)")
IDENTIFIER = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|TA\d{4}|(?:RC|AG|LI|RSK|PRI|IO|IMP|CON)\d{1,3})$")
REDACT_FIELD = re.compile(r"password|passwd|passphrase|secret|token|authorization|credential|api[_-]?key|cookie|ttylog|^input$|^valor$|^url$|^username$|^outfile$|^ruta$|^ip_", re.I)
EVENT_KEYS = {"evento","eventos","id_evento","evento_orden","eventos_entregados","referencias_tty","eventos_relacionados"}


def minimized(value, key="", depth=0):
    if depth > 14:
        return {"omitido":"profundidad"}
    if isinstance(value, dict):
        return {name:minimized(item,name,depth+1) for name,item in list(value.items())[:240]
                if isinstance(name,str) and (SAFE_KEYS.fullmatch(name)
                    or key == "motivos_por_campo" and DECISION_PATH.fullmatch(name))
                    and not sensitive_field(name) and not REDACT_FIELD.search(name)}
    if isinstance(value, (list,tuple)):
        return [minimized(item,key,depth+1) for item in value[:180]]
    if isinstance(value, str):
        if ((key in CLASSIFICATION_KEYS and value in ENUMS)
            or (key in EVENT_KEYS and re.fullmatch(r"\d{1,20}",value))
            or (key in RULE_KEYS and IDENTIFIER.fullmatch(value))
            or (key=="operacion" and (value in OPERATIONS_TRACE or IDENTIFIER.fullmatch(value)))
            or (key=="categoria" and value in PHASE_NAMES)
            or (key=="diagnosticos" and value in SAFE_DIAGNOSTICS)
            or (key=="procedencia" and value in {*PROVENANCE.values(),"fallo_reportado_por_cowrie","origen_terminal_no_identificado"})
            or (key=="herramienta" and value in SAFE_ACTION_TOOLS)):
            return value
        return {"texto_omitido":True}
    if type(value) is int and (key in EVENT_KEYS or key in COUNT_KEYS and 0 <= value <= 1_000_000):
        return value
    if type(value) is bool or value is None:
        return value
    return {"valor_omitido":True}


def restrict_windows_acl(path: Path, sid: str):
    """Replace the NTFS DACL without opening inheritance on existing files."""
    from ctypes import POINTER, WinDLL, WinError, byref, c_void_p, get_last_error
    from ctypes.wintypes import BOOL, DWORD, LPWSTR, LPCWSTR

    security = WinDLL("advapi32", use_last_error=True)
    free = WinDLL("kernel32").LocalFree
    free.argtypes = [c_void_p]
    free.restype = c_void_p
    convert = security.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [LPCWSTR, DWORD, POINTER(c_void_p), POINTER(DWORD)]
    convert.restype = BOOL
    get_dacl = security.GetSecurityDescriptorDacl
    get_dacl.argtypes = [c_void_p, POINTER(BOOL), POINTER(c_void_p), POINTER(BOOL)]
    get_dacl.restype = BOOL
    apply_acl = security.SetNamedSecurityInfoW
    apply_acl.argtypes = [LPWSTR, DWORD, DWORD, c_void_p, c_void_p, c_void_p, c_void_p]
    apply_acl.restype = DWORD
    descriptor = c_void_p()
    if not convert(f"D:P(A;OICI;FA;;;{sid})", 1, byref(descriptor), None):
        raise WinError(get_last_error())
    try:
        present, defaulted, acl = BOOL(), BOOL(), c_void_p()
        if not get_dacl(descriptor, byref(present), byref(acl), byref(defaulted)):
            raise WinError(get_last_error())
        if not present.value or not acl.value:
            raise OSError("DACL local sin entradas")
        file_object, dacl, protected_dacl = 1, 4, 0x80000000
        status = apply_acl(str(path.resolve()), file_object, dacl | protected_dacl, None, None, acl, None)
        if status:
            raise WinError(status)
    finally:
        free(descriptor)


def private_directory(path: Path):
    if path.is_symlink() or getattr(path,"is_junction", lambda:False)():
        raise OSError("Directorio de trazas no válido")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or getattr(path,"is_junction", lambda:False)():
        raise OSError("Directorio de trazas no válido")
    if os.name == "nt":
        ident = subprocess.run(["whoami","/user","/fo","csv","/nh"],check=True,capture_output=True,text=True,timeout=5)
        sid = re.search(r"S-1-(?:\d+-)*\d+",ident.stdout)
        if not sid:
            raise OSError("No se pudo limitar el acceso local")
        restrict_windows_acl(path, sid.group())
    else:
        if path.stat().st_uid != os.getuid():
            raise OSError("Directorio de otro usuario")
        path.chmod(0o700)
    return path


class DiagnosticTrace:
    def __init__(self, enabled=False):
        self.enabled = enabled
        self.stages = {}
        self.lock = Lock()

    @classmethod
    def configured(cls):
        return cls(os.getenv("TACTICLENS_TRACE_ANALYSIS","").strip()=="1")

    def record(self, stage, payload):
        if self.enabled:
            value = minimized(payload)
            with self.lock:
                self.stages[stage] = value

    def record_failure(self, failure):
        if self.enabled:
            # AnalysisFailure messages are fixed locally. Store only the typed fields.
            with self.lock:
                self.stages["error"] = {"fase": failure.phase, "codigo": failure.code,
                                        "reintentable": failure.retryable}

    def write(self, analysis_id, directory=None, retention=None):
        if not self.enabled:
            return False
        try:
            filename = str(UUID(str(analysis_id))) + ".json"
            if directory is None:
                base = os.getenv("LOCALAPPDATA") if os.name=="nt" else os.path.expanduser("~/.local/state")
                if not base:
                    return False
                directory = Path(base) / "TacticLens" / "diagnostico-analisis-v2"
            path = private_directory(directory)
            hours = max(1,min(72,int(retention if retention is not None else os.getenv("TACTICLENS_TRACE_HOURS","24"))))
            cutoff = time.time() - hours*3600
            for entry in path.glob("*.json"):
                if not entry.is_symlink() and re.fullmatch(r"[a-f0-9-]{36}\.json",entry.name) and entry.stat().st_mtime < cutoff:
                    entry.unlink(missing_ok=True)
            fd, temp = tempfile.mkstemp(prefix="trace-",suffix=".tmp",dir=path)
            try:
                with self.lock:
                    stages = dict(self.stages)
                with os.fdopen(fd,"w",encoding="utf-8") as stream:
                    json.dump({"creado_en":datetime.now(timezone.utc).isoformat(),"retencion_horas":hours,
                               "etapas":stages},stream,ensure_ascii=False)
                os.replace(temp,path/filename)
            finally:
                Path(temp).unlink(missing_ok=True)
            return True
        except (OSError,ValueError,subprocess.SubprocessError):
            return False

