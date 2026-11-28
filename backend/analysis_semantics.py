"""Static, evidence-scoped descriptions for telemetry and narrative validation."""
from collections import defaultdict
from dataclasses import asdict, dataclass
from itertools import groupby
import re

from .rag.mitre_evidence import COMMAND_INPUT, telemetry
from .threat_evaluation import FAILURES, classification_confidence

# Each display value is server-owned. Arguments and captured text never become labels.
OPERATIONS = {
    "pwd": ("directorio_actual", "consultar el directorio de trabajo", "directorio de trabajo", "descubrimiento"),
    "whoami": ("identidad", "consultar la identidad del usuario", "identidad de usuario", "descubrimiento"),
    "id": ("identidad", "consultar la identidad y los grupos de la cuenta", "identidad de usuario", "descubrimiento"),
    "hostname": ("nombre_host", "consultar el nombre del sistema", "nombre del sistema", "descubrimiento"),
    "uname": ("plataforma", "consultar información del sistema", "información del sistema", "descubrimiento"),
    "ls": ("listar", "enumerar el contenido de un directorio", "directorio indicado", "descubrimiento"),
    "lsblk": ("almacenamiento", "enumerar dispositivos de almacenamiento", "dispositivos de almacenamiento", "descubrimiento"),
    "df": ("espacio", "consultar el espacio de almacenamiento", "sistemas de archivos", "descubrimiento"),
    "ps": ("procesos", "consultar los procesos", "procesos del sistema", "descubrimiento"),
    "top": ("procesos", "consultar los procesos", "procesos del sistema", "descubrimiento"),
    "uptime": ("actividad_sistema", "consultar el tiempo de actividad", "información del sistema", "descubrimiento"),
    "groups": ("grupos", "consultar la pertenencia a grupos", "grupos de usuario", "descubrimiento"),
    "date": ("reloj", "consultar la fecha y hora", "reloj del sistema", "descubrimiento"),
    "free": ("memoria", "consultar el uso de memoria", "memoria del sistema", "descubrimiento"),
    "clear": ("pantalla", "limpiar la pantalla del terminal", "pantalla del terminal", "interaccion"),
    "echo": ("mostrar", "mostrar texto en el terminal", "terminal", "interaccion"),
    "cd": ("cambiar_directorio", "cambiar el directorio de trabajo", "directorio indicado", "interaccion"),
    "exit": ("salir", "finalizar la interacción", "sesión de terminal", "finalizacion"),
    "cat": ("leer", "leer un archivo", "archivo indicado", "recursos"),
    "head": ("leer", "leer las primeras líneas de un archivo", "archivo indicado", "recursos"),
}
EVENTS = {
    "cowrie.session.connect": ("conexion", "Conexión recibida", "servicio de captura"),
    "cowrie.client.version": ("negociacion", "Identificador del cliente registrado", "transporte SSH"),
    "cowrie.client.kex": ("negociacion", "Intercambio criptográfico registrado", "transporte SSH"),
    "cowrie.login.success": ("autenticacion", "Autenticación aceptada por el sensor", "control de acceso"),
    "cowrie.login.failed": ("autenticacion", "Autenticación rechazada por el sensor", "control de acceso"),
    "cowrie.direct-tcpip.request": ("red", "Solicitud de reenvío de transporte", "destino de red"),
    "cowrie.log.closed": ("registro", "Registro de captura cerrado", "registro de sesión"),
    "cowrie.session.closed": ("finalizacion", "Cierre de sesión registrado sin atribución causal", "sesión"),
}
PHASE_NAMES = {
    "conexion":"Establecimiento de conexión","negociacion":"Negociación SSH","autenticacion":"Autenticación",
    "interaccion":"Interacción por terminal","descubrimiento":"Consultas de descubrimiento","finalizacion":"Finalización de la interacción",
    "recursos":"Solicitudes sobre recursos","red":"Solicitudes de red","transferencia":"Transferencia registrada",
    "registro":"Registro de captura","modificacion":"Solicitudes de modificación","fallo":"Fallo registrado",
    "contexto":"Eventos auxiliares de sesión",
}
SPECIAL = {
    "T1059.001","T1059.004","T1059.006","T1059.007","T1059.011","T1543.002","T1560.001","T1572",
}
STATIC_RESOURCES = {"/","/tmp","/etc","/proc","/etc/hostname","/etc/os-release","/proc/version","/etc/passwd"}
SAFE_ACTION_TOOLS = set(OPERATIONS) | {
    "sh","bash","dash","zsh","pwsh","python","python2","python3","node","nodejs","lua","lua5.3","lua5.4","luajit",
    "wget","curl","ip","arp","ss","netstat","nmap","tcpdump","at","crontab","systemctl","chmod","truncate",
    "chage","usermod","useradd","gpasswd","tar","shutdown","getent","grep","journalctl","virt-what","passwd",
    "systemd-detect-virt","nmcli","iw","iwconfig","showmount","lsusb","lspci","timedatectl","localectl","lsmod",
    "locale","dpkg","dpkg-query","rpm","apt","pacman","apk","unset","set","history","unshadow","service",
}


@dataclass(frozen=True)
class Behavior:
    evento: int
    categoria: str
    operacion: str
    descripcion: str
    estado: str
    recurso: str | None
    herramienta: str | None = None
    objetivo: str | None = None
    limitacion: str | None = None
    indicador_script: bool = False

    def public(self):
        return asdict(self)


def simple_operation(command):
    if not command or command.append_target or command.tool not in OPERATIONS:
        return None
    tool, args = command.tool, command.args
    accepted = not args
    if tool == "exit":
        accepted = not args or len(args) == 1 and args[0].isdigit()
    elif tool == "uname":
        accepted = all(re.fullmatch(r"-[asnrvmpio]+", a) for a in args)
    elif tool in {"ls","lsblk","df","ps","top"}:
        accepted = all(re.fullmatch(r"-?[a-zA-Z0-9]+|/[\w./-]+|\.[\w./-]*", a) for a in args)
    elif tool == "echo":
        accepted = not any(a.startswith("-") for a in args)
    elif tool in {"cd","cat","head"}:
        accepted = tool == "cd" and not args or (
            len(args) == 1 and not args[0].startswith("-") and bool(re.fullmatch(r"[.\w/~-]+", args[0])))
    return OPERATIONS[tool] if accepted else None


def describe_events(events, modality, mitre=(), resource_for=None):
    witnesses = defaultdict(list)
    for witness in mitre:
        for eid in witness.ids:
            witnesses[eid].append(witness)
    output = {}
    for event in events:
        eid, kind = event.id_evento, event.tipo_evento
        related = witnesses[eid]
        recorded = next((w for w in related if w.grade == "resultado_en_honeypot"), None)
        if recorded:
            behavior = Behavior(eid,"transferencia","descarga_registrada","Descarga registrada por el sensor",
                                "resultado_observado","artefacto transferido",limitacion="El registro acredita la descarga dentro del sensor.")
        elif kind == COMMAND_INPUT:
            command = telemetry(event, modality).command
            tool = command.tool if command and command.tool in SAFE_ACTION_TOOLS else None
            operation = simple_operation(command)
            if operation:
                code, objective, target, category = operation
                if tool in {"ls","cat","head","cd"}:
                    literal = next((arg for arg in command.args if arg in STATIC_RESOURCES),None)
                    if literal:
                        target = literal
                behavior = Behavior(eid,category,code,f"Se solicitó {objective}", "intento",target,tool,objective)
            elif related:
                w = related[0]
                from .threat_evaluation import ROWS
                tactics = {t["codigo"] for t in ROWS[w.code]["tacticas_admitidas"]}
                category = ("descubrimiento" if "TA0007" in tactics else "red" if "TA0011" in tactics else
                            "modificacion" if tactics & {"TA0003","TA0112","TA0040","TA0004"} else "recursos")
                description = w.summary.rstrip(".")
                behavior = Behavior(eid,category,w.code,description,"intento",
                                    resource_for(w) if resource_for else None,tool,description,
                                    indicador_script=w.code in SPECIAL and bool(command and command.args and
                                       command.args[-1].endswith((".py",".sh",".js",".lua",".ps1"))))
            else:
                behavior = Behavior(eid,"interaccion","orden_sin_semantica",
                    f"Entrada literal con {tool}" if tool else "Entrada de terminal registrada",
                    "intento" if command else "no_determinable",None,tool,
                    limitacion="Operación sin interpretación fiable; argumentos reservados.")
        elif kind == "cowrie.llm.response":
            behavior = Behavior(eid,"contexto","salida_simulada","Respuesta generada por el señuelo",
                                "salida_simulada",None,limitacion="La respuesta generada no acredita ejecución ni efectos.")
        elif kind in FAILURES:
            behavior = Behavior(eid,"fallo",kind,"Fallo registrado por el sensor","fallido",None)
        elif info := EVENTS.get(kind):
            category, description, target = info
            state = "intento" if category == "red" else "registrado"
            behavior = Behavior(eid,category,kind,description,state,target)
        else:
            behavior = Behavior(eid,"contexto","registro_auxiliar","Registro auxiliar de la sesión","no_determinable",None,
                                limitacion="El evento aislado no define una operación.")
        output[eid] = behavior
    return output


def describe_group(behaviors):
    return ". ".join(dict.fromkeys(b.descripcion for b in behaviors)) + "." if behaviors else ""


def chronological_groups(events, behaviors):
    ordered = sorted(events, key=lambda e:(e.fecha_hora,e.id_evento))
    return [(category,list(group)) for category,group in groupby(ordered,lambda e:behaviors[e.id_evento].categoria)]


def characterize(behaviors, events, mitre, history):
    actions = [b for b in behaviors.values() if b.objetivo and b.categoria != "finalizacion"]
    categories = list(dict.fromkeys(b.categoria for b in behaviors.values() if b.categoria != "contexto"))
    operation_codes = {b.operacion for b in actions}
    advanced = any(w.code in {"T1543.002","T1560.001","T1572"} for w in mitre)
    specialized = any(b.operacion in SPECIAL or b.categoria in {"modificacion", "transferencia", "red"} for b in actions)
    complexity = ("avanzada" if advanced else "intermedia" if specialized and len(operation_codes) >= 2 else
                  "basica" if actions or set(categories) & {"autenticacion","conexion","negociacion"} else "no_evaluable")
    basis = {"avanzada":"Existe un testigo especializado validado de correlación o reenvío.",
             "intermedia":"Se registraron operaciones con objetivos diferenciados en la misma sesión.",
             "basica":"Se observó una actividad directa de alcance limitado.",
             "no_evaluable":"Los eventos disponibles no describen un mecanismo analizable."}[complexity]
    sequence = [b.operacion for b in actions]
    signature = tuple(sequence)
    repetition = any(getattr(h,"secuencia",()) == signature for h in history) if len(sequence) >= 3 else False
    dates = {e.id_evento:e.fecha_hora for e in events}
    gaps = [(dates[right.evento]-dates[left.evento]).total_seconds() for left,right in zip(actions,actions[1:])]
    regular = len(gaps) >= 3 and min(gaps) > 0 and max(gaps)-min(gaps) <= 0.2
    scripted = any(b.indicador_script for b in actions)
    sizes = {(e.datos_originales.get("width"),e.datos_originales.get("height")) for e in events
             if e.tipo_evento=="cowrie.client.size"
             and all(type(e.datos_originales.get(key)) is int for key in ("width","height"))}
    interactive = len(sizes) >= 2 and len(actions) >= 3 and len(gaps) >= 2 and max(gaps)-min(gaps) >= 3
    automation = "mixta_probable" if scripted and interactive else "automatizada_probable" if scripted and (repetition or regular) else "manual_probable" if interactive and not scripted and not repetition else "indeterminada"
    indicator = {"mixta_probable":"Solicitud de un script junto con indicios de interacción de terminal.",
                 "automatizada_probable":"Solicitud de script acompañada de regularidad temporal o secuencia repetida.",
                 "manual_probable":"Cambio del terminal y pausas variables entre varias órdenes. Es una inferencia.",
                 "indeterminada":"No hay una combinación suficiente de señales de intervención manual o automática."}[automation]
    if not gaps:
        timing = "Se necesitan al menos dos órdenes interpretables para medir intervalos."
    elif len(gaps) == 1:
        timing = f"Se midió un intervalo de {gaps[0]:.2f} segundos. Una sola medición no permite evaluar regularidad."
    else:
        timing = f"Se midieron {len(gaps)} intervalos. Mínimo de {min(gaps):.2f} s y máximo de {max(gaps):.2f} s."
    terminal = ("La captura registra un único tamaño de terminal." if len(sizes) == 1 else
                f"La captura registra {len(sizes)} tamaños de terminal distintos." if sizes else
                "La captura carece de tamaños de terminal verificables.")
    indicator = "\n".join((
        indicator, f"Intervalos — {timing}",
        "Script — Solicitud de un script registrada." if scripted else "Script — Las órdenes interpretadas carecen de solicitudes explícitas de script.",
        "Secuencia — Coincidencia observada en el historial consultado." if repetition else
        "Secuencia — La comparación disponible no acredita repetición.",
        f"Terminal — {terminal}",
    ))
    cites = [a.evento for a in actions]
    if interactive:
        cites.extend(e.id_evento for e in events if e.tipo_evento == "cowrie.client.size")
    return categories, complexity, automation, basis, indicator, list(dict.fromkeys(cites))


# Full-match only. A safe surface grammar verifies each clause independently and
# never accepts extra clauses, arguments, claims of success, or instructions.
def validated_sentences(proposal, behaviors):
    allowed = {f"{b.descripcion.rstrip('.')}.".casefold(): b.objetivo or b.descripcion for b in behaviors}
    for behavior in behaviors:
        if behavior.objetivo and behavior.herramienta and behavior.descripcion.startswith("Se solicitó "):
            variants = {
                f"La orden {behavior.herramienta} solicitó {behavior.objetivo}.",
                f"Se registró una solicitud para {behavior.objetivo}.",
                f"El cliente solicitó {behavior.objetivo}.",
                f"La sesión registró una solicitud para {behavior.objetivo}.",
                f"Se observó una orden para {behavior.objetivo}.",
                f"Los eventos documentan una solicitud para {behavior.objetivo}.",
                f"La captura contiene una orden para {behavior.objetivo}.",
            }
            allowed.update({variant.casefold(): behavior.objetivo for variant in variants})
    def normalize(sentence):
        return re.sub(r"\s+", " ", sentence.strip()).casefold()

    canonical = {normalize(value): normalize(meaning) for value, meaning in allowed.items()}
    request = re.compile(r"^(?:(?:el cliente|la sesión) )?(?:solicitó|pidió|registró una solicitud para|realizó una solicitud para) (.+?)[.]$")
    nominal = re.compile(r"^(?:se (?:observó|documentó|registró|capturó)|la captura (?:documenta|registra|contiene)) (?:una |la )?(?:solicitud (?:para|de)|orden (?:para|de)) (.+?)[.]?$")
    goals = {normalize(b.objetivo) for b in behaviors if b.objetivo and b.herramienta and b.descripcion.startswith("Se solicitó ")}
    def supported(part):
        value = normalize(part)
        if value in canonical:
            return canonical[value]
        match = request.fullmatch(value) or nominal.fullmatch(value)
        return match[1] if match and match[1] in goals else None
    parts = [part.strip() for part in re.split(r"(?<=\.)\s+|\n+",proposal or "") if part.strip()]
    unique = {}
    rejected = 0
    for part in parts:
        if meaning := supported(part):
            unique.setdefault(meaning, part)
        else:
            rejected += 1
    accepted = list(unique.values())
    return accepted, {"aceptadas":len(accepted), "rechazadas":rejected, "duplicadas":len(parts)-len(accepted)-rejected,
                      "motivo_codigo":"comparacion_literal","motivo":"La proposición debe describir una solicitud u observación contenida en sus citas."}
