"""Read-only Cowrie/DB telemetry audit. Exports shapes and counts, never log payloads."""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
from urllib.parse import urlsplit


MODES = ("cowrie_shell", "cowrie_proxy", "cowrie_llm")
INSTANCES = tuple(zip(MODES, ("honeypot", "honeypot-proxy", "honeypot-llm"),
                      ("cowrie-tacticlens", "cowrie-proxy", "cowrie-llm")))
EVENT = re.compile(r"cowrie(?:\.[a-z0-9_-]{1,45}){2,6}")
FIELDS = frozenset("""
    arch backend_ip backend_port channel command compCS data destfile direction duplicate
    dst_ip dst_port duration duration_ms encCS error eventid filename hassh hasshAlgorithms
    height honey_ip honey_port input ip kexAlgs langCS late local_ip local_port macCS message
    name new_ip new_port orig_ip orig_port outfile output packet protocol realm response sensor
    session shasum size src_ip src_port timestamp ttylog url username uuid value version width
""".split())
SAMPLE_SIZE = 1500
TAIL_BYTES = 4 * 1024 * 1024


def event_type(value):
    return value if isinstance(value, str) and EVENT.fullmatch(value) else "otro_o_invalido"


def fields(raw):
    visible = {}
    for name, value in raw.items():
        if name in FIELDS:
            visible[name] = type(value).__name__
    return visible


def occurrence(raw, kind):
    session, date = raw.get("session"), raw.get("timestamp")
    if not isinstance(session, str) or not isinstance(date, str):
        return None
    try:
        instant = datetime.fromisoformat(date.replace("Z", "+00:00"))
        if instant.tzinfo is None:
            return None
        instant = instant.astimezone(timezone.utc).isoformat()
        return sha256(json.dumps([session, instant, kind]).encode()).hexdigest()
    except ValueError:
        return None


class Shapes:
    def __init__(self):
        self.counts = defaultdict(Counter)
        self.field_types = defaultdict(lambda: defaultdict(Counter))
        self.occurrences = defaultdict(list)
        self.sessions = set()
        self.sensor_labels = set()
        self.signals = Counter()

    def add(self, raw, kind, receipt=False, instance=False):
        kind = event_type(kind)
        known = fields(raw)
        self.counts[kind].update({"eventos": 1, "recibos": int(receipt), "instancia_en_envoltura": int(instance)})
        if isinstance(raw.get("session"), str):
            self.sessions.add(raw["session"])
        if isinstance(raw.get("sensor"), str):
            self.sensor_labels.add(raw["sensor"])
        for name, type_name in known.items():
            self.field_types[kind][name][type_name] += 1
        self.counts[kind]["campos_fuera_lista"] += len(raw.keys() - FIELDS - {"_collector"})
        if identity := occurrence(raw, kind):
            self.occurrences[identity].append(sorted(known))
        if kind == "cowrie.command.input":
            self.signals["entrada_literal"] += int(isinstance(raw.get("input"), str) and raw.get("realm") is None)
            self.signals["entrada_con_realm"] += int(raw.get("realm") is not None)
        if kind == "cowrie.session.connect":
            port = raw.get("dst_port")
            gate = str(port) if type(port) is int and port in {2222, 2223, 2224} else "otro_o_ausente"
            self.signals[f"conexion_puerto_{gate}"] += 1
        if kind in {"cowrie.login.failed", "cowrie.login.success"}:
            self.signals[kind + ".con_password"] += int(isinstance(raw.get("password"), str) and bool(raw["password"]))

    def report(self, anchors=False):
        output = {"sesiones_en_muestra": len(self.sessions), "etiquetas_sensor_distintas": len(self.sensor_labels),
                  "tipos": self.counts, "campos_y_tipos": self.field_types, "senales": self.signals}
        if anchors:
            output["anclas_pseudonimas"] = self.occurrences
        return output


def command(*args):
    try:
        return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=5, check=False).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def service(name):
    keys = ("ActiveState", "SubState", "Result")
    status = command("systemctl", "show", name, *(f"--property={key}" for key in keys))
    return {key: value for line in status.splitlines() for key, _, value in [line.partition("=")]
            if key in keys and re.fullmatch(r"[a-z-]+", value)}


def readable_text(path):
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            return stream.read(524288)
    except OSError:
        return None


def cowrie_unit(base, unit):
    root = Path("/home/cowrie", base)
    text = readable_text(root / "etc/cowrie.cfg")
    # Match only scalar choices. Credential settings are never selected.
    backend = re.search(r"(?m)^\s*backend\s*=\s*(shell|proxy|llm)\s*$", text or "")
    ports = re.findall(r"(?m)^\s*listen_endpoints\s*=\s*tcp:(\d{1,5})(?::[^\r\n]*)?$", text or "")
    versions = {match[1] for directory in (root, root / "cowrie-env", root / ".venv", root / "venv")
                for path in directory.glob("lib/python*/site-packages/cowrie-*.dist-info")
                if (match := re.fullmatch(r"cowrie-([0-9][A-Za-z0-9.+_-]{0,39})\.dist-info", path.name))}
    if (root / ".git").is_dir():
        version = command("git", "--no-optional-locks", "-C", str(root), "describe", "--tags", "--always")
        if re.fullmatch(r"[A-Za-z0-9.+_-]{4,50}", version):
            versions.add(version)
    return root, {"servicio": service(unit), "config_legible": text is not None,
                  "backend_declarado": backend[1] if backend else None,
                  "puertos_ssh_declarados": list(map(int, ports)), "versiones": sorted(versions)}


def sample_log(path):
    with path.open("rb") as stream:
        size = stream.seek(0, 2)
        offset = max(0, size - TAIL_BYTES)
        stream.seek(offset)
        if offset:
            stream.readline()
        return stream.read(TAIL_BYTES).splitlines()[-SAMPLE_SIZE:]


def export_inventory():
    name = "tacticlens-exportador"
    properties = command("systemctl", "show", name, "--property=EnvironmentFiles", "--property=ExecStart",
                         "--property=WorkingDirectory")
    allow_roots = (Path("/opt/tacticlens-cowrie"), Path("/etc/tacticlens-cowrie"), Path("/home/cowrie"),
                   Path("/etc/default"))
    paths = []
    for value in re.findall(r"/[A-Za-z0-9_/.@-]+", properties):
        path = Path(value).resolve()
        if path.suffix in {".py", ".env"} and any(path.is_relative_to(root) for root in allow_roots):
            paths.append(path)
    paths.extend(Path("/opt/tacticlens-cowrie", file) for file in ("exportar_eventos.py", "sqlite_sender.py"))
    paths.append(Path("/etc/tacticlens-cowrie/exportador.env"))
    scripts = [text for path in set(paths) if path.suffix == ".py" and (text := readable_text(path))]
    targets = set()
    for path in set(paths):
        if path.suffix != ".env":
            continue
        for match in re.finditer(r"(?m)^\s*TACTICLENS_URL\s*=\s*['\"]?(https?://[^\s'\"#]+)", readable_text(path) or ""):
            try:
                url = urlsplit(match[1])
                address = ipaddress.ip_address(url.hostname)
                targets.add((url.scheme, str(address), url.port or (443 if url.scheme == "https" else 80)))
            except ValueError:
                continue
    endpoints = []
    for scheme, address, port in sorted(targets):
        route = command("ip", "-j", "route", "get", address)
        try:
            source = json.loads(route)[0].get("prefsrc")
            source = str(ipaddress.ip_address(source)) if source else None
        except (ValueError, IndexError, AttributeError):
            source = None
        endpoints.append({"esquema": scheme, "destino": address, "puerto": port, "origen_ruta": source})
    return {"servicio": service(name), "temporizador": service(name + ".timer"), "scripts_legibles": len(scripts),
            "cola_presente": Path("/var/lib/tacticlens-cowrie/cola.sqlite3").is_file(), "destinos_configurados": endpoints,
            "marcadores_codigo": {tag: any(tag in script for script in scripts)
                                  for tag in ("instance_id", "source_id", "X-API-Key", "confirmaciones")}}


def remote():
    output = {}
    labels = {}
    for mode, base, unit in INSTANCES:
        root, report = cowrie_unit(base, unit)
        shapes = Shapes()
        logs = sorted((root / "var/log/cowrie").glob("cowrie.json*"))
        # Only read the active log and one uncompressed rotation.
        paths = [root / "var/log/cowrie/cowrie.json"]
        rotations = [path for path in logs if path.suffix != ".gz" and path not in paths and path.is_file()]
        paths.extend(rotations[-1:])
        read, invalid, inaccessible = 0, 0, 0
        for path in paths:
            try:
                lines = sample_log(path)
            except OSError:
                inaccessible += 1
                continue
            read += 1
            for line in lines:
                try:
                    raw = json.loads(line)
                    if not isinstance(raw, dict):
                        raise ValueError()
                except (ValueError, UnicodeError):
                    invalid += 1
                    continue
                collector = raw.get("_collector")
                shapes.add(raw, raw.get("eventid"), instance=isinstance(collector, dict) and "instance_id" in collector)
        report.update(shapes.report(anchors=True))
        report.update(archivos_leidos=read, archivos_inaccesibles=inaccessible, filas_invalidas=invalid)
        output[mode] = report
        labels[mode] = shapes.sensor_labels
    listeners = command("ss", "-H", "-ltn")
    ports = [port for port in (2222, 2223, 2224)
             if re.search(rf"(?m)^\S+\s+\S+\s+\S+\s+\S+:{port}\s", listeners)]
    return {"origen": "cowrie", "hora_utc": datetime.now(timezone.utc).isoformat(),
            "muestra_maxima_por_archivo": SAMPLE_SIZE, "modalidades": output, "exportador": export_inventory(),
            "puertos_tcp_escuchando": ports,
            "etiquetas_repetidas_por_par": {f"{a}/{b}": len(labels[a] & labels[b])
                                          for i,a in enumerate(MODES) for b in MODES[i+1:]}}


def postgres(remote_report=None):
    import psycopg
    from dotenv import dotenv_values
    from psycopg.rows import dict_row
    from backend.rag.mitre_evidence import technique_evidence

    values = dotenv_values(Path(".env"))
    config = {**values, **os.environ}
    modes = {config[f"HONEYPOT_ID_{mode.upper()}"]: mode for mode in MODES if config.get(f"HONEYPOT_ID_{mode.upper()}")}
    shapes = defaultdict(Shapes)
    observed_rules = defaultdict(Counter)
    db_anchors = defaultdict(list)
    with psycopg.connect(dbname=config["DATABASE_NAME"], user=config["DATABASE_USER"],
                         password=config["DATABASE_PASSWORD"], host=config["DATABASE_HOST"],
                         port=config.get("DATABASE_PORT") or 5432, row_factory=dict_row, connect_timeout=5,
                         options="-c default_transaction_read_only=on -c statement_timeout=15000") as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        totals = conn.execute("""
            SELECT s.id_honeypot, count(*) AS eventos, count(DISTINCT s.id_sesion) AS sesiones,
                   count(o.id_evento) AS recibos, max(e.ingresado_en) AS ultima_ingesta
            FROM honeypot.evento e JOIN honeypot.sesion s USING (id_sesion)
            LEFT JOIN honeypot.evento_origen o USING (id_evento)
            GROUP BY s.id_honeypot
        """).fetchall()
        for summary in totals:
            sensor = summary["id_honeypot"]
            mode = modes.get(str(sensor), "desconocido")
            sample = conn.execute("""
                SELECT e.id_evento, e.id_sesion, e.fecha_hora, e.tipo_evento, e.datos_originales, EXISTS (
                    SELECT 1 FROM honeypot.evento_origen o WHERE o.id_evento=e.id_evento) AS recibo
                FROM honeypot.evento e JOIN honeypot.sesion s USING (id_sesion)
                WHERE s.id_honeypot=%s ORDER BY e.ingresado_en DESC, e.id_evento DESC LIMIT %s
            """, (sensor, SAMPLE_SIZE * 2)).fetchall()
            for row in sample:
                raw, kind = row["datos_originales"], row["tipo_evento"]
                shapes[mode].add(raw, kind, receipt=row["recibo"])
                if remote_report and (anchor := occurrence(raw, event_type(kind))):
                    db_anchors[anchor].append((mode, set(fields(raw))))
            for code, signals in technique_evidence([SimpleNamespace(**row) for row in sample], mode).items():
                observed_rules[mode][code] += len(signals)
            summary["modalidad"] = mode
            del summary["id_honeypot"]
    result = {"origen": "postgresql", "solo_lectura": True, "sensor_configurado": sorted(modes.values()),
              "totales_por_sensor": totals, "modalidades": {mode: stats.report() for mode, stats in shapes.items()},
              "evidencia_preliminar_por_contrato": observed_rules}
    if remote_report:
        result["comparacion_muestras"] = compare(remote_report, db_anchors)
    return result


def compare(report, db_anchors):
    comparison = {}
    remote_count = Counter(anchor for mode in MODES for anchor in report["modalidades"][mode]["anclas_pseudonimas"])
    for mode in MODES:
        counts, lost, added = Counter(), Counter(), Counter()
        origin = report["modalidades"][mode]["anclas_pseudonimas"]
        for anchor, remote_fields in origin.items():
            stored = db_anchors.get(anchor, ())
            if not stored:
                counts["sin_par_en_muestra"] += 1
            elif remote_count[anchor] != 1 or len(remote_fields) != 1 or len(stored) != 1:
                counts["ambiguos"] += 1
            else:
                stored_mode, stored_fields = stored[0]
                counts["coincidentes"] += 1
                counts[f"persistidos_como_{stored_mode}"] += 1
                lost.update(set(remote_fields[0]) - stored_fields)
                added.update(stored_fields - set(remote_fields[0]))
        comparison[mode] = {"conteos": counts, "campos_ausentes_en_postgresql": lost, "campos_adicionales_en_postgresql": added}
    return comparison


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres", action="store_true")
    parser.add_argument("--comparar-con", type=Path)
    args = parser.parse_args()
    try:
        origin = json.loads(args.comparar_con.read_text(encoding="utf-8-sig")) if args.comparar_con else None
        result = postgres(origin) if args.postgres else remote()
    except Exception as exc:
        # Connection errors and JSON decoder context can carry data from the source.
        print(json.dumps({"error": type(exc).__name__, "sqlstate": getattr(exc, "sqlstate", None)}))
        return 1
    print(json.dumps(result, ensure_ascii=True, default=str, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
