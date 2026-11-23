"""Evidence-specific scope, access profile and Linux safeguards for reports."""
from .intelligence import ip_scope, normalize_ip
from .operational_report import section
from .rag.behavior import command_features


def references(events):
    return ", ".join("#" + str(event.id_evento) for event in events) or "Sin eventos correspondientes en el conjunto revisado"


def complete_assessment(report, events, session, payload, total):
    by_kind = {}
    for event in events:
        by_kind.setdefault(event.tipo_evento, []).append(event)
    commands = by_kind.get("cowrie.command.input", [])
    features = {event.id_evento: command_features((event.datos_originales or {}).get("input", "")) for event in commands}
    def tagged(tags):
        return [event for event in commands if features[event.id_evento].intersection(tags)]
    connects = by_kind.get("cowrie.session.connect", [])
    raw = connects[0].datos_originales if connects else {}
    port = raw.get("dst_port") or getattr(session, "puerto_destino", None)
    modes = {2222:"Shell Cowrie", 2223:"Proxy hacia Alpine/QEMU", 2224:"Respuestas LLM DeepSeek"}
    try:
        mode = modes.get(int(port), "Modo pendiente de identificar")
    except (ValueError, TypeError):
        mode = "Modo pendiente de identificar"
    proxy_events = by_kind.get("cowrie.proxy.backend_connected", [])
    node = section("Nodo de captura y certeza del entorno", [
        "La relación entre los puertos 2222, 2223 y 2224 y sus modos corresponde a la arquitectura declarada del laboratorio. El puerto observado permite identificar esa ruta; su configuración debe contrastarse con el servicio del sensor.",
        "La comprobación del guest exige telemetría del sistema invitado, obtenida por un canal administrativo de confianza y relacionada con la sesión y su hora."
    ], ["Dato", "Evidencia y nivel de certeza"], [
        ["Sensor declarado en el evento", str(raw.get("sensor", "Sin identificador de sensor en la conexión"))],
        ["Destino y puerto observado", str(raw.get("dst_ip", "Dirección no registrada")) + ":" + str(port or "Sin puerto")],
        ["Ruta del laboratorio", mode],
        ["Conexión al backend del proxy", references(proxy_events)],
        ["Estado real del guest", "Pendiente de verificación independiente. Una conexión proxy o una salida de shell/LLM carece por sí sola de prueba de integridad, persistencia o compromiso del guest."],
        ["Referencia de conexión", references(connects)]
    ])
    try:
        scope = ip_scope(normalize_ip(str(session.ip_origen)))
    except ValueError:
        scope = "sin determinar"
    profile_rows = [["Origen y alcance", str(session.ip_origen) + " · " + scope],
                    ["Puerto efímero de origen", str(raw.get("src_port") or getattr(session,"puerto_origen",None) or "Sin registro")]]
    for kind, field, label in (("cowrie.client.version","version","Banner del cliente"),
                               ("cowrie.client.kex","hassh","HASSH del cliente")):
        matched = by_kind.get(kind, [])
        values = [str((event.datos_originales or {}).get(field)) + " · #" + str(event.id_evento)
                  for event in matched if (event.datos_originales or {}).get(field)]
        profile_rows.append([label, "\n".join(values) or "Sin dato en los eventos revisados"])
    for kind, label in (("cowrie.login.success","Autenticaciones aceptadas"),("cowrie.login.failed","Autenticaciones rechazadas")):
        profile_rows.append([label, references(by_kind.get(kind, []))])
    profile_rows.append(["Enriquecimiento público del origen",
        "Omitido para reputación de IP pública por tratarse de una dirección " + scope + ". Su alcance requiere contexto local."
        if scope != "global" and scope != "sin determinar" else
        "Consultar los resultados y estados de los proveedores registrados en Fuentes externas consultadas. La falta de resultados exige comprobar acceso, conectividad y cobertura."])
    profile_rows.append(["Identidad y autenticación", "El banner y HASSH caracterizan el cliente observado. La atribución personal requiere evidencia adicional. Los secretos capturados se mantienen redactados."])
    profile = section("Perfil de acceso inicial y origen", [], ["Atributo", "Registro y fundamento"], profile_rows)
    examined = []
    for title, tags, extra_kinds, check in (
        ("Persistencia", {"cron","ssh_keys","account_create"}, [], "Revisar crontabs, unidades systemd, usuarios y authorized_keys del guest mediante telemetría administrativa con integridad verificable."),
        ("Exfiltración y salida de red", {"transfer","archive","collection"}, ["cowrie.session.file_download","cowrie.session.file_upload","cowrie.direct-tcpip.request"], "Contrastar destinos, dirección de transferencias, registros de firewall y flujos de red. Una descarga hacia el señuelo indica ingreso, y requiere distinguirse de salida de datos."),
        ("Movimiento lateral y pivoteo", {"network_scan"}, ["cowrie.direct-tcpip.request","cowrie.forward-tcpip.request"], "Correlacionar solicitudes de reenvío y conexiones SSH salientes con flujos y autenticaciones de otros equipos autorizados.")
    ):
        matches = tagged(tags)
        if title.startswith("Movimiento"):
            import re
            matches += [event for event in commands if re.match(r"^\s*(ssh|scp|sftp|telnet)\s", (event.datos_originales or {}).get("input", ""))]
        for kind in extra_kinds:
            matches += by_kind.get(kind, [])
        matches = list({event.id_evento:event for event in matches}.values())
        examined.append([title, ("Entradas o eventos candidatos que requieren corroboración. " + references(matches)) if matches else
            "Sin coincidencias en los campos y reglas revisados. La captura parcial y la cobertura del sensor limitan esta observación.", check])
    coverage = section("Verificación de persistencia, exfiltración y movimiento lateral", [
        f"Se revisaron {len(events)} de {total} eventos almacenados y {len(commands)} entradas de comando. La evaluación aplica reglas deterministas sobre texto capturado y tipos de evento.",
        "Los patrones señalan intentos o referencias candidatas. Confirmar efectos requiere resultados del sensor y, para el guest, evidencia administrativa independiente."
    ], ["Dimensión", "Observación y evidencia", "Comprobación para resolverla"], examined)
    safeguards = []
    access_events = by_kind.get("cowrie.login.success", []) + by_kind.get("cowrie.login.failed", [])
    discovery = tagged({"system_discovery","user_discovery","process_discovery","file_discovery","network_discovery"})
    rules = [
        (access_events, "Preventiva · Autenticación SSH", "Alta", "Acceso SSH observado", "Distribuir y comprobar claves nominativas; validar acceso de emergencia, aplicar PasswordAuthentication no y PermitRootLogin no en el servidor Linux protegido. Validar sshd -t y probar una segunda sesión antes de retirar el acceso anterior.", "La contraseña y el acceso root directo se rechazan; la cuenta autorizada con clave conserva acceso.", "Puede bloquear administración y automatizaciones antiguas; requiere despliegue gradual y reversión preparada."),
        (access_events or commands, "Preventiva · Restricción de origen y segmentación", "Alta", "Superficie de acceso al servicio", "Restringir el SSH administrativo a la VPN o bastión y a orígenes aprobados mediante reglas del firewall y segmentación. Verificar reglas de retorno y acceso de emergencia antes de activar la política.", "Pruebas desde origen permitido y origen excluido producen los resultados aprobados y quedan registradas.", "Riesgo de pérdida de conectividad administrativa o interrupción de integraciones."),
        (discovery, "Preventiva · Mínimo privilegio", "Media", "Reconocimiento post-acceso y alcance de lectura", "Usar cuentas individuales, revisar grupos, sudoers y permisos de directorios sensibles. Limitar sudo a operaciones necesarias y probar la política con visudo -c.", "La cuenta de servicio conserva sus funciones y carece de permisos administrativos ajenos a su cometido.", "Puede afectar tareas de mantenimiento y aplicaciones que dependan de permisos excesivos."),
        (discovery or commands, "Detectiva · Auditoría de sesiones y reconocimiento", "Media", "Descubrimiento del sistema y ejecución de órdenes", "Configurar auditd para registrar ejecución y cambios en rutas sensibles con contexto de usuario, centralizar registros y correlacionar la autenticación con secuencias de reconocimiento. Ajustar reglas y retención al volumen observado.", "Una repetición autorizada de la secuencia genera registros con usuario, tiempo y proceso; la alerta correlacionada referencia la sesión y supera la revisión de falsos positivos.", "Coste de almacenamiento, privacidad y carga de auditoría; aplicar retención y acceso restringido."),
        (access_events or discovery, "Correctiva · Contención condicionada a verificación", "Según impacto corroborado", "Acceso cuya autorización y efectos deben investigarse", "Si se confirma acceso no autorizado, preservar evidencia, revocar la credencial afectada, terminar sesiones comprometidas y aislar el activo conforme al alcance confirmado. Restaurar desde una fuente confiable si se corrobora alteración.", "Las credenciales revocadas dejan de funcionar, se comprueba integridad y los servicios superan pruebas de recuperación autorizadas.", "Puede interrumpir operaciones; la aplicación requiere aprobación del responsable y plan de recuperación.")
    ]
    for relevant, title, priority, risk, measure, validation, impact in rules:
        if relevant:
            related = ["H%02d" % index for index, phase in enumerate((payload.get("informe") or {}).get("fases", []), 1)
                       if set(map(str, phase.get("eventos", []))).intersection(str(event.id_evento) for event in relevant)]
            safeguards.append([title + "\nPrioridad propuesta " + priority,
                "Riesgo abordado. " + risk + "\nHallazgos " + (", ".join(related) or "Por relacionar por el analista") + "\nEvidencia " + references(relevant) + "\n" + measure,
                "Validación. " + validation + "\nImpacto operativo. " + impact])
    defense = section("Salvaguardas defensivas para un servidor Linux en producción", [
        "Propuestas derivadas de los comportamientos capturados. Aplicarlas requiere verificar configuración y permisos del servidor Linux protegido, responsable y ventana de cambio.",
        "En los nodos del laboratorio deben preservarse los objetivos de captura. La réplica de validación permite medir los controles sin modificar la evidencia del caso.",
        "Referencias de configuración. OpenSSH https://man.openbsd.org/sshd_config.5 y auditoría Linux https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/system_design_guide/auditing-the-system_system-design-guide"
    ], ["Clase y prioridad", "Trazabilidad e intervención", "Eficacia e impacto operativo"], safeguards)
    # Use evidence and human decisions as the sole authority for executive severity.
    assessment = payload.get("evaluacion_incidente") or {}
    revisions = assessment.get("revisiones") or []
    decision = revisions[-1] if revisions else {}
    executive = [
        f"La sesión contiene {total} eventos almacenados. En el conjunto revisado hay {len(commands)} entradas de comando, {len(by_kind.get('cowrie.login.success', []))} autenticaciones aceptadas y {len(by_kind.get('cowrie.login.failed', []))} rechazadas.",
        "Se observaron consultas de reconocimiento del entorno. Eventos relacionados. " + references(discovery)
        if discovery else "La reconstrucción técnica documenta las actividades identificadas y sus referencias.",
        "Clasificación del expediente. " + decision.get("decision", assessment.get("clasificacion", "Pendiente de evaluación")) +
        ". Severidad. " + decision.get("severidad", "Por determinar por el analista") + ".",
        "Valoración humana. " + decision["justificacion"] if decision else "La autorización, impacto y decisión de incidente requieren revisión del analista.",
        "La verificación de persistencia, exfiltración y movimiento lateral documenta qué patrones se revisaron y qué corroboración falta."
    ]
    report["sections"][0]["paragraphs"] = executive
    event_types = {str(event.id_evento):event.tipo_evento for event in events}
    phases = (payload.get("informe") or {}).get("fases", [])
    for index, phase in enumerate(phases, 1):
        finding = next((item for item in report["sections"] if item["title"].startswith(f"H{index:02d} ·")), None)
        if finding:
            finding["paragraphs"].append("Tipos de registro citados. " + "; ".join(
                "#"+str(eid)+" · "+event_types.get(str(eid), "Fuera del conjunto mostrado") for eid in phase.get("eventos", [])))
    report["sections"][1:1] = [node, profile]
    index = next(i for i,s in enumerate(report["sections"]) if s["title"] == "Plan de investigación y respuesta")
    report["sections"][index:index] = [coverage, defense]
    report["metadata"] += [("Puerto de captura", str(port or "Sin registro")), ("Modo declarado del nodo", mode)]
    return report
