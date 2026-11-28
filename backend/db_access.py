"""Least-privilege contract for the application connection in PostgreSQL."""
from sqlalchemy import text

# Table-wide reads support SQLAlchemy reflection and the existing row projections.
# The runtime has no DELETE, DDL, catalog maintenance, or schema migration grants.
RUNTIME_GRANTS = {
    **dict.fromkeys((
        "honeypot", "rol", "tipo_ioc", "tactica_mitre", "tecnica_mitre", "tecnica_tactica",
        "catalogo_mitre", "modelo_embedding", "schema_migration",
    ), ("SELECT",)),
    **dict.fromkeys((
        "evento", "evento_origen", "modelo_llm", "accion_identificada", "accion_evento", "deteccion_ioc",
        "accion_ioc", "mapeo_mitre_evento", "auth_auditoria", "auth_soporte", "salvaguarda_origen",
        "salvaguarda_historial",
    ), ("SELECT", "INSERT")),
    **dict.fromkeys((
        "sesion", "analisis_llm", "ioc", "observacion_ioc", "mapeo_mitre", "usuario",
        "auth_factor", "auth_token", "auth_sesion", "auth_recuperacion", "auth_limite",
        "auth_solicitud_password", "auth_notificacion", "salvaguarda",
    ), ("SELECT", "INSERT", "UPDATE")),
    "salvaguarda_config": ("SELECT", "UPDATE"),
}
INCIDENT_GRANTS = {
    "incidente": ("SELECT", "INSERT", "UPDATE"),
    **dict.fromkeys(("incidente_evaluacion", "incidente_sesion", "incidente_analisis", "incidente_evidencia"),
                    ("SELECT", "INSERT")),
}
RESPONSE_GRANTS = {
    **dict.fromkeys(("incidente_respuesta", "incidente_accion", "incidente_recomendacion_lote"),
                    ("SELECT", "INSERT", "UPDATE")),
    **dict.fromkeys(("incidente_accion_evidencia", "incidente_respuesta_historial", "incidente_recomendacion_peticion"),
                    ("SELECT", "INSERT")),
    "incidente_respuesta_config": ("SELECT", "UPDATE"),
}
RESPONSE_AUTOMATION_GRANTS = {
    "incidente_borrador": ("SELECT", "INSERT", "UPDATE"),
    "incidente_borrador_version": ("SELECT", "INSERT"),
    "incidente_aviso": ("SELECT", "INSERT", "UPDATE"),
}


def runtime_grants(existing):
    existing = set(existing)
    grants = dict(RUNTIME_GRANTS)
    for group, label in ((INCIDENT_GRANTS, "evaluación"), (RESPONSE_GRANTS, "respuesta"),
                         (RESPONSE_AUTOMATION_GRANTS, "automatización de respuesta")):
        present = existing & group.keys()
        if present and present != group.keys():
            raise RuntimeError(f"El esquema de {label} de incidentes está incompleto")
        if present:
            grants.update(group)
    if existing & RESPONSE_GRANTS.keys() and not INCIDENT_GRANTS.keys() <= existing:
        raise RuntimeError("La respuesta requiere la evaluación de incidentes")
    if existing & RESPONSE_AUTOMATION_GRANTS.keys() and not RESPONSE_GRANTS.keys() <= existing:
        raise RuntimeError("La automatización requiere el esquema de respuesta")
    return grants


def verify_migration_owner(conn):
    if conn.scalar(text("""
        SELECT NOT EXISTS (
            SELECT 1 FROM pg_namespace n WHERE n.nspname = 'honeypot'
              AND pg_get_userbyid(n.nspowner) = current_user
        ) OR EXISTS (
            SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'honeypot' AND pg_get_userbyid(c.relowner) <> current_user
        ) OR EXISTS (
            SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'honeypot' AND pg_get_userbyid(p.proowner) <> current_user
        )
    """)):
        raise RuntimeError("El migrador debe ser el propietario del esquema honeypot y de sus objetos")


def verify_runtime_identity(conn, role):
    flags = conn.execute(text("""
        SELECT r.rolcanlogin, r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolreplication, r.rolbypassrls,
               EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid) AS membership,
               EXISTS (SELECT 1 FROM pg_shdepend d
                       WHERE d.refclassid = 'pg_authid'::regclass AND d.refobjid = r.oid AND d.deptype = 'o'
                         AND (d.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
                              OR (d.classid = 'pg_database'::regclass
                                  AND d.objid = (SELECT oid FROM pg_database WHERE datname = current_database())))) AS owner
        FROM pg_roles r WHERE r.rolname = :role
    """), {"role": role}).one_or_none()
    if flags is None or not flags.rolcanlogin or any(flags[1:]):
        raise RuntimeError("El rol operativo debe ser un LOGIN dedicado, sin propiedad, membresías ni atributos administrativos")


def verify_runtime_access(conn, role):
    verify_runtime_identity(conn, role)
    flags = conn.execute(text("""
        SELECT has_database_privilege(:role, current_database(), 'CONNECT'),
               has_schema_privilege(:role, 'honeypot', 'USAGE'),
               has_database_privilege(:role, current_database(), 'CREATE,TEMP'),
               has_parameter_privilege(:role, 'session_replication_role', 'SET,ALTER SYSTEM'),
               EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg_%'
                         AND n.nspname <> 'information_schema' AND has_schema_privilege(:role, n.oid, 'CREATE')),
               EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                       WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
                         AND (p.prosecdef OR n.nspname = 'honeypot') AND has_schema_privilege(:role, n.oid, 'USAGE')
                         AND has_function_privilege(:role, p.oid, 'EXECUTE'))
    """), {"role": role}).one()
    if not all(flags[:2]) or any(flags[2:]):
        raise RuntimeError("Revise CONNECT/USAGE, CREATE/TEMP efectivos y funciones ejecutables por el rol operativo")

    rows = conn.execute(text("""
        SELECT c.relname,
            ARRAY(SELECT p FROM unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']) p
                           WHERE has_table_privilege(:role, c.oid, p)) AS privileges,
            ARRAY(SELECT p FROM unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES']) p
                           WHERE has_any_column_privilege(:role, c.oid, p)) AS columns,
            has_table_privilege(:role, c.oid, 'SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION') AS grantable
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'honeypot' AND c.relkind IN ('r','p','v','m','f')
    """), {"role": role}).all()
    existing = {row.relname for row in rows}
    grants = runtime_grants(existing)
    mismatch = set(grants) - existing
    for row in rows:
        expected = set(grants.get(row.relname, ()))
        if set(row.privileges) != expected or set(row.columns) != expected or row.grantable:
            mismatch.add(row.relname)
    if mismatch:
        raise RuntimeError(f"Permisos operativos incompatibles en: {', '.join(sorted(mismatch))}")
    for row in owned_sequences(conn, role):
        needs_usage = row.kind == "a" and "INSERT" in grants.get(row.table_name, ())
        if row.usage != needs_usage or row.other_access:
            raise RuntimeError(f"Permisos operativos incompatibles en la secuencia: {row.sequence_name}")
    secured = conn.scalar(text("""
        SELECT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
          WHERE t.tgrelid = 'honeypot.auth_auditoria'::regclass
            AND t.tgname = 'trg_auth_auditoria_inmutable' AND t.tgenabled IN ('O','A')
            AND p.oid = 'honeypot.impedir_cambio_auditoria()'::regprocedure AND NOT p.prosecdef
            AND (t.tgtype & 27) = 27)
    """))
    if not secured:
        raise RuntimeError("La protección de auditoría debe estar activa para UPDATE y DELETE")


def owned_sequences(conn, role):
    return conn.execute(text("""
        SELECT seq.relname AS sequence_name, tab.relname AS table_name, d.deptype AS kind,
               has_sequence_privilege(:role, seq.oid, 'USAGE') AS usage,
               has_sequence_privilege(:role, seq.oid, 'SELECT,UPDATE,USAGE WITH GRANT OPTION') AS other_access
        FROM pg_class seq JOIN pg_namespace n ON n.oid = seq.relnamespace
        LEFT JOIN pg_depend d ON d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass
             AND d.objid = seq.oid AND d.deptype IN ('a','i')
        LEFT JOIN pg_class tab ON tab.oid = d.refobjid
        WHERE seq.relkind = 'S' AND n.nspname = 'honeypot'
    """), {"role": role}).all()


def configure_runtime_grants(conn, role):
    verify_migration_owner(conn)
    verify_runtime_identity(conn, role)
    identifier = conn.dialect.identifier_preparer.quote_identifier
    grantees = f"PUBLIC, {identifier(role)}"
    conn.exec_driver_sql(f"REVOKE ALL ON SCHEMA honeypot FROM {grantees}")
    for object_type in ("TABLES", "SEQUENCES", "ROUTINES"):
        conn.exec_driver_sql(f"REVOKE ALL ON ALL {object_type} IN SCHEMA honeypot FROM {grantees}")
        conn.exec_driver_sql(f"ALTER DEFAULT PRIVILEGES REVOKE ALL ON {object_type} FROM {grantees}")
        conn.exec_driver_sql(f"ALTER DEFAULT PRIVILEGES IN SCHEMA honeypot REVOKE ALL ON {object_type} FROM {grantees}")

    # Table-level REVOKE does not revoke separately granted column privileges.
    columns = conn.execute(text("""
        SELECT c.relname, array_agg(a.attname) AS names
        FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'honeypot' AND a.attnum > 0 AND NOT a.attisdropped AND a.attacl IS NOT NULL
          AND c.relkind IN ('r','p','v','m','f')
        GROUP BY c.relname
    """)).all()
    for table, names in columns:
        fields = ", ".join(map(identifier, names))
        conn.exec_driver_sql(f"REVOKE ALL ({fields}) ON honeypot.{identifier(table)} FROM {grantees}")

    conn.exec_driver_sql(f"GRANT USAGE ON SCHEMA honeypot TO {identifier(role)}")
    existing = conn.scalars(text("SELECT tablename FROM pg_tables WHERE schemaname = 'honeypot'")).all()
    grants = runtime_grants(existing)
    for table, privileges in grants.items():
        conn.exec_driver_sql(f"GRANT {', '.join(privileges)} ON honeypot.{identifier(table)} TO {identifier(role)}")

    # PostgreSQL identity columns need no sequence grants. SERIAL defaults do.
    for row in owned_sequences(conn, role):
        if row.kind == "a" and "INSERT" in grants.get(row.table_name, ()):
            conn.exec_driver_sql(f"GRANT USAGE ON SEQUENCE honeypot.{identifier(row.sequence_name)} TO {identifier(role)}")
    verify_runtime_access(conn, role)
