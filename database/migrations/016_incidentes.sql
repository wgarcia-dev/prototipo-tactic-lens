-- Preserve original Cowrie JSON and the historical allocation of sessions.
ALTER TABLE honeypot.evento ADD COLUMN procedencia_cowrie jsonb
    CHECK (procedencia_cowrie IS NULL OR jsonb_typeof(procedencia_cowrie) = 'object');

CREATE TABLE honeypot.incidente (
    id_incidente uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    revision_actual integer NOT NULL DEFAULT 1 CHECK (revision_actual > 0),
    creado_en timestamptz NOT NULL DEFAULT now(),
    actualizado_en timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incidente_actualizado_idx ON honeypot.incidente (actualizado_en DESC, id_incidente DESC);

CREATE TABLE honeypot.incidente_evaluacion (
    id_incidente uuid NOT NULL REFERENCES honeypot.incidente(id_incidente),
    revision_evaluacion integer NOT NULL CHECK (revision_evaluacion > 0),
    decision text NOT NULL CHECK (decision IN ('incidente_confirmado','actividad_sospechosa','actividad_autorizada','evidencia_insuficiente')),
    severidad text CHECK (severidad IN ('S0','S1','S2','S3','S4')),
    prioridad text NOT NULL CHECK (prioridad IN ('baja','media','alta','inmediata','por_determinar')),
    clasificacion text NOT NULL,
    titulo text NOT NULL,
    resumen text NOT NULL,
    id_actor uuid REFERENCES honeypot.usuario(id_usuario),
    evidencia_sha256 char(64) NOT NULL,
    evaluado_en timestamptz NOT NULL DEFAULT clock_timestamp(),
    detalle jsonb NOT NULL CHECK (jsonb_typeof(detalle) = 'object'),
    PRIMARY KEY (id_incidente, revision_evaluacion)
);
ALTER TABLE honeypot.incidente ADD CONSTRAINT incidente_evaluacion_actual_fk
    FOREIGN KEY (id_incidente, revision_actual) REFERENCES honeypot.incidente_evaluacion(id_incidente, revision_evaluacion)
    DEFERRABLE INITIALLY DEFERRED;
CREATE TRIGGER incidente_evaluacion_inmutable
    BEFORE UPDATE OR DELETE ON honeypot.incidente_evaluacion
    FOR EACH ROW EXECUTE FUNCTION honeypot.impedir_cambio_auditoria();

CREATE TABLE honeypot.incidente_sesion (
    id_incidente uuid NOT NULL REFERENCES honeypot.incidente(id_incidente),
    id_sesion uuid NOT NULL UNIQUE REFERENCES honeypot.sesion(id_sesion),
    revision_ingreso integer NOT NULL,
    correlacion jsonb NOT NULL CHECK (jsonb_typeof(correlacion) = 'object'),
    PRIMARY KEY (id_incidente, id_sesion),
    FOREIGN KEY (id_incidente, revision_ingreso) REFERENCES honeypot.incidente_evaluacion(id_incidente, revision_evaluacion)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE honeypot.incidente_analisis (
    id_analisis uuid PRIMARY KEY REFERENCES honeypot.analisis_llm(id_analisis),
    id_incidente uuid NOT NULL,
    id_sesion uuid NOT NULL,
    revision_ingreso integer NOT NULL,
    FOREIGN KEY (id_incidente,id_sesion) REFERENCES honeypot.incidente_sesion(id_incidente,id_sesion),
    FOREIGN KEY (id_incidente,revision_ingreso) REFERENCES honeypot.incidente_evaluacion(id_incidente,revision_evaluacion)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX incidente_analisis_incidente_idx ON honeypot.incidente_analisis (id_incidente, id_sesion, revision_ingreso DESC);

CREATE TABLE honeypot.incidente_evidencia (
    id_incidente uuid NOT NULL,
    revision_evaluacion integer NOT NULL,
    id_evento bigint NOT NULL REFERENCES honeypot.evento(id_evento),
    id_sesion uuid NOT NULL,
    id_analisis uuid REFERENCES honeypot.analisis_llm(id_analisis),
    grado text NOT NULL CHECK (grado IN ('observacion','intento','resultado_en_honeypot','resultado_confirmado')),
    procedencia jsonb NOT NULL CHECK (jsonb_typeof(procedencia) = 'object'),
    PRIMARY KEY (id_incidente, revision_evaluacion, id_evento),
    FOREIGN KEY (id_incidente,id_sesion) REFERENCES honeypot.incidente_sesion(id_incidente,id_sesion),
    FOREIGN KEY (id_incidente,revision_evaluacion) REFERENCES honeypot.incidente_evaluacion(id_incidente,revision_evaluacion)
);
CREATE TRIGGER incidente_evidencia_inmutable
    BEFORE UPDATE OR DELETE ON honeypot.incidente_evidencia
    FOR EACH ROW EXECUTE FUNCTION honeypot.impedir_cambio_auditoria();
