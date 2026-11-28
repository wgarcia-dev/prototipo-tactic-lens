CREATE TABLE honeypot.incidente_respuesta (
    id_respuesta uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    id_incidente uuid NOT NULL UNIQUE,
    revision_plan integer NOT NULL CHECK (revision_plan > 0),
    revision_respuesta integer NOT NULL DEFAULT 1 CHECK (revision_respuesta > 0),
    estado text NOT NULL DEFAULT 'en_respuesta' CHECK (estado IN ('en_respuesta','resuelto','cerrado','cancelado')),
    objetivo text NOT NULL,
    alcance text NOT NULL,
    criterio_cierre text NOT NULL,
    id_responsable uuid REFERENCES honeypot.usuario(id_usuario),
    fases_no_aplicables jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(fases_no_aplicables) = 'object'),
    resolucion jsonb CHECK (resolucion IS NULL OR jsonb_typeof(resolucion) = 'object'),
    creado_en timestamptz NOT NULL DEFAULT now(),
    actualizado_en timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id_respuesta, id_incidente),
    FOREIGN KEY (id_incidente, revision_plan)
        REFERENCES honeypot.incidente_evaluacion(id_incidente, revision_evaluacion)
);

CREATE TABLE honeypot.incidente_accion (
    id_accion uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    orden bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    id_respuesta uuid NOT NULL,
    id_incidente uuid NOT NULL,
    revision_origen integer NOT NULL,
    revision_validada integer NOT NULL,
    revision_accion integer NOT NULL DEFAULT 1 CHECK (revision_accion > 0),
    fase text NOT NULL CHECK (fase IN ('contencion','erradicacion','recuperacion','verificacion')),
    estado text NOT NULL DEFAULT 'propuesta' CHECK (estado IN
        ('propuesta','aprobada','rechazada','en_curso','ejecutada','verificada','cancelada')),
    medida text NOT NULL,
    objetivo text NOT NULL,
    justificacion text NOT NULL,
    criterio_verificacion text NOT NULL,
    origen text NOT NULL CHECK (origen IN ('manual','analisis','llm','salvaguarda')),
    clave_origen text,
    procedencia jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(procedencia) = 'object'),
    id_responsable uuid REFERENCES honeypot.usuario(id_usuario),
    vence_en date,
    creado_por uuid NOT NULL REFERENCES honeypot.usuario(id_usuario),
    creado_en timestamptz NOT NULL DEFAULT now(),
    actualizado_en timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id_accion, id_respuesta, id_incidente),
    UNIQUE (id_respuesta, clave_origen),
    CHECK (estado NOT IN ('en_curso','ejecutada','verificada') OR id_responsable IS NOT NULL),
    FOREIGN KEY (id_respuesta, id_incidente) REFERENCES honeypot.incidente_respuesta(id_respuesta, id_incidente),
    FOREIGN KEY (id_incidente, revision_origen) REFERENCES honeypot.incidente_evaluacion(id_incidente, revision_evaluacion),
    FOREIGN KEY (id_incidente, revision_validada) REFERENCES honeypot.incidente_evaluacion(id_incidente, revision_evaluacion)
);
CREATE INDEX incidente_accion_tablero_idx ON honeypot.incidente_accion(estado, orden DESC);
CREATE INDEX incidente_accion_respuesta_idx ON honeypot.incidente_accion(id_respuesta, orden DESC);
CREATE INDEX incidente_accion_responsable_idx ON honeypot.incidente_accion(id_responsable, estado, orden DESC);

CREATE TABLE honeypot.incidente_accion_evidencia (
    id_evidencia bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id_accion uuid NOT NULL,
    id_respuesta uuid NOT NULL,
    id_incidente uuid NOT NULL,
    revision_evaluacion integer NOT NULL,
    id_evento bigint REFERENCES honeypot.evento(id_evento),
    id_sesion uuid REFERENCES honeypot.sesion(id_sesion),
    id_analisis uuid REFERENCES honeypot.analisis_llm(id_analisis),
    referencia text,
    tipo text NOT NULL CHECK (tipo IN ('propuesta','ratificacion','ejecucion','verificacion','avance','cancelacion')),
    id_actor uuid NOT NULL REFERENCES honeypot.usuario(id_usuario),
    creado_en timestamptz NOT NULL DEFAULT now(),
    CHECK ((id_evento IS NOT NULL AND id_sesion IS NOT NULL AND referencia IS NULL)
        OR (id_evento IS NULL AND id_sesion IS NULL AND id_analisis IS NULL AND referencia IS NOT NULL)),
    FOREIGN KEY (id_accion,id_respuesta,id_incidente)
        REFERENCES honeypot.incidente_accion(id_accion,id_respuesta,id_incidente),
    FOREIGN KEY (id_incidente,revision_evaluacion)
        REFERENCES honeypot.incidente_evaluacion(id_incidente,revision_evaluacion)
);
CREATE INDEX incidente_accion_evidencia_idx ON honeypot.incidente_accion_evidencia(id_accion,id_evidencia);

CREATE TABLE honeypot.incidente_respuesta_historial (
    id_cambio bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id_respuesta uuid NOT NULL,
    id_incidente uuid NOT NULL,
    id_accion uuid,
    revision_evaluacion integer NOT NULL,
    revision_respuesta integer NOT NULL CHECK (revision_respuesta > 0),
    id_actor uuid NOT NULL REFERENCES honeypot.usuario(id_usuario),
    operacion text NOT NULL,
    motivo text NOT NULL,
    detalle jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(detalle) = 'object'),
    creado_en timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (id_respuesta,id_incidente) REFERENCES honeypot.incidente_respuesta(id_respuesta,id_incidente),
    FOREIGN KEY (id_accion,id_respuesta,id_incidente)
        REFERENCES honeypot.incidente_accion(id_accion,id_respuesta,id_incidente),
    FOREIGN KEY (id_incidente,revision_evaluacion)
        REFERENCES honeypot.incidente_evaluacion(id_incidente,revision_evaluacion)
);
CREATE INDEX incidente_respuesta_historial_idx ON honeypot.incidente_respuesta_historial(id_respuesta,id_cambio DESC);

CREATE TABLE honeypot.incidente_recomendacion_lote (
    id_lote uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    id_respuesta uuid NOT NULL,
    id_incidente uuid NOT NULL,
    revision_evaluacion integer NOT NULL,
    id_actor uuid NOT NULL REFERENCES honeypot.usuario(id_usuario),
    huella char(64) NOT NULL,
    evidencia_sha256 char(64) NOT NULL,
    proveedor text NOT NULL,
    modelo text NOT NULL,
    version_prompt text NOT NULL,
    estado text NOT NULL CHECK (estado IN ('en_proceso','completado','fallido','vencido','sustituido')),
    resultado jsonb,
    error_codigo text,
    vence_en timestamptz NOT NULL,
    creado_en timestamptz NOT NULL DEFAULT now(),
    terminado_en timestamptz,
    UNIQUE (id_lote,id_respuesta),
    FOREIGN KEY (id_respuesta,id_incidente) REFERENCES honeypot.incidente_respuesta(id_respuesta,id_incidente),
    FOREIGN KEY (id_incidente,revision_evaluacion)
        REFERENCES honeypot.incidente_evaluacion(id_incidente,revision_evaluacion)
);
CREATE UNIQUE INDEX incidente_recomendacion_activa_idx
    ON honeypot.incidente_recomendacion_lote(id_respuesta) WHERE estado = 'en_proceso';
CREATE INDEX incidente_recomendacion_reuso_idx ON honeypot.incidente_recomendacion_lote(id_respuesta,huella,estado);

CREATE TABLE honeypot.incidente_recomendacion_peticion (
    id_respuesta uuid NOT NULL,
    clave_sha256 char(64) NOT NULL,
    id_lote uuid NOT NULL,
    PRIMARY KEY (id_respuesta,clave_sha256),
    FOREIGN KEY (id_lote,id_respuesta) REFERENCES honeypot.incidente_recomendacion_lote(id_lote,id_respuesta)
);

CREATE TABLE honeypot.incidente_respuesta_config (
    tablero boolean PRIMARY KEY DEFAULT true CHECK (tablero),
    wip_activo boolean NOT NULL DEFAULT true,
    limite_wip integer NOT NULL DEFAULT 5 CHECK (limite_wip BETWEEN 1 AND 10000),
    revision_config integer NOT NULL DEFAULT 1 CHECK (revision_config > 0)
);
INSERT INTO honeypot.incidente_respuesta_config DEFAULT VALUES;
