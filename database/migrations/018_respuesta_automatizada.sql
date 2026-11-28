ALTER TABLE honeypot.incidente_respuesta
    ADD COLUMN origen text NOT NULL DEFAULT 'manual' CHECK (origen IN ('manual','llm','historica')),
    ADD COLUMN detalle_plan jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(detalle_plan) = 'object');

ALTER TABLE honeypot.incidente_accion
    DROP CONSTRAINT incidente_accion_fase_check,
    ADD CONSTRAINT incidente_accion_fase_check CHECK (fase IN
        ('investigacion','contencion','erradicacion','recuperacion','mitigacion','verificacion')),
    ADD COLUMN prioridad text NOT NULL DEFAULT 'media' CHECK (prioridad IN ('baja','media','alta','inmediata'));

CREATE INDEX incidente_accion_plazo_idx ON honeypot.incidente_accion(vence_en)
    WHERE estado IN ('aprobada','en_curso') AND vence_en IS NOT NULL;

CREATE TABLE honeypot.incidente_borrador (
    id_borrador uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    id_incidente uuid NOT NULL,
    revision_evaluacion integer NOT NULL,
    evidencia_sha256 char(64) NOT NULL,
    version_prompt text NOT NULL,
    generacion integer NOT NULL DEFAULT 0 CHECK (generacion >= 0),
    estado text NOT NULL DEFAULT 'pendiente' CHECK (estado IN
        ('pendiente','en_proceso','disponible','abstencion','fallido','sustituido','aprobado','rechazado')),
    historico boolean NOT NULL DEFAULT false,
    intentos integer NOT NULL DEFAULT 0 CHECK (intentos BETWEEN 0 AND 3),
    disponible_en timestamptz NOT NULL DEFAULT now(),
    token_ejecucion uuid,
    vence_en timestamptz,
    modelo text,
    consumo jsonb CHECK (jsonb_typeof(consumo) = 'object'),
    error_codigo text,
    creado_en timestamptz NOT NULL DEFAULT now(),
    terminado_en timestamptz,
    UNIQUE (id_incidente, revision_evaluacion, evidencia_sha256, version_prompt, generacion),
    FOREIGN KEY (id_incidente, revision_evaluacion)
        REFERENCES honeypot.incidente_evaluacion(id_incidente, revision_evaluacion),
    CHECK ((estado = 'en_proceso') = (token_ejecucion IS NOT NULL AND vence_en IS NOT NULL))
);
CREATE UNIQUE INDEX incidente_borrador_pendiente_idx ON honeypot.incidente_borrador(id_incidente)
    WHERE estado IN ('pendiente','en_proceso');
CREATE INDEX incidente_borrador_cola_idx ON honeypot.incidente_borrador(estado, disponible_en, creado_en);
CREATE INDEX incidente_borrador_historial_idx ON honeypot.incidente_borrador(id_incidente, creado_en DESC);

CREATE TABLE honeypot.incidente_borrador_version (
    id_borrador uuid NOT NULL REFERENCES honeypot.incidente_borrador(id_borrador),
    version integer NOT NULL CHECK (version > 0),
    id_actor uuid REFERENCES honeypot.usuario(id_usuario),
    motivo text NOT NULL,
    propuesta jsonb NOT NULL CHECK (jsonb_typeof(propuesta) = 'object'),
    decisiones jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(decisiones) = 'object'),
    creado_en timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id_borrador, version)
);
CREATE TRIGGER incidente_borrador_version_inmutable BEFORE UPDATE OR DELETE ON honeypot.incidente_borrador_version
    FOR EACH ROW EXECUTE FUNCTION honeypot.impedir_cambio_auditoria();

CREATE TABLE honeypot.incidente_aviso (
    id_aviso uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    destinatario uuid NOT NULL REFERENCES honeypot.usuario(id_usuario),
    id_incidente uuid NOT NULL REFERENCES honeypot.incidente(id_incidente),
    id_accion uuid REFERENCES honeypot.incidente_accion(id_accion),
    tipo text NOT NULL,
    clave char(64) NOT NULL,
    vencimiento date,
    creado_en timestamptz NOT NULL DEFAULT now(),
    leido_en timestamptz,
    UNIQUE (destinatario, clave)
);
CREATE INDEX incidente_aviso_bandeja_idx ON honeypot.incidente_aviso(destinatario, creado_en DESC, id_aviso DESC);
