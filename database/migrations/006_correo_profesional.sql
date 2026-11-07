-- Safe metadata/reference queue: never stores OTPs, passwords or recovery links.
CREATE TABLE honeypot.auth_soporte (
 id_soporte uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 id_usuario uuid REFERENCES honeypot.usuario(id_usuario),
 nombre varchar(120) NOT NULL,
 correo varchar(254) NOT NULL,
 asunto varchar(140) NOT NULL,
 categoria varchar(20) NOT NULL CHECK(categoria IN ('acceso','mfa','recuperacion','funcional','general')),
 descripcion varchar(3000) NOT NULL,
 correo_verificado boolean NOT NULL DEFAULT false,
 dedupe_hash varchar(64) NOT NULL,
 estado_registro varchar(20) NOT NULL DEFAULT 'vigente' CHECK(estado_registro IN ('vigente','inactivo')),
 creado_por uuid REFERENCES honeypot.usuario(id_usuario),
 modificado_por uuid REFERENCES honeypot.usuario(id_usuario),
 creado_en timestamptz NOT NULL DEFAULT now(),
 actualizado_en timestamptz NOT NULL DEFAULT now(),
 CHECK(NOT correo_verificado OR id_usuario IS NOT NULL)
);
CREATE INDEX ix_soporte_dedupe ON honeypot.auth_soporte(dedupe_hash,creado_en DESC);
CREATE INDEX ix_soporte_usuario ON honeypot.auth_soporte(id_usuario,creado_en DESC);
CREATE TRIGGER trg_soporte_actualizado BEFORE UPDATE ON honeypot.auth_soporte FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();

CREATE TABLE honeypot.auth_notificacion (
 id_notificacion uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 clave varchar(64) NOT NULL UNIQUE,
 tipo varchar(30) NOT NULL CHECK(tipo IN ('administrativa','alerta','soporte','confirmacion_soporte')),
 id_auditoria bigint REFERENCES honeypot.auth_auditoria(id_auditoria),
 id_soporte uuid REFERENCES honeypot.auth_soporte(id_soporte),
 destinatario varchar(254) NOT NULL,
 estado varchar(20) NOT NULL DEFAULT 'pendiente' CHECK(estado IN ('pendiente','en_proceso','aceptado','fallido','incierto','cancelado')),
 intentos integer NOT NULL DEFAULT 0 CHECK(intentos BETWEEN 0 AND 5),
 primer_intento_en timestamptz,
 ultimo_intento_en timestamptz,
 proximo_intento_en timestamptz,
 aceptado_en timestamptz,
 resultado varchar(40),
 estado_registro varchar(20) NOT NULL DEFAULT 'vigente' CHECK(estado_registro IN ('vigente','inactivo')),
 creado_por uuid REFERENCES honeypot.usuario(id_usuario),
 modificado_por uuid REFERENCES honeypot.usuario(id_usuario),
 creado_en timestamptz NOT NULL DEFAULT now(),
 actualizado_en timestamptz NOT NULL DEFAULT now(),
 CHECK((tipo IN ('administrativa','alerta') AND id_auditoria IS NOT NULL AND id_soporte IS NULL)
    OR (tipo IN ('soporte','confirmacion_soporte') AND id_soporte IS NOT NULL AND id_auditoria IS NULL)),
 CHECK(estado<>'aceptado' OR aceptado_en IS NOT NULL)
);
CREATE UNIQUE INDEX uq_notificacion_evento ON honeypot.auth_notificacion(id_auditoria,tipo) WHERE id_auditoria IS NOT NULL;
CREATE UNIQUE INDEX uq_notificacion_soporte ON honeypot.auth_notificacion(id_soporte,tipo) WHERE id_soporte IS NOT NULL;
CREATE INDEX ix_notificacion_pendiente ON honeypot.auth_notificacion(estado,proximo_intento_en,creado_en);
CREATE TRIGGER trg_notificacion_actualizado BEFORE UPDATE ON honeypot.auth_notificacion FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();
