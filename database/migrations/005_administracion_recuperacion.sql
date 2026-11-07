-- Extend the current identity/session system without deleting historical records.
ALTER TABLE honeypot.usuario DROP CONSTRAINT ck_password_temporal,
 ADD CONSTRAINT ck_password_temporal CHECK(
  NOT password_cambio_obligatorio OR
  (password_temporal_hash IS NULL AND password_temporal_vence_en IS NULL AND password_temporal_usada_en IS NULL) OR
  (password_temporal_vence_en IS NOT NULL AND (password_temporal_hash IS NOT NULL OR password_temporal_usada_en IS NOT NULL))
 );
ALTER TABLE honeypot.usuario
 ADD COLUMN restriccion_acceso varchar(20) CHECK(restriccion_acceso IN ('suspendido','bloqueado')),
 ADD COLUMN motivo_restriccion varchar(300),
 ADD COLUMN restriccion_por uuid REFERENCES honeypot.usuario(id_usuario),
 ADD COLUMN restriccion_en timestamptz,
 ADD COLUMN ultimo_acceso_en timestamptz;
UPDATE honeypot.usuario SET restriccion_acceso='suspendido'
 WHERE autorizacion='aprobado' AND NOT activo;
ALTER TABLE honeypot.usuario ADD CONSTRAINT ck_usuario_restriccion CHECK(restriccion_acceso IS NULL OR NOT activo);
ALTER TABLE honeypot.auth_sesion ADD COLUMN dispositivo varchar(180);
CREATE INDEX ix_auth_sesion_actividad ON honeypot.auth_sesion(id_usuario,ultima_actividad DESC);
UPDATE honeypot.usuario u SET ultimo_acceso_en=s.ultimo FROM
 (SELECT id_usuario,max(mfa_en) ultimo FROM honeypot.auth_sesion WHERE etapa='completa' GROUP BY id_usuario) s
 WHERE s.id_usuario=u.id_usuario;

CREATE TABLE honeypot.auth_solicitud_password (
 id_solicitud uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 id_usuario uuid NOT NULL REFERENCES honeypot.usuario(id_usuario),
 origen varchar(20) NOT NULL DEFAULT 'recuperacion' CHECK(origen IN ('recuperacion','alta')),
 estado varchar(20) NOT NULL DEFAULT 'pendiente' CHECK(estado IN ('pendiente','aprobada','rechazada','expirada','completada','cancelada')),
 vence_en timestamptz NOT NULL,
 resuelto_por uuid REFERENCES honeypot.usuario(id_usuario),
 resuelto_en timestamptz,
 motivo_decision varchar(300),
 enlace_vence_en timestamptz,
 completado_en timestamptz,
 notificacion_estado varchar(20) NOT NULL DEFAULT 'pendiente' CHECK(notificacion_estado IN ('pendiente','enviada','fallida')),
 notificado_en timestamptz,
 estado_registro varchar(20) NOT NULL DEFAULT 'vigente' CHECK(estado_registro IN ('vigente','inactivo')),
 creado_por uuid REFERENCES honeypot.usuario(id_usuario),
 modificado_por uuid REFERENCES honeypot.usuario(id_usuario),
 creado_en timestamptz NOT NULL DEFAULT now(),
 actualizado_en timestamptz NOT NULL DEFAULT now(),
 UNIQUE(id_solicitud,id_usuario),
 CHECK(estado NOT IN ('aprobada','completada') OR (resuelto_por IS NOT NULL AND resuelto_en IS NOT NULL AND enlace_vence_en IS NOT NULL)),
 CHECK(estado<>'completada' OR completado_en IS NOT NULL)
);
CREATE UNIQUE INDEX uq_solicitud_password_abierta ON honeypot.auth_solicitud_password(id_usuario) WHERE estado IN ('pendiente','aprobada');
CREATE INDEX ix_solicitud_password_estado ON honeypot.auth_solicitud_password(estado,creado_en DESC);
CREATE TRIGGER trg_solicitud_password_actualizado BEFORE UPDATE ON honeypot.auth_solicitud_password
 FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();
ALTER TABLE honeypot.auth_token
 ADD COLUMN id_solicitud uuid,
 ADD CONSTRAINT fk_token_solicitud FOREIGN KEY(id_solicitud,id_usuario) REFERENCES honeypot.auth_solicitud_password(id_solicitud,id_usuario),
 ADD CONSTRAINT ck_token_solicitud CHECK(id_solicitud IS NULL OR proposito='password');
CREATE INDEX ix_token_solicitud ON honeypot.auth_token(id_solicitud);
-- Previously issued password links had no administrative approval. Keep history but revoke them.
UPDATE honeypot.auth_token SET usado_en=now(),estado_registro='inactivo'
 WHERE proposito='password' AND usado_en IS NULL;
