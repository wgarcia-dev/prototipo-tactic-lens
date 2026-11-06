-- Preserve existing credentials and approvals; only new registrations use this flow.
ALTER TABLE honeypot.usuario
 DROP CONSTRAINT ck_usuario_autorizacion,
 ADD CONSTRAINT ck_usuario_autorizacion CHECK(autorizacion IN ('pendiente','aprobado','rechazado')),
 ADD COLUMN password_cambio_obligatorio boolean NOT NULL DEFAULT false,
 ADD COLUMN password_temporal_hash text,
 ADD COLUMN password_temporal_vence_en timestamptz,
 ADD COLUMN password_temporal_usada_en timestamptz,
 ADD COLUMN rechazado_por uuid REFERENCES honeypot.usuario(id_usuario),
 ADD COLUMN rechazado_en timestamptz,
 ADD COLUMN motivo_rechazo varchar(300),
 ADD CONSTRAINT ck_password_temporal CHECK(
   NOT password_cambio_obligatorio OR
   (password_temporal_vence_en IS NOT NULL AND
    ((password_temporal_hash IS NOT NULL AND password_temporal_usada_en IS NULL) OR
     (password_temporal_hash IS NULL AND password_temporal_usada_en IS NOT NULL)))
 ),
 ADD CONSTRAINT ck_password_temporal_inactiva CHECK(password_cambio_obligatorio OR password_temporal_hash IS NULL);

ALTER TABLE honeypot.auth_sesion
 DROP CONSTRAINT auth_sesion_etapa_check,
 ADD CONSTRAINT auth_sesion_etapa_check CHECK(etapa IN ('correo','aprobacion','crear_password','configurar_mfa','mfa','completa'));

-- Reuse the token store for pre-registration; proof is bound to an HttpOnly cookie.
ALTER TABLE honeypot.auth_token
 ALTER COLUMN id_usuario DROP NOT NULL,
 DROP CONSTRAINT auth_token_proposito_check,
 ADD CONSTRAINT auth_token_proposito_check CHECK(proposito IN ('correo','password','pre_registro')),
 ADD COLUMN correo varchar(254),
 ADD COLUMN navegador_hash varchar(64),
 ADD COLUMN verificado_en timestamptz,
 ADD CONSTRAINT ck_token_titular CHECK(
   (proposito='pre_registro' AND id_usuario IS NULL AND correo IS NOT NULL AND navegador_hash IS NOT NULL) OR
   (proposito IN ('correo','password') AND id_usuario IS NOT NULL)
 );
CREATE INDEX ix_token_pre_registro_navegador ON honeypot.auth_token(navegador_hash,creado_en DESC) WHERE proposito='pre_registro';
CREATE INDEX ix_token_pre_registro_correo ON honeypot.auth_token(correo,creado_en DESC) WHERE proposito='pre_registro';
