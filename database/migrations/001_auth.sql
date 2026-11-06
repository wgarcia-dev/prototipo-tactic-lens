-- Additive migration. Executed once, transactionally, by scripts.migrate.
-- Existing users remain unable to authenticate until verified and approved.
ALTER TABLE honeypot.rol ADD COLUMN codigo varchar(30);
UPDATE honeypot.rol SET codigo = CASE
 WHEN lower(btrim(nombre)) IN ('administrador','administrador de seguridad') THEN 'administrador'
 WHEN lower(btrim(nombre)) IN ('analista','analista de seguridad') THEN 'analista' END;
CREATE UNIQUE INDEX uq_rol_codigo ON honeypot.rol(codigo);
INSERT INTO honeypot.rol(id_rol,nombre,codigo)
 SELECT coalesce(max(id_rol),0)+1,'Administrador de seguridad','administrador' FROM honeypot.rol
 HAVING NOT EXISTS(SELECT 1 FROM honeypot.rol WHERE codigo='administrador');
INSERT INTO honeypot.rol(id_rol,nombre,codigo)
 SELECT coalesce(max(id_rol),0)+1,'Analista de seguridad','analista' FROM honeypot.rol
 HAVING NOT EXISTS(SELECT 1 FROM honeypot.rol WHERE codigo='analista');

ALTER TABLE honeypot.usuario
 ADD COLUMN cedula varchar(10),
 ADD COLUMN nombres varchar(58),
 ADD COLUMN apellidos varchar(58),
 ADD COLUMN nombre_usuario varchar(64),
 ADD COLUMN correo_verificado_en timestamptz,
 ADD COLUMN autorizacion varchar(20) NOT NULL DEFAULT 'pendiente',
 ADD COLUMN autorizado_por uuid REFERENCES honeypot.usuario(id_usuario),
 ADD COLUMN autorizado_en timestamptz,
 ADD COLUMN creado_por uuid REFERENCES honeypot.usuario(id_usuario),
 ADD COLUMN modificado_por uuid REFERENCES honeypot.usuario(id_usuario),
 ADD CONSTRAINT ck_usuario_autorizacion CHECK(autorizacion IN ('pendiente','aprobado')),
 ADD CONSTRAINT ck_usuario_cedula CHECK(cedula IS NULL OR cedula ~ '^[0-9]{10}$'),
 ADD CONSTRAINT ck_usuario_username CHECK(nombre_usuario IS NULL OR nombre_usuario ~ '^[a-z0-9][a-z0-9_.-]{2,63}$');
CREATE UNIQUE INDEX uq_usuario_cedula ON honeypot.usuario(cedula);
CREATE UNIQUE INDEX uq_usuario_username ON honeypot.usuario(lower(btrim(nombre_usuario)));
-- Preflight in the migration runner rejects normalized collisions before changes.
CREATE UNIQUE INDEX uq_usuario_correo_normalizado ON honeypot.usuario(lower(btrim(correo)));
UPDATE honeypot.usuario SET correo=lower(btrim(correo));

CREATE TABLE honeypot.auth_factor (
 id_usuario uuid PRIMARY KEY REFERENCES honeypot.usuario(id_usuario),
 secreto_cifrado text,
 confirmado_en timestamptz,
 vence_en timestamptz NOT NULL,
 ultimo_intervalo bigint NOT NULL DEFAULT -1,
 CHECK(confirmado_en IS NULL OR secreto_cifrado IS NOT NULL)
);
CREATE TABLE honeypot.auth_token (
 id_token uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 id_usuario uuid NOT NULL REFERENCES honeypot.usuario(id_usuario),
 proposito varchar(20) NOT NULL CHECK(proposito IN ('correo','password')),
 token_hash varchar(64) NOT NULL UNIQUE,
 vence_en timestamptz NOT NULL,
 intentos integer NOT NULL DEFAULT 0 CHECK(intentos>=0),
 usado_en timestamptz
);
CREATE INDEX ix_auth_token_usuario ON honeypot.auth_token(id_usuario,proposito,vence_en);
CREATE TABLE honeypot.auth_sesion (
 id_sesion uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 id_usuario uuid NOT NULL REFERENCES honeypot.usuario(id_usuario),
 token_hash varchar(64) NOT NULL UNIQUE,
 etapa varchar(30) NOT NULL CHECK(etapa IN ('correo','aprobacion','configurar_mfa','mfa','completa')),
 primaria_en timestamptz NOT NULL DEFAULT now(),
 mfa_en timestamptz,
 vence_en timestamptz NOT NULL,
 ultima_actividad timestamptz NOT NULL DEFAULT now(),
 ip_hash varchar(64) NOT NULL,
 revocado_en timestamptz,
 CHECK(etapa<>'completa' OR mfa_en IS NOT NULL)
);
CREATE INDEX ix_auth_sesion_usuario ON honeypot.auth_sesion(id_usuario,revocado_en);
CREATE TABLE honeypot.auth_recuperacion (
 id_recuperacion uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 id_usuario uuid NOT NULL REFERENCES honeypot.usuario(id_usuario),
 codigo_hash varchar(64) NOT NULL UNIQUE,
 usado_en timestamptz
);
CREATE INDEX ix_auth_recuperacion_usuario ON honeypot.auth_recuperacion(id_usuario);
CREATE TABLE honeypot.auth_limite (
 clave varchar(64) PRIMARY KEY,
 ventana timestamptz NOT NULL,
 intentos integer NOT NULL CHECK(intentos>=0)
);
CREATE TABLE honeypot.auth_auditoria (
 id_auditoria bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 id_usuario uuid REFERENCES honeypot.usuario(id_usuario),
 actor_id uuid REFERENCES honeypot.usuario(id_usuario),
 tipo varchar(80) NOT NULL,
 fecha_evento timestamptz NOT NULL DEFAULT now(),
 metadatos jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(metadatos)='object')
);
CREATE INDEX ix_auth_auditoria_fecha ON honeypot.auth_auditoria(fecha_evento DESC);

-- The same audit convention for every new technical entity and the existing role.
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['rol','auth_factor','auth_token','auth_sesion','auth_recuperacion','auth_limite','auth_auditoria'] LOOP
  EXECUTE format('ALTER TABLE honeypot.%I ADD COLUMN estado_registro varchar(20) NOT NULL DEFAULT ''vigente'' CHECK(estado_registro IN (''vigente'',''inactivo'')), ADD COLUMN creado_por uuid REFERENCES honeypot.usuario(id_usuario), ADD COLUMN modificado_por uuid REFERENCES honeypot.usuario(id_usuario)',t);
  IF t<>'rol' THEN
   EXECUTE format('ALTER TABLE honeypot.%I ADD COLUMN creado_en timestamptz NOT NULL DEFAULT now(), ADD COLUMN actualizado_en timestamptz NOT NULL DEFAULT now()',t);
   EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON honeypot.%I FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria()','trg_'||t||'_actualizado',t);
  END IF;
 END LOOP;
END $$;
