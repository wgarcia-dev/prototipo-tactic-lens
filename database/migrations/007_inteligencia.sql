-- Observables independent of the LLM; analyst decisions remain separate from evidence.
CREATE TABLE honeypot.observacion_ioc (
 id_observacion uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 id_ioc uuid NOT NULL REFERENCES honeypot.ioc(id_ioc),
 id_evento bigint NOT NULL REFERENCES honeypot.evento(id_evento),
 evidencia text NOT NULL CHECK(length(btrim(evidencia)) > 0),
 estado_revision varchar(20) NOT NULL DEFAULT 'pendiente'
   CHECK(estado_revision IN ('pendiente','confirmado','descartado')),
 motivo_revision varchar(500),
 revisado_por uuid REFERENCES honeypot.usuario(id_usuario),
 revisado_en timestamptz,
 creado_en timestamptz NOT NULL DEFAULT now(),
 UNIQUE(id_ioc,id_evento),
 CHECK((estado_revision='pendiente' AND revisado_por IS NULL AND revisado_en IS NULL)
    OR (estado_revision<>'pendiente' AND revisado_por IS NOT NULL AND revisado_en IS NOT NULL
        AND length(btrim(motivo_revision)) >= 10))
);
CREATE INDEX ix_observacion_ioc_evento ON honeypot.observacion_ioc(id_evento);
CREATE INDEX ix_observacion_ioc_revision ON honeypot.observacion_ioc(estado_revision,creado_en DESC);
ALTER TABLE honeypot.mapeo_mitre
 ADD COLUMN estado_revision varchar(20) NOT NULL DEFAULT 'pendiente'
   CHECK(estado_revision IN ('pendiente','confirmado','descartado')),
 ADD COLUMN motivo_revision varchar(500),
 ADD COLUMN revisado_por uuid REFERENCES honeypot.usuario(id_usuario),
 ADD COLUMN revisado_en timestamptz,
 ADD CONSTRAINT ck_mapeo_revision CHECK(
   (estado_revision='pendiente' AND revisado_por IS NULL AND revisado_en IS NULL)
   OR (estado_revision<>'pendiente' AND revisado_por IS NOT NULL AND revisado_en IS NOT NULL
       AND length(btrim(motivo_revision)) >= 10));
