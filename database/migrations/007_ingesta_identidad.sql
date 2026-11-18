-- Preserve historical IDs/sequences. New sequences are allocated under a sensor lock.
ALTER TABLE honeypot.evento ALTER COLUMN numero_secuencia TYPE bigint;
CREATE TABLE honeypot.evento_origen (
 id_honeypot uuid NOT NULL REFERENCES honeypot.honeypot(id_honeypot),
 origen_id varchar(512) NOT NULL CHECK(length(btrim(origen_id))>0),
 id_evento bigint NOT NULL UNIQUE REFERENCES honeypot.evento(id_evento) ON DELETE RESTRICT,
 contenido_sha256 varchar(64) NOT NULL CHECK(contenido_sha256 ~ '^[0-9a-f]{64}$'),
 registrado_en timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(id_honeypot,origen_id)
);
COMMENT ON TABLE honeypot.evento_origen IS 'Stable occurrence receipts; no raw passwords or API keys. One legacy event can be adopted once.';
