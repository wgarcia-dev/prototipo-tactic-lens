-- Preserve the existing observation, review and detection identities.
ALTER TABLE honeypot.observacion_ioc
    ADD COLUMN IF NOT EXISTS detalles jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(detalles) = 'array');

CREATE UNIQUE INDEX IF NOT EXISTS uq_observacion_ioc_traza
    ON honeypot.observacion_ioc (id_observacion, id_ioc, id_evento);

ALTER TABLE honeypot.deteccion_ioc
    ADD COLUMN IF NOT EXISTS id_observacion uuid
        CHECK (id_observacion IS NULL OR id_evento IS NOT NULL);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'honeypot.deteccion_ioc'::regclass AND conname = 'fk_deteccion_observacion'
    ) THEN
        ALTER TABLE honeypot.deteccion_ioc ADD CONSTRAINT fk_deteccion_observacion
            FOREIGN KEY (id_observacion, id_ioc, id_evento)
            REFERENCES honeypot.observacion_ioc (id_observacion, id_ioc, id_evento)
            MATCH SIMPLE;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_deteccion_observacion
    ON honeypot.deteccion_ioc (id_observacion) WHERE id_observacion IS NOT NULL;
