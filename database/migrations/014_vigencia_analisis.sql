ALTER TABLE honeypot.sesion
    ADD COLUMN revision_eventos bigint NOT NULL DEFAULT 0;

CREATE FUNCTION honeypot.registrar_revision_eventos() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF ROW(OLD.id_sesion, OLD.id_evento, OLD.tipo_evento, OLD.fecha_hora,
               OLD.numero_secuencia, OLD.datos_originales)
           IS NOT DISTINCT FROM
           ROW(NEW.id_sesion, NEW.id_evento, NEW.tipo_evento, NEW.fecha_hora,
               NEW.numero_secuencia, NEW.datos_originales) THEN
            RETURN NULL;
        END IF;
        UPDATE honeypot.sesion
           SET revision_eventos = revision_eventos + 1
         WHERE id_sesion IN (OLD.id_sesion, NEW.id_sesion);
    ELSIF TG_OP = 'INSERT' THEN
        UPDATE honeypot.sesion SET revision_eventos = revision_eventos + 1
         WHERE id_sesion = NEW.id_sesion;
    ELSE
        UPDATE honeypot.sesion SET revision_eventos = revision_eventos + 1
         WHERE id_sesion = OLD.id_sesion;
    END IF;
    RETURN NULL;
END
$$;

REVOKE EXECUTE ON FUNCTION honeypot.registrar_revision_eventos() FROM PUBLIC;

CREATE TRIGGER trg_evento_revision_analisis
AFTER INSERT OR DELETE OR UPDATE OF id_sesion, id_evento, tipo_evento, fecha_hora, numero_secuencia, datos_originales
ON honeypot.evento FOR EACH ROW EXECUTE FUNCTION honeypot.registrar_revision_eventos();
