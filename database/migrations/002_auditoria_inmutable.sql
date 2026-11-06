-- Security audit is append-only even through the application SQL connection.
CREATE FUNCTION honeypot.impedir_cambio_auditoria() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'La auditoría de seguridad es de solo anexado' USING ERRCODE='42501';
END;
$$;
CREATE TRIGGER trg_auth_auditoria_inmutable
 BEFORE UPDATE OR DELETE ON honeypot.auth_auditoria
 FOR EACH ROW EXECUTE FUNCTION honeypot.impedir_cambio_auditoria();

DO $$ BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM pg_trigger
  WHERE tgrelid='honeypot.rol'::regclass
    AND tgfoid='honeypot.actualizar_fecha_auditoria()'::regprocedure
    AND NOT tgisinternal
 ) THEN
  CREATE TRIGGER trg_auth_rol_actualizado BEFORE UPDATE ON honeypot.rol
   FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();
 END IF;
END $$;
