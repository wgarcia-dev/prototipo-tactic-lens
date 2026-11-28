-- Extend the existing outbox without changing historical rows or owners.
ALTER TABLE honeypot.auth_notificacion
 DROP CONSTRAINT auth_notificacion_tipo_check,
 DROP CONSTRAINT auth_notificacion_estado_check,
 DROP CONSTRAINT auth_notificacion_check,
 ADD CONSTRAINT auth_notificacion_tipo_check
  CHECK(tipo IN ('administrativa','alerta','soporte','confirmacion_soporte','recuperacion_enlace','recuperacion_rechazo')),
 ADD CONSTRAINT auth_notificacion_estado_check
  CHECK(estado IN ('pendiente','en_proceso','aceptado','fallido','reintento','incierto','cancelado')),
 ADD CONSTRAINT auth_notificacion_check
  CHECK((tipo IN ('administrativa','alerta','recuperacion_enlace','recuperacion_rechazo') AND id_auditoria IS NOT NULL AND id_soporte IS NULL)
     OR (tipo IN ('soporte','confirmacion_soporte') AND id_soporte IS NOT NULL AND id_auditoria IS NULL));

ALTER TABLE honeypot.auth_solicitud_password
 DROP CONSTRAINT auth_solicitud_password_notificacion_estado_check,
 ADD CONSTRAINT auth_solicitud_password_notificacion_estado_check
  CHECK(notificacion_estado IN ('pendiente','en_proceso','enviada','fallida','reintento','incierto'));
