# Correo profesional de TacticLens

## Arquitectura e integración

Se conserva FastAPI, SQLAlchemy Core, PostgreSQL y el servicio `backend/auth/mailer.py`. Todos los envíos utilizan el mismo transporte SMTP de Resend. No se incorpora SDK, proveedor, servicio de recepción ni dependencia nueva. Zoho administra los buzones humanos; TacticLens no consulta sus mensajes ni conoce si una persona los leyó.

El registro guiado verifica primero el correo mediante el código existente, de cinco minutos y con límites de intentos/reenvío. Al crear la cuenta con ese correo verificado, se registra **un solo aviso de solicitud pendiente** a administración. El camino compatible de cuentas anteriores notifica al verificar el correo. Una clave única por usuario evita que ambos eventos dupliquen el aviso. Aprobar/rechazar se hace en la aplicación y exige los permisos y factores existentes. Los correos no autorizan acciones por respuesta.

La aprobación y rechazo de cuentas, los avisos al titular, los enlaces de creación/recuperación de contraseña, el cifrado TOTP y las sesiones revocables se reutilizan. Los enlaces personales siguen enviándose por la ruta segura existente: la cola nueva **no guarda contraseñas, OTP, secretos ni tokens** y la recuperación no omite MFA, aprobación ni restricciones administrativas.

## Configuración privada

Archivo exacto de esta instalación:

```text
C:\Users\user\Documents\tesis\prototipo-tactic-lens\.env
```

El backend lo carga con `python-dotenv`; las variables del proceso tienen prioridad. No se usa `frontend/.env` para secretos. Se conservaron todos los valores ya configurados de SMTP y las credenciales. Solo se agregaron las direcciones públicas que faltaban. La plantilla `.env.example` contiene las opciones sin credenciales.

```dotenv
MAIL_TRANSPORT=smtp
MAIL_FROM="TacticLens <no-reply@tacticlens.app>"
ADMIN_EMAIL=admin@tacticlens.app
SUPPORT_EMAIL=soporte@tacticlens.app
MAIL_TIMEZONE=America/Guayaquil
MAIL_ALERT_THRESHOLD=5
MAIL_ALERT_WINDOW_SECONDS=900
MAIL_ALERT_COOLDOWN_SECONDS=900
MAIL_NOTIFICATION_MAX_ATTEMPTS=3
SMTP_HOST=smtp.resend.com
SMTP_PORT=465
SMTP_USER=resend
SMTP_PASSWORD=CONSERVAR_LA_API_KEY_PRIVADA_EXISTENTE
SMTP_SSL=true
SMTP_STARTTLS=false
AUTH_PUBLIC_URL=http://127.0.0.1:5173
```

No copie el marcador sobre su clave. `SMTP_PASSWORD` sigue siendo la API Key de Resend y no necesita `RESEND_API_KEY`. `MAIL_FROM` ya representa el remitente del sistema; no se duplica con `SYSTEM_EMAIL`. `AUTH_PUBLIC_URL` debe apuntar al frontend real y confiable: comprar el dominio no implica que ya aloje la aplicación. En producción use HTTPS y la configuración de cookies/orígenes de la guía de autenticación.

`ADMIN_EMAIL` y `SUPPORT_EMAIL` vacíos deshabilitan sus canales nuevos, para permitir instalaciones existentes o pruebas sin buzones. Se validan las direcciones y la zona horaria al iniciar. `SMTP_SSL=true` selecciona TLS implícito en 465; se conserva la compatibilidad con STARTTLS/587 para un cambio posterior de proveedor. No se modificaron DNS, MX, SPF ni DKIM. `.env`, `.local/` y `.eml` están excluidos de Git.

## Alertas administrativas

Se notifican registros verificados pendientes, recuperaciones pendientes/aprobadas, suspensión, bloqueo, reactivación, cambio de rol, restablecimiento administrativo de MFA completado y consultas de soporte sobre MFA. El aviso contiene referencia de auditoría, usuario, fecha con zona horaria y enlace al módulo privado; no documentos de identidad, secretos ni tokens.

Los fallos de contraseña, MFA y reautenticación se agrupan por cuenta o huella de IP cuando no se identifica una cuenta. Inicialmente se alerta al acumular cinco fallos en quince minutos, con un intervalo mínimo de quince minutos entre alertas del mismo grupo. La denegación temporal por rate limiting comparte ese periodo de espera. No se manda un correo por inicio de sesión exitoso ni por fallo aislado. El límite temporal de autenticación **no se convierte en un bloqueo administrativo permanente**.

Las consultas de ayuda por MFA generan un aviso de solicitud; no crean una autorización para restablecer el factor. El administrador debe seguir el procedimiento documentado de comprobación de identidad y reautenticación. No existe una vía de soporte para omitir MFA.

## Formulario de ayuda

La ruta `/ayuda` funciona incluso sin sesión completa. Aparece en las pantallas de acceso y en Seguridad de mi cuenta. Incluye nombre, correo de respuesta, asunto, categoría y descripción. El correo oficial se obtiene de la configuración pública del backend.

El backend valida y normaliza los campos, rechaza caracteres de control y patrones evidentes de credenciales, limita el tamaño, aplica CSRF y límites por IP/correo. La descripción se representa como texto escapado; sus enlaces no se convierten en botones. El formulario no acepta destinatarios arbitrarios: solo envía a `SUPPORT_EMAIL`, con `Reply-To` validado del solicitante. Una coincidencia de correo sin autenticación **no demuestra identidad**.

Se conserva una referencia e historial mínimo en PostgreSQL. Dos solicitudes iguales dentro de cinco minutos producen la misma referencia sin otro envío. Límites iniciales: diez llamadas por IP y tres consultas nuevas por dirección cada quince minutos. Solo un usuario con sesión completa y correo verificado coincidente recibe confirmación por correo y puede ver sus propias consultas recientes. El visitante obtiene confirmación en pantalla: no se permite utilizar el formulario para enviar acuses a terceros.

El historial muestra el estado de **remisión del correo**, no un supuesto estado de resolución de tickets. No hay un sistema de tickets ni lectura automática de Zoho. Soporte responde manualmente usando su buzón y debe verificar identidad antes de gestionar solicitudes sensibles. No adjunte claves, códigos, documentos personales ni capturas que los contengan; la validación de patrones no puede identificar todos los secretos posibles.

## Confiabilidad y reintentos

Los avisos administrativos y de soporte se registran con referencias a auditoría o consulta, destinatario fijo y clave única. La transacción de negocio se confirma antes del envío; los intentos y sus resultados quedan persistidos y auditados, con errores genéricos sin volcar excepciones SMTP. La recuperación de contraseña mantiene su manejo previo de fallo de entrega y tokens invalidados; los OTP/enlaces no se agregan a esta cola.

La pestaña **Administración de usuarios → Correo del sistema** permite filtrar y consultar estos nuevos avisos. Un administrador puede solicitar un reintento con motivo, contraseña y segundo factor. Se exige espera progresiva, máximo configurable de intentos y exclusión mediante bloqueo de fila. Un aviso aceptado/cancelado no se reenvía. Un intento interrumpido queda identificable; tras cinco minutos puede revisarse y reintentarse de forma supervisada. No se vacía la cola automáticamente al arrancar el servidor.

Se conserva la misma cabecera `Resend-Idempotency-Key` en los reintentos, conforme a la [documentación SMTP de Resend](https://resend.com/docs/send-with-smtp). Resend conserva estas claves [durante 24 horas](https://resend.com/docs/dashboard/emails/idempotency-keys); TacticLens limita los reintentos a 23 horas desde el primer intento. Fuera de ese plazo se requiere revisión manual, evitando un reenvío fuera de la protección del proveedor. Mantenga configuración y contenido estables durante los reintentos: cambios de plantilla, usuario o remitente podrían provocar rechazo del proveedor por contenido distinto con la misma clave. No se promete entrega exactamente una vez para cualquier proveedor SMTP futuro.

Estados: `pendiente`, `en_proceso`, `aceptado`, `fallido`, `incierto`, `cancelado`. `aceptado/smtp_aceptado` significa que SMTP aceptó el mensaje; `aceptado/buzon_local` significa que se guardó en el buzón de desarrollo. Una desconexión durante el envío puede quedar `incierto`. No hay webhooks de entrega/rebote configurados: para confirmarlos se consulta Resend y el buzón humano. La lista nueva no representa todos los correos históricos ni registra sus contenidos personales.

## Base de datos y endpoints

Migración aditiva `006_correo_profesional.sql`, aplicada localmente sin borrar datos. Reejecutar el migrador verifica el checksum y no duplica tablas:

- `auth_soporte`: consulta, identidad declarada/verificada, referencia de usuario opcional, huella de deduplicación, campos de auditoría y fechas.
- `auth_notificacion`: referencias seguras, destinatario, unicidad, estado, intentos, fechas de aceptación/reintento y resultado. No almacena el mensaje sensible de recuperación.

Endpoints nuevos:

| Método | Ruta | Acceso |
|---|---|---|
| GET | `/api/auth/contacto` | Público; solo canal de soporte |
| POST | `/api/auth/soporte` | Público con CSRF y rate limiting |
| GET | `/api/auth/soporte/mis-solicitudes` | Sesión completa; consultas propias |
| GET | `/api/auth/admin/notificaciones` | Administrador con MFA completo |
| POST | `/api/auth/admin/notificaciones/{id}/reintentar` | Administrador + reautenticación + motivo |

Archivos principales: `mail_config.py`, `notifications.py`, `support.py`, `mailer.py`, `email_templates.py`, los puntos de integración `store.py`, `middleware.py` y `api.py`; componentes `SupportContact`, `SupportPage`, `AdminNotifications` e integración en `AuthBoundary`, `components`, `SecurityPage`, `AdminUsers`; migración 006, `.env.example`, `scripts/preview_emails.py`, `tests/test_professional_mail.py` y ajustes de aislamiento de configuración en las pruebas anteriores. No se alteran Cowrie, LLM, IoCs ni MITRE.

## Inicio y pruebas locales

Desde la raíz, después de detener el backend anterior con Ctrl+C:

```powershell
cd C:\Users\user\Documents\tesis\prototipo-tactic-lens
.\.venv\Scripts\python.exe -m scripts.migrate
.\.venv\Scripts\python.exe -m uvicorn backend.api:app --host 192.168.56.1 --port 8000
```

En otra terminal:

```powershell
cd C:\Users\user\Documents\tesis\prototipo-tactic-lens\frontend
npm.cmd run dev
```

La dirección 192.168.56.1 conserva el proxy Vite configurado en esta PC. En otra instalación ajuste conjuntamente el bind del backend y `VITE_API_PROXY_TARGET` sin modificar las claves. No se necesita reinstalar dependencias.

Pruebas automáticas sin enviar mensajes externos, desde la raíz:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
cd frontend
npm.cmd test
npm.cmd run build
```

Las pruebas usan el PostgreSQL local y transacciones revertidas; el transporte se sustituye por mocks. La prueba de concurrencia usa un esquema temporal aislado y comprueba consumo único de enlaces. No ejecute estos comandos sobre una base de producción. Para las vistas previas ficticias, sin cargar `.env` ni conectar SMTP:

```powershell
.\.venv\Scripts\python.exe -m scripts.preview_emails
```

Prueba manual de envío **solo después de confirmar destinatarios de prueba y autorizarla**:

1. Para una simulación local, cambie temporalmente `MAIL_TRANSPORT=file`, reinicie y abra los `.eml` privados de `.local/mail`. Restaure `smtp` y reinicie antes de la prueba real autorizada.
2. Registre una cuenta de prueba autorizada, reciba/valide el código y complete el registro. Revise un solo aviso en `admin@tacticlens.app` y en Correo del sistema. Su enlace debe exigir acceso administrativo y MFA; no debe autorizar por sí mismo.
3. Apruebe o rechace la cuenta desde el panel y compruebe el correo correspondiente al titular. Si se aprueba una cuenta nueva, defina la contraseña con su enlace y configure Google Authenticator según el flujo existente.
4. Abra `/ayuda`, complete una consulta sin secretos y envíela. Compruebe la referencia en pantalla, la llegada a `soporte@tacticlens.app` y que «Responder» utilice el correo declarado. Repita exactamente el mismo formulario dentro de cinco minutos: no debe crear otro envío. Con sesión completa y su mismo correo verificado, compruebe además el acuse y Mis consultas recientes.
5. En Zoho responda manualmente. La aplicación no debe cambiar a «leído» ni «resuelto» por esa respuesta. Para MFA siga el procedimiento de identidad establecido.
6. Solicite recuperación de contraseña y apruébela desde el panel. El enlace del titular vence a los quince minutos, se consume una vez y conserva la exigencia de MFA. Revise que el aviso administrativo no contenga el token.
7. Para comprobar errores sin afectar Resend, utilice la suite con mocks. No produzca fallos masivos reales sobre cuentas existentes.

Resultado de verificación: 122 pruebas de backend aprobadas (incluidas 19 de correo profesional), 7 pruebas de frontend aprobadas y compilación de producción completada. Se revisó la pantalla de ayuda en móvil y el componente administrativo con datos ficticios y envíos desactivados. El build conserva avisos de React Router y tamaño del bundle, sin errores de compilación.

No se enviaron mensajes reales durante esta implementación. No se comprobó entrega externa ni el contenido privado de Zoho/Resend; las pruebas de transporte y rutas utilizan mocks.

## Zoho y recepción futura

El [plan gratuito documentado de Zoho](https://www.zoho.com/mail/zohomail-pricing.html) no incluye IMAP, POP ni ActiveSync. Esta solución usa sus buzones para lectura y respuestas humanas, sin hacer depender al backend de esos protocolos ni de SMTP Zoho. La recepción automática futura necesitaría evaluar una API, protocolo o servicio entrante que esté habilitado y autorizado en el plan y región de la cuenta; no está implementada ni requiere contratar nada para el flujo actual.
