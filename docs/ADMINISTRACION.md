# Administración de cuentas y recuperación supervisada

## Arquitectura y alcance

Se amplían React/TypeScript/Vite, FastAPI, SQLAlchemy Core y el esquema PostgreSQL existente. Se reutilizan `usuario`, `rol`, `auth_sesion`, `auth_token`, `auth_factor` y la auditoría inmutable. No se incorporan JWT, otro proveedor de correo ni dependencias nuevas. Cowrie, IoCs, LLM y MITRE conservan sus funcionalidades.

Las cuatro secciones de `/usuarios` son **Usuarios**, **Usuarios conectados**, **Solicitudes de recuperación** e **Historial administrativo**. El backend exige siempre una sesión completa con MFA y rol Administrador. La interfaz también oculta estas funciones a Analistas.

## Cuentas y estados

El listado incluye búsqueda por nombre/correo/usuario, filtro de rol y estado, orden de registro/nombre/último acceso/actividad y páginas de 25 filas. Muestra verificaciones, último acceso completo, actividad y número de sesiones vigentes.

Se conservan la autorización (`pendiente/aprobado/rechazado`) y el indicador `activo`. El nuevo `restriccion_acceso` distingue suspensión de bloqueo; no sustituye ni mezcla correo o MFA. Los estados de presentación son pendiente, activo, rechazado, suspendido y bloqueado.

- Aprobar un registro pendiente sigue requiriendo solo un código nuevo del Google Authenticator del administrador, como se acordó anteriormente.
- Rechazar, cambiar rol, suspender, bloquear o reactivar requiere la contraseña **del administrador**, segundo factor y confirmación del formulario. Suspensión y bloqueo requieren motivo; la interfaz también lo solicita al reactivar.
- No se permiten cambios de rol/estado propios ni dejar al sistema sin administradores habilitados. Las decisiones administrativas se serializan mediante el bloqueo transaccional existente.
- Suspender/bloquear revoca sesiones y cancela recuperaciones abiertas con sus tokens. Reactivar no restaura sesiones, enlaces ni solicitudes previas.
- Reactivar aplica solo a cuentas ya autorizadas. No aprueba implícitamente registros pendientes o rechazados.
- El restablecimiento administrativo de MFA mantiene sus controles anteriores: otro administrador, verificación independiente de identidad y referencia documentada.

## Sesiones y actividad

Una sesión solo se cuenta como vigente si completó MFA, no está revocada/expirada, no superó la inactividad y su cuenta, rol y factor siguen habilitados. Los desafíos de autenticación se muestran como incompletos.

La actividad reciente usa interacciones de puntero, teclado y desplazamiento en una pestaña visible, con un heartbeat máximo cada 30 segundos mientras haya interacción reciente. Sin interacción no continúa enviándolo. La ventana inicial de presencia es de 120 segundos. Las consultas periódicas de datos no prolongan la sesión ni simulan presencia.

Se muestran **Actividad reciente**, **Inactivo con sesión vigente** o **Desconectado**. Son señales de actividad de la aplicación, no una garantía de presencia física. La inactividad y expiración absoluta existentes siguen aplicándose.

El administrador puede filtrar sesiones por usuario/estado y revocar una específica o todas las de otra cuenta. La revocación actúa sobre PostgreSQL y se comprueba en la siguiente petición. El cliente detecta los 401 y vuelve al flujo de acceso. Los UUID administrativos identifican registros; nunca se devuelven cookies, tokens, hashes ni direcciones IP. El dispositivo es una etiqueta gruesa de navegador/sistema, sin conservar el User-Agent completo.

## Contraseñas: dos procesos separados

**Cambio voluntario:** desde Seguridad de mi cuenta, contraseña actual, contraseña nueva y confirmación, más el segundo factor existente. No crea una solicitud ni requiere aprobación. Conserva Argon2id y la fortaleza mínima de 75%; revoca sesiones/enlaces anteriores y notifica al correo verificado.

**Recuperación:** desde ¿Olvidaste tu contraseña?, se solicita revisión administrativa. La respuesta pública es idéntica para correos elegibles o desconocidos. Solo cuentas autorizadas, activas y con correo verificado generan solicitudes. Hay límites por IP/cuenta y una restricción única que impide más de una solicitud abierta por usuario. El aviso de recepción no incluye enlace y se envía después de responder, evitando esperar SMTP en la respuesta pública.

Estados de solicitud: pendiente, aprobada, rechazada, expirada, completada y cancelada. Cancelada representa una restricción administrativa, cambio voluntario de contraseña u otra invalidación que hace improcedente una solicitud previamente abierta. La solicitud pendiente caduca inicialmente en 24 horas; el enlace aprobado caduca en 15 minutos.

Otro administrador verifica la identidad por un canal conocido y aprueba o rechaza con su contraseña, segundo factor y motivo. No puede aprobar su propia recuperación ni resolver dos veces una solicitud. Una aprobación genera un token de 256 bits cuyo HMAC se almacena en `auth_token`; se vincula a solicitud y usuario mediante claves foráneas. El administrador no recibe el token ni establece contraseñas.

El enlace usa exclusivamente `AUTH_PUBLIC_URL`, con el token en el fragmento `#token=`. No se deriva del Host recibido. La pantalla retira el fragmento del historial, mantiene el token solo en memoria y valida el enlace sin consumirlo. La confirmación explícita, protegida por CSRF, bloquea las filas de usuario/solicitud/token y realiza de forma atómica: nuevo hash, consumo del token, solicitud completada e invalidación de sesiones/enlaces. No crea sesión ni elude MFA.

Se mantiene `Cache-Control: no-store` y `Referrer-Policy: no-referrer` en backend; Vite también sirve esos encabezados y el HTML incluye política de referencia. No se cargan scripts de terceros en recuperación. En producción, el servidor que publique el frontend debe conservar esos encabezados.

## Registro sin contraseñas enviadas

Los registros nuevos verifican el correo en el formulario y quedan pendientes. Se envía solo un aviso de recepción. Al aprobar el registro, se emite un enlace para **definir la primera contraseña**, con la misma protección de uso único y vigencia. No hay contraseñas temporales en nuevos mensajes. Las credenciales de cuentas anteriores se conservan para no romper el acceso existente.

Si falla el enlace inicial, la aprobación de cuenta se conserva y aparece una solicitud de origen `alta` pendiente, con notificación fallida, para reintentar desde Recuperaciones. Las solicitudes de recuperación posteriores de una cuenta aprobada también permiten resolver una primera contraseña pendiente.

## Correo y fallos

Se conserva SMTP/Resend y la plantilla TacticLens en español. El enlace aparece en texto y como enlace HTML escapado. Hay avisos de registro, aprobación/rechazo, suspensión, bloqueo, reactivación, recuperación recibida, recuperación aprobada/rechazada y contraseña modificada.

La emisión de enlaces es síncrona y se realiza mientras están bloqueadas las filas relevantes. No hay una cola con tokens en texto plano. Si SMTP falla, el intento de token se invalida, la solicitud permanece pendiente y la API devuelve 503 con posibilidad de reintento explícito. Rechazos/notificaciones comunes muestran si el aviso fue aceptado por el servicio y auditan fallos sin detalles privados.

SMTP y PostgreSQL no forman una transacción distribuida: si el proveedor acepta un mensaje y falla el commit final, el enlace recibido puede ser inválido. No se reenvía automáticamente; el administrador puede revisar y reintentar. La aceptación SMTP tampoco garantiza la entrega en Gmail. El aviso no sensible de recepción usa una tarea en proceso; si este termina antes de ejecutarla, la solicitud sigue persistida aunque ese aviso pueda perderse.

## Migración y configuración

Nueva migración `005_administracion_recuperacion.sql`:

- `usuario`: restricción, motivo, responsable/fecha y último acceso; distingue las cuentas previamente suspendidas.
- `auth_sesion`: etiqueta de dispositivo e índice de actividad.
- Nueva `auth_solicitud_password`: estados, caducidad, decisión, notificación y auditoría técnica.
- `auth_token.id_solicitud`: relación con usuario y solicitud. Los enlaces de contraseña anteriores sin aprobación se invalidan, conservando sus registros.
- Permite alta sin credencial temporal y conserva los hashes/estados de cuentas existentes.

La migración ya se aplicó localmente. En otra instalación:

```powershell
.\.venv\Scripts\python.exe -B -m scripts.migrate
```

Variables adicionales, con valores por defecto y sin secretos:

```dotenv
AUTH_RECOVERY_REQUEST_SECONDS=86400
AUTH_RECENT_ACTIVITY_SECONDS=120
```

Se reutilizan `AUTH_RESET_SECONDS=900`, `AUTH_IDLE_SECONDS`, `AUTH_SESSION_SECONDS`, `AUTH_PUBLIC_URL`, las claves existentes y `MAIL_*`/`SMTP_*`. No se modificó el `.env` privado en esta tarea ni se hicieron envíos reales. La configuración Resend pendiente se conserva; consulte [Correo SMTP](CORREO_SMTP.md).

## API nueva y modificada

| Método y ruta, prefijo `/api/auth` | Operación |
|---|---|
| GET `/admin/usuarios` | Búsqueda, filtros, orden, actividad y paginación |
| PATCH `/admin/usuarios/{id}` | Registro, rol, suspensión, bloqueo y reactivación |
| POST `/actividad` | Actividad de una sesión completa |
| GET `/admin/sesiones` | Sesiones por usuario/estado, sin secretos |
| POST `/admin/sesiones/{id}/revocar` | Revocación específica |
| POST `/admin/usuarios/{id}/sesiones/revocar` | Revocación total de otra cuenta |
| GET `/admin/auditoria` | Responsables, afectados, motivo y resultado; filtros/paginación |
| POST `/password/solicitar` | Solicitud pública genérica, sin emitir enlace |
| GET `/admin/recuperaciones` | Solicitudes por estado, con resolución/notificación |
| POST `/admin/recuperaciones/{id}/resolver` | Aprobar/rechazar con reautenticación |
| POST `/password/validar` | Validación no destructiva del enlace |
| POST `/password/fortaleza` | Política de contraseña, también con enlace aprobado |
| POST `/password/restablecer` | Consumo atómico del enlace aprobado |
| POST `/password/cambiar` | Cambio voluntario independiente |

## Pruebas y procedimiento manual

Se ejecutaron **92 pruebas backend**, **7 pruebas frontend** y compilación TypeScript/Vite, todas correctas. Los servicios externos están simulados. Las pruebas de integración revierten sus datos; la de concurrencia utiliza y elimina exclusivamente un esquema aleatorio `test_tacticlens_*`, con dos conexiones reales a PostgreSQL y dos peticiones simultáneas: solo una puede consumir el token. El usuario de pruebas necesita permiso para crear ese esquema desechable.

Se revisaron visualmente las cuatro secciones con los componentes reales y datos ficticios, sin conectar el artefacto de revisión a la API. A 390 px no hubo desbordamiento del documento; las tablas conservan desplazamiento horizontal. El artefacto temporal fue eliminado.

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
cd frontend
npm.cmd test
npm.cmd run build
```

Prueba manual, una vez autorizado el envío SMTP:

1. Iniciar backend y frontend como indica README. Entrar como administrador con MFA y abrir `/usuarios`.
2. Buscar una cuenta de prueba autorizada, consultar sus sesiones/historial y comprobar sus fechas. En otro perfil mantener una sesión de ese usuario; dejar de interactuar para ver el paso de actividad reciente a inactivo.
3. Revocar una sesión desde el administrador: la siguiente petición del usuario debe fallar. Probar suspensión y bloqueo con motivo; intentar iniciar sesión y recuperar contraseña debe fallar sin revelar la existencia de la cuenta.
4. Reactivar y comprobar que se necesita un nuevo inicio de sesión; las sesiones anteriores no reaparecen.
5. Desde otro perfil, solicitar recuperación. Debe aparecer pendiente en Recuperaciones, sin enlace público. Rechazar una solicitud y comprobar aviso/auditoría. Una nueva solicitud puede aprobarse tras verificar la identidad.
6. Aprobar y revisar Gmail/Resend. Abrir el enlace, confirmar contraseña segura y comprobar que la solicitud queda completada, el enlace no se reutiliza, la contraseña anterior falla y MFA sigue siendo obligatorio.
7. Probar Cambio de contraseña desde Seguridad de mi cuenta: no debe crear solicitudes administrativas. Revisar el aviso y la revocación de sesiones.
8. Registrar una cuenta nueva, verificar el correo y aprobarla. El correo de aprobación contiene un enlace, nunca una contraseña.

La entrega real por Resend/Gmail queda pendiente de la confirmación del titular sobre su API Key. Si el único administrador olvida su contraseña y no dispone de otro administrador con acceso, este flujo no crea un bypass público: debe aplicarse una recuperación operativa supervisada por el responsable del servidor.
