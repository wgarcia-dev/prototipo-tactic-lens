# Entrega del módulo de autenticación de TacticLens

## Resultado

Se implementaron registro validado, autorización administrativa, correo verificado, vinculación y acceso mediante TOTP obligatorio, recuperación, sesiones revocables, RBAC y administración. La implementación conserva React/TypeScript, FastAPI y SQLAlchemy Core; reutiliza los registros existentes de usuario y rol. No se modificaron el recolector ni las operaciones de eventos, sesiones, LLM, IoCs y MITRE, salvo la protección común de sus rutas y el cliente HTTP con CSRF.

El flujo vigente es: verificar correo dentro del formulario → solicitar cuenta como Analista pendiente → primer ingreso con credencial temporal de un solo uso → crear contraseña definitiva con fortaleza mínima del 75% → autorización de un Administrador → vinculación confirmada o desafío TOTP → sesión completa. Administración puede aceptar o rechazar solicitudes. Las llamadas directas a la API no pueden omitir la etapa MFA. El detalle de la ampliación, archivos, migraciones y prueba manual está en [Registro guiado](REGISTRO_GUIADO.md).

## Archivos creados

| Archivo | Responsabilidad |
|---|---|
| `backend/db.py` | Conexión PostgreSQL compartida, parámetros protegidos en errores |
| `backend/auth/__init__.py` | Paquete de autenticación |
| `backend/auth/config.py` | Configuración validada, claves, orígenes y expiraciones |
| `backend/auth/security.py` | Argon2id, generación de tokens, HMAC y comprobación TOTP |
| `backend/auth/schemas.py` | Validación y normalización de identidad y formularios |
| `backend/auth/store.py` | Transacciones, límites, bloqueos, sesiones, roles y auditoría |
| `backend/auth/service.py` | Registro, códigos de correo, recuperación y reautenticación |
| `backend/auth/mailer.py` | Plantilla española multipart, buzón local y SMTP TLS |
| `backend/auth/routes.py` | Los 21 endpoints de autenticación y administración |
| `backend/auth/middleware.py` | Protección de rutas, CSRF, origen y tamaño del cuerpo |
| `database/migrations/001_auth.sql` | Extensión aditiva del modelo existente |
| `database/migrations/002_auditoria_inmutable.sql` | Auditoría de solo anexado y fecha de roles |
| `scripts/configure_auth.py` | Generación local de claves ausentes, sin imprimirlas |
| `scripts/migrate.py` | Migraciones transaccionales con versión y checksum |
| `scripts/create_admin.py` | Bootstrap interactivo del primer administrador, sin endpoint público |
| `frontend/src/auth/client.ts` | Cliente HTTP con cookies y CSRF en memoria |
| `frontend/src/auth/context.tsx` | Estado de sesión, caducidad y actividad del usuario |
| `frontend/src/auth/components.tsx` | Formularios, campos, mensajes y reautenticación reutilizables |
| `frontend/src/auth/AuthBoundary.tsx` | Registro, acceso, correo, MFA, respaldo y recuperación |
| `frontend/src/auth/SecurityPage.tsx` | Contraseña, recuperación, teléfono y cierre de sesiones |
| `frontend/src/auth/AdminUsers.tsx` | Autorizaciones, roles, suspensión, restablecimiento y auditoría |
| `frontend/src/auth/AdminOnly.tsx` | Protección visual de operaciones administrativas |
| `frontend/src/auth/auth.css` | Diseño integrado con TacticLens y comportamiento móvil |
| `tests/test_auth.py` | 57 pruebas de validación, seguridad e integración de autenticación |
| `docs/AUTENTICACION.md` | Configuración, endpoints, modelo y procedimiento manual completo |
| `docs/INFORME_AUTENTICACION.md` | Este informe |

## Archivos modificados

- `backend/api.py`: conexión compartida, configuración y reflexión de tablas nuevas, middleware/router y errores sin valores sensibles. La dependencia histórica `local_only` ahora exige autenticación real.
- `frontend/src/main.tsx`: frontera autenticada, cliente HTTP protegido, controles de sesión y rutas de seguridad/administración.
- `requirements.txt`: argon2-cffi, cryptography, PyOTP, email-validator, zxcvbn, qrcode e itsdangerous.
- `.env.example`: opciones completas sin claves reales.
- `.gitignore`: buzón local, mensajes y configuración privada del frontend.
- `README.md`: arranque con migraciones y administrador, alcance actualizado y enlace a la guía.
- `tests/test_live.py`: aislamiento de la nueva frontera de acceso para probar módulos previos y catálogos de prueba revertidos al terminar.

Los archivos `.env` reales no están en Git. En el entorno local se generaron únicamente las claves de autenticación que faltaban; se conservaron las opciones y credenciales preexistentes. No se creó una cuenta administrativa con datos inventados ni contraseña predeterminada.

## Base de datos

Se aplicaron las dos migraciones en PostgreSQL local. Se extendieron `usuario` y `rol`, y se agregaron `auth_factor`, `auth_token`, `auth_sesion`, `auth_recuperacion`, `auth_limite` y `auth_auditoria`. El seguimiento técnico usa `schema_migration`. La [guía del modelo](AUTENTICACION.md#modelo-de-datos-y-migraciones) describe campos y restricciones.

Se mantienen separados el estado general (`activo`), la verificación del correo, la autorización administrativa y la confirmación MFA. Se agregaron los actores de creación/modificación y se reutilizaron las fechas y triggers existentes. Las entidades técnicas tienen campos comunes de auditoría y metadatos de caducidad, uso o revocación según corresponda.

La comprobación inicial de entrega encontró **0 usuarios, 2 roles, 1 sesión Cowrie, 3 eventos y 1 análisis almacenado**. No quedaron cuentas de prueba persistentes ni se eliminaron datos de los módulos existentes. Las cuentas que el titular registre posteriormente se conservan en las ejecuciones siguientes de las pruebas.

## Seguridad aplicada

- Validación de cédula de persona natural y normalización de usuario, correo y nombres; restricciones únicas reales en PostgreSQL.
- Contraseñas de 12 a 128 caracteres, comprobación de fortaleza y hash Argon2id con sal de la biblioteca.
- Códigos de correo aleatorios, HMAC fuera de la base, caducidad, intentos, reenvío espaciado y uso único.
- Google Authenticator mediante RFC 6238, QR local y clave manual, confirmación obligatoria, Fernet y rechazo de intervalos ya utilizados bajo bloqueo de usuario.
- Diez códigos de recuperación de 128 bits, almacenamiento solo mediante HMAC y consumo atómico. Su regeneración exige reautenticación.
- Tokens opacos de sesión y desafío, estados MFA explícitos en servidor, cookies HttpOnly/SameSite=Strict y Secure obligatorio en producción.
- CSRF firmado con HMAC-SHA256, origen exacto y cabecera personalizada; sin tokens sensibles en almacenamiento web persistente.
- Rate limiting persistente por cuenta/IP, tamaño máximo de 16 KiB en autenticación y respuestas sin contraseñas o códigos rechazados.
- Expiración absoluta e inactividad que no se prolonga mediante polling; revocación al cambiar contraseña, suspender, cambiar rol o restablecer MFA.
- Recuperación de contraseña que conserva MFA. Reemplazo propio de teléfono mediante contraseña y factor válido; restablecimiento ajeno mediante administrador reautenticado y procedimiento de identidad documentado.
- Auditoría sin secretos, consultable solo por Administradores y protegida contra UPDATE/DELETE en PostgreSQL.

La matriz RBAC y los [endpoints principales](AUTENTICACION.md#endpoints) están documentados con sus permisos en la guía; los de verificación previa y contraseña inicial se describen en [Registro guiado](REGISTRO_GUIADO.md). La ingesta automática conserva `X-API-Key` y no depende de una sesión humana.

## Verificaciones ejecutadas

| Comprobación | Resultado observado |
|---|---|
| `python -B -m unittest discover -s tests -v` usando `.venv` | **65 pruebas, todas correctas**, 15,389 segundos en la ejecución más reciente |
| Desglose | 57 pruebas de autenticación, 5 de núcleo y 3 de integración de módulos existentes |
| `npm.cmd test` | **7 pruebas correctas** de validación del registro |
| `npm.cmd run build` | TypeScript y compilación de Vite correctos |
| `python -m pip check` usando `.venv` | Sin dependencias incompatibles |
| `git diff --check` | Sin errores de espacios |
| Migraciones | Aplicadas y verificadas; la repetición conserva filas y no reaplica archivos |
| Buzón local | Envío real a archivo temporal `.eml`, contenido y marca TacticLens comprobados |
| Navegador | Acceso, registro, correo y recuperación revisados; registro comprobado a ancho móvil |
| HTTP real a través de Vite | `/login` y `/api/health`: 200; sesiones, métricas y administración sin autenticación: 401 |
| Estado persistente | Sin usuarios de prueba; datos Cowrie y análisis existentes conservados |

Las pruebas usan PostgreSQL real, transacciones que se revierten y claves efímeras específicas del proceso de prueba. Los casos de autenticación no sustituyen el servicio de sesión ni RBAC; sustituyen el envío externo de correo y controlan el reloj TOTP. El caso de buzón sí ejecuta el transporte de archivos. Los casos antiguos de módulos aíslan autenticación y proveedor LLM para verificar que sus funciones no se rompieron.

Vite informa un aviso no bloqueante por el tamaño del bundle; la suite informa una deprecación de Starlette sobre su adaptador TestClient/httpx. Ninguno impidió compilar ni ejecutar las pruebas. No se amplió el alcance para refactorizar gráficos o sustituir el cliente HTTP existente del proveedor LLM.

## Inicio y prueba local

Las dependencias y migraciones ya se prepararon en esta PC y ambos servidores quedaron iniciados. El siguiente paso del titular es crear su primer administrador desde la raíz:

```powershell
.\.venv\Scripts\python.exe -m scripts.create_admin
```

Introduzca sus datos y contraseña directamente en la terminal. Después abra el mensaje de `.local/mail`, verifique el correo en la interfaz e inicie sesión. Escanee el QR con Google Authenticator, confirme los seis dígitos actuales y guarde los códigos de recuperación. No entregue su contraseña a un tercero para completar este paso.

Si ya registró y verificó su cuenta desde la interfaz antes de crear un administrador, use `scripts.create_admin --existente`. Esta variante solicita su correo y contraseña actual, conserva la identidad y el MFA, revoca sesiones y habilita únicamente al primer administrador cuando todavía no hay ninguno. Está probada contra PostgreSQL sin modificar cuentas reales. Después recargue la interfaz e inicie sesión para completar el segundo factor.

Para iniciar de nuevo después de cerrar las terminales:

```powershell
# Terminal 1, raíz del proyecto:
.\.venv\Scripts\python.exe -m uvicorn backend.api:app --host 192.168.56.1 --port 8000
```

```powershell
# Terminal 2, raíz del proyecto:
cd frontend
npm.cmd run dev
```

Abra `http://127.0.0.1:5173/login`. La [prueba manual completa](AUTENTICACION.md#prueba-manual-completa) incluye el segundo registro, autorización, teléfono, cierre, nuevo inicio con MFA, recuperación y suspensión desde otro perfil de navegador.

## Límites comprobables y configuración pendiente del titular

- No se ha escaneado el QR con un teléfono físico del titular. Se probaron URI, QR, valores TOTP reales y el vector RFC por API; la guía incluye la validación manual con Google Authenticator.
- Se configuró el buzón local por elección del titular. No se enviaron mensajes a un proveedor SMTP real ni se verificó una cuenta externa; SMTP está implementado y requiere sus parámetros privados para usarlo.
- El administrador inicial debe introducir sus propios datos. La herramienta existe y su registro subyacente está probado, pero no se inventaron identidad ni credenciales para ejecutar ese alta persistente.
- El proceso administrativo requiere una comprobación de identidad fuera de la aplicación, documentada por la organización. No hay bypass web para un administrador que pierda todos sus factores y sea el único administrador.
- No se desplegó en producción ni se cambió infraestructura externa. HTTPS, custodia de claves, políticas de retención, permisos mínimos de PostgreSQL y supervisión operativa se describen en la guía.
- La entrega no equivale a una auditoría de penetración externa ni valida la infraestructura de Cowrie/DeepSeek nuevamente; sus pruebas previas se conservaron y la ingesta permanece independiente.
