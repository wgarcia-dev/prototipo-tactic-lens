# Registro guiado y decisiones administrativas

Este es el flujo vigente del registro público. Las cuentas existentes y el bootstrap local del primer administrador conservan sus contraseñas y estados.

## Registro en una pantalla

1. Abrir `/registro` sin una sesión completa. La cédula se comprueba al completar diez dígitos, con un mensaje inmediato. Nombres, apellidos, usuario y formato del correo muestran correcciones durante la entrada. La validación matemática no certifica identidad oficial.
2. Pulsar **Verificar correo** junto a la dirección. Se envía un código y aparece un campo debajo, en la misma pantalla. Al completar seis dígitos se verifica automáticamente. También hay confirmación manual para reintentar un fallo de conexión.
3. Una verificación correcta oculta el código y deja el correo de solo lectura. **Editar correo** invalida la prueba anterior en el servidor y permite modificarlo; la dirección debe verificarse otra vez. Alterar atributos HTML o una bandera del cliente no sustituye esa prueba.
4. Pulsar **Enviar solicitud de cuenta** cuando los datos y el correo sean válidos. No hay campos de contraseña en este formulario. Se crea un Analista con correo verificado y autorización pendiente, y se envía una credencial temporal aleatoria.
5. Iniciar sesión con la credencial temporal. Caduca inicialmente en 24 horas y se consume en el primer ingreso correcto. Solo permite crear la contraseña definitiva; no habilita módulos ni sustituye MFA.
6. Elegir y confirmar la contraseña definitiva. El porcentaje aparece junto al campo y se actualiza con una barra y condiciones. Se exige al menos 75%, entre 12 y 128 caracteres y confirmación coincidente. No se admite reutilizar la credencial enviada por correo.
7. La cuenta espera autorización si está pendiente. Después de ser aceptada, debe configurar o validar Google Authenticator antes de entrar a los módulos.

El porcentaje es una **estimación**, no una garantía ni una probabilidad de seguridad. Mapea el nivel 0–4 de zxcvbn a 0–100. El servidor calcula el porcentaje y aplica la misma política al guardar, considerando también los datos personales de la cuenta. Admite gestores, pegado y frases largas, sin imponer combinaciones arbitrarias de símbolos. Las evaluaciones usan el backend propio, no un servicio externo; no se guardan ni se registran las contraseñas evaluadas. Las solicitudes se retrasan 450 ms al escribir y se cancelan las anteriores.

## Aceptar o rechazar

**Administrar usuarios** muestra inicialmente las solicitudes pendientes. El filtro permite consultar pendientes, autorizadas, rechazadas o todas.

Al seleccionar una solicitud se elige **Aceptar solicitud** o **Rechazar solicitud**. Para aceptar una solicitud pendiente basta un código nuevo del Google Authenticator del administrador con sesión completa; no se solicita su contraseña ni se admiten códigos de recuperación en esta operación. El servidor comprueba el estado pendiente, el rol administrativo y el TOTP, con límite de intentos y protección frente a reutilización.

Rechazar exige un motivo de 10 a 300 caracteres, sin documentos ni datos sensibles, y conserva la confirmación con contraseña administrativa y segundo factor. También mantienen esa confirmación los cambios de rol/estado de cuentas ya aprobadas, la reaprobación de cuentas rechazadas y los restablecimientos de MFA. Enviar `aprobar=true` para una cuenta que ya no está pendiente no permite eludir la contraseña.

- Aceptar registra autorización, actor y fecha. Puede asignarse un rol. No crea una sesión completa ni configura MFA por el usuario.
- Rechazar marca `rechazado`, deshabilita la cuenta, revoca sesiones, notifica al titular y audita la decisión. El motivo solo se muestra en administración.
- Solo se rechazan solicitudes pendientes. Para cuentas autorizadas se usa la suspensión del estado general.
- Un administrador no puede gestionar unilateralmente su propio rol o estado. Los Analistas no pueden ejecutar estas operaciones por HTTP directo.

Los cambios administrativos revocan las sesiones previas. Si el primer acceso se revoca o caduca antes de guardar la contraseña definitiva, utilice **Recuperar acceso**. El enlace permite definir la contraseña, manteniendo los requisitos de autorización y MFA. La credencial temporal consumida no se reactiva.

## Correo y almacenamiento

Se utiliza la configuración de correo existente, sin modificar credenciales SMTP. Con `MAIL_TRANSPORT=file`, código y contraseña temporal aparecen en **mensajes distintos** dentro de `.local/mail/*.eml`; con `smtp`, se usa el servidor configurado. La contraseña definitiva nunca se envía por correo.

Si no puede entregarse el código, se devuelve un error y no se crea el usuario. Si falla el envío de la credencial después de crear la cuenta, la solicitud se conserva y la interfaz ofrece recuperación de acceso. Los fallos se auditan sin contenido del mensaje ni detalles sensibles del proveedor.

La credencial temporal contiene 144 bits aleatorios y se almacena únicamente con Argon2id. Se conserva su hash como historial para impedir que se reutilice como contraseña definitiva, incluso por recuperación o cambio posterior. Su validez se controla además por caducidad y fecha de uso: conservar el hash no vuelve a habilitarla.

## Migraciones y arranque

```powershell
# Desde la raíz:
.\.venv\Scripts\python.exe -m scripts.migrate
.\.venv\Scripts\python.exe -m uvicorn backend.api:app --host 192.168.56.1 --port 8000
```

```powershell
# Otra terminal, desde la raíz:
cd frontend
npm.cmd run dev
```

- `003_registro_guiado.sql` reutiliza `auth_token` para verificación previa y ligada al navegador. Añade la etapa `crear_password`, campos de credencial temporal y el estado administrativo `rechazado` con actor, fecha y motivo. El cambio obligatorio de contraseña se inicializa en falso para cuentas anteriores.
- `004_historial_credencial_temporal.sql` permite conservar el hash histórico sin reactivar la credencial consumida.

Opciones nuevas, documentadas en `.env.example`:

```dotenv
AUTH_REGISTRATION_PROOF_SECONDS=900
AUTH_TEMP_PASSWORD_SECONDS=86400
```

Se conservan `AUTH_EMAIL_TTL_SECONDS=300`, `AUTH_MAX_ATTEMPTS=5` y `AUTH_RESEND_SECONDS=60`. La prueba confirmada dura quince minutos, está vinculada al correo y a una cookie HttpOnly/SameSite=Strict del navegador y se consume al registrar la cuenta. Secure es obligatorio en producción. No hay tokens de verificación en localStorage.

## API actualizada

| Método y ruta | Propósito |
|---|---|
| GET `/api/auth/registro/correo` | Estado de verificación del navegador actual |
| POST `/api/auth/registro/correo/enviar` | Enviar o reemitir código previo |
| POST `/api/auth/registro/correo/verificar` | Confirmar código y crear prueba limitada |
| POST `/api/auth/registro/correo/editar` | Invalidar la prueba para editar la dirección |
| POST `/api/auth/registro` | Solo identidad; exige prueba y emite credencial temporal |
| POST `/api/auth/login` | Reconoce y consume la credencial temporal vigente |
| POST `/api/auth/password/inicial` | Crear contraseña desde el desafío restringido |
| POST `/api/auth/password/fortaleza` | Evaluación con sesión válida o token de recuperación |
| GET `/api/auth/admin/usuarios?estado=pendiente` | Filtrar; también admite `aprobado` y `rechazado` |
| PATCH `/api/auth/admin/usuarios/{id}` | Aceptar/rechazar con reautenticación |

Las rutas anteriores de correo siguen disponibles para el bootstrap por CLI y las cuentas antiguas. El registro público no admite contraseña elegida por el cliente ni indicadores de correo verificado en el JSON.

## Validación ejecutada

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
cd frontend
npm.cmd test
npm.cmd run build
```

Pasaron **65 pruebas del backend** sobre PostgreSQL con datos de prueba revertidos y la compilación TypeScript/Vite. Incluyen aprobación mediante TOTP sin contraseña, rechazo de códigos faltantes, inválidos, vencidos o reutilizados, autorización efectiva y conservación de los requisitos de las demás operaciones. Las **7 pruebas del frontend** de validación del registro también pasaron en la entrega del registro guiado.

Los tests del frontend usan el runner nativo de Node (probado con Node 24), sin dependencias nuevas. Se revisaron en navegador los mensajes instantáneos y la distribución a 390 px, sin desbordamiento horizontal. El envío SMTP real depende de la configuración privada del proveedor elegido por el titular.

Referencias: [zxcvbn](https://github.com/dropbox/zxcvbn), [autenticación OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) y [recuperación mediante credenciales de uso único](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html). La credencial inicial solo autoriza crear una contraseña; no reemplaza MFA ni se convierte en contraseña permanente.
