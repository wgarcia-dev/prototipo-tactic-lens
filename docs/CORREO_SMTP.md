# Correo SMTP de TacticLens con Resend

## Estado revisado

El backend ya admite Resend mediante `smtp.resend.com`, puerto `465`, usuario `resend` y API Key como contraseña. No se requieren dependencias nuevas ni cambios de rutas. `backend/auth/mailer.py` utiliza `smtplib.SMTP_SSL` con validación de certificados cuando `SMTP_SSL=true`. Con esta configuración no utiliza STARTTLS. Las operaciones de cuenta reutilizan ese mismo servicio. La configuración coincide con la [documentación oficial de Resend](https://resend.com/docs/send-with-smtp).

Se actualizaron las variables públicas de correo en el `.env` principal, conservando `SMTP_PASSWORD` sin mostrarlo. Si todavía contiene la contraseña anterior de Gmail, el titular debe sustituirla por su API Key de Resend. No se reinició el backend ni se efectuaron conexiones o envíos SMTP. El titular informó que el dominio ya está verificado en Resend; no se accedió a su cuenta para comprobarlo ni se modificó DNS en Cloudflare.

## Archivo que debes editar

```text
C:\Users\user\Documents\tesis\prototipo-tactic-lens\.env
```

Es el archivo de la raíz del repositorio, no `frontend/.env` ni `.env.example`. `backend/api.py` llama a `load_dotenv()` de `python-dotenv`; con la estructura actual encuentra este archivo porque no existe un `backend/.env` intermedio. Las variables que ya existan en el entorno del proceso tienen prioridad: el cargador no las sobrescribe.

## Configuración para Resend

El bloque público ya está preparado. Solo debes colocar la API Key en la asignación existente de `SMTP_PASSWORD`. Mantén una sola asignación de cada variable y conserva PostgreSQL, claves de autenticación, TOTP y el resto de configuración. No hace falta una variable nueva llamada `RESEND_API_KEY`.

```dotenv
MAIL_TRANSPORT=smtp
MAIL_FROM="TacticLens <no-reply@tacticlens.app>"
SMTP_HOST=smtp.resend.com
SMTP_PORT=465
SMTP_USER=resend
SMTP_PASSWORD=PEGA_AQUI_TU_API_KEY_DE_RESEND
SMTP_STARTTLS=false
SMTP_SSL=true
```

1. Abre el archivo `.env` indicado con tu editor local.
2. Busca `SMTP_PASSWORD` y sustituye su valor por la API Key de Resend con permiso de envío para `tacticlens.app`. No uses la contraseña de Gmail, un código de Google Authenticator ni la contraseña de Cloudflare.
3. No copies la clave en el chat, en `.env.example` ni en comandos de terminal. El ejemplo versionado conserva `SMTP_PASSWORD=` vacío.
4. El remitente será `TacticLens <no-reply@tacticlens.app>`. Tu Gmail será el destinatario de la prueba.
5. Conserva `MAIL_TRANSPORT=smtp`, `SMTP_HOST=smtp.resend.com`, `SMTP_PORT=465`, `SMTP_USER=resend`, `SMTP_STARTTLS=false` y `SMTP_SSL=true`. En este puerto la conexión se cifra desde el principio.
6. Guarda el archivo. `MAIL_DEV_DIRECTORY=.local/mail` puede permanecer: no se usa cuando el transporte es `smtp`.

No se necesita activar POP/IMAP ni configurar OAuth o una contraseña de aplicación de Gmail para enviar desde Resend. Las comillas simples o dobles alrededor de los valores son compatibles con `python-dotenv`.

## Aplicar la configuración después de introducir credenciales

El proceso actual no relee el archivo automáticamente. En la terminal donde se ejecuta el backend, detenlo con **Ctrl+C** y vuelve a iniciarlo:

```powershell
cd C:\Users\user\Documents\tesis\prototipo-tactic-lens
.\.venv\Scripts\python.exe -m uvicorn backend.api:app --host 192.168.56.1 --port 8000
```

Este comando conserva la dirección de API usada por el proxy Vite de esta instalación. No requiere reinstalar dependencias, aplicar migraciones ni reiniciar el frontend. Iniciar el backend no envía correos por sí solo; las operaciones de registro, recuperación y notificaciones sí pueden hacerlo con SMTP activo.

No se ha realizado una prueba de entrega. Después de que el titular confirme que terminó de introducir las credenciales, se podrá acordar y ejecutar esa comprobación. Hasta entonces no se debe pulsar el envío de códigos ni realizar operaciones que generen notificaciones para probarlo.

## Prueba posterior de un único correo real

Solo después de guardar la clave y confirmar que terminó, desde la raíz:

```powershell
.\.venv\Scripts\python.exe -m scripts.send_test_email
```

El script pide únicamente el Gmail destinatario y envía un mensaje de prueba reutilizando el servicio y la plantilla actuales. No recibe la clave por argumentos, no la imprime y no modifica usuarios, sesiones o contraseñas. No envía mensajes al importarse ni al iniciar FastAPI. No se ejecutó durante esta preparación.

Compruebe el remitente y la recepción en Gmail, incluido Spam, y el estado del mensaje en la tabla de correos de Resend. La aceptación SMTP no garantiza entrega en la bandeja de entrada. Si falla la autenticación, revise `SMTP_USER=resend` y la API Key. Si falla la conexión, revise acceso saliente al puerto 465. No desactive la validación de certificados.

## Verificación posterior del flujo de cuentas

Después de comprobar el correo de prueba:

1. Abra `http://127.0.0.1:5173/registro` sin una sesión completa y use datos autorizados no registrados. Si su Gmail ya pertenece a una cuenta, use otro buzón o un alias propio para la nueva solicitud.
2. Pulse **Verificar correo**, compruebe el código recibido e introdúzcalo en el mismo formulario. El correo debe quedar bloqueado con opción de edición. El código caduca inicialmente en cinco minutos y no puede reutilizarse.
3. Envíe la solicitud. Recibirá un aviso de recepción sin contraseña. Al aprobarse el registro, recibirá un enlace de un solo uso para definir una contraseña con fortaleza mínima de 75%.
4. Un administrador acepta la solicitud usando su propio Google Authenticator. Compruebe el enlace y la notificación de autorización. El titular debe definir la contraseña e iniciar sesión para completar la configuración o desafío MFA antes de acceder a los módulos.
5. Cierre sesión y abra `http://127.0.0.1:5173/recuperar`. Solicite recuperación para una cuenta existente. La respuesta es genérica. El administrador debe aprobarla desde Solicitudes de recuperación antes de que se envíe el enlace.
6. Abra el enlace recibido dentro de su vigencia, cambie la contraseña e inicie sesión. Debe seguir exigiéndose Google Authenticator. El enlace usado no debe poder reutilizarse y las sesiones anteriores se revocan.

`AUTH_PUBLIC_URL` determina el destino del enlace de recuperación. Consérvelo en la URL real del frontend local mientras la aplicación se ejecute localmente. Tener un dominio remitente no despliega la aplicación web en ese dominio.

## Protección de secretos y puntos de retorno

`.gitignore` excluye `.env` en cualquier directorio, `frontend/.env`, `.local/` y los archivos `.eml`. Los archivos de configuración privados no están versionados. No introduzcas secretos en `.env.example`, en el código, en commits o en el chat. El `.env` es un archivo local de configuración, no un almacén cifrado.

Comprobaciones de Git que no muestran valores:

```powershell
git check-ignore .env frontend/.env
git ls-files -- .env backend/.env frontend/.env
```

El primero debe listar los archivos ignorados; el segundo no debe devolver archivos. El commit local `e757cb9` conserva el código del proyecto antes de esta preparación SMTP. Los commits no respaldan PostgreSQL, el `.env` ni los mensajes locales, que están deliberadamente fuera de Git.

## Cambio posterior de proveedor

El servicio sigue siendo independiente del proveedor. Otro servicio puede configurarse cambiando `MAIL_FROM`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` y los modos TLS. Resend utiliza actualmente SSL directo en 465; para un proveedor que exija STARTTLS en 587 se configurarían `SMTP_SSL=false` y `SMTP_STARTTLS=true`. No se incorporó el SDK de Resend ni se hicieron cambios de infraestructura externa.
