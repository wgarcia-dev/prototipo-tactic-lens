# Correo SMTP de TacticLens

## Estado revisado

El backend ya admite Gmail mediante `smtp.gmail.com`, puerto `587`, autenticación con contraseña de aplicación y STARTTLS. No se requieren dependencias nuevas, cambios de rutas ni cambios del servicio de correo. `backend/auth/mailer.py` utiliza `smtplib.SMTP`, establece TLS con un contexto que valida certificados, se autentica y envía el mensaje. Las operaciones de cuenta reutilizan ese mismo servicio.

En esta intervención no se modificó el `.env`, no se reemplazaron credenciales, no se reinició el backend ni se efectuaron conexiones o envíos SMTP. Se revisó la presencia de variables sin mostrar sus valores. En el momento de revisión había configuración del buzón local y faltaban las asignaciones `SMTP_*` en el `.env` principal.

## Archivo que debes editar

```text
C:\Users\user\Documents\tesis\prototipo-tactic-lens\.env
```

Es el archivo de la raíz del repositorio, no `frontend/.env` ni `.env.example`. `backend/api.py` llama a `load_dotenv()` de `python-dotenv`; con la estructura actual encuentra este archivo porque no existe un `backend/.env` intermedio. Las variables que ya existan en el entorno del proceso tienen prioridad: el cargador no las sobrescribe.

## Configuración para Gmail

Edita las asignaciones existentes de `MAIL_TRANSPORT` y `MAIL_FROM` y agrega las de `SMTP_*` que falten. Mantén una sola asignación de cada variable. No reemplaces todo el archivo: conserva PostgreSQL, claves de autenticación, TOTP y el resto de configuración.

```dotenv
MAIL_TRANSPORT=smtp
MAIL_FROM="TacticLens <TU_CORREO@gmail.com>"
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=TU_CORREO@gmail.com
SMTP_PASSWORD=TU_CONTRASENA_DE_APLICACION
SMTP_STARTTLS=true
SMTP_SSL=false
```

1. Abre el archivo `.env` indicado con tu editor local.
2. Cambia `MAIL_TRANSPORT=file` por `MAIL_TRANSPORT=smtp`.
3. Sustituye `TU_CORREO@gmail.com` en **ambos lugares** por la misma dirección completa de la cuenta Gmail remitente.
4. Sustituye `TU_CONTRASENA_DE_APLICACION` por la contraseña de aplicación ya generada. Pega los 16 caracteres sin espacios de agrupación. No uses la contraseña habitual de tu cuenta ni un código de Google Authenticator.
5. Conserva exactamente `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_STARTTLS=true` y `SMTP_SSL=false`. STARTTLS cifra la conexión; `SMTP_SSL=false` desactiva únicamente el TLS implícito de otro modo de conexión.
6. Guarda el archivo. `MAIL_DEV_DIRECTORY=.local/mail` puede permanecer: no se usa cuando el transporte es `smtp`.

No se necesita activar POP o IMAP para enviar. La configuración coincide con la [ayuda oficial de Gmail sobre SMTP y STARTTLS](https://support.google.com/mail/answer/7104828?hl=es). Google documenta el uso de [contraseñas de aplicación](https://support.google.com/accounts/answer/185833?hl=es).

## Aplicar la configuración después de introducir credenciales

El proceso actual no relee el archivo automáticamente. En la terminal donde se ejecuta el backend, detenlo con **Ctrl+C** y vuelve a iniciarlo:

```powershell
cd C:\Users\user\Documents\tesis\prototipo-tactic-lens
.\.venv\Scripts\python.exe -m uvicorn backend.api:app --host 192.168.56.1 --port 8000
```

Este comando conserva la dirección de API usada por el proxy Vite de esta instalación. No requiere reinstalar dependencias, aplicar migraciones ni reiniciar el frontend. Iniciar el backend no envía correos por sí solo; las operaciones de registro, recuperación y notificaciones sí pueden hacerlo con SMTP activo.

No se ha realizado una prueba de entrega. Después de que el titular confirme que terminó de introducir las credenciales, se podrá acordar y ejecutar esa comprobación. Hasta entonces no se debe pulsar el envío de códigos ni realizar operaciones que generen notificaciones para probarlo.

## Protección de secretos y puntos de retorno

`.gitignore` excluye `.env` en cualquier directorio, `frontend/.env`, `.local/` y los archivos `.eml`. Los archivos de configuración privados no están versionados. No introduzcas secretos en `.env.example`, en el código, en commits o en el chat. El `.env` es un archivo local de configuración, no un almacén cifrado.

Comprobaciones de Git que no muestran valores:

```powershell
git check-ignore .env frontend/.env
git ls-files -- .env backend/.env frontend/.env
```

El primero debe listar los archivos ignorados; el segundo no debe devolver archivos. El commit local `e757cb9` conserva el código del proyecto antes de esta preparación SMTP. Los commits no respaldan PostgreSQL, el `.env` ni los mensajes locales, que están deliberadamente fuera de Git.

## Cambio posterior de proveedor

El servicio no está acoplado a Gmail. Para un dominio propio, cambia en el `.env` `MAIL_FROM`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` y los modos TLS según el proveedor. En puerto 587 suele utilizarse STARTTLS; para TLS implícito, configura `SMTP_SSL=true` y `SMTP_STARTTLS=false` con el puerto indicado por el proveedor. Conserva TLS. La configuración de dominio y sus registros de correo se realizará cuando se elija el proveedor.
