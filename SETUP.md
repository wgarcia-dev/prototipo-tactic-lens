# Instalación y ejecución del prototipo

Esta guía sirve para el equipo original y para un compañero que clone el proyecto desde GitHub. La aplicación tiene tres procesos distintos:

| Componente | Equipo | Función |
| --- | --- | --- |
| Cowrie y `collector.py` | Ubuntu Server en VirtualBox | Capturan eventos y los envían por HTTP |
| FastAPI y PostgreSQL | Windows | Guardan eventos, consultan sesiones y ejecutan el análisis LLM |
| React/Vite | Windows | Muestran los datos que devuelve FastAPI |

El prototipo original usa Windows `192.168.56.1`, Ubuntu `192.168.56.101`, FastAPI `8000`, SSH administrativo de Ubuntu `22` y honeypot Cowrie `2222`. **El puerto 22 y el 2222 no llevan al mismo sistema.** La API usa `http://`, sin `https://`, dentro de la red host-only de VirtualBox.

## 1. Obtener el código y comprobar los requisitos

En Windows, clone el repositorio y abra **PowerShell en la raíz del proyecto**, donde están `backend.py`, `collector.py` y `deploy/`:

```powershell
git clone "URL_DEL_REPOSITORIO"
cd "CARPETA_CLONADA"
Test-Path .\backend.py
Test-Path .\collector.py
Test-Path .\deploy\cowrie-ingest.service
```

Los tres `Test-Path` deben devolver `True`. Si el prompt termina en `\deploy>`, ejecute `cd ..` antes de los comandos que usan ` .\collector.py` y ` .\deploy\...`. Se necesitan Python, Node.js/npm, PostgreSQL 18 y pgvector. En el equipo original Cowrie ya está instalado en `/home/cowrie/my-honeypot`.

```powershell
python --version
node --version
npm.cmd --version
Get-NetIPAddress -IPAddress 192.168.56.1
```

`Get-NetIPAddress` debe encontrar la IP host-only. Si el compañero no tiene esta red, puede ejecutar la API localmente en `127.0.0.1` y usar la importación manual descrita en la sección 8. Para conectar una VM con otras IPs, actualice las direcciones de los comandos, `DEV_HOST_IP`, `INGEST_URL`, la regla de firewall y el proxy de Vite.

## 2. Preparar PostgreSQL sin borrar bases existentes

El backend **no crea tablas ni aplica migraciones**. El archivo [database/honeypot_schema.sql](database/honeypot_schema.sql) es una exportación **solo del esquema** de las 20 tablas existentes en PostgreSQL 18; no contiene sesiones, eventos ni contraseñas capturadas.

### Si ya tiene la base de datos del proyecto

Use su base y esquema `honeypot` existentes. En pgAdmin confirme que están `honeypot.honeypot`, `honeypot.sesion` y `honeypot.evento`, y consulte el honeypot disponible:

```sql
SELECT id_honeypot, nombre, host FROM honeypot.honeypot;
```

Copie el `id_honeypot` correspondiente a `HONEYPOT_ID` en `.env`. **No ejecute el archivo SQL de esquema sobre una base que ya tiene tablas.** El nombre real de la base se toma de `DATABASE_NAME`; no tiene por qué coincidir con el nombre de la carpeta ni con el ejemplo de la tesis.

### Si el compañero empieza con una base vacía

En pgAdmin, cree una base de datos nueva con el nombre que prefiera y ejecute en ella:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

Importe `database/honeypot_schema.sql` con `psql` de PostgreSQL 18. Desde PowerShell en la raíz del proyecto, sustituyendo los valores de ejemplo:

```powershell
& 'C:\Program Files\PostgreSQL\18\bin\psql.exe' -h localhost -U "USUARIO_DB" -d "NOMBRE_DB" -v ON_ERROR_STOP=1 -f .\database\honeypot_schema.sql
```

Después cree un registro del honeypot en esa base y conserve el UUID devuelto:

```sql
INSERT INTO honeypot.honeypot (nombre, host)
VALUES ('Cowrie-Prototipo-01', '192.168.56.101')
RETURNING id_honeypot;
```

Una base vacía no mostrará sesiones hasta importar un archivo Cowrie real o habilitar el recolector. El catálogo MITRE mínimo se carga más adelante mediante `seed_catalog.py`.

## 3. Configurar variables y dependencias en Windows

Desde PowerShell en la raíz del proyecto:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
notepad .env
```

Si `.env` ya existe, **no lo sobrescriba**: ábralo y complete los valores que falten. Configure `DATABASE_NAME`, `DATABASE_USER`, `DATABASE_PASSWORD`, `DATABASE_HOST` y el UUID real en `HONEYPOT_ID`. `DEV_HOST_IP=192.168.56.1` corresponde a la IP de Windows en la red host-only.

Genere una clave aleatoria para `INGEST_API_KEY` con este comando en PowerShell y péguela en `.env`:

```powershell
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
```

**No copie la clave a GitHub ni a mensajes.** `INGEST_API_KEY` autentica al recolector y es distinta de `LLM_API_KEY`. Para análisis real configure `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` y `LLM_TIMEOUT_SECONDS`; el backend actual no genera análisis simulados. Puede dejar la clave LLM sin configurar si solo quiere demostrar ingesta, consulta y gráficos: el botón **Analizar sesión** fallará hasta configurarla, pero la ingesta continuará.

Instale el pequeño catálogo de referencia MITRE después de haber configurado la conexión y `HONEYPOT_ID`:

```powershell
.\.venv\Scripts\python.exe seed_catalog.py
```

## 4. Iniciar FastAPI en Windows

Abra una terminal PowerShell dedicada y déjela abierta:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend:app --host 192.168.56.1 --port 8000
```

Compruebe desde **otra terminal Windows**:

```powershell
Invoke-RestMethod http://192.168.56.1:8000/api/health
```

Debe responder `status: ok`, `database: connected` y `llm_mode: real`. `collector_last_seen: null` significa que aún no hay señal del recolector; no significa que la base esté desconectada.

Si aparece `[WinError 10048]` o `address already in use`, **ya hay un proceso usando el puerto 8000**. No abra un segundo Uvicorn. Compruebe si el existente responde a `/api/health`; si ejecuta código antiguo, deténgalo con `Ctrl+C` en su propia terminal y vuelva a iniciar uno solo. Si no puede enlazar `192.168.56.1`, revise `Get-NetIPAddress` y la configuración host-only.

Para una demo local sin VM, use `--host 127.0.0.1 --port 8000`. En ese caso configure el proxy de la sección siguiente hacia `http://127.0.0.1:8000`.

## 5. Iniciar React en Windows

Abra otra terminal PowerShell en la raíz del proyecto:

```powershell
cd frontend
npm.cmd ci --cache .npm-cache
if (-not (Test-Path .env.local)) { Copy-Item .env.example .env.local }
npm.cmd run dev
```

En `frontend/.env.local`, `VITE_API_PROXY_TARGET` debe apuntar al FastAPI que está ejecutando: `http://192.168.56.1:8000` en el equipo original o `http://127.0.0.1:8000` para demo local. Abra `http://127.0.0.1:5173` en el navegador. PowerShell puede bloquear `npm.ps1`; `npm.cmd` evita ese problema. Vite sirve la interfaz, **no guarda eventos en PostgreSQL**. La pantalla consulta FastAPI cada 5 segundos.

## 6. Permitir el tráfico de la VM hacia FastAPI

En **PowerShell como administrador de Windows**, cree la regla solo si todavía no existe:

```powershell
New-NetFirewallRule -DisplayName 'Cowrie Ingesta' -Direction Inbound -Action Allow -Protocol TCP -LocalAddress 192.168.56.1 -LocalPort 8000 -RemoteAddress 192.168.56.101
```

Esta regla permite únicamente a la VM acceder a FastAPI. PostgreSQL permanece local en Windows. Desde **Ubuntu real**, `curl -i http://192.168.56.1:8000/api/health` debe responder HTTP 200. Si alguien usa `https://`, obtendrá un error TLS porque este prototipo sirve HTTP.

## 7. Instalar el recolector en Ubuntu real

En una terminal PowerShell ubicada en la **raíz del proyecto**, compruebe primero `Test-Path .\collector.py` y `Test-Path .\deploy\cowrie-ingest.service`. Transfiera **ambos archivos antes de entrar por SSH**:

```powershell
scp .\collector.py .\deploy\cowrie-ingest.service william@192.168.56.101:/home/william/
ssh william@192.168.56.101
```

`scp` solicita la contraseña administrativa de `william` y debe mostrar la transferencia de dos archivos. El segundo comando usa el SSH real de Ubuntu por el puerto **22**. También puede abrir otra ventana PowerShell para SCP si ya tiene abierta una sesión SSH administrativa.

El prompt correcto es `william@ubuntuserver:~$`. Verifique antes de instalar:

```bash
whoami
hostname
ls -l /home/william/collector.py /home/william/cowrie-ingest.service
```

`whoami` debe mostrar `william` y deben aparecer **ambos archivos**. Si el prompt dice `root@svr04`, está dentro de Cowrie por el puerto **2222**: escriba `exit` hasta volver a `PS C:\...>` y conecte con `ssh william@192.168.56.101`. En Cowrie simulado `sudo` e `install` no administran Ubuntu. Si Linux dice `Could not resolve hostname c:`, ejecutó el SCP de Windows dentro de Ubuntu; vuelva a PowerShell y repítalo allí.

Como `william` en Ubuntu real, prepare el directorio de configuración e instale los archivos:

```bash
sudo install -o cowrie -g cowrie -m 0700 -d /home/cowrie/.config
sudo install -o cowrie -g cowrie -m 0644 /home/william/collector.py /home/cowrie/collector.py
sudo install -o root -g root -m 0644 /home/william/cowrie-ingest.service /etc/systemd/system/cowrie-ingest.service
```

Cree `/home/cowrie/.config/cowrie-ingest.env` con `sudo nano /home/cowrie/.config/cowrie-ingest.env` y estos nombres de variable:

```dotenv
INGEST_API_KEY=PEGUE_LA_MISMA_CLAVE_QUE_EN_WINDOWS
INGEST_URL=http://192.168.56.1:8000/api/ingesta/eventos
COLLECTOR_STATE=/home/cowrie/.config/cowrie-ingest-state.json
```

No coloque `LLM_API_KEY` en Ubuntu. Proteja el archivo y verifique que el usuario `cowrie` pueda leer el log:

```bash
sudo chown cowrie:cowrie /home/cowrie/.config/cowrie-ingest.env
sudo chmod 600 /home/cowrie/.config/cowrie-ingest.env
sudo -u cowrie test -r /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json
```

El último comando no debe mostrar errores. Active el servicio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie-ingest
sudo systemctl status cowrie-ingest --no-pager
```

Debe decir `active (running)`. Para ver errores sin mostrar el JSON capturado:

```bash
sudo journalctl -u cowrie-ingest -n 30 --no-pager
```

Si `Unit cowrie-ingest.service not found`, el archivo de servicio no se instaló: vuelva a comprobar `ls -l /home/william/cowrie-ingest.service` y el segundo `sudo install`. Si `scp` responde `stat local ./collector.py: No such file`, está en el directorio incorrecto; vuelva a la raíz del proyecto con `cd ..` si está en `deploy`. No ejecute dos recolectores sobre el mismo archivo de estado. El servicio ya reinicia el recolector si falla y lo inicia al arrancar Ubuntu.

Cowrie es un proceso distinto. Verifique su puerto en Ubuntu real con `sudo ss -lntp | grep ':2222'`. Si ya escucha, no necesita ejecutar `cowrie start` otra vez. Los comandos escritos en el SSH administrativo de `william` no son eventos del honeypot.

## 8. Comprobar el flujo completo

Primero, desde Windows:

```powershell
Invoke-RestMethod http://192.168.56.1:8000/api/health
```

`collector_last_seen` debe ser una fecha reciente. El recolector envía un latido cada 20 segundos; la interfaz muestra **SIN SEÑAL DEL RECOLECTOR** si no recibió uno en 45 segundos. Si sigue `null`, compruebe el servicio y el firewall antes de probar comandos.

En **otra terminal Windows** entre al honeypot simulado:

```powershell
ssh -p 2222 root@192.168.56.101
```

En el prompt `root@svr04`, ejecute `whoami`, `pwd` y `uname -a`. Después salga con `exit`. En Windows consulte los datos nuevos:

```powershell
$sesiones = Invoke-RestMethod http://192.168.56.1:8000/api/sesiones
$sesiones | Select-Object -First 5 cowrie_session_id,fecha_inicio,eventos
$id = @($sesiones)[0].id_sesion
Invoke-RestMethod "http://192.168.56.1:8000/api/sesiones/$id/eventos"
```

En pgAdmin puede verificar la base que figura en `DATABASE_NAME` con:

```sql
SELECT id_sesion, cowrie_session_id, fecha_inicio FROM honeypot.sesion ORDER BY fecha_inicio DESC LIMIT 10;
SELECT id_evento, id_sesion, tipo_evento, fecha_hora FROM honeypot.evento ORDER BY fecha_hora DESC LIMIT 20;
```

Compare las marcas temporales **nuevas**; las filas antiguas no demuestran que el recolector esté funcionando ahora. La API oculta campos de contraseña en las respuestas, pero los registros originales de Cowrie permanecen en PostgreSQL según el modelo.

### Importación manual opcional

Si el compañero no tiene VM o el recolector todavía no está operativo, puede importar un `cowrie.json` **real** desde la pantalla **Importar Cowrie** o por CLI en Windows:

```powershell
.\.venv\Scripts\python.exe import_cowrie.py .\cowrie.json
```

Si `william` no puede leer el log de Cowrie, copie primero el archivo a su directorio desde Ubuntu real: `sudo cp /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json /home/william/cowrie.json` y `sudo chown william:william /home/william/cowrie.json`. Después, desde PowerShell Windows, ejecute `scp william@192.168.56.101:/home/william/cowrie.json .`. No suba logs capturados a GitHub.

## 9. Pruebas y análisis LLM

En Windows, desde la raíz del proyecto:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

En `frontend/`:

```powershell
npm.cmd run build
```

La prueba de ingesta crea eventos dentro de una transacción que se revierte. El botón **Analizar sesión** llama al proveedor indicado en `.env`; requiere una API Key válida, puede consumir saldo y no afecta la ingesta si el proveedor no está disponible. Los resultados del LLM son propuestas con evidencias, no una conclusión automática de compromiso.

## 10. Compartir el proyecto por GitHub

`.gitignore` excluye `.env`, `frontend/.env.local`, los entornos virtuales, `node_modules` y los archivos compilados. Comparta `.env.example` y `frontend/.env.example`, **no las claves reales**, el archivo del estado del recolector, logs Cowrie ni un respaldo de la base con eventos capturados. Antes de publicar, compruebe los archivos que Git incluirá:

```powershell
git status --short
git check-ignore .env frontend/.env.local
```

Una versión anterior de esta guía contenía una clave real de ingesta; ya se sustituyó por un marcador. **Renueve `INGEST_API_KEY` antes de compartir el repositorio**: genere otra clave, actualícela en `.env` de Windows y en `/home/cowrie/.config/cowrie-ingest.env` de Ubuntu, y reinicie FastAPI y `cowrie-ingest`. Su compañero debe generar su propia clave y su propia configuración. El archivo SQL incluido contiene solo estructura; cada equipo debe crear o importar sus propios datos de prueba con autorización.
