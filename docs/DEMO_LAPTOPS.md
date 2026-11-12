# Demostración TacticLens entre dos laptops

## Implementación y estado comprobado

Se conserva FastAPI, PostgreSQL, React, los roles y MFA existentes. No se crea otro receptor. Flujo:

```text
Cowrie → cowrie.json y rotaciones → events en cola.sqlite3
       → API POST /api/ingesta/eventos por SSH inverso
       → PostgreSQL → proxy local de Vite → interfaz React
```

Punto de retorno Git creado antes de editar: `f636248`, cuyo contenido corresponde al estado anterior `b6a01db`. Antes de la migración se generó además un respaldo privado de PostgreSQL en `.local/backups/antes-ingesta-*.dump`, excluido de Git. Git restaura código, no revierte las bases ni recupera automáticamente cambios posteriores; no restaure un respaldo sobre datos nuevos sin conservarlos primero.

La adaptación se basa en el **exportador real** de `/opt/tacticlens-cowrie/exportar_eventos.py` adjunto en `diagnostico_tacticlens.json`, SHA-256 `36f42dc347ef33d4899536ce2bba7a17bd8f0268fc023b8fe0142d9ea7c17003`. El diagnóstico confirmó 17 filas en `events`, las tablas `events(id,payload,created_at)` y `cursor(name,inode,offset)`, servicio root y timer cada 30 segundos. El programa anterior usaba `events`/Bearer y eliminaba filas tras HTTP 2xx: era incompatible con la API real y no distinguía todas las ocurrencias idénticas.

El diagnóstico también informa `GatewayPorts no`, `AllowTcpForwarding yes`, puerto administrativo 22 y UFW activo, permitiendo 22 y 2222 desde `192.168.0.0/24`. Es compatible con el túnel propuesto a nivel de configuración global. Una regla `Match` específica u otra restricción deberá validarse al abrirlo.

**No se ha instalado el kit en Ubuntu ni se ha probado un túnel real desde este entorno:** la autenticación SSH no interactiva disponible fue rechazada (`Permission denied`). El operador debe introducir sus credenciales solo en su terminal. No se deshabilita la comprobación de host, UFW ni el segundo factor de TacticLens. La prueba en el hotspot requiere las dos laptops y el teléfono físicamente conectados.

## Correcciones de ingesta

- Migración aditiva `007_ingesta_identidad.sql`, aplicada localmente: amplía `numero_secuencia` a bigint y agrega `evento_origen`, con origen completo, sensor, referencia única al evento, huella del contenido y fecha. Los IDs y secuencias históricos no se renumeran.
- Los eventos nuevos usan el generador de IDs PostgreSQL y una secuencia por sesión asignada bajo bloqueo de ingesta del sensor. Se elimina el hash de 31 bits como orden. Los reintentos concurrentes se serializan.
- Una identidad repetida con contenido distinto se rechaza. Dos ocurrencias nuevas distintas con JSON idéntico se conservan. La compatibilidad histórica exige que coincida la identidad de origen anterior; nunca adopta una fila PostgreSQL solo por tener JSON igual. Si una captura histórica perdió su identidad, no se infiere que otra ocurrencia sea la misma.
- El endpoint conserva `{"eventos":[...]}` y `X-API-Key`. Responde `contrato: "tacticlens.ingesta.v2"`, contadores y `confirmaciones` por índice/origen. Cada confirmación indica `insertado`, `duplicado` o `rechazado`; los aceptados incluyen `id_evento`. Las confirmaciones se publican después de confirmar la transacción.
- Se usan savepoints para aislar eventos inválidos. Un lote parcialmente válido obtiene 200 con sus resultados individuales; si todos son inválidos obtiene 422 con el mismo contrato. Los fallos de infraestructura producen 503 y el emisor conserva el lote.
- El emisor comprueba contrato, índices, identidades, IDs persistidos y contadores. No basta HTTP 200. No sigue redirecciones ni proxies ambientales; solo acepta la URL loopback de la API real. Hay límites de bytes por petición y adaptación del tamaño del lote.

`/api/health` añade el contrato, cantidad de eventos y última ingesta persistida. Un heartbeat sigue indicando solamente actividad del proceso, no entrega de datos.

## Exportador real y conservación de SQLite

`collector/exportar_eventos.py` sustituye el programa inspeccionado después de respaldarlo. `collector/sqlite_sender.py` es su módulo de entrega, no otro lector ni otro backend. Se mantienen la unidad `tacticlens-exportador.service`, su timer, la base y las variables reales `TACTICLENS_*`.

Se conservan las tablas originales y sus filas. Se añaden solo metadatos a la misma base:

| Tabla | Uso |
|---|---|
| `tacticlens_envio_meta` | UUID durable de la cola y versión de captura |
| `tacticlens_entregas` | Pendiente, enviado o revisión; intentos y confirmación PostgreSQL |
| `tacticlens_archivos` | Cursor independiente por generación de archivo, inode y huellas |
| `tacticlens_captura_origen` | Correspondencia entre ocurrencia física y fila original |
| `tacticlens_legacy` | Conjunto inicial de filas históricas que se adoptan una vez |
| `tacticlens_captura_revision` | Líneas inválidas retenidas para revisión, sin bloquear líneas posteriores |

La identidad de envío usa el UUID persistente de SQLite y la clave de la fila. El cursor y la nueva ocurrencia se confirman en una transacción durable. Se revisan todas las rotaciones disponibles, incluidas `.gz`; la compresión entre consultas se reconoce mediante el prefijo completo de bytes ya confirmado. Las líneas incompletas esperan; las inválidas quedan conservadas en SQLite antes de avanzar el cursor. Un fallo de escritura revierte ambos.

Los 17 IDs históricos se conservan: una revisión inicial del log asocia las filas antiguas una sola vez. Las ocurrencias posteriores idénticas generan filas nuevas. No se ejecuta `DELETE FROM events` al enviar. `--status` distingue pendientes, enviados y revisión; por eso el total conservado puede crecer después de sincronizar.

La captura continúa aunque falte el túnel. Los fallos de transporte reciben espera progresiva y reintentos por el timer existente. Los eventos rechazados se conservan para revisión. No se imprimen payloads, contraseñas capturadas, claves ni respuestas de error sin filtrar. El contenido original de Cowrie, incluidos intentos de contraseña, permanece en el SQLite privado y en PostgreSQL como antes; proteja ambos respaldos.

No hay garantía frente a disco agotado o logs eliminados antes de ser leídos. Mantenga la retención de rotaciones suficiente para cubrir el intervalo del timer y las interrupciones. Una reescritura completamente idéntica tras `copytruncate` entre dos observaciones puede ser indistinguible de un archivo sin cambios; la rotación por renombrado y la compresión están cubiertas por pruebas. No copie archivos de respaldo adicionales dentro del patrón `cowrie.json*` de captura.

## Preparación en Windows

Desde PowerShell, en la raíz:

```powershell
cd C:\Users\user\Documents\tesis\prototipo-tactic-lens
.\scripts\windows\Comprobar-Requisitos.ps1
```

La migración 007 ya está aplicada en esta PC. En otra instalación existente respalde PostgreSQL antes de ejecutar:

```powershell
.\.venv\Scripts\python.exe -m scripts.migrate
```

Se conserva `HONEYPOT_ID` y el sensor lógico `Cowrie-Prototipo-01`. Se actualizaron solamente sus metadatos a host `192.168.0.110` y versión declarada `3.1.6`, sin cambiar sesiones/eventos. La IP de ese campo es descriptiva; no dirige el transporte. Si necesita actualizarla posteriormente:

```powershell
.\.venv\Scripts\python.exe -m scripts.configure_sensor --host IP_ACTUAL_UBUNTU --version 3.1.6
```

El `.env` de la raíz conserva PostgreSQL, `INGEST_API_KEY`, correo y claves MFA. No genere claves nuevas. El proxy local quedó en `frontend/.env` y su ejemplo usa `VITE_API_PROXY_TARGET=http://127.0.0.1:8000`. El script de arranque además lo establece únicamente para el proceso Vite, evitando que una configuración antigua tenga prioridad.

## Instalar la adaptación en Ubuntu: una vez

Prepare un kit que contiene únicamente los archivos enumerados, sin `.env`, claves privadas ni respaldos:

```powershell
.\scripts\windows\Preparar-KitUbuntu.ps1
scp -r .\.local\kit-cowrie tacticadmin@192.168.0.110:~/
ssh -t tacticadmin@192.168.0.110
```

En la sesión administrativa Ubuntu:

```bash
cd ~/kit-cowrie
sudo bash scripts/ubuntu/configurar.sh "$PWD"
```

El instalador solicita de forma oculta la **`INGEST_API_KEY` del `.env` privado de Windows**. Introdúzcala solo en la terminal de Ubuntu. La almacena como `TACTICLENS_TOKEN`, respetando el nombre real del exportador, y configura:

```dotenv
TACTICLENS_URL=http://127.0.0.1:18765/api/ingesta/eventos
TACTICLENS_TOKEN=LA_MISMA_CLAVE_PRIVADA_INGEST_API_KEY_DE_WINDOWS
TACTICLENS_SENSOR_ID=tacticlens-cowrie-01
```

`TACTICLENS_SENSOR_ID` existente se conserva; no sustituye al UUID del sensor de PostgreSQL ni debe cambiar por cada Wi-Fi. No copie los marcadores ni introduzca las claves en argumentos o en el chat.

Antes de tocar la cola, el instalador comprueba el hash del programa inspeccionado, el esquema real y la unidad oneshot. Pausa el timer y espera a que termine la ejecución activa. Respalda script/configuración y usa la API de backup de SQLite, incluyendo datos comprometidos en WAL; no copia solo el archivo `.sqlite3` mientras está activo. Prepara metadatos, actualiza el programa y su módulo y deshabilita `cowrie-ingest.service` si existe. El servicio y timer originales quedan como único mecanismo automático. No cambia Cowrie, UFW ni SSH.

Si el hash o esquema difieren, se detiene para otra revisión. Si falla después de pausar el timer, restaura script/configuración y deja el timer pausado para evitar envíos al receptor anterior; Cowrie sigue registrando. Revise el mensaje y el respaldo antes de reactivarlo. No ejecute manualmente el lector anterior ni otro emisor sobre la misma cola.

## Arranque diario: tres terminales Windows

**Terminal 1 — backend local:**

```powershell
cd C:\Users\user\Documents\tesis\prototipo-tactic-lens
.\scripts\windows\Iniciar-Backend.ps1
```

**Terminal 2 — frontend:**

```powershell
cd C:\Users\user\Documents\tesis\prototipo-tactic-lens
.\scripts\windows\Iniciar-Frontend.ps1
```

**Terminal 3 — túnel:**

```powershell
cd C:\Users\user\Documents\tesis\prototipo-tactic-lens
.\scripts\windows\Abrir-Tunel.ps1 -UbuntuHost 192.168.0.110
```

Puede omitir `-UbuntuHost` para introducir la IP actual. `-Reconectar` reintenta si cae SSH; si cambió la IP de Ubuntu, cierre con Ctrl+C y vuelva a indicarla. `-IdentityFile RUTA` permite usar una clave privada ya autorizada sin incluir su contenido en el script. También admite autenticación interactiva, sin guardar la contraseña.

El túnel ejecuta OpenSSH con `-N -T -R 127.0.0.1:18765:127.0.0.1:8000`, comprobación de host, `ExitOnForwardFailure` y keepalive. Usa el alias de host `tacticlens-cowrie` para conservar la verificación de identidad al cambiar la IP. Verifique la huella pública desde la consola Ubuntu si es el primer acceso; no acepte cambios inesperados ni desactive la comprobación.

No se abre 8000 en la LAN ni 18765 fuera de Ubuntu. No hace falta una regla Windows de entrada para FastAPI: Windows inicia la conexión SSH saliente. Mantenga las tres terminales abiertas.

En Ubuntu:

```bash
cd ~/kit-cowrie
bash scripts/ubuntu/verificar.sh
sudo bash scripts/ubuntu/sincronizar.sh
sudo bash scripts/ubuntu/estado.sh
```

`verificar.sh` rechaza un túnel publicado fuera de `127.0.0.1`, comprueba la API real y detecta el recolector anterior activo. `sincronizar.sh` pausa el timer, espera a que termine cualquier ejecución activa y llama al mismo exportador con un reintento inmediato supervisado; después restaura el timer. No ejecuta dos lectores ni detiene Cowrie. El timer repite automáticamente cada 30 segundos, además de la espera progresiva del envío, de hasta cinco minutos. `--status` muestra la fecha del próximo reintento.

En Windows, otra terminal puede mostrar el estado:

```powershell
.\scripts\windows\Estado-Ingesta.ps1 -Seguir
```

Abra `http://127.0.0.1:5173`, inicie sesión con su cuenta habilitada y Google Authenticator, y consulte Sesiones y eventos. El acceso administrativo SSH a Ubuntu es distinto del SSH simulado de Cowrie.

## Demostración y desconexión

1. Confirme `verificar.sh`, `database: connected` y los contadores iniciales.
2. Desde Windows abra `ssh -p 2222 root@IP_UBUNTU`; dentro de Cowrie ejecute `whoami`, `pwd` y `exit`.
3. Espere el timer o ejecute `sincronizar.sh`. La nueva sesión debe aparecer en TacticLens. SQLite conserva sus filas y aumenta `enviados`.
4. Cierre solo el túnel con Ctrl+C. Genere otra sesión controlada. Cowrie debe seguir funcionando y el timer debe aumentar `pendientes`.
5. En Ubuntu ejecute `sudo bash scripts/ubuntu/probar-reconexion.sh antes`.
6. Reabra el túnel, espere la sincronización y ejecute `sudo bash scripts/ubuntu/probar-reconexion.sh despues`. El script exige confirmaciones de todos los pendientes de la muestra, sin disminución de filas ni registros en revisión.
7. Consulte nuevamente la sesión en la web. Si se perdió una respuesta después de guardar PostgreSQL, la reentrega obtiene recibos de duplicado y no crea otra ocurrencia.

## Hotspot sin Internet

Conecte ambas laptops al mismo hotspot. Obtenga las direcciones con `ipconfig` en Windows e `ip -br address` en Ubuntu. No asuma que el teléfono mantiene `192.168.0.*` ni que permite comunicación entre clientes.

UFW actualmente permite solo `192.168.0.0/24`. Desde la **consola física de Ubuntu**, autorice exclusivamente la nueva dirección privada de Windows:

```bash
cd ~/kit-cowrie
sudo bash scripts/ubuntu/autorizar-windows.sh IP_PRIVADA_ACTUAL_WINDOWS
```

El script añade acceso a 22 y 2222 para esa dirección; no deshabilita UFW ni abre 18765, y no borra reglas anteriores. Al terminar revise las reglas antiguas según su política; este kit no las elimina automáticamente.

Abra nuevamente `Abrir-Tunel.ps1 -UbuntuHost IP_ACTUAL_UBUNTU`. No cambie URLs del exportador, clave, UUID del sensor ni el proxy. Repita la demostración con los datos móviles desactivados. Si falla TCP/22 aun con reglas correctas, compruebe aislamiento entre clientes del hotspot.

DeepSeek y Resend requieren Internet. Para esta prueba bastan captura, SQLite, ingesta, PostgreSQL, consulta y cuentas previamente autorizadas con MFA. TOTP funciona localmente, pero ambos relojes deben estar correctos. No intente completar registro por correo ni análisis nuevos de DeepSeek como parte de la prueba offline.

## Pruebas y archivos

Pruebas automáticas:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
cd frontend
npm.cmd test
npm.cmd run build
```

Se ejecutaron 144 pruebas Python, incluidas concurrencia PostgreSQL, identidad histórica, dos ocurrencias idénticas, respuesta perdida después del commit, SQLite → API real → PostgreSQL → consultas con autenticación, rotaciones múltiples, gzip, cuarentena y rollback del cursor. Las llamadas externas de correo/LLM se simulan. Se corrigió el aislamiento de las pruebas de correo para que no contaran avisos reales anteriores; no se borraron esos avisos. También se ejecutaron 7 pruebas frontend y el build, con los avisos previos de tamaño de bundle/React Router.

La sintaxis PowerShell y Bash se comprobó con las herramientas ya instaladas; OpenSSH `-G` confirmó la configuración del reenvío, sin abrirlo. No se declaran aprobados el despliegue remoto, túnel real, captura en hardware ni hotspot: requieren ejecución manual con las credenciales del operador.

Archivos principales: `backend/ingestion.py`, integración en `backend/api.py`, `backend/routes.py` y el límite del middleware; migración 007; `collector/exportar_eventos.py` y `sqlite_sender.py`; retiro del arranque de `collector/collector.py`; scripts de Windows/Ubuntu; `scripts/configure_sensor.py`, `scripts/demo_status.py`; pruebas `test_ingestion.py`, `test_sqlite_capture.py`, `test_sqlite_sender.py`; aislamiento en `test_professional_mail.py`; proxy de ejemplo, README, `.gitattributes` y esta guía. No se modifica el análisis LLM, IoCs ni MITRE.
