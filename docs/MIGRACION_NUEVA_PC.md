# Migración de TacticLens a otra PC Windows

Preparación comprobada el **18 de noviembre de 2026**. Prioridad: desarrollar con los
históricos PostgreSQL en una sola PC. No configurar Ubuntu inicialmente.

## ARRANQUE RÁPIDO

Instalar primero los requisitos de la sección siguiente. En la **nueva PC**, clonar la
rama integrada (no el `main` antiguo):

```powershell
git clone --branch codex/integracion-colaborativa-http https://github.com/wgarcia-dev/prototipo-tactic-lens.git C:\TacticLens
cd C:\TacticLens
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Preparar-NuevaPC.ps1
```

Recibir por canales privados separados el paquete cifrado y su archivo de clave. Los
ejemplos usan rutas locales ilustrativas; **no escribir claves en la terminal ni en el chat**:

```powershell
.\.venv\Scripts\python.exe -m scripts.private_transfer unpack `
  --input C:\Traslado\TacticLens_Privado.fernet `
  --key-file C:\ClaveSeparada\transfer.key `
  --destination .local\recibido
.\.venv\Scripts\python.exe -m scripts.recover_private --source .local\recibido
```

Editar `.env` **directamente en la nueva PC** para adaptar únicamente la conexión a su
PostgreSQL y las rutas locales que cambien. Conservar exactamente `AUTH_SECRET_KEY`,
`AUTH_TOTP_KEYS`, `HONEYPOT_ID` y las credenciales de servicios que se quieran mantener.
Después, con PostgreSQL/pgvector disponibles y un destino vacío:

```powershell
.\.venv\Scripts\python.exe -m scripts.portability prerequisites
.\.venv\Scripts\python.exe -m scripts.portability restore `
  --archive .local\recibido\database\TacticLens_Completo.backup `
  --manifest .local\recibido\database\manifest.json `
  --database tactic-lens-db
.\.venv\Scripts\python.exe -m scripts.portability check --model
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Iniciar-TacticLens.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Verificar-TacticLens.ps1
```

URL: **http://127.0.0.1:5173/**. Iniciar sesión con la cuenta y Google Authenticator
existentes. No generar otro administrador ni volver a registrar los mismos usuarios.

## 1. Requisitos y alcance comprobado

| Requisito | Preparación |
|---|---|
| Windows | x64; se recomienda Windows 11 con soporte vigente |
| CPU/RAM/disco | CPU x64 adecuada para ONNX en CPU; 8 GB RAM orientativos, 16 GB recomendados; reservar varios GB para PostgreSQL, dependencias y respaldos |
| Git | Git for Windows, en PATH |
| Python | x64 3.10–3.13 admitido por el preparador; entorno comprobado: **3.10.11**. Para otra versión, verificar las ruedas del lock; 3.12 es una opción de desarrollo |
| Node.js/npm | Node **22.13+**; comprobado **24.14.0**, npm **11.9.0**. Preferir Node 24 LTS |
| PostgreSQL | **18**, comprobado **18.3**, puerto actual 5432 |
| pgvector servidor | **0.8.7** compatible con ese PostgreSQL, además del paquete Python |
| Red | Internet para descargar paquetes/modelo si faltan; búsquedas locales e históricos funcionan después sin Internet. DeepSeek y SMTP reales sí requieren conectividad |

Fuentes: [PostgreSQL Windows](https://www.postgresql.org/download/windows/),
[Python Windows](https://www.python.org/downloads/windows/),
[Node.js](https://nodejs.org/en/download), [Git](https://git-scm.com/download/win).
No se comprobó físicamente la segunda PC; se ensayaron los scripts y una restauración
aislada en esta PC. No se necesita GPU ni un servidor adicional de embeddings.

## 2. Código público y transferencia privada

**En GitHub:** backend, frontend, migraciones, exportador, scripts Windows/Ubuntu,
dependencias/locks, ejemplos sin secretos, tests y documentación técnica. Se conserva
la historia integrada de los dos autores y la rama `codex/integracion-colaborativa-http`.

**Solo por transferencia cifrada:** dump real, manifiesto de integridad, `.env` original,
configuración privada de frontend y todo el estado privado de desarrollo de `.local/`
(cachés MiniLM/STIX, informes de prueba, respaldos previos, correo de desarrollo y
configuración histórica del demo). Los archivos de esta migración se incluyen de forma
selectiva para no empaquetarse recursivamente. No se transportan `.venv` ni `node_modules`:
se reconstruyen con los locks.

`scripts/private_transfer.py` utiliza **Fernet de cryptography**, cifrado autenticado
con clave aleatoria independiente. El archivo `transfer.key` abre el paquete: enviarlo
por otro canal o custodiarlo aparte del USB con el cifrado. **No enviarlo junto al paquete
por el mismo medio y no publicarlo en GitHub/chat**. Mantener copias privadas de respaldo.
La carpeta de origen tiene ACL limitada al usuario actual, SYSTEM y administradores.
La extracción, recuperación y preparación también restringen permisos de las carpetas
privadas y archivos `.env` de destino; nunca se imprime el contenido de las claves.

Paquete **ya generado y comprobado**, relativo a la raíz de esta PC:

```text
Cifrado: .local/migration/20261118/TacticLens_Privado.fernet
Tamaño: 45.837.688 bytes; 125 archivos
SHA-256: a097dad3ee1123b0ad68d72df6576d502b4499b7b33c488babdd3cdaa5ea68e6
Clave SEPARADA: .local/migration/20261118/clave-separada/transfer.key
```

Se ensayó su descifrado autenticado y recuperación a una carpeta aislada: 118 archivos
copiados, `.env` y dump idénticos byte a byte, 0 archivos copiados al repetir. El modelo
recuperado cargó en CPU y produjo vectores de 384 dimensiones. Este ensayo no sustituye
la instalación física de PostgreSQL/dependencias en la segunda computadora.

La clave de transferencia **no sustituye** `AUTH_TOTP_KEYS`, que está dentro del `.env`
cifrado y permite descifrar los secretos Google Authenticator de la base. Perder o
regenerar esas claves impediría usar los factores MFA restaurados.

La extracción autentica el paquete y comprueba cada SHA-256 antes de escribir archivos.
Rechaza destinos existentes y rutas que salgan de la carpeta. La recuperación posterior
solo copia archivos ausentes, idénticos o `.env` que sean exactamente el ejemplo sin
rellenar. Ante un archivo privado distinto, se detiene y exige revisión manual; no lo
sobrescribe. Se omiten PIDs de procesos anteriores y se adapta el puntero conocido de
respaldo a la nueva raíz. Los auxiliares de red archivados no se ejecutan.

## 3. Respaldo real de esta preparación

```text
Origen: tactic-lens-db, PostgreSQL 18.3, puerto 5432, vector 0.8.7
Archivo: .local/migration/20261118/database/TacticLens_Completo.backup
Tamaño: 2.423.124 bytes
SHA-256: 3449961c3ce37961036038e2bfc6bf064bb567d1ef9b51c88257c52c04b780c6
```

Fue creado con `pg_dump -Fc` y un snapshot exportado desde una transacción de solo
lectura. El manifiesto y el dump corresponden a la misma vista consistente. Se comprobó
`pg_restore --list` (**280 entradas**) y la decodificación completa a `NUL`.

Se restauró en **`tacticlens_restorecheck_20261118`**, una base nueva aislada:

- **33 tablas** con conteos y hashes de contenido coincidentes.
- **33 PK, 74 FK, 22 restricciones únicas y 100 CHECKs** conservadas y comparadas.
- PostgreSQL reescribe 29 expresiones de cast de arrays varchar/text al restaurar;
  el verificador normaliza solo esa equivalencia conocida. No ignora diferencias de
  valores, relaciones, validación ni otras expresiones.
- 4 usuarios, 2 roles, 125 sesiones, 1.493 eventos, 3 IoCs y 1.490 observaciones.
- 7 análisis, 11 mapeos y sus vínculos/evidencias; también se preservan los demás datos
  de autenticación, recuperación, auditoría y configuraciones presentes.
- Catálogo 20.1, 867 técnicas/subtécnicas, 1.099 relaciones técnica–táctica y 706 vectores.
- Las **4 configuraciones MFA** se descifran con las claves privadas preservadas.

La base original se comprobó sin cambios de contenido en sus 33 tablas después de las
pruebas. La copia aislada queda disponible para revisión; no se borró la base original.
No debe confundirse la copia de pruebas con el archivo original que se trasladará.

## 4. Preparación automática

`Preparar-NuevaPC.ps1` admite Windows PowerShell 5.1. Trabaja desde `$PSScriptRoot`,
comprueba Git/Python/Node/npm/clientes PostgreSQL, crea `.venv` cuando falta e instala
`requirements-portable.lock.txt`. Comprueba versiones existentes para evitar reinstalar
innecesariamente. Para React utiliza `npm ci` y `package-lock.json`; no actualiza el lock.
Conserva los `.env` existentes y crea ejemplos cuando faltan. No genera claves MFA nuevas.

```powershell
# Solo comprobar, sin instalar ni escribir configuraciones:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Preparar-NuevaPC.ps1 -SoloComprobar
# Si PostgreSQL esta en otra ruta:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Preparar-NuevaPC.ps1 -PgBinDirectory D:\PostgreSQL\18\bin
# Descargar/verificar solo el modelo oficial si falta:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Preparar-NuevaPC.ps1 -PrepararModelo
```

Si aún falta `.env` privado o pgvector, se informa que la restauración no está certificada.
No se ejecutan migraciones, seeding, importación MITRE, regeneración de embeddings,
restauraciones, correos ni llamadas LLM durante este preparador.

## 5. Configuración privada que debe conservarse

El backend carga `.env` en la raíz. No imprimirlo ni copiar sus valores al chat.

| Variables | Acción en la nueva PC |
|---|---|
| `DATABASE_NAME` | Nombre del destino restaurado; ejemplo `tactic-lens-db` |
| `DATABASE_HOST`, `DATABASE_PORT` | Habitualmente `localhost`, `5432` |
| `DATABASE_USER`, `DATABASE_PASSWORD` | Adaptar al rol SQL instalado en la nueva PC, introduciendo la contraseña solo localmente |
| `AUTH_SECRET_KEY`, `AUTH_TOTP_KEYS` | **Conservar exactamente** los valores originales |
| `HONEYPOT_ID` | Conservar el UUID existente; no crear otro sensor lógico |
| `INGEST_API_KEY` | Conservar privada; no hace falta ningún emisor para arrancar |
| `AUTH_PUBLIC_URL`, `AUTH_ALLOWED_ORIGINS` | URL/orígenes locales correspondientes a `127.0.0.1:5173` y, si ya está permitido, localhost |
| `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL`, `LLM_API_KEY` | Recuperar la configuración DeepSeek original; ninguna prueba de migración la consume |
| `MAIL_*`, `SMTP_*`, `ADMIN_EMAIL`, `SUPPORT_EMAIL` | Recuperar la configuración existente; no se envía correo de prueba. El buzón de archivos es opcional en desarrollo |
| `RAG_MODEL_DIRECTORY` | Preferir valor omitido para `.local/rag/models/minilm`; corregir si contiene una ruta antigua |
| `PG_BIN_DIRECTORY` | Opcional si los clientes PostgreSQL 18 están fuera de PATH/ruta estándar |

No ejecutar `scripts.configure_auth` sobre esta recuperación: regeneraría las claves.
No reaprobar registros ni restablecer MFA para trasladar cuentas. Sincronizar la hora
de Windows para que TOTP siga funcionando. Los usuarios deberán iniciar sesión en el
navegador nuevo; no es necesario transferir cookies del navegador.

## 6. PostgreSQL 18 y pgvector en Windows

Instalar PostgreSQL 18 desde el distribuidor oficial, conservando la contraseña del rol
SQL solo en el entorno privado. El paquete Python `pgvector` no instala la extensión
servidor. Para compilarla, seguir la [guía oficial Windows](https://github.com/pgvector/pgvector#windows):
tener soporte C++ de Visual Studio y abrir su consola **x64 Native Tools** elevada.
Ejemplo para la versión que usamos, ejecutado únicamente si falta en la nueva PC:

```bat
set "PGROOT=C:\Program Files\PostgreSQL\18"
cd /d "%TEMP%"
git clone --branch v0.8.7 https://github.com/pgvector/pgvector.git pgvector-tacticlens-087
cd pgvector-tacticlens-087
nmake /F Makefile.win
nmake /F Makefile.win install
```

Esto instala binarios de extensión, no recrea el directorio de datos. No hay que
copiar DLLs de otra versión mayor de PostgreSQL. Si existe pgvector compatible,
no recompilarlo. El dump contiene la definición de la extensión y la restauración
la habilita al reconstruir el destino.

`python -m scripts.portability prerequisites` consulta `pg_available_extensions`
en `postgres`, sin DDL. Después de restaurar, `check --model` comprueba extensión
habilitada, operador coseno, dimensiones y carga CPU. Un error de extensión bloquea
la comprobación; no se degrada silenciosamente a otra base o buscador.

## 7. Restauración segura

El comando de ARRANQUE RÁPIDO comprueba SHA-256, rechaza `postgres`/`template0`/`template1`
y cualquier destino con objetos. Crea el destino si no existe y ejecuta el equivalente a:

```text
pg_restore --no-owner --no-privileges --exit-on-error --single-transaction --dbname=DESTINO respaldo.backup
```

La contraseña se pasa solo por el entorno privado del proceso, no por argumentos ni logs.
El propietario pasa al rol local que restaura; los roles **de aplicación** están en las
tablas y se conservan. `pg_dump` no es un respaldo de roles SQL globales del clúster:
el rol local PostgreSQL se instala/configura aparte. Para desarrollo, usar un rol con
permisos suficientes para crear la base y la extensión, o preparar el destino vacío
con un administrador. No restaurar sobre la base original de esta PC.

La verificación independiente se puede repetir sin escribir datos:

```powershell
.\.venv\Scripts\python.exe -m scripts.portability verify `
  --manifest .local\recibido\database\manifest.json --database tactic-lens-db
```

**No ejecutar `honeypot_schema.sql`, seeds o migraciones automáticamente después de
restaurar.** `check` comprueba el historial y checksums: están 001–007 (incluidos los
dos 007 existentes) y 009. **008_limpieza_dominios.sql sigue excluida y sin ejecutarse**.
Ante cambios futuros del código, respaldar y revisar las migraciones pendientes antes
de decidir aplicar alguna.

## 8. Catálogo, embeddings y prueba sin créditos

El dump ya incluye catálogo, relaciones, vectores HNSW/GIN y registro del modelo. No
volver a importar ni regenerar si la comprobación encuentra los 706 vectores vigentes.
La caché privada contiene el modelo oficial MiniLM ONNX, sus archivos de tokenizador,
manifest y SHA-256 fijados en `backend/rag/embeddings.py`.

Si falta el modelo, `-PrepararModelo` descarga desde la revisión oficial fijada y verifica
sus hashes. Esto no toca PostgreSQL. La regeneración es una acción aparte para cuando
el modelo o catálogo cambien realmente, usando `scripts.embed_mitre`; no es parte del
arranque. Consultar `IMPLEMENTACION_RAG_MITRE.md` para versión/licencia/dimensiones.

```powershell
.\.venv\Scripts\python.exe -m scripts.portability check --model
.\.venv\Scripts\python.exe -m scripts.evaluate_rag
```

El evaluador usa casos sintéticos en memoria sin insertarlos en la base y no llama al LLM.
En React, abrir una sesión histórica y pulsar **Consultar candidatos** también es local.
`/mitre` muestra mapeos guardados y sus estados; `/api/mitre/catalogo` muestra metadatos
del catálogo. El análisis DeepSeek es un botón manual diferente y puede consumir créditos:
no usarlo como comprobación de instalación sin autorización.

## 9. Arranque, verificación y parada

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Iniciar-TacticLens.ps1 -NoAbrirNavegador
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Iniciar-TacticLens.ps1 -SoloComprobar
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Verificar-TacticLens.ps1
```

El lanzador valida la base/modelo, inicia backend y frontend ocultos en loopback, espera
salud y guarda solo PIDs/fechas de procesos y logs en `.local/run-local`. Repetirlo reutiliza
procesos compatibles. Rechaza un backend LAN o puertos ocupados por otra aplicación,
sin matarlos ni cambiar firewall. El proxy de Vite apunta a `127.0.0.1:8000` incluso si
la configuración privada de frontend conserva una IP vieja.
El auxiliar `start_local_process.py` desacopla los procesos sin consola para que el host
externo de Windows PowerShell 5.1 devuelva el control al terminar el script de arranque.

`Verificar-TacticLens.ps1` comprueba PostgreSQL, pgvector, historial de migraciones,
catálogo, embeddings, descifrado MFA, carga del modelo, históricos, búsqueda híbrida,
salud FastAPI, página React y proxy. Comprueba que siete rutas privadas rechacen una
sesión ausente y que el WebSocket real rechace la conexión no autenticada. Solo usa
lecturas y no crea sesiones ni actualiza actividad. Informa la presencia de configuración
DeepSeek sin imprimir la clave ni consultar su API. La **lectura autenticada y el socket
autenticado** se verificaron en tests aislados con el flujo MFA existente; el usuario
debe comprobar visualmente su sesión real en el navegador de la segunda PC.

No hay un servidor RAG adicional: el modelo ONNX se carga dentro de FastAPI. El WebSocket
local continúa con heartbeat aunque no lleguen eventos de Cowrie; las cifras históricas
no desaparecen por falta de un sensor. Una indicación de recolector sin actividad es
esperable y no equivale a fallo de la base.

Después de editar `.env`, detener y volver a iniciar para cargar la configuración:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Iniciar-TacticLens.ps1 -Detener
```

Solo detiene procesos cuya identidad/fecha coinciden con los iniciados por este lanzador,
incluidos sus hijos. No detiene PostgreSQL ni procesos ajenos. Los procesos previos
iniciados manualmente se cierran desde su propia terminal.

## 10. Pruebas y resultados

Ejecutar pruebas con escrituras sobre **otra restauración aislada**, por ejemplo
`tacticlens_pruebas`, para mantener intacta la base de trabajo:

```powershell
.\.venv\Scripts\python.exe -m scripts.portability restore `
  --archive .local\recibido\database\TacticLens_Completo.backup `
  --manifest .local\recibido\database\manifest.json --database tacticlens_pruebas
$env:DATABASE_NAME='tacticlens_pruebas'
.\.venv\Scripts\python.exe -m scripts.test_offline
cd frontend
npm.cmd test
npm.cmd run build
cd ..
```

Cerrar esa terminal después de las pruebas para no conservar el override de la base.
Los tests usan rollback, mocks y esquemas de prueba. No se envían correos ni se consume
DeepSeek. La suite necesita los históricos restaurados, modelo local y caché STIX. Si
falta el bundle STIX del paquete privado, descargarlo **sin importar de nuevo la base**:

```powershell
.\.venv\Scripts\python.exe -c "from backend.rag.catalog import download; download('.local/rag/enterprise-attack-20.1.json')"
```

Resultados ejecutados en esta PC:

| Comprobación | Resultado real |
|---|---|
| Suite Python completa sobre la restauración aislada | **228 pruebas aprobadas**, 47,673 s; SMTP/DeepSeek reales bloqueados |
| Frontend | **20 pruebas aprobadas**, 0 fallos; `npm run build` correcto |
| PowerShell | **9 comprobaciones** de firewall con mocks, sin tocar reglas; preparación, arranque, verificador y parada ejecutados con PowerShell 5.1 |
| Instalación reproducible | Lock Python resuelto desde cero con `pip --dry-run --ignore-installed`; sin reinstalar este entorno |
| Arranque local | Backend/React en loopback; repetición conserva PIDs; parada selectiva correcta |
| Históricos y MFA | Consultas autenticadas de sesiones/eventos, IoCs, administración, catálogo, análisis y candidatos; socket autenticado sin eventos nuevos |
| Restauración | 33 tablas y restricciones equivalentes; destino poblado rechazado; original sin cambios |
| Transferencia | Cifrado, autenticidad, hashes, recuperación y segunda ejecución idempotente comprobados |
| Recuperación RAG local | 20 casos sintéticos de desarrollo; Recall@5 = 0,9412; @10 y @20 = 1,0 en 17 casos positivos |

Una ejecución previa detectó una carrera de cancelación al cerrar simultáneamente tres
contextos WebSocket de TestClient. La prueba ahora completa el cierre y espera la
liberación antes de destruir los contextos; **no se cambió el WebSocket de producción**.
La suite completa posterior pasó. La compilación conserva advertencias no bloqueantes
de React Router y bundle de aproximadamente 753 kB.

Los casos RAG no son un conjunto independiente ni demuestran una mejora estadística
de DeepSeek. No se gastaron créditos ni se enviaron correos reales. No se instaló en una
segunda PC física: quedan allí la instalación PostgreSQL/pgvector, configuración del rol
SQL, restauración y comprobación visual con el usuario/MFA originales.

## 11. Rutas, IP y errores frecuentes

| Situación | Acción |
|---|---|
| Falta pgvector | Instalar extensión para PostgreSQL 18; `pip install pgvector` no basta |
| Credenciales SQL distintas | Adaptar `DATABASE_*` localmente; no cambiar claves MFA para arreglar PostgreSQL |
| MFA no puede descifrarse | Recuperar `AUTH_TOTP_KEYS` original; no regenerar ni desactivar MFA |
| TOTP rechazado | Revisar hora del sistema y usar el código actual; no omitir el factor |
| Puerto 8000/5173 ocupado | Cerrar la aplicación propietaria desde su terminal; no matar procesos arbitrarios |
| Backend de demo activo | Detener su terminal y usar el lanzador local; no cambiar reglas de firewall |
| Modelo no encontrado | Recuperar `.local/rag/models/minilm` o preparar modelo oficial; revisar ruta privada absoluta |
| Conflicto al recuperar `.env` | Conservar el archivo privado y revisar diferencias localmente; el recuperador no lo sobrescribe |
| Destino de restauración no vacío | Elegir otra base vacía; el script no usa `--clean` ni borra datos |
| Migration checksum distinto | Revisar código/historial antes de ejecutar SQL; nunca ejecutar 008 para resolverlo |
| PowerShell bloquea scripts | Usar `-ExecutionPolicy Bypass` solo en el proceso del comando mostrado; no cambiar política global |
| Falta Internet | Históricos y RAG funcionan con caché completa; instalación inicial, DeepSeek y SMTP pueden requerir Internet |

Los módulos de aplicación usan rutas relativas a la raíz o `$PSScriptRoot`. Las referencias
a IPs `192.168.*` de tests son fixtures; las de `scripts/windows/Configurar-*`,
`scripts/medir_monitoreo.py` y scripts Ubuntu pertenecen a la demostración entre laptops.
Ese último auxiliar conserva una ruta convencional del SSH de Git for Windows. No se
ejecuta al preparar/iniciar localmente. Las rutas `/opt`, `/etc` y `/home/cowrie` pertenecen
al despliegue Ubuntu conservado. Las guías anteriores de VirtualBox/IPs antiguas son
históricas y no describen este arranque local.

## 12. Reactivar Cowrie más adelante

Cuando se solicite esa etapa: identificar las IP actuales, revisar la única clave de
ingesta y el sensor lógico, arrancar el modo demo HTTP existente y ajustar de forma
restringida firewall/exportador, manteniendo SQLite, inotify y deduplicación. Seguir
`TIEMPO_REAL_WEBSOCKET.md` y `DEMO_LAPTOPS.md`, verificando primero su contexto de red.
En esta migración **no se accedió por SSH, no se ejecutó el exportador real ni se cambiaron
UFW/Windows Firewall, DHCP o túneles**. Las pruebas de scripts usaron mocks y carpetas
temporales. Esas funcionalidades permanecen en el repositorio para después.

Para continuar IoCs y salvaguardas, ver
`CONTINUIDAD_DESARROLLO_IOC_SALVAGUARDAS.md`: el documento distingue lo implementado
de las recomendaciones/relaciones que aún faltan desarrollar.
