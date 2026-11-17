# Monitoreo por eventos y WebSocket

Estado verificado el **16 de noviembre de 2026**, America/Guayaquil.

## Flujo vigente

```text
Cowrie → cowrie.json → notificación inotify de Linux
       → captura existente + cursor/identidad en SQLite
       → POST /api/ingesta/eventos con X-API-Key
       → transacción PostgreSQL y recibos existentes
       → aviso WebSocket autenticado → React consulta la vista afectada
```

Se eligió **inotify + HTTP inmediato** como alternativa al WebSocket de ingestión
permitida en el requisito. Inotify bloquea esperando notificaciones del kernel,
sin sondear el archivo cada dos segundos. Reutilizar HTTP evita sustituir el
protocolo de recibos ya probado o instalar un cliente WebSocket en Ubuntu. El
canal persistente **FastAPI → React sí es WebSocket real**. No se afirma que
ambos tramos sean WebSocket.

El servicio permanente utiliza las funciones instaladas `ingest()` y
`deliver_pending()`. Estas siguen guardando evento/cursor de forma durable,
preservando el identificador por ocurrencia, validando cada recibo y marcando
enviado solo después de la confirmación PostgreSQL. Se conservan JSON inválidos
para revisión y recuperación de rotaciones. El vigilante se abre antes del
primer escaneo para evitar una carrera entre lectura y suscripción; un desborde
de inotify fuerza una nueva lectura desde los cursores duraderos.

## Archivos principales

| Área | Archivos |
| --- | --- |
| Servidor | `backend/realtime.py`, integración en `backend/api.py`, límite LAN en `backend/ingest_transport.py` |
| Captura y estado | `collector/event_watch.py`, `collector/event_status.py`; reutilizan el exportador y emisor SQLite existentes |
| Operación | `scripts/ubuntu/activar_eventos.py`, `scripts/windows/Activar-TiempoReal.ps1`, auxiliares Ubuntu de estado/verificación/sincronización |
| Navegador | `frontend/src/monitoring/Realtime.tsx`, `socket.ts`, `invalidation.ts`, integración en `main.tsx` y proxy en `vite.config.ts` |
| Compatibilidad | `scripts/demo_prepare.py`, argumentos del lanzador PowerShell 5.1 y límites en `scripts/serve_demo.py` |
| Pruebas nuevas | `tests/test_realtime.py`, `test_event_watch.py`, `test_event_activation.py`, pruebas frontend `socket.test.mjs` e `invalidation.test.mjs` |

## Servicios y exclusión

- Cowrie conserva `cowrie-tacticlens.service`, su SSH simulado y sus archivos.
- Se reutiliza **`tacticlens-exportador.service`**, con un drop-in
  `30-eventos.conf` que cambia `Type=oneshot` a `Type=simple` y ejecuta
  `/opt/tacticlens-cowrie/event_watch.py`.
- `tacticlens-exportador.timer` queda deshabilitado. No funciona en paralelo.
- El mismo `sender_lock()` exclusivo permanece tomado por el servicio; un
  segundo emisor manual no puede escribir/enviar simultáneamente.
- `Restart=on-failure` recupera el proceso. Los timeouts para reintentos o el
  heartbeat de 15 s **no son sondeos del archivo**. Los cambios de Cowrie
  despiertan inmediatamente el bucle mediante inotify.
- Un HTTP lento puede demorar la siguiente captura; el archivo y los avisos del
  kernel permanecen pendientes. No se garantiza latencia máxima durante cortes.
- `event_status.py` consulta SQLite en modo de solo lectura sin tomar el bloqueo
  del emisor. Los auxiliares existentes de estado/verificación/sincronización
  reconocen el modo permanente y no reactivan el timer ni ejecutan otro emisor.

La activación respalda configuración, cola con la API de backup SQLite,
drop-in/herramientas existentes, verifica las huellas del exportador revisado y
comprueba la clave contra la API sin guardar un evento inválido. No sustituye
el código original de captura/entrega ni ejecuta migraciones PostgreSQL.

## WebSocket y seguridad

Endpoint: **`/api/monitor/ws`**, subprotocolo `tacticlens.monitor.v1`.

- Autentica con la cookie HttpOnly existente y exige etapa `completa`, cuenta
  habilitada, correo/autorización y MFA configurado. No hay tokens nuevos en
  localStorage, parámetros de URL ni excepciones para omitir MFA.
- Reutiliza los orígenes exactos de `AUTH_ALLOWED_ORIGINS`; rechaza parámetros
  en la URL y exige el subprotocolo. En producción exige WSS.
- La interfaz LAN de demostración continúa reservada a salud/ingestión desde
  la IP de Ubuntu. No expone el WebSocket de usuarios a la LAN. El navegador
  lo alcanza a través del proxy local Vite, con `ws:true`.
- Revalida la sesión antes de cada aviso y cada heartbeat; una revocación o
  suspensión impide recibir nuevos avisos. Una conexión ociosa se cierra en el
  siguiente control, como máximo aproximadamente 15 s después de la revocación.
- Máximo 64 conexiones por proceso y 3 por usuario; límite de aperturas por
  cuenta/IP con los mecanismos existentes.
- Ping de aplicación cada 15 s, respuesta `pong`, cierre por inactividad >40 s,
  límite de mensajes, timeout de envío de 5 s y limpieza de tareas/suscriptores.
  El lanzador local configura además límites de tramas y cola en Uvicorn.
- Cada cliente dispone de una cola de **un aviso**: se agrupan invalidaciones
  para clientes lentos. Los eventos duraderos nunca dependen de esa cola.
- Los avisos contienen revisión, época, tiempos e IDs persistidos; no envían
  contraseñas capturadas, cuerpos originales de eventos ni claves de ingestión.
- `persist_events()` publica después de que `persist()` retorna del commit.
  Un error o un lote exclusivamente duplicado no publica una inserción nueva.

Mensajes del protocolo: `listo`, `cambio`, `ping`; el cliente solo responde `pong`.
La época cambia al reiniciar el proceso. Tras reconectar se vuelve a consultar
PostgreSQL para recuperar cualquier actualización perdida: el WebSocket es un
aviso, no el almacenamiento ni un registro de entrega durable.

## React y consultas

`RealtimeProvider` mantiene un único canal por pestaña autenticada. Reconecta con
espera exponencial y variación aleatoria, cierra al ocultar la pestaña y recupera
el estado al volver. Un watchdog detecta canales silenciosos. Una sesión revocada
activa el flujo de expiración existente.

Dashboard, sesiones y detalle hacen una carga inicial; luego cargan al recibir
invalidaciones. Los ciclos internos inactivos no producen HTTP mientras el
canal esté conectado. Hay **respaldo HTTP cada 15 s solo al desconectarse**, no
polling de monitoreo de un segundo. Las consultas se serializan y agrupan; una
invalidación recibida durante una respuesta lenta no se pierde. Los filtros y
páginas permanecen en su estado React. Los datos no se vacían en cada aviso.

Las listas IoC/MITRE conservan sus consultas anteriores de 5 s; no se cambió su
implementación en esta tarea. La salud ligera también conserva su intervalo.
Ninguna actualización invoca `POST .../analizar`: DeepSeek sigue siendo manual.

## Operación local

Actualmente: Ubuntu **192.168.0.103** y Windows **192.168.0.111**.

Desde la raíz del repositorio, en una PowerShell:

```powershell
.\scripts\windows\Iniciar-DemoHTTP.ps1 -UbuntuHost 192.168.0.103
```

En otra:

```powershell
.\scripts\windows\Iniciar-Frontend.ps1
```

Abrir `http://127.0.0.1:5173/`, iniciar sesión y completar Google Authenticator.
El dashboard indica **EN VIVO · WEBSOCKET** al recibir la confirmación del canal.
El análisis LLM se ejecuta únicamente desde sus botones existentes.

La activación **ya se realizó en Ubuntu**. No repetirla en cada arranque:
se habilitó el mismo servicio para iniciar permanentemente con systemd. Si
cambia la IP de Windows o se necesita actualizar los auxiliares, iniciar el
backend con las direcciones actuales y ejecutar:

```powershell
.\scripts\windows\Activar-TiempoReal.ps1 -UbuntuHost 192.168.0.103
```

SCP y SSH solo administran Ubuntu; las contraseñas se escriben en la terminal.
El auxiliar conserva la clave y actualiza exclusivamente la URL de ingestión
cuando cambia Windows. `-SoloComprobar` muestra los argumentos sin conectar.
No se utiliza túnel SSH. La regla de firewall sigue limitada a Ubuntu, TCP/8000,
IP/interfaz seleccionadas. El lanzador reutiliza la regla correcta sin otra UAC.

En Ubuntu:

```bash
systemctl is-active cowrie-tacticlens.service tacticlens-exportador.service
systemctl is-enabled tacticlens-exportador.timer # debe indicar disabled
sudo bash /opt/tacticlens-cowrie/scripts/estado.sh
sudo bash /opt/tacticlens-cowrie/scripts/verificar.sh
```

En modo permanente, `sincronizar.sh` verifica el servicio y consulta su estado;
no fuerza otro emisor ni borra el backoff. El CLI antiguo `exportar_eventos.py`
toma el bloqueo de emisor incluso con `--status`; utilizar ahora `estado.sh` o
`event_status.py` para una consulta concurrente.

La dependencia nueva en Windows es `websockets>=15,<17` (se instaló 16.1.1 en el
entorno existente). No se reinstalaron las demás dependencias ni se añadieron
paquetes de Ubuntu. Las variables de autenticación, correo e ingestión conservan
sus nombres y secretos; no se editó `.env`.

## Demostración física ejecutada

Comando: `echo TacticLensLive_549b91a1766f`, evento **1653**, sesión
`70a83177-eec1-4a7d-8396-a5c48daf1ed3`.

| Momento | Valor registrado, UTC |
| --- | --- |
| Windows envía el comando al SSH simulado TCP/2222 | `2026-11-17T00:00:02.198596Z` |
| Timestamp original del evento Cowrie | `2026-11-17T00:00:02.878808Z` |
| FastAPI inicia la persistencia del lote ya validado | `2026-11-17T00:00:02.713126Z` |
| API retorna de la persistencia con commit confirmado | `2026-11-17T00:00:02.722478Z` |
| React incorpora la fila del comando en el DOM | `2026-11-17T00:00:02.772Z` |

La hora local del envío fue **16/11/2026, 19:00:02 America/Guayaquil**.
Resultado: **573,4 ms envío Windows → React**, **49,5 ms confirmación API →
React**, **9,4 ms dentro de la persistencia API** en esa muestra. No se recargó
ni se navegó la página entre el envío y la captura del nuevo comando.

**Desfase detectado:** el reloj de Ubuntu sitúa su evento después del tiempo de
recepción en Windows. Por ello no es válido restar esas dos horas para afirmar
latencia de red o Cowrie → API; se requiere sincronizar/medir los relojes antes
de esa comparación. Se conservan ambos valores sin corregirlos artificialmente.
`ingresado_en` de PostgreSQL es tiempo de registro de fila/transacción, **no** un
timestamp exacto del commit; el tiempo posterior al commit es `confirmado_api`.

Segunda prueba: se detuvo únicamente el backend iniciado para la demostración,
se envió `echo TacticLensLive_01644b4e9d96` durante la interrupción y se reinició
FastAPI con la misma configuración. El evento **1665** se conservó, llegó tras
los reintentos y apareció automáticamente después de reconectar el WebSocket.
La recuperación tardó aproximadamente **20,3 s**, acorde al timeout/backoff, no
a la latencia normal. Se comprobó también la sesión en su cronología React.

Reenviar cada uno de esos eventos con el mismo origen produjo **0 inserciones y
1 duplicado**; ambos comandos aparecen una sola vez en PostgreSQL. La última
salida real de Ubuntu confirmó **1490 registros de cola, 1490 enviados, 0
pendientes, 0 en revisión y 0 errores**, después de reiniciar su servicio con
las herramientas actualizadas. PostgreSQL tenía 1493 eventos y 125 sesiones
en la verificación de estos comandos, incluidos los históricos anteriores.

Los registros técnicos de tiempos y la imagen de evidencia están en
`.local/monitoreo/`, ignorado por Git. La prueba usa una contraseña desechable
ficticia exclusivamente contra Cowrie TCP/2222; nunca credenciales SSH reales.

## Pruebas automatizadas ejecutadas

**124 casos Python distintos** aprobados en los módulos/clases seleccionados:

| Grupo | Casos |
| --- | ---: |
| `test_realtime.py` | 9 |
| `test_event_watch.py` | 3 |
| `test_event_activation.py` | 2 |
| `test_sqlite_capture.py` | 5 |
| `test_sqlite_sender.py` | 8 |
| `test_monitoring.py` | 4 |
| `test_auth.py` | 58 |
| `test_collaborative_integration.py`, excluyendo el test del migrador | 6 |
| `test_analysis.py` | 9 |
| `test_demo_http.py` | 5 |
| `test_core.py` | 7 |
| `test_ingestion.IngestionTests` | 8 |

También: **20 pruebas frontend**, compilación TypeScript/Vite, **9 comprobaciones
PowerShell del firewall**, sintaxis Bash y argumentos en PowerShell 5.1. Dos
reproducciones transaccionales adicionales documentan hallazgos MITRE, sin
modificarlo. No se ejecutó toda la batería del repositorio ni pruebas que
invocan migraciones. No hubo envíos de correo ni llamadas LLM reales iniciadas
por esta intervención. Persisten avisos previos de tamaño del bundle y una
advertencia de deprecación del cliente de pruebas HTTP.

## Límites y recuperación operativa

- El hub es de **un proceso**: corresponde al lanzador actual. Antes de usar
  varios workers o máquinas FastAPI hace falta un canal compartido de avisos.
- Escrituras externas directamente a PostgreSQL no emiten avisos. El flujo
  soportado usa `persist_events()` en la API; no hay triggers nuevos.
- El WebSocket emite invalidaciones de ingestión, no una ejecución LLM ni una
  transmisión de sus respuestas token por token.
- La prueba física cubre esta red local. No se certificó una segunda red hotspot
  en esta intervención ni todas las rotaciones/fallos de disco en el servidor.
- HTTP sin cifrar queda limitado a la demostración privada existente. Producción
  requiere HTTPS/WSS; no abrir el puerto a Internet.
- Para volver al modo periódico, un administrador debe detener el servicio,
  mover el drop-in `30-eventos.conf` a su respaldo privado, ejecutar
  `systemctl daemon-reload` y habilitar de nuevo el timer. No ejecutar ambos
  modos a la vez y no restaurar/borrar SQLite para cambiar de modalidad.
- Los respaldos privados de esta activación están bajo
  `/var/lib/tacticlens-cowrie/backups/eventos-*`; no copiarlos al repositorio,
  pues contienen configuración privada e históricos.
