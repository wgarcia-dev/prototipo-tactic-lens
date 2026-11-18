# Implementación de IoCs · etapa 1

El módulo de TacticLens registra valores observados en Cowrie, conserva el evento que respalda cada aparición y permite la revisión de relevancia por un administrador. La clasificación del alcance de una IP y el grado de evidencia describen lo que registró el sensor. El estado de revisión expresa una decisión humana.

## Hallazgos de la revisión inicial

- La ingesta ya guardaba el JSON del evento y la identidad de su aparición en la misma transacción que los observables. El catálogo real de tipos es `honeypot.tipo_ioc`. Los pares únicos en `ioc` y `observacion_ioc` ya permitían deduplicar el valor y conservar un registro por evento.
- La extracción anterior buscaba dominios e IP en texto libre y consideraba hashes ciertas cadenas hexadecimales de comandos. Admitía IPv6 en `src_ip`, pero no como argumento. Tampoco distinguía los eventos de descarga completada, descarga fallida y subida.
- El análisis LLM podía crear un IoC si el valor coincidía con una subcadena de una versión del evento preparada para el modelo. Una coincidencia podía provenir de un nombre de archivo, un fragmento de URL u otro campo sin procedencia adecuada.
- La consulta devolvía un evento representativo por valor. El administrador podía revisar en conjunto las observaciones de ese valor, aunque pertenecieran a sesiones y comportamientos distintos.

## Extracción y normalización

| Evidencia | Dato utilizado | Interpretación registrada |
| --- | --- | --- |
| Conexión | `cowrie.session.connect.src_ip` | Conexión de origen registrada. |
| Origen en otros eventos | `src_ip` registrado por Cowrie | Referencia al origen de esa sesión. |
| Host de un comando | Argumento de destino de una herramienta de red reconocida, en `cowrie.command.input.input` | Referencia a una IPv4, IPv6 o dominio. Contacto y resolución sin verificar. |
| URL en un comando | Argumento literal válido de `input` | Intento cuando una invocación directa reconocida de `curl` o `wget` utiliza esa URL. Una mención, una consulta de cabeceras o una sintaxis ambigua se registran como referencia. |
| Descarga registrada | `cowrie.session.file_download.url` | Resultado observado por Cowrie. La ejecución posterior queda por verificar. |
| Descarga fallida | `cowrie.session.file_download.failed.url` | Fallo registrado. El evento carece de evidencia de recepción del archivo. |
| Archivo en el honeypot | `shasum` de `cowrie.session.file_download` o `cowrie.session.file_upload` | SHA-256 de 64 caracteres hexadecimales informado por Cowrie. Incluye capturas de archivo sin URL, cuando se registra ese campo. |

Se usaron los códigos y campos de transferencia documentados por Cowrie. El `shasum` de un registro TTY describe otro objeto y queda fuera de la extracción de hashes de archivos. [Referencia de eventos de Cowrie](https://docs.cowrie.org/en/stable/OUTPUT.html)

- IPv4 e IPv6 se validan con `ipaddress` y se guardan en representación canónica. El alcance distingue privada, loopback, enlace local, multicast, documentación, reservada, no especificada, no enrutable y global. Se conserva una IP especial cuando aparece en el campo de origen, incluyendo evidencia del laboratorio.
- Los dominios se validan por etiquetas completas y se normalizan a minúsculas ASCII con IDNA. El contexto de argumento de red evita inferencias desde archivos, correos y texto libre. Los sufijos de prueba y los bloques de documentación se excluyen de menciones de comandos y URLs.
- Las URLs con `http`, `https`, `ftp` y `tftp` validan autoridad, dominio o IP, puerto y codificación porcentual. Se normalizan esquema y host y se conserva literalmente el resto, incluidos puerto explícito, ruta, orden y repetición de parámetros, y fragmento. El valor original se conserva en la evidencia. Se excluyen URLs con credenciales en la autoridad.
- Los hashes se normalizan a minúsculas. La procedencia viene del tipo de evento y el campo `shasum`. El sistema desconoce los bytes del archivo y no recalcula el digest. Cadenas hexadecimales en comandos y hashes fuera de los dos eventos de archivo indicados carecen de esta procedencia.

## Persistencia, revisión y API

- `ioc` retiene la clave única de tipo y valor normalizado. `observacion_ioc` retiene su UUID, revisión y clave única de IoC y evento. El campo JSONB `detalles` registra cada contexto dentro de ese evento, con campo, valor original, método, comportamiento, grado de evidencia, limitación, alcance de IP, algoritmo y posición cuando corresponda. Dos contextos en el mismo evento se muestran en la misma observación. Dos eventos o sesiones conservan observaciones distintas.
- La sesión se resuelve por la clave foránea de `evento.id_sesion`. Para detecciones nuevas, `deteccion_ioc.id_observacion` se vincula por clave foránea compuesta al UUID de observación, IoC y evento. `accion_ioc` conserva los vínculos con todas las acciones que citan la evidencia, incluso si comparten detección dentro de un análisis.
- La deduplicación de eventos conserva la identidad de ingesta existente. Un reintento con el mismo identificador de origen reutiliza el evento. Dos apariciones con identidades distintas conservan sus observaciones, incluso con contenido idéntico. La importación manual conserva su identidad por línea y número de ocurrencia de esa línea en el archivo.
- `GET /api/iocs` devuelve la primera y última fecha de evento, observaciones por evento, sesiones distintas, cobertura determinista y estado agregado de revisión. La etiqueta histórica indica ausencia de respaldo determinista en esa fila. Si hay decisiones distintas entre observaciones verificables, el estado agregado es mixto. El panel principal cuenta valores con respaldo determinista.
- `GET /api/iocs/{id_ioc}/observaciones` devuelve todas las observaciones por páginas, con JSON del evento bajo el filtrado existente de campos sensibles y las acciones asociadas. Los IDs de evento en esta ruta se serializan como texto para conservar precisión en el navegador. Las URLs observadas se muestran como texto.
- Analistas y administradores autenticados pueden consultar. Solo administradores pueden confirmar relevancia o descartar mediante `PATCH /api/inteligencia/observacion_ioc/{id_observacion}/revision`, con motivo, autor, fecha y auditoría. Una observación solo histórica se puede descartar y queda impedida de recibir una confirmación nueva. La ruta de revisión por IoC se conserva para observaciones con respaldo.

## DeepSeek + RAG MITRE

DeepSeek sigue recibiendo el contexto de RAG MITRE y una lista de referencias deterministas por cada evento muestreado. El listado suplementario incluye procedencia y comportamiento, sin reenviar los parámetros originales de URLs por ese canal. El servidor resuelve la referencia contra el JSON original del evento citado por la acción. También acepta el valor completo cuando el tipo, la normalización y el evento coinciden. Los valores inventados, fragmentos, referencias fuera de rango y propuestas de eventos ajenos a la acción se excluyen y la causa se guarda en `propuestas_ioc_descartadas`. Las asociaciones admitidas conservan la interpretación y la confianza del modelo aparte de la revisión humana.

## Migración e histórico

`010_ioc_trazabilidad.sql` añade el campo de detalles, el vínculo de detección y sus índices. Preserva los UUID y las columnas originales. El reprocesamiento deriva detalles de eventos existentes en orden estable y por lotes. Las detecciones anteriores se conservan y se muestran como históricas cuando el valor carece de respaldo con las reglas actuales. Los análisis completados, fechas y motivos de revisión, y el JSON original siguen disponibles.

```powershell
.venv/Scripts/python.exe -m scripts.migrate
.venv/Scripts/python.exe -m scripts.backfill_observables
```

El ejecutor difiere `008_limpieza_dominios.sql`. En instalaciones con alias históricos que difieran de la representación canónica, las filas originales se conservan y quedan fuera del recuento determinista cuando el extractor actual no avala su identidad.

Se aplicó la migración en PostgreSQL local tras verificarla en una copia aislada. La segunda ejecución no aplicó cambios. Dos pasadas de reprocesamiento revisaron los mismos 32 eventos y dejaron 29 observaciones trazables. Se compararon recuentos y huellas de todas las columnas originales en 12 tablas antes y después. Coincidieron las 7 sesiones, los 32 eventos con sus JSON, el IoC, las 29 observaciones, los 2 análisis y las relaciones históricas. La migración 008 sigue diferida.

## Archivos de esta etapa

| Archivos | Cambios |
| --- | --- |
| `backend/intelligence.py`, `requirements.txt` | Extracción, validación por tipo, procedencia y persistencia de observables. |
| `backend/routes.py`, `backend/api.py`, `backend/analysis_report.py` | Consultas, revisión individual, comprobación de esquema y validación de propuestas de DeepSeek. |
| `database/migrations/010_ioc_trazabilidad.sql`, `scripts/backfill_observables.py` | Migración aditiva y reprocesamiento determinista de registros existentes. |
| `frontend/src/main.tsx`, `frontend/src/analysis/iocEvidence.ts` | Pantalla de observables, detalles de evento y revisión por observación. |
| `tests/test_ioc_extraction.py`, `tests/test_core.py`, `tests/test_collaborative_integration.py`, `tests/test_analysis.py`, `tests/test_live.py` | Casos positivos, negativos y ambiguos, persistencia, permisos y análisis simulado. |
| `frontend/src/analysis/iocEvidence.test.mjs`, `frontend/package.json` | Pruebas de presentación y navegación interna incorporadas a la suite. |

## Pruebas y límites

- Pasaron las 236 pruebas de Python con `unittest` y una copia aislada de PostgreSQL en Windows. Incluyen conexiones, comandos y transferencias de prueba, varias sesiones, reimportación, preservación del histórico, permisos y propuestas LLM aceptadas y rechazadas. DeepSeek se simuló.
- Pasaron las 23 pruebas de `pnpm.cmd test` y la compilación de `pnpm.cmd run build`. Vite emitió avisos de tamaño del paquete y directivas de React Router. Con una API simulada, el navegador mostró el detalle de descargas registradas y fallidas, los controles de JSON y la sesión asociada. Se verificó la revisión de una observación y la ausencia de desbordamiento horizontal en pantalla estrecha.
- La extracción de comandos reconoce literales y formas comunes. El shell completo, las variables, las sustituciones, las opciones ambiguas y los comandos de más de 8192 caracteres limitan la cobertura. El host dentro de una URL permanece en la evidencia de la URL. Para verificar una descarga se consulta su evento de transferencia.
- El histórico local disponible consta de 32 eventos sin eventos de transferencia. La cobertura de descargas, subidas y fallos se comprueba con fixtures aislados. El trabajo se realizó en Windows, con PostgreSQL local y sin conexiones al sensor.

## Siguiente etapa

El enlace `acción → detección → observación → evento → sesión` y los mapeos MITRE existentes permiten empezar la correlación con evidencia trazable. Queda definir qué comportamientos y relaciones temporales justifican un vínculo entre observaciones y técnicas, qué evidencia mínima necesita cada vínculo y cómo evaluarlo con sesiones etiquetadas de forma independiente. La cantidad de apariciones, la procedencia IP y una revisión de relevancia son señales contextuales. Para atribuir un comportamiento o técnica hará falta evidencia propia de esa relación.
