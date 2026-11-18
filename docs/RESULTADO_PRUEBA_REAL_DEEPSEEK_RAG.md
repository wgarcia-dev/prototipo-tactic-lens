# Resultado de la primera llamada real DeepSeek + RAG MITRE

Fecha: **17 de noviembre de 2026**, America/Guayaquil (UTC−05:00).

## Conclusión

La ejecución autorizada se completó y persistió **un análisis nuevo con tres propuestas
MITRE**, todas **pendientes de revisión** y con grado **intento**. La revisión de sus
eventos originales encuentra asociaciones comportamentales razonables para T1033,
T1083 y T1059.004. Eso no demuestra intención maliciosa, obtención de información ni
ejecución en el Ubuntu anfitrión.

No basta con el HTTP 200: se contrastaron respuesta original, mapeos guardados,
definiciones oficiales, tácticas y evidencia de Cowrie. Hay matices narrativos que deben
corregirse editorialmente en una revisión humana; se describen más abajo sin alterar
el resultado guardado. **Esta prueba individual no demuestra una mejora estadística
frente a DeepSeek sin RAG.**

## Identificación y controles de la ejecución

| Campo | Valor comprobado |
|---|---|
| Sesión | `b100f403-1495-486b-88ee-26f9357681ab` |
| Sesión Cowrie | `69ab20a1719e` |
| Análisis nuevo | `c8c93065-9adf-4174-920e-9f1012ec39b5` |
| Análisis histórico conservado de la sesión | `7583fc57-cf87-45e6-b439-43ff95d7ffb8` |
| Proveedor y modelo solicitado/reportado | DeepSeek / `deepseek-v4-pro` |
| Solicitudes de generación | **1** |
| Reintentos | **0** |
| Respuesta | HTTP 200, JSON, `finish_reason=stop` |
| Parámetros | Temperatura 0, `response_format=json_object`, `thinking=disabled`, `max_tokens=8192` |
| Snapshot | 15 eventos originales, 7 entradas de comandos |
| Candidatos entregados | 22, catálogo Enterprise ATT&CK 20.1 |
| Inicio de la llamada | 00:15:35 del 17/11/2026, America/Guayaquil; 05:15:35 UTC |
| Duración del POST HTTPS | 20,297 s |
| Duración registrada por el adaptador LLM | 20,352 s |
| Duración inicio/fin de `analisis_llm` | 20,679816 s |

Se revalidaron antes del envío el sensor, los 15 eventos, hash del snapshot, hash exacto
del payload, parámetros y ausencia de secretos conocidos. Las comprobaciones posteriores
confirmaron las mismas huellas:

```text
Snapshot eventos: 25688012970ae153300482a9431e529beae5095958403a68f608642d574f4acd
Payload enviado:   a52762f6bb71a6251041ba0b5bf9bfa9a6f4cda5d6503da054de21637026ab55
Catálogo 20.1:     539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5
```

La generación se solicitó una sola vez desde la interfaz autenticada con MFA existente.
Se instrumentó temporalmente el **mismo backend**: un bloqueo de creación exclusiva
permitía únicamente el body aprobado, usaba transporte con `retries=0` y no seguía
redirecciones. La respuesta original se capturó en `.local/` antes de la validación.
Después se retiró la instrumentación y se dejó activo el arranque normal de FastAPI,
con las mismas interfaces, clave de ingesta y autenticación. No se generó otra respuesta.

## Uso real y costo calculado

| Contador devuelto por DeepSeek | Tokens |
|---|---:|
| Entrada total | **18.794** |
| Entrada con acierto de caché | 1.152 |
| Entrada sin caché | 17.642 |
| Salida | **1.803** |
| Total | **20.597** |

La llamada ocurrió a las 05:15 UTC, fuera de los intervalos pico publicados. Cálculo
con los tokens reales y las [tarifas oficiales](https://api-docs.deepseek.com/quick_start/pricing/)
de `deepseek-v4-pro` consultadas para esta prueba:

| Componente | USD / millón de tokens, off-peak | Costo USD |
|---|---:|---:|
| Entrada con caché | 0,022 | 0,000025344 |
| Entrada sin caché | 0,66 | 0,011643720 |
| Salida | 1,98 | 0,003569940 |
| **Total calculado** | | **0,015239004** |

Es decir, aproximadamente **US$0,01524**, unos **1,52 centavos de dólar**. Es el costo
calculado del consumo real con la tarifa publicada, **no un importe contrastado contra
una factura o un movimiento de saldo**. No se consultaron datos financieros de la cuenta.
La estimación previa era conservadora y usaba tarifas pico; no se confunde esa estimación
con este uso medido.

## Evidencia original de Cowrie

Todos los eventos pertenecen a la sesión autorizada. Las horas siguientes son del
**12 de noviembre de 2026**, America/Guayaquil, y conservan precisión de milisegundos
para facilitar su revisión. El intervalo exacto observado es **2,908546 s**.
No se reproducen credenciales del login.

| Evento | Hora aproximada | Tipo | Evidencia relevante |
|---:|---|---|---|
| 533 | 09:26:14.777 | `cowrie.session.connect` | Conexión SSH al honeypot |
| 755 | 09:26:14.794 | `cowrie.client.version` | Identificación de cliente SSH |
| 1564 | 09:26:14.799 | `cowrie.client.kex` | Metadatos de negociación SSH |
| 682 | 09:26:14.854 | `cowrie.login.success` | Acceso aceptado por Cowrie; credenciales ocultas |
| 715 | 09:26:15.062 | `cowrie.client.size` | Dimensiones de terminal |
| 617 | 09:26:15.070 | `cowrie.session.params` | Parámetros de la sesión |
| 786 | 09:26:15.435 | `cowrie.command.input` | `echo TLAB-20261112T142316Z ESCENARIO_SESION NUM_48` |
| 1446 | 09:26:15.711 | `cowrie.command.input` | `whoami` |
| 700 | 09:26:16.040 | `cowrie.command.input` | `pwd` |
| 1409 | 09:26:16.268 | `cowrie.command.input` | `ls` |
| 593 | 09:26:16.669 | `cowrie.command.input` | `echo TACTICLENS_ESCENARIO_LAB` |
| 469 | 09:26:16.861 | `cowrie.command.input` | `id` |
| 576 | 09:26:17.271 | `cowrie.command.input` | `exit` |
| 458 | 09:26:17.279 | `cowrie.log.closed` | Cierre del registro de interacción |
| 704 | 09:26:17.685 | `cowrie.session.closed` | Cierre de sesión |

No hay eventos de salida de comandos, transferencias, modificaciones o persistencia
en este snapshot. Su ausencia limita el análisis; no demuestra que esas acciones nunca
ocurrieran fuera de la captura. Las órdenes son compatibles también con actividad de
laboratorio o administración normal, no solo con reconocimiento adversario.

## Revisión de cada técnica propuesta

Se verificó en PostgreSQL que las tres técnicas están vigentes, que sus relaciones
técnica–táctica existen en el catálogo 20.1 y que todos sus IDs citados corresponden a
esta sesión. Las justificaciones siguientes son las devueltas por DeepSeek, sin editarlas.

### T1033 — System Owner/User Discovery

- Táctica: **TA0007, Discovery**. Versión del objeto: **1.6**.
- Eventos: **1446 (`whoami`) y 469 (`id`)**.
- Justificación del modelo: «Los comandos whoami e id intentan identificar al usuario
  actual, consistente con descubrimiento de propietario/usuario.»
- Confianza declarada por el modelo: 0,6, sin calibración probabilística.
- Estado guardado: **pendiente**; grado: **intento**.
- Mapeo: `bb11be87-69a0-46f1-834b-31be37547532`.

**Evaluación:** asociación específica y razonable. `whoami` consulta la identidad del
usuario e `id` solicita UID/GID/grupos. Es más preciso describir ese comportamiento como
descubrimiento de usuario que como identificación del sistema operativo. Sin salida no
se demuestra qué información recibió el cliente. Tampoco se enumeraron todas las cuentas
ni se demostró compromiso de cuentas reales. No se confirma el mapeo administrativamente.

### T1083 — File and Directory Discovery

- Táctica: **TA0007, Discovery**. Versión del objeto: **1.7**.
- Eventos: **700 (`pwd`) y 1409 (`ls`)**.
- Justificación del modelo: «Los comandos pwd y ls buscan enumerar directorios y
  archivos, típico de descubrimiento de archivos y directorios.»
- Confianza declarada: 0,6, sin calibración probabilística.
- Estado guardado: **pendiente**; grado: **intento**.
- Mapeo: `280cadd5-4497-40c8-8cd8-4f39b7726933`.

**Evaluación:** razonable en conjunto, sustentada principalmente por **`ls`**, que solicita
un listado. Hay una imprecisión en la justificación: **`pwd` no enumera archivos**; consulta
el directorio actual y aporta contexto. `pwd` por sí solo no bastaría para sostener una
enumeración de archivos. No hay salida que confirme el listado ni acceso a archivos reales.
Este matiz se documenta para revisión humana sin reescribir el mapeo almacenado.

### T1059.004 — Unix Shell

- Táctica: **TA0002, Execution**. Versión del objeto: **1.4**.
- Eventos: **1446, 700, 1409 y 469** (`whoami`, `pwd`, `ls`, `id`).
- Justificación del modelo: «Los eventos registran comandos enviados a la shell Unix
  emulada; la ejecución real no está demostrada.»
- Confianza declarada: 0,7, sin calibración probabilística.
- Estado guardado: **pendiente**; grado: **intento**.
- Mapeo: `c2ef20d6-8f1b-4161-bd1c-1afe5d866cf8`.

**Evaluación:** coherente como uso observado/intento de intérprete Unix en la shell
emulada. El nombre de la táctica Execution no convierte la observación en ejecución
confirmada en Ubuntu real. Las técnicas de descubrimiento describen el propósito de las
órdenes; T1059.004 describe el mecanismo. Esa combinación no es un duplicado de mapeo,
aunque comparte eventos. No se observaron scripts, malware o un intérprete en el anfitrión.

## Propuestas rechazadas y candidatos no seleccionados

- Propuestas originales de DeepSeek: **3**.
- Propuestas persistidas por el backend: **3**.
- Propuestas rechazadas por el validador en esta ejecución: **0** (`mapeos_descartados=[]`).
- Duplicados de propuesta o mapeo: **0**.
- IoCs propuestos por el LLM: **0**. Esto no elimina los observables históricos del sistema.

De los 22 candidatos recuperados, **19 no fueron seleccionados por el modelo**.
**No se presentan como rechazos del validador**: DeepSeek no dio una razón individual
para omitirlos. La última columna es esta revisión de evidencia, no una explicación
atribuida al modelo.

| Candidato no elegido | Revisión de evidencia disponible |
|---|---|
| T1059 — Command and Scripting Interpreter | El hijo T1059.004 resulta más específico; no hace falta duplicar padre/hijo para las mismas órdenes |
| T1564.002 — Hidden Users | No se observan creación u ocultación de usuarios |
| T1564.001 — Hidden Files and Directories | No hay órdenes que oculten archivos o directorios |
| T1059.003 — Windows Command Shell | No hay shell ni órdenes Windows observadas |
| T1546.004 — Unix Shell Configuration Modification | No se observan cambios en configuración de shell |
| T1098.004 — SSH Authorized Keys | No se observa modificación de `authorized_keys` |
| T1564.005 — Hidden File System | No se observan preparación u ocultación de sistemas de archivos |
| T1680 — Local Storage Discovery | No hay enumeración de discos o volúmenes; `pwd` no la demuestra |
| T1082 — System Information Discovery | No hay consultas de SO/hardware como `uname`; `id` describe identidad de usuario, no versión de SO |
| T1049 — System Network Connections Discovery | No se observan `ss`, `netstat` ni consultas de conexiones |
| T1556.007 — Hybrid Identity | No hay evidencia de infraestructura híbrida o modificación de autenticación |
| T1087 — Account Discovery | `whoami`/`id` consultan al usuario actual; no se observa un listado de cuentas |
| T1222.002 — Linux and Mac Permissions | No se observan cambios de permisos o propietarios |
| T1222 — File and Directory Permissions Modification | No hay modificación de permisos; consultar directorios es otra conducta |
| T1547.015 — Login Items | No hay configuración de inicio de sesión macOS |
| T1003.008 — /etc/passwd and /etc/shadow | No hay lectura o extracción de esos archivos |
| T1039 — Data from Network Shared Drive | No se observan recursos compartidos de red ni recolección desde ellos |
| T1070.003 — Clear Command History | No hay borrado de historial; `exit` no equivale a limpiarlo |
| T1690 — Prevent Command History Logging | No se observan cambios para impedir el registro del historial |

T1105 no fue propuesto ni figura entre los 22 candidatos de este snapshot. No apareció
la asociación incorrecta `pwd → T1105`. Tampoco se propuso T1078 por el simple login
aceptado en Cowrie. Esta observación no sustituye las pruebas negativas automatizadas:
en este ensayo el validador no tuvo que rechazar una propuesta errónea.

## Calidad del resumen y limitaciones detectadas

**Aspectos sustentados:** el modelo conservó recuentos (15 eventos, 7 comandos), duración,
orden general y citas. Diferenció los intentos de sus resultados no confirmados, reconoció
la emulación y contempló la alternativa de un ejercicio de laboratorio. No inventó técnicas
fuera de catálogo ni generó IoCs sin evidencia.

**Aspectos que requieren criterio humano:**

1. El resumen llama a las siete órdenes “comandos de reconocimiento”; `echo` y `exit`
   son marcadores/control de sesión y no son por sí mismos descubrimiento. Los cuatro
   comandos citados en la acción sí justifican la reconstrucción principal.
2. La frase sobre posibles “etiquetas de campaña” es especulativa. Los marcadores de
   laboratorio no sustentan una atribución a campaña. La hipótesis de automatización
   por Paramiko también sigue siendo una inferencia, no prueba de un ataque automatizado.
3. “Bajo riesgo” no proviene de una política de riesgo calibrada. Debe limitarse a describir
   el alcance observado en esta captura, sin clasificar el riesgo real de la organización.
4. La limitación que sugiere que redactar credenciales impide analizar cuentas comprometidas
   puede inducir a error: incluso con esos datos, una autenticación aceptada en un honeypot
   no acredita una cuenta real comprometida. La redacción es una protección necesaria.
5. Debe preferirse “no demuestra ejecución en el anfitrión” frente a afirmaciones absolutas
   de no ejecución. No se observaron salidas ni telemetría del sistema anfitrión en el snapshot.
6. El buscador entregó bastante ruido (Windows, identidad híbrida, persistencia, etc.). El
   modelo no convirtió ese ruido en mapeos, lo cual es favorable en este caso; sigue siendo
   una oportunidad de evaluación de recuperación y costo antes de ampliar funcionalidades.

Estas observaciones **no modificaron el informe original, las propuestas ni sus estados**.
Son anotaciones de revisión. No se activó ningún bloqueo de IP recomendado por el modelo.

## Persistencia y conservación de históricos

Se ejecutó `python -m scripts.verify_deepseek_trial` después de la respuesta. Resultado:
**`integridad_correcta=true`**, un análisis nuevo, misma solicitud/modelo/catálogo, snapshot
intacto, tres mapeos pendientes y ninguna pareja `(id_accion,id_vinculo)` duplicada.

| Tabla | Antes | Después | Filas anteriores faltantes/modificadas |
|---|---:|---:|---:|
| sesion | 125 | 125 | 0 |
| evento | 1493 | 1493 | 0 |
| analisis_llm | 5 | 6 | 0 |
| accion_identificada | 7 | 8 | 0 |
| accion_evento | 12 | 16 | 0 |
| mapeo_mitre | 7 | 10 | 0 |

El análisis anterior de 10 eventos sigue disponible y sin cambios. No se ejecutó otra
generación para “probar” reutilización. La ausencia de duplicados se verificó con consultas,
hashes y los registros de la única solicitud, sin consumir una segunda llamada.

## Evidencias de ejecución y reproducción de la revisión

Archivos privados, ignorados por Git, en `.local/rag/ensayo-controlado/`:

- `preflight.json`, `payload.json`: snapshot y body aprobado sin credenciales conocidas.
- `solicitud-unica.intentada.json`: bloqueo de autorización consumida; no borrarlo para repetir.
- `transporte-real.json`: contador 1, reintentos 0, duración, HTTP y `usage`.
- `respuesta-proveedor.json`: respuesta original antes de validar.
- `resultado-revisable.json`: resultado persistido, justificaciones, evidencia y estados.
- `evidencias-revision.json`: evidencia seleccionada sin credenciales y definiciones oficiales.
- `costo-real.json`, `revision-tecnica.json`, `verificacion.json`: cálculo y comprobaciones.
- `resultado-real.jpg`: comprobación visual del análisis RAG en React.

Revisar nuevamente no genera texto ni consume créditos:

```powershell
.\.venv\Scripts\python.exe -m scripts.verify_deepseek_trial
```

No se añadieron migraciones ni se modificaron catálogo, autenticación, MFA, ingesta o
WebSockets para esta prueba. Se preservó la rama integrada y no hubo push.

## Alcance de la conclusión de calidad

Las tres asociaciones pasan las comprobaciones formales y son razonables como intentos
al revisar esta sesión. No se calcula una “precisión del 100%”: esta es una sesión de
laboratorio sin etiquetado independiente y la revisión se hizo después de ver la respuesta.
La sesión contiene órdenes sencillas y no somete el pipeline a transferencias, ataques
de autenticación repetidos, comandos ambiguos o prompt injection adversarial reales.

El análisis histórico anterior usó 10 eventos y esta llamada 15. Aunque ahora no aparezca
la propuesta histórica T1082, esa diferencia no puede atribuirse causalmente a RAG.
La comparación justa necesita ambos métodos sobre los mismos snapshots etiquetados,
con protocolo común y autorización separada para las llamadas adicionales, como se
preparó en `docs/PRUEBA_CONTROLADA_DEEPSEEK_RAG.md`.
