# Continuidad de TacticLens: prototipo Sigma y pruebas controladas

**Estado al cierre de este chat: 27 de noviembre de 2026, Ecuador.**

Esta guía permite continuar el trabajo sin leer la conversación. **Sigma todavía no
está integrado en el flujo principal ni en la sección de análisis de TacticLens.**
Se construyó una prueba de concepto independiente, se validó con la muestra real
disponible y se preparó un ejecutor de escenarios para ampliar la evaluación.

El siguiente trabajo recomendado es ejecutar los escenarios permitidos contra las
instancias Cowrie del laboratorio, recoger sus eventos y ajustar las reglas con esa
evidencia. Después, integrar Sigma en modo observación y finalmente habilitar alertas.

## 1. Contexto y decisiones de este chat

TacticLens ya trabaja con Cowrie, un collector, PostgreSQL, FastAPI, React y análisis
LLM/IoCs/MITRE. El contexto previo de las instancias está en
[README_RECOLECCION_COWRIE_2026-11-26.md](README_RECOLECCION_COWRIE_2026-11-26.md).

| Modalidad | Puerto SSH del laboratorio | Interpretación |
|---|---:|---|
| Shell | 2222 | Respuestas de shell emuladas |
| Proxy | 2223 | Conexión a un invitado de laboratorio; puede ejecutar comandos reales |
| LLM | 2224 | Respuestas generadas; no demuestran ejecución real |

Se implementó lo solicitado en [NEW_PROMPT.md](NEW_PROMPT.md) dentro de
`tacticlens-sigma-lab/`. Las decisiones principales fueron:

- Usar **pySigma y su backend SQLite reales**, no un intérprete casero de condiciones YAML.
- Evaluar eventos de las tres modalidades sin depender del LLM.
- Mantener separadas detecciones, alertas, confianza e impacto verificable.
- Conservar IDs originales para la trazabilidad y evitar exportar contraseñas o comandos
  originales en las salidas del detector.
- No modificar el backend, frontend, collector, dependencias principales ni base de datos
  para construir esta PoC. El ejecutor SSH es una herramienta aparte y solo conecta cuando
  se solicita explícitamente su modo `ssh`.
- Construir un catálogo común de pruebas para las tres modalidades, en lugar de tres
  scripts divergentes.

## 2. Qué existe y dónde encontrarlo

| Ruta | Función |
|---|---|
| [tacticlens-sigma-lab/README.md](tacticlens-sigma-lab/README.md) | Documentación técnica del detector y sus limitaciones |
| [tacticlens-sigma-lab/main.py](tacticlens-sigma-lab/main.py) | Ejecutar Sigma sobre un JSON/JSONL exportado |
| [tacticlens-sigma-lab/run_exercises.py](tacticlens-sigma-lab/run_exercises.py) | **Script para planificar, reproducir o ejecutar las pruebas** |
| [tacticlens-sigma-lab/exercises/README.md](tacticlens-sigma-lab/exercises/README.md) | Guía detallada del ejecutor y comandos SSH |
| [tacticlens-sigma-lab/exercises/catalog.py](tacticlens-sigma-lab/exercises/catalog.py) | Escenarios, pasos, niveles, intención y reglas esperadas |
| [tacticlens-sigma-lab/exercises/replay.py](tacticlens-sigma-lab/exercises/replay.py) | Generación sintética y comparación de expectativas |
| [tacticlens-sigma-lab/exercises/ssh_runner.py](tacticlens-sigma-lab/exercises/ssh_runner.py) | Transporte SSH acotado y manifiestos |
| [tacticlens-sigma-lab/src/](tacticlens-sigma-lab/src/) | Normalización, compilación, almacenamiento temporal, detección, correlación, alertas y métricas |
| [tacticlens-sigma-lab/rules/](tacticlens-sigma-lab/rules/) | Reglas Sigma propias, con estado experimental |
| [tacticlens-sigma-lab/tests/](tacticlens-sigma-lab/tests/) | Pruebas automatizadas y fixtures sintéticos |
| [tacticlens-sigma-lab/requirements.lock.txt](tacticlens-sigma-lab/requirements.lock.txt) | Dependencias del entorno del detector probado |
| [tacticlens-sigma-lab/requirements-exercises.txt](tacticlens-sigma-lab/requirements-exercises.txt) | Dependencias opcionales para ejecutar SSH desde el entorno del laboratorio |
| `eventos_json_50.json` | Export real entregado por el usuario; tratarlo como información privada |
| `tacticlens-sigma-lab/data/cowrie_events.json` | Copia local idéntica de los 50 eventos, excluida de Git |
| `tacticlens-sigma-lab/output/` | Resultados locales; excluidos de Git salvo el archivo de conservación del directorio |

El recolector previo `scripts/recolectar_cowrie_una_clave.py` sigue existiendo. El
ejecutor nuevo no lo reemplaza: añade un catálogo orientado a la evaluación de Sigma.

## 3. Qué se comprobó y qué no

### Muestra real inicial

`eventos_json_50.json` sí corresponde a la muestra descrita en el prompt. La copia
local se verificó byte a byte. El análisis obtuvo:

| Medición | Resultado |
|---|---:|
| Eventos procesados | 50 |
| Eventos Shell / Proxy / LLM | 17 / 15 / 18 |
| Tipos de evento / campos comunes | 12 / 16 |
| Autenticaciones exitosas como root | 3 detecciones |
| Reconocimiento básico | 4 detecciones |
| Posible prompt injection ES/EN | 2 detecciones |
| Comando no reconocido | 1 detección |
| Total de detecciones | **10** |
| Detecciones Shell / Proxy / LLM | **4 / 2 / 4** |
| Alertas graves | **0** |
| Duplicados / registros rechazados | 0 / 0 |

También se observaron seis comandos vacíos, tres UUID distintos repetidos y descensos
de `numero_secuencia` al ordenar cronológicamente. Por eso se deduplica por `id_evento`,
se ordena por `timestamp` y se usa `instance_type` para la modalidad, no el puerto.

No hubo diferencias respecto de los totales esperados. **Cero alertas graves no
demuestra ausencia de ataques**: describe las coincidencias de estas reglas sobre
esta muestra. Un comando registrado no prueba que se haya ejecutado exitosamente.

### Pruebas sintéticas y automatizadas

- La primera etapa del detector terminó con **66 pruebas aprobadas**.
- El ejecutor añadió **25 pruebas**: la última suite completa dio **91 aprobadas**.
- El fixture pequeño de nueve eventos produjo siete detecciones y seis alertas.
- El replay ampliado de diez escenarios en tres modalidades produjo **99 eventos,
  78 detecciones y 30 alertas**. Coincidieron las expectativas de reglas y correlaciones.
- Al comparar con intención de ataque, ese replay dio 54 verdaderos positivos,
  **33 falsos positivos**, cero falsos negativos y 12 verdaderos negativos; precisión
  aproximada 0.6207 y recall 1.0, exclusivamente para ese conjunto artificial.

Los 33 positivos sobre actividad etiquetada como benigna corresponden a 27 logins root
de infraestructura, tres preparaciones de archivos ficticios y tres ejemplos de curl
citados como texto. Esto no contradice que las reglas coincidan según su definición:
**coincidencia de patrón e intención maliciosa son evaluaciones distintas**. No se
cambiaron las reglas para ocultar esos resultados. Tampoco deben interpretarse esas
métricas como precisión de alertas graves en producción.

**Pendiente de comprobar:** la campaña nueva todavía no se ha ejecutado contra la VM.
Las pruebas del transporte usan dobles controlados; no certifican el funcionamiento
empírico del script con las tres instancias instaladas. Tampoco se han hecho pruebas
masivas de rendimiento ni se dispone de un catálogo real de malware verificado.

## 4. Preparar el entorno en otra máquina

Los comandos siguientes son para **PowerShell desde la raíz del repositorio**.
Entorno probado: Python 3.13.16, SQLite 3.50.4, pySigma 2.1.2, backend SQLite 2.2.0,
pytest 9.2.0. Para SSH se comprobó que el entorno principal tiene Paramiko 4.0.0.

Si no existe el entorno independiente, crearlo usando Python 3.13. El siguiente
comando presupone que la `.venv` principal ya usa esa versión:

```powershell
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m venv tacticlens-sigma-lab/.venv
.\tacticlens-sigma-lab\.venv\Scripts\python.exe -m pip install -r tacticlens-sigma-lab/requirements.lock.txt
```

Si no existe la `.venv` principal, sustituir únicamente el ejecutable del comando de
creación por la ruta de una instalación Python 3.13. No instalar las dependencias del
prototipo en el entorno principal como atajo.

Para ejecutar también SSH desde el entorno independiente:

```powershell
.\tacticlens-sigma-lab\.venv\Scripts\python.exe -m pip install -r tacticlens-sigma-lab/requirements-exercises.txt
```

No copiar `.venv` entre máquinas; recrearla. La muestra privada y `output/` no viajan
normalmente con Git. Entregar la muestra por un canal adecuado o indicar otra ruta con
`--input`. Para que la suite use la muestra ubicada en la raíz:

```powershell
$env:COWRIE_REAL_EVENTS = (Resolve-Path eventos_json_50.json).Path
```

Si falta la muestra real, su test se omite explícitamente. Un resultado con ese test
omitido no equivale a reproducir toda la validación real de este chat.

## 5. Reproducir el detector y las pruebas sin conectarse a Cowrie

### Analizar la muestra real

```powershell
.\tacticlens-sigma-lab\.venv\Scripts\python.exe tacticlens-sigma-lab/main.py --input eventos_json_50.json
```

Resultados: `tacticlens-sigma-lab/output/detections.json`, `alerts.json` y `metrics.json`.
Se espera el resumen de 50 eventos, 10 detecciones y cero alertas. Revisar el código de
salida `$LASTEXITCODE`: 0 completo, 1 error, 2 resultados parciales por registros
rechazados. Los resultados anteriores pueden permanecer si una ejecución falla.

### Ejecutar la suite completa

```powershell
Push-Location tacticlens-sigma-lab
try {
    .\.venv\Scripts\python.exe -m pytest -q
} finally {
    Pop-Location
}
```

### Revisar y reproducir todos los escenarios

```powershell
# Solo muestra y guarda el plan; no abre conexiones.
.\tacticlens-sigma-lab\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --nivel critico

# Genera eventos sintéticos y ejecuta Sigma, sin red.
.\tacticlens-sigma-lab\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --modo replay --nivel critico
```

Cada ejecución crea un directorio nuevo `output/exercises/TL-*/`. Los nombres y fechas
del manifiesto usan UTC. Consultar `plan.json`, `synthetic_events.json`,
`intent_labels.json`, `expectations.json`, `comparison.json` y las salidas del detector.
Si hay discrepancias con las expectativas, el replay devuelve código 2.

No mezclar estos eventos sintéticos con la muestra real ni presentarlos como tráfico
capturado. Las etiquetas son por evento y las métricas actuales miden cualquier
detección; todavía falta una evaluación separada de calidad de alertas.

## 6. Ejecutar las pruebas reales en el laboratorio

### Catálogo disponible

| Escenario | Nivel | Transporte permitido |
|---|---|---|
| `benigno` | bajo | SSH o replay |
| `reconocimiento` | bajo | SSH o replay |
| `instrucciones_llm` | medio | SSH o replay |
| `texto_citado` | medio | SSH o replay; el texto no descarga archivos |
| `cadena_controlada` | alto | SSH sobre archivos ficticios o replay |
| `fuerza_bruta` | alto | Cinco autenticaciones inválidas como máximo por modalidad, o replay |
| `escalamiento` | alto | Solo replay |
| `transferencia` | alto | Solo replay |
| `desactivar_controles` | alto | Solo replay |
| `destruccion` | crítico | Solo replay |

`--nivel` incluye los niveles inferiores. Para SSH, seleccionar escenarios explícitos:
una selección que incluya casos exclusivos de replay se rechaza antes de conectar.

### Preparación y primera ejecución

1. Comprobar que la VM y las instancias Cowrie están disponibles; la dirección usada
   en este laboratorio es `192.168.56.101`, ajustable con `--host`.
2. Comprobar que el collector registra las tres modalidades. Seguir la guía previa de
   recolección enlazada al principio; este script no arranca ni configura servicios.
3. Verificar las claves SSH del laboratorio y disponer de sus entradas en `known_hosts`.
   Se puede indicar `--known-hosts RUTA`. No se aceptan claves nuevas automáticamente.
4. Empezar con un caso bajo en Shell y verificar sus eventos antes de ampliar la campaña.

Ejemplos usando el entorno principal, que en esta máquina ya tiene Paramiko:

```powershell
.\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --modo ssh --nivel bajo --escenarios reconocimiento --modalidades shell --host 192.168.56.101

.\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --modo ssh --nivel bajo --escenarios benigno reconocimiento --modalidades shell proxy llm --host 192.168.56.101

.\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --modo ssh --nivel medio --escenarios instrucciones_llm texto_citado --modalidades shell proxy llm --host 192.168.56.101

.\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --modo ssh --nivel alto --escenarios cadena_controlada --modalidades shell --host 192.168.56.101

.\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --modo ssh --nivel alto --escenarios fuerza_bruta --modalidades shell --host 192.168.56.101
```

Si se instaló Paramiko en la `.venv` del laboratorio, puede usarse ese ejecutable en
su lugar. Para repetir el escenario alto en Proxy/LLM, cambiar `--modalidades` después
de revisar la primera ejecución. No se necesita LLM para que Sigma detecte patrones,
pero conectarse a Cowrie LLM sí puede consumir el servicio que usa esa instancia.

### Cómo interpretar la ejecución

- La contraseña se solicita una vez y no se guarda en el manifiesto; usar credenciales
  del señuelo, pues Cowrie puede registrarlas en sus propios eventos.
- La cadena controlada crea fixtures pequeños bajo `/tmp/TL-...`; no lee el shadow real
  ni instala una clave válida. No hace limpieza automática de esos fixtures.
- Si Cowrie acepta una autenticación aleatoria, la prueba de fuerza bruta se detiene
  como inconclusa. No cuenta esa aceptación como un fallo ni inventa cinco rechazos.
- La campaña se detiene ante un caso fallido; hay esperas mínimas, límites de respuesta
  y un máximo de 50 líneas de shell hacia LLM por campaña.
- `resultados.json` registra lo intentado y lo observado por transporte. El eco de un
  comando no se considera confirmación; se espera una línea con un marcador y estado.
- `commands_acknowledged` **no prueba impacto**. Shell emula y LLM puede inventar una
  respuesta. Una versión de Cowrie sin soporte adecuado de `printf`/`$?` puede dejar el
  escenario incompleto; revisar antes de cambiar el ejecutor.

### Recoger evidencia antes de ajustar reglas

Para cada caso, conservar marcador, modalidad, fechas, estado y comandos enviados;
localizar los eventos reales y asociar sus IDs de evento/sesión/honeypot. Confirmar
comandos vacíos o ausentes y distinguir la línea original de `wire_command`, que
incluye la instrumentación de confirmación.

El formato de manifiesto conserva los campos del recolector anterior. El exportador
existente `scripts/exportar_dataset_cowrie.py` admite como directorio de manifiestos
`--source tacticlens-sigma-lab/output/exercises`. **Ese exportador genera un CSV de
vinculación y análisis; no sustituye el JSON de eventos que consume Sigma.** No se
ejecutó ni se consultó PostgreSQL durante este chat. Revisar su configuración al usarlo.
Un marcador de autenticaciones fallidas puede vincular varias sesiones legítimamente.

Exportar los eventos reales conservando `datos_originales` y metadatos, etiquetar lo
que realmente se observó y ejecutar `main.py --input RUTA_JSON --output RUTA_RESULTADOS`.
El comando de exportación específico depende del entorno de base de datos del compañero;
no se ha implementado un exportador nuevo ni una conexión automática desde la PoC.

No trasladar automáticamente las etiquetas sintéticas a eventos diferentes o faltantes.
Revisar errores de ingesta, diferencias entre modalidades y límites de las reglas por
separado. Mantener una porción del corpus reservada para validar ajustes posteriores.

## 7. Qué falta antes de integrar

1. Ejecutar y revisar las campañas SSH en las tres modalidades con evidencia real.
2. Ampliar el corpus benigno y de ataques controlados, etiquetarlo y medir por regla,
   modalidad y severidad: falsos positivos, falsos negativos, precisión y recall.
3. Revisar los positivos benignos conocidos: root, texto citado y preparación de fixtures.
   No excluir globalmente `/tmp` o todos los `echo` solo para mejorar esta muestra.
4. Probar variantes de comandos, comandos partidos/ausentes, eventos tardíos y ventanas
   de correlación. Documentar qué no puede observar cada modalidad.
5. Medir consumo de memoria y tiempo con lotes mayores; la PoC carga los eventos en memoria.
6. Acordar criterios de aceptación para cada regla y para las alertas. No hay todavía
   un umbral de calidad de producción acordado ni validado.

No es necesario añadir Redis, Kafka, Elasticsearch ni un LLM nuevo para completar esta
evaluación. `risk_score` sigue en null salvo que se inyecte una política explícita; no
hay que inventar una puntuación para poder continuar.

## 8. Plan propuesto para integrar Sigma en el flujo principal

**Todo este apartado es trabajo futuro, no funcionalidad ya implementada.** Los nombres
de tablas, endpoints y estados definitivos deben acordarse después de revisar el código
actual. La integración debe conservar el flujo de ingesta y análisis existente.

### Paso 1: definir el contrato y el punto de activación

Iniciar el análisis Sigma después de persistir los eventos, en una tarea desacoplada de
la recepción del collector. Un fallo de Sigma no debe impedir almacenar eventos ni
ejecutar el análisis LLM existente. Identificar cada ejecución con estado pendiente,
en proceso, completado, parcial o fallido; no mostrar un fallo como «sin amenazas».

Entrada: `id_evento`, `id_sesion`, `id_honeypot`, timestamp, modalidad y JSON original.
Salida: detecciones con regla y versión, severidad, IDs relacionados, evidencia saneada,
técnicas MITRE aplicables, confianza e impacto verificable, además de alertas agrupadas.

La PoC ofrece `src.pipeline.analyze(...)`; su motor `src.engine.detect(...)` recibe un
almacén mediante `EventStore`. Antes de incorporarlo, empaquetar el módulo con un nombre
propio; evitar copiar un paquete genérico `src` o lanzar `main.py` como subproceso por
cada petición HTTP.

### Paso 2: elegir la estrategia de evaluación

La base principal puede seguir siendo PostgreSQL y el evaluador seguir usando SQLite
temporal para cada lote. **Esta es una opción inicial de integración que conserva el
backend ya probado**; requiere medir límites y aislar bien cada ejecución.

Si se decide evaluar directamente en PostgreSQL, seleccionar y validar un compilador
compatible y adaptar los resultados de correlación. No ejecutar allí el SQL de SQLite
ni asumir equivalencia en fechas, regex, NULL o ventanas.

### Paso 3: diseñar persistencia y migraciones

Proponer almacenamiento separado para ejecuciones Sigma, detecciones, relaciones con
eventos, alertas y estado de entrega. Incluir versión/hash del conjunto de reglas,
fecha, estado, error saneado e identificadores deterministas para idempotencia.

Relacionar con `HONEYPOT`, `SESION` y `EVENTO` por IDs originales. `IOC` puede aportar
inteligencia de hashes verificada; no reutilizar automáticamente `DETECCION_IOC` para
coincidencias Sigma. Revisar los vínculos a `MAPEO_MITRE`/`TECNICA_MITRE` sin convertir
una inferencia en `ACCION_IDENTIFICADA` ejecutada. Diseñar migración y reversión sobre
una copia de desarrollo antes de aplicarlas al entorno compartido.

### Paso 4: implementar procesamiento incremental y correlación entre lotes

Persistir un cursor de ingesta fiable, reintentos acotados y deduplicación. Para las
reglas actuales, recuperar contexto suficiente para las ventanas de cinco minutos,
incluyendo eventos de sesiones anteriores cuando la regla agrupa por IP/instancia.
No evaluar únicamente «los últimos eventos nuevos» si eso rompe una correlación.

Separar orden de procesamiento y tiempo del evento: pueden llegar registros tardíos.
Definir solapamiento de ventanas y reevaluación sin generar alertas repetidas. Los
IDs actuales son una base útil, pero aún no existe idempotencia persistente entre
ejecuciones ni control de versiones de reglas en esos IDs.

### Paso 5: exponer resultados en la sección de análisis

Añadir endpoints y componentes de interfaz con permisos equivalentes a los de las
sesiones. Mostrar el estado de Sigma, fecha y versión del análisis, regla, severidad,
eventos relacionados, evidencia saneada y si existe alerta. Distinguir «sin ejecutar»,
«sin coincidencias», «parcial» y «fallido».

Presentar los resultados con origen explícito: **Sigma**, **IoCs** y **LLM**. Sigma debe
seguir funcionando aunque el LLM falle. No reemplazar silenciosamente el resultado
LLM existente ni presentar una respuesta generada como ejecución verificada.

### Paso 6: desplegar primero en modo observación

Habilitar la función mediante configuración, inicialmente sin notificaciones externas
ni acciones automáticas de respuesta. Comparar los resultados persistidos con el
prototipo sobre los mismos eventos. Registrar latencia, fallos y volumen de coincidencias.
Debe poder deshabilitarse Sigma sin perder ingesta, acceso a sesiones ni análisis LLM.

### Paso 7: activar alertas después de validar

Mantener inicialmente el umbral `high`/`critical`, configurable. Persistir agrupación,
deduplicación y entrega; separar una alerta almacenada de una notificación enviada.
Agregar reintentos de envío y evitar duplicados tras reinicios o reprocesamientos.
Verificar que las alertas reflejen la política ajustada y no solo coincidencias benignas.

### Paso 8: pruebas de aceptación de la integración

- Los mismos eventos y reglas producen resultados explicables y trazables frente a la PoC.
- Reprocesar un lote o reiniciar el servicio no duplica detecciones ni notificaciones.
- Las correlaciones funcionan al cruzar límites de lotes y con llegadas tardías.
- Un error del motor no bloquea el collector, la persistencia ni el análisis existente.
- La UI representa estados incompletos y errores sin confundirlos con ausencia de riesgo.
- Se mantienen permisos y protección de credenciales en API, interfaz y registros.
- La función puede desactivarse y la migración dispone de una estrategia de reversión.

## 9. Lista de continuidad para el compañero

- [ ] Obtener código y muestra privada; recrear el entorno independiente.
- [ ] Reproducir las 91 pruebas y comprobar si se omitió el test real.
- [ ] Reproducir los 50 eventos y guardar los resultados como referencia.
- [ ] Revisar el plan y ejecutar el replay ampliado sin modificar las reglas.
- [ ] Validar primero reconocimiento SSH en Shell y sus eventos persistidos.
- [ ] Repetir en Proxy y LLM, después avanzar a casos medios y altos permitidos.
- [ ] Exportar, etiquetar y separar evidencia real/sintética y errores de transporte/ingesta.
- [ ] Ajustar reglas con un corpus más amplio y validar en casos reservados.
- [ ] Acordar la estrategia de ejecución, persistencia y criterios de aceptación.
- [ ] Integrar en la sección de análisis en modo observación; activar alertas al final.

Los archivos creados durante este chat no fueron confirmados en un commit. Revisar
`git status` antes de compartir el trabajo; no dar por hecho que el compañero recibirá
los archivos locales ignorados, los resultados o el entorno virtual. El JSON real
original está fuera de la carpeta del laboratorio: revisar expresamente su tratamiento
antes de incluirlo en un commit.
