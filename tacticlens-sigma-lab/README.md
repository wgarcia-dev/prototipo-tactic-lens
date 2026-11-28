# TacticLens Sigma Lab

PoC independiente solicitada en `NEW_PROMPT.md`. Convierte reglas Sigma reales a SQL
con pySigma y su backend SQLite; no interpreta condiciones YAML por cuenta propia.
Las reglas son propias del laboratorio, con estado `experimental`, no reglas que se
atribuyan al repositorio oficial SigmaHQ. No importa módulos del sistema principal,
no modifica sus dependencias ni accede a PostgreSQL, al collector o a servicios LLM.

Para ampliar la evaluación con escenarios comparables en las tres modalidades,
consultar [el ejecutor de ejercicios controlados](exercises/README.md): planificación,
replay sintético y SSH acotado, separados de la muestra real original.

## Instalación y ejecución

Verificado en Windows con Python **3.13.16**, SQLite **3.50.4**, pySigma **2.1.2**,
backend SQLite **2.2.0** y pytest **9.2.0**. Las APIs se comprobaron contra el código
instalado y la documentación oficial. `requirements.txt` fija dependencias directas;
`requirements.lock.txt` registra también las transitivas del entorno probado.

Desde la raíz de TacticLens, PowerShell:

```powershell
# Crear el entorno independiente si aún no existe.
.\.venv\Scripts\python.exe -m venv tacticlens-sigma-lab/.venv
cd tacticlens-sigma-lab
.\.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
.\.venv\Scripts\python.exe main.py
.\.venv\Scripts\python.exe -m pytest -q
```

El entorno ya creado para esta implementación permite ejecutar directamente los dos
últimos comandos. En Linux, crear con `python3.13 -m venv .venv` y usar
`.venv/bin/python`; esta plataforma no se ha ejecutado en esta entrega.

Entrada alternativa y umbral configurable:

```powershell
.\.venv\Scripts\python.exe main.py --input ../eventos_json_50.json --alert-threshold high --grouping-seconds 300
.\.venv\Scripts\python.exe main.py --input tests/fixtures/synthetic_events.json --labels tests/fixtures/synthetic_labels.json --output output/synthetic
```

Después de instalar, análisis y pruebas funcionan sin red. Una prueba impide crear
sockets mientras evalúa la muestra sintética. Para instalar en otra máquina sin red,
preparar previamente un directorio de wheels compatible con Python 3.13 y su sistema
operativo usando `pip download -r requirements.lock.txt -d wheels`, e instalar con
`pip install --no-index --find-links wheels -r requirements.lock.txt`.

## Flujo y responsabilidades

1. `loader.py`: JSON array/JSONL UTF-8, sin ejecutar contenido.
2. `normalizer.py`: validación, copia de evidencia, UTC, deduplicación y perfilado.
3. `intelligence.py`: enriquecimiento opcional con catálogo local de hashes.
4. `rule_loader.py`: validación pySigma, resolución de referencias y compilación SQL.
5. `database.py`: adaptador SQLite en memoria con consultas de lectura.
6. `engine.py`: ejecución mediante `EventStore`, detecciones y trazabilidad.
7. `correlator.py`: adaptación de identificadores de correlaciones nativas Sigma.
8. `alerts.py`: umbral y agrupación; `risk.py`: contrato opcional de puntuación.
9. `pipeline.py`: coordinación; `evaluation.py`: métricas etiquetadas;
   `main.py`: argumentos, archivos JSON y resumen de terminal.

`analyze(records, rules_directory, config, catalog, labels, scorer)` devuelve un
diccionario sin escribir archivos. `detect(store, compiled, events)` no depende del
sistema de archivos ni de la terminal. `EventStore` permite sustituir la ejecución
de consultas; el compilador y el adaptador de correlación también deben cambiar al
cambiar de dialecto SQL.

## Fases y validación real

La muestra entregada `../eventos_json_50.json` se copió sin alterarla a
`data/cowrie_events.json`, excluida de Git. Los registros conservan su evidencia
original; no se vuelcan contraseñas, comandos, mensajes ni credenciales en salidas.
Cada evidencia exportada incluye identificador de evento, tipo, timestamp y SHA256
de la representación JSON canónica del registro original. No es un hash de malware.
La revisión del contenido íntegro debe hacerse sobre la fuente privada por ID.

Resultados comprobados mediante el test real:

| Medición | Resultado |
|---|---:|
| Eventos | 50 |
| Shell / Proxy / LLM | 17 / 15 / 18 |
| Tipos de evento / campos comunes | 12 / 16 |
| Login root | 3 |
| Reconocimiento `ls`, `pwd`, `whoami` | 4 |
| Posible prompt injection ES/EN | 2 |
| Comando no reconocido | 1 |
| Detecciones Shell / Proxy / LLM | 4 / 2 / 4 |
| Total detecciones / alertas graves | 10 / 0 |
| Duplicados / rechazados | 0 / 0 |
| Comandos vacíos | 6 |

La ejecución final completó **66 pruebas sin fallos ni omisiones** y `pip check`
no encontró incompatibilidades. Se compilaron 16 salidas de reglas (incluidas las
correlaciones); la regla base de fallos SSH se consume dentro de la correlación.
Se observaron tres UUID distintos, todos repetidos, y 20 descensos de
`numero_secuencia` al ordenar por timestamp dentro de sesión/instancia. La copia
local coincide byte a byte con el archivo proporcionado.

En esta máquina, la ejecución final por CLI tardó aproximadamente 0.057 s para la
muestra real y 0.049 s para la sintética. Son mediciones de estas ejecuciones, no un
benchmark de capacidad ni una garantía de latencia.

No hubo diferencias respecto de los totales esperados. Los comandos de reconocimiento
admiten argumentos; por eso `ls -la` y `ls /ruta-inexistente` cuentan. La entrada de un
comando inexistente solo cuenta como fallo cuando existe `cowrie.command.failed`.
No se infiere un fallo a partir del texto del comando. La regla de prompt injection
busca las dos frases indicadas en cualquier modalidad, no solo en LLM.

La fase 1 genera campos comunes/opcionales y por modalidad, frecuencias, UUID repetidos
y descensos de secuencia respecto del orden cronológico. `id_evento` identifica y
deduplica; UUID nunca se usa para deduplicar. Las fechas requieren zona horaria y se
ordenan en UTC, con ID como desempate determinista. `instance_type` manda sobre el
puerto. Los ID se serializan como cadenas, conservando su valor; los originales siguen
en la fuente. Se admite también el contenedor `datos_originales`, objeto o JSON textual,
con prioridad para los metadatos exteriores del exportador.

Los registros inválidos se contabilizan por posición sin incluir su contenido;
el CLI devuelve código 2 aunque escriba resultados parciales. Duplicados idénticos se
cuentan y omiten; un ID repetido con evidencia distinta cancela el análisis. Fechas
sin zona no se interpretan silenciosamente como locales. Errores de entrada,
configuración, SQL o reglas devuelven código 1; una ejecución completa devuelve 0.

## Reglas graves y correlación

Las carpetas `rules/` cubren archivos sensibles, claves privadas, transferencias,
escalamiento, persistencia SSH/cron, desactivación de firewall/auditoría/SELinux,
intentos destructivos y coincidencias de hashes de archivos. Ningún comando se ejecuta.
Todas se prueban en las tres modalidades con eventos sintéticos separados.

Las correlaciones se ejecutan con **Sigma Correlations nativo**, sin ventanas
reimplementadas en Python:

- `ssh_bruteforce`: al menos cinco fallos SSH en una ventana inclusiva de cinco
  minutos, agrupados por IP, honeypot y modalidad. Puede abarcar varias sesiones.
- `login_then_sensitive`: login root seguido de intento de acceso a archivos
  sensibles dentro de cinco minutos, en la misma sesión, honeypot y modalidad.
  El orden es estricto: timestamps iguales no prueban una secuencia.

El backend requiere SQLite >=3.38 para correlaciones. La adaptación de evidencia
usa el prefijo de fuente `0:` del backend 2.2 para nuestra única tabla `logs`.
Los grupos con claves NULL no correlacionan; se informa cuántos eventos carecen de
contexto. Una IP compartida permite agrupar observaciones, pero nunca identifica
concluyentemente a una persona o al mismo atacante.

Los YAML pueden ampliarse sin editar el motor: UUID único, severidad, logsource
`product: cowrie` y campos normalizados. Las reglas se compilan como una colección
para resolver correlaciones entre archivos. Los campos opcionales ausentes se crean
como NULL. Las reglas inválidas, incompatibles, duplicadas o de otro producto cancelan
la evaluación: no se presenta una ejecución incompleta como limpia. Solo se deben
incorporar reglas revisadas; la PoC no es un sandbox para reglas hostiles.

## Detecciones, alertas y privacidad

Una detección es una coincidencia Sigma, con regla, severidad, IDs de eventos,
sesiones/honeypots/modalidades, fecha, evidencia y técnicas aplicables. Una alerta
agrupa detecciones que superan el umbral (`high` por defecto, incluyendo `critical`).
Los cinco niveles Sigma están disponibles. La agrupación usa regla, sesiones,
honeypots y modalidades, durante 300 segundos desde la primera detección. Sin contexto
de sesión/honeypot no se agrupan eventos independientes. Se deduplican IDs de detección
y de evento. Los IDs resultantes son deterministas para facilitar idempotencia futura.

La deduplicación de alertas es por ejecución; no hay almacenamiento de entregas entre
ejecuciones. Si se integra un notificador, debe persistir los IDs ya entregados.

La confianza se declara `heuristic`; `verified_impact` es siempre `false`. Ni severidad
ni respuesta emulada/LLM demuestran ejecución efectiva, infección o compromiso.
`risk_score` permanece null; se puede inyectar un `RiskScorer` que devuelva enteros
0–100 sin alterar la política de umbral por severidad.

El catálogo opcional `--hash-catalog catalog.json` es un array con entradas:

```json
{
  "sha256": "<64 caracteres hexadecimales verificados por el operador>",
  "verified": true,
  "source": "nombre de la fuente de inteligencia",
  "reference": "referencia de verificación",
  "verified_at": "2026-11-27T00:00:00Z"
}
```

No se suministra un catálogo de malware real: no se recibió inteligencia verificada.
Las pruebas usan un catálogo explícitamente ficticio. El sistema valida la estructura
y procedencia declarada, pero no verifica por Internet la veracidad de la fuente.
Solo se enriquecen `cowrie.session.file_download` y `cowrie.session.file_upload`, usando
`sha256` o `shasum`. Se ignoran etiquetas `verified_malware` aportadas por los eventos.
Los hashes de `cowrie.log.closed` nunca disparan esta regla, incluso si coinciden.

## Resultados y límites de evaluación

`output/detections.json`, `output/alerts.json` y `output/metrics.json` se regeneran en
cada ejecución exitosa. Se reemplaza cada archivo mediante un temporal; no hay
transacción conjunta entre los tres. Si una ejecución falla antes de escribir,
los resultados anteriores permanecen: comprobar siempre el código de salida.

Las métricas contienen tiempo total de análisis, reglas compiladas, cantidades por
regla/modalidad, alertas, duplicados, rechazados y perfil del conjunto. Las etiquetas
deben cubrir exactamente los IDs procesados con booleanos. Se calculan TP, TN, FP,
FN, precisión y recall por **evento con alguna detección**, no por intrusión confirmada
ni por cada regla individual. Un denominador cero produce null.

La muestra sintética etiquetada tiene 7 positivos y 2 negativos, 0 FP y 0 FN;
precisión/recall 1.0 describen únicamente esos nueve casos diseñados. No estiman
rendimiento de producción. El test adicional de confusión comprueba FP y FN reales
del conjunto de prueba y obtiene 0.5/0.5. La muestra real no tiene ground truth de
incidentes: sus métricas de clasificación se dejan null.

Limitaciones: patrones deliberadamente pequeños, evasión por codificación/alias o
variantes de shell, posibles coincidencias dentro de texto citado y actividad
administrativa legítima. Las reglas de comandos no son un parser de shell. SQLite
NOCASE/LIKE tiene limitaciones Unicode; las expresiones de prompt injection cubren
las frases observadas, no todas las paráfrasis. Las correlaciones ISO usan resolución
de milisegundos del backend, aunque se preserve microsegundo en las detecciones.
La PoC carga el corpus en memoria y no se ha sometido a pruebas de carga masiva.

Los mapeos MITRE se asignan por regla; se separan cron, claves SSH, archivos de
contraseñas y claves privadas para no atribuir todas las técnicas a cada coincidencia.
Las reglas ambiguas, prompt injection y texto de comandos fallidos no inventan una
técnica. Firewall usa T1686 en el catálogo oficial consultado; el antiguo enlace
T1562.004 redirige a esa técnica. Revisar versiones al integrar el catálogo principal.

## Integración futura, sin cambios al sistema actual

1. Adaptar `EVENTO.datos_originales` JSONB a registros con `id_evento`, `id_sesion`,
   `id_honeypot`, timestamp e instancia; procesar por lotes con cursor persistido.
2. Conservar la normalización y el contrato de detecciones. Enlazar a `EVENTO`,
   `SESION` y `HONEYPOT` por los IDs originales, nunca por UUID ni por IP solamente.
3. Sustituir compilador/adaptador SQLite por un backend adecuado y probado para
   PostgreSQL. **No reutilizar automáticamente el SQL generado para SQLite.**
4. Crear, mediante una migración futura independiente, almacenamiento de detecciones,
   alertas y entrega idempotente. No reutilizar `DETECCION_IOC` como detección Sigma
   sin definir explícitamente su semántica; `IOC` puede aportar inteligencia verificada.
5. Vincular técnicas revisadas con `MAPEO_MITRE`/`TECNICA_MITRE` sin convertirlas en
   `ACCION_IDENTIFICADA` ejecutada. Mantener observación, inferencia e impacto separados.
6. Exponer resultados por FastAPI y notificaciones después de definir permisos,
   retención, reintentos y deduplicación persistente. El LLM puede consumir evidencia
   saneada como enriquecimiento opcional; nunca controla el motor de detección.

## Fuentes oficiales consultadas

- [pySigma](https://github.com/SigmaHQ/pySigma) y su [API de backends](https://sigmahq-pysigma.readthedocs.io/en/latest/reference/backends.html).
- [Backend SQLite: APIs y requisitos](https://github.com/SigmaHQ/pySigma-backend-sqlite).
- [Semántica de correlaciones](https://github.com/SigmaHQ/pySigma-backend-sqlite/blob/main/docs/correlations.md).
- [MITRE: archivos de contraseñas](https://attack.mitre.org/techniques/T1003/008/),
  [claves privadas](https://attack.mitre.org/techniques/T1552/004/),
  [claves SSH autorizadas](https://attack.mitre.org/techniques/T1098/004/),
  [cron](https://attack.mitre.org/techniques/T1053/003/) y
  [firewall](https://attack.mitre.org/techniques/T1562/004/).
