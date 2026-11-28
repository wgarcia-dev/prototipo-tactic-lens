# Escenarios controlados para Cowrie Shell, Proxy y LLM

Un solo catálogo parametrizado permite comparar las tres modalidades: Shell 2222,
Proxy 2223 y LLM 2224. `run_exercises.py` no cambia el collector, PostgreSQL, las
reglas Sigma ni la sección de análisis del sistema principal.

Hay dos dimensiones diferentes: **severidad del comportamiento que se estudia** y
**riesgo operativo del ejercicio**. Los escenarios altos enviados por SSH actúan
solo sobre archivos ficticios bajo un directorio exclusivo `/tmp/TL-<identificador>`.
Los comandos destructivos, de escalamiento, descarga o desactivación de controles
permanecen exclusivamente en replay. No se instalan herramientas ofensivas, no se
descarga malware y no se modifica una clave SSH válida.

## Catálogo

| ID | Nivel | SSH real | Qué compara |
|---|---|---|---|
| `benigno` | bajo | Sí | Texto inerte y lectura de `/etc/os-release` |
| `reconocimiento` | bajo | Sí | `ls`, `pwd`, `whoami` |
| `instrucciones_llm` | medio | Sí | Texto de prompt injection ES/EN, también en Shell y Proxy |
| `texto_citado` | medio | Sí | Ejemplo de curl citado mediante echo; no ejecuta curl |
| `cadena_controlada` | alto | Sí | Reconocimiento, lectura de shadow ficticio y escritura de clave inválida en un archivo fuera de `~/.ssh` |
| `fuerza_bruta` | alto | Sí, acotado | Cinco intentos inválidos, usuario de prueba único, contraseñas aleatorias sin diccionario |
| `escalamiento` | alto | No | Patrón de sudo en un evento sintético |
| `transferencia` | alto | No | Patrón de curl en un evento sintético, sin acceso a red |
| `desactivar_controles` | alto | No | Patrones de firewall/auditoría, sin modificar servicios |
| `destruccion` | crítico | No | Patrón destructivo solo en datos JSON |

`--nivel` incluye niveles inferiores. `--escenarios` restringe por ID. Si un escenario
seleccionado excede el nivel indicado, se devuelve error. No hay ejecución paralela,
reintentos automáticos, barrido de hosts ni selección arbitraria de puertos.

## 1. Revisar el plan, sin conectarse

Desde la raíz de TacticLens:

```powershell
.\tacticlens-sigma-lab\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --nivel critico
```

El modo predeterminado es `plan`. Genera `plan.json`, incluyendo objetivos, comandos,
etiquetas, reglas esperadas y marcadores diferentes por escenario/modalidad.
No solicita contraseñas ni abre conexiones. Nunca se carga un plan editado como
código: el ejecutor SSH comprueba cada caso contra el catálogo interno.

## 2. Ejecutar todos los escenarios mediante replay

```powershell
.\tacticlens-sigma-lab\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --modo replay --nivel critico
```

Genera un directorio nuevo en `tacticlens-sigma-lab/output/exercises/TL-*/` con:

- `plan.json`: escenarios y procedencia sintética.
- `synthetic_events.json`: eventos artificiales, separados de la muestra real.
- `intent_labels.json`: intención controlada de ataque por evento, establecida por
  el catálogo antes de ejecutar Sigma. Un login root aislado o la preparación del
  fixture son negativos; una lectura intencional del fixture es un positivo.
- `expectations.json`: coincidencias esperadas de las reglas individuales por evento.
- `comparison.json`: diferencias entre esas expectativas y el resultado, incluyendo
  las correlaciones por sesión. Las discrepancias devuelven código 2.
- `detections.json`, `alerts.json`, `metrics.json`: salida del motor actual.

El replay **no genera tráfico SSH ni telemetría real de Cowrie**. Comprueba reglas y
ventanas sobre registros sintéticos; el comportamiento del collector, las respuestas
de cada modalidad y el registro de comandos vacíos requieren la ejecución SSH posterior.

## 3. Ejecutar reconocimiento contra el laboratorio

El entorno principal ya dispone de Paramiko 4.0.0. Usarlo permite ejecutar SSH sin
modificar ninguna dependencia existente:

```powershell
.\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --modo ssh --nivel bajo --escenarios reconocimiento --modalidades shell --host 192.168.56.101
```

Repetir en Proxy y LLM, o seleccionar las tres:

```powershell
.\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --modo ssh --nivel bajo --escenarios reconocimiento --modalidades shell proxy llm --host 192.168.56.101
```

Para un entorno independiente, instalar previamente
`tacticlens-sigma-lab/requirements-exercises.txt` dentro de la `.venv` del laboratorio.
Plan y replay no necesitan Paramiko. El entorno principal no necesita pySigma para SSH.

Se requiere un archivo `known_hosts` con las claves del laboratorio verificadas por
un canal conocido. El valor predeterminado es `$HOME/.ssh/known_hosts`; se puede
indicar otro mediante `--known-hosts RUTA`. Para puertos no estándar, OpenSSH suele
usar entradas `[192.168.56.101]:2222`, `:2223` y `:2224`. No se aceptan claves nuevas
automáticamente ni se desactiva su verificación. El host debe ser una IPv4 literal
RFC1918; se usa exclusivamente el laboratorio autorizado del usuario.

La contraseña se solicita una vez, solo en memoria. No se guarda ni se incluye en
argumentos. No se usan claves privadas ni el agente SSH. Cowrie puede registrar la
contraseña en sus propios eventos: usar únicamente credenciales del señuelo.

## 4. Ejecutar el escenario alto controlado

Primero probarlo en Shell y luego en Proxy/LLM:

```powershell
.\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --modo ssh --nivel alto --escenarios cadena_controlada --modalidades shell --host 192.168.56.101
```

El escenario crea un directorio nuevo mediante `mkdir -m 700`, sin reutilizarlo si ya
existe. Después crea un archivo de hash ficticio y un archivo con un comentario que
no es una clave pública válida. Ambos están bajo `/tmp/TL-...`, nunca en `/etc/shadow`
real ni en el directorio de autenticación SSH. No configura cron, servicios, sudo,
setuid, firewall, payloads ni conexión saliente. No borra archivos automáticamente;
los pequeños fixtures permanecen para inspección y pueden retirarse al restaurar
el contenedor o la instantánea desechable del laboratorio.

Este escenario reproduce una **secuencia observable**, no una vulnerabilidad
explotada ni persistencia efectiva. La correlación `login_then_sensitive` presupone
que el login observado sea de root. Si se usa otro usuario, esa expectativa debe
interpretarse como no aplicable, no como un fallo de registro.

## 5. Autenticaciones inválidas acotadas

```powershell
.\.venv\Scripts\python.exe tacticlens-sigma-lab/run_exercises.py --modo ssh --nivel alto --escenarios fuerza_bruta --modalidades shell --host 192.168.56.101
```

Solo cinco conexiones por modalidad, separadas al menos por un segundo, con un
usuario de prueba cuyo nombre es el marcador y contraseñas aleatorias que no se
persisten. No busca descubrir credenciales. Si Cowrie acepta un intento —puede
ocurrir por la política permisiva del señuelo— se detiene inmediatamente, sin abrir
shell, y registra `inconclusive_auth_accepted`. No se reinterpretará como cinco
fallos ni se cambiará la configuración de autenticación para forzar el resultado.

La correlación agrupa por IP, honeypot y modalidad a través de sesiones distintas.
El límite de cinco intentos no garantiza por sí mismo que se reciban cinco eventos
de fallo dentro de la ventana: debe verificarse en los eventos exportados.

## Estado, evidencia y límites

Cada ejecución SSH escribe `resultados.json` incrementalmente. Conserva los campos
del recolector existente (`marcador`, `modalidad`, `escenario`, `objetivo`, fechas,
destino, puerto, `codigo_ssh`, comandos y verificación), junto con resultados por paso.
Los marcadores son únicos incluso entre modalidades. En autenticación el marcador
es el usuario; en sesiones de shell se envían marcadores de inicio y fin.

Se pueden pasar estos manifiestos al exportador existente mediante
`--source tacticlens-sigma-lab/output/exercises`; no se ejecuta aquí ese exportador ni
se consulta PostgreSQL. Los cinco fallos pueden producir varias sesiones vinculadas
al marcador y aparecer como vinculación ambigua: no debe inventarse una sesión única.

Cada línea de shell lleva una confirmación aleatoria con el código de salida
reportado. El eco del comando no basta para marcarlo como terminado. Un timeout,
cierre prematuro, salida no nula o respuesta mayor de 128 KiB detiene la ejecución;
también se detiene la campaña al fallar un caso. Hay un máximo de 50 líneas enviadas
a LLM por campaña. `Ctrl+C` deja constancia del caso iniciado sin marcarlo completo.
Los tiempos límite son por conexión/comando, no una garantía sobre servicios remotos.

No se almacenan transcripciones crudas: se guardan tamaño y SHA256 de la respuesta,
comandos propios, código reportado y tipo de error, sin mensajes de excepción que
pudieran contener secretos. Las respuestas remotas nunca se evalúan como instrucciones.

`commands_acknowledged` significa que se recibieron confirmaciones de transporte.
En Shell las respuestas son emuladas; en LLM pueden ser texto inventado. Incluso en
Proxy no equivale a una verificación independiente del estado del sistema.
`impacto_verificado` permanece false. En una versión antigua de Cowrie que no soporte
`printf`/`$?`, el caso puede quedar incompleto; no se continuará ignorando el error.
La línea exacta enviada figura como `wire_command`: Cowrie puede registrar la línea
completa o sus comandos por separado. Esto debe tenerse en cuenta al comparar con
el replay, que contiene los comandos de escenario sin la instrumentación.

Después de una ejecución real: localizar sus eventos por marcador, confirmar
`instance_type`, IDs y timestamps, revisar comandos faltantes/vacíos y ejecutar el
motor sobre el export real. No asignar automáticamente las etiquetas de replay a
eventos ausentes o diferentes. Esa revisión empírica precede al ajuste de las reglas.

## Validación efectuada

Se ejecutaron 25 pruebas nuevas y la suite completa: **91 pruebas aprobadas**.
Cubren separación entre replay/SSH, direcciones/puertos, identificadores únicos,
límites de autenticación, rechazo de planes alterados, eco de terminal, fragmentación
de respuestas, límite de bytes, cierre y ausencia de contraseñas en manifiestos.
Los transportes SSH de las pruebas son dobles controlados: **no se ha ejecutado esta
campaña contra la VM y no se afirma compatibilidad empírica con sus tres instancias**.

Replay completo ejecutado: **99 eventos, 78 detecciones, 30 alertas**, con todas las
expectativas de reglas y correlaciones satisfechas. Respecto a intención: 54 TP,
33 FP, 0 FN y 12 TN (precisión 0.6207; recall 1.0). Los falsos positivos son esperados
en estos controles: 27 logins root de infraestructura, tres preparaciones de fixture
y tres ejemplos citados. No se cambió el catálogo de reglas para ocultarlos.

Una regla puede coincidir correctamente con su patrón y aun así señalar actividad
benigna. Estas métricas mezclan niveles informativos y graves y miden este conjunto
artificial; no son precisión de alertas de producción ni prueba de intrusión exitosa.

Referencias de API comprobadas: [SSHClient](https://docs.paramiko.org/en/stable/api/client.html),
[Channel](https://docs.paramiko.org/en/stable/api/channel.html) y
[printf de Cowrie](https://github.com/cowrie/cowrie/blob/main/src/cowrie/commands/printf.py).
