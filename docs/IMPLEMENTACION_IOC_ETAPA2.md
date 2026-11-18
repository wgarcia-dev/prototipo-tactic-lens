# Implementación de IoCs · etapa 2

TacticLens correlaciona observables con comportamientos de Cowrie, acciones guardadas y mapeos MITRE ATT&CK. La interfaz muestra qué eventos sostienen cada relación y cuál es el alcance de la evidencia.

## Modelo existente y cambio en PostgreSQL

`ioc` conserva la identidad normalizada. `observacion_ioc` identifica una aparición por IoC y evento. `evento.id_sesion` enlaza cada registro con su sesión. `deteccion_ioc` ofrece un vínculo verificable a esa observación cuando existe la clave foránea de la etapa 1. `accion_ioc` relaciona la detección con una acción y `accion_evento` identifica los eventos que la respaldan. `mapeo_mitre` enlaza la acción con la pareja oficial de técnica y táctica y conserva la revisión humana.

Antes de esta etapa, el mapeo mantenía sus citas en el JSON de procedencia y en texto. La migración aditiva `011_correlacion_ioc_mitre.sql` añade `mapeo_mitre_evento`. Su clave primaria es el par mapeo–evento. Las claves foráneas compuestas obligan a que el evento pertenezca a la acción del propio mapeo. El índice por acción y evento facilita la consulta inversa. Cada vínculo identifica el método que aportó la cita.

- Las nuevas citas explícitas que aprueban la validación RAG se guardan junto con el análisis en la misma transacción. Un mapeo que usa los eventos de la acción por omisión conserva su revisión y su procedencia original, con el marcador `citas_explicitas=false` y sin citas específicas nuevas.
- La migración recupera únicamente listas históricas estructuradas de RAG cuyos IDs completos corresponden a la acción y la sesión del análisis completado. Las distingue mediante `cita_rag_historica_v1`; las relaciones derivadas de estas citas siguen siendo candidatas incluso si se confirmó el mapeo. Las citas históricas ausentes, parciales, ajenas o presentes solo en texto quedan sin vínculo estructurado.
- Las relaciones temporales se calculan sobre las observaciones guardadas al consultar. Una importación tardía puede cambiar una relación contextual a candidata. Repetir la consulta, el archivo o el análisis completado conserva las identidades existentes. La migración 008 permanece diferida.

## Evidencia mínima y etiquetas comprobadas

| Caso | Evidencia mínima | Resultado esperado |
| --- | --- | --- |
| IP de origen, dominio o URL en un comando | Observación determinista del campo registrado. Cada aparición conserva su evento y sesión. | **Directa** entre el campo y el evento. La IP, la mera mención y el intento conservan sus propios comportamientos. |
| Una IP en varias sesiones | Misma identidad normalizada con observaciones distintas. | Cada sesión conserva su evidencia directa. |
| URL y SHA-256 de un archivo | URL de descarga y SHA-256 observados en el mismo evento de archivo. | **Directa** entre URL y hash. Se puede navegar en ambas direcciones. |
| Comando anterior y resultado posterior | Misma URL normalizada completa, misma sesión y un único candidato admisible en ambas direcciones. | **Contextual**. Se distingue la transferencia registrada del fallo. |
| Dos comandos, varios resultados o empate temporal | Coincidencias admisibles por URL y sesión, con orden indeterminado o contrapartes múltiples. | **Candidata**. Se conservan alternativas para revisión. |
| Intento aislado, resultado sin comando o URLs distintas | Falta una contraparte admisible para ese valor y sesión. | **Evidencia insuficiente** para vincular comando y resultado. El evento de transferencia conserva su propio valor probatorio. |
| Acción que cita el observable | Detección validada con FK a la observación y el mismo evento en `accion_evento`, dentro del análisis y la sesión correctos. | **Directa** para la cita de la acción. La descripción de la acción sigue siendo una interpretación. |
| Técnica en la misma sesión o acción sin evidencia común | Coincidencia de sesión o acción, con evento distinto, cita omitida o comportamiento incompatible. | Sin asociación IoC–técnica. |
| Técnica con evidencia común | Cadena verificada IoC–acción, evento citado específicamente por el mapeo y comportamiento compatible con el papel del observable. | **Candidata** si el mapeo está pendiente, **contextual** si está confirmado, **insuficiente** tras un descarte. La revisión del mapeo se muestra por separado. |

La compatibilidad se comprueba contra los rasgos por evento del análisis RAG. Se admite la transferencia para un intento, una URL de descarga registrada o el hash de ese archivo. Se admite la interpretación de shell para observables extraídos de argumentos, y el patrón de autenticación repetida para la IP de origen de los fallos citados. Una IP presente incidentalmente en un evento de descarga queda fuera de la asociación con la técnica de transferencia. Confirmar una técnica no atribuye causalidad al observable. El catálogo y los modelos se reutilizan.

### Tiempo y ambigüedad

La regla usa `evento.fecha_hora`, la hora de Cowrie. `ingresado_en` registra la recepción en PostgreSQL y `numero_secuencia` ayuda a inspeccionar el orden de almacenamiento. La fecha, la secuencia y el ID estabilizan la presentación. Si empata la fecha de Cowrie, la secuencia no decide qué evento ocurrió primero.

`IOC_CORRELACION_MAX_SEGUNDOS` admite un entero positivo. Vacío toma la propia sesión como límite y no impone un umbral sin datos de latencia. Si el laboratorio configura un límite, este se aplica a la diferencia entre las horas de Cowrie, se devuelve con la relación y se muestra en la interfaz. El resultado incluye el número total de candidatos y hasta 20 referencias por observación para mantener acotada la respuesta. Una transferencia registrada demuestra recepción en el honeypot. Su ejecución posterior requiere evidencia propia.

## API e interfaz

- `GET /api/iocs/{id_ioc}/observaciones` añade estado de la relación, correlaciones, citas de acciones, mapeos que comparten evidencia y los tiempos de evento e ingesta. Permite seleccionar un evento exacto. `GET /api/iocs` admite filtrar por UUID para abrir el observable desde otro panel.
- `GET /api/analisis/{id_analisis}` devuelve observables respaldados por acción y las citas específicas de cada mapeo. `GET /api/mitre/mapeos/{id_mapeo}/observables` permite recorrer la misma cadena en sentido inverso y consulta el estado de revisión vigente. Un mapeo descartado conserva su evidencia histórica y queda fuera del listado inverso de observables respaldados.
- La pantalla de observables conserva el detalle de la etapa 1 y añade etiquetas, justificación, límites y enlaces al evento, la acción guardada y el mapeo. Desde MITRE y Análisis LLM se puede abrir la observación exacta. Los enlaces conservan los IDs de evento como texto para evitar pérdidas de precisión de JavaScript.
- Analistas y administradores autenticados pueden consultar las relaciones. La revisión de relevancia del observable y del mapeo MITRE usa los permisos y la auditoría administrativa existentes.

## Archivos de la etapa

| Archivo | Responsabilidad |
| --- | --- |
| `backend/correlation.py` | Correlación temporal, enlaces por evento y clasificación de relaciones con técnicas. |
| `backend/routes.py`, `backend/api.py`, `backend/rag/validation.py` | Exposición y persistencia de citas verificadas, consultas de detalle y distinción entre citas explícitas y de la acción. |
| `database/migrations/011_correlacion_ioc_mitre.sql`, `.env.example` | Esquema aditivo, recuperación histórica y configuración de la ventana opcional. |
| `frontend/src/main.tsx`, `frontend/src/index.css`, `frontend/src/analysis/IocCorrelations.tsx`, `frontend/src/analysis/iocEvidence.ts` | Evidencia, etiquetas y navegación bidireccional en las pantallas existentes. |
| `tests/test_ioc_correlations.py`, `frontend/src/analysis/iocEvidence.test.mjs` | Casos temporales y ambiguos, revisión, enlaces, permisos, preservación e idempotencia. |

## Verificación y límites

- Pasaron 244 pruebas del backend en una copia aislada de PostgreSQL con DeepSeek simulado y 25 pruebas de frontend. La compilación de React pasó con los avisos de Vite sobre el tamaño del paquete y las directivas de React Router.
- Se revisaron las etiquetas de la matriz mediante fixtures aislados y se comprobó en el navegador la navegación entre observable, evento de Cowrie, acción guardada y técnica. La vista previa distinguió los tres estados de revisión MITRE y las cuatro etiquetas de relación.
- La migración se ejecuta con `.venv/Scripts/python.exe -m scripts.migrate`. El reprocesamiento de citas históricas se probó dos veces, conservando los registros originales y excluyendo una lista de citas que incluía un evento ajeno.
- Se respaldó y migró la base local. Se compararon recuentos y huellas de todas las columnas de 12 tablas existentes. Coincidieron las 7 sesiones, 32 eventos con su JSON, 29 observaciones, 2 análisis, 4 acciones y 2 mapeos existentes, entre las demás relaciones. Los mapeos locales carecen de citas estructuradas recuperables y permanecen consultables con su evidencia original. La segunda ejecución de migraciones dejó el esquema intacto.

El histórico local de esta intervención contiene 7 sesiones y 32 eventos, sin transferencias registradas. Esta base sirve para comprobar preservación y navegación histórica. La evaluación de precisión con comportamiento real requiere más sesiones etiquetadas de forma independiente, con transferencias exitosas y fallidas, reintentos, comandos ambiguos, timestamps empatados y citas MITRE variadas. Las relaciones candidatas se conservan como hipótesis revisables. La etapa de salvaguardas podrá consumir el método, la evidencia y el estado de cada vínculo.
