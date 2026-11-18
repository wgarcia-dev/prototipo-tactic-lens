# Auditoría de MITRE ATT&CK en TacticLens

Fecha: **16 de noviembre de 2026**, America/Guayaquil. Rama local:
`codex/integracion-colaborativa-http`.

## 1. Alcance y conclusión

Se inspeccionaron código, esquema SQL, migraciones, pruebas y PostgreSQL real.
Esta auditoría **no modifica MITRE**, no importa catálogos, no ejecuta migraciones,
no reprocesa los análisis históricos y no llama a DeepSeek. Las comprobaciones
con escrituras usaron fixtures transaccionales y rollback.

La implementación existe y está integrada: **catálogo reducido manual, propuestas
del LLM, validación de códigos/evidencias, persistencia relacional y revisión
administrativa**. No existe un detector determinista de técnicas ni una
sincronización automática con STIX. Una propuesta pendiente no equivale a una
técnica confirmada, ni un comando de Cowrie demuestra su ejecución en el equipo
real.

El principal vacío es semántico: se comprueba que el evento exista y el código
esté permitido, pero no que ese evento sustente precisamente esa técnica.

## 2. Archivos y funciones relevantes

| Archivo | Implementación inspeccionada |
| --- | --- |
| `database/honeypot_schema.sql` | Tablas originales, PK, FK, índices y restricciones |
| `database/migrations/007_inteligencia.sql` | Revisión de mapeos y observaciones IoC |
| `scripts/seed_catalog.py` | `VERSION`, `TACTICS`, `TECHNIQUES`, `seed_catalog()` |
| `backend/routes.py` | `COWRIE_TECHNIQUES`, `MitreProposal`, `mitre_catalog()`, `real_result()`, `analyze()`, `persist_findings()`, `get_analysis()`, `list_mappings()`, `review_intelligence()` |
| `backend/analysis_report.py` | `analysis_instruction()`, `observation_context()`, `validate_report_evidence()` |
| `backend/analysis_state.py` | Vigencia, expiración y reutilización de análisis |
| `backend/intelligence.py` | Extracción determinista de **IoCs**, no de técnicas MITRE |
| `scripts/backfill_mappings.py` | `main()`: recuperación de propuestas históricas guardadas |
| `frontend/src/main.tsx` | `ListingPage`, `ReviewControls`, `SessionDetail`, `AnalysisPage` |
| `backend/auth/store.py` | `session()`, `require_admin()`, `audit()` |
| `tests/test_collaborative_integration.py` | Integración de catálogo, propuestas, revisiones y permisos |
| `tests/test_analysis.py`, `tests/test_live.py` | Contrato LLM, citas, persistencia y consultas |

Referencias orientativas: `analyze()` en `backend/routes.py:216`, validación MITRE
alrededor de la línea 266, `persist_findings():298`, mapeo en 341,
`list_mappings():385`, revisión en 406. Las líneas pueden cambiar en revisiones
posteriores; los nombres de funciones identifican el comportamiento.

## 3. Almacenamiento PostgreSQL real

Todas las entidades siguientes están en el esquema `honeypot`.

| Tabla | Campos y relaciones relevantes |
| --- | --- |
| `tactica_mitre` | PK `codigo_tactica`; nombre, descripción, `stix_id`, `version_attack`, `sincronizado_en` |
| `tecnica_mitre` | PK `codigo_tecnica`; FK autorreferente `tecnica_padre_id`; nombre, descripción, STIX y versión; campos opcionales de embedding |
| `tecnica_tactica` | PK UUID `id_vinculo`; FK técnica y táctica; combinación única de ambos códigos |
| `analisis_llm` | FK sesión y modelo; estado, fechas, resumen y `resultado_estructurado` JSONB |
| `accion_identificada` | FK análisis; tipo, descripción y confianza |
| `accion_evento` | Relación entre acción y eventos, con texto de evidencia |
| `mapeo_mitre` | FK acción y `id_vinculo`; evidencia, justificación, confianza, fecha; revisión administrativa |
| `auth_auditoria` | Evento `inteligencia_revisada`, actor, fecha y referencia de mapeo/decisión |

Las subtécnicas **no tienen una tabla separada**: son filas de `tecnica_mitre`
con `tecnica_padre_id`. La FK preserva la existencia del padre y un CHECK impide
el autopadre directo; no valida que la numeración del hijo corresponda al padre
ni impide por sí mismo ciclos más largos.

Hay índices en `mapeo_mitre.id_accion`, `id_vinculo` y `tecnica_mitre.tecnica_padre_id`.
`UNIQUE(id_accion,id_vinculo)` impide repetir el mismo vínculo dentro de una acción.
Las FK relevantes usan `ON DELETE RESTRICT` en el esquema original.

La migración `007_inteligencia.sql` añade `estado_revision` con estados
`pendiente`, `confirmado`, `descartado`, motivo, responsable y fecha. Convive con
`007_ingesta_identidad.sql`; el ejecutor identifica por nombre completo y checksum.
Ambas constan aplicadas en esta PC. `008_limpieza_dominios.sql` sigue sin aplicar;
esta auditoría no la ejecutó.

### Foto de datos consultada durante la auditoría

- 5 tácticas, 11 técnicas y 11 relaciones técnica–táctica.
- 2 subtécnicas: `T1059.004` y `T1110.001`.
- 7 mapeos: `T1059.004` ×2, `T1110` ×2, `T1082` ×2, `T1033` ×1.
- Los 7 estaban pendientes; no se interpretan como confirmaciones humanas.
- 5 análisis, 7 acciones y 12 relaciones acción–evento.
- 0 mapeos sin relaciones de evidencia y 0 enlaces acción–evento de otra sesión.
- 0 filas en `revision_analisis`: esa tabla original no es el mecanismo actual
  de revisión MITRE y no está integrada en las rutas inspeccionadas.
- Las 11 técnicas tienen `version_attack='20.1'`; sus `stix_id` y embeddings
  están vacíos.

Son recuentos de una consulta, no valores fijos: el equipo puede seguir usando
la aplicación. Se guardó la inspección técnica sin credenciales en un artefacto
local ignorado por Git.

## 4. Procedencia, versión y actualización del catálogo

`scripts/seed_catalog.py` declara **Enterprise ATT&CK 20.1**, con referencia al
5 de noviembre de 2026. Introduce cinco tácticas y once técnicas mediante tuplas
escritas en Python; sus descripciones son enlaces a páginas oficiales. Utiliza
`ON CONFLICT DO NOTHING`: preserva datos existentes, pero **no actualiza** sus
nombres, versiones, padres o metadatos si MITRE cambia.

La [historia oficial de versiones](https://attack.mitre.org/resources/versions/)
mostraba v20.1 como actual en la consulta. La
[publicación oficial v20.1](https://github.com/mitre-attack/attack-stix-data/releases/tag/v20.1)
permite identificar una fuente reproducible.

Además se leyó incrementalmente el
[bundle Enterprise v20.1 oficial](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.1/enterprise-attack/enterprise-attack.json):
**los 11 códigos existen, ninguno está revocado ni deprecado**, las dos
subtécnicas están marcadas como tales y las tácticas seleccionadas coinciden con
esa fuente. SHA-256 de los 55.277.605 bytes consultados:

`539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5`

Este cotejo pertenece a la auditoría: **la aplicación no realiza esa validación
ni conserva un bundle/checksum STIX**. No tiene TAXII, sincronización periódica,
control de revocaciones ni actualización por fecha. `sincronizado_en` es una
fecha de inserción, no prueba de una sincronización remota. Las versiones de
cada objeto ATT&CK son distintas de la versión global 20.1 y no se almacenan.

Conclusión: el subconjunto consultado corresponde a la versión vigente; no puede
afirmarse que TacticLens importe o mantenga actualizada toda la matriz Enterprise.

## 5. Flujo de clasificación implementado

1. La ingestión guarda eventos Cowrie y observables IoC. **No clasifica MITRE**.
2. Un usuario autenticado solicita `POST /api/sesiones/{id}/analizar`.
3. `analyze()` bloquea la sesión al decidir si reutiliza un análisis vigente,
   rechaza un intento concurrente y obtiene los eventos de esa sesión.
4. `real_result()` entrega al proveedor configurado eventos con credenciales
   redactadas, recuentos calculados y `mitre_catalog()`.
5. Ese catálogo es la intersección de PostgreSQL con diez códigos de
   `COWRIE_TECHNIQUES`. El padre `T1059` existe en PostgreSQL pero no está en esa
   lista de propuestas permitidas.
6. El prompt exige hechos, interpretación, limitaciones, códigos permitidos y
   referencias a eventos reales; prohíbe inferir cuentas reales por entrar en
   Cowrie y tratar una orden enviada como ejecución demostrada.
7. Pydantic valida estructura y confianza 0–1. El backend comprueba que las
   referencias pertenezcan a la sesión y que los IoCs aparezcan en su evidencia.
8. Para MITRE solo comprueba pertenencia al catálogo permitido y justificación
   no vacía. Guarda códigos descartados en
   `resultado_estructurado.mapeos_descartados`.
9. En una transacción se guarda el resultado completo, acciones, enlaces de
   eventos, IoCs y mapeos. Ante un fallo, el análisis queda fallido y no se
   conservan hallazgos parciales de esa transacción.
10. React consulta los resultados guardados. La revisión humana cambia el estado
    de una propuesta; no cambia el evento original.

No se encontraron reglas `comando → técnica`, umbrales deterministas MITRE,
clasificador entrenado, búsqueda vectorial ni correlación entre sesiones. Los
campos pgvector existen en el esquema, pero no hay consultas de embeddings en
este flujo. Las reglas de `backend/intelligence.py` son para observables IoC.

`backfill_mappings.py` puede recuperar propuestas de análisis ya guardados sin
LLM: exige una acción inequívoca por descripción y que los eventos guardados
coincidan, verifica código/justificación y usa `ON CONFLICT DO NOTHING`. No es
un detector nuevo ni se ejecutó durante esta auditoría.

## 6. Evidencia y trazabilidad

Cadena real:

`sesion → analisis_llm → accion_identificada → mapeo_mitre → tecnica_tactica`

La evidencia normalizada sigue otra relación:

`accion_identificada → accion_evento → evento → datos_originales JSONB`

Por cada mapeo se guarda un texto como `Eventos: 123, 124`, la justificación del
modelo, confianza y vínculo técnica–táctica. Los IDs verificables están en
`accion_evento`; el texto `mapeo_mitre.evidencia` no es una lista tipada ni una FK.
La referencia demuestra que el evento existe, **no la corrección semántica del
juicio**. La confianza es la declaración del LLM, no una probabilidad calibrada.

Los mapeos remiten indirectamente a la sesión y al modelo. No guardan por separado
un estado de técnica intentada/confirmada por telemetría, versión del prompt o
versión STIX usada para cada propuesta. El JSON del análisis conserva sus
acciones y descartes; `version_informe` es versión del formato, no versión MITRE.

## 7. Revisión administrativa y permisos

- Administrador y analista pueden consultar y analizar; solo el administrador
  puede confirmar o descartar mapeos.
- `review_intelligence()` exige sesión completa, MFA y `require_admin()`;
  bloquea la fila y valida estado y motivo de 10–500 caracteres. La escritura
  también pasa por CSRF en el middleware existente.
- Guarda responsable, fecha y motivo en `mapeo_mitre`; añade auditoría con actor
  y referencia `mitre:{id}:{estado}`.
- La UI oculta los controles al analista, pero el permiso efectivo es del backend.
- La misma propuesta puede revisarse de nuevo. No existe edición administrativa
  del catálogo, reasignación manual de táctica, creación manual de mapeos ni
  aprobación automática por confianza en las rutas inspeccionadas.
- La auditoría conserva las decisiones sucesivas, pero su metadato no contiene
  el texto de cada motivo anterior. El motivo actual sobrescribe el previo en la
  fila. La UI no muestra responsable y fecha de revisión porque el listado no
  los devuelve.

## 8. Endpoints y componentes

| Ruta | Función |
| --- | --- |
| `POST /api/sesiones/{id_sesion}/analizar` | LLM manual, validación y persistencia; reutiliza resultados vigentes |
| `GET /api/analisis/{id_analisis}` | Resultado, acciones, eventos y técnicas asociadas |
| `GET /api/mitre/mapeos?limit=...&offset=...` | Listado paginado de propuestas y revisión actual |
| `PATCH /api/inteligencia/mitre/{item_id}/revision` | Decisión administrativa sobre un mapeo |
| `GET /api/dashboard/resumen` | Cuenta vínculos MITRE distintos, incluidos pendientes/descartados |

No hay endpoint de sincronización STIX ni CRUD público de catálogo. En React,
`ListingPage(kind='mitre')` organiza tabla, paginación y detalle; `ReviewControls`
solicita motivo y guarda la decisión. `AnalysisPage` y `SessionDetail` muestran
acciones con etiquetas MITRE y conservan el análisis manual. El detalle del
mapeo enlaza a la sesión, no al evento concreto. No hay filtros por táctica,
subtécnica, estado o versión, matriz Enterprise ni visor jerárquico completo.

El listado de MITRE conserva su actualización previa de 5 s. Esta intervención
de WebSockets cambió el monitoreo de Cowrie, no las reglas ni la interfaz MITRE.

## 9. Qué puede respaldar Cowrie

La tabla expresa **posibilidad de evidencia**, no un detector garantizado. Las
propuestas actuales siguen dependiendo del LLM y de revisión humana.

| Código permitido | Evidencia que puede justificar una propuesta | Límite |
| --- | --- | --- |
| `T1059.004` | Órdenes `cowrie.command.input` en la shell emulada | No acredita ejecución arbitraria en Ubuntu real |
| `T1110` | Patrón de intentos reiterados de autenticación | Un fallo aislado no prueba fuerza bruta; no hay correlación entre sesiones |
| `T1110.001` | Evidencia de adivinación iterativa de contraseñas | Las contraseñas se redactan antes del LLM; faltan métricas específicas para distinguir variantes |
| `T1082` | Consultas como `uname`, `hostname`, datos de sistema | Solo el intento y la información que Cowrie registre |
| `T1083` | Enumeración explícita de archivos/directorios, p. ej. `ls`, `find` | Datos emulados; no prueba acceso al sistema real |
| `T1016` | Consultas explícitas de red, p. ej. `ip`, `ifconfig` | No acredita descubrimiento de toda la red organizacional |
| `T1033` | Consultas de usuario/identidad, p. ej. `id`, `whoami` | Usuario simulado; no identidad real del atacante |
| `T1057` | Enumeración de procesos, p. ej. `ps` | La salida y procesos pueden ser simulados |
| `T1005` | Lectura/recopilación explícita de archivos y contexto | Una orden `cat` no demuestra extracción ni datos reales comprometidos |
| `T1105` | Descarga/transferencia explícita y, para afirmar éxito, evento de transferencia compatible | Una URL sola o `wget` sin confirmación solo sustentan un intento |

Las definiciones oficiales de
[Unix Shell](https://attack.mitre.org/techniques/T1059/004/),
[Password Guessing](https://attack.mitre.org/techniques/T1110/001/),
[Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) y
[Data from Local System](https://attack.mitre.org/techniques/T1005/) respaldan esas
distinciones. Los ejemplos de comandos son criterios orientativos de esta
auditoría, **no reglas ya implementadas**.

`T1078` no está permitido: un login aceptado por Cowrie no demuestra uso de una
cuenta real válida. No hay cobertura implementada para confirmar explotación
real, escalamiento de privilegios, persistencia efectiva, movimiento lateral,
robo de credenciales reales, ransomware o exfiltración consumada. Tampoco se
demuestran malware/actor/campaña por una asociación MITRE.

## 10. Hallazgos y prioridades

| Prioridad | Hallazgo | Evidencia y corrección futura recomendada |
| --- | --- | --- |
| **P1** | Validación semántica insuficiente | En `analyze()` basta código permitido y texto no vacío. Prueba controlada: un evento `pwd` aceptó `T1105`. Añadir comprobaciones de evidencia específicas y distinción intento/resultado, sin convertirlas en afirmaciones de compromiso |
| **P1** | Justificación omitida puede pasar | `MitreProposal.justificacion` tiene el valor predeterminado `Propuesta para revisión`, que supera el chequeo `.strip()`. La misma prueba lo confirmó. Exigir justificación concreta, ligada a evidencia |
| **P2** | Propuestas repetidas fallan todo el análisis | Dos propuestas idénticas producen violación de `UNIQUE(id_accion,id_vinculo)` y HTTP 502. Reproducido con rollback. Normalizar/deduplicar antes de persistir |
| **P2** | Selección de táctica arbitraria al ampliar catálogo | `persist_findings()` y el backfill usan `limit(1)` sin criterio si una técnica tiene varias tácticas. Hoy cada código tiene una relación. Ampliar el contrato para seleccionar y validar táctica explícitamente |
| **P2** | Estado humano no se propaga a todas las vistas | `get_analysis()` no devuelve estado de revisión para las etiquetas MITRE; un mapeo descartado puede seguir apareciendo como etiqueta. Propagar decisión y procedencia |
| **P2** | Métrica mezcla pendientes, confirmados y descartados | Dashboard cuenta `distinct(id_vinculo)` sin filtro. Mostrar métricas separadas y etiquetas claras |
| **P2** | Catálogo no sincronizado ni trazado a STIX | El seed manual conserva metadatos viejos y deja STIX vacío. Incorporar actualización revisable, checksum, versión por objeto y tratamiento de revocaciones |
| **P2** | Historial de revisiones incompleto en detalle | Se sobrescribe el motivo; auditoría no guarda cada motivo anterior; UI no muestra responsable/fecha. Conservar decisiones completas y exponerlas con permisos |
| **P2** | Mezcla de análisis históricos | El listado incluye mapeos de todos los análisis sin indicar vigencia del análisis en la UI. Distinguir histórico, vigente y desactualizado sin borrar evidencia |
| **P3** | Evidencia del listado es texto | Exponer IDs estructurados y enlaces a eventos; conservar las FK normalizadas existentes |
| **P3** | Restricciones SQL no certifican semántica oficial | Los códigos solo se comprueban no vacíos, y el padre solo existe/no es el propio código. Validar también catálogo y jerarquía durante una importación controlada |
| **P3** | CHECK de revisión admite `NULL` en el motivo mediante SQL directo | `length(btrim(NULL))` produce NULL y un CHECK no lo rechaza. El endpoint sí exige un motivo. En una futura migración aditiva, exigir explícitamente motivo no nulo para estados resueltos |

No se aplicó ninguna de estas correcciones al módulo MITRE en esta tarea.

## 11. Pruebas y límites de lo verificado

Ejecutadas ahora:

- **6 pruebas** de `test_collaborative_integration.py`: recibos/observables,
  rollback, revisión y auditoría, permisos, filtrado de `T1078`, revisión MITRE
  administrativa y preservación del catálogo. Se excluyó la séptima prueba
  porque invoca el ejecutor de migraciones.
- **9 pruebas** de `test_analysis.py`: contexto calculado, redacción de secretos,
  IDs ajenos, estructura/evidencia del informe y respuestas truncadas/inválidas,
  con proveedor simulado.
- **58 pruebas** de autenticación, incluida la protección de módulos privados.
- **2 reproducciones adicionales transaccionales**, con proveedor simulado:
  asociación `pwd → T1105` con motivo predeterminado aceptada y propuesta
  repetida que provoca fallo 502. No se añadieron datos permanentes ni se llamó
  al proveedor real.
- Consulta real de catálogo/FK/estados y cotejo de once códigos con STIX oficial.

También se inspeccionó `test_live.py`, que cubre importación/reimportación y
persistencia de acciones/mapeos con LLM simulado; **no se ejecutó ese módulo en
esta intervención**. Las pruebas de frontend ejecutadas se centran en identidad
y monitoreo; no son pruebas de la revisión MITRE en navegador.

Faltan pruebas específicas de exactitud semántica por cada técnica, negativos
adversariales, cambio de táctica múltiple, técnicas revocadas/actualizadas,
jerarquías incorrectas, recuperación `backfill_mappings` aislada, historial
completo de decisiones, concurrencia de revisiones, estado descartado en todas
las vistas y flujos React MITRE. No hay conjunto etiquetado con precisión,
recobrado o tasa de falsos positivos medidos. Los siete mapeos reales no fueron
validados manualmente uno por uno y no se certifica su corrección semántica.

## 12. Orden de trabajo recomendado

1. Validar evidencia semántica y exigir justificaciones concretas; agregar
   negativos por técnica y deduplicación de propuestas.
2. Mostrar revisión, vigencia, responsable y fecha de forma consistente; separar
   las métricas de propuestas y confirmaciones.
3. Hacer reproducible la actualización STIX y resolver la táctica explícitamente.
4. Completar pruebas de backfill, concurrencia, interfaz y calidad del mapeo.

Hasta entonces, presentar la funcionalidad en la tesis como **propuestas
MITRE asistidas por LLM, respaldadas por referencias a eventos y sujetas a
revisión humana**, con el alcance limitado de la emulación Cowrie.
