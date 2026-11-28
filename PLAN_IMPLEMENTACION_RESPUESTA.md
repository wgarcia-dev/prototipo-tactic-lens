# Plan de implementación de Respuesta a Incidentes

Rama `feature/incidentes-respuesta`, creada en un directorio de trabajo separado a partir de `origin/main` en `f803dd728add3ff996ed85810fa6e6027d6588e1`. Las interfaces con evaluación e identificación se rigen por el [contrato de integración](CONTRATO_INTEGRACION_INCIDENTES.md).

## Componentes de partida

| Componente actual | Decisión | Trabajo previsto |
| --- | --- | --- |
| `backend/auth/middleware.py`, `auth/store.py`, `sensitive.py` | Reutilizar | Sesión completa, CSRF, autorización, auditoría y redacción. Mantener la habilitación de usuarios y el alcance efectivo en las consultas del nuevo módulo. |
| `backend/report_export.py`, `backend/report_renderer/render.mjs` | Reutilizar | Pasar el mismo documento canónico adaptado a JSON, PDF y DOCX. `report_snapshot.py` requiere generalizar la identidad de sesión a incidente con un propósito de firma distinto. Los informes de sesión conservan su contrato. |
| `frontend/src/analysis/SafeguardBoard.tsx`, `safeguards-board.css`, `SafeguardsPage.tsx` | Adaptar | Extraer el tablero reutilizable, el panel de detalle, accesos por teclado y los patrones de filtros y paginación. Sustituir tipos, columnas y operaciones específicas de salvaguardas. |
| `backend/safeguards.py` y migraciones 012–013 | Adaptar patrones y sustituir el dominio | Reusar el patrón de bloqueo WIP, asignación a analistas activos, historial y validación de evidencia. El tablero actual se vincula a sesiones y usa tres estados, mientras que la respuesta depende de un incidente confirmado y distingue aprobación, ejecución y verificación. |
| `backend/safeguard_proposals.py`, `SafeguardProposalsPage.tsx` | Sustituir en el flujo operativo | Conservar el control de revisión y la evidencia de verificación como patrones. Trasladar las decisiones nuevas a entidades de respuesta. Las revisiones antiguas quedan en el JSON histórico de su análisis. |
| `backend/analysis_report.py`, `analysis_execution.py`, `analysis_state.py` | Reutilizar y adaptar | Aprovechar recomendaciones guardadas e identificadores de evidencia. Para nuevas recomendaciones, reutilizar configuración, redacción, límites y patrón de intentos. La generación de respuestas tendrá un esquema y un prompt propios. |
| `backend/incident_assessment.py`, `frontend/src/analysis/IncidentAssessment.tsx` | D1 | Consumir la evaluación versionada. D1 decide la convivencia con el triaje histórico y conserva su presentación. |

## Secuencia de trabajo

### 1. Persistencia y reglas de negocio

- Crear `database/migrations/017_respuesta_incidentes.sql` con la FK hacia la evaluación de D1. Tablas propuestas `incidente_respuesta` (una fila por incidente con referencia a la evaluación aceptada), `incidente_accion` (responsable, fase, procedencia y revisiones), `incidente_accion_evidencia` (citas y referencias de verificación), `incidente_respuesta_historial` (solo inserción), `incidente_recomendacion_lote` y `incidente_respuesta_config`. Indexar por incidente, estado y responsable, y ordenar el historial por un identificador creciente.
- Implementar reglas transaccionales en `backend/incident_response.py` y HTTP en `backend/incident_response_routes.py`. Validar que las acciones, referencias, sesiones y análisis pertenezcan a la evaluación citada. Una revisión del plan conserva objetivos y criterios anteriores en el historial. Para ratificar acciones pendientes, registra su evaluación vigente por separado de la revisión que originó la propuesta, o cancela con motivo. Cualquier evidencia nueva que cambie el alcance se incorpora primero a través de D1.
- Cada mutación confirmada incrementa `revision_respuesta`. Las acciones tienen además su propia revisión. Reunir en la misma transacción el cambio, su historial con actor y fecha de servidor, la auditoría y la invalidación pertinente. El historial conserva estado anterior, decisión, justificación, evidencia y resultado. La auditoría general recibe solo IDs y metadatos permitidos. Añadir permisos mínimos en `backend/db_access.py`, con historial y evidencia histórica de solo inserción y lectura.
- Administrador abre el plan, asigna responsables activos y aprobados, decide propuestas, verifica resultados y resuelve, cierra o reabre. El responsable asignado documenta e informa la ejecución. Usuarios autorizados pueden consultar y proponer medidas manuales. Revalidar el estado de la cuenta al actuar. Mantener el límite WIP configurable del patrón actual, contando solo `en_curso`. Dos transacciones que compitan por el último cupo deben producir un solo inicio.

### 2. Planes, recomendaciones y verificación

- El plan registra objetivo, alcance, responsables y criterio de salida. Distinguir contención, erradicación y recuperación según la evaluación. Puede incluir verificación como acción. La evidencia del señuelo sustenta investigar o verificar el alcance, y solo la evidencia corroborada permite afirmar afectación real. El administrador puede declarar fases no aplicables con motivo.
- Importar recomendaciones de análisis completados ya citados por D1 si su procedencia y eventos coinciden con la evaluación. Conservar origen `id_analisis` y posición. Las recomendaciones sin citas suficientes quedan consultables como antecedente. Una propuesta manual nueva debe citar evidencia de la evaluación o justificar su base con una referencia verificable.
- Encapsular la generación explícita en `backend/incident_response_recommendations.py`. Enviar a DeepSeek solo una proyección redactada y acotada de la revisión. La salida propuesta contiene fase, medida, objetivo, justificación, criterio de verificación y citas. Validar formato, alcance, citas y tamaño de salida. Si la evidencia es insuficiente, admitir abstención y mantener disponible la propuesta manual.
- Un lote registra proveedor, modelo, versión de prompt, revisión y huella de evidencia. Usar `Idempotency-Key` y reutilizar un lote exitoso para la misma entrada. Reservar el intento antes de la llamada, aplicar tiempo máximo sin retener bloqueos durante la espera y aceptar la respuesta solo si el intento y la evaluación siguen vigentes. Persistir las propuestas válidas como `propuesta`, con deduplicación por origen, y evitar sobrescribir decisiones humanas. No hay ejecutor, conexiones a activos ni herramientas externas invocables por el modelo.
- El usuario documenta qué hizo, resultado y evidencia verificable. Admin acepta aplicando el criterio de verificación o devuelve la acción con motivo. Resolver exige dejar las acciones admitidas verificadas o canceladas con motivo, documentar riesgos pendientes y registrar la comprobación final, incluso si se justifica que ninguna acción era necesaria. Cerrar exige una resolución vigente y el criterio de cierre documentado. Reabrir exige motivo y conserva el cierre precedente. Conservar el historial de las acciones ya verificadas aunque cambie el plan.

### 3. Frontend, Kanban e informes

- Crear `frontend/src/incidents/response/` con plan, tablero, detalle de acción, historial y vista previa. Mostrar por separado el estado analítico de D1 y el estado operativo. Agrupar tarjetas en Por decidir, Aprobadas, En curso, Por verificar y Finalizadas. Mostrar el estado exacto dentro de cada grupo. Arrastrar una tarjeta abre la transición permitida y su formulario. El servidor confirma el movimiento. Conservar alternativa de teclado, capacidad WIP y filtros por incidente, estado y responsable.
- Reutilizar `useMonitorQuery` y la invalidación PostgreSQL posterior al commit de `backend/realtime.py`. Añadir el dominio `respuesta_incidentes` en backend y `frontend/src/monitoring/socket.ts`, en coordinación con D1. Los avisos solo invalidan consultas autorizadas y no llevan IDs ni contenido. Para un alcance parcial que el canal actual no pueda filtrar con seguridad, usar reconciliación autenticada hasta ampliar el filtro. En reconexión, releer el estado desde la API.
- Componer `backend/incident_response_report.py` con evaluación y revisión citadas, alcance, responsables, actuaciones, evidencias, resultados, resolución y reaperturas. Mantener fecha, secciones omitidas y conteos. La vista previa firma un snapshot por incidente, revisiones, usuario y huella del documento canónico. PDF y DOCX exigen ese snapshot. Si cambió la fuente, devolver `409`. Si venció, devolver `410`. Revalidar alcance y aplicar H01 antes de renderizar.

### 4. Sustitución de Salvaguardas y entrega

- Tras validar las rutas nuevas, sustituir la entrada de navegación de Salvaguardas por Respuesta a Incidentes y desactivar la creación automática de tareas legadas en el arranque y en el análisis. Mantener `linked_tasks`, fichas, informes, tablas y consultas históricas en solo lectura. Conservar los enlaces antiguos al historial correspondiente. No convertir una tarea de sesión en incidente.
- Antes del cambio, inventariar tareas abiertas y revisiones pendientes. Permitir vincular una salvaguarda a una respuesta por decisión administrativa explícita y con evidencia compatible. Crear una propuesta con referencia al registro original y unicidad por origen. Si no hay incidente compatible, se conserva en el archivo histórico. Reconciliar las tareas abiertas con sus responsables antes de deshabilitar sus escrituras.

## Criterios de aceptación

| Área | Verificación dirigida |
| --- | --- |
| Integración y acceso | Incidente confirmado en una o varias sesiones. Un incidente parcial o fuera de alcance no se expone. Una reevaluación simultánea bloquea nuevas decisiones obsoletas y conserva el historial. Incluir un ID de evento mayor al entero seguro de JavaScript. |
| Flujo y concurrencia | Aprobar, rechazar, asignar, ejecutar manualmente, devolver la verificación, resolver, cerrar y reabrir con roles reales de prueba. Una versión antigua devuelve `409`. Probar responsable desactivado y último cupo WIP con dos transacciones. |
| LLM | Usar un proveedor simulado. Comprobar reutilización, abstención, citas ajenas, ausencia de secretos, timeout, respuesta tardía y rechazo por reevaluación. La generación no cambia el estado de una acción aprobada. |
| Frontend y tiempo real | Dos clientes, filtros, movimiento mediante teclado, acceso a historial, confirmaciones y reconexión. Un rollback no debe invalidar como si el cambio estuviera confirmado. |
| Informes | Abrir JSON y extraer contenido de PDF y DOCX para verificar revisiones, citas y equivalencia. Comprobar expiración, cambios concurrentes, acceso, secciones omitidas y redacción. |
| Migración y compatibilidad | Aplicar 016 y 017 en PostgreSQL aislado con datos sintéticos e históricos de prueba. Verificar claves, permisos, conteos, que las migraciones 012–015 conservan checksum y que los informes anteriores siguen disponibles. |

Las pruebas nuevas se concentrarán en `tests/test_incident_response*.py` y en el módulo de frontend. Usar los fixtures de autenticación, WIP, informes y monitoreo tras acordar el fixture compartido con D1.
