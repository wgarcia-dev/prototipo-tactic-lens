# Resultados de Respuesta a Incidentes

**Estado.** Bloque del desarrollador 2 implementado y validado con el contrato sintético de D1. La integración con su migración, servicio y vistas reales sigue pendiente. Trabajo local en `feature/incidentes-respuesta` desde `origin/main` en `f803dd7`.

## Funcionalidades

- Borrador editable a partir de la evaluación confirmada y plan versionado por incidente. Las acciones conservan la revisión de origen y la revisión validada. Una nueva evaluación exige ratificación explícita antes de autorizar nuevas actuaciones.
- Contención, erradicación, recuperación y verificación. Propuestas manuales o derivadas de evidencia, asignación a cuentas activas y aprobadas, aprobación o rechazo, ejecución documentada, comprobación, devolución y cancelación. Kanban con filtros, paginación, acceso por teclado y límite WIP transaccional.
- Resolución, cierre, cancelación por pérdida de elegibilidad y reapertura. Se conservan las justificaciones, cierres anteriores, resultados, referencias y actores en el historial y la auditoría.
- Solicitud explícita a DeepSeek con contexto acotado y redactado, salida validada, abstención, claves idempotentes, reutilización, exclusión simultánea por respuesta y vencimiento. Una evaluación o plan sustituido invalida el resultado tardío. Las sugerencias quedan pendientes de decisión humana. Las actuaciones se documentan desde TacticLens y se ejecutan manualmente por personal autorizado.
- Vista previa JSON y exportaciones PDF/DOCX con el mismo documento canónico, firma ligada al usuario y al incidente, límites por sección y referencias. Se rechaza una exportación vencida o cuyo contenido cambió.
- Invalidación `respuesta_incidentes` mediante PostgreSQL y WebSocket, sin contenido ni identificadores en el aviso. Se comparte el calendario de reconciliación del frontend. Se exige alcance completo de sensores para las notificaciones de respuesta.
- Importación explícita y deduplicada de antecedentes de análisis y salvaguardas que tengan citas compatibles. Las filas históricas, sus informes y sus enlaces se preservan. El modo histórico de Salvaguardas quedó preparado y desactivado por defecto.

## Migración y archivos

- `database/migrations/017_respuesta_incidentes.sql` crea respuestas, acciones, evidencias, historial, lotes y solicitudes idempotentes, y configuración WIP. Incluye claves compuestas hacia la evaluación y su revisión, índices para consultas e historial, y unicidad de los lotes activos. SHA-256 `14e71292887ac9835922c546efe10b7482a528bf45603a10a7496b3cf8a93634`.
- `backend/incident_response.py`, `incident_response_models.py`, `incident_response_routes.py`, `incident_response_recommendations.py` e `incident_response_report.py` implementan el dominio, la API, DeepSeek y los informes. Integración acotada en `backend/api.py`, `db_access.py`, `realtime.py`, `routes.py`, `safeguards.py` y `.env.example`.
- `frontend/src/incidents/response/` contiene plan, formularios, tablero, historial y vista previa. `frontend/src/analysis/SafeguardBoard.tsx` comparte la interacción de arrastre y el panel de detalle. `frontend/src/main.tsx`, `monitoring/socket.ts`, `frontend/.env.example` y `frontend/package.json` conectan rutas, monitoreo, configuración y pruebas.
- `tests/fixtures/016_incidentes_sintetico.sql` es un fixture exclusivo de prueba. `tests/test_incident_response.py`, `frontend/src/incidents/response/model.test.mjs` y `response.browser.mjs` cubren el módulo.

## API e interfaces

| Ruta bajo `/api/incidentes/{id_incidente}/respuesta` | Métodos y uso |
| --- | --- |
| Raíz, `/revisiones`, `/transiciones` | GET/POST del plan y POST de revisión y ciclo operativo. |
| `/acciones`, `/acciones/{id_accion}`, `/acciones/{id_accion}/transiciones` | GET/POST de acciones, GET de detalle y POST de mutaciones con versión esperada. |
| `/antecedentes`, `/importaciones` | GET de antecedentes referidos por D1 y POST de vinculación administrativa. |
| `/recomendaciones`, `/recomendaciones/{id_lote}` | GET de lotes recientes, POST explícito con `Idempotency-Key` y GET del estado del lote. |
| `/historial`, `/informe` | GET paginado y GET de JSON, PDF o DOCX. La exportación recibe el token de la vista previa. |

`/api/respuestas-incidentes` ofrece GET de `/acciones`, `/responsables` y `/configuracion`, y PUT de `/configuracion`. Las vistas son `/respuesta-incidentes` y `/incidentes/:id/respuesta`. Separan evaluación y respuesta, muestran la evidencia vinculada y requieren confirmación para escribir.

## Validación ejecutada

| Comprobación | Resultado |
| --- | --- |
| `python -m unittest test_incident_response` | 13 aprobadas en PostgreSQL aislado. Incluye ciclo de vida, permisos, alcance múltiple, versiones obsoletas, último cupo WIP, notificación tras commit, importación histórica, exclusión de reservas duplicadas, timeout y reevaluación con DeepSeek simulado. |
| Regresión de `test_safeguards`, `test_safeguard_wip`, `test_operational_report`, `test_report_export`, `test_incident_assessment` y `test_safeguard_lifecycle_deduplication_and_authorization` | 20 aprobadas. |
| Migraciones y permisos | Se aplicaron 015, el fixture D1 y 017 a PostgreSQL desechable restaurado con estructura y catálogos. Verifiqué 14 checksums registrados, migraciones históricas idénticas a `origin/main` y rechazo de una FK hacia una revisión inexistente. Un rol de prueba recibió inserción y lectura del historial, sin permisos efectivos de modificación, borrado o truncado del historial y evidencia. El rol temporal se revirtió. |
| Exportaciones | PDF y DOCX reales de la misma vista previa. La extracción confirmó la versión y la cita bigint exacta, sin el secreto sintético. Se comprobaron vencimiento y cambio de versión. |
| `npm --prefix frontend run build` y `npm --prefix frontend test` | Compilación correcta y 35 pruebas aprobadas. |
| Chromium | Flujo de respuesta aprobado con apertura, movimiento por teclado, confirmación y actualización de un segundo cliente mediante WebSocket simulado. El Kanban histórico también pasó su prueba de interacción. PostgreSQL confirmó por separado que el aviso se entrega solo al confirmar una transacción. |

Para reproducir, preparar una instancia desechable en `127.0.0.1:56590`, base `tacticlens_incidentes_fixture`, con el esquema hasta 015, un sensor sintético y los catálogos de prueba. Aplicar allí `tests/fixtures/016_incidentes_sintetico.sql` y luego 017. Configurar `PYTHON_DOTENV_DISABLED=1`, `PYTHONPATH=tests`, credenciales sintéticas, `HONEYPOT_ID` del fixture, correo de archivo y dependencias de exportación más `pypdf` para la extracción. Desde el worktree ejecutar las suites anteriores y `node frontend/src/incidents/response/response.browser.mjs` después de compilar. Los mocks de la suite interceptan las llamadas de recomendación.

## Integración pendiente con D1

1. Integrar `016_incidentes.sql` de D1 y su `backend/incidents.py`. Verificar las claves de `incidente` e `incidente_evaluacion`, la revisión actual, la lectura histórica y la firma `get_incident_for_response(conn, actor, id_incidente, revision=None, lock=False)`. La consulta debe devolver la proyección del contrato o indicar ausencia y aplicar el alcance del actor. Con `lock=True` debe tomar el bloqueo de la fila de incidente dentro de la transacción compartida.
2. Validar 016 → 017 en una nueva instancia aislada sin el fixture sintético. Conciliar los registros compartidos de rutas, permisos y monitoreo. El bloqueo de D1 se comprueba contra una reevaluación real y el rechazo de citas ajenas. Incorporar desde el detalle de D1 el enlace `/incidentes/:id/respuesta`.
3. Ejecutar una prueba conjunta de usuarios y sensores, informes y eventos entre procesos. Si D1 introduce visibilidad distinta por usuario dentro del mismo sensor, adaptar el filtro del canal o usar reconciliación autenticada para esas audiencias. La bandeja y el detalle analítico dependen de las vistas de D1.
4. Tras conciliar salvaguardas abiertas, habilitar juntos `INCIDENT_RESPONSE_ARCHIVE_SAFEGUARDS=true` y `VITE_INCIDENT_RESPONSE_ARCHIVE_SAFEGUARDS=true` para pasar a histórico. Se conservan las tablas, datos y rutas de lectura. DeepSeek requiere una URL HTTPS explícita y la configuración del servidor. Probar con el proveedor real es una validación separada de las pruebas simuladas.

La base operativa, Ubuntu Server y `main` permanecieron intactos. La rama conserva las dos especificaciones previas del usuario en su worktree. Los commits funcionales locales son `7181bc2` y `a782b86`.
