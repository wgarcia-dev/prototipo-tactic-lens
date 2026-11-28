# Automatización de Respuesta a Incidentes

La automatización quedó implementada en `integration/incidentes`. El commit funcional es `86697c89e9647292ded0dc8ce5f04d96c10740a2`. La migración 018 se verificó en PostgreSQL aislado y se aplicó en el entorno operativo. La vista previa inicial identificó 21 candidatos históricos. El lote queda pendiente de autorización y la configuración operativa mantiene desactivados la generación automática, el correo externo de incidentes y el archivo histórico de Salvaguardas.

## Flujo de trabajo

1. El registro transaccional de un candidato D1 con evidencia verificable crea un trabajo persistente. El trabajador reclama la fila en PostgreSQL, limita la concurrencia global y libera la transacción antes de solicitar la propuesta. La confirmación humana conserva el borrador si la huella de las citas permanece igual. El cambio de evidencia invalida la propuesta anterior.
2. El contexto usa sesiones y eventos citados, procedencia Cowrie, clasificación, severidad, prioridad, grado de evidencia, impacto, comportamientos, IoCs, MITRE y antecedentes compatibles. De RAG reutiliza las técnicas recuperadas que también tienen citas admitidas. Usa el redactor existente y omite los comandos y el JSON original. La salida se valida por esquema, citas, precedencia y correspondencia de antecedentes. Los resultados posibles incluyen abstención, fallo y borrador disponible.
3. El administrador revisa la propuesta y puede agregar, editar o retirar acciones justificadamente, rechazar una acción o el borrador, y solicitar otra generación. Cada edición conserva la versión anterior. El incidente debe estar confirmado y la evidencia vigente para activar el plan y aprobar una acción o un lote. La operación usa las mismas transiciones, autorizaciones y controles de concurrencia que D2.
4. La asignación filtra cuentas activas, con correo verificado, aprobadas y con rol habilitado. Ordena por acciones en curso, carga abierta y un desempate estable. El administrador puede confirmar o cambiar la propuesta. Sin un responsable elegible, la acción queda pendiente de asignación y se avisa a los administradores. El inicio respeta el WIP global y exige verificar las acciones predecesoras.
5. El Kanban presenta códigos, prioridad, origen, responsable, fecha y vencimiento. Incluye filtros, «Mis acciones», detalle y evidencias, carga por responsable para administradores y sincronización WebSocket. El plan muestra el avance, los recuentos por estado, el tiempo transcurrido y las condiciones para resolver o cerrar. La resolución, el cierre y la reapertura se registran mediante decisión humana. Los informes conservan los snapshots y añaden el origen y los datos de las actuaciones generadas.

## Avisos y Salvaguardas

- La bandeja persistente cubre candidatos, borradores, aprobación, rechazo, asignación, reasignación, recordatorios, vencimiento, verificación pendiente, resolución, cierre, reapertura y errores de generación. La campana muestra el recuento de avisos sin leer y permite abrir el incidente o acción, consultar el historial y marcar sus avisos como leídos.
- Las invalidaciones de la bandeja se dirigen al destinatario mediante PostgreSQL y WebSocket. Asignaciones, reasignaciones y recordatorios pueden encolar correo mediante el outbox existente de Resend. El envío externo se realiza después de confirmar la operación. El correo contiene un aviso genérico y acceso a la plataforma. Los recordatorios se deduplican por acción, destinatario, tipo y fecha límite.
- La navegación operativa se concentra en Respuesta a Incidentes. Sigue disponible el acceso a Salvaguardas para la conciliación. Incorporar un antecedente precisa aprobación explícita y conserva su identificador, estado anterior y citas. El guardado reutiliza los identificadores de origen y detecta medidas equivalentes de la misma fase. El modo histórico de solo lectura conserva la condición de conciliación existente.
- Según el inventario facilitado, quedan 21 candidatos históricos elegibles para revisión de borradores, 50 salvaguardas con citas compatibles, 68 salvaguardas en total y 8 sesiones pendientes de reevaluación. La automatización se probó con registros sintéticos. Esos recuentos operativos se deberán corroborar en la vista previa del despliegue.

## Migración y archivos

- `database/migrations/018_respuesta_automatizada.sql` añade la cola, el historial inmutable de borradores, la bandeja, la procedencia y el detalle del plan, la prioridad de acciones y las fases de investigación y mitigación. SHA-256 registrado `00fcb350e705e2ab8bff76af3ea9af6c00a3178ff6cf13c296929498565333a2`. Las migraciones anteriores conservan sus archivos y checksums.
- Trabajo en segundo plano, conclusiones y notificaciones en `backend/incident_automation.py`, `backend/incident_automation_routes.py` y `backend/incident_notices.py`. Integración en `backend/incidents.py`, `backend/api.py`, `backend/db_access.py`, `backend/realtime.py` y `backend/auth/notifications.py`.
- Plan, acciones e informes en `backend/incident_response.py`, `backend/incident_response_models.py`, `backend/incident_response_routes.py` y `backend/incident_response_report.py`.
- Interfaces en `frontend/src/incidents/EvaluationPage.tsx`, `frontend/src/incidents/IncidentInbox.tsx`, `frontend/src/incidents/response/{DraftPanel,ResponsePage,ResponseBoard}.tsx`, `frontend/src/incidents/response/model.ts`, `frontend/src/main.tsx` y `frontend/src/monitoring/socket.ts`.
- Configuración de referencia en `.env.example`. Pruebas en `tests/test_incident_automation.py`, `tests/test_realtime.py` y `frontend/src/incidents/response/response.browser.mjs`.

## Endpoints

| Ruta | Método y uso |
| --- | --- |
| `/api/incidentes/{id}/respuesta/borradores` | `GET` lista propuestas y estado. `POST` solicita otra generación. |
| `/api/incidentes/{id}/respuesta/borradores/{borrador}` | `GET` consulta versiones y sugerencias. `PUT` guarda una revisión con control optimista. |
| `/api/incidentes/{id}/respuesta/borradores/{borrador}/aprobar` | `POST` activa la respuesta confirmada o incorpora acciones seleccionadas. |
| `/api/incidentes/{id}/respuesta/borradores/{borrador}/rechazar` | `POST` registra el rechazo justificado del borrador. |
| `/api/respuestas-incidentes/automatizacion/retrospectiva` | `POST` previsualiza o encola hasta 21 casos históricos. |
| `/api/respuestas-incidentes/avisos` | `GET` devuelve el historial paginado y el recuento personal sin leer. |
| `/api/respuestas-incidentes/avisos/leer-todos` y `/api/respuestas-incidentes/avisos/{id}/leer` | `POST` registra la lectura dentro de la cuenta autenticada. |
| `/api/respuestas-incidentes/acciones` | `GET` amplía el tablero con `mias`, `prioridad`, `vencimiento` y `origen`. Conserva los filtros existentes. |

## Pruebas realizadas

| Comprobación | Resultado |
| --- | --- |
| Migrador sobre el PostgreSQL aislado `tacticlens_incidentes_integracion`, puerto 56591 | Aplicó la 018. La segunda ejecución aplicó cero migraciones. Coincidieron los checksums 016–018 y se verificó el trigger inmutable habilitado. |
| `python -m unittest test_incident_automation test_incidents test_incident_response test_realtime` | 39 aprobadas. Incluyen registro D1 desde análisis guardado, cola persistente, deduplicación, validación de citas, respuestas tardías, control de roles, aprobación parcial, dependencias, avisos privados, correo genérico, recordatorios, informes y ciclo de vida. |
| `npm --prefix frontend test` | 37 aprobadas. |
| `npm --prefix frontend run build` | Compilación de TypeScript y Vite correcta. Se observaron avisos del empaquetador sobre directivas de React Router. |
| `node frontend/src/incidents/response/response.browser.mjs` | Chromium con dos pestañas y API/WebSocket simulados. Verificó Kanban, «Mis acciones», recuperación histórica, borrador del candidato sin controles de aprobación y lectura de la campana. |
| Regresión ampliada de autenticación | La prueba de alta guiada despacha explícitamente la referencia persistida con un proveedor simulado y verifica la deduplicación. La prueba de IoC obtiene `revision_esperada` y verifica el rechazo de una decisión obsoleta. |

## Activación del lote histórico

1. En una ventana de despliegue, respaldar PostgreSQL y verificar que la única migración nueva autorizada sea `018_respuesta_automatizada.sql`. Aplicarla con las credenciales y propietarios del esquema existentes. El contrato de permisos solo incorpora las tres tablas nuevas. La aplicación operativa de H02 sigue fuera de alcance.
2. Reiniciar el backend actualizado con `INCIDENT_RESPONSE_AUTO_ENABLED=false` e `INCIDENT_RESPONSE_EMAIL_ENABLED=false`. Verificar la consulta del tablero, la campana y la vista de conciliación. Mantener `INCIDENT_RESPONSE_ARCHIVE_SAFEGUARDS=false` mientras el flujo existente indique actuaciones o revisiones pendientes.
3. Con una cuenta administradora y MFA completo, abrir **Respuesta a incidentes → Borradores para candidatos históricos → Previsualizar lote histórico**. La API equivalente recibe `{"limite":21,"vista_previa":true}` en `/api/respuestas-incidentes/automatizacion/retrospectiva`. Contrastar los identificadores y las revisiones con los 21 candidatos previstos.
4. Cuando se autorice el consumo operativo, configurar el DeepSeek existente y habilitar `INCIDENT_RESPONSE_AUTO_ENABLED=true`. Los valores iniciales de `.env.example` son dos ejecuciones concurrentes en la base, dos intentos como máximo por trabajo, tres generaciones por huella con solicitud humana para las adicionales, 2.800 tokens máximos de salida y 45 segundos por ejecución. El contexto saliente se limita a 14 KB. Para probar un lote menor, reducir `limite` en la petición.
5. Encolar desde la misma pantalla con **Encolar borradores en DeepSeek**, o enviar `{"limite":21,"vista_previa":false}` al mismo endpoint. La escritura vuelve a verificar las revisiones actuales y omite casos ya encolados. Revisar los estados de la cola y el consumo informado por el proveedor. Activar `INCIDENT_RESPONSE_EMAIL_ENABLED=true` por separado si se autoriza correo directo y está configurado el servicio transaccional.

## Límites y pendientes

- El piloto operativo autorizado ejecutó una solicitud a `deepseek-v4-pro`. El proveedor consumió 2.286 tokens de entrada y los 2.800 de salida en razonamiento, devolvió `finish_reason=length` y no devolvió un borrador estructurado. El trabajo quedó fallido y emitió un aviso interno. El corte por tokens queda pendiente de corrección. El lote histórico sigue sin activarse.
- La calidad semántica de recomendaciones y el comportamiento de Resend en vivo requieren validación operativa. La validación automática comprueba la estructura y la pertenencia de citas, y la revisión humana valida la pertinencia de la actuación y las conclusiones.
- La autorización actual usa el alcance de sensores configurado para la instancia y las cuentas autorizadas. El proyecto carece de un calendario de disponibilidad y de un ACL individual por sensor. Las sugerencias usan la carga registrada y el WIP compartido.
- El control de duplicados compara la procedencia y la medida normalizada. Las recomendaciones equivalentes con redacción diferente requieren conciliación humana. Las vistas de la API muestran hasta 50 borradores y 100 ediciones por borrador.
- La generación retrospectiva, el despacho de correo real y el cambio a archivo histórico requieren la autorización y las comprobaciones de activación correspondientes.
