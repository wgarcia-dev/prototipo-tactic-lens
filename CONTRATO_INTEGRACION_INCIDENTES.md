# Contrato de integración de incidentes

**Propuesta v1 para acordar entre los dos desarrolladores.** Base de trabajo `origin/main` en `f803dd728add3ff996ed85810fa6e6027d6588e1`.

## Responsabilidades y límites

| Responsable | Autoridad y entregables |
| --- | --- |
| Desarrollador 1 | Identificación, correlación, clasificación, evaluación, revisiones y presentación del incidente. Define cuándo está confirmado y qué evidencias sustentan esa decisión. |
| Desarrollador 2 | Planes, propuestas de acción, responsables, aprobaciones, Kanban, verificación, resolución, cierre operativo e informes. Registra actuaciones humanas sobre un incidente existente. |

El triaje actual vive en `analisis_llm.resultado_estructurado.evaluacion_incidente`. D1 decide cómo mostrar o vincular esas revisiones históricas al nuevo incidente. Una alerta, una evaluación histórica o una recomendación de un análisis no crean un incidente ni habilitan una respuesta por sí solas.

## Identidad y evidencia

- D1 entrega `honeypot.incidente` con clave `id_incidente uuid` y `honeypot.incidente_evaluacion` con clave compuesta `(id_incidente, revision_evaluacion)`. Cada evaluación es inmutable y las revisiones son enteros positivos, crecientes por incidente. D1 mantiene el puntero actual y las relaciones con sesiones, evidencia y análisis.
- Una evidencia referencia un evento `bigint` y su sesión `uuid`. En JSON el evento viaja como cadena decimal positiva, sin ceros iniciales. `id_analisis` es UUID o `null` y, si se informa, pertenece a esa sesión. Para cada revisión D1 conserva la pertenencia de las citas y una huella SHA-256 de la evidencia. Si usa un análisis, conserva la huella de evidencia de esa versión. La huella cambia al modificarse el contenido o conjunto de evidencia. Las revisiones nuevas conservan las anteriores.
- D1 entrega el alcance completo de sesiones y sus sensores para autorizar acceso. D1 y D2 aplican el mismo alcance. Una consulta o exportación fuera de alcance devuelve `404`, también cuando el incidente abarca sensores y solo se tiene acceso a una parte. Los resúmenes y las citas que se comparten se proyectan con la protección de H01.
- D2 mantiene una respuesta por incidente. Su plan apunta por clave compuesta a una evaluación de D1. Las acciones, lotes LLM e historial pertenecen a esa respuesta. Las citas conservan la revisión y procedencia que las originaron. `revision_respuesta` y `revision_accion` son enteros positivos e independientes de la revisión analítica.

Vista mínima de una revisión que consume D2. Las claves son contractuales. El ejemplo usa datos sintéticos.

```json
{
  "version_contrato": 1,
  "id_incidente": "00000000-0000-4000-8000-000000000001",
  "revision_evaluacion": 3,
  "decision": "incidente_confirmado",
  "severidad": "S2",
  "titulo": "Acceso al señuelo bajo investigación",
  "resumen": "Registro de interacción con Cowrie. El alcance externo está por corroborar.",
  "evaluado_en": "2026-11-27T18:00:00Z",
  "alcance": {
    "sesiones": ["00000000-0000-4000-8000-000000000002"],
    "recursos_confirmados": []
  },
  "evidencia_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "evidencias": [
    {
      "id_evento": "9007199254740993",
      "id_sesion": "00000000-0000-4000-8000-000000000002",
      "id_analisis": null,
      "grado": "resultado_en_honeypot"
    }
  ]
}
```

`decision` admite `incidente_confirmado`, `actividad_sospechosa`, `actividad_autorizada` y `evidencia_insuficiente`. La severidad usa `S0`–`S4` o `null` cuando D1 no pueda determinarla. Los grados compartidos son `observacion`, `intento`, `resultado_en_honeypot` y `resultado_confirmado`. El grado `resultado_confirmado` exige una consecuencia corroborada. Los recursos confirmados se expresan como lista de nombres o identificadores de activos, que puede estar vacía. Solo una revisión confirmada, con evidencia verificable, habilita la respuesta. D1 conserva la autoridad para sustituir su decisión con una nueva revisión.

## Estados y concurrencia

| Entidad | Transiciones y autoridad |
| --- | --- |
| Respuesta | `sin_respuesta` es ausencia de registro. Administrador abre `en_respuesta`, resuelve a `resuelto`, cierra a `cerrado` y reabre de `resuelto` o `cerrado` a `en_respuesta`, con motivo. Admin puede pasar de `en_respuesta` o `resuelto` a `cancelado` por pérdida de elegibilidad, con motivo y disposición de las acciones. Puede reabrir una respuesta cancelada si el incidente vuelve a cumplir los requisitos. |
| Acción | El administrador decide `propuesta → aprobada/rechazada`. El responsable asignado o el administrador gestionan `aprobada → en_curso → ejecutada` y documentan resultado y evidencia. El administrador verifica `ejecutada → verificada` o devuelve a `aprobada` con motivo. Puede cancelar acciones activas con justificación y registro de las actuaciones ya realizadas. Las acciones verificadas, rechazadas y canceladas conservan su historial. |

Cuando cambia la evaluación vigente, la respuesta sigue consultable y se marca `desactualizada`. Se permite documentar actuaciones ya realizadas y registrar cancelaciones. Para aprobar, iniciar, verificar, resolver o cerrar hace falta actualizar explícitamente el plan con la revisión elegible vigente y revisar las acciones pendientes. Una reapertura revalida la revisión actual y conserva la resolución previa en el historial.

D1 y D2 usan la misma fila de `incidente` como primer bloqueo en escrituras que cambian evaluación o respuesta. D2 comprueba alcance, revisión analítica y revisión del recurso mutado dentro de la transacción. Después bloquea la respuesta y, si aplica, sus acciones. Así, una reevaluación concurrente no puede habilitar una acción sobre evidencia que ya cambió.

## API y coordinación

| Responsable | Rutas propuestas | Uso |
| --- | --- | --- |
| D1 | `GET /api/incidentes`, `GET /api/incidentes/{id_incidente}`, `GET /api/incidentes/{id_incidente}/evaluaciones/{revision}` | Bandeja, evaluación actual y evaluación histórica. D1 ofrece además una consulta de servicio en `backend/incidents.py` que recibe conexión, actor, incidente y revisión opcional, y puede bloquear el incidente en escrituras. D2 la usa en el mismo proceso y transacción. |
| D2 | `GET` y `POST /api/incidentes/{id_incidente}/respuesta` | Leer o abrir el plan. Para una revisión elegible sin respuesta, GET devuelve `estado: "sin_respuesta"`. |
| D2 | `POST /api/incidentes/{id_incidente}/respuesta/revisiones`, `POST /api/incidentes/{id_incidente}/respuesta/transiciones` | Revisar el plan o cambiar su estado. |
| D2 | `GET` y `POST …/respuesta/acciones`, `GET …/respuesta/acciones/{id_accion}`, `POST …/respuesta/acciones/{id_accion}/transiciones` | Consultar, proponer, asignar, avanzar, verificar o cancelar. Las escrituras de asignación, avance y verificación envían su operación y datos específicos. |
| D2 | `POST …/respuesta/recomendaciones`, `GET …/respuesta/recomendaciones/{id_lote}` | Solicitud explícita e idempotente y seguimiento del lote LLM. El resultado crea propuestas pendientes de decisión humana. |
| D2 | `GET …/respuesta/historial`, `GET …/respuesta/informe?formato=json\|pdf\|docx` | Actuaciones paginadas e informe relacionado con el plan, con token de vista previa para las exportaciones. |
| D2 | `GET /api/respuestas-incidentes/acciones`, `GET /api/respuestas-incidentes/responsables`, `GET` y `PUT /api/respuestas-incidentes/configuracion` | Kanban transversal, selector de analistas elegibles y límite WIP. |

En las rutas abreviadas, `…` representa `/api/incidentes/{id_incidente}`. Las listas usan `limite` y `cursor`. Ejemplo de transición de una acción. El servidor registra actor y fecha.

```json
{
  "operacion": "aprobar",
  "revision_evaluacion": 3,
  "revision_esperada": 2,
  "motivo": "La acción de revisión está sustentada por la evidencia del incidente."
}
```

Proyección mínima de `GET …/respuesta` para que D1 muestre un enlace y el estado operativo. En estado `sin_respuesta`, `id_respuesta`, `revision_respuesta` y `revision_plan` son `null`.

```json
{
  "id_incidente": "00000000-0000-4000-8000-000000000001",
  "id_respuesta": "00000000-0000-4000-8000-000000000003",
  "estado": "en_respuesta",
  "revision_respuesta": 5,
  "revision_plan": 3,
  "revision_evaluacion_actual": 3,
  "desactualizada": false
}
```

La respuesta incluye el recurso actualizado y su revisión. `revision_esperada` se refiere a la respuesta o acción que se muta. Para abrir un plan se envía la revisión de evaluación y se aplica unicidad por incidente. Sesión completa, CSRF para escrituras y permisos en servidor. `403` para rol insuficiente dentro del alcance, `409` para revisión obsoleta, transición incompatible o WIP completo, y `422` para requisitos o citas inválidos. Los conflictos de revisión devuelven las revisiones vigentes al actor autorizado.

## Archivos y orden de integración

- D1 reserva `016_incidentes.sql`, `backend/incidents.py` y su router, y es dueño de `backend/incident_assessment.py`, `IncidentAssessment.tsx` y la vista `/incidentes/:id`. Publica primero la firma de la consulta compartida, el esquema de `016` y un fixture sintético con incidente confirmado, revisión histórica y pérdida de elegibilidad.
- D2 reserva `017_respuesta_incidentes.sql`, los módulos `backend/incident_response*.py` y `frontend/src/incidents/response/`. Incorpora `/incidentes/:id/respuesta` y `/respuesta-incidentes`. Prueba contra el fixture y después contra la implementación de D1. La migración 017 depende de las claves de 016. Los números se confirman juntos si `main` avanza.
- Los registros de rutas en `backend/api.py` y `frontend/src/main.tsx`, los dominios de monitoreo y `backend/db_access.py` se editan de forma coordinada. D1 habilita un enlace al detalle de respuesta. D2 monta el tablero y el historial. Cada uno añade los permisos mínimos de sus tablas, sin modificar las migraciones aplicadas.
