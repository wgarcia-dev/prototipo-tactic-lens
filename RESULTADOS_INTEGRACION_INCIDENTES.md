# Integración de incidentes de TacticLens

## Estado y referencias

La evaluación (D1), la respuesta (D2) y la atribución Cowrie (H03) quedaron integradas y validadas en `integration/incidentes`. La sustitución de la navegación de Salvaguardas está lista. Su paso a solo lectura queda condicionado a conciliar las actuaciones abiertas del entorno que se despliegue.

| Referencia | Commit |
| --- | --- |
| `main` y `origin/main` de partida | `f803dd728add3ff996ed85810fa6e6027d6588e1` |
| `feature/incidentes-evaluacion` | `51706f422ffb8a1d7ae8f13af483d919353a8b7b` |
| `feature/incidentes-respuesta` publicada | `ef26ee8de9ad71b5d2d7edef675ef7cfd7b41f69` |
| Commit funcional final de la integración | `0dcb55c1798c2b26c39851a1d330815b5ba55262` |

La rama de integración permanece local. `main`, la rama publicada de D2, PostgreSQL operativo y Ubuntu Server se mantuvieron intactos.

## Evaluación y respuesta

- **D1.** La persistencia de un análisis exitoso registra candidatos usando el triaje, la evaluación de amenazas, la severidad, el impacto CIA y la evidencia ya calculados. El alta bajo demanda referencia un análisis almacenado. La correlación automática exige una identidad de sensor verificada, el mismo origen observado, un SHA-256 de transferencia común, proximidad de hasta 60 minutos y una única coincidencia. La IP por sí sola no agrupa sesiones. Las restricciones de sesión y análisis evitan duplicados. Las revisiones conservan autor, motivo, fecha, precedencia y evidencia vinculada a sesiones, eventos, comandos, IoCs y citas MITRE.
- **D2.** Se conservan planes, recomendaciones explícitas con DeepSeek y citas verificadas, asignación, aprobación y rechazo, registro de ejecución y verificación, límite WIP, historial, resolución, cierre, cancelación y reapertura. Las acciones son gestionadas por usuarios. Los informes JSON, PDF y DOCX comparten el snapshot y mantienen la protección de datos sensibles.
- **Contrato compartido.** `backend/incidents.py` implementa `get_incident_for_response(conn, actor, id_incidente, revision=None, lock=False)`. D1 y D2 coordinan sus escrituras con el mismo bloqueo por incidente. El plan opera sobre una revisión confirmada con evidencia verificable. Un cambio de revisión o evidencia obliga a revisar la base de las actuaciones dependientes y conserva las versiones anteriores. El acceso requiere permiso y alcance sobre todos los sensores vinculados. La invalidación WebSocket distingue evaluación y respuesta y solo anuncia transacciones confirmadas.

## H03 y procedencia Cowrie

| Identidad reconocida | Modalidad | Puerto de contraste |
| --- | --- | --- |
| `tacticlens-cowrie-01` | Shell | 2222 |
| `tacticlens-cowrie-proxy` | Proxy | 2223 |
| `tacticlens-cowrie-llm` | LLM | 2224 |

Se conserva el JSON original del evento y se registra la atribución normalizada por separado. La identidad de la instancia declarada por el recolector y el identificador exacto del sensor sirven como evidencia. Una atribución contradictoria queda marcada como no verificada y el puerto se utiliza como contraste. La procedencia alimenta filtros, sesiones, eventos, análisis, evaluaciones e informes. Los registros históricos pueden atribuirse al consultarlos si conservan identificadores verificables. En una muestra histórica de 50 eventos, el sensor genérico `ubuntuserver` y las etiquetas de modo o puerto no aportaron esa verificación. Esos eventos conservan su información original. El análisis distingue observaciones y efectos emulados de consecuencias corroboradas. La modalidad Proxy por sí sola tampoco acredita un compromiso organizacional.

## Migraciones y resolución de conflictos

| Migración | Función | SHA-256 normalizado |
| --- | --- | --- |
| `016_incidentes.sql` | Incidentes, versiones, relaciones, evidencia y procedencia Cowrie | `9f993f810783531fd61dc371376c8e4eb1b5b54308beb4cb02931534c8f5dc9e` |
| `017_respuesta_incidentes.sql` | Planes, acciones, recomendaciones, configuración e historial D2 | `14e71292887ac9835922c546efe10b7482a528bf45603a10a7496b3cf8a93634` |

Las claves de 016 satisfacen las referencias de 017. La 017 conserva exactamente el contenido publicado por D2. Las migraciones 001 a 015 permanecen intactas. Se retiró el fixture sintético 016 de la suite conjunta, que ahora usa las migraciones y el servicio D1 reales.

Se resolvieron seis conflictos. `backend/api.py` registra ambos routers y prepara el modo histórico. `backend/db_access.py` combina las concesiones de evaluación y respuesta. `backend/realtime.py` y `frontend/src/monitoring/socket.ts` coordinan dominios y alcance. `frontend/package.json` conserva ambas suites. `frontend/src/main.tsx` conserva las rutas de ambos bloques y el acceso histórico.

## API e interfaces

| Superficie | Funciones |
| --- | --- |
| `/api/incidentes` | `GET` con búsqueda, filtros, orden y cursor. `POST` registra un incidente a partir de un análisis persistido. |
| `/api/incidentes/resumen` y `/api/incidentes/{id}` | Métricas, detalle, evaluación vigente, evidencia, procedencia y enlaces. |
| `/api/incidentes/{id}/evaluaciones/{revision}` y `/api/incidentes/{id}/revisiones` | Consulta de una versión y registro de una revisión humana con control optimista. |
| `/api/incidentes/{id}/respuesta` | Plan, revisiones, transiciones, acciones, recomendaciones, historial, antecedentes, importaciones e informe. |
| `/api/respuestas-incidentes` | Consulta global de acciones, responsables y configuración WIP. |
| `/api/salvaguardas/archivo` | Estado del modo histórico y conteos de actuaciones por conciliar. |
| `/incidentes`, `/incidentes/:id`, `/incidentes/:id/respuesta` y `/respuesta-incidentes` | Panel y listado, detalle y revisión, enlace al plan confirmado, seguimiento y Kanban. |

## Validación

| Comprobación | Resultado |
| --- | --- |
| `python -m unittest test_incidents test_incident_response` | 20 aprobadas sobre PostgreSQL 18 aislado. Incluye autorización, evidencia histórica, concurrencia, WIP, notificación tras commit y rollback, recomendaciones simuladas y ciclo desde la ingesta hasta el cierre y la reapertura. Se extrajo el contenido de PDF y DOCX y se contrastó con el snapshot. |
| Regresión histórica y compatibilidad | 68 aprobadas. Dos corresponden a persistencia parcial y capacidad de respuesta durante la importación, ejecutadas por separado en el fixture PostgreSQL que exige la suite. Cuatro aserciones fallaron también en un árbol idéntico a `origin/main` contra la misma base aislada. |
| `npm --prefix frontend test` y `npm --prefix frontend run build` | 37 pruebas aprobadas. Compilación TypeScript y Vite satisfactoria. |
| Chromium | Dos recorridos aprobados. El primero cubrió evaluación, plan, aprobación por teclado e invalidación entre clientes con WebSocket simulado. El segundo cubrió el Kanban histórico con paginación, teclado, ratón, interacción táctil, conflicto y vista móvil. |
| Migrador y permisos | En una segunda base aislada, el migrador aplicó 015, 016 y 017 en orden. La segunda ejecución no aplicó cambios. Se verificaron los checksums y el aplazamiento previsto de 008. Con un rol sintético revertido se comprobaron `SELECT` e `INSERT` permitidos y `UPDATE`, `DELETE` y `TRUNCATE` denegados sobre cuatro tablas de evidencia e historial. |

En total, **88 pruebas de backend aprobadas**. Las discrepancias reproducidas en `main` fueron dos peticiones de revisión sin `revision_esperada` que obtienen `422`, un conteo MITRE de pendientes y una expectativa de eliminar parámetros URL no sensibles. Se conservaron esas pruebas y el comportamiento de referencia.

Para reproducir la suite conjunta, use una base desechable con el esquema anterior, los catálogos de prueba, un sensor sintético y las migraciones 016 y 017. Configure `PYTHON_DOTENV_DISABLED=1`, `PYTHONPATH=tests`, las variables `DATABASE_*` de la base desechable, `HONEYPOT_ID` del sensor de prueba, correo de archivo y las dependencias de exportación y `pypdf`. Los dobles de prueba interceptan las llamadas al LLM. El recorrido Chromium de integración se ejecuta con `node frontend/src/incidents/response/response.browser.mjs` tras compilar. Las pruebas usaron datos sintéticos y catálogos de referencia.

## Despliegue y transición de Salvaguardas

1. Verificar el respaldo y el registro de la 015 en el entorno de destino. Aplicar 016 y 017 en ese orden, registrar sus checksums y comprobar el arranque. Mantener la configuración vigente de roles y credenciales. El despliegue de H02 queda fuera de esta intervención.
2. Comprobar que `HONEYPOT_ID_COWRIE_SHELL`, `HONEYPOT_ID_COWRIE_PROXY` y `HONEYPOT_ID_COWRIE_LLM` apuntan a los UUID de las fuentes registradas. Conservar la configuración DeepSeek existente en `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL` y `LLM_API_KEY`, y ajustar `LLM_TIMEOUT_SECONDS` e `INCIDENT_RESPONSE_LLM_TIMEOUT_SECONDS` si procede.
3. Mantener `INCIDENT_RESPONSE_ARCHIVE_SAFEGUARDS=false` en el primer arranque. La navegación principal ya dirige a Incidentes y Respuesta a Incidentes. El tablero de respuesta enlaza a Salvaguardas para consultar o conciliar las tareas. El historial, los registros, las propuestas, los informes y las evidencias siguen disponibles.
4. Revisar `GET /api/salvaguardas/archivo`. Completar las tareas abiertas en el flujo legado o importarlas explícitamente al incidente que corresponda y revisar su acción sucesora. Hacer lo mismo con las propuestas aprobadas o en curso. Cuando ambos conteos estén en cero, habilitar `INCIDENT_RESPONSE_ARCHIVE_SAFEGUARDS=true` y reiniciar coordinadamente todas las instancias. El backend mantiene habilitadas las escrituras legadas si todavía detecta pendientes. No hay conversión automática de registros históricos.

Quedan pendientes el inventario de actuaciones abiertas en el entorno operativo y la activación del modo histórico. Las pruebas H03 validaron los identificadores suministrados mediante eventos sintéticos. La ingestión de las tres instancias reales deberá comprobarse en el entorno de destino. La evaluación conjunta usó DeepSeek simulado y no generó solicitudes de pago.
