# Correcciones H06, H07 y H08 de TacticLens

27 de noviembre de 2026 · Base de referencia `74b417f5aa841ce48c008a81b2abd6061776e5b1`

| Hallazgo | Estado final | Evidencia principal |
| --- | --- | --- |
| H07 · Ejecución LLM | **Corregido** | Intentos identificados y acotados. La prueba de concurrencia bloqueó la segunda solicitud, venció la primera y conservó el resultado del reintento cuando llegó la respuesta tardía. |
| H08 · Enriquecimiento de IoCs | **Corregido** | Contratos, cuotas, caché, concurrencia y fallos parciales verificados con respuestas simuladas. La clasificación diferencia ausencia de coincidencia de fallo de consulta. |
| H06 · Actualización en tiempo real | **Corregido** | Dos clientes WebSocket autenticados recibieron cambios confirmados. Una reversión y una notificación de otro sensor quedaron fuera de ambos clientes. Un proceso externo publicó en PostgreSQL y ambos clientes lo recibieron. |

## H07 · Ejecución LLM

Antes de iniciar un intento, FastAPI valida proveedor, URL HTTPS, modelo, credencial, catálogo activo y disponibilidad de embeddings. El intento registra su UUID, la huella de evidencia de H05 y su vencimiento. Un bloqueo por sesión serializa la reserva. El guardado exige que ese UUID siga en proceso y dentro del plazo de PostgreSQL. Hallazgos, mapeos, salvaguardas y resultado se confirman juntos.

Los errores incluyen fase, código, mensaje seguro y posibilidad de reintento. Las fases distinguen configuración, recuperación RAG, enriquecimiento, proveedor, validación y persistencia. La API conserva el último éxito y reutiliza un resultado vigente en las condiciones de H05. Los reintentos siguen siendo explícitos. El proveedor tiene un plazo total de intercambio HTTP, incluido el cuerpo de la respuesta. El plazo del intento incluye las fases posteriores a la preparación y reserva, con límites de ejecución en PostgreSQL para la persistencia.

**Medición.** Una respuesta retenida por el proveedor simulado devolvió HTTP 504 en **1 521,7 ms** desde el cliente con un plazo de **1 400 ms**, incluida la preparación de la solicitud y el registro del fallo. Una solicitud concurrente recibió HTTP 409 y se observó una sola invocación al proveedor para el intento en curso. Se verificaron la reversión de un hallazgo escrito durante una persistencia fallida, el reintento y la conservación del resultado previo.

**Archivos.** [Ejecución](backend/analysis_execution.py) · [rutas](backend/routes.py) · [estados](backend/analysis_state.py) · [traza](backend/analysis_trace.py) · [recuperación](backend/rag/retrieval.py) · [mensajes al cliente](frontend/src/auth/client.ts) · [configuración](.env.example) · [pruebas integradas](tests/test_execution_realtime.py) · [regresión H05](tests/test_analysis_freshness.py) · [regresión del análisis](tests/test_analysis.py) · [regresión de ingesta y análisis](tests/test_live.py) · [regresión RAG](tests/test_rag.py) · [regresión H01](tests/test_security_h01_h02.py).

## H08 · Enriquecimiento de IoCs

ThreatFox valida sus registros de coincidencia. URLhaus consulta exclusivamente hashes SHA-256 y coteja el hash de la respuesta. MISP evalúa las listas locales una vez por lote y conserva sus coincidencias, versión y estado de cobertura. Los resultados conservan proveedor, fecha y referencia. Los fallos de autenticación, cuota, formato, disponibilidad y timeout tienen estados propios. H01 protege los secretos capturados, incluidas credenciales anidadas. El modelo recibe estados y referencias de evento.

El presupuesto global es de **4 s** por defecto. Cada proveedor remoto tiene **2 s** y un reintento transitorio por defecto, condicionado por el tiempo restante y la cuota. Se agrupan búsquedas equivalentes, se limitan las solicitudes en espera y se usan hasta seis trabajadores concurrentes por proceso. La caché LRU conserva hasta **512** coincidencias o ausencias de coincidencia durante **1 h** por defecto. Los presupuestos, cuotas, TTL y capacidad se pueden ajustar con las variables de ejemplo.

**Medición.** Dos consultas de red simuladas se ejecutaron en paralelo para dos consumidores que solicitaron los mismos indicadores. El lote devolvió estados de timeout en **164,4 ms** con un presupuesto de **160 ms** y dos solicitudes simuladas en total. Pasaron pruebas con HTTP 429, 500 y 403, fallos de red, JSON inválido, estructuras incompatibles, expiración, límite de caché y continuidad ante un fallo parcial. [API de ThreatFox](https://threatfox.abuse.ch/api/) · [API de URLhaus](https://urlhaus.abuse.ch/api/).

**Archivos.** [Enriquecimiento](backend/enrichment.py) · [proyección de IoCs](backend/ioc_views.py) · [informe de sesión](backend/session_report.py) · [detalle del análisis](frontend/src/analysis/AnalysisNarrative.tsx) · [panel de IoCs](frontend/src/analysis/IocDashboard.tsx) · [etiquetas](frontend/src/analysis/iocEvidence.ts) · [pruebas](tests/test_enrichment.py).

## H06 · Actualización en tiempo real

Las escrituras de ingesta, análisis, revisiones de IoCs y MITRE, y cambios de salvaguardas registran invalidaciones en su propia transacción. PostgreSQL entrega el aviso tras el `COMMIT`. Cada proceso del backend tiene una conexión `LISTEN` y filtra por sensor antes de enviar el aviso. El WebSocket revalida la sesión autorizada y envía dominios, revisión y metadatos acotados de ingesta. La caché de métricas se invalida antes de notificar a los clientes cuando cambia el panel.

El frontend refresca las consultas de los dominios afectados. El planificador serializa las peticiones, agrupa avisos durante una consulta y resincroniza al volver a conectar. La reconciliación periódica se mantiene incluso con el WebSocket conectado, con valor predeterminado de **30 s** y frecuencia de hasta **15 s** sin conexión.

**Medición.** Una ingesta sintética confirmó y llegó a dos clientes en **55,8 ms** desde la solicitud. Se verificaron inicio, finalización y fallo de análisis, revisión de IoC y MITRE, asignación y cambio de estado de una salvaguarda, métrica del panel, reconexión, reversión, filtrado por sensor y rechazo sin autenticación. La publicación desde otro proceso pasó por PostgreSQL y fue recibida por ambos clientes.

**Archivos.** [WebSocket y suscripción](backend/realtime.py) · [ciclo de vida de FastAPI](backend/api.py) · [ingesta](backend/ingestion.py) · [guardado y revisiones](backend/routes.py) · [salvaguardas](backend/safeguards.py) · [reconciliación React](frontend/src/monitoring/Realtime.tsx) · [protocolo](frontend/src/monitoring/socket.ts) · [planificador](frontend/src/monitoring/polling.ts) · [suscripción por dominio](frontend/src/monitoring/usePolling.ts) · [pantallas principales](frontend/src/main.tsx) · [MITRE](frontend/src/analysis/MitreDashboard.tsx) · [tablero](frontend/src/analysis/SafeguardsPage.tsx) · [configuración web](frontend/.env.example) · [pruebas de invalidación](frontend/src/monitoring/invalidation.test.mjs). El planificador compartido sustituye `frontend/src/monitoring/invalidation.ts`. [PostgreSQL 18, `NOTIFY`](https://www.postgresql.org/docs/18/sql-notify.html).

## Validación y estado operativo

- **7 pruebas dirigidas y de integración** pasaron con PostgreSQL aislado, incluido el recorrido de ingesta SQLite–FastAPI tras perder el acuse. Se usaron catálogos y datos de prueba con proveedores simulados.
- **78 pruebas Python** de regresión pasaron, incluidas redacción H01, análisis, informes, RAG, triaje y enriquecimiento.
- **32 pruebas de frontend**, la comprobación de tipos y la compilación de Vite pasaron.
- **Migraciones nuevas o aplicadas en esta intervención** · Ninguna. La 014 y las credenciales, permisos y propietarios existentes se conservaron.
- **Backend operativo actualizado** · `127.0.0.1:8000` respondió con `status=ok`, PostgreSQL conectado y HTTP 401 a la consulta privada sin sesión. Se verificó la conexión de escucha en PostgreSQL y, en solo lectura, el acceso a 350 sesiones, incluidos 29 resultados históricos visibles. El cotejo posterior confirmó que las huellas de las 37 tablas históricas coinciden con el respaldo validado de H05.

## Límites de las comprobaciones

Las latencias corresponden al entorno de validación y a una muestra dirigida. Los cupos y cachés de enriquecimiento son por proceso. Los avisos PostgreSQL son efímeros y la reconciliación repone el estado tras perderlos. El análisis conserva su interfaz HTTP y los plazos persistidos permiten reconocer intentos vencidos tras una interrupción. La verificación de dos clientes y de fallos se realizó en el entorno aislado. Queda observar los nuevos estados y las métricas con tráfico real autorizado. No se consumieron cuotas externas ni se modificó Ubuntu Server.
