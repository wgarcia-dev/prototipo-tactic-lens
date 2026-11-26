# Evidencias del capítulo 5 de TacticLens

## Pruebas funcionales y resultados

Usar el título del apartado como referencia. En la captura del borrador es 5.4 y en la plantilla es 5.5. La figura del laboratorio corresponde a una ejecución nueva del 24 de noviembre de 2026, hora de Ecuador.

| Ubicación dentro del apartado | Figura y pie sugerido | Alcance |
|---|---|---|
| Después de la explicación del recorrido desde Cowrie hasta PostgreSQL | [Conexión SSH y verificación del evento en PostgreSQL](prueba-ssh.png) | Se envió un identificador de cliente único al puerto 2222 y se buscó ese mismo valor en el JSON original. La consulta encontró el evento 11162 de la sesión 20603e11a449. La prueba verifica la captura de la negociación SSH. |
| Después del párrafo del 12 de noviembre | [Resultados históricos de recuperación y deduplicación](prueba-registro-12.png) | Extracto del registro escrito en [RESULTADOS_HTTP_LOCAL.md](../docs/RESULTADOS_HTTP_LOCAL.md). Documenta 26 entregas, 29 eventos, 6 sesiones y el reenvío reconocido como duplicado. Es una reproducción del registro histórico. |
| Al explicar el tratamiento de duplicados | [Persistencia idempotente de eventos y observables](prueba-persistencia.png) | Prueba de integración aprobada con FastAPI y PostgreSQL en una transacción de prueba. |
| Después del párrafo sobre recuperación de pendientes | [Recuperación de la cola SQLite después de una desconexión](prueba-cola.png) | Regresión aprobada con dos ocurrencias, reapertura de SQLite y transporte simulado. La cifra histórica de cuatro pendientes del 19 de noviembre requiere el registro original de esa jornada. |
| Después de explicar la actualización de la interfaz | [Notificación WebSocket después de confirmar la ingesta](prueba-websocket.png) | Prueba aprobada con cliente WebSocket de pruebas. Recibe el ID del evento confirmado y verifica que el reenvío duplicado no publica otra notificación. El alcance es el canal del backend. |

Las figuras de las tres pruebas automatizadas reproducen la orden y la salida de unittest de esta ejecución. Para la tabla de resultados de la plantilla, registrar «Cumple» en recuperación, persistencia y notificación, con las condiciones indicadas arriba.

## Figuras para los marcadores del documento Word

| Apartado y marcador | Imagen |
|---|---|
| Front end · Interfaz de análisis LLM y técnicas MITRE identificadas | [Análisis de sesión](5-2-analisis.png) |
| Front end · Consulta de indicadores de compromiso y sus evidencias | [Módulo de IoCs](5-2-iocs.png) |
| Front end · Vista previa y descarga de informes de sesiones | [Informe](5-2-informe.png) |
| Front end · Implementación de componentes y tratamiento de eventos | [Código de sessionAnalysis.ts](5-2-componente.png) |
| Back end · Recepción y almacenamiento de eventos | [Código de ingestion.py](5-3-ingesta.png) |
| Back end · Procesamiento de sesiones mediante LLM | [Código de routes.py](5-3-llm.png) |
| Back end · Recuperación híbrida de técnicas MITRE | [Código de retrieval.py](5-3-rag.png) |
| Back end · Validación de contratos MITRE | [Código de validation.py](5-3-validacion.png) |
| Integración del sistema · Arquitectura de integración | [Diagrama de componentes](5-4-integracion.png) |

Las figuras de interfaz muestran el frontend en Chromium con Puppeteer, una cuenta temporal de prueba y consultas a FastAPI mediante TestClient. Las imágenes de código reproducen líneas del repositorio. El diagrama representa la arquitectura documentada.
