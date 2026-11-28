# Correcciones H05, H17 y H04

27 de noviembre de 2026

| Hallazgo | Estado | Evidencia y condición pendiente |
| --- | --- | --- |
| H05 · Vigencia del análisis | **Corregido** | API, panel e informe comprobados con datos sintéticos y PostgreSQL aislado. Pendiente desplegar el código y aplicar la migración 014 en la base operativa. |
| H17 · Recolector Cowrie | **Parcial** | Servicio e instalación actualizados. Captura, persistencia, reenvío y deduplicación verificados en aislamiento. Pendiente validar y arrancar la unidad en Linux con systemd e inotify reales. |
| H04 · Calidad del análisis | **Parcial** | Corpus inicial y evaluación reproducible disponibles. Se corrigieron inferencias deterministas. Quedan pendientes la revisión experta y la medición con DeepSeek real. |

## H05 · Vigencia y estados del análisis

Una política compartida calcula **cobertura de eventos**, **vigencia metodológica** y **estado del último intento**. Cada análisis nuevo registra los identificadores de los eventos y la huella del contenido. Cada triaje conserva sus propias referencias de evidencia. La migración 014 añade a cada sesión un contador de cambios de evidencia mantenido por PostgreSQL, incluso ante ediciones con la misma cantidad de eventos. El listado consulta revisiones y metadatos en lote. La reconstrucción completa se realiza al iniciar un análisis nuevo.

La vigencia considera proveedor, modelo, parámetros, prompt, pipeline, catálogo activo de ATT&CK, contratos, configuración analítica y el contexto de sesiones relacionadas. El último resultado exitoso queda disponible después de un intento fallido o vencido. Los análisis históricos con metadatos insuficientes aparecen como **No verificable** y siguen accesibles. En registros con solo un conteo histórico, ese valor tiene carácter orientativo y la API indica que la evidencia no es verificable. La revisión de una sesión relacionada puede invalidar conservadoramente un resultado aunque el evento concreto modificado quede fuera de su ventana.

**Archivos.** [Política de vigencia](backend/analysis_state.py) · [API](backend/api.py) · [rutas de análisis](backend/routes.py) · [consultas de observables](backend/ioc_views.py) · [triaje](backend/incident_assessment.py) · [informe](backend/session_report.py) · [indicadores de estado](frontend/src/analysis/AnalysisStatus.tsx) · [integración del panel](frontend/src/main.tsx) · [migración 014](database/migrations/014_vigencia_analisis.sql) · [prueba dirigida](tests/test_analysis_freshness.py) · [regresión API](tests/test_live.py) · [regresión de informes](tests/test_collaborative_integration.py).

**Prueba dirigida.** Se ejecutaron en PostgreSQL aislado los flujos de sesión sin cambios, nuevos eventos, cambio de contenido con igual conteo, cambios de proveedor, modelo, prompt, pipeline, catálogo, configuración y contexto, fallo posterior, vencimiento y resultados históricos. El recorrido contrastó el listado que consume el panel, las métricas del panel, el detalle y el informe. El LLM fue simulado.

**Aplicación operativa pendiente.** Respaldar la base y registrar las migraciones aplicadas. Aplicar `python -m scripts.migrate` con el rol administrativo antes de iniciar el backend actualizado. Comprobar el acceso con `python -m scripts.db_roles` según el procedimiento de H02. Validar la lectura de una sesión histórica y la ingesta autorizada en el entorno previo al despliegue. No se recalculan los análisis históricos. [Procedimiento de H01 y H02](CORRECCIONES_H01_H02.md).

## H17 · Instalación del recolector Cowrie

La unidad se instala como `tacticlens-exportador.service` y ejecuta `event_watch.py`, que coordina el exportador vigente y el emisor SQLite. Se ejecuta con el usuario `cowrie`, mantiene la cola en `/var/lib/tacticlens-cowrie` y limita las escrituras a sus áreas de estado. Tiene reinicios acotados, rutas explícitas y un bloqueo exclusivo por cola. `--initialize` crea una cola nueva sin reemplazar otra preexistente. Para la misma fuente debe conservarse una única ruta de cola y deshabilitarse el servicio o temporizador anterior antes de activar la unidad. Se conserva `collector.py`.

**Archivos.** [Unidad](deploy/cowrie-ingest.service) · [configuración de ejemplo](deploy/cowrie-ingest.env.example) · [exportador](collector/exportar_eventos.py) · [instalación y diagnóstico](README.md) · [pruebas del servicio y supervisor](tests/test_event_watch.py).

**Pruebas aisladas.** Pasaron 20 pruebas dirigidas de configuración estática, inicialización SQLite y supervisión, incluidos lectura, cola, cortes simulados, reintento, reinicio, rotación y deduplicación. Pasó una integración adicional con SQLite, FastAPI y PostgreSQL aislado que perdió el acuse HTTP tras el primer envío y comprobó que el reintento no duplicó registros.

**Validación pendiente.** En una VM Linux desechable instalar la unidad, ejecutar `sudo systemd-analyze verify /etc/systemd/system/tacticlens-exportador.service` y comprobar arranque, bloqueo entre instancias, rotación por inotify y reinicio con pendientes. Interrumpir el destino HTTP, generar eventos sintéticos y confirmar tras restablecerlo que la cola drena una sola vez por evento. El entorno disponible carecía de una instancia Linux funcional con systemd para la prueba. La laptop Ubuntu queda pendiente de autorización. [Instalación y comprobaciones](README.md#5-recolector-automático-en-ubuntu).

## H04 · Calidad del análisis LLM

La evaluación diferencia acciones intentadas, resultados ambiguos, salidas simuladas y efectos sustentados por eventos. CIA deja dimensiones sin evaluar cuando la evidencia es insuficiente. Las operaciones sobre disponibilidad tampoco implican automáticamente alteración de integridad. La presentación separa el riesgo técnico potencial del organizacional. Este último se muestra como **No evaluado** cuando falta evidencia referenciada sobre activo, exposición o criticidad, como sucede en el flujo ordinario de Cowrie.

El corpus inicial contiene **26 casos sintéticos y 37 eventos**, con etiquetas fijadas antes de predecir, casos negativos, severidad S0–S4 y afirmaciones prohibidas. Las etiquetas están pendientes de revisión experta. Los casos de desarrollo de recuperación permanecen separados. El caso E24 requiere corroboración externa para S4 y el flujo habitual de Cowrie solo sustenta S0. Cualquier medición final tras ajustes requiere un conjunto de evaluación independiente que no se haya usado para diagnosticarlos.

**Archivos.** [Semántica](backend/analysis_semantics.py) · [CIA](backend/analysis_impact.py) · [riesgo organizacional](backend/threat_evaluation.py) · [presentación](backend/analysis_presentation.py) · [ejecución reutilizada](backend/routes.py) · [métricas](backend/rag/evaluation.py) · [ejecutor](scripts/evaluate_analysis_quality.py) · [pruebas de riesgo](tests/test_threat_evaluation.py) · [pruebas de presupuesto](tests/test_evaluate_analysis_quality.py) · [corpus](tests/fixtures/h04_corpus_inicial.json) · [resultados locales](tests/fixtures/h04_resultados_locales.json) · [resultados simulados](tests/fixtures/h04_resultados_iniciales.json).

### Métricas obtenidas

| Medición | Resultado local y simulado, salvo donde se indica |
| --- | --- |
| Cobertura operativa del corpus | 26/26 casos completados, 37/37 eventos, 0 fallos técnicos |
| Severidad | 25/26 exactos (96,15 %). La única celda fuera de la diagonal fue S4 → S0 |
| CIA observado | Confidencialidad 25/26, integridad 25/26, disponibilidad 24/26 |
| CIA potencial | Confidencialidad 26/26, integridad 26/26, disponibilidad 25/26 |
| Acciones y estados | Precision, recall y F1 de 97,30 %, con 36 verdaderos positivos, 1 falso positivo y 1 falso negativo |
| IoCs | Precision, recall y F1 de 100 %, con 29 verdaderos positivos y 0 falsos positivos o negativos |
| Recuperación RAG | Recall@5, @10 y @20 de 100 % en 11 casos positivos. Catálogo Enterprise ATT&CK 20.1 y 706 embeddings locales |
| Selección MITRE con simulador | Precision, recall y F1 de 100 %, 12 verdaderos positivos y 0 falsos positivos o negativos. 15/26 abstenciones |
| Trazabilidad con simulador | 14/14 citas propuestas admisibles y 12/12 grupos de evidencia requeridos para técnicas |
| Latencia y consumo | Media total de 74,66 ms local y 77,39 ms simulada. Sin llamadas, medición de tokens ni cargos de DeepSeek |

El simulador elige entre testigos disponibles en el prompt. Sus métricas comprueban el encadenamiento y la validación del resultado. La muestra y la recuperación incluyen reglas deterministas, por lo que los valores describen únicamente este corpus. Los análisis previos de DeepSeek carecían de etiquetas independientes compatibles con estos casos y no se usaron para calcular precisión. Los archivos estructurados registran versiones, huellas, matrices, latencia y métricas por etapa. [Resultados locales](tests/fixtures/h04_resultados_locales.json) · [resultados simulados](tests/fixtures/h04_resultados_iniciales.json).

### Reproducción y evaluación real pendiente

Desde la raíz, activar el entorno Python y configurar una conexión a PostgreSQL aislado con el catálogo y los embeddings importados.

```powershell
python -m scripts.evaluate_analysis_quality --modo local --salida .local/rag/h04-local.json
python -m scripts.evaluate_analysis_quality --modo simulado --salida .local/rag/h04-simulado.json
python -m scripts.evaluate_analysis_quality --resultados-guardados tests/fixtures/h04_resultados_iniciales.json --salida .local/rag/h04-recalculado.json
```

Para una futura ejecución autorizada, configurar DeepSeek en el entorno y asignar `$presupuesto`, `$tarifaEntrada` y `$tarifaSalida` con el presupuesto total y las tarifas verificadas en USD por millón de tokens. El ejecutor comprueba el destino oficial y reserva de manera conservadora entrada y salida antes de cada solicitud. El límite es una estimación con las tarifas suministradas. El siguiente ejemplo limita la corrida a dos casos y la salida a 1 024 tokens por solicitud.

```powershell
python -m scripts.evaluate_analysis_quality --modo real --casos-max 2 --tokens-max 35000 --salida-tokens-max 1024 --presupuesto-usd $presupuesto --precio-entrada-millon $tarifaEntrada --precio-salida-millon $tarifaSalida --salida .local/rag/h04-deepseek.json
```

## Regresión consolidada

- **90 pruebas Python** pasaron en análisis, RAG, riesgo, triaje, evaluación y recolector. Incluyen las 20 dirigidas a H17.
- **4 pruebas de integración PostgreSQL** pasaron en vigencia, ejecución y reutilización con LLM simulado, informes y SQLite → FastAPI con pérdida del acuse.
- **6 pruebas de seguridad H01/H02** pasaron con el rol operativo aislado y la migración 014 aplicada. Se conservaron la política de redacción y la separación de privilegios.
- **32 pruebas de frontend** y la comprobación de tipos con `tsc --project frontend/tsconfig.json --noEmit --incremental false` pasaron.
- El recálculo del resultado simulado guardado completó 26/26 casos. Se usaron datos sintéticos o un catálogo local, sin cambios en PostgreSQL operativo ni en Ubuntu.
