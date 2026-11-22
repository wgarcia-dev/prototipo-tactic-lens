# Evaluación formal de incidentes

TacticLens organiza el análisis de cada sesión como un expediente con evidencia Cowrie, interpretación del LLM, contexto MITRE y decisión de un administrador de seguridad. La evaluación sigue la orientación de [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) sobre análisis de eventos adversos, alcance y criterios de declaración. Los criterios y prioridades siguientes son decisiones metodológicas propias del prototipo, versionadas como `tacticlens-triaje-1`.

## Criterios automáticos

FastAPI identifica autenticaciones fallidas, autenticaciones aceptadas por el señuelo, órdenes recibidas y transferencias registradas. Cada criterio conserva los identificadores de sus eventos. La prioridad de triaje es media cuando hay interacción con la shell o transferencia y baja para las demás capturas. Esta prioridad determina el orden de revisión. La severidad organizacional comienza por determinar.

Se conserva el número de eventos, la fecha de evaluación y el SHA-256 de la representación JSON del conjunto evaluado. Este hash permite detectar cambios en el conjunto usado, aunque su valor depende de la serialización de TacticLens. La política actual evalúa una sesión. La correlación entre campañas y sesiones requiere trabajo posterior.

## Decisión del analista

En el detalle del análisis, la sección Evaluación de incidente presenta criterios, cobertura y revisiones. Un administrador puede registrar actividad sospechosa, actividad autorizada, evidencia insuficiente o incidente confirmado. Debe justificar la decisión, identificar el criterio de incidente aplicable, valorar el impacto, delimitar alcance, asignar responsable, proponer medidas y citar eventos del conjunto evaluado.

Una confirmación exige severidad. El cierre exige un criterio y su verificación. Los estados disponibles son en investigación, en respuesta y cerrado. Se pueden registrar revisiones sucesivas para reabrir o corregir la evaluación. Cada revisión conserva actor, fecha, evidencia y justificación. El bloqueo de fila y el número esperado de revisión evitan sobrescribir decisiones concurrentes. La autorización utiliza el rol administrativo existente y la auditoría de la aplicación.

La escala de severidad requiere criterio humano contextual. Baja corresponde a un alcance acotado con afectación menor documentada, media a una afectación limitada que requiere respuesta, alta a una afectación relevante de activos o información, y crítica a una afectación grave que requiere atención inmediata. El analista debe documentar su fundamento y la política local. La confianza del modelo y la similitud MITRE carecen de equivalencia automática con esta escala.

## Persistencia y compatibilidad

Se reutiliza `analisis_llm.resultado_estructurado.evaluacion_incidente` y `auth_auditoria`. Las revisiones se agregan en una transacción. El historial se preserva en el JSON y se reproduce en el informe exportado. Su integridad depende de los controles de acceso PostgreSQL existentes. Para análisis históricos, Preparar evaluación local construye el expediente sobre los eventos actualmente almacenados de la sesión y registra explícitamente ese origen. Esta operación consume únicamente recursos locales.

Los nuevos análisis incluyen la evaluación automáticamente. Un resultado ya vigente continúa reutilizándose y permite preparar la evaluación desde su detalle. Si llegan eventos posteriores, se debe revisar el estado de actualización de la sesión y generar el análisis correspondiente. Cada evaluación permanece asociada a su conjunto de eventos.

## Informes y actualización

La versión 4 del informe incorpora las instrucciones actuales de evaluación y límites de evidencia. Los resultados anteriores permiten solicitar Actualizar análisis, con consumo del proveedor, cuando corresponda actualizar el formato. La exportación está disponible para todo análisis completado, incluidos los históricos. El servidor verifica conjuntamente sesión y análisis. La vista previa y las descargas usan el mismo identificador de análisis, que también aparece en el nombre del archivo. Cada descarga reconstruye los datos guardados y las revisiones actuales en una lectura consistente de PostgreSQL. Si llegan eventos nuevos, el documento identifica el análisis como desactualizado y diferencia su cobertura de la cronología actual. Los análisis cuya cobertura se desconoce muestran esa limitación. Una sesión sin análisis completado requiere analizarse antes de exportar.

## Pruebas

Las pruebas `tests/test_incident_assessment.py` verifican prioridad, ausencia de confirmación automática, huella del conjunto, rechazo de citas ajenas, severidad requerida y cierre documentado. Las pruebas de análisis existentes cubren las referencias del informe. La compilación TypeScript verifica el formulario. Las revisiones utilizan los endpoints autenticados `/api/analisis/{id}/preparar-evaluacion` y `/api/analisis/{id}/evaluacion-incidente`.
