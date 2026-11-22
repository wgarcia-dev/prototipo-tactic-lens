# Registro de trabajo de TacticLens

Este documento recoge las modificaciones y decisiones de esta conversación. La fecha del nombre identifica el inicio del trabajo. El estado descrito corresponde al cierre de la corrección de informes históricos.

## Contexto

El trabajo partió de `NEW_INSTRUCTIONS.md`, que solicita trazabilidad del análisis LLM, fuentes verificables, validación de referencias, conservación de datos y mejoras de interfaz. El contexto se obtuvo de los archivos del proyecto y los mensajes de esta conversación. El acceso al grafo de codebase-memory devolvió un fallo de transporte y la revisión continuó mediante lectura del código.

La arquitectura utiliza Cowrie, Python, FastAPI, PostgreSQL, DeepSeek y React. El catálogo MITRE STIX local, su búsqueda híbrida y parte de la trazabilidad de IoCs ya existían al iniciar esta conversación.

## Enriquecimiento de observables

Se creó `backend/enrichment.py` y se integró en el flujo anterior a DeepSeek. Reutiliza la extracción determinista de observables, conserva referencias a eventos y mantiene resultados por proveedor.

- MISP Warning Lists admite una copia local y coincidencias de tipo string, hostname y CIDR.
- ThreatFox dispone de consultas opcionales de IP pública, dominio y hash mediante su clave de acceso.
- URLhaus dispone de consulta opcional de SHA-256.
- Las IP privadas y otros alcances no públicos se omiten de las consultas externas de IP.
- Se omiten URLs completas en consultas de reputación y se filtran coincidencias con secretos capturados identificados por el extractor.
- El caché de resultados consultables dura una hora en memoria. Los fallos de conectividad y cuotas se registran como estados del proveedor.

Los resultados quedan en `analisis_llm.resultado_estructurado.enriquecimiento`. La interfaz incorpora Fuentes y evidencias con referencias a eventos y resultados externos. `.env.example` documenta las variables opcionales. La configuración real de secretos se mantiene en los archivos privados de cada instalación.

MITRE Detection Strategies, Analytics, VirusTotal y Cisco XDR se investigaron y documentaron como ampliaciones pendientes. Las integraciones remotas requieren validar credenciales, términos de acceso y funcionamiento en vivo. Las pruebas de enriquecimiento realizadas utilizan respuestas controladas.

## Evaluación formal de incidentes

Se añadió `backend/incident_assessment.py`, con criterios versionados de autenticación fallida, acceso aceptado por el señuelo, interacción con la shell y transferencias registradas. Cada criterio conserva sus eventos. Se calcula prioridad de triaje y una huella SHA-256 del conjunto evaluado.

El componente `frontend/src/analysis/IncidentAssessment.tsx` permite a administradores preparar una evaluación local para resultados históricos y registrar decisiones con justificación, criterio de incidente, impacto, alcance, responsable, medidas y eventos. Las decisiones disponibles son actividad sospechosa, actividad autorizada, evidencia insuficiente e incidente confirmado.

La confirmación exige valorar severidad. El cierre exige documentar criterio y verificación. Las revisiones conservan autor y fecha. El servidor utiliza bloqueo de fila y un número esperado de revisión para resolver conflictos concurrentes. Los cambios se registran en la auditoría existente.

La persistencia reutiliza el JSON del análisis. El historial de revisiones depende de los controles de acceso de la base. La metodología propia del prototipo toma como referencia NIST SP 800-61 Rev. 3 y requiere justificación humana del impacto organizacional.

## Calidad de la narrativa y revisión técnica

Se reforzaron las instrucciones para usar evidencia, alternativas y vacíos de telemetría. Se indicó que expresiones como sistema comprometido requieren evidencia adicional. Cuando las salidas faltan en la entrada del modelo, el informe debe expresar ese alcance con precisión, considerando que Cowrie puede conservar grabaciones TTY.

La interfaz presenta Hipótesis por verificar. La estimación subjetiva del modelo queda en un desplegable. El formato actual tiene versión 4. La actualización explícita de resultados anteriores puede consumir DeepSeek. La consulta y exportación de resultados guardados utilizan los datos persistidos.

Las acciones de MITRE ahora indican Confirmar mapeo y Descartar mapeo. Las de observables indican Confirmar relevancia y Descartar relevancia. Estas decisiones valoran asociaciones y observaciones concretas. La decisión global del incidente se documenta en su evaluación.

## Paginación y navegación

La línea de tiempo se ajustó a 10 eventos por página. Muestra el total de eventos y páginas. Los controles compartidos se ocultan cuando todo cabe en una página y señalan la última página cuando corresponde. Se añadió un icono a Ayuda y soporte.

La captura original mostraba 17 eventos, que antes cabían en una página de 20. Con el tamaño nuevo se distribuyen en dos páginas.

## Informes PDF y Word

Las fechas principales del informe y las tablas de comandos y eventos se muestran en `America/Guayaquil`, con indicación UTC-05:00. La vista de sesión incorpora un mensaje de análisis en curso y un aviso al completarlo. Cuando existe un informe anterior durante la actualización, se identifica como resultado guardado previo.

Se corrigió además la limpieza de errores al reintentar la vista previa y al recibir un informe correcto. Se identificó un backend DemoHTTP anterior que seguía ocupando el puerto 8000 y se reinició conservando Windows `192.168.56.1` y Ubuntu `192.168.56.101`, tras comprobar que no había análisis en proceso. La salud de la API respondió correctamente después del reinicio. Se verificó la generación de datos del informe de la sesión `483f9460d7c0`, con inicio local `2026-11-21 20:07:42 UTC-05:00`. Las fechas de consulta de proveedores y revisión del analista también se convierten a la hora de Ecuador en la exportación.

Se vinculó la exportación con el identificador del análisis seleccionado y su sesión. La vista previa valida ambos identificadores. El nombre de descarga incluye sesión y análisis. Las respuestas usan controles de caché y las solicitudes canceladas se descartan antes de actualizar la vista.

La exportación reconstruye cada documento desde PostgreSQL y conserva los resultados y revisiones del análisis seleccionado. Incluye evaluación del incidente, narrativa, comandos, evidencias, observables, mapeos y fuentes externas disponibles. Las comprobaciones calculadas por reglas se identifican como automáticas.

La condición inicial exigía la versión 4 y cobertura vigente, lo que ocultó informes de sesiones ya analizadas. Se corrigió después de la observación del usuario.

El comportamiento final es el siguiente.

| Situación | Disponibilidad del informe |
| --- | --- |
| Sesión sin análisis completado | Se habilita después del análisis |
| Análisis completado vigente | Vista previa y exportación disponibles |
| Análisis de formato anterior | Disponible con aviso de formato conservado |
| Análisis con eventos posteriores | Disponible con aviso de cobertura desactualizada |
| Cobertura histórica desconocida | Disponible con advertencia de cobertura sin verificar |
| Identificador de análisis de otra sesión | Solicitud rechazada |

En un informe desactualizado, la cronología y los observables reflejan los registros actuales de la sesión. La narrativa y los mapeos reflejan el análisis seleccionado. El documento explica esta diferencia. La actualización del análisis permite incorporar los eventos posteriores a su interpretación.

Se verificó la separación de contenidos entre dos sesiones y la generación de dos PDF diferentes mediante Chromium. La inspección visual de documentos extensos con sesiones reales continúa pendiente.

## Ejecución y diagnóstico de la VM

Las capturas del usuario permitieron identificar la VM de VirtualBox con IP Host-only `192.168.56.101` y Windows con `192.168.56.1`. La conexión SSH a Cowrie en el puerto 2222 se completó.

La instalación mostraba Cowrie en `/home/cowrie/my-honeypot` y el servicio `tacticlens-cowrie-live.service`. `cowrie-ingest.service` estaba retirado y detenido. Sus registros remitían a SQLite y `sqlite_sender.py`. Se localizaron archivos de exportación en `/opt/tacticlens-cowrie`.

Se explicó el uso de HTTP para el backend del laboratorio y se identificó un intento de conexión HTTPS como causa del error TLS mostrado. El inicio local escucha en loopback y el inicio DemoHTTP permite configurar la recepción desde la VM. La recuperación efectiva de la ingesta de esa VM queda pendiente de confirmación mediante eventos persistidos en TacticLens.

Algunas instrucciones iniciales usaban las IP del entorno de dos laptops. Se corrigieron al identificar el entorno real de VirtualBox. También se aclaró la diferencia de sintaxis entre Bash y PowerShell.

## Pruebas de comportamiento sobre Cowrie

Se discutió la combinación de escenarios manuales iniciales y repeticiones automatizadas. Las pruebas se realizan sobre el señuelo SSH. La confirmación de efectos sobre Linux requiere telemetría de una máquina objetivo real.

Se creó `scripts/windows/Probar-Cowrie.ps1`, con 11 escenarios de control, identidad, cuentas, procesos, red local, configuración, archivos, búsqueda, preparación de artefactos inocuos, descargas fallidas y entradas de error o prompt injection.

El script abre sesiones separadas, asigna marcadores únicos, admite selección y repeticiones, y conserva comandos, salida SSH y manifiesto en `.local/pruebas-cowrie/`. OpenSSH puede solicitar credenciales por sesión. Los resultados deben contrastarse con eventos Cowrie. Se validó la sintaxis del script y su ejecución contra el honeypot queda pendiente.

## Verificación realizada

- Las suites completas previas de 251 y 258 pruebas finalizaron correctamente durante distintas etapas del trabajo.
- La suite posterior de 261 pruebas detectó una expectativa de versión 3 en `test_live.py`. Se actualizó para usar `REPORT_VERSION` y las tres pruebas de ese módulo pasaron al repetirlas.
- Las pruebas de integración de informes verifican sesiones distintas, ausencia de análisis, selección de análisis ajeno y compatibilidad histórica.
- Las dos pruebas de exportación PDF pasaron al ejecutar Chromium fuera del entorno restringido. Dentro de ese entorno se produjo un timeout.
- Las 25 pruebas del frontend y la compilación Vite/TypeScript pasaron en las verificaciones anteriores.
- La compilación mantiene un aviso de tamaño del bundle JavaScript.
- La generación de informes y las pruebas descritas evitan llamadas pagadas al LLM.

La corrección final de disponibilidad histórica se valida nuevamente de forma específica. Los resultados del repositorio requieren reiniciar el backend y recargar el frontend de la instalación utilizada para comprobarlos en la aplicación abierta.

## Pendientes identificados

- Confirmar la ingesta actual entre la VM del usuario y PostgreSQL.
- Ejecutar el script de escenarios sobre el Cowrie de laboratorio y contrastar sus marcadores.
- Verificar visualmente informes extensos reales.
- Verificar las nuevas revisiones de incidente desde la cuenta autenticada del usuario.
- Validar proveedores externos con credenciales y conectividad autorizadas.
- Evaluar correlación de incidentes entre sesiones y criterios locales de severidad con etiquetado independiente para la tesis.

## Documentación relacionada

- [Enriquecimiento verificable](ENRIQUECIMIENTO_VERIFICABLE.md)
- [Evaluación de incidentes](EVALUACION_INCIDENTES.md)
- [Instrucciones que iniciaron el trabajo](../NEW_INSTRUCTIONS.md)
- [Script de escenarios](../scripts/windows/Probar-Cowrie.ps1)
