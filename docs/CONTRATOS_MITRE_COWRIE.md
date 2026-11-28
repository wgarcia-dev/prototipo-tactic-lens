# Contratos de evidencia MITRE ATT&CK para Cowrie

La matriz de Enterprise 20.1 incluye los 867 objetos del catálogo fijado. Hay 706 vigentes, de los cuales 227 son técnicas y 479 subtécnicas. Cada fila conserva el nombre oficial, plataformas, tácticas, jerarquía y fuentes de las analíticas Linux que MITRE asocia con la técnica. Las fuentes oficiales indican qué se podría instrumentar. La presencia operativa de esas fuentes requiere comprobación. [Matriz completa en JSON](MATRIZ_MITRE_ENTERPRISE_20_1.json)

## Alcance por modalidad

| Modalidad | Códigos soportados | Intento explícito | Correlación | Con una vía de resultado observado |
|---|---:|---:|---:|---:|
| Shell, 2222 | 55 | 49 | 5 | 1 |
| Proxy, 2223 | 55 | 50 | 5 | 0 |
| LLM, 2224 | 55 | 50 | 5 | 0 |

Hay 55 códigos únicos, 55 contratos compartidos y 165 combinaciones de código y modalidad. La vía de resultado observado es exclusiva de Shell dentro del contrato compartido T1105. La modalidad para clasificar proviene del sensor registrado en la sesión. Los once contratos históricos que admitían origen desconocido lo siguen admitiendo. Los tres restantes y las reglas nuevas requieren una modalidad registrada.

Las órdenes literales se clasifican como intentos. Shell emula un sistema. Proxy puede interactuar con un Linux aislado, pero una orden o su salida textual no acredita cambios de archivos, procesos ni conexiones. LLM registra una entrada del cliente y puede responder con texto generado. Ese texto tampoco acredita ejecución. Un evento estructurado de reenvío SSH acredita una solicitud. Una descarga HTTP observada por Shell requiere un evento estructurado y un hash o tamaño válido. Ninguno de estos registros acredita un efecto en el anfitrión. [Eventos oficiales](https://docs.cowrie.org/en/stable/OUTPUT.html) · [Proxy](https://docs.cowrie.org/en/stable/PROXY.html) · [Backend LLM](https://docs.cowrie.org/en/stable/LLM.html)

El motor se comprobó también contra las formas de datos de PostgreSQL mediante una consulta de solo lectura. En la muestra histórica se encontraron entradas literales para hostname, uptime y top en lote de una iteración. Esas formas se incorporaron a T1082 y T1057, conservando el grado de intento. Los puertos observados se usan para auditoría. La modalidad de clasificación sigue dependiendo de la identidad registrada del sensor. [T1082](https://attack.mitre.org/techniques/T1082/) · [T1057](https://attack.mitre.org/techniques/T1057/)

En v5, el cruce de las muestras de origen y PostgreSQL vinculó inequívocamente 132 eventos de Shell, 223 de Proxy y 114 de LLM. Se conservaron los campos auditados y la modalidad persistida era desconocida en los 469 casos. El registro confirmó una entrada literal de groups por modalidad. T1069 clasifica esa consulta y getent group como intentos de descubrimiento general. T1069.001 exige una fuente local explícita como files o /etc/group. [T1069](https://attack.mitre.org/techniques/T1069/)

## Activación de la procedencia

La captura versionada admite tres rutas absolutas de directorios distintos mediante COWRIE_LOG_SHELL, COWRIE_LOG_PROXY y COWRIE_LOG_LLM. La cola se prepara con el procedimiento local existente de respaldo y preparación antes de activar las tres rutas. Cada ruta recién registrada conserva su cursor previo. Si el archivo carece de un cursor reconocido, la captura solo continúa después del último registro completo ya presente. Una modalidad se fija por ruta para sesiones cuyo evento de conexión llega a partir de la activación. El emisor conserva el source_id y agrega instance_id únicamente desde los metadatos persistidos en SQLite.

La configuración de destino requiere tres UUID de honeypot ya registrados y distintos del sensor histórico. Se usan HONEYPOT_ID_COWRIE_SHELL, HONEYPOT_ID_COWRIE_PROXY y HONEYPOT_ID_COWRIE_LLM. Un reintento de una ocurrencia SQLite con recibo previo conserva su registro original. Los eventos históricos y la cola anterior conservan su modalidad. El modo de una sola ruta continúa usando COWRIE_LOG.

## Distribución por táctica

| Táctica oficial | Objetos vigentes | Códigos soportados por modalidad |
|---|---:|---:|
| TA0043 Reconnaissance | 46 | 0 |
| TA0042 Resource Development | 51 | 0 |
| TA0001 Initial Access | 22 | 0 |
| TA0002 Execution | 66 | 6 |
| TA0003 Persistence | 113 | 6 |
| TA0004 Privilege Escalation | 96 | 0 |
| TA0005 Stealth | 151 | 1 |
| TA0112 Defense Impairment | 57 | 3 |
| TA0006 Credential Access | 68 | 6 |
| TA0007 Discovery | 49 | 27 |
| TA0008 Lateral Movement | 23 | 0 |
| TA0009 Collection | 41 | 1 |
| TA0011 Command and Control | 45 | 2 |
| TA0010 Exfiltration | 20 | 0 |
| TA0040 Impact | 33 | 3 |

Por modalidad quedan 651 códigos vigentes sin contrato. La matriz clasifica 281 como candidatos que requieren telemetría adicional, 253 como no aplicables a Linux, 97 como actividad fuera de la sesión y 20 como parcialmente observables. Una autenticación del señuelo no basta para T1078.003, leer un archivo cualquiera no basta para T1005 y una transferencia aislada no acredita T1041. Cada fila incluye la evidencia que falta según la táctica y, cuando existe, las fuentes de la analítica Linux oficial. Los casos ambiguos frecuentes incluyen el discriminador específico que falta.

## Contratos añadidos

| Familia | Códigos |
|---|---|
| Descubrimiento | T1007, T1016.001, T1016.002, T1040, T1049, T1069, T1069.001, T1087.001, T1120, T1124, T1135, T1201, T1518, T1518.001, T1518.002, T1614.001, T1652, T1654, T1673, T1680 |
| Ejecución y programación | T1053.002, T1059.001, T1059.006, T1059.007, T1059.011 |
| Persistencia y cuentas | T1053.006, T1098.007, T1543.002 |
| Credenciales | T1003.008, T1110.001, T1110.003, T1552.003, T1552.004 |
| Preparación de datos y reenvío | T1560.001, T1572 |
| Deterioro de defensas | T1222.002, T1685.006, T1690 |
| Impacto solicitado | T1489, T1529, T1531 |

Las correlaciones se limitan a una sesión y agrupan por cuenta, origen o recurso, según el contrato. El archivado exige una orden de lectura seguida de una orden para archivar el mismo recurso en un destino temporal. La persistencia de un servicio systemd requiere enlazar y habilitar la misma unidad en orden. Un bloqueo o deshabilitación intermedio de esa unidad invalida la secuencia citada. Ambas secuencias usan una ventana de cinco minutos y su grado sigue siendo intento. Los patrones de autenticación requieren tres valores distintos pertinentes. El motor usa una huella de igualdad de la contraseña dentro de su evaluación y la excluye de la evidencia devuelta.

## RAG, validación y persistencia

La recuperación híbrida de pgvector y texto añade las técnicas con evidencia aunque superen el presupuesto exploratorio. El muestreo reserva primero las citas necesarias para cada contrato. Con más de 24 candidatos, el modelo recibe una representación compacta con código, nombre, táctica, jerarquía y etiqueta de comportamiento, además de IDs y grados de evidencia. Las salidas de terminal y las respuestas generadas quedan fuera de las entradas del cliente. Los hechos enviados se tratan como datos no confiables y se redactan.

El validador cowrie_contracts_v5 verifica catálogo, plataforma, táctica, modalidad, citas entregadas, suficiencia, contradicciones y grado. Entre propuestas válidas, la subtécnica oficial prevalece sobre el padre si cubre las mismas citas. Si el modelo propone solo el padre y una única subtécnica recuperada valida esas mismas citas y táctica, el servidor aplica esa subtécnica. El servidor registra la justificación del contrato, grado, modalidad, alcance de la fuente, versiones y citas exactas en el esquema existente. La huella del pipeline cambió para evitar reutilizar resultados incompatibles. Los análisis históricos siguen disponibles por sus identificadores.

## Reproducción y evaluación

Este comando genera la matriz con el catálogo local fijado.

~~~powershell
.\.venv\Scripts\python.exe -B -m scripts.inventory_mitre --salida docs/MATRIZ_MITRE_ENTERPRISE_20_1.json
~~~

La evaluación acepta resultados guardados y un conjunto de referencia etiquetado de forma independiente. Cuando los resultados incluyen los códigos recuperados y propuestos en los campos recuperadas y propuestas, informa pérdidas entre etapas. Con el inventario calcula cobertura por táctica oficial y duplicación de jerarquía. Las métricas por modalidad usan la etiqueta de sesión del conjunto de referencia.

~~~powershell
.\.venv\Scripts\python.exe -B -m scripts.evaluate_mitre --etiquetas etiquetas.json --resultados resultados.json --inventario docs/MATRIZ_MITRE_ENTERPRISE_20_1.json
~~~

Los fixtures comprueban semántica, falsos positivos de formas similares, orden, ambigüedad, abstención, citas, modos, catálogo, límite de candidatos y persistencia. La evaluación independiente con telemetría real queda pendiente. Hace falta confirmar procedencia por modalidad en el exportador y revisar muestras anonimizadas antes de medir precisión y recall operativos.

En 210 casos sintéticos dirigidos a 35 contratos de órdenes, con un candidato de fixture por caso, se obtuvieron 105 verdaderos positivos, 0 falsos positivos, 0 falsos negativos y 105 abstenciones. La precisión, recall y F1 fueron 1,00 en este conjunto. La medición describe la regresión de los predicados y el validador sobre estos ejemplos. La recuperación híbrida y la persistencia se verifican por separado con PostgreSQL temporal.

## Archivos de la intervención

| Área | Archivos |
|---|---|
| Contratos, señales y reglas de entrada | backend/rag/mitre_evidence.py, backend/rag/mitre_command_rules.py |
| RAG, muestra y prompt | backend/rag/behavior.py, backend/rag/pipeline.py, backend/rag/retrieval.py |
| Validación, análisis y correlación | backend/rag/validation.py, backend/routes.py, backend/correlation.py |
| Inventario y evaluación | scripts/inventory_mitre.py, scripts/evaluate_mitre.py, backend/rag/evaluation.py |
| Pruebas | tests/test_mitre_contracts.py, tests/test_mitre_modalities.py, tests/test_rag.py, frontend/src/analysis/mitreResults.test.mjs |
| Documentación | docs/CONTRATOS_MITRE_COWRIE.md, docs/MATRIZ_MITRE_ENTERPRISE_20_1.json |
