# DeepSeek + RAG MITRE ATT&CK en TacticLens

Fecha de ejecución: 16 de noviembre de 2026, America/Guayaquil (17 de noviembre UTC).
Repositorio y rama existentes: `codex/integracion-colaborativa-http`.

## Resultado y alcance

Implementación integrada con FastAPI, SQLAlchemy Core, PostgreSQL y React existentes.
DeepSeek continúa siendo el proveedor del análisis, que sigue siendo **manual por sesión**.
No se alteraron autenticación, MFA, permisos administrativos, captura Cowrie, exportador
SQLite ni WebSockets. No se hizo push ni se llamó al proveedor LLM real durante las pruebas
automatizadas. El 17 de noviembre se completó [una prueba real expresamente autorizada](RESULTADO_PRUEBA_REAL_DEEPSEEK_RAG.md),
con tres propuestas pendientes y revisión de su evidencia.

El catálogo Enterprise 20.1 completo está importado. La búsqueda híbrida y los embeddings
en CPU funcionan con PostgreSQL real. El flujo de análisis se comprobó con recuperación
real y DeepSeek simulado; la llamada real posterior también funcionó. Falta la evaluación
de calidad con etiquetas independientes. Los resultados sintéticos no demuestran que RAG
clasifique mejor que el método anterior.

## Protección previa y conservación de datos

Antes de modificar código se creó el commit **`eaeeb73`**:
`Respaldo: monitoreo Cowrie por eventos, WebSocket y auditoria MITRE`.
La auditoría previa permanece en `docs/AUDITORIA_MITRE_ATTCK.md` como diagnóstico
histórico del método anterior; este documento describe su sustitución para análisis nuevos.

Se tomó un `pg_dump -Fc` completo antes de la migración:

```text
C:\Users\user\Documents\tesis\prototipo-tactic-lens\.local\rag\private\TacticLens_antes_RAG_20261117T032238Z.backup
```

- Tamaño: **408.201 bytes**.
- SHA-256: `fe006f599fa4e6445501b5d4a9845c5669e8b3afb456032421d314b2e1d73282`.
- `pg_restore --list`: válido, **269 entradas** en el índice.
- Decodificación completa con `pg_restore --file NUL`: correcta.
- No se restauró sobre ninguna base. Esta comprobación no sustituye un ensayo de
  restauración en una base aislada.
- Copia, manifiesto privado, modelos y resultados locales están dentro de `.local/`,
  ignorada por Git. No se incorporaron credenciales ni archivos `.env` reales.

`scripts/verify_rag_snapshot.py` compara PK y hashes de las columnas que existían
antes de migrar. Las columnas añadidas no producen falsos cambios. Comprobación real:

| Tabla | Registros anteriores | Faltantes | Modificados |
|---|---:|---:|---:|
| sesion | 125 | 0 | 0 |
| evento | 1493 | 0 | 0 |
| evento_origen | 1490 | 0 | 0 |
| analisis_llm | 5 | 0 | 0 |
| accion_identificada | 7 | 0 | 0 |
| accion_evento | 12 | 0 | 0 |
| mapeo_mitre | 7 | 0 | 0 |
| ioc | 3 | 0 | 0 |
| observacion_ioc | 1490 | 0 | 0 |
| usuario | 4 | 0 | 0 |
| auth_factor | 4 | 0 | 0 |

Los accesos posteriores de usuarios pueden actualizar legítimamente actividad y
metadatos MFA; esta tabla representa la comprobación posterior a la implementación.
Las definiciones MITRE sí se actualizan desde STIX; se conservan sus claves, FK y
asociaciones históricas. Los análisis históricos guardados no se reescriben.

## PostgreSQL y migraciones

Estado comprobado en esta PC:

| Elemento | Resultado |
|---|---|
| Base | `tactic-lens-db` |
| PostgreSQL | **18.3**, puerto **5432** |
| Extensión `vector` | disponible y habilitada, **0.8.7** |
| Operador coseno `<=>` | probado; distancia entre vectores ortogonales = **1,0** |
| Columna anterior | `embedding_descripcion vector(768)`, conservada |
| Columna nueva | `embedding_rag vector(384)` |
| Índices | GIN de texto y HNSW de coseno creados |

No fue necesario instalar pgvector, reinstalar PostgreSQL ni tocar el directorio de datos.
La referencia para otra PC es la [instalación oficial de pgvector en Windows](https://github.com/pgvector/pgvector#windows).

Se aplicó **`009_rag_mitre.sql`** con el migrador existente. SHA-256 registrado:
`4dcd3970303d8ff08b47bac0b1eb093116e01f653e26e1a305422f3947ca14db`.
Las migraciones anteriores conservan sus checksums. Los dos archivos `007_*` existentes
se mantienen. **`008_limpieza_dominios.sql` continúa diferida y no se ejecutó**: el migrador
ya la excluye por ser una limpieza destructiva de evidencia. No se renumeró ni eliminó.

Cambios aditivos de 009:

- Nueva `catalogo_mitre`: dominio, versión, fuente, SHA-256, conteos, fecha de importación,
  unicidad dominio/versión y un catálogo activo por dominio.
- `modelo_embedding`: configuración reproducible JSONB y dimensiones admitidas 384/768.
- `tactica_mitre` y `tecnica_mitre`: catálogo, versión STIX, revocación y deprecación.
- Técnicas: plataformas, indicador de subtécnica, procedencia de jerarquía, hash del objeto,
  vector RAG, modelo, hash del texto y documento de búsqueda generado en inglés.
- `tecnica_tactica`: catálogo y vigencia de la relación. Las filas históricas no se eliminan.
- `mapeo_mitre`: `rag_procedencia` JSONB y `grado_evidencia` opcional. Sus valores anteriores
  quedan sin reinterpretar; el estado de revisión existente se conserva.

## Catálogo oficial importado

Fuente fijada: [MITRE attack-stix-data, Enterprise 20.1](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v20.1/enterprise-attack/enterprise-attack.json).

SHA-256 verificado del bundle:
`539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5`.

| Contenido real | Cantidad |
|---|---:|
| Tácticas | 15 |
| Técnicas y subtécnicas | 867 |
| Subtécnicas, incluidas dentro de las 867 | 497 |
| Relaciones técnica–táctica | 1099 |
| Técnicas revocadas | 149 |
| Técnicas deprecadas | 12 |
| Técnicas vigentes y representadas por embeddings | 706 |

`backend/rag/catalog.py` valida estructura, códigos, jerarquías y checksum antes de escribir.
La importación usa una transacción y un advisory lock compartido con la persistencia RAG.
Reimportar la misma versión conserva IDs, vínculos y vectores sin duplicarlos. Si cambia
el checksum de una versión registrada, se exige revisión explícita en lugar de sobrescribirla.

El bundle carece de relaciones `subtechnique-of` para **16 subtécnicas revocadas**. Solo
para esos objetos se conserva el padre numérico cuando existe, identificado como
`jerarquia_fuente=codigo_revocado`; no se presenta como relación STIX. La ausencia de
padre de una subtécnica vigente se rechaza. Las jerarquías explícitas usan `stix`.

## Modelo de embeddings reproducible

- Modelo: **`sentence-transformers/all-MiniLM-L6-v2`**, inglés.
- Revisión: **`1110a243fdf4706b3f48f1d95db1a4f5529b4d41`**.
- Licencia: **Apache-2.0**, según la [ficha oficial y archivos fijados](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/tree/1110a243fdf4706b3f48f1d95db1a4f5529b4d41).
- Artefacto: `onnx/model_quint8_avx2.onnx`, **23.046.789 bytes**, inferencia CPU.
- Dimensión: **384**; truncamiento a **256 tokens**, media con máscara de atención y L2.
- Motor: `onnxruntime==1.23.2`, `CPUExecutionProvider`, dos hilos intra-op.
- Dependencias opcionales: `numpy==2.2.6`, `tokenizers==0.23.3`, en `requirements-rag.txt`.
- Sin GPU, Torch, inferencia remota ni ejecución de código descargado del modelo.

Los SHA-256 de modelo/tokenizador/configuración están fijados en `embeddings.py` y se
verifican al preparar y cargar. El manifiesto se guarda junto a los artefactos y en
`modelo_embedding.configuracion`. El vector referencia modelo, catálogo, objeto STIX y
hash del texto normalizado. Solo se vuelve a generar cuando cambia el contenido/modelo
o falta el vector. Una actualización concurrente del catálogo no puede guardar un vector
obsoleto: cada escritura comprueba catálogo y hash del objeto.

Generación real: **706 vectores en 27,52 s**. Segunda ejecución: **0 regenerados**, 706
vigentes, **0,62 s**. La búsqueda rechaza un catálogo incompleto en lugar de clasificar
silenciosamente con una fracción de sus embeddings.

`RAG_MODEL_DIRECTORY` es la única variable nueva, **opcional**. Por defecto usa
`.local/rag/models/minilm` dentro del proyecto. No requiere claves. No se modificó el
`.env` privado ni las variables DeepSeek ya configuradas.

## Flujo de recuperación y análisis

1. El usuario abre una sesión y solicita candidatos o pulsa analizar manualmente.
2. FastAPI lee los eventos originales de PostgreSQL, sin recapturar ni reinsertar Cowrie.
3. `behavior.represent()` produce acciones canónicas, orden temporal, conteos e indicación
   de intento/resultado. **No utiliza el JSON completo como consulta vectorial.**
4. Solo etiquetas técnicas en inglés llegan al codificador; contraseñas, argumentos,
   salidas, IP, URLs arbitrarias e instrucciones capturadas no entran en los embeddings.
5. `retrieval.search()` consulta coseno pgvector y FTS de PostgreSQL. Fusiona rankings con
   RRF `sum(1/(60+posición))`, elimina códigos repetidos y filtra revocadas/deprecadas.
   Se consultan también comportamientos individuales para recuperar varias técnicas.
6. `pipeline.evidence_sample()` acota el prompt a un máximo de 80 eventos, conservando
   contexto y secuencia; declara el muestreo. Se entregan a DeepSeek hasta 24 candidatos
   con definiciones oficiales y procedencia. El contexto computado resume todo el snapshot.
7. La instrucción mantiene el informe narrativo existente y añade el contrato RAG:
   múltiples propuestas o abstención, técnica/táctica, evidencia, justificación y límites.
8. `validation.validate()` filtra propuestas; `persist_findings()` revalida catálogo,
   hash de definición y relación técnica/táctica dentro de la transacción final.
9. Se guardan análisis, acciones, enlaces a eventos, IoCs y propuestas de forma atómica.
   **Todos los mapeos nuevos permanecen pendientes de revisión**, con independencia del score.

`COWRIE_TECHNIQUES` ya no limita la clasificación nueva. La constante solo permanece
por compatibilidad con el auxiliar histórico `backfill_mappings.py`, que no se ejecutó
en esta intervención. No debe usarse ese auxiliar para sustituir el pipeline validado.

### Validación semántica y límites de observabilidad

La búsqueda considera las 706 técnicas vigentes; la elegibilidad de una propuesta
requiere además un perfil compatible con evidencia Cowrie y plataformas aplicables.
Los perfiles se derivan de nombres oficiales, no de una lista fija de diez códigos.
Incluyen descubrimiento, transferencia, autenticación repetida, shell, borrado,
creación de cuentas, claves SSH, cron, archivado y limpieza de historial.

Esto amplía la cobertura, pero sigue siendo una **cobertura explícita y limitada**.
Una técnica sin perfil figura como fuera de cobertura aunque se recupere por similitud.
Importar todo ATT&CK no implica poder detectar todo ATT&CK. Los perfiles son controles
heurísticos, no una demostración automática de corrección semántica; la revisión humana
sigue siendo necesaria, especialmente en comandos ambiguos y técnicas de persistencia.

Se comprueban existencia, vigencia, táctica oficial, IDs de evidencia de la sesión/acción,
justificación no vacía ni predeterminada, limitaciones y duplicados por acción/táctica.
`pwd → T1105` se descarta por incompatibilidad de comportamiento. Un `wget` es intento;
solo telemetría `cowrie.session.file_download` con hash válido o tamaño positivo admite
`resultado_en_honeypot`. Ni eso afirma ejecución en el Ubuntu anfitrión.

Los comandos son datos no confiables. Se redactan credenciales y se ordena al modelo
ignorar instrucciones capturadas. Esto reduce riesgo de prompt injection, sin prometer
que un prompt por sí solo lo elimine. La validación backend sigue siendo obligatoria.

### Procedencia e historial

Cada análisis nuevo guarda `rag.metodo=deepseek_rag_mitre_v1`, catálogo, hash, modelo
embeddings/revisión, modelo/proveedor LLM configurados, candidatos y muestreo.
Cada mapeo guarda STIX ID, versión de objeto, hash de definición, evidencia, limitaciones
y relevancia de recuperación. Se conservan los estados pendiente/confirmado/descartado
y los responsables de revisión existentes.

Los análisis anteriores se presentan como históricos (`deepseek_legacy`). Por defecto
se reutilizan resultados vigentes. El botón **Analizar con RAG** usa
`actualizar_rag=true` para crear otro análisis; no reescribe el anterior.

## Endpoints e interfaz

| Endpoint | Comportamiento |
|---|---|
| `GET /api/mitre/catalogo` | Versión, procedencia, cantidades y disponibilidad de embeddings |
| `POST /api/sesiones/{id}/mitre/candidatos` | Consulta local manual, sin LLM, con CSRF y límites por cuenta/IP |
| `POST /api/sesiones/{id}/analizar` | Pipeline DeepSeek + RAG; `actualizar_rag=true` permite ampliar un resultado histórico |
| `GET /api/analisis/{id}` | Añade estado de revisión, grado y procedencia a los mapeos |
| `GET /api/mitre/mapeos` | Añade procedencia y metadatos de revisión |

Todos conservan la autenticación y autorización existentes. La revisión administrativa
continúa en su endpoint original. No se publica un endpoint de embeddings arbitrarios.
`RagCandidates.tsx` añade **Consultar candidatos** al detalle de sesión, con carga,
errores y cancelación al cambiar de sesión. No hay consulta automática al montar ni
llamadas al LLM por cada notificación WebSocket. Los puntajes se etiquetan como relevancia,
**no probabilidad de ataque**.

## Resultados de recuperación y evaluación

Comprobaciones reales de recuperación local:

| Comportamiento | Primer candidato verificado |
|---|---|
| Información del sistema / `uname` | T1082 |
| Usuario actual / `whoami` | T1033 |
| Transferencia con `wget`/`curl` | T1105 |

También se verificó recuperar **T1098.004** con escritura de `authorized_keys`, fuera de
los diez códigos anteriores, y varios candidatos de diferentes comportamientos por sesión.

`tests/fixtures/rag_retrieval_dev.json` contiene **20 casos sintéticos de desarrollo**,
17 con técnicas relevantes etiquetadas. Incluye positivos, desconocidos y negativos como
`pwd`/transferencia y texto de prompt injection. Resultado real de `scripts.evaluate_rag`:

| Métrica de recuperación | Resultado |
|---|---:|
| Recall@5 | 0,9412 |
| Recall@10 | 1,0000 |
| Recall@20 | 1,0000 |

Los casos sin relevantes no entran en el denominador de Recall. La abstención y los
rechazos se prueban aparte. El conjunto fue usado en desarrollo, **no es independiente**.
No se midió exactitud operativa de clasificación ni se compararon respuestas reales de ambos LLM.
**Todavía no se ha demostrado mejora de DeepSeek + RAG frente a DeepSeek anterior.**

El evaluador permite otro dataset independiente y archivos de predicciones de ambos
pipelines para los mismos casos. Calcula Recall y métricas descriptivas micro de
clasificación/abstención; nunca llama a DeepSeek ni declara mejora automáticamente.

## Pruebas ejecutadas

- Suite Python completa: **209 pruebas aprobadas**, ejecución final en **45,35 s**
  con DeepSeek y SMTP reales bloqueados. Incluye autenticación, ingesta, consultas,
  WebSockets, exportador y regresiones existentes.
- Suite RAG ampliada: **25 pruebas aprobadas**, PostgreSQL y embeddings reales, LLM simulado.
- Frontend: **20 pruebas aprobadas**; `npm run build` correcto.
- PowerShell: **9 comprobaciones aprobadas**, firewall simulado, sin modificar reglas.
- Verificación de huellas históricas: ninguna fila original faltante o modificada.
- FastAPI activo con PostgreSQL conectado y contrato de ingesta `tacticlens.ingesta.v2`;
  React escuchando en `127.0.0.1:5173`. El catálogo sin sesión devuelve **401**.
- Comprobación visual con sesión autenticada y MFA: **correcta**. En la sesión
  `b100f403-1495-486b-88ee-26f9357681ab` (15 eventos, incluidos `whoami`, `ls` e `id`),
  el botón **Consultar candidatos** mostró **22 candidatos ATT&CK 20.1**, entre ellos
  T1059, T1059.004, T1033 y T1083. Se comprobaron definiciones, tácticas, advertencias
  de cobertura, relevancia RRF y la identificación del análisis anterior conservado.
  No se pulsó analizar ni se ejecutó DeepSeek. Evidencia visual local privada:
  `.local/rag/rag-verificado.jpg`.

Las suites existentes cubren autenticación y sus validaciones por regresión. La suite RAG
cubre representación segura, comandos desconocidos, redacción, intentos
repetidos, metadatos de transferencia, técnicas/tácticas incorrectas, evidencia ajena,
duplicados, propuestas múltiples, abstención, revisión, reutilización, ampliación de
históricos, generación reanudable, importación idempotente y rollback tras un fallo
intermedio. No se envían correos ni se consumen créditos LLM.

La compilación informa advertencias existentes de React Router (`use client`) y un
bundle de aproximadamente 753 kB; no bloquean la compilación. No se introdujo una
reestructuración de bundles ajena al alcance.

Comandos de reproducción, con PostgreSQL, catálogo y artefactos locales preparados:

```powershell
.\.venv\Scripts\python.exe -m scripts.test_offline
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/test_firewall_demo.ps1
cd frontend
npm.cmd test
npm.cmd run build
cd ..
```

La suite usa rollback para sus fixtures PostgreSQL. Su prueba de concurrencia utiliza
un esquema temporal de prueba, sin borrar datos de la aplicación. El guard global del
ejecutor bloquea los transportes externos; cada prueba puede sustituirlos por mocks.

## Archivos creados y modificados

| Grupo | Archivos |
|---|---|
| Servicios nuevos | `backend/rag/{catalog,embeddings,behavior,retrieval,pipeline,validation,evaluation}.py`, `__init__.py` |
| Backend adaptado | `backend/api.py` (solo reflexión), `backend/routes.py`, `backend/analysis_state.py` |
| Base de datos | `database/migrations/009_rag_mitre.sql` |
| Herramientas | `scripts/import_mitre.py`, `scripts/embed_mitre.py`, `scripts/evaluate_rag.py`, `scripts/verify_rag_snapshot.py`, `scripts/test_offline.py` |
| React | `frontend/src/analysis/RagCandidates.tsx`, `frontend/src/analysis/AnalysisNarrative.tsx`, `frontend/src/main.tsx` |
| Pruebas | `tests/test_rag.py`, `tests/fixtures/rag_retrieval_dev.json`; fixtures adaptados en `test_analysis.py`, `test_collaborative_integration.py`, `test_live.py` |
| Configuración/documentación | `requirements-rag.txt`, `.env.example`, `README.md`, este documento |

## Reproducción y prueba manual

Esta PC **ya tiene** la migración, catálogo, dependencias y modelo preparados. No es
necesario repetir la preparación para consultar candidatos. Los siguientes comandos
documentan la reproducción desde PowerShell en la raíz del repositorio, con su `.env`
privado existente y un respaldo verificado antes de migrar:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-rag.txt
.\.venv\Scripts\python.exe -m scripts.migrate
.\.venv\Scripts\python.exe -m scripts.import_mitre --descargar
.\.venv\Scripts\python.exe -m scripts.embed_mitre --preparar-modelo
.\.venv\Scripts\python.exe -m scripts.evaluate_rag
.\.venv\Scripts\python.exe -m scripts.test_offline
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/test_firewall_demo.ps1
cd frontend
npm.cmd test
npm.cmd run build
```

La primera descarga STIX/modelo requiere Internet; después el buscador funciona localmente
en CPU. DeepSeek sigue necesitando su conectividad habitual para analizar. Los tests RAG
necesitan el catálogo y modelo preparados; no se marcan como aprobados si faltan.

Arranque existente en dos terminales, cuando no estén ya activos:

```powershell
.\scripts\windows\Iniciar-DemoHTTP.ps1 -UbuntuHost 192.168.0.103
.\scripts\windows\Iniciar-Frontend.ps1
```

1. Abrir `http://127.0.0.1:5173/`; iniciar sesión y completar MFA.
2. Abrir **Sesiones y eventos** y una sesión con comandos.
3. Pulsar **Consultar candidatos**. Verificar versión 20.1, técnicas y aviso de relevancia.
   Esto no consume DeepSeek ni crea mapeos.
4. Cuando se desee consumir una llamada manual con el proveedor configurado, pulsar
   **Analizar** o **Analizar con RAG**. Revisar evidencias y limitaciones, sin equiparar
   comandos emulados con ejecución en Ubuntu.
5. Como administrador, revisar las propuestas pendientes. Confirmar/descartar conserva
   los permisos y auditoría existentes. Un score alto nunca confirma por sí solo.
6. Consultar los análisis anteriores y comprobar que siguen disponibles como históricos.

Para volver a comprobar las huellas del respaldo local:

```powershell
.\.venv\Scripts\python.exe -m scripts.verify_rag_snapshot
```

El puntero privado solo existe en esta PC. En otra, utilizar `--manifest RUTA_PRIVADA`
con el manifiesto del respaldo correspondiente; no publicarlo.

## Limitaciones y comprobaciones pendientes

- La [primera prueba controlada con DeepSeek](PRUEBA_CONTROLADA_DEEPSEEK_RAG.md) se ejecutó
  una sola vez tras autorización, con [resultado real documentado](RESULTADO_PRUEBA_REAL_DEEPSEEK_RAG.md).
  Incluye la corrección de redacción detectada al inspeccionar el payload real.
  En esa preparación posterior se ejecutaron 23 pruebas unitarias específicas; la suite
  completa de 209 arriba corresponde al cierre de la fase de implementación anterior.
- Se ejecutó una llamada real con los nuevos candidatos: tres propuestas coherentes como
  intentos, con matices narrativos pendientes de revisión. Los escenarios de error siguen
  verificados con proveedor simulado, sin gastar créditos en fallos deliberados.
- Hace falta un corpus etiquetado independiente y una comparación controlada de ambos
  pipelines antes de afirmar mejora de calidad.
- Los perfiles semánticos son conservadores y deben ampliarse con evidencia etiquetada;
  la similitud por sí sola nunca valida una técnica. Se permite abstención.
  Flags, alias, redirecciones y comandos compuestos pueden requerir interpretación humana;
  reconocer el nombre de una utilidad no prueba por sí solo intención ni éxito.
- Los prompts grandes se muestrean y las definiciones se recortan; no se promete cobertura
  exhaustiva de cada comando de sesiones largas ni del catálogo completo en una llamada.
- Solo se importó Enterprise 20.1. Cambiar de versión/modelo exige actualizar las constantes,
  revisar fuentes y reproducir importación/embeddings; no hay actualizaciones silenciosas.
- Al cerrar esta fase no se había ensayado la restauración. En la preparación posterior
  del 18/11/2026 sí se verificó una restauración aislada completa y transferencia privada;
  ver [MIGRACION_NUEVA_PC.md](MIGRACION_NUEVA_PC.md). Para trasladar una base existente,
  seguir esa guía, **sin repetir las migraciones, importaciones o seeds de esta sección**.
  No se desplegó a producción.
