# Primera prueba controlada: DeepSeek + RAG

Estado: **ejecutada tras autorización expresa, una llamada y cero reintentos**.
Véase el [resultado real y revisión de cada técnica](RESULTADO_PRUEBA_REAL_DEEPSEEK_RAG.md).
Lo siguiente conserva el protocolo y la preparación previos a esa ejecución.
Preparación: 16/17 de noviembre de 2026, America/Guayaquil / UTC.

## Sesión y proveedor comprobados

- Sesión: `b100f403-1495-486b-88ee-26f9357681ab` (Cowrie `69ab20a1719e`).
- **15 eventos** originales, incluidos `whoami`, `pwd`, `ls` e `id`.
- Snapshot SHA-256: `25688012970ae153300482a9431e529beae5095958403a68f608642d574f4acd`.
- Proveedor configurado: **DeepSeek**, modelo **`deepseek-v4-pro`**,
  origen **`https://api.deepseek.com`**.
- `GET /models`: **200**, modelo listado y `owned_by=deepseek`.
  Solo se consultaron metadatos; no se enviaron eventos ni se llamó a `/chat/completions`.
  Esto prueba autenticación y disponibilidad del listado, no la generación, saldo suficiente
  o latencia real de una respuesta, que solo se comprobarán en la prueba autorizada.

No se imprimió la clave ni se consultó el saldo de la cuenta. Las comprobaciones de
configuración rechazan HTTP, orígenes distintos al oficial y URLs con credenciales,
consultas o redirecciones.

## Contexto exacto preparado y privacidad

Se ejecutó el constructor real de `real_result()` con el transporte POST sustituido
por un capturador local que interrumpe la operación **antes de cualquier transmisión**.
No se invocó el endpoint de análisis ni se creó una fila `en_proceso`.

- 15/15 eventos suministrados; no fue necesario muestrear esta sesión.
- 22 candidatos con nombre, definición oficial, técnica/táctica, plataformas y procedencia.
- Catálogo Enterprise **20.1**, hash
  `539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5`.
- Relevancia RRF y límites de cobertura incluidos; **no son probabilidades de ataque**.
- Instrucciones de datos no confiables, entorno emulado y abstención conservadas.
- Payload SHA-256:
  `a52762f6bb71a6251041ba0b5bf9bfa9a6f4cda5d6503da054de21637026ab55`.

La auditoría del payload encontró inicialmente una copia de la contraseña capturada
dentro de `message` de un evento de login. **No salió de esta PC**. Se corrigió
`facts_for_model()` para omitir el mensaje redundante de autenticación, ocultar el
usuario de login y redactar copias conocidas de secretos en otros campos o comandos.
No se modificaron los eventos originales ni el mecanismo de autenticación de TacticLens.

La comprobación posterior detectó **cero coincidencias con secretos conocidos**:
campos sensibles de los eventos y valores de credenciales configuradas. No se exportaron
headers Authorization. Esta comprobación y las reglas de redacción no son una garantía
universal ante secretos arbitrarios desconocidos: cualquier contenido no reconocido sigue
requiriendo cuidado antes de compartir un corpus fuera del equipo.

Artefactos privados, ignorados por Git:

```text
.local/rag/ensayo-controlado/payload.json
.local/rag/ensayo-controlado/preflight.json
.local/rag/ensayo-controlado/verificacion.json
```

No subirlos como dataset público: aunque las credenciales estén ocultas, conservan
telemetría local. El preparador usa creación exclusiva para no reemplazar el snapshot.

## Estimación de una llamada

Fuente consultada: [tarifas oficiales de DeepSeek](https://api-docs.deepseek.com/quick_start/pricing/).
Tarifa usada: **hora pico, entrada sin caché**, deliberadamente conservadora para Pro:
**US$1,32 / millón de tokens de entrada** y **US$3,96 / millón de salida**.
El proveedor publica descuentos por caché y horario; no se presupusieron.

| Concepto | Preparación real / escenario |
|---|---:|
| Caracteres de los mensajes serializados | 69.362 |
| Bytes UTF-8 de los mensajes | 69.504 |
| Tokens de entrada aproximados | 21.065–34.937 |
| Salida usada para el intervalo estimado | 2.000–4.000 tokens |
| Límite configurado de salida | 8.192 tokens |
| Costo estimado sin descuentos | **US$0,03573–0,06196** |
| Escenario conservador de entrada por bytes + salida completa | **US$0,12554** |

La estimación no usa un tokenizador exacto de este modelo y **no es un tope contractual**.
Se siguió la [guía oficial de tokens](https://api-docs.deepseek.com/quick_start/token_usage/)
para distinguir estimación de uso facturado. La cifra real requiere `usage` de la respuesta.
El escenario por bytes reserva margen adicional, sin prometer un contador exacto.

Se mantiene temperatura 0, JSON estructurado y `thinking.type=disabled`. No hay herramientas
externas, búsqueda web del proveedor ni inferencias de embeddings remotas. No se ejecutará
ninguna generación hasta la autorización del usuario. La autorización será para **una**
solicitud, sin reintentos automáticos; un timeout o fallo requerirá revisión antes de otra.

## Preparación de la ejecución y validación posterior

Se recargó únicamente FastAPI para activar la redacción corregida y el registro seguro de
`usage`, modelo reportado, hora UTC, duración y hash de la solicitud. Se conservaron las
interfaces y clave de ingesta existentes. Para este proceso se amplió la espera LLM de
60 a **180 segundos**, sin editar `.env`, para reducir reintentos por timeout. Esto no
modifica la caducidad de las sesiones de usuario. Los WebSockets volvieron a conectar.

Después de autorizar:

1. Verificar el preflight sin volver a crear el snapshot y comprobar que no hay un análisis
   nuevo o en curso para esta sesión. Si lo hay, detenerse y revisar; no repetir la llamada.
2. Desde la sesión autenticada con MFA existente, solicitar una sola vez el análisis de
   la sesión seleccionada (`actualizar_rag=true` cuando corresponda). No usar una ruta
   alternativa ni omitir permisos. El backend serializa por sesión y rechaza concurrencia.
3. Revisar el resumen y las fases, distinguiendo hecho, inferencia, intento y resultado en
   Cowrie. Los comandos no prueban ejecución en el Ubuntu anfitrión.
4. Comprobar técnicas, tácticas oficiales, IDs de evidencia, justificaciones y límites.
   Recuperar un candidato no equivale a detectarlo; técnicas incompatibles deben descartarse.
5. Revisar `mapeos_descartados`, razones y posibles abstenciones. No confirmar automáticamente.
6. Comprobar que todos los nuevos mapeos permanecen **pendientes** y que los históricos
   continúan disponibles. No cambiar sus estados durante esta comprobación.
7. Ejecutar el verificador de solo lectura y presentar resultado, latencia y costo basado
   en tokens reales. No ejecutar un segundo análisis para probar reutilización de forma
   ciega: primero comprobar el resultado guardado; la reutilización ya tiene pruebas mock.

```powershell
.\.venv\Scripts\python.exe -m scripts.verify_deepseek_trial
```

El verificador compara los hashes de todas las filas anteriores de sesiones, eventos,
análisis, acciones, enlaces y mapeos; permite nuevas filas sin modificar las anteriores.
Exige como máximo un análisis nuevo de esta sesión, mismo snapshot, modelo, catálogo y
hash del payload aprobado. Comprueba duplicados de `(id_accion,id_vinculo)` y revisión
pendiente. Después de una ejecución genera `resultado-revisable.json` privado con resumen,
acciones, informe, evidencias, justificaciones, descartes, estados y metadatos del proveedor.

Estado **antes de generar**, realmente comprobado:

- 125 sesiones, 1.493 eventos, 5 análisis, 7 acciones y 7 mapeos.
- Cero filas anteriores faltantes/modificadas.
- Cero parejas de mapeo duplicadas.
- **Cero análisis nuevos** para esta sesión.
- Un análisis histórico de esta sesión sigue disponible. Abarcaba 10 eventos, por lo que
  **no sirve de baseline pareada frente al nuevo snapshot de 15 eventos**.

## Comparación posterior sin RAG / con RAG

Se añadió `scripts/compare_deepseek_trials.py`, sin acceso a red ni llamadas LLM. Reutiliza
las métricas de `backend/rag/evaluation.py`. Se prepararon tres plantillas privadas:

```text
.local/rag/ensayo-controlado/comparacion-dataset.plantilla.json
.local/rag/ensayo-controlado/sin_rag.plantilla.json
.local/rag/ensayo-controlado/con_rag.plantilla.json
```

La primera sesión está **sin etiquetar**, no se inventó un gold standard a partir de los
candidatos del propio RAG. Antes de comparar:

1. Reunir sesiones positivas, negativas y ambiguas. Congelar IDs, eventos y SHA-256 de cada
   snapshot y redactar de la misma manera en ambas variantes.
2. Un revisor humano debe etiquetar evidencias con el catálogo oficial, sin usar las
   salidas del modelo como verdad. Marcar `etiquetado=true` solo después de revisar;
   `esperados=[]` significa negativo revisado, no tarea pendiente.
3. Fijar el mismo modelo/versionado, temperatura, modo de razonamiento, límites de salida
   y contrato JSON/evidencia. Definir y congelar un prompt común con SHA-256 para ambos.
   La diferencia experimental debe ser el contexto oficial recuperado, no cambios en
   las instrucciones, la redacción o los eventos. Una baseline sin RAG no debe quedar
   obligada por error a escoger de una lista vacía de candidatos ni del antiguo límite
   de diez códigos. Puede validar identificadores contra el catálogo sin suministrar
   definiciones recuperadas. Documentar la política exacta antes de ejecutar ambos brazos.
4. Registrar propuestas crudas y aceptadas por separado, descartes y evidencias. Aplicar
   reglas comunes de evaluación para no atribuir a recuperación una mejora producida
   solamente por filtrar resultados de una variante.
5. Obtener autorización aparte para el lote de llamadas; no se ha preparado un ejecutor
   que las dispare automáticamente. Esta primera prueba es un **piloto**, no un estudio A/B.
6. Registrar `estado=completado`, snapshot, tokens, duración y costo por sesión/variante.
   El comparador rechaza sesiones distintas, snapshots diferentes, parámetros/modelos o
   prompts no coincidentes, etiquetas pendientes y ejecuciones fallidas.

Cuando las copias de trabajo estén cumplimentadas:

```powershell
.\.venv\Scripts\python.exe -m scripts.compare_deepseek_trials `
  --dataset .local/rag/ensayo-controlado/comparacion-dataset.json `
  --sin-rag .local/rag/ensayo-controlado/sin_rag.json `
  --con-rag .local/rag/ensayo-controlado/con_rag.json
```

Calcula precisión/recall/F1 micro sobre propuestas y aceptadas, abstención de negativos
y, si se guardan candidatos ordenados, Recall@K **solo de recuperación RAG**. No confunde
Recall del buscador con exactitud del análisis. Las cifras son descriptivas: independencia,
suficiencia de muestras y revisión de evidencias requieren evaluación humana. El programa
no declara mejora automáticamente, ni con una sesión favorable.

## Cambios y pruebas de esta preparación

- `backend/rag/pipeline.py`: redacción de copias conocidas de credenciales y mensajes de login.
- `backend/routes.py`: hash del body y metadatos seguros del proveedor en los análisis nuevos.
- `scripts/prepare_deepseek_trial.py`: preflight de solo lectura con POST interceptado localmente.
- `scripts/verify_deepseek_trial.py`: comprobaciones antes/después, sin generación ni escrituras SQL.
- `scripts/compare_deepseek_trials.py`: comparación offline de snapshots pareados.
- Pruebas añadidas/adaptadas en `tests/test_rag.py`, `tests/test_analysis.py` y
  `tests/test_deepseek_trial.py`.

**23 pruebas unitarias ejecutadas y aprobadas**: privacidad, contrato/proveedor simulado,
uso retenido, protección de origen, bloqueo por secretos, estimación y comparación pareada.
No ejecutan importaciones de catálogo ni escrituras PostgreSQL. No se repitió toda la batería
porque esta preparación no toca autenticación, ingesta ni WebSockets.

No hubo migraciones, modificaciones del catálogo o de datos históricos, cambios de
autenticación/MFA ni push. La llamada real se ejecutó posteriormente con autorización;
su resultado, consumo y limitaciones están en el informe enlazado al inicio.
