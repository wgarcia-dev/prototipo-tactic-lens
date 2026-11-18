# Continuidad de desarrollo: IoCs y salvaguardas

Auditoría del código local: **18 de noviembre de 2026**. La prioridad es desarrollar
con los históricos restaurados en una sola PC Windows. No hace falta activar Cowrie
para consultar evidencia, recuperar candidatos MITRE o probar servicios con mocks.

## Estado implementado de IoCs

| Capacidad | Implementación real | Límites actuales |
|---|---|---|
| Extracción determinista | `backend/intelligence.py:observables()` | IP de origen; IPv4 escrita en comandos; URL HTTP(S), dominios y hashes presentes en comandos. No reputación externa |
| Normalización | `ipaddress`, dominios/hashes en minúsculas | Normalización de URL parcial; no canonicalización exhaustiva ni cobertura de toda sintaxis de shell |
| Deduplicación | `persist_observables()` y unicidad `(id_tipo_ioc,valor)` | Equivalencias semánticas entre URLs diferentes requieren trabajo adicional |
| Evidencia | `observacion_ioc` → `evento` → `sesion`; unicidad por observable/evento | Una aparición no acredita malicia. Un archivo escrito como texto no prueba descarga |
| Propuestas LLM | `backend/routes.py:real_result()`, `analyze()`, `persist_findings()` | Tipos permitidos y evidencia perteneciente a la acción/sesión; valores deben aparecer en el evento. Ejecución manual |
| Contexto de análisis | `deteccion_ioc`, `accion_ioc`, `accion_identificada`, `accion_evento`, `analisis_llm` | Hay relaciones existentes; no es todavía un motor de correlación multisesión |
| Consulta | `GET /api/iocs`, paginación; origen y cantidad de evidencias | El listado devuelve una evidencia/sesión representativa. No hay endpoint completo de todas las evidencias por IoC ni filtros avanzados de IoCs |
| Interfaz | `frontend/src/main.tsx:ListingPage`, ruta `/iocs` | Tabla, enlaces a sesión y revisión; no buscador avanzado ni grafo de inteligencia |
| Revisión administrativa | `PATCH /api/inteligencia/ioc/{id}/revision`, `review_intelligence()` | Requiere administrador y auditoría. Aplica la decisión a las observaciones del IoC; no es revisión individual por contexto |

Las relaciones históricas y los campos de revisión están en `007_inteligencia.sql` y en
el esquema PostgreSQL. `backfill_detections()` conserva evidencia LLM en la lista unificada;
no debe ejecutarse una limpieza de dominios para trasladar la base.

El respaldo actual conserva **3 observables, 1.490 observaciones, 125 sesiones y 1.493
eventos**, además de detecciones y relaciones. Son los datos reales disponibles, no un
dataset nuevo generado para aparentar actividad. El prototipo no debe presentar una IP
capturada como compromiso confirmado ni consultar una URL capturada como si fuera confiable.

## Salvaguardas: lo existente y lo que falta

**Existe** `BehaviorReport.recomendaciones` en `backend/analysis_report.py`: una lista de
textos defensivos dentro del informe JSON guardado en `analisis_llm`. El prompt exige
recomendaciones proporcionales a los hechos, sin ejecutar comandos. La interfaz
`AnalysisNarrative.tsx` permite leerlas junto con fases, evidencia y limitaciones.

**No existe todavía un módulo integral de salvaguardas**. La inspección del esquema,
rutas y componentes no encontró una entidad o flujo propio que permita:

- Asociar cada recomendación individual a IoCs, técnicas y eventos concretos mediante FK.
- Guardar una justificación estructurada por salvaguarda, prioridad y alcance.
- Gestionar propuesta, revisión, aprobación, rechazo, implementación y seguimiento.
- Distinguir automáticamente medidas proporcionadas de recomendaciones especulativas.
- Aplicar mitigaciones o modificar infraestructura desde TacticLens.

La tabla SQL `revision_analisis` está vacía y no constituye por sí sola una funcionalidad
de revisión de salvaguardas. No debe afirmarse que ese workflow esté implementado.
La revisión de mapeos MITRE y observaciones IoC sí está operativa y es un patrón reutilizable.

## Base disponible para continuar

- FastAPI + SQLAlchemy Core + PostgreSQL 18/pgvector; misma arquitectura.
- React/Vite, roles Administrador/Analista, cookies, CSRF y MFA obligatorio.
- Históricos, análisis y propuestas conservados; ningún registro se confirma por un score.
- DeepSeek configurado por `.env`, manual por sesión. Su uso real requiere Internet,
  credenciales y autorización para gastar créditos; los tests usan mocks.
- Catálogo Enterprise 20.1: 867 técnicas/subtécnicas y 706 vectores vigentes.
- MiniLM local en CPU, 384 dimensiones; búsqueda híbrida sin proveedor remoto de embeddings.
- Validación de técnicas/tácticas/evidencia y revisión administrativa auditada.
- Dashboard de históricos y WebSocket local que puede permanecer conectado sin ataques nuevos.

No hay motor de grafos, feeds de reputación, geolocalización, campañas o reglas de
correlación multisesión implementados por el mero hecho de tener estos datos. El catálogo
completo tampoco significa que Cowrie pueda observar todas sus técnicas.

## Trabajo siguiente, sin implementarlo en esta migración

1. Definir casos etiquetados independientes para IoCs, contexto y recomendaciones. Evitar
   usar la salida del mismo LLM como etiqueta de verdad.
2. Mejorar canonicalización, extracción de hashes de archivos y cobertura de formatos,
   conservando el valor original y sin perder trazabilidad.
3. Crear consulta completa de observaciones por IoC y filtros por tipo, sesión, tiempo,
   estado y evidencia. Separar valor observado de valoración contextual.
4. Diseñar correlación multisesión justificable, con ventanas temporales y procedencia;
   no atribuir automáticamente identidad por compartir una IP.
5. Modelar salvaguardas propuestas y vínculos a evidencia, justificación, alcance y revisión.
   Reutilizar servicios/roles/auditoría actuales; migraciones aditivas con respaldo.
6. Evaluar recomendaciones frente a hechos: no bloquear una IP de laboratorio solo porque
   el modelo lo sugiera. No ejecutar medidas automáticamente.
7. Comparar DeepSeek sin/con RAG sobre los mismos snapshots y contrato, registrando
   propuestas crudas, descartes, latencia y costo. La prueba individual ya documentada
   no demuestra mejora estadística.

## Cómo trabajar sin Ubuntu

Seguir `docs/MIGRACION_NUEVA_PC.md`: recuperar el paquete privado, restaurar la base y
ejecutar `Iniciar-TacticLens.ps1`. Abrir `/sesiones`, `/iocs`, `/analisis` y `/mitre` con
la cuenta existente y Google Authenticator. Consultar candidatos MITRE en el detalle
de sesión no llama a DeepSeek. Las búsquedas y pruebas locales no requieren recibir
eventos nuevos ni tienen que modificar el dashboard con datos ficticios.

Para validaciones con escrituras, usar una restauración aislada y
`python -m scripts.test_offline`. No hay que reinstalar Cowrie, acceder por SSH, cambiar
firewalls ni configurar redes entre laptops para continuar estas líneas de desarrollo.
