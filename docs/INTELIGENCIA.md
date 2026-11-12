# Observables y MITRE ATT&CK en TacticLens

TacticLens guarda valores observados por Cowrie aunque DeepSeek no esté disponible. Una IP de origen, un dominio, una URL o un hash escrito en un comando **no prueba malicia ni ejecución exitosa**. Cada observación cita un evento y una sesión; el administrador puede confirmarla o descartarla con un motivo auditado. La revisión es una decisión humana sobre la relevancia del valor dentro de este laboratorio.

Los mapeos MITRE son propuestas de análisis. El LLM recibe únicamente un subconjunto de técnicas Enterprise aplicables a sesiones SSH de Cowrie. El backend comprueba que el código exista en el catálogo y que la propuesta tenga justificación y eventos de la acción. Las propuestas inválidas quedan registradas en `resultado_estructurado.mapeos_descartados`; no crean un mapeo. Un resultado `T1078` por una autenticación en el SSH simulado no se acepta: Cowrie no demuestra el uso de una cuenta real válida.

## Preparación y actualización

Desde la raíz del proyecto, con PostgreSQL disponible y `.env` configurado:

```powershell
.\.venv\Scripts\python.exe -m scripts.migrate
.\.venv\Scripts\python.exe -m scripts.seed_catalog
.\.venv\Scripts\python.exe -m scripts.backfill_observables
.\.venv\Scripts\python.exe -m scripts.backfill_mappings
```

Los comandos son repetibles. `seed_catalog` conserva relaciones existentes y carga un subconjunto revisado de ATT&CK Enterprise 20.1. `backfill_observables` procesa eventos históricos sin llamar al LLM. `backfill_mappings` recupera propuestas históricas solo si puede asociarlas inequívocamente a la acción y a sus eventos; omite otras. Las nuevas observaciones se crean durante la ingesta. Reinicie Uvicorn después de aplicar la migración y el código.

El catálogo se limita deliberadamente a técnicas pertinentes al laboratorio. El origen de los códigos es [MITRE ATT&CK Enterprise](https://attack.mitre.org/) y su [distribución oficial STIX](https://github.com/mitre-attack/attack-stix-data). Al ampliar el subconjunto, revise la técnica y su táctica en esa fuente, agregue la relación en `scripts/seed_catalog.py` y actualice `COWRIE_TECHNIQUES` en `backend/routes.py`. No incorpore códigos producidos únicamente por un LLM.

## Uso en la interfaz

1. **Observables de Cowrie:** un valor aparece una vez con cantidad de eventos, contexto y sesión de origen. Un administrador puede confirmarlo o descartarlo con una explicación de al menos diez caracteres. Las observaciones conservan la trazabilidad de cada evento.
2. **MITRE ATT&CK:** abra un mapeo para ver técnica, táctica, sesión, evidencia y justificación. El administrador revisa la propuesta. La confianza mostrada es la declaración del modelo; no es una probabilidad calibrada.
3. **Sesiones y eventos:** analice manualmente una sesión para generar nuevas propuestas MITRE. Los observables aparecen tras la ingesta, sin requerir ese análisis.

La revisión cambia el estado del hallazgo; no modifica el evento original. Las decisiones se registran en `auth_auditoria`. La migración `007_inteligencia.sql` crea `observacion_ioc` y añade revisión a `mapeo_mitre`; `008_limpieza_dominios.sql` retira nombres de archivo que pudieron clasificarse erróneamente como dominios durante el primer reproceso.

## Límites actuales

- El extractor local reconoce valores literales en `src_ip` y en comandos `cowrie.command.input`. No consulta reputación externa ni abre las URL observadas.
- La detección de dominios evita extensiones habituales de archivos; un nombre poco común todavía requiere revisión humana.
- El subconjunto ATT&CK cubre ejemplos SSH del prototipo, no toda la matriz Enterprise. La emulación de Cowrie limita lo que puede afirmarse sobre ejecución, archivos y persistencia reales.
- Un administrador revisa hallazgos; el sistema no ejecuta respuestas automáticas ni bloqueos de red.
