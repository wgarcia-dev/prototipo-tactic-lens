# Integración colaborativa de TacticLens — 12 de noviembre de 2026

## Estado auditado y protección

Se partió de `main` local en `7e7c4a2`, con el árbol limpio: no había cambios sin confirmar que guardar. `origin` apunta a `https://github.com/wgarcia-dev/prototipo-tactic-lens.git`. Se ejecutó `git fetch --all --prune` y se consultaron todas las ramas publicadas: el remoto solo tenía `main`.

Base común: `b6a01db`. El local tenía seis commits propios y el remoto un commit adicional del compañero:

| Procedencia | Commits |
|---|---|
| Local, Rober7o-Garcia | `f636248`, `44c45db`, `acbacf2`, `ebf10b0`, `bcd1890`, `7e7c4a2` |
| Remoto, William García | `52a3f22` — refactor: cambiando lógica central |

Los commits `ebf10b0`, `bcd1890` y `7e7c4a2` se comprobaron expresamente. Una segunda actualización de referencias confirmó que el remoto seguía en `52a3f22` antes de cerrar la integración.

- Respaldo: `codex/respaldo-antes-integracion-20261112`, apuntando a `7e7c4a2`.
- Integración: `codex/integracion-colaborativa-http`.
- Copia Git completa y verificada: `.local/backups/antes-integracion-20261112.bundle`.
- Respaldo PostgreSQL previo: `.local/backups/antes-merge-colaborativo-20261112T073138Z.dump`.
- Huellas y conteos previos, sin contenidos sensibles: `.local/backups/integracion-baseline.json`.

Se utilizó `git merge --no-ff --no-commit origin/main`, seguido de resolución, pruebas y commit de merge **`1a364bc`**, con padres `7e7c4a2` y `52a3f22`. No se hizo rebase, reemplazo de carpetas, reset destructivo, limpieza de archivos ni publicación de credenciales. No se modificaron archivos `.env` ni se editó o migró manualmente la cola SQLite de Ubuntu; su exportador siguió incorporando los eventos de la prueba. Las ramas principal local y remota se conservaron en sus respectivos puntos; no se ejecutó push.

## Comparación funcional

| Módulo | Cambios del compañero | Integración y conservación local |
|---|---|---|
| Ingesta FastAPI | Extracción de observables al insertar eventos | Se conectó al servicio transaccional actual, conservando recibos v2, identidades durables, secuencias y aislamiento de eventos inválidos |
| IoCs | IP, dominio, URL y hash deterministas sin LLM; revisión humana | Se conserva la evidencia por evento y se mantienen visibles los IoCs respaldados por análisis LLM |
| MITRE / LLM | Subconjunto ATT&CK, catálogo en el prompt, descarte de códigos no permitidos, revisión administrativa | Se conserva el informe detallado y su evidencia; nuevas propuestas y revisiones quedan disponibles |
| React | Listado de observables, estados y controles de revisión IoC/MITRE | Se conservan sesiones reales, proxy local, navegación y autenticación |
| Autenticación / usuarios | Sin cambios al núcleo; autorización administrativa para revisar inteligencia | Cookies, CSRF, MFA, roles, recuperación, sesiones y administración existentes se conservan |
| PostgreSQL | Observaciones IoC y campos de revisión MITRE; limpieza de falsos positivos | Solo se aplicó el cambio aditivo; se difirió la limpieza destructiva |
| SQLite / transporte | Sin cambios remotos | Se conserva el exportador, timer, cola, reintentos, clave exclusiva, HTTP directo privado y firewall restringido; no se vuelve al túnel |
| Scripts | Catálogo y reprocesamiento histórico | Sembrado sin sobrescribir metadatos; reprocesamientos idempotentes; diagnóstico comprueba ambas tablas nuevas |
| Dependencias | Sin cambios | Se mantienen FastAPI, SQLAlchemy Core, PostgreSQL, React, Vite y las dependencias existentes |
| Pruebas y documentación | Tres pruebas nuevas y guía de inteligencia | Se mantienen las 153 anteriores y se añaden siete pruebas específicas de integración |

## Conflictos y decisiones

Git detectó conflictos textuales en `README.md` y `backend/api.py`.

1. **Tablas reflejadas:** se conservaron tanto `evento_origen` como `observacion_ioc`.
2. **Persistencia:** el remoto añadía `persist_observables` a una implementación anterior de `_persist_events`. Se mantuvo el servicio actual `backend/ingestion.py` y se trasladó ese efecto a la misma transacción del evento y su recibo. Un fallo de infraestructura revierte todo y no confirma una entrega parcial.
3. **Documentación:** se combinaron la guía de HTTP local y la explicación de observables/MITRE con revisión humana.
4. **Migraciones con prefijo 007:** se mantienen los dos nombres publicados. El ejecutor usa el nombre completo y checksum; no fue necesario renumerarlas ni alterar SQL ya aplicado.
5. **Limpieza destructiva:** `008_limpieza_dominios.sql` contiene DELETE sobre evidencia e IoCs. Se conserva su contenido y checksum por compatibilidad con instalaciones que ya la aplicaron. Si está pendiente, el ejecutor la informa como diferida, no la ejecuta y no la registra falsamente como aplicada. No se eliminó evidencia histórica.
6. **IoCs existentes:** el nuevo listado consulta observaciones. Para conservar las detecciones LLM anteriores, el reprocesamiento las incorpora sin sobrescribir revisiones; los análisis nuevos también crean esa relación.
7. **Validaciones y trazabilidad:** el motivo se valida después de quitar espacios. Las subconsultas de evento, sesión y evidencia usan el mismo desempate estable.
8. **Pruebas:** se amplió el esquema aislado de concurrencia para incluir observaciones e IoCs, y se separó la consulta del catálogo del mock del proveedor LLM.
9. **Arranque Windows:** después de cerrar un servidor, CIM llegó a mostrar listeners obsoletos con PID 0 aunque los sockets ya estaban libres. El lanzador ahora comprueba los mismos enlaces exclusivos que usa FastAPI. Se verificó que rechaza un servidor realmente activo y permite reiniciar cuando los sockets están libres; no modifica las reglas ni pide UAC adicional.

## Esquema y actualización local

Se aplicó únicamente `007_inteligencia.sql`: crea `observacion_ioc` y añade estado, motivo, responsable y fecha de revisión a `mapeo_mitre`. `007_ingesta_identidad.sql` ya estaba aplicada y permanece intacta. `008_limpieza_dominios.sql` no se ejecutó.

Antes de la nueva prueba física, las huellas completas de los 29 eventos, 6 sesiones, 26 recibos de origen, 4 usuarios, 4 factores MFA, 2 análisis y 4 acciones coincidieron con el respaldo previo. Los catálogos MITRE estaban vacíos antes de la actualización; se agregaron cinco tácticas, once técnicas (incluido el padre) y sus relaciones. El sembrado ahora preserva metadatos existentes.

El reprocesamiento inicial añadió 26 observaciones y recuperó dos propuestas MITRE respaldadas por los análisis guardados; omitió dos propuestas no admitidas. Una repetición recuperó cero mapeos adicionales. No se llamó a DeepSeek.

## Verificaciones ejecutadas

- **163 pruebas Python correctas:** 153 locales, tres del compañero y siete específicas de la integración. PostgreSQL real con fixtures transaccionales o esquemas de prueba aislados; correo y proveedor LLM simulados.
- **9 comprobaciones PowerShell 5.1 correctas:** alcance exacto del firewall, rechazo de IP/puertos/interfaz adicionales y reutilización sin UAC.
- **7 pruebas frontend correctas** y compilación React/Vite correcta. Permanecen las advertencias previas de React Router y tamaño del bundle.
- FastAPI integrado arrancó mediante `Iniciar-DemoHTTP.ps1`; reutilizó la regla existente sin UAC y respondió con PostgreSQL conectado y contrato `tacticlens.ingesta.v2`.
- La interfaz autenticada siguió mostrando las seis sesiones históricas. Se comprobaron los nuevos observables, sus enlaces de evidencia y controles administrativos, y las dos propuestas MITRE con estado pendiente. No se emitieron decisiones reales de confirmación o descarte: esas operaciones se probaron con datos transaccionales.
- **Prueba física posterior al merge:** conexión inocua a Cowrie TCP/2222, sin contraseñas ni comandos. Marcador `TacticLensDemo_f179cc66c65c`, sesión Cowrie `7b0ddd1df4ec`, sesión PostgreSQL `a2ce17e7-0b52-4716-bc25-5a3b66c9dc00`. El exportador Ubuntu existente entregó sus tres eventos por HTTP directo y creó tres observaciones en la misma ingesta.
- Estado después de esa prueba: **32 eventos, 7 sesiones, 29 recibos de origen, 29 observaciones y 2 mapeos MITRE**. Los tres eventos y la séptima sesión son nuevos datos de prueba, no reemplazos de los históricos.
- Reintento HTTP real del mismo evento y origen: **insertados=0, duplicados=1**. Los cinco conteos anteriores permanecieron iguales; tampoco se duplicaron observaciones. La entrega original fue desde Ubuntu; el reintento explícito de comprobación se hizo desde loopback.
- El transporte, configuración y código del exportador SQLite, la clave exclusiva y las reglas de firewall se conservaron respecto de `7e7c4a2`. El único ajuste del lanzador HTTP es la comprobación real de disponibilidad de sockets indicada antes. No fue necesario reinstalar nada en Ubuntu ni modificar SSH administrativo o UFW.

Las pruebas nuevas cubren transacción conjunta de evento/observable/recibo, reversión ante fallo, JSON idéntico con ocurrencias distintas, revisiones persistentes tras reintento/reproceso, permisos de analista y anónimo, auditoría, motivos inválidos, IoCs del LLM, filtrado MITRE, catálogo y migración diferida.

## Archivos incorporados o ajustados

Respecto al estado local previo:

- Backend: `backend/api.py`, `backend/ingestion.py`, `backend/intelligence.py`, `backend/routes.py`, `backend/analysis_report.py`.
- Frontend: `frontend/src/main.tsx`.
- Migraciones: `database/migrations/007_inteligencia.sql`, `database/migrations/008_limpieza_dominios.sql` (esta última conservada pero no ejecutada).
- Scripts: `scripts/migrate.py`, `scripts/seed_catalog.py`, `scripts/backfill_observables.py`, `scripts/backfill_mappings.py`, `scripts/demo_status.py`, `scripts/serve_demo.py`, `scripts/windows/Iniciar-DemoHTTP.ps1`.
- Pruebas: `tests/test_auth.py`, `tests/test_core.py`, `tests/test_analysis.py`, `tests/test_ingestion.py`, `tests/test_collaborative_integration.py`.
- Documentación: `README.md`, `docs/INTELIGENCIA.md`, este informe.

## Repetir el arranque y las comprobaciones

Desde PowerShell normal en la raíz del proyecto, con PostgreSQL activo y las dependencias existentes instaladas:

```powershell
.\.venv\Scripts\python.exe -m scripts.migrate
.\.venv\Scripts\python.exe -m scripts.seed_catalog
.\.venv\Scripts\python.exe -m scripts.backfill_observables
.\.venv\Scripts\python.exe -m scripts.backfill_mappings
.\scripts\windows\Iniciar-DemoHTTP.ps1 -UbuntuHost 192.168.0.110
```

Si ya existe un backend en 8000, detenga únicamente esa instancia con Ctrl+C antes de iniciarlo. React se inicia en otra terminal con `Iniciar-Frontend.ps1`. No configure un túnel. Para otra red, use la IP actual de Ubuntu y siga `docs/DEMO_LAPTOPS.md`; el script detecta la dirección de Windows.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/test_firewall_demo.ps1
npm.cmd --prefix frontend test
npm.cmd --prefix frontend run build
```

## Pendientes y propuesta de Pull Request

No se han repetido físicamente el hotspot sin Internet ni la interrupción de la red tras este merge. La recuperación física anterior está documentada y las pruebas de desconexión, reintento y confirmación perdida vuelven a pasar; la nueva entrega física directa sí se ejecutó. No se volvió a consultar por SSH el contador final de SQLite después de generar los tres eventos nuevos; se comprobaron sus recibos persistidos y observaciones en PostgreSQL. Tampoco se enviaron correos reales, se invocó DeepSeek real o se realizó un inicio MFA nuevo desde cero en la interfaz: los flujos de autenticación se verificaron mediante la suite y una sesión real ya autenticada.

La rama de integración queda local. Se recomienda revisarla con ambos integrantes y, cuando el usuario lo autorice, publicar **solo esa rama** y abrir un Pull Request hacia `main`. Título sugerido: «Integrar observables y revisión MITRE conservando ingesta HTTP de Cowrie». Incluir este informe, los resultados y la decisión de diferir la limpieza. Conservar el commit de merge para que ambos historiales queden presentes. No hacer push directo a `main` ni usar force push.
