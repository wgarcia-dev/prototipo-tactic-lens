# Correcciones de seguridad H01 y H02 de TacticLens

**Validado el 27 de noviembre de 2026 · Ecuador**

| Hallazgo | Estado final | Evidencia |
| --- | --- | --- |
| H01 · Exposición inconsistente de secretos | **Corregido** en las superficies verificadas | Marcadores sintéticos ocultos en API, panel, IoCs, citas MITRE, informes JSON/PDF/DOCX, traza y cuerpo enviado al LLM simulado. El JSON original se recuperó intacto de PostgreSQL. |
| H02 · Rol operativo propietario de tablas | **Parcial en operación** | Separación implementada y validada en PostgreSQL 18 aislado con pgvector. El cambio de roles y credenciales en la base operativa sigue pendiente de aplicación autorizada. |

## H01 · Redacción y preservación de evidencia

La API usaba reglas distintas para el detalle de eventos, los comandos del panel y los documentos. Un valor capturado en un campo de contraseña podía reaparecer en texto libre en otra pantalla. El mecanismo compartido en `backend/sensitive.py` detecta campos sensibles, sintaxis de credenciales y valores repetidos dentro del contexto de la sesión, incluidos registros históricos fuera de la página consultada. Omite cargas terminales crudas en las vistas ordinarias conservando campos y evidencias técnicas publicables. También protege usuario/contraseña de URL, tokens nombrados y claves API en texto, rutas y parámetros. La redacción distingue los IDs de referencia y códigos MITRE estructurados.

Los informes aplican la política al modelo común que alimenta JSON, PDF y DOCX. El LLM recibe el conjunto de hechos minimizado y un filtro final con el contexto de secretos de la sesión. Las trazas conservan sus campos permitidos y siguen omitiendo el texto libre. Los errores inesperados de la API registran la clase de excepción en vez del cuerpo, el SQL o la URL del proveedor. Los datos originales y la normalización interna para extracción, correlación y deduplicación conservan su representación previa.

**Archivos.** [Política compartida](backend/sensitive.py) · [API](backend/api.py) · [rutas analíticas y panel](backend/routes.py) · [IoCs](backend/ioc_views.py) · [RAG y proveedor](backend/rag/pipeline.py) · [compatibilidad RAG](backend/rag/behavior.py) · [modelo de informe](backend/session_report.py) · [render](backend/report_export.py) · [trazas](backend/analysis_trace.py) · [salvaguardas](backend/safeguards.py) · [errores](backend/auth/middleware.py) · [lectura de auditoría](backend/auth/routes.py) · [registro de auditoría](backend/auth/store.py).

## H02 · Privilegios de PostgreSQL

El backend usa `DATABASE_USER` y `DATABASE_PASSWORD`. Las migraciones y tareas de mantenimiento usan un login distinto configurado mediante `DATABASE_MIGRATION_USER` y `DATABASE_MIGRATION_PASSWORD`. El migrador comprueba que es dueño de los objetos de `honeypot` y reconcilia los permisos del runtime dentro de la misma transacción que las migraciones. El rol operativo solo recibe las operaciones usadas por cada tabla, incluida lectura del registro de migraciones para el diagnóstico y acceso de lectura/inserción a `auth_auditoria`. Las secuencias de identidad funcionan sin conceder acceso directo. Una futura secuencia SERIAL vinculada a una tabla de escritura recibe solo `USAGE`. Las tablas y rutinas futuras quedan cerradas hasta incorporar una concesión explícita. FastAPI puede exigir la comprobación de privilegios en desarrollo y la exige en producción.

El backfill de salvaguardas conserva las concesiones requeridas para escribir tareas y orígenes durante el arranque. El catálogo, los embeddings y la edición administrativa del sensor usan el migrador. La preparación posterior a una restauración configura roles separados en la base nueva y guarda el secreto del propietario en un archivo privado fuera de la configuración de ejecución. Se mantuvieron los SQL históricos y sus checksums.

**Archivos.** [Conexiones](backend/db.py) · [concesiones y validación](backend/db_access.py) · [arranque](backend/api.py) · [variables de ejemplo](.env.example) · [migraciones](scripts/migrate.py) · [verificación del rol](scripts/db_roles.py) · [sensor](scripts/configure_sensor.py) · [catálogo](scripts/import_mitre.py) · [embeddings](scripts/embed_mitre.py) · [semilla](scripts/seed_catalog.py) · [portabilidad](scripts/portability.py) · [restauración histórica](scripts/historical_database.py) · [restauración de archivo](scripts/restore_existing_archive.py) · [entrada Windows histórica](scripts/windows/Restaurar-Historico.ps1) · [entrada Windows de archivo](scripts/windows/Restaurar-ArchivoHistorico.ps1).

## Pruebas y resultados

- **Pruebas dirigidas.** Pasaron los 6 casos de H01/H02. El flujo integrado usó TOTP y correo simulado, ingesta autenticada, revisión de datos guardados, RAG local con 706 vectores, LLM simulado, revisión de IoCs y MITRE, y asignación, avance y cierre de salvaguardas. Se extrajo texto del PDF y DOCX para comprobar simultáneamente la ausencia de secretos y la presencia de evidencia técnica. La comparación SQL confirmó que las inserciones originales de Cowrie conservaron los valores sintéticos íntegros.
- **Permisos negativos y migraciones.** La instancia aislada rechazó 12 operaciones administrativas o privilegiadas del runtime, incluidas modificación, borrado y truncado de auditoría, desactivación del trigger, cambio de `session_replication_role` y asunción del rol propietario. El runtime pudo iniciar FastAPI, insertar y consultar auditoría mediante sus flujos autorizados. El migrador pudo aplicar y repetir la migración, y se comprobó que una tabla y una rutina futuras permanecen cerradas por defecto. Se verificó el aprovisionamiento posterior a la restauración sobre una segunda base temporal con el esquema inicial importado.
- **Regresión.** De 151 casos de autenticación, administración, ingesta, análisis, IoCs, monitoreo, informes y portabilidad, 148 pasaron inicialmente. Se corrigió la serialización del ID de IoC y se ajustó el caso de migración idempotente para usar el migrador. Los tres casos afectados pasaron en la repetición dirigida. La última verificación ejecutó 17 casos de seguridad, validación HTTP y portabilidad, todos exitosos. Los recuentos de estas ejecuciones se superponen.
- **Preflight y aislamiento.** El diagnóstico con el rol operativo leyó 13 migraciones y 706 vectores, y cargó el modelo local. El clúster temporal con datos sintéticos se detuvo y se retiró. No se cambiaron roles, permisos, propietarios ni datos de PostgreSQL operativo. No hubo llamadas reales ni uso de claves reales del LLM, commits ni push.

[Pruebas dirigidas](tests/test_security_h01_h02.py) · [Regresión de migración](tests/test_auth.py)

## Aplicación posterior en PostgreSQL operativo

1. **Respaldar y registrar el estado.** Detener el backend de manera coordinada y conservar una copia privada de su configuración y del binario o árbol de despliegue anterior. Con el propietario actual, hacer un `pg_dump --format=custom --create` de la base en un destino privado, verificar que `pg_restore --list` lea el archivo y comprobar restaurabilidad en una base aparte. Registrar el propietario y las ACL de base, esquemas, tablas, secuencias, rutinas y roles. Mantener la contraseña fuera de la línea de comandos y del manifiesto.
2. **Crear el login operativo.** Usar una sesión DBA verificada en la base correcta. El propietario actual del esquema y sus objetos puede quedar como migrador exclusivo. Si la propiedad está repartida, corregirla en una intervención administrativa revisada antes de ejecutar el script. Crear un login operativo nuevo y aplicar las restricciones de base. Revisar antes si otros roles necesitan concesiones explícitas de los permisos que hoy reciben de `PUBLIC`.

   Ejemplo en `psql`, con `tacticlens_db` como nombre de ejemplo.

   ```sql
   SELECT current_database();
   CREATE ROLE tacticlens_runtime LOGIN NOINHERIT NOSUPERUSER
       NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
   REVOKE CREATE, TEMP ON DATABASE tacticlens_db FROM PUBLIC;
   GRANT CONNECT ON DATABASE tacticlens_db TO tacticlens_runtime;
   REVOKE CREATE ON SCHEMA public FROM PUBLIC;
   ```

   Asignar el secreto del nuevo login con `\password tacticlens_runtime` o el gestor privado aprobado. Evitar membresías, concesiones sobre `session_replication_role` y ejecución de rutinas `SECURITY DEFINER` accesibles desde esquemas no confiables.
3. **Migrar y comprobar.** Guardar solo las credenciales del runtime en la configuración normal del backend y habilitar `DATABASE_ENFORCE_RUNTIME_ROLE=true`. Inyectar las credenciales del propietario únicamente en una sesión administrativa. Ejecutar lo siguiente y retirar de esa sesión las variables administrativas antes de arrancar FastAPI.

   ```powershell
   .\.venv\Scripts\python.exe -m scripts.migrate
   .\.venv\Scripts\python.exe -m scripts.db_roles
   .\.venv\Scripts\python.exe -m scripts.portability check --model
   ```

   Verificar el arranque y lecturas de sesión, evento, informe y auditoría. Comprobar actos de escritura con el conjunto de pruebas aislado antes de abrir el servicio. No publicar el archivo privado de migración ni entregarlo al proceso de FastAPI.
4. **Revertir ante fallos.** Si falla la transacción de migración o concesiones, PostgreSQL revierte ese paso. Mantener el backend detenido, corregir el diagnóstico y revisar por separado las ACL de base aplicadas por DBA. Si se necesita volver a una versión de aplicación anterior, preferir conservar el rol mínimo y probar esa versión con él en una copia. Restaurar permisos anteriores solo mediante un cambio DBA explícito con la captura del paso 1 y sin reabrir privilegios de auditoría al runtime. Usar el respaldo sobre una base nueva para recuperar datos o comparar el estado, manteniendo la base original disponible para diagnóstico.

## Límites residuales

- H01 enmascara secretos reconocibles por estructura, sintaxis o contexto de la sesión. No puede inferir un valor arbitrario sin esas señales ni asociar automáticamente credenciales entre sesiones distintas. El dato original permanece en PostgreSQL y requiere controles de acceso, respaldo y retención adecuados. Los resultados históricos se protegen al publicarse, sin reescribir el histórico.
- H02 protege frente a la identidad SQL de ejecución. El DBA y el propietario conservan capacidad administrativa. Se requiere separar también el acceso al secreto administrativo y al respaldo a nivel de sistema operativo. La verificación aislada incluyó la preparación posterior a la restauración, pero no una restauración operativa completa ni una rotación real de credenciales.

