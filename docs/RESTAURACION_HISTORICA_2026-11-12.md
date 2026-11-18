# Restauración de un archivo histórico PostgreSQL · 12 de noviembre de 2026

Este procedimiento se verificó en Windows con PostgreSQL de versión mayor 18 y pgvector 0.8.7. Se utilizó un respaldo custom existente y se comprobó que los recuentos originales coincidieran y las restricciones quedaran validadas. Los valores cifrados de los factores MFA se verificaron con sus claves originales. Los resultados de inspección y los datos del respaldo se custodian en el entorno local.

## Inspección y restauración

Para inspeccionar un archivo sin cambiar PostgreSQL, ejecute desde la raíz del proyecto.

```powershell
.\.venv\Scripts\python.exe -m scripts.restore_existing_archive RUTA_PRIVADA_DEL_RESPALDO.backup
```

La inspección verifica formato y versión, lee completamente el archivo mediante `pg_restore`, calcula su SHA-256 y comprueba que las migraciones declaradas correspondan al repositorio. Un checksum generado al recibir el archivo identifica esa copia. La autenticidad del respaldo requiere un origen confiable o una comprobación independiente.

El siguiente comando crea una base nueva y conserva cualquier configuración existente. Indique un archivo privado con las claves de la instalación original para validar y habilitar MFA.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Restaurar-ArchivoHistorico.ps1 -Respaldo RUTA_PRIVADA_DEL_RESPALDO.backup -ClavesOriginales RUTA_PRIVADA_ENV
```

La restauración guarda los registros de inspección y el SQL temporal de trabajo en `.local/restauracion`. El material puede contener credenciales capturadas, datos personales y factores MFA cifrados. Manténgalo fuera del repositorio y bajo la misma custodia que el respaldo. La contraseña administrativa se pide en un cuadro local y se usa durante el proceso.

## Verificación posterior

```powershell
.\.venv\Scripts\python.exe -m scripts.verify_restored_archive
```

El verificador compara los recuentos y los factores MFA cifrados y revisa las restricciones sin escribir en PostgreSQL. El migrador conserva sus comprobaciones de checksum y mantiene `008_limpieza_dominios.sql` diferida. Para el arranque local y la verificación de los servicios, consulte la [guía de instalación histórica](INSTALACION_WINDOWS_HISTORICO.md).
