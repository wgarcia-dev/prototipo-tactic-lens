# Instalación histórica de TacticLens en Windows

El [procedimiento general de migración](MIGRACION_NUEVA_PC.md) usa una transferencia privada cifrada. Los comandos de esta guía permiten operar también con un respaldo PostgreSQL en formato custom que se recibió por separado. Use solamente archivos cuyo origen pueda verificar.

## Preparar un respaldo en el equipo de origen

Con el entorno virtual del proyecto y la configuración de origen disponibles, ejecute desde la raíz del repositorio.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Respaldar-Historico.ps1 -Destino .\.local\transferencia\tacticlens.dump
```

Si los binarios de PostgreSQL están en otra ubicación, indique `-PgBin`. Use un cliente compatible con la versión mayor del servidor. El script genera un dump custom, un manifiesto con el checksum y los recuentos del mismo snapshot, y un archivo privado con la configuración necesaria para conservar MFA. Custodie los tres archivos por separado del repositorio, en almacenamiento privado cifrado.

## Restaurar en una base nueva

Deposite los archivos en un directorio privado, por ejemplo `.local/restauracion/entrada`. La exclusión de Git no desactiva la sincronización de carpetas. Para un resguardo local use una ubicación que cumpla su política de custodia y pase su ruta al restaurador.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Restaurar-Historico.ps1 -Respaldo .\.local\restauracion\entrada\tacticlens.dump
```

El script pide en un cuadro local la contraseña administrativa de PostgreSQL. Verifica versión, checksum y extensiones. Crea una base y un usuario de aplicación con identificadores nuevos, restaura los objetos en una transacción y compara los recuentos antes de habilitar el inicio de la aplicación. Si ya existe `.env`, detiene la operación y lo conserva.

Para un dump custom sin manifiesto, use primero el procedimiento de [inspección y restauración de archivo](RESTAURACION_HISTORICA_2026-11-12.md).

## Arranque y verificación

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Iniciar-TacticLens.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Verificar-TacticLens.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Detener-TacticLens.ps1
```

El frontend está en `http://127.0.0.1:5173`. Use la cuenta original y su segundo factor. Con `MAIL_TRANSPORT=file`, los mensajes del flujo local se guardan en el buzón privado de desarrollo. Los análisis guardados y la recuperación RAG se pueden consultar con recursos locales. Las llamadas para análisis nuevos requieren la configuración del proveedor.

Si los puertos ya sirven una instancia iniciada antes de una actualización, compruebe que el proceso pertenezca a este proyecto antes de cerrarlo o volver a iniciar TacticLens.
