# Actualización de la instalación Windows · 18 de noviembre de 2026

Esta nota registra los ajustes de compatibilidad y las verificaciones de la instalación local. Para trasladar otra instalación, consulte la [guía de migración](MIGRACION_NUEVA_PC.md) y el [procedimiento para respaldos históricos](INSTALACION_WINDOWS_HISTORICO.md).

## Ajustes de la instalación

- En Windows, el módulo SQLite cierra explícitamente las conexiones de origen y respaldo. El cierre libera los archivos sin cambiar el comportamiento de confirmación y reversión de transacciones. Las pruebas usan el mismo cierre para sus archivos temporales.
- La desconexión WebSocket completa la limpieza de tareas hijas ante la cancelación ASGI. Se conservan las comprobaciones de autenticación, revocación y límites del monitor.
- Las dependencias de RAG mantienen NumPy 2.2.6 y ONNX Runtime 1.23.2 antes de Python 3.14. Para Python 3.14 se instalan NumPy 2.3.5 y ONNX Runtime 1.24.4. Tokenizers sigue en 0.23.3.
- Los lanzadores de Windows comprueban el modelo y la base local. FastAPI escucha en loopback y usa el ciclo de apagado de Uvicorn para cerrar sus conexiones. El lanzador detiene únicamente los procesos de TacticLens que reconoce y mantiene PostgreSQL activo.
- Se comprobó PostgreSQL 18.1, pgvector 0.8.7 y el modelo MiniLM ONNX para vectores normalizados de 384 dimensiones en CPU. La búsqueda híbrida usa el catálogo MITRE ATT&CK Enterprise 20.1 guardado localmente.

## Histórico y pruebas

Se creó un respaldo privado antes de aplicar la migración aditiva de RAG `009_rag_mitre.sql`. Se verificaron huellas de las columnas históricas con tablas temporales. La limpieza `008_limpieza_dominios.sql` permaneció diferida. Las verificaciones cubrieron SQLite, WebSockets, autenticación, sesiones, análisis almacenados y búsqueda local, con el proveedor LLM y el correo simulados.

Los respaldos, manifiestos privados, archivos de correo, configuraciones y registros de ejecución se custodian fuera de Git.

Para abrir TacticLens use `Iniciar-TacticLens.cmd`. Para apagar los procesos propios use `Detener-TacticLens.cmd`. La verificación del entorno se ejecuta desde la raíz del proyecto.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Verificar-TacticLens.ps1
```
