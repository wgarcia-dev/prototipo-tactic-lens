# Honey Analytics · prototipo de tesis

Plataforma local para importar o recibir eventos Cowrie, reconstruir sesiones, analizarlas con un proveedor LLM y revisar evidencias en React. Los gráficos usan datos reales de PostgreSQL. La interfaz sigue las referencias de `ui/`.

## Arranque rápido en Windows

Desde PowerShell en esta carpeta:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
npm.cmd install --prefix frontend --cache frontend/.npm-cache
.\.venv\Scripts\python.exe seed_catalog.py
```

Configure `.env` según [.env.example](.env.example). La base existente usa las variables `DATABASE_*`; `HONEYPOT_ID` debe corresponder a un registro de `honeypot.honeypot`. `INGEST_API_KEY` es exclusiva del recolector. Configure `LLM_API_KEY`, `LLM_MODEL` y `LLM_BASE_URL` con el proveedor compatible con `/chat/completions`. El análisis se ejecuta en modo real desde FastAPI.

Abra dos terminales:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend:app --host 192.168.56.1 --port 8000
```

```powershell
cd frontend
npm.cmd run dev
```

Abra `http://127.0.0.1:5173`. Vite envía `/api` al backend en `192.168.56.1:8000`. Los endpoints de consulta y escritura interactiva solo aceptan solicitudes originadas en el host Windows; el recolector de Ubuntu usa `X-API-Key` en `/api/ingesta/eventos`. El frontend no recibe claves. `GET /api/health` permite diagnosticar conectividad desde la VM.

## Demostración de principio a fin

1. Inicie PostgreSQL, el backend y el frontend con los comandos anteriores.
2. En Ubuntu, inicie Cowrie y el servicio `cowrie-ingest` según [SETUP.md](SETUP.md). La ingesta automática continúa aunque el LLM esté inaccesible.
3. Desde Windows ejecute `ssh -p 2222 root@192.168.56.101`, y dentro de Cowrie escriba `whoami`, `pwd` y `uname -a`.
4. Abra **Sesiones y eventos** en React. Compruebe la sesión nueva, su cronología y los comandos. En **Análisis LLM**, los comandos recientes se actualizan cada 5 segundos. Pulse **Analizar sesión** para llamar al proveedor real.
5. Compruebe **Panel principal**, **Indicadores de compromiso** y **MITRE ATT&CK**. Los mapeos solo se guardan cuando el código existe en el catálogo cargado. El catálogo mínimo incluye [T1059.004](https://attack.mitre.org/techniques/T1059/004/) y la táctica [TA0002](https://attack.mitre.org/tactics/TA0002/).
6. Para probar la carga manual, copie el `cowrie.json` real desde Ubuntu con la cuenta administrativa `william` y súbalo en **Importar Cowrie**. La carga repetida debe informar duplicados.

Si `william` no puede leer directamente el log de Cowrie, desde Ubuntu copie temporalmente el archivo con `sudo cp /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json /home/william/cowrie.json` y `sudo chown william:william /home/william/cowrie.json`; luego, desde Windows, use `scp william@192.168.56.101:/home/william/cowrie.json .`. El puerto 22 es el SSH administrativo de Ubuntu; el 2222 es Cowrie.

La importación también está disponible por CLI: `.\.venv\Scripts\python.exe import_cowrie.py .\cowrie.json`.

## Pruebas

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
cd frontend
npm.cmd run build
```

La prueba de importación utiliza la base configurada, pero revierte su transacción al terminar. La prueba completa con VM requiere comprobar Cowrie, el servicio de recolección y una sesión SSH nueva en el entorno del usuario.

## Estado del prototipo

| Área | Estado |
| --- | --- |
| Ingesta automática Cowrie → FastAPI → PostgreSQL | Implementada; depende del servicio instalado en Ubuntu |
| Importación JSONL, reimportación y errores por línea | Implementada y probada |
| Sesiones, cronología, métricas y frontend React | Implementados; compilación verificada |
| Análisis LLM real por `httpx` | Implementado y comprobado con DeepSeek en una sesión existente |
| IoCs y MITRE | Extracción inicial y subconjunto MITRE verificado; requiere revisión humana |
| Revisión formal por analista, SFTP y búsqueda semántica | Pendientes |
| Embeddings `VECTOR(768)` | Esquema existente reconocido; generación y almacenamiento pendientes |

Este es un prototipo académico local. No incluye login ni autorización multiusuario. Los eventos originales permanecen en PostgreSQL; las respuestas de eventos ocultan campos de contraseña. El backend elimina esos campos antes de enviarlos al proveedor LLM.

Versiones verificadas en este entorno: FastAPI 0.162.0, SQLAlchemy 2.1.6, psycopg 3.3.7, Pydantic 2.14.2, pgvector para Python 0.5.1, httpx 0.28.1, React 19.3.1, Vite 7.3.7, Tailwind CSS 4.3.4, React Router 7.18.5 y Recharts 3.10.1. `package-lock.json` fija las dependencias del frontend. El esquema PostgreSQL existente evita crear migraciones Alembic en esta etapa.

## Requerimiento inicial conservado

Implementa una integración mínima y **automática** entre Cowrie, FastAPI y PostgreSQL para mi prototipo de tesis.

**Entorno:**

- Cowrie está en Ubuntu Server, dentro de VirtualBox.
- Cowrie genera eventos JSONL en `/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json`.
- Ubuntu utiliza la IP `192.168.56.101`.
- Windows utiliza la IP `192.168.56.1`.
- FastAPI y PostgreSQL se ejecutarán en Windows.
- Base de datos PostgreSQL 18: `honeypot_db`.
- Esquema existente: `honeypot`.
- Ya existen las tablas `honeypot`, `sesion` y `evento`, además de otras tablas del modelo lógico.

**Objetivo principal:**

Cuando alguien se conecte a Cowrie o ejecute comandos, los nuevos eventos deben almacenarse automáticamente en PostgreSQL, sin subir archivos manualmente.

**Implementa únicamente lo siguiente:**

1. Un backend mínimo en FastAPI con conexión a PostgreSQL mediante SQLAlchemy.
2. Inspección del esquema real de las tablas existentes antes de escribir consultas de inserción. No inventar columnas ni modificar las tablas.
3. Un endpoint `POST /api/ingesta/eventos` que reciba lotes de eventos JSON de Cowrie y los almacene en `sesion` y `evento`, respetando claves foráneas y restricciones.
4. Un recolector ligero en Python que se ejecute en Ubuntu Server, lea continuamente las nuevas líneas de `cowrie.json` y las envíe a FastAPI mediante HTTP cada 2 segundos.
5. El recolector debe guardar su posición de lectura para no volver a procesar todo el archivo, detectar rotación o truncamiento y reintentar los envíos si FastAPI no está disponible.
6. Los eventos deben tener identificación estable para evitar duplicados, incluso ante reintentos o reinicios.
7. El recolector debe avanzar su posición confirmada únicamente después de recibir una respuesta de éxito de FastAPI. Si una línea JSON está incompleta, debe esperar a que se complete.
8. Implementar una clave de autenticación sencilla para el endpoint de ingesta, almacenada en variables de entorno.
9. Crear `GET /api/sesiones` y `GET /api/sesiones/{id}/eventos` para comprobar lo almacenado.
10. Proporcionar instrucciones para ejecutar FastAPI en Windows con `--host 192.168.56.1 --port 8000` y permitir la conexión desde la VM mediante una regla de firewall restringida a `192.168.56.101`.

**Restricciones:**

- No eliminar ni recrear las tablas existentes.
- No implementar todavía React, DeepSeek, embeddings ni MITRE ATT&CK.
- No exponer contraseñas capturadas en las respuestas de la API ni imprimirlas en los registros.
- Si necesitas el DDL real de PostgreSQL y no puedes inspeccionar la base de datos, solicítalo antes de inventar la estructura.

**Prueba de aceptación:**

Con el recolector ejecutándose, conectarme desde Windows al honeypot usando `ssh -p 2222 root@192.168.56.101`, ejecutar `whoami`, `pwd` y `uname -a`, y comprobar que los eventos aparecen automáticamente en PostgreSQL, sin intervención manual y sin duplicados.
