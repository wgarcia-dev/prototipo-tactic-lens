# Recolección Cowrie — 26 de noviembre de 2026

Guía del laboratorio TacticLens. Fecha local: 26 de noviembre de 2026, Ecuador (UTC−05:00). Los puertos 2222, 2223 y 2224 corresponden a señuelos controlados en `192.168.56.101`. Ejecute los comandos de Windows desde la raíz de este repositorio en **PowerShell**, salvo donde se indique Ubuntu.

## Qué hicimos hoy

1. Recolectamos sesiones de Cowrie Shell mediante escenarios identificables por marcadores `TL-`. Confirmamos en la interfaz que se registran con modalidad `cowrie_shell` y se pueden analizar.
2. Preparamos una segunda instancia Cowrie con backend LLM en el puerto 2224. Confirmamos sesiones `cowrie_llm` en TacticLens. Su respuesta es texto generado por el modelo, no ejecución del sistema operativo.
3. Preparamos Cowrie Proxy en el puerto 2223, conectado a un invitado Alpine aislado en Docker. Tras corregir el servicio systemd para ejecutar `twistd` en primer plano, verificamos que escucha en 2223 y que la autenticación llega al invitado. Después se registraron y analizaron sesiones `cowrie_proxy`.
4. Configuramos el exportador activo `tacticlens-cowrie-live.service` para leer los registros de Shell, LLM y Proxy. La variable `TACTICLENS_EXTRA_LOGS` incluye los JSONL de LLM y Proxy. Corregimos la atribución de modalidad por instancia/puerto durante la ingesta.
5. Añadimos manifiestos de pruebas con escenario, comandos y marcador, y exportación CSV que vincula cada prueba con la sesión y el análisis almacenados en PostgreSQL. Los CSV existentes son `datasets/cowrie_sesiones_2026-11-26.csv` (auditoría completa) y `datasets/cowrie_analizados_2026-11-26.csv` (solo sesiones vinculadas y analizadas). **El CSV no se rellena al ejecutar SSH:** hay que analizar las nuevas sesiones y volver a exportar.
6. Añadimos `scripts/recolectar_cowrie_una_clave.py`: usa los mismos escenarios del catálogo PowerShell, solicita la contraseña una vez y la mantiene solo en memoria durante las conexiones. Conserva el manifiesto `resultados.json` que usa el exportador del dataset.

## Antes de arrancar

- La VM Ubuntu debe estar encendida y accesible en `192.168.56.101`. En Windows compruebe `Test-NetConnection 192.168.56.101 -Port 22`.
- PostgreSQL, el `.env` del proyecto, las migraciones y la cuenta de TacticLens deben estar preparados. Use la `.venv` del repositorio. Para el ejecutor nuevo instale una vez `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`.
- Las claves de DeepSeek y de ingesta permanecen en su configuración privada. No las copie al manifiesto, CSV ni al README.
- Cada instancia Cowrie debe tener su propio directorio, configuración, puerto y archivo `cowrie.json`. El filtro por modalidad solo puede ser fiable si el exportador ingiere los tres registros con la atribución correcta.

## Paso 1. Iniciar backend y frontend en Windows

Abra dos PowerShell independientes en la raíz del proyecto:

```powershell
# Terminal 1: backend HTTP del laboratorio
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Iniciar-DemoHTTP.ps1 -UbuntuHost 192.168.56.101
```

Si el puerto 8000 ya está ocupado, compruebe `Invoke-RestMethod http://127.0.0.1:8000/api/health`. Si responde el backend actual, manténgalo; no inicie otro. Si es un proceso antiguo, deténgalo en su terminal con Ctrl+C. La URL de ingesta anunciada debe usar la IP de Windows visible desde Ubuntu, usualmente `192.168.56.1`.

```powershell
# Terminal 2: interfaz
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Iniciar-Frontend.ps1
```

Abra `http://127.0.0.1:5173/sesiones` y autentíquese. Si la interfaz ya está activa, el script lo indicará.

## Paso 2. Verificar las tres instancias en Ubuntu

Desde otra terminal Windows:

```powershell
ssh william@192.168.56.101
```

En **Ubuntu**, compruebe puertos y procesos:

```bash
sudo ss -lntp | grep -E ':2222|:2223|:2224'
systemctl is-active tacticlens-cowrie-live.service
sudo systemctl --no-pager --full status tacticlens-cowrie-proxy.service
```

La correspondencia es:

| Modalidad | Puerto | Directorio | Funcionamiento |
| --- | ---: | --- | --- |
| Shell | 2222 | `/home/cowrie/my-honeypot` | Shell emulada por Cowrie; registra órdenes, pero no las ejecuta en Linux real. |
| Proxy | 2223 | `/home/cowrie/proxy-honeypot` | Cowrie retransmite al invitado Alpine aislado; allí sí se ejecutan las órdenes permitidas. |
| LLM | 2224 | `/home/cowrie/llm-honeypot` | El modelo genera respuestas de terminal; no demuestra que los comandos se hayan ejecutado. |

Si **Shell** no escucha, desde Ubuntu arranque su instalación existente y verifique que aparece el puerto (evite duplicar un proceso ya activo):

```bash
sudo -u cowrie bash -lc 'cd /home/cowrie/my-honeypot && source cowrie-env/bin/activate && cowrie start'
sudo ss -lntp | grep ':2222'
```

Si **LLM** no escucha:

```bash
sudo -u cowrie bash -lc 'cd /home/cowrie/llm-honeypot && source /home/cowrie/my-honeypot/cowrie-env/bin/activate && cowrie start'
sudo ss -lntp | grep ':2224'
sudo -u cowrie python3 -c "import configparser; p=configparser.ConfigParser(); p.read('/home/cowrie/llm-honeypot/etc/cowrie.cfg'); print(p.get('honeypot','backend'))"
```

El último comando debe indicar `llm`. Si Cowrie informa una opción duplicada, corrija esa opción dentro de su sección en `cowrie.cfg`; `listen_endpoints` puede existir en secciones distintas. La clave y URL del proveedor LLM deben estar configuradas de forma privada en Ubuntu. No vuelva a ejecutar `cowrie init` sobre la instalación configurada.

Si **Proxy** no escucha, asegúrese de que el invitado Docker del laboratorio está activo y reinicie el servicio existente:

```bash
sudo docker ps --filter name=tacticlens-proxy-guest
sudo systemctl restart tacticlens-cowrie-proxy.service
sudo systemctl --no-pager --full status tacticlens-cowrie-proxy.service
sudo ss -lntp | grep ':2223'
```

Este servicio usa el drop-in `/etc/systemd/system/tacticlens-cowrie-proxy.service.d/foreground.conf` para ejecutar `twistd --nodaemon`. No sustituya su `ExecStart` por `cowrie start -n`: esa forma ya causó un arranque aparente sin escucha útil. Si el invitado Docker no existe, consulte su configuración anterior antes de recrearlo: el backend Proxy depende de ese invitado y de la red aislada.

## Paso 3. Verificar el exportador de las tres fuentes

En **Ubuntu**:

```bash
systemctl is-active tacticlens-cowrie-live.service
sudo grep '^TACTICLENS_EXTRA_LOGS=' /etc/tacticlens-cowrie/exportador.env
sudo -u cowrie ls -l /home/cowrie/my-honeypot/var/log/cowrie/cowrie.json /home/cowrie/llm-honeypot/var/log/cowrie/cowrie.json /home/cowrie/proxy-honeypot/var/log/cowrie/cowrie.json
curl --connect-timeout 5 http://192.168.56.1:8000/api/health
```

La variable debe incluir los JSONL de LLM y Proxy separados por coma. Si la IP de Windows cambió, use la IP que mostró `Iniciar-DemoHTTP.ps1`. Si el exportador está activo pero las sesiones no llegan, revise su cola, el estado HTTP y los rechazos antes de repetir las pruebas; `active` por sí solo no confirma entrega. La configuración Windows–Ubuntu puede resincronizarse desde Windows con:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\Configurar-UbuntuHTTP.ps1 -UbuntuHost 192.168.56.101 -Usuario william -ExportadorLive
```

Hágalo con el backend operativo. El comando usa SSH administrativo y sudo; no es una conexión de ataque a Cowrie.

## Paso 4. Recolectar escenarios sin repetir la contraseña

Primero acepte **una vez por puerto** la huella SSH desde OpenSSH, verificándola antes de aceptarla. El ejecutor Python exige que las claves ya estén en `~/.ssh/known_hosts`:

```powershell
ssh -p 2222 root@192.168.56.101
ssh -p 2223 root@192.168.56.101
ssh -p 2224 root@192.168.56.101
```

Salga con `exit` en cada una. Luego inspeccione el catálogo y ejecute una modalidad por vez:

```powershell
.\.venv\Scripts\python.exe -m scripts.recolectar_cowrie_una_clave --modalidades cowrie_shell --solo-mostrar
.\.venv\Scripts\python.exe -m scripts.recolectar_cowrie_una_clave --modalidades cowrie_shell
.\.venv\Scripts\python.exe -m scripts.recolectar_cowrie_una_clave --modalidades cowrie_proxy
.\.venv\Scripts\python.exe -m scripts.recolectar_cowrie_una_clave --modalidades cowrie_llm
```

Para una corrida corta: `--modalidades cowrie_proxy --escenarios proxy_identidad,proxy_archivos`. Para una corrida de las tres: omita `--modalidades`. El programa solicita la contraseña del señuelo **una sola vez por corrida** y abre una sesión separada por escenario. No la imprime ni la escribe a disco. Los escenarios operan exclusivamente dentro del laboratorio: incluyen reconocimiento del entorno, cuentas, procesos, red local, archivos temporales, secuencias de comandos y controles negativos. En Proxy se pueden contrastar los efectos reales dentro del contenedor aislado; en Shell y LLM son observaciones de emulación o respuestas generadas.

### Tamaño de la recolección

Una corrida **parcial** permite comprobar extremo a extremo sin generar demasiadas sesiones:

```powershell
.\.venv\Scripts\python.exe -m scripts.recolectar_cowrie_una_clave --modalidades cowrie_shell --escenarios control,identidad,red
.\.venv\Scripts\python.exe -m scripts.recolectar_cowrie_una_clave --modalidades cowrie_proxy --escenarios proxy_identidad,proxy_permisos,proxy_script
.\.venv\Scripts\python.exe -m scripts.recolectar_cowrie_una_clave --modalidades cowrie_llm --escenarios llm_identidad,llm_estado
```

Una corrida **completa por modalidad** ejecuta todo su catálogo (11 escenarios Shell, 9 Proxy, 8 LLM al redactar esta guía). Para aumentar el número de sesiones sin cambiar el tipo de prueba, use `--repeticiones 2`; cada repetición crea sesiones y marcadores distintos:

```powershell
.\.venv\Scripts\python.exe -m scripts.recolectar_cowrie_una_clave --modalidades cowrie_shell --repeticiones 2
.\.venv\Scripts\python.exe -m scripts.recolectar_cowrie_una_clave --modalidades cowrie_proxy --repeticiones 2
.\.venv\Scripts\python.exe -m scripts.recolectar_cowrie_una_clave --modalidades cowrie_llm --escenarios llm_identidad,llm_estado,llm_error,llm_red --repeticiones 2
.\.venv\Scripts\python.exe -m scripts.recolectar_cowrie_una_clave --modalidades cowrie_llm --escenarios llm_archivos,llm_procesos,llm_secuencia,llm_instruccion --repeticiones 2
```

El límite actual de LLM es 50 comandos por ejecución y dos repeticiones. Por eso el ejemplo lo divide en dos grupos. La cantidad por sí sola no mejora el dataset: preserve variedad, resultados negativos, sesiones de control y evidencia de cada modalidad. No repita lotes hasta confirmar que el exportador está entregando y las sesiones aparecen en TacticLens.

El ejecutor genera `.local/pruebas-cowrie/TL-.../resultados.json`, archivos de comandos y trazas SSH. `codigo_ssh=0` indica que apareció el marcador final en la salida; **no acredita** que TacticLens recibió y analizó la sesión. Si aparece `255`, revise conectividad, clave de host y credenciales. Para mantener el flujo anterior con OpenSSH también existe `scripts/windows/Probar-Cowrie.ps1`, que puede pedir contraseña por escenario.

## Paso 5. Verificar ingesta, análisis y CSV

1. En la página **Sesiones y eventos**, filtre Shell, Proxy o LLM. Confirme que hay una fila nueva por escenario, con IP y cronología coherentes. Abra alguna sesión y busque su marcador `TL-` en la evidencia.
2. Pulse **Analizar** en las sesiones seleccionadas y espere a que indique resultado guardado. La generación del escenario no inicia automáticamente el análisis LLM de TacticLens.
3. Desde la raíz del proyecto, en Windows, regenere ambos CSV:

```powershell
.\.venv\Scripts\python.exe -m scripts.exportar_dataset_cowrie --output datasets/cowrie_sesiones_2026-11-26.csv
.\.venv\Scripts\python.exe -m scripts.exportar_dataset_cowrie --solo-completados --output datasets/cowrie_analizados_2026-11-26.csv
```

El CSV de auditoría conserva pruebas fallidas o no vinculadas; el de analizados conserva filas con sesión única, modalidad reconocida y análisis completado. Revise `estado_vinculacion`, `modalidad_planificada` frente a `modalidad_registrada`, `eventos_con_marcador` y los comandos observados. Un análisis generado por DeepSeek es una **propuesta** que requiere validación humana para usar el conjunto como verdad de referencia en la tesis. No mezcle una prueba Proxy fallida con datos de un invitado realmente ejecutado.

### Qué sesiones analizar y posibilidad de automatización

Analice **todas las sesiones nuevas vinculadas a marcadores** que vaya a incluir en `cowrie_analizados_2026-11-26.csv`, de las tres modalidades. Incluya controles y errores, no solo los casos que parezcan interesantes. No hace falta analizar intentos sin sesión capturada, conexiones fallidas que no generaron evidencia suficiente ni registros ajenos a las corridas; esos quedan en el CSV de auditoría. Si llega un evento después del análisis, actualice esa sesión antes de exportar.

**Sí se puede automatizar el inicio del análisis**, pero todavía no lo hace el ejecutor de recolección. El backend ya ofrece `POST /api/sesiones/{id_sesion}/analizar` y reutiliza un resultado vigente; la ruta exige autenticación de la aplicación. Un lote futuro debería seleccionar exclusivamente sesiones vinculadas de los manifiestos, esperar el cierre y la ingesta, llamar esa ruta secuencialmente con una sesión autenticada, respetar los límites y costos de DeepSeek, registrar fallos/reintentos y comprobar el estado final antes de exportar. Automatizar la solicitud al modelo **no equivale a validar sus etiquetas**: la revisión humana de técnicas MITRE, incidentes y salvaguardas sigue siendo necesaria para un dataset de tesis confiable. No use una llamada directa a DeepSeek ni escriba resultados en PostgreSQL por fuera de la API, porque omitiría la validación y trazabilidad de TacticLens.
