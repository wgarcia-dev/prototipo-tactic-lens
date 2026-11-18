# Demostración de TacticLens entre dos laptops: HTTP local

La modalidad vigente es **HTTP directo de demostración**, sin túnel SSH. Se utiliza el backend real y la base existente:

`Cowrie → cowrie.json → cola.sqlite3 → POST /api/ingesta/eventos → PostgreSQL → React`

Punto de retorno antes de esta adaptación: **ebf10b0**. Los commits anteriores `44c45db` y `acbacf2` conservan la implementación previa. Git restaura código; no revierte PostgreSQL ni SQLite. No restaure respaldos sobre datos nuevos.

## Preparación e inicio en Windows

Abra PowerShell como usuario normal en el proyecto:

```powershell
cd C:\Users\user\Documents\tesis\prototipo-tactic-lens
.\scripts\windows\Comprobar-Requisitos.ps1
```

Conserve PostgreSQL activo. Cierre con Ctrl+C el backend anterior que utilice 8000 y la ventana antigua `Abrir-Tunel.ps1`, si sigue abierta. Cancele también sincronizaciones antiguas que aún esperen contraseña. Conserve SSH administrativo; no se modifica sshd ni UFW.

```powershell
.\scripts\windows\Iniciar-DemoHTTP.ps1 -UbuntuHost 192.168.0.110
```

Este script detecta la dirección e interfaz de Windows mediante la ruta local hacia Ubuntu. En la red actual son `192.168.0.111` y Ethernet. Rechaza rutas que pasen por una puerta de enlace; las laptops deben compartir la red local.

- Ejecuta **una instancia** de la aplicación existente en `127.0.0.1:8000` y en la IP LAN seleccionada. No escucha en `0.0.0.0` ni en la interfaz VirtualBox.
- Crea una clave exclusiva en `.local/demo-http/ingest.key`, con ACL privada. No cambia `INGEST_API_KEY` del `.env` ni la autenticación de usuarios.
- Comprueba la regla antes de elevar permisos. Si coincide, muestra «Regla de firewall verificada y reutilizada. No se solicita UAC».
- Solo si falta o cambia el alcance, solicita UAC para el firewall. Activa el perfil de esa interfaz, bloquea entrada por defecto y permite **TCP/8000 desde la IP exacta de Ubuntu, a la IP exacta de Windows y por esa interfaz**. Conserva otras reglas y perfiles. Se guarda el estado previo en `.local/demo-http/firewall-previo.json`.
- En LAN, la aplicación solo acepta `/api/health` (GET) y `/api/ingesta/eventos` y `/api/ingesta/heartbeat` (POST), desde Ubuntu. No expone login, documentación ni módulos privados por esa interfaz. Ignora encabezados de proxy para identificar al cliente.
- Si la configuración no queda confirmada, no inicia el servidor LAN. Ctrl+C lo detiene.

El proceso de FastAPI continúa como usuario normal; solo el proceso breve del firewall se eleva. Las comprobaciones no generan nuevos avisos UAC. Si cambia la IP o interfaz, hará falta actualizar la regla una vez.

En otra PowerShell normal:

```powershell
.\scripts\windows\Iniciar-Frontend.ps1
.\scripts\windows\Estado-Ingesta.ps1
```

Mantenga el frontend en su propia terminal. La interfaz es `http://127.0.0.1:5173`, con proxy al backend de loopback. Correo, aprobación y Google Authenticator permanecen intactos.

## Instalar/actualizar Ubuntu y alinear la clave

Con el backend anterior activo, desde otra PowerShell normal:

```powershell
.\scripts\windows\Configurar-UbuntuHTTP.ps1 -UbuntuHost 192.168.0.110
```

Esto utiliza **SSH administrativo para instalar archivos**, no un túnel. El código y la clave exclusiva viajan por stdin cifrado; la clave no aparece en argumentos, consola ni repositorio. Puede pedir la contraseña SSH dos veces y luego sudo. No terminó al aparecer «entrada temporal recibida»: espere «Configuracion HTTP completada» y los contadores finales.

Primero se comprueba la clave contra la API existente usando un evento deliberadamente inválido que no inserta filas. Si obtiene 401 o no alcanza la API, no modifica la configuración. Después se respalda y actualiza el exportador inspeccionado y su biblioteca, se realiza un respaldo SQLite mediante su API de backup y se conservan filas, UUID de cola, cursores y metadatos de entrega.

La configuración resultante en `/etc/tacticlens-cowrie/exportador.env` es:

```dotenv
TACTICLENS_URL=http://192.168.0.111:8000/api/ingesta/eventos
TACTICLENS_TRANSPORT=demo-http
TACTICLENS_TOKEN=<clave exclusiva, sincronizada automáticamente>
TACTICLENS_SENSOR_ID=<valor existente, conservado>
```

No copie el marcador de ejemplo como clave. No necesita editar varios archivos ni compartir secretos en el chat. El archivo queda con permisos 0600. No se toca la contraseña SSH ni el MFA de TacticLens.

Se conservan `cowrie-tacticlens.service`, `tacticlens-exportador.service`, su timer de 30 segundos, `/home/cowrie/honeypot/var/log/cowrie/cowrie.json` y `/var/lib/tacticlens-cowrie/cola.sqlite3`. Se desactiva exclusivamente el recolector antiguo `cowrie-ingest.service`, si existe, para impedir dos emisores.

### Alternativa de instalación manual

El kit sin secretos puede prepararse y transferirse así:

```powershell
.\scripts\windows\Preparar-KitUbuntu.ps1
scp -r .\.local\kit-cowrie tacticadmin@192.168.0.110:~/kit-cowrie-http
ssh -t tacticadmin@192.168.0.110
```

En Ubuntu:

```bash
cd ~/kit-cowrie-http
sudo bash scripts/ubuntu/configurar-http.sh "$PWD" 192.168.0.111
```

Esta alternativa pide la clave de demostración de forma oculta; la ruta local donde reside es `.local/demo-http/ingest.key`. Prefiera el método automático para evitar copiarla manualmente. Nunca use `set -x` ni muestre el archivo de configuración.

## Comprobaciones reales

En Ubuntu, después de instalar:

```bash
sudo bash /opt/tacticlens-cowrie/scripts/verificar.sh
sudo bash /opt/tacticlens-cowrie/scripts/estado.sh
sudo bash /opt/tacticlens-cowrie/scripts/sincronizar.sh
curl --noproxy '*' --fail --max-time 5 http://192.168.0.111:8000/api/health
```

`verificar.sh` comprueba Cowrie, timer, contrato v2 y PostgreSQL mediante HTTP directo. `sincronizar.sh` pausa el timer, espera al envío en curso, reintenta con el mismo exportador y restaura el timer. No borra la cola. Un latido o una respuesta de salud no demuestran persistencia de eventos.

En Windows, genere una conexión inocua nueva en Cowrie, sin contraseñas ni comandos:

```powershell
.\.venv\Scripts\python.exe -m scripts.cowrie_demo generar --ubuntu 192.168.0.110
```

Copie el marcador `TacticLensDemo_...` que imprime. Espere al timer o sincronice desde Ubuntu y verifique:

```powershell
.\.venv\Scripts\python.exe -m scripts.cowrie_demo verificar --marker TacticLensDemo_REEMPLAZAR
.\scripts\windows\Estado-Ingesta.ps1
```

El verificador solo consulta PostgreSQL. Exige origen `sqlite:`, muestra la sesión y sus eventos y comprueba secuencias duplicadas. Código de salida 2 significa que el marcador aún no tiene recibo persistido; no significa éxito.

Inicie sesión en React con su cuenta y Google Authenticator. En «Sesiones y eventos», busque el `cowrie_session_id` obtenido, abra la sesión y despliegue el JSON relevante del evento de versión del cliente. Debe aparecer el marcador. No pulse «Analizar» para esta prueba offline.

Ejecute la sincronización otra vez: los mismos orígenes no deben aumentar los eventos en PostgreSQL. Guarde los contadores reales. El exportador solo marca enviado tras recibir confirmación v2 por cada identidad y un ID persistido. Un HTTP 200 genérico no basta.

## Interrupción, reinicio y hotspot sin Internet

1. Detenga FastAPI con Ctrl+C; deje Cowrie y su timer activos.
2. Genere otra conexión con `cowrie_demo generar`. Espere al timer: los nuevos eventos deben quedar pendientes en SQLite, sin eliminar filas.
3. En Ubuntu: `sudo bash /opt/tacticlens-cowrie/scripts/probar-reconexion.sh antes`.
4. Inicie de nuevo `Iniciar-DemoHTTP.ps1` con la misma IP de Ubuntu. La clave se conserva y, si la regla coincide, no solicita UAC.
5. Espere al timer o ejecute `sincronizar.sh`; después `sudo bash /opt/tacticlens-cowrie/scripts/probar-reconexion.sh despues`.
6. Contraste el marcador con PostgreSQL y React. Repita la sincronización y compruebe que no hay aumento por duplicados.
7. Para probar reinicio del exportador: `sudo systemctl restart tacticlens-exportador.timer` y `sudo systemctl start tacticlens-exportador.service`; consulte `estado.sh`. No reinicie ni reinstale Cowrie innecesariamente.

Para cambiar al hotspot, conecte ambas laptops, obtenga la nueva IP de Ubuntu (`hostname -I`) y ejecute los dos scripts de Windows con esa IP. Windows detecta su propia dirección; el instalador cambia una sola URL de Ubuntu y conserva la clave/cola. Si UFW permite SSH/2222 únicamente desde la subred anterior, agregue reglas de origen exacto para la nueva IP de Windows desde la consola Ubuntu:

```bash
sudo ufw allow from IP_WINDOWS_ACTUAL to any port 22 proto tcp
sudo ufw allow from IP_WINDOWS_ACTUAL to any port 2222 proto tcp
sudo ufw status
```

No necesita abrir 8000 entrante en Ubuntu: el exportador realiza conexiones salientes. No desactive UFW. Algunos hotspots aíslan clientes; si no hay conectividad entre equipos, debe desactivarse ese aislamiento en el punto de acceso o utilizarse una red local que permita comunicación entre clientes. Las dependencias deben estar instaladas previamente. DeepSeek y el envío de correo pueden requerir Internet; no forman parte de esta prueba.

## Integridad y seguridad conservadas

La migración **007**, ya aplicada en esta máquina, amplía `evento.numero_secuencia` a bigint y agrega `evento_origen`. Esta adaptación HTTP no necesita otra migración. No renumera ni elimina datos históricos. Se mantiene `Cowrie-Prototipo-01` y el mismo `HONEYPOT_ID`.

Las ocurrencias nuevas usan identidad durable de SQLite y orden secuencial por sesión; dos JSON iguales en posiciones distintas no se descartan. El backend serializa la ingesta concurrente por sensor y rechaza cambios de contenido para una identidad ya usada. Los registros inválidos quedan en revisión y no bloquean eventos válidos posteriores. Los cursores se confirman después de guardar duraderamente cada ocurrencia. Se recuperan rotaciones disponibles, incluidas gzip.

HTTP sin cifrar se permite solo con `demo-http`, IPv4 RFC1918 y puerto 8000; el backend exige `AUTH_ENV=development`. Fuera de esa modalidad, la ingesta remota por HTTP se rechaza. No utilice esta modalidad en redes públicas ni producción. La clave de demo es exclusiva y no sustituye la configuración SMTP, LLM o de usuarios. No se confía en X-Forwarded-For ni se siguen redirecciones/proxies en el emisor.

Para retirar la exposición de demostración, detenga su backend y ejecute en PowerShell administrativa, con las IP/interfaz actuales:

```powershell
.\scripts\windows\Configurar-FirewallDemo.ps1 -LocalIP 192.168.0.111 -UbuntuIP 192.168.0.110 -InterfaceIndex 19 -Quitar
```

Esto elimina únicamente la regla propia. No desactiva el firewall. El backend habitual vuelve a iniciarse con `Iniciar-Backend.ps1`; el exportador conserva pendientes mientras no exista un receptor compatible con su clave y URL.

## Pruebas automatizadas

Desde la raíz:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
powershell -NoProfile -ExecutionPolicy Bypass -File tests/test_firewall_demo.ps1
npm.cmd --prefix frontend test
npm.cmd --prefix frontend run build
```

Se utilizan fixtures transaccionales/esquemas aislados y mocks de correo/servicios externos. No se envían correos reales ni se omite MFA. Los resultados entre laptops y el estado observado se documentan en `docs/RESULTADOS_HTTP_LOCAL.md`; una prueba automatizada no sustituye la demostración física.
