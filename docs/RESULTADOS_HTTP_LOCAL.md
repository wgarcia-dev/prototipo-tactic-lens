# Resultados de HTTP local entre laptops

Fecha: 12 de noviembre de 2026. Punto de retorno: `ebf10b0`.

## Comprobado en los equipos reales

- Windows `192.168.0.111`; Ubuntu `192.168.0.110`.
- Una instancia del backend existente escucha en loopback y en la IP LAN seleccionada, puerto 8000. El frontend conserva su proxy local.
- Regla Windows Firewall `TacticLens-DemoHTTP-Ubuntu`: entrada TCP/8000, origen exacto `192.168.0.110`, destino exacto `192.168.0.111`, interfaz Ethernet. Perfil Public activo, entrada bloqueada por defecto. Domain y Private no se alteraron.
- Se corrigió la repetición de UAC: lectura de regla/filtros/perfil antes de elevar y reutilización cuando coinciden. La comprobación real devuelve True para Ubuntu correcto y False para una IP diferente.
- El operador ejecutó la instalación en Ubuntu mediante SSH administrativo. El procedimiento guardó respaldo SQLite `cola-antes-envio-20261112T070619Z-03b99c86.sqlite3` y respaldo de código/configuración `instalacion-20261112T070619Z` en `/var/lib/tacticlens-cowrie/backups/`.
- `verificar.sh` confirmó Cowrie y timer activos, salud del backend real y PostgreSQL por HTTP directo.
- Salida real de primera entrega: `total_cola=20, enviados=20, pendientes=0, revision=0, errores_envio={}`. La autenticación dejó de producir 401.
- Consultas independientes en Windows confirmaron **26 eventos, 5 sesiones y 23 recibos SQLite**, frente a los 3 eventos y 1 sesión anteriores. Ninguna secuencia repetida dentro de una sesión.
- Marcador previo `TacticLensDemo_74368450eb4b`: evento 82, sesión Cowrie `4830a14e8097`, sesión PostgreSQL `5c33bbda-46c5-42ed-af1d-8b1e50bf0213`, recibo SQLite persistido, 3 eventos en la sesión.
- Marcador nuevo `TacticLensDemo_f7adf1a1d338`: evento 99, sesión Cowrie `4f0cd96655ac`, sesión PostgreSQL `28301527-58ee-4ca2-ac28-333894bef76e`, recibo SQLite persistido, 3 eventos. El timer capturó y entregó automáticamente los eventos posteriores a la instalación.
- La interfaz React autenticada con MFA mostró las 5 sesiones, incluidos los identificadores anteriores. Se abrió la sesión nueva y su línea temporal de 3 eventos.
- No se enviaron correos reales ni se invocó DeepSeek. No se modificó el sistema de autenticación ni Google Authenticator.

## Pruebas automatizadas ejecutadas

- Python: **153 pruebas correctas**, suite completa final de regresión contra PostgreSQL con fixtures aislados y correo externo simulado. Incluye concurrencia, reintentos, pérdida de confirmación, identidad durable, validación del contrato, rotaciones, errores de captura, autenticación/MFA y protección del instalador contra el consumo accidental de archivos ajenos.
- PowerShell 5.1: **9 comprobaciones correctas** del firewall, sin crear reglas ni solicitar UAC. Verifican regla exacta, IP/puerto/interfaz erróneos, fuentes o puertos adicionales, propiedades string/array y firewall desactivado.
- Frontend: **7 pruebas correctas**, compilación Vite correcta. Advertencias preexistentes por directivas `use client` de React Router y tamaño del bundle.
- Sintaxis de PowerShell, Python y Bash comprobada. No se agregó ninguna migración para cambiar el transporte; se conserva la 007 aplicada anteriormente.

## Interrupción y alcance pendiente

Se generó `TacticLensDemo_1794cf10bc57` con FastAPI detenido. El operador comprobó en Ubuntu: **26 filas conservadas, 23 enviadas y 3 pendientes**, sin registros en revisión. Tras reiniciar el backend, el timer entregó automáticamente los tres eventos. PostgreSQL confirmó el marcador en el evento 100, sesión Cowrie `d2a29aaff405`, sesión PostgreSQL `8d5764d6-b642-4e5d-80b8-e909424cded3`, con recibo SQLite y 3 eventos de sesión.

El reinicio real imprimió «Regla de firewall verificada y reutilizada. No se solicita UAC» y FastAPI inició correctamente como usuario normal.

La comprobación posterior en PostgreSQL confirmó **29 eventos, 6 sesiones, 26 recibos de origen y cero secuencias duplicadas**. La sesión recuperada se abrió en React y se desplegó el JSON relevante: mostraba explícitamente `SSH-2.0-TacticLensDemo_1794cf10bc57` y sus tres eventos. La pestaña se dejó abierta para revisión del operador.

El operador ejecutó una nueva sincronización y reinició `tacticlens-exportador.timer` y `tacticlens-exportador.service`. Las tres lecturas posteriores de SQLite coincidieron: **total_cola=26, enviados=26, pendientes=0, revision=0, revision_captura=0, errores_envio={}, reintento_desde=null**. La API seguía informando 29 eventos persistidos. Esto confirma la recuperación, conservación de las filas y funcionamiento después del reinicio del exportador, sin nuevos duplicados.

Se repitió una petición HTTP real del evento ya persistido `TacticLensDemo_f7adf1a1d338`, conservando la identidad de origen. La API devolvió **insertados=0, duplicados=1, rechazados=0** y PostgreSQL mantuvo **29 eventos antes y después**. Esta comprobación de reintento se hizo desde loopback; la entrega original y la recuperación de pendientes sí procedieron del exportador Ubuntu por HTTP directo.

La prueba física en el hotspot del celular **no se ha ejecutado**. El procedimiento está en `DEMO_LAPTOPS.md`; se deben comprobar las IP nuevas, UFW para SSH/2222 y que el hotspot permita comunicación entre clientes. No se declara aprobada por haber funcionado en la red Wi-Fi actual.

## Archivos y configuración

Cambios de backend: `backend/api.py` integra `backend/ingest_transport.py`; `scripts/serve_demo.py` abre dos sockets para una sola aplicación. No se crearon endpoints ni otro backend. Los existentes conservan su contrato: `POST /api/ingesta/eventos`, `POST /api/ingesta/heartbeat`, `GET /api/health`; las consultas autenticadas siguen siendo las existentes.

Exportador y despliegue: `collector/exportar_eventos.py`, `collector/sqlite_sender.py`, `scripts/sync_ingest_key.py`, `scripts/ubuntu/configurar.sh`, `configurar-http.sh`, `sincronizar_clave.py`, `verificar.sh` y `probar-reconexion.sh`.

Windows: scripts nuevos `Iniciar-DemoHTTP.ps1`, `Configurar-FirewallDemo.ps1`, `Test-FirewallDemo.ps1`, `Configurar-UbuntuHTTP.ps1`; se adaptaron `Preparar-KitUbuntu.ps1` y `Sincronizar-ClaveUbuntu.ps1`. Todos están en `scripts/windows/`.

Pruebas: `tests/test_demo_http.py`, `tests/test_firewall_demo.ps1`, actualización de `tests/test_key_sync.py` y del cliente de red de una prueba de concurrencia en `tests/test_ingestion.py`. Utilidad reproducible: `scripts/cowrie_demo.py`. Documentación: `README.md`, `.env.example`, `docs/DEMO_LAPTOPS.md` y este informe.

Variables nuevas: `TACTICLENS_TRANSPORT=demo-http` únicamente en Ubuntu; `INGEST_TRANSPORT=demo-http`, `INGEST_DEMO_LOCAL_IP` y `INGEST_DEMO_UBUNTU_IP` solo en el proceso del backend iniciado por el script. Se reutilizan `TACTICLENS_URL`, `TACTICLENS_TOKEN`, `TACTICLENS_SENSOR_ID` e `INGEST_API_KEY` (sobrescrita solo en el proceso de demo con su clave exclusiva). No se cambiaron secretos reales del `.env`, ni variables SMTP/LLM ni configuración de cuentas.

La carpeta `.local/`, `.env` y `frontend/.env` están ignorados por Git. Se revisaron los archivos versionables contra los valores secretos locales sin imprimirlos: ninguna coincidencia.
