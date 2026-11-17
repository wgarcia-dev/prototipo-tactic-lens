# Monitoreo local de Cowrie sin recargar la página

> Referencia de la etapa anterior de polling. El modo vigente por eventos y
> WebSocket, que sustituye el timer de 2 s y el polling de monitoreo de 1 s, se
> documenta en [TIEMPO_REAL_WEBSOCKET.md](TIEMPO_REAL_WEBSOCKET.md).

El recorrido se conserva: Cowrie → cola SQLite durable → HTTP directo → API
existente `/api/ingesta/eventos` → PostgreSQL → React. No hay WebSockets ni
ejecuciones automáticas del análisis LLM. No se requieren migraciones ni nuevas
dependencias.

## Cadencia y controles

- El temporizador existente intenta ejecutar el mismo servicio `oneshot` **2 s
  después de que termina** la ejecución anterior, con `AccuracySec=100ms` y sin
  retardo aleatorio. No es una garantía de entrega cada dos segundos: un envío
  lento o los reintentos del exportador pueden demorar más.
- Systemd no inicia otra instancia de la misma unidad mientras sigue activa.
  Se comprueba además el bloqueo exclusivo `flock` del exportador instalado.
  No se sustituye el código del exportador ni se altera SQLite.
- Dashboard, lista de sesiones y metadatos de la sesión consultan cada **1 s**.
  Cada ciclo espera a que terminen sus peticiones antes de programar el siguiente.
  Una pestaña oculta pausa las consultas y cancela las peticiones pendientes;
  al volver a mostrarla se actualiza. Los errores aplican espera progresiva,
  hasta 15 s.
- Se conservan los datos visibles durante una actualización; los resultados
  iguales reutilizan su referencia y las barras no reinician animaciones.
- La lista de eventos se vuelve a pedir cuando cambia el número de eventos o la
  página. El análisis almacenado se consulta cuando cambia su identificador.
  El botón **Analizar** continúa siendo manual.
- El resumen usa una caché de proceso de 750 ms compartida entre consultas
  concurrentes. Una ingesta nueva la invalida después del commit. Los permisos
  y MFA siguen verificándose antes de entregar el resumen.
- La comprobación de salud sigue cada 5 s y las listas de IoCs/MITRE cada 5 s.

## Iniciar una demostración posterior

En PowerShell, desde la raíz del repositorio, usando las direcciones actuales:

```powershell
.\scripts\windows\Iniciar-DemoHTTP.ps1 -UbuntuHost 192.168.0.100
```

En otra terminal:

```powershell
.\scripts\windows\Iniciar-Frontend.ps1
```

Abrir `http://127.0.0.1:5173/`, iniciar sesión con MFA y mantener visible el
dashboard. La sección **Últimos comandos observados** muestra los cinco comandos
más recientes con enlace a su sesión.

El ajuste del temporizador **ya está aplicado** en el servidor actual y persiste
después de reiniciar. No es necesario repetirlo en cada arranque. Si cambia la
IP de Windows, iniciar primero el backend con el script anterior y ejecutar:

```powershell
.\scripts\windows\Configurar-Monitoreo.ps1 -UbuntuHost 192.168.0.100
```

Este auxiliar copia un script público mediante SCP y lo ejecuta con SSH/sudo.
SSH se usa solo para administración. Las contraseñas se introducen en la terminal.
Se valida la clave existente sin almacenar un evento de prueba inválido, se
respalda la configuración en un directorio privado y se modifica solamente la
URL cuando sea necesario y el drop-in del temporizador:

`/etc/systemd/system/tacticlens-exportador.timer.d/20-monitoreo-local.conf`

Puede inspeccionarse el plan local sin modificar Ubuntu:

```powershell
.\scripts\windows\Configurar-Monitoreo.ps1 -UbuntuHost 192.168.0.100 -SoloComprobar
```

Desde una terminal administrativa de Ubuntu, para consultar el estado sin
reconfigurar nada:

```bash
systemctl show tacticlens-exportador.timer -p ActiveState -p TimersMonotonic -p AccuracyUSec
sudo python3 /opt/tacticlens-cowrie/exportar_eventos.py --status
```

La demostración HTTP se limita a la red privada y a la IP autorizada en el
firewall. Conservar HTTPS en producción. La comunicación local y el monitoreo
no requieren Internet; el proveedor LLM y el correo externo sí pueden requerirlo.

## Medición ejecutada

Prueba real del **15 de noviembre de 2026, 20:45:30 (America/Guayaquil)**:

| Comprobación | Resultado |
| --- | --- |
| Comando en Cowrie TCP/2222 | `echo TacticLensLive_dc6ec1706dae` |
| Evento persistido | `1639` |
| Sesión | `5d7a60c4-c1c6-4fdc-af93-604c79d89d06` |
| Envío del comando → timestamp de persistencia PostgreSQL | 779,8 ms |
| Detección SQL desde Windows | 875,0 ms |
| Comando visible automáticamente en el dashboard | antes de 3,85 s |
| Reenvío del mismo evento y origen a la API | 0 insertados, 1 duplicado |
| Ocurrencias del comando en PostgreSQL después del reenvío | 1 |

La medida visual es un **límite superior observado**, pues incluye el tiempo
hasta que la herramienta leyó la página. No es una medida exacta del instante
de pintado ni una garantía para todas las redes. No se recargó ni se navegó la
página entre el envío y la observación. Después se comprobó también la sesión y
su línea de tiempo en React.

El auxiliar opcional usa el cliente SSH de Git para Windows ya instalado y una
contraseña ficticia desechable exclusivamente contra el honeypot TCP/2222:

```powershell
.\.venv\Scripts\python.exe -m scripts.medir_monitoreo --ubuntu 192.168.0.100
```

Genera eventos reales de demostración y registra los tiempos locales en
`.local/monitoreo/`, directorio ignorado por Git. Nunca utiliza credenciales
administrativas. `--armar` permite preparar la sesión y esperar un archivo de
disparo para coordinar una observación visual.

## Verificación automatizada de esta modificación

Se ejecutaron con éxito 22 pruebas Python: 4 de monitoreo/caché/autenticación,
3 del ajuste del temporizador con systemd simulado, 8 de ingestión y 7 del núcleo.
Las pruebas de integración usan PostgreSQL y rollback; no ejecutan migraciones.
Las pruebas del temporizador verifican respaldos, conservación de la cola,
idempotencia y restauración ante fallos. La configuración real del temporizador
se confirmó separadamente con la salida de Ubuntu.

También pasaron las 13 pruebas del frontend (incluidas 6 de polling), la
compilación TypeScript/Vite y las comprobaciones de argumentos en PowerShell 5.1.
No se ejecutó nuevamente la batería completa del repositorio, ni se probaron
envíos de correo o llamadas LLM.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_monitoring.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_monitoring_timer.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_core.py
```

Desde `frontend`: `npm.cmd test` y `npm.cmd run build`.
