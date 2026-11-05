## Instrucciones finales: implementación, análisis histórico y documentación integral

Aplica todos los cambios necesarios tomando en cuenta el contexto del proyecto, los requerimientos anteriores y la implementación existente. Antes de modificar archivos, inspecciona la estructura del repositorio, el modelo de datos, los endpoints, los servicios y las funcionalidades ya desarrolladas.

**Prioriza reutilizar y mejorar el código existente, sin reconstruir componentes que ya funcionan ni introducir cambios innecesarios en la arquitectura o en la base de datos.**

### 1. Mejorar el historial de sesiones y su análisis

Quiero mejorar el módulo de historial de sesiones del honeypot, especialmente su integración con el análisis mediante LLM.

Actualmente pueden registrarse varias sesiones SSH consecutivas. Sin embargo, una sesión anterior podría quedar sin analizar cuando se genera una nueva. Por ello, el historial debe permitir recuperar y analizar sesiones que todavía no hayan sido procesadas.

Implementa o ajusta lo siguiente:

- Mostrar todas las sesiones registradas, tanto analizadas como pendientes.
- Identificar claramente el estado del análisis de cada sesión: `pendiente`, `en proceso`, `analizada` o `error`, utilizando los estados y campos existentes cuando sea posible.
- Incorporar una acción **Analizar** en las sesiones que todavía no tengan un análisis válido.
- Permitir analizar sesiones históricas, aunque posteriormente se hayan registrado otras sesiones.
- Evitar ejecutar nuevamente el análisis de una sesión que ya tenga resultados válidos y completos.
- Si una sesión ya fue analizada, mostrar sus resultados almacenados en PostgreSQL en lugar de volver a consumir la API de DeepSeek.
- Si un análisis falla, permitir reintentarlo sin duplicar los registros previamente generados.
- Impedir que dos solicitudes simultáneas inicien el mismo análisis.
- Si una sesión continúa activa y recibe nuevos eventos después de un análisis, definir un mecanismo para identificar si el resultado quedó desactualizado. No considerar automáticamente vigente un análisis que no contempla todos los eventos relevantes.
- Si el sistema ya dispone de un mecanismo de análisis automático, mantenerlo compatible con el análisis manual desde el historial.

**Importante:** analizar una sesión no debe implicar volver a capturarla ni volver a insertar sus eventos. El análisis debe utilizar los datos que ya están almacenados en PostgreSQL.

El objetivo es evitar llamadas innecesarias a DeepSeek, reducir el consumo de tokens y permitir analizar posteriormente cualquier sesión pendiente.

En el frontend, mejora la experiencia del historial con indicadores de estado, acceso a los eventos, visualización de resultados, manejo de errores y acciones contextuales según el estado de cada sesión.

### 2. Respetar la arquitectura y el flujo del sistema

El proyecto es un prototipo académico de ciberseguridad que integra un honeypot SSH con análisis mediante modelos de lenguaje.

Su arquitectura general combina:

- Cliente-servidor de tres capas: React, FastAPI y PostgreSQL.
- Despliegue distribuido: Ubuntu Server en VirtualBox y backend/base de datos en Windows.
- Ingesta orientada a eventos mediante un recolector Python.
- Pipeline de captura, almacenamiento, análisis y visualización.
- Integración con DeepSeek para el análisis de comportamiento, extracción de IoCs y asociación con MITRE ATT&CK.

El flujo funcional esperado es:

1. Un cliente SSH se conecta al honeypot Cowrie.
2. Cowrie simula un entorno SSH y registra conexiones, autenticaciones y comandos.
3. Los eventos se almacenan en el archivo JSONL de Cowrie.
4. `collector.py` detecta nuevos eventos y los envía automáticamente a FastAPI.
5. FastAPI valida y almacena las sesiones y eventos en PostgreSQL.
6. El sistema permite analizar las sesiones mediante DeepSeek, tanto desde el flujo automático existente, si lo hay, como desde el historial.
7. Los resultados del análisis, posibles IoCs y asociaciones MITRE ATT&CK se almacenan y relacionan con sus sesiones y evidencias.
8. React presenta los registros y resultados mediante una interfaz web.

Mantén la separación entre la ingesta y el análisis LLM: los eventos deben poder almacenarse aunque DeepSeek no esté disponible.

### 3. Mejorar significativamente el README.md

Quiero que el `README.md` se convierta en una **guía integral, técnica y reproducible del proyecto**, útil tanto para desarrolladores como para la presentación de mi tesis.

No quiero un README genérico. Debe describir la implementación real del repositorio, las decisiones arquitectónicas, los requisitos y los pasos para levantar todo el entorno desde cero.

Organiza el README con secciones claras y ejemplos de comandos que se puedan copiar y ejecutar.

#### A. Introducción y objetivos

Explica:

- Qué problema aborda el proyecto.
- Qué es un honeypot y por qué se utiliza Cowrie.
- Cómo se emplea el LLM para interpretar actividades sospechosas.
- Qué son los IoCs y cómo se relacionan con el análisis.
- Para qué se utiliza MITRE ATT&CK.
- Cuáles son las principales funcionalidades del sistema.

#### B. Tecnologías y arquitectura

Documenta las tecnologías realmente utilizadas, incluyendo React, TypeScript, FastAPI, Python, PostgreSQL, Cowrie, VirtualBox, Ubuntu Server y DeepSeek.

Explica las arquitecturas cliente-servidor, tres capas, distribuida y el pipeline de ingesta de eventos.

Incluye un diagrama Mermaid que represente los componentes y sus conexiones.

#### C. Estructura del repositorio

Inspecciona la estructura real del proyecto y documenta sus directorios y archivos principales mediante un árbol de carpetas.

Explica brevemente la responsabilidad de cada componente: frontend, backend, rutas, servicios, modelos, recolector, configuración, migraciones, scripts y pruebas, según lo que exista realmente.

No inventes archivos ni directorios.

#### D. Requisitos previos

Indica los programas, servicios y herramientas necesarios para ejecutar el sistema, distinguiendo los que se instalan en Windows de los que se instalan en Ubuntu Server.

Incluye versiones cuando estén confirmadas por el repositorio o el entorno, y los comandos para verificarlas.

#### E. Configuración de VirtualBox y red

Documenta paso a paso la configuración de red utilizada durante el desarrollo.

La infraestructura actual es:

**Windows (anfitrión):**

- IP Host-only: `192.168.56.1`.
- FastAPI: puerto `8000`.
- PostgreSQL: servicio local, normalmente puerto `5432`.
- React: servidor de desarrollo local.

**Ubuntu Server (máquina virtual):**

- IP Host-only: `192.168.56.101`.
- SSH administrativo: puerto `22`.
- Cowrie SSH simulado: puerto `2222`.

Explica cómo:

1. Crear o habilitar una red Host-only en VirtualBox.
2. Asociar el adaptador Host-only a la máquina virtual.
3. Configurar las direcciones IP y la máscara de red.
4. Configurar una IP estática en Ubuntu, identificando primero el nombre real de la interfaz.
5. Mantener un adaptador NAT adicional si se necesita acceso a Internet desde la VM.
6. Verificar la comunicación entre Windows y Ubuntu mediante `ping`, SSH y HTTP.
7. Comprobar los puertos con `ss` y herramientas equivalentes.
8. Configurar el firewall de Windows para permitir la comunicación necesaria desde la VM.

Aclara que el cliente atacante de las pruebas puede ser PowerShell en Windows, conectado al puerto `2222` de la VM.

Distingue explícitamente el SSH administrativo del SSH simulado de Cowrie.

Las direcciones anteriores son las utilizadas en el entorno de desarrollo, no deben estar incrustadas permanentemente en el código.

#### F. Instalación y configuración de Cowrie en Ubuntu Server

Esta sección debe ser especialmente detallada porque es una de las partes fundamentales del sistema.

Documenta el procedimiento completo desde una instalación limpia:

1. Preparar Ubuntu Server e instalar los paquetes necesarios.
2. Crear un usuario de sistema dedicado llamado `cowrie`, sin utilizar `root` para ejecutar el honeypot.
3. Configurar correctamente su directorio de trabajo y los permisos.
4. Descargar e instalar Cowrie siguiendo el procedimiento compatible con la versión utilizada.
5. Crear y activar el entorno virtual Python.
6. Configurar Cowrie para escuchar conexiones SSH en el puerto `2222`.
7. Configurar la interfaz de escucha adecuada para permitir conexiones desde Windows.
8. Habilitar y verificar la salida de eventos JSON.
9. Explicar la diferencia entre el shell simulado de Cowrie y el Ubuntu real.
10. Iniciar, detener, reiniciar y consultar el estado de Cowrie.
11. Explicar cómo automatizar su arranque mediante systemd, si corresponde.
12. Realizar una conexión SSH de prueba y comprobar que los eventos se registran correctamente.

En nuestra instalación actual se utilizan estas rutas:

- Proyecto Cowrie: `/home/cowrie/my-honeypot/`
- Entorno virtual: `/home/cowrie/my-honeypot/cowrie-env/`
- Log JSON: `/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json`

Los comandos utilizados para iniciarlo manualmente son:

```bash
sudo -u cowrie -H bash
cd /home/cowrie/my-honeypot
source cowrie-env/bin/activate
cowrie start
```

Para comprobar el puerto:

```bash
ss -lnt | grep ':2222'
```

Desde PowerShell:

```powershell
ssh -p 2222 root@192.168.56.101
```

Explica que las credenciales utilizadas para probar Cowrie pertenecen al entorno simulado, no al usuario administrador real de Ubuntu.

#### G. Configuración del recolector automático

Documenta cómo se integra `collector.py` con Cowrie.

Explica:

- Dónde se encuentra el recolector.
- Cómo se transfiere desde Windows hacia Ubuntu mediante SCP.
- Cómo asignar propietario y permisos adecuados.
- Cómo crear el archivo de configuración.
- Cómo configurar la URL de FastAPI.
- Cómo establecer `INGEST_API_KEY`.
- Cómo funciona la lectura incremental de JSONL.
- Cómo se conserva la posición de lectura.
- Cómo se evitan eventos duplicados.
- Cómo se gestionan los reintentos y los errores de conexión.
- Cómo ejecutar el recolector manualmente.
- Cómo configurarlo mediante systemd para que se inicie automáticamente.
- Cómo consultar su estado y sus logs.

Configuración utilizada:

```dotenv
INGEST_URL=http://192.168.56.1:8000/api/ingesta/eventos
INGEST_API_KEY=REEMPLAZAR_CON_CLAVE_COMPARTIDA
COLLECTOR_STATE=/home/cowrie/.config/cowrie-ingest-state.json
```

Ubicación:

`/home/cowrie/.config/cowrie-ingest.env`

Comando manual desde el usuario `william`:

```bash
sudo -u cowrie bash -c 'set -a; source /home/cowrie/.config/cowrie-ingest.env; set +a; python3 /home/cowrie/collector.py'
```

Aclara que no deben ejecutarse simultáneamente dos recolectores que utilicen el mismo archivo de estado.

#### H. Configuración de PostgreSQL

Documenta:

- Cómo crear o preparar la base de datos.
- Cómo configurar la conexión desde FastAPI.
- Cómo aplicar los scripts SQL o migraciones existentes.
- Cómo verificar el esquema `honeypot`.
- Cómo se relacionan las sesiones, eventos, análisis, IoCs y técnicas MITRE ATT&CK.
- Cómo verificar que se están almacenando eventos nuevos.

Respeta el modelo de datos ya diseñado. No recrees las tablas innecesariamente ni asumas que deben eliminarse datos existentes.

Incluye consultas SQL útiles de diagnóstico.

#### I. Instalación y ejecución del backend

Explica cómo:

1. Entrar al directorio correspondiente.
2. Crear un entorno virtual Python.
3. Activarlo desde PowerShell.
4. Instalar las dependencias.
5. Crear y configurar el `.env`.
6. Configurar PostgreSQL, la clave de ingesta y DeepSeek.
7. Iniciar FastAPI.
8. Acceder a la documentación Swagger.
9. Verificar los endpoints principales.

El comando utilizado anteriormente es:

```powershell
python -m uvicorn backend:app --host 192.168.56.1 --port 8000
```

Adapta el comando si la estructura real del backend ha cambiado.

#### J. Instalación y ejecución del frontend

Documenta:

- Requisitos de Node.js y npm.
- Instalación de dependencias con `npm ci` o `npm install`, según corresponda.
- Configuración de variables de entorno de Vite.
- URL del backend.
- Comando para iniciar el servidor de desarrollo.
- Comandos disponibles para compilación, lint y pruebas, si existen.

Ejemplo:

```powershell
npm ci
npm run dev
```

No asumas que el frontend está en la raíz del repositorio: identifica su ubicación real.

#### K. Configuración de DeepSeek

Explica cómo configurar la integración con DeepSeek desde el backend.

Documenta:

- Dónde configurar la API Key.
- Cómo seleccionar el modelo disponible.
- Cómo se realiza el análisis de sesiones.
- Qué datos se envían al modelo.
- Cómo se procesan y validan las respuestas.
- Cómo se almacenan los resultados.
- Cómo se gestionan errores, límites de uso y saldo insuficiente.
- Cómo se evita analizar innecesariamente una misma sesión.

La API Key de DeepSeek debe mantenerse exclusivamente en el backend. No debe exponerse en React, en el repositorio ni en los logs.

No inventes nombres de modelos ni precios: utiliza los valores reales configurados en el proyecto.

#### L. Guía de uso del sistema

Describe un escenario completo:

1. Iniciar PostgreSQL.
2. Iniciar FastAPI.
3. Iniciar React.
4. Iniciar Cowrie.
5. Verificar que el recolector está activo.
6. Conectarse al honeypot desde PowerShell.
7. Ejecutar comandos de prueba.
8. Comprobar que aparece una nueva sesión en el frontend.
9. Consultar sus eventos.
10. Analizar la sesión mediante DeepSeek.
11. Revisar los IoCs y asociaciones MITRE ATT&CK.
12. Recuperar una sesión histórica pendiente y analizarla.
13. Comprobar que una sesión ya analizada no vuelve a consumir tokens innecesariamente.

#### M. Solución de problemas frecuentes

Incluye los errores reales que encontramos durante el desarrollo y cómo diagnosticarlos:

- `Connection refused` al conectar al puerto `2222`.
- Confundir el SSH real del puerto `22` con Cowrie.
- Intentar usar HTTPS cuando FastAPI solo escucha mediante HTTP.
- Errores de permisos en `/home/cowrie/`.
- Intentar ejecutar `sudo` estando conectado como usuario `cowrie`.
- Errores de SCP por usuario o directorio incorrecto.
- Falta del archivo `.env` después de clonar el repositorio.
- Diferencias entre `INGEST_API_KEY` en Windows y Ubuntu.
- Mensaje `Ya existe un recolector usando este estado`.
- Eventos antiguos en PostgreSQL que se confunden con eventos nuevos.
- Cowrie funcionando, pero sin eventos visibles en el frontend.
- FastAPI inaccesible desde Ubuntu por firewall o configuración de IP.
- Fallos de conexión a PostgreSQL.
- Fallos de autenticación o saldo en DeepSeek.

Incluye comandos concretos para diagnosticar cada situación.

#### N. Seguridad y buenas prácticas

Documenta:

- Uso de cuentas de servicio con permisos limitados.
- Gestión de secretos mediante variables de entorno.
- Exclusión de `.env` y archivos sensibles de Git.
- Restricciones de firewall.
- Separación entre SSH administrativo y SSH simulado.
- Uso de redes aisladas para las pruebas.
- Protección de las credenciales capturadas por Cowrie.
- Consideraciones para despliegues fuera del entorno local.

### 4. Archivos de configuración de ejemplo

Si todavía no existen, crea archivos `.env.example` para los componentes correspondientes, con valores de ejemplo seguros y comentarios útiles.

No sobrescribas archivos `.env` reales ni incluyas claves auténticas.

Asegúrate de que la documentación permita restaurar el proyecto después de clonarlo nuevamente desde GitHub.

### 5. Calidad y validación

Antes de finalizar:

- Revisa que los comandos del README coincidan con las rutas y scripts reales.
- Evita instrucciones duplicadas o contradictorias.
- Mantén una documentación ordenada, en español y con Markdown bien estructurado.
- Comprueba que los enlaces internos y los diagramas Mermaid sean válidos.
- Ejecuta las pruebas, compilaciones y verificaciones disponibles.
- No declares funcional una integración que no hayas podido comprobar.
- Distingue las funcionalidades implementadas de las previstas o pendientes.
- Si alguna parte de la instalación requiere decisiones del usuario, documéntalas explícitamente.
- No elimines datos, recrees la base de datos ni modifiques configuraciones sensibles sin necesidad.

### 6. Resultado esperado

Al terminar quiero obtener:

1. Un historial de sesiones más completo y funcional, que permita analizar sesiones pendientes sin repetir análisis válidos.
2. Un mecanismo robusto para almacenar, consultar y reutilizar los resultados del LLM.
3. Una integración coherente entre frontend, backend, PostgreSQL y DeepSeek.
4. Un `README.md` suficientemente completo para instalar, configurar, ejecutar, probar y diagnosticar todo el sistema desde cero.
5. Archivos de configuración de ejemplo cuando sean necesarios.
6. Un resumen final de los cambios realizados, las pruebas ejecutadas y los aspectos que requieran configuración manual.

**Prioridad final:** este proyecto forma parte de una tesis universitaria. Prefiero una solución funcional, mantenible, verificable y correctamente documentada antes que incorporar complejidad innecesaria. La documentación debe reflejar fielmente el sistema implementado, no una arquitectura idealizada que todavía no existe.
