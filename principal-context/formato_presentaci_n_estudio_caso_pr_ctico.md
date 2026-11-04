# UNEMI - UNIVERSIDAD ESTATAL DE MILAGRO

## DISEÑO DE INTEGRACIÓN CURRICULAR

### FORMATO DE PRESENTACIÓN - ESTUDIO DE CASO PRÁCTICO

**CARRERA DE INGENIERÍA DE SOFTWARE**

_Extensión máxima: 2 páginas_

---

## 1. DATOS GENERALES

| Campo                                      | Detalle                                                                                                          |
| :----------------------------------------- | :--------------------------------------------------------------------------------------------------------------- |
| **Estudiante 1:**                          | \*\*                                                                                                             |
| **Estudiante 2:**                          | \*\*                                                                                                             |
| **Correo electrónico:**                    | —                                                                                                                |
| **Teléfono:**                              | —                                                                                                                |
| **Título del trabajo (máx. 20 palabras):** | Plataforma web para análisis de eventos de honeypot mediante LLM para extraer IoCs y mapear TTPs en MITRE ATT&CK |
| **Línea de investigación:**                | Desarrollo de sistemas inteligentes, Big Data y Ciberseguridad                                                   |

---

## 2. DEFINICIÓN DE LA PROPUESTA

### 2.1 Problema y contexto

Los honeypots permiten registrar actividades potencialmente maliciosas en entornos controlados; no obstante, la información obtenida requiere un proceso de interpretación que permita comprender el comportamiento observado durante las sesiones. La dificultad se presenta al transformar estos eventos técnicos en información estructurada que facilite la identificación de indicadores de compromiso (IoCs), el mapeo de las acciones registradas con técnicas y tácticas de MITRE ATT&CK y la detección de patrones relevantes para el análisis de seguridad. Esta situación limita el aprovechamiento de los datos recopilados y dificulta su conversión en información útil para apoyar el análisis y la comprensión de la actividad observada.

### 2.2 Solución de software propuesta

Se propone desarrollar una plataforma web dirigida a analistas y administradores de seguridad, orientada al análisis de los eventos generados por un honeypot de código abierto en un entorno controlado. La solución permitirá recopilar, almacenar y procesar las sesiones registradas mediante un modelo de lenguaje de gran escala (LLM), con el fin de interpretar el comportamiento observado, identificar indicadores de compromiso (IoCs) y mapear las acciones detectadas con técnicas y tácticas de MITRE ATT&CK. La información procesada se presentará mediante consultas, métricas y visualizaciones que faciliten el análisis de la actividad registrada.

### 2.3 Objetivo del aplicativo

Desarrollar una plataforma web para el análisis de eventos de un honeypot mediante LLM para la extracción de IoCs y mapeo de TTPs en MITRE ATT&CK.

### 2.4 Usuarios y roles principales

- **Administrador de seguridad:** Será responsable de gestionar la configuración general de la plataforma, administrar los usuarios y permisos de acceso, supervisar la integración con el honeypot y los componentes de análisis, y consultar las sesiones registradas, los IoCs identificados, las TTPs asociadas y los paneles de visualización disponibles.
- **Analista de seguridad:** Será responsable de revisar y analizar las sesiones y eventos generados por el honeypot, consultar los IoCs identificados y las TTPs mapeadas con MITRE ATT&CK, interpretar los resultados del análisis y utilizar las métricas y visualizaciones de la plataforma para comprender el comportamiento observado.

---

## 3. ALCANCE FUNCIONAL Y PROPUESTA TÉCNICA

### 3.1 Funcionalidades principales del aplicativo

- **RF-01.** El sistema deberá recopilar y almacenar las sesiones y eventos generados por el honeypot, conservando la información necesaria para su posterior procesamiento y análisis.
- **RF-02.** El sistema deberá procesar los eventos registrados mediante un modelo de lenguaje de gran escala (LLM) para interpretar las acciones realizadas durante cada sesión y generar información estructurada sobre el comportamiento observado.
- **RF-03.** El sistema deberá identificar y almacenar indicadores de compromiso (IoCs) presentes en los eventos analizados, manteniendo su relación con las sesiones y acciones en las que fueron detectados.
- **RF-04.** El sistema deberá relacionar los comportamientos identificados durante las sesiones con técnicas y tácticas de MITRE ATT&CK, registrando la evidencia asociada a cada mapeo para facilitar su interpretación.
- **RF-05.** El sistema deberá permitir consultar y reconstruir cronológicamente las sesiones registradas, mostrando los eventos ocurridos, los IoCs identificados, las técnicas y tácticas asociadas y los resultados obtenidos durante el análisis.
- **RF-06.** El sistema deberá presentar indicadores, métricas y visualizaciones sobre las sesiones, IoCs y técnicas de MITRE ATT&CK identificadas, con el propósito de facilitar el análisis de patrones y comportamientos registrados.

### 3.2 Alcance y delimitación

La versión funcional incluirá una plataforma web con autenticación y control de acceso por roles, integrada con un honeypot de código abierto desplegado en un entorno controlado. La solución contemplará la captura y almacenamiento de sesiones y eventos, su procesamiento mediante un modelo de lenguaje de gran escala (LLM), la identificación de indicadores de compromiso (IoCs), el mapeo de los comportamientos observados con técnicas y tácticas de MITRE ATT&CK, la consulta detallada de las sesiones y la visualización de métricas e indicadores mediante paneles de análisis.

**Fuera del alcance:** Quedan fuera del alcance el desarrollo de un honeypot propio, el entrenamiento o ajuste de un LLM desde cero, el análisis de malware, la protección integral de redes empresariales, el reemplazo de soluciones SIEM, IDS o IPS y el despliegue distribuido de múltiples honeypots.

### 3.3 Propuesta técnica inicial

- **Frontend:** React.js con Vite y Tailwind CSS para la construcción de la interfaz web. Se utilizará una librería de visualización como Recharts para representar métricas, indicadores y resultados del análisis.
- **Backend:** Python con FastAPI para implementar la lógica de negocio, autenticación, recepción y procesamiento de los eventos generados por el honeypot, así como la comunicación con el modelo LLM y la exposición de servicios mediante API REST.
- **Base de datos:** PostgreSQL para almacenar usuarios, sesiones, eventos, indicadores de compromiso (IoCs), técnicas y tácticas de MITRE ATT&CK y resultados del análisis. Se utilizarán campos JSONB cuando sea necesario conservar información de eventos con estructuras variables.
- **APIs o servicios externos:** MITRE ATT&CK será utilizado como base de conocimiento mediante sus datos estructurados en formato STIX/JSON para consultar y asociar las técnicas y tácticas correspondientes a los comportamientos identificados. El modelo LLM será integrado como componente de análisis para interpretar los eventos y apoyar el mapeo de los comportamientos observados.
- **Otros componentes:** Cowrie será utilizado como honeypot de código abierto, desplegado de forma independiente en un entorno aislado, desde el cual se obtendrán los eventos analizados por la plataforma. Docker y Docker Compose permitirán aislar y organizar los servicios del proyecto, mientras que JWT y el control de acceso basado en roles se utilizarán para gestionar la autenticación y autorización de los usuarios.

### 3.4 Arquitectura o componentes previstos

La arquitectura estará compuesta por un honeypot de código abierto desplegado de forma independiente en un entorno controlado, encargado de registrar las sesiones y eventos generados durante las interacciones. Estos datos serán enviados al backend, desarrollado con FastAPI, donde se realizará su procesamiento, almacenamiento en PostgreSQL y comunicación con el modelo LLM para interpretar el comportamiento observado. El backend utilizará la información estructurada de MITRE ATT&CK para relacionar los comportamientos identificados con sus técnicas y tácticas correspondientes. Finalmente, el frontend web consumirá la API para presentar sesiones, IoCs, resultados del análisis, mapeos MITRE ATT&CK, métricas e indicadores.

### 3.5 Resultado funcional esperado

El aplicativo deberá demostrar la captura y almacenamiento persistente de las sesiones y eventos generados por el honeypot, así como su procesamiento mediante un modelo de lenguaje de gran escala (LLM) para interpretar el comportamiento observado, identificar IoCs y apoyar el mapeo de técnicas y tácticas de MITRE ATT&CK. La plataforma deberá permitir consultar el detalle cronológico de las sesiones, revisar los resultados del análisis y visualizar métricas e indicadores de seguridad. Asimismo, se deberá comprobar la correcta comunicación entre el honeypot, el backend, la base de datos, el modelo LLM y el frontend, además del funcionamiento de la autenticación, el control de acceso y las principales funcionalidades mediante pruebas funcionales.

---

## REGISTRO DE FIRMAS Y REVISIÓN

| ESTUDIANTE 1                            | ESTUDIANTE 2                                |
| :-------------------------------------- | :------------------------------------------ |
| **Firma:** ************\_\_************ | **Firma:** **************\_\_************** |

### REVISIÓN DOCENTE

- [ ] Aprobada
- [ ] Aprobada con ajustes
- [ ] Requiere reformulación

**Nombre del Tutor:** Ruano Lara Erick Leandro  
**Observaciones:** ****************************************\_****************************************  
**Firma:** ************\_\_************

---

### Nota de validación del tutor

> Con su firma, el tutor deja constancia de haber revisado la propuesta, su alcance funcional y técnico, y de haber proporcionado las orientaciones y recomendaciones pertinentes para su desarrollo. La firma implica la conformidad con la propuesta presentada; por tanto, durante la ejecución del estudio de caso no deberán solicitarse cambios sustanciales que modifiquen el objetivo, alcance o funcionalidades principales previamente aprobadas, salvo que existan razones técnicas o académicas debidamente justificadas.
