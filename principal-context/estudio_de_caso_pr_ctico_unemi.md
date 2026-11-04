# UNEMI - UNIVERSIDAD ESTATAL DE MILAGRO

## ESTUDIO DE CASO PRÁCTICO

**Título:** Plataforma web para análisis de eventos de honeypot mediante LLM para extraer IoCs y mapear TTPs en MITRE ATT&CK

## 1. Introducción

### 1.1. Descripción

Los honeypots son herramientas de seguridad que permiten registrar interacciones dirigidas a servicios expuestos en entornos controlados. A través de la captura de conexiones, intentos de autenticación y comandos ejecutados, proporcionan información sobre actividades potencialmente maliciosas y los comportamientos observados durante una sesión (Oliveira et al., 2026). Herramientas de código abierto como Cowrie facilitan la obtención de estos registros. Sin embargo, la recopilación de eventos constituye únicamente la primera etapa del análisis, debido a que los datos obtenidos requieren interpretación para comprender las acciones realizadas y su posible relación con técnicas de ataque.

Los eventos generados por un honeypot contienen información técnica que puede presentar diferentes estructuras y niveles de detalle según la actividad registrada. Una sesión puede comprender múltiples eventos relacionados, como intentos de acceso, ejecución de comandos e interacciones posteriores con el entorno simulado. Aunque cada registro proporciona información específica, su análisis aislado puede resultar insuficiente para comprender el comportamiento desarrollado durante toda la interacción. Por esta razón, es necesario conservar la secuencia temporal de los eventos y establecer relaciones que permitan interpretar las acciones dentro de su contexto original (Oliveira et al., 2026).

El problema radica en la dificultad de transformar estos registros técnicos en información estructurada que facilite el análisis de las actividades observadas. Los datos pueden contener direcciones IP, dominios, URL, comandos y otros elementos relevantes, pero su presencia no determina por sí sola el significado de una interacción. Identificar indicadores de compromiso (IoCs) y relacionar determinados comportamientos con técnicas y tácticas de MITRE ATT&CK requiere interpretar la información disponible, considerar la secuencia de acciones y conservar las evidencias que sustentan cada asociación (Johnson et al., 2016).

Estas dificultades se originan principalmente en la diversidad de los registros generados, el análisis aislado de los eventos y la ausencia de mecanismos que integren las sesiones, indicadores y resultados obtenidos; como consecuencia, se limita el aprovechamiento de la información recopilada por el honeypot (Oliveira et al., 2026). Cuando los eventos, los indicadores identificados y los resultados del análisis no mantienen una relación estructurada, resulta más difícil reconstruir una sesión, reconocer comportamientos recurrentes y determinar qué registros respaldan una interpretación. Esta situación también dificulta la consulta de información consolidada y la elaboración de indicadores que permitan examinar la actividad registrada desde diferentes perspectivas, reduciendo la utilidad de los datos para los usuarios encargados de su análisis.

Para atender esta necesidad, se propone desarrollar una plataforma web que integre la recopilación, el almacenamiento y el análisis de eventos generados por un honeypot de código abierto mediante un modelo de lenguaje de gran escala (LLM). La solución estará orientada a transformar los registros capturados en información estructurada, identificando IoCs y relacionando los comportamientos observados con tácticas y técnicas documentadas en MITRE ATT&CK. De esta manera, se busca proporcionar un entorno que permita consultar tanto los eventos originales como los resultados derivados de su procesamiento.

En este contexto, el honeypot funcionará como un componente externo e independiente de la plataforma, desplegado en un entorno controlado para registrar las interacciones recibidas. Los eventos generados serán recopilados y almacenados junto con la información correspondiente a sus sesiones, conservando sus datos originales y referencias temporales. Esta organización permitirá reconstruir cronológicamente las actividades registradas y establecer una base de información consistente para las etapas posteriores del procesamiento, sin modificar el funcionamiento del honeypot ni intervenir en las respuestas proporcionadas durante la interacción.

Sobre esta información se incorporará el procesamiento mediante un LLM, cuya función será interpretar los comportamientos registrados y reconocer elementos relevantes para el análisis de seguridad. La extracción de IoCs permitirá identificar posibles indicadores presentes en los eventos, mientras que la utilización de MITRE ATT&CK proporcionará una referencia para asociar las acciones observadas con técnicas y tácticas documentadas (Krašovec et al., 2025). Ambas actividades requieren considerar el contexto de las interacciones, debido a que determinados comandos o registros pueden admitir distintas interpretaciones según las circunstancias en las que se producen (Froudakis et al., 2025).

Por ello, los resultados generados no se tratarán como afirmaciones definitivas sobre las actividades registradas, sino como interpretaciones que deberán conservar una relación verificable con la información de origen. La plataforma almacenará las evidencias y justificaciones asociadas a los indicadores y mapeos identificados, permitiendo examinar los eventos que sustentan cada resultado. Esta característica resulta relevante ante las posibles imprecisiones de los modelos de lenguaje, pues facilita la revisión de las asociaciones realizadas y evita que la interpretación de una sesión quede desvinculada de los registros que la originaron (Froudakis et al., 2025).

La información obtenida se presentará mediante una interfaz web que facilite su consulta desde distintos niveles de detalle. Los usuarios podrán partir de una visión general de la actividad registrada y examinar posteriormente las sesiones, los eventos y los resultados de su procesamiento. La reconstrucción cronológica permitirá comprender el desarrollo de cada interacción, mientras que los indicadores y gráficos ofrecerán una perspectiva agregada de los datos almacenados. Así, la visualización no se limitará a presentar estadísticas, sino que estará vinculada con la información que permite explicar los comportamientos identificados.

Estas capacidades estarán dirigidas a administradores y analistas de seguridad, cuyas responsabilidades determinarán las funcionalidades disponibles dentro de la plataforma. Mientras los administradores se encargarán de la configuración de los componentes y la gestión de los accesos, los analistas dispondrán de herramientas para examinar las sesiones y contrastar los resultados obtenidos con sus respectivas evidencias. La organización de la información y el control de acceso por roles permitirán mantener una separación de responsabilidades sin afectar la continuidad del proceso de análisis.

La realización del proyecto se justifica por la necesidad de mejorar el aprovechamiento de los eventos registrados por un honeypot, integrando en una misma plataforma su almacenamiento, procesamiento, contextualización y consulta. La solución permitirá mantener una relación verificable entre los registros originales, los IoCs identificados y los mapeos realizados, facilitando el análisis de las sesiones sin sustituir el criterio del especialista. De esta manera, se busca atender una necesidad concreta relacionada con la organización e interpretación de información de seguridad, beneficiando principalmente a administradores y analistas encargados de revisar la actividad registrada.

### 1.2. Propósito del caso

La finalidad es desarrollar una plataforma web funcional que permita aprovechar la información obtenida de un honeypot para el análisis de eventos de seguridad. Mediante la integración de un modelo de lenguaje de gran escala (LLM), se busca obtener información estructurada sobre indicadores de compromiso (IoCs) y comportamientos relacionados con MITRE ATT&CK, conservando las evidencias que respaldan los resultados.

La solución estará destinada a administradores y analistas de seguridad, quienes podrán consultar las sesiones registradas y examinar las interpretaciones generadas dentro de su contexto original. Con ello, se pretende disponer de una herramienta que facilite la consulta y comprensión de las actividades observadas en un entorno controlado.

La construcción de la plataforma permitirá aplicar conocimientos relacionados con el diseño de aplicaciones web, la integración de servicios, el almacenamiento de datos y el procesamiento de información mediante modelos de lenguaje. Estos aprendizajes se desarrollarán a partir de la conexión entre los componentes de la solución y la organización de los resultados para su posterior consulta. Asimismo, se realizarán pruebas funcionales que permitan comprobar la comunicación entre los módulos, la persistencia de los registros y la correspondencia de la información presentada con los datos almacenados. El resultado esperado será una plataforma funcional que demuestre la integración de sus componentes y el cumplimiento de las funcionalidades previstas, sin contemplar su puesta en producción ni su utilización como herramienta de protección activa.

#### 1.2.1. Objetivo general

Desarrollar una plataforma web para el análisis de eventos de un honeypot mediante LLM para la extracción de IoCs y mapeo de TTPs en MITRE ATT&CK.

#### 1.2.2. Objetivos específicos

- Identificar indicadores de compromiso (IoCs) a partir de los eventos registrados por un honeypot de código abierto, mediante su recopilación, almacenamiento y procesamiento con un LLM, conservando la relación de los indicadores identificados con sus evidencias de origen.
- Mapear los comportamientos observados durante las sesiones del honeypot con las técnicas y tácticas de MITRE ATT&CK, mediante la interpretación de las acciones identificadas por el LLM y el registro de las evidencias y justificaciones correspondientes.
- Presentar los resultados del análisis mediante una plataforma web que integre la consulta cronológica de sesiones y eventos, la visualización de IoCs y mapeos MITRE ATT&CK, así como indicadores y métricas que faciliten la interpretación de las actividades registradas.

---

## 2. Referentes Empíricos

Las investigaciones sobre el uso de modelos de lenguaje en el análisis de amenazas informáticas presentan diferentes enfoques para procesar e interpretar información de seguridad. Algunos trabajos se centran en los eventos registrados por honeypots, mientras que otros examinan la identificación de indicadores de compromiso (IoCs) y el mapeo de comportamientos con MITRE ATT&CK a partir de informes de amenazas.

Los cuatro estudios seleccionados abordan estas aplicaciones mediante procedimientos y criterios de evaluación distintos, cuyos resultados permiten examinar las posibilidades y limitaciones del procesamiento mediante LLM, especialmente en la interpretación contextual de los datos y la correspondencia entre los hallazgos obtenidos y sus evidencias de origen.

### 2.1. Análisis de eventos de honeypot mediante LLM – Portugal

Oliveira et al. (2026), en su investigación titulada _An Integrated Honeypot and LLM-Based Framework for near Real-Time Detection and Behavioral Analysis of Malicious Activities_, desarrollaron una arquitectura que combina el honeypot Cowrie con un modelo de lenguaje ejecutado localmente para analizar actividades registradas durante sesiones de interacción. El estudio aborda la dificultad de interpretar eventos técnicos que, al examinarse individualmente, pueden proporcionar información insuficiente sobre las acciones realizadas. Su propuesta incorpora mecanismos de recopilación, organización temporal y procesamiento contextual para obtener una representación más comprensible del comportamiento observado.

La arquitectura desarrollada utiliza Python para procesar los registros generados por Cowrie y organiza los eventos de acuerdo con sus sesiones antes de enviarlos al modelo Mistral NeMo. Esta preparación permite conservar información sobre intentos de autenticación, secuencias de comandos y actividades posteriores al acceso. El procesamiento mediante LLM produce resultados estructurados que incluyen clasificaciones de severidad, explicaciones y recomendaciones. Los autores destacan la importancia de combinar procedimientos deterministas de tratamiento de datos con la interpretación contextual del modelo, debido a que ambos componentes intervienen en la consistencia de los resultados.

La evaluación se realizó mediante escenarios controlados que incluyeron actividades de distinta naturaleza e intensidad. Sobre un conjunto de 52 observaciones independientes, los investigadores reportaron una exactitud del $94.23\%$, una precisión del $100\%$ y un F1-score del $93.33\%$ para la clasificación de actividades maliciosas. Sin embargo, reconocieron que estas mediciones corresponden a condiciones experimentales específicas y no constituyen evidencia suficiente para garantizar el mismo rendimiento en entornos operativos más amplios. También identificaron dificultades al interpretar sesiones de baja intensidad y comportamientos ambiguos, cuya clasificación puede depender de la información disponible.

La organización de los registros por sesión antes de su procesamiento constituye un aspecto relevante para interpretar secuencias de eventos sin perder el contexto de las acciones observadas. La arquitectura desarrollada por Oliveira et al. (2026) permite separar la captura de información mediante Cowrie de su análisis posterior con un LLM, manteniendo ambos procesos como componentes independientes. Este enfoque resulta adecuado para una plataforma centrada en el tratamiento de eventos, donde la interpretación de las actividades depende de la información recopilada durante cada interacción. No obstante, los resultados de exactitud reportados corresponden a la clasificación de comportamientos y no permiten anticipar la precisión que podría alcanzarse en la identificación de IoCs o en el mapeo de técnicas de MITRE ATT&CK.

### 2.2. Integración de inteligencia artificial y visualización de amenazas – Estados Unidos

Devkar & Chen (2026), en el trabajo _An AI-Enhanced SSH Honeypot for Real-Time Threat Intelligence and Interactive Security Analytics_, presentaron una solución que combina un honeypot SSH con mecanismos de inteligencia artificial para transformar las interacciones capturadas en información destinada a su análisis. La propuesta contempla un entorno de interacción que registra los comandos ejecutados y utiliza un LLM para atender determinadas instrucciones que no están contempladas en su lógica convencional. Paralelamente, incorpora un proceso de enriquecimiento de eventos orientado a proporcionar información estructurada sobre los comportamientos registrados.

El componente de análisis examina los comandos capturados para generar descripciones comprensibles, etiquetas de comportamiento relacionadas con MITRE ATT&CK, niveles de riesgo e indicadores de compromiso. Estos resultados se exponen mediante servicios de consulta y una interfaz gráfica que permite explorar eventos e información asociada con su procedencia. De esta manera, la solución integra la captura de interacciones con un mecanismo de interpretación que facilita la consulta de los hallazgos desde una misma interfaz, conservando referencias a las actividades que originaron cada resultado.

Los investigadores presentaron una demostración del funcionamiento de la arquitectura utilizando registros capturados y sesiones reproducidas. También realizaron una evaluación preliminar del procesamiento de eventos mediante datos etiquetados y una comparación cualitativa con Cowrie. Los resultados permiten observar la integración de los componentes y la presentación de información enriquecida, aunque el carácter demostrativo del trabajo limita las conclusiones sobre su rendimiento en condiciones más amplias.

La presentación conjunta de los eventos y de la información obtenida mediante su procesamiento permite examinar los hallazgos sin desvincularlos de los registros originales. Esta organización resulta especialmente útil cuando se requiere consultar indicadores de compromiso y asociaciones con MITRE ATT&CK, debido a que cada resultado debe conservar referencias a las acciones que sustentan su interpretación. Aunque Devkar y Chen también incorporan mecanismos para generar respuestas dinámicas durante las interacciones, esta capacidad responde a una finalidad diferente del análisis posterior de los eventos. La separación de ambas funciones permite concentrar el desarrollo en la interpretación y consulta de información, sin necesidad de modificar el comportamiento del honeypot.

### 2.3. Identificación de técnicas MITRE ATT&CK mediante LLM – Italia

Krašovec et al. (2025), en su investigación _Large Language Models for Cyber Threat Intelligence: Extracting MITRE With LLMs_, estudiaron el uso de modelos de lenguaje para relacionar información textual de amenazas con las técnicas documentadas en MITRE ATT&CK. El problema abordado se relaciona con la dificultad de clasificar descripciones de actividades cuando existe un número considerable de técnicas posibles y su identificación depende de la interpretación del contexto. Los investigadores plantearon un procedimiento que busca disminuir la cantidad de alternativas que deben examinarse durante la clasificación.

La metodología utiliza dos etapas consecutivas. Inicialmente, un LLM compara los fragmentos de información con las descripciones de las técnicas para seleccionar aquellas que presentan una posible relación. Posteriormente, el modelo organiza las alternativas seleccionadas según su correspondencia con el contenido analizado. Para evaluar este procedimiento, los autores utilizaron un informe real de inteligencia de amenazas y el conjunto de datos TRAM, integrado por fragmentos de texto etiquetados con técnicas de MITRE ATT&CK. Esta organización permitió examinar por separado la capacidad de recuperar técnicas relevantes y la precisión de la clasificación final.

Los resultados mostraron que el procedimiento podría reducir considerablemente el número de técnicas candidatas. En el conjunto TRAM, el filtrado disminuyó aproximadamente 33 veces la cantidad de alternativas y conservó la técnica correcta entre las seleccionadas en el $84.84\%$ de los casos. No obstante, la exactitud de la clasificación final fue del $29.08\%$, una diferencia que evidencia las dificultades del modelo para escoger correctamente una técnica entre varias opciones relacionadas. Los investigadores señalaron que el enfoque puede apoyar el trabajo de los analistas, pero que sus resultados requieren revisión y no sustituyen necesariamente el criterio especializado.

La diferencia entre recuperar técnicas potencialmente relacionadas y clasificarlas correctamente evidencia una limitación que debe considerarse al utilizar modelos de lenguaje para el mapeo de comportamientos. Los resultados obtenidos por Krašovec et al. muestran que reducir el número de técnicas candidatas no garantiza que la asociación final corresponda con la actividad analizada. Esta distinción adquiere relevancia cuando se interpretan acciones registradas durante sesiones de un honeypot, debido a que la coincidencia entre una descripción técnica y un comportamiento observado puede resultar insuficiente para establecer una clasificación. Por ello, conservar los eventos originales y las justificaciones asociadas a cada mapeo permitirá examinar las correspondencias generadas.

### 2.4. Extracción contextual de indicadores de compromiso – Estados Unidos

Froudakis et al. (2025), en el trabajo _Revealing the True Indicators: Understanding and Improving IoC Extraction From Threat Reports_, analizaron las dificultades relacionadas con la identificación automática de indicadores de compromiso en documentos de inteligencia de amenazas. Los investigadores observaron que reconocer direcciones IP, dominios, URL u otros elementos técnicos no es suficiente para determinar su relevancia, debido a que algunos pueden aparecer en un documento sin constituir evidencia de actividad maliciosa. Por ello, abordaron la necesidad de considerar el contexto de los posibles indicadores y mejorar la calidad de la información utilizada para su clasificación.

La propuesta integra un clasificador basado en un modelo de lenguaje, denominado LANCE, con un procedimiento de validación realizado por especialistas. El modelo examina los posibles indicadores y genera clasificaciones acompañadas de explicaciones que facilitan su revisión. A partir de esta interacción se construyó PRISM, un conjunto de referencia formado por indicadores previamente examinados y etiquetados. La metodología combina el procesamiento automatizado con la intervención de analistas para reducir inconsistencias en la identificación de elementos relevantes dentro de los informes.

La evaluación contó con la participación de seis analistas y permitió observar una reducción del $43\%$ en el tiempo dedicado a determinadas tareas de anotación en comparación con el procedimiento exclusivamente manual. Además, los investigadores construyeron un conjunto de 1,791 indicadores etiquetados a partir de 50 informes de amenazas. Estos resultados aportan evidencia sobre la utilidad de combinar el procesamiento mediante LLM con explicaciones que permitan examinar las clasificaciones obtenidas. Sin embargo, las mediciones corresponden al procedimiento y al conjunto documental evaluado, por lo que no pueden extrapolación directamente al análisis de registros generados por honeypots.

La identificación de un elemento técnico no implica necesariamente que constituya un indicador de compromiso relevante para el análisis de seguridad. Los resultados de Froudakis et al. (2025) muestran la importancia de considerar las circunstancias en las que aparece cada indicador y disponer de información que permita examinar su clasificación. Esta distinción resulta pertinente para los eventos de un honeypot, donde una dirección IP, un dominio o una URL pueden adquirir diferentes significados según las acciones registradas durante la sesión. Mantener la relación entre los indicadores identificados y sus evidencias de origen permitirá conservar ese contexto y facilitar la interpretación de los resultados.

### 2.5. Análisis crítico y relación con el estudio de caso práctico

El análisis de las cuatro investigaciones permite identificar avances relevantes en la aplicación de modelos de lenguaje al procesamiento de información de ciberseguridad. En conjunto, los trabajos demuestran que la inteligencia artificial puede intervenir en diferentes etapas del análisis, desde la interpretación de sesiones y comandos hasta la asociación con técnicas de MITRE ATT&CK y la identificación contextualizada de indicadores de compromiso. Sin embargo, también presentan diferencias en sus objetivos, fuentes de información, procedimientos de evaluación y funcionalidades desarrolladas.

Los estudios de Oliveira et al. (2026) y Devkar & Chen (2026) constituyen los antecedentes más cercanos al contexto del proyecto, debido a que trabajan directamente con honeypots y utilizan inteligencia artificial para transformar eventos técnicos en información comprensible. El primero aporta un enfoque de reconstrucción de sesiones y procesamiento estructurado, mientras que el segundo demuestra la integración de indicadores, asociaciones con MITRE ATT&CK y visualizaciones orientadas a los analistas. No obstante, ambos responden a objetivos particulares: Oliveira et al. priorizan la detección y clasificación de comportamientos, mientras que Devkar y Chen incorporan mecanismos de interacción dinámica con los posibles atacantes.

Por otra parte, Krašovec et al. (2025) y Froudakis et al. (2025) abordan componentes específicos del procesamiento de inteligencia de amenazas. El primero demuestra las posibilidades de utilizar LLM para reducir las técnicas candidatas de MITRE ATT&CK, aunque sus resultados también reflejan dificultades en la clasificación final. El segundo evidencia la importancia de considerar el contexto durante la extracción de IoCs y de utilizar procedimientos que permitan comprobar la calidad de los indicadores identificados. Estos aportes son complementarios, pues permiten comprender que la generación automática de resultados debe acompañarse de información suficiente para interpretar su significado y verificar su relación con los datos originales.

Desde una posición crítica, los resultados de estas investigaciones no deben interpretarse como una garantía de que la utilización de un LLM producirá identificaciones o mapeos correctos en todos los escenarios. La calidad del análisis depende de aspectos como la información disponible, la estructuración de los eventos, el contexto proporcionado al modelo y los criterios utilizados para evaluar sus respuestas. Asimismo, las diferencias entre los conjuntos de datos y las métricas empleadas impiden comparar directamente los porcentajes reportados por los investigadores como si representaran una misma capacidad.

En este contexto, el presente estudio de caso práctico se diferencia por concentrarse en el desarrollo de una plataforma web que integre la recopilación de eventos procedentes de Cowrie, su procesamiento mediante un LLM, la extracción de IoCs, el mapeo de comportamientos con MITRE ATT&CK y la consulta de resultados mediante sesiones cronológicas, métricas y visualizaciones. Su finalidad no será desarrollar un honeypot adaptativo ni entrenar un modelo de lenguaje desde cero, sino integrar componentes existentes dentro de una arquitectura funcional orientada al análisis de información registrada en un entorno controlado.

La revisión de los antecedentes también permite establecer criterios para el desarrollo práctico. Entre ellos se encuentran la necesidad de conservar los eventos originales, mantener las relaciones entre sesiones e indicadores, estructurar los resultados del procesamiento y registrar la evidencia correspondiente a los mapeos realizados. Asimismo, será importante verificar mediante pruebas funcionales la comunicación entre los componentes y el funcionamiento de los mecanismos de consulta, autenticación y control de acceso establecidos en la propuesta.

En consecuencia, los trabajos revisados permiten fundamentar la pertinencia del proyecto y reconocer los desafíos técnicos relacionados con el procesamiento automatizado de eventos de seguridad. Su principal contribución al presente estudio consiste en proporcionar experiencias previas que orientan la integración de tecnologías y permiten contrastar diferentes enfoques de interpretación, extracción y organización de información. De esta manera, el desarrollo de la plataforma buscará responder al problema identificado mediante una solución de software que facilite a administradores y analistas de seguridad el aprovechamiento de los registros generados por un honeypot, considerando tanto las capacidades como las limitaciones evidenciadas en las investigaciones precedentes.

---

## 3. Metodología de desarrollo de software

### 3.1. Selección del método Kanban

El desarrollo de la plataforma web se organizará mediante Kanban, un método de gestión del trabajo orientado a controlar el flujo de actividades y mejorar la entrega de resultados. Kanban University (2021) establece que su aplicación se fundamenta en la visualización del trabajo, la limitación de las actividades en curso y el establecimiento de políticas que regulen su avance. A diferencia de los marcos de trabajo organizados en iteraciones de duración fija, Kanban permite mantener un flujo continuo, en el que las actividades avanzan conforme se completan las condiciones establecidas para cada etapa.

La selección responde a la estructura del equipo, conformado por dos integrantes, y a las dependencias técnicas entre los componentes de la plataforma. El procesamiento mediante LLM requiere disponer previamente de los eventos recopilados por Cowrie, mientras que la identificación de IoCs y el mapeo con MITRE ATT&CK dependen de los resultados obtenidos durante el análisis. Estas relaciones condicionan el orden de desarrollo y requieren un seguimiento que permita reconocer las actividades prioritarias, controlar los bloqueos y evitar la acumulación de funcionalidades inconclusas.

Kanban se aplicará durante las actividades de diseño, programación, integración y pruebas funcionales. El trabajo se gestionará mediante un tablero digital en GitHub Projects, vinculado al repositorio de código fuente. Las actividades estarán relacionadas con las historias de usuario y contarán con criterios de aceptación que determinen su finalización. El seguimiento del equipo se concentrará en el avance de las funcionalidades comprometidas, la resolución de impedimentos técnicos y la entrega de componentes verificables dentro del periodo de desarrollo.

### 3.2. Identificación y organización de requisitos

Los requisitos se derivan del objetivo del estudio y del alcance funcional definido en la propuesta inicial. Se conservan los identificadores RF-01 a RF-06 para las seis funciones principales. La autenticación y la gestión de usuarios se registran como RF-07 y RF-08, por tratarse de capacidades complementarias ya consideradas en el alcance de la plataforma. La numeración permite relacionar necesidades, desarrollo y pruebas sin alterar las funciones aprobadas.

#### 3.2.1. Requisitos de usuario

| Campo                         | Ficha de requisito de usuario                                                         |
| :---------------------------- | :------------------------------------------------------------------------------------ |
| **ID**                        | RU-01                                                                                 |
| **Usuario(s) relacionado(s)** | Administrador y analista                                                              |
| **Necesidad del usuario**     | Ingresar a la plataforma y utilizar únicamente las funciones autorizadas para su rol. |

| Campo                         | Ficha de requisito de usuario                                          |
| :---------------------------- | :--------------------------------------------------------------------- |
| **ID**                        | RU-02                                                                  |
| **Usuario(s) relacionado(s)** | Administrador                                                          |
| **Necesidad del usuario**     | Crear, modificar y consultar cuentas, y asignar los roles habilitados. |

| Campo                         | Ficha de requisito de usuario                                                       |
| :---------------------------- | :---------------------------------------------------------------------------------- |
| **ID**                        | RU-03                                                                               |
| **Usuario(s) relacionado(s)** | Administrador                                                                       |
| **Necesidad del usuario**     | Conservar las sesiones y eventos recibidos desde Cowrie para su revisión posterior. |

| Campo                         | Ficha de requisito de usuario                                                     |
| :---------------------------- | :-------------------------------------------------------------------------------- |
| **ID**                        | RU-04                                                                             |
| **Usuario(s) relacionado(s)** | Analista                                                                          |
| **Necesidad del usuario**     | Obtener una interpretación estructurada de las acciones registradas mediante LLM. |

| Campo                         | Ficha de requisito de usuario                                             |
| :---------------------------- | :------------------------------------------------------------------------ |
| **ID**                        | RU-05                                                                     |
| **Usuario(s) relacionado(s)** | Analista                                                                  |
| **Necesidad del usuario**     | Revisar los IoCs identificados junto con la evidencia que les dio origen. |

| Campo                         | Ficha de requisito de usuario                                                            |
| :---------------------------- | :--------------------------------------------------------------------------------------- |
| **ID**                        | RU-06                                                                                    |
| **Usuario(s) relacionado(s)** | Analista                                                                                 |
| **Necesidad del usuario**     | Consultar las técnicas y tácticas de MITRE ATT&CK asociadas con las acciones observadas. |

| Campo                         | Ficha de requisito de usuario                                                 |
| :---------------------------- | :---------------------------------------------------------------------------- |
| **ID**                        | RU-07                                                                         |
| **Usuario(s) relacionado(s)** | Administrador y analista                                                      |
| **Necesidad del usuario**     | Reconstruir cronológicamente una sesión y revisar sus resultados de análisis. |

| Campo                         | Ficha de requisito de usuario                                                   |
| :---------------------------- | :------------------------------------------------------------------------------ |
| **ID**                        | RU-08                                                                           |
| **Usuario(s) relacionado(s)** | Administrador y analista                                                        |
| **Necesidad del usuario**     | Consultar métricas y gráficos calculados a partir de la información almacenada. |

#### 3.2.2. Requisitos funcionales

| Campo                       | Ficha de requisito funcional (RF-01)                                                                                                                          |
| :-------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **ID**                      | RF-01                                                                                                                                                         |
| **Nombre**                  | Recopilación de eventos de Cowrie                                                                                                                             |
| **Descripción**             | El sistema debe obtener las sesiones y eventos generados por Cowrie y almacenar los datos originales con sus referencias temporales.                          |
| **Actor(es) / usuario(s)**  | Administrador de seguridad                                                                                                                                    |
| **Origen / necesidad**      | RU-03: Conservar sesiones y eventos recibidos desde Cowrie para su revisión.                                                                                  |
| **Precondición**            | Integración con el honeypot configurada                                                                                                                       |
| **Prioridad**               | Alta                                                                                                                                                          |
| **RNF asociados**           | RNF-02, RNF-03, RNF-05                                                                                                                                        |
| **Criterios de aceptación** | **CA-01.1:** los eventos de prueba se almacenan con su contenido original.<br>**CA-01.2:** cada evento puede recuperarse desde su sesión y fecha de registro. |
| **Observaciones**           | La integración con Cowrie debe estar configurada y disponible antes de iniciar la recopilación.                                                               |

| Campo                       | Ficha de requisito funcional (RF-02)                                                                                                                                                                                     |
| :-------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ID**                      | RF-02                                                                                                                                                                                                                    |
| **Nombre**                  | Procesamiento de eventos mediante LLM                                                                                                                                                                                    |
| **Descripción**             | El sistema debe procesar eventos almacenados con un LLM y conservar resultados estructurados sobre las acciones observadas.                                                                                              |
| **Actor(es) / usuario(s)**  | Analista de seguridad                                                                                                                                                                                                    |
| **Origen / necesidad**      | RU-04: Obtener una interpretación estructurada de las acciones registradas.                                                                                                                                              |
| **Precondición**            | Existencia de eventos persistidos                                                                                                                                                                                        |
| **Prioridad**               | Alta                                                                                                                                                                                                                     |
| **RNF asociados**           | RNF-02, RNF-03, RNF-05                                                                                                                                                                                                   |
| **Criterios de aceptación** | **CA-02.1:** al procesar una sesión, se almacena una respuesta estructurada con referencia a los eventos analizados.<br>**CA-02.2:** ante un fallo del LLM, se registra el error sin marcar el análisis como completado. |
| **Observaciones**           | Los análisis se realizarán sobre eventos almacenados. Un fallo del LLM no se considerará un análisis completado.                                                                                                         |

| Campo                       | Ficha de requisito funcional (RF-03)                                                                                                                                                  |
| :-------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **ID**                      | RF-03                                                                                                                                                                                 |
| **Nombre**                  | Identificación de indicadores de compromiso                                                                                                                                           |
| **Descripción**             | El sistema debe identificar y guardar los IoCs detectados, con su tipo, valor y referencia a la evidencia de origen.                                                                  |
| **Actor(es) / usuario(s)**  | Analista de seguridad                                                                                                                                                                 |
| **Origen / necesidad**      | RU-05: Revisar IoCs junto con la evidencia de su origen.                                                                                                                              |
| **Precondición**            | Resultados del análisis disponibles                                                                                                                                                   |
| **Prioridad**               | Alta                                                                                                                                                                                  |
| **RNF asociados**           | RNF-02, RNF-05                                                                                                                                                                        |
| **Criterios de aceptación** | **CA-03.1:** cada IoC identificado conserva tipo, valor y evidencia asociada.<br>**CA-03.2:** cuando la sesión no proporciona un IoC sustentado, no se crea uno de manera artificial. |
| **Observaciones**           | No se registrarán IoCs sin evidencia suficiente en los eventos o en el análisis asociado.                                                                                             |

| Campo                       | Ficha de requisito funcional (RF-04)                                                                                                                                                                                                                           |
| :-------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ID**                      | RF-04                                                                                                                                                                                                                                                          |
| **Nombre**                  | Mapeo de acciones a MITRE ATT&CK                                                                                                                                                                                                                               |
| **Descripción**             | El sistema debe relacionar las acciones interpretadas con técnicas y tácticas documentadas en MITRE ATT&CK, conservando la justificación y los eventos que respaldan cada asociación.                                                                          |
| **Actor(es) / usuario(s)**  | Analista de seguridad                                                                                                                                                                                                                                          |
| **Origen / necesidad**      | RU-06: Consultar técnicas y tácticas de MITRE ATT&CK asociadas a las acciones observadas.                                                                                                                                                                      |
| **Precondición**            | Análisis y catálogo MITRE disponibles                                                                                                                                                                                                                          |
| **Prioridad**               | Alta                                                                                                                                                                                                                                                           |
| **RNF asociados**           | RNF-02, RNF-05                                                                                                                                                                                                                                                 |
| **Criterios de aceptación** | **CA-04.1:** los mapeos almacenados señalan un identificador válido de técnica y su táctica correspondiente.<br>**CA-04.2:** cada relación conserva una justificación y referencias a eventos; las asociaciones sin respaldo no se presentan como confirmadas. |
| **Observaciones**           | Los mapeos propuestos no se presentarán como confirmados cuando carezcan de evidencia que los respalde.                                                                                                                                                        |

| Campo                       | Ficha de requisito funcional (RF-05)                                                                                                                                                      |
| :-------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ID**                      | RF-05                                                                                                                                                                                     |
| **Nombre**                  | Consulta de sesiones y eventos                                                                                                                                                            |
| **Descripción**             | El sistema debe mostrar las sesiones y sus eventos en orden cronológico, además de los resultados del análisis vinculados cuando existan.                                                 |
| **Actor(es) / usuario(s)**  | Administrador y analista de seguridad                                                                                                                                                     |
| **Origen / necesidad**      | RU-07: Reconstruir cronológicamente las sesiones y sus resultados.                                                                                                                        |
| **Precondición**            | Registros almacenados                                                                                                                                                                     |
| **Prioridad**               | Alta                                                                                                                                                                                      |
| **RNF asociados**           | RNF-02, RNF-04                                                                                                                                                                            |
| **Criterios de aceptación** | **CA-05.1:** los eventos se muestran ordenados por fecha dentro de la sesión.<br>**CA-05.2:** los IoCs, mapeos y resultados disponibles pueden consultarse desde el detalle de la sesión. |
| **Observaciones**           | El detalle de IoCs, mapeos y análisis se mostrará cuando existan resultados asociados a la sesión.                                                                                        |

| Campo                       | Ficha de requisito funcional (RF-06)                                                                                                                                                             |
| :-------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ID**                      | RF-06                                                                                                                                                                                            |
| **Nombre**                  | Visualización de métricas y gráficos                                                                                                                                                             |
| **Descripción**             | El sistema debe presentar indicadores sobre sesiones, IoCs y técnicas identificadas, calculados a partir de los datos almacenados.                                                               |
| **Actor(es) / usuario(s)**  | Administrador y analista de seguridad                                                                                                                                                            |
| **Origen / necesidad**      | RU-08: Consultar métricas y gráficos de la información almacenada.                                                                                                                               |
| **Precondición**            | Información disponible para consulta                                                                                                                                                             |
| **Prioridad**               | Media                                                                                                                                                                                            |
| **RNF asociados**           | RNF-02, RNF-04                                                                                                                                                                                   |
| **Criterios de aceptación** | **CA-06.1:** el panel presenta conteos y gráficos basados en registros almacenados.<br>**CA-06.2:** los valores visualizados coinciden con las consultas de verificación sobre la base de datos. |
| **Observaciones**           | Los indicadores se calcularán con datos persistidos; no se utilizarán valores simulados en el panel final.                                                                                       |

| Campo                       | Ficha de requisito funcional (RF-07)                                                                                                                                                  |
| :-------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **ID**                      | RF-07                                                                                                                                                                                 |
| **Nombre**                  | Autenticación y control de permisos                                                                                                                                                   |
| **Descripción**             | El sistema debe validar credenciales, generar una sesión autenticada mediante JWT y restringir las funciones según el rol del usuario.                                                |
| **Actor(es) / usuario(s)**  | Administrador y analista de seguridad                                                                                                                                                 |
| **Origen / necesidad**      | RU-01: Ingresar a la plataforma y utilizar únicamente las funciones autorizadas para el rol.                                                                                          |
| **Precondición**            | Cuenta habilitada                                                                                                                                                                     |
| **Prioridad**               | Alta                                                                                                                                                                                  |
| **RNF asociados**           | RNF-01, RNF-04                                                                                                                                                                        |
| **Criterios de aceptación** | **CA-07.1:** credenciales válidas permiten el acceso al rol correspondiente.<br>**CA-07.2:** credenciales inválidas o un rol sin permiso no permiten ejecutar operaciones protegidas. |
| **Observaciones**           | El acceso a operaciones protegidas requiere un token válido y permisos acordes con el rol asignado.                                                                                   |

| Campo                       | Ficha de requisito funcional (RF-08)                                                                                                                                             |
| :-------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ID**                      | RF-08                                                                                                                                                                            |
| **Nombre**                  | Gestión de usuarios y roles                                                                                                                                                      |
| **Descripción**             | El sistema debe permitir crear, consultar y modificar usuarios, así como asignar los roles establecidos.                                                                         |
| **Actor(es) / usuario(s)**  | Administrador de seguridad                                                                                                                                                       |
| **Origen / necesidad**      | RU-02: Administrar cuentas y asignar los roles habilitados.                                                                                                                      |
| **Precondición**            | Administrador autenticado                                                                                                                                                        |
| **Prioridad**               | Media                                                                                                                                                                            |
| **RNF asociados**           | RNF-01, RNF-04                                                                                                                                                                   |
| **Criterios de aceptación** | **CA-08.1:** un administrador puede crear, consultar y actualizar cuentas y roles.<br>**CA-08.2:** un analista no puede acceder a las operaciones de administración de usuarios. |
| **Observaciones**           | Las operaciones de administración estarán restringidas al administrador de seguridad.                                                                                            |

#### 3.2.3. Requerimientos no funcionales

| Campo                      | Ficha de requisito no funcional (RNF-01)                                                                                                                                                   |
| :------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ID y Atributo**          | **RNF-01 – Seguridad**                                                                                                                                                                     |
| **Descripción**            | Proteger las credenciales almacenadas y restringir las operaciones de la API según la autenticación y el rol.                                                                              |
| **Métrica / umbral**       | El $100\%$ de las contraseñas almacenadas tendrá hash con sal. El $100\%$ de las rutas protegidas incluidas en las pruebas rechazará solicitudes sin autenticación o sin el rol requerido. |
| **Ámbito**                 | RF-07, RF-08                                                                                                                                                                               |
| **Prioridad**              | Alta                                                                                                                                                                                       |
| **Método de verificación** | Inspección del almacenamiento y pruebas de acceso con credenciales válidas, token ausente y rol no autorizado.                                                                             |
| **Evidencia prevista**     | Resultados de prueba, comprobación del hash y respuestas HTTP.                                                                                                                             |

| Campo                      | Ficha de requisito no funcional (RNF-02)                                                                                                                                                                                |
| :------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ID y Atributo**          | **RNF-02 – Integridad y trazabilidad**                                                                                                                                                                                  |
| **Descripción**            | Conservar los registros originales y permitir rastrear los resultados del análisis hasta los eventos que los sustentan.                                                                                                 |
| **Métrica / umbral**       | El $100\%$ de los eventos del conjunto de pruebas conservará su contenido original y la referencia a su sesión. El $100\%$ de los IoCs y mapeos generados en esas pruebas tendrá al menos un evento de origen asociado. |
| **Ámbito**                 | RF-01, RF-02, RF-03, RF-04, RF-05, RF-06                                                                                                                                                                                |
| **Prioridad**              | Alta                                                                                                                                                                                                                    |
| **Método de verificación** | Consultas a la base de datos y contraste de relaciones entre sesión, evento, IoC y mapeo.                                                                                                                               |
| **Evidencia prevista**     | Capturas o resultados de consultas y casos de prueba.                                                                                                                                                                   |

| Campo                      | Ficha de requisito no funcional (RNF-03)                                                                                                                               |
| :------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ID y Atributo**          | **RNF-03 – Manejo de errores**                                                                                                                                         |
| **Descripción**            | Informar y registrar los fallos relevantes sin presentar como exitoso un procesamiento incompleto.                                                                     |
| **Métrica / umbral**       | Los tres escenarios de prueba (evento inválido, indisponibilidad del LLM y fallo de persistencia) deberán registrar el error y evitar una confirmación falsa de éxito. |
| **Ámbito**                 | RF-01, RF-02                                                                                                                                                           |
| **Prioridad**              | Alta                                                                                                                                                                   |
| **Método de verificación** | Ejecución controlada de los tres escenarios y comprobación de respuestas y registros de error.                                                                         |
| **Evidencia prevista**     | Registros de error y respuestas observadas de la API.                                                                                                                  |

| Campo                      | Ficha de requisito no funcional (RNF-04)                                                                                                                                                                              |
| :------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ID y Atributo**          | **RNF-04 – Usabilidad**                                                                                                                                                                                               |
| **Descripción**            | Facilitar el acceso a las vistas principales y presentar únicamente las operaciones habilitadas para cada rol.                                                                                                        |
| **Métrica / umbral**       | Desde la navegación principal, cada rol accederá a sus vistas permitidas de sesiones, indicadores y mapeos en un máximo de tres acciones. Las funciones restringidas no aparecerán como disponibles para el analista. |
| **Ámbito**                 | RF-05, RF-06, RF-07, RF-08                                                                                                                                                                                            |
| **Prioridad**              | Media                                                                                                                                                                                                                 |
| **Método de verificación** | Recorridos guiados de la interfaz con cuentas de administrador y analista.                                                                                                                                            |
| **Evidencia prevista**     | Lista de comprobación y capturas de los recorridos por rol.                                                                                                                                                           |

| Campo                      | Ficha de requisito no funcional (RNF-05)                                                                                                                                                                                                             |
| :------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ID y Atributo**          | **RNF-05 – Mantenibilidad**                                                                                                                                                                                                                          |
| **Descripción**            | Separar las principales responsabilidades del aplicativo para facilitar su localización y modificación.                                                                                                                                              |
| **Métrica / umbral**       | Los cinco componentes previstos (recopilación, acceso a datos, análisis LLM, autenticación y presentación) estarán organizados en módulos diferenciados. El $100\%$ de los servicios de la API tendrá una ubicación identificable en el repositorio. |
| **Ámbito**                 | RF-01, RF-02, RF-03, RF-04                                                                                                                                                                                                                           |
| **Prioridad**              | Media                                                                                                                                                                                                                                                |
| **Método de verificación** | Revisión del árbol de directorios y correspondencia entre los servicios de la API y sus módulos.                                                                                                                                                     |
| **Evidencia prevista**     | Árbol de directorios y registro de revisión del repositorio.                                                                                                                                                                                         |

### 3.3. Definición y priorización del trabajo

Las funcionalidades se documentarán mediante ocho historias de usuario vinculadas con los requisitos y el alcance aprobado. Seis corresponden a los requisitos funcionales RF-01 a RF-06, mientras que las dos restantes comprenden la autenticación y la gestión de usuarios.

| Campo                       | Ficha de historia (HU-01)                                                                                                                 |
| :-------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------- |
| **Identificador**           | HU-01                                                                                                                                     |
| **Título**                  | Inicio de sesión según rol                                                                                                                |
| **Enunciado**               | Como usuario autorizado, quiero iniciar sesión con mis credenciales para acceder a las funcionalidades correspondientes a mi rol.         |
| **Requisitos relacionados** | RF-07; RNF-01, RNF-04                                                                                                                     |
| **Prioridad / Valor**       | Alta — indispensable para el funcionamiento principal                                                                                     |
| **Criterios de aceptación** | Validación de credenciales; autenticación mediante JWT; rechazo de accesos no autorizados; restricciones de acceso según el rol asignado. |
| **Estimación**              | Por definir                                                                                                                               |
| **Dependencias**            | Estructura de usuarios y roles                                                                                                            |

| Campo                       | Ficha de historia (HU-02)                                                                                                                       |
| :-------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------- |
| **Identificador**           | HU-02                                                                                                                                           |
| **Título**                  | Gestión de usuarios y roles                                                                                                                     |
| **Enunciado**               | Como administrador, quiero gestionar las cuentas y los roles de usuario para controlar el acceso a las funcionalidades de la plataforma.        |
| **Requisitos relacionados** | RF-08; RNF-01, RNF-04                                                                                                                           |
| **Prioridad / Valor**       | Media — funcionalidad de apoyo                                                                                                                  |
| **Criterios de aceptación** | Registro y modificación de usuarios; consulta de cuentas existentes; asignación de roles; acceso restringido a las operaciones administrativas. |
| **Estimación**              | Por definir                                                                                                                                     |
| **Dependencias**            | HU-01                                                                                                                                           |

| Campo                       | Ficha de historia (HU-03)                                                                                                                                        |
| :-------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Identificador**           | HU-03                                                                                                                                                            |
| **Título**                  | Recopilación y almacenamiento de eventos                                                                                                                         |
| **Enunciado**               | Como administrador, quiero que las sesiones y eventos generados por Cowrie se recopilen y almacenen para conservar los registros utilizados durante el análisis. |
| **Requisitos relacionados** | RF-01; RNF-02, RNF-03, RNF-05                                                                                                                                    |
| **Prioridad / Valor**       | Alta — indispensable para el funcionamiento principal                                                                                                            |
| **Criterios de aceptación** | Obtención de eventos desde Cowrie; almacenamiento persistente; conservación de los datos originales; asociación de cada evento con su sesión.                    |
| **Estimación**              | Por definir                                                                                                                                                      |
| **Dependencias**            | Integración con Cowrie y modelo de datos                                                                                                                         |

| Campo                       | Ficha de historia (HU-04)                                                                                                                                                                 |
| :-------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Identificador**           | HU-04                                                                                                                                                                                     |
| **Título**                  | Procesamiento de eventos mediante LLM                                                                                                                                                     |
| **Enunciado**               | Como analista, quiero disponer de información estructurada sobre las acciones registradas para interpretar los comportamientos identificados durante las sesiones.                        |
| **Requisitos relacionados** | RF-02; RNF-02, RNF-03, RNF-05                                                                                                                                                             |
| **Prioridad / Valor**       | Alta — indispensable para el funcionamiento principal                                                                                                                                     |
| **Criterios de aceptación** | Procesamiento de eventos almacenados mediante LLM; generación de información estructurada; almacenamiento de resultados; conservación de referencias a las sesiones y eventos analizados. |
| **Estimación**              | Por definir                                                                                                                                                                               |
| **Dependencias**            | HU-03                                                                                                                                                                                     |

| Campo                       | Ficha de historia (HU-05)                                                                                                                         |
| :-------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Identificador**           | HU-05                                                                                                                                             |
| **Título**                  | Identificación de indicadores de compromiso                                                                                                       |
| **Enunciado**               | Como analista, quiero consultar los indicadores de compromiso identificados para examinar su relación con los eventos y acciones registrados.     |
| **Requisitos relacionados** | RF-03; RNF-02, RNF-05                                                                                                                             |
| **Prioridad / Valor**       | Alta — indispensable para el funcionamiento principal                                                                                             |
| **Criterios de aceptación** | Identificación y almacenamiento de IoCs; conservación de su tipo y valor; asociación con sesiones y acciones; consulta de la evidencia de origen. |
| **Estimación**              | Por definir                                                                                                                                       |
| **Dependencias**            | HU-04                                                                                                                                             |

| Campo                       | Ficha de historia (HU-06)                                                                                                                                                      |
| :-------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Identificador**           | HU-06                                                                                                                                                                          |
| **Título**                  | Mapeo de TTPs con MITRE ATT&CK                                                                                                                                                 |
| **Enunciado**               | Como analista, quiero consultar las técnicas y tácticas de MITRE ATT&CK asociadas con las acciones identificadas para examinar los comportamientos registrados.                |
| **Requisitos relacionados** | RF-04; RNF-02, RNF-05                                                                                                                                                          |
| **Prioridad / Valor**       | Alta — indispensable para el funcionamiento principal                                                                                                                          |
| **Criterios de aceptación** | Asociación de acciones con técnicas y tácticas documentadas; almacenamiento de los mapeos; conservación de evidencias y justificaciones; consulta de los resultados asociados. |
| **Estimación**              | Por definir                                                                                                                                                                    |
| **Dependencias**            | HU-04                                                                                                                                                                          |

| Campo                       | Ficha de historia (HU-07)                                                                                                                                                                  |
| :-------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Identificador**           | HU-07                                                                                                                                                                                      |
| **Título**                  | Consulta y reconstrucción de sesiones                                                                                                                                                      |
| **Enunciado**               | Como analista, quiero consultar las sesiones y sus eventos en orden cronológico para comprender las actividades registradas y revisar los resultados del análisis.                         |
| **Requisitos relacionados** | RF-05; RNF-02, RNF-04                                                                                                                                                                      |
| **Prioridad / Valor**       | Alta — indispensable para el funcionamiento principal                                                                                                                                      |
| **Criterios de aceptación** | Consulta de sesiones; ordenamiento cronológico de eventos; visualización del detalle de cada sesión; acceso a IoCs, técnicas, tácticas y resultados relacionados cuando estén disponibles. |
| **Estimación**              | Por definir                                                                                                                                                                                |
| **Dependencias**            | HU-03                                                                                                                                                                                      |

| Campo                       | Ficha de historia (HU-08)                                                                                                                                              |
| :-------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Identificador**           | HU-08                                                                                                                                                                  |
| **Título**                  | Visualización de métricas e indicadores                                                                                                                                |
| **Enunciado**               | Como analista, quiero visualizar métricas sobre las sesiones, los IoCs y las técnicas identificadas para examinar los patrones presentes en la información registrada. |
| **Requisitos relacionados** | RF-06; RNF-02, RNF-04                                                                                                                                                  |
| **Prioridad / Valor**       | Media — funcionalidad de apoyo                                                                                                                                         |
| **Criterios de aceptación** | Presentación de indicadores y gráficos; utilización de información almacenada; correspondencia entre los valores mostrados y los registros consultados.                |
| **Estimación**              | Por definir                                                                                                                                                            |
| **Dependencias**            | HU-03, HU-05 y HU-06                                                                                                                                                   |

#### 3.3.1. Backlog / registro priorizado

| ID trabajo | RF / RNF                      | Descripción breve                           | Prioridad | Estimación  | Estado    |
| :--------- | :---------------------------- | :------------------------------------------ | :-------- | :---------- | :-------- |
| **HU-01**  | RF-07; RNF-01, RNF-04         | Inicio de sesión según rol                  | Alta      | Por definir | Pendiente |
| **HU-02**  | RF-08; RNF-01, RNF-04         | Gestión de usuarios y roles                 | Media     | Por definir | Pendiente |
| **HU-03**  | RF-01; RNF-02, RNF-03, RNF-05 | Recopilación y almacenamiento de eventos    | Alta      | Por definir | Pendiente |
| **HU-04**  | RF-02; RNF-02, RNF-03, RNF-05 | Procesamiento de eventos mediante LLM       | Alta      | Por definir | Pendiente |
| **HU-05**  | RF-03; RNF-02, RNF-05         | Identificación de indicadores de compromiso | Alta      | Por definir | Pendiente |
| **HU-06**  | RF-04; RNF-02, RNF-05         | Mapeo de TTPs con MITRE ATT&CK              | Alta      | Por definir | Pendiente |
| **HU-07**  | RF-05; RNF-02, RNF-04         | Consulta y reconstrucción de sesiones       | Alta      | Por definir | Pendiente |
| **HU-08**  | RF-06; RNF-02, RNF-04         | Visualización de métricas e indicadores     | Media     | Por definir | Pendiente |

### 3.4. Planificación del desarrollo

El flujo de trabajo estará organizado en cinco estados: **Pendiente**, **Preparada**, **En desarrollo**, **En pruebas** y **Finalizada**.

| Elemento                       | Definición del equipo                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| :----------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Columnas del tablero**       | Pendiente $\rightarrow$ Preparada $\rightarrow$ En desarrollo $\rightarrow$ En pruebas $\rightarrow$ Finalizada.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| **Política de entrada/salida** | - **Pendiente $\rightarrow$ Preparada:** descripción, prioridad, historia, dependencias y criterios de aceptación definidos.<br>- **Preparada $\rightarrow$ En desarrollo:** responsable asignado, dependencias satisfechas y capacidad disponible.<br>- **En desarrollo $\rightarrow$ En pruebas:** funcionalidad construida y cambios registrados.<br>- **En pruebas $\rightarrow$ Finalizada:** criterios de aceptación cumplidos y evidencia registrada.<br>- **En pruebas $\rightarrow$ En desarrollo:** incidencia que requiere corrección y capacidad disponible. |
| **Límite WIP**                 | En desarrollo: máximo 2 tareas simultáneas. En pruebas: máximo 2. Sin límite en Pendiente, Preparada y Finalizada. Los límites se aplican a tarjetas, no a historias.                                                                                                                                                                                                                                                                                                                                                                                                    |
| **Reposición y priorización**  | Selección por mecanismo pull, según prioridad, dependencias y capacidad. Revisión de prioridades los lunes (20 minutos); seguimiento diario de 10 minutos en días de trabajo. Las tareas bloqueadas mantienen su estado y registran la causa.                                                                                                                                                                                                                                                                                                                            |
| **Fecha objetivo / hitos**     | Preparación: 21–24 de octubre de 2026.<br>Desarrollo y seguimiento: 26 de octubre–5 de diciembre de 2026. Los periodos semanales son hitos de seguimiento, no sprints.                                                                                                                                                                                                                                                                                                                                                                                                   |
| **Métricas de flujo**          | Trabajo en curso (WIP); tiempo de entrega (Lead Time), desde Preparada $\rightarrow$ En desarrollo hasta Finalizada; tasa de entrega, medida por tarjetas finalizadas por semana.                                                                                                                                                                                                                                                                                                                                                                                        |

#### Cronograma de hitos de desarrollo

| Hito / fecha            | Elementos priorizados      | Responsable          | Entregable                                                             |
| :---------------------- | :------------------------- | :------------------- | :--------------------------------------------------------------------- |
| **21–24 oct. 2026**     | Preparación técnica        | Equipo de desarrollo | Arquitectura, modelo de datos y tablero Kanban.                        |
| **26–31 oct. 2026**     | HU-01 y HU-02              | Equipo de desarrollo | Autenticación, control de acceso y administración de usuarios.         |
| **2–7 nov. 2026**       | HU-03                      | Equipo de desarrollo | Recopilación y almacenamiento de sesiones y eventos de Cowrie.         |
| **9–14 nov. 2026**      | HU-07 y HU-04              | Equipo de desarrollo | Consulta cronológica de sesiones y procesamiento inicial mediante LLM. |
| **16–21 nov. 2026**     | HU-04 y HU-05              | Equipo de desarrollo | Análisis de acciones e identificación de IoCs con evidencias.          |
| **23–28 nov. 2026**     | HU-06 y HU-08              | Equipo de desarrollo | Mapeo MITRE ATT&CK y panel de métricas.                                |
| **30 nov.–5 dic. 2026** | Integración y verificación | Equipo de desarrollo | Plataforma integrada, pruebas funcionales y documentación.             |

### 3.5. Seguimiento y control del desarrollo

| Fecha de control | ID    | Estado        | Avance / resultado | Bloqueo o cambio | Acción / responsable |
| :--------------- | :---- | :------------ | :----------------- | :--------------- | :------------------- |
| Por registrar    | HU-01 | Por registrar | Por registrar      | Por registrar    | Por registrar        |
| Por registrar    | HU-02 | Por registrar | Por registrar      | Por registrar    | Por registrar        |
| Por registrar    | HU-03 | Por registrar | Por registrar      | Por registrar    | Por registrar        |
| Por registrar    | HU-04 | Por registrar | Por registrar      | Por registrar    | Por registrar        |
| Por registrar    | HU-05 | Por registrar | Por registrar      | Por registrar    | Por registrar        |
| Por registrar    | HU-06 | Por registrar | Por registrar      | Por registrar    | Por registrar        |
| Por registrar    | HU-07 | Por registrar | Por registrar      | Por registrar    | Por registrar        |
| Por registrar    | HU-08 | Por registrar | Por registrar      | Por registrar    | Por registrar        |

### 3.6. Estrategia de pruebas y validación

| ID prueba | RF/RNF y Criterio                                              | Escenario / datos                                                        | Resultado esperado                                                                                                       | Tipo de prueba          |
| :-------- | :------------------------------------------------------------- | :----------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------- | :---------------------- |
| **CP-01** | RF-07; RNF-01; CA: acceso autorizado y rechazo de credenciales | Inicio de sesión con credenciales válidas e inválidas; acceso según rol. | Acceso permitido para credenciales válidas y rol autorizado; rechazo de credenciales inválidas o permisos insuficientes. | Funcional / seguridad   |
| **CP-02** | RF-08; RNF-01, RNF-04; CA: gestión restringida                 | Administrador registra, modifica y consulta usuarios; asigna roles.      | Los cambios se almacenan y las operaciones administrativas se restringen a usuarios autorizados.                         | Funcional / seguridad   |
| **CP-03** | RF-01; RNF-02, RNF-03, RNF-05; CA: persistencia de registros   | Recopilar sesiones y eventos generados por Cowrie.                       | Se guardan los datos originales, la referencia de la sesión y los eventos; las incidencias se registran.                 | Integración / funcional |
| **CP-04** | RF-02; RNF-02, RNF-03, RNF-05; CA: análisis estructurado       | Procesar mediante LLM una sesión con eventos almacenados.                | Se obtiene y guarda una interpretación estructurada vinculada con su sesión y eventos; el error se registra si falla.    | Integración / funcional |
| **CP-05** | RF-03; RNF-02, RNF-05; CA: IoCs con evidencia                  | Revisar resultados que contengan indicadores de compromiso.              | Los IoCs se registran con tipo, valor y referencia a la evidencia de origen.                                             | Funcional               |
| **CP-06** | RF-04; RNF-02, RNF-05; CA: mapeo justificado                   | Relacionar acciones interpretadas con el catálogo MITRE ATT&CK.          | Los mapeos incluyen técnica o táctica pertinente y conservan su evidencia y justificación.                               | Funcional / integración |
| **CP-07** | RF-05; RNF-02, RNF-04; CA: orden cronológico                   | Consultar el detalle de una sesión con varios eventos.                   | Los eventos se muestran cronológicamente y se accede a los hallazgos asociados cuando existan.                           | Funcional / interfaz    |
| **CP-08** | RF-06; RNF-02, RNF-04; CA: métricas consistentes               | Consultar paneles y comparar métricas con registros almacenados.         | Los valores y gráficos coinciden con los datos consultados y se muestran de forma comprensible.                          | Funcional / interfaz    |

_Nota._ Los identificadores CP-01 a CP-08 corresponden a la matriz de trazabilidad del borrador. Los criterios se expresan de forma resumida y se verificarán con la ficha completa de cada requisito e historia de usuario. Los resultados indicados son esperados, no resultados ejecutados.

---

## 4. Diseño

_(En desarrollo)_

- 4.1. Arquitectura del software
- 4.2. Diseño dinámico y estático
- 4.3. Diseño de base de datos

---

## 5. Desarrollo

_(En desarrollo)_

- 5.1. Tecnologías y herramientas
- 5.2. Front end
- 5.3. Back end
- 5.4. Integración del sistema
- 5.5. Pruebas funcionales y resultados

---

## 6. Conclusiones y recomendaciones

_(Por definir)_

---

## 7. Referencias

- Devkar, A., & Chen, Y. (2026). _An AI-Enhanced SSH Honeypot for Real-Time Threat Intelligence and Interactive Security Analytics_.
- Froudakis, G., et al. (2025). _Revealing the True Indicators: Understanding and Improving IoC Extraction From Threat Reports_.
- Krašovec, M., et al. (2025). _Large Language Models for Cyber Threat Intelligence: Extracting MITRE With LLMs_.
- Oliveira, R., et al. (2026). _An Integrated Honeypot and LLM-Based Framework for near Real-Time Detection and Behavioral Analysis of Malicious Activities_.

---

## 8. Anexos

_(Por incluir)_
