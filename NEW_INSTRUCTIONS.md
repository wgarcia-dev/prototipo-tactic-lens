# TacticLens — Mejora del análisis LLM mediante inteligencia de amenazas verificable

Necesito fortalecer la calidad y trazabilidad de los análisis de ciberseguridad de TacticLens.

## Contexto

El sistema utiliza Cowrie para capturar eventos SSH, un recolector Python para enviar los registros, FastAPI para procesarlos, PostgreSQL para persistirlos, DeepSeek para analizar sesiones y React para visualizar resultados.

El problema identificado es que algunas interpretaciones del LLM carecen de referencias externas verificables y podrían confundirse hechos observados con hipótesis o inferencias.

## Objetivo

Implementar un mecanismo de análisis respaldado por fuentes verificables, sin reemplazar la arquitectura actual.

### 1. Auditar el análisis existente

Inspecciona los servicios reales de análisis, los prompts, las respuestas JSON, las tablas PostgreSQL y las vistas React.

Identifica qué afirmaciones se generan sin evidencias suficientes, cómo se validan actualmente los mapeos MITRE y cómo se conserva la trazabilidad de los IoCs.

### 2. Incorporar fuentes oficiales

Prioriza:

- MITRE ATT&CK STIX 2.1.
- MITRE Detection Strategies y Analytics, cuando sean pertinentes.
- MISP Warning Lists.
- ThreatFox y URLhaus, sujetos a sus requisitos de acceso.
- VirusTotal AI/API, opcionalmente.
- NIST SP 800-61 Rev. 3 como referencia metodológica.

Investiga también Cisco XDR MCP Community y las API de Cisco XDR, pero no hagas depender la implementación de Cisco si no existen credenciales o acceso autorizado.

No utilices scraping no autorizado de plataformas de reputación.

### 3. Implementar un servicio de enriquecimiento

Crea un componente modular en FastAPI que:

- Extraiga observables de los eventos.
- Distinga direcciones privadas de IPs públicas.
- Obtenga información contextual de fuentes disponibles.
- Mantenga los resultados de cada proveedor separados.
- Conserve identificadores, URLs, versiones y fechas de consulta.
- Gestione errores, cuotas, caché y falta de conectividad.

No envíes credenciales capturadas por Cowrie a proveedores externos.

### 4. Mejorar el análisis LLM

Antes de llamar a DeepSeek, proporciona:

- Eventos originales identificados.
- Patrones detectados mediante reglas.
- Técnicas candidatas verificadas.
- Contexto recuperado de fuentes oficiales.
- Referencias comprobables.

Exige respuestas estructuradas con:

- Hechos observados.
- Hipótesis de comportamiento.
- Técnica MITRE candidata.
- Evidencias relacionadas.
- Fuentes externas.
- Justificación.
- Estado de verificación.
- Limitaciones del análisis.

Nunca aceptes URLs, identificadores o evidencias fabricadas por el LLM. Valida todo desde FastAPI contra los resultados realmente recuperados.

### 5. Persistencia

Reutiliza ANALISIS_LLM, ACCION_IDENTIFICADA, DETECCION_IOC, MAPEO_MITRE, EVENTO y las entidades existentes.

Si resulta necesario, propone migraciones pequeñas para registrar fuentes externas y relaciones de evidencia.

No elimines tablas ni datos existentes.

### 6. Frontend

En el detalle de cada análisis, incorpora una sección de fuentes y evidencias que permita consultar:

- Evento original de Cowrie.
- Técnica y documentación oficial MITRE.
- Proveedor externo consultado.
- Fecha y resultado del enriquecimiento.
- Justificación del análisis.
- Estado de verificación.

Distingue explícitamente resultados observados, inferidos y revisados.

### 7. Pruebas

Implementa pruebas para:

- Referencias MITRE válidas e inválidas.
- Evidencias inexistentes.
- Respuestas inventadas por el LLM.
- IPs privadas.
- Ausencia de resultados en fuentes externas.
- Fallos y cuotas de las API.
- Análisis históricos ya almacenados.
- Funcionamiento con fuentes locales sin Internet.
- Intentos de prompt injection contenidos en los registros.

Evita llamadas innecesarias a DeepSeek y operaciones de pago durante las pruebas.

### 8. Entregables

Entrega una implementación modular y documentada, junto con un resumen técnico de las fuentes integradas, sus limitaciones, los cambios en PostgreSQL y las pruebas ejecutadas.

Distingue lo realmente implementado de lo pendiente.

La meta es que cada hallazgo de TacticLens tenga trazabilidad y respaldo técnico, sin presentar las inferencias del LLM como hechos confirmados.
