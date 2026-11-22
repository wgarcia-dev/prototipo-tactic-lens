# Enriquecimiento verificable de análisis

## Flujo implementado

Antes de DeepSeek, FastAPI recupera candidatos del catálogo local MITRE ATT&CK STIX 2.1 y calcula patrones de eventos. `backend/enrichment.py` extrae IP, dominio, URL y SHA-256 de campos Cowrie y comandos mediante las reglas existentes. Cada observable conserva sus IDs de evento. El contexto de proveedores se adjunta al análisis en `ANALISIS_LLM.resultado_estructurado.enriquecimiento`; no se cambió el esquema PostgreSQL ni se modificaron análisis históricos.

El modelo recibe estados resumidos del enriquecimiento, sin URLs de proveedores ni identificadores de sus respuestas. Sus referencias a eventos, IoCs y técnicas MITRE se validan en FastAPI antes de persistir. Las técnicas se contrastan con el catálogo vigente, táctica, observabilidad y evidencia de la acción. Las coincidencias de reputación no convierten automáticamente un observable en malicioso. Las afirmaciones narrativas del modelo siguen siendo inferencias hasta revisión humana.

## Fuentes y configuración

| Fuente | Estado | Configuración | Alcance y límite |
| --- | --- | --- | --- |
| MITRE ATT&CK STIX 2.1 | Integrada previamente mediante importación local | `scripts/import_mitre.py` y embeddings | Definiciones, versiones, STIX ID, hash y URL oficial de técnicas; el mapeo sigue siendo candidato. |
| MISP Warning Lists | Integrada opcionalmente en disco | `MISP_WARNING_LISTS_DIR` apunta a `lists` de una copia versionada | Coincidencia `string`, `hostname` y `cidr`; indica posibles falsos positivos o infraestructura compartida, no reputación maliciosa. No se implementan listas `regex`/`substring`. |
| ThreatFox | Integrada opcionalmente | `THREATFOX_AUTH_KEY` | Búsqueda exacta de IP pública o dominio y búsqueda de hash; los resultados pueden caducar y no son exhaustivos. |
| URLhaus | Integrada opcionalmente | `URLHAUS_AUTH_KEY` | Consulta solo de SHA-256; no se envían URLs capturadas porque ruta y consulta pueden contener secretos. |
| MITRE Detection Strategies / Analytics | Investigadas, pendientes | Ninguna | Se pueden incorporar cuando la telemetría Cowrie sustente sus requisitos de detección; no se atribuyen estrategias sin datos. |
| VirusTotal AI/API | Pendiente, opcional | Ninguna | Requiere credenciales y evaluación de cuotas/privacidad. |
| Cisco XDR MCP Community / API | Investigado, pendiente | Ninguna | Requiere acceso Cisco XDR y token OAuth; el análisis no depende de Cisco. |
| NIST SP 800-61 Rev. 3 | Referencia metodológica | Ninguna | Orienta el análisis y la respuesta, no es fuente de reputación. |

Las fuentes remotas no se consultan sin clave. IP privadas, de documentación o no enrutable no salen a proveedores. Ninguna credencial capturada se envía a esos proveedores. El caché de búsquedas positivas y sin resultado dura una hora en memoria de proceso; errores y cuotas no se cachean. Una falla remota se guarda como estado `error` o `cuota` y no detiene el análisis. No hay scraping. La carpeta MISP se actualiza manualmente y debe conservarse con su versión/commit para reproducibilidad.

## Datos, interfaz y limitaciones

La sección «Fuentes y evidencias» del análisis enlaza cada observable con los eventos Cowrie, las coincidencias de MISP y el estado, hora e identificador de los proveedores disponibles. Los mapeos MITRE y su justificación siguen en el detalle de las acciones y en la vista MITRE. Los análisis anteriores muestran un aviso de que no tenían enriquecimiento registrado.

El análisis usa como máximo 30 observables por sesión para acotar cuotas. El caché en memoria no se comparte entre procesos y no persiste reinicios; los resultados de cada análisis sí quedan en PostgreSQL. Las consultas remotas requieren conectividad y pueden no devolver coincidencias. El texto libre del LLM no admite una verificación semántica completa: se preserva la distinción entre observado, inferido y revisado, y se exige revisión humana para confirmar conclusiones.

## Referencias oficiales

- [MITRE ATT&CK Data & Tools](https://attack.mitre.org/resources/attack-data-and-tools/)
- [MITRE Detection Strategies](https://attack.mitre.org/detectionstrategies/) y [Analytics](https://attack.mitre.org/analytics/)
- [MISP Warning Lists](https://github.com/MISP/misp-warninglists)
- [ThreatFox Community API](https://threatfox.abuse.ch/api/)
- [URLhaus Community API](https://urlhaus.abuse.ch/api/)
- [Cisco XDR MCP Community](https://developer.cisco.com/codeexchange/github/repo/CiscoDevNet/xdr-mcp-community/) y [autenticación API](https://developer.cisco.com/docs/cisco-xdr/authentication/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
