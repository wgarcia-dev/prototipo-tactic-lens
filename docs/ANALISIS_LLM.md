# Informe de comportamiento del honeypot

El informe nuevo conserva el resumen ejecutivo e incorpora contexto, reconstrucción cronológica por fases, hipótesis de objetivos, conclusión, limitaciones y comprobaciones recomendadas. Cada fase separa hechos observados, interpretación técnica y resultado registrado; tanto las fases como las hipótesis deben citar eventos de la sesión.

## Cómo usarlo

1. Abra **Análisis LLM** y seleccione una sesión, o entre a su detalle desde **Sesiones y eventos**.
2. Para una sesión pendiente, pulse **Analizar sesión**. El servidor usa el proveedor y modelo que ya estén configurados; no se cambió DeepSeek por otro servicio.
3. Un resultado antiguo muestra **Ampliar análisis**. Ese botón realiza una consulta nueva al proveedor y genera un resultado adicional. El anterior permanece guardado y conserva su identificador.
4. Un informe ampliado vigente muestra **Resultado guardado**. Las solicitudes posteriores reutilizan el resultado, salvo que existan eventos nuevos. Las consultas periódicas de la interfaz no solicitan análisis al LLM.
5. Revise los hechos y los IDs de evidencia antes de aceptar la interpretación del modelo. Las recomendaciones son comprobaciones propuestas, no acciones realizadas automáticamente.

Una solicitud nueva puede consumir saldo del proveedor. No se ampliaron automáticamente sesiones guardadas ni se invocó DeepSeek durante la implementación. La calidad final del texto generado se comprobará con una sesión real cuando el usuario solicite el análisis.

## Qué cambia en la petición

El prompt anterior solo exigía un resumen libre y una descripción breve. Ahora especifica profundidad proporcional a la evidencia, secuencia, finalidad de comandos, opciones y rutas relevantes, relación entre fases y resultado. Una sesión rica puede justificar aproximadamente 400–900 palabras; una conexión sin actividad debe producir una explicación breve sin inventar etapas.

El modelo recibe los eventos ordenados y los recuentos/fechas calculados por el servidor. Las contraseñas y secretos en campos reconocidos se redactan antes de construir el JSON, como en el flujo anterior. El prompt trata el contenido capturado como datos no confiables y prohíbe seguir instrucciones incrustadas, ejecutar comandos o visitar URLs.

No se debe confundir:

- Comando enviado con ejecución exitosa.
- URL en un comando con descarga confirmada.
- Archivo descargado con malware identificado o ejecutado.
- Intento de persistencia con persistencia demostrada.
- Acceso al entorno emulado con compromiso de la máquina real.
- Ausencia de un evento con prueba de que una acción no ocurrió.

La salida mantiene JSON y temperatura cero; el presupuesto máximo de salida pasa de 4096 a 8192 tokens. Si el proveedor informa `finish_reason=length`, devuelve contenido vacío, omite el informe o cita eventos ajenos, el análisis falla sin guardar hallazgos parciales. No hay reintentos automáticos que generen consultas adicionales. El timeout existente `LLM_TIMEOUT_SECONDS` sigue aplicándose.

El esquema y las referencias se validan, pero esto no certifica la corrección semántica de todas las afirmaciones. El porcentaje de confianza del modelo no es una probabilidad calibrada; requiere revisión del analista.

## Persistencia y compatibilidad

No hay tablas ni migraciones nuevas. Se reutilizan `analisis_llm.resumen` y `analisis_llm.resultado_estructurado`:

- `resumen`: síntesis ejecutiva.
- `informe`: contexto, fases, hipótesis, conclusión, limitaciones y recomendaciones.
- `contexto_observado`: recuentos, tipos de evento, marcas de tiempo y ventana entre el primer y el último evento.
- `version_informe=2`: versión del formato detallado.
- `eventos_analizados`: recuento usado para detectar eventos nuevos.

`POST /api/sesiones/{id}/analizar?actualizar_informe=true` permite ampliar explícitamente un resultado vigente con formato anterior. El servidor comprueba la versión; el indicador no fuerza consultas repetidas para un informe actual. Se mantienen autenticación, autorización, exclusión mutua por sesión y persistencia atómica de acciones, IoCs y mapeos MITRE.

## Archivos y comprobaciones

`backend/analysis_report.py` contiene el contrato narrativo, prompt, contexto calculado y validación de referencias. `backend/routes.py` integra proveedor, persistencia y ampliación. `frontend/src/analysis/AnalysisNarrative.tsx` presenta las secciones y se comparte entre las dos vistas existentes.

Se ejecutaron **74 pruebas del backend**, todas correctas, incluyendo nueve pruebas nuevas del contrato/proveedor simulado y ampliaciones de la prueba de integración PostgreSQL. Se comprobaron compatibilidad, ampliación explícita, conservación del resultado anterior, fallos del proveedor, rechazo de evidencia ajena y reutilización sin nueva consulta. Los datos de integración se revierten. No se enviaron correos externos ni se hicieron consultas reales al proveedor LLM.

La compilación TypeScript/Vite pasó. Se revisó visualmente el componente real con una vista temporal de datos ficticios, sin autenticación ni consultas al proveedor; dicha vista se eliminó después de la comprobación.

```powershell
# Desde la raíz del proyecto:
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v

# Desde frontend:
npm.cmd run build
```

Para cargar el nuevo backend, detenga el proceso anterior con Ctrl+C y ejecute desde la raíz:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.api:app --host 192.168.56.1 --port 8000
```

Referencias de la API del proveedor: [JSON Output](https://api-docs.deepseek.com/guides/json_mode/) y [Chat Completions: tokens y causas de finalización](https://api-docs.deepseek.com/api/create-chat-completion/).
