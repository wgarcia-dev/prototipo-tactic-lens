# Muestra privada

`cowrie_events.json` es una copia local, byte a byte, del archivo proporcionado
`../eventos_json_50.json`. Ambos contienen datos originales; no son fixtures sintéticos.
La copia y los resultados están excluidos de Git por el `.gitignore` del laboratorio.
No se ha modificado el archivo proporcionado ni se ha consultado PostgreSQL.

Si distribuyes el laboratorio, entrega la muestra mediante un canal adecuado o usa
`--input RUTA`. El test real se omite explícitamente si no dispone de la muestra;
puede localizarse con la variable `COWRIE_REAL_EVENTS`.
