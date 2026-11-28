# Datos exclusivamente sintéticos

`synthetic_events.json` contiene nueve eventos inventados, con IP de documentación
y dominios `.invalid`. Los textos de comando son datos: ninguna prueba los ejecuta.
`synthetic_labels.json` define, antes de evaluar el motor, siete eventos que deben
producir alguna detección y dos negativos. Esta etiqueta mide detección de patrones,
no compromiso confirmado. Se esperan seis alertas graves.

Las pruebas parametrizadas generan además fuerza bruta, secuencias, ventanas,
modalidades, credenciales ficticias y coincidencias de hashes. El hash repetido `a`
es una entrada de inteligencia sintética, no un hash de malware real verificado.
