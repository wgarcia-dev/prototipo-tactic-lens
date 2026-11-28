# Restricciones del diccionario que PostgreSQL no aplica tal como están documentadas

Fecha de verificación del 24 de noviembre de 2026, horario de Ecuador.

## Alcance

Comparación de la sección 4.3.4, «Diccionario de datos», del archivo `Documento_Estudio_Caso_Practico.pdf`, tablas 36 a 55, páginas 62 a 78, con el esquema `honeypot` de la base PostgreSQL configurada en el proyecto.

Se revisaron claves primarias, claves foráneas y sus acciones de eliminación, nulabilidad, valores predeterminados, identidad, unicidad y condiciones CHECK de los campos documentados. La comparación se efectuó mediante consultas de solo lectura al catálogo de PostgreSQL.

## Diferencia encontrada

| Tabla del diccionario | Campo | Restricción escrita en el documento | Restricción existente en PostgreSQL | Diferencia |
|---|---|---|---|---|
| MODELO_EMBEDDING, tabla 43, página 68 | `dimension` | `CHECK (dimension = 768)` | `CHECK (dimension = ANY (ARRAY[384, 768]))` | El documento exige exclusivamente 768 dimensiones. La base también admite 384. Por tanto, la exclusividad de 768 escrita en el diccionario no está aplicada. |

El campo conserva `NOT NULL` y `DEFAULT 768`. Esas dos condiciones coinciden con el documento.

La diferencia corresponde al contenido de un CHECK existente. La regla documentada rechazaría el valor 384, mientras que la regla implementada lo acepta.

## Resultado del resto de la comparación

Para los demás campos descritos en las tablas 36 a 55, no se identificaron restricciones expresamente escritas en el diccionario que falten en PostgreSQL.

Se consideraron equivalentes las siguientes representaciones del catálogo.

- `BETWEEN 0 AND 1` y la conjunción de las comparaciones `>= 0` y `<= 1`.
- `IN (...)` y `= ANY (ARRAY[...])`, cuando contienen los mismos valores.
- Una condición compuesta del documento y varias condiciones CHECK de PostgreSQL que, en conjunto, imponen la misma regla.
- La unicidad aplicada mediante un índice único y la exigencia de unicidad del diccionario, cuando coinciden los campos y la expresión.

Las restricciones adicionales de PostgreSQL y los campos o tablas ausentes del documento quedan fuera de esta lista, cuyo propósito es identificar exigencias del diccionario que la base no reproduce.

## Estado de la verificación

Este archivo registra el resultado de la comparación. La revisión no modificó datos, restricciones ni el documento PDF.
