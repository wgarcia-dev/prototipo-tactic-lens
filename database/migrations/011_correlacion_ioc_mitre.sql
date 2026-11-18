CREATE UNIQUE INDEX IF NOT EXISTS uq_mapeo_mitre_id_accion
    ON honeypot.mapeo_mitre (id_mapeo, id_accion);

CREATE TABLE IF NOT EXISTS honeypot.mapeo_mitre_evento (
    id_mapeo uuid NOT NULL,
    id_accion uuid NOT NULL,
    id_evento bigint NOT NULL,
    metodo text NOT NULL CHECK (metodo IN ('rag_validado_v1', 'cita_rag_historica_v1')),
    PRIMARY KEY (id_mapeo, id_evento),
    FOREIGN KEY (id_mapeo, id_accion) REFERENCES honeypot.mapeo_mitre (id_mapeo, id_accion),
    FOREIGN KEY (id_accion, id_evento) REFERENCES honeypot.accion_evento (id_accion, id_evento)
);

CREATE INDEX IF NOT EXISTS ix_mapeo_mitre_evento_accion_evento
    ON honeypot.mapeo_mitre_evento (id_accion, id_evento);

-- Recover only explicit, complete historical RAG citations that belong to
-- the mapping's action and the analysis session. Leave free-form text intact.
WITH citas AS (
    SELECT m.id_mapeo, m.id_accion, a.id_sesion,
           CASE WHEN jsonb_typeof(m.rag_procedencia->'eventos') = 'array'
                THEN m.rag_procedencia->'eventos' ELSE '[]'::jsonb END AS eventos
    FROM honeypot.mapeo_mitre m
    JOIN honeypot.accion_identificada ai USING (id_accion)
    JOIN honeypot.analisis_llm a USING (id_analisis)
    WHERE m.rag_procedencia->>'metodo' = 'deepseek_rag_mitre_v1'
      AND coalesce(m.rag_procedencia->>'citas_explicitas', 'true') = 'true'
      AND a.estado = 'completado'
)
INSERT INTO honeypot.mapeo_mitre_evento (id_mapeo, id_accion, id_evento, metodo)
SELECT c.id_mapeo, c.id_accion, ae.id_evento, 'cita_rag_historica_v1'
FROM citas c
JOIN honeypot.accion_evento ae USING (id_accion)
JOIN honeypot.evento e USING (id_evento)
WHERE e.id_sesion = c.id_sesion
  AND c.eventos @> jsonb_build_array(ae.id_evento)
  AND NOT EXISTS (
      SELECT 1 FROM jsonb_array_elements(c.eventos) cita(valor)
      WHERE NOT EXISTS (
          SELECT 1 FROM honeypot.accion_evento ae2
          JOIN honeypot.evento e2 USING (id_evento)
          WHERE ae2.id_accion = c.id_accion AND e2.id_sesion = c.id_sesion
            AND cita.valor = to_jsonb(ae2.id_evento)
      )
  )
ON CONFLICT (id_mapeo, id_evento) DO NOTHING;
