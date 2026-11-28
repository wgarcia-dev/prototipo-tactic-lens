CREATE TABLE honeypot.salvaguarda (
    id_salvaguarda uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    codigo bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    id_sesion uuid NOT NULL REFERENCES honeypot.sesion(id_sesion),
    huella char(64) NOT NULL,
    nombre text NOT NULL,
    nivel_riesgo varchar(7) NOT NULL CHECK (nivel_riesgo IN ('bajo','medio','alto','critico')),
    prioridad varchar(10),
    estado varchar(16) NOT NULL DEFAULT 'pendiente' CHECK (estado IN ('pendiente','en_desarrollo','realizada')),
    id_responsable uuid REFERENCES honeypot.usuario(id_usuario),
    creado_en timestamptz NOT NULL DEFAULT now(),
    asignado_en timestamptz,
    iniciado_en timestamptz,
    vence_en date,
    finalizado_en timestamptz,
    UNIQUE (id_sesion, huella),
    CHECK ((estado = 'pendiente') = (iniciado_en IS NULL)),
    CHECK ((estado = 'realizada') = (finalizado_en IS NOT NULL)),
    CHECK (estado = 'pendiente' OR id_responsable IS NOT NULL)
);

CREATE TABLE honeypot.salvaguarda_origen (
    id_analisis uuid NOT NULL REFERENCES honeypot.analisis_llm(id_analisis),
    posicion integer NOT NULL CHECK (posicion > 0),
    id_salvaguarda uuid NOT NULL REFERENCES honeypot.salvaguarda(id_salvaguarda),
    recomendacion jsonb NOT NULL CHECK (jsonb_typeof(recomendacion) = 'object'),
    valoracion jsonb NOT NULL CHECK (jsonb_typeof(valoracion) = 'object'),
    PRIMARY KEY (id_analisis, posicion)
);

CREATE TABLE honeypot.salvaguarda_historial (
    id_cambio bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id_salvaguarda uuid NOT NULL REFERENCES honeypot.salvaguarda(id_salvaguarda),
    id_actor uuid NOT NULL REFERENCES honeypot.usuario(id_usuario),
    operacion varchar(16) NOT NULL CHECK (operacion IN ('asignacion','estado','avance','evidencia','reapertura')),
    detalle jsonb NOT NULL CHECK (jsonb_typeof(detalle) = 'object'),
    creado_en timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX salvaguarda_tablero_idx ON honeypot.salvaguarda (estado, id_responsable, vence_en);
CREATE INDEX salvaguarda_origen_tarea_idx ON honeypot.salvaguarda_origen (id_salvaguarda);
CREATE INDEX salvaguarda_historial_tarea_idx ON honeypot.salvaguarda_historial (id_salvaguarda, id_cambio);
