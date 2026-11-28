-- Fixture exclusivo de respuesta. No instalar como migración de la aplicación.
CREATE TABLE honeypot.incidente (
    id_incidente uuid PRIMARY KEY,
    revision_actual integer NOT NULL
);
CREATE TABLE honeypot.incidente_evaluacion (
    id_incidente uuid NOT NULL REFERENCES honeypot.incidente(id_incidente),
    revision_evaluacion integer NOT NULL,
    vista jsonb NOT NULL,
    PRIMARY KEY (id_incidente, revision_evaluacion)
);
