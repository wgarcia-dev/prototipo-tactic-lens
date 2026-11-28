CREATE TABLE honeypot.salvaguarda_config (
    tablero boolean PRIMARY KEY DEFAULT true CHECK (tablero),
    wip_activo boolean NOT NULL DEFAULT true,
    limite_wip integer NOT NULL DEFAULT 5 CHECK (limite_wip BETWEEN 1 AND 10000)
);

INSERT INTO honeypot.salvaguarda_config DEFAULT VALUES;
