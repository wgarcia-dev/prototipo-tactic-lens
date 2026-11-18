-- Additive RAG metadata; existing vectors, IDs, analyses and decisions are retained.
CREATE TABLE honeypot.catalogo_mitre (
 id_catalogo uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 dominio text NOT NULL CHECK(dominio='enterprise-attack'),
 version text NOT NULL, fuente text NOT NULL, sha256 varchar(64) NOT NULL,
 activo boolean NOT NULL DEFAULT false,
 conteos jsonb NOT NULL DEFAULT '{}'::jsonb,
 importado_en timestamptz NOT NULL DEFAULT now(),
 UNIQUE(dominio,version), CHECK(length(sha256)=64)
);
CREATE UNIQUE INDEX uq_catalogo_mitre_activo ON honeypot.catalogo_mitre(dominio) WHERE activo;
ALTER TABLE honeypot.modelo_embedding
 DROP CONSTRAINT ck_embedding_dimension,
 ADD CONSTRAINT ck_embedding_dimension CHECK(dimension IN (384,768)),
 ADD COLUMN configuracion jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE honeypot.tactica_mitre
 ADD COLUMN id_catalogo uuid REFERENCES honeypot.catalogo_mitre(id_catalogo),
 ADD COLUMN version_objeto text,
 ADD COLUMN revocada boolean NOT NULL DEFAULT false,
 ADD COLUMN deprecada boolean NOT NULL DEFAULT false;
ALTER TABLE honeypot.tecnica_mitre
 ADD COLUMN id_catalogo uuid REFERENCES honeypot.catalogo_mitre(id_catalogo),
 ADD COLUMN version_objeto text,
 ADD COLUMN plataformas jsonb NOT NULL DEFAULT '[]'::jsonb,
 ADD COLUMN es_subtecnica boolean NOT NULL DEFAULT false,
 ADD COLUMN jerarquia_fuente text,
 ADD COLUMN revocada boolean NOT NULL DEFAULT false,
 ADD COLUMN deprecada boolean NOT NULL DEFAULT false,
 ADD COLUMN objeto_sha256 varchar(64),
 ADD COLUMN embedding_rag vector(384),
 ADD COLUMN id_modelo_rag uuid REFERENCES honeypot.modelo_embedding(id_modelo_embedding),
 ADD COLUMN embedding_rag_sha256 varchar(64),
 ADD COLUMN documento_busqueda tsvector GENERATED ALWAYS AS (
   setweight(to_tsvector('english'::regconfig,coalesce(nombre,'')),'A') ||
   setweight(to_tsvector('english'::regconfig,coalesce(descripcion,'')),'B')) STORED,
 ADD CONSTRAINT ck_embedding_rag_metadata CHECK(embedding_rag IS NULL OR
   (id_modelo_rag IS NOT NULL AND embedding_rag_sha256 IS NOT NULL AND length(embedding_rag_sha256)=64));
CREATE INDEX ix_mitre_documento_rag ON honeypot.tecnica_mitre USING gin(documento_busqueda);
CREATE INDEX ix_mitre_vector_rag ON honeypot.tecnica_mitre USING hnsw(embedding_rag vector_cosine_ops)
 WHERE embedding_rag IS NOT NULL AND NOT revocada AND NOT deprecada;
ALTER TABLE honeypot.tecnica_tactica
 ADD COLUMN id_catalogo uuid REFERENCES honeypot.catalogo_mitre(id_catalogo),
 ADD COLUMN activa_en_catalogo boolean NOT NULL DEFAULT true;
ALTER TABLE honeypot.mapeo_mitre
 ADD COLUMN rag_procedencia jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(rag_procedencia)='object'),
 ADD COLUMN grado_evidencia varchar(24) CHECK(grado_evidencia IN ('intento','resultado_en_honeypot'));
