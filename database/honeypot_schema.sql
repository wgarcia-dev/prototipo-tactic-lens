--
-- PostgreSQL database dump
--

\restrict mDWcjS9y14ajh1i7DTItC8Z9UEn9oaalf7XwCwdPTlEYPCAZf0Qyr2QzqtBF3VL

-- Dumped from database version 18.4
-- Dumped by pg_dump version 18.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: honeypot; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA honeypot;


--
-- Name: actualizar_fecha_auditoria(); Type: FUNCTION; Schema: honeypot; Owner: -
--

CREATE FUNCTION honeypot.actualizar_fecha_auditoria() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.actualizado_en := NOW();
    RETURN NEW;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: accion_evento; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.accion_evento (
    id_accion uuid NOT NULL,
    id_evento bigint NOT NULL,
    evidencia text NOT NULL,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_ae_evidencia CHECK ((length(btrim(evidencia)) > 0))
);


--
-- Name: accion_identificada; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.accion_identificada (
    id_accion uuid DEFAULT gen_random_uuid() NOT NULL,
    id_analisis uuid NOT NULL,
    tipo_accion character varying(80) NOT NULL,
    descripcion text NOT NULL,
    confianza numeric(5,4),
    embedding_descripcion public.vector(768),
    id_modelo_embedding uuid,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_accion_confianza CHECK (((confianza >= (0)::numeric) AND (confianza <= (1)::numeric))),
    CONSTRAINT ck_accion_descripcion CHECK ((length(btrim(descripcion)) > 0)),
    CONSTRAINT ck_accion_embedding CHECK (((embedding_descripcion IS NULL) OR (id_modelo_embedding IS NOT NULL))),
    CONSTRAINT ck_accion_tipo CHECK ((length(btrim((tipo_accion)::text)) > 0))
);


--
-- Name: accion_ioc; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.accion_ioc (
    id_accion uuid NOT NULL,
    id_deteccion uuid NOT NULL,
    creado_en timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: analisis_llm; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.analisis_llm (
    id_analisis uuid DEFAULT gen_random_uuid() NOT NULL,
    id_sesion uuid NOT NULL,
    id_modelo uuid NOT NULL,
    estado character varying(30) DEFAULT 'pendiente'::character varying NOT NULL,
    fecha_inicio timestamp with time zone,
    fecha_fin timestamp with time zone,
    resumen text,
    resultado_estructurado jsonb,
    mensaje_error text,
    embedding_resumen public.vector(768),
    id_modelo_embedding uuid,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_analisis_embedding CHECK (((embedding_resumen IS NULL) OR (id_modelo_embedding IS NOT NULL))),
    CONSTRAINT ck_analisis_error CHECK ((((estado)::text <> 'fallido'::text) OR ((fecha_fin IS NOT NULL) AND (NULLIF(btrim(mensaje_error), ''::text) IS NOT NULL)))),
    CONSTRAINT ck_analisis_estado CHECK (((estado)::text = ANY ((ARRAY['pendiente'::character varying, 'en_proceso'::character varying, 'completado'::character varying, 'fallido'::character varying])::text[]))),
    CONSTRAINT ck_analisis_fechas CHECK (((fecha_fin IS NULL) OR ((fecha_inicio IS NOT NULL) AND (fecha_fin >= fecha_inicio)))),
    CONSTRAINT ck_analisis_json CHECK (((resultado_estructurado IS NULL) OR (jsonb_typeof(resultado_estructurado) = 'object'::text))),
    CONSTRAINT ck_analisis_resultado CHECK ((((estado)::text <> 'completado'::text) OR ((fecha_inicio IS NOT NULL) AND (fecha_fin IS NOT NULL) AND (resultado_estructurado IS NOT NULL))))
);


--
-- Name: configuracion_integracion; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.configuracion_integracion (
    id_config uuid DEFAULT gen_random_uuid() NOT NULL,
    id_honeypot uuid NOT NULL,
    version_config integer NOT NULL,
    parametros jsonb DEFAULT '{}'::jsonb NOT NULL,
    activo boolean DEFAULT true NOT NULL,
    actualizado_en timestamp with time zone DEFAULT now() NOT NULL,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    actualizado_por uuid,
    CONSTRAINT ck_config_json CHECK ((jsonb_typeof(parametros) = 'object'::text)),
    CONSTRAINT ck_config_version CHECK ((version_config > 0))
);


--
-- Name: deteccion_ioc; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.deteccion_ioc (
    id_deteccion uuid DEFAULT gen_random_uuid() NOT NULL,
    id_ioc uuid NOT NULL,
    id_analisis uuid NOT NULL,
    id_evento bigint NOT NULL,
    evidencia text NOT NULL,
    confianza numeric(5,4),
    detectado_en timestamp with time zone DEFAULT now() NOT NULL,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_deteccion_confianza CHECK (((confianza >= (0)::numeric) AND (confianza <= (1)::numeric))),
    CONSTRAINT ck_deteccion_evidencia CHECK ((length(btrim(evidencia)) > 0))
);


--
-- Name: evento; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.evento (
    id_evento bigint NOT NULL,
    id_sesion uuid NOT NULL,
    numero_secuencia integer NOT NULL,
    tipo_evento character varying(100) NOT NULL,
    fecha_hora timestamp with time zone NOT NULL,
    datos_originales jsonb NOT NULL,
    ingresado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_evento_json CHECK ((jsonb_typeof(datos_originales) = 'object'::text)),
    CONSTRAINT ck_evento_secuencia CHECK ((numero_secuencia >= 0)),
    CONSTRAINT ck_evento_tipo CHECK ((length(btrim((tipo_evento)::text)) > 0))
);


--
-- Name: evento_id_evento_seq; Type: SEQUENCE; Schema: honeypot; Owner: -
--

ALTER TABLE honeypot.evento ALTER COLUMN id_evento ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME honeypot.evento_id_evento_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: honeypot; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.honeypot (
    id_honeypot uuid DEFAULT gen_random_uuid() NOT NULL,
    nombre character varying(80) NOT NULL,
    software character varying(40) DEFAULT 'Cowrie'::character varying NOT NULL,
    version character varying(30),
    host character varying(255) NOT NULL,
    estado character varying(20) DEFAULT 'activo'::character varying NOT NULL,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp with time zone DEFAULT now() NOT NULL,
    id_usuario uuid,
    CONSTRAINT ck_honeypot_estado CHECK (((estado)::text = ANY ((ARRAY['activo'::character varying, 'inactivo'::character varying, 'mantenimiento'::character varying])::text[]))),
    CONSTRAINT ck_honeypot_host CHECK ((length(btrim((host)::text)) > 0)),
    CONSTRAINT ck_honeypot_nombre CHECK ((length(btrim((nombre)::text)) > 0))
);


--
-- Name: ioc; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.ioc (
    id_ioc uuid DEFAULT gen_random_uuid() NOT NULL,
    id_tipo_ioc smallint NOT NULL,
    valor text NOT NULL,
    primera_observacion timestamp with time zone NOT NULL,
    ultima_observacion timestamp with time zone NOT NULL,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_ioc_observaciones CHECK ((ultima_observacion >= primera_observacion)),
    CONSTRAINT ck_ioc_valor CHECK ((length(btrim(valor)) > 0))
);


--
-- Name: mapeo_mitre; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.mapeo_mitre (
    id_mapeo uuid DEFAULT gen_random_uuid() NOT NULL,
    id_accion uuid NOT NULL,
    id_vinculo uuid NOT NULL,
    evidencia text NOT NULL,
    justificacion text NOT NULL,
    confianza numeric(5,4),
    fecha_mapeo timestamp with time zone DEFAULT now() NOT NULL,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_mapeo_confianza CHECK (((confianza >= (0)::numeric) AND (confianza <= (1)::numeric))),
    CONSTRAINT ck_mapeo_evidencia CHECK ((length(btrim(evidencia)) > 0)),
    CONSTRAINT ck_mapeo_justificacion CHECK ((length(btrim(justificacion)) > 0))
);


--
-- Name: modelo_embedding; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.modelo_embedding (
    id_modelo_embedding uuid DEFAULT gen_random_uuid() NOT NULL,
    proveedor character varying(80) NOT NULL,
    nombre_modelo character varying(120) NOT NULL,
    dimension integer DEFAULT 768 NOT NULL,
    activo boolean DEFAULT true NOT NULL,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_embedding_dimension CHECK ((dimension = 768)),
    CONSTRAINT ck_embedding_nombre CHECK ((length(btrim((nombre_modelo)::text)) > 0)),
    CONSTRAINT ck_embedding_proveedor CHECK ((length(btrim((proveedor)::text)) > 0))
);


--
-- Name: modelo_llm; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.modelo_llm (
    id_modelo uuid DEFAULT gen_random_uuid() NOT NULL,
    proveedor character varying(80) NOT NULL,
    nombre_modelo character varying(100) NOT NULL,
    version_modelo character varying(40) NOT NULL,
    activo boolean DEFAULT true NOT NULL,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_modelo_llm_nombre CHECK ((length(btrim((nombre_modelo)::text)) > 0)),
    CONSTRAINT ck_modelo_llm_proveedor CHECK ((length(btrim((proveedor)::text)) > 0)),
    CONSTRAINT ck_modelo_llm_version CHECK ((length(btrim((version_modelo)::text)) > 0))
);


--
-- Name: revision_analisis; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.revision_analisis (
    id_revision uuid DEFAULT gen_random_uuid() NOT NULL,
    id_analisis uuid NOT NULL,
    id_usuario uuid NOT NULL,
    estado_revision character varying(30) NOT NULL,
    observaciones text,
    revisado_en timestamp with time zone,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_revision_estado CHECK (((estado_revision)::text = ANY ((ARRAY['pendiente'::character varying, 'aprobado'::character varying, 'observado'::character varying, 'rechazado'::character varying])::text[]))),
    CONSTRAINT ck_revision_fecha CHECK ((((estado_revision)::text = 'pendiente'::text) OR (revisado_en IS NOT NULL)))
);


--
-- Name: rol; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.rol (
    id_rol smallint NOT NULL,
    nombre character varying(40) NOT NULL,
    descripcion text,
    activo boolean DEFAULT true NOT NULL,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_rol_nombre CHECK ((length(btrim((nombre)::text)) > 0))
);


--
-- Name: sesion; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.sesion (
    id_sesion uuid DEFAULT gen_random_uuid() NOT NULL,
    id_honeypot uuid NOT NULL,
    cowrie_session_id character varying(100) NOT NULL,
    ip_origen inet,
    puerto_origen integer,
    puerto_destino integer,
    protocolo character varying(20) DEFAULT 'ssh'::character varying NOT NULL,
    fecha_inicio timestamp with time zone NOT NULL,
    fecha_fin timestamp with time zone,
    metadatos jsonb DEFAULT '{}'::jsonb NOT NULL,
    registrado_en timestamp with time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_sesion_fechas CHECK (((fecha_fin IS NULL) OR (fecha_fin >= fecha_inicio))),
    CONSTRAINT ck_sesion_identificador CHECK ((length(btrim((cowrie_session_id)::text)) > 0)),
    CONSTRAINT ck_sesion_metadatos CHECK ((jsonb_typeof(metadatos) = 'object'::text)),
    CONSTRAINT ck_sesion_puerto_destino CHECK (((puerto_destino >= 1) AND (puerto_destino <= 65535))),
    CONSTRAINT ck_sesion_puerto_origen CHECK (((puerto_origen >= 1) AND (puerto_origen <= 65535)))
);


--
-- Name: tactica_mitre; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.tactica_mitre (
    codigo_tactica character varying(16) NOT NULL,
    stix_id character varying(120),
    nombre character varying(150) NOT NULL,
    descripcion text,
    version_attack character varying(20),
    sincronizado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_tactica_codigo CHECK ((length(btrim((codigo_tactica)::text)) > 0)),
    CONSTRAINT ck_tactica_nombre CHECK ((length(btrim((nombre)::text)) > 0))
);


--
-- Name: tecnica_mitre; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.tecnica_mitre (
    codigo_tecnica character varying(20) NOT NULL,
    tecnica_padre_id character varying(20),
    stix_id character varying(120),
    nombre character varying(180) NOT NULL,
    descripcion text,
    version_attack character varying(20),
    embedding_descripcion public.vector(768),
    id_modelo_embedding uuid,
    sincronizado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_tecnica_codigo CHECK ((length(btrim((codigo_tecnica)::text)) > 0)),
    CONSTRAINT ck_tecnica_embedding_modelo CHECK (((embedding_descripcion IS NULL) OR (id_modelo_embedding IS NOT NULL))),
    CONSTRAINT ck_tecnica_no_autopadre CHECK (((tecnica_padre_id)::text IS DISTINCT FROM (codigo_tecnica)::text)),
    CONSTRAINT ck_tecnica_nombre CHECK ((length(btrim((nombre)::text)) > 0))
);


--
-- Name: tecnica_tactica; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.tecnica_tactica (
    id_vinculo uuid DEFAULT gen_random_uuid() NOT NULL,
    codigo_tecnica character varying(20) NOT NULL,
    codigo_tactica character varying(16) NOT NULL,
    sincronizado_en timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: tipo_ioc; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.tipo_ioc (
    id_tipo_ioc smallint NOT NULL,
    nombre character varying(40) NOT NULL,
    descripcion text,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_tipo_ioc_nombre CHECK ((length(btrim((nombre)::text)) > 0))
);


--
-- Name: tipo_ioc_id_tipo_ioc_seq; Type: SEQUENCE; Schema: honeypot; Owner: -
--

ALTER TABLE honeypot.tipo_ioc ALTER COLUMN id_tipo_ioc ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME honeypot.tipo_ioc_id_tipo_ioc_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: usuario; Type: TABLE; Schema: honeypot; Owner: -
--

CREATE TABLE honeypot.usuario (
    id_usuario uuid DEFAULT gen_random_uuid() NOT NULL,
    id_rol smallint NOT NULL,
    nombre character varying(120) NOT NULL,
    correo character varying(255) NOT NULL,
    password_hash text NOT NULL,
    activo boolean DEFAULT true NOT NULL,
    creado_en timestamp with time zone DEFAULT now() NOT NULL,
    actualizado_en timestamp with time zone DEFAULT now() NOT NULL,
    desactivado_en timestamp with time zone,
    CONSTRAINT ck_usuario_correo CHECK (((length(btrim((correo)::text)) > 0) AND ((correo)::text = btrim((correo)::text)))),
    CONSTRAINT ck_usuario_desactivacion CHECK (((desactivado_en IS NULL) OR (activo = false))),
    CONSTRAINT ck_usuario_nombre CHECK ((length(btrim((nombre)::text)) > 0)),
    CONSTRAINT ck_usuario_password CHECK ((length(password_hash) > 0))
);


--
-- Name: accion_identificada accion_identificada_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.accion_identificada
    ADD CONSTRAINT accion_identificada_pkey PRIMARY KEY (id_accion);


--
-- Name: analisis_llm analisis_llm_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.analisis_llm
    ADD CONSTRAINT analisis_llm_pkey PRIMARY KEY (id_analisis);


--
-- Name: configuracion_integracion configuracion_integracion_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.configuracion_integracion
    ADD CONSTRAINT configuracion_integracion_pkey PRIMARY KEY (id_config);


--
-- Name: deteccion_ioc deteccion_ioc_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.deteccion_ioc
    ADD CONSTRAINT deteccion_ioc_pkey PRIMARY KEY (id_deteccion);


--
-- Name: evento evento_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.evento
    ADD CONSTRAINT evento_pkey PRIMARY KEY (id_evento);


--
-- Name: honeypot honeypot_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.honeypot
    ADD CONSTRAINT honeypot_pkey PRIMARY KEY (id_honeypot);


--
-- Name: ioc ioc_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.ioc
    ADD CONSTRAINT ioc_pkey PRIMARY KEY (id_ioc);


--
-- Name: mapeo_mitre mapeo_mitre_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.mapeo_mitre
    ADD CONSTRAINT mapeo_mitre_pkey PRIMARY KEY (id_mapeo);


--
-- Name: modelo_embedding modelo_embedding_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.modelo_embedding
    ADD CONSTRAINT modelo_embedding_pkey PRIMARY KEY (id_modelo_embedding);


--
-- Name: modelo_llm modelo_llm_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.modelo_llm
    ADD CONSTRAINT modelo_llm_pkey PRIMARY KEY (id_modelo);


--
-- Name: accion_evento pk_accion_evento; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.accion_evento
    ADD CONSTRAINT pk_accion_evento PRIMARY KEY (id_accion, id_evento);


--
-- Name: accion_ioc pk_accion_ioc; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.accion_ioc
    ADD CONSTRAINT pk_accion_ioc PRIMARY KEY (id_accion, id_deteccion);


--
-- Name: revision_analisis revision_analisis_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.revision_analisis
    ADD CONSTRAINT revision_analisis_pkey PRIMARY KEY (id_revision);


--
-- Name: rol rol_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.rol
    ADD CONSTRAINT rol_pkey PRIMARY KEY (id_rol);


--
-- Name: sesion sesion_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.sesion
    ADD CONSTRAINT sesion_pkey PRIMARY KEY (id_sesion);


--
-- Name: tactica_mitre tactica_mitre_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.tactica_mitre
    ADD CONSTRAINT tactica_mitre_pkey PRIMARY KEY (codigo_tactica);


--
-- Name: tactica_mitre tactica_mitre_stix_id_key; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.tactica_mitre
    ADD CONSTRAINT tactica_mitre_stix_id_key UNIQUE (stix_id);


--
-- Name: tecnica_mitre tecnica_mitre_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.tecnica_mitre
    ADD CONSTRAINT tecnica_mitre_pkey PRIMARY KEY (codigo_tecnica);


--
-- Name: tecnica_mitre tecnica_mitre_stix_id_key; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.tecnica_mitre
    ADD CONSTRAINT tecnica_mitre_stix_id_key UNIQUE (stix_id);


--
-- Name: tecnica_tactica tecnica_tactica_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.tecnica_tactica
    ADD CONSTRAINT tecnica_tactica_pkey PRIMARY KEY (id_vinculo);


--
-- Name: tipo_ioc tipo_ioc_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.tipo_ioc
    ADD CONSTRAINT tipo_ioc_pkey PRIMARY KEY (id_tipo_ioc);


--
-- Name: configuracion_integracion uq_config_version; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.configuracion_integracion
    ADD CONSTRAINT uq_config_version UNIQUE (id_honeypot, version_config);


--
-- Name: deteccion_ioc uq_deteccion_identidad; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.deteccion_ioc
    ADD CONSTRAINT uq_deteccion_identidad UNIQUE (id_ioc, id_analisis, id_evento);


--
-- Name: evento uq_evento_secuencia; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.evento
    ADD CONSTRAINT uq_evento_secuencia UNIQUE (id_sesion, numero_secuencia);


--
-- Name: honeypot uq_honeypot_nombre; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.honeypot
    ADD CONSTRAINT uq_honeypot_nombre UNIQUE (nombre);


--
-- Name: ioc uq_ioc_tipo_valor; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.ioc
    ADD CONSTRAINT uq_ioc_tipo_valor UNIQUE (id_tipo_ioc, valor);


--
-- Name: mapeo_mitre uq_mapeo_accion_vinculo; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.mapeo_mitre
    ADD CONSTRAINT uq_mapeo_accion_vinculo UNIQUE (id_accion, id_vinculo);


--
-- Name: modelo_embedding uq_modelo_embedding; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.modelo_embedding
    ADD CONSTRAINT uq_modelo_embedding UNIQUE (proveedor, nombre_modelo);


--
-- Name: modelo_llm uq_modelo_llm; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.modelo_llm
    ADD CONSTRAINT uq_modelo_llm UNIQUE (proveedor, nombre_modelo, version_modelo);


--
-- Name: rol uq_rol_nombre; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.rol
    ADD CONSTRAINT uq_rol_nombre UNIQUE (nombre);


--
-- Name: sesion uq_sesion_cowrie; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.sesion
    ADD CONSTRAINT uq_sesion_cowrie UNIQUE (id_honeypot, cowrie_session_id);


--
-- Name: tecnica_tactica uq_tecnica_tactica; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.tecnica_tactica
    ADD CONSTRAINT uq_tecnica_tactica UNIQUE (codigo_tecnica, codigo_tactica);


--
-- Name: tipo_ioc uq_tipo_ioc_nombre; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.tipo_ioc
    ADD CONSTRAINT uq_tipo_ioc_nombre UNIQUE (nombre);


--
-- Name: usuario usuario_pkey; Type: CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.usuario
    ADD CONSTRAINT usuario_pkey PRIMARY KEY (id_usuario);


--
-- Name: ix_accion_analisis; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_accion_analisis ON honeypot.accion_identificada USING btree (id_analisis);


--
-- Name: ix_accion_embedding_modelo; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_accion_embedding_modelo ON honeypot.accion_identificada USING btree (id_modelo_embedding);


--
-- Name: ix_accion_evento_evento; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_accion_evento_evento ON honeypot.accion_evento USING btree (id_evento);


--
-- Name: ix_accion_ioc_deteccion; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_accion_ioc_deteccion ON honeypot.accion_ioc USING btree (id_deteccion);


--
-- Name: ix_analisis_embedding_modelo; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_analisis_embedding_modelo ON honeypot.analisis_llm USING btree (id_modelo_embedding);


--
-- Name: ix_analisis_modelo; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_analisis_modelo ON honeypot.analisis_llm USING btree (id_modelo);


--
-- Name: ix_analisis_sesion; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_analisis_sesion ON honeypot.analisis_llm USING btree (id_sesion, creado_en DESC);


--
-- Name: ix_config_honeypot; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_config_honeypot ON honeypot.configuracion_integracion USING btree (id_honeypot);


--
-- Name: ix_config_usuario; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_config_usuario ON honeypot.configuracion_integracion USING btree (actualizado_por);


--
-- Name: ix_deteccion_analisis; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_deteccion_analisis ON honeypot.deteccion_ioc USING btree (id_analisis);


--
-- Name: ix_deteccion_evento; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_deteccion_evento ON honeypot.deteccion_ioc USING btree (id_evento);


--
-- Name: ix_deteccion_ioc; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_deteccion_ioc ON honeypot.deteccion_ioc USING btree (id_ioc);


--
-- Name: ix_evento_datos_gin; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_evento_datos_gin ON honeypot.evento USING gin (datos_originales jsonb_path_ops);


--
-- Name: ix_evento_sesion_fecha; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_evento_sesion_fecha ON honeypot.evento USING btree (id_sesion, fecha_hora, id_evento);


--
-- Name: ix_evento_tipo_fecha; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_evento_tipo_fecha ON honeypot.evento USING btree (tipo_evento, fecha_hora DESC);


--
-- Name: ix_honeypot_usuario; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_honeypot_usuario ON honeypot.honeypot USING btree (id_usuario);


--
-- Name: ix_ioc_tipo; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_ioc_tipo ON honeypot.ioc USING btree (id_tipo_ioc);


--
-- Name: ix_mapeo_accion; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_mapeo_accion ON honeypot.mapeo_mitre USING btree (id_accion);


--
-- Name: ix_mapeo_vinculo; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_mapeo_vinculo ON honeypot.mapeo_mitre USING btree (id_vinculo);


--
-- Name: ix_revision_analisis; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_revision_analisis ON honeypot.revision_analisis USING btree (id_analisis);


--
-- Name: ix_revision_usuario; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_revision_usuario ON honeypot.revision_analisis USING btree (id_usuario);


--
-- Name: ix_sesion_honeypot_inicio; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_sesion_honeypot_inicio ON honeypot.sesion USING btree (id_honeypot, fecha_inicio DESC);


--
-- Name: ix_tecnica_embedding_modelo; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_tecnica_embedding_modelo ON honeypot.tecnica_mitre USING btree (id_modelo_embedding);


--
-- Name: ix_tecnica_padre; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_tecnica_padre ON honeypot.tecnica_mitre USING btree (tecnica_padre_id);


--
-- Name: ix_tt_tactica; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_tt_tactica ON honeypot.tecnica_tactica USING btree (codigo_tactica);


--
-- Name: ix_usuario_rol; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE INDEX ix_usuario_rol ON honeypot.usuario USING btree (id_rol);


--
-- Name: ux_config_activa_honeypot; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE UNIQUE INDEX ux_config_activa_honeypot ON honeypot.configuracion_integracion USING btree (id_honeypot) WHERE (activo = true);


--
-- Name: ux_usuario_correo; Type: INDEX; Schema: honeypot; Owner: -
--

CREATE UNIQUE INDEX ux_usuario_correo ON honeypot.usuario USING btree (lower((correo)::text));


--
-- Name: analisis_llm trg_analisis_llm_actualizado_en; Type: TRIGGER; Schema: honeypot; Owner: -
--

CREATE TRIGGER trg_analisis_llm_actualizado_en BEFORE UPDATE ON honeypot.analisis_llm FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();


--
-- Name: configuracion_integracion trg_configuracion_integracion_actualizado_en; Type: TRIGGER; Schema: honeypot; Owner: -
--

CREATE TRIGGER trg_configuracion_integracion_actualizado_en BEFORE UPDATE ON honeypot.configuracion_integracion FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();


--
-- Name: honeypot trg_honeypot_actualizado_en; Type: TRIGGER; Schema: honeypot; Owner: -
--

CREATE TRIGGER trg_honeypot_actualizado_en BEFORE UPDATE ON honeypot.honeypot FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();


--
-- Name: ioc trg_ioc_actualizado_en; Type: TRIGGER; Schema: honeypot; Owner: -
--

CREATE TRIGGER trg_ioc_actualizado_en BEFORE UPDATE ON honeypot.ioc FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();


--
-- Name: modelo_embedding trg_modelo_embedding_actualizado_en; Type: TRIGGER; Schema: honeypot; Owner: -
--

CREATE TRIGGER trg_modelo_embedding_actualizado_en BEFORE UPDATE ON honeypot.modelo_embedding FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();


--
-- Name: modelo_llm trg_modelo_llm_actualizado_en; Type: TRIGGER; Schema: honeypot; Owner: -
--

CREATE TRIGGER trg_modelo_llm_actualizado_en BEFORE UPDATE ON honeypot.modelo_llm FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();


--
-- Name: revision_analisis trg_revision_analisis_actualizado_en; Type: TRIGGER; Schema: honeypot; Owner: -
--

CREATE TRIGGER trg_revision_analisis_actualizado_en BEFORE UPDATE ON honeypot.revision_analisis FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();


--
-- Name: rol trg_rol_actualizado_en; Type: TRIGGER; Schema: honeypot; Owner: -
--

CREATE TRIGGER trg_rol_actualizado_en BEFORE UPDATE ON honeypot.rol FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();


--
-- Name: sesion trg_sesion_actualizado_en; Type: TRIGGER; Schema: honeypot; Owner: -
--

CREATE TRIGGER trg_sesion_actualizado_en BEFORE UPDATE ON honeypot.sesion FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();


--
-- Name: tipo_ioc trg_tipo_ioc_actualizado_en; Type: TRIGGER; Schema: honeypot; Owner: -
--

CREATE TRIGGER trg_tipo_ioc_actualizado_en BEFORE UPDATE ON honeypot.tipo_ioc FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();


--
-- Name: usuario trg_usuario_actualizado_en; Type: TRIGGER; Schema: honeypot; Owner: -
--

CREATE TRIGGER trg_usuario_actualizado_en BEFORE UPDATE ON honeypot.usuario FOR EACH ROW EXECUTE FUNCTION honeypot.actualizar_fecha_auditoria();


--
-- Name: accion_identificada fk_accion_analisis; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.accion_identificada
    ADD CONSTRAINT fk_accion_analisis FOREIGN KEY (id_analisis) REFERENCES honeypot.analisis_llm(id_analisis) ON DELETE RESTRICT;


--
-- Name: accion_identificada fk_accion_embedding; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.accion_identificada
    ADD CONSTRAINT fk_accion_embedding FOREIGN KEY (id_modelo_embedding) REFERENCES honeypot.modelo_embedding(id_modelo_embedding) ON DELETE RESTRICT;


--
-- Name: accion_evento fk_ae_accion; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.accion_evento
    ADD CONSTRAINT fk_ae_accion FOREIGN KEY (id_accion) REFERENCES honeypot.accion_identificada(id_accion) ON DELETE RESTRICT;


--
-- Name: accion_evento fk_ae_evento; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.accion_evento
    ADD CONSTRAINT fk_ae_evento FOREIGN KEY (id_evento) REFERENCES honeypot.evento(id_evento) ON DELETE RESTRICT;


--
-- Name: accion_ioc fk_ai_accion; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.accion_ioc
    ADD CONSTRAINT fk_ai_accion FOREIGN KEY (id_accion) REFERENCES honeypot.accion_identificada(id_accion) ON DELETE RESTRICT;


--
-- Name: accion_ioc fk_ai_deteccion; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.accion_ioc
    ADD CONSTRAINT fk_ai_deteccion FOREIGN KEY (id_deteccion) REFERENCES honeypot.deteccion_ioc(id_deteccion) ON DELETE RESTRICT;


--
-- Name: analisis_llm fk_analisis_embedding; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.analisis_llm
    ADD CONSTRAINT fk_analisis_embedding FOREIGN KEY (id_modelo_embedding) REFERENCES honeypot.modelo_embedding(id_modelo_embedding) ON DELETE RESTRICT;


--
-- Name: analisis_llm fk_analisis_modelo; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.analisis_llm
    ADD CONSTRAINT fk_analisis_modelo FOREIGN KEY (id_modelo) REFERENCES honeypot.modelo_llm(id_modelo) ON DELETE RESTRICT;


--
-- Name: analisis_llm fk_analisis_sesion; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.analisis_llm
    ADD CONSTRAINT fk_analisis_sesion FOREIGN KEY (id_sesion) REFERENCES honeypot.sesion(id_sesion) ON DELETE RESTRICT;


--
-- Name: configuracion_integracion fk_config_honeypot; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.configuracion_integracion
    ADD CONSTRAINT fk_config_honeypot FOREIGN KEY (id_honeypot) REFERENCES honeypot.honeypot(id_honeypot) ON DELETE RESTRICT;


--
-- Name: configuracion_integracion fk_config_usuario; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.configuracion_integracion
    ADD CONSTRAINT fk_config_usuario FOREIGN KEY (actualizado_por) REFERENCES honeypot.usuario(id_usuario) ON DELETE RESTRICT;


--
-- Name: deteccion_ioc fk_deteccion_analisis; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.deteccion_ioc
    ADD CONSTRAINT fk_deteccion_analisis FOREIGN KEY (id_analisis) REFERENCES honeypot.analisis_llm(id_analisis) ON DELETE RESTRICT;


--
-- Name: deteccion_ioc fk_deteccion_evento; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.deteccion_ioc
    ADD CONSTRAINT fk_deteccion_evento FOREIGN KEY (id_evento) REFERENCES honeypot.evento(id_evento) ON DELETE RESTRICT;


--
-- Name: deteccion_ioc fk_deteccion_ioc; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.deteccion_ioc
    ADD CONSTRAINT fk_deteccion_ioc FOREIGN KEY (id_ioc) REFERENCES honeypot.ioc(id_ioc) ON DELETE RESTRICT;


--
-- Name: evento fk_evento_sesion; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.evento
    ADD CONSTRAINT fk_evento_sesion FOREIGN KEY (id_sesion) REFERENCES honeypot.sesion(id_sesion) ON DELETE RESTRICT;


--
-- Name: honeypot fk_honeypot_usuario; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.honeypot
    ADD CONSTRAINT fk_honeypot_usuario FOREIGN KEY (id_usuario) REFERENCES honeypot.usuario(id_usuario) ON DELETE RESTRICT;


--
-- Name: ioc fk_ioc_tipo; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.ioc
    ADD CONSTRAINT fk_ioc_tipo FOREIGN KEY (id_tipo_ioc) REFERENCES honeypot.tipo_ioc(id_tipo_ioc) ON DELETE RESTRICT;


--
-- Name: mapeo_mitre fk_mapeo_accion; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.mapeo_mitre
    ADD CONSTRAINT fk_mapeo_accion FOREIGN KEY (id_accion) REFERENCES honeypot.accion_identificada(id_accion) ON DELETE RESTRICT;


--
-- Name: mapeo_mitre fk_mapeo_vinculo; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.mapeo_mitre
    ADD CONSTRAINT fk_mapeo_vinculo FOREIGN KEY (id_vinculo) REFERENCES honeypot.tecnica_tactica(id_vinculo) ON DELETE RESTRICT;


--
-- Name: revision_analisis fk_revision_analisis; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.revision_analisis
    ADD CONSTRAINT fk_revision_analisis FOREIGN KEY (id_analisis) REFERENCES honeypot.analisis_llm(id_analisis) ON DELETE RESTRICT;


--
-- Name: revision_analisis fk_revision_usuario; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.revision_analisis
    ADD CONSTRAINT fk_revision_usuario FOREIGN KEY (id_usuario) REFERENCES honeypot.usuario(id_usuario) ON DELETE RESTRICT;


--
-- Name: sesion fk_sesion_honeypot; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.sesion
    ADD CONSTRAINT fk_sesion_honeypot FOREIGN KEY (id_honeypot) REFERENCES honeypot.honeypot(id_honeypot) ON DELETE RESTRICT;


--
-- Name: tecnica_mitre fk_tecnica_embedding; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.tecnica_mitre
    ADD CONSTRAINT fk_tecnica_embedding FOREIGN KEY (id_modelo_embedding) REFERENCES honeypot.modelo_embedding(id_modelo_embedding) ON DELETE RESTRICT;


--
-- Name: tecnica_mitre fk_tecnica_padre; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.tecnica_mitre
    ADD CONSTRAINT fk_tecnica_padre FOREIGN KEY (tecnica_padre_id) REFERENCES honeypot.tecnica_mitre(codigo_tecnica) ON DELETE RESTRICT;


--
-- Name: tecnica_tactica fk_tt_tactica; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.tecnica_tactica
    ADD CONSTRAINT fk_tt_tactica FOREIGN KEY (codigo_tactica) REFERENCES honeypot.tactica_mitre(codigo_tactica) ON DELETE RESTRICT;


--
-- Name: tecnica_tactica fk_tt_tecnica; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.tecnica_tactica
    ADD CONSTRAINT fk_tt_tecnica FOREIGN KEY (codigo_tecnica) REFERENCES honeypot.tecnica_mitre(codigo_tecnica) ON DELETE RESTRICT;


--
-- Name: usuario fk_usuario_rol; Type: FK CONSTRAINT; Schema: honeypot; Owner: -
--

ALTER TABLE ONLY honeypot.usuario
    ADD CONSTRAINT fk_usuario_rol FOREIGN KEY (id_rol) REFERENCES honeypot.rol(id_rol) ON DELETE RESTRICT;


--
-- PostgreSQL database dump complete
--

\unrestrict mDWcjS9y14ajh1i7DTItC8Z9UEn9oaalf7XwCwdPTlEYPCAZf0Qyr2QzqtBF3VL

