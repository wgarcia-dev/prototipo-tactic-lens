-- Keep the irreversible Argon2id hash solely to reject the mailed credential as
-- a permanent password. Expiration/use/required-change flags govern its validity.
ALTER TABLE honeypot.usuario
 DROP CONSTRAINT ck_password_temporal,
 DROP CONSTRAINT ck_password_temporal_inactiva,
 ADD CONSTRAINT ck_password_temporal CHECK(
  NOT password_cambio_obligatorio OR
  (password_temporal_vence_en IS NOT NULL AND
   (password_temporal_hash IS NOT NULL OR password_temporal_usada_en IS NOT NULL))
 );
