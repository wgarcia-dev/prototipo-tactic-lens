// Native Node runner: test-only imports never enter the browser build.
import test from "node:test";
import assert from "node:assert/strict";
import {
  cedulaError,
  nameError,
  usernameError,
  emailError,
  normalizeName,
  normalizeUsername,
  normalizeEmail,
  registrationErrors,
} from "./validators.ts";

test("cédulas sintéticas con dígito correcto, ceros iniciales y provincia 30", () => {
  for (const value of ["1710000017", "0910000017", "3010000010"])
    assert.equal(cedulaError(value), "");
});
test("cédulas incompletas, tercer dígito, provincia y verificador incorrectos", () => {
  for (const value of [
    "1710000018",
    "1760000000",
    "9912345678",
    "0000000000",
    "171000001",
    "17100000170",
    "１２３４５６７８９０",
  ])
    assert.notEqual(cedulaError(value), "");
});
test("nombres legítimos con Unicode, apóstrofos y normalización", () => {
  for (const value of [
    "Ángela María",
    "O'Neill Ñúñez",
    "María-José",
    "A.",
    "李 明",
  ])
    assert.equal(nameError(value), "");
  assert.equal(normalizeName("  Mari\u0301a   José "), "María José");
});
test("nombres vacíos o con entradas que no son nombres", () => {
  for (const value of ["", "123", "<script>", "Nombre; DROP TABLE usuario"])
    assert.notEqual(nameError(value), "");
});
test("usuario normalizado y correcciones de formato", () => {
  assert.equal(normalizeUsername(" ＡＮＡ.G "), "ana.g");
  assert.equal(usernameError(" ANA.G "), "");
  for (const value of ["ab", ".ana", "ana@dominio", "josé"])
    assert.notEqual(usernameError(value), "");
});
test("correo: formato inmediato y normalización sin afirmar titularidad", () => {
  assert.equal(normalizeEmail(" ANA@EXAMPLE.ORG "), "ana@example.org");
  assert.equal(emailError(" ANA@EXAMPLE.ORG "), "");
  for (const value of [
    "",
    "ana",
    "ana@dominio",
    "ana@@example.org",
    "a..b@example.org",
    "ana@exa mple.org",
  ])
    assert.notEqual(emailError(value), "");
});
test("el formulario necesita todos los datos válidos", () => {
  const values = {
    cedula: "1710000017",
    nombres: "Ana",
    apellidos: "Muñoz",
    nombre_usuario: "ana.m",
    correo: "ana@example.org",
  };
  assert.equal(Object.values(registrationErrors(values)).some(Boolean), false);
  assert.notEqual(
    registrationErrors({ ...values, cedula: "1710000018" }).cedula,
    "",
  );
});
