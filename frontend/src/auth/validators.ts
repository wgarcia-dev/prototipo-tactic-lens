/** Immediate format feedback; PostgreSQL and server validators remain authoritative. */
export type RegistrationValues = {
  cedula: string;
  nombres: string;
  apellidos: string;
  nombre_usuario: string;
  correo: string;
};

export function cedulaError(value: string): string {
  if (!/^[0-9]{10}$/.test(value))
    return "La cédula debe contener exactamente diez dígitos.";
  const province = Number(value.slice(0, 2));
  if (
    !((province >= 1 && province <= 24) || province === 30) ||
    Number(value[2]) >= 6
  )
    return "La cédula no corresponde al formato de persona natural ecuatoriana.";
  const total = [...value.slice(0, 9)].reduce((sum, digit, index) => {
    const number = Number(digit) * (index % 2 === 0 ? 2 : 1);
    return sum + (number > 9 ? number - 9 : number);
  }, 0);
  return (10 - (total % 10)) % 10 === Number(value[9])
    ? ""
    : "El dígito verificador de la cédula no es válido.";
}

export const normalizeName = (value: string) =>
  value.normalize("NFC").trim().replace(/\s+/g, " ");
export const normalizeUsername = (value: string) =>
  value.normalize("NFKC").trim().toLowerCase();
export const normalizeEmail = (value: string) => value.trim().toLowerCase();

export function nameError(value: string): string {
  const name = normalizeName(value);
  if (name.length < 1 || name.length > 58)
    return "Use entre 1 y 58 caracteres.";
  return /^[\p{L}\p{M} '\u2019.\-]+$/u.test(name) && /\p{L}/u.test(name)
    ? ""
    : "Use letras, espacios, apóstrofos, puntos o guiones.";
}

export function usernameError(value: string): string {
  return /^[a-z0-9][a-z0-9_.-]{2,63}$/.test(normalizeUsername(value))
    ? ""
    : "Use de 3 a 64 letras sin tildes, números, puntos o guiones.";
}

export function emailError(value: string): string {
  const email = normalizeEmail(value);
  if (
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    email.split("@")[0].length > 64
  )
    return "Escriba un correo completo, por ejemplo nombre@dominio.com.";
  const [local, domain] = email.split("@");
  if (
    local.startsWith(".") ||
    local.endsWith(".") ||
    local.includes("..") ||
    domain.includes("..") ||
    /[<>()[\]\\,:;\"]/.test(local) ||
    /[/?#:\s]/.test(domain)
  )
    return "Revise los puntos y caracteres de la dirección de correo.";
  return "";
}

export function registrationErrors(values: RegistrationValues) {
  return {
    cedula: cedulaError(values.cedula),
    nombres: nameError(values.nombres),
    apellidos: nameError(values.apellidos),
    nombre_usuario: usernameError(values.nombre_usuario),
    correo: emailError(values.correo),
  };
}
