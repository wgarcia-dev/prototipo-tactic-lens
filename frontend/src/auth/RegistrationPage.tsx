import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { CheckCircle2, Mail } from "lucide-react";
import { api, mutate } from "./client";
import { AuthFrame, Field, Form, Status, Submit, useTask } from "./components";
import {
  normalizeEmail,
  normalizeName,
  normalizeUsername,
  registrationErrors,
  type RegistrationValues,
} from "./validators";
import "./onboarding.css";

type EmailState = "idle" | "sent" | "verified";
type EmailStatus = {
  correo: string;
  enviado: boolean;
  verificado: boolean;
  caducado: boolean;
};

export function RegistrationPage() {
  const task = useTask(),
    emailTask = useTask(),
    navigate = useNavigate();
  const [values, setValues] = useState<RegistrationValues>({
    cedula: "",
    nombres: "",
    apellidos: "",
    nombre_usuario: "",
    correo: "",
  });
  const [touched, setTouched] = useState<Record<string, boolean>>({});
  const [emailState, setEmailState] = useState<EmailState>("idle");
  const [code, setCode] = useState("");
  const [cooldown, setCooldown] = useState(0);
  const [submitted, setSubmitted] = useState<{
    credencial_enviada: boolean;
  } | null>(null);
  const version = useRef(0);
  const errors = registrationErrors(values);
  const ready =
    Object.values(errors).every((error) => !error) && emailState === "verified";

  useEffect(() => {
    let active = true;
    void api<EmailStatus>("/auth/registro/correo")
      .then((status) => {
        if (!active || version.current) return;
        if (status.correo)
          setValues((previous) => ({ ...previous, correo: status.correo }));
        setEmailState(
          status.verificado ? "verified" : status.enviado ? "sent" : "idle",
        );
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = window.setTimeout(
      () => setCooldown((previous) => Math.max(0, previous - 1)),
      1000,
    );
    return () => window.clearTimeout(timer);
  }, [cooldown]);

  function change(field: keyof RegistrationValues, value: string) {
    setValues((previous) => ({ ...previous, [field]: value }));
    if (field === "correo") {
      version.current++;
      setEmailState("idle");
      setCode("");
      setCooldown(0);
      emailTask.clear();
    }
  }
  function blur(field: keyof RegistrationValues) {
    setTouched((previous) => ({ ...previous, [field]: true }));
    const normalizer =
      field === "nombres" || field === "apellidos"
        ? normalizeName
        : field === "nombre_usuario"
          ? normalizeUsername
          : field === "correo"
            ? normalizeEmail
            : (x: string) => x;
    setValues((previous) => ({
      ...previous,
      [field]: normalizer(previous[field]),
    }));
  }
  function shownError(field: keyof RegistrationValues) {
    const completeCedula = field === "cedula" && values.cedula.length === 10;
    return touched[field] ||
      completeCedula ||
      (values[field] && field !== "cedula")
      ? errors[field]
      : "";
  }

  function sendCode() {
    const correo = normalizeEmail(values.correo),
      requestVersion = version.current;
    void emailTask.run(async () => {
      const result = await mutate<{ mensaje: string; reenviar_en: number }>(
        "/auth/registro/correo/enviar",
        { correo },
      );
      if (requestVersion !== version.current) return;
      setValues((previous) => ({ ...previous, correo }));
      setEmailState("sent");
      setCode("");
      setCooldown(result.reenviar_en);
      emailTask.setNotice(result.mensaje);
    });
  }
  function verifyCode(value: string) {
    const correo = normalizeEmail(values.correo),
      requestVersion = version.current;
    void emailTask.run(async () => {
      const result = await mutate<{ correo: string }>(
        "/auth/registro/correo/verificar",
        { correo, codigo: value },
      );
      if (requestVersion !== version.current) return;
      setValues((previous) => ({ ...previous, correo: result.correo }));
      setEmailState("verified");
      setCode("");
      emailTask.setNotice(
        "Correo verificado. Puede continuar con la solicitud.",
      );
    });
  }
  function editEmail() {
    void emailTask.run(async () => {
      await mutate("/auth/registro/correo/editar");
      version.current++;
      setEmailState("idle");
      setCode("");
      setCooldown(0);
      emailTask.setNotice(
        "Puede editar la dirección. El nuevo correo también deberá verificarse.",
      );
    });
  }

  if (submitted)
    return (
      <AuthFrame
        step="SOLICITUD RECIBIDA"
        title="Revise su correo"
        description="Su correo está verificado y su solicitud está pendiente de revisión administrativa."
      >
        <div className="auth-step-note">
          <Mail size={24} />
          <span>
            {submitted.credencial_enviada
              ? "Le enviamos una contraseña temporal de un solo uso. En el primer ingreso deberá crear su contraseña definitiva."
              : "La solicitud se guardó, pero no se pudo entregar la contraseña temporal. Use Recuperar acceso para establecer su contraseña."}
          </span>
        </div>
        <p className="auth-help">
          El acceso a los módulos seguirá bloqueado hasta la autorización del
          administrador y la confirmación de Google Authenticator.
        </p>
        <button
          className="btn auth-submit"
          onClick={() =>
            navigate(submitted.credencial_enviada ? "/login" : "/recuperar", {
              state: { correo: values.correo },
            })
          }
        >
          {submitted.credencial_enviada
            ? "Ir al primer inicio de sesión"
            : "Recuperar acceso"}
        </button>
      </AuthFrame>
    );

  return (
    <AuthFrame
      step="SOLICITUD DE ACCESO"
      title="Crear una cuenta"
      description="Complete sus datos y verifique el correo aquí mismo. Recibirá una contraseña temporal para su primer ingreso."
    >
      <Status {...task} />
      <Form
        busy={task.busy}
        onSubmit={() => {
          setTouched({
            cedula: true,
            nombres: true,
            apellidos: true,
            nombre_usuario: true,
            correo: true,
          });
          if (!ready) return;
          void task.run(async () =>
            setSubmitted(
              await mutate("/auth/registro", {
                ...values,
                nombres: normalizeName(values.nombres),
                apellidos: normalizeName(values.apellidos),
                nombre_usuario: normalizeUsername(values.nombre_usuario),
                correo: normalizeEmail(values.correo),
              }),
            ),
          );
        }}
      >
        <Field
          label="Cédula ecuatoriana"
          name="cedula"
          inputMode="numeric"
          autoComplete="off"
          pattern="[0-9]{10}"
          maxLength={10}
          required
          value={values.cedula}
          onChange={(e) =>
            change("cedula", e.target.value.replace(/[ -]/g, ""))
          }
          onBlur={() => blur("cedula")}
          error={shownError("cedula")}
          success={
            values.cedula.length === 10 && !errors.cedula
              ? "Cédula válida en su estructura y dígito verificador."
              : undefined
          }
          hint="La comprobación matemática no certifica oficialmente su identidad."
        />
        <div className="auth-two-col">
          <Field
            label="Nombres"
            name="nombres"
            autoComplete="given-name"
            maxLength={58}
            required
            value={values.nombres}
            onChange={(e) => change("nombres", e.target.value)}
            onBlur={() => blur("nombres")}
            error={shownError("nombres")}
          />
          <Field
            label="Apellidos"
            name="apellidos"
            autoComplete="family-name"
            maxLength={58}
            required
            value={values.apellidos}
            onChange={(e) => change("apellidos", e.target.value)}
            onBlur={() => blur("apellidos")}
            error={shownError("apellidos")}
          />
        </div>
        <Field
          label="Nombre de usuario"
          name="nombre_usuario"
          autoComplete="username"
          minLength={3}
          maxLength={64}
          required
          value={values.nombre_usuario}
          onChange={(e) => change("nombre_usuario", e.target.value)}
          onBlur={() => blur("nombre_usuario")}
          error={shownError("nombre_usuario")}
          hint="Letras sin tildes, números, puntos y guiones. Se normaliza a minúsculas."
        />
        <div className="auth-email-verification">
          <div className="auth-email-row">
            <Field
              label="Correo electrónico"
              name="correo"
              type="email"
              autoComplete="email"
              required
              maxLength={254}
              value={values.correo}
              readOnly={emailState === "verified"}
              disabled={emailTask.busy}
              onChange={(e) => change("correo", e.target.value)}
              onBlur={() => blur("correo")}
              error={shownError("correo")}
              success={
                emailState === "verified"
                  ? "Correo verificado y protegido frente a cambios accidentales."
                  : undefined
              }
            />
            <div className="auth-email-actions">
              <button
                type="button"
                className="btn-secondary"
                disabled={
                  emailTask.busy ||
                  (emailState !== "verified" &&
                    (!!errors.correo || cooldown > 0))
                }
                onClick={emailState === "verified" ? editEmail : sendCode}
              >
                {emailState === "verified"
                  ? "Editar correo"
                  : cooldown > 0
                    ? `Reenviar (${cooldown}s)`
                    : emailState === "sent"
                      ? "Reenviar código"
                      : "Verificar correo"}
              </button>
            </div>
          </div>
          {emailState === "sent" && (
            <div className="auth-inline-verification">
              <Field
                label="Código de verificación del correo"
                name="codigo_correo"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={code}
                disabled={emailTask.busy}
                onChange={(e) => {
                  const value = e.target.value.replace(/\D/g, "").slice(0, 6);
                  setCode(value);
                  if (value.length === 6 && !emailTask.busy) verifyCode(value);
                }}
                hint="Al completar los seis dígitos se verificará automáticamente. No es el código de Google Authenticator."
              />
              <button
                type="button"
                className="auth-text-button"
                disabled={emailTask.busy || code.length !== 6}
                onClick={() => verifyCode(code)}
              >
                {emailTask.busy ? "Verificando…" : "Confirmar código"}
              </button>
            </div>
          )}
          {emailState === "verified" && (
            <div className="auth-email-confirmed">
              <CheckCircle2 size={17} />
              <span>Dirección confirmada</span>
            </div>
          )}
          <Status {...emailTask} />
        </div>
        <div className="auth-step-note">
          <Mail size={20} />
          <span>
            No necesita crear una contraseña en este formulario. Le enviaremos
            una temporal; la definitiva se crea en el primer ingreso.
          </span>
        </div>
        <Submit busy={task.busy} disabled={!ready || emailTask.busy}>
          Enviar solicitud de cuenta
        </Submit>
        {!ready && (
          <p className="auth-help">
            Complete los datos válidos y verifique el correo para habilitar el
            envío.
          </p>
        )}
      </Form>
      <div className="auth-links">
        <Link to="/login">Ya tengo una cuenta</Link>
      </div>
    </AuthFrame>
  );
}
