import { useEffect, useState } from "react";
import { api, ApiError } from "./client";
import { PasswordField } from "./components";

type Assessment = {
  porcentaje: number;
  longitud_valida: boolean;
  no_comun: boolean;
  aceptable: boolean;
  no_reutiliza_temporal: boolean;
};

/** Uses the same estimator and account data as final server-side validation. */
export function PasswordCreationFields({
  onValidityChange,
  passwordName = "password",
  token,
}: {
  onValidityChange: (valid: boolean) => void;
  passwordName?: string;
  token?: string;
}) {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [result, setResult] = useState<{
    value: string;
    assessment: Assessment;
  } | null>(null);
  const [error, setError] = useState("");
  const assessment = result?.value === password ? result.assessment : null;
  const checking = password.length > 0 && !assessment && !error;
  const ready =
    !!assessment?.aceptable && password === confirmation && !!confirmation;
  useEffect(() => {
    onValidityChange(ready);
  }, [ready, onValidityChange]);
  useEffect(() => {
    setError("");
    if (!password) {
      setResult(null);
      return;
    }
    let active = true;
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      void api<Assessment>("/auth/password/fortaleza", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password, ...(token ? { token } : {}) }),
        signal: controller.signal,
      })
        .then((value) => {
          if (active) setResult({ value: password, assessment: value });
        })
        .catch((e) => {
          if (active && !controller.signal.aborted)
            setError(
              e instanceof ApiError
                ? e.message
                : "No se pudo medir la fortaleza. Revise la conexión e intente nuevamente.",
            );
        });
    }, 450);
    return () => {
      active = false;
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [password, token]);
  return (
    <div className="auth-password-creation">
      <div className="auth-strength-row">
        <PasswordField
          label="Nueva contraseña"
          name={passwordName}
          autoComplete="new-password"
          minLength={12}
          value={password}
          onChange={(e) => {
            onValidityChange(false);
            setPassword(e.target.value);
          }}
        />
        <output
          className={
            "auth-strength-score " + (assessment?.aceptable ? "strong" : "")
          }
          aria-live="polite"
          aria-label="Fortaleza estimada de la contraseña"
        >
          {checking ? "…" : `${assessment?.porcentaje ?? 0}%`}
        </output>
      </div>
      <div
        className="auth-strength-track"
        role="progressbar"
        aria-label="Fortaleza estimada"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={assessment?.porcentaje ?? 0}
        aria-valuetext={
          checking ? "Calculando" : `${assessment?.porcentaje ?? 0} por ciento`
        }
      >
        <span
          className={assessment?.aceptable ? "strong" : ""}
          style={{ width: `${assessment?.porcentaje ?? 0}%` }}
        />
      </div>
      <ul className="auth-password-rules">
        <li
          className={
            password.length >= 12 && password.length <= 128 ? "met" : ""
          }
        >
          Entre 12 y 128 caracteres.
        </li>
        <li className={assessment?.aceptable ? "met" : ""}>
          Al menos 75% de fortaleza estimada; sin patrones comunes ni datos
          personales.
        </li>
      </ul>
      <p className="auth-help">
        El porcentaje es una estimación, no una garantía. Puede pegar una
        contraseña de su gestor o usar varias palabras poco relacionadas.
      </p>
      {error && (
        <p role="alert" className="auth-field-error">
          {error}
        </p>
      )}
      {assessment?.no_reutiliza_temporal === false && <p role="alert" className="auth-field-error">Elija una contraseña diferente de la temporal que recibió por correo.</p>}
      <PasswordField
        label="Confirmar nueva contraseña"
        name="confirmacion"
        autoComplete="new-password"
        minLength={12}
        value={confirmation}
        onChange={(e) => {
          onValidityChange(false);
          setConfirmation(e.target.value);
        }}
      />
      {confirmation && (
        <p
          className={
            password === confirmation
              ? "auth-field-success"
              : "auth-field-error"
          }
          role="status"
        >
          {password === confirmation
            ? "Las contraseñas coinciden."
            : "Las contraseñas todavía no coinciden."}
        </p>
      )}
    </div>
  );
}
