import {
  useId,
  useState,
  type FormEvent,
  type InputHTMLAttributes,
  type ReactNode,
} from "react";
import { Activity, ShieldCheck } from "lucide-react";
import "./auth.css";

export function Field({
  label,
  hint,
  error,
  success,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & {
  label: string;
  hint?: string;
  error?: string;
  success?: string;
}) {
  const id = useId();
  return (
    <div className="auth-field">
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        aria-describedby={
          [hint ? id + "-hint" : "", error || success ? id + "-feedback" : ""]
            .filter(Boolean)
            .join(" ") || undefined
        }
        aria-invalid={error ? true : undefined}
        {...props}
      />
      {hint && <small id={id + "-hint"}>{hint}</small>}
      {(error || success) && (
        <small
          id={id + "-feedback"}
          className={error ? "auth-field-error" : "auth-field-success"}
          role="status"
        >
          {error || success}
        </small>
      )}
    </div>
  );
}

export function PasswordField({
  label = "Contraseña",
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label?: string }) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="auth-password">
      <Field
        label={label}
        type={visible ? "text" : "password"}
        maxLength={128}
        required
        {...props}
      />
      <button
        type="button"
        onClick={() => setVisible((v) => !v)}
        aria-pressed={visible}
      >
        {visible ? "Ocultar" : "Mostrar"}
      </button>
    </div>
  );
}

export function Status({ error, notice }: { error?: string; notice?: string }) {
  return (
    <>
      {error && (
        <div className="auth-message auth-error" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <div className="auth-message" role="status">
          {notice}
        </div>
      )}
    </>
  );
}

export function useTask() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "No se pudo completar la operación.",
      );
    } finally {
      setBusy(false);
    }
  }
  return {
    busy,
    error,
    notice,
    run,
    setNotice,
    clear: () => {
      setError("");
      setNotice("");
    },
  };
}

export function Form({
  onSubmit,
  busy,
  children,
  className = "",
}: {
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  busy: boolean;
  children: ReactNode;
  className?: string;
}) {
  return (
    <form
      className={"auth-form " + className}
      onSubmit={(e) => {
        e.preventDefault();
        if (!busy) onSubmit(e);
      }}
      aria-busy={busy}
    >
      <fieldset disabled={busy}>{children}</fieldset>
    </form>
  );
}

export function Submit({
  busy,
  disabled = false,
  children,
}: {
  busy: boolean;
  disabled?: boolean;
  children: ReactNode;
}) {
  return (
    <button
      type="submit"
      className="btn auth-submit"
      disabled={busy || disabled}
    >
      {busy ? "Procesando…" : children}
    </button>
  );
}

export function AuthFrame({
  title,
  description,
  step,
  children,
}: {
  title: string;
  description: string;
  step: string;
  children: ReactNode;
}) {
  return (
    <main className="auth-layout">
      <aside className="auth-brand">
        <div className="auth-brand-name">
          <Activity size={30} />
          <span>
            TacticLens<small>OBSERVATORIO COWRIE</small>
          </span>
        </div>
        <div className="auth-brand-copy">
          <span className="auth-kicker">ACCESO AL OBSERVATORIO</span>
          <h1>
            La evidencia comienza
            <br />
            con un acceso seguro.
          </h1>
          <p>
            Sesiones, indicadores y comportamiento observado. Un espacio de
            trabajo para el equipo de seguridad.
          </p>
          <div className="auth-trust">
            <ShieldCheck size={20} />
            <span>Correo verificado · Cuenta autorizada · Segundo factor</span>
          </div>
        </div>
        <p className="auth-brand-footer">Prototipo académico · TacticLens</p>
      </aside>
      <section className="auth-content">
        <div className="auth-card">
          <p className="auth-kicker">{step}</p>
          <h2>{title}</h2>
          <p className="auth-description">{description}</p>
          {children}
        </div>
      </section>
    </main>
  );
}

export function AuthenticatorField() {
  return (
    <Field
      label="Tu código actual de Google Authenticator"
      name="codigo"
      required
      autoComplete="one-time-code"
      inputMode="numeric"
      pattern="[0-9]{6}"
      minLength={6}
      maxLength={6}
      hint="Usa el código de tu cuenta de administrador. Si acaba de utilizarse, espera el siguiente."
    />
  );
}

export function ReauthFields() {
  const [recovery, setRecovery] = useState(false);
  return (
    <>
      <PasswordField
        label="Contraseña actual"
        name="password"
        autoComplete="current-password"
      />
      <label className="auth-checkbox">
        <input
          type="checkbox"
          name="recuperacion"
          checked={recovery}
          onChange={(e) => setRecovery(e.target.checked)}
        />
        Usar un código de recuperación
      </label>
      <Field
        label={
          recovery
            ? "Código de recuperación"
            : "Código actual de Google Authenticator"
        }
        name="codigo"
        required
        autoComplete="one-time-code"
        inputMode={recovery ? "text" : "numeric"}
        minLength={6}
        maxLength={recovery ? 64 : 6}
        hint="Cada código se acepta una sola vez. Si acaba de usarlo, espere el siguiente intervalo."
      />
    </>
  );
}

export function formData(form: HTMLFormElement) {
  return Object.fromEntries(new FormData(form).entries()) as Record<
    string,
    string
  >;
}

export function reauthData(
  form: HTMLFormElement,
): Record<string, string | boolean> & { recuperacion: boolean } {
  const data = formData(form);
  return { ...data, recuperacion: data.recuperacion === "on" };
}
