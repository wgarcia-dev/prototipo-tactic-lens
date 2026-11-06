import { Link } from "react-router-dom";
import { useState } from "react";
import { ShieldCheck, LogOut, Users } from "lucide-react";
import { mutate } from "./client";
import { useAuth } from "./context";
import {
  Form,
  ReauthFields,
  Status,
  Submit,
  reauthData,
  useTask,
} from "./components";
import { PasswordCreationFields } from "./PasswordCreationFields";

export function SessionControls() {
  const { session, logout } = useAuth(),
    task = useTask();
  return (
    <div className="auth-session-controls">
      <p>{session?.usuario.nombres}</p>
      <small>
        {session?.usuario.rol === "administrador"
          ? "Administrador de seguridad"
          : "Analista de seguridad"}
      </small>
      <Link to="/seguridad">
        <ShieldCheck size={15} />
        Seguridad de mi cuenta
      </Link>
      {session?.usuario.rol === "administrador" && (
        <Link to="/usuarios">
          <Users size={15} />
          Administrar usuarios
        </Link>
      )}
      <button disabled={task.busy} onClick={() => void task.run(logout)}>
        <LogOut size={15} />
        Cerrar sesión
      </button>
      <Status {...task} />
    </div>
  );
}

function ReplaceAuthenticator() {
  const auth = useAuth(),
    task = useTask();
  return (
    <section className="panel auth-section">
      <h2>Reemplazar Google Authenticator</h2>
      <p className="muted">
        Para cambiar de teléfono, verifique su contraseña y un código actual o
        de recuperación. Se cerrarán sus sesiones y deberá confirmar la nueva
        vinculación antes de volver a los módulos.
      </p>
      <Status {...task} />
      <Form
        busy={task.busy}
        onSubmit={(e) => {
          const data = reauthData(e.currentTarget);
          void task.run(async () => {
            await mutate("/auth/mfa/reemplazar", data);
            await auth.refresh();
          });
        }}
      >
        <ReauthFields />
        <label className="auth-checkbox">
          <input type="checkbox" required />
          Entiendo que debo volver a escanear y confirmar el nuevo autenticador.
        </label>
        <Submit busy={task.busy}>Verificar e iniciar reemplazo</Submit>
      </Form>
    </section>
  );
}

export function SecurityPage() {
  const [passwordReady, setPasswordReady] = useState(false);
  const auth = useAuth(),
    password = useTask(),
    recovery = useTask(),
    sessions = useTask();
  return (
    <>
      <header className="auth-page-header">
        <p className="auth-kicker">MI CUENTA</p>
        <h1>Seguridad de la cuenta</h1>
        <p className="muted">
          Proteja su acceso y mantenga una alternativa segura si pierde su
          teléfono.
        </p>
      </header>
      <section className="panel auth-profile">
        <ShieldCheck size={32} className="accent" />
        <div>
          <h2>
            {auth.session?.usuario.nombres} {auth.session?.usuario.apellidos}
          </h2>
          <p className="muted">{auth.session?.usuario.correo}</p>
        </div>
        <span className="badge">MFA ACTIVO</span>
      </section>
      <div className="auth-security-grid">
        <section className="panel auth-section">
          <h2>Códigos de recuperación</h2>
          <p className="muted">
            Tiene {auth.session?.codigos_disponibles ?? "—"} códigos
            disponibles. Al regenerarlos se invalidan todos los anteriores.
          </p>
          <Status {...recovery} />
          <Form
            busy={recovery.busy}
            onSubmit={(e) => {
              const form = e.currentTarget,
                data = reauthData(form);
              void recovery.run(async () => {
                const result = await mutate<{ codigos_recuperacion: string[] }>(
                  "/auth/mfa/codigos",
                  data,
                );
                form.reset();
                auth.showRecoveryCodes(result.codigos_recuperacion);
                await auth.refresh();
              });
            }}
          >
            <ReauthFields />
            <Submit busy={recovery.busy}>
              Regenerar códigos de recuperación
            </Submit>
          </Form>
        </section>
        <section className="panel auth-section">
          <h2>Cambiar contraseña</h2>
          <p className="muted">
            Se requiere contraseña actual y segundo factor. Al cambiarla se
            cerrarán todas sus sesiones.
          </p>
          <Status {...password} />
          <Form
            busy={password.busy}
            onSubmit={(e) => {
              if (!passwordReady) return;
              const form = e.currentTarget,
                data = reauthData(form);
              void password.run(async () => {
                await mutate("/auth/password/cambiar", data);
                form.reset();
                await auth.refresh();
              });
            }}
          >
            <ReauthFields />
            <PasswordCreationFields
              passwordName="nueva_password"
              onValidityChange={setPasswordReady}
            />
            <Submit busy={password.busy} disabled={!passwordReady}>
              Cambiar contraseña y cerrar sesiones
            </Submit>
          </Form>
        </section>
        <section className="panel auth-section">
          <h2>Cerrar todas las sesiones</h2>
          <p className="muted">
            Útil si dejó abierta su cuenta en otro equipo. También cerrará esta
            sesión.
          </p>
          <Status {...sessions} />
          <Form
            busy={sessions.busy}
            onSubmit={(e) => {
              const data = reauthData(e.currentTarget);
              void sessions.run(async () => {
                await mutate("/auth/sesiones/revocar", data);
                await auth.refresh();
              });
            }}
          >
            <ReauthFields />
            <Submit busy={sessions.busy}>Cerrar todas las sesiones</Submit>
          </Form>
        </section>
        <ReplaceAuthenticator />
        <section className="panel auth-section">
          <h2>Si perdió su teléfono</h2>
          <p className="muted">
            Inicie sesión con su contraseña y uno de sus códigos de
            recuperación. Si tampoco dispone de ellos, solicite al administrador
            una verificación de identidad por un canal independiente.
          </p>
          <p className="auth-help">
            Un correo electrónico no permite desactivar MFA. Un administrador no
            puede restablecer unilateralmente su propio segundo factor.
          </p>
        </section>
      </div>
    </>
  );
}
