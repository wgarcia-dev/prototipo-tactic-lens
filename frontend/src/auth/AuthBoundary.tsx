import { useEffect, useState, type ReactNode } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { Mail, Smartphone, KeyRound, CheckCircle2 } from "lucide-react";
import { mutate } from "./client";
import { useAuth } from "./context";
import { RegistrationPage } from "./RegistrationPage";
import { InitialPasswordPage } from "./InitialPasswordPage";
import { PasswordCreationFields } from "./PasswordCreationFields";
import {
  AuthFrame,
  Field,
  Form,
  PasswordField,
  Status,
  Submit,
  formData,
  useTask,
} from "./components";

export function AuthBoundary({ children }: { children: ReactNode }) {
  const auth = useAuth();
  const location = useLocation();
  if (auth.loading)
    return (
      <AuthFrame
        step="CONEXIÓN SEGURA"
        title="Preparando su acceso"
        description="Comprobando la sesión con TacticLens…"
      >
        <div className="auth-loading" role="status">
          Espere un momento.
        </div>
      </AuthFrame>
    );
  if (auth.error)
    return (
      <AuthFrame
        step="CONEXIÓN"
        title="No se pudo conectar"
        description={auth.error}
      >
        <button className="btn auth-submit" onClick={() => void auth.refresh()}>
          Volver a intentar
        </button>
      </AuthFrame>
    );
  if (auth.recoveryCodes.length) return <RecoveryCodes />;
  // Password-reset links remain usable even when another tab already has a session.
  if (location.pathname === "/recuperar") return <PasswordRecovery />;
  if (!auth.session || auth.session.etapa !== "completa")
    return <Authentication />;
  if (
    ["/login", "/registro", "/verificar-correo", "/mfa"].includes(
      location.pathname,
    )
  )
    return <Navigate to="/" replace />;
  return children;
}

function Authentication() {
  const { session } = useAuth();
  const { pathname } = useLocation();
  if (session?.etapa === "correo")
    return <VerifyEmail initialEmail={session.usuario.correo} />;
  if (session?.etapa === "aprobacion") return <PendingApproval />;
  if (session?.etapa === "crear_password") return <InitialPasswordPage />;
  if (session?.etapa === "configurar_mfa") return <MfaSetup />;
  if (session?.etapa === "mfa") return <MfaChallenge />;
  if (pathname === "/registro") return <RegistrationPage />;
  if (pathname === "/verificar-correo") return <VerifyEmail />;
  return <Login />;
}

function Login() {
  const auth = useAuth(),
    task = useTask(),
    location = useLocation();
  const initialEmail =
    (location.state as { correo?: string } | null)?.correo || "";
  return (
    <AuthFrame
      step="01 / IDENTIFICACIÓN"
      title="Iniciar sesión"
      description="Use su correo y contraseña. En el primer ingreso utilice la contraseña temporal recibida; deberá crear la definitiva antes de continuar."
    >
      <Status {...task} />
      <Form
        busy={task.busy}
        onSubmit={(e) => {
          const data = formData(e.currentTarget);
          void task.run(async () => {
            await mutate("/auth/login", data);
            await auth.refresh();
          });
        }}
      >
        <Field
          label="Correo electrónico"
          name="correo"
          type="email"
          autoComplete="username"
          required
          maxLength={254}
          defaultValue={initialEmail}
        />
        <PasswordField name="password" autoComplete="current-password" />
        <Submit busy={task.busy}>Continuar</Submit>
      </Form>
      <div className="auth-links">
        <Link to="/recuperar">Olvidé mi contraseña</Link>
        <Link to="/registro">Solicitar una cuenta</Link>
        <Link to="/verificar-correo">Verificar mi correo</Link>
      </div>
    </AuthFrame>
  );
}

function VerifyEmail({ initialEmail }: { initialEmail?: string }) {
  const task = useTask(),
    auth = useAuth(),
    location = useLocation(),
    navigate = useNavigate();
  const [correo, setCorreo] = useState(
    initialEmail ||
      (location.state as { correo?: string } | null)?.correo ||
      "",
  );
  const [verified, setVerified] = useState(false);
  return (
    <AuthFrame
      step="02 / CORREO ELECTRÓNICO"
      title={verified ? "Correo verificado" : "Verifique su correo"}
      description="Este código llega a su correo electrónico. Es diferente del código de Google Authenticator."
    >
      <div className="auth-step-note">
        <Mail size={21} />
        <span>
          Busque un mensaje de TacticLens. El código caduca en cinco minutos.
        </span>
      </div>
      <Status {...task} />
      {verified ? (
        <>
          <p className="auth-help">
            La cuenta también debe ser autorizada por un administrador. Después
            podrá configurar su segundo factor.
          </p>
          <button
            className="btn auth-submit"
            onClick={() => {
              navigate("/login", { state: { correo } });
              void auth.refresh();
            }}
          >
            Continuar
          </button>
        </>
      ) : (
        <>
          <Form
            busy={task.busy}
            onSubmit={(e) => {
              const data = formData(e.currentTarget);
              void task.run(async () => {
                await mutate("/auth/correo/verificar", data);
                setVerified(true);
              });
            }}
          >
            <Field
              label="Correo electrónico"
              name="correo"
              type="email"
              autoComplete="email"
              required
              value={correo}
              onChange={(e) => setCorreo(e.target.value)}
            />
            <Field
              label="Código recibido por correo"
              name="codigo"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              minLength={6}
              maxLength={6}
              required
            />
            <Submit busy={task.busy}>Verificar correo electrónico</Submit>
          </Form>
          <button
            className="btn-secondary auth-submit"
            disabled={task.busy || !correo}
            onClick={() =>
              void task.run(async () => {
                const result = await mutate<{ mensaje: string }>(
                  "/auth/correo/reenviar",
                  { correo },
                );
                task.setNotice(result.mensaje);
              })
            }
          >
            Solicitar otro código
          </button>
          <p className="auth-help">
            Espere al menos un minuto entre envíos. Un código nuevo invalida el
            anterior.
          </p>
        </>
      )}
      <div className="auth-links">
        <Link
          to="/login"
          onClick={() => {
            if (auth.session) void auth.logout();
          }}
        >
          Volver al inicio de sesión
        </Link>
      </div>
    </AuthFrame>
  );
}

function PendingApproval() {
  const auth = useAuth(),
    task = useTask();
  return (
    <AuthFrame
      step="AUTORIZACIÓN ADMINISTRATIVA"
      title="Su cuenta está pendiente"
      description="Su correo ya está verificado. Un administrador de seguridad debe autorizar su acceso antes de configurar Google Authenticator."
    >
      <div className="auth-step-note">
        <CheckCircle2 size={22} />
        <span>Correo verificado. Todavía no hay acceso a los módulos.</span>
      </div>
      <Status {...task} />
      <button
        className="btn auth-submit"
        disabled={task.busy}
        onClick={() => void task.run(auth.refresh)}
      >
        Comprobar autorización
      </button>
      <button
        className="btn-secondary auth-submit"
        onClick={() => void task.run(auth.logout)}
      >
        Cerrar sesión
      </button>
      <p className="auth-help">
        Por seguridad, este acceso temporal caduca. Puede volver a iniciar
        sesión para consultar su estado.
      </p>
    </AuthFrame>
  );
}

function MfaSetup() {
  const auth = useAuth(),
    task = useTask();
  const [setup, setSetup] = useState<{
    clave_manual: string;
    qr: string;
  } | null>(null);
  return (
    <AuthFrame
      step="03 / GOOGLE AUTHENTICATOR"
      title="Vincule su autenticador"
      description="Abra Google Authenticator u otra aplicación TOTP. Añada una cuenta y escanee el código QR."
    >
      <div className="auth-step-note">
        <Smartphone size={23} />
        <span>
          Este código se genera en su teléfono y cambia cada treinta segundos.
        </span>
      </div>
      <Status {...task} />
      {!setup ? (
        <button
          className="btn auth-submit"
          disabled={task.busy}
          onClick={() =>
            void task.run(async () =>
              setSetup(await mutate("/auth/mfa/configuracion")),
            )
          }
        >
          Preparar código QR
        </button>
      ) : (
        <>
          <div className="auth-qr">
            <img
              src={setup.qr}
              alt="Código QR para vincular Google Authenticator con su cuenta de TacticLens"
              width={224}
              height={224}
            />
          </div>
          <details className="auth-manual">
            <summary>Configurar con clave manual</summary>
            <p>Seleccione una cuenta basada en tiempo. Emisor: TacticLens.</p>
            <code>{setup.clave_manual}</code>
          </details>
          <Form
            busy={task.busy}
            onSubmit={(e) => {
              const data = formData(e.currentTarget);
              void task.run(async () => {
                const result = await mutate<{ codigos_recuperacion: string[] }>(
                  "/auth/mfa/confirmar",
                  data,
                );
                setSetup(null);
                auth.showRecoveryCodes(result.codigos_recuperacion);
                await auth.refresh();
              });
            }}
          >
            <Field
              label="Código de Google Authenticator"
              name="codigo"
              autoComplete="one-time-code"
              inputMode="numeric"
              pattern="[0-9]{6}"
              minLength={6}
              maxLength={6}
              required
              hint="Active la hora automática en el teléfono. La vinculación solo termina al confirmar un código válido."
            />
            <Submit busy={task.busy}>Confirmar y activar segundo factor</Submit>
          </Form>
        </>
      )}
      <button
        className="auth-text-button"
        onClick={() => void task.run(auth.logout)}
      >
        Cerrar sesión
      </button>
    </AuthFrame>
  );
}

function MfaChallenge() {
  const auth = useAuth(),
    task = useTask();
  const [recovery, setRecovery] = useState(false);
  return (
    <AuthFrame
      step="02 / SEGUNDO FACTOR"
      title={
        recovery
          ? "Usar un código de recuperación"
          : "Verifique Google Authenticator"
      }
      description={
        recovery
          ? "Introduzca uno de los códigos que guardó al activar MFA. Se invalidará al usarlo."
          : "La contraseña es correcta. Introduzca el código actual de la aplicación autenticadora para completar el acceso."
      }
    >
      <div className="auth-step-note">
        {recovery ? <KeyRound size={23} /> : <Smartphone size={23} />}
        <span>
          {recovery
            ? "Los códigos de recuperación se muestran una sola vez."
            : "El código se consulta en su teléfono; no se envía por correo."}
        </span>
      </div>
      <Status {...task} />
      <Form
        busy={task.busy}
        onSubmit={(e) => {
          const data = formData(e.currentTarget);
          void task.run(async () => {
            await mutate("/auth/mfa/verificar", {
              ...data,
              recuperacion: recovery,
            });
            await auth.refresh();
          });
        }}
      >
        <Field
          key={String(recovery)}
          label={
            recovery
              ? "Código de recuperación"
              : "Código de Google Authenticator"
          }
          name="codigo"
          required
          autoComplete="one-time-code"
          inputMode={recovery ? "text" : "numeric"}
          minLength={6}
          maxLength={recovery ? 64 : 6}
        />
        <Submit busy={task.busy}>Verificar e ingresar</Submit>
      </Form>
      <button
        className="auth-text-button"
        onClick={() => setRecovery((v) => !v)}
      >
        {recovery
          ? "Usar Google Authenticator"
          : "Perdí mi teléfono: usar código de recuperación"}
      </button>
      <p className="auth-help">
        Si tampoco tiene códigos de recuperación, contacte al administrador para
        una verificación de identidad. Un correo por sí solo no restablece MFA.
      </p>
      <button
        className="auth-text-button"
        onClick={() => void task.run(auth.logout)}
      >
        Cancelar y cerrar sesión
      </button>
    </AuthFrame>
  );
}

function RecoveryCodes() {
  const auth = useAuth(),
    task = useTask(),
    navigate = useNavigate();
  function download() {
    const url = URL.createObjectURL(
      new Blob(
        [
          "TacticLens · Códigos de recuperación\nGuárdelos fuera del dispositivo autenticador. Cada código funciona una sola vez.\n\n" +
            auth.recoveryCodes.join("\n"),
        ],
        { type: "text/plain;charset=utf-8" },
      ),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = "tacticlens-codigos-recuperacion.txt";
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <AuthFrame
      step="RESPALDO DEL SEGUNDO FACTOR"
      title="Guarde sus códigos"
      description="Estos diez códigos solo se muestran ahora. Guárdelos en su gestor de contraseñas o en un lugar seguro fuera de su teléfono."
    >
      <div className="auth-recovery-grid">
        {auth.recoveryCodes.map((code) => (
          <code key={code}>{code}</code>
        ))}
      </div>
      <Status {...task} />
      <div className="auth-two-col">
        <button className="btn-secondary" onClick={download}>
          Descargar códigos
        </button>
        <button
          className="btn-secondary"
          onClick={() =>
            void task.run(async () => {
              await navigator.clipboard.writeText(
                auth.recoveryCodes.join("\n"),
              );
              task.setNotice("Códigos copiados. Guárdelos de forma segura.");
            })
          }
        >
          Copiar códigos
        </button>
      </div>
      <button
        className="btn auth-submit"
        onClick={() => {
          auth.showRecoveryCodes([]);
          navigate("/", { replace: true });
        }}
      >
        Ya los guardé: continuar
      </button>
    </AuthFrame>
  );
}

function PasswordRecovery() {
  const task = useTask(),
    auth = useAuth();
  const [token] = useState(
    () => new URLSearchParams(window.location.hash.slice(1)).get("token") || "",
  );
  const [done, setDone] = useState(false);
  const [passwordReady, setPasswordReady] = useState(false);
  useEffect(() => {
    if (token)
      window.history.replaceState(
        window.history.state,
        "",
        window.location.pathname,
      );
  }, [token]);
  return (
    <AuthFrame
      step="RECUPERACIÓN DE CONTRASEÑA"
      title={token ? "Establecer nueva contraseña" : "Recuperar acceso"}
      description="La recuperación cambia su contraseña y cierra las sesiones anteriores. Google Authenticator sigue siendo obligatorio."
    >
      <Status {...task} />
      {done ? (
        <div className="auth-message" role="status">
          Contraseña actualizada. Inicie sesión con su nueva contraseña y su
          segundo factor.
        </div>
      ) : (
        <Form
          busy={task.busy}
          onSubmit={(e) => {
            if (token && !passwordReady) return;
            const data = formData(e.currentTarget);
            void task.run(async () => {
              if (token) {
                await mutate("/auth/password/restablecer", { ...data, token });
                setDone(true);
                await auth.refresh();
              } else {
                const result = await mutate<{ mensaje: string }>(
                  "/auth/password/solicitar",
                  data,
                );
                task.setNotice(result.mensaje);
              }
            });
          }}
        >
          {token ? (
            <PasswordCreationFields
              token={token}
              onValidityChange={setPasswordReady}
            />
          ) : (
            <Field
              label="Correo electrónico"
              name="correo"
              type="email"
              autoComplete="email"
              required
            />
          )}
          <Submit busy={task.busy} disabled={!!token && !passwordReady}>
            {token
              ? "Restablecer contraseña"
              : "Solicitar enlace de recuperación"}
          </Submit>
        </Form>
      )}
      <div className="auth-links">
        <Link to="/login">Volver al inicio de sesión</Link>
      </div>
    </AuthFrame>
  );
}
