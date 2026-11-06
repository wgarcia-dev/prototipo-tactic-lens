import { useState } from "react";
import { useAuth } from "./context";
import { mutate } from "./client";
import {
  AuthFrame,
  Form,
  Status,
  Submit,
  formData,
  useTask,
} from "./components";
import { PasswordCreationFields } from "./PasswordCreationFields";

export function InitialPasswordPage() {
  const auth = useAuth(),
    task = useTask();
  const [ready, setReady] = useState(false);
  return (
    <AuthFrame
      step="PRIMER INGRESO / CONTRASEÑA DEFINITIVA"
      title="Cree su contraseña"
      description="La contraseña temporal ya se consumió. Elija una contraseña definitiva con fortaleza estimada de al menos 75%."
    >
      <Status {...task} />
      <Form
        busy={task.busy}
        onSubmit={(e) => {
          if (!ready) return;
          const data = formData(e.currentTarget);
          void task.run(async () => {
            await mutate("/auth/password/inicial", data);
            await auth.refresh();
          });
        }}
      >
        <PasswordCreationFields onValidityChange={setReady} />
        <Submit busy={task.busy} disabled={!ready}>
          Guardar contraseña y continuar
        </Submit>
      </Form>
      <p className="auth-help">
        Este paso no omite la aprobación administrativa ni Google Authenticator.
        Si este acceso temporal caduca, utilice Recuperar acceso.
      </p>
      <button
        className="auth-text-button"
        onClick={() => void task.run(auth.logout)}
      >
        Cancelar y volver al inicio de sesión
      </button>
    </AuthFrame>
  );
}
