import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, mutate } from "./client";
import { useAuth } from "./context";
import {
  Form,
  AuthenticatorField,
  ReauthFields,
  Status,
  Submit,
  reauthData,
  useTask,
} from "./components";

type Account = {
  id_usuario: string;
  nombres: string;
  apellidos: string;
  nombre_usuario: string;
  correo: string;
  activo: boolean;
  autorizacion: string;
  correo_verificado_en: string | null;
  rol: string;
  mfa_confirmado_en: string | null;
  rechazado_en: string | null;
  motivo_rechazo: string | null;
  password_cambio_obligatorio: boolean;
};
type Audit = {
  id_auditoria: string;
  tipo: string;
  fecha_evento: string;
  id_usuario: string | null;
};
type Role = { codigo: string; nombre: string };
const auditLabels: Record<string, string> = {
  cuenta_creada: "Cuenta creada",
  correo_verificado: "Correo verificado",
  cuenta_autorizada: "Cuenta autorizada",
  cuenta_rechazada: "Solicitud rechazada",
  password_temporal_emitida: "Credencial temporal emitida",
  password_definitiva_creada: "Contraseña definitiva creada",
  login_exitoso: "Inicio de sesión completo",
  login_fallido: "Acceso rechazado",
  mfa_configurado: "Autenticador vinculado",
  mfa_validado: "Segundo factor validado",
  mfa_rechazado: "Segundo factor rechazado",
  rol_cambiado: "Rol actualizado",
  cuenta_estado_actualizado: "Estado de cuenta actualizado",
  mfa_restablecido_administrativamente: "MFA restablecido por un administrador",
  logout: "Sesión cerrada",
  password_restablecida: "Contraseña restablecida",
  password_cambiada: "Contraseña cambiada",
  codigo_recuperacion_usado: "Código de recuperación utilizado",
};

export function AdminUsers() {
  const { session } = useAuth();
  if (session?.usuario.rol !== "administrador")
    return (
      <div className="panel auth-section">
        <h1>Acceso restringido</h1>
        <p>Esta sección requiere un administrador de seguridad.</p>
        <Link to="/">Volver al panel</Link>
      </div>
    );
  return <AdminWorkspace />;
}

function AdminWorkspace() {
  const [filter, setFilter] = useState("pendiente");
  const [decision, setDecision] = useState("aprobar");
  const generation = useRef(0);
  const [users, setUsers] = useState<Account[]>([]),
    [roles, setRoles] = useState<Role[]>([]),
    [audit, setAudit] = useState<Audit[]>([]);
  const [selected, setSelected] = useState<Account | null>(null),
    [page, setPage] = useState(0),
    [hasNext, setHasNext] = useState(false);
  const [loading, setLoading] = useState(true),
    [error, setError] = useState("");
  const { session } = useAuth(),
    task = useTask(),
    reset = useTask();
  const load = useCallback(async () => {
    const current = ++generation.current;
    setLoading(true);
    try {
      const [accounts, availableRoles, events] = await Promise.all([
        api<Account[]>(
          `/auth/admin/usuarios?limit=26&offset=${page * 25}${filter === "todos" ? "" : `&estado=${filter}`}`,
        ),
        api<Role[]>("/auth/admin/roles"),
        api<Audit[]>("/auth/admin/auditoria?limit=12"),
      ]);
      if (current !== generation.current) return;
      setUsers(accounts.slice(0, 25));
      setHasNext(accounts.length > 25);
      setRoles(availableRoles);
      setAudit(events);
      setError("");
      setSelected(
        (previous) =>
          accounts.find(
            (account) => account.id_usuario === previous?.id_usuario,
          ) || null,
      );
    } catch (e) {
      if (current === generation.current) setError((e as Error).message);
    } finally {
      if (current === generation.current) setLoading(false);
    }
  }, [page, filter]);
  useEffect(() => {
    setLoading(true);
    void load();
  }, [load]);
  useEffect(() => {
    setDecision("aprobar");
  }, [selected?.id_usuario, selected?.autorizacion]);
  const ownAccount = selected?.id_usuario === session?.usuario.id_usuario;
  return (
    <>
      <header className="auth-page-header">
        <p className="auth-kicker">ADMINISTRACIÓN DE SEGURIDAD</p>
        <h1>Usuarios y autorizaciones</h1>
        <p className="muted">
          Revise solicitudes, asigne roles y gestione cuentas con
          reautenticación.
        </p>
      </header>
      <Status error={error} />
      <Status {...task} />
      <div className="auth-request-filter">
        <label htmlFor="requests-filter">Mostrar cuentas</label>
        <select
          id="requests-filter"
          value={filter}
          onChange={(e) => {
            setFilter(e.target.value);
            setPage(0);
          }}
        >
          <option value="pendiente">Solicitudes pendientes</option>
          <option value="aprobado">Cuentas autorizadas</option>
          <option value="rechazado">Solicitudes rechazadas</option>
          <option value="todos">Todas las cuentas</option>
        </select>
      </div>
      <div className="auth-admin-grid">
        <section className="panel auth-section">
          <div className="auth-section-heading">
            <h2>Cuentas de la organización</h2>
            <button className="btn-secondary" onClick={() => void load()}>
              Actualizar
            </button>
          </div>
          {loading ? (
            <p role="status">Cargando cuentas…</p>
          ) : (
            <div className="auth-table-scroll">
              <table className="w-full text-sm">
                <thead>
                  <tr>
                    <th>Usuario</th>
                    <th>Estado</th>
                    <th>Verificaciones</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr
                      key={user.id_usuario}
                      className={
                        selected?.id_usuario === user.id_usuario
                          ? "auth-selected"
                          : ""
                      }
                    >
                      <td>
                        <button
                          className="auth-account-button"
                          onClick={() => setSelected(user)}
                          disabled={task.busy || reset.busy}
                          aria-pressed={
                            selected?.id_usuario === user.id_usuario
                          }
                        >
                          {user.nombres} {user.apellidos}
                          <small>{user.correo}</small>
                        </button>
                      </td>
                      <td>
                        <span
                          className={
                            "badge " +
                            (!user.activo
                              ? "error"
                              : user.autorizacion === "pendiente"
                                ? "warn"
                                : "")
                          }
                        >
                          {user.autorizacion === "rechazado"
                            ? "Rechazada"
                            : !user.activo
                              ? "Suspendida"
                              : user.autorizacion === "pendiente"
                                ? "Pendiente"
                                : "Autorizada"}
                        </span>
                        <small className="auth-table-sub">
                          {user.rol === "administrador"
                            ? "Administrador"
                            : "Analista"}
                        </small>
                      </td>
                      <td>
                        <small>
                          Correo:{" "}
                          {user.correo_verificado_en
                            ? "verificado"
                            : "pendiente"}
                          <br />
                          MFA: {user.mfa_confirmado_en ? "activo" : "pendiente"}
                        </small>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!users.length && (
                <p>
                  {filter === "pendiente"
                    ? "No hay solicitudes pendientes de revisión."
                    : "No hay cuentas en este filtro."}
                </p>
              )}
            </div>
          )}
          <nav className="pager" aria-label="Paginación de usuarios">
            <span className="muted">Página {page + 1}</span>
            <div className="flex gap-2">
              <button
                className="btn-secondary"
                disabled={loading || page === 0}
                onClick={() => setPage((p) => p - 1)}
              >
                Anterior
              </button>
              <button
                className="btn-secondary"
                disabled={loading || !hasNext}
                onClick={() => setPage((p) => p + 1)}
              >
                Siguiente
              </button>
            </div>
          </nav>
        </section>
        <section className="panel auth-section">
          <h2>{selected ? "Gestionar cuenta" : "Seleccione una cuenta"}</h2>
          {selected && (
            <>
              <p className="muted">{selected.correo}</p>
              {ownAccount ? (
                <p className="auth-message">
                  Otro administrador debe gestionar su rol, estado o
                  restablecimiento de MFA.
                </p>
              ) : (
                <>
                  {selected.autorizacion === "rechazado" && (
                    <div className="auth-message auth-error">
                      <strong>Solicitud rechazada</strong>
                      <p>{selected.motivo_rechazo}</p>
                    </div>
                  )}
                  <Form
                    key={`${selected.id_usuario}:${selected.rol}:${selected.activo}:${selected.autorizacion}`}
                    busy={task.busy}
                    onSubmit={(e) => {
                      const form = e.currentTarget,
                        data = reauthData(form);
                      void task.run(async () => {
                        await mutate(
                          "/auth/admin/usuarios/" + selected.id_usuario,
                          {
                            password: data.password,
                            codigo: data.codigo,
                            recuperacion: data.recuperacion,
                            rol: data.rol || selected.rol,
                            activo:
                              selected.autorizacion !== "aprobado"
                                ? decision === "aprobar"
                                : data.activo === "true",
                            aprobar:
                              selected.autorizacion !== "aprobado" &&
                              decision === "aprobar",
                            rechazar:
                              selected.autorizacion === "pendiente" &&
                              decision === "rechazar",
                            motivo_rechazo:
                              decision === "rechazar"
                                ? data.motivo_rechazo
                                : null,
                          },
                          "PATCH",
                        );
                        form.reset();
                        await load();
                        task.setNotice(
                          selected.autorizacion !== "aprobado"
                            ? decision === "rechazar"
                              ? "Solicitud rechazada. El usuario no tiene acceso a los módulos."
                              : "Solicitud aceptada. El usuario todavía debe completar su contraseña y MFA si están pendientes."
                            : "Cuenta actualizada. Se revocaron sus sesiones anteriores.",
                        );
                      });
                    }}
                  >
                    {selected.autorizacion !== "aprobado" && (
                      <fieldset className="auth-decision">
                        <legend>Decisión sobre la solicitud</legend>
                        <label className="auth-checkbox">
                          <input
                            type="radio"
                            name="decision"
                            value="aprobar"
                            checked={decision === "aprobar"}
                            onChange={() => setDecision("aprobar")}
                          />
                          Aceptar solicitud
                        </label>
                        {selected.autorizacion === "pendiente" && (
                          <label className="auth-checkbox">
                            <input
                              type="radio"
                              name="decision"
                              value="rechazar"
                              checked={decision === "rechazar"}
                              onChange={() => setDecision("rechazar")}
                            />
                            Rechazar solicitud
                          </label>
                        )}
                      </fieldset>
                    )}
                    <div className="auth-field">
                      <label htmlFor="account-role">Rol</label>
                      <select
                        id="account-role"
                        name="rol"
                        defaultValue={selected.rol}
                        disabled={
                          decision === "rechazar" &&
                          selected.autorizacion !== "aprobado"
                        }
                      >
                        {roles.map((role) => (
                          <option value={role.codigo} key={role.codigo}>
                            {role.nombre}
                          </option>
                        ))}
                      </select>
                    </div>
                    {selected.autorizacion === "aprobado" && (
                      <div className="auth-field">
                        <label htmlFor="account-status">Estado general</label>
                        <select
                          id="account-status"
                          name="activo"
                          defaultValue={String(selected.activo)}
                        >
                          <option value="true">Habilitada</option>
                          <option value="false">Suspendida</option>
                        </select>
                      </div>
                    )}
                    {decision === "rechazar" &&
                      selected.autorizacion === "pendiente" && (
                        <div className="auth-field">
                          <label htmlFor="reject-reason">
                            Motivo del rechazo
                          </label>
                          <textarea
                            id="reject-reason"
                            name="motivo_rechazo"
                            required
                            minLength={10}
                            maxLength={300}
                            placeholder="Explique el motivo sin incluir contraseñas, documentos ni datos sensibles."
                          />
                        </div>
                      )}
                    <p className="auth-help">
                      La autorización requiere correo verificado. MFA continúa
                      siendo obligatorio.
                    </p>
                    {selected.autorizacion === "pendiente" &&
                    decision === "aprobar" ? (
                      <AuthenticatorField />
                    ) : (
                      <ReauthFields />
                    )}
                    <Submit
                      busy={task.busy}
                      disabled={
                        decision === "aprobar" &&
                        selected.autorizacion !== "aprobado" &&
                        !selected.correo_verificado_en
                      }
                    >
                      {selected.autorizacion === "aprobado"
                        ? "Guardar cambios y revocar sesiones"
                        : decision === "rechazar"
                          ? "Rechazar solicitud"
                          : "Aceptar solicitud"}
                    </Submit>
                  </Form>
                  <details className="auth-danger-zone">
                    <summary>Restablecer Google Authenticator</summary>
                    <p>
                      Solo después de verificar la identidad por un canal
                      independiente y documentar el procedimiento. Esta acción
                      elimina la vinculación y los códigos de recuperación, y
                      cierra las sesiones del titular.
                    </p>
                    <Status {...reset} />
                    <Form
                      key={"reset-" + selected.id_usuario}
                      busy={reset.busy}
                      onSubmit={(e) => {
                        const form = e.currentTarget,
                          data = reauthData(form);
                        void reset.run(async () => {
                          await mutate(
                            "/auth/admin/usuarios/" +
                              selected.id_usuario +
                              "/mfa/restablecer",
                            data,
                          );
                          form.reset();
                          await load();
                          reset.setNotice(
                            "MFA restablecido. Se notificó al titular.",
                          );
                        });
                      }}
                    >
                      <div className="auth-field">
                        <label htmlFor="identity-reference">
                          Referencia del expediente de verificación
                        </label>
                        <textarea
                          id="identity-reference"
                          name="referencia_verificacion"
                          required
                          minLength={20}
                          maxLength={160}
                          placeholder="Referencia y procedimiento aplicado; no incluya documentos ni datos sensibles."
                        />
                      </div>
                      <label className="auth-checkbox">
                        <input type="checkbox" required />
                        Confirmo que verifiqué la identidad conforme al
                        procedimiento documentado.
                      </label>
                      <ReauthFields />
                      <Submit busy={reset.busy}>
                        Restablecer MFA y cerrar sesiones
                      </Submit>
                    </Form>
                  </details>
                </>
              )}
            </>
          )}
        </section>
      </div>
      <section className="panel auth-section auth-audit">
        <h2>Actividad reciente de seguridad</h2>
        <p className="muted">
          Registro de solo lectura. No contiene contraseñas, códigos ni
          secretos.
        </p>
        <div className="auth-table-scroll">
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th>Fecha</th>
                <th>Operación</th>
                <th>Usuario</th>
              </tr>
            </thead>
            <tbody>
              {audit.map((event) => (
                <tr key={event.id_auditoria}>
                  <td>
                    {new Date(event.fecha_evento).toLocaleString("es-EC")}
                  </td>
                  <td>
                    {auditLabels[event.tipo] || event.tipo.replaceAll("_", " ")}
                  </td>
                  <td>
                    <code>{event.id_usuario?.slice(0, 8) || "—"}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
