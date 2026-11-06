import type { ReactNode } from "react";
import { useAuth } from "./context";

/** Visual guard; the API independently checks the administrator role. */
export function AdminOnly({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  if (session?.usuario.rol !== "administrador") {
    return (
      <section className="panel auth-section" role="alert">
        <h1>Acceso restringido</h1>
        <p>Esta operación requiere un administrador de seguridad.</p>
      </section>
    );
  }
  return children;
}
