import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { api, ApiError, mutate } from "./client";

export type User = {
  id_usuario: string;
  nombres: string;
  apellidos: string;
  nombre_usuario: string;
  correo: string;
  rol: "administrador" | "analista";
};
export type AuthSession = {
  etapa:
    | "correo"
    | "aprobacion"
    | "crear_password"
    | "configurar_mfa"
    | "mfa"
    | "completa";
  usuario: User;
  codigos_disponibles?: number;
};
type AuthContextValue = {
  session: AuthSession | null;
  loading: boolean;
  error: string;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
  recoveryCodes: string[];
  showRecoveryCodes: (codes: string[]) => void;
};
const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<AuthSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [recoveryCodes, showRecoveryCodes] = useState<string[]>([]);
  const refresh = useCallback(async () => {
    try {
      setSession(await api<AuthSession>("/auth/me"));
      setError("");
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setSession(null);
        setError("");
      } else
        setError(
          "No se pudo conectar con TacticLens. Compruebe que el backend esté iniciado.",
        );
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    void refresh();
    const expired = () => {
      showRecoveryCodes([]);
      void refresh();
    };
    window.addEventListener("tacticlens:session-expired", expired);
    return () =>
      window.removeEventListener("tacticlens:session-expired", expired);
  }, [refresh]);
  useEffect(() => {
    if (session?.etapa !== "completa") return;
    let lastInteraction = 0;
    const activity = () => { lastInteraction = Date.now(); };
    const heartbeat = window.setInterval(() => {
      if (document.visibilityState === "visible" && Date.now() - lastInteraction < 60000)
        void mutate("/auth/actividad").catch(() => {});
    }, 30000);
    for (const event of ["pointerdown", "keydown", "scroll", "pointermove"])
      window.addEventListener(event, activity, {passive:true});
    return () => {
      window.clearInterval(heartbeat);
      for (const event of ["pointerdown", "keydown", "scroll", "pointermove"])
        window.removeEventListener(event, activity);
    };
  }, [session?.etapa, refresh]);
  const logout = useCallback(async () => {
    try {
      await mutate("/auth/logout");
    } finally {
      showRecoveryCodes([]);
      setSession(null);
      await refresh();
    }
  }, [refresh]);
  return (
    <AuthContext.Provider
      value={{
        session,
        loading,
        error,
        refresh,
        logout,
        recoveryCodes,
        showRecoveryCodes,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("AuthProvider requerido");
  return value;
}
