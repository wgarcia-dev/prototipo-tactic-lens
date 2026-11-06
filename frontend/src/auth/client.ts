/** Same-origin cookies and an in-memory CSRF token. No credentials in storage. */
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

let csrfRequest: Promise<string> | null = null;

async function csrf(): Promise<string> {
  if (!csrfRequest) {
    csrfRequest = fetch("/api/auth/csrf", {
      credentials: "same-origin",
      cache: "no-store",
    })
      .then(async (response) => {
        if (!response.ok)
          throw new ApiError(
            response.status,
            "No se pudo preparar una conexión segura.",
          );
        return (await response.json()).csrf_token as string;
      })
      .catch((error) => {
        csrfRequest = null;
        throw error;
      });
  }
  return csrfRequest;
}

export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers);
  if (!["GET", "HEAD", "OPTIONS"].includes(method))
    headers.set("X-CSRF-Token", await csrf());
  const response = await fetch("/api" + path, {
    ...options,
    method,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) {
    let message = `No se pudo completar la solicitud (HTTP ${response.status}).`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (Array.isArray(body.detail))
        message = body.detail
          .map((e: { msg: string }) => e.msg.replace(/^Value error, /, ""))
          .join(". ");
    } catch {
      /* Proxy failures can return plain text. */
    }
    if (response.status === 401 && !path.startsWith("/auth/"))
      window.dispatchEvent(new Event("tacticlens:session-expired"));
    if (response.status === 403 && message.includes("Recarg"))
      csrfRequest = null;
    throw new ApiError(response.status, message);
  }
  return response.json();
}

export function mutate<T>(
  path: string,
  data: unknown = {},
  method = "POST",
): Promise<T> {
  return api<T>(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}
