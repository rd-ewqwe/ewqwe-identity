/**
 * API client for the Verifier App backend.
 *
 * All paths are relative to `/api/v1`, which maps to the credential verifier's
 * `web::scope("/api/v1")` scope.  Proxy configuration in `vite.config.ts`
 * forwards `/api/*` requests to `https://localhost:9443` during development.
 */

export const API_BASE = "/api/v1";

export interface ApiOptions extends Omit<RequestInit, "body"> {
  body?: unknown;
}

/**
 * Fetch a JSON endpoint.  Throws an `Error` with the server's `error` message
 * on non-2xx responses.  Returns `null` for 204 No Content.
 */
export async function apiFetch<T>(
  path: string,
  opts: ApiOptions = {},
): Promise<T> {
  const { body, ...rest } = opts;
  const headers: Record<string, string> = {};
  let serialised: string | undefined;

  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    serialised = JSON.stringify(body);
  }

  const res = await fetch(API_BASE + path, {
    ...rest,
    headers,
    body: serialised,
    credentials: "same-origin",
  });

  if (res.status === 204) return null as T;

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error((data as { error?: string })?.error ?? res.statusText);
  }
  return data as T;
}
