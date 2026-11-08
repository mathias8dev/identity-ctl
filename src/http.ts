import { getCACertificates, setDefaultCACertificates } from "node:tls";
import { VERSION } from "./version.js";

setDefaultCACertificates([...getCACertificates("default"), ...getCACertificates("system")]);

enum OAuthErrorCode {
  INVALID_REQUEST = "invalid_request", INVALID_CLIENT = "invalid_client", INVALID_GRANT = "invalid_grant",
  UNAUTHORIZED_CLIENT = "unauthorized_client", UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type",
  INVALID_SCOPE = "invalid_scope", ACCESS_DENIED = "access_denied", SERVER_ERROR = "server_error",
  TEMPORARILY_UNAVAILABLE = "temporarily_unavailable", INVALID_TOKEN = "invalid_token",
}

export class ApiError extends Error {
  constructor(readonly status: number, readonly code?: string) {
    super(`Identity HTTP ${status}${code ? ` (${code})` : ""}`);
  }
}

export async function boundedBody(response: Response, limit = 2 * 1024 * 1024): Promise<Uint8Array> {
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit) throw new Error(`Identity response exceeds ${limit} bytes; use pagination or export-download`);
      chunks.push(value);
    }
    return Buffer.concat(chunks);
  } finally { await reader.cancel(); }
}

export async function request(url: URL, init: RequestInit = {}): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(url, {
      ...init, redirect: "error", signal: init.signal ?? AbortSignal.timeout(30_000),
      headers: { Accept: "application/json", "Cache-Control": "no-store", "User-Agent": `identityctl/${VERSION}`, ...init.headers },
    });
  } catch {
    throw new Error(`Identity request failed for ${url.origin}; check connectivity and trusted CA configuration`);
  }
  if (!response.ok) {
    const bytes = await boundedBody(response);
    let code: string | undefined;
    try {
      const data = JSON.parse(new TextDecoder().decode(bytes));
      if (Object.values(OAuthErrorCode).includes(data?.error)) code = data.error;
    } catch { /* Remote error bodies are never echoed into credential-bearing diagnostics. */ }
    throw new ApiError(response.status, code);
  }
  return response;
}

export async function oauthPost(issuer: string, path: string, values: Record<string, string>): Promise<unknown> {
  const response = await request(new URL(path, issuer), {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(values),
  });
  const text = new TextDecoder().decode(await boundedBody(response, 64 * 1024));
  if (!text) return undefined;
  try { return JSON.parse(text); } catch { throw new Error("Identity returned invalid OAuth JSON"); }
}
