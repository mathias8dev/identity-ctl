import { origin, TOKEN_PATTERN } from "./config.js";
import { request } from "./http.js";
import { currentSession } from "./session.js";

/** One authenticated transport for workflow commands and the complete HTTP API. */
export async function apiRequest(path: string, init: RequestInit = {}): Promise<Response> {
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\") || path.includes("#")) {
    throw new Error("API path must be absolute within the selected Identity origin");
  }
  let apiUrl: string;
  let accessToken: string;
  if (process.env.IDENTITY_ADMIN_ACCESS_TOKEN) {
    accessToken = process.env.IDENTITY_ADMIN_ACCESS_TOKEN;
    if (!TOKEN_PATTERN.test(accessToken)) throw new Error("Invalid IDENTITY_ADMIN_ACCESS_TOKEN");
    if (!process.env.IDENTITY_ADMIN_API_URL) throw new Error("IDENTITY_ADMIN_API_URL is required with an external bearer token");
    apiUrl = origin(process.env.IDENTITY_ADMIN_API_URL);
  } else {
    ({ apiUrl, accessToken } = await currentSession());
  }
  const url = new URL(path, apiUrl);
  if (url.origin !== apiUrl) throw new Error("API request must stay on the selected Identity origin");
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${accessToken}`);
  return request(url, { ...init, headers: Object.fromEntries(headers) });
}
