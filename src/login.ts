import { createServer } from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { lstat } from "node:fs/promises";
import { CLIENT_PATTERN, SCOPES, TOKEN_PATTERN, integer, origin, sessionPath } from "./config.js";
import { oauthPost } from "./http.js";
import { saveSession, tokenSession, withSessionLock } from "./session.js";

export interface LoginOptions {
  issuer: string;
  apiUrl?: string;
  clientId?: string;
  callbackPort?: string;
  timeout?: string;
  noBrowser?: boolean;
}

export async function login(options: LoginOptions): Promise<void> {
  const issuer = origin(options.issuer, "Issuer");
  const apiUrl = origin(options.apiUrl ?? issuer, "API URL");
  const clientId = options.clientId ?? "identityctl";
  if (!CLIENT_PATTERN.test(clientId)) throw new Error("Invalid public client ID");
  const port = options.callbackPort ? integer(options.callbackPort, "Callback port", 1024, 65535) : 0;
  const timeoutMs = integer(options.timeout ?? "300", "Login timeout", 1, 900) * 1000;
  await withSessionLock(async () => {
    const existing = await lstat(sessionPath()).catch((error: NodeJS.ErrnoException) => { if (error.code === "ENOENT") return undefined; throw error; });
    if (existing) throw new Error("A session already exists; logout first or choose another IDENTITYCTL_SESSION_FILE");
    const state = randomBytes(32).toString("base64url");
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    let resolveCode!: (code: string) => void;
    let rejectCode!: (error: Error) => void;
    const received = new Promise<string>((resolve, reject) => { resolveCode = resolve; rejectCode = reject; });
    // Binding can fail before the main await; cancellation must still be observed.
    void received.catch(() => {});
    let redirectUri = "";
    let accepted = false;
    const server = createServer({ maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 5000 }, (request, response) => {
      const reply = (status: number, text: string) => {
        response.writeHead(status, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store",
          "Content-Security-Policy": "default-src 'none'", "Referrer-Policy": "no-referrer" });
        response.end(text);
      };
      if (!redirectUri || !request.url?.startsWith("/") || request.url.startsWith("//")) { reply(400, "Invalid Identity callback."); return; }
      const callback = new URL(request.url, redirectUri);
      const actualState = Buffer.from(callback.searchParams.get("state") ?? "");
      const validState = actualState.length === state.length && timingSafeEqual(actualState, Buffer.from(state));
      if (request.method !== "GET" || request.headers.host !== new URL(redirectUri).host ||
          callback.pathname !== "/oauth2/callback" || !validState ||
          callback.searchParams.getAll("state").length !== 1 || callback.searchParams.getAll("iss").length !== 1 ||
          callback.searchParams.get("iss") !== issuer) {
        reply(400, "Invalid Identity callback."); return;
      }
      if (accepted) { reply(409, "Identity callback already received."); return; }
      const errors = callback.searchParams.getAll("error");
      const codes = callback.searchParams.getAll("code");
      if (errors.length === 1 && codes.length === 0 && /^[a-z_]{1,64}$/.test(errors[0]!)) {
        accepted = true;
        reply(400, "Identity authorization was refused.");
        rejectCode(new Error(`Identity authorization refused (${errors[0]})`));
        return;
      }
      if (errors.length || codes.length !== 1 || !codes[0] || !TOKEN_PATTERN.test(codes[0])) {
        reply(400, "Invalid Identity callback."); return;
      }
      accepted = true;
      reply(200, "Identity CLI authorization received. You can close this tab.");
      resolveCode(codes[0]);
    });
    const abort = () => rejectCode(new Error("Identity login cancelled"));
    const timeout = setTimeout(() => rejectCode(new Error("Identity login timed out")), timeoutMs);
    process.once("SIGINT", abort);
    process.once("SIGTERM", abort);
    try {
      await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(port, "127.0.0.1", resolve); });
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("Cannot bind the loopback callback listener");
      redirectUri = `http://127.0.0.1:${address.port}/oauth2/callback`;
      const authorization = new URL("/oauth2/authorize", issuer);
      authorization.search = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri,
        response_type: "code", scope: SCOPES, resource: `${issuer}/identity/admin`,
        code_challenge: challenge, code_challenge_method: "S256", state }).toString();
      process.stderr.write(`Open this URL to authorize Identity CLI:\n${authorization.href}\n`);
      if (!options.noBrowser) {
        const command = process.platform === "darwin" ? "open" : process.platform === "win32" ? "rundll32" : "xdg-open";
        const arguments_ = process.platform === "win32" ? ["url.dll,FileProtocolHandler", authorization.href] : [authorization.href];
        const browser = spawn(command, arguments_, { stdio: "ignore", detached: true });
        browser.on("error", () => process.stderr.write("Open the authorization URL above manually.\n"));
        browser.unref();
      }
      const code = await received;
      const token = await oauthPost(issuer, "/oauth2/token", { grant_type: "authorization_code", client_id: clientId,
        code, redirect_uri: redirectUri, code_verifier: verifier });
      await saveSession(tokenSession(token, { issuer, apiUrl, clientId }));
    } finally {
      clearTimeout(timeout);
      process.removeListener("SIGINT", abort);
      process.removeListener("SIGTERM", abort);
      server.closeAllConnections();
      server.close();
    }
  });
}
