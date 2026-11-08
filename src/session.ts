import { constants, type Stats } from "node:fs";
import { lstat, mkdir, open, rename, link, rm } from "node:fs/promises";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { CLIENT_PATTERN, TOKEN_PATTERN, origin, sessionPath } from "./config.js";
import { oauthPost } from "./http.js";

const sessionSchema = z.object({
  schemaVersion: z.literal(1), issuer: z.string(), apiUrl: z.string(),
  clientId: z.string().regex(CLIENT_PATTERN), accessToken: z.string().regex(TOKEN_PATTERN),
  refreshToken: z.string().regex(TOKEN_PATTERN), accessTokenExpiresAt: z.number().int().positive(), scopes: z.string(),
}).strict();
const tokenSchema = z.object({
  access_token: z.string().min(1).regex(TOKEN_PATTERN), refresh_token: z.string().min(1).regex(TOKEN_PATTERN),
  token_type: z.string().refine(value => value.toLowerCase() === "bearer"),
  expires_in: z.number().int().min(1).max(86400), scope: z.string(),
});
export type Session = z.infer<typeof sessionSchema>;

function requirePrivate(stat: Stats, directory = false): void {
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile()) ||
      (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()))) {
    throw new Error(`Session ${directory ? "directory" : "file"} must belong to you, be private and not be a symlink`);
  }
}

async function privateDirectory(path: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  requirePrivate(await lstat(dirname(path)), true);
}

export async function withSessionLock<T>(action: () => Promise<T>, path = sessionPath()): Promise<T> {
  await privateDirectory(path);
  const lockPath = `${path}.lock`;
  const lock = await open(lockPath, "wx", 0o600).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "EEXIST") throw new Error("Session is in use; retry after the other identityctl command finishes. For an interrupted command, verify it has stopped before removing its .lock file.");
    throw error;
  });
  try {
    await lock.writeFile(JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() }));
    return await action();
  } finally { await lock.close(); await rm(lockPath); }
}

export async function loadSession(path = sessionPath()): Promise<Session> {
  requirePrivate(await lstat(dirname(path)), true);
  requirePrivate(await lstat(path));
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    requirePrivate(await handle.stat());
    if ((await handle.stat()).size > 64 * 1024) throw new Error("Stored Identity session is too large");
    let session: Session;
    try { session = sessionSchema.parse(JSON.parse(await handle.readFile("utf8"))); }
    catch { throw new Error("Stored Identity session is malformed; choose another session file or sign in again"); }
    if (origin(session.issuer) !== session.issuer || origin(session.apiUrl) !== session.apiUrl) throw new Error("Stored session origins are not canonical");
    if (process.env.IDENTITYCTL_ISSUER && origin(process.env.IDENTITYCTL_ISSUER) !== session.issuer) throw new Error("Stored session issuer does not match IDENTITYCTL_ISSUER");
    if (process.env.IDENTITYCTL_API_URL && origin(process.env.IDENTITYCTL_API_URL) !== session.apiUrl) throw new Error("Stored session API URL does not match IDENTITYCTL_API_URL");
    if (process.env.IDENTITYCTL_CLIENT_ID && process.env.IDENTITYCTL_CLIENT_ID !== session.clientId) throw new Error("Stored session client does not match IDENTITYCTL_CLIENT_ID");
    return session;
  } finally { await handle.close(); }
}

export async function saveSession(session: Session, path = sessionPath(), replace = false): Promise<void> {
  sessionSchema.parse(session);
  await privateDirectory(path);
  const existing = await lstat(path).catch((error: NodeJS.ErrnoException) => { if (error.code === "ENOENT") return undefined; throw error; });
  if (existing) requirePrivate(existing);
  const temporary = `${path}.${randomBytes(12).toString("hex")}.tmp`;
  try {
    const handle = await open(temporary, "wx", 0o600);
    try { await handle.writeFile(JSON.stringify(session) + "\n"); await handle.sync(); }
    finally { await handle.close(); }
    if (replace) await rename(temporary, path);
    else await link(temporary, path);
  } finally { await rm(temporary, { force: true }); }
}

export function tokenSession(value: unknown, context: Pick<Session, "issuer" | "apiUrl" | "clientId">): Session {
  const parsed = tokenSchema.safeParse(value);
  if (!parsed.success) throw new Error("Identity returned an invalid access/rotating-refresh token response");
  const token = parsed.data;
  return { schemaVersion: 1, issuer: context.issuer, apiUrl: context.apiUrl, clientId: context.clientId,
    accessToken: token.access_token, refreshToken: token.refresh_token,
    accessTokenExpiresAt: Math.floor(Date.now() / 1000) + token.expires_in, scopes: token.scope };
}

export async function currentSession(): Promise<Session> {
  return withSessionLock(async () => {
    const session = await loadSession();
    if (session.accessTokenExpiresAt > Math.floor(Date.now() / 1000) + 60) return session;
    const token = await oauthPost(session.issuer, "/oauth2/token", {
      grant_type: "refresh_token", client_id: session.clientId, refresh_token: session.refreshToken,
    });
    const refreshed = tokenSession(token, session);
    await saveSession(refreshed, sessionPath(), true);
    return refreshed;
  });
}

export async function logout(): Promise<void> {
  await withSessionLock(async () => {
    if (!await lstat(sessionPath()).catch((error: NodeJS.ErrnoException) => { if (error.code === "ENOENT") return undefined; throw error; })) return;
    const session = await loadSession();
    await oauthPost(session.issuer, "/oauth2/revoke", { token: session.refreshToken, client_id: session.clientId, token_type_hint: "refresh_token" });
    await rm(sessionPath());
  });
}
