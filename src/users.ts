import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { once } from "node:events";
import { z } from "zod";
import { TOKEN_PATTERN, integer, origin } from "./config.js";
import { boundedBody, request } from "./http.js";
import { currentSession } from "./session.js";

enum ImportMode { VALIDATE_ONLY = "VALIDATE_ONLY", CREATE_ONLY = "CREATE_ONLY" }
const envelope = z.object({ schemaVersion: z.literal(1), source: z.string().min(1), mode: z.enum(ImportMode),
  idempotencyKey: z.string().min(1), records: z.array(z.unknown()).min(1).max(500) });
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function id(value: string | undefined): string {
  if (!value || !uuid.test(value)) throw new Error("Tenant and job IDs must be UUIDs");
  return value;
}

async function importDocument(path: string): Promise<string> {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Import must be a regular non-symlink file");
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const current = await handle.stat();
    if (!current.isFile() || current.size < 1 || current.size > 524288) throw new Error("Import must be 1-512 KiB");
    const buffer = Buffer.alloc(524289);
    let size = 0;
    while (size < buffer.length) {
      const read = await handle.read(buffer, size, buffer.length - size, null);
      if (!read.bytesRead) break;
      size += read.bytesRead;
    }
    if (size > 524288) throw new Error("Import must be 1-512 KiB");
    const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, size));
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { throw new Error("Import must contain valid canonical bulk JSON"); }
    if (Array.isArray(parsed)) throw new Error("A source export must first be converted to a canonical schemaVersion 1 bulk document");
    if (!envelope.safeParse(parsed).success) throw new Error("Import requires schemaVersion 1, source, mode, idempotencyKey and 1-500 records");
    return text;
  } finally { await handle.close(); }
}

async function access(): Promise<{ apiUrl: string; accessToken: string }> {
  if (process.env.IDENTITY_ADMIN_ACCESS_TOKEN) {
    if (!TOKEN_PATTERN.test(process.env.IDENTITY_ADMIN_ACCESS_TOKEN)) throw new Error("Invalid IDENTITY_ADMIN_ACCESS_TOKEN");
    if (!process.env.IDENTITY_ADMIN_API_URL) throw new Error("IDENTITY_ADMIN_API_URL is required with an external bearer token");
    return { apiUrl: origin(process.env.IDENTITY_ADMIN_API_URL), accessToken: process.env.IDENTITY_ADMIN_ACCESS_TOKEN };
  }
  return currentSession();
}

export async function users(args: string[]): Promise<void> {
  const [command, tenant, third, fourth] = args;
  const tenantId = id(tenant);
  let method = "GET";
  let path: string;
  let body: string | undefined;
  let download = false;
  const page = (value?: string) => integer(value ?? "0", "Page", 0, 2147483647);
  switch (command) {
    case "import":
      if (args.length !== 3) throw new Error("Usage: identityctl users import TENANT_ID CANONICAL_JSON_FILE");
      body = await importDocument(third!); method = "POST"; path = "user-imports"; break;
    case "imports": case "exports":
      if (args.length > 3) throw new Error("List jobs accepts an optional page number");
      path = `${command === "imports" ? "user-imports" : "user-exports"}?page=${page(third)}&size=100`; break;
    case "import-results": case "export-records":
      if (args.length < 3 || args.length > 4) throw new Error("Job results require a job ID and optional page");
      path = command === "import-results" ? `user-imports/${id(third)}/results` : `user-exports/${id(third)}/records`;
      path += `?page=${page(fourth)}&size=100`; break;
    case "cancel-import": case "cancel-export":
      if (args.length !== 3) throw new Error("Cancellation requires exactly one job ID");
      path = `${command === "cancel-import" ? "user-imports" : "user-exports"}/${id(third)}`; method = "DELETE"; break;
    case "export":
      if (args.length !== 3 || !third || !/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(third)) throw new Error("Export requires an 8-128 character idempotency key");
      path = "user-exports"; method = "POST"; body = JSON.stringify({ schemaVersion: 1, idempotencyKey: third }); break;
    case "export-download":
      if (args.length !== 3) throw new Error("Download requires exactly one job ID");
      path = `user-exports/${id(third)}/download`; download = true; break;
    default: throw new Error("Unknown users command; run identityctl --help");
  }
  const session = await access();
  const response = await request(new URL(`/identity/admin/tenants/${tenantId}/${path}`, session.apiUrl), {
    method, headers: { Authorization: `Bearer ${session.accessToken}`, Accept: download ? "application/x-ndjson" : "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}) },
    ...(body ? { body } : {}),
  });
  if (download) {
    if (response.body) for await (const chunk of response.body) {
      if (!process.stdout.write(chunk)) await once(process.stdout, "drain");
    }
  } else {
    const text = new TextDecoder().decode(await boundedBody(response));
    if (text) process.stdout.write(`${text}\n`);
  }
}
