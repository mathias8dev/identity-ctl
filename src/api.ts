import { constants } from "node:fs";
import { lstat, open, rm } from "node:fs/promises";
import { once } from "node:events";
import { boundedBody } from "./http.js";
import { apiRequest } from "./api-client.js";

enum HttpMethod { GET = "GET", HEAD = "HEAD", OPTIONS = "OPTIONS", POST = "POST", PUT = "PUT", PATCH = "PATCH", DELETE = "DELETE" }
const MAX_INPUT = 64 * 1024 * 1024;

async function readInput(path: string, max = MAX_INPUT): Promise<Uint8Array> {
  if (path === "-") {
    let size = 0; const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > max) throw new Error(`API input exceeds ${max} bytes`);
      chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("API input must be a regular non-symlink file");
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > max) throw new Error(`API input must be at most ${max} bytes`);
    const chunks: Buffer[] = []; let size = 0;
    for (;;) {
      const block = Buffer.alloc(64 * 1024);
      const result = await handle.read(block, 0, block.length, null);
      if (!result.bytesRead) break;
      size += result.bytesRead;
      if (size > max) throw new Error(`API input exceeds ${max} bytes`);
      chunks.push(block.subarray(0, result.bytesRead));
    }
    return Buffer.concat(chunks);
  } finally { await handle.close(); }
}

export async function api(args: string[]): Promise<void> {
  const [method, path, ...options] = args;
  if (!method || !path || !Object.values(HttpMethod).includes(method as HttpMethod)) {
    throw new Error("Usage: identityctl api METHOD /PATH [--input FILE|-] [--headers FILE] [--content-type TYPE] [--output FILE|-]");
  }
  const values = new Map<string, string>();
  for (let index = 0; index < options.length; index++) {
    const name = options[index]!; const value = options[++index];
    if (!["--input", "--headers", "--content-type", "--output"].includes(name) || values.has(name) || !value || value.startsWith("--")) {
      throw new Error("Unknown, duplicate or missing API option");
    }
    values.set(name, value);
  }
  if ([HttpMethod.GET, HttpMethod.HEAD].includes(method as HttpMethod) && values.has("--input")) throw new Error("GET and HEAD cannot send an input body");
  const headers = new Headers();
  if (values.has("--headers")) {
    if (values.get("--headers") === "-") throw new Error("Headers must come from a file");
    let value: unknown;
    try { value = JSON.parse(new TextDecoder().decode(await readInput(values.get("--headers")!, 64 * 1024))); }
    catch { throw new Error("Headers file must be a JSON object of header names and string values"); }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Headers file must be a JSON object");
    for (const [name, item] of Object.entries(value)) {
      if (["authorization", "cookie", "host", "forwarded", "proxy-authorization", "content-length", "connection", "transfer-encoding"].includes(name.toLowerCase()) || name.toLowerCase().startsWith("x-forwarded-")) {
        throw new Error("Credential and routing headers are owned by the Identity client");
      }
      if (typeof item !== "string") throw new Error("Header values must be strings");
      headers.set(name, item);
    }
  }
  const body = values.has("--input") ? await readInput(values.get("--input")!) : undefined;
  if (values.has("--content-type") || body !== undefined) headers.set("Content-Type", values.get("--content-type") ?? "application/json");
  const output = values.get("--output");
  // Reserve output before any mutation: an existing/unwritable destination must not lose a one-time secret.
  const file = output && output !== "-" ? await open(output, "wx", 0o600) : undefined;
  let complete = false;
  try {
    const response = await apiRequest(path, { method, headers, ...(body === undefined ? {} : { body: body as BodyInit }) });
    if (file || output === "-") {
      if (response.body) for await (const chunk of response.body) {
        if (file) await file.writeFile(chunk);
        else if (!process.stdout.write(chunk)) await once(process.stdout, "drain");
      }
    } else {
      const bytes = await boundedBody(response);
      if (bytes.length) process.stdout.write(bytes);
    }
    complete = true;
  } finally {
    await file?.close();
    if (file && !complete) await rm(output!);
  }
}
