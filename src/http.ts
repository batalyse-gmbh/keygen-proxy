import { randomUUID } from "node:crypto";
import type { Server } from "bun";
import type { AppEnv } from "./config";

const requestIdPattern = /^[A-Za-z0-9_-]{1,64}$/;

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown error";
}

export function getRequestId(req: Request): string {
  const value = req.headers.get("x-request-id");
  return value && requestIdPattern.test(value) ? value : randomUUID();
}

export function getIp(req: Request, env: AppEnv, server: Server<unknown>): string {
  if (env.trustProxy) {
    const forwarded = req.headers.get("x-forwarded-for");
    if (forwarded) {
      // The trusted reverse proxy appends the client IP, so only the last
      // entry is trustworthy; earlier entries are client-controlled.
      const parts = forwarded.split(",");
      const last = parts[parts.length - 1].trim();
      if (last) return last;
    }
  }

  return server.requestIP(req)?.address ?? "direct";
}

export function json(status: number, payload: unknown, headers: HeadersInit = {}) {
  return Response.json(payload, { status, headers });
}

export function readJsonSafe(input: string): unknown {
  try {
    return JSON.parse(input);
  } catch {
    return null;
  }
}
