import { randomUUID } from "node:crypto";
import type { AppEnv } from "./config";

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown error";
}

export function getRequestId(req: Request): string {
  return req.headers.get("x-request-id") ?? randomUUID();
}

export function getIp(req: Request, env: AppEnv): string {
  if (!env.trustProxy) return "direct";

  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim();
  return "direct";
}

export function json(status: number, payload: unknown, headers: HeadersInit = {}) {
  return Response.json(payload, {
    status,
    headers: {
      "content-type": "application/json",
      ...headers,
    },
  });
}

export function readJsonSafe(input: string): unknown {
  try {
    return JSON.parse(input);
  } catch {
    return null;
  }
}
