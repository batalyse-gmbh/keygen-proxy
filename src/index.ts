import { adminRateLimitResetPath, resetRateLimits } from "./admin";
import { type AppEnv, parseEnv } from "./config";
import { getRequestId, json } from "./http";
import { isKeygenApiPath, proxyKeygenApi } from "./keygen";
import { log, safeLogLevel } from "./logging";
import { type AppState, createState } from "./rate-limits";

export function createKeygenProxyServer(env: AppEnv = parseEnv(), state: AppState = createState()) {
  return Bun.serve({
    port: env.port,
    routes: {
      "/health": (req) => {
        log(env, "debug", "health.request", {
          requestId: getRequestId(req),
          method: req.method,
        });
        return json(200, { ok: true });
      },
    },
    fetch(req) {
      const url = new URL(req.url);
      if (url.pathname === adminRateLimitResetPath) {
        return resetRateLimits(req, env, state);
      }

      if (isKeygenApiPath(url.pathname)) {
        return proxyKeygenApi(req, env, state);
      }

      return json(404, { error: "not_found" });
    },
  });
}

if (import.meta.main) {
  const env = parseEnv();
  const server = createKeygenProxyServer(env);
  log(env, "info", "server.started", {
    port: server.port,
    keygenOrigin: env.keygenOrigin,
    keygenAccountConfigured: Boolean(env.keygenAccount),
    forwardClientHost: env.forwardClientHost,
    trustProxy: env.trustProxy,
    logLevel: safeLogLevel(env.logLevel),
    rateLimitResetEnabled: Boolean(env.rateLimitResetToken),
    rateLimits: {
      ip: env.ipLimit,
      key: env.keyLimit,
      fingerprint: env.fpLimit,
    },
  });
}
