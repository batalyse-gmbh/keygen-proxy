import { createHash, randomUUID } from "node:crypto";
import http from "node:http";
import https from "node:https";

type RateWindow = {
  count: number;
  resetAt: number;
};

type UpstreamResponse = {
  status: number;
  statusText: string;
  headers: Headers;
  body: Buffer;
};

type LogLevel = "debug" | "info" | "warn" | "error";

type AppEnv = {
  port: number;
  keygenAccount: string;
  keygenOrigin: string;
  forwardClientHost: boolean;
  trustProxy: boolean;
  logLevel: LogLevel;
  ipLimit: { max: number; windowMs: number };
  keyLimit: { max: number; windowMs: number };
  fpLimit: { max: number; windowMs: number };
};

type AppState = {
  ipWindow: Map<string, RateWindow>;
  keyWindow: Map<string, RateWindow>;
  fpWindow: Map<string, RateWindow>;
};

type ValidationPayload = {
  licenseKey: string;
  fingerprint: string;
};

type BunEnv = Record<string, string | undefined>;

const logLevelRank: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

function parseEnv(source: BunEnv = Bun.env): AppEnv {
  const env = {
    port: Number(source.PORT ?? 3000),
    keygenAccount: source.KEYGEN_ACCOUNT,
    keygenOrigin: source.KEYGEN_ORIGIN ?? "https://api.keygen.sh",
    forwardClientHost: source.KEYGEN_FORWARD_CLIENT_HOST === "true",
    trustProxy: source.TRUST_PROXY === "true",
    logLevel: (source.LOG_LEVEL ?? "info").toLowerCase() as LogLevel,
    ipLimit: { max: Number(source.RL_IP_MAX ?? 20), windowMs: 60_000 },
    keyLimit: { max: Number(source.RL_KEY_MAX ?? 1), windowMs: Number(source.RL_KEY_WINDOW_MS ?? 10 * 60_000) },
    fpLimit: { max: Number(source.RL_FP_MAX ?? 1), windowMs: Number(source.RL_FP_WINDOW_MS ?? 10 * 60_000) }
  };

  if (!env.keygenAccount) {
    throw new Error("Missing KEYGEN_ACCOUNT");
  }

  return env as AppEnv;
}

function createState(): AppState {
  return {
    ipWindow: new Map<string, RateWindow>(),
    keyWindow: new Map<string, RateWindow>(),
    fpWindow: new Map<string, RateWindow>()
  };
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeLogLevel(value: LogLevel): LogLevel {
  return value in logLevelRank ? value : "info";
}

function shortHash(hash: string): string {
  return hash.slice(0, 12);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown error";
}

function getRequestId(req: Request): string {
  return req.headers.get("x-request-id") ?? randomUUID();
}

function log(env: AppEnv, level: LogLevel, event: string, fields: Record<string, unknown> = {}) {
  if (logLevelRank[level] < logLevelRank[safeLogLevel(env.logLevel)]) {
    return;
  }

  const payload = {
    ts: new Date().toISOString(),
    level,
    event,
    ...fields
  };

  const line = JSON.stringify(payload);
  if (level === "error") {
    console.error(line);
  } else if (level === "warn") {
    console.warn(line);
  } else {
    console.log(line);
  }
}

function getIp(req: Request, env: AppEnv): string {
  if (!env.trustProxy) return "direct";

  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0]!.trim();
  return "direct";
}

function withinLimit(bucket: Map<string, RateWindow>, key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const current = bucket.get(key);

  if (!current || current.resetAt <= now) {
    bucket.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }

  if (current.count >= max) return false;
  current.count += 1;
  return true;
}

function readJsonSafe(input: string): unknown {
  try {
    return JSON.parse(input);
  } catch {
    return null;
  }
}

function json(status: number, payload: unknown, headers: HeadersInit = {}) {
  return Response.json(payload, {
    status,
    headers: {
      "content-type": "application/json",
      ...headers
    }
  });
}

function parseValidationPayload(raw: string): ValidationPayload | null {
  const parsed = readJsonSafe(raw) as { licenseKey?: string; fingerprint?: string; meta?: { key?: string; scope?: { fingerprint?: string } } } | null;
  const licenseKey = parsed?.licenseKey ?? parsed?.meta?.key;
  const fingerprint = parsed?.fingerprint ?? parsed?.meta?.scope?.fingerprint;

  if (!licenseKey || !fingerprint) return null;
  return { licenseKey, fingerprint };
}

function isValidationPayloadUsable(payload: ValidationPayload): boolean {
  return payload.licenseKey.length >= 8 && payload.fingerprint.length >= 8;
}

function validationHashesFor(payload: ValidationPayload): { licenseHash: string; fpHash: string } {
  const licenseHash = sha256(payload.licenseKey);
  const fpHash = sha256(payload.fingerprint);
  return { licenseHash, fpHash };
}

function isAllowedKeygenValidationProxyPath(pathname: string, env: AppEnv): boolean {
  return pathname === `/v1/accounts/${env.keygenAccount}/licenses/actions/validate-key`;
}

function isAllowedKeygenEntitlementsProxyPath(pathname: string, env: AppEnv): boolean {
  const prefix = `/v1/accounts/${env.keygenAccount}/licenses/`;
  if (!pathname.startsWith(prefix)) return false;

  const parts = pathname.slice(prefix.length).split("/");
  return parts.length === 2 && parts[0].length > 0 && parts[1] === "entitlements";
}

function parseBasicLicenseAuthorization(header: string | null): string | null {
  if (!header?.toLowerCase().startsWith("basic ")) return null;

  try {
    const credentials = Buffer.from(header.slice("basic ".length).trim(), "base64").toString("utf8");
    const separator = credentials.indexOf(":");
    if (separator === -1) return null;

    const username = credentials.slice(0, separator);
    const licenseKey = credentials.slice(separator + 1);
    if (username !== "license" || licenseKey.length < 8) return null;
    return licenseKey;
  } catch {
    return null;
  }
}

function isKeygenApiPath(pathname: string): boolean {
  return pathname.startsWith("/v1/");
}

function buildKeygenValidationHeaders(req: Request, upstreamUrl: URL, env: AppEnv): Headers {
  const headers = new Headers({
    accept: "application/vnd.api+json",
    "content-type": "application/vnd.api+json"
  });
  const forwardedHost = env.forwardClientHost ? req.headers.get("host") : upstreamUrl.host;
  headers.set("host", forwardedHost ?? upstreamUrl.host);

  return headers;
}

function buildKeygenEntitlementsHeaders(req: Request, upstreamUrl: URL, env: AppEnv, authorization: string): Headers {
  const headers = new Headers({
    accept: "application/vnd.api+json",
    authorization
  });
  const forwardedHost = env.forwardClientHost ? req.headers.get("host") : upstreamUrl.host;
  headers.set("host", forwardedHost ?? upstreamUrl.host);

  return headers;
}

function headersToObject(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};

  for (const [name, value] of headers) {
    result[name] = value;
  }

  return result;
}

function copyResponseHeaders(upstream: Pick<UpstreamResponse, "headers">): Headers {
  const headers = new Headers();
  const passthroughHeaders = [
    "cache-control",
    "content-type",
    "date",
    "digest",
    "etag",
    "keygen-signature",
    "retry-after"
  ];

  for (const name of passthroughHeaders) {
    const value = upstream.headers.get(name);
    if (value) {
      headers.set(name, value);
    }
  }

  return headers;
}

function proxyRequest(upstreamUrl: URL, method: string, headers: Headers, body?: Buffer): Promise<UpstreamResponse> {
  const transport = upstreamUrl.protocol === "http:" ? http : https;

  return new Promise((resolve, reject) => {
    const upstreamReq = transport.request(
      {
        protocol: upstreamUrl.protocol,
        hostname: upstreamUrl.hostname,
        port: upstreamUrl.port,
        path: `${upstreamUrl.pathname}${upstreamUrl.search}`,
        method,
        headers: headersToObject(headers),
        servername: upstreamUrl.hostname
      },
      (upstreamRes) => {
        const chunks: Buffer[] = [];

        upstreamRes.on("data", (chunk) => {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });

        upstreamRes.on("end", () => {
          const responseHeaders = new Headers();
          for (const [name, value] of Object.entries(upstreamRes.headers)) {
            if (Array.isArray(value)) {
              responseHeaders.set(name, value.join(", "));
            } else if (value !== undefined) {
              responseHeaders.set(name, value);
            }
          }

          resolve({
            status: upstreamRes.statusCode ?? 502,
            statusText: upstreamRes.statusMessage ?? "Bad Gateway",
            headers: responseHeaders,
            body: Buffer.concat(chunks)
          });
        });
      }
    );

    upstreamReq.on("error", reject);

    if (body) {
      upstreamReq.write(body);
    }
    upstreamReq.end();
  });
}

async function proxyKeygenApi(req: Request, env: AppEnv, state: AppState): Promise<Response> {
  const requestId = getRequestId(req);
  const url = new URL(req.url);
  const start = Date.now();

  const isValidationProxy = req.method === "POST" && isAllowedKeygenValidationProxyPath(url.pathname, env);
  const isEntitlementsProxy = req.method === "GET" && isAllowedKeygenEntitlementsProxyPath(url.pathname, env);

  if (!isValidationProxy && !isEntitlementsProxy) {
    log(env, "warn", "proxy.rejected", {
      requestId,
      method: req.method,
      pathname: url.pathname,
      reason: "not_allowlisted"
    });
    return json(404, { error: "not_found" });
  }

  if (isEntitlementsProxy) {
    const authorization = req.headers.get("authorization");
    const licenseKey = parseBasicLicenseAuthorization(authorization);

    if (!authorization || !licenseKey) {
      log(env, "warn", "proxy.bad_request", {
        requestId,
        reason: "missing_or_invalid_license_authorization",
        durationMs: Date.now() - start
      });
      return json(401, { error: "license authorization is required" });
    }

    const ip = getIp(req, env);
    const licenseHash = sha256(licenseKey);
    const isAllowed =
      withinLimit(state.ipWindow, `entitlements:${ip}`, env.ipLimit.max, env.ipLimit.windowMs) &&
      withinLimit(state.keyWindow, `entitlements:${licenseHash}`, env.keyLimit.max, env.keyLimit.windowMs);

    if (!isAllowed) {
      log(env, "warn", "proxy.rate_limited", {
        requestId,
        ip,
        licenseHash: shortHash(licenseHash),
        durationMs: Date.now() - start
      });
      return json(429, { error: "rate_limited" }, { "retry-after": "60" });
    }

    const upstreamUrl = new URL(`${url.pathname}${url.search}`, env.keygenOrigin);
    log(env, "info", "proxy.request", {
      requestId,
      method: req.method,
      pathname: url.pathname,
      upstreamHost: upstreamUrl.host,
      bodyBytes: 0
    });

    let upstream: UpstreamResponse;
    try {
      upstream = await proxyRequest(upstreamUrl, req.method, buildKeygenEntitlementsHeaders(req, upstreamUrl, env, authorization));
    } catch (error) {
      log(env, "error", "proxy.upstream.error", {
        requestId,
        method: req.method,
        pathname: url.pathname,
        upstreamHost: upstreamUrl.host,
        durationMs: Date.now() - start,
        error: errorMessage(error)
      });

      return json(502, {
        error: "upstream_unavailable",
        message: errorMessage(error)
      });
    }

    log(env, upstream.status >= 500 ? "warn" : "info", "proxy.response", {
      requestId,
      method: req.method,
      pathname: url.pathname,
      upstreamHost: upstreamUrl.host,
      status: upstream.status,
      durationMs: Date.now() - start,
      bodyBytes: upstream.body.length,
      signed: Boolean(upstream.headers.get("keygen-signature"))
    });

    return new Response(new Uint8Array(upstream.body), {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: copyResponseHeaders(upstream)
    });
  }

  const raw = await req.text();
  const payload = parseValidationPayload(raw);

  if (!payload) {
    log(env, "warn", "proxy.bad_request", {
      requestId,
      reason: "missing_license_or_fingerprint",
      durationMs: Date.now() - start
    });
    return json(400, { error: "license key and fingerprint are required" });
  }

  if (!isValidationPayloadUsable(payload)) {
    log(env, "warn", "proxy.bad_request", {
      requestId,
      reason: "license_or_fingerprint_too_short",
      licenseLength: payload.licenseKey.length,
      fingerprintLength: payload.fingerprint.length,
      durationMs: Date.now() - start
    });
    return json(400, { error: "license key/fingerprint too short" });
  }

  const ip = getIp(req, env);
  const { licenseHash, fpHash } = validationHashesFor(payload);
  const isAllowed =
    withinLimit(state.ipWindow, ip, env.ipLimit.max, env.ipLimit.windowMs) &&
    withinLimit(state.keyWindow, licenseHash, env.keyLimit.max, env.keyLimit.windowMs) &&
    withinLimit(state.fpWindow, fpHash, env.fpLimit.max, env.fpLimit.windowMs);

  if (!isAllowed) {
    log(env, "warn", "proxy.rate_limited", {
      requestId,
      ip,
      licenseHash: shortHash(licenseHash),
      fingerprintHash: shortHash(fpHash),
      durationMs: Date.now() - start
    });
    return json(429, { error: "rate_limited" }, { "retry-after": "60" });
  }

  const upstreamUrl = new URL(`${url.pathname}${url.search}`, env.keygenOrigin);
  const body = Buffer.from(raw);

  log(env, "info", "proxy.request", {
    requestId,
    method: req.method,
    pathname: url.pathname,
    upstreamHost: upstreamUrl.host,
    bodyBytes: body.length
  });

  let upstream: UpstreamResponse;
  try {
    upstream = await proxyRequest(upstreamUrl, req.method, buildKeygenValidationHeaders(req, upstreamUrl, env), body);
  } catch (error) {
    log(env, "error", "proxy.upstream.error", {
      requestId,
      method: req.method,
      pathname: url.pathname,
      upstreamHost: upstreamUrl.host,
      durationMs: Date.now() - start,
      error: errorMessage(error)
    });

    return json(502, {
      error: "upstream_unavailable",
      message: errorMessage(error)
    });
  }

  log(env, upstream.status >= 500 ? "warn" : "info", "proxy.response", {
    requestId,
    method: req.method,
    pathname: url.pathname,
    upstreamHost: upstreamUrl.host,
    status: upstream.status,
    durationMs: Date.now() - start,
    bodyBytes: upstream.body.length,
    signed: Boolean(upstream.headers.get("keygen-signature"))
  });

  return new Response(new Uint8Array(upstream.body), {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: copyResponseHeaders(upstream)
  });
}

export function createKeygenProxyServer(env: AppEnv = parseEnv(), state: AppState = createState()) {
  return Bun.serve({
    port: env.port,
    routes: {
      "/health": (req) => {
        log(env, "debug", "health.request", {
          requestId: getRequestId(req),
          method: req.method
        });
        return json(200, { ok: true });
      }
    },
    fetch(req) {
      const url = new URL(req.url);
      if (isKeygenApiPath(url.pathname)) {
        return proxyKeygenApi(req, env, state);
      }

      log(env, "warn", "request.not_found", {
        requestId: getRequestId(req),
        method: req.method,
        pathname: url.pathname
      });
      return json(404, { error: "not_found" });
    }
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
    rateLimits: {
      ip: env.ipLimit,
      key: env.keyLimit,
      fingerprint: env.fpLimit
    }
  });
}
