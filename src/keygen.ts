import http from "node:http";
import https from "node:https";
import type { Server } from "bun";
import type { AppEnv } from "./config";
import { errorMessage, getIp, getRequestId, json, readJsonSafe } from "./http";
import { log } from "./logging";
import type { AppState, RateWindow } from "./rate-limits";
import { maxWindowMs, recordAssociation, sha256, shortHash, withinLimit } from "./rate-limits";

const upstreamTimeoutMs = 15_000;
const maxUpstreamResponseBytes = 5 * 1024 * 1024;
const maxValidationBodyBytes = 16 * 1024;

type UpstreamResponse = {
  status: number;
  statusText: string;
  headers: Headers;
  body: Buffer;
};

type ValidationPayload = {
  licenseKey: string;
  fingerprint: string;
};

type KeygenProxyRequest = {
  req: Request;
  env: AppEnv;
  requestId: string;
  start: number;
  url: URL;
  buildHeaders: (upstreamUrl: URL) => Headers;
  body?: Buffer;
};

export function isKeygenApiPath(pathname: string): boolean {
  return pathname.startsWith("/v1/");
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

function buildKeygenHeaders(
  req: Request,
  upstreamUrl: URL,
  env: AppEnv,
  options: { authorization?: string; includeContentType?: boolean } = {},
): Headers {
  const headers = new Headers({
    accept: "application/vnd.api+json",
  });

  if (options.includeContentType) {
    headers.set("content-type", "application/vnd.api+json");
  }
  if (options.authorization) {
    headers.set("authorization", options.authorization);
  }

  const forwardedHost = env.forwardClientHost ? req.headers.get("host") : upstreamUrl.host;
  headers.set("host", forwardedHost ?? upstreamUrl.host);

  return headers;
}

function copyResponseHeaders(upstream: Pick<UpstreamResponse, "headers">): Headers {
  const headers = new Headers();
  const passthroughHeaders = ["cache-control", "content-type", "date", "digest", "etag", "keygen-signature", "retry-after"];

  for (const name of passthroughHeaders) {
    const value = upstream.headers.get(name);
    if (value) {
      headers.set(name, value);
    }
  }

  return headers;
}

function parseValidationPayload(raw: string): ValidationPayload | null {
  const parsed = readJsonSafe(raw) as {
    licenseKey?: string;
    fingerprint?: string;
    meta?: { key?: string; scope?: { fingerprint?: string } };
  } | null;
  // Prefer the Keygen-native fields: the raw body is forwarded upstream and
  // Keygen only reads meta.key / meta.scope.fingerprint, so rate-limit
  // identity must match what Keygen will actually validate.
  const licenseKey = parsed?.meta?.key ?? parsed?.licenseKey;
  const fingerprint = parsed?.meta?.scope?.fingerprint ?? parsed?.fingerprint;

  if (!licenseKey || !fingerprint) return null;
  return { licenseKey, fingerprint };
}

function isValidationPayloadUsable(payload: ValidationPayload): boolean {
  return payload.licenseKey.length >= 8 && payload.fingerprint.length >= 8;
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
        headers: Object.fromEntries(headers),
        servername: upstreamUrl.hostname,
        timeout: upstreamTimeoutMs,
      },
      (upstreamRes) => {
        const chunks: Buffer[] = [];
        let receivedBytes = 0;

        upstreamRes.on("error", reject);

        upstreamRes.on("data", (chunk) => {
          const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          receivedBytes += buffer.length;
          if (receivedBytes > maxUpstreamResponseBytes) {
            upstreamRes.destroy(new Error("upstream_response_too_large"));
            return;
          }
          chunks.push(buffer);
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
            body: Buffer.concat(chunks),
          });
        });
      },
    );

    upstreamReq.on("error", reject);
    upstreamReq.on("timeout", () => {
      upstreamReq.destroy(new Error("upstream_timeout"));
    });

    if (body) {
      upstreamReq.write(body);
    }
    upstreamReq.end();
  });
}

async function forwardKeygenRequest({ req, env, requestId, start, url, buildHeaders, body }: KeygenProxyRequest): Promise<Response> {
  const upstreamUrl = new URL(`${url.pathname}${url.search}`, env.keygenOrigin);
  const headers = buildHeaders(upstreamUrl);
  const bodyBytes = body?.length ?? 0;

  log(env, "info", "proxy.request", {
    requestId,
    method: req.method,
    pathname: url.pathname,
    upstreamHost: upstreamUrl.host,
    bodyBytes,
  });

  let upstream: UpstreamResponse;
  try {
    upstream = await proxyRequest(upstreamUrl, req.method, headers, body);
  } catch (error) {
    log(env, "error", "proxy.upstream.error", {
      requestId,
      method: req.method,
      pathname: url.pathname,
      upstreamHost: upstreamUrl.host,
      durationMs: Date.now() - start,
      error: errorMessage(error),
    });

    return json(502, { error: "upstream_unavailable" });
  }

  log(env, upstream.status >= 500 ? "warn" : "info", "proxy.response", {
    requestId,
    method: req.method,
    pathname: url.pathname,
    upstreamHost: upstreamUrl.host,
    status: upstream.status,
    durationMs: Date.now() - start,
    bodyBytes: upstream.body.length,
    signed: Boolean(upstream.headers.get("keygen-signature")),
  });

  return new Response(new Uint8Array(upstream.body), {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: copyResponseHeaders(upstream),
  });
}

type RateLimitCheck = {
  bucket: Map<string, RateWindow>;
  key: string;
  limit: { max: number; windowMs: number };
  blockedBy: "ip" | "license" | "fingerprint";
};

type RateLimitIdentity = {
  ip: string;
  licenseHash: string;
  fpHash?: string;
};

function applyRateLimit(
  env: AppEnv,
  state: AppState,
  requestId: string,
  start: number,
  identity: RateLimitIdentity,
  checks: RateLimitCheck[],
): Response | null {
  for (const check of checks) {
    if (withinLimit(check.bucket, check.key, check.limit.max, check.limit.windowMs)) continue;

    const resetAt = check.bucket.get(check.key)?.resetAt ?? Date.now();
    const retryAfterSeconds = Math.max(1, Math.ceil((resetAt - Date.now()) / 1000));
    log(env, "warn", "proxy.rate_limited", {
      requestId,
      ip: identity.ip,
      licenseHash: shortHash(identity.licenseHash),
      fingerprintHash: identity.fpHash ? shortHash(identity.fpHash) : undefined,
      blockedBy: check.blockedBy,
      durationMs: Date.now() - start,
    });
    return json(429, { error: "rate_limited" }, { "retry-after": String(retryAfterSeconds) });
  }

  // Record associations only for requests within the limits so blocked
  // requests cannot grow the table with attacker-controlled values.
  recordAssociation(state, {
    ip: identity.ip,
    licenseHash: identity.licenseHash,
    fpHash: identity.fpHash,
    expiresAt: Date.now() + maxWindowMs(env),
  });
  return null;
}

async function proxyEntitlementsRequest(
  req: Request,
  env: AppEnv,
  state: AppState,
  server: Server<unknown>,
  url: URL,
  requestId: string,
  start: number,
): Promise<Response> {
  const authorization = req.headers.get("authorization");
  const licenseKey = parseBasicLicenseAuthorization(authorization);

  if (!authorization || !licenseKey) {
    log(env, "warn", "proxy.bad_request", {
      requestId,
      reason: "missing_or_invalid_license_authorization",
      durationMs: Date.now() - start,
    });
    return json(401, { error: "license authorization is required" });
  }

  const ip = getIp(req, env, server);
  const licenseHash = sha256(licenseKey);
  const blocked = applyRateLimit(env, state, requestId, start, { ip, licenseHash }, [
    { bucket: state.ipWindow, key: `entitlements:${ip}`, limit: env.ipLimit, blockedBy: "ip" },
    { bucket: state.keyWindow, key: `entitlements:${licenseHash}`, limit: env.keyLimit, blockedBy: "license" },
  ]);
  if (blocked) return blocked;

  return forwardKeygenRequest({
    req,
    env,
    requestId,
    start,
    url,
    buildHeaders: (upstreamUrl) => buildKeygenHeaders(req, upstreamUrl, env, { authorization }),
  });
}

async function proxyValidationRequest(
  req: Request,
  env: AppEnv,
  state: AppState,
  server: Server<unknown>,
  url: URL,
  requestId: string,
  start: number,
): Promise<Response> {
  const contentLength = Number(req.headers.get("content-length") ?? 0);
  if (contentLength > maxValidationBodyBytes) {
    log(env, "warn", "proxy.bad_request", {
      requestId,
      reason: "payload_too_large",
      contentLength,
      durationMs: Date.now() - start,
    });
    return json(413, { error: "payload_too_large" });
  }

  const raw = await req.text();
  const payload = parseValidationPayload(raw);

  if (!payload) {
    log(env, "warn", "proxy.bad_request", {
      requestId,
      reason: "missing_license_or_fingerprint",
      durationMs: Date.now() - start,
    });
    return json(400, { error: "license key and fingerprint are required" });
  }

  if (!isValidationPayloadUsable(payload)) {
    log(env, "warn", "proxy.bad_request", {
      requestId,
      reason: "license_or_fingerprint_too_short",
      licenseLength: payload.licenseKey.length,
      fingerprintLength: payload.fingerprint.length,
      durationMs: Date.now() - start,
    });
    return json(400, { error: "license key/fingerprint too short" });
  }

  const ip = getIp(req, env, server);
  const licenseHash = sha256(payload.licenseKey);
  const fpHash = sha256(payload.fingerprint);
  const blocked = applyRateLimit(env, state, requestId, start, { ip, licenseHash, fpHash }, [
    { bucket: state.ipWindow, key: ip, limit: env.ipLimit, blockedBy: "ip" },
    { bucket: state.keyWindow, key: licenseHash, limit: env.keyLimit, blockedBy: "license" },
    { bucket: state.fpWindow, key: fpHash, limit: env.fpLimit, blockedBy: "fingerprint" },
  ]);
  if (blocked) return blocked;

  return forwardKeygenRequest({
    req,
    env,
    requestId,
    start,
    url,
    buildHeaders: (upstreamUrl) => buildKeygenHeaders(req, upstreamUrl, env, { includeContentType: true }),
    body: Buffer.from(raw),
  });
}

export async function proxyKeygenApi(req: Request, env: AppEnv, state: AppState, server: Server<unknown>): Promise<Response> {
  const requestId = getRequestId(req);
  const url = new URL(req.url);
  const start = Date.now();

  const isValidationProxy = req.method === "POST" && isAllowedKeygenValidationProxyPath(url.pathname, env);
  const isEntitlementsProxy = req.method === "GET" && isAllowedKeygenEntitlementsProxyPath(url.pathname, env);

  if (!isValidationProxy && !isEntitlementsProxy) {
    return json(404, { error: "not_found" });
  }

  if (isEntitlementsProxy) {
    return proxyEntitlementsRequest(req, env, state, server, url, requestId, start);
  }

  return proxyValidationRequest(req, env, state, server, url, requestId, start);
}
