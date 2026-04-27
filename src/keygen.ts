import http from "node:http";
import https from "node:https";
import type { AppEnv } from "./config";
import { errorMessage, getIp, getRequestId, json, readJsonSafe } from "./http";
import { log } from "./logging";
import type { AppState } from "./rate-limits";
import { maxWindowMs, recordAssociation, sha256, withinLimit } from "./rate-limits";

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
  bodyBytes: number;
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

function headersToObject(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};

  for (const [name, value] of headers) {
    result[name] = value;
  }

  return result;
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
  const licenseKey = parsed?.licenseKey ?? parsed?.meta?.key;
  const fingerprint = parsed?.fingerprint ?? parsed?.meta?.scope?.fingerprint;

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
        headers: headersToObject(headers),
        servername: upstreamUrl.hostname,
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
            body: Buffer.concat(chunks),
          });
        });
      },
    );

    upstreamReq.on("error", reject);

    if (body) {
      upstreamReq.write(body);
    }
    upstreamReq.end();
  });
}

function validationHashesFor(payload: ValidationPayload): { licenseHash: string; fpHash: string } {
  const licenseHash = sha256(payload.licenseKey);
  const fpHash = sha256(payload.fingerprint);
  return { licenseHash, fpHash };
}

async function forwardKeygenRequest({
  req,
  env,
  requestId,
  start,
  url,
  buildHeaders,
  body,
  bodyBytes,
}: KeygenProxyRequest): Promise<Response> {
  const upstreamUrl = new URL(`${url.pathname}${url.search}`, env.keygenOrigin);
  const headers = buildHeaders(upstreamUrl);

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

    return json(502, {
      error: "upstream_unavailable",
      message: errorMessage(error),
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
    signed: Boolean(upstream.headers.get("keygen-signature")),
  });

  return new Response(new Uint8Array(upstream.body), {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: copyResponseHeaders(upstream),
  });
}

async function proxyEntitlementsRequest(
  req: Request,
  env: AppEnv,
  state: AppState,
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

  const ip = getIp(req, env);
  const licenseHash = sha256(licenseKey);
  let blockedBy: "ip" | "license" | null = null;
  if (!withinLimit(state.ipWindow, `entitlements:${ip}`, env.ipLimit.max, env.ipLimit.windowMs)) {
    blockedBy = "ip";
  } else if (!withinLimit(state.keyWindow, `entitlements:${licenseHash}`, env.keyLimit.max, env.keyLimit.windowMs)) {
    blockedBy = "license";
  }

  recordAssociation(state, {
    ip,
    licenseHash,
    fpHash: undefined,
    expiresAt: Date.now() + maxWindowMs(env),
  });

  if (blockedBy) {
    log(env, "warn", "proxy.rate_limited", {
      requestId,
      ip,
      licenseHash,
      blockedBy,
      durationMs: Date.now() - start,
    });
    return json(429, { error: "rate_limited" }, { "retry-after": "60" });
  }

  return forwardKeygenRequest({
    req,
    env,
    requestId,
    start,
    url,
    buildHeaders: (upstreamUrl) => buildKeygenHeaders(req, upstreamUrl, env, { authorization }),
    bodyBytes: 0,
  });
}

async function proxyValidationRequest(
  req: Request,
  env: AppEnv,
  state: AppState,
  url: URL,
  requestId: string,
  start: number,
): Promise<Response> {
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

  const ip = getIp(req, env);
  const { licenseHash, fpHash } = validationHashesFor(payload);
  let blockedBy: "ip" | "license" | "fingerprint" | null = null;
  if (!withinLimit(state.ipWindow, ip, env.ipLimit.max, env.ipLimit.windowMs)) {
    blockedBy = "ip";
  } else if (!withinLimit(state.keyWindow, licenseHash, env.keyLimit.max, env.keyLimit.windowMs)) {
    blockedBy = "license";
  } else if (!withinLimit(state.fpWindow, fpHash, env.fpLimit.max, env.fpLimit.windowMs)) {
    blockedBy = "fingerprint";
  }

  recordAssociation(state, {
    ip,
    licenseHash,
    fpHash,
    expiresAt: Date.now() + maxWindowMs(env),
  });

  if (blockedBy) {
    log(env, "warn", "proxy.rate_limited", {
      requestId,
      ip,
      licenseHash,
      fingerprintHash: fpHash,
      blockedBy,
      durationMs: Date.now() - start,
    });
    return json(429, { error: "rate_limited" }, { "retry-after": "60" });
  }

  const body = Buffer.from(raw);

  return forwardKeygenRequest({
    req,
    env,
    requestId,
    start,
    url,
    buildHeaders: (upstreamUrl) => buildKeygenHeaders(req, upstreamUrl, env, { includeContentType: true }),
    body,
    bodyBytes: body.length,
  });
}

export async function proxyKeygenApi(req: Request, env: AppEnv, state: AppState): Promise<Response> {
  const requestId = getRequestId(req);
  const url = new URL(req.url);
  const start = Date.now();

  const isValidationProxy = req.method === "POST" && isAllowedKeygenValidationProxyPath(url.pathname, env);
  const isEntitlementsProxy = req.method === "GET" && isAllowedKeygenEntitlementsProxyPath(url.pathname, env);

  if (!isValidationProxy && !isEntitlementsProxy) {
    return json(404, { error: "not_found" });
  }

  if (isEntitlementsProxy) {
    return proxyEntitlementsRequest(req, env, state, url, requestId, start);
  }

  return proxyValidationRequest(req, env, state, url, requestId, start);
}
