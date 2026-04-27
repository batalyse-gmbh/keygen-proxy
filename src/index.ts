import { createHash } from "node:crypto";

type CachedValidation = {
  ok: boolean;
  status: number;
  body: unknown;
  keygenHeaders?: Record<string, string>;
  cachedAt: number;
  expiresAt: number;
  graceUntil?: number;
};

type RateWindow = {
  count: number;
  resetAt: number;
};

const env = {
  port: Number(Bun.env.PORT ?? 3000),
  keygenAccount: Bun.env.KEYGEN_ACCOUNT,
  keygenToken: Bun.env.KEYGEN_TOKEN,
  keygenProduct: Bun.env.KEYGEN_PRODUCT,
  validTtlMs: Number(Bun.env.CACHE_VALID_TTL_MS ?? 24 * 60 * 60 * 1000),
  invalidTtlMs: Number(Bun.env.CACHE_INVALID_TTL_MS ?? 5 * 60 * 1000),
  graceMs: Number(Bun.env.CACHE_GRACE_MS ?? 3 * 24 * 60 * 60 * 1000)
};

if (!env.keygenAccount || !env.keygenToken) {
  throw new Error("Missing KEYGEN_ACCOUNT or KEYGEN_TOKEN");
}

const cache = new Map<string, CachedValidation>();
const ipWindow = new Map<string, RateWindow>();
const keyWindow = new Map<string, RateWindow>();
const fpWindow = new Map<string, RateWindow>();
const inflight = new Map<string, Promise<Response>>();

const ipLimit = { max: Number(Bun.env.RL_IP_MAX ?? 20), windowMs: 60_000 };
const keyLimit = { max: Number(Bun.env.RL_KEY_MAX ?? 1), windowMs: Number(Bun.env.RL_KEY_WINDOW_MS ?? 10 * 60_000) };
const fpLimit = { max: Number(Bun.env.RL_FP_MAX ?? 1), windowMs: Number(Bun.env.RL_FP_WINDOW_MS ?? 10 * 60_000) };

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function getIp(req: Request): string {
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0]!.trim();
  return "unknown";
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

async function callKeygen(licenseKey: string, fingerprint: string): Promise<CachedValidation> {
  const endpoint = `https://api.keygen.sh/v1/accounts/${env.keygenAccount}/licenses/actions/validate-key`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.keygenToken}`,
      accept: "application/vnd.api+json",
      "content-type": "application/vnd.api+json"
    },
    body: JSON.stringify({
      meta: {
        key: licenseKey,
        scope: {
          fingerprint,
          product: env.keygenProduct
        }
      }
    })
  });

  const textBody = await response.text();
  const parsedBody = readJsonSafe(textBody) ?? { raw: textBody };
  const now = Date.now();
  const ok = response.ok;

  return {
    ok,
    status: response.status,
    body: parsedBody,
    keygenHeaders: {
      "Keygen-Signature": response.headers.get("Keygen-Signature") ?? "",
      Digest: response.headers.get("Digest") ?? "",
      Date: response.headers.get("Date") ?? ""
    },
    cachedAt: now,
    expiresAt: now + (ok ? env.validTtlMs : env.invalidTtlMs),
    graceUntil: ok ? now + env.validTtlMs + env.graceMs : undefined
  };
}

function getCached(key: string): CachedValidation | undefined {
  const entry = cache.get(key);
  if (!entry) return undefined;
  if (entry.graceUntil && entry.graceUntil < Date.now()) {
    cache.delete(key);
    return undefined;
  }
  return entry;
}

const server = Bun.serve({
  port: env.port,
  routes: {
    "/health": () => json(200, { ok: true }),
    "/license/validate": async (req) => {
      if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

      const ip = getIp(req);
      const raw = await req.text();
      const parsed = readJsonSafe(raw) as { licenseKey?: string; fingerprint?: string } | null;

      if (!parsed?.licenseKey || !parsed?.fingerprint) {
        return json(400, { error: "licenseKey and fingerprint are required" });
      }

      if (parsed.licenseKey.length < 8 || parsed.fingerprint.length < 8) {
        return json(400, { error: "licenseKey/fingerprint too short" });
      }

      const licenseHash = sha256(parsed.licenseKey);
      const fpHash = sha256(parsed.fingerprint);
      const cacheKey = `license_validation:${licenseHash}:${fpHash}:${env.keygenProduct ?? "*"}`;

      const isAllowed =
        withinLimit(ipWindow, ip, ipLimit.max, ipLimit.windowMs) &&
        withinLimit(keyWindow, licenseHash, keyLimit.max, keyLimit.windowMs) &&
        withinLimit(fpWindow, fpHash, fpLimit.max, fpLimit.windowMs);

      const cached = getCached(cacheKey);
      if (!isAllowed) {
        if (cached?.ok && cached.graceUntil && cached.graceUntil > Date.now()) {
          return json(200, { ...cached, source: "cache-grace" }, { "x-proxy-cache": "grace" });
        }
        return json(429, { error: "rate_limited" }, { "retry-after": "60" });
      }

      if (cached && cached.expiresAt > Date.now()) {
        return json(cached.status, { ...cached, source: "cache" }, { "x-proxy-cache": "hit" });
      }

      const existing = inflight.get(cacheKey);
      if (existing) return existing;

      const requestPromise = (async () => {
        try {
          const fresh = await callKeygen(parsed.licenseKey!, parsed.fingerprint!);
          cache.set(cacheKey, fresh);
          return json(fresh.status, { ...fresh, source: "keygen" }, { "x-proxy-cache": "miss" });
        } catch (error) {
          if (cached?.ok && cached.graceUntil && cached.graceUntil > Date.now()) {
            return json(200, { ...cached, source: "cache-grace-error" }, { "x-proxy-cache": "grace" });
          }

          return json(503, {
            error: "upstream_unavailable",
            message: error instanceof Error ? error.message : "Unknown error"
          });
        } finally {
          inflight.delete(cacheKey);
        }
      })();

      inflight.set(cacheKey, requestPromise);
      return requestPromise;
    }
  },
  fetch() {
    return json(404, { error: "not_found" });
  }
});

console.log(`Keygen proxy listening on http://localhost:${server.port}`);
