import { timingSafeEqual } from "node:crypto";
import type { AppEnv } from "./config";
import { getRequestId, json, readJsonSafe } from "./http";
import { log } from "./logging";
import type { AppState } from "./rate-limits";
import { deleteKeys, hashFromRawOrHash, shortHash } from "./rate-limits";

export const adminRateLimitResetPath = "/admin/rate-limits/reset";

type RateLimitResetPayload = {
  ip?: string;
  licenseKey?: string;
  licenseHash?: string;
  fingerprint?: string;
  fingerprintHash?: string;
};

function normalizeString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function parseRateLimitResetPayload(raw: string): RateLimitResetPayload | null {
  const parsed = readJsonSafe(raw) as Record<string, unknown> | null;
  if (!parsed || typeof parsed !== "object") return null;

  return {
    ip: normalizeString(parsed.ip),
    licenseKey: normalizeString(parsed.licenseKey),
    licenseHash: normalizeString(parsed.licenseHash),
    fingerprint: normalizeString(parsed.fingerprint),
    fingerprintHash: normalizeString(parsed.fingerprintHash),
  };
}

function isBearerAuthorized(header: string | null, token: string): boolean {
  const expected = Buffer.from(`Bearer ${token}`);
  const actual = Buffer.from(header ?? "");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export async function resetRateLimits(req: Request, env: AppEnv, state: AppState): Promise<Response> {
  const requestId = getRequestId(req);
  const start = Date.now();

  if (!env.rateLimitResetToken) {
    return json(404, { error: "not_found" });
  }

  if (req.method !== "POST") {
    return json(404, { error: "not_found" });
  }

  if (!isBearerAuthorized(req.headers.get("authorization"), env.rateLimitResetToken)) {
    log(env, "warn", "rate_limits.reset.rejected", {
      requestId,
      reason: "unauthorized",
      durationMs: Date.now() - start,
    });
    return json(401, { error: "unauthorized" });
  }

  const payload = parseRateLimitResetPayload(await req.text());
  if (!payload) {
    log(env, "warn", "rate_limits.reset.bad_request", {
      requestId,
      reason: "invalid_json",
      durationMs: Date.now() - start,
    });
    return json(400, { error: "invalid_request" });
  }

  const licenseHash = hashFromRawOrHash(payload.licenseKey, payload.licenseHash);
  const fingerprintHash = hashFromRawOrHash(payload.fingerprint, payload.fingerprintHash);

  if (licenseHash === null || fingerprintHash === null) {
    log(env, "warn", "rate_limits.reset.bad_request", {
      requestId,
      reason: "invalid_hash",
      hasLicenseTarget: Boolean(payload.licenseKey || payload.licenseHash),
      hasFingerprintTarget: Boolean(payload.fingerprint || payload.fingerprintHash),
      durationMs: Date.now() - start,
    });
    return json(400, { error: "invalid_request" });
  }

  const hasIpTarget = payload.ip !== undefined;
  const hasLicenseTarget = licenseHash !== undefined;
  const hasFingerprintTarget = fingerprintHash !== undefined;

  if (!hasIpTarget && !hasLicenseTarget && !hasFingerprintTarget) {
    log(env, "warn", "rate_limits.reset.bad_request", {
      requestId,
      reason: "missing_targets",
      durationMs: Date.now() - start,
    });
    return json(400, { error: "at least one reset target is required" });
  }

  const ipResetKeys = payload.ip === undefined ? [] : [payload.ip, `entitlements:${payload.ip}`];
  const reset = {
    ip: hasIpTarget ? deleteKeys(state.ipWindow, ipResetKeys) : 0,
    license: hasLicenseTarget ? deleteKeys(state.keyWindow, [licenseHash, `entitlements:${licenseHash}`]) : 0,
    fingerprint: hasFingerprintTarget ? deleteKeys(state.fpWindow, [fingerprintHash]) : 0,
  };

  log(env, "info", "rate_limits.reset", {
    requestId,
    hasIpTarget,
    hasLicenseTarget,
    hasFingerprintTarget,
    licenseHash: licenseHash ? shortHash(licenseHash) : undefined,
    fingerprintHash: fingerprintHash ? shortHash(fingerprintHash) : undefined,
    reset,
    durationMs: Date.now() - start,
  });

  return json(200, {
    ok: true,
    targets: {
      ip: hasIpTarget,
      license: hasLicenseTarget,
      fingerprint: hasFingerprintTarget,
    },
    reset,
  });
}
