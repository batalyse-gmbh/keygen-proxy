import { timingSafeEqual } from "node:crypto";
import type { AppEnv } from "./config";
import { getRequestId, json, readJsonSafe } from "./http";
import { log } from "./logging";
import type { AppState, ExpandedTargets } from "./rate-limits";
import {
  deleteKeys,
  dropAssociationsMatching,
  expandResetTargets,
  hashFromRawOrHash,
  pruneExpiredAssociations,
  shortHash,
} from "./rate-limits";

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

  const now = Date.now();
  pruneExpiredAssociations(state, now);

  const expanded: ExpandedTargets = expandResetTargets(state.associations, {
    ip: payload.ip,
    licenseHash: licenseHash || undefined,
    fpHash: fingerprintHash || undefined,
  });

  const ipKeys: string[] = [];
  for (const ip of expanded.ips) {
    ipKeys.push(ip, `entitlements:${ip}`);
  }
  const licenseKeys: string[] = [];
  for (const hash of expanded.licenseHashes) {
    licenseKeys.push(hash, `entitlements:${hash}`);
  }

  const reset = {
    ip: deleteKeys(state.ipWindow, ipKeys),
    license: deleteKeys(state.keyWindow, licenseKeys),
    fingerprint: deleteKeys(state.fpWindow, [...expanded.fpHashes]),
  };

  dropAssociationsMatching(state, expanded);

  log(env, "info", "rate_limits.reset", {
    requestId,
    hasIpTarget,
    hasLicenseTarget,
    hasFingerprintTarget,
    licenseHash: licenseHash ? shortHash(licenseHash) : undefined,
    fingerprintHash: fingerprintHash ? shortHash(fingerprintHash) : undefined,
    expanded: {
      ips: expanded.ips.size,
      licenses: expanded.licenseHashes.size,
      fingerprints: expanded.fpHashes.size,
    },
    reset,
    durationMs: now - start,
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
