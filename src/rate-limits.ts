import { createHash } from "node:crypto";

export type RateWindow = {
  count: number;
  resetAt: number;
};

export type RequestAssociation = {
  ip: string;
  licenseHash: string;
  fpHash: string | undefined;
  expiresAt: number;
};

export type AppState = {
  ipWindow: Map<string, RateWindow>;
  keyWindow: Map<string, RateWindow>;
  fpWindow: Map<string, RateWindow>;
  associations: RequestAssociation[];
};

const sha256HexPattern = /^[0-9a-f]{64}$/i;

export function createState(): AppState {
  return {
    ipWindow: new Map<string, RateWindow>(),
    keyWindow: new Map<string, RateWindow>(),
    fpWindow: new Map<string, RateWindow>(),
    associations: [],
  };
}

export function maxWindowMs(env: { ipLimit: { windowMs: number }; keyLimit: { windowMs: number }; fpLimit: { windowMs: number } }): number {
  return Math.max(env.ipLimit.windowMs, env.keyLimit.windowMs, env.fpLimit.windowMs);
}

export function recordAssociation(state: AppState, association: RequestAssociation): void {
  state.associations.push(association);
}

export function pruneExpiredAssociations(state: AppState, now: number): void {
  if (state.associations.length === 0) return;
  state.associations = state.associations.filter((a) => a.expiresAt > now);
}

export type ResetSeed = {
  ip?: string;
  licenseHash?: string;
  fpHash?: string;
};

export type ExpandedTargets = {
  ips: Set<string>;
  licenseHashes: Set<string>;
  fpHashes: Set<string>;
};

export function expandResetTargets(associations: RequestAssociation[], seed: ResetSeed): ExpandedTargets {
  const ips = new Set<string>();
  const licenseHashes = new Set<string>();
  const fpHashes = new Set<string>();

  if (seed.ip) ips.add(seed.ip);
  if (seed.licenseHash) licenseHashes.add(seed.licenseHash);
  if (seed.fpHash) fpHashes.add(seed.fpHash);

  for (const a of associations) {
    const matches =
      (seed.ip !== undefined && a.ip === seed.ip) ||
      (seed.licenseHash !== undefined && a.licenseHash === seed.licenseHash) ||
      (seed.fpHash !== undefined && a.fpHash === seed.fpHash);
    if (!matches) continue;
    ips.add(a.ip);
    licenseHashes.add(a.licenseHash);
    if (a.fpHash !== undefined) fpHashes.add(a.fpHash);
  }

  return { ips, licenseHashes, fpHashes };
}

export function dropAssociationsMatching(state: AppState, expanded: ExpandedTargets): void {
  if (state.associations.length === 0) return;
  state.associations = state.associations.filter(
    (a) =>
      !expanded.ips.has(a.ip) && !expanded.licenseHashes.has(a.licenseHash) && !(a.fpHash !== undefined && expanded.fpHashes.has(a.fpHash)),
  );
}

export function deleteKeys(bucket: Map<string, RateWindow>, keys: string[]): number {
  let deleted = 0;

  for (const key of keys) {
    if (bucket.delete(key)) {
      deleted += 1;
    }
  }

  return deleted;
}

export function hashFromRawOrHash(rawValue: string | undefined, hashValue: string | undefined): string | null | undefined {
  if (hashValue !== undefined) {
    return sha256HexPattern.test(hashValue) ? hashValue.toLowerCase() : null;
  }

  return rawValue === undefined ? undefined : sha256(rawValue);
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function shortHash(hash: string): string {
  return hash.slice(0, 12);
}

export function withinLimit(bucket: Map<string, RateWindow>, key: string, max: number, windowMs: number): boolean {
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
