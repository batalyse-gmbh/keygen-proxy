import { createHash } from "node:crypto";

export type RateWindow = {
  count: number;
  resetAt: number;
};

export type AppState = {
  ipWindow: Map<string, RateWindow>;
  keyWindow: Map<string, RateWindow>;
  fpWindow: Map<string, RateWindow>;
};

const sha256HexPattern = /^[0-9a-f]{64}$/i;

export function createState(): AppState {
  return {
    ipWindow: new Map<string, RateWindow>(),
    keyWindow: new Map<string, RateWindow>(),
    fpWindow: new Map<string, RateWindow>(),
  };
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
