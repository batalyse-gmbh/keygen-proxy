export type LogLevel = "debug" | "info" | "warn" | "error";

export type RateLimitPolicy = {
  max: number;
  windowMs: number;
};

export type AppEnv = {
  port: number;
  keygenAccount: string;
  keygenOrigin: string;
  forwardClientHost: boolean;
  trustProxy: boolean;
  logLevel: LogLevel;
  rateLimitResetToken?: string;
  ipLimit: RateLimitPolicy;
  keyLimit: RateLimitPolicy;
  fpLimit: RateLimitPolicy;
};

type BunEnv = Record<string, string | undefined>;

function numberEnv(name: string, raw: string | undefined, fallback: number): number {
  if (raw === undefined) return fallback;

  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error(`Invalid ${name}: expected a positive number, got "${raw}"`);
  }
  return value;
}

function parseLogLevel(raw: string | undefined): LogLevel {
  const value = (raw ?? "info").toLowerCase();
  return value === "debug" || value === "warn" || value === "error" ? value : "info";
}

export function parseEnv(source: BunEnv = Bun.env): AppEnv {
  const keygenAccount = source.KEYGEN_ACCOUNT;
  if (!keygenAccount) {
    throw new Error("Missing KEYGEN_ACCOUNT");
  }

  return {
    port: numberEnv("PORT", source.PORT, 3000),
    keygenAccount,
    keygenOrigin: source.KEYGEN_ORIGIN ?? "https://api.keygen.sh",
    forwardClientHost: source.KEYGEN_FORWARD_CLIENT_HOST === "true",
    trustProxy: source.TRUST_PROXY === "true",
    logLevel: parseLogLevel(source.LOG_LEVEL),
    rateLimitResetToken: source.RATE_LIMIT_RESET_TOKEN,
    ipLimit: { max: numberEnv("RL_IP_MAX", source.RL_IP_MAX, 10), windowMs: 60_000 },
    keyLimit: {
      max: numberEnv("RL_KEY_MAX", source.RL_KEY_MAX, 2),
      windowMs: numberEnv("RL_KEY_WINDOW_MS", source.RL_KEY_WINDOW_MS, 6 * 60 * 60_000),
    },
    fpLimit: {
      max: numberEnv("RL_FP_MAX", source.RL_FP_MAX, 2),
      windowMs: numberEnv("RL_FP_WINDOW_MS", source.RL_FP_WINDOW_MS, 6 * 60 * 60_000),
    },
  };
}
