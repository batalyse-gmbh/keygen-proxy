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

export function parseEnv(source: BunEnv = Bun.env): AppEnv {
  const env = {
    port: Number(source.PORT ?? 3000),
    keygenAccount: source.KEYGEN_ACCOUNT,
    keygenOrigin: source.KEYGEN_ORIGIN ?? "https://api.keygen.sh",
    forwardClientHost: source.KEYGEN_FORWARD_CLIENT_HOST === "true",
    trustProxy: source.TRUST_PROXY === "true",
    logLevel: (source.LOG_LEVEL ?? "info").toLowerCase() as LogLevel,
    rateLimitResetToken: source.RATE_LIMIT_RESET_TOKEN,
    ipLimit: { max: Number(source.RL_IP_MAX ?? 10), windowMs: 60_000 },
    keyLimit: { max: Number(source.RL_KEY_MAX ?? 2), windowMs: Number(source.RL_KEY_WINDOW_MS ?? 6 * 60 * 60_000) },
    fpLimit: { max: Number(source.RL_FP_MAX ?? 2), windowMs: Number(source.RL_FP_WINDOW_MS ?? 6 * 60 * 60_000) },
  };

  if (!env.keygenAccount) {
    throw new Error("Missing KEYGEN_ACCOUNT");
  }

  return env as AppEnv;
}
