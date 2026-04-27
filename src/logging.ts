import type { AppEnv, LogLevel } from "./config";

const logLevelRank: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export function safeLogLevel(value: LogLevel): LogLevel {
  return value in logLevelRank ? value : "info";
}

export function log(env: AppEnv, level: LogLevel, event: string, fields: Record<string, unknown> = {}) {
  if (logLevelRank[level] < logLevelRank[safeLogLevel(env.logLevel)]) {
    return;
  }

  const payload = {
    ts: new Date().toISOString(),
    level,
    event,
    ...fields,
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
