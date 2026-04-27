import { afterEach, describe, expect, test } from "bun:test";
import net from "node:net";
import { createKeygenProxyServer } from "./index";

type TestEnv = Parameters<typeof createKeygenProxyServer>[0];

type CapturedRequest = {
  method: string;
  pathname: string;
  authorization: string | null;
  body: unknown;
};

const servers: Array<{ stop: () => void }> = [];

afterEach(() => {
  while (servers.length > 0) {
    servers.pop()?.stop();
  }
});

function baseEnv(overrides: Partial<TestEnv> = {}): TestEnv {
  return {
    port: 0,
    keygenAccount: "acct_123",
    keygenProduct: "prod_123",
    keygenOrigin: "http://127.0.0.1:9",
    forwardClientHost: false,
    trustProxy: false,
    logLevel: "error",
    validTtlMs: 86_400_000,
    invalidTtlMs: 300_000,
    graceMs: 259_200_000,
    ipLimit: { max: 20, windowMs: 60_000 },
    keyLimit: { max: 20, windowMs: 600_000 },
    fpLimit: { max: 20, windowMs: 600_000 },
    ...overrides
  };
}

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close(() => reject(new Error("Unable to allocate test port")));
        return;
      }
      const { port } = address;
      server.close(() => resolve(port));
    });
  });
}

async function startMockKeygen() {
  const requests: CapturedRequest[] = [];
  const server = Bun.serve({
    port: await getFreePort(),
    async fetch(req) {
      const url = new URL(req.url);
      const raw = await req.text();
      requests.push({
        method: req.method,
        pathname: url.pathname,
        authorization: req.headers.get("authorization"),
        body: raw ? JSON.parse(raw) : null
      });

      return Response.json(
        { meta: { valid: true } },
        {
          headers: {
            "keygen-signature": "sig",
            digest: "digest"
          }
        }
      );
    }
  });
  servers.push(server);
  return { server, requests };
}

async function startProxy(env: TestEnv) {
  const server = createKeygenProxyServer({ ...env, port: await getFreePort() });
  servers.push(server);
  return server;
}

function validationBody(key = "LICENSE-1234", fingerprint = "FINGERPRINT-1234") {
  return JSON.stringify({
    meta: {
      key,
      scope: {
        fingerprint,
        product: "prod_123"
      }
    }
  });
}

function basicLicenseAuth(key = "LICENSE-1234") {
  return `Basic ${Buffer.from(`license:${key}`).toString("base64")}`;
}

describe("Keygen-compatible proxy route", () => {
  test("rejects non-allowlisted Keygen API paths without calling upstream", async () => {
    const mock = await startMockKeygen();
    const proxy = await startProxy(baseEnv({ keygenOrigin: `http://127.0.0.1:${mock.server.port}` }));

    const response = await fetch(`http://127.0.0.1:${proxy.port}/v1/accounts/acct_123/licenses`, {
      method: "GET"
    });

    expect(response.status).toBe(404);
    expect(mock.requests).toHaveLength(0);
  });

  test("forwards only the account-scoped validate-key path without privileged auth", async () => {
    const mock = await startMockKeygen();
    const proxy = await startProxy(baseEnv({ keygenOrigin: `http://127.0.0.1:${mock.server.port}` }));

    const response = await fetch(`http://127.0.0.1:${proxy.port}/v1/accounts/acct_123/licenses/actions/validate-key`, {
      method: "POST",
      headers: {
        authorization: "Bearer attacker-token",
        "content-type": "application/vnd.api+json"
      },
      body: validationBody()
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("keygen-signature")).toBe("sig");
    expect(mock.requests).toHaveLength(1);
    expect(mock.requests[0]).toMatchObject({
      method: "POST",
      pathname: "/v1/accounts/acct_123/licenses/actions/validate-key",
      authorization: null
    });
  });

  test("rejects validate-key paths for other accounts", async () => {
    const mock = await startMockKeygen();
    const proxy = await startProxy(baseEnv({ keygenOrigin: `http://127.0.0.1:${mock.server.port}` }));

    const response = await fetch(`http://127.0.0.1:${proxy.port}/v1/accounts/other_acct/licenses/actions/validate-key`, {
      method: "POST",
      body: validationBody()
    });

    expect(response.status).toBe(404);
    expect(mock.requests).toHaveLength(0);
  });

  test("applies rate limits to proxied validation requests", async () => {
    const mock = await startMockKeygen();
    const proxy = await startProxy(
      baseEnv({
        keygenOrigin: `http://127.0.0.1:${mock.server.port}`,
        ipLimit: { max: 1, windowMs: 60_000 },
        keyLimit: { max: 20, windowMs: 600_000 },
        fpLimit: { max: 20, windowMs: 600_000 }
      })
    );
    const url = `http://127.0.0.1:${proxy.port}/v1/accounts/acct_123/licenses/actions/validate-key`;

    const first = await fetch(url, {
      method: "POST",
      body: validationBody("LICENSE-1234", "FINGERPRINT-1234")
    });
    const second = await fetch(url, {
      method: "POST",
      body: validationBody("LICENSE-5678", "FINGERPRINT-5678")
    });

    expect(first.status).toBe(200);
    expect(second.status).toBe(429);
    expect(mock.requests).toHaveLength(1);
  });

  test("forwards account-scoped license entitlements with caller license auth only", async () => {
    const mock = await startMockKeygen();
    const proxy = await startProxy(baseEnv({ keygenOrigin: `http://127.0.0.1:${mock.server.port}` }));

    const response = await fetch(`http://127.0.0.1:${proxy.port}/v1/accounts/acct_123/licenses/lic_123/entitlements`, {
      method: "GET",
      headers: {
        authorization: basicLicenseAuth(),
        accept: "application/vnd.api+json"
      }
    });

    expect(response.status).toBe(200);
    expect(mock.requests).toHaveLength(1);
    expect(mock.requests[0]).toMatchObject({
      method: "GET",
      pathname: "/v1/accounts/acct_123/licenses/lic_123/entitlements",
      authorization: basicLicenseAuth()
    });
  });

  test("rejects license entitlements requests without Basic license auth", async () => {
    const mock = await startMockKeygen();
    const proxy = await startProxy(baseEnv({ keygenOrigin: `http://127.0.0.1:${mock.server.port}` }));

    const response = await fetch(`http://127.0.0.1:${proxy.port}/v1/accounts/acct_123/licenses/lic_123/entitlements`, {
      method: "GET"
    });

    expect(response.status).toBe(401);
    expect(mock.requests).toHaveLength(0);
  });

  test("rejects mutating license entitlements requests", async () => {
    const mock = await startMockKeygen();
    const proxy = await startProxy(baseEnv({ keygenOrigin: `http://127.0.0.1:${mock.server.port}` }));

    const response = await fetch(`http://127.0.0.1:${proxy.port}/v1/accounts/acct_123/licenses/lic_123/entitlements`, {
      method: "POST",
      headers: { authorization: basicLicenseAuth() },
      body: "{}"
    });

    expect(response.status).toBe(404);
    expect(mock.requests).toHaveLength(0);
  });

  test("keeps entitlement rate limits separate from validation key limits", async () => {
    const mock = await startMockKeygen();
    const proxy = await startProxy(
      baseEnv({
        keygenOrigin: `http://127.0.0.1:${mock.server.port}`,
        ipLimit: { max: 20, windowMs: 60_000 },
        keyLimit: { max: 1, windowMs: 600_000 },
        fpLimit: { max: 20, windowMs: 600_000 }
      })
    );

    const validation = await fetch(`http://127.0.0.1:${proxy.port}/v1/accounts/acct_123/licenses/actions/validate-key`, {
      method: "POST",
      body: validationBody("LICENSE-1234", "FINGERPRINT-1234")
    });
    const entitlements = await fetch(`http://127.0.0.1:${proxy.port}/v1/accounts/acct_123/licenses/lic_123/entitlements`, {
      method: "GET",
      headers: { authorization: basicLicenseAuth("LICENSE-1234") }
    });

    expect(validation.status).toBe(200);
    expect(entitlements.status).toBe(200);
    expect(mock.requests).toHaveLength(2);
  });
});

describe("client IP handling", () => {
  test("ignores X-Forwarded-For by default", async () => {
    const mock = await startMockKeygen();
    const proxy = await startProxy(
      baseEnv({
        keygenOrigin: `http://127.0.0.1:${mock.server.port}`,
        ipLimit: { max: 1, windowMs: 60_000 },
        keyLimit: { max: 20, windowMs: 600_000 },
        fpLimit: { max: 20, windowMs: 600_000 }
      })
    );
    const url = `http://127.0.0.1:${proxy.port}/license/validate`;

    const first = await fetch(url, {
      method: "POST",
      headers: { "x-forwarded-for": "198.51.100.1" },
      body: JSON.stringify({ licenseKey: "LICENSE-1234", fingerprint: "FINGERPRINT-1234" })
    });
    const second = await fetch(url, {
      method: "POST",
      headers: { "x-forwarded-for": "198.51.100.2" },
      body: JSON.stringify({ licenseKey: "LICENSE-5678", fingerprint: "FINGERPRINT-5678" })
    });

    expect(first.status).toBe(200);
    expect(second.status).toBe(429);
    expect(mock.requests).toHaveLength(1);
  });

  test("uses X-Forwarded-For only when TRUST_PROXY is enabled", async () => {
    const mock = await startMockKeygen();
    const proxy = await startProxy(
      baseEnv({
        keygenOrigin: `http://127.0.0.1:${mock.server.port}`,
        trustProxy: true,
        ipLimit: { max: 1, windowMs: 60_000 },
        keyLimit: { max: 20, windowMs: 600_000 },
        fpLimit: { max: 20, windowMs: 600_000 }
      })
    );
    const url = `http://127.0.0.1:${proxy.port}/license/validate`;

    const first = await fetch(url, {
      method: "POST",
      headers: { "x-forwarded-for": "198.51.100.1" },
      body: JSON.stringify({ licenseKey: "LICENSE-1234", fingerprint: "FINGERPRINT-1234" })
    });
    const second = await fetch(url, {
      method: "POST",
      headers: { "x-forwarded-for": "198.51.100.2" },
      body: JSON.stringify({ licenseKey: "LICENSE-5678", fingerprint: "FINGERPRINT-5678" })
    });

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(mock.requests).toHaveLength(2);
  });
});
