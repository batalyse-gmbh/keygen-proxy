# Keygen validation proxy (Bun + Docker)

A small Bun service that shields Keygen from direct client traffic by adding:

- input validation before upstream calls
- rate limiting (IP + license hash + fingerprint hash)

## Run locally

```bash
cp .env.example .env
bun run start
```

## Run with Docker

```bash
docker build -t keygen-proxy .
docker run --rm -p 3000:3000 --env-file .env keygen-proxy
```

## API

### Keygen-compatible proxy routes

Only these routes are forwarded to `KEYGEN_ORIGIN`:

- `POST /v1/accounts/$KEYGEN_ACCOUNT/licenses/actions/validate-key`
- `GET /v1/accounts/$KEYGEN_ACCOUNT/licenses/:id/entitlements`

The proxy returns the upstream status, body, and signature headers without a JSON
wrapper. This is the route shape expected by Collect's existing Keygen client.
Validation requests use the license key in the request body and do not require a
server-side Keygen token.
Entitlement requests must include `Authorization: Basic license:<licenseKey>`;
the proxy forwards that caller license authorization and never injects the
server-side Keygen token for entitlement reads.

By default, the proxy sends `Host: api.keygen.sh` upstream so Keygen returns a
signed JSON response. `KEYGEN_FORWARD_CLIENT_HOST=true` can be used to test
client-host forwarding, but Keygen currently rejects `host.docker.internal:3000`
with an unsigned 503 response.

Other `/v1/*` routes are rejected locally.

### `GET /health`

Simple health endpoint.

### `POST /admin/rate-limits/reset`

Operator endpoint for clearing in-memory rate-limit buckets for a specific IP,
license, or fingerprint. It is disabled by default; set
`RATE_LIMIT_RESET_TOKEN` to enable it. Requests must include
`Authorization: Bearer $RATE_LIMIT_RESET_TOKEN`.

Example:

```bash
curl -X POST http://localhost:3000/admin/rate-limits/reset \
  -H "Authorization: Bearer $RATE_LIMIT_RESET_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "198.51.100.10",
    "licenseKey": "LICENSE-1234",
    "fingerprint": "FINGERPRINT-1234"
  }'
```

The endpoint also accepts `licenseHash` and `fingerprintHash` as SHA-256 hex
values. IP resets clear both validation and entitlement IP buckets. License
resets clear both validation and entitlement license buckets. Fingerprint resets
clear the validation fingerprint bucket.

## Rate limits

The default limits are tuned for about 30 clients checking every 6 hours, where
each check performs one validation request and one entitlement request:

```env
RL_IP_MAX=10
RL_KEY_MAX=2
RL_KEY_WINDOW_MS=21600000
RL_FP_MAX=2
RL_FP_WINDOW_MS=21600000
```

`RL_IP_MAX` allows 10 proxied Keygen requests per minute per client IP.
`RL_KEY_MAX` and `RL_FP_MAX` allow two validation attempts per license key and
fingerprint in each 6-hour window, giving each client one normal check plus one
startup or retry allowance. Entitlement reads use a separate license-key bucket,
so a normal validate + entitlements check can complete without the two calls
blocking each other.

## Important notes

- This proxy does not require `KEYGEN_TOKEN`; keep privileged Keygen tokens out
  of this service.
- `RATE_LIMIT_RESET_TOKEN` enables an authenticated operator reset endpoint for
  clearing in-memory rate-limit buckets. Leave it unset unless you need that
  operational escape hatch.
- `TRUST_PROXY=false` ignores client-supplied `X-Forwarded-For` for rate limits.
  Set `TRUST_PROXY=true` only behind a trusted reverse proxy that strips and
  rewrites that header.
- This sample uses in-memory maps; for production use Redis/Upstash/Cloudflare KV.
- Rate-limit keys are based on SHA-256 hashes (no plaintext license keys in memory keys/logs).
- Logs are emitted as JSON. Set `LOG_LEVEL=debug`, `info`, `warn`, or `error`; request logs include request IDs, timings, statuses, body sizes, rate-limit decisions, and short hash prefixes instead of raw license keys or fingerprints.
