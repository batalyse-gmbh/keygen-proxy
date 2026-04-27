# Keygen validation proxy (Bun + Docker)

A small Bun service that shields Keygen from direct client traffic by adding:

- input validation before upstream calls
- rate limiting (IP + license hash + fingerprint hash)
- in-memory response cache
- grace-period fallback for known-valid licenses when Keygen is unavailable
- in-flight request de-duplication

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

### `POST /license/validate`

Request:

```json
{
  "licenseKey": "XXXX-XXXX-XXXX-XXXX",
  "fingerprint": "device-fingerprint"
}
```

Response includes one of:

- `source: "cache"` when served from fresh cache
- `source: "cache-grace"` when rate-limited and using grace cache
- `source: "cache-grace-error"` when Keygen is unavailable and grace cache is used
- `source: "keygen"` for fresh upstream validation

### `GET /health`

Simple health endpoint.

## Important notes

- This proxy does not require `KEYGEN_TOKEN`; keep privileged Keygen tokens out
  of this service.
- `TRUST_PROXY=false` ignores client-supplied `X-Forwarded-For` for rate limits.
  Set `TRUST_PROXY=true` only behind a trusted reverse proxy that strips and
  rewrites that header.
- This sample uses in-memory maps; for production use Redis/Upstash/Cloudflare KV.
- Cache keys and rate-limit keys are based on SHA-256 hashes (no plaintext license keys in memory keys/logs).
- Logs are emitted as JSON. Set `LOG_LEVEL=debug`, `info`, `warn`, or `error`; request logs include request IDs, timings, statuses, body sizes, cache/rate-limit decisions, and short hash prefixes instead of raw license keys or fingerprints.
