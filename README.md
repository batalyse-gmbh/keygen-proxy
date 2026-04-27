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

- Keep `KEYGEN_TOKEN` server-side only.
- This sample uses in-memory maps; for production use Redis/Upstash/Cloudflare KV.
- Cache keys and rate-limit keys are based on SHA-256 hashes (no plaintext license keys in memory keys/logs).
