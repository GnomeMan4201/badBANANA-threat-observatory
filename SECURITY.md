# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's security-advisory interface for this repository. Do not open a public issue containing credentials, exploit details, malicious indicators, or data that could identify an affected party.

Include the affected route or module, reproduction conditions, expected impact, and the smallest safe proof of concept. Reports are evaluated against the current `main` branch.

## Security boundaries

- Feed credentials are server-only and must never use a `NEXT_PUBLIC_*` name.
- Client requests cannot choose upstream feed or geolocation destinations.
- Malicious URL indicators remain defanged and are not rendered as clickable links.
- IP geolocation is approximate infrastructure metadata, not actor location or attribution.
- The application does not download or serve malware samples.
- API rate limiting is best-effort and isolate-local; it is not a distributed authorization control. Per-client-IP buckets rely on Cloudflare's trusted edge to supply/overwrite `cf-connecting-ip`; that assumption is deployment-specific.
- `POST /api/ingest` is intentionally callable as a bounded demand-driven maintenance endpoint. Its same-origin check mitigates browser CSRF; it is not an authentication boundary for direct HTTP clients. TTL, backoff, D1 leases, and the dedicated ingest rate bucket constrain redundant work.
- The deployed CSP currently permits same-origin inline script/style needed by the Next.js/vinext rendering path. This is a documented defense-in-depth limitation, not an input-sanitization mechanism; React's escaped rendering and avoidance of unsafe HTML sinks remain the primary XSS controls. Production deployment verifies that the configured security headers are actually present.

## Supported release

Only the current release on `main` receives security fixes.
