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
- Ordinary read and geography rate limiting remains best-effort and isolate-local; it is not a distributed authorization control. Per-client-IP buckets rely on Cloudflare's trusted edge to supply/overwrite `cf-connecting-ip`; that assumption is deployment-specific.
- `POST /api/ingest` accepts only browser requests carrying an exact same-origin `Origin` and compatible Fetch Metadata. This rejects missing-origin and cross-origin maintenance requests, but these headers can be forged by direct HTTP clients and therefore remain request-origin enforcement rather than authentication.
- When D1 is available, ingestion uses a D1-shared fixed-window bucket keyed by a SHA-256 digest of the Cloudflare-reported client IP. If D1 cannot service that counter, the route falls back to the explicitly documented isolate-local ingest bucket rather than claiming a distributed limit that was not applied. TTL, backoff, and D1 refresh leases continue to constrain redundant upstream work.
- The deployed CSP currently permits same-origin inline script/style needed by the Next.js/vinext rendering path. This is a documented defense-in-depth limitation, not an input-sanitization mechanism; React's escaped rendering and avoidance of unsafe HTML sinks remain the primary XSS controls. Production deployment verifies that the configured security headers are actually present.
- The production build currently uses the beta-tagged `vinext` adapter. Dependency audits, the complete test/build gate, and pinned CI actions reduce but do not eliminate build-tool stability and supply-chain risk; this dependency should be revisited when a stable compatible release is available.

## Supported release

Only the current release on `main` receives security fixes.
