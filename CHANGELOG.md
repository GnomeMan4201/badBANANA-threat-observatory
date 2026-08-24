# Changelog

## 1.2.1

- Hardened the demand-driven `/api/ingest` maintenance boundary so missing-Origin and cross-origin browser requests are rejected while keeping the documentation explicit that request-origin enforcement is not client authentication.
- Added a D1-shared six-request-per-minute ingest limiter keyed by a SHA-256 digest of the Cloudflare-reported client IP, with an explicitly documented isolate-local fallback when D1 is unavailable.
- Made the shared D1 counter return its post-increment value from the same SQLite UPSERT, avoiding a separate post-write read under concurrency.
- Replaced source-text-only limiter assertions with executed behavioral regressions covering concurrent shared-counter calls, no lost updates, hashed persistent keys, and D1-failure fallback behavior.
- Documented the beta-tagged `vinext` build adapter as a known stability/supply-chain caveat without treating the beta label itself as a demonstrated defect.
- Preserved the v1.2.0 evidence model, source normalization, export policy, replay semantics, correlation discipline, geography boundaries, and client/server credential isolation unchanged.

## 1.2.0

- Standardized the release source on Cloudflare Workers hosting: standard Cloudflare Vite/Wrangler configuration is now authoritative, D1 is a normal `DB` Workers binding with first-deploy auto-provisioning, and production deployment is available through a manual GitHub Actions workflow.
- Rejected impossible source and filter calendar dates without JavaScript rollover, while preserving valid leap days.
- Canonicalized supported acknowledgement timestamp formats to UTC ISO-8601 and made device-local storage failures non-fatal with inline feedback.
- Stabilized current-record correlation dependencies so the one-second Observatory clock cannot trigger repeated correlation reads.
- Strengthened the evidence drawer with source-supplied, normalized, derived, correlated, source-specific, provenance, and bounded-reasoning sections.
- Added compact current-page source, record-type, confidence-presence, and cross-source correlation filters with visible bounded-result disclosure.
- Distinguished loading, failed, and successful zero-result states across source observations, event workspaces, correlation, and KEV reads.
- Improved source-health interpretation, Briefing source contribution, selected-event state, narrow-screen drawer containment, focus visibility, and touch targets.
- Added regression coverage for strict dates, timestamp equivalence, ledger semantics, unreliable storage, stable correlation requests, and release-state wording.
- Prevented unresolved or failed searches from substituting ordinary observation records into search-scoped exports.
- Kept failed Briefing-ledger fallbacks observational only so acknowledgement delta, no-change, and ledger-gap claims require authoritative ledger bounds.
- Preserved four-digit years across alternate timestamp formats, including years `0001` through `0099`, without `Date.UTC` century rollover.
- Replaced unresolved GEO zero counts with explicit unresolved states and clarified cross-source filter scope as the current window.

## 1.1.2

- Isolated Briefing, Replay, and Recent Events request state so paginating one workspace cannot alter another.
- Made Briefing always request the newest retained ledger page and kept Recent Events cursor history local to that view.
- Replaced sub-day Recent KEV claims with explicit `TODAY`, `7D`, and `30D` day-granular ranges.
- Required exact-indicator correlation candidates to span distinct sources before applying the safety bound.
- Exposed bounded correlation results as lower bounds instead of exact-looking totals.
- Added behavioral release regressions for event isolation, CISA time semantics, cross-source correlation, and bounded-result disclosure.
- Upgraded the Vinext/RSC build chain to audited compatible versions and cleared both full and production dependency audits.

## 1.1.1

- Applied source and kind scopes in D1 before cursor pagination for URLs, Malware, Infrastructure, and scoped search.
- Added dedicated complete-window candidate queries for GEO and dedicated CISA pagination for Recent KEV.
- Corrected empty export allow-lists, added STIX Vulnerability and MalwareBazaar hash representations, and disclosed selected/emitted/omitted counts.
- Made briefing ledger-gap detection use authoritative retained-ledger bounds before reporting newer changes.
- Preserved active search and investigative scope through Export; removed unrelated observation pagination from Replay.
- Made exact-indicator correlations dataset-level, canonicalized tag hashes, and deduplicated every adapter before persistence.
- Added same-origin maintenance checks, complete dialog focus behavior, new cross-layer regressions, MIT licensing, and aligned framework/tooling versions.

## 1.1.0

- Added a page-bounded, ledger-driven transition replay for retained `NEW`, `UPDATED`, and `REMOVED` events.
- Added device-local change acknowledgement with explicit baseline and retention limits.
- Added policy-bound exports for the validated visible page.
- Added D1-backed approximate public-IP geography with fixed providers, cache bounds, response identity checks, and visible provenance.
- Improved mobile navigation, contextual controls, reversible pagination, evidence-card readability, and keyboard-operable canvas controls.
- Replaced the banana mark with the supplied Observatory gnome formation across the header, favicon, footer, and social preview.
- Preserved demand-driven ingestion, read-path isolation, strict IOC handling, and explicit degraded states.

## 1.0.0

- Established the multi-source normalized observation model, D1 current state, material event ledger, source health telemetry, evidence drawer, relationship field, and CISA analyst workspace.
