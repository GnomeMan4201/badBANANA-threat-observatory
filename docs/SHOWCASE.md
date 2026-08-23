# badBANANA Threat Observatory — production views

These are presentation crops of real production captures from the Observatory. Cropping and resizing do not alter evidence values or interface state.

![badBANANA Threat Observatory production views](screenshots/production-views.webp)

## Included views

- **Briefing** — device-local acknowledgement baseline and page-bounded ledger delta.
- **Pulse** — current-window filters and the observation relationship field.
- **Public IP geography** — approximate infrastructure geolocation with explicit non-attribution semantics.
- **Transition Replay** — ledger-driven `NEW`, `UPDATED`, and `REMOVED` transitions.
- **URLhaus** — defanged malicious URL observations.
- **MalwareBazaar** — metadata-only sample records; samples are not downloaded or served.

The screenshots are documentation only. The live deployment remains the source of truth for current state.

Live Observatory: https://badbanana-threat-observatory.badbanana6969.workers.dev
