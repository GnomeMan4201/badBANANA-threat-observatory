# badBANANA Threat Observatory — production views

These captures are source-preserving production screenshots from the live v1.2.0 Observatory. They are cropped and normalized for presentation; evidence values and interface states are not regenerated or substituted.

## Pulse / observation relationships

![Pulse relationship view](screenshots/pulse-relationships.svg)

Cross-source relationship field with source health, page-bounded metrics, and explicit relationship semantics.

## Transition Replay

![Transition Replay](screenshots/replay-transitions.svg)

Ledger-driven reconstruction of retained `NEW`, `UPDATED`, and `REMOVED` transitions. Replay is page-bounded and is not presented as network traffic volume or a complete historical snapshot.

## Public IP geography

![Public IP geography](screenshots/geo-public-ip.svg)

Approximate public-IP infrastructure geography. The interface explicitly separates geolocation from actor location, ownership, nationality, and attribution.

## Source evidence surfaces

![URLhaus and MalwareBazaar evidence views](screenshots/source-evidence.svg)

URLhaus observations remain defanged by default; MalwareBazaar remains metadata-only. Missing confidence stays visibly missing rather than being synthesized.
